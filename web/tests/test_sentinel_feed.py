"""Keeping the Sentinels fed: hosts with no address are not a backlog, IPv6 is scanned with -6, the caps grow with the Sentinels' slots, and the
work queued behind a Sentinel is twice its capacity."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import assessment_review as ar
from cveFeed import coverage_topup, hosting, host_assessment, nmap_scan, unresolved_archive
from cveFeed.models import HostAssessment, HostState
from dashboard.models import Org, Project
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain


class NmapIpv6Tests(SimpleTestCase):
    REPORT = '<?xml version="1.0"?><nmaprun><hosthint><address addr="{a}"/></hosthint>{hosts}<runstats/></nmaprun>'

    def run_with(self, targets, answers):
        """Run ``run_nmap_xml`` with Popen replaced: ``answers`` is the XML text per call, in order. Returns the commands run and the result."""
        commands, replies = [], list(answers)

        class Proc:
            def __init__(self, cmd, **kw):
                commands.append(cmd)

            def communicate(self, timeout=None):
                return replies.pop(0), ''

        class Job:
            def __enter__(self):
                return self

            def __exit__(self, *e):
                return False

            def attach(self, proc):
                pass

            def raise_if_killed(self):
                pass
        with mock.patch('cveFeed.nmap_scan.subprocess.Popen', Proc), mock.patch('reNgine.resources.heavy_job', lambda *a, **k: Job()):
            return commands, nmap_scan.run_nmap_xml(targets, ['-sU'], '5m')

    def test_an_ipv6_target_runs_with_dash_6_and_an_ipv4_one_does_not(self):
        commands, _ = self.run_with(['2606:4700:20::681a:907'], [self.REPORT.format(a='x', hosts='')])
        self.assertEqual(commands[0][:3], ['nmap', '-6', '-sU'])
        commands, _ = self.run_with(['203.0.113.5'], [self.REPORT.format(a='x', hosts='')])
        self.assertNotIn('-6', commands[0])

    def test_a_mixed_list_runs_once_per_family_and_one_report_answers_for_both(self):
        v4 = self.REPORT.format(a='203.0.113.5', hosts='<host><address addr="203.0.113.5"/></host>')
        v6 = self.REPORT.format(a='2001:db8::5', hosts='<host><address addr="2001:db8::5" addrtype="ipv6"/></host>')
        commands, merged = self.run_with(['203.0.113.5', '2001:db8::5'], [v4, v6])
        self.assertEqual([('-6' in c) for c in commands], [False, True])
        self.assertIn('addr="203.0.113.5"/></host>', merged)
        self.assertIn('2001:db8::5', merged.split('</hosthint>')[1])
        self.assertTrue(merged.rstrip().endswith('</nmaprun>'))
        self.assertEqual(len(nmap_scan.parse_xml(merged)), 2)

    def test_merging_a_report_with_no_hosts_changes_nothing(self):
        report = self.REPORT.format(a='x', hosts='<host><address addr="203.0.113.5"/></host>')
        self.assertEqual(nmap_scan.merge_xml(report, self.REPORT.format(a='y', hosts='')), report)


class ProviderRangeTests(SimpleTestCase):
    def test_cloudflares_published_ranges_are_a_shared_edge_for_both_families(self):
        for address in ('2606:4700:20::681a:807', '2606:4700:20::ac43:440a', '104.16.1.1', '172.67.1.1', '188.114.97.1'):
            self.assertEqual(hosting.provider_range(address), ('Cloudflare', 'cdn'), address)
        for address in ('2603:1036:304:86e::8', '203.0.113.5', 'not an address'):
            self.assertIsNone(hosting.provider_range(address), address)


class Base(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Feed org', slug='feed-org')
        self.project = Project.objects.create(name='Feed', slug='feed', org=self.org, insert_date=self.now)
        self.domain = Domain.objects.create(name='feed.example', project=self.project, insert_date=self.now)
        self.user = User.objects.create_user('feed-owner', password='x')
        self.n = 0
        mock.patch('cveFeed.scan_control.pause_requested', return_value=False).start()
        self.addCleanup(mock.patch.stopall)

    def host(self, name, unresolved=0, note='', last=None):
        sub = Subdomain.objects.create(target_domain=self.domain, name=f'{name}.feed.example')
        if unresolved:
            HostState.objects.create(project=self.project, domain=self.domain, host=sub.name, unresolved_checks=unresolved,
                                     unresolved_first_at=self.now - timedelta(days=1), unresolved_last_at=last or self.now, resolution_note=note)
        return sub

    def sentinel(self, slots=3, scope=None):
        self.n += 1
        token, _raw = create_token(self.user, f'feed-{self.n}')
        return Agent.objects.create(token=token, name=f'feed-{self.n}', kind='scanner', status='active', max_concurrent=slots,
                                    capabilities=['nmap', 'nuclei_light', 'nuclei_targeted'], last_seen=timezone.now(),
                                    scope=scope or {'orgs': [], 'projects': [self.project.slug], 'hosts': []})


class NoAddressTests(Base):
    def due(self):
        return ar.host_coverage_due(self.project, self.now, limit=50, need_count=False)[1]

    def test_a_host_with_no_scannable_address_is_not_a_first_pass_backlog_and_does_not_gate_the_deep_sweeps(self):
        waiting = self.host('real')
        dangling = self.host('dangling', unresolved=2, note='no DNS answer')
        self.assertEqual(self.due(), [waiting.pk])
        waiting.delete()
        self.assertEqual(self.due(), [])
        self.assertFalse(coverage_topup.backlog_exists(self.now))  # nothing outstanding: the full-port and UDP sweeps may run
        self.assertTrue(Subdomain.objects.filter(pk=dangling.pk).exists())

    def test_an_old_streak_counts_again_so_a_forgotten_host_is_looked_at(self):
        old = self.host('old', unresolved=3, last=self.now - unresolved_archive.COUNTS_FOR - timedelta(hours=1))
        self.assertEqual(self.due(), [old.pk])

    def test_recheck_clears_a_host_that_now_resolves_and_says_why_the_others_do_not(self):
        back = self.host('back', unresolved=2, last=self.now - timedelta(days=1))
        private = self.host('inside', unresolved=2, last=self.now - timedelta(days=1))
        gone = self.host('gone', unresolved=2, last=self.now - timedelta(days=1))
        answers = {(back.name, '93.184.216.34'), (private.name, '10.100.11.232')}
        out = unresolved_archive.recheck(self.now, resolver=lambda names: {a for a in answers if a[0] in names})
        self.assertEqual((out['checked'], out['resolved'], out['private'], out['no_dns']), (3, 1, 1, 1))
        states = {s.host: s for s in HostState.objects.all()}
        self.assertEqual((states[back.name].unresolved_checks, states[back.name].unresolved_first_at), (0, None))
        self.assertIn('private address (10.100.11.232)', states[private.name].resolution_note)
        self.assertEqual(states[gone.name].resolution_note, 'no DNS answer')
        self.assertIn(back.pk, self.due())  # due for its first pass again at once
        self.assertNotIn(private.pk, self.due())

    def test_recheck_asks_a_host_at_most_every_few_hours_and_a_batch_at_a_time(self):
        self.host('fresh', unresolved=1, last=self.now - timedelta(hours=1))
        called = []
        out = unresolved_archive.recheck(self.now, resolver=lambda names: called.append(names) or set())
        self.assertEqual(out['checked'], 0)
        self.assertEqual(called, [])

    def test_the_unscannable_facet_counts_unscanned_hosts_with_no_address_by_reason(self):
        from agentapi import services
        self.host('a', unresolved=1, note='private address (10.0.0.1): x')
        self.host('b', unresolved=1, note='no DNS answer')
        self.host('c')
        withip = self.host('d')
        withip.ip_addresses.add(IpAddress.objects.create(address='93.184.216.34'))
        qs = Subdomain.objects.filter(target_domain__project=self.project)
        heat = {s.pk: 'unscanned' for s in qs}
        out = services._unscannable_facet(qs, heat)
        self.assertEqual(out, {'count': 3, 'private': 1, 'no_dns': 1, 'unknown': 1})


class CapsTests(Base):
    def test_without_a_sentinel_the_caps_are_the_base_ones(self):
        self.assertEqual(host_assessment.caps(self.project), (20, 5))

    def test_a_live_sentinel_raises_them_to_three_per_slot_so_twice_its_capacity_waits_behind_it(self):
        self.sentinel(slots=3)
        global_cap, project_cap = host_assessment.caps(self.project)
        self.assertEqual((global_cap, project_cap), (20 + 9, 9))

    def test_a_sentinel_that_does_not_cover_the_project_does_not_raise_its_cap(self):
        self.sentinel(slots=3, scope={'orgs': [], 'projects': ['elsewhere'], 'hosts': []})
        self.assertEqual(host_assessment.caps(self.project)[1], 5)

    def test_the_top_up_queues_up_to_the_scaled_cap(self):
        for i in range(30):
            self.host(f'h{i}')
        self.sentinel(slots=3)
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'task'
            out = coverage_topup.top_up(now=self.now)
        self.assertEqual(out['hosts_queued'], 9)


class FeedTests(Base):
    def test_nothing_happens_without_a_live_sentinel(self):
        self.host('a')
        self.assertEqual(coverage_topup.feed_sentinels(self.now), {'skipped': 'no live Sentinel'})

    def test_it_feeds_when_less_than_twice_the_slots_wait_and_stops_when_the_queue_is_deep(self):
        for i in range(30):
            self.host(f'h{i}')
        self.sentinel(slots=3)
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'task'
            out = coverage_topup.feed_sentinels(self.now)
        self.assertEqual((out['slots'], out['wanted'], out['hosts_queued']), (3, 6, 9))
        from agentapi.models import SentinelTask
        for _ in range(6):
            SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status='queued')
        self.assertEqual(coverage_topup.feed_sentinels(self.now)['skipped'], 'queue is deep enough')

    def test_the_feed_leaves_a_project_no_sentinel_covers_to_the_ordinary_top_up(self):
        other = Project.objects.create(name='Feed other', slug='feed-other', org=self.org, insert_date=self.now)
        domain = Domain.objects.create(name='other.feed.example', project=other, insert_date=self.now)
        Subdomain.objects.create(target_domain=domain, name='x.other.feed.example')
        self.sentinel(slots=3)
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'task'
            out = coverage_topup.feed_sentinels(self.now)
        self.assertEqual(out['hosts_queued'], 0)
        self.assertFalse(HostAssessment.objects.filter(project=other).exists())

    def test_the_task_is_scheduled_every_minute_and_exempt_from_a_scanning_pause(self):
        from django_celery_beat.models import PeriodicTask
        from cveFeed import scan_control
        task = PeriodicTask.objects.get(name='cvengine-feed-sentinels')
        self.assertEqual((task.task, task.enabled, task.interval.every, task.interval.period), ('feed_sentinels', True, 1, 'minutes'))
        self.assertIn('feed_sentinels', scan_control.PAUSE_EXEMPT_TASKS)
