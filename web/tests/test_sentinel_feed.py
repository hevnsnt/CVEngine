"""Keeping the Sentinels fed: hosts with no address are not a backlog, the caps grow with the Sentinels' slots, and the
work queued behind a Sentinel is twice its capacity."""
import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import coverage_topup, hosting, host_assessment, unresolved_archive
from cveFeed.models import HostAssessment, HostState
from dashboard.models import Org, Project
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain


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
        # these tests pin the caps and the feed as they count one host per pipeline run; hosts carried in batches are tests/test_assess_batch.py's
        mock.patch.dict(os.environ, {'CVENGINE_ASSESS_BATCH': '1'}).start()
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
        return coverage_topup.host_coverage_due(self.project, self.now, limit=50, need_count=False)[1]

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


class RefreshTests(Base):
    """With every host covered nothing is due, so nothing would reach a Sentinel: the refresh gives it the stalest hosts again."""

    def setUp(self):
        super().setUp()
        mock.patch('cveFeed.coverage_topup.host_coverage_due', return_value=(0, [])).start()  # every host has its first pass
        sender = mock.patch('cveFeed.tasks.assess_host.apply_async').start()
        sender.return_value.id = 'task'

    def assessed(self, sub, hours_ago):
        job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=sub.name.lower(), status='completed')
        HostAssessment.objects.filter(pk=job.pk).update(created_at=self.now - timedelta(hours=hours_ago))

    def queued_hosts(self):
        return list(HostAssessment.objects.filter(status='queued').order_by('id').values_list('host', flat=True))

    def test_the_stalest_hosts_are_queued_first_and_one_assessed_inside_the_gap_is_left_alone(self):
        never, old, older, fresh = self.host('never'), self.host('old'), self.host('older'), self.host('fresh')
        self.assessed(old, 20)
        self.assessed(older, 70)
        self.assessed(fresh, 1)
        self.sentinel(slots=3)
        out = coverage_topup.refresh_for_sentinels(self.now)
        self.assertEqual(out['refreshed'], 3)
        self.assertEqual(self.queued_hosts(), [never.name, older.name, old.name])  # never assessed, then longest ago; 'fresh' rests
        self.assertEqual(set(HostAssessment.objects.filter(status='queued').values_list('source', flat=True)), {'refresh'})

    def test_archived_hosts_do_not_crowd_the_live_ones_out_of_the_candidates(self):
        from django.utils import timezone as tz

        from cveFeed.models import HostState
        for i in range(120):  # never assessed, so the stalest of all: before the fix they filled the whole candidate window
            sub = self.host(f'gone{i}')
            HostState.objects.create(project=self.project, domain=self.domain, host=sub.name.lower(), archived_at=tz.now())
        live = [self.host('live-a'), self.host('live-b')]
        self.assessed(live[0], 20)
        self.assessed(live[1], 30)
        self.sentinel(slots=1)
        self.assertEqual([s.pk for s in coverage_topup.stalest_hosts(self.project, self.now, 10, timedelta(hours=1))], [live[1].pk, live[0].pk])
        out = coverage_topup.refresh_for_sentinels(self.now)
        self.assertEqual(self.queued_hosts(), [live[1].name, live[0].name])
        self.assertEqual(out['refreshed'], 2)

    def test_it_fills_the_sentinel_scaled_cap_and_no_more(self):
        for i in range(20):
            self.host(f'h{i}')
        self.sentinel(slots=3)  # project cap 9
        self.assertEqual(coverage_topup.refresh_for_sentinels(self.now)['refreshed'], 9)
        self.assertEqual(coverage_topup.refresh_for_sentinels(self.now)['refreshed'], 0)  # the pool is full

    def test_a_project_no_sentinel_covers_is_not_refreshed(self):
        self.host('a')
        self.sentinel(slots=3, scope={'orgs': [], 'projects': ['elsewhere'], 'hosts': []})
        self.assertEqual(coverage_topup.refresh_for_sentinels(self.now)['refreshed'], 0)
        self.assertEqual(self.queued_hosts(), [])

    def test_the_gap_is_configurable_and_zero_turns_the_refresh_off(self):
        self.host('a')
        self.sentinel(slots=3)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_REFRESH_GAP_HOURS': '0'}):
            self.assertEqual(coverage_topup.refresh_for_sentinels(self.now), {'refreshed': 0, 'skipped': 'refresh is off'})
        self.assertEqual(coverage_topup.refresh_gap(), timedelta(hours=6))
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_REFRESH_GAP_HOURS': '24'}):
            self.assertEqual(coverage_topup.refresh_gap(), timedelta(hours=24))

    def test_a_pause_stops_it_and_an_excluded_or_archived_host_is_skipped_not_fatal(self):
        archived, ok = self.host('archived'), self.host('ok')
        HostState.objects.create(project=self.project, domain=self.domain, host=archived.name, archived_at=self.now)
        self.sentinel(slots=3)
        self.assertEqual(coverage_topup.refresh_for_sentinels(self.now)['refreshed'], 1)
        self.assertEqual(self.queued_hosts(), [ok.name])
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            self.assertEqual(coverage_topup.refresh_for_sentinels(self.now)['skipped'], 'paused')

    def test_the_feed_gives_an_idle_sentinel_work_once_nothing_is_due(self):
        for name in ('a', 'b'):
            self.host(name)
        self.sentinel(slots=3)
        out = coverage_topup.feed_sentinels(self.now)
        self.assertEqual((out['hosts_queued'], out['refresh']['refreshed']), (0, 2))
        self.assertEqual(len(self.queued_hosts()), 2)

    def test_the_refresh_only_ever_queues_a_host_once_at_a_time(self):
        self.host('a')
        self.sentinel(slots=3)
        coverage_topup.refresh_for_sentinels(self.now)
        coverage_topup.refresh_for_sentinels(self.now)
        self.assertEqual(HostAssessment.objects.filter(status='queued').count(), 1)
