"""A target set to manual only ("just add them, do not scan yet") is left alone by every sweep and queue that picks work by itself (issue 284):
the entry points of tests.test_bounty_gate run against a plain project (no bug bounty engagement) whose target is manual only and then standard,
the slow sweeps run through their own fixtures, and a person's explicit request is shown to still reach the host.
Passive is not held back by any of them: it limits discovery, and the stages after a passive discovery are the ones the pipeline has always run."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import bounty_gate, conductor, discovery, openvas_scan, testssl_scan, web_shot, wpscan_scan
from cveFeed.models import HostScreenshot, ProbeObservation
from dashboard.models import Org, Project
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests import test_bounty_gate as gate_tests
from tests import test_bucket_scan, test_subdir_apps, test_vhost_scan, test_web_shot
from tests.test_bounty_gate import IN_HOST, PUBLIC_IP, Gated

MANUAL, STANDARD = Domain.DISCOVERY_MANUAL, Domain.DISCOVERY_STANDARD


class PlainWorld(Gated):
    """The bounty harness's project, host and address, with no engagement: only the target's discovery mode differs."""

    def plain(self, mode=MANUAL, host=IN_HOST):
        n = Project.objects.count()
        org = Org.objects.create(name=f'M{n}', slug=f'manual-o{n}')
        project = Project.objects.create(name=f'MP{n}', slug=f'manual-p{n}', insert_date=self.now, org=org)
        root = '.'.join(host.split('.')[-2:])
        domain = Domain.objects.create(name=root, project=project, insert_date=self.now, discovery_mode=mode)
        scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, scan_status=2, start_scan_date=self.now, results_dir='/tmp')
        sub = Subdomain.objects.create(name=host, target_domain=domain, scan_history=scan)
        ip = IpAddress.objects.create(address=PUBLIC_IP, org=org)
        sub.ip_addresses.add(ip)
        return type('World', (), {'host': host, 'project': project, 'domain': domain, 'scan': scan, 'sub': sub, 'ip': ip})


def conductor_round(self, w):  # the target is the project's own row, not one the harness adds in the default mode
    ScanHistory.objects.filter(domain=w.domain).update(start_scan_date=self.now - timedelta(days=3))
    return w.domain.id in conductor.next_targets(10)


def discovery_pipeline(self, w):
    scan = ScanHistory.objects.create(domain=w.domain, scan_type=self.engine, scan_status=-1, start_scan_date=self.now, results_dir='/tmp')
    with mock.patch('cveFeed.discovery.run_discovery', return_value={'status': 'stopped'}) as found:
        discovery._run_pipeline(scan.id)
    return found.called


def openvas_automatic(self, w):
    ready, verdicts = openvas_scan.assess(w.project.id, [w.host], gate=False, resolve=lambda host, project: PUBLIC_IP, blocked=lambda host: False)
    return bool(ready)


def testssl_targets(self, w):
    return any(t[0] == w.host for t in testssl_scan.targets(w.project.id))


def thorough_state(self, w):
    return wpscan_scan._latest_row(w.project.id, w.host) is not None


# name, function: each returns True when it started work on the host
ENTRY_POINTS = [
    ('work conductor', conductor_round),
    ('certificate transparency watch', gate_tests.ct_watch_finds_a_host),
    ('host assessment queue (top-up, refresh, review)', gate_tests.host_assessment_enqueue),
    ('new-hosts pipeline', gate_tests.host_pipeline_unattended),
    ('retest of changed hosts', gate_tests.retest_hosts_task),
    ('full TCP port sweep', gate_tests.full_port_sweep),
    ('weekly deep nuclei', gate_tests.weekly_deep_nuclei),
    ('thorough WPScan', gate_tests.thorough_wpscan),
    ('discovery pipeline of a scan the system queued', discovery_pipeline),
    ('hygiene sweep', gate_tests.hygiene_sweep),
    ('OpenVAS automatic selection', openvas_automatic),
    ('TLS audit targets', testssl_targets),
]


class EveryAutomaticEntryPointTests(PlainWorld):
    def test_a_manual_only_target_is_never_worked_on(self):
        for name, fn in ENTRY_POINTS:
            with self.subTest(name):
                self.assertFalse(fn(self, self.plain(MANUAL)))

    def test_the_same_entry_points_do_act_on_a_standard_target(self):
        for name, fn in ENTRY_POINTS:
            with self.subTest(name):
                self.assertTrue(fn(self, self.plain(STANDARD)), name)

    def test_a_passive_or_deep_target_is_not_held_back_by_the_host_sweeps(self):
        for mode in ('passive', 'deep'):
            for name, fn in ENTRY_POINTS:
                if name == 'certificate transparency watch':
                    continue  # a passive target's certificate finds are recorded and not connected to: its own test in test_discovery_mode_paths
                with self.subTest(f'{name} {mode}'):
                    self.assertTrue(fn(self, self.plain(mode)), name)

    def test_the_bug_bounty_gate_is_unchanged_beside_it(self):
        w = self.world(IN_HOST, confirmed=False)
        self.assertTrue(bounty_gate.Gate().refusal(w.project.id, IN_HOST))
        self.assertFalse(gate_tests.host_assessment_enqueue(self, w))
        self.assertTrue(gate_tests.host_assessment_enqueue(self, self.world(IN_HOST)))  # confirmed, standard: still acts


class APersonsRequestStillReachesTheHost(PlainWorld):
    def test_a_person_rescanning_hosts_of_a_manual_only_target_runs_the_pipeline(self):
        w = self.plain(MANUAL)
        with mock.patch('cveFeed.discovery._run_stages', return_value={'status': 2}) as stages, mock.patch('reNgine.tasks.persist_bbot_result'):
            discovery.run_host_pipeline(w.domain.id, [w.host], resolver=lambda names: {(n, PUBLIC_IP) for n in names}, by_person=True)
        stages.assert_called_once()
        self.assertEqual(gate_tests._pipeline_scans(w), 1)

    def test_an_unattended_run_never_gets_to_the_stages_the_rdp_and_screenshot_stages_among_them(self):
        w = self.plain(MANUAL)
        with mock.patch('cveFeed.discovery._run_stages') as stages:
            out = discovery.run_host_pipeline(w.domain.id, [w.host], resolver=lambda names: {(n, PUBLIC_IP) for n in names})
        stages.assert_not_called()
        self.assertEqual((out['status'], gate_tests._pipeline_scans(w)), ('inconclusive', 0))

    def test_a_person_assessing_a_host_is_admitted(self):
        from cveFeed.host_assessment import enqueue
        w = self.plain(MANUAL)
        user = User.objects.create_user('manual-asker', password='x')
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as sent:
            sent.return_value.id = 'task'
            job, created = enqueue(w.project, w.sub, user=user)
        self.assertTrue(created)

    def test_openvas_scans_a_host_a_person_named(self):
        w = self.plain(MANUAL)
        ready, _ = openvas_scan.assess(w.project.id, [w.host], forced={w.host}, gate=False, resolve=lambda host, project: PUBLIC_IP, blocked=lambda host: False)
        self.assertTrue(ready)

    def test_openvas_says_why_a_manual_only_host_is_not_ready(self):
        w = self.plain(MANUAL)
        _, verdicts = openvas_scan.assess(w.project.id, [w.host], gate=False, resolve=lambda host, project: PUBLIC_IP, blocked=lambda host: False)
        self.assertIn('manual only', verdicts[w.host]['reason'])

    def test_a_thorough_wpscan_waiting_for_a_target_made_manual_only_is_failed_not_run(self):
        w = self.plain(STANDARD)
        wpscan_scan.record_thorough(w.project.id, w.domain.id, w.host, 'pending', 'queued')
        Domain.objects.filter(pk=w.domain.pk).update(discovery_mode=MANUAL)
        runner = mock.Mock(side_effect=AssertionError('WPScan must not run'))
        summary = wpscan_scan.run_thorough(w.project.id, runner=runner, sleep=lambda s: None, probe_get=mock.Mock())
        runner.assert_not_called()
        self.assertEqual(summary['failed'], 1)
        row = ProbeObservation.objects.get(project=w.project, host=w.host, probe=wpscan_scan.THOROUGH_PROBE)
        self.assertEqual(row.variant, 'failed')
        self.assertIn('manual only', row.evidence.get('reason', '') + str(row.evidence))


class VirtualHostSweepTests(test_vhost_scan.VhostFixture, TestCase):
    def test_a_manual_only_target_gives_no_address_and_no_name_to_ask(self):
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        summary = test_vhost_scan.vhost_scan.sweep(self.project.id, fetch=self.server, pace=test_vhost_scan.pace())
        self.assertEqual(self.server.calls, [])
        self.assertIn('skipped', summary)

    def test_the_standard_target_is_asked(self):
        self.run_sweep()
        self.assertTrue(self.server.calls)


class SubdirectorySweepTests(test_subdir_apps.SubdirFixture, TestCase):
    def test_a_manual_only_target_is_not_asked_for_its_application_paths(self):
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        summary = self.run_subdirs()
        self.assertEqual(summary['hosts'], 0)
        self.assertEqual(self.site.calls, [])

    def test_the_standard_target_is(self):
        self.assertEqual(self.run_subdirs()['hosts'], 1)


class BucketSweepTests(test_bucket_scan.Fixture, TestCase):
    def test_a_manual_only_targets_buckets_are_not_checked_on_a_schedule(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        out = self.sweep()
        self.assertEqual(out['checked'], 0)
        self.assertEqual(self.net.calls, [])

    def test_the_standard_target_is(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        self.assertEqual(self.sweep()['checked'], 1)


class ScreenshotTests(test_web_shot.ShotFixture, TestCase):
    def test_the_hourly_backfill_does_not_photograph_a_manual_only_target(self):
        self.host()
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        self.assertEqual(web_shot.backfill()['queued'], 0)
        self.assertEqual(HostScreenshot.objects.count(), 0)

    def test_the_backfill_photographs_the_standard_target(self):
        self.host()
        self.assertGreater(web_shot.backfill()['queued'], 0)

    def test_an_old_picture_of_a_manual_only_target_is_not_taken_again(self):
        self.host()
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        self.make_row(outcome='ok', captured_at=timezone.now() - timedelta(days=400), image_path='x.png')
        self.assertEqual(web_shot._due_names(self.project.id, 10, timezone.now()), [])

    def test_a_scan_stage_queues_nothing_for_a_manual_only_target_and_a_persons_request_queues_it(self):
        sub = self.host()
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        sub = self.fresh(sub)
        self.assertEqual(web_shot.queue_for_subs([sub], self.project.id)['queued'], 0)
        self.assertEqual(HostScreenshot.objects.count(), 0)
        self.assertGreater(web_shot.queue_for_subs([sub], self.project.id, by_person=True)['queued'], 0)

    def test_a_page_queued_before_the_target_was_made_manual_only_is_blocked_unless_a_person_asked(self):
        self.host(ports=((443, 'https'),))
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        for by_person, outcome in ((False, 'blocked'), (True, 'ok')):
            HostScreenshot.objects.all().delete()
            self.make_row(by_person=by_person)
            test_web_shot.FakeProxy.instances = []
            with mock.patch('cveFeed.web_shot._resolve', mock.Mock(return_value='203.0.113.5')):
                web_shot.drain(runner=test_web_shot.runner_for({}), proxy_factory=test_web_shot.FakeProxy)
            row = HostScreenshot.objects.get()
            self.assertEqual(row.outcome, outcome, by_person)
            if not by_person:
                self.assertIn('manual only', row.reason)


class SharedHostTests(PlainWorld):
    """A host that two targets hold is held back only when EVERY target holding it is manual only. The row of the manual only one is the newest
    here (a certificate-transparency find has no scan, which sorts first when rows are put newest-first), so a sweep that lets the newest row
    decide would refuse a host a standard target also holds."""

    HOST = 'www.shared.test'

    def shared(self, standard_mode=STANDARD):
        n = Project.objects.count()
        org = Org.objects.create(name=f'S{n}', slug=f'shared-o{n}')
        project = Project.objects.create(name=f'SP{n}', slug=f'shared-p{n}', insert_date=self.now, org=org)
        std = Domain.objects.create(name='shared.test', project=project, insert_date=self.now, discovery_mode=standard_mode)
        man = Domain.objects.create(name=self.HOST, project=project, insert_date=self.now, discovery_mode=MANUAL)
        scan = ScanHistory.objects.create(domain=std, scan_type=self.engine, scan_status=2, start_scan_date=self.now, results_dir='/tmp')
        ip = IpAddress.objects.create(address=PUBLIC_IP, org=org)
        scanned = Subdomain.objects.create(name=self.HOST, target_domain=std, scan_history=scan)
        scanned.ip_addresses.add(ip)
        found = Subdomain.objects.create(name=self.HOST, target_domain=man)  # certificate transparency: no scan, the newest row
        found.ip_addresses.add(ip)
        return type('World', (), {'project': project, 'std': std, 'man': man, 'scan': scan, 'ip': ip, 'scanned': scanned, 'found': found})

    def test_the_helpers_hold_a_host_back_only_when_every_holder_is_manual_only(self):
        from cveFeed import manual_only
        w = self.shared()
        self.assertEqual(manual_only.only_manual_hosts(w.project.id, [self.HOST]), set())
        self.assertEqual(manual_only.other_holder(w.project.id, self.HOST), w.std)
        Domain.objects.filter(pk=w.std.pk).update(discovery_mode=MANUAL)
        self.assertEqual(manual_only.only_manual_hosts(w.project.id, [self.HOST, 'SHARED.test.']), {self.HOST, 'shared.test'})
        self.assertIsNone(manual_only.other_holder(w.project.id, self.HOST))
        self.assertEqual(manual_only.only_manual_hosts(w.project.id, []), set())

    def test_openvas_scans_a_host_a_standard_target_also_holds_and_refuses_one_only_manual_targets_hold(self):
        w = self.shared()
        ready, verdicts = openvas_scan.assess(w.project.id, [self.HOST], gate=False, resolve=lambda host, project: PUBLIC_IP, blocked=lambda host: False)
        self.assertEqual([h for h, _ip, _d in ready], [self.HOST], verdicts)
        self.assertEqual(ready[0][2], w.std.id)  # attributed to the target that may be scanned
        Domain.objects.filter(pk=w.std.pk).update(discovery_mode=MANUAL)
        ready, verdicts = openvas_scan.assess(w.project.id, [self.HOST], gate=False, resolve=lambda host, project: PUBLIC_IP, blocked=lambda host: False)
        self.assertEqual(ready, [])
        self.assertIn('manual only', verdicts[self.HOST]['reason'])

    def test_the_tls_audit_and_wpscan_use_the_row_of_the_target_that_may_be_scanned(self):
        w = self.shared()
        self.assertEqual(testssl_scan._latest_row(w.project.id, self.HOST).target_domain, w.std)
        self.assertEqual(wpscan_scan._latest_row(w.project.id, self.HOST).target_domain, w.std)
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **kw: list(hosts)):
            self.assertEqual({t[0] for t in testssl_scan.targets(w.project.id)}, {self.HOST})
            Domain.objects.filter(pk=w.std.pk).update(discovery_mode=MANUAL)
            self.assertEqual(testssl_scan.targets(w.project.id), [])
        self.assertIsNone(wpscan_scan._latest_row(w.project.id, self.HOST))

    def test_an_automatic_assessment_of_the_manual_only_row_goes_to_the_standard_target(self):
        from cveFeed.host_assessment import _admit
        w = self.shared()
        domain, host = _admit(w.project, Subdomain.objects.select_related('target_domain').get(pk=w.found.pk))
        self.assertEqual((domain, host), (w.std, self.HOST))
        Domain.objects.filter(pk=w.std.pk).update(discovery_mode=MANUAL)
        with self.assertRaisesRegex(ValueError, 'manual only'):
            _admit(w.project, Subdomain.objects.select_related('target_domain').get(pk=w.found.pk))

    def test_the_coverage_backlog_counts_the_host_through_the_standard_targets_row(self):
        from cveFeed import assessment_review
        w = self.shared()
        count, due = assessment_review.host_coverage_due(w.project, self.now)
        self.assertEqual(due, [w.scanned.pk])  # the row of the target that may be scanned, not the manual only one


class SharedHostBucketTests(test_bucket_scan.Fixture, TestCase):
    def test_a_bucket_a_shared_host_leads_to_is_checked_and_attributed_to_the_standard_target(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        manual = Domain.objects.create(name='other.example.test', project=self.project, insert_date=timezone.now(), discovery_mode=MANUAL)
        Subdomain.objects.create(name='static.example.test', target_domain=manual, cname='ex-static.s3.amazonaws.com')  # the newest row
        out = self.sweep()
        self.assertEqual(out['checked'], 1)
        self.assertTrue(self.net.calls)

    def test_a_bucket_only_manual_only_targets_hosts_lead_to_is_not_checked(self):
        manual = Domain.objects.create(name='other.example.test', project=self.project, insert_date=timezone.now(), discovery_mode=MANUAL)
        Subdomain.objects.create(name='static.example.test', target_domain=manual, cname='ex-static.s3.amazonaws.com')
        self.assertEqual(self.sweep()['checked'], 0)
        self.assertEqual(self.net.calls, [])


class SharedHostScreenshotTests(test_web_shot.ShotFixture, TestCase):
    def shared(self):
        sub = self.host()  # www.rt.test, scanned, under the project's own (standard) target
        manual = Domain.objects.create(name='www.rt.test', project=self.project, insert_date=timezone.now(), discovery_mode=MANUAL)
        newest = Subdomain.objects.create(name='www.rt.test', target_domain=manual)
        newest.ip_addresses.add(*sub.ip_addresses.all())
        return sub, manual, newest

    def test_the_backfill_photographs_a_host_a_standard_target_also_holds(self):
        sub, manual, newest = self.shared()
        self.assertEqual(web_shot._current_row(self.project.id, 'www.rt.test').target_domain_id, self.domain.id)
        self.assertGreater(web_shot.backfill()['queued'], 0)
        self.assertTrue(HostScreenshot.objects.filter(project=self.project, host='www.rt.test').exists())

    def test_it_is_not_left_due_and_does_not_burn_a_backfill_slot_every_hour(self):
        self.shared()
        web_shot.backfill()
        HostScreenshot.objects.update(outcome='timeout', attempted_at=timezone.now() - timedelta(days=30))
        self.assertEqual(web_shot._due_names(self.project.id, 10, timezone.now()), ['www.rt.test'])  # due again: and it is queued, not skipped
        self.assertGreater(web_shot.backfill()['queued'], 0)

    def test_a_host_only_manual_only_targets_hold_is_not_due_for_a_new_picture(self):
        self.shared()
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        self.make_row(host='www.rt.test', outcome='timeout', attempted_at=timezone.now() - timedelta(days=30), domain=self.domain)
        self.assertEqual(web_shot._due_names(self.project.id, 10, timezone.now()), [])
        self.assertEqual(web_shot.backfill()['queued'], 0)

    def test_a_queued_page_of_a_shared_host_is_photographed(self):
        self.shared()
        HostScreenshot.objects.all().delete()
        self.make_row(host='www.rt.test', by_person=False)
        test_web_shot.FakeProxy.instances = []
        with mock.patch('cveFeed.web_shot._resolve', mock.Mock(return_value='203.0.113.5')):
            web_shot.drain(runner=test_web_shot.runner_for({}), proxy_factory=test_web_shot.FakeProxy)
        self.assertEqual(HostScreenshot.objects.get().outcome, 'ok')


class SubdirectoryVirtualHostLookupTests(test_subdir_apps.SubdirFixture, TestCase):
    def test_a_virtual_host_found_under_a_manual_only_target_is_not_asked(self):
        test_vhost_scan.vhost_scan.sweep(self.project.id, fetch=self.server, pace=test_vhost_scan.pace())
        names = {e['name'] for e in test_subdir_apps.subdir_apps.web_hosts(self.project.id)}
        self.assertIn('portal.example.test', names)  # control: found by the virtual host sweep, asked at its own address
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=MANUAL)
        self.assertEqual(test_subdir_apps.subdir_apps.web_hosts(self.project.id), [])
        self.assertEqual(self.run_subdirs()['hosts'], 0)
