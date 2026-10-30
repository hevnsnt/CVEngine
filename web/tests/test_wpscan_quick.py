"""A WordPress site the scan's own WPScan stage cannot reach in time is queued as its own background job, not left for the next scan."""
from unittest import mock

from django.test import TestCase

from cveFeed import wpscan_scan
from cveFeed.models import ProbeObservation
from reNgine import resources
from tests.test_probes import page
from tests.test_wordpress import LINK, WordPressFixture, PLUGIN_REPORT

WP = {'/wp-login.php': page(200, headers=LINK, body='<form id="loginform">')}


class QuickQueueTests(WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.table = dict(WP)
        self.queued = []

    def queue(self, scan, hosts, attempt=0, dispatch=True):
        self.queued.append((sorted(hosts), attempt, dispatch))
        return sorted(hosts)

    def busy_runner(self, url, token):
        raise resources.MemoryBusy('no memory')

    def test_hosts_that_met_no_memory_are_queued_not_left_for_the_next_scan(self):
        with mock.patch.object(wpscan_scan, 'queue_quick', self.queue):
            out = self.go(runner=self.busy_runner)
        self.assertEqual(out['scanned'], 0)
        self.assertTrue(self.queued)
        self.assertTrue({'www.rt.test'} <= set(self.queued[0][0]))
        self.assertEqual(self.queued[0][1], 0)

    def test_a_stopped_scan_queues_nothing_behind_the_person_who_stopped_it(self):
        def stopped(url, token):
            raise resources.ScanAborted('stopped')
        with mock.patch.object(wpscan_scan, 'queue_quick', self.queue):
            self.go(runner=stopped)
        self.assertEqual([q for q in self.queued if q[0]], [])

    def test_a_site_over_the_per_scan_limit_is_queued(self):
        with mock.patch.object(wpscan_scan, 'queue_quick', self.queue), mock.patch.object(wpscan_scan, 'max_sites', return_value=1):
            self.go()
        scanned = {u.split('//')[1] for u, _t in self.calls}
        queued = {h for q in self.queued for h in q[0]}
        self.assertEqual(len(scanned), 1)  # all three names probe positive: one is scanned, the other two are queued, none twice
        self.assertEqual(len(queued), 2)
        self.assertFalse(scanned & queued)

    def test_a_scanned_site_is_not_queued(self):
        with mock.patch.object(wpscan_scan, 'queue_quick', self.queue):
            self.go()
        self.assertEqual([q for q in self.queued if q[0]], [])

    def test_only_limits_a_run_to_the_queued_hosts(self):
        out = self.go(only={'rt.test'})
        self.assertEqual({u for u, _t in self.calls}, {'https://rt.test'})
        self.assertEqual(out['scanned'], 1)


class QueueQuickTests(WordPressFixture, TestCase):
    def test_it_marks_the_hosts_queued_and_starts_the_task_a_little_later_each_attempt(self):
        with mock.patch('cveFeed.tasks.wpscan_quick.apply_async') as start:
            queued = wpscan_scan.queue_quick(self.scan_obj, ['www.rt.test', 'rt.test'], attempt=1)
        self.assertEqual(queued, ['rt.test', 'www.rt.test'])
        _args, kwargs = start.call_args
        self.assertEqual(kwargs['args'], [self.scan_obj.id, ['rt.test', 'www.rt.test'], 2])
        self.assertEqual((kwargs['countdown'], kwargs['queue']), (wpscan_scan.QUICK_DELAY * 2, wpscan_scan.THOROUGH_QUEUE))
        self.assertEqual(self.state('www.rt.test')['state'], 'queued')

    def test_the_attempts_are_bounded_and_the_host_stays_waiting(self):
        with mock.patch('cveFeed.tasks.wpscan_quick.apply_async') as start:
            self.assertEqual(wpscan_scan.queue_quick(self.scan_obj, ['www.rt.test'], attempt=wpscan_scan.QUICK_ATTEMPTS), [])
        start.assert_not_called()

    def test_a_broker_that_is_down_leaves_the_hosts_waiting_for_the_next_scan(self):
        with mock.patch('cveFeed.tasks.wpscan_quick.apply_async', side_effect=OSError('broker down')):
            self.assertEqual(wpscan_scan.queue_quick(self.scan_obj, ['www.rt.test']), [])
        self.assertFalse(ProbeObservation.objects.filter(host='www.rt.test', probe='wpscan', variant='queued').exists())

    def test_nothing_is_started_when_dispatch_is_off(self):
        with mock.patch('cveFeed.tasks.wpscan_quick.apply_async') as start:
            self.assertEqual(wpscan_scan.queue_quick(self.scan_obj, ['www.rt.test'], dispatch=False), [])
        start.assert_not_called()


class RunQuickTests(WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.table = dict(WP)

    def test_it_runs_the_stage_for_just_the_queued_hosts(self):
        out = wpscan_scan.run_quick(self.scan_obj.id, ['rt.test'], attempt=1, runner=self.runner, probe_get=self.probe_get, sleep=lambda s: None)
        self.assertNotIn('skipped', out)
        self.assertEqual({u for u, _t in self.calls}, {'https://rt.test'})

    def test_a_paused_installation_queues_the_hosts_again(self):
        with mock.patch.object(resources, 'global_pause_requested', return_value=True), mock.patch.object(wpscan_scan, 'queue_quick') as again:
            out = wpscan_scan.run_quick(self.scan_obj.id, ['rt.test'], attempt=1)
        self.assertIn('paused', out['skipped'])
        again.assert_called_once()

    def test_a_scan_that_is_gone_is_skipped(self):
        self.assertEqual(wpscan_scan.run_quick(0, ['rt.test']), {'skipped': 'the scan is gone'})
