"""One request that adds hundreds of targets queues the first batch for discovery and leaves the rest to the work conductor."""
import os
from unittest import mock

from django.test import SimpleTestCase

from agentapi import services


class DiscoverNewTests(SimpleTestCase):
    def run_it(self, count, env=None, depth=3):
        domains = [mock.Mock(id=i) for i in range(count)]
        env = {k: v for k, v in (env or {}).items()}
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(services, '_start_discoveries', side_effect=lambda d, *a, **k: list(d)) as start, \
                mock.patch('cveFeed.conductor.wanted_depth', return_value=depth), mock.patch('cveFeed.activity.log') as log:
            scans, deferred = services._discover_new(domains, 'standard', 7, initiated_by='someone')
        return scans, deferred, start, log

    def test_a_small_add_is_queued_whole(self):
        scans, deferred, start, log = self.run_it(30)
        self.assertEqual((len(scans), deferred), (30, 0))
        log.assert_not_called()

    def test_a_big_add_queues_the_first_batch_and_defers_the_rest_with_a_line_in_the_activity(self):
        scans, deferred, start, log = self.run_it(812)
        self.assertEqual((len(scans), deferred), (services.BULK_DISCOVER_NOW, 812 - services.BULK_DISCOVER_NOW))
        self.assertEqual([d.id for d in scans], list(range(services.BULK_DISCOVER_NOW)))  # the first ones, in order
        self.assertIn('work conductor', log.call_args.args[1])

    def test_who_asked_is_recorded_on_the_scans(self):
        _, _, start, _ = self.run_it(5)
        self.assertEqual(start.call_args.kwargs['initiated_by'], 'someone')

    def test_the_batch_size_is_set_from_the_environment(self):
        scans, deferred, *_ = self.run_it(40, env={'CVENGINE_BULK_DISCOVER_NOW': '10'})
        self.assertEqual((len(scans), deferred), (10, 30))

    def test_a_bad_setting_falls_back_to_the_default(self):
        scans, deferred, *_ = self.run_it(80, env={'CVENGINE_BULK_DISCOVER_NOW': 'lots'})
        self.assertEqual(len(scans), services.BULK_DISCOVER_NOW)

    def test_with_the_conductor_off_nothing_would_pick_the_rest_up_so_everything_is_queued(self):
        scans, deferred, *_ = self.run_it(200, depth=0)
        self.assertEqual((len(scans), deferred), (200, 0))


class AlreadyQueuedTests(SimpleTestCase):
    def test_scans_the_project_already_has_waiting_count_against_the_batch(self):
        domains = [mock.Mock(id=i) for i in range(60)]
        with mock.patch.object(services, '_start_discoveries', side_effect=lambda d, *a, **k: list(d)), mock.patch('cveFeed.conductor.wanted_depth', return_value=3), \
                mock.patch('cveFeed.activity.log'), mock.patch('startScan.models.ScanHistory.objects') as scans:
            scans.filter.return_value.count.return_value = 40
            queued, deferred = services._discover_new(domains, 'standard', 7)
        self.assertEqual((len(queued), deferred), (services.BULK_DISCOVER_NOW - 40, 60 - (services.BULK_DISCOVER_NOW - 40)))

    def test_a_project_already_at_the_batch_size_queues_none_now(self):
        domains = [mock.Mock(id=i) for i in range(5)]
        with mock.patch.object(services, '_start_discoveries') as start, mock.patch('cveFeed.conductor.wanted_depth', return_value=3), \
                mock.patch('cveFeed.activity.log'), mock.patch('startScan.models.ScanHistory.objects') as scans:
            scans.filter.return_value.count.return_value = services.BULK_DISCOVER_NOW + 10
            queued, deferred = services._discover_new(domains, 'standard', 7)
        self.assertEqual((queued, deferred), ([], 5))
        start.assert_not_called()
