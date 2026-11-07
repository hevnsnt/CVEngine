"""Questions to Celery's workers never block a page or run three times: the worker panel's answer comes from the shared cache (refreshed behind the
request), and the reaper asks the broker and the workers once per run, naming the workers that already answered."""
import time
from unittest import mock

from django.core.cache import cache
from django.test import TestCase

from cveFeed import broker_recovery, probe_cache


class CachedProbeTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_a_fresh_answer_is_served_without_asking_again(self):
        compute = mock.Mock(side_effect=['first', 'second'])
        self.assertEqual(probe_cache.cached_probe('t:fresh', compute, fresh=30)[0], 'first')
        self.assertEqual(probe_cache.cached_probe('t:fresh', compute, fresh=30)[0], 'first')
        self.assertEqual(compute.call_count, 1)

    def test_a_stale_answer_is_served_at_once_and_refreshed_in_the_background(self):
        compute = mock.Mock(side_effect=['old', 'new'])
        probe_cache.cached_probe('t:stale', compute, fresh=0.01)
        time.sleep(0.05)
        started = []
        with mock.patch.object(probe_cache.threading, 'Thread', side_effect=lambda target, **kw: mock.Mock(start=lambda: (started.append(1), target()))):
            value, _ = probe_cache.cached_probe('t:stale', compute, fresh=0.01)
        self.assertEqual(value, 'old')  # the caller did not wait for the new answer
        self.assertEqual((compute.call_count, started), (2, [1]))
        self.assertEqual(probe_cache.cached_probe('t:stale', compute, fresh=30)[0], 'new')

    def test_one_refresh_at_a_time(self):
        compute = mock.Mock(return_value='x')
        probe_cache.cached_probe('t:one', compute, fresh=0.01)
        time.sleep(0.05)
        cache.set('t:one:refreshing', 1, 60)  # another request is already asking
        with mock.patch.object(probe_cache.threading, 'Thread') as thread:
            probe_cache.cached_probe('t:one', compute, fresh=0.01)
        thread.assert_not_called()

    def test_a_probe_that_fails_is_not_cached(self):
        with self.assertRaises(OSError):
            probe_cache.cached_probe('t:fail', mock.Mock(side_effect=OSError('down')))
        self.assertEqual(probe_cache.cached_probe('t:fail', mock.Mock(return_value='up'))[0], 'up')


class WorkerPanelTests(TestCase):
    def inspector(self):
        inspector = mock.Mock()
        inspector.active_queues.return_value = {'cve_feed_worker@h': [{'name': 'cve_feed_queue'}]}
        inspector.active.return_value = {'cve_feed_worker@h': [{'args': 'secret'}, {}]}
        return inspector

    def test_the_second_look_asks_no_worker(self):
        from cveFeed import admin_api
        cache.clear()
        with mock.patch('reNgine.celery.app.control.inspect', return_value=self.inspector()) as inspect:
            first = admin_api.scheduler_health(None, mock.Mock(is_superuser=True))
            asked = inspect.call_count
            second = admin_api.scheduler_health(None, mock.Mock(is_superuser=True))
        self.assertEqual(inspect.call_count, asked)
        self.assertGreaterEqual(asked, 1)
        self.assertEqual(first['workers'], second['workers'])
        self.assertEqual(next(w for w in first['workers'] if w['worker'] == 'cve_feed_worker')['active'], 2)
        self.assertNotIn('secret', str(first))
        # the question about what each worker runs names the workers that already answered, so it does not wait out the timeout
        self.assertEqual(inspect.call_args_list[-1].kwargs.get('destination'), ['cve_feed_worker@h'])


class ReaperProbeTests(TestCase):
    def test_the_reaper_asks_the_workers_once_and_names_the_ones_that_answered(self):
        calls = []

        def inspect(timeout=1.0, destination=None, **kwargs):
            calls.append(destination)
            return mock.Mock(active=lambda: {'w@h': [{'id': 'a'}]}, reserved=lambda: {'w@h': []}, scheduled=lambda: {'w@h': []})
        with mock.patch('reNgine.celery.app.control.inspect', side_effect=inspect), mock.patch('reNgine.celery.app.connection_for_read') as conn:
            conn.return_value.__enter__.return_value.default_channel = mock.Mock(client=mock.Mock(llen=lambda n: 0, hvals=lambda k: []), unacked_key='unacked')
            with broker_recovery.shared_probe():
                first = broker_recovery.live_task_ids()
                second = broker_recovery.live_task_ids()
                third = broker_recovery.live_tasks()
        self.assertEqual((first, second), ({'a'}, {'a'}))
        self.assertEqual(third, ({'a'}, set()))
        self.assertEqual(calls, [None, ['w@h'], ['w@h']])  # one run: three questions, only the first waits for whoever answers
