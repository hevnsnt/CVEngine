"""Certificate transparency lookups run on their own queue and never sit in a worker slot waiting for crt.sh's shared pacing."""
import os
from unittest import mock

from celery.exceptions import Retry
from django.test import SimpleTestCase

from agentapi import system_status
from cveFeed import ctmonitor, tasks
from reNgine import time_limits


class QueueTests(SimpleTestCase):
    def test_the_watch_runs_on_its_own_queue_which_a_worker_consumes(self):
        self.assertEqual(tasks.watch_certificate_transparency.queue, 'ctwatch_queue')
        self.assertIn('ctwatch_queue', system_status.QUEUES)
        entry = open(os.path.join(os.path.dirname(__file__), '..', 'celery-entrypoint.sh')).read()
        self.assertIn(',ctwatch_queue"', entry)
        self.assertIsNotNone(time_limits.limits_for('ctwatch_queue'))

    def test_the_sweep_that_queues_the_watches_stays_on_the_feed_queue(self):
        self.assertEqual(tasks.watch_certificates_all.queue, 'cve_feed_queue')


class PacingTests(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch.object(ctmonitor, '_redis', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        ctmonitor._local['next'] = 0.0
        self.addCleanup(ctmonitor._local.update, {'next': 0.0})

    def test_the_wait_for_a_slot_is_read_without_taking_one(self):
        ctmonitor.push_back(90, now=lambda: 1000.0)
        self.assertEqual(ctmonitor.wait_for_slot(now=lambda: 1000.0), 90.0)
        self.assertEqual(ctmonitor.wait_for_slot(now=lambda: 1000.0), 90.0)  # asking again did not move it

    def test_a_long_wait_goes_back_to_the_queue_instead_of_sleeping_in_the_slot(self):
        ctmonitor.push_back(500, now=lambda: __import__('time').time())
        slept = []
        with mock.patch('requests.get') as get:
            with self.assertRaises(ctmonitor.CtBusy) as busy:
                ctmonitor._fetch('rt.test', sleep=slept.append)
        self.assertGreater(busy.exception.wait, ctmonitor.MAX_INLINE_WAIT)
        self.assertEqual(slept, [])
        get.assert_not_called()

    def test_a_short_wait_is_slept_in_place(self):
        slept = []
        response = mock.Mock(status_code=200)
        with mock.patch('requests.get', return_value=response), mock.patch.object(ctmonitor, '_read_json', return_value=[]):
            ctmonitor._fetch('rt.test', sleep=slept.append)
        self.assertEqual(len(slept), 1)
        self.assertLessEqual(slept[0], ctmonitor.MAX_INLINE_WAIT)

    def test_crt_sh_asking_everyone_to_slow_down_frees_the_slot_for_that_long(self):
        slept = []
        throttled = mock.Mock(status_code=429, headers={'Retry-After': '100'})
        with mock.patch('requests.get', return_value=throttled):
            with self.assertRaises(ctmonitor.CtBusy) as busy:
                ctmonitor._fetch('rt.test', sleep=slept.append)  # the 429 sets the shared backoff; the next attempt would wait longer than a moment
        self.assertGreater(busy.exception.wait, ctmonitor.MAX_INLINE_WAIT)
        self.assertLessEqual(sum(slept), 5)


class TaskTests(SimpleTestCase):
    def test_a_busy_pacing_retries_the_task_later_without_failing_it(self):
        with mock.patch('cveFeed.ctmonitor.run_ct_watch', side_effect=ctmonitor.CtBusy(120.0)), \
                mock.patch.object(tasks.watch_certificate_transparency, 'retry', side_effect=Retry()) as retry:
            with self.assertRaises(Retry):
                tasks.watch_certificate_transparency.run(7)
        kwargs = retry.call_args.kwargs
        self.assertGreaterEqual(kwargs['countdown'], 121)
        self.assertLessEqual(kwargs['countdown'], 180)
        self.assertIsNone(kwargs['max_retries'])  # waiting for the pacing is not a failure, so it does not use up the retries
