"""Each worker lane reports its memory and the tasks it held it after (reNgine/lane_memory.py)."""
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase

from reNgine import lane_memory as lm


class LaneMemoryTests(SimpleTestCase):
    def setUp(self):
        lm._state.update(lane=None, started={}, tasks={}, last_write=0.0, peak_mb=0.0)
        for lane in lm.LANES:
            cache.delete(lm.CACHE_PREFIX + lane)

    def test_the_lane_comes_from_the_workers_name(self):
        self.assertEqual(lm.lane_name(['celery', 'worker', '-n', 'cve_feed_worker']), 'cve_feed')
        self.assertEqual(lm.lane_name(['celery', '--hostname=classic_worker@h']), 'classic')
        self.assertEqual(lm.lane_name(['manage.py', 'test']), '')

    def test_a_finished_task_is_recorded_with_its_growth_and_the_report_ranks_it(self):
        sizes = iter([100.0, 100.0, 400.0, 400.0])
        with mock.patch.object(lm, 'rss_mb', side_effect=lambda: next(sizes)), mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.before('a')                 # 100
            lm.before('b')                 # 100
            lm.after('a', 'cveFeed.tasks.big', now=1000.0)   # 400: grew 300
            lm.after('b', 'cveFeed.tasks.small', now=1001.0)  # 400: grew 300 as well, but within the write interval
        rows = lm.report(now=1030.0)
        self.assertEqual([r['lane'] for r in rows], ['cve_feed'])
        self.assertEqual(rows[0]['rss_mb'], 400.0)
        self.assertEqual(rows[0]['by_size'][0], {'task': 'cveFeed.tasks.big', 'runs': 1, 'max_rss_mb': 400.0})
        self.assertEqual(rows[0]['by_growth'][0]['max_growth_mb'], 300.0)
        self.assertEqual(rows[0]['age_seconds'], 30)

    def test_a_cache_that_fails_never_fails_the_task(self):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='classic'), \
                mock.patch('django.core.cache.cache.set', side_effect=OSError('redis down')):
            lm.before('x')
            lm.after('x', 't', now=5000.0)  # must not raise

    def test_the_system_status_carries_the_lanes(self):
        from agentapi import system_status
        with mock.patch('reNgine.resources.cluster_snapshot', return_value={'store': 'redis', 'containers': []}), \
                mock.patch('reNgine.lane_memory.report', return_value=[{'lane': 'classic', 'rss_mb': 1.0}]):
            self.assertEqual(system_status._memory()['lanes'], [{'lane': 'classic', 'rss_mb': 1.0}])


class ProgressTests(SimpleTestCase):
    def setUp(self):
        for lane in lm.LANES:
            cache.delete(lm.CACHE_PREFIX + lane)

    def test_a_lane_that_finished_a_task_a_moment_ago_is_working(self):
        import json
        cache.set(lm.CACHE_PREFIX + 'cve_feed', json.dumps({'pid': 1, 'at': 1000.0, 'rss_mb': 5, 'peak_mb': 5, 'tasks': {}}), 600)
        cache.set(lm.CACHE_PREFIX + 'classic', json.dumps({'pid': 2, 'at': 800.0, 'rss_mb': 5, 'peak_mb': 5, 'tasks': {}}), 600)
        self.assertEqual(lm.recent_progress(now=1030.0), {'cve_feed': 30})  # classic last finished 230 s ago: not evidence of anything


class InFlightTests(SimpleTestCase):
    """A lane running one long task writes nothing when it ends, so the start of a task is recorded (the watchdog took such a lane for a dead one)."""

    def setUp(self):
        lm._state.update(lane=None, started={}, running={}, tasks={}, last_write=0.0, peak_mb=0.0)
        for lane in lm.LANES:
            cache.delete(lm.RUNNING_PREFIX + lane)

    def test_a_task_that_started_is_in_flight_until_it_ends(self):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.before('a', 'cveFeed.tasks.port_load', now=1000.0)
            lm.heartbeat_once(now=1470.0)  # a worker with a task running keeps beating (a record nobody refreshes is ignored)
            self.assertEqual(lm.in_flight(now=1480.0), {'cve_feed': 480})
            lm.after('a', 'cveFeed.tasks.port_load', now=1500.0)
        self.assertEqual(lm.in_flight(now=1501.0), {})

    def test_the_youngest_running_task_sets_the_age(self):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='classic'):
            lm.before('a', 't1', now=1000.0)
            lm.before('b', 't2', now=1900.0)
            lm.heartbeat_once(now=1990.0)
        self.assertEqual(lm.in_flight(now=2000.0), {'classic': 100})

    def test_a_task_running_longer_than_the_ceiling_is_no_longer_evidence_of_life(self):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='classic'):
            lm.before('a', 't1', now=1000.0)
        self.assertEqual(lm.in_flight(now=1000.0 + lm.IN_FLIGHT_MAX_SECONDS + 1), {})

    def test_a_cache_that_fails_never_fails_the_task_start(self):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='classic'), \
                mock.patch('django.core.cache.cache.set', side_effect=OSError('redis down')):
            lm.before('x', 't', now=5000.0)  # must not raise


class LivenessTests(SimpleTestCase):
    """The in-flight record needs a sign that the worker that wrote it is alive: a heartbeat it keeps writing while a task runs, and its process id."""

    def setUp(self):
        lm._state.update(lane=None, started={}, running={}, tasks={}, last_write=0.0, peak_mb=0.0)
        for lane in lm.LANES:
            cache.delete(lm.RUNNING_PREFIX + lane)

    def _start(self, now, lane='cve_feed'):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value=lane), mock.patch.object(lm, '_ensure_heartbeat'):
            lm.before('a', 'cveFeed.tasks.port_load', now=now)

    def test_a_record_whose_heartbeat_is_three_minutes_old_is_not_busy(self):
        self._start(1000.0)
        self.assertEqual(lm.in_flight(now=1000.0 + 60), {'cve_feed': 60})
        self.assertEqual(lm.in_flight(now=1000.0 + 180), {})  # no beat for 3 minutes: the worker that wrote it is gone

    def test_a_task_started_forty_five_minutes_ago_with_a_fresh_heartbeat_is_busy(self):
        self._start(1000.0)
        later = 1000.0 + 45 * 60
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.write_running(now=later - 10)  # the heartbeat
        self.assertEqual(lm.in_flight(now=later), {'cve_feed': 45 * 60})

    def test_a_heartbeating_task_older_than_the_ceiling_is_no_longer_evidence(self):
        self._start(1000.0)
        later = 1000.0 + lm.IN_FLIGHT_MAX_SECONDS + 60
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.write_running(now=later - 10)
        self.assertEqual(lm.in_flight(now=later), {})

    def test_a_record_written_by_a_process_that_is_not_the_answering_worker_is_not_busy(self):
        self._start(1000.0)
        me = lm.os.getpid()
        self.assertEqual(lm.in_flight(now=1010.0, pids={'cve_feed': {me}}), {'cve_feed': 10})
        self.assertEqual(lm.in_flight(now=1010.0, pids={'cve_feed': {me + 1}}), {})  # a new worker answers under another pid: the record is a dead process's
        self.assertEqual(lm.in_flight(now=1010.0, pids={'classic': {me + 1}}), {'cve_feed': 10})  # another lane's pids say nothing about this one

    def test_a_record_with_no_heartbeat_is_not_trusted(self):
        cache.set(lm.RUNNING_PREFIX + 'classic', lm.json.dumps({'pid': 1, 'running': [{'name': 't', 'since': 990.0}]}), 600)  # the format before the heartbeat
        self.assertEqual(lm.in_flight(now=1000.0), {})

    def test_the_heartbeat_keeps_writing_while_a_task_runs_and_stops_when_none_does(self):
        self._start(1000.0)
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            self.assertTrue(lm.heartbeat_once(now=1030.0))
            self.assertEqual(lm.in_flight(now=1100.0), {'cve_feed': 100})  # beat at 1030: fresh at 1100
            lm._state['running'].clear()
            self.assertFalse(lm.heartbeat_once(now=1060.0))

    def test_a_task_that_blocks_the_worker_without_yielding_loses_its_protection(self):
        # the hub is stalled, so the heartbeat greenlet never runs: the last beat is the one written at the start
        self._start(1000.0)
        self.assertEqual(lm.in_flight(now=1000.0 + lm.BEAT_STALE_SECONDS), {'cve_feed': lm.BEAT_STALE_SECONDS})
        self.assertEqual(lm.in_flight(now=1000.0 + lm.BEAT_STALE_SECONDS + 1), {})  # the record is ignored, like a hung worker's

    def test_a_ghost_entry_whose_postrun_never_fired_is_bounded_by_the_ceiling(self):
        self._start(1000.0)  # a task that started and never reported its end: the beat goes on for as long as the process lives
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            for beat in range(1030, 1000 + lm.IN_FLIGHT_MAX_SECONDS + 3600, 600):
                lm.heartbeat_once(now=float(beat))
            self.assertTrue(lm._state['running'])  # still a ghost, still beating
            just_inside = 1000.0 + lm.IN_FLIGHT_MAX_SECONDS - 60
            lm.heartbeat_once(now=just_inside - 5)
            self.assertEqual(lm.in_flight(now=just_inside), {'cve_feed': lm.IN_FLIGHT_MAX_SECONDS - 60})
            past = 1000.0 + lm.IN_FLIGHT_MAX_SECONDS + 60
            lm.heartbeat_once(now=past - 5)
            self.assertEqual(lm.in_flight(now=past), {})  # beating, but past the twelve hour ceiling

    def test_the_first_task_starts_one_heartbeat_thread(self):
        lm._state['beat_thread'] = None
        with mock.patch.object(lm.threading, 'Thread') as thread, mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='classic'):
            lm.before('a', 't', now=1000.0)
            lm.before('b', 't', now=1001.0)
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()
        lm._state['beat_thread'] = None

    def test_a_worker_that_shuts_down_cleanly_clears_its_record(self):
        self._start(1000.0)
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.reset()
        self.assertEqual(lm.in_flight(now=1001.0), {})


class HeartbeatThreadTests(SimpleTestCase):
    """The heartbeat thread must not touch ``time.sleep`` (tests patch it globally, and a call from this thread landed in their mock: it advanced a fake clock
    and tripped the "a test slept for real" guard), and must not run at all outside a Celery worker (an eager task in a test process fires the same hook)."""
    def setUp(self):
        lm._state.update(lane=None, running={}, beat_thread=None)
        self.addCleanup(lm.stop)
        self.addCleanup(lm._state.update, beat_thread=None)

    def test_the_loop_never_calls_time_sleep_while_it_beats(self):
        import time
        beats = []
        lm._state['running']['t'] = {'name': 'x', 'since': 0}
        with mock.patch.object(time, 'sleep') as slept, mock.patch.object(lm, 'HEARTBEAT_SECONDS', 0.01), mock.patch.object(lm, 'lane_name', return_value='classic'), \
                mock.patch.object(lm, 'heartbeat_once', side_effect=lambda *a: beats.append(1)):
            lm._ensure_heartbeat()
            deadline = time.monotonic() + 5
            while len(beats) < 3 and time.monotonic() < deadline:
                lm._stop.wait(0.01)
            lm.stop()
        self.assertGreaterEqual(len(beats), 3)
        slept.assert_not_called()

    def test_outside_a_worker_no_thread_is_started(self):
        with mock.patch.object(lm, 'lane_name', return_value=''):
            lm.before('eager-task', 'some.task')
        self.assertIsNone(lm._state['beat_thread'])
