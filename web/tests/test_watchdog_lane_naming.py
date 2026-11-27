"""R1 names itself and does not restart a lane that is alive (cveFeed.watchdog, cvengine.lane_memory).

On 11/15 the scanner host's watchdog had recreated the celery container 31 times since 11/9 and its log said only "restart-celery R1": the lane that was silent,
for how long, what the ping returned and why were not recorded. The database held the lane (the classic lane, queue empty, on every restart since 11/13), and the
lane's own records showed why that lane: a lane with nothing to do wrote no liveness record, so the proof of life the rule accepts from a busy lane (a task
finished lately, a task in flight with a fresh beat) never existed for an idle one.
"""
import json
import time
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase

from cveFeed import watchdog as wd
from cveFeed.models import WatchdogEvent
from cvengine import lane_memory as lm
from tests import test_watchdog as base

LANE_NAMES = ('discovery', 'cve_feed', 'validation_priority', 'classic')


def _clear_lane_records():
    for lane in LANE_NAMES:
        cache.delete(lm.RUNNING_PREFIX + lane)
        cache.delete(lm.CACHE_PREFIX + lane)


class NamingTests(base.WatchdogCase):
    def setUp(self):
        super().setUp()
        _clear_lane_records()
        self.addCleanup(_clear_lane_records)

    def silent_classic_restart(self):
        self.break_lanes('classic')
        self.probes.data['lanes'] = {n: q for n, q in base.LANES.items() if not n.startswith('classic')}
        self.probes.data['seconds'] = 6.5
        self.tick()
        self.tick(61)
        self.tick(61)
        self.tick(61)  # 183 seconds since the first miss
        return WatchdogEvent.objects.get(rule='R1', level='action', action='restart-celery')

    def test_the_restart_names_the_silent_lane_how_long_the_ping_and_the_reason(self):
        event = self.silent_classic_restart()
        report = event.detail['report']
        self.assertIn('silent lane: classic (queue 0 waiting)', report)
        self.assertIn('silent for 183 s over 4 checks in a row', report)
        self.assertIn('ping: no reply within 3 s from classic_worker', report)
        self.assertIn('replied: cve_feed_worker, discovery_worker, validation_priority_worker', report)
        self.assertIn('reason: no ping reply for the whole confirm time and no sign of life or work', report)
        self.assertEqual(event.detail['silent_seconds'], 183)
        self.assertEqual(event.detail['evidence']['absent'], ['classic_worker'])
        self.assertEqual(event.detail['evidence']['ping_seconds'], 3)
        self.assertTrue(event.result.startswith('Asked the host to carry it out. R1 restart-celery: silent lane: classic'))

    def test_the_report_goes_to_the_web_log_with_the_request_id_the_host_log_carries(self):
        with self.assertLogs('cveFeed.watchdog', level='WARNING') as logs:
            event = self.silent_classic_restart()
        line = next(line for line in logs.output if 'silent lane: classic' in line)
        self.assertIn(f'(request {event.detail["request"]})', line)

    def test_the_lanes_own_records_are_in_the_report(self):
        now = time.time()
        cache.set(lm.RUNNING_PREFIX + 'classic', json.dumps({'pid': 780, 'beat': now - 400, 'running': [{'name': 'cveFeed.tasks.openvas_sweep', 'since': now - 900}]}), 600)
        cache.set('lane_gc:classic', json.dumps({'last_s': 0.4, 'last_full_s': 4.6, 'worst_s': 6.4, 'frozen': 1, 'pid': 780, 'at': now}), 600)
        report = self.silent_classic_restart().detail['report']
        self.assertIn('classic liveness record: 400 s old, 1 task(s) in flight', report)
        self.assertIn('classic worst collection 6.4 s', report)

    def test_a_lane_with_no_record_says_so(self):
        self.assertIn('classic liveness record: none', self.silent_classic_restart().detail['report'])

    def test_the_host_request_is_unchanged(self):
        """The host script accepts the action name, the rule and an id and nothing else: the reason stays on the web side."""
        self.silent_classic_restart()
        self.assertEqual(set(self.request()), {'id', 'action', 'rule', 'at'})

    def test_the_count_of_checks_restarts_when_the_lane_answers(self):
        self.break_lanes('classic')
        self.probes.data['lanes'] = {n: q for n, q in base.LANES.items() if not n.startswith('classic')}
        self.tick()
        self.tick(61)
        self.assertEqual(self.state('R1').data['silent_checks'], 2)
        self.probes.data['lanes'] = dict(base.LANES)
        self.tick(61)
        self.assertEqual(self.state('R1').data['silent_checks'], 0)

    def test_a_check_that_could_not_ask_does_not_count_as_a_silent_lane(self):
        self.break_lanes('classic')
        self.probes.data['lanes'] = {n: q for n, q in base.LANES.items() if not n.startswith('classic')}
        self.tick()
        self.probes.data['lanes'] = RuntimeError('broker did not answer')
        self.tick(61)
        self.assertEqual(self.state('R1').data['silent_checks'], 1)


class BeatsTests(SimpleTestCase):
    def setUp(self):
        _clear_lane_records()
        self.addCleanup(_clear_lane_records)

    def test_beats_report_the_age_of_every_record_even_a_stale_one(self):
        cache.set(lm.RUNNING_PREFIX + 'classic', json.dumps({'pid': 7, 'beat': 1000.0, 'running': [{'name': 'a.b', 'since': 900.0}]}), 600)
        out = lm.beats(now=1500.0)
        self.assertEqual(out['classic'], {'age_seconds': 500, 'pid': 7, 'running': ['a.b']})
        self.assertNotIn('discovery', out)
        self.assertEqual(lm.in_flight(now=1500.0), {})  # in_flight still drops it: beats() is for the log, not for a decision

    def test_a_record_that_is_not_a_record_is_skipped(self):
        cache.set(lm.RUNNING_PREFIX + 'classic', 'not json', 600)
        cache.set(lm.RUNNING_PREFIX + 'discovery', json.dumps({'pid': 1}), 600)
        self.assertEqual(lm.beats(now=5.0), {})


class IdleLaneTests(base.WatchdogCase):
    """R1 must not take a lane that is only slow to answer for a lane that is gone, and must still catch one that is gone."""

    def setUp(self):
        super().setUp()
        _clear_lane_records()
        self.addCleanup(_clear_lane_records)
        self.break_lanes('classic')
        self.probes.data['lanes'] = {n: q for n, q in base.LANES.items() if not n.startswith('classic')}

    def beat(self, age=5, lane='classic', running=()):
        cache.set(lm.RUNNING_PREFIX + lane, json.dumps({'pid': 780, 'beat': time.time() - age, 'running': list(running)}), 600)

    def test_an_idle_lane_that_misses_every_ping_but_beats_is_not_restarted(self):
        """11/14: the classic lane, queue empty, missed the 3 s ping through a long collection and was recreated 13 times in two days. The longest collection measured stopped a lane 24.6 s."""
        self.beat(age=25)
        self.tick()
        self.tick(400)
        self.tick(400)
        self.assertIsNone(self.request())
        self.assertIn('alive', self.state('R1').status_text)
        self.assertIn('its own heartbeat is 25 seconds old', self.state('R1').status_text)

    def test_a_lane_that_is_dead_is_still_restarted_on_the_old_schedule(self):
        """No record at all: a worker that never wrote one, or whose container is gone."""
        self.tick()
        self.tick(179)
        self.assertIsNone(self.request())
        self.tick(2)
        self.assertEqual(self.request()['action'], 'restart-celery')

    def test_a_lane_whose_beat_stopped_is_restarted(self):
        """A worker that stalled or died: its beat is older than ALIVE_SECONDS, so the ping miss stands."""
        self.beat(age=lm.ALIVE_SECONDS + 30)
        self.tick()
        self.tick(181)
        self.assertEqual(self.request()['action'], 'restart-celery')
        self.assertIn('classic liveness record: 120 s old', WatchdogEvent.objects.get(rule='R1', level='action').detail['report'])

    def test_a_beat_alone_does_not_excuse_a_lane_that_answers_no_ping_for_fifteen_minutes(self):
        """Remote control down (a worker that consumes but never replies): the beat is fresh, the restart is what repairs it."""
        self.beat(age=5)
        self.tick()
        self.tick(wd.ALIVE_EXCUSE_SECONDS - 60)
        self.assertIsNone(self.request())
        self.tick(61)  # the excuse has run out: the usual three minutes of confirmation start now
        self.assertIsNone(self.request())
        self.tick(181)
        self.assertEqual(self.request()['action'], 'restart-celery')
        self.assertIn('remote control down', WatchdogEvent.objects.get(rule='R1', level='action').detail['report'])

    def test_the_fifteen_minutes_count_from_the_first_silent_check_of_this_run(self):
        self.beat(age=5)
        self.tick()
        self.tick(600)
        self.probes.data['lanes'] = dict(base.LANES)  # it answered once
        self.tick(30)
        self.assertNotIn('classic_worker', self.state('R1').data['silent_since'])
        self.probes.data['lanes'] = {n: q for n, q in base.LANES.items() if not n.startswith('classic')}
        self.tick(30)
        self.tick(600)  # 600 s into the new run, not 1260 s
        self.assertIsNone(self.request())

    def test_other_lanes_silent_are_judged_on_their_own_beat(self):
        self.beat(age=5)  # classic beats
        self.probes.data['lanes'] = {n: q for n, q in base.LANES.items() if n.startswith('discovery')}  # cve_feed, validation and classic silent
        self.tick()
        self.tick(181)
        report = WatchdogEvent.objects.get(rule='R1', level='action').detail['report']
        self.assertIn('cve_feed (queue', report)
        self.assertNotIn('silent lane: classic', report)


class IdleBeatTests(TestCase):
    def setUp(self):
        _clear_lane_records()
        self.addCleanup(_clear_lane_records)
        lm._state.update(lane=None, running={})

    def test_an_idle_worker_writes_a_record_that_lists_no_task(self):
        with mock.patch.object(lm, 'lane_name', return_value='classic'):
            self.assertTrue(lm.heartbeat_once(now=1000.0))
        self.assertEqual(lm.alive(now=1030.0), {'classic': 30})
        self.assertEqual(lm.in_flight(now=1030.0), {})

    def test_a_process_that_is_not_a_worker_writes_nothing(self):
        with mock.patch.object(lm, 'lane_name', return_value=''):
            self.assertFalse(lm.heartbeat_once(now=1000.0))
        self.assertEqual(lm.alive(now=1000.0), {})

    def test_alive_stops_at_the_limit_and_covers_the_longest_measured_collection(self):
        self.assertGreater(lm.ALIVE_SECONDS, lm.HEARTBEAT_SECONDS + 24.6)  # a beat missed during the worst collection seen is still inside the limit
        cache.set(lm.RUNNING_PREFIX + 'classic', json.dumps({'pid': 1, 'beat': 1000.0, 'running': []}), 600)
        self.assertEqual(lm.alive(now=1000.0 + lm.ALIVE_SECONDS), {'classic': lm.ALIVE_SECONDS})
        self.assertEqual(lm.alive(now=1000.0 + lm.ALIVE_SECONDS + 1), {})

    def test_alive_ignores_a_record_of_another_process(self):
        cache.set(lm.RUNNING_PREFIX + 'classic', json.dumps({'pid': 1, 'beat': 1000.0, 'running': []}), 600)
        self.assertEqual(lm.alive(now=1010.0, pids={'classic': {2}}), {})
        self.assertEqual(lm.alive(now=1010.0, pids={'classic': {1}}), {'classic': 10})

    def test_the_beat_starts_when_the_worker_is_ready_not_at_its_first_task(self):
        from celery.signals import worker_ready
        lm.install()
        with mock.patch.object(lm, 'record_start'), mock.patch.object(lm, 'reset'), mock.patch.object(lm, '_ensure_heartbeat') as started:
            worker_ready.send(sender=None)
        started.assert_called()
