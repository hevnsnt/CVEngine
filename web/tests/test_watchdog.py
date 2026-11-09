"""The outer watchdog (cveFeed.watchdog): the snapshot, each rule R1 to R9, hysteresis, the rate limits, standing down during an update, the check after an
action and the flap guard (R10), the switches, the host request files, and a tick that never raises and always ends in time. Redis, Celery and Docker are
fakes: nothing here talks to a broker or a container."""
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from cveFeed import scan_concurrency as sc
from cveFeed import watchdog as wd
from cveFeed import watchdog_snapshot as snap_mod
from cveFeed.models import AdminAlert, ScanConcurrency, ScanControl, WatchdogEvent, WatchdogState

T0 = datetime(2026, 11, 8, 18, 0, 0, tzinfo=dt_timezone.utc)
LANES = {'discovery_worker@c': ['discovery_queue'], 'cve_feed_worker@c': ['cve_feed_queue'],
         'validation_priority_worker@c': ['validation_priority_queue'], 'classic_worker@c': ['api_queue']}


def healthy():
    return {
        'queues': {'discovery_queue': 0, 'cve_feed_queue': 0, 'validation_priority_queue': 0, 'api_queue': 0, 'default': 0},
        'unacked': {'count': 0, 'oldest_age_seconds': 0},
        'lanes': dict(LANES),
        'lane_work': {},
        'beat_age': 5,
        'conductor': {'age_seconds': 30},
        'sentinels': {'slots': 4, 'busy': 4, 'free': 0, 'waiting': 3, 'due': None},
        'discovery': {'value': 8, 'source': 'default', 'env_name': 'DISCOVERY_CONCURRENCY', 'env_value': None, 'env_pinned': False, 'floor': 4, 'saved_by': None, 'running': 8},
        'assessments': 0,
        'db': {'connections': 20, 'max': 200, 'idle_in_transaction_seconds': 0},
        'disk': {'free_mb': 200000, 'total_mb': 400000, 'free_pct': 50.0},
        'memory': [{'host': 'celery', 'used_pct': 40.0}],
        'scans': {'running': 1, 'queued': 0, 'stale_candidates': 0},
        'update': {'phase': 'idle', 'approved': False, 'locked': False, 'active': False},
    }


class FakeRedis:
    def __init__(self):
        self.unacked, self.held, self.kv = {}, {}, {}

    def ping(self):
        return True

    def zrangebyscore(self, key, lo, hi):
        return [t for t, (score, raw) in self.unacked.items() if score <= float(hi)]

    def hget(self, key, tag):
        return self.unacked[tag][1] if tag in self.unacked else None

    def set(self, key, value, ex=None):
        self.kv[key] = value


class FakeProbes:
    """Every probe returns its entry of ``data`` (an Exception instance is raised, a callable is called)."""

    def __init__(self, **over):
        self.data = healthy()
        self.data.update(over)
        self.client = FakeRedis()

    def redis(self):
        if self.data.get('queues') is None:
            raise ConnectionError('redis down')
        return self.client

    def __getattr__(self, name):
        if name.startswith('_') or name not in self.data and name not in snap_mod.SECTIONS + ('lane_work',):
            raise AttributeError(name)

        def probe(*args, **kwargs):
            value = self.data.get(name)
            if isinstance(value, Exception):
                raise value
            return value() if callable(value) else value
        return probe


class WatchdogCase(TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.home, ignore_errors=True))
        p = override_settings(RENGINE_HOME=str(self.home), BASE_DIR=str(self.home))
        p.enable()
        self.addCleanup(p.disable)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('CVENGINE_WATCHDOG', None)
        os.environ.pop('DISCOVERY_CONCURRENCY', None)
        self.probes = FakeProbes()
        self.t = T0

    def tick(self, seconds=0, probes=None, **over):
        self.t = self.t + timedelta(seconds=seconds)
        if over:
            self.probes.data.update(over)
        return wd.tick(now=self.t, probes=probes or self.probes, alarm=False)

    def state(self, rule):
        return WatchdogState.objects.get(rule=rule)

    def break_lanes(self, *gone):
        lanes = {n: q for n, q in LANES.items() if not any(n.startswith(g) for g in (gone or ('cve_feed', 'validation_priority', 'classic')))}
        self.probes.data['lanes'] = lanes
        self.probes.data['queues'] = {**self.probes.data['queues'], 'cve_feed_queue': 313, 'discovery_queue': 1317}

    def request(self):
        path = self.home / wd.ACTION_FILE
        return json.loads(path.read_text()) if path.exists() else None

    def host_answers(self, ok=True, at=None):
        req = self.request()
        (self.home / wd.ACTION_FILE).unlink()
        (self.home / wd.RESULT_FILE).write_text(json.dumps({'id': req['id'], 'action': req['action'], 'ok': ok, 'at': (at or self.t).timestamp(), 'detail': 'done'}))
        return req


class SnapshotTests(WatchdogCase):
    def test_a_probe_that_raises_becomes_none_and_never_stops_the_others(self):
        probes = FakeProbes(lanes=RuntimeError('boom'), disk=OSError('gone'))
        snap = snap_mod.collect(probes)
        self.assertIsNone(snap['lanes'])
        self.assertIsNone(snap['disk'])
        self.assertEqual(snap['beat_age'], 5)
        self.assertIn('lanes', snap['errors'])
        self.assertTrue(snap['redis_ok'])

    def test_redis_down_means_redis_ok_false(self):
        snap = snap_mod.collect(FakeProbes(queues=ConnectionError('x')))
        self.assertFalse(snap['redis_ok'])

    def test_lane_status_names_the_missing_lanes(self):
        snap = {'lanes': {'discovery_worker@c': ['discovery_queue'], 'classic_worker@c': ['api_queue']}}
        status = snap_mod.lane_status(snap)
        self.assertTrue(status['discovery_worker']['present'])
        self.assertFalse(status['cve_feed_worker']['present'])
        self.assertIsNone(snap_mod.lane_status({'lanes': None})['classic_worker']['present'])

    def test_a_worker_that_does_not_consume_its_queue_is_not_the_lane(self):
        snap = {'lanes': {'cve_feed_worker@c': ['discovery_queue']}}
        self.assertFalse(snap_mod.lane_status(snap)['cve_feed_worker']['present'])

    def test_the_real_probes_report_unreachable_services_as_none(self):
        with mock.patch.dict(os.environ, {'CELERY_BROKER': 'redis://127.0.0.1:1/0'}), mock.patch('reNgine.celery.app.control.inspect', side_effect=OSError('no broker')):
            snap = snap_mod.collect(snap_mod.Probes())
        self.assertIsNone(snap['queues'])
        self.assertIsNone(snap['lanes'])
        self.assertFalse(snap['redis_ok'])


class R1LanesTests(WatchdogCase):
    def test_healthy_instance_does_nothing(self):
        out = self.tick()
        self.assertTrue(out['ok'])
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R1').status, 'ok')
        self.assertEqual(WatchdogEvent.objects.exclude(level='info').count(), 0)

    def test_three_missing_lanes_are_only_watched_until_three_minutes(self):
        self.break_lanes()
        self.tick()
        self.assertEqual(self.state('R1').status, 'watching')
        self.tick(179)
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R1').status, 'watching')
        self.tick(2)  # 181 seconds since first seen
        self.assertEqual(self.request()['action'], 'restart-celery')
        self.assertEqual(self.request()['rule'], 'R1')
        self.assertEqual(self.state('R1').status, 'acting')
        self.assertTrue(WatchdogEvent.objects.filter(rule='R1', level='action').exists())

    def test_the_symptom_going_away_resets_the_clock(self):
        self.break_lanes()
        self.tick()
        self.tick(120)
        self.probes.data['lanes'] = dict(LANES)
        self.tick(30)
        self.assertIsNone(self.state('R1').fire_since)
        self.break_lanes()
        self.tick(30)
        self.tick(100)  # 100 seconds since the second first-seen: not enough
        self.assertIsNone(self.request())

    def test_one_missing_lane_is_enough(self):
        self.break_lanes('cve_feed')
        self.probes.data['lanes'] = {n: q for n, q in LANES.items() if not n.startswith('cve_feed')}
        self.tick()
        self.tick(181)
        self.assertEqual(self.request()['action'], 'restart-celery')

    def test_redis_down_is_not_a_lane_problem(self):
        self.probes.data['queues'] = ConnectionError('down')
        self.probes.data['lanes'] = RuntimeError('down')
        self.tick()
        self.tick(600)
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R1').status, 'unknown')

    def test_no_worker_answering_while_redis_is_up_counts_as_all_lanes_missing(self):
        self.probes.data['lanes'] = {}
        self.tick()
        self.tick(200)
        self.assertEqual(self.request()['action'], 'restart-celery')

    def test_fixed_after_the_action_is_verified_two_minutes_after_the_host_finished(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers()
        self.probes.data['lanes'] = dict(LANES)
        self.tick(30)  # reads the host answer; the check is due at host time + 120 s
        self.assertEqual(self.state('R1').status, 'acting')
        self.tick(60)
        self.assertEqual(self.state('R1').status, 'acting')
        self.tick(70)
        self.assertEqual(self.state('R1').status, 'ok')
        fixed = WatchdogEvent.objects.get(rule='R1', level='fixed')
        self.assertIn('Verified', fixed.result)
        alert = AdminAlert.objects.get(code='watchdog_r1', resolved_at__isnull=True)
        self.assertEqual(alert.severity, 'info')
        self.assertIn('stopped answering at {{time:2026-11-08T18:00:00Z}}', alert.title)
        self.assertIn('they answer again', alert.title)

    def test_not_fixed_escalates_once_and_stops_for_an_hour(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers()
        self.tick(30)
        self.tick(125)  # check due, symptom still there
        self.assertEqual(self.state('R1').status, 'problem')
        alert = AdminAlert.objects.get(code='watchdog_r1', resolved_at__isnull=True)
        self.assertEqual(alert.severity, 'critical')
        self.assertIn('docker compose restart celery', alert.title)
        self.assertEqual(WatchdogEvent.objects.filter(rule='R1', level='problem').count(), 1)
        for _ in range(40):  # 40 more minutes of the same symptom: nothing more is asked
            self.tick(60)
            self.assertIsNone(self.request())
        self.assertEqual(self.state('R1').status, 'problem')
        self.assertEqual(AdminAlert.objects.filter(code='watchdog_r1').count(), 1)

    def test_after_the_hold_ends_it_may_try_again_within_the_daily_cap(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers()
        self.tick(30)
        self.tick(125)
        self.assertIsNone(self.request())
        self.tick(3600)
        self.tick(5)
        self.assertIsNotNone(self.request())

    def test_four_a_day_then_no_more(self):
        self.break_lanes()
        state_actions = []
        for _ in range(4):
            self.tick(1000)
            self.tick(1000)
            if self.request():
                state_actions.append(self.host_answers())
                self.probes.data['lanes'] = dict(LANES)
                self.tick(200)  # verified
                self.break_lanes()
        self.assertEqual(len(state_actions), 4)
        self.tick(1000)
        self.tick(1000)
        self.assertIsNone(self.request())
        self.assertIn('limit', self.state('R1').status_text)

    def test_minimum_gap_of_fifteen_minutes(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers()
        self.probes.data['lanes'] = dict(LANES)
        self.tick(30)
        self.tick(130)  # verified, fixed
        self.break_lanes()
        self.tick(5)
        self.tick(400)  # 6 minutes after the action: the gap holds
        self.assertIsNone(self.request())
        self.assertIn('minutes', self.state('R1').status_text)

    def test_host_never_answering_is_an_escalation_not_a_silent_wait(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.tick(660)
        self.assertEqual(self.state('R1').status, 'problem' if self.state('R1').hold_until else self.state('R1').status)
        self.assertTrue(WatchdogEvent.objects.filter(rule='R1', level='problem', result__contains='host did not carry').exists())
        self.assertIsNone(self.request())  # the unserved request was withdrawn

    def test_the_host_refusing_is_checked_at_once(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers(ok=False)
        self.tick(30)
        self.assertEqual(self.state('R1').status, 'problem')

    def test_unacknowledged_messages_go_back_after_a_verified_restart(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers()
        self.probes.data['lanes'] = dict(LANES)
        self.probes.client.unacked = {'tag1': (self.t.timestamp() - 300, '[{"headers": {"id": "dead-1"}}]')}
        with mock.patch('cveFeed.broker_recovery.requeue_tags', return_value=1) as restored, mock.patch.object(wd, 'held_task_ids', return_value=set()):
            self.tick(30)
            self.tick(125)
        restored.assert_called_once_with(['tag1'])
        self.assertIn('1 unacknowledged message', WatchdogEvent.objects.get(rule='R1', level='fixed').result)


class StandDownTests(WatchdogCase):
    def test_an_update_in_progress_means_no_action_for_any_rule(self):
        self.break_lanes()
        self.probes.data['update'] = {'phase': 'applying', 'approved': False, 'locked': False, 'active': True}
        self.tick()
        self.tick(900)
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R1').status, 'standing_down')
        self.assertIn('update', self.state('R1').status_text)

    def test_each_marker_alone_stands_it_down(self):
        for update in ({'phase': 'draining', 'active': True}, {'phase': 'idle', 'approved': True, 'active': True}, {'phase': 'idle', 'locked': True, 'active': True}):
            WatchdogState.objects.all().delete()
            self.break_lanes()
            self.probes.data['update'] = {'phase': 'idle', 'approved': False, 'locked': False, **update}
            self.tick()
            self.tick(900)
            self.assertIsNone(self.request(), update)

    def test_after_the_update_the_clock_starts_from_when_the_symptom_is_seen_again(self):
        self.break_lanes()
        self.probes.data['update'] = {'phase': 'applying', 'approved': False, 'locked': False, 'active': True}
        self.tick()
        self.tick(900)
        self.assertIsNone(self.request())
        self.probes.data['update'] = {'phase': 'done', 'approved': False, 'locked': False, 'active': False}
        self.tick(30)  # the lanes are still absent: already seen for a long time, so it acts
        self.assertIsNotNone(self.request())

    def test_an_unreadable_update_state_stands_it_down(self):
        self.break_lanes()
        self.probes.data['update'] = RuntimeError('cannot read')
        self.tick()
        self.tick(900)
        self.assertIsNone(self.request())

    def test_a_check_due_during_an_update_waits(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        self.host_answers()
        self.tick(30)
        self.probes.data['update'] = {'phase': 'applying', 'approved': False, 'locked': False, 'active': True}
        self.tick(200)  # the check is due; the update restarts the workers by design
        self.assertNotEqual(self.state('R1').status, 'problem')
        self.assertEqual(AdminAlert.objects.filter(code='watchdog_r1', severity='critical').count(), 0)

    def test_the_real_update_state_reads_the_marker_files_and_the_lock(self):
        self.assertFalse(snap_mod.update_state()['active'])
        (self.home / '.update-approved').write_text('x' * 40)
        self.assertTrue(snap_mod.update_state()['approved'])
        (self.home / '.update-approved').unlink()
        import fcntl
        fd = os.open(self.home / '.update-lock', os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.assertTrue(snap_mod.update_state()['locked'])
        finally:
            os.close(fd)
        self.assertFalse(snap_mod.update_state()['locked'])
        (self.home / '.update-phase.json').write_text(json.dumps({'phase': 'applying', 'detail': '', 'scans_running': 0, 'changed_at': None}))
        self.assertTrue(snap_mod.update_state()['active'])


class SwitchTests(WatchdogCase):
    def test_the_environment_kill_switch_does_nothing_at_all(self):
        os.environ['CVENGINE_WATCHDOG'] = '0'
        self.break_lanes()
        out = self.tick()
        self.tick(900)
        self.assertEqual(out['skipped'], 'switched off')
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R1').status, 'off')
        self.assertIn('CVENGINE_WATCHDOG', self.state('R1').status_text)

    def test_the_instance_setting_switches_everything_off(self):
        user = User.objects.create(username='admin', is_superuser=True)
        wd.set_enabled(None, False, user)
        self.break_lanes()
        self.tick()
        self.tick(900)
        self.assertIsNone(self.request())
        self.assertFalse(wd.view()['enabled'])
        wd.set_enabled(None, True, user)
        self.tick()
        self.assertEqual(self.state('R1').status, 'watching')

    def test_one_rule_off_leaves_the_others_running(self):
        user = User.objects.create(username='admin', is_superuser=True)
        wd.set_enabled('R1', False, user)
        self.break_lanes()
        self.probes.data['beat_age'] = 600
        self.tick()
        self.tick(400)
        self.assertEqual(self.request()['action'], 'restart-celery-beat')
        self.assertEqual(self.state('R1').status, 'off')

    def test_an_unknown_rule_cannot_be_switched(self):
        with self.assertRaises(ValueError):
            wd.set_enabled('R99', False, User.objects.create(username='a'))

    def test_switching_is_audited(self):
        from dashboard.models import AuditLog
        user = User.objects.create(username='admin', is_superuser=True)
        wd.set_enabled('R4', False, user)
        self.assertTrue(AuditLog.objects.filter(action='watchdog.off', target='R4', actor_name='admin').exists())


class R2HungTests(WatchdogCase):
    def setUp(self):
        super().setUp()
        self.probes.data['lane_work'] = {'cve_feed_worker@c': {'completed': 50, 'active': 1, 'capacity': 8}}

    def grow(self, depth):
        self.probes.data['queues'] = {**self.probes.data['queues'], 'cve_feed_queue': depth}

    def test_rising_queue_and_nothing_finishing_for_ten_minutes_acts(self):
        self.grow(10)
        self.tick()
        for step in range(1, 11):
            self.grow(10 + step * 5)
            self.tick(60)
        self.tick(60)
        self.assertEqual(self.request()['rule'], 'R2')

    def test_completions_reset_the_window(self):
        self.grow(10)
        self.tick()
        for step in range(1, 12):
            self.grow(10 + step * 5)
            self.probes.data['lane_work'] = {'cve_feed_worker@c': {'completed': 50 + step, 'active': 1, 'capacity': 8}}
            self.tick(60)
        self.assertIsNone(self.request())

    def test_a_full_pool_is_busy_not_hung(self):
        self.probes.data['lane_work'] = {'cve_feed_worker@c': {'completed': 50, 'active': 8, 'capacity': 8}}
        self.grow(10)
        self.tick()
        for step in range(1, 14):
            self.grow(10 + step * 5)
            self.tick(60)
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R2').status, 'ok')

    def test_a_queue_that_shrinks_is_not_hung(self):
        self.grow(100)
        self.tick()
        for step in range(1, 14):
            self.grow(100 - step * 5)
            self.tick(60)
        self.assertIsNone(self.request())


class R3PoolTests(WatchdogCase):
    def starved(self, source='environment'):
        self.probes.data['discovery'] = {**healthy()['discovery'], 'value': 1, 'source': source, 'env_value': 1, 'env_pinned': True, 'running': 1}
        self.probes.data['assessments'] = 100
        self.probes.data['sentinels'] = {'slots': 4, 'busy': 0, 'free': 4, 'waiting': 0, 'due': True}

    def setUp(self):
        super().setUp()
        apply = mock.patch.object(sc, 'apply_discovery', return_value={'want': 4, 'workers': {'discovery_worker@c': 4}, 'changed': ['discovery_worker@c']})
        self.apply = apply.start()
        self.addCleanup(apply.stop)
        request = mock.patch.object(sc, 'request_apply')
        request.start()
        self.addCleanup(request.stop)
        os.environ['DISCOVERY_CONCURRENCY'] = '1'

    def run_until_raised(self):
        self.starved()
        self.tick()
        self.tick(121)

    def test_an_env_pinned_pool_is_raised_through_the_saved_layer_by_the_watchdog(self):
        self.run_until_raised()
        row = ScanConcurrency.current()
        self.assertEqual(row.values['discovery_concurrency'], 4)
        self.assertEqual(row.meta['discovery_concurrency']['by'], 'watchdog')
        self.assertEqual(os.environ['DISCOVERY_CONCURRENCY'], '1')  # the environment is never touched
        self.assertEqual(sc.resolve('discovery_concurrency', row.values, {})['value'], 4)
        override = self.state('R3').data['override']
        self.assertEqual((override['env_name'], override['value'], override['env_value']), ('DISCOVERY_CONCURRENCY', 4, 1))
        alert = AdminAlert.objects.get(code='watchdog_r3', resolved_at__isnull=True)
        self.assertIn('held at 1 by DISCOVERY_CONCURRENCY in .env', alert.title)
        self.assertIn('raised it to 4', alert.title)
        self.assertIn('.env file was not changed', alert.detail)
        from dashboard.models import AuditLog
        self.assertTrue(AuditLog.objects.filter(action='scan_concurrency.set', actor_name='watchdog').exists())

    def test_nothing_is_done_before_the_pool_is_starved_for_two_minutes(self):
        self.starved()
        self.tick()
        self.tick(100)
        self.assertEqual(ScanConcurrency.current().values, {})

    def test_a_value_a_person_saved_is_never_overridden(self):
        self.starved(source='admin')
        self.probes.data['discovery']['saved_by'] = 'owner'
        self.tick()
        self.tick(130)
        self.assertEqual(ScanConcurrency.current().values, {})
        self.assertIn('owner', self.state('R3').status_text)

    def test_busy_sentinels_mean_the_small_pool_is_not_what_holds_work_back(self):
        self.starved()
        self.probes.data['sentinels'] = {'slots': 4, 'busy': 4, 'free': 0, 'waiting': 5, 'due': None}
        self.tick()
        self.tick(300)
        self.assertEqual(ScanConcurrency.current().values, {})

    def test_nothing_waiting_means_no_override(self):
        self.starved()
        self.probes.data['assessments'] = 0
        self.tick()
        self.tick(300)
        self.assertEqual(ScanConcurrency.current().values, {})

    def test_no_raise_when_memory_is_above_ninety_percent(self):
        self.starved()
        self.probes.data['memory'] = [{'host': 'celery', 'used_pct': 95.0}]
        self.tick()
        self.tick(130)
        self.assertEqual(ScanConcurrency.current().values, {})

    def test_the_override_is_released_when_the_environment_stops_pinning_it(self):
        self.run_until_raised()
        os.environ.pop('DISCOVERY_CONCURRENCY')
        self.probes.data['discovery'] = {**healthy()['discovery'], 'value': 4, 'source': 'admin', 'env_value': None, 'env_pinned': False}
        self.tick(30)
        self.assertEqual(ScanConcurrency.current().values, {})  # the saved value is cleared: the auto-tuner decides again
        self.assertNotIn('override', self.state('R3').data)
        self.assertFalse(AdminAlert.objects.filter(code='watchdog_r3', resolved_at__isnull=True).exists())
        self.assertTrue(WatchdogEvent.objects.filter(rule='R3', action='release').exists())

    def test_the_override_is_released_when_the_environment_value_is_raised_to_the_minimum(self):
        self.run_until_raised()
        os.environ['DISCOVERY_CONCURRENCY'] = '6'
        self.probes.data['discovery'] = {**healthy()['discovery'], 'value': 4, 'source': 'admin', 'env_value': 6}
        self.tick(30)
        self.assertEqual(ScanConcurrency.current().values, {})

    def test_a_person_saving_their_own_value_takes_over_and_it_is_not_cleared(self):
        self.run_until_raised()
        owner = User.objects.create(username='owner', is_superuser=True)
        sc.update({'discovery_concurrency': 6}, owner)
        self.probes.data['discovery'] = {**healthy()['discovery'], 'value': 6, 'source': 'admin', 'env_value': 1, 'saved_by': 'owner'}
        self.tick(30)
        self.assertEqual(ScanConcurrency.current().values['discovery_concurrency'], 6)
        self.assertNotIn('override', self.state('R3').data)
        released = WatchdogEvent.objects.get(rule='R3', action='release')
        self.assertIn('owner saved a value of their own', released.result)

    def test_the_health_panel_says_what_the_watchdog_changed(self):
        self.run_until_raised()
        self.tick(30)
        changes = wd.view(self.t)['changes']
        self.assertEqual(len(changes), 1)
        self.assertIn('held by DISCOVERY_CONCURRENCY in .env, raised to 4 by the watchdog', changes[0]['what'])
        self.assertIn('remove it in .env', changes[0]['undo'])
        row = [r for r in wd.view(self.t)['rules'] if r['code'] == 'R3'][0]
        self.assertIn('raised to 4 by the watchdog', row['text'])

    def test_the_check_after_the_action_finds_the_pool_fixed(self):
        self.run_until_raised()
        self.probes.data['discovery'] = {**healthy()['discovery'], 'value': 4, 'source': 'admin', 'env_value': 1}
        self.tick(125)
        self.assertTrue(WatchdogEvent.objects.filter(rule='R3', level='fixed').exists())
        self.assertEqual(AdminAlert.objects.get(code='watchdog_r3', resolved_at__isnull=True).severity, 'warning')  # still held: stays up until released


class R4R5R6Tests(WatchdogCase):
    def test_idle_sentinels_with_due_work_are_fed_after_five_minutes(self):
        self.probes.data['sentinels'] = {'slots': 4, 'busy': 0, 'free': 4, 'waiting': 0, 'due': True}
        with mock.patch('cveFeed.coverage_topup.feed_sentinels', return_value={'hosts_queued': 3}) as feed:
            self.tick()
            self.tick(290)
            feed.assert_not_called()
            self.tick(20)
            feed.assert_called_once()
        self.assertTrue(WatchdogEvent.objects.filter(rule='R4', level='action').exists())

    def test_a_feed_that_finds_nothing_to_queue_is_not_an_action_and_never_escalates(self):
        self.probes.data['sentinels'] = {'slots': 4, 'busy': 0, 'free': 4, 'waiting': 0, 'due': True}
        with mock.patch('cveFeed.coverage_topup.feed_sentinels', return_value={'skipped': 'global capacity', 'slots': 4}) as feed:
            self.tick()
            self.tick(301)
            self.tick(30)
            self.tick(200)
            self.assertEqual(feed.call_count, 1)  # the gap holds: not asked every tick
        self.assertEqual(self.state('R4').status, 'watching')
        self.assertTrue(WatchdogEvent.objects.filter(rule='R4', action='none', result__contains='nothing to queue').exists())
        self.assertEqual(WatchdogEvent.objects.filter(rule='R4', level='problem').count(), 0)
        self.assertEqual(AdminAlert.objects.filter(code='watchdog_r4').count(), 0)
        self.assertEqual(self.state('R4').actions, [])

    def test_idle_sentinels_with_nothing_due_are_left_alone(self):
        self.probes.data['sentinels'] = {'slots': 4, 'busy': 0, 'free': 4, 'waiting': 0, 'due': False}
        with mock.patch('cveFeed.coverage_topup.feed_sentinels') as feed:
            self.tick()
            self.tick(900)
            feed.assert_not_called()

    def test_the_feed_runs_in_the_tick_not_on_celery(self):
        self.probes.data['sentinels'] = {'slots': 4, 'busy': 0, 'free': 4, 'waiting': 0, 'due': True}
        with mock.patch('cveFeed.coverage_topup.feed_sentinels', return_value={'hosts_queued': 2}), mock.patch('cveFeed.tasks.feed_sentinels.apply_async') as queued:
            self.tick()
            self.tick(301)
        queued.assert_not_called()

    def test_stuck_unacked_messages_no_worker_holds_go_back(self):
        self.probes.data['unacked'] = {'count': 2, 'oldest_age_seconds': 4000}
        self.probes.client.unacked = {'a': (self.t.timestamp() - 4000, '[{"headers": {"id": "held-1"}}]'), 'b': (self.t.timestamp() - 3000, '[{"headers": {"id": "gone-2"}}]')}
        with mock.patch.object(wd, 'held_task_ids', return_value={'held-1'}), mock.patch('cveFeed.broker_recovery.requeue_tags', return_value=1) as restored:
            self.tick()
            restored.assert_called_once_with(['b'])  # only the message nobody holds
        self.assertIn('1 message', WatchdogEvent.objects.get(rule='R5', level='action').result)

    def test_unacked_messages_a_worker_holds_are_not_stuck(self):
        self.probes.data['unacked'] = {'count': 1, 'oldest_age_seconds': 9000}
        self.probes.client.unacked = {'a': (self.t.timestamp() - 9000, '[{"headers": {"id": "held-1"}}]')}
        with mock.patch.object(wd, 'held_task_ids', return_value={'held-1'}), mock.patch('cveFeed.broker_recovery.requeue_tags') as restored:
            self.tick()
            restored.assert_not_called()
        self.assertEqual(self.state('R5').status, 'ok')

    def test_recent_unacked_messages_are_left_alone(self):
        self.probes.data['unacked'] = {'count': 30, 'oldest_age_seconds': 120}
        with mock.patch('cveFeed.broker_recovery.requeue_tags') as restored:
            self.tick()
        restored.assert_not_called()

    def test_a_silent_scheduler_is_recreated_through_the_host(self):
        self.probes.data['beat_age'] = 900
        self.tick()
        self.assertEqual(self.state('R6').status, 'watching')
        self.tick(121)
        self.assertEqual(self.request()['action'], 'restart-celery-beat')

    def test_a_scheduler_with_no_readable_heartbeat_is_unknown_not_dead(self):
        self.probes.data['beat_age'] = None
        self.tick()
        self.tick(600)
        self.assertIsNone(self.request())
        self.assertEqual(self.state('R6').status, 'unknown')

    def test_only_one_host_request_waits_at_a_time(self):
        self.break_lanes()
        self.probes.data['beat_age'] = 900
        self.tick()
        self.tick(185)
        first = self.request()
        self.assertEqual(first['rule'], 'R1')
        self.tick(30)
        self.assertEqual(self.request()['id'], first['id'])  # R6 waits its turn
        self.assertEqual(self.state('R6').status, 'watching')


class R7R8R9Tests(WatchdogCase):
    def test_low_disk_pauses_heavy_work_and_asks_the_host_to_prune(self):
        self.probes.data['disk'] = {'free_mb': 3000, 'total_mb': 100000, 'free_pct': 3.0}
        self.tick()
        self.tick(121)
        row = ScanControl.objects.get(pk=1)
        self.assertTrue(row.paused)
        self.assertTrue(row.paused_by_update)  # running work carries on: only the starting of more is held
        self.assertTrue(row.reason.startswith(wd.PAUSE_REASON))
        self.assertEqual(self.request()['action'], 'prune-docker')
        self.assertTrue(AdminAlert.objects.filter(code='watchdog_r7').exists())
        self.assertTrue(any(c['rule'] == 'R7' for c in wd.view(self.t)['changes']))

    def test_memory_pressure_pauses_but_does_not_prune(self):
        self.probes.data['memory'] = [{'host': 'celery', 'used_pct': 96.0}]
        self.tick()
        self.tick(121)
        self.assertTrue(ScanControl.objects.get(pk=1).paused)
        self.assertIsNone(self.request())

    def test_the_pause_is_released_when_the_pressure_is_gone_but_only_the_watchdogs(self):
        self.probes.data['disk'] = {'free_mb': 3000, 'total_mb': 100000, 'free_pct': 3.0}
        self.tick()
        self.tick(121)
        self.probes.data['disk'] = {'free_mb': 80000, 'total_mb': 100000, 'free_pct': 80.0}
        self.tick(130)
        self.tick(30)
        self.assertFalse(ScanControl.objects.get(pk=1).paused)
        self.assertTrue(WatchdogEvent.objects.filter(rule='R7', action='resume').exists())

    def test_an_operators_own_pause_is_never_touched(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': False, 'reason': 'maintenance window'})
        self.probes.data['disk'] = {'free_mb': 3000, 'total_mb': 100000, 'free_pct': 3.0}
        self.tick()
        self.tick(121)
        self.probes.data['disk'] = {'free_mb': 80000, 'total_mb': 100000, 'free_pct': 80.0}
        self.tick(130)
        self.tick(30)
        row = ScanControl.objects.get(pk=1)
        self.assertTrue(row.paused)
        self.assertEqual(row.reason, 'maintenance window')

    def test_database_connections_near_the_limit_only_raise_a_notice(self):
        self.probes.data['db'] = {'connections': 190, 'max': 200, 'idle_in_transaction_seconds': 0}
        self.tick()
        self.tick(121)
        self.assertIsNone(self.request())
        alert = AdminAlert.objects.get(code='watchdog_r8')
        self.assertIn('190 of 200', alert.detail)
        self.probes.data['db'] = {'connections': 20, 'max': 200, 'idle_in_transaction_seconds': 0}
        self.tick(30)
        self.assertFalse(AdminAlert.objects.filter(code='watchdog_r8', resolved_at__isnull=True).exists())

    def test_a_session_idle_in_a_transaction_is_noticed(self):
        self.probes.data['db'] = {'connections': 20, 'max': 200, 'idle_in_transaction_seconds': 1500}
        self.tick()
        self.tick(121)
        self.assertIn('idle inside a transaction', AdminAlert.objects.get(code='watchdog_r8').detail)

    def test_a_stalled_scan_no_worker_holds_is_marked_interrupted(self):
        self.probes.data['scans'] = {'running': 1, 'queued': 0, 'stale_candidates': 1}
        ghost = mock.Mock(pk=77)
        with mock.patch('cveFeed.ghost_scans.find', return_value=[(ghost, T0)]), mock.patch('cveFeed.ghost_scans.close', return_value=[77]) as close:
            self.tick()
        close.assert_called_once()
        self.assertEqual(close.call_args.kwargs['message'], wd.R9_MESSAGE)
        self.assertIn('Marked 1 scan', WatchdogEvent.objects.get(rule='R9', level='action').result)

    def test_scans_a_worker_holds_are_left_alone(self):
        self.probes.data['scans'] = {'running': 1, 'queued': 0, 'stale_candidates': 1}
        with mock.patch('cveFeed.ghost_scans.find', return_value=[]), mock.patch('cveFeed.ghost_scans.close') as close:
            self.tick()
        close.assert_not_called()

    def test_the_stalled_scan_probe_is_not_repeated_every_tick(self):
        self.probes.data['scans'] = {'running': 1, 'queued': 0, 'stale_candidates': 1}
        with mock.patch('cveFeed.ghost_scans.find', return_value=[]) as find:
            self.tick()
            self.tick(30)
            self.tick(30)
        self.assertEqual(find.call_count, 1)

    def test_ghost_close_uses_the_message_it_is_given(self):
        from cveFeed import ghost_scans
        from dashboard.models import Org, Project
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        org = Org.objects.create(name='Wd', slug='wd')
        project = Project.objects.create(name='W', slug='wd-p', insert_date=T0, org=org)
        domain = Domain.objects.create(name='example.com', project=project, insert_date=T0)
        engine = EngineType.objects.create(engine_name='e-wd', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=T0 - timedelta(hours=3), scan_status=1, results_dir='/tmp')
        closed = ghost_scans.close(now=T0, live=set(), idle_minutes=5, message='closed by the watchdog')
        self.assertEqual(closed, [scan.pk])
        scan.refresh_from_db()
        self.assertEqual((scan.scan_status, scan.error_message), (0, 'closed by the watchdog'))


class TickSafetyTests(WatchdogCase):
    def test_every_probe_raising_still_returns_ok_and_changes_nothing(self):
        probes = FakeProbes(**{name: RuntimeError('boom') for name in snap_mod.SECTIONS})
        out = wd.tick(now=T0, probes=probes, alarm=False)
        self.assertTrue(out['ok'])
        self.assertIsNone(self.request())
        self.assertEqual(AdminAlert.objects.filter(code__startswith='watchdog_').count(), 0)

    def test_a_rule_that_raises_does_not_stop_the_others(self):
        self.probes.data['beat_age'] = 900
        with mock.patch.object(wd.BY_CODE['R1'], 'check', side_effect=RuntimeError('bug')):
            self.tick()
            self.tick(121)
        self.assertEqual(self.state('R1').status, 'unknown')
        self.assertEqual(self.request()['action'], 'restart-celery-beat')

    def test_a_probe_that_hangs_is_cut_off_by_the_time_limit(self):
        probes = FakeProbes(lanes=lambda: time.sleep(30))
        started = time.time()
        out = wd.tick(now=T0, probes=probes, limit=1)
        self.assertLess(time.time() - started, 5)
        self.assertFalse(out['ok'])
        self.assertIn('stopped itself', out['skipped'])

    def test_redis_db_and_celery_all_hanging_end_in_time(self):
        hang = lambda: time.sleep(30)  # noqa: E731
        probes = FakeProbes(queues=hang, lanes=hang, db=hang)
        started = time.time()
        out = wd.tick(now=T0, probes=probes, limit=1)
        self.assertLess(time.time() - started, 5)
        self.assertFalse(out['ok'])

    def test_the_commands_own_timer_ends_a_process_blocked_where_python_cannot_interrupt(self):
        code = ('import threading, sys\n'
                'sys.path.insert(0, %r)\n'
                'import os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "reNgine.settings")\n'
                'import django\ndjango.setup()\n'
                'from cveFeed.management.commands.watchdog_tick import self_destruct\n'
                'self_destruct(1)\nthreading.Event().wait()\n') % str(Path(__file__).resolve().parents[1])
        started = time.time()
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr.decode()[-500:])
        self.assertLess(time.time() - started, 40)

    def test_the_command_runs_one_tick_and_prints_what_it_did(self):
        from io import StringIO

        from django.core.management import call_command
        out = StringIO()
        with mock.patch.object(wd, 'tick', return_value={'ok': True, 'acted': []}):
            call_command('watchdog_tick', stdout=out)
        self.assertEqual(json.loads(out.getvalue())['ok'], True)

    def test_the_tick_records_when_it_ran_and_the_snapshot(self):
        self.tick()
        row = self.state('_all')
        self.assertEqual(row.last_tick_at, self.t)
        self.assertIn('queues', row.data['snapshot'])
        self.assertIn('cvengine:watchdog:snapshot', self.probes.client.kv)

    def test_events_are_append_only(self):
        event = wd.event('R1', 'action', observation='o', action='a', result='r')
        event.result = 'changed'
        with self.assertRaises(RuntimeError):
            event.save()

    def test_old_events_are_pruned_by_age_and_count(self):
        old = wd.event('R1', 'info', observation='old')
        WatchdogEvent.objects.filter(pk=old.pk).update(at=T0 - timedelta(days=40))
        wd.event('R1', 'info', observation='new')
        wd.prune_events(T0)
        self.assertEqual(list(WatchdogEvent.objects.values_list('observation', flat=True)), ['new'])

    def test_settled_notices_expire_after_a_day(self):
        wd.notice('R1', 'info', 'fixed', 'it is')
        AdminAlert.objects.filter(code='watchdog_r1').update(last_seen=T0 - timedelta(days=2))
        wd.expire_settled(T0)
        self.assertFalse(AdminAlert.objects.filter(code='watchdog_r1', resolved_at__isnull=True).exists())

    def test_nothing_secret_reaches_the_records(self):
        os.environ['REDIS_PASSWORD'] = 'hunter2-secret'
        os.environ['DISCOVERY_CONCURRENCY'] = '1'
        self.break_lanes()
        self.tick()
        self.tick(181)
        blob = json.dumps(list(WatchdogEvent.objects.values()), default=str) + json.dumps(list(AdminAlert.objects.values('title', 'detail', 'facts')), default=str) + json.dumps(
            list(WatchdogState.objects.values('status_text', 'data')), default=str)
        self.assertNotIn('hunter2', blob)


class HostFileTests(WatchdogCase):
    def test_the_runtime_files_are_ignored_by_git(self):
        """A tracked runtime file makes `git merge --ff-only` refuse on every server that has it: the update would stop."""
        ignore = Path(__file__).resolve().parents[2] / '.gitignore'
        if not ignore.is_file():
            self.skipTest('the repository root is not mounted')
        text = ignore.read_text()
        for name in ('web/.watchdog-action', 'web/.watchdog-action.tmp', 'web/.watchdog-result'):
            self.assertIn(name, text)

    def test_only_the_known_actions_can_be_requested(self):
        with self.assertRaises(ValueError):
            wd.request_host_action('rm-rf', 'R1')
        self.assertIsNone(self.request())

    def test_the_request_holds_only_an_id_an_action_a_rule_and_a_time(self):
        req = wd.request_host_action('restart-celery', 'R1', T0)
        self.assertEqual(sorted(req), ['action', 'at', 'id', 'rule'])
        self.assertEqual(sorted(self.request()), ['action', 'at', 'id', 'rule'])

    def test_a_second_request_waits_while_one_is_pending(self):
        self.assertIsNotNone(wd.request_host_action('restart-celery', 'R1', T0))
        self.assertIsNone(wd.request_host_action('restart-celery-beat', 'R6', T0))

    def test_a_linked_or_oversized_result_is_ignored(self):
        victim = self.home / 'victim'
        victim.write_text('{"id": "x", "at": 1}')
        (self.home / wd.RESULT_FILE).symlink_to(victim)
        self.assertIsNone(wd.read_host_result())
        (self.home / wd.RESULT_FILE).unlink()
        (self.home / wd.RESULT_FILE).write_text('x' * 5000)
        self.assertIsNone(wd.read_host_result())

    def test_an_answer_is_used_once(self):
        self.break_lanes()
        self.tick()
        self.tick(181)
        req = self.host_answers()
        self.tick(5)
        self.assertEqual(WatchdogEvent.objects.filter(rule='R1', result__startswith='The host carried it out').count(), 1)
        self.tick(5)
        self.assertEqual(WatchdogEvent.objects.filter(rule='R1', result__startswith='The host carried it out').count(), 1)
        self.assertEqual(self.state('_all').data['last_result'], req['id'])


class ViewTests(WatchdogCase):
    def test_the_view_says_each_rule_in_words_and_a_colour(self):
        self.break_lanes()
        self.tick()
        view = wd.view(self.t)
        by = {r['code']: r for r in view['rules']}
        self.assertEqual([r['code'] for r in view['rules']], ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'])
        self.assertEqual(by['R1']['color'], 'amber')
        self.assertEqual(by['R6']['color'], 'green')
        self.assertTrue(view['running'])
        self.assertIn('No answer from', by['R1']['text'])

    def test_a_watchdog_that_stopped_ticking_is_shown_as_not_known(self):
        self.tick()
        view = wd.view(self.t + timedelta(minutes=10))
        self.assertFalse(view['running'])
        self.assertTrue(all(r['color'] == 'amber' for r in view['rules']))
        self.assertIn('not ticking', view['rules'][0]['text'])

    def test_the_last_twenty_actions_newest_first(self):
        for i in range(25):
            wd.event('R1', 'action', observation=f'o{i}', action='restart-celery', result='r')
        events = wd.view(T0)['events']
        self.assertEqual(len(events), 20)
        self.assertEqual(events[0]['observation'], 'o24')


class AdminApiTests(WatchdogCase):
    def setUp(self):
        super().setUp()
        from dashboard.models import Org, OrgMembership
        from tests.test_tenancy import client_for
        self.root = User.objects.create_superuser('wd-root', 'wd@example.test', 'pw')
        self.admin = User.objects.create_user('wd-org', password='pw')
        org = Org.objects.create(name='Wd Org', slug='wd-org')
        OrgMembership.objects.create(user=self.admin, org=org, role='admin')
        self.client_for = client_for

    def api(self, user, method, body=None):
        from tests.test_admin import api
        return api(self.client_for(user), method, 'watchdog', body)

    def test_only_an_app_admin_may_read_or_switch_it(self):
        self.assertEqual(self.api(self.admin, 'GET')[0], 403)
        self.assertEqual(self.api(self.admin, 'POST', {'enabled': False})[0], 403)

    def test_read_returns_the_panel_payload(self):
        self.tick()
        status, body = self.api(self.root, 'GET')
        self.assertEqual(status, 200)
        self.assertEqual(len(body['rules']), 9)
        self.assertTrue(body['enabled'])
        self.assertIn('events', body)

    def test_switch_the_watchdog_and_one_rule(self):
        status, body = self.api(self.root, 'POST', {'enabled': False})
        self.assertEqual(status, 200)
        self.assertFalse(body['enabled'])
        status, body = self.api(self.root, 'POST', {'enabled': True})
        status, body = self.api(self.root, 'POST', {'rule': 'R3', 'enabled': False})
        self.assertEqual([r['enabled'] for r in body['rules'] if r['code'] == 'R3'], [False])
        self.assertTrue(body['enabled'])

    def test_bad_input_is_refused(self):
        self.assertEqual(self.api(self.root, 'POST', {'enabled': 'yes'})[0], 400)
        self.assertEqual(self.api(self.root, 'POST', {'rule': 'R99', 'enabled': False})[0], 400)
        self.assertEqual(self.api(self.root, 'POST', {'rule': ['R1'], 'enabled': False})[0], 400)


class DiscoveryWorkerNameTests(WatchdogCase):
    def test_a_worker_named_celery_at_discovery_worker_is_the_discovery_worker(self):
        """celery names a worker started with ``-n discovery_worker`` celery@discovery_worker: the live resize (which the watchdog's R3 uses) must find it."""
        class App:
            class control:
                @staticmethod
                def inspect(timeout=1.5):
                    return mock.Mock(stats=lambda: {'celery@discovery_worker': {'autoscaler': {'max': 1}}, 'celery@cve_feed_worker': {'autoscaler': {'max': 4}}})
        self.assertEqual(sc.discovery_workers(App), {'celery@discovery_worker': 1})


class ReviewerSeesTheWatchdogTests(WatchdogCase):
    def test_the_operations_snapshot_carries_what_the_watchdog_did_for_the_diagnosis(self):
        from cveFeed import reviewer
        wd.event('R1', 'action', observation='no answer', action='restart-celery', result='Asked the host.')
        wd.event('R1', 'info', observation='noise')
        snap = reviewer.snapshot()
        self.assertEqual([(e['rule'], e['action']) for e in snap['watchdog']], [('R1', 'restart-celery')])
