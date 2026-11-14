"""The maintainer's checks (1.4.0 work package 2): ``memory``, ``queue_starvation``, ``sentinel_claims_refused`` and the corrected ``sentinel_waiting``.

Each verdict is tried with healthy, unhealthy and unknown numbers, the four production incidents are replayed as inputs and must produce the right words, and
the checks are shown to run from the watchdog tick and to age out of the banner when they stop running."""
import time
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from agentapi.models import SentinelTask
from cveFeed import maintainer_checks as mc, reviewer
from cveFeed.models import AdminAlert
from tests.test_alerts_tell_the_truth import Base, WAIT

UNKNOWN = {'state': 'unknown', 'reason': 'could not be read'}


def lane(name='cve_feed', rss=500, limit=4608, restarts=0, last=None):
    return {'lane': name, 'state': 'known', 'rss_mb': rss, 'limit_mb': limit, 'percent_of_limit': round(100 * rss / limit, 1), 'restarts_24h': restarts,
            'last_restart': {'at': last} if last else None}


def box(role='worker', used=1000, limit=4608, kills=0, last=None):
    return {'role': role, 'state': 'known', 'used_mb': used, 'limit_mb': limit, 'percent_of_limit': round(100 * used / limit, 1), 'oom_kills_24h': kills, 'last_oom_at': last}


def mem_signals(lanes=(), boxes=()):
    return {'lanes': {'state': 'known', 'lanes': list(lanes)}, 'containers': {'state': 'known', 'containers': list(boxes)}}


class MemoryCheckTests(SimpleTestCase):
    def test_healthy_numbers_are_ok(self):
        out = mc.memory(mem_signals([lane(rss=800)], [box(used=1500), box('web', 400, 1024)]))
        self.assertEqual(out['state'], 'ok')

    def test_a_lane_near_its_limit_is_a_warning_and_named(self):
        out = mc.memory(mem_signals([lane('classic', rss=4000)], [box(used=1000)]))
        self.assertEqual(out['state'], 'warning')
        self.assertIn('classic worker lane holds 4,000 MB, 87%', out['detail'])

    def test_the_thresholds_are_named_constants_and_the_boundary_is_inclusive(self):
        at = mc.MEMORY_WARN_PERCENT * 1000 / 100
        self.assertEqual(mc.memory(mem_signals([], [box('web', at, 1000)]))['state'], 'warning')
        self.assertEqual(mc.memory(mem_signals([], [box('web', at - 1, 1000)]))['state'], 'ok')
        self.assertEqual(mc.memory(mem_signals([], [box('web', mc.MEMORY_PROBLEM_PERCENT * 10, 1000)]))['state'], 'problem')

    def test_a_lane_that_keeps_restarting_is_a_problem_but_not_one_restart(self):
        self.assertEqual(mc.memory(mem_signals([lane(restarts=mc.LANE_RESTARTS_PROBLEM - 1)]))['state'], 'ok')
        out = mc.memory(mem_signals([lane(restarts=mc.LANE_RESTARTS_PROBLEM, last=1_700_000_000)]))
        self.assertEqual(out['state'], 'problem')
        self.assertIn('cve_feed worker lane restarted 3 times in 24 hours (last at 22:13 UTC)', out['detail'])

    def test_nothing_read_is_unknown_never_ok_and_never_an_alarm(self):
        self.assertEqual(mc.memory({})['state'], 'unknown')
        self.assertEqual(mc.memory({'lanes': UNKNOWN, 'containers': UNKNOWN})['state'], 'unknown')
        self.assertEqual(mc.memory(mem_signals([{'lane': 'classic', 'state': 'unknown'}], [{'role': 'web', 'state': 'unknown'}]))['state'], 'unknown')

    def test_an_unlimited_or_unreadable_limit_gives_no_percentage_verdict(self):
        unlimited = {'role': 'web', 'state': 'known', 'used_mb': 9000, 'limit_mb': None, 'percent_of_limit': None, 'oom_kills_24h': 0, 'last_oom_at': None}
        out = mc.memory(mem_signals([], [unlimited]))
        self.assertEqual(out['state'], 'ok')

    def test_what_could_not_be_read_is_listed_beside_a_verdict_on_what_could(self):
        out = mc.memory({'lanes': UNKNOWN, 'containers': {'state': 'known', 'containers': [box('web', 1000, 1024)]}})
        self.assertEqual(out['state'], 'problem')
        self.assertIn('worker lanes', out['facts']['not_read'])

    def test_incident_celery_workers_killed_repeatedly(self):
        out = mc.memory(mem_signals([lane('cve_feed', 2100, 4608, restarts=5, last=1_700_000_000), lane('classic', 1500, 4608), lane('discovery', 300, 4608)],
                                    [box('worker', 4450, 4608, kills=3, last=1_700_000_000), box('web', 500, 1024)]))
        self.assertEqual(out['state'], 'problem')
        text = out['detail']
        self.assertIn('worker container was killed by the kernel for running out of memory 3 times in 24 hours (last at 22:13 UTC)', text)
        self.assertIn('cve_feed worker lane restarted 5 times', text)
        self.assertIn('CELERY_MEM_LIMIT', text)
        self.assertIn('largest lane is cve_feed at 2,100 MB', text)
        self.assertNotIn('web container', text)

    def test_incident_web_container_at_its_one_gib_limit(self):
        out = mc.memory(mem_signals([lane(rss=200)], [box('web', 1010, 1024), box('worker', 900, 4608)]))
        self.assertEqual(out['state'], 'problem')
        self.assertIn('The web container uses 1,010 MB, 99% of its 1,024 MB limit', out['detail'])
        self.assertIn('WEB_MEM_LIMIT', out['detail'])
        self.assertEqual([c['role'] for c in out['facts']['containers']], ['web'])


def starve_work(**over):
    work = {'paused': False, 'scans_queued': 0, 'assessments_running': 0, 'assessments_queued': 0, 'sentinel_kinds': []}
    work.update(over)
    return work


def queue_signals(scan_age=None, queued=True):
    scan = {'state': 'known', 'queued': queued, 'age_seconds': scan_age}
    return {'queues': {'state': 'known', 'oldest_queued': {'scan': scan, 'assessment': {'state': 'known', 'queued': True, 'age_seconds': 100}}}}


class QueueStarvationTests(SimpleTestCase):
    def test_healthy_a_short_wait_is_ok(self):
        out = mc.queue_starvation(queue_signals(300), starve_work(scans_queued=2, assessments_running=4, assessments_queued=10))
        self.assertEqual(out['state'], 'ok')

    def test_a_long_wait_with_nothing_else_holding_the_workers_is_not_starvation(self):
        self.assertEqual(mc.queue_starvation(queue_signals(7200), starve_work(scans_queued=2))['state'], 'ok')

    def test_scans_behind_assessments_are_starved_at_the_named_threshold(self):
        work = starve_work(scans_queued=3, assessments_running=2, assessments_queued=5)
        self.assertEqual(mc.queue_starvation(queue_signals(mc.SCAN_STARVED_SECONDS - 1), work)['state'], 'ok')
        self.assertEqual(mc.queue_starvation(queue_signals(mc.SCAN_STARVED_SECONDS), work)['state'], 'problem')

    def test_a_paused_instance_is_not_starved(self):
        out = mc.queue_starvation(queue_signals(99999), starve_work(paused=True, assessments_queued=9))
        self.assertEqual(out['state'], 'ok')

    def test_unknown_numbers_give_no_verdict(self):
        self.assertEqual(mc.queue_starvation({}, starve_work(sentinel_kinds=None, assessments_running=None, assessments_queued=None))['state'], 'unknown')
        out = mc.queue_starvation({'queues': UNKNOWN}, starve_work())
        self.assertEqual((out['state'], out['facts']['not_read']), ('ok', ['scan queue']))  # the Sentinel queue was read and is fine; the scan queue is listed as not read
        self.assertEqual(mc.queue_starvation(queue_signals(99999), starve_work(assessments_running=None, assessments_queued=None, sentinel_kinds=None))['state'], 'unknown')

    def test_a_sentinel_kind_far_beyond_its_normal_while_others_are_claimed(self):
        kind = {'kind': 'nmap', 'queued': 14, 'oldest_age_seconds': 4 * 3600, 'typical_wait_seconds': 240, 'busy_with': ['nuclei', 'bbot']}
        out = mc.queue_starvation(queue_signals(10), starve_work(sentinel_kinds=[kind]))
        self.assertEqual(out['state'], 'problem')
        self.assertIn('14 nmap tasks queued, the oldest for 4 hours, normally about 4 minutes, while the Sentinels worked on nuclei, bbot', out['detail'])
        self.assertEqual(mc.queue_starvation(queue_signals(10), starve_work(sentinel_kinds=[{**kind, 'busy_with': []}]))['state'], 'ok')
        slow_kind = {**kind, 'typical_wait_seconds': 3 * 3600}  # this kind normally waits hours: four hours is not far beyond its normal
        self.assertEqual(mc.queue_starvation(queue_signals(10), starve_work(sentinel_kinds=[slow_kind]))['state'], 'ok')

    def test_incident_assessments_starved_scans_for_hours(self):
        out = mc.queue_starvation(queue_signals(16 * 3600), starve_work(scans_queued=18, assessments_running=8, assessments_queued=360))
        self.assertEqual(out['state'], 'problem')
        self.assertIn('18 scans are queued, the oldest for 16 hours, while host assessments hold the discovery workers (8 running, 360 queued)', out['detail'])
        self.assertIn('Hosts per assessment batch', out['detail'])


def refusal_signals(*rows, state='known'):
    return {'claim_refusals': {'state': state, 'by': [{'action': a, 'caller': c, 'sentinel': True, 'this_hour': t, 'previous_hour': p} for a, c, t, p in rows]}}


class ClaimsRefusedTests(SimpleTestCase):
    def test_none_or_a_few_refused_is_ok(self):
        self.assertEqual(mc.claim_refusals(refusal_signals())['state'], 'ok')
        self.assertEqual(mc.claim_refusals(refusal_signals(('claim', 's1', 3, 2)))['state'], 'ok')

    def test_other_actions_do_not_count(self):
        self.assertEqual(mc.claim_refusals(refusal_signals(('heartbeat', 's1', 500, 500)))['state'], 'ok')

    def test_thresholds(self):
        self.assertEqual(mc.claim_refusals(refusal_signals(('claim', 's1', mc.CLAIM_REFUSED_WARN, 0)))['state'], 'warning')
        self.assertEqual(mc.claim_refusals(refusal_signals(('claim', 's1', 0, mc.CLAIM_REFUSED_PROBLEM)))['state'], 'problem')

    def test_unknown_is_no_verdict(self):
        self.assertEqual(mc.claim_refusals({})['state'], 'unknown')
        self.assertEqual(mc.claim_refusals({'claim_refusals': UNKNOWN})['state'], 'unknown')

    def test_incident_the_limiter_refused_every_claim_for_an_hour(self):
        out = mc.claim_refusals(refusal_signals(('claim', 'sentinel-1', 900, 40), ('claim', 'sentinel-2', 870, 35)))
        self.assertEqual(out['state'], 'problem')
        self.assertIn('rate limiter refused 1845 claim calls', out['detail'])
        self.assertIn('sentinel-1 (940)', out['detail'])
        self.assertIn('adding more will not help', out['detail'])
        self.assertNotIn('Add a Sentinel', out['detail'])


class NotClaimingTests(SimpleTestCase):
    def test_slots_busy_is_back_pressure_not_a_claim_problem(self):
        self.assertEqual(mc.not_claiming(8, 7, 200, 0), (False, ''))

    def test_free_slots_with_refusals_names_the_limiter(self):
        flag, why = mc.not_claiming(8, 0, 0, 300)
        self.assertTrue(flag)
        self.assertIn('refused 300 claim calls', why)

    def test_free_slots_and_no_claims_at_all(self):
        flag, why = mc.not_claiming(8, 1, 0, 0)
        self.assertTrue(flag)
        self.assertIn('No Sentinel has claimed any task in the last two hours', why)

    def test_unknown_numbers_make_no_claim(self):
        self.assertEqual(mc.not_claiming(8, None, 0, 0), (False, ''))
        self.assertEqual(mc.not_claiming(0, 0, 0, 0), (False, ''))


class BriefTests(SimpleTestCase):
    def test_the_brief_is_bounded_whitelisted_and_lists_what_is_unknown(self):
        signals = {**mem_signals([lane(name=f'l{i}') for i in range(4)], [box()]), 'queues': UNKNOWN, 'database': {'state': 'known', 'size_mb': 5, 'secret': 'x'}}
        tuning = {'effective_mode': 'auto', 'pinned': ['a'], 'last_decisions': [{'setting': 'assess_batch', 'old_value': 8, 'new_value': 10, 'reason': 'r', 'extra': 'x'}] * 5}
        out = mc.brief(signals, tuning)
        self.assertEqual(out['signals']['unknown'], ['queues'])
        self.assertNotIn('secret', out['signals']['database'])
        self.assertEqual(out['tuning']['mode'], 'auto')
        self.assertNotIn('extra', out['tuning']['last_decisions'][0])

    def test_it_is_cut_to_its_size_budget(self):
        import json
        signals = mem_signals([lane(name='x' * 300) for _ in range(40)], [box(role='y' * 300) for _ in range(40)])
        self.assertLessEqual(len(json.dumps(mc.brief(signals, {'last_decisions': [{'reason': 'z' * 900}] * 5}), default=str)), mc.BRIEF_MAX_CHARS)


def patched_signals(**signals):
    return mock.patch('agentapi.system_status._signals', return_value={'at': 0, 'signals': signals, 'unknown': []})


class IntegrationTests(Base):
    """``ops_checks`` with the signals injected: the checks are registered, an unknown one opens nothing, and the incident words arrive in the checks."""

    def checks(self, **signals):
        with patched_signals(**signals):
            return {c['code']: c for c in reviewer.ops_checks()}

    def test_the_three_checks_exist_and_are_in_the_code_list(self):
        found = self.checks()
        for code in ('memory', 'queue_starvation', 'sentinel_claims_refused'):
            self.assertIn(code, reviewer.OPS_CODES)
            self.assertIn(code, found)

    def test_unknown_signals_open_nothing_and_resolve_nothing(self):
        found = self.checks()
        self.assertEqual(found['memory']['state'], 'unknown')
        self.assertEqual(found['sentinel_claims_refused']['state'], 'unknown')
        AdminAlert.objects.create(code='memory', severity='critical', title='old', detail='old', facts={}, digest='x', first_seen=timezone.now(), last_seen=timezone.now())
        reviewer.sync_alerts(list(found.values()))
        self.assertEqual(AdminAlert.objects.filter(code='memory', resolved_at__isnull=True).count(), 1)
        self.assertFalse(AdminAlert.objects.exclude(code='memory').filter(code__in=('queue_starvation', 'sentinel_claims_refused')).exists())

    def test_an_unhealthy_memory_opens_an_alert_and_a_healthy_reading_resolves_it(self):
        bad = self.checks(**mem_signals([lane()], [box('web', 1010, 1024)]))
        reviewer.sync_alerts(list(bad.values()))
        self.assertEqual(AdminAlert.objects.get(code='memory', resolved_at__isnull=True).severity, 'critical')
        good = self.checks(**mem_signals([lane()], [box('web', 300, 1024)]))
        reviewer.sync_alerts(list(good.values()))
        self.assertFalse(AdminAlert.objects.filter(code='memory', resolved_at__isnull=True).exists())

    def test_the_snapshot_leaves_out_unknown_checks_and_carries_signals_and_decisions(self):
        with patched_signals(**mem_signals([lane()], [box()])):
            snap = reviewer.snapshot()
        self.assertTrue(all(c['state'] != 'unknown' for c in snap['checks']))
        self.assertIn('memory', {c['code'] for c in snap['checks']})
        self.assertEqual(snap['signals']['lanes'][0]['lane'], 'cve_feed')
        self.assertIn('last_decisions', snap['tuning'])
        self.assertLess(len(str(snap['signals'])), mc.BRIEF_MAX_CHARS)

    def test_incident_the_limiter_refused_every_claim_and_nobody_is_told_to_add_sentinels(self):
        self.live(count=2, slots=4)
        self.tasks(200, 'done', ago=timedelta(hours=5))
        self.tasks(10, 'expired', WAIT, kind='nmap', ago=timedelta(hours=4))
        self.tasks(60, 'expired', WAIT, kind='nmap', ago=timedelta(minutes=30))
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind='nmap', target={}, status='queued') for _ in range(12)])
        found = self.checks(**refusal_signals(('claim', 'sentinel-1', 700, 100), ('claim', 'sentinel-2', 650, 90)))
        waiting = found['sentinel_waiting']
        self.assertEqual(waiting['title'], 'Sentinels are not claiming work')
        self.assertEqual(waiting['severity'], 'warning')
        self.assertIn('0 of 8 slots are in use while tasks expire unclaimed', waiting['detail'])
        self.assertIn('rate limiter refused 1540 claim calls', waiting['detail'])
        for words in ('Add a Sentinel', 'more slots', 'falling behind', 'at capacity'):
            self.assertNotIn(words, waiting['detail'])
        self.assertTrue(waiting['facts']['not_claiming'])
        self.assertEqual(found['sentinel_claims_refused']['state'], 'problem')

    def test_no_claims_at_all_is_said_without_a_limiter(self):
        self.live(count=2, slots=4)
        self.tasks(200, 'done', ago=timedelta(hours=5))
        self.tasks(60, 'expired', WAIT, kind='nmap', ago=timedelta(minutes=30))
        waiting = self.checks(**refusal_signals())['sentinel_waiting']
        self.assertIn('not claiming work', waiting['title'].lower())
        self.assertIn('No Sentinel has claimed any task in the last two hours', waiting['detail'])
        self.assertNotIn('Add a Sentinel', waiting['detail'])

    def test_slots_really_busy_keeps_the_capacity_advice(self):
        self.live(count=2, slots=4)
        self.tasks(200, 'done', ago=timedelta(hours=5))
        self.tasks(10, 'expired', WAIT, kind='nmap', ago=timedelta(hours=4))
        self.tasks(60, 'expired', WAIT, kind='nmap', ago=timedelta(minutes=30))
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind='nmap', target={}, status='running') for _ in range(8)]
                                         + [SentinelTask(project=self.proj, kind='nmap', target={}, status='queued') for _ in range(12)])
        waiting = self.checks(**refusal_signals())['sentinel_waiting']
        self.assertFalse(waiting['facts']['not_claiming'])
        self.assertIn('Add a Sentinel', waiting['detail'])

    def test_incident_starved_scans_are_found_from_the_database(self):
        with mock.patch.object(reviewer, '_starvation_inputs', return_value=starve_work(scans_queued=18, assessments_running=8, assessments_queued=360)):
            found = self.checks(**queue_signals(16 * 3600))
        self.assertEqual(found['queue_starvation']['state'], 'problem')
        self.assertIn('360 queued', found['queue_starvation']['detail'])


class StaleAlertTests(Base):
    def test_an_alert_not_re_checked_for_an_hour_says_so_and_a_fresh_one_does_not(self):
        old = timezone.now() - timedelta(hours=3)
        AdminAlert.objects.create(code='workers_down', severity='critical', title='Background workers are down', detail='A lane is gone.', facts={}, digest='a',
                                  first_seen=old, last_seen=old)
        AdminAlert.objects.create(code='memory', severity='warning', title='Memory', detail='Fresh.', facts={}, digest='b', first_seen=old, last_seen=timezone.now())
        AdminAlert.objects.create(code='watchdog_R1', severity='warning', title='Own lifecycle', detail='Old.', facts={}, digest='c', first_seen=old, last_seen=old)
        by = {a['code']: a for a in reviewer.open_alerts()}
        self.assertTrue(by['workers_down']['stale'])
        self.assertTrue(by['workers_down']['detail'].startswith('Not re-checked for 3 hours, so this may no longer be true. A lane is gone.'))
        self.assertFalse(by['memory']['stale'])
        self.assertEqual(by['memory']['detail'], 'Fresh.')
        self.assertFalse(by['watchdog_R1']['stale'])  # the watchdog's own notices have their own lifecycle


class WatchdogRunsTheChecksTests(Base):
    """AM-9: the checks do not depend on the Celery lane that dies in the incidents."""

    def wd_state(self):
        from cveFeed import watchdog
        from cveFeed.models import WatchdogState
        return WatchdogState.objects.get_or_create(rule=watchdog.ALL)[0]

    def test_a_tick_with_the_beat_task_never_run_opens_workers_down(self):
        from cveFeed import watchdog
        health = {'workers_state': 'degraded', 'worker_note': 'no lane answered', 'workers': [{'worker': 'cve_feed', 'consuming': False}, {'worker': 'classic', 'consuming': True}],
                  'jobs': {}, 'schedules': [], 'beat': {'state': 'ticking'}, 'last_activity': None}
        self.assertFalse(AdminAlert.objects.filter(code='workers_down').exists())
        with mock.patch('agentapi.system_status._workers_and_jobs', return_value=health), patched_signals():
            result = watchdog._run_ops_checks(self.wd_state(), timezone.now())  # no Celery task ran: the tick alone raised it
        self.assertIn('opened', result)
        alert = AdminAlert.objects.get(code='workers_down', resolved_at__isnull=True)
        self.assertIn('cve_feed', alert.detail)

    def test_it_runs_every_thirty_minutes_not_every_tick(self):
        from cveFeed import watchdog
        state, now = self.wd_state(), timezone.now()
        with mock.patch.object(reviewer, 'run_ops_checks', return_value={'opened': 0, 'resolved': 0}) as run:
            self.assertEqual(watchdog._run_ops_checks(state, now), {'opened': 0, 'resolved': 0})
            self.assertEqual(watchdog._run_ops_checks(state, now + timedelta(seconds=30)), '')
            self.assertEqual(watchdog._run_ops_checks(state, now + timedelta(minutes=29)), '')
            watchdog._run_ops_checks(state, now + timedelta(minutes=31))
        self.assertEqual(run.call_count, 2)

    def test_a_failed_run_is_tried_again_in_five_minutes(self):
        from cveFeed import watchdog
        state, now = self.wd_state(), timezone.now()
        with mock.patch.object(reviewer, 'run_ops_checks', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                watchdog._run_ops_checks(state, now)
        with mock.patch.object(reviewer, 'run_ops_checks', return_value={}) as run:
            self.assertEqual(watchdog._run_ops_checks(state, now + timedelta(minutes=2)), '')
            watchdog._run_ops_checks(state, now + timedelta(minutes=6))
        self.assertEqual(run.call_count, 1)
