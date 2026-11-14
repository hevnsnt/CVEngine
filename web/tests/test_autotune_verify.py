"""The maintainer verifies what it changes (1.4.0 WP3): every tuning decision records what it expected to improve and the measurements before it,
is judged after a settling time against the same measurements (``autotune_policy.verdict``, a pure function), the outcome is stored on the
decision, and a calm change that made things worse is put back by the tuner and not tried again for a day. One calm change is unverified at a
time; a forced back-off, a cap and an emergency back-off never wait. The watchdog's memory pause is evidence for one back-off (AM-8). After a long
Sentinel outage the aim is repeated and a probe lands exactly on the target (AM-11)."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import autotune, autotune_policy as policy, autotune_signals as signals
from cveFeed.models import AutoTuneSettings, ScanControl, TuningDecision
from reNgine import resources
from tests.test_autotune import (BASE, BATCH, DEPTH, DISCOVERY32, NMAP8, NOW, REFRESH_GAP, SETTLED, SETTINGS, STAGE16, TWO_SENTINELS, WORK_GAP, Isolated,
                                 change, decide, history, merge)

QUEUE_BEFORE = {'discovery': {'active': 8, 'ceiling': 8, 'queued': 40}, 'sentinel': {'live': 2, 'slots': 9}}
QUEUE_AFTER = {'discovery': {'active': 8, 'ceiling': 8, 'queued': 5}, 'sentinel': {'live': 2, 'slots': 9}}
QUEUE_WORSE = {'discovery': {'active': 8, 'ceiling': 8, 'queued': 70}, 'sentinel': {'live': 2, 'slots': 9}}
QUEUE_BLIND = {'discovery': {'active': 8, 'ceiling': 8, 'queued': None}, 'sentinel': {'live': 2, 'slots': 9}}


def before(metric, value, trouble=0, kills=0, oom=0):
    return {'metric': metric, 'better': policy.METRICS[metric][0], 'value': value, 'trouble': trouble, 'kills': kills, 'oom': oom}


class VerdictTests(SimpleTestCase):
    """``autotune_policy.verdict``: a pure function of the measurements before and after, over a table of cases."""

    CASES = [
        # (metric, before, after, outcome)
        ('discovery_queue', 40, 5, 'helped'),
        ('discovery_queue', 40, 32, 'helped'),          # exactly the 20 percent that counts
        ('discovery_queue', 40, 33, 'no_effect'),
        ('discovery_queue', 40, 36, 'no_effect'),
        ('discovery_queue', 10, 2, 'helped'),
        ('discovery_queue', 4, 2, 'no_effect'),         # under the floor of 3: noise
        ('discovery_queue', 5, 40, 'regressed'),
        ('discovery_queue', 5, 10, 'no_effect'),
        ('discovery_queue', 5, 11, 'regressed'),        # twice the floor, and half of its value before
        ('discovery_queue', 0, 5, 'no_effect'),
        ('discovery_queue', 0, 6, 'regressed'),
        ('discovery_queue', 0, 0, 'no_effect'),
        ('discovery_queue', None, 5, 'unknown'),
        ('discovery_queue', 5, None, 'unknown'),
        ('discovery_queue', None, None, 'unknown'),
        ('assess_oldest_s', 7200, 600, 'helped'),
        ('assess_oldest_s', 3600, 3000, 'no_effect'),
        ('assess_oldest_s', 600, 3000, 'regressed'),
        ('wait_share', 1.0, 0.2, 'helped'),
        ('wait_share', 0.2, 0.9, 'regressed'),
        ('wait_share', 0.5, 0.45, 'no_effect'),
        ('conductor_saturated_share', 1.0, 0.0, 'helped'),
        ('conductor_idle_share', 0.0, 1.0, 'regressed'),
        ('sentinel_idle_share', 0.9, 0.3, 'helped'),
        ('trouble', 1, 0, 'helped'),
        ('trouble', 1, 1, 'no_effect'),
        ('trouble', None, 0, 'unknown'),
    ]

    def test_the_expected_measurement_decides_when_nothing_else_happened(self):
        for metric, was, now, outcome in self.CASES:
            got = policy.verdict(before(metric, was), {**before(metric, now)})
            self.assertEqual(got.outcome, outcome, (metric, was, now, got.detail))
            self.assertTrue(got.detail, (metric, was, now))

    def test_a_better_expected_measurement_does_not_excuse_a_new_kill_restart_or_trouble(self):
        for name, was, now in (('kills', 0, 1), ('kills', 2, 3), ('oom', 0, 1), ('oom', 4, 5)):
            got = policy.verdict(before('discovery_queue', 40, **{name: was}), before('discovery_queue', 5, **{name: now}))
            self.assertEqual(got.outcome, 'regressed', (name, was, now))
            self.assertIn(str(now), got.detail)
        got = policy.verdict(before('discovery_queue', 40, trouble=0), before('discovery_queue', 5, trouble=1))
        self.assertEqual(got.outcome, 'regressed')
        # unchanged or fewer kills, trouble that was already there: not a regression of its own
        for was, now in ((1, 1), (3, 0)):
            self.assertEqual(policy.verdict(before('discovery_queue', 40, kills=was), before('discovery_queue', 5, kills=now)).outcome, 'helped')
        self.assertEqual(policy.verdict(before('discovery_queue', 40, trouble=1), before('discovery_queue', 5, trouble=1)).outcome, 'helped')

    def test_an_unknown_number_is_never_an_improvement(self):
        # kills not measured before or after: no regression is claimed, and the judgement stays with the expected measurement
        got = policy.verdict(before('discovery_queue', 40, kills=None, oom=None), before('discovery_queue', 5, kills=3, oom=None))
        self.assertEqual(got.outcome, 'helped')
        for was, now in ((None, 0), (40, None), (None, None)):
            got = policy.verdict(before('discovery_queue', was), before('discovery_queue', now))
            self.assertEqual(got.outcome, 'unknown')
            self.assertNotEqual(got.outcome, 'helped')
        for broken in ({}, {'metric': 'made_up', 'value': 1}, {'metric': None}):
            self.assertEqual(policy.verdict(broken, before('discovery_queue', 1)).outcome, 'unknown')
        self.assertEqual(policy.verdict(before('discovery_queue', 40), before('wait_share', 0.1)).outcome, 'unknown')  # not the same measurement
        # a regression the guards see is still a regression when the expected measurement is unknown
        self.assertEqual(policy.verdict(before('discovery_queue', None), before('discovery_queue', None, kills=1)).outcome, 'regressed')

    def test_every_metric_has_a_direction_floor_and_label_and_every_setting_a_metric(self):
        for name, (better, floor, label) in policy.METRICS.items():
            self.assertIn(better, ('lower', 'higher'))
            self.assertGreater(floor, 0)
            self.assertTrue(label)
        for setting in SETTINGS:
            for direction in ('more', 'less'):
                self.assertIn(policy.expectation(setting, direction), policy.METRICS)

    def test_what_a_change_expects_to_improve(self):
        self.assertEqual(policy.expectation(NMAP8, 'more'), 'wait_share')
        self.assertEqual(policy.expectation(DISCOVERY32, 'more'), 'discovery_queue')
        self.assertEqual(policy.expectation(BATCH, 'more'), 'assess_oldest_s')
        self.assertEqual(policy.expectation(DEPTH, 'more'), 'conductor_saturated_share')
        self.assertEqual(policy.expectation(STAGE16, 'more'), 'sentinel_idle_share')
        self.assertEqual(policy.expectation(WORK_GAP, policy.direction_of(WORK_GAP, 2, 1)), 'conductor_idle_share')  # a shorter gap is more work
        self.assertEqual(policy.expectation(REFRESH_GAP, policy.direction_of(REFRESH_GAP, 6, 3)), 'sentinel_idle_share')
        for setting in SETTINGS:
            self.assertEqual(policy.expectation(setting, 'less'), 'trouble')  # backing off expects the trouble to go


class MeasureTests(SimpleTestCase):
    def test_the_expected_measurement_is_read_from_the_samples(self):
        got = policy.measure(DISCOVERY32, history(3, discovery={'active': 8, 'ceiling': 8, 'queued': 40}))
        self.assertEqual((got['metric'], got['better'], got['value'], got['trouble'], got['n']), ('discovery_queue', 'lower', 40.0, 0, 3))
        self.assertEqual(policy.measure(DISCOVERY32, [merge(BASE, {'t': 1, 'discovery': {'queued': 10}}), merge(BASE, {'t': 2, 'discovery': {'queued': 20}})])['value'], 15.0)

    def test_what_was_not_measured_is_none_never_zero(self):
        self.assertIsNone(policy.measure(DISCOVERY32, history(3, discovery={'queued': None}))['value'])
        self.assertIsNone(policy.measure(BATCH, history(3, assess=None))['value'])                       # the assessment probe failed
        self.assertEqual(policy.measure(BATCH, history(3))['value'], 0.0)                              # nothing queued: a known zero
        self.assertIsNone(policy.measure(STAGE16, history(3))['value'])                                # no live Sentinel: not measured
        self.assertEqual(policy.measure(STAGE16, history(3, sentinel={'live': 2, 'slots': 9, 'in_use': 3}))['value'], 0.667)
        self.assertIsNone(policy.measure(NMAP8, history(3, memory={'reported': False}))['value'])
        self.assertEqual(policy.measure(NMAP8, history(3))['value'], 1.0)
        self.assertIsNone(policy.measure(DEPTH, history(3, conductor={'state': 'unknown'}))['value'])
        self.assertEqual(policy.measure(DEPTH, history(3, conductor={'state': 'saturated'}))['value'], 1.0)
        empty = policy.measure(DISCOVERY32, [])
        self.assertEqual((empty['value'], empty['trouble'], empty['n']), (None, None, 0))

    def test_kills_and_restarts_are_counted_and_unknown_when_nothing_measured_them(self):
        got = policy.measure(DISCOVERY32, history(3, maint={'oom_kills_24h': 2, 'lane_restarts_24h': 1}, memory={'kills': 1}))
        self.assertEqual((got['kills'], got['oom']), (3, 3))
        got = policy.measure(DISCOVERY32, history(3))
        self.assertEqual((got['kills'], got['oom']), (0, None))
        self.assertEqual(policy.measure(DISCOVERY32, history(3, memory={'reported': False}))['kills'], None)

    def test_trouble_is_what_the_trouble_rule_says(self):
        self.assertEqual(policy.measure(DISCOVERY32, history(3, memory={'free_frac': 0.05}), direction='less')['trouble'], 1)
        self.assertEqual(policy.measure(DISCOVERY32, history(3), direction='less')['value'], 0.0)


class GateTests(SimpleTestCase):
    def test_when_a_change_is_judged(self):
        at = 10_000.0
        for now, count, want in ((at - 121, 3, 'wait'), (at - 119, 3, 'judge'), (at, 3, 'judge'), (at, 2, 'wait'), (at + 600, 1, 'wait'),
                                 (at + policy.VERIFY_GIVE_UP_SECONDS - 1, 2, 'wait'), (at + policy.VERIFY_GIVE_UP_SECONDS, 2, 'give_up'),
                                 (at + policy.VERIFY_GIVE_UP_SECONDS, 0, 'give_up'), (at + policy.VERIFY_GIVE_UP_SECONDS, 3, 'judge')):
            self.assertEqual(policy.verify_due(now, at, count), want, (now - at, count))

    def test_which_changes_wait_which_hold_and_which_are_taken_back(self):
        table = [  # phase, pressure: (blocks the next calm change, waits for the gate, is reverted when it regressed)
            ('probe', False, True, True, True), ('recover', False, True, True, True), ('', False, True, True, True),
            ('aim_high', False, True, False, True),   # the one-off jump: never waits, but the next calm change waits for it
            ('back_off', True, False, False, False), ('cap', False, False, False, False), ('emergency', False, False, False, False),
            ('verify', True, False, False, False), ('', True, False, False, False),
        ]
        for phase, pressure, blocks, waits, reverted in table:
            self.assertEqual(policy.blocks_calm(phase, pressure), blocks, (phase, pressure))
            self.assertEqual(policy.is_calm(phase, pressure), waits, (phase, pressure))
            self.assertEqual(policy.revert_wanted('regressed', phase, pressure), reverted, (phase, pressure))
            for outcome in ('helped', 'no_effect', 'unknown', ''):
                self.assertFalse(policy.revert_wanted(outcome, phase, pressure), (phase, pressure, outcome))


class ReaimTests(SimpleTestCase):
    """AM-11 in the pure policy."""
    busy = history(13)

    def test_a_probe_lands_exactly_on_the_target_when_one_step_would_pass_it(self):
        with mock.patch.object(policy, 'room', return_value=None), mock.patch.object(policy, 'demand', return_value=None):
            for value in (16, 17):
                plan = decide(BATCH, value, 8, self.busy, past=SETTLED, target=18)
                self.assertEqual((plan['phase'], plan['new']), ('probe', 18), value)  # the step is 4: it used to stop at 16 for good
            self.assertEqual(decide(BATCH, 18, 8, self.busy, past=SETTLED, target=18)['new'], None)
            self.assertEqual(decide(BATCH, 12, 8, self.busy, past=SETTLED, target=18)['new'], 16)  # a whole step still goes by steps

    def test_after_a_cap_the_aim_is_repeated_once_the_facts_are_back(self):
        outage = [change(8 * 3600, 8, 18, 'aim_high'), change(2 * 3600, 18, 8, 'cap')]
        plan = decide(BATCH, 8, 8, history(3), past=outage, target=18)
        self.assertEqual((plan['phase'], plan['new']), ('aim_high', 18))
        self.assertIn('aimed again', plan['reason'])
        self.assertEqual(plan['ai_range'], (8, 18))

    def test_the_aim_is_not_repeated_without_a_cap_after_a_day_twice_a_day_or_while_held_or_with_remembered_trouble(self):
        base = [change(8 * 3600, 8, 18, 'aim_high')]
        self.assertNotEqual(decide(BATCH, 18, 8, history(3), past=base, target=18)['phase'], 'aim_high')  # nothing was capped
        old = base + [change(26 * 3600, 18, 8, 'cap')]
        self.assertNotEqual(decide(BATCH, 8, 8, history(3), past=old, target=18)['phase'], 'aim_high')
        twice = [change(8 * 3600, 8, 18, 'aim_high'), change(5 * 3600, 18, 8, 'cap'), change(4 * 3600, 8, 18, 'aim_high'), change(1 * 3600, 18, 8, 'cap')]
        self.assertNotEqual(decide(BATCH, 8, 8, history(3), past=twice, target=18)['phase'], 'aim_high')
        capped = base + [change(2 * 3600, 18, 8, 'cap')]
        self.assertNotEqual(decide(BATCH, 8, 8, history(3), past=capped, target=18, hold_until=NOW + 3600)['phase'], 'aim_high')
        trouble = base + [change(3 * 3600, 18, 12, 'back_off', pressure=True), change(2 * 3600, 12, 8, 'cap')]
        plan = decide(BATCH, 8, 8, history(3), past=trouble, target=18)
        self.assertEqual((plan['phase'], plan['new']), ('aim_high', 14))  # aimed again, but not up to the level that caused trouble


class PauseEvidenceTests(SimpleTestCase):
    def test_a_memory_pause_is_trouble_for_what_holds_memory_only(self):
        busy = history(3)
        why = 'the watchdog paused the starting of work'
        for setting in (DISCOVERY32, DEPTH, WORK_GAP, NMAP8):
            self.assertEqual(policy.trouble(setting, busy, why), why, setting.key)  # nmap has two runs going in BASE
        for setting in (BATCH, STAGE16, REFRESH_GAP):
            self.assertIsNone(policy.trouble(setting, busy, why), setting.key)
        self.assertIsNone(policy.trouble(NMAP8, history(3, memory={'running': {'nmap': 0}, 'waiting': {'nmap': 0}}), why))  # no run of it was going
        self.assertIsNone(policy.trouble(DISCOVERY32, busy))                               # no pause, no trouble
        plan = decide(DISCOVERY32, 16, 8, busy, past=SETTLED, pause=why)
        self.assertEqual((plan['phase'], plan['pressure'], plan['new']), ('back_off', True, 12))


class VerifyRunTests(Isolated, TestCase):
    """The run end to end: the record, the verdict stored, the revert, the one-at-a-time gate, the emergency and the memory pause."""

    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('verify_root', 'v@x.io', 'x')
        self.start = timezone.now()

    def run_at(self, minutes, over=None):
        resources.redis_client().delete('cvengine:sweep:autotune')
        sample = merge(BASE, {'t': (self.start + timedelta(minutes=minutes)).timestamp(), **(over or {})})
        with mock.patch.object(signals, 'collect', return_value=sample):
            return autotune.run(self.start + timedelta(minutes=minutes))

    def pool(self):
        return AutoTuneSettings.current().values.get('discovery_concurrency')

    def test_a_change_records_what_it_expected_and_the_measurements_before_it(self):
        summary = self.run_at(0, QUEUE_BEFORE)
        self.assertIn('discovery_concurrency', [c['setting'] for c in summary['changes']])
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual((d.applied, d.phase, d.expected, d.outcome), (True, 'aim_high', 'discovery_queue', ''))
        self.assertEqual((d.baseline['metric'], d.baseline['value'], d.baseline['better'], d.baseline['direction']), ('discovery_queue', 40.0, 'lower', 'more'))
        self.assertEqual((d.baseline['trouble'], d.baseline['n']), (0, 1))
        self.assertAlmostEqual((d.verify_at - self.start).total_seconds(), policy.VERIFY_SETTLE_SECONDS, delta=2)
        self.assertIsNone(d.verified_at)
        item = autotune.serialize(d)
        self.assertEqual((item['expected'], item['outcome'], item['baseline']['value']), ('discovery_queue', None, 40.0))
        self.assertTrue(item['verify_at'])

    def test_a_change_that_helped_is_kept_and_judged_after_the_settling_time_only(self):
        self.run_at(0, QUEUE_BEFORE)
        self.assertEqual(self.pool(), 22)
        for minutes in (10, 20):
            summary = self.run_at(minutes, QUEUE_AFTER)
            self.assertEqual(summary['verified'], [], minutes)  # three measurements after it, and thirty minutes, first
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual(d.outcome, '')
        summary = self.run_at(30, QUEUE_AFTER)
        judged = {j['setting']: j for j in summary['verified']}
        self.assertEqual((judged['discovery_concurrency']['outcome'], judged['discovery_concurrency']['reverted']), ('helped', False))
        d.refresh_from_db()
        self.assertEqual((d.outcome, d.resolution, d.baseline['after']['value']), ('helped', '', 5.0))
        self.assertIn('40 before, 5 after', d.outcome_detail)
        self.assertIsNotNone(d.verified_at)
        self.assertEqual(self.pool(), 22)  # kept
        self.assertFalse(TuningDecision.objects.filter(action='revert').exists())
        self.run_at(40, QUEUE_AFTER)  # judged once
        self.assertEqual(TuningDecision.objects.get(pk=d.pk).verified_at, d.verified_at)

    def test_a_change_that_made_things_worse_is_reverted_once_and_cooled_down(self):
        self.run_at(0, {**QUEUE_BEFORE, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 5}})
        self.assertEqual(self.pool(), 22)
        for minutes in (10, 20):
            self.run_at(minutes, QUEUE_WORSE)
        summary = self.run_at(30, QUEUE_WORSE)
        judged = {j['setting']: j for j in summary['verified']}
        self.assertEqual((judged['discovery_concurrency']['outcome'], judged['discovery_concurrency']['reverted']), ('regressed', True))
        self.assertEqual(self.pool(), 8)  # back to where it was
        original = TuningDecision.objects.get(setting='discovery_concurrency', phase='aim_high')
        self.assertEqual((original.outcome, original.resolution, original.resolved_by), ('regressed', 'reverted', 'auto-tune'))
        back = TuningDecision.objects.get(setting='discovery_concurrency', action='revert')
        self.assertEqual((back.old_value, back.new_value, back.phase, back.source, back.pressure, back.applied, back.outcome),
                         (22, 8, 'verify', 'controller', True, True, 'reverted'))
        self.assertIn('5 before, 70 after', back.reason)
        self.assertIsNone(back.verify_at)  # a revert is not judged in its turn
        # the cool-down: neither the aim nor a probe brings the pool up again, and it is not reverted twice
        for minutes in (40, 50, 60, 300):
            summary = self.run_at(minutes, QUEUE_WORSE)
            self.assertNotIn('discovery_concurrency', [c['setting'] for c in summary['changes']], minutes)
        self.assertEqual(self.pool(), 8)
        self.assertEqual(TuningDecision.objects.filter(setting='discovery_concurrency', action='revert').count(), 1)
        self.assertIn('reverted', summary['settings']['discovery_concurrency']['why_not_raised'])
        # a person can read the reverted decision but cannot revert it again
        with self.assertRaises(autotune.TuningError):
            autotune.revert(self.root, original.pk)

    def test_a_revert_does_not_overwrite_a_later_change(self):
        self.run_at(0, {**QUEUE_BEFORE, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 5}})
        original = TuningDecision.objects.get(setting='discovery_concurrency')
        row = AutoTuneSettings.current()
        row.values = {**row.values, 'discovery_concurrency': 18}  # something else moved it since
        row.save()
        for minutes in (10, 20, 30):
            summary = self.run_at(minutes, QUEUE_WORSE)
        self.assertEqual(TuningDecision.objects.get(pk=original.pk).outcome, 'regressed')
        self.assertEqual(self.pool(), 18)
        self.assertFalse(TuningDecision.objects.filter(action='revert').exists())
        self.assertEqual(TuningDecision.objects.get(pk=original.pk).resolution, '')

    def test_a_measurement_that_could_not_be_taken_is_unknown_and_nothing_is_reverted(self):
        self.run_at(0, QUEUE_BEFORE)
        for minutes in (10, 20, 30):
            summary = self.run_at(minutes, QUEUE_BLIND)
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual(d.outcome, 'unknown')
        self.assertIn('not measured after', d.outcome_detail)
        self.assertEqual(self.pool(), 22)
        self.assertFalse(TuningDecision.objects.filter(action='revert').exists())

    def test_a_change_that_cannot_be_judged_for_hours_is_given_up_not_held_for_ever(self):
        self.run_at(0, QUEUE_BEFORE)
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertTrue(autotune.calm_change_unverified())
        summary = self.run_at(policy.VERIFY_SETTLE_SECONDS // 60 + policy.VERIFY_GIVE_UP_SECONDS // 60 + 1, QUEUE_AFTER)
        self.assertEqual(TuningDecision.objects.get(pk=d.pk).outcome, 'unknown')
        self.assertIn('measurement(s) came after', TuningDecision.objects.get(pk=d.pk).outcome_detail)
        self.assertFalse(TuningDecision.objects.filter(action='revert').exists())

    def probing_state(self):
        """Five hours of healthy, busy measurements, aimed high three hours ago: every setting that has work waiting may probe up one step."""
        boot = timezone.now().timestamp() - 5 * 3600
        started = mock.patch.object(autotune, '_process_started', return_value=boot)
        started.start()
        self.addCleanup(started.stop)
        for m in autotune.managed():  # every setting aimed high three hours ago, since the restart: the probing regime
            old = TuningDecision.objects.create(setting=m.key, old_value=1, new_value=2, mode='auto', source='controller', action='raise', layer='auto',
                                                applied=True, phase='aim_high')
            TuningDecision.objects.filter(pk=old.pk).update(created_at=self.start - timedelta(hours=3))
        row = AutoTuneSettings.current()
        row.values = {'discovery_concurrency': 8, 'heavy.nmap': 2, 'assess_batch': 16}
        row.save()
        autotune.publish(row)
        for i, s in enumerate(history(31, end=(self.start - timedelta(minutes=1)).timestamp())):
            autotune.store_sample(merge(s, {'discovery': {'active': 8, 'ceiling': 8, 'queued': 30}}))

    BUSY = {'discovery': {'active': 8, 'ceiling': 8, 'queued': 30}}

    def test_only_one_calm_change_is_unverified_at_a_time(self):
        self.probing_state()
        summary = self.run_at(0, self.BUSY)
        probes = [c for c in summary['changes']]
        self.assertEqual(len(probes), 1, summary['changes'])
        first = TuningDecision.objects.get(pk=probes[0]['id'])
        self.assertEqual((first.phase, first.pressure), ('probe', False))
        waiting = [k for k, v in summary['settings'].items() if 'one calm change at a time' in (v.get('why_not_raised') or '')]
        self.assertTrue(waiting, summary['settings'])  # others had a probe to make and waited
        self.assertTrue(autotune.calm_change_unverified())
        for minutes in (10, 20):
            self.assertEqual(self.run_at(minutes, self.BUSY)['changes'], [], minutes)  # still unverified: nothing else calm
        summary = self.run_at(30, self.BUSY)  # judged first, then the next calm change may go
        self.assertEqual([j['id'] for j in summary['verified']], [first.pk])
        self.assertEqual(TuningDecision.objects.get(pk=first.pk).verified_at is not None, True)
        self.assertEqual(len(summary['changes']), 1)
        self.assertNotEqual(summary['changes'][0]['setting'], first.setting)

    def test_a_forced_back_off_does_not_wait_for_an_unverified_change(self):
        self.probing_state()
        self.run_at(0, self.BUSY)
        self.assertTrue(autotune.calm_change_unverified())
        summary = self.run_at(10, {'memory': {'free_frac': 0.05, 'running': {'nmap': 2}}})
        backs = [c for c in summary['changes']]
        self.assertTrue(backs)
        decisions = TuningDecision.objects.filter(pk__in=[c['id'] for c in backs])
        self.assertTrue(all(d.pressure and d.phase == 'back_off' for d in decisions))
        self.assertTrue(all(d.expected == 'trouble' and d.verify_at for d in decisions))  # judged for the record
        self.assertFalse(any(policy.blocks_calm(d.phase, d.pressure) for d in decisions))

    def test_a_forced_back_off_is_judged_but_never_reverted_upwards(self):
        row = AutoTuneSettings.current()
        row.values = {'discovery_concurrency': 24}
        row.save()
        autotune.publish(row)
        low = {'memory': {'free_frac': 0.05}, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 5}}
        self.run_at(0, low)
        d = TuningDecision.objects.get(setting='discovery_concurrency', pressure=True)
        self.assertEqual((d.phase, d.baseline['trouble'], d.baseline['value']), ('back_off', 1, 1.0))
        before_pool = self.pool()
        for minutes in (10, 20, 30):
            self.run_at(minutes, {'memory': {'free_frac': 0.05}, 'maint': {'oom_kills_24h': 1}})
        d.refresh_from_db()
        self.assertIn(d.outcome, ('no_effect', 'regressed'))
        self.assertFalse(TuningDecision.objects.filter(setting='discovery_concurrency', action='revert').exists())
        self.assertLessEqual(self.pool(), before_pool)

    def test_an_emergency_back_off_still_acts_with_a_change_unverified(self):
        self.probing_state()
        self.run_at(0, self.BUSY)
        self.assertTrue(autotune.calm_change_unverified())
        from django.db import OperationalError
        row = AutoTuneSettings.current()
        row.values = {**row.values, 'discovery_concurrency': 24, 'work_depth': 8}
        row.save()
        autotune.publish(row)
        results = []
        for minutes in (10, 20):
            resources.redis_client().delete('cvengine:sweep:autotune')
            with mock.patch.object(autotune, 'settings_row', side_effect=OperationalError('too many clients')), \
                    mock.patch.object(autotune, '_resize_discovery_directly'):
                results.append(autotune.run(self.start + timedelta(minutes=minutes)))
        self.assertEqual({c['setting']: (c['from'], c['to']) for c in results[1]['changes']}, {'discovery_concurrency': (24, 18), 'work_depth': (8, 6)})
        self.run_at(30, self.BUSY)  # the database answers again: recorded, and not judged (nothing to compare)
        emergency = TuningDecision.objects.filter(phase='emergency')
        self.assertTrue(emergency.exists())
        self.assertFalse(emergency.exclude(outcome='').exists())
        self.assertFalse(emergency.exclude(verify_at=None).exists())

    # --- AM-8: the watchdog's memory pause -------------------------------------------------------------------------------------------

    def pause_state(self, reason='Paused by the watchdog: memory nearly full', by_update=True, over=None):
        row = AutoTuneSettings.current()
        row.values = {'discovery_concurrency': 16, 'work_depth': 5}
        row.save()
        autotune.publish(row)
        for s in history(3, end=(self.start - timedelta(minutes=1)).timestamp(), **(over or {})):
            autotune.store_sample(s)
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': by_update, 'reason': reason,
                                                             'changed_at': self.start - timedelta(minutes=2)})

    def paused_run(self, minutes):
        return self.run_at(minutes, {'paused': True})

    def test_the_memory_pause_is_taken_as_evidence_and_the_settings_back_off_once(self):
        self.pause_state(over={'memory': {'free_frac': 0.04}})  # the measurements just before the pause show little memory
        summary = self.paused_run(0)
        changes = {c['setting']: c for c in summary['changes']}
        self.assertEqual((changes['discovery_concurrency']['from'], changes['discovery_concurrency']['to']), (16, 12))
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual((d.pressure, d.phase, d.applied, d.source), (True, 'back_off', True, 'controller'))
        self.assertTrue(d.signals['watchdog_memory_pause'])
        self.assertIn('backed off once', summary['held'])
        self.assertEqual(self.pool(), 12)
        again = self.paused_run(10)
        self.assertEqual(again['changes'], [])  # once per pause, not every run
        self.assertEqual(TuningDecision.objects.filter(setting='discovery_concurrency').count(), 1)
        # the pause ends: the same numbers do not simply come back
        ScanControl.objects.filter(pk=1).update(paused=False, paused_by_update=False, reason='')
        for minutes in (20, 30, 40):
            summary = self.run_at(minutes, self.BUSY)
            self.assertEqual([c for c in summary['changes'] if c['setting'] == 'discovery_concurrency'], [], minutes)
        self.assertEqual(self.pool(), 12)
        self.assertEqual(TuningDecision.objects.filter(setting='discovery_concurrency', action='raise').count(), 0)

    def test_the_pause_alone_is_evidence_when_the_scanners_own_memory_looked_fine(self):
        self.pause_state()  # host memory is over 90 percent, the scanning container's free share was fine
        summary = self.paused_run(0)
        self.assertEqual(self.pool(), 12)
        self.assertIn('discovery_concurrency', [c['setting'] for c in summary['changes']])
        self.assertTrue(all(TuningDecision.objects.get(pk=c['id']).pressure for c in summary['changes']))

    def test_a_pause_that_is_not_the_watchdogs_memory_pause_still_changes_nothing(self):
        for reason, by_update in (('Paused by the watchdog: disk nearly full', True), ('An update is being applied', True), ('maintenance', False)):
            ScanControl.objects.all().delete()
            TuningDecision.objects.all().delete()
            self.pause_state(reason=reason, by_update=by_update, over={'memory': {'free_frac': 0.04}})
            summary = self.paused_run(0)
            self.assertEqual(summary['changes'], [], reason)
            self.assertIn('nothing changes', summary['held'])
            self.assertFalse(TuningDecision.objects.exists(), reason)

    def test_in_suggest_mode_the_memory_pause_makes_a_recommendation_not_a_change(self):
        self.pause_state(over={'memory': {'free_frac': 0.04}})
        AutoTuneSettings.objects.filter(pk=AutoTuneSettings.current().pk).update(mode='suggest')
        summary = self.paused_run(0)
        self.assertTrue(summary['changes'])
        self.assertTrue(all(c['applied'] is False for c in summary['changes']))
        self.assertFalse(TuningDecision.objects.filter(applied=True).exists())

    # --- AM-11 end to end ------------------------------------------------------------------------------------------------------------

    def test_after_a_long_sentinel_outage_the_aim_is_repeated_and_lands_exactly_on_the_target(self):
        def tuned():
            values = AutoTuneSettings.current().values
            return values['discovery_concurrency'], values['stage_parallel'], values['assess_batch'], values['work_depth']
        self.run_at(0, TWO_SENTINELS)
        self.assertEqual(tuned(), (22, 9, 18, 7))
        gone = {'sentinel': {'live': 1, 'slots': 4}}  # one of the two Sentinels, with four of the nine slots, stays away
        for minutes in (10, 20, 30):
            self.run_at(minutes, gone)
        self.assertEqual(tuned(), (12, 4, 8, 5))  # capped: the Sentinels are gone (as before)
        summary = self.run_at(40, TWO_SENTINELS)  # and back
        self.assertEqual({c['setting']: (c['from'], c['to']) for c in summary['changes'] if c['setting'] in ('discovery_concurrency', 'stage_parallel',
                                                                                                          'assess_batch', 'work_depth')},
                         {'discovery_concurrency': (12, 22), 'stage_parallel': (4, 9), 'assess_batch': (8, 18), 'work_depth': (5, 7)})
        self.assertEqual(tuned(), (22, 9, 18, 7))  # exactly the target, in one jump, not after two days of probes
        self.assertEqual(TuningDecision.objects.filter(setting='assess_batch', phase='aim_high').count(), 2)
        self.assertIn('aimed again', TuningDecision.objects.filter(setting='assess_batch').order_by('-pk').first().reason)
        again = self.run_at(50, TWO_SENTINELS)
        self.assertEqual([c for c in again['changes'] if c['setting'] == 'assess_batch'], [])  # and it does not repeat itself


class SignalTests(SimpleTestCase):
    def test_the_sample_carries_the_kernels_kills_and_the_lane_restarts_and_unknown_is_none(self):
        containers = {'containers': [{'state': 'known', 'oom_kills_24h': 2}, {'state': 'known', 'oom_kills_24h': 1}, {'state': 'unknown', 'oom_kills_24h': 9},
                                     {'state': 'known', 'oom_kills_24h': None}]}
        lanes = {'lanes': [{'restarts_24h': 1}, {'restarts_24h': None}, {'restarts_24h': 2}]}
        with mock.patch('agentapi.maintainer_signals.containers', return_value=containers), mock.patch('agentapi.maintainer_signals.lanes', return_value=lanes):
            self.assertEqual(signals.maintainer(NOW), {'oom_kills_24h': 3, 'lane_restarts_24h': 3})
        with mock.patch('agentapi.maintainer_signals.containers', return_value={'containers': []}), \
                mock.patch('agentapi.maintainer_signals.lanes', return_value={'lanes': [{'restarts_24h': None}]}):
            self.assertEqual(signals.maintainer(NOW), {'oom_kills_24h': None, 'lane_restarts_24h': None})
