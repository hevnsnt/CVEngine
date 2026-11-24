"""Per-Sentinel auto-tuning (cveFeed.autotune_sentinels, agentapi.sentinel_machine): the machine report a Sentinel sends is validated and bounded, stored
with the server's time and shown; each Sentinel's concurrency and per-kind slots back off fast on a kill, low memory, a load far above its CPUs or
timeouts, probe up slowly, never pass the machine's own setting, never move a number an administrator set, leave an offline Sentinel or one with no
report alone, and are verified and taken back when they hurt. The claim and the settings reply enforce what was chosen."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker, sentinel_machine, sentinel_settings
from agentapi.models import Agent, SentinelTask
from cveFeed import autotune, autotune_policy as policy, autotune_sentinels as at, autotune_signals as signals
from cveFeed.models import AutoTuneSettings, TuningDecision
from dashboard.models import AuditLog
from cvengine import resources
from tests.test_agentapi import call
from tests.test_autotune import BASE, Isolated, merge
from tests.test_sentinels import build_world, register_sentinel, reset_rates

NOW = 1_800_000_000.0
MACHINE = {'cpus': 4, 'host_cpus': 4, 'load': [0.8, 0.9, 1.0], 'mem_total_mb': 8000, 'mem_available_mb': 6000, 'swap_total_mb': 0, 'swap_free_mb': 0,
           'cgroup_limit_mb': None, 'cgroup_used_mb': None, 'cgroup_oom_kills': 0, 'oom_kills_1h': {}}


def row(t, **over):
    """One fresh per-Sentinel report: 4 CPUs, 75% memory available, light load, every one of its 6 slots held and work queued."""
    out = {'t': t, 'fresh': True, 'live': True, 'cpus': 4, 'host_cpus': 4, 'load1': 0.8, 'load5': 0.9, 'load1_per_cpu': 0.2, 'load5_per_cpu': 0.22,
           'avail_share': 0.75, 'avail_mb': 6000, 'total_mb': 8000, 'oom_1h': {}, 'cg_oom': 0, 'oom_failed': {}, 'timeouts': 0, 'done': 10, 'held': 6,
           'held_by_kind': {'nuclei_light': 2}, 'slots': 6, 'ceiling': 8, 'queued': 5}
    out.update(over)
    return out


def rows(n=14, end=NOW, **over):
    return [row(end - (n - 1 - i) * 600, **over) for i in range(n)]


def decide(value, ceiling, reports, past=(), **kw):
    return at.decide(value, ceiling, reports, list(past), now=NOW, probe_cooldown=7200, **kw)


class TelemetryValidationTests(SimpleTestCase):
    def test_a_well_formed_report_is_kept(self):
        got = sentinel_machine.clean_machine({**MACHINE, 'oom_kills_1h': {'nuclei_deep': 2}})
        self.assertEqual(got['cpus'], 4)
        self.assertEqual(got['load'], [0.8, 0.9, 1.0])
        self.assertEqual(got['oom_kills_1h'], {'nuclei_deep': 2})

    def test_every_field_is_bounded_and_anything_else_is_dropped(self):
        got = sentinel_machine.clean_machine({'cpus': 0, 'host_cpus': True, 'load': [1, 'x', 2], 'mem_total_mb': 1000, 'mem_available_mb': 5000,
                                              'swap_total_mb': -1, 'swap_free_mb': 3, 'cgroup_limit_mb': 1 << 40, 'cgroup_used_mb': 'lots',
                                              'cgroup_oom_kills': 2.5, 'oom_kills_1h': {'rm -rf /': 3, 'nmap': -1, 'nuclei_light': 10 ** 9, 'naabu': 1},
                                              'evil': '<script>'})
        self.assertEqual(got, {'cpus': None, 'host_cpus': None, 'load': None, 'mem_total_mb': 1000, 'mem_available_mb': None, 'swap_total_mb': None,
                               'swap_free_mb': None, 'cgroup_limit_mb': None, 'cgroup_used_mb': None, 'cgroup_oom_kills': None, 'oom_kills_1h': {'naabu': 1}})

    def test_a_load_that_is_not_a_finite_number_is_dropped(self):
        self.assertIsNone(sentinel_machine.clean_machine({**MACHINE, 'load': [float('nan'), 1, 1]})['load'])
        self.assertIsNone(sentinel_machine.clean_machine({**MACHINE, 'load': [10 ** 9, 1, 1]})['load'])

    def test_nothing_usable_or_not_an_object_is_none_and_never_refused(self):
        for bad in (None, 'x', [], {'cpus': 'many'}, {'evil': 1}):
            self.assertIsNone(sentinel_machine.clean_machine(bad))
        self.assertNotIn('machine', sentinel_settings.clean_info({'machine': 'junk'}))

    def test_the_view_uses_the_container_limit_and_the_host_load(self):
        class A:
            info = {'machine': {**MACHINE, 'load': [8.0, 6.0, 4.0], 'cgroup_limit_mb': 2000, 'cgroup_used_mb': 1800,
                                'at': timezone.now().isoformat()}}
        v = sentinel_machine.view(A())
        self.assertEqual((v['total_mb'], v['available_mb'], v['available_share']), (2000, 200, 0.1))
        self.assertEqual(v['load_per_cpu'], [2.0, 1.5, 1.0])
        self.assertFalse(v['stale'])
        A.info['machine']['at'] = (timezone.now() - timedelta(minutes=10)).isoformat()
        self.assertTrue(sentinel_machine.view(A())['stale'])


class DecisionTests(SimpleTestCase):
    def test_at_its_machines_own_number_nothing_moves(self):
        got = decide(8, 8, rows(held=8))
        self.assertIsNone(got['new'])
        self.assertIn("machine's own setting", got['why_not_raised'])

    def test_a_kill_the_sentinel_counted_backs_off_at_once(self):
        reports = rows(5)
        reports[-1] = {**reports[-1], 'oom_1h': {'nuclei_deep': 1}}
        got = decide(8, 8, reports)
        self.assertEqual((got['direction'], got['new'], got['phase'], got['pressure']), ('less', 6, 'back_off', True))
        self.assertIn('killed for memory (nuclei_deep)', got['reason'])

    def test_a_rolling_count_read_for_the_first_time_is_not_a_new_kill_but_a_failed_task_is(self):
        self.assertIsNone(decide(8, 8, [row(NOW, oom_1h={'nuclei_deep': 3})])['new'])
        self.assertEqual(decide(8, 8, [row(NOW, oom_failed={'nmap': 1})])['new'], 6)

    def test_the_containers_own_kill_count_counts(self):
        reports = rows(2)
        reports[-1] = {**reports[-1], 'cg_oom': 2}
        self.assertIn('the container', decide(8, 8, reports)['reason'])

    def test_low_memory_high_load_and_timeouts_back_off(self):
        self.assertEqual(decide(8, 8, rows(3, avail_share=0.05))['new'], 6)
        self.assertEqual(decide(8, 8, rows(3, load1_per_cpu=3.0, load1=12.0))['new'], 6)  # two reports in a row
        self.assertIsNone(decide(8, 8, rows(3, held=0) [:-1] + [row(NOW, load1_per_cpu=3.0)])['new'])  # one report alone is a spike
        self.assertEqual(decide(8, 8, [row(NOW, load5_per_cpu=2.5)])['new'], 6)  # the five-minute load is already an average
        self.assertEqual(decide(4, 8, rows(3, timeouts=3))['new'], 2)
        self.assertEqual(decide(2, 8, rows(3, avail_share=0.05))['new'], 1)

    def test_a_back_off_holds_before_the_next_one(self):
        past = [{'at': NOW - 600, 'old': 8, 'new': 6, 'pressure': True, 'phase': 'back_off'}]
        got = decide(6, 8, rows(3, avail_share=0.05), past)
        self.assertIsNone(got['new'])
        self.assertIn('holding', got['reason'])

    def test_probes_up_one_slot_after_two_healthy_hours_with_every_slot_held(self):
        got = decide(6, 8, rows())
        self.assertEqual((got['direction'], got['new'], got['phase'], got['pressure']), ('more', 7, 'probe', False))

    def test_no_probe_without_room_demand_or_enough_healthy_reports(self):
        self.assertIn('slots in use', decide(6, 8, rows(held=3))['why_not_raised'])
        self.assertIn('no Sentinel work is queued', decide(6, 8, rows(queued=0))['why_not_raised'])
        self.assertIn('memory available', decide(6, 8, rows(avail_share=0.3))['why_not_raised'])
        self.assertIn('load', decide(6, 8, rows(load1_per_cpu=0.9))['why_not_raised'])
        self.assertIn('healthy minutes', decide(6, 8, rows(5))['why_not_raised'])
        reports = rows()
        reports[-8] = {**reports[-8], 'oom_failed': {'nmap': 1}}
        self.assertIn('killed for memory', decide(6, 8, reports)['why_not_raised'])

    def test_the_level_that_caused_trouble_is_not_reached_again_for_a_day(self):
        past = [{'at': NOW - 5 * 3600, 'old': 8, 'new': 6, 'pressure': True, 'phase': 'back_off'},
                {'at': NOW - 3 * 3600, 'old': 6, 'new': 7, 'pressure': False, 'phase': 'probe'}]
        got = decide(7, 8, rows(), past)
        self.assertIsNone(got['new'])
        self.assertIn('8 caused trouble', got['why_not_raised'])

    def test_a_revert_hold_and_the_probe_cooldown_stop_a_probe(self):
        self.assertIn('taken back', decide(6, 8, rows(), hold_until=NOW + 60)['why_not_raised'])
        self.assertIn('a probe waits', decide(6, 8, rows(), [{'at': NOW - 600, 'old': 5, 'new': 6, 'pressure': False, 'phase': 'probe'}])['why_not_raised'])

    def test_a_kinds_cap_halves_on_its_own_kill_and_probes_back(self):
        reports = rows(3)
        reports[-1] = {**reports[-1], 'oom_failed': {'nuclei_light': 1}}
        got = decide(6, 6, reports, kind='nuclei_light', slots=6)
        self.assertEqual((got['new'], got['phase']), (3, 'back_off'))
        self.assertIsNone(decide(6, 6, reports, kind='nuclei_deep', slots=6)['new'])  # another kind's kill is not this kind's trouble
        up = decide(3, 6, rows(held_by_kind={'nuclei_light': 3}), kind='nuclei_light', slots=6)
        self.assertEqual((up['new'], up['phase']), (4, 'probe'))
        self.assertIn('slots in use', decide(3, 6, rows(held_by_kind={'nuclei_light': 1}), kind='nuclei_light', slots=6)['why_not_raised'])

    def test_a_probe_that_brought_a_kill_regresses_and_a_quiet_one_does_not(self):
        before = at.measure(rows(3))
        after = rows(3, end=NOW + 3600)
        after[-1] = {**after[-1], 'oom_failed': {'nmap': 1}}
        self.assertEqual(policy.verdict(before, at.measure(after)).outcome, 'regressed')
        self.assertEqual(policy.verdict(before, at.measure(rows(3, end=NOW + 3600))).outcome, 'no_effect')
        self.assertEqual(policy.verdict(before, at.measure(rows(3, end=NOW + 3600, done=20))).outcome, 'helped')

    def test_keys(self):
        self.assertEqual(at.parse_key(at.slots_key(7)), (7, None))
        self.assertEqual(at.parse_key(at.kind_key(7, 'nuclei_light')), (7, 'nuclei_light'))
        for bad in ('heavy.nmap', 'sentinel:x:max_concurrent', 'sentinel:7:kind:nope', 'sentinel:7:other', None):
            self.assertIsNone(at.parse_key(bad))


class SentinelWorld(Isolated, TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        super().setUp()
        reset_rates(self.tokens)
        status, out = register_sentinel(self.tokens['alice'], capabilities=['nmap', 'nuclei_light', 'nuclei_deep'], max_concurrent=8,
                                        settings={'max_concurrent': 8})
        self.assertIn(status, (200, 201), out)
        self.agent = Agent.objects.get(pk=out['id'])

    def beat(self, machine=None, token=None):
        info = {'contract_version': 11, 'machine': {**MACHINE, **(machine or {})}}
        status, out = call(token or self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': info})
        self.assertEqual(status, 200, out)
        self.agent.refresh_from_db()
        return out

    def run_with(self, machine_rows, *, now=None, n=None):
        """Seed the per-Sentinel reports ``machine_rows`` (oldest first, one sample each, ten minutes apart, ending now) and run the tuner once."""
        now = now or timezone.now()
        end = now.timestamp()
        samples = []
        for i, r in enumerate(machine_rows):
            t = end - (len(machine_rows) - 1 - i) * 600
            samples.append(merge(BASE, {'t': t, 'sentinel': {'live': 1, 'slots': 8, 'machines': {str(self.agent.pk): {**r, 't': t}}}}))
        for s in samples[:-1]:
            autotune.store_sample(s)
        resources.redis_client().delete('cvengine:sweep:autotune')
        Agent.objects.filter(pk=self.agent.pk).update(last_seen=now)
        with mock.patch.object(signals, 'collect', return_value=samples[-1]), mock.patch.object(autotune, '_process_started', return_value=end - 8 * 3600):
            out = autotune.run(now)
        self.agent.refresh_from_db()
        return out


class TelemetryStorageTests(SentinelWorld):
    def test_the_heartbeat_stores_the_report_with_the_servers_time_and_the_page_shows_it(self):
        self.beat({'oom_kills_1h': {'nuclei_deep': 1}})
        stored = self.agent.info['machine']
        self.assertEqual(stored['cpus'], 4)
        self.assertIn('at', stored)
        status, out = call(self.tokens['alice'], 'GET', f'/api/v1/agents/{self.agent.pk}')
        self.assertEqual(status, 200, out)
        self.assertEqual(out['machine']['available_share'], 0.75)
        self.assertEqual(out['machine']['oom_kills_1h'], {'nuclei_deep': 1})
        self.assertEqual(out['tuning']['ceiling'], 8)

    def test_a_full_report_without_the_machine_drops_the_old_numbers(self):
        self.beat()
        call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'contract_version': 11}})
        self.agent.refresh_from_db()
        self.assertNotIn('machine', self.agent.info)

    def test_a_malformed_report_never_costs_the_heartbeat(self):
        status, _ = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'contract_version': 11, 'machine': {'cpus': 'lots'}}})
        self.assertEqual(status, 200)


class RunTests(SentinelWorld):
    def test_a_kill_backs_the_sentinel_off_and_the_claim_and_the_reply_hold_it(self):
        reports = [row(0, slots=8, held=8)] * 3 + [row(0, slots=8, held=8, oom_failed={'nuclei_deep': 1})]
        summary = self.run_with(reports)
        change = next(c for c in summary['changes'] if c['setting'] == at.slots_key(self.agent.pk))
        self.assertEqual((change['from'], change['to'], change['applied']), (8, 6, True))
        self.assertEqual(sentinel_machine.tuned(self.agent)['max_concurrent'], 6)
        self.assertEqual(sentinel_broker.SentinelEff(self.agent, timezone.now()).max_concurrent, 6)
        self.assertEqual(sentinel_settings.reply(self.agent)['values']['max_concurrent'], 6)
        d = TuningDecision.objects.get(setting=at.slots_key(self.agent.pk))
        self.assertEqual((d.layer, d.phase, d.pressure, d.source), ('sentinel', 'back_off', True, 'controller'))
        self.assertEqual(d.signals['label'], f'Tasks at once on {self.agent.name}')
        self.assertTrue(AuditLog.objects.filter(action='autotune.sentinel').exists())
        kind = TuningDecision.objects.get(setting=at.kind_key(self.agent.pk, 'nuclei_deep'))
        self.assertEqual((kind.old_value, kind.new_value), (8, 4))
        self.assertEqual(sentinel_broker.SentinelEff(self.agent, timezone.now()).kind_caps.get('nuclei_deep'), 4)
        status = autotune.status()
        mine = next(s for s in status['sentinels'] if s['id'] == self.agent.pk)
        self.assertEqual(mine['tuning']['max_concurrent'], 6)
        self.assertIn(at.slots_key(self.agent.pk), mine['last_run']['settings'])

    def test_a_pinned_sentinel_is_never_moved(self):
        Agent.objects.filter(pk=self.agent.pk).update(managed_settings={'max_concurrent': {'value': 5, 'at': timezone.now().isoformat(), 'by': 's_root'}})
        self.run_with([row(0, slots=5, held=5)] * 3 + [row(0, slots=5, held=5, avail_share=0.02)])
        self.assertFalse(TuningDecision.objects.filter(setting=at.slots_key(self.agent.pk)).exists())
        self.assertIsNone(sentinel_machine.tuned_slots(self.agent))

    def test_an_offline_sentinel_or_one_with_no_report_is_left_as_it_is(self):
        summary = self.run_with([row(0, fresh=False, avail_share=0.02)] * 3)
        self.assertIn('no fresh machine report', summary['sentinels'][str(self.agent.pk)]['held'])
        now = timezone.now()
        Agent.objects.filter(pk=self.agent.pk).update(last_seen=now - timedelta(hours=1))
        sample = merge(BASE, {'t': now.timestamp(), 'sentinel': {'machines': {str(self.agent.pk): row(now.timestamp(), avail_share=0.02)}}})
        plans, _offered, entries = at.plan('auto', now, [sample])
        self.assertEqual(entries[str(self.agent.pk)]['held'], 'offline: left as it is')
        self.assertEqual(plans, [])
        self.assertFalse(TuningDecision.objects.filter(setting__startswith=at.PREFIX).exists())

    def test_the_machines_own_setting_is_a_ceiling_the_server_never_raises(self):
        Agent.objects.filter(pk=self.agent.pk).update(managed_settings={'tuned': {'max_concurrent': 10}})
        self.agent.refresh_from_db()
        self.assertEqual(sentinel_machine.tuned_slots(self.agent), 8)
        self.assertEqual(sentinel_broker.SentinelEff(self.agent, timezone.now()).max_concurrent, 8)

    def test_suggest_records_and_changes_nothing_and_off_does_nothing(self):
        AutoTuneSettings.objects.filter(pk=AutoTuneSettings.current().pk).update(mode='suggest')
        self.run_with([row(0, slots=8, held=8)] * 3 + [row(0, slots=8, held=8, avail_share=0.02)])
        d = TuningDecision.objects.get(setting=at.slots_key(self.agent.pk))
        self.assertFalse(d.applied)
        self.assertIsNone(sentinel_machine.tuned_slots(self.agent))
        TuningDecision.objects.all().delete()
        AutoTuneSettings.objects.filter(pk=AutoTuneSettings.current().pk).update(mode='off')
        self.run_with([row(0, slots=8, held=8, avail_share=0.02)] * 4)
        self.assertFalse(TuningDecision.objects.exists())

    def test_leaving_auto_and_the_kill_switch_put_every_sentinel_back_on_its_own_numbers(self):
        Agent.objects.filter(pk=self.agent.pk).update(managed_settings={'tuned': {'max_concurrent': 3, 'kinds': {'nuclei_deep': 1}}})
        self.agent.refresh_from_db()
        with mock.patch.dict('os.environ', {'CVENGINE_AUTOTUNE': '0'}):
            self.assertIsNone(sentinel_machine.tuned_slots(self.agent))
            self.assertNotIn('nuclei_deep', sentinel_broker.SentinelEff(self.agent, timezone.now()).kind_caps)
        self.assertEqual(sentinel_machine.tuned_slots(self.agent), 3)
        from django.contrib.auth.models import User
        autotune.set_mode(User.objects.get(username='s_root'), mode='off')
        self.agent.refresh_from_db()
        self.assertNotIn('tuned', self.agent.managed_settings)

    def test_a_probe_that_hurt_is_verified_reverted_and_held(self):
        Agent.objects.filter(pk=self.agent.pk).update(managed_settings={'tuned': {'max_concurrent': 6}})
        now = timezone.now()
        healthy = [row(0, slots=6, held=6)] * 14
        summary = self.run_with(healthy, now=now - timedelta(minutes=40))
        probe = TuningDecision.objects.get(setting=at.slots_key(self.agent.pk))
        self.assertEqual((probe.phase, probe.old_value, probe.new_value), ('probe', 6, 7))
        self.assertIsNotNone(probe.verify_at)
        self.assertTrue(any(c['setting'] == probe.setting for c in summary['changes']))
        hurt = [row(0, slots=7, held=7, done=1)] * 5  # it finished a tenth of what it did before
        TuningDecision.objects.filter(pk=probe.pk).update(baseline={**probe.baseline, 't': now.timestamp() - 3000})
        self.run_with(hurt, now=now)
        probe.refresh_from_db()
        self.assertEqual((probe.outcome, probe.resolution), ('regressed', 'reverted'))
        back = TuningDecision.objects.get(setting=probe.setting, action='revert')
        self.assertEqual((back.old_value, back.new_value, back.phase, back.pressure), (7, 6, 'verify', True))
        self.agent.refresh_from_db()
        self.assertEqual(sentinel_machine.tuned(self.agent)['max_concurrent'], 6)
        self.assertIn(at.slots_key(self.agent.pk), sentinel_machine.tuned(self.agent)['hold_until'])


class PersonTests(SentinelWorld):
    def setUp(self):
        super().setUp()
        from django.contrib.auth.models import User
        self.root_user = User.objects.get(username='s_root')

    def test_a_person_reverts_the_newest_change_and_it_is_held(self):
        self.run_with([row(0, slots=8, held=8)] * 3 + [row(0, slots=8, held=8, avail_share=0.02)])
        d = TuningDecision.objects.get(setting=at.slots_key(self.agent.pk))
        out = autotune.revert(self.root_user, d.pk)
        self.assertEqual((out['action'], out['old_value'], out['new_value']), ('revert', 6, 8))
        self.agent.refresh_from_db()
        self.assertIsNone(sentinel_machine.tuned(self.agent)['max_concurrent'])
        self.assertIn(at.slots_key(self.agent.pk), sentinel_machine.tuned(self.agent)['hold_until'])
        with self.assertRaises(autotune.TuningError):
            autotune.revert(self.root_user, d.pk)

    def test_applying_a_recommendation_outside_auto_pins_it_as_the_sentinels_setting(self):
        AutoTuneSettings.objects.filter(pk=AutoTuneSettings.current().pk).update(mode='suggest')
        self.run_with([row(0, slots=8, held=8)] * 3 + [row(0, slots=8, held=8, avail_share=0.02)])
        d = TuningDecision.objects.get(setting=at.slots_key(self.agent.pk), applied=False)
        autotune.apply_decision(self.root_user, d.pk)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.managed_settings['max_concurrent']['value'], 6)
        self.assertIsNotNone(sentinel_machine.slots_pin(self.agent))

    def test_release_hands_a_pinned_number_to_the_tuner_without_a_jump(self):
        sentinel_settings.set_managed(self.agent, {'max_concurrent': 5}, self.root_user)
        out = autotune.release(self.root_user, at.slots_key(self.agent.pk))
        self.assertEqual((out['action'], out['new_value']), ('release', 5))
        self.agent.refresh_from_db()
        self.assertNotIn('max_concurrent', self.agent.managed_settings)
        self.assertEqual(sentinel_machine.tuned_slots(self.agent), 5)
        with self.assertRaises(autotune.TuningError):
            autotune.release(self.root_user, at.slots_key(self.agent.pk))


class ServerCheckTests(SimpleTestCase):
    def test_a_broker_that_does_not_answer_twice_backs_the_discovery_pool_off_and_blocks_probes(self):
        pool = policy.Setting('discovery_concurrency', 'discovery', 'pool', 4, 32, 2, 'more', 16, 8)
        down = [merge(BASE, {'t': NOW - 600, 'broker': {'ok': False}}), merge(BASE, {'t': NOW, 'broker': {'ok': False}})]
        self.assertEqual(policy.trouble(pool, down), 'the Celery broker does not answer')
        self.assertIsNone(policy.trouble(pool, down[-1:]))
        self.assertEqual(policy.room(down[-1]), 'the Celery broker did not answer')

    def test_the_summary_carries_the_broker_and_the_sentinel_capacity_signals(self):
        s = merge(BASE, {'t': NOW, 'broker': {'ok': True, 'latency_ms': 3, 'queued': {'planner_queue': 4}},
                         'sentinel': {'expired_unclaimed': 2, 'oldest_queued_s': 1200}})
        out = signals.summarise([s])
        self.assertEqual(out['sentinel']['expired_unclaimed'], 2)
        self.assertEqual(out['sentinel']['oldest_queued_minutes'], 20)
        self.assertEqual(out['broker']['queued']['planner_queue'], {'min': 4, 'max': 4, 'mean': 4})

    def test_the_advisor_sees_each_sentinels_machine_and_its_settings(self):
        self.assertIn('sentinel:<id>:max_concurrent', autotune.ADVISOR_SYSTEM)
        samples = [merge(BASE, {'t': NOW, 'sentinel': {'machines': {'7': row(NOW)}}})]
        got = at.advisor_numbers(samples)['7']
        self.assertEqual((got['memory_available_share'], got['machine_ceiling'], got['slots']), (0.75, 8, 6))
