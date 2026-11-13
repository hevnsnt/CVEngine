"""Agents act through the auto-tune engine (1.4.0 WP4, review finding AM-3). A write from an agent token to a throughput setting is not a saved value and
not a pin: it is a decision of the engine (``source='agent'``) under the agent policy a person set (off, suggest, auto), clamped to the auto range and to
what the controller itself would allow, held by the same guard rails, verified after 30 minutes and taken back if it made things worse. Spend caps and
every other cost-bearing number are lower-only for an agent, an update is never approved by one, and every audit row an agent causes names its token and
agent. A person's own write (the settings page) is unchanged."""
import os
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import settings_bridge as bridge
from agentapi.auth import create_token
from agentapi.models import Agent
from agentapi.services import ApiError, Ctx
from cveFeed import autotune, scan_concurrency as sc, tunables
from cveFeed import autotune_signals as signals
from cveFeed.models import AutoTuneSettings, ScanConcurrency, SetupAnswer, TunableSettings, TuningDecision
from dashboard.models import AuditLog
from reNgine import resources
from tests.test_agentapi import call, tool_call
from tests.test_autotune import BASE, Isolated, merge
from tests.test_settings import send
from tests.test_tenancy import client_for

TWO_SENTINELS = {'sentinel': {'live': 2, 'slots': 9}}  # the pool is sized to 22 for two Sentinels with nine slots
QUEUE_BEFORE = {**TWO_SENTINELS, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 10}}
QUEUE_WORSE = {**TWO_SENTINELS, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 70}}
QUEUE_AFTER = {**TWO_SENTINELS, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 3}}
POOL = {'values': {'discovery_concurrency': 12}}


class AgentBase(Isolated, TestCase):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('agent_root', 'a@x.io', 'x')
        self.token, self.raw = create_token(self.root, 'maintenance bot')
        self.agent = Agent.objects.create(token=self.token, name='fixer-7', kind='remediation', status='active')
        self.ctx = Ctx(user=self.root, token=self.token)
        self.start = timezone.now()
        self.seed(QUEUE_BEFORE)

    def seed(self, over, minutes=0, n=3):
        for i in range(n):
            autotune.store_sample(merge(BASE, {'t': (self.start + timedelta(minutes=minutes - 10 * (n - 1 - i))).timestamp(), **over}))

    def policy(self, name, mode=None):
        row = AutoTuneSettings.current()
        row.agent_policy = name
        if mode:
            row.mode = mode
        row.save()

    def write(self, values=None, name='scan_concurrency'):
        return bridge.change_setting(self.ctx, name, values or POOL)

    def run_at(self, minutes, over):
        resources.redis_client().delete('cvengine:sweep:autotune')
        sample = merge(BASE, {'t': (self.start + timedelta(minutes=minutes)).timestamp(), **over})
        with mock.patch.object(signals, 'collect', return_value=sample):
            return autotune.run(self.start + timedelta(minutes=minutes))

    def saved(self):
        return dict(ScanConcurrency.current().values or {})


class PolicyTests(AgentBase):
    def test_the_default_policy_is_suggest_and_a_write_becomes_a_recommendation_not_a_pin(self):
        self.assertEqual(autotune.agent_policy(), 'suggest')
        out = self.write()
        result = out['agent_changes']['discovery_concurrency']
        self.assertEqual((result['status'], result['value']), ('suggested', 8))
        self.assertIn('Recorded as a recommendation', out['agent_summary'])
        self.assertIn('Hosts assessed at once 8 -> 12', out['agent_summary'])
        self.assertEqual(self.saved(), {})  # not a saved value: nothing is pinned
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual((d.source, d.applied, d.old_value, d.new_value, d.resolution), ('agent', False, 8, 12, ''))
        self.assertIn('fixer-7', d.reason)
        self.assertEqual(sc.resolve('discovery_concurrency')['source'], 'default')
        # a person applies it with one click: it becomes the tuned number, a person's decision
        done = autotune.apply_decision(self.root, d.pk)
        self.assertEqual((done['source'], done['layer'], done['new_value']), ('person', 'auto', 12))
        self.assertEqual(self.saved(), {})

    def test_off_refuses_and_records_nothing(self):
        self.policy('off')
        with self.assertRaises(ApiError) as caught:
            self.write()
        self.assertEqual(caught.exception.status, 403)
        self.assertIn('agent policy to Off', caught.exception.message)
        self.assertFalse(TuningDecision.objects.exists())
        self.assertEqual(self.saved(), {})

    def test_auto_applies_through_the_engine_with_a_verify_step_and_no_pin(self):
        self.policy('auto')
        out = self.write()
        result = out['agent_changes']['discovery_concurrency']
        self.assertEqual((result['status'], result['value']), ('applied', 12))
        self.assertIn('checked after 30 minutes', result['text'])
        self.assertEqual(self.saved(), {})
        resources.invalidate_auto()
        self.assertEqual(sc.resolve('discovery_concurrency'), {'value': 12, 'source': 'auto'})
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual((d.source, d.applied, d.layer, d.phase, d.pressure, d.actor_id), ('agent', True, 'auto', '', False, self.root.pk))
        self.assertEqual(d.expected, 'discovery_queue')
        self.assertEqual(d.baseline['value'], 10.0)
        self.assertAlmostEqual((d.verify_at - timezone.now()).total_seconds(), 30 * 60, delta=5)
        self.assertEqual(autotune.pin_of(autotune.by_key()['discovery_concurrency'], autotune._saved_rows()), None)

    def test_the_mode_decides_too_suggest_mode_records_and_off_or_the_kill_switch_refuses(self):
        self.policy('auto', mode='suggest')
        out = self.write()
        self.assertEqual(out['agent_changes']['discovery_concurrency']['status'], 'suggested')
        self.assertIn('Suggest mode', out['agent_summary'])
        self.assertEqual(AutoTuneSettings.current().values, {})
        self.policy('auto', mode='off')
        with self.assertRaises(ApiError) as caught:
            self.write()
        self.assertEqual(caught.exception.status, 409)
        self.assertIn('auto-tuning is off', caught.exception.message)
        self.policy('auto', mode='auto')
        with mock.patch.dict(os.environ, {'CVENGINE_AUTOTUNE': '0'}):
            with self.assertRaises(ApiError) as caught:
                self.write()
        self.assertIn('CVENGINE_AUTOTUNE=0', caught.exception.message)
        self.assertEqual(TuningDecision.objects.filter(applied=True).count(), 0)

    def test_only_a_person_changes_the_policy(self):
        # the page of a person (session)
        c = client_for(self.root)
        status, data = send(c, 'PUT', 'autotune', {'agent_policy': 'auto'})
        self.assertEqual((status, data['agent_policy']), (200, 'auto'))
        self.assertEqual(send(c, 'PUT', 'autotune', {'agent_policy': 'sometimes'})[0], 400)
        self.assertTrue(AuditLog.objects.filter(action='autotune.mode').exists())
        # the agent: REST, MCP tool, and the settings bridge all say 403, and nothing changes
        self.assertEqual(call(self.raw, 'PUT', '/api/v1/tuning/mode', {'agent_policy': 'off'})[0], 403)
        error, text = tool_call(self.raw, 'change_setting', {'name': 'autotune', 'values': {'agent_policy': 'off'}})
        self.assertTrue(error)
        self.assertIn('person', text)
        with self.assertRaises(ApiError) as caught:
            bridge.change_setting(self.ctx, 'autotune', {'agent_policy': 'off'})
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(AutoTuneSettings.current().agent_policy, 'auto')
        # the REST route for a session of a person works the same way
        status, data = call(self.raw, 'GET', '/api/v1/tuning')
        self.assertEqual((status, data['agent_policy']), (200, 'auto'))


class GuardRailTests(AgentBase):
    def setUp(self):
        super().setUp()
        self.policy('auto')

    def test_a_number_outside_the_range_is_clamped_and_one_above_the_machines_target_is_held_at_it(self):
        out = self.write({'values': {'discovery_concurrency': 500}})
        result = out['agent_changes']['discovery_concurrency']
        self.assertEqual((result['status'], result['value'], result['clamped']), ('applied', 22, True))  # 500 -> 32 (range) -> 22 (target for two Sentinels)
        self.assertIn('clamped to 32', result['text'])
        self.assertIn('held at 22', result['text'])
        d = TuningDecision.objects.get(setting='discovery_concurrency')
        self.assertEqual(d.new_value, 22)
        out = self.write({'values': {'discovery_concurrency': 1}})  # lower: clamped up to the auto minimum of 4
        self.assertEqual(out['agent_changes']['discovery_concurrency']['value'], 4)
        self.assertIn('clamped to 4', out['agent_changes']['discovery_concurrency']['text'])

    def test_a_level_that_caused_trouble_in_the_last_day_is_not_reached_again(self):
        TuningDecision.objects.create(setting='discovery_concurrency', old_value=20, new_value=14, mode='auto', source='controller', action='lower', layer='auto',
                                      applied=True, pressure=True, phase='back_off', reason='memory', created_at=timezone.now() - timedelta(hours=3))
        row = AutoTuneSettings.current()
        row.values = {'discovery_concurrency': 14}
        row.save()
        out = self.write({'values': {'discovery_concurrency': 22}})
        result = out['agent_changes']['discovery_concurrency']
        self.assertEqual(result['value'], 18)  # one step short of the 20 that caused trouble
        self.assertIn('20 caused trouble 3 h ago', result['text'])

    def test_trouble_now_a_pin_a_hold_and_the_one_change_at_a_time_gate_refuse_a_raise(self):
        # trouble in the newest measurement
        self.seed({**QUEUE_BEFORE, 'db': {'used': 270, 'max': 300}}, minutes=10, n=1)
        with self.assertRaises(ApiError) as caught:
            self.write()
        self.assertEqual(caught.exception.status, 409)
        self.assertIn('stays 8', caught.exception.message)
        self.assertFalse(TuningDecision.objects.exists())
        resources.redis_client().delete(autotune.SAMPLES_KEY)
        self.seed(QUEUE_BEFORE, minutes=20)
        # a hold left by a revert
        row = AutoTuneSettings.current()
        row.meta = {'discovery_concurrency': {'hold_until': (timezone.now() + timedelta(hours=5)).isoformat()}}
        row.save()
        with self.assertRaises(ApiError) as caught:
            self.write()
        self.assertIn('not raised for a day', caught.exception.message)
        row.meta = {}
        row.save()
        # one calm change at a time: the first goes through, a second raise elsewhere waits for the verdict, a lowering does not
        self.assertEqual(self.write()['agent_changes']['discovery_concurrency']['status'], 'applied')
        with self.assertRaises(ApiError) as caught:
            self.write({'values': {'assess_batch': 12}})
        self.assertIn('one calm change at a time', caught.exception.message)
        out = self.write({'values': {'assess_batch': 6}})
        self.assertEqual(out['agent_changes']['assess_batch']['status'], 'applied')
        # the raise cooldown on the same setting
        with self.assertRaises(ApiError):
            self.write({'values': {'discovery_concurrency': 16}})

    def test_a_pinned_setting_is_never_moved_or_reset_by_an_agent(self):
        sc.update({'discovery_concurrency': 10}, self.root)
        with self.assertRaises(ApiError) as caught:
            self.write()
        self.assertIn('pinned by agent_root', caught.exception.message)
        self.assertEqual(self.saved(), {'discovery_concurrency': 10})
        with self.assertRaises(ApiError) as caught:
            self.write({'values': {'discovery_concurrency': None}})
        self.assertEqual(self.saved(), {'discovery_concurrency': 10})
        for bad in (True, 'many', 1.5):
            with self.assertRaises(ApiError):
                self.write({'values': {'assess_batch': bad}})
        self.assertFalse(TuningDecision.objects.filter(applied=True).exists())

    def test_a_person_still_pins_as_before_through_the_settings_page(self):
        c = client_for(self.root)
        status, data = send(c, 'PUT', 'scan_concurrency', POOL)
        self.assertEqual(status, 200)
        self.assertEqual(self.saved(), {'discovery_concurrency': 12})
        self.assertEqual(sc.resolve('discovery_concurrency')['source'], 'admin')
        self.assertFalse(TuningDecision.objects.exists())
        self.assertTrue(AuditLog.objects.filter(action='scan_concurrency.set').exists())

    def test_a_write_with_other_keys_in_it_sends_the_managed_ones_to_the_engine_and_the_rest_to_the_page(self):
        out = self.write({'values': {'discovery_concurrency': 12, 'heavy.nmap-full-bg': 1}})
        self.assertEqual(out['agent_changes']['discovery_concurrency']['status'], 'applied')
        self.assertEqual(self.saved(), {'heavy.nmap-full-bg': 1})  # not auto-tuned: the page's handler saved it
        self.assertNotIn('heavy.nmap-full-bg', out['agent_changes'])


class VerifyAndRevertTests(AgentBase):
    def test_an_agent_change_that_made_things_worse_is_taken_back_and_one_that_helped_is_kept(self):
        self.policy('auto')
        self.write()
        d = TuningDecision.objects.get(setting='discovery_concurrency', source='agent')
        for minutes in (10, 20):
            self.assertEqual(self.run_at(minutes, QUEUE_WORSE)['verified'], [])
        summary = self.run_at(30, QUEUE_WORSE)
        judged = {j['setting']: j for j in summary['verified']}
        self.assertEqual((judged['discovery_concurrency']['outcome'], judged['discovery_concurrency']['reverted']), ('regressed', True))
        d.refresh_from_db()
        self.assertEqual((d.outcome, d.resolution), ('regressed', 'reverted'))
        self.assertEqual(AutoTuneSettings.current().values.get('discovery_concurrency'), 8)
        back = TuningDecision.objects.get(setting='discovery_concurrency', action='revert')
        self.assertEqual((back.old_value, back.new_value, back.source, back.phase), (12, 8, 'controller', 'verify'))
        # and the agent may not just try again: the setting is held for a day
        with self.assertRaises(ApiError) as caught:
            self.write()
        self.assertIn('not raised for a day', caught.exception.message)

    def test_an_agent_change_that_helped_is_kept(self):
        self.policy('auto')
        self.write()
        for minutes in (10, 20):
            self.run_at(minutes, QUEUE_AFTER)
        summary = self.run_at(30, QUEUE_AFTER)
        self.assertEqual([(j['outcome'], j['reverted']) for j in summary['verified'] if j['setting'] == 'discovery_concurrency'], [('helped', False)])
        self.assertEqual(AutoTuneSettings.current().values['discovery_concurrency'], 12)

    def test_an_agent_decision_is_listed_with_its_source_by_rest_and_mcp_alike(self):
        self.policy('auto')
        self.write()
        status, rest = call(self.raw, 'GET', '/api/v1/tuning/decisions?setting=discovery_concurrency')
        error, mcp = tool_call(self.raw, 'list_tuning_decisions', {'setting': 'discovery_concurrency'})
        self.assertEqual((status, error), (200, False))
        self.assertEqual(rest, mcp)
        self.assertEqual((rest['results'][0]['source'], rest['results'][0]['applied']), ('agent', True))


class AgentLimitTests(AgentBase):
    def test_spend_caps_and_every_cost_bearing_number_are_lower_only(self):
        values = lambda **kw: {'values': kw}
        now = tunables.value('triage_max_per_day')
        for key in ('triage_max_per_day', 'nuclei_ai_max_per_day', 'validate_max_per_day', 'template_gen_max_per_day', 'autotune_ai_max_per_day',
                    'triage_max_per_run', 'validate_max_per_project_day', 'triage_max_per_project_day', 'validate_max_per_run'):
            cap = tunables.value(key)
            with self.assertRaises(ApiError) as caught:
                self.write(values(**{key: cap + 1}), name='tunables')
            self.assertEqual(caught.exception.status, 403, key)
            self.assertIn('only lower', caught.exception.message)
        self.assertEqual(TunableSettings.current().values, {})
        # lowering one is allowed, is audited and is a saved value (the AI spend caps are not auto-tuned)
        out = self.write(values(triage_max_per_day=now - 500), name='tunables')
        self.assertEqual(tunables.value('triage_max_per_day'), now - 500)
        self.assertNotIn('agent_changes', out)
        # resetting one to a default that is higher than what is saved would raise it
        with self.assertRaises(ApiError):
            self.write(values(triage_max_per_day=None), name='tunables')
        self.assertEqual(tunables.value('triage_max_per_day'), now - 500)
        # the gap between validations is the other way round, and the switches only go off
        with self.assertRaises(ApiError):
            self.write(values(validate_min_gap_hours=1), name='tunables')
        self.write(values(validate_min_gap_hours=24), name='tunables')
        self.assertEqual(tunables.value('validate_min_gap_hours'), 24)
        self.write(values(planner_enabled=0), name='tunables')
        with self.assertRaises(ApiError):
            self.write(values(planner_enabled=1), name='tunables')
        with self.assertRaises(ApiError):
            self.write(values(sentinel_bbot_keys=2), name='tunables')

    def test_a_cap_of_zero_on_the_port_25_pacing_is_not_lower_it_turns_the_pacing_off(self):
        with self.assertRaises(ApiError):
            self.write({'values': {'egress_port25_per_hour': 0}}, name='tunables')
        self.write({'values': {'egress_port25_per_hour': 100}}, name='tunables')
        self.assertEqual(tunables.value('egress_port25_per_hour'), 100)

    def test_the_ai_and_reviewer_limits_are_lower_only_and_nothing_paid_or_scan_wide_is_switched_on(self):
        from dashboard.models import AIProviderSettings
        row = AIProviderSettings.objects.first() or AIProviderSettings()
        row.plan_daily_total, row.enabled = 100, False
        row.save()
        with self.assertRaises(ApiError) as caught:
            self.write({'plan_daily_total': 101}, name='ai')
        self.assertEqual(caught.exception.status, 403)
        self.assertIn('only lower', caught.exception.message)
        self.write({'plan_daily_total': 50}, name='ai')
        self.assertEqual(AIProviderSettings.objects.first().plan_daily_total, 50)
        for name, body in (('ai', {'enabled': True}), ('ai', {'auto_fire': True}), ('reviewer', {'enabled': True}), ('openvas', {'enabled': True}),
                           ('scan_policy', {'nuclei_all_templates': True}), ('updates', {'mode': 'automatic'}), ('scanner_plan', {'plan': 'both'}),
                           ('reviewer', {'review_daily_max': 20000})):
            with self.assertRaises(ApiError, msg=(name, body)) as caught:
                self.write(body, name=name)
            self.assertEqual(caught.exception.status, 403, (name, body))
        self.write({'enabled': False}, name='ai')  # switching off is fine

    def test_an_agent_cannot_approve_an_update_and_the_list_says_so(self):
        with self.assertRaises(ApiError) as caught:
            bridge.change_setting(self.ctx, 'updates_approve', {})
        self.assertEqual(caught.exception.status, 403)
        listed = bridge.list_settings(self.ctx)
        self.assertFalse(next(s for s in listed['settings'] if s['name'] == 'updates_approve')['change'])
        self.assertTrue(any('update' in n['why'] and 'agents' in n['why'] for n in listed['not_exposed']))
        error, text = tool_call(self.raw, 'change_setting', {'name': 'updates_approve', 'values': {}})
        self.assertTrue(error)

    def test_a_person_is_not_limited_by_any_of_this(self):
        c = client_for(self.root)
        cap = tunables.value('triage_max_per_day')
        self.assertEqual(send(c, 'PUT', 'tunables', {'values': {'triage_max_per_day': cap + 100}})[0], 200)
        self.assertEqual(tunables.value('triage_max_per_day'), cap + 100)


class AuditTests(AgentBase):
    def test_every_audit_row_an_agent_causes_names_its_token_and_agent_next_to_the_owner(self):
        self.policy('auto')
        error, out = tool_call(self.raw, 'change_setting', {'name': 'scan_concurrency', 'values': POOL})
        self.assertFalse(error)
        error, _ = tool_call(self.raw, 'change_setting', {'name': 'tunables', 'values': {'values': {'triage_max_per_day': 100}}})
        self.assertFalse(error)
        rows = list(AuditLog.objects.filter(action__in=('autotune.change', 'tunable.set')))
        self.assertEqual({r.action for r in rows}, {'autotune.change', 'tunable.set'})
        for r in rows:
            self.assertEqual(r.actor_name, 'agent_root')
            self.assertEqual(r.detail['via_token'], {'name': 'maintenance bot', 'agent_id': self.agent.pk, 'agent_name': 'fixer-7'}, r.action)
        change = next(r for r in rows if r.action == 'autotune.change')
        self.assertEqual((change.detail['source'], change.detail['after']), ('agent', 12))

    def test_a_token_that_is_no_registered_agent_is_named_by_the_token_and_a_person_has_no_mark(self):
        other, raw = create_token(self.root, 'plain token')
        error, _ = tool_call(raw, 'change_setting', {'name': 'tunables', 'values': {'values': {'triage_max_per_day': 100}}})
        self.assertFalse(error)
        row = AuditLog.objects.get(action='tunable.set', target='triage_max_per_day')
        self.assertEqual(row.detail['via_token'], {'name': 'plain token'})
        send(client_for(self.root), 'PUT', 'tunables', {'values': {'triage_max_per_project_day': 100}})
        person = AuditLog.objects.get(action='tunable.set', target='triage_max_per_project_day')
        self.assertNotIn('via_token', person.detail)
        # the mark does not leak into the next call on the same thread
        from tenancy import audit
        self.assertEqual(audit.token_detail(), {})


class UpdateQuestionTests(AgentBase):
    """The post-update question about the agent policy (``cveFeed.setup_questions``): no cost line, the safe default is Suggest, a person answers it, an agent never can."""

    def question(self):
        from cveFeed import setup_questions
        return next(q for q in setup_questions.snapshot()['questions'] if q['key'] == 'agent_policy')

    def test_it_is_asked_only_where_an_agent_could_use_it(self):
        from dashboard.models import ApiToken
        ApiToken.objects.all().update(revoked=True)
        q = self.question()
        self.assertEqual((q['state'], q['choices']), ('not_applicable', []))
        self.assertIn('nothing to decide', q['why_not'])
        ApiToken.objects.all().update(revoked=False, scope='sentinel')  # a Sentinel's key is not an agent's
        self.assertEqual(self.question()['state'], 'not_applicable')
        ApiToken.objects.all().update(scope='full')
        self.assertEqual(self.question()['state'], 'pending')

    def test_it_is_asked_with_the_safe_default_suggest_and_no_cost_line(self):
        q = self.question()
        self.assertEqual((q['state'], q['safe_default'], q['current']), ('pending', 'suggest', 'suggest'))
        self.assertEqual(q['title'], 'May AI agents change performance settings by themselves?')
        self.assertEqual([c['value'] for c in q['choices']], ['off', 'suggest', 'auto'])
        self.assertEqual([c['value'] for c in q['choices'] if c['safe']], ['suggest'])
        self.assertEqual(q['facts'], [])
        self.assertIn('spends nothing', q['text'])

    def test_a_person_answers_it_through_the_settings_handler_and_it_is_audited(self):
        from cveFeed import setup_questions
        setup_questions.answer(self.root, 'agent_policy', 'auto')
        self.assertEqual(AutoTuneSettings.current().agent_policy, 'auto')
        self.assertEqual(self.question()['state'], 'answered')
        self.assertTrue(AuditLog.objects.filter(action='setup.question', target='agent_policy').exists())
        self.assertTrue(AuditLog.objects.filter(action='autotune.mode').exists())
        setup_questions.answer(self.root, 'agent_policy', 'off')
        self.assertEqual(AutoTuneSettings.current().agent_policy, 'off')
        SetupAnswer.objects.all().delete()
        self.assertEqual(self.question()['state'], 'decided')  # a policy other than the default was chosen somewhere else (Settings): never asked

    def test_deciding_later_changes_nothing_and_an_agent_cannot_answer(self):
        from cveFeed import setup_questions
        setup_questions.answer(self.root, 'agent_policy', 'later')
        self.assertEqual(AutoTuneSettings.current().agent_policy, 'suggest')
        with self.assertRaises(ApiError):
            bridge.change_setting(self.ctx, 'setup_questions', {'answers': {'agent_policy': 'auto'}})
        self.assertEqual(AutoTuneSettings.current().agent_policy, 'suggest')
