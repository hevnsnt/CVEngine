"""Final review B (1.4.0), the agent rules: an agent (any API token or MCP call) may lower, never raise, what costs money, widens what is scanned or switches an
update on. A person's own save in the web interface is unaffected. One class per finding of ``review140/final-b.md`` (FB-1, FB-2, FB-3, FB-5, FB-8, FB-12)."""
import json
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase

from agentapi import settings_bridge as bridge
from agentapi.services import ApiError, Ctx
from tests.test_autotune_agents import AgentBase


def agent_ctx(user, read_only=False):
    return Ctx(user=user, token=SimpleNamespace(read_only=read_only))


class Base(TestCase):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('rules_root', 'r@x.io', 'x')
        self.ctx = agent_ctx(self.root)

    def refused(self, name, values=None, ident=None, status=403, **kw):
        with self.assertRaises(ApiError, msg=(name, values)) as caught:
            bridge.change_setting(self.ctx, name, values, ident, **kw)
        self.assertEqual(caught.exception.status, status, (name, values, caught.exception.message))
        return caught.exception.message


class ResetAndActionsTests(Base):
    """FB-1: ``config_maxxing_reset`` put auto-tuning on Auto with the advisor on, raised every AI spend cap a person lowered and removed every person's pin."""

    def state(self):
        from cveFeed import autotune, tunables
        from cveFeed import scan_concurrency as sc
        row = autotune.settings_row()
        return (tunables.value('triage_max_per_day'), row.mode, row.advisor, row.agent_policy, dict(sc.ScanConcurrency.current().values or {}) if hasattr(sc, 'ScanConcurrency') else None)

    def seed(self):
        from cveFeed import autotune, tunables
        from cveFeed import scan_concurrency as sc
        from cveFeed.models import AutoTuneSettings
        tunables.update({'triage_max_per_day': 10}, self.root)  # a person lowered an AI spend cap
        autotune.settings_row()
        AutoTuneSettings.objects.update(mode='off', advisor=False, agent_policy='off')
        sc.update({'discovery_concurrency': 4}, self.root)  # a person's pin

    def test_an_agent_cannot_reset_the_throughput_settings_and_nothing_changes(self):
        self.seed()
        before = self.state()
        message = self.refused('config_maxxing_reset', {})
        self.assertIn('change_setting', message)
        self.assertEqual(before, self.state())
        self.assertEqual(before[:3], (10, 'off', False))

    def test_a_person_in_the_web_interface_can_still_reset(self):
        self.seed()
        c = Client()
        c.force_login(self.root)
        response = c.post('/cve/api/settings/config_maxxing/reset', '{}', content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content[:200])
        self.assertNotEqual(self.state()[0], 10)

    def test_the_cve_guidance_run_that_ignores_the_daily_budget_is_refused_to_an_agent(self):
        with mock.patch('cveFeed.tasks.write_cve_guidance_now.delay') as queued:
            self.refused('cve_guidance_run', {'count': 5000})
        queued.assert_not_called()

    def test_every_post_entry_is_refused_or_listed_with_a_reason_and_none_of_the_allowed_ones_raises_autonomy_or_spend(self):
        """Walks every bridge entry whose change is a POST: it is refused to agents, or it is in ``AGENT_ACTIONS_ALLOWED`` (with a reason), and calling it as an agent with an
        empty body leaves the auto-tuning mode, the advisor, the AI spend caps and the pins as they were."""
        self.seed()
        before = self.state()
        posts = []
        for name, (api, pattern, _text, ident) in bridge.ENTRIES.items():
            method = next((m for m in bridge._methods(api, pattern) if m in bridge.WRITE_METHODS), None)
            if method == 'POST':
                posts.append((name, ident))
        self.assertGreaterEqual(len(posts), 10)
        for name, ident in posts:
            if name in bridge.READ_ONLY_FOR_AGENTS:
                self.refused(name, {}, '1' if ident else None)
                continue
            self.assertIn(name, bridge.AGENT_ACTIONS_ALLOWED, f'{name} is a POST an agent can send and nobody decided it is safe: refuse it or list it with a reason')
            self.assertGreater(len(bridge.AGENT_ACTIONS_ALLOWED[name]), 20)
            with mock.patch('celery.app.task.Task.delay'), mock.patch('smtplib.SMTP'), mock.patch('smtplib.SMTP_SSL'), mock.patch('cveFeed.updater.check'):
                try:
                    bridge.change_setting(self.ctx, name, {}, ('1/x' if '/' in (ident or '') else '1') if ident else None)
                except ApiError:
                    pass
            self.assertEqual(before, self.state(), name)
        for name in bridge.AGENT_ACTIONS_ALLOWED:
            self.assertIn(name, bridge.ENTRIES)
            self.assertNotIn(name, bridge.READ_ONLY_FOR_AGENTS)

    def test_an_agent_cannot_remove_an_exclusion_but_can_add_one(self):
        from cveFeed.models import ExcludedAddress
        from dashboard.models import Org
        org = Org.objects.create(name='X', slug='x')
        entry = ExcludedAddress.objects.create(org=org, cidr='10.0.0.9/32', note='keep out', created_by=self.root)
        self.refused('org_excluded_address', None, f'{org.pk}/{entry.pk}', remove=True)
        self.assertTrue(ExcludedAddress.objects.filter(pk=entry.pk).exists())
        out = bridge.change_setting(self.ctx, 'org_excluded_addresses', {'cidr': '10.0.0.10', 'note': 'x'}, str(org.pk))
        self.assertTrue(out)


class UpdateSettingsTests(Base):
    """FB-2: ``'auto'`` passed a rule spelt ``'automatic'``; the repository and branch an install updates from could be changed."""

    def test_an_agent_cannot_switch_updates_to_automatic_whatever_the_word(self):
        from cveFeed import updater
        with mock.patch.object(updater, 'set_mode') as set_mode:
            for word in ('auto', 'automatic', 'AUTO', 'on', True, 1, None):
                self.refused('updates', {'mode': word})
        set_mode.assert_not_called()

    def test_an_agent_can_choose_manual(self):
        from cveFeed import updater
        with mock.patch.object(updater, 'set_mode') as set_mode, mock.patch.object(updater, 'read_mode', return_value='auto'):
            bridge.change_setting(self.ctx, 'updates', {'mode': 'manual'})
        set_mode.assert_called_once_with('manual')

    def test_an_agent_cannot_change_the_repository_or_the_branch_but_may_send_them_back_unchanged(self):
        now = bridge.get_setting(self.ctx, 'updates')
        self.refused('updates', {'repo': 'someone-else/fork'})
        self.refused('updates', {'branch': 'develop'})
        self.refused('updates', {'repo': 'someone-else/fork', 'branch': 'develop'})
        after = bridge.get_setting(self.ctx, 'updates')
        self.assertEqual((now['repo'], now['branch']), (after['repo'], after['branch']))
        bridge.change_setting(self.ctx, 'updates', {'repo': now['repo'], 'branch': now['branch']})  # what the page shows is not a change

    def test_a_person_in_the_web_interface_can_still_choose_automatic(self):
        from cveFeed import updater
        c = Client()
        c.force_login(self.root)
        with mock.patch.object(updater, 'set_mode') as set_mode:
            response = c.put('/cve/api/settings/updates', json.dumps({'mode': 'auto'}), content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content[:200])
        set_mode.assert_called_once_with('auto')


class ScannerPlanTests(Base):
    """FB-8: an agent chose ``external`` with no Sentinel of the owner's own, which removes the built-in scanner and counts as the scanner question being decided."""

    def test_an_agent_cannot_choose_any_plan_and_the_question_is_not_decided_by_it(self):
        from cveFeed import scanner_plan
        for plan in ('external', 'internal', 'both'):
            with mock.patch.object(scanner_plan, 'request') as request:
                self.refused('scanner_plan', {'plan': plan})
            request.assert_not_called()
        self.assertFalse(scanner_plan.chosen())

    def test_an_agent_can_still_read_the_plan(self):
        self.assertIsInstance(bridge.get_setting(self.ctx, 'scanner_plan'), dict)


class TuningTokenTests(AgentBase):
    """FB-3: an agent applied its own recommendation (which made it a person's change, and in Suggest mode a pin), released a person's pin and reverted a person's change."""

    def test_a_token_cannot_apply_its_own_recommendation_by_rest_or_mcp_and_nothing_changes(self):
        from cveFeed import scan_concurrency as sc
        from cveFeed.models import TuningDecision

        from tests.test_agentapi import call, tool_call
        b = self
        b.policy('suggest', mode='auto')
        b.write()
        d = TuningDecision.objects.get(setting='discovery_concurrency', applied=False)
        before = sc.resolve('discovery_concurrency')
        status, data = call(b.raw, 'POST', f'/api/v1/tuning/decisions/{d.pk}/apply', {})
        self.assertEqual(status, 403, data)
        self.assertIn('change_setting', json.dumps(data))
        error, text = tool_call(b.raw, 'apply_tuning_suggestion', {'decision_id': d.pk})
        self.assertTrue(error)
        self.assertIn('person', text)
        d.refresh_from_db()
        self.assertEqual((d.applied, d.resolution), (False, ''))
        self.assertEqual(sc.resolve('discovery_concurrency'), before)
        self.assertFalse(TuningDecision.objects.filter(action='apply').exists())

    def test_in_suggest_mode_a_token_cannot_turn_its_recommendation_into_a_pin(self):
        from cveFeed.models import TuningDecision

        from tests.test_agentapi import call
        b = self
        b.policy('auto', mode='suggest')
        b.write()
        d = TuningDecision.objects.get(setting='discovery_concurrency', applied=False)
        self.assertEqual(call(b.raw, 'POST', f'/api/v1/tuning/decisions/{d.pk}/apply', {})[0], 403)
        self.assertEqual(b.saved(), {})

    def test_a_token_cannot_release_a_persons_pin_or_revert_a_persons_change(self):
        from cveFeed import autotune
        from cveFeed import scan_concurrency as sc
        from cveFeed.models import AutoTuneSettings, TuningDecision

        from tests.test_agentapi import call, tool_call
        b = self
        AutoTuneSettings.objects.update(mode='auto')
        sc.update({'discovery_concurrency': 4}, b.root)  # a person's pin
        self.assertEqual(call(b.raw, 'POST', '/api/v1/tuning/release', {'setting': 'discovery_concurrency'})[0], 403)
        error, _ = tool_call(b.raw, 'release_tuning_pin', {'setting': 'discovery_concurrency'})
        self.assertTrue(error)
        self.assertEqual(b.saved(), {'discovery_concurrency': 4})
        AutoTuneSettings.objects.update(mode='suggest', values={})  # a person applies a lower recommendation: it is saved
        sc.update({'discovery_concurrency': None}, b.root)
        m = autotune.by_key()['discovery_concurrency']
        cur = autotune._effective(m, {}, {})
        dec = autotune.recommend(m, cur, cur - 2, mode='suggest', source='controller', reason='test', signals={})
        autotune.apply_decision(b.root, dec.pk)
        applied = TuningDecision.objects.filter(action='apply').latest('pk')
        saved = b.saved()
        self.assertEqual(call(b.raw, 'POST', f'/api/v1/tuning/decisions/{applied.pk}/revert', {})[0], 403)
        error, _ = tool_call(b.raw, 'revert_tuning_decision', {'decision_id': applied.pk})
        self.assertTrue(error)
        self.assertEqual(b.saved(), saved)

    def test_a_token_cannot_revert_even_its_own_change(self):
        from cveFeed.models import TuningDecision

        from tests.test_agentapi import call
        b = self
        b.policy('auto', mode='auto')
        b.seed({'sentinel': {'live': 2, 'slots': 9}, 'discovery': {'active': 8, 'ceiling': 8, 'queued': 10}})
        b.write()
        mine = TuningDecision.objects.filter(source='agent', applied=True).first()
        self.assertIsNotNone(mine)
        self.assertEqual(call(b.raw, 'POST', f'/api/v1/tuning/decisions/{mine.pk}/revert', {})[0], 403)

    def test_a_person_signed_in_still_applies_reverts_and_releases(self):
        from cveFeed import autotune
        from cveFeed import scan_concurrency as sc
        from cveFeed.models import AutoTuneSettings

        from tests.test_settings import send
        from tests.test_tenancy import client_for
        b = self
        AutoTuneSettings.objects.update(mode='auto')
        sc.update({'discovery_concurrency': 4}, b.root)
        status, data = send(client_for(b.root), 'POST', 'autotune/release', {'setting': 'discovery_concurrency'})
        self.assertEqual(status, 200, data)
        self.assertEqual(b.saved(), {})
        self.assertTrue(autotune.status())


class WidenOutsideTheBridgeTests(Base):
    """FB-5, the doors of the settings bridge: a switch or a number sent as text, a filter list emptied, Tailscale routing and the heavy scanner limits."""

    def link(self):
        from cveFeed.models import TailscaleLink
        from dashboard.models import Org, Project
        from django.utils import timezone
        org = Org.objects.create(name='O', slug='o')
        project = Project.objects.create(name='P', slug='p', insert_date=timezone.now(), org=org)
        link = TailscaleLink.objects.create(project=project, credentials={'client_id': 'c', 'client_secret': 's'}, use_local=False, auto_scan=True, max_devices=10, routing='auto',
                                            only_tags=['tag:lab', 'tag:web'], skip_tags=['tag:old'], only_os=['linux'], enabled=True)
        return project, link

    def test_tailscale_scope_in_every_shape_cannot_be_widened_and_can_be_narrowed(self):
        project, link = self.link()
        ident = str(project.pk)
        for values in ({'max_devices': '5000'}, {'max_devices': 5000}, {'max_devices': 11}, {'only_tags': []}, {'only_tags': ''}, {'only_tags': 'tag:lab, tag:other'},
                       {'only_tags': ['tag:lab', 'tag:other']}, {'skip_tags': []}, {'skip_tags': 'tag:new'}, {'only_os': []}, {'only_os': 'windows'}, {'routing': 'host'},
                       {'auto_scan': 'false'}, {'auto_scan': 'yes'}, {'enabled': 'no'}):
            self.refused('tailscale_project', values, ident)
        link.refresh_from_db()
        self.assertEqual((link.max_devices, link.only_tags, link.skip_tags, link.only_os, link.routing), (10, ['tag:lab', 'tag:web'], ['tag:old'], ['linux'], 'auto'))
        bridge.change_setting(self.ctx, 'tailscale_project', {'max_devices': '5', 'only_tags': 'tag:lab', 'skip_tags': ['tag:old', 'tag:new'], 'only_os': ['linux'], 'auto_scan': False}, ident)
        link.refresh_from_db()
        self.assertEqual((link.max_devices, link.only_tags, link.skip_tags, link.only_os, link.auto_scan), (5, ['tag:lab'], ['tag:old', 'tag:new'], ['linux'], False))

    def test_a_text_where_the_page_shows_a_switch_is_a_switch(self):
        for name, values in (('updates', {'enabled': 'yes'}), ('updates', {'enabled': 'false'})):
            self.refused(name, values)

    def test_the_heavy_scanner_limits_an_agent_can_lower_but_not_raise(self):
        from cveFeed import scan_concurrency as sc
        unmanaged = [f.key for f in sc.FIELDS if not f.auto_tunable]
        self.assertTrue(unmanaged)
        for key in unmanaged:
            now = sc.resolve(key)['value']
            self.refused('scan_concurrency', {'values': {key: min(sc.BY_KEY[key].high, now + 1)}})
            if now > sc.BY_KEY[key].low:
                bridge.change_setting(self.ctx, 'scan_concurrency', {'values': {key: now - 1}})
                self.assertEqual(sc.resolve(key)['value'], now - 1)


class WidenThroughSentinelAndTargetToolsTests(TestCase):
    """FB-5, the tools outside the bridge: the Sentinel defaults, one Sentinel's settings and limits, runZero import and a target's scope and discovery mode."""

    @classmethod
    def setUpTestData(cls):
        from tests.test_sentinels import build_world
        build_world(cls)

    def setUp(self):
        from tests.test_sentinels import reset_rates
        reset_rates(self.tokens)
        self.person = Ctx(user=self.root, token=None)

    def sentinel(self):
        from agentapi.models import Agent

        from tests.test_sentinels import register_sentinel
        status, out = register_sentinel(self.tokens['alice'])
        self.assertIn(status, (200, 201), out)
        return Agent.objects.get(pk=out['id'])

    def test_sentinel_defaults_by_token_can_be_narrowed_never_widened(self):
        from agentapi import sentinel_settings as ss

        from tests.test_agentapi import call, tool_call
        root = self.tokens['root']
        ss.set_defaults(self.root, {'external_kinds': {'nuclei_deep': {'mode': 'deny'}}, 'self_update': 'manual', 'keep_newest': False})
        for args in ({'external_kinds': {}}, {'builtin_kinds': {}}, {'external_kinds': {'nuclei_deep': {'mode': 'allow'}}}, {'external_kinds': {'nuclei_deep': {'mode': 'prefer'}}},
                     {'self_update': 'automatic'}, {'self_update': None}, {'external_kinds': None, 'self_update': 'automatic'}):
            error, _text = tool_call(root, 'set_sentinel_defaults', args)
            self.assertTrue(error, args)
            self.assertEqual(call(root, 'PUT', '/api/v1/sentinels/defaults', args)[0], 403, args)
        self.assertEqual(call(root, 'PUT', '/api/v1/sentinels/defaults', {'keep_newest': True})[0], 403)
        after = ss.get_defaults()
        self.assertEqual((after['external_kinds'], after['self_update'], after['keep_newest']), ({'nuclei_deep': {'mode': 'deny', 'max_concurrent': None}}, 'manual', False))
        error, out = tool_call(root, 'set_sentinel_defaults', {'external_kinds': {'nuclei_deep': {'mode': 'deny'}, 'nmap': {'mode': 'deny'}}, 'self_update': 'off'})
        self.assertFalse(error, out)
        self.assertEqual((sorted(ss.get_defaults()['external_kinds']), ss.get_defaults()['self_update']), (['nmap', 'nuclei_deep'], 'off'))
        ss.set_defaults(self.root, {'external_kinds': {'nuclei_deep': {'mode': 'deny'}}}, via_agent=False)  # a person widens it again

    def test_one_sentinels_settings_and_limits_by_token_can_be_narrowed_never_widened(self):
        from agentapi import agent_broker as broker

        from tests.test_agentapi import call
        agent = self.sentinel()
        root = self.tokens['root']
        patch = lambda body: call(root, 'PATCH', f'/api/v1/agents/{agent.pk}', body)
        for settings in ({'network': 'internal'}, {'discovery_keys': True}, {'self_update': 'automatic'}, {'self_update': None}, {'max_concurrent': 9}):
            self.assertEqual(patch({'settings': settings})[0], 403, settings)
        self.assertEqual(patch({'settings': {'network': 'external', 'profile': 'light', 'discovery_keys': False, 'self_update': 'manual', 'kinds': {'nmap': {'mode': 'deny'}}}})[0], 200)
        self.assertEqual(patch({'settings': {'profile': 'full'}})[0], 403)  # light was chosen: full is wider
        self.assertEqual(patch({'settings': {'kinds': {'nmap': {'mode': 'allow'}}}})[0], 403)  # a denied kind allowed again
        self.assertEqual(patch({'settings': {'disabled_kinds': []}})[0], 403)
        self.assertEqual(patch({'settings': {'kinds': {'naabu': {'mode': 'allow', 'max_concurrent': 2}}}})[0], 200)
        self.assertEqual(patch({'settings': {'kinds': {'naabu': {'mode': 'allow', 'max_concurrent': 3}}}})[0], 403)
        self.assertEqual(patch({'settings': {'kinds': {'naabu': None}}})[0], 403)
        # limits are replaced as a whole: a key left out is no limit
        broker.update_agent(self.person, agent.pk, {'limits': {'capabilities': ['nmap', 'naabu'], 'max_concurrent': 2}})
        for limits in ({'capabilities': ['nmap', 'naabu', 'nuclei_light']}, {'max_concurrent': 2}, {'capabilities': ['nmap']}, {'capabilities': ['nmap'], 'max_concurrent': 3}, {}):
            self.assertEqual(patch({'limits': limits})[0], 403, limits)
        agent.refresh_from_db()
        self.assertEqual(agent.limits, {'capabilities': ['nmap', 'naabu'], 'max_concurrent': 2})
        self.assertEqual(patch({'limits': {'capabilities': ['nmap'], 'max_concurrent': 1}})[0], 200)
        broker.update_agent(self.person, agent.pk, {'settings': {'network': 'internal', 'profile': 'full'}, 'limits': {'max_concurrent': 5}})  # a person may
        agent.refresh_from_db()
        self.assertEqual((agent.network, agent.limits), ('internal', {'max_concurrent': 5}))

    def test_runzero_import_scope_and_discovery_mode_by_token_can_be_narrowed_never_widened(self):
        from agentapi import services as svc
        from cveFeed import runzero_sync

        from tests.test_agentapi import tool_call
        root = self.tokens['root']
        error, _ = tool_call(root, 'set_runzero_sync', {'project': 'sen-a', 'import_enabled': True})
        self.assertTrue(error)
        self.assertFalse(runzero_sync.settings_for(self.pa).import_enabled)
        svc.set_runzero(self.person, 'sen-a', {'import_enabled': True})  # a person
        error, _ = tool_call(root, 'set_runzero_sync', {'project': 'sen-a', 'search': 'alive:true AND os:linux'})
        self.assertTrue(error)  # the import is on: a different search can add more
        error, _ = tool_call(root, 'set_runzero_sync', {'project': 'sen-a', 'import_enabled': False})
        self.assertFalse(error)
        self.assertFalse(runzero_sync.settings_for(self.pa).import_enabled)
        target = {'project': 'sen-a', 'target_id': self.da.pk}
        error, _ = tool_call(root, 'set_target_scope', {**target, 'scope_mode': 'parent'})
        self.assertTrue(error)
        error, _ = tool_call(root, 'set_target_scope', {**target, 'scope_mode': 'host'})
        self.assertFalse(error)
        error, _ = tool_call(root, 'set_target_scope', {**target, 'scope_mode': 'auto'})
        self.assertTrue(error)  # host to auto reaches further
        svc.set_target_scope(self.person, 'sen-a', self.da.pk, 'parent')  # a person
        error, _ = tool_call(root, 'set_target_discovery_mode', {**target, 'discovery_mode': 'deep'})
        self.assertTrue(error)
        for mode, refused in (('passive', False), ('standard', True), ('manual', False), ('passive', True)):
            error, text = tool_call(root, 'set_target_discovery_mode', {**target, 'discovery_mode': mode})
            self.assertEqual(bool(error), refused, (mode, text))


class AnswerWordsTests(TestCase):
    """FB-11 (Recommend only must mean a person decides) and FB-13 (an old "Decide later" is no answer)."""

    def setUp(self):
        from tests.test_setup_questions import Base as QuestionBase
        self.q = QuestionBase('setUp')
        self.q._testMethodName = 'setUp'
        self.q.setUp()
        self.addCleanup(self.q.tearDown)
        self.q.connect_ai()

    def row(self):
        from cveFeed.models import ReviewerSettings
        return ReviewerSettings.current()

    def test_recommend_only_does_not_switch_the_ai_written_checks_on_and_act_does(self):
        from tests.test_setup_questions import post
        q = self.q
        for answer, templates in (('recommend', False), ('act', True), ('off', True)):  # off after act leaves what a person had on
            self.assertEqual(post(q.c, {'key': 'ai_validation', 'answer': answer}).status_code, 200)
            row = self.row()
            self.assertEqual(row.template_validation_enabled, templates, answer)
        from cveFeed.models import ReviewerSettings
        ReviewerSettings.objects.update(template_validation_enabled=False)
        post(q.c, {'key': 'ai_validation', 'answer': 'recommend'})
        self.assertFalse(self.row().template_validation_enabled)
        self.assertTrue(self.row().host_review_enabled)  # the host review is a line a person decides each step of: still switched on

    def test_the_words_of_the_two_choices_say_what_happens_to_the_checks(self):
        question = self.q.question('ai_validation')
        effects = {c['value']: c['effect'] for c in question['choices']}
        self.assertIn('AI-written checks stay off', effects['recommend'])
        self.assertIn('Settings > AI model', effects['recommend'])
        self.assertIn('with no person approving it', effects['act'])
        self.assertIn('Only "Act on safe steps" switches this on', ' '.join(question['facts']))

    def test_asked_again_for_the_new_lines_switch_it_on_still_switches_the_checks_on(self):
        from cveFeed.models import ReviewerSettings, SetupAnswer

        from tests.test_setup_questions import post
        q = self.q
        ReviewerSettings.objects.create(enabled=True, auto_close=False, updated_by=q.admin)
        SetupAnswer.objects.create(key='ai_validation', answer='recommend', answered_by=q.admin, version=1)
        self.assertEqual(post(q.c, {'key': 'ai_validation', 'answer': 'recommend'}).status_code, 200)
        row = self.row()
        self.assertEqual((row.enabled, row.auto_close, row.host_review_enabled, row.template_validation_enabled), (True, False, True, True))

    def test_an_old_decide_later_asks_the_whole_question_again_finding_review_included(self):
        from cveFeed.models import ReviewerSettings, SetupAnswer

        from tests.test_setup_questions import post
        q = self.q
        ReviewerSettings.objects.create(enabled=True, auto_close=False, updated_by=q.admin)  # the development default the old build left
        SetupAnswer.objects.create(key='ai_validation', answer='later', answered_by=q.admin, version=1)
        question = q.question('ai_validation')
        self.assertEqual(question['new_lines'], [])
        self.assertEqual([c['value'] for c in question['choices']], ['off', 'recommend', 'act'])
        self.assertIn('finding review', ' '.join(question['facts']).lower())
        self.assertEqual(post(q.c, {'key': 'ai_validation', 'answer': 'off'}).status_code, 200)
        row = self.row()
        self.assertEqual((row.enabled, row.auto_close, row.host_review_enabled, row.template_validation_enabled), (False, False, False, False))  # every line carried out, the finding review too
        self.assertEqual(SetupAnswer.objects.get(key='ai_validation').version, 3)

    def test_an_old_real_answer_still_asks_only_for_the_new_lines(self):
        from cveFeed.models import SetupAnswer
        SetupAnswer.objects.create(key='ai_validation', answer='recommend', answered_by=self.q.admin, version=1)
        self.assertEqual(self.q.question('ai_validation')['new_lines'], ['AI host review', 'AI-written checks'])


class PersonsMarkTests(Base):
    """FB-12: the bridge put the old ``updated_by`` back after an agent's save, which also wiped a person's mark made in between. The handler now leaves it alone for an agent."""

    def test_a_person_who_saves_while_an_agent_saves_keeps_their_mark(self):
        from cveFeed import reviewer
        from cveFeed.models import ReviewerSettings
        person = User.objects.create_user('rules_person', password='x')
        pk = reviewer.settings_row().pk
        real_audit = __import__('cveFeed.admin_api', fromlist=['audit']).audit

        def a_person_saves_now(*args, **kwargs):  # between the agent's save and the end of its call
            ReviewerSettings.objects.filter(pk=pk).update(updated_by=person)
            return real_audit(*args, **kwargs)

        with mock.patch('cveFeed.admin_api.audit', side_effect=a_person_saves_now):
            bridge.change_setting(self.ctx, 'reviewer', {'review_daily_max': 10})
        row = ReviewerSettings.objects.get(pk=pk)
        self.assertEqual((row.review_daily_max, row.updated_by_id), (10, person.pk))

    def test_an_agents_save_still_leaves_nobody_marked_and_a_persons_save_marks_them(self):
        from cveFeed import reviewer
        bridge.change_setting(self.ctx, 'reviewer', {'review_daily_max': 10})
        self.assertIsNone(reviewer.settings_row().updated_by_id)
        c = Client()
        c.force_login(self.root)
        self.assertEqual(c.put('/cve/api/settings/reviewer', json.dumps({'review_daily_max': 9}), content_type='application/json').status_code, 200)
        self.assertEqual(reviewer.settings_row().updated_by_id, self.root.pk)
