"""Final review B (1.4.0), the agent rules: an agent (any API token or MCP call) may lower, never raise, what costs money, widens what is scanned or switches an
update on. A person's own save in the web interface is unaffected. One class per finding of ``review140/final-b.md`` (FB-1, FB-2, FB-3, FB-5, FB-8, FB-12)."""
import json
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase

from agentapi import settings_bridge as bridge
from agentapi.services import ApiError, Ctx


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
        from cveFeed import autotune, scan_concurrency as sc, tunables
        row = autotune.settings_row()
        return (tunables.value('triage_max_per_day'), row.mode, row.advisor, row.agent_policy, dict(sc.ScanConcurrency.current().values or {}) if hasattr(sc, 'ScanConcurrency') else None)

    def seed(self):
        from cveFeed import autotune, scan_concurrency as sc, tunables
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
        from dashboard.models import Org
        from cveFeed.models import ExcludedAddress
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
