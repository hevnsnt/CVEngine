"""Every setting a person can change in the web UI can be read and changed by an agent through the MCP (owner, 2026-11-09), with the same limits."""
import json
import re
from types import SimpleNamespace

from django.contrib.auth.models import User
from unittest import mock

from django.test import TestCase

from agentapi import mcp, settings_bridge as bridge
from agentapi.services import ApiError, Ctx
from dashboard.models import AuditLog, SystemTimings


def ctx(user, read_only=False):
    return Ctx(user=user, token=SimpleNamespace(read_only=read_only))


class CoverageTests(TestCase):
    def test_every_settings_route_has_an_mcp_entry_or_a_stated_reason(self):
        for api, table in bridge._tables().items():
            for _method, pattern, _fn in table:
                if api == 'admin' and pattern.split('/')[0] in bridge.IDENTITY_ROUTES_NOT_YET and not pattern.startswith('orgs/(?P<org_id>\\d+)/'):
                    continue
                exposed = any(a == api and p == pattern for a, p, _t, _i in bridge.ENTRIES.values())
                self.assertTrue(exposed or (api, pattern) in bridge.NOT_EXPOSED, f'{api} route {pattern} is not exposed to the MCP and has no reason')

    def test_every_entry_points_at_a_real_route(self):
        for name, (api, pattern, _text, ident) in bridge.ENTRIES.items():
            self.assertTrue(bridge._methods(api, pattern), f'{name}: no such route {pattern}')
            names = re.findall(r'\(\?P<(\w+)>', pattern)
            self.assertEqual(ident is not None, bool(names), name)
            if ident:
                self.assertEqual(ident.split('/'), names, name)

    def test_the_three_tools_are_listed(self):
        names = {t[0] for t in mcp.TOOLS}
        self.assertTrue({'list_settings', 'get_setting', 'change_setting'} <= names)


class BridgeTests(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser('bridge_root', 'b@x.io', 'x')
        self.plain = User.objects.create_user('bridge_plain', 'p@x.io', 'x')

    def test_an_app_admin_reads_and_changes_the_timings_with_the_page_limits_and_an_audit_entry(self):
        self.assertEqual(bridge.get_setting(ctx(self.root), 'timings')['ct_watch_minutes'], 20)
        out = bridge.change_setting(ctx(self.root), 'timings', {'ct_watch_minutes': 1440})
        self.assertEqual(out['ct_watch_minutes'], 1440)
        self.assertEqual(SystemTimings.current().ct_watch_minutes, 1440)
        self.assertTrue(AuditLog.objects.filter(action='timings.update').exists())
        for bad in (4, 1441, 'x'):
            with self.assertRaises(ApiError) as caught:
                bridge.change_setting(ctx(self.root), 'timings', {'ct_watch_minutes': bad})
            self.assertEqual(caught.exception.status, 400)
        self.assertEqual(SystemTimings.current().ct_watch_minutes, 1440)

    def test_the_certificate_interval_reaches_the_beat_schedule(self):
        from django_celery_beat.models import IntervalSchedule, PeriodicTask
        interval, _ = IntervalSchedule.objects.get_or_create(every=20, period='minutes')
        PeriodicTask.objects.update_or_create(name='cvengine-ct-watch', defaults={'task': 'watch_certificate_transparency_sweep', 'interval': interval})
        bridge.change_setting(ctx(self.root), 'timings', {'ct_watch_minutes': 1440})
        self.assertEqual(PeriodicTask.objects.get(name='cvengine-ct-watch').interval.every, 1440)

    def test_a_person_who_is_not_an_admin_gets_nothing(self):
        for fn in (lambda: bridge.get_setting(ctx(self.plain), 'timings'), lambda: bridge.get_setting(ctx(self.plain), 'ai'),
                   lambda: bridge.change_setting(ctx(self.plain), 'timings', {'ct_watch_minutes': 60})):
            with self.assertRaises(ApiError) as caught:
                fn()
            self.assertEqual(caught.exception.status, 403)

    def test_a_read_only_token_cannot_change_anything_but_can_read(self):
        self.assertIn('limits', bridge.get_setting(ctx(self.root, read_only=True), 'timings'))
        with self.assertRaises(ApiError) as caught:
            bridge.change_setting(ctx(self.root, read_only=True), 'timings', {'ct_watch_minutes': 60})
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(SystemTimings.current().ct_watch_minutes, 20)

    def test_an_unknown_name_an_id_that_is_not_an_id_and_a_download_are_refused(self):
        with self.assertRaises(ApiError) as caught:
            bridge.get_setting(ctx(self.root), 'nope')
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(ApiError):
            bridge.get_setting(ctx(self.root), 'org_api_key', '../../x/y')
        with self.assertRaises(ApiError):
            bridge.get_setting(ctx(self.root), 'org_api_key', '3')  # needs org_id/service
        with self.assertRaises(ApiError) as caught:
            bridge.change_setting(ctx(self.root), 'audit', {'x': 1})  # read only
        self.assertEqual(caught.exception.status, 405)

    def test_every_read_entry_answers_for_an_app_admin_and_none_returns_a_secret(self):
        secret = 'SECRET-VALUE-0123456789'
        with mock.patch('cveFeed.settings_api.ai_url_blocked', return_value=False):
            bridge.change_setting(ctx(self.root), 'email', {'host': 'mail.example.com', 'port': 587, 'security': 'starttls', 'username': 'u', 'password': secret})
        for item in bridge.catalogue():
            if not item['read'] or item['id']:
                continue
            try:
                out = bridge.get_setting(ctx(self.root), item['name'])
            except ApiError as exc:
                self.assertNotEqual(exc.status, 500, item['name'])
                continue
            self.assertNotIn(secret, repr(out), item['name'])

    def test_the_list_names_every_entry_and_what_is_left_out(self):
        out = bridge.list_settings(ctx(self.root))
        self.assertEqual({s['name'] for s in out['settings']}, set(bridge.ENTRIES))
        self.assertTrue(any(n['route'] == 'factory_reset' for n in out['not_exposed']))
        timings = next(s for s in out['settings'] if s['name'] == 'timings')
        self.assertTrue(timings['read'] and timings['change'])


class CredentialChecksThroughTheBridgeTests(TestCase):
    """Owner rule: no check that sends credentials runs unless a person turned it on. An agent token, even one of an App Admin, cannot turn it on."""

    def setUp(self):
        self.root = User.objects.create_superuser('cred_root', 'c@x.io', 'x')

    def test_an_agent_cannot_switch_credential_checks_on_but_can_switch_them_off_and_change_the_other_switch(self):
        from dashboard.models import ScanPolicy
        for values in ({'allow_credential_checks': True}, {'allow_credential_checks': True, 'nuclei_all_templates': False}):
            with self.assertRaises(ApiError) as caught:
                bridge.change_setting(ctx(self.root), 'scan_policy', values)
            self.assertEqual(caught.exception.status, 403, values)
        self.assertFalse(ScanPolicy.current().allow_credential_checks)
        self.assertFalse(ScanPolicy.current().nuclei_all_templates is False and ScanPolicy.objects.exists())  # nothing was half applied
        self.assertIs(bridge.get_setting(ctx(self.root), 'scan_policy')['allow_credential_checks'], False)
        ScanPolicy.objects.create(allow_credential_checks=True)  # a person turned it on in the web interface
        self.assertIs(bridge.change_setting(ctx(self.root), 'scan_policy', {'allow_credential_checks': False})['allow_credential_checks'], False)
        self.assertEqual(bridge.change_setting(ctx(self.root), 'scan_policy', {'nuclei_all_templates': False})['nuclei_all_templates'], False)


class AllowlistThroughTheBridgeTests(TestCase):
    """AM-2: the bridge's own request has an address of its own, so an agent must not be able to put it on the list and switch the list on."""

    def setUp(self):
        self.root = User.objects.create_superuser('lock_root', 'l@x.io', 'x')

    def tearDown(self):
        from reNgine import ip_allowlist
        ip_allowlist.invalidate_cache()

    def test_an_agent_cannot_add_an_entry_switch_the_list_on_or_delete_an_entry(self):
        from dashboard.models import IpAccessControl, IpAllowlistEntry
        entry = IpAllowlistEntry.objects.create(cidr='203.0.113.0/24', label='office')
        for name, values, ident, remove in (('ip_allowlist_entry_add', {'cidr': '127.0.0.1/32', 'label': 'agent'}, None, False),
                                            ('ip_allowlist', {'enabled': True}, None, False),
                                            ('ip_allowlist_entry', None, str(entry.id), True)):
            with self.assertRaises(ApiError) as caught:
                bridge.change_setting(ctx(self.root), name, values, ident=ident, remove=remove)
            self.assertEqual(caught.exception.status, 403, name)
        self.assertEqual(list(IpAllowlistEntry.objects.values_list('cidr', flat=True)), ['203.0.113.0/24'])
        self.assertFalse(IpAccessControl.current().enabled)

    def test_the_lockout_the_reviewer_found_does_not_happen_and_a_person_from_outside_still_gets_in(self):
        from django.test import Client
        for name, values in (('ip_allowlist_entry_add', {'cidr': '127.0.0.1/32'}), ('ip_allowlist', {'enabled': True})):
            with self.assertRaises(ApiError):
                bridge.change_setting(ctx(self.root), name, values)
        client = Client(REMOTE_ADDR='203.0.113.7')
        client.force_login(self.root)
        self.assertEqual(client.get('/cve/api/settings/ip_allowlist/').status_code, 200)

    def test_the_list_can_still_be_read_and_says_these_are_not_for_agents(self):
        out = bridge.get_setting(ctx(self.root), 'ip_allowlist')
        self.assertFalse(out['enabled'])
        self.assertTrue(any(n['route'] == 'ip_allowlist' for n in bridge.list_settings(ctx(self.root))['not_exposed']))

    def test_no_bridge_request_carries_the_loopback_address_into_a_guard(self):
        seen = []
        original = bridge.RequestFactory

        class Spy(original):
            def generic(self, *a, **k):
                request = super().generic(*a, **k)
                seen.append(request.META.get('REMOTE_ADDR'))
                return request

            def get(self, *a, **k):
                request = super().get(*a, **k)
                seen.append(request.META.get('REMOTE_ADDR'))
                return request

        with mock.patch.object(bridge, 'RequestFactory', Spy):
            bridge.get_setting(ctx(self.root), 'ip_allowlist')
            bridge.change_setting(ctx(self.root), 'timings', {'ct_watch_minutes': 30})
        self.assertGreaterEqual(len(seen), 2)
        for addr in seen:
            self.assertNotIn(addr, ('127.0.0.1', '::1', 'localhost', None))


# --- the cost and scope rule, default deny (final review FA-1 and FA-4) -------------------------------------------------------------------------------
class AgentCostRuleTests(TestCase):
    """An agent (MCP, a write token) may switch off and lower, never switch on or raise what costs money, widens what is scanned or changes who may reach the instance.
    A person's own save in the web interface is unaffected."""

    def setUp(self):
        self.root = User.objects.create_superuser('cost_root', 'c@x.io', 'x')

    def refused(self, name, values, ident=None):
        with self.assertRaises(ApiError, msg=(name, values)) as caught:
            bridge.change_setting(ctx(self.root), name, values, ident)
        self.assertEqual(caught.exception.status, 403, (name, values))

    def test_the_reviewers_probe_every_line_is_refused_and_leaves_the_row_untouched(self):
        from cveFeed import reviewer
        from cveFeed.models import ReviewerSettings
        before = ReviewerSettings.objects.filter(pk=reviewer.settings_row().pk).values('enabled', 'auto_close', 'review_daily_max', 'ops_hours', 'updated_by_id').get()
        for values in ({'enabled': True}, {'auto_close': True}, {'enabled': True, 'auto_close': True}, {'review_daily_max': 20000}, {'ops_hours': list(range(24))},
                       {'host_review_enabled': True}, {'host_review_auto_close': True}):
            self.refused('reviewer', values)
        for name, values in (('scan_policy', {'nuclei_all_templates': True}), ('scan_policy', {'allow_credential_checks': True}), ('ai', {'enabled': True}),
                             ('ai', {'auto_fire': True}), ('openvas', {'enabled': True}), ('scanner_plan', {'plan': 'both'}), ('updates', {'mode': 'automatic'}),
                             ('setup_questions', {'key': 'ai_validation', 'answer': 'act'})):
            self.refused(name, values)
        after = ReviewerSettings.objects.filter(pk=reviewer.settings_row().pk).values('enabled', 'auto_close', 'review_daily_max', 'ops_hours', 'updated_by_id').get()
        self.assertEqual(before, after)

    def test_lowering_and_switching_off_still_work_and_hours_can_be_taken_away(self):
        from cveFeed import reviewer
        row = reviewer.settings_row()
        row.enabled, row.auto_close, row.review_daily_max, row.ops_hours = True, True, 500, [3, 9, 15]
        row.save()
        out = bridge.change_setting(ctx(self.root), 'reviewer', {'auto_close': False, 'review_daily_max': 100, 'ops_hours': [9]})
        row.refresh_from_db()
        self.assertEqual((row.auto_close, row.review_daily_max, row.ops_hours, row.enabled), (False, 100, [9], True))
        bridge.change_setting(ctx(self.root), 'reviewer', {'enabled': False})
        row.refresh_from_db()
        self.assertFalse(row.enabled)
        self.refused('reviewer', {'ops_hours': [9, 10]})  # one hour added

    def test_an_agents_save_does_not_look_like_a_persons_choice(self):
        from cveFeed import reviewer, setup_questions
        row = reviewer.settings_row()
        self.assertIsNone(row.updated_by_id)
        bridge.change_setting(ctx(self.root), 'reviewer', {'review_daily_max': 10, 'review_model': 'some-model'})
        row.refresh_from_db()
        self.assertEqual(row.review_model, 'some-model')  # the save happened
        self.assertIsNone(row.updated_by_id)  # but nobody "chose"
        with mock.patch.object(setup_questions.BY_KEY['ai_validation'], 'applies', return_value=(True, '')):
            q = next(x for x in setup_questions.snapshot()['questions'] if x['key'] == 'ai_validation')
        self.assertEqual(q['state'], 'pending')
        self.assertTrue(AuditLog.objects.filter(action='settings.reviewer').exists())

    def test_a_person_in_the_web_interface_is_unaffected(self):
        from django.test import Client
        c = Client()
        c.force_login(self.root)
        for path, body in (('reviewer', {'enabled': True, 'auto_close': True, 'review_daily_max': 20000, 'ops_hours': [1, 2, 3]}), ('scan_policy', {'nuclei_all_templates': True})):
            response = c.put(f'/cve/api/settings/{path}', json.dumps(body), content_type='application/json')
            self.assertEqual(response.status_code, 200, (path, response.content[:200]))

    def test_every_bridge_entry_refuses_a_switch_that_is_not_on_the_allow_list_and_a_new_one_by_default(self):
        """Walks EVERY entry an agent can write: a boolean True in any field is refused unless (entry, field) is in ``AGENT_MAY_SWITCH_ON``, and a field nobody has heard of
        ('zz_new_switch') is refused the same way, so a setting added to a handler later stays closed to agents until someone lists it with a reason."""
        for name, entry in bridge.ENTRIES.items():
            method = next((m for m in bridge._methods(entry[0], entry[1]) if m in bridge.WRITE_METHODS), None)
            if method is None or name in bridge.READ_ONLY_FOR_AGENTS or name in bridge.GENERIC_RULE_SKIPS:
                continue
            ident = '1/x' if entry[3] and '/' in entry[3] else '1' if entry[3] else None
            for field in ('zz_new_switch',) + tuple(f for (n, f) in bridge.AGENT_MAY_SWITCH_ON if n == name):
                try:
                    bridge._default_deny(ctx(self.root), name, {field: True}, ident)
                    refused = False
                except ApiError as exc:
                    refused = exc.status == 403
                listed = (name, field) in bridge.AGENT_MAY_SWITCH_ON
                self.assertEqual(refused, not listed, (name, field))
                try:
                    bridge._default_deny(ctx(self.root), name, {'nested': {field: True}}, ident)
                    refused_nested = False
                except ApiError:
                    refused_nested = True
                self.assertEqual(refused_nested, not listed, ('nested', name, field))
        for (name, field), why in bridge.AGENT_MAY_SWITCH_ON.items():
            self.assertIn(name, bridge.ENTRIES, f'{name} is not an entry')
            self.assertGreater(len(why), 20, f'({name}, {field}) is allowed without a reason')
        for name, why in bridge.AGENT_NUMBERS_FREE.items():
            self.assertIn(name, bridge.ENTRIES)
            self.assertGreater(len(why), 5)
        # every explicit table names real entries
        for table in (bridge.AGENT_CANNOT_ENABLE, bridge.AGENT_CANNOT_SET, bridge.AGENT_LOWER_ONLY):
            for name in table:
                self.assertIn(name, bridge.ENTRIES)

    def test_a_number_the_entry_shows_cannot_be_raised_by_an_agent_unless_the_entry_is_listed(self):
        for name in ('ai', 'reviewer'):
            body = bridge.get_setting(ctx(self.root), name)
            flat = bridge._flatten(body)
            numeric = {k: v for k, v in flat.items() if isinstance(v, (int, float)) and not isinstance(v, bool) and 0 < v < 10 ** 6}
            self.assertTrue(numeric, name)
            for path, value in numeric.items():
                field = path.rsplit('.', 1)[-1]
                if field in bridge.AGENT_LOWER_ONLY.get(name, ()):
                    continue  # these have their own lower-only rule, tested in the agent tests
                with self.assertRaises(ApiError, msg=(name, path)):
                    bridge._default_deny(ctx(self.root), name, {field: value + 1}, None)
        bridge._default_deny(ctx(self.root), 'timings', {'ct_watch_minutes': 10 ** 5}, None)  # a listed entry: pacing, no spend
