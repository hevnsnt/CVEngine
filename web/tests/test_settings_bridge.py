"""Every setting a person can change in the web UI can be read and changed by an agent through the MCP (owner, 2026-11-09), with the same limits."""
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
