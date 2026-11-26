"""An address ban never locks the owner out silently: the guard does not ban an address that, in the last 24 hours, was the source of a signed-in App
Admin session or of a live Sentinel's calls. It keeps the strikes and raises an App Admin alert instead. A 403 that refuses an address is marked
(``X-CVEngine-Refusal``) so a Sentinel can tell it from a refusal of its token, and an App Admin lifts a ban with one click.

Addresses are truly public ones (8.8.4.4, 9.9.9.9): the guard never bans a private or documentation address.
"""
import json

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase
from django.utils import timezone

from agentapi import settings_bridge
from agentapi.auth import create_token
from agentapi.models import Agent
from agentapi.services import Ctx
from cveFeed.models import AdminAlert
from cvengine import guard_sources
from cvengine import input_guard as guard
from dashboard.models import AbuseBan, AbuseStrike, AuditLog, Org, Project

HOME = '8.8.4.4'
STRANGER = '9.9.9.9'
PROBE = '/api/v1/projects/w-p/targets'


class BanWithheld(TestCase):
    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='W', slug='w')
        cls.project = Project.objects.create(name='W', slug='w-p', insert_date=timezone.now(), org=org)
        cls.admin = User.objects.create_superuser('owner', 'o@x.test', 'x')
        cls.user = User.objects.create_user('someone', password='x')

    def setUp(self):
        cache.clear()  # the noted addresses and the alert gate live in the cache
        self.addCleanup(cache.clear)  # and must not protect an address in a later module's test
        guard.invalidate_cache()
        self.addCleanup(guard.invalidate_cache)

    def attack(self, ip):
        """One unauthenticated probe the guard counts (path traversal: 3 points, the default threshold): what a scan sends."""
        return Client().get('/cve/api/settings/x', {'path': '../../etc/passwd'}, REMOTE_ADDR=ip)

    def admin_session(self, ip):
        client = Client()
        client.force_login(self.admin)
        client.get('/cve/', REMOTE_ADDR=ip)
        return client

    def live_sentinel(self, status='active'):
        token, raw = create_token(self.admin, 'haxxxk-token', scope='sentinel')
        Agent.objects.create(token=token, name='haxxxK', kind='scanner', status=status)
        return raw

    def sentinel_call(self, raw, ip):
        return Client().post('/api/v1/sentinel/heartbeat', json.dumps({}), content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {raw}', REMOTE_ADDR=ip)

    # --- the ban is withheld for the owner and a live Sentinel -----------------------------------------------------------------------------------
    def test_a_stranger_is_banned_as_before(self):
        self.assertEqual(self.attack(STRANGER).status_code, 403)
        self.assertTrue(AbuseBan.objects.filter(ip=STRANGER, lifted=False).exists())
        self.assertFalse(AdminAlert.objects.exists())

    def test_the_address_of_an_app_admin_session_is_not_banned_and_an_alert_names_it(self):
        self.admin_session(HOME)
        response = self.attack(HOME)
        self.assertEqual(response.status_code, 400)  # rejected, as every payload is, but nothing blocked
        self.assertFalse(AbuseBan.objects.filter(ip=HOME).exists())
        self.assertTrue(AbuseStrike.objects.filter(ip=HOME, category='path_traversal', weight=3).exists())  # the strikes are kept
        alert = AdminAlert.objects.get(resolved_at__isnull=True)
        self.assertTrue(alert.code.startswith('ban_withheld'))
        self.assertIn(HOME, alert.title)
        self.assertIn('/cve/api/settings/x', alert.detail)
        self.assertIn('path_traversal', alert.detail)
        self.assertEqual(alert.facts['protected'], ['admin'])
        self.assertTrue(AuditLog.objects.filter(action='abuse.ban_withheld', target=HOME).exists())
        guard.invalidate_cache()
        self.assertNotEqual(Client().get('/login/', REMOTE_ADDR=HOME).status_code, 403)  # the owner still gets in

    def test_the_address_of_a_live_sentinel_is_not_banned(self):
        raw = self.live_sentinel()
        self.sentinel_call(raw, HOME)
        self.assertEqual(self.attack(HOME).status_code, 400)
        self.assertFalse(AbuseBan.objects.filter(ip=HOME).exists())
        alert = AdminAlert.objects.get(resolved_at__isnull=True)
        self.assertIn('haxxxK', alert.title)

    def test_a_sentinel_that_is_not_active_does_not_protect_its_address(self):
        raw = self.live_sentinel(status='suspended')
        self.sentinel_call(raw, HOME)
        self.assertEqual(self.attack(HOME).status_code, 403)
        self.assertTrue(AbuseBan.objects.filter(ip=HOME, lifted=False).exists())

    def test_an_ordinary_users_session_does_not_protect_its_address(self):
        client = Client()
        client.force_login(self.user)
        client.get('/cve/', REMOTE_ADDR=HOME)
        self.assertEqual(self.attack(HOME).status_code, 403)
        self.assertTrue(AbuseBan.objects.filter(ip=HOME).exists())

    def test_a_scan_of_many_requests_writes_one_alert(self):
        self.admin_session(HOME)
        for _ in range(5):
            self.attack(HOME)
        self.assertEqual(AdminAlert.objects.filter(resolved_at__isnull=True).count(), 1)
        self.assertEqual(AuditLog.objects.filter(action='abuse.ban_withheld').count(), 1)

    def test_an_unreadable_cache_protects_nothing(self):
        self.admin_session(HOME)
        from unittest import mock
        with mock.patch.object(cache, 'get_many', side_effect=ConnectionError('redis down')):
            self.assertEqual(self.attack(HOME).status_code, 403)
        self.assertTrue(AbuseBan.objects.filter(ip=HOME).exists())

    # --- the refusal is marked, so a Sentinel can tell it from a token refusal --------------------------------------------------------------------
    def test_a_ban_answer_is_marked_and_a_bad_token_is_not(self):
        response = self.attack(STRANGER)
        self.assertEqual(response[guard.REFUSAL_HEADER], 'banned')
        guard.invalidate_cache()
        banned = Client().post('/api/v1/sentinel/heartbeat', '{}', content_type='application/json', HTTP_AUTHORIZATION='Bearer nope', REMOTE_ADDR=STRANGER)
        self.assertEqual(banned.status_code, 403)
        self.assertEqual(banned[guard.REFUSAL_HEADER], 'banned')
        bad = Client().post('/api/v1/sentinel/heartbeat', '{}', content_type='application/json', HTTP_AUTHORIZATION='Bearer nope', REMOTE_ADDR=HOME)
        self.assertEqual(bad.status_code, 401)
        self.assertNotIn(guard.REFUSAL_HEADER, bad)

    # --- lifting a ban ----------------------------------------------------------------------------------------------------------------------------
    def test_an_app_admin_lifts_a_ban_with_one_call_and_an_agent_can_only_read_them(self):
        ban = AbuseBan.objects.create(ip=STRANGER, reason='x', expires_at=timezone.now() + timezone.timedelta(hours=1))
        AbuseBan.objects.create(ip='1.1.1.1', reason='old', expires_at=timezone.now() - timezone.timedelta(hours=1))
        guard.invalidate_cache()
        client = Client()
        client.force_login(self.admin)
        listed = client.get('/cve/api/settings/ip_bans', REMOTE_ADDR=HOME).json()
        self.assertEqual([b['ip'] for b in listed['bans']], [STRANGER])  # an expired ban is not in force
        self.assertEqual(Client().get('/login/', REMOTE_ADDR=STRANGER).status_code, 403)
        self.assertEqual(client.post(f'/cve/api/settings/ip_bans/{ban.pk}/lift', REMOTE_ADDR=HOME).status_code, 200)
        self.assertTrue(AbuseBan.objects.get(pk=ban.pk).lifted)
        self.assertTrue(AuditLog.objects.filter(action='abuse.ban_lifted', target=STRANGER).exists())
        self.assertNotEqual(Client().get('/login/', REMOTE_ADDR=STRANGER).status_code, 403)
        user = Client()
        user.force_login(self.user)
        self.assertEqual(user.post(f'/cve/api/settings/ip_bans/{ban.pk}/lift').status_code, 403)  # App Admin only
        token, _ = create_token(self.admin, 'agent')
        ctx = Ctx(user=self.admin, token=token)
        self.assertEqual(settings_bridge.get_setting(ctx, 'ip_bans')['bans'], [])
        with self.assertRaises(Exception):
            settings_bridge.change_setting(ctx, 'ip_ban_lift', ident=str(ban.pk))

    def test_noting_costs_no_query(self):
        client = self.admin_session(HOME)
        with self.assertNumQueries(0):
            guard_sources.note_request(type('R', (), {'api_token': None, 'user': self.admin, 'META': {'REMOTE_ADDR': HOME}})())
        self.assertTrue(guard_sources.protected(HOME))
        del client
