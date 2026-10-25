"""Regression cases for pending login binding, factor consumption, and inherited MFA policy."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import close_old_connections
from django.test import Client, TestCase, TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.account_api import account_payload
from dashboard.models import Org, OrgMembership, Project, ProjectMembership, UserProfile
from tenancy import mfa, roles, views
from tests.test_tenancy import client_for


class PendingMfaSecurityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('pending-user', password='Initial-password-123!')
        self.profile = UserProfile.objects.create(
            user=self.user, mfa_enabled=True, mfa_secret=mfa.new_secret())
        self.client = Client()
        response = self.client.post('/login/', {
            'username': self.user.username, 'password': 'Initial-password-123!'})
        self.assertEqual(response['Location'], '/mfa/verify/')

    def assert_pending_refused(self, code=None):
        response = self.client.post('/mfa/verify/', {'code': code or mfa.totp(self.profile.mfa_secret)})
        self.assertEqual((response.status_code, response['Location']), (302, '/login/'))
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertNotIn(views.PENDING_KEY, self.client.session)

    def test_password_change_invalidates_pending_first_factor(self):
        plain, hashes = mfa.new_recovery_codes()
        self.profile.recovery_codes = hashes
        self.profile.save(update_fields=['recovery_codes'])
        self.user.set_password('Replacement-password-456!')
        self.user.save(update_fields=['password'])
        self.assert_pending_refused(plain[0])
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.recovery_codes, hashes)

    def test_disabled_account_cannot_finish_pending_login(self):
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        self.assert_pending_refused()

    def test_deleted_account_is_rejected_without_server_error(self):
        self.user.delete()
        self.assert_pending_refused()

    def test_deleted_profile_is_not_recreated_by_pending_login(self):
        self.profile.delete()
        self.assert_pending_refused()
        self.assertFalse(UserProfile.objects.filter(user=self.user).exists())

    def test_disabled_factor_invalidates_pending_login(self):
        UserProfile.objects.filter(pk=self.profile.pk).update(mfa_enabled=False)
        self.assert_pending_refused()

    def test_replaced_factor_invalidates_pending_login_even_with_new_valid_code(self):
        replacement = mfa.new_secret()
        UserProfile.objects.filter(pk=self.profile.pk).update(mfa_secret=replacement)
        self.assert_pending_refused(mfa.totp(replacement))

    def test_unchanged_credentials_allow_pending_login(self):
        response = self.client.post('/mfa/verify/', {'code': mfa.totp(self.profile.mfa_secret)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session[SESSION_KEY], str(self.user.pk))

    def test_expired_or_legacy_pending_records_fail_closed(self):
        original = dict(self.client.session[views.PENDING_KEY])
        for pending in (None, {}, {**original, 'ts': 0}, {**original, 'auth_hash': ''},
                        {**original, 'ts': 'invalid'}, {**original, 'factor_state': ''}):
            with self.subTest(pending=pending):
                session = self.client.session
                session[views.PENDING_KEY] = pending
                session.save()
                self.assert_pending_refused()


class FactorConsumptionSecurityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('factor-user')
        self.profile = UserProfile.objects.create(
            user=self.user, mfa_enabled=True, mfa_secret=mfa.new_secret())

    def test_stale_profile_cannot_reuse_consumed_totp(self):
        first = UserProfile.objects.get(pk=self.profile.pk)
        stale = UserProfile.objects.get(pk=self.profile.pk)
        with patch('tenancy.mfa.time.time', return_value=1800000000):
            code = mfa.totp(first.mfa_secret)
            self.assertTrue(views.check_second_factor(first, code))
            self.assertFalse(views.check_second_factor(stale, code))

    def test_stale_profiles_cannot_reuse_or_restore_recovery_codes(self):
        plain, hashes = mfa.new_recovery_codes()
        self.profile.recovery_codes = hashes
        self.profile.save(update_fields=['recovery_codes'])
        first = UserProfile.objects.get(pk=self.profile.pk)
        stale = UserProfile.objects.get(pk=self.profile.pk)
        self.assertTrue(views.check_second_factor(first, plain[0]))
        self.assertFalse(views.check_second_factor(stale, plain[0]))
        self.assertTrue(views.check_second_factor(stale, plain[1]))
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.recovery_codes, hashes[2:])

    def test_stale_profile_cannot_use_disabled_factor(self):
        UserProfile.objects.filter(pk=self.profile.pk).update(mfa_enabled=False)
        self.assertFalse(views.check_second_factor(self.profile, mfa.totp(self.profile.mfa_secret)))


class ConcurrentFactorConsumptionTests(TransactionTestCase):
    @skipUnlessDBFeature('has_select_for_update')
    def test_two_connections_cannot_consume_one_recovery_code(self):
        user = User.objects.create_user('concurrent-factor-user')
        plain, hashes = mfa.new_recovery_codes()
        profile = UserProfile.objects.create(
            user=user, mfa_enabled=True, mfa_secret=mfa.new_secret(), recovery_codes=hashes)
        ready = Barrier(2)

        def consume():
            close_old_connections()
            try:
                stale = UserProfile.objects.get(pk=profile.pk)
                ready.wait(timeout=5)
                return views.check_second_factor(stale, plain[0])
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(consume) for _ in range(2)]
            results = [future.result(timeout=10) for future in futures]
        self.assertEqual(sorted(results), [False, True])


class ProjectMembershipMfaPolicyTests(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Org.objects.create(name='Mandatory MFA', slug='mandatory-mfa', require_mfa=True)
        self.project = Project.objects.create(name='Protected', slug='protected', org=self.org,
                                              insert_date=timezone.now())
        self.user = User.objects.create_user('project-only', password='Project-password-123!')
        self.membership = ProjectMembership.objects.create(user=self.user, project=self.project, role='user')

    def test_project_only_member_is_redirected_to_enrollment(self):
        self.assertFalse(OrgMembership.objects.filter(user=self.user).exists())
        response = client_for(self.user).get('/cve/protected/hosts/')
        self.assertEqual((response.status_code, response['Location']), (302, '/cve/account/#security'))
        self.assertTrue(account_payload(self.user)['mfa_required'])

    def test_project_only_member_tokens_cannot_bypass_required_enrollment(self):
        _, raw = create_token(self.user, 'test policy')
        client = Client(HTTP_AUTHORIZATION='Bearer ' + raw)
        self.assertEqual(client.get('/api/v1/me').status_code, 403)
        self.assertEqual(client.post('/mcp/', data={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
                                     content_type='application/json').status_code, 403)

    def test_project_only_member_cannot_disable_required_factor(self):
        profile = UserProfile.objects.create(user=self.user, mfa_enabled=True, mfa_secret=mfa.new_secret())
        response = client_for(self.user).post('/cve/api/account/mfa/disable',
            {'code': mfa.totp(profile.mfa_secret)}, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('requires two-step sign-in', response.json()['error'])
        profile.refresh_from_db()
        self.assertTrue(profile.mfa_enabled)

    def test_policy_tracks_current_memberships_and_org_flag(self):
        self.assertTrue(roles.requires_mfa(self.user))
        self.membership.delete()
        self.assertFalse(roles.requires_mfa(self.user))
        OrgMembership.objects.create(user=self.user, org=self.org, role='audit')
        self.assertTrue(roles.requires_mfa(self.user))
        self.org.require_mfa = False
        self.org.save(update_fields=['require_mfa'])
        self.assertFalse(roles.requires_mfa(self.user))
