from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase

from tenancy import views


class LoginThrottleTests(TestCase):
	"""The password step counts wrong passwords and refuses further tries (it used to allow unlimited guessing)."""

	def setUp(self):
		cache.clear()
		self.user = User.objects.create_user('victim', password='right-pw-1')

	def attempt(self, password, username='victim', client=None):
		return (client or Client()).post('/login/', {'username': username, 'password': password})

	def test_wrong_passwords_are_refused_after_the_pair_limit_even_with_the_right_one(self):
		limit = dict(views.LOGIN_LIMITS)['pair']
		c = Client()
		for _ in range(limit):
			self.assertEqual(self.attempt('wrong', client=c).status_code, 200)
		r = self.attempt('right-pw-1', client=c)
		self.assertEqual(r.status_code, 429)
		self.assertNotIn('_auth_user_id', c.session)

	def test_a_success_clears_the_pair_counter(self):
		limit = dict(views.LOGIN_LIMITS)['pair']
		for _ in range(limit - 1):
			self.attempt('wrong')
		self.assertEqual(self.attempt('right-pw-1').status_code, 302)
		for _ in range(limit - 1):
			self.assertEqual(self.attempt('wrong').status_code, 200)

	def test_one_address_spraying_many_names_is_stopped(self):
		limit = dict(views.LOGIN_LIMITS)['ip']
		for i in range(limit):
			self.attempt('x', username=f'nobody{i}')
		self.assertEqual(self.attempt('right-pw-1').status_code, 429)

	def test_another_address_can_still_sign_in_after_one_is_blocked(self):
		limit = dict(views.LOGIN_LIMITS)['pair']
		for _ in range(limit):
			self.attempt('wrong')
		other = Client(REMOTE_ADDR='203.0.113.9')
		self.assertEqual(self.attempt('right-pw-1', client=other).status_code, 302)

	def test_the_username_case_does_not_dodge_the_counter(self):
		limit = dict(views.LOGIN_LIMITS)['pair']
		for i in range(limit):
			self.attempt('wrong', username='VICTIM' if i % 2 else 'victim')
		self.assertEqual(self.attempt('right-pw-1', username='Victim').status_code, 429)

	def test_unicode_spellings_of_a_name_share_one_counter(self):
		limit = dict(views.LOGIN_LIMITS)['pair']
		spellings = ['victim', '\uff56\uff49\uff43\uff54\uff49\uff4d', ' VICTIM ', '\uff36ictim', 'victim\u200b'[:-1]]
		for i in range(limit):
			self.attempt('wrong', username=spellings[i % len(spellings)])
		self.assertEqual(self.attempt('right-pw-1', username='\uff56ictim').status_code, 429)
		self.assertEqual(views._login_name('\uff21\uff44\uff4d\uff49\uff4e '), 'admin')

	def test_the_attempt_that_locks_an_account_is_audited_once_for_its_organization(self):
		from dashboard.models import AuditLog, Org, OrgMembership
		OrgMembership.objects.create(user=self.user, org=Org.objects.create(name='L', slug='l'), role='user')
		limit = dict(views.LOGIN_LIMITS)['pair']
		for _ in range(limit + 3):
			self.attempt('wrong')
		rows = AuditLog.objects.filter(action='account.login_locked')
		self.assertEqual((rows.count(), rows.get().target, rows.get().org.slug), (1, 'victim', 'l'))
		self.attempt('wrong', username='nobody-here')  # an unknown name has no account to record against
		self.assertEqual(AuditLog.objects.filter(action='account.login_locked').count(), 1)


class PasswordChangeThrottleTests(TestCase):
	def setUp(self):
		cache.clear()
		self.user = User.objects.create_user('pwuser', password='right-pw-1')
		self.client = Client()
		self.client.force_login(self.user)

	def change(self, current):
		return self.client.post('/cve/api/account/password', {'current': current, 'new': 'Another-Strong-pw-91'},
								content_type='application/json')

	def test_wrong_current_passwords_lock_the_change_endpoint(self):
		from cveFeed import account_api
		for _ in range(account_api.PASSWORD_MAX_FAILURES):
			self.assertEqual(self.change('wrong').status_code, 400)
		self.assertEqual(self.change('right-pw-1').status_code, 429)


class MfaSecretStorageTests(TestCase):
	def test_the_totp_seed_is_encrypted_in_the_column_and_recovery_codes_are_keyed(self):
		import hashlib

		from django.db import connection

		from dashboard.models import UserProfile
		from tenancy import mfa
		user = User.objects.create_user('seeded', password='x')
		seed = mfa.new_secret()
		plain, hashes = mfa.new_recovery_codes()
		profile = UserProfile.objects.create(user=user, mfa_enabled=True, mfa_secret=seed, recovery_codes=hashes)
		with connection.cursor() as cursor:
			cursor.execute('SELECT mfa_secret FROM dashboard_userprofile WHERE id = %s', [profile.pk])
			stored = cursor.fetchone()[0]
		self.assertTrue(stored.startswith('enc:v1:'))
		self.assertNotIn(seed, stored)
		self.assertEqual(UserProfile.objects.get(pk=profile.pk).mfa_secret, seed)
		self.assertTrue(all(h.startswith(mfa.KEYED_PREFIX) for h in hashes))
		self.assertEqual(len(plain[0].replace('-', '')), 20)  # 80 bits
		self.assertNotIn(hashlib.sha256(plain[0].replace('-', '').encode()).hexdigest(), hashes)

	def test_a_code_stored_by_an_older_version_still_works_once(self):
		import hashlib

		from tenancy import mfa
		legacy = [hashlib.sha256(b'abc123def456').hexdigest()]
		rest = mfa.consume_recovery_code(legacy, 'ABC123-DEF456')
		self.assertEqual(rest, [])
		self.assertIsNone(mfa.consume_recovery_code(rest, 'abc123-def456'))


class SecurityHeaderTests(TestCase):
	def test_every_response_carries_a_content_security_policy(self):
		response = Client().get('/login/')
		policy = response['Content-Security-Policy']
		for directive in ("base-uri 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'"):
			self.assertIn(directive, policy)
		self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

	def test_the_validate_deep_link_only_focuses_the_button(self):
		import os
		source = open(os.path.join(os.path.dirname(__file__), '..', 'static', 'cve', 'app.js'), encoding='utf-8').read()
		self.assertNotIn('run.click()', source)
