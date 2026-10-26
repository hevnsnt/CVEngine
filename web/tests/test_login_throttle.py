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
