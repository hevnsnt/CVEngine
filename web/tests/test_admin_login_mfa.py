from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.test import Client, TestCase

from dashboard.models import UserProfile
from tests.test_tenancy import client_for


class AdminLoginDoesNotSkipTwoStepTests(TestCase):
	"""Django's own /admin/login/ signs a staff user in with the password alone. Two-step sign-in lives in MFALoginView at /login/, so the
	admin login must never create a session itself: it sends the user to /login/, whatever the account's two-step state."""

	@classmethod
	def setUpTestData(cls):
		cls.secured = User.objects.create_superuser('admin-mfa', 'a@example.com', 'pw-correct-horse')
		UserProfile.objects.create(user=cls.secured, mfa_enabled=True, mfa_secret='JBSWY3DPEHPK3PXP')
		cls.plain = User.objects.create_superuser('admin-plain', 'p@example.com', 'pw-correct-horse')
		cls.nonstaff = User.objects.create_user('member', password='pw-correct-horse')

	def post_admin_login(self, username, **extra):
		client = Client()
		response = client.post('/admin/login/' + extra.get('query', ''), {'username': username, 'password': 'pw-correct-horse', 'next': '/admin/'})
		return client, response

	def test_a_password_alone_does_not_open_a_session_for_an_account_with_two_step(self):
		client, response = self.post_admin_login('admin-mfa')
		self.assertNotIn(SESSION_KEY, client.session)
		self.assertEqual(response.status_code, 302)
		self.assertTrue(response['Location'].startswith('/login/'), response['Location'])
		self.assertEqual(client.get('/admin/').status_code, 302)  # still signed out: the admin redirects to sign in

	def test_the_admin_login_is_not_a_second_password_form_for_any_account(self):
		client, response = self.post_admin_login('admin-plain')
		self.assertNotIn(SESSION_KEY, client.session)  # sign in at /login/, where the two-step rule is applied
		self.assertTrue(response['Location'].startswith('/login/'))

	def test_a_signed_out_visit_goes_to_the_app_login_and_keeps_a_safe_next(self):
		response = Client().get('/admin/login/?next=/admin/')
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response['Location'], '/login/?next=%2Fadmin%2F')

	def test_an_unsafe_next_is_dropped(self):
		for target in ('https://evil.example/', '//evil.example/x', 'javascript:alert(1)'):
			response = Client().get('/admin/login/', {'next': target})
			self.assertEqual(response['Location'], '/login/', target)

	def test_the_stock_admin_login_form_is_never_rendered(self):
		self.assertNotContains(Client().get('/admin/login/', follow=False), 'id_username', status_code=302)

	def test_a_signed_in_staff_user_is_sent_on_to_the_admin(self):
		response = client_for(self.secured).get('/admin/login/?next=/admin/')
		self.assertEqual((response.status_code, response['Location']), (302, '/admin/'))
		self.assertEqual(client_for(self.secured).get('/admin/').status_code, 200)

	def test_a_signed_in_non_staff_user_is_refused_everywhere_under_admin(self):
		client = client_for(self.nonstaff)
		for path in ('/admin/', '/admin/login/?next=/admin/'):
			self.assertEqual(client.get(path, follow=False).status_code, 403, path)  # refused outright, so nothing can loop
