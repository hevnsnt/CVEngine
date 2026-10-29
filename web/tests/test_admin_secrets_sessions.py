from django.contrib.auth.models import User
from django.test import TestCase


class AdminSecretsTests(TestCase):
	def setUp(self):
		self.root = User.objects.create_superuser('adm-root', 'r@example.test', 'pw-12345-long')
		self.client.force_login(self.root)

	def test_the_admin_never_shows_a_stored_key_in_a_form_or_a_list(self):
		from dashboard.models import NetlasAPIKey, OpenAiAPIKey
		netlas = NetlasAPIKey.objects.create(key='nl-very-secret-value')
		openai = OpenAiAPIKey.objects.create(key='sk-very-secret-value')
		for url in (f'/admin/dashboard/netlasapikey/{netlas.pk}/change/', f'/admin/dashboard/openaiapikey/{openai.pk}/change/',
					f'/admin/dashboard/netlasapikey/', f'/admin/dashboard/openaiapikey/'):
			response = self.client.get(url)
			self.assertEqual(response.status_code, 200, url)
			self.assertNotContains(response, 'very-secret-value')

	def test_a_key_model_does_not_print_its_value(self):
		from dashboard.models import ChaosAPIKey
		self.assertNotIn('secret', str(ChaosAPIKey(key='chaos-secret-value')))


class HashedSessionTests(TestCase):
	def test_the_session_table_never_holds_the_cookie_value_and_logins_still_work(self):
		from django.contrib.sessions.models import Session
		user = User.objects.create_user('sess-user', password='pw-12345-long')
		self.client.login(username='sess-user', password='pw-12345-long')
		cookie = self.client.cookies['sessionid'].value
		self.assertFalse(Session.objects.filter(session_key=cookie).exists())
		self.assertEqual(Session.objects.count(), 1)
		from reNgine.hashed_sessions import db_key
		self.assertTrue(Session.objects.filter(session_key=db_key(cookie)).exists())
		self.assertEqual(self.client.get('/cve/api/account/me').status_code, 200)  # the session is found again on the next request
		self.client.post('/signout/') if False else self.client.logout()
		self.assertEqual(Session.objects.count(), 0)  # signing out deletes the row

	def test_a_stolen_database_row_is_not_a_login(self):
		from django.contrib.sessions.models import Session
		User.objects.create_user('sess-user2', password='pw-12345-long')
		self.client.login(username='sess-user2', password='pw-12345-long')
		row_key = Session.objects.get().session_key
		from django.test import Client
		thief = Client()
		thief.cookies['sessionid'] = row_key  # what a copy of the table would offer
		self.assertEqual(thief.get('/cve/api/account/me').status_code, 302)
