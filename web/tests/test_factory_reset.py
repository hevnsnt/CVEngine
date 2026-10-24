import json
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from tests.test_tenancy import client_for
from cveFeed import factory_reset
from dashboard.models import AIProviderSettings, ApiToken, AuditLog, Org, OrgMembership, Project, UserProfile
from targetApp.models import Domain

URL = '/cve/api/settings/factory_reset'


def post(client, body):
	return client.post(URL, json.dumps(body), content_type='application/json')


class FactoryResetTests(TestCase):
	def setUp(self):
		cache.clear()
		self.admin = User.objects.create_superuser('root', 'r@x.test', 'rootpw')
		self.other = User.objects.create_user('other', password='x')
		self.org = Org.objects.create(name='Acme', slug='acme')
		self.project = Project.objects.create(name='Web', slug='acme-web', insert_date=timezone.now(), org=self.org)
		OrgMembership.objects.create(user=self.other, org=self.org, role='admin')
		Domain.objects.create(name='a.example', project=self.project, insert_date=timezone.now())
		create_token(self.other, 'tok')
		AIProviderSettings.objects.create(provider='openai', api_key='sk-secret', enabled=True)
		UserProfile.objects.create(user=self.admin, onboarded=True, mfa_enabled=True)
		self.client = client_for(self.admin)

	def test_needs_the_phrase_and_the_password(self):
		self.assertEqual(post(self.client, {'confirm': 'reset', 'password': 'rootpw'}).status_code, 400)
		self.assertEqual(post(self.client, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'wrong'}).status_code, 403)
		self.assertTrue(Project.objects.filter(slug='acme-web').exists())  # nothing happened

	def test_wrong_passwords_lock_the_button(self):
		for _ in range(5):
			post(self.client, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'wrong'})
		self.assertEqual(post(self.client, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'rootpw'}).status_code, 429)

	def test_only_superusers(self):
		member = client_for(self.other)
		self.assertEqual(post(member, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'x'}).status_code, 403)
		self.assertEqual(Client().post(URL, '{}', content_type='application/json').status_code, 302)  # signed out: sent to the login page

	def test_running_scans_block_unless_forced(self):
		with mock.patch.object(factory_reset, 'running_scans', return_value=2):
			body = {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'rootpw'}
			self.assertEqual(post(self.client, body).status_code, 409)
			self.assertTrue(Project.objects.filter(slug='acme-web').exists())
			self.assertEqual(post(self.client, {**body, 'force': True}).status_code, 200)

	def test_reset_returns_to_a_fresh_install(self):
		response = post(self.client, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'rootpw'})
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()['redirect'], '/cve/welcome/')
		self.assertEqual(list(Org.objects.values_list('slug', flat=True)), ['default'])
		self.assertEqual(list(Project.objects.values_list('slug', 'name')), [('default', 'Default')])
		self.assertEqual(Domain.objects.count(), 0)
		self.assertEqual(list(User.objects.values_list('username', flat=True)), ['root'])
		self.assertEqual((ApiToken.objects.count(), AIProviderSettings.objects.count(), OrgMembership.objects.count()), (0, 0, 0))
		profile = UserProfile.objects.get(user=self.admin)
		self.assertFalse(profile.onboarded)
		self.assertTrue(profile.mfa_enabled)  # the administrator's sign-in is untouched
		self.assertTrue(User.objects.get(username='root').check_password('rootpw'))
		self.assertEqual(AuditLog.objects.filter(action='system.factory_reset').count(), 1)  # the only audit row left
		self.assertEqual(AuditLog.objects.count(), 1)

	def test_the_administrator_stays_signed_in_and_is_sent_to_the_wizard(self):
		post(self.client, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'rootpw'})
		response = self.client.get('/cve/')
		self.assertEqual((response.status_code, response['Location']), (302, '/cve/welcome/'))

	def test_other_sessions_are_ended(self):
		client_for(self.other)  # a second signed-in session that the reset must end
		post(self.client, {'confirm': factory_reset.CONFIRM_PHRASE, 'password': 'rootpw'})
		self.assertEqual(Session.objects.count(), 1)
