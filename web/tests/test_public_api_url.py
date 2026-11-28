"""CVENGINE_PUBLIC_API_URL (cvengine.public_url): when a server sets a public address that is not DOMAIN_NAME (a hosted server's shared
host), the Sentinel enrollment server_url, the default link base of server emails, the MCP address and the host on the API keys and
Sentinels pages use it; unset (or not a usable URL), each keeps its DOMAIN_NAME or request based behaviour."""
import base64
import json
import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings

from cvengine import public_url
from dashboard.models import Org, OrgMembership
from tests.test_sentinels import build_world, call, reset_rates
from tests.test_tenancy import client_for

SHARED = 'https://scanner.example.test'


class ParseTests(SimpleTestCase):
	def test_a_usable_value_is_normalised(self):
		for raw, want in (('https://scanner.example.test', ('https://scanner.example.test', 'scanner.example.test')),
				('https://Scanner.Example.Test/', ('https://scanner.example.test', 'scanner.example.test')),
				(' https://scanner.example.test:8443 ', ('https://scanner.example.test:8443', 'scanner.example.test:8443')),
				('http://localhost:8000', ('http://localhost:8000', 'localhost:8000'))):
			with self.subTest(raw=raw), override_settings(CVENGINE_PUBLIC_API_URL=raw):
				self.assertEqual(public_url.configured(), want)
				self.assertEqual((public_url.base_url(), public_url.host()), want)

	def test_unset_or_unusable_values_are_ignored(self):
		for raw in ('', '   ', 'scanner.example.test', 'ftp://scanner.example.test', 'https://', 'https://scanner.example.test/mcp/',
				'https://scanner.example.test?x=1', 'https://scanner.example.test#a', 'https://user@scanner.example.test',
				'https://scanner.example.test:99999', 'javascript:alert(1)'):
			with self.subTest(raw=raw), override_settings(CVENGINE_PUBLIC_API_URL=raw):
				self.assertIsNone(public_url.configured())
				self.assertIsNone(public_url.base_url())
				self.assertIsNone(public_url.host())

	def test_the_domain_name_address_is_unchanged(self):
		with mock.patch.dict(os.environ, {'DOMAIN_NAME': 's-abc123.example.test'}):
			self.assertEqual(public_url.domain_base_url(), 'https://s-abc123.example.test')
		with mock.patch.dict(os.environ, {'DOMAIN_NAME': 'localhost'}):
			self.assertEqual(public_url.domain_base_url(), 'http://localhost')


class EnrollmentServerUrlTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		build_world(cls)  # dana is an admin of the organization that holds project sen-a

	def setUp(self):
		reset_rates(self.tokens)

	def enroll(self, query=''):
		status, out = call(self.tokens['dana'], 'POST', f'/api/v1/projects/sen-a/sentinels/enroll{query}')
		self.assertEqual(status, 201, out)
		return out

	def test_the_enrollment_names_the_public_address_when_set(self):
		with mock.patch.dict(os.environ, {'DOMAIN_NAME': 's-abc123.example.test'}), override_settings(CVENGINE_PUBLIC_API_URL=SHARED):
			self.assertEqual(self.enroll()['server_url'], SHARED)

	def test_the_blob_carries_the_same_address(self):
		with mock.patch.dict(os.environ, {'DOMAIN_NAME': 's-abc123.example.test'}), override_settings(CVENGINE_PUBLIC_API_URL=SHARED):
			out = self.enroll('?format=blob&network=external&profile=light')
		self.assertEqual(json.loads(base64.b64decode(out['blob']))['server_url'], SHARED)

	def test_without_it_the_enrollment_keeps_domain_name(self):
		for raw in ('', 'not a url'):
			with self.subTest(raw=raw), mock.patch.dict(os.environ, {'DOMAIN_NAME': 's-abc123.example.test'}), override_settings(CVENGINE_PUBLIC_API_URL=raw):
				self.assertEqual(self.enroll()['server_url'], 'https://s-abc123.example.test')


class MailLinkBaseTests(TestCase):
	def test_the_default_link_base_is_the_public_address_when_set(self):
		from cveFeed import mailer
		from cveFeed.models import SmtpSettings
		cfg = SmtpSettings.current()
		cfg.link_base = ''
		with override_settings(CVENGINE_PUBLIC_API_URL=SHARED + '/', DOMAIN_NAME='s-abc123.example.test'):
			self.assertEqual(mailer.base_url(cfg), SHARED)
		with override_settings(CVENGINE_PUBLIC_API_URL='', DOMAIN_NAME='s-abc123.example.test'):
			self.assertEqual(mailer.base_url(cfg), 'https://s-abc123.example.test')

	def test_a_link_address_set_under_settings_still_wins(self):
		from cveFeed import mailer
		from cveFeed.models import SmtpSettings
		cfg = SmtpSettings.current()
		cfg.link_base = 'https://links.example.test/'
		with override_settings(CVENGINE_PUBLIC_API_URL=SHARED, DOMAIN_NAME='s-abc123.example.test'):
			self.assertEqual(mailer.base_url(cfg), 'https://links.example.test')


class PagesTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.user = User.objects.create_user('pub-user', password='x')
		OrgMembership.objects.create(user=cls.user, org=Org.objects.create(name='P', slug='pub-org'), role='user')

	def test_the_mcp_page_names_the_public_address_when_set(self):
		with override_settings(CVENGINE_PUBLIC_API_URL=SHARED):
			page = client_for(self.user).get('/cve/mcp/', secure=True)
		self.assertEqual(page.context['mcp_url'], f'{SHARED}/mcp/')
		self.assertContains(page, f'{SHARED}/mcp/')
		self.assertNotContains(page, 'testserver/mcp/')

	def test_without_it_the_mcp_page_keeps_the_request_address(self):
		with override_settings(CVENGINE_PUBLIC_API_URL=''):
			page = client_for(self.user).get('/cve/mcp/', secure=True)
		self.assertEqual(page.context['mcp_url'], 'https://testserver/mcp/')

	def test_the_api_keys_and_sentinels_pages_use_the_public_host_when_set(self):
		for path in ('/cve/agents/', '/cve/sentinels/'):
			with self.subTest(path=path):
				with override_settings(CVENGINE_PUBLIC_API_URL=SHARED):
					page = client_for(self.user).get(path, secure=True)
				self.assertEqual((page.context['host'], page.context['api_origin']), ('scanner.example.test', SHARED))
				with override_settings(CVENGINE_PUBLIC_API_URL=''):
					page = client_for(self.user).get(path, secure=True)
				self.assertEqual((page.context['host'], page.context['api_origin']), ('testserver', ''))

	def test_the_api_keys_page_hands_the_public_address_to_the_connect_card(self):
		with override_settings(CVENGINE_PUBLIC_API_URL=SHARED):
			page = client_for(self.user).get('/cve/agents/', secure=True)
		self.assertContains(page, f'data-api-origin="{SHARED}"')
		with override_settings(CVENGINE_PUBLIC_API_URL=''):
			page = client_for(self.user).get('/cve/agents/', secure=True)
		self.assertNotContains(page, 'data-api-origin')
