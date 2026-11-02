"""The scope_mode field on the agent API, and the call that switches it."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from unittest import mock

from agentapi.auth import create_token
from dashboard.models import Org, Project, ProjectMembership
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call


class ScopeApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='S6', slug='scp6')
		cls.project = Project.objects.create(name='P6', slug='scp6', insert_date=timezone.now(), org=org)
		cls.tenant = Domain.objects.create(name='acme.jfrog.com', project=cls.project, insert_date=timezone.now())
		user = User.objects.create_user('scoper', password='x')
		ProjectMembership.objects.create(user=user, project=cls.project, role='user')
		_, cls.token = create_token(user, 'agent')
		_, cls.read_token = create_token(user, 'ro', read_only=True)

	def test_targets_expose_scope_mode_and_host_scoped(self):
		status, data = call(self.token, 'GET', f'/api/v1/projects/scp6/targets/{self.tenant.id}')
		self.assertEqual((status, data['scope_mode'], data['host_scoped']), (200, 'auto', True))

	def test_the_scope_can_be_switched_and_is_validated(self):
		url = f'/api/v1/projects/scp6/targets/{self.tenant.id}/scope'
		status, data = call(self.token, 'POST', url, {'scope_mode': 'parent'})
		self.assertEqual((status, data['scope_mode'], data['host_scoped']), (200, 'parent', False))
		self.tenant.refresh_from_db()
		self.assertEqual(self.tenant.scope_mode, 'parent')
		self.assertEqual(call(self.token, 'POST', url, {'scope_mode': 'everything'})[0], 400)
		self.assertEqual(call(self.token, 'POST', url, {})[0], 400)
		self.assertEqual(call(self.read_token, 'POST', url, {'scope_mode': 'host'})[0], 403)

	@mock.patch('cveFeed.ct_queue.queue_lookups')
	def test_added_names_default_to_exact_host_but_allow_explicit_expansion(self, queue):
		url = '/api/v1/projects/scp6/targets'
		status, data = call(self.token, 'POST', url, {'value': 'example.test'})
		self.assertEqual((status, data['created'][0]['scope_mode'], data['created'][0]['host_scoped']), (201, 'host', True))
		status, data = call(self.token, 'POST', url, {'value': 'wide.example.test', 'scope_mode': 'parent'})
		self.assertEqual((status, data['created'][0]['scope_mode'], data['created'][0]['host_scoped']), (201, 'parent', False))
		status, data = call(self.token, 'POST', url, {'value': 'wide.example.test', 'scope_mode': 'host'})
		self.assertEqual((status, data['already_exists']), (201, ['wide.example.test']))
		self.assertEqual(Domain.objects.get(name='wide.example.test').scope_mode, 'parent')
		self.assertEqual(call(self.token, 'POST', url, {'value': 'bad.example.test', 'scope_mode': 'wider'})[0], 400)
		self.assertFalse(Domain.objects.filter(name='bad.example.test').exists())

	@mock.patch('cveFeed.ct_queue.queue_lookups')
	def test_bulk_scope_defaults_to_exact_and_validates_before_exclusions(self, queue):
		url = '/api/v1/projects/scp6/targets/bulk'
		status, data = call(self.token, 'POST', url, {'text': 'a.example.test\n203.0.113.7', 'discover': False})
		self.assertEqual((status, data['created']), (201, 2))
		self.assertEqual(Domain.objects.get(name='a.example.test').scope_mode, 'host')
		status, _ = call(self.token, 'POST', url, {'text': 'b.example.test', 'discover': False, 'scope_mode': 'parent'})
		self.assertEqual(status, 201)
		self.assertEqual(Domain.objects.get(name='b.example.test').scope_mode, 'parent')
		self.assertEqual(call(self.token, 'POST', url, {'text': '-a.example.test', 'scope_mode': 'bad'})[0], 400)
		self.assertTrue(Domain.objects.filter(name='a.example.test').exists())

	@mock.patch('cveFeed.ct_queue.queue_lookups')
	def test_org_bulk_and_mcp_respect_scope_without_changing_existing_targets(self, queue):
		status, data = call(self.token, 'POST', '/api/v1/targets/bulk-org',
			{'text': '#P6\norg.example.test', 'current_project': 'scp6', 'discover': False})
		self.assertEqual((status, data['created']), (201, 1))
		self.assertEqual(Domain.objects.get(name='org.example.test').scope_mode, 'host')
		status, _ = call(self.token, 'POST', '/api/v1/targets/bulk-org',
			{'text': '#P6\nwide-org.example.test', 'current_project': 'scp6', 'discover': False, 'scope_mode': 'parent'})
		self.assertEqual(status, 201)
		self.assertEqual(Domain.objects.get(name='wide-org.example.test').scope_mode, 'parent')
		self.assertEqual(call(self.token, 'POST', '/api/v1/targets/bulk-org',
			{'text': '#P6\ninvalid-org.example.test', 'current_project': 'scp6', 'scope_mode': 'anything'})[0], 400)
		self.assertFalse(Domain.objects.filter(name='invalid-org.example.test').exists())
		failed, data = tool_call(self.token, 'add_target', {'project': 'scp6', 'value': 'via-mcp.example.test'})
		self.assertFalse(failed)
		self.assertEqual(data['created'][0]['scope_mode'], 'host')
		failed, data = tool_call(self.token, 'add_targets',
			{'project': 'scp6', 'targets': ['via-bulk-mcp.example.test'], 'scope_mode': 'parent', 'discover': False})
		self.assertFalse(failed)
		self.assertEqual(Domain.objects.get(name='via-bulk-mcp.example.test').scope_mode, 'parent')
		failed, data = tool_call(self.token, 'add_targets_by_org',
			{'text': '#P6\nvia-org-mcp.example.test', 'current_project': 'scp6', 'discover': False})
		self.assertFalse(failed)
		self.assertEqual(Domain.objects.get(name='via-org-mcp.example.test').scope_mode, 'host')
