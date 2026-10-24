"""The scope_mode field on the agent API, and the call that switches it."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from dashboard.models import Org, Project, ProjectMembership
from targetApp.models import Domain
from tests.test_agentapi import call


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
