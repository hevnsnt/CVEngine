from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import DEFAULT_SLA_DAYS, ProjectSettings
from dashboard.models import Org, Project, ProjectMembership
from tests.test_agentapi import call, tool_call

NOW = timezone.now()


class ProjectSettingsTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='PS', slug='ps-org')
		cls.pa = Project.objects.create(name='A', slug='ps-a', insert_date=NOW, org=org)
		cls.pb = Project.objects.create(name='B', slug='ps-b', insert_date=NOW, org=org)
		cls.alice, cls.carol = User.objects.create_user('ps-alice', password='x'), User.objects.create_user('ps-carol', password='x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=cls.carol, project=cls.pa, role='audit')
		_, cls.token = create_token(cls.alice, 'ps')
		_, cls.ro = create_token(cls.alice, 'ps-ro', read_only=True)
		_, cls.audit = create_token(cls.carol, 'ps-audit')

	url = '/api/v1/projects/ps-a/settings'

	def test_a_project_without_a_row_reads_the_defaults(self):
		status, data = call(self.token, 'GET', self.url)
		self.assertEqual(status, 200)
		self.assertEqual(data['sla_days'], {'critical': 7, 'high': 30, 'medium': 90, 'low': 180})
		self.assertEqual(data['sla_defaults'], DEFAULT_SLA_DAYS)
		self.assertFalse(ProjectSettings.objects.exists())  # reading creates nothing

	def test_put_is_a_partial_update_and_null_restores_a_default(self):
		status, data = call(self.token, 'PUT', self.url, {'sla_days': {'critical': 3, 'low': 365}})
		self.assertEqual((status, data['sla_days']), (200, {'critical': 3, 'high': 30, 'medium': 90, 'low': 365}))
		status, data = call(self.token, 'PUT', self.url, {'sla_days': {'high': 14}})
		self.assertEqual(data['sla_days'], {'critical': 3, 'high': 14, 'medium': 90, 'low': 365})
		status, data = call(self.token, 'PUT', self.url, {'sla_days': {'critical': None}})
		self.assertEqual(data['sla_days']['critical'], 7)
		self.assertEqual(call(self.token, 'GET', self.url)[1]['sla_days'], {'critical': 7, 'high': 14, 'medium': 90, 'low': 365})
		self.assertEqual(ProjectSettings.objects.get(project=self.pa).updated_by, self.alice)

	def test_one_projects_settings_never_leak_into_another(self):
		call(self.token, 'PUT', self.url, {'sla_days': {'critical': 1}})
		self.assertEqual(ProjectSettings.sla_for(self.pb)['critical'], 7)

	def test_bad_values_are_400_and_change_nothing(self):
		for body in ({}, {'sla_days': {}}, {'sla_days': []}, {'sla_days': {'info': 5}}, {'sla_days': {'high': 0}},
		             {'sla_days': {'high': 3651}}, {'sla_days': {'high': 'soon'}}, {'sla_days': {'high': 1.5}}, {'sla_days': {'high': True}},
		             {'sla_days': {'critical': 2, 'high': -1}}):
			self.assertEqual(call(self.token, 'PUT', self.url, body)[0], 400, body)
		self.assertEqual(call(self.token, 'GET', self.url)[1]['sla_days'], DEFAULT_SLA_DAYS)

	def test_writes_are_gated_like_every_other_write(self):
		body = {'sla_days': {'critical': 2}}
		self.assertEqual(call(self.ro, 'PUT', self.url, body)[0], 403)
		self.assertEqual(call(self.audit, 'PUT', self.url, body)[0], 403)
		self.assertEqual(call(self.audit, 'GET', self.url)[0], 200)  # but the audit role can read them
		self.assertEqual(call(self.token, 'GET', self.url.replace('ps-a', 'ps-b'))[0], 404)  # not a member
		self.assertEqual(call(self.token, 'PUT', '/api/v1/projects/_all/settings', body)[0], 400)
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/_all/settings')[0], 400)
		self.assertEqual(call(self.token, 'GET', self.url)[1]['sla_days'], DEFAULT_SLA_DAYS)

	def test_mcp_get_and_set(self):
		is_error, data = tool_call(self.token, 'set_project_settings', {'project': 'ps-a', 'sla_days': {'medium': 60}})
		self.assertEqual((is_error, data['sla_days']['medium']), (False, 60))
		self.assertEqual(tool_call(self.token, 'get_project_settings', {'project': 'ps-a'})[1]['sla_days']['medium'], 60)
