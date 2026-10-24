from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Org, Project, ProjectMembership
from tests.test_tenancy import client_for


class DashboardScrollbackTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='One', slug='one')
		cls.pa = Project.objects.create(name='A', slug='act-a', insert_date=timezone.now(), org=org)
		cls.alice = User.objects.create_user('act-alice', password='x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')

	def test_dashboard_links_to_full_pages(self):
		page = client_for(self.alice).get('/cve/')
		self.assertContains(page, '/cve/act-a/activity/')
		self.assertContains(page, '/cve/act-a/vulns/')
