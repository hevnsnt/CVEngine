from django.contrib.auth.models import User
from django.test import TestCase

from dashboard.models import Org, OrgMembership
from tests.test_tenancy import client_for


class AgentsPageSchemeTests(TestCase):
	"""The copy-paste snippets carry a bearer token, so they must use the scheme the page itself was served over."""

	def setUp(self):
		self.user = User.objects.create_user('schemeuser', password='x')
		OrgMembership.objects.create(user=self.user, org=Org.objects.create(name='S', slug='s'), role='user')

	def test_snippets_follow_the_request_scheme(self):
		page = client_for(self.user).get('/cve/agents/', secure=True)
		self.assertContains(page, 'https://testserver/mcp/')
		self.assertContains(page, 'https://testserver/api/v1/me')
		self.assertNotContains(page, 'http://testserver/')
