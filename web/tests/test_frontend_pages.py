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
		# the commands are built in the browser from the address the page was loaded from (window.location.origin), so the scheme and
		# host are the page's own; the server no longer writes any address into the page (test_connect_card.mjs checks the https case)
		from pathlib import Path
		page = client_for(self.user).get('/cve/agents/', secure=True)
		self.assertNotContains(page, 'http://testserver/')
		static = Path(__file__).resolve().parents[1] / 'static' / 'cve'
		self.assertIn('createCard(window.location.origin)', (static / 'api-keys-page.js').read_text())
