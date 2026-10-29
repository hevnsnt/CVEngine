"""Requests do no per-request bookkeeping nothing reads: no UserPreferences row is made, and pages still render."""
from django.contrib.auth.models import User
from django.test import TestCase

from dashboard.models import UserPreferences
from tests.test_tenancy import client_for


class RequestOverheadTests(TestCase):
	def test_a_page_request_does_not_create_a_preferences_row_and_the_page_renders(self):
		user = User.objects.create_superuser('overhead', password='x')
		response = client_for(user).get('/cve/about/')
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'Version')  # the version context processor is still there
		self.assertFalse(UserPreferences.objects.filter(user=user).exists())
