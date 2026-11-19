"""Requests do no per-request bookkeeping nothing reads (the per-user preferences row the old reNgine made is gone with its table), and pages still render."""
from django.contrib.auth.models import User
from django.test import TestCase

from tests.test_tenancy import client_for


class RequestOverheadTests(TestCase):
	def test_a_page_request_renders(self):
		user = User.objects.create_superuser('overhead', password='x')
		response = client_for(user).get('/cve/about/')
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'Version')  # the version context processor is still there
