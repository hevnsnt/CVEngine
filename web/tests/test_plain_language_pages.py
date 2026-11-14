import re

from django.contrib.auth.models import User
from django.test import TestCase

from tests.test_tenancy import client_for


def closed_details(html):
	"""The text of every closed <details> block of a page (these pages do not nest them)."""
	return ' '.join(m.group(1) for m in re.finditer(r'<details(?![^>]*\bopen\b)[^>]*>(.*?)</details>', html, re.S))


def outside_details(html):
	"""The page without its <details> blocks and without script and style: what a person reads without opening anything."""
	html = re.sub(r'<details[^>]*>.*?</details>', ' ', html, flags=re.S)
	return re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', html, flags=re.S)


class PlainLanguagePagesTests(TestCase):
	"""Pages for people who never use a command line: developer and operator text sits behind a closed Details disclosure."""

	def get(self, path, **flags):
		user = User.objects.filter(username='reader').first() or User.objects.create_user('reader', password='x', **flags)
		return client_for(user).get(path).content.decode()

	def test_about_page_keeps_compose_and_gmp_lines_behind_a_closed_disclosure(self):
		html = self.get('/cve/about/')
		self.assertIn('COMPOSE_PROFILES=openvas', closed_details(html))
		self.assertIn('python-gvm', closed_details(html))
		self.assertNotIn('COMPOSE_PROFILES', outside_details(html))
		self.assertNotIn('python-gvm', outside_details(html))
		# the credits stay: the names are still on the page
		for name in ('gvmd', 'ospd-openvas', 'openvas-scanner', 'pg-gvm', 'Greenbone feed'):
			self.assertIn(name, html)

	def test_sentinel_provisioning_page_keeps_the_blob_and_endpoint_text_behind_a_closed_disclosure(self):
		html = self.get('/cve/sentinels/', is_superuser=True)
		for word in ('base64', 'bootstrap', 'sentinel/heartbeat'):
			self.assertIn(word, closed_details(html), word)
			self.assertNotIn(word, outside_details(html), word)
		self.assertIn('For developers and integrators', html)
