import re
from pathlib import Path

from django.contrib.auth.models import User
from django.test import TestCase

from tests.test_tenancy import client_for

ROOT = Path(__file__).resolve().parents[2]


class AboutPageTests(TestCase):
	def page(self):
		return client_for(User.objects.create_user('reader', password='x')).get('/cve/about/')

	def test_page_opens_for_any_signed_in_user_and_shows_the_version(self):
		from django.conf import settings
		r = self.page()
		self.assertContains(r, 'About CVEngine')
		self.assertContains(r, settings.RENGINE_CURRENT_VERSION)

	def test_page_credits_every_tool_the_image_pins_and_the_optional_ones(self):
		# the pinned tools (web/Dockerfile) and the optional add-ons must not go missing from the credits page again
		html = self.page().content.decode()
		for name in ('bbot', 'nuclei', 'naabu', 'nmap', 'testssl.sh', 'WPScan', 'wafw00f', 'gowitness', 'Greenbone', 'Tailscale',
		             'cvengine-sentinel', 'VulnCheck', 'runZero', 'LM Studio'):
			self.assertIn(name, html, f'{name} is not on the About page')

	def test_every_tool_in_the_third_party_list_has_its_link_on_the_page(self):
		# THIRD-PARTY.md is the license record; the About page carries the same scanners with the same project links
		listed = (ROOT / 'THIRD-PARTY.md').read_text().split('## Scanners and tools', 1)[1].split('## Data sources', 1)[0]
		html = self.page().content.decode()
		missing = []
		for row in listed.splitlines():
			match = re.match(r'\| \[([^\]]+)\]\((https://github\.com/[^)]+)\)', row)
			# the Greenbone parts are one entry on the page, nuclei's templates sit in nuclei's row and nmap links its own site
			if match and not any(skip in match.group(1) for skip in ('gvmd', 'ospd', 'openvas-scanner', 'pg-gvm', 'python-gvm', 'nuclei-templates', 'nmap')) \
					and match.group(2).lower() not in html.lower():
				missing.append(match.group(1))
		self.assertEqual(missing, [], f'on THIRD-PARTY.md but not on the About page: {missing}')
