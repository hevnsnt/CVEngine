import re
from pathlib import Path

from django.contrib.auth.models import User
from django.test import TestCase

from tests.test_tenancy import client_for

ROOT = Path(__file__).resolve().parents[2]


class AboutPageTests(TestCase):
	def page(self):
		user = User.objects.filter(username='reader').first() or User.objects.create_user('reader', password='x')
		return client_for(user).get('/cve/about/')

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

	def test_a_named_release_shows_its_edition_beside_the_version(self):
		from django.test import override_settings
		with override_settings(RENGINE_EDITION='camstork edition'):
			self.assertContains(self.page(), ', camstork edition')
		with override_settings(RENGINE_EDITION=''):
			self.assertNotContains(self.page(), 'edition')

	def test_only_a_plain_name_is_accepted_as_an_edition(self):
		# reNgine/settings.py reads .edition with this pattern: letters, digits, spaces, dots and hyphens, at most 40 characters
		pattern = re.compile(r'[A-Za-z0-9][A-Za-z0-9 .-]{0,39}')
		for good in ('camstork edition', 'Winter 2026'):
			self.assertTrue(pattern.fullmatch(good))
		for bad in ('', '<script>', 'x' * 60, '-leading'):
			self.assertFalse(pattern.fullmatch(bad))

	def test_a_changelog_edition_line_is_one_the_release_workflow_can_read(self):
		# release.yml puts "<!-- edition: NAME -->" from a release's section in the release title: the line must have the shape its sed reads
		text = (ROOT / 'CHANGELOG.md').read_text()
		for line in re.findall(r'^<!-- edition: .* -->$', text, flags=re.M):
			self.assertRegex(line, r'^<!-- edition: [A-Za-z0-9][A-Za-z0-9 .-]{0,39} -->$')

