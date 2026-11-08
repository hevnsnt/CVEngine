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

	def test_page_names_its_contributors(self):
		html = self.page().content.decode()
		self.assertIn('Contributors', html)
		self.assertIn('https://github.com/camstork', html)

	def test_page_credits_every_tool_the_image_pins_and_the_optional_ones(self):
		# the pinned tools (web/Dockerfile) and the optional add-ons must not go missing from the credits page again
		html = self.page().content.decode()
		for name in ('bbot', 'nuclei', 'naabu', 'nmap', 'testssl.sh', 'WPScan', 'wafw00f', 'gowitness', 'Greenbone', 'Tailscale',
		             'cvengine-sentinel', 'VulnCheck', 'runZero', 'LM Studio', 'sshamble', 'Kingfisher', 'Playwright', 'Chromium',
		             'badkeys', 'aardwolf', 'node2shell', 'PostgreSQL', 'Redis', 'nginx', 'WeasyPrint', 'openvas-scanner', 'gvmd', 'ospd-openvas', 'pg-gvm', 'Greenbone feed'):
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



# ---- the software list: every tool the images pin is on the page, at the version pinned ----------------------------------------------------------

def _tool_versions_module():
	import importlib.util
	spec = importlib.util.spec_from_file_location('check_tool_versions', ROOT / 'scripts' / 'check_tool_versions.py')
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def _sentinel_files():
	"""The Sentinel repository's Dockerfile and requirements.txt: the directory named by CVENGINE_SENTINEL_FILES (CI fetches them at the pinned commit),
	else the checkout the library is imported from. None when neither is here."""
	import os
	import cvengine_scanner
	for candidate in (os.environ.get('CVENGINE_SENTINEL_FILES'), str(Path(cvengine_scanner.__file__).resolve().parent.parent)):
		if candidate and (Path(candidate) / 'Dockerfile').is_file() and (Path(candidate) / 'requirements.txt').is_file():
			return Path(candidate)
	return None


class SoftwareListTests(TestCase):
	def page(self):
		return AboutPageTests.page(self)

	def test_every_tool_and_version_of_the_list_is_on_the_page(self):
		from cveFeed import software
		html = self.page().content.decode()
		missing = []
		for group in software.tools_by_group():
			for item in group['items']:
				if item['name'].replace('&', '&amp;') not in html and item['name'] not in html:
					missing.append(item['name'])
				if item['shown'] and item['shown'] not in html:
					missing.append(f"{item['name']} {item['shown']}")
		self.assertEqual(missing, [])
		for name, version, _ in software.server_libraries():
			# the name and its pinned version sit in one row of the inventory table
			self.assertRegex(html, rf'>{re.escape(name)}</a></th>\s*<td[^>]*>{re.escape(version)}</td>', f'{name} {version} is pinned in web/requirements.txt and missing from the page')
		for source in software.DATA_SOURCES + software.AI_PROVIDERS:
			self.assertIn(source['url'], html)

	def test_the_version_written_in_the_list_is_the_one_the_pin_holds(self):
		# the page reads the pin when it can; the written version is the fallback, so a bump of a pin must change both
		from cveFeed import software
		pins = _tool_versions_module().pinned
		sentinel = _sentinel_files()
		wrong = []
		for item in software.TOOLS:
			for path, pattern in item['pins']:
				if path.startswith('sentinel:'):
					if sentinel is None:
						continue
					text = (sentinel / path.split(':', 1)[1]).read_text(encoding='utf-8')
					found = re.search(pattern, text)
					found = found.group(1) if found else None
				else:
					found = pins(path, pattern)
				if found != item['version']:
					wrong.append(f"{item['name']}: {path} pins {found}, the list says {item['version']}")
		self.assertEqual(wrong, [])

	def _args(self, text):
		return re.findall(r'(?m)^ARG ([A-Z0-9_]+)=', text)

	def _uncovered(self, dockerfile_key, text):
		from cveFeed import software
		covered = ' '.join(pattern for item in software.TOOLS for path, pattern in item['pins'] if path == dockerfile_key)
		# checksums and the toolchain's per-architecture hashes are not tools of their own
		return [name for name in self._args(text) if not re.search(r'_SHA256|^TZDATA_VERSION$|^PYSOCKS_VERSION$|^NUCLEI_TEMPLATES_SHA', name) and f'ARG {name}=' not in covered]

	def test_a_tool_pinned_in_the_server_image_is_on_the_list(self):
		self.assertEqual(self._uncovered('web/Dockerfile', (ROOT / 'web' / 'Dockerfile').read_text()), [])

	def test_a_tool_pinned_in_the_sentinel_image_is_on_the_list(self):
		import os
		sentinel = _sentinel_files()
		if sentinel is None:
			if os.environ.get('CVENGINE_REQUIRE_SENTINEL_FILES') == '1':
				self.fail('the Sentinel Dockerfile is required here (CVENGINE_REQUIRE_SENTINEL_FILES=1) and was not found')
			self.skipTest('no Sentinel checkout or CVENGINE_SENTINEL_FILES: the Sentinel Dockerfile cannot be read')
		self.assertEqual(self._uncovered('sentinel:Dockerfile', (sentinel / 'Dockerfile').read_text()), [])
		# every ==pin of its requirements.txt is a library the page names (playwright and aardwolf are tools of their own)
		listed = {name.lower() for name, _, _ in __import__('cveFeed.software', fromlist=['x']).SENTINEL_LIBRARIES}
		listed |= {name.lower() for name, _, _ in __import__('cveFeed.software', fromlist=['x']).server_libraries()}
		for line in (sentinel / 'requirements.txt').read_text().splitlines():
			match = re.match(r'([A-Za-z0-9_.-]+)(==|>=)', line.split('#')[0].strip())
			if match:
				self.assertIn(match.group(1).lower(), listed, f'{match.group(1)} is in the Sentinel requirements.txt and not on the About page')

	def test_the_list_was_read_at_the_sentinel_commit_the_server_pins(self):
		import json
		from cveFeed import software
		lock = json.loads((ROOT / 'scanner.lock.json').read_text())['source']['commit']
		requirements = (ROOT / 'web' / 'requirements.txt').read_text()
		self.assertEqual(software.SENTINEL_PINS_COMMIT, lock, 'scanner.lock.json moved: read the Sentinel pins again and update cveFeed/software.py')
		self.assertIn(f'cvENGINE-sentinel@{lock}', requirements)

	def test_the_greenbone_images_of_the_compose_file_are_on_the_list(self):
		from cveFeed import software
		names = ' '.join(t['name'] for t in software.TOOLS)
		for service in re.findall(r'(?m)^  openvas-([a-z-]+):$', (ROOT / 'docker-compose.yml').read_text()):
			image = re.search(rf'(?ms)^  openvas-{service}:.*?image: "registry\.community\.greenbone\.net/community/([a-z-]+):', (ROOT / 'docker-compose.yml').read_text())
			self.assertIsNotNone(image, service)
			part = image.group(1)
			self.assertTrue(part in names or part in ' '.join(t['name'] for t in software.TOOLS if t['group'] == 'greenbone') or
			                part in ('vulnerability-tests', 'notus-data', 'scap-data', 'cert-bund-data', 'dfn-cert-data', 'data-objects', 'report-formats', 'gpg-data', 'redis-server', 'pg-gvm-migrator'),
			                f'the Greenbone image {part} is not on the About page list')


# ---- the page's shape: order, the reNgine credit last, a complete inventory, no scanner banner -------------------------------------------------------

RENGINE_TEXT = ("CVEngine is a fork of reNgine 2.x by Yogesh Ojha, and still uses its code. Thanks to everyone who built it, including "
                "Aju100, d1pakda5, subha7595, Suprita-25, TheBinitGhimire, Vinay Leo and Erdem Ozgen. "
                "The full list is on reNgine's contributors page.")


def _text(fragment):
	import html as htmllib
	return re.sub(r'\s+', ' ', htmllib.unescape(re.sub(r'<[^>]+>', '', fragment))).strip()


class AboutPageShapeTests(TestCase):
	def page(self):
		return AboutPageTests.page(self)

	def main(self):
		html = self.page().content.decode()
		return html.split('<main', 1)[1].split('</main>', 1)[0]

	def test_sections_come_in_the_planned_order(self):
		ids = re.findall(r'<section[^>]*\bid="([^"]+)"', self.main())
		self.assertEqual(ids, ['product', 'where', 'software', 'sources', 'licenses', 'contributors', 'built-on-rengine'])

	def test_the_rengine_credit_is_the_last_element_of_the_page_with_its_text_unchanged(self):
		main = self.main()
		last = re.findall(r'<section[^>]*\bid="([^"]+)"[^>]*>(.*?)</section>', main, flags=re.S)[-1]
		self.assertEqual(last[0], 'built-on-rengine')
		self.assertEqual(re.findall(r'<h2[^>]*>(.*?)</h2>', last[1], flags=re.S), ['Built on reNgine'])
		self.assertEqual(_text(re.sub(r'<h2[^>]*>.*?</h2>', '', last[1], flags=re.S)), RENGINE_TEXT)
		# the last heading of the page is that one, and after its section nothing but closing tags is left in <main>
		self.assertEqual(_text(re.findall(r'<h2[^>]*>(.*?)</h2>', main, flags=re.S)[-1]), 'Built on reNgine')
		tail = main.rsplit('</section>', 1)[1]
		self.assertEqual(re.sub(r'</div>|\s', '', tail), '')
		self.assertEqual(main.count('fork of'), 1)  # the credit appears once, and nowhere earlier

	def test_the_product_card_links_the_repository_once(self):
		card = self.main().split('id="product"', 1)[1].split('</section>', 1)[0]
		self.assertEqual(card.count('github.com/hevnsnt/CVEngine"'), 1)
		for label in ('Made by', 'Created by', 'Source code', 'Version', 'License'):
			self.assertIn(f'<dt>{label}</dt>', card)

	def test_about_shows_no_scanner_status_banner_but_other_pages_still_do(self):
		loaded = r'<script type="module" src="[^"]*scannerbar\.js'  # the import map names every module; only a script tag loads one
		self.assertIsNone(re.search(loaded, self.page().content.decode()))
		user = User.objects.get(username='reader') if User.objects.filter(username='reader').exists() else User.objects.create_user('reader', password='x')
		other = client_for(user).get('/cve/how-it-works/').content.decode()
		self.assertIsNotNone(re.search(loaded, other))

	def test_no_short_string_of_the_inventory_ends_in_a_period(self):
		from cveFeed import software
		for group in software.inventory():
			for r in group['rows']:
				for key in ('purpose', 'license', 'detail'):
					self.assertFalse(r[key].endswith('.'), f"{r['name']} {key}: {r[key]!r}")


class InventoryRowTests(TestCase):
	"""Every row the page shows says what it is for and under which license, or says plainly that it does not know."""

	def test_every_row_has_a_name_link_version_license_and_purpose(self):
		from cveFeed import software
		groups = software.inventory()
		self.assertGreater(sum(g['count'] for g in groups), 40)
		for group in groups:
			self.assertEqual(group['count'], len(group['rows']))
			for r in group['rows']:
				for key in ('name', 'url', 'version', 'license', 'purpose', 'where'):
					self.assertTrue(r.get(key), f"{group['id']}: {r.get('name')!r} has no {key}")
				self.assertTrue(r['url'].startswith('https://'), r['name'])

	def test_the_source_list_itself_states_a_license_and_a_purpose_for_every_tool(self):
		from cveFeed import software
		for item in software.TOOLS:
			self.assertTrue(item['license'].strip(), f"{item['name']} has no license: write 'Unknown (why)' when it is not known")
			self.assertTrue(item['purpose'].strip(), f"{item['name']} has no purpose")
		for source in software.DATA_SOURCES + software.AI_PROVIDERS:
			self.assertTrue(source['purpose'].strip(), source['name'])

	def test_an_unknown_license_or_purpose_is_marked_unknown_not_left_blank(self):
		from cveFeed import software
		r = software.row('x', 'https://example.com', '', '', '', 'server')
		self.assertEqual((r['license'], r['purpose'], r['version']), (software.NOT_STATED, 'Not stated', software.NOT_PINNED))

	def test_a_license_note_moves_below_the_license_and_a_purpose_detail_below_the_purpose(self):
		from cveFeed import software
		r = software.row('x', 'https://example.com', '1', 'GPL-2.0 (a separate program, never linked)', 'Does a thing. It also does `more`.', 'both')
		self.assertEqual((r['license'], r['license_note'], r['purpose'], r['detail'], r['where']), ('GPL-2.0', 'a separate program, never linked', 'Does a thing', 'It also does more', 'Both'))

	def test_the_page_stylesheet_keeps_tables_from_widening_the_page(self):
		css = (Path(__file__).resolve().parents[1] / 'static' / 'cve' / 'cve.css').read_text()
		for needle in ('.about{min-width:0}', 'table-layout:fixed', 'overflow-wrap:anywhere', '@container (max-width:759px)'):
			self.assertIn(needle, css)
