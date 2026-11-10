"""The left menu after Hygiene and Suppliers came back: every link opens, appears once and has a name, and exactly one entry (or none,
on a utility page) is current. The rule is documented in docs/FRONTEND.md."""
import re

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import nav
from dashboard.models import Org, Project, UserProfile, ProjectMembership
from tests.test_tenancy import client_for


def menu(html):
	"""[(label, href, current)] of the rail entries, in order."""
	block = html[html.index('aria-label="Sections"'):html.index('<details class="acct">')]
	return [(m.group(1), m.group(2), 'aria-current="page"' in m.group(0)) for m in re.finditer(r'<a data-nav="([^"]+)" href="([^"]+)"[^>]*>', block)]


def account(html):
	"""(summary is current, [labels of the current account-menu items])"""
	block = html[html.index('<details class="acct">'):html.index('</aside>')]
	summary = re.search(r'<summary[^>]*>', block).group(0)
	items = [m.group(1) for m in re.finditer(r'<a data-nav="([^"]+)"[^>]*aria-current="page"', block)]
	return 'aria-current="page"' in summary, items


class MenuTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='Org', slug='org')
		cls.proj = Project.objects.create(name='Alpha', slug='alpha', insert_date=now, org=org)
		cls.root = User.objects.create_superuser('nav-root', 'root@example.test', 'pw-12345-long')
		cls.pentester = User.objects.create_user('nav-pentester', password='x')
		ProjectMembership.objects.create(user=cls.pentester, project=cls.proj, role='pentester')
		UserProfile.objects.update_or_create(user=cls.pentester, defaults={'bugbounty_enabled': True})

	def page(self, path, user=None):
		r = client_for(user or self.root).get(path)
		self.assertEqual(r.status_code, 200, (path, r.status_code))
		return r.content.decode()

	def test_the_menu_order_and_labels(self):
		self.assertEqual([l for l, _, _ in menu(self.page('/cve/alpha/hosts/'))],
						['Overview', 'Findings', 'Hygiene', 'Assets', 'Suppliers', 'Scans', 'Scanners', 'Bug bounty'])

	def test_every_link_opens_appears_once_and_has_a_name(self):
		html = self.page('/cve/alpha/hosts/')
		entries = menu(html)
		self.assertEqual(len({l for l, _, _ in entries}), len(entries))
		self.assertEqual(len({h for _, h, _ in entries}), len(entries))
		block = html[html.index('aria-label="Sections"'):html.index('<details class="acct">')]
		for label, href, _ in entries:
			self.assertTrue(label.strip())
			if label != 'Overview':  # a first-run App Admin is sent to the setup wizard from here
				self.assertEqual(client_for(self.root).get(href).status_code, 200, (label, href))
		# the visible text of each link is its accessible name (no aria-label that hides it), and its icon is hidden from the name
		for m in re.finditer(r'<a data-nav="([^"]+)"[^>]*>(.*?)</a>', block, re.S):
			self.assertNotIn('aria-label', m.group(0).split('>')[0], m.group(1))
			self.assertEqual(re.sub(r'<[^>]+>', '', m.group(2)).strip(), m.group(1))
		self.assertEqual(re.findall(r'data-nav="Hygiene"', html).count('data-nav="Hygiene"'), 1)

	def test_hygiene_and_suppliers_keep_their_original_icons_and_have_no_badge(self):
		html = self.page('/cve/alpha/hosts/')
		self.assertRegex(html, r'data-nav="Hygiene"[^>]*><svg[^>]*><use href="#i-shield"/></svg>Hygiene</a>')
		self.assertRegex(html, r'data-nav="Suppliers"[^>]*><svg[^>]*><use href="#i-building"/></svg>Suppliers</a>')
		self.assertEqual((nav.SECTION_ICON['hygiene'], nav.SECTION_ICON['suppliers']), ('shield', 'building'))

	def test_one_entry_is_current_on_a_page_of_the_work(self):
		expected = {
			'/cve/alpha/vulns/': 'Findings', '/cve/alpha/matches/': 'Findings', '/cve/alpha/changes/': 'Findings', '/cve/cves/': 'Findings',
			'/cve/alpha/hygiene/': 'Hygiene',  # the page's own entry wins; Findings is not also current
			'/cve/alpha/hosts/': 'Assets', '/cve/alpha/targets/': 'Assets', '/cve/alpha/secrets/': 'Assets', '/cve/graph/': 'Assets',
			'/cve/alpha/suppliers/': 'Suppliers',  # likewise: Assets is not also current
			'/cve/alpha/scans/': 'Scans', '/cve/alpha/activity/': 'Scans',
			'/cve/scanners/': 'Scanners', '/cve/sentinels/': 'Scanners',
		}
		self.assertGreaterEqual(len(expected), 12)
		for path, label in expected.items():
			current = [l for l, _, c in menu(self.page(path)) if c]
			self.assertEqual(current, [label], path)

	def test_bug_bounty_is_current_on_its_page(self):
		self.assertEqual([l for l, _, c in menu(self.page('/cve/bounty/', self.pentester)) if c], ['Bug bounty'])

	def test_no_entry_is_current_on_a_utility_page_the_account_is(self):
		for path, item in (('/cve/admin/', 'Administration'), ('/cve/settings/', 'Settings'), ('/cve/about/', 'Help'), ('/cve/account/', 'My account'),
						  ('/cve/agents/', 'API keys')):
			html = self.page(path)
			self.assertEqual([l for l, _, c in menu(html) if c], [], path)
			self.assertEqual(account(html), (True, [item]), path)
			self.assertIn('id="acct-btn"', html)
			self.assertRegex(html, r'id="acct-btn"[^>]*aria-current="page"')

	def test_a_page_of_the_work_does_not_mark_the_account(self):
		html = self.page('/cve/alpha/hygiene/')
		self.assertEqual(account(html), (False, []))
		self.assertNotRegex(html, r'id="acct-btn"[^>]*aria-current')

	def test_the_phone_sheet_offers_the_four_entries_the_bar_does_not_and_marks_the_current_one(self):
		html = self.page('/cve/alpha/suppliers/')
		bar = html[html.index('class="tabbar"'):html.index('id="more-btn"')]
		self.assertEqual(re.findall(r'</svg>([^<]+)</a>', bar), ['Overview', 'Findings', 'Assets', 'Scans'])
		self.assertNotRegex(bar, r'aria-current="page"[^>]*><svg[^>]*><use href="#i-server"')  # Assets is not current on Suppliers
		sheet = html[html.index('id="sheet"'):html.index('id="acct-sheet"')]
		self.assertEqual(re.findall(r'</svg>([^<]+)</a>', sheet)[:4], ['Hygiene', 'Suppliers', 'Scanners', 'Bug bounty'])
		self.assertRegex(sheet, r'aria-current="page"><svg[^>]*><use href="#i-building"/></svg>Suppliers')
		self.assertRegex(html, r'id="more-btn"[^>]*aria-current="page"')  # the bar shows where you are: More holds the current entry
		self.assertNotRegex(self.page('/cve/alpha/hosts/'), r'id="more-btn"[^>]*aria-current')

	def test_the_tab_strip_of_a_page_with_its_own_entry_is_named_for_its_family(self):
		html = self.page('/cve/alpha/hygiene/')
		self.assertIn('aria-label="Findings pages"', html)
		self.assertRegex(html, r'<a href="[^"]+" aria-current="page">Config checks</a>')

	def test_without_a_project_the_menu_leaves_out_what_needs_one(self):
		out = nav.build('about', None, bounty_enabled=False, sentinels_enabled=False)
		self.assertEqual([e['label'] for e in out['rail']], ['Overview', 'Assets', 'Scanners'])


class RuleTests(SimpleTestCase):
	def test_every_page_name_is_in_exactly_one_place(self):
		for page in nav.GROUP_OF:
			self.assertNotIn(page, nav.UTILITY)
		for page, entry in nav.OWN_ENTRY.items():
			self.assertIn(entry, nav.SECTION_ICON)
			self.assertEqual(nav.build(page, 'alpha', bounty_enabled=True, sentinels_enabled=False)['current'], entry)

	def test_the_current_entry_is_unique_for_every_known_page(self):
		for page in list(nav.GROUP_OF) + list(nav.UTILITY):
			out = nav.build(page, 'alpha', bounty_enabled=True, sentinels_enabled=True)
			self.assertLessEqual(sum(e['current'] for e in out['rail']), 1, page)
			if page in nav.UTILITY:
				self.assertEqual(sum(e['current'] for e in out['rail']), 0, page)
				self.assertIsNotNone(out['utility'])
