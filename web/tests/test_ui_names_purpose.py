"""One name per page (rail, page tabs, jump palette, account menu, page title) and one plain sentence under every page title.

The names are the rail's own, except where the review (B-ui N1) asked for another: Hosts (the page the Assets entry opens), About (not Help).
"""
import os
import re

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import nav
from dashboard.models import Org, Project, ProjectMembership
from cveFeed.views import SECTION_PURPOSE
from tests.test_tenancy import client_for
from tests.test_ui_nav import rail, tabs

STATIC = os.path.join(os.path.dirname(__file__), '..', 'static', 'cve')


def h1_and_sub(html):
	h1 = re.search(r'<h1[^>]*>(.*?)</h1>', html, re.S)
	sub = re.search(r'<p class="sub"[^>]*>(.*?)</p>', html, re.S)
	return (re.sub(r'<[^>]+>', '', h1.group(1)).strip() if h1 else '', re.sub(r'<[^>]+>', '', sub.group(1)).strip() if sub else '')


class OneNamePerPageTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.org = Org.objects.create(name='Org', slug='org')
		cls.proj = Project.objects.create(name='Alpha', slug='alpha', insert_date=timezone.now(), org=cls.org)
		cls.root = User.objects.create_superuser('nm-root', 'root@example.test', 'pw-12345-long')
		cls.analyst = User.objects.create_user('nm-analyst', password='x')
		ProjectMembership.objects.create(user=cls.analyst, project=cls.proj, role='user')

	def get(self, user, path):
		r = client_for(user).get(path)
		self.assertEqual(r.status_code, 200, (path, r.status_code))
		return r.content.decode()

	def test_every_rail_entry_is_named_like_the_page_it_opens(self):
		"""The rail label, the page's h1 and the page's own tab (when it has one) are one word or phrase."""
		html = self.get(self.analyst, '/cve/?project=alpha&skip=1')
		for label, href in rail(html):
			page = self.get(self.analyst, href)
			heading, _ = h1_and_sub(page)
			self.assertEqual(heading, label, (href, heading, label))
			own = [t for _, _, t in tabs(page)]
			if own:
				self.assertIn(label, own, (href, own))

	def test_the_tabs_the_palette_and_the_menu_use_the_rail_words(self):
		findings = [t for _, _, t in tabs(self.get(self.analyst, '/cve/alpha/vulns/'))]
		self.assertEqual(findings, ['Findings', 'CVE matches', 'Hygiene', 'Changes', 'CVE catalog'])
		hosts = [t for _, _, t in tabs(self.get(self.analyst, '/cve/alpha/hosts/'))]
		self.assertEqual(hosts, ['Hosts', 'Targets', 'Graph', 'Secrets', 'Suppliers'])
		self.assertEqual([t for _, _, t in tabs(self.get(self.root, '/cve/sentinels/'))][:2], ['Scanners', 'Sentinels'])
		built = nav.build('hosts', 'alpha', bounty_enabled=False, sentinels_enabled=False)
		names = [i['label'] for i in built['index']]
		for old in ('Asset graph', 'Scanner health', 'Config checks', 'Third parties', 'All findings'):
			self.assertNotIn(old, names)
		for new in ('Graph', 'Scanners', 'Hygiene', 'Suppliers', 'Findings'):
			self.assertIn(new, names)

	def test_the_page_titles_match_the_names(self):
		for path, name, heading in (('/cve/alpha/hygiene/', 'Hygiene', 'Hygiene'), ('/cve/alpha/suppliers/', 'Suppliers', 'Suppliers'),
									('/cve/alpha/hosts/', 'Hosts', 'Hosts'), ('/cve/graph/', 'Graph', 'Graph'), ('/cve/cves/', 'CVE catalog', 'CVE catalog'),
									('/cve/scanners/', 'Scanners', 'Scanners'), ('/cve/agents/', 'API keys', 'API keys'),
									('/cve/about/', 'About', 'About CVEngine')):
			html = self.get(self.root, path)
			self.assertEqual(h1_and_sub(html)[0], heading, path)
			self.assertIn(f'<title>CVEngine · {name}</title>', html, path)

	def test_the_account_menu_says_about_not_help(self):
		html = self.get(self.analyst, '/cve/about/')
		menu = html[html.index('<details class="acct">'):html.index('</aside>')]
		self.assertIn('data-nav="About"', menu)
		self.assertNotIn('data-nav="Help"', menu)
		self.assertRegex(menu, r'data-nav="About" aria-current="page"')

	def test_the_scheduler_has_one_name_on_the_scanners_page_and_in_administration(self):
		self.assertIn('Scheduler detail', self.get(self.root, '/cve/scanners/'))
		self.assertIn('label: "Scheduler detail"', open(os.path.join(STATIC, 'admin.js'), encoding='utf-8').read())

	def test_the_rail_with_no_project_names_the_page_it_opens(self):
		built = nav.build('dashboard', None, bounty_enabled=False, sentinels_enabled=False)
		self.assertEqual([e['label'] for e in built['rail']], ['Overview', 'Graph', 'Scanners'])


class PurposeLineTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.org = Org.objects.create(name='Org', slug='org')
		cls.proj = Project.objects.create(name='Alpha', slug='alpha', insert_date=timezone.now(), org=cls.org)
		cls.root = User.objects.create_superuser('pl-root', 'root@example.test', 'pw-12345-long')

	def test_the_overview_has_a_visible_title_and_a_sentence(self):
		html = client_for(self.root).get('/cve/?project=alpha&skip=1').content.decode()
		self.assertNotRegex(html, r'<h1 class="sr">')
		heading, sub = h1_and_sub(html)
		self.assertEqual(heading, 'Overview')
		self.assertGreater(len(sub), 40)
		self.assertIn('<title>CVEngine · Overview', html)

	def test_every_list_page_says_what_it_is_for(self):
		seen = set()
		for section in ('hosts', 'targets', 'scans', 'changes', 'activity', 'vulns', 'matches', 'hygiene', 'secrets', 'suppliers'):
			html = client_for(self.root).get(f'/cve/alpha/{section}/').content.decode()
			_, sub = h1_and_sub(html)
			self.assertGreater(len(sub), 40, (section, sub))
			self.assertTrue(sub.startswith(SECTION_PURPOSE[section]), (section, sub))
			self.assertTrue(sub.endswith('Project: Alpha'), (section, sub))
			self.assertNotIn(sub, seen)
			seen.add(sub)
			self.assertIn('Alpha', html)  # the project name is still shown, in the page head

	def test_the_all_projects_view_keeps_its_scope_line_next_to_the_sentence(self):
		Project.objects.create(name='Beta', slug='beta', insert_date=timezone.now(), org=self.org)
		html = client_for(self.root).get('/cve/_all/hosts/').content.decode()
		self.assertIn('All projects', html)
		self.assertIn('read-only', html)


class PurposeCopyTests(SimpleTestCase):
	def test_the_purpose_sentences_follow_the_copy_rules(self):
		from cveFeed.views import SECTIONS
		self.assertEqual(set(SECTION_PURPOSE), set(SECTIONS) - {'keys', 'sentinels'})
		for key, text in SECTION_PURPOSE.items():
			self.assertNotRegex(text, '[–—]|--', key)
			self.assertIsNone(re.search(r'(?i)scanning|discovery running', text), key)
