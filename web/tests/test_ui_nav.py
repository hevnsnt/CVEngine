"""The simplified shell: eight rail entries (six, then Hygiene and Suppliers back), page tabs for the pages that moved under them, role-aware links, and the pages' small fixes.

Every address that existed before the regroup still answers: the rail got shorter, no route went away.
"""
import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import nav
from dashboard.models import AIProviderSettings, Org, OrgMembership, Project, ProjectMembership, UserProfile
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain
from tests.test_tenancy import client_for

SECTIONS = ('targets', 'scans', 'hosts', 'changes', 'activity', 'vulns', 'matches', 'hygiene', 'secrets', 'suppliers')


def rail(html):
	"""(label, href) of the links in the left rail."""
	block = html[html.index('aria-label="Sections"'):html.index('<details class="acct">')]
	return re.findall(r'<a data-nav="([^"]+)" href="([^"]+)"', block)


def tabs(html):
	m = re.search(r'<nav class="pagetabs"[^>]*>(.*?)</nav>', html, re.S)
	return re.findall(r'<a href="([^"]+)" ?(aria-current="page")?>([^<]+)</a>', m.group(1)) if m else []


class ShellTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org = Org.objects.create(name='Org', slug='org')
		cls.proj = Project.objects.create(name='Alpha', slug='alpha', insert_date=now, org=cls.org)
		cls.other = Project.objects.create(name='Beta', slug='beta', insert_date=now, org=cls.org)
		cls.root = User.objects.create_superuser('ui-root', 'root@example.test', 'pw-12345-long')
		cls.org_admin = User.objects.create_user('ui-orgadmin', password='x')
		OrgMembership.objects.create(user=cls.org_admin, org=cls.org, role='admin')
		cls.analyst = User.objects.create_user('ui-analyst', password='x')
		ProjectMembership.objects.create(user=cls.analyst, project=cls.proj, role='user')
		cls.pentester = User.objects.create_user('ui-pentester', password='x')
		ProjectMembership.objects.create(user=cls.pentester, project=cls.proj, role='pentester')
		UserProfile.objects.update_or_create(user=cls.pentester, defaults={'bugbounty_enabled': True})

	def get(self, user, path):
		r = client_for(user).get(path)
		self.assertEqual(r.status_code, 200, (path, r.status_code))
		return r.content.decode()

	def test_the_rail_has_eight_entries_or_seven_without_bug_bounty(self):
		self.assertEqual([label for label, _ in rail(self.get(self.root, '/cve/?project=alpha&skip=1'))],
						['Overview', 'Findings', 'Hygiene', 'Assets', 'Suppliers', 'Scans', 'Scanners', 'Bug bounty'])
		for user in (self.analyst, self.org_admin):
			self.assertEqual([label for label, _ in rail(self.get(user, '/cve/?project=alpha&skip=1'))],
							['Overview', 'Findings', 'Hygiene', 'Assets', 'Suppliers', 'Scans', 'Scanners'], user.username)
		self.assertIn('Bug bounty', [label for label, _ in rail(self.get(self.pentester, '/cve/?project=alpha&skip=1'))])

	def test_every_rail_entry_opens_a_page(self):
		for label, href in rail(self.get(self.root, '/cve/?project=alpha&skip=1')):
			if label == 'Overview':
				continue  # a first-run App Admin is sent to the setup wizard from here, which is the point of the wizard
			self.assertEqual(client_for(self.root).get(href).status_code, 200, (label, href))
		self.assertEqual(client_for(self.analyst).get('/cve/').status_code, 200)

	def test_every_page_that_had_a_rail_link_still_answers(self):
		c = client_for(self.root)
		for section in SECTIONS:
			self.assertEqual(c.get(f'/cve/alpha/{section}/').status_code, 200, section)
		for path in ('/cve/graph/', '/cve/agents/', '/cve/sentinels/', '/cve/cves/', '/cve/scanners/', '/cve/about/', '/cve/how-it-works/',
					'/cve/settings/', '/cve/admin/', '/cve/_all/hosts/'):
			self.assertEqual(c.get(path).status_code, 200, path)
		self.assertEqual(c.get('/cve/alpha/keys/').status_code, 302)  # the old keys link still redirects

	def test_the_pages_that_moved_under_an_entry_are_a_tab_strip(self):
		findings = tabs(self.get(self.root, '/cve/alpha/matches/'))
		self.assertEqual([label for _, _, label in findings], ['All findings', 'CVE matches', 'Config checks', 'Changes', 'CVE catalog'])
		self.assertEqual([label for _, current, label in findings if current], ['CVE matches'])
		self.assertEqual([label for _, _, label in tabs(self.get(self.root, '/cve/alpha/suppliers/'))], ['Hosts', 'Targets', 'Graph', 'Secrets', 'Third parties'])
		self.assertEqual([label for _, _, label in tabs(self.get(self.root, '/cve/alpha/activity/'))], ['Scans', 'Activity'])
		self.assertEqual([label for _, _, label in tabs(self.get(self.root, '/cve/graph/'))][:3], ['Hosts', 'Targets', 'Graph'])
		self.assertEqual([label for _, _, label in tabs(self.get(self.root, '/cve/sentinels/'))], ['Health', 'Sentinels', 'Integrations'])
		self.assertEqual(tabs(self.get(self.root, '/cve/?skip=1')), [])  # Overview has no siblings

	def test_the_current_page_marks_its_entry_in_the_rail(self):
		html = self.get(self.root, '/cve/alpha/hygiene/')
		block = html[html.index('aria-label="Sections"'):html.index('<details class="acct">')]
		self.assertRegex(block, r'data-nav="Hygiene"[^>]*aria-current="page"')  # Hygiene has its own entry again, and it wins over Findings
		self.assertNotRegex(block, r'data-nav="Findings"[^>]*aria-current')
		self.assertNotRegex(block, r'data-nav="Assets"[^>]*aria-current')

	def test_the_phone_bar_makes_findings_primary(self):
		html = self.get(self.analyst, '/cve/alpha/hosts/')
		bar = html[html.index('class="tabbar"'):html.index('id="more-btn"')]
		self.assertEqual(re.findall(r'</svg>([^<]+)</a>', bar), ['Overview', 'Findings', 'Assets', 'Scans'])
		more = html[html.index('id="sheet"'):html.index('id="acct-sheet"')]
		self.assertIn('Scanners', more)
		self.assertNotIn('Bug bounty', more)  # not for this person

	def test_the_jump_palette_still_finds_every_old_page(self):
		html = self.get(self.analyst, '/cve/alpha/hosts/')
		index = html[html.index('id="nav-index"'):html.index('id="sheet-scrim"')]
		for label in ('Findings', 'CVE matches', 'Config checks', 'Changes', 'Targets', 'Asset graph', 'Secrets', 'Third parties', 'Activity',
					'Sentinels', 'API tokens and MCP', 'CVE catalog'):
			self.assertIn(f'data-nav="{label}"', index)

	def test_account_menu_is_role_aware(self):
		def menu(user):
			html = self.get(user, '/cve/about/')
			return re.findall(r'<a data-nav="([^"]+)"', html[html.index('<details class="acct">'):html.index('</aside>')])
		self.assertEqual(menu(self.root), ['My account', 'Administration', 'Connect AI model', 'Settings', 'Help'])
		self.assertEqual(menu(self.org_admin), ['My account', 'Administration', 'Help'])
		self.assertEqual(menu(self.analyst), ['My account', 'Help'])

	def test_the_project_sentinels_tab_only_appears_for_a_project_that_has_one(self):
		from unittest import mock
		client = client_for(self.root)
		client.get('/cve/alpha/hosts/')  # the session remembers the project, so the Scanners page knows which one it is for
		self.assertNotIn('This project', [label for _, _, label in tabs(client.get('/cve/scanners/').content.decode())])
		with mock.patch('agentapi.sentinel_broker.has_sentinels', return_value=True):
			self.assertIn('This project', [label for _, _, label in tabs(client.get('/cve/scanners/').content.decode())])

	def test_nav_builds_without_a_project(self):
		built = nav.build('dashboard', None, bounty_enabled=False, sentinels_enabled=False)
		self.assertEqual([e['label'] for e in built['rail']], ['Overview', 'Assets', 'Scanners'])
		self.assertEqual(built['rail'][1]['href'], '/cve/graph/')  # the one asset page that needs no project


class ScannersPageTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.root = User.objects.create_superuser('sc-root', 'root@example.test', 'pw-12345-long')
		cls.org = Org.objects.create(name='Org', slug='org')
		cls.analyst = User.objects.create_user('sc-analyst', password='x')
		OrgMembership.objects.create(user=cls.analyst, org=cls.org, role='user')

	def test_the_page_renders_for_everyone_and_asks_workers_only_for_app_admins(self):
		self.assertIn('data-app-admin="1"', client_for(self.root).get('/cve/scanners/').content.decode())
		html = client_for(self.analyst).get('/cve/scanners/').content.decode()
		self.assertNotIn('data-app-admin="1"', html)
		self.assertNotIn('Scheduler detail', html)
		self.assertEqual(client_for(self.analyst).get('/cve/api/admin/health').status_code, 403)  # the server still decides

	def test_the_page_is_neutral_about_where_scans_run_with_no_sentinel(self):
		html = client_for(self.root).get('/cve/scanners/').content.decode()
		self.assertIn('When no Sentinel is online, this server runs the external stages itself', html)
		self.assertNotIn('last resort', html.lower())

	def test_anonymous_is_sent_to_sign_in(self):
		from django.test import Client
		self.assertEqual(Client().get('/cve/scanners/').status_code, 302)


class DashboardFixesTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='Org', slug='org')
		cls.proj = Project.objects.create(name='Alpha', slug='alpha', insert_date=now, org=org)
		cls.root = User.objects.create_superuser('db-root', 'root@example.test', 'pw-12345-long')
		cls.analyst = User.objects.create_user('db-analyst', password='x')
		ProjectMembership.objects.create(user=cls.analyst, project=cls.proj, role='user')
		cls.org_admin = User.objects.create_user('db-orgadmin', password='x')
		OrgMembership.objects.create(user=cls.org_admin, org=org, role='admin')

	def test_connect_your_ai_model_is_offered_only_to_the_app_admin_who_can_open_it(self):
		AIProviderSettings.objects.all().delete()
		self.assertContains(client_for(self.root).get('/cve/?project=alpha&skip=1'), 'Connect your AI model')
		for user in (self.analyst, self.org_admin):
			r = client_for(user).get('/cve/?project=alpha&skip=1')
			self.assertNotContains(r, 'Connect your AI model', msg_prefix=user.username)
			self.assertEqual(client_for(user).get('/cve/welcome/').status_code, 403)  # the page itself is still refused

	def test_the_exposed_tile_opens_the_exposed_list(self):
		self.assertContains(client_for(self.root).get('/cve/?project=alpha&skip=1'), 'href="/cve/alpha/hosts/?exposed=1"')

	def test_provision_preselects_nothing_and_starts_disabled(self):
		client = client_for(self.root)
		client.get('/cve/alpha/hosts/')  # the session remembers the project being worked in: it must not become a default
		for url in ('/cve/sentinels/', '/cve/sentinels/?project=alpha'):
			html = client.get(url).content.decode()
			form = html[html.index('id="enroll-scope"') - 8:html.index('id="enroll-out"')]
			self.assertNotIn('data-current', html)
			selects = re.findall(r'<select id="(enroll-[a-z]+)"[^>]*>(.*?)</select>', form, re.S)
			self.assertEqual([n for n, _ in selects], ['enroll-scope', 'enroll-project', 'enroll-org', 'enroll-network', 'enroll-profile'])
			placeholders = {'enroll-scope': 'Choose a scope', 'enroll-project': 'Choose a project', 'enroll-org': 'Choose an organization',
							'enroll-network': 'Choose where it runs', 'enroll-profile': 'Choose a size'}
			for name, inner in selects:
				selected = re.findall(r'<option[^>]*\bselected\b[^>]*>([^<]*)</option>', inner)
				self.assertEqual(selected, [placeholders[name]], name)
				self.assertRegex(inner, r'<option value="" selected disabled>')
			button = re.search(r'<button[^>]*id="enroll-go"[^>]*>', html).group(0)
			self.assertIn(' disabled', button)
			self.assertIn('aria-disabled="true"', button)
			self.assertContains(client.get(url), 'Choose a scope to continue.')
			self.assertNotIn('style="display:none"', form)


class ShellRequestTests(TestCase):
	def test_running_and_queued_scans_come_back_in_one_request(self):
		from datetime import timedelta
		now = timezone.now()
		org = Org.objects.create(name='Org', slug='org')
		proj = Project.objects.create(name='Alpha', slug='alpha', insert_date=now, org=org)
		domain = Domain.objects.create(name='one.test', project=proj, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		made = {}
		for key, status, started in (('running', 1, now - timedelta(minutes=5)), ('queued', -1, now), ('done', 2, now - timedelta(hours=3)),
									('failed', 0, now - timedelta(hours=2))):
			made[key] = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=status, start_scan_date=started, tasks=[]).id
		root = User.objects.create_superuser('sr-root', 'root@example.test', 'pw-12345-long')
		r = client_for(root).get('/api/v1/projects/alpha/scans', {'status': 'active', 'page_size': 100})
		self.assertEqual(r.status_code, 200)
		self.assertEqual({s['id'] for s in r.json()['results']}, {made['running'], made['queued']})

	def test_the_notifier_asks_once(self):
		import pathlib
		source = (pathlib.Path(__file__).resolve().parent.parent / 'static/cve/notify.js').read_text()
		self.assertEqual(source.count('status=active'), 1)
		self.assertNotIn('status=running', source)
		self.assertNotIn('status=queued', source)
