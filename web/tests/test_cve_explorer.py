"""The CVE explorer (/cve/cves/ and /cve/api/cves): search the whole catalog by CVE id, part of one, or a technology, and see how many of
your own hosts each CVE matches. The catalog is shared; the host counts and the matching hosts are only ever from projects the caller can see."""
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import cve_explorer
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for

API = '/cve/api/cves'


class ExplorerBase(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = cls.now = timezone.now()
		day = timedelta(days=1)
		mk = CVEEntry.objects.create
		cls.regresshion = mk(cve_id='CVE-2024-6387', title='Signal handler race in sshd', cvss=8.1, kev=False, epss_reached=True,
			published_at=now - 400 * day, summary='A remote unauthenticated attacker may run code as root.',
			affected=[{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'ranges': [{'introduced': '8.5p1', 'fixed': '9.8p1'}]}],
			references=[{'url': 'https://www.openssh.com/txt/release-9.8', 'type': 'advisory'}],
			intel={'epss': {'score': 0.43, 'percentile': 0.97}})
		cls.ssh_old = mk(cve_id='CVE-2023-38408', title='Remote code execution in the forwarded agent', cvss=9.8, kev=True,
			published_at=now - 800 * day, affected=[{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'ranges': []}])
		cls.ssh_title = mk(cve_id='CVE-2025-1111', title='Libssh2 style ssh client crash in a router', cvss=5.3,
			published_at=now - 10 * day, affected=[{'vendor': 'Acme', 'product': 'Router firmware', 'ranges': []}])
		cls.php = mk(cve_id='CVE-2024-4577', title='Argument injection in CGI mode', cvss=9.8, kev=True, exploit_db=True,
			published_at=now - 300 * day, affected=[{'vendor': 'PHP Group', 'product': 'PHP', 'ranges': [{'introduced': '8.1.0', 'fixed': '8.1.29'}]}])
		cls.php_pkg = mk(cve_id='CVE-2024-8926', title='Bypass of an earlier fix', cvss=3.1,
			published_at=now - 30 * day, affected=[{'package': 'php', 'ranges': []}])
		cls.unrelated = mk(cve_id='CVE-2024-63870', title='Something in a printer', cvss=None,
			published_at=now - 5 * day, affected=[{'vendor': 'Printco', 'product': 'Laser', 'ranges': []}])
		cls.org = Org.objects.create(name='Org', slug='org')
		cls.mine = Project.objects.create(name='Mine', slug='mine', insert_date=now, org=cls.org)
		cls.theirs = Project.objects.create(name='Theirs', slug='theirs', insert_date=now, org=cls.org)
		engine = EngineType.objects.create(engine_name='fast', yaml_configuration='x')
		cls.hosts = {}
		for project in (cls.mine, cls.theirs):
			domain = Domain.objects.create(name=f'{project.slug}.example.com', project=project, insert_date=now)
			scan = ScanHistory.objects.create(start_scan_date=now, scan_status=2, domain=domain, scan_type=engine)
			for n in (1, 2):
				sub = Subdomain.objects.create(name=f'h{n}.{project.slug}.example.com', target_domain=domain, scan_history=scan)
				cls.hosts[(project.slug, n)] = sub
				CVEMatch.objects.create(cve_entry=cls.regresshion, subdomain=sub, scan_history=scan, matched_product='OpenSSH',
					matched_version='9.6p1', version_in_range=True, confidence=0.9)
		# a match the reviewer ruled out is not a host this CVE matches
		CVEMatch.objects.create(cve_entry=cls.php, subdomain=cls.hosts[('mine', 1)], matched_product='PHP', ai_verdict='not_affected')
		cls.admin = User.objects.create_user('root', password='x', is_superuser=True)
		cls.solo = User.objects.create_user('solo', password='x')
		ProjectMembership.objects.create(user=cls.solo, project=cls.mine, role='user')
		cls.nobody = User.objects.create_user('nobody', password='x')

	def search(self, user=None, **params):
		r = client_for(user or self.admin).get(API, params)
		self.assertEqual(r.status_code, 200, r.content)
		return r.json()

	def ids(self, **params):
		return [i['cve_id'] for i in self.search(**params)['items']]


class QueryShapeTests(TestCase):
	def test_what_counts_as_an_id(self):
		for q in ('CVE-2024-6387', 'cve-2024-6387', '2024-6387', 'CVE-2024', '2024-', '6387', '63870', 'cve-'):
			self.assertTrue(cve_explorer.looks_like_id(q), q)
		for q in ('ssh', 'php', '123', '8.1', 'openssh 9', 'log4j', ''):
			self.assertFalse(cve_explorer.looks_like_id(q), q)

	def test_severity_bands(self):
		self.assertEqual([cve_explorer.severity_of(v) for v in (9.8, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.0, None)],
			['critical', 'critical', 'high', 'high', 'medium', 'medium', 'low', 'low', ''])

	def test_the_product_expression_is_the_one_the_index_covers(self):
		from importlib import import_module
		migration = import_module('cveFeed.migrations.0149_cve_explorer_search_index')
		self.assertIn(cve_explorer.PRODUCTS_SQL, migration.PRODUCTS_INDEX)
		self.assertIn(cve_explorer.TITLE_SQL, migration.TITLE_INDEX)


class SearchTests(ExplorerBase):
	def test_full_id_finds_that_cve_first(self):
		self.assertEqual(self.ids(q='CVE-2024-6387'), ['CVE-2024-6387', 'CVE-2024-63870'])
		self.assertEqual(self.ids(q='cve-2024-6387')[0], 'CVE-2024-6387')

	def test_partial_id(self):
		self.assertEqual(self.ids(q='2024-6387'), ['CVE-2024-6387', 'CVE-2024-63870'])
		self.assertEqual(self.ids(q='6387'), ['CVE-2024-6387', 'CVE-2024-63870'])
		self.assertEqual(set(self.ids(q='CVE-2024')), {'CVE-2024-6387', 'CVE-2024-4577', 'CVE-2024-8926', 'CVE-2024-63870'})

	def test_a_short_number_is_not_an_id_search(self):
		self.assertEqual(self.ids(q='638'), [])  # three digits: searched as text, which nothing here contains

	def test_ssh_finds_openssh(self):
		got = self.ids(q='ssh')
		self.assertEqual(got[:2], ['CVE-2024-6387', 'CVE-2023-38408'])  # product hits, newest first
		self.assertEqual(got[2:], ['CVE-2025-1111'])  # then the title-only hit, though it is the newest
		self.assertNotIn('CVE-2024-4577', got)

	def test_php_finds_php_by_product_and_package(self):
		self.assertEqual(self.ids(q='php'), ['CVE-2024-8926', 'CVE-2024-4577'])
		self.assertEqual(self.ids(q='PHP'), ['CVE-2024-8926', 'CVE-2024-4577'])

	def test_vendor_matches(self):
		self.assertEqual(self.ids(q='openbsd'), ['CVE-2024-6387', 'CVE-2023-38408'])

	def test_a_version_in_a_range_is_not_a_product(self):
		self.assertEqual(self.ids(q='8.5p1'), [])

	def test_wildcards_are_literal(self):
		self.assertEqual(self.ids(q='%'), [])
		self.assertEqual(self.ids(q='_'), [])

	def test_no_query_lists_the_newest(self):
		self.assertEqual(self.ids()[:3], ['CVE-2024-63870', 'CVE-2025-1111', 'CVE-2024-8926'])

	def test_filters(self):
		self.assertEqual(self.ids(q='ssh', kev='1'), ['CVE-2023-38408'])
		self.assertEqual(self.ids(q='ssh', severity='high'), ['CVE-2024-6387'])
		self.assertEqual(self.ids(severity='critical'), ['CVE-2024-4577', 'CVE-2023-38408'])
		self.assertEqual(self.ids(severity='low'), ['CVE-2024-8926'])
		self.assertEqual(self.ids(kev='1', severity='critical'), ['CVE-2024-4577', 'CVE-2023-38408'])
		r = client_for(self.admin).get(API, {'severity': 'bogus'})
		self.assertEqual(r.status_code, 400)

	def test_row_shape(self):
		row = next(i for i in self.search(q='CVE-2024-6387')['items'] if i['cve_id'] == 'CVE-2024-6387')
		self.assertEqual(row['title'], 'Signal handler race in sshd')
		self.assertEqual(row['severity'], 'high')
		self.assertEqual((row['kev'], row['epss'], row['epss_score'], row['exploit_db']), (False, True, 0.43, False))
		self.assertEqual(row['hosts'], 4)  # an admin sees all four hosts
		self.assertTrue(row['published_at'])
		self.assertIn(row['tier'], ('fire', 'smoke', 'ice'))
		php = next(i for i in self.search(q='php')['items'] if i['cve_id'] == 'CVE-2024-4577')
		self.assertEqual(php['hosts'], 0)  # its only match was ruled out


class PaginationTests(ExplorerBase):
	def test_fifty_a_page(self):
		now = timezone.now()
		CVEEntry.objects.bulk_create([CVEEntry(cve_id=f'CVE-2030-{1000 + i}', title='Bulk entry for nginx', published_at=now - timedelta(minutes=i))
			for i in range(120)])
		first = self.search(q='nginx')
		self.assertEqual((first['count'], first['page'], first['page_size'], len(first['items']), first['has_next']), (120, 1, 50, 50, True))
		self.assertEqual(first['items'][0]['cve_id'], 'CVE-2030-1000')
		third = self.search(q='nginx', page='3')
		self.assertEqual((len(third['items']), third['has_next']), (20, False))
		self.assertEqual(third['items'][-1]['cve_id'], 'CVE-2030-1119')
		seen = [i['cve_id'] for p in (1, 2, 3) for i in self.search(q='nginx', page=str(p))['items']]
		self.assertEqual(len(set(seen)), 120)
		self.assertEqual(self.search(q='nginx', page='99')['items'], [])
		self.assertEqual(self.search(q='nginx', page='x')['page'], 1)


class ScopeTests(ExplorerBase):
	def test_counts_include_only_projects_the_caller_sees(self):
		row = lambda user: next(i for i in self.search(user, q='CVE-2024-6387')['items'] if i['cve_id'] == 'CVE-2024-6387')
		self.assertEqual(row(self.admin)['hosts'], 4)
		self.assertEqual(row(self.solo)['hosts'], 2)
		self.assertEqual(client_for(self.nobody).get(API, {'q': 'ssh'}).status_code, 403)  # no project at all: no counts, no catalog either

	def test_the_catalog_itself_is_not_scoped(self):
		# solo sees no PHP match of their own, yet the catalog search is the same for them as for anyone
		self.assertEqual(self.ids(user=self.solo, q='php'), self.ids(q='php'))
		self.assertEqual(self.ids(user=self.solo, q='php'), ['CVE-2024-8926', 'CVE-2024-4577'])

	def test_detail_hosts_only_from_visible_projects(self):
		def hosts(user):
			r = client_for(user).get(f'{API}/CVE-2024-6387')
			self.assertEqual(r.status_code, 200)
			return sorted(h['host'] for h in r.json()['hosts'])
		self.assertEqual(hosts(self.admin), ['h1.mine.example.com', 'h1.theirs.example.com', 'h2.mine.example.com', 'h2.theirs.example.com'])
		self.assertEqual(hosts(self.solo), ['h1.mine.example.com', 'h2.mine.example.com'])
		self.assertEqual(client_for(self.solo).get(f'{API}/CVE-2024-6387').json()['host_count'], 2)
		self.assertEqual(client_for(self.nobody).get(f'{API}/CVE-2024-6387').status_code, 403)

	def test_a_project_the_caller_cannot_see_is_a_404(self):
		r = client_for(self.solo).get(API, {'q': 'ssh', 'project': 'theirs'})
		self.assertEqual(r.status_code, 404)
		r = client_for(self.solo).get(API, {'q': 'CVE-2024-6387', 'project': 'mine'})
		self.assertEqual(r.json()['items'][0]['hosts'], 2)

	def test_signed_out_gets_nothing(self):
		from django.test import Client
		r = Client().get(API, {'q': 'ssh'})
		self.assertNotEqual(r.status_code, 200)


class DetailTests(ExplorerBase):
	def test_detail(self):
		r = client_for(self.admin).get(f'{API}/cve-2024-6387')
		self.assertEqual(r.status_code, 200)
		d = r.json()
		self.assertEqual(d['cve_id'], 'CVE-2024-6387')
		self.assertEqual(d['summary'], 'A remote unauthenticated attacker may run code as root.')
		self.assertEqual((d['cvss'], d['severity'], d['epss_score'], d['epss_percentile']), (8.1, 'high', 0.43, 0.97))
		self.assertEqual(d['affected'], [{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'package': '', 'ranges': [{'introduced': '8.5p1', 'fixed': '9.8p1'}]}])
		self.assertEqual(d['references'], [{'url': 'https://www.openssh.com/txt/release-9.8', 'type': 'advisory'}])
		h = next(h for h in d['hosts'] if h['host'] == 'h1.mine.example.com')
		self.assertEqual((h['project'], h['project_name'], h['product'], h['version']), ('mine', 'Mine', 'OpenSSH', '9.6p1'))
		self.assertIn(h['heat'], ('fire', 'smoke', 'ice'))
		self.assertTrue(h['match_id'])

	def test_unknown_is_404(self):
		self.assertEqual(client_for(self.admin).get(f'{API}/CVE-1999-0000').status_code, 404)

	def test_unsafe_reference_urls_are_dropped(self):
		CVEEntry.objects.filter(pk=self.php.pk).update(references=['javascript:alert(1)', 'https://example.com/a', {'url': 'data:x'}, 7])
		d = client_for(self.admin).get(f'{API}/CVE-2024-4577').json()
		self.assertEqual(d['references'], [{'url': 'https://example.com/a', 'type': ''}])
		self.assertEqual(d['hosts'], [])  # the ruled out match is not listed


class PageTests(ExplorerBase):
	def test_page_renders_with_the_query(self):
		r = client_for(self.solo).get('/cve/cves/', {'q': 'ssh'})
		self.assertEqual(r.status_code, 200)
		self.assertContains(r, 'id="cve-q"')
		self.assertContains(r, 'value="ssh"')
		self.assertContains(r, 'cve/explorer.js')

	def test_the_query_is_escaped(self):
		r = client_for(self.solo).get('/cve/cves/', {'q': '" autofocus onfocus="x'})
		self.assertEqual(r.status_code, 200)
		self.assertContains(r, 'value="&quot; autofocus onfocus=&quot;x"')
