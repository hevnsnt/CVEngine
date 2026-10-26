"""Names that resolve to exactly the same addresses are one host with several names (``example.com`` and ``www.example.com`` on the
same servers), on every surface: the Hosts page, the dashboard counts, the attack-surface map, the group overview and the history.
A name behind a CDN, a name with a different set of addresses, a name that never resolved and the same addresses in another project
stay separate hosts."""
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import stats_history, views
from cveFeed.graph_overview import groups
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for


class AliasFixture(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='H', slug='h')
		cls.p1 = Project.objects.create(name='P1', slug='hp1', insert_date=now, org=org)
		cls.p2 = Project.objects.create(name='P2', slug='hp2', insert_date=now, org=org)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		cls.d1 = Domain.objects.create(name='example.test', project=cls.p1, insert_date=now)
		cls.d2 = Domain.objects.create(name='other.test', project=cls.p2, insert_date=now)
		scans = {d: ScanHistory.objects.create(domain=d, scan_type=engine, scan_status=2, start_scan_date=now - timedelta(hours=1), tasks=[])
				for d in (cls.d1, cls.d2)}
		cls.ip_a = IpAddress.objects.create(address='198.51.100.1')
		cls.ip_b = IpAddress.objects.create(address='198.51.100.2')
		cls.ip_c = IpAddress.objects.create(address='198.51.100.3')
		cls.ip_cdn = IpAddress.objects.create(address='203.0.113.9', is_cdn=True)

		def host(domain, name, *ips):
			sub = Subdomain.objects.create(target_domain=domain, name=name, scan_history=scans[domain])
			sub.ip_addresses.add(*ips)
			return sub
		cls.host = host
		cls.apex = host(cls.d1, 'example.test', cls.ip_a)
		cls.www = host(cls.d1, 'www.example.test', cls.ip_a)
		cls.cdn_a = host(cls.d1, 'cdn-a.example.test', cls.ip_cdn)
		cls.cdn_b = host(cls.d1, 'cdn-b.example.test', cls.ip_cdn)
		cls.api_host = host(cls.d1, 'api.example.test', cls.ip_a, cls.ip_b)  # a different set of addresses: not the same machine
		cls.unresolved_a = Subdomain.objects.create(target_domain=cls.d1, name='ghost-a.example.test', scan_history=scans[cls.d1], http_status=200)
		cls.unresolved_b = Subdomain.objects.create(target_domain=cls.d1, name='ghost-b.example.test', scan_history=scans[cls.d1], http_status=200)
		cls.in_other_project = host(cls.d2, 'example.other.test', cls.ip_a)  # the same address, another project
		cls.user = User.objects.create_user('aliaser', password='x')
		for p in (cls.p1, cls.p2):
			ProjectMembership.objects.create(user=cls.user, project=p, role='user')

	def setUp(self):
		cache.clear()
		views._STATS_CACHE.clear()
		self.client_ = client_for(self.user)

	def api(self, path, **params):
		r = self.client_.get(f'/api/v1/{path}', params)
		self.assertEqual(r.status_code, 200, r.content[:200])
		return r.json()

	def stats(self, project=''):
		return self.client_.get('/cve/api/stats', {'project': project} if project else {}).json()

	def hosts(self, slug='hp1'):
		return {h['host']: h for h in self.api(f'projects/{slug}/hosts', page_size=50)['results']}


class AliasedHostTests(AliasFixture):
	def test_two_names_on_the_same_addresses_are_one_host_with_an_alias(self):
		rows = self.hosts()
		# example.test + www (one host), cdn-a and cdn-b (CDN addresses keep names apart), api (more addresses), two unresolved names
		self.assertEqual(set(rows), {'example.test', 'cdn-a.example.test', 'cdn-b.example.test', 'api.example.test', 'ghost-a.example.test', 'ghost-b.example.test'})
		self.assertEqual(rows['example.test']['aliases'], ['www.example.test'])
		self.assertEqual(rows['api.example.test']['aliases'], [])
		self.assertEqual(self.api('projects/hp1/hosts')['count'], 6)

	def test_the_own_target_name_is_the_one_shown_and_a_search_still_finds_the_host(self):
		self.assertEqual([h['host'] for h in self.api('projects/hp1/hosts', q='example.test', page_size=50)['results'] if h['host'] == 'example.test'], ['example.test'])
		# searching for the other name finds the host through the row that matches it; the host still lists its other name
		found = [h for h in self.api('projects/hp1/hosts', q='www.', page_size=50)['results']]
		self.assertEqual([h['host'] for h in found], ['www.example.test'])
		self.assertEqual(found[0]['aliases'], ['example.test'])

	def test_the_dashboard_the_overview_and_the_history_count_one_host(self):
		self.assertEqual(self.stats('hp1')['hosts'], 6)
		self.assertEqual(self.stats()['hosts'], 7)  # the other project's host on the same address is a host of its own
		self.assertEqual(groups()['hosts'], 7)
		self.assertEqual(stats_history.compute_snapshot(self.p1)['hosts'], 6)

	def test_the_map_draws_the_host_once_and_lists_its_other_names(self):
		self.stats('hp1')
		nodes = [n for n in views.graph_payload()['nodes'] if n['kind'] == 'subdomain']
		labels = [n['label'] for n in nodes if n['project'] == 'hp1']
		self.assertIn('example.test', labels)
		self.assertNotIn('www.example.test', labels)
		apex = next(n for n in nodes if n['label'] == 'example.test')
		self.assertEqual(apex['info']['aliases'], ['www.example.test'])

	def test_the_same_addresses_in_another_project_are_another_host(self):
		self.assertEqual(set(self.hosts('hp2')), {'example.other.test'})
		self.assertEqual(self.hosts('hp2')['example.other.test']['aliases'], [])

	def test_a_name_that_gains_an_address_is_a_separate_host_again(self):
		self.www.ip_addresses.add(self.ip_c)
		self.assertEqual(set(self.hosts()) & {'example.test', 'www.example.test'}, {'example.test', 'www.example.test'})


class AliasedExposureTests(AliasFixture):
	def test_a_finding_on_the_other_name_belongs_to_the_one_host(self):
		finding = Vulnerability.objects.create(subdomain=self.www, target_domain=self.d1, scan_history=self.www.scan_history, name='admin panel', severity=3)
		host = self.hosts()['example.test']
		self.assertEqual(host['vuln_count'], 1)  # the finding on www is the host's finding, not a second host's
		self.assertEqual([v['id'] for v in host['vulns']], [finding.id])
		self.assertEqual(self.stats('hp1')['exposed_hosts'], 1)
		self.assertEqual(stats_history.compute_snapshot(self.p1)['exposed_hosts'], 1)
		node = next(n for n in views.graph_payload()['nodes'] if n['label'] == 'example.test')
		self.assertEqual(node['status'], 'vulnerable')
		self.assertEqual(node['info']['findings'], 1)

	def test_the_same_finding_on_both_names_is_counted_once_on_the_map(self):
		for sub in (self.apex, self.www):
			Vulnerability.objects.create(subdomain=sub, target_domain=self.d1, scan_history=sub.scan_history, name='admin panel', severity=3)
		node = next(n for n in views.graph_payload()['nodes'] if n['label'] == 'example.test')
		self.assertEqual(node['info']['findings'], 1)
		self.assertEqual(self.stats('hp1')['exposed_hosts'], 1)

	def test_a_cve_match_on_both_names_is_one_match_for_the_host(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=9.0, kev=True, affected=[])
		for sub in (self.apex, self.www):
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', confidence=.8)
		self.assertEqual(self.hosts()['example.test']['cve_matches'], 1)
		node = next(n for n in views.graph_payload()['nodes'] if n['label'] == 'example.test')
		self.assertEqual(node['info']['cves'], 1)
		self.assertEqual(self.stats('hp1')['exposed_hosts'], 1)

	def test_a_finding_on_a_cdn_name_does_not_expose_its_neighbour(self):
		Vulnerability.objects.create(subdomain=self.cdn_a, target_domain=self.d1, scan_history=self.cdn_a.scan_history, name='x', severity=3)
		self.assertEqual(self.stats('hp1')['exposed_hosts'], 1)
		self.assertEqual(self.hosts()['cdn-b.example.test']['vuln_count'], 0)
