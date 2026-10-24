from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.services import Ctx, host_group, list_hosts, search_hosts
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class OneRowPerHostTests(TestCase):
	"""A name stored twice (a scan-less row and a scanned copy) is one host, whole."""

	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='G', slug='g-org')
		cls.project = Project.objects.create(name='G', slug='grp', insert_date=now, org=org)
		cls.domain = Domain.objects.create(name='grp.example', project=cls.project, insert_date=now)
		scan = ScanHistory.objects.create(start_scan_date=now, scan_status=2, domain=cls.domain,
			scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='x'))
		cls.bare = Subdomain.objects.create(name='www.grp.example', target_domain=cls.domain, score=60)
		cls.rich = Subdomain.objects.create(name='www.grp.example', target_domain=cls.domain, scan_history=scan, score=60)
		ip = IpAddress.objects.create(address='203.0.113.26')
		for n in range(8):
			ip.ports.add(Port.objects.create(number=1000 + n, service_name='x', state='open'))
		ip.ports.add(Port.objects.create(number=9999, state='closed'))
		cls.rich.ip_addresses.add(ip)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, cvss=9.8, title='t', published_at=now)
		CVEMatch.objects.create(cve_entry=cve, subdomain=cls.rich, confidence=0.9)
		# the scan-less copy carries its own open finding and its own IP without ports
		cls.bare.ip_addresses.add(IpAddress.objects.create(address='203.0.113.27'))
		cls.vuln = Vulnerability.objects.create(name='Exposed thing', severity=3, subdomain=cls.bare, target_domain=cls.domain, http_url='https://www.grp.example/')
		Subdomain.objects.create(name='other.grp.example', target_domain=cls.domain)
		cls.ctx = Ctx(user=User.objects.create_user('g-admin', password='x', is_superuser=True))

	def test_list_and_search_collapse_to_the_richest_row(self):
		for fn in (list_hosts, search_hosts):
			page = fn(self.ctx, 'grp', {})
			self.assertEqual(page['count'], 2)
			www = [h for h in page['results'] if h['host'] == 'www.grp.example']
			self.assertEqual(len(www), 1)
			self.assertEqual(www[0]['id'], self.rich.id)
		self.assertEqual(search_hosts(self.ctx, 'grp', {'q': 'www'})['count'], 1)
		self.assertEqual(search_hosts(self.ctx, 'grp', {'q': 'port:1003'})['count'], 1)

	def test_paging_counts_names_not_rows(self):
		page = list_hosts(self.ctx, 'grp', {'page_size': '1', 'page': '2'})
		self.assertEqual((page['count'], len(page['results'])), (2, 1))

	def test_detail_aggregates_the_whole_name(self):
		for sub in (self.rich, self.bare):  # whichever row was asked for
			h = host_group(self.project, sub)
			self.assertEqual(sorted(ip['address'] for ip in h['ips']), ['203.0.113.26', '203.0.113.27'])
			self.assertEqual(sum(len(ip['ports']) for ip in h['ips']), 8)  # the closed port is not counted
			self.assertEqual(h['cve_matches'], 1)
			self.assertEqual([v['id'] for v in h['vulns']], [self.vuln.id])
			self.assertEqual(h['heat'], 'fire')
		# the list row carries the same counts
		row = [h for h in list_hosts(self.ctx, 'grp', {})['results'] if h['host'] == 'www.grp.example'][0]
		self.assertEqual((row['cve_matches'], len(row['vulns'])), (1, 1))
