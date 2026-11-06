
from django.test import TestCase
from django.utils import timezone

from cveFeed import db_exposure as dbx
from cveFeed import port_inventory
from cveFeed.models import CVEMatch
from cvengine_scanner import nmap as nmap_service
from startScan.models import IpAddress, Subdomain, Vulnerability
from tests.test_hard_distro import SSH_CVE, SSH_FIXES, Fixture, NGINX_CVE


class MatchEvidenceTests(Fixture):
	"""Area 4: a match records which row, version, entry and range it rests on."""

	def test_a_port_match_records_its_source_range_and_distro(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		port = self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0', 22, 'cpe:/a:openbsd:openssh:8.9p1')
		port.extra = {'method': 'probed', 'cpes': ['cpe:/a:openbsd:openssh:8.9p1']}
		port.save()
		(match,) = self.correlate([cve], lambda d, p, c: SSH_FIXES)
		ev = match.evidence
		self.assertEqual((ev['source'], ev['source_id'], ev['ip'], ev['port']), ('port', port.id, '192.0.2.60', 22))
		self.assertEqual((ev['raw_version'], ev['service_extra'], ev['cpe'], ev['method']),
			('8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0', 'cpe:/a:openbsd:openssh:8.9p1', 'probed'))
		self.assertEqual((ev['affected_index'], ev['range']), (0, {'introduced': '8.5p1', 'fixed': '9.8p1'}))
		self.assertEqual((ev['distro']['distro'], ev['distro']['package_release']), ('ubuntu', '8.9p1-3ubuntu0.6'))

	def test_a_technology_match_records_the_technology_row(self):
		from startScan.models import Technology
		tech = Technology.objects.create(name='nginx:1.18.0')
		self.sub.technologies.add(tech)
		cve = self.cve('CVE-2099-1', NGINX_CVE)
		(match,) = self.correlate([cve], None)
		self.assertEqual((match.evidence['source'], match.evidence['source_id'], match.evidence['raw_version']), ('tech', tech.id, '1.18.0'))

	def test_the_api_exposes_evidence_and_the_template_result(self):
		from agentapi.services import _match
		cve = self.cve('CVE-2099-1', NGINX_CVE)
		self.port('nginx', '1.18.0', '', 80)
		self.correlate([cve], None)
		CVEMatch.objects.update(template_result='no_match', template_id='cve-2099-1', template_tested_at=timezone.now())
		item = _match(CVEMatch.objects.select_related('cve_entry', 'subdomain').get())
		self.assertEqual((item['evidence']['source'], item['template_result'], item['template_id']), ('port', 'no_match', 'cve-2099-1'))
		self.assertTrue(item['template_tested'])


class NmapRecordTests(TestCase):
	def test_the_probe_method_the_ostype_and_every_cpe_are_kept(self):
		xml = ('<?xml version="1.0"?><nmaprun><host><address addr="198.51.100.40" addrtype="ipv4"/><ports>'
			'<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.6" '
			'extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>'
			'<cpe>cpe:/o:canonical:ubuntu_linux:22.04</cpe></service></port>'
			'<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" method="table"/></port></ports></host></nmaprun>')
		port_inventory.persist_inventory(port_inventory.parse_xml(xml))
		ip = IpAddress.objects.get(address='198.51.100.40')
		ssh, guessed = ip.ports.get(number=22), ip.ports.get(number=8080)
		self.assertEqual(ssh.extra, {'cpes': ['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux:22.04'], 'ostype': 'Linux', 'method': 'probed'})
		self.assertEqual((ssh.distro, ssh.distro_release, ssh.service_extra), ('ubuntu', '22.04', 'Ubuntu Linux; protocol 2.0'))
		self.assertEqual(guessed.extra['method'], 'table')  # named from the port number, not probed
		self.assertEqual(nmap_service.extract_nmap_inventory({'nmaprun': {'host': []}}), [])


class DbExposureEvidenceTests(TestCase):
	"""Review 2.6: one probe and one finding per host for names that share an address, with the server's reply."""

	def setUp(self):
		from dashboard.models import Org, Project
		from scanEngine.models import EngineType
		from startScan.models import Port, ScanHistory
		from targetApp.models import Domain
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='db.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
		ip = IpAddress.objects.create(address='203.0.113.50')
		ip.ports.add(Port.objects.create(number=6379, service_name='redis', product='Redis key-value store'))
		self.subs = []
		for n in range(30):
			sub = Subdomain.objects.create(name=f'h{n}.db.test', target_domain=domain, scan_history=self.scan)
			sub.ip_addresses.add(ip)
			self.subs.append(sub)

	def test_thirty_names_on_one_address_are_probed_once(self):
		calls = []

		def probe(host, port):
			calls.append((host, port))
			dbx._note(host, port, 'PONG (redis 6.2.6)')
			return True
		out = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		self.assertEqual(calls, [('203.0.113.50', 6379)])
		self.assertEqual(out, {'checked': 1, 'exposed': 1})

	def test_each_host_keeps_a_finding_with_the_same_reply_as_evidence(self):
		def probe(host, port):
			dbx._note(host, port, 'PONG (redis 6.2.6)')
			return True
		dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		self.assertEqual(Vulnerability.objects.filter(source='db_exposure').count(), 30)
		vuln = Vulnerability.objects.filter(source='db_exposure').first()
		self.assertEqual(vuln.extracted_results, ['PONG (redis 6.2.6)'])
		self.assertIn('PONG (redis 6.2.6)', vuln.description)

	def test_a_probe_that_found_nothing_open_makes_no_finding_and_no_stale_reply(self):
		dbx.EVIDENCE[('203.0.113.50', 6379)] = 'left over'
		out = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', lambda h, p: False)})
		self.assertEqual((out, Vulnerability.objects.count()), ({'checked': 1, 'exposed': 0}, 0))
		self.assertEqual(dbx.EVIDENCE, {})
