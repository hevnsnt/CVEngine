import os
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import nmap_scan
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

FAST_XML = '''<?xml version="1.0"?>
<nmaprun><host>
<address addr="192.0.2.10" addrtype="ipv4"/>
<os><osmatch name="Linux 5.X" accuracy="95"/></os>
<ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
</port></ports>
</host></nmaprun>'''

FULL_XML = '''<?xml version="1.0"?>
<nmaprun><host>
<address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080">
<state state="open"/><service name="http" product="nginx" version="1.18"/>
</port></ports>
</host></nmaprun>'''


class BuildTargetsTests(TestCase):
	def test_dedupes_and_sorts_ips(self):
		self.assertEqual(nmap_scan.build_targets(['192.0.2.2', '192.0.2.1', '192.0.2.2']), ['192.0.2.1', '192.0.2.2'])

	def test_drops_falsy_values(self):
		self.assertEqual(nmap_scan.build_targets(['192.0.2.1', None, '']), ['192.0.2.1'])

	def test_truncates_to_max_targets(self):
		ips = [f'10.0.{i // 250}.{i % 250 + 1}' for i in range(nmap_scan.MAX_TARGETS + 10)]
		self.assertEqual(len(nmap_scan.build_targets(ips)), nmap_scan.MAX_TARGETS)
		self.assertEqual(len(nmap_scan.build_targets(ips, limit=None)), len(ips))


class ParseXmlTests(TestCase):
	def test_blank_output_is_empty(self):
		self.assertEqual(nmap_scan.parse_xml(''), [])
		self.assertEqual(nmap_scan.parse_xml('   '), [])

	def test_unparseable_xml_is_empty_not_a_crash(self):
		self.assertEqual(nmap_scan.parse_xml('<not xml'), [])

	def test_valid_report_extracts_host_os_and_service(self):
		inventory = nmap_scan.parse_xml(FAST_XML)
		self.assertEqual(len(inventory), 1)
		host = inventory[0]
		self.assertEqual(host['ip'], '192.0.2.10')
		self.assertEqual((host['os_guess'], host['os_accuracy']), ('Linux 5.X', 95))
		self.assertEqual(host['ports'], [{
			'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
			'product': 'OpenSSH', 'version': '8.9', 'service_extra': 'Ubuntu', 'ostype': '',
			'cpe': '', 'cpes': [], 'method': '', 'scripts': {}, 'banner': '',
		}])


class PersistInventoryTests(TestCase):
	def test_creates_ip_and_port_rows_with_os_and_service_fields(self):
		result = nmap_scan.persist_inventory(nmap_scan.parse_xml(FAST_XML))
		self.assertEqual(result, {'ports': 1, 'hosts_with_os': 1})
		ip = IpAddress.objects.get(address='192.0.2.10')
		self.assertEqual((ip.os_guess, ip.os_accuracy), ('Linux 5.X', 95))
		self.assertIsNotNone(ip.last_seen)
		port = ip.ports.get(number=22)
		self.assertEqual((port.protocol, port.product, port.version, port.service_extra, port.source),
			('tcp', 'OpenSSH', '8.9', 'Ubuntu', 'nmap'))

	def test_rescan_updates_the_ips_own_port_row_in_place(self):
		nmap_scan.persist_inventory(nmap_scan.parse_xml(FAST_XML))
		ip = IpAddress.objects.get(address='192.0.2.10')
		ip.ports.filter(number=22).update(version='8.8')
		nmap_scan.persist_inventory(nmap_scan.parse_xml(FAST_XML))
		self.assertEqual(Port.objects.filter(number=22).count(), 1)
		self.assertEqual(ip.ports.get(number=22).version, '8.9')

	def test_a_product_on_one_ip_is_not_visible_on_another(self):
		def host(ip, product):
			return [{'ip': ip, 'os_guess': '', 'os_accuracy': None, 'ports': [
				{'number': 443, 'protocol': 'tcp', 'state': 'open', 'service_name': 'https', 'product': product, 'version': '1'}]}]
		nmap_scan.persist_inventory(host('192.0.2.1', 'nginx'))
		nmap_scan.persist_inventory(host('192.0.2.2', 'Apache httpd'))
		self.assertEqual(IpAddress.objects.get(address='192.0.2.1').ports.get(number=443).product, 'nginx')
		self.assertEqual(IpAddress.objects.get(address='192.0.2.2').ports.get(number=443).product, 'Apache httpd')

	def test_a_port_row_shared_by_older_code_is_split_not_overwritten(self):
		shared = Port.objects.create(number=443, product='nginx', version='1')
		for address in ('192.0.2.1', '192.0.2.2'):
			IpAddress.objects.create(address=address).ports.add(shared)
		nmap_scan.persist_inventory([{'ip': '192.0.2.2', 'os_guess': '', 'os_accuracy': None,
			'ports': [{'number': 443, 'product': 'Caddy', 'version': '2'}]}])
		self.assertEqual(IpAddress.objects.get(address='192.0.2.1').ports.get(number=443).product, 'nginx')
		self.assertEqual(IpAddress.objects.get(address='192.0.2.2').ports.get(number=443).product, 'Caddy')

	def test_host_without_ip_is_skipped(self):
		self.assertEqual(nmap_scan.persist_inventory([{'ip': None, 'os_guess': '', 'os_accuracy': None, 'ports': []}]),
			{'ports': 0, 'hosts_with_os': 0})

	def test_port_without_number_is_skipped(self):
		inventory = [{'ip': '192.0.2.5', 'os_guess': '', 'os_accuracy': None,
		              'ports': [{'number': None, 'protocol': 'tcp'}]}]
		result = nmap_scan.persist_inventory(inventory)
		self.assertEqual(result, {'ports': 0, 'hosts_with_os': 0})
		self.assertEqual(IpAddress.objects.get(address='192.0.2.5').ports.count(), 0)


class RunNmapForScanTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='N', slug='nm')
		self.project = Project.objects.create(name='P', slug='pnm', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(),
			scan_status=1, results_dir='/tmp')
		sub = Subdomain.objects.create(scan_history=self.scan, name='www.example.test')
		ip = IpAddress.objects.create(address='192.0.2.10')
		sub.ip_addresses.add(ip)

	def test_no_targets_is_skipped_without_calling_the_runner(self):
		Subdomain.objects.filter(scan_history=self.scan).delete()
		runner = mock.Mock()
		self.assertEqual(nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner), {'targets': 0})
		runner.assert_not_called()

	def test_one_pass_by_default_with_top_ports_1000_and_no_full_sweep(self):
		calls = []

		def runner(targets, flags, host_timeout):
			calls.append((targets, flags, host_timeout))
			return FAST_XML
		result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual([c[1:] for c in calls], [(nmap_scan.FAST_FLAGS, nmap_scan.HOST_TIMEOUT_FAST)])
		self.assertEqual(nmap_scan.FAST_FLAGS, ['-sV', '--version-intensity', '7', '-O', '--osscan-limit', '--top-ports', '1000', '-Pn',
			'-T4', '--max-retries', '2', '--min-hostgroup', '32', '--defeat-rst-ratelimit', '--script', ','.join(nmap_scan.NSE_SCRIPTS),
			'--script-timeout', '30s'])
		self.assertEqual(calls[0][0], ['192.0.2.10'])  # IPs only, never the hostname
		self.assertEqual(result, {'targets': 1, 'reused': 0, 'fast': {'ports': 1, 'hosts_with_os': 1}})
		from cveFeed.models import ServiceRun
		self.assertFalse(ServiceRun.objects.filter(service='nmap-full').exists())  # the stage never ran, so no ledger key
		self.assertFalse(any('sweeping every port' in m for m in AgentActivity.objects.values_list('message', flat=True)))

	@mock.patch.dict('os.environ', {'CVENGINE_NMAP_FULL': '1'})
	def test_the_pipeline_never_sweeps_every_port_whatever_the_old_switch_says(self):
		calls = []

		def runner(targets, flags, host_timeout):
			calls.append(flags)
			return FAST_XML
		result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual(calls, [nmap_scan.FAST_FLAGS])
		self.assertNotIn('full', result)

	def test_fast_stage_failure_skips_full_stage_and_reports_error(self):
		def runner(targets, flags, host_timeout):
			raise RuntimeError('nmap exploded')
		result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual(result, {'targets': 1, 'reused': 0, 'error': 'nmap exploded'})

	def _runner(self, calls):
		def runner(targets, flags, host_timeout):
			calls.append((list(targets), flags))
			return FAST_XML if flags == nmap_scan.FAST_FLAGS else FULL_XML
		return runner

	def test_hostnames_are_never_passed_to_the_runner(self):
		calls = []
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=self._runner(calls))
		for targets, _flags in calls:
			self.assertNotIn('www.example.test', targets)
			self.assertTrue(all(t[0].isdigit() for t in targets))

	def test_two_scans_sharing_an_ip_scan_it_once(self):
		other_domain = Domain.objects.create(name='other.test', project=self.project, insert_date=timezone.now())
		other = ScanHistory.objects.create(domain=other_domain, scan_type=self.scan.scan_type, start_scan_date=timezone.now(),
			scan_status=1, results_dir='/tmp')
		sub = Subdomain.objects.create(scan_history=other, name='shared.other.test')
		sub.ip_addresses.add(IpAddress.objects.get(address='192.0.2.10'))  # shared hosting
		calls = []
		runner = self._runner(calls)
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual(len(calls), 1)
		result = nmap_scan.run_nmap_for_scan(other.id, runner=runner)
		self.assertEqual(len(calls), 1)  # nothing new to scan
		self.assertEqual(result['reused'], 1)

	def test_a_fresh_ip_is_skipped_and_an_expired_one_is_rescanned(self):
		from datetime import timedelta

		from cveFeed.models import ServiceRun
		calls = []
		runner = self._runner(calls)
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual(len(calls), 1)
		ServiceRun.objects.filter(service='nmap-fast').update(finished_at=timezone.now() - timedelta(days=8))
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual([c[1] for c in calls[1:]], [nmap_scan.FAST_FLAGS])  # past the 7 day TTL it is fingerprinted again

	def test_a_failed_pass_is_recorded_as_failed_and_retried_next_time(self):
		def boom(targets, flags, host_timeout):
			raise RuntimeError('nmap exploded')
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=boom)
		calls = []
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=self._runner(calls))
		self.assertEqual(len(calls), 1)


def _report(ports, scanned='22,80,443,3306,8080', extraports='closed', status='up'):
	"""A one-host nmap XML report: ``ports`` is [(number, state, product, version)]; the run probed ``scanned``."""
	body = ''.join(f'<port protocol="tcp" portid="{n}"><state state="{state}"/>'
		f'<service name="svc" product="{product}" version="{version}"/></port>' for n, state, product, version in ports)
	extra = f'<extraports state="{extraports}" count="3"/>' if extraports else ''
	return (f'<?xml version="1.0"?><nmaprun><scaninfo type="syn" protocol="tcp" numservices="5" services="{scanned}"/>'
		f'<host><status state="{status}"/><address addr="192.0.2.77" addrtype="ipv4"/><ports>{extra}{body}</ports></host></nmaprun>')


class OpenPortStateTests(TestCase):
	"""Review 2.5: only open ports are scanned, correlated and listed, and a port that closed is closed."""

	def _sub_with_ip(self):
		org = Org.objects.create(name='N', slug='nm')
		project = Project.objects.create(name='P', slug='pnm', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='ports.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1, results_dir='/tmp')
		sub = Subdomain.objects.create(scan_history=self.scan, target_domain=domain, name='www.ports.test')
		self.ip = IpAddress.objects.get_or_create(address='192.0.2.77')[0]
		sub.ip_addresses.add(self.ip)
		return sub

	def test_the_scan_parses_which_ports_the_run_probed(self):
		host = nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')], scanned='22,80-82,8080'))[0]
		self.assertEqual(host['scanned'], {22, 80, 81, 82, 8080})
		self.assertEqual((host['status'], host['extraports']), ('up', ['closed']))

	def test_a_filtered_port_is_not_a_target_and_not_correlated(self):
		from cveFeed import correlation
		from cveFeed.nuclei_scan import scan_targets
		sub = self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([
			(22, 'open', 'OpenSSH', '8.9'), (3306, 'filtered', 'MySQL', '5.7.1'), (8080, 'closed', 'nginx', '1.18.0')])))
		self.assertEqual(self.ip.ports.get(number=3306).state, 'filtered')
		self.assertEqual({n for _h, n in scan_targets(self.scan)[2]}, {22})
		cve = type('C', (), {'id': 1, 'affected': [{'product': 'mysql', 'ranges': [{'fixed': '8'}]}, {'product': 'nginx', 'ranges': [{'fixed': '1.20'}]}],
			'kev': False})()
		rows = correlation.collect_subdomain_matches(sub, correlation.build_product_index([cve]), {1: cve})
		self.assertEqual(rows, [])  # neither the filtered MySQL nor the closed nginx is on the host

	def test_an_open_port_is_still_correlated(self):
		from cveFeed import correlation
		sub = self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(8080, 'open', 'nginx', '1.18.0')])))
		cve = type('C', (), {'id': 1, 'affected': [{'product': 'nginx', 'ranges': [{'fixed': '1.20'}]}], 'kev': False})()
		rows = correlation.collect_subdomain_matches(sub, correlation.build_product_index([cve]), {1: cve})
		self.assertEqual([r['version_in_range'] for r in rows], [True])

	def test_a_port_absent_from_the_next_run_is_closed_not_retained(self):
		self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.18.0')])))
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')])))
		self.assertEqual(self.ip.ports.get(number=8080).state, 'closed')
		self.assertEqual(self.ip.ports.get(number=22).state, 'open')

	def test_a_port_outside_the_probed_set_is_left_alone(self):
		self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (9200, 'open', 'Elasticsearch', '7.10')],
			scanned='22,80,443,9200')))
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')], scanned='22,80,443')))  # never tried 9200
		self.assertEqual(self.ip.ports.get(number=9200).state, 'open')

	def test_a_silent_host_does_not_wipe_what_was_open(self):
		self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')])))
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([], extraports='filtered')))  # everything dropped: unreachable, not closed
		self.assertEqual(self.ip.ports.get(number=22).state, 'open')

	def test_a_closed_port_that_opens_again_is_open(self):
		self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.18.0')])))
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')])))
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.26.0')])))
		port = self.ip.ports.get(number=8080)
		self.assertEqual((port.state, port.version), ('open', '1.26.0'))

	def test_closed_ports_are_not_listed_by_the_inventory_or_probed_for_hygiene_and_db_exposure(self):
		from cveFeed import hygiene
		from startScan.models import open_ports
		sub = self._sub_with_ip()
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (3306, 'closed', 'MySQL', '5.7')])))
		self.assertEqual([p.number for p in open_ports(self.ip)], [22])
		nmap_scan.persist_inventory([{'ip': '192.0.2.77', 'ports': [{'number': 8443, 'state': 'filtered'}]}])
		self.assertNotIn(('www.ports.test', 8443), hygiene.tls_targets(sub.target_domain))
		nmap_scan.persist_inventory([{'ip': '192.0.2.77', 'ports': [{'number': 8443, 'state': 'open'}]}])
		self.assertIn(('www.ports.test', 8443), hygiene.tls_targets(sub.target_domain))


class PortListTests(SimpleTestCase):
	"""The fingerprint pass scans nmap's top thousand plus the high-risk ports the frequency ranking leaves out."""

	def _services(self, rows):
		import tempfile
		handle = tempfile.NamedTemporaryFile('w', suffix='-nmap-services', delete=False)
		handle.write('# comment line\n' + ''.join(f'{name}\t{port}/{proto}\t{freq}\n' for name, port, proto, freq in rows))
		handle.close()
		self.addCleanup(os.unlink, handle.name)
		return (handle.name,)

	def test_top_ports_come_from_nmaps_frequency_table(self):
		from cveFeed.nmap_scan import top_tcp_ports
		paths = self._services([('http', 80, 'tcp', 0.48), ('ssh', 22, 'tcp', 0.18), ('dns', 53, 'udp', 0.9), ('https', 443, 'tcp', 0.2)])
		self.assertEqual(top_tcp_ports(2, paths), [80, 443])  # udp ignored, highest frequency first
		self.assertIsNone(top_tcp_ports(2, ('/nonexistent/nmap-services',)))

	def test_fast_flags_add_the_high_risk_ports(self):
		from cveFeed.nmap_scan import EXTRA_PORTS, fast_flags
		flags = fast_flags(self._services([('http', 80, 'tcp', 0.48), ('https', 443, 'tcp', 0.2)]))
		self.assertNotIn('--top-ports', flags)
		ports = flags[flags.index('-p') + 1]
		for port in ('80', '443', '6379', '27017', '10250', '2375', '6443', '11211'):
			self.assertIn(port, ports.replace('-', ',').split(','), port)
		self.assertEqual(len(EXTRA_PORTS), len(set(EXTRA_PORTS)))
		for flag in ('-sV', '-O', '-Pn', '-T4'):
			self.assertIn(flag, flags)

	def test_without_the_frequency_table_the_plain_top_thousand_is_scanned(self):
		from cveFeed.nmap_scan import FAST_FLAGS, fast_flags
		self.assertEqual(fast_flags(('/nonexistent/nmap-services',)), FAST_FLAGS)

	def test_naabu_narrowing_also_replaces_an_explicit_port_list(self):
		from cveFeed import naabu_scan
		build = naabu_scan.flags_for({'203.0.113.5': [22, 443]}, ['-sV', '-p', '80,443,6379', '-Pn'])
		self.assertEqual(build(['203.0.113.5']), ['-sV', '-p', '22,443', '-Pn'])


class NaabuSwitchTests(SimpleTestCase):
	def test_naabu_is_off_unless_switched_on_even_when_installed(self):
		from cveFeed import naabu_scan
		with mock.patch('shutil.which', return_value='/usr/local/bin/naabu'):
			with mock.patch.dict(os.environ, {'CVENGINE_NAABU': ''}):
				self.assertIsNone(naabu_scan.naabu_path())
				self.assertIsNone(naabu_scan.discover(['203.0.113.5']))
			with mock.patch.dict(os.environ, {'CVENGINE_NAABU': '1'}):
				self.assertEqual(naabu_scan.naabu_path(), '/usr/local/bin/naabu')


NSE_XML = '''<?xml version="1.0"?>
<nmaprun><host>
<address addr="192.0.2.30" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.5"/>
<script id="banner" output="220 (vsFTPd 3.0.5)"/>
<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/>
<script id="ssh-hostkey" output="256 aa:bb (ED25519)"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/>
<script id="rdp-ntlm-info" output="Product_Version: 10.0.20348"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="nginx" servicefp="SF-Port8080-TCP:V=7.99"/></port>
</ports>
<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2022&#xa;Computer name: WIN-ACME"/></hostscript>
</host></nmaprun>'''


class NseCaptureTests(TestCase):
	def test_the_parser_keeps_each_ports_script_output_and_banner(self):
		ports = {p['number']: p for p in nmap_scan.parse_xml(NSE_XML)[0]['ports']}
		self.assertEqual(ports[21]['banner'], '220 (vsFTPd 3.0.5)')  # the banner script wins
		self.assertIn('Anonymous FTP login allowed', ports[21]['scripts']['ftp-anon'])
		self.assertEqual(ports[22]['scripts'], {'ssh-hostkey': '256 aa:bb (ED25519)'})
		self.assertEqual(ports[8080]['banner'], 'SF-Port8080-TCP:V=7.99')  # no banner script: nmap's own probe bytes
		self.assertEqual(ports[8080]['scripts'], {})

	def test_the_parser_keeps_host_level_scripts(self):
		host = nmap_scan.parse_xml(NSE_XML)[0]
		self.assertIn('Windows Server 2022', host['hostscripts']['smb-os-discovery'])

	def test_a_report_without_scripts_has_none(self):
		host = nmap_scan.parse_xml(FAST_XML)[0]
		self.assertEqual(host['hostscripts'], {})
		self.assertEqual(host['ports'][0]['scripts'], {})

	def test_script_output_is_capped(self):
		from reNgine.nmap_service import BANNER_CAP, SCRIPT_OUTPUT_CAP
		xml = ('<nmaprun><host><address addr="192.0.2.31" addrtype="ipv4"/><ports><port protocol="tcp" portid="25">'
			'<state state="open"/><service name="smtp"/><script id="banner" output="' + 'A' * 9000 + '"/></port></ports></host></nmaprun>')
		port = nmap_scan.parse_xml(xml)[0]['ports'][0]
		self.assertEqual(len(port['banner']), BANNER_CAP)
		self.assertEqual(len(port['scripts']['banner']), SCRIPT_OUTPUT_CAP)

	def test_persisting_stores_banner_scripts_and_host_scripts(self):
		nmap_scan.persist_inventory(nmap_scan.parse_xml(NSE_XML))
		ip = IpAddress.objects.get(address='192.0.2.30')
		ftp = ip.ports.get(number=21)
		self.assertEqual(ftp.banner, '220 (vsFTPd 3.0.5)')
		self.assertIn('ftp-anon', ftp.extra['scripts'])
		self.assertIn('smb-os-discovery', ip.fingerprint['scripts'])

	def test_a_rescan_without_scripts_keeps_the_last_banner(self):
		nmap_scan.persist_inventory(nmap_scan.parse_xml(NSE_XML))
		bare = NSE_XML.replace('<script id="banner" output="220 (vsFTPd 3.0.5)"/>', '')
		bare = bare.replace('<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/>', '')
		nmap_scan.persist_inventory(nmap_scan.parse_xml(bare))
		ftp = IpAddress.objects.get(address='192.0.2.30').ports.get(number=21)
		self.assertEqual(ftp.banner, '220 (vsFTPd 3.0.5)')
		self.assertIn('ftp-anon', ftp.extra['scripts'])


class ReviewedScriptsTests(TestCase):
	# nmap's -sV runs its whole "version" NSE category on top of whatever --script asked for (rpcinfo, hnap-info, and
	# more), unasked and unreviewed; persist_inventory must never let that reach storage, search, or the host page.
	def test_a_script_outside_nse_scripts_is_dropped_but_a_reviewed_one_is_kept(self):
		xml = NSE_XML.replace(
			'<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/>',
			'<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/>'
			'<script id="rpcinfo" output="ERROR: Script execution failed (use -d to debug)"/>')
		nmap_scan.persist_inventory(nmap_scan.parse_xml(xml))
		ftp = IpAddress.objects.get(address='192.0.2.30').ports.get(number=21)
		self.assertIn('ftp-anon', ftp.extra['scripts'])
		self.assertNotIn('rpcinfo', ftp.extra['scripts'])
		self.assertNotIn('rpcinfo', ftp.extra['script_text'])

	def test_a_port_with_only_unreviewed_scripts_keeps_the_last_reviewed_output(self):
		nmap_scan.persist_inventory(nmap_scan.parse_xml(NSE_XML))
		only_unreviewed = NSE_XML.replace(
			'<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/>',
			'<script id="vmware-version" output="ERROR: Script execution failed (use -d to debug)"/>')
		only_unreviewed = only_unreviewed.replace('<script id="banner" output="220 (vsFTPd 3.0.5)"/>', '')
		nmap_scan.persist_inventory(nmap_scan.parse_xml(only_unreviewed))
		ftp = IpAddress.objects.get(address='192.0.2.30').ports.get(number=21)
		self.assertIn('ftp-anon', ftp.extra['scripts'])  # the earlier, reviewed run's output survives
		self.assertNotIn('vmware-version', ftp.extra['scripts'])

	def test_an_unreviewed_host_script_is_dropped(self):
		xml = NSE_XML.replace(
			'<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2022&#xa;Computer name: WIN-ACME"/></hostscript>',
			'<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2022&#xa;Computer name: WIN-ACME"/>'
			'<script id="hnap-info" output="ERROR: Script execution failed (use -d to debug)"/></hostscript>')
		nmap_scan.persist_inventory(nmap_scan.parse_xml(xml))
		ip = IpAddress.objects.get(address='192.0.2.30')
		self.assertIn('smb-os-discovery', ip.fingerprint['scripts'])
		self.assertNotIn('hnap-info', ip.fingerprint['scripts'])


class OversizedBannerTests(TestCase):
	def test_long_strings_from_the_target_are_clipped_and_do_not_cost_the_chunk(self):
		huge = 'A' * 5000
		inventory = [{'ip': '192.0.2.77', 'os_guess': huge, 'os_accuracy': 90, 'ports': [
			{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 's' * 500, 'product': huge, 'version': huge,
			 'service_extra': huge, 'cpe': huge, 'cpes': [], 'scripts': {}, 'banner': huge},
			{'number': 80, 'protocol': 'tcp', 'state': 'open', 'service_name': 'http', 'product': 'nginx', 'version': '1.18.0',
			 'service_extra': '', 'cpe': '', 'cpes': [], 'scripts': {}, 'banner': ''}]}]
		result = nmap_scan.persist_inventory(inventory)
		self.assertEqual(result['ports'], 2)
		ip = IpAddress.objects.get(address='192.0.2.77')
		self.assertEqual(len(ip.os_guess), 255)
		self.assertEqual(len(ip.ports.get(number=22).product), 255)
		self.assertEqual(ip.ports.get(number=80).product, 'nginx')
