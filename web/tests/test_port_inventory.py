from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import port_inventory
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
</host><runstats><finished exit="success"/></runstats></nmaprun>'''

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


class PersistInventoryTests(TestCase):
	def test_creates_ip_and_port_rows_with_os_and_service_fields(self):
		result = port_inventory.persist_inventory(port_inventory.parse_xml(FAST_XML))
		self.assertEqual(result, {'ports': 1, 'hosts_with_os': 1})
		ip = IpAddress.objects.get(address='192.0.2.10')
		self.assertEqual((ip.os_guess, ip.os_accuracy), ('Linux 5.X', 95))
		self.assertIsNotNone(ip.last_seen)
		port = ip.ports.get(number=22)
		self.assertEqual((port.protocol, port.product, port.version, port.service_extra, port.source),
			('tcp', 'OpenSSH', '8.9', 'Ubuntu', 'nmap'))

	def test_rescan_updates_the_ips_own_port_row_in_place(self):
		port_inventory.persist_inventory(port_inventory.parse_xml(FAST_XML))
		ip = IpAddress.objects.get(address='192.0.2.10')
		ip.ports.filter(number=22).update(version='8.8')
		port_inventory.persist_inventory(port_inventory.parse_xml(FAST_XML))
		self.assertEqual(Port.objects.filter(number=22).count(), 1)
		self.assertEqual(ip.ports.get(number=22).version, '8.9')

	def test_a_run_without_service_detection_keeps_what_a_fingerprinting_pass_found(self):
		"""S04-3: the -p- sweep and naabu know only that a port is open."""
		probed = {'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '8.9p1',
			'service_extra': 'Ubuntu Linux; protocol 2.0', 'cpes': ['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:linux:linux_kernel'], 'method': 'probed', 'tunnel': 'ssl'}
		port_inventory.persist_inventory([{'ip': '192.0.2.40', 'os_guess': '', 'os_accuracy': None, 'ports': [probed]}])
		port = IpAddress.objects.get(address='192.0.2.40').ports.get(number=22)
		before = (port.distro, port.package_release, port.extra['cpes'], port.extra['method'], port.extra['tunnel'], port.service_name, port.product, port.version)
		self.assertEqual(before[4], 'ssl')
		sweep = {'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh', 'method': 'table', 'confidence': '3'}
		port_inventory.persist_inventory([{'ip': '192.0.2.40', 'os_guess': '', 'os_accuracy': None, 'ports': [sweep, {'number': 9999, 'state': 'open'}]}], source='fullscan')
		naabu = [{'ip': '192.0.2.40', 'os_guess': '', 'ports': [{'number': 22, 'state': 'open', 'protocol': 'tcp'}]}]
		port_inventory.persist_inventory(naabu, source='naabu')
		port = IpAddress.objects.get(address='192.0.2.40').ports.get(number=22)
		self.assertEqual((port.distro, port.package_release, port.extra['cpes'], port.extra['method'], port.extra['tunnel'], port.service_name, port.product, port.version), before)
		self.assertEqual((port.state, port.source), ('open', 'nmap'))
		self.assertTrue(IpAddress.objects.get(address='192.0.2.40').ports.filter(number=9999).exists())  # a new port is still recorded

	def test_a_product_on_one_ip_is_not_visible_on_another(self):
		def host(ip, product):
			return [{'ip': ip, 'os_guess': '', 'os_accuracy': None, 'ports': [
				{'number': 443, 'protocol': 'tcp', 'state': 'open', 'service_name': 'https', 'product': product, 'version': '1'}]}]
		port_inventory.persist_inventory(host('192.0.2.1', 'nginx'))
		port_inventory.persist_inventory(host('192.0.2.2', 'Apache httpd'))
		self.assertEqual(IpAddress.objects.get(address='192.0.2.1').ports.get(number=443).product, 'nginx')
		self.assertEqual(IpAddress.objects.get(address='192.0.2.2').ports.get(number=443).product, 'Apache httpd')

	def test_a_port_row_shared_by_older_code_is_split_not_overwritten(self):
		shared = Port.objects.create(number=443, product='nginx', version='1')
		for address in ('192.0.2.1', '192.0.2.2'):
			IpAddress.objects.create(address=address).ports.add(shared)
		port_inventory.persist_inventory([{'ip': '192.0.2.2', 'os_guess': '', 'os_accuracy': None,
			'ports': [{'number': 443, 'product': 'Caddy', 'version': '2'}]}])
		self.assertEqual(IpAddress.objects.get(address='192.0.2.1').ports.get(number=443).product, 'nginx')
		self.assertEqual(IpAddress.objects.get(address='192.0.2.2').ports.get(number=443).product, 'Caddy')

	def test_host_without_ip_is_skipped(self):
		self.assertEqual(port_inventory.persist_inventory([{'ip': None, 'os_guess': '', 'os_accuracy': None, 'ports': []}]),
			{'ports': 0, 'hosts_with_os': 0})

	def test_port_without_number_is_skipped(self):
		inventory = [{'ip': '192.0.2.5', 'os_guess': '', 'os_accuracy': None,
		              'ports': [{'number': None, 'protocol': 'tcp'}]}]
		result = port_inventory.persist_inventory(inventory)
		self.assertEqual(result, {'ports': 0, 'hosts_with_os': 0})
		self.assertEqual(IpAddress.objects.get(address='192.0.2.5').ports.count(), 0)

def _report(ports, scanned='22,80,443,3306,8080', extraports='closed', status='up'):
	"""A one-host nmap XML report: ``ports`` is [(number, state, product, version)]; the run probed ``scanned``."""
	body = ''.join(f'<port protocol="tcp" portid="{n}"><state state="{state}"/>'
		f'<service name="svc" product="{product}" version="{version}"/></port>' for n, state, product, version in ports)
	extra = f'<extraports state="{extraports}" count="3"/>' if extraports else ''
	return (f'<?xml version="1.0"?><nmaprun><scaninfo type="syn" protocol="tcp" numservices="5" services="{scanned}"/>'
		f'<host><status state="{status}"/><address addr="192.0.2.77" addrtype="ipv4"/><ports>{extra}{body}</ports></host><runstats><finished exit="success"/></runstats></nmaprun>')

class OpenPortStateTests(TestCase):
	def setUp(self):
		patcher = mock.patch('targetApp.target_types.blocked_names', return_value=set())
		patcher.start()
		self.addCleanup(patcher.stop)

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
		host = port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')], scanned='22,80-82,8080'))[0]
		self.assertEqual(host['scanned'], {22, 80, 81, 82, 8080})
		self.assertEqual((host['status'], host['extraports']), ('up', ['closed']))

	def test_a_cdn_or_shared_edge_address_is_not_a_nuclei_target(self):
		from cveFeed.nuclei_scan import scan_targets
		self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(443, 'open', 'nginx', '1.18.0')])))
		self.assertEqual(scan_targets(self.scan)[1], {'192.0.2.77'})
		IpAddress.objects.filter(pk=self.ip.pk).update(is_cdn=True)
		hostnames, ips, ports = scan_targets(self.scan)
		self.assertEqual((hostnames, ips, ports), ({'www.ports.test'}, set(), set()))  # S04-13: the name is still scanned, the edge address is not

	def test_a_filtered_port_is_not_a_target_and_not_correlated(self):
		from cveFeed import correlation
		from cveFeed.nuclei_scan import scan_targets
		sub = self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([
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
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(8080, 'open', 'nginx', '1.18.0')])))
		cve = type('C', (), {'id': 1, 'affected': [{'product': 'nginx', 'ranges': [{'fixed': '1.20'}]}], 'kev': False})()
		rows = correlation.collect_subdomain_matches(sub, correlation.build_product_index([cve]), {1: cve})
		self.assertEqual([r['version_in_range'] for r in rows], [True])

	def test_a_port_absent_from_the_next_run_is_closed_not_retained(self):
		self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.18.0')])))
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')])))
		self.assertEqual(self.ip.ports.get(number=8080).state, 'closed')
		self.assertEqual(self.ip.ports.get(number=22).state, 'open')

	def test_a_port_outside_the_probed_set_is_left_alone(self):
		self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (9200, 'open', 'Elasticsearch', '7.10')],
			scanned='22,80,443,9200')))
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')], scanned='22,80,443')))  # never tried 9200
		self.assertEqual(self.ip.ports.get(number=9200).state, 'open')

	def test_a_silent_host_does_not_wipe_what_was_open(self):
		self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')])))
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([], extraports='filtered')))  # everything dropped: unreachable, not closed
		self.assertEqual(self.ip.ports.get(number=22).state, 'open')

	def test_a_closed_port_that_opens_again_is_open(self):
		self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.18.0')])))
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9')])))
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.26.0')])))
		port = self.ip.ports.get(number=8080)
		self.assertEqual((port.state, port.version), ('open', '1.26.0'))

	def test_closed_ports_are_not_listed_by_the_inventory_or_probed_for_hygiene_and_db_exposure(self):
		from cveFeed import hygiene
		from startScan.models import open_ports
		sub = self._sub_with_ip()
		port_inventory.persist_inventory(port_inventory.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (3306, 'closed', 'MySQL', '5.7')])))
		self.assertEqual([p.number for p in open_ports(self.ip)], [22])
		port_inventory.persist_inventory([{'ip': '192.0.2.77', 'ports': [{'number': 8443, 'state': 'filtered'}]}])
		self.assertNotIn(('www.ports.test', 8443), hygiene.tls_targets(sub.target_domain))
		port_inventory.persist_inventory([{'ip': '192.0.2.77', 'ports': [{'number': 8443, 'state': 'open'}]}])
		self.assertIn(('www.ports.test', 8443), hygiene.tls_targets(sub.target_domain))

class NseCaptureTests(TestCase):
	def test_the_parser_keeps_each_ports_script_output_and_banner(self):
		ports = {p['number']: p for p in port_inventory.parse_xml(NSE_XML)[0]['ports']}
		self.assertEqual(ports[21]['banner'], '220 (vsFTPd 3.0.5)')  # the banner script wins
		self.assertIn('Anonymous FTP login allowed', ports[21]['scripts']['ftp-anon'])
		self.assertEqual(ports[22]['scripts'], {'ssh-hostkey': '256 aa:bb (ED25519)'})
		self.assertEqual(ports[8080]['banner'], 'SF-Port8080-TCP:V=7.99')  # no banner script: nmap's own probe bytes
		self.assertEqual(ports[8080]['scripts'], {})

	def test_the_parser_keeps_host_level_scripts(self):
		host = port_inventory.parse_xml(NSE_XML)[0]
		self.assertIn('Windows Server 2022', host['hostscripts']['smb-os-discovery'])

	def test_a_report_without_scripts_has_none(self):
		host = port_inventory.parse_xml(FAST_XML)[0]
		self.assertEqual(host['hostscripts'], {})
		self.assertEqual(host['ports'][0]['scripts'], {})

	def test_script_output_is_capped(self):
		from cvengine_scanner.nmap import BANNER_CAP, SCRIPT_OUTPUT_CAP
		xml = ('<nmaprun><host><address addr="192.0.2.31" addrtype="ipv4"/><ports><port protocol="tcp" portid="25">'
			'<state state="open"/><service name="smtp"/><script id="banner" output="' + 'A' * 9000 + '"/></port></ports></host></nmaprun>')
		port = port_inventory.parse_xml(xml)[0]['ports'][0]
		self.assertEqual(len(port['banner']), BANNER_CAP)
		self.assertEqual(len(port['scripts']['banner']), SCRIPT_OUTPUT_CAP)

	def test_persisting_stores_banner_scripts_and_host_scripts(self):
		port_inventory.persist_inventory(port_inventory.parse_xml(NSE_XML))
		ip = IpAddress.objects.get(address='192.0.2.30')
		ftp = ip.ports.get(number=21)
		self.assertEqual(ftp.banner, '220 (vsFTPd 3.0.5)')
		self.assertIn('ftp-anon', ftp.extra['scripts'])
		self.assertIn('smb-os-discovery', ip.fingerprint['scripts'])

	def test_a_rescan_without_scripts_keeps_the_last_banner(self):
		port_inventory.persist_inventory(port_inventory.parse_xml(NSE_XML))
		bare = NSE_XML.replace('<script id="banner" output="220 (vsFTPd 3.0.5)"/>', '')
		bare = bare.replace('<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/>', '')
		port_inventory.persist_inventory(port_inventory.parse_xml(bare))
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
		port_inventory.persist_inventory(port_inventory.parse_xml(xml))
		ftp = IpAddress.objects.get(address='192.0.2.30').ports.get(number=21)
		self.assertIn('ftp-anon', ftp.extra['scripts'])
		self.assertNotIn('rpcinfo', ftp.extra['scripts'])
		self.assertNotIn('rpcinfo', ftp.extra['script_text'])

	def test_a_port_with_only_unreviewed_scripts_keeps_the_last_reviewed_output(self):
		port_inventory.persist_inventory(port_inventory.parse_xml(NSE_XML))
		only_unreviewed = NSE_XML.replace(
			'<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x 2 ftp ftp 4096 pub"/>',
			'<script id="vmware-version" output="ERROR: Script execution failed (use -d to debug)"/>')
		only_unreviewed = only_unreviewed.replace('<script id="banner" output="220 (vsFTPd 3.0.5)"/>', '')
		port_inventory.persist_inventory(port_inventory.parse_xml(only_unreviewed))
		ftp = IpAddress.objects.get(address='192.0.2.30').ports.get(number=21)
		self.assertIn('ftp-anon', ftp.extra['scripts'])  # the earlier, reviewed run's output survives
		self.assertNotIn('vmware-version', ftp.extra['scripts'])

	def test_an_unreviewed_host_script_is_dropped(self):
		xml = NSE_XML.replace(
			'<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2022&#xa;Computer name: WIN-ACME"/></hostscript>',
			'<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2022&#xa;Computer name: WIN-ACME"/>'
			'<script id="hnap-info" output="ERROR: Script execution failed (use -d to debug)"/></hostscript>')
		port_inventory.persist_inventory(port_inventory.parse_xml(xml))
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
		result = port_inventory.persist_inventory(inventory)
		self.assertEqual(result['ports'], 2)
		ip = IpAddress.objects.get(address='192.0.2.77')
		self.assertEqual(len(ip.os_guess), 255)
		self.assertEqual(len(ip.ports.get(number=22).product), 255)
		self.assertEqual(ip.ports.get(number=80).product, 'nginx')

class ProductChangeTests(TestCase):
	def rec(self, **kw):
		base = {'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh', 'scripts': {}, 'cpes': [], 'banner': '',
				'product': '', 'version': '', 'service_extra': '', 'cpe': ''}
		return [{'ip': '192.0.2.88', 'ports': [{**base, **kw}]}]

	def test_a_new_product_without_a_version_does_not_inherit_the_old_products_version_cpe_and_banner(self):
		port_inventory.persist_inventory(self.rec(product='OpenSSH', version='7.4', cpe='cpe:/a:openbsd:openssh:7.4', banner='SSH-2.0-OpenSSH_7.4'))
		port_inventory.persist_inventory(self.rec(product='Dropbear sshd'))  # the next scan found another server and no version
		port = IpAddress.objects.get(address='192.0.2.88').ports.get(number=22)
		self.assertEqual((port.product, port.version, port.cpe, port.banner), ('Dropbear sshd', '', '', ''))

	def test_the_same_product_keeps_what_an_incomplete_scan_did_not_repeat(self):
		port_inventory.persist_inventory(self.rec(product='OpenSSH', version='7.4'))
		port_inventory.persist_inventory(self.rec(product='OpenSSH'))
		self.assertEqual(IpAddress.objects.get(address='192.0.2.88').ports.get(number=22).version, '7.4')

class ProbedServiceNameTests(TestCase):
	"""#408: a soft match that did not finish (nmap reports it with method "table") still names the service; a later run that only knows the
	port is open must not replace that name with the port table's guess."""

	def test_a_port_table_guess_does_not_replace_a_soft_matched_name(self):
		soft = {'number': 5353, 'protocol': 'tcp', 'state': 'open', 'service_name': 'domain', 'service_extra': 'generic dns response: REFUSED',
			'method': 'table', 'confidence': '3'}
		port_inventory.persist_inventory([{'ip': '192.0.2.53', 'os_guess': '', 'os_accuracy': None, 'ports': [soft]}])
		sweep = {'number': 5353, 'protocol': 'tcp', 'state': 'open', 'service_name': 'mdns', 'method': 'table', 'confidence': '3'}
		port_inventory.persist_inventory([{'ip': '192.0.2.53', 'os_guess': '', 'os_accuracy': None, 'ports': [sweep]}], source='fullscan')
		port = IpAddress.objects.get(address='192.0.2.53').ports.get(number=5353)
		self.assertEqual((port.service_name, port.service_extra, port.state), ('domain', 'generic dns response: REFUSED', 'open'))

	def test_a_probed_answer_still_replaces_the_stored_guess(self):
		Port.objects.create(number=5353, protocol='tcp', service_name='mdns', service_extra='generic dns response: REFUSED',
			extra={'method': 'table', 'confidence': '3'})
		IpAddress.objects.create(address='192.0.2.53').ports.add(Port.objects.get(number=5353))
		probed = {'number': 5353, 'protocol': 'tcp', 'state': 'open', 'service_name': 'domain', 'service_extra': 'generic dns response: REFUSED',
			'method': 'probed', 'confidence': '10'}
		port_inventory.persist_inventory([{'ip': '192.0.2.53', 'os_guess': '', 'os_accuracy': None, 'ports': [probed]}])
		port = IpAddress.objects.get(address='192.0.2.53').ports.get(number=5353)
		self.assertEqual((port.service_name, port.extra['method']), ('domain', 'probed'))
