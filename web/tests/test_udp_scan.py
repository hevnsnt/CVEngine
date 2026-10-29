import os
from datetime import timedelta
from unittest import mock
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import hygiene, ledger, nmap_scan, udp_scan
from cveFeed.models import AgentActivity, HostExclusion, HygieneFinding, ScanControl, ServiceRun
from dashboard.models import Org, Project, ProjectMembership
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import OPEN_PORT_STATES, IpAddress, Port, ScanHistory, Subdomain, open_ports, open_services
from targetApp.models import Domain
from tests.test_agentapi import call

# nmap -sU -sV output, written to the format nmap 7.9x prints (scaninfo, state with reason, extraports with extrareasons, service
# with method/conf and cpe, script elements). Host 192.0.2.10 answers on four ports and ignores the rest.
ANSWERED = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sU -sV --version-intensity 3 -Pn -n --max-retries 1 --max-rate 20 -p U:123,161,53,69,1900,11211 -oX - 192.0.2.10" version="7.95">
<scaninfo type="udp" protocol="udp" numservices="6" services="53,69,123,161,1900,11211"/>
<host starttime="1" endtime="2"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<ports>
<port protocol="udp" portid="53"><state state="closed" reason="port-unreach" reason_ttl="62"/><service name="domain" method="table" conf="3"/></port>
<port protocol="udp" portid="69"><state state="open|filtered" reason="no-response" reason_ttl="0"/><service name="tftp" method="table" conf="3"/></port>
<port protocol="udp" portid="123"><state state="open" reason="udp-response" reason_ttl="62"/><service name="ntp" product="NTP" version="4.2.8p15" extrainfo="Ubuntu" method="probed" conf="10"><cpe>cpe:/a:ntp:ntp:4.2.8p15</cpe></service><script id="ntp-info" output="&#10;  receive time stamp: Tue Oct 27 10:00:00 2026&#10;  version: ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)&#10;  processor: x86_64&#10;  system: Linux/5.15.0"/></port>
<port protocol="udp" portid="161"><state state="open" reason="udp-response" reason_ttl="62"/><service name="snmp" method="table" conf="3"/><script id="snmp-sysdescr" output="Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)&#10;  System uptime: 41d3h22m5s (354372500 timeticks)"/><script id="snmp-info" output="&#10;  enterprise: ciscoSystems"/></port>
<port protocol="udp" portid="1900"><state state="open|filtered" reason="no-response" reason_ttl="0"/><service name="upnp" method="table" conf="3"/></port>
<port protocol="udp" portid="11211"><state state="open" reason="udp-response" reason_ttl="62"/><service name="memcached" method="table" conf="3"/></port>
</ports><times srtt="21000" rttvar="3000" to="100000"/></host>
</nmaprun>'''

# a host behind a firewall that drops everything: nothing answered, every port open|filtered
SILENT = '''<?xml version="1.0"?>
<nmaprun><scaninfo type="udp" protocol="udp" numservices="3" services="53,123,161"/>
<host><status state="up" reason="user-set"/><address addr="192.0.2.20" addrtype="ipv4"/>
<ports>
<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/><service name="domain" method="table"/></port>
<port protocol="udp" portid="123"><state state="open|filtered" reason="no-response"/><service name="ntp" method="table"/></port>
<port protocol="udp" portid="161"><state state="open|filtered" reason="no-response"/><service name="snmp" method="table"/></port>
</ports></host></nmaprun>'''

# a custom list of 40 ports: nmap summarises the 38 closed ones and lists the two that differ
COLLAPSED = '''<?xml version="1.0"?>
<nmaprun><scaninfo type="udp" protocol="udp" numservices="40" services="1-38,123,161"/>
<host><status state="up" reason="user-set"/><address addr="192.0.2.30" addrtype="ipv4"/>
<ports><extraports state="closed" count="38"><extrareasons reason="port-unreach" count="38" proto="udp" ports="1-38"/></extraports>
<port protocol="udp" portid="123"><state state="open" reason="udp-response"/><service name="ntp" product="NTP" version="4.2.8p15" method="probed"/></port>
<port protocol="udp" portid="161"><state state="open|filtered" reason="no-response"/><service name="snmp" method="table"/></port>
</ports></host></nmaprun>'''


def udp_xml(address, states, extra=''):
	"""A report for ``address`` with ``{port: state}``; a state of ``open`` carries service name ``svc<port>``."""
	body = ''.join(f'<port protocol="udp" portid="{n}"><state state="{s}" reason="x"/><service name="svc{n}" method="table"/></port>'
	               for n, s in states.items())
	return (f'<?xml version="1.0"?><nmaprun><scaninfo type="udp" protocol="udp" services="{",".join(map(str, states))}"/>'
	        f'<host><status state="up"/><address addr="{address}" addrtype="ipv4"/><ports>{body}</ports></host></nmaprun>')


class UdpBase(TestCase):
	def setUp(self):
		now = timezone.now()
		self.org = Org.objects.create(name='U', slug='u')
		self.project = Project.objects.create(name='P', slug='pu', insert_date=now, org=self.org)
		self.domain = Domain.objects.create(name='udp.test', project=self.project, insert_date=now)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=now, scan_status=2, results_dir='/tmp')
		for p in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
		          mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'),
		          mock.patch('cveFeed.udp_scan.CLAIM_KEY', 'cvengine:udpscan:test'),
		          # These fixtures do not build full core-stage coverage; the deep-scan coverage gate (see
		          # cveFeed.coverage_topup.backlog_exists, tests/test_coverage_gate.py) is exercised on its own there.
		          mock.patch('cveFeed.coverage_topup.backlog_exists', return_value=False),
		          mock.patch.dict(os.environ, {}, clear=False)):
			p.start()
		self.addCleanup(mock.patch.stopall)
		client = getattr(resources.get_store(), 'r', None)
		for key in ('cvengine:sweep:udp-unavailable-note', 'cvengine:sweep:udp-kick', udp_scan.STATUS_KEY, udp_scan.CLAIM_KEY):
			if client is not None:  # a key a previous test run left in Redis would hide what this one checks
				client.delete(key)
		udp_scan._last_status.clear()
		for name in ('CVENGINE_UDPSCAN', 'CVENGINE_UDPSCAN_PORTS', 'CVENGINE_ALLOW_PRIVATE_TARGETS', 'CVENGINE_UDPSCAN_MAX_RATE'):
			os.environ.pop(name, None)

	def ip(self, address, name=None, cdn=False, scan=None):
		ip = IpAddress.objects.create(address=address, org=self.org, is_cdn=cdn)
		if name is not False:
			sub = Subdomain.objects.create(scan_history=scan or self.scan, target_domain=self.domain, name=name or f'h{address.split(".")[-1]}.udp.test')
			sub.ip_addresses.add(ip)
		return ip

	def host_of(self, xml, address):
		return next(h for h in nmap_scan.parse_xml(xml) if h['ip'] == address)

	def udp(self, ip, number=None):
		rows = ip.ports.filter(protocol='udp')
		return rows.filter(number=number).get() if number else rows


class ParsingTests(SimpleTestCase):
	def test_a_real_shaped_report_gives_a_state_per_udp_port(self):
		host = nmap_scan.parse_xml(ANSWERED)[0]
		states = {r['number']: (r['protocol'], r['state']) for r in host['ports']}
		self.assertEqual(states, {53: ('udp', 'closed'), 69: ('udp', 'open|filtered'), 123: ('udp', 'open'), 161: ('udp', 'open'),
		                          1900: ('udp', 'open|filtered'), 11211: ('udp', 'open')})
		self.assertEqual(host['scanned_udp'], {53, 69, 123, 161, 1900, 11211})
		self.assertIsNone(host['scanned'])  # a UDP run says nothing about TCP: no TCP port may be closed by it

	def test_a_version_detected_service_keeps_product_version_and_cpe(self):
		ntp = next(r for r in nmap_scan.parse_xml(ANSWERED)[0]['ports'] if r['number'] == 123)
		self.assertEqual((ntp['product'], ntp['version'], ntp['service_extra'], ntp['cpe'], ntp['method']),
		                 ('NTP', '4.2.8p15', 'Ubuntu', 'cpe:/a:ntp:ntp:4.2.8p15', 'probed'))
		self.assertIn('ntpd 4.2.8p15', ntp['scripts']['ntp-info'])

	def test_classify_reads_open_open_filtered_closed_and_summarised_ports(self):
		states, answered = udp_scan.classify(nmap_scan.parse_xml(ANSWERED)[0])
		self.assertEqual(states[123], 'open')
		self.assertEqual(states[69], 'open|filtered')
		self.assertEqual(states[53], 'closed')
		self.assertTrue(answered)
		states, answered = udp_scan.classify(nmap_scan.parse_xml(COLLAPSED)[0])
		self.assertEqual((states[7], states[38], states[123], states[161]), ('closed', 'closed', 'open', 'open|filtered'))  # extraports fill the rest
		self.assertEqual(len(states), 40)

	def test_a_host_that_only_stays_silent_has_not_answered(self):
		states, answered = udp_scan.classify(nmap_scan.parse_xml(SILENT)[0])
		self.assertEqual(set(states.values()), {'open|filtered'})
		self.assertFalse(answered)

	def test_only_reviewed_scripts_survive_and_the_udp_ones_are_reviewed(self):
		self.assertTrue(set(nmap_scan.UDP_NSE_SCRIPTS) <= nmap_scan.NSE_SCRIPT_SET)
		self.assertNotIn('ntp-monlist', nmap_scan.NSE_SCRIPT_SET)  # nmap files it under intrusive, and the target records it
		self.assertNotIn('snmp-brute', nmap_scan.NSE_SCRIPT_SET)
		self.assertEqual(nmap_scan._reviewed_scripts({'snmp-sysdescr': 'x', 'ntp-monlist': 'y', 'ike-version': 'z'}), {'snmp-sysdescr': 'x'})


class FlagTests(SimpleTestCase):
	def test_the_command_is_slow_and_low(self):
		flags = udp_scan.nmap_flags()
		self.assertEqual(flags[:2], ['-sU', '-sV'])
		self.assertEqual(flags[flags.index('--version-intensity') + 1], '3')
		self.assertEqual(flags[flags.index('--max-retries') + 1], '1')
		self.assertEqual(flags[flags.index('--max-rate') + 1], '20')
		self.assertIn('-Pn', flags)
		self.assertIn('-n', flags)
		self.assertNotIn('-T4', flags)
		self.assertNotIn('-p-', flags)
		scripts = flags[flags.index('--script') + 1].split(',')
		self.assertTrue(set(scripts) <= nmap_scan.NSE_SCRIPT_SET)
		self.assertEqual(flags[flags.index('-p') + 1], 'U:' + ','.join(str(p) for p in udp_scan.DEFAULT_PORTS))
		self.assertEqual(udp_scan.host_timeout(), '20m')

	def test_the_default_list_is_the_documented_exposure_list(self):
		self.assertEqual(set(udp_scan.DEFAULT_PORTS), set(udp_scan.PORT_NOTES))
		for port in (53, 67, 68, 69, 123, 137, 161, 500, 514, 623, 1194, 1812, 1813, 1900, 4500, 5060, 5353, 11211):
			self.assertIn(port, udp_scan.DEFAULT_PORTS)

	def test_the_port_list_and_rate_are_configurable_and_a_bad_list_is_ignored(self):
		with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN_PORTS': '161, 123,161', 'CVENGINE_UDPSCAN_MAX_RATE': '5'}):
			self.assertEqual(udp_scan.ports(), [123, 161])
			self.assertEqual(udp_scan.nmap_flags()[udp_scan.nmap_flags().index('--max-rate') + 1], '5')
		for bad in ('', 'dns', '0', '70000', '161,abc', ','.join(str(n) for n in range(1, 80))):
			with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN_PORTS': bad}):
				self.assertEqual(udp_scan.ports(), list(udp_scan.DEFAULT_PORTS), bad)
		with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN_MAX_RATE': 'fast'}):
			self.assertEqual(udp_scan.max_rate(), 20)

	def test_the_off_switch(self):
		for value, expected in (('0', False), ('off', False), ('1', True), ('', True)):
			with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN': value}):
				self.assertEqual(udp_scan.enabled(), expected, value)

	def test_it_is_on_by_default_and_only_the_switch_turns_it_off(self):
		env = {k: v for k, v in os.environ.items() if k != 'CVENGINE_UDPSCAN'}
		with mock.patch.dict(os.environ, env, clear=True):
			self.assertTrue(udp_scan.enabled())
		for value in ('0', 'false', 'no', 'off'):
			with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN': value}):
				self.assertFalse(udp_scan.enabled(), value)

	def test_the_heavy_kind_and_queue_are_registered(self):
		from cveFeed.tasks import background_full_scan, udp_scan_sweep
		from agentapi import system_status
		self.assertEqual((udp_scan_sweep.name, udp_scan_sweep.queue), ('udp_scan_sweep', 'udp_queue'))
		self.assertEqual(resources.MAX_CONCURRENT['nmap-udp-bg'], 1)
		self.assertIn('nmap-udp-bg', resources.BASE_COSTS_MB)
		self.assertIn('udp_queue', system_status.QUEUES)
		here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		with open(os.path.join(here, 'celery-entrypoint.sh'), encoding='utf-8') as handle:
			self.assertIn('udp_queue', handle.read())
		self.assertEqual(background_full_scan.name, 'background_full_scan')


class PortKeyTests(UdpBase):
	"""UDP 161 and TCP 161 are two services on one address."""

	def test_tcp_and_udp_ports_with_one_number_are_two_rows(self):
		ip = self.ip('192.0.2.10')
		tcp = '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="161"><state state="open"/><service name="http" product="Acme" version="1"/></port></ports></host></nmaprun>'
		nmap_scan.persist_inventory(nmap_scan.parse_xml(tcp), org_id=self.org.id)
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(ip.ports.filter(number=161).count(), 2)
		self.assertEqual(ip.ports.get(number=161, protocol='tcp').product, 'Acme')
		self.assertEqual(ip.ports.get(number=161, protocol='udp').service_name, 'snmp')
		# a TCP re-scan updates the TCP row and leaves the UDP one alone
		nmap_scan.persist_inventory(nmap_scan.parse_xml(tcp.replace('version="1"', 'version="2"')), org_id=self.org.id)
		self.assertEqual(ip.ports.get(number=161, protocol='tcp').version, '2')
		self.assertEqual(ip.ports.get(number=161, protocol='udp').state, 'open')
		self.assertEqual(ip.ports.filter(number=161).count(), 2)

	def test_a_legacy_row_with_no_protocol_is_still_the_tcp_row(self):
		ip = self.ip('192.0.2.10')
		legacy = Port.objects.create(number=161, protocol='', state='open')
		ip.ports.add(legacy)
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(ip.ports.filter(number=161).count(), 2)
		legacy.refresh_from_db()
		self.assertEqual((legacy.protocol, legacy.state), ('', 'open'))

	def test_a_tcp_scan_never_closes_a_udp_port_and_a_udp_scan_never_closes_tcp(self):
		ip = self.ip('192.0.2.10')
		ip.ports.add(Port.objects.create(number=53, protocol='tcp', state='open'))
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))  # UDP 53 is closed in this report
		self.assertEqual(ip.ports.get(number=53, protocol='tcp').state, 'open')
		tcp_sweep = '<nmaprun><scaninfo type="syn" protocol="tcp" services="1-1000"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><extraports state="closed" count="999"/><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>'
		nmap_scan.persist_inventory(nmap_scan.parse_xml(tcp_sweep), org_id=self.org.id)
		self.assertEqual(ip.ports.get(number=161, protocol='udp').state, 'open')
		self.assertEqual(ip.ports.get(number=11211, protocol='udp').state, 'open')

	def test_update_or_create_port_finds_the_tcp_row(self):
		from reNgine.common_func import update_or_create_port
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		port, created = update_or_create_port(161, service_name='http', ip=ip)
		self.assertTrue(created)
		self.assertEqual(port.protocol, 'tcp')
		self.assertEqual(ip.ports.get(number=161, protocol='udp').service_name, 'snmp')


class ExposureTests(UdpBase):
	"""Only an answer is exposure: open|filtered is stored for people to see and counted nowhere."""

	def setUp(self):
		super().setUp()
		self.ip1 = self.ip('192.0.2.10', name='router.udp.test')
		udp_scan.record_run(self.ip1, self.host_of(ANSWERED, '192.0.2.10'))

	def test_the_answered_ports_are_open_and_the_silent_ones_are_not(self):
		self.assertEqual(sorted(p.number for p in open_services(self.ip1)), [123, 161, 11211])
		self.assertEqual(self.udp(self.ip1, 69).state, 'open|filtered')
		self.assertEqual(self.udp(self.ip1, 1900).state, 'open|filtered')
		self.assertFalse(self.ip1.ports.filter(number=53).exists())  # a closed port gets no row
		self.assertNotIn('open|filtered', OPEN_PORT_STATES)

	def test_udp_ports_are_never_connect_targets(self):
		self.assertEqual(open_ports(self.ip1), [])  # every TCP consumer (nuclei, TLS, databases, RDP) reads this
		from cveFeed import route_auth
		self.udp(self.ip1, 11211)
		sub = Subdomain.objects.get(name='router.udp.test')
		self.assertEqual(route_auth.web_bases(Subdomain.objects.prefetch_related('ip_addresses__ports').get(pk=sub.pk)), [])

	def test_a_silent_udp_port_adds_nothing_to_counts_search_or_the_host_record(self):
		member = User.objects.create_user('udp-user', password='x')
		ProjectMembership.objects.create(user=member, project=self.project, role='user')
		_, token = create_token(member, 'udp')

		def names(q):
			status, data = call(token, 'GET', '/api/v1/projects/pu/search?' + urlencode({'q': q}))
			self.assertEqual(status, 200, data)
			return [h['host'] for h in data['results']], data

		self.assertEqual(names('port:123')[0], ['router.udp.test'])
		self.assertEqual(names('port:69')[0], [])  # open|filtered
		self.assertEqual(names('port:1900')[0], [])
		self.assertEqual(names('proto:udp')[0], ['router.udp.test'])
		self.assertEqual(names('proto:udp port:11211')[0], ['router.udp.test'])
		self.assertEqual(names('proto:tcp')[0], [])
		self.assertEqual(names('service:tftp')[0], [])
		self.assertEqual(names('service:upnp')[0], [])
		hosts, _ = names('proto:udp')
		status, data = call(token, 'GET', '/api/v1/projects/pu/search?q=proto:udp')
		self.assertEqual(sorted(p['number'] for p in data['results'][0]['ips'][0]['ports']), [123, 161, 11211])
		self.assertEqual(data['results'][0]['ips'][0]['udp_unanswered'], [69, 1900])
		self.assertEqual(status, 200)
		self.assertEqual(call(token, 'GET', '/api/v1/projects/pu/search?q=proto:icmp')[0], 400)
		why = {h['host']: h['matched'] for h in call(token, 'GET', '/api/v1/projects/pu/search?q=proto:udp')[1]['results']}
		self.assertTrue(any('/udp' in line for line in why['router.udp.test']))

	def test_a_host_that_stays_silent_on_everything_stores_nothing(self):
		quiet = self.ip('192.0.2.20')
		outcome = udp_scan.record_run(quiet, self.host_of(SILENT, '192.0.2.20'))
		self.assertEqual(quiet.ports.count(), 0)  # a firewall that drops UDP says nothing about any port
		self.assertEqual(outcome['open'], [])
		self.assertEqual(outcome['unanswered'], [53, 123, 161])


class ReconcileTests(UdpBase):
	def test_a_port_that_goes_silent_keeps_its_state_for_a_sweep_then_stops_being_open(self):
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {123: 'open', 53: 'closed'}), '192.0.2.10'))
		silent = self.host_of(udp_xml('192.0.2.10', {123: 'open|filtered', 53: 'closed'}), '192.0.2.10')
		udp_scan.record_run(ip, silent)
		port = self.udp(ip, 123)
		self.assertEqual((port.state, port.extra['udp_unanswered']), ('open', 1))  # one lost datagram is not a closed port
		udp_scan.record_run(ip, silent)
		self.assertEqual(self.udp(ip, 123).state, 'open|filtered')
		self.assertEqual(open_services(ip), [])

	def test_an_answer_resets_the_silence_and_a_port_unreachable_closes_it(self):
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {123: 'open', 53: 'closed'}), '192.0.2.10'))
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {123: 'open|filtered', 53: 'closed'}), '192.0.2.10'))
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {123: 'open', 53: 'closed'}), '192.0.2.10'))
		self.assertNotIn('udp_unanswered', self.udp(ip, 123).extra)
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {123: 'closed', 53: 'closed'}), '192.0.2.10'))
		self.assertEqual(self.udp(ip, 123).state, 'closed')

	def test_a_port_the_run_did_not_probe_is_left_alone(self):
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {123: 'open', 161: 'open'}), '192.0.2.10'))
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {53: 'closed'}), '192.0.2.10'))
		self.assertEqual({p.number: p.state for p in self.udp(ip)}, {123: 'open', 161: 'open'})

	def test_a_script_that_no_longer_answers_is_no_longer_evidence(self):
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertIn('snmp-sysdescr', self.udp(ip, 161).extra['scripts'])
		udp_scan.record_run(ip, self.host_of(udp_xml('192.0.2.10', {161: 'open', 53: 'closed'}), '192.0.2.10'))
		self.assertNotIn('scripts', self.udp(ip, 161).extra)

	def test_changed_ports_are_the_new_or_different_services(self):
		ip = self.ip('192.0.2.10')
		first = udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(first['changed'], [123, 161, 11211])
		again = udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(again['changed'], [])

	def test_hostscripts_and_tcp_state_are_untouched_by_a_udp_report(self):
		ip = self.ip('192.0.2.10')
		ip.ports.add(Port.objects.create(number=22, protocol='tcp', state='open', product='OpenSSH'))
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(ip.ports.get(number=22).state, 'open')


class EvidenceTests(UdpBase):
	def test_snmp_sysdescr_names_the_product_when_nmap_did_not(self):
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		snmp = self.udp(ip, 161)
		self.assertEqual((snmp.product, snmp.version), ('Cisco IOS', '15.0(2)SE11'))
		self.assertEqual(snmp.extra['method'], 'probed')

	def test_nmaps_own_product_is_never_overwritten_by_a_script_guess(self):
		ip = self.ip('192.0.2.10')
		xml = ANSWERED.replace('<service name="snmp" method="table" conf="3"/>', '<service name="snmp" product="net-snmp" version="5.9" method="probed" conf="10"/>')
		udp_scan.record_run(ip, self.host_of(xml, '192.0.2.10'))
		self.assertEqual((self.udp(ip, 161).product, self.udp(ip, 161).version), ('net-snmp', '5.9'))

	def test_identify_reads_only_stated_products(self):
		rec = lambda number, **scripts: {'number': number, 'scripts': scripts, 'banner': '', 'service_extra': ''}  # noqa: E731
		self.assertEqual(udp_scan.identify(rec(161, **{'snmp-sysdescr': 'Cisco IOS XE Software, Version 16.9.4, RELEASE SOFTWARE'})), ('Cisco IOS XE', '16.9.4', ''))
		self.assertEqual(udp_scan.identify(rec(161, **{'snmp-sysdescr': 'Juniper Networks, Inc. ex2200 , version JUNOS 12.3R12.4'})), ('Junos OS', '12.3R12.4', ''))
		self.assertIsNone(udp_scan.identify(rec(161, **{'snmp-sysdescr': 'Linux web1 5.15.0-91-generic #101-Ubuntu SMP x86_64'})))  # a kernel string is not a product
		self.assertEqual(udp_scan.identify(rec(1900, **{'upnp-info': 'Server: Linux/3.10 UPnP/1.1 MiniUPnPd/1.9'})), ('MiniUPnPd', '1.9', ''))
		self.assertEqual(udp_scan.identify(rec(123, **{'ntp-info': 'version: ntpd 4.2.6p5@1.2349-o'})), ('NTP', '4.2.6p5', 'cpe:/a:ntp:ntp:4.2.6p5'))
		self.assertIsNone(udp_scan.identify(rec(53)))

	def test_a_udp_service_feeds_the_same_cve_correlation_as_a_tcp_one(self):
		from cveFeed import correlation

		class Cve:
			id, kev, epss_reached, exploit_db, cvss = 99, False, False, False, 9.8
			affected = [{'product': 'ntp', 'vendor': 'ntp', 'ranges': [{'introduced': '4.0.0', 'fixed': '4.2.8p17'}]}]
		ip = self.ip('192.0.2.10', name='time.udp.test')
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		sub = Subdomain.objects.prefetch_related('ip_addresses__ports', 'technologies').get(name='time.udp.test')
		rows = correlation.collect_subdomain_matches(sub, correlation.build_product_index([Cve]), {99: Cve})
		ntp = [r for r in rows if r['evidence'].get('port') == 123]
		self.assertTrue(ntp, rows)
		self.assertEqual(ntp[0]['evidence']['protocol'], 'udp')
		self.assertTrue(ntp[0]['version_in_range'])
		# the same product on a silent (open|filtered) port is not evidence
		Port.objects.filter(protocol='udp', number=123).update(state='open|filtered')
		sub = Subdomain.objects.prefetch_related('ip_addresses__ports', 'technologies').get(name='time.udp.test')
		self.assertFalse([r for r in correlation.collect_subdomain_matches(sub, correlation.build_product_index([Cve]), {99: Cve})
		                  if r['evidence'].get('port') == 123])


class FindingTests(UdpBase):
	def setUp(self):
		super().setUp()
		self.ip1 = self.ip('192.0.2.10', name='edge.udp.test')

	def findings(self, **filters):
		return {f.check_name: f for f in HygieneFinding.objects.filter(domain=self.domain, status='open', **filters)}

	def test_memcached_snmp_public_and_ntp_readvar_are_findings_with_a_fix(self):
		udp_scan.record_run(self.ip1, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(udp_scan.store_findings(self.ip1), 3)
		found = self.findings()
		self.assertEqual(set(found), {'udp_memcached', 'udp_snmp_public', 'udp_ntp_readvar'})
		self.assertEqual((found['udp_memcached'].severity, found['udp_snmp_public'].severity, found['udp_ntp_readvar'].severity),
		                 (udp_scan.HIGH, udp_scan.HIGH, udp_scan.LOW))
		memcached = found['udp_memcached']
		self.assertEqual(memcached.host, 'edge.udp.test')
		self.assertIn('amplif', memcached.detail)
		self.assertIn('Fix:', memcached.detail)
		self.assertTrue(memcached.evidence['remediation'])
		self.assertEqual((memcached.evidence['port'], memcached.evidence['protocol'], memcached.evidence['addresses']), (11211, 'udp', ['192.0.2.10']))
		self.assertIn('Cisco IOS', found['udp_snmp_public'].evidence['answer'])

	def test_snmp_open_without_the_script_answer_is_not_a_public_community_finding(self):
		udp_scan.record_run(self.ip1, self.host_of(udp_xml('192.0.2.10', {161: 'open', 53: 'closed'}), '192.0.2.10'))
		self.assertEqual(udp_scan.store_findings(self.ip1), 0)
		self.assertEqual(self.findings(), {})

	def test_ssdp_and_ipmi_findings_need_an_answer(self):
		xml = udp_xml('192.0.2.10', {1900: 'open', 623: 'open', 53: 'closed'})
		udp_scan.record_run(self.ip1, self.host_of(xml, '192.0.2.10'))
		udp_scan.store_findings(self.ip1)
		self.assertEqual(set(self.findings()), {'udp_ssdp'})  # IPMI needs ipmi-version's own answer, a bare reply is not enough
		xml = ('<nmaprun><scaninfo type="udp" protocol="udp" services="623"/><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>'
		       '<port protocol="udp" portid="623"><state state="open"/><service name="asf-rmcp" method="table"/>'
		       '<script id="ipmi-version" output="&#10;  Version: IPMI-2.0&#10;  UserAuth: password, md5, md2, null"/></port></ports></host></nmaprun>')
		udp_scan.record_run(self.ip1, self.host_of(xml, '192.0.2.10'))
		udp_scan.store_findings(self.ip1)
		self.assertEqual(set(self.findings()), {'udp_ssdp', 'udp_ipmi'})
		self.assertEqual(self.findings()['udp_ipmi'].severity, udp_scan.HIGH)

	def test_a_silent_port_is_never_a_finding(self):
		xml = udp_xml('192.0.2.10', {11211: 'open|filtered', 1900: 'open|filtered', 53: 'closed'})
		udp_scan.record_run(self.ip1, self.host_of(xml, '192.0.2.10'))
		self.assertEqual(udp_scan.store_findings(self.ip1), 0)
		self.assertEqual(HygieneFinding.objects.count(), 0)

	def test_a_finding_is_idempotent_and_resolves_when_the_service_stops_answering(self):
		udp_scan.record_run(self.ip1, self.host_of(ANSWERED, '192.0.2.10'))
		udp_scan.store_findings(self.ip1)
		udp_scan.store_findings(self.ip1)
		self.assertEqual(HygieneFinding.objects.count(), 3)
		udp_scan.record_run(self.ip1, self.host_of(udp_xml('192.0.2.10', {11211: 'closed', 161: 'closed', 123: 'closed'}), '192.0.2.10'))
		self.assertEqual(udp_scan.store_findings(self.ip1), 0)
		self.assertEqual(self.findings(), {})
		self.assertEqual(HygieneFinding.objects.filter(status='resolved').count(), 3)
		udp_scan.record_run(self.ip1, self.host_of(udp_xml('192.0.2.10', {11211: 'open'}), '192.0.2.10'))
		udp_scan.store_findings(self.ip1)
		self.assertEqual(set(self.findings()), {'udp_memcached'})  # it is back: one row, reopened
		self.assertEqual(HygieneFinding.objects.filter(check_name='udp_memcached').count(), 1)

	def test_a_host_with_two_addresses_keeps_what_the_other_address_showed(self):
		second = IpAddress.objects.create(address='192.0.2.11', org=self.org)
		Subdomain.objects.get(name='edge.udp.test').ip_addresses.add(second)
		udp_scan.record_run(self.ip1, self.host_of(udp_xml('192.0.2.10', {11211: 'open'}), '192.0.2.10'))
		udp_scan.store_findings(self.ip1)
		udp_scan.record_run(second, self.host_of(udp_xml('192.0.2.11', {11211: 'closed', 53: 'closed'}), '192.0.2.11'))
		udp_scan.store_findings(second)
		self.assertEqual(set(self.findings()), {'udp_memcached'})  # 192.0.2.10 still answers

	def test_an_excluded_host_gets_no_finding(self):
		HostExclusion.objects.create(org=self.org, host='edge.udp.test')
		udp_scan.record_run(self.ip1, self.host_of(ANSWERED, '192.0.2.10'))
		self.assertEqual(udp_scan.store_findings(self.ip1), 0)
		self.assertEqual(HygieneFinding.objects.count(), 0)

	def test_the_tls_and_email_hygiene_run_does_not_resolve_udp_findings(self):
		udp_scan.record_run(self.ip1, self.host_of(ANSWERED, '192.0.2.10'))
		udp_scan.store_findings(self.ip1)
		hygiene.store_findings(self.domain, [], owns=lambda check: not check.startswith(('ts_', 'udp_')))
		self.assertEqual(len(self.findings()), 3)
		with mock.patch('cveFeed.hygiene.probe_tls', return_value=None):
			hygiene.run_hygiene(self.domain.id, probe=lambda *a, **k: None, emailer=lambda name: ([], None), mx=lambda *a: False)
		self.assertEqual(len(self.findings()), 3)


class SweepTests(UdpBase):
	def runner(self, xml_for=None):
		calls = []

		def run(targets, flags, host_timeout):
			calls.append((list(targets), list(flags), host_timeout))
			return (xml_for or (lambda a: ANSWERED.replace('192.0.2.10', a)))(targets[0])
		run.calls = calls
		return run

	def test_a_sweep_scans_one_ip_records_it_and_stamps_the_ledger(self):
		ip = self.ip('192.0.2.10', name='edge.udp.test')
		runner = self.runner()
		out = udp_scan.run(runner=runner, pipeline=lambda d, n: None)
		self.assertEqual(len(out['scanned']), 1)
		result = out['scanned'][0]
		self.assertTrue(result['ok'])
		self.assertEqual((result['open'], result['findings']), ([123, 161, 11211], 3))
		self.assertEqual(runner.calls[0][0], ['192.0.2.10'])  # one IP per nmap process
		self.assertEqual(runner.calls[0][1], udp_scan.nmap_flags())
		self.assertEqual(sorted(p.number for p in open_services(ip)), [123, 161, 11211])
		self.assertTrue(ledger.fresh(udp_scan.SERVICE, [udp_scan.asset_of(ip)]))
		self.assertEqual(result['retested'], ['edge.udp.test'])
		self.assertTrue(AgentActivity.objects.filter(message__startswith='Background UDP scan of 192.0.2.10: 3 port(s) answered').exists())
		self.assertEqual(udp_scan.recorded_status()['state'], 'ok')

	def test_each_ip_is_scanned_at_most_once_per_ttl_and_the_oldest_goes_first(self):
		a, b, c = self.ip('192.0.2.1'), self.ip('192.0.2.2'), self.ip('192.0.2.3')
		runner = self.runner(lambda addr: udp_xml(addr, {53: 'closed'}))
		udp_scan.run(runner=runner)
		self.assertEqual(sorted(t[0][0] for t in runner.calls), ['192.0.2.1', '192.0.2.2', '192.0.2.3'])  # all in one firing, one at a time
		self.assertTrue(all(len(t[0]) == 1 for t in runner.calls))
		again = self.runner(lambda addr: udp_xml(addr, {53: 'closed'}))
		self.assertEqual(udp_scan.run(runner=again), {'scanned': []})  # the week has not passed
		self.assertEqual(again.calls, [])
		ServiceRun.objects.filter(service=udp_scan.SERVICE, asset=udp_scan.asset_of(b)).update(finished_at=timezone.now() - timedelta(days=8))
		ServiceRun.objects.filter(service=udp_scan.SERVICE, asset=udp_scan.asset_of(c)).update(finished_at=timezone.now() - timedelta(days=9))
		udp_scan.run(runner=again)
		self.assertEqual([t[0][0] for t in again.calls], ['192.0.2.3', '192.0.2.2'])  # stale ones, longest waiting first; a is still fresh
		self.assertIsNotNone(a.pk)

	def test_the_ttl_is_a_week_and_configurable_in_hours(self):
		self.assertEqual(ledger.ttl(udp_scan.SERVICE), 7 * 24 * 3600)
		with mock.patch.dict(os.environ, {'CVENGINE_TTL_UDP_SCAN': '48'}):
			self.assertEqual(ledger.ttl(udp_scan.SERVICE), 48 * 3600)

	def test_the_time_budget_stops_a_firing(self):
		for n in range(1, 4):
			self.ip(f'192.0.2.{n}')
		runner = self.runner(lambda addr: udp_xml(addr, {53: 'closed'}))
		ticks = iter([0, 1, 2, 10 ** 6, 10 ** 6, 10 ** 6])
		out = udp_scan.run(runner=runner, clock=lambda: next(ticks))
		self.assertEqual(len(out['scanned']), 2)

	def test_scanning_paused_runs_nothing(self):
		self.ip('192.0.2.10')
		ScanControl.objects.create(pk=1, paused=True)
		runner = self.runner()
		self.assertEqual(udp_scan.run(runner=runner), {'skipped': 'scanning is paused'})
		self.assertEqual(runner.calls, [])

	def test_a_pause_that_arrives_between_two_addresses_stops_the_next(self):
		self.ip('192.0.2.1')
		self.ip('192.0.2.2')

		def runner(targets, flags, host_timeout):
			ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
			return udp_xml(targets[0], {53: 'closed'})
		out = udp_scan.run(runner=runner)
		self.assertEqual(len(out['scanned']), 2)
		self.assertEqual(out['scanned'][1], {'skipped': 'scanning is paused'})
		self.assertEqual(ServiceRun.objects.filter(service=udp_scan.SERVICE).count(), 1)

	def test_the_off_switch_runs_nothing(self):
		self.ip('192.0.2.10')
		runner = self.runner()
		with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN': '0'}):
			self.assertEqual(udp_scan.run(runner=runner), {'skipped': 'CVENGINE_UDPSCAN is off'})
		self.assertEqual(runner.calls, [])

	def test_one_sweep_at_a_time(self):
		self.ip('192.0.2.10')
		runner = self.runner()
		with resources.redis_claim(udp_scan.CLAIM_KEY, 'someone-else', 60) as mine:
			if mine is not True:
				self.skipTest('nothing to hold the claim with')
			out = udp_scan.run(runner=runner)
		self.assertIn('another UDP sweep is running', out['skipped'])
		self.assertEqual(runner.calls, [])

	def test_a_failed_scan_is_recorded_and_asked_again_tomorrow_not_next_firing(self):
		ip = self.ip('192.0.2.10')

		def broken(targets, flags, host_timeout):
			raise RuntimeError('nmap exploded at /srv/secret/path')
		out = udp_scan.run(runner=broken)
		self.assertEqual(out['scanned'], [{'ip': '192.0.2.10', 'ok': False, 'error': 'RuntimeError'}])
		self.assertFalse(ledger.fresh(udp_scan.SERVICE, [udp_scan.asset_of(ip)]))
		self.assertTrue(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))
		self.assertNotIn('/srv/secret', ' '.join(AgentActivity.objects.values_list('message', flat=True)))  # the raw message stays in the worker log
		runner = self.runner()
		self.assertEqual(udp_scan.run(runner=runner), {'scanned': []})
		self.assertEqual(runner.calls, [])

	def test_an_empty_report_is_a_failure_not_an_all_clear(self):
		ip = self.ip('192.0.2.10')
		out = udp_scan.run(runner=lambda t, f, h: '')
		self.assertFalse(out['scanned'][0]['ok'])
		self.assertFalse(ledger.fresh(udp_scan.SERVICE, [udp_scan.asset_of(ip)]))
		self.assertEqual(ip.ports.count(), 0)

	def test_waiting_for_memory_is_not_the_addresss_failure(self):
		ip = self.ip('192.0.2.10')

		def busy(targets, flags, host_timeout):
			raise resources.MemoryBusy('waited too long')
		udp_scan.run(runner=busy)
		self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))

	def test_the_default_runner_uses_the_udp_heavy_job_and_rechecks_scope_before_launch(self):
		with mock.patch('cveFeed.nmap_scan.run_nmap_xml', return_value='') as run:
			udp_scan._runner(['192.0.2.10'], udp_scan.nmap_flags(), '20m', org_id=self.org.id)
		self.assertEqual(run.call_args.kwargs['kind'], 'nmap-udp-bg')
		self.assertTrue(callable(run.call_args.kwargs['before_launch']))

	def test_a_host_excluded_while_the_job_waits_is_never_scanned(self):
		self.ip('192.0.2.10', name='edge.udp.test')
		launched = []

		def fake_nmap(targets, flags, host_timeout, kind=None, wait_timeout=None, before_launch=None):
			HostExclusion.objects.create(org=self.org, host='edge.udp.test')  # excluded while it waited for memory
			before_launch()
			launched.append(targets)
			return ANSWERED
		with mock.patch('cveFeed.nmap_scan.run_nmap_xml', fake_nmap):
			result = udp_scan.scan_ip(IpAddress.objects.get(address='192.0.2.10'))
		self.assertEqual(launched, [])
		self.assertFalse(result['ok'])
		self.assertEqual(Port.objects.count(), 0)


class GatingTests(UdpBase):
	"""The same gate as the TCP sweep: nothing is scanned that a scanner may not touch."""

	def test_out_of_scope_cdn_blocked_private_and_excluded_addresses_are_never_chosen(self):
		self.ip('192.0.2.1', cdn=True)
		self.ip('192.0.2.2', name=False)  # attached to no host
		self.ip('10.1.2.3')  # private
		self.ip('127.0.0.1')  # always blocked
		self.ip('198.51.100.7', name='gone.udp.test')
		HostExclusion.objects.create(org=self.org, host='gone.udp.test')
		orphan = Domain.objects.create(name='orphan.test', insert_date=timezone.now())  # no project
		lonely = IpAddress.objects.create(address='192.0.2.9')
		Subdomain.objects.create(scan_history=self.scan, target_domain=orphan, name='x.orphan.test').ip_addresses.add(lonely)
		self.assertIsNone(udp_scan.pick())
		with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
			self.assertEqual(udp_scan.pick().address, '10.1.2.3')

	def test_a_project_whose_bounty_engagement_has_not_confirmed_automated_testing_is_not_scanned(self):
		from cveFeed.models import BountyAsset, BountyEngagement, BountyProgram
		program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
		BountyAsset.objects.create(program=program, kind='domain', identifier='bb.udp.test')  # the scope names the host (cveFeed.bounty_gate)
		engagement = BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
		ip = self.ip('192.0.2.1', name='bb.udp.test')
		self.assertIsNone(udp_scan.pick())
		self.assertEqual(udp_scan.due(), [])
		runner = []
		self.assertEqual(udp_scan.run(runner=lambda *a: runner.append(a))['scanned'], [])
		self.assertEqual(runner, [])
		BountyEngagement.objects.filter(pk=engagement.pk).update(automated_ok=True, policy_ack_at=timezone.now())
		self.assertEqual(udp_scan.pick().pk, ip.pk)

	def test_an_address_shared_with_a_cleared_project_is_still_scanned_and_attributed_to_it(self):
		from cveFeed.models import BountyEngagement, BountyProgram
		program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
		BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
		other = Project.objects.create(name='Q', slug='pq', insert_date=timezone.now(), org=self.org)
		other_domain = Domain.objects.create(name='free.test', project=other, insert_date=timezone.now())
		ip = self.ip('192.0.2.1', name='bb.udp.test')
		Subdomain.objects.create(scan_history=self.scan, target_domain=other_domain, name='www.free.test').ip_addresses.add(ip)
		self.assertEqual(udp_scan.pick().pk, ip.pk)

	def test_a_host_that_resolves_somewhere_blocked_is_skipped(self):
		self.ip('192.0.2.1', name='rebind.udp.test')
		ok = self.ip('192.0.2.2', name='fine.udp.test')
		with mock.patch('targetApp.target_types.resolves_to_blocked', side_effect=lambda name: name.startswith('rebind')):
			self.assertEqual(udp_scan.pick().pk, ok.pk)

	def test_an_archived_host_is_not_scanned(self):
		from cveFeed.models import HostState
		self.ip('192.0.2.1', name='old.udp.test')
		HostState.objects.create(project=self.project, domain=self.domain, host='old.udp.test', archived_at=timezone.now())
		self.assertIsNone(udp_scan.pick())

	def test_the_same_address_in_two_organizations_is_two_assets(self):
		other = Org.objects.create(name='V', slug='v')
		a = IpAddress.objects.create(address='192.0.2.5', org=self.org)
		b = IpAddress.objects.create(address='192.0.2.5', org=other)
		self.assertNotEqual(udp_scan.asset_of(a), udp_scan.asset_of(b))


class DegradeTests(UdpBase):
	def test_without_raw_sockets_the_sweep_does_not_run_and_says_why(self):
		self.ip('192.0.2.10')

		def denied(*args, **kwargs):
			raise PermissionError(1, 'Operation not permitted')
		ok, reason = udp_scan.raw_sockets_available(opener=denied)
		self.assertFalse(ok)
		self.assertIn('CAP_NET_RAW', reason)
		with mock.patch('cveFeed.udp_scan.shutil.which', return_value='/usr/local/bin/nmap'), \
				mock.patch('cveFeed.nmap_scan.run_nmap_xml') as nmap:
			out = udp_scan.run(raw_check=lambda: (ok, reason))
		nmap.assert_not_called()
		self.assertEqual(out, {'skipped': reason})
		recorded = udp_scan.recorded_status()
		self.assertEqual((recorded['state'], recorded['reason']), ('unavailable', reason))
		self.assertTrue(AgentActivity.objects.filter(message__contains='UDP scanning is off on this worker').exists())
		self.assertEqual(ServiceRun.objects.filter(service=udp_scan.SERVICE).count(), 0)  # nothing was stamped as scanned

	def test_the_note_in_the_feed_is_one_a_day_but_the_status_is_every_firing(self):
		with mock.patch.object(ledger, 'sweep_claim', side_effect=[True, False]):
			udp_scan.run(raw_check=lambda: (False, 'no raw sockets'))
			udp_scan.run(raw_check=lambda: (False, 'no raw sockets'))
		self.assertEqual(AgentActivity.objects.filter(message__contains='UDP scanning is off').count(), 1)

	def test_a_missing_nmap_is_a_recorded_reason_too(self):
		with mock.patch('cveFeed.udp_scan.shutil.which', return_value=None):
			out = udp_scan.run(raw_check=lambda: (True, ''))
		self.assertIn('nmap is not installed', out['skipped'])
		self.assertIn('nmap is not installed', udp_scan.recorded_status()['reason'])

	def test_another_oserror_is_reported_with_its_type(self):
		def broken(*args, **kwargs):
			raise OSError(97, 'Address family not supported')
		ok, reason = udp_scan.raw_sockets_available(opener=broken)
		self.assertFalse(ok)
		self.assertIn('OSError', reason)

	def test_this_process_check_returns_a_boolean_and_a_reason(self):
		ok, reason = udp_scan.raw_sockets_available()
		self.assertIsInstance(ok, bool)
		self.assertEqual(bool(reason), not ok)

	def test_the_system_status_shows_the_unavailable_reason_as_a_problem(self):
		from agentapi import system_status
		udp_scan.record_status('unavailable', 'no raw sockets here')
		problems = []
		out = system_status._udp_scan(problems)
		self.assertEqual((out['state'], out['reason']), ('unavailable', 'no raw sockets here'))
		self.assertEqual(problems, ['udp scan: no raw sockets here'])
		with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN': '0'}):
			self.assertEqual(system_status._udp_scan([])['state'], 'off')


class StatusTests(UdpBase):
	def test_the_status_counts_what_the_sweep_holds(self):
		ip = self.ip('192.0.2.10')
		udp_scan.record_run(ip, self.host_of(ANSWERED, '192.0.2.10'))
		ledger.record(udp_scan.SERVICE, [udp_scan.asset_of(ip)])
		out = udp_scan.status()
		self.assertEqual((out['open_udp_ports'], out['unanswered_udp_ports'], out['ips_covered']), (3, 2, 1))
		self.assertEqual(out['ports'], list(udp_scan.DEFAULT_PORTS))
		self.assertTrue(out['enabled'])


class KickTests(UdpBase):
	def test_every_firing_queues_at_most_one_udp_sweep_per_five_minutes_and_it_expires(self):
		with mock.patch('cveFeed.tasks.udp_scan_sweep.apply_async') as queued, mock.patch.object(ledger, 'sweep_claim', side_effect=[True, False]):
			self.assertTrue(udp_scan.kick())
			self.assertFalse(udp_scan.kick())
		queued.assert_called_once()
		self.assertIn('expires', queued.call_args.kwargs)

	def test_the_off_switch_queues_nothing(self):
		with mock.patch('cveFeed.tasks.udp_scan_sweep.apply_async') as queued, mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN': '0'}):
			self.assertFalse(udp_scan.kick())
		queued.assert_not_called()

	def test_the_tcp_sweeps_task_kicks_the_udp_sweep_and_survives_its_failure(self):
		from cveFeed.tasks import background_full_scan
		with mock.patch('cveFeed.fullscan.run', return_value={'swept': []}), mock.patch('cveFeed.udp_scan.kick') as kick:
			self.assertEqual(background_full_scan(), {'swept': []})
		kick.assert_called_once()
		with mock.patch('cveFeed.tasks.udp_scan_sweep.apply_async', side_effect=RuntimeError('broker down')), \
				mock.patch.object(ledger, 'sweep_claim', return_value=True):
			self.assertFalse(udp_scan.kick())


class RetestTests(UdpBase):
	def test_a_changed_service_re_tests_each_host_once_a_day(self):
		self.ip('192.0.2.10', name='edge.udp.test')
		ip = IpAddress.objects.get(address='192.0.2.10')
		seen = []
		self.assertEqual(udp_scan.queue_retests(ip, [123], self.project.id, pipeline=lambda d, n: seen.append((d, n))), ['edge.udp.test'])
		self.assertEqual(udp_scan.queue_retests(ip, [123], self.project.id, pipeline=lambda d, n: seen.append((d, n))), [])
		self.assertEqual(seen, [(self.domain.id, ['edge.udp.test'])])

	def test_without_an_injected_pipeline_the_retest_task_is_queued(self):
		self.ip('192.0.2.10', name='edge.udp.test')
		ip = IpAddress.objects.get(address='192.0.2.10')
		with mock.patch('cveFeed.tasks.retest_hosts.delay') as delay:
			udp_scan.queue_retests(ip, [123], self.project.id)
		delay.assert_called_once_with(self.domain.id, ['edge.udp.test'])
