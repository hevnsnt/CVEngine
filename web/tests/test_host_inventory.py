"""Host inventory reports: the schema gate, storing and matching a report to a host, the ingest endpoint and the token that may only
post to it, tenancy, and the reads. The CVE side is tests/test_inventory_match.py and the reporter scripts tests/test_inventory_scripts.py."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token, hash_token
from cveFeed import host_inventory, inventory_schema as schema
from cveFeed.models import HostExclusion, HostInventory, ProjectSettings
from dashboard.models import AbuseStrike, ApiToken, AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

MACHINE = 'a' * 64


def report(**changes):
	"""A valid inventory v1 report of an Ubuntu host; ``changes`` replace top-level keys."""
	base = {
		'schema': 'cvengine-inventory/1', 'script': {'name': 'cvengine-inventory.sh', 'version': '1.0.0'},
		'collected_at': timezone.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
		'host': {'hostname': 'web01', 'fqdn': 'web01.example.test', 'machine_id': MACHINE, 'ips': ['192.0.2.10']},
		'os': {'family': 'linux', 'id': 'ubuntu', 'id_like': ['debian'], 'name': 'Ubuntu', 'version': '22.04', 'pretty': 'Ubuntu 22.04.3 LTS',
			'kernel': '5.15.0-91-generic', 'arch': 'x86_64'},
		'packages': [{'n': 'openssl', 'v': '3.0.2-0ubuntu1.10', 'e': 'dpkg', 'a': 'amd64'},
			{'n': 'libssl3', 'v': '3.0.2-0ubuntu1.10', 'e': 'dpkg', 'a': 'amd64', 's': 'openssl'}],
		'patches': [], 'services': [{'p': 'tcp', 'a': '*', 'n': 22, 'x': 'sshd'}],
		'runtime': {'reboot_required': False, 'kernels_installed': ['5.15.0-91-generic'], 'containers': [], 'units': ['ssh.service']},
		'security': {'firewall': 'ufw active'},
	}
	base.update(changes)
	return base


class SchemaTests(SimpleTestCase):
	def test_a_valid_report_is_kept_in_its_normal_form(self):
		clean = schema.validate(report())
		self.assertEqual(clean['host']['fqdn'], 'web01.example.test')
		self.assertEqual(clean['os']['kernel'], '5.15.0-91-generic')
		self.assertEqual(clean['packages'][1], {'n': 'libssl3', 'v': '3.0.2-0ubuntu1.10', 'e': 'dpkg', 'a': 'amd64', 's': 'openssl'})
		self.assertEqual(clean['services'], [{'p': 'tcp', 'a': '*', 'n': 22, 'x': 'sshd'}])
		self.assertEqual(clean['dropped'], {})

	def test_the_wrong_shape_is_refused_with_a_clear_reason(self):
		for body in ([], 'text', None, 5):
			with self.assertRaises(schema.InventoryError):
				schema.validate(body)
		with self.assertRaisesRegex(schema.InventoryError, 'schema must be'):
			schema.validate({'host': {}})
		with self.assertRaisesRegex(schema.InventoryError, 'update the server or the reporter script'):
			schema.validate(report(schema='cvengine-inventory/2'))
		with self.assertRaisesRegex(schema.InventoryError, 'at least a hostname'):
			schema.validate(report(host={'ips': ['127.0.0.1']}))  # a loopback address says nothing about which machine this is
		with self.assertRaisesRegex(schema.InventoryError, 'os.family'):
			schema.validate(report(os={'family': 'plan9', 'name': 'x'}))
		with self.assertRaisesRegex(schema.InventoryError, 'os.name'):
			schema.validate(report(os={'family': 'linux'}))

	def test_a_list_over_its_cap_is_refused_not_cut_short(self):
		many = [{'n': f'p{i}', 'v': '1', 'e': 'dpkg'} for i in range(schema.MAX_PACKAGES + 1)]
		with self.assertRaises(schema.InventoryError) as raised:
			schema.validate(report(packages=many))
		self.assertEqual(raised.exception.status, 413)
		self.assertEqual(len(schema.validate(report(packages=many[:schema.MAX_PACKAGES]))['packages']), schema.MAX_PACKAGES)
		with self.assertRaises(schema.InventoryError):
			schema.validate(report(patches=[{'i': 'KB1234567'}] * (schema.MAX_PATCHES + 1)))
		with self.assertRaises(schema.InventoryError):
			schema.validate(report(host={'hostname': 'x', 'ips': ['192.0.2.1'] * (schema.MAX_IPS + 1)}))
		with self.assertRaisesRegex(schema.InventoryError, 'must be a list'):
			schema.validate(report(packages={'n': 'x'}))

	def test_one_bad_item_costs_only_itself(self):
		packages = [{'n': 'good', 'v': '1.0', 'e': 'dpkg'}, 'text', None, {'n': '', 'v': '1', 'e': 'dpkg'}, {'n': 'x', 'v': '1', 'e': 'shell'},
			{'n': 'bad version', 'v': 'v\x00\x01 1', 'e': 'win'}, {'v': '2', 'e': 'dpkg'}]
		clean = schema.validate(report(packages=packages))
		self.assertEqual([p['n'] for p in clean['packages']], ['good', 'bad version'])
		self.assertEqual(clean['packages'][1]['v'], 'v 1')  # control characters removed, never stored
		self.assertEqual(clean['dropped']['packages'], 5)

	def test_duplicates_collapse_and_other_versions_stay(self):
		same = {'n': 'linux-image', 'v': '5.15.0-91', 'e': 'dpkg', 'a': 'amd64'}
		clean = schema.validate(report(packages=[same, dict(same), {**same, 'v': '5.15.0-92'}]))
		self.assertEqual([p['v'] for p in clean['packages']], ['5.15.0-91', '5.15.0-92'])
		self.assertEqual(len(schema.validate(report(services=[{'p': 'tcp', 'a': '*', 'n': 22}] * 5))['services']), 1)
		self.assertEqual(len(schema.validate(report(patches=[{'i': 'KB5034441'}, {'i': 'KB5034441'}]))['patches']), 1)

	def test_hostile_text_is_cleaned_and_clipped(self):
		evil = '<script>alert(1)</script>‮​${jndi:ldap://x}\x00; rm -rf /' + 'A' * 5000
		clean = schema.validate(report(packages=[{'n': evil, 'v': '1.0', 'e': 'dpkg', 's': evil}], os={'family': 'linux', 'name': evil, 'pretty': evil},
			runtime={'units': [evil] * 3, 'containers': [{'rt': 'docker', 'image': evil}]}))
		self.assertLessEqual(len(clean['packages'][0]['n']), 200)
		self.assertLessEqual(len(clean['os']['name']), 120)
		for bad in ('‮', '​', '\x00'):
			self.assertNotIn(bad, json.dumps(clean, ensure_ascii=True).encode().decode('unicode_escape') if bad != '\x00' else clean['packages'][0]['n'])
		self.assertEqual(len(clean['runtime']['units']), 1)  # the three identical units are one
		self.assertEqual(len(clean['runtime']['containers']), 1)

	def test_fields_with_a_known_form_must_have_it(self):
		clean = schema.validate(report(host={'hostname': 'web 01;', 'fqdn': 'Web01.Example.Test', 'machine_id': 'not-a-hash', 'ips': [
			'192.0.2.10', '192.0.2.10', '127.0.0.1', '::1', 'fe80::1%eth0', '224.0.0.1', '0.0.0.0', 'nope', 5, '::ffff:192.0.2.11', '2001:db8::1%eth0'],
			'macs': ['AA:BB:CC:DD:EE:FF', 'aa:bb', 'zz:bb:cc:dd:ee:ff']},
			collected_at='yesterday', services=[{'p': 'icmp', 'a': '*', 'n': 1}, {'p': 'tcp', 'a': '*', 'n': 70000}, {'p': 'tcp', 'a': 'x', 'n': 22},
				{'p': 'udp', 'a': '2001:db8::1', 'n': 53, 'x': 'bad name!'}, {'p': 'tcp', 'a': '*', 'n': True}]))
		self.assertEqual(clean['host']['hostname'], '')
		self.assertEqual(clean['host']['fqdn'], 'web01.example.test')
		self.assertEqual(clean['host']['machine_id'], '')
		self.assertEqual(clean['host']['ips'], ['192.0.2.10', '192.0.2.11', '2001:db8::1'])
		self.assertEqual(clean['host']['macs'], ['aa:bb:cc:dd:ee:ff'])
		self.assertEqual(clean['collected_at'], '')
		self.assertEqual(clean['services'], [{'p': 'udp', 'a': '2001:db8::1', 'n': 53, 'x': ''}])

	def test_a_host_clock_far_in_the_future_is_not_believed(self):
		now = timezone.now()
		future = (now + timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
		self.assertEqual(schema.validate(report(collected_at=future), now=now)['collected_at'], '')
		ok = schema.validate(report(collected_at='2026-10-01T12:30:00+02:00'), now=now)['collected_at']
		self.assertEqual(ok, '2026-10-01T10:30:00+00:00')

	def test_deep_nesting_is_refused(self):
		deep = current = {}
		for _ in range(20):
			current['x'] = {}
			current = current['x']
		with self.assertRaisesRegex(schema.InventoryError, 'nests too deeply'):
			schema.validate(report(extra=deep))

	def test_unknown_keys_are_never_stored(self):
		clean = schema.validate(report(secret_dump={'password': 'x'}, os={'family': 'linux', 'name': 'Ubuntu', 'shadow': 'root:x'}))
		self.assertNotIn('secret_dump', clean)
		self.assertNotIn('shadow', clean['os'])

	def test_security_posture_is_an_allowlist(self):
		clean = schema.validate(report(security={'firewall': 'on', 'ssh_private_key': 'KEY', 'antivirus_signature_age_days': 3,
			'selinux': 'x' * 100, 'sip': 5}))
		self.assertEqual(clean['security'], {'firewall': 'on', 'antivirus_signature_age_days': 3, 'selinux': 'x' * 20})

	def test_machine_key_prefers_the_hashed_id(self):
		self.assertEqual(schema.machine_key({'machine_id': MACHINE, 'hostname': 'a'}), MACHINE)
		self.assertEqual(schema.machine_key({'hostname': 'Web01', 'fqdn': ''}), 'h:web01')
		self.assertEqual(schema.machine_key({'hostname': 'web01', 'fqdn': 'Web01.Example.Test'}), 'h:web01.example.test')


class NormalisationTests(SimpleTestCase):
	def test_purl_of_each_ecosystem(self):
		ubuntu = {'id': 'ubuntu', 'version': '22.04'}
		self.assertEqual(schema.purl({'n': 'openssl', 'v': '3.0.2-0ubuntu1.10', 'e': 'dpkg', 'a': 'amd64'}, ubuntu),
			'pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04')
		self.assertEqual(schema.purl({'n': 'attr', 'v': '1:2.4.47-2+b1', 'e': 'dpkg'}, {'id': 'debian', 'version': '12'}),
			'pkg:deb/debian/attr@1:2.4.47-2%2Bb1?distro=debian-12')
		self.assertEqual(schema.purl({'n': 'curl', 'v': '1:7.76.1-26.el9', 'e': 'rpm', 'a': 'x86_64'}, {'id': 'rhel', 'version': '9.3'}),
			'pkg:rpm/rhel/curl@7.76.1-26.el9?arch=x86_64&distro=rhel-9.3&epoch=1')
		self.assertEqual(schema.purl({'n': 'curl', 'v': '8.5.0-r0', 'e': 'apk', 'a': 'x86_64'}, {'id': 'alpine', 'version': '3.19.1'}),
			'pkg:apk/alpine/curl@8.5.0-r0?arch=x86_64&distro=alpine-3.19.1')
		self.assertEqual(schema.purl({'n': 'openssl', 'v': '3.2.0-1', 'e': 'pacman'}, {'id': 'arch', 'version': ''}), 'pkg:alpm/arch/openssl@3.2.0-1?distro=arch')
		self.assertEqual(schema.purl({'n': '7-Zip 23.01 (x64)', 'v': '23.01', 'e': 'win'}, {}), 'pkg:generic/7-Zip%2023.01%20%28x64%29@23.01?ecosystem=win')

	def test_identity_carries_distribution_architecture_and_source(self):
		ident = schema.identity({'n': 'libssl3', 'v': '3.0.2-0ubuntu1.10', 'e': 'dpkg', 'a': 'amd64', 's': 'openssl'}, {'id': 'ubuntu', 'version': '22.04'})
		self.assertEqual((ident['name'], ident['distro'], ident['distro_release'], ident['arch'], ident['source']),
			('libssl3', 'ubuntu', '22.04', 'amd64', 'openssl'))
		self.assertTrue(ident['purl'].startswith('pkg:deb/ubuntu/libssl3@'))


class MemoryThrottle:
	"""tenancy.throttle with its counts in a dict."""

	def __init__(self):
		self.counts = {}

	def count(self, key, window):
		self.counts[key] = self.counts.get(key, 0) + 1

	def exceeded(self, key, limit):
		return self.counts.get(key, 0) >= limit


class Base(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org, cls.org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
		cls.project = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=cls.org)
		cls.other = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=cls.org2)
		cls.domain = Domain.objects.create(name='example.test', project=cls.project, insert_date=now)
		cls.domain_b = Domain.objects.create(name='other.test', project=cls.other, insert_date=now)
		mk = lambda n: User.objects.create_user(n, password='x')
		cls.alice, cls.carol, cls.bob, cls.dan = mk('alice'), mk('carol'), mk('bob'), mk('dan')
		ProjectMembership.objects.create(user=cls.alice, project=cls.project, role='user')
		ProjectMembership.objects.create(user=cls.carol, project=cls.project, role='audit')
		OrgMembership.objects.create(user=cls.bob, org=cls.org2, role='admin')
		ProjectMembership.objects.create(user=cls.dan, project=cls.project, role='user')
		cls.t_alice = create_token(cls.alice, 'agent')[1]
		cls.t_audit = create_token(cls.carol, 'auditor')[1]
		cls.t_bob = create_token(cls.bob, 'bob')[1]
		cls.t_ro = create_token(cls.alice, 'ro', read_only=True)[1]
		cls.t_rep = create_token(cls.alice, 'reporter', scope='inventory', project=cls.project)[1]
		cls.t_rep_other = create_token(cls.bob, 'reporter b', scope='inventory', project=cls.other)[1]
		cls.engine = EngineType.objects.create(engine_name='fast', yaml_configuration='x')

	def setUp(self):
		# the counters live in the cache, which every test (and every test run) shares: these tests count in memory
		counters = MemoryThrottle()
		throttle = mock.patch('agentapi.inventory.throttle', counters)
		throttle.start()
		self.addCleanup(throttle.stop)
		self.counters = counters
		# the test client always comes from 127.0.0.1, an address no scanned host has: these tests do not exercise the source-address witness
		address = mock.patch('agentapi.inventory.client_ip', return_value='')
		address.start()
		self.addCleanup(address.stop)
		patcher = mock.patch('cveFeed.tasks.correlate_host_inventory.delay')
		self.queued = patcher.start()
		self.addCleanup(patcher.stop)

	def scanned(self, name, ips=(), project=None, domain=None):
		"""A host in the project's current inventory (a finished scan of its target)."""
		domain = domain or self.domain
		scan = ScanHistory.objects.filter(domain=domain, scan_status=2).first() or ScanHistory.objects.create(
			domain=domain, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now(), tasks=['x'])
		sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)
		for address in ips:
			ip, _ = IpAddress.objects.get_or_create(address=address, org=(project or self.project).org)
			sub.ip_addresses.add(ip)
		return sub

	def post(self, token, body, slug='proj-a'):
		return call(token, 'POST', f'/api/v1/projects/{slug}/inventory', body)


class IngestTests(Base):
	def test_a_report_matches_the_host_by_name_first(self):
		self.scanned('web01.example.test', ['192.0.2.10'])
		inv, outcome = host_inventory.ingest(self.project, schema.validate(report()))
		self.assertEqual((outcome, inv.host, inv.match_basis), ('new', 'web01.example.test', 'name'))
		self.assertEqual(inv.package_count, 2)
		self.assertEqual(inv.os_name, 'Ubuntu')

	def test_a_report_matches_by_address_when_the_names_differ(self):
		self.scanned('www.example.test', ['192.0.2.10'])
		self.scanned('other.example.test', ['192.0.2.99'])
		inv, _ = host_inventory.ingest(self.project, schema.validate(report()))
		self.assertEqual((inv.host, inv.match_basis), ('www.example.test', 'ip'))

	def test_names_on_the_same_addresses_are_one_host_and_the_target_name_is_shown(self):
		self.scanned('example.test', ['192.0.2.10'])
		self.scanned('www.example.test', ['192.0.2.10'])
		inv, _ = host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'srv', 'ips': ['192.0.2.10']})))
		self.assertEqual(inv.host, 'example.test')

	def test_a_cdn_address_never_matches(self):
		sub = self.scanned('www.example.test', ['192.0.2.10'])
		IpAddress.objects.filter(address='192.0.2.10').update(is_cdn=True)
		inv, _ = host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'srv', 'ips': ['192.0.2.10']})))
		self.assertEqual(inv.host, '')
		self.assertTrue(sub.pk)

	def test_a_short_host_name_matches_only_when_one_scanned_name_starts_with_it(self):
		self.scanned('web01.example.test')
		inv, _ = host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'web01', 'machine_id': MACHINE, 'ips': []})))
		self.assertEqual((inv.host, inv.match_basis), ('web01.example.test', 'name'))
		Subdomain.objects.create(name='web01.other.example.test', target_domain=self.domain, scan_history=ScanHistory.objects.first())
		inv2, _ = host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'web01', 'machine_id': 'b' * 64, 'ips': []})))
		self.assertEqual(inv2.host, '')  # two candidates: not a guess

	def test_a_name_in_another_project_is_not_a_match(self):
		self.scanned('web01.other.test', ['192.0.2.10'], project=self.other, domain=self.domain_b)
		inv, _ = host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'web01', 'fqdn': 'web01.other.test', 'ips': ['192.0.2.10']})))
		self.assertEqual(inv.host, '')

	def test_an_unknown_host_is_recorded_unmatched(self):
		inv, outcome = host_inventory.ingest(self.project, schema.validate(report()))
		self.assertEqual((outcome, inv.host, inv.match_basis), ('new', '', ''))

	def test_a_second_report_updates_the_same_row_and_keeps_summarised_history(self):
		host_inventory.ingest(self.project, schema.validate(report()))
		packages = [{'n': 'openssl', 'v': '3.0.2-0ubuntu1.12', 'e': 'dpkg', 'a': 'amd64'}, {'n': 'nginx', 'v': '1.18', 'e': 'dpkg'}]
		inv, outcome = host_inventory.ingest(self.project, schema.validate(report(packages=packages)))
		self.assertEqual((outcome, HostInventory.objects.count()), ('updated', 1))
		first, second = inv.history.order_by('id')
		self.assertTrue(first.changes['first'])
		self.assertEqual((second.changes['added'], second.changes['removed'], second.changes['changed']), (1, 1, 1))
		self.assertEqual(set(second.changes['names']), {'nginx', 'libssl3', 'openssl'})

	def test_an_os_change_is_reported_as_changed(self):
		host_inventory.ingest(self.project, schema.validate(report()))
		upgraded = report(os={**report()['os'], 'version': '24.04'})
		self.assertEqual(host_inventory.ingest(self.project, schema.validate(upgraded))[1], 'changed')

	def test_history_is_trimmed_to_the_newest_reports(self):
		for i in range(host_inventory.HISTORY_KEEP + 5):
			host_inventory.ingest(self.project, schema.validate(report(packages=[{'n': f'p{i}', 'v': '1', 'e': 'dpkg'}])))
		inv = HostInventory.objects.get()
		self.assertEqual(inv.history.count(), host_inventory.HISTORY_KEEP)
		self.assertFalse(inv.history.filter(changes__first=True).exists())

	def test_a_machine_that_gains_a_machine_id_keeps_its_row(self):
		no_id = report(host={'hostname': 'web01', 'ips': ['192.0.2.10']})
		host_inventory.ingest(self.project, schema.validate(no_id))
		inv, outcome = host_inventory.ingest(self.project, schema.validate(report()))
		self.assertEqual((outcome == 'new', HostInventory.objects.count(), inv.key), (False, 1, MACHINE))

	def test_an_adopted_match_survives_later_reports(self):
		self.scanned('www.example.test', ['192.0.2.50'])
		inv, _ = host_inventory.ingest(self.project, schema.validate(report()))
		host_inventory.adopt(inv, 'www.example.test')
		inv, _ = host_inventory.ingest(self.project, schema.validate(report()))
		self.assertEqual((inv.host, inv.match_basis), ('www.example.test', 'adopted'))

	def test_an_excluded_host_is_refused_and_nothing_is_stored(self):
		HostExclusion.objects.create(org=self.org, host='web01.example.test')
		with self.assertRaises(host_inventory.ReportRefused) as raised:
			host_inventory.ingest(self.project, schema.validate(report()))
		self.assertEqual(raised.exception.status, 409)
		self.assertFalse(HostInventory.objects.exists())

	def test_the_machines_per_project_are_capped(self):
		with mock.patch.object(host_inventory, 'MAX_MACHINES_PER_PROJECT', 2):
			for n in range(2):
				host_inventory.ingest(self.project, schema.validate(report(host={'hostname': f'h{n}', 'machine_id': f'{n}' * 64, 'ips': []})))
			with self.assertRaises(host_inventory.ReportRefused):
				host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'h9', 'machine_id': '9' * 64, 'ips': []})))
			host_inventory.ingest(self.project, schema.validate(report(host={'hostname': 'h0', 'machine_id': '0' * 64, 'ips': []})))  # a known one still reports

	def test_the_host_reported_os_outranks_the_network_guess(self):
		sub = self.scanned('web01.example.test', ['192.0.2.10'])
		ip = sub.ip_addresses.get()
		IpAddress.objects.filter(pk=ip.pk).update(os_guess='Linux 4.15 - 5.8', os_accuracy=88)
		inv, _ = host_inventory.ingest(self.project, schema.validate(report()))
		ip.refresh_from_db()
		self.assertEqual((ip.os_guess, ip.os_accuracy), ('Ubuntu 22.04.3 LTS', 100))
		self.assertEqual(ip.fingerprint['host_reported']['inventory_id'], inv.id)
		self.assertTrue(host_inventory.keeps_reported_os(ip))
		from cveFeed import nmap_scan
		nmap_scan.persist_inventory([{'ip': '192.0.2.10', 'os_guess': 'Linux 5.4', 'os_accuracy': 95, 'ports': []}], org_id=self.org.pk)
		ip.refresh_from_db()
		self.assertEqual(ip.os_guess, 'Ubuntu 22.04.3 LTS')  # the scan did not replace it
		stamp = ip.fingerprint['host_reported']
		stamp['at'] = (timezone.now() - timedelta(days=host_inventory.REPORTED_OS_DAYS + 1)).isoformat()
		IpAddress.objects.filter(pk=ip.pk).update(fingerprint={'host_reported': stamp})
		nmap_scan.persist_inventory([{'ip': '192.0.2.10', 'os_guess': 'Linux 5.4', 'os_accuracy': 95, 'ports': []}], org_id=self.org.pk)
		ip.refresh_from_db()
		self.assertEqual(ip.os_guess, 'Linux 5.4')  # an old report no longer outranks a fresh scan

	def test_a_listening_process_is_noted_on_an_existing_open_port_only(self):
		sub = self.scanned('web01.example.test', ['192.0.2.10'])
		ip = sub.ip_addresses.get()
		known = Port.objects.create(number=22, protocol='tcp', service_name='ssh', product='OpenSSH', version='8.9')
		ip.ports.add(known)
		listening = report(services=[{'p': 'tcp', 'a': '*', 'n': 22, 'x': 'sshd'}, {'p': 'tcp', 'a': '192.0.2.10', 'n': 5432, 'x': 'postgres'}])
		host_inventory.ingest(self.project, schema.validate(listening))
		known.refresh_from_db()
		self.assertEqual(known.extra['host_reported']['process'], 'sshd')
		self.assertEqual(known.product, 'OpenSSH')  # what the scan saw is not overwritten
		self.assertEqual(ip.ports.count(), 1)  # a socket nobody scanned is not turned into an exposed port


class EndpointTests(Base):
	def test_a_report_is_accepted_and_the_answer_names_no_host(self):
		self.scanned('web01.example.test')
		status, data = self.post(self.t_alice, report())
		self.assertEqual(status, 201)
		self.assertEqual((data['accepted'], data['status'], data['outcome'], data['packages']), (True, 'matched', 'new', 2))
		self.assertNotIn('web01', json.dumps(data))
		self.assertEqual(self.post(self.t_alice, report())[0], 200)
		self.queued.assert_called()
		self.assertEqual(self.post(self.t_alice, report())[1]['outcome'], 'updated')

	def test_an_unmatched_report_is_stored_and_not_queued_for_cves(self):
		status, data = self.post(self.t_alice, report())
		self.assertEqual((status, data['status']), (201, 'unmatched'))
		self.queued.assert_not_called()

	def test_a_reporter_token_can_post_to_its_own_project_and_nothing_else(self):
		self.assertEqual(self.post(self.t_rep, report())[0], 201)
		for method, path, body in (
				('GET', '/api/v1/me', None), ('GET', '/api/v1/projects', None), ('GET', '/api/v1/projects/proj-a/hosts', None),
				('GET', '/api/v1/projects/proj-a/inventory', None), ('GET', '/api/v1/projects/proj-a/inventory/1', None),
				('POST', '/api/v1/projects/proj-a/targets', {'value': 'x.example.test'}),
				('POST', '/api/v1/projects/proj-a/inventory/1/adopt', {'create': True}), ('DELETE', '/api/v1/projects/proj-a/inventory/1', None),
				('PUT', '/api/v1/projects/proj-a/settings', {'inventory': {'create_hosts': True}}),
				('POST', '/api/v1/tokens', {'name': 'x'}), ('GET', '/api/v1/tokens', None),
				('POST', '/api/v1/projects/proj-b/inventory', report()),  # a project the user may not even see
				('GET', '/api/v1/openapi.json', None)):
			status, _ = call(self.t_rep, method, path, body)
			self.assertEqual(status, 403, (method, path))
		self.assertEqual(call(self.t_rep, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})[0], 403)
		self.assertEqual(call(self.t_rep, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
			'params': {'name': 'list_host_inventories', 'arguments': {'project': 'proj-a'}}})[0], 403)

	def test_a_reporter_token_cannot_report_to_another_project_even_if_its_user_can_write_there(self):
		ProjectMembership.objects.create(user=self.alice, project=self.other, role='user')
		self.assertEqual(self.post(self.t_rep, report(), slug='proj-b')[0], 403)
		self.assertEqual(self.post(self.t_alice, report(), slug='proj-b')[0], 201)  # the user's own full token is unaffected

	def test_a_reporter_token_whose_project_is_gone_is_useless(self):
		ApiToken.objects.filter(key_hash=hash_token(self.t_rep)).update(project=None)
		self.assertEqual(self.post(self.t_rep, report())[0], 403)

	def test_the_audit_role_a_read_only_token_and_strangers_cannot_post(self):
		self.assertEqual(self.post(self.t_audit, report())[0], 403)
		self.assertEqual(self.post(self.t_ro, report())[0], 403)
		self.assertEqual(self.post(self.t_bob, report())[0], 404)  # another organization: the project does not exist for them
		self.assertEqual(self.post(None, report())[0], 401)
		self.assertEqual(self.post('cve_wrong', report())[0], 401)
		self.assertFalse(HostInventory.objects.exists())

	def test_a_revoked_or_expired_reporter_token_stops_working(self):
		token, raw = create_token(self.alice, 'temp', scope='inventory', project=self.project)
		self.assertEqual(self.post(raw, report())[0], 201)
		token.revoked = True
		token.save()
		self.assertEqual(self.post(raw, report())[0], 401)

	def test_a_disabled_user_takes_the_reporter_token_with_them(self):
		User.objects.filter(pk=self.alice.pk).update(is_active=False)
		self.assertEqual(self.post(self.t_rep, report())[0], 401)

	def test_bad_bodies_are_refused_with_the_right_status(self):
		c = Client()
		url = '/api/v1/projects/proj-a/inventory'
		headers = {'HTTP_AUTHORIZATION': f'Bearer {self.t_alice}'}
		self.assertEqual(c.post(url, 'not json', content_type='application/json', **headers).status_code, 400)
		self.assertEqual(c.post(url, '[1]', content_type='application/json', **headers).status_code, 400)
		self.assertEqual(self.post(self.t_alice, {'schema': 'cvengine-inventory/9'})[0], 400)
		big = c.post(url, 'x' * (schema.MAX_BODY_BYTES + 10), content_type='application/json', **headers)
		self.assertEqual(big.status_code, 413)
		many = report(packages=[{'n': f'p{i}', 'v': '1', 'e': 'dpkg'} for i in range(schema.MAX_PACKAGES + 1)])
		with mock.patch.object(schema, 'MAX_BODY_BYTES', 10 * 1024 * 1024):
			self.assertEqual(self.post(self.t_alice, many)[0], 413)
		self.assertFalse(HostInventory.objects.exists())

	def test_reports_are_rate_limited_per_token(self):
		for _ in range(host_inventory.REPORTS_PER_HOUR):
			self.assertIn(self.post(self.t_rep, report())[0], (200, 201))
		status, data = self.post(self.t_rep, report())
		self.assertEqual(status, 429)
		self.assertIn('an hour', data['error'])
		other = report(host={'hostname': 'web02', 'machine_id': 'd' * 64, 'ips': ['192.0.2.11']})
		self.assertIn(self.post(self.t_rep, other)[0], (200, 201))  # another machine on the same token is not slowed down by it
		self.assertEqual(self.post(self.t_alice, other)[0], 409)  # (and another token cannot report for a machine this one owns)

	def test_hostile_names_are_not_an_attack_on_the_reporters_owner(self):
		evil = 'x; rm -rf / | sh `id` $(whoami) <script>alert(1)</script> UNION SELECT 1 ../../etc/passwd'
		hostile = report(packages=[{'n': evil, 'v': '1.0', 'e': 'dpkg'}], services=[{'p': 'tcp', 'a': '*', 'n': 80, 'x': 'sh'}],
			os={'family': 'linux', 'name': evil, 'pretty': evil})
		for _ in range(4):
			self.assertEqual(self.post(self.t_alice, hostile)[0] in (200, 201), True)
		self.assertFalse(AbuseStrike.objects.exists())
		self.assertTrue(User.objects.get(pk=self.alice.pk).is_active)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/me')[0], 200)

	def test_the_audit_trail_records_what_an_administrator_reads_it_for(self):
		self.post(self.t_alice, report())
		self.post(self.t_alice, report())  # nothing changed: not another entry
		self.post(self.t_alice, report(os={**report()['os'], 'version': '24.04'}))
		rows = list(AuditLog.objects.filter(action='inventory.report').order_by('id'))
		self.assertEqual([r.detail['outcome'] for r in rows], ['new', 'changed'])
		self.assertEqual(rows[0].org_id, self.org.pk)
		self.assertNotIn(self.t_alice, json.dumps(rows[0].detail))  # only the prefix that tells tokens apart
		self.assertEqual(rows[0].detail['token'], self.t_alice[:8])

	def test_a_project_that_allows_it_adds_an_unknown_host_as_a_target(self):
		ProjectSettings.objects.create(project=self.project, inventory_create_hosts=True)
		with mock.patch('cveFeed.discovery.start_discoveries', return_value=[]) as start, mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async'):
			status, data = self.post(self.t_alice, report())
		self.assertEqual((status, data['status']), (201, 'created'))
		self.assertTrue(Domain.objects.filter(project=self.project, name='web01.example.test').exists())
		start.assert_called_once()
		self.assertEqual(HostInventory.objects.get().match_basis, 'created')

	def test_creating_a_host_honours_exclusions_and_the_default_is_off(self):
		self.assertEqual(self.post(self.t_alice, report())[1]['status'], 'unmatched')
		self.assertFalse(Domain.objects.filter(name='web01.example.test').exists())
		ProjectSettings.objects.create(project=self.project, inventory_create_hosts=True)
		HostExclusion.objects.create(org=self.org, host='example.test', include_subdomains=True)
		other = report(host={'hostname': 'db01', 'fqdn': 'db01.corp.test', 'machine_id': 'c' * 64, 'ips': ['192.0.2.60']})
		HostExclusion.objects.create(org=self.org, host='corp.test', include_subdomains=True)
		self.assertEqual(self.post(self.t_alice, other)[0], 409)  # excluded: the report itself is refused
		self.assertFalse(Domain.objects.filter(name='db01.corp.test').exists())

	def test_a_private_address_the_scanner_refuses_leaves_the_report_unmatched(self):
		ProjectSettings.objects.create(project=self.project, inventory_create_hosts=True)
		lone = report(host={'hostname': 'nas', 'machine_id': 'd' * 64, 'ips': ['10.1.2.3']})
		with mock.patch('cveFeed.discovery.start_discoveries', return_value=[]):
			status, data = self.post(self.t_alice, lone)
		self.assertEqual((status, data['status']), (201, 'unmatched'))


class ReadTests(Base):
	def setUp(self):
		super().setUp()
		self.scanned('web01.example.test', ['192.0.2.10'])
		self.post(self.t_alice, report())
		self.post(self.t_alice, report(host={'hostname': 'lone', 'machine_id': 'e' * 64, 'ips': ['192.0.2.200']}))
		self.inv = HostInventory.objects.get(host='web01.example.test')

	def test_the_list_filters_by_status(self):
		_, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory')
		self.assertEqual((data['count'], data['stale_after_days']), (2, 14))
		_, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory?status=unmatched')
		self.assertEqual([r['hostname'] for r in data['results']], ['lone'])
		_, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory?status=matched&q=web01')
		self.assertEqual(data['count'], 1)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory?status=bogus')[0], 400)
		HostInventory.objects.filter(pk=self.inv.pk).update(reported_at=timezone.now() - timedelta(days=30))
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory?status=stale')[1]['count'], 1)

	def test_the_detail_by_host_has_normalised_packages_and_a_stale_flag(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts/web01.example.test/inventory')
		self.assertEqual(status, 200)
		self.assertFalse(data['stale'])
		self.assertEqual(data['os']['version'], '22.04')
		first = data['packages_page']['results'][0]
		self.assertEqual((first['name'], first['distro'], first['distro_release']), ('libssl3', 'ubuntu', '22.04'))
		self.assertTrue(first['purl'].startswith('pkg:deb/ubuntu/libssl3@'))
		self.assertEqual(data['services'][0]['n'], 22)
		_, filtered = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts/web01.example.test/inventory?q=libssl&page_size=1')
		self.assertEqual(filtered['packages_page']['count'], 1)
		HostInventory.objects.filter(pk=self.inv.pk).update(reported_at=timezone.now() - timedelta(days=15))
		self.assertTrue(call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/inventory/{self.inv.id}')[1]['stale'])
		ProjectSettings.objects.create(project=self.project, inventory_stale_days=30)
		self.assertFalse(call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/inventory/{self.inv.id}')[1]['stale'])

	def test_an_unknown_host_or_id_is_404_and_another_projects_report_is_invisible(self):
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts/nope.example.test/inventory')[0], 404)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory/99999')[0], 404)
		self.assertEqual(call(self.t_bob, 'GET', f'/api/v1/projects/proj-a/inventory/{self.inv.id}')[0], 404)
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-a/inventory')[0], 404)
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-a/hosts/web01.example.test/inventory')[0], 404)
		self.post(self.t_bob, report(host={'hostname': 'bobs', 'machine_id': 'f' * 64, 'ips': ['192.0.2.9']}), slug='proj-b')
		_, mine = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/inventory')
		self.assertNotIn('bobs', json.dumps(mine))
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-b/inventory/' + str(self.inv.id))[0], 404)  # an id of A under B's slug

	def test_the_audit_role_can_read(self):
		self.assertEqual(call(self.t_audit, 'GET', '/api/v1/projects/proj-a/inventory')[0], 200)
		self.assertEqual(call(self.t_audit, 'GET', '/api/v1/projects/proj-a/hosts/web01.example.test/inventory')[0], 200)

	def test_the_host_record_carries_the_brief_with_age_and_staleness(self):
		_, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')
		brief = data['results'][0]['inventory']
		self.assertEqual((brief['stale'], brief['packages'], brief['host']), (False, 2, 'web01.example.test'))
		HostInventory.objects.filter(pk=self.inv.pk).update(reported_at=timezone.now() - timedelta(days=20))
		self.assertTrue(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')[1]['results'][0]['inventory']['stale'])
		Subdomain.objects.create(name='plain.example.test', target_domain=self.domain, scan_history=ScanHistory.objects.first())
		hosts = {h['host']: h for h in call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')[1]['results']}
		self.assertIsNone(hosts['plain.example.test']['inventory'])

	def test_mcp_read_tools(self):
		error, listing = tool_call(self.t_alice, 'list_host_inventories', {'project': 'proj-a', 'status': 'unmatched'})
		self.assertFalse(error)
		self.assertEqual(listing['count'], 1)
		error, detail = tool_call(self.t_alice, 'get_host_inventory', {'project': 'proj-a', 'host': 'web01.example.test', 'page_size': 1})
		self.assertFalse(error)
		self.assertEqual(len(detail['packages_page']['results']), 1)
		error, message = tool_call(self.t_alice, 'get_host_inventory', {'project': 'proj-a'})
		self.assertTrue(error)
		self.assertTrue(tool_call(self.t_bob, 'get_host_inventory', {'project': 'proj-a', 'host': 'web01.example.test'})[0])

	def test_adopting_and_deleting_need_a_write_role_in_that_project(self):
		lone = HostInventory.objects.get(hostname='lone')
		url = f'/api/v1/projects/proj-a/inventory/{lone.id}/adopt'
		self.assertEqual(call(self.t_audit, 'POST', url, {'host': 'web01.example.test'})[0], 403)
		self.assertEqual(call(self.t_bob, 'POST', url, {'host': 'web01.example.test'})[0], 404)
		self.assertEqual(call(self.t_alice, 'POST', url, {'host': 'nope.example.test'})[0], 404)
		self.assertEqual(call(self.t_alice, 'POST', url, {})[0], 400)
		status, data = call(self.t_alice, 'POST', url, {'host': 'WEB01.example.test'})
		self.assertEqual((status, data['host'], data['match_basis']), (200, 'web01.example.test', 'adopted'))
		self.assertEqual(call(self.t_audit, 'DELETE', f'/api/v1/projects/proj-a/inventory/{lone.id}')[0], 403)
		self.assertEqual(call(self.t_alice, 'DELETE', f'/api/v1/projects/proj-a/inventory/{lone.id}')[0], 200)
		self.assertFalse(HostInventory.objects.filter(pk=lone.pk).exists())
		self.assertEqual(call(self.t_alice, 'DELETE', f'/api/v1/projects/proj-a/inventory/{lone.id}')[0], 404)

	def test_adopting_by_creating_a_target_honours_exclusions(self):
		lone = HostInventory.objects.get(hostname='lone')
		HostInventory.objects.filter(pk=lone.pk).update(fqdn='lone.example.test')
		HostExclusion.objects.create(org=self.org, host='lone.example.test')
		self.assertEqual(call(self.t_alice, 'POST', f'/api/v1/projects/proj-a/inventory/{lone.id}/adopt', {'create': True})[0], 409)

	def test_deleting_a_hosts_data_removes_its_reports(self):
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/hosts/web01.example.test/delete', {})[0], 200)
		self.assertFalse(HostInventory.objects.filter(host='web01.example.test').exists())
		self.assertTrue(HostInventory.objects.filter(hostname='lone').exists())

	def test_project_settings_carry_the_inventory_policy(self):
		_, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/settings')
		self.assertEqual(data['inventory'], {'create_hosts': False, 'stale_days': 14})
		status, data = call(self.t_alice, 'PUT', '/api/v1/projects/proj-a/settings', {'inventory': {'create_hosts': True, 'stale_days': 30}})
		self.assertEqual((status, data['inventory']), (200, {'create_hosts': True, 'stale_days': 30}))
		for bad in ({'create_hosts': 'yes'}, {'stale_days': 0}, {'stale_days': 400}, {'stale_days': True}, {'other': 1}, {}):
			self.assertEqual(call(self.t_alice, 'PUT', '/api/v1/projects/proj-a/settings', {'inventory': bad})[0], 400, bad)
		self.assertEqual(call(self.t_audit, 'PUT', '/api/v1/projects/proj-a/settings', {'inventory': {'create_hosts': True}})[0], 403)


class TokenTests(Base):
	def test_a_session_user_mints_a_reporter_token_for_a_project_they_can_write_to(self):
		from tests.test_tenancy import client_for
		c = client_for(self.alice)
		response = c.post('/api/v1/tokens', json.dumps({'name': 'rack 4', 'scope': 'inventory', 'project': 'proj-a'}), content_type='application/json')
		self.assertEqual(response.status_code, 201)
		made = response.json()
		self.assertEqual((made['scope'], made['project']), ('inventory', 'proj-a'))
		token = ApiToken.objects.get(pk=made['id'])
		self.assertEqual((token.scope, token.project_id, token.read_only, token.user_id), ('inventory', self.project.pk, False, self.alice.pk))
		self.assertEqual(self.post(made['token'], report())[0], 201)
		self.assertTrue(AuditLog.objects.filter(action='token.create', detail__scope='inventory').exists())
		listing = c.get('/api/v1/tokens').json()['results']
		self.assertIn(('inventory', 'proj-a'), [(t['scope'], t['project']) for t in listing])

	def test_the_audit_role_and_strangers_cannot_mint_one(self):
		from tests.test_tenancy import client_for
		body = json.dumps({'name': 'x', 'scope': 'inventory', 'project': 'proj-a'})
		self.assertEqual(client_for(self.carol).post('/api/v1/tokens', body, content_type='application/json').status_code, 403)
		self.assertEqual(client_for(self.bob).post('/api/v1/tokens', body, content_type='application/json').status_code, 404)
		self.assertEqual(client_for(self.alice).post('/api/v1/tokens', json.dumps({'name': 'x', 'scope': 'inventory'}), content_type='application/json').status_code, 400)
		self.assertEqual(client_for(self.alice).post('/api/v1/tokens', json.dumps({'name': 'x', 'scope': 'inventory', 'project': '_all'}), content_type='application/json').status_code, 400)

	def test_a_token_cannot_mint_a_token(self):
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/tokens', {'name': 'x', 'scope': 'inventory', 'project': 'proj-a'})[0], 403)

	def test_an_ordinary_token_is_still_full_scope(self):
		self.assertEqual(ApiToken.objects.get(user=self.alice, name='agent').scope, 'full')
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/me')[0], 200)
