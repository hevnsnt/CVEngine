import os
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import host_context, nmap_scan, os_detection
from startScan.models import IpAddress


class UnreliableTests(SimpleTestCase):
	def kernel(self, release):
		return mock.patch.object(os_detection, '_kernel', return_value=release)

	def test_docker_desktops_vm_kernel_is_unreliable(self):
		with self.kernel('6.10.14-linuxkit'), mock.patch.dict(os.environ, {}, clear=False):
			os.environ.pop('CVENGINE_OS_DETECTION', None)
			self.assertTrue(os_detection.unreliable())

	def test_an_ordinary_linux_kernel_is_reliable(self):
		with self.kernel('6.8.0-45-generic'), mock.patch.dict(os.environ, {}, clear=False):
			os.environ.pop('CVENGINE_OS_DETECTION', None)
			self.assertFalse(os_detection.unreliable())

	def test_docker_desktop_on_windows_and_orbstack_are_unreliable_too(self):
		for release in ('5.15.153.1-microsoft-standard-WSL2', '6.12.7-orbstack-00123'):
			with self.kernel(release), mock.patch.dict(os.environ, {}, clear=False):
				os.environ.pop('CVENGINE_OS_DETECTION', None)
				self.assertTrue(os_detection.unreliable(), release)

	def test_the_override_wins_either_way(self):
		with self.kernel('6.10.14-linuxkit'), mock.patch.dict(os.environ, {'CVENGINE_OS_DETECTION': 'trust'}):
			self.assertFalse(os_detection.unreliable())
		with self.kernel('6.8.0-45-generic'), mock.patch.dict(os.environ, {'CVENGINE_OS_DETECTION': 'distrust'}):
			self.assertTrue(os_detection.unreliable())

	def test_the_reason_names_the_fix(self):
		self.assertIn('Docker Desktop', os_detection.REASON)
		self.assertIn('services', os_detection.REASON)


def _record(address='203.0.113.40'):
	return {'ip': address, 'os_guess': 'Google Fuchsia', 'os_accuracy': 86, 'ports': []}


class StoredGuessTests(TestCase):
	"""Behind Docker Desktop's network a local nmap's OS guess describes that network (issue 214): it is not stored. A Sentinel's is."""

	def stored(self):
		return IpAddress.objects.get(address='203.0.113.40').os_guess

	def test_a_local_scan_behind_docker_desktop_stores_no_guess(self):
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			nmap_scan.persist_inventory([_record()])
		self.assertEqual(self.stored(), '')

	def test_a_local_scan_elsewhere_stores_it(self):
		with mock.patch.object(os_detection, 'unreliable', return_value=False):
			nmap_scan.persist_inventory([_record()])
		self.assertEqual(self.stored(), 'Google Fuchsia')

	def test_a_sentinels_guess_is_stored_even_when_this_server_is_behind_docker_desktop(self):
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			nmap_scan.persist_inventory([_record()], os_reliable=True)
		self.assertEqual(self.stored(), 'Google Fuchsia')

	def test_the_ports_are_stored_either_way(self):
		record = {**_record(), 'ports': [{'number': 22, 'state': 'open', 'protocol': 'tcp', 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.9'}]}
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			nmap_scan.persist_inventory([record])
		self.assertEqual(IpAddress.objects.get(address='203.0.113.40').ports.filter(number=22).count(), 1)


class HostContextTests(SimpleTestCase):
	def sub(self):
		ip = SimpleNamespace(os_guess='Google Fuchsia', os_accuracy=86, fingerprint={'os_matches': [{'name': 'Apple OS X'}, {'name': 'Linux'}]})
		return SimpleNamespace(ip_addresses=SimpleNamespace(all=lambda: [ip]))

	def test_the_guess_reaches_the_model_when_it_can_be_believed(self):
		with mock.patch.object(os_detection, 'unreliable', return_value=False):
			out = host_context._os(self.sub(), [])
		self.assertEqual(out['guesses'][0]['guess'], 'Google Fuchsia')
		self.assertNotIn('note', out)

	def test_behind_docker_desktop_no_guess_is_given_and_the_block_says_why(self):
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			out = host_context._os(self.sub(), [])
		self.assertEqual(out['guesses'], [])
		self.assertIn('Docker Desktop', out['note'])


def _port(number, **kw):
	base = dict(number=number, state='open', service_name='ssh', distro='', distro_release='', extra={})
	return SimpleNamespace(**{**base, **kw})


class FromServicesTests(SimpleTestCase):
	def test_a_distribution_in_a_banner_names_the_system(self):
		found = os_detection.from_services([_port(22, distro='ubuntu', distro_release='24.04')])
		self.assertEqual((found['os'], found['source']), ('Ubuntu 24.04', 'service detection'))
		self.assertIn('port 22', found['basis'])

	def test_a_distribution_without_a_release_is_just_the_name(self):
		self.assertEqual(os_detection.from_services([_port(22, distro='debian')])['os'], 'Debian')

	def test_the_most_specific_service_wins_across_ports(self):
		ports = [_port(80, service_name='http', extra={'ostype': 'Linux'}),
		         _port(22, distro='ubuntu', distro_release='22.04'),
		         _port(443, service_name='https', extra={'cpes': ['cpe:/o:linux:linux_kernel']})]
		self.assertEqual(os_detection.from_services(ports)['os'], 'Ubuntu 22.04')

	def test_an_os_cpe_and_an_ostype_name_a_system_when_there_is_no_distribution(self):
		self.assertEqual(os_detection.from_services([_port(445, extra={'cpes': ['cpe:/o:microsoft:windows']})])['os'], 'Microsoft Windows')
		self.assertEqual(os_detection.from_services([_port(5000, extra={'cpes': ['cpe:/o:linux:linux_kernel:5.10']})])['os'], 'Linux')
		self.assertEqual(os_detection.from_services([_port(80, extra={'ostype': 'Linux'})])['os'], 'Linux')

	def test_a_closed_port_or_a_service_that_says_nothing_gives_nothing(self):
		self.assertEqual(os_detection.from_services([_port(22, state='closed', distro='ubuntu')]), {})
		self.assertEqual(os_detection.from_services([_port(80, service_name='http')]), {})


class ServiceEvidenceTests(TestCase):
	"""Behind Docker Desktop the packet guess is gone, but the host still has an operating system, read from what its services report."""

	def host(self):
		from startScan.models import Port
		ip, _ = IpAddress.objects.get_or_create(address='203.0.113.41')
		port = Port.objects.create(number=22, service_name='ssh', state='open', distro='ubuntu', distro_release='24.04')
		ip.ports.add(port)
		return ip

	def test_the_services_fill_an_empty_guess_and_are_labelled_as_such(self):
		from cveFeed import service_intel
		ip = self.host()
		self.assertTrue(service_intel.apply_host_facts(ip))
		ip.refresh_from_db()
		self.assertEqual(ip.os_guess, 'Ubuntu 24.04')
		self.assertIsNone(ip.os_accuracy)
		self.assertEqual(ip.fingerprint['facts']['source'], 'service detection')

	def test_the_system_it_was_reinstalled_as_replaces_the_one_the_services_named_before(self):
		from cveFeed import service_intel
		ip = self.host()
		service_intel.apply_host_facts(ip)
		ip.ports.update(distro='debian', distro_release='12')
		ip = IpAddress.objects.get(pk=ip.pk)
		service_intel.apply_host_facts(ip)
		self.assertEqual(IpAddress.objects.get(pk=ip.pk).os_guess, 'Debian 12')

	def test_a_guess_another_source_made_is_not_replaced(self):
		from cveFeed import service_intel
		ip = self.host()
		ip.os_guess, ip.os_accuracy = 'Windows Server 2022', 100
		ip.save()
		service_intel.apply_host_facts(ip)
		self.assertEqual(IpAddress.objects.get(pk=ip.pk).os_guess, 'Windows Server 2022')

	def test_the_context_gives_the_model_the_services_account_and_no_packet_guess(self):
		from cveFeed import service_intel
		ip = self.host()
		ip.os_guess, ip.os_accuracy = 'Google Fuchsia', 86
		ip.save()
		service_intel.apply_host_facts(ip)
		sub = SimpleNamespace(ip_addresses=SimpleNamespace(all=lambda: [IpAddress.objects.get(pk=ip.pk)]))
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			out = host_context._os(sub, [])
		self.assertEqual(out['guesses'], [])
		self.assertEqual(out['reported_by_other_tools']['facts']['os'], 'Ubuntu 24.04')
		self.assertEqual(out['reported_by_other_tools']['facts']['source'], 'service detection')


class ClearStoredGuessesTests(TestCase):
	"""An install that already stored Fuchsia and OS X guesses (1.3.0) has them removed, and the hosts named from their services."""

	def make(self, address, **fields):
		ip, _ = IpAddress.objects.get_or_create(address=address)
		for key, value in fields.items():
			setattr(ip, key, value)
		ip.save()
		return ip

	def test_nmap_guesses_go_and_the_machines_own_report_stays(self):
		from startScan.models import Port
		bad = self.make('203.0.113.50', os_guess='Google Fuchsia', os_accuracy=86, fingerprint={'os_matches': [{'name': 'x'}], 'os_source': 'nmap'})
		bad.ports.add(Port.objects.create(number=22, service_name='ssh', state='open', distro='ubuntu', distro_release='24.04'))
		told = self.make('203.0.113.51', os_guess='Ubuntu 24.04.1 LTS', os_accuracy=100, fingerprint={'host_reported': {'os': 'Ubuntu'}})
		typed = self.make('203.0.113.52', os_guess='Windows 11')  # runZero and service facts carry no accuracy
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			self.assertEqual(os_detection.clear_stored_guesses(), 1)
		bad.refresh_from_db()
		self.assertEqual((bad.os_guess, bad.os_accuracy), ('Ubuntu 24.04', None))  # named from its SSH banner instead
		self.assertNotIn('os_matches', bad.fingerprint)
		self.assertEqual(IpAddress.objects.get(pk=told.pk).os_guess, 'Ubuntu 24.04.1 LTS')
		self.assertEqual(IpAddress.objects.get(pk=typed.pk).os_guess, 'Windows 11')

	def test_nothing_is_touched_on_an_install_that_measures_correctly(self):
		ip = self.make('203.0.113.53', os_guess='Linux 5.4', os_accuracy=95)
		with mock.patch.object(os_detection, 'unreliable', return_value=False):
			self.assertEqual(os_detection.clear_stored_guesses(), 0)
		self.assertEqual(IpAddress.objects.get(pk=ip.pk).os_guess, 'Linux 5.4')

	def test_a_second_run_changes_nothing(self):
		self.make('203.0.113.54', os_guess='Google Fuchsia', os_accuracy=86)
		with mock.patch.object(os_detection, 'unreliable', return_value=True):
			self.assertEqual(os_detection.clear_stored_guesses(), 1)
			self.assertEqual(os_detection.clear_stored_guesses(), 0)


class SentinelFlagTests(TestCase):
	"""A Sentinel's guess is believed unless it says it sits behind Docker Desktop's network too."""

	def run_nmap(self, result):
		from agentapi import sentinel_dispatch
		with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
		     mock.patch.object(sentinel_dispatch, 'dispatch_or_none', return_value=result):
			sentinel_dispatch.try_nmap(SimpleNamespace(id=1), None, ['203.0.113.60'])
		return IpAddress.objects.get(address='203.0.113.60').os_guess

	def hosts(self):
		return [{'ip': '203.0.113.60', 'os_guess': 'Google Fuchsia', 'ports': []}]

	def test_a_sentinels_guess_is_stored(self):
		self.assertEqual(self.run_nmap({'hosts': self.hosts()}), 'Google Fuchsia')

	def test_a_sentinel_that_says_its_guesses_are_unreliable_is_not_believed(self):
		self.assertEqual(self.run_nmap({'hosts': self.hosts(), 'os_reliable': False}), '')
