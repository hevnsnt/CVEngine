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

	def test_the_override_wins_either_way(self):
		with self.kernel('6.10.14-linuxkit'), mock.patch.dict(os.environ, {'CVENGINE_OS_DETECTION': 'trust'}):
			self.assertFalse(os_detection.unreliable())
		with self.kernel('6.8.0-45-generic'), mock.patch.dict(os.environ, {'CVENGINE_OS_DETECTION': 'distrust'}):
			self.assertTrue(os_detection.unreliable())

	def test_the_reason_names_the_fix(self):
		self.assertIn('Docker Desktop', os_detection.REASON)
		self.assertIn('Sentinel', os_detection.REASON)


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
