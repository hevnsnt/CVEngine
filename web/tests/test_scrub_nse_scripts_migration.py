import importlib

from django.apps import apps
from django.test import TestCase

from startScan.models import IpAddress, Port

migration = importlib.import_module('startScan.migrations.0016_scrub_unreviewed_nse_scripts')


class ScrubUnreviewedNseScriptsTests(TestCase):
	# The upgrade-time cleanup for hosts scanned before NSE_SCRIPTS was narrowed, or before -sV's "version" category
	# scripts started being filtered at persist time: old, unreviewed script output must not linger on the host page
	# until that host's next scan, which could be up to 7 days away.
	def go(self):
		migration.scrub(apps, None)

	def test_an_unreviewed_script_is_stripped_and_a_reviewed_one_survives(self):
		port = Port.objects.create(number=21, extra={'scripts': {'ftp-anon': 'Anonymous FTP login allowed', 'rpcinfo': 'ERROR'},
			'script_text': 'Anonymous FTP login allowed\nERROR'})
		self.go()
		port.refresh_from_db()
		self.assertEqual(port.extra['scripts'], {'ftp-anon': 'Anonymous FTP login allowed'})
		self.assertEqual(port.extra['script_text'], 'Anonymous FTP login allowed')

	def test_a_port_with_only_unreviewed_scripts_loses_the_scripts_keys_entirely(self):
		port = Port.objects.create(number=443, extra={'scripts': {'vmware-version': 'ERROR'}, 'script_text': 'ERROR', 'cpes': ['cpe:/a:x']})
		self.go()
		port.refresh_from_db()
		self.assertNotIn('scripts', port.extra)
		self.assertNotIn('script_text', port.extra)
		self.assertEqual(port.extra['cpes'], ['cpe:/a:x'])  # untouched

	def test_a_port_already_clean_is_left_alone(self):
		port = Port.objects.create(number=22, extra={'scripts': {'ssh-hostkey': '256 aa:bb (ED25519)'}})
		self.go()
		port.refresh_from_db()
		self.assertEqual(port.extra['scripts'], {'ssh-hostkey': '256 aa:bb (ED25519)'})

	def test_a_port_with_no_scripts_at_all_is_left_alone(self):
		port = Port.objects.create(number=80, extra={'cpes': ['cpe:/a:nginx']})
		self.go()
		port.refresh_from_db()
		self.assertEqual(port.extra, {'cpes': ['cpe:/a:nginx']})

	def test_host_level_scripts_are_scrubbed_the_same_way(self):
		ip = IpAddress.objects.create(address='192.0.2.40', fingerprint={'scripts': {'smb-os-discovery': 'OS: Windows', 'hnap-info': 'ERROR'},
			'facts': {'os': 'Windows Server 2022'}})
		self.go()
		ip.refresh_from_db()
		self.assertEqual(ip.fingerprint['scripts'], {'smb-os-discovery': 'OS: Windows'})
		self.assertEqual(ip.fingerprint['facts'], {'os': 'Windows Server 2022'})  # untouched

	def test_a_host_with_only_unreviewed_scripts_loses_the_scripts_key(self):
		ip = IpAddress.objects.create(address='192.0.2.41', fingerprint={'scripts': {'hnap-info': 'ERROR'}})
		self.go()
		ip.refresh_from_db()
		self.assertNotIn('scripts', ip.fingerprint)
