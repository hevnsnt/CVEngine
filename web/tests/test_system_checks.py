from django.test import SimpleTestCase, override_settings

from cveFeed.checks import allowed_hosts_check


class AllowedHostsCheckTests(SimpleTestCase):
	def ids(self, domain, hosts):
		with override_settings(DOMAIN_NAME=domain, ALLOWED_HOSTS=hosts):
			return [w.id for w in allowed_hosts_check()]

	def test_a_placeholder_or_loopback_site_name_warns(self):
		for domain in ('', 'localhost:8000', 'cvengine.example.com', 'scanner.test'):
			self.assertEqual(self.ids(domain, ['localhost', '127.0.0.1', '[::1]']), ['cvengine.W001'], domain)

	def test_a_real_name_or_an_explicit_extra_host_does_not(self):
		self.assertEqual(self.ids('scanner.acme-example.ai', ['scanner.acme-example.ai', 'localhost']), [])
		self.assertEqual(self.ids('myexample.com', ['myexample.com', 'localhost']), [])  # a real domain, not the placeholder
		self.assertEqual(self.ids('localhost:8000', ['localhost', '192.0.2.10']), [])  # CVENGINE_ALLOWED_HOSTS names one

	def test_it_is_registered(self):
		from django.core import checks
		self.assertIn(allowed_hosts_check, checks.registry.registry.get_checks())
