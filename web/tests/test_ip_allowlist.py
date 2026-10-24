from django.contrib.auth.models import User
from django.test import Client, TestCase

from dashboard.models import IpAccessControl, IpAllowlistEntry
from reNgine import ip_allowlist as ipa


class IsAllowedTests(TestCase):
	def setUp(self):
		self.addCleanup(ipa.invalidate_cache)
		ipa.invalidate_cache()

	def test_disabled_allows_everything(self):
		self.assertTrue(ipa.is_allowed('203.0.113.9'))
		self.assertTrue(ipa.is_allowed('not-an-ip'))

	def test_enabled_only_allows_matching_entries(self):
		IpAccessControl.objects.create(enabled=True)
		IpAllowlistEntry.objects.create(cidr='203.0.113.0/24')
		IpAllowlistEntry.objects.create(cidr='10.1.2.3')
		ipa.invalidate_cache()
		self.assertTrue(ipa.is_allowed('203.0.113.9'))
		self.assertTrue(ipa.is_allowed('10.1.2.3'))
		self.assertFalse(ipa.is_allowed('10.1.2.4'))
		self.assertFalse(ipa.is_allowed('198.51.100.1'))

	def test_malformed_client_ip_is_denied_when_enabled(self):
		IpAccessControl.objects.create(enabled=True)
		IpAllowlistEntry.objects.create(cidr='203.0.113.0/24')
		ipa.invalidate_cache()
		self.assertFalse(ipa.is_allowed(''))
		self.assertFalse(ipa.is_allowed('garbage'))

	def test_invalid_stored_entry_is_skipped_not_fatal(self):
		IpAccessControl.objects.create(enabled=True)
		IpAllowlistEntry.objects.create(cidr='not a cidr')
		IpAllowlistEntry.objects.create(cidr='203.0.113.0/24')
		ipa.invalidate_cache()
		self.assertTrue(ipa.is_allowed('203.0.113.1'))
		self.assertFalse(ipa.is_allowed('10.0.0.1'))

	def test_result_is_cached_until_invalidated(self):
		ipa.invalidate_cache()
		self.assertTrue(ipa.is_allowed('203.0.113.9'))  # caches "disabled"
		IpAccessControl.objects.create(enabled=True)
		IpAllowlistEntry.objects.create(cidr='10.0.0.0/8')
		self.assertTrue(ipa.is_allowed('203.0.113.9'))  # stale cache, not yet reflecting the enable
		ipa.invalidate_cache()
		self.assertFalse(ipa.is_allowed('203.0.113.9'))  # now enforced


class MiddlewareIntegrationTests(TestCase):
	def setUp(self):
		self.addCleanup(ipa.invalidate_cache)
		ipa.invalidate_cache()
		self.user = User.objects.create_user('ipuser', password='x')

	def test_disabled_by_default_everything_reaches_the_app(self):
		c = Client()
		response = c.get('/login/', REMOTE_ADDR='203.0.113.9')
		self.assertEqual(response.status_code, 200)

	def test_enabled_blocks_every_path_for_a_non_listed_ip_before_auth(self):
		IpAccessControl.objects.create(enabled=True)
		IpAllowlistEntry.objects.create(cidr='10.0.0.0/8')
		ipa.invalidate_cache()
		c = Client()
		for path in ('/login/', '/cve/', '/admin/', '/mcp/'):
			response = c.get(path, REMOTE_ADDR='203.0.113.9')
			self.assertEqual(response.status_code, 403, path)

	def test_enabled_allows_a_listed_ip_through(self):
		IpAccessControl.objects.create(enabled=True)
		IpAllowlistEntry.objects.create(cidr='203.0.113.0/24')
		ipa.invalidate_cache()
		c = Client()
		response = c.get('/login/', REMOTE_ADDR='203.0.113.9')
		self.assertEqual(response.status_code, 200)
