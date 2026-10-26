import os
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import ledger
from cveFeed.models import ServiceRun
from dashboard.models import Org, Project


class LedgerTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='L', slug='l')
		self.a = Project.objects.create(name='A', slug='la', insert_date=timezone.now(), org=org)
		self.b = Project.objects.create(name='B', slug='lb', insert_date=timezone.now(), org=org)

	def test_a_run_inside_the_ttl_is_fresh_and_outside_it_is_not(self):
		ledger.record('nuclei', ['x.test', 'y.test'], self.a)
		self.assertEqual(ledger.fresh('nuclei', ['x.test', 'y.test', 'z.test'], self.a), {'x.test', 'y.test'})
		ServiceRun.objects.filter(asset='y.test').update(finished_at=timezone.now() - timedelta(hours=25))
		self.assertEqual(ledger.fresh('nuclei', ['x.test', 'y.test'], self.a), {'x.test'})

	def test_ttl_defaults_and_env_override(self):
		self.assertEqual(ledger.ttl('nmap-fast'), 7 * 86400)
		self.assertEqual(ledger.ttl('nmap-full'), 14 * 86400)
		self.assertEqual(ledger.ttl('nuclei:cve,nginx'), 86400)
		with mock.patch.dict(os.environ, {'CVENGINE_TTL_NMAP_FAST': '2'}):
			self.assertEqual(ledger.ttl('nmap-fast'), 7200)

	def test_a_failed_run_is_not_fresh_and_a_rerun_updates_the_same_row(self):
		ledger.record('nuclei', ['x.test'], self.a, status='failed')
		self.assertEqual(ledger.fresh('nuclei', ['x.test'], self.a), set())
		ledger.record('nuclei', ['x.test'], self.a)
		self.assertEqual(ledger.fresh('nuclei', ['x.test'], self.a), {'x.test'})
		self.assertEqual(ServiceRun.objects.filter(service='nuclei', asset='x.test').count(), 1)

	def test_project_rows_do_not_leak_and_global_rows_are_unique_and_shared(self):
		ledger.record('nuclei', ['x.test'], self.a)
		self.assertEqual(ledger.fresh('nuclei', ['x.test'], self.b), set())
		ledger.record('nmap-fast', ['192.0.2.1'])
		ledger.record('nmap-fast', ['192.0.2.1'])
		self.assertEqual(ServiceRun.objects.filter(service='nmap-fast').count(), 1)  # global rows are unique too
		# nmap callers always ask with project None, so the row is fresh whichever project is scanning
		self.assertEqual(ledger.fresh('nmap-fast', ['192.0.2.1']), {'192.0.2.1'})
		self.assertEqual(ledger.fresh('nmap-fast', ['192.0.2.1'], self.a), set())

	def test_tag_service_names_are_stable_and_short(self):
		self.assertEqual(ledger.nuclei_tag_service(['b', 'a']), 'nuclei:a,b')
		self.assertLessEqual(len(ledger.nuclei_tag_service([f'tag{i}' for i in range(50)])), 64)


class ClaimTests(TestCase):
	def setUp(self):
		from reNgine import resources
		if getattr(resources.get_store(), 'r', None) is None:
			self.skipTest('no Redis to hold claims in this environment')
		self.asset = f'claim-{os.getpid()}-{timezone.now().timestamp()}.test'

	def test_a_second_concurrent_claim_is_refused(self):
		with ledger.claim('nmap-fast', self.asset) as first:
			self.assertTrue(first)
			with ledger.claim('nmap-fast', self.asset) as second:
				self.assertFalse(second)
		with ledger.claim('nmap-fast', self.asset) as again:
			self.assertTrue(again)  # released on exit

	def test_claim_many_returns_only_what_it_won_and_releases_it(self):
		other = self.asset + '.other'
		with ledger.claim('nmap-fast', other):
			with ledger.claim_many('nmap-fast', [self.asset, other]) as won:
				self.assertEqual(won, [self.asset])
		with ledger.claim_many('nmap-fast', [self.asset, other]) as won:
			self.assertEqual(sorted(won), sorted([self.asset, other]))


class NoRedisTests(TestCase):
	def test_claims_succeed_without_redis(self):
		from reNgine import resources
		with mock.patch.object(resources, 'get_store', return_value=object()):
			with ledger.claim('nmap-fast', 'a.test') as ok:
				self.assertTrue(ok)
			with ledger.claim_many('nmap-fast', ['a.test', 'b.test']) as won:
				self.assertEqual(won, ['a.test', 'b.test'])


class AtomicClaimTests(TestCase):
	def setUp(self):
		from reNgine import resources
		client = getattr(resources.get_store(), 'r', None)
		if client is None:
			self.skipTest('no Redis to hold claims in this environment')
		self.client, self.resources = client, resources
		self.key = f'cvengine:test-claim:{os.getpid()}:{timezone.now().timestamp()}'
		self.addCleanup(lambda: self.client.delete(self.key))

	def test_a_holder_extends_and_releases_only_its_own_claim(self):
		self.client.set(self.key, 'mine', ex=100)
		self.assertEqual(self.resources.claim_refresh(self.client, self.key, 'mine', 500), 'ok')
		self.assertGreater(self.client.ttl(self.key), 200)
		self.assertFalse(self.resources.claim_release(self.client, self.key, 'someone-else'))
		self.assertEqual(self.client.get(self.key), 'mine')
		self.assertTrue(self.resources.claim_release(self.client, self.key, 'mine'))
		self.assertIsNone(self.client.get(self.key))

	def test_a_lapsed_claim_taken_by_another_job_is_never_extended_or_deleted_by_the_old_holder(self):
		self.client.set(self.key, 'new-holder', ex=30)
		self.assertEqual(self.resources.claim_refresh(self.client, self.key, 'old-holder', 9999), 'lost')
		self.assertLessEqual(self.client.ttl(self.key), 30)  # the new holder's expiry is untouched
		self.assertFalse(self.resources.claim_release(self.client, self.key, 'old-holder'))
		self.assertEqual(self.client.get(self.key), 'new-holder')

	def test_a_claim_that_expired_is_taken_again_when_nobody_else_has_it(self):
		self.assertEqual(self.resources.claim_refresh(self.client, self.key, 'me', 60), 'regained')
		self.assertEqual(self.client.get(self.key), 'me')
