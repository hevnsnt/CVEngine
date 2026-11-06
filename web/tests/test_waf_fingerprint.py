"""The WAF fingerprint stage: a Sentinel names the product in front of a web host and the server stores it as a technology; a generic block, no
firewall, a failure and a host inside its window name nothing. The kind never runs on this server (``sentinel_dispatch.NEVER_LOCAL``)."""
import json
import unittest
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_broker as broker
from cveFeed import waf_fingerprint
from cveFeed.models import ServiceRun
from startScan.models import Subdomain, Technology
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally
from tests.test_fake_scanner import NoRealSleep
from tests.test_route_auth import RouteFixture

IP = '203.0.113.5'  # RouteFixture's address


class NamedTests(unittest.TestCase):
	def test_a_named_firewall_is_a_product(self):
		self.assertEqual(waf_fingerprint._named([('FortiWeb', 'Fortinet')]), [{'firewall': 'FortiWeb', 'manufacturer': 'Fortinet'}])

	def test_generic_none_and_empty_names_are_no_product(self):
		self.assertEqual(waf_fingerprint._named([('Generic', 'Unknown'), ('None', 'None'), ('', ''), (None, None), ('unknown', '')]), [])

	def test_a_product_named_twice_counts_once_and_a_long_name_is_cut(self):
		out = waf_fingerprint._named([('Cloudflare', 'x'), ('cloudflare', 'x'), ('A' * 500, '')])
		self.assertEqual([r['firewall'] for r in out], ['Cloudflare', 'A' * 100])


class StageTests(NoRealSleep, RouteFixture, TestCase):
	"""``run_for_scan`` hands each web site to a Sentinel and stores what comes back; nothing runs here."""

	def setUp(self):
		super().setUp()
		LocalFallback('none').apply(self)
		self.no_real_sleep()
		mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True).start()
		self.guard = assert_ran_nowhere_locally(self, 'waf')

	def scan_with_web_hosts(self, *names):
		scan = self.scan(names=names)
		Subdomain.objects.filter(scan_history=scan).update(http_status=200, http_url='https://www.rt.test/login?next=/x')
		return scan

	def run_it(self, scan, responder=None, mode='ok', **kw):
		with FakeScanner(kinds=['waf'], mode=mode, responders={'waf': responder} if responder else None) as fake:
			out = waf_fingerprint.run_for_scan(scan.id, **kw)
		return out, fake

	def test_the_product_becomes_a_technology_of_the_host_and_the_site_root_is_what_is_asked(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		out, fake = self.run_it(scan, {'outcome': 'done', 'generic': False, 'products': [{'name': 'FortiWeb', 'manufacturer': 'Fortinet'}]})
		self.assertEqual(fake.served[0]['target'], {'host': 'www.rt.test', 'ip': IP, 'port': 443, 'scheme': 'https'})  # the root, never the path the host's URL carried
		self.assertEqual((out['tested'], out['named']), (1, 1))
		self.assertEqual([t.name for t in Subdomain.objects.get(scan_history=scan).technologies.all()], ['FortiWeb'])
		self.assertEqual(self.guard.calls, [])

	def test_a_host_that_did_not_answer_over_http_is_not_asked(self):
		scan = self.scan(names=('www.rt.test',))  # http_status stays 0
		out, fake = self.run_it(scan)
		self.assertEqual((out, fake.served), ({'checked': 0}, []))

	def test_a_generic_block_names_nothing_but_is_counted_and_not_asked_again_inside_the_window(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		with FakeScanner(kinds=['waf'], responders={'waf': {'outcome': 'done', 'generic': True, 'products': []}}) as fake:
			out = waf_fingerprint.run_for_scan(scan.id)
			self.assertEqual((out['generic'], out['named']), (1, 0))
			self.assertEqual(Subdomain.objects.get(scan_history=scan).technologies.count(), 0)
			self.assertEqual(len(fake.served), 1)
			again = waf_fingerprint.run_for_scan(scan.id)
			self.assertEqual((len(fake.served), again['tested'], again['reused']), (1, 0, 1))
			waf_fingerprint.run_for_scan(scan.id, force=True)
			self.assertEqual(len(fake.served), 2)

	def test_with_no_scanner_the_hosts_stay_due_and_nothing_is_recorded(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		out, fake = self.run_it(scan, mode='offline')
		self.assertEqual(fake.served, [])
		self.assertIn('no scanner could take this work (waf)', out['skipped'])
		self.assertFalse(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE).exists())
		self.assertEqual(self.guard.calls, [])

	def test_a_failed_task_is_not_recorded_so_the_next_scan_asks_again(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		out, _ = self.run_it(scan, mode='fail')
		self.assertIn('no scanner could take this work (waf)', out['skipped'])
		self.assertFalse(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE).exists())

	def test_it_can_be_turned_off_and_is_bounded_per_scan(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		with mock.patch.dict('os.environ', {'CVENGINE_WAFW00F': '0'}):
			self.assertEqual(waf_fingerprint.run_for_scan(scan.id), {'checked': 0, 'skipped': 'disabled'})
		scan = self.scan_with_web_hosts('a.rt.test', 'b.rt.test', 'c.rt.test')
		with mock.patch.dict('os.environ', {'CVENGINE_WAFW00F_MAX_HOSTS': '2'}):
			out, fake = self.run_it(scan)
		self.assertEqual((out['tested'], len(fake.served)), (2, 2))


class ContractResultTests(RouteFixture, TestCase):
	"""A Sentinel's ``waf`` result is stored as technologies of the host, whatever its names."""
	def two_hosts(self):
		scan = self.scan(names=('local.rt.test', 'remote.rt.test'))
		Subdomain.objects.filter(scan_history=scan).update(http_status=200)
		for sub in Subdomain.objects.filter(scan_history=scan):
			Subdomain.objects.filter(pk=sub.pk).update(http_url=f'https://{sub.name}/')
		return scan, Subdomain.objects.get(scan_history=scan, name='local.rt.test'), Subdomain.objects.get(scan_history=scan, name='remote.rt.test')

	def stored(self, sub):
		return sorted(sub.technologies.values_list('name', 'version', 'category'))

	def test_the_fixture_is_stored_as_technologies_of_the_host(self):
		fixture = json.loads((Path(__file__).parent / 'fixtures' / 'sentinel_results' / 'waf.json').read_text())
		result = broker.clean_result('waf', fixture)
		scan, _local, remote = self.two_hosts()
		out = waf_fingerprint.persist_waf_result(self.project, remote, result, scan)
		self.assertEqual(out, {'named': 2, 'generic': False, 'recorded': True})
		self.assertEqual([t[0] for t in self.stored(remote)], ['ExampleShield', 'FortiWeb'])
		self.assertEqual(Technology.objects.filter(name__in=['FortiWeb', 'ExampleShield']).count(), 2)  # the one technology row each, shared

	def test_the_same_rules_apply_to_a_sentinels_names_as_to_wafw00fs(self):
		scan, _local, remote = self.two_hosts()
		result = {'outcome': 'done', 'generic': False, 'products': [{'name': ' Cloudflare ', 'manufacturer': 'Cloudflare, Inc.'}, {'name': 'cloudflare'},
			{'name': 'Generic'}, {'name': 'None'}, {'name': 'A' * waf_fingerprint.NAME_LEN}]}
		out = waf_fingerprint.persist_waf_result(self.project, remote, result, scan)
		self.assertEqual((out['named'], out['generic']), (2, False))
		self.assertEqual(sorted(t.name for t in remote.technologies.all()), ['A' * waf_fingerprint.NAME_LEN, 'Cloudflare'])

	def test_a_generic_block_names_nothing_but_the_host_is_not_asked_again_inside_the_window(self):
		scan, _local, remote = self.two_hosts()
		out = waf_fingerprint.persist_waf_result(self.project, remote, {'outcome': 'done', 'products': [], 'generic': True}, scan)
		self.assertEqual(out, {'named': 0, 'generic': True, 'recorded': True})
		self.assertEqual(remote.technologies.count(), 0)
		self.assertEqual(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE, asset='remote.rt.test').count(), 1)

	def test_a_result_that_is_not_done_stores_and_records_nothing(self):
		scan, _local, remote = self.two_hosts()
		for result in ({'outcome': 'error', 'error': 'timed out'}, {}, None, 'done'):
			self.assertEqual(waf_fingerprint.persist_waf_result(self.project, remote, result, scan), {'named': 0, 'generic': False, 'recorded': False})
		self.assertFalse(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE).exists())
		self.assertEqual(remote.technologies.count(), 0)

	def test_a_host_of_another_project_is_refused(self):
		from dashboard.models import Project
		scan, _local, remote = self.two_hosts()
		other = Project.objects.create(name='Q', slug='pq', insert_date=timezone.now(), org=self.project.org)
		with self.assertRaises(ValueError):
			waf_fingerprint.persist_waf_result(other, remote, {'outcome': 'done', 'products': [{'name': 'FortiWeb'}], 'generic': False}, scan)
		self.assertEqual(remote.technologies.count(), 0)
		self.assertFalse(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE).exists())


if __name__ == '__main__':
	unittest.main()
