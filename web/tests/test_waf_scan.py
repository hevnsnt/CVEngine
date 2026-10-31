"""The wafw00f stage: it names the product in front of a web host and stores it as a technology; a generic block, no firewall, a failure and a host
inside its window name nothing. One test runs the real wafw00f against a server on this machine."""
import http.server
import json
import shutil
import threading
import unittest
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_broker as broker
from cveFeed import waf_scan
from cveFeed.models import ServiceRun
from startScan.models import Subdomain, Technology
from tests.test_route_auth import RouteFixture

NAMED = json.dumps([{'detected': True, 'firewall': 'FortiWeb', 'manufacturer': 'Fortinet', 'trigger_url': 'http://x/?a', 'url': 'http://x/'}])
GENERIC = json.dumps([{'detected': True, 'firewall': 'Generic', 'manufacturer': 'Unknown', 'trigger_url': 'http://x/?a', 'url': 'http://x/'}])
NONE = json.dumps([{'detected': False, 'firewall': 'None', 'manufacturer': 'None', 'trigger_url': None, 'url': 'http://x/'}])


class ParseTests(unittest.TestCase):
	def test_a_named_firewall_is_a_product(self):
		self.assertEqual(waf_scan.parse_output(NAMED), [{'firewall': 'FortiWeb', 'manufacturer': 'Fortinet'}])

	def test_generic_and_none_and_junk_name_nothing(self):
		for text in (GENERIC, NONE, '', 'not json', '{}', '[1, "a"]'):
			self.assertEqual(waf_scan.parse_output(text), [], text)

	def test_a_product_named_twice_counts_once_and_a_long_name_is_cut(self):
		rows = [{'detected': True, 'firewall': 'Cloudflare', 'manufacturer': 'x'}, {'detected': True, 'firewall': 'cloudflare', 'manufacturer': 'x'},
			{'detected': True, 'firewall': 'A' * 500, 'manufacturer': ''}]
		out = waf_scan.parse_output(json.dumps(rows))
		self.assertEqual([r['firewall'] for r in out], ['Cloudflare', 'A' * 100])


class StageTests(RouteFixture, TestCase):
	def scan_with_web_hosts(self, *names):
		scan = self.scan(names=names)
		Subdomain.objects.filter(scan_history=scan).update(http_status=200, http_url='https://www.rt.test/login?next=/x')
		return scan

	def run_it(self, scan, results, **kw):
		asked = []

		def runner(url):
			asked.append(url)
			return results.get(url, {'products': [], 'generic': False, 'error': ''})
		out = waf_scan.run_for_scan(scan.id, runner=runner, **kw)
		return out, asked

	def test_the_product_becomes_a_technology_of_the_host_and_the_site_root_is_what_is_asked(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		out, asked = self.run_it(scan, {'https://www.rt.test/': {'products': [{'firewall': 'FortiWeb', 'manufacturer': 'Fortinet'}], 'generic': False, 'error': ''}})
		self.assertEqual(asked, ['https://www.rt.test/'])  # the root, never the path or the query the host's own URL carried
		self.assertEqual((out['tested'], out['named']), (1, 1))
		self.assertEqual([t.name for t in Subdomain.objects.get(scan_history=scan).technologies.all()], ['FortiWeb'])

	def test_a_host_that_did_not_answer_over_http_is_not_asked(self):
		scan = self.scan(names=('www.rt.test',))  # http_status stays 0
		out, asked = self.run_it(scan, {})
		self.assertEqual((out, asked), ({'checked': 0}, []))

	def test_a_generic_block_names_nothing_but_is_counted_and_not_asked_again_inside_the_window(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		out, _ = self.run_it(scan, {'https://www.rt.test/': {'products': [], 'generic': True, 'error': ''}})
		self.assertEqual((out['generic'], out['named']), (1, 0))
		self.assertEqual(Subdomain.objects.get(scan_history=scan).technologies.count(), 0)
		again, asked = self.run_it(scan, {})
		self.assertEqual((asked, again['tested'], again['reused']), ([], 0, 1))
		_, forced = self.run_it(scan, {}, force=True)
		self.assertEqual(forced, ['https://www.rt.test/'])

	def test_a_failed_run_is_not_recorded_so_the_next_scan_asks_again(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		out, _ = self.run_it(scan, {'https://www.rt.test/': {'products': [], 'generic': False, 'error': 'timed out'}})
		self.assertEqual(out['errors'], 1)
		self.assertFalse(ServiceRun.objects.filter(service=waf_scan.SERVICE).exists())

	def test_it_can_be_turned_off_and_is_bounded_per_scan(self):
		scan = self.scan_with_web_hosts('www.rt.test')
		with mock.patch.dict('os.environ', {'CVENGINE_WAFW00F': '0'}):
			self.assertEqual(waf_scan.run_for_scan(scan.id), {'checked': 0, 'skipped': 'disabled'})
		scan = self.scan_with_web_hosts('a.rt.test', 'b.rt.test', 'c.rt.test')
		with mock.patch.dict('os.environ', {'CVENGINE_WAFW00F_MAX_HOSTS': '2'}):
			out, asked = self.run_it(scan, {})
		self.assertEqual((out['tested'], len(asked)), (2, 2))


class ContractResultTests(RouteFixture, TestCase):
	"""A Sentinel's ``waf`` result stores exactly what a local run of the same products stores."""
	def two_hosts(self):
		scan = self.scan(names=('local.rt.test', 'remote.rt.test'))
		Subdomain.objects.filter(scan_history=scan).update(http_status=200)
		for sub in Subdomain.objects.filter(scan_history=scan):
			Subdomain.objects.filter(pk=sub.pk).update(http_url=f'https://{sub.name}/')
		return scan, Subdomain.objects.get(scan_history=scan, name='local.rt.test'), Subdomain.objects.get(scan_history=scan, name='remote.rt.test')

	def stored(self, sub):
		return sorted(sub.technologies.values_list('name', 'version', 'category'))

	def test_the_fixture_stores_what_the_local_path_stores_for_the_same_products(self):
		fixture = json.loads((Path(__file__).parent / 'fixtures' / 'sentinel_results' / 'waf.json').read_text())
		result = broker.clean_result('waf', fixture)
		scan, local, remote = self.two_hosts()
		ran = {'products': [{'firewall': p['name'], 'manufacturer': p.get('manufacturer', '')} for p in fixture['products']], 'generic': False, 'error': ''}
		waf_scan.run_for_scan(scan.id, runner=lambda url: ran if 'local' in url else {'products': [], 'generic': False, 'error': ''}, force=True)
		self.assertEqual([t[0] for t in self.stored(local)], ['ExampleShield', 'FortiWeb'])
		out = waf_scan.persist_waf_result(self.project, remote, result, scan)
		self.assertEqual(out, {'named': 2, 'generic': False, 'recorded': True})
		self.assertEqual(self.stored(remote), self.stored(local))  # name, version and category: the same rows
		self.assertEqual(Technology.objects.filter(name__in=['FortiWeb', 'ExampleShield']).count(), 2)  # the one technology row each, shared

	def test_the_same_rules_apply_to_a_sentinels_names_as_to_wafw00fs(self):
		scan, _local, remote = self.two_hosts()
		result = {'outcome': 'done', 'generic': False, 'products': [{'name': ' Cloudflare ', 'manufacturer': 'Cloudflare, Inc.'}, {'name': 'cloudflare'},
			{'name': 'Generic'}, {'name': 'None'}, {'name': 'A' * waf_scan.NAME_LEN}]}
		out = waf_scan.persist_waf_result(self.project, remote, result, scan)
		self.assertEqual((out['named'], out['generic']), (2, False))
		self.assertEqual(sorted(t.name for t in remote.technologies.all()), ['A' * waf_scan.NAME_LEN, 'Cloudflare'])

	def test_a_generic_block_names_nothing_but_the_host_is_not_asked_again_inside_the_window(self):
		scan, _local, remote = self.two_hosts()
		out = waf_scan.persist_waf_result(self.project, remote, {'outcome': 'done', 'products': [], 'generic': True}, scan)
		self.assertEqual(out, {'named': 0, 'generic': True, 'recorded': True})
		self.assertEqual(remote.technologies.count(), 0)
		self.assertEqual(ServiceRun.objects.filter(service=waf_scan.SERVICE, asset='remote.rt.test').count(), 1)

	def test_a_result_that_is_not_done_stores_and_records_nothing(self):
		scan, _local, remote = self.two_hosts()
		for result in ({'outcome': 'error', 'error': 'timed out'}, {}, None, 'done'):
			self.assertEqual(waf_scan.persist_waf_result(self.project, remote, result, scan), {'named': 0, 'generic': False, 'recorded': False})
		self.assertFalse(ServiceRun.objects.filter(service=waf_scan.SERVICE).exists())
		self.assertEqual(remote.technologies.count(), 0)

	def test_a_host_of_another_project_is_refused(self):
		from dashboard.models import Project
		scan, _local, remote = self.two_hosts()
		other = Project.objects.create(name='Q', slug='pq', insert_date=timezone.now(), org=self.project.org)
		with self.assertRaises(ValueError):
			waf_scan.persist_waf_result(other, remote, {'outcome': 'done', 'products': [{'name': 'FortiWeb'}], 'generic': False}, scan)
		self.assertEqual(remote.technologies.count(), 0)
		self.assertFalse(ServiceRun.objects.filter(service=waf_scan.SERVICE).exists())


@unittest.skipUnless(shutil.which('wafw00f'), 'wafw00f is not installed')
class RealWafw00fTests(unittest.TestCase):
	"""The real tool against a server on this machine: one that blocks attack-looking requests the way a generic WAF does, and a plain one."""
	def serve(self, blocking):
		class Handler(http.server.BaseHTTPRequestHandler):
			def do_GET(self):
				bad = blocking and any(t in self.path.lower() for t in ('<script', 'union', '../', 'etc/passwd', 'xss', 'select', '%3cscript'))
				self.send_response(403 if bad else 200)
				self.end_headers()
				self.wfile.write(b'blocked' if bad else b'ok')

			def log_message(self, *args):
				pass
		server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
		threading.Thread(target=server.serve_forever, daemon=True).start()
		self.addCleanup(server.shutdown)
		return f'http://127.0.0.1:{server.server_port}/'

	def test_a_blocking_server_is_a_generic_detection_and_a_plain_one_is_nothing(self):
		blocked = waf_scan.run_wafw00f(self.serve(True), timeout_s=60)
		self.assertEqual((blocked['error'], blocked['products'], blocked['generic']), ('', [], True))
		plain = waf_scan.run_wafw00f(self.serve(False), timeout_s=60)
		self.assertEqual((plain['error'], plain['products'], plain['generic']), ('', [], False))

	def test_a_server_that_is_not_there_is_an_error_not_a_crash(self):
		out = waf_scan.run_wafw00f('http://127.0.0.1:9/', timeout_s=30)
		self.assertEqual(out['products'], [])


if __name__ == '__main__':
	unittest.main()
