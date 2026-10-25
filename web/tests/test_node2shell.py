from unittest import mock

from django.test import TestCase

from cveFeed import discovery, node2shell_scan
from cveFeed.models import RouteAuth, ServiceRun
from startScan.models import Subdomain, Technology, Vulnerability
from tests.test_route_auth import RouteFixture

VULNERABLE = {'vulnerable': True, 'verdict': 'VULNERABLE', 'reason': 'the 23068764-byte probe reached the valid route',
              'response': 'HTTP/1.1 200 OK\r\n\r\n{"ok":true}', 'status_code': 200}
NOT_VULNERABLE = {'vulnerable': False, 'verdict': 'NO SIGNAL', 'reason': 'the probe matched neither learned class'}
INCONCLUSIVE = {'vulnerable': None, 'verdict': 'INCONCLUSIVE', 'error': 'valid Brotli control request failed: timed out'}


class EnabledTests(TestCase):
	def test_disabled_unless_explicitly_turned_on(self):
		with mock.patch.dict('os.environ', {}, clear=False):
			import os
			os.environ.pop('CVENGINE_NODE2SHELL', None)
			self.assertFalse(node2shell_scan.enabled())
		with mock.patch.dict('os.environ', {'CVENGINE_NODE2SHELL': '1'}):
			self.assertTrue(node2shell_scan.enabled())
		with mock.patch.dict('os.environ', {'CVENGINE_NODE2SHELL': '0'}):
			self.assertFalse(node2shell_scan.enabled())


class NodeSitesTests(RouteFixture, TestCase):
	def test_a_technology_row_names_the_site(self):
		scan = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
		sub = Subdomain.objects.get(scan_history=scan)
		sub.technologies.add(Technology.objects.create(name='Express:4.18.2'))
		self.assertEqual([s.name for s, _u in node2shell_scan.node_sites(scan)], ['api.rt.test'])

	def test_a_plain_nodejs_technology_name_also_matches(self):
		scan = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
		sub = Subdomain.objects.get(scan_history=scan)
		sub.technologies.add(Technology.objects.create(name='Node.js'))
		self.assertEqual(len(node2shell_scan.node_sites(scan)), 1)

	def test_a_route_fingerprint_also_identifies_a_node_host(self):
		scan = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
		sub = Subdomain.objects.get(scan_history=scan)
		RouteAuth.objects.create(project=self.project, domain=self.domain, host=sub.name, url=f'https://{sub.name}/', path='/',
								 auth_state='open', evidence={'fingerprint_names': ['Express:4.18.2']})
		self.assertEqual(len(node2shell_scan.node_sites(scan)), 1)

	def test_an_unrelated_technology_is_not_a_candidate(self):
		scan = self.scan(names=('www.rt.test',), ports=((443, 'https'),))
		sub = Subdomain.objects.get(scan_history=scan)
		sub.technologies.add(Technology.objects.create(name='nginx'))
		self.assertEqual(node2shell_scan.node_sites(scan), [])

	def test_no_hosts_at_all_is_a_no_op(self):
		scan = self.scan(names=(), ports=())
		self.assertEqual(node2shell_scan.node_sites(scan), [])


class RunForScanTests(RouteFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.scan_obj = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
		self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
		self.sub.technologies.add(Technology.objects.create(name='Express:4.18.2'))
		self.calls = []

	def checker(self, url, **kw):
		self.calls.append(url)
		return self.result

	def go(self, **kw):
		with mock.patch('cveFeed.node2shell_scan.enabled', return_value=True):
			return node2shell_scan.run_for_scan(self.scan_obj.id, checker=self.checker, **kw)

	def test_disabled_by_default(self):
		self.result = VULNERABLE
		out = node2shell_scan.run_for_scan(self.scan_obj.id, checker=self.checker)
		self.assertEqual(out, {'checked': 0, 'skipped': 'disabled'})
		self.assertEqual(self.calls, [])

	def test_a_vulnerable_verdict_is_a_critical_finding_with_the_cve_id(self):
		self.result = VULNERABLE
		out = self.go()
		self.assertEqual(self.calls, ['https://api.rt.test'])
		self.assertEqual((out['tested'], out['vulnerable'], out['errors']), (1, 1, 0))
		vuln = Vulnerability.objects.get(source='node2shell')
		self.assertEqual((vuln.severity, vuln.subdomain_id, vuln.http_url), (4, self.sub.id, 'https://api.rt.test'))
		self.assertEqual([c.name for c in vuln.cve_ids.all()], ['CVE-2026-111497'])
		self.assertTrue(ServiceRun.objects.filter(service='node2shell', asset='api.rt.test').exists())

	def test_not_vulnerable_creates_no_finding(self):
		self.result = NOT_VULNERABLE
		out = self.go()
		self.assertEqual((out['tested'], out['vulnerable'], out['errors']), (1, 0, 0))
		self.assertFalse(Vulnerability.objects.filter(source='node2shell').exists())

	def test_inconclusive_creates_no_finding_but_is_counted(self):
		self.result = INCONCLUSIVE
		out = self.go()
		self.assertEqual((out['vulnerable'], out['errors']), (0, 1))
		self.assertFalse(Vulnerability.objects.filter(source='node2shell').exists())

	def test_a_raising_checker_is_caught_by_run_check_not_the_stage(self):
		# run_check (the real default) never lets an exception through; prove that contract directly
		out = node2shell_scan.run_check('https://nowhere.invalid/', timeout_s=1)
		self.assertIsNone(out['vulnerable'])
		self.assertIn('verdict', out)

	def test_runs_once_per_window_then_only_on_force(self):
		self.result = NOT_VULNERABLE
		self.go()
		again = self.go()
		self.assertEqual(again['tested'], 0)
		self.assertEqual(again['reused'], 1)
		self.go(force=True)
		self.assertEqual(len(self.calls), 2)

	def test_bounded_per_scan(self):
		self.result = NOT_VULNERABLE
		for i in range(3):
			sub = Subdomain.objects.create(name=f'api{i}.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
			sub.technologies.add(Technology.objects.get(name='Express:4.18.2'))
		with mock.patch('cveFeed.node2shell_scan.max_hosts', return_value=2):
			out = self.go()
		self.assertEqual(out['tested'], 2)

	def test_no_candidates_is_a_no_op(self):
		other = self.scan(names=('plain.rt.test',), ports=((443, 'https'),))
		with mock.patch('cveFeed.node2shell_scan.enabled', return_value=True):
			out = node2shell_scan.run_for_scan(other.id, checker=self.checker)
		self.assertEqual(out, {'checked': 0})
		self.assertEqual(self.calls, [])


class PipelineWiringTests(RouteFixture, TestCase):
	def test_the_pipeline_runs_the_stage_only_when_enabled_and_a_candidate_exists(self):
		scan = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
		sub = Subdomain.objects.get(scan_history=scan)
		sub.technologies.add(Technology.objects.create(name='Express:4.18.2'))
		calls = []

		def checker(url, **kw):
			calls.append(url)
			return NOT_VULNERABLE
		with mock.patch('cveFeed.node2shell_scan.enabled', return_value=True), mock.patch('cveFeed.discovery.stopped', return_value=False):
			discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False,
								  nmap_runner=lambda targets, flags, timeout: '', db_exposure_checks={}, provider=None,
								  light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
								  route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''},
								  node2shell_checker=checker)
		self.assertEqual(calls, ['https://api.rt.test'])
		from startScan.models import ScanActivity
		self.assertTrue(ScanActivity.objects.filter(scan_of=scan, name='node2shell').exists())

	def test_disabled_by_default_the_stage_never_starts(self):
		scan = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
		sub = Subdomain.objects.get(scan_history=scan)
		sub.technologies.add(Technology.objects.create(name='Express:4.18.2'))
		from startScan.models import ScanActivity
		with mock.patch('cveFeed.discovery.stopped', return_value=False):
			discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False,
								  nmap_runner=lambda targets, flags, timeout: '', db_exposure_checks={}, provider=None,
								  light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
								  route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
		self.assertFalse(ScanActivity.objects.filter(scan_of=scan, name='node2shell').exists())
