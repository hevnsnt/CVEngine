"""Scanner wrappers that used to call ``subprocess.run`` (wpscan, testssl.sh, wafw00f) and the in-process checks (node2shell, the database
exposure probes) run under ``resources.heavy_job``: a global pause or a stopped scan reaches them, and a timeout stops the whole process group."""
import os
import subprocess
import time
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import heavy_process, node2shell_scan, testssl_scan, waf_scan, wpscan_scan
from reNgine import resources
from tests.test_route_auth import RouteFixture


class RunTests(SimpleTestCase):
	def test_the_output_comes_back_and_the_job_is_released(self):
		done = heavy_process.run('route-probe', ['sh', '-c', 'echo out; echo err >&2; exit 3'], 20, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.assertEqual((done.returncode, done.stdout.strip(), done.stderr.strip()), (3, 'out', 'err'))

	def test_a_timeout_stops_the_whole_process_group_not_only_the_leader(self):
		pidfile = f'/tmp/cve-heavy-{os.getpid()}.pid'
		self.addCleanup(lambda: os.path.exists(pidfile) and os.unlink(pidfile))
		with self.assertRaises(subprocess.TimeoutExpired):
			heavy_process.run('route-probe', ['sh', '-c', f'sleep 60 & echo $! > {pidfile}; wait'], 1.5)
		child = int(open(pidfile).read())
		for _ in range(40):  # the grandchild goes with the group (a plain subprocess.run would have left it running)
			try:
				os.kill(child, 0)
			except ProcessLookupError:
				break
			time.sleep(0.25)
		else:
			os.kill(child, 9)
			self.fail('the child of the timed-out tool is still running')

	def test_a_global_pause_kills_the_tool_and_raises_scan_aborted(self):
		started = time.monotonic()
		with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
			with self.assertRaises(resources.ScanAborted):
				heavy_process.run('route-probe', ['sleep', '60'], 120)
		self.assertLess(time.monotonic() - started, 30)


class WpscanTests(SimpleTestCase):
	def test_the_wpscan_process_goes_through_the_gate_under_its_own_kind(self):
		seen = {}

		def fake(kind, argv, timeout, **kw):
			seen.update(kind=kind, timeout=timeout, env=kw.get('env'))
			with open(argv[argv.index('-o') + 1], 'w') as out:
				out.write('{"version": {"number": "6.0"}}')
			return mock.Mock(returncode=0, stderr='')
		with mock.patch('cveFeed.heavy_process.run', side_effect=fake):
			wpscan_scan.run_wpscan_process('https://www.example.test/', 'tok')
		self.assertEqual((seen['kind'], seen['env']['WPSCAN_API_TOKEN']), ('wpscan', 'tok'))
		self.assertIn('wpscan', resources.BASE_COSTS_MB)
		self.assertIn('testssl', resources.BASE_COSTS_MB)


class TestsslTests(SimpleTestCase):
	def test_the_default_runner_is_the_gated_one(self):
		with mock.patch('cveFeed.heavy_process.run') as run:
			testssl_scan._run(['testssl.sh', 'rt.test:443'], {'PATH': '/usr/bin'}, 120)
		run.assert_called_once_with('testssl', ['testssl.sh', 'rt.test:443'], 120, label='rt.test:443', env={'PATH': '/usr/bin'})


class WafTests(SimpleTestCase):
	def test_a_stopped_scan_is_an_error_result_not_a_crash(self):
		with mock.patch('cveFeed.heavy_process.run', side_effect=resources.ScanAborted('stopped')):
			out = waf_scan.run_wafw00f('https://www.example.test/')
		self.assertEqual((out['products'], out['error']), ([], 'stopped'))


class Node2shellTests(RouteFixture, TestCase):
	def test_a_pause_ends_the_loop_between_hosts_and_the_hosts_stay_due(self):
		scan = self.scan(names=('a.rt.test', 'b.rt.test'), ports=((443, 'https'),))
		from startScan.models import Subdomain, Technology
		for sub in Subdomain.objects.filter(scan_history=scan):
			sub.technologies.add(Technology.objects.get_or_create(name='Express:4.18.2')[0])
		asked = []

		class Job:
			def raise_if_killed(self):
				if asked:
					raise resources.ScanAborted('stopped')

		from contextlib import contextmanager

		@contextmanager
		def gate(kind, label='', **kw):
			yield Job()
		with mock.patch.dict('os.environ', {'CVENGINE_NODE2SHELL': '1'}), mock.patch('reNgine.resources.heavy_job', gate):
			out = node2shell_scan.run_for_scan(scan.id, checker=lambda url: asked.append(url) or {'vulnerable': False})
		self.assertEqual((len(asked), out['skipped']), (1, 'scanning was stopped or memory was short'))


class DbExposureTests(RouteFixture, TestCase):
	def test_a_stopped_scan_ends_the_database_checks(self):
		from contextlib import contextmanager

		from cveFeed import db_exposure
		scan = self.scan(names=('a.rt.test', 'b.rt.test'), ports=())
		from startScan.models import Port, Subdomain
		for sub in Subdomain.objects.filter(scan_history=scan):
			for ip in sub.ip_addresses.all():
				ip.ports.add(Port.objects.create(number=6379, service_name='redis', state='open'), Port.objects.create(number=6380, service_name='redis', state='open'))
		probed = []

		class Job:
			def raise_if_killed(self):
				if probed:
					raise resources.ScanAborted('stopped')

		@contextmanager
		def gate(kind, label='', **kw):
			yield Job()
		with mock.patch('reNgine.resources.heavy_job', gate):
			out = db_exposure.run_db_exposure_checks(scan.id, checks={'redis': ('Redis', lambda host, port: probed.append(host) or False)})
		self.assertEqual((len(probed), out['skipped']), (1, 'scanning was stopped or memory was short'))
