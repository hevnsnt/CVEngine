"""Scanner wrappers that used to call ``subprocess.run`` (testssl.sh, wafw00f) and the in-process checks (node2shell, the database
exposure probes) run under ``resources.heavy_job``: a global pause or a stopped scan reaches them, and a timeout stops the whole process group."""
import os
import subprocess
import time
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import heavy_process
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
				with open(f'/proc/{child}/stat') as status:
					state = status.read().rsplit(')', 1)[1].split()[0]
			except FileNotFoundError:
				break
			if state == 'Z':  # a reparented zombie cannot run; the container's PID 1 may reap it later
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
