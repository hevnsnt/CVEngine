import contextlib
import unittest
from unittest import mock

from cveFeed import nmap_scan
from reNgine import resources


class _Job:
	def attach(self, proc):
		pass

	def raise_if_killed(self):
		pass


class NmapSpeedTests(unittest.TestCase):
	def test_fast_profile_and_timeouts(self):
		flags = nmap_scan.FAST_FLAGS
		self.assertEqual(flags[flags.index('--version-intensity') + 1], '7')
		for wanted in ('-sV', '-O', '--osscan-limit', '-Pn', '-T4', '--defeat-rst-ratelimit'):
			self.assertIn(wanted, flags)
		self.assertEqual(flags[flags.index('--min-hostgroup') + 1], '32')
		self.assertEqual(flags[flags.index('--max-retries') + 1], '2')
		self.assertEqual(flags[flags.index('--top-ports') + 1], '1000')
		self.assertEqual(nmap_scan.HOST_TIMEOUT_FAST, '8m')

	def test_process_timeout_is_three_host_timeouts_plus_five_minutes_whatever_the_chunk_size(self):
		seen = []

		class Proc:
			returncode = 0

			def __init__(self, cmd, **kw):
				seen.append(cmd)

			def communicate(self, timeout=None):
				seen.append(timeout)
				return '<nmaprun/>', ''

		heavy = contextlib.contextmanager(lambda *a, **k: (yield _Job()))
		with mock.patch.object(resources, 'heavy_job', heavy), mock.patch.object(nmap_scan.subprocess, 'Popen', Proc):
			nmap_scan.run_nmap_xml([f'192.0.2.{i}' for i in range(64)], nmap_scan.FAST_FLAGS, nmap_scan.HOST_TIMEOUT_FAST)
			nmap_scan.run_nmap_xml(['192.0.2.1'], nmap_scan.FAST_FLAGS, nmap_scan.HOST_TIMEOUT_FAST)
		self.assertEqual(seen[1], 3 * 8 * 60 + 300)
		self.assertEqual(seen[3], 3 * 8 * 60 + 300)
		self.assertIn('--host-timeout', seen[0])

	def test_two_nmap_processes_may_run_at_once(self):
		self.assertEqual(resources.MAX_CONCURRENT['nmap'], 2)
		self.assertEqual(resources.max_concurrent('nmap'), 2)
