import contextlib
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from cveFeed import templategen
from reNgine.resources import MemoryKill


class _Job:
	def attach(self, proc):
		pass

	def raise_if_killed(self):
		pass


@contextlib.contextmanager
def _heavy_job(*a, **k):
	yield _Job()


class _FakeNuclei:
	"""Stands in for subprocess.Popen: reads the -l host file and reports every host containing 'vuln' as a hit."""
	runs = []
	kill_over = None  # raise MemoryKill (via the job) for runs bigger than this
	returncode = 0

	def __init__(self, cmd, **kwargs):
		self.hosts = open(cmd[cmd.index('-l') + 1]).read().split()
		type(self).runs.append(self.hosts)

	def communicate(self, timeout=None):
		lines = [json.dumps({'host': f'https://{h}:443', 'template-id': 't', 'matcher-name': 'vulnerable'}) for h in self.hosts if 'vuln' in h]
		return '\n'.join(lines), ''


class BatchedRunTests(unittest.TestCase):
	def setUp(self):
		_FakeNuclei.runs = []
		patches = [mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),  # no real DNS: a slow lookup now counts as blocked
			mock.patch('cveFeed.validation.approved_template', return_value=('id: fixture', '')),
			mock.patch('reNgine.resources.heavy_job', _heavy_job),
			mock.patch.object(templategen.subprocess, 'Popen', _FakeNuclei)]
		for p in patches:
			p.start()
			self.addCleanup(p.stop)

	def test_one_process_per_chunk_of_100_and_results_map_back_to_hosts(self):
		hosts = [f'h{i}.example.com' for i in range(250)] + ['vuln.example.com']
		out = templategen.run_template('/t.yaml', hosts)
		self.assertEqual(len(_FakeNuclei.runs), 1)
		self.assertEqual([o['host'] for o in out], hosts)
		self.assertEqual([o['host'] for o in out if o['vulnerable']], ['vuln.example.com'])

	def test_run_cve_tests_chunks_the_hosts(self):
		hosts = [f'h{i}.example.com' for i in range(205)]
		hosts[150] = 'vuln150.example.com'
		cve = SimpleNamespace(cve_id='CVE-2099-1', pk=1)
		with mock.patch('cveFeed.validation.resolve_template', return_value=('/t.yaml', '')), \
				mock.patch('cveFeed.activity.log'), mock.patch('cveFeed.activity.step') as step:
			step.return_value.__enter__.return_value = SimpleNamespace(done_message='')
			out = templategen.run_cve_tests(cve, hosts)
		self.assertEqual([len(r) for r in _FakeNuclei.runs], [100, 100, 5])
		self.assertEqual(len(out['results']), 205)
		self.assertEqual([r['host'] for r in out['results'] if r['vulnerable']], ['vuln150.example.com'])

	def test_memory_kill_halves_the_chunk(self):
		real = templategen.run_template
		sizes = []

		def flaky(path, hosts):
			sizes.append(len(hosts))
			if len(hosts) > 25:
				raise MemoryKill('low')
			return real(path, hosts)
		hosts = [f'h{i}.example.com' for i in range(100)]
		with mock.patch.object(templategen, 'run_template', flaky):
			out = templategen._run_template_with_retry('/t.yaml', hosts)
		self.assertEqual(sizes, [100, 50, 25, 25, 50, 25, 25])
		self.assertEqual([o['host'] for o in out], hosts)
		self.assertFalse(any(o.get('error') for o in out))

	def test_a_single_host_that_keeps_getting_killed_is_reported_not_tested(self):
		with mock.patch.object(templategen, 'run_template', side_effect=MemoryKill('low')):
			out = templategen._run_template_with_retry('/t.yaml', ['a.example.com'])
		self.assertIn('not tested', out[0]['error'])


class TemplateIndexTests(unittest.TestCase):
	def setUp(self):
		templategen.invalidate_template_index()
		self.addCleanup(templategen.invalidate_template_index)

	def test_one_walk_serves_many_lookups_and_a_save_invalidates_it(self):
		with tempfile.TemporaryDirectory() as d, mock.patch.object(templategen, 'GENERATED_DIR', d):
			open(os.path.join(d, 'CVE-2024-1.yaml'), 'w').close()
			with mock.patch.object(templategen.os, 'walk', wraps=os.walk) as walk:
				for n in range(20):
					templategen.find_existing_template('CVE-2024-1', roots=[d])
				self.assertEqual(walk.call_count, 1)
				self.assertEqual(templategen.find_existing_template('cve-2024-9', roots=[d]), [])
				templategen.save_template_file('cve-2024-9', 'id: x')
				self.assertEqual(len(templategen.find_existing_template('cve-2024-9', roots=[d])), 1)
				self.assertEqual(walk.call_count, 2)

	def test_a_template_update_marker_rebuilds_the_index(self):
		with tempfile.TemporaryDirectory() as d:
			open(os.path.join(d, 'CVE-2024-1.yaml'), 'w').close()
			self.assertEqual(len(templategen.find_existing_template('CVE-2024-1', roots=[d])), 1)
			os.makedirs(os.path.join(d, 'http'))
			open(os.path.join(d, 'http', 'cve-2024-2.yml'), 'w').close()
			marker = os.path.join(d, '.checksum')
			open(marker, 'w').close()
			os.utime(marker, (1, 4102444800))  # nuclei rewrites .checksum on every update
			self.assertEqual(len(templategen.find_existing_template('CVE-2024-2', roots=[d])), 1)
