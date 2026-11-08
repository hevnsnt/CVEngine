import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from cveFeed import templategen


class _FakeScanner:
	"""Stands in for the built-in scanner (``sentinel_dispatch.try_template_test``): records the hosts of every call and reports every host
	containing 'vuln' as a hit."""
	calls = []

	@classmethod
	def test(cls, text, hosts, project):
		cls.calls.append(list(hosts))
		return [{'host': h, 'vulnerable': 'vuln' in h, 'output': '', 'hit': None} for h in hosts]


class BatchedRunTests(unittest.TestCase):
	def setUp(self):
		_FakeScanner.calls = []
		patches = [mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),  # no real DNS: a slow lookup now counts as blocked
			mock.patch('cveFeed.validation.approved_template', return_value=('id: fixture', '')),
			mock.patch('agentapi.sentinel_dispatch.try_template_test', _FakeScanner.test)]
		for p in patches:
			p.start()
			self.addCleanup(p.stop)

	def test_one_scanner_call_per_run_and_results_map_back_to_hosts(self):
		hosts = [f'h{i}.example.com' for i in range(250)] + ['vuln.example.com']
		out = templategen.run_template('/t.yaml', hosts, project=1)
		self.assertEqual(len(_FakeScanner.calls), 1)
		self.assertEqual([o['host'] for o in out], hosts)
		self.assertEqual([o['host'] for o in out if o['vulnerable']], ['vuln.example.com'])

	def test_run_cve_tests_chunks_the_hosts(self):
		hosts = [f'h{i}.example.com' for i in range(205)]
		hosts[150] = 'vuln150.example.com'
		cve = SimpleNamespace(cve_id='CVE-2099-1', pk=1)
		with mock.patch('cveFeed.validation.resolve_template', return_value=('/t.yaml', '')), \
				mock.patch('cveFeed.activity.log'), mock.patch('cveFeed.activity.step') as step:
			step.return_value.__enter__.return_value = SimpleNamespace(done_message='')
			out = templategen.run_cve_tests(cve, hosts, project=1)
		self.assertEqual([len(c) for c in _FakeScanner.calls], [100, 100, 5])
		self.assertEqual(len(out['results']), 205)
		self.assertEqual([r['host'] for r in out['results'] if r['vulnerable']], ['vuln150.example.com'])

	def test_without_a_project_nothing_is_run_and_every_host_is_not_tested(self):
		out = templategen.run_template('/t.yaml', ['a.example.com'])
		self.assertEqual(_FakeScanner.calls, [])  # no scanner is asked and nothing runs here
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
