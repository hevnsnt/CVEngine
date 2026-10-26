import importlib.util
import os
from urllib.parse import urlparse

from django.test import SimpleTestCase

PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'check_tool_versions.py')
spec = importlib.util.spec_from_file_location('check_tool_versions', PATH)
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)


class ToolVersionCheckTests(SimpleTestCase):
	def test_it_reads_the_pins_and_flags_the_ones_that_are_behind(self):
		def get(url, as_json=True):
			host = urlparse(url).hostname
			if host == 'nmap.org':
				return '<a href="nmap-7.95.tar.bz2">x</a> <a href="nmap-99.1.tar.bz2">y</a> <a href="nmap-7.992.tar.bz2">z</a>'
			if host == 'rubygems.org':
				return {'version': '9.9.9'}
			return {'tag_name': 'v0.0.1'}
		rows = {r['tool']: r for r in tools.collect(get)}
		self.assertTrue(rows['nmap']['behind'])
		self.assertEqual(rows['nmap']['latest'], '99.1')
		self.assertTrue(rows['wpscan']['behind'])
		self.assertFalse(rows['nuclei (CI smoke test)']['behind'])
		self.assertIn('| nmap |', tools.report(list(rows.values())))

	def test_an_unreachable_site_is_unknown_not_a_crash(self):
		def get(url, as_json=True):
			raise OSError('offline')
		rows = tools.collect(get)
		self.assertTrue(all(r['latest'] is None and not r['behind'] for r in rows))
		self.assertTrue(all(r['pinned'] for r in rows))  # the pins are still read from the repository

	def test_versions_compare_numerically(self):
		self.assertTrue(tools.version_key('3.10.1') > tools.version_key('3.9.9'))
