import importlib.util
import os
import sys
from unittest import mock
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
			if host == 'proxy.golang.org':
				return {'Version': 'v99.0.0'}
			if host == 'pypi.org':
				return {'info': {'version': '9999.0'}}
			if host == 'api.github.com':
				return [{'name': 'v3.3dev'}, {'name': 'v99.1'}, {'name': 'v3.2.3'}]
			if host == 'go.dev':
				return [{'version': 'go99.1rc1', 'stable': False}, {'version': 'go99.0.1', 'stable': True}]
			return {'results': [{'name': 'stable'}, {'name': 'v99.2.0'}, {'name': 'v1.0.0'}]}
		rows = {r['tool']: r for r in tools.collect(get)}
		self.assertTrue(rows['nmap']['behind'])
		self.assertEqual(rows['nmap']['latest'], '99.1')
		self.assertTrue(rows['wpscan']['behind'])
		for tool in ('nuclei', 'nuclei (CI smoke test)', 'naabu', 'bbot', 'tzdata (bbot)', 'wafw00f', 'go (toolchain)'):
			self.assertTrue(rows[tool]['behind'], tool)
		self.assertEqual((rows['naabu']['latest'], rows['go (toolchain)']['latest']), ('99.0.0', '99.0.1'))
		self.assertEqual((rows['testssl.sh']['latest'], rows['testssl.sh']['behind']), ('99.1', True))  # a development tag is not a release
		self.assertIn('| nmap |', tools.report(list(rows.values())))

	def test_an_unreachable_site_is_unknown_not_a_crash(self):
		def get(url, as_json=True):
			raise OSError('offline')
		rows = tools.collect(get)
		self.assertTrue(all(r['latest'] is None and not r['behind'] for r in rows))
		self.assertTrue(all(r['pinned'] for r in rows))  # the pins are still read from the repository

	def test_versions_compare_numerically(self):
		self.assertTrue(tools.version_key('3.10.1') > tools.version_key('3.9.9'))

	def test_every_image_build_tool_is_pinned_to_a_version(self):
		rows = {r['tool']: r for r in tools.collect(lambda url, as_json=True: {})}
		for tool in ('nuclei', 'naabu', 'bbot', 'tzdata (bbot)', 'wafw00f', 'go (toolchain)', 'nmap', 'wpscan', 'testssl.sh'):
			self.assertRegex(rows[tool]['pinned'], r'^\d+(\.\d+)+$', tool)

	def test_a_tool_missing_from_the_checkout_is_skipped_but_a_required_one_is_not(self):
		with mock.patch.object(tools, 'pinned', return_value=None):
			rows = tools.collect(lambda url, as_json=True: {})
		names = {r['tool'] for r in rows}
		self.assertNotIn('tailscale (sidecar image)', names)
		self.assertIn('nmap', names)

	def exit_status(self, rows, *flags):
		with mock.patch.object(tools, 'collect', return_value=rows), mock.patch.object(sys, 'argv', ['c', *flags]), \
				mock.patch('builtins.print'), mock.patch.object(sys, 'exit') as leave:
			tools.main()
		return leave.call_args[0][0] if leave.called else 0

	def test_fail_if_behind_sets_the_exit_status(self):
		behind = [{'tool': 'x', 'pinned': '1', 'latest': '2', 'behind': True}]
		current = [{'tool': 'x', 'pinned': '2', 'latest': '2', 'behind': False}]
		self.assertEqual(self.exit_status(behind, '--fail-if-behind'), 1)
		self.assertEqual(self.exit_status(current, '--fail-if-behind'), 0)
		self.assertEqual(self.exit_status(behind), 0)  # the weekly report never fails the workflow

	def test_the_gate_fails_closed_on_a_missing_pin_or_an_unreadable_latest(self):
		missing_pin = [{'tool': 'x', 'pinned': None, 'latest': '2', 'behind': False}]
		unreachable = [{'tool': 'x', 'pinned': '2', 'latest': None, 'behind': False}]
		self.assertEqual(self.exit_status(missing_pin, '--fail-if-behind'), 1)
		self.assertEqual(self.exit_status(unreachable, '--fail-if-behind'), 1)
		self.assertEqual(self.exit_status(missing_pin + unreachable), 0)

	def test_a_renamed_pin_is_found_missing_by_collect(self):
		with mock.patch.object(tools, 'pinned', side_effect=lambda path, pattern: None if 'NMAPVERSION' in pattern else '1.0'):
			rows = {r['tool']: r for r in tools.collect(lambda url, as_json=True: {})}
		self.assertIsNone(rows['nmap']['pinned'])

	def test_nmap_has_a_checksum_for_the_amd64_rpm_and_for_the_source_tarball(self):
		dockerfile = open(os.path.join(os.path.dirname(PATH), '..', 'web', 'Dockerfile'), encoding='utf-8').read()
		for name in ('NMAP_SHA256', 'NMAP_RPM_SHA256_AMD64'):
			self.assertRegex(dockerfile, rf'(?m)^ARG {name}=[0-9a-f]{{64}}$')
