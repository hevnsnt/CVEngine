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
			if host == 'proxy.golang.org':
				return {'Version': 'v99.0.0'}
			if host == 'pypi.org':
				return {'info': {'version': '9999.0'}}
			if host == 'go.dev':
				return [{'version': 'go99.1rc1', 'stable': False}, {'version': 'go99.0.1', 'stable': True}]
			return {'results': [{'name': 'stable'}, {'name': 'v99.2.0'}, {'name': 'v1.0.0'}]}
		rows = {r['tool']: r for r in tools.collect(get)}
		self.assertTrue(rows['tailscale (sidecar image)']['behind'])
		self.assertIn('| tailscale (sidecar image) |', tools.report(list(rows.values())))
		for gone in ('nuclei', 'go (toolchain)', 'nmap', 'wpscan', 'naabu', 'bbot', 'tzdata (bbot)', 'wafw00f', 'testssl.sh'):  # every scan tool runs on the Sentinels
			self.assertNotIn(gone, rows)

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
		self.assertRegex(rows['tailscale (sidecar image)']['pinned'], r'^\d+(\.\d+)+$')
		self.assertNotIn('nuclei', rows)  # the server image builds no scan tool

	def test_a_tool_missing_from_the_checkout_is_skipped_but_a_required_one_is_not(self):
		with mock.patch.object(tools, 'pinned', return_value=None):
			rows = tools.collect(lambda url, as_json=True: {})
		names = {r['tool'] for r in rows}
		self.assertNotIn('tailscale (sidecar image)', names)
		self.assertEqual(names, set())  # the server image pins no required tool any more

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



	def test_the_github_token_goes_to_the_github_api_only(self):
		"""Unauthenticated, api.github.com is limited to 60 requests an hour per address, which shared CI runners use up: the lookup then reads as unknown and the
		gate, which fails closed, turns red for no reason. The token must reach GitHub's API and no other host."""
		seen = {}

		def urlopen(request, timeout=None):
			seen[request.full_url] = request.get_header('Authorization')
			raise OSError('stop here')

		with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'token-value'}), mock.patch.object(tools.urllib.request, 'urlopen', urlopen):
			for url in ('https://api.github.com/repos/hevnsnt/CVEngine/tags', 'https://pypi.org/pypi/python-gvm/json', 'https://go.dev/dl/?mode=json'):
				with self.assertRaises(OSError):
					tools.fetch(url)
		self.assertEqual(seen['https://api.github.com/repos/hevnsnt/CVEngine/tags'], 'Bearer token-value')
		self.assertIsNone(seen['https://pypi.org/pypi/python-gvm/json'])
		self.assertIsNone(seen['https://go.dev/dl/?mode=json'])
		with mock.patch.dict(os.environ, {'GITHUB_TOKEN': ''}), mock.patch.object(tools.urllib.request, 'urlopen', urlopen):
			with self.assertRaises(OSError):
				tools.fetch('https://api.github.com/repos/hevnsnt/CVEngine/tags')
		self.assertIsNone(seen['https://api.github.com/repos/hevnsnt/CVEngine/tags'])
