import json
import sys
import unittest
from unittest import mock

from reNgine.bbot import BbotProcessError, BbotResult, build_command, parse_event, parse_output, stream_events

SEED = {'type': 'DNS_NAME', 'id': 'DNS_NAME:aaa', 'data': 'Example.com', 'host': 'example.com', 'module': 'SEED',
        'resolved_hosts': ['1.2.3.4', '2600::1'], 'parent': 'SCAN:s'}
CHILD = {'type': 'DNS_NAME', 'id': 'DNS_NAME:bbb', 'data': 'www.example.com', 'host': 'www.example.com',
         'module': 'crt', 'resolved_hosts': ['1.2.3.5'], 'parent': 'DNS_NAME:aaa'}
PORT = {'type': 'OPEN_TCP_PORT', 'id': 'OPEN:1', 'data': 'www.example.com:443', 'host': 'www.example.com',
        'module': 'shodan_idb', 'parent': 'DNS_NAME:bbb'}
TECH = {'type': 'TECHNOLOGY', 'id': 'TECH:1', 'data': None, 'host': 'www.example.com', 'module': 'shodan_idb',
        'data_json': {'host': 'www.example.com', 'technology': 'nginx'}, 'parent': 'DNS_NAME:bbb'}
FINDING = {'type': 'FINDING', 'id': 'F:1', 'data': None, 'host': 'www.example.com', 'module': 'shodan_idb',
           'data_json': {'description': 'Possible CVE-2024-1 on nginx'}, 'parent': 'DNS_NAME:bbb'}
SHOT = {'type': 'WEBSCREENSHOT', 'id': 'WS:1', 'data': None, 'host': 'www.example.com', 'module': 'gowitness',
        'data_json': {'path': 'gowitness/screenshots/https---www.example.com-443-.jpeg', 'url': 'https://www.example.com/'},
        'parent': 'DNS_NAME:bbb'}


WAF = {'type': 'WAF', 'id': 'WAF:1', 'data': None, 'host': 'www.example.com', 'module': 'wafw00f',
       'data_json': {'host': 'www.example.com', 'url': 'https://www.example.com/', 'waf': 'FortiWeb (Fortinet)'}, 'parent': 'DNS_NAME:bbb'}


class BbotParseTests(unittest.TestCase):
	def test_a_named_waf_is_a_technology_of_the_host_without_its_vendor_suffix(self):
		result = BbotResult()
		seen = parse_event(WAF, result, {})
		self.assertEqual(result.technologies, {('www.example.com', 'FortiWeb')})
		self.assertEqual((seen.type, seen.label), ('WAF', 'WAF FortiWeb (Fortinet) on www.example.com'))

	def test_a_generic_waf_detection_names_no_product(self):
		result = BbotResult()
		parse_event({**WAF, 'data_json': {**WAF['data_json'], 'waf': 'generic detection', 'info': 'Blocked on a probe'}}, result, {})
		self.assertEqual(result.technologies, set())
		parse_event({**WAF, 'data_json': {'host': 'www.example.com', 'waf': ''}}, result, {})
		self.assertEqual(result.technologies, set())

	def test_parse_events_with_parent_ids_and_data_json(self):
		lines = ['not json', '{broken'] + [json.dumps(e) for e in (SEED, CHILD, PORT, TECH, FINDING)]
		r = parse_output(lines)
		self.assertEqual(r.subdomains, {'example.com', 'www.example.com'})
		self.assertEqual(r.ips, {'1.2.3.4', '1.2.3.5'})
		self.assertEqual(r.resolutions, {('example.com', '1.2.3.4'), ('www.example.com', '1.2.3.5')})
		self.assertEqual(r.ports, {('www.example.com', 443)})
		self.assertEqual(r.technologies, {('www.example.com', 'nginx')})
		self.assertEqual(r.edges, {('example.com', 'www.example.com')})  # child linked through the parent id

	def test_webscreenshot_events_are_captured(self):
		result, hosts = BbotResult(), {}
		parse_event(SHOT, result, hosts)
		self.assertEqual(result.screenshots, [{
			'host': 'www.example.com', 'rel_path': 'gowitness/screenshots/https---www.example.com-443-.jpeg',
			'url': 'https://www.example.com/'}])

	def test_webscreenshot_without_a_path_is_ignored(self):
		result = BbotResult()
		bad = {**SHOT, 'data_json': {'url': 'https://www.example.com/'}}
		parse_event(bad, result, {})
		self.assertEqual(result.screenshots, [])

	def test_observed_labels_for_the_live_feed(self):
		result, hosts = BbotResult(), {}
		seen = [parse_event(e, result, hosts) for e in (SEED, CHILD, PORT, TECH, FINDING)]
		self.assertEqual([(o.type, o.label) for o in seen], [
			('DNS_NAME', 'Example.com'), ('DNS_NAME', 'www.example.com'), ('OPEN_TCP_PORT', 'www.example.com:443'),
			('TECHNOLOGY', 'nginx on www.example.com'), ('FINDING', 'Possible CVE-2024-1 on nginx')])
		self.assertEqual(seen[1].parent_host, 'example.com')
		self.assertEqual(seen[1].module, 'crt')
		self.assertIsNone(parse_event({'type': 'SCAN', 'id': 'S', 'data': None}, result, hosts))  # not interesting

	def test_out_of_scope_neighbours_are_ignored(self):
		mx = {'type': 'DNS_NAME', 'id': 'D9', 'data': 'aspmx.l.google.com', 'host': 'aspmx.l.google.com', 'module': 'MX',
		      'scope_distance': 1, 'parent': 'DNS_NAME:aaa'}
		result = BbotResult()
		self.assertIsNone(parse_event(mx, result, {}))
		self.assertEqual(result.subdomains, set())

	def test_standard_is_the_default_with_the_web_preset_and_safe_modules(self):
		from reNgine.bbot import DEFAULT_MODE
		self.assertEqual(DEFAULT_MODE, 'standard')
		cmd = build_command(['example.com'])
		self.assertEqual(cmd[:3], ['bbot', '-t', 'example.com'])
		self.assertIn('--json', cmd)
		self.assertEqual([cmd[i + 1] for i, c in enumerate(cmd) if c == '-p'], ['subdomain-enum', 'web'])
		self.assertEqual(cmd[cmd.index('-rf') + 1], 'safe')
		self.assertIn('--force', cmd)
		self.assertNotIn('kitchen-sink', cmd)
		self.assertNotIn('passive', cmd)

	def test_deep_still_uses_the_kitchen_sink_preset(self):
		cmd = build_command(['example.com'], mode='deep')
		self.assertEqual(cmd[cmd.index('-p') + 1], 'kitchen-sink')
		self.assertIn('--force', cmd)  # real bbot 3.x flag; there is no "--allow-deadly" in this version
		self.assertNotIn('-rf', cmd)

	def test_each_mode_runs_under_its_own_memory_kind(self):
		import contextlib
		from reNgine import resources
		kinds = []

		@contextlib.contextmanager
		def fake_job(kind, label=''):
			kinds.append(kind)
			raise RuntimeError('stop before running bbot')
			yield
		with mock.patch.object(resources, 'heavy_job', fake_job):
			for mode in ('deep', 'standard', 'passive', 'whatever'):
				with self.assertRaises(RuntimeError):
					list(stream_events(['example.com'], mode=mode))
		self.assertEqual(kinds, ['bbot-deep', 'bbot-standard', 'bbot-passive', 'bbot-standard'])
		self.assertEqual((resources.BASE_COSTS_MB['bbot-standard'], resources.MAX_CONCURRENT['bbot-standard']), (1000, 2))

	def test_passive_mode(self):
		cmd = build_command(['example.com'])
		passive = build_command(['example.com'], mode='passive')
		self.assertEqual((passive[passive.index('-p') + 1], 'passive' in passive, '--force' in passive), ('subdomain-enum', True, False))
		self.assertNotIn('--silent', cmd)  # --silent hides the event stream


class StreamEventsProcessTests(unittest.TestCase):
	"""A real subprocess (not bbot itself) stands in, so these exercise the actual Popen/thread plumbing."""

	def test_a_crash_with_no_output_raises_instead_of_looking_like_a_clean_empty_scan(self):
		script = 'import sys; print("some bbot startup noise", file=sys.stderr); sys.exit(1)'
		with mock.patch('reNgine.bbot.build_command', return_value=[sys.executable, '-c', script]):
			with self.assertRaises(BbotProcessError) as cm:
				list(stream_events(['example.com']))
		self.assertIn('status 1', str(cm.exception))
		self.assertIn('startup noise', str(cm.exception))

	def test_events_still_stream_normally_on_a_clean_exit(self):
		script = 'print(\'{"type": "DNS_NAME", "data": "a.com", "host": "a.com"}\')'
		with mock.patch('reNgine.bbot.build_command', return_value=[sys.executable, '-c', script]):
			events = list(stream_events(['example.com']))
		self.assertEqual(events, [{'type': 'DNS_NAME', 'data': 'a.com', 'host': 'a.com'}])

	def test_a_crash_after_at_least_one_event_is_not_treated_as_a_total_failure(self):
		script = ('print(\'{"type": "DNS_NAME", "data": "a.com", "host": "a.com"}\'); '
		          'import sys; sys.exit(1)')
		with mock.patch('reNgine.bbot.build_command', return_value=[sys.executable, '-c', script]):
			events = list(stream_events(['example.com']))  # partial results are kept, not discarded as an error
		self.assertEqual(len(events), 1)


class BbotCliFlagsAreRealTests(unittest.TestCase):
	"""Every flag build_command emits must be a flag the installed bbot binary actually recognises.

	This is what would have caught --allow-deadly (a flag from a different tool/version that bbot 3.0.2
	rejects with "unrecognized arguments", which stream_events now correctly treats as a crash). A full
	--dry-run is too slow here (bbot resolves dependencies for every kitchen-sink module first), so this
	only checks argument *names* against --help, which is instant and still catches a typo'd or removed flag.
	"""

	@classmethod
	def setUpClass(cls):
		import shutil
		if shutil.which('bbot') is None:
			raise unittest.SkipTest('bbot is not installed in this environment')

	def test_every_mode_s_flags_are_accepted_by_bbot(self):
		import subprocess
		help_text = subprocess.run(['bbot', '--help'], capture_output=True, text=True, timeout=30).stdout
		for mode in ('deep', 'standard', 'passive'):
			cmd = build_command(['example.com'], mode=mode)
			for flag in cmd:
				if flag.startswith('--') and flag not in help_text:
					self.fail(f'{flag!r} (mode={mode}) is not a recognised bbot flag')


if __name__ == '__main__':
	unittest.main()
