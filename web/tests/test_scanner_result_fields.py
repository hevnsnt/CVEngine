"""The fields the review of the scanners needs from a Sentinel's result survive result cleaning, and a result without them reads exactly as before."""
from django.test import SimpleTestCase

from agentapi import probe_results, sentinel_broker as broker


class ResultFieldTests(SimpleTestCase):
    def test_an_nmap_host_that_timed_out_keeps_that_and_only_that_explicit_flag(self):
        out = broker._clean_nmap_result({'hosts': [{'ip': '192.0.2.10', 'timed_out': True, 'ports': []}, {'ip': '192.0.2.11', 'timed_out': 'yes', 'ports': []},
                                                    {'ip': '192.0.2.12', 'ports': []}]})
        flags = {h['ip']: h.get('timed_out') for h in out['hosts']}
        self.assertEqual(flags, {'192.0.2.10': True, '192.0.2.11': None, '192.0.2.12': None})

    def test_an_incomplete_naabu_result_names_the_addresses_it_did_not_finish(self):
        out = broker._clean_naabu_result({'ports': {'192.0.2.10': [22, 80]}, 'incomplete': True, 'unfinished': ['192.0.2.11', 'not an address', '192.0.2.12']})
        self.assertEqual((out['incomplete'], out['unfinished']), (True, ['192.0.2.11', '192.0.2.12']))
        self.assertEqual(broker._clean_naabu_result({'ports': {}}), {'ports': {}})

    def test_a_nuclei_result_keeps_the_unreachable_hosts_and_the_template_release(self):
        out = broker._clean_nuclei_result({'findings': [], 'unreachable': ['Down.Example.com', '', 5], 'templates_release': 'v10.5.1'})
        self.assertEqual((out['unreachable'], out['templates_release']), (['down.example.com'], 'v10.5.1'))
        self.assertEqual(broker._clean_nuclei_result({'findings': []}), {'findings': []})

    def test_a_testssl_result_keeps_the_return_code_and_the_handshake_flag(self):
        out = broker._clean_testssl_result({'items': [], 'returncode': 9, 'handshake': False})
        self.assertEqual((out['returncode'], out['handshake']), (9, False))
        self.assertEqual(broker._clean_testssl_result({'items': [], 'returncode': True, 'handshake': 'no'}), {'items': []})

    def test_a_hygiene_result_keeps_error_rows_and_the_names_whose_lookup_failed(self):
        out = probe_results.clean_hygiene_check({'certs': [], 'mail': [{'name': 'example.com', 'error': 'mx lookup failed'}], 'unknown_names': ['mail.example.com', 7]})
        self.assertEqual(out['mail'], [{'name': 'example.com', 'has_mx': False, 'findings': [], 'error': 'mx lookup failed'}])
        self.assertEqual(out['unknown_names'], ['mail.example.com'])
        self.assertNotIn('unknown_names', probe_results.clean_hygiene_check({'certs': [], 'mail': []}))
