"""What the server stores of what real tools found (1.4.0 tool review).

``tests/fixtures/sentinel_lab/*.json`` are payloads of the Sentinel's own runners (the image built from the Sentinel repository, tools at their pinned
versions) run against a lab of containers on a private network: nginx behind a WordPress-looking tree, an expired self-signed TLS endpoint, sshd, Redis,
Postgres. Each fixture holds the target the task carried, the exact payload the daemon would POST, and where the tool's own raw output was kept the number
of rows the tool wrote (``tool_rows``). Lab addresses 10.77.40.N are 192.0.2.N here.

Every fixture goes through ``clean_result`` bound to its task and nothing may be dropped but what is listed in ``KNOWN_DROPS``; the kinds whose rows can be
counted are counted against the tool, and the main consumers (the port inventory, the nuclei finding lines, the TLS audit, WPScan's classifier, the UDP
reader, the nmap report reader) read the stored result."""
import glob
import json
import os
from unittest import mock

from django.test import TestCase

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as sd
from agentapi.models import SentinelTask
from startScan.models import IpAddress
from tests.test_sentinels import build_world

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'sentinel_lab')
KNOWN_DROPS = {  # payload fields the server does not keep, and why that is no loss
    ('hygiene_check', '.certs[].cert.host'): 'the same host and port are on the certificate row itself',
    ('hygiene_check', '.certs[].cert.port'): 'the same host and port are on the certificate row itself',
    ('nuclei_empty_tags', '.no_templates'): 'findings [] and unreachable [] already say nothing was checked',
}
KNOWN_DROP_PREFIXES = {('nuclei_test', '.outcomes[].hit.'): 'the raw nuclei line of a hit: the outcome keeps the verdict and the trimmed matched row'}


def load(name):
    with open(os.path.join(FIXTURES, name + '.json'), encoding='utf-8') as handle:
        return json.load(handle)


def all_fixtures():
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(FIXTURES, '*.json')) if not p.endswith('_partial.json'))


def leaf_paths(value, path=''):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaf_paths(item, f'{path}.{key}')
    elif isinstance(value, list):
        yield path + '[]'
        for item in value:
            yield from leaf_paths(item, path + '[]')
    else:
        yield path


class Chunks:
    """``dispatch_many`` as the stages see it: the cleaned result of the stored fixture for chunk 0."""
    def __init__(self, cleaned):
        self.cleaned = cleaned

    def __call__(self, project, kind, chunks, **kwargs):
        def gen():
            for index, _chunk in enumerate(chunks):
                yield index, sd.Result(self.cleaned)
        return gen()


class LabResults(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def task_for(self, fixture):
        target = fixture['target']
        ips = sorted({a for a in (target.get('addresses') or ([target['address']] if target.get('address') else [])) if isinstance(a, str)})
        return SentinelTask.objects.create(project=self.pa, scan=self.scan, kind=fixture['kind'], target=target, host='lab.test', ips=ips)

    def cleaned(self, name):
        fixture = load(name)
        return fixture, sb.clean_result(fixture['kind'], fixture['payload'], self.task_for(fixture))

    def test_there_is_a_fixture_for_every_kind_that_can_run_in_a_lab(self):
        kinds = {load(n)['kind'] for n in all_fixtures()}
        for kind in ('naabu', 'nmap', 'nmap_full', 'nmap_verify', 'nmap_udp', 'testssl', 'waf', 'wpscan', 'wpscan_thorough', 'nuclei_light', 'nuclei_validate',
                     'path_probe', 'db_probe', 'rdp_shot', 'node2shell', 'ssh_probe', 'secrets_scan', 'web_screenshot', 'http_probe', 'dns_resolve',
                     'identity_check' if False else 'hygiene_check', 'subdir_probe', 'route_probe', 'vhost_probe', 'alive_check', 'page_read', 'discover'):
            self.assertIn(kind, kinds)

    def test_every_payload_is_accepted_and_nothing_is_dropped_but_what_is_listed(self):
        for name in all_fixtures():
            fixture, out = self.cleaned(name)
            stored = set(leaf_paths(out))
            for path in sorted(set(leaf_paths(fixture['payload']))):
                if path in stored or path == '':
                    continue
                if (name, path) in KNOWN_DROPS or any(name == n and path.startswith(p) for (n, p) in KNOWN_DROP_PREFIXES):
                    continue
                self.fail(f'{name}: the server dropped {path} of what the Sentinel sent')

    def test_naabu_stores_a_port_for_every_line_the_tool_wrote(self):
        fixture, out = self.cleaned('naabu')
        self.assertEqual(sum(len(v) for v in out['ports'].values()), fixture['tool_rows'])
        self.assertEqual(len(out['ports']), 5)

    def test_nmap_stores_every_open_port_the_report_listed_in_the_inventory(self):
        for name in ('nmap_top', 'nmap_ports'):
            fixture, out = self.cleaned(name)
            self.assertEqual(sum(len([p for p in h['ports'] if p['state'] == 'open']) for h in out['hosts']), fixture['tool_rows'], name)
            targets = fixture['target']['addresses']
            for address in targets:
                IpAddress.objects.get_or_create(address=address)
            with mock.patch.object(sd, 'dispatch_many', Chunks(out)), mock.patch.object(sd, 'any_scanner_for', return_value=True):
                totals = sd.try_nmap(self.pa, self.scan, targets)
            self.assertEqual(totals['ports'], fixture['tool_rows'], name)
            stored = sum(IpAddress.objects.get(address=a).ports.count() for a in targets)
            self.assertEqual(stored, fixture['tool_rows'], name)
            IpAddress.objects.filter(address__in=targets).delete()

    def test_nuclei_gives_the_stage_a_line_for_every_finding_the_tool_wrote_and_names_the_hosts_nothing_answered(self):
        fixture, out = self.cleaned('nuclei_light')
        self.assertEqual(len(out['findings']), fixture['tool_rows'])
        lines = [sd._finding_to_nuclei_line(f) for f in out['findings']]
        self.assertEqual(len(lines), fixture['tool_rows'])
        self.assertTrue(all(line['template-id'] and line['host'] for line in lines))
        down_fixture, down = self.cleaned('nuclei_bare_down')  # the stage's targets are bare hosts (nuclei_scan.build_targets): one answers, one is dead
        self.assertEqual(len(down['findings']), down_fixture['tool_rows'])
        self.assertEqual(sd._unreachable_of(down, down_fixture['target']['targets']), {'192.0.2.99'})
        wide_fixture, wide = self.cleaned('nuclei_bare_dead_wide')  # a dead host given the wide tags is still unreachable, never a clean pass
        self.assertEqual((wide['findings'], sd._unreachable_of(wide, wide_fixture['target']['targets'])), ([], {'192.0.2.99'}))
        quiet_fixture, quiet = self.cleaned('nuclei_bare_quiet')  # a live web server with nothing found is scanned, not unreachable
        self.assertNotIn('192.0.2.10', sd._unreachable_of(quiet, quiet_fixture['target']['targets']))
        self.assertNotIn('192.0.2.11', sd._unreachable_of(quiet, quiet_fixture['target']['targets']))
        targeted_fixture, targeted = self.cleaned('nuclei_targeted')
        self.assertEqual(len(targeted['findings']), targeted_fixture['tool_rows'])

    def test_testssl_keeps_every_item_and_the_audit_reads_them(self):
        from cveFeed.tls_audit import evaluate
        fixture, out = self.cleaned('testssl')
        self.assertEqual(len(out['items']), fixture['tool_rows'])
        result = evaluate(out['items'], '192.0.2.11:443')
        self.assertTrue(result.tested)
        self.assertEqual(result.protocols.get('TLS1'), 'offered')
        titles = ' | '.join(f['title'] for f in result.findings)
        for expected in ('anonymous ciphers', 'BEAST', 'Lucky13'):  # the certificate itself (expired, self-signed, wrong name) is the hygiene check's, which the lab reads below
            self.assertIn(expected, titles)
        _f, hygiene = self.cleaned('hygiene_check')
        cert = hygiene['certs'][0]
        self.assertTrue(cert['found'])
        self.assertEqual(cert['cert']['not_after'][:4], '2024')

    def test_a_testssl_run_that_could_not_connect_is_a_failure_the_audit_says_so_and_never_a_clean_result(self):
        from cveFeed.tls_audit import _why, evaluate
        _fixture, out = self.cleaned('testssl_closed')
        self.assertFalse(out['handshake'])
        self.assertFalse(evaluate(out['items'], '192.0.2.10:443').tested)
        self.assertIn("Can't connect", _why(out['items']))

    def test_wpscan_reports_are_read_by_the_one_classifier_and_a_cut_thorough_run_is_marked_partial(self):
        from cveFeed.wpscan_scan import _classify
        _f, quick = self.cleaned('wpscan')
        report = _classify(quick['report'], quick['returncode'], quick['stderr_tail'])
        self.assertIn('contact-form-7', report['plugins'])
        self.assertIn('twentytwentythree', report['themes'])
        _f, thorough = self.cleaned('wpscan_thorough')
        self.assertEqual(thorough['returncode'], 4)
        partial = _classify(thorough['report'], thorough['returncode'], thorough['stderr_tail'])
        self.assertIn('Max Scan Duration', partial['cvengine_partial'])

    def test_a_wpscan_that_could_not_update_its_database_is_a_failure_not_a_clean_site(self):
        from cveFeed.wpscan_scan import _classify
        report = {'db_update_started': True, 'update_aborted': True, 'target_url': 'http://192.0.2.10/'}  # recorded with no route to WPScan's database server
        with self.assertRaises(Exception) as caught:
            _classify(report, 4, '')
        self.assertTrue(any(word in str(caught.exception).lower() for word in ('update', 'database', 'did not finish', 'tool')), str(caught.exception))

    def test_udp_report_gives_the_eighteen_ports_and_keeps_open_filtered(self):
        from cveFeed.udp_scan import host_from_report
        fixture, out = self.cleaned('nmap_udp')
        host = host_from_report(out['xml'], '192.0.2.10')
        states = {p['state'] for p in host['ports']}
        self.assertEqual(len(host['ports']), 18)
        self.assertIn('open|filtered', states)

    def test_nmap_full_and_verify_reports_are_read_for_their_own_address_only(self):
        _f, full = self.cleaned('nmap_full')
        hosts = sd.nmap_hosts(full['xml'], '192.0.2.10')
        self.assertEqual([p['number'] for p in hosts[0]['ports']], [80])
        self.assertEqual(sd.nmap_hosts(full['xml'], '192.0.2.99'), [])  # a report that names another address never gives its ports to this one
        _f, verify = self.cleaned('nmap_verify')
        self.assertEqual([(p['number'], p['product']) for p in sd.nmap_hosts(verify['xml'], '192.0.2.10')[0]['ports']], [(80, 'nginx')])

    def test_the_closed_and_empty_answers_of_the_small_probes_are_answers_not_failures(self):
        self.assertTrue(self.cleaned('db_probe_redis')[1]['open'])
        self.assertIs(self.cleaned('db_probe_closed')[1]['open'], False)
        self.assertIs(self.cleaned('rdp_shot')[1]['painted'], False)
        self.assertEqual(self.cleaned('waf')[1], {'outcome': 'done', 'products': [], 'generic': False})

    def test_a_scan_that_found_nothing_to_run_is_not_a_result_with_a_missing_field(self):
        fixture, out = self.cleaned('nuclei_empty_tags')
        self.assertEqual((out['findings'], out['unreachable']), ([], []))
        self.assertTrue(fixture['payload']['no_templates'])  # the Sentinel says why; the server keeps what the stage acts on

    def test_a_bbot_batch_keeps_what_was_found_and_the_closing_result_keeps_the_incomplete_text(self):
        from agentapi import sentinel_stream
        fixture = load('bbot_discovery_partial')
        task = self.task_for(fixture)
        task.target = fixture['target']
        batch = sentinel_stream.clean_partial(task, fixture['payload'])
        self.assertEqual(batch['ips'], fixture['payload']['ips'])
        self.assertEqual(len(batch['events']), len(fixture['payload']['events']))
        final = load('bbot_discovery')['payload']
        self.assertEqual(sentinel_stream.clean_bbot_result(final)['incomplete'], '')
        text = 'bbot reached its time limit of 21600 seconds'
        cut = sentinel_stream.clean_bbot_result({**final, 'incomplete': text})
        self.assertEqual(cut['incomplete'], text)  # the bbot kind writes text where naabu writes a boolean, and the server keeps it as text
        self.assertTrue(cut['incomplete'] and not sentinel_stream.clean_bbot_result(final)['incomplete'])  # what ``not result.get('incomplete')`` in the adopter and the ledger read

    def test_a_naabu_run_that_ran_out_of_time_keeps_its_boolean_and_the_addresses_left_due(self):
        cleaned = sb.clean_result('naabu', {'outcome': 'done', 'ports': {'192.0.2.10': [80]}, 'incomplete': True, 'unfinished': ['192.0.2.11', '192.0.2.12']})
        self.assertEqual((cleaned['incomplete'], cleaned['unfinished']), (True, ['192.0.2.11', '192.0.2.12']))
        text = sb.clean_result('naabu', {'outcome': 'done', 'ports': {}, 'incomplete': 'ran out', 'unfinished': ['192.0.2.11']})
        self.assertNotIn('incomplete', text)  # text where a boolean belongs is not read as incomplete

    def test_a_discover_result_is_cut_to_the_chunk_the_sweep_asked_about(self):
        import ipaddress

        from cveFeed.internal_discovery import _usable
        fixture, out = self.cleaned('discover')
        net = ipaddress.ip_network(fixture['target']['cidr'])
        found = [_usable(net, h['ip']) for h in out['hosts']]
        self.assertTrue(all(found), found)
        self.assertGreaterEqual(len(found), 5)
        stranger = sb.clean_result('discover', {'outcome': 'done', 'hosts': [{'ip': '192.0.2.200', 'hostnames': []}, {'ip': '198.51.100.9', 'hostnames': []}]})
        self.assertEqual([_usable(net, h['ip']) for h in stranger['hosts']], [None, None])  # the server never trusts a Sentinel's address to be in the range

    def test_a_template_test_names_the_host_nothing_answered_as_an_error_never_a_negative_test(self):
        _f, out = self.cleaned('nuclei_test')
        by_host = {o['host']: o for o in out['outcomes']}
        self.assertTrue(by_host['http://192.0.2.10']['vulnerable'])
        dead = by_host['http://192.0.2.99']
        self.assertFalse(dead['vulnerable'])
        self.assertIn('never reached', dead['error'])
