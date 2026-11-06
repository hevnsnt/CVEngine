"""1.3.5 scanner false positives (audit items 11, 12, 13, 15, 16) and the nuclei evidence a finding keeps (item 5, storage half).

Every fixture is synthetic: the shape of the bad input the audit found, on example.test names and documentation addresses."""
import datetime
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi import sentinel_dispatch as dispatch
from cveFeed import cleartext, hygiene, nuclei_fp, nuclei_scan, tls_audit
from cveFeed.models import HygieneFinding
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

# what a PostgreSQL startup message and a RocketMQ broker request look like on the wire, shortened: the templates' matcher words are inside
PSQL_PAYLOAD = '\x00\x00\x00\x52\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00application_name\x00psql\x00\x00'
ROCKETMQ_PAYLOAD = '\x00\x00\x00\xc0\x00\x00\x00\xac{"code":105,"flag":0,"language":"JAVA","opaque":1,"serializeTypeCurrentRPC":"JSON","version":433}'
HAPROXY_503 = ('<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n')


def protocol_line(template_id, tags, request, response, matched='app.example.test:1000', severity='high', kind='tcp'):
    return {'template-id': template_id, 'template': f'network/{template_id}.yaml', 'type': kind, 'host': matched, 'matched-at': matched,
            'request': request, 'response': response,
            'info': {'name': template_id.replace('-', ' ').title(), 'severity': severity, 'tags': tags}}


def http_line(template_id, response, matched='http://lb.example.test/', severity='high', request='GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'):
    return {'template-id': template_id, 'template': f'http/{template_id}.yaml', 'type': 'http', 'host': matched, 'matched-at': matched,
            'request': request, 'response': response, 'info': {'name': template_id.replace('-', ' ').title(), 'severity': severity, 'tags': ['proxy']}}


def raw_http(status, reason, body, headers=''):
    return f'HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\n{headers}\r\n{body}'


class NucleiBase(TestCase):
    def setUp(self):
        org = Org.objects.create(name='S', slug='fp135')
        self.project = Project.objects.create(name='S', slug='fp135-p', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-fp135', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1,
                                               results_dir='/tmp')
        self.sub = Subdomain.objects.create(scan_history=self.scan, name='app.example.test')
        self.ip = IpAddress.objects.create(address='192.0.2.40')
        self.sub.ip_addresses.add(self.ip)
        Subdomain.objects.create(scan_history=self.scan, name='lb.example.test')

    def run_lines(self, lines, control=None):
        def stream(_path, **_kwargs):
            return iter(lines)
        with mock.patch.object(nuclei_fp, 'control_get', control or mock.Mock(return_value=None)) as got:
            out = nuclei_scan._run_nuclei(self.scan.id, stream=stream, targets=['app.example.test:1000', 'lb.example.test'], force=True)
        if control is None:
            self.assertFalse(got.called, 'no control request was expected')
        return out, got

    def templates(self):
        return sorted(Vulnerability.objects.values_list('template_id', flat=True))


class EchoServiceTests(NucleiBase):
    """Item 11: a port that echoes its input matched unauth-psql and apache-rocketmq-broker-unauth with their own payloads."""

    def test_a_response_that_is_the_request_payload_is_not_a_finding(self):
        out, _ = self.run_lines([protocol_line('unauth-psql', ['network', 'postgresql', 'unauth', 'js'], PSQL_PAYLOAD, PSQL_PAYLOAD)])
        self.assertEqual(self.templates(), [])
        self.assertEqual(out['set_aside'], {nuclei_fp.ECHO: 1})

    def test_a_response_that_contains_the_payload_is_an_echo_too(self):
        line = protocol_line('apache-rocketmq-broker-unauth', ['network', 'rocketmq', 'apache', 'unauth'], ROCKETMQ_PAYLOAD,
                             ROCKETMQ_PAYLOAD + ROCKETMQ_PAYLOAD)
        self.run_lines([line])
        self.assertEqual(self.templates(), [])

    def test_two_unrelated_protocol_templates_on_one_port_are_both_dropped(self):
        # the answers are not the payloads (a listener that answers anything with a fixed blob): the port still cannot be both
        lines = [protocol_line('unauth-psql', ['network', 'postgresql', 'unauth'], PSQL_PAYLOAD, 'user database application_name'),
                 protocol_line('apache-rocketmq-broker-unauth', ['network', 'rocketmq', 'apache', 'unauth'], ROCKETMQ_PAYLOAD,
                               '{"code":0,"serializeTypeCurrentRPC":"JSON"} user database')]
        out, _ = self.run_lines(lines)
        self.assertEqual(self.templates(), [])
        self.assertEqual(out['set_aside'], {nuclei_fp.MANY_PROTOCOLS: 2})

    def test_two_templates_for_the_same_product_on_one_port_stand(self):
        lines = [protocol_line('unauth-psql', ['network', 'postgresql', 'unauth'], PSQL_PAYLOAD, 'R\x00\x00\x00\x08\x00\x00\x00\x00S'),
                 protocol_line('pgsql-detect', ['network', 'postgresql', 'detect'], 'probe', 'SFATAL unsupported frontend protocol',
                               severity='info')]
        out, _ = self.run_lines(lines)
        self.assertEqual(self.templates(), ['pgsql-detect', 'unauth-psql'])
        self.assertNotIn('set_aside', out)

    def test_a_port_nmap_named_echo_matches_nothing(self):
        self.ip.ports.add(Port.objects.create(number=1000, service_name='echo', state='open', protocol='tcp', extra={'method': 'probed'}))
        line = protocol_line('unauth-psql', ['network', 'postgresql', 'unauth'], PSQL_PAYLOAD, 'R\x00\x00\x00\x08 a real answer')
        out, _ = self.run_lines([line, protocol_line('unauth-psql', ['network', 'postgresql'], PSQL_PAYLOAD, 'R', matched='192.0.2.40:1000')])
        self.assertEqual(self.templates(), [])
        self.assertEqual(out['set_aside'], {nuclei_fp.ECHO_SERVICE: 2})

    def test_a_real_protocol_match_is_kept_with_its_request_and_response(self):
        self.run_lines([protocol_line('unauth-psql', ['network', 'postgresql', 'unauth'], PSQL_PAYLOAD, 'R\x00\x00\x00\x08\x00\x00\x00\x00S')])
        vuln = Vulnerability.objects.get(template_id='unauth-psql')
        self.assertIn('postgres', vuln.request)
        self.assertNotIn('\x00', vuln.request)
        self.assertTrue(vuln.response.startswith('R'))


class SameBodyTests(NucleiBase):
    """Item 12: an open-proxy template fired on a load balancer with no backend; every request returns the same 503 page."""

    def test_an_error_page_the_host_returns_for_any_path_is_not_a_finding(self):
        control = mock.Mock(return_value=(503, '', HAPROXY_503))
        out, got = self.run_lines([http_line('open-proxy-localhost', raw_http(503, 'Service Unavailable', HAPROXY_503))], control=control)
        self.assertEqual(self.templates(), [])
        self.assertEqual(out['set_aside'], {nuclei_fp.SAME_BODY: 1})
        url = got.call_args[0][0]
        self.assertTrue(url.startswith('http://lb.example.test/.cvengine-control-'))

    def test_a_different_control_answer_keeps_the_finding(self):
        control = mock.Mock(return_value=(404, '', '<h1>Not Found</h1>'))
        self.run_lines([http_line('open-proxy-localhost', raw_http(503, 'Service Unavailable', HAPROXY_503))], control=control)
        self.assertEqual(self.templates(), ['open-proxy-localhost'])

    def test_every_recorded_response_with_the_same_body_needs_no_control(self):
        both = raw_http(503, 'Service Unavailable', HAPROXY_503) + raw_http(503, 'Service Unavailable', HAPROXY_503)
        self.run_lines([http_line('open-proxy-localhost', both)])
        self.assertEqual(self.templates(), [])

    def test_a_success_page_an_info_match_and_a_failed_control_are_left_alone(self):
        control = mock.Mock(side_effect=OSError('refused'))
        self.run_lines([http_line('exposed-config', raw_http(200, 'OK', 'secret=1'), matched='http://lb.example.test/.env'),
                        http_line('waf-detect', raw_http(403, 'Forbidden', 'denied'), severity='info'),
                        http_line('open-proxy-localhost', raw_http(503, 'Service Unavailable', HAPROXY_503))], control=control)
        self.assertEqual(self.templates(), ['exposed-config', 'open-proxy-localhost', 'waf-detect'])
        self.assertEqual(control.call_count, 1)  # only the error page of the medium-and-up match was checked

    def test_a_match_without_a_recorded_response_is_not_re_requested(self):
        self.run_lines([http_line('open-proxy-localhost', None)])
        self.assertEqual(self.templates(), ['open-proxy-localhost'])

    def test_a_redirect_to_a_different_place_is_not_the_same_answer(self):
        self.assertFalse(nuclei_fp.same_bodies([(302, 'https://evil.example.net/', 'moved'), (302, 'https://lb.example.test/', 'moved')]))


class EvidenceTests(NucleiBase):
    """Item 5 (storage): the matched request and response are kept, bounded, from a local run and from a Sentinel's result."""

    def test_a_local_line_keeps_a_bounded_request_and_response(self):
        body = 'x' * (nuclei_fp.MAX_EVIDENCE * 3)
        self.run_lines([http_line('exposed-config', raw_http(200, 'OK', body), matched='http://lb.example.test/.env', request='GET /.env HTTP/1.1')])
        vuln = Vulnerability.objects.get(template_id='exposed-config')
        self.assertEqual(vuln.request, 'GET /.env HTTP/1.1')
        self.assertEqual(len(vuln.response), nuclei_fp.MAX_EVIDENCE)
        self.assertTrue(vuln.response.startswith('HTTP/1.1 200 OK\r\n'))

    def test_a_sentinel_result_carries_optional_evidence_and_one_without_it_is_accepted(self):
        sent = [{'template_id': 'exposed-config', 'name': 'Exposed config', 'severity': 'high', 'host': 'lb.example.test',
                 'matched_at': 'http://lb.example.test/.env', 'type': 'http', 'request': 'GET /.env HTTP/1.1\r\n\r\n',
                 'response': 'HTTP/1.1 200 OK\r\n\r\nsecret=1' + 'y' * 10000},
                {'template_id': 'old-client', 'name': 'Old client', 'severity': 'low', 'host': 'lb.example.test',
                 'matched_at': 'http://lb.example.test/x'}]
        cleaned, dropped = sentinel_broker._clean_findings(sent)
        self.assertEqual(dropped, 0)
        self.assertEqual(cleaned[0]['type'], 'http')
        self.assertEqual(cleaned[0]['request'], 'GET /.env HTTP/1.1\r\n\r\n')  # newlines kept: the evidence is a transcript
        self.assertEqual(len(cleaned[0]['response']), sentinel_broker.MAX_EVIDENCE)
        self.assertNotIn('request', cleaned[1])
        self.assertNotIn('type', cleaned[1])
        lines = [dispatch._finding_to_nuclei_line(f) for f in cleaned]
        self.assertEqual(lines[1]['type'], 'http')
        self.assertIsNone(lines[1]['request'])
        self.run_lines(lines)
        self.assertTrue(Vulnerability.objects.get(template_id='exposed-config').response.endswith('y'))
        self.assertIsNone(Vulnerability.objects.get(template_id='old-client').request)

    def test_a_sentinel_echo_is_recognised_from_its_optional_fields(self):
        cleaned, _ = sentinel_broker._clean_findings([{
            'template_id': 'unauth-psql', 'name': 'Unauth PSQL', 'severity': 'high', 'host': 'app.example.test:1000',
            'matched_at': 'app.example.test:1000', 'tags': ['network', 'postgresql'], 'request': 'user postgres database postgres',
            'response': 'user postgres database postgres'}])
        out, _ = self.run_lines([dispatch._finding_to_nuclei_line(f) for f in cleaned])
        self.assertEqual(self.templates(), [])
        self.assertEqual(out['set_aside'], {nuclei_fp.ECHO: 1})

    def test_bad_optional_fields_are_dropped_not_refused(self):
        cleaned, _ = sentinel_broker._clean_findings([{'template_id': 't', 'severity': 'low', 'type': 'gopher', 'request': 7, 'response': ['x']}])
        self.assertNotIn('type', cleaned[0])
        self.assertNotIn('request', cleaned[0])
        self.assertNotIn('response', cleaned[0])


class CleartextBannerTests(TestCase):
    """Item 13: FTP and rlogin named from the port number on a front end that accepts and closes every port."""

    def setUp(self):
        org = Org.objects.create(name='C', slug='ct135')
        project = Project.objects.create(name='C', slug='ct135-p', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.test', project=project, insert_date=timezone.now())

    def host(self, name, address, ports):
        sub = Subdomain.objects.create(name=name, target_domain=self.domain)
        ip = IpAddress.objects.get_or_create(address=address)[0]
        sub.ip_addresses.add(ip)
        for number, service, fields in ports:
            ip.ports.add(Port.objects.create(number=number, service_name=service, state='open', protocol='tcp', **fields))
        return ip

    def checks(self):
        return {(f.host, f.check) for f in cleartext.findings_for(self.domain)}

    def test_ports_named_from_the_port_table_with_no_banner_are_not_findings(self):
        self.host('front.example.test', '198.51.100.20', [(21, 'ftp', {'extra': {'method': 'table'}}),
                                                          (513, 'login', {'extra': {'method': 'table'}})])
        self.assertEqual(self.checks(), set())

    def test_a_fingerprint_without_a_banner_on_an_address_that_accepts_everything_is_not_a_finding(self):
        silent = [(n, '', {'extra': {'method': 'table'}}) for n in range(40000, 40000 + cleartext.ACCEPT_ALL_PORTS)]
        self.host('front.example.test', '198.51.100.21', [(21, 'ftp', {'extra': {'method': 'probed'}}), *silent])
        self.assertEqual(self.checks(), set())

    def test_a_greeting_is_still_a_finding_even_on_such_an_address(self):
        silent = [(n, '', {'extra': {'method': 'table'}}) for n in range(40000, 40000 + cleartext.ACCEPT_ALL_PORTS)]
        self.host('ftp.example.test', '198.51.100.22', [(21, 'ftp', {'extra': {'method': 'probed'}, 'banner': '220 ProFTPD Server ready.'}), *silent])
        found = cleartext.findings_for(self.domain)
        self.assertEqual({(f.host, f.check) for f in found}, {('ftp.example.test', cleartext.FTP)})
        self.assertEqual(found[0].evidence['identified'], 'banner')
        self.assertEqual(found[0].evidence['banner'], '220 ProFTPD Server ready.')

    def test_a_fingerprinted_service_on_a_normal_host_is_a_finding(self):
        self.host('router.example.test', '198.51.100.23', [(23, 'telnet', {'extra': {'method': 'probed'}}), (22, 'ssh', {'extra': {'method': 'probed'}})])
        self.assertEqual(self.checks(), {('router.example.test', cleartext.TELNET)})


ALL_NOT_OFFERED = [{'id': p, 'severity': 'INFO', 'finding': 'not offered'} for p in ('SSLv2', 'SSLv3', 'TLS1', 'TLS1_1', 'TLS1_2', 'TLS1_3')]


class TestsslArtefactTests(SimpleTestCase):
    """Item 15: "no forward secrecy" on a listener that completes no handshake, and a fallback test whose downgrade never completed."""

    def test_a_listener_that_negotiates_nothing_gets_one_low_finding_instead_of_no_forward_secrecy(self):
        items = ALL_NOT_OFFERED + [{'id': 'FS', 'severity': 'MEDIUM', 'finding': 'No ciphers supporting Forward Secrecy offered'},
                                   {'id': 'cipherlist_3DES_IDEA', 'severity': 'WARN', 'finding': 'test failed'},
                                   {'id': 'heartbleed', 'severity': 'OK', 'finding': 'not vulnerable, no heartbeat extension'}]
        result = tls_audit.evaluate(items, 'help.example.test:443')
        self.assertEqual([f['check'] for f in result.findings], [tls_audit.NO_HANDSHAKE])
        finding = result.findings[0]
        self.assertEqual(finding['severity'], tls_audit.SEVERITY['LOW'])
        self.assertEqual(finding['title'], 'help.example.test:443: TLS listener does not negotiate')
        self.assertNotIn('tlsa_cipherlist_3des_idea', result.inconclusive)  # the old cipher findings of the port resolve
        self.assertIn('heartbleed', result.cleared)

    def test_a_listener_that_negotiates_keeps_its_forward_secrecy_finding(self):
        items = [{'id': 'TLS1_2', 'severity': 'OK', 'finding': 'offered'},
                 {'id': 'TLS1_3', 'severity': 'INFO', 'finding': 'not offered'},
                 {'id': 'FS', 'severity': 'MEDIUM', 'finding': 'No ciphers supporting Forward Secrecy offered'}]
        self.assertEqual([f['check'] for f in tls_audit.evaluate(items, 'a.example.test:443').findings], ['tlsa_fs'])

    def test_a_downgraded_handshake_that_never_completes_is_not_a_finding(self):
        items = [{'id': 'TLS1_1', 'severity': 'INFO', 'finding': 'offered (deprecated)'},
                 {'id': 'fallback_SCSV', 'severity': 'MEDIUM',
                  'finding': "some unexpected 'handshake failure' instead of 'inappropriate fallback' (likely: warning)"}]
        result = tls_audit.evaluate(items, 'support.example.test:443')
        self.assertEqual(result.findings, [])
        self.assertNotIn('tlsa_fallback_scsv', result.inconclusive)

    def test_a_real_missing_downgrade_protection_is_still_a_finding(self):
        items = [{'id': 'TLS1_1', 'severity': 'INFO', 'finding': 'offered (deprecated)'},
                 {'id': 'fallback_SCSV', 'severity': 'HIGH', 'finding': 'Downgrade attack prevention NOT supported'}]
        self.assertEqual([f['check'] for f in tls_audit.evaluate(items, 'old.example.test:443').findings], ['tlsa_fallback_scsv'])


class TestsslStoreTests(TestCase):
    def test_the_artefact_finding_resolves_and_the_listener_finding_takes_its_place(self):
        org = Org.objects.create(name='T', slug='ts135')
        project = Project.objects.create(name='T', slug='ts135-p', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='example.test', project=project, insert_date=timezone.now())
        where = 'help.example.test:443'
        HygieneFinding.objects.create(domain=domain, host=where, check_name='tlsa_fs', severity=2, title=f'{where} does not offer forward secrecy',
                                      status='open')
        items = ALL_NOT_OFFERED + [{'id': 'FS', 'severity': 'MEDIUM', 'finding': 'No ciphers supporting Forward Secrecy offered'}]
        tls_audit.store(domain, 'help.example.test', 443, tls_audit.evaluate(items, where), where)
        rows = dict(HygieneFinding.objects.filter(domain=domain).values_list('check_name', 'status'))
        self.assertEqual(rows, {'tlsa_fs': 'resolved', tls_audit.NO_HANDSHAKE: 'open'})


class LegacyEvidenceTests(SimpleTestCase):
    """Item 16: the legacy-protocol finding stored "protocol: TLSv1.3" (the modern handshake); it now names the TLS 1.0 / 1.1 handshake."""

    def test_the_finding_stores_the_legacy_handshake_not_the_modern_one(self):
        addresses = ((2, ('203.0.113.10', 443)),)
        modern = {'host': 'legacy.example.test', 'port': 443, 'protocol': 'TLSv1.3', 'cipher': 'TLS_AES_128_GCM_SHA256',
                  'not_after': datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc), 'sans': ['legacy.example.test'],
                  'subject': 'legacy.example.test', 'signature_algorithm': 'sha256', 'key_description': 'RSA 2048'}
        with mock.patch.object(hygiene.pinned_transport, 'resolve', return_value=addresses), \
                mock.patch.object(hygiene, '_fetch_cert', return_value=dict(modern)), \
                mock.patch.object(hygiene, '_chain_error', return_value=''), \
                mock.patch.object(hygiene.legacy_tls, 'handshake', return_value=(b'der', 'TLSv1', 'ECDHE-RSA-AES128-SHA')):
            info = hygiene.probe_tls('legacy.example.test', 443)
        self.assertTrue(info['legacy_tls'])
        found = [f for f in hygiene.evaluate_cert(hygiene.clip_certificate(info)) if f.check == 'tls_legacy_protocol']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].evidence, {'protocol': 'TLSv1', 'cipher': 'ECDHE-RSA-AES128-SHA',
                                             'handshake': 'TLSv1 handshake completed with ECDHE-RSA-AES128-SHA', 'modern_protocol': 'TLSv1.3'})

    def test_a_server_that_only_speaks_the_old_protocols_says_so(self):
        info = {'host': 'old.example.test', 'port': 443, 'protocol': 'TLSv1.1', 'cipher': 'AES256-SHA', 'legacy_tls': True,
                'legacy_handshake': {'protocol': 'TLSv1.1', 'cipher': 'AES256-SHA'}}
        found = [f for f in hygiene.evaluate_cert(info) if f.check == 'tls_legacy_protocol']
        self.assertEqual(found[0].evidence['protocol'], 'TLSv1.1')
        self.assertNotIn('modern_protocol', found[0].evidence)

    def test_a_refused_legacy_handshake_is_no_finding(self):
        with mock.patch.object(hygiene.legacy_tls, 'handshake', return_value=(b'der', 'TLSv1.2', 'X')):
            self.assertIsNone(hygiene.legacy_tls.negotiated('a.example.test', 443, 5))
            self.assertFalse(hygiene.legacy_tls.accepts('a.example.test', 443, 5))
