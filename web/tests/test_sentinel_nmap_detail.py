"""TL-1 on the server (Sentinel contract version 5): what a Sentinel's nmap pass reports reaches the host; a contract 4 result is stored as before."""
import json
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as sd
from cveFeed import cleartext, result_cuts
from startScan.models import IpAddress
from tests.test_sentinels import build_world

FIXTURES = Path(__file__).with_name('fixtures') / 'sentinel_results'
V5 = json.loads((FIXTURES / 'nmap.json').read_text())
V4 = json.loads((FIXTURES / 'v4' / 'nmap.json').read_text())
HOST = '192.0.2.11'


class Chunks:
    """``dispatch_many`` as try_nmap sees it: the cleaned result for chunk 0."""
    def __init__(self, cleaned):
        self.cleaned = cleaned

    def __call__(self, project, kind, chunks, **kwargs):
        def gen():
            for index, _chunk in enumerate(chunks):
                yield index, sd.Result(self.cleaned)
        return gen()


class NmapDetailReachesTheHost(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def run_pass(self, payload, addresses=(HOST, '192.0.2.12')):
        for address in addresses:
            IpAddress.objects.get_or_create(address=address)
        cleaned = sb.clean_result('nmap', payload)
        with mock.patch.object(sd, 'dispatch_many', Chunks(cleaned)), mock.patch.object(sd, 'any_scanner_for', return_value=True):
            try:
                return sd.try_nmap(self.pa, self.scan, list(addresses))
            except Exception as exc:  # the second host timed out: it stays due, which the caller is told
                self.assertEqual(type(exc).__name__, 'ScannerUnavailable')

    def port(self, number, address=HOST):
        return IpAddress.objects.get(address=address).ports.get(number=number)

    def test_the_tls_mark_and_the_certificate_of_a_v5_result_are_stored(self):
        self.run_pass(V5)
        https = self.port(443)
        self.assertEqual(https.extra['tunnel'], 'ssl')  # 443 is no longer stored as plain http
        self.assertEqual(https.service_name, 'http')
        self.assertIn('commonName=web.example.test', https.tls['subject'])
        self.assertEqual(https.tls['fingerprint_sha1'], 'fedcba9876543210fedcba9876543210fedcba98')
        self.assertIn('http-title', https.extra['scripts'])

    def test_ftp_with_tls_is_not_plain_ftp_and_the_one_without_is(self):
        self.run_pass(V5)
        with_tls, without = self.port(21), self.port(2121)
        self.assertTrue(with_tls.tls and cleartext.offers_tls(with_tls))
        self.assertEqual(with_tls.banner, '220 (vsFTPd 3.0.5)')
        found = cleartext.evaluate('host.example', [(HOST, with_tls), (HOST, without)])
        shown = json.dumps([getattr(f, '__dict__', str(f)) for f in found], default=str)
        self.assertIn('2121', shown)
        self.assertNotIn('21/tcp', shown.replace('2121/tcp', ''))

    def test_cpes_service_extra_and_the_os_detail_are_stored(self):
        self.run_pass(V5)
        ssh = self.port(22)
        self.assertEqual(ssh.cpe, 'cpe:/a:openbsd:openssh:9.6p1')
        self.assertEqual(ssh.extra['cpes'], ['cpe:/a:openbsd:openssh:9.6p1', 'cpe:/o:linux:linux_kernel'])
        self.assertEqual(ssh.service_extra, 'Ubuntu Linux; protocol 2.0')
        self.assertEqual(ssh.extra['method'], 'probed')
        ip = IpAddress.objects.get(address=HOST)
        self.assertEqual(ip.os_accuracy, 97)
        self.assertEqual([m['name'] for m in ip.fingerprint['os_matches']], ['Linux 5.15 - 6.1', 'Linux 4.15'])
        self.assertIn('smb-os-discovery', ip.fingerprint['scripts'])

    def test_the_closed_port_nmap_used_is_kept_so_the_path_check_has_a_candidate(self):
        self.run_pass(V5)
        fingerprint = IpAddress.objects.get(address=HOST).fingerprint
        self.assertEqual(fingerprint['closed_tcp'], 1)
        self.assertIn('closed_tcp_at', fingerprint)

    def test_a_port_that_was_scanned_and_is_not_open_now_is_closed_by_the_next_pass(self):
        self.run_pass(V5)
        self.assertEqual(self.port(80).state, 'open')
        second = json.loads(json.dumps(V5))
        second['hosts'][0]['ports'] = [p for p in second['hosts'][0]['ports'] if p['number'] != 80]  # 80 is inside scanned_ranges and no longer answers
        self.run_pass(second)
        self.assertEqual(self.port(80).state, 'closed')
        self.assertEqual(self.port(443).state, 'open')

    def test_a_port_outside_what_the_run_probed_is_left_alone(self):
        self.run_pass(V5)
        from startScan.models import Port
        extra = Port.objects.create(number=9999, protocol='tcp', state='open', service_name='custom')
        IpAddress.objects.get(address=HOST).ports.add(extra)
        self.run_pass(V5)
        extra.refresh_from_db()
        self.assertEqual(extra.state, 'open')

    def test_a_host_nmap_gave_up_on_is_stored_as_nothing(self):
        self.run_pass(V5)
        self.assertEqual(IpAddress.objects.get(address='192.0.2.12').ports.count(), 0)

    def test_a_contract_4_result_is_stored_as_before(self):
        self.run_pass(V4, addresses=('192.0.2.10',))
        ssh = self.port(22, '192.0.2.10')
        self.assertEqual((ssh.product, ssh.version, ssh.state), ('OpenSSH', '9.6', 'open'))
        self.assertNotIn('tunnel', ssh.extra or {})
        self.assertFalse(ssh.tls)
        fingerprint = IpAddress.objects.get(address='192.0.2.10').fingerprint or {}
        self.assertNotIn('closed_tcp', fingerprint)
        self.assertNotIn('result_cuts', fingerprint)
        # nothing was said about what was probed: a port stored earlier is not closed by it
        from startScan.models import Port
        other = Port.objects.create(number=80, protocol='tcp', state='open', service_name='http')
        IpAddress.objects.get(address='192.0.2.10').ports.add(other)
        self.run_pass(V4, addresses=('192.0.2.10',))
        other.refresh_from_db()
        self.assertEqual(other.state, 'open')

    def test_what_the_pass_cut_for_a_host_is_on_the_host_and_cleared_by_a_pass_that_cut_nothing(self):
        payload = json.loads(json.dumps(V5))
        payload['cuts'] = [{'what': 'banner', 'kind': 'chars', 'limit': 1024, 'dropped': 30, 'target': HOST}, {'what': 'host_timeout', 'kind': 'time', 'limit': 480, 'target': '192.0.2.12'}]
        self.run_pass(payload)
        notes = [result_cuts.words(c) for c in IpAddress.objects.get(address=HOST).fingerprint['result_cuts']['nmap']]
        self.assertEqual(notes, ['banner text on 192.0.2.11: 30 characters clipped (limit 1024)'])
        self.run_pass(V5)
        self.assertNotIn('result_cuts', IpAddress.objects.get(address=HOST).fingerprint)


class NmapCleaning(SimpleTestCase):
    def host(self, **fields):
        return {'hosts': [{'ip': HOST, 'ports': [{'number': 80, **fields}]}]}

    def stored(self, body):
        return sb.clean_result('nmap', {'outcome': 'done', **body})

    def test_the_v5_fixture_goes_through_whole(self):
        self.assertEqual(self.stored({k: v for k, v in V5.items() if k != 'outcome'}), V5)

    def test_hostile_text_is_bounded_and_cleaned_like_the_old_fields(self):
        evil = 'A' * 5000 + '\x00\x07'
        port = self.stored(self.host(banner='x\n' + evil, service_extra=evil, hostname=evil, ostype=evil, devicetype=evil,
                                     scripts={'banner': 'ok\x00' + evil, 'Bad Id': 'x', 'x' * 80: 'y'}, tunnel='tls', method='guess', confidence='99'))['hosts'][0]['ports'][0]
        self.assertEqual(len(port['banner']), 1024)
        self.assertNotIn('\x00', port['banner'])
        self.assertIn('\n', port['banner'])
        self.assertEqual((len(port['service_extra']), len(port['hostname']), len(port['ostype']), len(port['devicetype'])), (200, 255, 40, 64))
        self.assertEqual(list(port['scripts']), ['banner'])
        self.assertEqual(len(port['scripts']['banner']), 4000)
        for dropped in ('tunnel', 'method', 'confidence'):
            self.assertNotIn(dropped, port)

    def test_script_output_is_held_to_sixteen_thousand_characters_and_twenty_four_ids(self):
        scripts = {f's{i}': 'z' * 4000 for i in range(30)}
        kept = self.stored(self.host(scripts=scripts))['hosts'][0]['ports'][0]['scripts']
        self.assertEqual((len(kept), sum(len(v) for v in kept.values())), (4, 16000))
        many = self.stored(self.host(scripts={f's{i}': 'z' for i in range(40)}))['hosts'][0]['ports'][0]['scripts']
        self.assertEqual(len(many), 24)

    def test_cpes_are_bounded_and_must_be_cpes(self):
        port = self.stored(self.host(cpes=['cpe:/a:x:y:1'] * 12 + ['http://evil', 7], cpe='javascript:alert(1)'))['hosts'][0]['ports'][0]
        self.assertEqual(len(port['cpes']), 8)
        self.assertNotIn('cpe', port)

    def test_a_certificate_keeps_only_its_known_fields_and_real_digests(self):
        tls = self.stored(self.host(tls={'subject': 'cn=a', 'issuer': 'i' * 999, 'sans': ['a'] * 90, 'fingerprint_sha1': 'XYZ', 'fingerprint_md5': 'a' * 32,
                                          'evil': '<script>'}))['hosts'][0]['ports'][0]['tls']
        self.assertEqual((len(tls['issuer']), len(tls['sans']), tls['fingerprint_md5']), (300, 40, 'a' * 32))
        self.assertNotIn('fingerprint_sha1', tls)
        self.assertNotIn('evil', tls)
        self.assertNotIn('tls', self.stored(self.host(tls={'issuer': 'no subject'}))['hosts'][0]['ports'][0])

    def test_the_host_fields_are_bounded(self):
        body = {'hosts': [{'ip': HOST, 'ports': [], 'os_accuracy': 400, 'os_matches': [{'name': 'n' * 300, 'accuracy': 5}] * 6, 'closed_tcp': 70000,
                           'scanned_ranges': [[1, 5], [9, 3], [0, 4], ['a', 2], [1, 2, 3]] + [[7, 7]] * 5000, 'hostscripts': {'nbstat': 'x'}, 'status': 'sideways',
                           'extraports': ['closed'] * 12}]}
        row = self.stored(body)['hosts'][0]
        for dropped in ('os_accuracy', 'closed_tcp', 'status'):
            self.assertNotIn(dropped, row)
        self.assertEqual(len(row['os_matches']), 3)
        self.assertEqual(len(row['os_matches'][0]['name']), 100)
        self.assertEqual(len(row['scanned_ranges']), 4096 - 4)  # the first 4096 entries are looked at, four of them are not ranges
        self.assertEqual(row['scanned_ranges'][0], [1, 5])
        self.assertEqual(len(row['extraports']), 8)

    def test_scanned_ranges_never_expand_past_the_port_space(self):
        self.assertEqual(len(sd.scanned_ports([[1, 65535], [1, 65535]] * 3)), 65535)
        self.assertIsNone(sd.scanned_ports(None))

    def test_more_ports_than_the_cap_say_so_in_cuts(self):
        ports = [{'number': n} for n in range(1, 520)]
        out = self.stored({'hosts': [{'ip': HOST, 'ports': ports}]})
        self.assertEqual(len(out['hosts'][0]['ports']), sb.MAX_PORTS_PER_HOST)
        self.assertEqual(out['cuts'], [{'what': 'ports', 'kind': 'items', 'limit': 500, 'dropped': 19, 'target': HOST}])

    def test_a_result_with_no_cuts_has_none(self):
        self.assertNotIn('cuts', self.stored({'hosts': [{'ip': HOST, 'ports': [{'number': 22}]}]}))
