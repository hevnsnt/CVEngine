"""The kinds of contract version 3 (docs/SCANNER-ARCHITECTURE.md, section B): what the server keeps of each result, which Sentinel may take the
built-in-only kinds, and each stage served end to end by the fake built-in scanner with ``CVENGINE_LOCAL_FALLBACK=none`` (nothing may run here),
then again with the scanner offline, where the stage waits and leaves its targets due."""
import base64
import json
import shutil
import struct
import tempfile
import zlib
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import scanner_state, sentinel_broker
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import Agent
from agentapi.services import ApiError
from agentapi.auth import create_token
from cveFeed import db_exposure, fullscan, node2shell_scan, path_probe, probes, rdp_shot, templategen, waf_fingerprint
from cveFeed.models import RdpScreenshot, ServiceRun
from reNgine import resources
from startScan.models import IpAddress, Port, Subdomain, Technology, Vulnerability
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_fake_scanner import NoRealSleep
from tests.test_fullscan import FullScanBase
from tests.test_route_auth import RouteFixture
from tests.test_service_intel import RDP_ENC

IP = '203.0.113.5'  # RouteFixture's address


def png(width, height, rows=None):
    rows = rows or [[(x + y) % 2 * 255 for x in range(width)] for y in range(height)]
    raw = b''.join(b'\x00' + bytes(r) for r in rows)

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 0, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')


class _Task:
    def __init__(self, target):
        self.target = target


# ============================================================================== what the server keeps of a result

class CleanResultTests(SimpleTestCase):
    def clean(self, kind, body, task=None):
        return sentinel_broker.clean_result(kind, {'outcome': 'done', **body}, task)

    def test_an_rdp_capture_is_checked_before_anything_opens_it(self):
        good = base64.b64encode(png(2, 2)).decode()
        self.assertEqual(self.clean('rdp_shot', {'painted': True, 'image': good})['image'], good)
        self.assertEqual(self.clean('rdp_shot', {'painted': False, 'image': good}), {'outcome': 'done', 'painted': False})  # nothing painted: no image
        bomb = png(1, 1)[:16] + struct.pack('>II', 100_000, 100_000) + png(1, 1)[24:]  # an IHDR that claims ten billion pixels
        for bad in ({'painted': True, 'image': base64.b64encode(bomb).decode()},
                    {'painted': True, 'image': base64.b64encode(b'GIF89a' + b'x' * 40).decode()},
                    {'painted': True, 'image': 'not base64!'},
                    {'painted': True, 'image': 'A' * (sentinel_broker.MAX_RDP_IMAGE_BYTES * 2)},
                    {'painted': 'yes'}):
            with self.subTest(bad=str(bad)[:60]), self.assertRaises(ApiError):
                self.clean('rdp_shot', bad)

    def test_a_db_probe_answer_is_a_boolean_or_none_and_evidence_only_when_open(self):
        self.assertEqual(self.clean('db_probe', {'open': False, 'evidence': 'x'}), {'outcome': 'done', 'open': False, 'evidence': ''})
        self.assertEqual(self.clean('db_probe', {'open': None}), {'outcome': 'done', 'open': None, 'evidence': ''})
        self.assertEqual(len(self.clean('db_probe', {'open': True, 'evidence': 'v' * 900})['evidence']), 300)
        for bad in ({'open': 'true'}, {}):
            with self.subTest(bad=bad), self.assertRaises(ApiError):
                self.clean('db_probe', bad)

    def test_a_node2shell_verdict_that_is_not_a_boolean_is_refused(self):
        self.assertIsNone(self.clean('node2shell', {'vulnerable': None, 'verdict': 'INCONCLUSIVE', 'status_code': 'x'})['status_code'])
        with self.assertRaises(ApiError):
            self.clean('node2shell', {'vulnerable': 'yes'})

    def test_the_path_survey_keeps_only_well_formed_rows_for_the_addresses_the_task_named(self):
        task = _Task({'targets': [{'ip': '192.0.2.10', 'port': 81}]})
        out = self.clean('path_probe', {'results': [{'ip': '192.0.2.10', 'port': 81, 'plain': False, 'odd': True},
                                                    {'ip': '198.51.100.9', 'port': 9, 'plain': True, 'odd': True},
                                                    {'ip': 'not an ip', 'port': 9, 'plain': True}]}, task)
        self.assertEqual(out['results'], [{'ip': '192.0.2.10', 'port': 81, 'plain': False, 'odd': None}])  # odd means nothing without a plain answer
        self.assertEqual(out['dropped'], 1)

    def test_a_template_hit_counts_only_with_its_result_line_and_only_for_a_host_asked_about(self):
        task = _Task({'mode': 'test', 'targets': ['https://www.example.test']})
        out = self.clean('nuclei_validate', {'outcomes': [
            {'host': 'https://www.example.test', 'vulnerable': True, 'hit': None},
            {'host': 'https://other.example.test', 'vulnerable': True, 'hit': {'matcher-name': 'x'}}]}, task)
        self.assertEqual([(o['host'], o['vulnerable']) for o in out['outcomes']], [('https://www.example.test', False)])
        hit = self.clean('nuclei_validate', {'outcomes': [{'host': 'h', 'vulnerable': True,
                                                           'hit': {'matcher-name': 'm', 'response': 'r' * 9000, 'evil': 'x', 'info': {'severity': 'nope'}}}]})
        kept = hit['outcomes'][0]['hit']
        self.assertEqual((len(kept['response']), 'evil' in kept, kept['info']['severity']), (8000, False, 'unknown'))
        with self.assertRaises(ApiError):
            self.clean('nuclei_validate', {})

    def test_an_nmap_report_is_bounded(self):
        self.assertEqual(self.clean('nmap_full', {'xml': '<nmaprun/>'})['xml'], '<nmaprun/>')
        with self.assertRaises(ApiError):
            self.clean('nmap_verify', {'xml': 'x' * (sentinel_broker.MAX_NMAP_UDP_XML + 1)})

    def test_a_report_that_names_another_host_puts_only_the_asked_address_in_the_inventory(self):
        xml = fixture('nmap_full')['xml'].replace('</host>', '</host><host><status state="up"/><address addr="198.51.100.66" addrtype="ipv4"/>'
                                                  '<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>', 1)
        self.assertEqual([h['ip'] for h in dispatch.nmap_hosts(xml, '192.0.2.10')], ['192.0.2.10'])


# ============================================================================== who may take the built-in-only kinds

class BuiltinOnlyKindTests(RouteFixture, TestCase):
    def external(self, capabilities):
        user = User.objects.create_user('ext-owner', password='x')
        token, _raw = create_token(user, 'ext-token')
        return Agent.objects.create(token=token, name='remote', kind='scanner', status='active', scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=capabilities, last_seen=timezone.now(), info={'contract_version': 3})

    def test_an_external_sentinel_is_never_offered_path_probe_or_nuclei_validate(self):
        self.external(['path_probe', 'nuclei_validate', 'db_probe'])
        self.assertTrue(dispatch.any_scanner_for(self.project, 'db_probe'))
        for kind in sentinel_broker.BUILTIN_KINDS:
            with self.subTest(kind=kind):
                self.assertFalse(dispatch.any_scanner_for(self.project, kind))
                self.assertEqual(sentinel_broker.capacity_state(self.project, kind)['state'], 'none')

    def test_the_built_in_scanner_is(self):
        with FakeScanner(kinds=['path_probe', 'nuclei_validate']):
            for kind in sentinel_broker.BUILTIN_KINDS:
                self.assertTrue(dispatch.any_scanner_for(self.project, kind), kind)

    def test_every_kind_now_has_a_stage(self):
        self.assertEqual(scanner_state.NO_STAGE, ())
        self.assertEqual(set(dispatch.COMPLETION_CEILING), set(sentinel_broker.SentinelTask.KINDS))


# ============================================================================== each stage, served and offline

class StageBase(NoRealSleep, RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.no_real_sleep()
        mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True).start()

    def arm(self, kind):
        return assert_ran_nowhere_locally(self, kind)

    def assertNothingFailed(self):
        self.assertFalse(ServiceRun.objects.filter(status='failed').exists(), list(ServiceRun.objects.values_list('service', 'asset', 'status')))


class WafStageTests(StageBase):
    def web_scan(self):
        scan = self.scan(names=('www.rt.test',))
        Subdomain.objects.filter(scan_history=scan).update(http_status=200, http_url='https://www.rt.test/login')
        return scan

    def test_the_scanner_names_the_product_and_the_stage_stores_it(self):
        scan = self.web_scan()
        self.arm('waf')
        with FakeScanner(kinds=['waf']) as fake:
            out = waf_fingerprint.run_for_scan(scan.id)
        self.assertEqual(fake.served[0]['target'], {'host': 'www.rt.test', 'ip': IP, 'port': 443, 'scheme': 'https'})
        self.assertEqual((out['tested'], out['named']), (1, 2))
        self.assertEqual(sorted(t.name for t in Subdomain.objects.get(scan_history=scan).technologies.all()), ['ExampleShield', 'FortiWeb'])
        self.assertTrue(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE, asset='www.rt.test', status='done').exists())

    def test_offline_it_waits_and_the_host_stays_due(self):
        scan = self.web_scan()
        self.arm('waf')
        with FakeScanner(kinds=['waf'], mode='offline') as fake:
            out = waf_fingerprint.run_for_scan(scan.id)
        self.assertEqual(fake.served, [])
        self.assertIn('no scanner could take this work (waf)', out['skipped'])
        self.assertFalse(ServiceRun.objects.filter(service=waf_fingerprint.SERVICE).exists())


class DbProbeStageTests(StageBase):
    def test_an_open_database_is_a_critical_finding_made_here(self):
        scan = self.scan(names=('cache.rt.test',), ports=((6379, 'redis'),))
        self.arm('db_probe')
        with FakeScanner(kinds=['db_probe']) as fake:
            out = db_exposure.run_db_exposure_checks(scan.id)
        self.assertEqual(fake.served[0]['target'], {'address': IP, 'port': 6379, 'db': 'redis'})
        self.assertEqual(out, {'checked': 1, 'exposed': 1})
        vuln = Vulnerability.objects.get(source='db_exposure')
        self.assertIn('PONG (redis 7.2.4)', vuln.description)

    def test_a_scanner_with_no_client_for_it_leaves_the_service_due(self):
        scan = self.scan(names=('cache.rt.test',), ports=((6379, 'redis'),))
        self.arm('db_probe')
        with FakeScanner(kinds=['db_probe'], responders={'db_probe': {'outcome': 'done', 'open': None, 'evidence': ''}}):
            out = db_exposure.run_db_exposure_checks(scan.id)
        self.assertEqual(out, {'checked': 0, 'exposed': 0})
        self.assertFalse(Vulnerability.objects.exists())

    def test_offline_it_waits(self):
        scan = self.scan(names=('cache.rt.test',), ports=((6379, 'redis'),))
        self.arm('db_probe')
        with FakeScanner(kinds=['db_probe'], mode='offline'):
            out = db_exposure.run_db_exposure_checks(scan.id)
        self.assertIn('no scanner could take this work (db_probe)', out['skipped'])
        self.assertFalse(Vulnerability.objects.exists())


class Node2shellStageTests(StageBase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('api.rt.test',), ports=((443, 'https'),))
        Subdomain.objects.get(scan_history=self.scan_obj).technologies.add(Technology.objects.create(name='Express:4.18.2'))
        mock.patch('cveFeed.node2shell_scan.enabled', return_value=True).start()

    def test_a_vulnerable_verdict_from_the_scanner_is_a_critical_finding(self):
        self.arm('node2shell')
        verdict = {'outcome': 'done', 'vulnerable': True, 'verdict': 'VULNERABLE', 'reason': 'same class', 'status_code': 200, 'evidence': 'HTTP/1.1 200'}
        with FakeScanner(kinds=['node2shell'], responders={'node2shell': verdict}) as fake:
            out = node2shell_scan.run_for_scan(self.scan_obj.id)
        self.assertEqual(fake.served[0]['target'], {'url': 'https://api.rt.test'})
        self.assertEqual((out['tested'], out['vulnerable']), (1, 1))
        self.assertEqual(Vulnerability.objects.get(source='node2shell').severity, 4)

    def test_offline_it_waits(self):
        self.arm('node2shell')
        with FakeScanner(kinds=['node2shell'], mode='offline'):
            out = node2shell_scan.run_for_scan(self.scan_obj.id)
        self.assertIn('no scanner could take this work (node2shell)', out['skipped'])
        self.assertFalse(ServiceRun.objects.filter(service=node2shell_scan.SERVICE).exists())


class RdpShotStageTests(StageBase):
    def setUp(self):
        super().setUp()
        self.media_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
        override = self.settings(MEDIA_ROOT=self.media_root)
        override.enable()
        self.addCleanup(override.disable)
        self.scan_obj = self.scan(names=('win.rt.test',), ports=())
        ip = Subdomain.objects.get(scan_history=self.scan_obj).ip_addresses.get()
        ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server', extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))

    def test_the_scanner_captures_and_the_reading_stays_here(self):
        self.arm('rdp_shot')
        read = []
        with FakeScanner(kinds=['rdp_shot']) as fake:
            out = rdp_shot.run_for_scan(self.scan_obj.id, reader=lambda image: read.append(image) or {'logged_in_user': '', 'summary': 'a login screen'})
        self.assertEqual(fake.served[0]['target'], {'address': IP, 'port': 3389})
        self.assertEqual((out['attempted'], out['captured'], out['read']), (1, 1, 1))
        self.assertEqual(read, [base64.b64decode(fixture('rdp_shot')['image'])])
        self.assertEqual(RdpScreenshot.objects.get(host='win.rt.test').ai_summary, 'a login screen')

    def test_offline_it_waits(self):
        self.arm('rdp_shot')
        with FakeScanner(kinds=['rdp_shot'], mode='offline'):
            out = rdp_shot.run_for_scan(self.scan_obj.id, reader=lambda image: {})
        self.assertIn('no scanner could take this work (rdp_shot)', out['skipped'])
        self.assertFalse(RdpScreenshot.objects.exists())
        self.assertNothingFailed()


class FullSweepTests(NoRealSleep, FullScanBase):
    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.no_real_sleep()

    def test_the_scanner_sweeps_and_fingerprints_the_new_ports(self):
        ip = self.ip('192.0.2.10')
        assert_ran_nowhere_locally(self, 'nmap_full')
        retested = []
        with FakeScanner(kinds=['nmap_full', 'nmap_verify']) as fake:
            out = fullscan.sweep_ip(ip, pipeline=lambda domain_id, names: retested.append(names))
        self.assertEqual(fake.served_kinds(), ['nmap_full', 'nmap_verify'])
        self.assertEqual(fake.served[1]['target'], {'address': '192.0.2.10', 'ports': [22, 443, 8443], 'version_intensity': 5})
        self.assertEqual((out['ok'], out['open'], out['new']), (True, 3, [22, 443, 8443]))
        ip = IpAddress.objects.get(pk=ip.pk)
        self.assertIsNotNone(ip.full_scanned_at)
        self.assertEqual(ip.ports.get(number=8443).product, 'nginx')
        self.assertEqual(retested, [['h10.fs.test']])

    def test_offline_the_address_is_not_marked_failed(self):
        ip = self.ip('192.0.2.10')
        assert_ran_nowhere_locally(self, 'nmap_full')
        with FakeScanner(kinds=['nmap_full'], mode='offline'):
            out = fullscan.sweep_ip(ip, pipeline=lambda *a: None)
        self.assertEqual(out, {'ip': '192.0.2.10', 'ok': False, 'error': 'ScannerUnavailable'})
        ip.refresh_from_db()
        self.assertIsNone(ip.full_scanned_at)
        self.assertEqual(ip.full_scan_failures, 0)  # waiting is not the address's failure: no back-off


class NmapProbeTests(StageBase):
    def test_the_full_intensity_probe_runs_on_the_scanner_with_the_same_safe_scripts(self):
        scan = self.scan(names=('www.rt.test',), ports=((8443, 'http'),))
        sub = Subdomain.objects.get(scan_history=scan)
        self.arm('nmap_verify')
        xml = fixture('nmap_verify')['xml'].replace('192.0.2.10', IP)
        with FakeScanner(kinds=['nmap_verify'], responders={'nmap_verify': {'outcome': 'done', 'xml': xml}}) as fake:
            found = probes.run_one(self.project.id, self.domain.id, sub, {'probe': 'nmap-version-all', 'target': {'ip': IP, 'port': 8443, 'service': 'http'}})
        target = fake.served[0]['target']
        self.assertEqual((target['ports'], target['version_all'], target['host_timeout']), ([8443], True, 90))
        self.assertEqual(target['scripts'], 'http-server-header,http-headers,http-generator,http-title,ssl-cert,banner'.split(','))  # the http set of probe_nmap_flags
        self.assertIn(('nginx', '1.25.3'), [(o['product'], o['version']) for o in found if o['kind'] == 'version'])

    def test_offline_the_probe_is_held_not_failed(self):
        scan = self.scan(names=('www.rt.test',), ports=((8443, 'http'),))
        sub = Subdomain.objects.get(scan_history=scan)
        self.arm('nmap_verify')
        with FakeScanner(kinds=['nmap_verify'], mode='offline'), self.assertRaises(resources.ScannerUnavailable):
            probes.run_one(self.project.id, self.domain.id, sub, {'probe': 'nmap-version-all', 'target': {'ip': IP, 'port': 8443, 'service': 'http'}})


class PathProbeTests(StageBase):
    TARGETS = [('192.0.2.10', 81), ('198.51.100.20', 8081), ('203.0.113.30', 9)]

    def test_the_survey_runs_on_the_built_in_scanner_one_task_per_project(self):
        self.arm('path_probe')
        with mock.patch.object(path_probe, 'candidates', return_value=self.TARGETS), mock.patch.object(path_probe, 'holder', return_value=self.project.id), \
                FakeScanner(kinds=['path_probe']) as fake:
            out = path_probe.check()
        self.assertEqual(len(fake.served), 1)
        self.assertEqual(fake.served[0]['target'], {'targets': [{'ip': ip, 'port': port} for ip, port in self.TARGETS]})
        self.assertEqual((out['vantage'], out['answered'], out['lost']), ('scanner', 3, 1))  # the fixture's fourth row names an address not asked about

    def test_with_no_built_in_scanner_nothing_is_sent_from_here(self):
        self.arm('path_probe')
        with mock.patch.object(path_probe, 'candidates', return_value=self.TARGETS), mock.patch.object(path_probe, 'holder', return_value=self.project.id):
            out = path_probe.check()
        self.assertEqual(out['state'], 'unknown')
        self.assertIn('no scanner could take this work (path_probe)', out['why'])


class NucleiValidateTests(StageBase):
    TEMPLATE = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'nuclei_validate.json').read_text())['template']

    def test_a_new_template_is_checked_on_the_scanner(self):
        self.arm('nuclei_validate')
        with FakeScanner(kinds=['nuclei_validate']) as fake:
            valid, output = templategen.validate_anywhere(self.TEMPLATE, '/nonexistent.yaml', self.project)
        self.assertEqual(fake.served[0]['target'], {'mode': 'validate', 'template': self.TEMPLATE})
        self.assertTrue(valid)
        self.assertIn('no match on benign local fixture', output)

    def test_a_failed_fixture_is_not_valid(self):
        self.arm('nuclei_validate')
        answer = {**fixture('nuclei_validate'), 'fixture_ok': False, 'fixture_note': 'matched a benign local fixture (possible false positive)'}
        with FakeScanner(kinds=['nuclei_validate'], responders={'nuclei_validate': answer}):
            valid, output = templategen.validate_anywhere(self.TEMPLATE, '/nonexistent.yaml', self.project)
        self.assertFalse(valid)
        self.assertIn('possible false positive', output)

    def test_no_ai_call_is_made_when_nothing_could_check_the_template(self):
        with self.assertRaises(resources.ScannerUnavailable):
            dispatch.nuclei_validate_ready(self.project)

    def _cve(self):
        from cveFeed.models import CVEEntry
        return CVEEntry.objects.create(cve_id='CVE-2099-8802', kev=True, cvss=9.8, published_at=timezone.now(), title='Heap overflow',
                                       affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])

    def test_no_ai_job_is_queued_when_nothing_could_check_the_template(self):
        from cveFeed.models import AIJob
        with self.assertRaises(resources.ScannerUnavailable):
            templategen.generate_template(self._cve(), project=self.project.id)
        self.assertFalse(AIJob.objects.exists())  # the AI reviewer was never asked for a template nothing could check

    def test_a_template_whose_scanner_went_away_before_its_check_is_never_a_draft(self):
        from types import SimpleNamespace
        from cveFeed.models import GeneratedTemplate
        cve = self._cve()
        job = SimpleNamespace(context={'cve': cve.pk, 'project': self.project.id}, provider='vllm', model='m')
        with mock.patch.object(templategen, 'static_check', return_value=(True, '')), \
                mock.patch.object(templategen, 'validate_anywhere', side_effect=resources.ScannerUnavailable('nuclei_validate', 'gone')):
            templategen.job_answer(job, self.TEMPLATE)
        saved = GeneratedTemplate.objects.get(cve_entry=cve)
        self.assertEqual(saved.status, GeneratedTemplate.STATUS_INVALID)
        self.assertIn('not validated: no scanner could take this work (nuclei_validate)', saved.validation_output)

    def test_an_approved_template_is_run_against_the_project_hosts_on_the_scanner(self):
        self.arm('nuclei_validate')
        hosts = ['https://www.rt.test', 'https://api.rt.test']

        def answer(task):
            return {'outcome': 'done', 'outcomes': [
                {'host': hosts[0], 'vulnerable': True, 'output': '{}', 'hit': {'matcher-name': 'word', 'matched-at': hosts[0] + '/x'}},
                {'host': 'https://elsewhere.example.test', 'vulnerable': True, 'output': '', 'hit': {'matcher-name': 'word'}}]}
        with FakeScanner(kinds=['nuclei_validate'], responders={'nuclei_validate': answer}) as fake:
            outcomes = dispatch.try_template_test(self.TEMPLATE, hosts, self.project.id)
        self.assertEqual(fake.served[0]['target'], {'mode': 'test', 'template': self.TEMPLATE, 'targets': hosts})
        self.assertEqual(fake.tasks()[0].project_id, self.project.id)  # filed under the hosts' own project
        self.assertTrue(outcomes[0]['vulnerable'])
        self.assertEqual(outcomes[0]['hit']['matched-at'], 'https://www.rt.test/x')
        self.assertEqual(outcomes[1]['error'], dispatch.NOT_REPORTED)  # left out by the scanner: not tested, never a clean "no match"

    def test_without_a_project_the_template_test_never_leaves_this_server(self):
        with mock.patch.object(dispatch, 'try_template_test') as remote, mock.patch.object(templategen, '_run_template', return_value=['local']):
            self.assertEqual(templategen._run_anywhere('/t.yaml', ['https://www.rt.test']), ['local'])
            self.assertEqual(templategen._run_anywhere('/t.yaml', ['https://www.rt.test'], secret_file='/s', project=self.project.id), ['local'])
        remote.assert_not_called()  # a signed-in run is never dispatched either
