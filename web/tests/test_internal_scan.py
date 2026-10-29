"""The internal scan driver: a target inside a declared internal range is scanned only through a network:internal Sentinel."""
import os
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import assessment_review, coverage_topup, host_assessment, internal_scan
from cveFeed.models import HostAssessment
from cveFeed.discovery import FAILED, QUEUED, SUCCESS
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_internal_ranges import World
from tests.test_sentinels import reset_rates

def iter_none(targets_file, **kwargs):
    return iter(())


NMAP_RESULT = {'hosts': [{'ip': '10.20.0.7', 'os_guess': 'Linux 5.x', 'ports': [
    {'number': 22, 'protocol': 'tcp', 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '8.2'},
    {'number': 443, 'protocol': 'tcp', 'service_name': 'https', 'product': 'nginx', 'version': '1.18.0'}]}]}


class Base(World):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        EngineType.objects.create(engine_name='e-isc', yaml_configuration='x', default_engine=True)
        self.declare()
        self.domain = Domain.objects.create(name='10.20.0.7', project=self.pa, insert_date=timezone.now())

    def sentinel(self, name, capabilities):
        token = create_token(self.root, f'isc-{name}')[1]
        reset_rates({'t': token})
        status, out = call(token, 'PUT', '/api/v1/sentinel', {'name': name, 'scope': {'projects': ['ir-a']}, 'capabilities': capabilities})
        self.assertIn(status, (200, 201), out)
        # network:internal is the server's to grant (the enrollment an administrator provisioned, or an administrator's change), not a Sentinel's to declare
        Agent.objects.filter(pk=out['id']).update(status='active', last_seen=timezone.now(), network='internal' if 'network:internal' in capabilities else 'external')
        return out['id']

    def queued_scan(self):
        return ScanHistory.objects.create(domain=self.domain, scan_type=EngineType.objects.first(), start_scan_date=timezone.now(),
                                          scan_status=QUEUED, results_dir='/tmp', tasks=[internal_scan.TASK_TAG])


class RunTests(Base):
    def test_a_sentinel_answer_becomes_the_host_its_services_and_a_correlation_run(self):
        scan = self.queued_scan()
        calls = []

        def dispatch(project, kind, target, **kwargs):
            calls.append((kind, target, kwargs))
            return NMAP_RESULT
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}) as correlate, \
                mock.patch('cveFeed.nmap_scan.scan_in_chunks') as local_nmap:
            out = internal_scan.run(scan.id, dispatch=dispatch, nuclei_stream=lambda kind: iter_none, provider=None)
            local_nmap.assert_not_called()
        self.assertEqual(out['status'], SUCCESS, out)
        self.assertEqual(calls[0][:2], ('nmap', {'addresses': ['10.20.0.7']}))
        self.assertTrue(all(kw['internal'] for _k, _t, kw in calls))  # every step is for an internal Sentinel
        self.assertTrue(Subdomain.objects.filter(scan_history=scan, name='10.20.0.7').exists())
        self.assertEqual(sorted(Port.objects.filter(ports__address='10.20.0.7').values_list('number', flat=True)), [22, 443])
        self.assertEqual(IpAddress.objects.get(address='10.20.0.7').os_guess, 'Linux 5.x')
        correlate.assert_called_once_with(scan_history_id=scan.id)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, SUCCESS)
        self.assertTrue(ScanActivity.objects.filter(scan_of=scan, name='cve_correlation', status=SUCCESS).exists())
        stages = list(ScanActivity.objects.filter(scan_of=scan).order_by('id').values_list('name', flat=True))
        self.assertLess(stages.index('cve_correlation'), stages.index('nuclei_targeted_scan'))

    def test_internal_inventory_is_serviced_by_its_own_pipeline_not_host_assessment(self):
        scan = self.queued_scan()
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            internal_scan.run(scan.id, dispatch=lambda *a, **k: NMAP_RESULT, nuclei_stream=lambda kind: iter_none, provider=None)
        sub = Subdomain.objects.get(scan_history=scan, name=self.domain.name)
        # Even an incomplete internal stage belongs to the Sentinel scan cadence,
        # rather than the external host-assessment queue or deep-scan gate.
        ScanActivity.objects.filter(scan_of=scan, name='cve_correlation').update(status=FAILED)
        self.assertEqual(assessment_review.host_coverage_due(self.pa, timezone.now()), (0, []))
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
                mock.patch('cveFeed.unresolved_archive.recheck', return_value=0), \
                mock.patch('cveFeed.tasks.assess_host.apply_async') as external:
            self.assertEqual(coverage_topup.top_up()['hosts_queued'], 0)
            self.assertFalse(coverage_topup.backlog_exists())
            external.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'internal Sentinel'):
            host_assessment.enqueue(self.pa, sub)

    def test_queued_external_assessment_is_refused_after_host_becomes_internal(self):
        Subdomain.objects.create(target_domain=self.domain, name=self.domain.name)
        job = HostAssessment.objects.create(project=self.pa, domain=self.domain, host=self.domain.name, status='queued')
        with mock.patch('cveFeed.discovery.run_host_pipeline') as external:
            outcome = host_assessment.execute(job.pk)
            external.assert_not_called()
        self.assertEqual(outcome['status'], 'inconclusive')

    def test_no_sentinel_answering_fails_the_scan_and_nothing_runs_locally(self):
        scan = self.queued_scan()
        with mock.patch('cveFeed.tasks.correlate_cves') as correlate, mock.patch('cveFeed.nmap_scan.scan_in_chunks') as local_nmap, \
                mock.patch('cveFeed.nmap_scan.run_nmap_xml') as local_xml:
            out = internal_scan.run(scan.id, dispatch=lambda *a, **k: None, nuclei_stream=lambda kind: iter_none, provider=None)
            local_nmap.assert_not_called()
            local_xml.assert_not_called()
            correlate.assert_not_called()
        self.assertEqual(out['status'], FAILED)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, FAILED)
        self.assertIn('network:internal', scan.error_message)

    def test_a_range_removed_after_queueing_scans_nothing(self):
        scan = self.queued_scan()
        self.pa.internal_ranges.all().delete()
        seen = []
        out = internal_scan.run(scan.id, dispatch=lambda *a, **k: seen.append(a) or NMAP_RESULT)
        self.assertEqual(out['status'], FAILED)
        self.assertEqual(seen, [])
        self.assertIn('no longer inside', out['error'])

    def test_an_answer_about_another_address_is_not_stored(self):
        scan = self.queued_scan()
        other = {'hosts': [{'ip': '10.20.0.99', 'ports': [{'number': 80, 'protocol': 'tcp', 'service_name': 'http'}]}]}
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            internal_scan.run(scan.id, dispatch=lambda *a, **k: other, nuclei_stream=lambda kind: iter_none, provider=None)
        self.assertFalse(Port.objects.filter(ports__address='10.20.0.99').exists())


class EligibilityTests(Base):
    def test_only_a_network_internal_sentinel_counts_for_internal_work(self):
        self.sentinel('outside', ['nmap'])
        self.assertTrue(sb.any_scanner_for(self.pa, 'nmap'))
        self.assertFalse(sb.any_scanner_for(self.pa, 'nmap', internal=True))
        self.sentinel('inside', ['nmap', 'network:internal'])
        self.assertTrue(sb.any_scanner_for(self.pa, 'nmap', internal=True))

    def test_dispatch_creates_no_task_when_only_an_outside_sentinel_exists(self):
        self.sentinel('outside', ['nmap'])
        self.assertIsNone(sentinel_dispatch.dispatch_or_none(self.pa, 'nmap', {'addresses': ['10.20.0.7']}, ips=['10.20.0.7'], internal=True))
        self.assertFalse(SentinelTask.objects.exists())


class StartAndSweepTests(Base):
    def test_start_queues_one_scan_and_returns_the_same_one_again(self):
        with mock.patch('cveFeed.tasks.run_internal_scan') as task:
            first = internal_scan.start(self.domain)
            second = internal_scan.start(self.domain)
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.scan_status, QUEUED)
        task.delay.assert_called_once_with(first.id)

    def test_start_refuses_a_target_that_is_not_internal(self):
        public = Domain.objects.create(name='203.0.113.7', project=self.pa, insert_date=timezone.now())
        with self.assertRaises(ValueError):
            internal_scan.start(public)

    def test_sweep_needs_an_internal_sentinel_and_respects_the_cadence(self):
        self.assertEqual(internal_scan.due_targets(), [])  # no Sentinel at all
        self.sentinel('outside', ['nmap'])
        self.assertEqual(internal_scan.due_targets(), [])  # an outside one cannot take it
        self.sentinel('inside', ['nmap', 'network:internal'])
        self.assertEqual([d.id for d in internal_scan.due_targets()], [self.domain.id])
        ScanHistory.objects.create(domain=self.domain, scan_type=EngineType.objects.first(), start_scan_date=timezone.now() - timedelta(days=1),
                                   scan_status=SUCCESS, results_dir='/tmp', tasks=[internal_scan.TASK_TAG])
        self.assertEqual(internal_scan.due_targets(), [])  # scanned yesterday
        ScanHistory.objects.filter(domain=self.domain).update(start_scan_date=timezone.now() - timedelta(days=8))
        self.assertEqual([d.id for d in internal_scan.due_targets()], [self.domain.id])

    def test_the_sweep_queues_and_skips_while_paused(self):
        self.sentinel('inside', ['nmap', 'network:internal'])
        with mock.patch('cveFeed.tasks.run_internal_scan') as task:
            with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
                self.assertEqual(internal_scan.sweep()['skipped'], 'paused')
            self.assertEqual(internal_scan.sweep(), {'started': 1})
        task.delay.assert_called_once()


class HandStartedTests(Base):
    def test_starting_a_scan_on_an_internal_target_queues_the_internal_pipeline_not_bbot(self):
        with mock.patch('cveFeed.discovery.start_discovery') as bbot, mock.patch('cveFeed.tasks.run_internal_scan') as task:
            status, out = call(self.t['admin'], 'POST', f'/api/v1/projects/ir-a/targets/{self.domain.pk}/discover', {})
            self.assertEqual(status, 202, out)
            self.assertTrue(out['internal'])
            status, out2 = call(self.t['admin'], 'POST', '/api/v1/projects/ir-a/scans', {'target_id': self.domain.pk})
            self.assertEqual(status, 202, out2)
            bbot.assert_not_called()
        self.assertEqual(out['scan_id'], out2['scan_id'])
        self.assertEqual(task.delay.call_count, 1)


class StorageTests(Base):
    def test_an_internal_address_is_stored_only_for_the_host_that_is_that_address(self):
        from reNgine.tasks import save_ip_address
        self.assertIsNotNone(save_ip_address('10.20.0.7', subdomain=None, project_id=self.pa.id)[0])
        self.assertIsNone(save_ip_address('10.20.0.8', subdomain=None, project_id=self.pb.id)[0])  # another project did not declare it
        self.assertIsNone(save_ip_address('10.20.0.9', subdomain=None)[0])  # no project: a name that resolved there
        self.assertIsNone(save_ip_address('10.30.0.9', subdomain=None, project_id=self.pa.id)[0])  # outside the range


TLS_ITEMS = {'items': [{'id': 'heartbleed', 'severity': 'CRITICAL', 'finding': 'VULNERABLE (NOT ok)', 'cve': 'CVE-2014-0160'},
                       {'id': 'SSLv3', 'severity': 'OK', 'finding': 'not offered'}]}
NUCLEI_FINDING = {'host': '10.20.0.7:8443', 'matched_at': 'https://10.20.0.7:8443/', 'template_id': 'exposed-panel', 'name': 'Exposed admin panel',
                  'severity': 'medium', 'description': 'x', 'tags': ['panel']}


class StageTests(Base):
    def run_scan(self, answers, **kwargs):
        scan = self.queued_scan()
        kinds = []

        def dispatch(project, kind, target, **kw):
            kinds.append(kind)
            return answers.get(kind)
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            out = internal_scan.run(scan.id, dispatch=dispatch, **{'nuclei_stream': lambda kind: iter_none, 'provider': None, **kwargs})
        return scan, out, kinds

    def test_each_tls_port_nmap_found_is_audited_and_its_findings_stored(self):
        from cveFeed.models import ProbeObservation
        scan, out, kinds = self.run_scan({'nmap': NMAP_RESULT, 'testssl': TLS_ITEMS})
        self.assertEqual(out['status'], SUCCESS, out)
        self.assertEqual(kinds, ['nmap', 'testssl', 'nmap_udp'])  # one TLS port (443); ssh is not audited
        self.assertTrue(ProbeObservation.objects.filter(project_id=self.pa.id, host='10.20.0.7').exists())

    def test_a_failed_tls_audit_does_not_fail_the_scan(self):
        scan, out, kinds = self.run_scan({'nmap': NMAP_RESULT})
        self.assertEqual(out['status'], SUCCESS)
        self.assertEqual(kinds, ['nmap', 'testssl', 'nmap_udp'])

    def test_nuclei_findings_from_the_sentinel_are_stored_through_the_normal_parser(self):
        from cveFeed import nuclei_scan
        from startScan.models import Vulnerability
        from targetApp.target_types import internal_scope
        scan, out, _kinds = self.run_scan({'nmap': NMAP_RESULT})
        self.assertEqual(out['status'], SUCCESS)
        with internal_scope():  # the targeted pass's own seam, fed a Sentinel's finding
            nuclei_scan._run_nuclei(scan.id, stream=lambda path, **kw: iter([sentinel_dispatch._finding_to_nuclei_line(NUCLEI_FINDING)]))
        self.assertTrue(Vulnerability.objects.filter(scan_history=scan, name='Exposed admin panel').exists())

    def test_the_nuclei_stream_dispatches_for_internal_and_never_falls_back_to_local(self):
        scan = self.queued_scan()
        stream = sentinel_dispatch.wrap_nuclei_stream(scan, 'nuclei_light', internal=True)
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
            handle.write('10.20.0.7\n')
        with mock.patch('cveFeed.nuclei_scan.stream_nuclei') as local, self.assertRaises(RuntimeError):
            list(stream(handle.name))  # no Sentinel at all
        local.assert_not_called()

    def test_an_internal_stream_refuses_a_secrets_file_instead_of_dropping_it(self):
        scan = self.queued_scan()
        stream = sentinel_dispatch.wrap_nuclei_stream(scan, 'nuclei_targeted', internal=True)
        with mock.patch('agentapi.sentinel_dispatch.dispatch_or_none') as dispatched, self.assertRaises(RuntimeError) as caught:
            list(stream('/nonexistent', secret_file='/tmp/secrets.yaml'))
        dispatched.assert_not_called()
        self.assertIn('signed-in', str(caught.exception))

    def test_every_local_scanner_refuses_inside_an_internal_scan(self):
        from cveFeed import naabu_scan, nmap_scan, nuclei_scan, testssl_scan, wpscan_scan
        from targetApp.target_types import internal_scope
        with internal_scope():
            for call_ in (lambda: naabu_scan.run_naabu(['10.20.0.7'], binary='/bin/true'),
                          lambda: nmap_scan.run_nmap_xml(['10.20.0.7'], [], 1),
                          lambda: testssl_scan.run_testssl('10.20.0.7', '10.20.0.7', 443),
                          lambda: wpscan_scan.run_wpscan_process('https://10.20.0.7/', 'token'),
                          lambda: list(nuclei_scan.stream_nuclei('/nonexistent'))):
                with self.assertRaises(RuntimeError) as caught:
                    call_()
                self.assertIn('only a Sentinel inside the network', str(caught.exception))

    def test_scan_targets_include_the_internal_address_only_inside_the_scope(self):
        from cveFeed import nuclei_scan
        from targetApp.target_types import internal_scope
        scan = self.queued_scan()
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            internal_scan.run(scan.id, dispatch=lambda p, k, t, **kw: NMAP_RESULT if k == 'nmap' else None,
                              nuclei_stream=lambda kind: iter_none, provider=None)
        self.assertEqual(nuclei_scan.scan_targets(scan), (set(), set(), set()))
        with internal_scope():
            hostnames, ips, _ports = nuclei_scan.scan_targets(scan)
        self.assertEqual((hostnames, ips), ({'10.20.0.7'}, {'10.20.0.7'}))


UDP_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.20.0.7" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open"/><service name="snmp" product="net-snmp" version="5.9"/></port></ports></host></nmaprun>"""


class UdpStageTests(StageTests):
    def test_the_sentinels_udp_xml_is_stored_by_the_external_sweeps_own_functions(self):
        scan, out, kinds = self.run_scan({'nmap': NMAP_RESULT, 'nmap_udp': {'xml': UDP_XML}})
        self.assertEqual(out['status'], SUCCESS)
        self.assertEqual(list(Port.objects.filter(ports__address='10.20.0.7', protocol='udp').values_list('number', flat=True)), [161])

    def test_an_empty_udp_answer_is_recorded_as_a_failed_stage_not_a_failed_scan(self):
        scan, out, kinds = self.run_scan({'nmap': NMAP_RESULT, 'nmap_udp': {'xml': ''}})
        self.assertEqual(out['status'], SUCCESS)
        self.assertFalse(Port.objects.filter(protocol='udp').exists())


class WpscanTests(Base):
    """WPScan for an internal host: through a Sentinel inside the network, only where the Sentinel-run technology pass tagged WordPress."""

    def run_scan(self, tagged=True, wp_runner=None, wpscan_answer=None, **kwargs):
        from startScan.models import Subdomain, Technology
        scan = self.queued_scan()
        calls = []

        def dispatch(project, kind, target, **kw):
            if kind == 'nmap' and tagged:
                sub = Subdomain.objects.get(scan_history=scan, name='10.20.0.7')
                sub.technologies.add(Technology.objects.create(name='WordPress'))
            return NMAP_RESULT if kind == 'nmap' else None

        def fake_dispatch_or_none(project, kind, target, **kw):
            calls.append((kind, target, kw))
            return wpscan_answer
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}), \
                mock.patch('agentapi.sentinel_dispatch.dispatch_or_none', side_effect=fake_dispatch_or_none), \
                mock.patch('cveFeed.probes.run_http_probe') as probe, mock.patch('cveFeed.wpscan_scan.plugin_titles') as titles, \
                mock.patch('cveFeed.wpscan_scan.run_wpscan_process') as local, mock.patch('cveFeed.wpscan_scan.queue_thorough') as thorough:
            out = internal_scan.run(scan.id, dispatch=dispatch, nuclei_stream=lambda kind: iter_none, provider=None, wp_runner=wp_runner, **kwargs)
        return scan, out, calls, {'probe': probe, 'titles': titles, 'local': local, 'thorough': thorough}

    def test_a_site_tagged_wordpress_is_scanned_through_the_runner_and_stored_with_nothing_sent_from_this_server(self):
        from startScan.models import Vulnerability
        from tests.test_wpscan import REPORT
        urls = []

        def runner(url, token):
            urls.append(url)
            return REPORT
        scan, out, _calls, mocks = self.run_scan(wp_runner=runner)
        self.assertEqual(out['status'], SUCCESS, out)
        self.assertEqual(urls, ['https://10.20.0.7'])
        self.assertTrue(Vulnerability.objects.filter(scan_history=scan, name__startswith='WordPress').exists())
        mocks['probe'].assert_not_called()  # no WordPress probe from here
        mocks['titles'].assert_not_called()  # no plugin page lookups from here
        mocks['thorough'].assert_not_called()  # a thorough pass would run from here
        mocks['local'].assert_not_called()

    def test_a_host_with_no_sign_of_wordpress_is_not_scanned(self):
        scan, out, calls, _mocks = self.run_scan(tagged=False, wp_runner=mock.Mock(side_effect=AssertionError('must not run')))
        self.assertEqual(out['status'], SUCCESS, out)
        self.assertEqual(calls, [])

    def test_the_real_runner_hands_the_site_to_an_internal_sentinel_with_its_address_so_an_outside_one_cannot_take_it(self):
        from tests.test_wpscan import REPORT
        scan, out, calls, mocks = self.run_scan(wpscan_answer={'report': REPORT, 'returncode': 0, 'stderr_tail': ''})
        self.assertEqual(out['status'], SUCCESS, out)
        kind, target, kw = calls[0]
        self.assertEqual((kind, target['url']), ('wpscan', 'https://10.20.0.7'))
        self.assertTrue(kw['internal'])
        self.assertEqual(kw['ips'], ['10.20.0.7'])
        mocks['local'].assert_not_called()

    def test_with_no_sentinel_answering_nothing_runs_locally_and_the_site_is_recorded_as_failed(self):
        from cveFeed.models import ProbeObservation
        scan, out, calls, mocks = self.run_scan(wpscan_answer=None)
        self.assertEqual(out['status'], SUCCESS, out)  # a WordPress site without a Sentinel answer does not fail the whole scan
        self.assertEqual(len(calls), 1)
        mocks['local'].assert_not_called()
        self.assertTrue(ProbeObservation.objects.filter(project_id=self.pa.id, host='10.20.0.7', kind='wordpress').exists())
