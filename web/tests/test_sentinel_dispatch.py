"""Dispatch-or-local: the critical regression property (zero Sentinels behaves exactly as before this feature existed),
plus the three dispatch points actually wired (nmap, naabu, nuclei light/targeted) succeeding and timing out."""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import nmap_scan, nuclei_scan
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

FAST_XML = '''<?xml version="1.0"?>
<nmaprun><host>
<address addr="192.0.2.10" addrtype="ipv4"/>
<os><osmatch name="Linux 5.X" accuracy="95"/></os>
<ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
</port></ports>
</host></nmaprun>'''


def _answer_queued_task(result, status='done'):
    """A fake ``time.sleep`` that, the first time dispatch's wait loop calls it, completes the SentinelTask it is
    waiting on as a real Sentinel would, without any real concurrency or a second process."""
    def fake_sleep(_seconds):
        task = SentinelTask.objects.filter(status__in=('queued', 'claimed', 'running')).order_by('-id').first()
        if task:
            SentinelTask.objects.filter(pk=task.pk).update(status=status, result=result, finished_at=timezone.now())
    return fake_sleep


class DispatchBase(TestCase):
    def setUp(self):
        self.org = Org.objects.create(name='D', slug='disp')
        self.project = Project.objects.create(name='D', slug='disp-p', insert_date=timezone.now(), org=self.org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-disp', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(),
                                               scan_status=1, results_dir='/tmp')
        sub = Subdomain.objects.create(scan_history=self.scan, name='www.example.test')
        sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.10'))

    def make_sentinel(self, capabilities):
        user = User.objects.create_user(f'sentinel-owner-{capabilities[0]}', password='x')
        token, _raw = create_token(user, 'sentinel-token')
        agent = Agent.objects.create(token=token, name='live-sentinel', kind='scanner', status='active',
                                     scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                     capabilities=capabilities, last_seen=timezone.now())
        return agent


class ZeroSentinelRegressionTests(DispatchBase):
    """The single most important property: a project with no Sentinel registered runs nmap, naabu and nuclei exactly as
    it did before this feature existed. No Agent row exists anywhere in this test class's database."""

    def test_any_scanner_for_is_false_with_no_agents(self):
        for kind in SentinelTask.KINDS:
            self.assertFalse(dispatch.any_scanner_for(self.project, kind))

    def test_run_nmap_for_scan_result_is_unchanged(self):
        calls = []

        def runner(targets, flags, host_timeout):
            calls.append((targets, flags, host_timeout))
            return FAST_XML
        result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
        self.assertEqual(result, {'targets': 1, 'reused': 0, 'fast': {'ports': 1, 'hosts_with_os': 1}})
        self.assertEqual(calls, [(['192.0.2.10'], nmap_scan.FAST_FLAGS, nmap_scan.HOST_TIMEOUT_FAST)])
        # IpAddress rows are per organization (startScan.ip_rows.get_or_create_ip): the row nmap wrote is the one scoped
        # to this project's own org, not the address-only row IP objects.create() made in setUp with no org.
        port = IpAddress.objects.get(address='192.0.2.10', org_id=self.project.org_id).ports.get(number=22)
        self.assertEqual((port.product, port.source), ('OpenSSH', 'nmap'))

    def test_wrap_naabu_runner_is_none_so_discover_uses_its_own_default(self):
        self.assertIsNone(dispatch.wrap_naabu_runner(self.project, self.scan))

    def test_try_nmap_is_a_no_op(self):
        remaining, totals = dispatch.try_nmap(self.project, self.scan, ['192.0.2.10', '192.0.2.11'])
        self.assertEqual(remaining, ['192.0.2.10', '192.0.2.11'])
        self.assertEqual(totals, {'ports': 0, 'hosts_with_os': 0})
        self.assertFalse(SentinelTask.objects.exists())  # not even a row was created

    def test_wrap_nuclei_stream_returns_the_literal_unwrapped_function(self):
        stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
        self.assertIs(stream, nuclei_scan.stream_nuclei)  # identity, not just equal: _run_nuclei checks `stream is stream_nuclei`

    def test_dispatch_or_none_is_a_no_op(self):
        self.assertIsNone(dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}))
        self.assertFalse(SentinelTask.objects.exists())


class NmapDispatchTests(DispatchBase):
    def test_a_live_eligible_sentinel_handles_the_chunk_and_persists_through_the_same_function(self):
        self.make_sentinel(['nmap'])
        result = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.10', 'os_guess': 'Linux 6.X',
                   'ports': [{'number': 443, 'protocol': 'tcp', 'state': 'open', 'service_name': 'https', 'product': 'nginx', 'version': '1.25'}]}]}
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            remaining, totals = dispatch.try_nmap(self.project, self.scan, ['192.0.2.10'], timeout=5)
        self.assertEqual(remaining, [])
        self.assertEqual(totals, {'ports': 1, 'hosts_with_os': 1})
        port = IpAddress.objects.get(address='192.0.2.10').ports.get(number=443)
        self.assertEqual((port.product, port.version, port.source), ('nginx', '1.25', 'nmap'))

    def test_timeout_falls_back_to_local_and_the_task_is_marked_expired(self):
        self.make_sentinel(['nmap'])
        remaining, totals = dispatch.try_nmap(self.project, self.scan, ['192.0.2.10'], timeout=0.2)
        self.assertEqual(remaining, ['192.0.2.10'])
        self.assertEqual(totals, {'ports': 0, 'hosts_with_os': 0})
        task = SentinelTask.objects.get(kind='nmap')
        self.assertEqual(task.status, 'expired')
        self.assertIsNone(task.agent_id)

    def test_end_to_end_via_run_nmap_for_scan_falls_back_locally_on_timeout(self):
        self.make_sentinel(['nmap'])
        calls = []

        def local_runner(targets, flags, host_timeout):
            calls.append(targets)
            return FAST_XML
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_DISPATCH_TIMEOUT': '1'}):
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=local_runner)
        self.assertTrue(calls)  # the local runner still ran for whatever the Sentinel did not finish in time
        self.assertEqual(result['fast']['ports'], 1)


class NaabuDispatchTests(DispatchBase):
    def test_a_live_eligible_sentinel_supplies_ports_without_a_local_naabu_call(self):
        self.make_sentinel(['naabu'])
        result = {'outcome': 'done', 'ports': {'192.0.2.10': [22, 80]}}
        local = mock.Mock(return_value={})
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)), \
             mock.patch('cveFeed.naabu_scan.run_naabu', local):
            runner = dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)
            found = runner(['192.0.2.10'])
        self.assertEqual(found, {'192.0.2.10': [22, 80]})
        local.assert_not_called()

    def test_timeout_falls_back_to_the_real_local_naabu_runner(self):
        self.make_sentinel(['naabu'])
        local = mock.Mock(return_value={'192.0.2.10': [9999]})
        with mock.patch('cveFeed.naabu_scan.run_naabu', local):
            runner = dispatch.wrap_naabu_runner(self.project, self.scan, timeout=0.2)
            found = runner(['192.0.2.10'])
        local.assert_called_once()
        self.assertEqual(found, {'192.0.2.10': [9999]})


class NucleiDispatchTests(DispatchBase):
    def test_light_pass_sentinel_finding_creates_a_technology_link_via_the_unchanged_local_loop(self):
        """run_light_nuclei's own loop turns each result line into a Technology link (cveFeed.nuclei_scan.tech_name_from);
        a Sentinel's reconstructed line goes through that exact, untouched loop, same as a locally-run nuclei line would."""
        self.make_sentinel(['nuclei_light'])
        result = {'outcome': 'done', 'findings': [{'template_id': 'exposed-panel', 'name': 'jQuery', 'severity': 'info',
                   'host': 'www.example.test', 'matched_at': 'https://www.example.test/', 'description': '', 'tags': [],
                   'extracted_results': []}]}
        stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', timeout=5)
        self.assertIsNot(stream, nuclei_scan.stream_nuclei)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            light_result = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        self.assertEqual(light_result['hosts'], 1)
        self.assertEqual(light_result['techs'], {'www.example.test': ['jQuery']})
        sub = Subdomain.objects.get(scan_history=self.scan, name='www.example.test')
        self.assertIn('jQuery', [t.name for t in sub.technologies.all()])

    def test_light_pass_a_finding_with_no_name_links_nothing(self):
        # cveFeed.nuclei_scan.tech_name_from names a technology from info.name (or, for the real tech-detect template,
        # its matcher-name). A Sentinel that reports no name and no matcher_name for a light-pass finding correctly
        # links nothing, same as a local nuclei line nuclei_scan would have skipped for the same reason.
        self.make_sentinel(['nuclei_light'])
        result = {'outcome': 'done', 'findings': [{'template_id': 'tech-detect', 'name': '', 'severity': 'info',
                   'host': 'www.example.test', 'matched_at': 'https://www.example.test/', 'description': '', 'tags': [],
                   'extracted_results': []}]}
        stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', timeout=5)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            light_result = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        self.assertEqual(light_result['hosts'], 0)

    def test_light_pass_tech_detect_finding_with_matcher_name_links_the_same_technology_a_local_run_would(self):
        # tech-detect is named by its matcher, not by info.name (cveFeed.nuclei_scan.tech_name_from): a Sentinel-reported
        # finding must carry matcher_name through to the reconstructed nuclei line's 'matcher-name' for this to work,
        # exactly as a locally-run nuclei -jsonl line already supplies it.
        self.make_sentinel(['nuclei_light'])
        result = {'outcome': 'done', 'findings': [{'template_id': 'tech-detect', 'name': '', 'severity': 'info',
                   'host': 'www.example.test', 'matched_at': 'https://www.example.test/', 'description': '', 'tags': [],
                   'extracted_results': [], 'matcher_name': 'jquery'}]}
        stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', timeout=5)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            light_result = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        self.assertEqual(light_result['hosts'], 1)
        self.assertEqual(light_result['techs'], {'www.example.test': ['jquery']})
        sub = Subdomain.objects.get(scan_history=self.scan, name='www.example.test')
        self.assertIn('jquery', [t.name for t in sub.technologies.all()])
        # The same name a local nuclei run's tech_name_from would have produced, from the equivalent raw line.
        local_line = {'template-id': 'tech-detect', 'matcher-name': 'jquery', 'info': {'name': ''}, 'extracted-results': []}
        self.assertEqual(nuclei_scan.tech_name_from(local_line), 'jquery')

    def test_targeted_pass_sentinel_findings_land_in_vulnerability_rows_via_the_unchanged_local_loop(self):
        """run_targeted_nuclei's own template-group loop calls run_nuclei -> _run_nuclei, which persists through
        reNgine.tasks.save_vulnerability for every result line; a Sentinel's reconstructed line goes through that exact,
        untouched code, so a dispatched finding becomes a Vulnerability row the same way a local one would."""
        self.make_sentinel(['nuclei_targeted'])
        result = {'outcome': 'done', 'findings': [{'template_id': 'exposed-panel', 'name': 'Exposed admin panel', 'severity': 'high',
                   'host': 'www.example.test', 'matched_at': 'https://www.example.test/admin', 'description': 'found it',
                   'extracted_results': ['panel'], 'tags': ['panel']}]}
        stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_targeted', timeout=5)
        self.assertIsNot(stream, nuclei_scan.stream_nuclei)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            targeted = nuclei_scan._run_nuclei(self.scan.id, stream=stream, targets=['www.example.test'])
        self.assertEqual(targeted['findings'], 1)
        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.get(name='Exposed admin panel')
        self.assertEqual(vuln.template_id, 'exposed-panel')
        self.assertEqual(vuln.severity, 3)  # NUCLEI_SEVERITY_MAP['high']

    def test_timeout_falls_back_to_the_real_local_stream(self):
        self.make_sentinel(['nuclei_light'])
        calls = []

        def local_stream(path, **kwargs):
            calls.append(path)
            return iter([{'host': 'local-fallback-ran'}])
        with mock.patch('cveFeed.nuclei_scan.stream_nuclei', local_stream):
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', timeout=0.2)
            lines = list(stream('/tmp/does-not-exist-targets.txt'))
        self.assertTrue(calls)  # the real local stream ran once the dispatch wait timed out
        self.assertEqual(lines, [{'host': 'local-fallback-ran'}])
