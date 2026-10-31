"""With ``CVENGINE_LOCAL_FALLBACK=none`` and no scanner that can take the work, every scan stage waits instead of failing: the local tool is never
run, no ledger row says ``failed`` (nor ``done``: the target is still due), the stage returns without raising and its activity line names the
scanner, not memory. nmap, naabu and nuclei had no such handler until now; testssl, UDP and WPScan are asserted here so a regression is caught."""
import os
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_dispatch as dispatch
from cveFeed import discovery, ledger, naabu_scan, nmap_scan, nuclei_scan, performance_review, testssl_scan, udp_scan, wpscan_scan
from cveFeed.models import AgentActivity, BackgroundCursor, ServiceRun
from reNgine import resources
from startScan.models import ScanActivity, ScanHistory, Subdomain, Technology
from tests.test_route_auth import RouteFixture
from tests.test_sentinel_dispatch import DispatchBase
from tests.test_testssl_scan import CLEAN
from tests.test_udp_scan import UdpBase
from tests.test_wpscan import REPORT

ENV = dispatch.LOCAL_FALLBACK_ENV
IP = '192.0.2.10'


class WaitsMixin:
    """The assertions every stage shares."""

    def assertNothingRecorded(self, *services):
        self.assertFalse(ServiceRun.objects.filter(status='failed').exists(), list(ServiceRun.objects.values_list('service', 'asset', 'status')))
        for service in services:  # not a success either: the target is still due
            self.assertFalse(ServiceRun.objects.filter(service__startswith=service).exists(), service)

    def waiting_lines(self):
        return list(AgentActivity.objects.filter(message__icontains='waiting').values_list('message', 'status'))

    def assertNamesTheScanner(self, kind, lines=None):
        lines = self.waiting_lines() if lines is None else lines
        self.assertTrue(lines, 'the stage left no activity line saying it waits')
        for message, status in lines:
            self.assertIn('no scanner could take this work', message)
            self.assertIn(kind, message)
            self.assertNotIn('memory', message.lower())
            self.assertNotEqual(status, 'failed')
            self.assertNotEqual(status, 'running')


class FallbackOffBase(WaitsMixin, DispatchBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ, {ENV: 'none'}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True)  # example.test never resolves in a sandbox
        patcher.start()
        self.addCleanup(patcher.stop)


class NmapFastTests(FallbackOffBase):
    def run_fast(self, **kwargs):
        runner = mock.Mock(return_value='<nmaprun/>')
        with mock.patch('cveFeed.naabu_scan.run_naabu') as naabu:
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner, **kwargs)
        return result, runner, naabu

    def test_with_no_sentinel_the_stage_waits_and_nothing_runs_here(self):
        result, runner, naabu = self.run_fast()
        runner.assert_not_called()
        naabu.assert_not_called()
        self.assertEqual(result['targets'], 1)
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (naabu)', result['skipped'])
        self.assertNothingRecorded('nmap-fast', 'naabu')
        self.assertFalse(ledger.fresh('nmap-fast', [IP], self.project.id))
        self.assertNamesTheScanner('naabu')

    def test_when_only_naabu_can_be_reached_nmap_itself_waits(self):
        self.make_sentinel(['naabu'])
        answer = {'outcome': 'done', 'ports': {IP: [443]}}
        runner = mock.Mock(return_value='<nmaprun/>')
        from tests.test_sentinel_dispatch import _answer_queued_task
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(answer)):
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
        runner.assert_not_called()
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nmap)', result['skipped'])
        self.assertNothingRecorded('nmap-fast')
        self.assertNamesTheScanner('nmap')

    def test_the_activity_line_is_settled_not_left_running_and_not_failed(self):
        self.run_fast()
        running = AgentActivity.objects.filter(kind='run_check', message__icontains='nmap')
        self.assertTrue(running.exists())
        self.assertFalse(running.filter(status__in=('running', 'failed')).exists())

    def test_the_claim_is_released_so_another_scan_can_take_the_addresses(self):
        self.run_fast()
        with ledger.claim_many(f'nmap-fast@{self.project.id}', [IP]) as won:
            self.assertEqual(list(won), [IP])

    def test_a_genuine_tool_failure_still_records_failed_exactly_as_before(self):
        with mock.patch.dict(os.environ, {ENV: 'nmap,naabu'}):  # nmap may run here, so the runner is reached and breaks
            runner = mock.Mock(side_effect=RuntimeError('nmap exploded'))
            with mock.patch('cveFeed.naabu_scan.naabu_path', return_value=None):
                result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
        self.assertEqual(result['error'], 'nmap exploded')
        self.assertEqual(list(ServiceRun.objects.filter(service='nmap-fast').values_list('status', flat=True)), ['failed'])

    def test_by_default_nothing_changes_and_a_missing_scanner_runs_the_local_tool(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV, None)
            runner = mock.Mock(return_value='<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>')
            with mock.patch('cveFeed.naabu_scan.naabu_path', return_value=None):
                result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
        runner.assert_called_once()
        self.assertNotIn('skipped', result)
        self.assertEqual(list(ServiceRun.objects.filter(service='nmap-fast').values_list('status', flat=True)), ['done'])


class NaabuDiscoverTests(FallbackOffBase):
    def test_a_runner_no_scanner_could_serve_returns_none_without_a_failed_row(self):
        self.make_sentinel(['naabu'])  # live, but nobody claims the task in time
        local = mock.Mock(return_value={})
        with mock.patch('cveFeed.naabu_scan.run_naabu', local), mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            runner = dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)
            self.assertIsNone(naabu_scan.discover([IP], self.scan, runner))
        local.assert_not_called()
        self.assertNothingRecorded('naabu')
        self.assertNamesTheScanner('naabu')

    def test_the_runner_raising_scanner_unavailable_directly_is_the_same(self):
        runner = mock.Mock(side_effect=resources.ScannerUnavailable('naabu', 'no Sentinel is live for this project'))
        with mock.patch('cveFeed.naabu_scan.run_naabu') as local:
            self.assertIsNone(naabu_scan.discover([IP], self.scan, runner))
        local.assert_not_called()
        runner.assert_called_once()
        self.assertNothingRecorded('naabu')
        self.assertNamesTheScanner('naabu')

    def test_the_claim_is_released_when_it_waits(self):
        naabu_scan.discover([IP], self.scan, mock.Mock(side_effect=resources.ScannerUnavailable('naabu')))
        with ledger.claim_many(f'{naabu_scan.SERVICE}@{self.project.id}', [IP]) as won:
            self.assertEqual(list(won), [IP])

    def test_a_genuine_naabu_failure_still_records_failed(self):
        self.assertIsNone(naabu_scan.discover([IP], self.scan, mock.Mock(side_effect=RuntimeError('naabu broke'))))
        self.assertEqual(list(ServiceRun.objects.filter(service=naabu_scan.SERVICE).values_list('status', flat=True)), ['failed'])


class NucleiStageTests(FallbackOffBase):
    def test_light_pass_waits_and_runs_no_local_nuclei(self):
        local = mock.Mock(return_value=iter(()))
        with mock.patch('cveFeed.nuclei_scan.stream_nuclei', local), mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            self.make_sentinel(['nuclei_light'])
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', timeout=5)
            result = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        local.assert_not_called()
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nuclei_light)', result['skipped'])
        self.assertEqual((result['technologies'], result['hosts']), (0, 0))
        self.assertNothingRecorded('nuclei-light')
        self.assertNamesTheScanner('nuclei_light')

    def test_targeted_pass_waits_and_runs_no_local_nuclei(self):
        local = mock.Mock(return_value=iter(()))
        cve_runner = mock.Mock()
        sub = Subdomain.objects.get(scan_history=self.scan, name='www.example.test')
        sub.technologies.add(Technology.objects.create(name='WordPress'))
        with mock.patch('cveFeed.nuclei_scan.stream_nuclei', local), mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            self.make_sentinel(['nuclei_targeted'])
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_targeted', timeout=5)
            result = nuclei_scan.run_targeted_nuclei(self.scan.id, stream=stream, provider=None, cve_runner=cve_runner,
                                                     light_techs={'www.example.test': ['WordPress']})
        local.assert_not_called()
        self.assertGreaterEqual(result['groups'], 1, 'the fixture must form a group, or this proves nothing')
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nuclei_targeted)', result['skipped'])
        self.assertEqual((result['targets'], result['findings']), (0, 0))
        self.assertNothingRecorded('nuclei')
        self.assertNamesTheScanner('nuclei_targeted')

    def test_a_pass_that_waits_halfway_keeps_what_it_finished_and_leaves_the_rest_due(self):
        targets = [f'h{i}.example.test' for i in range(nuclei_scan.NUCLEI_CHUNK + 1)]

        def stream(path, **kwargs):
            if open(path).read().split() == targets[:nuclei_scan.NUCLEI_CHUNK]:
                return iter(())
            raise resources.ScannerUnavailable('nuclei_targeted', 'no Sentinel is live for this project')
        result = nuclei_scan._run_nuclei(self.scan.id, stream=stream, targets=targets, service_override='nuclei-half')
        self.assertIn('the 1 target stays due', result['skipped'])
        done = set(ServiceRun.objects.filter(service='nuclei-half', status='done').values_list('asset', flat=True))
        self.assertEqual(done, set(targets[:nuclei_scan.NUCLEI_CHUNK]))
        self.assertFalse(ServiceRun.objects.filter(service='nuclei-half', asset=targets[-1]).exists())
        self.assertFalse(ServiceRun.objects.filter(status='failed').exists())

    def test_a_genuine_nuclei_failure_still_records_failed(self):
        def broken(path, **kwargs):
            raise RuntimeError('nuclei crashed')
        light = nuclei_scan.run_light_nuclei(self.scan.id, stream=broken)
        self.assertEqual(light['error'], 'nuclei crashed')
        targeted = nuclei_scan._run_nuclei(self.scan.id, stream=broken, targets=['www.example.test'], service_override='nuclei-broken')
        self.assertEqual(targeted['error'], 'nuclei crashed')
        self.assertEqual(set(ServiceRun.objects.values_list('service', 'status')), {('nuclei-light', 'failed'), ('nuclei-broken', 'failed')})

    def test_the_weekly_deep_pass_waits_too_and_does_not_mark_the_host_checked(self):
        from cveFeed.tasks import weekly_deep_nuclei
        sub = Subdomain.objects.get(scan_history=self.scan, name='www.example.test')
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=2)  # weekly_deep_nuclei reads finished scans only
        Subdomain.objects.filter(pk=sub.pk).update(target_domain=self.domain)
        local = mock.Mock(return_value=iter(()))
        with mock.patch('cveFeed.nuclei_scan.approved_templates', return_value=('/tmp/approved', 'rev1', 1)), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, **kw: names), \
                mock.patch('cveFeed.nuclei_scan.scan_targets', return_value=({sub.name}, set(), set())), \
                mock.patch('cveFeed.nuclei_scan.stream_nuclei', local):
            result = weekly_deep_nuclei()
        local.assert_not_called()
        self.assertEqual((result['status'], result['host']), ('skipped', sub.name))
        self.assertIn('no scanner could take this work (nuclei_deep)', result['skipped'])
        self.assertNothingRecorded('nuclei-deep')
        self.assertNamesTheScanner('nuclei_deep')
        self.assertTrue(BackgroundCursor.objects.filter(lane='weekly_nuclei').exists())


class PipelineStageTests(FallbackOffBase):
    """No Sentinel is live at all, so the wrappers themselves raise before any stage body runs: the pipeline's own stage rows are not failed."""

    def test_the_nmap_nuclei_and_wpscan_stages_are_not_marked_failed(self):
        nmap_runner, naabu, wpscan = mock.Mock(), mock.Mock(), mock.Mock()
        local_nuclei = mock.Mock(return_value=iter(()))
        scan = self.scan
        Subdomain.objects.filter(scan_history=scan).update(target_domain=self.domain)
        Subdomain.objects.get(scan_history=scan).technologies.add(Technology.objects.create(name='WordPress'))  # a site for WPScan to wait on
        with mock.patch('cveFeed.discovery.stopped', return_value=False), mock.patch('cveFeed.naabu_scan.run_naabu', naabu), \
                mock.patch('cveFeed.wpscan_scan.run_wpscan_process', wpscan), mock.patch('cveFeed.nuclei_scan.stream_nuclei', local_nuclei):
            out = discovery._run_stages(
                scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False, nmap_runner=nmap_runner, db_exposure_checks={}, provider=None,
                route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''},
                probe_get=lambda url: {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '',
                                       'content_type': '', 'final_url': url, 'url': url})
        for tool in (nmap_runner, naabu, wpscan, local_nuclei):
            tool.assert_not_called()
        rows = {row.name: row.status for row in ScanActivity.objects.filter(scan_of=scan)}
        for name in ('nmap_scan', 'nuclei_light_scan', 'nuclei_targeted_scan', 'wpscan'):
            self.assertEqual(rows[name], discovery.SUCCESS, f'{name}: {rows}')
        self.assertEqual(out['failed_stages'], [])
        self.assertNothingRecorded('nmap-fast', 'naabu', 'nuclei', 'wpscan')
        self.assertTrue(any('nuclei' in m.lower() and 'no scanner could take this work' in m for m, _s in self.waiting_lines()))
        self.assertTrue(any(m.startswith('WPScan') for m, _s in self.waiting_lines()))
        for message, _status in self.waiting_lines():
            self.assertNotIn('memory', message.lower())


class TestsslTests(WaitsMixin, RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',), ports=((443, 'https'),))
        for patcher in (mock.patch.dict(os.environ, {ENV: 'none'}, clear=False), mock.patch('reNgine.resources.global_pause_requested', return_value=False)):
            patcher.start()
        self.addCleanup(mock.patch.stopall)

    def test_the_sweep_waits_names_the_scanner_and_records_nothing(self):
        runner = mock.Mock()
        out = testssl_scan.sweep(self.project.id, runner=runner, resolve=lambda host, port, project: '203.0.113.5')
        runner.assert_not_called()
        self.assertIn('no scanner could take this work (testssl)', out['skipped'])
        self.assertNotIn('memory', out['skipped'])
        self.assertEqual((out['tested'], out['failed']), (0, 0))
        self.assertNothingRecorded('testssl')
        self.assertNamesTheScanner('testssl')

    def test_a_real_memory_wait_keeps_the_memory_wording(self):
        with mock.patch('agentapi.sentinel_dispatch.try_testssl', side_effect=resources.MemoryBusy('waited too long for memory')):
            out = testssl_scan.sweep(self.project.id, runner=mock.Mock(), resolve=lambda host, port, project: '203.0.113.5')
        self.assertIn('memory was short', out['skipped'])
        self.assertNothingRecorded('testssl')

    def test_by_default_the_local_runner_still_runs(self):
        import json

        def runner(args, env, timeout):
            with open(args[args.index('--jsonfile') + 1], 'w') as handle:
                json.dump(CLEAN, handle)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV, None)
            out = testssl_scan.sweep(self.project.id, runner=runner, resolve=lambda host, port, project: '203.0.113.5')
        self.assertEqual(out['tested'], 1)


class UdpTests(WaitsMixin, UdpBase):
    def setUp(self):
        super().setUp()
        mock.patch.dict(os.environ, {ENV: 'none'}, clear=False).start()

    def test_the_sweep_waits_names_the_scanner_and_runs_no_local_nmap(self):
        ip = self.ip(IP, name='edge.udp.test')
        local = mock.Mock(return_value='')
        out = udp_scan.run(runner=local)
        local.assert_not_called()
        self.assertEqual(out['scanned'], [{'ip': IP, 'ok': False, 'error': 'ScannerUnavailable', 'waiting': True}])
        self.assertNothingRecorded('udp-scan')
        self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))
        self.assertNamesTheScanner('nmap_udp')

    def test_a_firing_does_not_ask_the_same_address_again_and_stops_after_a_few(self):
        for n in range(1, 7):
            self.ip(f'192.0.2.{n}', name=f'h{n}.udp.test')
        local = mock.Mock(return_value='')
        out = udp_scan.run(runner=local)
        local.assert_not_called()
        asked = [row['ip'] for row in out['scanned']]
        self.assertEqual(len(asked), udp_scan.MAX_WAITING)
        self.assertEqual(len(set(asked)), udp_scan.MAX_WAITING)  # never the same address twice in one firing

    def test_a_real_memory_wait_is_still_a_failed_line_with_no_failed_row(self):
        ip = self.ip(IP, name='edge.udp.test')
        with mock.patch.dict(os.environ, {ENV: 'all'}):  # the local run is allowed, so it is reached and its memory gate gives up
            out = udp_scan.scan_ip(ip, runner=mock.Mock(side_effect=resources.MemoryBusy('waited too long for memory')))
        self.assertEqual(out, {'ip': IP, 'ok': False, 'error': 'MemoryBusy'})
        self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))


class WpscanTests(WaitsMixin, RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'plain.rt.test'))
        self.wp = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        self.wp.technologies.add(Technology.objects.create(name='WordPress'))
        mock.patch.dict(os.environ, {ENV: 'none'}, clear=False).start()
        self.addCleanup(mock.patch.stopall)

    def go(self, **kw):
        kw.setdefault('probe_get', lambda url: {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '',
                                                'content_type': '', 'final_url': url, 'url': url})
        kw.setdefault('sleep', lambda s: None)
        return wpscan_scan.run_wpscan(self.scan_obj.id, **kw)

    def test_with_no_sentinel_the_stage_waits_and_runs_no_local_wpscan(self):
        local = mock.Mock(return_value=REPORT)
        with mock.patch('cveFeed.wpscan_scan.run_wpscan_process', local):
            out = self.go()
        local.assert_not_called()
        self.assertNotIn('error', out)
        self.assertIn('no scanner could take this work (wpscan)', out['skipped'])
        self.assertNothingRecorded('wpscan')
        self.assertNamesTheScanner('wpscan')

    def test_with_a_sentinel_nobody_claims_the_site_is_waiting_not_failed(self):
        from django.contrib.auth.models import User

        from agentapi.auth import create_token
        from agentapi.models import Agent
        user = User.objects.create_user('wpscan-wait-owner', password='x')
        token, _raw = create_token(user, 'wpscan-wait-token')
        Agent.objects.create(token=token, name='live-wpscan-sentinel', kind='scanner', status='active',
                             scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, capabilities=['wpscan'], last_seen=timezone.now())
        local = mock.Mock(return_value=REPORT)
        with mock.patch('cveFeed.wpscan_scan.run_wpscan_process', local), mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2), \
                mock.patch('cveFeed.wpscan_scan.queue_quick', return_value=[]):  # the retry job would go to the real broker
            out = self.go()
        local.assert_not_called()
        self.assertNotIn('error', out)
        self.assertEqual(out['scanned'], 0)
        self.assertNothingRecorded('wpscan')
        from cveFeed.models import ProbeObservation
        state = wpscan_scan.state_of(list(ProbeObservation.objects.filter(host='www.rt.test')))
        self.assertEqual(state['state'], 'waiting')
        self.assertIn('no scanner could take this work (wpscan)', state['reason'])
        self.assertNotIn('memory', state['reason'])
        message = AgentActivity.objects.filter(message__startswith='WPScan finished').latest('id').message
        self.assertIn('no scanner could take the remaining sites (wpscan)', message)
        self.assertNotIn('memory', message)


class PerformanceReviewTests(SimpleTestCase):
    def test_work_waiting_for_a_scanner_is_never_a_capacity_failure(self):
        for text in ('no scanner could run nmap work: the Sentinel reported it failed: timed out; it stays due until one can',
                     'no scanner could run nuclei_light work: the queue did not return a result in time; it stays due until one can',
                     'no scanner could take this work (nmap); the targets stay due until one can'):
            self.assertEqual(performance_review.failure_cause(text), 'other', text)
        self.assertEqual(performance_review.failure_cause('nmap on 1 address waited too long for memory (10 MB free)'), 'capacity')


class MemoryPressureResponseTests(SimpleTestCase):
    def test_the_error_is_a_memory_busy_for_waiting_but_carries_its_kind_for_the_wording(self):
        error = resources.ScannerUnavailable('nmap', 'no Sentinel is live for this project')
        self.assertIsInstance(error, resources.MemoryBusy)
        self.assertNotIsInstance(error, resources.MemoryKill)  # the one a memory-pressure retry reacts to
        self.assertNotIn('memory', str(error).lower())
        self.assertEqual(error.kind, 'nmap')

    def test_the_memory_retries_of_nmap_and_nuclei_do_not_catch_it(self):
        # nmap's chunk halving and nuclei's lighter profile react to MemoryKill (the container ran low), which it is not: it propagates to the stage
        runner = mock.Mock(side_effect=resources.ScannerUnavailable('nmap'))
        with self.assertRaises(resources.ScannerUnavailable):
            nmap_scan.scan_in_chunks(runner, ['192.0.2.1'] * 8, [], '5m', size=8)
        runner.assert_called_once()  # not halved and retried
