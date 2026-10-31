"""The fake built-in Sentinel (``tests/fake_scanner.py``): its own behaviour, and one end-to-end test per dispatchable kind.

Part one tests the harness: it serves a task through the real broker with the contract fixture, fails, times out, stays silent or goes offline on
request, and its guards trip. Part two is the pattern every phase 5 delete PR copies (docs/SCANNER-ARCHITECTURE.md, risk 7): with
``CVENGINE_LOCAL_FALLBACK=none`` and ``assert_ran_nowhere_locally`` armed, the real stage entry point runs against a live fake scanner that serves the
kind's result, and the test asserts what the stage stored; then again with the fake offline, where the stage must wait, fail nothing and leave its
target due. The stages are the ones ``tests/test_scanner_unavailable_stages.py`` already drives, with its fixtures.

Entry points: nmap ``nmap_scan.run_nmap_for_scan`` (which dispatches naabu and nmap itself), naabu ``naabu_scan.discover`` with
``wrap_naabu_runner`` (the runner the nmap stage builds), nuclei light and targeted ``nuclei_scan.run_light_nuclei`` / ``run_targeted_nuclei`` with
``wrap_nuclei_stream`` (what ``discovery._run_stages`` passes them), nuclei deep ``tasks.weekly_deep_nuclei`` (which wraps its own stream),
testssl ``testssl_scan.sweep``, nmap -sU ``udp_scan.run`` / ``scan_ip``, wpscan ``wpscan_scan.run_wpscan`` (which wraps its own runner)."""
import os
import time
from unittest import mock

from django.test import TestCase

from agentapi import scanner_state, sentinel_broker
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from cveFeed import discovery, ledger, naabu_scan, nmap_scan, nuclei_scan, testssl_scan, udp_scan, wpscan_scan
from cveFeed.models import ProbeObservation, ServiceRun
from reNgine import resources
from startScan.models import IpAddress, ScanHistory, Subdomain, Technology, Vulnerability
from tests import fake_scanner as fs
from tests.fake_scanner import FakeScanner, LocalFallback, LocalRunDetected, assert_ran_nowhere_locally, fixture, for_host
from tests.test_route_auth import RouteFixture
from tests.test_scanner_unavailable_stages import ENV, IP, FallbackOffBase, WaitsMixin
from tests.test_sentinel_dispatch import UDP_XML, DispatchBase
from tests.test_testssl_scan import CLEAN
from tests.test_udp_scan import UdpBase

HOST = 'www.example.test'


class NoRealSleep:
    """A test that waits on a fake scanner never sleeps for real: nothing may call ``time.sleep`` with more than a blink."""

    def no_real_sleep(self):
        patcher = mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real'))
        patcher.start()
        self.addCleanup(patcher.stop)


# ============================================================================== the harness itself

class HarnessServeTests(NoRealSleep, DispatchBase):
    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.no_real_sleep()

    def dispatch(self, kind='nmap', target=None, ips=('192.0.2.10',), **kwargs):
        return dispatch.dispatch_or_none(self.project, kind, target or {'addresses': list(ips)}, ips=list(ips), scan=self.scan, **kwargs)

    def test_it_registers_the_built_in_scanner_live_with_the_chosen_kinds_and_contract(self):
        with FakeScanner(kinds=['nmap', 'testssl'], contract_version=1) as fake:
            agent = fake.agent
            self.assertEqual((agent.kind, agent.status), ('scanner', 'active'))
            self.assertTrue(sentinel_broker.is_builtin(agent))
            self.assertTrue(agent.scope['instance'])
            self.assertEqual(agent.capabilities, ['nmap', 'testssl'])
            self.assertEqual(agent.info['contract_version'], 1)
            self.assertTrue(sentinel_broker.any_scanner_for(self.project, 'nmap'))
            self.assertFalse(sentinel_broker.any_scanner_for(self.project, 'naabu'))  # a kind it did not declare
        self.assertIs(dispatch.time, time)  # nothing leaks out of the block: the dispatcher's own clock and the environment are back
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', os.environ)

    def test_a_task_is_served_through_claim_accept_and_report_with_the_contract_fixture(self):
        with FakeScanner(kinds=['nmap']) as fake:
            result = self.dispatch('nmap')
        self.assertEqual(result, {**fixture('nmap'), 'hosts': result['hosts']})  # clean_result rebuilds the host rows; the outcome and fields are the fixture's
        self.assertEqual(result['hosts'][0]['ip'], '192.0.2.10')
        self.assertEqual(result['hosts'][0]['ports'][0]['product'], 'OpenSSH')
        task = SentinelTask.objects.get(kind='nmap')
        self.assertEqual((task.status, task.agent_id, task.attempts), ('done', fake.agent.pk, 1))
        self.assertIsNotNone(task.accepted_at)  # accept_task ran, not a shortcut from claimed to done
        self.assertEqual(fake.served_kinds(), ['nmap'])
        self.assertEqual(fake.served[0]['target'], {'addresses': ['192.0.2.10']})

    def test_a_task_the_fake_does_not_declare_is_never_served(self):
        with FakeScanner(kinds=['naabu']) as fake:
            self.assertFalse(dispatch.any_scanner_for(self.project, 'nmap'))
            with self.assertRaises(resources.ScannerUnavailable):
                self.dispatch('nmap')
        self.assertEqual(fake.served, [])
        self.assertFalse(SentinelTask.objects.exists())

    def test_a_responder_replaces_the_fixture_and_sees_the_task(self):
        seen = []

        def responder(task):
            seen.append(task)
            return {'outcome': 'done', 'hosts': [{'ip': '192.0.2.10', 'os_guess': 'Plan 9', 'ports': []}]}
        with FakeScanner(kinds=['nmap', 'naabu'], responders={'nmap': responder, 'naabu': {'outcome': 'done', 'ports': {'192.0.2.10': [80]}}}):
            self.assertEqual(self.dispatch('nmap')['hosts'][0]['os_guess'], 'Plan 9')
            self.assertEqual(self.dispatch('naabu')['ports'], {'192.0.2.10': [80]})  # a plain dict is a responder too
        self.assertEqual((seen[0]['kind'], seen[0]['target']), ('nmap', {'addresses': ['192.0.2.10']}))
        self.assertTrue(seen[0]['trace_id'])

    def test_every_kind_with_a_fixture_is_served_a_result_the_broker_accepts(self):
        # the default fixture of each kind passes the real clean_result: the fake cannot drift from the contract unnoticed
        targets = {'nmap': {'addresses': ['192.0.2.10']}, 'naabu': {'addresses': ['192.0.2.10']}, 'testssl': fixture_target('testssl'),
                   'nmap_udp': {'address': '192.0.2.10'}, 'wpscan': fixture_target('wpscan'),
                   'nuclei_light': {'targets': [HOST]}, 'nuclei_targeted': {'targets': [HOST]}, 'nuclei_deep': {'targets': [HOST]}}
        with FakeScanner(kinds=list(targets)) as fake:
            for kind, target in targets.items():
                result = self.dispatch(kind, target)
                self.assertEqual(result['outcome'], 'done', kind)
        self.assertEqual(sorted(fake.served_kinds()), sorted(targets))
        self.assertEqual(set(SentinelTask.objects.values_list('status', flat=True)), {'done'})

    def test_an_older_contract_version_is_served_its_frozen_fixture(self):
        with FakeScanner(kinds=['nmap'], contract_version=1) as fake:
            self.assertEqual(fake.result_for({'kind': 'nmap'}), fixture('nmap', version=1))
        self.assertTrue((fs.FIXTURES / 'v1' / 'nmap.json').exists())

    def test_a_result_that_breaks_the_contract_fails_like_it_would_for_a_real_sentinel_and_is_not_hidden(self):
        fake = FakeScanner(kinds=['nmap'], responders={'nmap': {'outcome': 'done', 'hosts': 'not a list'}})
        with self.assertRaises(AssertionError) as caught:
            with fake:
                with self.assertRaises(Exception):  # the stage's own handling would swallow it: the dispatch call raises here only because of the serve
                    self.dispatch('nmap')
        self.assertIn('could not serve a task', str(caught.exception))
        self.assertEqual(SentinelTask.objects.get(kind='nmap').status, 'failed')


def fixture_target(kind):
    import json
    return json.loads((fs.FIXTURES.parent / 'sentinel_targets' / f'{kind}.json').read_text())


class HarnessModeTests(NoRealSleep, DispatchBase):
    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.no_real_sleep()

    def go(self, kind='nmap'):
        return dispatch.dispatch_or_none(self.project, kind, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], scan=self.scan)

    def test_fail_reports_an_error_so_the_task_ends_failed_and_the_stage_must_wait(self):
        with FakeScanner(kinds=['nmap'], mode='fail', error='nmap exited with status 1') as fake:
            with self.assertRaises(resources.ScannerUnavailable) as caught:
                self.go()
        task = SentinelTask.objects.get(kind='nmap')
        self.assertEqual((task.status, task.agent_id), ('failed', fake.agent.pk))
        self.assertIn('nmap exited with status 1', task.error)
        self.assertIn('the Sentinel reported it failed', str(caught.exception))

    def test_fail_where_local_is_allowed_returns_none_so_the_stage_falls_back(self):
        with LocalFallback('nmap'), FakeScanner(kinds=['nmap'], mode='fail'):
            self.assertIsNone(self.go())
        self.assertEqual(SentinelTask.objects.get(kind='nmap').status, 'failed')

    def test_timeout_claims_and_never_reports_so_the_task_expires_and_the_stage_must_wait(self):
        started = time.monotonic()
        with FakeScanner(kinds=['nmap'], mode='timeout') as fake:
            with self.assertRaises(resources.ScannerUnavailable) as caught:
                self.go()
        self.assertLess(time.monotonic() - started, 1.0)  # the 1 second budget ran on the virtual clock
        task = SentinelTask.objects.get(kind='nmap')
        self.assertEqual(task.status, 'expired')
        self.assertEqual(task.agent_id, None)  # expiry hands the task back
        self.assertEqual(fake.served[0]['mode'], 'timeout')
        self.assertIsNone(fake.served[0]['result'])
        self.assertIn('did not return a result in time', str(caught.exception))

    def test_idle_is_live_but_never_claims(self):
        with FakeScanner(kinds=['nmap'], mode='idle') as fake:
            self.assertTrue(dispatch.any_scanner_for(self.project, 'nmap'))
            with self.assertRaises(resources.ScannerUnavailable):
                self.go()
        task = SentinelTask.objects.get(kind='nmap')
        self.assertEqual((task.status, task.attempts), ('expired', 0))
        self.assertEqual(fake.served, [])

    def test_a_mode_can_be_set_for_one_kind_only(self):
        with FakeScanner(kinds=['nmap', 'naabu'], modes={'nmap': 'fail'}):
            self.assertEqual(self.go('naabu')['outcome'], 'done')
            with self.assertRaises(resources.ScannerUnavailable):
                self.go('nmap')

    def test_offline_means_no_dispatch_is_attempted_and_the_kind_is_waiting(self):
        with FakeScanner(kinds=['nmap'], mode='offline') as fake:
            self.assertFalse(dispatch.any_scanner_for(self.project, 'nmap'))
            with self.assertRaises(resources.ScannerUnavailable) as caught:
                self.go()
            self.assertEqual(caught.exception.kind, 'nmap')
            self.assertFalse(SentinelTask.objects.exists())  # not even a row
            self.assertIn('nmap', scanner_state.waiting_kinds())
            self.assertEqual(fake.served, [])

    def test_a_fake_that_goes_offline_and_comes_back_serves_again(self):
        with FakeScanner(kinds=['nmap']) as fake:
            self.assertEqual(self.go()['outcome'], 'done')
            fake.go_offline()
            with self.assertRaises(resources.ScannerUnavailable):
                self.go()
            self.assertIn('nmap', scanner_state.waiting_kinds())
            fake.go_online()
            self.assertEqual(self.go()['outcome'], 'done')
            self.assertNotIn('nmap', scanner_state.waiting_kinds())
        self.assertEqual(list(SentinelTask.objects.order_by('id').values_list('status', flat=True)), ['done', 'done'])


class HarnessGuardTests(TestCase):
    def guarded(self, kind):
        class Case:
            cleanups = []

            def addCleanup(self, fn, *args):
                self.cleanups.append((fn, args))
        case = Case()
        case.cleanups = []
        return case, assert_ran_nowhere_locally(case, kind)

    def finish(self, case):
        failures = []
        for fn, args in reversed(case.cleanups):  # the order a TestCase runs them in
            try:
                fn(*args)
            except AssertionError as exc:
                failures.append(exc)
        return failures

    def test_a_local_run_raises_an_assertion_error_that_says_what_ran(self):
        case, guard = self.guarded('nmap')
        try:
            with self.assertRaises(AssertionError) as caught:
                nmap_scan.run_nmap_xml(['192.0.2.1'], [], '5m')
            self.assertIsInstance(caught.exception, LocalRunDetected)
            self.assertIn('nmap ran on this server', str(caught.exception))
            self.assertIn('run_nmap_xml', str(caught.exception))
            with self.assertRaises(LocalRunDetected):
                guard.runner(['192.0.2.1'], [], '5m')
            with self.assertRaises(LocalRunDetected):
                with resources.heavy_job('nmap', label='x'):
                    pass
        finally:
            failures = self.finish(case)
        self.assertEqual(len(guard.calls), 3)
        self.assertEqual(len(failures), 1, 'a run that a stage swallowed must still fail the test when it ends')

    def test_the_resource_gate_is_closed_for_the_kinds_tools_and_open_for_everything_else(self):
        from contextlib import contextmanager

        from cveFeed import heavy_process
        entered = []

        @contextmanager
        def gate(kind, *args, **kwargs):  # stands in for the real memory gate, which needs Redis
            entered.append(kind)
            yield mock.MagicMock()
        with mock.patch.object(resources, 'heavy_job', gate):
            case, guard = self.guarded('testssl')
            try:
                with self.assertRaises(LocalRunDetected):
                    heavy_process.run('testssl', ['testssl.sh', 'example.test'], 5)
                with self.assertRaises(LocalRunDetected):
                    testssl_scan.run_testssl('example.test', '192.0.2.1', 443, '')
                with resources.heavy_job('route-probe', label='x'):  # another tool's job goes through the real gate
                    pass
            finally:
                failures = self.finish(case)
        self.assertEqual(entered, ['route-probe'])
        self.assertEqual(len(guard.calls), 2)
        self.assertTrue(guard.calls[0][0].startswith('heavy_process.run'), guard.calls)
        self.assertEqual(len(failures), 1)

    def test_every_kind_has_a_local_path_and_a_gate(self):
        from agentapi.models import SentinelTask as Task
        dispatchable = set(Task.KINDS) - set(scanner_state.NO_STAGE) - {'openvas', 'discover'}
        self.assertEqual(set(fs.LOCAL_RUNNERS), dispatchable)
        self.assertEqual(set(fs.HEAVY_KINDS), dispatchable)
        with self.assertRaises(ValueError):
            assert_ran_nowhere_locally(mock.Mock(), 'nope')

    def test_local_fallback_sets_and_restores_the_environment_variable(self):
        before = os.environ.get(ENV)
        with LocalFallback('none'):
            self.assertEqual(dispatch.local_fallback_kinds(), set())
            with LocalFallback('nmap,naabu'):
                self.assertEqual(dispatch.local_fallback_kinds(), {'nmap', 'naabu'})
            with LocalFallback(None):
                self.assertIn('nmap', dispatch.local_fallback_kinds())
        self.assertEqual(os.environ.get(ENV), before)

        @LocalFallback('none')
        def decorated():
            return dispatch.fallback_allowed('nmap')
        self.assertFalse(decorated())


# ============================================================================== one stage per kind, end to end

class StageBase(NoRealSleep, WaitsMixin):
    """What every kind's end-to-end test asserts, so the tests below read as the scenario only."""

    def arm(self, *kinds):
        """The fallback is off and any local run of ``kinds`` fails the test."""
        self.guards = [assert_ran_nowhere_locally(self, kind) for kind in kinds]
        self.no_real_sleep()
        return self.guards

    def assertServed(self, fake, *kinds):
        self.assertEqual(fake.served_kinds(), list(kinds))
        for task in fake.tasks():
            self.assertEqual((task.status, task.agent_id), ('done', fake.agent.pk), task.kind)
        for guard in self.guards:
            self.assertEqual(guard.calls, [], f'{guard.kind} ran locally')

    def assertWaited(self, fake, *tasks):
        """The scanner was offline: nothing was dispatched, nothing ran here, no run is recorded as failed or done (the target stays due)."""
        self.assertEqual(fake.served, [])
        self.assertEqual(list(SentinelTask.objects.values_list('kind', flat=True)), list(tasks))
        for guard in self.guards:
            self.assertEqual(guard.calls, [], f'{guard.kind} ran locally')
        self.assertFalse(ServiceRun.objects.filter(status='failed').exists(), list(ServiceRun.objects.values_list('service', 'asset', 'status')))


class NmapServedTests(StageBase, FallbackOffBase):
    """The fast nmap stage: naabu finds the ports and nmap fingerprints them, each one a task for the scanner (``run_nmap_for_scan`` dispatches both)."""

    def test_the_scanner_serves_naabu_and_nmap_and_the_stage_stores_what_they_found(self):
        guard = self.arm('nmap', 'naabu')[0]
        with FakeScanner(kinds=['naabu', 'nmap'], responders={'naabu': fixture('naabu', ports={IP: [22]})}) as fake:
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=guard.runner)
        self.assertServed(fake, 'naabu', 'nmap')
        self.assertEqual(result, {'targets': 1, 'reused': 0, 'fast': {'ports': 1, 'hosts_with_os': 1}})
        port = IpAddress.objects.get(address=IP, org_id=self.org.id).ports.get(number=22)
        self.assertEqual((port.product, port.version, port.source), ('OpenSSH', '9.6', 'nmap'))  # the nmap fixture's host, through persist_inventory
        self.assertEqual(list(ServiceRun.objects.filter(service='nmap-fast').values_list('status', flat=True)), ['done'])
        self.assertEqual(fake.served[1]['target'], {'addresses': [IP]})

    def test_with_the_scanner_offline_the_stage_waits_and_the_address_stays_due(self):
        guard = self.arm('nmap', 'naabu')[0]
        with FakeScanner(kinds=['naabu', 'nmap'], mode='offline') as fake:
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=guard.runner)
        self.assertWaited(fake)
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (naabu)', result['skipped'])
        self.assertNothingRecorded('nmap-fast', 'naabu')
        self.assertFalse(ledger.fresh('nmap-fast', [IP], self.project.id))
        self.assertNamesTheScanner('naabu')

    def test_a_scanner_that_fails_the_nmap_task_leaves_the_address_due_not_failed(self):
        guard = self.arm('nmap', 'naabu')[0]
        with FakeScanner(kinds=['naabu', 'nmap'], modes={'nmap': 'fail'}, responders={'naabu': fixture('naabu', ports={IP: [22]})}) as fake:
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=guard.runner)
        self.assertEqual(fake.served_kinds(), ['naabu', 'nmap'])
        self.assertEqual(guard.calls, [])
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nmap)', result['skipped'])
        self.assertNothingRecorded('nmap-fast')
        self.assertFalse(ledger.fresh('nmap-fast', [IP], self.project.id))


class NaabuServedTests(StageBase, FallbackOffBase):
    """The naabu stage: ``naabu_scan.discover`` with the runner ``wrap_naabu_runner`` builds (the nmap stage passes the same one)."""

    def test_the_scanner_serves_the_fixture_and_discover_stores_the_open_ports(self):
        self.arm('naabu')
        with FakeScanner(kinds=['naabu']) as fake:
            runner = dispatch.wrap_naabu_runner(self.project, self.scan)
            found = naabu_scan.discover([IP], self.scan, runner)
        self.assertServed(fake, 'naabu')
        self.assertEqual(found, {IP: [22, 443]})  # the fixture's ports for the address asked about (its tarpit entry is another address)
        ports = IpAddress.objects.get(address=IP, org_id=self.org.id).ports
        self.assertEqual(sorted((p.number, p.source) for p in ports.all()), [(22, 'naabu'), (443, 'naabu')])
        self.assertEqual(list(ServiceRun.objects.filter(service=naabu_scan.SERVICE).values_list('status', flat=True)), ['done'])

    def test_with_the_scanner_offline_the_runner_waits_and_the_address_stays_due(self):
        self.arm('naabu')
        with FakeScanner(kinds=['naabu']) as fake:
            runner = dispatch.wrap_naabu_runner(self.project, self.scan)
            fake.go_offline()
            self.assertIsNone(naabu_scan.discover([IP], self.scan, runner))
            with self.assertRaises(resources.ScannerUnavailable):  # and building the runner while it is offline says so at once, which the nmap stage handles
                dispatch.wrap_naabu_runner(self.project, self.scan)
        self.assertWaited(fake)
        self.assertNothingRecorded('naabu')
        self.assertFalse(ledger.fresh(naabu_scan.SERVICE, [IP], self.project.id))
        self.assertNamesTheScanner('naabu')


class NucleiLightServedTests(StageBase, FallbackOffBase):
    """The technology pass: ``run_light_nuclei`` with ``wrap_nuclei_stream`` (what ``discovery._run_stages`` gives it)."""

    def test_the_scanner_serves_a_finding_and_the_pass_stores_the_technology(self):
        self.arm('nuclei_light')
        with FakeScanner(kinds=['nuclei_light'], responders={'nuclei_light': lambda task: for_host(fixture('nuclei_light'), HOST)}) as fake:
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
            result = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        self.assertServed(fake, 'nuclei_light')
        self.assertEqual((result['technologies'], result['hosts'], result['techs']), (1, 1, {HOST: ['nginx']}))
        self.assertNotIn('skipped', result)
        self.assertEqual(list(Subdomain.objects.get(scan_history=self.scan, name=HOST).technologies.values_list('name', flat=True)), ['nginx'])
        target = fake.served[0]['target']
        self.assertEqual((target['tags'], target['severities'], HOST in target['targets']), (['tech'], ['info'], True))  # the tech fingerprint, nothing broader
        self.assertEqual(set(ServiceRun.objects.filter(service='nuclei-light').values_list('asset', 'status')), {(HOST, 'done'), (IP, 'done')})  # every target of the chunk is recorded

    def test_with_the_scanner_offline_the_pass_waits_and_the_host_stays_due(self):
        self.arm('nuclei_light')
        with FakeScanner(kinds=['nuclei_light']) as fake:
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
            fake.go_offline()
            result = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        self.assertWaited(fake)
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nuclei_light)', result['skipped'])
        self.assertEqual((result['technologies'], result['hosts']), (0, 0))
        self.assertFalse(Technology.objects.exists())
        self.assertNothingRecorded('nuclei-light')
        self.assertNamesTheScanner('nuclei_light')


class NucleiTargetedServedTests(StageBase, FallbackOffBase):
    """The AI-targeted pass: ``run_targeted_nuclei`` with ``wrap_nuclei_stream``, on the fixture ``test_scanner_unavailable_stages`` uses (a WordPress host)."""

    def setUp(self):
        super().setUp()
        sub = Subdomain.objects.get(scan_history=self.scan, name=HOST)
        sub.technologies.add(Technology.objects.create(name='WordPress'))

    def run_pass(self, stream):
        return nuclei_scan.run_targeted_nuclei(self.scan.id, stream=stream, provider=None, cve_runner=mock.Mock(), light_techs={HOST: ['WordPress']})

    def test_the_scanner_serves_a_finding_and_the_pass_stores_the_vulnerability(self):
        self.arm('nuclei_targeted')
        with FakeScanner(kinds=['nuclei_targeted'], responders={'nuclei_targeted': lambda task: for_host(fixture('nuclei_targeted'), HOST)}) as fake:
            result = self.run_pass(dispatch.wrap_nuclei_stream(self.scan, 'nuclei_targeted'))
        self.assertGreaterEqual(result['groups'], 1, 'the fixture must form a group, or this proves nothing')
        self.assertServed(fake, *['nuclei_targeted'] * result['groups'])
        self.assertNotIn('error', result)
        self.assertIsInstance(result['skipped'], int)  # the count of hosts with nothing to aim at: not a scanner wait (that one is text)
        self.assertGreaterEqual(result['findings'], 1)
        vuln = Vulnerability.objects.get(scan_history=self.scan)
        self.assertEqual((vuln.name, vuln.severity), ('Tech detect', 0))
        self.assertTrue(ServiceRun.objects.filter(service__startswith='nuclei', status='done').exists())
        self.assertIn('wordpress', {tag.lower() for tag in fake.served[0]['target']['tags']})

    def test_with_the_scanner_offline_the_pass_waits_and_the_targets_stay_due(self):
        self.arm('nuclei_targeted')
        with FakeScanner(kinds=['nuclei_targeted']) as fake:
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_targeted')
            fake.go_offline()
            result = self.run_pass(stream)
        self.assertWaited(fake)
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nuclei_targeted)', result['skipped'])
        self.assertEqual((result['targets'], result['findings']), (0, 0))
        self.assertFalse(Vulnerability.objects.exists())
        self.assertNothingRecorded('nuclei')
        self.assertNamesTheScanner('nuclei_targeted')


class NucleiDeepServedTests(StageBase, FallbackOffBase):
    """The weekly deep pass: ``tasks.weekly_deep_nuclei`` wraps its own stream, so only the template library and the target scope are stubbed."""

    def setUp(self):
        super().setUp()
        from cveFeed import tasks  # noqa: F401 - imported so the celery task is registered
        self.sub = Subdomain.objects.get(scan_history=self.scan, name=HOST)
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=2)  # weekly_deep_nuclei reads finished scans only
        Subdomain.objects.filter(pk=self.sub.pk).update(target_domain=self.domain)
        for patcher in (mock.patch('cveFeed.nuclei_scan.approved_templates', return_value=('/tmp/approved', 'rev1', 1)),
                        mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, **kw: names),
                        mock.patch('cveFeed.nuclei_scan.scan_targets', return_value=({HOST}, set(), set()))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_sweep(self):
        from cveFeed.tasks import weekly_deep_nuclei
        return weekly_deep_nuclei()

    def test_the_scanner_serves_a_finding_and_the_host_is_stored_and_marked_checked(self):
        self.arm('nuclei_deep')
        with FakeScanner(kinds=['nuclei_deep'], responders={'nuclei_deep': lambda task: for_host(fixture('nuclei_deep'), HOST)}) as fake:
            result = self.run_sweep()
        self.assertServed(fake, 'nuclei_deep')
        self.assertEqual((result['status'], result['host'], result['findings']), ('done', HOST, 1))
        self.assertEqual(Vulnerability.objects.get(scan_history=self.scan).name, 'Tech detect')
        self.assertEqual(fake.served[0]['target']['targets'], [HOST])
        self.assertEqual(ledger.fresh('nuclei-deep-host:rev1', [HOST], self.project.id), {HOST})  # checked: not due for a week

    def test_with_the_scanner_offline_the_sweep_waits_and_the_host_is_not_marked_checked(self):
        self.arm('nuclei_deep')
        with FakeScanner(kinds=['nuclei_deep'], mode='offline') as fake:
            result = self.run_sweep()
        self.assertWaited(fake)
        self.assertEqual((result['status'], result['host']), ('skipped', HOST))
        self.assertIn('no scanner could take this work (nuclei_deep)', result['skipped'])
        self.assertFalse(Vulnerability.objects.exists())
        self.assertFalse(ledger.fresh('nuclei-deep-host:rev1', [HOST], self.project.id))
        self.assertNothingRecorded('nuclei-deep')
        self.assertNamesTheScanner('nuclei_deep')


class TestsslServedTests(StageBase, RouteFixture, TestCase):
    """The TLS audit: ``testssl_scan.sweep`` for the project."""

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',), ports=((443, 'https'),))
        LocalFallback('none').apply(self)
        mock.patch('reNgine.resources.global_pause_requested', return_value=False).start()

    def sweep(self, guard):
        return testssl_scan.sweep(self.project.id, runner=guard.runner, resolve=lambda host, port, project: '203.0.113.5')

    def test_the_scanner_serves_a_report_and_the_sweep_records_the_audit(self):
        guard = self.arm('testssl')[0]
        # the contract fixture is one protocol line, which testssl_scan reads as "no test ran": the scenario serves a full report (the one test_testssl_scan uses)
        report = {'outcome': 'done', 'items': CLEAN}
        with FakeScanner(kinds=['testssl'], responders={'testssl': report}) as fake:
            out = self.sweep(guard)
        self.assertServed(fake, 'testssl')
        self.assertEqual((out['tested'], out['failed']), (1, 0))
        self.assertNotIn('skipped', out)
        self.assertEqual(fake.served[0]['target'], {'host': 'www.rt.test', 'ip': '203.0.113.5', 'port': 443, 'starttls': ''})
        self.assertEqual(list(ServiceRun.objects.filter(service=testssl_scan.SERVICE).values_list('asset', 'status')), [('www.rt.test:443', 'done')])
        audit = ProbeObservation.objects.get(host='www.rt.test', probe=testssl_scan.PROBE, kind=testssl_scan.OBS_AUDIT)
        self.assertEqual((audit.outcome, audit.evidence['protocols']['TLS1_2'], audit.evidence['ip']), ('found', 'offered', '203.0.113.5'))
        self.assertTrue(ProbeObservation.objects.filter(host='www.rt.test', probe=testssl_scan.PROBE, product='heartbleed', outcome='absent').exists())

    def test_with_the_scanner_offline_the_sweep_waits_and_the_target_stays_due(self):
        guard = self.arm('testssl')[0]
        with FakeScanner(kinds=['testssl'], mode='offline') as fake:
            out = self.sweep(guard)
        self.assertWaited(fake)
        self.assertEqual((out['tested'], out['failed']), (0, 0))
        self.assertIn('no scanner is online for testssl', out['skipped'])
        self.assertFalse(ServiceRun.objects.exists())
        self.assertEqual([(host, port) for host, port, *_ in testssl_scan.due(self.project.id)], [('www.rt.test', 443)])  # still due


class UdpServedTests(StageBase, UdpBase):
    """The UDP sweep: ``udp_scan.run`` (one firing) and ``scan_ip`` (one address). The contract fixture's report names no host, so the responder serves a real one."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.ip_row = self.ip(IP, name='edge.udp.test')

    def test_the_scanner_serves_a_report_and_the_sweep_stores_the_udp_ports(self):
        guard = self.arm('nmap_udp')[0]
        with FakeScanner(kinds=['nmap_udp'], responders={'nmap_udp': {'outcome': 'done', 'xml': UDP_XML}}) as fake:
            out = udp_scan.run(runner=guard.runner)
        self.assertServed(fake, 'nmap_udp')
        self.assertEqual([(row['ip'], row['ok']) for row in out['scanned']], [(IP, True)])
        self.assertEqual({p.number: p.state for p in self.udp(self.ip_row)}, {123: 'open', 161: 'open|filtered'})
        self.assertEqual(self.udp(self.ip_row, 123).product, 'NTP')
        self.assertEqual(fake.served[0]['target'], {'address': IP})
        self.assertEqual(ServiceRun.objects.filter(service=udp_scan.SERVICE, status='done').count(), 1)

    def test_with_the_scanner_offline_the_sweep_waits_and_the_address_stays_due(self):
        guard = self.arm('nmap_udp')[0]
        with FakeScanner(kinds=['nmap_udp'], mode='offline') as fake:
            out = udp_scan.run(runner=guard.runner)
            self.assertIn('no scanner is online for nmap_udp', out['skipped'])
            self.reach_the_stage_handler()  # a stale read of the scanner's state: the address itself still waits
            again = udp_scan.scan_ip(self.ip_row, runner=guard.runner)
        self.assertWaited(fake)
        self.assertEqual(again, {'ip': IP, 'ok': False, 'error': 'ScannerUnavailable', 'waiting': True})
        self.assertFalse(self.udp(self.ip_row).exists())
        self.assertNothingRecorded('udp-scan')
        self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(self.ip_row)]))
        self.assertNamesTheScanner('nmap_udp')


class WpscanServedTests(StageBase, RouteFixture, TestCase):
    """The WPScan stage: ``wpscan_scan.run_wpscan`` builds its own runner with ``wrap_wpscan_runner``."""

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'plain.rt.test'))
        wp = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        wp.technologies.add(Technology.objects.create(name='WordPress'))
        LocalFallback('none').apply(self)
        for target in ('cveFeed.wpscan_scan.queue_quick', 'cveFeed.wpscan_scan.queue_thorough'):  # the retry and thorough jobs would go to the real broker
            mock.patch(target, return_value=[] if target.endswith('quick') else 0).start()

    def go(self):
        return wpscan_scan.run_wpscan(self.scan_obj.id, probe_get=lambda url: {
            'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '', 'content_type': '',
            'final_url': url, 'url': url}, sleep=lambda seconds: None)

    def state(self):
        return wpscan_scan.state_of(list(ProbeObservation.objects.filter(host='www.rt.test')))

    def test_the_scanner_serves_the_fixture_and_the_stage_records_the_site(self):
        self.arm('wpscan')
        with FakeScanner(kinds=['wpscan']) as fake:
            out = self.go()
        self.assertServed(fake, 'wpscan')
        self.assertNotIn('error', out)
        self.assertEqual((out['sites'], out['scanned']), (1, 1))
        state = self.state()
        self.assertEqual((state['state'], state['core']), ('scanned', '6.5'))  # the fixture's WordPress version, through the local classifier
        self.assertEqual(list(ServiceRun.objects.filter(service=wpscan_scan.SERVICE).values_list('asset', 'status')), [('www.rt.test', 'done')])
        self.assertEqual(fake.served[0]['target']['url'], 'https://www.rt.test')

    def test_with_the_scanner_offline_the_stage_waits_and_the_site_stays_due(self):
        self.arm('wpscan')
        with FakeScanner(kinds=['wpscan'], mode='offline') as fake:
            out = self.go()
        self.assertWaited(fake)
        self.assertNotIn('error', out)
        self.assertEqual(out['scanned'], 0)
        self.assertIn('no scanner could take this work (wpscan)', out['skipped'])
        self.assertNothingRecorded('wpscan')
        state = self.state()
        self.assertEqual(state['state'], 'waiting')
        self.assertIn('no scanner could take this work (wpscan)', state['reason'])
        self.assertNamesTheScanner('wpscan')


# ============================================================================== the pipeline's own stage rows

class PipelineServedTests(StageBase, FallbackOffBase):
    """``discovery._run_stages`` with the scanner offline: the stages that wrap their runner before they run (nmap, nuclei, wpscan) are not failed."""

    def test_with_the_scanner_offline_no_stage_fails_and_no_tool_runs_here(self):
        from startScan.models import ScanActivity
        self.arm('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'wpscan')
        Subdomain.objects.filter(scan_history=self.scan).update(target_domain=self.domain)
        Subdomain.objects.get(scan_history=self.scan).technologies.add(Technology.objects.create(name='WordPress'))
        with FakeScanner(mode='offline') as fake, mock.patch('cveFeed.discovery.stopped', return_value=False):
            out = discovery._run_stages(
                self.scan.id, {'scan_id': self.scan.id, 'status': discovery.SUCCESS}, hygiene=False, nmap_runner=self.guards[0].runner,
                db_exposure_checks={}, provider=None, route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''},
                probe_get=lambda url: {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '',
                                       'content_type': '', 'final_url': url, 'url': url})
        self.assertWaited(fake)
        rows = {row.name: row.status for row in ScanActivity.objects.filter(scan_of=self.scan)}
        for name in ('nmap_scan', 'nuclei_light_scan', 'nuclei_targeted_scan', 'wpscan'):
            self.assertEqual(rows[name], discovery.SUCCESS, f'{name}: {rows}')
        self.assertEqual(out['failed_stages'], [])
        self.assertNothingRecorded('nmap-fast', 'naabu', 'nuclei', 'wpscan')
