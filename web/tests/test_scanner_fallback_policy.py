"""``CVENGINE_LOCAL_FALLBACK``: which task kinds may still run on this server when no Sentinel takes them. Unset means every kind, exactly as
before; a kind taken off the list is never run here and its stage waits (``ScannerUnavailable``) instead."""
from unittest import mock

from django.test import SimpleTestCase

from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from reNgine import resources
from tests.test_sentinel_dispatch import DispatchBase, _answer_queued_task

ENV = dispatch.LOCAL_FALLBACK_ENV


class PolicyParsingTests(SimpleTestCase):
    def kinds(self, value):
        with mock.patch.dict('os.environ', {ENV: value} if value is not None else {}, clear=False):
            if value is None:
                import os
                os.environ.pop(ENV, None)
            return dispatch.local_fallback_kinds()

    def test_unset_empty_all_and_star_allow_every_kind(self):
        for value in (None, '', 'all', '*', 'ALL', ' all '):
            self.assertEqual(self.kinds(value), set(SentinelTask.KINDS), repr(value))

    def test_none_allows_no_kind(self):
        self.assertEqual(self.kinds('none'), set())

    def test_a_list_allows_exactly_its_kinds_and_ignores_unknown_ones(self):
        self.assertEqual(self.kinds('nmap, naabu'), {'nmap', 'naabu'})
        self.assertEqual(self.kinds('nmap,telnet,'), {'nmap'})

    def test_the_scanner_unavailable_error_is_a_memory_busy_so_stages_leave_the_work_due(self):
        error = resources.ScannerUnavailable('nmap', 'no Sentinel is live')
        self.assertIsInstance(error, resources.MemoryBusy)
        self.assertEqual(error.kind, 'nmap')
        self.assertIn('stays due', str(error))


class DispatchPolicyTests(DispatchBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict('os.environ', {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        import os
        os.environ.pop(ENV, None)

    def set_policy(self, value):
        import os
        os.environ[ENV] = value

    def test_by_default_no_sentinel_means_none_so_the_caller_runs_it_locally(self):
        self.assertIsNone(dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10']))

    def test_with_no_local_fallback_no_sentinel_raises_and_creates_no_task(self):
        self.set_policy('none')
        with self.assertRaises(resources.ScannerUnavailable) as caught:
            dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'])
        self.assertEqual(caught.exception.kind, 'nmap')
        self.assertFalse(SentinelTask.objects.exists())

    def test_only_the_kinds_taken_off_the_list_raise(self):
        self.set_policy('nmap')  # nmap may still run here; everything else may not
        self.assertIsNone(dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10']))
        with self.assertRaises(resources.ScannerUnavailable):
            dispatch.dispatch_or_none(self.project, 'naabu', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'])

    def test_an_internal_task_is_unchanged_it_never_had_a_local_run(self):
        self.set_policy('none')
        self.assertIsNone(dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], internal=True))

    def test_a_task_nobody_claims_raises_instead_of_running_locally(self):
        self.set_policy('none')
        self.make_sentinel(['nmap'])
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            with self.assertRaises(resources.ScannerUnavailable):
                dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], timeout=5)
        self.assertEqual(SentinelTask.objects.get().status, 'expired')

    def test_a_task_the_sentinel_reports_failed_raises_instead_of_running_locally(self):
        self.set_policy('none')
        self.make_sentinel(['nmap'])
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'error': 'boom'}, status='failed')):
            with self.assertRaises(resources.ScannerUnavailable):
                dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], timeout=5)

    def test_a_task_the_sentinel_answers_is_returned_whatever_the_policy(self):
        self.set_policy('none')
        self.make_sentinel(['nmap'])
        result = {'outcome': 'done', 'hosts': []}
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            self.assertEqual(dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], timeout=5), result)


class WrapperPolicyTests(DispatchBase):
    """With no Sentinel for the project every wrapper used to hand the work back to a local run; under ``none`` each says it must wait."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict('os.environ', {ENV: 'none'}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_wrapper_waits_when_no_sentinel_is_live(self):
        calls = {
            'nmap': lambda: dispatch.try_nmap(self.project, self.scan, ['192.0.2.10']),
            'testssl': lambda: dispatch.try_testssl(self.project, 'www.example.test', '192.0.2.10', 443),
            'nmap_udp': lambda: dispatch.try_nmap_udp(self.project, '192.0.2.10'),
            'naabu': lambda: dispatch.wrap_naabu_runner(self.project, self.scan),
            'nuclei_light': lambda: dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light'),
            'wpscan': lambda: dispatch.wrap_wpscan_runner(self.project, scan=self.scan),
        }
        for kind, call in calls.items():
            with self.subTest(kind=kind):
                with self.assertRaises(resources.ScannerUnavailable) as caught:
                    call()
                self.assertEqual(caught.exception.kind, kind)

    def test_the_wrappers_still_hand_back_to_a_local_run_by_default(self):
        with mock.patch.dict('os.environ', {ENV: 'all'}):
            self.assertEqual(dispatch.try_nmap(self.project, self.scan, ['192.0.2.10'])[0], ['192.0.2.10'])
            self.assertIsNone(dispatch.try_testssl(self.project, 'www.example.test', '192.0.2.10', 443))
            self.assertIsNone(dispatch.try_nmap_udp(self.project, '192.0.2.10'))
            self.assertIsNone(dispatch.wrap_naabu_runner(self.project, self.scan))

    def test_naabu_never_runs_the_remainder_beyond_one_task_locally(self):
        self.make_sentinel(['naabu'])
        many = [f'192.0.2.{i}' for i in range(1, dispatch.MAX_ADDRESSES + 5)]
        local = mock.Mock(return_value={})
        result = {'outcome': 'done', 'ports': {}}
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)), \
                mock.patch('cveFeed.naabu_scan.run_naabu', local):
            runner = dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)
            with self.assertRaises(resources.ScannerUnavailable):
                runner(many)
        local.assert_not_called()

    def test_nuclei_does_not_run_unresolvable_targets_locally(self):
        self.make_sentinel(['nuclei_light'])
        local = mock.Mock(return_value=iter(()))
        with mock.patch('cveFeed.nuclei_scan.stream_nuclei', local), \
                mock.patch('agentapi.sentinel_dispatch.resolvable_targets', return_value=[]), \
                mock.patch('agentapi.sentinel_dispatch.any_scanner_for', return_value=True):
            import tempfile
            with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
                handle.write('nothing.invalid\n')
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
            self.assertEqual(list(stream(handle.name)), [])
        local.assert_not_called()
