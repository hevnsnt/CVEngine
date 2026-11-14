"""No kind runs on this server (``sentinel_dispatch.NEVER_LOCAL``), and ``CVENGINE_LOCAL_FALLBACK`` is ignored since 1.4: with no Sentinel able to take the
work, or none that finished it, the stage waits (``ScannerUnavailable``) and the targets stay due. Nothing returns ``None`` for a stage to run itself."""
import os
from unittest import mock

from django.test import SimpleTestCase

from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from reNgine import resources
from tests.test_sentinel_dispatch import DispatchBase, _answer_queued_task

ENV = 'CVENGINE_LOCAL_FALLBACK'  # ignored since 1.4: every test below sets it to prove it changes nothing
KIND = 'openvas'


class NoKindRunsLocallyTests(SimpleTestCase):
    def test_every_contract_kind_is_never_local_except_the_internal_one(self):
        self.assertEqual(set(SentinelTask.KINDS) - set(dispatch.NEVER_LOCAL), {'discover'})  # discover: internal ranges, Sentinel-only by design

    def test_the_policy_machinery_is_gone(self):
        for name in ('local_fallback_kinds', 'default_fallback_kinds', 'unknown_fallback_kinds', 'fallback_allowed', 'offline_fallback', 'LOCAL_FALLBACK_ENV'):
            self.assertFalse(hasattr(dispatch, name), name)

    def test_the_scanner_unavailable_error_is_a_memory_busy_so_stages_leave_the_work_due(self):
        error = resources.ScannerUnavailable(KIND, 'no Sentinel is live')
        self.assertIsInstance(error, resources.MemoryBusy)
        self.assertEqual(error.kind, KIND)
        self.assertIn('stays due', str(error))

    def test_no_local_always_raises_whatever_the_variable_says(self):
        for value in (None, '', 'all', '*', 'none', 'openvas', 'openvas,testssl'):
            with mock.patch.dict(os.environ, {} if value is None else {ENV: value}):
                with self.assertRaises(resources.ScannerUnavailable) as caught:
                    dispatch._no_local(KIND, 'nothing took it')
                self.assertEqual(caught.exception.kind, KIND, repr(value))


class DispatchPolicyTests(DispatchBase):
    """Every value of the ignored variable gives the same answer: the stage waits."""
    VALUES = (None, 'all', 'none', 'openvas')

    def each_value(self):
        for value in self.VALUES:
            with self.subTest(value=value), mock.patch.dict(os.environ, {} if value is None else {ENV: value}):
                if value is None:
                    os.environ.pop(ENV, None)
                yield value

    def test_no_sentinel_raises_and_creates_no_task_whatever_the_variable_says(self):
        for _ in self.each_value():
            with self.assertRaises(resources.ScannerUnavailable) as caught:
                dispatch.dispatch_or_none(self.project, KIND, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'])
            self.assertEqual(caught.exception.kind, KIND)
            self.assertFalse(SentinelTask.objects.exists())

    def test_an_internal_task_is_unchanged_it_never_had_a_local_run(self):
        for _ in self.each_value():
            self.assertIsNone(dispatch.dispatch_or_none(self.project, KIND, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], internal=True))

    def test_a_task_nobody_claims_raises_instead_of_running_locally(self):
        self.make_sentinel([KIND])
        for _ in self.each_value():
            with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
                with self.assertRaises(resources.ScannerUnavailable):
                    dispatch.dispatch_or_none(self.project, KIND, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], timeout=5)
        self.assertEqual(set(SentinelTask.objects.values_list('status', flat=True)), {'expired'})

    def test_a_task_the_sentinel_reports_failed_raises_instead_of_running_locally(self):
        self.make_sentinel([KIND])
        for _ in self.each_value():
            with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'error': 'boom'}, status='failed')):
                with self.assertRaises(resources.ScannerUnavailable):
                    dispatch.dispatch_or_none(self.project, KIND, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], timeout=5)

    def test_a_task_the_sentinel_answers_is_returned_whatever_the_variable_says(self):
        self.make_sentinel([KIND])
        result = {'outcome': 'done', 'hosts': []}
        for _ in self.each_value():
            with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
                self.assertEqual(dispatch.dispatch_or_none(self.project, KIND, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], timeout=5), result)


class ActivityWordingTests(DispatchBase):
    """The activity line and the expiry reason of a task nobody took say what really happened to the work: nothing ran locally, the targets stay due."""
    STAYS_DUE = 'the targets stay due until a scanner can take the work'

    def setUp(self):
        super().setUp()
        self.make_sentinel([KIND])

    def _entries(self):
        from cveFeed.models import AgentActivity
        return list(AgentActivity.objects.filter(project=self.project).order_by('id'))

    def unclaimed(self, value):
        with mock.patch.dict(os.environ, {} if value is None else {ENV: value}):
            if value is None:
                os.environ.pop(ENV, None)
            SentinelTask.objects.all().delete()
            with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
                try:
                    dispatch.dispatch_or_none(self.project, KIND, {'addresses': ['192.0.2.10']}, host='www.example.test', ips=['192.0.2.10'], timeout=5)
                except resources.ScannerUnavailable:
                    pass
        return self._entries()[-1].message, SentinelTask.objects.get().error

    def test_the_wording_says_the_targets_stay_due_whatever_the_variable_says(self):
        for value in (None, 'all', 'none', 'openvas,testssl'):
            with self.subTest(value=value):
                message, reason = self.unclaimed(value)
                self.assertIn(f'{KIND} work for www.example.test is waiting for a Sentinel to pick it up; {self.STAYS_DUE}', message)
                self.assertIn(self.STAYS_DUE, reason)
                for text in (message, reason):
                    self.assertNotIn('locally', text)
                    self.assertNotIn('local execution', text)

    def test_a_task_nobody_finished_expires_with_a_true_default_reason(self):
        from agentapi import sentinel_broker
        for value in ('all', 'none'):
            with mock.patch.dict(os.environ, {ENV: value}):
                task = SentinelTask.objects.create(project=self.project, kind=KIND, target={'addresses': ['192.0.2.10']})
                self.assertIn(self.STAYS_DUE, sentinel_broker.expire(task).error)


class WrapperPolicyTests(DispatchBase):
    """With no Sentinel for the project every wrapper used to hand the work back to a local run; each now says it must wait."""

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

    def test_the_wrappers_wait_even_when_the_ignored_variable_asks_for_every_kind(self):
        with mock.patch.dict('os.environ', {ENV: 'all'}):
            for kind, call in (('testssl', lambda: dispatch.try_testssl(self.project, 'www.example.test', '192.0.2.10', 443)),
                               ('nmap', lambda: dispatch.try_nmap(self.project, self.scan, ['192.0.2.10'])),
                               ('nmap_udp', lambda: dispatch.try_nmap_udp(self.project, '192.0.2.10')),
                               ('naabu', lambda: dispatch.wrap_naabu_runner(self.project, self.scan))):
                with self.assertRaises(resources.ScannerUnavailable) as caught:
                    call()
                self.assertEqual(caught.exception.kind, kind)

    def test_naabu_never_runs_the_remainder_beyond_one_task_locally(self):
        # the addresses beyond one task go to the Sentinel in further chunk tasks (sentinel_dispatch.dispatch_many): nothing runs here
        self.make_sentinel(['naabu'])
        many = [f'192.0.2.{i}' for i in range(1, dispatch.NAABU_CHUNK + 5)]
        result = {'outcome': 'done', 'ports': {}}
        for parallel in ('1', '4'):
            with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)), \
                    mock.patch.dict('os.environ', {'CVENGINE_STAGE_PARALLEL': parallel}):
                runner = dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)
                self.assertEqual(runner(many), {})
        self.assertEqual(SentinelTask.objects.filter(kind='naabu', status='done').count(), 4)

    def test_naabu_remainder_after_an_unclaimed_chunk_waits_instead_of_running_here(self):
        self.make_sentinel(['naabu'])
        many = [f'192.0.2.{i}' for i in range(1, dispatch.NAABU_CHUNK + 5)]
        for parallel in ('1', '4'):
            with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2), \
                    mock.patch.dict('os.environ', {'CVENGINE_STAGE_PARALLEL': parallel}):
                runner = dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)
                with self.assertRaises(resources.ScannerUnavailable):
                    runner(many)

    def test_nuclei_does_not_send_unresolvable_targets_anywhere(self):
        self.make_sentinel(['nuclei_light'])
        with mock.patch('agentapi.sentinel_dispatch.resolvable_targets', return_value=[]), \
                mock.patch('agentapi.sentinel_dispatch.any_scanner_for', return_value=True), \
                mock.patch('agentapi.sentinel_dispatch.dispatch_or_none') as sent:
            import tempfile
            with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
                handle.write('nothing.invalid\n')
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
            self.assertEqual(list(stream(handle.name)), [])
        sent.assert_not_called()
