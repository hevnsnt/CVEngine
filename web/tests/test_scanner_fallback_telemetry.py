"""The fallback telemetry (``agentapi.scanner_fallback``, the ``ScannerFallback`` table, ``manage.py scanner_fallbacks``, the ``scanning.scanner.fallbacks`` status
block) is gone with the local paths it watched. What these tests keep is what every reason it used to record now means: the stage waits
(``ScannerUnavailable``), the task ends ``expired`` or ``failed``, nothing runs on this server and nothing is recorded as done."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_dispatch as dispatch, system_status
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from dashboard.models import ProjectMembership
from reNgine import resources
from tests.test_agentapi import call
from tests.test_sentinel_dispatch import DispatchBase, _answer_queued_task
from tests.test_system_status import patched

import time as real_time

REAL_SLEEP = real_time.sleep  # the dispatch module shares the ``time`` module, so patching its sleep patches this one too
ADDR = ['192.0.2.10']


class Base(DispatchBase):
    def dispatch(self, kind='openvas', **kwargs):
        return dispatch.dispatch_or_none(self.project, kind, {'addresses': ADDR}, ips=ADDR, **kwargs)

    def waits(self, kind='openvas', **kwargs):
        with self.assertRaises(resources.ScannerUnavailable) as caught:
            self.dispatch(kind, **kwargs)
        self.assertEqual(caught.exception.kind, kind)
        return caught.exception


class EveryReasonWaitsTests(Base):
    """The reasons the telemetry used to name, one scenario each: every one of them ends in ScannerUnavailable and no local run."""

    def test_no_scanner_at_all_waits_and_creates_no_task(self):
        self.waits()
        self.assertFalse(SentinelTask.objects.exists())

    def test_the_kinds_with_no_local_path_wait(self):
        for attempt in (lambda: dispatch.try_testssl(self.project, 'example.test', ADDR[0], 443),
                        lambda: dispatch.try_nmap(self.project, self.scan, ADDR), lambda: dispatch.try_nmap_udp(self.project, ADDR[0]),
                        lambda: dispatch.wrap_naabu_runner(self.project, self.scan), lambda: dispatch.wrap_wpscan_runner(self.project)):
            with self.assertRaises(resources.ScannerUnavailable):
                attempt()

    def test_a_task_nobody_claims_in_time_expires_and_waits(self):
        self.make_sentinel(['openvas'])
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            self.waits(timeout=5)
        self.assertEqual(SentinelTask.objects.get().status, 'expired')

    def test_every_slot_busy_until_the_queue_budget_runs_out_expires_and_waits(self):
        agent = self.make_sentinel(['openvas'])
        for _ in range(agent.max_concurrent):
            SentinelTask.objects.create(project=self.project, kind='openvas', agent=agent, status='running', target={'addresses': ADDR})
        with mock.patch('agentapi.sentinel_dispatch._queue_timeout', return_value=0.2):
            self.waits(timeout=5)
        self.assertEqual(SentinelTask.objects.filter(status='expired').count(), 1)
        self.assertIn('no Sentinel slot freed up in time', SentinelTask.objects.get(status='expired').error)

    def test_a_sentinel_that_reports_failure_waits(self):
        self.make_sentinel(['openvas'])
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'error': 'boom'}, status='failed')):
            self.waits(timeout=5)
        self.assertEqual(SentinelTask.objects.get().status, 'failed')

    def test_a_claimed_task_that_never_reports_back_expires_and_waits(self):
        agent = self.make_sentinel(['openvas'])

        def claim_then_wait(_seconds):
            SentinelTask.objects.filter(status='queued').update(status='claimed', agent=agent, claimed_at=timezone.now())
            REAL_SLEEP(0.05)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=claim_then_wait):
            self.waits(timeout=0.2)
        self.assertEqual(SentinelTask.objects.get().status, 'expired')

    def test_the_last_sentinel_going_away_while_queued_waits(self):
        agent = self.make_sentinel(['openvas'])

        def vanish(_seconds):
            Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(hours=2))
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=vanish), mock.patch('agentapi.sentinel_dispatch.REAP_EVERY', 0):
            self.waits(timeout=30)
        self.assertEqual(SentinelTask.objects.get().status, 'expired')

    @mock.patch.dict('os.environ', {'CVENGINE_STAGE_PARALLEL': '1'})  # the serial loop: one chunk task at a time
    def test_the_addresses_beyond_one_task_go_in_a_second_task_and_nothing_runs_here(self):
        self.make_sentinel(['naabu'])
        ips = [f'192.0.2.{n}' for n in range(1, dispatch.MAX_ADDRESSES + 6)]
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'outcome': 'done', 'ports': {}})):
            dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)(ips)
        self.assertEqual(SentinelTask.objects.filter(kind='naabu').count(), 2)

    @mock.patch.dict('os.environ', {'CVENGINE_STAGE_PARALLEL': '4'})
    def test_side_by_side_chunks_wait_when_no_sentinel_claims_them(self):
        agent = self.make_sentinel(['naabu'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=4)
        ips = [f'192.0.2.{n}' for n in range(1, dispatch.MAX_ADDRESSES + 6)]
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            with self.assertRaises(resources.ScannerUnavailable):
                dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)(ips)
        self.assertFalse(SentinelTask.objects.filter(status__in=('queued', 'claimed', 'running')).exists())

    @mock.patch.dict('os.environ', {'CVENGINE_STAGE_PARALLEL': '1'})
    def test_a_chunk_never_sent_waits(self):
        self.make_sentinel(['naabu'])
        ips = [f'192.0.2.{n}' for n in range(1, dispatch.MAX_ADDRESSES + 6)]
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            with self.assertRaises(resources.ScannerUnavailable):
                dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)(ips)

    def test_a_sentinel_that_answers_returns_its_result(self):
        self.make_sentinel(['openvas'])
        result = {'outcome': 'done', 'hosts': []}
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            self.assertEqual(self.dispatch(timeout=5), result)

    def test_an_internal_task_is_unchanged_it_never_had_a_local_run(self):
        self.assertIsNone(self.dispatch(internal=True))

    def test_the_reason_vocabulary_is_gone_from_the_code(self):
        import inspect
        source = inspect.getsource(dispatch)
        for reason in ('not_claimed_in_time', 'slot_busy', 'failed_then_local', 'completion_timeout', 'over_chunk', 'partial_result', 'disabled_everywhere'):
            self.assertNotIn(f"'{reason}'", source)


class NmapPartialResultTests(DispatchBase):
    """The addresses of an nmap chunk a Sentinel finished without covering them (no host row) are never fingerprinted here: they go through
    ``_no_local`` and stay due (``ScannerUnavailable``)."""

    def setUp(self):
        super().setUp()
        from startScan.models import IpAddress, Subdomain
        Subdomain.objects.get(scan_history=self.scan).ip_addresses.add(IpAddress.objects.create(address='192.0.2.11'))
        self.make_sentinel(['nmap'])

    @staticmethod
    def answer(*hosts):
        return {'outcome': 'done', 'hosts': [{'ip': ip, 'os_guess': 'Linux 6.X', 'ports': [{'number': port, 'protocol': 'tcp', 'state': 'open',
                                                                                         'product': 'OpenSSH', 'version': '8.9'} for port in ports]}
                                             for ip, ports in hosts]}

    def run_stage(self, answer):
        from cveFeed import port_stage
        with mock.patch('cveFeed.port_stage.enabled', return_value=False), \
                mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(answer)):
            return port_stage.run_for_scan(self.scan.id)

    def fresh(self):
        from cveFeed import ledger
        return set(ledger.fresh('nmap-fast', ['192.0.2.10', '192.0.2.11'], self.project.id))

    def test_an_unreported_address_is_never_fingerprinted_here_and_it_stays_due(self):
        result = self.run_stage(self.answer(('192.0.2.11', [22])))
        self.assertIn('no scanner could take this work (nmap)', result['skipped'])
        self.assertEqual(self.fresh(), {'192.0.2.11'})  # the Sentinel's address is done, the one it did not report stays due
        from cveFeed.models import AgentActivity
        message = AgentActivity.objects.filter(message__startswith='the port scan for').latest('id').message
        self.assertIn('the 1 IP stay due until one can (1 fingerprinted by a Sentinel)', message)

    def test_try_nmap_names_what_a_sentinel_covered_when_it_must_wait(self):
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(self.answer(('192.0.2.11', [22])))):
            with self.assertRaises(resources.ScannerUnavailable) as caught:
                dispatch.try_nmap(self.project, self.scan, ['192.0.2.10', '192.0.2.11'], timeout=5)
        self.assertEqual(caught.exception.kind, 'nmap')
        self.assertEqual(caught.exception.done, ['192.0.2.11'])

    def test_a_sentinel_that_covers_everything_returns_the_totals(self):
        with mock.patch('agentapi.sentinel_dispatch.time.sleep',
                        side_effect=_answer_queued_task(self.answer(('192.0.2.10', [22]), ('192.0.2.11', [22])))):
            totals = dispatch.try_nmap(self.project, self.scan, ['192.0.2.10', '192.0.2.11'], timeout=5)
        self.assertEqual(totals['ports'], 2)

    def test_a_chunk_no_sentinel_did_waits(self):
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            with self.assertRaises(resources.ScannerUnavailable):
                dispatch.try_nmap(self.project, self.scan, ['192.0.2.10'], timeout=5)


class TheTelemetryIsGoneTests(TestCase):
    def test_the_table_the_module_and_the_command_no_longer_exist(self):
        from django.apps import apps
        from django.core.management import get_commands
        with self.assertRaises(LookupError):
            apps.get_model('agentapi', 'ScannerFallback')
        with self.assertRaises(ImportError):
            __import__('agentapi.scanner_fallback')
        self.assertNotIn('scanner_fallbacks', get_commands())

    def test_the_weekly_maintenance_no_longer_prunes_it(self):
        import inspect

        from cveFeed import maintenance
        self.assertNotIn('scanner_fallback', inspect.getsource(maintenance))


class SystemStatusBlockTests(Base):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('fb-root', 'r@x.io', 'x')
        _, self.t_root = create_token(self.root, 'root')
        self.member = User.objects.create_user('fb-member', password='x')
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')
        _, self.t_member = create_token(self.member, 'member')

    def get(self, token):
        a, b, c = patched()
        with a, b, c:
            return call(token, 'GET', '/api/v1/system/status')

    def test_the_scanner_block_keeps_the_offline_signal_and_has_no_fallback_block(self):
        for token in (self.t_root, self.t_member):
            status, data = self.get(token)
            self.assertEqual(status, 200)
            scanner = data['scanning']['scanner']
            self.assertIn('offline', scanner)
            self.assertIn('kinds', scanner)
            for gone in ('fallbacks', 'unknown_kinds', 'vantage'):
                self.assertNotIn(gone, scanner)

    def test_the_scanner_reading_is_exactly_the_scanner_state(self):
        out = system_status._scanner(True)
        self.assertEqual(set(out) - {'messages', 'message', 'cooling_message', 'disabled_message', 'never_seen_message'}, {'offline', 'kinds', 'never_seen'})
