"""Fallback telemetry (``agentapi.scanner_fallback``): a durable record of every time a stage that could have used a Sentinel ran, or was allowed to run,
on this server instead, and the gate built on it (docs/SCANNER-ARCHITECTURE.md, "Fallback telemetry"). Recording must never break a scan."""
import os
import time as real_time
from datetime import datetime, timedelta, timezone as dt_timezone
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from agentapi import scanner_fallback, sentinel_dispatch as dispatch, system_status
from agentapi.auth import create_token
from agentapi.models import Agent, ScannerFallback, SentinelEnrollment, SentinelTask
from dashboard.models import Org, Project, ProjectMembership
from reNgine import resources
from tests.test_agentapi import call
from tests.test_sentinel_dispatch import DispatchBase, _answer_queued_task
from tests.test_system_status import patched

ENV = dispatch.LOCAL_FALLBACK_ENV
REAL_SLEEP = real_time.sleep  # the dispatch module shares the ``time`` module, so patching its sleep patches this one too
FROZEN = datetime(2026, 6, 15, 12, 0, tzinfo=dt_timezone.utc)
ADDR = ['192.0.2.10']


class FallbackBase(DispatchBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict('os.environ', {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(ENV, None)
        warned = mock.patch.object(scanner_fallback, '_warned', False)
        warned.start()
        self.addCleanup(warned.stop)

    def rows(self):
        return list(ScannerFallback.objects.order_by('id').values_list('kind', 'reason'))

    def dispatch(self, kind='nmap', **kwargs):
        return dispatch.dispatch_or_none(self.project, kind, {'addresses': ADDR}, ips=ADDR, **kwargs)


class RecordedReasonTests(FallbackBase):
    def test_no_scanner_at_all_is_recorded_with_kind_and_project_only(self):
        self.assertIsNone(self.dispatch())
        self.assertEqual(self.rows(), [('nmap', 'no_scanner')])
        row = ScannerFallback.objects.get()
        self.assertEqual(row.project, self.project)
        self.assertIsNotNone(row.created_at)
        text = ' '.join(str(v) for v in ScannerFallback.objects.values().get().values())
        self.assertNotIn('192.0.2', text)  # no address, no target name
        self.assertNotIn('example.test', text)

    def test_every_wrapper_that_sees_no_scanner_records_its_kind(self):
        dispatch.try_nmap(self.project, self.scan, ADDR)
        dispatch.try_testssl(self.project, 'example.test', ADDR[0], 443)
        dispatch.try_nmap_udp(self.project, ADDR[0])
        dispatch.wrap_naabu_runner(self.project, self.scan)
        dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
        dispatch.wrap_wpscan_runner(self.project)
        self.assertEqual(self.rows(), [(k, 'no_scanner') for k in ('nmap', 'testssl', 'nmap_udp', 'naabu', 'nuclei_light', 'wpscan')])

    def test_a_task_nobody_claims_in_time(self):
        self.make_sentinel(['nmap'])
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            self.assertIsNone(self.dispatch(timeout=5))
        self.assertEqual(self.rows(), [('nmap', 'not_claimed_in_time')])

    def test_every_slot_busy_until_the_queue_budget_runs_out(self):
        agent = self.make_sentinel(['nmap'])
        for _ in range(agent.max_concurrent):
            SentinelTask.objects.create(project=self.project, kind='nmap', agent=agent, status='running', target={'addresses': ADDR})
        with mock.patch('agentapi.sentinel_dispatch._queue_timeout', return_value=0.2):
            self.assertIsNone(self.dispatch(timeout=5))
        self.assertEqual(self.rows(), [('nmap', 'slot_busy')])

    def test_a_sentinel_that_reports_failure(self):
        self.make_sentinel(['nmap'])
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'error': 'boom'}, status='failed')):
            self.assertIsNone(self.dispatch(timeout=5))
        self.assertEqual(self.rows(), [('nmap', 'failed_then_local')])

    def test_a_claimed_task_that_never_reports_back(self):
        agent = self.make_sentinel(['nmap'])

        def claim_then_wait(_seconds):
            SentinelTask.objects.filter(status='queued').update(status='claimed', agent=agent, claimed_at=timezone.now())
            REAL_SLEEP(0.05)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=claim_then_wait):
            self.assertIsNone(self.dispatch(timeout=0.2))
        self.assertEqual(self.rows(), [('nmap', 'completion_timeout')])

    def test_the_last_sentinel_going_away_while_queued_reads_as_no_scanner(self):
        agent = self.make_sentinel(['nmap'])

        def vanish(_seconds):
            Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(hours=2))
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=vanish), mock.patch('agentapi.sentinel_dispatch.REAP_EVERY', 0):
            self.assertIsNone(self.dispatch(timeout=30))
        self.assertEqual(self.rows(), [('nmap', 'no_scanner')])

    def test_the_addresses_beyond_one_task_run_here_and_are_recorded(self):
        self.make_sentinel(['naabu'])
        ips = [f'192.0.2.{n}' for n in range(1, dispatch.MAX_ADDRESSES + 6)]
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'outcome': 'done', 'ports': {}})), \
                mock.patch('cveFeed.naabu_scan.run_naabu', return_value={}) as local:
            dispatch.wrap_naabu_runner(self.project, self.scan, timeout=5)(ips)
        self.assertEqual(local.call_args.args[0], ips[dispatch.MAX_ADDRESSES:])
        self.assertEqual(self.rows(), [('naabu', 'over_chunk')])

    def test_every_reason_the_code_can_name_is_a_listed_reason(self):
        import inspect
        source = inspect.getsource(dispatch)
        for reason in ('no_scanner', 'not_claimed_in_time', 'slot_busy', 'failed_then_local', 'completion_timeout', 'over_chunk'):
            self.assertIn(f"'{reason}'", source)
            self.assertIn(reason, scanner_fallback.REASONS)


class NothingRecordedTests(FallbackBase):
    def test_a_sentinel_that_answers_records_nothing(self):
        self.make_sentinel(['nmap'])
        result = {'outcome': 'done', 'hosts': []}
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task(result)):
            self.assertEqual(self.dispatch(timeout=5), result)
        self.assertEqual(self.rows(), [])

    def test_a_kind_off_the_fallback_list_waits_and_records_nothing(self):
        os.environ[ENV] = 'none'
        with self.assertRaises(resources.ScannerUnavailable):
            self.dispatch()
        self.make_sentinel(['nmap'])
        with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
            with self.assertRaises(resources.ScannerUnavailable):
                self.dispatch(timeout=5)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'error': 'x'}, status='failed')):
            with self.assertRaises(resources.ScannerUnavailable):
                self.dispatch(timeout=5)
        self.assertEqual(self.rows(), [])

    def test_only_the_kinds_still_on_the_list_are_recorded(self):
        os.environ[ENV] = 'nmap'
        self.assertIsNone(self.dispatch('nmap'))
        with self.assertRaises(resources.ScannerUnavailable):
            self.dispatch('naabu')
        self.assertEqual(self.rows(), [('nmap', 'no_scanner')])

    def test_an_internal_task_never_had_a_local_run_so_it_records_nothing(self):
        self.assertIsNone(self.dispatch(internal=True))
        self.assertEqual(self.rows(), [])


class RecordingNeverBreaksDispatchTests(FallbackBase):
    def test_a_failing_insert_does_not_change_what_dispatch_returns(self):
        with mock.patch.object(ScannerFallback.objects, 'create', side_effect=RuntimeError('table gone')), self.assertLogs('agentapi.scanner_fallback', level='DEBUG'):
            self.assertIsNone(self.dispatch())
            self.make_sentinel(['nmap'])
            with mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=0.2):
                self.assertIsNone(self.dispatch(timeout=5))
            runner = dispatch.wrap_naabu_runner(self.project, self.scan)
        self.assertEqual(self.rows(), [])
        self.assertIsNone(runner)  # no naabu Sentinel: the wrapper steps aside as before, the failed insert changes nothing
        self.assertEqual(SentinelTask.objects.count(), 1)

    def test_a_real_database_error_is_contained_in_a_savepoint(self):
        with self.assertLogs('agentapi.scanner_fallback', level='WARNING'):
            self.assertFalse(scanner_fallback.record('k' * 60, self.project, 'no_scanner'))  # varchar(20): the INSERT itself fails
        self.assertEqual(ScannerFallback.objects.count(), 0)  # the surrounding transaction is still usable
        self.assertTrue(scanner_fallback.record('nmap', self.project, 'no_scanner'))
        self.assertEqual(ScannerFallback.objects.count(), 1)

    def test_a_failure_is_logged_once_per_process_at_warning_level(self):
        with self.assertLogs('agentapi.scanner_fallback', level='WARNING') as logs:
            with mock.patch.object(ScannerFallback.objects, 'create', side_effect=RuntimeError('boom')):
                for _ in range(3):
                    self.assertFalse(scanner_fallback.record('nmap', self.project, 'no_scanner'))
        self.assertEqual(len(logs.records), 1)

    def test_the_stage_cost_is_one_insert(self):
        with self.assertNumQueries(3):  # the INSERT, inside a savepoint pair (the pair only appears under an outer transaction, as in tests)
            scanner_fallback.record('nmap', self.project, 'no_scanner')


class CommandTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='C', slug='c-fb')
        self.project = Project.objects.create(name='C', slug='c-fb-p', insert_date=timezone.now(), org=org)

    def add(self, kind, reason, ago):
        ScannerFallback.objects.create(kind=kind, project=self.project, reason=reason, created_at=timezone.now() - ago)

    def run_command(self, *args):
        out = StringIO()
        call_command('scanner_fallbacks', *args, stdout=out)
        return out.getvalue()

    def test_counts_by_kind_and_reason_and_the_last_time(self):
        self.add('nmap', 'no_scanner', timedelta(hours=1))
        self.add('nmap', 'no_scanner', timedelta(hours=5))
        self.add('nmap', 'slot_busy', timedelta(days=2))
        self.add('naabu', 'failed_then_local', timedelta(days=1))
        self.add('naabu', 'no_scanner', timedelta(days=20))  # outside --days 7
        out = self.run_command('--days', '7')
        self.assertIn('last 7 day(s)', out)
        self.assertIn('nmap: 3', out)
        self.assertIn('    no_scanner: 2', out)
        self.assertIn('    slot_busy: 1', out)
        self.assertIn('naabu: 1', out)
        self.assertIn('    failed_then_local: 1', out)
        self.assertNotIn('    no_scanner: 3', out)
        self.assertIn('testssl: 0, never recorded', out)
        self.assertIn('Total: 4', out)
        last_nmap = ScannerFallback.objects.filter(kind='nmap').latest('created_at').created_at.isoformat()
        self.assertIn(f'nmap: 3, last {last_nmap}', out)

    def test_a_kind_filter_and_the_window(self):
        self.add('nmap', 'no_scanner', timedelta(days=10))
        self.add('naabu', 'no_scanner', timedelta(hours=1))
        out = self.run_command('--days', '30', '--kind', 'nmap')
        self.assertIn('nmap: 1', out)
        self.assertNotIn('naabu', out)
        self.assertIn('nmap: 0', self.run_command('--days', '7', '--kind', 'nmap'))

    def test_a_bad_kind_or_window_is_refused(self):
        with self.assertRaises(CommandError):
            self.run_command('--kind', 'nmpa')
        with self.assertRaises(CommandError):
            self.run_command('--days', '0')

    def test_with_nothing_recorded_it_says_so_in_numbers(self):
        out = self.run_command()
        self.assertIn('nmap: 0, never recorded', out)
        self.assertIn('Total: 0', out)


class StatusAndGateTests(FallbackBase):
    def builtin(self, caps, last_seen=FROZEN, name='builtin'):
        user = User.objects.create_user(f'bi-{name}', password='x')
        token, _raw = create_token(user, f'{name}-token')
        agent = Agent.objects.create(token=token, name=name, kind='scanner', status='active', capabilities=caps, last_seen=last_seen,
                                     scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})
        SentinelEnrollment.objects.create(token_hash=f'h-{name}', prefix='cvs_x', created_by=user, expires_at=FROZEN + timedelta(days=1),
                                          builtin=True, used_by_agent=agent, used_at=FROZEN)
        return agent

    def add(self, kind, ago, reason='no_scanner'):
        ScannerFallback.objects.create(kind=kind, project=self.project, reason=reason, created_at=FROZEN - ago)

    def test_zero_fallbacks_is_an_empty_block(self):
        block = scanner_fallback.status(admin=True, now=FROZEN)
        self.assertEqual(block['days'], 7)
        self.assertEqual(block['by_kind'], {})
        self.assertEqual(block['ready_to_delete'], [])
        self.assertEqual(block['soak_hours'], 72)

    def test_nonzero_counts_carry_the_last_time_inside_the_seven_days_only(self):
        self.add('nmap', timedelta(hours=2))
        self.add('nmap', timedelta(days=3))
        self.add('naabu', timedelta(days=6))
        self.add('naabu', timedelta(days=8))  # outside the window
        self.add('testssl', timedelta(days=9))
        block = scanner_fallback.status(admin=True, now=FROZEN)
        self.assertEqual(block['by_kind'], {'nmap': {'count': 2, 'last_at': (FROZEN - timedelta(hours=2)).isoformat()},
                                            'naabu': {'count': 1, 'last_at': (FROZEN - timedelta(days=6)).isoformat()}})

    def test_ready_to_delete_needs_a_quiet_72_hours_and_a_live_builtin_scanner_declaring_the_kind(self):
        self.builtin(['nmap', 'naabu', 'testssl'])
        self.add('nmap', timedelta(hours=71, minutes=59))  # inside the soak: not ready
        self.add('naabu', timedelta(hours=72, minutes=1))  # just outside it: ready
        self.add('wpscan', timedelta(hours=1))  # recent, and nothing declares wpscan anyway
        ready = scanner_fallback.ready_to_delete(FROZEN)
        self.assertEqual(ready, ['naabu', 'testssl'])  # nmap: too recent; wpscan, nuclei_*, nmap_udp: not declared by the built-in scanner
        self.assertEqual(scanner_fallback.status(admin=True, now=FROZEN)['ready_to_delete'], ['naabu', 'testssl'])

    def test_the_window_edge_follows_the_named_constant(self):
        self.builtin(['nmap'])
        self.add('nmap', timedelta(hours=10))
        self.assertEqual(scanner_fallback.ready_to_delete(FROZEN), [])
        with mock.patch.object(scanner_fallback, 'SOAK_HOURS', 8):
            self.assertEqual(scanner_fallback.ready_to_delete(FROZEN), ['nmap'])
        self.assertEqual(scanner_fallback.SOAK_HOURS, 72)

    def test_an_external_sentinel_does_not_make_a_kind_ready(self):
        agent = self.make_sentinel(['nmap'])  # live, but not the built-in scanner
        Agent.objects.filter(pk=agent.pk).update(last_seen=FROZEN)
        self.assertEqual(scanner_fallback.ready_to_delete(FROZEN), [])

    def test_a_built_in_scanner_that_is_not_live_makes_nothing_ready(self):
        self.builtin(['nmap'], last_seen=FROZEN - timedelta(hours=3))
        self.assertEqual(scanner_fallback.ready_to_delete(FROZEN), [])
        self.assertEqual(scanner_fallback.ready_to_delete(FROZEN - timedelta(hours=3)), ['nmap'])  # the same row, heard from at that moment

    def test_a_kind_no_stage_dispatches_is_never_ready(self):
        self.builtin(['waf', 'nmap'])
        self.assertEqual(scanner_fallback.ready_to_delete(FROZEN), ['nmap'])

    def test_a_non_admin_sees_counts_only(self):
        self.builtin(['nmap'])
        self.add('nmap', timedelta(hours=1))
        self.assertEqual(scanner_fallback.status(admin=False, now=FROZEN), {'days': 7, 'by_kind': {'nmap': {'count': 1}}})


class SystemStatusBlockTests(FallbackBase):
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

    def test_zero_fallbacks(self):
        status, data = self.get(self.t_root)
        self.assertEqual(status, 200)
        fallbacks = data['scanning']['scanner']['fallbacks']
        self.assertEqual((fallbacks['days'], fallbacks['by_kind'], fallbacks['ready_to_delete']), (7, {}, []))

    def test_nonzero_counts_for_an_admin_include_the_time_and_the_gate(self):
        ScannerFallback.objects.create(kind='nmap', project=self.project, reason='slot_busy')
        _, data = self.get(self.t_root)
        fallbacks = data['scanning']['scanner']['fallbacks']
        self.assertEqual(fallbacks['by_kind']['nmap']['count'], 1)
        self.assertIn('last_at', fallbacks['by_kind']['nmap'])
        self.assertIn('ready_to_delete', fallbacks)

    def test_a_project_member_gets_the_counts_and_nothing_beyond(self):
        ScannerFallback.objects.create(kind='nmap', project=self.project, reason='slot_busy')
        status, data = self.get(self.t_member)
        self.assertEqual(status, 200)
        self.assertEqual(data['scanning']['scanner']['fallbacks'], {'days': 7, 'by_kind': {'nmap': {'count': 1}}})

    def test_a_telemetry_read_that_fails_leaves_the_scanner_block_intact(self):
        with mock.patch.object(scanner_fallback, 'status', side_effect=RuntimeError('db')), self.assertLogs('agentapi.system_status', level='WARNING'):
            out = system_status._scanner(True)
        self.assertNotIn('fallbacks', out)
        self.assertIn('offline', out)


class PruneTests(TestCase):
    def test_rows_older_than_thirty_days_go_and_newer_ones_stay(self):
        for age in (timedelta(days=31), timedelta(days=30, hours=1), timedelta(days=29), timedelta(hours=1)):
            ScannerFallback.objects.create(kind='nmap', reason='no_scanner', created_at=FROZEN - age)
        self.assertEqual(scanner_fallback.prune(FROZEN), 2)
        self.assertEqual(ScannerFallback.objects.count(), 2)
        self.assertEqual(scanner_fallback.RETENTION_DAYS, 30)

    def test_the_weekly_maintenance_runs_it(self):
        import inspect

        from cveFeed import maintenance
        self.assertIn('scanner_fallback.prune(now)', inspect.getsource(maintenance))

    def test_a_deleted_project_keeps_its_rows(self):
        project = Project.objects.create(name='P', slug='fb-prune-p', insert_date=timezone.now(), org=Org.objects.create(name='O', slug='fb-prune-o'))
        ScannerFallback.objects.create(kind='nmap', project=project, reason='no_scanner')
        project.delete()
        self.assertIsNone(ScannerFallback.objects.get().project)
