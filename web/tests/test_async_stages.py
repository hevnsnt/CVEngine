"""Asynchronous stages (queue Q4, ``agentapi.stage_runs``): a stage that waits on Sentinels gives its worker back, a completion callback continues it,
expiry and fallback end it exactly as the blocking wait did, and a restart loses nothing. Plus the Redis wake-ups (``agentapi.sentinel_notify``).

The fake scanner (``tests/fake_scanner.py``) runs with ``async_stages=True``: the stage's first call returns the ``waiting`` marker with nothing
served yet (the worker is free), and ``fake.drain()`` does what the server's workers do afterwards (serve, wake, run the callback, drive the
budgets) until no run is open."""
import os
import time
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_broker, sentinel_notify, stage_runs
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import ScannerFallback, SentinelTask, StageRun
from cveFeed import discovery, ledger, nmap_scan, reaper
from cveFeed.models import AgentActivity, ServiceRun
from reNgine import resources
from startScan.models import IpAddress, ScanActivity, ScanHistory, Subdomain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_route_auth import RouteFixture
from tests.test_scanner_unavailable_stages import IP, FallbackOffBase
from tests.test_sentinel_dispatch import DispatchBase

HOST = 'www.example.test'


def adapter(name, body):
    """Register a stage adapter for one test (the real stage, with the test's own seams), removed again at the end."""
    stage_runs.adapter(name, queue='discovery_queue')(body)
    return name


class AsyncBase(FallbackOffBase):
    def setUp(self):
        super().setUp()
        self.addCleanup(lambda: [stage_runs.ADAPTERS.pop(k, None) for k in [k for k in stage_runs.ADAPTERS if k.startswith('test.')]])
        self.addCleanup(mock.patch.stopall)
        mock.patch('reNgine.resources.global_pause_requested', return_value=False).start()


class StageFreesItsWorkerTests(AsyncBase):
    """The nmap stage (naabu, then nmap: two waits) under a StageRun."""

    def nmap_stage(self, guard):
        name = adapter('test.nmap', lambda ctx: nmap_scan.run_nmap_for_scan(ctx['scan_id'], runner=guard.runner))
        return stage_runs.run(name, {'scan_id': self.scan.id}, first=lambda: nmap_scan.run_nmap_for_scan(self.scan.id, runner=guard.runner),
                              project=self.project, scan=self.scan)

    def test_the_stage_returns_at_once_and_the_callback_finishes_it_as_the_blocking_wait_did(self):
        guard = assert_ran_nowhere_locally(self, 'nmap')
        with FakeScanner(kinds=['naabu', 'nmap'], responders={'naabu': fixture('naabu', ports={IP: [22]})}, async_stages=True) as fake:
            first = self.nmap_stage(guard)
            self.assertTrue(stage_runs.is_waiting(first))  # the worker is free: the Sentinel has not even been asked yet
            self.assertEqual(fake.served, [])
            run = StageRun.objects.get(pk=first['stage_run'])
            self.assertEqual((run.state, run.kind, len(run.task_ids)), ('waiting', 'test.nmap', 1))
            self.assertEqual(SentinelTask.objects.get().kind, 'naabu')
            self.assertFalse(ledger.fresh('nmap-fast', [IP], self.project.id))
            results = fake.drain()
        self.assertEqual(fake.served_kinds(), ['naabu', 'nmap'])
        self.assertEqual(results[-1], {'targets': 1, 'reused': 0, 'fast': {'ports': 1, 'hosts_with_os': 1}})  # the blocking test's own result
        self.assertTrue(stage_runs.is_waiting(results[0]))  # naabu came back; the pass then waited on nmap
        port = IpAddress.objects.get(address=IP, org_id=self.org.id).ports.get(number=22)
        self.assertEqual((port.product, port.source), ('OpenSSH', 'nmap'))
        self.assertEqual(list(ServiceRun.objects.filter(service='nmap-fast').values_list('status', flat=True)), ['done'])
        run.refresh_from_db()
        self.assertEqual((run.state, run.rounds, len(run.task_ids)), ('done', 2, 2))
        self.assertEqual(guard.calls, [])
        # the passes repeated the stage's opening lines: each is in the feed once, and none is left running
        self.assertEqual(list(AgentActivity.objects.filter(message__startswith='nmap fingerprinted').values_list('status', flat=True)), ['done'])
        self.assertFalse(AgentActivity.objects.filter(message__startswith='nmap is fingerprinting').exists())
        self.assertFalse(AgentActivity.objects.filter(status='running').exists())

    def test_a_claim_taken_in_a_pass_is_held_while_the_run_waits(self):
        guard = assert_ran_nowhere_locally(self, 'nmap')
        with FakeScanner(kinds=['naabu', 'nmap'], responders={'naabu': fixture('naabu', ports={IP: [22]})}, async_stages=True) as fake:
            self.nmap_stage(guard)
            with ledger.claim_many(f'naabu@{self.project.id}', [IP]) as won:
                self.assertEqual(won, [])  # another scan cannot start the same sweep while this one waits for its Sentinel
            fake.drain()
        with ledger.claim_many(f'naabu@{self.project.id}', [IP]) as won:
            self.assertEqual(won, [IP])  # released when the run ended


class ExpiryTests(AsyncBase):
    """A task nobody claims (or that fails) ends the run's wait exactly as the blocking wait ended: the same fallback decision, recorded once."""

    def one(self, ips=('192.0.2.10',)):
        def body(ctx=None):
            return dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': list(ips)}, ips=list(ips), scan=self.scan)
        name = adapter('test.one', lambda ctx: body())
        return stage_runs.run(name, {}, first=body, project=self.project, scan=self.scan)

    def test_unclaimed_where_local_is_allowed_returns_none_with_one_fallback_row(self):
        LocalFallback('all').apply(self)
        with FakeScanner(kinds=['nmap'], mode='idle', async_stages=True) as fake:
            self.assertTrue(stage_runs.is_waiting(self.one()))
            results = fake.drain()
        self.assertEqual(results, [None])  # the caller runs it here, as before
        task = SentinelTask.objects.get()
        self.assertEqual(task.status, 'expired')
        self.assertIn('no Sentinel claimed the task in time', task.error)
        self.assertEqual(list(ScannerFallback.objects.values_list('kind', 'reason')), [('nmap', 'not_claimed_in_time')])
        self.assertEqual(list(AgentActivity.objects.filter(message__contains='No Sentinel picked up nmap work').values_list('status', flat=True)),
                         ['expired'])  # the hand-off line, closed once, as the blocking wait closes it

    def test_unclaimed_where_local_is_not_allowed_raises_scanner_unavailable_in_the_callback(self):
        with FakeScanner(kinds=['nmap'], mode='idle', async_stages=True) as fake:
            self.assertTrue(stage_runs.is_waiting(self.one()))
            results = fake.drain()
        self.assertEqual(results[0]['status'], 'failed')
        self.assertIn('ScannerUnavailable', StageRun.objects.get().error)
        self.assertFalse(ScannerFallback.objects.exists())  # a kind that may not run here records nothing

    def test_a_stage_that_waits_and_falls_back_keeps_the_stage_semantics(self):
        """The nmap stage whose nmap task fails, with the fallback off: the stage says it waits and leaves the address due (the blocking test's case)."""
        guard = assert_ran_nowhere_locally(self, 'nmap')
        name = adapter('test.nmapfail', lambda ctx: nmap_scan.run_nmap_for_scan(self.scan.id, runner=guard.runner))
        with FakeScanner(kinds=['naabu', 'nmap'], modes={'nmap': 'fail'}, responders={'naabu': fixture('naabu', ports={IP: [22]})},
                         async_stages=True) as fake:
            stage_runs.run(name, {}, first=lambda: nmap_scan.run_nmap_for_scan(self.scan.id, runner=guard.runner), scan=self.scan)
            result = fake.drain()[-1]
        self.assertNotIn('error', result)
        self.assertIn('no scanner could take this work (nmap)', result['skipped'])
        self.assertNothingRecorded('nmap-fast')
        self.assertEqual(guard.calls, [])
        self.assertEqual(StageRun.objects.get().state, 'done')


class FanOutTests(AsyncBase):
    """``dispatch_many`` under a StageRun: the window, the refill when a chunk ends, every result handed over once and in order."""

    def test_the_chunks_go_out_in_windows_and_come_back_together(self):
        chunks = [['192.0.2.1'], ['192.0.2.2'], ['192.0.2.3']]
        seen = []

        def body(ctx=None):
            for index, result in dispatch.dispatch_many(self.project, 'nmap', chunks, scan=self.scan):
                seen.append((index, bool(result)))
            return len(seen)
        name = adapter('test.many', lambda ctx: body())
        with FakeScanner(kinds=['nmap'], max_concurrent=2, async_stages=True) as fake, \
                mock.patch('agentapi.sentinel_dispatch.stage_parallel', return_value=2), mock.patch('cveFeed.discovery.stopped', return_value=False):
            first = stage_runs.run(name, {}, first=body, project=self.project, scan=self.scan)
            self.assertTrue(stage_runs.is_waiting(first))
            self.assertEqual(SentinelTask.objects.count(), 2)  # the window: two slots, two chunks; nothing handed to the stage yet
            self.assertEqual(seen, [])
            results = fake.drain()
        self.assertEqual(results[-1], 3)
        self.assertEqual(seen, [(0, True), (1, True), (2, True)])  # once each, in order, though they took two waits
        self.assertEqual(SentinelTask.objects.filter(status='done').count(), 3)

    def test_a_stopped_scan_cancels_its_chunks_and_the_stage_ends_aborted(self):
        def body(ctx=None):
            return list(dispatch.dispatch_many(self.project, 'nmap', [['192.0.2.1'], ['192.0.2.2']], scan=self.scan))
        name = adapter('test.stop', lambda ctx: body())
        with FakeScanner(kinds=['nmap'], mode='idle', async_stages=True) as fake, mock.patch('agentapi.sentinel_dispatch.stage_parallel', return_value=2):
            stage_runs.run(name, {}, first=body, project=self.project, scan=self.scan)
            with mock.patch('agentapi.sentinel_dispatch._stopped', return_value=True):
                results = fake.drain()
        self.assertEqual(results[0]['status'], 'failed')  # ScanAborted, as the blocking loop raised it
        self.assertEqual(set(SentinelTask.objects.values_list('status', flat=True)), {'expired'})
        self.assertFalse(ScannerFallback.objects.exists())


class PipelineTests(AsyncBase):
    """The real pipeline adapter: the nmap stage waits, the callback finishes it and runs every stage after it once."""

    def test_the_callback_continues_the_pipeline_from_the_waiting_stage(self):
        Subdomain.objects.filter(scan_history=self.scan).update(target_domain=self.domain)
        stubs = {}
        for path, value in (('cveFeed.db_exposure.run_db_exposure_checks', {'checked': 0, 'exposed': 0}),
                            ('cveFeed.nuclei_scan.run_light_nuclei', {'targets': 0, 'techs': {}}),
                            ('cveFeed.route_auth.run_route_auth', {'routes': 0}), ('cveFeed.probes.run_for_scan', {'hosts': 0}),
                            ('cveFeed.wpscan_scan.run_wpscan', {'sites': 0}), ('cveFeed.tasks.correlate_cves', {'subdomains': 0, 'matches': 0}),
                            ('cveFeed.nuclei_scan.run_targeted_nuclei', {'targets': 0, 'findings': 0}), ('cveFeed.triage.run_for_scan', {'rows': 0}),
                            ('cveFeed.changes.record_scan_changes', {'changes': 0})):
            stubs[path] = mock.patch(path, return_value=value).start()
        mock.patch('cveFeed.discovery._announce').start()
        mock.patch('cveFeed.web_shot.has_work_for_scan', return_value=False).start()
        mock.patch('cveFeed.waf_scan.enabled', return_value=False).start()
        mock.patch('cveFeed.node2shell_scan.enabled', return_value=False).start()
        found = {'scan_id': self.scan.id, 'status': discovery.SUCCESS, 'error': ''}
        guard = assert_ran_nowhere_locally(self, 'nmap')
        with FakeScanner(kinds=['naabu', 'nmap', 'nuclei_light', 'nuclei_targeted'], responders={'naabu': fixture('naabu', ports={IP: [22]})},
                         async_stages=True) as fake, \
                mock.patch('cveFeed.discovery.stopped', return_value=False), mock.patch('cveFeed.nmap_scan.run_nmap_xml', guard.runner):
            first = stage_runs.run('pipeline', {'scan_id': self.scan.id, 'found': found, 'kwargs': {'hygiene': False}, 'domain_id': self.domain.id},
                                   first=lambda: discovery._run_stages(self.scan.id, found, hygiene=False), project=self.project, scan=self.scan)
            self.assertTrue(stage_runs.is_waiting(first))
            self.assertEqual(first['stage'], 'nmap_scan')
            self.assertEqual(ScanActivity.objects.get(scan_of=self.scan, name='nmap_scan').status, discovery.RUNNING)
            self.assertFalse(ScanActivity.objects.filter(scan_of=self.scan, name='db_exposure_scan').exists())  # nothing after the stage ran yet
            self.assertEqual(stage_runs.open_scan_ids(), {self.scan.id})
            results = fake.drain()
        out = results[-1]
        self.assertEqual(out['status'], discovery.SUCCESS)
        self.assertEqual(out['nmap']['fast'], {'ports': 1, 'hosts_with_os': 1})
        self.assertEqual(ScanHistory.objects.get(pk=self.scan.id).scan_status, discovery.SUCCESS)
        self.assertEqual(ScanActivity.objects.filter(scan_of=self.scan, name='nmap_scan').count(), 1)  # one row, though the stage took three passes
        for path, stub in stubs.items():
            self.assertEqual(stub.call_count, 1, path)  # every stage after it ran once
        self.assertEqual(stage_runs.open_scan_ids(), set())


class RestartTests(AsyncBase):
    """Nothing is lost to a restart: the tick re-drives what a dead worker or a lost message left."""

    def waiting_run(self, fake):
        def body(ctx=None):
            return dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], scan=self.scan)
        name = adapter('test.restart', lambda ctx: body())
        out = stage_runs.run(name, {}, first=body, project=self.project, scan=self.scan)
        return StageRun.objects.get(pk=out['stage_run'])

    def test_a_pass_whose_worker_died_is_continued_by_the_tick(self):
        with FakeScanner(kinds=['nmap'], async_stages=True) as fake:
            run = self.waiting_run(fake)
            fake.serve_once()
            run.refresh_from_db()
            self.assertEqual(run.state, 'ready')
            # the callback started and its worker was killed mid-pass: the run says running, with a lease nobody renews
            StageRun.objects.filter(pk=run.pk).update(state='running', lease_until=timezone.now() - timedelta(seconds=1))
            with self.captureOnCommitCallbacks(execute=False):
                self.assertEqual(stage_runs.tick(), {'recovered': 1})
            self.assertEqual(StageRun.objects.get(pk=run.pk).state, 'ready')
            result = stage_runs.resume(run.pk)
        self.assertEqual(result['hosts'][0]['ip'], '192.0.2.10')
        self.assertEqual(StageRun.objects.get(pk=run.pk).state, 'done')

    def test_a_lost_callback_message_is_sent_again_and_a_missed_deadline_is_driven(self):
        with FakeScanner(kinds=['nmap'], mode='idle', async_stages=True) as fake:
            run = self.waiting_run(fake)
            StageRun.objects.filter(pk=run.pk).update(deadline=timezone.now() - timedelta(minutes=5))
            fake.clock.offset += 30
            with mock.patch('agentapi.stage_runs.drive', wraps=stage_runs.drive) as driven:
                stage_runs.tick()
            driven.assert_called_once_with(run.pk)
            self.assertEqual(StageRun.objects.get(pk=run.pk).state, 'ready')  # the claim budget ran out: the wait is over
            StageRun.objects.filter(pk=run.pk).update(woke_at=timezone.now() - timedelta(minutes=5))
            with self.captureOnCommitCallbacks() as sent:
                self.assertEqual(stage_runs.tick(), {'requeued': 1})
            self.assertEqual(len(sent), 1)

    def test_the_orphan_reaper_leaves_a_waiting_scan_alone(self):
        ScanHistory.objects.filter(pk=self.scan.pk).update(start_scan_date=timezone.now() - timedelta(hours=1), celery_ids=['gone'])
        with FakeScanner(kinds=['nmap'], async_stages=True) as fake:
            self.waiting_run(fake)
            self.assertEqual(reaper.expire_orphaned_running(live=set()), {})
            self.assertEqual(ScanHistory.objects.get(pk=self.scan.pk).scan_status, 1)
            fake.drain()
        self.assertEqual(reaper.expire_orphaned_running(live=set()), {'ScanHistory': 1})  # once nothing carries it, it is an orphan again

    def test_with_async_stages_off_the_stage_waits_in_its_worker_as_before(self):
        with FakeScanner(kinds=['nmap']):  # async_stages=False: CVENGINE_ASYNC_STAGES=0
            name = adapter('test.sync', lambda ctx: None)
            out = stage_runs.run(name, {}, first=lambda: dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']},
                                                                                     ips=['192.0.2.10'], scan=self.scan))
        self.assertEqual(out['hosts'][0]['ip'], '192.0.2.10')
        self.assertFalse(StageRun.objects.exists())


class MetricsTests(AsyncBase):
    def test_waiting_runs_the_oldest_wait_the_callback_latency_and_the_worker_time_given_back(self):
        with FakeScanner(kinds=['nmap'], async_stages=True) as fake:
            name = adapter('test.metric', lambda ctx: dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']},
                                                                                ips=['192.0.2.10'], scan=self.scan))
            out = stage_runs.run(name, {}, first=lambda: dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']},
                                                                                     ips=['192.0.2.10'], scan=self.scan), project=self.project)
            StageRun.objects.filter(pk=out['stage_run']).update(waiting_since=timezone.now() - timedelta(seconds=90))
            m = stage_runs.metrics()
            self.assertEqual((m['waiting'], m['waiting_by_kind'], m['slots_freed']), (1, {'test.metric': 1}, 1))
            self.assertGreaterEqual(m['oldest_wait_seconds'], 90)
            fake.drain()
        m = stage_runs.metrics()
        self.assertEqual((m['waiting'], m['resumed_1h']), (0, 1))
        self.assertIsNotNone(m['callback_latency_p50_seconds'])
        self.assertGreaterEqual(m['freed_seconds_1h'], 0)
        self.assertEqual(stage_runs.metrics(project_ids=[]), {**stage_runs.metrics(project_ids=[]), 'waiting': 0})

    def test_the_system_status_and_the_live_view_carry_them(self):
        from agentapi import system_status
        from agentapi.services import Ctx
        from django.contrib.auth.models import User
        block = system_status._sentinels([])
        self.assertEqual(block['stage_runs']['waiting'], 0)
        admin = User.objects.create_superuser('q4-admin', 'q4@example.test', 'x')
        self.assertIn('stage_runs', sentinel_broker.live_overview(Ctx(user=admin, token=None)))


class NotifyTests(DispatchBase):
    """The Redis wake-ups that replace the half-second polling."""

    def setUp(self):
        super().setUp()
        self.client = sentinel_notify.client()
        if self.client is None:
            self.skipTest('no Redis')
        for key in self.client.scan_iter(f'{sentinel_notify.PREFIX}:*'):
            self.client.delete(key)

    def test_a_queued_task_wakes_the_long_poll_of_a_sentinel_that_could_take_it_and_not_another(self):
        agent = self.make_sentinel(['nmap'])
        with self.captureOnCommitCallbacks(execute=True):
            SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [IP]}, ips=[IP])
        started = time.monotonic()
        self.assertTrue(sentinel_notify.wait_agent(agent.pk, 5))
        self.assertLess(time.monotonic() - started, 1)  # at once, not at the next poll
        self.assertFalse(sentinel_notify.wait_agent(agent.pk + 1000, 0.2))  # nobody else was woken

    def test_a_reported_or_expired_task_wakes_the_stage_waiting_for_it_and_frees_the_sentinels_poll(self):
        agent = self.make_sentinel(['nmap'])
        task = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [IP]}, ips=[IP], status='claimed', agent=agent,
                                           lease_expires_at=timezone.now() + timedelta(minutes=5))
        with self.captureOnCommitCallbacks(execute=True):
            sentinel_broker.expire(task, 'test')
        self.assertTrue(sentinel_notify.wait_tasks([task.pk], 1))
        self.assertTrue(sentinel_notify.wait_agent(agent.pk, 1))

    def test_the_dispatchers_wait_blocks_on_redis_and_returns_when_woken(self):
        with self.captureOnCommitCallbacks(execute=True):
            sentinel_notify.wake_tasks([4242])
        started = time.monotonic()
        dispatch._wait([4242], 5)
        self.assertLess(time.monotonic() - started, 1)
        started = time.monotonic()
        dispatch._wait([4243], 0.3)  # nothing wakes it: the safety interval (here the budget) ends it
        self.assertGreaterEqual(time.monotonic() - started, 0.25)

    def test_the_long_poll_waits_on_its_wake_key_with_the_safety_interval_and_polls_each_second_while_a_task_is_held_back(self):
        agent = self.make_sentinel(['nmap'])
        with mock.patch.object(sentinel_notify, 'wait_agent') as waited:
            sentinel_broker._await_work(agent, 'no eligible work is queued', 30)
        waited.assert_called_once()
        self.assertEqual(waited.call_args.args[:2], (agent.pk, float(sentinel_notify.safety_seconds())))
        with mock.patch.object(sentinel_notify, 'wait_agent') as waited, mock.patch('agentapi.sentinel_broker.time.sleep') as slept:
            sentinel_broker._await_work(agent, sentinel_broker.HELD_BACK + 'nmap is held for a Sentinel that prefers it)', 30)
        waited.assert_not_called()
        slept.assert_called_once_with(1.0)

    def test_without_redis_every_wait_sleeps_as_before(self):
        with mock.patch.object(sentinel_notify, 'client', return_value=None), mock.patch('time.sleep') as slept:
            self.assertFalse(sentinel_notify.wait_agent(1, 0.5))
            self.assertFalse(sentinel_notify.wait_tasks([1], 0.5))
        self.assertEqual(slept.call_count, 2)

    def test_the_safety_interval_is_read_from_the_environment_and_bounded(self):
        with mock.patch.dict(os.environ, {sentinel_notify.SAFETY_ENV: '2'}):
            self.assertEqual(sentinel_notify.safety_seconds(), 2)
        with mock.patch.dict(os.environ, {sentinel_notify.SAFETY_ENV: '999'}):
            self.assertEqual(sentinel_notify.safety_seconds(), sentinel_notify.MAX_SAFETY)
        with mock.patch.dict(os.environ, {sentinel_notify.SAFETY_ENV: 'x'}):
            self.assertEqual(sentinel_notify.safety_seconds(), sentinel_notify.DEFAULT_SAFETY)


class ResultWakesTheCallbackTests(AsyncBase):
    def test_the_report_of_the_last_task_queues_the_callback_at_once(self):
        with FakeScanner(kinds=['nmap'], async_stages=True) as fake:
            name = adapter('test.wake', lambda ctx: None)
            out = stage_runs.run(name, {}, first=lambda: dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': [IP]}, ips=[IP], scan=self.scan))
            with mock.patch('cveFeed.tasks.stage_run_resume.apply_async') as queued, self.captureOnCommitCallbacks(execute=True):
                fake.serve_once()
            self.assertEqual(StageRun.objects.get(pk=out['stage_run']).state, 'ready')
            queued.assert_called_once_with((out['stage_run'],), queue='discovery_queue')
            fake.drain()


class ReplayTests(TestCase):
    """The engine's own rules, without a scanner."""

    def test_a_context_that_cannot_be_stored_runs_blocking(self):
        stage_runs.adapter('test.plain')(lambda ctx: 'x')
        self.addCleanup(stage_runs.ADAPTERS.pop, 'test.plain', None)
        with mock.patch.dict(os.environ, {'CVENGINE_ASYNC_STAGES': '1'}):
            self.assertEqual(stage_runs.run('test.plain', {'runner': object()}, first=lambda: 'ran'), 'ran')
            self.assertEqual(stage_runs.run('test.plain', {}, first=lambda: 'ran'), 'ran')
        self.assertFalse(StageRun.objects.exists())  # a stage that never waited writes no row

    def test_the_key_of_a_dispatch_leaves_out_the_token_and_the_template_policy(self):
        a = stage_runs.task_key('wpscan', {'url': 'https://example.test', 'token': 'secret'})
        self.assertEqual(a, stage_runs.task_key('wpscan', {'url': 'https://example.test', 'token': '***'}))
        self.assertNotEqual(a, stage_runs.task_key('wpscan', {'url': 'https://other.example.test'}))
        self.assertEqual(stage_runs.task_key('nuclei_light', {'targets': ['a'], 'template_policy': {'rev': 1}}),
                         stage_runs.task_key('nuclei_light', {'targets': ['a'], 'template_policy': {'rev': 2}}))

    def test_a_signed_in_dispatch_is_other_work_than_the_same_scan_without_the_sign_in(self):
        plain = stage_runs.task_key('nuclei_light', {'targets': ['a']})
        self.assertEqual(plain, stage_runs.task_key('nuclei_light', {'targets': ['a']}, secret_ref=None))  # no sign-in: the key is what it always was
        signed = stage_runs.task_key('nuclei_light', {'targets': ['a']}, secret_ref='ref-1')
        self.assertNotEqual(plain, signed)
        self.assertNotEqual(signed, stage_runs.task_key('nuclei_light', {'targets': ['a']}, secret_ref='ref-2'))

    def test_once_outside_a_run_just_calls(self):
        self.assertEqual(stage_runs.once('x', lambda: 5), 5)
        self.assertIsNone(stage_runs.current())

    def test_resources_claim_is_held_across_a_suspend_and_taken_back(self):
        if getattr(resources.get_store(), 'r', None) is None:
            self.skipTest('no Redis')
        p = stage_runs.Pass(StageRun(kind='test.claim'), 'test.claim')
        stage_runs._local.active = p
        try:
            claim = stage_runs.claim_kwargs('svc', 'plain-owner')
            owner = claim.pop('owner')
            with self.assertRaises(stage_runs.Suspend):
                with resources.redis_claim('cvengine:test:q4claim', owner, 60, **claim) as held:
                    self.assertIs(held, True)
                    p.suspend()
            self.assertEqual(p.claims, [('cvengine:test:q4claim', owner)])
            with resources.redis_claim('cvengine:test:q4claim', 'another', 60) as held:
                self.assertNotEqual(held, True)  # held for the waiting run
            with resources.redis_claim('cvengine:test:q4claim', owner, 60, **claim) as held:
                self.assertIs(held, True)  # its next pass takes it back
        finally:
            stage_runs._local.active = None
            stage_runs._release_claims(p.claims)


class SweepTests(RouteFixture, TestCase):
    """A sweep (the testssl.sh audit) under a StageRun: one target per wait, the next pass takes the batch up where it stopped, and a second firing
    does not start while one waits."""

    def setUp(self):
        super().setUp()
        self.scan(names=('a.rt.test', 'b.rt.test'), ports=((443, 'https'),))
        LocalFallback('none').apply(self)
        for patcher in (mock.patch('reNgine.resources.global_pause_requested', return_value=False),
                        mock.patch('cveFeed.testssl_scan.installed', return_value=True),
                        mock.patch('cveFeed.testssl_scan._address', return_value='203.0.113.5'),
                        mock.patch('cveFeed.ledger.sweep_claim', return_value=True)):
            patcher.start()

    def test_each_target_waits_without_the_worker_and_none_is_audited_twice(self):
        from cveFeed import testssl_scan
        from tests.test_testssl_scan import CLEAN
        guard = assert_ran_nowhere_locally(self, 'testssl')
        with FakeScanner(kinds=['testssl'], responders={'testssl': {'outcome': 'done', 'items': CLEAN}}, async_stages=True) as fake:
            first = testssl_scan.sweep_all()
            self.assertTrue(stage_runs.is_waiting(first))
            self.assertEqual(testssl_scan.sweep_all(), {'skipped': 'another sweep is running (it waits on a Sentinel)'})
            fake.drain()
        self.assertEqual(sorted(t['target']['host'] for t in fake.served), ['a.rt.test', 'b.rt.test'])  # each once, one wait each
        self.assertEqual(sorted(ServiceRun.objects.filter(service=testssl_scan.SERVICE).values_list('asset', 'status')),
                         [('a.rt.test:443', 'done'), ('b.rt.test:443', 'done')])
        self.assertEqual(StageRun.objects.get().rounds, 2)
        self.assertEqual(guard.calls, [])
        self.assertFalse(AgentActivity.objects.filter(status='running').exists())
