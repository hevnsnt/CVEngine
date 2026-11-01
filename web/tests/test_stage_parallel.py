"""One scan stage fanned out across Sentinel slots (``sentinel_dispatch.dispatch_many`` and the nmap, naabu and nuclei callers built on it).

``FakeSentinels`` is a small harness for the Sentinels: it is driven by the dispatcher's own ``time.sleep`` (which also advances a fake
clock), claims queued tasks for whichever of its agents has a free slot, finishes them after a simulated duration and keeps the numbers the
tests assert on (how many tasks of the stage were in flight at once, in what order they were created). No threads, no real waiting."""
import contextlib
import os
import tempfile
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import nuclei_scan
from reNgine import resources
from startScan.models import ScanHistory, Subdomain
from tests.test_sentinel_dispatch import DispatchBase

ACTIVE = ('queued', 'claimed', 'running')
OTHER_KINDS = ('testssl', 'nuclei_deep')  # tasks a test plants as other work: the harness never claims or counts them


def chunks_of(n, size=2):
    return [[f'192.0.2.{i * size + j + 1}' for j in range(size)] for i in range(n)]


class FakeSentinels:
    """Sentinels in a test. ``duration(index)`` is how many simulated seconds a chunk runs for once claimed, ``outcome(index)`` is 'done', 'failed'
    or 'hang' (claimed and never reported), and ``answer(task)`` builds the result. ``index_of(task)`` finds a task's chunk from its target."""

    def __init__(self, agents, chunks, duration=lambda i: 4, outcome=lambda i: 'done', answer=None, claim=True):
        self.agents, self.chunks = agents, chunks
        self.duration, self.outcome, self.claim = duration, outcome, claim
        self.answer = answer or self.default_answer
        self.clock = 1000.0
        self.wall0 = timezone.now()  # the wall clock the code under test sees is this plus the simulated seconds, so ages and leases agree with the fake monotonic clock
        self.claimed_at = {}  # task pk -> clock when the harness claimed it
        self.peak_inflight = self.peak_claimed = self.sleeps = 0
        self.hooks = []  # (tick number, callable)
        self.heartbeating = True

    def index_of(self, task):
        target = task.target.get('addresses') or task.target.get('targets')
        return next(i for i, chunk in enumerate(self.chunks) if set(target) <= set(chunk))

    def default_answer(self, task):
        if task.kind == 'naabu':
            return {'outcome': 'done', 'ports': {ip: [22] for ip in task.target['addresses']}}
        if task.kind == 'nmap':
            return {'outcome': 'done', 'hosts': [{'ip': ip, 'os_guess': '', 'ports': []} for ip in task.target['addresses']]}
        return {'outcome': 'done', 'findings': [{'template_id': 'tech-detect', 'name': 'nginx', 'severity': 'info', 'host': host,
                                                 'matched_at': f'https://{host}/', 'matcher_name': 'nginx', 'tags': []} for host in task.target['targets']]}

    def monotonic(self):
        return self.clock

    def wall(self):
        return self.wall0 + timedelta(seconds=self.clock - 1000.0)

    def sleep(self, seconds):
        self.clock += max(seconds, 0.01)
        self.sleeps += 1
        self.tick()
        for number, hook in list(self.hooks):
            if self.sleeps >= number:
                self.hooks.remove((number, hook))
                hook()

    def tick(self):
        if self.heartbeating:  # the Sentinels heartbeat: they stay live, and keep their leases
            Agent.objects.filter(pk__in=[a.pk for a in self.agents]).update(last_seen=self.wall())
        if self.heartbeating:
            SentinelTask.objects.filter(status__in=('claimed', 'running'), pk__in=list(self.claimed_at)).update(lease_expires_at=self.wall() + timedelta(minutes=5))
        for task in SentinelTask.objects.filter(status='claimed', pk__in=list(self.claimed_at)).order_by('id'):
            index = self.index_of(task)
            if self.clock - self.claimed_at[task.pk] < self.duration(index):
                continue
            outcome = self.outcome(index)
            if outcome == 'done':
                SentinelTask.objects.filter(pk=task.pk).update(status='done', result=self.answer(task), finished_at=self.wall())
            elif outcome == 'failed':
                SentinelTask.objects.filter(pk=task.pk).update(status='failed', error='boom', finished_at=timezone.now())
        if self.claim:
            for task in SentinelTask.objects.filter(status='queued').exclude(kind__in=OTHER_KINDS).order_by('-priority', 'id'):
                for agent in self.agents:
                    held = SentinelTask.objects.filter(agent=agent, status__in=('claimed', 'running')).count()
                    if held < agent.max_concurrent and task.kind in agent.capabilities:
                        SentinelTask.objects.filter(pk=task.pk, status='queued').update(
                            status='claimed', agent=agent, claimed_at=self.wall(), lease_expires_at=self.wall() + timedelta(minutes=5))
                        self.claimed_at[task.pk] = self.clock
                        break
        stage = SentinelTask.objects.filter(status__in=ACTIVE).exclude(kind__in=OTHER_KINDS)
        self.peak_inflight = max(self.peak_inflight, stage.count())
        self.peak_claimed = max(self.peak_claimed, stage.exclude(status='queued').count())

    def run(self, call):
        with mock.patch('agentapi.sentinel_dispatch.time.monotonic', side_effect=self.monotonic), \
                mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=self.sleep), \
                mock.patch('django.utils.timezone.now', side_effect=self.wall):
            return call()


class StageBase(DispatchBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ('CVENGINE_STAGE_PARALLEL', 'CVENGINE_SENTINEL_DISPATCH_TIMEOUT'):
            os.environ.pop(name, None)
        resources.clear_abort(self.scan.id)
        self.addCleanup(resources.clear_abort, self.scan.id)

    def agent(self, name, capabilities=('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted'), slots=2):
        user = User.objects.create_user(f'owner-{name}', password='x')
        token, _raw = create_token(user, f'token-{name}')
        return Agent.objects.create(token=token, name=name, kind='scanner', status='active', max_concurrent=slots,
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=list(capabilities), last_seen=timezone.now(),
                                    network='internal' if 'network:internal' in capabilities else 'external')

    def two_agents(self, slots=2):
        return [self.agent('sentinel-a', slots=slots), self.agent('sentinel-b', slots=slots)]

    def fan_out(self, fake, kind='nmap', **kw):
        got = []

        def call():
            for index, result in dispatch.dispatch_many(self.project, kind, fake.chunks, scan=self.scan, **kw):
                got.append((index, result))
        fake.run(call)
        return got

    def active_tasks(self):
        return SentinelTask.objects.filter(status__in=ACTIVE).count()


class WindowTests(StageBase):
    def test_eight_chunks_over_four_free_slots_keep_at_most_four_in_flight_and_refill_as_they_finish(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(8), duration=lambda i: 2 + i)  # each finishes at a different moment
        got = self.fan_out(fake)
        self.assertEqual(sorted(i for i, _ in got), list(range(8)))
        self.assertTrue(all(result is not None for _, result in got))
        self.assertEqual(fake.peak_inflight, 4)  # four free slots (and the ceiling is four)
        self.assertEqual(fake.peak_claimed, 4)
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 8)  # every chunk a task of its own, created as the window made room
        self.assertEqual(self.active_tasks(), 0)

    def test_each_chunks_result_belongs_to_its_chunk_and_they_arrive_as_they_finish_not_in_order(self):
        chunks = chunks_of(4)
        fake = FakeSentinels(self.two_agents(), chunks, duration=lambda i: 30 if i == 0 else 3)  # the first chunk is the slowest
        got = self.fan_out(fake)
        for index, result in got:
            self.assertEqual([h['ip'] for h in result['hosts']], chunks[index])
        self.assertEqual(got[-1][0], 0)  # the slow one lands last, though it was sent first
        self.assertEqual(sorted(i for i, _ in got), [0, 1, 2, 3])

    def test_the_window_is_the_free_slots_never_more(self):
        agents = self.two_agents()  # four slots
        for _ in range(2):  # two of them held by other work, so two are free
            SentinelTask.objects.create(project=self.project, kind='testssl', target={}, agent=agents[0], status='running',
                                        lease_expires_at=timezone.now() + timedelta(minutes=5))
        fake = FakeSentinels(agents, chunks_of(8), duration=lambda i: 5)
        got = self.fan_out(fake)
        self.assertEqual(len(got), 8)
        self.assertEqual(fake.peak_inflight, 2)  # the 2 free slots: no chunk task is created to queue behind its own stage's
        self.assertEqual(fake.peak_claimed, 2)

    def test_a_ceiling_below_the_free_slots_wins(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(8), duration=lambda i: 5)
        with mock.patch.dict(os.environ, {'CVENGINE_STAGE_PARALLEL': '2'}):
            got = self.fan_out(fake)
        self.assertEqual((len(got), fake.peak_inflight), (8, 2))

    def test_one_scan_does_not_take_every_slot_when_other_scans_dispatch_too(self):
        agents = self.two_agents(slots=2)
        for _ in range(3):  # three other scans with a stage waiting: four slots, so two chunk tasks each (twice the slots shared four ways)
            other = ScanHistory.objects.create(domain=self.domain, scan_type=self.scan.scan_type, start_scan_date=timezone.now(),
                                               scan_status=1, results_dir='/tmp')
            SentinelTask.objects.create(project=self.project, scan=other, kind='nuclei_deep', target={}, status='queued')
        self.assertEqual(dispatch._stage_share(self.scan, 'nmap', 4), 2)
        self.assertEqual(dispatch._stage_share(self.scan, 'nmap', 0), 1)  # never below one
        fake = FakeSentinels(agents, chunks_of(8), duration=lambda i: 5)
        got = self.fan_out(fake)
        self.assertEqual(len(got), 8)
        self.assertEqual(fake.peak_inflight, 2)

    @mock.patch.object(dispatch, 'DISPATCH_POLL_INTERVAL', 5)  # a coarser poll keeps the simulated half hour short
    def test_a_one_slot_sentinel_with_a_long_first_chunk_keeps_the_stage_serial_as_before(self):
        from agentapi import sentinel_broker
        ttl = sentinel_broker.queued_ttl('nmap').total_seconds()
        fake = FakeSentinels([self.agent('solo', slots=1)], chunks_of(3), duration=lambda i: ttl * 2.5 if i == 0 else 5)  # the first runs far past what the reaper allows a queued task
        got = dict(self.fan_out(fake, timeout=ttl * 4))
        self.assertTrue(all(result is not None for result in got.values()), got)  # nothing was sent to run here
        self.assertEqual(fake.peak_inflight, 1)  # one chunk task at a time: none is queued behind its own stage's
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 3)
        self.assertEqual(SentinelTask.objects.filter(status='expired').count(), 0)

    @mock.patch.object(dispatch, 'DISPATCH_POLL_INTERVAL', 5)
    def test_a_chunk_queued_behind_its_own_stage_is_given_up_by_the_loop_before_the_reaper_and_says_so(self):
        """The safety net: should a chunk end up queued behind its own stage's claimed chunks, it waits no longer than the reaper would let a queued
        task, and it is the loop that ends it (the stage stops sending, the activity line says no slot freed up), not the reaper."""
        from agentapi import sentinel_broker
        from cveFeed.models import AgentActivity
        ttl = sentinel_broker.queued_ttl('nmap').total_seconds()
        fake = FakeSentinels([self.agent('solo', slots=1)], chunks_of(4), duration=lambda i: ttl * 3 if i == 0 else 5)
        real = sentinel_broker.capacity_state
        calls = []

        def two_free_slots_once(*args, **kwargs):  # the first look says two slots are free, though the Sentinel has one
            state = real(*args, **kwargs)
            calls.append(1)
            return {**state, 'free': 2} if len(calls) == 1 else state
        with mock.patch.object(sentinel_broker, 'capacity_state', two_free_slots_once):
            got = dict(self.fan_out(fake, timeout=ttl * 4))
        self.assertIsNone(got[1])  # the queued chunk was given up, to run here
        self.assertIsNotNone(got[0])
        queued = SentinelTask.objects.get(kind='nmap', target__addresses=fake.chunks[1])
        self.assertEqual(queued.status, 'expired')
        self.assertIn('no Sentinel slot freed up in time', queued.error)  # step ended it, not reap_expired ('while it waited in the queue')
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 2)  # and the stage stopped sending: chunks 2 and 3 were never created
        self.assertEqual([got[2], got[3]], [None, None])
        self.assertTrue(AgentActivity.objects.filter(message__contains='No Sentinel slot freed up for nmap work').exists())
        self.assertFalse(AgentActivity.objects.filter(message__contains='No Sentinel checked in nmap work').exists())

    def test_one_poll_read_per_tick_whatever_the_number_of_chunks_in_flight(self):
        agents = self.two_agents()
        for n in (4, 8):
            SentinelTask.objects.all().delete()
            fake = FakeSentinels(agents, chunks_of(n), duration=lambda i: 5)
            with CaptureQueriesContext(connection) as queries:
                self.fan_out(fake)
            reads = [q for q in queries if 'FROM "agentapi_sentineltask"' in q['sql'] and '"id" IN' in q['sql'] and '"status"' not in q['sql']]  # not the harness's own
            self.assertLessEqual(len(reads), fake.sleeps + 1)  # one read of every task in flight per tick, not one per task


class FallbackTests(StageBase):
    def test_a_failed_chunk_and_an_expired_one_fall_back_alone_and_the_rest_carry_on(self):
        outcomes = {1: 'failed', 3: 'hang'}
        fake = FakeSentinels(self.two_agents(), chunks_of(6), outcome=lambda i: outcomes.get(i, 'done'))
        got = dict(self.fan_out(fake, timeout=40))
        self.assertEqual([i for i, result in sorted(got.items()) if result is None], [1, 3])
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 6)  # a failure does not stop the chunks after it
        self.assertEqual(list(SentinelTask.objects.filter(status='expired').values_list('error', flat=True)),
                         ['the dispatch wait timed out; the stage fell back to local execution'])
        self.assertEqual(self.active_tasks(), 0)

    def test_no_live_sentinel_creates_nothing_and_every_chunk_is_left_to_run_here(self):
        got = self.fan_out(FakeSentinels([], chunks_of(5)))
        self.assertEqual(got, [(i, None) for i in range(5)])
        self.assertFalse(SentinelTask.objects.exists())

    def test_the_sentinels_going_away_stops_the_fan_out_and_the_chunks_not_sent_are_left_to_run_here(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(8), duration=lambda i: 3)
        def go_quiet():
            fake.heartbeating = False
            Agent.objects.update(last_seen=fake.wall() - timedelta(hours=1))
        fake.hooks.append((1, go_quiet))  # both go quiet after the first tick
        got = dict(self.fan_out(fake))
        sent = SentinelTask.objects.filter(kind='nmap').count()
        self.assertLess(sent, 8)
        self.assertEqual(sorted(got), list(range(8)))  # every chunk is accounted for
        self.assertTrue(all(result is None for i, result in got.items() if i >= sent))  # the unsent ones are the caller's, in order
        self.assertEqual(self.active_tasks(), 0)

    def test_a_sentinel_that_never_claims_stops_the_fan_out_after_the_first_window(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(10), claim=False)
        got = dict(self.fan_out(fake))
        self.assertTrue(all(result is None for result in got.values()))
        self.assertEqual(sorted(got), list(range(10)))
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 4)  # one window, not ten waits of the claim timeout
        self.assertEqual(set(SentinelTask.objects.values_list('status', flat=True)), {'expired'})


class StopTests(StageBase):
    def test_a_stop_cancels_every_outstanding_chunk_task_and_raises_scan_aborted(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(8), duration=lambda i: 500)  # long enough that all are outstanding when it stops
        fake.hooks.append((6, lambda: resources.request_abort(self.scan.id)))
        with self.assertRaises(resources.ScanAborted):
            self.fan_out(fake)
        self.assertEqual(self.active_tasks(), 0)  # none queued, none still claimed
        self.assertEqual(set(SentinelTask.objects.values_list('status', flat=True)), {'expired'})
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 4)  # and no more were sent once it stopped

    def test_a_global_pause_stops_it_the_same_way(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(8), duration=lambda i: 500)
        paused = {'on': False}
        fake.hooks.append((4, lambda: paused.update(on=True)))
        with mock.patch('reNgine.resources.global_pause_requested', side_effect=lambda fail_closed=False: paused['on']), \
                self.assertRaises(resources.ScanAborted):
            self.fan_out(fake)
        self.assertEqual(self.active_tasks(), 0)

    def test_a_consumer_that_stops_early_leaves_no_orphan_task(self):
        fake = FakeSentinels(self.two_agents(), chunks_of(8), duration=lambda i: 3 + 10 * i)

        def call():
            with contextlib.closing(dispatch.dispatch_many(self.project, 'nmap', fake.chunks, scan=self.scan)) as results:
                next(results)  # the first result lands; the consumer fails before asking for more
        fake.run(call)
        self.assertEqual(self.active_tasks(), 0)

    def test_an_error_in_the_caller_while_it_holds_a_result_leaves_no_orphan_task(self):
        ips = [f'198.51.100.{i}' for i in range(1, 201)]  # four chunks
        fake = FakeSentinels(self.two_agents(), dispatch._chunks(ips), duration=lambda i: 3 + 100 * i)
        with mock.patch('cveFeed.nmap_scan.persist_inventory', side_effect=RuntimeError('db down')), self.assertRaises(RuntimeError):
            fake.run(lambda: dispatch.try_nmap(self.project, self.scan, ips))
        self.assertEqual(SentinelTask.objects.filter(kind='nmap').count(), 4)  # all four were out when the first result failed to be saved
        self.assertEqual(self.active_tasks(), 0)


class SerialTests(StageBase):
    def test_a_stage_parallel_of_one_is_the_old_serial_behaviour_task_for_task(self):
        chunks = chunks_of(5)
        agents = self.two_agents()
        fake = FakeSentinels(agents, chunks, duration=lambda i: 3)
        with mock.patch.dict(os.environ, {'CVENGINE_STAGE_PARALLEL': '1'}):
            got = self.fan_out(fake)
        self.assertEqual([i for i, _ in got], list(range(5)))  # in order
        self.assertEqual(fake.peak_inflight, 1)
        self.assertEqual([t.target['addresses'] for t in SentinelTask.objects.filter(kind='nmap').order_by('id')], chunks)  # one task per chunk, one after the other

        SentinelTask.objects.all().delete()  # the loop that was there before, over the same chunks
        old = []
        fake_old = FakeSentinels(agents, chunks, duration=lambda i: 3)
        fake_old.run(lambda: old.extend(dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': c}, ips=c, scan=self.scan) for c in chunks))
        self.assertEqual([t.target['addresses'] for t in SentinelTask.objects.filter(kind='nmap').order_by('id')], chunks)
        self.assertEqual(fake_old.peak_inflight, 1)
        self.assertEqual(old, [result for _, result in got])

    def test_a_stop_on_none_serial_run_ends_at_the_first_chunk_nobody_took(self):
        calls = []

        def fake_dispatch(project, kind, target, **kw):
            calls.append(target['addresses'])
            return None
        with mock.patch.dict(os.environ, {'CVENGINE_STAGE_PARALLEL': '1'}), mock.patch.object(dispatch, 'dispatch_or_none', fake_dispatch):
            got = list(dispatch.dispatch_many(self.project, 'nmap', chunks_of(4), stop_on_none=True))
        self.assertEqual(len(calls), 1)
        self.assertEqual(got, [(i, None) for i in range(4)])

    def test_the_ceiling_setting_is_read_and_defaults_to_four(self):
        self.assertEqual(dispatch.stage_parallel(), 4)
        for raw, expected in (('1', 1), ('8', 8), ('0', 1), ('-3', 1), ('x', 4), ('', 4)):
            with mock.patch.dict(os.environ, {'CVENGINE_STAGE_PARALLEL': raw}):
                self.assertEqual(dispatch.stage_parallel(), expected, raw)


class CallerTests(StageBase):
    """The callers, end to end through the fake Sentinels."""

    def test_nmap_chunks_are_persisted_as_each_lands_and_a_chunk_nobody_did_stays_for_the_local_pass(self):
        ips = [f'198.51.100.{i}' for i in range(1, 161)]  # three chunks: 64, 64, 32
        chunks = [ips[:64], ips[64:128], ips[128:]]
        fake = FakeSentinels(self.two_agents(), chunks, outcome=lambda i: 'failed' if i == 1 else 'done')
        saved = []

        def persist(inventory, org_id=None, os_reliable=True):
            saved.append([h['ip'] for h in inventory])
            return {'ports': len(inventory), 'hosts_with_os': 0}
        with mock.patch('cveFeed.nmap_scan.persist_inventory', side_effect=persist):
            remaining, totals, _ = fake.run(lambda: dispatch.try_nmap(self.project, self.scan, ips))
        self.assertEqual(remaining, chunks[1])  # the failed chunk, and only it
        self.assertEqual(totals['ports'], 96)
        self.assertEqual(sorted(sum(saved, [])), sorted(chunks[0] + chunks[2]))
        self.assertEqual(fake.peak_inflight, 3)

    def test_naabu_merges_every_chunk_and_scans_only_the_failed_one_here(self):
        ips = [f'198.51.100.{i}' for i in range(1, 151)]
        chunks = [ips[:64], ips[64:128], ips[128:]]
        fake = FakeSentinels(self.two_agents(), chunks, outcome=lambda i: 'failed' if i == 2 else 'done')
        local = mock.Mock(return_value={ips[140]: [443]})
        with mock.patch('cveFeed.naabu_scan.run_naabu', local):
            found = fake.run(lambda: dispatch.wrap_naabu_runner(self.project, self.scan)(ips))
        local.assert_called_once_with(chunks[2])
        self.assertEqual(set(found), set(ips[:128]) | {ips[140]})
        self.assertEqual(found[ips[0]], [22])

    def _targets(self, n):
        targets = [f'h{i}.example.test' for i in range(n)]
        path = os.path.join(tempfile.mkdtemp(), 'targets.txt')
        with open(path, 'w') as handle:
            handle.write('\n'.join(targets))
        return targets, path

    def test_the_nuclei_stream_still_yields_every_line_of_every_chunk_and_runs_an_unserved_chunk_here_last(self):
        targets, path = self._targets(dispatch.MAX_ADDRESSES * 3 + 7)
        chunks = dispatch._chunks(targets)
        fake = FakeSentinels(self.two_agents(), chunks, outcome=lambda i: 'failed' if i == 1 else 'done')
        local = []

        def local_stream(targets_file, **kw):
            with open(targets_file) as handle:
                local.append(handle.read().split())
            return iter([{'host': 'local.example.test'}])
        with mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True), mock.patch('cveFeed.nuclei_scan.stream_nuclei', local_stream):
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
            lines = fake.run(lambda: list(stream(path)))
        hosts = [line['host'] for line in lines]
        self.assertEqual(sorted(h for h in hosts if h != 'local.example.test'), sorted(chunks[0] + chunks[2] + chunks[3]))
        self.assertEqual(hosts[-1], 'local.example.test')  # the Sentinels' chunks first, the local one once they are in
        self.assertEqual(local, [chunks[1]])
        self.assertEqual(fake.peak_inflight, 4)

    def test_the_internal_nuclei_stream_fans_out_too_and_raises_for_an_unanswered_chunk(self):
        targets, path = self._targets(dispatch.MAX_ADDRESSES * 2)
        chunks = dispatch._chunks(targets)
        agents = [self.agent('inner', capabilities=('nuclei_light', 'network:internal'), slots=2)]
        fake = FakeSentinels(agents, chunks)
        stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', internal=True)
        lines = fake.run(lambda: list(stream(path)))
        self.assertEqual(len(lines), len(targets))
        self.assertEqual(fake.peak_inflight, 2)
        SentinelTask.objects.all().delete()
        fake = FakeSentinels(agents, chunks, outcome=lambda i: 'failed')
        with self.assertRaises(RuntimeError):
            fake.run(lambda: list(stream(path)))
        self.assertEqual(self.active_tasks(), 0)

    def test_the_light_pass_hands_the_whole_list_to_the_sentinel_wrapper_and_100_at_a_time_to_a_local_stream(self):
        for i in range(150):
            Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=f'h{i}.example.test')
        seen = []

        def spy(real):
            def stream(path, **kwargs):
                seen.append(len(open(path).read().split()))
                return real(path, **kwargs)
            stream.chunks_itself = getattr(real, 'chunks_itself', False)
            return stream

        def sentinels():
            fake = FakeSentinels(agents, [], duration=lambda i: 3)
            fake.index_of = lambda task: 0
            fake.answer = lambda task: {'outcome': 'done', 'findings': []}
            return fake
        agents = self.two_agents()
        with mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True):
            real = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')
            fake = sentinels()
            out = fake.run(lambda: nuclei_scan.run_light_nuclei(self.scan.id, stream=spy(real)))
        self.assertNotIn('error', out)
        self.assertEqual(seen, [out['targets']])  # one call with everything
        self.assertGreater(out['targets'], nuclei_scan.NUCLEI_CHUNK)
        self.assertEqual(SentinelTask.objects.filter(kind='nuclei_light').count(), -(-out['targets'] // dispatch.MAX_ADDRESSES))
        self.assertGreater(fake.peak_inflight, 1)  # the chunks ran side by side

        SentinelTask.objects.all().delete()
        seen.clear()
        with mock.patch.dict(os.environ, {'CVENGINE_STAGE_PARALLEL': '1'}), mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True):
            fake = sentinels()
            fake.run(lambda: nuclei_scan.run_light_nuclei(self.scan.id, stream=spy(real), force=True))
        self.assertEqual((len(seen), seen[0]), (2, nuclei_scan.NUCLEI_CHUNK))  # the serial behaviour exactly: 100, then the rest
        self.assertEqual(fake.peak_inflight, 1)

        seen.clear()  # a stream that is not the wrapper (a test's, or the local one) keeps its chunking whatever the setting
        nuclei_scan.run_light_nuclei(self.scan.id, stream=lambda path, **kw: seen.append(len(open(path).read().split())) or iter(()), force=True)
        self.assertEqual((len(seen), seen[0]), (2, nuclei_scan.NUCLEI_CHUNK))


class LedgerTests(StageBase):
    def test_a_failure_after_some_calls_finished_marks_only_the_unfinished_targets_failed(self):
        from cveFeed import ledger
        for i in range(600):
            Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=f'h{i}.example.test')
        calls = []

        def stream(path, **kwargs):
            with open(path) as handle:
                calls.append(handle.read().split())
            if len(calls) == 3:
                raise RuntimeError('no Sentinel inside the network answered')
            return iter(())
        stream.chunks_itself = True  # what the Sentinel wrapper declares
        out = nuclei_scan.run_light_nuclei(self.scan.id, stream=stream)
        self.assertEqual([len(c) for c in calls[:2]], [256, 256])  # enough per call to fill the window, no more
        self.assertIn('error', out)
        done = set(ledger.fresh(nuclei_scan.LIGHT_SERVICE, sum(calls, []), self.project.pk))
        self.assertEqual(done, set(calls[0] + calls[1]))  # what the finished calls covered stays recorded as scanned
        self.assertFalse(done & set(calls[2]))  # only the call that failed is not
