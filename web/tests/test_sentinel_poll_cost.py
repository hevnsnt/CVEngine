"""What a Sentinel's long poll, its heartbeat and the task lists cost in the database, with the claim's lock and state rules unchanged: ``last_seen`` is
written at most every ``TOUCH_EVERY``, the later rounds of a poll reap at most every few seconds fleet wide, two Sentinels claiming in turn take every
task once in queue order, the rights of many Sentinels read their failure streaks in one query (the same answer as one query each), and the lists never
read a result too large to show."""
import json
import re
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import sentinel_broker as sb
from agentapi.models import Agent, SentinelTask
from dashboard.models import AuditLog, Project
from tests.test_sentinels import SentinelBase, call, register_sentinel


class Clock:
    """``time`` for ``sentinel_broker``: a long poll's deadline and its one-second waits run on this clock, so a 5 s poll is six rounds and takes no time."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, 0.01)


def _agent_updates(queries):
    return [q['sql'] for q in queries if q['sql'].startswith('UPDATE "agentapi_agent"')]


def _reaper_selects(queries):
    return [q['sql'] for q in queries if q['sql'].startswith('SELECT') and '"agentapi_sentineltask"."lease_expires_at" <' in q['sql']]


class Base(SentinelBase):
    def setUp(self):
        super().setUp()
        cache.delete('sentinel:poll-reap')
        cache.delete('agentapi:poll-reap')
        self.project = Project.objects.get(slug='sen-a')

    def sentinel(self, user='dana', **override):
        status, out = register_sentinel(self.t[user], name=f'poll-{user}', **override)
        self.assertIn(status, (200, 201), out)
        return Agent.objects.get(pk=out['id'])

    def queue(self, ip='192.0.2.50', priority=1, age=timedelta(seconds=0), **fields):
        task = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [ip]}, ips=[ip], priority=priority, **fields)
        if age:
            SentinelTask.objects.filter(pk=task.pk).update(created_at=timezone.now() - age)
        return task


class TouchTests(Base):
    def test_a_fresh_last_seen_is_not_written_again(self):
        agent = self.sentinel()
        now = timezone.now()
        Agent.objects.filter(pk=agent.pk).update(last_seen=now - timedelta(seconds=5))
        agent.refresh_from_db()
        with self.assertNumQueries(0):
            broker._touch(agent, now)
        agent.refresh_from_db()
        self.assertEqual(agent.last_seen, now - timedelta(seconds=5))

    def test_an_old_missing_or_future_last_seen_is_written(self):
        agent = self.sentinel()
        now = timezone.now()
        for stored in (now - broker.TOUCH_EVERY - timedelta(seconds=1), None, now + timedelta(minutes=5)):
            Agent.objects.filter(pk=agent.pk).update(last_seen=stored)
            agent.refresh_from_db()
            with self.assertNumQueries(1):
                broker._touch(agent, now)
            self.assertEqual(agent.last_seen, now)
            agent.refresh_from_db()
            self.assertEqual(agent.last_seen, now, stored)

    def test_the_update_itself_leaves_a_time_another_call_just_wrote(self):
        agent = self.sentinel()
        now = timezone.now()
        Agent.objects.filter(pk=agent.pk).update(last_seen=now - timedelta(minutes=1))
        agent.refresh_from_db()
        Agent.objects.filter(pk=agent.pk).update(last_seen=now - timedelta(seconds=2))  # another request of the same Sentinel, meanwhile
        broker._touch(agent, now)
        self.assertEqual(Agent.objects.get(pk=agent.pk).last_seen, now - timedelta(seconds=2))

    def test_liveness_is_unchanged_by_the_throttle(self):
        agent = self.sentinel()
        now = timezone.now()
        Agent.objects.filter(pk=agent.pk).update(last_seen=now - timedelta(seconds=10))
        agent.refresh_from_db()
        broker._touch(agent, now)
        self.assertTrue(sb.effective(agent, now).live)


class Gate:
    """``agent_broker.poll_reap_due`` over a dict instead of the shared cache (another test run may flush it), on the poll's own clock."""

    def __init__(self, clock):
        self.clock, self.until = clock, {}

    def __call__(self, key):
        if self.until.get(key, 0) > self.clock.now:
            return False
        self.until[key] = self.clock.now + broker.POLL_REAP_EVERY
        return True


class PollRoundTests(Base):
    def poll(self, token, wait):
        clock = Clock()
        with mock.patch.object(sb, 'time', clock), mock.patch.object(broker, 'poll_reap_due', Gate(clock)), CaptureQueriesContext(connection) as q:
            status, out = call(token, 'POST', '/api/v1/sentinel/tasks/next', {'wait': wait, 'kinds': ['nmap']})
        self.assertEqual(status, 200, out)
        return out, q.captured_queries

    def test_a_long_poll_writes_last_seen_once_and_reaps_once(self):
        agent = self.sentinel()
        Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(minutes=1))
        out, queries = self.poll(self.t['dana'], 4)  # five rounds, all inside one gate interval
        self.assertIsNone(out['task'])
        self.assertEqual(len(_agent_updates(queries)), 1, _agent_updates(queries))  # was one per round (5)
        self.assertEqual(len(_reaper_selects(queries)), 1, _reaper_selects(queries))  # was one per round

    def test_each_later_round_of_a_long_poll_stays_within_its_bound(self):
        self.sentinel()
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0, 'kinds': ['nmap']})  # warm the per-process lookups
        cache.delete('sentinel:poll-reap')
        _, one = self.poll(self.t['dana'], 0)
        _, six = self.poll(self.t['dana'], 5)
        per_round = (len(six) - len(one)) / 5
        self.assertLessEqual(per_round, 20, [x['sql'][:100] for x in six[len(one):]])

    def test_a_round_after_the_gate_lapses_reaps_again(self):
        self.sentinel()
        _, queries = self.poll(self.t['dana'], 12)  # rounds at 0..12 s on the poll's clock: the gate lets one through every 5 s
        self.assertEqual(len(_reaper_selects(queries)), 3)
        with mock.patch.object(broker, 'poll_reap_due', return_value=True), mock.patch.object(sb, 'time', Clock()), \
                CaptureQueriesContext(connection) as q:
            call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 2, 'kinds': ['nmap']})
        self.assertEqual(len(_reaper_selects(q.captured_queries)), 3)  # without the gate (or without the cache) every round reaps, as before

    def test_the_gate_is_one_cache_add(self):
        cache.delete('sentinel:poll-reap')
        self.assertTrue(broker.poll_reap_due('sentinel:poll-reap'))
        self.assertFalse(broker.poll_reap_due('sentinel:poll-reap'))
        with mock.patch.object(broker.cache, 'add', side_effect=RuntimeError('no cache')):
            self.assertTrue(broker.poll_reap_due('sentinel:poll-reap'))  # without the cache every round reaps

    def test_a_task_queued_during_the_poll_is_claimed_in_a_later_round(self):
        self.sentinel()
        clock = Clock()
        queued = []

        def sleep(seconds):
            clock.now += seconds
            if not queued:
                queued.append(self.queue())
        clock.sleep = sleep
        with mock.patch.object(sb, 'time', clock), mock.patch.object(broker, 'poll_reap_due', Gate(clock)):
            status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 5, 'kinds': ['nmap']})
        self.assertEqual(status, 200, out)
        self.assertEqual(out['task']['id'], queued[0].pk)


class SequentialClaimTests(Base):
    def claim(self, user):
        status, out = call(self.t[user], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0, 'kinds': ['nmap']})
        self.assertEqual(status, 200, out)
        return out['task']['id'] if out['task'] else None

    def test_two_claimers_in_turn_take_every_task_once_in_queue_order(self):
        a, b = self.sentinel('dana'), self.sentinel('alice')
        Agent.objects.filter(pk__in=[a.pk, b.pk]).update(max_concurrent=5)
        tasks = [self.queue(priority=p, age=timedelta(seconds=s)) for p, s in ((1, 30), (3, 10), (1, 40), (2, 5), (3, 20))]
        order = [t.pk for t in sorted(tasks, key=lambda t: (-t.priority, SentinelTask.objects.get(pk=t.pk).created_at, t.pk))]
        with mock.patch.object(sb, 'balance_defer_for', return_value=0), mock.patch.object(sb, 'prefer_defer_for', return_value=0):
            got = [self.claim(user) for user in ('dana', 'alice', 'dana', 'alice', 'dana', 'alice', 'dana')]
        self.assertEqual(got[:5], order)
        self.assertEqual(got[5:], [None, None])
        held = dict(SentinelTask.objects.filter(pk__in=order).values_list('pk', 'agent_id'))
        self.assertEqual([held[pk] for pk in order], [a.pk, b.pk, a.pk, b.pk, a.pk])
        self.assertEqual(set(SentinelTask.objects.filter(pk__in=order).values_list('status', flat=True)), {'claimed'})
        self.assertEqual(set(SentinelTask.objects.filter(pk__in=order).values_list('attempts', flat=True)), {1})
        claims = AuditLog.objects.filter(action='sentinel.task.claim').values_list('detail', flat=True)
        self.assertEqual(sorted(d['task_id'] for d in claims), sorted(order))  # one claim row per task, none twice


class FailingKindsTests(Base):
    def finished(self, agent, kind, status, minutes, error=''):
        SentinelTask.objects.create(project=self.project, kind=kind, status=status, agent=agent, error=error,
                                    finished_at=timezone.now() - timedelta(minutes=minutes))

    def test_one_query_gives_what_one_query_per_sentinel_gives(self):
        a, b = self.sentinel('dana'), self.sentinel('alice')
        for m in (1, 2, 3):
            self.finished(a, 'naabu', 'failed', m)  # withheld
            self.finished(b, 'naabu', 'failed', m, error='12 bytes of output; the run was stopped' if m == 2 else 'x')  # one the host caused: not counted
        for m in range(20, 23):
            self.finished(a, 'nmap', 'failed', m)
        with mock.patch.object(sb, 'FAIL_RECENT', 4):  # nmap's failures are past a's latest four: one query each never saw them
            single = {agent.pk: sb.failing_kinds(agent) for agent in (a, b)}
            many = sb.failing_kinds_many([a, b])
        self.assertEqual(set(single[a.pk]), {'naabu'})
        self.assertEqual(single[b.pk], {})
        self.assertEqual(many, single)

    def test_the_rights_of_many_sentinels_read_the_streaks_once(self):
        self.sentinel('dana')
        self.sentinel('alice')
        with CaptureQueriesContext(connection) as q:
            live = sb._live_for(self.project, timezone.now())
        self.assertEqual(len(live), 2)
        streaks = [x for x in q.captured_queries if '"agentapi_sentineltask"' in x['sql'] and "'failed'" in x['sql'].replace('"', "'")]
        self.assertEqual(len(streaks), 1, [x['sql'][:120] for x in streaks])


class ListTests(Base):
    def setUp(self):
        super().setUp()
        self.agent = self.sentinel()
        now = timezone.now()
        cuts = [{'what': 'findings', 'kind': 'items', 'limit': 500, 'dropped': 7}]
        self.big = SentinelTask.objects.create(project=self.project, kind='nmap', status='done', agent=self.agent, finished_at=now, claimed_at=now,
                                               result={'outcome': 'done', 'cuts': cuts, 'partial': True, 'templates_release': 'v1', 'xml': 'x' * 40000})
        self.small = SentinelTask.objects.create(project=self.project, kind='nmap', status='done', agent=self.agent, finished_at=now, claimed_at=now,
                                                 result={'outcome': 'done', 'cuts': cuts, 'hosts': [{'ip': '192.0.2.1'}]})
        self.edge = SentinelTask.objects.create(project=self.project, kind='nmap', status='done', agent=self.agent, finished_at=now, claimed_at=now,
                                                result={'outcome': 'done', 'note': '\u00e9' * 2000})  # under LISTED_LOAD_MAX stored, over the limit once escaped
        self.empty = SentinelTask.objects.create(project=self.project, kind='nmap', status='failed', agent=self.agent, finished_at=now, error='boom')

    def full_rows(self):
        return {t.pk: sb.task_row(t) for t in SentinelTask.objects.filter(agent=self.agent).select_related('project__org', 'agent')}

    def test_recent_tasks_never_read_a_result_too_large_to_show(self):
        before = self.full_rows()
        with CaptureQueriesContext(connection) as q:
            rows = {r['id']: r for r in sb.recent_tasks(self.agent)}
        self.assertEqual(len(q), 2, [x['sql'][:120] for x in q.captured_queries])  # the light page, then the results small enough to show
        load = q.captured_queries[1]['sql']
        self.assertNotIn(str(self.big.pk), re.search(r'IN \(([^)]*)\)', load).group(1).split(', '))
        for pk in (self.small.pk, self.edge.pk, self.empty.pk):
            self.assertEqual(rows[pk], before[pk])  # the same row as before
        big, old = rows[self.big.pk], before[self.big.pk]
        self.assertEqual({k: v for k, v in big.items() if k != 'result'}, {k: v for k, v in old.items() if k != 'result'})
        self.assertTrue(big['result']['omitted'])
        self.assertGreater(big['result']['bytes'], sb.LISTED_RESULT_MAX)
        self.assertTrue(rows[self.edge.pk]['result']['omitted'])
        self.assertEqual(rows[self.small.pk]['result']['hosts'], [{'ip': '192.0.2.1'}])

    def test_the_project_task_list_pages_without_the_large_result(self):
        status, out = call(self.t['dana'], 'GET', '/api/v1/projects/sen-a/sentinel-tasks')
        self.assertEqual(status, 200, out)
        rows = {r['id']: r for r in out['results']}
        self.assertEqual(out['count'], 4)
        self.assertTrue(rows[self.big.pk]['result']['omitted'])
        self.assertEqual(rows[self.big.pk]['cut_notes'], sb.result_notes(self.big.result)['cut_notes'])
        self.assertTrue(rows[self.big.pk]['partly_checked'])
        self.assertEqual(rows[self.big.pk]['templates_release'], 'v1')
        self.assertEqual(rows[self.small.pk]['result'], json.loads(json.dumps(self.small.result)))

    def test_the_sentinels_page_reads_no_result_column(self):
        with mock.patch.object(sb, 'reap_expired', return_value=0), CaptureQueriesContext(connection) as q:  # the reaper reads whole rows it ends (none here)
            status, out = call(self.t['dana'], 'GET', '/api/v1/sentinels/live')
        self.assertEqual(status, 200, out)
        bare = [x['sql'][:160] for x in q.captured_queries if re.search(r'"agentapi_sentineltask"\."result"(,| FROM)', x['sql'])]
        self.assertEqual(bare, [])
        card = next(r for r in out['results'] if r['id'] == self.agent.pk)
        recent = {r['id']: r for r in card['recent']}
        self.assertEqual(recent[self.big.pk]['outcome'], 'completed at its time budget (partial)')
        self.assertEqual(recent[self.big.pk]['cut_notes'], sb.result_notes(self.big.result)['cut_notes'])
        self.assertEqual(recent[self.big.pk]['templates_release'], 'v1')
        self.assertEqual(recent[self.small.pk]['outcome'], 'completed')


class RecordInfoTests(Base):
    def test_the_same_report_again_writes_nothing(self):
        from agentapi import sentinel_settings
        agent = self.sentinel()
        sentinel_settings.record_info(agent, {'version': 'abc', 'contract_version': 3})
        agent = Agent.objects.get(pk=agent.pk)
        with CaptureQueriesContext(connection) as q:
            sentinel_settings.record_info(agent, {'version': 'abc', 'contract_version': 3})
        self.assertEqual(_agent_updates(q.captured_queries), [])
        sentinel_settings.record_info(agent, {'version': 'abd', 'contract_version': 3})
        self.assertEqual(Agent.objects.get(pk=agent.pk).info['version'], 'abd')
