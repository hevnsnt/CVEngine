"""Sentinel capacity: a Sentinel at its concurrency limit is busy, not missing. Work for it waits in the queue under its own budget, the completion budget
counts from the claim, budgets scale with the number of targets, and the slots and queue are visible with each Sentinel."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import Agent, SentinelTask
from tests.test_agentapi import call, tool_call
from tests.test_sentinel_dispatch import DispatchBase
from tests.test_sentinels import build_world, register_sentinel, reset_rates

RESULT = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.10', 'ports': []}]}


class Clock:
    """A fake monotonic clock: ``sleep`` advances it, and ``at`` runs a hook the first time the clock passes a moment, so a test can say what the
    Sentinels do and when without waiting."""

    def __init__(self):
        self.now = 1000.0
        self.hooks = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, 0.01)
        for hook in list(self.hooks):
            moment, fn = hook
            if self.now >= moment:
                self.hooks.remove(hook)
                fn()

    def at(self, seconds_from_now, fn):
        self.hooks.append((self.now + seconds_from_now, fn))

    def patches(self):
        return (mock.patch('agentapi.sentinel_dispatch.time.monotonic', side_effect=self.monotonic),
                mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=self.sleep))


class CapacityBase(DispatchBase):
    def busy(self, agent, kind='nmap', n=1):
        """Hold ``n`` of the Sentinel's slots with tasks it is running."""
        for _ in range(n):
            SentinelTask.objects.create(project=self.project, kind=kind, target={}, agent=agent, status='running',
                                        lease_expires_at=timezone.now() + timedelta(minutes=5))

    def dispatch(self, **kw):
        kw.setdefault('host', 'www.example.test')
        return dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, **kw)

    def waiting(self):
        return SentinelTask.objects.filter(status='queued').first()

    def claim(self, agent):
        SentinelTask.objects.filter(status='queued').update(agent=agent, status='claimed', claimed_at=timezone.now(),
                                                            lease_expires_at=timezone.now() + timedelta(minutes=5))

    def finish(self):
        SentinelTask.objects.filter(status__in=('claimed', 'running'), target__has_key='addresses').update(
            status='done', result=RESULT, finished_at=timezone.now())

    def free_slot(self):
        SentinelTask.objects.filter(target={}, status='running').update(status='done', finished_at=timezone.now())


class StateTests(CapacityBase):
    def test_none_free_and_busy(self):
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'none')
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['slots'], state['free']), ('free', 1, 1))
        self.busy(agent)
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['live'], state['free']), ('busy', 1, 0))

    def test_a_busy_sentinel_still_counts_as_a_scanner_so_work_is_queued_for_it_not_sent_elsewhere(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        self.busy(agent)
        self.assertTrue(dispatch.any_scanner_for(self.project, 'nmap'))

    def test_a_sentinel_that_stopped_heartbeating_is_not_live_whatever_its_slots(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'none')
        self.assertFalse(dispatch.any_scanner_for(self.project, 'nmap'))

    def test_the_slots_of_two_sentinels_add_up(self):
        a = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=a.pk).update(max_concurrent=1)
        self.busy(a)
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'busy')


class QueueTests(CapacityBase):
    def test_work_for_a_busy_sentinel_waits_for_a_slot_and_is_not_run_locally(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        self.busy(agent)
        clock = Clock()
        clock.at(40, self.free_slot)  # a slot frees 40 s in ...
        clock.at(41, lambda: self.claim(agent))  # ... and the Sentinel claims the queued task ...
        clock.at(60, self.finish)  # ... and finishes it
        monotonic, sleep = clock.patches()
        from cveFeed import activity
        with monotonic, sleep, mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=8), \
                mock.patch('cveFeed.activity.log', wraps=activity.log) as log:
            out = self.dispatch(timeout=120)
        self.assertEqual(out, RESULT)  # well past the 8 s claim timeout: the queue budget, not the claim timeout, governed the wait
        self.assertIn('Queued nmap work', log.call_args_list[0].args[1])
        self.assertIn('Sentinel slot', log.call_args_list[0].args[1])

    def test_the_queue_budget_ending_falls_back_locally_and_says_no_slot_freed_up(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        self.busy(agent)
        clock = Clock()
        monotonic, sleep = clock.patches()
        with monotonic, sleep, mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_QUEUE_TIMEOUT': '90'}):
            out = self.dispatch(timeout=120)
        self.assertIsNone(out)
        self.assertGreaterEqual(clock.now - 1000, 90)
        self.assertLess(clock.now - 1000, 100)
        task = SentinelTask.objects.exclude(target={}).get()
        self.assertEqual(task.status, 'expired')
        self.assertIn('no Sentinel slot freed up', task.error)
        from cveFeed.models import AgentActivity
        self.assertIn('No Sentinel slot freed up', AgentActivity.objects.filter(project=self.project).order_by('id').last().message)

    def test_the_completion_budget_counts_from_the_claim_not_from_the_queueing(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        self.busy(agent)
        clock = Clock()
        clock.at(100, self.free_slot)
        clock.at(101, lambda: self.claim(agent))
        clock.at(101 + 45, self.finish)  # 45 s of running: inside a 60 s completion budget, though 146 s after the task was queued
        monotonic, sleep = clock.patches()
        with monotonic, sleep:
            out = self.dispatch(timeout=60)
        self.assertEqual(out, RESULT)

    def test_a_claimed_task_that_outlasts_its_completion_budget_still_expires(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        self.busy(agent)
        clock = Clock()
        clock.at(10, self.free_slot)
        clock.at(11, lambda: self.claim(agent))
        monotonic, sleep = clock.patches()
        with monotonic, sleep:
            out = self.dispatch(timeout=60)  # claimed at ~11 s, never reported
        self.assertIsNone(out)
        self.assertGreaterEqual(clock.now - 1000, 71)
        self.assertEqual(SentinelTask.objects.exclude(target={}).get().status, 'expired')

    def test_the_last_live_sentinel_going_away_ends_the_wait_without_waiting_out_the_queue(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        self.busy(agent)
        clock = Clock()
        clock.at(15, lambda: Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(hours=1)))
        monotonic, sleep = clock.patches()
        with monotonic, sleep:
            out = self.dispatch(timeout=60)
        self.assertIsNone(out)
        self.assertLess(clock.now - 1000, 40)  # nowhere near the 300 s queue budget
        self.assertIn('no live Sentinel is left', SentinelTask.objects.exclude(target={}).get().error)

    def test_a_slot_taken_by_another_stage_first_sends_the_wait_into_the_queue_not_to_a_local_run(self):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=1)
        clock = Clock()
        # at the start a slot is free, so the short claim timeout applies; before it ends another stage's task takes the slot
        clock.at(3, lambda: self.busy(agent))
        clock.at(20, self.free_slot)
        clock.at(21, lambda: self.claim(agent))
        clock.at(30, self.finish)
        monotonic, sleep = clock.patches()
        with monotonic, sleep, mock.patch('agentapi.sentinel_dispatch._claim_timeout', return_value=8):
            out = self.dispatch(timeout=120)
        self.assertEqual(out, RESULT)

    def test_no_sentinel_at_all_is_still_an_immediate_no_op(self):
        self.assertIsNone(self.dispatch(timeout=5))
        self.assertFalse(SentinelTask.objects.exists())


class BudgetTests(SimpleTestCase):
    def test_completion_ceilings_scale_with_the_number_of_targets(self):
        one = dispatch._dispatch_timeout('nmap', 1)
        self.assertEqual(one, dispatch.COMPLETION_CEILING['nmap'])
        self.assertEqual(dispatch._dispatch_timeout('nmap', 0), one)
        self.assertEqual(dispatch._dispatch_timeout('nmap', 65), one + 64 * dispatch.PER_TARGET_SECONDS['nmap'])
        self.assertEqual(dispatch._dispatch_timeout('testssl', 5), dispatch.COMPLETION_CEILING['testssl'])  # one host:port per task: no scaling

    def test_the_operators_single_number_still_replaces_every_ceiling(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_DISPATCH_TIMEOUT': '45'}):
            self.assertEqual(dispatch._dispatch_timeout('nmap', 64), 45)

    def test_openvas_follows_the_instances_own_hour_limit(self):
        with mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_MAX_HOURS': '5'}):
            self.assertEqual(dispatch._dispatch_timeout('openvas'), 5 * 3600 + 600)

    def test_the_queue_budget_is_configurable_and_a_bad_value_falls_back(self):
        self.assertEqual(dispatch._queue_timeout('nmap'), dispatch.DEFAULT_QUEUE_SECONDS)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_QUEUE_TIMEOUT': '45'}):
            self.assertEqual(dispatch._queue_timeout('nmap'), 45)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_QUEUE_TIMEOUT': 'soon'}):
            self.assertEqual(dispatch._queue_timeout('nmap'), dispatch.DEFAULT_QUEUE_SECONDS)

    def test_the_budgets_object_lists_every_wait(self):
        out = dispatch.budgets()
        self.assertEqual(set(out), {'claim_seconds', 'queue_seconds', 'completion_seconds', 'per_target_seconds', 'lease_seconds'})
        self.assertEqual(out['completion_seconds']['nmap'], dispatch.COMPLETION_CEILING['nmap'])
        self.assertGreater(out['lease_seconds'], 0)


class VisibilityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        reset_rates(self.tokens)

    def sentinel(self, **extra):
        status, out = register_sentinel(self.tokens['alice'], max_concurrent=2, **extra)
        self.assertIn(status, (200, 201), out)
        Agent.objects.filter(pk=out['id']).update(last_seen=timezone.now())
        return Agent.objects.get(pk=out['id'])

    def hold(self, agent, kind, status='running'):
        from dashboard.models import Project
        SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind=kind, target={'x': 1}, agent=agent, status=status,
                                    lease_expires_at=timezone.now() + timedelta(minutes=5))

    def test_a_sentinel_row_shows_its_slots_by_kind(self):
        agent = self.sentinel()
        self.hold(agent, 'nmap')
        self.hold(agent, 'nuclei_light', 'claimed')
        status, out = call(self.tokens['root'], 'GET', '/api/v1/agents?kind=scanner')
        row = next(r for r in out['results'] if r['id'] == agent.pk)
        self.assertEqual(row['slots'], {'max': 2, 'in_use': 2, 'free': 0, 'by_kind': {'nmap': 1, 'nuclei_light': 1}})

    def test_the_slots_follow_an_administrators_lower_limit_and_free_ones_are_counted(self):
        agent = self.sentinel()
        Agent.objects.filter(pk=agent.pk).update(limits={'max_concurrent': 1})
        self.hold(agent, 'nmap')
        row = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')[1]
        self.assertEqual((row['slots']['max'], row['slots']['free']), (1, 0))

    def test_the_detail_shows_what_is_waiting_in_the_queue_for_it(self):
        from dashboard.models import Project
        agent = self.sentinel()
        project = Project.objects.get(slug='sen-a')
        for kind in ('nmap', 'nmap', 'naabu'):
            SentinelTask.objects.create(project=project, kind=kind, target={}, status='queued')
        row = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')[1]
        self.assertEqual(row['queued_for_it'], {'nmap': 2, 'naabu': 1})
        self.assertNotIn('queued_for_it', call(self.tokens['root'], 'GET', '/api/v1/agents?kind=scanner')[1]['results'][0])  # the list stays cheap

    def test_the_budgets_are_readable_over_rest_and_mcp(self):
        status, out = call(self.tokens['alice'], 'GET', '/api/v1/sentinels/dispatch')
        self.assertEqual(status, 200)
        self.assertIn('queue_seconds', out)
        err, mcp = tool_call(self.tokens['alice'], 'get_sentinel_dispatch')
        self.assertEqual((err, mcp['queue_seconds']), (False, out['queue_seconds']))
