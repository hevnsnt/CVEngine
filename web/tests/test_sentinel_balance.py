"""Least-loaded claiming (``sentinel_broker._lighter_elsewhere``): with two or more live Sentinels a queued task is passed over by one that holds more than a
less loaded, eligible peer with room for it, for ``balance_defer_for(kind)`` at most; the order of the policy it follows (deny, per-kind cap, prefer, then this);
the cases that never defer; the kill switch; one query round per pass over many tasks; and the activity metrics (utilisation, queue wait, queue depth)."""
from datetime import timedelta
from unittest import mock

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi.models import Agent, SentinelTask
from agentapi.services import Ctx
from cveFeed.models import InternalRange
from dashboard.models import Project, ProjectMembership
from tests.fake_scanner import FakeScanner
from tests.test_sentinel_capability_policy import PolicyBase

CLAIM_8 = {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}  # a stage waits 8 s for a Sentinel: the hold ends at 8 - 2 = 6 s


class BalanceBase(PolicyBase):
    def hold(self, agent, n=1, kind='naabu', status='running', **fields):
        """``n`` tasks the Sentinel holds now (claimed or running)."""
        for _ in range(n):
            SentinelTask.objects.create(project=self.project, kind=kind, target={}, agent=agent, status=status,
                                        claimed_at=timezone.now(), accepted_at=timezone.now() if status == 'running' else None,
                                        lease_expires_at=timezone.now() + timedelta(minutes=5), **fields)

    def pair(self, x_held=1, y_held=0, x_max=4, y_max=4):
        x, y = self.external('X', max_concurrent=x_max), self.external('Y', max_concurrent=y_max)
        self.hold(x, x_held)
        self.hold(y, y_held)
        return x, y


class LeastLoadedTests(BalanceBase):
    def test_the_idle_peer_gets_the_task_when_the_first_asker_is_busier(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=1, y_held=0)
            created = timezone.now()
            task = self.queue('nmap', created=created)
            taken, why = self.claim(x, ['nmap'], created + timedelta(seconds=1))
            self.assertIsNone(taken)
            self.assertIn('held for a less loaded Sentinel for up to 6 seconds', why)
            self.assertEqual(self.claim(y, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)

    def test_equal_load_is_no_reason_to_wait_and_the_first_asker_wins(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            for held in (0, 2):
                SentinelTask.objects.all().delete()
                Agent.objects.all().delete()
                x, y = self.pair(x_held=held, y_held=held)
                created = timezone.now()
                task = self.queue('nmap', created=created)
                self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk, f'both holding {held}')

    def test_a_less_loaded_peer_is_a_reason_only_when_strictly_so(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=1, y_held=1)
            self.hold(y, 1)  # y: 2 of 4, x: 1 of 4: x is the lighter one, y is held back
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(y, ['nmap'], created + timedelta(seconds=1))[0])
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)

    def test_capacity_weighted_slots_fall_out_of_the_ratio(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=3, x_max=4, y_max=8)  # 2/4 = 0.5 against 3/8 = 0.375: the big one is the lighter
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0])
            self.hold(y, 1)  # 4/8 = 0.5: a tie
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)

    def test_the_hold_ends_with_the_window_the_stage_can_afford(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair()
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(x, ['nmap'], created + timedelta(seconds=5))[0])
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=7))[0].pk, task.pk)  # y never asked: no stage loses its Sentinel
            self.assertEqual(sb.balance_defer_for('nmap'), 6)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_BALANCE_DEFER_SECONDS': '4', 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '30'}):
            self.assertEqual((sb.balance_defer_for('nmap'), sb.balance_defer_for('openvas')), (4, 4))
            late = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(x, ['nmap'], created + timedelta(seconds=3))[0])
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=5))[0].pk, late.pk)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_BALANCE_DEFER_SECONDS': '600', 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '30'}):
            self.assertEqual((sb.balance_defer_for('nmap'), sb.balance_defer_for('openvas')), (28, 600))  # only the kinds a stage waits on are capped
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '1'}):
            self.assertEqual(sb.balance_defer_for('nmap'), 0)
        self.assertEqual(sb.balance_defer_seconds(), 60)

    def test_an_openvas_task_keeps_the_whole_window(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair()
            created = timezone.now()
            task = self.queue('openvas', created=created)
            self.assertIsNone(self.claim(x, ['openvas'], created + timedelta(seconds=59))[0])
            self.assertEqual(self.claim(x, ['openvas'], created + timedelta(seconds=61))[0].pk, task.pk)

    def test_the_kill_switch_hands_the_task_to_the_first_asker(self):
        with mock.patch.dict('os.environ', {**CLAIM_8, 'CVENGINE_SENTINEL_BALANCE': '0'}):
            x, y = self.pair()
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertEqual((sb.balance_enabled(), sb.balance_defer_seconds(), sb.balance_defer_for('openvas')), (False, 0, 0))
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)
        with mock.patch.dict('os.environ', {**CLAIM_8, 'CVENGINE_SENTINEL_BALANCE_DEFER_SECONDS': '0'}):
            late = self.queue('nmap', created=created)
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, late.pk)
        self.assertTrue(sb.balance_enabled())

    def test_one_live_sentinel_is_unchanged(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x = self.external('X', max_concurrent=4)
            self.hold(x, 2)
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertEqual(self.claim(x, ['nmap'], created)[0].pk, task.pk)
            # and when the other is not a candidate at all: it does not declare the kind
            other = self.external('Z', caps=('naabu',), max_concurrent=4)
            late = self.queue('nmap', created=created)
            SentinelTask.objects.filter(pk=task.pk).update(status='done')  # (x holds two again)
            self.assertTrue(other.pk)
            self.assertEqual(self.claim(x, ['nmap'], created)[0].pk, late.pk)

    def test_an_idle_sentinel_is_never_held_back(self):
        with mock.patch.dict('os.environ', {**CLAIM_8, 'CVENGINE_SENTINEL_PREFER_DEFER_SECONDS': '0'}):  # (the prefer check looks its peers up on its own)
            x, y = self.pair(x_held=0, y_held=0)
            task = self.queue('nmap', created=timezone.now())
            with CaptureQueriesContext(connection) as captured:
                taken = self.claim(x, ['nmap'])[0]
            self.assertEqual(taken.pk, task.pk)
            peers = [q for q in captured.captured_queries if '"agentapi_agent"."last_seen" >=' in q['sql']]
            self.assertEqual(peers, [], 'a Sentinel that holds nothing is never less loaded: the peers are not even looked up')


class NeverHoldBackTests(BalanceBase):
    """The other Sentinel is lighter, but it could not take the task: waiting for it would only cost the task time."""

    def check(self, change, kind='nmap', **task_fields):
        with mock.patch.dict('os.environ', CLAIM_8):
            SentinelTask.objects.all().delete()
            Agent.objects.all().delete()
            x, y = self.pair()
            change(x, y)
            created = timezone.now()
            task = SentinelTask.objects.create(project=self.project, kind=kind, target={'addresses': ['192.0.2.10']}, **{'ips': ['192.0.2.10'], **task_fields})
            SentinelTask.objects.filter(pk=task.pk).update(created_at=created)
            taken, why = self.claim(x, [kind], created + timedelta(seconds=1))
            self.assertIsNotNone(taken, why)
            self.assertEqual(taken.pk, task.pk)

    def test_when_the_lighter_one_is_not_live(self):
        self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(last_seen=timezone.now() - timedelta(hours=1)))
        self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(last_seen=None))

    def test_when_it_is_updating_itself(self):
        update = {'update': {'status': 'updating', 'at': timezone.now().strftime('%Y-%m-%dT%H:%M:%SZ')}}
        self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(info={**y.info, **update}))

    def test_when_it_is_at_capacity(self):
        # x holds 3 of 4 (ratio .75); y's one slot is taken: it is not lighter in any case, and cannot take the task whatever its ratio
        self.check(lambda x, y: (Agent.objects.filter(pk=y.pk).update(max_concurrent=1), self.hold(y, 1), self.hold(x, 2)))
        found = sb._can_take(sb.effective(Agent.objects.select_related('token__user').get(name='Y')), sb._holders([Agent.objects.get(name='Y').pk]),
                             self.queue('nmap'), timezone.now())
        self.assertFalse(found)

    def test_when_it_is_not_active(self):
        for status in ('suspended', 'pending'):
            self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(status=status))

    def test_when_the_kind_is_denied_there(self):
        self.check(lambda x, y: self.manage(y, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}}))

    def test_when_it_does_not_declare_the_kind(self):
        self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(capabilities=['naabu', 'openvas']))

    def test_when_the_kind_is_at_its_cap_there(self):
        def cap(x, y):
            self.manage(y, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 1}}})
            self.hold(y, 1, kind='nmap')  # y holds 1 of 4 (lighter than x's 2 of 4) but is at its cap of 1 nmap
            self.hold(x, 1)
        self.check(cap)

    def test_when_the_kind_is_withheld_from_it_after_failures(self):
        def fail(x, y):
            for _ in range(3):
                SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=y, status='failed', finished_at=timezone.now())
        self.check(fail)

    def test_when_its_scope_does_not_reach_the_project(self):
        other = Project.objects.create(name='Other', slug='balance-other', insert_date=timezone.now(), org=self.org)
        self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(scope={'orgs': [], 'projects': [other.slug], 'hosts': []}))

    def test_when_its_host_patterns_do_not_reach_the_target(self):
        self.check(lambda x, y: Agent.objects.filter(pk=y.pk).update(scope={'orgs': [], 'projects': [self.project.slug], 'hosts': ['only.test']}),
                   host='b.elsewhere.test', ips=[])

    def test_when_the_target_is_inside_a_network_only_the_asker_can_reach(self):
        InternalRange.objects.create(project=self.project, cidr='10.20.0.0/24')

        def inside(x, y):
            Agent.objects.filter(pk=x.pk).update(network='internal', capabilities=['nmap', 'naabu', 'network:internal'])
        self.check(inside, ips=['10.20.0.5'], host='10.20.0.5')

    def test_when_the_task_needs_a_stored_credential_and_the_lighter_one_is_not_the_built_in_scanner(self):
        fake = FakeScanner(kinds=['nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.hold(fake.agent, 1)
        with mock.patch.dict('os.environ', CLAIM_8):
            created = timezone.now()
            task = self.queue('nmap', created=created, secret_ref='authcred:1')
            self.assertEqual(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)  # outside is idle but may never see it
            Agent.objects.filter(pk=outside.pk).update(last_seen=timezone.now())  # (and is live: it is the credential that rules it out)

    def test_a_task_the_lighter_one_could_take_is_still_held_while_its_scope_names_hosts(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair()
            Agent.objects.filter(pk=y.pk).update(scope={'orgs': [], 'projects': [self.project.slug], 'hosts': ['only.test']})
            created = timezone.now()
            inside = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, host='a.only.test', ips=[])
            outside = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, host='b.elsewhere.test', ips=[])
            SentinelTask.objects.filter(pk__in=(inside.pk, outside.pk)).update(created_at=created)
            taken, _ = self.claim(x, ['nmap'], created + timedelta(seconds=1))
            self.assertEqual(taken.pk, outside.pk)
            inside.refresh_from_db()
            self.assertEqual(inside.status, 'queued')


class OpenvasAndSharedLookupTests(BalanceBase):
    def test_a_peer_running_an_openvas_task_is_not_waited_for_openvas(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=0)
            self.hold(y, 1, kind='openvas')  # y: 1 of 4 against x's 2 of 4: lighter, but it takes no second OpenVAS run
            created = timezone.now()
            task = self.queue('openvas', created=created)
            self.assertEqual(self.claim(x, ['openvas'], created + timedelta(seconds=1))[0].pk, task.pk)
            nmap = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0])  # other kinds are still shared by load
            self.assertEqual(self.claim(y, ['nmap'], created + timedelta(seconds=1))[0].pk, nmap.pk)

    def test_the_prefer_and_balance_checks_share_one_lookup_of_the_peers(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=0)
            created = timezone.now()
            self.queue('nmap', created=created)
            with CaptureQueriesContext(connection) as captured:
                self.assertIsNone(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0])
            lookups = [q for q in captured.captured_queries if '"agentapi_agent"."last_seen" >=' in q['sql']]
            self.assertEqual(len(lookups), 1, 'the candidates are looked up once for both checks')
        with mock.patch.dict('os.environ', {**CLAIM_8, 'CVENGINE_SENTINEL_BALANCE': '0'}):  # with balancing off the prefer check keeps its own cheap lookup
            self.assertIsNotNone(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0])


class PolicyInterplayTests(BalanceBase):
    def test_prefer_wins_over_balance_for_the_one_that_prefers(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=0)
            self.manage(x, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)  # x prefers nmap: busier or not, it takes it first

    def test_prefer_holds_the_task_from_the_idle_one_even_though_the_preferring_one_is_busier(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=0)
            self.manage(x, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()
            task = self.queue('nmap', created=created)
            taken, why = self.claim(y, ['nmap'], created + timedelta(seconds=1))
            self.assertIsNone(taken)
            self.assertIn('prefers it', why)  # the preference is what holds it, not the load
            self.assertEqual(self.claim(y, ['nmap'], created + timedelta(seconds=7))[0].pk, task.pk)  # and it ends with the same window

    def test_balance_applies_to_the_kinds_nobody_prefers(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=0)
            self.manage(x, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()
            task = self.queue('naabu', created=created)
            taken, why = self.claim(x, ['naabu'], created + timedelta(seconds=1))
            self.assertIsNone(taken)
            self.assertIn('less loaded', why)
            self.assertEqual(self.claim(y, ['naabu'], created + timedelta(seconds=1))[0].pk, task.pk)

    def test_the_order_is_deny_then_cap_then_prefer_then_balance(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            x, y = self.pair(x_held=2, y_held=0)
            self.manage(x, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 1}, 'openvas': {'mode': 'deny', 'max_concurrent': None}}})
            self.hold(x, 1, kind='nmap')
            created = timezone.now()
            self.queue('nmap', created=created)
            self.queue('openvas', created=created)
            taken, why = self.claim(x, ['nmap', 'openvas'], created + timedelta(seconds=1))
            self.assertIsNone(taken)
            self.assertIn('nmap is at its limit', why)  # the cap decided first, and a denied kind is not looked at
            self.assertNotIn('less loaded', why)


class FakeScannerTests(BalanceBase):
    """The built-in scanner (FakeScanner) and an external Sentinel are peers: whichever is lighter takes the work."""

    def setUp(self):
        super().setUp()
        self.enterContext(mock.patch.dict('os.environ', CLAIM_8))  # the fake would otherwise shorten the claim window to one second, which leaves no room to hold anything

    def test_the_built_in_scanner_defers_to_a_lighter_external_one_and_serves_the_task_once_the_window_has_passed(self):
        fake = FakeScanner(kinds=['nmap'], max_concurrent=4, mode='timeout').start_for(self)
        outside = self.external('Remote-1')
        self.hold(fake.agent, 2)
        created = timezone.now() - timedelta(seconds=1)
        task = self.queue('nmap', created=created)
        self.assertIsNone(fake.serve_once())  # the external Sentinel is idle: the task waits for it
        task.refresh_from_db()
        self.assertEqual(task.status, 'queued')
        self.assertEqual(self.claim(outside, ['nmap'])[0].pk, task.pk)
        self.assertEqual(task.__class__.objects.get(pk=task.pk).agent_id, outside.pk)

    def test_the_external_sentinel_defers_to_a_lighter_built_in_scanner(self):
        fake = FakeScanner(kinds=['nmap'], max_concurrent=4, mode='timeout').start_for(self)
        outside = self.external('Remote-1')
        self.hold(outside, 1)
        created = timezone.now()
        task = self.queue('nmap', created=created)
        self.assertIsNone(self.claim(outside, ['nmap'], created + timedelta(seconds=1))[0])
        served = fake.serve_once()
        self.assertEqual(served['id'], task.pk)

    def test_two_idle_peers_serve_in_the_order_they_ask(self):
        fake = FakeScanner(kinds=['nmap'], max_concurrent=4, mode='timeout').start_for(self)
        self.external('Remote-1')
        task = self.queue('nmap', created=timezone.now())
        self.assertEqual(fake.serve_once()['id'], task.pk)

    def test_the_stage_still_gets_a_sentinel_when_the_lighter_peer_never_answers(self):
        fake = FakeScanner(kinds=['nmap'], max_concurrent=4, mode='timeout').start_for(self)
        self.external('Remote-1')  # live and idle, never polls
        self.hold(fake.agent, 1)
        self.queue('nmap', created=timezone.now() - timedelta(seconds=10))
        served = fake.serve_once()
        self.assertIsNotNone(served)  # past the window: the busier one takes it rather than the stage running it locally


class QueryCountTests(BalanceBase):
    def test_a_pass_over_many_queued_tasks_of_several_projects_does_not_query_per_task(self):
        with mock.patch.dict('os.environ', CLAIM_8):
            projects = [self.project] + [Project.objects.create(name=f'P{n}', slug=f'balance-p{n}', insert_date=timezone.now(), org=self.org) for n in range(2)]
            x, y = self.external('X'), self.external('Y')
            for agent in (x, y):
                Agent.objects.filter(pk=agent.pk).update(scope={'orgs': [self.org.slug], 'projects': [], 'hosts': []}, max_concurrent=10)
                for project in projects[1:]:
                    ProjectMembership.objects.get_or_create(user=agent.token.user, project=project, defaults={'role': 'user'})
            self.hold(x, 3)
            created = timezone.now()

            def queue_many(n):
                for project in projects:
                    for kind in ('nmap', 'naabu'):
                        for _ in range(n):
                            task = SentinelTask.objects.create(project=project, kind=kind, target={}, ips=['192.0.2.10'])
                            SentinelTask.objects.filter(pk=task.pk).update(created_at=created)

            def queries(now):
                with CaptureQueriesContext(connection) as captured:
                    taken, why = self.claim(x, ['nmap', 'naabu'], now)
                return len(captured), taken, why
            queue_many(1)
            queries(created + timedelta(seconds=1))  # (the first pass warms the caches the later ones read)
            few, taken, why = queries(created + timedelta(seconds=1))
            self.assertIsNone(taken)  # every task is held for the lighter Sentinel
            self.assertIn('less loaded', why)
            queue_many(9)
            many, taken, _ = queries(created + timedelta(seconds=1))
            self.assertIsNone(taken)
            self.assertEqual(many, few, f'{many} queries for 60 tasks against {few} for 6: the balance check must not query per task')


class MetricsTests(BalanceBase):
    def test_utilisation_is_the_busy_time_of_the_hour_over_every_slot_and_capped_at_one(self):
        now = timezone.now()
        x = self.external('X', max_concurrent=2)
        for minutes in (30, 30):  # one slot busy for the first half hour, the other for the second half: half of 2 slots * 1 h
            SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=x, status='done', accepted_at=now - timedelta(minutes=minutes + 10),
                                        claimed_at=now - timedelta(minutes=minutes + 10), finished_at=now - timedelta(minutes=10))
        metrics = sb.activity_metrics([x.pk], now, max_concurrent={x.pk: 2})
        self.assertEqual(metrics['agents'][x.pk]['utilisation_1h'], 0.5)
        self.assertEqual(metrics['agents'][x.pk]['tasks_1h'], 2)
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=x, status='running', accepted_at=now - timedelta(hours=5),
                                    claimed_at=now - timedelta(hours=5), lease_expires_at=now + timedelta(minutes=5))  # a long run counts for the hour, not for five
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=x, status='running', accepted_at=now - timedelta(hours=5),
                                    claimed_at=now - timedelta(hours=5), lease_expires_at=now + timedelta(minutes=5))
        self.assertEqual(sb.activity_metrics([x.pk], now, max_concurrent={x.pk: 2})['agents'][x.pk]['utilisation_1h'], 1.0)
        # a task finished more than an hour ago is not in it, and an idle Sentinel reads zero with no percentiles
        y = self.external('Y')
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=y, status='done', accepted_at=now - timedelta(hours=3),
                                    claimed_at=now - timedelta(hours=3), finished_at=now - timedelta(hours=2))
        row = sb.activity_metrics([y.pk], now, max_concurrent={y.pk: 4})['agents'][y.pk]
        self.assertEqual((row['utilisation_1h'], row['tasks_1h'], row['wait_p50_seconds'], row['wait_p95_seconds'], row['wait_by_kind']), (0.0, 0, None, None, {}))

    def test_queue_wait_percentiles_per_agent_and_per_kind_and_the_queue_depth_by_kind(self):
        now = timezone.now()
        x, y = self.external('X'), self.external('Y')
        for agent, kind, wait in [(x, 'nmap', 1), (x, 'nmap', 3), (x, 'nmap', 5), (x, 'naabu', 10), (y, 'nmap', 20)]:
            task = SentinelTask.objects.create(project=self.project, kind=kind, target={}, agent=agent, status='done')
            SentinelTask.objects.filter(pk=task.pk).update(created_at=now - timedelta(minutes=5), claimed_at=now - timedelta(minutes=5) + timedelta(seconds=wait))
        old = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=x, status='done')
        SentinelTask.objects.filter(pk=old.pk).update(created_at=now - timedelta(hours=3), claimed_at=now - timedelta(hours=2, minutes=59))  # outside the hour
        self.queue('nmap')
        self.queue('nmap')
        self.queue('openvas')
        metrics = sb.activity_metrics([x.pk, y.pk], now, max_concurrent={x.pk: 4, y.pk: 4})
        mine = metrics['agents'][x.pk]
        self.assertEqual((mine['wait_p50_seconds'], mine['wait_p95_seconds']), (4.0, 9.2))  # 1, 3, 5, 10: the median is between 3 and 5; the 95th is 5 + 0.85 * 5, to a tenth
        self.assertEqual(mine['wait_by_kind']['nmap'], {'n': 3, 'p50_seconds': 3.0, 'p95_seconds': 4.8})
        self.assertEqual(mine['wait_by_kind']['naabu'], {'n': 1, 'p50_seconds': 10.0, 'p95_seconds': 10.0})
        nmap = metrics['kinds']['nmap']
        self.assertEqual((nmap['queued'], nmap['wait_p50_seconds']), (2, 4.0))  # 1, 3, 5, 20 over both Sentinels
        self.assertEqual(metrics['kinds']['openvas']['queued'], 1)
        self.assertEqual(set(metrics['kinds']), set(SentinelTask.KINDS))

    def test_the_live_overview_carries_load_and_queue_depth_for_the_viewer(self):
        now = timezone.now()
        x = self.external('X', max_concurrent=2)
        self.hold(x, 1)
        SentinelTask.objects.filter(agent=x).update(accepted_at=now - timedelta(minutes=30))
        self.queue('nmap')
        out = sb.live_overview(Ctx(user=self.root, token=self.root_token))
        row = next(r for r in out['results'] if r['id'] == x.pk)
        self.assertEqual(row['load']['held'], 1)
        for key in ('utilisation_1h', 'tasks_1h', 'wait_p50_seconds', 'wait_p95_seconds', 'wait_by_kind'):
            self.assertIn(key, row['load'])
        self.assertEqual(out['kinds']['nmap']['queued'], 1)
        self.assertGreater(row['load']['utilisation_1h'], 0)

    def test_the_system_status_carries_per_agent_load_and_the_per_kind_queue(self):
        from agentapi.system_status import _sentinels
        x, y = self.external('X', max_concurrent=4), self.external('Y', max_concurrent=2)
        self.hold(x, 1)
        self.queue('nmap')
        load = _sentinels([])['load']
        rows = {r['name']: r for r in load['per_agent']}
        self.assertEqual((rows['X']['held'], rows['X']['load'], rows['Y']['held'], rows['Y']['load']), (1, 0.25, 0, 0.0))
        self.assertEqual(rows['X']['max_concurrent'], 4)
        self.assertIn('utilisation_1h', rows['Y'])
        self.assertEqual(load['by_kind']['nmap']['queued'], 1)
        self.assertEqual(load['balancing'], {'enabled': True, 'defer_seconds': 60})
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_BALANCE': '0'}):
            self.assertEqual(_sentinels([])['load']['balancing'], {'enabled': False, 'defer_seconds': 0})
