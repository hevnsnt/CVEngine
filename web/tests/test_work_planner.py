"""The work planner (cveFeed.work_planner): it queues the checks that are due when Sentinel slots are idle, and only then; it respects every gate the scan
stages have; it is fair across projects; and it is idempotent. Sentinels are fakes (a registered Agent row, or ``tests.fake_scanner.FakeScanner`` serving
tasks through the real broker); nothing runs a tool."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker, sentinel_contract
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import ledger, secrets_scan, ssh_scan, work_planner
from cveFeed.models import ExcludedAddress, HostExclusion, PlannerBatch, ProbeObservation, RouteAuth, ServiceRun
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner
from tests.test_ssh_scan import host_row

KEYS = (work_planner.CENSUS_KEY, work_planner.LAST_KEY, work_planner.LOCK_KEY, work_planner.CURSOR_KEY)
BASES = {'alpha': '203.0.113', 'beta': '198.51.100', 'gamma': '93.184.216'}


class Fleet(TestCase):
    """Projects, hosts and Sentinel rows. ``host`` makes a host with an open SSH port (and a web port with route data when ``web``) on its own address."""

    def setUp(self):
        self.now = timezone.now()
        self.n = 0
        self.user = User.objects.create_user('planner-owner', password='x')
        self.org = Org.objects.create(name='Org A', slug='org-a')
        self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.project = self.make_project('alpha', self.org)
        for key in KEYS:
            cache.delete(key)
        mock.patch('cveFeed.scan_control.pause_requested', return_value=False).start()
        mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False).start()
        self.sent = mock.patch('cveFeed.tasks.work_planner_batch.apply_async').start()
        self.census_task = mock.patch('cveFeed.tasks.work_planner_census.apply_async').start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(lambda: [cache.delete(k) for k in KEYS])

    def make_project(self, slug, org):
        project = Project.objects.create(name=slug, slug=slug, org=org, insert_date=self.now)
        domain = Domain.objects.create(name=f'{slug}.example', project=project, insert_date=self.now)
        scan = ScanHistory.objects.create(domain=domain, start_scan_date=self.now, scan_status=2, tasks=[], results_dir='x', scan_type=self.engine)
        project.t_domain, project.t_scan = domain, scan
        return project

    def host(self, project, name, ssh=True, web=False, routed=True, address=None):
        self.n += 1
        address = address or f'{BASES[project.slug]}.{self.n % 250 + 1}'
        sub = Subdomain.objects.create(name=f'{name}.{project.slug}.example', target_domain=project.t_domain, scan_history=project.t_scan)
        ip, _ = IpAddress.objects.get_or_create(address=address)
        sub.ip_addresses.add(ip)
        if ssh and not ip.ports.filter(number=22).exists():
            ip.ports.add(Port.objects.create(number=22, service_name='ssh', state='open'))
        if web:
            if not ip.ports.filter(number=443).exists():
                ip.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
            if routed:
                RouteAuth.objects.create(project=project, domain=project.t_domain, host=sub.name, url=f'https://{sub.name}/', path='/', auth_state='open',
                                         http_status=200, content_type='text/html')
        return sub, address

    def sentinel(self, slots=4, kinds=('ssh_probe', 'secrets_scan'), projects=None, contract=None, name=None):
        self.n += 1
        token, _raw = create_token(self.user, f'pl-{self.n}')
        return Agent.objects.create(token=token, name=name or f'pl-{self.n}', kind='scanner', status='active', max_concurrent=slots, capabilities=list(kinds),
                                    last_seen=timezone.now(), info={'contract_version': contract or sentinel_contract.version()},
                                    scope={'orgs': [], 'projects': projects or [p.slug for p in Project.objects.all()], 'hosts': []})

    def tick(self, census=True, **kw):
        if census:
            work_planner.census(self.now)
        return work_planner.run(self.now, **kw)

    def batches(self, kind=None):
        rows = PlannerBatch.objects.all()
        return list(rows.filter(kind=kind) if kind else rows)


class IdleTests(Fleet):
    def test_it_queues_due_work_when_the_sentinels_are_idle_in_batches_of_a_tasks_worth(self):
        for i in range(30):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=4)
        out = self.tick()
        self.assertEqual(out['state'], 'queued')
        rows = self.batches('ssh_probe')
        self.assertEqual(sorted(len(b.units) for b in rows), [5, 25])  # 30 endpoints, at most 25 to a task
        self.assertEqual(out['queued'], {'ssh_probe': 30})
        self.assertEqual(self.sent.call_count, 2)
        self.assertTrue(all(c.kwargs['queue'] == 'planner_queue' for c in self.sent.call_args_list))
        self.assertEqual(out['due']['ssh_probe'], 30)

    def test_tick_is_the_entry_the_watchdog_calls_it_builds_the_census_itself_and_returns_what_it_queued(self):
        for i in range(3):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=4)
        out = work_planner.tick(self.now)  # no census was built first
        self.assertEqual(out['state'], 'queued')
        self.assertEqual(out['queued'], {'ssh_probe': 3})
        self.assertEqual(work_planner.tick()['queued'], {})  # the next call finds the work in flight and queues nothing again

    def test_one_summary_row_per_run_in_the_activity_feed_not_one_per_task(self):
        from cveFeed.models import AgentActivity
        for i in range(30):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=4)
        self.tick()
        rows = AgentActivity.objects.filter(message__startswith='Work planner queued')
        self.assertEqual(rows.count(), 1)
        self.assertIn('30 SSH checks', rows[0].message)

    def test_web_hosts_with_route_data_get_secret_checks_and_those_without_wait_for_the_route_check(self):
        self.host(self.project, 'routed', ssh=False, web=True)
        self.host(self.project, 'bare', ssh=False, web=True, routed=False)
        self.sentinel()
        out = self.tick()
        (batch,) = self.batches('secrets_scan')
        self.assertEqual([u['u'] for u in batch.units], ['routed.alpha.example'])
        self.assertEqual((out['due']['secrets_scan'], out['awaiting']['secrets_scan']), (2, 1))

    def test_nothing_due_is_said_as_such(self):
        self.sentinel()
        out = self.tick()
        self.assertEqual(out['state'], 'nothing_due')
        self.assertEqual(self.batches(), [])
        self.assertTrue(work_planner.overview(None, self.now)['line'].startswith('Planner: nothing due'))

    def test_the_first_tick_without_a_census_asks_for_one_and_queues_nothing(self):
        self.host(self.project, 'a')
        self.sentinel()
        out = self.tick(census=False)
        self.assertEqual(out['state'], 'warming')
        self.census_task.assert_called_once()
        self.assertEqual(self.batches(), [])

    def test_no_live_sentinel_queues_nothing(self):
        self.host(self.project, 'a')
        self.assertEqual(self.tick()['state'], 'no_sentinel')
        self.assertEqual(self.batches(), [])


class BusyTests(Fleet):
    def test_all_slots_busy_queues_nothing(self):
        for i in range(10):
            self.host(self.project, f'h{i}')
        agent = self.sentinel(slots=2)
        for _ in range(2):
            SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status='running', agent=agent, claimed_at=self.now,
                                        lease_expires_at=self.now + timedelta(minutes=10))
        out = self.tick()
        self.assertEqual(out['state'], 'busy')
        self.assertEqual(out['reasons']['ssh_probe'], 'no free slot: all 2 Sentinel slots busy')
        self.assertEqual(self.batches(), [])
        self.assertEqual(work_planner.overview(None, self.now)['line'].split(',')[0], 'Planner: waiting')

    def test_the_reason_names_the_real_cause_when_other_slots_are_free(self):
        """6 of 10 slots free did not mean "all slots busy": the Sentinels able to run the kind can be full while others are idle."""
        cap = {'free_total': 6, 'queued_total': 0, 'queued': {}, 'agents': [{'slots': 5}, {'slots': 5}]}
        full = work_planner._busy_reason({'sentinels': 1, 'slots': 4, 'free': 0}, cap, 'ssh_probe')
        self.assertIn('1 Sentinel(s) that can run it have no free slot', full)
        self.assertIn('6 slot(s) are free on Sentinels that cannot take it', full)
        crowded = work_planner._busy_reason({'sentinels': 2, 'slots': 10, 'free': 6}, {**cap, 'queued_total': 9, 'queued': {'nmap': 9}}, 'ssh_probe')
        self.assertIn('9 task(s) of other kinds already wait for the 6 free slot(s)', crowded)

    def test_a_queue_at_its_target_queues_nothing_more(self):
        for i in range(60):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=2)  # two idle slots, factor 2: four tasks waiting is the target
        for _ in range(4):
            SentinelTask.objects.create(project=self.project, kind='ssh_probe', target={'targets': [{'address': '203.0.113.250', 'port': 22}]}, status='queued',
                                        priority=0)
        out = self.tick()
        self.assertEqual(self.batches(), [])
        self.assertIn('deep enough', out['reasons']['ssh_probe'])

    def test_work_of_other_kinds_already_waiting_takes_the_slots_first(self):
        for i in range(40):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=2)
        for _ in range(2):
            SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status='queued', priority=1)
        self.tick()
        self.assertEqual(self.batches(), [])  # both idle slots are promised to the scan's tasks

    def test_the_queue_follows_the_factor_and_the_ceiling_per_sentinel(self):
        for i in range(400):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=3)
        with mock.patch.object(work_planner, 'queue_factor', return_value=3):
            out = self.tick()
        self.assertEqual(out['batches'], 9)  # 3 idle slots x factor 3
        PlannerBatch.objects.all().delete()
        with mock.patch.object(work_planner, 'queue_factor', return_value=6), mock.patch.object(work_planner, 'max_queue_per_sentinel', return_value=4), \
                mock.patch.object(work_planner, 'batches_per_run', return_value=50):
            out = self.tick(census=False)
        self.assertEqual(out['batches'], 4)  # 18 wanted, never more than 4 waiting for the one Sentinel

    def test_a_run_queues_at_most_its_cap_of_batches(self):
        for i in range(200):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=8)
        with mock.patch.object(work_planner, 'batches_per_run', return_value=2):
            out = self.tick()
        self.assertEqual(out['batches'], 2)

    def test_running_it_twice_queues_the_work_once(self):
        for i in range(30):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=4)
        first = self.tick()
        again = self.tick(census=False)
        self.assertEqual(first['queued'], {'ssh_probe': 30})
        self.assertEqual(len(self.batches('ssh_probe')), 2)
        self.assertEqual(again['queued'], {})
        self.assertEqual(sum(len(b.units) for b in self.batches()), 30)

    def test_a_run_while_another_goes_does_nothing(self):
        self.host(self.project, 'a')
        self.sentinel()
        cache.add(work_planner.LOCK_KEY, 1, 60)
        self.assertEqual(work_planner.run(self.now)['state'], 'running')
        self.assertEqual(self.batches(), [])

    def test_a_kind_that_failed_three_batches_in_a_row_is_left_alone_for_a_while(self):
        for i in range(10):
            self.host(self.project, f'h{i}')
        self.sentinel()
        for i in range(3):
            PlannerBatch.objects.create(project=self.project, kind='ssh_probe', units=[], status='failed', finished_at=self.now - timedelta(minutes=i + 1))
        out = self.tick()
        self.assertEqual(out['state'], 'backing_off')
        self.assertEqual(len(self.batches('ssh_probe')), 3)
        PlannerBatch.objects.update(finished_at=self.now - timedelta(minutes=30))
        self.assertEqual(self.tick(census=False)['state'], 'queued')

    def test_units_of_a_failed_or_refused_batch_are_left_alone_and_the_rest_goes_on(self):
        for i in range(3):
            self.host(self.project, f'h{i}')
        self.sentinel()
        self.tick()
        (batch,) = self.batches('ssh_probe')
        refused = batch.units[0]['u']
        work_planner._memo_skip('ssh_probe', self.project.pk, refused, 60)
        PlannerBatch.objects.all().delete()
        again = self.tick(census=False)
        (batch,) = self.batches('ssh_probe')
        self.assertNotIn(refused, [u['u'] for u in batch.units])
        self.assertEqual(again['queued'], {'ssh_probe': 2})


class GateTests(Fleet):
    def test_scanning_paused_queues_nothing(self):
        self.host(self.project, 'a')
        self.sentinel()
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            out = self.tick()
        self.assertEqual((out['state'], self.batches()), ('paused', []))
        self.assertIn('scanning is paused', work_planner.overview(None, self.now)['line'])

    def test_the_instance_switch_pauses_it(self):
        self.host(self.project, 'a')
        self.sentinel()
        from cveFeed import tunables
        with mock.patch.object(tunables, 'value', side_effect=lambda key, default=None: 0 if key == 'planner_enabled' else default):
            out = self.tick()
            line = work_planner.overview(None, self.now)['line']
        self.assertEqual((out['state'], self.batches()), ('off', []))
        self.assertTrue(line.startswith('Planner: off'))

    def test_a_bug_bounty_project_that_has_not_confirmed_automated_testing_is_not_planned(self):
        self.host(self.project, 'a')
        self.sentinel()
        with mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value={self.project.pk}):
            out = self.tick()
        self.assertEqual(self.batches(), [])
        self.assertEqual(out['due']['ssh_probe'], 0)

    def test_a_batch_whose_project_became_blocked_is_skipped_when_it_runs(self):
        self.host(self.project, 'a')
        self.sentinel()
        self.tick()
        (batch,) = self.batches('ssh_probe')
        with mock.patch('cveFeed.bounty_gate.Gate.project_blocked', return_value=True):
            out = work_planner.execute_batch(batch.pk)
        self.assertEqual(out['status'], 'skipped')
        self.assertEqual(ServiceRun.objects.filter(service='ssh-probe').count(), 0)

    def test_an_address_on_the_do_not_scan_list_is_not_planned(self):
        _sub, address = self.host(self.project, 'blocked')
        self.host(self.project, 'fine')
        ExcludedAddress.objects.create(org=self.org, cidr=f'{address}/32')
        self.sentinel()
        self.tick()
        units = [u['u'] for b in self.batches('ssh_probe') for u in b.units]
        self.assertNotIn(f'{address}:22', units)
        self.assertEqual(len(units), 1)

    def test_an_address_excluded_after_the_census_is_not_sent_either(self):
        _sub, address = self.host(self.project, 'blocked')
        self.host(self.project, 'fine')
        self.sentinel()
        work_planner.census(self.now)
        ExcludedAddress.objects.create(org=self.org, cidr=f'{address}/32')  # added between the census and the tick
        work_planner.run(self.now)
        units = [u['u'] for b in self.batches('ssh_probe') for u in b.units]
        self.assertEqual(len(units), 1)
        self.assertNotIn(f'{address}:22', units)

    def test_an_excluded_host_is_not_planned_and_not_counted(self):
        sub, _a = self.host(self.project, 'gone', ssh=True, web=True)
        HostExclusion.objects.create(org=self.org, host=sub.name)
        self.host(self.project, 'ok')
        self.sentinel()
        out = self.tick()
        self.assertEqual(out['due'], {'ssh_probe': 1, 'secrets_scan': 0})

    def test_a_manual_only_target_is_not_planned(self):
        self.host(self.project, 'a')
        Domain.objects.filter(pk=self.project.t_domain.pk).update(discovery_mode=Domain.DISCOVERY_MANUAL)
        self.sentinel()
        self.tick()
        self.assertEqual(self.batches(), [])

    def test_a_project_no_sentinel_covers_is_not_planned(self):
        other = self.make_project('beta', self.org)
        self.host(other, 'b')
        self.sentinel(projects=['alpha'])
        out = self.tick()
        self.assertEqual(self.batches(), [])
        self.assertIn('no live Sentinel covers it', json.dumps(out['reasons']))


class CapabilityTests(Fleet):
    def test_a_sentinel_without_the_kind_is_no_capacity_for_it(self):
        self.host(self.project, 'a')
        self.sentinel(kinds=('nmap',))
        out = self.tick()
        self.assertEqual(self.batches(), [])
        self.assertEqual(out['reasons']['ssh_probe'], 'no live Sentinel can take it')

    def test_a_sentinel_whose_contract_predates_the_kind_is_not_offered_it(self):
        self.host(self.project, 'a')
        self.assertFalse(sentinel_contract.can_run(1, 'ssh_probe'))
        self.sentinel(contract=1)
        out = self.tick()
        self.assertEqual(self.batches(), [])
        self.assertEqual(out['reasons']['ssh_probe'], 'no live Sentinel can take it')

    def test_a_kind_a_sentinel_keeps_failing_is_not_planned_for_it(self):
        self.host(self.project, 'a')
        agent = self.sentinel()
        for i in range(3):
            SentinelTask.objects.create(project=self.project, kind='ssh_probe', target={}, status='failed', agent=agent, error='boom',
                                        finished_at=timezone.now() - timedelta(minutes=i))
        out = self.tick()  # "Paused after repeated failures" (sentinel_broker.failing_kinds) takes the kind out of its capabilities
        self.assertEqual(self.batches('ssh_probe'), [])
        self.assertEqual(out['reasons']['ssh_probe'], 'no live Sentinel can take it')

    def test_the_built_in_scanner_adds_no_capacity_while_an_external_sentinel_can_take_the_kind(self):
        external = self.sentinel(slots=2, name='external')
        builtin = self.sentinel(slots=4, name='builtin')
        with mock.patch('agentapi.sentinel_policy.is_builtin', side_effect=lambda agent, *a, **k: agent.pk == builtin.pk), \
                mock.patch('agentapi.sentinel_broker.builtin_pk', return_value=builtin.pk):
            cap = sentinel_broker.planner_capacity(['ssh_probe'], self.now)
        self.assertEqual(cap['kinds']['ssh_probe'], {'sentinels': 1, 'slots': 2, 'free': 2})
        self.assertEqual(cap['live'], 2)
        self.assertEqual({a['id'] for a in cap['agents']}, {external.pk, builtin.pk})


class FairnessTests(Fleet):
    def test_projects_and_organizations_take_turns_so_a_big_one_cannot_hog_the_queue(self):
        big = self.project
        other_org = Org.objects.create(name='Org B', slug='org-b')
        small1, small2 = self.make_project('beta', other_org), self.make_project('gamma', other_org)
        for i in range(120):
            self.host(big, f'b{i}')
        for i in range(3):
            self.host(small1, f's{i}')
            self.host(small2, f't{i}')
        self.sentinel(slots=4)
        with mock.patch.object(work_planner, 'batches_per_run', return_value=3):
            self.tick()
        self.assertEqual(sorted(b.project.slug for b in self.batches('ssh_probe')), ['alpha', 'beta', 'gamma'])

    def test_the_turn_moves_on_between_runs(self):
        other_org = Org.objects.create(name='Org B', slug='org-b')
        small = self.make_project('beta', other_org)
        for i in range(60):
            self.host(self.project, f'b{i}')
            self.host(small, f's{i}')
        self.sentinel(slots=4)
        with mock.patch.object(work_planner, 'batches_per_run', return_value=1):
            self.tick()
            PlannerBatch.objects.all().update(status='done', finished_at=self.now)
            self.tick(census=False)
        self.assertEqual({b.project.slug for b in self.batches('ssh_probe')}, {'alpha', 'beta'})

    def test_within_a_project_the_never_run_come_first_then_the_longest_since_a_run(self):
        _n, never = self.host(self.project, 'never')
        _o, old = self.host(self.project, 'old')
        _f, newer = self.host(self.project, 'newer')
        ServiceRun.objects.create(service=ssh_scan.FAILED_SERVICE, asset=f'{old}:22', project=self.project, status='failed', finished_at=self.now - timedelta(days=9))
        ServiceRun.objects.create(service=ssh_scan.FAILED_SERVICE, asset=f'{newer}:22', project=self.project, status='failed', finished_at=self.now - timedelta(hours=30))
        self.sentinel()
        self.tick()
        (batch,) = self.batches('ssh_probe')
        self.assertEqual([u['u'] for u in batch.units], [f'{never}:22', f'{old}:22', f'{newer}:22'])

    def test_web_hosts_that_answered_come_first_for_secrets(self):
        down, _a = self.host(self.project, 'down', ssh=False, web=True)
        up, _b = self.host(self.project, 'up', ssh=False, web=True)
        Subdomain.objects.filter(pk=up.pk).update(http_status=200)
        self.sentinel()
        self.tick()
        (batch,) = self.batches('secrets_scan')
        self.assertEqual([u['u'] for u in batch.units], [up.name, down.name])  # 'down' sorts first by name: the order is the planner's


class DedupeTests(Fleet):
    def test_an_endpoint_already_queued_for_a_sentinel_is_not_queued_again(self):
        _s, address = self.host(self.project, 'a')
        self.host(self.project, 'b')
        self.sentinel()
        SentinelTask.objects.create(project=self.project, kind='ssh_probe', status='queued', priority=1, target={'targets': [{'address': address, 'port': 22}]})
        self.tick()
        units = [u['u'] for b in self.batches('ssh_probe') for u in b.units]
        self.assertNotIn(f'{address}:22', units)
        self.assertEqual(len(units), 1)

    def test_a_fresh_ledger_row_is_not_due_even_when_the_census_was_taken_before_it(self):
        _s, address = self.host(self.project, 'a')
        self.host(self.project, 'b')
        self.sentinel()
        work_planner.census(self.now)
        ledger.record(ssh_scan.SERVICE, [f'{address}:22'], self.project.pk)  # a scan stage inspected it after the census
        out = work_planner.run(self.now)
        units = [u['u'] for b in self.batches('ssh_probe') for u in b.units]
        self.assertNotIn(f'{address}:22', units)
        self.assertEqual(out['queued'], {'ssh_probe': 1})

    def test_an_endpoint_past_its_ttl_is_due_again(self):
        _s, address = self.host(self.project, 'a')
        ledger.record(ssh_scan.SERVICE, [f'{address}:22'], self.project.pk)
        self.sentinel()
        self.assertEqual(self.tick()['state'], 'nothing_due')
        ServiceRun.objects.filter(service=ssh_scan.SERVICE).update(finished_at=self.now - timedelta(days=8))
        self.assertEqual(self.tick()['queued'], {'ssh_probe': 1})

    def test_a_batch_lost_with_its_worker_stops_counting_as_in_flight(self):
        self.host(self.project, 'a')
        self.sentinel()
        PlannerBatch.objects.create(project=self.project, kind='ssh_probe', units=[{'u': '203.0.113.2:22'}], status='queued', created_at=self.now - timedelta(hours=2))
        work_planner._reap(self.now)
        self.assertEqual(PlannerBatch.objects.get().status, 'failed')


class CountersTests(Fleet):
    def test_waiting_tasks_include_the_planners_and_the_host_feed_does_not_count_them(self):
        SentinelTask.objects.create(project=self.project, kind='ssh_probe', target={}, status='queued', priority=sentinel_broker.PLANNER_PRIORITY)
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status='queued', priority=1)
        self.assertEqual(sentinel_broker.waiting_tasks(), 2)
        self.assertEqual(sentinel_broker.waiting_tasks(planner=False), 1)

    def test_the_planner_line_says_what_it_did_what_is_left_and_when_it_runs_next(self):
        for i in range(30):
            self.host(self.project, f'h{i}')
        self.sentinel(slots=4)
        with mock.patch.object(work_planner, 'batches_per_run', return_value=1):
            self.tick()
        view = work_planner.overview(None, self.now + timedelta(seconds=20))
        self.assertEqual(view['line'], 'Planner: queued 25 SSH checks, 5 SSH checks still due, next run in 40 s')
        row = {r['kind']: r for r in view['kinds']}['ssh_probe']
        self.assertEqual((row['due'], row['in_flight'], row['applicable']), (30, 25, 30))

    def test_the_due_table_is_limited_to_the_projects_the_viewer_may_read(self):
        other = self.make_project('beta', self.org)
        self.host(self.project, 'a')
        self.host(other, 'b')
        self.host(other, 'c')
        self.sentinel()
        work_planner.census(self.now)
        mine = {r['kind']: r for r in work_planner.overview({self.project.pk}, self.now)['kinds']}
        everything = {r['kind']: r for r in work_planner.overview(None, self.now)['kinds']}
        self.assertEqual((mine['ssh_probe']['due'], everything['ssh_probe']['due']), (1, 3))

    def test_the_live_overview_carries_the_planner(self):
        self.host(self.project, 'a')
        self.sentinel()
        self.tick()
        view = sentinel_broker._planner_overview(None)
        self.assertIn('line', view)
        self.assertEqual([k['kind'] for k in view['kinds']], ['ssh_probe', 'secrets_scan'])


class RunBatchTests(Fleet):
    """A planned batch goes through the scan stage's own entry point, a fake Sentinel serves it, the ledger and the observations are written and the due
    count falls."""

    def test_ssh_batches_are_served_at_the_lowest_priority_with_no_scan_and_the_due_count_falls(self):
        for i in range(30):
            self.host(self.project, f'h{i}')
        fake = FakeScanner(kinds=['ssh_probe'], responders={'ssh_probe': lambda task: {
            'outcome': 'done', 'touched': [], 'refused': [], 'hosts': [host_row(t['address'], t['port']) for t in task['target']['targets']]}}, max_concurrent=4)
        with fake:
            out = self.tick()
            self.assertEqual(out['due']['ssh_probe'], 30)
            for batch in self.batches('ssh_probe'):
                self.assertEqual(work_planner.execute_batch(batch.pk)['status'], 'done')
        tasks = SentinelTask.objects.filter(kind='ssh_probe')
        self.assertEqual(sorted(tasks.values_list('priority', flat=True)), [0, 0])
        self.assertEqual(set(tasks.values_list('scan_id', flat=True)), {None})
        self.assertEqual(ServiceRun.objects.filter(service='ssh-probe', status='done').count(), 30)
        self.assertTrue(ProbeObservation.objects.filter(probe='ssh-probe').exists())
        self.assertEqual({b.status for b in self.batches()}, {'done'})
        self.assertEqual(work_planner.census(self.now)['projects'][str(self.project.pk)]['kinds']['ssh_probe']['due'], 0)

    def test_a_batch_runs_once(self):
        self.host(self.project, 'a')
        self.sentinel()
        self.tick()
        (batch,) = self.batches('ssh_probe')
        calls = []
        with mock.patch.object(ssh_scan, 'run_for_hosts', side_effect=lambda *a, **k: calls.append(1) or {'inspected': 0, 'endpoints': 0, 'findings': 0}):
            work_planner.execute_batch(batch.pk)
            self.assertEqual(work_planner.execute_batch(batch.pk)['status'], 'ignored')
        self.assertEqual(len(calls), 1)

    def test_no_sentinel_to_take_it_fails_the_batch_and_leaves_the_units_due_and_alone_for_a_while(self):
        _s, address = self.host(self.project, 'a')
        self.sentinel()
        self.tick()
        (batch,) = self.batches('ssh_probe')
        Agent.objects.all().update(last_seen=self.now - timedelta(hours=1))  # it went away before the batch ran
        out = work_planner.execute_batch(batch.pk)
        self.assertEqual(out['status'], 'failed')
        self.assertEqual(ServiceRun.objects.filter(service='ssh-probe').count(), 0)
        self.assertEqual(self.tick()['queued'], {})
        self.assertTrue(cache.get(work_planner.SKIP_KEY.format(kind='ssh_probe', project=self.project.pk, unit=f'{address}:22')))

    def test_secrets_batches_read_the_routed_web_hosts_through_the_stage_entry(self):
        for i in range(3):
            self.host(self.project, f'w{i}', ssh=False, web=True)
        self.sentinel()
        self.tick()
        (batch,) = self.batches('secrets_scan')
        seen = []

        def dispatch(project, target, hosts, scan):
            seen.append((target['hosts'][0]['host'], scan))
            return {'outcome': 'done', 'findings': [], 'fetched': answered(target), 'references': []}
        out = work_planner.execute_batch(batch.pk, dispatch=dispatch)
        self.assertEqual(out['status'], 'done')
        self.assertEqual(len(seen), 1)
        self.assertIsNone(seen[0][1])
        self.assertEqual(ServiceRun.objects.filter(service='secrets-scan', status='done').count(), 3)
        self.assertEqual(work_planner.census(self.now)['projects'][str(self.project.pk)]['kinds']['secrets_scan']['due'], 0)

    def test_the_stage_entry_still_runs_the_stage_the_way_it_did(self):
        self.host(self.project, 'w', ssh=False, web=True)
        calls = []
        out = secrets_scan.run_for_scan(self.project.t_scan.pk, dispatch=lambda p, t, h, s: calls.append(s) or {'outcome': 'done', 'findings': [],
                                                                                                              'fetched': answered(t), 'references': []})
        self.assertEqual((out['hosts'], out['tasks']), (1, 1))
        self.assertEqual(calls[0].pk, self.project.t_scan.pk)


def answered(target):
    """What a Sentinel sends back for a batch whose every host answered: one fetched page per host, with its HTTP status (a host with none was
    not read, cveFeed.secrets_scan.read_hosts)."""
    return [{'url': f"https://{h['host']}/", 'kind': 'page', 'status': 200, 'bytes': 0, 'content_type': 'text/html'} for h in target['hosts']]


class GuardTests(SimpleTestCase):
    def test_every_sentinel_kind_is_planner_enabled_or_on_the_allowlist_with_a_reason(self):
        enabled = set(work_planner.specs())
        listed = set(work_planner.NOT_PLANNED)
        self.assertFalse(enabled & listed, 'a kind is both planner enabled and on the allowlist')
        missing = set(sentinel_contract.KINDS) - enabled - listed
        self.assertFalse(missing, f'{sorted(missing)}: a new Sentinel kind must be planner enabled (work_planner.specs) or listed in work_planner.NOT_PLANNED with a reason')
        self.assertFalse((enabled | listed) - set(sentinel_contract.KINDS), 'the planner names a kind the contract does not have')
        for kind, (_check, reason) in work_planner.NOT_PLANNED.items():
            self.assertGreater(len(reason), 10, f'{kind} needs a reason')

    def test_every_check_a_kind_is_tied_to_exists_in_the_registry(self):
        from cveFeed import check_coverage
        for spec in work_planner.specs().values():
            self.assertIn(spec.check_id, check_coverage.BY_ID, spec.kind)
        for kind, (check, _reason) in work_planner.NOT_PLANNED.items():
            self.assertTrue(check is None or check in check_coverage.BY_ID, f'{kind}: {check} is not a check')

    def test_a_check_of_a_sentinel_stage_is_never_silently_unplanned(self):
        from cveFeed import check_coverage
        reached = {s.check_id for s in work_planner.specs().values()} | {c for c, _r in work_planner.NOT_PLANNED.values() if c}
        stages = {'secrets_scan', 'ssh_probe', 'nmap_scan', 'nuclei_light_scan', 'nuclei_targeted_scan', 'wpscan', 'wafw00f', 'route_auth_scan', 'version_probes',
                  'node2shell', 'rdp_screenshot', 'db_exposure_scan'}
        unplaced = {c.id for c in check_coverage.CHECKS if set(c.stages) & stages} - reached
        self.assertFalse(unplaced, f'checks of Sentinel stages that the planner neither runs nor explains: {sorted(unplaced)}')

    def test_the_per_task_size_is_the_contracts_bound(self):
        for spec in work_planner.specs().values():
            props = sentinel_contract.load()['$defs']['targets'][spec.kind]['properties']
            self.assertEqual(spec.per_task, (props.get('targets') or props['hosts'])['maxItems'], spec.kind)

    def test_the_planners_priority_is_below_every_other_dispatch(self):
        self.assertEqual(sentinel_broker.PLANNER_PRIORITY, 0)
        self.assertEqual(SentinelTask._meta.get_field('priority').default, 1)

    def test_the_tick_and_the_census_run_while_scanning_is_paused_so_the_page_can_say_so(self):
        from cveFeed import scan_control
        self.assertIn('work_planner_tick', scan_control.PAUSE_EXEMPT_TASKS)
        self.assertIn('work_planner_census', scan_control.PAUSE_EXEMPT_TASKS)
        self.assertNotIn('work_planner_batch', scan_control.PAUSE_EXEMPT_TASKS)
