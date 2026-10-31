"""Host assessments in batches: the feed carries the due hosts of one target through ONE pipeline run (``CVENGINE_ASSESS_BATCH``), each host
keeping its own row, outcome, bookkeeping and gates, with the caps counted in pipeline runs and the reaper and time limits sized for a batch."""
import os
import socket
import uuid
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_dispatch
from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import assessment_review as ar
from cveFeed import coverage_topup, discovery, host_assessment, reaper
from cveFeed.host_assessment import BATCH_STOPPED, batch_size, batches, enqueue, enqueue_batch, execute_batch
from cveFeed.models import HostAssessment, HostState
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_perf_hostpipeline import _stages


def unique_ids(*args, **kwargs):
    return mock.Mock(id=str(uuid.uuid4()))


class Base(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Batch org', slug='batch-org')
        self.project = Project.objects.create(name='Batch', slug='batch', org=self.org, insert_date=self.now)
        self.other = Project.objects.create(name='Batch other', slug='batch-other', org=self.org, insert_date=self.now)
        self.a1 = Domain.objects.create(name='a1.example', project=self.project, insert_date=self.now)
        self.a2 = Domain.objects.create(name='a2.example', project=self.project, insert_date=self.now)
        self.b1 = Domain.objects.create(name='b1.example', project=self.other, insert_date=self.now)
        EngineType.objects.create(engine_name='batch-engine', yaml_configuration='x', default_engine=True)
        patcher = mock.patch.dict(os.environ, {'CVENGINE_ASSESS_BATCH': '32'})  # the default, whatever the environment of the run says
        patcher.start()
        self.addCleanup(patcher.stop)

    def hosts(self, domain, n, prefix='h'):
        return [Subdomain.objects.create(target_domain=domain, name=f'{prefix}{i}.{domain.name}') for i in range(n)]

    def sweep(self, size, fn=None):
        """One top-up sweep with the given batch size; returns (result, batch task mock, single task mock)."""
        with mock.patch.dict(os.environ, {'CVENGINE_ASSESS_BATCH': str(size)}), \
                mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
                mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=unique_ids) as many, \
                mock.patch('cveFeed.tasks.assess_host.apply_async', side_effect=unique_ids) as one:
            result = (fn or coverage_topup.top_up)(now=self.now)
        return result, many, one


class BatchSizeTests(SimpleTestCase):
    def test_default_range_and_unreadable_values(self):
        cases = {None: 32, '': 32, '1': 1, '16': 16, '64': 64, '65': 64, '1000': 64, '0': 1, '-3': 1, 'many': 32, ' 8 ': 8}
        for raw, expected in cases.items():
            env = {} if raw is None else {'CVENGINE_ASSESS_BATCH': raw}
            with mock.patch.dict(os.environ, env, clear=False):
                if raw is None:
                    os.environ.pop('CVENGINE_ASSESS_BATCH', None)
                self.assertEqual(batch_size(), expected, raw)


class GroupingTests(Base):
    def test_hosts_group_by_target_and_split_at_the_batch_size(self):
        subs = self.hosts(self.a1, 5) + self.hosts(self.a2, 2) + self.hosts(self.a1, 2, prefix='x')
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in subs]).select_related('target_domain').order_by('pk'))
        groups = batches(subs, 4)
        self.assertEqual([(g[0].target_domain.name, len(g)) for g in groups], [('a1.example', 4), ('a1.example', 3), ('a2.example', 2)])
        for group in groups:
            self.assertEqual(len({s.target_domain_id for s in group}), 1)
        self.assertEqual(sorted(s.pk for g in groups for s in g), sorted(s.pk for s in subs))  # nothing lost, nothing twice

    def test_size_one_is_every_host_alone(self):
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in self.hosts(self.a1, 4)]).select_related('target_domain'))
        self.assertEqual([len(g) for g in batches(subs, 1)], [1, 1, 1, 1])

    def test_a_host_scoped_target_and_an_address_typed_as_a_host_run_alone(self):
        single = Domain.objects.create(name='one.example', project=self.project, insert_date=self.now, scope_mode=Domain.SCOPE_HOST)
        literal = Domain.objects.create(name='203.0.113.9', project=self.project, insert_date=self.now)
        subs = [Subdomain.objects.create(target_domain=single, name='one.example'),
                Subdomain.objects.create(target_domain=literal, name='203.0.113.9'),
                Subdomain.objects.create(target_domain=literal, name='203.0.113.10')] + self.hosts(self.a1, 3)
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in subs]).select_related('target_domain').order_by('pk'))
        self.assertEqual([len(g) for g in batches(subs, 32)], [1, 1, 1, 3])


class TopUpBatchTests(Base):
    def test_due_hosts_of_a_target_are_one_run_and_projects_never_mix(self):
        self.hosts(self.a1, 5)
        self.hosts(self.a2, 3)
        self.hosts(self.b1, 4)
        result, many, one = self.sweep(32)
        self.assertEqual((result['hosts_queued'], result['batches_queued']), (12, 3))
        one.assert_not_called()
        self.assertEqual(many.call_count, 3)
        seen = []
        for call_ in many.call_args_list:
            ids = call_.kwargs['args'][0]
            rows = list(HostAssessment.objects.filter(pk__in=ids))
            self.assertEqual(len({(r.project_id, r.domain_id) for r in rows}), 1)  # one project, one target per run
            self.assertEqual({r.celery_id for r in rows}, {call_.kwargs['task_id']})  # the rows share the task that carries them
            self.assertEqual({r.status for r in rows}, {'queued'})
            self.assertEqual(call_.kwargs['queue'], 'discovery_queue')
            seen += [r.host for r in rows]
        self.assertEqual(sorted(seen), sorted(Subdomain.objects.values_list('name', flat=True)))  # a row for every host
        self.assertEqual(HostAssessment.objects.filter(project=self.other).count(), 4)

    def test_batch_of_one_is_the_old_behaviour_exactly(self):
        self.hosts(self.a1, 7)
        result, many, one = self.sweep(1)
        self.assertEqual(result['hosts_queued'], 5)  # the per-project cap of 5, one run each
        self.assertEqual(one.call_count, 5)
        many.assert_not_called()
        self.assertEqual(HostAssessment.objects.filter(project=self.project, status='queued').count(), 5)
        self.assertEqual(host_assessment.active_slots(self.project), 5)
        self.assertEqual(len({r.celery_id for r in HostAssessment.objects.all()}), 5)

    def test_caps_bound_the_runs_and_so_the_hosts_in_flight(self):
        self.hosts(self.a1, 50)
        first, many, _ = self.sweep(2)
        # the project's cap is 5 runs: with 2 hosts a run that is 10 hosts, never the 50 that are due
        self.assertEqual((first['hosts_queued'], first['batches_queued']), (10, 5))
        self.assertEqual(host_assessment.active_count(self.project), 10)  # every host still has its own active row
        self.assertEqual(host_assessment.active_slots(self.project), 5)
        second, many, _ = self.sweep(2)
        self.assertEqual(second['hosts_queued'], 0)
        many.assert_not_called()

    def test_a_batch_is_one_slot_and_its_hosts_are_counted_one_by_one(self):
        for celery_id, n in (('t1', 6), ('t2', 1), ('', 1)):
            for i in range(n):
                HostAssessment.objects.create(project=self.project, domain=self.a1, host=f'{celery_id or "none"}{i}.a1.example',
                                              status='running', celery_id=celery_id)
        self.assertEqual(host_assessment.active_count(self.project), 8)
        self.assertEqual(host_assessment.active_slots(self.project), 3)
        self.assertEqual(host_assessment.active_slots(self.other), 0)

    def test_the_global_cap_binds_in_runs_across_projects(self):
        for i in range(18):  # 18 of the 20 global slots are taken by another project
            HostAssessment.objects.create(project=self.other, domain=self.b1, host=f'busy{i}.b1.example', status='running',
                                          celery_id=f'busy-{i}')
        self.hosts(self.a1, 50)
        result, many, _ = self.sweep(32)
        self.assertEqual((result['batches_queued'], result['hosts_queued']), (2, 50))  # two runs left in the global cap, 32 + 18 hosts
        self.assertEqual(host_assessment.active_slots(), 20)

    def test_a_paused_or_bounty_blocked_project_queues_nothing(self):
        self.hosts(self.a1, 3)
        with mock.patch.dict(os.environ, {'CVENGINE_ASSESS_BATCH': '32'}), \
                mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
                mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value={self.project.pk}), \
                mock.patch('cveFeed.tasks.assess_hosts.apply_async') as many:
            self.assertEqual(coverage_topup.top_up(now=self.now)['hosts_queued'], 0)
        many.assert_not_called()

    def test_an_excluded_host_is_left_out_and_the_rest_of_the_run_goes_on(self):
        subs = self.hosts(self.a1, 4)
        with mock.patch('cveFeed.exclusions.is_excluded', side_effect=lambda project, host: host == subs[1].name):
            result, many, _ = self.sweep(32)
        self.assertEqual((result['hosts_queued'], result['batches_queued']), (3, 1))
        self.assertFalse(HostAssessment.objects.filter(host=subs[1].name).exists())

    def test_a_host_already_being_assessed_is_not_queued_twice(self):
        subs = self.hosts(self.a1, 3)
        HostAssessment.objects.create(project=self.project, domain=self.a1, host=subs[0].name, status='running', celery_id='t')
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=unique_ids):
            jobs, skipped = enqueue_batch(self.project, list(Subdomain.objects.filter(pk__in=[s.pk for s in subs]).select_related('target_domain')))
        self.assertEqual(len(jobs), 2)
        self.assertEqual([s.name for s, _ in skipped if _ == 'already queued'], [subs[0].name])
        self.assertEqual(HostAssessment.objects.filter(project=self.project, host=subs[0].name).count(), 1)

    def test_a_broker_failure_fails_every_row_of_the_run_and_they_can_be_queued_again(self):
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in self.hosts(self.a1, 3)]).select_related('target_domain'))
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=OSError('broker unavailable')):
            jobs, skipped = enqueue_batch(self.project, subs)
        self.assertEqual(jobs, [])
        self.assertEqual(set(HostAssessment.objects.values_list('status', 'error')), {('failed', 'broker enqueue failed: OSError')})
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=unique_ids):
            jobs, skipped = enqueue_batch(self.project, subs)
        self.assertEqual(len(jobs), 3)

    def sentinel(self, scope):
        user = User.objects.get_or_create(username='batch-owner')[0]
        token, _raw = create_token(user, f'batch-{Agent.objects.count()}')
        return Agent.objects.create(token=token, name=f'batch-{Agent.objects.count()}', kind='scanner', status='active', max_concurrent=3,
                                    capabilities=['nmap', 'nuclei_light'], last_seen=timezone.now(), scope=scope)

    def test_a_project_a_host_narrowed_sentinel_covers_is_not_batched(self):
        # a task that names many hosts is claimable by a Sentinel any one of them is in the scope of, so these hosts keep a task each
        self.hosts(self.a1, 6)
        self.sentinel({'orgs': [], 'projects': [self.project.slug], 'hosts': ['h0.a1.example']})
        result, many, one = self.sweep(32)
        self.assertEqual((result['hosts_queued'], result['batches_queued']), (6, 6))  # a run each (the live Sentinel's 3 slots make the cap 9)
        many.assert_not_called()
        self.assertEqual(one.call_count, 6)

    def test_a_sentinel_narrowed_to_hosts_of_another_project_does_not_stop_batching(self):
        self.hosts(self.a1, 6)
        self.sentinel({'orgs': [], 'projects': [self.other.slug], 'hosts': ['h0.b1.example']})
        self.sentinel({'orgs': [], 'projects': [self.project.slug], 'hosts': []})  # covers the project, no narrowing
        result, many, one = self.sweep(32)
        self.assertEqual((result['hosts_queued'], result['batches_queued']), (6, 1))
        one.assert_not_called()

    def test_the_once_a_minute_feed_sends_runs_of_hosts_not_single_hosts(self):
        self.hosts(self.a1, 30)
        with mock.patch('agentapi.sentinel_broker.project_slots', return_value=3), mock.patch('agentapi.sentinel_broker.total_slots', return_value=3), \
                mock.patch('agentapi.sentinel_broker.waiting_tasks', return_value=0):
            out, many, one = self.sweep(32, coverage_topup.feed_sentinels)
        self.assertEqual((out['hosts_queued'], out['batches_queued']), (30, 1))
        self.assertEqual(many.call_count, 1)
        one.assert_not_called()

    def test_the_refresh_batches_the_stalest_hosts_too(self):
        self.hosts(self.a1, 6)
        with mock.patch('agentapi.sentinel_broker.project_slots', return_value=3), mock.patch('agentapi.sentinel_broker.total_slots', return_value=3):
            result, many, one = self.sweep(32, coverage_topup.refresh_for_sentinels)
        self.assertEqual(result['refreshed'], 6)
        self.assertEqual(many.call_count, 1)
        one.assert_not_called()
        self.assertEqual(set(HostAssessment.objects.values_list('source', flat=True)), {'refresh'})


class TenancyTests(Base):
    def test_a_host_of_another_project_is_never_put_in_a_run(self):
        mine = self.hosts(self.a1, 2)
        theirs = self.hosts(self.b1, 1)
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in mine + theirs]).select_related('target_domain'))
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=unique_ids):
            jobs, skipped = enqueue_batch(self.project, subs)
        self.assertEqual({j.host for j in jobs}, {s.name for s in mine})
        self.assertEqual([(s.name, why) for s, why in skipped], [(theirs[0].name, 'host is outside its stored target scope')])
        self.assertFalse(HostAssessment.objects.filter(project=self.other).exists())

    def test_two_targets_in_one_call_are_two_runs_not_one(self):
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in self.hosts(self.a1, 1) + self.hosts(self.a2, 1)])
                    .select_related('target_domain').order_by('pk'))
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=unique_ids):
            jobs, skipped = enqueue_batch(self.project, subs)
        self.assertEqual(len(jobs), 1)  # the second target's host is refused in this call: batches() never builds such a group
        self.assertEqual([why for _, why in skipped], ['a batch holds the hosts of one target'])

    def test_the_global_cap_counts_runs_of_projects_the_caller_cannot_see(self):
        from tenancy import scope
        for i in range(20):
            HostAssessment.objects.create(project=self.other, domain=self.b1, host=f'h{i}.b1.example', status='running', celery_id=f't{i}')
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in self.hosts(self.a1, 2)]).select_related('target_domain'))
        user = User.objects.create_user('batch-user', password='x')
        tokens = scope.set_scope({self.project.pk}, user)
        try:
            self.assertEqual(HostAssessment.objects.filter(status='running').count(), 0)
            with self.assertRaisesRegex(RuntimeError, 'capacity'):
                enqueue_batch(self.project, subs)
        finally:
            scope.reset_scope(tokens)

    def test_a_person_asking_for_one_host_is_still_one_run_for_that_host(self):
        [sub] = self.hosts(self.a1, 1)
        with mock.patch('cveFeed.tasks.assess_host.apply_async', side_effect=unique_ids) as one, \
                mock.patch('cveFeed.tasks.assess_hosts.apply_async') as many:
            job, created = enqueue(self.project, sub, user=User.objects.create_user('batch-person', password='x'))
        self.assertTrue(created)
        one.assert_called_once()
        many.assert_not_called()


class ExecuteBatchTests(Base):
    """The real pipeline with its stages doubled: one run, one scan, one outcome per host."""

    def queue(self, domain, names):
        subs = [Subdomain.objects.create(target_domain=domain, name=name) for name in names]
        subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in subs]).select_related('target_domain').order_by('pk'))
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async', side_effect=unique_ids):
            jobs, skipped = enqueue_batch(self.project, subs)
        self.assertEqual(skipped, [])
        return jobs

    @staticmethod
    def public(wanted):
        """Every name resolves, each to its own public address (a test address is not scannable with ``force``)."""
        return {(n, f'8.8.8.{i + 1}') for i, n in enumerate(sorted(wanted))}

    def run_batch(self, jobs, **over):
        nmap, kwargs = _stages(**{'resolver': self.public, **over})
        real = discovery.run_host_pipeline

        def piped(*args, **kw):
            return real(*args, **{**kw, **kwargs})
        with mock.patch('cveFeed.discovery.run_host_pipeline', side_effect=piped) as pipeline, \
                mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), \
                mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'), \
                mock.patch('cveFeed.hygiene.run_hygiene', return_value={'tls_hosts': 1}) as hygiene:
            outcome = execute_batch([j.pk for j in jobs], celery_id='batch-task')
        return outcome, nmap, pipeline, hygiene

    def test_one_run_serves_every_host_and_each_keeps_its_own_outcome(self):
        names = ['ok1.a1.example', 'ok2.a1.example', 'nodns.a1.example']
        jobs = self.queue(self.a1, names)
        resolver = lambda wanted: {(n, f'8.8.8.{i + 1}') for i, n in enumerate(sorted(wanted)) if not n.startswith('nodns')}  # noqa: E731
        outcome, nmap, pipeline, hygiene = self.run_batch(jobs, resolver=resolver)
        self.assertEqual(outcome, {'hosts': 3, 'statuses': {'completed': 2, 'inconclusive': 1}})
        self.assertEqual(pipeline.call_count, 1)  # one pipeline run, not three
        self.assertEqual(pipeline.call_args.args[1], names)
        self.assertEqual(len(nmap), 1)  # and one nmap call naming both addresses: what a Sentinel is given as one multi-target task
        self.assertEqual(len(nmap[0]), 2)
        rows = {j.host: HostAssessment.objects.get(pk=j.pk) for j in jobs}
        self.assertEqual({r.scan_id for r in rows.values()}, {rows['ok1.a1.example'].scan_id})  # the shared scan, for the Live page and the stages
        self.assertEqual({h: r.status for h, r in rows.items()}, {'ok1.a1.example': 'completed', 'ok2.a1.example': 'completed',
                                                                    'nodns.a1.example': 'inconclusive'})
        self.assertEqual(rows['nodns.a1.example'].result['resolved'], 0)
        self.assertEqual(rows['ok1.a1.example'].result['resolved'], 1)
        self.assertTrue(rows['nodns.a1.example'].error.startswith('No scannable IP address'))
        self.assertTrue(all(r.finished_at and r.started_at for r in rows.values()))
        scan = ScanHistory.objects.get(pk=rows['ok1.a1.example'].scan_id)
        self.assertEqual(scan.scan_status, discovery.SUCCESS)
        for name in ('nmap_scan', 'nuclei_light_scan', 'nuclei_targeted_scan'):
            self.assertTrue(ScanActivity.objects.filter(scan_of=scan, name=name, status=discovery.SUCCESS).exists(), name)
        # per-host bookkeeping: only the host with no address starts a streak, the others are reset
        self.assertEqual(HostState.objects.get(project=self.project, host='nodns.a1.example').unresolved_checks, 1)
        self.assertFalse(HostState.objects.filter(project=self.project, host__in=['ok1.a1.example', 'ok2.a1.example'],
                                                  unresolved_checks__gte=1).exists())
        hygiene.assert_called_once()
        self.assertEqual(sorted(hygiene.call_args.kwargs['hosts']), ['ok1.a1.example', 'ok2.a1.example'])  # TLS hygiene of the hosts that resolved

    def test_the_scan_fails_only_when_every_host_failed(self):
        jobs = self.queue(self.a1, ['x1.a1.example', 'x2.a1.example'])
        outcome, nmap, _pipeline, _hygiene = self.run_batch(jobs, resolver=lambda wanted: set())
        self.assertEqual(outcome['statuses'], {'inconclusive': 2})
        self.assertEqual(nmap, [])
        scan = ScanHistory.objects.get(pk=HostAssessment.objects.get(pk=jobs[0].pk).scan_id)
        self.assertEqual(scan.scan_status, discovery.FAILED)
        self.assertEqual(HostState.objects.filter(project=self.project, unresolved_checks=1).count(), 2)

    def test_a_lookup_that_is_not_answered_for_one_host_does_not_fail_the_others(self):
        jobs = self.queue(self.a1, ['ok1.a1.example', 'slow.a1.example', 'ok2.a1.example'])

        real_lookup = socket.getaddrinfo

        def lookup(name, *args, **kwargs):
            if not str(name).endswith('.a1.example'):
                return real_lookup(name, *args, **kwargs)  # the database and Redis are not the test's to break
            if name.startswith('slow'):
                raise socket.gaierror(socket.EAI_AGAIN, 'Temporary failure in name resolution')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (f'8.8.4.{len(name) % 200 + 1}', 0))]
        nmap, kwargs = _stages()
        del kwargs['resolver']  # the real resolver, so a lookup that is not answered is told from a name with no address
        real = discovery.run_host_pipeline
        with mock.patch('cveFeed.discovery.run_host_pipeline', side_effect=lambda *a, **k: real(*a, **{**k, **kwargs})), \
                mock.patch('socket.getaddrinfo', side_effect=lookup), \
                mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), \
                mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'), \
                mock.patch('cveFeed.hygiene.run_hygiene', return_value={'tls_hosts': 1}):
            outcome = execute_batch([j.pk for j in jobs], celery_id='t')
        rows = {j.host: HostAssessment.objects.get(pk=j.pk) for j in jobs}
        self.assertEqual({h: r.status for h, r in rows.items()},
                         {'ok1.a1.example': 'completed', 'ok2.a1.example': 'completed', 'slow.a1.example': 'inconclusive'})
        self.assertIn('DNS could not answer', rows['slow.a1.example'].error)
        self.assertEqual(ScanHistory.objects.get(pk=rows['ok1.a1.example'].scan_id).scan_status, discovery.SUCCESS)
        self.assertEqual(outcome['statuses'], {'completed': 2, 'inconclusive': 1})
        self.assertFalse(Subdomain.objects.filter(scan_history_id=rows['ok1.a1.example'].scan_id, name='slow.a1.example').exists())  # not recorded as a host with no address

    def test_a_host_that_fails_the_gate_at_the_point_of_use_ends_alone(self):
        jobs = self.queue(self.a1, ['ok1.a1.example', 'gone.a1.example', 'ok2.a1.example'])
        with mock.patch('cveFeed.exclusions.is_excluded', side_effect=lambda project, host: host == 'gone.a1.example'):
            outcome, nmap, pipeline, _ = self.run_batch(jobs)
        rows = {j.host: HostAssessment.objects.get(pk=j.pk) for j in jobs}
        self.assertEqual({h: r.status for h, r in rows.items()},
                         {'ok1.a1.example': 'completed', 'ok2.a1.example': 'completed', 'gone.a1.example': 'inconclusive'})
        self.assertEqual(pipeline.call_args.args[1], ['ok1.a1.example', 'ok2.a1.example'])  # the refused host is not even offered to the pipeline
        self.assertIsNone(rows['gone.a1.example'].scan_id)

    def test_a_host_stopped_while_it_waited_is_skipped(self):
        jobs = self.queue(self.a1, ['ok1.a1.example', 'stop.a1.example'])
        HostAssessment.objects.filter(pk=jobs[1].pk).update(status='stopped', error='Stopped by a person')
        outcome, nmap, pipeline, _ = self.run_batch(jobs)
        self.assertEqual(pipeline.call_args.args[1], ['ok1.a1.example'])
        self.assertEqual(HostAssessment.objects.get(pk=jobs[1].pk).status, 'stopped')
        self.assertEqual(outcome['hosts'], 1)

    def test_every_row_stopped_means_nothing_runs(self):
        jobs = self.queue(self.a1, ['a.a1.example', 'b.a1.example'])
        HostAssessment.objects.update(status='stopped')
        self.assertEqual(execute_batch([j.pk for j in jobs]), {'status': 'stopped_or_already_started'})

    def test_a_second_message_for_a_run_that_started_does_nothing(self):
        jobs = self.queue(self.a1, ['ok1.a1.example'])
        self.run_batch(jobs)
        self.assertEqual(execute_batch([j.pk for j in jobs]), {'status': 'stopped_or_already_started'})

    def test_a_stop_or_pause_mid_run_stops_every_host_of_the_run(self):
        jobs = self.queue(self.a1, ['ok1.a1.example', 'ok2.a1.example'])
        with mock.patch('cveFeed.discovery.run_host_pipeline', return_value={'scan_id': None, 'status': 'aborted'}):
            outcome = execute_batch([j.pk for j in jobs])
        self.assertEqual(outcome['statuses'], {'stopped': 2})
        self.assertEqual(set(HostAssessment.objects.values_list('status', flat=True)), {'stopped'})

    def test_an_exception_fails_the_run_with_a_diagnostic_and_no_host_text(self):
        jobs = self.queue(self.a1, ['ok1.a1.example', 'ok2.a1.example'])
        secret = 'connection to 10.0.0.7:5432 refused at /opt/app/secret_path.py'
        with mock.patch('cveFeed.discovery.run_host_pipeline', side_effect=RuntimeError(secret)), \
                self.assertLogs('cveFeed.activity', 'WARNING'):
            outcome = execute_batch([j.pk for j in jobs])
        self.assertEqual(outcome['statuses'], {'failed': 2})
        for job in HostAssessment.objects.filter(pk__in=[j.pk for j in jobs]):
            self.assertNotIn('10.0.0.7', job.error + str(job.result))
            self.assertTrue(job.error.startswith(f'Host assessment #{job.pk} failed (RuntimeError); diagnostic '), job.error)

    def test_a_failed_stage_is_the_runs_for_every_host(self):
        jobs = self.queue(self.a1, ['ok1.a1.example', 'ok2.a1.example'])
        outcome = {'status': discovery.SUCCESS, 'failed_stages': ['nmap_scan'], 'scan_id': None, 'error': 'Failed stages: nmap_scan', 'resolved': 2}
        with mock.patch('cveFeed.discovery.run_host_pipeline', return_value=outcome):
            result = execute_batch([j.pk for j in jobs])
        self.assertEqual(result['statuses'], {'failed': 2})
        self.assertEqual(set(HostAssessment.objects.values_list('error', flat=True)), {'Failed stages: nmap_scan'})
        self.assertEqual(set(HostAssessment.objects.values_list('result__resolved', flat=True)), {1})  # each host resolved once, not "2" for the run

    def test_a_single_row_through_the_batch_task_is_the_single_host_run(self):
        jobs = self.queue(self.a1, ['ok1.a1.example'])
        outcome, nmap, pipeline, hygiene = self.run_batch(jobs)
        self.assertEqual(outcome['statuses'], {'completed': 1})
        self.assertEqual(sorted(hygiene.call_args.kwargs['hosts']), ['ok1.a1.example'])
        self.assertNotIn('per_host', HostAssessment.objects.get(pk=jobs[0].pk).result)


class RunHostPipelineSingleTests(Base):
    def test_a_one_host_assessment_result_is_what_it_always_was(self):
        [sub] = self.hosts(self.a1, 1)
        job = HostAssessment.objects.create(project=self.project, domain=self.a1, host=sub.name, status='running')
        nmap, kwargs = _stages(resolver=lambda names: {(name, '8.8.8.8') for name in names})
        with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('reNgine.tasks.geo_localize.delay'), \
                mock.patch('cveFeed.hygiene.run_hygiene', return_value={'tls_hosts': 1}) as hygiene:
            out = discovery.run_host_pipeline(self.a1.pk, [sub.name], force=True, hygiene=True, assessment_id=job.pk, **kwargs)
        self.assertNotIn('per_host', out)
        self.assertEqual(hygiene.call_args.kwargs['hosts'], [sub.name])
        self.assertEqual(HostAssessment.objects.get(pk=job.pk).scan_id, out['scan_id'])


class StopTests(Base):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('batch-stopper', password='x')
        ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
        _, self.token = create_token(self.user, 'test')

    def running_batch(self, n):
        subs = self.hosts(self.a1, n)
        scan = ScanHistory.objects.create(domain=self.a1, scan_type=EngineType.objects.first(), start_scan_date=self.now, scan_status=1,
                                          results_dir='x', tasks=[discovery.HOST_PIPELINE_TASK], celery_ids=['batch-task'])
        jobs = [HostAssessment.objects.create(project=self.project, domain=self.a1, host=s.name, status='running', scan=scan,
                                              celery_id='batch-task', started_at=self.now) for s in subs]
        return scan, jobs

    def test_stopping_one_host_stops_the_run_and_the_others_are_due_again(self):
        scan, jobs = self.running_batch(3)
        with mock.patch('reNgine.celery.app.control.revoke'):
            status, body = call(self.token, 'POST', f'/api/v1/projects/batch/host-assessments/{jobs[0].pk}/stop', {})
        self.assertEqual((status, body['status']), (200, 'stopped'))
        self.assertEqual(ScanHistory.objects.get(pk=scan.pk).scan_status, 3)
        rows = {j.pk: HostAssessment.objects.get(pk=j.pk) for j in jobs}
        self.assertEqual(rows[jobs[0].pk].error, 'Stopped by a person')
        for other in jobs[1:]:
            self.assertEqual((rows[other.pk].status, rows[other.pk].error), ('stopped', BATCH_STOPPED))
        # the host a person stopped waits out the 24 hours like any attempt; the ones that were only in the same run are due at the next sweep
        _, due = ar.host_coverage_due(self.project, self.now + timedelta(minutes=1), limit=10, need_count=False)
        by_pk = {s.pk: s.name for s in Subdomain.objects.filter(pk__in=due)}
        self.assertEqual(sorted(by_pk.values()), sorted(j.host for j in jobs[1:]))

    def test_the_worker_finishing_later_does_not_overwrite_a_stopped_row(self):
        scan, jobs = self.running_batch(2)
        with mock.patch('reNgine.celery.app.control.revoke'):
            call(self.token, 'POST', f'/api/v1/projects/batch/host-assessments/{jobs[0].pk}/stop', {})
        host_assessment._finish(HostAssessment.objects.get(pk=jobs[1].pk), {'status': discovery.SUCCESS, 'failed_stages': [], 'scan_id': scan.pk})
        self.assertEqual(HostAssessment.objects.get(pk=jobs[1].pk).status, 'stopped')


class ReaperAndLimitsTests(Base):
    def rows(self, n, started, celery_id='t'):
        return [HostAssessment.objects.create(project=self.project, domain=self.a1, host=f'r{celery_id}{i}.a1.example', status='running',
                                              celery_id=celery_id, started_at=started) for i in range(n)]

    def test_a_batch_running_past_the_single_host_limit_is_left_alone_until_its_own(self):
        now = timezone.now()
        batch = self.rows(8, now - timedelta(hours=7), 'big')  # 32 hosts would be 8 hosts here: six hours per four hosts, capped (see below)
        single = self.rows(1, now - timedelta(hours=7), 'solo')
        pair = self.rows(2, now - timedelta(hours=7), 'pair')  # two hosts are still one host's limit
        reaper.reap(now)
        self.assertEqual({HostAssessment.objects.get(pk=r.pk).status for r in batch}, {'running'})
        self.assertEqual(HostAssessment.objects.get(pk=single[0].pk).status, 'failed')
        self.assertEqual({HostAssessment.objects.get(pk=r.pk).status for r in pair}, {'failed'})

    def test_a_batch_never_outlives_the_discovery_queues_time_limit(self):
        from reNgine import time_limits
        now = timezone.now()
        hard = time_limits.limits_for('discovery_queue')[1]
        self.assertGreater(hard, 6 * 3600)  # a task of this queue may run longer than the single-host limit...
        late = self.rows(8, now - timedelta(seconds=hard + 3600), 'late')  # ...and one that is past even that has lost its task
        fresh = self.rows(8, now - timedelta(hours=hard // 3600 - 1), 'fresh')
        reaper.reap(now)
        self.assertEqual({HostAssessment.objects.get(pk=r.pk).status for r in late}, {'failed'})
        self.assertEqual({HostAssessment.objects.get(pk=r.pk).status for r in fresh}, {'running'})

    def test_an_explicit_running_limit_scales_the_same_way(self):
        now = timezone.now()
        batch = self.rows(8, now - timedelta(hours=3), 'env')
        single = self.rows(1, now - timedelta(hours=3), 'one')
        with mock.patch.dict(os.environ, {'CVENGINE_ASSESSMENT_RUNNING_HOURS': '2'}):
            reaper.reap(now)
        self.assertEqual({HostAssessment.objects.get(pk=r.pk).status for r in batch}, {'running'})
        self.assertEqual(HostAssessment.objects.get(pk=single[0].pk).status, 'failed')

    def test_a_batch_whose_task_is_gone_is_closed_at_once_like_a_single_row(self):
        now = timezone.now()
        batch = self.rows(4, now - timedelta(minutes=10), 'dead')
        counts = reaper.expire_orphaned_running(now, live=set())
        self.assertEqual(counts['HostAssessment'], 4)
        self.assertEqual({HostAssessment.objects.get(pk=r.pk).status for r in batch}, {'failed'})

    def test_a_queued_row_of_a_batch_whose_task_is_alive_is_not_asked_for_again(self):
        old = timezone.now() - timedelta(hours=1)
        rows = [HostAssessment.objects.create(project=self.project, domain=self.a1, host=f'q{i}.a1.example', celery_id='alive') for i in range(3)]
        HostAssessment.objects.filter(pk__in=[r.pk for r in rows]).update(created_at=old)
        with mock.patch('cveFeed.broker_recovery.live_task_ids', return_value={'alive'}), \
                mock.patch('cveFeed.tasks.assess_host.apply_async') as one:
            self.assertEqual(reaper.redispatch_queued_assessments(), 0)
        one.assert_not_called()

    def test_the_batch_task_has_the_discovery_queues_limits(self):
        from reNgine.celery import app
        import cveFeed.tasks  # noqa: F401 - registers the tasks
        single, many = app.tasks['assess_host'], app.tasks['assess_hosts']
        self.assertEqual(many.queue, 'discovery_queue')
        self.assertEqual((many.time_limit, many.soft_time_limit), (single.time_limit, single.soft_time_limit))
        self.assertTrue(many.time_limit and many.time_limit > 6 * 3600)


class SentinelChunkTests(SimpleTestCase):
    def test_every_chunk_of_a_long_address_list_goes_to_a_sentinel(self):
        targets = [f'198.51.100.{i}' for i in range(1, 101)] + [f'203.0.113.{i}' for i in range(1, 51)]  # 150 addresses: three chunks
        sent = []

        def dispatch(project, kind, target, ips=None, **kw):
            sent.append((kind, list(ips)))
            return {'hosts': [{'ip': ip, 'ports': []} for ip in ips]}
        with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'dispatch_or_none', side_effect=dispatch), \
                mock.patch('cveFeed.nmap_scan.persist_inventory', return_value={'ports': 1, 'hosts_with_os': 0}):
            remaining, totals, _ = sentinel_dispatch.try_nmap(mock.Mock(), mock.Mock(), targets)
        self.assertEqual([len(ips) for _, ips in sent], [64, 64, 22])
        self.assertEqual(totals, {'ports': 3, 'hosts_with_os': 0})
        self.assertEqual(remaining, [])  # every address was reported by a Sentinel, in whichever chunk

    def test_the_first_chunk_no_sentinel_takes_ends_the_dispatching_and_the_rest_runs_here(self):
        targets = [f'198.51.100.{i}' for i in range(1, 101)]
        calls = []

        def dispatch(project, kind, target, ips=None, **kw):
            calls.append(len(ips))
            return None
        with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'dispatch_or_none', side_effect=dispatch):
            remaining, totals, _ = sentinel_dispatch.try_nmap(mock.Mock(), mock.Mock(), targets)
        self.assertEqual(calls, [64])  # not a wait for each remaining chunk
        self.assertEqual((remaining, totals), (targets, {'ports': 0, 'hosts_with_os': 0}))

    def test_naabu_sends_every_chunk_and_runs_what_no_sentinel_took_here(self):
        ips = [f'198.51.100.{i}' for i in range(1, 151)]
        answers = [{'ports': {ips[0]: [22]}}, None]
        local = mock.Mock(return_value={ips[70]: [443]})
        with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'dispatch_or_none', side_effect=answers) as sent, \
                mock.patch('cveFeed.naabu_scan.run_naabu', local):
            found = sentinel_dispatch.wrap_naabu_runner(mock.Mock(), mock.Mock())(ips)
        self.assertEqual(sent.call_count, 2)
        local.assert_called_once_with(ips[64:])  # the chunk no Sentinel took and everything after it
        self.assertEqual(found, {ips[0]: [22], ips[70]: [443]})
