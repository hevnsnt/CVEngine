"""Sentinel dispatch policy and broker robustness: the light nuclei pass and the template policy a Sentinel is sent, the long-poll cap, queued tasks that
expire, a bounded lease, a retryable report, rights computed once per sweep, the cached broker probe, project rotation, the update hold, private-address
hosts that are not archived, and the OpenVAS run a queued Sentinel task can no longer hold."""
import tempfile
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelEnrollment, SentinelTask
from cveFeed import nuclei_scan
from cveFeed import openvas_scan as ov
from cveFeed.models import HostAssessment, HostState, OpenvasRun, ServiceRun
from dashboard.models import Project
from startScan.models import Subdomain
from tests.test_openvas import Fixture
from tests.test_sentinel_dispatch import DispatchBase, _answer_queued_task
from tests.test_sentinels import SentinelBase, register_sentinel


def _targets_file(*names):
    handle = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False)
    handle.write('\n'.join(names) + '\n')
    handle.close()
    return handle.name


class LightNucleiPolicyTests(DispatchBase):
    """S03-4 and S03-5: a Sentinel runs the same quick technology pass the server runs, under the template policy the server applies."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def dispatched(self, kind, **kwargs):
        self.make_sentinel([kind])
        stream = dispatch.wrap_nuclei_stream(self.scan, kind, timeout=5)
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=_answer_queued_task({'outcome': 'done', 'findings': []})):
            list(stream(_targets_file('www.example.test'), **kwargs))
        return SentinelTask.objects.get(kind=kind).target

    def test_the_light_pass_goes_out_as_tech_tags_at_info_severity(self):
        target = self.dispatched('nuclei_light')
        self.assertEqual((target['tags'], target['severities']), (['tech'], ['info']))
        self.assertEqual(target['targets'], ['www.example.test'])

    def test_a_targeted_pass_keeps_its_own_tags_and_severities(self):
        target = self.dispatched('nuclei_targeted', tags=['wordpress', 'cms'], severities=['high', 'critical'])
        self.assertEqual((target['tags'], target['severities']), (['cms', 'wordpress'], ['high', 'critical']))

    def test_every_nuclei_task_carries_the_servers_excluded_tags_and_template_policy(self):
        with mock.patch('cveFeed.validation.all_templates_allowed', return_value=False):
            for kind in ('nuclei_light', 'nuclei_targeted'):
                target = self.dispatched(kind)
                self.assertEqual(target['etags'], ['dos'], kind)  # nuclei_scan.BASE_FLAGS: the tags the local run never runs
                self.assertEqual(target['template_policy'], {'rev': nuclei_scan.TEMPLATE_POLICY_REV, 'read_only': True, 'bundle_sha256': None}, kind)  # no snapshot is cached here, so no bundle yet

    def test_a_policy_that_allows_every_template_is_said_so(self):
        with mock.patch('cveFeed.validation.all_templates_allowed', return_value=True):
            target = dispatch._nuclei_target('nuclei_targeted', ['www.example.test'], {})
        self.assertEqual(target['template_policy'], {'rev': nuclei_scan.ALL_TEMPLATES_REV, 'read_only': False, 'bundle_sha256': None})

    def test_the_light_pass_falls_back_to_the_quick_local_pass_not_the_whole_library(self):
        self.make_sentinel(['nuclei_light'])
        seen = []

        def local(path, **kwargs):
            seen.append(kwargs)
            return iter([])
        with mock.patch('cveFeed.nuclei_scan.stream_nuclei', local):
            stream = dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', timeout=0.2)
            list(stream(_targets_file('www.example.test')))  # nobody claims it: the stage runs locally
        self.assertEqual(seen, [{'tech': True}])

    def test_the_internal_light_pass_is_the_quick_one_too(self):
        self.make_sentinel(['nuclei_light'])
        with mock.patch('agentapi.sentinel_dispatch.dispatch_or_none', return_value={'outcome': 'done', 'findings': []}) as sent:
            list(dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light', internal=True)(_targets_file('10.0.0.5')))
        self.assertEqual((sent.call_args.args[2]['tags'], sent.call_args.args[2]['severities']), (['tech'], ['info']))


class ResolveBoundTests(SimpleTestCase):
    def test_a_resolver_that_never_answers_does_not_hold_the_stage(self):
        def slow(host, timeout):
            if host == 'slow.example.test':
                time.sleep(3)
            return True
        started = time.monotonic()
        with mock.patch('agentapi.sentinel_dispatch._resolves', side_effect=slow):
            kept = dispatch.resolvable_targets(['fast.example.test', 'slow.example.test'], workers=2, timeout=0.3)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(kept, ['fast.example.test'])


class LongPollTests(SentinelBase):
    """S03-3: a Sentinel's long poll takes a waiter slot like every other agent's."""

    def test_with_every_waiter_slot_taken_a_long_poll_answers_at_once(self):
        _, out = register_sentinel(self.t['dana'], name='poller')
        cache.set('agentapi:waiters', broker.MAX_WAITERS, 120)
        self.addCleanup(cache.delete, 'agentapi:waiters')
        started = time.monotonic()
        status, body = self.call_next(wait=15)
        self.assertLess(time.monotonic() - started, 5)  # not held for the 15 s
        self.assertEqual((status, body['task'], body['retry_after_seconds']), (200, None, 5))

    def test_a_long_poll_that_gets_a_slot_still_returns_a_task_that_arrives_first(self):
        register_sentinel(self.t['dana'], name='poller')
        task = SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind='nmap', target={'addresses': ['192.0.2.50']}, ips=['192.0.2.50'])
        status, body = self.call_next(wait=15)
        self.assertEqual(body['task']['id'], task.pk)
        self.assertEqual(cache.get('agentapi:waiters') or 0, 0)  # the slot was given back

    def call_next(self, wait):
        from tests.test_agentapi import call
        return call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': wait})


class QueuedExpiryTests(SentinelBase):
    """S03-10: a queued task nobody claims does not live for ever, nor count as waiting work."""

    def queue(self, kind='nmap', age=timedelta(0)):
        task = SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind=kind, target={'addresses': ['192.0.2.50']}, ips=['192.0.2.50'])
        SentinelTask.objects.filter(pk=task.pk).update(created_at=timezone.now() - age)
        return task

    def test_a_task_that_waited_past_its_budget_is_expired_a_young_one_is_not(self):
        old = self.queue(age=timedelta(minutes=30))
        young = self.queue(age=timedelta(minutes=1))
        sb.reap_expired()
        old.refresh_from_db()
        young.refresh_from_db()
        self.assertEqual((old.status, young.status), ('expired', 'queued'))
        self.assertIn('waited in the queue', old.error)
        self.assertIsNotNone(old.finished_at)

    def test_the_budget_is_the_dispatchers_own_queue_budget_plus_a_grace(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_QUEUE_TIMEOUT': '1200'}):
            task = self.queue(age=timedelta(minutes=20))  # inside 1200 s + 5 min
            sb.reap_expired()
            task.refresh_from_db()
            self.assertEqual(task.status, 'queued')

    def test_an_openvas_task_may_wait_an_hour_for_a_busy_sentinel(self):
        waiting = self.queue('openvas', age=timedelta(minutes=50))
        abandoned = self.queue('openvas', age=timedelta(minutes=70))
        sb.reap_expired()
        waiting.refresh_from_db()
        abandoned.refresh_from_db()
        self.assertEqual((waiting.status, abandoned.status), ('queued', 'expired'))

    def test_an_expired_orphan_is_not_claimable_and_not_counted_as_waiting(self):
        register_sentinel(self.t['dana'], name='taker')
        orphan = self.queue(age=timedelta(hours=3))
        self.assertEqual(sb.waiting_tasks(), 0)  # counted as waiting only while it could still be taken
        from tests.test_agentapi import call
        status, body = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertIsNone(body['task'])
        orphan.refresh_from_db()
        self.assertEqual(orphan.status, 'expired')


class LeaseAndReportTests(SentinelBase):
    """S03-11: heartbeats do not keep a dropped task for ever, and a report can be sent again."""

    def running(self, accepted_ago):
        _, out = register_sentinel(self.t['dana'], name='worker')
        self.agent = Agent.objects.get(pk=out['id'])
        now = timezone.now()
        return SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind='nmap', target={'addresses': ['192.0.2.50']}, ips=['192.0.2.50'],
                                           agent=self.agent, status='running', claimed_at=now - accepted_ago, accepted_at=now - accepted_ago,
                                           lease_expires_at=now + timedelta(minutes=1))

    def test_a_heartbeat_extends_a_fresh_task_by_the_run_lease(self):
        task = self.running(timedelta(minutes=2))
        now = timezone.now()
        sb.extend_leases(self.agent, now)
        task.refresh_from_db()
        self.assertGreater(task.lease_expires_at, now + sb.RUN_LEASE - timedelta(seconds=5))

    def test_a_heartbeat_stops_extending_a_task_past_its_longest_runtime(self):
        task = self.running(timedelta(hours=5))  # nmap: 15 min of ceiling plus a grace
        now = timezone.now()
        sb.extend_leases(self.agent, now)
        task.refresh_from_db()
        self.assertLess(task.lease_expires_at, now)  # the cap is in the past: the reaper takes it
        self.assertEqual(sb.reap_expired(), 1)
        task.refresh_from_db()
        self.assertEqual((task.status, task.agent_id), ('expired', None))

    def test_an_openvas_task_runs_for_its_own_budget(self):
        _, out = register_sentinel(self.t['dana'], name='worker', capabilities=['openvas'])
        agent = Agent.objects.get(pk=out['id'])
        now = timezone.now()
        task = SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind='openvas', target={'hosts': {'192.0.2.50': 'h'}, 'max_hours': 30},
                                           agent=agent, status='running', accepted_at=now - timedelta(hours=20), lease_expires_at=now + timedelta(minutes=1))
        sb.extend_leases(agent, now)
        task.refresh_from_db()
        self.assertGreater(task.lease_expires_at, now)  # twenty hours into a thirty hour budget

    def test_a_report_sent_twice_is_answered_twice_and_stored_once(self):
        from tests.test_agentapi import call
        task = self.running(timedelta(minutes=1))
        body = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'ports': []}]}
        url = f'/api/v1/sentinel/tasks/{task.pk}/result'
        first = call(self.t['dana'], 'POST', url, body)
        again = call(self.t['dana'], 'POST', url, body)
        garbled = call(self.t['dana'], 'POST', url, {'outcome': 'nonsense'})  # a retry never fails on its body once the task is done
        self.assertEqual([r[0] for r in (first, again, garbled)], [200, 200, 200])
        self.assertEqual((first[1]['duplicate'], again[1]['duplicate'], garbled[1]['duplicate']), (False, True, True))
        task.refresh_from_db()
        self.assertEqual(task.status, 'done')

    def test_a_report_that_does_not_fit_ends_the_task_so_its_dispatcher_does_not_wait_for_it(self):
        from tests.test_agentapi import call
        task = self.running(timedelta(minutes=1))
        status, _ = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'done', 'hosts': 'not-a-list'})
        task.refresh_from_db()
        self.assertEqual((status, task.status, task.lease_expires_at), (400, 'failed', None))
        self.assertIn('rejected', task.error)


class UpdateHoldTests(SentinelBase):
    """S03-20: a Sentinel whose updater said it is draining is handed nothing new."""

    def setUp(self):
        super().setUp()
        _, out = register_sentinel(self.t['dana'], name='updating')
        self.agent = Agent.objects.get(pk=out['id'])
        SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind='nmap', target={'addresses': ['192.0.2.50']}, ips=['192.0.2.50'])

    def report(self, status, age):
        at = (timezone.now() - age).strftime('%Y-%m-%dT%H:%M:%SZ')
        Agent.objects.filter(pk=self.agent.pk).update(info={'update': {'status': status, 'at': at}})
        from tests.test_agentapi import call
        return call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]

    def test_while_draining_or_updating_no_task_is_leased(self):
        for status in ('draining', 'updating'):
            body = self.report(status, timedelta(minutes=1))
            self.assertIsNone(body['task'], status)
            self.assertIn('updating', body['reason'])

    def test_a_stale_report_never_starves_a_sentinel(self):
        self.assertIsNotNone(self.report('draining', timedelta(hours=2))['task'])

    def test_an_idle_or_finished_update_takes_work(self):
        self.assertIsNotNone(self.report('done', timedelta(minutes=1))['task'])


class CapacityQueueTests(DispatchBase):
    """S03-17: tasks already waiting are promised the free slots."""

    def sentinel(self, slots):
        agent = self.make_sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(max_concurrent=slots)
        return agent

    def queue(self, n=1):
        return [SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': ['192.0.2.10']}) for _ in range(n)]

    def test_queued_tasks_use_up_free_slots(self):
        self.sentinel(2)
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['free'], 2)
        self.queue(1)
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['free'], 1)
        self.queue(1)
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['free'], state['slots']), ('busy', 0, 2))

    def test_a_dispatchers_own_queued_task_is_not_counted_against_it(self):
        self.sentinel(1)
        own = self.queue(1)[0]
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'busy')
        self.assertEqual(sb.capacity_state(self.project, 'nmap', exclude=own.pk)['state'], 'free')

    def test_other_kinds_and_other_projects_are_not_counted(self):
        self.sentinel(1)
        other = Project.objects.create(name='Other', slug='other-p', insert_date=timezone.now(), org=self.org)
        SentinelTask.objects.create(project=other, kind='nmap', target={})
        SentinelTask.objects.create(project=self.project, kind='naabu', target={})
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'free')

    def test_an_abandoned_orphan_does_not_hold_a_slot(self):
        self.sentinel(1)
        orphan = self.queue(1)[0]
        SentinelTask.objects.filter(pk=orphan.pk).update(created_at=timezone.now() - timedelta(hours=2))
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'free')

    def test_a_free_sentinel_that_never_claims_falls_back_after_the_claim_timeout_not_the_queue_budget(self):
        from tests.test_sentinel_capacity import Clock
        self.sentinel(1)
        clock = Clock()
        monotonic, sleep = clock.patches()
        with monotonic, sleep:
            out = dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': ['192.0.2.10']}, timeout=120)
        self.assertIsNone(out)
        self.assertLess(clock.now - 1000, 30)  # its own queued task did not turn the wait into the 300 s queue wait


class RightsOnceTests(DispatchBase):
    """S03-14: a sweep builds each live Sentinel's rights once, however many projects it looks at."""

    def test_rights_are_built_once_inside_the_memo_and_every_time_outside_it(self):
        self.make_sentinel(['nmap'])
        Agent.objects.filter(kind='scanner').update(scope={'orgs': [self.org.slug], 'projects': [], 'hosts': []})
        projects = [self.project] + [Project.objects.create(name=f'P{i}', slug=f'memo-p{i}', insert_date=timezone.now(), org=self.org) for i in range(4)]
        real = sb.SentinelEff
        with mock.patch.object(sb, 'SentinelEff', wraps=real) as built:
            with sb.memoised_rights():
                answers = [(sb.project_slots(p), sb.total_slots(), sb.capacity_state(p, 'nmap')['state']) for p in projects]
            inside = built.call_count
            built.reset_mock()
            [(sb.project_slots(p), sb.total_slots(), sb.capacity_state(p, 'nmap')['state']) for p in projects]
            outside = built.call_count
        self.assertEqual(inside, 1)
        self.assertGreater(outside, inside * 5)
        self.assertEqual(answers[0][1], answers[1][1])  # same answers either way
        self.assertTrue(all(a[0] > 0 for a in answers[1:]))

    def test_a_sweep_that_covers_many_projects_builds_each_sentinels_rights_once(self):
        from cveFeed import coverage_topup
        self.make_sentinel(['nmap', 'nuclei_light'])
        Agent.objects.filter(kind='scanner').update(scope={'orgs': [self.org.slug], 'projects': [], 'hosts': []})
        for i in range(5):
            Project.objects.create(name=f'Q{i}', slug=f'sweep-q{i}', insert_date=timezone.now(), org=self.org)
        with mock.patch.object(sb, 'SentinelEff', wraps=sb.SentinelEff) as built, mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
                mock.patch('cveFeed.unresolved_archive.recheck', return_value={}):
            coverage_topup.feed_sentinels()
        self.assertEqual(built.call_count, 1)


class ProjectRotationTests(TestCase):
    """S03-18: with more projects than one sweep looks at, every project gets its turn."""

    def test_the_sweep_carries_on_after_the_project_the_last_one_ended_on(self):
        from cveFeed import coverage_topup
        cache.delete(coverage_topup.CURSOR_KEY)
        self.addCleanup(cache.delete, coverage_topup.CURSOR_KEY)
        ids = [Project.objects.create(name=f'R{i}', slug=f'rot-{i}', insert_date=timezone.now()).pk for i in range(5)]
        seen = []
        with mock.patch.object(coverage_topup, 'PROJECT_LIMIT', 2), mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
                mock.patch('cveFeed.unresolved_archive.recheck', return_value={}), \
                mock.patch('cveFeed.assessment_review.host_coverage_due', side_effect=lambda p, *a, **k: seen.append(p.pk) or (0, [])), \
                mock.patch('cveFeed.host_assessment.active_count', return_value=0):
            for _ in range(4):
                coverage_topup.top_up()
        mine = [pk for pk in seen if pk in ids]
        self.assertEqual(set(mine), set(ids))  # no project is starved
        self.assertEqual(mine[:2], ids[:2])
        self.assertEqual(mine[2:4], ids[2:4])


class OfflineProbeTests(TestCase):
    """S03-15: counting active assessments never asks the broker."""

    def test_the_snapshot_is_what_the_reaper_left_and_only_judges_rows_that_existed_when_it_was_taken(self):
        from cveFeed import broker_recovery, host_assessment
        from dashboard.models import Org
        from targetApp.models import Domain
        org = Org.objects.create(name='Probe', slug='probe-org')
        project = Project.objects.create(name='Probe', slug='probe', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='probe.example', project=project, insert_date=timezone.now())
        now = timezone.now()

        def row(host, minutes_ago, celery_id):
            job = HostAssessment.objects.create(project=project, domain=domain, host=host, status='queued', celery_id=celery_id)
            HostAssessment.objects.filter(pk=job.pk).update(created_at=now - timedelta(minutes=minutes_ago))
        row('before.probe.example', 60, 'gone')
        row('alive.probe.example', 60, 'alive')
        cache.delete(broker_recovery.SNAPSHOT_KEY)
        self.addCleanup(cache.delete, broker_recovery.SNAPSHOT_KEY)
        with mock.patch('cveFeed.broker_recovery.live_tasks', side_effect=AssertionError('never asked')):
            self.assertEqual(host_assessment.active_count(), 2)  # no snapshot: every row counts
            broker_recovery._remember({'alive'})
            self.assertEqual(host_assessment.active_count(), 1)  # the one the snapshot says is gone is not counted
            row('after.probe.example', 15, 'queued-after')  # older than 10 minutes, but made after the snapshot was taken
            cache.set(broker_recovery.SNAPSHOT_KEY, {'at': time.time() - 20 * 60, 'ids': ['alive']}, 600)
            self.assertEqual(host_assessment.active_count(), 2)
            cache.set(broker_recovery.SNAPSHOT_KEY, {'at': time.time() - 2 * 3600, 'ids': ['alive']}, 600)  # too old to trust
            self.assertEqual(host_assessment.active_count(), 3)

    def test_a_probe_that_got_an_answer_leaves_it_for_every_process(self):
        from cveFeed import broker_recovery
        cache.delete(broker_recovery.SNAPSHOT_KEY)
        self.addCleanup(cache.delete, broker_recovery.SNAPSHOT_KEY)
        self.assertIsNone(broker_recovery.live_snapshot())
        broker_recovery._remember({'a', 'b'})
        ids, taken = broker_recovery.live_snapshot()
        self.assertEqual(ids, {'a', 'b'})
        self.assertLess(abs((timezone.now() - taken).total_seconds()), 5)


class DiscoveryQueueTests(SimpleTestCase):
    def test_the_range_sweep_runs_on_the_discovery_queue_not_the_four_slot_feed_queue(self):
        from reNgine.celery import app
        self.assertEqual(app.tasks['run_internal_discovery'].queue, 'discovery_queue')


class PrivateAddressArchiveTests(TestCase):
    """S03-23: a host that resolves into a private network is kept, not archived as one that never resolved."""

    def setUp(self):
        from dashboard.models import Org
        from targetApp.models import Domain
        now = timezone.now()
        org = Org.objects.create(name='Priv', slug='priv-org')
        self.project = Project.objects.create(name='Priv', slug='priv', insert_date=now, org=org)
        self.domain = Domain.objects.create(name='priv.example', project=self.project, insert_date=now)

    def state(self, host, note):
        Subdomain.objects.create(target_domain=self.domain, name=host)
        return HostState.objects.create(project=self.project, domain=self.domain, host=host, last_seen=timezone.now(), resolution_note=note,
                                        unresolved_first_at=timezone.now() - timedelta(days=9), unresolved_checks=5)

    def test_a_name_that_resolves_into_a_private_network_is_archived_like_any_other_that_cannot_be_scanned(self):
        from cveFeed import unresolved_archive as ua
        private = self.state('inside.priv.example', f'{ua.PRIVATE_NOTE} (10.0.0.7): kept')
        dangling = self.state('dangling.priv.example', 'no DNS answer')
        plain = self.state('plain.priv.example', '')
        ids = set(ua.candidates().values_list('pk', flat=True))
        self.assertEqual(ids, {private.pk, dangling.pk, plain.pk})
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(ua.check_one(private), 'archived')
            self.assertEqual(ua.check_one(dangling), 'archived')
        private.refresh_from_db()
        self.assertIsNotNone(private.archived_at)

    def test_the_recheck_note_does_not_promise_a_path_that_is_not_there(self):
        from cveFeed import unresolved_archive as ua
        row = self.state('inside2.priv.example', '')
        HostState.objects.filter(pk=row.pk).update(unresolved_last_at=timezone.now() - timedelta(days=1))
        ua.recheck(resolver=lambda names: [(n, '10.0.0.9') for n in names])
        row.refresh_from_db()
        self.assertTrue(row.resolution_note.startswith(ua.PRIVATE_NOTE))
        self.assertNotIn('once the project declares', row.resolution_note)
        self.assertIn('archived after the usual wait', row.resolution_note)

    def test_a_later_success_clears_the_note(self):
        from cveFeed import unresolved_archive as ua
        row = self.state('back.priv.example', f'{ua.PRIVATE_NOTE} (10.0.0.7): kept')
        ua.record_attempt(self.project, self.domain, row.host, {'status': 'completed', 'resolved': 1})
        row.refresh_from_db()
        self.assertEqual((row.resolution_note, row.unresolved_checks), ('', 0))


class EnrollmentPruneTests(TestCase):
    def test_only_secrets_that_expired_without_being_used_are_deleted_and_a_used_one_is_kept(self):
        user = User.objects.create_user('enroller', password='x')
        now = timezone.now()
        token, _ = create_token(user, 'redeemed')

        def make(n, expired_days, **extra):
            return SentinelEnrollment.objects.create(token_hash=f'{n:064d}', prefix='senr_x', created_by=user,
                                                     expires_at=now - timedelta(days=expired_days), **extra)
        stale, recent, used = make(1, 30), make(2, 2), make(3, 30, used_at=now - timedelta(days=30), token=token)
        self.assertEqual(sb.prune_enrollments(now), 1)
        self.assertEqual(set(SentinelEnrollment.objects.values_list('pk', flat=True)), {recent.pk, used.pk})


class OpenvasQueuedTaskTests(Fixture, TestCase):
    """S05-2: a queued Sentinel OpenVAS task nobody takes releases the one-at-a-time run; S05-15: so does a local run gvmd can no longer answer for."""

    def make_sentinel(self):
        user = User.objects.create_user('sentinel-owner-q', password='x')
        token, _raw = create_token(user, 'sentinel-token-q')
        return Agent.objects.create(token=token, name='gvm-queued', kind='scanner', status='active', capabilities=['openvas'], last_seen=timezone.now(),
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})

    def dispatched(self):
        self.agent = self.make_sentinel()
        self.assertEqual(self.tick()['status'], 'running')
        return OpenvasRun.objects.get()

    def age(self, run, **ago):
        SentinelTask.objects.filter(pk=run.sentinel_task_id).update(created_at=timezone.now() - timedelta(**ago))

    def test_a_young_queued_task_keeps_waiting(self):
        run = self.dispatched()
        self.assertEqual(self.tick()['sentinel_status'], 'queued')
        self.assertEqual(OpenvasRun.objects.get(pk=run.pk).status, 'running')

    def test_a_task_queued_past_the_hour_is_expired_and_the_run_released_with_no_host_blamed(self):
        run = self.dispatched()
        self.age(run, hours=2)
        out = self.tick()
        self.assertEqual(out['status'], 'failed')
        run.refresh_from_db()
        self.assertEqual(run.status, 'failed')
        self.assertEqual(SentinelTask.objects.get(pk=run.sentinel_task_id).status, 'expired')
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())
        self.assertEqual(self.tick()['status'], 'running')  # the slot is free: the next batch is handed out again

    def test_when_every_sentinel_is_gone_the_task_is_given_up_after_the_grace(self):
        run = self.dispatched()
        Agent.objects.filter(pk=self.agent.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        self.age(run, minutes=10)
        self.assertEqual(self.tick()['sentinel_status'], 'queued')  # a Sentinel only briefly out of contact may come back
        self.age(run, minutes=45)
        self.assertEqual(self.tick()['status'], 'failed')
        self.assertEqual(SentinelTask.objects.get(pk=run.sentinel_task_id).status, 'expired')

    def test_a_task_a_live_sentinel_still_covers_is_not_given_up_early(self):
        run = self.dispatched()
        self.age(run, minutes=45)
        self.assertEqual(self.tick()['sentinel_status'], 'queued')

    def test_a_local_run_gvmd_cannot_answer_for_is_failed_once_past_its_budget(self):
        self.assertEqual(self.tick()['status'], 'running')
        run = OpenvasRun.objects.get()
        self.assertIsNone(run.sentinel_task_id)

        def down():
            raise ov.OpenvasError('gvmd could not be reached')
        young = ov.tick(session_factory=down, resolve=self.resolve, blocked=lambda h: False)
        self.assertEqual(young, {'error': 'gvmd could not be reached'})  # inside its budget it is left alone
        self.assertEqual(OpenvasRun.objects.get().status, 'running')
        OpenvasRun.objects.filter(pk=run.pk).update(started_at=timezone.now() - timedelta(hours=ov.budget_hours(2) + 1))
        out = ov.tick(session_factory=down, resolve=self.resolve, blocked=lambda h: False)
        self.assertEqual((out['run'], out['status']), (run.pk, 'failed'))
        self.assertEqual(OpenvasRun.objects.get(pk=run.pk).status, 'failed')
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())
