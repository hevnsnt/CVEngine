"""The Sentinel and agent lifecycles as explicit tables (cvengine.state_machines AGENT, SENTINEL_TASK, STAGE_RUN), and the stale-write bugs fixed while
moving them: a registration or an admin's change that overwrote a newer decision, a late result that revived a cancelled task, a report written after
the task expired, a stage-run pass that overwrote the pass that took over from it, the self-update request a stale failure wiped, the 403 a Sentinel
could not tell from a revoked token, and the outcome every expired task was labelled with."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import sentinel_broker as sentinels
from agentapi import sentinel_settings, stage_runs
from agentapi.models import Agent, SentinelTask, StageRun
from cveFeed.models import ScanControl
from dashboard.models import AuditLog
from cvengine.state_machines import AGENT, SENTINEL_TASK, STAGE_RUN
from startScan.models import IpAddress, ScanHistory
from tests.test_agentapi import call
from tests.test_sentinels import SentinelBase, register_sentinel

NMAP_RESULT = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'os_guess': 'Linux 5.X',
                                             'ports': [{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '9.1'}]}]}
CAPS = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted']


class Tables(SimpleTestCase):
    def test_revoked_leads_only_to_a_persons_reinstatement(self):
        self.assertEqual(AGENT.next_states('revoked'), ('active',))
        self.assertFalse(AGENT.allowed('revoked', 'suspended'))

    def test_an_expired_task_becomes_done_or_failed_only_from_expired_and_a_finished_one_never_moves(self):
        self.assertEqual(set(SENTINEL_TASK.sources('done')), {'claimed', 'running', 'expired'})
        self.assertTrue(SENTINEL_TASK.is_final('done') and SENTINEL_TASK.is_final('failed'))

    def test_the_stage_run_table_leaves_out_cancelled_which_nothing_writes(self):
        self.assertNotIn('cancelled', STAGE_RUN.states)
        self.assertEqual(set(STAGE_RUN.sources('done')), {'running', 'ready'})


class Base(SentinelBase):
    def setUp(self):
        super().setUp()
        _, self.out = register_sentinel(self.t['dana'], name='sm-sentinel', capabilities=CAPS)
        self.agent = Agent.objects.get(pk=self.out['id'])

    def held(self, status='running', reason='the lease expired without a report'):
        """A task this Sentinel holds (its claim on record); ``status='expired'`` expires it with ``reason`` afterwards."""
        now = timezone.now()
        task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example',
                                           ips=['192.0.2.50'], status='running', agent=self.agent, claimed_at=now - timedelta(minutes=10),
                                           accepted_at=now - timedelta(minutes=10), lease_expires_at=now + timedelta(minutes=5))
        from tenancy import audit
        audit.record(self.agent.token.user, 'sentinel.task.claim', 'task', org=self.pa.org_id, task_id=task.pk, agent_id=self.agent.pk, agent=self.agent.name)
        if status == 'expired':
            sentinels.expire(task, reason)
        return task

    def interrupted(self):
        """An update ran while the task was held: the scan is interrupted and the update window is on record (the task is an orphan)."""
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=0, error_message='interrupted by an update')
        now = timezone.now()
        ScanControl.objects.update_or_create(pk=1, defaults={'update_started_at': now - timedelta(minutes=15), 'update_ended_at': now - timedelta(minutes=2),
                                                              'update_grace_until': now + timedelta(minutes=8)})

    def report(self, task, body=None):
        return call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', body or NMAP_RESULT)

    def filed(self):
        return IpAddress.objects.filter(address='192.0.2.50', org_id=self.pa.org_id, ports__number=22).exists()


class StaleAgentWrites(Base):
    """(a) A registration or an administrator's change writes only the fields it changes, and a claim re-reads the status under its lock."""

    def test_a_registration_does_not_undo_a_suspension_made_while_it_ran(self):
        real = broker._parse_registration

        def suspended_meanwhile(body, creating):
            Agent.objects.filter(pk=self.agent.pk).update(status='suspended')  # an administrator's Suspend lands after the registration read the row
            return real(body, creating)

        with mock.patch.object(broker, '_parse_registration', side_effect=suspended_meanwhile):
            status, out = call(self.t['dana'], 'PUT', '/api/v1/sentinel', {'capabilities': [*CAPS, 'testssl']})  # OpenVAS-style capability change
        self.assertEqual(status, 200, out)
        self.agent.refresh_from_db()
        self.assertEqual((self.agent.status, self.agent.capabilities), ('suspended', [*CAPS, 'testssl']))
        self.assertEqual(out['status'], 'suspended')  # the answer says what is stored, not the stale read

    def test_an_administrators_change_keeps_what_a_heartbeat_wrote_meanwhile(self):
        real = broker._clean_limits
        asked = timezone.now()

        def heartbeat_meanwhile(value):
            Agent.objects.filter(pk=self.agent.pk).update(info={'version': 'v2'}, update_requested_at=asked)
            return real(value)

        with mock.patch.object(broker, '_clean_limits', side_effect=heartbeat_meanwhile):
            status, out = call(self.root, 'PATCH', f'/api/v1/agents/{self.agent.pk}', {'limits': {'max_concurrent': 1}})
        self.assertEqual(status, 200, out)
        self.agent.refresh_from_db()
        self.assertEqual((self.agent.info.get('version'), self.agent.update_requested_at, self.agent.limits), ('v2', asked, {'max_concurrent': 1}))

    def test_a_claim_rereads_the_status_under_its_lock(self):
        task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example', ips=['192.0.2.50'])

        def suspended_meanwhile(agent, now):
            Agent.objects.filter(pk=agent.pk).update(status='suspended')  # after the rights were checked, before the lock
            return False

        with mock.patch.object(sentinels, '_updating', side_effect=suspended_meanwhile):
            status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual((status, out.get('code')), (403, 'agent_blocked'), out)
        task.refresh_from_db()
        self.assertEqual((task.status, task.agent_id), ('queued', None))

    def test_a_token_cannot_turn_a_revoked_agent_into_a_suspended_one_but_a_person_can_still_reinstate_it(self):
        Agent.objects.filter(pk=self.agent.pk).update(status='revoked')
        status, out = call(self.t['root'], 'PATCH', f'/api/v1/agents/{self.agent.pk}', {'status': 'suspended'})
        self.assertEqual(status, 409, out)
        self.assertIn('allowed next: active', out['error'])
        status, out = call(self.root, 'PATCH', f'/api/v1/agents/{self.agent.pk}', {'status': 'active'})
        self.assertEqual((status, Agent.objects.get(pk=self.agent.pk).status), (200, 'active'), out)


class LateResults(Base):
    """(b) A late result is filed only for a task that was lost while its Sentinel held it, and only while that Sentinel still covers the work."""

    def assert_refused(self, task):
        status, out = self.report(task)
        self.assertEqual(status, 200, out)
        self.assertEqual((out['duplicate'], out['late'], out['task']['status']), (True, True, 'expired'))
        self.assertNotIn('adopted', out)
        self.assertFalse(self.filed())
        self.assertTrue(AuditLog.objects.filter(action='sentinel.task.late', detail__task_id=task.pk).exists())

    def test_a_task_a_person_cancelled_is_not_revived_by_a_spooled_result(self):
        task = self.held()
        self.assertEqual(call(self.t['dana'], 'POST', f'/api/v1/projects/sen-a/sentinel-tasks/{task.pk}/cancel')[0], 200)
        self.interrupted()
        self.assert_refused(task)

    def test_a_task_taken_back_from_a_suspended_sentinel_is_not_revived(self):
        task = self.held()
        self.assertEqual(call(self.root, 'PATCH', f'/api/v1/agents/{self.agent.pk}', {'status': 'suspended'})[0], 200)
        self.interrupted()
        self.assert_refused(task)

    def test_a_task_taken_back_when_the_sentinel_was_narrowed_is_not_revived(self):
        task = self.held()
        self.assertEqual(call(self.root, 'PATCH', f'/api/v1/agents/{self.agent.pk}', {'limits': {'capabilities': ['naabu']}})[0], 200)
        self.assertEqual(SentinelTask.objects.get(pk=task.pk).error, 'the agent no longer covers this work')
        self.interrupted()
        self.assert_refused(task)

    def test_a_lost_task_is_not_filed_for_a_sentinel_narrowed_after_it_expired(self):
        task = self.held('expired')
        Agent.objects.filter(pk=self.agent.pk).update(limits={'capabilities': ['naabu']})
        self.interrupted()
        self.assert_refused(task)

    def test_a_lost_task_of_a_sentinel_that_still_covers_it_is_still_filed(self):
        task = self.held('expired')
        self.interrupted()
        status, out = self.report(task)
        self.assertEqual((status, out.get('adopted'), out['task']['status']), (200, True, 'done'), out)
        self.assertTrue(self.filed())


class ReportAfterExpiry(Base):
    """(c) The report is filed only while the task is still claimed or running when it is written."""

    def test_a_task_that_expired_between_the_check_and_the_write_stays_expired(self):
        task = self.held()
        from agentapi import address_guard

        def cancelled_meanwhile(t, result):
            SentinelTask.objects.filter(pk=t.pk).update(status='expired', agent=None, lease_expires_at=None, error='cancelled by a person')
            return None

        with mock.patch.object(address_guard, 'result_refusal', side_effect=cancelled_meanwhile):
            status, out = self.report(task)
        self.assertEqual(status, 200, out)
        self.assertEqual((out['duplicate'], out.get('late'), out['task']['status']), (True, True, 'expired'))
        task.refresh_from_db()
        self.assertEqual((task.status, task.error, task.result.get('hosts')), ('expired', 'cancelled by a person', None))


class StageRunPasses(TestCase):
    """(d) A pass that outlived its lease writes nothing once another worker resumed the run."""

    def setUp(self):
        self.run = StageRun.objects.create(kind='sm-test', state='running', rounds=2, lease_until=timezone.now() + timedelta(minutes=5))

    def stale_pass(self):
        row = StageRun.objects.get(pk=self.run.pk)
        row.rounds = 1  # the round it had when the first worker resumed it; the tick took it back and a second worker resumed it (round 2)
        return stage_runs.Pass(row, row.kind)

    def test_the_old_pass_does_not_close_the_run_the_new_pass_owns(self):
        stage_runs._close(self.stale_pass(), 'done')
        self.assertEqual(StageRun.objects.get(pk=self.run.pk).state, 'running')

    def test_the_old_pass_does_not_park_the_run_the_new_pass_owns(self):
        p = self.stale_pass()
        self.assertIsNone(p.save_waiting())
        self.assertEqual(StageRun.objects.get(pk=self.run.pk).state, 'running')

    def test_the_pass_that_owns_its_round_still_closes_it_even_after_the_tick_took_its_lease(self):
        StageRun.objects.filter(pk=self.run.pk).update(state='ready', lease_until=None)
        row = StageRun.objects.get(pk=self.run.pk)
        stage_runs._close(stage_runs.Pass(row, row.kind), 'done')
        self.assertEqual(StageRun.objects.get(pk=self.run.pk).state, 'done')


class UpdateRequest(Base):
    """(e) A failed self-update reported before an administrator's Update now does not clear it."""

    def test_a_stale_failure_does_not_clear_a_fresh_update_now(self):
        failed_at = timezone.now() - timedelta(hours=2)
        Agent.objects.filter(pk=self.agent.pk).update(info={'update': {'status': 'failed', 'at': failed_at.isoformat()}}, update_requested_at=timezone.now())
        agent = Agent.objects.get(pk=self.agent.pk)
        sentinel_settings.record_info(agent, {'update': {'status': 'failed', 'at': failed_at.isoformat()}})
        self.assertIsNotNone(Agent.objects.get(pk=self.agent.pk).update_requested_at)
        sentinel_settings.record_info(agent, {'update': {'status': 'failed', 'at': (timezone.now() + timedelta(seconds=5)).isoformat()}})
        self.assertIsNone(Agent.objects.get(pk=self.agent.pk).update_requested_at)  # a new attempt failed: the request is answered

    def test_without_a_time_only_a_change_into_failed_answers_the_request(self):
        Agent.objects.filter(pk=self.agent.pk).update(info={'update': {'status': 'failed'}}, update_requested_at=timezone.now())
        agent = Agent.objects.get(pk=self.agent.pk)
        sentinel_settings.record_info(agent, {'update': {'status': 'failed'}})
        self.assertIsNotNone(Agent.objects.get(pk=self.agent.pk).update_requested_at)
        sentinel_settings.record_info(agent, {'update': {'status': 'updating'}})
        sentinel_settings.record_info(agent, {'update': {'status': 'failed'}})
        self.assertIsNone(Agent.objects.get(pk=self.agent.pk).update_requested_at)


class ErrorCodes(Base):
    """(f) A 403 says whether the agent is blocked for now or revoked, beside the unchanged ``error``."""

    def test_a_suspended_sentinel_is_told_it_is_blocked_not_revoked(self):
        Agent.objects.filter(pk=self.agent.pk).update(status='suspended')
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual((status, out['code'], out['reason'], out['error']),
                         (403, 'agent_blocked', 'the agent is suspended', 'no work can be assigned: the agent is suspended'))

    def test_a_revoked_sentinel_is_told_its_token_is_revoked(self):
        Agent.objects.filter(pk=self.agent.pk).update(status='revoked')
        for method, path, body in (('POST', '/api/v1/sentinel/tasks/next', {'wait': 0}), ('PUT', '/api/v1/sentinel', {'name': 'again'})):
            status, out = call(self.t['dana'], method, path, body)
            self.assertEqual((status, out['code'], out['error']), (403, 'token_revoked', 'this agent was revoked by an administrator'))


class Outcomes(TestCase):
    """(g) An expired task is labelled by why it expired, not always as lost."""

    def outcome(self, error):
        return sentinels.task_outcome(SentinelTask(status='expired', error=error))

    def test_each_way_a_task_expires_has_its_own_words(self):
        self.assertEqual(self.outcome('the agent is suspended'), 'taken back (the Sentinel was suspended)')
        self.assertEqual(self.outcome('the agent no longer covers this work'), 'taken back (the Sentinel no longer covers this work)')
        self.assertEqual(self.outcome('no Sentinel claimed the task in time; the targets stay due'), 'not taken in time (no Sentinel was free)')
        self.assertEqual(self.outcome('no Sentinel took the task while it waited in the queue'), 'not taken in time (no Sentinel was free)')
        self.assertEqual(self.outcome('the lease expired without a report'), 'lost (the Sentinel stopped answering)')
        self.assertEqual(self.outcome('released by the Sentinel'), 'released by the Sentinel')
