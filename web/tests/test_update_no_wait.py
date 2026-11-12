"""An update does not wait for scans that run on Sentinels: the update window, leases kept through it, adoption of what a Sentinel held, the drain query,
the opt-in, and the optional spool count a Sentinel reports. The Sentinel's own spool is tested in the Sentinel repository."""
import contextlib
import io
import re
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_adopt, sentinel_settings
from agentapi import sentinel_broker as sentinels
from agentapi.models import Agent, SentinelTask, StageRun
from cveFeed import scan_control, updater
from cveFeed.models import AgentActivity, ScanControl, ServiceRun
from dashboard.models import AuditLog
from startScan.models import IpAddress, ScanHistory
from tests.test_agentapi import call
from tests.test_sentinels import SentinelBase, register_sentinel

APPLY = Path(__file__).resolve().parents[2] / 'scripts' / 'apply-update.sh'

NMAP_RESULT = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'os_guess': 'Linux 5.X',
                                             'ports': [{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '9.1'}]}]}


def open_window(started_ago=timedelta(minutes=8), ended_ago=None, grace=600):
    now = timezone.now()
    ScanControl.objects.update_or_create(pk=1, defaults={
        'update_started_at': now - started_ago,
        'update_ended_at': (now - ended_ago) if ended_ago is not None else None,
        'update_grace_until': (now - ended_ago + timedelta(seconds=grace)) if ended_ago is not None else None})


class UpdateWindowTests(TestCase):
    def test_a_drain_pause_opens_the_window_and_a_second_request_keeps_it(self):
        scan_control.request_drain_pause()
        first = ScanControl.objects.get(pk=1)
        self.assertTrue(first.paused and first.paused_by_update)
        self.assertIsNotNone(first.update_started_at)
        self.assertIsNone(first.update_ended_at)
        scan_control.request_drain_pause()  # the host asks again at every poll while it settles
        self.assertEqual(ScanControl.objects.get(pk=1).update_started_at, first.update_started_at)
        self.assertTrue(scan_control.in_update_grace())
        self.assertTrue(scan_control.update_hold())

    def test_the_release_closes_the_window_and_starts_the_grace(self):
        scan_control.request_drain_pause()
        scan_control.release_update_pause()
        row = ScanControl.objects.get(pk=1)
        self.assertFalse(row.paused)
        self.assertIsNotNone(row.update_ended_at)
        self.assertAlmostEqual((row.update_grace_until - row.update_ended_at).total_seconds(), scan_control.grace_seconds(), delta=2)
        self.assertTrue(scan_control.in_update_grace())  # the Sentinels have minutes to come back
        self.assertFalse(scan_control.update_hold())

    def test_the_grace_ends(self):
        open_window(started_ago=timedelta(minutes=30), ended_ago=timedelta(minutes=20), grace=600)
        self.assertFalse(scan_control.in_update_grace())

    def test_a_window_nobody_closed_does_not_hold_leases_for_ever(self):
        open_window(started_ago=timedelta(hours=7))
        self.assertFalse(scan_control.in_update_grace())
        open_window(started_ago=timedelta(hours=2))
        self.assertTrue(scan_control.in_update_grace())

    def test_the_grace_setting(self):
        with mock.patch.dict('os.environ', {scan_control.GRACE_ENV: '90'}):
            self.assertEqual(scan_control.grace_seconds(), 90)
        with mock.patch.dict('os.environ', {scan_control.GRACE_ENV: 'soon'}):
            self.assertEqual(scan_control.grace_seconds(), scan_control.DEFAULT_GRACE_SECONDS)

    def test_the_outage_is_the_part_of_the_window_after_a_given_time(self):
        now = timezone.now()
        open_window(started_ago=timedelta(minutes=10), ended_ago=timedelta(minutes=4))  # a six minute outage
        self.assertAlmostEqual(scan_control.outage_overlap((now - timedelta(hours=1)).timestamp(), now), 360, delta=2)
        self.assertAlmostEqual(scan_control.outage_overlap((now - timedelta(minutes=7)).timestamp(), now), 180, delta=2)
        self.assertEqual(scan_control.outage_overlap((now - timedelta(minutes=2)).timestamp(), now), 0)  # a task from after it

    def test_an_operator_resume_after_a_failed_update_ends_the_window(self):
        scan_control.request_drain_pause()
        row = ScanControl.objects.get(pk=1)
        fields = scan_control.close_update_window(row, timezone.now())
        self.assertEqual(sorted(fields), ['update_ended_at', 'update_grace_until'])
        self.assertEqual(scan_control.close_update_window(row, timezone.now()), [])  # closed once


class SentinelLeaseTests(SentinelBase):
    def setUp(self):
        super().setUp()
        _, self.agent = register_sentinel(self.t['dana'], name='lease-sentinel', capabilities=['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'testssl'])
        self.agent_row = Agent.objects.get(pk=self.agent['id'])

    def task(self, kind='nmap', status='running', lease=None, **extra):
        now = timezone.now()
        fields = {'project': self.pa, 'scan': self.scan, 'kind': kind, 'target': {'addresses': ['192.0.2.50']}, 'host': 'www.a.example', 'ips': ['192.0.2.50'],
                  'status': status, 'agent': self.agent_row, 'claimed_at': now - timedelta(minutes=10), 'accepted_at': now - timedelta(minutes=10),
                  'lease_expires_at': lease if lease is not None else now - timedelta(minutes=3)}
        fields.update(extra)
        return SentinelTask.objects.create(**fields)

    def test_the_drain_pause_holds_the_leases_of_what_the_sentinels_run(self):
        task = self.task(lease=timezone.now() + timedelta(seconds=30))
        scan_control.request_drain_pause()
        task.refresh_from_db()
        self.assertGreater(task.lease_expires_at, timezone.now() + timedelta(minutes=25))

    def test_a_lapsed_lease_is_reaped_outside_an_update_and_kept_inside_it(self):
        task = self.task()
        open_window(started_ago=timedelta(minutes=8))
        self.assertEqual(sentinels.reap_expired(), 0)
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')
        open_window(started_ago=timedelta(minutes=40), ended_ago=timedelta(minutes=30), grace=600)
        self.assertGreaterEqual(sentinels.reap_expired(), 1)  # the grace is over: judged as before
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')

    def test_a_task_the_heartbeat_does_not_list_is_kept_inside_an_update_and_ended_after(self):
        task = self.task(lease=timezone.now() + timedelta(minutes=5), claimed_at=timezone.now() - timedelta(minutes=20), accepted_at=timezone.now() - timedelta(minutes=20))
        open_window(started_ago=timedelta(minutes=8))
        self.assertEqual(sentinels._end_unreported(self.agent_row.pk, set()), set())
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')
        ScanControl.objects.filter(pk=1).update(update_started_at=None)
        self.assertEqual(sentinels._end_unreported(self.agent_row.pk, set()), {task.pk})

    def test_a_heartbeat_inside_the_grace_takes_up_a_lease_that_lapsed_during_the_outage(self):
        task = self.task()
        open_window(started_ago=timedelta(minutes=12), ended_ago=timedelta(minutes=2))
        sentinels.extend_leases(self.agent_row, timezone.now())
        task.refresh_from_db()
        self.assertGreater(task.lease_expires_at, timezone.now())
        # outside the grace a lapsed lease stays lapsed (the reaper's), as before
        ScanControl.objects.filter(pk=1).update(update_started_at=None)
        again = self.task(lease=timezone.now() - timedelta(minutes=3))
        sentinels.extend_leases(self.agent_row, timezone.now())
        again.refresh_from_db()
        self.assertLess(again.lease_expires_at, timezone.now())

    def test_a_result_whose_lease_lapsed_during_the_outage_is_taken(self):
        task = self.task(kind='testssl', target={'host': 'a.example', 'ip': '192.0.2.50', 'port': 443, 'starttls': ''})
        open_window(started_ago=timedelta(minutes=12), ended_ago=timedelta(minutes=2))
        status, out = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'done', 'items': []})
        self.assertEqual((status, out['task']['status']), (200, 'done'))
        ScanControl.objects.filter(pk=1).update(update_started_at=None)
        late = self.task(kind='testssl', target={'host': 'a.example', 'ip': '192.0.2.50', 'port': 443, 'starttls': ''})
        from tenancy import audit
        audit.record(self.agent_row.token.user, 'sentinel.task.claim', 'task', org=self.pa.org_id, task_id=late.pk, agent_id=self.agent_row.pk, agent=self.agent_row.name)
        status, out = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{late.pk}/result', {'outcome': 'done', 'items': []})
        self.assertEqual((status, out['late'], out['task']['status']), (200, True, 'expired'))  # outside an update a lapsed lease is expired first, and the result is the old late one

    def test_no_new_work_is_handed_out_while_the_update_pause_is_on(self):
        SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example', ips=['192.0.2.50'])
        scan_control.request_drain_pause()
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 200)
        self.assertIsNone(out['task'])
        self.assertIn('updating', out['reason'])
        scan_control.release_update_pause()
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertIsNotNone(out['task'])  # the queue resumes with the update

    def test_an_operator_pause_does_not_hold_the_queue_here_as_the_update_pause_does(self):
        SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example', ips=['192.0.2.50'])
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': False})
        self.assertFalse(scan_control.update_hold())


class StageStopTests(TestCase):
    def test_an_updates_pause_does_not_stop_a_stage_that_waits_on_sentinels_but_an_operators_does(self):
        from agentapi import sentinel_dispatch
        scan = mock.Mock(id=99)
        with mock.patch('cveFeed.discovery.stopped', return_value=False):
            ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True})
            self.assertFalse(sentinel_dispatch._stopped(scan))
            ScanControl.objects.filter(pk=1).update(paused_by_update=False)
            self.assertTrue(sentinel_dispatch._stopped(scan))


class DispatchBudgetTests(SentinelBase):
    def state_for(self, task, started_ago, claim_in, run_in):
        import time
        wall = time.time()
        return {'key': 'k', 'id': task.pk, 'kind': 'nmap', 'project_id': self.pa.pk, 'scan_id': self.scan.pk, 'internal': False, 'busy': False, 'timeout': 900,
                'label': 'x', 'entry': None, 'started': wall - started_ago, 'queue_budget': 300, 'claim_deadline': wall + claim_in, 'run_deadline': wall + run_in,
                'never_claimed': False, 'vanished': False, 'stop_check': False}

    def test_the_budgets_are_wall_clock_time_minus_the_outage_and_credited_once(self):
        from agentapi import sentinel_dispatch
        task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={}, status='running', claimed_at=timezone.now())
        open_window(started_ago=timedelta(minutes=9), ended_ago=timedelta(minutes=1))  # an eight minute outage, inside the task's life
        state = self.state_for(task, started_ago=3600, claim_in=-30, run_in=60)
        plain = sentinel_dispatch._Dispatch.restore({**state, 'outage_credit': 99999})  # already credited more than the outage: nothing added
        moved = sentinel_dispatch._Dispatch.restore(state)
        gained = moved.run_deadline - plain.run_deadline
        self.assertAlmostEqual(gained, 480, delta=3)
        again = sentinel_dispatch._Dispatch.restore(moved.state('k'))  # the state written back by a drive and read by the next
        self.assertAlmostEqual(again.run_deadline - moved.run_deadline, 0, delta=1)
        self.assertAlmostEqual(again.outage_credit, moved.outage_credit, delta=1)

    def test_a_task_older_than_nothing_is_untouched_without_an_update(self):
        from agentapi import sentinel_dispatch
        task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={}, status='running', claimed_at=timezone.now())
        state = self.state_for(task, started_ago=100, claim_in=10, run_in=60)
        restored = sentinel_dispatch._Dispatch.restore(state)
        self.assertEqual(restored.outage_credit, 0.0)


class AdoptionTests(SentinelBase):
    def setUp(self):
        super().setUp()
        _, self.agent = register_sentinel(self.t['dana'], name='adopt-sentinel', capabilities=['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'testssl'])
        self.agent_row = Agent.objects.get(pk=self.agent['id'])
        self.url = '/api/v1/sentinel/tasks/{}/result'

    def ip(self):
        """The organization's own row for the address: what the stage's persistence writes (the fixture's address has another, unowned row)."""
        return IpAddress.objects.get_or_create(address='192.0.2.50', org_id=self.pa.org_id)[0]

    def held(self, kind='nmap', target=None, scan=None, ips=('192.0.2.50',), minutes_ago=10, status='expired'):
        """A task the Sentinel held while the server was down: expired by the reaper after the outage, its claim on record."""
        now = timezone.now()
        task = SentinelTask.objects.create(project=self.pa, scan=scan if scan is not None else self.scan, kind=kind,
                                           target=target if target is not None else {'addresses': list(ips)}, host='www.a.example', ips=list(ips), status='claimed',
                                           agent=self.agent_row, claimed_at=now - timedelta(minutes=minutes_ago), accepted_at=now - timedelta(minutes=minutes_ago),
                                           lease_expires_at=now + timedelta(minutes=5))
        from tenancy import audit
        audit.record(self.agent_row.token.user, 'sentinel.task.claim', 'task', org=self.pa.org_id, task_id=task.pk, agent_id=self.agent_row.pk, agent=self.agent_row.name)
        if status == 'expired':
            sentinels.expire(task, 'the lease expired without a report')
        return task

    def interrupted(self):
        """What an update does to a scan that waits on a Sentinel: the scan is interrupted, and the update window (which began after the task was
        claimed) is on record. A closed scan alone does not make a result an orphan: a sweep that blocks on its own task files its own result."""
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=0, error_message='interrupted by an update')
        now = timezone.now()
        ScanControl.objects.update_or_create(pk=1, defaults={'update_started_at': now - timedelta(minutes=15), 'update_ended_at': now - timedelta(minutes=2),
                                                              'update_grace_until': now + timedelta(minutes=8)})

    def report(self, task, body=None):
        return call(self.t['dana'], 'POST', self.url.format(task.pk), body or NMAP_RESULT)

    def test_a_late_nmap_result_of_an_interrupted_scan_lands_in_the_host_data_and_the_ledger(self):
        task = self.held()
        self.interrupted()
        status, out = self.report(task)
        self.assertEqual(status, 200, out)
        self.assertEqual((out['adopted'], out['duplicate']), (True, False))
        self.assertEqual(out['task']['status'], 'done')
        port = self.ip().ports.get(number=22)
        self.assertEqual((port.product, port.version, port.service_name), ('OpenSSH', '9.1', 'ssh'))
        self.assertTrue(ServiceRun.objects.filter(service='nmap-fast', asset='192.0.2.50', status='done', project_id=self.pa.pk).exists())
        self.assertEqual(AuditLog.objects.filter(action='sentinel.task.adopt', detail__task_id=task.pk).count(), 1)
        self.assertFalse(AuditLog.objects.filter(action='sentinel.task.late', detail__task_id=task.pk).exists())  # not a discarded late result
        self.scan.refresh_from_db()
        self.assertEqual(ScanHistory.objects.get(pk=self.scan.pk).scan_status, 0)  # the scan record stays interrupted

    def test_a_late_naabu_result_leaves_the_addresses_the_sentinel_did_not_finish_due(self):
        task = self.held(kind='naabu', ips=('192.0.2.50', '192.0.2.51'))
        self.interrupted()
        status, out = self.report(task, {'outcome': 'done', 'ports': {'192.0.2.50': [22]}, 'incomplete': True, 'unfinished': ['192.0.2.51']})
        self.assertEqual((status, out['adopted']), (200, True), out)
        self.assertEqual(list(ServiceRun.objects.filter(service='naabu', asset='192.0.2.50').values_list('status', flat=True)), ['done'])
        self.assertEqual(list(ServiceRun.objects.filter(service='naabu', asset='192.0.2.51').values_list('status', flat=True)), ['failed'])  # a failed scan is not a clean host

    def test_a_late_nmap_result_does_not_file_or_mark_a_host_nmap_timed_out_on(self):
        task = self.held(kind='nmap', ips=('192.0.2.50', '192.0.2.51'))
        self.interrupted()
        body = {'outcome': 'done', 'hosts': [NMAP_RESULT['hosts'][0], {'ip': '192.0.2.51', 'os_guess': '', 'ports': [], 'timed_out': True}]}
        status, out = self.report(task, body)
        self.assertEqual((status, out['adopted']), (200, True), out)
        self.assertTrue(ServiceRun.objects.filter(service='nmap-fast', asset='192.0.2.50', status='done').exists())
        self.assertFalse(ServiceRun.objects.filter(service='nmap-fast', asset='192.0.2.51').exists())  # left due

    def test_the_second_delivery_is_a_duplicate_and_files_nothing_again(self):
        task = self.held()
        self.interrupted()
        self.assertEqual(self.report(task)[1]['adopted'], True)
        before = (self.ip().ports.count(), AuditLog.objects.filter(action='sentinel.task.adopt').count(),
                  ServiceRun.objects.filter(service='nmap-fast').count())
        for _ in range(3):
            status, again = self.report(task)
            self.assertEqual((status, again['duplicate']), (200, True))
            self.assertNotIn('adopted', again)
        self.assertEqual((self.ip().ports.count(), AuditLog.objects.filter(action='sentinel.task.adopt').count(),
                          ServiceRun.objects.filter(service='nmap-fast').count()), before)

    def test_one_activity_line_counts_what_a_project_adopted_not_one_per_task(self):
        open_window(started_ago=timedelta(minutes=12), ended_ago=timedelta(minutes=2))
        self.interrupted()
        tasks = [self.held(ips=(f'192.0.2.{50 + i}',)) for i in range(3)]
        for i, task in enumerate(tasks):
            body = {'outcome': 'done', 'hosts': [{'ip': f'192.0.2.{50 + i}', 'ports': [{'number': 80, 'protocol': 'tcp', 'state': 'open', 'service_name': 'http'}]}]}
            self.assertEqual(self.report(task, body)[1]['adopted'], True)
        lines = AgentActivity.objects.filter(message__startswith='Adopted ', project=self.pa)
        self.assertEqual(lines.count(), 1)
        self.assertEqual(lines.get().message, 'Adopted 3 results a Sentinel held during the update')

    def test_a_late_result_of_a_scan_that_is_still_running_is_discarded_as_before(self):
        task = self.held()  # no update ran, the scan is running: its stage fell back, this is the old late result
        status, out = self.report(task)
        self.assertEqual((status, out['duplicate'], out['late']), (200, True, True))
        self.assertFalse(self.ip().ports.exists())

    def test_a_task_an_open_stage_run_waits_on_is_left_to_the_stage_run(self):
        task = self.held(status='running')
        self.interrupted()
        StageRun.objects.create(kind='x', project=self.pa, scan=self.scan, task_ids=[task.pk], state='waiting')
        status, out = self.report(task)
        self.assertEqual(status, 200, out)
        self.assertNotIn('adopted', out)  # the stage run's callback consumes it
        self.assertFalse(self.ip().ports.exists())
        self.assertEqual(out['task']['status'], 'done')

    def test_a_task_held_across_an_update_is_adopted_even_when_its_scan_record_still_says_running(self):
        open_window(started_ago=timedelta(minutes=12), ended_ago=timedelta(minutes=2))
        task = self.held(status='running')
        status, out = self.report(task)
        self.assertEqual((status, out.get('adopted')), (200, True))  # the stage that blocked in its worker died in the restart
        self.assertTrue(self.ip().ports.filter(number=22).exists())

    def test_a_result_that_does_not_fit_the_schema_is_not_adopted_and_not_a_server_error(self):
        task = self.held()
        self.interrupted()
        status, out = self.report(task, {'outcome': 'done', 'hosts': 'not a list'})
        self.assertEqual(status, 200)
        self.assertEqual((out['duplicate'], out['late']), (True, True))  # the old late answer
        self.assertFalse(self.ip().ports.exists())

    def test_a_sentinel_that_never_held_the_task_cannot_have_a_result_adopted(self):
        task = self.held()
        self.interrupted()
        register_sentinel(self.t['root'], name='bystander', scope={'projects': ['sen-a']})
        status, _ = call(self.t['root'], 'POST', self.url.format(task.pk), NMAP_RESULT)
        self.assertEqual(status, 404)

    def test_a_host_outside_the_chunk_is_never_filed(self):
        task = self.held()
        self.interrupted()
        body = {'outcome': 'done', 'hosts': [{'ip': '198.51.100.7', 'ports': [{'number': 23, 'protocol': 'tcp', 'state': 'open', 'service_name': 'telnet'}]}]}
        self.assertEqual(self.report(task, body)[0], 200)
        self.assertFalse(IpAddress.objects.filter(address='198.51.100.7', org_id=self.pa.org_id).exists())

    def test_a_naabu_result_lands_as_open_ports_and_marks_discovery_done(self):
        task = self.held(kind='naabu')
        self.interrupted()
        status, out = self.report(task, {'outcome': 'done', 'ports': {'192.0.2.50': [22, 443]}})
        self.assertEqual((status, out['adopted']), (200, True))
        self.assertEqual(sorted(self.ip().ports.values_list('number', flat=True)), [22, 443])
        self.assertTrue(ServiceRun.objects.filter(service='naabu', asset='192.0.2.50', status='done').exists())

    def test_a_nuclei_result_is_filed_through_the_findings_path_and_marked_unscreened(self):
        from startScan.models import Vulnerability
        task = self.held(kind='nuclei_targeted', target={'targets': ['www.a.example']}, ips=())
        self.interrupted()
        finding = {'template_id': 'exposed-panel', 'name': 'Exposed panel', 'severity': 'medium', 'host': 'www.a.example', 'matched_at': 'https://www.a.example/admin'}
        status, out = self.report(task, {'outcome': 'done', 'findings': [finding]})
        self.assertEqual((status, out['adopted']), (200, True))
        vuln = Vulnerability.objects.get(scan_history=self.scan, name='Exposed panel')
        self.assertIn('unscreened-same-body', [t.name for t in vuln.tags.all()])
        self.assertEqual(self.report(task, {'outcome': 'done', 'findings': [finding]})[1]['duplicate'], True)
        self.assertEqual(Vulnerability.objects.filter(scan_history=self.scan, name='Exposed panel').count(), 1)

    def test_a_closed_scan_without_an_update_is_not_adopted(self):
        task = self.held(status='claimed')
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=2)
        status, out = self.report(task)
        self.assertEqual(status, 200, out)
        self.assertNotIn('adopted', out)  # the sweep that waits on it files its own result
        self.assertFalse(AuditLog.objects.filter(action='sentinel.task.adopt', detail__task_id=task.pk).exists())

    def test_a_kind_with_no_adopter_keeps_its_result_on_the_task_row(self):
        self.assertFalse(sentinel_adopt.has_adopter('testssl'))
        task = self.held(kind='testssl', target={'host': 'a.example', 'ip': '192.0.2.50', 'port': 443, 'starttls': ''})
        self.interrupted()
        status, out = self.report(task, {'outcome': 'done', 'items': []})
        self.assertEqual((status, out['adopted']), (200, True))
        task.refresh_from_db()
        self.assertEqual((task.status, task.result['outcome']), ('done', 'done'))

    def test_an_adopter_that_fails_still_ends_the_task_done_and_never_raises(self):
        task = self.held()
        self.interrupted()
        with mock.patch.dict(sentinel_adopt.ADOPTERS, {'nmap': mock.Mock(side_effect=RuntimeError('boom'))}):
            with self.assertLogs('agentapi.sentinel_adopt', 'ERROR'):
                status, out = self.report(task)
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'done')
        self.assertEqual(task.result['outcome'], 'done')  # the result is still on the row
        self.assertEqual(AuditLog.objects.get(action='sentinel.task.adopt', detail__task_id=task.pk).detail['adopted'], False)

    def test_a_failed_result_is_recorded_failed_not_adopted(self):
        task = self.held()
        self.interrupted()
        status, out = self.report(task, {'outcome': 'error', 'error': 'nmap exited with status 1'})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'failed')
        self.assertFalse(self.ip().ports.exists())


class DrainQueryTests(TestCase):
    """The two counts scripts/apply-update.sh asks the web service for, run here against the test database."""

    @staticmethod
    def query(name):
        text = APPLY.read_text()
        found = re.search(name + r'="(.*?)"\n', text, re.S)
        assert found, name
        return found.group(1)

    def count(self, name):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(self.query(name), {})
        return int(out.getvalue().strip().splitlines()[-1])

    def setUp(self):
        from tests.test_sentinels import build_world
        build_world(self.__class__)
        self.engine = self.scan.scan_type

    def scan_running(self, domain=None):
        return ScanHistory.objects.create(domain=domain or self.db, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1, results_dir='/tmp')

    def test_a_scan_that_waits_on_a_sentinel_task_is_not_counted_but_one_working_on_this_server_is(self):
        server_side = self.scan_running()
        SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={}, status='running')  # self.scan waits on a Sentinel
        self.assertEqual(self.count('RUNNING_QUERY_ALL'), 2)  # the opt-in counts every running scan
        self.assertEqual(self.count('RUNNING_QUERY_SERVER'), 1)
        self.assertEqual(server_side.scan_status, 1)

    def test_a_scan_with_an_open_stage_run_is_not_counted(self):
        StageRun.objects.create(kind='x', project=self.pa, scan=self.scan, task_ids=[], state='waiting')
        self.assertEqual(self.count('RUNNING_QUERY_SERVER'), 0)
        StageRun.objects.filter(scan=self.scan).update(state='done')
        self.assertEqual(self.count('RUNNING_QUERY_SERVER'), 1)

    def test_queued_and_finished_sentinel_tasks_decide_only_what_they_should(self):
        SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={}, status='done')
        self.assertEqual(self.count('RUNNING_QUERY_SERVER'), 1)  # a finished task waits for nothing
        SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={}, status='queued')
        self.assertEqual(self.count('RUNNING_QUERY_SERVER'), 0)


class OptInAndStatusTests(SentinelBase):
    def setUp(self):
        super().setUp()
        import tempfile
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch.object(updater, '_file', lambda name: str(Path(self.dir) / name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_waiting_for_scans_is_off_unless_an_administrator_turns_it_on(self):
        self.assertFalse(updater.read_wait_scans())
        updater.set_wait_scans(True)
        self.assertTrue(updater.read_wait_scans())
        self.assertEqual((Path(self.dir) / '.update-wait-scans').read_text().strip(), '1')
        updater.set_wait_scans(False)
        self.assertFalse(updater.read_wait_scans())
        (Path(self.dir) / '.update-wait-scans').write_text('banana')
        self.assertFalse(updater.read_wait_scans())  # anything but 1 is off

    def test_the_state_says_what_the_sentinels_hold_and_whether_the_update_waits(self):
        from cveFeed.models import UpdateSettings
        _, agent = register_sentinel(self.t['dana'], name='state-sentinel')
        SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={}, status='running', agent_id=agent['id'])
        Agent.objects.filter(pk=agent['id']).update(info={'spool': {'count': 4, 'oldest_seconds': 30}})
        state = updater.state(UpdateSettings.current())
        self.assertEqual((state['wait_for_scans'], state['sentinel_tasks_open'], state['sentinel_scans_running'], state['sentinel_results_held']), (False, 1, 1, 4))
        updater.set_wait_scans(True)
        self.assertTrue(updater.state(UpdateSettings.current())['wait_for_scans'])

    def test_the_setting_is_changed_through_the_settings_api_by_a_boolean_only(self):
        from django.test import Client
        client = Client()
        client.force_login(self.root)
        reply = client.put('/cve/api/settings/updates', {'wait_for_scans': True}, content_type='application/json')
        self.assertEqual(reply.status_code, 200, reply.content)
        self.assertTrue(reply.json()['wait_for_scans'])
        self.assertTrue(updater.read_wait_scans())
        bad = client.put('/cve/api/settings/updates', {'wait_for_scans': 'yes'}, content_type='application/json')
        self.assertEqual(bad.status_code, 400)
        self.assertTrue(AuditLog.objects.filter(action='update.wait_scans_changed').exists())


class SpoolInfoTests(SentinelBase):
    def test_the_spool_count_is_optional_clean_and_never_an_error(self):
        self.assertEqual(sentinel_settings.clean_info({'version': 'abc', 'spool': {'count': 3, 'oldest_seconds': 90}})['spool'], {'count': 3, 'oldest_seconds': 90})
        for bad in ({'count': 0}, {'count': -1}, {'count': True}, {'count': 'x'}, {'oldest_seconds': 5}, 'many', 5, [1]):
            self.assertNotIn('spool', sentinel_settings.clean_info({'version': 'abc', 'spool': bad}), bad)
        self.assertNotIn('spool', sentinel_settings.clean_info({'version': 'abc'}))  # a Sentinel older than the field
        self.assertEqual(sentinel_settings.clean_info({'spool': {'count': 2, 'oldest_seconds': -4}})['spool'], {'count': 2})

    def test_a_full_report_with_no_spool_clears_what_was_held_and_a_partial_one_does_not(self):
        _, agent = register_sentinel(self.t['dana'], name='spool-sentinel')
        row = Agent.objects.get(pk=agent['id'])
        sentinel_settings.record_info(row, {'contract_version': 3, 'spool': {'count': 2}})
        row.refresh_from_db()
        self.assertEqual(row.info['spool'], {'count': 2})
        sentinel_settings.record_info(row, {'version': 'abc'})  # not a full report: what it held is not forgotten
        row.refresh_from_db()
        self.assertEqual(row.info['spool'], {'count': 2})
        sentinel_settings.record_info(row, {'contract_version': 3})
        row.refresh_from_db()
        self.assertNotIn('spool', row.info)

    def test_the_heartbeat_carries_the_count_to_the_agent_detail(self):
        _, agent = register_sentinel(self.t['dana'], name='hb-sentinel')
        status, _ = call(self.t['dana'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'contract_version': 3, 'spool': {'count': 5, 'oldest_seconds': 61}}, 'running': []})
        self.assertEqual(status, 200)
        status, _ = call(self.t['dana'], 'POST', '/api/v1/sentinel/heartbeat', {'running': []})  # a Sentinel that does not know the field is not refused
        self.assertEqual(status, 200)
        self.assertEqual(Agent.objects.get(pk=agent['id']).info['spool'], {'count': 5, 'oldest_seconds': 61})  # no info this time: nothing forgotten
        status, _ = call(self.t['dana'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'contract_version': 3}, 'running': []})
        self.assertNotIn('spool', Agent.objects.get(pk=agent['id']).info)


class CopyTests(SimpleTestCase):
    """The words the owner reads: no wait for Sentinel scans, and what a Sentinel does meanwhile."""

    def read(self, name):
        return (Path(__file__).resolve().parents[1] / 'static' / 'cve' / name).read_text()

    def test_the_banner_no_longer_says_it_waits_for_scans_unless_the_opt_in_is_on(self):
        js = self.read('updatebar.js')
        self.assertIn('wait_for_scans', js)
        self.assertIn('Pausing new work', js)
        self.assertIn('hand it over when cvENGINE is back', js)
        self.assertIn('"Settle"', js)
        # the old text is only reachable behind the opt-in
        self.assertRegex(js, r'waits && n > 0\) paint\(1, `Waiting for')

    def test_the_maintenance_page_says_sentinels_keep_their_results(self):
        html = ' '.join(self.read('maintenance.html').split())
        self.assertIn('Your Sentinels keep running what they have', html)
        self.assertIn('hand their results over when cvENGINE is back', html)

    def test_the_sentinels_page_says_it_holds_results(self):
        js = self.read('sentinel-settings.js')
        self.assertIn('until cvENGINE is back', js)

    def test_no_dashes_in_the_new_copy(self):
        for name in ('updatebar.js', 'maintenance.html'):
            text = self.read(name)
            self.assertNotIn('\u2014', text, name)
            self.assertNotIn('\u2013', text, name)
