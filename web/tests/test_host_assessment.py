from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import discovery
from cveFeed.host_assessment import enqueue, execute, serialize
from cveFeed.models import HostAssessment
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanActivity, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, rpc
from tests.test_perf_hostpipeline import _stages


class HostAssessmentTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Assessment', slug='assess-org')
        self.project = Project.objects.create(name='Assessment', slug='assess', org=org, insert_date=now)
        self.other = Project.objects.create(name='Other', slug='other-assess', org=org, insert_date=now)
        self.domain = Domain.objects.create(name='assess.example', project=self.project, insert_date=now)
        self.other_domain = Domain.objects.create(name='other.example', project=self.other, insert_date=now)
        self.host = Subdomain.objects.create(target_domain=self.domain, name='www.assess.example')
        self.outside = Subdomain.objects.create(target_domain=self.other_domain, name='www.other.example')
        self.user = User.objects.create_user('assess-user', password='x')
        self.auditor = User.objects.create_user('assess-audit', password='x')
        ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
        ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')
        _, self.token = create_token(self.user, 'test')
        _, self.audit_token = create_token(self.auditor, 'test-audit')
        EngineType.objects.create(engine_name='test-engine', yaml_configuration='x', default_engine=True)

    def test_scoped_rest_and_mcp_job_and_duplicate_click(self):
        path = '/api/v1/projects/assess/host-assessments'
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:
            send.return_value.id = 'task-1'
            status, first = call(self.token, 'POST', path, {'host_id': self.host.pk})
            self.assertEqual(status, 202)
            self.assertEqual(first['status'], 'queued')
            self.assertTrue(first['created'])
            self.assertEqual(call(self.token, 'POST', path, {'host_id': self.host.pk})[1]['id'], first['id'])
            self.assertEqual(call(self.token, 'GET', path + f'?host_id={self.host.pk}')[1]['id'], first['id'])
            self.assertEqual(call(self.token, 'GET', path + f'/{first["id"]}')[1]['id'], first['id'])
            send.assert_called_once()
            _, answer = rpc(self.token, 'tools/call', {'name': 'assess_host',
                'arguments': {'project': 'assess', 'host_id': self.host.pk}})
            self.assertFalse(answer['result']['isError'])
            send.assert_called_once()
        self.assertEqual(call(self.audit_token, 'POST', path, {'host_id': self.host.pk})[0], 403)
        self.assertEqual(call(self.token, 'POST', path, {'host_id': self.outside.pk})[0], 404)
        self.assertEqual(call(self.token, 'POST', '/api/v1/projects/_all/host-assessments', {'host_id': self.host.pk})[0], 400)
        self.assertEqual(call(self.token, 'GET', '/api/v1/projects/other-assess/host-assessments/' + str(first['id']))[0], 404)

    def test_broker_failure_is_persisted_and_retryable(self):
        with mock.patch('cveFeed.tasks.assess_host.apply_async', side_effect=OSError('broker unavailable')):
            job, fresh = enqueue(self.project, self.host)
        self.assertTrue(fresh)
        self.assertEqual(job.status, 'failed')
        self.assertEqual(job.error, 'broker enqueue failed: OSError')
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:
            send.return_value.id = 'task-2'
            retried, fresh = enqueue(self.project, self.host)
        self.assertTrue(fresh)
        self.assertNotEqual(job.pk, retried.pk)

    def test_stopped_queued_job_is_never_executed(self):
        job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name)
        path = f'/api/v1/projects/assess/host-assessments/{job.pk}/stop'
        self.assertEqual(call(self.token, 'POST', path, {})[1]['status'], 'stopped')
        self.assertEqual(execute(job.pk)['status'], 'stopped_or_already_started')

    def test_a_bad_or_missing_host_id_is_a_400_not_a_server_error(self):
        for body in ({'host_id': 'abc'}, {'host_id': [1]}, {}):
            self.assertEqual(call(self.token, 'POST', '/api/v1/projects/assess/host-assessments', body)[0], 400, body)
        self.assertEqual(call(self.token, 'GET', '/api/v1/projects/assess/host-assessments?host_id=abc')[0], 400)
        self.assertEqual(call(self.token, 'GET', '/api/v1/projects/assess/host-assessments')[0], 400)

    def test_a_failed_stage_fails_the_assessment_while_the_scan_stands(self):
        for failed, expected in ((['nuclei_targeted_scan'], 'failed'), ([], 'completed')):
            job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name)
            outcome = {'status': discovery.SUCCESS, 'failed_stages': failed, 'scan_id': None,
                       'error': 'Failed stages: nuclei_targeted_scan' if failed else ''}
            with mock.patch('cveFeed.discovery.run_host_pipeline', return_value=outcome):
                execute(job.pk)
            job.refresh_from_db()
            self.assertEqual(job.status, expected)

    def test_exception_text_is_kept_out_of_the_stored_and_served_error(self):
        secret = 'connection to 10.0.0.7:5432 refused at /opt/app/secret_path.py'
        cases = ((mock.patch('cveFeed.discovery.run_host_pipeline', side_effect=RuntimeError(secret)), ' (RuntimeError)'),
                 (mock.patch('cveFeed.discovery.run_host_pipeline', return_value={'status': discovery.FAILED, 'error': secret}), ''))
        for patch, kind in cases:
            job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name)
            with patch, self.assertLogs('cveFeed.activity', 'WARNING') as logs:
                execute(job.pk)
            job.refresh_from_db()
            for text in (job.error, str(job.result), str(serialize(job))):
                self.assertNotIn('10.0.0.7', text)
                self.assertNotIn('secret_path', text)
            self.assertTrue(job.error.startswith(f'Host assessment #{job.pk} failed{kind}; diagnostic '), job.error)
            self.assertIn(secret, '\n'.join(logs.output))  # the operator still has it, in the worker log
        outcome = {'status': discovery.SUCCESS, 'failed_stages': ['nmap_scan'], 'scan_id': None, 'error': 'Failed stages: nmap_scan'}
        job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name)
        with mock.patch('cveFeed.discovery.run_host_pipeline', return_value=outcome):
            execute(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.error, 'Failed stages: nmap_scan')  # the pipeline's own explanation is not hidden

    def test_the_global_cap_counts_projects_the_caller_cannot_see(self):
        from tenancy import scope
        hidden = Domain.objects.create(name='hidden.example', project=self.other, insert_date=timezone.now())
        for i in range(20):
            HostAssessment.objects.create(project=self.other, domain=hidden, host=f'h{i}.hidden.example', status='running')
        tokens = scope.set_scope({self.project.pk}, self.user)  # a request by a user of this project only
        try:
            self.assertEqual(HostAssessment.objects.filter(status='running').count(), 0)  # the caller sees none of them
            with self.assertRaisesRegex(RuntimeError, 'capacity'):
                enqueue(self.project, self.host)
        finally:
            scope.reset_scope(tokens)

    def _fill_the_queue(self):
        hidden = Domain.objects.create(name='full.example', project=self.other, insert_date=timezone.now())
        for i in range(40):
            HostAssessment.objects.create(project=self.other, domain=hidden, host=f'h{i}.full.example', status='running')

    def test_a_persons_rescan_is_never_refused_for_capacity_and_goes_to_the_front(self):
        from cveFeed.host_assessment import PERSON_PRIORITY
        self._fill_the_queue()
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:
            send.return_value.id = 'front-1'
            job, created = enqueue(self.project, self.host, user=self.user)
        self.assertTrue(created)
        self.assertEqual((job.status, job.celery_id, job.requested_by_id, job.front), ('queued', 'front-1', self.user.pk, True))
        self.assertEqual(send.call_args.kwargs['priority'], PERSON_PRIORITY)
        self.assertEqual(send.call_args.kwargs['kwargs'], {'front': True})
        with self.assertRaisesRegex(RuntimeError, 'capacity'):  # an unattended caller still keeps to the caps
            enqueue(self.project, Subdomain.objects.create(target_domain=self.domain, name='api.assess.example'))

    def test_the_rescan_button_is_never_told_the_queue_is_full(self):
        self._fill_the_queue()
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:
            send.return_value.id = 'front-2'
            status, body = call(self.token, 'POST', '/api/v1/projects/assess/host-assessments', {'host_id': self.host.pk})
        self.assertEqual(status, 202)
        self.assertEqual((body['status'], body['front']), ('queued', True))

    def test_a_host_already_queued_by_the_top_up_is_moved_to_the_front(self):
        from cveFeed.host_assessment import PERSON_PRIORITY
        self._fill_the_queue()
        old = timezone.now() - timedelta(hours=2)
        waiting = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name, source='topup', celery_id='batch-1')
        HostAssessment.objects.filter(pk=waiting.pk).update(created_at=old)
        self.assertFalse(serialize(waiting)['front'])  # the page offers "Rescan now" for it
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:
            send.return_value.id = 'front-3'
            job, created = enqueue(self.project, self.host, user=self.user)
        self.assertFalse(created)
        self.assertEqual(job.pk, waiting.pk)  # no second row
        self.assertEqual((job.celery_id, job.requested_by_id, job.front, job.source), ('front-3', self.user.pk, True, 'topup'))  # its own task now, out of the batch
        self.assertGreater(job.created_at, old)
        self.assertEqual(send.call_args.kwargs['priority'], PERSON_PRIORITY)
        self.assertEqual(HostAssessment.objects.filter(project=self.project, host=self.host.name).count(), 1)
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:  # asked again: it is already the person's, at the front
            send.return_value.id = 'front-4'
            self.assertEqual(enqueue(self.project, self.host, user=self.user)[0].pk, waiting.pk)
        HostAssessment.objects.filter(pk=waiting.pk).update(status='running')
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:  # running: nothing to move
            job, created = enqueue(self.project, self.host, user=self.user)
        send.assert_not_called()
        self.assertEqual((job.pk, created), (waiting.pk, False))

    def test_an_unattended_request_does_not_move_a_queued_row_and_is_not_at_the_front(self):
        waiting = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name, source='topup', celery_id='batch-1')
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:
            job, created = enqueue(self.project, self.host, user=self.user, unattended=True, source='host_review')
        send.assert_not_called()
        self.assertEqual((job.pk, job.celery_id, job.requested_by_id), (waiting.pk, 'batch-1', None))
        waiting.delete()
        from cveFeed.host_assessment import ASSESS_PRIORITY
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:  # a token start of the AI host review: the user on the record, the caps and the back of the queue
            send.return_value.id = 'token-1'
            job, created = enqueue(self.project, self.host, user=self.user, unattended=True, source='host_review')
        self.assertEqual((created, job.requested_by_id, job.front), (True, self.user.pk, False))
        self.assertEqual(send.call_args.kwargs['priority'], ASSESS_PRIORITY)
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as send:  # a person's click still moves it to the front
            send.return_value.id = 'front-5'
            job, created = enqueue(self.project, self.host, user=self.user)
        self.assertEqual((created, job.pk, job.front, job.celery_id), (False, job.pk, True, 'front-5'))

    def test_a_front_task_is_never_put_off_for_the_scans_share(self):
        from cveFeed import tasks
        with mock.patch('cveFeed.host_assessment.still_queued', return_value=True), \
                mock.patch('cveFeed.host_assessment.over_share', return_value=True), \
                mock.patch('cveFeed.host_assessment.deferral_count', return_value=0), \
                mock.patch('cveFeed.host_assessment.execute', return_value={'status': 'done'}) as run, \
                mock.patch('cveFeed.tasks.assess_host.apply_async') as again:
            self.assertEqual(tasks.assess_host(7, front=True), {'status': 'done'})
            run.assert_called_once()
            again.assert_not_called()
            self.assertEqual(tasks.assess_host(7)['status'], 'deferred')  # the top-up's still gives way

    def test_a_persons_assessment_runs_as_theirs_and_lifts_its_sentinel_tasks(self):
        from agentapi.sentinel_dispatch import PERSON_PRIORITY, person_priority
        from startScan.models import ScanHistory
        job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name, requested_by=self.user, front=True)
        token = HostAssessment.objects.create(project=self.other, domain=self.other_domain, host=self.outside.name, requested_by=self.user)
        with mock.patch('cveFeed.discovery.run_host_pipeline', return_value={'status': 'empty', 'hosts': 0}) as run:
            execute(job.pk)
            self.assertEqual(run.call_args.kwargs['initiated_by_id'], self.user.pk)
            execute(token.pk)  # a token start keeps its user on the record but is not lifted
            self.assertEqual(run.call_args.kwargs['initiated_by_id'], None)
        engine = EngineType.objects.first()
        host_run = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), initiated_by=self.user,
                                              tasks=[discovery.HOST_PIPELINE_TASK])
        self.assertEqual(person_priority(host_run, 1), PERSON_PRIORITY)
        self.assertEqual(person_priority(host_run, 3), PERSON_PRIORITY)
        self.assertEqual(person_priority(host_run, 0), 0)  # a planner task stays last
        full = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), initiated_by=self.user, tasks=['bbot'])
        self.assertEqual(person_priority(full, 1), 1)  # a full discovery a person started is not lifted
        system = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), tasks=[discovery.HOST_PIPELINE_TASK])
        self.assertEqual(person_priority(system, 1), 1)
        self.assertEqual(person_priority(None, 2), 2)

    def test_no_resolution_is_inconclusive_and_does_not_mark_coverage(self):
        job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=self.host.name)
        HostAssessment.objects.filter(pk=job.pk).update(status='running')
        out = discovery.run_host_pipeline(self.domain.pk, [self.host.name], resolver=lambda names: set(),
                                          force=True, assessment_id=job.pk)
        self.assertEqual(out['status'], 'inconclusive')
        self.assertEqual(out['resolved'], 0)
        self.assertFalse(ScanActivity.objects.filter(scan_of_id=out['scan_id'], name='nmap_scan').exists())

    def test_explicit_request_bypasses_freshness_and_runs_host_hygiene(self):
        nmap, kwargs = _stages(resolver=lambda names: {(name, '8.8.8.8') for name in names})
        with mock.patch('cveFeed.hygiene.run_hygiene', return_value={'tls_hosts': 1}) as hygiene:
            first_job = self._running_job()
            first = discovery.run_host_pipeline(self.domain.pk, [self.host.name], force=True,
                                                hygiene=True, assessment_id=first_job, **kwargs)
            HostAssessment.objects.filter(pk=first_job).update(status='completed')
            second = discovery.run_host_pipeline(self.domain.pk, [self.host.name], force=True,
                                                 hygiene=True, assessment_id=self._running_job(), **kwargs)
        self.assertEqual(len(nmap), 2)
        self.assertEqual(first['status'], discovery.SUCCESS)
        self.assertEqual(second['status'], discovery.SUCCESS)
        self.assertEqual(hygiene.call_count, 2)
        self.assertTrue(ScanActivity.objects.filter(scan_of_id=first['scan_id'], name='host_hygiene', status=2).exists())

    def _running_job(self):
        return HostAssessment.objects.create(project=self.project, domain=self.domain,
                                             host=self.host.name, status='running').pk
