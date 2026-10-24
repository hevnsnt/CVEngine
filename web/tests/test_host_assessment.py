from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import discovery
from cveFeed.host_assessment import enqueue, execute
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
        with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), \
             mock.patch('reNgine.tasks.geo_localize.delay'), \
             mock.patch('cveFeed.hygiene.run_hygiene', return_value={'tls_hosts': 1}) as hygiene:
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
