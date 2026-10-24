"""Bounded three-hour AI review and deterministic capacity limits."""
import json
import os
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import assessment_review as ar
from cveFeed.models import AssessmentReview, AssessmentReviewDecision, HostAssessment, HostExclusion
from cveFeed.performance_review import safe_candidate, summarize
from dashboard.models import Org, Project
from targetApp.models import Domain
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain


class DecisionTests(SimpleTestCase):
    def test_model_cannot_name_an_unoffered_action_or_target(self):
        self.assertIsNone(ar.parse_decision('{"action":"discover","reason":"scan elsewhere"}', ['triage']))
        self.assertIsNone(ar.parse_decision('{"action":"triage","reason":"go","target":"other.test"}', ['triage']))
        self.assertEqual(ar.parse_decision('{"action":"none","reason":"No due work"}', [])['action'], 'none')

    def test_sparse_data_and_overload_reduce_only_observed_kind(self):
        self.assertEqual(safe_candidate(None)['direction'], 'none')
        sample = {'samples': 150, 'span_minutes': 170, 'free_p10': .1,
                  'waiting': {'nmap': 0}, 'running': {'nmap': 100, 'nuclei': 10}}
        caps = {'nmap': 2, 'nuclei': 1}
        bounds = {'nmap': (1, 3), 'nuclei': (1, 2)}
        result = safe_candidate(sample, caps=caps, bounds=bounds, now=100000)
        self.assertEqual((result['kind'], result['direction']), ('nmap', 'down'))
        caps['nmap'] = 1
        self.assertEqual(safe_candidate(sample, caps=caps, bounds=bounds, now=100000)['kind'], 'none')

    def test_scale_up_requires_wait_success_headroom_operator_room_and_cooldown(self):
        sample = {'samples': 150, 'span_minutes': 170, 'free_p10': .6,
                  'waiting': {'nmap': 60, 'nuclei': 5}, 'running': {'nmap': 70}}
        caps = {'nmap': 2, 'nuclei': 1}
        bounds = {'nmap': (1, 3), 'nuclei': (1, 1)}
        args = {'caps': caps, 'bounds': bounds, 'scanner_runs': 20, 'now': 100000}
        self.assertEqual(safe_candidate(sample, **args)['direction'], 'up')
        self.assertEqual(safe_candidate(sample, provider_throttles=1, **args)['direction'], 'none')
        self.assertEqual(safe_candidate(sample, previous={'at': 99999}, **args)['direction'], 'none')
        self.assertEqual(safe_candidate(sample, scanner_failures=4, **args)['direction'], 'down')
        caps['nmap'] = 3
        self.assertEqual(safe_candidate(sample, **args)['direction'], 'none')

    def test_rollback_after_pressure_and_two_hour_coverage_requirement(self):
        sample = {'samples': 150, 'span_minutes': 170, 'free_p10': .1,
                  'waiting': {'nmap': 0}, 'running': {'nmap': 50}}
        previous = {'kind': 'nmap', 'direction': 'up', 'previous': 2, 'at': 99999}
        result = safe_candidate(sample, caps={'nmap': 3}, bounds={'nmap': (1, 3)}, previous=previous, now=100000)
        self.assertIn('Rollback', result['reason'])
        data = [{'t': i * 60, 'memory': {'total_mb': 1000, 'available_mb': 600},
                 'waiting_by_kind': {}, 'running_by_kind': {}} for i in range(130)]
        self.assertIsNone(summarize(data[:100], 130 * 60))
        self.assertEqual(summarize(data, 130 * 60)['samples'], 130)

    def test_live_cap_uses_shared_override_and_clamps_to_operator_bounds(self):
        store = mock.Mock()
        store.r.get.return_value = json.dumps({'value': 3}).encode()
        with mock.patch.object(resources, 'get_store', return_value=store), \
             mock.patch.dict(os.environ, {'HEAVY_TUNE_MAX_NMAP': '3'}):
            self.assertEqual(resources.max_concurrent('nmap'), 3)
            store.r.get.return_value = json.dumps({'value': 99}).encode()
            self.assertEqual(resources.max_concurrent('nmap'), 3)
            store.r.get.side_effect = ConnectionError('broker unavailable')
            self.assertEqual(resources.max_concurrent('nmap'), 2)


class ScheduledReviewTests(TestCase):
    def setUp(self):
        self.projects = [Project.objects.create(name=f'P{i}', slug=f'review-p{i}', insert_date=timezone.now()) for i in range(12)]

    def test_schedule_and_page_checkpoint_cover_later_projects(self):
        from django_celery_beat.models import PeriodicTask
        schedule = PeriodicTask.objects.get(name='cvengine-three-hour-assessment-review')
        self.assertEqual((schedule.task, schedule.queue, schedule.interval.every, schedule.interval.period),
                         ('assessment_review', 'cve_feed_queue', 3, 'hours'))
        with mock.patch('cveFeed.performance_review.review', return_value={'status': 'no_change'}), \
             mock.patch('cveFeed.tasks.assessment_review_task.apply_async') as continuation:
            first = ar.run_page()
            self.assertEqual(first['reviewed'], 10)
            continuation.assert_called_once()
            second = ar.run_page(first['review_id'])
        self.assertEqual(second['reviewed'], 12)
        review = AssessmentReview.objects.get(pk=first['review_id'])
        self.assertEqual(review.status, 'completed')
        self.assertEqual(AssessmentReviewDecision.objects.filter(review=review).count(), 12)
        self.assertEqual(ar.run_page()['skipped'], 'not due')

    def test_ai_choice_is_bounded_and_durable(self):
        project = self.projects[0]
        facts = {'project_id': project.id, 'targets': 1, 'hosts': 2, 'matched_cves': 1,
                 'findings': {'pending': 1}, 'scans': {'active': 0}, 'recent_activity': {'errors': 0}}
        with mock.patch.object(ar, 'PAGE', 1), \
             mock.patch('cveFeed.performance_review.review', return_value={'status': 'no_change'}), \
             mock.patch.object(ar, 'project_facts', return_value=(project, facts, ['triage'])), \
             mock.patch.object(ar, 'model_decision', return_value=({'action': 'triage', 'reason': 'pending findings'}, '')), \
             mock.patch.object(ar, 'dispatch', return_value=('queued', None, 'triage task fake')) as dispatch, \
             mock.patch('cveFeed.tasks.assessment_review_task.apply_async'):
            result = ar.run_page()
        review = AssessmentReview.objects.get(pk=result['review_id'])
        self.assertEqual((review.reviewed_projects, review.model_calls, review.queued_actions), (1, 1, 1))
        self.assertEqual(AssessmentReviewDecision.objects.get(review=review, project=project).status, 'queued')
        dispatch.assert_called_once()

    def test_dispatch_respects_pause_and_exclusions_without_calling_scanner(self):
        project = self.projects[0]
        target = Domain.objects.create(name='review.example.test', project=project, insert_date=timezone.now())
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True), \
             mock.patch('cveFeed.discovery.start_discovery') as scanner:
            self.assertEqual(ar.dispatch(project, {'due_discovery_target_id': target.pk}, 'discover')[0], 'deferred')
            scanner.assert_not_called()
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.exclusions.is_excluded', return_value=True), \
             mock.patch('cveFeed.discovery.start_discovery') as scanner:
            self.assertEqual(ar.dispatch(project, {'due_discovery_target_id': target.pk}, 'discover')[0], 'stale')
            scanner.assert_not_called()

    def test_host_coverage_counts_inventory_not_just_targets_and_queues_stored_host(self):
        project = self.projects[0]
        domain = Domain.objects.create(name='coverage.example', project=project, insert_date=timezone.now())
        missing = Subdomain.objects.create(name='new.coverage.example', target_domain=domain)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(
            engine_name='coverage', yaml_configuration='x'), start_scan_date=timezone.now(), scan_status=2)
        partial = Subdomain.objects.create(name='partial.coverage.example', target_domain=domain, scan_history=scan)
        complete = Subdomain.objects.create(name='done.coverage.example', target_domain=domain, scan_history=scan)
        for stage in ar.HOST_STAGES:
            ScanActivity.objects.create(scan_of=scan, name=stage, title=stage, status=2, time=timezone.now())
        # A successful scan's stages cover both attached hosts; a scanless CT host remains due.
        self.assertEqual(ar.host_coverage_gap(project, timezone.now())[0], 1)
        self.assertEqual(ar.host_coverage_gap(project, timezone.now())[1], missing.pk)
        ScanActivity.objects.filter(scan_of=scan, name='nuclei_targeted_scan').update(status=0)
        self.assertEqual(ar.host_coverage_gap(project, timezone.now())[0], 3)
        HostAssessment.objects.create(project=project, domain=domain, host=missing.name, status='failed')
        self.assertEqual(ar.host_coverage_gap(project, timezone.now())[0], 2)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'coverage-task'
            status, job_id, _ = ar.dispatch(project, {'due_host_id': partial.pk}, 'assess_host')
        self.assertEqual(status, 'queued')
        self.assertEqual(HostAssessment.objects.get(pk=job_id).host, partial.name)

    def test_host_coverage_ignores_active_scans_and_exact_exclusions(self):
        org = Org.objects.create(name='Coverage Org', slug='coverage-org')
        project = Project.objects.create(name='Coverage', slug='coverage-org-proj', org=org, insert_date=timezone.now())
        domain = Domain.objects.create(name='coverage.org', project=project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='coverage-active', yaml_configuration='x')
        active = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1)
        Subdomain.objects.create(target_domain=domain, scan_history=active, name='active.coverage.org')
        Subdomain.objects.create(target_domain=domain, name='blocked.coverage.org')
        HostExclusion.objects.create(org=org, host='blocked.coverage.org')
        self.assertEqual(ar.host_coverage_gap(project, timezone.now()), (0, None))

    def test_broker_error_is_saved_as_failed_decision_without_repeating_action(self):
        project = self.projects[0]
        facts = {'project_id': project.id, 'targets': 1, 'hosts': 0, 'matched_cves': 0,
                 'findings': {}, 'scans': {}, 'recent_activity': {}}
        with mock.patch.object(ar, 'PAGE', 1), \
             mock.patch('cveFeed.performance_review.review', return_value={'status': 'no_change'}), \
             mock.patch.object(ar, 'project_facts', return_value=(project, facts, ['triage'])), \
             mock.patch.object(ar, 'model_decision', return_value=({'action': 'triage', 'reason': 'due'}, '')), \
             mock.patch.object(ar, 'dispatch', side_effect=RuntimeError('broker secret-marker')), \
             mock.patch('cveFeed.tasks.assessment_review_task.apply_async'):
            result = ar.run_page()
        review = AssessmentReview.objects.get(pk=result['review_id'])
        self.assertEqual(review.error_count, 1)
        decision = AssessmentReviewDecision.objects.get(review=review, project=project)
        self.assertEqual(decision.status, 'failed')
        self.assertNotIn('secret-marker', decision.reason)

    def test_budget_pause_and_recovery_are_explicit(self):
        with mock.patch.object(ar, 'MAX_MODEL_CALLS', 1), mock.patch.object(ar, 'PAGE', 2), \
             mock.patch('cveFeed.performance_review.review', return_value={'status': 'no_change'}), \
             mock.patch.object(ar, 'project_facts', side_effect=lambda project_id, *_: (Project.objects.get(pk=project_id),
                {'project_id': project_id, 'targets': 1, 'hosts': 0, 'matched_cves': 0,
                 'findings': {}, 'scans': {}, 'recent_activity': {}}, ['triage'])), \
             mock.patch.object(ar, 'model_decision', return_value=(None, 'provider unavailable')):
            result = ar.run_page()
        review = AssessmentReview.objects.get(pk=result['review_id'])
        self.assertEqual((review.status, review.cursor_project_id, review.model_calls), ('partial', self.projects[0].id, 1))
        with mock.patch.object(ar, 'MAX_MODEL_CALLS', 1):
            self.assertEqual(ar.run_page()['skipped'], 'not due')
        AssessmentReview.objects.filter(pk=review.pk).update(period_end=timezone.now() - timedelta(hours=4))
        with mock.patch.object(ar, 'MAX_MODEL_CALLS', 1), \
             mock.patch('cveFeed.performance_review.review', return_value={'status': 'no_change'}):
            next_result = ar.run_page()
        new = AssessmentReview.objects.get(pk=next_result['review_id'])
        self.assertGreater(new.id, review.id)
        self.assertGreater(new.cursor_project_id, review.cursor_project_id)
