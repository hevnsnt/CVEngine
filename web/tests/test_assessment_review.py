"""Bounded three-hour AI review and deterministic capacity limits."""
import json
import os
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import assessment_review as ar
from cveFeed import performance_review
from cveFeed.models import AssessmentReview, AssessmentReviewDecision, CVEEntry, CVEMatch, HostAssessment, HostExclusion, Triage
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
        # An unattributed failure cannot justify reducing the busiest, unrelated tool.
        self.assertEqual(safe_candidate(sample, scanner_failures=4, **args)['direction'], 'none')
        self.assertEqual(safe_candidate(sample, scanner_failures=4,
                        stage_outcomes={'nmap': {'runs': 20, 'failures': 4, 'capacity_failures': 4}}, **args)['kind'], 'nmap')
        caps['nmap'] = 3
        self.assertEqual(safe_candidate(sample, **args)['direction'], 'none')

    def test_failure_reduction_targets_the_failing_tool_and_can_rollback_during_cooldown(self):
        sample = {'samples': 150, 'span_minutes': 170, 'free_p10': .65,
                  'waiting': {'nmap': 60}, 'running': {'nmap': 100, 'nuclei': 5}}
        caps = {'nmap': 3, 'nuclei': 2}
        bounds = {'nmap': (1, 4), 'nuclei': (1, 3)}
        outcomes = {'nmap': {'runs': 30, 'failures': 0, 'capacity_failures': 0}, 'nuclei': {'runs': 20, 'failures': 5, 'capacity_failures': 5}}
        previous = {'kind': 'nuclei', 'direction': 'up', 'previous': 1, 'at': 99999}
        result = safe_candidate(sample, caps=caps, bounds=bounds, scanner_runs=50, scanner_failures=5,
                                stage_outcomes=outcomes, previous=previous, now=100000)
        self.assertEqual((result['kind'], result['direction']), ('nuclei', 'down'))
        self.assertIn('Rollback', result['reason'])
        caps['nuclei'] = 1
        self.assertEqual(safe_candidate(sample, caps=caps, bounds=bounds, scanner_runs=50,
                         scanner_failures=5, stage_outcomes=outcomes, now=100000)['direction'], 'none')

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

    def test_performance_review_attributes_scanner_failures_before_reducing_capacity(self):
        now = timezone.now()
        project = self.projects[0]
        domain = Domain.objects.create(name='performance.example', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(
            engine_name='performance', yaml_configuration='x'), start_scan_date=now, scan_status=2)
        ScanActivity.objects.bulk_create([
            ScanActivity(scan_of=scan, name='nmap_scan', title='nmap', status=2, time=now)
            for _ in range(20)
        ] + [
            ScanActivity(scan_of=scan, name='nuclei_light_scan', title='nuclei', status=0 if i < 5 else 2, time=now,
                         error_message='Nuclei timed out' if i < 5 else None)
            for i in range(20)
        ])
        samples = [{'t': now.timestamp() - 7200 + i * 60,
                    'memory': {'total_mb': 1000, 'available_mb': 700},
                    'waiting_by_kind': {}, 'running_by_kind': {'nmap': 4, 'nuclei': 1}} for i in range(121)]
        client = mock.Mock()
        client.get.return_value = None
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch.object(resources, 'get_store', return_value=mock.Mock(r=client)), \
             mock.patch.object(resources, 'adaptive_history', return_value=samples), \
             mock.patch.object(resources, 'max_concurrent', side_effect=lambda kind: 3 if kind == 'nmap' else 2 if kind == 'nuclei' else 1), \
             mock.patch.object(resources, 'adaptive_bounds', side_effect=lambda kind: (1, 4) if kind == 'nmap' else (1, 3) if kind == 'nuclei' else (1, 1)), \
             mock.patch.object(performance_review, '_model_agrees', return_value=(True, 'agreed')):
            result = performance_review.review(now)
        self.assertEqual((result['status'], result['kind'], result['before'], result['after']), ('changed', 'nuclei', 2, 1))
        self.assertEqual(result['stage_outcomes'], {
            'nmap': {'runs': 20, 'failures': 0, 'capacity_failures': 0, 'configuration_failures': 0},
            'nuclei': {'runs': 20, 'failures': 5, 'capacity_failures': 5, 'configuration_failures': 0}})
        self.assertEqual(client.set.call_count, 2)

    def test_failure_cause_separates_capacity_from_configuration(self):
        for message in ('nmap on web1 waited too long for memory (210 MB free, needs 600 MB)', 'Nuclei timed out',
                        'probe exceeded its total time budget', 'Nuclei exited with status -9', 'nmap exited with status 137'):
            self.assertEqual(performance_review.failure_cause(message), 'capacity', message)
        for message in ('Nuclei template library is unavailable', 'No installed Nuclei templates passed the read-only policy',
                        'invalid probe URL', 'www.example.com is not scanned: the program has not confirmed automated testing'):
            self.assertEqual(performance_review.failure_cause(message), 'configuration', message)
        for message in ('nmap exited with status 1', 'nmap returned no XML report', '', None):
            self.assertEqual(performance_review.failure_cause(message), 'other', message)

    def test_configuration_and_unexplained_failures_never_lower_a_cap(self):
        sample = {'samples': 150, 'span_minutes': 170, 'free_p10': .65, 'waiting': {'nmap': 60}, 'running': {'nmap': 100, 'nuclei': 5}}
        args = {'caps': {'nmap': 3, 'nuclei': 2}, 'bounds': {'nmap': (1, 4), 'nuclei': (1, 3)}, 'scanner_runs': 50,
                'scanner_failures': 8, 'now': 100000}
        configuration = {'nuclei': {'runs': 20, 'failures': 8, 'capacity_failures': 0, 'configuration_failures': 8}}
        result = safe_candidate(sample, stage_outcomes=configuration, **args)
        self.assertEqual((result['kind'], result['direction']), ('none', 'none'))
        self.assertIn('configuration, not capacity', result['reason'])
        unexplained = {'nuclei': {'runs': 20, 'failures': 8, 'capacity_failures': 0, 'configuration_failures': 0}}
        self.assertEqual(safe_candidate(sample, stage_outcomes=unexplained, **args)['direction'], 'none')
        capacity = {'nuclei': {'runs': 20, 'failures': 8, 'capacity_failures': 5, 'configuration_failures': 3}}
        self.assertEqual((safe_candidate(sample, stage_outcomes=capacity, **args)['kind'],
                          safe_candidate(sample, stage_outcomes=capacity, **args)['direction']), ('nuclei', 'down'))

    def test_performance_review_reports_configuration_failures_without_lowering_the_cap(self):
        now = timezone.now()
        project = self.projects[0]
        domain = Domain.objects.create(name='config.example', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(
            engine_name='config', yaml_configuration='x'), start_scan_date=now, scan_status=2)
        ScanActivity.objects.bulk_create([
            ScanActivity(scan_of=scan, name='nuclei_light_scan', title='nuclei', status=0 if i < 8 else 2, time=now,
                         error_message='Nuclei template library is unavailable' if i < 8 else None) for i in range(20)]
            + [ScanActivity(scan_of=scan, name='nmap_scan', title='nmap', status=0, time=now, error_message='nmap exited with status 137')
               for _ in range(3)])
        samples = [{'t': now.timestamp() - 7200 + i * 60, 'memory': {'total_mb': 1000, 'available_mb': 700},
                    'waiting_by_kind': {}, 'running_by_kind': {'nuclei': 1}} for i in range(121)]
        client = mock.Mock()
        client.get.return_value = None
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch.object(resources, 'get_store', return_value=mock.Mock(r=client)), \
             mock.patch.object(resources, 'adaptive_history', return_value=samples), \
             mock.patch.object(resources, 'max_concurrent', side_effect=lambda kind: 2), \
             mock.patch.object(resources, 'adaptive_bounds', side_effect=lambda kind: (1, 3)), \
             mock.patch.object(performance_review, '_model_agrees') as model:
            result = performance_review.review(now)
        model.assert_not_called()
        self.assertEqual(result['status'], 'no_change')
        self.assertIn('configuration, not capacity', result['reason'])
        self.assertEqual(result['stage_outcomes']['nuclei'], {'runs': 20, 'failures': 8, 'capacity_failures': 0, 'configuration_failures': 8})
        # the same pattern read by the database: an exit status of 137 (the kernel's kill) is capacity, not configuration
        self.assertEqual(result['stage_outcomes']['nmap'], {'runs': 3, 'failures': 3, 'capacity_failures': 3, 'configuration_failures': 0})
        client.set.assert_not_called()

    def test_rescan_history_does_not_inflate_review_or_requeue_old_cve_rows(self):
        from cveFeed import triage, validation
        project = self.projects[0]
        domain = Domain.objects.create(name='review.example', project=project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='review-history', yaml_configuration='x')
        cve = CVEEntry.objects.create(cve_id='CVE-2099-100', cvss=8.0)
        rows = []
        for _ in range(2):
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine,
                                              start_scan_date=timezone.now(), scan_status=2)
            host = Subdomain.objects.create(name='app.review.example', target_domain=domain, scan_history=scan)
            match = CVEMatch.objects.create(cve_entry=cve, subdomain=host, matched_product='Example App')
            rows.append(Triage.objects.create(project=project, domain=domain, host=host.name,
                                              kind='cve_match', match=match, status='pending'))
        with mock.patch.object(ar, 'host_coverage_gap', return_value=(0, None)):
            _, facts, offered = ar.project_facts(project.pk, timezone.now() - timedelta(hours=3), timezone.now())
        self.assertEqual((facts['hosts'], facts['matched_cves'], facts['matched_cves_updated_in_window']), (1, 1, 1))
        self.assertEqual((facts['findings']['total'], facts['findings']['pending']), (1, 1))
        self.assertEqual([r['id'] for r in facts['top_pending_findings']], [rows[1].pk])
        self.assertEqual(validation.due_ids(project.pk), [rows[1].pk])
        self.assertIn('triage', offered)
        with mock.patch.object(triage, 'backfill'), mock.patch.object(triage, 'run_triage', return_value={
                'rows': 1, 'asked': 0, 'cached': 0, 'queued': 0, 'not_triaged': 1, 'errors': 0}) as run:
            triage.sweep(project.pk)
        self.assertEqual([r.pk for r, _ in run.call_args.args[0]], [rows[1].pk])

    def test_a_run_a_little_early_is_due_and_windows_are_contiguous(self):
        end = timezone.now() - timedelta(hours=2, minutes=50)  # the last run started late; this one starts on time
        AssessmentReview.objects.create(period_start=end - timedelta(hours=3), period_end=end, status='completed', total_projects=0)
        with mock.patch('cveFeed.performance_review.review', return_value={'status': 'no_change'}), \
             mock.patch('cveFeed.tasks.assessment_review_task.apply_async'):
            result = ar.run_page()
        self.assertNotIn('skipped', result)
        self.assertEqual(AssessmentReview.objects.get(pk=result['review_id']).period_start, end)
        AssessmentReview.objects.update(status='completed', period_end=timezone.now() - timedelta(hours=2))
        self.assertEqual(ar.run_page()['skipped'], 'not due')  # but not an hour early

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
