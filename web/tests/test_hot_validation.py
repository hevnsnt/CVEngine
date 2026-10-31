from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone

from cveFeed import hot_validation, triage
from cveFeed.models import (AutomaticValidation, CVEEntry, CVEMatch, HygieneFinding,
                            HotValidationCursor, OnDemandValidation, RouteAuth, Triage)
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tenancy import roles


class HotValidationTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='One', slug='one')
        self.project = Project.objects.create(name='One', slug='one', org=self.org, insert_date=now)
        self.domain = Domain.objects.create(name='a.example', project=self.project, insert_date=now)
        self.sub = Subdomain.objects.create(name='www.a.example', target_domain=self.domain)
        self.fire = CVEEntry.objects.create(cve_id='CVE-2099-1', cvss=9.8, affected=[{'product': 'nginx'}], published_at=now)
        self.smoke = CVEEntry.objects.create(cve_id='CVE-2099-2', cvss=7.5, affected=[{'product': 'nginx'}], published_at=now)
        self.fire_match = CVEMatch.objects.create(cve_entry=self.fire, subdomain=self.sub, matched_product='nginx')
        self.smoke_match = CVEMatch.objects.create(cve_entry=self.smoke, subdomain=self.sub, matched_product='nginx')
        self.high = Vulnerability.objects.create(name='High scanner observation', severity=3, source='bbot',
                                                 subdomain=self.sub, target_domain=self.domain)
        self.medium = Vulnerability.objects.create(name='Medium scanner observation', severity=2, source='bbot',
                                                   subdomain=self.sub, target_domain=self.domain)
        triage.track([self.fire_match, self.smoke_match, self.high, self.medium])

    def test_fire_is_dispatched_before_smoke_on_priority_lane_and_duplicates_are_suppressed(self):
        calls = []
        def record(name):
            return lambda *a, **kw: calls.append((name, kw['priority']))
        with mock.patch('cveFeed.hot_validation._backfill_projects', return_value=0), \
                mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async', side_effect=record('cve')), \
                mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async', side_effect=record('finding')):
            result = hot_validation.sweep()
            again = hot_validation.sweep()
        self.assertEqual((result['fire'], result['smoke']), (2, 2))
        self.assertEqual([priority for _, priority in calls], [0, 0, 6, 6])
        self.assertEqual((again['fire'], again['smoke']), (0, 0))
        self.assertEqual(OnDemandValidation.objects.filter(status='queued').count(), 2)
        self.assertEqual(AutomaticValidation.objects.filter(status='queued').count(), 2)
        self.assertTrue(HotValidationCursor.objects.filter(lane='fire').exists())

    def test_queued_smoke_is_promoted_when_it_becomes_fire(self):
        row = Triage.objects.get(match=self.smoke_match)
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(row, 'smoke'), 'queued')
            self.smoke.cvss = 9.8
            self.smoke.save(update_fields=['cvss'])
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'promoted')
        self.assertEqual([call.kwargs['priority'] for call in dispatch.call_args_list], [6, 0])
        self.assertEqual(OnDemandValidation.objects.filter(match=self.smoke_match).count(), 1)
        self.assertEqual(OnDemandValidation.objects.get(match=self.smoke_match).priority, 0)

    def test_broker_failure_is_retriable_after_backoff_and_project_cap_defers(self):
        row = Triage.objects.get(match=self.fire_match)
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async', side_effect=RuntimeError('broker down')):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'failed')
        first = OnDemandValidation.objects.get(match=self.fire_match)
        self.assertEqual(first.status, 'failed')
        self.assertEqual(hot_validation.enqueue(row, 'fire'), 'fresh')
        OnDemandValidation.objects.filter(pk=first.pk).update(finished_at=timezone.now() - timedelta(minutes=6))
        with mock.patch('cveFeed.hot_validation._active_count', return_value=10):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'project_cap')
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        dispatch.assert_called_once_with(args=[mock.ANY], priority=0)

    def _rescan_twin(self, validated_ago):
        """The same finding in a later scan: a new host row of the same name and a new match for the same CVE."""
        Triage.objects.filter(match=self.fire_match).update(status='triaged', classification='likely', validation_status='clean',
                                                            validated_at=timezone.now() - validated_ago)
        later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
        match = CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')
        return triage.track([match])[0][0]

    def test_a_rescans_new_match_keeps_the_validation_its_predecessor_finished(self):
        row = self._rescan_twin(timedelta(days=1))
        self.assertEqual((row.validation_status, row.classification), ('clean', 'likely'))
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'fresh')
        dispatch.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.filter(match=row.match).exists())

    def test_a_validation_older_than_the_window_is_run_again_on_the_new_match(self):
        row = self._rescan_twin(timedelta(days=9))
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        dispatch.assert_called_once()

    def test_a_failed_validation_is_not_carried_to_the_new_match(self):
        Triage.objects.filter(match=self.fire_match).update(status='triaged', validation_status='failed', validated_at=timezone.now())
        later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
        row = triage.track([CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')])[0][0]
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')

    def _rescan_with_job(self, **job):
        """A rescan's new match whose predecessor had a validation job in the given state."""
        Triage.objects.filter(match=self.fire_match).update(status='triaged', classification='likely')
        OnDemandValidation.objects.create(match=self.fire_match, project=self.project, evidence_signature='old-nonce-signature', **job)
        later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
        match = CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')
        row = triage.track([match])[0][0]
        self.assertEqual(row.carried_from, self.fire_match.pk)
        return row

    def _enqueue(self, row):
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            return hot_validation.enqueue(row, 'fire'), dispatch

    def test_a_job_that_failed_for_good_is_not_started_again_at_attempt_one_by_every_rescan(self):
        row = self._rescan_with_job(status='failed', attempts=hot_validation.MAX_ATTEMPTS, next_attempt_at=None, finished_at=timezone.now())
        outcome, dispatch = self._enqueue(row)
        self.assertEqual(outcome, 'fresh')
        dispatch.assert_not_called()

    def test_a_job_that_is_backing_off_keeps_its_backoff(self):
        row = self._rescan_with_job(status='failed', attempts=2, next_attempt_at=timezone.now() + timedelta(hours=1), finished_at=timezone.now())
        self.assertEqual(self._enqueue(row)[0], 'fresh')

    def test_the_attempt_count_goes_on_after_the_backoff(self):
        row = self._rescan_with_job(status='failed', attempts=2, next_attempt_at=timezone.now() - timedelta(minutes=1),
                                    finished_at=timezone.now() - timedelta(hours=1))
        outcome, _ = self._enqueue(row)
        self.assertEqual(outcome, 'queued')
        self.assertEqual(OnDemandValidation.objects.get(match=row.match).attempts, 3)

    def test_a_job_finished_inside_the_window_stands_for_the_new_match(self):
        row = self._rescan_with_job(status='completed', result={'ai_state': 'ok'}, finished_at=timezone.now() - timedelta(days=2))
        self.assertEqual(self._enqueue(row)[0], 'fresh')

    def test_changed_evidence_on_a_carried_row_is_validated_again(self):
        # issue 206: only an UNCHANGED finding keeps its predecessor's job. save_matches moves a match's evidence in place (distro or range
        # data moved), which resets the Triage row; the stale carried_from used to hand it the old job's "fresh" verdict all the same
        row = self._rescan_with_job(status='completed', result={'ai_state': 'ok'}, finished_at=timezone.now() - timedelta(days=1))
        self.assertEqual(self._enqueue(row)[0], 'fresh')  # unchanged evidence: the job stands
        CVEMatch.objects.filter(pk=row.match_id).update(matched_version='1.19.0')
        row = triage.track(triage.with_cves([CVEMatch.objects.select_related('subdomain__target_domain').get(pk=row.match_id)]))[0][0]
        self.assertEqual((row.status, row.classification, row.validation_status), ('pending', '', 'none'))
        outcome, dispatch = self._enqueue(Triage.objects.get(pk=row.pk))
        self.assertEqual(outcome, 'queued')
        dispatch.assert_called_once()
        self.assertIsNone(Triage.objects.get(pk=row.pk).carried_from)  # persisted, not just set on the object

    def _ai_off_rescan(self, validated_ago):
        """A rescan's new row of a finding the AI never reviewed (no provider), validated by the scan pipeline, with no job of its own."""
        Triage.objects.filter(match=self.fire_match).update(status='not_triaged', validation_status='clean',
                                                            validated_at=timezone.now() - validated_ago)
        later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
        row = triage.track([CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')])[0][0]
        Triage.objects.filter(pk=row.pk).update(status='not_triaged')  # (the host's other matches differ in this fixture, which re-queues it)
        row.refresh_from_db()
        self.assertEqual((row.status, row.validation_status, row.carried_from), ('not_triaged', 'clean', self.fire_match.pk))
        return row

    def test_an_ai_off_row_validated_three_days_ago_is_validated_again(self):
        # the shorter window is for a result the AI could not review (_job_current); the same applies to a row with no job of its own
        self.assertEqual(self._enqueue(self._ai_off_rescan(timedelta(days=3)))[0], 'queued')

    def test_an_ai_off_row_validated_a_few_hours_ago_is_still_fresh(self):
        self.assertEqual(self._enqueue(self._ai_off_rescan(timedelta(hours=5)))[0], 'fresh')

    def test_the_shorter_window_applies_when_the_ai_could_not_answer(self):
        row = self._rescan_with_job(status='completed', result={'ai_state': 'unavailable'}, finished_at=timezone.now() - timedelta(days=2))
        self.assertEqual(self._enqueue(row)[0], 'queued')

    def test_a_job_still_running_on_the_old_match_does_not_hold_the_new_one_back(self):
        # its result goes to the old match's row, so the new match needs a job of its own
        row = self._rescan_with_job(status='running', started_at=timezone.now())
        self.assertEqual(self._enqueue(row)[0], 'queued')

    def test_the_history_is_followed_through_matches_that_never_had_a_job(self):
        Triage.objects.filter(match=self.fire_match).update(status='triaged', classification='likely')
        OnDemandValidation.objects.create(match=self.fire_match, project=self.project, evidence_signature='x', status='failed',
                                          attempts=hot_validation.MAX_ATTEMPTS, finished_at=timezone.now())
        row = None
        for _ in range(3):  # three more scans, none of which queued anything
            later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
            row = triage.track([CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')])[0][0]
            Triage.objects.filter(pk=row.pk).update(status='triaged')  # reviewed, so the next scan's row takes its record from this one
        self.assertNotEqual(row.carried_from, self.fire_match.pk)
        self.assertEqual(self._enqueue(row)[0], 'fresh')

    def test_a_row_that_took_nothing_from_an_earlier_one_has_no_history(self):
        row = Triage.objects.get(match=self.fire_match)
        self.assertIsNone(row.carried_from)
        self.assertEqual(self._enqueue(row)[0], 'queued')

    def test_a_record_older_than_the_window_is_not_inherited(self):
        Triage.objects.filter(match=self.fire_match).update(status='triaged', classification='likely')
        Triage.objects.filter(match=self.fire_match).update(updated_at=timezone.now() - triage.TWIN_WINDOW - timedelta(days=1))
        later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
        row = triage.track([CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')])[0][0]
        self.assertEqual((row.status, row.classification, row.carried_from), ('pending', '', None))

    def test_the_twin_lookup_returns_one_row_per_finding_however_many_scans_there_were(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        Triage.objects.filter(match=self.fire_match).update(status='triaged', classification='likely')
        for _ in range(6):
            later = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain)
            triage.track([CVEMatch.objects.create(cve_entry=self.fire, subdomain=later, matched_product='nginx')])
        fresh = CVEMatch.objects.create(cve_entry=self.fire, subdomain=Subdomain.objects.create(name=self.sub.name, target_domain=self.domain),
                                        matched_product='nginx')
        description = triage.describe(fresh)
        with CaptureQueriesContext(connection) as queries:
            found = triage._twins([(fresh, description)])
        self.assertEqual(len(found), 1)
        self.assertIn('DISTINCT ON', ' '.join(q['sql'] for q in queries.captured_queries))

    def test_cursor_keeps_work_over_the_per_sweep_cap(self):
        with mock.patch('cveFeed.hot_validation._backfill_projects', return_value=0), \
                mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'), \
                mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            first = hot_validation.sweep(max_jobs=1)
            second = hot_validation.sweep(max_jobs=1)
        self.assertEqual((first['fire'], second['fire']), (1, 1))

    def test_an_automatic_validation_with_the_ai_off_keeps_the_earlier_triage(self):
        # the job asks for a fresh review under its own nonce; that must not reset the row (the same loss as an on-demand match validation)
        from cveFeed import tasks
        row = Triage.objects.get(vulnerability=self.high)
        Triage.objects.filter(pk=row.pk).update(status='triaged', classification='likely', reason='earlier answer')
        row.refresh_from_db()
        job = AutomaticValidation.objects.create(triage=row, project_id=row.project_id, signature=row.signature, priority=6)
        with mock.patch('cveFeed.validation_authority.require_authority'), \
                mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
                mock.patch('cveFeed.triage._resolve_provider', return_value=None):
            tasks.automatic_validate_finding(job.pk)
        row.refresh_from_db()
        self.assertEqual(AutomaticValidation.objects.get(pk=job.pk).status, 'completed')
        self.assertEqual((row.classification, row.reason), ('likely', 'earlier answer'))

    def test_backfill_existing_untracked_findings(self):
        Triage.objects.all().delete()
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'), \
                mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            result = hot_validation.sweep()
        self.assertEqual(result['projects'], 1)
        self.assertTrue(Triage.objects.filter(match=self.fire_match).exists())
        self.assertEqual(result['fire'], 2)

    def test_unsupported_fire_finding_gets_ai_review_and_explicit_no_check(self):
        from cveFeed.tasks import automatic_validate_finding
        row = Triage.objects.get(vulnerability=self.high)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        job = AutomaticValidation.objects.get(triage=row)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.validation.run_validation') as checks, \
                mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
            result = automatic_validate_finding(job.pk)
        checks.assert_not_called()
        self.assertEqual((result['check_state'], result['ai_state']), ('no_check', 'unavailable'))
        self.assertEqual(AutomaticValidation.objects.get(pk=job.pk).status, 'completed')

    def test_manual_low_tier_finding_is_reviewed_but_closed_one_is_rejected(self):
        from cveFeed.tasks import automatic_validate_finding
        requester = get_user_model().objects.create_user('requester', password='x' * 24)
        ProjectMembership.objects.create(user=requester, project=self.project, role=roles.ADMIN)  # manual jobs re-check this at run time
        low = Vulnerability.objects.create(name='Low observation', severity=1, source='bbot',
                                            subdomain=self.sub, target_domain=self.domain)
        row = triage.track([low])[0][0]
        job = AutomaticValidation.objects.create(triage=row, project=self.project, signature=row.signature,
                                                 source='manual', priority=3, attempts=1, requested_by=requester)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}) as review:
            result = automatic_validate_finding(job.pk)
        self.assertEqual((result['check_state'], result['ai_state']), ('no_check', 'unavailable'))
        review.assert_called_once()
        self.assertEqual(AutomaticValidation.objects.get(pk=job.pk).status, 'completed')
        low.open_status = False
        low.save(update_fields=['open_status'])
        again = AutomaticValidation.objects.create(triage=row, project=self.project, signature=row.signature,
                                                   source='manual', priority=3, attempts=1, requested_by=requester)
        with mock.patch('cveFeed.triage.run_triage') as review:
            result = automatic_validate_finding(again.pk)
        review.assert_not_called()
        self.assertEqual(AutomaticValidation.objects.get(pk=again.pk).status, 'skipped')
        self.assertEqual(result['reason'], 'no_longer_eligible')
        self.assertIsNone(AutomaticValidation.objects.get(pk=again.pk).next_attempt_at)

    def test_a_skipped_job_of_a_replaced_match_does_not_stand_for_its_successor(self):
        from cveFeed.models import OnDemandValidation
        now = timezone.now()
        job = OnDemandValidation(status='skipped', result={'reason': 'historical'}, created_at=now, finished_at=now)
        self.assertFalse(hot_validation._job_current(job, now))
        job.result = {'reason': 'out_of_scope'}
        self.assertTrue(hot_validation._job_current(job, now))
        self.assertFalse(hot_validation._job_current(job, now + timedelta(minutes=31)))

    def test_stale_evidence_is_superseded_without_false_worker_failure(self):
        from cveFeed.tasks import automatic_validate_finding
        row = Triage.objects.get(vulnerability=self.high)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        job = AutomaticValidation.objects.get(triage=row)
        self.high.name = 'Updated scanner observation'
        self.high.save(update_fields=['name'])
        with mock.patch('cveFeed.triage.run_triage') as review:
            result = automatic_validate_finding(job.pk)
        review.assert_not_called()
        self.assertEqual(result['reason'], 'evidence_changed')
        self.assertEqual(AutomaticValidation.objects.get(pk=job.pk).status, 'skipped')
        row.refresh_from_db()
        self.assertNotEqual(row.signature, job.signature)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')

    def test_each_non_cve_kind_loads_and_describes_real_model_rows(self):
        route = RouteAuth.objects.create(project=self.project, domain=self.domain, host=self.sub.name,
            url='https://www.a.example/admin', path='/admin', auth_state='open', http_status=200)
        hygiene = HygieneFinding.objects.create(domain=self.domain, host=self.sub.name, check_name='tls_expired',
            severity=4, title='TLS certificate expired')
        db = Vulnerability.objects.create(name='Database response', severity=3, source='db_exposure',
            http_url='tcp://www.a.example:5432', subdomain=self.sub, target_domain=self.domain)
        nuclei = Vulnerability.objects.create(name='Template response', severity=3, source='nuclei',
            http_url='https://www.a.example:443', subdomain=self.sub, target_domain=self.domain)
        for finding in (self.high, route, hygiene, db, nuclei):
            with self.subTest(finding=type(finding).__name__, pk=finding.pk):
                row, _ = triage.track([finding])[0]
                loaded = triage.load_findings([row])
                self.assertEqual(len(loaded), 1)
                self.assertEqual(triage.describe(loaded[0])['project_id'], self.project.pk)

    def test_malformed_scanner_url_does_not_break_loading_or_describing(self):
        self.high.http_url = 'https://www.a.example:not-a-port/path'
        self.high.save(update_fields=['http_url'])
        row = Triage.objects.get(vulnerability=self.high)
        self.assertEqual(triage.describe(triage.load_findings([row])[0])['project_id'], self.project.pk)
        db = Vulnerability.objects.create(name='Database response', severity=3, source='db_exposure',
            http_url='tcp://www.a.example:not-a-port', subdomain=self.sub, target_domain=self.domain)
        row, _ = triage.track([db])[0]
        self.assertEqual(triage.describe(triage.load_findings([row])[0])['project_id'], self.project.pk)

    def test_route_and_hygiene_are_included_by_their_severity(self):
        route = RouteAuth.objects.create(project=self.project, domain=self.domain, host=self.sub.name,
            url='https://www.a.example/admin', path='/admin', auth_state='open', http_status=200)
        hygiene = HygieneFinding.objects.create(domain=self.domain, host=self.sub.name, check_name='tls_expired',
            severity=4, title='TLS certificate expired')
        rows = triage.track([route, hygiene])
        self.assertEqual([hot_validation.tier_for(row) for row, _ in rows], ['smoke', 'fire'])

    def test_route_worker_executes_approved_check_then_reviews_fresh_evidence(self):
        from cveFeed.tasks import automatic_validate_finding
        route = RouteAuth.objects.create(project=self.project, domain=self.domain, host=self.sub.name,
            url='https://www.a.example/admin', path='/admin', auth_state='open', http_status=200)
        row = triage.track([route])[0][0]
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'smoke'), 'queued')
        job = AutomaticValidation.objects.get(triage=row)
        old_signature = row.signature
        def checked(project_id, ids):
            self.assertEqual((project_id, ids), (self.project.pk, [row.pk]))
            Triage.objects.filter(pk=row.pk).update(validation_status='observed')
            return {'ran': 1, 'reused': 0, 'no_check': 0}
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.validation.run_validation', side_effect=checked) as check, \
                mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}) as review:
            result = automatic_validate_finding(job.pk)
        check.assert_called_once()
        review.assert_called_once()
        self.assertEqual((result['check_state'], result['ai_state']), ('observed', 'unavailable'))
        self.assertNotEqual(AutomaticValidation.objects.get(pk=job.pk).signature, old_signature)
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'smoke'), 'fresh')

    def test_route_worker_real_plan_and_result_path_with_fixture_runner(self):
        from cveFeed.tasks import automatic_validate_finding
        from cveFeed import validation
        route = RouteAuth.objects.create(project=self.project, domain=self.domain, host=self.sub.name,
            url='https://www.a.example/admin', path='/admin', auth_state='open', http_status=200)
        row = triage.track([route])[0][0]
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'smoke'), 'queued')
        job = AutomaticValidation.objects.get(triage=row)
        safe_runner = lambda check: {'status': 'observed', 'summary': 'fixture HEAD response'}
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, **kw: names), \
                mock.patch.dict(validation.RUNNERS, {'http_head': safe_runner}), \
                mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
            result = automatic_validate_finding(job.pk)
        self.assertNotIn('error', result)
        self.assertEqual(AutomaticValidation.objects.get(pk=job.pk).status, 'completed')

    def test_non_cve_worker_real_ai_review_with_fixture_provider(self):
        import json
        from cveFeed.tasks import automatic_validate_finding
        row = Triage.objects.get(vulnerability=self.high)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        job = AutomaticValidation.objects.get(triage=row)
        provider = mock.Mock(name='fixture_provider')
        provider.name, provider.model = 'anthropic', 'fixture-model'
        provider.complete.return_value = json.dumps({
            'classification': 'likely', 'reason': 'fixture evidence', 'impact': 'fixture impact',
            'severity_adjust': 0, 'severity_reason': '', 'remediation': 'Review fixture', 'validation_steps': []})
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider):
            result = automatic_validate_finding(job.pk)
        self.assertNotIn('error', result)
        self.assertEqual(result['ai_state'], 'completed')
        self.assertEqual(AutomaticValidation.objects.get(pk=job.pk).status, 'completed')

    def test_scope_recheck_blocks_checks_and_ai_review(self):
        from cveFeed.tasks import automatic_validate_finding
        row = Triage.objects.get(vulnerability=self.high)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            hot_validation.enqueue(row, 'fire')
        job = AutomaticValidation.objects.get(triage=row)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[]), \
                mock.patch('cveFeed.validation.run_validation') as checks, \
                mock.patch('cveFeed.triage.run_triage') as review:
            result = automatic_validate_finding(job.pk)
        checks.assert_not_called()
        review.assert_not_called()
        self.assertEqual(result['reason'], 'out_of_scope')
        failed = AutomaticValidation.objects.get(pk=job.pk)
        self.assertEqual(failed.status, 'skipped')
        self.assertIsNone(failed.next_attempt_at)

    def test_worker_failure_attaches_safe_stack_and_retries_with_backoff(self):
        from cveFeed.tasks import automatic_validate_finding
        from cveFeed.models import AgentActivity
        row = Triage.objects.get(vulnerability=self.high)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        first = AutomaticValidation.objects.get(triage=row)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.triage.load_findings', side_effect=ValueError('password=private-marker')):
            result = automatic_validate_finding(first.pk)
        self.assertEqual(result['diagnostic']['category'], 'ValueError')
        self.assertEqual(result['diagnostic']['finding_kind'], 'bbot')
        self.assertEqual(result['diagnostic']['stage'], 'load_bbot')
        self.assertEqual(result['diagnostic']['failure_code'], 'unexpected_value')
        self.assertNotIn('private-marker', str(result))
        self.assertIn('tasks.py', result['diagnostic']['stack'])
        entry = AgentActivity.objects.filter(detail__job_id=first.pk, status='failed').latest('id')
        self.assertNotIn('private-marker', str(entry.detail) + entry.message)
        self.assertEqual(entry.detail['diagnostic']['id'], result['diagnostic']['id'])
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'fresh')
        AutomaticValidation.objects.filter(pk=first.pk).update(next_attempt_at=timezone.now() - timedelta(seconds=1))
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'queued')
        second = AutomaticValidation.objects.latest('id')
        self.assertEqual(second.attempts, 2)

    def test_a_failed_on_demand_validation_backs_off_instead_of_retrying_every_sweep(self):
        from cveFeed.tasks import validate_match_on_demand
        row = Triage.objects.get(match=self.fire_match)
        job = OnDemandValidation.objects.create(match=self.fire_match, project=self.project, evidence_signature=row.signature,
                                                priority=0)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', side_effect=OSError('boom')), self.assertLogs('cveFeed.tasks', 'ERROR'):
            validate_match_on_demand(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertGreater(job.next_attempt_at, timezone.now() + timedelta(minutes=4))
        # the sweep runs every 5 minutes: a job that finished 6 minutes ago is still inside its backoff
        OnDemandValidation.objects.filter(pk=job.pk).update(finished_at=timezone.now() - timedelta(minutes=6))
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'fresh')
        OnDemandValidation.objects.filter(pk=job.pk).update(next_attempt_at=timezone.now() - timedelta(seconds=1))
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'queued')
        self.assertEqual(OnDemandValidation.objects.latest('id').attempts, 2)

    def test_an_on_demand_validation_stops_after_its_last_attempt(self):
        from cveFeed.tasks import validate_match_on_demand
        row = Triage.objects.get(match=self.fire_match)
        job = OnDemandValidation.objects.create(match=self.fire_match, project=self.project, evidence_signature=row.signature,
                                                priority=0, attempts=hot_validation.MAX_ATTEMPTS)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', side_effect=OSError('boom')), self.assertLogs('cveFeed.tasks', 'ERROR'):
            validate_match_on_demand(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertIsNone(job.next_attempt_at)
        OnDemandValidation.objects.filter(pk=job.pk).update(finished_at=timezone.now() - timedelta(days=2))
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'fresh')  # exhausted for this evidence

    def test_an_automatic_validation_that_keeps_failing_stops_after_its_last_attempt(self):
        from cveFeed.tasks import automatic_validate_finding
        row = Triage.objects.get(vulnerability=self.high)
        job = AutomaticValidation.objects.create(triage=row, project=self.project, signature=row.signature, priority=0,
                                                 attempts=hot_validation.MAX_ATTEMPTS)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[row.host]), \
                mock.patch('cveFeed.triage.run_triage', return_value={'errors': 1}):
            result = automatic_validate_finding(job.pk)
        job.refresh_from_db()
        self.assertEqual((job.status, result['ai_state']), ('failed', 'failed'))
        self.assertIsNone(job.next_attempt_at)  # not a fresh 6 h backoff forever
        AutomaticValidation.objects.filter(pk=job.pk).update(finished_at=timezone.now() - timedelta(days=2))
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'fresh')

    def test_a_cap_deferral_waits_for_the_cap_reset_without_spending_an_attempt(self):
        from cveFeed.validation import next_cap_reset
        self.assertEqual(hot_validation.retry_after(3, capped_only=True), next_cap_reset())
        self.assertGreater(next_cap_reset(), timezone.now())
        row = Triage.objects.get(match=self.fire_match)
        OnDemandValidation.objects.create(match=self.fire_match, project=self.project, evidence_signature=row.signature,
                                          priority=0, status='failed', attempts=3, result={'deferred_by_cap': True},
                                          finished_at=timezone.now() - timedelta(days=1),
                                          next_attempt_at=timezone.now() - timedelta(seconds=1))
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')
        self.assertEqual(OnDemandValidation.objects.latest('id').attempts, 3)

    def test_exhausted_loader_failure_does_not_retry_same_evidence(self):
        from cveFeed.tasks import automatic_validate_finding
        row = Triage.objects.get(vulnerability=self.high)
        job = AutomaticValidation.objects.create(triage=row, project=self.project, signature=row.signature,
                                                   attempts=7, priority=0)
        with mock.patch('cveFeed.triage.load_findings', side_effect=ValueError('bad stored value')):
            result = automatic_validate_finding(job.pk)
        self.assertIsNone(result['retry_at'])
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=row.pk), 'fire'), 'fresh')

    def test_finding_detail_shows_scoped_automatic_job_without_raw_error(self):
        from agentapi.services import Ctx, finding_detail
        user = get_user_model().objects.create_superuser('operator', 'operator@example.test', 'local-only')
        row = Triage.objects.get(vulnerability=self.high)
        AutomaticValidation.objects.create(triage=row, project=self.project, signature=row.signature,
            priority=0, status='failed', error='secret-provider-token', result={'check_state': 'no_check', 'ai_state': 'failed'})
        detail = finding_detail(Ctx(user), self.project.slug, 'vulnerability', self.high.pk)
        shown = detail['automatic_validation']
        self.assertEqual((shown['status'], shown['priority'], shown['ai_state']), ('failed', 0, 'failed'))
        self.assertNotIn('secret-provider-token', str(shown))


class EveryMatchIsValidatedTests(TestCase):
    """A CVE match of any confidence is queued for validation by itself, hottest first; the cold ones (Ice) only use what Fire and
    Smoke leave, and are not allowed to fill a project's slots."""

    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Ice', slug='ice')
        self.project = Project.objects.create(name='Ice', slug='ice', org=org, insert_date=now)
        domain = Domain.objects.create(name='ice.example', project=self.project, insert_date=now)
        self.sub = Subdomain.objects.create(name='www.ice.example', target_domain=domain)

        def match(cve_id, cvss, **fields):
            entry = CVEEntry.objects.create(cve_id=cve_id, cvss=cvss, affected=[{'product': 'nginx'}], published_at=now)
            return CVEMatch.objects.create(cve_entry=entry, subdomain=self.sub, matched_product='nginx', **fields)
        self.fire = match('CVE-2099-10', 9.8)
        self.smoke = match('CVE-2099-11', 7.5)
        self.cold = match('CVE-2099-12', 4.3)
        self.unscored = match('CVE-2099-13', None)
        self.ruled_out = match('CVE-2099-14', 3.0, ai_verdict='not_affected')
        self.patched = match('CVE-2099-15', 3.1, distro_status='patched')
        triage.track([self.fire, self.smoke, self.cold, self.unscored, self.ruled_out, self.patched])

    def sweep(self, **kwargs):
        calls = []
        record = lambda *a, **kw: calls.append(kw['priority'])  # noqa: E731
        with mock.patch('cveFeed.hot_validation._backfill_projects', return_value=0), \
                mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async', side_effect=record), \
                mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async', side_effect=record):
            return hot_validation.sweep(**kwargs), calls

    def queued(self):
        return {j.match.cve_entry.cve_id: j.priority for j in OnDemandValidation.objects.filter(status='queued').select_related('match__cve_entry')}

    def test_every_match_of_any_confidence_is_queued_hottest_first(self):
        result, calls = self.sweep()
        self.assertEqual((result['fire'], result['smoke'], result['ice']), (1, 1, 2))
        self.assertEqual(calls, [0, 6, 9, 9])
        self.assertEqual(self.queued(), {'CVE-2099-10': 0, 'CVE-2099-11': 6, 'CVE-2099-12': 9, 'CVE-2099-13': 9})  # the unscored one too

    def test_a_match_the_ai_ruled_out_or_the_distro_patched_is_not_validated(self):
        self.sweep()
        self.assertNotIn('CVE-2099-14', self.queued())
        self.assertNotIn('CVE-2099-15', self.queued())
        self.assertFalse(OnDemandValidation.objects.filter(match__in=[self.ruled_out, self.patched]).exists())

    def test_a_second_sweep_queues_nothing_again(self):
        self.sweep()
        result, calls = self.sweep()
        self.assertEqual((result['fire'], result['smoke'], result['ice'], calls), (0, 0, 0, []))
        self.assertEqual(OnDemandValidation.objects.count(), 4)

    def test_ice_only_uses_the_capacity_fire_and_smoke_leave(self):
        result, _ = self.sweep(max_jobs=2)
        self.assertEqual((result['fire'], result['smoke'], result['ice']), (1, 1, 0))  # the cold ones wait: no capacity left
        result, _ = self.sweep(max_jobs=1)
        self.assertEqual(result['ice'], 1)  # each later sweep carries on with the cold matches
        result, _ = self.sweep(max_jobs=1)
        self.assertEqual(result['ice'], 1)
        self.assertEqual(OnDemandValidation.objects.filter(status='queued').count(), 4)

    def test_ice_stops_at_a_lower_project_cap_than_fire_and_smoke(self):
        cold = Triage.objects.get(match=self.cold)
        hot = Triage.objects.get(match=self.fire)
        with mock.patch('cveFeed.hot_validation._active_count', return_value=hot_validation.PROJECT_ICE_CAP), \
                mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            self.assertEqual(hot_validation.enqueue(cold, 'ice'), 'project_cap')
            self.assertEqual(hot_validation.enqueue(hot, 'fire'), 'queued')  # five cold jobs never block a Fire one

    def test_a_queued_ice_job_moves_up_when_the_cve_gets_hot(self):
        row = Triage.objects.get(match=self.cold)
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(row, 'ice'), 'queued')
            entry = self.cold.cve_entry
            entry.cvss = 8.1
            entry.save(update_fields=['cvss'])
            self.assertEqual(hot_validation.enqueue(row, 'smoke'), 'promoted')
        self.assertEqual([c.kwargs['priority'] for c in dispatch.call_args_list], [9, 6])
        self.assertEqual(OnDemandValidation.objects.get(match=self.cold).priority, 6)
        self.assertEqual(OnDemandValidation.objects.filter(match=self.cold).count(), 1)

    def test_a_scanner_finding_is_never_an_ice_job(self):
        vuln = Vulnerability.objects.create(name='Low observation', severity=1, source='bbot', subdomain=self.sub, target_domain=self.sub.target_domain)
        triage.track([vuln])
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(Triage.objects.get(vulnerability=vuln), 'ice'), 'stale')
        dispatch.assert_not_called()

    def test_it_can_be_switched_off(self):
        for value in ('0', 'false', 'no', 'off'):
            OnDemandValidation.objects.all().delete()
            with mock.patch.dict('os.environ', {'CVENGINE_AUTO_VALIDATE_ALL_MATCHES': value}):
                result, calls = self.sweep()
            self.assertEqual((result['ice'], calls), (0, [0, 6]), value)  # Fire and Smoke exactly as before
            self.assertEqual(set(self.queued()), {'CVE-2099-10', 'CVE-2099-11'})
        self.assertTrue(hot_validation.validate_all_matches())  # on by default
