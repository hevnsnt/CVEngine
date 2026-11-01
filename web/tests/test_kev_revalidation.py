"""Issue 338: a KEV match was validated again after every rescan (83 validations of one finding in six days, three AI calls each).

The sequence behind it: a template run writes ``validated_at``/``updated_at`` on every Triage row of the CVE on the host, the rows of
superseded matches included; the rescan's new rows then took the twin with the newest ``updated_at`` (an old match), ``carried_from``
pointed at an old job that was stale, and ``enqueue`` only looked at the row's own inherited validation when there was no carried job
at all. A validation also moved its own match's signature (the probe results it stores are part of it), so the same match was queued
once more."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import hot_validation, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, OnDemandValidation, Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='K', slug='k')
        self.project = Project.objects.create(name='K', slug='k', org=self.org, insert_date=now)
        self.domain = Domain.objects.create(name='k.example', project=self.project, insert_date=now)
        self.engine = EngineType.objects.create(engine_name='full', yaml_configuration='x')
        self.kev = CVEEntry.objects.create(cve_id='CVE-2099-338', cvss=9.8, kev=True, affected=[{'product': 'nginx'}], published_at=now)

    def scan(self):
        """A finished full scan, newer than every scan made before it: the earlier scans' matches are superseded."""
        return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2)

    def match(self, scan, source='port', version='1.18.0', cve=None, name='www.k.example'):
        sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
        return CVEMatch.objects.create(cve_entry=cve or self.kev, subdomain=sub, matched_product='nginx', matched_version=version,
                                       source=source, version_in_range=True)

    def track(self, *matches):
        loaded = CVEMatch.objects.filter(pk__in=[m.pk for m in matches]).select_related('subdomain__target_domain')
        return [row for row, _ in triage.track(triage.with_cves(list(loaded)))]

    def enqueue(self, row, lane='fire'):
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            return hot_validation.enqueue(Triage.objects.get(pk=row.pk), lane), dispatch

    def template_run(self, vulnerable=False):
        outcome = {'host': 'www.k.example', 'vulnerable': vulnerable, 'output': ''}
        return validation.record_template_outcomes(self.kev, [outcome], self.project.id, '/t/cve-2099-338.yaml')


class RescanSequenceTests(Base):
    def history(self):
        """Three scans of one host. Each match had its validation job, finished with the AI unavailable (so it counts for one day only)."""
        self.scan1, self.scan2 = self.scan(), None
        self.a0 = self.match(self.scan1)
        (row0,) = self.track(self.a0)
        Triage.objects.filter(pk=row0.pk).update(status='not_triaged', classification='likely', validation_status='clean',
                                                 validated_at=timezone.now() - timedelta(days=6))
        OnDemandValidation.objects.create(match=self.a0, project=self.project, status='completed', evidence_signature='x',
                                          result={'ai_state': 'unavailable'}, finished_at=timezone.now() - timedelta(days=5))
        self.scan2 = self.scan()
        self.a = self.match(self.scan2)
        (row,) = self.track(self.a)
        OnDemandValidation.objects.create(match=self.a, project=self.project, status='completed', evidence_signature='x',
                                          result={'ai_state': 'unavailable'}, finished_at=timezone.now() - timedelta(days=2))
        return row0, row

    def test_a_rescan_after_a_template_run_inherits_the_fresh_validation_and_queues_nothing(self):
        row0, row = self.history()
        self.assertEqual(row.carried_from, self.a0.pk)  # scan 2's row took the record of scan 1's
        self.template_run()  # the template says clean on the host: every row of the CVE on it is a validation step now
        # production writes the rows in whatever order the database returns them: the superseded match's row came out last and is
        # the newest by updated_at, which is what the twin lookup used to rank on
        Triage.objects.filter(match=self.a0).update(updated_at=timezone.now() + timedelta(seconds=5))
        scan3 = self.scan()
        b = self.match(scan3)
        (row_b,) = self.track(b)
        self.assertEqual((row_b.validation_status, row_b.status), ('clean', 'not_triaged'))
        self.assertGreater(row_b.validated_at, timezone.now() - timedelta(minutes=5))
        outcome, dispatch = self.enqueue(row_b)
        self.assertEqual(outcome, 'fresh')
        dispatch.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.filter(match=b).exists())

    def test_the_twin_is_the_row_of_the_newest_match_not_the_one_touched_last(self):
        row0, row = self.history()
        Triage.objects.filter(match=self.a0).update(updated_at=timezone.now() + timedelta(seconds=5))
        b = self.match(self.scan())
        (row_b,) = self.track(b)
        self.assertEqual(row_b.carried_from, self.a.pk)

    def test_the_twin_does_not_cross_a_version_or_a_source(self):
        row0, row = self.history()
        newer_version = self.match(self.scan(), version='1.18.1')
        (row_v,) = self.track(newer_version)
        self.assertIsNone(row_v.carried_from)
        other_source = self.match(self.scan(), source='tech')
        (row_s,) = self.track(other_source)
        self.assertIsNone(row_s.carried_from)

    def test_a_stale_carried_job_does_not_hide_the_rows_own_fresh_validation(self):
        row0, row = self.history()
        Triage.objects.filter(pk=row.pk).update(validation_status='clean', validated_at=timezone.now() - timedelta(hours=3))
        scan3 = self.scan()
        b = self.match(scan3)
        (row_b,) = self.track(b)
        self.assertEqual(row_b.carried_from, self.a.pk)
        self.assertEqual(self.enqueue(row_b)[0], 'fresh')

    def test_a_stale_carried_job_and_a_stale_validation_still_validate_again(self):
        row0, row = self.history()
        Triage.objects.filter(pk=row.pk).update(validation_status='clean', validated_at=timezone.now() - timedelta(days=3))
        b = self.match(self.scan())
        (row_b,) = self.track(b)
        outcome, dispatch = self.enqueue(row_b)
        self.assertEqual(outcome, 'queued')
        dispatch.assert_called_once()

    def test_a_template_run_writes_only_the_rows_of_current_matches(self):
        row0, row = self.history()
        before = Triage.objects.get(pk=row0.pk)
        self.assertEqual(self.template_run(), 1)
        after = Triage.objects.get(pk=row0.pk)
        self.assertEqual((after.updated_at, after.validated_at), (before.updated_at, before.validated_at))  # scan 1's match: untouched
        self.assertEqual(Triage.objects.get(pk=row.pk).validation_steps[-1]['kind'], 'nuclei_template')
        self.assertEqual(Triage.objects.get(pk=row0.pk).validation_steps, [])

    def test_a_template_hit_still_confirms_the_current_match(self):
        row0, row = self.history()
        outcome = {'host': 'www.k.example', 'vulnerable': True, 'output': '{}', 'hit': {'matcher-name': 'm', 'matched-at': 'https://www.k.example/'}}
        with mock.patch('cveFeed.validation._record_template_hit'):
            validation.record_template_outcomes(self.kev, [outcome], self.project.id, '/t/cve-2099-338.yaml')
        self.assertEqual(Triage.objects.get(pk=row.pk).validation_status, 'hit')


class SupersededMatchTests(Base):
    def test_a_superseded_match_is_not_queued(self):
        first = self.scan()
        old = self.match(first)
        (row,) = self.track(old)
        self.match(self.scan())  # scan 2 replaced the host row
        outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'stale')
        dispatch.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.filter(match=old).exists())

    def test_a_current_match_is_queued(self):
        old = self.match(self.scan())
        (row,) = self.track(old)
        self.assertEqual(self.enqueue(row)[0], 'queued')

    def _run_task(self, job, supersede_during):
        from cveFeed.tasks import validate_match_on_demand
        plan = {'check_kinds': [], 'reason': 'no check', 'generate_template': False, 'source': 'test'}

        def planned(*args, **kwargs):
            supersede_during()
            return plan, None
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.k.example']), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
                mock.patch('cveFeed.validation_plan.plan', side_effect=planned) as planning, \
                mock.patch('cveFeed.validation.run_validation', return_value={}) as checks, \
                mock.patch('cveFeed.triage.run_triage', return_value={}) as review:
            result = validate_match_on_demand(job.pk)
        return result, planning, checks, review

    def test_a_match_replaced_while_it_was_planned_runs_no_check_and_no_review(self):
        match = self.match(self.scan())
        (row,) = self.track(match)
        job = OnDemandValidation.objects.create(match=match, project=self.project, evidence_signature=row.signature, priority=0)
        result, planning, checks, review = self._run_task(job, lambda: self.match(self.scan()))
        self.assertEqual(result['reason'], 'historical')
        checks.assert_not_called()
        review.assert_not_called()
        self.assertEqual(OnDemandValidation.objects.get(pk=job.pk).status, 'skipped')

    def test_a_current_match_runs_to_the_end(self):
        match = self.match(self.scan())
        (row,) = self.track(match)
        job = OnDemandValidation.objects.create(match=match, project=self.project, evidence_signature=row.signature, priority=0)
        result, planning, checks, review = self._run_task(job, lambda: None)
        self.assertNotIn('reason', result)
        review.assert_called_once()
        self.assertEqual(OnDemandValidation.objects.get(pk=job.pk).status, 'completed')


class SignatureStabilityTests(Base):
    def test_a_validation_that_stores_probe_results_does_not_queue_its_own_match_again(self):
        """The probe results a validation stores are in the host context digest, which is part of the signature: the signature the job
        recorded before its checks was never the row's signature afterwards, so the next sweep took the finished job for another
        evidence's and queued the match once more (jobs 4750 and 4752 of the report)."""
        from cveFeed.tasks import validate_match_on_demand
        match = self.match(self.scan())
        (row,) = self.track(match)
        stored = {'probes': False}

        def digest(context):
            return 'probe-stored' if stored['probes'] else ''

        def run(*args, **kwargs):
            stored['probes'] = True  # the fact probe wrote its result
            return {'ran': 1}
        job = OnDemandValidation.objects.create(match=match, project=self.project, evidence_signature=row.signature, priority=0)
        plan = {'check_kinds': [], 'reason': 'probe', 'generate_template': False, 'source': 'test'}
        with mock.patch('cveFeed.host_context.signal_digest', side_effect=digest), \
                mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.k.example']), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
                mock.patch('cveFeed.validation_plan.plan', return_value=(plan, None)), \
                mock.patch('cveFeed.validation.run_validation', side_effect=run), \
                mock.patch('cveFeed.triage.run_triage', return_value={}):
            validate_match_on_demand(job.pk)
            job.refresh_from_db()
            self.assertEqual(job.status, 'completed')
            row = Triage.objects.get(match=match)
            self.assertEqual(job.evidence_signature, row.signature)
            outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'fresh')
        dispatch.assert_not_called()
        self.assertEqual(OnDemandValidation.objects.filter(match=match).count(), 1)


class MinGapTests(Base):
    """At most one automatic validation per host, CVE, product and version in CVENGINE_VALIDATE_MIN_GAP_HOURS unless the evidence changed."""

    def finished(self, match, hours_ago, evidence=None, **fields):
        evidence = evidence if evidence is not None else triage.revalidation_key(triage.describe(CVEMatch.objects.select_related(
            'cve_entry', 'subdomain__target_domain').get(pk=match.pk)))
        return OnDemandValidation.objects.create(
            match=match, project=self.project, status=fields.pop('status', 'completed'), evidence_signature='x',
            result={'ai_state': 'completed', 'revalidation_key': evidence}, finished_at=timezone.now() - timedelta(hours=hours_ago), **fields)

    def setUp(self):
        super().setUp()
        self.first = self.match(self.scan())
        self.track(self.first)
        self.second = self.match(self.scan())  # the next scan's match of the same finding, which took nothing from the first
        (self.row,) = self.track(self.second)
        Triage.objects.filter(pk=self.row.pk).update(carried_from=None, validation_status='none', validated_at=None, status='pending')

    def test_a_validation_of_the_same_evidence_inside_the_gap_is_not_repeated(self):
        self.finished(self.second, 3)  # the job is of the very evidence the second match has (even on another match row)
        OnDemandValidation.objects.filter(match=self.second).update(match=self.first)
        outcome, dispatch = self.enqueue(self.row)
        self.assertEqual(outcome, 'min_gap')
        dispatch.assert_not_called()

    def test_it_is_repeated_once_the_gap_has_passed(self):
        self.finished(self.first, 13)
        self.assertEqual(self.enqueue(self.row)[0], 'queued')

    def test_changed_evidence_bypasses_it(self):
        self.finished(self.first, 3)
        self.kev.cvss = 8.1  # the feed's intelligence moved: part of the signature
        self.kev.save(update_fields=['cvss'])
        self.assertEqual(self.enqueue(self.row)[0], 'queued')

    def test_a_job_recorded_before_the_gap_existed_does_not_hold_anything_back(self):
        OnDemandValidation.objects.create(match=self.first, project=self.project, status='completed', evidence_signature='x',
                                          result={'ai_state': 'completed'}, finished_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(self.enqueue(self.row)[0], 'queued')

    def test_another_version_or_host_is_another_finding(self):
        self.finished(self.first, 3)
        other_version = self.match(self.scan(), version='1.18.1')
        (row_v,) = self.track(other_version)
        self.assertEqual(self.enqueue(row_v)[0], 'queued')

    def test_a_failed_job_is_left_to_its_backoff_not_the_gap(self):
        self.finished(self.first, 3, status='failed', next_attempt_at=timezone.now() - timedelta(minutes=1), attempts=2)
        self.assertEqual(self.enqueue(self.row)[0], 'queued')

    def test_the_gap_is_set_by_the_environment_and_zero_turns_it_off(self):
        self.finished(self.first, 3)
        with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MIN_GAP_HOURS': '0'}):
            self.assertEqual(self.enqueue(self.row)[0], 'queued')
        OnDemandValidation.objects.filter(status='queued').delete()
        with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MIN_GAP_HOURS': '2'}):
            self.assertEqual(self.enqueue(self.row)[0], 'queued')  # 3 hours ago is outside a 2 hour gap
        OnDemandValidation.objects.filter(status='queued').delete()
        with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MIN_GAP_HOURS': 'soon'}):
            self.assertEqual(self.enqueue(self.row)[0], 'min_gap')  # an unreadable value is the default, 12

    def test_a_manual_revalidation_always_runs(self):
        from agentapi.services import Ctx, validate_match_now
        user = User.objects.create_user('alice', password='x')
        ProjectMembership.objects.create(user=user, project=self.project, role='user')
        self.finished(self.first, 1)
        self.assertEqual(self.enqueue(self.row)[0], 'min_gap')
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            body = validate_match_now(Ctx(user, None), self.project.slug, self.second.pk)
        self.assertEqual(body['status'], 'queued')
        dispatch.assert_called_once()
        job = OnDemandValidation.objects.get(pk=body['id'])
        self.assertEqual(job.source, 'manual')


class PostReviewKeyTests(Base):
    def test_the_key_a_job_records_describes_the_match_as_the_review_left_it(self):
        """The review writes the match's ai_verdict, and an edge-verified host's closure basis reads it (``has_standing``): a key made from the
        match as it was before the review never equals the one the next enqueue makes from the database, and the gap never held."""
        from cveFeed.tasks import validate_match_on_demand
        match = self.match(self.scan(), source='tech')
        (row,) = self.track(match)
        job = OnDemandValidation.objects.create(match=match, project=self.project, evidence_signature=row.signature, priority=0)
        plan = {'check_kinds': [], 'reason': 'edge', 'generate_template': False, 'source': 'test'}
        edge = {'fronted': True, 'verified': True, 'providers': ['cloudflare'], 'basis': ['cname']}

        def review(rows):
            CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='affected')  # the AI answered: confirmed
            return {}
        digest = {'value': ''}
        with mock.patch('cveFeed.host_context.edge_of', return_value=edge), \
                mock.patch('cveFeed.host_context.signal_digest', side_effect=lambda context: digest['value']), \
                mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.k.example']), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
                mock.patch('cveFeed.validation_plan.plan', return_value=(plan, None)), \
                mock.patch('cveFeed.validation.run_validation', return_value={}), \
                mock.patch('cveFeed.triage.run_triage', side_effect=review):
            validate_match_on_demand(job.pk)
            self.assertEqual(OnDemandValidation.objects.get(pk=job.pk).status, 'completed')
            self.assertEqual(CVEMatch.objects.get(pk=match.pk).ai_verdict, 'affected')
            digest['value'] = 'a-later-probe'  # the host context moved: the row is re-tracked under a new signature, the evidence is the same
            (row,) = self.track(CVEMatch.objects.get(pk=match.pk))
            self.assertNotEqual(row.signature, OnDemandValidation.objects.get(pk=job.pk).evidence_signature)
            outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'min_gap')
        dispatch.assert_not_called()
