"""Issue 338: a KEV match was validated again after every rescan (83 validations of one finding in six days, three AI calls each).

The sequence behind it: a template run writes ``validated_at``/``updated_at`` on every Triage row of the CVE on the host, the rows of
superseded matches included; the rescan's new rows then took the twin with the newest ``updated_at`` (an old match), ``carried_from``
pointed at an old job that was stale, and ``enqueue`` only looked at the row's own inherited validation when there was no carried job
at all. A validation also moved its own match's signature (the probe results it stores are part of it), so the same match was queued
once more."""
import json
import types
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import host_context, hot_validation, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, OnDemandValidation, ProbeObservation, TlsCertificate, Triage, TriageCall, TriageVerdict
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


class ReportTimelineTests(Base):
    """The report's 31/10 sequence end to end, with the port match and the tech match of the CVE on the one host: scan 82 (22:46), the
    re-test scan 83 whose matches exist before their Triage rows (23:03), the negative template run in between (23:04:39), the rows of
    scan 83 made a second later, then the Fire sweeps (23:05, 23:10, 23:30) and the next rescan."""

    def pair(self, scan):
        sub = Subdomain.objects.create(name='www.k.example', target_domain=self.domain, scan_history=scan)
        return [CVEMatch.objects.create(cve_entry=self.kev, subdomain=sub, matched_product='nginx', matched_version='1.18.0', source=source,
                                        version_in_range=True) for source in ('port', 'tech')]

    def track(self, *matches):
        return sorted(super().track(*matches), key=lambda row: row.match_id)  # in the order the matches were made: port, then tech

    def retest(self, finished=True):
        """A change-triggered re-test of the host (a host-pipeline scan): its rows replace the host's rows once it has finished."""
        return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(),
                                          scan_status=2 if finished else 1, tasks=['host_pipeline'])

    def setUp(self):
        super().setUp()
        self.old = self.pair(self.scan())  # 28/10 (matches 8398 and 7723): validated while the AI was off, so their jobs count one day
        rows = self.track(*self.old)
        Triage.objects.filter(pk__in=[r.pk for r in rows]).update(status='not_triaged', classification='likely', validation_status='clean',
                                                                  validated_at=timezone.now() - timedelta(days=3))
        for match in self.old:
            OnDemandValidation.objects.create(match=match, project=self.project, status='completed', evidence_signature='x',
                                              result={'ai_state': 'unavailable'}, finished_at=timezone.now() - timedelta(days=3))
        self.scan82 = self.pair(self.scan())  # 9281 and 9270
        self.rows82 = self.track(*self.scan82)
        self.assertEqual([r.carried_from for r in self.rows82], [m.pk for m in self.old])

    def run_job(self, job):
        """The validation task, with the fact probe storing a result that moves the row's signature (what queued #4752 after #4750)."""
        from cveFeed.tasks import validate_match_on_demand
        stored = {'probes': False}

        def run(*args, **kwargs):
            stored['probes'] = True
            return {'ran': 1}
        plan = {'check_kinds': [], 'reason': 'probe', 'generate_template': False, 'source': 'test'}
        with mock.patch('cveFeed.host_context.signal_digest', side_effect=lambda context: 'probe-stored' if stored['probes'] else ''), \
                mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.k.example']), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
                mock.patch('cveFeed.validation_plan.plan', return_value=(plan, None)), \
                mock.patch('cveFeed.validation.run_validation', side_effect=run), \
                mock.patch('cveFeed.triage.run_triage', return_value={}):
            validate_match_on_demand(job.pk)
            # the next sweeps read the row as the probe left it
            return [self.enqueue(Triage.objects.get(match_id=job.match_id))[0] for _ in range(2)]

    def test_the_template_run_before_the_rows_of_the_retest_exist(self):
        """Scan 83 finished before the template ran: the template run writes no superseded row, scan 82's matches are not validated, each
        of scan 83's is validated once (the signature its own probe moved does not queue it again), and the next rescan validates nothing."""
        scan83 = self.pair(self.retest())  # 9305 and 9294, no Triage rows yet
        stamps = dict(Triage.objects.values_list('pk', 'updated_at'))
        self.assertEqual(self.template_run(), 0)  # the only current matches have no row yet; the rows of older matches stay as they were
        self.assertEqual(dict(Triage.objects.values_list('pk', 'updated_at')), stamps)
        rows83 = self.track(*scan83)
        self.assertEqual([r.carried_from for r in rows83], [m.pk for m in self.scan82])  # not 8398 and 7723

        for row in self.rows82:  # 23:05, #4750 and #4751: the matches scan 83 had just replaced
            outcome, dispatch = self.enqueue(row)
            self.assertEqual(outcome, 'stale')
            dispatch.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.filter(match__in=self.scan82).exists())

        for row in rows83:  # one validation of each finding of the current scan, then nothing more
            self.assertEqual(self.enqueue(row)[0], 'queued')
            self.assertEqual(self.enqueue(row)[0], 'inflight')
            job = OnDemandValidation.objects.get(match_id=row.match_id)
            self.assertEqual(self.run_job(job), ['fresh', 'fresh'])
            self.assertEqual(OnDemandValidation.objects.get(pk=job.pk).status, 'completed')
        self.assertEqual(OnDemandValidation.objects.filter(match__in=scan83).count(), 2)

        scan84 = self.pair(self.retest())  # the next rescan of an unchanged host
        rows84 = self.track(*scan84)
        self.assertEqual([r.carried_from for r in rows84], [m.pk for m in scan83])
        self.assertEqual([self.enqueue(r)[0] for r in rows84], ['fresh', 'fresh'])
        self.assertFalse(OnDemandValidation.objects.filter(match__in=scan84).exists())

    def test_the_template_run_while_the_retest_is_still_running(self):
        """The template ran while scan 83 was still running: scan 82's rows were the current ones and took its result, and scan 83's rows,
        made once it finished, inherit that validation of a minute ago although the job of the match before (28/10) is stale."""
        retest = self.retest(finished=False)
        scan83 = self.pair(retest)
        self.assertEqual(self.template_run(), 2)
        self.assertEqual(Triage.objects.filter(match__in=self.old, validated_at__gt=timezone.now() - timedelta(hours=1)).count(), 0)
        ScanHistory.objects.filter(pk=retest.pk).update(scan_status=2)
        rows83 = self.track(*scan83)
        self.assertEqual([r.carried_from for r in rows83], [m.pk for m in self.scan82])
        for row in rows83:
            self.assertGreater(row.validated_at, timezone.now() - timedelta(minutes=5))
            outcome, dispatch = self.enqueue(row)
            self.assertEqual(outcome, 'fresh')
            dispatch.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.exclude(match__in=self.old).exists())


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


class ManualJobKeyTests(Base):
    """A manual job counts as standing (``match_policy.has_standing``) once it is no longer running, and an edge-verified host's closure basis
    reads that. The key and the signature the job recorded were made while it still ran, so they described the match as clearable by the edge;
    the ones ``enqueue`` and ``track`` make from the database (the job finished by then) did not: the minimum gap failed open, the job was never
    taken for the evidence the row had, and the match was reviewed and validated again."""

    def run_manual_job(self, review, match=None, attempts=0, describe_hook=None, status='completed'):
        from cveFeed.tasks import validate_match_on_demand
        default_match = match is None
        match = match or self.match(self.scan(), source='tech')
        (row,) = self.track(match)
        user = User.objects.create_user('bob', password='x')
        ProjectMembership.objects.create(user=user, project=self.project, role='user')
        job = OnDemandValidation.objects.create(match=match, project=self.project, evidence_signature=row.signature, priority=0,
                                                source='manual', requested_by=user, attempts=attempts)
        plan = {'check_kinds': [], 'reason': 'edge', 'generate_template': False, 'source': 'test'}
        edge = {'fronted': True, 'verified': True, 'providers': ['cloudflare'], 'basis': ['cname']}
        patches = [mock.patch('cveFeed.host_context.edge_of', return_value=edge),
                   mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.k.example']),
                   mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''),
                   mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')),
                   mock.patch('cveFeed.validation_plan.plan', return_value=(plan, None)),
                   mock.patch('cveFeed.validation.run_validation', return_value={}),
                   mock.patch('cveFeed.triage.run_triage', side_effect=review)]
        if describe_hook:
            real = triage.describe

            def describe(finding):
                describe_hook(finding)
                return real(finding)
            patches.append(mock.patch('cveFeed.triage.describe', side_effect=describe))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        OnDemandValidation.objects.filter(pk=job.pk).update(status='running')
        if default_match and not describe_hook:
            running = triage.describe(triage.with_cves([CVEMatch.objects.get(pk=match.pk)])[0])
            self.assertEqual(running['facts']['closure_basis'], ['cdn_edge_only'])  # while it runs, the edge may clear the match
        OnDemandValidation.objects.filter(pk=job.pk).update(status='queued')
        validate_match_on_demand(job.pk)
        job.refresh_from_db()
        self.assertEqual((job.status, job.source), (status, 'manual'))
        match = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)
        after = triage.describe(match)
        self.assertEqual(after['facts']['closure_basis'], [])  # the finished manual job vouches for the match: the state the job has to describe
        self.assertEqual(job.result['revalidation_key'], triage.revalidation_key(after))
        if not describe_hook:
            self.assertEqual(job.evidence_signature, triage.effective_signature(after, Triage.objects.get(match=match).review_nonce))
        return match, job

    def answer(self, classification):
        def review(rows):
            for row, d in rows:
                verdict = TriageVerdict.objects.create(kind='cve_match', signature=d['signature'], classification=classification)
                Triage.objects.filter(pk=row.pk).update(status='triaged', verdict=verdict, classification=classification)
            return {}
        return review

    def test_a_manual_validation_of_an_edge_fronted_match_holds_the_gap_for_the_next_automatic_one(self):
        match, job = self.run_manual_job(lambda rows: {})
        (row,) = self.track(match)
        self.assertEqual(row.signature, job.evidence_signature)
        # not 'fresh' (the job is of this evidence) is what the signature gives; the gap is what is asked when it is not
        Triage.objects.filter(pk=row.pk).update(signature='moved')
        outcome, dispatch = self.enqueue(Triage.objects.get(pk=row.pk))
        self.assertEqual(outcome, 'min_gap')
        dispatch.assert_not_called()
        self.assertEqual(OnDemandValidation.objects.filter(match=match).count(), 1)

    def test_the_job_is_taken_for_the_evidence_the_row_has_so_nothing_is_validated_again(self):
        match, job = self.run_manual_job(self.answer('likely'))
        (row,) = self.track(match)
        self.assertEqual((row.status, row.classification, row.signature), ('triaged', 'likely', job.evidence_signature))
        outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'fresh')
        dispatch.assert_not_called()
        # a row that is triaged under its current signature is not queued for the review (run_triage and the sweep only take pending rows)
        self.assertFalse(Triage.objects.filter(status__in=('pending', 'error', 'not_triaged')).exists())
        self.assertEqual(OnDemandValidation.objects.filter(match=match).count(), 1)

    def test_an_answer_below_the_floor_the_finished_job_leaves_is_asked_again(self):
        """The review ran while the edge could clear the match. The finished job gives the match standing and the in-range floor applies: an answer
        that said it was cleared is not carried over under the new signature."""
        match, job = self.run_manual_job(self.answer('likely_false_positive'))
        (row,) = self.track(match)
        self.assertEqual((row.status, row.classification), ('pending', 'likely_false_positive'))  # queued again, the record kept meanwhile
        self.assertEqual(row.signature, job.evidence_signature)


    # Only the job's own standing (``closure_basis``) is absorbed into the row's signature when the job ends. Whatever else moved while the checks
    # and the review ran is tracked as a change, as it always was.

    def test_a_floor_lowered_during_the_review_is_not_left_confirmed(self):
        match = self.match(self.scan(), source='tech')
        CVEMatch.objects.filter(pk=match.pk).update(template_result='vulnerable')  # the floor is 'confirmed'
        answer = self.answer('confirmed')

        def review(rows):
            answer(rows)
            CVEMatch.objects.filter(pk=match.pk).update(template_result='')  # a later template run found it clean while the review ran
            return {}
        match, job = self.run_manual_job(review, match=CVEMatch.objects.get(pk=match.pk))
        row = Triage.objects.get(match=match)
        self.assertEqual((row.status, row.classification, row.verdict_id), ('pending', '', None))  # reset: the evidence it rested on is gone
        self.assertEqual(row.signature, job.evidence_signature)

    def test_a_banner_that_changed_during_the_review_is_asked_about(self):
        cve = CVEEntry.objects.create(cve_id='CVE-2099-340', cvss=7.5, published_at=timezone.now(),
                                      affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
        match = CVEMatch.objects.create(cve_entry=cve, matched_product='nginx', matched_version='1.21.0', source='port', version_in_range=None,
                                        evidence={'branch_unlisted': True},
                                        subdomain=Subdomain.objects.create(name='www.k.example', target_domain=self.domain, scan_history=self.scan()))
        answer = self.answer('needs_validation')

        def review(rows):
            answer(rows)
            CVEMatch.objects.filter(pk=match.pk).update(evidence={'branch_unlisted': True, 'service_extra': 'nginx (a new banner)'})
            return {}
        match, job = self.run_manual_job(review, match=match)
        row = Triage.objects.get(match=match)
        self.assertEqual((row.status, row.classification, row.verdict_id is not None), ('pending', 'needs_validation', True))  # queued, record kept
        self.assertEqual(row.signature, job.evidence_signature)

    def test_a_failed_first_manual_job_on_an_edge_fronted_match_keeps_its_backoff(self):
        def review(rows):
            Triage.objects.filter(pk__in=[row.pk for row, _ in rows]).update(status='error')
            return {'errors': 1}
        match, job = self.run_manual_job(review, attempts=1, status='failed')
        self.assertEqual(job.status, 'failed')
        self.assertGreater(job.next_attempt_at, timezone.now())
        (row,) = self.track(match)
        self.assertEqual(row.signature, job.evidence_signature)  # one description of the evidence, not two
        outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'fresh')  # not queued again at once
        dispatch.assert_not_called()
        OnDemandValidation.objects.filter(pk=job.pk).update(next_attempt_at=timezone.now() - timedelta(minutes=1))
        outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'queued')
        self.assertEqual(OnDemandValidation.objects.filter(match=match).order_by('-id').first().attempts, 2)  # the attempt number goes on

    def test_a_fresh_review_requested_meanwhile_keeps_its_evidence_key(self):
        state = {}

        def hook(finding):
            if state.get('done') or OnDemandValidation.objects.filter(status='running').exists():
                return
            state['done'] = True  # the first description after the job left 'running': a person asks for a fresh review just now
            row = Triage.objects.get(match_id=finding.pk)
            triage.request_fresh_review(row, self.real_describe(finding), 'nonce-1')
        self.real_describe = triage.describe  # the hook runs inside the patched describe
        match, job = self.run_manual_job(self.answer('likely'), describe_hook=hook)
        row = Triage.objects.get(match=match)
        self.assertEqual(row.review_nonce, 'nonce-1')
        self.assertEqual(row.evidence_key, triage.evidence_key_for('cve_match', self.real_describe(match)['signature_fields'], 'nonce-1'))
        self.assertEqual((row.status, row.classification, row.verdict_id is not None), ('pending', 'likely', True))  # queued, the record kept (not reset)


class StableViewTests(TestCase):
    """``host_context.stable_view``: what the host text key of a match's signature is made from."""

    def context(self, **over):
        base = {'technologies': [{'name': 'nginx', 'version': '1.18.0', 'category': 'web', 'source': 'scan'}],
                'ports': [{'number': 443, 'product': 'nginx', 'version': '1.18.0', 'banner': ''}],
                'web': {'status': 200, 'title': 'x', 'kept_response_headers': ['server: nginx', 'content-type: text/html']},
                'certificates': [{'port': 443, 'issuer': 'R3', 'days_left': 90, 'protocol': 'TLSv1.3', 'legacy_tls': False, 'san_count': 2}],
                'probe_results': [{'probe': 'nginx-version', 'kind': 'version', 'product': 'nginx', 'version': '1.18.0', 'variant': '',
                                   'outcome': 'found', 'confidence': 0.9, 'source': 'header:server', 'port': 443, 'observed': '2026-10-01'}],
                'host_inventory': {'os': 'Ubuntu 22.04', 'kernel': '5.15', 'packages': 400, 'reported_at': '2026-10-01T10:00:00+00:00'},
                'tailscale': {'online': True, 'os': 'linux'}, 'other_cve_matches': [{'cve': 'CVE-2099-1', 'product': 'nginx', 'version': '1.18.0',
                                                                                      'in_range': True, 'verdict': ''}],
                'operating_system': {'guesses': [], 'reported_by_other_tools': {}}}
        return {**base, **over}

    def test_what_changes_while_the_host_does_not_is_left_out(self):
        today = self.context()
        later = self.context(
            certificates=[{'port': 443, 'issuer': 'R3', 'days_left': 61, 'protocol': 'TLSv1.3', 'legacy_tls': False, 'san_count': 2}],
            probe_results=[{**today['probe_results'][0], 'observed': '2026-10-30'}],
            host_inventory={'os': 'Ubuntu 22.04', 'kernel': '5.15', 'packages': 417, 'reported_at': '2026-10-30T09:00:00+00:00'},
            tailscale={'online': False, 'os': 'linux'},
            other_cve_matches=[{'cve': 'CVE-2099-1', 'product': 'nginx', 'version': '1.18.0', 'in_range': True, 'verdict': 'uncertain'}])
        self.assertNotEqual(today, later)
        self.assertEqual(host_context.stable_view(today), host_context.stable_view(later))

    def test_what_the_review_conditions_on_is_kept(self):
        base = host_context.stable_view(self.context())
        probe = self.context()['probe_results'][0]
        changes = {
            'a probe found another version': {'probe_results': [{**probe, 'version': '1.18.1'}]},
            'a probe found the version hidden': {'probe_results': [{**probe, 'outcome': 'hidden'}]},
            'the banner changed': {'ports': [{'number': 443, 'product': 'nginx', 'version': '1.18.0', 'banner': 'nginx/1.18.0 (Ubuntu)'}]},
            'the kernel changed': {'host_inventory': {'os': 'Ubuntu 22.04', 'kernel': '6.1', 'packages': 400, 'reported_at': 'x'}},
            'the certificate issuer changed': {'certificates': [{'port': 443, 'issuer': 'Other CA', 'days_left': 90, 'protocol': 'TLSv1.3',
                                                                 'legacy_tls': False, 'san_count': 2}]},
            'TLS 1.0 is accepted': {'certificates': [{'port': 443, 'issuer': 'R3', 'days_left': 90, 'protocol': 'TLSv1.3',
                                                      'legacy_tls': True, 'san_count': 2}]},
            'a header changed': {'web': {'status': 200, 'title': 'x', 'kept_response_headers': ['server: Apache', 'content-type: text/html']}},
            'another CVE matches the host': {'other_cve_matches': [{'cve': 'CVE-2099-1', 'product': 'nginx', 'version': '1.18.0',
                                                                    'in_range': True, 'verdict': ''},
                                                                   {'cve': 'CVE-2099-2', 'product': 'nginx', 'version': '1.18.0',
                                                                    'in_range': True, 'verdict': ''}]},
            'a match is now inside the range': {'other_cve_matches': [{'cve': 'CVE-2099-1', 'product': 'nginx', 'version': '1.18.0',
                                                                       'in_range': False, 'verdict': ''}]},
            'a technology appeared': {'technologies': [{'name': 'php', 'version': '8.1', 'category': 'lang', 'source': 'scan'}]},
        }
        for what, change in changes.items():
            self.assertNotEqual(base, host_context.stable_view(self.context(**change)), what)

    def test_a_certificate_matters_when_it_expires_not_every_day_before_that(self):
        def state(days):
            return host_context.stable_view(self.context(certificates=[{'port': 443, 'issuer': 'R3', 'days_left': days, 'san_count': 2}]))
        self.assertEqual(state(90), state(31))
        self.assertEqual(state(29), state(1))
        self.assertEqual(state(-3), state(-200))
        self.assertEqual(len({str(state(90)), str(state(29)), str(state(-1))}), 3)
        self.assertNotEqual(state(None), state(90))  # no certificate date is not a valid certificate

    def test_the_order_rows_came_back_in_does_not_matter_where_the_rows_have_none(self):
        probes = [{'probe': 'a', 'kind': 'version', 'product': 'nginx', 'version': '1', 'outcome': 'found', 'observed': '2026-10-01'},
                  {'probe': 'b', 'kind': 'identity', 'product': 'nginx', 'version': '', 'outcome': 'absent', 'observed': '2026-10-02'}]
        certs = [{'port': 443, 'issuer': 'R3', 'days_left': 5}, {'port': 8443, 'issuer': 'R3', 'days_left': 6}]
        ports = [{'number': 80, 'product': 'a', 'banner': 'x'}, {'number': 80, 'product': 'b', 'banner': 'y'}, {'number': 22, 'product': 'ssh'}]
        one = host_context.stable_view(self.context(probe_results=probes, certificates=certs, ports=ports))
        two = host_context.stable_view(self.context(probe_results=probes[::-1], certificates=certs[::-1], ports=ports[::-1]))
        self.assertEqual(one, two)

    def test_per_request_headers_keep_their_presence_and_lose_their_value(self):
        def headers(*lines):
            return host_context.stable_view(self.context(web={'kept_response_headers': list(lines)}))
        self.assertEqual(headers('server: cloudflare', 'cf-ray: 8a1b2c3d-AMS', 'cf-cache-status: HIT', 'x-request-id: abc'),
                         headers('server: cloudflare', 'cf-ray: 99ffee00-FRA', 'cf-cache-status: MISS', 'x-request-id: def'))
        self.assertNotEqual(headers('server: cloudflare', 'cf-ray: 1'), headers('server: cloudflare'))  # the edge header being there is evidence
        self.assertNotEqual(headers('server: nginx'), headers('server: Apache'))
        policy = "content-security-policy: script-src 'nonce-{}' 'self'"
        self.assertEqual(headers(policy.format('AbC123+/=')), headers(policy.format('zzz999')))
        self.assertNotEqual(headers(policy.format('x')), headers("content-security-policy: script-src 'self' evil.example"))

    def test_a_time_of_day_in_a_banner_is_not_evidence(self):
        def banner(text):
            return host_context.stable_view(self.context(ports=[{'number': 25, 'banner': text}]))
        self.assertEqual(banner('220 mail ESMTP Postfix 10:15:32'), banner('220 mail ESMTP Postfix 23:59:01'))
        self.assertNotEqual(banner('220 mail ESMTP Postfix'), banner('220 mail ESMTP Exim'))

    def test_a_context_with_none_of_it_is_returned_as_it_is(self):
        plain = {'technologies': [{'name': 'nginx', 'version': '1.18.0'}], 'ports': [{'number': 22}, {'number': 443}],
                 'web': {'status': 200, 'kept_response_headers': ['server: nginx']}, 'labels': ['a'], 'certificates': [],
                 'probe_results': [], 'host_inventory': None, 'tailscale': None}
        self.assertEqual(host_context.stable_view(plain), plain)
        self.assertEqual(host_context.stable_view(None), None)
        self.assertEqual(host_context.stable_view({}), {})


class HostTextSignatureTests(Base):
    """Issue 338 follow-up: ``triage.bind_host_text`` keyed the verdict of every match without a floor to the whole host context, so
    a certificate's days left or a probe's observed date moved the signature daily and every rescan asked the model the same question again."""

    def setUp(self):
        super().setUp()
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-339', cvss=7.5, affected=[{'product': 'nginx', 'ranges': [
            {'introduced': '1.0.0', 'fixed': '1.20.0'}]}], published_at=timezone.now())
        self.host = 'www.k.example'

    def floorless(self, scan=None):
        """A match with no hard evidence floor (the version is not inside the range), so its verdict is keyed to the host text."""
        sub = Subdomain.objects.create(name=self.host, target_domain=self.domain, scan_history=scan or self.scan())
        return CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.21.0', source='port',
                                       version_in_range=None, evidence={'branch_unlisted': True})  # a candidate, not closed for want of a bound

    def describe(self, match):
        return triage.describe(triage.with_cves([CVEMatch.objects.get(pk=match.pk)])[0])

    def certificate(self, days, issuer='R3'):
        # days is far from a band edge, so the second a test takes cannot matter
        TlsCertificate.objects.update_or_create(domain=self.domain, host=self.host, port=443, defaults={
            'issuer': issuer, 'not_after': timezone.now() + timedelta(days=days, hours=12)})

    def probe(self, observed_days_ago, outcome='found', version='1.21.0'):
        ProbeObservation.objects.update_or_create(project=self.project, domain=self.domain, host=self.host, probe='nginx-version', port=443,
                                                  kind='version', product='nginx', defaults={
            'version': version, 'outcome': outcome, 'confidence': 0.9, 'source': 'header:server',
            'observed_at': timezone.now() - timedelta(days=observed_days_ago)})

    def test_only_a_match_without_a_floor_has_the_key(self):
        self.assertIn('host_text', self.describe(self.floorless())['signature_fields'])

    def test_the_same_host_a_day_later_has_the_same_signature(self):
        match = self.floorless()
        self.certificate(100)
        self.probe(3)
        before = self.describe(match)
        self.assertIn('context', before['signature_fields'])  # the probe is in the signature too (its digest does not hold the date)
        self.assertEqual(before['host_context']['certificates'][0]['expiry'], 'valid')  # the model is shown what the key is made of
        self.certificate(99)
        self.probe(0)
        after = self.describe(match)
        self.assertEqual(before['host_context'], after['host_context'])
        self.assertEqual(before['signature'], after['signature'])
        self.assertEqual(before['evidence_key'], after['evidence_key'])

    def test_evidence_that_changes_still_changes_the_signature(self):
        match = self.floorless()
        self.certificate(100)
        self.probe(3)
        base = self.describe(match)['signature']
        seen = {base}
        self.certificate(10)  # now expiring
        seen.add(self.describe(match)['signature'])
        self.certificate(-5)  # expired
        seen.add(self.describe(match)['signature'])
        self.certificate(100, issuer='Other CA')
        seen.add(self.describe(match)['signature'])
        self.certificate(100)
        self.probe(0, outcome='hidden')
        seen.add(self.describe(match)['signature'])
        self.probe(0, version='1.22.0')
        seen.add(self.describe(match)['signature'])
        self.assertEqual(len(seen), 6)

    def test_a_host_with_nothing_volatile_keeps_the_key_it_always_had(self):
        """The first deploy of the new definition re-asks nothing for a host whose context has no date or counter in it: the key is made
        from the context exactly as before."""
        import hashlib
        import json
        match = self.floorless()
        d = self.describe(match)
        text = [d['payload'].get('cpe'), d['payload'].get('service_extra'), d['host_context']]
        legacy = hashlib.sha1(json.dumps(text, sort_keys=True, default=str).encode()).hexdigest()[:16]
        self.assertEqual(d['signature_fields']['host_text'], legacy)

    def reviewed_row(self, match, provider):
        (row, d), = triage.track(triage.with_cves([match]))
        triage.run_triage([(row, d)], provider=provider)
        row.refresh_from_db()
        self.assertEqual((row.status, bool(row.classification)), ('triaged', True))
        self.kept = row.classification  # whatever the rules made of the answer: the record that has to survive a re-review
        return row

    def provider(self):
        import json
        answer = {'classification': 'likely', 'reason': 'because', 'impact': 'bad', 'severity_adjust': 0, 'severity_reason': '',
                  'remediation': 'patch', 'validation_steps': []}
        provider = mock.Mock(model='m')
        provider.name = 'anthropic'
        provider.complete.return_value = json.dumps(answer)
        return provider

    def test_a_rescan_a_day_later_asks_the_model_nothing(self):
        self.certificate(100)
        self.probe(3)
        provider = self.provider()
        first = self.floorless()
        row = self.reviewed_row(first, provider)
        self.assertEqual(provider.complete.call_count, 1)
        self.certificate(99)
        self.probe(0)
        second = self.floorless()  # the rescan's match: a new row, which takes the record of the first (issue 206)
        (row2, d2), = triage.track(triage.with_cves([second]))
        self.assertEqual((row2.status, row2.classification, row2.carried_from), ('triaged', self.kept, first.pk))
        self.assertEqual(row2.signature, row.signature)
        stats = triage.run_triage([(row2, d2)], provider=provider)
        self.assertEqual(provider.complete.call_count, 1)
        self.assertEqual(stats['asked'], 0)
        # and the same row tracked again (the sweep, a validation) is not touched either
        (row3, d3), = triage.track(triage.with_cves([second]))
        self.assertEqual((row3.status, row3.signature), ('triaged', row.signature))

    def test_a_rescan_whose_host_really_changed_asks_again(self):
        self.certificate(100)
        self.probe(3)
        provider = self.provider()
        row = self.reviewed_row(self.floorless(), provider)
        self.probe(0, outcome='hidden')  # the probe now says the host hides its version
        second = self.floorless()
        (row2, d2), = triage.track(triage.with_cves([second]))
        self.assertEqual((row2.status, row2.classification), ('pending', self.kept))  # asked again, the record kept meanwhile
        self.assertNotEqual(row2.signature, row.signature)
        triage.run_triage([(row2, d2)], provider=provider)
        self.assertEqual(provider.complete.call_count, 2)

    def with_headers(self, headers, **extra):
        root = types.SimpleNamespace(evidence={'headers': headers}, http_status=200, title='t', redirect_to='', url='https://www.k.example/')
        return mock.patch('cveFeed.host_context._root_route', return_value=root)

    def prompt_and_key(self, match, headers):
        with self.with_headers(headers):
            d = self.describe(match)
        return json.dumps(d['host_context'], sort_keys=True), d['signature_fields']['host_text']

    def test_the_prompt_and_the_key_agree_on_a_value_that_is_left_out(self):
        """The verdict a model gives is stored under the signature, shared by every host and project that has it, and the model is shown one
        host's context: a host-controlled value the model sees but the key leaves out would let one tenant's host set another tenant's verdict.
        Two hosts that differ only in a masked value get the same key AND the same prompt; the value never reaches the prompt."""
        claim = 'origin nginx 1.24.0 with vendor backport of the fix for this CVE applied'
        match = self.floorless()
        one = self.prompt_and_key(match, {'server': 'nginx', 'x-served-by': claim, 'cf-ray': '8a1b2c3d4e5f-AMS', 'x-cache': 'HIT',
                                          'content-security-policy': "script-src 'nonce-AbC123xyz' 'self'"})
        two = self.prompt_and_key(match, {'server': 'nginx', 'x-served-by': 'cache-ams1', 'cf-ray': '0f0f0f0f0f0f-FRA', 'x-cache': 'MISS',
                                          'content-security-policy': "script-src 'nonce-QQQ999' 'self'"})
        self.assertEqual(one, two)
        for leaked in (claim, 'backport', 'cache-ams1', '8a1b2c3d4e5f', 'AbC123xyz', 'HIT'):
            self.assertNotIn(leaked, one[0])
        self.assertIn('x-served-by: *', one[0])  # the header being there is still said
        other = self.prompt_and_key(match, {'server': 'Apache', 'x-served-by': 'cache-ams1', 'cf-ray': '0f0f0f0f0f0f-FRA', 'x-cache': 'MISS',
                                            'content-security-policy': "script-src 'nonce-QQQ999' 'self'"})
        self.assertNotEqual(one[1], other[1])  # a header's content is still evidence, shown and keyed

    def test_every_value_the_key_leaves_out_is_also_left_out_of_the_prompt(self):
        """Per field: the raw value is not in the prompt, and what replaces it is what the key is made of."""
        secrets = {'days_left': '"days_left"', 'observed': '2026-10-01', 'packages': '"packages"', 'reported_at': '2026-10-01T10:00:00',
                   'online': '"online"', 'clock': '10:15:32', 'banner date': '01 Nov 2026', 'cf-ray': '8a1b2c3d4e5f', 'nonce': 'AbC123xyz'}
        context = {
            'ports': [{'number': 25, 'banner': '220 mail.example ESMTP Exim 4.96 Sun, 01 Nov 2026 10:15:32 +0000'}],
            'web': {'kept_response_headers': ['cf-ray: 8a1b2c3d4e5f-AMS', "content-security-policy: script-src 'nonce-AbC123xyz'"]},
            'certificates': [{'port': 443, 'issuer': 'R3', 'days_left': 90}],
            'probe_results': [{'probe': 'p', 'kind': 'version', 'product': 'nginx', 'version': '1', 'outcome': 'found', 'observed': '2026-10-01'}],
            'host_inventory': {'os': 'Ubuntu', 'kernel': '5', 'packages': 400, 'reported_at': '2026-10-01T10:00:00+00:00'},
            'tailscale': {'online': True, 'os': 'linux'}}
        shown = json.dumps(host_context.clipped(context, stable=True), sort_keys=True)
        for name, raw in secrets.items():
            self.assertNotIn(raw, shown, name)
        self.assertIn('"expiry": "valid"', shown)
        self.assertIn('hh:mm:ss', shown.replace('timestamp', 'hh:mm:ss'))
        # the view is its own fixed point: hashing it again (bind_host_text) cannot disagree with what is shown
        view = host_context.clipped(context, stable=True)
        self.assertEqual(host_context.stable_view(view), view)

    def test_a_banner_that_carries_the_date_is_the_same_banner_tomorrow(self):
        def banner(text):
            return host_context.clipped({'ports': [{'number': 25, 'banner': text}]}, stable=True)
        for greeting in ('220 mail.example ESMTP Exim 4.96 {}', '220 mail.example Microsoft ESMTP MAIL Service ready at {}',
                         '220 mail.example ESMTP Sendmail 8.15.2; {}'):
            self.assertEqual(banner(greeting.format('Sun, 01 Nov 2026 10:15:32 +0000')), banner(greeting.format('Mon, 02 Nov 2026 23:59:01 +0100')))
            self.assertEqual(banner(greeting.format('2026-11-01T10:15:32Z')), banner(greeting.format('2026-11-02 23:59:01')))
        self.assertNotEqual(banner('220 mail.example ESMTP Exim 4.96 Sun, 01 Nov 2026 10:15:32'), banner('220 mail.example ESMTP Exim 4.97 Sun, 01 Nov 2026 10:15:32'))

    def test_a_certificates_expiry_date_in_a_port_record_is_still_evidence(self):
        def cert(text):
            return host_context.clipped({'ports': [{'number': 443, 'certificate': text}]}, stable=True)
        self.assertNotEqual(cert('subject x; issuer R3; expires 2027-01-01 00:00:00'), cert('subject x; issuer R3; expires 2027-04-01 00:00:00'))

    def test_the_edge_nodes_and_ids_that_change_with_each_response_are_masked(self):
        def shown(*lines):
            return host_context.clipped({'web': {'kept_response_headers': list(lines)}}, stable=True)
        self.assertEqual(shown('via: 1.1 d111111abcdef8.cloudfront.net (CloudFront)', 'x-iinfo: 11-222-333 NNNN CT(0 0 0) RT(1 0)'),
                         shown('via: 1.1 e999999fedcba1.cloudfront.net (CloudFront)', 'x-iinfo: 9-8-7 NNNN CT(1 1 1) RT(2 2)'))
        self.assertNotEqual(shown('via: 1.1 d111111abcdef8.cloudfront.net (CloudFront)'), shown('via: 1.1 varnish'))
        self.assertIn('x-iinfo: *', json.dumps(shown('x-iinfo: 1-2-3')))

    def test_the_host_matches_are_listed_in_an_order_the_database_does_not_decide(self):
        """Matches of equal confidence came back in whatever order the database liked (and the list is cut at ten): the same host could
        hash differently with nothing changed."""
        scan = self.scan()
        sub = Subdomain.objects.create(name=self.host, target_domain=self.domain, scan_history=scan)
        cves = [CVEEntry.objects.create(cve_id=f'CVE-2099-{n}', cvss=5.0, affected=[], published_at=timezone.now()) for n in (905, 901, 903)]
        for cve in cves:
            CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', matched_version='1.21.0', source='port', confidence=0.5)
        listed = [m['cve'] for m in host_context._matches(sub, ())]
        self.assertEqual(listed, sorted(listed))

    def test_the_halving_of_a_long_list_cuts_the_end_of_the_sorted_list(self):
        rows = [{'probe': f'p{n:02d}', 'kind': 'version', 'product': 'x' * 60, 'version': '1', 'outcome': 'found', 'observed': f'2026-10-{n % 28 + 1:02d}'}
                for n in range(36)]  # the rows ``host_context`` reads are at most MAX_PROBES (30), below the cap of 40 per list in ``_deep``
        one = host_context.clipped({'probe_results': rows}, limit=2000, stable=True)
        two = host_context.clipped({'probe_results': rows[::-1]}, limit=2000, stable=True)
        self.assertEqual(one, two)
        self.assertLess(len(one['probe_results']), 36)
        self.assertEqual([p['probe'] for p in one['probe_results']], [f'p{n:02d}' for n in range(len(one['probe_results']))])

    def legacy_view(self):
        """The definition before this change: the whole context, as shown."""
        return mock.patch('cveFeed.host_context.stable_view', side_effect=lambda context: context)

    def test_the_definition_change_asks_only_where_the_model_would_be_shown_something_else(self):
        """Rows as production wrote them: keyed under the old definition, and keyed AGAIN once their own review had written the match's verdict
        (the context lists the host's matches, this one among them). A host with a certificate or a probe date in its context has no stored
        answer for its new signature and is asked once, keeping its verdict meanwhile. A host without one lands on the signature its first review
        was stored under, so the stored answer applies: no AI call at all."""
        plain_host = 'plain.k.example'
        self.certificate(100)
        self.probe(3)
        provider = self.provider()
        scan = self.scan()
        dated = self.floorless(scan)
        plain = CVEMatch.objects.create(cve_entry=self.cve, matched_product='nginx', matched_version='1.21.0', source='port', version_in_range=None,
                                        evidence={'branch_unlisted': True},
                                        subdomain=Subdomain.objects.create(name=plain_host, target_domain=self.domain, scan_history=scan))
        with self.legacy_view():
            first = {m.pk: self.reviewed_row(m, provider).signature for m in (dated, plain)}
            again = {m.pk: row.signature for m in (dated, plain) for row, _ in triage.track(triage.with_cves([CVEMatch.objects.get(pk=m.pk)]))}
        self.assertNotEqual(first, again)  # the verdict the review wrote moved the old key: this is what production holds
        self.assertEqual(provider.complete.call_count, 2)
        self.certificate(99)  # a day later, under the new definition
        self.probe(0)
        rows = {m.pk: pair for m in (dated, plain) for pair in triage.track(triage.with_cves([CVEMatch.objects.get(pk=m.pk)]))}
        for pk, (row, d) in rows.items():
            self.assertEqual((row.status, row.classification, row.verdict_id is not None), ('pending', self.kept, True))  # queued, the record kept
        stats = triage.run_triage(list(rows.values()), provider=provider)
        self.assertEqual((stats['asked'], stats['cached']), (1, 1))  # the plain host's stored answer applies; the dated host is asked once
        self.assertEqual(provider.complete.call_count, 3)
        for row, _ in rows.values():
            row.refresh_from_db()
            self.assertEqual(row.status, 'triaged')
        # and from here on the same host a day later is the same key, and asks nothing
        self.certificate(98)
        self.probe(0)
        (row, d), = triage.track(triage.with_cves([CVEMatch.objects.get(pk=dated.pk)]))
        self.assertEqual((row.status, row.signature), ('triaged', rows[dated.pk][0].signature))

    def burst(self):
        """Four rows whose keys the definition change moves (a certificate and a probe date in the context), all reviewed today."""
        self.certificate(100)
        self.probe(3)
        provider = self.provider()
        scan = self.scan()
        matches = []
        for n in range(4):
            sub = Subdomain.objects.create(name=self.host, target_domain=self.domain, scan_history=scan)
            matches.append(CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version=f'1.21.{n}',
                                                   source='port', version_in_range=None, evidence={'branch_unlisted': True}))
        with self.legacy_view():
            for m in matches:
                self.reviewed_row(m, provider)
        self.assertEqual((provider.complete.call_count, TriageCall.objects.count()), (4, 4))
        self.certificate(99)
        self.probe(0)
        pairs = triage.track(triage.with_cves(matches))
        self.assertEqual({row.status for row, _ in pairs}, {'pending'})
        return matches, provider, pairs

    def spread(self, cap, limit):
        """Each cap, set to admit one call more than the four already made today, asks one row and leaves the rest pending with their verdicts."""
        matches, provider, pairs = self.burst()
        with mock.patch.dict('os.environ', {cap: str(limit(TriageCall.objects.count()))}):
            stats = triage.run_triage(pairs, provider=provider)
        self.assertEqual((stats['asked'], stats['queued']), (1, 3))
        self.assertEqual(provider.complete.call_count, 5)
        self.assertEqual(Triage.objects.filter(status='pending', classification=self.kept).count(), 3)  # waiting, verdicts kept

    def test_the_one_time_review_burst_is_spread_by_the_run_cap(self):
        self.spread('CVENGINE_TRIAGE_MAX_PER_RUN', lambda today: 1)

    def test_the_one_time_review_burst_is_spread_by_the_project_day_cap(self):
        self.spread('CVENGINE_TRIAGE_MAX_PER_PROJECT_DAY', lambda today: today + 1)

    def test_the_one_time_review_burst_is_spread_by_the_day_cap(self):
        self.spread('CVENGINE_TRIAGE_MAX_PER_DAY', lambda today: today + 1)
