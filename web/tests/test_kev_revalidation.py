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

from cveFeed import host_context, hot_validation, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, OnDemandValidation, ProbeObservation, TlsCertificate, Triage
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


class ManualJobKeyTests(Base):
    def test_a_manual_validation_of_an_edge_fronted_match_holds_the_gap_for_the_next_automatic_one(self):
        """A manual job counts as standing (``match_policy.has_standing``) once it is no longer running, and an edge-verified host's closure
        basis reads that. The key was made while the job still ran, so it described the match as clearable by the edge; the key ``enqueue``
        makes from the database (the job completed by then) does not. The two never matched, and the minimum gap failed open."""
        from cveFeed.tasks import validate_match_on_demand
        match = self.match(self.scan(), source='tech')
        (row,) = self.track(match)
        user = User.objects.create_user('bob', password='x')
        ProjectMembership.objects.create(user=user, project=self.project, role='user')
        job = OnDemandValidation.objects.create(match=match, project=self.project, evidence_signature=row.signature, priority=0,
                                                source='manual', requested_by=user)
        plan = {'check_kinds': [], 'reason': 'edge', 'generate_template': False, 'source': 'test'}
        edge = {'fronted': True, 'verified': True, 'providers': ['cloudflare'], 'basis': ['cname']}
        with mock.patch('cveFeed.host_context.edge_of', return_value=edge), \
                mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.k.example']), \
                mock.patch('cveFeed.correlation.invalid_identity_reason', return_value=''), \
                mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
                mock.patch('cveFeed.validation_plan.plan', return_value=(plan, None)), \
                mock.patch('cveFeed.validation.run_validation', return_value={}), \
                mock.patch('cveFeed.triage.run_triage', return_value={}):
            OnDemandValidation.objects.filter(pk=job.pk).update(status='running')
            running = triage.describe(triage.with_cves([CVEMatch.objects.get(pk=match.pk)])[0])
            self.assertEqual(running['facts']['closure_basis'], ['cdn_edge_only'])  # while it runs, the edge may clear the match
            OnDemandValidation.objects.filter(pk=job.pk).update(status='queued')
            validate_match_on_demand(job.pk)
            job.refresh_from_db()
            self.assertEqual((job.status, job.source), ('completed', 'manual'))
            match = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)
            after = triage.describe(match)
            # the finished manual job vouches for the match, so the edge no longer clears it: that is the state the key has to describe
            self.assertEqual(after['facts']['closure_basis'], [])
            self.assertEqual(job.result['revalidation_key'], triage.revalidation_key(after))
            (row,) = self.track(match)
            self.assertNotEqual(row.signature, job.evidence_signature)  # not 'fresh': the gap is what is asked
            outcome, dispatch = self.enqueue(row)
        self.assertEqual(outcome, 'min_gap')
        dispatch.assert_not_called()
        self.assertEqual(OnDemandValidation.objects.filter(match=match).count(), 1)


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
        self.assertEqual(before['host_context']['certificates'][0]['days_left'], 100)  # what the model is shown is untouched
        self.certificate(99)
        self.probe(0)
        after = self.describe(match)
        self.assertEqual(after['host_context']['certificates'][0]['days_left'], 99)
        self.assertEqual(before['host_context']['probe_results'][0]['observed'] != after['host_context']['probe_results'][0]['observed'], True)
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

    def legacy_view(self):
        """The definition before this change: the whole context, as shown."""
        return mock.patch('cveFeed.host_context.stable_view', side_effect=lambda context: context)

    def test_the_definition_change_queues_a_review_only_where_a_volatile_value_was_in_the_key_and_keeps_the_verdict(self):
        """The rows written under the old definition: a host with a certificate or a probe date in its context has a different key now
        (and is asked once, keeping its verdict meanwhile); a host without one has the same key and is asked nothing."""
        plain_host, dated_host = 'plain.k.example', self.host
        self.certificate(100)
        self.probe(3)
        provider = self.provider()
        scan = self.scan()
        dated = self.floorless(scan)
        plain = CVEMatch.objects.create(cve_entry=self.cve, matched_product='nginx', matched_version='1.21.0', source='port', version_in_range=None,
                                        evidence={'branch_unlisted': True},
                                        subdomain=Subdomain.objects.create(name=plain_host, target_domain=self.domain, scan_history=scan))
        with self.legacy_view():
            rows = [self.reviewed_row(m, provider) for m in (dated, plain)]
        self.assertEqual(provider.complete.call_count, 2)
        old = {row.pk: row.signature for row in rows}
        self.certificate(99)  # a day later, under the new definition
        self.probe(0)
        tracked = {m.pk: row for m in (dated, plain) for row, _ in triage.track(triage.with_cves([m]))}
        self.assertEqual(tracked[plain.pk].signature, old[tracked[plain.pk].pk])
        self.assertEqual(tracked[plain.pk].status, 'triaged')
        self.assertNotEqual(tracked[dated.pk].signature, old[tracked[dated.pk].pk])  # the one time the key's definition moved it
        self.assertEqual((tracked[dated.pk].status, tracked[dated.pk].classification, tracked[dated.pk].verdict_id is not None),
                         ('pending', self.kept, True))
        # and from here on the same host a day later is the same key
        self.certificate(98)
        self.probe(0)
        (again, _), = triage.track(triage.with_cves([dated]))
        self.assertEqual(again.signature, tracked[dated.pk].signature)

    def test_the_one_time_review_burst_is_spread_by_the_triage_caps(self):
        """Many rows moved by the definition change are asked at most TRIAGE_MAX_PER_RUN a run (the rest stay pending with their verdicts)
        and never more than the daily caps allow."""
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
        self.assertEqual(provider.complete.call_count, 4)
        self.certificate(99)
        self.probe(0)
        pairs = triage.track(triage.with_cves(matches))
        self.assertEqual({row.status for row, _ in pairs}, {'pending'})
        with mock.patch.dict('os.environ', {'CVENGINE_TRIAGE_MAX_PER_RUN': '1'}):
            stats = triage.run_triage(pairs, provider=provider)
        self.assertEqual((stats['asked'], stats['queued']), (1, 3))
        self.assertEqual(provider.complete.call_count, 5)
        self.assertEqual(Triage.objects.filter(status='pending', classification=self.kept).count(), 3)  # waiting, verdicts kept
