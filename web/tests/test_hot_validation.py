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

    def test_cursor_keeps_work_over_the_per_sweep_cap(self):
        with mock.patch('cveFeed.hot_validation._backfill_projects', return_value=0), \
                mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'), \
                mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            first = hot_validation.sweep(max_jobs=1)
            second = hot_validation.sweep(max_jobs=1)
        self.assertEqual((first['fire'], second['fire']), (1, 1))

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
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[]):
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
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[]):
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
