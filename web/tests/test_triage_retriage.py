"""Evidence that changes after a finding was triaged is triaged again (the AI review coverage fixes, docs/AI-REVIEWER.md):

* a correlation outside a scan (a probe, a version source, a panel version, a KEV re-read) that moves a match tracks it and asks again (F1);
* the triage sweep runs hourly, a refreshed CVE's matches and a backfill's new rows are asked, not left for the daily sweep (F2);
* a new detection strategy (remote ceiling, guidance) re-asks the matches that already hold an answer, without moving any other signature (F9);
* a validation that queued its triage question learns the answer (F11);
* the model is told when the evidence it reads was shortened, and list_triage can keep to the current inventory (F12).
"""
import json
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, triage
from cveFeed.models import AIJob, AutomaticValidation, CVEDetection, CVEMatch, OnDemandValidation, Triage
from tests import ai_queue
from tests.test_triage import TriageDbBase, reply


def row_for(sub, cve, **kw):
    return {'cve_entry_id': cve.pk, 'source': 'port', 'matched_product': 'nginx', 'matched_version': '1.18.0', 'version_in_range': True,
            'confidence': 0.9, 'scan_history_id': None, 'distro_status': 'no_data', 'distro_fixed_version': '',
            'evidence': {'ip': '203.0.113.8', 'port': 443}, 'subdomain_id': sub.pk, **kw}


@mock.patch('cveFeed.activity.log', return_value=None)
class ChangedEvidenceTests(TriageDbBase):
    def test_a_match_moved_outside_a_scan_is_tracked_and_asked_again_after_the_write(self, _log):
        m = self.match('a.tr.test')
        self.run_all(provider=self.provider(reply('likely')))
        before = Triage.objects.get(match=m)
        self.assertEqual(before.status, 'triaged')
        with mock.patch('cveFeed.tasks.retriage_matches.delay') as queued, self.captureOnCommitCallbacks(execute=True):
            correlation.save_matches([row_for(m.subdomain, self.cve, matched_version='1.19.0', distro_status='vulnerable')])
        queued.assert_called_once_with([m.pk])
        from cveFeed.tasks import retriage_matches
        provider = self.provider(reply('confirmed'))
        ai_queue.ensure_configured(provider)
        stats = retriage_matches([m.pk])
        self.assertEqual(stats['asked'], 1)
        row = Triage.objects.get(match=m)
        self.assertNotEqual(row.signature, before.signature)  # the row describes what the match holds now
        self.assertEqual(row.status, 'pending')  # and waits for the answer of the new question, no longer "triaged" on the old evidence
        ai_queue.serve(provider)
        self.assertEqual(Triage.objects.get(match=m).status, 'triaged')

    def test_a_new_match_outside_a_scan_is_queued_by_its_key(self, _log):
        from startScan.models import Subdomain
        sub = Subdomain.objects.create(name='new.tr.test', target_domain=self.domain)
        with mock.patch('cveFeed.tasks.retriage_matches.delay') as queued, self.captureOnCommitCallbacks(execute=True):
            correlation.save_matches([row_for(sub, self.cve)])
        queued.assert_called_once_with([CVEMatch.objects.get(subdomain=sub).pk])

    def test_a_scans_own_correlation_leaves_it_to_the_scans_triage_stage(self, _log):
        m = self.match('a.tr.test')
        with mock.patch('cveFeed.tasks.retriage_matches.delay') as queued, self.captureOnCommitCallbacks(execute=True):
            correlation.save_matches([row_for(m.subdomain, self.cve, matched_version='1.19.0')], retriage=False)
        queued.assert_not_called()

    def test_an_unchanged_match_queues_nothing(self, _log):
        m = self.match('a.tr.test', confidence=0.9, evidence={'ip': '203.0.113.8', 'port': 443}, distro_status='no_data')
        with mock.patch('cveFeed.tasks.retriage_matches.delay') as queued, self.captureOnCommitCallbacks(execute=True):
            correlation.save_matches([row_for(m.subdomain, self.cve)])
        queued.assert_not_called()

    def test_a_refreshed_cve_is_asked_not_only_tracked(self, _log):
        from cveFeed.tasks import correlate_refreshed_cves
        m = self.match('a.tr.test')
        self.cve.needs_recorrelation = True
        self.cve.save(update_fields=['needs_recorrelation'])
        provider = self.provider(reply('likely'))
        ai_queue.ensure_configured(provider)
        with mock.patch('cveFeed.autofire.correlate_hot_cves'):
            out = correlate_refreshed_cves()
        self.assertEqual((out['correlated'], out['asked']), (1, 1))
        ai_queue.serve(provider)
        self.assertEqual(Triage.objects.get(match=m).status, 'triaged')

    def test_a_backfill_that_made_rows_queues_the_projects_sweep(self, _log):
        from cveFeed import hot_validation
        self.match('a.tr.test')
        with mock.patch('cveFeed.tasks.triage_pending.delay') as queued:
            hot_validation._backfill_projects()
        queued.assert_called_once_with(self.project.pk)
        with mock.patch('cveFeed.tasks.triage_pending.delay') as queued:
            hot_validation._backfill_projects()  # nothing new: nothing queued
        queued.assert_not_called()

    def test_the_triage_sweep_runs_hourly(self, _log):
        from django_celery_beat.models import PeriodicTask
        task = PeriodicTask.objects.get(name='cvengine-triage-sweep')
        self.assertEqual((task.crontab.minute, task.crontab.hour, task.task), ('41', '*', 'triage_sweep'))


@mock.patch('cveFeed.activity.log', return_value=None)
class StrategyTests(TriageDbBase):
    def strategy(self, state='likely', note='Read the admin page version.'):
        return {'summary': 'Detection.', 'identify': note, 'validation': {'max_remote_state': state, 'remote_determinable': 'partial'},
                'remote_checks': [], 'local_checks': []}

    def test_the_strategy_is_not_part_of_the_evidence_signature(self, _log):
        m = self.match('a.tr.test')
        before = triage.describe(triage.with_cves([m])[0])['signature']
        CVEDetection.objects.create(cve_entry=self.cve, source='ai', strategy=self.strategy())
        after = triage.describe(triage.with_cves([CVEMatch.objects.get(pk=m.pk)])[0])['signature']
        self.assertEqual(before, after)  # an update never re-asks the whole catalogue because records exist

    def test_a_changed_strategy_asks_the_answered_matches_again_with_the_new_ceiling(self, _log):
        m = self.match('a.tr.test')
        self.run_all(provider=self.provider(reply('confirmed')))
        first = Triage.objects.get(match=m)
        self.assertEqual(first.status, 'triaged')
        CVEDetection.objects.create(cve_entry=self.cve, source='ai', strategy=self.strategy('needs_validation'))
        provider = self.provider(reply('confirmed'))
        ai_queue.ensure_configured(provider)
        out = triage.strategy_changed(self.cve.pk)
        self.assertEqual((out['asked_again'], out['asked']), (1, 1))
        row = Triage.objects.get(match=m)
        self.assertTrue(row.review_nonce.startswith(triage.STRATEGY_NONCE))
        self.assertEqual(row.classification, first.classification)  # the record stays until the new answer lands
        ai_queue.serve(provider)
        row = Triage.objects.get(match=m)
        self.assertEqual((row.status, row.classification), ('triaged', 'needs_validation'))  # the new ceiling clamps the same answer
        self.assertEqual(triage.strategy_changed(self.cve.pk)['asked_again'], 0)  # once per strategy

    def test_an_ai_answer_that_moves_the_key_queues_the_retriage_after_commit(self, _log):
        from cveFeed import detection_author
        row = CVEDetection.objects.create(cve_entry=self.cve, source='rules', strategy={})
        row = CVEDetection.objects.select_related('cve_entry').get(pk=row.pk)
        with mock.patch('cveFeed.tasks.retriage_cve_strategy.delay') as queued, self.captureOnCommitCallbacks(execute=True), \
                mock.patch('cveFeed.detection.finalize', side_effect=lambda s, v: s), mock.patch('cveFeed.detection.merge_strategies', side_effect=lambda a, b: b), \
                mock.patch('cveFeed.locality.apply_scope'):
            detection_author._apply_answer(row, self.strategy(), [], 'anthropic:m', 'h')
        queued.assert_called_once_with(self.cve.pk)
        self.assertNotEqual(triage.strategy_key({}, 'rules'), triage.strategy_key(self.strategy(), 'ai'))
        self.assertEqual(triage.strategy_key(self.strategy(), 'ai'), triage.strategy_key(json.loads(json.dumps(self.strategy())), 'ai'))


@mock.patch('cveFeed.activity.log', return_value=None)
class ValidationAnswerTests(TriageDbBase):
    def test_a_deferred_validation_takes_the_answer_of_its_triage_question(self, _log):
        m = self.match('a.tr.test')
        provider = self.provider(reply('likely'))
        ai_queue.ensure_configured(provider)
        pairs = triage.track(triage.with_cves([m]))
        triage.run_triage(pairs)
        row, d = pairs[0]
        job_id = triage.open_job_id(d['kind'], d['signature'])
        self.assertIsNotNone(job_id)
        record = OnDemandValidation.objects.create(match=m, project=self.project, status='completed', ai_job_id=job_id,
                                                   result={'ai_state': 'deferred', 'ai_status': 'pending'})
        other = AutomaticValidation.objects.create(triage=row, project=self.project, signature=row.signature, status='completed', ai_job_id=job_id,
                                                   result={'ai_state': 'queued'})
        ai_queue.serve(provider)
        record.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual((record.result['ai_state'], record.result['ai_status'], record.result['classification']),
                         ('completed', 'triaged', Triage.objects.get(match=m).classification))
        self.assertTrue(record.result['classification'])
        self.assertEqual(other.result['ai_state'], 'completed')

    def test_a_failed_question_marks_the_record_failed_and_one_answered_before_the_write_is_settled_too(self, _log):
        m = self.match('a.tr.test')
        provider = self.provider('not json at all')
        ai_queue.ensure_configured(provider)
        pairs = triage.track(triage.with_cves([m]))
        triage.run_triage(pairs)
        job_id = triage.open_job_id(pairs[0][1]['kind'], pairs[0][1]['signature'])
        ai_queue.serve(provider)  # refused twice: the job fails before any record names it
        self.assertEqual(AIJob.objects.get(pk=job_id).status, 'applied')
        record = OnDemandValidation.objects.create(match=m, project=self.project, status='completed', ai_job_id=job_id,
                                                   result={'ai_state': 'deferred'})
        triage.settle_if_done(job_id)
        record.refresh_from_db()
        self.assertEqual(Triage.objects.get(match=m).status, 'error')
        self.assertEqual(record.result['ai_state'], 'failed')  # the job was applied as an error on the row: read from the row, not the job


class TruncationNoteTests(TestCase):
    def test_the_model_is_told_when_the_finding_was_shortened_and_not_otherwise(self):
        from reNgine.ai_providers import triage_parts
        short = triage_parts('cve_match', {'product': 'nginx', 'affected': [{'product': 'nginx'}]})
        self.assertFalse(any('shortened' in p.get('text', '') for p in short))
        long = triage_parts('cve_match', {'product': 'nginx', 'affected': [{'product': f'p{i}'} for i in range(30)], 'description': 'x ' * 2000})
        note = [p['text'] for p in long if 'shortened' in p.get('text', '')]
        self.assertEqual(len(note), 1)
        self.assertIn('lists longer than 20 items', note[0])
        self.assertIn('text longer than 3000 characters', note[0])
        self.assertIn('unknown, not absent', note[0])


@mock.patch('cveFeed.activity.log', return_value=None)
class CurrentInventoryTests(TriageDbBase):
    def test_list_triage_can_keep_to_the_current_inventory(self, _log):
        from django.contrib.auth.models import User
        from agentapi import services as svc
        from agentapi.services import Ctx
        from startScan.models import Vulnerability
        m = self.match('a.tr.test')
        gone = Vulnerability.objects.create(source='nuclei', name='Old', severity=2, discovered_date=timezone.now(), target_domain=self.domain,
                                            subdomain=m.subdomain, open_status=False)
        triage.track(triage.with_cves([m]) + triage.vulnerabilities(Vulnerability.objects.filter(pk=gone.pk)))
        admin = User.objects.create_superuser('cur-admin', password='x')
        ctx = Ctx(user=admin)
        everything = svc.list_triage(ctx, self.project.slug, {'status': 'pending'})
        current = svc.list_triage(ctx, self.project.slug, {'status': 'pending', 'current': 'true'})
        self.assertEqual(everything['count'], 2)
        self.assertEqual([r['kind'] for r in current['results']], ['cve_match'])
        self.assertEqual(Triage.objects.filter(triage.current_q()).count(), 1)
