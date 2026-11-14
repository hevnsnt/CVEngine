"""The automatic lifecycle of AI-written templates (cveFeed.templatevalidate): every gate, with fakes. No AI, no network, no scanner."""
import datetime
import importlib
import json
import tempfile
from pathlib import Path
from unittest import mock

from django.apps import apps
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import reviewer, templatefixture, templategen, templatevalidate, validation
from cveFeed.models import AgentActivity, AIJob, CVEEntry, GeneratedTemplate, ReviewerSettings
from reNgine.resources import ScannerUnavailable

GOOD = '''id: cve-2099-1234
info: {name: ExampleApp version check, severity: high, tags: cve-2099-1234}
http:
  - method: GET
    path: ["{{BaseURL}}/version"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["ExampleApp 1.2.3"]
      - type: status
        status: [200]
'''
AFFECTED = {'status': 200, 'headers': {'Server': 'ExampleApp'}, 'body': 'ExampleApp 1.2.3 build 7'}
FIXED = {'status': 200, 'headers': {'Server': 'ExampleApp'}, 'body': 'ExampleApp 1.2.9 build 2'}
FIXTURE_REPLY = json.dumps({'vulnerable': AFFECTED, 'not_affected': FIXED})
AGREE = json.dumps({'verdict': 'agree', 'reasons': ['reads one path and matches the vulnerable version']})
SENTINEL_OK = (True, 'validated', True, 'no benign match')


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1234', title='t', original_description='ExampleApp 1.2.3 is affected', summary='',
                                           cvss=9.8, affected=[], references=[], published_at=timezone.now())
        self.dir = tempfile.mkdtemp()
        for patcher in (mock.patch.object(templategen, 'GENERATED_DIR', str(Path(self.dir) / 'generated')),
                        mock.patch.object(templategen, 'TEMPLATES_ROOT', str(Path(self.dir) / 'installed')),
                        mock.patch('cveFeed.ai_jobs.ai_on', return_value=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        ReviewerSettings.current()
        ReviewerSettings.objects.update(template_validation_enabled=True)  # these tests are about the validator itself; it ships off (test_template_validation_gate)

    def draft(self, text=GOOD, **extra):
        extra.setdefault('validation_started_at', timezone.now())
        return GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2099-1234', yaml=text, status='draft', **extra)

    def run_validator(self, now=None, sentinel=SENTINEL_OK):
        with mock.patch('agentapi.sentinel_dispatch.try_nuclei_validate', return_value=sentinel) as sent:
            self.sentinel = sent
            return templatevalidate.run_pending(now)

    def open_job(self, phase):
        return AIJob.objects.get(kind='template_validation', context__phase=phase, status='queued')

    def answer(self, phase, text):
        job = self.open_job(phase)
        job.status = 'applying'
        job.save()
        templatevalidate.job_answer(job, text)
        AIJob.objects.filter(pk=job.pk).update(status='applied')  # what ai_jobs.apply does once the handler returns
        return job


class FixtureEvaluatorTests(SimpleTestCase):
    def test_it_matches_the_affected_response_and_not_the_others(self):
        self.assertTrue(templatefixture.matches(GOOD, AFFECTED))
        for response in (FIXED, templatefixture.BENIGN, templatefixture.NOT_FOUND):
            self.assertFalse(templatefixture.matches(GOOD, response))

    def test_the_status_must_agree_when_the_matchers_are_anded(self):
        self.assertFalse(templatefixture.matches(GOOD, {**AFFECTED, 'status': 404}))

    def test_regex_header_and_negative_matchers(self):
        text = GOOD.replace('type: word\n        words: ["ExampleApp 1.2.3"]', 'type: regex\n        part: header\n        regex: ["Server: ExampleApp/1\\\\.[0-2]"]')
        self.assertTrue(templatefixture.matches(text, {'status': 200, 'headers': {'Server': 'ExampleApp/1.1'}, 'body': ''}))
        self.assertFalse(templatefixture.matches(text, {'status': 200, 'headers': {'Server': 'ExampleApp/2.0'}, 'body': ''}))

    def test_a_matcher_it_cannot_decide_is_refused_not_trusted(self):
        text = GOOD.replace('type: word\n        words: ["ExampleApp 1.2.3"]', 'type: dsl\n        dsl: ["contains(body, \'x\')"]')
        with self.assertRaises(templatefixture.Unsupported):
            templatefixture.matches(text, AFFECTED)

    def test_a_fixture_is_bounded_and_well_formed(self):
        self.assertIsNone(templatefixture.clean_fixture({'status': 'x', 'body': ''}))
        self.assertIsNone(templatefixture.clean_fixture('text'))
        self.assertEqual(len(templatefixture.clean_fixture({'status': 200, 'body': 'a' * 99999})['body']), templatefixture.MAX_BODY)


class StaticAndSentinelGateTests(Base):
    def test_a_draft_that_fails_the_static_gate_is_rejected_with_the_reason(self):
        row = self.draft(GOOD.replace('method: GET', 'method: POST'))
        self.run_validator()
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('static check', row.validation_reason)
        self.assertFalse(AIJob.objects.exists())

    def test_the_scanner_refusing_the_template_rejects_it(self):
        row = self.draft()
        self.run_validator(sentinel=(False, 'unknown field', None, ''))
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('the scanner did not accept', row.validation_reason)

    def test_matching_the_benign_control_on_the_sentinel_rejects_it(self):
        row = self.draft()
        self.run_validator(sentinel=(True, 'ok', False, 'matched'))
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('benign page', row.validation_reason)

    def test_no_sentinel_makes_it_wait_without_using_a_try(self):
        row = self.draft()
        with mock.patch('agentapi.sentinel_dispatch.try_nuclei_validate', side_effect=ScannerUnavailable('nuclei_validate', 'none')):
            out = templatevalidate.run_pending()
        row.refresh_from_db()
        self.assertEqual((row.status, row.validation_attempts, out['waiting']), ('draft', 0, 1))
        self.assertGreater(row.validation_next_at, timezone.now())
        self.assertIn('no Sentinel', row.validation_reason)
        self.assertFalse(AIJob.objects.exists())

    def test_a_pending_back_off_is_respected(self):
        row = self.draft(validation_next_at=timezone.now() + datetime.timedelta(hours=1))
        self.run_validator()
        self.sentinel.assert_not_called()
        row.refresh_from_db()
        self.assertEqual(row.status, 'draft')


class FixtureAndCritiqueGateTests(Base):
    def start(self):
        row = self.draft()
        self.run_validator()
        row.refresh_from_db()
        return row

    def test_passing_the_sentinel_queues_the_fixture_job_under_the_new_stage(self):
        row = self.start()
        job = self.open_job('fixture')
        self.assertEqual((job.stage, row.validation_stage), ('template_validation', 'waiting:fixture'))
        self.assertNotIn('ExampleApp version check', json.dumps(job.packet['parts']))  # the fixture writer sees the CVE data, not the template

    def test_the_whole_lifecycle_promotes_only_after_every_gate(self):
        row = self.start()
        self.answer('fixture', FIXTURE_REPLY)
        row.refresh_from_db()
        self.assertEqual((row.status, row.path), ('draft', ''))  # the critique has not agreed yet
        self.assertEqual(row.fixture['vulnerable']['body'], AFFECTED['body'])
        self.assertIn('TEMPLATE', json.dumps(self.open_job('critique').packet['parts']))
        self.answer('critique', AGREE)
        row.refresh_from_db()
        self.assertEqual(row.status, 'valid')
        self.assertTrue(Path(row.path).is_file())
        self.assertIsNotNone(row.positive_fixture_verified_at)
        self.assertIn('critique', row.positive_fixture_source)
        self.assertEqual(validation.approved_template(row.path), (GOOD, ''))  # the host-side gate now accepts exactly this row
        self.assertTrue(AgentActivity.objects.filter(message__contains='passed every automatic gate').exists())

    def test_a_template_that_also_matches_the_fixed_release_is_rejected(self):
        row = self.start()
        broad = {'vulnerable': AFFECTED, 'not_affected': {**FIXED, 'body': 'ExampleApp 1.2.3 patched'}}
        self.answer('fixture', json.dumps(broad))
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('fixed release', row.validation_reason)

    def test_a_template_that_matches_a_benign_page_is_rejected(self):
        text = GOOD.replace('type: word\n        words: ["ExampleApp 1.2.3"]', 'type: word\n        words: ["Welcome", "nothing"]\n        condition: or')
        row = self.draft(text)
        self.run_validator()
        self.answer('fixture', json.dumps({'vulnerable': {'status': 200, 'body': 'Welcome'}, 'not_affected': {'status': 200, 'body': 'x'}}))
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('benign page', row.validation_reason)

    def test_a_positive_miss_is_retried_with_back_off_then_rejected(self):
        row = self.start()
        miss = json.dumps({'vulnerable': {'status': 200, 'body': 'something else'}, 'not_affected': FIXED})
        waits = []
        for attempt in range(1, templatevalidate.MAX_ATTEMPTS):
            self.answer('fixture', miss)
            row.refresh_from_db()
            self.assertEqual((row.status, row.validation_attempts), ('draft', attempt))
            waits.append(row.validation_next_at - timezone.now())
            self.run_validator(now=row.validation_next_at + datetime.timedelta(seconds=1))
        self.assertLess(waits[0], waits[1])
        self.answer('fixture', miss)
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('did not match the response an affected host gives', row.validation_reason)

    def test_an_unreadable_answer_uses_a_try_and_no_data_means_rejected(self):
        row = self.start()
        self.answer('fixture', 'I cannot help with that')
        row.refresh_from_db()
        self.assertEqual((row.status, row.validation_attempts), ('draft', 1))
        self.run_validator(now=row.validation_next_at + datetime.timedelta(seconds=1))
        self.answer('fixture', json.dumps({'vulnerable': None, 'not_affected': None}))
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('does not say what an affected host shows', row.validation_reason)

    def test_an_unsupported_matcher_is_rejected_with_that_reason(self):
        text = GOOD.replace('type: word\n        words: ["ExampleApp 1.2.3"]', 'type: dsl\n        dsl: ["contains(body, \'ExampleApp 1.2.3\')"]')
        row = self.draft(text)
        self.run_validator()
        self.answer('fixture', FIXTURE_REPLY)
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('cannot be tested offline', row.validation_reason)

    def test_the_second_pass_must_agree(self):
        row = self.start()
        self.answer('fixture', FIXTURE_REPLY)
        self.answer('critique', json.dumps({'verdict': 'disagree', 'reasons': ['the version banner is not specific to this flaw']}))
        row.refresh_from_db()
        self.assertEqual((row.status, row.path), ('invalid', ''))
        self.assertIn('second pass disagreed', row.validation_reason)
        self.assertIn('not specific', row.validation_reason)
        self.assertFalse(Path(templategen.GENERATED_DIR).exists() and any(Path(templategen.GENERATED_DIR).iterdir()))

    def test_an_unclear_verdict_is_not_an_agreement(self):
        row = self.start()
        self.answer('fixture', FIXTURE_REPLY)
        self.answer('critique', json.dumps({'verdict': 'maybe'}))
        row.refresh_from_db()
        self.assertEqual((row.status, row.validation_attempts), ('draft', 1))

    def test_a_refused_or_failed_ai_call_is_retried_a_bounded_number_of_times(self):
        row = self.start()
        for _ in range(templatevalidate.MAX_ATTEMPTS):
            row.refresh_from_db()
            job = AIJob.objects.filter(kind='template_validation', status='queued').first()
            if job is None:
                self.run_validator(now=row.validation_next_at + datetime.timedelta(seconds=1))
                job = AIJob.objects.filter(kind='template_validation', status='queued').first()
            job.status = 'applying'
            job.save()
            templatevalidate.job_failure(job, 'refused', {})
            AIJob.objects.filter(pk=job.pk).update(status='failed')
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')
        self.assertIn('declined', row.validation_reason)

    def test_with_the_ai_off_the_draft_waits_and_asks_nothing(self):
        row = self.draft()
        with mock.patch('cveFeed.ai_jobs.ai_on', return_value=False):
            self.run_validator()
        row.refresh_from_db()
        self.assertEqual((row.status, row.validation_attempts), ('draft', 0))
        self.assertIn('AI provider', row.validation_reason)
        self.assertFalse(AIJob.objects.exists())

    def test_a_different_installed_check_with_the_same_id_blocks_promotion(self):
        row = self.start()
        Path(templategen.GENERATED_DIR).mkdir(parents=True)
        (Path(templategen.GENERATED_DIR) / 'cve-2099-1234.yaml').write_text('id: other')
        self.answer('fixture', FIXTURE_REPLY)
        self.answer('critique', AGREE)
        row.refresh_from_db()
        self.assertEqual(row.status, 'invalid')


class NeverDispatchedUnvalidatedTests(Base):
    def put(self, row):
        Path(templategen.GENERATED_DIR).mkdir(parents=True, exist_ok=True)
        path = Path(templategen.GENERATED_DIR) / 'cve-2099-1234.yaml'
        path.write_text(GOOD)
        row.path = str(path)
        row.save()
        return str(path)

    def test_a_draft_is_never_sent_to_a_host_even_with_fixture_fields_and_a_file(self):
        row = self.draft(positive_fixture_verified_at=timezone.now(), positive_fixture_source='forged')
        path = self.put(row)
        with mock.patch('agentapi.sentinel_dispatch.try_template_test') as sent:
            outcome = templategen.run_template(path, ['198.51.100.7'], project=1)
        sent.assert_not_called()
        self.assertIn('not validated', outcome[0]['error'])
        self.assertEqual(validation.resolve_template('CVE-2099-1234')[0], '')

    def test_rejected_and_expired_rows_are_never_sent_either(self):
        for status in ('invalid', 'expired'):
            row = self.draft(positive_fixture_verified_at=timezone.now(), positive_fixture_source='x')
            row.status = status
            path = self.put(row)
            with mock.patch('agentapi.sentinel_dispatch.try_template_test') as sent:
                templategen.run_template(path, ['198.51.100.7'], project=1)
            sent.assert_not_called()
            row.delete()

    def test_a_template_that_passed_the_validator_is_the_only_kind_that_runs(self):
        row = self.draft()
        self.run_validator()
        self.answer('fixture', FIXTURE_REPLY)
        self.answer('critique', AGREE)
        row.refresh_from_db()
        with mock.patch('agentapi.sentinel_dispatch.try_template_test', return_value=[{'host': '198.51.100.7', 'vulnerable': False, 'output': ''}]) as sent:
            templategen.run_template(row.path, ['198.51.100.7'], project=1)
        sent.assert_called_once()


class ExpiryTests(Base):
    def test_a_draft_still_pending_after_the_window_is_closed_as_expired_with_the_reason(self):
        old = timezone.now() - datetime.timedelta(days=templatevalidate.expiry_days() + 1)
        row = self.draft(validation_started_at=old, validation_reason='waiting: no Sentinel can run template checks (nuclei_validate) right now')
        out = self.run_validator()
        row.refresh_from_db()
        self.assertEqual((row.status, out['expired']), ('expired', 1))
        self.assertTrue(row.validation_reason.startswith('expired, not validated'))
        self.assertIn('no Sentinel', row.validation_reason)
        self.assertTrue(AgentActivity.objects.filter(kind='validate', message__contains='expired').exists())
        self.sentinel.assert_not_called()

    def test_an_old_unstamped_draft_is_processed_not_expired(self):
        row = self.draft(validation_started_at=None)
        GeneratedTemplate.objects.filter(pk=row.pk).update(created_at=timezone.now() - datetime.timedelta(days=30), validation_started_at=None)
        out = self.run_validator()
        row.refresh_from_db()
        self.assertEqual((row.status, out['stamped']), ('draft', 1))
        self.assertEqual(row.validation_stage, 'waiting:fixture')

    def test_the_expiry_window_is_settable_and_never_zero(self):
        with mock.patch.dict('os.environ', {'CVENGINE_TEMPLATE_DRAFT_EXPIRY_DAYS': '0'}):
            self.assertEqual(templatevalidate.expiry_days(), 1)
        with mock.patch.dict('os.environ', {'CVENGINE_TEMPLATE_DRAFT_EXPIRY_DAYS': 'x'}):
            self.assertEqual(templatevalidate.expiry_days(), templatevalidate.DEFAULT_EXPIRY_DAYS)

    def test_a_job_that_vanished_is_a_try_not_a_hang(self):
        row = self.draft(validation_stage='waiting:fixture')
        self.run_validator()
        row.refresh_from_db()
        self.assertEqual(row.validation_attempts, 1)


class ReviewerCheckTests(Base):
    def check(self):
        return {c['code']: c for c in reviewer.ops_checks()}['generated_templates']

    def old(self, n=3):
        for _ in range(n):
            self.draft(validation_started_at=timezone.now() - datetime.timedelta(days=4))

    def test_it_no_longer_asks_a_person_to_review_anything(self):
        self.old()
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready'):
            check = self.check()
        self.assertEqual(check['state'], 'ok')
        self.assertEqual(check['detail'], '')
        text = json.dumps(check).lower()
        for word in ('person to review', 'for review', 'review them'):
            self.assertNotIn(word, text)

    def test_no_sentinel_that_can_validate_is_reported_with_the_fix(self):
        self.old()
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready', side_effect=ScannerUnavailable('nuclei_validate', 'none')):
            check = self.check()
        self.assertEqual(check['state'], 'warning')
        self.assertIn('no Sentinel that runs template checks is online', check['detail'])
        self.assertIn('Fix:', check['detail'])
        self.assertNotIn('review', check['detail'].lower())

    def test_the_ai_being_off_is_reported_with_the_fix(self):
        self.old()
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready'), mock.patch('cveFeed.ai_jobs.ai_on', return_value=False):
            check = self.check()
        self.assertEqual(check['state'], 'warning')
        self.assertIn('Settings, AI', check['detail'])

    def test_every_draft_failing_is_reported_but_a_working_system_is_not(self):
        for n in range(5):
            GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='invalid', validation_reason='it also matches a benign page',
                                             validated_at=timezone.now())
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready'):
            check = self.check()
            self.assertEqual(check['state'], 'warning')
            self.assertIn('benign page', check['detail'])
            GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='valid', validated_at=timezone.now())
            self.assertEqual(self.check()['state'], 'ok')

    def test_all_rejected_alert_does_not_advise_a_bigger_model(self):
        for n in range(5):
            GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='invalid', validation_reason='the fixture did not match',
                                             validated_at=timezone.now())
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready'):
            check = self.check()
        self.assertEqual(check['state'], 'warning')
        text = check['detail'].lower()
        for advice in ('more capable', 'bigger model', 'larger model', 'choose a'):
            self.assertNotIn(advice, text)
        self.assertIn('the fixture did not match', text)  # what happened
        self.assertIn('what you can do', text)  # and what to do about it
        self.assertIn('product and version', text)
        self.assertNotIn('needs a review by hand', text)  # no promise the alert cannot keep

    def test_fresh_pending_drafts_are_no_problem(self):
        self.draft()
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready', side_effect=ScannerUnavailable('nuclei_validate', 'none')):
            self.assertEqual(self.check()['state'], 'ok')


class StuckDraftsMigrationTests(Base):
    migration = importlib.import_module('cveFeed.migrations.0154_generatedtemplate_auto_validation')

    def test_the_one_shot_pushes_waiting_drafts_into_the_validator_and_schedules_it(self):
        from django_celery_beat.models import PeriodicTask
        stuck = [self.draft(validation_started_at=None, validation_attempts=2, validation_stage='critique') for _ in range(3)]
        settled = GeneratedTemplate.objects.create(cve_entry=self.cve, yaml=GOOD, status='valid')
        self.migration.start_validation(apps, None)
        for row in stuck:
            row.refresh_from_db()
            self.assertEqual((row.validation_attempts, row.validation_stage), (0, ''))
            self.assertIsNotNone(row.validation_started_at)
        settled.refresh_from_db()
        self.assertEqual(settled.status, 'valid')
        task = PeriodicTask.objects.get(name=self.migration.TASK_NAME)
        self.assertEqual(task.task, 'validate_template_drafts')
        self.migration.start_validation(apps, None)  # safe to run twice
        self.assertEqual(PeriodicTask.objects.filter(name=self.migration.TASK_NAME).count(), 1)
        self.migration.stop_validation(apps, None)

    def test_the_stuck_drafts_are_then_processed_by_the_task(self):
        from cveFeed.tasks import validate_template_drafts
        rows = [self.draft(validation_started_at=None) for _ in range(3)]
        GeneratedTemplate.objects.update(created_at=timezone.now() - datetime.timedelta(days=20))
        self.migration.start_validation(apps, None)
        with mock.patch('agentapi.sentinel_dispatch.try_nuclei_validate', return_value=SENTINEL_OK):
            out = validate_template_drafts()
        self.assertEqual((out['asked'], out['expired']), (3, 0))
        for row in rows:
            row.refresh_from_db()
            self.assertEqual(row.validation_stage, 'waiting:fixture')
        self.assertEqual(AIJob.objects.filter(kind='template_validation').count(), 3)


class SummaryTests(Base):
    def test_counts_and_plain_reasons(self):
        self.draft()
        GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='valid')
        for _ in range(2):
            GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='invalid', validation_reason='it also matches a benign page')
        GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='expired', validation_reason='expired, not validated: no Sentinel')
        GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status='invalid', validation_output='static check: forbidden key')
        data = templatevalidate.summary()
        self.assertEqual((data['valid'], data['pending'], data['rejected'], data['expired']), (1, 1, 3, 1))
        self.assertEqual(data['reasons'][0], {'reason': 'it also matches a benign page', 'count': 2})
        self.assertIn('static check: forbidden key', [r['reason'] for r in data['reasons']])

    def test_the_usage_snapshot_and_headline_carry_it(self):
        from cveFeed import ai_usage
        from cveFeed.views import stats_payload
        self.draft()
        self.assertEqual(ai_usage.snapshot()['templates']['pending'], 1)
        stats = stats_payload()
        self.assertEqual((stats['templates'], stats['templates_pending'], stats['templates_rejected']), (0, 1, 0))
