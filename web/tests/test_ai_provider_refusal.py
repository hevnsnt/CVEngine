"""A refusal by the AI provider (the usage limit reached, a rate limit, an HTTP error) is not a failed ask of cve_detection: it never counts toward
``AI_MAX_FAILURES``. The usage limit refusal also opens one admin alert that names the pause and its resume date (cveFeed.ai_pause)."""
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from cveFeed import ai_jobs, ai_pause, detection_author as da
from cveFeed.models import AdminAlert, AIJob, CVEDetection, CVEEntry

PAUSE = 'you have reached your specified api usage limits. you will regain access on 2026-11-30 at 18:00 utc.'


class RefusalCountTests(TestCase):
    def record(self, failures=0, n=1):
        cve = CVEEntry.objects.create(cve_id=f'CVE-2099-77{n}', title='t', summary='s')
        row = CVEDetection.objects.create(cve_entry=cve, source='rules', ai_attempted_at=timezone.now(), ai_failures=failures)
        job = AIJob.objects.create(kind='cve_detection', stage='cve_detection', context={'record': row.pk, 'purpose': 'author'})
        return row, job

    def test_a_provider_refusal_leaves_the_count_and_the_record_stays_due_after_an_hour(self):
        for n, category in enumerate(('provider_rate_limit', 'provider_http')):
            row, job = self.record(failures=4, n=n)
            for _ in range(3):  # a long outage: many refusals of the same record
                da.job_failure(job, category, {})
            row.refresh_from_db()
            self.assertEqual(row.ai_failures, 4)
            self.assertIsNotNone(row.ai_retry_at)  # never the give-up state (None at the last failure)
            self.assertIn('not counted', row.ai_problems[0])
            now = timezone.now()
            self.assertFalse(CVEDetection.objects.filter(da.due_q(now), pk=row.pk).exists())
            self.assertTrue(CVEDetection.objects.filter(da.due_q(now + timedelta(hours=2)), pk=row.pk).exists())

    def test_the_usage_limit_message_is_not_counted_whatever_its_category(self):
        row, job = self.record(failures=4)
        da.job_failure(job, 'unexpected_error', {'error': 'unexpected_error', 'provider_message': PAUSE})
        row.refresh_from_db()
        self.assertEqual(row.ai_failures, 4)
        self.assertIsNotNone(row.ai_retry_at)

    def test_a_real_failure_counts_exactly_as_before(self):
        row, job = self.record(failures=0)
        da.job_failure(job, 'output_truncated', {})
        row.refresh_from_db()
        self.assertEqual(row.ai_failures, 1)
        self.assertIn('will retry after 6 hours', row.ai_problems[0])
        row, job = self.record(failures=da.AI_MAX_FAILURES - 1, n=2)
        da.job_failure(job, 'output_truncated', {})
        row.refresh_from_db()
        self.assertEqual((row.ai_failures, row.ai_retry_at), (da.AI_MAX_FAILURES, None))  # the fifth failure gives up
        self.assertIn('could not author', row.ai_problems[0])

    def test_refusals_between_real_failures_do_not_shorten_the_tries(self):
        row, job = self.record(failures=3)
        da.job_failure(job, 'provider_http', {})
        da.job_failure(job, 'output_truncated', {})
        row.refresh_from_db()
        self.assertEqual(row.ai_failures, 4)
        self.assertIsNotNone(row.ai_retry_at)


class PauseAlertTests(TestCase):
    def leased(self):
        return AIJob.objects.create(kind='cve_detection', stage='cve_detection', status='leased', lease='L', lease_until=timezone.now() + timedelta(hours=1),
                                    context={'record': 0, 'purpose': 'author'})

    def refuse(self, message=PAUSE, error='provider_http'):
        body = {'lease': 'L', 'error': error, 'calls': [], 'provider': 'anthropic', 'model': 'claude-sonnet-5-5'}
        if message is not None:
            body['provider_message'] = message
        ai_jobs.submit(self.leased().pk, body)

    def test_the_usage_limit_opens_one_alert_naming_the_pause_and_the_date(self):
        self.refuse()
        self.refuse()  # a second refused job refreshes it
        alerts = AdminAlert.objects.filter(code=ai_pause.CODE, resolved_at__isnull=True)
        self.assertEqual(alerts.count(), 1)
        alert = alerts.get()
        self.assertIn('usage limit', alert.title)
        self.assertEqual(alert.facts['resume'], '2026-11-30 at 18:00 utc')
        self.assertIn('2026-11-30 at 18:00 utc', alert.detail)
        self.assertEqual(AIJob.objects.filter(result__provider_message=PAUSE).count(), 2)

    def test_a_pause_without_a_date_says_so(self):
        self.refuse('you have reached your usage limit')
        self.assertIn('names no resume date', AdminAlert.objects.get(code=ai_pause.CODE).detail)

    def test_another_provider_failure_opens_no_alert_and_stores_no_message(self):
        self.refuse(message='overloaded, please retry')
        self.refuse(message=None, error='provider_rate_limit')
        self.assertFalse(AdminAlert.objects.filter(code=ai_pause.CODE).exists())
        self.assertFalse(AIJob.objects.filter(result__has_key='provider_message').exists())

    def test_an_answered_job_resolves_the_alert(self):
        self.refuse()
        ai_jobs.submit(self.leased().pk, {'lease': 'L', 'text': '{}', 'calls': [], 'provider': 'anthropic', 'model': 'm'})
        self.assertFalse(AdminAlert.objects.filter(code=ai_pause.CODE, resolved_at__isnull=True).exists())
        self.refuse()  # a new pause opens a new row
        self.assertEqual(AdminAlert.objects.filter(code=ai_pause.CODE).count(), 2)

    def test_the_refused_job_reaches_the_record_without_a_failure_count(self):
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7790', title='t', summary='s')
        row = CVEDetection.objects.create(cve_entry=cve, source='rules', ai_attempted_at=timezone.now(), ai_failures=4)
        job = AIJob.objects.create(kind='cve_detection', stage='cve_detection', status='leased', lease='L', lease_until=timezone.now() + timedelta(hours=1),
                                   context={'record': row.pk, 'purpose': 'author'})
        ai_jobs.submit(job.pk, {'lease': 'L', 'error': 'provider_http', 'provider_message': PAUSE, 'calls': [], 'provider': 'anthropic', 'model': 'm'})
        ai_jobs.apply(job.pk)
        row.refresh_from_db()
        self.assertEqual(row.ai_failures, 4)
