"""CVE guidance answers outside the schema and the daily budget (the AI review coverage fixes, F7): an answer the validator refuses is sent back
once with why, and a second refusal is a failed ask (counted, backed off, asked again later), not an answer; the budget counts the questions
asked, so a revision that clears ``ai_attempted_at`` hands nothing back."""
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import detection, detection_author
from cveFeed.models import AIJob, CVEDetection, CVEEntry
from tests import ai_queue
from tests.test_cve_detection import NGINX, good_ai


class Base(TestCase):
    def setUp(self):
        self.hot = CVEEntry.objects.create(cve_id='CVE-2099-910', kev=True, cvss=9.8, published_at=timezone.now(), affected=NGINX, title='hot')
        with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
            detection_author.author_rules()

    def provider(self, *replies):
        provider = mock.Mock()
        provider.name, provider.model = 'fake', 'm1'
        provider.complete.side_effect = list(replies)
        return provider


class SchemaFailureTests(Base):
    def test_a_refused_answer_is_repaired_once_and_a_second_refusal_is_a_failure_that_stays_due(self):
        provider = self.provider('I will not answer in JSON.', 'Still not JSON.')
        self.assertEqual(ai_queue.asking(detection_author.author_with_ai, provider, per_run=1), 1)
        self.assertEqual(provider.complete.call_count, 2)
        self.assertIn('REJECTED', provider.complete.call_args_list[1].args[1])  # the second ask says why the first was refused
        row = CVEDetection.objects.get(cve_entry=self.hot)
        self.assertEqual((row.source, row.ai_model, row.ai_failures), ('rules', '', 1))  # not "answered": ai_model stays empty
        self.assertIsNotNone(row.ai_retry_at)
        self.assertIn('schema_invalid', row.ai_problems[0])
        self.assertFalse(CVEDetection.objects.filter(detection_author.due_q(timezone.now()), pk=row.pk).exists())  # backing off
        self.assertTrue(CVEDetection.objects.filter(detection_author.due_q(row.ai_retry_at + timedelta(minutes=1)), pk=row.pk).exists())
        CVEDetection.objects.filter(pk=row.pk).update(ai_retry_at=timezone.now() - timedelta(minutes=1))
        good = self.provider(good_ai())
        self.assertEqual(ai_queue.asking(detection_author.author_with_ai, good, per_run=1, within_budget=False), 1)
        row.refresh_from_db()
        self.assertEqual((row.source, row.ai_failures), ('ai', 0))

    def test_a_repaired_answer_is_stored(self):
        provider = self.provider('not json', good_ai())
        ai_queue.asking(detection_author.author_with_ai, provider, per_run=1)
        row = CVEDetection.objects.get(cve_entry=self.hot)
        self.assertEqual((row.source, row.ai_failures), ('ai', 0))
        self.assertTrue(row.ai_model)


class BudgetTests(Base):
    def test_the_budget_counts_the_questions_asked_and_a_revision_hands_nothing_back(self):
        ai_queue.configure(cve_guidance_daily=1)
        provider = self.provider(good_ai(), good_ai())
        self.assertEqual(ai_queue.asking(detection_author.author_with_ai, provider, per_run=5), 1)
        self.assertEqual((detection_author.ai_used_last_day(), detection_author.ai_budget_left()), (1, 0))
        CVEDetection.objects.update(ai_attempted_at=None)  # what mark_changed_for_revision does to queue a revision
        self.assertEqual(detection_author.ai_budget_left(), 0)
        self.assertEqual(ai_queue.asking(detection_author.author_with_ai, provider, per_run=5), 0)
        self.assertEqual(detection_author.progress()['ai_last_day'], 1)

    def test_an_expired_question_and_a_guidance_revision_do_not_count(self):
        AIJob.objects.create(kind='cve_detection', stage='cve_detection', dedupe='cve_detection:1:author', status='expired')
        AIJob.objects.create(kind='cve_detection', stage='cve_detection', dedupe='cve_detection:1:guidance', status='applied')
        AIJob.objects.create(kind='cve_detection', stage='cve_detection', dedupe='cve_detection:2:author', status='applied',
                             created_at=timezone.now() - timedelta(days=2))
        self.assertEqual(detection_author.ai_used_last_day(), 0)
