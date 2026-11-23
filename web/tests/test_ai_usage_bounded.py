"""The AI usage page's answer is bounded and the page asks for what it draws: GET /cve/api/settings/ai/usage was 55 KB and 20 statements every 15 seconds
on the production install, 35 KB of it ``cost_by_stage_day``, which the page never shows. ``?cost=0`` (what the page asks) leaves that view out, the
view reuses the price rows the answer already read, and it is capped at ``COST_ROWS_MAX`` rows with ``cost_by_stage_day_has_more``."""
from datetime import date, timedelta
from pathlib import Path
import json

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import ai_usage
from cveFeed.models import AIPriceRate, AIUsage
from dashboard.models import AIProviderSettings
from tests.test_tenancy import client_for

PATH = '/cve/api/settings/ai/usage'
JS = Path(__file__).resolve().parent.parent / 'static' / 'cve' / 'ai-usage.js'


class UsageCostParamTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('usage-cost-root', 'usage-cost@example.test', 'x')

    def setUp(self):
        self.client = client_for(self.root)
        AIUsage.objects.all().delete()
        AIProviderSettings.objects.create(provider='anthropic', model='claude-test', api_key='x', enabled=True)
        now = timezone.now()
        for day in range(3):
            for stage in ('cve_detection', 'finding_triage'):
                AIUsage.objects.create(provider='anthropic', model='claude-test', actual_model='claude-actual', stage=stage, status='succeeded',
                                       input_tokens=100, output_tokens=10, started_at=now - timedelta(days=day))

    def test_the_default_answer_is_unchanged_and_cost_0_leaves_only_the_cost_view_out(self):
        full = self.client.get(PATH).json()
        lean = self.client.get(PATH + '?cost=0').json()
        self.assertEqual(len(full['cost_by_stage_day']), 6)
        self.assertFalse(full['cost_by_stage_day_has_more'])
        self.assertNotIn('cost_by_stage_day', lean)
        self.assertNotIn('cost_by_stage_day_has_more', lean)
        self.assertEqual(lean, {k: v for k, v in full.items() if not k.startswith('cost_by_stage_day')})
        self.assertEqual(self.client.get(PATH + '?cost=2').status_code, 400)

    def test_cost_0_reads_two_statements_fewer_and_the_view_no_second_price_read(self):
        snapshot = ai_usage.snapshot
        snapshot(7)  # process-wide caches (content types, settings) are filled before counting
        with CaptureQueriesContext(connection) as full:
            snapshot(7)
        with CaptureQueriesContext(connection) as lean:
            snapshot(7, with_cost=False)
        self.assertEqual(len(full) - len(lean), 1, 'the cost view is one grouped read: the price rows are the ones the answer already read')
        self.assertEqual(sum('cveFeed_aipricerate' in q['sql'] for q in full.captured_queries), 1)

    def test_the_view_is_capped_newest_days_first(self):
        rows = ai_usage.cost_by_stage_day(7, limit=4)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows, ai_usage.cost_by_stage_day(7)[:4])
        self.assertEqual(sorted({r['day'] for r in rows}, reverse=True), [r['day'] for r in rows][::2])
        cap = ai_usage.COST_ROWS_MAX
        try:
            ai_usage.COST_ROWS_MAX = 5
            answer = ai_usage.snapshot(7)
        finally:
            ai_usage.COST_ROWS_MAX = cap
        self.assertEqual(len(answer['cost_by_stage_day']), 5)
        self.assertTrue(answer['cost_by_stage_day_has_more'])

    def test_a_price_saved_shows_at_once_in_both_forms(self):
        self.assertIsNone(self.client.get(PATH + '?cost=0').json()['known_estimated_usd'])
        rate = {'provider': 'anthropic', 'model': 'claude-actual', 'input_per_million_usd': '1', 'output_per_million_usd': '1',
                'source_url': 'https://example.test/pricing', 'as_of': date.today().isoformat()}
        self.assertEqual(self.client.put(PATH + '/rate', json.dumps(rate), content_type='application/json').status_code, 200)
        self.assertEqual(self.client.get(PATH + '?cost=0').json()['known_estimated_usd'], '0.000660')  # 600 input and 60 output tokens at 1 USD a million
        self.assertTrue(all(r['list_usd'] for r in self.client.get(PATH).json()['cost_by_stage_day']))
        self.assertTrue(AIPriceRate.objects.exists())

    def test_the_page_asks_without_the_cost_view_and_never_reads_it(self):
        js = JS.read_text()
        self.assertIn('/cve/api/settings/ai/usage?days=${days.value}&cost=0', js)
        self.assertNotIn('cost_by_stage_day', js)
