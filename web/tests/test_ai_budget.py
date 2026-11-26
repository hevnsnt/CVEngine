"""The AI money budget (cveFeed.ai_budget) and the bulk model of the high-volume stages (cvengine.ai_routing): the spend is priced from the
usage ledger, the queue hands out nothing while a budget is spent and resumes on the next UTC day or month, the page wins over the
environment, the strip says so, and the high-volume stages are sent with the cheaper model."""
import datetime
import json
import os
from decimal import Decimal
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase

from cveFeed import ai_budget, ai_jobs, reviewer
from cveFeed.models import AIJob, AIPriceRate, AIUsage
from cvengine import ai_routing
from dashboard.models import AIProviderSettings
from tests import ai_queue
from tests.test_settings import send
from tests.test_tenancy import client_for

UTC = datetime.timezone.utc
SONNET, HAIKU = 'claude-sonnet-5-5', 'claude-haiku-5-5'
WEB = Path(settings.BASE_DIR) if hasattr(settings, 'BASE_DIR') else Path(__file__).resolve().parent.parent
BUDGET_ENV = (ai_budget.MONTHLY_ENV, ai_budget.DAILY_ENV)


def at(*args):
    return datetime.datetime(*args, tzinfo=UTC)


class Base(TestCase):
    def setUp(self):
        ai_budget.clear_cache()
        ai_routing.forget()
        self.addCleanup(ai_budget.clear_cache)
        self.addCleanup(ai_routing.forget)
        env = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in BUDGET_ENV}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.row = ai_queue.configure('anthropic', model=SONNET)

    def rate(self, model, inp, out, read=None, write=None, provider='anthropic'):
        return AIPriceRate.objects.create(provider=provider, model=model, input_per_million_usd=Decimal(inp), output_per_million_usd=Decimal(out),
                                          cache_read_per_million_usd=None if read is None else Decimal(read),
                                          cache_write_per_million_usd=None if write is None else Decimal(write),
                                          source_url='https://example.com/pricing', as_of=datetime.date(2026, 11, 1))

    def usage(self, when, model=SONNET, provider='anthropic', inp=0, out=0, read=0, write=0, status='succeeded', actual=''):
        return AIUsage.objects.create(provider=provider, model=model, actual_model=actual, stage='finding_triage', status=status,
                                      input_tokens=inp, output_tokens=out, cache_read_tokens=read, cache_write_tokens=write, started_at=when)

    def budget(self, monthly=None, daily=None):
        AIProviderSettings.objects.filter(pk=self.row.pk).update(monthly_budget_usd=monthly, daily_budget_usd=daily)
        self.row.refresh_from_db()
        ai_budget.clear_cache()


class SpendTests(Base):
    def test_price_counts_cache_reads_and_writes_and_an_openai_count_includes_its_cached_tokens(self):
        rate = {'input': Decimal(3), 'output': Decimal(15), 'cache_read': Decimal('0.3'), 'cache_write': Decimal('3.75')}
        totals = {'input': 1_000_000, 'output': 1_000_000, 'cache_read': 1_000_000, 'cache_write': 1_000_000}
        self.assertEqual(ai_budget.price('anthropic', totals, rate), Decimal('22.05'))  # 3 + 15 + 0.30 + 3.75
        self.assertEqual(ai_budget.price('openai', totals, rate), Decimal('19.05'))  # the input count already holds the cached million

    def test_the_month_and_the_day_are_priced_from_the_ledger_in_one_query(self):
        self.rate(SONNET, 3, 15, '0.3', '3.75')
        self.usage(at(2026, 11, 2, 9), inp=1_000_000, out=1_000_000)  # 18.00
        self.usage(at(2026, 11, 26, 1), inp=1_000_000, read=1_000_000, write=1_000_000)  # 3 + 0.30 + 3.75 = 7.05
        self.usage(at(2026, 11, 26, 2), out=100_000, status='failed')  # a failed call that was billed still counts: 1.50
        self.usage(at(2026, 10, 31, 23, 59), inp=9_000_000)  # last month
        with self.assertNumQueries(2):  # the price table and one grouped read of the ledger
            spent = ai_budget.compute_spend(at(2026, 11, 26, 12))
        self.assertEqual(spent['month'], Decimal('26.55'))
        self.assertEqual(spent['day'], Decimal('8.55'))
        self.assertEqual(spent['fallback_models'], [])

    def test_a_model_without_a_rate_counts_at_the_highest_rate_entered(self):
        self.rate(HAIKU, 1, 5, '0.1', '1.25')
        self.rate(SONNET, 3, 15)  # no cache rates: a cache read counts at its input rate, a write at 1.25 times it
        self.usage(at(2026, 11, 20), model='claude-opus-9', inp=1_000_000, out=1_000_000, read=1_000_000, write=1_000_000)
        spent = ai_budget.compute_spend(at(2026, 11, 20, 1))
        self.assertEqual(spent['month'], Decimal('24.75'))  # 3 + 15 + 3 + 3.75: each part at the highest rate entered
        self.assertEqual(spent['fallback_models'], ['claude-opus-9'])

    def test_with_no_rate_entered_every_call_counts_at_the_ceiling_and_self_hosted_calls_cost_nothing(self):
        self.usage(at(2026, 11, 20), inp=1_000_000, out=1_000_000)
        self.usage(at(2026, 11, 20), provider='ollama', model='llama', inp=50_000_000, out=50_000_000)
        spent = ai_budget.compute_spend(at(2026, 11, 20, 1))
        self.assertEqual(spent['month'], ai_budget.CEILING['input'] + ai_budget.CEILING['output'])
        self.assertTrue(spent['no_rates'])

    def test_the_billed_model_is_the_one_the_provider_named(self):
        self.rate(HAIKU, 1, 5)
        self.rate(SONNET, 3, 15)
        self.usage(at(2026, 11, 20), model='', actual=HAIKU, inp=1_000_000)
        self.assertEqual(ai_budget.compute_spend(at(2026, 11, 20, 1))['month'], Decimal(1))


class LimitTests(Base):
    def test_unset_is_no_limit(self):
        self.assertEqual(ai_budget.limits(self.row), {'monthly': (None, 'none'), 'daily': (None, 'none')})
        self.assertEqual(ai_budget.blocked(row=self.row), (False, ''))

    def test_the_environment_applies_when_the_page_sets_nothing_and_the_page_wins_over_it(self):
        with mock.patch.dict(os.environ, {ai_budget.MONTHLY_ENV: '500', ai_budget.DAILY_ENV: '$40.50'}):
            self.assertEqual(ai_budget.limits(self.row), {'monthly': (Decimal('500.00'), 'env'), 'daily': (Decimal('40.50'), 'env')})
            self.budget(monthly=Decimal('250'))
            self.assertEqual(ai_budget.limits(self.row)['monthly'], (Decimal('250.00'), 'setting'))
            self.assertEqual(ai_budget.limits(self.row)['daily'], (Decimal('40.50'), 'env'))

    def test_a_value_that_is_not_an_amount_is_ignored(self):
        for bad in ('ten', '-5', '1e9', 'nan', ''):
            with mock.patch.dict(os.environ, {ai_budget.MONTHLY_ENV: bad}):
                self.assertEqual(ai_budget.limits(self.row)['monthly'], (None, 'none'), bad)


class StateTests(Base):
    def setUp(self):
        super().setUp()
        self.rate(SONNET, 3, 15, '0.3', '3.75')
        self.usage(at(2026, 11, 3), inp=10_000_000, out=4_000_000)  # 30 + 60 = 90.00 this month

    def test_reached_says_how_much_of_what_and_when_it_resumes(self):
        self.budget(monthly=Decimal('90'))
        current = ai_budget.state(at(2026, 11, 26, 8))
        self.assertEqual(current['reached'], 'month')
        self.assertEqual(current['message'], 'AI budget reached: $90.00 of $90.00 this month, resumes 2026-12-01 (UTC).')
        self.assertEqual(current['resumes'], '2026-12-01')

    def test_a_december_month_resumes_in_january(self):
        self.usage(at(2026, 12, 3), inp=10_000_000, out=4_000_000)
        self.budget(monthly=Decimal('50'))
        self.assertEqual(ai_budget.state(at(2026, 12, 31, 23))['resumes'], '2027-01-01')

    def test_the_daily_budget_resumes_the_next_utc_day(self):
        self.usage(at(2026, 11, 26, 1), inp=1_000_000, out=1_000_000)  # 18.00 today
        self.budget(monthly=Decimal('1000'), daily=Decimal('15'))
        current = ai_budget.state(at(2026, 11, 26, 8))
        self.assertEqual(current['reached'], 'day')
        self.assertEqual(current['message'], 'AI budget reached: $18.00 of $15.00 today, resumes 2026-11-27 00:00 UTC.')

    def test_a_warning_at_80_percent(self):
        self.budget(monthly=Decimal('110'))
        current = ai_budget.state(at(2026, 11, 26, 8))
        self.assertEqual((current['reached'], current['warn']), ('', 'month'))
        self.assertIn('81 percent of the monthly budget: $90.00 of $110.00 this month', current['message'])
        self.budget(monthly=Decimal('200'))
        self.assertEqual(ai_budget.state(at(2026, 11, 26, 8))['message'], '')

    def test_the_spend_is_kept_a_minute_and_read_again_when_the_day_changes(self):
        self.budget(monthly=Decimal('1000'))
        ai_budget.spend(at(2026, 11, 26, 8))
        with self.assertNumQueries(0):
            ai_budget.spend(at(2026, 11, 26, 8, 0, 30))
        with self.assertNumQueries(2):
            ai_budget.spend(at(2026, 11, 27, 0, 0, 1))

    def test_a_ledger_that_cannot_be_read_holds_the_work_when_a_budget_is_set(self):
        self.budget(monthly=Decimal('1000'))
        with mock.patch.object(ai_budget, 'compute_spend', side_effect=RuntimeError('db')):
            spent, why = ai_budget.blocked(row=self.row)
        self.assertTrue(spent)
        self.assertIn('could not be checked', why)


class QueueTests(Base):
    """``ai_jobs.next_jobs`` hands out nothing while a budget is spent; the job stays queued and goes out once the month turns."""

    def setUp(self):
        super().setUp()
        admit = mock.patch.object(ai_jobs, '_admit', return_value=True)
        admit.start()
        self.addCleanup(admit.stop)
        self.rate(SONNET, 3, 15, '0.3', '3.75')
        self.usage(at(2026, 11, 25, 12), inp=10_000_000, out=4_000_000)  # 90.00
        self.job = ai_jobs.enqueue('triage', 'finding_triage', system='s', parts=[ai_jobs.text('q')], dedupe='budget-1')

    def hand_out(self, when):
        ai_budget.clear_cache()
        with mock.patch('django.utils.timezone.now', return_value=when):
            return ai_jobs.next_jobs(5, now=when)

    def test_admit_refuses_while_spent_and_resumes_on_rollover(self):
        self.budget(monthly=Decimal('80'))
        self.assertEqual(self.hand_out(at(2026, 11, 30, 23, 59)), [])
        self.assertEqual(AIJob.objects.get(pk=self.job.pk).status, 'queued')
        with mock.patch('django.utils.timezone.now', return_value=at(2026, 11, 30, 23, 59)):
            ok, why = ai_jobs.serving()
        self.assertFalse(ok)
        self.assertTrue(why.startswith('AI budget reached: $90.00 of $80.00 this month, resumes 2026-12-01'))
        handed = self.hand_out(at(2026, 12, 1, 0, 0, 5))
        self.assertEqual([j['id'] for j in handed], [self.job.pk])

    def test_the_daily_budget_resumes_the_next_day(self):
        self.usage(at(2026, 11, 26, 3), inp=1_000_000)
        self.budget(daily=Decimal('2'))
        self.assertEqual(self.hand_out(at(2026, 11, 26, 23)), [])
        self.assertEqual(len(self.hand_out(at(2026, 11, 27, 0, 1))), 1)

    def test_no_budget_hands_out_as_before(self):
        self.assertEqual(len(self.hand_out(at(2026, 11, 30, 12))), 1)

    def test_the_reviewer_stops_its_own_calls_too(self):
        self.budget(monthly=Decimal('80'))
        with mock.patch('django.utils.timezone.now', return_value=at(2026, 11, 30, 12)):
            ai_budget.clear_cache()
            row = reviewer.settings_row()
            row.enabled = True
            row.save()
            self.assertFalse(reviewer.enabled())
            out = reviewer.config()
        self.assertFalse(out['enabled'])
        self.assertFalse(out['jobs_enabled'])
        self.assertIn('AI budget reached', out['why'])


class RoutingTests(Base):
    def setUp(self):
        super().setUp()
        admit = mock.patch.object(ai_jobs, '_admit', return_value=True)
        admit.start()
        self.addCleanup(admit.stop)

    def sent(self, stage, kind='triage', options=None):
        ai_jobs.enqueue(kind, stage, system='s', parts=[ai_jobs.text('q')], dedupe=f'route-{stage}', options=options)
        handed = {j['stage']: j for j in ai_jobs.next_jobs(10)}
        return handed[stage]['options'].get('model')

    def test_the_table_names_each_stage_once_and_only_known_kinds(self):
        self.assertEqual(set(ai_routing.STAGE_MODEL.values()), {ai_routing.BULK, ai_routing.MAIN})
        for stage in ('finding_triage', 'validation_plan', 'cve_detection', 'nuclei_targeting', 'finding_review'):
            self.assertEqual(ai_routing.stage_kind(stage), ai_routing.BULK, stage)
        for stage in ('host_review', 'host_review_repair', 'assessment_review', 'template_generation', 'local_check_suggestion', 'unknown'):
            self.assertEqual(ai_routing.stage_kind(stage), ai_routing.MAIN, stage)

    def test_a_high_volume_stage_goes_out_on_the_bulk_model_and_a_host_review_on_the_main_one(self):
        self.assertEqual(self.sent('finding_triage'), HAIKU)  # Anthropic's cheapest current model
        self.assertIsNone(self.sent('host_review', kind='host_review'))  # no model: the configured one

    def test_the_chosen_bulk_model_a_list_read_and_the_switch(self):
        ai_routing.remember('anthropic', '', [{'id': SONNET, 'created': 3}, {'id': 'claude-haiku-6', 'created': 9}, {'id': HAIKU, 'created': 1}])
        self.assertEqual(ai_routing.bulk_model(self.row), 'claude-haiku-6')  # pick_cheapest_newest of the list the page read
        AIProviderSettings.objects.filter(pk=self.row.pk).update(bulk_model='claude-mini-x')
        self.assertEqual(self.sent('validation_plan', kind='validation_plan'), 'claude-mini-x')
        AIProviderSettings.objects.filter(pk=self.row.pk).update(use_bulk_model=False)
        self.assertIsNone(self.sent('cve_detection', kind='cve_detection'))

    def test_a_model_the_stage_chose_itself_is_kept(self):
        self.assertEqual(self.sent('nuclei_targeting', kind='nuclei_targeting', options={'model': SONNET, 'haiku': True}), SONNET)

    def test_a_self_hosted_server_keeps_its_one_model(self):
        row = ai_queue.configure('vllm', model='local-model')
        self.assertEqual(ai_routing.bulk_model(row), 'local-model')
        self.assertEqual(ai_routing.model_for_stage('finding_triage', row), '')

    def test_the_finding_reviewer_uses_the_bulk_model_unless_one_is_named_for_it(self):
        settings_row = reviewer.settings_row()
        self.assertEqual(reviewer.model_for('review', settings_row, self.row), HAIKU)
        self.assertEqual(reviewer.model_for('ops', settings_row, self.row), reviewer.DEFAULT_MODELS['ops'])
        AIProviderSettings.objects.filter(pk=self.row.pk).update(use_bulk_model=False)
        self.row.refresh_from_db()
        self.assertEqual(reviewer.model_for('review', settings_row, self.row), reviewer.DEFAULT_MODELS['review'])
        settings_row.review_model = 'claude-opus-5-5'
        self.assertEqual(reviewer.model_for('review', settings_row, self.row), 'claude-opus-5-5')


class SettingsAndStripTests(Base):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('budget-root', 'b@x.io', 'x')
        self.c = client_for(self.root)

    def test_the_page_saves_and_shows_the_budget_and_the_bulk_model(self):
        status, data = send(self.c, 'PUT', 'ai', {'monthly_budget_usd': '300', 'daily_budget_usd': '', 'bulk_model': '', 'use_bulk_model': True})
        self.assertEqual(status, 200, data)
        self.assertEqual((data['monthly_budget_usd'], data['daily_budget_usd'], data['use_bulk_model']), ('300.00', None, True))
        self.assertEqual(data['budget']['monthly_source'], 'setting')
        self.assertEqual(data['bulk_model_in_force'], HAIKU)
        self.assertIn('finding_triage', data['bulk_stages'])
        self.assertIn('host_review', data['main_stages'])
        status, data = send(self.c, 'PUT', 'ai', {'monthly_budget_usd': None, 'use_bulk_model': False})
        self.assertEqual((data['monthly_budget_usd'], data['use_bulk_model']), (None, False))

    def test_a_bad_amount_is_refused(self):
        for bad in ('-1', 'lots', '2000000', True):
            self.assertEqual(send(self.c, 'PUT', 'ai', {'monthly_budget_usd': bad})[0], 400, bad)
        self.assertEqual(send(self.c, 'PUT', 'ai', {'bulk_model': 'bad name!'})[0], 400)

    def test_the_strip_tells_an_app_admin_and_no_one_else(self):
        self.rate(SONNET, 3, 15)
        from django.utils import timezone
        self.usage(timezone.now(), inp=10_000_000)  # 30.00
        self.budget(monthly=Decimal('20'))
        body = self.c.get('/cve/api/scanner').json()
        self.assertEqual(body['ai_budget_level'], 'reached')
        self.assertTrue(body['ai_budget_message'].startswith('AI budget reached: $30.00 of $20.00 this month, resumes '))
        member = Client()
        member.force_login(User.objects.create_user('budget-user', password='x'))
        self.assertNotIn('ai_budget_message', member.get('/cve/api/scanner').json())
        self.budget(monthly=Decimal('35'))
        body = self.c.get('/cve/api/scanner').json()
        self.assertEqual(body['ai_budget_level'], 'warn')
        self.budget(monthly=None)
        self.assertNotIn('ai_budget_message', self.c.get('/cve/api/scanner').json())

    def test_the_strip_script_draws_the_budget_line(self):
        js = (WEB / 'static' / 'cve' / 'scannerbar.js').read_text()
        self.assertIn('setNotices("aibudget", budget)', js)
        self.assertIn('s.ai_budget_message', js)
        settings_js = (WEB / 'static' / 'cve' / 'settings.js').read_text()
        for name in ('monthly_budget_usd', 'daily_budget_usd', 'bulk_model', 'use_bulk_model', 'Use the bulk model for high-volume stages'):
            self.assertIn(name, settings_js)
