"""Anthropic spend: prompt caching, the cve_detection reply limit and its one retry, and the per-stage cost view."""
import json
import os
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import ai_usage, detection_author as da
from cveFeed.models import AIPriceRate, AIUsage
from reNgine import ai_providers as ai
from reNgine.ai_profiles import STAGE_CACHE_TTL, STAGE_REPLY_FLOORS, cache_min_tokens, stage_cache_ttl
from tests import ai_spend_fixture as fx

LONG = 'You are a careful analyst. ' * 200  # about 1,700 tokens, over every Claude minimum but 4096
SHORT = 'Reply with one word.'


def provider(model='claude-haiku-5-5', **kw):
	return ai.get_provider('anthropic', api_key='k', model=model, **kw)


def body_of(stage, system, model='claude-haiku-5-5', **kw):
	with ai.usage_stage(stage):
		return provider(model, **kw)._body(system, [{'role': 'user', 'content': 'u'}])


class CacheMarkerTests(TestCase):
	def test_minimums_per_model(self):
		for model, minimum in {'claude-haiku-5-5': 512, 'claude-sonnet-5-5': 512, 'claude-sonnet-5': 1024, 'claude-sonnet-4-6': 1024,
							   'claude-haiku-4-5-20251001': 4096, 'claude-opus-4-6': 4096, 'claude-opus-4-7': 2048, 'claude-opus-5-5': 512,
							   'some-local-model': 4096}.items():
			self.assertEqual(cache_min_tokens(model), minimum, model)

	def test_stable_prefix_is_marked_with_the_stage_lifetime(self):
		five = body_of('finding_triage', LONG)['system']
		self.assertEqual(five, [{'type': 'text', 'text': LONG, 'cache_control': {'type': 'ephemeral'}}])
		hour = body_of('cve_detection', LONG)['system']
		self.assertEqual(hour[0]['cache_control'], {'type': 'ephemeral', 'ttl': '1h'})

	def test_only_the_system_prompt_is_marked_never_the_user_turn(self):
		body = body_of('cve_detection', LONG)
		self.assertEqual(body['messages'], [{'role': 'user', 'content': 'u'}])
		self.assertNotIn('cache_control', json.dumps(body['messages']))

	def test_short_prefix_stage_off_switch_and_gateway_are_left_alone(self):
		self.assertEqual(body_of('cve_detection', SHORT)['system'], SHORT)  # under 512 tokens
		self.assertEqual(body_of('autotune_advisor', LONG)['system'], LONG)  # a stage set to off
		self.assertEqual(body_of('connection_test', LONG)['system'], LONG)
		self.assertEqual(body_of('nuclei_targeting', LONG)['system'], LONG)
		with mock.patch.dict(os.environ, {'CVENGINE_AI_PROMPT_CACHE': 'off'}):
			self.assertEqual(body_of('cve_detection', LONG)['system'], LONG)
		self.assertEqual(body_of('cve_detection', LONG, base_url='https://gateway.example')['system'], LONG)

	def test_a_name_that_is_not_claude_needs_4096_tokens(self):
		self.assertEqual(body_of('cve_detection', LONG, model='mystery')['system'], LONG)

	def test_the_real_stage_prompts_that_are_long_enough_are_the_ones_marked(self):
		from cveFeed import validation_plan, assessment_review
		self.assertIsInstance(body_of('cve_detection', da.SYSTEM_PROMPT)['system'], list)
		self.assertIsInstance(body_of('finding_triage', ai.TRIAGE_SYSTEM_PROMPT)['system'], list)
		self.assertIsInstance(body_of('validation_plan', validation_plan.SYSTEM)['system'], list)
		self.assertIsInstance(body_of('assessment_review', assessment_review.SYSTEM)['system'], str)  # about 140 tokens: too short
		self.assertIsInstance(body_of('local_check_suggestion', ai.LOCAL_CHECK_SYSTEM_PROMPT, model='claude-sonnet-5-5')['system'], list)

	def test_every_listed_lifetime_is_valid(self):
		self.assertTrue(set(STAGE_CACHE_TTL.values()) <= {'5m', '1h', 'off'})
		self.assertEqual(stage_cache_ttl('a stage nobody listed'), '5m')


class LedgerWritesCacheTokensTests(TestCase):
	def setUp(self):
		AIUsage.objects.all().delete()

	def test_cache_write_then_cache_read_reach_the_ledger(self):
		server = fx.FakeAnthropic({'u1': 50, 'u2': 50})
		p = provider()
		with mock.patch('requests.post', side_effect=server.post), ai.usage_stage('finding_triage'):
			server.now = 0
			p.complete(LONG, 'u1')
			server.now = 60
			p.complete(LONG, 'u2')
		first, second = AIUsage.objects.order_by('id')
		self.assertGreater(first.cache_write_tokens, 1000)
		self.assertEqual(first.cache_read_tokens, 0)
		self.assertEqual(second.cache_write_tokens, 0)
		self.assertEqual(second.cache_read_tokens, first.cache_write_tokens)
		self.assertEqual(second.stage, 'finding_triage')

	def test_the_request_carries_the_breakpoint(self):
		server = fx.FakeAnthropic({'u': 5})
		with mock.patch('requests.post', side_effect=server.post) as post, ai.usage_stage('cve_detection'):
			provider().complete(LONG, 'u')
		sent = post.call_args.kwargs['json']['system']
		self.assertEqual(sent[0]['cache_control'], {'type': 'ephemeral', 'ttl': '1h'})


class TruncationTests(TestCase):
	def setUp(self):
		AIUsage.objects.all().delete()

	def test_cve_detection_gets_a_higher_limit_other_stages_keep_2048(self):
		for stage, expected in (('cve_detection', 8192), ('finding_triage', 2048), ('unspecified', 2048)):
			with ai.usage_stage(stage):
				self.assertEqual(ai.reply_limit(provider()), expected, stage)
		self.assertEqual(STAGE_REPLY_FLOORS, {'cve_detection': 8192})

	def test_the_operators_own_limit_is_not_overridden(self):
		with mock.patch.dict(os.environ, {'CVENGINE_AI_MAX_TOKENS': '1500'}), ai.usage_stage('cve_detection'):
			self.assertEqual(ai.reply_limit(provider()), 1500)

	def _ask(self, need):
		server = fx.FakeAnthropic({'u': need})
		with mock.patch('requests.post', side_effect=server.post), ai.usage_stage('cve_detection'):
			try:
				ai.complete_retrying_truncation(provider(), 'sys', 'u')
				ok = True
			except ai.AIProviderError as error:
				self.assertEqual(error.category, 'output_truncated')
				ok = False
		return ok, [r['max_tokens'] for r in server.requests]

	def test_fits_the_first_time_one_call(self):
		self.assertEqual(self._ask(3000), (True, [8192]))

	def test_cut_off_once_is_asked_again_with_twice_the_limit(self):
		self.assertEqual(self._ask(10000), (True, [8192, 16384]))

	def test_never_a_second_retry(self):
		self.assertEqual(self._ask(40000), (False, [8192, 16384]))  # two billed calls, then the error stands
		self.assertEqual(AIUsage.objects.filter(status='failed', error_category='output_truncated').count(), 2)

	def test_other_errors_and_a_limit_at_the_ceiling_are_not_retried(self):
		p = provider()
		with mock.patch.object(p, 'complete', side_effect=ai.AIProviderError('x', category='provider_http')) as call:
			with self.assertRaises(ai.AIProviderError):
				ai.complete_retrying_truncation(p, 's', 'u')
		self.assertEqual(call.call_count, 1)
		with mock.patch.dict(os.environ, {'CVENGINE_AI_MAX_TOKENS': '32768'}):
			server = fx.FakeAnthropic({'u': 99999})
			with mock.patch('requests.post', side_effect=server.post), self.assertRaises(ai.AIProviderError):
				ai.complete_retrying_truncation(provider(), 's', 'u')
			self.assertEqual(len(server.requests), 1)

	def test_the_guidance_path_uses_the_retry(self):
		self.assertIn('complete_retrying_truncation', open(da.__file__).read().split('def revise_with_guidance')[1].split('def _enrich_in_thread')[0])


class SpendFixtureTests(TestCase):
	"""Before and after on one fixture of 400 invented CVEs through the real provider code and the real ledger writer."""

	def setUp(self):
		AIUsage.objects.all().delete()
		self.fixture = fx.cve_fixture()

	def totals(self):
		return {k: sum(getattr(r, f) or 0 for r in AIUsage.objects.all()) for k, f in
				(('input', 'input_tokens'), ('output', 'output_tokens'), ('cache_read', 'cache_read_tokens'), ('cache_write', 'cache_write_tokens'))}

	def test_before_matches_the_ledgers_truncation_rate(self):
		result = fx.run('claude-haiku-5-5', self.fixture, after=False)
		self.assertAlmostEqual(result['failed'] / result['cves'], fx.LEDGER_TRUNCATION_RATE, delta=0.01)
		self.assertEqual(self.totals()['cache_read'] + self.totals()['cache_write'], 0)

	def test_after_loses_fewer_replies_reads_the_cache_and_costs_less_per_completed_cve(self):
		for model in ('claude-haiku-5-5', 'claude-sonnet-5-5'):
			AIUsage.objects.all().delete()
			before = fx.run(model, self.fixture, after=False)
			before_totals, before_usd = self.totals(), self._usd(model)
			AIUsage.objects.all().delete()
			after = fx.run(model, self.fixture, after=True)
			after_totals, after_usd = self.totals(), self._usd(model)
			self.assertLess(after['failed'], before['failed'] / 10, model)
			self.assertLessEqual(after['calls'], after['cves'] + after['cves'] * 0.05)  # retries are rare: calls stay near one a CVE
			self.assertGreater(after_totals['cache_read'], 0)
			self.assertGreater(after_totals['cache_read'] / (after_totals['input'] + after_totals['cache_read'] + after_totals['cache_write']), 0.7)
			done_before, done_after = before['cves'] - before['failed'], after['cves'] - after['failed']
			self.assertLess(after_usd / done_after, before_usd / done_before, model)

	def _usd(self, model):
		return sum(Decimal(row['list_usd']) for row in ai_usage.cost_by_stage_day(days=1))

	def test_one_hour_keeps_the_cache_warm_between_30_minute_runs_five_minutes_does_not(self):
		hour = fx.run('claude-haiku-5-5', self.fixture, after=True)
		writes_hour = sum(r['wrote'] > 0 for r in hour['server'])
		AIUsage.objects.all().delete()
		with mock.patch.dict(STAGE_CACHE_TTL, {'cve_detection': '5m'}):
			five = fx.run('claude-haiku-5-5', self.fixture, after=True)
		writes_five = sum(r['wrote'] > 0 for r in five['server'])
		self.assertEqual(writes_hour, 1)  # one write for the whole day; every run after it reads
		self.assertGreaterEqual(writes_five, 400 // 11)  # a write at the start of every run


class CostViewTests(TestCase):
	def setUp(self):
		AIUsage.objects.all().delete()
		AIPriceRate.objects.all().delete()
		now = timezone.now()
		AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', actual_model='claude-haiku-5-5', stage='cve_detection', status='succeeded',
							   input_tokens=1000, output_tokens=500, cache_read_tokens=2000, cache_write_tokens=0, started_at=now)
		AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', actual_model='claude-haiku-5-5', stage='cve_detection', status='failed',
							   error_category='output_truncated', input_tokens=1000, output_tokens=2048, cache_read_tokens=0, cache_write_tokens=2000, started_at=now)
		AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', stage='finding_triage', status='failed', started_at=now)  # no token counts
		AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', stage='cve_detection', status='succeeded', input_tokens=1, output_tokens=1,
							   started_at=now - timedelta(days=40))  # outside the window
		AIUsage.objects.create(provider='openai', model='gpt', stage='cve_detection', status='succeeded', input_tokens=9, output_tokens=9, started_at=now)

	def test_one_row_per_day_stage_and_model_with_share_and_list_price(self):
		rows = {r['stage']: r for r in ai_usage.cost_by_stage_day(days=7)}
		row = rows['cve_detection']
		self.assertEqual((row['calls'], row['failed'], row['input_tokens'], row['output_tokens'], row['cache_read_tokens'], row['cache_write_tokens']),
						 (2, 1, 2000, 2548, 2000, 2000))
		self.assertEqual(row['cache_read_share'], round(2000 / 6000, 4))
		# haiku 5.5: 2000 in at 0.10, 2548 out at 0.50, 2000 read at 0.01, 2000 written at the 1h rate 0.20 (cve_detection is a 1h stage), per million
		self.assertEqual(Decimal(row['list_usd']), Decimal('0.000200') + Decimal('0.001274') + Decimal('0.000020') + Decimal('0.000400'))
		self.assertEqual(rows['finding_triage']['unpriced_calls'], 1)
		self.assertEqual(len(rows), 2)  # no openai row, no row older than the window

	def test_a_price_entered_on_the_usage_page_wins_over_the_file(self):
		AIPriceRate.objects.create(provider='anthropic', model='claude-haiku-5-5', input_per_million_usd=1, output_per_million_usd=5,
								   cache_read_per_million_usd=Decimal('0.1'), cache_write_per_million_usd=Decimal('1.25'), source_url='https://example.test', as_of='2026-11-10')
		row = {r['stage']: r for r in ai_usage.cost_by_stage_day(days=7)}['cve_detection']
		self.assertEqual(Decimal(row['list_usd']), Decimal('0.002000') + Decimal('0.012740') + Decimal('0.000200') + Decimal('0.002500'))

	def test_a_price_without_cache_rates_gives_no_dollar_figure_not_a_wrong_one(self):
		AIPriceRate.objects.create(provider='anthropic', model='claude-haiku-5-5', input_per_million_usd=1, output_per_million_usd=5,
								   source_url='https://example.test', as_of='2026-11-10')
		self.assertIsNone({r['stage']: r for r in ai_usage.cost_by_stage_day(days=7)}['cve_detection']['list_usd'])

	def test_the_owner_edits_the_rates_in_the_file(self):
		import tempfile
		with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
			json.dump({'models': {'anthropic': {'claude-haiku-5-5': {'input': '10', 'output': '10', 'cache_read': '10', 'cache_write_1h': '10'}}}}, handle)
		row = {r['stage']: r for r in ai_usage.cost_by_stage_day(days=7, path=handle.name)}['cve_detection']
		self.assertEqual(Decimal(row['list_usd']), Decimal('0.08548'))  # 2000 + 2548 + 2000 + 2000 = 8548 tokens at 10 dollars a million
		os.unlink(handle.name)

	def test_a_missing_file_prices_nothing(self):
		self.assertIsNone({r['stage']: r for r in ai_usage.cost_by_stage_day(days=7, path='/nonexistent.json')}['cve_detection']['list_usd'])

	def test_the_shipped_file_parses_and_the_snapshot_carries_the_view(self):
		prices = ai_usage.list_prices()
		self.assertEqual(prices[('anthropic', 'claude-sonnet-5-5')]['cache_read'], Decimal('0.10'))
		self.assertEqual(prices[('anthropic', 'claude-haiku-5-5')]['cache_write_1h'], Decimal('0.20'))
		from dashboard.models import AIProviderSettings
		AIProviderSettings.objects.create(provider='anthropic', model='claude-haiku-5-5', api_key='x', enabled=True)
		self.assertTrue(ai_usage.snapshot(7)['cost_by_stage_day'])


class SpendTable(TestCase):
	"""Prints the before and after table (``CVENGINE_PRINT_SPEND_TABLE=1 python manage.py test tests.test_ai_spend.SpendTable``); a no-op otherwise."""

	def test_print_table(self):
		if not os.environ.get('CVENGINE_PRINT_SPEND_TABLE'):
			self.skipTest('set CVENGINE_PRINT_SPEND_TABLE=1 to print')
		print('\ntail | model | code | attempts | fresh in | cache read | cache write | out | read share | first-try cut | lost CVEs | USD/100 attempts | USD/100 CVEs done')
		for sigma in (1.0, 1.5):
			fixture = fx.cve_fixture(sigma=sigma)
			for model in ('claude-haiku-5-5', 'claude-sonnet-5-5'):
				for after in (False, True):
					AIUsage.objects.all().delete()
					r = fx.run(model, fixture, after=after)
					rows = AIUsage.objects.all()
					t = {k: sum(getattr(x, f) or 0 for x in rows) for k, f in (('i', 'input_tokens'), ('o', 'output_tokens'), ('r', 'cache_read_tokens'), ('w', 'cache_write_tokens'))}
					usd = sum(Decimal(x['list_usd']) for x in ai_usage.cost_by_stage_day(days=1))
					first_cut = sum(1 for x in r['server'] if x['cut'] and x['max_tokens'] in (2048, 8192))
					done = r['cves'] - r['failed']
					print(f"sigma {sigma} | {model} | {'after' if after else 'before'} | {r['calls']} | {t['i']} | {t['r']} | {t['w']} | {t['o']} | "
						  f"{t['r'] / (t['i'] + t['r'] + t['w']):.1%} | {first_cut / r['cves']:.1%} | {r['failed'] / r['cves']:.1%} | "
						  f"{usd / r['calls'] * 100:.4f} | {usd / done * 100:.4f}")
