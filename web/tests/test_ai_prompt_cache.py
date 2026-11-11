"""Anthropic prompt caching on both request paths, and the per-stage cost view.

Path 1: the server's own requests (``reNgine.ai_providers.AnthropicProvider._body``: validation plans, Nuclei targeting, the connection test).
Path 2: AI jobs run by the reviewer container (``reviewer/cvengine_reviewer/llm.py``: triage, detection records, local checks, templates):
the server puts the stage's cache lifetime in the job's options and the container marks the system prompt with it. The container's own
two jobs (finding review, operations check) already marked their prompt; they now report what the cache did.
"""
import json
import math
import os
import sys
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import ai_jobs, ai_usage, detection_author as da, reviewer as server_reviewer, validation_plan
from cveFeed.models import AIPriceRate, AIUsage
from reNgine import ai_profiles, ai_providers as ai
from reNgine.ai_profiles import STAGE_CACHE_TTL, cache_min_tokens, stage_cache_ttl

REVIEWER = Path(__file__).resolve().parents[2] / 'reviewer'
LONG = 'You are a careful analyst. ' * 200  # about 1,700 tokens, over every Claude minimum but 4096
SHORT = 'Reply with one word.'
MODELS = ('claude-haiku-5-5', 'claude-sonnet-5-5', 'claude-sonnet-5', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001', 'claude-opus-4-6',
          'claude-opus-4-7', 'claude-opus-5-5', 'claude-3-5-haiku-latest', 'claude-fable-1', 'some-local-model', '')


def container():
    """The reviewer container's request layer, imported from its own directory (it is a separate image)."""
    if str(REVIEWER) not in sys.path:
        sys.path.insert(0, str(REVIEWER))
    from cvengine_reviewer import jobs, llm, profiles
    return llm, profiles, jobs


def provider(model='claude-haiku-5-5', **kw):
    return ai.get_provider('anthropic', api_key='k', model=model, **kw)


def body_of(stage, system, model='claude-haiku-5-5', **kw):
    with ai.usage_stage(stage):
        return provider(model, **kw)._body(system, [{'role': 'user', 'content': 'u'}])


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


class FakeAnthropic:
    """Anthropic's messages endpoint as documented: a marked system block at least the model's minimum is written on the first request and
    read on later ones within its lifetime; ``usage`` reports uncached input, cache writes and cache reads apart. No request leaves the process."""

    def __init__(self):
        self.cache = set()

    def post(self, method, url, headers=None, json=None, timeout=None, **_):
        system = json['system']
        text = system if isinstance(system, str) else ''.join(b['text'] for b in system)
        marked = None if isinstance(system, str) else system[-1].get('cache_control')
        tokens = math.ceil(len(text) / 3.5)
        read = wrote = 0
        if marked and tokens >= cache_min_tokens(json['model']):
            key = (json['model'], text)
            if key in self.cache:
                read = tokens
            else:
                wrote = tokens
                self.cache.add(key)
        usage = {'input_tokens': 5 + (0 if (read or wrote) else tokens), 'output_tokens': 3,
                 'cache_read_input_tokens': read, 'cache_creation_input_tokens': wrote}
        return FakeResponse({'model': json['model'], 'stop_reason': 'end_turn', 'usage': usage, 'content': [{'type': 'text', 'text': '{}'}]})


class ServerRequestTests(TestCase):
    def test_minimums_per_model(self):
        for model, minimum in {'claude-haiku-5-5': 512, 'claude-sonnet-5-5': 512, 'claude-sonnet-5': 1024, 'claude-sonnet-4-6': 1024,
                               'claude-haiku-4-5-20251001': 4096, 'claude-opus-4-6': 4096, 'claude-opus-4-7': 2048, 'claude-opus-5-5': 512,
                               'some-local-model': 4096}.items():
            self.assertEqual(cache_min_tokens(model), minimum, model)

    def test_the_system_prompt_is_marked_with_the_stage_lifetime_and_the_user_turn_never(self):
        body = body_of('validation_plan', LONG)
        self.assertEqual(body['system'], [{'type': 'text', 'text': LONG, 'cache_control': {'type': 'ephemeral'}}])
        self.assertEqual(body_of('cve_detection', LONG)['system'][0]['cache_control'], {'type': 'ephemeral', 'ttl': '1h'})
        self.assertNotIn('cache_control', json.dumps(body['messages']))

    def test_short_prefix_off_stages_the_switch_and_a_gateway_are_left_alone(self):
        self.assertEqual(body_of('cve_detection', SHORT)['system'], SHORT)
        for stage in ('autotune_advisor', 'connection_test', 'nuclei_targeting'):
            self.assertEqual(body_of(stage, LONG)['system'], LONG, stage)
        with mock.patch.dict(os.environ, {'CVENGINE_AI_PROMPT_CACHE': 'off'}):
            self.assertEqual(body_of('cve_detection', LONG)['system'], LONG)
        self.assertEqual(body_of('cve_detection', LONG, base_url='https://gateway.example.test')['system'], LONG)
        self.assertEqual(body_of('cve_detection', LONG, model='mystery')['system'], LONG)  # not Claude: needs 4096

    def test_the_validation_plan_prompt_is_long_enough_to_be_marked(self):
        self.assertIsInstance(body_of('validation_plan', validation_plan.SYSTEM)['system'], list)

    def test_every_listed_lifetime_is_valid(self):
        self.assertTrue(set(STAGE_CACHE_TTL.values()) <= {'5m', '1h', 'off'})
        self.assertEqual(stage_cache_ttl('a stage nobody listed'), '5m')

    def test_a_cache_write_then_a_cache_read_reach_the_ledger(self):
        AIUsage.objects.all().delete()
        server = FakeAnthropic()
        p = provider()
        with mock.patch('reNgine.ai_providers.guarded_request', side_effect=server.post), ai.usage_stage('validation_plan'):
            p.complete(LONG, 'u1')
            p.complete(LONG, 'u2')
        first, second = AIUsage.objects.order_by('id')
        self.assertGreater(first.cache_write_tokens, 1000)
        self.assertEqual((first.cache_read_tokens, second.cache_write_tokens), (0, 0))
        self.assertEqual(second.cache_read_tokens, first.cache_write_tokens)


class JobOptionTests(TestCase):
    def options(self, stage, kind='triage'):
        return ai_jobs.enqueue(kind, stage, system='x', parts=[ai_jobs.text('y')]).packet['options']

    def test_a_job_carries_its_stage_cache_lifetime(self):
        self.assertEqual(self.options('finding_triage')['cache_ttl'], '5m')
        self.assertEqual(self.options('cve_detection', 'cve_detection')['cache_ttl'], '1h')

    def test_an_off_stage_and_the_switch_send_no_lifetime(self):
        self.assertNotIn('cache_ttl', self.options('autotune_advisor', 'autotune_advice'))
        with mock.patch.dict(os.environ, {'CVENGINE_AI_PROMPT_CACHE': 'off'}):
            self.assertNotIn('cache_ttl', self.options('finding_triage'))

    def test_a_stage_may_still_set_its_own(self):
        job = ai_jobs.enqueue('triage', 'finding_triage', system='x', parts=[ai_jobs.text('y')], options={'cache_ttl': '1h'})
        self.assertEqual(job.packet['options']['cache_ttl'], '1h')


class ContainerRequestTests(TestCase):
    """The reviewer container's request: what Anthropic is sent for a pipeline job."""

    def request(self, system, options, model='claude-haiku-5-5', base=''):
        llm, _, _ = container()
        target = llm.Target({'provider': 'anthropic', 'model': model, 'api_key': 'k', 'base_url': base, 'runtime': {}})
        return llm._request(target, system, 'the job data', None, options, None, None, 'none')

    def test_the_real_triage_and_detection_prompts_are_marked_from_the_job_options(self):
        triage = ai_jobs.enqueue('triage', 'finding_triage', system=ai.TRIAGE_SYSTEM_PROMPT, parts=[ai_jobs.text('y')])
        url, _, body = self.request(ai.TRIAGE_SYSTEM_PROMPT, triage.packet['options'])
        self.assertEqual(url.split('/')[2], 'api.anthropic.com')
        self.assertEqual(body['system'], [{'type': 'text', 'text': ai.TRIAGE_SYSTEM_PROMPT, 'cache_control': {'type': 'ephemeral'}}])
        self.assertEqual(body['messages'], [{'role': 'user', 'content': 'the job data'}])
        _, _, body = self.request(da.SYSTEM_PROMPT, {'cache_ttl': '1h'})
        self.assertEqual(body['system'][0]['cache_control'], {'type': 'ephemeral', 'ttl': '1h'})

    def test_no_lifetime_a_gateway_or_a_short_prompt_sends_the_plain_string(self):
        self.assertEqual(self.request(LONG, {})[2]['system'], LONG)
        self.assertEqual(self.request(LONG, {'cache_ttl': 'forever'})[2]['system'], LONG)
        self.assertEqual(self.request(LONG, {'cache_ttl': '5m'}, base='https://gateway.example.test/v1/messages')[2]['system'], LONG)
        self.assertEqual(self.request(SHORT, {'cache_ttl': '5m'})[2]['system'], SHORT)
        self.assertEqual(self.request(LONG, {'cache_ttl': '5m'}, model='mystery')[2]['system'], LONG)

    def test_the_container_copy_of_the_minimum_table_matches_the_server(self):
        _, profiles, _ = container()
        for model in MODELS:
            self.assertEqual(profiles.cache_min_tokens(model), ai_profiles.cache_min_tokens(model), model)

    def test_the_container_own_jobs_report_their_cache_counts(self):
        _, _, jobs = container()
        server = mock.Mock()
        usage = {'input_tokens': 10, 'output_tokens': 4, 'cache_read_tokens': 900, 'cache_write_tokens': 0}
        with mock.patch.object(jobs.llm, 'call', return_value=('{}', usage, 'claude-haiku-5-5')):
            jobs.measured_call(server, 'finding_review', {'provider': 'anthropic', 'model': 'claude-haiku-5-5'}, LONG, 'u', {}, 400)
        report = server.usage.call_args.args[0]
        self.assertEqual((report['cache_read_tokens'], report['cache_write_tokens']), (900, 0))
        AIUsage.objects.all().delete()
        server_reviewer.record_usage({**report, 'duration_ms': 5})
        row = AIUsage.objects.get()
        self.assertEqual((row.stage, row.cache_read_tokens, row.cache_write_tokens), ('finding_review', 900, 0))


class CostViewTests(TestCase):
    def setUp(self):
        AIUsage.objects.all().delete()
        AIPriceRate.objects.all().delete()
        now = timezone.now()
        AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', actual_model='claude-haiku-5-5', stage='cve_detection', status='succeeded',
                               input_tokens=1000, output_tokens=500, cache_read_tokens=2000, cache_write_tokens=0, started_at=now)
        AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', actual_model='claude-haiku-5-5', stage='cve_detection', status='failed',
                               error_category='output_truncated', input_tokens=1000, output_tokens=2048, cache_read_tokens=0, cache_write_tokens=2000, started_at=now)
        AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', stage='finding_triage', status='failed', started_at=now)  # no counts
        AIUsage.objects.create(provider='anthropic', model='claude-haiku-5-5', stage='cve_detection', status='succeeded', input_tokens=1, output_tokens=1,
                               started_at=now - timedelta(days=40))  # outside the window
        AIUsage.objects.create(provider='openai', model='gpt', stage='cve_detection', status='succeeded', input_tokens=9, output_tokens=9, started_at=now)

    def rows(self):
        return {r['stage']: r for r in ai_usage.cost_by_stage_day(days=7)}

    def test_one_row_per_day_stage_and_model_with_the_cache_share(self):
        rows = self.rows()
        row = rows['cve_detection']
        self.assertEqual((row['calls'], row['failed'], row['input_tokens'], row['output_tokens'], row['cache_read_tokens'], row['cache_write_tokens']),
                         (2, 1, 2000, 2548, 2000, 2000))
        self.assertEqual(row['cache_read_share'], round(2000 / 6000, 4))
        self.assertEqual(rows['finding_triage']['unpriced_calls'], 1)
        self.assertEqual(len(rows), 2)  # no openai row, no row older than the window

    def test_no_price_ships_with_the_product(self):
        """Prices are the operator's to enter (owner ruling): with none entered there is no dollar figure, only tokens."""
        self.assertIsNone(self.rows()['cve_detection']['list_usd'])
        self.assertFalse((Path(ai_usage.__file__).parent / 'ai_list_prices.json').exists())

    def test_a_price_entered_on_the_usage_page_prices_the_row(self):
        AIPriceRate.objects.create(provider='anthropic', model='claude-haiku-5-5', input_per_million_usd=1, output_per_million_usd=5,
                                   cache_read_per_million_usd=Decimal('0.1'), cache_write_per_million_usd=Decimal('1.25'), source_url='https://example.test', as_of='2026-11-10')
        self.assertEqual(Decimal(self.rows()['cve_detection']['list_usd']),
                         Decimal('0.002000') + Decimal('0.012740') + Decimal('0.000200') + Decimal('0.002500'))

    def test_a_price_without_cache_rates_gives_no_dollar_figure_not_a_wrong_one(self):
        AIPriceRate.objects.create(provider='anthropic', model='claude-haiku-5-5', input_per_million_usd=1, output_per_million_usd=5,
                                   source_url='https://example.test', as_of='2026-11-10')
        self.assertIsNone(self.rows()['cve_detection']['list_usd'])

    def test_the_usage_snapshot_carries_the_view(self):
        from dashboard.models import AIProviderSettings
        AIProviderSettings.objects.create(provider='anthropic', model='claude-haiku-5-5', api_key='x', enabled=True)
        self.assertTrue(ai_usage.snapshot(7)['cost_by_stage_day'])
