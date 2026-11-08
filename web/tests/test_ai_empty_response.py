"""'anthropic response contained no text' in the nuclei AI targeting path: every response shape through a fake Messages API, the one retry with
a larger reply limit and its cap, never retrying a refusal, one log line per failure, the standard templates when the AI gives nothing, the
negative cache and backoff, the day's cap, and the plain reason on the usage page and in the activity."""
import json
import os
from unittest import mock

from django.test import TestCase

from cveFeed import nuclei_templates as nt
from cveFeed.models import AIUsage
from cveFeed.ai_usage import snapshot
from reNgine import ai_providers as ai
from tests.anthropic_fake import SHAPES, FakeAnthropic, message, text, THINKING

INSTALLED = {'nginx', 'php', 'exposure', 'cve'}
ANSWER = '{"0": {"tags": ["nginx"], "severities": ["high"]}}'


def provider(url):
    return ai.get_provider('anthropic', api_key='not-a-real-key', model='claude-haiku-5-5', base_url=url)


class Isolated(TestCase):
    def setUp(self):
        nt._failed.clear()
        from django.core.cache import cache
        cache.clear()
        patcher = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in ('CVENGINE_AI_MAX_TOKENS', 'CVENGINE_AI_REASONING')}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(cache.clear)
        self.addCleanup(nt._failed.clear)


class ResponseShapeTests(Isolated):
    def test_a_text_block_is_found_among_several_and_after_thinking(self):
        for shape in ('text_only', 'thinking_then_text', 'two_text_blocks'):
            with FakeAnthropic([SHAPES[shape]('{"a": 1}')]) as fake:
                self.assertEqual(provider(fake.url).complete('s', 'u'), '{"a": 1}', shape)

    def test_every_shape_without_text_is_a_provider_error_naming_its_stop_reason(self):
        want = {'thinking_only_max_tokens': ('output_truncated', 'max_tokens'), 'thinking_only_end_turn': ('empty_response', 'end_turn'),
                'refusal': ('refused', 'refusal'), 'empty_content': ('empty_response', 'end_turn'), 'tool_use': ('empty_response', 'tool_use')}
        for shape, (category, stop) in want.items():
            with FakeAnthropic([SHAPES[shape]()]) as fake, self.assertRaises(ai.AIProviderError) as raised:
                provider(fake.url).complete('s', 'u')
            error = raised.exception
            self.assertEqual((error.category, error.stop_reason), (category, stop), shape)
            self.assertEqual(error.usage['input_tokens'], 321, shape)
        row = AIUsage.objects.order_by('id')[0]
        self.assertEqual((row.status, row.error_category, row.stop_reason, row.input_tokens), ('failed', 'output_truncated', 'max_tokens', 321))

    def test_a_success_records_its_stop_reason(self):
        with FakeAnthropic([SHAPES['text_only']()]) as fake:
            provider(fake.url).complete('s', 'u')
        self.assertEqual(AIUsage.objects.get().stop_reason, 'end_turn')


class RetryTests(Isolated):
    def run_with(self, script, **env):
        with mock.patch.dict(os.environ, env), FakeAnthropic(script) as fake:
            try:
                return ai.complete_with_headroom(provider(fake.url), 's', 'u'), fake
            except ai.AIProviderError as error:
                return error, fake

    def test_a_cut_off_with_no_text_is_asked_once_more_with_twice_the_room_and_the_thinking_room(self):
        out, fake = self.run_with([SHAPES['thinking_only_max_tokens'](), SHAPES['text_only']('{"ok": 1}')])
        self.assertEqual(out, '{"ok": 1}')
        self.assertEqual(fake.limits, [4096, 6144])  # 2048 answer + 2048 thinking room; then 2 x 2048 + 2048
        self.assertEqual([r.stop_reason for r in AIUsage.objects.order_by('id')], ['max_tokens', 'end_turn'])  # both are in the usage table

    def test_only_one_retry_then_the_error_stands(self):
        out, fake = self.run_with([SHAPES['thinking_only_max_tokens']()])
        self.assertIsInstance(out, ai.AIProviderError)
        self.assertEqual((out.category, fake.limits), ('output_truncated', [4096, 6144]))
        self.assertEqual(AIUsage.objects.count(), 2)

    def test_the_retry_is_capped_and_skipped_when_it_would_not_be_larger(self):
        out, fake = self.run_with([SHAPES['thinking_only_max_tokens']()], CVENGINE_AI_MAX_TOKENS='3000')
        self.assertEqual(fake.limits, [5048, 8048])  # the owner's 3000 is the answer room: 3000 + 2048 thinking; then 2 x 3000 + 2048
        out, fake = self.run_with([SHAPES['thinking_only_max_tokens']()], CVENGINE_AI_MAX_TOKENS='8192')
        self.assertEqual(fake.limits, [10240, 18432])  # past the old 8192 ceiling: the hard ceiling is 32768
        out, fake = self.run_with([SHAPES['thinking_only_max_tokens']()], CVENGINE_AI_MAX_TOKENS='20000')
        self.assertEqual(fake.limits, [22048, 32768])
        out, fake = self.run_with([SHAPES['thinking_only_max_tokens']()], CVENGINE_AI_MAX_TOKENS='32768')
        self.assertEqual(fake.limits, [32768])

    def test_a_refusal_and_the_other_failures_are_never_retried(self):
        for shape in ('refusal', 'empty_content', 'tool_use', 'thinking_only_end_turn'):
            out, fake = self.run_with([SHAPES[shape]()])
            self.assertIsInstance(out, ai.AIProviderError, shape)
            self.assertEqual(len(fake.requests), 1, shape)

    def test_the_retry_asks_the_days_cap_first(self):
        with FakeAnthropic([SHAPES['thinking_only_max_tokens']()]) as fake, self.assertRaises(ai.AIProviderError):
            ai.complete_with_headroom(provider(fake.url), 's', 'u', allow_retry=lambda: False)
        self.assertEqual(len(fake.requests), 1)

    def test_a_thinking_budget_stays_below_the_larger_limit(self):
        with mock.patch.dict(os.environ, {'CVENGINE_AI_REASONING': 'medium'}), FakeAnthropic([SHAPES['thinking_only_max_tokens'](), SHAPES['text_only']()]) as fake:
            p = provider(fake.url)
            ai.complete_with_headroom(p, 's', 'u')
        for body in fake.requests:
            thinking = body.get('thinking') or {}
            if thinking.get('budget_tokens'):
                self.assertLess(thinking['budget_tokens'], body['max_tokens'])


class PlanFallbackTests(Isolated):
    SIG = [('nginx 1.18.0',)]

    def plan(self, fake, notes=None):
        return nt.ai_plan(self.SIG, provider(fake.url), INSTALLED, notes=notes)

    def test_a_good_answer_still_plans(self):
        with FakeAnthropic([SHAPES['thinking_then_text'](ANSWER)]) as fake:
            self.assertEqual(self.plan(fake)[0], ({'nginx'}, ('high',)))

    def test_a_failure_is_one_line_with_the_stop_reason_and_token_counts_and_no_traceback(self):
        notes = []
        with FakeAnthropic([SHAPES['thinking_only_end_turn']()]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING') as logs:
            self.assertEqual(self.plan(fake, notes), {})
        self.assertEqual(len(logs.records), 1)
        record = logs.records[0]
        self.assertIsNone(record.exc_info)
        line = record.getMessage()
        for part in ('empty_response', 'end_turn', 'input tokens 321', 'output tokens 2048'):
            self.assertIn(part, line)
        self.assertNotIn('\n', line)
        self.assertEqual(notes, ['The model answered with no text (stop reason: end_turn)'])

    def test_a_cut_off_says_so_in_the_words_the_operator_reads(self):
        notes = []
        with FakeAnthropic([SHAPES['thinking_only_max_tokens']()]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING'):
            self.plan(fake, notes)
        self.assertEqual(notes, ['The model answered with no text (it stopped at the token limit)'])
        self.assertEqual(len(fake.requests), 2)  # the one retry

    def test_a_refusal_is_asked_once(self):
        with FakeAnthropic([SHAPES['refusal']()]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING'):
            self.assertEqual(self.plan(fake), {})
        self.assertEqual(len(fake.requests), 1)

    def test_the_standard_templates_stand_when_the_ai_gives_nothing(self):
        profile = {'technologies': ['nginx'], 'services': [], 'exposure': [], 'cves': [], 'light': False}
        with FakeAnthropic([SHAPES['empty_content']()]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING'), \
                mock.patch.object(nt, 'allowed_tags', return_value=set(INSTALLED)), mock.patch.object(nt, 'profile_names', return_value=['nginx']):
            notes = []
            groups, skipped = nt.plan_targeting({'h.test': profile}, provider(fake.url), notes=notes)
        self.assertEqual((groups, skipped), ([{'tags': ['nginx'], 'severities': (), 'hosts': ['h.test']}], []))
        self.assertEqual(len(notes), 1)


class BackoffTests(Isolated):
    SIG = [('nginx 1.18.0',)]

    def test_the_same_request_is_not_asked_again_inside_its_window_and_the_window_grows(self):
        now = [1000.0]
        with mock.patch.object(nt, '_clock', lambda: now[0]), FakeAnthropic([SHAPES['thinking_only_end_turn']()]) as fake, \
                self.assertLogs('cveFeed.nuclei_templates', 'WARNING') as logs:
            p = provider(fake.url)
            ask = lambda notes=None: nt.ai_plan(self.SIG, p, INSTALLED, notes=notes)  # noqa: E731
            ask()
            self.assertEqual(len(fake.requests), 1)
            for _ in range(5):  # a scan pass that comes round again, a retried task
                notes = []
                ask(notes)
                now[0] += 10
            self.assertEqual(len(fake.requests), 1)
            self.assertIn('not asked again', notes[0])
            now[0] += nt.FAILURE_WINDOW  # the window is over
            ask()
            self.assertEqual(len(fake.requests), 2)
            now[0] += nt.FAILURE_WINDOW + 1  # the second window is twice as long
            ask()
            self.assertEqual(len(fake.requests), 2)
            now[0] += nt.FAILURE_WINDOW
            ask()
            self.assertEqual(len(fake.requests), 3)
        self.assertEqual(len(logs.records), 3)  # one line per request that was really made

    def test_another_question_is_not_held_back_by_a_failed_one(self):
        with FakeAnthropic([SHAPES['thinking_only_end_turn'](), SHAPES['text_only'](ANSWER)]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING'):
            p = provider(fake.url)
            nt.ai_plan([('apache',)], p, INSTALLED)
            self.assertEqual(nt.ai_plan(self.SIG, p, INSTALLED)[0][0], {'nginx'})

    def test_a_success_is_not_remembered(self):
        with FakeAnthropic([SHAPES['text_only'](ANSWER)]) as fake:
            p = provider(fake.url)
            nt.ai_plan(self.SIG, p, INSTALLED)
            nt.ai_plan(self.SIG, p, INSTALLED)
        self.assertEqual(len(fake.requests), 2)

    def test_the_shared_cache_holds_it_for_another_worker(self):
        with FakeAnthropic([SHAPES['thinking_only_end_turn']()]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING'):
            p = provider(fake.url)
            nt.ai_plan(self.SIG, p, INSTALLED)
            nt._failed.clear()  # a second process has no copy of its own
            nt.ai_plan(self.SIG, p, INSTALLED)
        self.assertEqual(len(fake.requests), 1)

    def test_the_tag_selection_path_has_the_same_guard(self):
        with FakeAnthropic([SHAPES['thinking_only_end_turn']()]) as fake, self.assertLogs('cveFeed.nuclei_templates', 'WARNING'):
            p = provider(fake.url)
            self.assertEqual(nt.ai_tags_for(['Weird Thing'], p), set())
            self.assertEqual(nt.ai_tags_for(['Weird Thing'], p), set())
        self.assertEqual(len(fake.requests), 1)


class DayCapTests(Isolated):
    def test_over_the_days_cap_nothing_is_asked_and_the_scan_is_told(self):
        for _ in range(3):
            AIUsage.objects.create(provider='anthropic', model='m', stage='nuclei_targeting', status='failed')
        notes = []
        with mock.patch.dict(os.environ, {'CVENGINE_NUCLEI_AI_MAX_PER_DAY': '3'}), FakeAnthropic([SHAPES['text_only'](ANSWER)]) as fake:
            self.assertEqual(nt.ai_plan([('nginx',)], provider(fake.url), INSTALLED, notes=notes), {})
        self.assertEqual(fake.requests, [])
        self.assertIn('CVENGINE_NUCLEI_AI_MAX_PER_DAY', notes[0])

    def test_the_retry_counts_against_the_cap(self):
        for _ in range(2):
            AIUsage.objects.create(provider='anthropic', model='m', stage='nuclei_targeting', status='failed')
        with mock.patch.dict(os.environ, {'CVENGINE_NUCLEI_AI_MAX_PER_DAY': '4'}), FakeAnthropic([SHAPES['thinking_only_max_tokens']()]) as fake, \
                self.assertLogs('cveFeed.nuclei_templates', 'WARNING'):
            nt.ai_plan([('nginx',)], provider(fake.url), INSTALLED)
            self.assertEqual(len(fake.requests), 2)  # 3rd call, then the retry is the 4th
            nt._failed.clear()
            from django.core.cache import cache
            cache.clear()
            nt.ai_plan([('nginx',)], provider(fake.url), INSTALLED)
        self.assertEqual(len(fake.requests), 2)  # 4 used: no more

    def test_the_counter_is_a_tunable_with_a_usage_line(self):
        from cveFeed import tunables
        self.assertEqual(tunables.value('nuclei_ai_max_per_day'), 400)
        self.assertEqual(tunables.usage_today()['nuclei_ai_max_per_day'], 0)


class ReasonShownTests(Isolated):
    def test_the_usage_page_data_carries_a_plain_reason_and_the_stop_reason(self):
        with FakeAnthropic([SHAPES['thinking_only_max_tokens']()]) as fake, self.assertRaises(ai.AIProviderError), ai.usage_stage('nuclei_targeting'):
            provider(fake.url).complete('s', 'u')
        row = snapshot()['recent'][0]
        self.assertEqual((row['stop_reason'], row['error_category']), ('max_tokens', 'output_truncated'))
        self.assertTrue(row['reason'].startswith('The model answered with no text (it stopped at the token limit)'))
        self.assertIn('Reasoning', row['reason'])  # the real next step; the automatic retry already asks for more room
        self.assertNotIn('CVENGINE_AI_MAX_TOKENS', row['reason'])
        self.assertNotIn('private reasoning', json.dumps(snapshot(), default=str))

    def test_a_success_has_no_reason(self):
        with FakeAnthropic([SHAPES['text_only']()]) as fake:
            provider(fake.url).complete('s', 'u')
        self.assertEqual(snapshot()['recent'][0]['reason'], '')
