"""A reply cut off at its limit (``output_truncated``), through the fake Anthropic Messages API: every stage keeps room for its answer AND for the
model's thinking, a cut-off is asked once more with a larger limit (and never a third time), each attempt is a usage row with its stage and
reason, the alert counts only a cut-off that survived the retry and names the stage, and a guard that fails when a stage skips all of it.

The container half (the AI jobs run in the reviewer container) imports ``reviewer/cvengine_reviewer`` and talks to the same fake."""
import ast
import os
import sys
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import ai_jobs
from cveFeed.models import AIJob, AIUsage
from reNgine import ai_profiles as profiles
from reNgine import ai_prompts
from reNgine import ai_providers as ai
from tests.anthropic_fake import SHAPES, FakeAnthropic

REVIEWER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'reviewer')
CUT = SHAPES['thinking_only_max_tokens']
OK = SHAPES['text_only']

# Stages that need no answer room of their own, and why. Every other stage of ``ai_prompts.STAGES`` must be in ``STAGE_ANSWER_CAPS``.
EXEMPT = {'nuclei_tag_selection': 'answered on the default room and asked once more by complete_with_headroom (tests/test_ai_empty_response.py RetryTests)',
          'nuclei_targeting': 'answered on the default room and asked once more by complete_with_headroom (tests/test_ai_empty_response.py RetryTests)',
          'connection_test': 'a fixed ping with a one-word answer, sent from the Settings page; nothing is retried or stored by it'}


def provider(url, model='claude-haiku-5-5', **runtime):
    return ai.get_provider('anthropic', api_key='not-a-real-key', model=model, base_url=url, runtime=profiles.AIRuntime(**runtime) if runtime else None)


class Isolated(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in ('CVENGINE_AI_MAX_TOKENS', 'CVENGINE_AI_REASONING')}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)


class RetryOnceTests(Isolated):
    def test_cut_off_then_answered_with_a_larger_limit(self):
        with FakeAnthropic([CUT(), OK('{"a": 1}')]) as fake, ai.usage_stage('validation_plan'):
            self.assertEqual(ai.complete_with_headroom(provider(fake.url), 's', 'u'), '{"a": 1}')
        first, second = fake.limits
        self.assertGreater(second, first)
        self.assertLessEqual(second, profiles.RETRY_CEILING)
        rows = list(AIUsage.objects.order_by('id').values_list('stage', 'status', 'error_category', 'stop_reason'))
        self.assertEqual(rows, [('validation_plan', 'failed', 'truncated_retried', 'max_tokens'), ('validation_plan', 'succeeded', '', 'end_turn')])

    def test_cut_off_twice_is_one_failure_with_its_stage_and_never_a_third_request(self):
        with FakeAnthropic([CUT(), CUT(), OK()]) as fake, ai.usage_stage('template_generation'), self.assertRaises(ai.AIProviderError) as raised:
            ai.complete_with_headroom(provider(fake.url), 's', 'u')
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(raised.exception.category, 'output_truncated')
        rows = list(AIUsage.objects.order_by('id').values_list('stage', 'error_category'))
        self.assertEqual(rows, [('template_generation', 'truncated_retried'), ('template_generation', 'output_truncated')])

    def test_no_retry_when_the_caller_has_no_room_and_none_after_a_refusal(self):
        with FakeAnthropic([CUT(), OK()]) as fake, ai.usage_stage('validation_plan'), self.assertRaises(ai.AIProviderError):
            ai.complete_with_headroom(provider(fake.url), 's', 'u', allow_retry=lambda: False)
        self.assertEqual(len(fake.requests), 1)
        self.assertEqual(AIUsage.objects.get().error_category, 'output_truncated')  # nothing asked it again: a failure, not a recovery
        with FakeAnthropic([SHAPES['refusal'](), OK()]) as fake, ai.usage_stage('validation_plan'), self.assertRaises(ai.AIProviderError):
            ai.complete_with_headroom(provider(fake.url), 's', 'u')
        self.assertEqual(len(fake.requests), 1)

    def test_the_owners_limit_is_the_base_and_the_retry_stops_at_the_ceiling(self):
        os.environ['CVENGINE_AI_MAX_TOKENS'] = '3000'
        with FakeAnthropic([CUT(), OK()]) as fake, ai.usage_stage('validation_plan'):
            ai.complete_with_headroom(provider(fake.url, model='claude-haiku-4-5'), 's', 'u')  # a model that does not think unless asked
        self.assertEqual(fake.limits, [3000, 6000])
        os.environ['CVENGINE_AI_MAX_TOKENS'] = '20000'
        with FakeAnthropic([CUT(), OK()]) as fake, ai.usage_stage('validation_plan'):
            ai.complete_with_headroom(provider(fake.url, model='claude-haiku-4-5'), 's', 'u')
        self.assertEqual(fake.limits, [20000, profiles.RETRY_CEILING])
        os.environ['CVENGINE_AI_MAX_TOKENS'] = str(profiles.RETRY_CEILING)
        with FakeAnthropic([CUT(), OK()]) as fake, ai.usage_stage('validation_plan'), self.assertRaises(ai.AIProviderError):
            ai.complete_with_headroom(provider(fake.url, model='claude-haiku-4-5'), 's', 'u')
        self.assertEqual(len(fake.requests), 1)  # already at the ceiling: nothing larger to ask for


class ThinkingRoomTests(Isolated):
    def test_a_thinking_budget_is_kept_apart_from_the_answer_room(self):
        os.environ['CVENGINE_AI_REASONING'] = 'high'
        with FakeAnthropic([OK()]) as fake, ai.usage_stage('validation_plan'):
            provider(fake.url, model='claude-sonnet-4-5').complete('s', 'u')
        body = fake.requests[0]
        self.assertEqual(body['thinking'], {'type': 'enabled', 'budget_tokens': 8192})
        self.assertGreaterEqual(body['max_tokens'] - body['thinking']['budget_tokens'], profiles.DEFAULT_REPLY_CAP)  # the whole answer room is left

    def test_an_owner_limit_is_the_answer_room_and_thinking_is_added_on_top(self):
        os.environ.update(CVENGINE_AI_REASONING='medium', CVENGINE_AI_MAX_TOKENS='1500')
        with FakeAnthropic([OK()]) as fake, ai.usage_stage('validation_plan'):
            provider(fake.url, model='claude-sonnet-4-5').complete('s', 'u')
        body = fake.requests[0]
        self.assertEqual((body['max_tokens'], body['thinking']['budget_tokens']), (1500 + 4096, 4096))

    def test_a_model_that_thinks_unless_told_not_to_gets_reserve_without_the_setting(self):
        with FakeAnthropic([OK()]) as fake, ai.usage_stage('validation_plan'):
            provider(fake.url, model='claude-haiku-5-5').complete('s', 'u')
        self.assertEqual(fake.limits, [profiles.DEFAULT_REPLY_CAP + profiles.THINKING_RESERVE[None]])
        with FakeAnthropic([OK()]) as fake, ai.usage_stage('validation_plan'):
            provider(fake.url, model='claude-haiku-5-5', reasoning='off').complete('s', 'u')  # off, and the model can be switched off: none reserved
        self.assertEqual(fake.limits, [profiles.DEFAULT_REPLY_CAP])

    def test_the_stage_answer_room_is_used_by_a_hosted_model_too(self):
        os.environ['CVENGINE_AI_REASONING'] = 'off'
        with FakeAnthropic([OK()]) as fake, ai.usage_stage('template_generation'):
            provider(fake.url, model='claude-haiku-4-5').complete('s', 'u')
        self.assertEqual(fake.limits, [profiles.STAGE_ANSWER_CAPS['template_generation']])
        self.assertGreater(profiles.STAGE_ANSWER_CAPS['template_generation'], profiles.DEFAULT_REPLY_CAP)  # a template is longer than 2048 tokens


class AlertTests(TestCase):
    def rows(self, n, category, stage, status='failed'):
        AIUsage.objects.bulk_create([AIUsage(provider='anthropic', model='m', stage=stage, status=status, error_category=category,
                                             started_at=timezone.now() - timedelta(hours=1)) for _ in range(n)])

    def check(self):
        from cveFeed import reviewer
        with mock.patch('agentapi.system_status.system_status', return_value={'problems': []}):
            return [c for c in reviewer.ops_checks() if c['code'] == 'ai_errors'][0]

    def test_a_cut_off_that_the_retry_fixed_never_alerts(self):
        self.rows(179, 'truncated_retried', 'template_generation')
        check = self.check()
        self.assertEqual((check['state'], check['detail']), ('ok', ''))

    def test_a_cut_off_that_survived_the_retry_names_the_stage_and_gives_the_real_next_step(self):
        self.rows(12, 'output_truncated', 'template_generation')
        self.rows(40, 'truncated_retried', 'finding_triage')
        check = self.check()
        self.assertEqual(check['state'], 'warning')
        self.assertIn('12 output_truncated in template_generation', check['detail'])
        self.assertNotIn('finding_triage', check['detail'].split('Next step')[0])  # the recovered ones are not listed as failures
        self.assertIn('Reasoning', check['detail'])
        self.assertNotRegex(check['detail'].lower(), r'raise.*(token|limit)|max output tokens')
        self.assertEqual(check['facts']['by_stage'], {'template_generation': {'output_truncated': 12}})
        self.assertEqual((check['facts']['cut_off_answered_by_retry'], check['facts']['automatic_retry']), (40, True))

    def test_other_failures_still_alert_with_their_stage(self):
        self.rows(11, 'provider_http', 'finding_triage')
        check = self.check()
        self.assertIn('11 provider_http in finding_triage', check['detail'])
        self.assertNotIn('Next step', check['detail'])


class JobRecordTests(TestCase):
    def job(self, calls, **extra):
        job = AIJob.objects.create(kind='cve_detection', stage='cve_detection', status='leased', lease='L', lease_until=timezone.now() + timedelta(hours=1))
        ai_jobs.submit(job.pk, {'lease': 'L', 'calls': calls, 'provider': 'anthropic', 'model': 'claude-haiku-5-5', **extra})
        return job

    def test_the_container_reports_each_attempt_and_the_server_records_the_recovered_one_apart(self):
        calls = [{'status': 'failed', 'category': 'output_truncated', 'stop_reason': 'max_tokens', 'retried': True, 'output_tokens': 4096},
                 {'status': 'succeeded', 'stop_reason': 'end_turn', 'output_tokens': 700}]
        self.job(calls, text='{}')
        self.assertEqual(list(AIUsage.objects.order_by('id').values_list('stage', 'status', 'error_category', 'stop_reason')),
                         [('cve_detection', 'failed', 'truncated_retried', 'max_tokens'), ('cve_detection', 'succeeded', '', 'end_turn')])

    def test_a_cut_off_that_survived_is_recorded_as_the_failure_it_is(self):
        calls = [{'status': 'failed', 'category': 'output_truncated', 'stop_reason': 'max_tokens', 'retried': True},
                 {'status': 'failed', 'category': 'output_truncated', 'stop_reason': 'max_tokens'}]
        self.job(calls, error='output_truncated', stop_reason='max_tokens')
        self.assertEqual(list(AIUsage.objects.order_by('id').values_list('error_category', flat=True)), ['truncated_retried', 'output_truncated'])


class EveryStageTests(TestCase):
    """The guard: a stage that skips the answer room, the thinking room or the retry fails here."""

    def source_stages(self):
        """The stage each ``ai_jobs.enqueue(...)`` call in the code names (a string, or a module constant of that name)."""
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cveFeed')
        found = {}
        for name in sorted(os.listdir(root)):
            if not name.endswith('.py'):
                continue
            tree = ast.parse(open(os.path.join(root, name), encoding='utf-8').read())
            constants = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                         and isinstance(n.value.value, str) for t in n.targets if isinstance(t, ast.Name)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'enqueue' \
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == 'ai_jobs' and len(node.args) >= 2:
                    arg = node.args[1]
                    stage = arg.value if isinstance(arg, ast.Constant) else constants.get(getattr(arg, 'id', ''))
                    self.assertIsNotNone(stage, f'{name}:{node.lineno}: the stage of this ai_jobs.enqueue must be a string literal or a module constant')
                    found[stage] = f'{name}:{node.lineno}'
        return found

    def test_every_stage_has_an_answer_room_or_a_stated_reason_not_to(self):
        for stage in ai_prompts.STAGES:
            self.assertTrue(stage in profiles.STAGE_ANSWER_CAPS or stage in EXEMPT, f'{stage}: add it to ai_profiles.STAGE_ANSWER_CAPS (and the container copy)')
        for stage, cap in profiles.STAGE_ANSWER_CAPS.items():
            self.assertIn(stage, ai_prompts.STAGES, f'{stage} is in STAGE_ANSWER_CAPS but is not a usage stage')
            self.assertGreaterEqual(cap, 64)
            self.assertLess(cap, profiles.REPLY_CEILING)

    def test_every_stage_a_job_is_queued_for_is_in_the_table(self):
        stages = self.source_stages()
        self.assertTrue({'template_generation', 'finding_triage', 'cve_detection', 'local_check_suggestion', 'rdp_screenshot'} <= set(stages), stages)
        for stage, where in stages.items():
            self.assertIn(stage, profiles.STAGE_ANSWER_CAPS, f'{where}: stage {stage!r} is queued with no answer room')

    def test_every_queued_job_carries_its_answer_room_and_the_retry(self):
        for kind in ai_jobs.HANDLERS:
            stage = {'triage': 'finding_triage', 'local_checks': 'local_check_suggestion', 'autotune_advice': 'autotune_advisor'}.get(kind, kind)
            job = ai_jobs.enqueue(kind, stage, system='s', parts=[{'text': 't'}], dedupe=f'guard:{kind}')
            options = job.packet['options']
            self.assertEqual(options['max_tokens'] > 0 and options['retry_truncated'], True, kind)
            self.assertIn(stage, profiles.STAGE_ANSWER_CAPS, kind)
        job = ai_jobs.enqueue('template_generation', 'template_generation', system='s', parts=[{'text': 't'}], options={'redact_reply': False}, dedupe='guard:x')
        self.assertEqual((job.packet['options']['max_tokens'], job.packet['options']['redact_reply']), (profiles.STAGE_ANSWER_CAPS['template_generation'], False))

    def test_every_stage_survives_a_cut_off_in_the_container(self):
        sys.path.insert(0, REVIEWER_DIR)
        self.addCleanup(sys.path.remove, REVIEWER_DIR)
        from cvengine_reviewer import llm, profiles as theirs
        self.assertEqual(theirs.STAGE_ANSWER_CAPS, profiles.STAGE_ANSWER_CAPS)
        for stage, cap in profiles.STAGE_ANSWER_CAPS.items():
            options = {'max_tokens': cap, 'retry_truncated': True}
            block = {'provider': 'anthropic', 'model': 'claude-haiku-5-5', 'api_key': 'k', 'base_url': '', 'runtime': {}}
            with FakeAnthropic([CUT(), OK('{"a": 1}')]) as fake:
                block['base_url'] = fake.url
                with mock.patch.object(llm, 'resolve_model', lambda target: None):
                    text, calls, _ = llm.complete(block, 's', 'u', None, options)
            first, second = fake.limits
            reserve = profiles.THINKING_RESERVE[None]
            self.assertEqual((text, first), ('{"a": 1}', max(cap, profiles.DEFAULT_REPLY_CAP) + reserve), stage)
            self.assertEqual(second, min(profiles.RETRY_CEILING, 2 * max(cap, profiles.DEFAULT_REPLY_CAP) + reserve), stage)
            self.assertEqual([(c['status'], c.get('retried', False), c['stop_reason']) for c in calls], [('failed', True, 'max_tokens'), ('succeeded', False, 'end_turn')], stage)
            with FakeAnthropic([CUT(), CUT(), OK()]) as fake:
                block['base_url'] = fake.url
                with mock.patch.object(llm, 'resolve_model', lambda target: None), self.assertRaises(llm.ModelError) as raised:
                    llm.complete(block, 's', 'u', None, options)
            self.assertEqual((len(fake.requests), raised.exception.category, len(raised.exception.calls)), (2, 'output_truncated', 2), stage)


class DetectionRecordTests(TestCase):
    """cve_detection was the stage that failed (892 of 914 errors in 8 days on the owner's server): its record is long, and it ran under the
    2048-token default with no retry."""

    def worst_case_record(self):
        from cveFeed import detection
        words = lambda n: 'x' * n
        check = {'id': 'ai-' + words(36), 'kind': 'version_banner', 'description': words(200), 'confidence': 'high',
                 'params': {'product': words(60), 'ranges': [{'introduced': words(20), 'fixed': words(20)}] * 2, 'source': 'http_header'}}
        return {'scope': 'external', 'scope_reason': words(200), 'summary': words(400), 'identify': words(320),
                'remote_checks': [check] * detection.MAX_CHECKS, 'local_checks': [check] * detection.MAX_CHECKS, 'prerequisites': [words(80)] * 3,
                'confirm_steps': [words(240)] * 6, 'true_positive_signs': [words(180)] * 4, 'false_positive_signs': [words(180)] * 4,
                'false_positive_notes': words(400), 'remediation': words(600), 'exploit_precondition': words(300), 'revision_note': words(200),
                'safety': 'read_only'}

    def test_the_stage_room_holds_the_largest_record_the_schema_allows(self):
        import json
        tokens = len(json.dumps(self.worst_case_record(), separators=(',', ':'))) / 3  # 3 characters a token: more than JSON in English costs
        self.assertGreater(tokens, 4000)  # the measure is real: this record would not have fit the 2048 default, nor 4096
        self.assertLessEqual(tokens, profiles.STAGE_ANSWER_CAPS['cve_detection'])
        self.assertLessEqual(2 * profiles.STAGE_ANSWER_CAPS['cve_detection'] + profiles.THINKING_RESERVE[None], profiles.RETRY_CEILING)  # the retry fits too

    def test_the_prompt_asks_for_compact_json(self):
        from cveFeed import detection_author
        self.assertIn('compactly', detection_author.SYSTEM_PROMPT)

    def test_a_record_the_model_cannot_write_backs_off_and_then_stops(self):
        from cveFeed import detection_author as da
        from cveFeed.models import CVEDetection, CVEEntry
        cve = CVEEntry.objects.create(cve_id='CVE-2099-0001', title='t', summary='s')
        row = CVEDetection.objects.create(cve_entry=cve, source='rules', ai_attempted_at=timezone.now())
        job = AIJob.objects.create(kind='cve_detection', stage='cve_detection', context={'record': row.pk, 'purpose': 'author'})
        waits = []
        for attempt in range(1, da.AI_MAX_FAILURES + 1):
            da.job_failure(job, 'output_truncated', {})
            row.refresh_from_db()
            self.assertEqual(row.ai_failures, attempt)
            waits.append(row.ai_retry_at)
            if attempt < da.AI_MAX_FAILURES:
                self.assertIn(f'will retry after', row.ai_problems[0])
                self.assertIn(f'attempt {attempt} of {da.AI_MAX_FAILURES - 1}', row.ai_problems[0])
        self.assertIsNone(waits[-1])
        self.assertIn('could not author', row.ai_problems[0])
        now = timezone.now()
        self.assertFalse(CVEDetection.objects.filter(da.due_q(now + timedelta(days=365)), pk=row.pk).exists())  # given up: never due again

    def test_a_failed_record_is_due_only_after_its_wait(self):
        from cveFeed import detection_author as da
        from cveFeed.models import CVEDetection, CVEEntry
        cve = CVEEntry.objects.create(cve_id='CVE-2099-0002', title='t', summary='s')
        row = CVEDetection.objects.create(cve_entry=cve, source='rules', ai_attempted_at=timezone.now())
        job = AIJob.objects.create(kind='cve_detection', stage='cve_detection', context={'record': row.pk, 'purpose': 'author'})
        da.job_failure(job, 'output_truncated', {})
        now = timezone.now()
        self.assertFalse(CVEDetection.objects.filter(da.due_q(now), pk=row.pk).exists())
        self.assertTrue(CVEDetection.objects.filter(da.due_q(now + timedelta(hours=7)), pk=row.pk).exists())
        self.assertTrue(CVEEntry.objects.filter(da.due_q(now + timedelta(hours=7), 'detection__'), pk=cve.pk).exists())

    def test_an_answer_resets_the_count(self):
        from cveFeed.models import CVEDetection, CVEEntry
        cve = CVEEntry.objects.create(cve_id='CVE-2099-0003', title='t', summary='s')
        row = CVEDetection.objects.create(cve_entry=cve, source='rules', ai_failures=3, ai_retry_at=timezone.now())
        from cveFeed import detection_author as da
        da._apply_answer(row, {'remote_checks': [], 'local_checks': [], 'summary': 's', 'scope': 'external'}, [], 'anthropic:m', 'h')
        row.refresh_from_db()
        self.assertEqual((row.ai_failures, row.ai_retry_at), (0, None))


class UsagePageTests(TestCase):
    def test_a_stage_lists_why_its_attempts_failed_and_what_the_retry_fixed(self):
        now = timezone.now()
        for category, stop, n in (('output_truncated', 'max_tokens', 3), ('truncated_retried', 'max_tokens', 5)):
            AIUsage.objects.bulk_create([AIUsage(provider='anthropic', model='m', stage='cve_detection', status='failed', error_category=category,
                                                 stop_reason=stop, started_at=now) for _ in range(n)])
        AIUsage.objects.create(provider='anthropic', model='m', stage='cve_detection', status='succeeded', started_at=now)
        from cveFeed.ai_usage import snapshot
        stage = [s for s in snapshot()['stages'] if s['stage'] == 'cve_detection'][0]
        self.assertEqual([(f['category'], f['stop_reason'], f['count'], f['recovered']) for f in stage['failed_reasons']],
                         [('output_truncated', 'max_tokens', 3, False), ('truncated_retried', 'max_tokens', 5, True)])
        self.assertEqual(stage['errors_final'], 3)
        script = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static', 'cve', 'ai-usage.js'), encoding='utf-8').read()
        self.assertIn('failed_reasons', script)
