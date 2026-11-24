"""The model for the Nuclei tag choice (stage nuclei_targeting, an AI job the reviewer container answers): the default is resolved from the
provider's list (the cheapest haiku it lists, else the model of everything else), an owner's choice is kept, a refusal or an empty reply is
retried once on the haiku default and both calls are in the usage table, the setting is validated like the others, and the Settings page
carries the row. The choice is made by the container from the job's options (``nuclei_templates.nuclei_options``); its request layer is
imported from reviewer/ and talks to the fake Anthropic API (tests/anthropic_fake.py): no network, no key."""
import json
import os
import sys
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase

from cveFeed import nuclei_templates as nt
from cveFeed.ai_usage import snapshot
from cveFeed.models import AIUsage
from dashboard.models import AIProviderSettings, AuditLog, Org, OrgMembership
from cvengine import ai_nuclei_model as anm
from cvengine import ai_providers as ai
from tests.anthropic_fake import SHAPES, FakeAnthropic
from tests.test_settings import send
from tests.test_tenancy import client_for

SONNET, OPUS, HAIKU, HAIKU_OLD = 'claude-sonnet-5-5', 'claude-opus-5-5', 'claude-haiku-5-5', 'claude-haiku-5-0'
LISTED = [SONNET, OPUS, HAIKU_OLD, HAIKU]
ANSWER = '{"0": {"tags": ["nginx"], "severities": ["high"]}}'
WEB = Path(settings.BASE_DIR) if hasattr(settings, 'BASE_DIR') else Path(__file__).resolve().parent.parent
REVIEWER_DIR = str(Path(__file__).resolve().parent.parent.parent / 'reviewer')


def container_llm():
    if REVIEWER_DIR not in sys.path:
        sys.path.insert(0, REVIEWER_DIR)
    from cvengine_reviewer import llm
    llm._HAIKU.clear()
    llm._RESOLVED.clear()
    return llm


def provider(url, model=SONNET):
    return ai.get_provider('anthropic', api_key='not-a-real-key', model=model, base_url=url)


class Isolated(TestCase):
    def setUp(self):
        nt._failed.clear()
        anm._picked.clear()
        cache.clear()
        patcher = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in ('CVENGINE_AI_MAX_TOKENS', 'CVENGINE_AI_REASONING')}, clear=True)
        patcher.start()
        for undo in (patcher.stop, cache.clear, nt._failed.clear, anm._picked.clear):
            self.addCleanup(undo)


class PickTests(TestCase):
    def test_the_cheapest_haiku_by_price_then_an_undated_alias_then_the_newest(self):
        priced = [{'id': 'haiku-a', 'price': 1.0, 'created': 5}, {'id': 'haiku-b', 'price': 0.25, 'created': 1}, {'id': 'sonnet', 'price': 0.01}]
        self.assertEqual(anm.pick_haiku(priced), 'haiku-b')
        unpriced = [{'id': 'claude-haiku-5-0', 'created': 1}, {'id': 'claude-haiku-5-5', 'created': 9}, {'id': 'claude-haiku-5-5-20261001', 'created': 10}]
        self.assertEqual(anm.pick_haiku(unpriced), 'claude-haiku-5-5')  # newest undated alias beats a dated snapshot
        self.assertEqual(anm.pick_haiku([{'id': 'CLAUDE-HAIKU-X', 'created': 1}]), 'CLAUDE-HAIKU-X')

    def test_none_listed_is_none(self):
        self.assertIsNone(anm.pick_haiku([{'id': SONNET}, {'id': OPUS}]))
        self.assertIsNone(anm.pick_haiku([]))
        self.assertIsNone(anm.pick_haiku(None))


class ResolutionTests(Isolated):
    def test_the_settings_page_shows_the_haiku_the_provider_lists_and_everything_else_is_untouched(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, enabled=True)
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.assertEqual(anm.in_force(provider(fake.url), fetch=True), {'model': HAIKU, 'default': HAIKU, 'source': 'haiku'})
        self.assertEqual(AIProviderSettings.objects.get().model, SONNET)

    def test_without_a_haiku_listed_the_page_names_the_everything_else_model(self):
        with FakeAnthropic([SHAPES['text_only']()], models=[SONNET, OPUS]) as fake:
            self.assertEqual(anm.in_force(provider(fake.url), fetch=True)['source'], 'everything_else')

    def test_the_job_carries_the_owners_choice_and_asks_for_the_haiku(self):
        self.assertEqual(nt.nuclei_options(), {'haiku': True})  # the default: the container resolves the haiku from its list
        row = AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=OPUS)
        self.assertEqual(nt.nuclei_options(), {'haiku': True, 'model': OPUS})
        row.refresh_from_db()
        self.assertEqual((row.model, row.nuclei_model), (SONNET, OPUS))  # nothing was written


class ContainerRetryTests(Isolated):
    """The reviewer container applies the rule the server applied before the job moved there (``cvengine_reviewer.llm.complete``)."""

    def ask(self, fake, options):
        llm = container_llm()
        block = {'provider': 'anthropic', 'model': SONNET, 'api_key': 'not-a-real-key', 'base_url': fake.url, 'runtime': {}}
        try:
            text, calls, model = llm.complete(block, 'system', 'user', None, {'max_tokens': 3000, **options})
        except llm.ModelError as error:
            return None, error.calls, error.category
        return text, calls, model

    def test_the_default_is_the_haiku_the_provider_lists(self):
        with FakeAnthropic([SHAPES['text_only'](ANSWER)], models=LISTED, echo_model=True) as fake:
            text, calls, model = self.ask(fake, {'haiku': True})
            self.assertEqual([r['model'] for r in fake.requests], [HAIKU])
        self.assertEqual((text, model), (ANSWER, HAIKU))

    def test_without_a_haiku_listed_it_is_the_everything_else_model_and_nothing_to_retry_on(self):
        with FakeAnthropic([SHAPES['refusal']()], models=[SONNET, OPUS], echo_model=True) as fake:
            text, calls, category = self.ask(fake, {'haiku': True})
            self.assertEqual([r['model'] for r in fake.requests], [SONNET])
        self.assertIsNone(text)
        self.assertIn(category, ('refused', 'empty_response'))  # the fake's refusal shape, as the container's request layer names it

    def test_a_refusal_of_the_owners_choice_is_asked_once_more_on_the_haiku_and_both_calls_are_recorded(self):
        from cveFeed import ai_jobs
        from cveFeed.models import AIJob
        from django.utils import timezone
        from datetime import timedelta
        with FakeAnthropic([SHAPES['refusal'](), SHAPES['text_only'](ANSWER)], models=LISTED, echo_model=True) as fake:
            text, calls, model = self.ask(fake, {'haiku': True, 'model': OPUS})
            self.assertEqual([r['model'] for r in fake.requests], [OPUS, HAIKU])
        self.assertEqual((text, model), (ANSWER, HAIKU))
        job = AIJob.objects.create(kind='nuclei_targeting', stage='nuclei_targeting', status='leased', lease='L',
                                   lease_until=timezone.now() + timedelta(hours=1), context={'signatures': [['nginx']], 'digest': 'd'})
        ai_jobs.submit(job.pk, {'lease': 'L', 'text': text, 'calls': calls, 'provider': 'anthropic', 'model': model})
        rows = list(AIUsage.objects.order_by('id'))
        self.assertEqual([(r.stage, r.model, r.status, r.error_category) for r in rows],
                         [('nuclei_targeting', OPUS, 'failed', calls[0]['category']), ('nuclei_targeting', HAIKU, 'succeeded', '')])
        self.assertIn(calls[0]['category'], ('refused', 'empty_response'))
        stage = {s['stage']: s for s in snapshot()['stages']}['nuclei_targeting']
        self.assertEqual(stage['answered_by'], [HAIKU])  # the usage page says which model answered

    def test_an_empty_reply_is_asked_once_more_the_same_way(self):
        with FakeAnthropic([SHAPES['empty_content'](), SHAPES['text_only'](ANSWER)], models=LISTED, echo_model=True) as fake:
            text, _calls, _model = self.ask(fake, {'haiku': True, 'model': OPUS})
            self.assertEqual([r['model'] for r in fake.requests], [OPUS, HAIKU])
        self.assertEqual(text, ANSWER)

    def test_a_retry_that_is_refused_too_is_final_and_never_a_third_call(self):
        with FakeAnthropic([SHAPES['refusal']()], models=LISTED, echo_model=True) as fake:
            text, calls, category = self.ask(fake, {'haiku': True, 'model': OPUS})
            self.assertEqual(len(fake.requests), 2)
        self.assertEqual((text, len(calls)), (None, 2))
        self.assertIn(category, ('refused', 'empty_response'))

    def test_no_retry_when_the_chosen_model_is_the_haiku_or_the_failure_is_another(self):
        with FakeAnthropic([SHAPES['refusal']()], models=LISTED, echo_model=True) as fake:
            self.ask(fake, {'haiku': True, 'model': HAIKU})
            self.assertEqual(len(fake.requests), 1)
        with FakeAnthropic([SHAPES['thinking_only_max_tokens']()], models=LISTED, echo_model=True) as fake:
            self.ask(fake, {'haiku': True, 'model': OPUS})
            self.assertEqual({r['model'] for r in fake.requests}, {OPUS})  # only the larger-limit retry, on the same model

    def test_a_job_without_the_options_is_asked_on_the_configured_model_as_before(self):
        with FakeAnthropic([SHAPES['refusal']()], models=LISTED, echo_model=True) as fake:
            self.ask(fake, {})
            self.assertEqual([r['model'] for r in fake.requests], [SONNET])


class SettingApiTests(Isolated):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('nroot', 'n@x.io', 'x')
        cls.admin = User.objects.create_user('nadmin', password='x')
        org = Org.objects.create(name='N', slug='n-org')
        OrgMembership.objects.create(user=cls.admin, org=org, role='admin')

    def setUp(self):
        super().setUp()
        self.c = client_for(self.root)

    def save_connection(self, fake, **extra):
        return send(self.c, 'PUT', 'ai', {'provider': 'anthropic', 'api_key': 'not-a-real-key', 'base_url': fake.url, 'model': SONNET, 'enabled': True, **extra})

    def test_a_listed_model_is_saved_and_everything_else_is_not_changed(self):
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.assertEqual(self.save_connection(fake)[0], 200)
            status, data = send(self.c, 'PUT', 'ai', {'nuclei_model': OPUS})
        self.assertEqual(status, 200)
        self.assertEqual((data['nuclei_model'], data['model']), (OPUS, SONNET))
        row = AIProviderSettings.objects.get()
        self.assertEqual((row.nuclei_model, row.model), (OPUS, SONNET))

    def test_an_unknown_model_is_refused_and_nothing_is_stored(self):
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.save_connection(fake)
            status, data = send(self.c, 'PUT', 'ai', {'nuclei_model': 'claude-not-a-model'})
            self.assertEqual(status, 400)
            self.assertIn('lists', data['error'])
            self.assertEqual(send(self.c, 'PUT', 'ai', {'nuclei_model': 'bad name!'})[0], 400)
            self.assertEqual(send(self.c, 'PUT', 'ai', {'nuclei_model': ['x']})[0], 400)
        self.assertEqual(AIProviderSettings.objects.get().nuclei_model, '')

    def test_empty_goes_back_to_the_default(self):
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.save_connection(fake, nuclei_model=OPUS)
            self.assertEqual(AIProviderSettings.objects.get().nuclei_model, OPUS)
            self.assertEqual(send(self.c, 'PUT', 'ai', {'nuclei_model': ''})[1]['nuclei_model'], '')

    def test_a_list_that_cannot_be_read_refuses_a_new_choice_but_not_the_rest_of_the_page(self):
        with FakeAnthropic([SHAPES['text_only']()], models=None) as fake:
            self.save_connection(fake)
            status, data = send(self.c, 'PUT', 'ai', {'nuclei_model': OPUS})
            self.assertEqual(status, 400)
            self.assertIn('could not check', data['error'])
            self.assertEqual(send(self.c, 'PUT', 'ai', {'nuclei_model': '', 'max_tokens': 900})[0], 200)  # an unchanged value is not checked

    def test_changing_the_provider_clears_a_choice_made_for_the_old_one(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=OPUS)
        self.assertEqual(send(self.c, 'PUT', 'ai', {'provider': 'ollama', 'base_url': 'http://ollama.invalid:11434'})[1]['nuclei_model'], '')

    def test_only_a_superuser_and_with_the_csrf_token(self):
        other = client_for(self.admin)
        self.assertEqual(send(other, 'PUT', 'ai', {'nuclei_model': OPUS})[0], 403)
        self.assertIsNone(AIProviderSettings.objects.first())
        strict = Client(enforce_csrf_checks=True)
        strict.cookies = self.c.cookies
        r = strict.put('/cve/api/settings/ai', json.dumps({'nuclei_model': ''}), content_type='application/json')
        self.assertEqual(r.status_code, 403)
        self.assertIsNone(AIProviderSettings.objects.first())

    def test_a_change_is_audited_by_name_and_value(self):
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.save_connection(fake)
            send(self.c, 'PUT', 'ai', {'nuclei_model': OPUS})
            before = AuditLog.objects.filter(action='ai.nuclei_model').count()
            send(self.c, 'PUT', 'ai', {'nuclei_model': OPUS})  # unchanged: not audited again
            self.assertEqual(AuditLog.objects.filter(action='ai.nuclei_model').count(), before)
        entry = AuditLog.objects.filter(action='ai.nuclei_model').latest('id')
        self.assertEqual((entry.actor_name, entry.detail['changed'], entry.detail['nuclei_model']), ('nroot', ['nuclei_model'], OPUS))
        self.assertNotIn('not-a-real-key', json.dumps(entry.detail) + entry.target)

    def test_the_models_list_names_the_default_with_and_without_a_haiku(self):
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.save_connection(fake)
            data = send(self.c, 'POST', 'ai/models', {'refresh': True})[1]
            self.assertEqual(data['nuclei_default'], HAIKU)
            self.assertEqual(send(self.c, 'GET', 'ai')[1]['nuclei_model_in_force'], HAIKU)
        cache.clear()
        anm._picked.clear()
        with FakeAnthropic([SHAPES['text_only']()], models=[SONNET, OPUS]) as fake:
            self.save_connection(fake, api_key='another-key')  # a new address drops a key that was not typed again
            status, data = send(self.c, 'POST', 'ai/models', {'refresh': True})
            self.assertEqual((status, data.get('nuclei_default'), len(data.get('models', []))), (200, '', 2), data)

class PageTests(TestCase):
    """The page is drawn by settings.js; Django serves its shell and the script. The row, its sentence and the classes are in the script, and the
    control is the page's own select (44px high, the shared rule)."""

    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('proot', 'p@x.io', 'x')

    def test_the_settings_page_loads_the_script_that_draws_the_row(self):
        r = client_for(self.root).get('/cve/settings/')
        self.assertEqual(r.status_code, 200)
        self.assertIn('cve/settings.js', r.content.decode())

    def script(self, name):
        return (WEB / 'static' / 'cve' / name).read_text(encoding='utf-8')

    def test_the_row_has_its_title_sentence_picker_and_the_ui_stacks_classes(self):
        js = self.script('settings.js')
        self.assertIn('jobRow("Nuclei targeting and tag selection", "Chooses which detection templates apply to the software found. '
                      'A smaller, faster model works well here and avoids refusals.", nucleiPick)', js)
        self.assertIn('nuclei_model: nucleiPick.value', js)
        self.assertIn('const jobRow = (title, about, pick)', js)
        self.assertIn('"ai-job"', js)
        self.assertIn('"note ai-job-about"', js)
        self.assertRegex(js, r'nucleiPick = modelPicker\(')

    def test_the_picker_is_a_select_of_at_least_44px(self):
        css = self.script('cve.css')
        self.assertRegex(css, r'(?m)^input,select,textarea\{[^}]*min-height:44px')
        self.assertIn('.ai-job-about{', css)
        self.assertNotRegex(css, r'\.ai-model[^{]*select[^{]*\{[^}]*(?<!min-)height:\s*[0-3]\d?px')

    def test_the_usage_page_has_the_answered_by_column(self):
        self.assertRegex(self.script('ai-usage.js'), r'label: "Answered by"')
