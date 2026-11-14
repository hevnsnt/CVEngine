"""The model for the Nuclei tag choice (stages nuclei_tag_selection and nuclei_targeting): the default is resolved from the provider's list (the
cheapest haiku it lists, else the model of everything else), an owner's choice is kept, a refusal or an empty reply is retried once on the
haiku default and both calls are in the usage table, the setting is validated like the others, and the Settings page carries the row.
All through the fake Anthropic API (tests/anthropic_fake.py): no network, no key."""
import json
import os
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
from reNgine import ai_nuclei_model as anm
from reNgine import ai_providers as ai
from tests.anthropic_fake import SHAPES, FakeAnthropic
from tests.test_settings import send
from tests.test_tenancy import client_for

SONNET, OPUS, HAIKU, HAIKU_OLD = 'claude-sonnet-5-5', 'claude-opus-5-5', 'claude-haiku-5-5', 'claude-haiku-5-0'
LISTED = [SONNET, OPUS, HAIKU_OLD, HAIKU]
ANSWER = '{"0": {"tags": ["nginx"], "severities": ["high"]}}'
WEB = Path(settings.BASE_DIR) if hasattr(settings, 'BASE_DIR') else Path(__file__).resolve().parent.parent


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
    def test_the_default_is_the_haiku_the_provider_lists_and_everything_else_is_untouched(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, enabled=True)
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            base = provider(fake.url)
            main, retry = anm.plan(base)
            self.assertEqual(main.model, HAIKU)
            self.assertIsNone(retry)  # the request already runs on the haiku
            self.assertEqual(base.model, SONNET)
            self.assertEqual(anm.in_force(base, fetch=True), {'model': HAIKU, 'default': HAIKU, 'source': 'haiku'})
        self.assertEqual(AIProviderSettings.objects.get().model, SONNET)

    def test_without_a_haiku_listed_it_falls_back_to_the_everything_else_model(self):
        with FakeAnthropic([SHAPES['text_only']()], models=[SONNET, OPUS]) as fake:
            base = provider(fake.url)
            main, retry = anm.plan(base)
            self.assertIs(main, base)
            self.assertIsNone(retry)
            self.assertEqual(anm.in_force(base, fetch=True)['source'], 'everything_else')

    def test_a_list_that_cannot_be_read_is_the_same_as_none_listed(self):
        with FakeAnthropic([SHAPES['text_only']()], models=None) as fake:  # no /v1/models
            base = provider(fake.url)
            self.assertEqual(anm.plan(base), (base, None))

    def test_the_owners_choice_is_used_and_the_haiku_is_the_one_retry(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=OPUS)
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            main, retry = anm.plan(provider(fake.url))
            self.assertEqual((main.model, retry.model), (OPUS, HAIKU))

    def test_an_owner_who_chose_the_haiku_keeps_it_and_has_no_other_model_to_retry_on(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=HAIKU_OLD)
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            main, retry = anm.plan(provider(fake.url))
            self.assertEqual((main.model, retry.model), (HAIKU_OLD, HAIKU))

    def test_an_existing_install_gets_the_default_with_no_stored_value(self):
        row = AIProviderSettings.objects.create(provider='anthropic', model=SONNET)  # a row from before this setting
        self.assertEqual(row.nuclei_model, '')
        with FakeAnthropic([SHAPES['text_only']()], models=LISTED) as fake:
            self.assertEqual(anm.plan(provider(fake.url))[0].model, HAIKU)
        row.refresh_from_db()
        self.assertEqual((row.model, row.nuclei_model), (SONNET, ''))  # nothing was written

    def test_a_double_that_is_not_a_provider_is_used_as_it_is(self):
        double = mock.Mock()
        self.assertEqual(anm.plan(double), (double, None))


class RetryTests(Isolated):
    def ask(self, fake, stage='nuclei_targeting'):
        notes = []
        reply = nt._ask(stage, provider(fake.url), 'system', 'user', notes)
        return reply, notes

    def test_a_refusal_is_retried_once_on_the_haiku_and_both_calls_are_recorded(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=SONNET)
        with FakeAnthropic([SHAPES['refusal'](), SHAPES['text_only'](ANSWER)], models=LISTED, echo_model=True) as fake:
            with self.assertLogs('cveFeed.nuclei_templates', 'INFO') as logged:
                reply, notes = self.ask(fake)
            self.assertEqual([r['model'] for r in fake.requests], [SONNET, HAIKU])
        self.assertEqual(reply, ANSWER)
        self.assertEqual(notes, [])
        rows = list(AIUsage.objects.order_by('id'))
        self.assertEqual([(r.stage, r.model, r.status, r.error_category, r.stop_reason) for r in rows],
                         [('nuclei_targeting', SONNET, 'failed', 'refused', 'refusal'), ('nuclei_targeting', HAIKU, 'succeeded', '', 'end_turn')])
        self.assertEqual([m for m in logged.output if 'retried on' in m], [f'INFO:cveFeed.nuclei_templates:refused by {SONNET}, retried on {HAIKU}'])
        self.assertEqual(nt._failed, {})  # the request is not backed off: it was answered

    def test_an_empty_reply_is_retried_the_same_way_for_the_tag_stage(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=OPUS)
        with FakeAnthropic([SHAPES['empty_content'](), SHAPES['text_only']('["nginx"]')], models=LISTED, echo_model=True) as fake:
            reply, _ = self.ask(fake, 'nuclei_tag_selection')
            self.assertEqual([r['model'] for r in fake.requests], [OPUS, HAIKU])
        self.assertEqual(reply, '["nginx"]')
        self.assertEqual(list(AIUsage.objects.order_by('id').values_list('stage', 'status')), [('nuclei_tag_selection', 'failed'), ('nuclei_tag_selection', 'succeeded')])

    def test_no_retry_when_the_configured_model_is_already_the_fallback(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=HAIKU)
        with FakeAnthropic([SHAPES['refusal']()], models=LISTED, echo_model=True) as fake:
            reply, notes = self.ask(fake)
            self.assertEqual(len(fake.requests), 1)
        self.assertIsNone(reply)
        self.assertEqual(AIUsage.objects.count(), 1)
        self.assertTrue(notes and 'declined' in notes[0])
        self.assertEqual(len(nt._failed), 1)  # the backoff of today

    def test_no_retry_by_default_either_because_the_default_is_the_haiku(self):
        with FakeAnthropic([SHAPES['refusal']()], models=LISTED, echo_model=True) as fake:
            self.assertIsNone(self.ask(fake)[0])
            self.assertEqual([r['model'] for r in fake.requests], [HAIKU])

    def test_no_haiku_listed_means_nothing_to_retry_on(self):
        with FakeAnthropic([SHAPES['refusal']()], models=[SONNET, OPUS], echo_model=True) as fake:
            self.assertIsNone(self.ask(fake)[0])
            self.assertEqual(len(fake.requests), 1)

    def test_a_retry_that_is_refused_too_is_the_existing_behaviour_and_never_a_third_call(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=SONNET)
        with FakeAnthropic([SHAPES['refusal']()], models=LISTED, echo_model=True) as fake:
            reply, notes = self.ask(fake)
            self.assertEqual(len(fake.requests), 2)
            self.assertIsNone(reply)
            self.assertTrue(notes and 'declined' in notes[0])
            self.assertEqual(AIUsage.objects.filter(status='failed').count(), 2)
            self.assertEqual(len(nt._failed), 1)
            again, notes_again = self.ask(fake)  # inside the five minutes: not asked at all
            self.assertEqual(len(fake.requests), 2)
        self.assertIsNone(again)
        self.assertIn('not asked again', notes_again[0])

    def test_other_failures_are_not_retried(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=SONNET)
        with FakeAnthropic([SHAPES['thinking_only_max_tokens']()], models=LISTED, echo_model=True) as fake:
            self.assertIsNone(self.ask(fake)[0])
            self.assertEqual({r['model'] for r in fake.requests}, {SONNET})  # only the larger-limit retry of today, on the same model

    def test_the_retry_counts_against_the_days_cap(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=SONNET)
        with FakeAnthropic([SHAPES['refusal'](), SHAPES['text_only'](ANSWER)], models=LISTED, echo_model=True) as fake, \
                mock.patch.object(nt, '_ai_room', side_effect=[True, False]):
            reply, _ = self.ask(fake)
            self.assertEqual(len(fake.requests), 1)
        self.assertIsNone(reply)


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

    def test_the_usage_page_says_which_model_answered_each_job(self):
        AIProviderSettings.objects.create(provider='anthropic', model=SONNET, nuclei_model=SONNET)
        with FakeAnthropic([SHAPES['refusal'](), SHAPES['text_only'](ANSWER)], models=LISTED, echo_model=True) as fake:
            nt._ask('nuclei_targeting', provider(fake.url), 's', 'u', [])
        stage = {s['stage']: s for s in snapshot()['stages']}['nuclei_targeting']
        self.assertEqual(stage['answered_by'], [HAIKU])
        self.assertEqual({m['model']: (m['attempts'], m['successes']) for m in stage['models']}, {SONNET: (1, 0), HAIKU: (1, 1)})
        status, data = send(self.c, 'GET', 'ai/usage')
        self.assertEqual(status, 200)
        self.assertEqual([s['answered_by'] for s in data['stages'] if s['stage'] == 'nuclei_targeting'], [[HAIKU]])


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
