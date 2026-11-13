"""Questions an administrator answers after an update (cveFeed.setup_questions): nothing that costs money or changes what is scanned is switched on by an
update, only an App Admin is asked (once per session), a person's earlier choice is never undone, and an answer goes through the Settings handlers."""
import importlib
import json
import os
import re
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from agentapi import settings_bridge as bridge
from agentapi.services import ApiError, Ctx
from cveFeed import reviewer, setup_questions
from cveFeed.models import ReviewerSettings, SetupAnswer
from dashboard.models import AIProviderSettings, AuditLog, Org, Project, ProjectMembership, SetupWizard
from tests.test_tenancy import client_for

API = '/cve/api/settings/setup_questions'


def post(client, body, path=API):
    return client.post(path, json.dumps(body), content_type='application/json')


class Base(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('qadmin', 'q@x.io', 'x')
        self.plain = User.objects.create_user('qplain', 'p@x.io', 'x')
        org = Org.objects.create(name='QOrg', slug='qorg')
        ProjectMembership.objects.create(user=self.plain, project=Project.objects.create(name='QP', slug='qp', org=org), role='user')
        self.c = client_for(self.admin)
        SetupWizard.objects.create(completed_at=timezone.now())  # a finished wizard: an existing install, so the dashboard is not the wizard
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for key in ('CVENGINE_BUILTIN_SCANNER', 'CVENGINE_SENTINEL_PLAN'):
            os.environ.pop(key, None)
        self.dir = tempfile.mkdtemp()
        override = override_settings(BASE_DIR=self.dir)
        override.enable()
        self.addCleanup(override.disable)

    def connect_ai(self):
        AIProviderSettings.objects.create(provider='anthropic', api_key='sk-ant-test', enabled=True)

    def question(self, key, client=None):
        data = (client or self.c).get(API).json()
        return next(q for q in data['questions'] if q['key'] == key)


class MigrationTests(Base):
    def test_the_migrations_answer_nothing(self):
        self.assertEqual(SetupAnswer.objects.count(), 0)
        for name in ('0161_setup_answer', '0162_reviewer_off_until_asked'):
            source = open(os.path.join(os.path.dirname(__file__), '..', 'cveFeed', 'migrations', name + '.py'), encoding='utf-8').read()
            self.assertNotIn('SetupAnswer.objects', source)
        module = importlib.import_module('cveFeed.migrations.0162_reviewer_off_until_asked')
        module.off_until_asked(apps, None)
        self.assertEqual(SetupAnswer.objects.count(), 0)

    def test_an_upgrade_leaves_the_new_ai_features_off_even_with_a_key_saved(self):
        self.connect_ai()
        row = ReviewerSettings.current()  # the row is made on first use, as on an upgraded install
        self.assertEqual((row.enabled, row.auto_close), (False, False))
        self.assertFalse(reviewer.enabled())
        self.assertFalse(reviewer.config()['enabled'])

    def test_a_row_a_build_made_with_both_on_and_no_person_behind_it_is_turned_off(self):
        row = ReviewerSettings.objects.create()
        ReviewerSettings.objects.filter(pk=row.pk).update(enabled=True, auto_close=True)  # what a 1.4 build wrote
        importlib.import_module('cveFeed.migrations.0162_reviewer_off_until_asked').off_until_asked(apps, None)
        row.refresh_from_db()
        self.assertEqual((row.enabled, row.auto_close), (False, False))

    def test_a_persons_earlier_choice_survives(self):
        row = ReviewerSettings.objects.create(enabled=True, auto_close=True, updated_by=self.admin)
        importlib.import_module('cveFeed.migrations.0162_reviewer_off_until_asked').off_until_asked(apps, None)
        row.refresh_from_db()
        self.assertEqual((row.enabled, row.auto_close), (True, True))
        self.connect_ai()
        question = self.question('ai_validation')
        self.assertEqual((question['state'], question['current']), ('decided', 'act'))  # already chosen in Settings: not asked again


class AskingTests(Base):
    def test_an_app_admin_is_taken_to_the_page_once_per_session(self):
        first = self.c.get('/cve/')
        self.assertEqual((first.status_code, first['Location']), (302, '/cve/update-questions/'))
        self.assertEqual(self.c.get('/cve/').status_code, 200)  # not again in this session
        self.assertEqual(self.c.get('/cve/update-questions/').status_code, 200)  # and the page itself never redirects
        self.assertEqual(client_for(self.admin).get('/cve/')['Location'], '/cve/update-questions/')  # a new session: asked again while nobody answered

    def test_nobody_else_is_redirected_or_blocked(self):
        plain = client_for(self.plain)
        self.assertEqual(plain.get('/cve/').status_code, 200)
        page = plain.get('/cve/update-questions/')
        self.assertEqual((page.status_code, page['Location']), (302, '/cve/'))
        self.assertEqual(plain.get('/cve/').status_code, 200)

    def test_the_api_static_and_other_routes_are_never_redirected(self):
        for path in ('/cve/api/settings/alerts', API, '/cve/settings/', '/cve/?skip=1', '/staticfiles/cve/cve.css'):
            response = client_for(self.admin).get(path)
            self.assertNotEqual(response.status_code, 302, path)
        request = RequestFactory().post('/cve/')  # only a plain page load is sent anywhere
        request.user, request.session = self.admin, {}
        self.assertFalse(setup_questions.should_redirect(request))

    def test_decide_later_ends_the_redirect_changes_nothing_and_keeps_a_reminder(self):
        self.connect_ai()
        out = post(self.c, {'later': True})
        self.assertEqual(out.status_code, 200)
        self.assertEqual((out.json()['pending'], out.json()['later']), (0, 2))
        self.assertEqual(client_for(self.admin).get('/cve/').status_code, 200)
        self.assertFalse(ReviewerSettings.current().enabled)
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))
        reminder = client_for(self.admin).get('/cve/api/settings/alerts').json()['questions']
        self.assertEqual(reminder['open'], 2)
        self.assertEqual(set(answer.answer for answer in SetupAnswer.objects.all()), {'later'})

    def test_no_reminder_and_no_redirect_once_everything_is_answered(self):
        self.connect_ai()
        self.assertEqual(post(self.c, {'key': 'ai_validation', 'answer': 'off'}).status_code, 200)
        self.assertEqual(post(self.c, {'key': 'scan_from', 'answer': 'internal'}).status_code, 200)
        self.assertEqual(client_for(self.admin).get('/cve/').status_code, 200)
        self.assertIsNone(self.c.get('/cve/api/settings/alerts').json()['questions'])

    def test_a_question_that_does_not_apply_is_not_asked(self):
        question = self.question('ai_validation')  # no AI model connected
        self.assertEqual((question['state'], question['applies']), ('not_applicable', False))
        self.assertIn('later in Settings', question['why_not'])
        self.assertEqual(post(self.c, {'key': 'ai_validation', 'answer': 'act'}).status_code, 409)
        self.assertFalse(SetupAnswer.objects.filter(key='ai_validation').exists())
        self.assertFalse(ReviewerSettings.objects.exists())

    def test_a_scanner_choice_already_made_elsewhere_is_not_asked(self):
        os.environ['CVENGINE_BUILTIN_SCANNER'] = '0'
        self.assertEqual(self.question('scan_from')['state'], 'decided')
        os.environ.pop('CVENGINE_BUILTIN_SCANNER')
        self.assertEqual(self.question('scan_from')['state'], 'pending')
        wizard = SetupWizard.objects.get()
        wizard.data = {'steps': {'plan': 'done'}}
        wizard.save()
        self.assertEqual(self.question('scan_from')['state'], 'decided')  # the wizard of a new install asked it as its own step


class AnswerTests(Base):
    def test_only_an_app_admin_answers_and_an_agent_never_does(self):
        self.connect_ai()
        self.assertEqual(post(client_for(self.plain), {'key': 'ai_validation', 'answer': 'act'}).status_code, 403)
        self.assertEqual(client_for(self.plain).get(API).status_code, 403)
        ctx = Ctx(user=self.admin, token=SimpleNamespace(read_only=False))
        with self.assertRaises(ApiError) as caught:
            bridge.change_setting(ctx, 'setup_questions', {'key': 'ai_validation', 'answer': 'act'})
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(bridge.get_setting(ctx, 'setup_questions')['pending'], 2)  # it can read them
        plain = Ctx(user=self.plain, token=SimpleNamespace(read_only=False))
        with self.assertRaises(ApiError) as caught:
            bridge.get_setting(plain, 'setup_questions')
        self.assertEqual(caught.exception.status, 403)
        entry = next(e for e in bridge.catalogue() if e['name'] == 'setup_questions')
        self.assertEqual((entry['read'], entry['change']), (True, False))
        self.assertFalse(SetupAnswer.objects.exists())
        self.assertFalse(ReviewerSettings.current().enabled)

    def test_an_ai_answer_goes_through_the_reviewer_settings_and_is_audited(self):
        self.connect_ai()
        for answer, expected in (('recommend', (True, False)), ('act', (True, True)), ('off', (False, False))):
            out = post(self.c, {'key': 'ai_validation', 'answer': answer})
            self.assertEqual(out.status_code, 200, out.content)
            row = ReviewerSettings.current()
            self.assertEqual((row.enabled, row.auto_close), expected, answer)
            self.assertEqual(row.updated_by, self.admin)  # the same record Settings keeps: a person chose it
            self.assertEqual(SetupAnswer.objects.get(key='ai_validation').answer, answer)
        self.assertTrue(AuditLog.objects.filter(action='settings.reviewer', actor=self.admin).exists())
        entry = AuditLog.objects.filter(action='setup.question').order_by('-id').first()
        self.assertEqual((entry.target, entry.detail['answer'], entry.actor), ('ai_validation', 'off', self.admin))

    def test_a_choice_that_is_not_offered_is_refused_and_nothing_is_recorded(self):
        self.connect_ai()
        for body in ({'key': 'ai_validation', 'answer': 'maximum'}, {'key': 'nope', 'answer': 'off'}, {'key': 'ai_validation'}, {'answer': 'off'}):
            self.assertIn(post(self.c, body).status_code, (400, 404), body)
        self.assertEqual(post(self.c, {'key': 'scan_from', 'answer': 'everywhere'}).status_code, 400)
        self.assertFalse(SetupAnswer.objects.exists())
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))

    def test_a_failure_of_the_settings_handler_records_nothing(self):
        self.connect_ai()
        from cveFeed import settings_api
        with mock.patch.object(settings_api, 'reviewer_put', side_effect=settings_api.SettingsError(400, 'refused')):
            self.assertEqual(post(self.c, {'key': 'ai_validation', 'answer': 'act'}).status_code, 400)
        self.assertFalse(SetupAnswer.objects.exists())

    def test_the_scanner_answer_is_handed_to_the_host_like_the_settings_page_does_it(self):
        out = post(self.c, {'key': 'scan_from', 'answer': 'both'})
        self.assertEqual(out.status_code, 200, out.content)
        with open(os.path.join(self.dir, '.scanner-plan-wanted')) as f:
            self.assertEqual(f.read().strip(), 'both')
        self.assertTrue(AuditLog.objects.filter(action='scanner_plan.changed', target='both').exists())
        self.assertEqual(SetupAnswer.objects.get(key='scan_from').answer, 'both')

    def test_the_choices_show_the_daily_caps_and_say_the_provider_bills(self):
        self.connect_ai()
        question = self.question('ai_validation')
        self.assertEqual([c['value'] for c in question['choices']], ['off', 'recommend', 'act'])
        self.assertEqual(question['safe_default'], 'off')
        self.assertTrue([c for c in question['choices'] if c['safe']][0]['value'] == 'off')
        for choice in question['choices'][1:]:
            self.assertIn('300 findings a day', choice['effect'])
            self.assertIn('4 times a day', choice['effect'])
            self.assertIn('bills every call', choice['effect'])
        self.assertIn('Nothing is billed', question['choices'][0]['effect'])

    def test_the_questions_list_every_question_with_its_state(self):
        data = self.c.get(API).json()
        self.assertEqual([q['key'] for q in data['questions']], ['scan_from', 'ai_validation'])
        self.assertEqual((data['pending'], data['later'], data['open']), (1, 0, 1))  # the AI one does not apply: no model
        for q in data['questions']:
            self.assertEqual(q['since'], '1.4.0')

    def test_the_wizard_of_a_new_install_asks_the_ai_question_once_a_model_is_connected(self):
        SetupWizard.objects.all().delete()
        state = self.c.get('/cve/api/welcome/state').json()
        self.assertFalse(state['ai_validation']['applies'])
        self.connect_ai()
        state = self.c.get('/cve/api/welcome/state').json()
        self.assertEqual((state['ai_validation']['state'], state['ai_validation']['safe_default']), ('pending', 'off'))
        self.assertFalse(ReviewerSettings.current().enabled)
        self.assertEqual(post(self.c, {'key': 'ai_validation', 'answer': 'recommend'}).status_code, 200)
        self.assertEqual(self.c.get('/cve/api/welcome/state').json()['ai_validation']['state'], 'answered')
        # its words are held to the wizard's calm words (no scanning, sentinel and the like)
        for text in [state['ai_validation']['title'], state['ai_validation']['text']] + [c['label'] + c['effect'] for c in state['ai_validation']['choices']]:
            self.assertIsNone(re.search(r'(?i)scan|discover|finding hosts|queued|found|sentinel', text), text)
        js = open(os.path.join(os.path.dirname(__file__), '..', 'static', 'cve', 'welcome.js'), encoding='utf-8').read()
        self.assertIn("'/cve/api/settings/setup_questions'", js)

    def test_adding_a_question_is_one_registry_entry(self):
        keys = [q.key for q in setup_questions.QUESTIONS]
        self.assertEqual(len(keys), len(set(keys)))
        for q in setup_questions.QUESTIONS:
            self.assertTrue(callable(q.choices) and callable(q.applies) and callable(q.decided) and callable(q.apply), q.key)
