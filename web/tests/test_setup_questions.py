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
        ProjectMembership.objects.create(user=self.plain, project=Project.objects.create(name='QP', slug='qp', org=org, insert_date=timezone.now()), role='user')
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
        for name in ('0162_setup_answer', '0163_reviewer_off_until_asked'):
            source = open(os.path.join(os.path.dirname(__file__), '..', 'cveFeed', 'migrations', name + '.py'), encoding='utf-8').read()
            self.assertNotIn('SetupAnswer.objects', source)
        module = importlib.import_module('cveFeed.migrations.0163_reviewer_off_until_asked')
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
        importlib.import_module('cveFeed.migrations.0163_reviewer_off_until_asked').off_until_asked(apps, None)
        row.refresh_from_db()
        self.assertEqual((row.enabled, row.auto_close), (False, False))

    def row_of_a_deleted_user(self, **fields):
        """A row a person saved (through the Settings handler, which audits it), whose account was deleted since: ``updated_by`` is emptied (SET_NULL)."""
        gone = User.objects.create_superuser('gone-admin', 'g@x.io', 'x')
        row = ReviewerSettings.objects.create(updated_by=gone, **fields)
        if True:
            AuditLog.objects.create(actor=gone, actor_name='gone-admin', action='settings.reviewer', target='AI reviewer settings', detail={})
        gone.delete()
        row.refresh_from_db()
        self.assertIsNone(row.updated_by_id)
        ReviewerSettings.objects.filter(pk=row.pk).update(enabled=True, auto_close=True)
        return row

    def test_a_choice_of_a_person_whose_account_was_deleted_is_not_undone(self):
        row = self.row_of_a_deleted_user()  # on, closing on, and the audit record of the save
        importlib.import_module('cveFeed.migrations.0163_reviewer_off_until_asked').off_until_asked(apps, None)
        row.refresh_from_db()
        self.assertEqual((row.enabled, row.auto_close), (True, True))

    def test_a_row_that_is_not_what_the_builds_made_is_not_touched_either(self):
        row = ReviewerSettings.objects.create(review_daily_max=500)  # no audit record and no user, but a person chose 500
        ReviewerSettings.objects.filter(pk=row.pk).update(enabled=True, auto_close=True)
        importlib.import_module('cveFeed.migrations.0163_reviewer_off_until_asked').off_until_asked(apps, None)
        row.refresh_from_db()
        self.assertEqual((row.enabled, row.auto_close), (True, True))

    def test_a_persons_earlier_choice_survives(self):
        row = ReviewerSettings.objects.create(enabled=True, auto_close=True, updated_by=self.admin)
        importlib.import_module('cveFeed.migrations.0163_reviewer_off_until_asked').off_until_asked(apps, None)
        row.refresh_from_db()
        self.assertEqual((row.enabled, row.auto_close), (True, True))
        self.connect_ai()
        question = self.question('ai_validation')
        # chosen in Settings before the host review existed: the host review line was never decided, so it is asked once, and stays off until then
        self.assertEqual((question['state'], question['current'], question['new_lines']), ('pending', 'act', []))  # (a state in Settings is not a stale answer: no 'new lines' text)
        self.assertFalse(ReviewerSettings.objects.get().host_review_enabled)
        ReviewerSettings.objects.update(host_review_enabled=True, template_validation_enabled=True)  # a person switched both later lines on in Settings: nothing left to ask
        self.assertEqual(self.question('ai_validation')['state'], 'decided')


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

    def test_the_cost_facts_are_stated_once_and_each_choice_is_one_sentence(self):
        self.connect_ai()
        question = self.question('ai_validation')
        self.assertEqual([c['value'] for c in question['choices']], ['off', 'recommend', 'act'])
        self.assertEqual(question['safe_default'], 'off')
        self.assertEqual([c['value'] for c in question['choices'] if c['safe']], ['off'])
        self.assertEqual(question['facts'][:2], ['Finding review: at most 300 findings a day, one provider call each.', 'Server health check: 4 calls a day.'])
        self.assertIn('Host review: the AI reads every open finding of a host that changed, one provider call per host, at most 100 a day', question['facts'][2])
        self.assertIn('at most 50 safe read-only steps per project a day, and only in a project a person set to automatic', question['facts'][2])
        self.assertIn('AI-written checks: ', question['facts'][3])  # the third line (FA-5), tested in test_template_validation_gate
        self.assertEqual(question['facts'][4], 'Your AI provider bills every call.')
        self.assertEqual(question['choices'][0]['tag'], 'Nothing is billed')
        for choice in question['choices']:
            self.assertNotIn('300', choice['effect'])

    def test_the_scan_question_uses_the_words_of_settings_and_pre_selects_what_runs_now(self):
        from cveFeed import scanner_plan
        question = self.question('scan_from')
        self.assertEqual(question['title'], 'Which scanners will you use?')
        self.assertEqual([c['label'] for c in question['choices']], [o['base'] for o in scanner_plan.decision()['options']])  # the same words as Settings > Sentinels
        self.assertEqual([c['label'] for c in question['choices']], ['Use my own Sentinels only', 'Use the built-in scanner only', 'Use both'])
        self.assertEqual((question['safe_default'], question['current']), ('internal', 'internal'))  # the built-in scanner runs now
        self.assertEqual([c['value'] for c in question['choices'] if c.get('tag') == 'Keeps what runs now'], ['internal'])
        os.environ['CVENGINE_SENTINEL_PLAN'] = ''
        os.environ['CVENGINE_BUILTIN_SCANNER'] = ''
        self.assertEqual(self.question('scan_from')['state'], 'pending')  # an empty value is no choice

    def test_the_answer_that_is_what_runs_now_changes_nothing_and_asks_the_host_for_nothing(self):
        out = post(self.c, {'key': 'scan_from', 'answer': 'internal'})
        self.assertEqual(out.status_code, 200)
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))
        self.assertEqual(SetupAnswer.objects.get(key='scan_from').answer, 'internal')  # the plan value itself is stored
        self.assertIsNone(self.question('scan_from')['next'])

    def test_external_with_no_sentinel_keeps_the_scanner_until_the_first_one_checks_in(self):
        with mock.patch('cveFeed.scanner_plan.externals_live', return_value=0):
            out = post(self.c, {'key': 'scan_from', 'answer': 'external'})
            self.assertEqual(out.status_code, 200, out.content)
            self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))  # nothing was switched off: scanning goes on
            question = self.question('scan_from')
            self.assertTrue(question['next']['waiting'])
            self.assertIn('nothing was switched off', question['next']['notes'][0])
            self.assertEqual([s['text'] for s in question['next']['steps']][0], 'Install a Sentinel inside your network')
            self.assertIn('only if you scan inside your network', question['next']['steps'][1]['text'])
            self.c.get('/cve/api/settings/alerts')  # still none live: still nothing
            self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))
        with mock.patch('cveFeed.scanner_plan.externals_live', return_value=1):
            self.c.get('/cve/api/settings/alerts')  # the first Sentinel is live: the choice is applied
        with open(os.path.join(self.dir, '.scanner-plan-wanted')) as f:
            self.assertEqual(f.read().strip(), 'external')
        self.assertTrue([a for a in AuditLog.objects.filter(action='scanner_plan.changed') if 'first Sentinel' in a.detail.get('via', '')])

    def test_external_with_a_sentinel_switches_to_your_own_sentinels_at_once(self):
        with mock.patch('cveFeed.scanner_plan.externals_live', return_value=2):
            self.assertEqual(post(self.c, {'key': 'scan_from', 'answer': 'external'}).status_code, 200)
        with open(os.path.join(self.dir, '.scanner-plan-wanted')) as f:
            self.assertEqual(f.read().strip(), 'external')
        self.assertFalse(self.question('scan_from')['next']['waiting'])

    def test_one_request_saves_every_answer_or_none(self):
        self.connect_ai()
        out = post(self.c, {'answers': {'scan_from': 'internal', 'ai_validation': 'recommend'}})
        self.assertEqual(out.status_code, 200, out.content)
        self.assertEqual(dict(SetupAnswer.objects.values_list('key', 'answer')), {'scan_from': 'internal', 'ai_validation': 'recommend'})
        self.assertEqual((out.json()['pending'], out.json()['open']), (0, 0))  # choosing Off or anything counts as answered: the reminder is gone
        self.assertIsNone(self.c.get('/cve/api/settings/alerts').json()['questions'])
        SetupAnswer.objects.all().delete()
        bad = post(self.c, {'answers': {'scan_from': 'internal', 'ai_validation': 'maximum'}})
        self.assertEqual(bad.status_code, 400)
        self.assertFalse(SetupAnswer.objects.exists())

    def test_a_later_answer_the_settings_refuse_applies_and_records_nothing_and_names_the_question(self):
        self.connect_ai()
        from cveFeed import settings_api
        with mock.patch.object(settings_api, 'scanner_plan_post', side_effect=settings_api.SettingsError(400, 'the host helper is not reachable')):
            out = post(self.c, {'answers': {'ai_validation': 'act', 'scan_from': 'both'}})  # the scanner plan is refused after the AI answer was carried out
        self.assertEqual(out.status_code, 400)
        self.assertIn('Which scanners will you use?', out.json()['error'])
        self.assertIn('the host helper is not reachable', out.json()['error'])
        self.assertFalse(SetupAnswer.objects.exists())
        row = ReviewerSettings.current()
        self.assertEqual((row.enabled, row.auto_close, row.host_review_enabled, row.template_validation_enabled), (False, False, False, False))
        self.assertFalse(AuditLog.objects.filter(action__in=('setup.question', 'settings.reviewer')).exists())
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))

    def test_the_scanner_plan_runs_last_so_a_refusal_after_it_cannot_leave_the_host_changed(self):
        self.connect_ai()
        from cveFeed import settings_api
        with mock.patch.object(settings_api, 'reviewer_put', side_effect=settings_api.SettingsError(400, 'refused')):
            out = post(self.c, {'answers': {'scan_from': 'both', 'ai_validation': 'act'}})  # the scanner answer is listed first
        self.assertEqual(out.status_code, 400)
        self.assertIn('Do you want AI validation?', out.json()['error'])
        self.assertFalse(SetupAnswer.objects.exists())
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))  # the file the host helper reads was never written

    def test_every_answer_is_saved_together_when_none_is_refused(self):
        self.connect_ai()
        out = post(self.c, {'answers': {'scan_from': 'both', 'ai_validation': 'act'}})
        self.assertEqual(out.status_code, 200, out.content)
        self.assertEqual(SetupAnswer.objects.count(), 2)
        self.assertTrue(os.path.exists(os.path.join(self.dir, '.scanner-plan-wanted')))

    def test_the_reminder_names_the_action(self):
        post(self.c, {'later': True})
        reminder = self.c.get('/cve/api/settings/alerts').json()['questions']
        self.assertEqual(reminder['text'], '1 question about this update is waiting.')
        self.assertEqual(reminder['url'], '/cve/update-questions/')

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


class HostReviewLineTests(Base):
    """The host review is one more line of the AI question: it ships off, an answer given before it existed is asked again for it, and a page answer never
    sets a project to automatic."""

    def setUp(self):
        super().setUp()
        self.connect_ai()
        org = Org.objects.get(slug='qorg')
        self.project = Project.objects.create(name='QP2', slug='qp2', org=org, insert_date=timezone.now())

    def enabled(self):
        return ReviewerSettings.current().host_review_enabled

    def test_a_fresh_install_has_it_off_and_asks(self):
        question = self.question('ai_validation')
        self.assertEqual((question['state'], self.enabled()), ('pending', False))

    def test_an_answer_from_before_the_host_review_is_asked_again_as_one_new_line_and_nothing_is_switched_on(self):
        SetupAnswer.objects.create(key='ai_validation', answer='recommend', answered_by=self.admin)  # version 1: the question before the host review
        ReviewerSettings.objects.create(enabled=True, auto_close=False, updated_by=self.admin)
        question = self.question('ai_validation')
        self.assertEqual((question['state'], question['new_lines'], question['safe_default']), ('pending', ['AI host review', 'AI-written checks'], 'off'))
        self.assertFalse(self.enabled())
        self.assertEqual(self.c.get('/cve/')['Location'], '/cve/update-questions/')  # an administrator is taken to the page again, once
        self.assertEqual(self.question('scan_from')['new_lines'], [])

    def test_each_answer_switches_the_host_review_on_or_leaves_it_off_and_no_project_becomes_automatic(self):
        from cveFeed import host_review
        for answer, expected in (('off', False), ('recommend', True), ('act', True)):
            ReviewerSettings.objects.filter().update(host_review_enabled=False)
            out = post(self.c, {'key': 'ai_validation', 'answer': answer})
            self.assertEqual(out.status_code, 200, out.content)
            self.assertEqual(self.enabled(), expected, answer)
            self.assertEqual(host_review.mode_of(self.project), 'recommend', answer)
            self.assertEqual(SetupAnswer.objects.get(key='ai_validation').version, 3)
        self.assertEqual(self.question('ai_validation')['new_lines'], [])

    def test_an_agent_cannot_answer_it(self):
        from agentapi import settings_bridge as bridge
        from agentapi.services import ApiError, Ctx
        with self.assertRaises(ApiError):
            bridge.change_setting(Ctx(user=self.admin), 'setup_questions', {'key': 'ai_validation', 'answer': 'recommend'})
        self.assertFalse(self.enabled())

    def test_the_page_says_it_in_one_line(self):
        text = (os.path.join(os.path.dirname(__file__), '..', 'static', 'cve', 'update-questions.js'))
        self.assertIn('new line', open(text, encoding='utf-8').read())
        act = next(c for c in self.question('ai_validation')['choices'] if c['value'] == 'act')
        self.assertIn('Host reviews stay on recommend in every project', act['effect'])


class ReaskTests(Base):
    """HV-2: answering the question again for its one new line changes ONLY the new line."""

    def setUp(self):
        super().setUp()
        self.connect_ai()
        ReviewerSettings.objects.create(enabled=True, auto_close=False, updated_by=self.admin)  # the finding review as answered before: on, closing off
        SetupAnswer.objects.create(key='ai_validation', answer='recommend', answered_by=self.admin, version=1)  # the question before the host review

    def state(self):
        row = ReviewerSettings.current()
        return (row.enabled, row.auto_close, row.host_review_enabled)

    def test_the_reask_is_about_the_host_review_alone(self):
        question = self.question('ai_validation')
        self.assertEqual((question['state'], question['new_lines']), ('pending', ['AI host review', 'AI-written checks']))
        self.assertIn('Your earlier answer about finding review', question['text'])
        self.assertEqual([c['value'] for c in question['choices']], ['off', 'recommend'])
        self.assertTrue(all('Your finding review is not changed' in c['effect'] for c in question['choices']))
        self.assertTrue(all('Finding review:' not in f for f in question['facts']))

    def test_switching_the_host_review_on_leaves_the_finding_review_as_it_was(self):
        out = post(self.c, {'key': 'ai_validation', 'answer': 'recommend'})
        self.assertEqual(out.status_code, 200, out.content)
        self.assertEqual(self.state(), (True, False, True))
        self.assertEqual(SetupAnswer.objects.get(key='ai_validation').version, 3)

    def test_the_act_answer_does_not_turn_closing_on(self):
        out = post(self.c, {'key': 'ai_validation', 'answer': 'act'})
        self.assertEqual(out.status_code, 200, out.content)
        self.assertEqual(self.state(), (True, False, True))

    def test_declining_the_host_review_does_not_switch_the_finding_review_off(self):
        out = post(self.c, {'key': 'ai_validation', 'answer': 'off'})
        self.assertEqual(out.status_code, 200, out.content)
        self.assertEqual(self.state(), (True, False, False))

    def test_an_answer_at_the_current_version_still_carries_out_every_line(self):
        SetupAnswer.objects.filter(key='ai_validation').update(version=3)
        post(self.c, {'key': 'ai_validation', 'answer': 'act'})
        self.assertEqual(self.state(), (True, True, True))
