"""FA-5: the automatic validation of AI-written checks (cveFeed.templatevalidate) is new in 1.4 and spends AI calls (two a draft) and promotes drafts to checks that
run on hosts. In 1.3.6 a draft waited for a maintainer's explicit approval and nothing ran it. So it is a line of the AI question: off until a person answers."""
import json

from django.core.cache import cache
from django.utils import timezone

from cveFeed import setup_questions, templatevalidate
from cveFeed.models import AIJob, CVEEntry, GeneratedTemplate, ReviewerSettings, SetupAnswer
from tests.test_setup_questions import API, Base, post

YAML = 'id: x\ninfo: {name: x, severity: low}\n'


class Gate(Base):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.connect_ai()
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-5101', cvss=7.0, published_at=timezone.now(), affected=[])
        self.draft = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='x', yaml=YAML, status='draft', validation_stage='fixture',
                                                      validation_started_at=timezone.now())

    def run_validator(self):
        return templatevalidate.run_pending()

    def jobs(self):
        return AIJob.objects.filter(kind='template_validation').count()


class OffUntilAnswered(Gate):
    def test_an_upgraded_install_with_a_provider_and_the_question_unanswered_makes_no_ai_call(self):
        self.assertFalse(ReviewerSettings.current().template_validation_enabled)
        out = self.run_validator()
        self.assertEqual(self.jobs(), 0)
        self.assertIn('skipped', out)
        self.draft.refresh_from_db()
        self.assertEqual((self.draft.status, self.draft.validation_stage), ('draft', 'fixture'))  # it waits, as in 1.3.6: not even expired

    def test_a_waiting_draft_is_not_expired_while_it_is_off(self):
        GeneratedTemplate.objects.filter(pk=self.draft.pk).update(validation_started_at=timezone.now() - timezone.timedelta(days=30))
        self.run_validator()
        self.draft.refresh_from_db()
        self.assertEqual(self.draft.status, 'draft')

    def test_an_answer_that_arrives_while_off_changes_nothing(self):
        job = type('J', (), {'context': {'template': self.draft.pk, 'phase': 'fixture'}, 'model': ''})()
        self.assertIsNone(templatevalidate.job_answer(job, json.dumps({'vulnerable': None, 'not_affected': None})))
        self.draft.refresh_from_db()
        self.assertEqual((self.draft.status, self.draft.validation_attempts), ('draft', 0))  # no rejection, no retry: nothing happened

    def test_no_stuck_warning_while_it_is_off(self):
        GeneratedTemplate.objects.filter(pk=self.draft.pk).update(validation_started_at=timezone.now() - timezone.timedelta(days=1))
        self.assertIsNone(templatevalidate.problem())

    def test_answering_on_starts_it(self):
        out = post(self.c, {'key': 'ai_validation', 'answer': 'recommend'})
        self.assertEqual(out.status_code, 200, out.content)
        self.assertTrue(ReviewerSettings.current().template_validation_enabled)
        self.run_validator()
        self.assertEqual(self.jobs(), 1)

    def test_answering_off_keeps_it_off(self):
        post(self.c, {'key': 'ai_validation', 'answer': 'off'})
        self.assertFalse(ReviewerSettings.current().template_validation_enabled)
        self.run_validator()
        self.assertEqual(self.jobs(), 0)

    def test_checks_already_promoted_keep_working_and_no_new_validation_starts(self):
        GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='y', yaml=YAML, status='valid', path='/x/y.yaml', validated_at=timezone.now())
        self.run_validator()
        self.assertEqual(GeneratedTemplate.objects.filter(status='valid').count(), 1)
        self.assertEqual(self.jobs(), 0)


class Setting(Gate):
    def test_a_person_sets_it_in_settings_and_an_agent_cannot_turn_it_on(self):
        from cveFeed import settings_api
        from django.test import RequestFactory
        def put(body, agent):
            request = RequestFactory().generic('PUT', '/x', json.dumps(body), content_type='application/json')
            request.user, request.via_agent = self.admin, agent
            return settings_api.reviewer_put(request)
        with self.assertRaises(settings_api.SettingsError) as raised:
            put({'template_validation_enabled': True}, True)
        self.assertEqual(raised.exception.status, 403)
        self.assertFalse(ReviewerSettings.current().template_validation_enabled)
        self.assertTrue(put({'template_validation_enabled': True}, False)['template_validation_enabled'])
        self.assertFalse(put({'template_validation_enabled': False}, True)['template_validation_enabled'])  # an agent may switch it off


class ReaskLine(Gate):
    def test_the_re_ask_changes_only_this_line(self):
        ReviewerSettings.objects.create(enabled=True, auto_close=False, host_review_enabled=True, updated_by=self.admin)
        SetupAnswer.objects.create(key='ai_validation', answer='recommend', answered_by=self.admin, version=2)  # answered with the host review line
        q = self.question('ai_validation')
        self.assertEqual((q['state'], q['new_lines']), ('pending', ['AI-written checks']))
        self.assertEqual([c['value'] for c in q['choices']], ['off', 'recommend'])
        out = post(self.c, {'key': 'ai_validation', 'answer': 'recommend'})
        self.assertEqual(out.status_code, 200, out.content)
        row = ReviewerSettings.current()
        self.assertEqual((row.enabled, row.auto_close, row.host_review_enabled, row.template_validation_enabled), (True, False, True, True))
        self.assertEqual(SetupAnswer.objects.get(key='ai_validation').version, 3)
        self.assertEqual(self.question('ai_validation')['new_lines'], [])

    def test_declining_leaves_the_other_lines_alone(self):
        ReviewerSettings.objects.create(enabled=True, auto_close=True, host_review_enabled=True, updated_by=self.admin)
        SetupAnswer.objects.create(key='ai_validation', answer='act', answered_by=self.admin, version=2)
        post(self.c, {'key': 'ai_validation', 'answer': 'off'})
        row = ReviewerSettings.current()
        self.assertEqual((row.enabled, row.auto_close, row.host_review_enabled, row.template_validation_enabled), (True, True, True, False))

    def test_a_person_who_switched_it_on_in_settings_is_not_asked(self):
        ReviewerSettings.objects.create(enabled=True, host_review_enabled=True, template_validation_enabled=True, updated_by=self.admin)
        self.assertEqual(self.question('ai_validation')['state'], 'decided')

    def test_the_facts_state_what_it_costs(self):
        facts = ' '.join(self.question('ai_validation')['facts'])
        self.assertIn('AI-written checks', facts)
        self.assertIn('two AI calls', facts)
