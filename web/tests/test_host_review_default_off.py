"""The AI host review costs the owner real money (one AI call per changed host), so it is OFF until a person turns it on in Settings, and a project starts on
"recommend" (a person starts each step). An update (the migration) never turns it on, whatever AI key is configured; an agent token cannot turn it on or
set a project to automatic. Every test here fails if the default is switched back to on or auto."""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client

from agentapi.auth import create_token
from cveFeed import ai_jobs, host_review
from cveFeed.models import AIJob, HostReview, ProjectSettings, ReviewerSettings
from dashboard.models import OrgMembership
from tests.test_agentapi import call, tool_call
from tests.test_host_review_job import HOST, Fixture


class DefaultOffFixture(Fixture):
    def setUp(self):
        super().setUp()
        ReviewerSettings.objects.filter(pk=ReviewerSettings.current().pk).update(host_review_enabled=False)  # what a fresh migrate leaves
        ProjectSettings.objects.all().delete()
        self.m1 = self.match()
        self.admin = User.objects.create_user('hro-admin', password='pw', is_superuser=True)
        OrgMembership.objects.create(user=self.admin, org=self.org, role='admin')
        self.token = create_token(self.admin, 'agent')[1]
        self.client = Client()
        self.client.force_login(self.admin)

    def put(self, **body):
        return self.client.put('/cve/api/settings/reviewer', data=json.dumps(body), content_type='application/json')


class MigrationDefaultTests(DefaultOffFixture):
    def test_a_migrated_install_with_an_ai_key_queues_no_review_and_makes_no_ai_call(self):
        self.assertTrue(ai_jobs.ai_on())  # the owner has a provider key
        self.assertFalse(ReviewerSettings.current().host_review_enabled)
        with mock.patch.object(ai_jobs, 'enqueue') as enqueue, mock.patch('cveFeed.host_review.build') as build:
            out = host_review.sweep()
            self.assertEqual((out['queued'], out['skipped']), (0, 'the AI host review is switched off'))
            with self.assertRaises(host_review.HostReviewRefused) as caught:
                host_review.request(self.proj, HOST)
            self.assertEqual(caught.exception.status, 503)
            self.assertIn('switched off', str(caught.exception))
        enqueue.assert_not_called()
        build.assert_not_called()
        self.assertFalse(HostReview.objects.exists())
        self.assertFalse(AIJob.objects.exists())

    def test_review_now_over_rest_and_mcp_does_nothing_while_it_is_off(self):
        base = f'/api/v1/projects/{self.proj.slug}/hosts/{self.sub.pk}/review'
        status, data = call(self.token, 'POST', base, {})
        self.assertEqual(status, 503, data)
        self.assertIn('switched off', data['error'])
        err, _ = tool_call(self.token, 'request_host_review', {'project': self.proj.slug, 'host_id': self.sub.pk})
        self.assertTrue(err)
        status, data = call(self.token, 'GET', base)
        self.assertEqual((data['readiness']['reason_code'], data['readiness']['can_request']), ('disabled', False))
        self.assertFalse(AIJob.objects.exists())

    def test_a_job_that_was_queued_before_it_was_switched_off_is_dropped_not_asked(self):
        ReviewerSettings.objects.update(host_review_enabled=True)
        review = host_review.request(self.proj, HOST)
        ReviewerSettings.objects.update(host_review_enabled=False)
        self.assertEqual(host_review.job_admit(review.ai_job), 'drop')

    def test_a_project_starts_on_recommend_and_a_step_is_proposed_not_started(self):
        self.assertEqual(host_review.mode_of(self.proj), 'recommend')
        ReviewerSettings.objects.update(host_review_enabled=True)
        review = self.queue()
        with mock.patch('cveFeed.host_actions.run') as run:
            review = self.deliver(review, self.body({'f1': ('true_open', 'high')}, action='validate_match', target='f1', reason='needs_check'))
        run.assert_not_called()
        self.assertEqual((review.step_mode, review.step_state), ('recommend', 'proposed'))


class TurningItOnTests(DefaultOffFixture):
    def test_a_person_turns_it_on_in_settings_and_the_sweep_then_queues_the_host(self):
        self.assertEqual(host_review.sweep()['queued'], 0)
        response = self.put(host_review_enabled=True, host_review_daily_max=20)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual((data['host_review_enabled'], data['host_review_daily_max']), (True, 20))
        self.assertEqual(host_review.sweep()['queued'], 1)
        self.assertEqual(HostReview.objects.get().host, HOST)

    def test_an_agent_cannot_turn_it_on_or_raise_its_caps_but_may_turn_it_off_and_lower_them(self):
        for values in ({'host_review_enabled': True}, {'host_review_daily_max': 500}, {'host_review_auto_per_project_day': 51}):
            err, text = tool_call(self.token, 'change_setting', {'name': 'reviewer', 'values': values})
            self.assertTrue(err, values)
            self.assertIn('only a person', text)
        row = ReviewerSettings.current()
        self.assertEqual((row.host_review_enabled, row.host_review_daily_max, row.host_review_auto_per_project_day), (False, 100, 50))
        self.put(host_review_enabled=True)
        err, data = tool_call(self.token, 'change_setting', {'name': 'reviewer', 'values': {'host_review_enabled': False, 'host_review_daily_max': 10}})
        self.assertFalse(err, data)
        row = ReviewerSettings.current()
        self.assertEqual((row.host_review_enabled, row.host_review_daily_max), (False, 10))

    def test_the_caps_are_checked(self):
        for body in ({'host_review_enabled': 'yes'}, {'host_review_daily_max': -1}, {'host_review_daily_max': True}, {'host_review_auto_per_project_day': 'x'}):
            self.assertEqual(self.put(**body).status_code, 400, body)

    def test_only_a_person_sets_a_project_to_automatic_an_api_key_may_set_recommend_or_off(self):
        url = f'/api/v1/projects/{self.proj.slug}/settings'
        status, data = call(self.token, 'PUT', url, {'host_review_mode': 'auto'})
        self.assertEqual(status, 403, data)
        self.assertIn('only a person', data['error'])
        self.assertTrue(tool_call(self.token, 'set_project_settings', {'project': self.proj.slug, 'host_review_mode': 'auto'})[0])
        self.assertEqual(host_review.mode_of(self.proj), 'recommend')
        for mode in ('off', 'recommend'):
            self.assertEqual(call(self.token, 'PUT', url, {'host_review_mode': mode})[0], 200)
        response = self.client.put(url, data=json.dumps({'host_review_mode': 'auto'}), content_type='application/json')  # a person in the web interface
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(host_review.mode_of(self.proj), 'auto')


class PerProjectModeTests(DefaultOffFixture):
    def test_settings_lists_every_project_with_its_mode_and_a_person_changes_them(self):
        data = self.client.get('/cve/api/settings/reviewer').json()
        modes = {p['slug']: p['mode'] for p in data['host_review_projects']}
        self.assertEqual(modes[self.proj.slug], 'recommend')
        response = self.put(host_review_modes={self.proj.slug: 'auto', self.other.slug: 'off'})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual((host_review.mode_of(self.proj), host_review.mode_of(self.other)), ('auto', 'off'))
        self.assertEqual(self.put(host_review_modes={'nope': 'off'}).status_code, 404)
        self.assertEqual(self.put(host_review_modes={self.proj.slug: 'sometimes'}).status_code, 400)

    def test_an_agent_may_list_and_lower_but_not_set_automatic(self):
        err, text = tool_call(self.token, 'change_setting', {'name': 'reviewer', 'values': {'host_review_modes': {self.proj.slug: 'auto'}}})
        self.assertTrue(err)
        self.assertEqual(host_review.mode_of(self.proj), 'recommend')
        err, data = tool_call(self.token, 'change_setting', {'name': 'reviewer', 'values': {'host_review_modes': {self.proj.slug: 'off'}}})
        self.assertFalse(err, data)
        self.assertEqual(host_review.mode_of(self.proj), 'off')
