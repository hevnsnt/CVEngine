"""The AI host review over REST and MCP (agentapi.host_review_api): read a host's review, Review now, Start and Dismiss the proposed step, and the project's
mode. Tenancy (a foreign project, host or review is a 404), permission (reading needs project read; every write needs a write role, never a read-only
token, the audit role or ``_all``) and each state the review can be in. The model is a stub (``test_host_review_job.Fixture``)."""
import json
from unittest import mock

from django.contrib.auth.models import User

from agentapi.auth import create_token
from cveFeed import host_actions, host_review
from cveFeed.models import AIJob, CVEMatch, HostReview, HostScreenshot, HostState, ProjectSettings, ReviewerSettings
from dashboard.models import AIProviderSettings, Org, OrgMembership
from startScan.models import Port, Subdomain
from tests.test_agentapi import call, tool_call
from tests.test_host_ai_review import HOSTILE
from tests.test_host_review_job import HOST, Fixture


class ApiFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.member = User.objects.create_user('hra-member', password='x')
        self.auditor = User.objects.create_user('hra-audit', password='x')
        self.outsider = User.objects.create_user('hra-out', password='x')
        OrgMembership.objects.create(user=self.member, org=self.org, role='user')
        OrgMembership.objects.create(user=self.auditor, org=self.org, role='audit')
        OrgMembership.objects.create(user=self.outsider, org=Org.objects.create(name='Elsewhere', slug='hra-else'), role='admin')
        self.tok = create_token(self.member, 'rw')[1]
        self.ro = create_token(self.member, 'ro', read_only=True)[1]
        self.audit_tok = create_token(self.auditor, 'au')[1]
        self.out_tok = create_token(self.outsider, 'out')[1]
        self.base = f'/api/v1/projects/{self.proj.slug}/hosts/{self.sub.pk}/review'
        self.m1 = self.match()

    def get(self, tok=None):
        return call(tok or self.tok, 'GET', self.base)

    def post(self, tail='', body=None, tok=None, base=None):
        return call(tok or self.tok, 'POST', (base or self.base) + tail, body or {})

    def applied(self, action='assess_host', target='', mode='recommend', verdicts=None, **kw):
        """A queued review answered by the stub, in a project whose mode is ``mode``."""
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': mode})
        review = self.queue()
        body = self.body(verdicts or {'f1': ('true_open', 'high')}, action=action, target=target, reason='needs_proof', step_note='A fresh assessment would settle it.', **kw)
        with mock.patch.object(host_actions, 'run', return_value={'action': action, 'target': target, 'state': 'started', 'detail': 'queued'}):
            return self.deliver(review, body)


class ReadTests(ApiFixture):
    def test_a_host_never_reviewed_says_so_and_whether_review_now_would_be_accepted(self):
        status, data = self.get()
        self.assertEqual(status, 200, data)
        self.assertEqual((data['status'], data['review'], data['mode'], data['host'], data['host_id']), ('none', None, 'auto', HOST, self.sub.pk))
        self.assertEqual(data['readiness'], {'can_request': True, 'reason_code': '', 'reason': ''})

    def test_each_reason_review_now_would_be_refused_is_named(self):
        def reason():
            return self.get()[1]['readiness']['reason_code']
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'off'})
        self.assertEqual(reason(), 'off')
        ProjectSettings.objects.filter(project=self.proj).update(host_review_mode='auto')
        row = ReviewerSettings.current()
        ReviewerSettings.objects.filter(pk=row.pk).update(host_review_daily_max=0)
        self.assertEqual(reason(), 'daily_limit')
        ReviewerSettings.objects.filter(pk=row.pk).update(host_review_daily_max=100)
        with mock.patch('cveFeed.reviewer.paused', return_value=True):
            self.assertEqual(reason(), 'paused')
        AIProviderSettings.objects.all().delete()
        status, data = self.get()
        self.assertEqual((data['readiness']['reason_code'], data['readiness']['can_request']), ('no_provider', False))
        self.assertIn('no AI provider', data['readiness']['reason'])

    def test_nothing_open_and_an_unavailable_host_are_named(self):
        CVEMatch.objects.all().update(remediation_status='fixed')
        self.assertEqual(self.get()[1]['readiness']['reason_code'], 'nothing_open')
        HostState.objects.filter(project=self.proj, host=HOST).update(retired_at='2020-01-01T00:00:00Z')
        self.assertEqual(self.get()[1]['readiness']['reason_code'], 'unavailable')

    def test_an_applied_review_gives_each_verdict_with_its_reason_and_the_step_without_any_internal_reference(self):
        second = self.match()
        review = self.applied(verdicts={'f1': ('true_open', 'high'), 'f2': ('false_positive', 'high')})
        status, data = self.get()
        self.assertEqual(status, 200, data)
        shown = data['review']
        self.assertEqual((shown['id'], shown['status'], shown['running'], shown['failure'], shown['held_for_instructions']), (review.pk, 'applied', False, None, False))
        self.assertEqual(shown['host_note'], 'The findings of this host were read together.')
        self.assertEqual({f['verdict'] for f in shown['findings']}, {'true_open', 'false_positive'})
        by_id = {f['finding']['id']: f for f in shown['findings']}
        self.assertEqual(by_id[self.m1.pk]['summary'], 'real')
        self.assertEqual(by_id[second.pk]['summary'], 'false_positive')
        self.assertEqual(by_id[second.pk]['finding']['type'], 'match')
        self.assertEqual(by_id[second.pk]['link'], f'/cve/{self.proj.slug}/vulns/#match-{second.pk}')
        self.assertEqual((by_id[second.pk]['title'], by_id[second.pk]['reason_code']), (second.cve_entry.cve_id, 'version_not_affected'))
        self.assertEqual(by_id[second.pk]['outcome'], 'closed')
        self.assertEqual((shown['counts']['real'], shown['counts']['false_positive'], shown['counts']['closed']), (1, 1, 1))
        step = shown['step']
        self.assertEqual((step['action'], step['mode'], step['state'], step['can_start'], step['can_dismiss']), ('assess_host', 'recommend', 'proposed', True, True))
        self.assertEqual(step['note'], 'A fresh assessment would settle it.')
        blob = json.dumps(data)
        self.assertNotIn('"f1"', blob)  # the model's short names stay on the server
        self.assertNotIn('refs', data['review'])

    def test_a_step_that_names_a_finding_says_which(self):
        review = self.applied(action='validate_match', target='f1', mode='recommend')
        step = self.get()[1]['review']['step']
        self.assertEqual(step['target'], {'type': 'match', 'id': self.m1.pk, 'title': self.m1.cve_entry.cve_id, 'link': f'/cve/{self.proj.slug}/vulns/#match-{self.m1.pk}'})
        self.assertTrue(step['can_start'])

    def test_a_step_started_on_its_own_is_shown_as_started_and_cannot_be_started_or_dismissed(self):
        self.applied(action='validate_match', target='f1', mode='auto')
        step = self.get()[1]['review']['step']
        self.assertEqual((step['mode'], step['state'], step['can_start'], step['can_dismiss']), ('auto', 'started', False, False))
        self.assertEqual(step['detail'], 'queued')

    def test_a_running_review_a_failed_one_and_a_stale_one_are_each_told_honestly(self):
        review = self.queue()
        data = self.get()[1]
        self.assertEqual((data['status'], data['review']['running'], data['review']['step'], data['review']['findings']), ('queued', True, None, []))
        self.assertEqual(data['readiness']['reason_code'], 'open')
        HostReview.objects.filter(pk=review.pk).update(status='failed', step_detail='failed: provider_rate_limit')
        data = self.get()[1]
        self.assertEqual((data['status'], data['review']['failure'], data['review']['running']), ('failed', 'failed: provider_rate_limit', False))
        HostReview.objects.filter(pk=review.pk).update(status='stale', step_detail='stale: the host changed while the AI was reading it')
        data = self.get()[1]
        self.assertEqual((data['status'], data['review']['failure']), ('stale', 'stale: the host changed while the AI was reading it'))

    def test_a_host_whose_own_text_carries_instructions_is_shown_as_held(self):
        Port.objects.filter(pk=self.port.pk).update(banner='SSH-2.0-OpenSSH_8.9 ' + HOSTILE, service_extra=HOSTILE[:250])
        Subdomain.objects.filter(pk=self.sub.pk).update(page_title=HOSTILE)
        HostScreenshot.objects.create(project=self.proj, domain=self.domain, host=HOST, scheme='https', port=443, outcome='ok', title=HOSTILE[:290])
        review = self.applied(verdicts={'f1': ('false_positive', 'high')}, action='assess_host')
        shown = self.get()[1]['review']
        self.assertTrue(shown['held_for_instructions'])
        self.assertTrue(shown['injection'])
        self.assertEqual((shown['findings'][0]['outcome'], shown['counts']['closed'], shown['counts']['held']), ('held', 0, 1))
        self.assertIn('aimed at AI', shown['findings'][0]['held_reason'])
        self.assertEqual((shown['step']['mode'], shown['step']['state']), ('recommend', 'proposed'))

    def test_the_newest_review_is_the_one_shown(self):
        old = self.applied()
        HostReview.objects.filter(pk=old.pk).update(status='failed')
        newer = self.queue()
        self.assertEqual(self.get()[1]['review']['id'], newer.pk)


class TenancyAndPermissionTests(ApiFixture):
    def test_another_organizations_caller_gets_404_on_every_route(self):
        self.applied()
        for method, tail in (('GET', ''), ('POST', ''), ('POST', '/step'), ('POST', '/dismiss')):
            status, _ = call(self.out_tok, method, self.base + tail, {} if method == 'POST' else None)
            self.assertEqual(status, 404, f'{method} {tail}')
        self.assertEqual(HostReview.objects.get().step_state, 'proposed')

    def test_a_host_of_another_project_is_a_404_through_this_projects_route(self):
        other_sub = self.host_of(self.other_domain, self.other_scan, 'www.example.org', self.other, '192.0.2.77')
        self.applied()
        foreign = f'/api/v1/projects/{self.proj.slug}/hosts/{other_sub.pk}/review'
        self.assertEqual(call(self.tok, 'GET', foreign)[0], 404)
        for tail in ('', '/step', '/dismiss'):
            self.assertEqual(self.post(tail, base=foreign)[0], 404, tail)
        self.assertEqual(call(self.tok, 'GET', f'/api/v1/projects/{self.proj.slug}/hosts/999999/review')[0], 404)

    def test_a_review_of_another_project_is_never_returned_for_a_host_of_the_same_name(self):
        other_sub = self.host_of(self.other_domain, self.other_scan, HOST, self.other, '192.0.2.78')  # the same name in another project
        self.applied()
        status, data = call(self.tok, 'GET', f'/api/v1/projects/{self.other.slug}/hosts/{other_sub.pk}/review')
        self.assertEqual((status, data['status'], data['review']), (200, 'none', None))

    def test_the_all_projects_view_cannot_start_or_dismiss_anything(self):
        self.applied()
        base = f'/api/v1/projects/_all/hosts/{self.sub.pk}/review'
        self.assertEqual(call(self.tok, 'GET', base)[0], 400)
        for tail in ('', '/step', '/dismiss'):
            self.assertEqual(self.post(tail, base=base)[0], 400, tail)

    def test_reading_is_open_to_a_read_only_token_and_the_audit_role_but_no_write_is(self):
        self.applied()
        for tok in (self.ro, self.audit_tok):
            self.assertEqual(self.get(tok)[0], 200)
            for tail in ('', '/step', '/dismiss'):
                self.assertEqual(self.post(tail, tok=tok)[0], 403, tail)
        self.assertEqual(HostReview.objects.get().step_state, 'proposed')
        self.assertEqual(HostReview.objects.count(), 1)

    def test_no_token_is_a_401(self):
        self.assertEqual(call(None, 'GET', self.base)[0], 401)
        self.assertEqual(call(None, 'POST', self.base, {})[0], 401)

    def test_the_project_mode_is_read_with_project_read_and_set_with_a_write_role(self):
        url = f'/api/v1/projects/{self.proj.slug}/settings'
        self.assertEqual(call(self.audit_tok, 'GET', url)[1]['host_review_mode'], 'auto')
        for tok in (self.ro, self.audit_tok):
            self.assertEqual(call(tok, 'PUT', url, {'host_review_mode': 'recommend'})[0], 403)
        self.assertEqual(call(self.out_tok, 'PUT', url, {'host_review_mode': 'recommend'})[0], 404)
        self.assertEqual(host_review.mode_of(self.proj), 'auto')
        status, data = call(self.tok, 'PUT', url, {'host_review_mode': 'recommend'})
        self.assertEqual((status, data['host_review_mode']), (200, 'recommend'))
        self.assertEqual(host_review.mode_of(self.proj), 'recommend')


class ReviewNowTests(ApiFixture):
    def test_review_now_queues_one_review_at_a_persons_priority_and_a_second_is_a_409(self):
        status, data = self.post()
        self.assertEqual(status, 202, data)
        self.assertEqual((data['created'], data['status'], data['review']['running']), (True, 'queued', True))
        review = HostReview.objects.get()
        self.assertEqual((review.project_id, review.host), (self.proj.pk, HOST))
        self.assertEqual(AIJob.objects.get(pk=review.ai_job_id).priority, 2)
        status, data = self.post()
        self.assertEqual((status, data['error']), (409, 'a review of this host is already open'))
        self.assertEqual(HostReview.objects.count(), 1)

    def test_it_says_why_it_was_refused(self):
        CVEMatch.objects.all().update(remediation_status='fixed')
        status, data = self.post()
        self.assertEqual(status, 409, data)
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'off'})
        self.assertEqual(self.post()[0], 409)
        ProjectSettings.objects.update(host_review_mode='auto')
        CVEMatch.objects.all().update(remediation_status='open')
        row = ReviewerSettings.current()
        ReviewerSettings.objects.filter(pk=row.pk).update(host_review_daily_max=0)
        self.assertEqual(self.post()[0], 429)
        ReviewerSettings.objects.filter(pk=row.pk).update(host_review_daily_max=100)
        AIProviderSettings.objects.all().delete()
        status, data = self.post()
        self.assertEqual(status, 503, data)
        self.assertIn('no AI provider', data['error'])
        self.assertFalse(HostReview.objects.exists())

    def test_an_excluded_or_archived_host_is_a_404(self):
        HostState.objects.filter(project=self.proj, host=HOST).update(archived_at='2020-01-01T00:00:00Z')
        self.assertEqual(self.post()[0], 404)


class StartAndDismissTests(ApiFixture):
    def test_start_runs_the_proposed_step_as_the_caller_once(self):
        review = self.applied(action='assess_host')
        with mock.patch.object(host_actions, 'run', return_value={'action': 'assess_host', 'target': '', 'state': 'started', 'detail': 'assessment #7 queued'}) as run:
            status, data = self.post('/step')
            self.assertEqual(status, 200, data)
            self.assertEqual(self.post('/step')[0], 409)  # two clicks start one step
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs['by'], self.member)
        self.assertEqual(data['result'], {'state': 'started', 'detail': 'assessment #7 queued'})
        step = data['review']['step']
        self.assertEqual((step['state'], step['detail'], step['can_start'], step['can_dismiss']), ('started', 'assessment #7 queued', False, False))
        self.assertEqual(HostReview.objects.get(pk=review.pk).step_state, 'started')

    def test_a_step_that_is_no_longer_offered_is_a_409_that_says_why_and_is_stored_as_refused(self):
        self.applied(action='assess_host')
        with mock.patch.object(host_actions, 'run', return_value={'action': 'assess_host', 'target': '', 'state': 'refused', 'detail': 'the host is excluded'}):
            status, data = self.post('/step')
        self.assertEqual((status, data['error']), (409, 'the host is excluded'))
        self.assertEqual((data['review']['step']['state'], data['review']['step']['detail']), ('refused', 'the host is excluded'))
        self.assertEqual(HostReview.objects.get().step_state, 'refused')

    def test_nothing_to_start_is_a_409_and_a_host_with_no_review_is_a_404(self):
        self.assertEqual(self.post('/step')[0], 404)
        self.assertEqual(self.post('/dismiss')[0], 404)
        self.applied(action='validate_match', target='f1', mode='auto')  # started on its own
        self.assertEqual(self.post('/step')[0], 409)
        self.assertEqual(self.post('/dismiss')[0], 409)

    def test_a_failed_review_has_nothing_to_start(self):
        review = self.queue()
        HostReview.objects.filter(pk=review.pk).update(status='failed', step_detail='failed: provider_timeout')
        self.assertEqual(self.post('/step')[0], 409)

    def test_dismiss_stores_who_and_why_and_the_step_is_not_offered_again(self):
        self.applied(action='assess_host')
        status, data = self.post('/dismiss', {'reason': 'we already did that yesterday'})
        self.assertEqual(status, 200, data)
        step = data['review']['step']
        self.assertEqual((step['state'], step['can_start'], step['can_dismiss'], step['dismissed_by']['id']), ('dismissed', False, False, self.member.pk))
        self.assertIn('we already did that', step['detail'])
        self.assertEqual(self.post('/dismiss')[0], 409)
        with mock.patch.object(host_actions, 'run') as run:
            self.assertEqual(self.post('/step')[0], 409)
        run.assert_not_called()

    def test_dismiss_takes_no_reason_and_refuses_one_that_is_not_text(self):
        self.applied(action='assess_host')
        self.assertEqual(self.post('/dismiss', {'reason': ['x']})[0], 400)
        self.assertEqual(self.post('/dismiss')[0], 200)

    def test_the_needs_a_person_flag_is_cleared_by_a_person_and_never_by_a_token(self):
        self.applied(action='ask_person', mode='recommend')
        step = self.get()[1]['review']['step']
        self.assertEqual((step['needs_person'], step['can_start'], step['can_dismiss']), (True, False, True))
        status, data = self.post('/dismiss')
        self.assertEqual(status, 403, data)  # HV-3: an API key may not clear it
        self.assertTrue(self.get()[1]['review']['step']['needs_person'])
        from django.test import Client
        person = Client()
        person.force_login(self.member)
        self.assertEqual(person.post(self.base + '/dismiss', data='{}', content_type='application/json').status_code, 200)
        self.assertFalse(self.get()[1]['review']['step']['needs_person'])

    def test_a_token_cannot_dismiss_a_step_held_for_planted_text_but_may_dismiss_any_other(self):
        review = self.applied(action='assess_host')
        HostReview.objects.filter(pk=review.pk).update(injection=['ai_directive'])
        self.assertEqual(self.post('/dismiss')[0], 403)
        self.assertEqual(HostReview.objects.get().step_state, 'proposed')
        HostReview.objects.filter(pk=review.pk).update(injection=['verdict_claim'])  # a claim about the verdict holds closures, not steps
        self.assertEqual(self.post('/dismiss')[0], 200)


class McpTests(ApiFixture):
    def test_the_four_tools_use_the_same_handlers_and_the_same_refusals(self):
        err, data = tool_call(self.tok, 'get_host_review', {'project': self.proj.slug, 'host_id': self.sub.pk})
        self.assertEqual((err, data['status']), (False, 'none'))
        err, data = tool_call(self.tok, 'request_host_review', {'project': self.proj.slug, 'host_id': self.sub.pk})
        self.assertEqual((err, data['status']), (False, 'queued'))
        err, text = tool_call(self.tok, 'request_host_review', {'project': self.proj.slug, 'host_id': self.sub.pk})
        self.assertTrue(err)
        self.assertIn('already open', text)
        HostReview.objects.all().delete()
        AIJob.objects.all().delete()  # the first review's queued job would be the one this host's next review dedupes onto
        self.applied()
        err, data = tool_call(self.tok, 'dismiss_host_review_step', {'project': self.proj.slug, 'host_id': self.sub.pk, 'reason': 'later'})
        self.assertFalse(err, data)
        self.assertEqual(data['review']['step']['state'], 'dismissed')
        err, text = tool_call(self.tok, 'start_host_review_step', {'project': self.proj.slug, 'host_id': self.sub.pk})
        self.assertTrue(err)

    def test_start_through_mcp_runs_the_step(self):
        self.applied(action='assess_host')
        with mock.patch.object(host_actions, 'run', return_value={'action': 'assess_host', 'target': '', 'state': 'started', 'detail': 'queued'}):
            err, data = tool_call(self.tok, 'start_host_review_step', {'project': self.proj.slug, 'host_id': self.sub.pk})
        self.assertEqual((err, data['result']['state']), (False, 'started'))

    def test_the_write_tools_refuse_a_read_only_token_and_every_tool_a_foreign_project(self):
        self.applied()
        args = {'project': self.proj.slug, 'host_id': self.sub.pk}
        for name in ('request_host_review', 'start_host_review_step', 'dismiss_host_review_step'):
            err, text = tool_call(self.ro, name, args)
            self.assertTrue(err, name)
        self.assertEqual(tool_call(self.ro, 'get_host_review', args)[0], False)
        for name in ('get_host_review', 'request_host_review', 'start_host_review_step', 'dismiss_host_review_step'):
            self.assertTrue(tool_call(self.out_tok, name, args)[0], name)
        self.assertEqual(HostReview.objects.get().step_state, 'proposed')

    def test_the_mode_is_a_project_setting_through_the_tools_too(self):
        err, data = tool_call(self.tok, 'set_project_settings', {'project': self.proj.slug, 'host_review_mode': 'recommend'})
        self.assertEqual((err, data['host_review_mode']), (False, 'recommend'))
        self.assertTrue(tool_call(self.tok, 'set_project_settings', {'project': self.proj.slug, 'host_review_mode': 'sometimes'})[0])
        self.assertTrue(tool_call(self.ro, 'set_project_settings', {'project': self.proj.slug, 'host_review_mode': 'off'})[0])
        self.assertEqual(tool_call(self.tok, 'get_project_settings', {'project': self.proj.slug})[1]['host_review_mode'], 'recommend')

    def test_the_mode_setting_is_validated_and_leaves_the_sla_alone(self):
        url = f'/api/v1/projects/{self.proj.slug}/settings'
        self.assertEqual(call(self.tok, 'PUT', url, {'host_review_mode': 'sometimes'})[0], 400)
        status, data = call(self.tok, 'PUT', url, {'sla_days': {'critical': 3}, 'host_review_mode': 'off'})
        self.assertEqual((status, data['sla_days']['critical'], data['host_review_mode']), (200, 3, 'off'))
        status, data = call(self.tok, 'PUT', url, {'sla_days': {'critical': None}})
        self.assertEqual((status, data['sla_days']['critical'], data['host_review_mode']), (200, 7, 'off'))


class AgentStartTests(ApiFixture):
    """HS-5: an API key or an agent starting a proposed step has no person's authority: a step held for planted text is refused, and the action runs under
    the unattended gates (the requester stays on the record). A session user (a person in the web interface) is unchanged."""

    def test_a_token_cannot_start_a_step_held_for_planted_text_and_a_person_can(self):
        from cveFeed.models import ProjectSettings
        review = self.applied(action='assess_host')
        HostReview.objects.filter(pk=review.pk).update(injection=['ai_directive'])
        with mock.patch.object(host_actions, 'run') as run:
            status, data = self.post('/step')
        self.assertEqual(status, 409, data)
        self.assertIn('a person starts it, in the web interface', data['error'])
        run.assert_not_called()
        self.assertEqual(HostReview.objects.get().step_state, 'proposed')
        from django.test import Client
        person = Client()
        person.force_login(self.member)
        with mock.patch.object(host_actions, 'run', return_value={'action': 'assess_host', 'target': '', 'state': 'started', 'detail': 'queued'}) as run:
            response = person.post(self.base + '/step', data='{}', content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(run.call_args.kwargs['agent'])

    def test_a_token_start_runs_under_the_unattended_gates_with_the_user_on_the_record(self):
        review = self.applied(action='assess_host')
        with mock.patch('cveFeed.host_assessment._admit', wraps=__import__('cveFeed.host_assessment', fromlist=['_admit'])._admit) as admit, \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, project=None: list(hosts)):
            status, data = self.post('/step')
        self.assertEqual(status, 200, data)
        self.assertTrue(admit.called)
        self.assertTrue(all(call.kwargs.get('unattended') for call in admit.call_args_list), admit.call_args_list)
        from cveFeed.models import HostAssessment
        self.assertEqual(HostAssessment.objects.get().requested_by, self.member)

    def test_a_manual_only_target_refuses_an_agents_start(self):
        self.applied(action='assess_host')
        from targetApp.models import Domain
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode='manual')
        status, data = self.post('/step')
        self.assertEqual(status, 409, data)
        self.assertEqual(HostReview.objects.get().step_state, 'refused')


class UnchangedReviewTests(ApiFixture):
    """HV-4: Review now on a host whose state has not changed returns the last review and makes no AI call; a token has a small hourly number."""

    def test_an_unchanged_host_returns_its_review_for_a_person_and_a_token_without_an_ai_call(self):
        review = self.applied()
        from django.test import Client
        person = Client()
        person.force_login(self.member)
        for status, data in ((self.post()[0], None), (person.post(self.base, data='{}', content_type='application/json').status_code, None)):
            self.assertEqual(status, 202)
        self.assertEqual(HostReview.objects.count(), 1)
        self.assertEqual(AIJob.objects.filter(kind='host_review').count(), 1)  # the one the first review made
        status, data = self.post()
        self.assertEqual((data['created'], data['review']['id']), (False, review.pk))
        self.assertEqual(data['readiness']['reason_code'], 'unchanged')
        with mock.patch.object(host_review, 'build') as build:
            self.post()
        build.assert_not_called()

    def test_a_changed_host_queues_a_new_review(self):
        self.applied()
        Port.objects.filter(pk=self.port.pk).update(version='9.9')
        status, data = self.post()
        self.assertEqual((status, data['created']), (202, True))
        self.assertEqual(HostReview.objects.count(), 2)

    def test_a_token_may_queue_only_a_few_reviews_an_hour_but_a_person_may_queue_more(self):
        from django.core.cache import cache
        sub2 = self.host_of(self.domain, self.scan, 'x2.example.com', self.proj, '192.0.2.90')
        self.match(sub=sub2)
        cache.clear()
        with mock.patch('agentapi.host_review_api.TOKEN_REVIEWS_PER_HOUR', 1):
            self.assertEqual(self.post()[0], 202)
            status, data = self.post(base=f'/api/v1/projects/{self.proj.slug}/hosts/{sub2.pk}/review')
            self.assertEqual(status, 429, data)
            self.assertFalse(HostReview.objects.filter(host='x2.example.com').exists())
            from django.test import Client
            person = Client()
            person.force_login(self.member)
            self.assertEqual(person.post(f'/api/v1/projects/{self.proj.slug}/hosts/{sub2.pk}/review', data='{}', content_type='application/json').status_code, 202)
