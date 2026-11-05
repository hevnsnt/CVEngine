"""The pipeline's AI jobs (cveFeed.ai_jobs, docs/AI-REVIEWER.md): the server queues them, only the AI reviewer container takes them, its
answers are checked with the stage's own validator and applied as the stage applied them itself, and nothing is lost or overspent when the
container is off, dies mid-call or an update restarts the server."""
import datetime
import json
import os
import sys
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import REVIEWER_PATH, create_token
from cveFeed import ai_jobs, triage
from cveFeed.models import AIJob, AIUsage, CVEEntry, CVEMatch, Triage, TriageCall, TriageVerdict
from dashboard.models import AIProviderSettings, Org, Project
from reNgine import ai_profiles
from startScan.models import Subdomain
from targetApp.models import Domain
from tests import ai_queue
from tests.test_agentapi import call
from tests.test_triage import reply


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Jobs', slug='jobs-org')
        self.project = Project.objects.create(name='Jobs', slug='jobs-proj', insert_date=now, org=org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-8801', kev=True, cvss=9.8, published_at=now, title='Heap overflow',
                                           affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
        self.admin = User.objects.create_superuser('jobs-admin', password='x')
        _, self.raw = create_token(self.admin, 'cvENGINE AI reviewer', scope='reviewer')
        ai_queue.configure('vllm', model='m')
        patcher = mock.patch('cveFeed.activity.log', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def match(self, name='www.example.com', version='1.18.0'):
        sub = Subdomain.objects.create(name=name, target_domain=self.domain)
        return CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version=version,
                                       version_in_range=True, source='port')

    def ask(self):
        """Triage every match: one job per signature."""
        return triage.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))))

    def take(self, limit=8):
        status, data = call(self.raw, 'GET', f'/api/v1/reviewer/jobs/next?limit={limit}')
        self.assertEqual(status, 200, data)
        return data['jobs']

    def post(self, job, **body):
        return call(self.raw, 'POST', f"/api/v1/reviewer/jobs/{job['id']}/result", {'lease': job['lease'], 'provider': 'vllm', 'model': 'm', **body})


class RouteTests(Base):
    def test_only_the_reviewer_token_takes_jobs_or_answers_them(self):
        self.assertTrue(REVIEWER_PATH.match('/api/v1/reviewer/jobs/next'))
        self.assertTrue(REVIEWER_PATH.match('/api/v1/reviewer/jobs/12/result'))
        self.assertFalse(REVIEWER_PATH.match('/api/v1/reviewer/jobs/12/result/../../projects'))
        self.match()
        self.ask()
        _, full = create_token(self.admin, 'admin-full')
        self.assertEqual(call(full, 'GET', '/api/v1/reviewer/jobs/next')[0], 403)
        client = Client()
        client.force_login(self.admin)
        self.assertEqual(client.get('/api/v1/reviewer/jobs/next').status_code, 403)
        self.assertEqual(AIJob.objects.get().status, 'queued')  # nothing was handed out to them
        job = self.take()[0]
        self.assertEqual(call(full, 'POST', f"/api/v1/reviewer/jobs/{job['id']}/result", {'lease': job['lease'], 'text': reply()})[0], 403)

    def test_a_job_carries_the_stage_prompt_its_parts_and_no_host_name_or_secret(self):
        m = self.match()
        CVEEntry.objects.filter(pk=self.cve.pk).update(title='Heap overflow, see AKIAIOSFODNN7EXAMPLE')
        self.ask()
        job = self.take()[0]
        self.assertEqual((job['kind'], job['stage'], job['attempt']), ('triage', 'finding_triage', 1))
        self.assertIn('vulnerability analyst', job['system'])
        self.assertEqual(job['parts'][0], {'text': 'Finding kind: cve_match'})
        self.assertEqual(job['parts'][1]['fence'], 'FINDING')
        self.assertEqual((job['options']['max_tokens'], job['options']['temperature'], job['options']['retry_truncated']), (400, 0, True))
        self.assertEqual(job['schema']['properties']['classification']['enum'][0], 'confirmed')
        text = json.dumps(job)
        self.assertNotIn(m.subdomain.name, text)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', text)
        self.assertNotIn('context', job)  # what the continuation needs stays on the server
        self.assertNotIn('claim', text)


class QueueTests(Base):
    def test_one_question_per_signature_and_the_rows_wait_pending(self):
        for n in range(5):
            self.match(f'h{n}.example.com')
        stats = self.ask()
        self.assertEqual((stats['asked'], AIJob.objects.count()), (1, 1))
        self.assertEqual(set(Triage.objects.values_list('status', flat=True)), {'pending'})
        again = self.ask()  # the sweep finds it in flight
        self.assertEqual((again['asked'], again['queued'], AIJob.objects.count()), (0, 5, 1))

    def test_nothing_is_handed_out_while_the_reviewer_is_off_paused_or_no_provider_is_set(self):
        self.match()
        self.ask()
        with mock.patch.dict(os.environ, {'CVENGINE_REVIEWER': '0'}):
            self.assertEqual(self.take(), [])
            state = ai_jobs.waiting()
            self.assertTrue(state['waiting_for_reviewer'])
            self.assertIn('CVENGINE_REVIEWER=0', ai_jobs.waiting_message(state))
        with mock.patch('cveFeed.reviewer.paused', return_value=True):
            self.assertEqual(self.take(), [])
        AIProviderSettings.objects.update(enabled=False)
        self.assertEqual(self.take(), [])
        self.assertEqual(AIJob.objects.get().status, 'queued')  # it waits; nothing failed
        self.assertEqual(Triage.objects.get().status, 'pending')

    def test_without_a_provider_nothing_is_queued_as_before(self):
        AIProviderSettings.objects.all().delete()
        self.match()
        self.assertEqual(self.ask()['not_triaged'], 1)
        self.assertFalse(AIJob.objects.exists())

    def test_a_lease_is_exclusive_and_one_that_runs_out_is_handed_out_again_then_failed(self):
        self.match()
        self.ask()
        first = self.take()[0]
        self.assertEqual(self.take(), [])  # leased
        AIJob.objects.update(lease_until=timezone.now() - datetime.timedelta(seconds=1))
        second = self.take()[0]
        self.assertNotEqual(first['lease'], second['lease'])
        self.assertEqual(self.post(first, text=reply())[0], 409)  # the old lease no longer answers
        AIJob.objects.update(lease_until=timezone.now() - datetime.timedelta(seconds=1))
        self.take()  # the third time it is handed out
        AIJob.objects.update(lease_until=timezone.now() - datetime.timedelta(seconds=1))
        with mock.patch('cveFeed.ai_jobs._schedule', side_effect=ai_jobs.apply):
            ai_jobs.release_expired()
        job = AIJob.objects.get()
        self.assertEqual((job.status, job.error_category), ('failed', 'lease_expired'))
        row = Triage.objects.get()
        self.assertEqual((row.status, json.loads(row.reason)['category']), ('error', 'lease_expired'))  # the sweep asks again
        self.assertEqual(TriageCall.objects.get().status, 'failed')

    def test_malformed_answers_are_refused(self):
        self.match()
        self.ask()
        job = self.take()[0]
        for body in ({}, {'text': 'x', 'error': 'provider_http'}, {'error': 'something else'}, {'text': 'x' * (ai_jobs.REPLY_MAX + 1)}):
            self.assertEqual(self.post(job, **body)[0], 400, body)
        self.assertEqual(call(self.raw, 'POST', '/api/v1/reviewer/jobs/999999/result', {'lease': 'x', 'text': 'y'})[0], 404)
        self.assertEqual(self.post({**job, 'lease': 'not-it'}, text=reply())[0], 409)

    def test_an_identical_open_question_is_not_queued_twice(self):
        a = ai_jobs.enqueue('triage', 's', system='x', parts=[ai_jobs.text('y')], dedupe='triage:q')
        b = ai_jobs.enqueue('triage', 's', system='x', parts=[ai_jobs.text('z')], dedupe='triage:q')
        self.assertEqual(a.pk, b.pk)


class AnswerTests(Base):
    def answer(self, job, text):
        status, data = self.post(job, text=text, calls=[{'status': 'succeeded', 'input_tokens': 120, 'output_tokens': 30,
                                                        'duration_ms': 900, 'model': 'm', 'actual_model': 'm-q4'}])
        self.assertEqual((status, data), (200, {'accepted': True}))
        return ai_jobs.apply(job['id'])

    def test_an_answer_is_applied_as_the_stage_applied_it_and_the_raw_text_is_dropped(self):
        m = self.match()
        self.ask()
        job = self.take()[0]
        self.assertEqual(self.answer(job, reply('likely')), 'applied')
        row = Triage.objects.get()
        m.refresh_from_db()
        # the model said likely, the only evidence is a version string: the ceiling keeps it at needs validation, as before
        self.assertEqual((row.status, row.classification, m.ai_verdict), ('triaged', 'needs_validation', 'uncertain'))
        self.assertEqual(TriageVerdict.objects.get().model, 'vllm:m')
        self.assertEqual(TriageCall.objects.get().status, 'succeeded')
        stored = AIJob.objects.get()
        self.assertEqual((stored.result, stored.input_tokens, stored.output_tokens), ({}, 120, 30))
        usage = AIUsage.objects.get()
        self.assertEqual((usage.stage, usage.provider, usage.status, usage.input_tokens, usage.actual_model), ('finding_triage', 'vllm', 'succeeded', 120, 'm-q4'))

    def test_a_rejected_answer_is_sent_back_once_with_why_and_the_second_counts(self):
        self.match()
        self.ask()
        job = self.take()[0]
        self.assertEqual(self.answer(job, '{"classification": "likely", "severity_adjust": "1"}'), 'retry')
        repair = self.take()[0]
        self.assertEqual((repair['id'], repair['attempt'], repair['stage']), (job['id'], 2, 'finding_triage_repair'))
        prompt = ai_queue.container().job_message(repair)
        self.assertIn('REJECTED by the validator', prompt)
        self.assertIn('"severity_adjust" must be the integer', prompt)
        self.assertIn('<<<REJECTED_REPLY ', prompt)  # the rejected reply goes back fenced
        self.assertIn('<<<FINDING ', prompt)  # with the original evidence
        self.assertEqual(self.answer(repair, reply('likely')), 'applied')
        self.assertEqual(Triage.objects.get().status, 'triaged')
        self.assertEqual(TriageCall.objects.filter(status='repair').count(), 1)  # the second call is billed

    def test_two_unusable_answers_are_a_schema_error_and_the_reply_is_not_kept(self):
        self.match()
        self.ask()
        self.answer(self.take()[0], 'no json sk-ant-SHOULD-NOT-LEAK')
        self.answer(self.take()[0], 'still no json')
        row = Triage.objects.get()
        diagnostic = json.loads(row.reason)
        self.assertEqual((row.status, diagnostic['category'], diagnostic['attempts'], diagnostic['provider']), ('error', 'schema_invalid', 2, 'vllm'))
        self.assertNotIn('SHOULD-NOT-LEAK', json.dumps(list(AIJob.objects.values()), default=str))
        self.assertEqual(TriageVerdict.objects.count(), 0)

    def test_a_provider_failure_marks_the_group_error_and_the_sweep_asks_again(self):
        self.match()
        self.ask()
        job = self.take()[0]
        self.assertEqual(self.post(job, error='provider_rate_limit', http_status=429, calls=[{'status': 'failed', 'category': 'provider_rate_limit'}])[0], 200)
        self.assertEqual(ai_jobs.apply(job['id']), 'failed')
        row = Triage.objects.get()
        self.assertEqual((row.status, json.loads(row.reason)['http_status']), ('error', 429))
        self.assertEqual(AIUsage.objects.get().error_category, 'provider_rate_limit')
        self.assertEqual(triage.sweep(self.project.pk)['asked'], 1)  # a new question, a new job
        self.assertEqual(AIJob.objects.filter(status='queued').count(), 1)

    def test_an_answer_for_rows_whose_evidence_changed_meanwhile_leaves_them_for_the_next_pass(self):
        m = self.match()
        self.ask()
        job = self.take()[0]
        CVEMatch.objects.filter(pk=m.pk).update(matched_version='1.19.0')  # a rescan read another version
        self.answer(job, reply('likely'))
        row = Triage.objects.get()
        self.assertEqual((row.status, row.verdict_id), ('pending', None))
        self.assertEqual(TriageVerdict.objects.count(), 1)  # the answer is kept for its own signature

    def test_a_secret_the_model_echoes_is_masked_before_it_is_parsed(self):
        self.match()
        self.ask()
        self.answer(self.take()[0], reply('likely', remediation='rotate AKIAIOSFODNN7EXAMPLE now'))
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', TriageVerdict.objects.get().remediation)


class BudgetTests(Base):
    def test_a_question_queued_on_an_earlier_day_is_counted_again_against_today(self):
        for n in range(3):
            self.match(f'h{n}.example.com', version=f'1.1{n}.0')
        self.ask()
        TriageCall.objects.update(started_at=timezone.now() - datetime.timedelta(days=2))
        TriageCall.objects.create(kind='cve_match', signature='z' * 40, project=self.project, status='succeeded', expires_at=timezone.now())
        with mock.patch.dict(os.environ, {'CVENGINE_TRIAGE_MAX_PER_PROJECT_DAY': '2'}):
            taken = self.take()
        self.assertEqual(len(taken), 1)  # today has room for one more
        self.assertEqual(AIJob.objects.filter(status='queued').count(), 2)  # the others wait for tomorrow
        self.assertEqual(triage.asked_today(self.project.pk), 2)

    def test_a_job_whose_claim_is_gone_is_dropped_not_asked(self):
        self.match()
        self.ask()
        TriageCall.objects.update(status='expired')
        self.assertEqual(self.take(), [])
        self.assertEqual(AIJob.objects.get().status, 'expired')


class HousekeepingTests(Base):
    def test_lost_continuations_are_applied_and_old_questions_expire(self):
        self.match()
        self.ask()
        job = self.take()[0]
        self.post(job, text=reply('likely'))
        AIJob.objects.update(answered_at=timezone.now() - datetime.timedelta(minutes=5))  # its Celery task was lost
        out = ai_jobs.housekeeping()
        self.assertEqual(out['applied'], 1)
        self.assertEqual(Triage.objects.get().status, 'triaged')
        other = self.match('b.example.com', version='1.17.0')
        triage.run_triage(triage.track(triage.with_cves([other])))
        AIJob.objects.filter(status='queued').update(created_at=timezone.now() - ai_jobs.TTL - datetime.timedelta(hours=1))
        self.assertEqual(ai_jobs.housekeeping()['expired'], 1)
        self.assertEqual(TriageCall.objects.filter(status='expired').count(), 1)
        self.assertEqual(triage.sweep(self.project.pk)['asked'], 1)  # asked again
        AIJob.objects.exclude(status='queued').update(finished_at=timezone.now() - ai_jobs.KEEP - datetime.timedelta(days=1))
        ai_jobs.housekeeping()
        self.assertEqual(list(AIJob.objects.values_list('status', flat=True)), ['queued'])

    def test_work_cut_off_by_an_update_is_simply_asked_again(self):
        """The old code reserved its call for ten minutes and asked the provider itself; a restart kills that call. Its claim runs out, the
        rows are still pending, and the sweep queues them for the reviewer container."""
        m = self.match()
        pairs = triage.track(triage.with_cves([m]))
        TriageCall.objects.create(kind='cve_match', signature=pairs[0][1]['signature'], project=self.project,
                                  expires_at=timezone.now() - datetime.timedelta(seconds=1))
        self.assertEqual(triage.sweep(self.project.pk)['asked'], 1)
        self.assertEqual(AIJob.objects.count(), 1)


class ConfigTests(Base):
    def test_the_config_carries_the_job_block_with_every_setting_resolved(self):
        AIProviderSettings.objects.update(max_tokens=900, structured_mode='off', keep_alive='30m')
        with mock.patch.dict(os.environ, {'CVENGINE_AI_TIMEOUT': '600', 'CVENGINE_AI_STRUCTURED': 'all', 'CVENGINE_AI_REASONING': 'low'}):
            data = call(self.raw, 'GET', '/api/v1/reviewer/config')[1]
        self.assertTrue(data['jobs_enabled'])
        block = data['jobs']
        self.assertEqual((block['provider'], block['model'], block['base_url']), ('vllm', 'm', 'http://192.0.2.10:8000/v1'))
        self.assertEqual(block['runtime'], {'request_timeout': 600, 'connect_timeout': None, 'max_tokens': 900, 'context_tokens': None,
                                            'structured_mode': 'off', 'reasoning': 'low', 'keep_alive': '30m'})  # the page wins over .env
        with mock.patch('cveFeed.reviewer.paused', return_value=True):
            data = call(self.raw, 'GET', '/api/v1/reviewer/config')[1]
        self.assertEqual((data['jobs_enabled'], data['jobs_why'], 'jobs' in data), (False, 'scanning is paused', False))

    def test_the_settings_page_says_when_ai_waits_for_the_container(self):
        self.match()
        self.ask()
        client = Client()
        client.force_login(self.admin)
        with mock.patch.dict(os.environ, {'CVENGINE_REVIEWER': '0'}):
            data = client.get('/cve/api/settings/reviewer').json()
        self.assertTrue(data['ai_jobs']['waiting_for_reviewer'])
        self.assertIn('AI is waiting for the reviewer container', data['ai_jobs']['message'])
        data = client.get('/cve/api/settings/reviewer').json()
        self.assertEqual((data['ai_jobs']['queued'], data['ai_jobs']['message']), (1, ''))  # on, and the job is fresh


class ContainerParityTests(TestCase):
    """The container's copy of the provider table (reviewer/cvengine_reviewer/profiles.py) is the server's."""

    def test_the_two_tables_agree(self):
        sys.path.insert(0, ai_queue.REVIEWER_DIR)
        self.addCleanup(sys.path.remove, ai_queue.REVIEWER_DIR)
        from cvengine_reviewer import profiles
        self.assertEqual(set(profiles.PROFILES), set(ai_profiles.PROFILES))
        for name, theirs in ai_profiles.PROFILES.items():
            ours = profiles.PROFILES[name]
            for field in ('transport', 'default_base', 'default_model', 'needs_key', 'needs_url', 'token_param', 'reply_cap', 'reply_cap_by_stage',
                          'temperature_ok', 'seed_ok', 'structured', 'structured_default', 'reasoning_field'):
                self.assertEqual(getattr(ours, field), getattr(theirs, field), (name, field))
            for model in ('claude-sonnet-4-5', 'claude-opus-4-6', 'claude-haiku-5-5', 'gpt-5.4-nano', 'o3', 'qwen3:8b', 'gpt-oss:20b', 'm'):
                for level in (None, 'off', 'low', 'max'):
                    self.assertEqual(profiles.reasoning_plan(name, model, level, 4096), ai_profiles.reasoning_plan(name, model, level, 4096))
        self.assertEqual(profiles.STAGE_REPLY_CAPS, ai_profiles.STAGE_REPLY_CAPS)
