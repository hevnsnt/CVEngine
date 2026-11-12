"""Retest on fix (``cveFeed.fix_retest``): a finding marked fixed is checked again on a Sentinel, and only a check that ran says it is gone.

Marking fixed (a person through REST, MCP or the bulk call, or an agent) queues a retest of the check that proved the finding; the result is
verified fixed, still reproduces (reopened, with the new exchange as proof) or could not retest (stays fixed, not verified, retried with
back-off, at most daily). A host that could not be reached is never read as fixed. A finding with no stored check says so and is never verified.
"""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_dispatch
from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import counts, fix_retest, reviewer, validation
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, FindingAuditEvent, FixRetest, HygieneFinding, Triage
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

HIT_STEP = {'kind': 'nuclei_template', 'label': 'nuclei template CVE-2099-7001', 'display': 'nuclei -t cve-2099-7001.yaml -u www.example.com',
            'target': 'www.example.com', 'ran_at': '2026-11-01T10:00:00+00:00', 'result': 'hit', 'summary': 'the template matched (panel)'}
EXCHANGE = {'matched_at': 'https://www.example.com/x', 'matcher_name': 'panel', 'request': 'GET /x HTTP/1.1', 'response': 'HTTP/1.1 200 OK\n\nvulnerable'}
NEW_EXCHANGE = {**EXCHANGE, 'response': 'HTTP/1.1 200 OK\n\nstill vulnerable'}


def hit_result():
    return {'status': 'hit', 'summary': 'the template matched (panel)', 'evidence': NEW_EXCHANGE}


def gone_result():
    return {'status': 'no_match', 'summary': 'the template did not match'}


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org, other = Org.objects.create(name='Rt', slug='rt-org'), Org.objects.create(name='Else', slug='rt-else')
        cls.proj = Project.objects.create(name='Rt', slug='rt-proj', insert_date=now, org=cls.org)
        cls.other = Project.objects.create(name='Else', slug='rt-else-proj', insert_date=now, org=other)
        cls.domain = Domain.objects.create(name='example.com', project=cls.proj, insert_date=now)
        engine = EngineType.objects.create(engine_name='rt-e', yaml_configuration='x', default_engine=True)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, scan_status=2, start_scan_date=now)
        cls.sub = Subdomain.objects.create(name='www.example.com', target_domain=cls.domain, scan_history=cls.scan)
        cls.alice, cls.viewer, cls.outsider = (User.objects.create_user(n, password='x') for n in ('rt-alice', 'rt-viewer', 'rt-outsider'))
        ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
        ProjectMembership.objects.create(user=cls.viewer, project=cls.proj, role='audit')
        OrgMembership.objects.create(user=cls.outsider, org=other, role='admin')
        _, cls.t_alice = create_token(cls.alice, 'agent')
        _, cls.t_viewer = create_token(cls.viewer, 'viewer')
        _, cls.t_out = create_token(cls.outsider, 'out')
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7001', cvss=9.8, kev=True, published_at=now, affected=[])
        token, _ = create_token(cls.alice, 'sentinel-token')
        cls.agent = Agent.objects.create(token=token, name='sentinel-east', kind='scanner', status='active')

    base = '/api/v1/projects/rt-proj'

    def setUp(self):
        self.match = CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sub, source='tech', matched_product='panel', matched_version='1.2',
                                             version_in_range=True, confidence=0.8, ai_verdict='uncertain', scan_history=self.scan,
                                             evidence={'ip': '192.0.2.10', 'port': 443}, template_result='vulnerable')
        self.triage = self.make_triage(match=self.match, kind='cve_match', steps=[dict(HIT_STEP)], evidence={'nuclei_template': dict(EXCHANGE)},
                                       status='hit')
        self.queue = mock.patch('cveFeed.tasks.retest_fixed_finding.apply_async')
        self.queued = self.queue.start()
        self.addCleanup(self.queue.stop)

    def make_triage(self, kind, steps, evidence=None, status='hit', **finding):
        return Triage.objects.create(project=self.proj, domain=self.domain, host='www.example.com', kind=kind, signature='sig', validation_status=status,
                                     validation_steps=steps, validation_evidence=evidence or {}, validated_at=timezone.now(), **finding)

    def mark(self, status='fixed', kind='match', finding=None, note='patched'):
        finding = finding or self.match
        return call(self.t_alice, 'PATCH', f'{self.base}/findings/{kind}/{finding.pk}', {'status': status, 'note': note})

    def refresh(self):
        self.match.refresh_from_db()
        self.triage.refresh_from_db()


def planned(subject=None, host='www.example.com'):
    """What ``fix_retest._planned`` answers for a template check: the planned check, with no database or template file behind it."""
    check = {'kind': 'nuclei_template', 'label': 'nuclei template CVE-2099-7001', 'display': 'nuclei', 'target': host, 'asset': host, 'service': 'validate:nuclei',
             'params': {'template': '/t/x.yaml', 'project_id': None}}
    return mock.patch('cveFeed.fix_retest._planned', return_value=(subject or {'kind': 'cve_match', 'host': host, 'candidate_services': [{'ip': '192.0.2.10', 'port': 443}]},
                                                                [check], []))


class RunsAs:
    """Make the runner of ``kind`` answer ``result``, as the Sentinel named ``agent`` ran it."""

    def __init__(self, test, result, agent=None, kind='nuclei_template'):
        self.patch = mock.patch.dict(validation.RUNNERS, {kind: self.run})
        self.result, self.agent = result, agent
        self.ran = 0

    def run(self, check):
        self.ran += 1
        sentinel_dispatch.Result({}, agent_id=self.agent.pk if self.agent else None)  # what the dispatch returns: the Sentinel is on it
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def __enter__(self):
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()


class StateTests(Base):
    """What the finding says about itself (``summary``): no query, and never 'verified' without a check that ran."""

    def test_a_finding_that_was_never_marked_fixed_has_no_state(self):
        self.assertEqual(fix_retest.summary('open', self.triage)['state'], '')
        self.assertEqual(fix_retest.summary('in_progress', None)['state'], '')

    def test_fixed_with_no_triage_row_is_marked_fixed_and_cannot_be_rechecked(self):
        s = fix_retest.summary('fixed', None)
        self.assertEqual((s['state'], s['text'], s['can_retest']), ('no_check', 'Marked fixed, cannot be re-checked automatically', False))

    def test_fixed_with_proof_but_never_retested_is_fixed_not_verified(self):
        s = fix_retest.summary('fixed', self.triage)
        self.assertEqual((s['state'], s['text'], s['can_retest']), ('not_verified', 'Fixed, not verified: not re-checked yet', True))

    def test_the_words_of_each_state(self):
        at = timezone.now().replace(year=2026, month=11, day=12)
        for state, reason, text in (('verifying', '', 'Fixed, verifying'), ('verified_fixed', '', 'Verified fixed on 2026-11-12'),
                                    ('not_verified', 'the host did not answer', 'Fixed, not verified: the host did not answer'),
                                    ('no_check', 'x', 'Marked fixed, cannot be re-checked automatically')):
            self.triage.retest_state, self.triage.retest_reason, self.triage.retest_at = state, reason, at
            self.assertEqual(fix_retest.summary('fixed', self.triage)['text'], text, state)
        self.triage.retest_state = 'still_reproduces'
        self.assertEqual(fix_retest.summary('open', self.triage)['text'], 'Still reproduces, reopened on 2026-11-12')

    def test_the_proof_is_the_hit_steps_else_the_reaffirmed_ones(self):
        self.assertEqual([c['kind'] for c in fix_retest.proof_checks(self.triage)], ['nuclei_template'])
        self.triage.validation_steps = [{**HIT_STEP, 'result': 'no_match'}, {**HIT_STEP, 'kind': 'nmap_sv', 'target': '192.0.2.10:443', 'result': 'reaffirmed'}]
        self.assertEqual([c['kind'] for c in fix_retest.proof_checks(self.triage)], ['nmap_sv'])
        self.triage.validation_steps = [{**HIT_STEP, 'result': 'observed'}, {**HIT_STEP, 'result': 'failed'}]
        self.assertEqual(fix_retest.proof_checks(self.triage), [])

    def test_a_kind_with_no_validated_check_has_no_proof(self):
        vuln = Vulnerability.objects.create(name='Exposed panel', severity=3, subdomain=self.sub, target_domain=self.domain, open_status=True,
                                            http_url='https://www.example.com/', source='nuclei')
        t = self.make_triage(kind='nuclei', steps=[dict(HIT_STEP)], vulnerability=vuln)
        self.assertEqual(fix_retest.proof_checks(t), [])
        self.assertEqual(fix_retest.summary('fixed', t)['state'], 'no_check')


class MarkFixedTests(Base):
    def test_marking_a_match_fixed_queues_a_retest_of_the_same_check(self):
        status, _ = self.mark()
        self.assertEqual(status, 200)
        job = FixRetest.objects.get()
        self.assertEqual((job.status, job.source, job.project_id, job.triage_id), ('queued', 'automatic', self.proj.pk, self.triage.pk))
        self.assertEqual([(c['kind'], c['target']) for c in job.check_run['checks']], [('nuclei_template', 'www.example.com')])
        self.queued.assert_called_once()
        self.refresh()
        self.assertEqual((self.match.remediation_status, self.triage.retest_state), ('fixed', 'verifying'))
        self.assertEqual(call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.match.pk}')[1]['retest']['text'], 'Fixed, verifying')

    def test_it_runs_through_the_validation_queue_not_a_new_path(self):
        self.mark()
        self.assertEqual(self.queued.call_args.kwargs['args'], [FixRetest.objects.get().pk])
        from cveFeed.tasks import retest_fixed_finding
        self.assertEqual(retest_fixed_finding.queue, 'validation_priority_queue')

    def test_the_bulk_call_and_the_mcp_tools_queue_one_each(self):
        status, body = call(self.t_alice, 'POST', f'{self.base}/findings/status', {'items': [{'kind': 'match', 'id': self.match.pk}], 'status': 'fixed'})
        self.assertEqual((status, body['updated']), (200, 1))
        self.assertEqual(FixRetest.objects.count(), 1)
        self.mark('open')
        FixRetest.objects.update(status='done', outcome='not_verified')  # the first one is over
        err, _ = tool_call(self.t_alice, 'update_remediation_status', {'project': 'rt-proj', 'match_id': self.match.pk, 'status': 'fixed'})
        self.assertFalse(err)
        self.assertEqual(FixRetest.objects.count(), 2)

    def test_an_agent_that_reports_a_fix_queues_one_too(self):
        from agentapi import agent_broker
        task = mock.Mock(project=self.proj, match_id=self.match.pk, kind='remediate', mode='apply')
        with mock.patch.object(agent_broker, '_match_with_host', return_value=CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=self.match.pk)):
            agent_broker._apply_result(task, mock.Mock(**{'name': 'fixer'}), self.alice, {'summary': 'upgraded', 'outcome': 'fixed'})
        self.assertEqual(FixRetest.objects.count(), 1)

    def test_other_statuses_and_a_second_fixed_queue_nothing(self):
        self.mark('accepted_risk')
        self.mark('in_progress')
        self.assertEqual(FixRetest.objects.count(), 0)
        self.mark('fixed')
        self.mark('fixed')
        self.assertEqual(FixRetest.objects.count(), 1)

    def test_a_finding_with_no_stored_check_is_marked_fixed_but_never_verified(self):
        self.triage.validation_steps, self.triage.validation_status = [], 'no_check'
        self.triage.save()
        self.mark()
        self.assertEqual(FixRetest.objects.count(), 0)
        self.queued.assert_not_called()
        self.refresh()
        self.assertEqual(self.triage.retest_state, 'no_check')
        r = call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.match.pk}/retest')[1]
        self.assertEqual((r['retest']['state'], r['retest']['text']), ('no_check', 'Marked fixed, cannot be re-checked automatically'))

    def test_a_finding_with_no_triage_row_is_the_same(self):
        hyg = HygieneFinding.objects.create(domain=self.domain, host='www.example.com', check_name='spf_missing', severity=2, title='No SPF')
        self.assertEqual(self.mark(kind='hygiene', finding=hyg)[0], 200)
        self.assertEqual(FixRetest.objects.count(), 0)
        r = call(self.t_alice, 'GET', f'{self.base}/findings/hygiene/{hyg.pk}/retest')[1]
        self.assertEqual(r['retest']['state'], 'no_check')

    def test_a_status_changed_by_hand_afterwards_starts_the_state_over(self):
        self.mark()
        self.mark('open')
        self.refresh()
        self.assertEqual(self.triage.retest_state, '')
        self.assertEqual(call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.match.pk}/retest')[1]['retest']['state'], '')

    def test_a_broken_queue_never_stops_the_status_change(self):
        self.queued.side_effect = RuntimeError('broker down')
        self.assertEqual(self.mark()[0], 200)
        self.refresh()
        self.assertEqual(self.match.remediation_status, 'fixed')
        self.assertEqual((self.triage.retest_state, FixRetest.objects.get().outcome), ('not_verified', 'not_verified'))
        self.assertIn('could not be queued', self.triage.retest_reason)


class OutcomeTests(Base):
    def fixed_and_run(self, result, alive=True, agent=None):
        self.mark()
        job = FixRetest.objects.get()
        with planned(), RunsAs(self, result, agent or self.agent), mock.patch('agentapi.probe_dispatch.try_alive', return_value={'x': alive}) as probe, \
                mock.patch('cveFeed.notify._send') as send:
            out = fix_retest.run(job.pk)
        self.refresh()
        job.refresh_from_db()
        return out, job, probe, send

    def test_verified_fixed_when_the_check_ran_the_host_answered_and_it_no_longer_reproduces(self):
        out, job, probe, _ = self.fixed_and_run(gone_result())
        self.assertEqual(out['outcome'], 'verified_fixed')
        self.assertEqual((job.status, job.outcome, job.sentinel), ('done', 'verified_fixed', 'sentinel-east'))
        self.assertIsNotNone(job.finished_at)
        probe.assert_called_once()
        self.assertEqual((self.match.remediation_status, self.triage.retest_state, self.triage.retest_sentinel), ('fixed', 'verified_fixed', 'sentinel-east'))
        s = fix_retest.summary('fixed', self.triage)
        self.assertRegex(s['text'], r'^Verified fixed on \d{4}-\d{2}-\d{2}$')
        self.assertTrue(FindingAuditEvent.objects.filter(event='retest', finding_id=self.match.pk, after__retest='verified_fixed').exists())
        self.assertTrue(AgentActivity.objects.filter(message__contains='verified fixed').exists())

    def test_still_reproduces_reopens_it_with_the_new_exchange_a_line_and_a_notice(self):
        out, job, _, send = self.fixed_and_run(hit_result())
        self.assertEqual(out['outcome'], 'still_reproduces')
        self.assertEqual((job.outcome, job.sentinel), ('still_reproduces', 'sentinel-east'))
        self.assertEqual(job.evidence['exchange']['response'], NEW_EXCHANGE['response'])
        self.assertEqual((self.match.remediation_status, self.match.remediation_by), ('open', None))
        self.assertIn('Reopened automatically', self.match.remediation_note)
        self.assertEqual((self.triage.retest_state, self.triage.validation_status), ('still_reproduces', 'hit'))
        self.assertEqual(self.triage.validation_evidence['nuclei_template']['response'], NEW_EXCHANGE['response'])  # the new exchange is the proof now
        self.assertTrue(AgentActivity.objects.filter(message__contains='still reproduces').exists())
        send.assert_called_once()
        self.assertIn('marked fixed, but a retest still reproduces it', send.call_args.args[0])
        s = fix_retest.summary(self.match.remediation_status, self.triage)
        self.assertEqual((s['state'], s['label']), ('still_reproduces', 'Still reproduces, reopened'))
        self.assertTrue(FindingAuditEvent.objects.filter(event='status', finding_id=self.match.pk, actor__isnull=True, after__status='open').exists())

    def test_a_host_that_did_not_answer_is_never_fixed(self):
        out, job, _, _ = self.fixed_and_run(gone_result(), alive=False)
        self.assertEqual((out['outcome'], out['reason']), ('not_verified', 'the host did not answer'))
        self.assertEqual((job.outcome, job.reason), ('not_verified', 'the host did not answer'))
        self.assertEqual((self.match.remediation_status, self.triage.retest_state), ('fixed', 'not_verified'))
        self.assertEqual(fix_retest.summary('fixed', self.triage)['text'], 'Fixed, not verified: the host did not answer')
        self.assertNotEqual(counts.retest_counts([self.proj.pk])['verified_fixed'], 1)

    def test_no_sentinel_means_could_not_retest(self):
        out, job, _, _ = self.fixed_and_run({'status': 'failed', 'error': 'not run: no scanner could take this work (nuclei_validate)'})
        self.assertEqual((out['outcome'], job.reason), ('not_verified', 'no Sentinel could take the check'))
        self.assertEqual(self.triage.retest_state, 'not_verified')

    def test_a_check_that_blows_up_or_is_blocked_is_not_fixed_either(self):
        out, _, _, _ = self.fixed_and_run(RuntimeError('boom'))
        self.assertEqual((out['outcome'], self.match.remediation_status), ('not_verified', 'fixed'))

    def test_a_check_that_only_read_something_cannot_tell(self):
        out, _, _, _ = self.fixed_and_run({'status': 'observed', 'summary': 'read a banner'})
        self.assertEqual((out['outcome'], self.match.remediation_status), ('not_verified', 'fixed'))

    def test_a_check_that_is_no_longer_planned_is_not_verified(self):
        self.mark()
        job = FixRetest.objects.get()
        with mock.patch('cveFeed.fix_retest._planned', return_value=({}, [], [{'kind': 'nuclei_template', 'target': 'x'}])):
            out = fix_retest.run(job.pk)
        self.assertEqual((out['outcome'], out['reason']), ('not_verified', 'the check that proved it is no longer available'))

    def test_the_daily_check_budget_is_the_validation_one(self):
        self.mark()
        job = FixRetest.objects.get()
        with planned(), RunsAs(self, gone_result(), self.agent) as runner, mock.patch('cveFeed.validation._reserve_validation_check', return_value=False):
            out = fix_retest.run(job.pk)
        self.assertEqual((runner.ran, out['outcome']), (0, 'not_verified'))

    def test_a_finding_reopened_by_hand_meanwhile_is_left_alone(self):
        self.mark()
        job = FixRetest.objects.get()
        self.mark('open')
        with planned(), RunsAs(self, hit_result(), self.agent) as runner:
            out = fix_retest.run(job.pk)
        self.assertEqual((out, runner.ran), ({'skipped': 'not fixed'}, 0))

    def test_the_sentinel_is_recorded_from_the_dispatch_result(self):
        with fix_retest.recording_sentinels() as seen:
            sentinel_dispatch.Result({}, agent_id=self.agent.pk)
            sentinel_dispatch.Result({})
        self.assertEqual(seen, [self.agent.pk])
        sentinel_dispatch.Result({}, agent_id=self.agent.pk)  # outside the block nothing is kept anywhere


class RetryTests(Base):
    def failed_try(self, when):
        self.mark()
        job = FixRetest.objects.get(status='queued')
        with planned(), RunsAs(self, {'status': 'failed', 'error': 'x'}, None):
            fix_retest.run(job.pk)
        job.refresh_from_db()
        return job

    def test_a_retest_that_could_not_tell_is_tried_again_after_a_day_with_back_off(self):
        now = timezone.now()
        job = self.failed_try(now)
        self.assertAlmostEqual((job.next_attempt_at - job.finished_at).total_seconds(), 86400, delta=5)
        self.assertEqual(fix_retest.retry_delay(1), timedelta(days=1))
        self.assertEqual([fix_retest.retry_delay(n).days for n in (1, 2, 3, 4, 5, 9)], [1, 2, 4, 7, 7, 7])
        self.assertTrue(all(fix_retest.retry_delay(n) >= timedelta(days=1) for n in range(1, 12)))  # never more than once a day

    def test_the_sweep_queues_only_what_is_due_and_once(self):
        job = self.failed_try(timezone.now())
        self.queued.reset_mock()
        self.assertEqual(fix_retest.sweep(now=job.finished_at + timedelta(hours=23)), {'queued': 0})
        self.assertEqual(fix_retest.sweep(now=job.finished_at + timedelta(days=1, minutes=1)), {'queued': 1})
        self.assertEqual(fix_retest.sweep(now=job.finished_at + timedelta(days=1, minutes=2)), {'queued': 0})
        retry = FixRetest.objects.order_by('-id').first()
        self.assertEqual((retry.source, retry.attempts, retry.status), ('retry', 2, 'queued'))
        self.queued.assert_called_once()

    def test_the_sweep_leaves_a_finding_that_is_no_longer_fixed(self):
        job = self.failed_try(timezone.now())
        self.mark('accepted_risk')
        self.assertEqual(fix_retest.sweep(now=job.finished_at + timedelta(days=2)), {'queued': 0})

    def test_it_gives_up_after_the_last_try_and_says_so(self):
        self.mark()
        job = FixRetest.objects.get()
        FixRetest.objects.filter(pk=job.pk).update(attempts=fix_retest.MAX_TRIES)
        with planned(), RunsAs(self, {'status': 'failed', 'error': 'x'}, None):
            fix_retest.run(job.pk)
        job.refresh_from_db()
        self.refresh()
        self.assertIsNone(job.next_attempt_at)
        self.assertIn('gave up', self.triage.retest_reason)
        self.assertEqual(self.triage.retest_state, 'not_verified')

    def test_the_validation_sweep_task_also_runs_the_retest_sweep(self):
        from cveFeed import tasks
        with mock.patch('cveFeed.hot_validation.sweep', return_value={}), mock.patch('cveFeed.fix_retest.sweep', return_value={'queued': 3}):
            self.assertEqual(tasks.queue_hot_validations()['retests'], 3)


class RetestNowTests(Base):
    def test_retest_now_on_a_fixed_finding_queues_one_and_is_not_queued_twice(self):
        self.mark()
        FixRetest.objects.update(status='done', outcome='not_verified', finished_at=timezone.now())
        Triage.objects.update(retest_state='not_verified', retest_reason='the host did not answer')
        self.queued.reset_mock()
        status, body = call(self.t_alice, 'POST', f'{self.base}/findings/match/{self.match.pk}/retest')
        self.assertEqual((status, body['queued'], body['retest']['state']), (202, True, 'verifying'))
        status, body = call(self.t_alice, 'POST', f'{self.base}/findings/match/{self.match.pk}/retest')
        self.assertEqual((status, body['queued']), (202, False))
        self.queued.assert_called_once()
        self.assertEqual(FixRetest.objects.filter(source='manual', requested_by=self.alice).count(), 1)

    def test_it_needs_a_finding_marked_fixed(self):
        self.assertEqual(call(self.t_alice, 'POST', f'{self.base}/findings/match/{self.match.pk}/retest')[0], 400)

    def test_it_follows_the_status_permissions_and_the_project_scope(self):
        self.mark()
        self.assertEqual(call(self.t_viewer, 'POST', f'{self.base}/findings/match/{self.match.pk}/retest')[0], 403)
        self.assertEqual(call(self.t_out, 'POST', f'{self.base}/findings/match/{self.match.pk}/retest')[0], 404)
        self.assertEqual(call(self.t_out, 'GET', f'{self.base}/findings/match/{self.match.pk}/retest')[0], 404)
        self.assertEqual(call(self.t_viewer, 'GET', f'{self.base}/findings/match/{self.match.pk}/retest')[0], 200)
        self.assertEqual(call(self.t_alice, 'POST', f'{self.base}/findings/route/1/retest')[0], 404)

    def test_the_read_carries_the_history_with_sentinel_time_and_evidence(self):
        self.mark()
        job = FixRetest.objects.get()
        with planned(), RunsAs(self, hit_result(), self.agent), mock.patch('cveFeed.notify._send'):
            fix_retest.run(job.pk)
        body = call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.match.pk}/retest')[1]
        self.assertEqual((body['status'], body['retest']['state']), ('open', 'still_reproduces'))
        h = body['history'][0]
        self.assertEqual((h['outcome'], h['sentinel'], h['evidence']['exchange']['response']), ('still_reproduces', 'sentinel-east', NEW_EXCHANGE['response']))
        self.assertTrue(h['finished'] and h['requested'])

    def test_the_mcp_tools_read_and_start_a_retest(self):
        self.mark()
        err, body = tool_call(self.t_alice, 'get_finding_retest', {'project': 'rt-proj', 'kind': 'match', 'id': self.match.pk})
        self.assertFalse(err)
        self.assertEqual(body['retest']['state'], 'verifying')
        FixRetest.objects.update(status='done', outcome='not_verified')
        Triage.objects.update(retest_state='not_verified')
        err, body = tool_call(self.t_alice, 'retest_finding', {'project': 'rt-proj', 'kind': 'match', 'id': self.match.pk})
        self.assertFalse(err)
        self.assertTrue(body['queued'])


class ListTests(Base):
    def other_match(self, n):
        cve = CVEEntry.objects.create(cve_id=f'CVE-2099-71{n:02d}', cvss=5.0, published_at=timezone.now(), affected=[])
        m = CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, source='tech', matched_product='p', matched_version='1', version_in_range=True,
                                    confidence=0.8, ai_verdict='uncertain', scan_history=self.scan, remediation_status='fixed')
        t = self.make_triage(kind='cve_match', steps=[dict(HIT_STEP)], match=m)
        Triage.objects.filter(pk=t.pk).update(retest_state='verified_fixed')
        return m

    def listing(self, **params):
        query = '&'.join(f'{k}={v}' for k, v in params.items())
        return call(self.t_alice, 'GET', f'{self.base}/findings?{query}')

    def test_the_list_row_carries_the_state(self):
        self.match.remediation_status = 'fixed'
        self.match.save()
        Triage.objects.update(retest_state='not_verified', retest_reason='the host did not answer')
        rows = self.listing(status='all')[1]['results']
        row = next(r for r in rows if r['id'] == self.match.pk)
        self.assertEqual(row['retest']['text'], 'Fixed, not verified: the host did not answer')

    def test_the_status_filters_and_counts_include_the_new_states(self):
        verified = self.other_match(1)
        self.match.remediation_status = 'fixed'
        self.match.save()  # fixed with proof and no retest yet: fixed, not verified
        reopened = self.other_match(2)
        CVEMatch.objects.filter(pk=reopened.pk).update(remediation_status='open')
        Triage.objects.filter(match=reopened).update(retest_state='still_reproduces')
        ids = lambda **p: sorted(r['id'] for r in self.listing(**p)[1]['results'])  # noqa: E731
        self.assertEqual(ids(status='verified_fixed'), [verified.pk])
        self.assertEqual(ids(status='unverified_fixed'), [self.match.pk])
        self.assertEqual(ids(status='reopened'), [reopened.pk])
        self.assertEqual(self.listing(status='verified_fixed')[1]['retest'], {'verified_fixed': 1, 'unverified_fixed': 1, 'reopened': 1})
        self.assertEqual(counts.retest_counts([self.proj.pk]), {'verified_fixed': 1, 'unverified_fixed': 1, 'reopened': 1})
        self.assertEqual(counts.retest_counts([self.other.pk]), {'verified_fixed': 0, 'unverified_fixed': 0, 'reopened': 0})  # another project's findings never count

    def test_the_cve_matches_list_filters_on_the_same_retest_states(self):
        """The CVE matches page offers the three retest chips the Findings list has, so its status filter takes the same three values (UI-10)."""
        verified = self.other_match(1)
        self.match.remediation_status = 'fixed'
        self.match.save()
        reopened = self.other_match(2)
        CVEMatch.objects.filter(pk=reopened.pk).update(remediation_status='open')
        Triage.objects.filter(match=reopened).update(retest_state='still_reproduces')
        ids = lambda status: sorted(r['id'] for r in call(self.t_alice, 'GET', f'{self.base}/matches?status={status}&verdict=')[1]['results'])  # noqa: E731
        self.assertEqual(ids('verified_fixed'), [verified.pk])
        self.assertEqual(ids('unverified_fixed'), [self.match.pk])
        self.assertEqual(ids('reopened'), [reopened.pk])
        self.assertEqual(ids('fixed'), sorted([verified.pk, self.match.pk]))  # the plain remediation statuses still filter on the status itself

    def test_a_list_of_fixed_findings_costs_no_query_per_row(self):
        def queries(n):
            for i in range(n):
                self.other_match(10 + i + 20 * n)
            self.listing(status='fixed')  # warm what is cached per process (the caller's role, the internal ranges): it is not per row
            with CaptureQueriesContext(connection) as ctx:
                status, body = self.listing(status='fixed')
            if getattr(self, 'show', False):
                print('\n'.join(q['sql'][:200] for q in ctx.captured_queries))
            self.assertEqual(status, 200)
            self.assertGreaterEqual(len(body['results']), n)
            return len(ctx)
        few = queries(2)
        many = queries(12)
        self.assertEqual(few, many)

    def test_the_detail_carries_state_and_history(self):
        self.mark()
        body = call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.match.pk}')[1]
        self.assertEqual(body['retest']['state'], 'verifying')
        self.assertEqual(body['retest']['history'][0]['status'], 'queued')


class GuardTests(Base):
    def test_the_ai_reviewer_does_not_take_a_marked_fixed_finding_up_and_holds_a_reopened_one(self):
        Triage.objects.filter(pk=self.triage.pk).update(validation_status='clean')
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result='', evidence={})  # no hard evidence: only the status a person set holds it
        self.triage.refresh_from_db()
        self.mark()
        self.match.refresh_from_db()
        self.assertFalse(Triage.objects.filter(reviewer.open_q(), pk=self.triage.pk).exists())  # not offered for review while marked fixed
        self.assertEqual(reviewer.close_gate('cve_match', self.triage, self.match, [])[0], 'held')  # and never closed on that alone (a status a person set)
        Triage.objects.filter(pk=self.triage.pk).update(retest_state='still_reproduces', validation_status='clean')
        CVEMatch.objects.filter(pk=self.match.pk).update(remediation_status='open')
        self.triage.refresh_from_db()
        self.match.refresh_from_db()
        outcome, reason = reviewer.close_gate('cve_match', self.triage, self.match, [])
        self.assertEqual(outcome, 'disputed')
        self.assertIn('retest', reason)

    def test_a_rescan_row_keeps_what_a_retest_found(self):
        from cveFeed import triage as triage_lib
        self.triage.retest_state, self.triage.retest_at = 'verified_fixed', timezone.now()
        self.triage.save()
        fields = triage_lib._inherited_fields(self.triage, {'signature': 'sig', 'evidence_key': 'k', 'kind': 'cve_match', 'facts': {}}, timezone.now())
        self.assertEqual(fields['retest_state'], 'verified_fixed')


class ReportTests(Base):
    def test_a_report_tells_verified_fixed_from_marked_fixed(self):
        from cveFeed import report_data
        self.match.remediation_status = 'fixed'
        self.match.save()
        self.assertEqual(report_data._status_label('fixed', self.triage), 'Marked fixed, not verified')
        Triage.objects.filter(pk=self.triage.pk).update(retest_state='verified_fixed', retest_at=timezone.now())
        self.triage.refresh_from_db()
        self.assertEqual(report_data._status_label('fixed', self.triage), 'Verified fixed')
        self.assertEqual(report_data._status_label('fixed', None), 'Marked fixed, cannot be re-checked')
        self.assertEqual(report_data._status_label('open', self.triage), 'Open')
        sources = {'cve': CVEMatch.objects.filter(pk=self.match.pk).annotate()}
        self.assertEqual(report_data._status_counts(sources), {'Verified fixed': 1})
        Triage.objects.filter(pk=self.triage.pk).update(retest_state='')
        self.assertEqual(report_data._status_counts(sources), {'Marked fixed, not verified': 1})
