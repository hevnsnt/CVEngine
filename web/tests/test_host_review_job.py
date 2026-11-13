"""The AI host review as an AI job (cveFeed.host_review): the queue, the validator of the reply, how a reply is applied through the finding review's
own gates, and the next step: automatic or only recommended (D6). The model is a stub: a reply is a JSON text delivered to ``ai_jobs.apply``.
Every safety test here fails without its guard."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import ai_jobs, host_actions, host_review, reviewer, triage
from cveFeed.models import (AIJob, CVEEntry, CVEMatch, FindingAuditEvent, FindingComment, FindingReview, HostReview, HostScreenshot, HostState,
                            ProjectSettings, ReviewerSettings, Triage)
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests import ai_queue
from tests.test_host_ai_review import HOSTILE

HOST = 'www.example.com'


class Fixture(TestCase):
    """A host with open CVE matches that the reviewer may close, an enabled provider, and scanning not paused."""

    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='HJ', slug='hj-org')
        self.proj = Project.objects.create(name='HJ', slug='hj-proj', insert_date=now, org=self.org)
        self.other = Project.objects.create(name='HJ2', slug='hj-proj2', insert_date=now, org=self.org)
        self.domain = Domain.objects.create(name='example.com', project=self.proj, insert_date=now)
        self.other_domain = Domain.objects.create(name='example.org', project=self.other, insert_date=now)
        engine = EngineType.objects.create(engine_name='hj-e', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=now)
        self.other_scan = ScanHistory.objects.create(domain=self.other_domain, scan_type=engine, scan_status=2, start_scan_date=now)
        self.sub = self.host_of(self.domain, self.scan, HOST, self.proj, '192.0.2.10')
        self.user = User.objects.create_user('hj-user', password='x')
        self.counter = 0
        ai_queue.configure('vllm', model='m')
        ReviewerSettings.objects.filter(pk=ReviewerSettings.current().pk).update(enabled=True, auto_close=True, host_review_enabled=True)  # all three are off until a person turns them on (test_host_review_default_off)
        for project in (self.proj, self.other):  # and a project starts on recommend: these tests are about the automatic mode unless one says otherwise
            ProjectSettings.objects.update_or_create(project=project, defaults={'host_review_mode': 'auto'})
        for patcher in (mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, project=None: list(hosts)),):
            patcher.start()
            self.addCleanup(patcher.stop)

    def host_of(self, domain, scan, name, project, address):
        sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan, page_title='Welcome', http_url=f'https://{name}/')
        ip = IpAddress.objects.create(address=address)
        port = Port.objects.create(number=22, service_name='ssh', product='OpenSSH', version='8.9', banner='SSH-2.0-OpenSSH_8.9')
        ip.ports.add(port)
        sub.ip_addresses.add(ip)
        HostState.objects.create(project=project, domain=domain, host=name, fingerprint='f' * 40)
        self.port = port
        return sub

    def match(self, sub=None, scan=None, **over):
        self.counter += 1
        n = self.counter
        cve = CVEEntry.objects.create(cve_id=f'CVE-2099-{7000 + n}', cvss=9.8, published_at=timezone.now(), affected=[], original_description='A flaw.')
        row = CVEMatch.objects.create(cve_entry=cve, subdomain=sub or self.sub, source='tech', matched_product=f'lib-{n}', matched_version='1.2',
                                      version_in_range=False, confidence=0.8, ai_verdict='uncertain', scan_history=scan or self.scan,
                                      evidence={'source': 'tech'}, **over)
        triage.track([row])
        return row

    def row_of(self, match):
        return Triage.objects.get(match=match)

    def queue(self, project=None, host=HOST):
        return host_review.request(project or self.proj, host)

    def body(self, verdicts, action='none', target='', reason='nothing_to_do', step_note='', host_note='The findings of this host were read together.'):
        """``verdicts`` is ``{ref: (verdict, confidence)}`` or ``{ref: dict}``."""
        findings = []
        for ref, v in verdicts.items():
            item = {'ref': ref, 'verdict': v[0], 'confidence': v[1], 'reason_code': 'version_not_affected', 'same_as': '',
                    'note': 'The version shown is outside the affected range.'} if isinstance(v, tuple) else {'ref': ref, **v}
            findings.append(item)
        return {'findings': findings, 'next_step': {'action': action, 'target': target, 'reason_code': reason, 'note': step_note}, 'host_note': host_note}

    def deliver(self, review, body=None, text=None, error=None):
        """The container's answer to the job of ``review``, applied the way the worker applies it."""
        job = AIJob.objects.get(pk=review.ai_job_id)
        job.status, job.answered_at, job.provider, job.model, job.input_tokens, job.output_tokens = 'answered', timezone.now(), 'vllm', 'm', 100, 50
        job.result = {'error': error} if error else {'text': text if text is not None else json.dumps(body)}
        job.save()
        with mock.patch('cveFeed.notify.host_needs_person') as self.notified:
            self.outcome = ai_jobs.apply(job.pk)
        review.refresh_from_db()
        return review

    def verdicts(self, review):
        return {r.triage_id: r for r in FindingReview.objects.filter(host_review=review)}

    def status_of(self, match):
        match.refresh_from_db()
        return match.remediation_status


class QueueTests(Fixture):
    def test_a_review_is_queued_as_one_ai_job_with_a_pinned_temperature_and_the_stage_of_its_own(self):
        self.match()
        review = self.queue()
        job = review.ai_job
        self.assertEqual((job.kind, job.stage, job.project_id, job.dedupe, job.status), ('host_review', 'host_review', self.proj.pk, f'hr:{self.proj.pk}:{HOST}', 'queued'))
        self.assertEqual((job.packet['options']['temperature'], job.packet['options']['seed']), (0, host_review.SEED))
        self.assertEqual(job.packet['options']['max_tokens'], 6000)
        self.assertEqual(ai_jobs.HANDLERS['host_review'], 'cveFeed.host_review')
        self.assertEqual((review.status, review.refs), ('queued', {'f1': self.row_of(CVEMatch.objects.get()).pk}))
        self.assertEqual(job.context['host_review'], review.pk)
        self.assertIn('validate_match', job.context['offered'])
        self.assertNotIn(HOST, json.dumps(job.packet))
        schema = job.packet['schema']
        self.assertFalse(schema['additionalProperties'])
        self.assertEqual(schema['properties']['findings']['items']['properties']['ref']['enum'], ['f1'])
        self.assertTrue(set(schema['properties']['next_step']['properties']['action']['enum']) <= set(host_actions.ACTIONS))

    def test_a_host_is_refused_with_a_reason_when_it_cannot_be_reviewed_now(self):
        for expect, setup in ((404, lambda: None),):  # no open finding is a 409, an unknown host 404
            with self.assertRaises(host_review.HostReviewRefused) as caught:
                host_review.request(self.proj, 'nope.example.com')
            self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(host_review.HostReviewRefused) as caught:
            self.queue()
        self.assertEqual(caught.exception.status, 409)  # nothing open
        self.match()
        self.queue()
        with self.assertRaises(host_review.HostReviewRefused) as caught:
            self.queue()
        self.assertEqual((caught.exception.status, str(caught.exception)), (409, 'a review of this host is already open'))
        self.assertEqual(AIJob.objects.filter(kind='host_review').count(), 1)

    def test_no_provider_a_pause_a_spent_cap_and_a_project_that_turned_it_off_queue_nothing(self):
        self.match()
        cases = []
        with mock.patch('cveFeed.ai_jobs.provider_row', return_value=None):
            cases.append((503, 'no AI provider'))
            with self.assertRaises(host_review.HostReviewRefused) as caught:
                self.queue()
            self.assertEqual((caught.exception.status, str(caught.exception)), (503, 'no AI provider is configured'))
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            with self.assertRaises(host_review.HostReviewRefused) as caught:
                self.queue()
            self.assertEqual(caught.exception.status, 503)
        ReviewerSettings.objects.update_or_create(pk=ReviewerSettings.current().pk, defaults={'host_review_daily_max': 0})
        with self.assertRaises(host_review.HostReviewRefused) as caught:
            self.queue()
        self.assertEqual(caught.exception.status, 429)
        ReviewerSettings.objects.update(host_review_daily_max=100)
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'off'})
        with self.assertRaises(host_review.HostReviewRefused):
            self.queue()
        ReviewerSettings.objects.update(host_review_enabled=False)
        ProjectSettings.objects.filter(project=self.proj).update(host_review_mode='auto')
        with self.assertRaises(host_review.HostReviewRefused):
            self.queue()
        self.assertFalse(HostReview.objects.exists())
        self.assertFalse(AIJob.objects.exists())


class ValidatorTests(Fixture):
    def setUp(self):
        super().setUp()
        self.refs = {'f1': 1, 'f2': 2}
        self.offered = {'none': {'targets': []}, 'validate_match': {'targets': ['f1']}}

    def ok(self, **change):
        body = self.body({'f1': ('true_open', 'high'), 'f2': ('uncertain', 'low')})
        body.update(change)
        return json.dumps(body)

    def test_the_exact_schema_is_accepted_and_parsed(self):
        parsed, why = host_review.validate(self.ok(), self.refs, self.offered)
        self.assertEqual(why, '')
        self.assertEqual([f['ref'] for f in parsed['findings']], ['f1', 'f2'])
        self.assertEqual(parsed['next_step'], {'action': 'none', 'target': '', 'reason_code': 'nothing_to_do', 'note': ''})

    def test_anything_outside_the_schema_is_rejected_with_a_reason(self):
        good = json.loads(self.ok())
        bad = []
        bad.append({**good, 'extra': 1})
        bad.append({**good, 'findings': [{**good['findings'][0], 'extra': 'x'}]})
        bad.append({**good, 'next_step': {**good['next_step'], 'extra': 'x'}})
        bad.append({**good, 'findings': [good['findings'][0], good['findings'][0]]})  # a ref twice
        bad.append({**good, 'findings': [{**good['findings'][0], 'ref': 'f3'}]})  # a ref the packet never had
        bad.append({**good, 'findings': [{**good['findings'][0], 'ref': 't17'}]})  # a raw triage id
        bad.append({**good, 'findings': [{**good['findings'][0], 'verdict': 'closed'}]})
        bad.append({**good, 'findings': [{**good['findings'][0], 'confidence': 'certain'}]})
        bad.append({**good, 'findings': [{**good['findings'][0], 'reason_code': 'because'}]})
        bad.append({**good, 'findings': [{**good['findings'][0], 'same_as': 'f9'}]})
        bad.append({**good, 'findings': [{**good['findings'][0], 'same_as': 'f1'}]})  # itself
        bad.append({**good, 'findings': [{**good['findings'][0], 'note': 'x' * 601}]})
        bad.append({**good, 'findings': [{**good['findings'][0], 'note': ['x']}]})
        bad.append({**good, 'next_step': {**good['next_step'], 'action': 'delete_host'}})
        bad.append({**good, 'next_step': {**good['next_step'], 'action': ['none']}})
        bad.append({**good, 'next_step': {**good['next_step'], 'target': 'f9'}})
        bad.append({**good, 'next_step': {**good['next_step'], 'reason_code': 'because'}})
        bad.append({**good, 'host_note': 'x' * 1201})
        bad.append({'findings': [], 'next_step': 'none'})
        bad.append({'findings': 'f1', 'next_step': good['next_step']})
        for body in bad:
            parsed, why = host_review.validate(json.dumps(body), self.refs, self.offered)
            self.assertIsNone(parsed, body)
            self.assertTrue(why)
        for text in ('', 'I think f1 is a false positive.', '[]', '{"findings": []}'):
            self.assertIsNone(host_review.validate(text, self.refs, self.offered)[0], text)

    def test_an_action_that_exists_but_was_not_offered_is_a_step_question_not_a_schema_one(self):
        parsed, why = host_review.validate(self.ok(next_step={'action': 'rescan_host', 'target': '', 'reason_code': 'needs_fresh_data', 'note': ''}), self.refs, self.offered)
        self.assertEqual((why, parsed['next_step']['action']), ('', 'rescan_host'))  # stored refused by store_step


class ApplyTests(Fixture):
    def test_a_clean_false_positive_is_closed_through_the_gate_and_linked_to_the_review(self):
        m1, m2 = self.match(), self.match()
        review = self.queue()
        review = self.deliver(review, self.body({'f1': ('false_positive', 'high'), 'f2': ('true_open', 'high')}))
        self.assertEqual((review.status, self.outcome), ('applied', 'applied'))
        self.assertEqual((self.status_of(m1), self.status_of(m2)), ('false_positive', 'open'))
        rows = self.verdicts(review)
        self.assertEqual(len(rows), 2)
        closed = rows[self.row_of(m1).pk]
        self.assertEqual((closed.verdict, closed.outcome, closed.host_review_id), ('false_positive', 'closed', review.pk))
        event = FindingAuditEvent.objects.get(finding_kind='match', finding_id=m1.pk)
        self.assertEqual((event.after['by'], event.after['host_review_id']), ('ai_reviewer', review.pk))
        self.assertEqual((review.model, review.input_tokens, review.output_tokens), ('vllm:m', 100, 50))
        self.assertEqual(review.host_note, 'The findings of this host were read together.')
        self.assertEqual(reviewer.due(25), [(t.pk, reviewer.review_key(t, 'f' * 40)) for t in []] or reviewer.due(25))
        self.assertEqual([pk for pk, _ in reviewer.due(25)], [])  # the finding review skips what the host review covered

    def test_low_or_medium_confidence_closes_nothing(self):
        m1 = self.match()
        review = self.deliver(self.queue(), self.body({'f1': ('false_positive', 'medium')}))
        self.assertEqual(self.status_of(m1), 'open')
        self.assertEqual(list(self.verdicts(review).values())[0].outcome, 'held')

    def test_a_persons_work_wins_a_comment_is_enough(self):
        m1 = self.match()
        FindingComment.objects.create(project=self.proj, finding_kind='match', finding_id=m1.pk, author=self.user, text='looking at it')
        review = self.deliver(self.queue(), self.body({'f1': ('false_positive', 'high')}))
        row = list(self.verdicts(review).values())[0]
        self.assertEqual((row.outcome, row.held_reason), ('held', 'a person has worked this finding'))
        self.assertEqual(self.status_of(m1), 'open')

    def test_hard_evidence_wins_the_finding_is_disputed_and_kept_open(self):
        m1 = self.match()
        Triage.objects.filter(match=m1).update(validation_status='hit')
        review = self.deliver(self.queue(), self.body({'f1': ('false_positive', 'high')}))
        row = list(self.verdicts(review).values())[0]
        self.assertEqual(row.outcome, 'disputed')
        self.assertEqual(self.status_of(m1), 'open')

    def test_a_state_that_changed_while_the_ai_read_it_makes_the_answer_stale_and_applies_nothing(self):
        m1 = self.match()
        review = self.queue()
        Port.objects.filter(pk=self.port.pk).update(version='9.9')  # a changed service version is a new state of the host
        review = self.deliver(review, self.body({'f1': ('false_positive', 'high')}, action='validate_match', target='f1'))
        self.assertEqual(review.status, 'stale')
        self.assertFalse(FindingReview.objects.exists())
        self.assertEqual((self.status_of(m1), review.step_state), ('open', ''))

    def test_a_finding_that_closed_meanwhile_is_skipped_and_the_rest_applied(self):
        m1, m2 = self.match(), self.match()
        review = self.queue()
        CVEMatch.objects.filter(pk=m1.pk).update(remediation_status='fixed')
        HostState.objects.filter(project=self.proj, host=HOST).update(fingerprint='f' * 40)
        review = self.deliver(review, self.body({'f1': ('false_positive', 'high'), 'f2': ('false_positive', 'high')}))
        self.assertEqual(review.status, 'stale')  # the open findings are part of the state key: it moved

    def test_a_reply_naming_a_finding_of_another_host_or_project_changes_nothing(self):
        m1 = self.match()
        other_sub = self.host_of(self.other_domain, self.other_scan, 'www.example.org', self.other, '192.0.2.77')
        foreign = self.match(sub=other_sub, scan=self.other_scan)
        sibling_sub = self.host_of(self.domain, self.scan, 'api.example.com', self.proj, '192.0.2.78')
        sibling = self.match(sub=sibling_sub)
        review = self.queue()
        for name in (f't{self.row_of(foreign).pk}', f'f{self.row_of(foreign).pk}', 'f2', 'f99', f't{self.row_of(sibling).pk}'):
            review_now = HostReview.objects.get(pk=review.pk)
            self.assertEqual(review_now.status, 'queued', name)
            self.deliver(review, self.body({name: ('false_positive', 'high'), 'f1': ('false_positive', 'high')}))
            review.refresh_from_db()
            job = AIJob.objects.get(pk=review.ai_job_id)
            self.assertEqual((job.status, job.attempt, job.stage), ('queued', 2, 'host_review_repair'), name)  # sent back once
            self.deliver(review, self.body({name: ('false_positive', 'high'), 'f1': ('false_positive', 'high')}))
            self.assertEqual(review.status, 'failed', name)
            self.assertIn('did not match the schema', review.step_detail)
            self.assertFalse(FindingReview.objects.exists(), name)  # not even the valid entry of the same reply
            for m in (m1, foreign, sibling):
                self.assertEqual(self.status_of(m), 'open')
            HostReview.objects.filter(pk=review.pk).delete()
            review = self.queue()

    def test_the_findings_of_the_hosts_review_are_resolved_from_its_stored_refs_so_a_swapped_ref_cannot_reach_another_project(self):
        m1 = self.match()
        other_sub = self.host_of(self.other_domain, self.other_scan, 'www.example.org', self.other, '192.0.2.77')
        foreign = self.row_of(self.match(sub=other_sub, scan=self.other_scan))
        review = self.queue()
        HostReview.objects.filter(pk=review.pk).update(refs={'f1': foreign.pk})  # tampered storage: still the project's and host's own only
        review.refresh_from_db()
        self.deliver(review, self.body({'f1': ('false_positive', 'high')}))
        self.assertFalse(FindingReview.objects.filter(triage=foreign).exists())
        self.assertEqual(self.status_of(foreign.match), 'open')

    def test_an_action_that_was_not_offered_is_refused_and_starts_nothing_while_the_verdicts_stand(self):
        m1 = self.match()
        with mock.patch.object(host_actions, 'offered', return_value={'none': {'class': 'auto', 'targets': []}}):
            review = self.queue()
        with mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, self.body({'f1': ('true_open', 'high')}, action='rescan_host', reason='needs_fresh_data'))
            run.assert_not_called()
        self.assertEqual((review.step_action, review.step_state, review.step_mode), ('rescan_host', 'refused', ''))
        self.assertIn('not offered', review.step_detail)
        self.assertEqual(review.status, 'applied')
        self.assertEqual(len(self.verdicts(review)), 1)

    def test_a_target_the_action_did_not_offer_is_refused(self):
        self.match(), self.match()
        review = self.queue()
        job = review.ai_job
        job.context['offered']['validate_match']['targets'] = ['f1']
        job.save()
        with mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, self.body({}, action='validate_match', target='f2', reason='needs_check'))
            run.assert_not_called()
        self.assertEqual(review.step_state, 'refused')
        review.delete()
        review = self.queue()
        with mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, self.body({}, action='rescan_host', target='f1', reason='needs_check'))  # a target for an action that takes none
            run.assert_not_called()
        self.assertEqual(review.step_state, 'refused')

    def test_a_failed_or_rate_limited_job_changes_nothing_and_starts_nothing(self):
        m1 = self.match()
        for category in ('provider_rate_limit', 'output_truncated', 'refused', 'lease_expired'):
            review = self.queue()
            with mock.patch.object(host_actions, 'run') as run:
                review = self.deliver(review, error=category)
                run.assert_not_called()
            self.assertEqual((review.status, review.step_state, review.step_action), ('failed', '', ''), category)
            self.assertEqual(review.step_detail, f'failed: {category}')
            self.assertFalse(FindingReview.objects.exists())
            self.assertEqual(self.status_of(m1), 'open')
            self.notified.assert_not_called()
            review.delete()

    def test_a_job_that_expired_marks_the_review_stale(self):
        self.match()
        review = self.queue()
        ai_jobs._expire(review.ai_job, timezone.now())
        review.refresh_from_db()
        self.assertEqual((review.status, review.step_detail), ('stale', 'stale: the AI did not answer in time'))
        self.queue()  # the host is free to be reviewed again

    def test_an_invalid_first_reply_is_sent_back_once_and_the_valid_second_one_is_applied(self):
        m1 = self.match()
        review = self.queue()
        self.deliver(review, text='I cannot decide.')
        self.assertEqual(self.outcome, 'retry')
        self.assertEqual(AIJob.objects.get(pk=review.ai_job_id).stage, 'host_review_repair')
        review = self.deliver(review, self.body({'f1': ('false_positive', 'high')}))
        self.assertEqual((review.status, self.status_of(m1)), ('applied', 'false_positive'))


class ConsistencyTests(Fixture):
    def tie(self, a, b):
        key = 'e' * 40
        Triage.objects.filter(pk__in=[self.row_of(a).pk, self.row_of(b).pk]).update(evidence_key=key)
        self.assertEqual(HostState.objects.filter(host=HOST).count(), 1)

    def test_findings_with_the_same_evidence_get_the_same_verdict_or_all_become_uncertain(self):
        m1, m2 = self.match(), self.match()
        self.tie(m1, m2)
        review = self.queue()
        review = self.deliver(review, self.body({'f1': ('false_positive', 'high'), 'f2': ('true_open', 'high')}))
        self.assertEqual((self.status_of(m1), self.status_of(m2)), ('open', 'open'))  # without the rule the first one would have been closed
        for row in self.verdicts(review).values():
            self.assertEqual((row.verdict, row.confidence, row.outcome), ('uncertain', 'low', 'recorded'))

    def test_findings_the_model_ties_with_same_as_are_judged_alike(self):
        m1, m2 = self.match(), self.match()
        review = self.queue()
        body = self.body({'f1': ('false_positive', 'high'), 'f2': {'verdict': 'true_open', 'confidence': 'high', 'reason_code': 'same_as_ref', 'same_as': 'f1', 'note': ''}})
        review = self.deliver(review, body)
        self.assertEqual((self.status_of(m1), self.status_of(m2)), ('open', 'open'))
        self.assertEqual({r.verdict for r in self.verdicts(review).values()}, {'uncertain'})

    def test_the_same_verdict_with_different_confidence_takes_the_lowest_so_the_closure_is_held(self):
        m1, m2 = self.match(), self.match()
        self.tie(m1, m2)
        review = self.deliver(self.queue(), self.body({'f1': ('false_positive', 'high'), 'f2': ('false_positive', 'medium')}))
        self.assertEqual((self.status_of(m1), self.status_of(m2)), ('open', 'open'))
        self.assertEqual({r.confidence for r in self.verdicts(review).values()}, {'medium'})

    def test_agreeing_findings_with_the_same_evidence_are_both_closed(self):
        m1, m2 = self.match(), self.match()
        self.tie(m1, m2)
        self.deliver(self.queue(), self.body({'f1': ('false_positive', 'high'), 'f2': ('false_positive', 'high')}))
        self.assertEqual((self.status_of(m1), self.status_of(m2)), ('false_positive', 'false_positive'))

    def test_same_as_ref_is_stored_as_a_duplicate_reason(self):
        m1, m2 = self.match(), self.match()
        body = self.body({'f1': ('true_open', 'high'), 'f2': {'verdict': 'true_open', 'confidence': 'high', 'reason_code': 'same_as_ref', 'same_as': 'f1', 'note': ''}})
        review = self.deliver(self.queue(), body)
        self.assertEqual({r.reason_code for r in self.verdicts(review).values()}, {'version_not_affected', 'duplicate'})


class AdmitTests(Fixture):
    def test_a_job_queued_on_an_earlier_day_waits_while_todays_cap_is_spent_and_a_switched_off_one_is_dropped(self):
        self.match()
        review = self.queue()
        job = review.ai_job
        self.assertTrue(host_review.job_admit(job))  # queued today: already counted
        HostReview.objects.filter(pk=review.pk).update(created_at=timezone.now() - timedelta(days=1))
        ReviewerSettings.current()
        ReviewerSettings.objects.update(host_review_daily_max=1)
        HostReview.objects.create(project=self.other, domain=self.other_domain, host='x.example.org', state_key='a' * 40, status='failed', ai_job=job)  # a failed review that made its AI call counts
        self.assertFalse(host_review.job_admit(job))
        ReviewerSettings.objects.update(host_review_daily_max=5)
        self.assertTrue(host_review.job_admit(job))
        review.refresh_from_db()
        self.assertGreaterEqual(review.created_at, timezone.now() - timedelta(minutes=1))  # it counts against today now
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'off'})
        self.assertEqual(host_review.job_admit(job), 'drop')
        HostReview.objects.filter(pk=review.pk).update(status='failed')
        ProjectSettings.objects.update(host_review_mode='auto')
        self.assertEqual(host_review.job_admit(job), 'drop')


class HostileClosureTests(Fixture):
    """A banner that tells the model to close everything: an obedient model closes nothing, whatever the host said."""

    def setUp(self):
        super().setUp()
        self.m1, self.m2 = self.match(), self.match()
        Port.objects.filter(pk=self.port.pk).update(banner='SSH-2.0-OpenSSH_8.9 ' + HOSTILE, service_extra=HOSTILE[:250])
        Subdomain.objects.filter(pk=self.sub.pk).update(page_title=HOSTILE)
        HostScreenshot.objects.create(project=self.proj, domain=self.domain, host=HOST, scheme='https', port=443, outcome='ok', title=HOSTILE[:290])

    def test_nothing_is_closed_whatever_the_obedient_reply_says(self):
        review = self.queue()
        self.assertTrue(review.injection)  # the flag is stored on the review
        review = self.deliver(review, self.body({'f1': ('false_positive', 'high'), 'f2': ('false_positive', 'high')}, action='assess_host', reason='needs_proof'))
        self.assertEqual((self.status_of(self.m1), self.status_of(self.m2)), ('open', 'open'))  # the host's planted text holds every closure of the host
        for row in self.verdicts(review).values():
            self.assertEqual((row.verdict, row.outcome), ('false_positive', 'held'))
            self.assertIn('text aimed at AI agents', row.held_reason)
        self.assertFalse(FindingAuditEvent.objects.filter(finding_kind='match', event='status').exists())

    def test_a_note_that_repeats_an_identifier_planted_in_the_host_is_discarded(self):
        review = self.queue()
        body = self.body({'f1': {'verdict': 'false_positive', 'confidence': 'high', 'reason_code': 'other', 'same_as': '', 'note': 'confirmed, reference a7c94e2b610f'}},
                         host_note='Please include reference a7c94e2b610f', step_note='reference a7c94e2b610f')
        review = self.deliver(review, body)
        self.assertEqual((review.host_note, review.step_note), ('', ''))
        self.assertIn('echo_marker', review.injection)
        row = list(self.verdicts(review).values())[0]
        self.assertEqual((row.verdict, row.confidence), ('uncertain', 'low'))
        self.assertNotIn('a7c94e2b610f', row.note)
