"""The findings' lifecycles (docs/STATE-MACHINES.md): a person's decision is never undone by a job that was already running.

Each test here plays the race the way it happens: an automatic actor (a retest, an agent's report, an AI answer that waited in the queue, the
supplier sweep, a scanner engine, an evaluation) reads a finding, a person changes it, and the actor then writes. The person's change stands.
"""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import ai_jobs, closure, fix_retest
from cveFeed.models import CVEEntry, CVEMatch, FindingAuditEvent, FindingComment, FixRetest, SavedSearch, Triage
from dashboard.models import Org, Project, ProjectMembership
from reNgine.lifecycle import REGISTRY
from reNgine.state_machines import REMEDIATION
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests import test_agent_broker as ab
from tests import test_ai_jobs as aj
from tests import test_fix_retest as fr
from tests import test_ssh_scan as ssh
from tests import test_suppliers as sup
from tests.test_agentapi import call
from tests.test_triage import reply


class TableTests(TestCase):
    def test_the_remediation_table_uses_the_closure_words_and_lets_a_person_move_anywhere(self):
        self.assertIs(REGISTRY['remediation'], REMEDIATION)
        legend = {s['key']: s for s in REMEDIATION.legend()['states']}
        self.assertEqual(list(legend), list(closure.STATUSES))
        self.assertEqual({k: s['label'] for k, s in legend.items()}, closure.LABELS)
        for a in closure.STATUSES:
            for b in closure.STATUSES:
                if a != b:
                    REMEDIATION.check(a, b)  # never raises: a person may move between any statuses

    def test_an_automatic_move_happens_only_from_the_status_it_read(self):
        now = timezone.now()
        org = Org.objects.create(name='Sm', slug='sm-org')
        project = Project.objects.create(name='Sm', slug='sm-proj', insert_date=now, org=org)
        domain = Domain.objects.create(name='sm.example', project=project, insert_date=now)
        sub = Subdomain.objects.create(name='www.sm.example', target_domain=domain)
        vuln = Vulnerability.objects.create(name='x', severity=2, subdomain=sub, target_domain=domain, open_status=True, remediation_status='false_positive')
        rows = Vulnerability.objects.filter(pk=vuln.pk)
        self.assertEqual(REMEDIATION.move(rows, 'open', only_from=('fixed',)), 0)
        self.assertEqual(rows.get().remediation_status, 'false_positive')
        self.assertEqual(REMEDIATION.move(rows, 'open', only_from=('false_positive',)), 1)


class RetestTests(fr.Base):
    """a) a retest that read the finding fixed minutes ago does not reopen it over a person's newer decision."""

    def test_a_retest_does_not_reopen_a_finding_a_person_closed_while_it_ran(self):
        self.mark()
        job = FixRetest.objects.get()
        test = self

        class PersonClosesItMeanwhile(fr.RunsAs):
            def run(self, check):
                out = super().run(check)
                test.mark('false_positive', note='only reachable from the lab')  # while the Sentinel check runs
                return out

        with fr.planned(), PersonClosesItMeanwhile(self, fr.hit_result(), self.agent), \
                mock.patch('agentapi.probe_dispatch.try_alive', return_value={'x': True}), mock.patch('cveFeed.notify._send') as send:
            out = fix_retest.run(job.pk)
        self.refresh()
        job.refresh_from_db()
        self.assertEqual((self.match.remediation_status, self.match.remediation_note, self.match.remediation_by),
                         ('false_positive', 'only reachable from the lab', self.alice))
        self.assertNotEqual(self.triage.retest_state, 'still_reproduces')
        self.assertEqual((out['outcome'], out['applied']), ('still_reproduces', False))
        self.assertEqual(job.evidence['exchange']['response'], fr.NEW_EXCHANGE['response'])  # the result is kept on the retest itself
        note = FindingAuditEvent.objects.get(event='retest', finding_id=self.match.pk, after__applied=False)
        self.assertIn('a person changed the status', note.after['note'])
        self.assertFalse(FindingAuditEvent.objects.filter(event='status', finding_id=self.match.pk, actor__isnull=True).exists())
        send.assert_not_called()


class AgentReportTests(TestCase):
    """b) an agent's "fixed" report does not overwrite a closure a person made while the remediate task ran."""

    @classmethod
    def setUpTestData(cls):
        ab.build_world(cls)

    def setUp(self):
        ab.reset_rates(self.tokens)
        ab.register(self.tokens['alice'], name='one')

    def run_task_and(self, meanwhile):
        ab.queue(self.tokens['alice'], 'remediate', [self.m_linux.pk])
        task_id = ab.next_task(self.tokens['alice'])[1]['task']['task']['id']
        call(self.tokens['alice'], 'POST', f'/api/v1/agent/tasks/{task_id}/accept')
        meanwhile()
        status, done = call(self.tokens['alice'], 'POST', f'/api/v1/agent/tasks/{task_id}/result', {'outcome': 'fixed', 'summary': 'upgraded to 1.24.0'})
        self.assertEqual((status, done['task']['status']), (200, 'completed'))
        return CVEMatch.objects.get(pk=self.m_linux.pk)

    def test_a_false_positive_set_while_the_task_ran_stands_and_the_comment_is_still_posted(self):
        match = self.run_task_and(lambda: CVEMatch.objects.filter(pk=self.m_linux.pk).update(
            remediation_status='false_positive', remediation_by=self.alice, remediation_note='not our nginx'))
        self.assertEqual((match.remediation_status, match.remediation_note, match.remediation_by), ('false_positive', 'not our nginx', self.alice))
        self.assertIn('upgraded to 1.24.0', FindingComment.objects.get(finding_id=match.pk).text)
        self.assertFalse(FindingAuditEvent.objects.filter(event='status', finding_id=match.pk).exists())

    def test_a_finding_someone_is_working_on_is_still_fixed_by_the_report(self):
        match = self.run_task_and(lambda: CVEMatch.objects.filter(pk=self.m_linux.pk).update(remediation_status='in_progress'))
        self.assertEqual(match.remediation_status, 'fixed')
        self.assertTrue(FindingAuditEvent.objects.filter(event='status', finding_id=match.pk, after__status='fixed').exists())


class TriageTests(aj.Base):
    """c) an AI answer that waited in the queue does not reopen or replace a deterministic rule's close made after the question was asked."""

    def answer(self, job, text):
        status, data = self.post(job, text=text, calls=[{'status': 'succeeded', 'input_tokens': 1, 'output_tokens': 1}])
        self.assertEqual((status, data), (200, {'accepted': True}))
        return ai_jobs.apply(job['id'])

    def test_a_match_closed_as_stale_while_the_question_waited_stays_closed(self):
        m = self.match()
        self.ask()
        job = self.take()[0]
        reason = 'Closed automatically: the host no longer matches this CVE (the version moved out of the affected range or the product is gone).'
        CVEMatch.objects.filter(pk=m.pk).update(ai_verdict='not_affected', confidence=0.0, ai_reason=reason)  # what correlation.close_stale writes
        self.answer(job, reply('likely'))
        m.refresh_from_db()
        self.assertEqual((m.ai_verdict, m.ai_reason), ('not_affected', reason))

    def test_a_match_closed_as_an_invalid_correlation_while_the_question_waited_keeps_the_rule_classification(self):
        from cveFeed import correlation
        m = self.match()
        self.ask()
        job = self.take()[0]
        reason = 'Closed automatically: invalid product correlation (the port runs another product).'
        self.assertTrue(correlation.close_invalid_correlation(CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=m.pk), reason=reason))
        self.answer(job, reply('likely'))
        m.refresh_from_db()
        row = Triage.objects.get(match=m)
        self.assertEqual((m.ai_verdict, m.ai_model), ('not_affected', 'deterministic-correlation'))
        self.assertEqual((row.classification, row.reason), ('not_applicable', reason))

    def test_an_answer_for_a_match_nobody_closed_is_still_applied(self):
        m = self.match()
        self.ask()
        self.assertEqual(self.answer(self.take()[0], reply('likely')), 'applied')
        m.refresh_from_db()
        self.assertEqual(m.ai_verdict, 'uncertain')


class SupplierTests(sup.Fixture, TestCase):
    """d) a supplier finding a person accepted keeps the decision when the issue goes away and comes back."""

    D = 'portal.vendor.test'

    def setUp(self):
        super().setUp()
        self.s = self.supplier(domains=[self.D])
        self.rows[self.D] = sup.row(self.D, postures=[sup.posture('hsts_missing')])

    def again(self, *postures):
        self.rows[self.D] = sup.row(self.D, postures=list(postures))
        self.expire()
        return self.sweep()

    def test_an_accepted_finding_keeps_the_person_decision_through_resolve_and_reappear(self):
        self.sweep()
        found = self.finding(self.s, self.D, 'hsts_missing')
        status, _ = call(self.t_admin, 'PATCH', f'/api/v1/projects/sup-a/suppliers/findings/{found.id}', {'status': 'accepted', 'note': 'vendor knows'})
        self.assertEqual(status, 200)
        self.again()  # the supplier fixed it
        found.refresh_from_db()
        self.assertEqual((found.status, found.status_by), ('accepted', self.admin))
        out = self.again(sup.posture('hsts_missing'))  # and it came back
        found.refresh_from_db()
        self.assertEqual((found.status, found.status_note, found.status_by, out['reopened']), ('accepted', 'vendor knows', self.admin, 0))


class SshTests(ssh.SshFixture, TestCase):
    """e) an SSH finding someone is working on is marked gone once a complete inspection reads a clean key, keeping its status."""

    def test_an_in_progress_finding_is_marked_gone_and_keeps_the_person_status(self):
        scan = self.ssh_scan_obj()
        self.go(scan, self.sentinel({(self.ADDRESS, 22): 'hit'}))
        Vulnerability.objects.filter(source='ssh-probe').update(remediation_status='in_progress')
        self.go(scan, self.sentinel({(self.ADDRESS, 22): 'clear'}), force=True)
        vuln = Vulnerability.objects.get(source='ssh-probe')
        self.assertEqual((vuln.open_status, vuln.remediation_status), (False, 'in_progress'))


class SavedSearchTests(TestCase):
    """f) editing a saved search does not write back the matches an evaluation stored while the edit was made."""

    def test_an_edit_keeps_the_matches_an_evaluation_wrote_meanwhile(self):
        from agentapi import saved_search
        now = timezone.now()
        project = Project.objects.create(name='Ss', slug='sm-ss', insert_date=now, org=Org.objects.create(name='Ss', slug='sm-ss-org'))
        owner = User.objects.create_user('sm-ss-owner', password='x')
        ProjectMembership.objects.create(user=owner, project=project, role='user')
        token = create_token(owner, 'ss')[1]
        s = SavedSearch.objects.create(project=project, owner=owner, name='db', query='port:5432', matched={'a': 'a.example'}, last_match_count=1,
                                       baseline_at=now, last_status='ok')
        real = saved_search._clean

        def evaluation_finishes_meanwhile(*args, **kwargs):
            SavedSearch.objects.filter(pk=s.pk).update(matched={'a': 'a.example', 'b': 'b.example'}, last_match_count=2)
            return real(*args, **kwargs)

        with mock.patch('agentapi.saved_search._clean', side_effect=evaluation_finishes_meanwhile):
            status, _ = call(token, 'PATCH', f'/api/v1/projects/sm-ss/saved-searches/{s.pk}', {'name': 'databases'})
        self.assertEqual(status, 200)
        s.refresh_from_db()
        self.assertEqual((s.name, s.matched, s.last_match_count), ('databases', {'a': 'a.example', 'b': 'b.example'}, 2))


class BulkStatusTests(TestCase):
    """g) the bulk status change does not overwrite a finding someone else changed after the bulk call read it."""

    def test_a_finding_changed_after_the_read_keeps_the_change_and_is_reported_failed(self):
        now = timezone.now()
        project = Project.objects.create(name='Bk', slug='sm-bk', insert_date=now, org=Org.objects.create(name='Bk', slug='sm-bk-org'))
        domain = Domain.objects.create(name='bk.example', project=project, insert_date=now)
        sub = Subdomain.objects.create(name='www.bk.example', target_domain=domain)
        alice, bob = User.objects.create_user('sm-bk-alice', password='x'), User.objects.create_user('sm-bk-bob', password='x')
        for user in (alice, bob):
            ProjectMembership.objects.create(user=user, project=project, role='user')
        token = create_token(alice, 'bk')[1]
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7301', cvss=9.8, published_at=now, affected=[])
        match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='panel', matched_version='1.2', confidence=0.8)
        vuln = Vulnerability.objects.create(name='Exposed panel', severity=3, subdomain=sub, target_domain=domain, open_status=True, source='nuclei')
        real = closure.clip_note

        def bob_closes_it_meanwhile(value, *args, **kwargs):
            Vulnerability.objects.filter(pk=vuln.pk).update(remediation_status='false_positive', remediation_by=bob, remediation_note='lab only',
                                                            remediation_updated_at=timezone.now())
            return real(value, *args, **kwargs)

        with mock.patch('cveFeed.tasks.retest_fixed_finding.apply_async'), mock.patch('cveFeed.closure.clip_note', side_effect=bob_closes_it_meanwhile):
            status, body = call(token, 'POST', '/api/v1/projects/sm-bk/findings/status',
                                {'items': [{'kind': 'match', 'id': match.pk}, {'kind': 'vulnerability', 'id': vuln.pk}], 'status': 'fixed', 'note': 'patched'})
        self.assertEqual((status, body['updated']), (200, 1), body)
        self.assertEqual([(f['kind'], f['id']) for f in body['failed']], [('vulnerability', vuln.pk)])
        vuln.refresh_from_db()
        match.refresh_from_db()
        self.assertEqual((vuln.remediation_status, vuln.remediation_by, vuln.remediation_note), ('false_positive', bob, 'lab only'))
        self.assertEqual((match.remediation_status, match.remediation_by), ('fixed', alice))
        self.assertFalse(FindingAuditEvent.objects.filter(finding_kind='vulnerability', finding_id=vuln.pk).exists())
