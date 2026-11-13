"""AR-5: the same evidence gets the same verdict across hosts. A closure that earlier reviews of the same evidence on other hosts of the project
contradict is held (reviewer.same_evidence_prior), the prior is told to the model as cvENGINE's own line, and nothing crosses a project."""
import json

from django.core.cache import cache
from django.db import connection
from django.utils import timezone

from cveFeed import reviewer, triage
from cveFeed.models import CVEMatch, FindingReview, HostState, Triage
from dashboard.models import Org, Project
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_reviewer import REVIEWER_DIR, Fixture


class Consistency(Fixture):
    def second_host(self, name='api.example.com', project=None, domain=None, scan=None, **over):
        """A match with the same CVE, product, version and evidence as ``self.match``, on another host."""
        domain, scan = domain or self.domain, scan or self.scan
        sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)
        fields = dict(cve_entry=self.cve, subdomain=sub, source='tech', matched_product='lib-a', matched_version='1.2', version_in_range=False,
                      confidence=0.8, ai_verdict='uncertain', scan_history=scan, evidence={'source': 'tech'})
        fields.update(over)
        match = CVEMatch.objects.create(**fields)
        triage.track([match])
        HostState.objects.create(project=project or self.proj, domain=domain, host=name, fingerprint='e' * 40)
        return match

    def packet_of(self, match):
        cache.clear()
        t = Triage.objects.get(match=match)
        return next(p for p in reviewer.next_packets(25) if p['ref'] == f't{t.pk}')

    def review(self, match, **over):
        return self.verdict(self.packet_of(match), **over)

    def test_the_two_hosts_have_one_evidence_key(self):
        other = self.second_host()
        self.assertEqual(Triage.objects.get(match=other).evidence_key, Triage.objects.get(match=self.match).evidence_key)
        self.assertNotEqual(Triage.objects.get(match=other).host, Triage.objects.get(match=self.match).host)

    def test_a_real_verdict_on_one_host_holds_the_false_positive_closure_on_the_other(self):
        other = self.second_host()
        self.assertEqual(self.review(self.match, verdict='true_open', confidence='high', reason_code='plausible_exposure')[1]['outcome'], 'recorded')
        status, data = self.review(other)
        self.assertEqual((status, data['outcome']), (200, 'held'), data)
        self.assertEqual(data['reason'], '1 earlier review of the same evidence on other hosts said it is real')
        other.refresh_from_db()
        self.assertEqual(other.remediation_status, 'open')
        self.assertEqual(FindingReview.objects.get(pk=data['review_id']).held_reason, data['reason'])
        self.assertIn('same evidence on other hosts said it is real', reviewer.review_summary(Triage.objects.get(match=other).pk)['outcome_text'])

    def test_the_count_is_in_the_reason_and_a_host_counts_once(self):
        a, b = self.second_host('a.example.com'), self.second_host('b.example.com')
        for m in (self.match, a):
            self.review(m, verdict='true_open', confidence='low', reason_code='plausible_exposure')
        self.assertEqual(self.review(b)[1]['reason'], '2 earlier reviews of the same evidence on other hosts said it is real')

    def test_the_held_verdict_does_not_demote_in_situations(self):
        from cveFeed import situations
        other = self.second_host()
        self.review(self.match, verdict='true_open', confidence='high', reason_code='plausible_exposure')
        self.review(other)
        row = Triage.objects.get(match=other)
        newest = FindingReview.objects.filter(triage=row).order_by('-id').first()
        self.assertEqual((newest.verdict, newest.outcome), ('false_positive', 'held'))
        qs = CVEMatch.objects.filter(pk=other.pk).annotate(**reviewer.newest_review_q('triage__')).annotate(disputed=situations._disputed())
        self.assertFalse(qs.get().disputed)

    def test_real_after_a_false_positive_stands(self):
        other = self.second_host()
        self.assertEqual(self.review(self.match)[1]['outcome'], 'closed')
        data = self.review(other, verdict='true_open', confidence='high', reason_code='confirmed_by_evidence')[1]
        self.assertEqual((data['outcome'], data['reason']), ('recorded', ''))
        other.refresh_from_db()
        self.assertEqual(other.remediation_status, 'open')

    def test_a_false_positive_on_another_host_does_not_hold_a_closure(self):
        other = self.second_host()
        self.assertEqual(self.review(self.match)[1]['outcome'], 'closed')
        self.assertEqual(self.review(other)[1]['outcome'], 'closed')

    def test_another_project_or_organization_has_no_effect(self):
        for n, org in enumerate((Org.objects.create(name='Other', slug='other-org'), self.org)):  # another organization, then a sibling project of this one
            proj = Project.objects.create(name=f'Other{n}', slug=f'other-proj{n}', insert_date=timezone.now(), org=org)
            domain = Domain.objects.create(name=f'other{n}.example', project=proj, insert_date=timezone.now())
            scan = ScanHistory.objects.create(domain=domain, scan_type=self.scan.scan_type, scan_status=2, start_scan_date=timezone.now())
            foreign = self.second_host(f'www.other{n}.example', project=proj, domain=domain, scan=scan)
            self.assertEqual(Triage.objects.get(match=foreign).evidence_key, Triage.objects.get(match=self.match).evidence_key)
            self.review(foreign, verdict='true_open', confidence='high', reason_code='plausible_exposure')
            self.assertEqual(reviewer.same_evidence_prior(Triage.objects.get(match=self.match)), (0, 0))
            self.assertNotIn('same_evidence_on_other_hosts', self.packet_of(self.match)['trusted'])
        self.assertEqual(self.review(self.match)[1]['outcome'], 'closed')

    def test_a_refused_or_planted_text_review_is_not_a_prior(self):
        other = self.second_host()
        t = Triage.objects.get(match=other)
        FindingReview.objects.create(triage=t, project=self.proj, review_key='k' * 40, verdict='', confidence='low', outcome='refused', held_reason='refused')
        FindingReview.objects.create(triage=t, project=self.proj, review_key='j' * 40, verdict='true_open', confidence='high', outcome='recorded',
                                     injection=['workflow_order'])
        FindingReview.objects.create(triage=t, project=self.proj, review_key='i' * 40, verdict='uncertain', confidence='low', outcome='recorded')
        mine = Triage.objects.get(match=self.match)
        self.assertEqual(reviewer.same_evidence_prior(mine), (0, 0))
        self.assertEqual(self.review(self.match)[1]['outcome'], 'closed')

    def test_the_packet_carries_the_prior_as_cvengines_own_line_with_no_host_names(self):
        a, b = self.second_host('a.example.com'), self.second_host('b.example.com')
        self.assertNotIn('same_evidence_on_other_hosts', self.packet_of(self.match)['trusted'])
        self.review(a, verdict='true_open', confidence='high', reason_code='plausible_exposure')
        self.review(b, verdict='true_open', confidence='high', reason_code='plausible_exposure')
        packet = self.packet_of(self.match)
        line = packet['trusted']['same_evidence_on_other_hosts']
        self.assertIn('the same evidence was judged real on 2 other hosts, false positive on 0', line)
        self.assertNotIn('example.com', json.dumps(packet))
        import os
        import sys
        sys.path.insert(0, os.path.abspath(REVIEWER_DIR))
        self.addCleanup(sys.path.remove, os.path.abspath(REVIEWER_DIR))
        from cvengine_reviewer import jobs
        message = jobs.review_message(packet)
        self.assertIn('judged real on 2 other hosts', message.split('<<<UNTRUSTED')[0])

    def test_a_false_positive_with_a_high_confidence_on_every_host_is_unchanged_without_a_real_prior(self):
        self.assertEqual(self.review(self.match)[1]['outcome'], 'closed')

    def test_the_prior_is_one_indexed_query_and_the_plan_uses_the_index(self):
        t = Triage.objects.get(match=self.match)
        with self.assertNumQueries(1):
            reviewer.same_evidence_prior(t)
        qs = FindingReview.objects.filter(project_id=t.project_id, triage__project_id=t.project_id, triage__kind=t.kind, triage__evidence_key=t.evidence_key, injection=[])
        sql, params = qs.exclude(triage__host=t.host).query.sql_with_params()
        with connection.cursor() as cursor:
            cursor.execute('SET enable_seqscan = off')
            cursor.execute('EXPLAIN ' + sql, params)
            plan = '\n'.join(r[0] for r in cursor.fetchall())
        self.assertIn('triage_proj_kind_evkey_idx', plan)
