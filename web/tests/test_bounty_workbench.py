from datetime import timedelta

from django.utils import timezone

from cveFeed.models import (BountyEngagement, BountyEngagementTarget, BountyReport, CVEEntry, CVEMatch, Triage)
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_bounty_api import B, BountyBase, call


class WorkbenchBase(BountyBase):
    """One engagement on the Acme program (scope: *.acme.test and www.acme.test in, status.acme.test out) whose imported target has
    hosts of every kind: in scope, out of scope, unclear (the apex of a wildcard), and one that never resolved."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        now = timezone.now()
        cls.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        cls.domain = Domain.objects.create(name='acme.test', project=cls.pa, insert_date=now)
        cls.other_domain = Domain.objects.create(name='unrelated.test', project=cls.pa, insert_date=now)  # not imported by any engagement
        scan = ScanHistory.objects.create(domain=cls.domain, scan_type=cls.engine, scan_status=2, start_scan_date=now - timedelta(hours=2), tasks=[])
        other_scan = ScanHistory.objects.create(domain=cls.other_domain, scan_type=cls.engine, scan_status=2, start_scan_date=now - timedelta(hours=2), tasks=[])
        n = [0]

        def host(domain, name, live=True, sc=scan):
            sub = Subdomain.objects.create(target_domain=domain, name=name, scan_history=sc)
            if live:
                n[0] += 1
                sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{n[0]}'))
            return sub
        cls.www, cls.api_host = host(cls.domain, 'www.acme.test'), host(cls.domain, 'api.acme.test')
        cls.status_host, cls.apex, cls.dead = host(cls.domain, 'status.acme.test'), host(cls.domain, 'acme.test'), host(cls.domain, 'dead.acme.test', live=False)
        cls.unrelated = host(cls.other_domain, 'x.unrelated.test', sc=other_scan)

        cls.eng = BountyEngagement.objects.create(project=cls.pa, program=cls.acme, status='active', policy_ack_at=now, ack_content_hash=cls.acme.content_hash)
        BountyEngagementTarget.objects.create(engagement=cls.eng, domain=cls.domain, value='acme.test')
        BountyEngagementTarget.objects.create(engagement=cls.eng, domain=None, value='203.0.113.0/30')  # a target that could not be imported as a domain

        def finding(sub, severity, name, **kw):
            return Vulnerability.objects.create(subdomain=sub, target_domain=sub.target_domain, scan_history=sub.scan_history, name=name, severity=severity, **kw)
        cls.medium = finding(cls.api_host, 2, 'Medium on api')
        cls.high = finding(cls.www, 3, 'High on www')
        cls.info = finding(cls.www, 0, 'tech detect')
        cls.closed = finding(cls.api_host, 3, 'closed high', open_status=False)
        cls.elsewhere = finding(cls.unrelated, 4, 'critical on an unrelated target')
        BountyReport.objects.create(project=cls.pa, engagement=cls.eng, program=cls.acme, status='draft', title='t', finding_kind='vuln', finding_id=cls.high.pk)

        cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=8.0, affected=[])
        cls.match = CVEMatch.objects.create(cve_entry=cve, subdomain=cls.www, matched_product='nginx', confidence=.9)
        Triage.objects.create(project=cls.pa, domain=cls.domain, host=cls.www.name, kind='match', match=cls.match, status='triaged', classification='needs_validation')
        ruled = CVEMatch.objects.create(cve_entry=cve, subdomain=cls.api_host, matched_product='nginx', confidence=.9, ai_verdict='not_affected')
        Triage.objects.create(project=cls.pa, domain=cls.domain, host=cls.api_host.name, kind='match', match=ruled, status='triaged', classification='needs_validation')

        cls.s_running = ScanHistory.objects.create(domain=cls.domain, scan_type=cls.engine, scan_status=1, start_scan_date=now - timedelta(minutes=3), tasks=[])
        cls.s_stalled = ScanHistory.objects.create(domain=cls.domain, scan_type=cls.engine, scan_status=1, start_scan_date=now - timedelta(hours=14), tasks=[])
        cls.s_queued = ScanHistory.objects.create(domain=cls.domain, scan_type=cls.engine, scan_status=-1, start_scan_date=now, tasks=[])
        ScanHistory.objects.create(domain=cls.other_domain, scan_type=cls.engine, scan_status=1, start_scan_date=now, tasks=[])  # another target's scan

    def bench(self, client=None, project='a1'):
        return call(client or self.c, 'GET', f'{B}workbench?project={project}')


class WorkbenchContentTests(WorkbenchBase):
    def test_identified_hosts_and_their_scope(self):
        status, d = self.bench()
        self.assertEqual(status, 200)
        t = d['totals']
        self.assertEqual((t['hosts'], t['live']), (5, 4))  # the unrelated target's host is not counted; the dead host is
        self.assertEqual(t['scope'], {'in_scope': 3, 'out_of_scope': 1, 'ambiguous': 1, 'not_listed': 0})
        self.assertEqual([h['host'] for h in d['out_of_scope_hosts']], ['status.acme.test'])
        row = d['engagements'][0]
        self.assertEqual((row['hosts'], row['live'], row['imported'], row['targets']), (5, 4, 1, 2))

    def test_scans_are_this_engagements_and_stalled_is_not_running(self):
        t = self.bench()[1]['totals']
        self.assertEqual(t['scans'], {'running': 1, 'queued': 1, 'stalled': 1})
        listed = {s['id']: s for s in self.bench()[1]['scans']}
        self.assertTrue(listed[self.s_stalled.pk]['stalled'])
        self.assertNotIn('unrelated.test', {s['target'] for s in listed.values()})

    def test_potential_findings_are_open_low_or_worse_and_not_yet_reported(self):
        d = self.bench()[1]
        self.assertEqual([p['name'] for p in d['potential']], ['Medium on api'])  # not: the reported one, info, closed, or another target's
        self.assertEqual(d['totals']['findings'], 2)    # medium and high are open and actionable on these targets
        self.assertEqual(d['totals']['potential'], 1)

    def test_matches_to_check_leave_out_what_the_ai_ruled_out(self):
        d = self.bench()[1]
        self.assertEqual([m['cve'] for m in d['matches']], ['CVE-2099-7'])
        self.assertEqual((d['totals']['matches'], d['totals']['needs_validation']), (1, 1))

    def test_reports_and_policy_state(self):
        d = self.bench()[1]
        self.assertEqual(d['engagements'][0]['reports'], {'draft': 1})
        self.assertTrue(d['engagements'][0]['policy_read'])
        self.assertFalse(d['engagements'][0]['scope_changed'])
        BountyEngagement.objects.filter(pk=self.eng.pk).update(ack_content_hash='old')
        self.assertTrue(self.bench()[1]['engagements'][0]['scope_changed'])

    def test_an_engagement_without_targets_is_listed_with_zeros(self):
        free = BountyEngagement.objects.create(project=self.pa2, program=self.acme, status='watching')
        d = self.bench(project='a2')[1]
        self.assertEqual(d['engagements'][0]['id'], free.pk)
        self.assertEqual((d['totals']['hosts'], d['totals']['scans']['running'], d['totals']['potential']), (0, 0, 0))

    def test_a_finished_engagement_is_not_shown(self):
        BountyEngagement.objects.filter(pk=self.eng.pk).update(status='done')
        self.assertEqual(self.bench()[1]['engagements'], [])


class WorkbenchAgreementTests(WorkbenchBase):
    """The numbers here are the numbers on the other pages, because both read cveFeed.counts."""

    def api(self, path, **params):
        r = self.c.get(f'/api/v1/{path}', params)
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_hosts_agree_with_the_hosts_page_for_the_imported_target(self):
        listed = [h for h in self.api('projects/a1/hosts', page_size=50)['results'] if h['target'] == 'acme.test']
        self.assertEqual(len(listed), self.bench()[1]['totals']['hosts'])

    def test_potential_plus_reported_equals_the_findings_page_for_the_target(self):
        total = self.bench()[1]['totals']['findings']
        scanner = [f for f in self.api('projects/a1/findings', type='scanner', page_size=50)['results'] if f['host'] and f['host'].endswith('.acme.test')]
        self.assertEqual(len(scanner), total)

    def test_matches_agree_with_the_findings_page(self):
        cve = [f for f in self.api('projects/a1/findings', type='cve', page_size=50)['results'] if f['host'].endswith('.acme.test')]
        self.assertEqual(len(cve), self.bench()[1]['totals']['matches'])


class WorkbenchAccessTests(WorkbenchBase):
    def test_a_user_without_bug_bounty_access_is_refused(self):
        from tests.test_tenancy import client_for
        self.assertEqual(self.bench(client_for(self.member))[0], 403)

    def test_a_project_of_another_organization_is_not_readable(self):
        status, _ = self.bench(project='b1')
        self.assertIn(status, (400, 403, 404))
        from tests.test_tenancy import client_for
        status, _ = self.bench(client_for(self.granted_b), project='a1')
        self.assertIn(status, (400, 403, 404))

    def test_a_project_is_required(self):
        self.assertEqual(call(self.c, 'GET', f'{B}workbench')[0], 400)

    def test_the_query_count_does_not_grow_with_the_hosts(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as small:
            self.bench()
        for i in range(30):
            Subdomain.objects.create(target_domain=self.domain, name=f'h{i}.acme.test', scan_history=self.dead.scan_history)
            Vulnerability.objects.create(subdomain=self.www, target_domain=self.domain, scan_history=self.dead.scan_history, name=f'v{i}', severity=2)
        with CaptureQueriesContext(connection) as big:
            self.bench()
        self.assertLessEqual(len(big), len(small))  # the first call also pays the one-time lookups; 30 more hosts and findings add none
