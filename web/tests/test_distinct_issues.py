"""Distinct issues: the open findings counted as the Findings list shows them grouped by product and version (``cveFeed.counts.match_issues``),
printed beside the raw counts on the Overview's CVE matches tile, the Findings page's header, the weekly email, the PDF and the system status.

The raw counts stay exactly what they were; the new figure is the same set with the version-only CVE matches of one product and version on one
host (every name of it) counted once, every other finding (a confirmed match, a scanner or a hygiene finding) once each. Every surface reads it
from one function, so they agree, and the Findings header's number is the grouped list's own row count.
"""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import report_scope, system_status
from agentapi.auth import create_token
from agentapi.services import Ctx, list_findings, list_matches
from cveFeed import counts, report_data, report_digest, report_pdf, snapshot_cache, views
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call

NOW = timezone.now()
NGINX_RANGE = {'introduced': '1.31.0', 'fixed': '1.31.9'}


class World(TestCase):
    """economicprinciples.org and www. on one address are one host, each stored twice (a scanless copy beside the scan's). nginx 1.31.1 matches
    three CVEs on every copy (12 matches) and jQuery 1.12.1 one on each scanned copy (2): two issues. stage. runs nginx 1.18.0 (one issue). Two
    more nginx 1.31.1 matches have hard evidence (a template hit, a validation hit): each stays its own issue. A fixed and a ruled-out match are
    not open. One scanner and one hygiene finding are open. Open: 17 CVE matches in 5 issues, 19 findings in 7 issues."""

    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='Distinct', slug='di-org')
        cls.project = Project.objects.create(name='Distinct', slug='di-p', insert_date=NOW, org=org)
        cls.domain = domain = Domain.objects.create(name='economicprinciples.org', project=cls.project, insert_date=NOW)
        scan = ScanHistory.objects.create(start_scan_date=NOW, scan_status=2, domain=domain, tasks=[],
                                          scan_type=EngineType.objects.create(engine_name='di', yaml_configuration='x'))
        ip = IpAddress.objects.create(address='203.0.113.90')
        cls.copies = {}
        for name in ('economicprinciples.org', 'www.economicprinciples.org'):
            old = Subdomain.objects.create(name=name, target_domain=domain)
            new = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)
            old.ip_addresses.add(ip)
            new.ip_addresses.add(ip)
            cls.copies[name] = (old, new)
        cls.stage = Subdomain.objects.create(name='stage.economicprinciples.org', target_domain=domain, scan_history=scan)
        cls.stage.ip_addresses.add(IpAddress.objects.create(address='203.0.113.91'))
        nginx = [CVEEntry.objects.create(cve_id=f'CVE-2026-{950 + i}', cvss=7.5, title='nginx', published_at=NOW, affected=[]) for i in range(3)]
        jq = CVEEntry.objects.create(cve_id='CVE-2020-11022', cvss=6.9, title='jQuery', published_at=NOW, affected=[])
        cls.version_only = []
        for old, new in cls.copies.values():
            for sub in (old, new):
                cls.version_only += [cls.match(cve, sub, 'NGINX Open Source', '1.31.1') for cve in nginx]
            cls.version_only.append(cls.match(jq, new, 'jQuery', '1.12.1'))
        apex, www = cls.copies['economicprinciples.org'][1], cls.copies['www.economicprinciples.org'][1]
        cls.on_stage = cls.match(nginx[0], cls.stage, 'nginx', '1.18.0')
        cls.proven = cls.match(nginx[1], apex, 'nginx', '1.31.1', template_result='vulnerable')
        cls.hit = cls.match(nginx[2], www, 'nginx', '1.31.1', validation_status='hit')
        cls.fixed = cls.match(CVEEntry.objects.create(cve_id='CVE-2026-990', cvss=7.5, published_at=NOW, affected=[]), apex, 'nginx', '1.31.1',
                              remediation_status='fixed')
        cls.ruled_out = cls.match(CVEEntry.objects.create(cve_id='CVE-2026-991', cvss=7.5, published_at=NOW, affected=[]), apex, 'nginx', '1.31.1',
                                  ai_verdict='not_affected')
        Vulnerability.objects.create(name='Exposed admin', severity=3, subdomain=cls.stage, target_domain=domain, open_status=True,
                                     discovered_date=NOW, http_url='https://stage.economicprinciples.org/admin')
        HygieneFinding.objects.create(domain=domain, host='economicprinciples.org', check_name='spf_missing', severity=2, status='open', title='no spf')
        cls.user = User.objects.create_user('di-alice', password='x')
        ProjectMembership.objects.create(user=cls.user, project=cls.project, role='admin')
        cls.ctx = Ctx(user=cls.user)
        _, cls.token = create_token(cls.user, 'di')

    @classmethod
    def match(cls, cve, sub, product, version, validation_status='none', **extra):
        m = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product=product, matched_version=version, source='tech',
                                    evidence={'source': 'tech', 'range': NGINX_RANGE, 'affected_index': 0}, **extra)
        Triage.objects.create(project=cls.project, domain=cls.domain, host=sub.name, kind='cve_match', match=m, status='triaged',
                              classification='needs_validation', validation_status=validation_status)
        return m

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def open_matches(self):
        return counts.exposed_matches().filter(subdomain__target_domain__project=self.project)


class CountTests(World):
    def test_version_only_matches_of_one_product_version_on_one_host_are_one_issue(self):
        self.assertEqual(len(self.version_only), 14)
        self.assertEqual(counts.match_issues(self.open_matches()), (17, 5))
        self.assertEqual(counts.match_issues(self.open_matches(), by_project=True), {self.project.id: (17, 5)})

    def test_a_confirmed_match_counts_on_its_own_as_the_helper_shows_it(self):
        hard = self.open_matches().filter(pk__in=[self.proven.pk, self.hit.pk])
        self.assertEqual(counts.match_issues(hard), (2, 2))  # the same product and version on the same host, but each has evidence of its own
        soft = self.open_matches().filter(subdomain__name='economicprinciples.org', matched_product='NGINX Open Source')
        self.assertEqual(counts.match_issues(soft), (6, 1))

    def test_without_the_hosts_fold_the_two_names_would_be_two_issues(self):
        apart = counts.match_issues(self.open_matches(), site_of=lambda project_id, name: None)
        self.assertEqual(apart, (17, 7))  # nginx and jQuery once per name: the fold onto one host is what makes them one fix

    def test_scanner_and_hygiene_findings_count_once_each(self):
        self.assertEqual(counts.distinct_issues(19, self.open_matches()), 7)
        self.assertEqual(counts.distinct_issues(2, None), 2)
        self.assertEqual(counts.issues_text(2140, 310), '2,140 findings in 310 distinct issues')
        self.assertEqual(counts.issues_text(1, 1), '1 finding in 1 distinct issue')

    def test_the_findings_header_number_is_the_grouped_list_and_the_counts_agree(self):
        body = list_findings(self.ctx, 'di-p', {'group': 'product'})
        self.assertEqual((body['findings_total'], body['total'], body['distinct_issues']), (19, 7, 7))
        self.assertEqual(body['counts'], {'cve': 17, 'scanner': 1, 'hygiene': 1})  # the raw counts are what they were
        self.assertEqual(body['distinct_issues'], counts.distinct_issues(body['findings_total'], self.open_matches()))
        cve = list_findings(self.ctx, 'di-p', {'group': 'product', 'type': 'cve'})
        self.assertEqual((cve['findings_total'], cve['distinct_issues']), counts.match_issues(self.open_matches()))
        grouped = list_matches(self.ctx, 'di-p', {'group_by': 'product', 'verdict': 'active', 'status': 'open'})
        self.assertEqual((grouped['findings_total'], grouped['distinct_issues'], grouped['count']), (17, 5, 5))
        for mode in ('none', 'cve'):
            self.assertNotIn('distinct_issues', list_findings(self.ctx, 'di-p', {'group': mode}))  # the other views answer as before

    def test_one_grouped_statement_and_no_host_read_when_no_two_names_share_a_version(self):
        # the current-scans lookup (``WITH full_last``) is the filter's own read, made by any query of the current matches: left out here
        reads = lambda ctx: [q['sql'] for q in ctx.captured_queries if not q['sql'].startswith('WITH full_last')]
        with CaptureQueriesContext(connection) as alone:
            self.assertEqual(counts.match_issues(self.open_matches().filter(subdomain=self.stage)), (1, 1))
        self.assertEqual(len(reads(alone)), 1, [q[:160] for q in reads(alone)])
        self.assertIn('GROUP BY', reads(alone)[0])
        with CaptureQueriesContext(connection) as shared:
            counts.match_issues(self.open_matches())
        self.assertEqual(len(reads(shared)), 3, [q[:160] for q in reads(shared)])  # the grouped read, the names' current rows, their fold
        with CaptureQueriesContext(connection) as given:
            counts.match_issues(self.open_matches(), site_of=lambda project_id, name: None)
        self.assertEqual(len(reads(given)), 1)


class OverviewTests(World):
    def test_the_overview_keeps_its_counts_and_adds_the_issues_beside_the_matches(self):
        payload = views.stats_payload()
        self.assertEqual(payload['matches'], counts.exposed_matches().count())  # the raw count is what it was
        self.assertEqual((payload['matches'], payload['match_issues']), (17, 5))
        self.assertEqual(payload['match_issues'], list_findings(self.ctx, 'di-p', {'group': 'product', 'type': 'cve'})['distinct_issues'])

    def test_the_figure_adds_no_statement_but_the_hosts_fold(self):
        """Before, 'matches' was a COUNT over the exposed matches; the grouped read replaces it, so the only new statements are the two host reads,
        and only because two names of the host share a product version here."""
        old = lambda qs, site_of=None, by_project=False: (qs.count(), 0)  # what the snapshot cost before: one COUNT
        with mock.patch.object(counts, 'match_issues', old), CaptureQueriesContext(connection) as before:
            views.stats_payload()
        with CaptureQueriesContext(connection) as after:
            views.stats_payload()
        self.assertLessEqual(len(after) - len(before), 2, [q['sql'][:120] for q in after.captured_queries])

    def test_the_cached_figure_moves_when_a_finding_is_closed(self):
        scope = snapshot_cache.scope_hash('stats', 'di')
        first = snapshot_cache.snapshot('stats', scope, views.stats_payload, 60)['payload']
        self.assertEqual((first['matches'], first['match_issues']), (17, 5))
        with self.captureOnCommitCallbacks(execute=True):  # the close bumps the revision when it commits
            status, body = call(self.token, 'PATCH', f'/api/v1/projects/di-p/matches/{self.on_stage.id}', {'status': 'fixed'})
        self.assertEqual(status, 200, body)
        again = snapshot_cache.snapshot('stats', scope, views.stats_payload, 60)['payload']
        self.assertEqual((again['matches'], again['match_issues']), (16, 4))  # the same snapshot, the same invalidation as the count beside it


class StatusTests(World):
    def test_the_system_status_row_says_the_open_findings_and_the_issues_they_are(self):
        own = system_status._project_row(self.project)
        shared = system_status._project_row(self.project, system_status._shared_inputs([self.project.id]))
        self.assertEqual((own['open_findings_total'], own['open_issues']), (19, 7))
        self.assertEqual(shared, own)  # the shared read (the hosts' own collapse) and the project's own read agree
        total = system_status._totals([own, own])
        self.assertEqual((total['open_findings'], total['open_issues']), (38, 14))
        self.assertIsNone(system_status._totals([own, {**own, 'open_issues': None}])['open_issues'])  # a row from before: no wrong sum

    def test_the_shared_read_does_not_collapse_the_hosts_again(self):
        from cveFeed import inventory_counts
        runs = []
        original = inventory_counts._collapse
        with mock.patch.object(inventory_counts, '_collapse', lambda *a, **k: runs.append(1) or original(*a, **k)), \
                CaptureQueriesContext(connection) as captured:
            system_status._shared_inputs([self.project.id])
        self.assertEqual(len(runs), 1)
        self.assertFalse([q for q in captured.captured_queries if 'ROW_NUMBER() OVER' in q['sql']])


class EmailAndPdfTests(World):
    def test_the_weekly_email_prints_the_issues_beside_the_open_findings(self):
        scope = report_scope.resolve(self.ctx, project='di-p')
        start, end = NOW - timedelta(days=7), NOW + timedelta(minutes=5)
        digest = report_digest.build(scope, start, end, 'weekly', end)
        h = digest['headline']
        self.assertEqual((h['open_findings'], h['open_issues']), (19, 7))
        line = report_digest.issues_line(digest)
        self.assertEqual(line, '19 findings in 7 distinct issues. Version-only matches on the same product and version of one host are one fix, '
                               'so they count as one issue.')
        _subject, text, html = report_digest.render(digest)
        self.assertIn(line, text)
        self.assertIn('19 findings in 7 distinct issues.', html)
        self.assertIn(report_digest.totals_line(digest), text)  # the totals line is still there, as it was
        self.assertEqual(report_digest.issues_line({'headline': {'open_findings': 0, 'open_issues': 0}}), '')
        self.assertEqual(report_digest.issues_line({'headline': {'open_findings': 3}}), '')  # a digest from before the figure

    def test_the_pdf_prints_the_issues_beside_its_counts(self):
        data = report_data.collect(self.project)
        s = data['summary']
        self.assertEqual((s['findings'], s['hygiene'], s['distinct_issues'], s['finding_issues']), (18, 1, 7, 6))
        html = report_pdf.build_html(data)
        self.assertIn('Counted per host as the Findings page and the Overview count them: 19 findings in 7 distinct issues.', html)
        self.assertIn(counts.ISSUES_NOTE, html)
        hosts = report_data.collect(self.project, kind='hosts')
        self.assertIn('that is 18 findings in 6 distinct issues.', report_pdf.build_html(hosts))
