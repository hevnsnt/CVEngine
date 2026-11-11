"""The status counts of a project (``stats_history.compute_snapshot``, behind ``get_system_status``) read the CVE match table once, and are computed once
per project however many people ask (review finding: the per-project severity and heat CASE aggregates were 30 and 26 of 120 slow samples).

Before: the severity bands and the heat counts of the CVE matches were two group-by passes over the same set (``values('sev')`` then ``values('heat_rank')``),
and the project row was cached per user AND project, so every caller of ``get_system_status`` paid for every project again.
"""
import re
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.db.models import Count
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services as svc
from agentapi import system_status
from cveFeed import stats_history
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain


class World(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='S', slug='se-org')
        cls.project = Project.objects.create(name='S', slug='se-proj', insert_date=now, org=org)
        cls.domain = Domain.objects.create(name='se.example.com', project=cls.project, insert_date=now)
        cls.www = Subdomain.objects.create(name='www.se.example.com', target_domain=cls.domain)
        cls.api = Subdomain.objects.create(name='api.se.example.com', target_domain=cls.domain)
        kev = CVEEntry.objects.create(cve_id='CVE-2099-9001', kev=True, cvss=9.8, published_at=now, affected=[])
        mild = CVEEntry.objects.create(cve_id='CVE-2099-9002', cvss=5.0, published_at=now, affected=[])
        CVEMatch.objects.create(cve_entry=kev, subdomain=cls.www, matched_product='nginx', template_result='vulnerable')
        CVEMatch.objects.create(cve_entry=mild, subdomain=cls.api, matched_product='php')
        CVEMatch.objects.create(cve_entry=mild, subdomain=cls.www, matched_product='openssl', remediation_status='fixed', remediation_updated_at=now)
        Vulnerability.objects.create(name='Exposed admin', severity=3, subdomain=cls.www, target_domain=cls.domain, open_status=True,
                                     discovered_date=now - timedelta(days=5), http_url='https://www.se.example.com/')
        cls.root = User.objects.create_superuser('se-root', 'root@se.example.test', 'x')
        cls.a, cls.b = User.objects.create_user('se-a', password='x'), User.objects.create_user('se-b', password='x')
        for user in (cls.a, cls.b):
            ProjectMembership.objects.create(user=user, project=cls.project, role='user')

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)


class MatchTableReadOnceTests(World):
    def test_the_severity_bands_and_the_heat_counts_come_from_one_pass_over_the_matches(self):
        with CaptureQueriesContext(connection) as captured:
            open_findings, matches = stats_history._open_findings_and_cve_matches(self.project)
        passes = [q for q in captured.captured_queries if re.search(r'FROM "cveFeed_cvematch"', q['sql']) and 'GROUP BY' in q['sql']]
        self.assertEqual(len(passes), 1)  # was 2: values('sev') and then values('heat_rank') over the same matches
        self.assertEqual(matches, {'fire': 1, 'smoke': 0, 'ice': 1})
        self.assertEqual(open_findings, {'critical': 1, 'high': 1, 'medium': 1, 'low': 0, 'info': 0})

    def test_the_numbers_are_those_of_the_two_separate_passes(self):
        from cveFeed.threat import HEAT_RANK
        heat_names = {rank: name for name, rank in HEAT_RANK.items()}
        open_findings, matches = stats_history._open_findings_and_cve_matches(self.project)
        expect_bands, expect_heat = {b: 0 for b in stats_history.OPEN_FINDING_BANDS}, {h: 0 for h in stats_history.CVE_MATCH_HEATS}
        for kind, qs in svc._finding_sources(self.project, {'status': 'actionable'}).items():
            for row in qs.values('sev').annotate(n=Count('id')):
                band = svc.SEVERITY_NAMES.get(row['sev'])
                if band in expect_bands:
                    expect_bands[band] += row['n']
            if kind == 'cve':
                for row in qs.values('heat_rank').annotate(n=Count('id')):
                    if heat_names.get(row['heat_rank']) in expect_heat:
                        expect_heat[heat_names[row['heat_rank']]] += row['n']
        self.assertEqual((open_findings, matches), (expect_bands, expect_heat))


class ProjectRowSharedTests(World):
    def rows(self, user):
        return system_status._projects(svc.Ctx(user=user))

    def test_two_callers_share_one_computation_of_a_project(self):
        with mock.patch.object(stats_history, 'compute_snapshot', wraps=stats_history.compute_snapshot) as computed:
            first, second = self.rows(self.a), self.rows(self.b)
            root = self.rows(self.root)
        self.assertEqual(computed.call_count, 1)  # was one per caller: the cache key held the user
        self.assertEqual(first, second)
        self.assertEqual([r['slug'] for r in root], ['se-proj'])
        self.assertEqual(first[0]['hosts'], 2)

    def test_a_caller_never_reads_a_project_they_cannot_see(self):
        outsider = User.objects.create_user('se-out', password='x')
        self.rows(self.a)  # warms the shared row
        self.assertEqual(self.rows(outsider), [])
