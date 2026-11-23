"""The Findings counts of a count-only request are a shared snapshot (review finding A3).

The Findings page asks ``findings?page_size=0`` once per chip (type, severity, heat), on every load and every filter change, and each request ran three
COUNTs over the project's findings (CVE matches with the current-inventory filter, scanner findings, hygiene findings). The counts of a count-only request
are now a ``cveFeed.snapshot_cache`` snapshot keyed by the scope (the project ids and the caller's allowed projects) and every facet, kept 15 seconds and
dropped at once when a finding is closed, reopened or given a heat. A page of rows still counts afresh.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call


class FindingCountsSnapshotTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Fc', slug='fc-org')
        engine = EngineType.objects.create(engine_name='fc-e', yaml_configuration='x', default_engine=True)
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7101', cvss=9.8, kev=True, published_at=now, affected=[])
        cls.tokens, cls.subs, cls.domains = {}, {}, {}
        for slug, n in (('fc-a', 3), ('fc-b', 1)):
            project = Project.objects.create(name=slug, slug=slug, insert_date=now, org=org)
            domain = Domain.objects.create(name=f'{slug}.example.com', project=project, insert_date=now)
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now, tasks=[])
            sub = Subdomain.objects.create(name=f'www.{slug}.example.com', target_domain=domain, scan_history=scan)
            for i in range(n):
                CVEMatch.objects.create(cve_entry=cls.cve, subdomain=sub, matched_product=f'p{i}', matched_version='1', confidence=.5,
                                        template_result='vulnerable')
                Vulnerability.objects.create(name=f'v{i}', severity=3, subdomain=sub, target_domain=domain, open_status=True, discovered_date=now)
            HygieneFinding.objects.create(domain=domain, host=sub.name, check_name='dmarc_none', severity=2, title='DMARC', status='open')
            user = User.objects.create_user(f'{slug}-user', password='x')
            ProjectMembership.objects.create(user=user, project=project, role='user')
            cls.tokens[slug] = create_token(user, 'agent')[1]
            cls.subs[slug], cls.domains[slug] = sub, domain

    def setUp(self):
        cache.clear()  # the counts are a shared snapshot: a test must not read another one's

    def counts(self, slug, query='page_size=0'):
        with CaptureQueriesContext(connection) as ctx:
            status, body = call(self.tokens[slug], 'GET', f'/api/v1/projects/{slug}/findings?{query}')
        self.assertEqual(status, 200, body)
        counting = sum(1 for q in ctx.captured_queries if q['sql'].lstrip().upper().startswith('SELECT COUNT(*)'))
        return body['counts'], counting

    def test_a_second_count_only_poll_runs_no_count_and_says_the_same(self):
        self.counts('fc-a', 'page_size=0&type=hygiene')  # the first request warms the token and the per-process caches: not the counts' own work
        first, counted = self.counts('fc-a')
        self.assertEqual(first, {'cve': 3, 'scanner': 3, 'hygiene': 1})
        again, recounted = self.counts('fc-a')
        self.assertEqual(again, first)
        self.assertEqual(counted - recounted, 3, 'the second poll must not run the three finding counts')
        self.assertEqual(self.counts('fc-a', 'page_size=5')[0], first)  # the page's own counts agree

    def test_each_project_and_each_facet_has_its_own_counts(self):
        self.counts('fc-a')
        self.assertEqual(self.counts('fc-b')[0], {'cve': 1, 'scanner': 1, 'hygiene': 1})
        self.assertEqual(self.counts('fc-a', 'page_size=0&type=scanner')[0], {'cve': 0, 'scanner': 3, 'hygiene': 0})
        self.assertEqual(self.counts('fc-a', 'page_size=0&host=nothing-here')[0], {'cve': 0, 'scanner': 0, 'hygiene': 0})
        self.assertEqual(self.counts('fc-a', 'page_size=0&severity=medium')[0], {'cve': 0, 'scanner': 0, 'hygiene': 1})

    def test_a_finding_marked_fixed_drops_the_counts(self):
        self.counts('fc-a')
        match = CVEMatch.objects.filter(subdomain=self.subs['fc-a']).first()
        with self.captureOnCommitCallbacks(execute=True):
            status, _ = call(self.tokens['fc-a'], 'PATCH', f'/api/v1/projects/fc-a/matches/{match.pk}', {'status': 'fixed'})
        self.assertEqual(status, 200)
        self.assertEqual(self.counts('fc-a')[0]['cve'], 2)

    def test_a_page_of_rows_always_counts_afresh(self):
        self.assertEqual(self.counts('fc-a', 'page_size=5')[0]['scanner'], 3)
        Vulnerability.objects.create(name='new', severity=3, subdomain=self.subs['fc-a'], target_domain=self.domains['fc-a'], open_status=True,
                                     discovered_date=timezone.now())
        self.assertEqual(self.counts('fc-a', 'page_size=5')[0]['scanner'], 4)
