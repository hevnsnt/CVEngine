"""The host search's whole-match counts (heat chips, the dashboard's coverage tile) at a scaled fixture: one walk over the hosts is shared by every
viewer for HEAT_FACET_SECONDS, so the next poll costs a fixed handful of queries however many hosts match, and a finding closed in between drops it."""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import views
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call


class SearchFacetCacheTests(TestCase):
    HOSTS = 60

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        project = Project.objects.create(name='S', slug='sf', insert_date=now, org=Org.objects.create(name='S', slug='sf-org'))
        domain = Domain.objects.create(name='sf.example.test', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='sf'), start_scan_date=now, scan_status=2)
        for i in range(cls.HOSTS):
            sub = Subdomain.objects.create(name=f'h{i}.sf.example.test', target_domain=domain, scan_history=scan, http_status=200)
            ip = IpAddress.objects.create(address=f'192.0.2.{i + 1}')
            ip.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
            sub.ip_addresses.add(ip)
        _, cls.token = create_token(User.objects.create_user('sf-root', password='x', is_superuser=True), 'sf')

    def setUp(self):
        cache.clear()

    def search(self, query='q=&page_size=1'):
        with CaptureQueriesContext(connection) as q:
            status, data = call(self.token, 'GET', f'/api/v1/projects/sf/search?{query}')
        self.assertEqual(status, 200, data)
        return data, len(q)

    def test_the_second_poll_costs_a_fixed_handful_of_queries_not_a_walk_over_the_hosts(self):
        first, cold = self.search()
        second, warm = self.search()
        self.assertEqual(first['facets'], second['facets'])
        self.assertEqual(sum(first['facets']['heat'].values()), self.HOSTS)
        self.assertGreater(cold - warm, 50, 'the first poll walks the hosts (prefetching ports, matches and findings): the cost the cache removes')
        self.assertLessEqual(warm, 50, 'a cached poll is the page build and the request overhead only')

    def test_the_cached_cost_does_not_grow_with_the_hosts(self):
        self.search()
        _, warm = self.search()
        cache.clear()
        for i in range(self.HOSTS, self.HOSTS + 30):
            sub = Subdomain.objects.create(name=f'h{i}.sf.example.test', target_domain=Domain.objects.get(name='sf.example.test'),
                                           scan_history=ScanHistory.objects.get(), http_status=200)
            sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i - self.HOSTS + 1}'))
        self.search()
        _, bigger_warm = self.search()
        self.assertEqual(warm, bigger_warm)

    def test_a_different_search_or_filter_is_not_served_the_cached_counts(self):
        everything, _ = self.search()
        nothing, _ = self.search('q=nosuchword&page_size=1')
        self.assertEqual(sum(everything['facets']['heat'].values()), self.HOSTS)
        self.assertEqual(sum(nothing['facets']['heat'].values()), 0)

    def test_a_revision_bump_drops_the_cached_counts(self):
        self.search()
        Subdomain.objects.filter(name='h0.sf.example.test').delete()
        stale, _ = self.search()
        self.assertEqual(sum(stale['facets']['heat'].values()), self.HOSTS)  # inside the freshness window: the shared snapshot
        views.bump_stats_revision()
        fresh, _ = self.search()
        self.assertEqual(sum(fresh['facets']['heat'].values()), self.HOSTS - 1)
