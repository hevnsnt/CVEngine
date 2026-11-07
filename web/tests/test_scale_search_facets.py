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
from cveFeed.models import CVEEntry, CVEMatch, Triage
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


class FacetFreshnessTests(TestCase):
    def test_a_dear_walk_is_served_longer_a_cheap_one_the_minimum(self):
        from agentapi import services
        self.assertEqual(services.facet_freshness(None), services.HEAT_FACET_SECONDS)
        self.assertEqual(services.facet_freshness(0.2), services.HEAT_FACET_SECONDS)
        self.assertEqual(services.facet_freshness(3.0), 30)
        self.assertEqual(services.facet_freshness(500), services.HEAT_FACET_CEILING)


class GraphPayloadQueryTests(TestCase):
    """graph_payload deferred columns of the match and its triage that the heat rules then read one row at a time (1,900 queries at 3000 hosts)."""

    def build(self, hosts):
        now = timezone.now()
        project = Project.objects.create(name='G', slug='gq', insert_date=now, org=Org.objects.create(name='G', slug='gq-org'))
        domain = Domain.objects.create(name='gq.example.test', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='gq'), start_scan_date=now, scan_status=2)
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=7.5, published_at=now)
        for i in range(hosts):
            sub = Subdomain.objects.create(name=f'g{i}.gq.example.test', target_domain=domain, scan_history=scan, http_status=200)
            sub.ip_addresses.add(IpAddress.objects.create(address=f'192.0.2.{i + 1}'))
            match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9, source='version')
            Triage.objects.create(project=project, domain=domain, host=sub.name, kind='cve', match=match, status='triaged', classification='confirmed', validation_status='hit')

    def cost(self):
        cache.clear()
        with CaptureQueriesContext(connection) as q:
            payload = views.graph_payload()
        self.assertGreater(len(payload['nodes']), 0)
        return len(q)

    def test_the_cost_does_not_grow_with_the_hosts_and_their_matches(self):
        self.build(5)
        self.cost()  # the first call fills the process-wide caches (content types, settings)
        few = self.cost()
        for i in range(5, 30):
            self.build_more(i)
        self.assertEqual(self.cost(), few)

    def build_more(self, i):
        from targetApp.models import Domain as D
        domain = D.objects.get(name='gq.example.test')
        scan = ScanHistory.objects.get()
        sub = Subdomain.objects.create(name=f'g{i}.gq.example.test', target_domain=domain, scan_history=scan, http_status=200)
        sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i}'))
        match = CVEMatch.objects.create(cve_entry=CVEEntry.objects.get(cve_id='CVE-2099-7'), subdomain=sub, confidence=0.9, source='version')
        Triage.objects.create(project=domain.project, domain=domain, host=sub.name, kind='cve', match=match, status='triaged', classification='confirmed', validation_status='hit')
