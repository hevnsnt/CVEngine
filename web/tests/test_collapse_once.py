"""The host collapse (``counts.host_reps``: one row per project and name, same-address names folded) is computed once per request or run, and
once for all the live screen's snapshots of a scope, not once per number it feeds.

Before: ``stats_payload`` collapsed the inventory twice (the host counts, then the exposed count), ``graph_payload`` twice (the drawn hosts, then the
per-project recount), the dashboard's coverage search four times (facet count, facet ids, page count, page), ``compute_snapshot`` twice. On the production
install each collapse took up to 9.9 s and the refresher asked for stats, discovery counts and the graph every 5 s, so one collapse was always running.
These tests count the collapse statements (the ROW_NUMBER window over the host key), and pin every number to what it was before.
"""
import re
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services as svc
from cveFeed import counts, snapshot_cache, views
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain

COLLAPSE = re.compile(r'ROW_NUMBER\(\) OVER \(PARTITION BY CASE')


def collapses(run):
    """``(times the host collapse ran, result)`` of one call: the SQL statements that run it, and the runs of the collapse worked out in Python from set-based
    reads (``cveFeed.inventory_counts``, which the whole-inventory ``counts.rep_ids`` uses; it was the SQL statement alone until then)."""
    from cveFeed import inventory_counts
    python_runs = []
    original = inventory_counts._collapse
    with mock.patch.object(inventory_counts, '_collapse', lambda *a, **k: python_runs.append(1) or original(*a, **k)), CaptureQueriesContext(connection) as captured:
        result = run()
    return sum(1 for q in captured.captured_queries if COLLAPSE.search(q['sql'])) + len(python_runs), result


class CollapseWorld(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='K', slug='k-org')
        cls.project = Project.objects.create(name='K', slug='k-proj', insert_date=now, org=org)
        cls.engine = EngineType.objects.create(engine_name='k-engine', yaml_configuration='x', default_engine=True)
        cls.domain = Domain.objects.create(name='k.example.com', project=cls.project, insert_date=now)
        scan = ScanHistory.objects.create(domain=cls.domain, scan_type=cls.engine, scan_status=2, start_scan_date=now - timedelta(hours=3), tasks=[])
        cls.user = User.objects.create_superuser('k-root', 'root@k.example.test', 'x')
        shared = IpAddress.objects.create(address='192.0.2.1')
        for i in range(6):  # six live hosts on six addresses
            sub = Subdomain.objects.create(target_domain=cls.domain, name=f'h{i}.k.example.com', scan_history=scan, http_status=200 if i % 2 else 0)
            sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i + 1}'))
        for name in ('k.example.com', 'www.k.example.com'):  # two names on one address are one host
            Subdomain.objects.create(target_domain=cls.domain, name=name, scan_history=scan).ip_addresses.add(shared)
        Subdomain.objects.create(target_domain=cls.domain, name='dead.k.example.com', scan_history=scan)  # never resolved: a host, not live
        cve = CVEEntry.objects.create(cve_id='CVE-2099-6001', cvss=9.8, kev=True, published_at=now, affected=[])
        CVEMatch.objects.create(cve_entry=cve, subdomain=Subdomain.objects.get(name='h0.k.example.com'), matched_product='nginx', confidence=.9)
        CVEMatch.objects.create(cve_entry=cve, subdomain=Subdomain.objects.get(name='www.k.example.com'), matched_product='nginx', confidence=.9)

    def setUp(self):
        views.clear_stats_cache()
        cache.clear()
        self.addCleanup(views.clear_stats_cache)


class CollapseRunsOnceTests(CollapseWorld):
    def test_the_headline_counts_collapse_the_inventory_once(self):
        n, payload = collapses(views.stats_payload)
        self.assertEqual(n, 1)
        # the numbers are what the two collapses gave: 6 live hosts + the folded pair + the dead one = 8 hosts, 7 live
        self.assertEqual((payload['hosts'], payload['hosts_live'], payload['exposed_hosts']), (8, 7, 2))
        self.assertEqual(payload['hosts'], counts.host_reps().count())
        self.assertEqual(payload['hosts_live'], counts.live_hosts().count())
        self.assertEqual(payload['exposed_hosts'], counts.exposed_among(counts.host_reps()).count())

    def test_the_headline_counts_with_a_declared_internal_network_still_collapse_once(self):
        from cveFeed.models import InternalRange
        InternalRange.objects.create(project=self.project, cidr='198.51.100.0/24', description='lab')
        from cveFeed import internal_view
        internal_view.invalidate()
        n, payload = collapses(views.stats_payload)
        self.assertEqual(n, 1)
        self.assertTrue(payload['internal']['has'])
        self.assertEqual(payload['internal']['hosts'], counts.host_reps().filter(internal_view.internal_q()).count())
        internal_view.invalidate()

    def test_the_graph_collapses_the_inventory_once_even_when_the_cap_cuts_it(self):
        with mock.patch.object(views, 'GRAPH_NODE_CAP', 3):
            n, payload = collapses(views.graph_payload)
        self.assertEqual(n, 1)
        self.assertEqual(payload['hosts']['total'], 7)  # the live hosts, counted past the cap
        self.assertEqual(payload['hosts']['projects'], {'k-proj': 7})

    def test_the_coverage_search_collapses_the_inventory_twice_at_most(self):
        ctx = svc.Ctx(user=self.user)
        n, page = collapses(lambda: svc.search_hosts(ctx, 'k-proj', {'q': '', 'page_size': '1'}))
        self.assertLessEqual(n, 2)  # was 4: the facet count, the facet ids, the page count and the page
        self.assertEqual(page['count'], 8)
        self.assertEqual(sum(page['facets']['heat'].values()), 8)

    def test_the_stored_daily_counts_collapse_once(self):
        from cveFeed.stats_history import compute_snapshot
        n, snap = collapses(lambda: compute_snapshot(self.project, with_fixed=False))
        self.assertEqual(n, 1)
        self.assertEqual((snap['hosts'], snap['exposed_hosts']), (8, 2))


class SharedCollapseTests(CollapseWorld):
    def test_the_live_snapshots_of_one_scope_share_one_collapse(self):
        """Headline counts, ticker counts and graph are three snapshots of one scope: the refresher built each from its own collapse."""
        def all_three():
            snapshot_cache.snapshot('stats', 's', views.stats_payload, 10)
            snapshot_cache.snapshot('discovery-counts', 's', views.discovery_counts, 10)
            snapshot_cache.snapshot('graph-version', 's', views.graph_payload, 10)
        n, _ = collapses(all_three)
        self.assertEqual(n, 1)

    def test_a_direct_call_is_never_served_from_the_shared_copy(self):
        snapshot_cache.snapshot('discovery-counts', 's', views.discovery_counts, 10)  # leaves the shared host list in the cache
        Subdomain.objects.create(target_domain=self.domain, name='new.k.example.com', scan_history=ScanHistory.objects.get(domain=self.domain))
        self.assertEqual(views.stats_payload()['hosts'], 9)  # a request that is not building a snapshot reads the database

    def test_a_revision_bump_drops_the_shared_copy(self):
        snapshot_cache.snapshot('stats', 's', views.stats_payload, 10)
        Subdomain.objects.create(target_domain=self.domain, name='new.k.example.com', scan_history=ScanHistory.objects.get(domain=self.domain))
        views.bump_stats_revision()
        self.assertEqual(snapshot_cache.snapshot('stats', 's', views.stats_payload, 10)['payload']['hosts'], 9)


class CostProportionalFreshnessTests(CollapseWorld):
    def test_a_slow_snapshot_is_served_longer_so_the_refresher_does_not_recompute_it_every_five_seconds(self):
        clock = [1000.0]
        calls = []

        def compute():
            calls.append(1)
            clock[0] += 8  # a computation that takes eight seconds
            return {'n': len(calls)}
        with mock.patch.object(snapshot_cache, '_now', lambda: clock[0]), mock.patch.object(snapshot_cache, '_elapsed', lambda: clock[0]):
            first = snapshot_cache.snapshot('stats', 'slow', compute, 10)
            clock[0] += 40  # 40 s after: stale at a fixed 10 s, fresh when a 8 s run is kept for 10 x 8 = 80 s
            again = snapshot_cache.snapshot('stats', 'slow', compute, 10)
            self.assertEqual(len(calls), 1)
            self.assertEqual(again['payload'], first['payload'])
            clock[0] += 60  # past 80 s: due again
            snapshot_cache.snapshot('stats', 'slow', compute, 10)
            self.assertEqual(len(calls), 2)

    def test_a_fast_snapshot_keeps_its_ten_seconds(self):
        clock = [1000.0]
        calls = []

        def compute():
            calls.append(1)
            clock[0] += 0.2
            return {'n': len(calls)}
        with mock.patch.object(snapshot_cache, '_now', lambda: clock[0]), mock.patch.object(snapshot_cache, '_elapsed', lambda: clock[0]):
            snapshot_cache.snapshot('stats', 'fast', compute, 10)
            clock[0] += 11
            snapshot_cache.snapshot('stats', 'fast', compute, 10)
        self.assertEqual(len(calls), 2)

    def test_a_closed_finding_still_drops_a_slow_snapshot_at_once(self):
        clock = [1000.0]
        calls = []

        def compute():
            calls.append(1)
            clock[0] += 8
            return {'n': len(calls)}
        with mock.patch.object(snapshot_cache, '_now', lambda: clock[0]), mock.patch.object(snapshot_cache, '_elapsed', lambda: clock[0]):
            snapshot_cache.snapshot('stats', 'bump', compute, 10)
            views.bump_stats_revision()
            snapshot_cache.snapshot('stats', 'bump', compute, 10)
        self.assertEqual(len(calls), 2)

    def test_the_refresher_leaves_a_slow_snapshot_alone_while_it_is_fresh(self):
        clock = [1000.0]
        calls = []

        def compute():
            calls.append(1)
            clock[0] += 8
            return {'n': len(calls)}
        with mock.patch.object(snapshot_cache, '_now', lambda: clock[0]), mock.patch.object(snapshot_cache, '_elapsed', lambda: clock[0]):
            snapshot_cache.refresh('stats', 'ref', compute, 10, due_age=5)
            clock[0] += 20  # a fixed 10 s freshness (due after 5 s) would recompute here
            status, _entry, _prev = snapshot_cache.refresh('stats', 'ref', compute, 10, due_age=5)
        self.assertEqual(status, 'fresh')
        self.assertEqual(len(calls), 1)
