"""The dashboard's stored numbers equal a direct recount, never leak another viewer's projects, and the host walk behind them runs once.

Fail without the change: before it, the headline counts were computed by the request (so equal by construction, and slow), and nothing bounded how
often one snapshot build walked the inventory; ``counts.walk_memo`` and the id sets of the ticker's counts are what these pin.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from cveFeed import counts, views
from cveFeed import dashboard_snapshot as snap
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tenancy import scope as tenancy_scope
from tests.test_dashboard_snapshot import seed
from tests.test_tenancy import client_for

STATS, DISCOVERY = '/cve/api/stats?project=_all', '/cve/api/discovery?scan=&after=0&project=_all'


def recount(project_ids=None):
    """What a single walk over everything the scope sees says: the numbers the page showed before snapshots existed."""
    tokens = tenancy_scope.set_scope(None if project_ids is None else set(project_ids), None)
    try:
        return views.stats_payload(), views.discovery_counts()
    finally:
        tenancy_scope.reset_scope(tokens)


class Shaped(TestCase):
    def setUp(self):
        cache.clear()
        self.projects = seed(6)
        # two projects of one organization that share an address, and one host name present in both: an address is one address however many
        # projects hold it, a name in two projects is two hosts
        a, b = self.projects[2], self.projects[3]
        shared = IpAddress.objects.create(org=a.org, address='198.51.100.77')
        for p in (a, b):
            d = Domain.objects.filter(project=p).first()
            sub = Subdomain.objects.create(target_domain=d, name='shared.example.com')
            sub.ip_addresses.add(shared)
        self.admin = User.objects.create_user('exact-admin', password='x', is_superuser=True)

    def refresh_all(self):
        return [snap.refresh_project(p.id) for p in self.projects]


class StoredNumbersEqualARecountTests(Shaped):
    def test_every_summed_headline_number_equals_a_direct_recount(self):
        self.refresh_all()
        entries, _ = snap.collect([p.id for p in self.projects], ask=False)
        merged = snap.merge_stats(entries)
        direct, _ = recount([p.id for p in self.projects])
        for key in snap.SUM_KEYS:
            self.assertEqual(merged[key], direct[key], f'{key}: stored {merged[key]} against a recount {direct[key]}')

    def test_the_tickers_addresses_and_ports_are_unions_so_a_shared_address_counts_once(self):
        self.refresh_all()
        entries, _ = snap.collect([p.id for p in self.projects], ask=False)
        merged = snap.merge_discovery(entries)
        _, direct = recount([p.id for p in self.projects])
        self.assertEqual(merged, direct)
        # the sum of the per-project counts would say one more: the stored sets are what make it exact
        self.assertEqual(sum(e['payload']['discovery']['ips'] for e in entries), direct['ips'] + 1)

    def test_what_the_page_gets_equals_the_recount_through_the_views(self):
        self.refresh_all()
        client = client_for(self.admin)
        stats, discovery = client.get(STATS).json(), client.get(DISCOVERY).json()['counts']
        direct, direct_discovery = recount()
        for key in ('hosts', 'hosts_live', 'exposed_hosts', 'matches', 'targets'):
            self.assertEqual(stats[key], direct[key], key)
        self.assertEqual(discovery, direct_discovery)

    def test_a_change_after_the_snapshot_is_shown_after_the_next_refresh_and_the_page_says_it_is_updating(self):
        self.refresh_all()
        p = self.projects[0]
        d = Domain.objects.filter(project=p).first()
        Subdomain.objects.create(target_domain=d, name='fresh.p0.example.com')
        client = client_for(self.admin)
        before = client.get(f'/cve/api/stats?project={p.slug}').json()
        self.assertEqual(before['hosts'], recount([p.id])[0]['hosts'] - 1)  # the stored number is the old one, and says when it was built
        self.assertTrue(before['snapshot']['as_of'])
        snap.refresh_project(p.id)
        after = client.get(f'/cve/api/stats?project={p.slug}').json()
        self.assertEqual(after['hosts'], recount([p.id])[0]['hosts'])


class TenancyTests(Shaped):
    def test_a_viewer_gets_only_the_projects_they_may_see_though_every_snapshot_is_stored(self):
        self.refresh_all()
        mine = self.projects[1]
        user = User.objects.create_user('exact-viewer', password='x')
        ProjectMembership.objects.create(user=user, project=mine, role='audit')
        stats = client_for(user).get(STATS).json()
        direct, _ = recount([mine.id])
        self.assertEqual((stats['hosts'], stats['targets'], stats['matches']), (direct['hosts'], 1, direct['matches']))
        self.assertLess(stats['hosts'], recount()[0]['hosts'])
        discovery = client_for(user).get(DISCOVERY).json()['counts']
        self.assertEqual(discovery, recount([mine.id])[1])

    def test_two_viewers_with_different_projects_never_read_each_others_numbers_in_either_order(self):
        self.refresh_all()
        users = []
        for i, p in enumerate((self.projects[4], self.projects[5])):
            u = User.objects.create_user(f'exact-{i}', password='x')
            ProjectMembership.objects.create(user=u, project=p, role='audit')
            users.append((u, p))
        for u, p in users + users[::-1]:
            got = client_for(u).get(STATS).json()
            self.assertEqual(got['hosts'], recount([p.id])[0]['hosts'], f'{u.username} was shown another scope')

    def test_a_viewer_of_nothing_is_shown_nothing_not_the_sum_of_everything(self):
        self.refresh_all()
        nobody = User.objects.create_user('exact-nobody', password='x')
        stats = client_for(nobody).get(STATS).json()
        self.assertEqual((stats.get('hosts', 0), stats.get('targets', 0)), (0, 0))

    def test_a_snapshot_is_keyed_by_project_not_by_viewer_or_scope_hash(self):
        self.refresh_all()
        keys = {snap.key_of(p.id) for p in self.projects}
        self.assertEqual(len(keys), len(self.projects))
        self.assertTrue(all(cache.get(k) is not None for k in keys))
        self.assertTrue(all(str(p.id) in snap.key_of(p.id) for p in self.projects))

    def test_the_stored_snapshots_are_bounded_one_entry_per_project(self):
        self.refresh_all()
        self.refresh_all()
        self.refresh_all()
        stored = [k for k in (snap.key_of(p.id) for p in Project.objects.all()) if cache.get(k) is not None]
        self.assertEqual(len(stored), Project.objects.count())


class OneWalkTests(Shaped):
    @staticmethod
    def walks(queries):
        return sum(1 for q in queries if 'ROW_NUMBER' in q['sql'].upper())

    def test_the_host_walk_runs_once_inside_a_memo_however_many_counts_ask_for_it(self):
        with CaptureQueriesContext(connection) as unmemoised:
            for _ in range(4):
                counts.host_reps().count()
        self.assertGreaterEqual(self.walks(unmemoised.captured_queries), 4)
        with CaptureQueriesContext(connection) as memoised, counts.walk_memo():
            for _ in range(4):
                counts.host_reps().count()
            counts.host_reps().filter(counts.LIVE_HOST_Q).count()
        self.assertEqual(self.walks(memoised.captured_queries), 1)

    def test_the_memo_gives_the_same_hosts_as_the_walk(self):
        plain = sorted(counts.host_reps().values_list('pk', flat=True))
        with counts.walk_memo():
            memo = sorted(counts.host_reps().values_list('pk', flat=True))
            again = sorted(counts.host_reps().values_list('pk', flat=True))
        self.assertEqual(plain, memo)
        self.assertEqual(plain, again)

    def test_a_memo_never_carries_one_scope_into_another(self):
        mine, other = self.projects[1], self.projects[2]
        with counts.walk_memo():
            tokens = tenancy_scope.set_scope({mine.id}, None)
            try:
                a = set(counts.host_reps().values_list('pk', flat=True))
            finally:
                tenancy_scope.reset_scope(tokens)
            tokens = tenancy_scope.set_scope({other.id}, None)
            try:
                b = set(counts.host_reps().values_list('pk', flat=True))
            finally:
                tenancy_scope.reset_scope(tokens)
        self.assertTrue(a and b and not (a & b))

    def test_a_snapshot_build_walks_the_inventory_once(self):
        project = self.projects[3]
        with CaptureQueriesContext(connection) as q:
            snap.compute_project(project.id)
        self.assertLessEqual(self.walks(q.captured_queries), 2, 'one walk for the counts and, at most, one more for the host search the heat facets read')

    def test_a_snapshot_build_costs_the_same_queries_with_ten_times_the_hosts(self):
        project = self.projects[0]
        with CaptureQueriesContext(connection) as small:
            snap.compute_project(project.id)
        d = Domain.objects.filter(project=project).first()
        for h in range(60):
            s = Subdomain.objects.create(target_domain=d, name=f'bulk{h}.p0.example.com')
            s.ip_addresses.add(IpAddress.objects.create(org=project.org, address=f'2001:db8::{h + 1:x}'))
        with CaptureQueriesContext(connection) as big:
            snap.compute_project(project.id)
        self.assertLessEqual(len(big.captured_queries), len(small.captured_queries) + 6, 'the query count must not grow with the hosts')
