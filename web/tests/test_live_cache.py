"""Stage 0 of the live-screen caching plan: shared per-scope snapshots, conditional GETs, and query ceilings for what the Live page polls."""
import contextlib
import json
import threading
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi.services import Ctx
from cveFeed import graph_live, snapshot_cache, views
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, DiscoveryEvent
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tenancy import roles, scope
from tests.test_tenancy import client_for


@contextlib.contextmanager
def steady_caches():
    """Pin the per-process caches that expire on the clock, so no request of a measure pays for one (the same helper as
    tests.test_check_coverage: the IP allowlist and ban caches expire after 10 s, the internal network table after 5 minutes, and a request
    landing after the expiry costs two or three queries more)."""
    from cveFeed import internal_view
    from reNgine import input_guard, ip_allowlist
    internal_view.invalidate()
    with mock.patch.object(internal_view, 'CACHE_SECONDS', float('inf')), \
            mock.patch.object(ip_allowlist, '_load', return_value=(False, [])), \
            mock.patch.object(input_guard, 'banned_ips', return_value=frozenset()):
        internal_view.table()
        yield
    internal_view.invalidate()


class World(TestCase):
    """Two tenants. alpha (organization A) has two members, beta (organization B) has one, and there is one App Admin."""

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org_a, cls.org_b = Org.objects.create(name='Org A', slug='org-a'), Org.objects.create(name='Org B', slug='org-b')
        cls.alpha = Project.objects.create(name='Alpha', slug='lc-alpha', insert_date=now, org=cls.org_a)
        cls.beta = Project.objects.create(name='Beta', slug='lc-beta', insert_date=now, org=cls.org_b)
        cls.engine = EngineType.objects.create(engine_name='lc-engine', yaml_configuration='x', default_engine=True)
        cls.hosts = {}
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7001', kev=True, cvss=9.8, published_at=now, affected=[])
        for project, word in ((cls.alpha, 'alpha'), (cls.beta, 'beta')):
            domain = Domain.objects.create(name=f'{word}.lcexample.test', project=project, insert_date=now)
            done = ScanHistory.objects.create(domain=domain, scan_type=cls.engine, scan_status=2, start_scan_date=now - timedelta(hours=2),
                                              stop_scan_date=now - timedelta(hours=1))
            running = ScanHistory.objects.create(domain=domain, scan_type=cls.engine, scan_status=1, start_scan_date=now - timedelta(minutes=3))
            host = Subdomain.objects.create(name=f'www.{word}.lcexample.test', target_domain=domain, scan_history=done, http_status=200)
            host.ip_addresses.add(IpAddress.objects.create(address='192.0.2.%d' % (10 if word == 'alpha' else 20)))
            CVEMatch.objects.create(cve_entry=cls.cve, subdomain=host, matched_product=f'{word}-nginx', confidence=0.9)
            DiscoveryEvent.objects.create(scan=running, domain=domain, type='DNS_NAME', label=f'{word}-event', host=f'www.{word}.lcexample.test')
            AgentActivity.objects.create(project=project, kind='scan', message=f'{word}-activity line', status='done')
            cls.hosts[word] = (domain, done, running, host)
        cls.a1 = User.objects.create_user('lc-a1', password='x')
        cls.a2 = User.objects.create_user('lc-a2', password='x')
        cls.b1 = User.objects.create_user('lc-b1', password='x')
        cls.root = User.objects.create_superuser('lc-root', 'root@lc.example.test', 'x')
        for user, project in ((cls.a1, cls.alpha), (cls.a2, cls.alpha), (cls.b1, cls.beta)):
            ProjectMembership.objects.create(user=user, project=project, role='user')

    def setUp(self):
        views.clear_stats_cache()
        self.addCleanup(views.clear_stats_cache)


# --- the scope hash and the snapshot itself ---------------------------------------------------------------------------


class ScopeHashTests(World):
    def hash_for(self, ids, *params):
        tokens = scope.set_scope(ids, None)
        try:
            return snapshot_cache.scope_hash(*params)
        finally:
            scope.reset_scope(tokens)

    def test_the_same_projects_hash_alike_whoever_asks_and_in_any_order(self):
        self.assertEqual(self.hash_for({self.alpha.id, self.beta.id}), self.hash_for({self.beta.id, self.alpha.id}))
        self.assertEqual(self.hash_for({self.alpha.id}, 'p', ''), self.hash_for({self.alpha.id}, 'p', ''))

    def test_different_projects_or_parameters_never_share_a_key(self):
        keys = {self.hash_for({self.alpha.id}), self.hash_for({self.beta.id}), self.hash_for({self.alpha.id, self.beta.id}),
                self.hash_for({self.alpha.id}, 'lc-alpha', ''), self.hash_for({self.alpha.id}, 'lc-alpha', 'org-a'), self.hash_for(set())}
        self.assertEqual(len(keys), 6)

    def test_an_unrestricted_caller_hashes_every_project_and_a_new_project_changes_the_key(self):
        before = self.hash_for(None)
        self.assertNotEqual(before, self.hash_for({self.alpha.id, self.beta.id}))  # unrestricted also sees rows no project owns
        Project.objects.create(name='Gamma', slug='lc-gamma', insert_date=timezone.now(), org=self.org_a)
        self.assertNotEqual(before, self.hash_for(None))


class SnapshotTests(SimpleTestCase):
    def setUp(self):
        self.name = f'unit-{time.monotonic_ns()}'
        self.addCleanup(lambda: cache.delete_many([f'cve:snap:{self.name}:s', f'cve:snap:{self.name}:s:lock', f'cve:snap:{self.name}:t']))

    def test_polls_inside_the_window_share_one_computation_and_a_later_one_recomputes(self):
        compute = mock.Mock(side_effect=[{'n': 1}, {'n': 2}])
        with mock.patch.object(snapshot_cache, '_now', side_effect=[100.0, 105.0, 111.0, 111.0]):
            first = snapshot_cache.snapshot(self.name, 's', compute, 10)
            again = snapshot_cache.snapshot(self.name, 's', compute, 10)
            later = snapshot_cache.snapshot(self.name, 's', compute, 10)
        self.assertEqual((first['payload'], again['payload'], later['payload']), ({'n': 1}, {'n': 1}, {'n': 2}))
        self.assertEqual(compute.call_count, 2)
        self.assertEqual(first['etag'], again['etag'])
        self.assertNotEqual(first['etag'], later['etag'])

    def test_a_revision_bump_makes_a_warm_snapshot_stale(self):
        compute = mock.Mock(side_effect=[{'n': 1}, {'n': 2}])
        self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'n': 1})
        self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'n': 1})
        snapshot_cache.bump_revision()
        self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'n': 2})

    def test_scopes_never_read_each_other(self):
        compute = mock.Mock(side_effect=[{'who': 's'}, {'who': 't'}])
        self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'who': 's'})
        self.assertEqual(snapshot_cache.snapshot(self.name, 't', compute, 60)['payload'], {'who': 't'})

    def test_a_cache_that_raises_never_breaks_the_answer(self):
        class Down:
            def __getattr__(self, name):
                def boom(*a, **k):
                    raise ConnectionError('redis is down')
                return boom
        compute = mock.Mock(side_effect=[{'n': 1}, {'n': 2}])
        with mock.patch.object(snapshot_cache, 'cache', Down()):
            self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'n': 1})
            self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'n': 2})  # nothing is cached: computed directly
            snapshot_cache.bump_revision()  # and a bump does not raise either

    def test_a_cache_that_stores_nothing_still_answers(self):
        compute = mock.Mock(return_value={'n': 1})
        with mock.patch.object(snapshot_cache.cache, 'set', side_effect=ConnectionError('down')):
            self.assertEqual(snapshot_cache.snapshot(self.name, 's', compute, 60)['payload'], {'n': 1})
        self.assertFalse(cache.get(f'cve:snap:{self.name}:s:lock'), 'the lock is released even when storing failed')

    def test_a_failing_compute_releases_the_lock_and_propagates(self):
        with self.assertRaises(RuntimeError):
            snapshot_cache.snapshot(self.name, 's', mock.Mock(side_effect=RuntimeError('x')), 60)
        self.assertEqual(snapshot_cache.snapshot(self.name, 's', mock.Mock(return_value={'ok': 1}), 60)['payload'], {'ok': 1})

    def test_ten_threads_on_a_cold_key_compute_once(self):
        calls = []

        def slow():
            calls.append(1)
            time.sleep(0.4)
            return {'n': len(calls)}
        results, errors = [], []

        def worker():
            try:
                results.append(snapshot_cache.snapshot(self.name, 's', slow, 60)['payload'])
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        threads = [threading.Thread(target=worker) for _ in range(10)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        self.assertEqual(len(calls), 1, 'the winner computes; the others wait for its answer')
        self.assertEqual(results, [{'n': 1}] * 10)

    def test_a_stale_copy_is_served_while_one_request_refreshes_it(self):
        compute = mock.Mock(return_value={'n': 1})
        with mock.patch.object(snapshot_cache, '_now', return_value=100.0):
            snapshot_cache.snapshot(self.name, 's', compute, 10)
        cache.add(f'cve:snap:{self.name}:s:lock', 1, 30)  # another request is refreshing right now
        loser = mock.Mock(return_value={'n': 99})
        with mock.patch.object(snapshot_cache, '_now', return_value=200.0):
            got = snapshot_cache.snapshot(self.name, 's', loser, 10)
        self.assertEqual(got['payload'], {'n': 1})
        loser.assert_not_called()

    def test_if_none_match_forms(self):
        from django.test import RequestFactory
        for header, expect in (('"abc"', True), ('W/"abc"', True), ('abc', True), ('"x", "abc"', True), ('*', True), ('"abd"', False), ('', False)):
            request = RequestFactory().get('/', HTTP_IF_NONE_MATCH=header) if header else RequestFactory().get('/')
            self.assertEqual(snapshot_cache.matches(request, 'abc'), expect, header)


# --- the endpoints ----------------------------------------------------------------------------------------------------


class SharedScopeTests(World):
    def test_two_members_of_one_project_share_one_stats_computation(self):
        with mock.patch.object(views, 'stats_payload', wraps=views.stats_payload) as compute:
            first = client_for(self.a1).get('/cve/api/stats')
            second = client_for(self.a2).get('/cve/api/stats')
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(compute.call_count, 1)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(first['ETag'], second['ETag'])

    def test_two_members_of_one_project_share_one_discovery_count_computation(self):
        with mock.patch.object(views, 'discovery_counts', wraps=views.discovery_counts) as compute:
            client_for(self.a1).get('/cve/api/discovery')
            client_for(self.a2).get('/cve/api/discovery')
        self.assertEqual(compute.call_count, 1)

    def test_two_scopes_never_share_a_snapshot(self):
        with mock.patch.object(views, 'stats_payload', wraps=views.stats_payload) as compute:
            client_for(self.a1).get('/cve/api/stats')
            client_for(self.b1).get('/cve/api/stats')
            client_for(self.root).get('/cve/api/stats')
            client_for(self.a1).get('/cve/api/stats?project=lc-alpha')  # a narrower request of the same user is its own scope
        self.assertEqual(compute.call_count, 4)

    def test_tenants_warm_side_by_side_and_neither_payload_holds_the_others_rows(self):
        a, b = client_for(self.a1), client_for(self.b1)
        for path in ('/cve/api/stats', '/cve/api/discovery', '/cve/api/graph-live', '/cve/api/graph', '/cve/api/activity'):
            a.get(path), b.get(path)  # warm both before reading either
        seen = {}
        for who, client in (('alpha', a), ('beta', b)):
            for path in ('/cve/api/stats', '/cve/api/discovery', '/cve/api/graph-live', '/cve/api/graph', '/cve/api/activity',
                         '/cve/api/stats?project=_all', '/cve/api/graph-live?project=_all'):
                response = client.get(path)
                self.assertEqual(response.status_code, 200, path)
                seen[(who, path)] = response.content.decode()
        other = {'alpha': 'beta', 'beta': 'alpha'}
        for (who, path), text in seen.items():
            self.assertNotIn(other[who], text.lower().replace('lcexample', ''), f'{who} {path} holds the other tenant: {text[:300]}')
        self.assertIn('www.alpha.lcexample.test', seen[('alpha', '/cve/api/graph')])
        self.assertIn('www.beta.lcexample.test', seen[('beta', '/cve/api/graph')])
        self.assertEqual(json.loads(seen[('alpha', '/cve/api/stats')])['targets'], 1)
        self.assertEqual(json.loads(seen[('beta', '/cve/api/discovery')])['counts']['hosts'], 1)

    def test_the_app_admin_sees_both_and_is_not_served_a_members_snapshot(self):
        client_for(self.a1).get('/cve/api/stats')
        self.assertEqual(client_for(self.root).get('/cve/api/stats').json()['targets'], 2)

    def test_a_revision_bump_makes_the_next_poll_recompute(self):
        client = client_for(self.a1)
        with mock.patch.object(views, 'stats_payload', wraps=views.stats_payload) as compute:
            client.get('/cve/api/stats')
            client.get('/cve/api/stats')
            self.assertEqual(compute.call_count, 1)
            views.bump_stats_revision()
            client.get('/cve/api/stats')
            self.assertEqual(compute.call_count, 2)

    def test_a_cache_that_raises_still_answers_every_polled_endpoint(self):
        broken = mock.Mock(side_effect=ConnectionError('redis is down'))
        client = client_for(self.a1)
        with mock.patch('django.core.cache.cache.get', broken), mock.patch('django.core.cache.cache.add', broken), \
                mock.patch('django.core.cache.cache.set', broken), mock.patch('django.core.cache.cache.delete', broken):
            for path in ('/cve/api/stats', '/cve/api/discovery', '/cve/api/graph-live', '/cve/api/graph', '/cve/api/activity'):
                response = client.get(path)
                self.assertEqual(response.status_code, 200, path)
        self.assertEqual(json.loads(client.get('/cve/api/stats').content)['targets'], 1)


class ConditionalGetTests(World):
    def etag_round(self, path, compute_target, client=None):
        """GET ``path`` twice with its ETag the second time; ``compute_target`` (a mock) must not run for the 304."""
        client = client or client_for(self.a1)
        first = client.get(path)
        self.assertEqual(first.status_code, 200, path)
        etag = first['ETag']
        self.assertEqual(first['Cache-Control'], 'private, no-cache', path)
        compute_target.reset_mock()
        second = client.get(path, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(second.status_code, 304, path)
        self.assertEqual(second.content, b'')
        self.assertEqual(second['ETag'], etag)
        self.assertEqual(second['Cache-Control'], 'private, no-cache')
        return first, second

    def test_stats_answers_304_without_running_the_count_walk(self):
        with mock.patch.object(views, 'stats_payload', wraps=views.stats_payload) as compute:
            self.etag_round('/cve/api/stats', compute)
        compute.assert_not_called()

    def test_stats_with_a_different_etag_gets_the_body(self):
        client = client_for(self.a1)
        client.get('/cve/api/stats')
        self.assertEqual(client.get('/cve/api/stats', HTTP_IF_NONE_MATCH='"not-it"').status_code, 200)

    def test_a_change_in_the_live_scan_counts_moves_the_stats_etag_at_once(self):
        client = client_for(self.a1)
        first = client.get('/cve/api/stats')
        ScanHistory.objects.create(domain=self.hosts['alpha'][0], scan_type=self.engine, scan_status=1, start_scan_date=timezone.now())
        with mock.patch.object(views, 'stats_payload', side_effect=AssertionError('the headline counts are still fresh')):
            second = client.get('/cve/api/stats', HTTP_IF_NONE_MATCH=first['ETag'])
        self.assertEqual(second.status_code, 200)  # the scan counts are read fresh on every poll, the headline walk is not redone
        self.assertEqual(second.json()['scans_running'], first.json()['scans_running'] + 1)

    def test_graph_live_answers_304_without_computing_and_ignores_the_clock(self):
        with mock.patch.object(graph_live, 'live', wraps=graph_live.live) as compute:
            first, _ = self.etag_round('/cve/api/graph-live', compute)
            compute.assert_not_called()
            self.assertEqual(len(first.json()['scans']), 1)
            # the snapshot expires: the clock fields differ (``at``, ``elapsed``) but nothing the scans do changed, so the ETag holds
            with mock.patch.object(snapshot_cache, '_now', return_value=time.time() + 60):
                again = client_for(self.a1).get('/cve/api/graph-live', HTTP_IF_NONE_MATCH=first['ETag'])
            self.assertEqual(compute.call_count, 1)
            self.assertEqual(again.status_code, 304)

    def test_graph_live_etag_moves_when_a_scan_starts(self):
        client = client_for(self.a1)
        first = client.get('/cve/api/graph-live')
        ScanHistory.objects.create(domain=self.hosts['alpha'][0], scan_type=self.engine, scan_status=1, start_scan_date=timezone.now())
        views.clear_stats_cache()
        self.assertEqual(client.get('/cve/api/graph-live', HTTP_IF_NONE_MATCH=first['ETag']).status_code, 200)

    def test_discovery_answers_304_without_the_counts_walk(self):
        with mock.patch.object(views, 'discovery_counts', wraps=views.discovery_counts) as compute:
            self.etag_round('/cve/api/discovery', compute)
        compute.assert_not_called()

    def test_activity_etag_leaves_out_now(self):
        client = client_for(self.a1)
        first = client.get('/cve/api/activity')
        with mock.patch.object(views.timezone, 'now', return_value=timezone.now() + timedelta(minutes=5)):
            second = client.get('/cve/api/activity', HTTP_IF_NONE_MATCH=first['ETag'])
        self.assertEqual(second.status_code, 304)
        self.assertIn('now', first.json())
        AgentActivity.objects.create(project=self.alpha, kind='scan', message='alpha-activity two', status='done')
        self.assertEqual(client.get('/cve/api/activity', HTTP_IF_NONE_MATCH=first['ETag']).status_code, 200)

    def test_the_running_scans_list_and_sentinels_live_answer_304(self):
        client = client_for(self.a1)
        for path in ('/api/v1/projects/lc-alpha/scans?status=running', '/api/v1/projects/lc-alpha/scans'):
            first = client.get(path)
            self.assertEqual(first.status_code, 200, path)
            self.assertEqual(first['Cache-Control'], 'private, no-cache')
            self.assertEqual(client.get(path, HTTP_IF_NONE_MATCH=first['ETag']).status_code, 304, path)
        started = ScanHistory.objects.create(domain=self.hosts['alpha'][0], scan_type=self.engine, scan_status=1, start_scan_date=timezone.now())
        first = client.get('/api/v1/projects/lc-alpha/scans?status=running')
        self.assertIn(started.id, [s['id'] for s in first.json()['results']])
        admin = client_for(self.root)
        live = admin.get('/api/v1/sentinels/live')
        self.assertEqual(live.status_code, 200)
        with mock.patch.object(timezone, 'now', return_value=timezone.now() + timedelta(seconds=30)):
            self.assertEqual(admin.get('/api/v1/sentinels/live', HTTP_IF_NONE_MATCH=live['ETag']).status_code, 304)  # server_time moved, nothing else

    def test_other_api_routes_send_no_etag(self):
        response = client_for(self.a1).get('/api/v1/projects/lc-alpha/hosts')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.has_header('ETag'))


class GraphVersionCacheTests(World):
    def test_the_304_path_stops_paying_for_the_aggregate_queries(self):
        client = client_for(self.a1)
        first = client.get('/cve/api/graph')
        version = first.json()['version']
        with mock.patch.object(views, 'graph_version', wraps=views.graph_version) as compute, \
                mock.patch.object(views, 'graph_payload', wraps=views.graph_payload) as payload:
            for _ in range(3):
                self.assertEqual(client.get(f'/cve/api/graph?v={version}').status_code, 304)
        compute.assert_not_called()
        payload.assert_not_called()

    def test_viewers_of_one_scope_share_the_graph_version_and_the_payload(self):
        with mock.patch.object(views, 'graph_version', wraps=views.graph_version) as compute, \
                mock.patch.object(views, 'graph_payload', wraps=views.graph_payload) as payload:
            one = client_for(self.a1).get('/cve/api/graph').json()
            two = client_for(self.a2).get('/cve/api/graph').json()
        self.assertEqual((compute.call_count, payload.call_count), (1, 1))
        self.assertEqual(one, two)

    def test_a_change_shows_after_the_ttl_or_a_revision_bump(self):
        client = client_for(self.a1)
        version = client.get('/cve/api/graph').json()['version']
        host = self.hosts['alpha'][3]
        host.ip_addresses.add(IpAddress.objects.create(address='192.0.2.99'))
        with mock.patch.object(views, 'GRAPH_VERSION_WINDOW', 10 ** 12):
            self.assertEqual(client.get(f'/cve/api/graph?v={version}').status_code, 304)  # inside the five seconds
            with mock.patch.object(snapshot_cache, '_now', return_value=time.time() + views.GRAPH_VERSION_SECONDS + 1):
                self.assertEqual(client.get(f'/cve/api/graph?v={version}').status_code, 200)  # after them
            views.bump_stats_revision()
            self.assertEqual(client.get(f'/cve/api/graph?v={version}').status_code, 200)  # or at once on a bump


# --- query ceilings ---------------------------------------------------------------------------------------------------


class QueryCeilingTests(World):
    """Pinned with the clock caches held steady. ``floor`` is what any authenticated request costs before its view runs (the session, the user, the
    memberships, the roles: 9 for a member, 5 for an App Admin), measured on /cve/api/alive, which does nothing else; what a poll adds to it is what
    this class pins."""

    def queries(self, client, path, **extra):
        with steady_caches():
            client.get(path, **extra)  # the first request of a user does its own one-off work (preferences, token use)
            with CaptureQueriesContext(connection) as ctx:
                response = client.get(path, **extra)
        return response, len(ctx)

    def floor(self, client):
        return self.queries(client, '/cve/api/alive')[1]

    def test_the_floor_is_what_it_was(self):
        self.assertEqual(self.floor(client_for(self.a1)), 9)
        self.assertEqual(self.floor(client_for(self.root)), 5)

    def test_stats_warm_poll_costs_the_floor_and_the_fresh_scan_counts(self):
        client = client_for(self.a1)
        response, n = self.queries(client, '/cve/api/stats')
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(n, self.floor(client) + 5)  # the headline walk is shared; the scan counts are read fresh (five queries)
        first = client.get('/cve/api/stats')
        _, not_modified = self.queries(client, '/cve/api/stats', HTTP_IF_NONE_MATCH=first['ETag'])
        self.assertLessEqual(not_modified, n)

    def test_stats_cold_poll_is_bounded(self):
        client = client_for(self.a1)
        with steady_caches():
            client.get('/cve/api/alive')
            views.clear_stats_cache()
            with CaptureQueriesContext(connection) as ctx:
                client.get('/cve/api/stats')
        self.assertLessEqual(len(ctx), 45, len(ctx))  # one walk (39 measured), once per scope per ten seconds, not once per tab

    def test_graph_live_warm_poll_costs_the_floor(self):
        client = client_for(self.a1)
        _, n = self.queries(client, '/cve/api/graph-live')
        self.assertLessEqual(n, self.floor(client) + 1)
        self.assertLessEqual(n, 12)

    def test_graph_304_poll_runs_no_aggregate(self):
        client = client_for(self.a1)
        version = client.get('/cve/api/graph').json()['version']
        _, n = self.queries(client, f'/cve/api/graph?v={version}')
        self.assertLessEqual(n, self.floor(client) + 1)  # was the floor + 8 aggregate queries

    def test_discovery_warm_poll(self):
        client = client_for(self.a1)
        _, n = self.queries(client, '/cve/api/discovery')
        self.assertLessEqual(n, self.floor(client) + 6)  # the scan, its events and the queue; the three walks come from the snapshot

    def add_running(self, count):
        domain = self.hosts['alpha'][0]
        for i in range(count):
            ScanHistory.objects.create(domain=domain, scan_type=self.engine, scan_status=1, start_scan_date=timezone.now() - timedelta(minutes=i))
            ScanHistory.objects.create(domain=domain, scan_type=self.engine, scan_status=-1, start_scan_date=timezone.now())

    def test_the_scan_lists_cost_the_same_with_two_rows_or_forty(self):
        client = client_for(self.a1)
        for path in ('/api/v1/projects/lc-alpha/scans?status=running&page_size=50', '/api/v1/projects/lc-alpha/scans?status=queued&page_size=50',
                     '/api/v1/projects/lc-alpha/scans?page_size=100', '/api/v1/projects/_all/scans?status=running&page_size=50'):
            ScanHistory.objects.filter(scan_status__in=(1, -1), domain__project=self.alpha).delete()
            self.add_running(2)
            few_response, few = self.queries(client, path)
            self.add_running(38)
            many_response, many = self.queries(client, path)
            self.assertEqual(few_response.status_code, 200, path)
            self.assertGreater(len(many_response.json()['results']), len(few_response.json()['results']), path)
            self.assertEqual(few, many, f'{path}: {few} queries for the few, {many} for the many')
            self.assertLessEqual(many, 22, path)

    def test_a_row_costs_no_settings_lookup(self):
        from agentapi import services
        self.add_running(10)
        with mock.patch.object(services, 'running_window', wraps=services.running_window) as window:
            response = client_for(self.a1).get('/api/v1/projects/lc-alpha/scans?page_size=100')
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(window.call_count, 2)  # once for the page (and once for the running filter), whatever the rows

    def test_stalled_still_follows_the_window(self):
        from cveFeed import counts
        domain = self.hosts['alpha'][0]
        old = ScanHistory.objects.create(domain=domain, scan_type=self.engine, scan_status=1,
                                         start_scan_date=timezone.now() - counts.running_window() - timedelta(minutes=5))
        rows = {s['id']: s for s in client_for(self.a1).get('/api/v1/projects/lc-alpha/scans?page_size=100').json()['results']}
        self.assertTrue(rows[old.id]['stalled'])
        self.assertFalse(rows[self.hosts['alpha'][2].id]['stalled'])


class SentinelOverviewTests(World):
    def test_the_viewers_projects_are_looked_up_once_per_request(self):
        with mock.patch.object(roles, 'allowed_project_ids', wraps=roles.allowed_project_ids) as lookup:
            data = sentinel_broker.live_overview(Ctx(user=self.a1))
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(data['results'], [])

    def test_an_app_admin_is_looked_up_once_too(self):
        with mock.patch.object(roles, 'allowed_project_ids', wraps=roles.allowed_project_ids) as lookup:
            sentinel_broker.live_overview(Ctx(user=self.root))
        self.assertEqual(lookup.call_count, 1)
