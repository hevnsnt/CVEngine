"""Stage 1 of the live-screen caching plan: the refresher keeps the hot scopes warm, a poll is served from the cache, and the per-user cache of the
projects a user may see never lets one scope read another's numbers.

Nothing here sleeps or waits on the wall clock. The snapshots' clock (``snapshot_cache._now``) and the bookkeeping clock around them (hot scopes,
the refresher's heartbeat, the counters: ``_clock``) are one fake clock a test moves by hand; the entries' real expiry in Redis (tens of seconds)
is far longer than a test runs."""
import contextlib
import json
import os
import threading
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import SimpleTestCase
from django.test.utils import CaptureQueriesContext

from agentapi import system_status
from cveFeed import graph_live, live_refresh, snapshot_cache, views
from cveFeed.models import CVEMatch
from dashboard.models import Org, OrgMembership, ProjectMembership
from reNgine import livecache_config
from startScan.models import Subdomain
from tenancy import membership_cache, roles, scope
from tests.test_live_cache import World, steady_caches
from tests.test_tenancy import client_for

REAL_BACKLOG = live_refresh.backlog  # before any test patches it
START = 1_000_000.0
STATS, DISCOVERY, GRAPH, GRAPH_LIVE = '/cve/api/stats', '/cve/api/discovery', '/cve/api/graph', '/cve/api/graph-live'
POLLS = (STATS, DISCOVERY, GRAPH, GRAPH_LIVE)
# the tables the headline, ticker, graph and graph-live walks read: a poll that touches none of them did no heavy work
HEAVY = ('cveFeed_cveentry', 'cveFeed_cvematch', 'startScan_subdomain', 'startScan_vulnerability', 'cveFeed_tlscertificate',
         'cveFeed_hygienefinding', 'startScan_ipaddress', 'startScan_port', 'startScan_scanactivity')


class Clock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Fresh(World):
    """The two tenants of the stage 0 tests, a fake clock, and nothing hot, cached or registered when each test starts."""

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        for name in ('_now', '_clock'):
            patch = mock.patch.object(snapshot_cache, name, self.clock)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(membership_cache, 'CACHE_IN_TRANSACTION', True)  # a test case is one open transaction: these tests are about the cache
        patch.start()
        self.addCleanup(patch.stop)
        # The refresher skips a run when the broker's classic queues are backlogged, and the broker is the real Redis the other tests (a bulk
        # certificate transparency add, say) publish to: a test of the refresher must not depend on what they left behind. The probe itself is tested
        # below with a fake broker.
        patch = mock.patch.object(live_refresh, 'backlog', return_value=(0, 0))
        patch.start()
        self.addCleanup(patch.stop)
        cache.clear()  # this run's Redis database: no snapshot, counter or registration of an earlier test is anywhere
        membership_cache.bump_epoch()
        self.addCleanup(snapshot_cache.reset_hot)

    def scope_of(self, ids, *params):
        tokens = scope.set_scope(ids, None)
        try:
            return snapshot_cache.scope_hash(*params)
        finally:
            scope.reset_scope(tokens)

    def entry(self, name, ids, *params):
        return cache.get(f'cve:snap:{name}:{self.scope_of(ids, *params)}')

    def heavy(self, ctx):
        return [q['sql'][:120] for q in ctx.captured_queries if any(table in q['sql'] for table in HEAVY)]


class Counting(contextlib.ExitStack):
    """Wraps the computations a poll can run, so a test can say how often each ran."""

    def __init__(self):
        super().__init__()
        self.mocks = {}

    def __enter__(self):
        super().__enter__()
        for name, owner, attr in (('stats', views, 'stats_payload'), ('discovery', views, 'discovery_counts'), ('version', views, 'graph_version'),
                                  ('graph', views, 'graph_payload'), ('live', graph_live, 'live')):
            self.mocks[name] = self.enter_context(mock.patch.object(owner, attr, wraps=getattr(owner, attr)))
        return self

    def calls(self):
        return {name: m.call_count for name, m in self.mocks.items()}


# --- (a) a warm cache means no heavy query in a request --------------------------------------------------------------------


class WarmCacheTests(Fresh):
    def warm(self, client):
        """The first poll of each endpoint (computed by the request, which registers the scope as hot), then one refresher run that finds them due."""
        for path in POLLS:
            self.assertEqual(client.get(path).status_code, 200, path)
        self.clock.advance(6)
        summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['errors'], summary['dropped']), (0, 0), summary)
        return summary

    def test_a_poll_after_the_refresher_ran_runs_no_heavy_query_and_computes_nothing(self):
        client = client_for(self.a1)
        with steady_caches():
            summary = self.warm(client)
            self.assertEqual(summary['hot'], 4)
            self.assertGreaterEqual(summary['refreshed'], 3)  # the headline and ticker walks were 6 s old: due within the 5 s interval
            self.clock.advance(11)  # past every freshness window (the longest is ten seconds): without the refresher each poll would compute
            with Counting() as computed, CaptureQueriesContext(connection) as ctx:
                bodies = {path: client.get(path) for path in POLLS}
        self.assertEqual({p: r.status_code for p, r in bodies.items()}, dict.fromkeys(POLLS, 200))
        self.assertEqual(computed.calls(), dict.fromkeys(computed.mocks, 0))
        self.assertEqual(self.heavy(ctx), [])
        self.assertEqual(bodies[STATS].json()['targets'], 1)

    def test_a_second_viewer_of_the_same_projects_is_served_the_same_warm_entries(self):
        with steady_caches():
            self.warm(client_for(self.a1))
            self.clock.advance(11)
            with Counting() as computed, CaptureQueriesContext(connection) as ctx:
                bodies = [client_for(self.a2).get(path) for path in POLLS]
        self.assertEqual([r.status_code for r in bodies], [200] * 4)
        self.assertEqual(computed.calls(), dict.fromkeys(computed.mocks, 0))
        self.assertEqual(self.heavy(ctx), [])

    def test_a_graph_whose_version_moved_is_built_by_the_refresher_not_by_the_viewers(self):
        client = client_for(self.a1)
        with steady_caches():
            version = client.get(GRAPH).json()['version']
            host = self.hosts['alpha'][3]
            Subdomain.objects.create(name='new.alpha.lcexample.test', target_domain=host.target_domain, scan_history=host.scan_history, http_status=200)
            self.clock.advance(6)  # the version snapshot is five seconds old
            with Counting() as built:
                live_refresh.refresh_hot_scopes()
            self.assertEqual(built.calls()['graph'], 1, 'the refresher builds the new payload once')
            with Counting() as computed, CaptureQueriesContext(connection) as ctx:
                response = client.get(f'{GRAPH}?v={version}')
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json()['version'], version)
        self.assertIn('new.alpha.lcexample.test', response.content.decode())
        self.assertEqual(computed.calls()['graph'], 0)
        self.assertEqual(self.heavy(ctx), [])

    def test_with_the_refresher_off_every_poll_computes_as_before(self):
        client = client_for(self.a1)
        with mock.patch.dict(os.environ, {'CVENGINE_LIVE_REFRESH': '0'}):
            client.get(STATS)
            self.assertEqual(snapshot_cache.hot_recipes(), [])  # nothing is registered
            self.assertEqual(live_refresh.refresh_hot_scopes(), {'enabled': False})
            self.clock.advance(11)
            with Counting() as computed:
                client.get(STATS)
        self.assertEqual(computed.calls()['stats'], 1)

    def test_a_refresher_that_stopped_is_not_trusted_to_keep_the_cache_warm(self):
        client = client_for(self.a1)
        self.warm(client)
        self.clock.advance(11)
        with Counting() as alive:
            client.get(STATS)
        self.assertEqual(alive.calls()['stats'], 0)  # its last heartbeat is 11 s old: it is on its way
        self.clock.advance(60)  # no heartbeat for over four intervals, and the entry is older than it is kept for the refresher's sake
        with Counting() as dead:
            client.get(STATS)
        self.assertEqual(dead.calls()['stats'], 1)

    def test_a_revision_bump_is_not_left_to_the_refresher(self):
        client = client_for(self.a1)
        self.warm(client)
        views.bump_stats_revision()  # a finding was closed: the person who closed it must see it now
        with Counting() as computed:
            client.get(STATS)
        self.assertEqual(computed.calls()['stats'], 1)


# --- (b) the refresher repopulates only hot scopes ---------------------------------------------------------------------------


class HotScopeTests(Fresh):
    def test_only_the_scopes_asked_for_lately_are_recomputed(self):
        alpha, root = client_for(self.a1), client_for(self.root)
        alpha.get(STATS)  # hot from START
        self.clock.advance(50)
        root.get(STATS)  # hot from START + 50
        alpha_at = self.entry('stats', {self.alpha.id}, '', '')['at']
        self.clock.advance(20)  # alpha's minute is over, root's is not
        self.assertEqual(len(snapshot_cache.hot_recipes()), 1)
        with Counting() as computed:
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['hot'], summary['refreshed']), (1, 1))
        self.assertEqual(computed.calls()['stats'], 1)
        self.assertEqual(self.entry('stats', {self.alpha.id}, '', '')['at'], alpha_at, 'the scope nobody asks for any more is left alone')
        self.assertEqual(self.entry('stats', None, '', '')['at'], START + 70)
        self.assertIsNone(self.entry('stats', {self.beta.id}, '', ''), 'a scope nobody asked for is never computed in advance')

    def test_a_scope_that_is_still_fresh_is_not_recomputed(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(1)
        with Counting() as computed:
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['fresh'], summary['refreshed']), (1, 0))
        self.assertEqual(computed.calls()['stats'], 0)

    def test_polls_register_a_scope_once_per_process_and_third_of_the_window(self):
        client = client_for(self.a1)
        client.get(STATS)
        with mock.patch.object(snapshot_cache.cache, 'set', wraps=snapshot_cache.cache.set) as writes:
            client.get(STATS)
            client.get(STATS)
        self.assertNotIn(snapshot_cache.HOT_KEY, [c.args[0] for c in writes.call_args_list], 'a poll writes no registration while one is recent')
        self.clock.advance(21)
        client.get(STATS)  # past a third of the minute: registered again, so the scope stays hot while it is polled
        self.clock.advance(50)
        self.assertEqual(len(snapshot_cache.hot_recipes()), 1)

    def test_the_hot_list_is_bounded(self):
        with mock.patch.object(snapshot_cache, 'MAX_HOT', 2):
            for project in ('p1', 'p2', 'p3'):
                tokens = scope.set_scope({self.alpha.id}, None)
                try:
                    snapshot_cache.mark_hot('stats', f'scope-{project}', {'params': (project,), 'args': {}})
                finally:
                    scope.reset_scope(tokens)
        self.assertEqual(len(snapshot_cache.hot_recipes()), 2)

    def test_one_scope_that_fails_does_not_stop_the_others(self):
        client_for(self.a1).get(STATS)
        client_for(self.b1).get(STATS)
        self.clock.advance(11)
        real = views.stats_payload
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('boom')
            return real()
        with mock.patch.object(views, 'stats_payload', flaky), self.assertLogs('cveFeed.live_refresh', 'ERROR'):
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['errors'], summary['refreshed']), (1, 1))
        self.assertFalse(cache.get(f'cve:snap:stats:{self.scope_of({self.alpha.id}, "", "")}:lock'), 'a failed run releases its lock')

    def test_a_run_that_overlaps_another_does_nothing(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(11)
        cache.add('cve:snap:refresher:lock', 1, 30)
        try:
            with Counting() as computed:
                summary = live_refresh.refresh_hot_scopes()
        finally:
            cache.delete('cve:snap:refresher:lock')
        self.assertIn('skipped', summary)
        self.assertEqual(computed.calls()['stats'], 0)

    def test_the_run_stops_at_its_time_budget_and_says_so(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(11)
        summary = live_refresh.refresh_hot_scopes(budget=-1)
        self.assertEqual((summary['refreshed'], summary['out_of_time']), (0, 1))


# --- (c) scope isolation ----------------------------------------------------------------------------------------------------


class IsolationTests(Fresh):
    def test_users_with_different_projects_read_only_their_own_numbers_before_and_after_the_refresher(self):
        both = User.objects.create_user('lc-both', password='x')
        for project in (self.alpha, self.beta):
            ProjectMembership.objects.create(user=both, project=project, role='user')
        clients = {'alpha': client_for(self.a1), 'beta': client_for(self.b1), 'both': client_for(both), 'root': client_for(self.root)}
        expect = {'alpha': 1, 'beta': 1, 'both': 2, 'root': 2}
        for phase in ('computed by the requests', 'served from the refresher'):
            seen = {}
            for who, client in clients.items():
                for path in POLLS + ('/cve/api/stats?project=_all',):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200, (phase, who, path))
                    seen[(who, path)] = response.content.decode()
                self.assertEqual(json.loads(seen[(who, STATS)])['targets'], expect[who], (phase, who))
                self.assertEqual(json.loads(seen[(who, DISCOVERY)])['counts']['hosts'], expect[who], (phase, who))
            for who, other in (('alpha', 'beta'), ('beta', 'alpha')):
                for path in POLLS:
                    self.assertNotIn(other, seen[(who, path)].lower().replace('lcexample', ''), (phase, who, path))
            self.assertIn('www.alpha.lcexample.test', seen[('both', GRAPH)])
            self.assertIn('www.beta.lcexample.test', seen[('both', GRAPH)])
            self.clock.advance(6)
            live_refresh.refresh_hot_scopes()
            self.clock.advance(11)
        keys = {self.scope_of({self.alpha.id}, '', ''), self.scope_of({self.beta.id}, '', ''), self.scope_of({self.alpha.id, self.beta.id}, '', ''),
                self.scope_of(None, '', '')}
        self.assertEqual(len(keys), 4)
        for ids, targets in (({self.alpha.id}, 1), ({self.beta.id}, 1), ({self.alpha.id, self.beta.id}, 2), (None, 2)):
            entry = self.entry('stats', ids, '', '')
            self.assertEqual((entry['by'], entry['payload']['targets']), ('refresher', targets))

    def test_a_recipe_whose_key_no_longer_matches_its_projects_is_dropped_not_stored(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(11)
        alpha_key = self.scope_of({self.alpha.id}, '', '')
        index = cache.get(snapshot_cache.HOT_KEY)
        recipe = index[f'stats:{alpha_key}']
        index[f'stats:{alpha_key}'] = {**recipe, 'allowed': [self.beta.id]}  # beta's projects under alpha's key
        cache.set(snapshot_cache.HOT_KEY, index, 300)
        before = cache.get(f'cve:snap:stats:{alpha_key}')['payload']
        with Counting() as computed:
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['dropped'], summary['refreshed']), (1, 0))
        self.assertEqual(computed.calls()['stats'], 0)
        self.assertEqual(cache.get(f'cve:snap:stats:{alpha_key}')['payload'], before)

    def test_an_app_admins_recipe_is_dropped_when_a_project_was_created_since(self):
        client_for(self.root).get(STATS)
        self.clock.advance(11)
        from dashboard.models import Project
        from django.utils import timezone
        Project.objects.create(name='Gamma', slug='lc-gamma', insert_date=timezone.now(), org=self.org_a)  # the all-projects hash moved
        summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['dropped'], summary['refreshed']), (1, 0))
        self.assertEqual(client_for(self.root).get(STATS).json()['targets'], 2)  # and the next poll registers and computes under the new key

    def test_the_refresher_runs_each_scope_under_its_own_projects_and_leaves_no_scope_behind(self):
        seen = []
        real = views.stats_payload

        def spy():
            seen.append(scope.current_allowed())
            return real()
        client_for(self.a1).get(STATS)
        client_for(self.root).get(STATS)
        self.clock.advance(11)
        seen.clear()
        with mock.patch.object(views, 'stats_payload', spy):
            live_refresh.refresh_hot_scopes()
        self.assertEqual(sorted(map(str, seen)), sorted([str({self.alpha.id}), 'None']))
        self.assertIsNone(scope.current_allowed())
        self.assertIsNone(scope.current_user())


# --- the per-user cache of the projects a user may see ---------------------------------------------------------------------


class MembershipCacheTests(Fresh):
    def test_the_polls_look_a_users_projects_up_once_and_everything_else_every_time(self):
        client = client_for(self.a1)
        with mock.patch.object(roles, 'allowed_project_ids', wraps=roles.allowed_project_ids) as lookup:
            client.get(STATS)
            client.get(STATS)
            client.get(GRAPH_LIVE)
            self.assertEqual(lookup.call_count, 1)
            client.get('/cve/api/alive')
            client.get('/cve/api/alive')
            self.assertEqual(lookup.call_count, 3, 'a request that is not a Live poll always reads them fresh')
            client.post(STATS)
            self.assertEqual(lookup.call_count, 4, 'and so does a request that is not a GET')

    def test_an_app_admin_is_never_cached(self):
        with mock.patch.object(roles, 'allowed_project_ids', wraps=roles.allowed_project_ids) as lookup:
            client_for(self.root).get(STATS)
            client_for(self.root).get(STATS)
        self.assertEqual(lookup.call_count, 0)  # (the answer for a superuser is None, with no lookup at all)

    def test_a_cached_poll_costs_the_queries_of_the_lookup_less(self):
        client = client_for(self.a1)
        with steady_caches():
            client.get(STATS)
            with CaptureQueriesContext(connection) as cached:
                client.get(STATS)
            with mock.patch.dict(os.environ, {'CVENGINE_AUTH_CACHE_SECONDS': '0'}), CaptureQueriesContext(connection) as fresh:
                client.get(STATS)
        self.assertEqual(len(fresh) - len(cached), 2, 'the project memberships and the organization memberships (a third query reads the organizations\' projects)')

    def test_removing_a_membership_takes_effect_on_the_next_poll(self):
        client = client_for(self.a1)
        self.assertEqual(client.get(STATS).json()['targets'], 1)
        self.assertEqual(client.get(STATS).json()['targets'], 1)  # cached now
        ProjectMembership.objects.filter(user=self.a1, project=self.alpha).delete()
        for path in (STATS, DISCOVERY, GRAPH, GRAPH_LIVE):
            response = client.get(path)
            self.assertIn(response.status_code, (403, 404), path)  # no role anywhere: refused, and nothing of alpha's is in the answer
            self.assertNotIn('alpha', response.content.decode().lower())

    def test_removing_one_of_two_memberships_narrows_the_next_poll_at_once(self):
        both = User.objects.create_user('lc-two', password='x')
        for project in (self.alpha, self.beta):
            ProjectMembership.objects.create(user=both, project=project, role='user')
        client = client_for(both)
        self.assertEqual(client.get(STATS).json()['targets'], 2)
        self.assertEqual(client.get(STATS).json()['targets'], 2)  # the cached set of two
        ProjectMembership.objects.filter(user=both, project=self.beta).delete()
        self.assertEqual(client.get(STATS).json()['targets'], 1)
        body = client.get(GRAPH).content.decode()
        self.assertIn('www.alpha.lcexample.test', body)
        self.assertNotIn('beta', body.lower().replace('lcexample', ''))
        self.assertEqual(client.get(DISCOVERY).json()['counts']['hosts'], 1)

    def test_adding_a_membership_takes_effect_on_the_next_poll_too(self):
        client = client_for(self.a1)
        self.assertEqual(client.get(STATS).json()['targets'], 1)
        ProjectMembership.objects.create(user=self.a1, project=self.beta, role='user')
        self.assertEqual(client.get(STATS).json()['targets'], 2)

    def test_leaving_an_organization_or_moving_its_project_takes_effect_on_the_next_poll(self):
        member = User.objects.create_user('lc-org', password='x')
        OrgMembership.objects.create(user=member, org=self.org_a, role='user')
        client = client_for(member)
        self.assertEqual(client.get(STATS).json()['targets'], 1)
        self.alpha.org = self.org_b  # moved to the other organization: the member's organization no longer holds it
        self.alpha.save()
        self.assertEqual(client.get(STATS).json()['targets'], 0)
        OrgMembership.objects.filter(user=member).delete()
        OrgMembership.objects.create(user=member, org=self.org_b, role='user')
        self.assertEqual(client.get(STATS).json()['targets'], 2)  # alpha and beta are both organization B's now
        self.org_b.delete()
        self.assertIn(client.get(STATS).status_code, (403, 404))

    def test_a_change_that_bypasses_the_signals_is_seen_within_the_ttl_and_the_ttl_is_short(self):
        client = client_for(self.a1)
        writes = []
        real_set = cache.set

        def spy(key, value, timeout=None, *a, **k):
            writes.append((key, timeout))
            return real_set(key, value, timeout, *a, **k)
        with mock.patch.object(membership_cache.cache, 'set', spy):
            self.assertEqual(client.get(STATS).json()['targets'], 1)
        ttl = [t for k, t in writes if k.startswith('cve:tenancy:allowed:')]
        self.assertEqual(ttl, [livecache_config.auth_cache_seconds()])
        self.assertLessEqual(ttl[0], 30)
        ProjectMembership.objects.filter(user=self.a1).update(project=self.beta)  # a bulk update fires no signal
        self.assertEqual(client.get(STATS).json()['targets'], 1, 'inside the TTL the cached set (alpha) still stands')
        cache.delete(membership_cache._key(self.a1))  # the TTL runs out
        self.assertEqual(client.get(STATS).json()['targets'], 1)
        self.assertEqual(client.get(DISCOVERY).json()['counts']['hosts'], 1)
        self.assertIn('www.beta.lcexample.test', client.get(GRAPH).content.decode())

    def test_the_ttl_is_clamped_and_zero_turns_the_cache_off(self):
        for raw, expect in (('999', 30), ('-4', 0), ('junk', 15), ('', 15), ('0', 0), ('7', 7)):
            self.assertEqual(livecache_config.auth_cache_seconds({'CVENGINE_AUTH_CACHE_SECONDS': raw}), expect, raw)
        client = client_for(self.a1)
        with mock.patch.dict(os.environ, {'CVENGINE_AUTH_CACHE_SECONDS': '0'}), \
                mock.patch.object(roles, 'allowed_project_ids', wraps=roles.allowed_project_ids) as lookup:
            client.get(STATS)
            client.get(STATS)
        self.assertEqual(lookup.call_count, 2)

    def test_a_recreated_user_with_the_same_id_never_reads_the_old_ones_projects(self):
        user = User.objects.create_user('lc-twin', password='x')
        ProjectMembership.objects.create(user=user, project=self.alpha, role='user')
        self.assertEqual(client_for(user).get(STATS).json()['targets'], 1)
        key_before = membership_cache._key(user)
        twin = User(pk=user.pk, username='lc-twin2', date_joined=user.date_joined.replace(year=user.date_joined.year - 1))
        self.assertNotEqual(membership_cache._key(twin), key_before)

    def test_a_cache_that_is_down_means_a_fresh_lookup(self):
        class Down:
            def get_many(self, *a, **k):
                raise ConnectionError('down')

            def set(self, *a, **k):
                raise ConnectionError('down')
        with mock.patch.object(membership_cache, 'cache', Down()):
            self.assertEqual(client_for(self.a1).get(STATS).json()['targets'], 1)

    def test_the_cached_set_is_a_copy_the_request_may_extend(self):
        request = mock.Mock(method='GET', path=STATS)
        first = membership_cache.allowed_for_request(request, self.a1)
        first.add(10 ** 9)  # scope.allow() does this for the project the caller just created
        self.assertNotIn(10 ** 9, membership_cache.allowed_for_request(request, self.a1))


# --- (e) a cold cache falls back to the single flight compute -------------------------------------------------------------


class ColdCacheTests(Fresh):
    def test_a_cold_poll_computes_once_and_the_next_is_served(self):
        client = client_for(self.a1)
        with Counting() as computed:
            first, second = client.get(STATS), client.get(STATS)
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(computed.calls()['stats'], 1)
        polls = snapshot_cache.metrics()['this_hour']
        self.assertEqual((polls['miss'], polls['hit']), (1, 1))

    def test_a_cold_poll_computes_even_while_the_refresher_is_alive(self):
        snapshot_cache.beat({'state': 'idle'})  # alive, but it has not met this scope yet
        with Counting() as computed:
            response = client_for(self.a1).get(STATS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(computed.calls()['stats'], 1)

    def test_concurrent_polls_of_a_cold_scope_compute_once(self):
        key = f'unit-{threading.get_ident()}'
        self.addCleanup(lambda: cache.delete_many([f'cve:snap:{key}:s', f'cve:snap:{key}:s:lock']))
        snapshot_cache.beat({'state': 'idle'})  # a refresher is alive and has nothing for this scope: still one request computes, the rest wait for it
        started, release, calls, results = threading.Event(), threading.Event(), [], []

        def slow():
            calls.append(1)
            started.set()
            release.wait(10)
            return {'n': len(calls)}

        def poll(compute):
            results.append(snapshot_cache.snapshot(key, 's', compute, 60)['payload'])
        wait = mock.patch.object(snapshot_cache, 'WAIT_SECONDS', 60)  # a loaded machine may start a loser late: it must wait for the winner, not give up
        wait.start()
        self.addCleanup(wait.stop)
        winner = threading.Thread(target=poll, args=(slow,))
        winner.start()
        self.assertTrue(started.wait(10))
        losers = [threading.Thread(target=poll, args=(mock.Mock(side_effect=AssertionError('a loser computed')),)) for _ in range(4)]
        [t.start() for t in losers]
        release.set()
        [t.join(60) for t in [winner, *losers]]
        self.assertEqual(calls, [1])
        self.assertEqual(results, [{'n': 1}] * 5)

    def test_a_poll_that_wins_the_lock_just_after_another_stored_the_entry_serves_it_and_computes_nothing(self):
        """The race behind a CI flake of the test above: a poll reads the key (nothing there), the winner then stores its entry and lets go of the
        lock, and only then does the poll try for the lock and win it. It must read the key again, not compute a second time."""
        key = f'unit-race-{threading.get_ident()}'
        entry_key = f'cve:snap:{key}:s'
        self.addCleanup(lambda: cache.delete_many([entry_key, f'{entry_key}:lock']))
        real_add = cache.add

        def add_after_the_winner_finished(name, value, timeout=None, **kw):
            cache.set(entry_key, {'payload': {'n': 1}, 'etag': 'e', 'at': snapshot_cache._now(), 'rev': snapshot_cache.revision(), 'by': 'request'}, 60)
            return real_add(name, value, timeout, **kw)  # the winner has let go of the lock: this one is granted
        compute = mock.Mock(side_effect=AssertionError('a second computation'))
        with mock.patch.object(cache, 'add', add_after_the_winner_finished):
            got = snapshot_cache.snapshot(key, 's', compute, 60)
        self.assertEqual(got['payload'], {'n': 1})
        compute.assert_not_called()
        self.assertIsNone(cache.get(f'{entry_key}:lock'))  # and the lock it won is let go of

    def test_a_cache_that_raises_still_answers_with_the_refresher_registered_and_counted(self):
        broken = mock.Mock(side_effect=ConnectionError('redis is down'))
        client = client_for(self.a1)
        with mock.patch('django.core.cache.cache.get', broken), mock.patch('django.core.cache.cache.add', broken), \
                mock.patch('django.core.cache.cache.set', broken), mock.patch('django.core.cache.cache.delete', broken), \
                mock.patch('django.core.cache.cache.get_many', broken), mock.patch('django.core.cache.cache.incr', broken):
            for path in POLLS:
                self.assertEqual(client.get(path).status_code, 200, path)
            self.assertEqual(live_refresh.refresh_hot_scopes()['enabled'], True)  # nor does the refresher raise


# --- metrics, the schedule, the lane ---------------------------------------------------------------------------------------


class MetricsTests(Fresh):
    def test_hits_stale_answers_misses_and_refreshes_are_counted_and_reach_the_status(self):
        client = client_for(self.a1)
        client.get(STATS)  # miss
        client.get(STATS)  # hit
        self.clock.advance(6)
        live_refresh.refresh_hot_scopes()  # refreshed
        self.clock.advance(11)
        client.get(STATS)  # stale: the refresher keeps it
        polls = snapshot_cache.metrics()['this_hour']
        self.assertEqual((polls['miss'], polls['hit'], polls['stale'], polls['refreshed']), (1, 1, 1, 1))
        self.assertEqual(polls['served_from_cache_percent'], round(100 * 2 / 3, 1))
        self.assertEqual(polls['by_snapshot']['stats'], {'miss': 1, 'hit': 1, 'stale': 1, 'refreshed': 1})
        self.assertEqual(snapshot_cache.metrics()['previous_hour']['hit'], 0)
        notes = []
        status = system_status._live_cache(notes)
        self.assertEqual((status['refresher'], status['interval_seconds'], status['hot_scopes']), ('running', 5, 1))
        self.assertEqual(status['polls']['this_hour']['hit'], 1)
        self.assertEqual(status['last_run']['errors'], 0)
        self.assertEqual(notes, [])

    def test_the_hour_rolls_into_the_previous_one(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(3600)
        metrics = snapshot_cache.metrics()
        self.assertEqual((metrics['this_hour']['miss'], metrics['previous_hour']['miss']), (0, 1))

    def test_a_silent_refresher_with_people_on_the_screen_is_a_note_and_off_is_not(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(3600)
        notes = []
        self.assertEqual(system_status._live_cache(notes)['refresher'], 'silent')
        self.assertEqual(len(notes), 0, 'the hot scope has expired: nobody is on the screen')
        client_for(self.a1).get(STATS)
        self.clock.advance(30)
        system_status._live_cache(notes)
        self.assertEqual(len(notes), 1)
        notes.clear()
        with mock.patch.dict(os.environ, {'CVENGINE_LIVE_REFRESH': 'off'}):
            self.assertEqual(system_status._live_cache(notes)['refresher'], 'off')
        self.assertEqual(notes, [])

    def test_an_app_admin_sees_it_in_the_system_status_and_a_member_does_not(self):
        from tests.test_system_status import patched
        from agentapi.services import Ctx
        a, b, c = patched()
        with a, b, c:
            admin = system_status.system_status(Ctx(user=self.root))
            member = system_status.system_status(Ctx(user=self.a1))
        self.assertIn('polls', admin['system']['live_cache'])
        self.assertIsNone(member['system'])
        self.assertIn('live_cache_queue', admin['system']['queues']['waiting'])


class ScheduleAndLaneTests(SimpleTestCase):
    def test_the_environment_sets_the_cadence_the_kill_switch_and_the_hot_window(self):
        env = livecache_config
        self.assertEqual(env.refresh_seconds({}), 5)
        for raw, expect in (('1', 2), ('3', 3), ('90', 60), ('x', 5), ('', 5)):
            self.assertEqual(env.refresh_seconds({'CVENGINE_LIVE_REFRESH_SECONDS': raw}), expect, raw)
        for raw, expect in (('0', False), ('false', False), ('No', False), ('off', False), ('1', True), ('', True), ('on', True)):
            self.assertEqual(env.refresh_enabled({'CVENGINE_LIVE_REFRESH': raw}), expect, raw)
        self.assertEqual((env.hot_seconds({}), env.hot_seconds({'CVENGINE_LIVE_HOT_SECONDS': '5'}), env.hot_seconds({'CVENGINE_LIVE_HOT_SECONDS': '9000'})),
                         (60, 15, 600))
        entry = env.beat_entry({'CVENGINE_LIVE_REFRESH_SECONDS': '8', 'CVENGINE_LIVE_REFRESH': '0'})
        self.assertEqual((entry['task'], entry['schedule'].run_every.total_seconds(), entry['enabled']), ('refresh_live_snapshots', 8.0, False))
        self.assertEqual(entry['options'], {'queue': 'live_cache_queue', 'expire_seconds': 24})

    def test_beat_writes_the_entry_to_its_table_with_the_queue_and_the_interval(self):
        from django.conf import settings
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['cvengine-live-refresh']['task'], 'refresh_live_snapshots')
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['cvengine-live-refresh']['options']['queue'], 'live_cache_queue')

    def test_the_task_has_a_queue_that_no_scan_feed_or_validation_worker_consumes_and_runs_while_scanning_is_paused(self):
        from cveFeed import tasks
        from cveFeed.scan_control import PAUSE_EXEMPT_TASKS
        from reNgine import time_limits
        self.assertEqual(tasks.refresh_live_snapshots.queue, 'live_cache_queue')
        self.assertIn('refresh_live_snapshots', PAUSE_EXEMPT_TASKS)
        self.assertIn('live_cache_queue', system_status.QUEUES)
        self.assertEqual(time_limits.limits_for('live_cache_queue')[1], 600)
        from tests.test_entrypoint import worker_commands
        consumers = [cmd for cmd in worker_commands() if 'live_cache_queue' in cmd]
        self.assertEqual(len(consumers), 1, 'one worker consumes it')
        self.assertNotIn('scan', consumers[0].split('-Q ')[1].split()[0].replace('wpscan', '').replace('bucketscan', ''), 'not a scan worker')
        for scan_worker in ('discovery_queue', 'cve_feed_queue', 'validation_priority_queue'):
            self.assertNotIn(scan_worker, consumers[0], 'a worker whose slots scan, feed or validation work holds for hours')


class BeatTableTests(Fresh):
    def test_beat_writes_the_row_from_the_environment_and_a_switched_off_one_is_disabled(self):
        """What ``DatabaseScheduler.update_from_dict`` does with each ``CELERY_BEAT_SCHEDULE`` entry when beat starts."""
        from django_celery_beat.models import PeriodicTask
        from django_celery_beat.schedulers import ModelEntry
        from reNgine.celery import app
        for environ, enabled, seconds in (({}, True, 5), ({'CVENGINE_LIVE_REFRESH_SECONDS': '9', 'CVENGINE_LIVE_REFRESH': '0'}, False, 9)):
            ModelEntry.from_entry('cvengine-live-refresh', app=app, **livecache_config.beat_entry(environ))
            row = PeriodicTask.objects.get(name='cvengine-live-refresh')
            self.assertEqual((row.task, row.queue, row.enabled, row.expire_seconds), ('refresh_live_snapshots', 'live_cache_queue', enabled, seconds * 3))
            self.assertEqual((row.interval.every, row.interval.period), (seconds, 'seconds'))


# --- review fixes: made-up scopes, graph payload lifetime, a small polite refresher, the run lock, the commit-time bump ---------------


class MadeUpScopeTests(Fresh):
    def register(self, user, name, scope_id, ids):
        tokens = scope.set_scope(set(ids), user)
        try:
            snapshot_cache.mark_hot(name, scope_id, {'params': (scope_id,), 'args': {}})
        finally:
            scope.reset_scope(tokens)

    def test_an_organization_that_narrows_nothing_is_not_a_scope(self):
        client = client_for(self.a1)
        client.get(STATS)
        client.get(GRAPH_LIVE)
        plain = len(snapshot_cache.hot_recipes())
        for i in range(30):
            for path in (STATS, GRAPH_LIVE, DISCOVERY):
                self.assertEqual(client.get(f'{path}?org=junk{i}').status_code, 200)
            self.assertEqual(client.get(f'{STATS}?project=_all&org=other-{i}').status_code, 200)
        self.assertEqual(len(snapshot_cache.hot_recipes()), plain + 2, 'the discovery ticker and the _all spelling of stats: no scope per made-up organization')
        self.assertEqual(client.get(f'{STATS}?org=org-b').json()['targets'], 1, 'an organization of another tenant still shows the caller only their own')
        self.assertEqual(len(snapshot_cache.hot_recipes()), plain + 2)
        client.get(f'{STATS}?project=lc-alpha&org=junk')  # a named project ignores the organization
        self.assertEqual(len([r for r in snapshot_cache.hot_recipes() if r['name'] == 'stats']), 3)  # plain, _all and the named project: none per organization

    def test_a_real_organization_that_narrows_is_still_its_own_scope(self):
        root = client_for(self.root)
        root.get(STATS)
        root.get(f'{STATS}?org=org-a')
        root.get(f'{STATS}?org=org-b')
        self.assertEqual(len(snapshot_cache.hot_recipes()), 3)
        self.assertEqual(root.get(f'{STATS}?org=org-a').json()['targets'], 1)

    def test_a_domain_or_scan_that_is_not_the_callers_is_answered_but_never_refreshed(self):
        client = client_for(self.a1)
        mine, theirs = self.hosts['alpha'], self.hosts['beta']
        for i in range(30):
            self.assertEqual(client.get(f'{GRAPH_LIVE}?domain={10 ** 6 + i}').status_code, 200)
            self.assertEqual(client.get(f'{GRAPH}?scan={10 ** 6 + i}').status_code, 200)
        self.assertEqual(client.get(f'{GRAPH_LIVE}?domain={theirs[0].id}').status_code, 200)
        self.assertEqual(client.get(f'{GRAPH}?scan={theirs[1].id}').status_code, 200)
        self.assertEqual(client.get(f'{GRAPH}?domain={10 ** 40}').status_code, 200)
        self.assertEqual(snapshot_cache.hot_recipes(), [])
        client.get(f'{GRAPH_LIVE}?domain={mine[0].id}')
        client.get(f'{GRAPH}?scan={mine[1].id}')
        self.assertEqual(sorted(r['name'] for r in snapshot_cache.hot_recipes()), ['graph-live', 'graph-version'])

    def test_one_user_holds_at_most_a_share_of_the_registry_and_others_still_register(self):
        for i in range(snapshot_cache.MAX_HOT_PER_USER + 20):
            self.register(self.a1, 'stats', f'scope-{i}', {self.alpha.id})
        mine = snapshot_cache.hot_recipes()
        self.assertEqual(len(mine), snapshot_cache.MAX_HOT_PER_USER)
        self.assertEqual({r['scope'] for r in mine}, {f'scope-{i}' for i in range(snapshot_cache.MAX_HOT_PER_USER)}, 'the first registered keep their place')
        self.register(self.b1, 'stats', 'b-scope', {self.beta.id})
        self.assertEqual(len(snapshot_cache.hot_recipes()), snapshot_cache.MAX_HOT_PER_USER + 1)
        self.register(self.a1, 'stats', 'scope-0', {self.alpha.id})  # one that is already registered is renewed, not refused
        self.assertEqual(len(snapshot_cache.hot_recipes()), snapshot_cache.MAX_HOT_PER_USER + 1)


class GraphPayloadLifetimeTests(Fresh):
    def test_a_prebuilt_graph_is_kept_as_long_as_one_a_request_builds_and_only_when_the_version_moved(self):
        client = client_for(self.a1)
        client.get(GRAPH)
        host = self.hosts['alpha'][3]
        Subdomain.objects.create(name='fresh.alpha.lcexample.test', target_domain=host.target_domain, scan_history=host.scan_history, http_status=200)
        self.clock.advance(6)
        writes = []
        real_set = cache.set

        def spy(key, value, timeout=None, *a, **k):
            writes.append((key, timeout))
            return real_set(key, value, timeout, *a, **k)
        with mock.patch.object(live_refresh.cache, 'set', spy), Counting() as computed:
            live_refresh.refresh_hot_scopes()
            self.assertEqual(computed.calls()['graph'], 1)
            self.clock.advance(6)
            live_refresh.refresh_hot_scopes()  # nothing changed since: nothing is built
            self.assertEqual(computed.calls()['graph'], 1)
        graph_writes = [timeout for key, timeout in writes if key.startswith('cve-graph:')]
        self.assertEqual(graph_writes, [views.GRAPH_CACHE_SECONDS])


class PoliteRefresherTests(Fresh):
    def test_the_budget_is_small_and_never_more_than_half_an_interval(self):
        self.assertEqual([live_refresh.budget_seconds(i) for i in (2, 5, 6, 8, 60)], [1.0, 2.5, 3.0, 3.0, 3.0])

    def test_the_backlog_probe_reads_only_the_named_queues_of_the_classic_worker(self):
        asked = []

        class Client:
            def llen(self, name):
                asked.append(name)
                return {'live_cache_queue': 2, 'ctwatch_queue': 70, 'api_queue': 5}.get(name, 0)

        class Connection:
            default_channel = SimpleNamespace(client=Client())

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch('reNgine.celery.app.connection_for_read', return_value=Connection()):
            self.assertEqual(REAL_BACKLOG(), (2, 75))
        self.assertEqual(asked, ['live_cache_queue', *live_refresh.CLASSIC_QUEUES])  # a fixed list of lengths: no scan of the keyspace
        with mock.patch('reNgine.celery.app.connection_for_read', side_effect=ConnectionError('down')):
            self.assertEqual(REAL_BACKLOG(), (0, 0), 'a broker that does not answer never holds a refresh back')

    def test_a_backlogged_worker_gets_no_refresh_and_the_skip_is_counted(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(11)
        for backlog in ((0, live_refresh.BACKLOG_SKIP), (live_refresh.OWN_BACKLOG_SKIP, 0)):
            with mock.patch.object(live_refresh, 'backlog', return_value=backlog), Counting() as computed:
                summary = live_refresh.refresh_hot_scopes()
            self.assertIn('skipped', summary)
            self.assertEqual(computed.calls()['stats'], 0)
        self.assertEqual(snapshot_cache.metrics()['this_hour']['skipped'], 2)
        self.assertEqual(system_status._live_cache([])['last_run']['skipped'].split()[0], '3')
        with mock.patch.object(live_refresh, 'backlog', return_value=(0, live_refresh.BACKLOG_SKIP - 1)), Counting() as computed:
            self.assertEqual(live_refresh.refresh_hot_scopes()['refreshed'], 1)

    def test_a_run_that_overran_is_counted_and_the_next_one_is_skipped_once(self):
        client_for(self.a1).get(STATS)
        self.clock.advance(11)
        ticks = iter([0.0, 0.1, 9.0])  # started, the check before the one scope, the end: nine seconds against a budget of 2.5
        fake_time = SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda s: None)
        with mock.patch.object(live_refresh, 'time', fake_time), mock.patch.object(live_refresh, '_yield'):
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual(summary['refreshed'], 1)
        self.assertEqual(snapshot_cache.metrics()['this_hour']['overran'], 1)
        self.assertTrue(snapshot_cache.last_beat()['overran'])
        self.clock.advance(11)
        with Counting() as computed:
            self.assertIn('overran', live_refresh.refresh_hot_scopes()['skipped'])
            self.assertEqual(computed.calls()['stats'], 0)
            self.assertEqual(live_refresh.refresh_hot_scopes()['refreshed'], 1)  # the skip cleared it

    def test_the_worker_is_yielded_to_between_scopes(self):
        client_for(self.a1).get(STATS)
        client_for(self.b1).get(STATS)
        self.clock.advance(11)
        with mock.patch.object(live_refresh, '_yield') as yielded:
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual((summary['refreshed'], yielded.call_count), (2, 2))

    def test_the_scopes_a_short_run_leaves_are_done_first_next_time(self):
        client_for(self.a1).get(STATS)
        client_for(self.b1).get(STATS)
        self.clock.advance(11)
        first = live_refresh.refresh_hot_scopes(budget=-1)  # no time for any
        self.assertEqual((first['refreshed'], first['out_of_time']), (0, 2))
        snapshot_cache.beat({'state': 'idle'})  # (a budget of -1 counts as an overrun, which would skip the next run)
        calls = []
        real = views.stats_payload
        with mock.patch.object(views, 'stats_payload', lambda: calls.append(1) or real()), \
                mock.patch.object(live_refresh, 'time', SimpleNamespace(monotonic=iter([0, 0, 9, 9, 9]).__next__, sleep=lambda s: None)), \
                mock.patch.object(live_refresh, '_yield'):
            second = live_refresh.refresh_hot_scopes(budget=2)
        self.assertEqual((second['refreshed'], second['out_of_time']), (1, 1), 'one scope is served per short run')

    def test_the_fast_snapshot_of_a_scope_nobody_polls_any_more_is_left_alone(self):
        client_for(self.a1).get(GRAPH_LIVE)
        client_for(self.a1).get(STATS)
        self.clock.advance(40)  # still hot (60 s) but not polled for longer than a few intervals plus the registration throttle
        with Counting() as computed:
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual(summary['idle'], 1)
        self.assertEqual((computed.calls()['live'], computed.calls()['stats']), (0, 1))

    def test_the_run_lock_is_a_token_and_a_run_never_deletes_one_another_run_holds(self):
        client_for(self.a1).get(STATS)
        client_for(self.b1).get(STATS)
        self.clock.advance(11)
        real = views.stats_payload
        calls = []

        def steal():
            calls.append(1)
            cache.set(live_refresh.RUN_LOCK, 'another-run', 30)  # our lock ran out and a later run took it
            return real()
        with mock.patch.object(views, 'stats_payload', steal):
            summary = live_refresh.refresh_hot_scopes()
        self.assertEqual(len(calls), 1, 'the run that lost its lock stops')
        self.assertEqual(summary['skipped'], 'the run lock was lost')
        self.assertEqual(cache.get(live_refresh.RUN_LOCK), 'another-run')
        cache.delete(live_refresh.RUN_LOCK)
        live_refresh.refresh_hot_scopes()
        self.assertIsNone(cache.get(live_refresh.RUN_LOCK), 'a run releases its own lock')


class CommitTimeBumpTests(Fresh):
    def test_a_poll_that_cached_the_old_answer_before_the_commit_is_dropped_at_the_commit(self):
        both = User.objects.create_user('lc-commit', password='x')
        for project in (self.alpha, self.beta):
            ProjectMembership.objects.create(user=both, project=project, role='user')
        client = client_for(both)
        self.assertEqual(client.get(STATS).json()['targets'], 2)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            ProjectMembership.objects.filter(user=both, project=self.beta).delete()
            # a poll running between the change and its commit saw the old rows and cached them under the (already bumped) epoch
            cache.set(membership_cache._key(both), {'epoch': cache.get(membership_cache.EPOCH_KEY), 'ids': [self.alpha.id, self.beta.id]}, 15)
        self.assertGreaterEqual(len(callbacks), 1)
        self.assertEqual(client.get(STATS).json()['targets'], 1)

    def test_the_commit_time_bump_is_robust(self):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            ProjectMembership.objects.create(user=self.a1, project=self.beta, role='user')
        self.assertTrue(callbacks)
        epoch = cache.get(membership_cache.EPOCH_KEY)
        for callback in callbacks:
            callback()
        self.assertNotEqual(cache.get(membership_cache.EPOCH_KEY), epoch)

    def test_demoting_and_promoting_a_superuser_changes_the_next_poll(self):
        user = User.objects.create_user('lc-su', password='x', is_superuser=True)
        ProjectMembership.objects.create(user=user, project=self.alpha, role='admin')
        client = client_for(user)
        self.assertEqual(client.get(STATS).json()['targets'], 2)
        user.is_superuser = False
        user.save()
        self.assertEqual(client.get(STATS).json()['targets'], 1)
        self.assertEqual(client.get(STATS).json()['targets'], 1)  # cached now
        user.is_superuser = True
        user.save()
        self.assertEqual(client.get(STATS).json()['targets'], 2)


class CounterTests(Fresh):
    def test_a_count_is_one_round_trip_after_the_first(self):
        snapshot_cache.count('stats', 'hit')
        with mock.patch.object(snapshot_cache.cache, 'add', wraps=snapshot_cache.cache.add) as add, \
                mock.patch.object(snapshot_cache.cache, 'incr', wraps=snapshot_cache.cache.incr) as incr:
            snapshot_cache.count('stats', 'hit')
            snapshot_cache.count('stats', 'hit')
        self.assertEqual((add.call_count, incr.call_count), (0, 2))
        self.assertEqual(snapshot_cache.metrics()['this_hour']['hit'], 3)
