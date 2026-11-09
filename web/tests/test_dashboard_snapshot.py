"""The dashboard's numbers come from one stored snapshot per project (``cveFeed.dashboard_snapshot``): the request sums them and never computes.

These tests fail on the code before the change: there the headline counts, the ticker's counts, the map and the host search's coverage counts were
computed in the request behind a cache keyed by the caller's whole scope, and a cold or stale answer made the request wait for the computation.

Nothing here waits on the wall clock: ages are set by rewriting the stored entry, and the background work (a celery task in production) is run by
calling it.
"""
import logging
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import dashboard_snapshot as snap
from cveFeed import timing, views
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for

PROJECTS = 15
STATS, GRAPH, DISCOVERY = '/cve/api/stats?project=_all', '/cve/api/graph?project=_all', '/cve/api/discovery?scan=&after=0&project=_all'


def seed(n_projects=PROJECTS):
    """``n_projects`` projects of different sizes (project k has k + 1 hosts, each with an address, and two CVE matches on the first)."""
    now = timezone.now()
    cve = CVEEntry.objects.get_or_create(cve_id='CVE-2099-1', defaults={'kev': True, 'cvss': 9.8, 'affected': []})[0]
    org = Org.objects.create(name='Snap', slug=f'snap-{n_projects}')
    engine = EngineType.objects.get_or_create(engine_name='snap', defaults={'yaml_configuration': 'x'})[0]
    projects = []
    for k in range(n_projects):
        p = Project.objects.create(name=f'P{k}', slug=f'p{k}-{n_projects}', insert_date=now, org=org)
        d = Domain.objects.create(name=f'p{k}.example.com', project=p, insert_date=now)
        ScanHistory.objects.create(domain=d, scan_type=engine, scan_status=2, start_scan_date=now, tasks=[])
        for h in range(k + 1):
            s = Subdomain.objects.create(target_domain=d, name=f'h{h}.p{k}.example.com')
            s.ip_addresses.add(IpAddress.objects.create(org=org, address=f'192.0.2.{(k * 16 + h) % 250 + 1}'))
            if h == 0:
                CVEMatch.objects.create(cve_entry=cve, subdomain=s, matched_product='nginx', confidence=0.9)
        projects.append(p)
    return projects


class Base(TestCase):
    def setUp(self):
        cache.clear()
        snap.reset_for_tests() if hasattr(snap, 'reset_for_tests') else None
        self.projects = seed()
        self.admin = User.objects.create_user('snap-admin', password='x', is_superuser=True)
        self.client_ = client_for(self.admin)
        patcher = mock.patch.object(snap, '_enqueue', return_value=True)  # the broker is not part of these tests: what would be queued is recorded
        self.enqueued = patcher.start()
        self.addCleanup(patcher.stop)

    def refresh_all(self):
        return [snap.refresh_project(p.id) for p in self.projects]

    def age(self, project, seconds):
        """Make the stored snapshot of ``project`` look ``seconds`` older (without waiting)."""
        entry = cache.get(snap.key_of(project.id))
        entry['at'] -= seconds
        cache.set(snap.key_of(project.id), entry, snap.KEEP_SECONDS)


class SumOfSnapshotsTests(Base):
    def test_the_all_view_is_the_sum_of_the_per_project_snapshots_and_computes_nothing(self):
        self.refresh_all()
        with mock.patch.object(snap, 'compute_project', side_effect=AssertionError('computed in the request')), \
                mock.patch.object(views, 'stats_payload', side_effect=AssertionError('computed in the request')), \
                mock.patch.object(views, 'graph_payload', side_effect=AssertionError('computed in the request')), \
                mock.patch.object(views, 'discovery_counts', side_effect=AssertionError('computed in the request')):
            stats = self.client_.get(STATS).json()
            graph = self.client_.get(GRAPH).json()
            discovery = self.client_.get(DISCOVERY).json()
        hosts = sum(k + 1 for k in range(PROJECTS))
        self.assertEqual(stats['hosts'], hosts)
        self.assertEqual(stats['targets'], PROJECTS)
        self.assertEqual(stats['coverage']['heat'] and sum(stats['coverage']['heat'].values()), hosts)
        self.assertEqual(discovery['counts']['hosts'], hosts)
        self.assertEqual(sum(1 for n in graph['nodes'] if n['kind'] == 'subdomain'), hosts)
        self.assertEqual(stats['snapshot']['partial'], False)
        # one project's own view is that project's snapshot, not a share of the sum
        one = self.client_.get(f'/cve/api/stats?project={self.projects[3].slug}').json()
        self.assertEqual(one['hosts'], 4)

    def test_a_viewer_who_sees_two_projects_gets_the_sum_of_those_two(self):
        self.refresh_all()
        user = User.objects.create_user('two', password='x')
        for p in self.projects[:2]:
            ProjectMembership.objects.create(user=user, project=p, role='audit')
        stats = client_for(user).get('/cve/api/stats?project=_all').json()
        self.assertEqual(stats['hosts'], 1 + 2)

    def test_a_poll_of_a_fresh_snapshot_computes_and_queues_nothing(self):
        self.refresh_all()
        self.enqueued.reset_mock()
        with mock.patch.object(snap, 'compute_project', side_effect=AssertionError('computed')):
            for _ in range(30):
                for url in (STATS, GRAPH, DISCOVERY):
                    self.assertEqual(self.client_.get(url).status_code, 200)
        self.enqueued.assert_not_called()


class ColdAndStaleTests(Base):
    def test_a_cold_instance_answers_at_once_with_nothing_to_show_and_asks_for_the_snapshots(self):
        with mock.patch.object(snap, 'compute_project', side_effect=AssertionError('computed in the request')):
            first = self.client_.get(STATS).json()
        self.assertFalse(first['snapshot']['ready'])
        self.assertNotIn('hosts', first)  # no zeros pretending to be numbers
        self.assertEqual(self.enqueued.call_count, PROJECTS)  # one refresh asked for per project, none run in the request
        # the background work runs: the next answer has the numbers
        summary = snap.refresh_due()
        self.assertEqual((summary['refreshed'], summary['due']), (PROJECTS, PROJECTS))
        second = self.client_.get(STATS).json()
        self.assertTrue(second['snapshot']['ready'])
        self.assertEqual(second['hosts'], sum(k + 1 for k in range(PROJECTS)))

    def test_a_partial_cold_instance_shows_what_is_stored_and_says_it_is_partial(self):
        snap.refresh_project(self.projects[2].id)
        stats = self.client_.get(STATS).json()
        self.assertTrue(stats['snapshot']['ready'])
        self.assertTrue(stats['snapshot']['partial'])
        self.assertEqual(stats['hosts'], 3)

    def test_a_stale_snapshot_is_served_at_once_then_refreshed_in_the_background(self):
        self.refresh_all()
        target = self.projects[4]
        self.age(target, 3600)
        for p in self.projects:
            if p.id != target.id:
                self.age(p, 3600)
        before = self.client_.get(STATS).json()['hosts']
        Subdomain.objects.create(target_domain=Domain.objects.get(project=target), name='new.p4.example.com')
        self.enqueued.reset_mock()
        cache.delete_many([snap.QUEUED % p.id for p in self.projects])  # the read above already asked once: ask again, as a viewer a quarter of a minute later would
        with mock.patch.object(snap, 'compute_project', side_effect=AssertionError('computed in the request')):
            served = self.client_.get(STATS).json()
        self.assertEqual(served['hosts'], before)  # the old number, at once
        self.assertTrue(served['snapshot']['stale'])
        self.assertTrue(served['snapshot']['as_of'])
        self.assertEqual(self.enqueued.call_count, PROJECTS)  # a refresh asked for, not waited for
        snap.refresh_due()
        refreshed = self.client_.get(STATS).json()
        self.assertEqual(refreshed['hosts'], before + 1)
        self.assertFalse(refreshed['snapshot']['stale'])

    def test_a_failing_refresh_keeps_the_previous_snapshot(self):
        self.refresh_all()
        with mock.patch.object(snap, 'compute_project', side_effect=RuntimeError('boom')):
            self.assertEqual(snap.refresh_project(self.projects[0].id), 'failed')
        self.assertTrue(self.client_.get(STATS).json()['snapshot']['ready'])
        self.assertEqual(self.client_.get(STATS).json()['hosts'], sum(k + 1 for k in range(PROJECTS)))


class WhenSnapshotsAreRefreshedTests(Base):
    def test_a_burst_of_results_queues_one_refresh_per_project(self):
        self.refresh_all()
        self.enqueued.reset_mock()
        for _ in range(200):
            snap.mark_dirty([self.projects[0].id])
        self.assertEqual(self.enqueued.call_count, 1)

    def test_a_dirty_project_is_refreshed_by_the_beat_run_and_a_clean_one_is_not(self):
        self.refresh_all()
        snap.mark_dirty([self.projects[1].id])
        with mock.patch.object(snap, 'compute_project', wraps=snap.compute_project) as compute:
            summary = snap.refresh_due()
        self.assertEqual((summary['due'], summary['refreshed']), (1, 1))
        self.assertEqual(compute.call_args[0][0], self.projects[1].id)
        with mock.patch.object(snap, 'compute_project', side_effect=AssertionError('nothing is due')):
            self.assertEqual(snap.refresh_due()['due'], 0)

    def test_a_sentinel_result_marks_its_project_dirty_and_a_poll_does_not(self):
        from agentapi.models import SentinelTask
        from tests.fake_scanner import FakeScanner, fixture
        project = self.projects[0]
        task = SentinelTask.objects.create(project=project, kind='naabu', target={'host': 'h0.p0.example.com', 'ports': [80]}, host='h0.p0.example.com',
                                           ips=['192.0.2.1'], status='queued')
        self.refresh_all()
        self.enqueued.reset_mock()
        for _ in range(20):  # polls of the dashboard: nothing is queued
            self.client_.get(STATS)
        self.enqueued.assert_not_called()
        with FakeScanner(kinds=['naabu'], responders={'naabu': fixture('naabu', ports={'192.0.2.1': [80]})}) as fake:
            with mock.patch.object(snap, 'mark_dirty', wraps=snap.mark_dirty) as dirty:
                served = fake.serve_once()
        self.assertEqual(served['id'], task.pk)
        dirty.assert_called_once_with([project.id])  # the result landed: that project, and only it
        self.assertEqual(self.enqueued.call_count, 1)
        self.assertEqual(self.enqueued.call_args.args[0], project.id)

    def test_closing_a_finding_marks_every_project_dirty_once_however_many_are_closed(self):
        self.refresh_all()
        self.enqueued.reset_mock()
        for _ in range(50):
            views.bump_stats_revision()
        self.assertEqual(self.enqueued.call_count, PROJECTS)


class BoundedRequestTests(Base):
    """Query counts, not wall time, are what is asserted; the time budget is generous for a loaded CI machine."""

    def count(self, url):
        with CaptureQueriesContext(connection) as q:
            response = self.client_.get(url)
        self.assertEqual(response.status_code, 200)
        return len(q)

    def test_the_dashboard_requests_cost_a_handful_of_queries_whatever_the_number_of_projects(self):
        self.refresh_all()
        for url in (STATS, GRAPH, DISCOVERY):
            self.client_.get(url)  # imports and the session
        counts = {url: self.count(url) for url in (STATS, GRAPH, DISCOVERY)}
        for url, n in counts.items():
            self.assertLessEqual(n, 20, f'{url} ran {n} queries at {PROJECTS} projects')
        # and the same number with a fifth of the projects: nothing is done per project
        cache.clear()
        small = Project.objects.exclude(id__in=[p.id for p in self.projects[:3]])
        small.delete()
        for p in self.projects[:3]:
            snap.refresh_project(p.id)
        for url in (STATS, GRAPH, DISCOVERY):
            self.client_.get(url)
            self.assertLessEqual(abs(self.count(url) - counts[url]), 1, url)

    def test_the_first_useful_numbers_come_back_inside_the_budget_even_when_cold(self):
        import time
        started = time.monotonic()
        self.client_.get(STATS)
        self.client_.get(DISCOVERY)
        self.client_.get(GRAPH)
        self.assertLess(time.monotonic() - started, 5.0)  # budget 2 s, with CI headroom; the cold path computes nothing

    def test_the_search_coverage_counts_come_from_the_snapshots_not_a_walk_over_the_hosts(self):
        from agentapi import services
        self.refresh_all()
        token = create_token(self.admin, 'snap-token')[1]
        with mock.patch.object(services, '_heat_facets', side_effect=AssertionError('walked the hosts')):
            r = self.client_.get('/api/v1/projects/_all/search?q=&page_size=1', HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(r.status_code, 200)
        facets = r.json()['facets']
        self.assertEqual(sum(facets['heat'].values()), sum(k + 1 for k in range(PROJECTS)))
        # a search with a term is not a plain one: it is walked as before
        with mock.patch.object(services, '_heat_facets', wraps=services._heat_facets) as walk:
            self.client_.get('/api/v1/projects/_all/search?q=h0&page_size=1', HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertTrue(walk.called)


class ObservabilityTests(Base):
    def test_the_dashboard_endpoints_answer_with_server_timing(self):
        self.refresh_all()
        response = self.client_.get(STATS)
        header = response['Server-Timing']
        self.assertRegex(header, r'total;dur=\d+(\.\d+)?')
        self.assertRegex(header, r'db;dur=\d+(\.\d+)?;desc="\d+ queries"')
        self.assertIn('snap;desc="15 of 15 project snapshots', header)

    def test_a_slow_request_writes_one_line_with_the_endpoint_and_the_query_count(self):
        self.refresh_all()
        with mock.patch.object(timing, 'SLOW_SECONDS', -1), self.assertLogs('cveFeed.timing', level=logging.WARNING) as logs:
            self.client_.get(STATS + '&secret=term')
        self.assertEqual(len(logs.records), 1)
        line = logs.records[0].getMessage()
        self.assertRegex(line, r'^slow request GET /cve/api/stats 200 \d+\.\d\ds db=\d+\.\d\ds queries=\d+ ')
        self.assertNotIn('secret', line)  # the path only: a query string can hold search terms

    def test_a_fast_request_writes_nothing(self):
        self.refresh_all()
        with self.assertNoLogs('cveFeed.timing', level=logging.WARNING):
            self.client_.get(STATS)


class MergeTests(TestCase):
    def entry(self, pid, stats=None, graph=None, coverage=None):
        base = {'targets': 1, 'certs_expiring': 0, 'certs_total': 0, 'hygiene_open': 0, 'hosts': 1, 'hosts_live': 1, 'matches': 0, 'match_groups': 0,
                'scanner_findings': 0, 'exposed_hosts': 0, 'tiers': {'fire': 1, 'smoke': 2, 'ice': 3}, 'cves': 7, 'autofire_runs': 0, 'templates': 0,
                'oldest_open_days': None, 'oldest_open_kind': None, 'oldest_open_id': None, 'oldest_open_what': None, 'hygiene_checks': [],
                'match_groups_truncated': False, 'internal': {'has': False}}
        return {'at': 1000.0 + pid, 'payload': {'v': snap.VERSION, 'project': {'id': pid, 'slug': f'p{pid}'}, 'stats': {**base, **(stats or {})},
                                                'discovery': {'hosts': 1, 'ips': 1, 'ports': 2}, 'coverage': coverage or {'heat': {'clean': 1}, 'truncated': False,
                                                                                                                      'unscannable': {'count': 0, 'private': 0, 'no_dns': 0, 'unknown': 0}},
                                                'graph': graph or {'nodes': [], 'edges': [], 'hosts': {'drawn': 0, 'total': 0, 'projects': {}}, 'projects': {}}}}

    def test_sums_add_up_and_global_numbers_are_not_added(self):
        merged = snap.merge_stats([self.entry(1, {'hosts': 4, 'exposed_hosts': 1}), self.entry(2, {'hosts': 6, 'exposed_hosts': 2})])
        self.assertEqual((merged['hosts'], merged['exposed_hosts'], merged['targets']), (10, 3, 2))
        self.assertEqual((merged['cves'], merged['tiers']), (7, {'fire': 1, 'smoke': 2, 'ice': 3}))  # the CVE catalogue is one, not two

    def test_the_hygiene_top_is_taken_after_adding_the_projects_up(self):
        a = [{'check': 'spf_missing', 'worst': 'medium', 'n': 5}, {'check': 'tls_expired', 'worst': 'high', 'n': 1}]
        b = [{'check': 'spf_missing', 'worst': 'medium', 'n': 5}, {'check': 'dmarc_none', 'worst': 'medium', 'n': 7}]
        merged = snap.merge_stats([self.entry(1, {'hygiene_checks': a}), self.entry(2, {'hygiene_checks': b})])
        self.assertEqual([(r['check'], r['n']) for r in merged['hygiene_top']], [('tls_expired', 1), ('spf_missing', 10), ('dmarc_none', 7)])

    def test_the_oldest_open_item_is_the_oldest_across_projects(self):
        merged = snap.merge_stats([self.entry(1, {'oldest_open_days': 4, 'oldest_open_kind': 'cve', 'oldest_open_id': 9}),
                                   self.entry(2, {'oldest_open_days': 40, 'oldest_open_kind': 'scanner', 'oldest_open_id': 3})])
        self.assertEqual((merged['oldest_open_days'], merged['oldest_open_kind'], merged['oldest_open_id']), (40, 'scanner', 3))

    def test_the_merged_map_keeps_the_riskiest_hosts_within_the_node_cap(self):
        def graph(pid, scores):
            nodes, edges = [{'id': f'dom:{pid}', 'kind': 'domain', 'label': f'd{pid}'}], []
            for i, score in enumerate(scores):
                nodes.append({'id': f'sub:{pid}{i}', 'kind': 'subdomain', 'label': f'h{i}.{pid}', 'score': score})
                edges.append({'from': f'dom:{pid}', 'to': f'sub:{pid}{i}'})
            return {'nodes': nodes, 'edges': edges, 'hosts': {'drawn': len(scores), 'total': len(scores), 'projects': {}}, 'projects': {f'p{pid}': {'name': 'x', 'hygiene': 0}}}
        merged = snap.merge_graph([self.entry(1, graph=graph(1, [10, 90, 50])), self.entry(2, graph=graph(2, [95, 5]))], cap=5)
        kept = [n['score'] for n in merged['nodes'] if n['kind'] == 'subdomain']
        self.assertEqual(sorted(kept, reverse=True), [95, 90, 50])  # 5 nodes: two domains and the three riskiest hosts; the next one would be the sixth
        self.assertTrue(all(e['from'] in {n['id'] for n in merged['nodes']} and e['to'] in {n['id'] for n in merged['nodes']} for e in merged['edges']))
        self.assertEqual(merged['hosts']['drawn'], 3)
        self.assertGreater(merged['hosts']['total'], merged['hosts']['drawn'])  # the cap cut something, and the page says so
