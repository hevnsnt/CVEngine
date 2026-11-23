"""The read paths at scale: the one-row-per-host collapse reads each host's open ports and address set once (and still picks the same rows as the
correlated form it replaced), a search and the Targets table run the collapse once, the list endpoints cut their page on ids before loading the wide
rows, a scan's detail counts its findings in one pass, and the oldest-open read only asks about its candidates."""
import ast
import random
from pathlib import Path

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from cveFeed import counts
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call


def _correlated_one_per_host():
    """The correlated form ``_one_per_host`` had before (git history), compiled from its source: the reference the set-based form must agree with."""
    source = Path(__file__).with_name('_one_per_host_reference.py').read_text()
    namespace = {'ArraySubquery': services.ArraySubquery}
    exec(compile(ast.parse(source), 'reference', 'exec'), namespace)
    return namespace['_one_per_host']


class Inventory(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='R', slug='rp-org')
        cls.p1 = Project.objects.create(name='R1', slug='rp1', insert_date=now, org=org)
        cls.p2 = Project.objects.create(name='R2', slug='rp2', insert_date=now, org=org)
        engine = EngineType.objects.create(engine_name='rp')
        cls.domains = [Domain.objects.create(name=f't{i}.rp.test', project=cls.p1 if i < 3 else cls.p2, insert_date=now) for i in range(5)]
        scans = [ScanHistory.objects.create(domain=d, scan_type=engine, start_scan_date=now, scan_status=2) for d in cls.domains]
        rng = random.Random(7)
        ips = [IpAddress.objects.create(address=f'192.0.2.{i + 1}', is_cdn=(i % 9 == 0)) for i in range(30)]
        for ip in ips:
            for n in rng.sample([22, 80, 443, 8080, 3306], rng.randint(0, 4)):
                ip.ports.add(Port.objects.create(number=n, state=rng.choice(['open', 'open', '', 'closed'])))
        cls.subs = []
        seen = set()
        for i in range(120):
            k = rng.randrange(5)
            name = rng.choice([cls.domains[k].name, f'www.{cls.domains[k].name}', f'h{rng.randrange(40)}.{cls.domains[k].name}', f'shared{rng.randrange(5)}.rp.test'])
            scan = rng.choice([scans[k], None])
            score = rng.randrange(100)
            if scan is not None and (scan.pk, k, name) in seen:
                continue  # a host is one row per scan and target now (uniq_sub_scan_dom_name)
            seen.add((scan.pk if scan else None, k, name))
            sub = Subdomain.objects.create(name=name, target_domain=cls.domains[k], scan_history=scan, score=score)
            sub.ip_addresses.add(*rng.sample(ips, rng.randint(0, 3)))
            cls.subs.append(sub)
        for sub in cls.subs[:40]:
            Vulnerability.objects.create(subdomain=sub, target_domain=sub.target_domain, scan_history=sub.scan_history, name=f'v{sub.pk}',
                                         severity=rng.randrange(5), open_status=True)
        cls.root = User.objects.create_user('rp-root', password='x', is_superuser=True)
        _, cls.token = create_token(cls.root, 'rp')

    def setUp(self):
        cache.clear()


class CollapseTests(Inventory):
    def test_the_set_based_collapse_keeps_the_same_rows_as_the_correlated_one(self):
        old = _correlated_one_per_host()
        from cveFeed.correlation import latest_scan_q
        for qs in (Subdomain.objects.all(), Subdomain.objects.filter(latest_scan_q()), Subdomain.objects.filter(target_domain__project=self.p1),
                   Subdomain.objects.filter(name__startswith='shared'), Subdomain.objects.none()):
            for per_project in (False, True):
                self.assertEqual(set(services._one_per_host(qs, per_project=per_project).values_list('id', flat=True)),
                                 set(old(qs, per_project=per_project).values_list('id', flat=True)), (str(qs.query) if qs.exists() else 'none', per_project))

    def test_each_fact_is_read_once_in_one_statement(self):
        sql = str(services._one_per_host(Subdomain.objects.all()).query)
        self.assertRegex(sql, r'"id" = ANY\(+ARRAY\(')
        self.assertEqual(sql.count('STRING_AGG'), 1)
        self.assertEqual(sql.count('COUNT(DISTINCT'), 1)

    def test_the_target_counts_collapse_once(self):
        with CaptureQueriesContext(connection) as captured:
            status, data = call(self.token, 'GET', '/api/v1/projects/rp1/targets')
        self.assertEqual(status, 200, data)
        self.assertEqual(sum(1 for q in captured.captured_queries if 'WITH cand AS' in q['sql']), 1)
        reps = counts.host_reps(domain_ids=[d.pk for d in self.domains[:3]])
        for row in data['results']:
            self.assertEqual(row['hosts'], reps.filter(target_domain_id=row['id']).count())

    def test_a_search_with_its_facets_collapses_once(self):
        with CaptureQueriesContext(connection) as captured:
            status, data = call(self.token, 'GET', '/api/v1/projects/rp1/search?q=rp.test&facets=port,tech')
        self.assertEqual(status, 200, data)
        self.assertEqual(sum(1 for q in captured.captured_queries if 'WITH cand AS' in q['sql']), 1)
        self.assertEqual(data['count'], services.search_host_rows(self.p1, services.parse_search('rp.test')).count())
        self.assertEqual(sum(data['facets']['heat'].values()), data['count'])

    def test_the_siblings_of_a_page_are_the_same_with_the_narrowed_read(self):
        from cveFeed.correlation import latest_scan_q
        current = Subdomain.objects.filter(latest_scan_q())
        ids = list(current.values_list('id', flat=True)[:30])
        found = counts.host_siblings(ids)
        keyed = {r['id']: r['host_key'] for r in counts.with_host_key(current).values('id', 'host_key')}
        names_by_key = {}
        for r in counts.with_host_key(current).values('host_key', 'name'):
            names_by_key.setdefault(r['host_key'], set()).add(r['name'])
        for i in ids:
            names = names_by_key.get(keyed[i], set()) | {Subdomain.objects.get(pk=i).name}
            project = Subdomain.objects.get(pk=i).target_domain.project_id
            expected = sorted((r.pk, r.name) for r in current.filter(name__in=names, target_domain__project_id=project).exclude(id__in=ids))
            self.assertEqual(sorted(found[i]), expected)


class ListPagingTests(Inventory):
    def test_the_vulnerabilities_pages_are_the_ordered_slices(self):
        order = list(Vulnerability.objects.order_by('-severity', '-id').values_list('id', flat=True))
        seen = []
        for page in (1, 2, 3, 4):
            status, data = call(self.token, 'GET', f'/api/v1/projects/{services.ALL_PROJECTS}/vulnerabilities?page={page}&page_size=11')
            self.assertEqual(status, 200, data)
            self.assertEqual(data['count'], 40)
            seen += [row['id'] for row in data['results']]
        self.assertEqual(seen, order)

    def test_page_slice_reads_the_ids_first_and_loads_only_the_page(self):
        qs = Vulnerability.objects.select_related('subdomain', 'target_domain').prefetch_related('cve_ids').order_by('-severity', '-id')
        with CaptureQueriesContext(connection) as captured:
            rows = services.page_slice(qs, 5, 15)
        self.assertEqual([r.pk for r in rows], list(qs.values_list('id', flat=True)[5:15]))
        first = captured.captured_queries[0]['sql']
        self.assertTrue(first.startswith('SELECT "startScan_vulnerability"."id" AS "pk"'), first)
        self.assertNotIn('startScan_subdomain', first)

    def test_the_findings_page_is_the_same_merge(self):
        status, data = call(self.token, 'GET', f'/api/v1/projects/{services.ALL_PROJECTS}/findings?status=all&page_size=200')
        self.assertEqual(status, 200, data)
        rows = [(r['kind'] if 'kind' in r else r.get('type'), r['id']) for r in data['results']]
        self.assertEqual(len(rows), data['count'])
        for page, size in ((1, 7), (2, 7), (3, 7)):
            status, part = call(self.token, 'GET', f'/api/v1/projects/{services.ALL_PROJECTS}/findings?status=all&page={page}&page_size={size}')
            self.assertEqual([(r['kind'] if 'kind' in r else r.get('type'), r['id']) for r in part['results']], rows[(page - 1) * size:page * size])

    def test_the_vulnerability_order_index_builds_concurrently(self):
        import importlib

        from django.contrib.postgres.operations import AddIndexConcurrently
        migration = importlib.import_module('startScan.migrations.0026_vulnerability_severity_id_idx').Migration
        self.assertFalse(migration.atomic)
        self.assertTrue(all(isinstance(op, AddIndexConcurrently) for op in migration.operations))


class ScanDetailTests(Inventory):
    def test_the_severity_counts_are_one_aggregate_with_the_same_numbers(self):
        scan = self.subs[0].scan_history or next(s.scan_history for s in self.subs if s.scan_history)
        project = scan.domain.project
        with CaptureQueriesContext(connection) as captured:
            status, data = call(self.token, 'GET', f'/api/v1/projects/{project.slug}/scans/{scan.pk}')
        self.assertEqual(status, 200, data)
        rows = Vulnerability.objects.filter(scan_history=scan)
        self.assertEqual(data['vulnerabilities'], rows.count())
        self.assertEqual(data['severity_counts'], {services.SEVERITY_NAMES[k]: rows.filter(severity=k).count() for k in (4, 3, 2, 1, 0)})
        self.assertEqual(sum(1 for q in captured.captured_queries if 'FROM "startScan_vulnerability"' in q['sql'] and 'COUNT' in q['sql']), 1)
