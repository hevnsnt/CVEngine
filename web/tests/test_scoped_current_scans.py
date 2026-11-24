"""Under a tenancy scope ``current_scans.current_scan_sets`` lists the scope's domains only.

It used to list every domain of the install, so a request limited to one project put every other project's domain in ``unfull_domains`` (it cannot
see their full scans) and the planner expected far more current host rows than there were. The rows a scoped caller reads must not change: every test
here compares the scoped answer with the unrestricted answer cut to the scope's projects, and with the answer of the previous domain list (kept below
as the reference), for one project, two, every project, and a caller with no project, on domains with and without full scans and manual-discovery
domains. The per-snapshot sharing of the sets stays, and two scopes never share one read.
"""
import contextlib
import json
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from cveFeed import current_scans, overview, situations, snapshot_cache
from cveFeed.correlation import latest_scan_q
from cveFeed.discovery import HOST_PIPELINE_TASK
from cveFeed.models import CVEEntry, CVEMatch, OnDemandValidation
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tenancy import roles, scope
from tests.steady import steady_caches
from tests.test_overview_fast import Seeded


def previous_current_scan_sets(connection):
    """``current_scans.current_scan_sets`` as it was before this change: the scans of the scope, every domain of the install. Kept as the reference."""
    from cveFeed.current_scans import ScanSets, _sql
    done = ScanHistory.objects.filter(scan_status=2)
    full_sql, full_params = _sql(done.exclude(tasks__contains=[HOST_PIPELINE_TASK]).order_by('domain_id', '-id').distinct('domain_id')
                                 .values_list('domain_id', 'id'))
    pipe_sql, pipe_params = _sql(done.filter(tasks__contains=[HOST_PIPELINE_TASK]).order_by().values_list('id', 'domain_id'))
    domain_sql, domain_params = _sql(Domain._base_manager.order_by().values_list('id'))
    sql = (f'WITH full_last (domain_id, last) AS ({full_sql}), pipeline (id, domain_id) AS ({pipe_sql}) '
           'SELECT (SELECT array_agg(last) FROM full_last), (SELECT array_agg(domain_id) FROM full_last), '
           '(SELECT array_agg(p.id) FROM pipeline p LEFT JOIN full_last f ON f.domain_id = p.domain_id WHERE f.last IS NULL OR p.id > f.last), '
           f'(SELECT array_agg(d.id) FROM ({domain_sql}) d (id) WHERE NOT EXISTS (SELECT 1 FROM full_last f WHERE f.domain_id = d.id))')
    with connection.cursor() as cursor:
        cursor.execute(sql, (*full_params, *pipe_params, *domain_params))
        latest_full, full_domains, after_full, unfull_domains = (frozenset(ids or ()) for ids in cursor.fetchone())
    return ScanSets(latest_full, after_full, latest_full | after_full, full_domains, unfull_domains)


@contextlib.contextmanager
def scoped(allowed):
    tokens = scope.set_scope(None if allowed is None else set(allowed), None)
    try:
        yield
    finally:
        scope.reset_scope(tokens)


# (model, prefix to the host, path to the host's project) for every kind of row that reads the current inventory
READERS = ((Subdomain, '', 'target_domain__project_id'), (CVEMatch, 'subdomain__', 'subdomain__target_domain__project_id'),
           (Vulnerability, 'subdomain__', 'target_domain__project_id'), (OnDemandValidation, 'match__subdomain__', 'project_id'))


class World(TestCase):
    """Three projects, each with a domain that has full scans (and host-pipeline scans before and after), one with host-pipeline scans only, one whose
    first full scan failed, a manual-discovery domain and a domain with scanless rows only; the same host names in every project."""

    @classmethod
    def setUpTestData(cls):
        cls.now = timezone.now()
        org = Org.objects.create(name='SC', slug='sc-org')
        cls.engine = EngineType.objects.create(engine_name='sc')
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7101', cvss=9.8, published_at=cls.now)
        cls.projects = [Project.objects.create(name=f'SC{i}', slug=f'sc-{i}', insert_date=cls.now, org=org) for i in range(3)]
        cls.domains = {}
        for project in cls.projects:
            cls.build(project)
        cls.member = User.objects.create_user('sc-member', password='x')
        ProjectMembership.objects.create(user=cls.member, project=cls.projects[0], role='user')
        cls.nobody = User.objects.create_user('sc-nobody', password='x')  # a user with no project at all

    @classmethod
    def domain(cls, project, name, manual=False):
        d = Domain.objects.create(name=f'{name}.{project.slug}.test', project=project, insert_date=cls.now,
                                  **({'discovery_mode': Domain.DISCOVERY_MANUAL} if manual else {}))
        cls.domains.setdefault(project.pk, []).append(d)
        return d

    @classmethod
    def scan(cls, domain, status=2, pipeline=False):
        return ScanHistory.objects.create(start_scan_date=cls.now, scan_status=status, domain=domain, scan_type=cls.engine,
                                          tasks=[HOST_PIPELINE_TASK] if pipeline else ['subdomain_discovery'])

    @classmethod
    def host(cls, domain, name, scan=None):
        sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)
        match = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=sub, confidence=0.5, matched_product='nginx')
        OnDemandValidation.objects.create(match=match, project=domain.project)
        Vulnerability.objects.create(subdomain=sub, target_domain=domain, scan_history=scan, name=f'v {name}', severity=3, discovered_date=cls.now)
        return sub

    @classmethod
    def build(cls, project):
        full = cls.domain(project, 'full')
        before, old, new = cls.scan(full, pipeline=True), cls.scan(full), cls.scan(full)
        after, running = cls.scan(full, pipeline=True), cls.scan(full, status=1)
        for scan, name in ((before, 'www'), (old, 'www'), (old, 'gone'), (new, 'www'), (new, 'api'), (after, 'api'), (after, 'new'),
                           (running, 'running'), (None, 'ct'), (None, 'www')):
            cls.host(full, name, scan)
        pipe_only = cls.domain(project, 'pipe')
        p1, p2 = cls.scan(pipe_only, pipeline=True), cls.scan(pipe_only, pipeline=True)
        for scan, name in ((p1, 'one'), (p1, 'both'), (p2, 'both'), (None, 'ct')):
            cls.host(pipe_only, name, scan)
        failed = cls.domain(project, 'failed')
        f1, f2 = cls.scan(failed, status=0), cls.scan(failed, status=1)
        for scan, name in ((f1, 'www'), (f1, 'old'), (f2, 'www')):
            cls.host(failed, name, scan)
        manual = cls.domain(project, 'manual', manual=True)
        m_full = cls.scan(manual)
        for scan, name in ((None, 'listed'), (m_full, 'listed'), (m_full, 'probed')):
            cls.host(manual, name, scan)
        manual_unscanned = cls.domain(project, 'manual-new', manual=True)
        cls.host(manual_unscanned, 'listed')
        scanless = cls.domain(project, 'ct')
        cls.host(scanless, 'ct')

    def scopes(self):
        a, b, _c = (p.pk for p in self.projects)
        return {'one project': {a}, 'two projects': {a, b}, 'every project': None, 'no project': set(),
                'a member of one project': roles.allowed_project_ids(self.member), 'a user with no project': roles.allowed_project_ids(self.nobody)}

    def current_ids(self, model, prefix, manager='objects', path=None, projects=None):
        qs = getattr(model, manager).filter(latest_scan_q(prefix))
        if projects is not None:
            qs = qs.filter(**{path + '__in': sorted(projects)})
        return sorted(qs.values_list('id', flat=True))


class SameRowsInEveryScopeTests(World):
    def test_a_scoped_caller_reads_the_unrestricted_inventory_of_its_projects(self):
        everything = {model: dict(model._base_manager.filter(latest_scan_q(prefix)).values_list('id', path)) for model, prefix, path in READERS}
        for label, allowed in self.scopes().items():
            for model, prefix, path in READERS:
                with self.subTest(scope=label, model=model.__name__), scoped(allowed):
                    expected = sorted(pk for pk, pid in everything[model].items() if allowed is None or pid in allowed)
                    self.assertEqual(self.current_ids(model, prefix), expected)
                    # a read with the base manager that names the caller's projects itself (counts.machines, report_threats)
                    if allowed is not None:
                        self.assertEqual(self.current_ids(model, prefix, '_base_manager', path, allowed), expected)

    def test_the_same_rows_as_the_previous_domain_list(self):
        for label, allowed in self.scopes().items():
            for model, prefix, path in READERS:
                with self.subTest(scope=label, model=model.__name__), scoped(allowed):
                    new = self.current_ids(model, prefix)
                    with mock.patch.object(current_scans, 'current_scan_sets', previous_current_scan_sets):
                        old = self.current_ids(model, prefix)
                    self.assertEqual(new, old)
                    if allowed:
                        new = self.current_ids(model, prefix, '_base_manager', path, allowed)
                        with mock.patch.object(current_scans, 'current_scan_sets', previous_current_scan_sets):
                            old = self.current_ids(model, prefix, '_base_manager', path, allowed)
                        self.assertEqual(new, old)

    def test_the_cases_really_differ(self):
        """Sanity for the fixture: each project keeps its newest copies, drops the old ones, and every domain kind is present."""
        with scoped({self.projects[0].pk}):
            names = {(s.target_domain.name.split('.')[0], s.name) for s in Subdomain.objects.filter(latest_scan_q()).select_related('target_domain')}
        self.assertTrue({('full', 'www'), ('full', 'api'), ('full', 'new'), ('full', 'ct'), ('pipe', 'one'), ('pipe', 'both'), ('pipe', 'ct'),
                         ('failed', 'www'), ('failed', 'old'), ('manual', 'listed'), ('manual', 'probed'), ('manual-new', 'listed'), ('ct', 'ct')} <= names)
        self.assertFalse({('full', 'gone'), ('full', 'running')} & names)


class ScopedSetsTests(World):
    def test_a_scoped_read_lists_only_the_scopes_domains(self):
        a = self.projects[0].pk
        mine = {d.pk for d in self.domains[a]}
        with scoped({a}):
            sets = current_scans.current_scan_sets(connection)
        self.assertEqual(sets.unfull_domains, {d.pk for d in self.domains[a] if d.name.split('.')[0] in ('pipe', 'failed', 'manual-new', 'ct')})
        self.assertEqual(sets.full_domains, {d.pk for d in self.domains[a] if d.name.split('.')[0] in ('full', 'manual')})
        self.assertLessEqual(sets.current, set(ScanHistory.objects.filter(domain_id__in=mine).values_list('id', flat=True)))
        unrestricted = current_scans.current_scan_sets(connection)
        self.assertEqual(unrestricted.unfull_domains, {d.pk for ds in self.domains.values() for d in ds} - unrestricted.full_domains)

    def test_a_scope_with_no_project_reads_empty_sets(self):
        with scoped(set()):
            sets = current_scans.current_scan_sets(connection)
            self.assertEqual(Subdomain.objects.filter(latest_scan_q()).count(), 0)
        self.assertEqual(tuple(sets), (frozenset(),) * 5)

    def test_the_statement_carries_only_the_scopes_domains(self):
        a = self.projects[0].pk
        with scoped({a}):
            sets = current_scans.current_scan_sets(connection)
            _sql, params = Subdomain.objects.filter(latest_scan_q()).query.sql_with_params()
        literal = lambda ids: '{%s}' % ','.join(str(i) for i in sorted(ids))  # noqa: E731
        arrays = {p for p in params if isinstance(p, str) and p.startswith('{')}
        self.assertEqual(arrays, {literal(getattr(sets, name)) for name in ('current', 'after_full', 'unfull_domains', 'full_domains')})
        self.assertLessEqual(sets.unfull_domains | sets.full_domains, {d.pk for d in self.domains[a]})

    def test_inside_a_snapshot_each_scope_reads_its_own_sets_once(self):
        """The per-snapshot sharing stays (one read per scope for the block) and two scopes never share one read."""
        a, b = self.projects[0].pk, self.projects[1].pk
        reads = mock.Mock(wraps=current_scans.current_scan_sets)
        got = {}

        def compute():
            for allowed in ({a}, {b}, {a}, {a, b}, {b}):
                with scoped(allowed):
                    got.setdefault(frozenset(allowed), []).append(current_scans.sets_for_statement(connection))
                    list(Subdomain.objects.filter(latest_scan_q()).values_list('id', flat=True))
        with mock.patch.object(current_scans, 'current_scan_sets', reads):
            snapshot_cache._build(compute, None, '')
        self.assertEqual(reads.call_count, 3)  # one per distinct scope
        for allowed, seen in got.items():
            self.assertTrue(all(s is seen[0] for s in seen), allowed)
        domains = {pid: {d.pk for d in ds} for pid, ds in self.domains.items()}
        self.assertLessEqual(got[frozenset({a})][0].unfull_domains, domains[a])
        self.assertLessEqual(got[frozenset({b})][0].unfull_domains, domains[b])
        self.assertEqual(got[frozenset({a, b})][0].unfull_domains, got[frozenset({a})][0].unfull_domains | got[frozenset({b})][0].unfull_domains)

    def test_outside_a_snapshot_a_statement_of_another_scope_reads_again(self):
        a, b = self.projects[0].pk, self.projects[1].pk
        reads = mock.Mock(wraps=current_scans.current_scan_sets)
        with mock.patch.object(current_scans, 'current_scan_sets', reads):
            with scoped({a}):
                first = current_scans.sets_for_statement(connection)
            with scoped({b}):
                second = current_scans.sets_for_statement(connection)
        self.assertEqual(reads.call_count, 2)
        self.assertFalse(first.unfull_domains & second.unfull_domains)


class PagesSayTheSameTests(Seeded):
    """The Overview and the Situations list of one project read the same with the scoped domain list as with the previous one."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        # another project's domain with no full scan, and one of its hosts: the previous list named it as never fully scanned under A's scope
        unfull = Domain.objects.create(name='pipe.sb.test', project=cls.pb, insert_date=cls.now)
        scan = ScanHistory.objects.create(domain=unfull, scan_type=cls.engine, scan_status=2, start_scan_date=cls.now, tasks=[HOST_PIPELINE_TASK])
        sub = Subdomain.objects.create(target_domain=unfull, name='web0.sa.test', scan_history=scan, http_status=200)
        cls.match(sub, cls.exploit)

    def payloads(self, allowed, sets):
        cache.clear()
        with mock.patch.object(current_scans, 'current_scan_sets', sets), scoped(allowed), steady_caches():
            ids = sorted(Project.objects.values_list('id', flat=True))
            built = overview.build(ids, live={'hosts': 9, 'exposed_hosts': 4}, now=self.now)
            cache.clear()
            listed = situations.listing(ids)
        built = {k: v for k, v in built.items() if k != 'updated_at'}
        return json.loads(json.dumps([built, listed], default=str, sort_keys=True))

    def test_one_project_and_two_say_the_same(self):
        for allowed in ({self.pa.pk}, {self.pb.pk}, {self.pa.pk, self.pb.pk}, {self.empty.pk}, None):
            with self.subTest(allowed=allowed):
                self.assertEqual(self.payloads(allowed, current_scans.current_scan_sets), self.payloads(allowed, previous_current_scan_sets))
