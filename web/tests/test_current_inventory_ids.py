"""``correlation.latest_scan_q`` reads the current scan ids once (cveFeed.current_scans) and passes them as array literals, instead of embedding
three subqueries over the finished scans in every statement. The rows must be the same as before in every state of the scans: this file keeps the
previous definition as the oracle and compares both on hosts and on the matches and validation requests that reach a host through a prefix.
"""
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import current_scans
from cveFeed.correlation import latest_scan_q
from cveFeed.discovery import HOST_PIPELINE_TASK
from cveFeed.models import CVEEntry, CVEMatch, OnDemandValidation
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


def previous_latest_scan_q(prefix=""):
    """``latest_scan_q`` as it was before this change (the window form), kept here as the oracle."""
    from django.db.models import Case, Exists, F, Max, OuterRef, Q, Value, When, Window

    done = ScanHistory.objects.filter(scan_status=2)
    full = done.exclude(tasks__contains=[HOST_PIPELINE_TASK])
    latest_full = full.values("domain_id").annotate(last=Max("id")).values("last")
    is_full = ~Q(tasks__contains=[HOST_PIPELINE_TASK])
    after_full = (done.annotate(_newest_full=Window(Max(Case(When(is_full, then=F("id")))), partition_by=[F("domain_id")]),
                                _is_pipeline=Window(Max(Case(When(is_full, then=Value(0)), default=Value(1))), partition_by=[F("id")]))
                  .filter(_is_pipeline=1).filter(Q(_newest_full__isnull=True) | Q(id__gt=F("_newest_full"))).values("id"))
    same_host = Subdomain.objects.filter(target_domain_id=OuterRef(prefix + "target_domain_id"), name=OuterRef(prefix + "name"))
    newer_row = same_host.filter(scan_history_id__in=after_full, scan_history_id__gt=OuterRef(prefix + "scan_history_id"))
    newer_fallback = same_host.filter(scan_history__isnull=False, id__gt=OuterRef(prefix + "id"))
    return ((Q(**{prefix + "scan_history_id__in": latest_full}) | Q(**{prefix + "scan_history_id__in": after_full})
             | Q(**{prefix + "scan_history__isnull": True})
             | ~Q(**{prefix + "target_domain_id__in": full.values("domain_id")}))
            & ~Q(Exists(newer_row))
            & (Q(**{prefix + "scan_history__isnull": True}) | Q(**{prefix + "target_domain_id__in": full.values("domain_id")})
               | ~Q(Exists(newer_fallback))))


class World(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.now = timezone.now()
        org = Org.objects.create(name='CI', slug='ci-org')
        cls.project = Project.objects.create(name='CI', slug='ci-proj', insert_date=cls.now, org=org)
        cls.engine = EngineType.objects.create(engine_name='ci')
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7001', cvss=9.8, published_at=cls.now)

    def domain(self, name):
        return Domain.objects.create(name=name, project=self.project, insert_date=self.now)

    def scan(self, domain, status=2, pipeline=False):
        return ScanHistory.objects.create(start_scan_date=self.now, scan_status=status, domain=domain, scan_type=self.engine,
                                          tasks=[HOST_PIPELINE_TASK] if pipeline else ['subdomain_discovery'])

    def host(self, domain, name, scan=None):
        sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)
        match = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, confidence=0.5, matched_product='nginx')
        OnDemandValidation.objects.create(match=match, project=self.project)
        return sub

    def assertSameAnswer(self):
        for prefix, manager in (('', Subdomain._base_manager), ('subdomain__', CVEMatch._base_manager),
                                ('match__subdomain__', OnDemandValidation._base_manager)):
            new = sorted(manager.filter(latest_scan_q(prefix)).values_list('id', flat=True))
            old = sorted(manager.filter(previous_latest_scan_q(prefix)).values_list('id', flat=True))
            self.assertEqual(new, old, prefix or 'hosts')
        return set(Subdomain.objects.filter(latest_scan_q()).values_list('name', flat=True))

    def build(self):
        """Every case the definition distinguishes, on separate domains."""
        a, b, c, d, e, f, g = (self.domain(f'{n}.ci.example.test') for n in 'abcdefg')
        # a: host-pipeline scans before and after several full scans, a failed and a running full scan after them, the same host in many scans
        a_pipe_before = self.scan(a, pipeline=True)
        a_full_old = self.scan(a)
        a_pipe_between = self.scan(a, pipeline=True)
        a_full = self.scan(a)
        a_pipe_after, a_pipe_after2 = self.scan(a, pipeline=True), self.scan(a, pipeline=True)
        a_failed, a_running = self.scan(a, status=0), self.scan(a, status=1)
        a_pipe_running = self.scan(a, status=1, pipeline=True)
        for scan, name in ((a_pipe_before, 'www.a'), (a_pipe_before, 'old.a'), (a_full_old, 'www.a'), (a_full_old, 'gone.a'),
                           (a_pipe_between, 'between.a'), (a_full, 'www.a'), (a_full, 'api.a'), (a_full, 'mail.a'),
                           (a_pipe_after, 'api.a'), (a_pipe_after, 'new.a'), (a_pipe_after2, 'api.a'), (a_failed, 'failed.a'),
                           (a_running, 'www.a'), (a_running, 'running.a'), (a_pipe_running, 'mail.a'), (None, 'ct.a'), (None, 'www.a')):
            self.host(a, name, scan)
        # b: only host-pipeline scans (no full scan), the same host in two of them, then a scanless row
        b1, b2 = self.scan(b, pipeline=True), self.scan(b, pipeline=True)
        for scan, name in ((b1, 'one.b'), (b1, 'both.b'), (b2, 'both.b'), (None, 'ct.b')):
            self.host(b, name, scan)
        # c: a first full scan still running, and one that failed: the newest copy of each host stays
        c_failed, c_running = self.scan(c, status=0), self.scan(c, status=1)
        for scan, name in ((c_failed, 'www.c'), (c_failed, 'old.c'), (c_running, 'www.c'), (c_running, 'new.c')):
            self.host(c, name, scan)
        # d: scanless rows only
        self.host(d, 'ct.d')
        self.host(d, 'ct2.d')
        # e: two full scans, the newer wins; a host-pipeline scan after them with a host of the older one only
        e1, e2 = self.scan(e), self.scan(e)
        e_pipe = self.scan(e, pipeline=True)
        for scan, name in ((e1, 'x.e'), (e1, 'only-old.e'), (e2, 'x.e'), (e2, 'y.e'), (e_pipe, 'only-old.e')):
            self.host(e, name, scan)
        # f: a full scan whose tasks are NULL counts as full (the host-pipeline scan before it is not current)
        f_pipe_before = self.scan(f, pipeline=True)
        f_null = self.scan(f)
        ScanHistory.objects.filter(pk=f_null.pk).update(tasks=None)
        for scan, name in ((f_null, 'www.f'), (f_pipe_before, 'www.f'), (f_pipe_before, 'late.f')):
            self.host(f, name, scan)
        # g: a domain with nothing yet
        # a match with no host, and a host with no domain
        CVEMatch.objects.create(cve_entry=self.cve, subdomain=None, confidence=0.5, matched_product='nginx')
        self.host(None, 'orphan.example.test', None)
        return locals()


class SameAnswerTests(World):
    def test_every_state_gives_the_rows_of_the_previous_definition(self):
        self.build()
        names = self.assertSameAnswer()
        # sanity: the cases above really are current, and these are not
        self.assertTrue({'www.a', 'api.a', 'mail.a', 'new.a', 'ct.a', 'one.b', 'both.b', 'ct.b', 'www.c', 'old.c', 'new.c', 'ct.d', 'ct2.d',
                         'x.e', 'y.e', 'only-old.e', 'www.f', 'orphan.example.test'} <= names)
        self.assertFalse({'old.a', 'gone.a', 'between.a', 'failed.a', 'running.a', 'late.f'} & names)

    def test_the_answer_follows_each_state_change(self):
        """The sets are read when the filter is built: each change of a scan shows in the next call."""
        world = self.build()
        a = world['a']
        ScanHistory.objects.filter(pk=world['a_running'].pk).update(scan_status=2)  # the running full scan finishes: it replaces the inventory
        names = self.assertSameAnswer()
        self.assertIn('running.a', names)
        self.assertNotIn('new.a', names)
        later = self.scan(a, pipeline=True)                                          # a new host-pipeline scan after it
        self.host(a, 'later.a', later)
        self.assertIn('later.a', self.assertSameAnswer())
        ScanHistory.objects.filter(pk=world['c_running'].pk).update(scan_status=2)  # the first full scan of c finishes
        names = self.assertSameAnswer()
        self.assertNotIn('old.c', names)
        ScanHistory.objects.filter(pk=world['e2'].pk).delete()                        # the newest full scan of e is deleted
        names = self.assertSameAnswer()
        self.assertIn('only-old.e', names)
        ScanHistory.objects.filter(domain=world['b']).update(tasks=None)              # b's scans become full scans
        self.assertSameAnswer()

    def test_no_finished_scan_at_all(self):
        d = self.domain('none.ci.example.test')
        self.host(d, 'www.none', self.scan(d, status=1))
        self.host(d, 'ct.none')
        self.assertEqual(self.assertSameAnswer(), {'www.none', 'ct.none'})


class ShapeTests(World):
    def test_the_sets_are_read_in_one_statement_over_the_partial_indexes(self):
        self.build()
        with CaptureQueriesContext(connection) as queries:
            latest_scan_q()
        self.assertEqual(len(queries.captured_queries), 1)
        sql = queries.captured_queries[0]['sql']
        with connection.cursor() as cursor:
            cursor.execute('SET LOCAL enable_seqscan = off')  # the tables are tiny: make the planner show whether it CAN use the indexes
            cursor.execute('EXPLAIN ' + sql)
            plan = '\n'.join(row[0] for row in cursor.fetchall())
        self.assertIn('scan_done_full_idx', plan)
        self.assertIn('scan_done_pipe_idx', plan)

    def test_the_statement_carries_ids_not_scan_subqueries(self):
        self.build()
        sql = str(Subdomain.objects.filter(latest_scan_q()).query)
        self.assertIn('= ANY(', sql)
        self.assertNotIn('startScan_scanhistory', sql)  # no subquery over the scans is left in the statement
        self.assertNotIn('OVER (', sql)

    def test_the_index_condition_names_the_host_pipeline_task(self):
        conditions = {index.name: str(index.condition) for index in ScanHistory._meta.indexes if index.condition is not None}
        self.assertIn(HOST_PIPELINE_TASK, conditions['scan_done_full_idx'])
        self.assertIn(HOST_PIPELINE_TASK, conditions['scan_done_pipe_idx'])

    def test_an_empty_id_set_matches_nothing(self):
        d = self.domain('empty.ci.example.test')
        self.host(d, 'www.empty', self.scan(d, status=1))
        self.assertFalse(Subdomain.objects.filter(scan_history_id__in_id_array=frozenset()).exists())
        self.assertTrue(Subdomain.objects.filter(target_domain_id__in_id_array={d.id}).exists())
        self.assertEqual(current_scans.current_scan_sets().latest_full, frozenset())
