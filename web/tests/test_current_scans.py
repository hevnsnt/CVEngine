"""``correlation.latest_scan_q``, the "which scans are current" filter every host statement embeds (the status inventory, the host list and search,
the dashboard counts, the live snapshots), no longer walks every finished scan of a domain for each host-pipeline scan.

Before: a host-pipeline scan was current when ``id > COALESCE((the newest full scan of its domain), 0)``, a subquery run once per finished host-pipeline
scan that read every finished scan of the domain. On an install with 3,332 of them on a few domains (170 each) that was 590,000 row visits, 157,000 buffer
hits and 1.4 s each time the set was built, once or twice in every host statement: the system status's project rows took 4.5 to 15 s each.
Now: one window over the finished scans gives each its domain's newest full scan, nothing correlated. The answer is the same.
"""
import json
from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.utils import timezone

from cveFeed.correlation import latest_scan_q
from cveFeed.discovery import HOST_PIPELINE_TASK
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class World(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='CS', slug='cs-org')
        cls.project = Project.objects.create(name='CS', slug='cs-proj', insert_date=now, org=org)
        cls.engine = EngineType.objects.create(engine_name='cs')
        cls.now = now

    def domain(self, name):
        return Domain.objects.create(name=name, project=self.project, insert_date=self.now)

    def scan(self, domain, status=2, pipeline=False, tasks=None):
        return ScanHistory.objects.create(start_scan_date=self.now, scan_status=status, domain=domain, scan_type=self.engine,
                                          tasks=tasks if tasks is not None else ([HOST_PIPELINE_TASK] if pipeline else []))

    def host(self, domain, name, scan=None):
        return Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)


def previous_latest_scan_q(prefix=""):
    """``latest_scan_q`` as it was before: the host-pipeline scans after the full scan found by a subquery per scan. Kept here as the oracle."""
    from django.db.models import Exists, F, Max, OuterRef, Q, Subquery
    from django.db.models.functions import Coalesce
    done = ScanHistory.objects.filter(scan_status=2)
    full = done.exclude(tasks__contains=[HOST_PIPELINE_TASK])
    latest_full = full.values("domain_id").annotate(last=Max("id")).values("last")
    newest_full_of = full.filter(domain_id=OuterRef("domain_id")).order_by("-id").values("id")[:1]
    after_full = done.filter(tasks__contains=[HOST_PIPELINE_TASK]).annotate(
        full_id=Coalesce(Subquery(newest_full_of), 0)).filter(id__gt=F("full_id")).values("id")
    same_host = Subdomain.objects.filter(target_domain_id=OuterRef(prefix + "target_domain_id"), name=OuterRef(prefix + "name"))
    newer_row = same_host.filter(scan_history_id__in=after_full, scan_history_id__gt=OuterRef(prefix + "scan_history_id"))
    newer_fallback = same_host.filter(scan_history__isnull=False, id__gt=OuterRef(prefix + "id"))
    return ((Q(**{prefix + "scan_history_id__in": latest_full}) | Q(**{prefix + "scan_history_id__in": after_full})
             | Q(**{prefix + "scan_history__isnull": True}) | ~Q(**{prefix + "target_domain_id__in": full.values("domain_id")}))
            & ~Q(Exists(newer_row))
            & (Q(**{prefix + "scan_history__isnull": True}) | Q(**{prefix + "target_domain_id__in": full.values("domain_id")}) | ~Q(Exists(newer_fallback))))


class SameAnswerTests(World):
    def test_the_current_hosts_are_those_of_the_previous_definition(self):
        a, b, c, d, e = (self.domain(f'{n}.cs.example.test') for n in 'abcde')
        a_before = self.scan(a, pipeline=True)            # before the domain's full scan
        a_full = self.scan(a)
        a_after, a_after2 = self.scan(a, pipeline=True), self.scan(a, pipeline=True)
        a_failed = self.scan(a, status=0)                 # not finished
        b1, b2 = self.scan(b, pipeline=True), self.scan(b, pipeline=True)  # a domain with only host-pipeline scans
        b_null = self.scan(b)                             # ... then a full scan whose tasks are NULL
        ScanHistory.objects.filter(pk=b_null.pk).update(tasks=None)
        b3 = self.scan(b, pipeline=True)
        c_queued = self.scan(c, status=-1)                # no finished scan at all
        e_full1, e_full2 = self.scan(e), self.scan(e)     # two full scans: only the newer is current
        self.scan(e, pipeline=True)
        for scan, name in ((a_before, 'old.a'), (a_full, 'www.a'), (a_full, 'full.a'), (a_after, 'new.a'), (a_after2, 'www.a'), (a_failed, 'failed.a'),
                           (b1, 'one.b'), (b2, 'two.b'), (b_null, 'full.b'), (b3, 'three.b'), (c_queued, 'only.c'), (None, 'ct.a'),
                           (e_full1, 'x.e'), (e_full2, 'x.e'), (e_full2, 'y.e')):
            self.host(a if name.endswith('.a') else b if name.endswith('.b') else c if name.endswith('.c') else e, name, scan)
        self.host(d, 'ct.d', None)
        new = set(Subdomain.objects.filter(latest_scan_q()).values_list('id', flat=True))
        old = set(Subdomain.objects.filter(previous_latest_scan_q()).values_list('id', flat=True))
        self.assertEqual(new, old)
        names = set(Subdomain.objects.filter(pk__in=new).values_list('name', flat=True))
        self.assertTrue({'new.a', 'ct.a', 'three.b', 'full.b', 'only.c', 'ct.d', 'y.e'} <= names)  # sanity: the cases above really are current
        self.assertFalse({'old.a', 'failed.a', 'one.b'} & names)                                   # and these are not


class PlanTests(World):
    def test_building_the_set_does_not_walk_every_scan_of_a_domain_per_host_pipeline_scan(self):
        """3,300 finished host-pipeline scans on 20 domains (165 each) and a few full scans: the old form read 22,000 buffers here (157,000 on the install that reported it)."""
        domains = [self.domain(f'p{i}.cs.example.test') for i in range(20)] + [self.domain(f'q{i}.cs.example.test') for i in range(200)]
        scans = [ScanHistory(start_scan_date=self.now - timedelta(minutes=i), scan_status=2, domain=d, scan_type=self.engine, tasks=[HOST_PIPELINE_TASK])
                 for d in domains[:20] for i in range(165)]
        scans += [ScanHistory(start_scan_date=self.now, scan_status=2, domain=d, scan_type=self.engine, tasks=[]) for d in domains]
        ScanHistory.objects.bulk_create(scans)
        Subdomain.objects.bulk_create([Subdomain(name=f'h.{s.domain.name}', target_domain=s.domain, scan_history=s) for s in ScanHistory.objects.select_related('domain')])
        with connection.cursor() as cursor:
            cursor.execute('ANALYZE "startScan_scanhistory"')
            cursor.execute('ANALYZE "startScan_subdomain"')  # the plan depends on the statistics of every table in it, and autovacuum has not seen these rows yet: without this it flipped at random
            cursor.execute('ANALYZE "targetApp_domain"')
        qs = Subdomain.objects.filter(latest_scan_q())
        sql, params = qs.query.sql_with_params()
        with connection.cursor() as cursor:
            cursor.execute('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + sql, params)
            plan = cursor.fetchone()[0]
        plan = plan if isinstance(plan, list) else json.loads(plan)
        hits = plan[0]['Plan'].get('Shared Hit Blocks', 0) + plan[0]['Plan'].get('Shared Read Blocks', 0)
        
        self.assertLess(hits, 5000, f'{hits} buffers')  # 563 now; 22,435 and 139 ms with the old form
        self.assertNotIn('COALESCE((SELECT', sql.replace('\n', ' '))
