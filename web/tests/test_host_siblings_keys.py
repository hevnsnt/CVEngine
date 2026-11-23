"""``counts.host_siblings`` works the host keys out from the address links in Python (``counts._host_keys``) instead of three correlated subqueries per
row in SQL (``with_host_key``), and answers exactly as before. The function as it was is copied below as the oracle and compared on the graph fixture
(other names on one address, a CDN address two names share, scanless rows, older scans) and on random inventories, under several scopes.

Measured on the production install for the 900 hosts the graph draws: the statement that keys the nearby rows read 59,600 buffers in 182 ms, the
form here 4,700 in 50 ms; the statement that keys the hosts asked about 38 ms, here 10 ms."""
import random

from django.db import connection
from django.db.models import Q
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import counts
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tenancy import scope
from tests.test_graph_payload_queries import build_world


def old_host_siblings(sub_ids):
    from cveFeed.correlation import latest_scan_q
    from cveFeed.counts import with_host_key
    sub_ids = list(sub_ids)
    if not sub_ids:
        return {}
    current = Subdomain.objects.filter(latest_scan_q())
    keyed = list(with_host_key(Subdomain.objects.filter(id__in=sub_ids)).values('id', 'name', 'target_domain__project_id', 'host_key'))
    names_by_key = {}
    through = Subdomain.ip_addresses.through
    near = Q(name__in={k['name'] for k in keyed}) | Q(id__in=through.objects.filter(
        ipaddress_id__in=through.objects.filter(subdomain_id__in=sub_ids).values('ipaddress_id')).values('subdomain_id'))
    for r in with_host_key(current.filter(near)).filter(host_key__in={k['host_key'] for k in keyed}).values('host_key', 'name'):
        names_by_key.setdefault(r['host_key'], set()).add(r['name'])
    wanted = {n for names in names_by_key.values() for n in names} | {k['name'] for k in keyed}
    rows = {}
    for r in current.filter(name__in=wanted).exclude(id__in=sub_ids).values('id', 'name', 'target_domain__project_id'):
        rows.setdefault((r['target_domain__project_id'], r['name']), []).append((r['id'], r['name']))
    out = {}
    for k in keyed:
        names = names_by_key.get(k['host_key'], set()) | {k['name']}
        out[k['id']] = sorted((row for n in names for row in rows.get((k['target_domain__project_id'], n), [])), key=lambda row: (row[1], row[0]))
    return out


def random_inventory(seed):
    """Two projects, a target each and one with no project, two scans a target, names that share addresses, CDN addresses, rows with none."""
    rng = random.Random(seed)
    now = timezone.now()
    engine = EngineType.objects.create(engine_name=f'rnd-engine-{seed}')
    org = Org.objects.create(name=f'rnd org {seed}', slug=f'rnd-org-{seed}')
    projects = [Project.objects.create(name=f'hs {seed} {i}', slug=f'rnd{seed}x{i}', insert_date=now, org=org) for i in range(2)]
    ips = [IpAddress.objects.create(address=f'172.16.{seed}.{i + 1}', is_cdn=rng.random() < 0.2) for i in range(12)]
    for t, project in enumerate(projects + [None]):
        domain = Domain.objects.create(name=f't{t}.hs{seed}.example.test', project=project, insert_date=now)
        scans = [ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2) for _ in range(2)]
        made = set()
        for h in range(10):
            name, scan = f'n{rng.randrange(6)}.t{t}.hs{seed}.example.test', rng.choice(scans + [None])
            if (name, scan) in made:  # one row per name in a scan (the table's own constraint)
                continue
            made.add((name, scan))
            sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan, http_status=200)
            sub.ip_addresses.add(*rng.sample(ips, rng.randrange(0, 4)))


class HostSiblingsEquivalenceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.world = build_world('hs', hosts=8)
        for seed in (1, 2, 3):
            random_inventory(seed)

    def compare(self, allowed, ids):
        tokens = scope.set_scope(allowed) if allowed is not None else None
        try:
            old, new = old_host_siblings(ids), counts.host_siblings(ids)
        finally:
            if tokens:
                scope.reset_scope(tokens)
        self.assertEqual(new, old)
        return new

    def test_the_same_answer_for_every_row_under_every_scope(self):
        ids = list(Subdomain.objects.order_by('id').values_list('id', flat=True))
        projects = self.world['projects']
        found = False
        for allowed in (None, {projects[0].id}, {projects[0].id, projects[2].id}, set()):
            for part in (ids, ids[::2], ids[1::2], ids[::3]):  # every row (each other name is then asked about itself) and some of them
                with self.subTest(allowed=allowed, rows=len(part)):
                    out = self.compare(allowed, part)
                    found = found or any(out.values())
        self.assertTrue(found, 'the fixture has hosts with other names')

    def test_the_same_answer_for_any_handful_of_rows(self):
        ids = list(Subdomain.objects.values_list('id', flat=True))
        rng = random.Random(7)
        for n in (1, 2, 5, 20):
            for _ in range(5):
                with self.subTest(n=n):
                    self.compare(None, rng.sample(ids, n))
        self.assertEqual(counts.host_siblings([]), {})

    def test_no_correlated_address_set_and_no_more_statements(self):
        ids = list(Subdomain.objects.values_list('id', flat=True))
        counts.host_siblings(ids)
        with CaptureQueriesContext(connection) as new:
            counts.host_siblings(ids)
        with CaptureQueriesContext(connection) as old:
            old_host_siblings(ids)
        self.assertEqual(len(new), len(old))
        self.assertFalse(any('STRING_AGG' in q['sql'] for q in new.captured_queries))
        self.assertTrue(any('STRING_AGG' in q['sql'] for q in old.captured_queries))
