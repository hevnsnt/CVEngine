"""The per-process CVE pool (cveFeed.correlation.cve_pool, local_pool): a feed sync that touches a few rows refreshes the cached pool from those
rows only, and the refreshed pool equals a pool built from scratch, entry for entry, token for token and in the same order."""
import random
import sys
import threading
from datetime import timedelta
from unittest import mock

from django.db import connection, connections
from django.test import TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import correlation, edge_builds, java_runtime, version_sources, windows_builds
from cveFeed.models import CVEEntry
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain

PRODUCTS = [
    {'vendor': 'f5', 'product': 'nginx'}, {'vendor': 'apache', 'product': 'http_server'}, {'vendor': 'openssl', 'product': 'openssl'},
    {'vendor': 'craftcms', 'product': 'cms'}, {'product': 'jquery', 'package': 'jquery'}, {'vendor': 'n/a', 'product': 'Apache Tomcat'},
    {'vendor': 'oracle', 'product': 'mysql'}, {'vendor': 'php', 'product': 'php'}, {'vendor': 'wordpress', 'product': 'wordpress'},
    {'vendor': 'openbsd', 'product': 'openssh'}, {'vendor': 'microsoft', 'product': 'exchange_server'}, {'product': 'redis'},
]
FIELDS = ('cve_id', 'affected', 'kev', 'epss_reached', 'exploit_db', 'cvss', 'cvss_vector', 'published_at', 'local_only')
T0 = timezone.now() - timedelta(days=10)


def _affected(rnd):
    out = []
    for item in rnd.sample(PRODUCTS, rnd.randint(0, 3)):
        lo = rnd.randint(0, 3)
        out.append({**item, 'ranges': [{'introduced': f'{lo}.0', 'fixed': f'{lo + rnd.randint(1, 3)}.{rnd.randint(0, 9)}'}]})
    if rnd.random() < 0.1:
        out.append('not a dict')  # what clean_affected drops
    return out


def snapshot(pool):
    """Everything a pool holds, in a comparable form: the entries in order with their fields, and the index token for token."""
    cve_by_id, index = pool
    entries = [(cid, tuple(getattr(cve, f) for f in FIELDS)) for cid, cve in cve_by_id.items()]
    return entries, {token: frozenset(ids) for token, ids in index.items()}


def scratch(cache, build):
    """The pool a from-scratch build gives now, leaving the cached one in place."""
    saved = dict(cache)
    try:
        cache.update(key=None, value=None, state=None)
        return build()
    finally:
        cache.clear()
        cache.update(saved)


class Clock:
    """A feed writer's clock: every write stamps synced_at later than the one before, as production's timezone.now() does."""

    def __init__(self):
        self.now = T0

    def tick(self):
        self.now += timedelta(hours=1)
        return self.now


class PoolTestMixin:
    def setUp(self):
        super().setUp()
        for cache in (correlation._INDEX_CACHE, correlation._LOCAL_CACHE):
            cache.clear()
            cache.update(key=None, value=None)
        self.clock = Clock()

    def make(self, rnd, n, **extra):
        made = []
        for _ in range(n):
            cve = CVEEntry.objects.create(cve_id=f'CVE-2099-{rnd.randint(1, 10 ** 9)}', affected=_affected(rnd), kev=rnd.random() < 0.2,
                                          cvss=round(rnd.uniform(1, 10), 1),
                                          published_at=None if rnd.random() < 0.1 else T0 - timedelta(days=rnd.randint(0, 3)),
                                          **extra)
            made.append(cve)
        CVEEntry.objects.filter(pk__in=[c.pk for c in made]).update(synced_at=self.clock.tick())
        return made

    def age(self, made):
        """Stamp the rows as a table synced over the past: one an hour back from T0, the first row newest."""
        for i, cve in enumerate(made):
            CVEEntry.objects.filter(pk=cve.pk).update(synced_at=T0 - timedelta(hours=i + 1))


class EquivalenceTests(PoolTestMixin, TestCase):
    """After any sequence of adds, updates, status flips, locality flips and deletions, the refreshed pool equals a full build."""

    def _op(self, rnd):
        ids = list(CVEEntry.objects.values_list('pk', flat=True))
        pick = CVEEntry.objects.filter(pk=rnd.choice(ids))
        op = rnd.choice(['add', 'affected', 'published', 'reject', 'unreject', 'local', 'unlocal', 'delete', 'kev', 'touch'])
        if op == 'add':
            self.make(rnd, rnd.randint(1, 3))
        elif op == 'affected':
            pick.update(affected=_affected(rnd), synced_at=self.clock.tick())
        elif op == 'published':
            pick.update(published_at=T0 - timedelta(days=rnd.randint(0, 3), hours=rnd.randint(0, 5)), synced_at=self.clock.tick())
        elif op == 'reject':  # the feed's status write stamps synced_at (cveFeed.tasks)
            pick.update(status='REJECTED', synced_at=self.clock.tick())
        elif op == 'unreject':
            pick.update(status='PUBLISHED', synced_at=self.clock.tick())
        elif op == 'local':  # cveFeed.locality writes local_only without moving synced_at
            pick.filter(local_only=False).update(local_only=True)
        elif op == 'unlocal':
            pick.filter(local_only=True).update(local_only=False)
        elif op == 'delete':
            pick.delete()
        elif op == 'kev':
            pick.update(kev=True, cvss=9.9, synced_at=self.clock.tick())
        else:  # a re-check that only stamps the row (cveFeed.tasks)
            pick.update(synced_at=self.clock.tick())
        return op

    def _check(self, cache, build, label):
        with mock.patch.object(correlation, '_full', wraps=correlation._full) as full:
            pool = build()
        self.assertEqual(full.call_count, 0, f'{label}: a full build ran where a refresh should have')
        pool[1].candidate_tokens('nginx')  # the word map is built from the refreshed index's own tokens when it was not patched
        fresh = scratch(cache, build)
        fresh[1].candidate_tokens('nginx')
        self.assertEqual(snapshot(pool), snapshot(fresh), label)
        self.assertEqual(list(pool[0]), list(fresh[0]), f'{label}: entry order')
        self.assertEqual(sorted(pool[1]), sorted(fresh[1]), f'{label}: product keys')
        self.assertEqual(pool[1]._by_word, fresh[1]._by_word, f'{label}: word map')
        return pool

    def test_random_sequences_refresh_to_the_full_build(self):
        keys = set()
        for seed in range(4):
            rnd = random.Random(seed)
            self.make(rnd, 40)
            self.make(rnd, 6, local_only=True)
            correlation.cve_pool()[1].candidate_tokens('nginx')  # the patched word map is checked too
            correlation.local_pool()[1].candidate_tokens('nginx')
            for step in range(25):
                op = self._op(rnd)
                if not CVEEntry.objects.exists():
                    break
                label = f'seed {seed} step {step} {op}'
                self._check(correlation._INDEX_CACHE, correlation.cve_pool, label)
                self._check(correlation._LOCAL_CACHE, correlation.local_pool, label)
                keys.add((correlation._INDEX_CACHE['key'], correlation._LOCAL_CACHE['key']))
            CVEEntry.objects.all().delete()
            for cache in (correlation._INDEX_CACHE, correlation._LOCAL_CACHE):
                cache.update(key=None, value=None)
        self.assertGreater(len(keys), 60, 'too few of the steps moved a key, so too few refreshes were compared')

    def test_old_pool_is_never_changed_by_a_refresh(self):
        rnd = random.Random(7)
        made = self.make(rnd, 30)
        old = correlation.cve_pool()
        old[1].candidate_tokens('nginx')
        before = snapshot(old), {w: frozenset(t) for w, t in old[1]._by_word.items()}
        CVEEntry.objects.filter(pk=made[0].pk).update(affected=[{'product': 'brandnewproduct'}], synced_at=self.clock.tick())
        CVEEntry.objects.filter(pk=made[1].pk).update(status='REJECTED', synced_at=self.clock.tick())
        new = correlation.cve_pool()
        self.assertIsNot(new, old)
        self.assertIn('brandnewproduct', new[1])
        self.assertEqual((snapshot(old), {w: frozenset(t) for w, t in old[1]._by_word.items()}), before)


class CorrelationResultTests(PoolTestMixin, TestCase):
    """The rows correlation makes for a set of hosts are the same with a refreshed pool as with a freshly built one."""

    def setUp(self):
        super().setUp()
        org = Org.objects.create(name='A', slug='a')
        project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='pool.test', project=project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
        self.hosts = []
        for i, (tech, product, version) in enumerate([('nginx', None, '1.2'), ('jquery', 'Apache httpd', '2.1'), ('wordpress', 'OpenSSH', '1.5'),
                                                      ('php', 'MySQL', '3.0'), (None, 'Redis', '0.5'), ('Apache Tomcat', None, '2.0')]):
            sub = Subdomain.objects.create(name=f'h{i}.pool.test', target_domain=domain, scan_history=scan)
            if tech:
                sub.technologies.add(Technology.objects.get_or_create(name=f'{tech}:{version}')[0])
            if product:
                ip = IpAddress.objects.create(address=f'192.0.2.{i + 1}')
                sub.ip_addresses.add(ip)
                ip.ports.add(Port.objects.create(number=80 + i, product=product, version=version))
            self.hosts.append(sub)

    def _rows(self, pool):
        cve_by_id, index = pool
        out = []
        for sub in Subdomain.objects.filter(pk__in=[h.pk for h in self.hosts]).prefetch_related('technologies', 'ip_addresses__ports'):
            rows = correlation.collect_subdomain_matches(sub, index, cve_by_id, 0.0, None, [])
            out.extend(repr(sorted((k, getattr(v, 'pk', v)) for k, v in row.items())) for row in rows)
        return sorted(out)

    def test_refreshed_pool_correlates_like_a_full_build(self):
        rnd = random.Random(3)
        made = self.make(rnd, 60)
        correlation.cve_pool()
        seen = 0
        for step, cve in enumerate(made[:20]):
            q = CVEEntry.objects.filter(pk=cve.pk)
            if step % 4 == 0:
                q.update(affected=_affected(rnd), synced_at=self.clock.tick())
            elif step % 4 == 1:
                q.update(status='REJECTED', synced_at=self.clock.tick())
            elif step % 4 == 2:
                q.update(local_only=True)
            else:
                q.delete()
                self.make(rnd, 2)
            with mock.patch.object(correlation, '_full', wraps=correlation._full) as full:
                pool = correlation.cve_pool()
            self.assertEqual(full.call_count, 0)
            rows = self._rows(pool)
            self.assertEqual(rows, self._rows(scratch(correlation._INDEX_CACHE, correlation.cve_pool)), f'step {step}')
            seen += len(rows)
        self.assertGreater(seen, 0, 'the fixture made no match at all, so it compared nothing')


class RefreshCostTests(PoolTestMixin, TestCase):
    def test_a_sync_touching_n_rows_reads_n_rows_not_the_table(self):
        rnd = random.Random(1)
        made = self.make(rnd, 400)
        self.age(made)  # the newest stamp is made[0]'s, so the overlap reads nothing that was not touched again
        correlation.cve_pool()
        touched = made[:7]
        for cve in touched:
            CVEEntry.objects.filter(pk=cve.pk).update(affected=[{'product': 'nginx', 'ranges': [{'fixed': '9.0'}]}], synced_at=self.clock.tick())
        loaded = []

        def counting(qs, sleep):
            out = real(qs, sleep)
            loaded.append(len(out))
            return out
        real = correlation._load_rows
        with mock.patch.object(correlation, '_load_rows', counting), CaptureQueriesContext(connection) as ctx:
            cve_by_id, index = correlation.cve_pool()
        self.assertEqual(loaded, [7])
        # the stamp, the ids of the pool, and the changed rows
        self.assertEqual(len(ctx), 3, [q['sql'][:120] for q in ctx])
        self.assertEqual(len(cve_by_id), 400)
        self.assertTrue({c.pk for c in touched} <= index['nginx'])

    def test_unchanged_table_reuses_the_cached_pool_with_one_query(self):
        self.make(random.Random(2), 20)
        first = correlation.cve_pool()
        with CaptureQueriesContext(connection) as ctx:
            again = correlation.cve_pool()
        self.assertIs(again, first)
        self.assertEqual(len(ctx), 1)
        first_local = correlation.local_pool()
        self.assertIs(correlation.local_pool(), first_local)

    def test_count_changes_move_the_key_even_when_synced_at_does_not(self):
        rnd = random.Random(4)
        made = self.make(rnd, 20)
        pool = correlation.cve_pool()
        # a row written with an old stamp: only the count moves, and the ids find it
        late = self.make(rnd, 1)[0]
        CVEEntry.objects.filter(pk=late.pk).update(synced_at=T0)
        self.assertIn(late.pk, correlation.cve_pool()[0])
        CVEEntry.objects.filter(pk=made[0].pk).delete()
        self.assertNotIn(made[0].pk, correlation.cve_pool()[0])
        CVEEntry.objects.filter(pk=made[1].pk).update(local_only=True)  # the locality count moves
        self.assertNotIn(made[1].pk, correlation.cve_pool()[0])
        self.assertIn(made[1].pk, correlation.local_pool()[0])
        self.assertIsNot(correlation.cve_pool(), pool)

    def test_full_build_on_reset_on_a_stamp_moving_back_and_after_the_full_interval(self):
        rnd = random.Random(5)
        made = self.make(rnd, 10)
        with mock.patch.object(correlation, '_full', wraps=correlation._full) as full:
            correlation.cve_pool()
            self.assertEqual(full.call_count, 1)
            CVEEntry.objects.filter(pk=made[0].pk).update(synced_at=self.clock.tick())
            correlation.cve_pool()
            self.assertEqual(full.call_count, 1)  # refreshed
            CVEEntry.objects.filter(pk=made[0].pk).update(synced_at=T0)  # the newest stamp went back: rebuilt whole
            correlation.cve_pool()
            self.assertEqual(full.call_count, 2)
            with mock.patch.object(correlation, 'POOL_FULL_EVERY_S', 0):
                CVEEntry.objects.filter(pk=made[1].pk).update(synced_at=self.clock.tick())
                correlation.cve_pool()
            self.assertEqual(full.call_count, 3)
            correlation._INDEX_CACHE.update(key=None, value=None)  # what the other test modules do
            correlation.cve_pool()
            self.assertEqual(full.call_count, 4)
            correlation.cve_pool(cve_limit=5)  # a capped pool is always built whole
            self.assertEqual(full.call_count, 5)

    def test_each_build_logs_one_info_line(self):
        made = self.make(random.Random(6), 5)
        self.age(made)
        with self.assertLogs('cveFeed.correlation', 'INFO') as logs:
            correlation.cve_pool()
            CVEEntry.objects.filter(pk=made[0].pk).update(synced_at=self.clock.tick())
            correlation.cve_pool()
            correlation.cve_pool()
        lines = [line for line in logs.output if 'cve pool' in line]
        self.assertEqual(len(lines), 2, lines)
        self.assertIn('cve pool cve full: 5 entries, 5 rows read', lines[0])
        self.assertIn('cve pool cve refresh: 5 entries, 1 rows read', lines[1])
        self.assertIn('pid ', lines[1])


class GeventYieldTests(PoolTestMixin, TestCase):
    def test_no_gevent_outside_a_gevent_worker_and_never_imported(self):
        with mock.patch.dict(sys.modules):
            sys.modules.pop('gevent.monkey', None)
            self.assertIsNone(correlation._gevent_sleep())
            self.assertNotIn('gevent.monkey', sys.modules)

    def test_a_patched_process_yields(self):
        monkey, gevent = mock.Mock(), mock.Mock()
        monkey.is_module_patched.return_value = True
        with mock.patch.dict(sys.modules, {'gevent.monkey': monkey, 'gevent': gevent}):
            self.assertIs(correlation._gevent_sleep(), gevent.sleep)
        monkey.is_module_patched.return_value = False
        with mock.patch.dict(sys.modules, {'gevent.monkey': monkey, 'gevent': gevent}):
            self.assertIsNone(correlation._gevent_sleep())

    def test_a_build_yields_every_n_rows(self):
        self.make(random.Random(8), 9)
        sleeps = []
        with mock.patch.object(correlation, '_gevent_sleep', return_value=sleeps.append), mock.patch.object(correlation, 'POOL_YIELD_ROWS', 2):
            correlation.cve_pool()
            correlation.local_pool()
        self.assertEqual(sleeps, [0] * 8)  # four while reading the 9 rows, four while indexing them; nothing for the empty local pool


class PoolMemoTests(TestCase):
    """The pool memos of the modules that walk a whole pool are kept per pool object, not per id and size: a refreshed pool of the same size
    can reuse a freed pool's id."""

    def test_same_size_pool_is_read_again(self):
        def cve(pk):
            return CVEEntry(pk=pk, cve_id=f'CVE-2099-{pk}', affected=[{'vendor': 'oracle', 'product': 'jdk', 'ranges': [{'fixed': '9'}]}])
        for pk in range(1, 30):  # a freed dict's slot is reused by the next one, so the id and the size are the old pool's
            pool = {1: cve(pk)}
            self.assertEqual([c.pk for c in java_runtime.java_cves(pool)], [pk])
            del pool
        for walk, memo in ((version_sources.runtime_cves, version_sources._POOL), (windows_builds.windows_cves, windows_builds._POOL),
                           (edge_builds.range_cves, edge_builds._POOL)):
            pool = {1: cve(1)}
            walk(pool)
            self.assertIs(memo['pool'], pool, walk.__name__)


class ConcurrentRefreshTests(PoolTestMixin, TransactionTestCase):
    """Two callers during a refresh: the one that waits gets the new pool, the pool visible meanwhile is the old one and whole, and the
    refresh runs once."""

    def test_second_caller_waits_and_never_sees_a_half_patched_pool(self):
        rnd = random.Random(9)
        made = self.make(rnd, 30)
        old = correlation.cve_pool()
        before = snapshot(old)
        CVEEntry.objects.filter(pk=made[0].pk).update(affected=[{'product': 'brandnewproduct'}], synced_at=self.clock.tick())
        inside, release = threading.Event(), threading.Event()
        real = correlation.patch_product_index
        calls, seen = [], {}

        def slow_patch(*args):
            calls.append(1)
            inside.set()
            release.wait(10)
            return real(*args)

        def caller(name):
            try:
                seen[name] = correlation.cve_pool()
            finally:
                connections.close_all()

        with mock.patch.object(correlation, 'patch_product_index', slow_patch):
            a = threading.Thread(target=caller, args=('a',))
            a.start()
            self.assertTrue(inside.wait(10))
            b = threading.Thread(target=caller, args=('b',))
            b.start()
            b.join(0.5)
            self.assertTrue(b.is_alive(), 'the second caller should wait for the running refresh')
            self.assertIs(correlation._INDEX_CACHE['value'], old)  # the published pool is still the old one, unchanged
            self.assertEqual(snapshot(correlation._INDEX_CACHE['value']), before)
            release.set()
            a.join(10)
            b.join(10)
        self.assertEqual(len(calls), 1)
        self.assertIs(seen['a'], seen['b'])
        self.assertIn('brandnewproduct', seen['a'][1])
        self.assertEqual(snapshot(seen['a']), snapshot(scratch(correlation._INDEX_CACHE, correlation.cve_pool)))
