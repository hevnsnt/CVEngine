"""reNgine.resources: memory reading, the shared Redis handle and its fallback, what each container publishes and the web container reads back,
claims, and the stop flags. No scanner runs on the server, so the per-tool memory gate (``heavy_job``, its costs, caps and watchdog) is gone."""
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from reNgine import resources as res

STATE = {'total_mb': 4000, 'limit_mb': 4000, 'used_mb': 1000, 'available_mb': 3000}


def redis_or_skip(case):
    try:
        import redis
        client = redis.Redis.from_url(os.environ.get('CELERY_BROKER', 'redis://localhost:6379/0'), decode_responses=True, socket_connect_timeout=1)
        client.ping()
    except Exception:  # noqa: BLE001
        case.skipTest('no Redis available')
    return client


class ReadingMemoryTests(unittest.TestCase):
    def test_cgroup_v2_counts_only_the_working_set_and_reads_the_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'memory.max').write_text(str(4 << 30) + '\n')
            (root / 'memory.current').write_text(str(3 << 30) + '\n')
            (root / 'memory.stat').write_text(f'anon 1\ninactive_file {1 << 30}\nactive_file 5\n')
            limit, used = res.cgroup_memory(str(root))
            self.assertEqual((limit, used), (4 << 30, 2 << 30))  # page cache that can be dropped is not "used"

    def test_cgroup_v2_without_a_limit_and_cgroup_v1(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'memory.max').write_text('max\n')
            (root / 'memory.current').write_text('1048576\n')
            self.assertEqual(res.cgroup_memory(str(root)), (None, 1048576))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'memory').mkdir()
            (root / 'memory' / 'memory.limit_in_bytes').write_text(str(2 << 30))
            (root / 'memory' / 'memory.usage_in_bytes').write_text(str(1 << 30))
            (root / 'memory' / 'memory.stat').write_text(f'total_inactive_file {256 << 20}\n')
            self.assertEqual(res.cgroup_memory(str(root)), (2 << 30, 768 << 20))
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(res.cgroup_memory(d), (None, None))

    def test_state_is_the_smaller_of_the_container_and_the_host_view(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'memory.max').write_text(str(4 << 30))
            (root / 'memory.current').write_text(str(1 << 30))
            (root / 'memory.stat').write_text('inactive_file 0\n')
            info = root / 'meminfo'
            info.write_text('MemTotal: 8388608 kB\nMemAvailable: 1048576 kB\n')  # host is nearly full: 1 GB available
            state = res.memory_state(str(root), str(info))
            self.assertEqual((state['limit_mb'], state['used_mb'], state['available_mb']), (4096, 1024, 1024))

    def test_unlimited_container_falls_back_to_meminfo(self):
        with tempfile.TemporaryDirectory() as d:
            info = Path(d) / 'meminfo'
            info.write_text('MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n')
            state = res.memory_state(d, str(info))
            self.assertEqual((state['limit_mb'], state['available_mb'], state['total_mb']), (None, 6144, 8192))


class RemovedGateTests(unittest.TestCase):
    def test_the_memory_gate_and_its_helpers_are_gone(self):
        for name in ('heavy_job', 'Job', 'MemoryKill', 'BASE_COSTS_MB', 'MAX_CONCURRENT', 'cost_mb', 'effective_cost', 'max_concurrent', 'base_cap',
                     'env_cap_pin', 'budget_mb', 'headroom_mb', 'critical_mb', 'terminate_group', 'tree_pids', 'tree_rss_mb', 'group_rss_mb', 'snapshot'):
            self.assertFalse(hasattr(res, name), name)
        for name in ('reserve', 'release', 'heartbeat', 'live', 'wait', 'waiting', 'event', 'events', 'learn', 'learned'):
            self.assertFalse(hasattr(res.MemoryStore, name), name)
            self.assertFalse(hasattr(res.RedisStore, name), name)

    def test_waiting_for_a_scanner_is_still_a_memory_busy_so_every_stage_keeps_the_work_due(self):
        for cls in (res.ScannerUnavailable, res.AddressExcluded, res.ScannerReportedNothing):
            self.assertTrue(issubclass(cls, res.MemoryBusy), cls)
        error = res.ScannerUnavailable('nmap', 'no Sentinel', waiting=True)
        self.assertEqual((error.kind, error.why, error.done, error.waiting), ('nmap', 'no Sentinel', [], True))
        self.assertIn('it stays due', str(error))
        excluded = res.AddressExcluded('nmap', 'on the do-not-scan list')
        self.assertEqual((excluded.refusal, excluded.waiting), ('on the do-not-scan list', False))
        self.assertFalse(issubclass(res.ScanAborted, res.MemoryBusy))


class StoreTests(unittest.TestCase):
    def setUp(self):
        res.reset_store()
        self.addCleanup(res.reset_store)

    def test_without_a_redis_broker_the_store_is_this_process_only(self):
        for url in ('', 'amqp://guest@rabbit//', 'redis://127.0.0.1:1/0'):  # not Redis, or a Redis nobody answers on
            res.reset_store()
            with mock.patch.dict(os.environ, {'CELERY_BROKER': url, 'CELERY_BROKER_URL': ''}):
                store = res.get_store()
            self.assertIsInstance(store, res.MemoryStore, url)
            self.assertIsNone(store.r, url)
            self.assertEqual(res._store['kind'], 'process', url)
            self.assertIs(res.get_store(), store)  # made once per process
        store.publish_state({'host': 'h', 'memory': STATE, 't': 1})
        self.assertEqual(store._state['host'], 'h')

    def test_with_redis_the_store_is_shared_and_named_after_this_container(self):
        client = redis_or_skip(self)
        with mock.patch.dict(os.environ, {'CELERY_BROKER': os.environ.get('CELERY_BROKER', 'redis://localhost:6379/0')}):
            store = res.get_store()
        self.assertIsInstance(store, res.RedisStore)
        self.assertEqual(res._store['kind'], 'redis')
        self.assertEqual(store.state_key, f'{res.STATE_PREFIX}{socket.gethostname()}:state')
        self.assertTrue(store.r.ping())

    def test_redis_store_publishes_the_state_and_a_short_history(self):
        client = redis_or_skip(self)
        namespace = f'cvengine:test:{os.getpid()}:{time.time_ns()}'
        self.addCleanup(lambda: [client.delete(k) for k in client.scan_iter(match=f'{namespace}:*')])
        store = res.RedisStore(client, namespace)
        for i in range(405):
            store.publish_state({'host': 'h', 'memory': STATE, 't': i})
        self.assertEqual(json.loads(client.get(f'{namespace}:state'))['t'], 404)
        self.assertTrue(0 < client.ttl(f'{namespace}:state') <= 120)
        self.assertEqual(client.llen(f'{namespace}:history'), 400)  # trimmed
        self.assertEqual(json.loads(client.lindex(f'{namespace}:history', 0))['t'], 404)  # newest first
        self.assertTrue(0 < client.ttl(f'{namespace}:history') <= 4 * 3600)


class PublishedPictureTests(unittest.TestCase):
    """``report_state`` in each worker container and ``cluster_snapshot`` / ``adaptive_history`` in the web container: memory only."""

    def setUp(self):
        self.client = redis_or_skip(self)
        self.namespace = f'{res.STATE_PREFIX}test-{os.getpid()}-{time.time_ns()}'
        self.addCleanup(lambda: [self.client.delete(k) for k in self.client.scan_iter(match=f'{res.STATE_PREFIX}test-{os.getpid()}-*')])
        self.store = res.RedisStore(self.client, self.namespace)
        shared = mock.patch.dict(res._store, {'obj': self.store, 'kind': 'redis'})
        shared.start()
        self.addCleanup(shared.stop)

    def mine(self, snapshot):
        return [c for c in snapshot['containers'] if c['host'].startswith(f'test-{os.getpid()}-')]

    def test_report_state_publishes_the_host_its_memory_and_the_time(self):
        with mock.patch.object(socket, 'gethostname', return_value=self.namespace[len(res.STATE_PREFIX):]), \
                mock.patch('reNgine.container_signals.publish') as signals:
            res.report_state(state_fn=lambda: STATE, now_fn=lambda: 1000.0)
        published = json.loads(self.client.get(f'{self.namespace}:state'))
        self.assertEqual(published, {'host': self.namespace[len(res.STATE_PREFIX):], 'memory': STATE, 't': 1000.0})
        signals.assert_called_once_with('worker', client=self.client, now=1000.0)
        process = res.MemoryStore()
        with mock.patch('reNgine.container_signals.publish') as signals:
            res.report_state(process, state_fn=lambda: STATE, now_fn=lambda: 5.0)
        self.assertEqual(set(process._state), {'host', 'memory', 't'})
        signals.assert_not_called()  # without Redis there is nobody to read it

    def test_cluster_snapshot_is_every_containers_memory_and_nothing_of_the_gate(self):
        host = self.namespace[len(res.STATE_PREFIX):]
        self.store.publish_state({'host': host, 'memory': STATE, 't': 1000.0})
        other = res.RedisStore(self.client, f'{self.namespace}-b')
        other.publish_state({'memory': {'total_mb': 2000}, 't': 990.0})  # an older worker that did not name itself: the key names it
        self.client.set(f'{self.namespace}-c:state', 'not json')
        snapshot = res.cluster_snapshot(now_fn=lambda: 1030.0)
        self.assertEqual(set(snapshot), {'store', 'containers'})
        self.assertEqual(snapshot['store'], 'redis')
        self.assertEqual(sorted(self.mine(snapshot), key=lambda c: c['host']), [{'host': host, 'memory': STATE, 'age_seconds': 30},
                                               {'host': f'{host}-b', 'memory': {'total_mb': 2000}, 'age_seconds': 40}])
        for container in snapshot['containers']:
            self.assertEqual(set(container), {'host', 'memory', 'age_seconds'})

    def test_without_redis_the_snapshot_describes_this_container(self):
        with mock.patch.dict(res._store, {'obj': res.MemoryStore(), 'kind': 'process'}), mock.patch.object(res, 'memory_state', return_value=STATE):
            snapshot = res.cluster_snapshot()
        self.assertEqual(snapshot, {'store': 'process', 'containers': [{'host': socket.gethostname(), 'memory': STATE, 'age_seconds': 0}]})

    def test_the_history_is_read_back_since_a_time_and_is_empty_without_redis(self):
        for t in (100.0, 200.0, 300.0):
            self.store.publish_state({'host': 'h', 'memory': STATE, 't': t})
        mine = [s for s in res.adaptive_history(150.0) if s.get('host') == 'h' and s['memory'] == STATE]
        self.assertEqual(sorted(s['t'] for s in mine), [200.0, 300.0])
        with mock.patch.dict(res._store, {'obj': res.MemoryStore(), 'kind': 'process'}):
            self.assertEqual(res.adaptive_history(0), [])


class ClaimTests(unittest.TestCase):
    def test_without_redis_every_claim_is_held_here(self):
        with mock.patch.dict(res._store, {'obj': res.MemoryStore(), 'kind': 'process'}):
            with res.redis_claim('cvengine:test:claim', 'me', 60) as held:
                self.assertIs(held, True)

    def test_one_holder_at_a_time_released_on_exit_and_owner_checked(self):
        client = redis_or_skip(self)
        key = f'cvengine:test:claim:{os.getpid()}:{time.time_ns()}'
        self.addCleanup(client.delete, key)
        with mock.patch.dict(res._store, {'obj': res.RedisStore(client, 'cvengine:test:ns'), 'kind': 'redis'}):
            with res.redis_claim(key, 'first', 60) as held:
                self.assertIs(held, True)
                self.assertEqual(client.get(key), 'first')
                with res.redis_claim(key, 'second', 60) as other:
                    self.assertEqual(other, 'first')  # the holder, not True
                self.assertEqual(client.get(key), 'first')  # the loser does not release it
            self.assertIsNone(client.get(key))
            client.set(key, 'mine', ex=60)
            with res.redis_claim(key, 'mine', 60, adopt=True) as held:
                self.assertIs(held, True)  # a run continuing its own claim takes it back
        self.assertEqual(res.claim_refresh(client, key, 'mine', 60), 'regained')  # gone: taken again
        self.assertEqual(res.claim_refresh(client, key, 'mine', 60), 'ok')
        self.assertEqual(res.claim_refresh(client, key, 'thief', 60), 'lost')
        self.assertFalse(res.claim_release(client, key, 'thief'))
        self.assertEqual(client.get(key), 'mine')
        self.assertTrue(res.claim_release(client, key, 'mine'))
        self.assertIsNone(client.get(key))


class AbortFlagTests(unittest.TestCase):
    def test_a_stop_is_seen_in_this_process_without_redis(self):
        with mock.patch.dict(res._store, {'obj': res.MemoryStore(), 'kind': 'process'}):
            self.assertFalse(res.abort_requested(987101))
            self.assertFalse(res.abort_requested(None))
            res.request_abort(987101)
            self.assertTrue(res.abort_requested(987101))
            res.clear_abort(987101)
            self.assertFalse(res.abort_requested(987101))

    def test_a_stop_reaches_every_worker_through_redis(self):
        client = redis_or_skip(self)
        self.addCleanup(client.delete, f'{res.ABORT_KEY}987102')
        with mock.patch.dict(res._store, {'obj': res.RedisStore(client, 'cvengine:test:ns'), 'kind': 'redis'}):
            res.request_abort(987102)
            self.assertEqual(client.get(f'{res.ABORT_KEY}987102'), '1')
            self.assertTrue(0 < client.ttl(f'{res.ABORT_KEY}987102') <= res.ABORT_TTL)
            res._aborted_here.discard(987102)  # another worker process: only Redis knows
            self.assertTrue(res.abort_requested(987102))
            res.clear_abort(987102)
            self.assertIsNone(client.get(f'{res.ABORT_KEY}987102'))
            self.assertFalse(res.abort_requested(987102))
