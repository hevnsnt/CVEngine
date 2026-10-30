"""reNgine.resources: memory reading, the admission queue, the watchdog, and how callers react to a memory kill."""
import os
import json
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from reNgine import resources as res


def fake_state(available, total=4000, used=None):
    return lambda: {'total_mb': total, 'limit_mb': total, 'used_mb': used if used is not None else total - available, 'available_mb': available}


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

    def test_budget_headroom_critical_and_cost_follow_the_environment(self):
        state = {'total_mb': 4096, 'limit_mb': 4096, 'used_mb': 0, 'available_mb': 4096}
        self.assertEqual((res.budget_mb(state), res.headroom_mb(state), res.critical_mb(state)), (3072, 256, 150))
        with mock.patch.dict(os.environ, {'HEAVY_MEMORY_BUDGET_MB': '2000', 'HEAVY_HEADROOM_MB': '500', 'HEAVY_COST_SCALE': '2',
                                          'HEAVY_COST_NMAP_MB': '111'}):
            self.assertEqual((res.budget_mb(state), res.headroom_mb(state)), (2000, 500))
            self.assertEqual((res.cost_mb('nuclei'), res.cost_mb('nmap')), (2000, 111))

    def test_group_rss_sees_a_child_process(self):
        proc = subprocess.Popen(['sleep', '5'], start_new_session=True)
        try:
            time.sleep(0.2)
            self.assertGreaterEqual(res.group_rss_mb(proc.pid), 0)
            self.assertEqual(res.group_rss_mb(2 ** 22 + 7), 0)  # no such group
        finally:
            proc.kill()
            proc.wait()


class StoreTests(unittest.TestCase):
    def check_store(self, store):
        now = 1000.0
        self.assertTrue(store.reserve('a', 3000, 'big', 3500, now))      # alone: always admitted
        self.assertFalse(store.reserve('b', 1000, 'next', 3500, now))    # would exceed the budget
        self.assertTrue(store.reserve('c', 400, 'small', 3500, now))     # fits beside the first
        store.heartbeat('a', 1234, now + 1)
        live = {j['token']: j for j in store.live(now + 1)}
        self.assertEqual((set(live), live['a']['rss']), ({'a', 'c'}, 1234))
        store.release('a')
        self.assertTrue(store.reserve('b', 1000, 'next', 3500, now + 2))
        # a holder that stops heartbeating loses its reservation
        self.assertEqual({j['token'] for j in store.live(now + 2 + res.RESERVATION_TTL + 1)}, set())
        store.wait('w', 900, 'waiting job', now)
        self.assertEqual([w['token'] for w in store.waiting(now + 1)], ['w'])
        store.release('w')
        self.assertEqual(store.waiting(now + 1), [])
        store.event({'t': now, 'kind': 'nuclei'})
        self.assertEqual(store.events()[0]['kind'], 'nuclei')

    def test_memory_store(self):
        self.check_store(res.MemoryStore())

    def test_redis_store_uses_the_same_rules(self):
        try:
            import redis
            client = redis.Redis.from_url(os.environ.get('CELERY_BROKER', 'redis://localhost:6379/0'), decode_responses=True, socket_connect_timeout=1)
            client.ping()
        except Exception:  # noqa: BLE001
            self.skipTest('no Redis available')
        namespace = f'cvengine:test:{os.getpid()}:{time.time_ns()}'
        store = res.RedisStore(client, namespace)
        try:
            self.check_store(store)
            store.publish_state({'host': 'h', 'memory': {}, 't': 1})
            self.assertEqual(client.get(f'{namespace}:state') is not None, True)
        finally:
            for key in client.scan_iter(match=f'{namespace}:*'):
                client.delete(key)


class QueueTests(unittest.TestCase):
    def test_a_job_starts_at_once_when_there_is_room(self):
        store = res.MemoryStore()
        with res.heavy_job('nmap', label='x', store=store, state_fn=fake_state(3000)) as job:
            self.assertEqual([j['token'] for j in store.live(time.time())], [job.token])
        self.assertEqual(store.live(time.time()), [])  # released on exit, also when the body raises

    def test_release_happens_when_the_body_fails(self):
        store = res.MemoryStore()
        with self.assertRaises(ValueError):
            with res.heavy_job('nmap', store=store, state_fn=fake_state(3000)):
                raise ValueError('boom')
        self.assertEqual(store.live(time.time()), [])

    def test_a_second_job_waits_until_the_first_is_done(self):
        store = res.MemoryStore()
        order = []
        first_in = threading.Event()
        first_may_leave = threading.Event()

        def first():
            with res.heavy_job('bbot-deep', label='one', store=store, state_fn=fake_state(3500)):
                order.append('first in')
                first_in.set()
                first_may_leave.wait(5)
                order.append('first out')

        t = threading.Thread(target=first)
        t.start()
        self.assertTrue(first_in.wait(5))
        sleeps = []

        def sleeper(seconds):
            sleeps.append(seconds)
            first_may_leave.set()  # the waiting job's first poll lets the holder finish
            t.join(5)

        with mock.patch.dict(os.environ, {'HEAVY_MEMORY_BUDGET_MB': '2500'}):  # 1800 + 1800 does not fit in 2500
            with res.heavy_job('bbot-deep', label='two', store=store, state_fn=fake_state(3500), sleep=sleeper):
                order.append('second in')
        self.assertEqual(order, ['first in', 'first out', 'second in'])
        self.assertTrue(sleeps)

    def test_not_enough_free_memory_right_now_also_makes_it_wait(self):
        store = res.MemoryStore()
        store.reserve('other', 100, 'other', 10 ** 6, time.time())  # something else is running
        states = iter([fake_state(500)(), fake_state(500)(), fake_state(3500)()])
        waits = []
        with res.heavy_job('nuclei', label='x', store=store, state_fn=lambda: next(states, fake_state(3500)()), sleep=waits.append):
            pass
        self.assertEqual(len(waits), 2)  # needs 1000 + headroom, so it waited while only 500 was free

    def test_the_system_wide_waiting_line_never_names_the_hosts_being_scanned(self):
        store = res.MemoryStore()
        store.reserve('other', 100, 'other', 10 ** 6, time.time())
        states = iter([fake_state(500)(), fake_state(3500)()])
        lines = []
        with mock.patch.object(res, '_log_activity', side_effect=lambda message, status='done': lines.append(message)):
            with res.heavy_job('nuclei', label='secret-tenant.example.com', store=store,
                               state_fn=lambda: next(states, fake_state(3500)()), sleep=lambda s: None):
                pass
        self.assertTrue(lines)
        self.assertFalse([m for m in lines if 'secret-tenant' in m], lines)

    def test_waiting_too_long_raises_instead_of_hanging(self):
        store = res.MemoryStore()
        store.reserve('hog', 3000, 'hog', 3500, time.time())
        clock = {'t': 0.0}
        with self.assertRaises(res.MemoryBusy):
            with res.heavy_job('nuclei', label='x', store=store, state_fn=fake_state(100), wait_timeout=30,
                               sleep=lambda s: clock.update(t=clock['t'] + 20), now_fn=lambda: clock['t']):
                self.fail('must not start')
        self.assertEqual([j['token'] for j in store.live(time.time())], ['hog'])  # and it left nothing behind


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

    def sleeper(self):
        proc = subprocess.Popen(['sleep', '60'], start_new_session=True)
        self.procs.append(proc)
        return proc

    def job(self, store, clock, available):
        job = res.Job('nuclei', 1000, 'x', store, fake_state(available), lambda: clock['t'])
        store.reserve(job.token, 1000, 'x', 10 ** 6, clock['t'])
        return job

    def test_no_kill_while_memory_is_fine_or_during_the_grace_period(self):
        store, clock = res.MemoryStore(), {'t': 1000.0}
        job = self.job(store, clock, available=10)
        job.attach(self.sleeper())
        clock['t'] += 1  # inside the grace period
        self.assertFalse(job.check_once())
        job.state_fn = fake_state(3000)
        clock['t'] += res.GRACE_SECONDS
        self.assertFalse(job.check_once())
        self.assertFalse(job.killed_for_memory)

    def test_the_biggest_job_is_stopped_when_memory_is_critical(self):
        store, clock = res.MemoryStore(), {'t': 1000.0}
        small, big = self.job(store, clock, available=10), self.job(store, clock, available=10)
        small.attach(self.sleeper())
        big.attach(self.sleeper())
        clock['t'] += res.GRACE_SECONDS + 1
        store.heartbeat(small.token, 100, clock['t'])
        store.heartbeat(big.token, 900, clock['t'])
        small.rss_mb = lambda: 100
        big.rss_mb = lambda: 900
        with mock.patch.object(res, 'terminate_group', side_effect=lambda proc, grace=10: proc.kill()) as stopper:
            self.assertFalse(small.check_once())  # not the biggest: left alone
            self.assertTrue(big.check_once())
        stopper.assert_called_once()
        self.assertTrue(big.killed_for_memory)
        self.assertEqual(store.events()[0]['kind'], 'nuclei')
        with self.assertRaises(res.MemoryKill):
            big.raise_if_killed()
        small.raise_if_killed()  # the small one carries on

    def test_terminate_group_stops_the_whole_tree(self):
        proc = subprocess.Popen(['sh', '-c', 'sleep 60 & sleep 60 & wait'], start_new_session=True)
        self.procs.append(proc)
        time.sleep(0.3)
        self.assertGreaterEqual(len([p for p in os.listdir('/proc') if p.isdigit() and
                                     (res._read(f'/proc/{p}/stat') or '').rsplit(')', 1)[-1].split()[2:3] == [str(proc.pid)]]), 2)
        res.terminate_group(proc, grace=3)
        self.assertIsNotNone(proc.poll())
        time.sleep(0.3)
        self.assertEqual(res.group_rss_mb(proc.pid), 0)  # the children are gone too

    def test_celery_gevent_timeout_stops_scanner_tree_before_releasing_capacity(self):
        # Celery's gevent timeout is a BaseException. Run it in a child interpreter
        # because monkey.patch_all() must not alter the Django test runner.
        script = textwrap.dedent('''
            from gevent import monkey
            monkey.patch_all()
            import importlib.util, json, os, subprocess, sys, time
            from unittest.mock import patch
            from celery.concurrency.gevent import apply_timeout

            spec = importlib.util.spec_from_file_location('resources', sys.argv[1])
            resources = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(resources)
            store, children = resources.MemoryStore(), []
            def task():
                with resources.heavy_job('nmap', store=store,
                                         state_fn=lambda: {'total_mb': 4096, 'available_mb': 4096}) as job:
                    proc = subprocess.Popen(['sh', '-c', 'sleep 30 & sleep 30 & wait'], start_new_session=True)
                    children.append(proc)
                    job.attach(proc)
                    proc.communicate(timeout=20)
            try:
                with patch.object(resources, 'global_pause_requested', return_value=False), \\
                     patch.object(resources.Job, 'start_watchdog'):
                    result = apply_timeout(task, timeout=0.3, getpid=os.getpid,
                                           timeout_callback=lambda *args: 'celery timed out')
                proc = children[0]
                print(json.dumps({'result': result, 'child_stopped': proc.poll() is not None,
                                  'tree_rss_mb': resources.group_rss_mb(proc.pid),
                                  'reservations': len(store.live(time.time()))}))
            finally:
                for proc in children:
                    resources.terminate_group(proc, grace=0)
                    proc.wait()
        ''')
        result = subprocess.run([sys.executable, '-c', script, res.__file__], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'result': 'celery timed out', 'child_stopped': True,
                                                       'tree_rss_mb': 0, 'reservations': 0})


class CallerReactionTests(unittest.TestCase):
    def test_nuclei_light_profile_lowers_concurrency_and_rate(self):
        from cveFeed import nuclei_scan
        normal, light = nuclei_scan.build_flags(), nuclei_scan.build_flags(profile='light')
        self.assertEqual(normal[normal.index('-c') + 1], '40')
        self.assertEqual((light[light.index('-c') + 1], light[light.index('-rl') + 1], light[light.index('-bs') + 1]), ('10', '50', '10'))
        self.assertEqual(nuclei_scan.build_flags(['rce', 'apache'], 'light')[-2:], ['-tags', 'apache,rce'])

    def test_nmap_chunks_are_halved_after_a_memory_kill_and_everything_is_scanned(self):
        from cveFeed import nmap_scan
        calls = []

        def runner(chunk, flags, timeout):
            calls.append(len(chunk))
            if len(chunk) > 8:
                raise res.MemoryKill('low memory')
            return '<nmaprun/>'
        with mock.patch.object(nmap_scan, 'parse_xml', return_value=[]), \
                mock.patch.object(nmap_scan, 'persist_inventory', return_value={'ports': 2, 'hosts_with_os': 1}):
            totals = nmap_scan.scan_in_chunks(runner, [f'h{i}.test' for i in range(40)], ['-F'], '3m', size=40)
        self.assertEqual(calls[0], 40)
        self.assertEqual(sum(c for c in calls if c <= 8), 40)  # every host ended up in a run that fit
        self.assertEqual(totals['ports'], 2 * len([c for c in calls if c <= 8]))

    def test_nmap_gives_up_when_even_a_tiny_chunk_is_killed(self):
        from cveFeed import nmap_scan

        def runner(chunk, flags, timeout):
            raise res.MemoryKill('low memory')
        with self.assertRaises(res.MemoryKill):
            nmap_scan.scan_in_chunks(runner, ['a.test', 'b.test', 'c.test'], ['-F'], '3m')


class LearnedCostTests(unittest.TestCase):
	"""The static estimates are guesses; the gate reserves what real runs of that kind actually needed."""

	def test_cost_rises_to_what_real_runs_needed(self):
		store = res.MemoryStore()
		self.assertEqual(res.effective_cost('bbot-deep', store), res.cost_mb('bbot-deep'))
		store.learn('bbot-deep', 4000)
		self.assertEqual(res.effective_cost('bbot-deep', store), int(4000 * res.LEARNED_MARGIN))

	def test_an_explicit_setting_wins_and_small_runs_only_nudge_it_down(self):
		store = res.MemoryStore()
		store.learn('nmap', 2000)
		store.learn('nmap', 100)
		self.assertGreater(store.learned()['nmap'], 1500)  # one small run does not undo a big one
		with mock.patch.dict(os.environ, {'HEAVY_COST_NMAP_MB': '123'}):
			self.assertEqual(res.effective_cost('nmap', store), 123)

	def test_a_finished_job_records_its_peak_and_a_stopped_one_leaves_room_above_it(self):
		store = res.MemoryStore()
		state = lambda: {'total_mb': 4000, 'used_mb': 100, 'available_mb': 3900, 'limit_mb': 4000, 'source': 'test'}
		with res.heavy_job('nuclei', label='a', store=store, state_fn=state) as job:
			job.peak = 800
		self.assertEqual(store.learned()['nuclei'], 800)
		with res.heavy_job('nmap', label='b', store=store, state_fn=state) as job:
			job.peak = 1000
			job.killed_for_memory = True
		self.assertEqual(store.learned()['nmap'], 1350)


class ConcurrencyCapTests(unittest.TestCase):
	"""nmap and nuclei are CPU and network bound: more at once only makes each slower, however much memory is free."""

	def test_only_two_nmaps_at_a_time_but_other_kinds_still_run(self):
		store = res.MemoryStore()
		self.assertTrue(store.reserve('a', 350, 'nmap: x', 4000, 0, 'nmap', res.max_concurrent('nmap')))
		self.assertTrue(store.reserve('b', 350, 'nmap: y', 4000, 0, 'nmap', res.max_concurrent('nmap')))
		self.assertFalse(store.reserve('d', 350, 'nmap: w', 4000, 0, 'nmap', res.max_concurrent('nmap')))
		self.assertTrue(store.reserve('c', 700, 'bbot-passive: z', 4000, 0, 'bbot-passive', res.max_concurrent('bbot-passive')))

	def test_cap_can_be_raised_from_the_environment(self):
		with mock.patch.dict(os.environ, {'HEAVY_MAX_NMAP': '3'}):
			self.assertEqual(res.max_concurrent('nmap'), 3)
		self.assertEqual(res.max_concurrent('nmap'), 2)

	def test_redis_store_enforces_the_same_cap(self):
		import redis
		client = redis.Redis.from_url(os.environ.get('CELERY_BROKER', 'redis://localhost:6379/0'), decode_responses=True)
		try:
			client.ping()
		except Exception:
			self.skipTest('no Redis')
		ns = f'test:cap:{os.getpid()}'
		store = res.RedisStore(client, ns)
		try:
			self.assertTrue(store.reserve('a', 350, 'nmap: x', 4000, 100, 'nmap', 1))
			self.assertFalse(store.reserve('b', 350, 'nmap: y', 4000, 100, 'nmap', 1))
			self.assertTrue(store.reserve('c', 500, 'nuclei: z', 4000, 100, 'nuclei', 1))
		finally:
			client.delete(f'{ns}:jobs')
