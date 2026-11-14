"""reNgine.gevent_gc: automatic collection off and a timer in a gevent worker, nothing changed anywhere else."""
import gc
import json
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase

from reNgine import gevent_db, gevent_gc, lane_memory


def _fresh_state(case):
    """The timer's counters start from zero in each test and are put back after it; nothing stays frozen."""
    saved = dict(gevent_gc._state)
    case.addCleanup(lambda: (gevent_gc._state.clear(), gevent_gc._state.update(saved)))
    case.addCleanup(gc.unfreeze)
    gevent_gc._state.update({'ticks': 0, 'frozen': False, 'collections': 0, 'last_s': None, 'last_full_s': None, 'worst_s': 0.0, 'freeze_s': None, 'slow_logged_at': None,
                             'slow_skipped': 0, 'loaded': None})


class GeventGcTests(SimpleTestCase):
    def setUp(self):
        self.was_enabled = gc.isenabled()
        self.addCleanup(lambda: gc.enable() if self.was_enabled else gc.disable())
        _fresh_state(self)

    def test_a_process_gevent_has_not_patched_keeps_the_interpreters_collector(self):
        with mock.patch.object(gevent_db, 'gevent_patched', return_value=False), mock.patch('gevent.spawn') as spawn:
            self.assertFalse(gevent_gc.install())
        spawn.assert_not_called()
        self.assertEqual(gc.isenabled(), self.was_enabled)

    def test_a_gevent_worker_gets_the_timer_and_the_automatic_collector_goes_off(self):
        gc.enable()
        with mock.patch.object(gevent_db, 'gevent_patched', return_value=True), mock.patch('gevent.spawn') as spawn:
            self.assertTrue(gevent_gc.install())
        self.assertFalse(gc.isenabled())
        spawn.assert_called_once()

    def test_it_can_be_switched_off(self):
        gc.enable()
        with mock.patch.dict('os.environ', {'CVENGINE_GC_MANUAL': '0'}), mock.patch.object(gevent_db, 'gevent_patched', return_value=True), \
                mock.patch('gevent.spawn') as spawn:
            self.assertFalse(gevent_gc.install())
        spawn.assert_not_called()
        self.assertTrue(gc.isenabled())

    def test_the_timer_collects_cycles_and_survives_a_failure(self):
        class Cycle:
            pass
        a = Cycle()
        a.me = a
        del a
        calls = []

        def sleep(seconds):
            calls.append(seconds)
            if len(calls) == 1:
                raise_once.append(1)
            if len(calls) >= 3:
                raise StopIteration
        raise_once = []
        with mock.patch.object(gevent_gc, 'collect_once', side_effect=[RuntimeError('boom'), 0.0]) as collect:
            with self.assertRaises(StopIteration):
                gevent_gc._loop(sleep)
        self.assertEqual(calls, [gevent_gc.INTERVAL_SECONDS] * 3)
        self.assertEqual(collect.call_count, 2)  # the failed one did not end the loop

    def test_a_collection_really_frees_a_cycle(self):
        freed = []

        class Cycle:
            def __del__(self):
                freed.append(1)
        c = Cycle()
        c.me = c
        del c
        gc.disable()
        gevent_gc.collect_once()
        self.assertEqual(freed, [1])


class Cycle:
    freed = 0

    def __init__(self):
        self.me = self

    def __del__(self):
        Cycle.freed += 1


class FrozenStartupTests(SimpleTestCase):
    def setUp(self):
        self.was_enabled = gc.isenabled()
        self.addCleanup(lambda: gc.enable() if self.was_enabled else gc.disable())
        _fresh_state(self)
        gc.disable()
        Cycle.freed = 0

    def test_install_waits_for_the_worker_to_have_loaded(self):
        from celery.signals import worker_ready
        with mock.patch.object(gevent_db, 'gevent_patched', return_value=True), mock.patch('gevent.spawn'):
            self.assertTrue(gevent_gc.install())
        loaded = gevent_gc._state['loaded']
        self.assertFalse(loaded.is_set())
        self.assertEqual(gc.get_freeze_count(), 0)  # install itself freezes nothing: the task modules are not imported yet
        self.addCleanup(worker_ready.disconnect, dispatch_uid='gevent-gc-loaded')
        ours = [r for r in worker_ready.receivers if r[0][0] == 'gevent-gc-loaded']
        self.assertEqual(len(ours), 1)
        with mock.patch.object(worker_ready, 'receivers', ours), mock.patch.object(worker_ready, 'sender_receivers_cache', {}):  # not the other receivers of the signal
            worker_ready.send(sender=None)
        self.assertTrue(loaded.is_set())  # the signal only says so: the freeze itself runs in the timer greenlet

    def test_the_freeze_happens_once_and_moves_the_startup_objects_out_of_the_collectors_view(self):
        startup = [Cycle() for _ in range(200)]  # long-lived objects of the loaded worker
        before = gc.get_freeze_count()
        frozen = gevent_gc.freeze_after_load()
        self.assertGreaterEqual(frozen, before + 200)
        self.assertEqual(gc.get_freeze_count(), frozen)
        self.assertEqual(gevent_gc.freeze_after_load(), 0)  # never a second time
        self.assertEqual(gc.get_freeze_count(), frozen)
        del startup

    def test_the_timer_freezes_on_its_first_wake_after_load_and_ticks_after_that(self):
        import gevent.event
        loaded = gevent_gc._state['loaded'] = gevent.event.Event()
        loaded.set()
        calls = []

        def sleep(seconds):
            calls.append(seconds)
            if len(calls) >= 4:
                raise StopIteration
        with mock.patch.object(gc, 'freeze', wraps=gc.freeze) as freeze:
            with self.assertRaises(StopIteration):
                gevent_gc._loop(sleep)
        freeze.assert_called_once()
        self.assertTrue(gevent_gc._state['frozen'])
        self.assertEqual(gevent_gc._state['ticks'], 2)  # wake 1 froze, wakes 2 and 3 were ticks, wake 4 ended the test

    def test_a_tick_does_not_walk_the_frozen_objects(self):
        frozen_cycle = Cycle()
        gevent_gc.freeze_after_load()
        frozen_count = gc.get_freeze_count()
        del frozen_cycle  # garbage now, but frozen: no collection looks at it
        young = Cycle()
        del young
        full_before = gc.get_stats()[2]['collections']
        gevent_gc.tick()  # a young tick
        self.assertEqual(gc.get_stats()[2]['collections'], full_before)  # no full walk
        self.assertEqual(Cycle.freed, 1)  # the young cycle went, the frozen one stayed
        gevent_gc._state['ticks'] = gevent_gc.FULL_EVERY - 1
        gevent_gc.tick()  # the full one
        self.assertEqual(gc.get_stats()[2]['collections'], full_before + 1)
        self.assertEqual(Cycle.freed, 1)  # a full collection leaves the frozen ones alone too
        self.assertEqual(gc.get_freeze_count(), frozen_count)  # and never freezes again

    def test_a_cycle_that_outlives_a_young_collection_is_freed_by_the_next_full_one(self):
        gevent_gc.freeze_after_load()
        old = Cycle()
        gevent_gc.tick()
        gevent_gc.tick()  # it survived both young collections: it is in the oldest generation now
        keep = old
        del old
        keep.me = None
        keep2 = Cycle()
        keep2.other = keep
        keep = None
        del keep2
        gevent_gc._state['ticks'] = gevent_gc.FULL_EVERY - 1
        gevent_gc.tick()
        self.assertEqual(Cycle.freed, 2)

    def test_switching_off_the_timer_restores_the_interpreters_collector_and_freezes_nothing(self):
        gc.enable()
        with mock.patch.dict('os.environ', {'CVENGINE_GC_MANUAL': '0'}), mock.patch.object(gevent_db, 'gevent_patched', return_value=True), \
                mock.patch('gevent.spawn') as spawn:
            self.assertFalse(gevent_gc.install())
        spawn.assert_not_called()
        self.assertTrue(gc.isenabled())
        self.assertIsNone(gevent_gc._state['loaded'])
        self.assertEqual(gc.get_freeze_count(), 0)

    def test_no_collection_starts_inside_a_greenlet_switch(self):
        import gevent
        gc.disable()
        timer = []
        where = []

        def on_gc(phase, info):
            if phase == 'start':
                where.append(gevent.getcurrent())
        gc.callbacks.append(on_gc)
        self.addCleanup(gc.callbacks.remove, on_gc)

        def churn():
            for _ in range(20):
                junk = [Cycle() for _ in range(2000)]  # far over the 2000 allocation threshold, with a switch between every batch
                del junk
                gevent.sleep(0)
        workers = [gevent.spawn(churn) for _ in range(4)]
        gevent.joinall(workers, timeout=30)
        self.assertEqual(where, [])  # the automatic collector is off: nothing collected while greenlets switched and allocated

        ticks = [0]

        def sleep(seconds):
            ticks[0] += 1
            gevent.sleep(0)
            if ticks[0] >= 3:
                raise gevent.GreenletExit
        loop = gevent.spawn(gevent_gc._loop, sleep)
        timer.append(loop)
        loop.join(timeout=30)
        self.assertTrue(where)
        self.assertTrue(all(g is loop for g in where))  # every collection ran in the timer greenlet and nowhere else

    def test_a_slow_collection_is_logged_rarely_not_every_tick(self):
        with mock.patch.object(gevent_gc.logger, 'warning') as warning:
            for _ in range(5):
                gevent_gc._log_slow(2, 3.4)
        self.assertEqual(warning.call_count, 1)
        gevent_gc._state['slow_logged_at'] -= gevent_gc.SLOW_LOG_EVERY + 1
        with mock.patch.object(gevent_gc.logger, 'warning') as warning:
            gevent_gc._log_slow(2, 3.4)
        self.assertIn('4 more', warning.call_args[0][0] % warning.call_args[0][1:])

    def test_the_lane_publishes_its_last_and_worst_collection_and_the_status_shows_them(self):
        lane = 'gc_test_lane'
        self.addCleanup(cache.delete, gevent_gc.GC_KEY + lane)
        self.addCleanup(cache.delete, lane_memory.CACHE_PREFIX + lane)
        gevent_gc._state.update({'last_s': 0.004, 'last_full_s': 0.02, 'worst_s': 3.4})
        with mock.patch.object(lane_memory, 'lane_name', return_value=lane):
            gevent_gc.publish(now=1000.0)
        self.assertEqual(lane_memory.gc_timing(lane, 1010.0)['worst_s'], 3.4)
        self.assertEqual(lane_memory.gc_timing(lane, 1010.0)['last_s'], 0.004)
        self.assertIsNone(lane_memory.gc_timing(lane, 1000.0 + lane_memory.GC_FRESH_SECONDS + 1))  # a lane that went quiet shows nothing stale
        self.assertIsNone(lane_memory.gc_timing('another_lane', 1010.0))
        cache.set(lane_memory.CACHE_PREFIX + 'classic', json.dumps({'pid': 1, 'at': 1000.0, 'rss_mb': 5, 'peak_mb': 5, 'tasks': {}}), 600)
        self.addCleanup(cache.delete, lane_memory.CACHE_PREFIX + 'classic')
        cache.set(gevent_gc.GC_KEY + 'classic', json.dumps({'at': 1000.0, 'last_s': 0.01, 'last_full_s': None, 'worst_s': 1.5, 'frozen': 9}), 600)
        self.addCleanup(cache.delete, gevent_gc.GC_KEY + 'classic')
        row = next(r for r in lane_memory.report(1005.0) if r['lane'] == 'classic')
        self.assertEqual(row['gc']['worst_s'], 1.5)

    def test_publishing_never_fails_the_timer(self):
        with mock.patch.object(lane_memory, 'lane_name', return_value='classic'), mock.patch('django.core.cache.cache.set', side_effect=OSError('redis down')):
            gevent_gc.publish()
