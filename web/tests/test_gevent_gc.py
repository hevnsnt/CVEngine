"""reNgine.gevent_gc: automatic collection off and a timer in a gevent worker, nothing changed anywhere else."""
import gc
from unittest import mock

from django.test import SimpleTestCase

from reNgine import gevent_db, gevent_gc


class GeventGcTests(SimpleTestCase):
    def setUp(self):
        self.was_enabled = gc.isenabled()
        self.addCleanup(lambda: gc.enable() if self.was_enabled else gc.disable())

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
