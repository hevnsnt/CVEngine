"""The discovery worker (and every other worker) runs a gevent pool under ``--autoscale=N,1``. Celery's own autoscaler never let such a worker run a
second task while the first one ran: a discovery run or a host assessment waiting on Sentinels held the only slot for hours while hundreds of
messages waited (the "Sentinels idle, 360 assessments pending" report). ``reNgine.gevent_autoscale.GeventAutoscaler`` is the fix; these tests drive
celery's real gevent ``TaskPool`` and gevent's real ``Pool``, with the worker's reserved requests stood in for."""
import unittest
from unittest import mock

import gevent
from celery.concurrency.gevent import TaskPool
from celery.worker import autoscale as celery_autoscale
from celery.worker.autoscale import Autoscaler
from gevent.event import Event

from reNgine.gevent_autoscale import GeventAutoscaler


class Harness:
    """A celery gevent pool of ``size`` slots, tasks that run until released, and the consumer's ``spawn`` that blocks when the pool is full."""

    def __init__(self, size=1):
        self.pool = TaskPool(limit=size)
        self.pool.start()
        self.inner = self.pool._pool
        self.release = Event()
        self.started = []
        self.reserved = set()

    def task(self, n):
        def run():
            self.started.append(n)
            self.release.wait()
            self.reserved.discard(n)
        return run

    def deliver(self, n):
        """What the worker's consumer does with one message: reserve it, then spawn it, waiting in ``Pool.spawn`` while the pool is full."""
        self.reserved.add(n)
        consumer = gevent.spawn(self.inner.spawn, self.task(n))
        gevent.sleep(0.01)  # it runs now: the task starts, or the consumer is left waiting in spawn
        return consumer

    def scaler(self, cls, max_concurrency=8, min_concurrency=1):
        return cls(self.pool, max_concurrency, min_concurrency, worker=mock.Mock(consumer=mock.Mock(prefetch_multiplier=1)))

    def tick(self, scaler, times=1):
        """One autoscaler round per second in a worker; here back to back, letting greenlets run in between."""
        with mock.patch.object(celery_autoscale, 'state', mock.Mock(reserved_requests=self.reserved)):
            for _ in range(times):
                scaler.maybe_scale()
                gevent.sleep(0.01)

    def finish(self):
        self.release.set()
        gevent.sleep(0.05)


class GeventAutoscalerTests(unittest.TestCase):

    def test_celerys_own_autoscaler_keeps_a_gevent_worker_at_one_task_while_it_runs(self):
        # The bug this module works around, pinned: if a celery release fixes it, this test says the workaround can go.
        h = Harness()
        h.deliver(1)
        h.deliver(2)  # the consumer now waits in spawn with the second message
        scaler = h.scaler(Autoscaler)
        h.tick(scaler, 5)
        self.assertEqual(h.started, [1])  # five "Scaling up" rounds, still one task running
        self.assertEqual(scaler.processes, 1)  # it counts running greenlets, not the pool's limit...
        self.assertGreaterEqual(h.inner.size, 6)  # ...so it raised the limit every round, and none of it reached the waiting consumer
        h.finish()

    def test_the_worker_takes_the_next_message_while_a_long_task_runs(self):
        h = Harness()
        h.deliver(1)
        h.deliver(2)
        scaler = h.scaler(GeventAutoscaler)
        h.tick(scaler)
        self.assertEqual(h.started, [1, 2])
        self.assertEqual((scaler.processes, h.inner.size, len(h.inner)), (2, 2, 2))
        h.finish()

    def test_it_ramps_up_to_the_ceiling_one_slot_a_round_and_no_further(self):
        h = Harness()
        waiting = []

        def consumer():  # the real consumer delivers one message at a time, waiting in spawn when full
            for n in range(1, 13):
                h.reserved.add(n)
                waiting.append(n)
                h.inner.spawn(h.task(n))
        gevent.spawn(consumer)
        gevent.sleep(0.01)
        scaler = h.scaler(GeventAutoscaler, max_concurrency=4)
        h.tick(scaler, 10)
        self.assertEqual(h.started, [1, 2, 3, 4])
        self.assertEqual((scaler.processes, len(h.inner)), (4, 4))
        self.assertEqual(scaler.info()['max'], 4)
        h.finish()

    def test_it_shrinks_back_after_the_keepalive_when_the_work_is_done(self):
        h = Harness()
        scaler = h.scaler(GeventAutoscaler)
        for n in (1, 2, 3):
            h.deliver(n)
            h.tick(scaler)
        self.assertEqual(h.inner.size, 3)
        h.finish()
        scaler._last_scale_up -= scaler.keepalive + 1
        h.tick(scaler)
        self.assertEqual((scaler.processes, h.inner._semaphore.counter), (1, 1))  # back to the floor, the one slot free

    def test_a_ceiling_lowered_live_holds_as_the_running_tasks_finish(self):
        h = Harness()
        scaler = h.scaler(GeventAutoscaler)
        for n in (1, 2, 3):
            h.deliver(n)
            h.tick(scaler)
        self.assertEqual(len(h.started), 3)
        scaler.update(max=1)  # the ``autoscale`` remote control (cveFeed.scan_concurrency.apply_discovery)
        self.assertEqual(scaler.processes, 1)
        h.deliver(4)
        self.assertEqual(h.started, [1, 2, 3])
        h.release.set()  # the three running ones finish; only then may the fourth start, alone
        gevent.sleep(0.05)
        self.assertEqual(h.started, [1, 2, 3, 4])
        self.assertEqual(h.inner._semaphore.counter, 1)  # it too has finished (the shared release event): the one slot is free again

    def test_the_ceiling_cannot_shrink_the_pool_under_its_floor(self):
        h = Harness()
        scaler = h.scaler(GeventAutoscaler, min_concurrency=1)
        scaler._shrink(5)
        self.assertEqual(h.inner.size, 1)

    def test_any_other_pool_gets_celerys_behaviour(self):
        pool = mock.Mock(spec=['num_processes', 'grow', 'shrink', 'maintain_pool'], num_processes=3)
        scaler = GeventAutoscaler(pool, 8, 1, worker=mock.Mock())
        self.assertEqual(scaler.processes, 3)
        scaler._grow(2)
        pool.grow.assert_called_once_with(2)
        scaler._shrink(1)
        pool.shrink.assert_called_once_with(1)


class WorkerConfigurationTests(unittest.TestCase):

    def test_every_worker_of_the_app_uses_it(self):
        from reNgine.celery import app
        self.assertEqual(app.conf.worker_autoscaler, 'reNgine.gevent_autoscale:GeventAutoscaler')
        from celery.utils.imports import symbol_by_name
        self.assertIs(symbol_by_name(app.conf.worker_autoscaler), GeventAutoscaler)
        self.assertFalse(app.conf.worker_enable_prefetch_count_reduction)  # its restore reads the greenlets running (test_gevent_worker_e2e)

    def test_a_live_change_of_the_ceiling_moves_the_prefetch_even_with_nothing_running(self):
        h = Harness()
        consumer = mock.Mock(prefetch_multiplier=1, initial_prefetch_count=8)
        scaler = GeventAutoscaler(h.pool, 8, 1, worker=mock.Mock(consumer=consumer))
        scaler.update(max=12)
        self.assertEqual(consumer.initial_prefetch_count, 12)
        consumer.qos.increment_eventually.assert_called_once_with(4)
        scaler.update(max=3)
        self.assertEqual(consumer.initial_prefetch_count, 3)
        consumer.qos.decrement_eventually.assert_called_once_with(9)
