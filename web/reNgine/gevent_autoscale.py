"""An autoscaler that works with the gevent pool every CVEngine worker runs (``celery-entrypoint.sh``: ``--pool=gevent --autoscale=N,1``).

Celery's own ``Autoscaler`` was written for the prefork pool. Before celery 5.7 it never let a gevent worker run more than one task while that
task ran (it counted the greenlets running instead of the pool's limit, and its grow raised the semaphore counter without waking the consumer
waiting in ``Pool.spawn``). Celery 5.7 fixed both, and this class now relies on that. Two gaps remain, and are what this class still does:

* a ceiling lowered live (the ``autoscale`` remote control) while every slot is busy brings the pool back down to it, never under the floor;
* a ceiling raised while nothing runs moves the consumer's prefetch with it.

Before 5.7, a discovery worker with an autoscale ceiling of 8 ran one discovery or host assessment at a time for as long as that one ran (a discovery run
or an assessment waiting on Sentinels takes hours), with hundreds of messages waiting behind it. ``tests/test_gevent_autoscale.py`` pins it.

With celery 5.7 the worker takes one more message per second until it runs as many tasks as there is work, up to the ceiling. When there is less work it gives slots
back, at the earliest ``keepalive`` (30 s) after its last scale-up. A live change of the ceiling moves the consumer's prefetch with it
(``_update_consumer_prefetch_count``): for acks_late tasks (``run_bbot_discovery``, ``run_internal_scan``) the prefetch is what bounds how many
run at once. ``reNgine/celery.py`` also turns off celery's prefetch reduction after a broker reconnect, whose restore reads the greenlets
running instead of the ceiling and left acks_late tasks at one at a time until a restart. The ceiling, the ``autoscale`` remote control that resizes it live (``cveFeed.scan_concurrency.apply_discovery``) and
the ``stats`` reply are unchanged. Any other pool (prefork, solo, threads: tests and tools) gets celery's behaviour untouched.
"""
from celery.worker.autoscale import Autoscaler


def _green_pool(pool):
    """The gevent ``Pool`` inside celery's gevent ``TaskPool``, or None for any other pool."""
    inner = getattr(pool, '_pool', None)
    if inner is None or not getattr(pool, 'is_green', False):
        return None
    if not isinstance(getattr(inner, 'size', None), int) or not hasattr(getattr(inner, '_semaphore', None), 'release'):
        return None
    return inner


class GeventAutoscaler(Autoscaler):
    """Celery's autoscaler, made correct for the gevent pool (see the module docstring)."""

    def _maybe_scale(self, req=None):
        # A pool above its ceiling (the ceiling was lowered live with the ``autoscale`` remote control) comes back down to it.
        if _green_pool(self.pool) is not None and self.processes > self.max_concurrency:
            self._shrink(self.processes - self.max_concurrency)
            return True
        return super()._maybe_scale(req)

    def _update_consumer_prefetch_count(self, new_max):
        # Celery's version goes through ``consumer._update_prefetch_count``, which returns early when no greenlet is running and otherwise sets
        # the prefetch from the greenlets running now: a ceiling raised while idle was never honoured for acks_late tasks (the broker hands out
        # only as many unacknowledged messages as the prefetch allows). The prefetch follows the ceiling, as it does at start.
        consumer = getattr(self.worker, 'consumer', None)
        if _green_pool(self.pool) is None or consumer is None:
            return super()._update_consumer_prefetch_count(new_max)
        diff = new_max - self.max_concurrency
        if not diff:
            return None
        multiplier = consumer.prefetch_multiplier
        consumer.initial_prefetch_count = max(new_max, 1) * multiplier
        qos = getattr(consumer, 'qos', None)
        if qos is not None:
            (qos.increment_eventually if diff > 0 else qos.decrement_eventually)(abs(diff) * multiplier)
        return None

    # Celery 5.7 counts a gevent pool by its limit and grows it with ``Semaphore.release`` (celery/concurrency/gevent.py ``grow``), which were
    # the two bugs this class first existed for: ``processes`` and ``_grow`` are celery's own again, so ``TaskPool.limit`` (what ``stats``
    # reports) always matches the pool.

    def _shrink(self, n):
        inner = _green_pool(self.pool)
        if inner is None or n <= 0:
            return super()._shrink(n)
        # Never under the floor. A busy slot can be taken away: the counter goes below zero and the next releases pay it back (what celery's
        # own gevent shrink does), so a ceiling lowered while every slot is busy holds as the running tasks finish.
        n = min(n, inner.size - max(self.min_concurrency, 1))
        if n <= 0:
            return None
        from celery.utils.log import get_logger
        get_logger(__name__).info('Scaling down %s greenlet slots (pool now %s).', n, inner.size - n)
        self.pool.shrink(n)  # celery 5.7: lowers the semaphore, TaskPool.limit and the pool's size together
        return None
