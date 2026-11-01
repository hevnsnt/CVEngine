"""An autoscaler that works with the gevent pool every CVEngine worker runs (``celery-entrypoint.sh``: ``--pool=gevent --autoscale=N,1``).

Celery's own ``Autoscaler`` was written for the prefork pool, and with gevent it never lets a worker run more than one task while that task
runs. Two things go wrong together:

* it counts the pool's size with ``pool.num_processes``, which for gevent is the number of greenlets running *now*, not the pool's limit.
  With one long task running and one more message taken off the queue, it sees "1 of 1 busy, 2 wanted" and grows the pool, every second,
  forever (the worker log fills with "Scaling up 1 processes.");
* gevent's ``TaskPool.grow`` raises the pool's semaphore counter directly, which does not wake the greenlet already waiting on it. That
  waiter is the worker's consumer, blocked in ``Pool.spawn`` with the next message, so no further message is taken until the running task
  ends. Then the swollen pool lets everything waiting in at once, above the ceiling.

So a discovery worker with an autoscale ceiling of 8 ran one discovery or host assessment at a time for as long as that one ran (a bbot run
or an assessment waiting on Sentinels takes hours), with hundreds of messages waiting behind it. ``tests/test_gevent_autoscale.py`` pins it.

This subclass counts the pool's limit (``Pool.size``) and grows it with ``Semaphore.release``, which wakes the waiting consumer: the worker
takes one more message per second until it runs as many tasks as there is work, up to the ceiling, and shrinks back after the keepalive
when there is less. The ceiling, the ``autoscale`` remote control that resizes it live (``cveFeed.scan_concurrency.apply_discovery``) and
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

    @property
    def processes(self):
        inner = _green_pool(self.pool)
        return inner.size if inner is not None else self.pool.num_processes

    def _grow(self, n):
        inner = _green_pool(self.pool)
        if inner is None or n <= 0:
            return super()._grow(n)
        from celery.utils.log import get_logger
        get_logger(__name__).info('Scaling up %s greenlet slots (pool now %s).', n, inner.size + n)
        inner.size += n
        for _ in range(n):
            inner._semaphore.release()  # release, not ``counter += 1``: it wakes the consumer waiting in Pool.spawn

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
        inner.size -= n
        inner._semaphore.counter -= n
        return None
