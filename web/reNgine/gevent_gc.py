"""Run Python's garbage collector on a timer in a gevent worker, not at whatever allocation reaches its threshold.

The Celery workers of the production VPS crashed with SIGSEGV every 20 to 90 minutes (and 5 to 15 times an hour while they were catching up). Every crash
we could read has the same shape: the process was inside the cyclic garbage collector (``Garbage-collecting`` in the Python traceback, the interrupted
instruction a pointer chase through the collector's object list in ``python3``), at a greenlet's first moments (``<invalid frame>``). Python 3.14 runs an
incremental collector (``gc.get_threshold()`` is ``(2000, 10, 0)``), which starts a step from any allocation, including one made while greenlet is
switching stacks. Python's own crash handler then fails again in libgcc_s while it prints the C stack, which is why the kernel's line points at the
unwinder, not at the collector.

With the automatic collector off and a full collection run from a timer greenlet (a place where no greenlet is half started), the cycles are still
collected, at a fixed rhythm, and the collector never starts inside a switch. ``CVENGINE_GC_MANUAL=0`` puts the interpreter's own behavior back.
Installed only in a process whose sockets gevent has patched (a gevent worker): the web server, beat, the tests and management commands keep Python's own.
"""
import gc
import logging
import os
import time

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 30
SLOW_SECONDS = 1.0  # a collection this long is worth a line in the log


def enabled():
    return os.environ.get('CVENGINE_GC_MANUAL', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def collect_once():
    """One full collection; returns how long it took."""
    started = time.monotonic()
    gc.collect()
    took = time.monotonic() - started
    if took > SLOW_SECONDS:
        logger.warning('gevent_gc: a full collection took %.1f s', took)
    return took


def _loop(sleep):
    while True:
        sleep(INTERVAL_SECONDS)
        try:
            collect_once()
        except Exception:  # noqa: BLE001 - housekeeping must never end the timer
            logger.exception('gevent_gc: collection failed')


def install():
    """True when the automatic collector was turned off and the timer started (this process is a gevent worker)."""
    from reNgine import gevent_db
    if not enabled() or not gevent_db.gevent_patched():
        return False
    import gevent
    gc.disable()
    gevent.spawn(_loop, gevent.sleep)
    logger.info('gevent_gc: automatic garbage collection is off; a full collection runs every %s s', INTERVAL_SECONDS)
    return True
