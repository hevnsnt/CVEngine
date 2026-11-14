"""Run Python's garbage collector on a timer in a gevent worker, not at whatever allocation reaches its threshold.

The Celery workers of the production VPS crashed with SIGSEGV every 20 to 90 minutes (and 5 to 15 times an hour while they were catching up). Every crash
we could read has the same shape: the process was inside the cyclic garbage collector (``Garbage-collecting`` in the Python traceback, the interrupted
instruction a pointer chase through the collector's object list in ``python3``), at a greenlet's first moments (``<invalid frame>``). Python 3.14 runs an
incremental collector (``gc.get_threshold()`` is ``(2000, 10, 0)``), which starts a step from any allocation, including one made while greenlet is
switching stacks. Python's own crash handler then fails again in libgcc_s while it prints the C stack, which is why the kernel's line points at the
unwinder, not at the collector.

With the automatic collector off and a full collection run from a timer greenlet (a place where no greenlet is half started), the cycles are still
collected, at a fixed rhythm, and the collector never starts inside a switch. ``CVENGINE_GC_MANUAL=0`` puts the interpreter's own behavior back.

What the timer walks is kept small, because a collection stops every greenlet of the process (the 30 s timer used to walk every object the worker holds: about 300,000 right
after start, 0.1 s on a fast core and seconds on a starved one, in each of the four lanes). Once the worker has finished loading (celery's ``worker_ready``: Django, every task
module and the caches are imported), the timer greenlet runs one full collection and then ``gc.freeze()``: the start-up objects move to the permanent generation, which no
collection looks at. After that a tick collects only the young generations (``gc.collect(1)``), and a full collection (``gc.collect()``, of everything not frozen) runs every
``FULL_EVERY`` ticks, so a cycle that outlived two young collections is still freed, a few minutes later. Frozen objects are never re-frozen and never unfrozen: a second
freeze would move whatever the worker holds by then, cycles that have become garbage among it included, out of the collector's reach for good, and the start-up objects of a
worker are not garbage until the process ends (a cycle among them that is dropped later is freed by reference counting or stays, which is a few kilobytes, not growth).
Each tick publishes its timing (the last and the worst collection of the lane) for the system status (``reNgine/lane_memory.py``).
Installed only in a process whose sockets gevent has patched (a gevent worker): the web server, beat, the tests and management commands keep Python's own.
"""
import gc
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 30
FULL_EVERY = 20  # ticks: a full collection of what is not frozen every 10 minutes; the other ticks collect only the young generations
SLOW_SECONDS = 1.0  # a collection this long is worth a line in the log...
SLOW_LOG_EVERY = 600  # ...but not more than one line this often (a starved host makes every collection slow; the status has the numbers)
GC_KEY = 'lane_gc:'  # cache key prefix, one per lane: what the timer last published (read by reNgine.lane_memory.report)
GC_KEEP_SECONDS = 3600

_state = {'ticks': 0, 'frozen': False, 'collections': 0, 'last_s': None, 'last_full_s': None, 'worst_s': 0.0, 'freeze_s': None, 'slow_logged_at': None, 'slow_skipped': 0,
          'loaded': None}


def enabled():
    return os.environ.get('CVENGINE_GC_MANUAL', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _log_slow(generation, took):
    now = time.monotonic()
    if _state['slow_logged_at'] is not None and now - _state['slow_logged_at'] < SLOW_LOG_EVERY:
        _state['slow_skipped'] += 1
        return
    _state['slow_logged_at'] = now
    more = f" ({_state['slow_skipped']} more since the last line)" if _state['slow_skipped'] else ''
    _state['slow_skipped'] = 0
    logger.warning('gevent_gc: a %s collection took %.1f s%s', 'full' if generation >= 2 else 'young', took, more)


def collect_once(generation=2):
    """One collection of ``generation`` and younger (2 is a full one, of everything not frozen); returns how long it took."""
    started = time.monotonic()
    gc.collect(generation)
    took = time.monotonic() - started
    _state['collections'] += 1
    _state['last_s'] = took
    _state['worst_s'] = max(_state['worst_s'], took)
    if generation >= 2:
        _state['last_full_s'] = took
    if took > SLOW_SECONDS:
        _log_slow(generation, took)
    return took


def freeze_after_load():
    """Once, after the worker has loaded: drop the start-up garbage with one full collection, then move what is left out of the collector's view. Runs in the timer
    greenlet. Returns how many objects were frozen (0 when it had already run)."""
    if _state['frozen']:
        return 0
    started = time.monotonic()
    gc.collect()
    gc.freeze()
    _state['frozen'] = True
    _state['freeze_s'] = time.monotonic() - started
    count = gc.get_freeze_count()
    logger.info('gevent_gc: the worker has loaded; %d objects moved out of the collector\'s view (%.2f s); a tick now collects only what was allocated since', count, _state['freeze_s'])
    return count


def tick():
    """One timer tick: young generations only, except every ``FULL_EVERY``th, which is a full collection of what is not frozen."""
    _state['ticks'] += 1
    took = collect_once(2 if _state['ticks'] % FULL_EVERY == 0 else 1)
    publish()
    return took


def stats():
    """What the timer has done so far in this process (seconds are None before the first collection)."""
    return {'last_s': _state['last_s'], 'last_full_s': _state['last_full_s'], 'worst_s': _state['worst_s'], 'freeze_s': _state['freeze_s'], 'collections': _state['collections'],
            'frozen': gc.get_freeze_count()}


def publish(now=None):
    """Write this lane's collection timing where the system status reads it. Never raises."""
    try:
        from django.core.cache import cache

        from reNgine import lane_memory
        lane = lane_memory.lane_name()
        if not lane:
            return
        cache.set(GC_KEY + lane, json.dumps(dict(stats(), pid=os.getpid(), at=time.time() if now is None else now)), GC_KEEP_SECONDS)
    except Exception:  # noqa: BLE001 - a measurement must never end the timer
        logger.debug('gevent_gc: could not publish the collection timing', exc_info=True)


def _loop(sleep):
    while True:
        sleep(INTERVAL_SECONDS)
        try:
            loaded = _state['loaded']
            if loaded is not None and loaded.is_set() and not _state['frozen']:
                freeze_after_load()
            else:
                tick()
        except Exception:  # noqa: BLE001 - housekeeping must never end the timer
            logger.exception('gevent_gc: collection failed')


def install():
    """True when the automatic collector was turned off and the timer started (this process is a gevent worker)."""
    from reNgine import gevent_db
    if not enabled() or not gevent_db.gevent_patched():
        return False
    import gevent
    import gevent.event
    from celery.signals import worker_ready
    loaded = _state['loaded'] = gevent.event.Event()
    worker_ready.connect(lambda **kw: loaded.set(), weak=False, dispatch_uid='gevent-gc-loaded')

    def wait(seconds):  # the timer wakes as soon as the worker has loaded, to freeze; after that it is a plain sleep
        if loaded.is_set() and _state['frozen']:
            gevent.sleep(seconds)
        else:
            loaded.wait(seconds)
    gc.disable()
    gevent.spawn(_loop, wait)
    logger.info('gevent_gc: automatic garbage collection is off; the start-up objects are frozen once the worker has loaded, then a collection of the young ones runs every %s s '
                'and a full one every %s s', INTERVAL_SECONDS, INTERVAL_SECONDS * FULL_EVERY)
    return True
