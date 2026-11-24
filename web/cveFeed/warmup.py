"""Startup warm-up: build, once and in the background, what a new process would otherwise build on the first request that needs it.

A new web worker (gunicorn starts two and recycles each after about 1,000 requests) and a new Celery lane pay a few one-off costs on first use.
Measured on a live install with a fresh process (scripts/live_probe.py, read only): the first request of any page or API imported the whole URL
configuration and every view module behind it (about 2.7 s, weasyprint alone 1.2 s), and the first CVE match list or triage read built the
service feature index (``service_features.index``: 24 s when no shared copy exists, a read of every CVE's ``synced_at`` and the changed rows
when one does). The first person to open a page after a restart or a recycle waited for all of it.

``start(role)`` runs ``run(role)`` once per process, in a daemon thread (a greenlet in a gevent Celery worker, where threading is patched), a moment
after the process starts. It never blocks startup, never raises, and is bounded: every step checks a deadline before it starts, and a step that
waits for another process holds no database connection while it waits. The thread closes its own database connections when it ends, so no
connection is left idle. It warms shared public data only: the URL configuration and view modules (no data), the service feature index (public
CVE text and the instance's detection records, the same for every caller, see ``service_features``) and the CVE catalogue counts (the catalogue
belongs to no project, see ``views._catalog_counts``). Nothing per tenant is warmed: the tenancy snapshot, the exclusion lists, the do-not-scan
gate, the current scan ids, the Overview, alert and stats snapshots are per project or per request by design and are never cached across callers
here.

The service feature index is built by one process at a time (``BUILD_LOCK``): a Celery lane (no statement timeout) may build it from the whole
table and shares it through the cache; a web worker (whose statements are cut at 30 s, ``CVENGINE_WEB_STATEMENT_TIMEOUT_MS``) never starts a
full build here: it waits, without a database connection, until a shared copy exists and takes that, or gives up at the deadline and leaves the
work to the first request, as before.

Who starts it: the web workers (``cvengine/wsgi.py``, imported by gunicorn in each worker and by ``runserver``) and the Celery lanes (the
``worker_ready`` signal in ``cvengine/celery.py``). Management commands (``watchdog_tick`` every 30 s, ``migrate``, ``shell``), Celery beat and the
container health check (``celery_healthcheck.py``, a fresh process every minute that loads no Django) never import either hook, so they never
run it. ``CVENGINE_WARMUP=0`` turns it off (default on). One log line per process gives each step's time.
"""
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

DELAY_SECONDS = 1.0  # after the process starts: the worker is serving by then, and the warm-up only fills in behind it
BUDGET_SECONDS = 180.0  # no step starts after this; a waiting step gives up at it
POLL_SECONDS = 2.0  # how often a waiting web worker looks for the shared service feature index
BUILD_LOCK = 'cvengine:warmup:service-features-build'
BUILD_LOCK_SECONDS = 300  # a build that dies without releasing the lock frees it after this
ROLES = ('web', 'celery')

_started = {'pid': None}
_start_lock = threading.Lock()


def enabled():
    """``CVENGINE_WARMUP`` is on unless set to 0, false, no or off."""
    return os.environ.get('CVENGINE_WARMUP', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _close_connections():
    """Close this thread's database connections (Django keeps one per thread), so the warm-up never leaves one open and idle."""
    try:
        from django.db import connections
        for conn in connections.all(initialized_only=True):
            conn.close()
    except Exception:  # noqa: BLE001 - best effort
        logger.debug('could not close the warm-up connections', exc_info=True)


def warm_urls(role, deadline):
    """Import the URL configuration and every view module it names: the first request of a new web worker did it, about 2.7 s. No data."""
    from django.urls import get_resolver
    resolver = get_resolver()
    resolver.url_patterns  # noqa: B018 - imports cvengine.urls and every included urls and views module
    resolver.reverse_dict  # noqa: B018 - and builds the reverse lookup tables the pages use
    return 'ok'


def _shared_index_present():
    from django.core.cache import cache

    from cveFeed import service_features
    key = getattr(service_features, 'INDEX_CACHE_KEY', None)
    if key is None:
        return True  # a version without the shared copy: build in this process as the first request would
    try:
        return cache.get(key) is not None
    except Exception:  # noqa: BLE001 - no cache: nothing to wait for
        return True


def warm_service_features(role, deadline):
    """Build this process's copy of the service feature index (public CVE text and detection records, the same for every caller).

    One process at a time builds (``BUILD_LOCK``). A Celery lane that takes the lock builds it (from the shared copy when there is one, else from
    the whole table, which shares it). Any other process waits, with no database connection, until the lock is free or a shared copy exists,
    then takes it; a web worker never starts a full build here (its statements are cut at 30 s), and gives up at the deadline."""
    from django.core.cache import cache

    from cveFeed import service_features
    while True:
        holder = False
        if role == 'celery' or _shared_index_present():
            try:
                holder = bool(cache.add(BUILD_LOCK, os.getpid(), BUILD_LOCK_SECONDS))
            except Exception:  # noqa: BLE001 - no cache: no other process to wait for
                holder = True
        if holder:
            try:
                service_features.index()
            finally:
                try:
                    cache.delete(BUILD_LOCK)
                except Exception:  # noqa: BLE001
                    pass
            return 'built'
        if time.monotonic() + POLL_SECONDS > deadline:
            return 'skipped: another process was still building it'
        _close_connections()
        time.sleep(POLL_SECONDS)


def warm_catalog_counts(role, deadline):
    """The CVE catalogue's total and tier counts the Overview headline reads (no project's data); shared through the cache, so this is a cache
    read unless the counts changed."""
    from cveFeed import views
    views._catalog_counts()
    return 'ok'


STEPS = {
    'web': (('urls', warm_urls), ('service_features', warm_service_features), ('catalog_counts', warm_catalog_counts)),
    'celery': (('service_features', warm_service_features),),
}


def run(role='web', budget=BUDGET_SECONDS):
    """Run the steps of ``role`` now, in this thread: ``{step: (result, milliseconds)}``. Never raises; logs one line with the timings."""
    started = time.monotonic()
    deadline = started + budget
    out = {}
    try:
        for name, step in STEPS.get(role, ()):
            if time.monotonic() >= deadline:
                out[name] = ('skipped: out of time', 0)
                continue
            t = time.monotonic()
            try:
                result = step(role, deadline)
            except Exception as exc:  # noqa: BLE001 - a warm-up step is never worth an error: the first request does the work instead
                result = f'failed: {type(exc).__name__}'
                logger.debug('startup warm-up step %s failed', name, exc_info=True)
            out[name] = (result, round((time.monotonic() - t) * 1000))
        logger.info('startup warm-up (%s, pid %s) took %d ms: %s', role, os.getpid(), round((time.monotonic() - started) * 1000),
                    ', '.join(f'{name} {ms} ms ({result})' for name, (result, ms) in out.items()))
    except Exception:  # noqa: BLE001
        logger.debug('startup warm-up failed', exc_info=True)
    finally:
        _close_connections()
    return out


def _worker(role, delay):
    try:
        time.sleep(delay)
        run(role)
    except Exception:  # noqa: BLE001 - never let the thread print a traceback into a worker's log
        pass


def start(role='web', delay=DELAY_SECONDS):
    """Start the warm-up of this process in a daemon thread and return at once: True when started, False when it is off
    (``CVENGINE_WARMUP=0``), already started in this process, or the role is unknown. Never raises."""
    try:
        if role not in ROLES or not enabled():
            return False
        with _start_lock:
            if _started['pid'] == os.getpid():
                return False
            _started['pid'] = os.getpid()
        threading.Thread(target=_worker, args=(role, delay), name=f'cvengine-warmup-{role}', daemon=True).start()
        return True
    except Exception:  # noqa: BLE001
        logger.debug('could not start the startup warm-up', exc_info=True)
        return False
