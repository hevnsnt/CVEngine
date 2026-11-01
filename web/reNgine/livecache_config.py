"""The live-screen cache's settings (stage 1: the periodic refresher and the per-user membership cache), read from the environment.

No Django imports, so ``settings.py`` (the beat schedule), the web workers and the Celery worker all read them the same way. Every value is
read when it is asked for, so a test can change one with ``mock.patch.dict(os.environ, ...)``.

* ``CVENGINE_LIVE_REFRESH`` (on): ``0``, ``false``, ``no`` or ``off`` is the kill switch. Nothing is registered as hot and the refresher does
  nothing, so every snapshot is computed by the request that finds it stale, as it was before stage 1.
* ``CVENGINE_LIVE_REFRESH_SECONDS`` (5): how often the refresher runs, 2 to 60.
* ``CVENGINE_LIVE_HOT_SECONDS`` (60): how long a scope stays "hot" after its last request, 15 to 600.
* ``CVENGINE_AUTH_CACHE_SECONDS`` (15): how long the live endpoints keep the set of projects a user may see, 0 to 30; ``0`` turns it off.
"""
import os

OFF = ('0', 'false', 'no', 'off')


def _int(name, default, low, high, environ=None):
    raw = str((os.environ if environ is None else environ).get(name, '')).strip()
    try:
        value = int(float(raw)) if raw else default
    except ValueError:
        value = default
    return max(low, min(high, value))


def refresh_enabled(environ=None):
    return str((os.environ if environ is None else environ).get('CVENGINE_LIVE_REFRESH', '1')).strip().lower() not in OFF


def refresh_seconds(environ=None):
    return _int('CVENGINE_LIVE_REFRESH_SECONDS', 5, 2, 60, environ)


def hot_seconds(environ=None):
    return _int('CVENGINE_LIVE_HOT_SECONDS', 60, 15, 600, environ)


def auth_cache_seconds(environ=None):
    return _int('CVENGINE_AUTH_CACHE_SECONDS', 15, 0, 30, environ)


def beat_entry(environ=None):
    """The refresher's celery beat entry (``settings.CELERY_BEAT_SCHEDULE``): beat writes it to its schedule table at every start, so the cadence
    follows ``CVENGINE_LIVE_REFRESH_SECONDS`` and the row is switched off by ``CVENGINE_LIVE_REFRESH=0``; either change takes effect when beat
    restarts. The message expires after three intervals, so a stopped worker does not come back to a backlog of refreshes."""
    from celery.schedules import schedule
    every = refresh_seconds(environ)
    return {'task': 'refresh_live_snapshots', 'schedule': schedule(run_every=every),
            'options': {'queue': 'live_cache_queue', 'expire_seconds': every * 3}, 'enabled': refresh_enabled(environ)}
