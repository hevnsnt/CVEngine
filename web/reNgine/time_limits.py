"""Generous per-queue time limits for Celery tasks.

A task that hangs (a socket with no timeout, a subprocess that never exits, a lock never released) holds its worker slot for ever;
nothing but a restart would end it. Each queue gets a hard limit set far above its slowest legitimate run, so only a hung task meets it.
A task that declares its own ``time_limit`` keeps it.

The scan queues are not given a short limit: a task that needs memory waits inside ``resources.heavy_job`` for its turn (up to
``HEAVY_WAIT_SECONDS``, a day) before it runs, so a limit of a few hours would kill queued work that is only waiting. They get the longest
limit that is safe, the broker's redelivery window: a task that outlives it is delivered to a second worker anyway. The light queues
(API, notifications, geolocation) never wait for memory and get half an hour.

The workers run the gevent pool (celery-entrypoint.sh). There the hard limit ends a task that is waiting (a sleep, a socket, a subprocess
wait) and marks it failed (``TimeLimitExceeded``), freeing its slot; it cannot interrupt a task that is computing without ever yielding, and
the soft limit (the prefork pool's gentle warning) is not delivered at all. The soft value is still set, so a prefork pool would use it.

``CVENGINE_TIME_LIMIT_<QUEUE>`` (the queue name without ``_queue``, upper case, in seconds) overrides a queue; ``0`` turns its limit off.
``CVENGINE_TIME_LIMITS=0`` turns every default off. A limit is held below the broker's visibility timeout (``CELERY_VISIBILITY_TIMEOUT``,
12 hours by default): a task allowed to run longer than that would be delivered to a second worker while it still runs."""
import os

HOUR = 3600
SOFT_MARGIN = 300  # the soft limit comes this long before the hard one
MIN_SECONDS = 60
VISIBILITY_MARGIN = 600

# hard limit in seconds per queue (a value above the redelivery window is held to it, see ``_ceiling``); a queue that is not here has no
# limit. openvas_queue is left out on purpose: a local OpenVAS task has a budget of 24 hours per host (cveFeed.openvas_scan.
# DEFAULT_MAX_HOURS) and keeps its own deadline.
SCAN_QUEUE = 24 * HOUR  # "as long as is safe"
DEFAULTS = {
    'discovery_queue': SCAN_QUEUE,
    'cve_feed_queue': SCAN_QUEUE,
    'validation_priority_queue': SCAN_QUEUE,
    'wpscan_queue': SCAN_QUEUE,
    'testssl_queue': SCAN_QUEUE,
    'screenshot_queue': 2 * HOUR,  # a drain stops taking batches after 40 minutes; a browser that hangs is killed long before this
    'bucketscan_queue': SCAN_QUEUE,
    'vhost_queue': SCAN_QUEUE,
    'udp_queue': SCAN_QUEUE,
    'supplier_queue': SCAN_QUEUE,
    'ctwatch_queue': 1 * HOUR,  # a lookup waits at most ``ctmonitor.MAX_INLINE_WAIT`` in a slot; a longer wait is a retry
    'run_command_queue': 1 * HOUR,
    'api_queue': 30 * 60,
    'send_notif_queue': 30 * 60,
    'send_task_notif_queue': 30 * 60,
    'geo_localize_queue': 30 * 60,
}


def _ceiling(environ):
    try:
        visibility = int(environ.get('CELERY_VISIBILITY_TIMEOUT') or 12 * HOUR)
    except ValueError:
        visibility = 12 * HOUR
    return max(MIN_SECONDS * 2, visibility - VISIBILITY_MARGIN)


def limits_for(queue, environ=None):
    """``(soft, hard)`` seconds for a task of ``queue``, or None when it has no limit."""
    environ = os.environ if environ is None else environ
    if not queue or str(environ.get('CVENGINE_TIME_LIMITS', '1')).strip() == '0':
        return None
    name = str(queue)
    key = 'CVENGINE_TIME_LIMIT_' + (name[:-6] if name.endswith('_queue') else name).upper()
    raw = environ.get(key)
    if raw is not None and str(raw).strip() != '':
        try:
            hard = int(raw)
        except ValueError:
            hard = DEFAULTS.get(name, 0)
    else:
        hard = DEFAULTS.get(name, 0)
    if hard <= 0:
        return None
    hard = max(MIN_SECONDS * 2, min(hard, _ceiling(environ)))
    return max(MIN_SECONDS, hard - SOFT_MARGIN), hard


class QueueTimeLimits:
    """A Celery ``task_annotations`` entry: gives a task the limits of its queue unless it declared its own."""

    def annotate(self, task):
        if getattr(task, 'time_limit', None) or getattr(task, 'soft_time_limit', None):
            return None
        found = limits_for(getattr(task, 'queue', None))
        if not found:
            return None
        return {'soft_time_limit': found[0], 'time_limit': found[1]}
