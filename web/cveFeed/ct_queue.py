"""Publishing certificate-transparency lookups without letting ``ctwatch_queue`` grow without bound.

Before this module the sweep (``watch_certificates_all``) queued up to an hour of lookups every interval with no memory of what it had
already queued, and the only consumer drains at crt.sh's pace, so any slowdown became a backlog that never emptied (and past
``broker_recovery.MAX_QUEUE_SCAN`` messages the reaper's orphan recovery stops). Three guards live here, shared by the sweep and by the
paths that add a target:

* a per-domain "queued" marker in Redis (``SET NX EX``): a domain with a lookup already on its way is not queued again; the task clears
  it when the lookup reaches a terminal outcome (``clear``), and it expires by itself a little after the message does;
* a message lifetime (``expires=``) on every publish, which Celery carries over to the retries of the same message, so a lookup nobody
  got to is dropped by the worker instead of waiting forever;
* a backlog cap (``backlog`` / ``backlog_max``) the sweep reads before it queues anything.

A lookup that failed for good is remembered in the ledger as ``ct-watch-failed`` (``record_failure``) and the sweep leaves it alone for that
kind's TTL. Redis being unavailable fails open: the lookup is queued as before (still with its lifetime).
"""
import logging
import os

logger = logging.getLogger(__name__)

QUEUE = 'ctwatch_queue'
FAILED_SERVICE = 'ct-watch-failed'  # a target whose lookup failed for good: not asked again by the sweep until this ledger kind's TTL passes
MARKER_PREFIX = 'cvengine:ctwatch:queued:'
MARKER_GRACE = 600  # seconds the marker outlives the message it stands for, so an expired message never leaves a domain unqueueable for long
SPACING = 2.5  # seconds between lookup starts: crt.sh blocks a burst
ADD_LIFETIME = 6 * 3600  # seconds a lookup queued when a target is added may wait before it is dropped
DEFAULT_BACKLOG_MAX = 500  # CVENGINE_CT_BACKLOG_MAX: messages the sweep lets wait in ctwatch_queue (never below one sweep batch)


def _client():
    try:
        from reNgine import resources
        return getattr(resources.get_store(), 'r', None)
    except Exception:  # noqa: BLE001 - bookkeeping must never stop a lookup being queued
        return None


def backlog_max(batch=0):
    """The most messages the sweep lets wait in ``ctwatch_queue``: ``CVENGINE_CT_BACKLOG_MAX`` when it is a positive whole number, else
    ``DEFAULT_BACKLOG_MAX`` and never less than one sweep ``batch``."""
    try:
        value = int(os.environ.get('CVENGINE_CT_BACKLOG_MAX', ''))
        if value > 0:
            return value
    except ValueError:
        pass
    return max(DEFAULT_BACKLOG_MAX, int(batch))


def backlog():
    """Messages waiting in ``ctwatch_queue`` (every priority step, as the status page counts them), or None when the broker cannot be read."""
    client = _client()
    if client is None:
        return None
    try:
        from cveFeed.broker_recovery import PRIORITY_SUFFIXES
        return sum(int(client.llen(QUEUE + suffix)) for suffix in PRIORITY_SUFFIXES)
    except Exception:  # noqa: BLE001
        logger.warning('ct watch: could not read the backlog of %s', QUEUE)
        return None


def _key(domain_id):
    return f'{MARKER_PREFIX}{domain_id}'


def _mark(client, domain_id, seconds):
    """True when this domain may be queued now: its marker was set, or Redis could not say (fail open)."""
    if client is None:
        return True
    try:
        return bool(client.set(_key(domain_id), '1', nx=True, ex=max(60, int(seconds))))
    except Exception:  # noqa: BLE001
        return True


def clear(domain_id):
    """Drop the marker of a lookup that reached a terminal outcome (never raises)."""
    client = _client()
    if client is None:
        return
    try:
        client.delete(_key(domain_id))
    except Exception:  # noqa: BLE001 - it expires by itself
        pass


def is_queued(domain_id):
    client = _client()
    try:
        return bool(client is not None and client.exists(_key(domain_id)))
    except Exception:  # noqa: BLE001
        return False


def queue_lookups(domain_ids, lifetime, spacing=SPACING, limit=None):
    """Publish one ``watch_certificate_transparency`` per domain id not already marked as queued, the n-th starting ``n * spacing`` seconds
    from now and dropped if still waiting ``lifetime`` seconds after that, at most ``limit`` of them. Returns the ids queued.
    A publish that fails clears its marker and raises, as a bare ``apply_async`` did."""
    from cveFeed.tasks import watch_certificate_transparency
    client = _client()
    queued = []
    for domain_id in domain_ids:
        if limit is not None and len(queued) >= limit:
            break
        countdown = int(len(queued) * spacing)
        expires = countdown + int(lifetime)
        if not _mark(client, domain_id, expires + MARKER_GRACE):
            continue
        try:
            watch_certificate_transparency.apply_async(args=[domain_id], countdown=countdown, expires=expires)
        except Exception:
            clear(domain_id)
            raise
        queued.append(domain_id)
    return queued


def recently_failed(rows):
    """The ids among ``rows`` (``(domain_id, name, project_id)``) whose lookup failed for good within ``ct-watch-failed``'s TTL."""
    from cveFeed import ledger
    by_project, ids = {}, {}
    for domain_id, name, project_id in rows:
        by_project.setdefault(project_id, []).append(name)
        ids.setdefault((project_id, ledger._norm(name)), []).append(domain_id)
    failed = set()
    for project_id, names in by_project.items():
        for asset in ledger.fresh(FAILED_SERVICE, names, project_id):
            failed.update(ids.get((project_id, asset), ()))
    return failed


def record_failure(domain_id):
    """Remember that this domain's lookup failed for good (never raises)."""
    try:
        from cveFeed import ledger
        from targetApp.models import Domain
        row = Domain.objects.filter(pk=domain_id).values_list('name', 'project_id').first()
        if row:
            ledger.record(FAILED_SERVICE, [row[0]], row[1])
    except Exception:  # noqa: BLE001
        logger.exception('ct watch: could not record the failure of domain %s', domain_id)
