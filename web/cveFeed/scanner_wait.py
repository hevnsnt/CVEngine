"""Work that waited for a scanner is scanned again once one is back, after a delay, instead of waiting for the target's next scheduled scan.

When a stage cannot run because no scanner took its kind and the kind may not run on this server (``sentinel_dispatch._no_local`` raises
``resources.ScannerUnavailable``), the stage waits: nothing is marked failed and nothing is recorded in the ledger, so its targets stay due. That alone
leaves them for the work conductor, which comes back to a target only after its minimum gap and behind every more overdue one. So a scan or host run
during which any stage waited (``requeues``) queues its hosts once more as a deferred re-test (``cveFeed.retest``, signature ``scanner-wait``), due
``CVENGINE_SCANNER_REQUEUE_MINUTES`` (default 10) later. The re-test dispatcher holds those rows back for as long as a scanner is still missing
(``agentapi.scanner_state.waiting_kinds``) and sends them through the host pipeline once none is: a scanner restart costs a delay, never a failed scan.
Nothing here runs a tool or writes ``ScanControl``.
"""
import contextvars
import functools
import logging
import os
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

SIGNATURE = 'scanner-wait'  # DeferredRetest.signature of a host queued again because its stages waited for a scanner
DEFAULT_DELAY_MINUTES = 10
MAX_HOSTS = 500  # hosts of one run queued again; a larger run's remaining hosts wait for the conductor as before

_waited = contextvars.ContextVar('cvengine_scanner_waited', default=None)


def delay():
    """CVENGINE_SCANNER_REQUEUE_MINUTES: how long after the wait the hosts are tried again (default 10, at least 1)."""
    try:
        return timedelta(minutes=max(1, int(os.environ.get('CVENGINE_SCANNER_REQUEUE_MINUTES', DEFAULT_DELAY_MINUTES))))
    except ValueError:
        return timedelta(minutes=DEFAULT_DELAY_MINUTES)


def noted(kind):
    """Called where a stage waits for a scanner: remembers ``kind`` for the run in this context (a pipeline wrapped by ``requeues``); a no-op outside one."""
    kinds = _waited.get()
    if kinds is not None:
        kinds.add(kind)


def requeues(names_of):
    """Decorator for a pipeline entry point that returns a dict with ``scan_id``: the stages it ran are watched, and when any waited for a scanner the run's
    hosts are queued again (``queue``). ``names_of(result, args, kwargs)`` gives the host names, or ``None`` for every host the scan recorded."""
    def wrap(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            kinds = set()
            token = _waited.set(kinds)
            try:
                result = func(*args, **kwargs)
            finally:
                _waited.reset(token)
            if kinds and isinstance(result, dict):
                result['scanner_waited'] = sorted(kinds)  # a re-test that waited again stays pending (cveFeed.tasks.retest_hosts)
            if kinds and isinstance(result, dict) and result.get('scan_id'):
                try:
                    queue(result['scan_id'], kinds, names_of(result, args, kwargs))
                except Exception:  # noqa: BLE001 - a re-queue that could not be written leaves the hosts to the conductor, as before
                    logger.exception('could not queue the hosts of scan %s again after waiting for a scanner', result.get('scan_id'))
            return result
        return inner
    return wrap


def queue(scan_id, kinds, names=None):
    """Queue the hosts of scan ``scan_id`` (or ``names``) to be tried again once a scanner for ``kinds`` is back. Returns how many were queued.
    Active rows coalesce (one waiting row per project, host and this signature at a time)."""
    from cveFeed import activity
    from cveFeed.models import DeferredRetest
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain').filter(pk=scan_id).first()
    if scan is None or scan.domain is None or scan.domain.project_id is None:
        return 0
    if names is None:
        names = Subdomain.objects.filter(scan_history=scan).order_by('id').values_list('name', flat=True)[:MAX_HOSTS]
    hosts = list(dict.fromkeys(n.strip().lower().rstrip('.') for n in names if n and n.strip()))[:MAX_HOSTS]
    if not hosts:
        return 0
    due = timezone.now() + delay()
    DeferredRetest.objects.bulk_create([DeferredRetest(project_id=scan.domain.project_id, domain=scan.domain, scan=scan, host=host,
                                                       signature=SIGNATURE, next_attempt_at=due) for host in hosts], ignore_conflicts=True)
    activity.log('run_check', f'{len(hosts)} host(s) of {scan.domain.name} waited for a scanner ({", ".join(sorted(kinds))}); they are scanned '
                 'again once one is back', project=scan.domain.project_id, scan_id=scan.id)
    return len(hosts)


def held_back():
    """Whether the waiting re-tests must stay pending: some kind is still waiting for a scanner. A reading that fails holds them back too (they are
    tried at the next round)."""
    try:
        from agentapi import scanner_state
        return bool(scanner_state.waiting_kinds())
    except Exception:  # noqa: BLE001
        return True
