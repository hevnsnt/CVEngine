"""Fallback telemetry: the gate for deleting a local scan path (docs/SCANNER-ARCHITECTURE.md, phase 5).

Every time a stage that could have used a Sentinel runs its tool on this server instead (or is allowed to: ``CVENGINE_LOCAL_FALLBACK`` lets the kind
run here and nothing took the work), ``sentinel_dispatch._no_local`` calls ``record`` with ``(kind, project, reason)``: one INSERT into
``agentapi.ScannerFallback``, nothing else on the scan's path. A kind that is off the fallback list never runs here (its stage waits), so it records nothing.
A row holds no target, address or host name. Rows older than ``RETENTION_DAYS`` are pruned by the weekly maintenance (``cveFeed.maintenance``).

Recording must never break or slow a scan: it runs in its own savepoint, catches everything, and logs the first failure of the process (later ones at
debug level) so a broken table is noticed once and does not flood the log.

``counts`` and ``last_at`` answer ``manage.py scanner_fallbacks`` and the ``scanning.scanner.fallbacks`` block of the system status. ``ready_to_delete`` is
the gate itself: the kinds with no fallback in the last ``SOAK_HOURS`` hours and a live built-in scanner that declares the kind. The clock of that window
starts when this code is first deployed: an empty table says nothing about the days before it.
"""
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

# Why a stage ran (or was allowed to run) locally. ``over_chunk`` is the one beyond the five a stage can name when the Sentinel was asked and
# answered: a port sweep carries more addresses than one task does, so the rest runs here.
REASONS = ('no_scanner', 'not_claimed_in_time', 'slot_busy', 'failed_then_local', 'completion_timeout', 'over_chunk')
RETENTION_DAYS = 30  # rows older than this are deleted by the weekly maintenance
SOAK_HOURS = 72  # a kind is ready to delete after this many hours with no fallback (the maintainer's gate, with the fake-scanner tests)
STATUS_DAYS = 7  # the window of the system status block
NO_STAGE = ('waf',)  # kinds no stage dispatches: they have no local path to delete (same as ``scanner_state.NO_STAGE``)

_warned = False  # the first failure to record in this process was logged at warning level


def record(kind, project, reason, now=None):
    """Write one fallback row. Never raises and returns whether it was written: a failure is logged (once per process at warning level) and swallowed."""
    global _warned
    try:
        from agentapi.models import ScannerFallback
        values = {'kind': kind, 'project': project if getattr(project, 'pk', None) else None, 'reason': reason}
        if now is not None:
            values['created_at'] = now
        with transaction.atomic():  # a savepoint: a failed insert must not poison the transaction a stage may be running in
            ScannerFallback.objects.create(**values)
        return True
    except Exception:  # noqa: BLE001 - telemetry is never worth a scan
        if not _warned:
            _warned = True
            logger.warning('scanner fallback telemetry could not be recorded (further failures are logged at debug level)', exc_info=True)
        else:
            logger.debug('scanner fallback telemetry could not be recorded', exc_info=True)
        return False


def _window(days, kind=None, now=None):
    from agentapi.models import ScannerFallback
    now = now or timezone.now()
    rows = ScannerFallback.objects.filter(created_at__gte=now - timedelta(days=days))
    return rows.filter(kind=kind) if kind else rows


def counts(days=STATUS_DAYS, kind=None, now=None):
    """``{kind: {'count': n, 'last_at': datetime, 'reasons': {reason: n}}}`` for the last ``days`` days (one grouped query), only kinds with a row."""
    from django.db.models import Count, Max
    out = {}
    for k, reason, n, last in _window(days, kind, now).values_list('kind', 'reason').annotate(n=Count('id'), last=Max('created_at')).order_by('kind', 'reason'):
        row = out.setdefault(k, {'count': 0, 'last_at': last, 'reasons': {}})
        row['count'] += n
        row['reasons'][reason] = n
        if last > row['last_at']:
            row['last_at'] = last
    return out


def last_at(kind=None, now=None):
    """``{kind: datetime}``: when each kind last ran locally, over the whole retention (a kind with no row is absent)."""
    from django.db.models import Max
    return dict(_window(RETENTION_DAYS, kind, now).values_list('kind').annotate(last=Max('created_at')).values_list('kind', 'last'))


def ready_to_delete(now=None):
    """The kinds whose local path may be deleted: no fallback in the last ``SOAK_HOURS`` hours and a live built-in scanner that declares the kind
    (sorted). Empty when there is no live built-in scanner."""
    from agentapi import sentinel_broker
    from agentapi.models import ScannerFallback, SentinelTask
    now = now or timezone.now()
    offered = set()
    for eff in sentinel_broker._live_scanners(now):
        if eff.builtin:
            offered |= eff.caps
    candidates = [k for k in SentinelTask.KINDS if k in offered and k not in NO_STAGE]
    if not candidates:
        return []
    recent = set(ScannerFallback.objects.filter(kind__in=candidates, created_at__gte=now - timedelta(hours=SOAK_HOURS)).values_list('kind', flat=True).distinct())
    return [k for k in candidates if k not in recent]


def _iso(value):
    return value.isoformat() if value else None


def status(admin=True, now=None):
    """The ``fallbacks`` block of the system status's ``scanning.scanner``: ``{'days': 7, 'by_kind': {kind: {'count': n, 'last_at': iso}}}``. An App Admin
    also gets ``ready_to_delete`` (the gate, ``SOAK_HOURS``) and ``soak_hours``; anyone else sees the counts only (no time, no gate)."""
    now = now or timezone.now()
    found = counts(STATUS_DAYS, now=now)
    if not admin:
        return {'days': STATUS_DAYS, 'by_kind': {k: {'count': v['count']} for k, v in found.items()}}
    return {'days': STATUS_DAYS,
            'by_kind': {k: {'count': v['count'], 'last_at': _iso(v['last_at'])} for k, v in found.items()},
            'soak_hours': SOAK_HOURS, 'ready_to_delete': ready_to_delete(now)}


def prune(now=None, days=RETENTION_DAYS):
    """Delete rows older than ``days`` days; returns how many. Called from the weekly maintenance."""
    from agentapi.models import ScannerFallback
    now = now or timezone.now()
    return ScannerFallback.objects.filter(created_at__lt=now - timedelta(days=days)).delete()[0]
