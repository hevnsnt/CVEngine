"""Scans stuck "running" with nobody working on them, closed by an update instead of waited for.

The update script (scripts/apply-update.sh) waits up to five minutes for running scans to finish. A scan whose worker is gone (a restart, a kill, a
cleared queue) never finishes, so that wait was always spent in full. A running scan is a GHOST only when all of these hold:

* its Celery task exists nowhere (``broker_recovery.live_task_ids``: not queued, not unacknowledged, not reserved, active or scheduled on any worker);
* it has no open stage run waiting on Sentinels (those have no Celery task on purpose);
* it has shown no sign of life for ``idle_minutes``: it started, and logged its last activity (``ScanActivity``), longer ago than that.

A scan that shows progress, or whose task a worker holds, keeps the update waiting as before. When the broker or the workers cannot be asked, nothing is
closed. A ghost is marked failed with the reason ``interrupted by an update`` and logged.
"""
import logging
from datetime import timedelta

from django.db.models import Max
from django.utils import timezone

logger = logging.getLogger(__name__)

IDLE_MINUTES = 5
MESSAGE = 'interrupted by an update'


def find(now=None, live=None, idle_minutes=IDLE_MINUTES):
    """The running scans that are ghosts, as ``[(ScanHistory, last_sign_of_life)]``. ``live`` (the set of existing task ids, or None when that
    cannot be told) is injectable for tests."""
    from agentapi import stage_runs
    from cveFeed import broker_recovery
    from startScan.models import ScanHistory
    now = now or timezone.now()
    if live is None:
        live = broker_recovery.live_task_ids()
    if live is None:
        return []
    cutoff = now - timedelta(minutes=idle_minutes)
    waiting = stage_runs.open_scan_ids()
    found = []
    rows = (ScanHistory.objects.filter(scan_status=1, start_scan_date__lt=cutoff)
            .annotate(last_activity=Max('scanactivity__time')).only('pk', 'celery_ids', 'start_scan_date'))
    for scan in rows:
        if set(scan.celery_ids or []) & live or scan.pk in waiting:
            continue
        last = max([t for t in (scan.last_activity, scan.start_scan_date) if t])
        if last >= cutoff:
            continue
        found.append((scan, last))
    return found


def close(now=None, live=None, idle_minutes=IDLE_MINUTES, message=MESSAGE):
    """Mark the ghosts failed, with ``message`` as the reason. Returns the ids closed."""
    from startScan.models import ScanHistory
    now = now or timezone.now()
    closed = []
    for scan, last in find(now, live, idle_minutes):
        n = ScanHistory.objects.filter(pk=scan.pk, scan_status=1).update(scan_status=0, stop_scan_date=now, error_message=message)
        if n:
            closed.append(scan.pk)
            logger.warning('scan %s closed for the update: no worker holds it and it has shown nothing since %s (%s)', scan.pk, last.isoformat(), message)
    return closed
