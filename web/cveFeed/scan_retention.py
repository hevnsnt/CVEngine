"""Scan history retention: delete the old scans a domain no longer needs.

Every scan stores its own copy of each host it found (Subdomain rows with their findings, matches and endpoints), and nothing removed them, so
the inventory tables only grew. A scan older than ``CVENGINE_SCAN_HISTORY_RETENTION_DAYS`` (180 by default, ``0`` keeps everything, at least
30 otherwise) is deleted, with the rows that hang off it, unless any of this is true:

* it is not finished (queued or running);
* some of its hosts are in the domain's current inventory (``correlation.latest_scan_q``): the latest successful full scan and the host
  scans after it are what every listing, count and match reads;
* it is one of the newest ``KEEP_LATEST`` scans of its domain, whatever their age (a domain scanned rarely keeps its last few);
* a person worked on something in it: a finding with a remediation status other than open, a note, an assignee, a comment or an
  audit event (including a change later reverted to open).

The work is done in small steps (one scan per transaction) inside a time budget, so a large backlog is cleared over several runs and no run
holds a long lock. IP addresses, ports and technologies that only the deleted scans used are left in place."""
import logging
import os
import time
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

logger = logging.getLogger(__name__)

DEFAULT_DAYS = 180
MIN_DAYS = 30
KEEP_LATEST = 3
TERMINAL = (0, 2, 3)  # failed, success, aborted: queued (-1) and running (1) scans are never touched
DEFAULT_BUDGET_SECONDS = 15 * 60


def retention_days(environ=None):
    """The age in days after which a scan may be deleted, or None when retention is off."""
    environ = os.environ if environ is None else environ
    raw = str(environ.get('CVENGINE_SCAN_HISTORY_RETENTION_DAYS', '') or '').strip().lower()
    if raw in ('0', 'off', 'never', 'false'):
        return None
    try:
        days = int(raw) if raw else DEFAULT_DAYS
    except ValueError:
        return DEFAULT_DAYS
    return max(MIN_DAYS, days)


def _worked(model, kind, scan_field):
    """Lazy scan-id subquery for findings with any human work, including audit history later reverted to open."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import FindingAuditEvent, FindingComment
    comments = FindingComment.objects.filter(finding_kind=kind, finding_id=OuterRef('pk'))
    audit = FindingAuditEvent.objects.filter(finding_kind=kind, finding_id=OuterRef('pk'))
    return (model.objects.filter(**{f'{scan_field}__isnull': False})
            .filter(~Q(remediation_status='open') | ~Q(remediation_note='') | Q(assignee__isnull=False)
                    | Q(Exists(comments)) | Q(Exists(audit)))
            .values(scan_field))


def worked_scans():
    """Two database subqueries, so retention never loads every worked scan id into worker memory."""
    from cveFeed.models import CVEMatch
    from startScan.models import Vulnerability
    return (_worked(Vulnerability, 'vulnerability', 'scan_history_id'),
            _worked(CVEMatch, 'match', 'scan_history_id'))


def candidates(now=None, days=None, kept=None):
    """``ScanHistory`` queryset of the finished scans past the retention that no rule above protects (before the newest-scans rule)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import ScanHistory, Subdomain
    now = now or timezone.now()
    days = retention_days() if days is None else days
    if days is None:
        return ScanHistory.objects.none()
    current = Subdomain.objects.filter(latest_scan_q(), scan_history__isnull=False).values('scan_history_id')
    kept = worked_scans() if kept is None else kept
    return (ScanHistory.objects.filter(start_scan_date__lt=now - timedelta(days=days), scan_status__in=TERMINAL)
            .exclude(pk__in=current).exclude(pk__in=kept[0]).exclude(pk__in=kept[1]))


def _newest(domain_ids):
    from startScan.models import ScanHistory
    keep = set()
    for domain_id in domain_ids:
        keep.update(ScanHistory.objects.filter(domain_id=domain_id).order_by('-id').values_list('id', flat=True)[:KEEP_LATEST])
    return keep


def run(now=None, days=None, dry_run=False, budget_seconds=DEFAULT_BUDGET_SECONDS, clock=time.monotonic):
    """Delete (or, with ``dry_run``, count) the expired scans. Returns ``{'days', 'scans', 'complete'}``: how many were deleted and whether
    nothing eligible is left (False when the time budget ran out first)."""
    from startScan.models import ScanHistory
    days = retention_days() if days is None else days
    if days is None:
        return {'days': None, 'scans': 0, 'complete': True}
    now = now or timezone.now()
    started, deleted, skipped, kept = clock(), 0, set(), worked_scans()
    while True:
        batch = list(candidates(now, days, kept).exclude(pk__in=skipped).order_by('id').values_list('id', 'domain_id')[:200])
        if not batch:
            return {'days': days, 'scans': deleted, 'complete': True}
        newest = _newest({domain_id for _, domain_id in batch})
        eligible = [pk for pk, _ in batch if pk not in newest]
        skipped.update(pk for pk, _ in batch if pk in newest)
        if dry_run:
            deleted += len(eligible)
            skipped.update(eligible)  # counted once
            if len(batch) < 200:
                return {'days': days, 'scans': deleted, 'complete': True}
            continue
        for pk in eligible:
            if clock() - started > budget_seconds:
                return {'days': days, 'scans': deleted, 'complete': False}
            with transaction.atomic():
                ScanHistory.objects.filter(pk=pk).delete()
            deleted += 1
