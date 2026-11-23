"""Scan history retention: delete the old scans a domain no longer needs.

Every scan stores its own copy of each host it found (Subdomain rows with their findings, matches and endpoints), and nothing removed them, so
the inventory tables only grew. A scan older than ``CVENGINE_SCAN_HISTORY_RETENTION_DAYS`` (180 by default, ``0`` keeps everything, at least
30 otherwise) is deleted, with the rows that hang off it, unless any of this is true:

* it is not finished (queued or running);
* some of its hosts are in the domain's current inventory (``correlation.latest_scan_q``): the latest successful full scan and the host
  scans after it are what every listing, count and match reads;
* it is one of the newest ``KEEP_LATEST`` scans of its domain, whatever their age (a domain scanned rarely keeps its last few);
* a person worked on something in it: a finding with a remediation status other than open, a note, an assignee, a comment or an
  audit event (including a change later reverted to open). The engine's own closures and reopenings are not a person's work
  (``_engine_q``): a status set with nobody in ``remediation_by`` and a note that is only the engine's lines (``closure.ENGINE_LINES``: an
  archive or gone closure, a duplicate or alias fold, a fixed version read, an automatic reopening), and an audit event the engine wrote
  (no actor, an ``after.by`` marker). They used to count, so one archive or gone closure of a host kept every old scan that held it for good.

The work is done in small steps (one scan at a time, the rows under it in bounded batches of their own transactions, see
``cveFeed.bounded_delete``) inside a time budget, so a large backlog is cleared over several runs and no run holds a long lock. IP
addresses, ports and technologies that only the deleted scans used are left in place."""
import logging
import os
import time
from datetime import timedelta
from functools import reduce
from operator import or_

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


def _engine_q():
    """The rows whose note is only the engine's: it starts with one of its lines (``closure.ENGINE_LINES``) and no later line is a person's.
    A person's text below an engine line (a note kept under an archive closure) still counts as work."""
    from cveFeed.closure import ENGINE_LINES
    starts = reduce(or_, (Q(remediation_note__startswith=line) for line in ENGINE_LINES))
    other_line = r'\n(?!(' + '|'.join(ENGINE_LINES) + r'))'  # the lines hold letters, spaces and colons only: nothing to escape
    return starts & ~Q(remediation_note__regex=other_line)


def _worked(model, kind, scan_field):
    """Lazy scan-id subquery for findings with any human work, including audit history later reverted to open. The engine's own closures
    are not work (see the module text)."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import FindingAuditEvent, FindingComment
    comments = FindingComment.objects.filter(finding_kind=kind, finding_id=OuterRef('pk'))
    audit = (FindingAuditEvent.objects.filter(finding_kind=kind, finding_id=OuterRef('pk'))
             .exclude(actor__isnull=True, after__has_key='by'))  # the engine's own events: no actor, and its ``by`` marker
    engine = _engine_q()
    by_person = Q(remediation_by__isnull=False) | ~engine
    return (model.objects.filter(**{f'{scan_field}__isnull': False})
            .filter(~Q(remediation_status='open') & by_person | ~Q(remediation_note='') & ~engine | Q(assignee__isnull=False)
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
    from django.db.models import F, Window
    from django.db.models.functions import RowNumber
    from startScan.models import ScanHistory
    # One ranked query for the batch instead of a query for every domain.
    return set(ScanHistory.objects.filter(domain_id__in=domain_ids)
               .annotate(position=Window(expression=RowNumber(), partition_by=[F('domain_id')], order_by=F('id').desc()))
               .filter(position__lte=KEEP_LATEST).values_list('id', flat=True))


def run(now=None, days=None, dry_run=False, budget_seconds=DEFAULT_BUDGET_SECONDS, clock=time.monotonic):
    """Delete (or, with ``dry_run``, count) the expired scans. Returns ``{'days', 'scans', 'complete'}``: how many were deleted and whether
    nothing eligible is left (False when the time budget ran out first)."""
    from startScan.models import ScanHistory
    days = retention_days() if days is None else days
    if days is None:
        return {'days': None, 'scans': 0, 'complete': True}
    now = now or timezone.now()
    from cveFeed import bounded_delete
    started, deleted, last, kept = clock(), 0, 0, worked_scans()
    while True:
        # keyset on id: every candidate up to ``last`` was deleted, kept as one of its domain's newest or (dry run) counted
        batch = list(candidates(now, days, kept).filter(pk__gt=last).order_by('id').values_list('id', 'domain_id')[:200])
        if not batch:
            return {'days': days, 'scans': deleted, 'complete': True}
        last = batch[-1][0]
        newest = _newest({domain_id for _, domain_id in batch})
        eligible = [pk for pk, _ in batch if pk not in newest]
        if dry_run:
            deleted += len(eligible)
            if len(batch) < 200:
                return {'days': days, 'scans': deleted, 'complete': True}
            continue
        for pk in eligible:
            if clock() - started > budget_seconds:
                return {'days': days, 'scans': deleted, 'complete': False}
            bounded_delete.drain_below(ScanHistory, [pk])  # its hosts, findings, matches and activity, a bounded batch per transaction
            with transaction.atomic():
                ScanHistory.objects.filter(pk=pk).delete()
            deleted += 1
