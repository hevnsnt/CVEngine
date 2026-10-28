"""Short-timeline archival for hosts that keep failing to resolve to a scannable IP.

cveFeed.inactive_archive handles a different case: a host that vanished from enumeration (HostState.retired_at,
set in cveFeed.changes only when a host that previously appeared in discovery results stops appearing) is
archived after MIN_ABSENCE (30 days) of confirmed absence. This module handles a host that is still enumerated
every run (it never vanished; retired_at stays unset) but has never once resolved to a scannable IP, so
cveFeed.host_assessment.execute() keeps ending its assessment inconclusive for lack of resolution (see
cveFeed.discovery.run_host_pipeline's "No scannable IP address resolved" branch). A host that resolves fine and
is merely waiting its turn for an assessment (see cveFeed.coverage_topup) is never touched by this path: a
single successful resolution clears the streak below.

record_attempt() is called from cveFeed.host_assessment.execute() after every finished assessment and keeps a
cheap, per-host streak on HostState (unresolved_first_at/unresolved_last_at/unresolved_checks), distinct from
and never written by the inactive_first_absent_at/retired_at fields the 30-day path owns. This module's own
daily, checkpointed sweep (same shape as cveFeed.inactive_archive's) archives a host once that streak has lasted
``ttl()`` (CVENGINE_TTL_UNRESOLVED_HOST hours, default 5 days) without a single success, with the same guards as
every other automatic archive path: scanning paused, the host excluded, pinned, already archived, or an
assessment for it currently queued or running.

Once archived this way (HostState.archived_at set, archived_by_user left False), the host lands on the same
daily rediscovery sweep cveFeed.archive_rediscovery already drives for every other archived host, because that
sweep's candidates() keys off archived_at and archived_by_user alone, regardless of why a host was archived.
"""
import logging
import os
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)
PAGE = 25
LEASE = timedelta(minutes=10)
DEFAULT_TTL_HOURS = 5 * 24  # 5 days; a short, separate timeline from inactive_archive.MIN_ABSENCE (30 days)
TTL_ENV = 'CVENGINE_TTL_UNRESOLVED_HOST'
# A queued or running scan of the domain defers the review for the same reason inactive_archive defers: it may be
# about to resolve the host. A scan stuck longer than this must not keep every host of its domain from review.
STUCK_SCAN_AGE = timedelta(days=3)


def ttl():
    """Span of consecutive no-scannable-IP attempts before a host is archived. Override with CVENGINE_TTL_UNRESOLVED_HOST
    (hours), the same CVENGINE_TTL_<NAME> convention cveFeed.ledger uses; defaults to 5 days."""
    try:
        hours = float(os.environ.get(TTL_ENV, ''))
    except ValueError:
        hours = DEFAULT_TTL_HOURS
    return timedelta(hours=hours)


def record_attempt(project, domain, host, result, now=None):
    """Update one host's no-scannable-IP streak from a finished host assessment's result.

    Only a result that actually attempted resolution updates anything: cveFeed.discovery.run_host_pipeline sets a
    ``resolved`` count on every outcome that reached resolution, success or not. A guard-clause skip (the host is
    absent, excluded, outside scope, or scanning is paused) or an unexpected exception carries no such key and is
    left alone, so neither can masquerade as a success or a failure.
    """
    from cveFeed.models import HostState
    if not isinstance(result, dict) or 'resolved' not in result:
        return 'skipped'
    now = now or timezone.now()
    host = host.lower().rstrip('.')
    if result.get('resolved'):
        HostState.objects.filter(project=project, host=host).update(
            unresolved_first_at=None, unresolved_last_at=None, unresolved_checks=0)
        return 'reset'
    row, created = HostState.objects.get_or_create(project=project, host=host, defaults={'domain': domain})
    first = now if created or not row.unresolved_first_at else row.unresolved_first_at
    checks = 1 if created else min((row.unresolved_checks or 0) + 1, 65535)
    HostState.objects.filter(pk=row.pk).update(unresolved_first_at=first, unresolved_last_at=now, unresolved_checks=checks)
    return 'bumped'


RECHECK_EVERY = timedelta(hours=6)  # a host with a no-address streak is resolved again this often (DNS only, no scan)
RECHECK_BATCH = 40  # hosts re-resolved per sweep
COUNTS_FOR = timedelta(days=7)  # a streak whose last check is newer than this keeps the host out of the first-pass backlog (see coverage_topup)


def recheck(now=None, batch=RECHECK_BATCH, resolver=None):
    """Resolve again the hosts that were found to have no scannable address, a few at a time, and say why they have none.

    A host whose name now resolves to a scannable address leaves the streak (it is due for a first pass again at once). One that still does
    not keeps its streak and gets a note: ``private address`` (the name points inside a private network, which only a Sentinel inside that
    network can scan, once the project declares the range) or ``no DNS answer`` (dangling). Only DNS is asked, so this costs seconds, not a
    scan. Returns ``{'checked', 'resolved', 'private', 'no_dns'}``."""
    import ipaddress
    from cveFeed.discovery import resolve_names
    from cveFeed.models import HostState
    from targetApp.target_types import is_scannable_ip
    now = now or timezone.now()
    rows = list(HostState.objects.filter(archived_at__isnull=True, unresolved_checks__gte=1, unresolved_last_at__lte=now - RECHECK_EVERY)
                .order_by('unresolved_last_at')[:batch])
    out = {'checked': len(rows), 'resolved': 0, 'private': 0, 'no_dns': 0}
    if not rows:
        return out
    found = {}
    for name, address in (resolver or resolve_names)({r.host for r in rows}):
        found.setdefault(name, set()).add(address)
    for row in rows:
        addresses = sorted(found.get(row.host, ()))
        if any(is_scannable_ip(a, project=row.project_id if a == row.host else None) for a in addresses):
            HostState.objects.filter(pk=row.pk).update(unresolved_first_at=None, unresolved_last_at=None, unresolved_checks=0, resolution_note='')
            out['resolved'] += 1
            continue
        private = [a for a in addresses if not _is_global(a, ipaddress)]
        if private:
            note, key = f'private address ({private[0]}): scannable only by a Sentinel inside that network, once the project declares the range', 'private'
        else:
            note, key = 'no DNS answer', 'no_dns'
        out[key] += 1
        HostState.objects.filter(pk=row.pk).update(unresolved_last_at=now, resolution_note=note[:160])
    return out


def _is_global(address, ipaddress):
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def candidates(now=None):
    from cveFeed.models import HostState
    now = now or timezone.now()
    return HostState.objects.filter(archived_at__isnull=True, pinned=False,
                                    unresolved_first_at__isnull=False, unresolved_first_at__lte=now - ttl())


def check_one(row, *, now=None):
    from cveFeed import activity
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostAssessment, HostState
    from cveFeed.scan_control import pause_requested
    from startScan.models import ScanHistory

    now = now or timezone.now()
    if pause_requested():
        return 'paused'
    if row.archived_at or row.pinned or not row.unresolved_first_at or row.unresolved_first_at > now - ttl():
        return 'deferred'
    domain, host = row.domain, row.host.lower().rstrip('.')
    if domain.project_id != row.project_id or is_excluded(row.project_id, host) or not (
            host == domain.name.lower() or (not domain.is_host_scoped() and host.endswith('.' + domain.name.lower()))):
        return 'deferred'
    if HostAssessment.objects.filter(project_id=row.project_id, host=host, status__in=('queued', 'running')).exists() or \
            ScanHistory.objects.filter(domain=domain, scan_status__in=(-1, 1), start_scan_date__gte=now - STUCK_SCAN_AGE).exists():
        return 'deferred'
    days = max(1, round(ttl().total_seconds() / 86400))
    changed = HostState.objects.filter(pk=row.pk, unresolved_first_at=row.unresolved_first_at,
                                       archived_at__isnull=True, pinned=False).update(
        archived_at=now, archived_by_user=False,
        archive_reason=f'Automatically archived after {days} day{"s" if days != 1 else ""} without once resolving to a scannable IP')
    if changed:
        activity.log('inventory', f'{host} archived after {days} days without a scannable IP',
                     project=row.project_id, status='done', host=host)
        return 'archived'
    return 'deferred'


def _claim(run_id=None):
    from cveFeed.models import UnresolvedArchiveReview
    now = timezone.now()
    with transaction.atomic():
        if run_id:
            run = UnresolvedArchiveReview.objects.select_for_update().filter(pk=run_id, finished_at__isnull=True).first()
        else:
            run = UnresolvedArchiveReview.objects.select_for_update().filter(finished_at__isnull=True).order_by('id').first()
            if run is None:
                run, _ = UnresolvedArchiveReview.objects.select_for_update().get_or_create(day=now.date(),
                    defaults={'total': candidates(now).count()})
                if run.finished_at:
                    return None, 'already completed today'
        if not run:
            return None, 'run not found'
        if run.lease_until and run.lease_until > now:
            return None, 'running elsewhere'
        run.status, run.lease_until = 'running', now + LEASE
        run.save(update_fields=['status', 'lease_until'])
        return run, ''


def run_page(run_id=None):
    """Visit a bounded page, checkpoint its last id, and enqueue continuation until every due host was visited."""
    from cveFeed import activity
    from cveFeed.models import UnresolvedArchiveReview
    from cveFeed.scan_control import pause_requested
    from cveFeed.tasks import review_unresolved_hosts

    run, reason = _claim(run_id)
    if not run:
        return {'skipped': reason}
    rows = list(candidates().filter(pk__gt=run.cursor_hoststate_id)
                .select_related('domain', 'project').order_by('pk')[:PAGE])
    for row in rows:
        if pause_requested():
            run.status, run.lease_until = 'partial', None
            run.save(update_fields=['status', 'lease_until'])
            return {'run_id': run.pk, 'status': 'paused', 'checked': run.checked}
        try:
            outcome = check_one(row)
        except Exception:
            logger.exception('unresolved host review failed for state %s', row.pk)
            outcome = 'error'
        run.checked += 1
        run.archived += outcome == 'archived'
        run.deferred += outcome == 'deferred'
        run.errors += outcome == 'error'
        run.cursor_hoststate_id = row.pk
        run.save(update_fields=['checked', 'archived', 'deferred', 'errors', 'cursor_hoststate_id'])
    more = candidates().filter(pk__gt=run.cursor_hoststate_id).exists()
    run.lease_until = None
    if more:
        run.status = 'queued'
        run.save(update_fields=['status', 'lease_until'])
        try:
            review_unresolved_hosts.apply_async(args=[run.pk], queue='cve_feed_queue', countdown=1)
        except Exception:
            run.status = 'partial'
            run.save(update_fields=['status'])
        return {'run_id': run.pk, 'status': run.status, 'checked': run.checked, 'more': True}
    run.status = 'partial' if run.errors else 'completed'
    run.finished_at = timezone.now()
    run.save(update_fields=['status', 'lease_until', 'finished_at'])
    activity.log('inventory', f'Unresolved host review #{run.pk}: {run.checked} checked, {run.archived} archived, '
                 f'{run.deferred} deferred, {run.errors} errors', status='failed' if run.errors else 'done', run_id=run.pk)
    return {'run_id': run.pk, 'status': run.status, 'checked': run.checked,
            'archived': run.archived, 'deferred': run.deferred, 'errors': run.errors}
