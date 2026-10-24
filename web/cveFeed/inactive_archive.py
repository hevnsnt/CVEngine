"""Conservative, checkpointed daily review of retired assets for reversible archival."""
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from cveFeed.models import HostState, InactiveArchiveReview

logger = logging.getLogger(__name__)
PAGE = 25
MIN_ABSENCE = timedelta(days=30)
LEASE = timedelta(minutes=10)


def candidates(now=None):
    now = now or timezone.now()
    return HostState.objects.filter(archived_at__isnull=True, pinned=False,
                                    retired_at__lte=now - MIN_ABSENCE,
                                    last_seen__lte=now - MIN_ABSENCE)


def check_one(row, *, resolver=None, tcp_probe=None, now=None):
    from cveFeed import activity
    from cveFeed.archive_rediscovery import observe, resolve_one
    from cveFeed.exclusions import is_excluded
    from cveFeed.host_assessment import enqueue
    from cveFeed.models import HostAssessment
    from cveFeed.scan_control import pause_requested
    from startScan.models import ScanHistory, Subdomain

    now = now or timezone.now()
    if pause_requested():
        return 'paused'
    if row.archived_at or row.pinned or not row.retired_at or row.retired_at > now - MIN_ABSENCE or \
            row.last_seen > now - MIN_ABSENCE:
        return 'deferred'
    domain, host = row.domain, row.host.lower().rstrip('.')
    if domain.project_id != row.project_id or is_excluded(row.project_id, host) or not (
            host == domain.name.lower() or (not domain.is_host_scoped() and host.endswith('.' + domain.name.lower()))):
        return 'deferred'
    if HostAssessment.objects.filter(project_id=row.project_id, host=host, status__in=('queued', 'running')).exists() or \
            ScanHistory.objects.filter(domain=domain, scan_status__in=(-1, 1)).exists():
        return 'deferred'
    observed = observe(row, resolver=resolver or resolve_one, tcp_probe=tcp_probe)
    status = observed['status']
    selector = HostState.objects.filter(pk=row.pk, retired_at=row.retired_at,
                                        archived_at__isnull=True, pinned=False)
    if status in ('rediscovered_dns', 'rediscovered_ip'):
        selector.update(inactive_first_absent_at=None, inactive_last_absent_at=None,
                        inactive_absent_checks=0, archive_checked_at=now, archive_check_status=status)
        sub = Subdomain.objects.filter(target_domain=domain, name=host).order_by('-id').first()
        if sub is None:
            sub = Subdomain.objects.create(target_domain=domain, name=host)
        try:
            job, _ = enqueue(row.project, sub, source='inactive_recheck')
        except (RuntimeError, ValueError):
            selector.update(archive_check_status='enqueue_deferred')
            return 'deferred'
        if job.status == 'failed':
            selector.update(archive_check_status='enqueue_deferred')
            return 'deferred'
        changed = selector.update(retired_at=None, archive_assessment=job, archive_check_status=status)
        if changed:
            activity.log('inventory', f'{host} reappeared; host assessment #{job.pk} queued',
                         project=row.project_id, job_id=job.pk)
        return 'reactivated' if changed else 'deferred'
    # A previously open TCP port going quiet cannot establish that an IP asset
    # has disappeared; the service may have moved or be filtered. Keep it for
    # review and never advance the absence clock from that probe alone.
    if status != 'absent':
        values = {'archive_checked_at': now, 'archive_check_status': status,
                  'archive_check_error': 'temporary lookup error' if status == 'error' else ''}
        if status == 'blocked':
            # A real DNS answer may be outside scan scope; it is still enough
            # to invalidate a previous NXDOMAIN-based absence sequence.
            values.update(inactive_first_absent_at=None, inactive_last_absent_at=None,
                          inactive_absent_checks=0)
        selector.update(**values)
        return 'error' if status == 'error' else 'deferred'

    prior_still_valid = bool(row.inactive_first_absent_at and row.last_seen <= row.inactive_first_absent_at)
    first = row.inactive_first_absent_at if prior_still_valid else now
    count = min((row.inactive_absent_checks or 0) + 1, 65535) if prior_still_valid else 1
    values = {'inactive_first_absent_at': first, 'inactive_last_absent_at': now,
              'inactive_absent_checks': count, 'archive_checked_at': now,
              'archive_check_status': status, 'archive_check_error': ''}
    if count >= 2 and first <= now - MIN_ABSENCE and row.last_seen <= first:
        values.update(archived_at=now, archive_reason='Automatically archived after two negative observations '
                      'at least 30 days apart; history is preserved')
        if selector.update(**values):
            activity.log('inventory', f'{host} archived after repeated absence over 30 days',
                         project=row.project_id, status='done', host=host)
            return 'archived'
        return 'deferred'
    return 'observed' if selector.update(**values) else 'deferred'


def _claim(run_id=None):
    now = timezone.now()
    with transaction.atomic():
        if run_id:
            run = InactiveArchiveReview.objects.select_for_update().filter(pk=run_id, finished_at__isnull=True).first()
        else:
            run = InactiveArchiveReview.objects.select_for_update().filter(finished_at__isnull=True).order_by('id').first()
            if run is None:
                run, _ = InactiveArchiveReview.objects.select_for_update().get_or_create(day=now.date(),
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


def run_page(run_id=None, *, resolver=None, tcp_probe=None):
    from cveFeed import activity
    from cveFeed.scan_control import pause_requested
    from cveFeed.tasks import review_inactive_hosts

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
            outcome = check_one(row, resolver=resolver, tcp_probe=tcp_probe)
        except Exception:
            logger.exception('inactive host review failed for state %s', row.pk)
            outcome = 'error'
            HostState.objects.filter(pk=row.pk).update(archive_checked_at=timezone.now(),
                archive_check_status='error', archive_check_error='unexpected checker error')
        run.checked += 1
        run.archived += outcome == 'archived'
        run.reactivated += outcome == 'reactivated'
        run.deferred += outcome == 'deferred'
        run.errors += outcome == 'error'
        run.cursor_hoststate_id = row.pk
        run.save(update_fields=['checked', 'archived', 'reactivated', 'deferred', 'errors', 'cursor_hoststate_id'])
    more = candidates().filter(pk__gt=run.cursor_hoststate_id).exists()
    run.lease_until = None
    if more:
        run.status = 'queued'
        run.save(update_fields=['status', 'lease_until'])
        try:
            review_inactive_hosts.apply_async(args=[run.pk], queue='cve_feed_queue', countdown=1)
        except Exception:
            run.status = 'partial'
            run.save(update_fields=['status'])
        return {'run_id': run.pk, 'status': run.status, 'checked': run.checked, 'more': True}
    run.status = 'partial' if run.errors or run.deferred else 'completed'
    run.finished_at = timezone.now()
    run.save(update_fields=['status', 'lease_until', 'finished_at'])
    activity.log('inventory', f'Inactive host review #{run.pk}: {run.checked} checked, '
                 f'{run.archived} archived, {run.reactivated} reactivated, {run.deferred} deferred, {run.errors} errors',
                 status='failed' if run.errors else 'done', run_id=run.pk)
    return {'run_id': run.pk, 'status': run.status, 'checked': run.checked,
            'archived': run.archived, 'reactivated': run.reactivated,
            'deferred': run.deferred, 'errors': run.errors}
