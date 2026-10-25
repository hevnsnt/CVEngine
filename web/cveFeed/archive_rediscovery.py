"""Daily, checkpointed rediscovery of archived assets without deleting their history."""
import concurrent.futures
import ipaddress
import logging
import socket
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from cveFeed.models import ArchiveRediscovery, HostState

logger = logging.getLogger(__name__)
PAGE = 25
DNS_TIMEOUT = 5
LEASE = timedelta(minutes=10)


def archived_names(project_id):
    return frozenset(HostState.objects.filter(project_id=project_id, archived_at__isnull=False)
                     .values_list('host', flat=True))


def resolve_one(host):
    """Return (resolved|absent|error, addresses). A temporary DNS failure is never absence."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    try:
        addresses = {item[4][0] for item in future.result(timeout=DNS_TIMEOUT)}
        return ('resolved', addresses) if addresses else ('absent', set())
    except socket.gaierror as exc:
        absent = {socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', socket.EAI_NONAME)}
        return ('absent', set()) if exc.errno in absent else ('error', set())
    except Exception:
        return 'error', set()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def observe(row, resolver=resolve_one, tcp_probe=None):
    """Positive DNS is rediscovery, not a claim that a service is alive.

    Wildcard DNS and addresses prohibited by scan policy are held for review.
    An IP asset requires an answering previously observed port instead of DNS.
    """
    from targetApp.target_types import is_scannable_ip
    host = row.host.lower().rstrip('.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        status, addresses = resolver(host)
        if status != 'resolved':
            return {'status': status, 'addresses': []}
        if not addresses or any(not is_scannable_ip(ip) for ip in addresses):
            return {'status': 'blocked', 'addresses': []}
        parent = host.partition('.')[2]
        if parent:
            marker = f'cvengine-nonexistent-{row.pk:x}.{parent}'
            wildcard_status, wildcard_ips = resolver(marker)
            if wildcard_status == 'error':
                return {'status': 'error', 'addresses': []}
            if wildcard_status == 'resolved' and addresses == wildcard_ips:
                return {'status': 'ambiguous_wildcard', 'addresses': sorted(addresses)}
        return {'status': 'rediscovered_dns', 'addresses': sorted(addresses)}
    if not is_scannable_ip(host):
        return {'status': 'blocked', 'addresses': []}
    from cveFeed.zombie import tcp_alive
    probe = tcp_probe or tcp_alive
    ports = []
    for key in ((row.state or {}).get('ips') or {}).get(host, {}).get('ports', {}):
        number, _, proto = str(key).partition('/')
        if number.isdigit() and proto in ('', 'tcp') and 0 < int(number) < 65536:
            ports.append(int(number))
    if not ports:
        return {'status': 'no_safe_liveness_probe', 'addresses': []}
    try:
        answering = [port for port in sorted(set(ports))[:3] if probe(host, port)]
    except Exception:
        return {'status': 'error', 'addresses': []}
    return {'status': 'rediscovered_ip', 'addresses': [host]} if answering else {'status': 'unobserved', 'addresses': []}


def check_one(row, *, resolver=resolve_one, tcp_probe=None):
    from cveFeed.exclusions import is_excluded
    from cveFeed.host_assessment import enqueue
    from cveFeed.scan_control import pause_requested
    from startScan.models import Subdomain

    if pause_requested():
        return 'paused'
    if row.archived_by_user:
        return 'checked'  # a person archived it; only Restore brings it back
    host, domain = row.host.lower().rstrip('.'), row.domain
    if domain.project_id != row.project_id or is_excluded(row.project_id, host) or not (
            host == domain.name.lower() or (not domain.is_host_scoped() and host.endswith('.' + domain.name.lower()))):
        HostState.objects.filter(pk=row.pk, archived_at__isnull=False).update(
            archive_checked_at=timezone.now(), archive_check_status='out_of_scope', archive_check_error='')
        return 'deferred'
    result = observe(row, resolver=resolver, tcp_probe=tcp_probe)
    status = result['status']
    now = timezone.now()
    if status not in ('rediscovered_dns', 'rediscovered_ip'):
        HostState.objects.filter(pk=row.pk, archived_at__isnull=False).update(
            archive_checked_at=now, archive_check_status=status, archive_check_error='temporary lookup error' if status == 'error' else '')
        return 'error' if status == 'error' else 'deferred' if status.startswith(('blocked', 'ambiguous', 'no_safe')) else 'checked'
    sub = Subdomain.objects.filter(target_domain=domain, name=host).order_by('-id').first()
    if sub is None:
        sub = Subdomain.objects.create(target_domain=domain, name=host)
    # Clear the archive gate before publishing; restore it on a rejected enqueue.
    # This makes every scanner see one consistent active state when the worker starts.
    HostState.objects.filter(pk=row.pk, archived_at__isnull=False).update(archived_at=None)
    try:
        job, _ = enqueue(row.project, sub, source='archive')
    except Exception as exc:  # whatever stopped the enqueue, the host goes back to archived: nothing will assess it
        expected = isinstance(exc, (RuntimeError, ValueError))  # at capacity, or no longer in scope
        if not expected:
            logger.exception('archived host rediscovery could not queue an assessment for state %s', row.pk)
        HostState.objects.filter(pk=row.pk, archived_at__isnull=True).update(
            archived_at=row.archived_at,
            archive_checked_at=now, archive_check_status='enqueue_deferred' if expected else 'error',
            archive_check_error=type(exc).__name__)
        return 'deferred' if expected else 'error'
    if job.status == 'failed':
        HostState.objects.filter(pk=row.pk, archived_at__isnull=True).update(
            archived_at=row.archived_at,
            archive_checked_at=now, archive_check_status='enqueue_deferred', archive_check_error='broker unavailable')
        return 'deferred'
    # A queued assessment is still pending. The archive is lifted because the asset was rediscovered,
    # and the job will determine actual service coverage separately.
    changed = HostState.objects.filter(pk=row.pk, archived_at__isnull=True).update(
        archive_reason='', archive_checked_at=now, archive_check_status=status,
        archive_check_error='', archive_assessment=job, retired_at=None,
        inactive_first_absent_at=None, inactive_last_absent_at=None, inactive_absent_checks=0)
    if changed:
        from cveFeed import activity
        activity.log('inventory', f'{host} rediscovered; host assessment #{job.pk} queued', project=row.project_id,
                     job_id=job.pk, evidence='DNS resolution' if status == 'rediscovered_dns' else 'known TCP port answered')
    return 'reactivated' if changed else 'checked'


def _claim(run_id=None):
    now = timezone.now()
    with transaction.atomic():
        if run_id:
            run = ArchiveRediscovery.objects.select_for_update().filter(pk=run_id, finished_at__isnull=True).first()
        else:
            run = ArchiveRediscovery.objects.select_for_update().filter(finished_at__isnull=True).order_by('id').first()
            if run is None:
                run, _ = ArchiveRediscovery.objects.get_or_create(day=now.date(), defaults={
                    'total': HostState.objects.filter(archived_at__isnull=False, archived_by_user=False).count()})
                if run.finished_at:
                    return None, 'already completed today'
        if not run:
            return None, 'run not found'
        if run.lease_until and run.lease_until > now:
            return None, 'running elsewhere'
        run.status, run.lease_until = 'running', now + LEASE
        run.save(update_fields=['status', 'lease_until'])
        return run, ''


def run_page(run_id=None, *, resolver=resolve_one, tcp_probe=None):
    """Visit a bounded page, checkpoint its last id, and enqueue continuation until all rows were visited."""
    from cveFeed import activity
    from cveFeed.scan_control import pause_requested
    from cveFeed.tasks import rediscover_archived_hosts

    run, reason = _claim(run_id)
    if not run:
        return {'skipped': reason}
    rows = list(HostState.objects.filter(pk__gt=run.cursor_hoststate_id, archived_at__isnull=False, archived_by_user=False)
                .select_related('domain', 'project').order_by('pk')[:PAGE])
    for row in rows:
        if pause_requested():
            run.status, run.lease_until = 'partial', None
            run.save(update_fields=['status', 'lease_until'])
            return {'run_id': run.pk, 'status': 'paused', 'checked': run.checked}
        try:
            outcome = check_one(row, resolver=resolver, tcp_probe=tcp_probe)
        except Exception:
            logger.exception('archived host rediscovery failed for state %s', row.pk)
            outcome = 'error'
            HostState.objects.filter(pk=row.pk).update(archive_checked_at=timezone.now(), archive_check_status='error',
                                                        archive_check_error='unexpected checker error')
        run.checked += 1
        run.reactivated += outcome == 'reactivated'
        run.deferred += outcome == 'deferred'
        run.errors += outcome == 'error'
        run.cursor_hoststate_id = row.pk
        run.save(update_fields=['checked', 'reactivated', 'deferred', 'errors', 'cursor_hoststate_id'])
    more = HostState.objects.filter(pk__gt=run.cursor_hoststate_id, archived_at__isnull=False, archived_by_user=False).exists()
    run.lease_until = None
    if more:
        run.status = 'queued'
        run.save(update_fields=['status', 'lease_until'])
        try:
            rediscover_archived_hosts.apply_async(args=[run.pk], queue='cve_feed_queue', countdown=1)
        except Exception:
            run.status = 'partial'
            run.save(update_fields=['status'])
        return {'run_id': run.pk, 'status': run.status, 'checked': run.checked, 'more': True}
    run.status = 'partial' if run.errors or run.deferred else 'completed'
    run.finished_at = timezone.now()
    run.save(update_fields=['status', 'lease_until', 'finished_at'])
    activity.log('inventory', f'Archived asset rediscovery #{run.pk}: {run.checked} checked, '
                 f'{run.reactivated} reactivated, {run.deferred} deferred, {run.errors} errors',
                 status='failed' if run.errors else 'done', run_id=run.pk)
    return {'run_id': run.pk, 'status': run.status, 'checked': run.checked,
            'reactivated': run.reactivated, 'deferred': run.deferred, 'errors': run.errors}
