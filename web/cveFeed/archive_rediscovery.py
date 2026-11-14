"""Daily, checkpointed rediscovery of archived assets without deleting their history."""
import ipaddress
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from cveFeed.models import ArchiveRediscovery, HostState

logger = logging.getLogger(__name__)
PAGE = 25
LEASE = timedelta(minutes=10)


def archived_names(project_id):
    return frozenset(HostState.objects.filter(project_id=project_id, archived_at__isnull=False)
                     .values_list('host', flat=True))


def marker_name(row, host):
    """The made-up name under ``host``'s parent that a wildcard zone would answer for ('' when ``host`` has no parent)."""
    parent = host.partition('.')[2]
    return f'cvengine-nonexistent-{row.pk:x}.{parent}' if parent else ''


def observed_ports(row, host):
    """The TCP ports a stored address was last seen with, as the liveness check asks them (at most three, lowest first)."""
    ports = []
    for key in ((row.state or {}).get('ips') or {}).get(host, {}).get('ports', {}):
        number, _, proto = str(key).partition('/')
        if number.isdigit() and proto in ('', 'tcp') and 0 < int(number) < 65536:
            ports.append(int(number))
    return sorted(set(ports))[:3]


class Reads:
    """What a Sentinel read for a page of archived (or inactive) hosts: the addresses of each name and of its wildcard marker (``identity_check``,
    ``A`` questions) and whether each stored address still accepts a connection on its known ports (``alive_check``). This server asks nothing of a
    name or an address. ``ScannerUnavailable`` propagates when no Sentinel can take a kind (neither has a local path): the caller leaves the page
    for later. A read that was not answered is ``error`` for a name and not alive for a port, so a host is never reactivated or archived on it."""

    def __init__(self, rows, scan=None, dns=True, tcp=True):
        from agentapi import probe_dispatch
        from targetApp.target_types import is_scannable_ip
        self.dns, self.tcp = {}, {}
        names, checks = {}, {}
        for row in rows:
            host = row.host.lower().rstrip('.')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not dns:
                    continue
                marker = marker_name(row, host)
                names.setdefault(row.project_id, ([], []))[0].extend([host] + ([marker] if marker else []))
                names[row.project_id][1].extend([marker] if marker else [])
                continue
            if tcp and is_scannable_ip(host, project=row.project_id):
                checks.setdefault(row.project_id, []).extend(
                    {'id': f'{host}:{port}', 'host': host, 'ip': host, 'port': port, 'scheme': 'tcp'} for port in observed_ports(row, host))
        projects = {row.project_id: row.project for row in rows}
        for project_id, (all_names, markers) in names.items():
            self.dns.update(probe_dispatch.resolve_addresses(projects[project_id], all_names, scan=scan, allow_archived=True, ungated=markers))
        for project_id, rows_checks in checks.items():
            answers = probe_dispatch.try_alive(projects[project_id], scan, rows_checks)
            self.tcp.update({(c['ip'], c['port']): bool(answers.get(c['id'])) for c in rows_checks})

    def resolve(self, host):
        return self.dns.get(host, ('error', set()))

    def tcp_probe(self, ip, port):
        return self.tcp.get((ip, port), False)


def observe(row, resolver=None, tcp_probe=None):
    """Positive DNS is rediscovery, not a claim that a service is alive.

    Wildcard DNS and addresses prohibited by scan policy are held for review.
    An IP asset requires an answering previously observed port instead of DNS. ``resolver(name) -> (resolved|absent|error, addresses)`` and
    ``tcp_probe(ip, port)`` default to what a Sentinel reads (``Reads``).
    """
    from targetApp.target_types import is_scannable_ip
    if resolver is None or tcp_probe is None:
        reads = Reads([row], dns=resolver is None, tcp=tcp_probe is None)
        resolver, tcp_probe = resolver or reads.resolve, tcp_probe or reads.tcp_probe
    host = row.host.lower().rstrip('.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        status, addresses = resolver(host)
        if status != 'resolved':
            return {'status': status, 'addresses': []}
        if not addresses or any(not is_scannable_ip(ip) for ip in addresses):  # answers from DNS carry no tailnet authority
            return {'status': 'blocked', 'addresses': []}
        marker = marker_name(row, host)
        if marker:
            wildcard_status, wildcard_ips = resolver(marker)
            if wildcard_status == 'error':
                return {'status': 'error', 'addresses': []}
            if wildcard_status == 'resolved' and addresses == wildcard_ips:
                return {'status': 'ambiguous_wildcard', 'addresses': sorted(addresses)}
        return {'status': 'rediscovered_dns', 'addresses': sorted(addresses)}
    if not is_scannable_ip(host, project=row.project_id):
        return {'status': 'blocked', 'addresses': []}
    probe = tcp_probe
    ports = observed_ports(row, host)
    if not ports:
        return {'status': 'no_safe_liveness_probe', 'addresses': []}
    try:
        answering = [port for port in ports if probe(host, port)]
    except Exception:
        return {'status': 'error', 'addresses': []}
    return {'status': 'rediscovered_ip', 'addresses': [host]} if answering else {'status': 'unobserved', 'addresses': []}


def check_one(row, *, resolver=None, tcp_probe=None):
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
    from cveFeed.bounty_gate import Gate
    if Gate().refusal(row.project_id, host):  # a bug bounty program that has not confirmed automated testing, or a host outside its scope: no lookup, no probe, no assessment
        HostState.objects.filter(pk=row.pk, archived_at__isnull=False).update(
            archive_checked_at=timezone.now(), archive_check_status='bounty_gate', archive_check_error='')
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
    # and the job will determine actual service coverage separately; both absence streaks (the 30-day vanished-
    # from-enumeration one and the 5-day never-resolved one, see cveFeed.unresolved_archive) start fresh so a
    # single new attempt cannot immediately re-trip either path from a stale, pre-archive streak.
    changed = HostState.objects.filter(pk=row.pk, archived_at__isnull=True).update(
        archive_reason='', archive_checked_at=now, archive_check_status=status,
        archive_check_error='', archive_assessment=job, retired_at=None,
        inactive_first_absent_at=None, inactive_last_absent_at=None, inactive_absent_checks=0,
        unresolved_first_at=None, unresolved_last_at=None, unresolved_checks=0)
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


def run_page(run_id=None, *, resolver=None, tcp_probe=None):
    """Visit a bounded page, checkpoint its last id, and enqueue continuation until all rows were visited."""
    from cveFeed import activity
    from cveFeed.scan_control import pause_requested
    from cveFeed.tasks import rediscover_archived_hosts

    run, reason = _claim(run_id)
    if not run:
        return {'skipped': reason}
    rows = list(HostState.objects.filter(pk__gt=run.cursor_hoststate_id, archived_at__isnull=False, archived_by_user=False)
                .select_related('domain', 'project').order_by('pk')[:PAGE])
    if (resolver is None or tcp_probe is None) and rows:
        from reNgine.resources import ScannerUnavailable
        try:
            reads = Reads(rows, dns=resolver is None, tcp=tcp_probe is None)
        except ScannerUnavailable as exc:  # no Sentinel can take the reads and they never run here: nothing was asked, the page waits for the next run
            run.status, run.lease_until = 'partial', None
            run.save(update_fields=['status', 'lease_until'])
            logger.info('archived host rediscovery waits for a scanner: %s', exc)
            return {'run_id': run.pk, 'status': 'waiting for a scanner', 'checked': run.checked}
        resolver, tcp_probe = resolver or reads.resolve, tcp_probe or reads.tcp_probe
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
