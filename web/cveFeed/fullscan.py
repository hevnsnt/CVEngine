"""Background full port scan: an always-on, slow sweep of all 65,535 TCP ports of ONE in-scope IP at a time.

A celery-beat task (``background_full_scan``) fires every few minutes. Each firing takes a Redis claim (one sweep across all
workers), picks the IP most worth sweeping next (never swept first, then the oldest sweep; among equally stale ones the IP with
the most open ports), sweeps it under the ``nmap-full-bg`` heavy job (it waits behind everything else, so discovery is never
starved), and writes the open ports into the same per-IP inventory the pipeline fills. A port open now that was not open before is
new surface: it is fingerprinted, and the hosts on that IP go through the re-test pipeline (see ``investigate``). The pipeline's own
nmap pass stays the top 1000 plus EXTRA_PORTS; this task is the only ``-p-`` sweep.

A failed or timed-out sweep records its attempt in ``full_scan_started_at`` but does not advance
``full_scanned_at``: only successful coverage is fresh. The in-flight lease delays retries of a stuck host, and an IP whose
sweeps keep failing backs off (``full_scan_retry_at``: 6 hours after the first failure, doubling, at most 7 days) and goes
behind the clean never-swept IPs, so a few dead addresses cannot hold the one sweep slot. Waiting too long for memory or a
pause is not the address's failure and does not count.
"""
import logging
import os

from django.utils import timezone

logger = logging.getLogger(__name__)

CLAIM_KEY = 'cvengine:fullscan'
CLAIM_TTL = 3 * 3600  # must exceed the memory wait (WAIT_SECONDS) so the single-sweep claim never lapses mid-sweep; a crashed worker's claim still expires
WAIT_SECONDS = 2 * 3600  # the longest a sweep waits for memory before it gives up (and still advances the rotation)
IN_FLIGHT_SECONDS = WAIT_SECONDS + 3600  # a sweep whose start is more recent than this, and not yet finished, is still running:
# never pick that IP again (this, not the global claim, is what stops the same host being swept twice if the claim lapses)
MAX_CANDIDATES = 500  # IPs looked at per pick: the scope checks resolve names, so they are bounded
MAX_NAMES_CHECKED = 5  # hostnames of one IP resolved to see that none points somewhere a scanner must not touch
DEFAULT_INTERVAL_MIN = 10
FAILURE_BACKOFF_HOURS = 6  # after the first failed sweep; doubles per further failure
MAX_BACKOFF_HOURS = 7 * 24
DEFAULT_INVESTIGATE_MAX = 50
FINGERPRINT_FLAGS = ['-sV', '--version-intensity', '5', '-Pn', '-T4']
OPEN = ('', 'open')


def _truthy(value):
    return str(value).strip().lower() not in ('0', 'false', 'no', 'off')


def enabled():
    """CVENGINE_FULLSCAN: on unless it is 0/false/no/off."""
    return _truthy(os.environ.get('CVENGINE_FULLSCAN', '1'))


def _int_env(name, default, low=1, high=1000):
    try:
        return min(high, max(low, int(os.environ.get(name, default))))
    except ValueError:
        return default


def interval_minutes():
    return _int_env('CVENGINE_FULLSCAN_INTERVAL_MIN', DEFAULT_INTERVAL_MIN, 1, 1440)


def batch_size():
    return _int_env('CVENGINE_FULLSCAN_BATCH', 1, 1, 20)


def investigate_max():
    return _int_env('CVENGINE_FULLSCAN_INVESTIGATE_MAX', DEFAULT_INVESTIGATE_MAX, 1, 1000)


# ----------------------------------------------------------------------------- selection

def active_attached(ip):
    """Stored host rows on this IP that are still in active project scope."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import HostState
    from startScan.models import Subdomain
    archived = HostState.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'),
                                        archived_at__isnull=False)
    return Subdomain.objects.filter(ip_addresses=ip, target_domain__project__isnull=False).filter(~Exists(archived))

def candidates():
    """In-scope IpAddress rows, in sweep order: ``full_scanned_at`` oldest first with never-swept first, then the fewest failed
    sweeps, then the most open ports, then id; an IP backing off after failures is left out until its retry time. In scope
    means attached to a Subdomain of a target that belongs to a project, and not a CDN address."""
    from datetime import timedelta

    from django.db.models import Count, Exists, F, OuterRef, Q
    from startScan.models import IpAddress
    attached = active_attached(OuterRef('pk'))
    # a sweep is in flight when it started after its last finish (or was never finished) and that start is recent
    in_flight = (Q(full_scan_started_at__isnull=False) & Q(full_scan_started_at__gte=timezone.now() - timedelta(seconds=IN_FLIGHT_SECONDS))
                 & (Q(full_scanned_at__isnull=True) | Q(full_scanned_at__lt=F('full_scan_started_at'))))
    return (IpAddress.objects.filter(Exists(attached), is_cdn=False, address__isnull=False).exclude(in_flight)
            .exclude(full_scan_retry_at__gt=timezone.now())
            .annotate(open_count=Count('ports', filter=Q(ports__state__in=OPEN), distinct=True))
            .order_by(F('full_scanned_at').asc(nulls_first=True), 'full_scan_failures', '-open_count', 'id'))


def in_scope(ip, *, strict=False):
    """Whether a scanner may be pointed at ``ip``: a scannable address (private ones only with CVENGINE_ALLOW_PRIVATE_TARGETS), and
    at least one of the in-scope names on it that does not resolve anywhere blocked."""
    from targetApp import target_types
    address = (ip.address or '').strip()
    if not address or ip.is_cdn or not target_types.is_scannable_ip(address):
        return False
    from cveFeed import hosting
    shared = hosting.shared_by_address([address])
    if shared:  # a shared platform's edge (Netlify, Vercel, a CDN): other customers answer here. Flag it so the queue skips it for good.
        hosting.mark_shared(shared)
        return False
    from cveFeed.exclusions import excluded_names
    from cveFeed.archive_rediscovery import archived_names
    rows = list(active_attached(ip)
                .values_list('name', 'target_domain__project_id').distinct()[:MAX_NAMES_CHECKED])
    banned = {}  # project id -> the names its organization excluded for good: such a name does not make the address in scope
    for _name, project in rows:
        if project not in banned:
            if strict:
                # Admission is an authorization boundary: a failed lookup must prevent process creation.
                from cveFeed.models import HostExclusion
                banned[project] = set(HostExclusion.objects.filter(org__projects__id=project).values_list('host', flat=True))
            else:
                banned[project] = excluded_names(project)
            banned[project] |= archived_names(project)
    names = [name for name, project in rows if name.lower().rstrip('.') not in banned[project]]
    return any(not target_types.resolves_to_blocked(name) for name in names)


def pick():
    """The next IpAddress to sweep, or None when nothing in scope is left to look at."""
    for ip in candidates()[:MAX_CANDIDATES]:
        try:
            if in_scope(ip):
                return ip
        except Exception:  # noqa: BLE001 - one odd row must not stop the rotation
            logger.warning('full scan: could not check %s', ip.address, exc_info=True)
    return None


def queue_depth():
    """IPs in scope never swept, and the newest sweep, for a status line."""
    from startScan.models import IpAddress
    waiting = candidates().filter(full_scanned_at__isnull=True).count()
    last = IpAddress.objects.filter(full_scanned_at__isnull=False).order_by('-full_scanned_at').first()
    return {'never_swept': waiting, 'last_ip': last.address if last else None, 'last_at': last.full_scanned_at if last else None}


# ----------------------------------------------------------------------------- the sweep

def _open_tcp(host):
    return sorted({r['number'] for r in host.get('ports', []) if r.get('number') and r.get('state', 'open') in OPEN
                   and r.get('protocol', 'tcp') in ('', 'tcp')})


def _project_of(ip):
    return active_attached(ip).values_list(
        'target_domain__project_id', flat=True).first()


def _claim_ip(ip):
    """Atomically mark this IP's sweep as started, so no other firing (even across workers or after the global claim lapses) sweeps
    it at the same time. Returns True when this caller won the claim. A stale in-flight mark (older than IN_FLIGHT_SECONDS, a crashed
    sweep) can be taken over."""
    from datetime import timedelta

    from django.db.models import F, Q
    from startScan.models import IpAddress
    now = timezone.now()
    stale = now - timedelta(seconds=IN_FLIGHT_SECONDS)
    free = (Q(full_scan_started_at__isnull=True) | Q(full_scan_started_at__lt=stale)
            | (Q(full_scanned_at__isnull=False) & Q(full_scanned_at__gte=F('full_scan_started_at'))))
    return IpAddress.objects.filter(pk=ip.pk).filter(free).update(full_scan_started_at=now) == 1


def sweep_ip(ip, runner=None, fingerprint_runner=None, pipeline=None):
    """Sweep every TCP port of one IpAddress and record it. Returns the result dict (``ok`` False with an ``error`` on a failed
    or timed-out sweep; ``full_scanned_at`` advances only on success). ``runner(targets, flags, host_timeout) -> xml`` runs the sweep
    and ``fingerprint_runner`` the -sV pass on new ports (both injectable); ``pipeline(domain_id, names)`` runs the re-test of the
    hosts on this IP."""
    from cveFeed import activity, naabu_scan
    from cveFeed import nmap_scan
    address = ip.address
    project = _project_of(ip)
    before = set(naabu_scan.known_open_ports([address]).get(address, []))
    seen = []

    def capture(targets, flags, host_timeout):
        runner_ = runner or _sweep_runner
        xml = runner_(targets, flags, host_timeout)
        seen.append(xml)
        return xml

    running = activity.log('run_check', f'Background full port scan of {address} (all 65,535 TCP ports; this can take a while)',
                           project=project, status='running')
    try:
        nmap_scan.scan_in_chunks(capture, [address], nmap_scan.FULL_PORT_FLAGS, nmap_scan.HOST_TIMEOUT_FULL, size=1)
    except Exception as exc:  # noqa: BLE001 - failure remains visible and retryable after the in-flight lease or the backoff
        from reNgine.resources import MemoryBusy, ScanAborted
        logger.warning('background full scan of %s failed', address, exc_info=True)
        retry = None if isinstance(exc, (MemoryBusy, ScanAborted)) else _back_off(ip)
        activity.settle(running, 'failed', message=activity.diagnostic(f'Background full port scan of {address}',
                                                                       f'{type(exc).__name__}: {exc}', type(exc).__name__)
                        + (f'; next try after {retry:%Y-%m-%d %H:%M} UTC' if retry else ''))
        return {'ip': address, 'ok': False, 'error': type(exc).__name__}
    found = set()
    for xml in seen:
        for host in nmap_scan.parse_xml(xml):
            if host.get('ip') == address:
                found.update(_open_tcp(host))
    _advance(ip, len(found))
    new = sorted(found - before)
    gone = sorted(before - found)
    activity.settle(running, 'done', message=(
        f'Background full port scan of {address}: {len(found)} open port(s)'
        + (f', {len(new)} new ({", ".join(map(str, new[:10]))})' if new else '')
        + (f', {len(gone)} closed' if gone else '')), open_ports=len(found), new_ports=len(new))
    result = {'ip': address, 'ok': True, 'open': len(found), 'new': new, 'closed': gone}
    if new:
        try:
            result['investigation'] = investigate(ip, new, project, runner=fingerprint_runner, pipeline=pipeline)
        except Exception:  # noqa: BLE001 - never lets the investigation undo the sweep or stop the rotation
            logger.exception('background full scan: investigating %s failed', address)
            result['investigation'] = {'error': 'investigation failed'}
    return result


def _back_off(ip):
    """Count a failed sweep of ``ip`` and set when it may be picked again. Returns that time."""
    from datetime import timedelta

    from django.db.models import F
    from startScan.models import IpAddress
    failures = (IpAddress.objects.filter(pk=ip.pk).values_list('full_scan_failures', flat=True).first() or 0) + 1
    retry = timezone.now() + timedelta(hours=min(MAX_BACKOFF_HOURS, FAILURE_BACKOFF_HOURS * 2 ** min(failures - 1, 10)))
    IpAddress.objects.filter(pk=ip.pk).update(full_scan_failures=F('full_scan_failures') + 1, full_scan_retry_at=retry)
    return retry


def _advance(ip, ports):
    from startScan.models import IpAddress
    fields = {'full_scanned_at': timezone.now(), 'full_scan_failures': 0, 'full_scan_retry_at': None}
    if ports is not None:
        fields['full_scan_ports'] = ports
    IpAddress.objects.filter(pk=ip.pk).update(**fields)


def _sweep_runner(targets, flags, host_timeout):
    from cveFeed import nmap_scan
    return nmap_scan.run_nmap_xml(targets, flags, host_timeout, kind='nmap-full-bg', wait_timeout=WAIT_SECONDS,
                                 before_launch=lambda: _require_current_scope(targets))


def _require_current_scope(targets):
    """Re-read inventory and exclusions after a resource wait; never use the IP instance captured by pick()."""
    from startScan.models import IpAddress
    for address in targets:
        ip = IpAddress.objects.filter(address=address).first()
        if ip is None or not in_scope(ip, strict=True):
            raise ValueError('background scan target is no longer in scope')


def _fingerprint_runner(targets, flags, host_timeout):
    from cveFeed import nmap_scan
    return nmap_scan.run_nmap_xml(targets, flags, host_timeout,
                                 before_launch=lambda: _require_current_scope(targets))


# ----------------------------------------------------------------------------- new ports

def investigate(ip, new_ports, project, runner=None, pipeline=None):
    """Look into ports that were not open on ``ip`` before this sweep, bounded by CVENGINE_FULLSCAN_INVESTIGATE_MAX ports:

    1. ``-sV`` on just those ports (the same runner and ``persist_inventory`` as every nmap pass), so product, version, CPE and
       distro land on the port rows.
    2. The hosts on this IP go through the re-test host pipeline (cveFeed.retest, ``run_host_pipeline(retest=True)``), once per
       target. It is the one path that already runs the database exposure check, the light and targeted nuclei passes, CVE
       correlation, triage and validation, and the asset change diff (which writes one ``port_opened`` AssetChange per new port per
       host and feeds the score, exactly like a port the pipeline found). Its ScanHistory is tagged ``host_pipeline`` + ``retest``,
       so findings have a scan to hang on, the per-scan dedupe works, and none of it passes for a full discovery. The re-test ledger
       (one per host per 24 hours) keeps a host that was just tested from being tested again.
    ``pipeline(domain_id, names)`` replaces the queueing of that task (tests run the pipeline inline)."""
    from cveFeed import activity, ledger, naabu_scan, nmap_scan, retest
    from cveFeed.models import ServiceRun
    from datetime import timedelta
    from startScan.models import Subdomain
    ports = sorted(set(new_ports))[:investigate_max()]
    out = {'ports': ports, 'capped': len(set(new_ports)) > len(ports)}
    try:
        flags = [*FINGERPRINT_FLAGS, '-p', naabu_scan.port_argument(ports)]
        fingerprinted = nmap_scan.scan_in_chunks(runner or _fingerprint_runner, [ip.address], flags,
                                                 nmap_scan.HOST_TIMEOUT_FAST, size=1)
        out['fingerprinted'] = fingerprinted.get('ports', 0)
    except Exception as exc:  # noqa: BLE001 - the ports are recorded; their versions arrive with the next fingerprint
        logger.warning('could not fingerprint new ports %s on %s', ports, ip.address, exc_info=True)
        out['fingerprint_error'] = str(exc)[:200]
    rows = active_attached(ip).values_list(
        'target_domain_id', 'name', 'target_domain__project_id')
    by_domain, projects = {}, {}
    for domain_id, name, project_id in rows:
        by_domain.setdefault(domain_id, set()).add(name.lower())
        projects[domain_id] = project_id
    queued = []
    for domain_id in list(by_domain)[:retest.max_hosts()]:
        names = sorted(by_domain[domain_id])
        recent = ledger.fresh(retest.RETEST_SERVICE, names, projects[domain_id])
        queued_recent = set(ServiceRun.objects.filter(service=retest.RETEST_SERVICE, project_id=projects[domain_id],
                         asset__in=names, status='queued', finished_at__gte=timezone.now() - timedelta(minutes=30))
                     .values_list('asset', flat=True))
        names = [n for n in names if n not in recent and n not in queued_recent][:retest.max_hosts()]
        if not names:
            continue
        try:
            if pipeline:
                pipeline(domain_id, names)
                ledger.record(retest.RETEST_SERVICE, names, projects[domain_id])
            else:
                from cveFeed.tasks import retest_hosts
                retest_hosts.delay(domain_id, names)
                ledger.record(retest.RETEST_SERVICE, names, projects[domain_id], status='queued')
            queued.extend(names)
        except Exception:  # noqa: BLE001
            logger.exception('could not re-test %s after a new port on %s', names, ip.address)
    out['retested'] = queued
    if queued:
        activity.log('changes', f'New open port(s) {", ".join(map(str, ports[:8]))} on {ip.address}: re-testing '
                     f'{", ".join(queued[:3])}{", ..." if len(queued) > 3 else ""}', project=project)
    return out


# ----------------------------------------------------------------------------- the task body

def run(runner=None, fingerprint_runner=None, pipeline=None):
    """One firing of the background sweep: up to CVENGINE_FULLSCAN_BATCH IPs, one at a time, under one Redis claim."""
    from reNgine import resources
    if not enabled():
        return {'skipped': 'CVENGINE_FULLSCAN is off'}
    swept = []
    with resources.redis_claim(CLAIM_KEY, f'fullscan-{os.getpid()}', CLAIM_TTL) as held:
        if held is not True:
            return {'skipped': f'another background sweep is running ({held})'}
        looked = 0
        while len(swept) < batch_size() and looked < MAX_CANDIDATES:
            ip = pick()
            if ip is None:
                break
            looked += 1
            if not _claim_ip(ip):
                continue  # another firing is already sweeping this IP; never run a second sweep of the same host
            swept.append(sweep_ip(ip, runner=runner, fingerprint_runner=fingerprint_runner, pipeline=pipeline))
    return {'swept': swept}
