"""Service ledger: which scanner already ran on which asset, so each runs once per asset, not once per scan.

``fresh`` says which assets a scanner covered within its TTL, ``claim``/``claim_many`` keep two pipelines from scanning the
same asset at the same moment (Redis), and ``record`` stores the outcome. Every function is non-fatal: when the database
or Redis is unavailable the caller simply scans.

Scoping: nmap rows are global (project None, the IP's ports are a public fact); nuclei and bbot rows are per project.
"""
import hashlib
import logging
import os
import socket
import threading
import uuid
from contextlib import contextmanager
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)



DEFAULT_TTL_HOURS = {'wafw00f': 7 * 24, 'nmap-fast': 7 * 24, 'nmap-full': 14 * 24, 'naabu': 7 * 24, 'nuclei': 24,
                     'nuclei-deep-target': 7 * 24, 'nuclei-deep-host': 7 * 24, 'bbot': 7 * 24,
                     'ct-watch': 24, 'ct-watch-failed': 6, 'hygiene': 24, 'bbot-deep': 7 * 24, 'route-auth': 7 * 24, 'retest': 24, 'validate': 24, 'archive-urls': 7 * 24,
                     'wpscan': 7 * 24, 'wpscan-partial': 24, 'wpscan-redirected': 6, 'wpscan-not-scannable': 24, 'wpscan-thorough': 30 * 24, 'wpscan-thorough-partial': 24, 'wp-probe': 24, 'probe': 72,
                     'testssl': 14 * 24, 'testssl-failed': 3 * 24, 'buckets': 7 * 24, 'buckets-failed': 24, 'vhost': 7 * 24, 'vhost-ip': 3 * 24, 'subapp': 7 * 24,
                     'nuclei-nocheck': 7 * 24, 'nuclei-auth': 24, 'nuclei-auth-refused': 24, 'route-auth-signed': 24, 'udp-scan': 7 * 24, 'udp-scan-failed': 24, 'udp-scan-noipv6': 24,
                     'openvas': 7 * 24, 'openvas-failed': 3 * 24, 'supplier': 7 * 24, 'supplier-failed': 24,
                     'secrets-scan': 7 * 24, 'secrets-validate': 7 * 24, 'ssh-probe': 7 * 24, 'ssh-probe-failed': 24,
                     # kinds that always ran on the 24 hour default; listed so the check coverage registry (cveFeed.check_coverage) can see them
                     'nuclei-light': 24, 'nuclei-cve': 24, 'rdp-shot': 24, 'node2shell': 24}
CLAIM_TTL = 180  # seconds; refreshed while held, so a crashed worker frees its assets within minutes
CHUNK = 500
KEY_PREFIX = 'cvengine:svc'


def nuclei_tag_service(tags):
    """Service name for a tech-tagged nuclei pass: ``nuclei:<sorted tags>``, hashed when long."""
    joined = ','.join(sorted(set(tags)))
    if len(joined) > 40:
        joined = hashlib.sha1(joined.encode()).hexdigest()[:16]
    return f'nuclei:{joined}'


def failed_service(service):
    """The ledger key under which a target that was only partly checked is remembered, for the same run (``nuclei:<tags>`` becomes ``nuclei-failed:<tags>``): a row
    there that is younger than its TTL (``nuclei-failed``, 24 h) means the target is asked again tomorrow, not at the next scan."""
    base, colon, rest = service.partition(':')
    return f'{base}-failed{colon}{rest}'


def allowlist_release():
    """A short name for which service classes the Sentinel library's service-port allowlist has a template for (``cvengine_scanner.nuclei_allowlist``): it changes
    exactly when a class gains or loses its first template, which is when a port that had no check may have one."""
    try:
        import hashlib
        from cvengine_scanner import nuclei_allowlist
        classes = sorted({k for e in nuclei_allowlist.load_allowlist()['templates'].values() if isinstance(e, dict) for k in (e.get('classes') or ())})
        return hashlib.sha1(','.join(classes).encode()).hexdigest()[:8]
    except Exception:  # noqa: BLE001 - a library without the list: one fixed name, so the 7 day window alone decides
        return '00000000'


def nocheck_service(service, release=None):
    """The ledger key under which a target that no check exists for is remembered (``nuclei:<tags>`` becomes ``nuclei-nocheck:<release>:<tags>``): a port of a
    service no template speaks to (postgres) is not failed and not covered, and is not asked again before the row's TTL (``nuclei-nocheck``, 7 days) is over or
    the allowlist's classes change (``allowlist_release``: a check may exist now). ``release`` defaults to the library in use."""
    base, _colon, rest = service.partition(':')
    return f'{base}-nocheck:{release or allowlist_release()}' + (f':{rest}' if rest else '')


def ttl(service):
    """Seconds a finished run of ``service`` stays fresh. Override with CVENGINE_TTL_<SERVICE> in hours."""
    base = service.split(':')[0]
    name = 'CVENGINE_TTL_' + base.upper().replace('-', '_')
    try:
        hours = float(os.environ.get(name, ''))
    except ValueError:
        hours = DEFAULT_TTL_HOURS.get(base, 24)
    return int(hours * 3600)


def ttl_label(service):
    """The TTL as people say it: ``24h``, ``7 days``."""
    hours = ttl(service) / 3600
    return f'{round(hours / 24)} days' if hours >= 48 else f'{round(hours)}h'


def _norm(asset):
    return str(asset).strip().lower()[:255]


def _pk(obj):
    return getattr(obj, 'pk', obj)


def _chunks(items, size=CHUNK):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def fresh(service, assets, project=None):
    """The subset of ``assets`` with a ``done`` run of ``service`` newer than its TTL, in the same project (global rows
    use project None)."""
    from cveFeed.models import ServiceRun
    wanted = {_norm(a) for a in assets}
    found = set()
    cutoff = timezone.now() - timedelta(seconds=ttl(service))
    try:
        for part in _chunks(wanted):
            found.update(ServiceRun.objects.filter(
                service=service, project_id=_pk(project), asset__in=part, status='done', finished_at__gte=cutoff
            ).values_list('asset', flat=True))
    except Exception:  # noqa: BLE001 - a ledger failure means "scan it again"
        logger.exception('ledger: could not read %s', service)
        return set()
    return found


def last_run(service, assets, project=None):
    """``{asset: when its latest run of ``service`` finished}`` (any status) for the assets that have one: to run the never-run and the
    longest-waiting first when a cap cuts the list."""
    from cveFeed.models import ServiceRun
    found = {}
    try:
        for part in _chunks({_norm(a) for a in assets}):
            found.update(ServiceRun.objects.filter(service=service, project_id=_pk(project), asset__in=part).values_list('asset', 'finished_at'))
    except Exception:  # noqa: BLE001 - a ledger failure means "no history": every asset reads as never run
        logger.exception('ledger: could not read %s', service)
    return found


def record(service, assets, project=None, scan=None, status='done'):
    """Upsert one row per asset with the outcome of this run."""
    from cveFeed.models import ServiceRun
    names = {_norm(a) for a in assets}
    now = timezone.now()
    try:
        for part in _chunks(names):
            existing = set(ServiceRun.objects.filter(service=service, project_id=_pk(project), asset__in=part)
                           .values_list('asset', flat=True))
            ServiceRun.objects.bulk_create([
                ServiceRun(service=service, asset=a, project_id=_pk(project), scan_id=_pk(scan), status=status, finished_at=now)
                for a in part if a not in existing], ignore_conflicts=True)
            ServiceRun.objects.filter(service=service, project_id=_pk(project), asset__in=part).update(
                scan_id=_pk(scan), status=status, finished_at=now)
    except Exception:  # noqa: BLE001
        logger.exception('ledger: could not record %s', service)


def stale_first(service, domains):
    """The ``(domain_id, name, project_id)`` rows of ``domains`` with no fresh ``done`` run of ``service``, never-run first,
    then oldest run first. A ledger failure means "everything is due"."""
    from cveFeed.models import ServiceRun
    rows = list(domains)
    cutoff = timezone.now() - timedelta(seconds=ttl(service))
    last = {}
    try:
        by_project = {}
        for row in rows:
            by_project.setdefault(row[2], set()).add(_norm(row[1]))
        for project_id, names in by_project.items():
            for part in _chunks(names):
                for asset, finished, status in ServiceRun.objects.filter(
                        service=service, project_id=project_id, asset__in=part).values_list('asset', 'finished_at', 'status'):
                    last[(project_id, asset)] = finished if status == 'done' else None
    except Exception:  # noqa: BLE001
        logger.exception('ledger: could not read %s', service)
        return rows
    epoch = timezone.now() - timedelta(days=36500)
    due = [r for r in rows if not (last.get((r[2], _norm(r[1]))) or epoch) >= cutoff]
    return sorted(due, key=lambda r: last.get((r[2], _norm(r[1]))) or epoch)


def sweep_claim(name, seconds):
    """Take the right to run the ``name`` sweep for the next ``seconds``. False when another sweep holds it. The key is
    left to expire, not released, so a sweep that is still working through what it queued is never doubled."""
    from reNgine import resources
    client = getattr(resources.get_store(), 'r', None)
    if client is None:
        return True
    try:
        return bool(client.set(f'cvengine:sweep:{name}', _owner(), nx=True, ex=max(60, int(seconds))))
    except Exception:  # noqa: BLE001
        return True


def sweep_claim_renew(name, seconds):
    """Take the ``name`` sweep's claim for the next ``seconds`` whoever held it (a run that must not wait for it). Never raises."""
    from reNgine import resources
    client = getattr(resources.get_store(), 'r', None)
    if client is None:
        return
    try:
        client.set(f'cvengine:sweep:{name}', _owner(), ex=max(60, int(seconds)))
    except Exception:  # noqa: BLE001
        pass


def _key(service, asset):
    return f'{KEY_PREFIX}:{service}:{_norm(asset)}'


def _owner():
    return f'{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}'


@contextmanager
def claim(service, asset):
    """Hold the right to run ``service`` on ``asset``. Yields True when this caller won it (or Redis is unavailable), False
    when another pipeline is running it right now."""
    from reNgine import resources
    from agentapi import stage_runs
    run = stage_runs.current()  # inside a StageRun the claim belongs to the run: held while it waits, taken back by its next pass
    owner = run.claim_owner(service) if run is not None else _owner()
    with resources.redis_claim(_key(service, asset), owner, CLAIM_TTL, adopt=run is not None, hold=run is not None) as holder:
        yield holder is True


@contextmanager
def claim_many(service, assets):
    """Claim every asset it can. Yields the list this caller won, and releases them on exit. One thread keeps them all alive."""
    from reNgine import resources
    assets = sorted({_norm(a) for a in assets})
    client = getattr(resources.get_store(), 'r', None)
    if client is None:
        yield assets
        return
    from agentapi import stage_runs
    run = stage_runs.current()
    # Inside a StageRun (agentapi.stage_runs) the claims belong to the run, not to this worker: they are held while the run waits for its
    # Sentinels and taken back by the pass that continues it, so another scan cannot start the same work in between.
    owner = run.claim_owner(service) if run is not None else _owner()
    won = []
    try:
        for a in assets:
            if client.set(_key(service, a), owner, nx=True, ex=CLAIM_TTL) or (run is not None and client.get(_key(service, a)) == owner):
                won.append(a)
    except Exception:  # noqa: BLE001 - never block scanning because the claim is unavailable
        logger.exception('ledger: Redis claim failed for %s', service)
        yield assets  # unknown state: scan everything; any keys already set expire on their own
        return
    stop = threading.Event()

    def keep_alive():
        while not stop.wait(CLAIM_TTL / 6):
            try:
                for a in list(won):
                    if resources.claim_refresh(client, _key(service, a), owner, CLAIM_TTL) == 'lost':
                        logger.warning('ledger: the %s claim on %s was taken over by another job', service, a)
                        won.remove(a)  # not ours any more: neither refreshed nor deleted on exit
            except Exception:  # noqa: BLE001
                pass
    if won:
        threading.Thread(target=keep_alive, name='ledger-claim', daemon=True).start()
    suspending = False
    try:
        yield won
    except stage_runs.Suspend:
        suspending = True
        raise
    finally:
        stop.set()
        try:
            for a in list(won):
                if suspending:  # the run waits: the claim outlives this pass, kept alive by the run's drive
                    resources.claim_refresh(client, _key(service, a), owner, stage_runs.HOLD_SECONDS)
                    run.hold_claim(_key(service, a), owner)
                else:
                    resources.claim_release(client, _key(service, a), owner)
        except Exception:  # noqa: BLE001
            pass
