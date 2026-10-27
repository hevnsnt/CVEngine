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
                     'ct-watch': 24, 'hygiene': 24, 'bbot-deep': 7 * 24, 'route-auth': 7 * 24, 'retest': 24, 'validate': 24, 'archive-urls': 7 * 24,
                     'wpscan': 7 * 24, 'wpscan-partial': 24, 'wpscan-thorough': 30 * 24, 'wpscan-thorough-partial': 24, 'wp-probe': 24, 'probe': 72}
CLAIM_TTL = 180  # seconds; refreshed while held, so a crashed worker frees its assets within minutes
CHUNK = 500
KEY_PREFIX = 'cvengine:svc'


def nuclei_tag_service(tags):
    """Service name for a tech-tagged nuclei pass: ``nuclei:<sorted tags>``, hashed when long."""
    joined = ','.join(sorted(set(tags)))
    if len(joined) > 40:
        joined = hashlib.sha1(joined.encode()).hexdigest()[:16]
    return f'nuclei:{joined}'


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


def _key(service, asset):
    return f'{KEY_PREFIX}:{service}:{_norm(asset)}'


def _owner():
    return f'{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}'


@contextmanager
def claim(service, asset):
    """Hold the right to run ``service`` on ``asset``. Yields True when this caller won it (or Redis is unavailable), False
    when another pipeline is running it right now."""
    from reNgine import resources
    with resources.redis_claim(_key(service, asset), _owner(), CLAIM_TTL) as holder:
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
    owner = _owner()
    won = []
    try:
        for a in assets:
            if client.set(_key(service, a), owner, nx=True, ex=CLAIM_TTL):
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
    try:
        yield won
    finally:
        stop.set()
        try:
            for a in list(won):
                resources.claim_release(client, _key(service, a), owner)
        except Exception:  # noqa: BLE001
            pass
