"""Finding the live hosts of a declared internal network (``cveFeed.models.InternalRange``): a Sentinel deployed inside the network sweeps
the range and reports what answered, and each answering address becomes a target of the project, which the internal scan driver
(``cveFeed.internal_scan``) then scans like any other. This server never sends a packet to the range itself.

A range is swept in /24 chunks, one ``discover`` ``SentinelTask`` each, so a task stays short enough for a Sentinel's lease and a
report stays small. The Sentinel says only which addresses answered; this module decides what to do with that. An address it names is
dropped unless it lies inside the chunk it was asked about, so a Sentinel cannot make the server add a target outside what the project
declared. Nothing is ever deleted: a host that stops answering stays a target (the scan of it says it was unreachable) until an
administrator removes it.

Cadence is weekly (``CVENGINE_INTERNAL_DISCOVERY_DAYS``) with a "scan now" on the range; the sweep only runs in a project where a live
``network:internal`` Sentinel declares ``discover``, and never reads a silent network as an empty one: a chunk nobody answered is an
error on the range, not a sweep that found nothing.
"""
import ipaddress
import logging
import os
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

CHUNK_PREFIX = 24  # IPv4 chunk swept by one task
CHUNKS_PER_RUN = 64  # chunks one run sweeps (CVENGINE_INTERNAL_DISCOVERY_CHUNKS): a /18; a larger range finishes over the next runs
LOCK_TTL = 3600


def cadence():
    """How long a swept range is left alone before the sweep queues it again (CVENGINE_INTERNAL_DISCOVERY_DAYS, default 7)."""
    try:
        return timedelta(days=max(1, int(os.environ.get('CVENGINE_INTERNAL_DISCOVERY_DAYS', '7'))))
    except ValueError:
        return timedelta(days=7)


def chunks(cidr, start=0, limit=None):
    """The /24 chunks of ``cidr`` from index ``start`` (at most ``limit``), and how many it has in all. An IPv6 range is not swept: it
    cannot be enumerated, so its hosts are added by hand."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        return [], 0
    parts = [net] if net.prefixlen >= CHUNK_PREFIX else list(net.subnets(new_prefix=CHUNK_PREFIX))
    return (parts[start:start + limit] if limit else parts[start:]), len(parts)


def _chunk_limit():
    try:
        return max(1, int(os.environ.get('CVENGINE_INTERNAL_DISCOVERY_CHUNKS', str(CHUNKS_PER_RUN))))
    except ValueError:
        return CHUNKS_PER_RUN


def _usable(net, value):
    """``value`` as an address inside ``net`` that may be a target, or ``None``: network and broadcast addresses of a chunk are never hosts."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version != net.version or ip not in net:
        return None
    if net.version == 4 and net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address):
        return None
    return str(ip)


def due_ranges(limit=10, now=None):
    """Declared ranges to sweep now, longest unswept first: none swept inside the cadence, and only in a project where a live
    ``network:internal`` Sentinel that declares ``discover`` could take the work."""
    from django.db.models import F
    from agentapi import sentinel_broker
    from cveFeed.models import InternalRange
    now = now or timezone.now()
    cutoff = now - cadence()
    chosen = []
    rows = (InternalRange.objects.select_related('project__org').exclude(last_discovery_at__gte=cutoff)
            .order_by(F('last_discovery_at').asc(nulls_first=True), 'id'))
    for row in rows:
        if len(chosen) >= limit:
            break
        if chunks(row.cidr)[1] and sentinel_broker.any_scanner_for(row.project, 'discover', internal=True):
            chosen.append(row)
    return chosen


def sweep():
    """One round of the scheduled sweep: queue a discovery of each due range. Returns how many."""
    from cveFeed.scan_control import pause_requested
    from cveFeed.tasks import run_internal_discovery
    if pause_requested():
        return {'queued': 0, 'skipped': 'paused'}
    rows = due_ranges()
    for row in rows:
        run_internal_discovery.delay(row.pk)
    return {'queued': len(rows)}


def discover_range(range_id, dispatch=None, scan_after=True):
    """Sweep one declared range through an internal Sentinel and add what answered as targets. ``dispatch`` replaces
    ``sentinel_dispatch.dispatch_or_none`` in tests. Returns a summary and records it on the range."""
    from agentapi import sentinel_dispatch
    from cveFeed import activity
    from cveFeed.models import InternalRange
    from reNgine.resources import redis_claim
    dispatch = dispatch or sentinel_dispatch.dispatch_or_none
    row = InternalRange.objects.select_related('project__org').filter(pk=range_id).first()
    if row is None:
        return {'range': range_id, 'skipped': 'range removed'}
    with redis_claim(f'internal-discovery:{row.pk}', 'discover', LOCK_TTL) as held:
        if held is not True:
            return {'range': row.cidr, 'skipped': 'a discovery of this range is already running'}
        return _discover(row, dispatch, activity, scan_after)


def _discover(row, dispatch, activity, scan_after):
    from agentapi.services import add_entries
    from cveFeed.models import InternalRange
    from targetApp.models import Domain
    project = row.project
    start = row.discovery_cursor if row.discovery_cursor < chunks(row.cidr)[1] else 0
    todo, total = chunks(row.cidr, start, _chunk_limit())
    if not todo:
        message = 'IPv6 ranges are not swept; add their hosts by hand' if ipaddress.ip_network(row.cidr, strict=False).version != 4 else 'nothing to sweep'
        InternalRange.objects.filter(pk=row.pk).update(last_discovery_error=message)
        return {'range': row.cidr, 'error': message}
    running = activity.log('run_check', f'Discovering hosts in internal range {row.cidr}: a Sentinel inside the network sweeps it, never this server',
                           project=project.id, status='running')
    found, failed, first_failure = [], 0, ''
    for net in todo:
        result = dispatch(project, 'discover', {'cidr': str(net)}, host=str(net), ips=[str(net.network_address)], internal=True)
        if result is None:
            failed += 1
            first_failure = first_failure or f'no Sentinel inside the network answered for {net}'
            continue
        for item in result.get('hosts') or []:
            ip = _usable(net, item.get('ip'))
            if ip:
                found.append(ip)
    found = list(dict.fromkeys(found))
    existing = set(Domain.objects.filter(project=project, name__in=found).values_list('name', flat=True))
    fresh = [ip for ip in found if ip not in existing]
    created = 0
    if fresh:
        outcome = add_entries(project, fresh, discover=False)
        created = outcome['created']
    done_sweep = start + len(todo) >= total
    update = {'last_discovery_error': first_failure[:200], 'discovery_cursor': start if failed else (0 if done_sweep else start + len(todo))}
    if not failed and done_sweep:
        update['last_discovery_at'] = timezone.now()
        if start == 0:
            update['last_discovery_hosts'] = len(found)
    InternalRange.objects.filter(pk=row.pk).update(**update)
    summary = {'range': row.cidr, 'chunks': len(todo), 'failed': failed, 'found': len(found), 'created': created}
    if failed and not found:
        activity.settle(running, 'failed', message=f'Internal range {row.cidr}: {first_failure}; nothing was swept, so this is not a clean result')
    else:
        activity.settle(running, 'done', message=f'Internal range {row.cidr}: {len(found)} live host(s), {created} new target(s)'
                        + (f'; {failed} of {len(todo)} chunk(s) got no answer' if failed else ''))
    if created and scan_after:
        from cveFeed import internal_scan
        internal_scan.sweep()
    return summary
