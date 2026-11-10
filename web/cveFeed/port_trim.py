"""Cut the stored port list of an address that answers on almost every port to the number the product keeps.

A Sentinel's full-port report is cut to ``TARPIT_PORTS`` open ports for an address like that (a tarpit, a load balancer or a filtering device,
``agentapi.sentinel_dispatch``): more says something about the address, not about a service on it, and ``port_flood`` files that as one finding. Lists
stored before the cut (or by a path that did not apply it) stayed whole: on the production VPS 45 addresses, mostly cloud load balancers, held 605,829 of
the 612,846 stored ports, 65,535 rows each. Every task that read a host pointing at one of them loaded all of its rows into Python: the work planner's
census alone grew a worker by 1.3 GB per run and the lanes sat at the container's memory ceiling (11/10). This keeps the lowest ``TARPIT_PORTS`` open TCP
ports of each such address, as the Sentinel path does, and removes the rest. The finding still stands (it fires from ``THRESHOLD`` ports).
"""
import logging

from django.db.models import Count

logger = logging.getLogger(__name__)

DELETE_BATCH = 2000


def keep_count():
    from agentapi.sentinel_dispatch import TARPIT_PORTS
    return TARPIT_PORTS


def flooded_ips(keep=None):
    """``{ipaddress_id: open TCP port count}`` for every address holding more than ``keep`` open TCP ports."""
    from startScan.models import OPEN_PORT_STATES, TCP_PROTOCOLS, IpAddress
    keep = keep_count() if keep is None else keep
    through = IpAddress.ports.through
    rows = (through.objects.filter(port__state__in=OPEN_PORT_STATES, port__protocol__in=TCP_PROTOCOLS)
            .order_by().values('ipaddress_id').annotate(n=Count('port_id')).filter(n__gt=keep))
    return {r['ipaddress_id']: r['n'] for r in rows}


def surplus_ids(ip_id, keep=None):
    """The ids of the open TCP ports of address ``ip_id`` beyond its lowest ``keep`` (by port number, then id)."""
    from startScan.models import OPEN_PORT_STATES, TCP_PROTOCOLS, Port
    keep = keep_count() if keep is None else keep
    ordered = (Port.objects.filter(ports__id=ip_id, state__in=OPEN_PORT_STATES, protocol__in=TCP_PROTOCOLS)
               .order_by('number', 'id').values_list('pk', flat=True))
    return list(ordered[keep:])


def trim(apply=False, keep=None):
    """Trim every flooded address. ``apply`` False is a dry run. Returns ``{'addresses': n, 'ports_before': n, 'removed': n}``; idempotent."""
    from startScan.models import Port
    keep = keep_count() if keep is None else keep
    flooded = flooded_ips(keep)
    out = {'addresses': len(flooded), 'ports_before': sum(flooded.values()), 'removed': 0}
    for ip_id, seen in sorted(flooded.items()):
        ids = surplus_ids(ip_id, keep)
        if apply:
            for start in range(0, len(ids), DELETE_BATCH):
                Port.objects.filter(pk__in=ids[start:start + DELETE_BATCH]).delete()
        out['removed'] += len(ids)
        logger.info('port trim: address %s had %s open ports, %s %s', ip_id, seen, 'removed' if apply else 'would remove', len(ids))
    return out
