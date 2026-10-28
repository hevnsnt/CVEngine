"""Which hosts are internal, for the pages and the live view.

A host is internal when its name is an address inside a network its project declared internal (``cveFeed.models.InternalRange``) that this
server may not scan itself (``targetApp.target_types.sentinel_only_target``): only a Sentinel inside the network scans it. The table of
those addresses is read for every project that declared a range and kept per process, so a list page asks a dictionary, not the database, once per
row. It is dropped when a range is declared or removed and when a host named by an address is added or removed (``connect``), and rebuilt at the
latest after ``CACHE_SECONDS``, so the number of queries a page makes never depends on how long ago it was last asked. Only an address of the caller's own rows is ever looked up, so the table leaks nothing.
"""
import ipaddress
import time

from django.db.models import Q

CACHE_SECONDS = 300
_IP_LITERAL = r'^[0-9a-fA-F:.]+$'
_cache = {'at': None, 'table': {}}  # 'at' is None until built: the monotonic clock starts at boot, so 0 is not "long ago"


def invalidate():
    _cache['at'] = None


def connect():
    """Drop the table whenever what it is built from changes: an internal range, or a host or target whose name is an address."""
    import re

    from django.db.models.signals import post_delete, post_save

    from cveFeed.models import InternalRange
    from startScan.models import Subdomain
    from targetApp.models import Domain
    literal = re.compile(_IP_LITERAL)

    def drop(sender, instance=None, **kwargs):
        if sender is InternalRange or literal.match(str(getattr(instance, 'name', '') or '')):
            invalidate()
    for model in (InternalRange, Domain, Subdomain):
        post_save.connect(drop, sender=model, weak=False, dispatch_uid=f'internal-view-{model.__name__}-save')
        post_delete.connect(drop, sender=model, weak=False, dispatch_uid=f'internal-view-{model.__name__}-delete')


def _load():
    """``{project_id: {'nets': [network...], 'names': {name: cidr}}}`` for every project that declared an internal range."""
    from cveFeed.models import InternalRange
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from targetApp.target_types import in_internal_range, sentinel_only_target
    table = {}
    for project_id, cidr in InternalRange.objects.order_by('project_id', 'cidr').values_list('project_id', 'cidr'):
        table.setdefault(project_id, {'nets': [], 'names': {}})['nets'].append(ipaddress.ip_network(cidr, strict=False))
    for project_id, entry in table.items():
        names = set(Domain.objects.filter(project_id=project_id, name__regex=_IP_LITERAL).values_list('name', flat=True))
        names |= set(Subdomain._base_manager.filter(target_domain__project_id=project_id, name__regex=_IP_LITERAL).values_list('name', flat=True).distinct())
        for name in names:
            if sentinel_only_target(name, project_id, entry['nets']):
                net = next((n for n in entry['nets'] if in_internal_range(name, [n])), None)
                entry['names'][name.strip().lower()] = str(net) if net else ''
    return table


def table():
    now = time.monotonic()
    if _cache['at'] is None or now - _cache['at'] > CACHE_SECONDS:
        _cache.update(at=now, table=_load())
    return _cache['table']


def network_of(project_id, name):
    """The declared network (``10.20.0.0/24``) ``name`` of ``project_id`` is inside, or None when the host is not internal."""
    entry = table().get(project_id)
    if not entry or not name:
        return None
    return entry['names'].get(str(name).strip().lower())


def is_internal(project_id, name):
    return network_of(project_id, name) is not None


def internal_q(prefix='', name_field='name', project_field='target_domain__project_id'):
    """A Q matching rows whose host is internal: ``prefix`` reaches the row from a related model (``'subdomain__'``), ``name_field`` and
    ``project_field`` name the host and its project on it. Matches nothing when no project declared a range."""
    q = Q(pk__in=[])
    for project_id, entry in table().items():
        if entry['names']:
            q |= Q(**{f'{prefix}{project_field}': project_id, f'{prefix}{name_field}__in': sorted(entry['names'])})
    return q


def _sentinel_state(project):
    """``{'state', 'online', 'total', 'last_seen'}`` of the Sentinels inside the project's internal networks: those covering the project
    that declare ``network:internal``. ``online`` (one is live), ``offline`` (some are registered, none live: the network is not being
    scanned, a quiet page there is not a clean one) or ``none``."""
    from django.utils import timezone

    from agentapi import sentinel_broker
    from agentapi.models import Agent
    now = timezone.now()
    agents = [a for a in Agent.objects.filter(sentinel_broker._covers(project.slug, project.org.slug if project.org_id else None), kind='scanner',
                                              token__revoked=False).exclude(status='revoked').select_related('token__user')[:50]
              if sentinel_broker.INTERNAL_CAPABILITY in (a.capabilities or [])]
    live = [a for a in agents if a.status == 'active' and a.last_seen and now - a.last_seen <= sentinel_broker.LIVE_WINDOW]
    seen = max((a.last_seen for a in agents if a.last_seen), default=None)
    return {'state': 'online' if live else ('offline' if agents else 'none'), 'online': len(live), 'total': len(agents),
            'last_seen': seen.isoformat() if seen else None}


def summary():
    """The ``internal`` object of ``/cve/api/stats``: the caller's declared internal networks (each with its host count, last internal scan
    and the state of the Sentinels inside it) and the internal share of the headline numbers. ``has`` is false when no visible project
    declared a network, so the page can leave the group out. The headline totals elsewhere in the payload still include internal hosts;
    these are the subset."""
    from cveFeed import counts
    from cveFeed.models import InternalRange
    from dashboard.models import Project
    from startScan.models import ScanHistory, Vulnerability
    projects = {p.pk: p for p in Project.objects.filter(pk__in=InternalRange.objects.values('project_id')).select_related('org')}
    if not projects:
        return {'has': False, 'networks': [], 'hosts': 0, 'hosts_live': 0, 'findings': 0, 'matches': 0, 'last_scan_at': None, 'sentinels_online': 0}
    tbl = table()
    networks, sentinels, last_overall = [], {}, None
    for rng in InternalRange.objects.filter(project_id__in=projects).order_by('project_id', 'cidr'):
        project = projects[rng.project_id]
        entry = tbl.get(rng.project_id, {'names': {}})
        names = sorted(n for n, cidr in entry['names'].items() if cidr == str(ipaddress.ip_network(rng.cidr, strict=False)))
        last = (ScanHistory.objects.filter(domain__project_id=rng.project_id, domain__name__in=names, tasks__contains=['internal_pipeline'], scan_status=2)
                .order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()) if names else None
        if rng.project_id not in sentinels:
            sentinels[rng.project_id] = _sentinel_state(project)
        if last and (last_overall is None or last > last_overall):
            last_overall = last
        networks.append({'project': project.slug, 'cidr': rng.cidr, 'description': rng.description, 'hosts': len(names),
                         'last_scan_at': last.isoformat() if last else None, 'sentinel': sentinels[rng.project_id],
                         'last_discovery_at': rng.last_discovery_at.isoformat() if rng.last_discovery_at else None,
                         'last_discovery_hosts': rng.last_discovery_hosts, 'last_discovery_error': rng.last_discovery_error})
    reps = counts.host_reps().filter(internal_q())
    return {'has': True, 'networks': networks, 'hosts': reps.count(), 'hosts_live': reps.filter(counts.LIVE_HOST_Q).distinct().count(),
            'findings': counts.actionable_findings(Vulnerability.objects.filter(internal_q('subdomain__'))).count(),
            'matches': counts.exposed_matches().filter(internal_q('subdomain__')).count(),
            'last_scan_at': last_overall.isoformat() if last_overall else None,
            'sentinels_online': sum(1 for s in sentinels.values() if s['state'] == 'online')}


def any_visible():
    """Whether a project the caller can see declared an internal network."""
    from cveFeed.models import InternalRange
    from dashboard.models import Project
    return InternalRange.objects.filter(project__in=Project.objects.all()).exists()
