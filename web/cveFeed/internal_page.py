"""The Internal network page: the status of only the internal hosts of the scope the person is looking at.

What an internal host is: the definition of ``cveFeed.internal_view``. A host (a target or a host row) is internal when its name is an
address inside a network its own project declared internal (``cveFeed.models.InternalRange``) that this server may not scan itself
(``targetApp.target_types.sentinel_only_target``). The hosts internal discovery adds are such addresses, so they are internal by the same
rule, and a host added by hand inside a declared range is internal too. A host named by a DNS name is never internal, even when it resolves
to a private address, because this server looks no target name up.

The scope is the one the shell shows: the selected project, or every project of the All projects view (narrowed to one organization when the
switcher chose one). Every number is computed with the functions the Overview uses (``cveFeed.counts``, ``cveFeed.situations``,
``agentapi.services._finding_sources``), restricted to internal hosts, so a number here is never larger than the Overview's and both read
the same rules. ``nav_visible`` decides whether the left rail offers the page at all.
"""
from datetime import timedelta

from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone

ACTIVE = ('queued', 'claimed', 'running')
RECENT_WINDOW = timedelta(hours=24)  # finished internal work shown under the live list
ACTIVITY_ROWS = 30
RECENT_ROWS = 15
FINDING_ROWS = 15


def _covering_internal_sentinels(slugs, org_slugs):
    """Not revoked Sentinels inside a private network (``Agent.network`` is ``internal``, which only this server sets) whose own scope names
    one of ``slugs`` or one of ``org_slugs``, and whose owner belongs to that organization or project (or is an App Admin). An instance-wide
    Sentinel is left out: it belongs to no organization, so it says nothing about this one having an internal network."""
    from agentapi.models import Agent
    from dashboard.models import OrgMembership, ProjectMembership
    named = Q(pk__in=[])
    for slug in slugs:
        named |= Q(scope__projects__contains=[slug])
    for org in org_slugs:
        named |= Q(scope__orgs__contains=[org])
    owner = (Q(token__user__is_superuser=True)
             | Q(Exists(OrgMembership.objects.filter(user=OuterRef('token__user'), org__slug__in=list(org_slugs))))
             | Q(Exists(ProjectMembership.objects.filter(user=OuterRef('token__user'), project__slug__in=list(slugs)))))
    return (Agent.objects.filter(named, owner, kind='scanner', network='internal', token__revoked=False)
            .exclude(status='revoked'))


def nav_visible(projects):
    """Whether the Internal network entry is shown for ``projects``: the rows of the shell's project list in the current scope (``slug`` and
    ``org_slug`` of each; the caller's own visible projects only, read through the tenancy scoped manager). True when one of them declared an
    internal range, or a not revoked Sentinel inside a private network covers one of them or its organization. ONE statement whatever the
    number of projects: two uncorrelated EXISTS over one row of the scoped project list."""
    from cveFeed.models import InternalRange
    from dashboard.models import Project
    slugs = sorted({p['slug'] for p in projects if p.get('slug')})
    if not slugs:
        return False
    orgs = sorted({p['org_slug'] for p in projects if p.get('org_slug')})
    ranges = InternalRange._base_manager.filter(project__slug__in=slugs)
    sentinels = _covering_internal_sentinels(slugs, orgs)
    return Project.objects.filter(slug__in=slugs).filter(Q(Exists(ranges)) | Q(Exists(sentinels))).exists()


def _next_discovery(network, now):
    """When the scheduled sweep next looks at the range (``cveFeed.internal_discovery``): ``{'at', 'state'}``. ``state`` is ``scheduled`` (``at`` is
    the time), ``due`` (it is due and a Sentinel inside is checking in, so the next sweep round takes it) or ``waiting`` (no Sentinel inside is
    checking in, so nothing sweeps it until one does)."""
    from cveFeed import internal_discovery
    if network['sentinel']['state'] != 'online':
        return {'at': None, 'state': 'waiting'}
    last = network['last_discovery_at']
    if last:
        from django.utils.dateparse import parse_datetime
        at = parse_datetime(last) + internal_discovery.cadence()
        if at > now:
            return {'at': at.isoformat(), 'state': 'scheduled'}
    return {'at': None, 'state': 'due'}


def _range_rows(now):
    from cveFeed import internal_view
    rows = []
    for n in internal_view.declared_networks(names=True):
        n['next_discovery'] = _next_discovery(n, now)
        rows.append(n)
    return rows


def _tiles(project, ids):
    """The four numbers at the top, each by the Overview's own rule restricted to internal hosts:

    * internal hosts: ``counts.host_reps`` (alias hosts once, archived left out) that are internal;
    * hosts with open findings: those of them ``counts.exposed_among`` finds exposed (a CVE match not ruled out, or an open finding of medium or worse);
    * critical findings open: actionable findings of critical severity on internal hosts (``_finding_sources``: what the Findings page counts for
      ``severity=critical&internal=1``, and the band the Overview's tile adds up);
    * needs attention: the hosts of the Situations ranking that need a person soon (``overview.host_counts``), internal ones only."""
    from agentapi.services import _finding_sources
    from cveFeed import counts, internal_view, overview, situations
    reps = counts.reps_of(counts.rep_ids()).filter(internal_view.internal_q())
    rep_ids = list(reps.values_list('pk', flat=True))
    hosts = len(rep_ids)
    exposed = counts.exposed_among(counts.reps_of(rep_ids), ids).count() if hosts else 0
    critical = sum(qs.count() for qs in _finding_sources(project, {'internal': '1', 'severity': 'critical'}, counting=True).values())
    high = sum(qs.count() for qs in _finding_sources(project, {'internal': '1', 'severity': 'high'}, counting=True).values())
    groups = [g for g in situations.ranked(list(ids))[0] if g.get('internal')]
    needs = overview.host_counts(groups)['needs']
    return {'hosts': hosts, 'exposed_hosts': exposed, 'critical': critical, 'high': high, 'needs': needs}


def _findings(ctx, slug):
    """The hottest open findings on internal hosts: the Findings list's own answer (``list_findings`` with ``internal=1``), first rows only."""
    from agentapi.services import list_findings
    out = list_findings(ctx, slug, {'internal': '1', 'page_size': str(FINDING_ROWS)})
    keep = ('type', 'kind', 'id', 'title', 'host', 'heat', 'severity', 'status', 'project', 'project_name')
    return {'total': out['total'], 'counts': out['counts'], 'results': [{k: r.get(k) for k in keep if k in r} for r in out['results']]}


def _activity(ids, now):
    """The internal scan work: Sentinel tasks of the scope's projects that sweep an internal range (``discover``), belong to an internal scan
    (``cveFeed.internal_scan``) or name an internal host (OpenVAS and any later kind), still waiting or running, then the last day's finished
    ones. Plus how many internal scans are queued or running."""
    from agentapi.models import SentinelTask
    from cveFeed import counts, internal_scan, internal_view
    from startScan.models import ScanHistory
    tbl = internal_view.table()
    hosts = Q(pk__in=[])
    for pid in ids:
        names = (tbl.get(pid) or {}).get('names')
        if names:
            hosts |= Q(project_id=pid, host__in=sorted(names))
    ranges = Q(project_id__in=[pid for pid in ids if pid in tbl])
    internal = Q(scan__tasks__contains=[internal_scan.TASK_TAG]) | (ranges & Q(kind='discover')) | hosts
    base = SentinelTask.objects.filter(project_id__in=list(ids)).filter(internal)
    fields = ('id', 'kind', 'host', 'status', 'agent__name', 'created_at', 'claimed_at', 'finished_at', 'error', 'project__slug')

    def rows(qs):
        return [{'id': r['id'], 'kind': r['kind'], 'host': r['host'], 'status': r['status'], 'sentinel': r['agent__name'] or '',
                 'created_at': r['created_at'].isoformat() if r['created_at'] else None,
                 'claimed_at': r['claimed_at'].isoformat() if r['claimed_at'] else None,
                 'finished_at': r['finished_at'].isoformat() if r['finished_at'] else None,
                 'error': r['error'], 'project': r['project__slug']} for r in qs.values(*fields)]
    active = rows(base.filter(status__in=ACTIVE).order_by('-id')[:ACTIVITY_ROWS])
    recent = rows(base.exclude(status__in=ACTIVE).filter(finished_at__gte=now - RECENT_WINDOW).order_by('-finished_at', '-id')[:RECENT_ROWS])
    scans = ScanHistory.objects.filter(domain__project_id__in=list(ids), tasks__contains=[internal_scan.TASK_TAG])
    scan_counts = {'running': counts.running_scans(scans).count(), 'queued': counts.queued_scans(scans).count()}
    return {'active': active, 'recent': recent, 'scans': scan_counts}


def payload(ctx, slug):
    """The page's answer for the scope already set on the request (``views.project_scoped``). ``slug``: the project, or ``_all``."""
    from agentapi.services import get_project
    from dashboard.models import Project
    now = timezone.now()
    project, _role = get_project(ctx, slug)
    ids = sorted(Project.objects.values_list('id', flat=True))  # the scope the decorator set
    networks = _range_rows(now)
    has = bool(networks) or nav_visible(list(Project.objects.values('slug', org_slug=F('org__slug'))))
    return {'has': has, 'tiles': _tiles(project, ids), 'networks': networks, 'findings': _findings(ctx, slug), 'activity': _activity(ids, now),
            'updated_at': now.isoformat()}
