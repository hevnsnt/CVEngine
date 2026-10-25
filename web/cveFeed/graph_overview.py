"""Bounded drilldown for the asset graph: project, registrable domain, then hosts."""
from django.db.models import Count, Q  # noqa: F401

from cveFeed.counts import LIVE_HOST_Q

from targetApp.target_types import apex_domain

HOST_PAGE = 100


def root_for(domain):
    """Use the bundled Public Suffix List; an explicitly host-scoped tenant stays its own group."""
    return domain.name.lower() if domain.is_host_scoped() else (apex_domain(domain.name) or 'IP assets')


def _domains(project_slug=None):
    from targetApp.models import Domain
    rows = Domain.objects.select_related('project').filter(project__isnull=False)
    if project_slug:
        rows = rows.filter(project__slug=project_slug)
    return list(rows.order_by('project_id', 'id'))


def groups(project_slug=None):
    """Aggregate all visible targets and current inventory rows; never truncate the overview.

    A host is counted once however many targets of its group (or project) hold it, exactly as the Hosts page and the dashboard
    count it: the same name in two targets of one project is one host (see ``cveFeed.counts``). Per-target numbers are summed
    nowhere; every group and project total is a count of distinct names."""
    from cveFeed.correlation import latest_scan_q
    from cveFeed.counts import RULED_OUT
    from startScan.models import Subdomain

    domains = _domains(project_slug)
    if not domains:
        return {'projects': [], 'targets': 0, 'hosts': 0}
    ids = [d.pk for d in domains]
    current = Subdomain.objects.filter(target_domain_id__in=ids).filter(latest_scan_q())

    def names_by_domain(qs, field='name'):
        found = {}
        for domain_id, name in qs.values_list('target_domain_id', field).distinct():
            found.setdefault(domain_id, set()).add(name)
        return found

    hosts_of = names_by_domain(current)
    live_of = names_by_domain(current.filter(LIVE_HOST_Q))
    assessed_of = names_by_domain(current.filter(
        scan_history__scan_status=2,
        scan_history__scanactivity__name__in=('nuclei_scan', 'nuclei_targeted_scan'),
        scan_history__scanactivity__status=2))
    from startScan.models import Vulnerability
    from cveFeed.models import CVEMatch
    finding_pks = Vulnerability.objects.filter(subdomain_id__in=current.values('pk'), open_status=True, severity__gte=1).values('subdomain')
    findings_of = names_by_domain(current.filter(pk__in=finding_pks))
    match_pks = CVEMatch.objects.filter(subdomain_id__in=current.values('pk')).exclude(ai_verdict=RULED_OUT).values('subdomain')
    candidates_of = names_by_domain(current.filter(pk__in=match_pks))

    projects = {}
    for domain in domains:
        project = domain.project
        item = projects.setdefault(project.pk, {'id': project.pk, 'slug': project.slug, 'name': project.name,
                                                'targets': 0, 'hosts': 0, 'roots': {}, '_names': set()})
        root = root_for(domain)
        group = item['roots'].setdefault(root, {'root': root, 'target_ids': [], 'targets': 0,
                                                'hosts': 0, 'live': 0, 'assessed': 0, 'findings': 0, 'cve_candidates': 0,
                                                '_sets': {k: set() for k in ('hosts', 'live', 'assessed', 'findings', 'cve_candidates')}})
        item['targets'] += 1
        group['targets'] += 1
        group['target_ids'].append(domain.pk)
        for key, source in (('hosts', hosts_of), ('live', live_of), ('assessed', assessed_of),
                            ('findings', findings_of), ('cve_candidates', candidates_of)):
            group['_sets'][key] |= source.get(domain.pk, set())
        item['_names'] |= hosts_of.get(domain.pk, set())
    result = []
    for project in projects.values():
        for group in project['roots'].values():
            for key, names in group.pop('_sets').items():
                group[key] = len(names)
        project['hosts'] = len(project.pop('_names'))
        project['roots'] = sorted(project['roots'].values(), key=lambda row: row['root'])
        result.append(project)
    result.sort(key=lambda row: row['name'].lower())
    return {'projects': result, 'targets': len(domains), 'hosts': sum(p['hosts'] for p in result)}


def hosts(project_slug, root, page=1, q=''):
    """One page of host summaries for a root group. IP/service details load only when selected."""
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch, HostState
    from dashboard.models import Project
    from startScan.models import ScanActivity, Subdomain, Vulnerability, open_ports

    project = Project.objects.filter(slug=project_slug).first()
    if not project:
        return None
    domains = [d.pk for d in _domains(project_slug) if root_for(d) == root]
    if not domains:
        return None
    page = min(max(int(page), 1), 100000)
    q = str(q or '').strip()[:100]
    base = Subdomain.objects.filter(target_domain_id__in=domains).filter(latest_scan_q())
    if q:
        base = base.filter(name__icontains=q)
    names = base.order_by().values('name').distinct().count()
    reps = base.order_by('name', '-id').distinct('name').values_list('id', flat=True)
    ids = list(reps[(page-1)*HOST_PAGE:page*HOST_PAGE])
    rows = list(Subdomain.objects.filter(pk__in=ids).select_related('target_domain')
                .prefetch_related('ip_addresses__ports').order_by('name'))
    found = set(Vulnerability.objects.filter(subdomain_id__in=ids, open_status=True, severity__gte=1)
                .values_list('subdomain_id', flat=True))
    matched = set(CVEMatch.objects.filter(subdomain_id__in=ids).exclude(ai_verdict='not_affected')
                  .values_list('subdomain_id', flat=True))
    scanned = set(ScanActivity.objects.filter(scan_of_id__in=[r.scan_history_id for r in rows if r.scan_history_id],
                  name__in=('nuclei_scan', 'nuclei_targeted_scan'), status=2).values_list('scan_of_id', flat=True))
    archived = set(HostState.objects.filter(project=project, host__in=[r.name for r in rows], archived_at__isnull=False)
                   .values_list('host', flat=True))
    return {'project': project.slug, 'root': root, 'count': names, 'page': page, 'page_size': HOST_PAGE,
            'has_more': page * HOST_PAGE < names,
            'results': [{'id': row.pk, 'host': row.name, 'target': row.target_domain.name,
                         'status': 'attention' if row.pk in found or row.pk in matched else
                                   'assessed' if row.scan_history_id in scanned else 'unscanned',
                         'archived': row.name.lower() in archived,
                         'ip_count': len(row.ip_addresses.all()),
                         'service_count': sum(len(open_ports(ip)) for ip in row.ip_addresses.all()),
                         'score': row.score} for row in rows]}
