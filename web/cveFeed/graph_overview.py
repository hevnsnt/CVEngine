"""Bounded drilldown for the asset graph: project, registrable domain, then hosts."""
from django.db.models import Count, Q

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
    """Aggregate all visible targets and current inventory rows in SQL; never truncate the overview."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain

    domains = _domains(project_slug)
    if not domains:
        return {'projects': [], 'targets': 0, 'hosts': 0}
    ids = [d.pk for d in domains]
    current = Subdomain.objects.filter(target_domain_id__in=ids).filter(latest_scan_q())
    counts = {row['target_domain_id']: row for row in current.values('target_domain_id').annotate(
        hosts=Count('name', distinct=True),
        resolved=Count('name', filter=Q(ip_addresses__isnull=False), distinct=True))}
    assessed = {row['target_domain_id']: row['count'] for row in current.filter(
        scan_history__scan_status=2,
        scan_history__scanactivity__name__in=('nuclei_scan', 'nuclei_targeted_scan'),
        scan_history__scanactivity__status=2).values('target_domain_id').annotate(count=Count('name', distinct=True))}
    from startScan.models import Vulnerability
    from cveFeed.models import CVEMatch
    findings = {row['subdomain__target_domain_id']: row['count'] for row in Vulnerability.objects.filter(
        subdomain_id__in=current.values('pk'), open_status=True, severity__gte=1
    ).values('subdomain__target_domain_id').annotate(count=Count('subdomain__name', distinct=True))}
    candidates = {row['subdomain__target_domain_id']: row['count'] for row in CVEMatch.objects.filter(
        subdomain_id__in=current.values('pk')).exclude(ai_verdict='not_affected').values(
        'subdomain__target_domain_id').annotate(count=Count('subdomain__name', distinct=True))}
    projects = {}
    for domain in domains:
        project = domain.project
        item = projects.setdefault(project.pk, {'id': project.pk, 'slug': project.slug, 'name': project.name,
                                                'targets': 0, 'hosts': 0, 'roots': {}})
        root = root_for(domain)
        group = item['roots'].setdefault(root, {'root': root, 'target_ids': [], 'targets': 0,
                                                'hosts': 0, 'resolved': 0, 'assessed': 0,
                                                'findings': 0, 'cve_candidates': 0})
        summary = dict(counts.get(domain.pk, {}))
        summary.update(assessed=assessed.get(domain.pk, 0), findings=findings.get(domain.pk, 0),
                       cve_candidates=candidates.get(domain.pk, 0))
        item['targets'] += 1
        group['targets'] += 1
        group['target_ids'].append(domain.pk)
        for name in ('hosts', 'resolved', 'assessed', 'findings', 'cve_candidates'):
            group[name] += summary.get(name, 0)
        item['hosts'] += summary.get('hosts', 0)
    result = []
    for project in projects.values():
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
