"""What is being scanned right now, for the asset graph's live highlighting and SOC mode.

Read fresh on every poll (a few small queries, never the graph itself): the running scans the caller may see, the step each is
in, and the host names those scans are working on, so the page can pulse the matching bubbles. Run it inside the tenancy scope
(the views wrap it with ``project_scoped``), so it only ever sees the caller's own rows.
"""
from django.utils import timezone

MAX_SCANS = 50
MAX_HOSTS = 2000


def live(project_slug=None, domain_id=None, now=None):
    """``{scans: [{id, domain_id, domain, project, stage, started, elapsed}], domains: [ids], hosts: [lowercase names],
    counts: {running, queued}, at}``. ``stage`` is the scan's step that is running now, or '' between steps."""
    from cveFeed import counts
    from startScan.models import ScanActivity, ScanHistory, Subdomain
    now = now or timezone.now()
    base = ScanHistory.objects.all()
    if project_slug:
        base = base.filter(domain__project__slug=project_slug)
    if domain_id:
        base = base.filter(domain_id=domain_id)
    running = counts.running_scans(base)
    rows = list(running.select_related('domain__project').order_by('-start_scan_date')[:MAX_SCANS])
    ids = [s.id for s in rows]
    stage = {}  # ascending by id, so the newest running step wins
    for scan_id, title, name in ScanActivity.objects.filter(scan_of_id__in=ids, status=1).order_by('id').values_list('scan_of_id', 'title', 'name'):
        stage[scan_id] = (title or name or '')[:120]
    hosts = sorted({n.lower() for n in Subdomain.objects.filter(scan_history_id__in=ids).values_list('name', flat=True)[:MAX_HOSTS]})
    return {
        'scans': [{'id': s.id, 'domain_id': s.domain_id, 'domain': s.domain.name,
                   'project': s.domain.project.slug if s.domain.project_id else '', 'stage': stage.get(s.id, ''),
                   'started': s.start_scan_date.isoformat(), 'elapsed': max(0, int((now - s.start_scan_date).total_seconds()))}
                  for s in rows],
        'domains': sorted({s.domain_id for s in rows}),
        'hosts': hosts,
        'counts': {'running': running.count(), 'queued': counts.queued_scans(base).count()},
        'at': now.isoformat(),
    }
