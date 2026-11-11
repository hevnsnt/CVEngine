"""A daily point-in-time snapshot of each project's inventory and findings counts (cveFeed.models.StatsSnapshot),
written once a day by the ``snapshot_daily_stats`` beat task. Nothing else in the schema keeps a past: every other
number CVEngine shows (cveFeed.counts) is derived live from current rows, so a trend chart (exposure over time,
mean time-to-fix) has nothing to plot without one of these per day."""
from django.db.models import Count
from django.utils import timezone

OPEN_FINDING_BANDS = ('critical', 'high', 'medium', 'low', 'info')
CVE_MATCH_HEATS = ('fire', 'smoke', 'ice')


def _open_findings_and_cve_matches(project):
    """{severity band: count} over every currently-actionable finding (CVE matches not ruled out, open scanner and
    hygiene findings, none of them closed: fixed, accepted_risk or false_positive), and {heat: count} over the CVE matches alone:
    the exact same set agentapi.services.list_findings shows as ``status=actionable``."""
    from cveFeed.threat import HEAT_RANK

    from agentapi.services import SEVERITY_NAMES, _finding_sources
    heat_names = {rank: name for name, rank in HEAT_RANK.items()}
    open_findings = {band: 0 for band in OPEN_FINDING_BANDS}
    cve_matches = {heat: 0 for heat in CVE_MATCH_HEATS}
    for kind, qs in _finding_sources(project, {'status': 'actionable'}).items():
        # the CVE matches are grouped by severity band and heat in ONE pass (they were two passes over the same set, each a CASE over every match)
        for row in qs.values('sev', 'heat_rank').annotate(n=Count('id')) if kind == 'cve' else qs.values('sev').annotate(n=Count('id')):
            band = SEVERITY_NAMES.get(row['sev'])
            if band in open_findings:
                open_findings[band] += row['n']
            if kind == 'cve':
                heat = heat_names.get(row['heat_rank'])
                if heat in cve_matches:
                    cve_matches[heat] += row['n']
    return open_findings, cve_matches


def _fixed_stats(project):
    """(count of findings of any kind currently marked fixed, mean days from first seen to that mark) for one project.
    ``None`` for the mean when there are no fixed findings, or none with both timestamps set."""
    from django.db.models import OuterRef, Subquery

    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability

    # Every scan keeps its own copy of a match, and ``_carry_remediation`` gives each new copy the fixed mark of the earlier one. Counting every
    # copy counted one finding once per retained scan, and measuring each copy's own ``created_at`` against the carried mark gave a negative
    # mean. One finding is one row of the current inventory, first seen when its earliest copy was made (review 1 F1).
    first_seen = Subquery(CVEMatch.objects.filter(
        cve_entry=OuterRef('cve_entry'), subdomain__target_domain=OuterRef('subdomain__target_domain'),
        subdomain__name=OuterRef('subdomain__name')).order_by('created_at').values('created_at')[:1])
    fixed_matches = (CVEMatch.objects.filter(latest_scan_q('subdomain__'), subdomain__target_domain__project=project, remediation_status='fixed')
                     .annotate(first_seen=first_seen))
    rows = []
    for qs, first_field in (
        (fixed_matches, 'first_seen'),
        (Vulnerability.objects.filter(target_domain__project=project, remediation_status='fixed'), 'discovered_date'),
        (HygieneFinding.objects.filter(domain__project=project, remediation_status='fixed'), 'first_seen'),
    ):
        rows += list(qs.values_list(first_field, 'remediation_updated_at'))
    deltas = [(updated - first).total_seconds() / 86400 for first, updated in rows if first and updated]
    return len(rows), (round(sum(deltas) / len(deltas), 2) if deltas else None)


def compute_snapshot(project, date=None, with_fixed=True):
    """One project's snapshot dict for ``date`` (today, in the server's local date, by default): hosts, exposed_hosts,
    open_findings, cve_matches, fixed, mean_days_to_fix. Pure read: callers decide whether and how to store it.
    ``with_fixed=False`` skips the fixed-findings walk (every fixed finding of the project is read to average its age) for a caller
    that only wants the live counts: ``fixed`` is then 0 and ``mean_days_to_fix`` None, so such a dict is never to be stored."""
    from cveFeed import counts
    from targetApp.models import Domain
    domain_ids = list(Domain.objects.filter(project=project).values_list('id', flat=True))
    host_qs = counts.reps_of(counts.rep_ids(domain_ids=domain_ids))  # collapsed once: the host count and the exposed count read the same ids
    hosts = host_qs.count()
    exposed_hosts = counts.exposed_among(host_qs, project_ids=[project.id]).count()
    open_findings, cve_matches = _open_findings_and_cve_matches(project)
    fixed, mean_days_to_fix = _fixed_stats(project) if with_fixed else (0, None)
    return {
        'date': date or timezone.localdate(), 'hosts': hosts, 'exposed_hosts': exposed_hosts,
        'open_findings': open_findings, 'cve_matches': cve_matches, 'fixed': fixed, 'mean_days_to_fix': mean_days_to_fix,
    }


def snapshot_all_projects(date=None):
    """Compute and store today's snapshot for every project, overwriting a prior run the same day (idempotent on retry).
    Returns the number of projects snapshotted."""
    from cveFeed.models import StatsSnapshot
    from dashboard.models import Project
    date = date or timezone.localdate()
    saved = 0
    for project in Project.objects.all():
        data = compute_snapshot(project, date=date)
        StatsSnapshot.objects.update_or_create(
            project=project, date=date, defaults={k: v for k, v in data.items() if k != 'date'})
        saved += 1
    return saved
