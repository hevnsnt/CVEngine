"""Technology coverage over the REST API and MCP (cveFeed.tech_coverage): which technology names the hosts carry connect to no CVE record,
which unversioned ones have the most CVEs, and which reach more than one vendor's products.

Read-only. The names are counted across every tenant's hosts (and narrowed to one project on request), so it is an App Admin read: anyone
else gets 403, whatever their role in a project. A read-only token may read it."""
from agentapi.services import ApiError

ADMIN_ONLY = 'technology coverage counts technology names across every tenant: only an App Admin may read it'


def technology_coverage(ctx, params=None):
    from cveFeed import correlation, tech_coverage
    from dashboard.models import Project
    if not (ctx.user.is_authenticated and ctx.user.is_superuser):
        raise ApiError(403, ADMIN_ONLY)
    params = params or {}
    project = None
    slug = params.get('project') or ''
    if slug:
        project = Project.objects.filter(slug=str(slug)).first()
        if project is None:
            raise ApiError(404, 'project not found')
    raw = params.get('limit')
    try:
        limit = int(raw) if raw not in (None, '') else tech_coverage.DEFAULT_LIMIT
    except (TypeError, ValueError, OverflowError):
        raise ApiError(400, 'limit must be an integer')
    cve_by_id, index = correlation.cve_pool()
    report = tech_coverage.report(tech_coverage.sightings_from_db(project), cve_by_id, index, limit)
    return {**report, 'project': project.slug if project else None}
