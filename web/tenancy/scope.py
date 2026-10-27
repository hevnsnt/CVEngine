"""Strict cross-project isolation at the data layer.

Per request, the middleware publishes the set of project ids the user may see.
Default managers of every project-owned model are wrapped so that, while that
set is active, queries are filtered to it. That covers Django views, ORM
lookups by id (``get_object_or_404(ScanHistory, id=...)``) and templates alike,
instead of trusting each view to filter. A DRF filter backend does the same for
viewsets whose class-level querysets were built at import time. Celery and
management commands run with no active scope, so they are unrestricted.
"""
import contextvars

from django.db.models import Q

_allowed = contextvars.ContextVar('tenancy_allowed_projects', default=None)  # None = unrestricted
_user = contextvars.ContextVar('tenancy_current_user', default=None)

# model label -> lookup path to the owning project id; nullable owners listed in NULLABLE
SCOPES = {
    'dashboard.Project': 'id',
    'dashboard.InAppNotification': 'project_id',
    'targetApp.Organization': 'project_id',
    'targetApp.Domain': 'project_id',
    'startScan.ScanHistory': 'domain__project_id',
    'startScan.Subdomain': 'target_domain__project_id',
    'startScan.EndPoint': 'target_domain__project_id',
    'startScan.Vulnerability': 'target_domain__project_id',
    'startScan.MetaFinderDocument': 'target_domain__project_id',
    'startScan.SubScan': 'scan_history__domain__project_id',
    'startScan.ScanActivity': 'scan_of__domain__project_id',
    'startScan.Command': 'scan_history__domain__project_id',
    'recon_note.TodoNote': 'project_id',
    'cveFeed.CVEMatch': 'subdomain__target_domain__project_id',
    'cveFeed.DiscoveryEvent': 'domain__project_id',
    'cveFeed.AgentActivity': 'project_id',
    'cveFeed.TlsCertificate': 'domain__project_id',
    'cveFeed.HygieneFinding': 'domain__project_id',
    'cveFeed.HostState': 'project_id',
    'cveFeed.HostAssessment': 'project_id',
    'cveFeed.AssetChange': 'project_id',
    'cveFeed.RouteAuth': 'project_id',
    'cveFeed.HostLabel': 'project_id',
    'cveFeed.ProbeObservation': 'project_id',
    'cveFeed.SavedSearch': 'project_id',
    'cveFeed.HostProfile': 'project_id',
    'cveFeed.TailscaleLink': 'project_id',
    'cveFeed.TailscaleDevice': 'project_id',
    'cveFeed.HostInventory': 'project_id',
    'cveFeed.HostInventoryReport': 'inventory__project_id',
    'cveFeed.Triage': 'project_id',
    'cveFeed.ReportExport': 'project_id',
    'cveFeed.BountyEngagement': 'project_id',
    'cveFeed.BountyReport': 'project_id',
    'cveFeed.BountyEngagementTarget': 'engagement__project_id',
    'cveFeed.BountyReportEvent': 'report__project_id',
    'agentapi.AgentTask': 'project_id',
}
NULLABLE = {'dashboard.InAppNotification', 'cveFeed.AgentActivity'}  # system-wide entries have no project


def set_scope(allowed_ids, user=None):
    return _allowed.set(allowed_ids), _user.set(user)


def reset_scope(tokens):
    _allowed.reset(tokens[0])
    _user.reset(tokens[1])


def allow(project_id):
    """Add a project to the active request's scope (e.g. one the caller just created)."""
    allowed = _allowed.get()
    if allowed is not None:
        allowed.add(project_id)


def current_user():
    return _user.get()


def current_allowed():
    return _allowed.get()


def scope_filter(label, allowed):
    lookup = SCOPES[label]
    q = Q(**{f'{lookup}__in': list(allowed)})
    return q | Q(**{f'{lookup}__isnull': True}) if label in NULLABLE else q


def scope_queryset(queryset):
    """Apply the active scope to ``queryset`` if its model is project-owned."""
    allowed = _allowed.get()
    label = queryset.model._meta.label
    if allowed is None or label not in SCOPES:
        return queryset
    return queryset.filter(scope_filter(label, allowed))


def install(apps):
    """Wrap each scoped model's default manager (called from the app ready hook)."""
    for label in SCOPES:
        model = apps.get_model(label)
        manager = model._default_manager
        if getattr(manager, '_tenancy_wrapped', False):
            continue
        original = manager.get_queryset

        def scoped(original=original):
            return scope_queryset(original())

        manager.get_queryset = scoped
        manager._tenancy_wrapped = True
