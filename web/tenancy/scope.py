"""Strict cross-project isolation at the data layer.

Per request, the middleware publishes the set of project ids the user may see.
Default managers of every project-owned model are wrapped so that, while that
set is active, queries are filtered to it. That covers Django views, ORM
lookups by id (``get_object_or_404(ScanHistory, id=...)``) and templates alike,
instead of trusting each view to filter. A DRF filter backend does the same for
viewsets whose class-level querysets were built at import time. Celery and
management commands run with no active scope, so they are unrestricted.
"""
import contextlib
import contextvars

from django.db.models import Q

_allowed = contextvars.ContextVar('tenancy_allowed_projects', default=None)  # None = unrestricted
_user = contextvars.ContextVar('tenancy_current_user', default=None)

# model label -> lookup path to the owning project id; nullable owners listed in NULLABLE
SCOPES = {
    'dashboard.Project': 'id',
    'targetApp.Domain': 'project_id',
    'startScan.ScanHistory': 'domain__project_id',
    'startScan.Subdomain': 'target_domain__project_id',
    'startScan.EndPoint': 'target_domain__project_id',
    'startScan.Vulnerability': 'target_domain__project_id',
    'startScan.MetaFinderDocument': 'target_domain__project_id',
    'startScan.SubScan': 'scan_history__domain__project_id',
    'startScan.ScanActivity': 'scan_of__domain__project_id',
    'cveFeed.CVEMatch': 'subdomain__target_domain__project_id',
    'cveFeed.DiscoveryEvent': 'domain__project_id',
    'cveFeed.AgentActivity': 'project_id',
    'cveFeed.TlsCertificate': 'domain__project_id',
    'cveFeed.ServiceFeature': 'domain__project_id',
    'cveFeed.HygieneFinding': 'domain__project_id',
    'cveFeed.HostState': 'project_id',
    'cveFeed.HostAssessment': 'project_id',
    'cveFeed.AssetChange': 'project_id',
    'cveFeed.RouteAuth': 'project_id',
    'cveFeed.HostLabel': 'project_id',
    'cveFeed.ProbeObservation': 'project_id',
    'cveFeed.JavaRuntime': 'project_id',
    'cveFeed.SavedSearch': 'project_id',
    'cveFeed.HostProfile': 'project_id',
    'cveFeed.TailscaleLink': 'project_id',
    'cveFeed.TailscaleDevice': 'project_id',
    'cveFeed.OpenvasProject': 'project_id',
    'cveFeed.OpenvasRun': 'project_id',
    'cveFeed.Supplier': 'project_id',
    'cveFeed.SupplierFinding': 'supplier__project_id',
    'cveFeed.SupplierHostCard': 'supplier__project_id',
    'cveFeed.HostInventory': 'project_id',
    'cveFeed.HostInventoryReport': 'inventory__project_id',
    'cveFeed.Triage': 'project_id',
    'cveFeed.HostReview': 'project_id',  # the AI's review of one host (cveFeed.host_review), kept with the project it belongs to
    'cveFeed.FindingReview': 'project_id',  # the AI reviewer's verdicts (cveFeed.reviewer), one project's finding each
    'cveFeed.FixRetest': 'project_id',  # one try to re-check a finding marked fixed (cveFeed.fix_retest), kept with the project it belongs to
    'cveFeed.ReportExport': 'project_id',
    'cveFeed.BountyEngagement': 'project_id',
    'cveFeed.BountyReport': 'project_id',
    'cveFeed.BountyEngagementTarget': 'engagement__project_id',
    'cveFeed.BountyReportEvent': 'report__project_id',
    'agentapi.AgentTask': 'project_id',
    'agentapi.SentinelTask': 'project_id',
    'agentapi.StageRun': 'project_id',  # a sweep over every project waits with no project (NULLABLE)
    'agentapi.DnsReading': 'project_id',  # what Sentinels said a project's names resolve to (agentapi.dns_crosscheck)
    'agentapi.SentinelPartial': 'task__project_id',  # a streamed task's batches waiting to be stored, read only by the stage that dispatched it
    'cveFeed.AuthCredential': 'project_id',
    'cveFeed.FindingComment': 'project_id',
    'cveFeed.HostNote': 'project_id',  # an operator's note on one host (agentapi.notes)
    'cveFeed.FindingAuditEvent': 'project_id',
    'cveFeed.HostArchive': 'project_id',
    'cveFeed.HostMove': 'project_id',
    'cveFeed.InternalRange': 'project_id',
    'cveFeed.RdpScreenshot': 'project_id',
    'cveFeed.HostScreenshot': 'project_id',
    'cveFeed.TriageCall': 'project_id',
    'cveFeed.PlannerBatch': 'project_id',  # the work planner's own bookkeeping of the batches it queued (cveFeed.work_planner)
    'cveFeed.AIJob': 'project_id',  # a pipeline model call the AI reviewer container makes (cveFeed.ai_jobs); a CVE-wide one has none
    'cveFeed.DeferredRetest': 'project_id',
    'cveFeed.OnDemandValidation': 'project_id',
    'cveFeed.AutomaticValidation': 'project_id',
    'cveFeed.StatsSnapshot': 'project_id',
    'cveFeed.ProjectSettings': 'project_id',
    'cveFeed.RunZeroSync': 'project_id',
    'cveFeed.SecretFinding': 'project_id',  # the exposed-secrets inventory (cveFeed.secrets_inventory)
    'cveFeed.SecretOccurrence': 'project_id',
    'cveFeed.ResourceRef': 'project_id',
    'dashboard.ApiCredential': 'project_id',  # an organization's own credential has no project (NULLABLE)
}
NULLABLE = {'dashboard.ApiCredential', 'cveFeed.AIJob', 'agentapi.StageRun',
            'cveFeed.ReportExport'}  # system-wide (or organization-wide) entries have no project; an organization report has none and is only ever read by requested_by (report_export._mine)
# cveFeed.AgentActivity is not NULLABLE: an activity line with no project describes the whole instance (how many CVEs were checked against how
# many hosts, worker restarts, the work planner's batches), so only a caller who sees instance-wide data reads it. That is an App Admin in an
# unrestricted view (All projects, an API token): a scope of project ids, even an App Admin's page narrowed to one project
# (cveFeed.views.project_scoped), holds that project's lines only. Keeping the rule a function of the project ids alone keeps every cached
# snapshot keyed by those ids (cveFeed.snapshot_cache.scope_hash) correct.

# Models that hold a foreign key to a project, domain, scan or organization and are deliberately NOT in SCOPES. Every other one must be listed above
# (tests.test_sentinel_hardening checks this), so a model that gains a project owner cannot be forgotten.
UNSCOPED = {
    'dashboard.ProjectMembership': 'the rows the allowed set itself is computed from',
    'dashboard.OrgMembership': 'the rows the allowed set itself is computed from',
    'dashboard.ApiToken': 'owned by a user, not a project; the inventory token only names the project it reports to; authenticated before any scope exists',
    'dashboard.AuditLog': 'organization level trail, read through its own organization filter',
    'startScan.IpAddress': 'per organization, shared by the organization\'s projects',
    'startScan.SubdomainTechnology': 'the table of the host-technology many-to-many link (as unscoped as it was when Django made it): read through a '
                                     'host already in scope, or as a subquery of host ids under the scoped host query',
    'cveFeed.HostExclusion': 'per organization',
    'cveFeed.ExcludedAddress': 'per organization',
    'cveFeed.OpenvasOrg': 'per organization',
    'cveFeed.ServiceRun': 'engine bookkeeping (nmap rows are global), never read for a user',
    'cveFeed.TriageVerdict': 'one answer shared by every finding with the same evidence; project only records where it was reached, so '
                             'triage reuses a closing answer and shows its words only there (task 256), never listed for a user',
    'cveFeed.ReportSubscription': 'a whole-organization report has no project; every read goes through agentapi.report_subscriptions, which filters by the caller\'s organizations and projects',
    'agentapi.SentinelEnrollment': 'organization or instance wide as often as project wide, and redeemed with no user at all',
}


def set_scope(allowed_ids, user=None):
    return _allowed.set(allowed_ids), _user.set(user)


def reset_scope(tokens):
    _allowed.reset(tokens[0])
    _user.reset(tokens[1])


@contextlib.contextmanager
def as_user(user):
    """Run a block under ``user``'s project scope, as a request of theirs would. A worker job made for one person (a report, a saved
    search) runs with no scope; this is the second guard behind the job's own project filters, so a query that forgot its filter still
    reads only the projects that person may see now. An App Admin's scope is unrestricted, as in a request."""
    from tenancy import roles
    tokens = set_scope(roles.allowed_project_ids(user), user)
    try:
        yield
    finally:
        reset_scope(tokens)


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


def _reached_from_scoped_row(manager):
    """True for a related manager (``row.children``) whose row is itself a project-owned model. That row was read through a scoped
    manager, so its children are read as they always were: no extra join or filter on the pages that walk them."""
    instance = getattr(manager, 'instance', None)
    return instance is not None and instance._meta.label in SCOPES


class ScopedManagerMixin:
    """Put before a manager class: its querysets carry the active scope (see ``scoped_manager_class``)."""
    _tenancy_wrapped = True

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset if _reached_from_scoped_row(self) else scope_queryset(queryset)


_scoped_classes = {}


def scoped_manager_class(cls):
    """A subclass of the manager class ``cls`` whose querysets carry the active scope.

    The scope lives on the class, not on one manager object, because Django builds every related manager from the default manager's
    CLASS: the reverse side of a foreign key (``cve_entry.matches``, ``engine.scanhistory_set``, ``agent.tasks``) and both sides of a
    many-to-many (``technology.technologies``, ``address.ip_addresses``). Patching only the ``objects`` object left those unscoped, so a
    row of a global model (a CVE, an engine, a technology, an address) could list another project's rows. Now such a list holds only the
    caller's projects, a ``prefetch_related`` through it included. A related manager whose row is itself project-owned keeps reading as
    before (``_reached_from_scoped_row``). Django's many-to-many ``count()`` and ``exists()`` shortcut (the link table alone) is taken
    only when the manager class is exactly ``Manager``, so such a count into a project-owned model now joins the target table: that is
    what lets the scope apply to it. No page counts one today."""
    made = _scoped_classes.get(cls)
    if made is None:
        made = _scoped_classes[cls] = type(f'Scoped{cls.__name__}', (ScopedManagerMixin, cls), {'__module__': cls.__module__})
    return made


def install(apps):
    """Scope each project-owned model's default manager, and with it every related manager Django derives from it (called from
    the app ready hook)."""
    for label in SCOPES:
        model = apps.get_model(label)
        manager = model._default_manager
        if getattr(manager, '_tenancy_wrapped', False):
            continue
        manager.__class__ = scoped_manager_class(manager.__class__)
