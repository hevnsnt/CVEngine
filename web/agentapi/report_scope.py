"""What a report is about: one project, or an organization, and who may read or manage reports of it (cveFeed.report_export, docs/REPORTING.md).

A scope is resolved once from the caller's access and carries the projects the report reads, so every query below it filters by those project ids
explicitly. That matters in a worker, which has no request scope: ``for_worker`` resolves the scope again from the user's access at that moment.

An organization scope holds the organization's projects the caller can read (the rule of ``host_export``): an Org Member or an App Admin gets all of
them, a person added to some projects only gets those, and ``whole`` says which. Nothing here reads a scan result or contacts a host.
"""
from dataclasses import dataclass, field

from agentapi import services as svc
from agentapi.services import ApiError
from tenancy import roles

WRITE_ROLES = (roles.ADMIN, roles.PENTESTER, roles.USER)  # the roles that may create or change things in a project; audit never
ATTACH_MAX_MB_DEFAULT, ATTACH_MAX_MB_CEILING = 10, 25


def attach_max_mb():
    """The largest file an email report attaches, in MB (``CVENGINE_REPORT_EMAIL_MAX_MB``, 1 to 25): a bigger one is replaced by a link."""
    import os
    try:
        return min(ATTACH_MAX_MB_CEILING, max(1, int(os.environ.get('CVENGINE_REPORT_EMAIL_MAX_MB', ''))))
    except ValueError:
        return ATTACH_MAX_MB_DEFAULT


def limits():
    """What an email report may hold (the Email tab of the Reporting page)."""
    from cveFeed.models import ReportSubscription as R
    return {'recipients': R.MAX_RECIPIENTS, 'per_scope': R.MAX_PER_SCOPE, 'attach_max_mb': attach_max_mb()}


@dataclass
class ReportScope:
    kind: str  # 'project' | 'org'
    project: object = None
    org: object = None
    projects: list = field(default_factory=list)  # the projects the report reads
    whole: bool = True  # an organization scope: every project of the organization (False when the caller can read only some)

    @property
    def ids(self):
        return [p.pk for p in self.projects]

    @property
    def label(self):
        return self.project.name if self.kind == 'project' else self.org.name

    @property
    def slug(self):
        return self.project.slug if self.kind == 'project' else self.org.slug

    def svc_scope(self):
        """What ``svc._finding_sources`` and ``svc._scoped`` accept: the Project, or ``AllProjects`` over the scope's ids for an organization."""
        return self.project if self.kind == 'project' else svc.AllProjects(self.ids)


def org_projects(user, org):
    """The projects of ``org`` that ``user`` may read, by slug. An App Admin reads every one."""
    from dashboard.models import Project
    allowed = roles.allowed_project_ids(user)  # None: an App Admin, every project
    qs = Project.objects.filter(org=org).select_related('org').order_by('slug')
    if allowed is not None:
        qs = qs.filter(id__in=sorted(allowed))
    return list(qs)


def resolve(ctx, project=None, org=None):
    """The scope named by exactly one of ``project`` (a slug) and ``org`` (a slug), read access: 400 for both or neither (and for ``_all``), 404 for a
    project or organization that is missing or not the caller's (the same answer for both)."""
    from dashboard.models import Org, Project
    if bool(project) == bool(org):
        raise ApiError(400, 'give a project or an organization, not both')
    if project:
        found, _ = svc.get_one_project(ctx, project)  # _all is a 400: a report names its project or its organization
        return ReportScope('project', project=found, projects=[found])
    found = Org.objects.filter(slug=str(org)).first()
    if found is None or not svc._visible_org(ctx.user, found):
        raise ApiError(404, 'organization not found')
    mine = org_projects(ctx.user, found)
    total = Project._base_manager.filter(org=found).count()
    return ReportScope('org', org=found, projects=mine, whole=len(mine) == total)


def _org_role(user, org_id):
    from dashboard.models import OrgMembership
    return OrgMembership.objects.filter(user=user, org_id=org_id).values_list('role', flat=True).first()


def can_view_subscriptions(user, scope):
    """May ``user`` see the email reports of ``scope``? A project: any role in it. An organization: an App Admin, or anyone with an organization role
    (a person added to some of its projects only cannot read the whole organization, so they cannot read its email reports either)."""
    if user.is_superuser:
        return True
    if scope.kind == 'project':
        return bool(roles.effective_role(user, scope.project))
    return _org_role(user, scope.org.pk) is not None


def can_manage(user, scope, token=None):
    """May ``user`` create, change or delete the email reports of ``scope``? A project: a write role. An organization: an App Admin or an Org Admin.
    A read-only API token never may."""
    if token is not None and getattr(token, 'read_only', False):
        return False
    if user.is_superuser:
        return True
    if scope.kind == 'project':
        return roles.effective_role(user, scope.project) in WRITE_ROLES
    return _org_role(user, scope.org.pk) == roles.ADMIN


def list_scopes(ctx):
    """The picker of the Reporting page: every organization and project the caller can report on, with what they may do with email reports there."""
    from cveFeed import mailer
    from dashboard.models import Org, OrgMembership, Project, ProjectMembership
    user = ctx.user
    allowed = roles.allowed_project_ids(user)  # None: an App Admin, every project; filtered here, not by the request scope, so a worker reads the same
    everything = Project._base_manager.select_related('org').order_by('name', 'slug')
    projects = list(everything if allowed is None else everything.filter(id__in=sorted(allowed)))
    visible = {p.pk for p in projects}
    project_roles = dict(ProjectMembership.objects.filter(user=user, project_id__in=visible).values_list('project_id', 'role'))
    org_roles = dict(OrgMembership.objects.filter(user=user).values_list('org_id', 'role'))
    org_ids = {p.org_id for p in projects if p.org_id} | set(org_roles)
    orgs = [o for o in Org.objects.filter(pk__in=org_ids).order_by('name', 'slug') if svc._visible_org(user, o)]
    totals = {}
    for org_id in Project._base_manager.filter(org_id__in=[o.pk for o in orgs]).values_list('org_id', flat=True):
        totals[org_id] = totals.get(org_id, 0) + 1
    mine = {}
    for p in projects:
        if p.org_id:
            mine[p.org_id] = mine.get(p.org_id, 0) + 1
    out = []
    for o in orgs:
        scope = ReportScope('org', org=o)
        out.append({'kind': 'org', 'slug': o.slug, 'name': o.name, 'projects': mine.get(o.pk, 0), 'whole': mine.get(o.pk, 0) == totals.get(o.pk, 0),
                    'can_subscribe': can_manage(user, scope, ctx.token), 'can_view_subscriptions': can_view_subscriptions(user, scope)})
    for p in projects:
        role = roles.resolve_role(project_roles.get(p.pk), org_roles.get(p.org_id) if p.org_id else None, user.is_superuser)
        scope = ReportScope('project', project=p, projects=[p])
        out.append({'kind': 'project', 'slug': p.slug, 'name': p.name, 'org': p.org.slug if p.org_id else '', 'org_name': p.org.name if p.org_id else '',
                    'role': role or '', 'can_subscribe': can_manage(user, scope, ctx.token), 'can_view_subscriptions': can_view_subscriptions(user, scope)})
    return {'scopes': out, 'me_email': user.email or '', 'mail_ready': mailer.ready(), 'limits': limits()}


def for_worker(user, kind, project_id=None, org_id=None):
    """The scope of a queued report as ``user`` can read it now, or None when they no longer can (a membership removed since they asked)."""
    from dashboard.models import Org, Project
    from agentapi.services import Ctx
    ctx = Ctx(user=user)
    try:
        if kind == 'project':
            slug = Project._base_manager.filter(pk=project_id).values_list('slug', flat=True).first()
            return resolve(ctx, project=slug or '-') if slug else None
        slug = Org._base_manager.filter(pk=org_id).values_list('slug', flat=True).first()
        return resolve(ctx, org=slug) if slug else None
    except ApiError:
        return None
