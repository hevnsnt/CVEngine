"""Role resolution and access rules for Organization -> Project tenancy.

Pure functions (no DB) so the rules are unit-testable; the DB-facing helpers
import models lazily.
"""
import re

ADMIN, USER, AUDIT, PENTESTER = 'admin', 'user', 'audit', 'pentester'
RANK = {ADMIN: 4, PENTESTER: 3, USER: 2, AUDIT: 1}
SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')

# The reserved project slug of the read-only "All projects" view: a combined list over every project the caller may see.
# No project may ever be created with it (see is_reserved_project), so it can never name a real project.
ALL_PROJECTS = '_all'


def is_reserved_project(*values):
    """True when any of ``values`` (a project name or slug) is the reserved all-projects slug, ignoring case and padding."""
    return any(str(v or '').strip().lower() == ALL_PROJECTS for v in values)

# Settings that only an admin may open or change.
# Instance-wide configuration (AI key, API vault, tools, user management) affects every org,
# so only superusers may open it. Per-project settings below need the admin role.
SUPERUSER_ONLY = re.compile(
    r'^/(admin/|cve/(api/)?(setup|settings|welcome)(/|$)|[^/]+/admin_interface|'
    r'scanEngine/[^/]+/(tool_settings|api_vault|tool_arsenal|ai_settings|llm_toolkit|rengine_settings|'
    r'notification_settings|proxy_settings|report_settings|hackerone_settings|add|delete|update|wordlist|interesting|testHackerone))')
# Per-project settings that need the admin role (none yet: notification, proxy and report
# settings are global singletons in reNgine, so they are instance-wide above).
ADMIN_ONLY = re.compile(r'^/(?!)')
# Bug bounty workflow: the program catalogue and report pages (/cve/bounty, /cve/api/bounty).
# App Admins always have it; any other user only after an App Admin authorized that user (UserProfile.bugbounty_enabled,
# set through /cve/api/admin/users/<id>/bug-bounty, which only an App Admin may call and which is written to the audit log).
# Anchored to the route's own segments: a project slug is free-form, so a project called "hackerone-team" must not look like a route.
BUGBOUNTY = re.compile(r'^/cve/(api/)?bounty(/|$)|^/(?!cve/)[^/]+/bountyhub(/|$)|'
                       r'^/scanEngine/[^/]+/(hackerone_settings|testHackerone)', re.I)
# api/v1 and mcp enforce tenancy in agentapi.services (the project is not always in the URL).
ALWAYS_OPEN = re.compile(r'^/((logout|login|invite|mfa|staticfiles|404)(/|$)|mcp/|api/v1/|cve/account(/|$)|cve/api/account(/|$)|cve/about(/|$)|cve/how-it-works(/|$))')


def best_role(roles):
    roles = [r for r in roles if r]
    return max(roles, key=RANK.get) if roles else None


def resolve_role(project_role, org_role, is_superuser=False):
    """Project-level role overrides the org-level one; superusers are admin everywhere."""
    if is_superuser:
        return ADMIN
    return project_role or org_role


def check_access(role, method, path, bugbounty_enabled=False, is_superuser=False):
    """Return None if allowed, else a short reason string."""
    if ALWAYS_OPEN.match(path):
        return None
    if SUPERUSER_ONLY.match(path) and not is_superuser:
        return 'instance-wide settings are restricted to superusers'
    if role is None:
        return 'no access to this project'
    if role == AUDIT and method not in SAFE_METHODS:
        return 'audit role is read only'
    if ADMIN_ONLY.match(path) and role != ADMIN:
        return 'settings require the admin role'
    if BUGBOUNTY.search(path) and not (is_superuser or bugbounty_enabled):
        return 'bug bounty features are not enabled for this user; an App Admin can authorize you'
    return None


def effective_role(user, project):
    from dashboard.models import OrgMembership, ProjectMembership
    if user.is_superuser:
        return ADMIN
    pm = ProjectMembership.objects.filter(user=user, project=project).values_list('role', flat=True).first()
    om = None
    if project.org_id:
        om = OrgMembership.objects.filter(user=user, org_id=project.org_id).values_list('role', flat=True).first()
    return resolve_role(pm, om)


def allowed_project_ids(user):
    """None = unrestricted (superuser); otherwise the set of project ids the user may see."""
    from dashboard.models import OrgMembership, Project, ProjectMembership
    if user.is_superuser:
        return None
    ids = set(ProjectMembership.objects.filter(user=user).values_list('project_id', flat=True))
    org_ids = list(OrgMembership.objects.filter(user=user).values_list('org_id', flat=True))
    if org_ids:
        ids |= set(Project.objects.filter(org_id__in=org_ids).values_list('id', flat=True))
    return ids


def user_best_role(user):
    from dashboard.models import OrgMembership, ProjectMembership
    if user.is_superuser:
        return ADMIN
    return best_role(
        list(ProjectMembership.objects.filter(user=user).values_list('role', flat=True)) +
        list(OrgMembership.objects.filter(user=user).values_list('role', flat=True)))


GLOBAL_ROLE_FOR = {ADMIN: 'sys_admin', PENTESTER: 'penetration_tester', USER: 'penetration_tester', AUDIT: 'auditor'}


def sync_global_role(user):
    """Keep reNgine's legacy global role equal to the user's highest tenancy role.

    The legacy decorators check that global role; tenancy's per-project rules
    (middleware) then tighten it for the project actually being accessed.
    """
    from rolepermissions.roles import assign_role, clear_roles
    role = user_best_role(user)
    clear_roles(user)
    if role:
        # `sys_admin` carries the instance-wide permissions of the legacy decorators (tools, config, user and
        # engine management). A tenant (org or project) admin must not get them: only superusers do.
        if role == ADMIN and not user.is_superuser:
            role = USER
        assign_role(user, GLOBAL_ROLE_FOR[role])


LEGACY_TO_TENANCY = {'sys_admin': ADMIN, 'penetration_tester': USER, 'auditor': AUDIT}


def grant_from_legacy_role(target_user, legacy_role, org_slug=None):
    """User-management UI hook: turn a legacy global role into an org membership (default org if unspecified)."""
    from dashboard.models import Org, OrgMembership
    role = LEGACY_TO_TENANCY.get(legacy_role)
    org = (Org.objects.filter(slug=org_slug).first() if org_slug else None) or Org.objects.order_by('id').first()
    if not (role and org):
        return
    OrgMembership.objects.update_or_create(user=target_user, org=org, defaults={'role': role})


# ---- who administers what -------------------------------------------------------------
# App Admin  = Django superuser (instance-wide)
# Org Admin  = OrgMembership role "admin"
# Org Member = OrgMembership role "user"      Project Member = ProjectMembership role "user"
# Audit      = role "audit" at either level (read only)
ROLE_LABELS = {
    ('org', 'admin'): 'Org Admin', ('org', 'user'): 'Org Member', ('org', 'pentester'): 'Org Member', ('org', 'audit'): 'Audit (organization)',
    ('project', 'admin'): 'Project Member', ('project', 'user'): 'Project Member', ('project', 'pentester'): 'Project Member',
    ('project', 'audit'): 'Audit (project)',
}
ASSIGNABLE = {'org': ('admin', 'user', 'audit'), 'project': ('user', 'audit')}


def managed_org_ids(user):
    """Org ids the user may administer: all of them for an App Admin, else the orgs where they are Org Admin."""
    from dashboard.models import Org, OrgMembership
    if user.is_superuser:
        return set(Org.objects.values_list('id', flat=True))
    return set(OrgMembership.objects.filter(user=user, role=ADMIN).values_list('org_id', flat=True))


def is_admin_anywhere(user):
    return user.is_superuser or bool(managed_org_ids(user))


def can_manage_org(user, org_id):
    return user.is_superuser or org_id in managed_org_ids(user)


def users_in_orgs(org_ids):
    """Users who belong to any of ``org_ids`` directly or through one of the orgs' projects."""
    from django.contrib.auth.models import User
    from django.db.models import Q
    return User.objects.filter(
        Q(org_memberships__org_id__in=org_ids) | Q(project_memberships__project__org_id__in=org_ids)).distinct()


def can_manage_user(actor, target):
    """App Admins manage everyone; Org Admins manage non-superusers who belong to an org they administer."""
    if actor.is_superuser:
        return True
    if target.is_superuser:
        return False
    return users_in_orgs(managed_org_ids(actor)).filter(pk=target.pk).exists()


def user_org_ids(user):
    """Every org the user belongs to, directly or through a project."""
    from dashboard.models import OrgMembership, ProjectMembership
    return (set(OrgMembership.objects.filter(user=user).values_list('org_id', flat=True)) |
            set(ProjectMembership.objects.filter(user=user).values_list('project__org_id', flat=True)))


def requires_mfa(user):
    """Organization MFA policy also covers members assigned directly to its projects."""
    from dashboard.models import OrgMembership, ProjectMembership
    return (OrgMembership.objects.filter(user=user, org__require_mfa=True).exists()
            or ProjectMembership.objects.filter(user=user, project__org__require_mfa=True).exists())


def can_manage_credentials(actor, target):
    """Password reset, MFA reset and enable/disable change who can sign in as ``target``, which exposes
    EVERY org the target belongs to. So an Org Admin needs to administer all of them, not just one; a user
    who also sits in another tenant has to be handled by an App Admin."""
    if actor.is_superuser:
        return True
    if not can_manage_user(actor, target):
        return False
    if _has_bugbounty(target):
        return False  # bug bounty access is authorized by an App Admin; resetting the sign-in would hand it to whoever resets
    return user_org_ids(target) <= managed_org_ids(actor)


def _has_bugbounty(user):
    profile = getattr(user, 'tenancy_profile', None)
    return bool(profile and profile.bugbounty_enabled)


def can_grant_membership_to(actor, target):
    """Whether ``actor`` may give ``target`` a NEW org/project membership. App Admins can grant to
    anyone. An Org Admin may grant to a brand-new user with no memberships yet (onboarding), or to one
    whose existing memberships are entirely inside orgs the actor already administers - but never to a
    user who already belongs to a DIFFERENT org, even one the actor cannot otherwise manage. Without
    this, an Org Admin of org A could grant themselves a membership over any user in org B (who they
    could not reach any other way) and then reset that user's password/MFA via the now-"managed" user,
    taking over their account - this is the one place a membership is handed out to a user who is not
    already reachable, so it needs its own check rather than reusing can_manage_user."""
    if actor.is_superuser:
        return True
    if target.is_superuser:
        return False
    from dashboard.models import OrgMembership, ProjectMembership
    managed = managed_org_ids(actor)
    existing_org_ids = (set(OrgMembership.objects.filter(user=target).values_list('org_id', flat=True)) |
                        set(ProjectMembership.objects.filter(user=target).values_list('project__org_id', flat=True)))
    if not existing_org_ids:
        # An account in no organization is adoptable only while it is unused (it has never signed in): that is onboarding. One that has
        # signed in and now belongs nowhere (a person removed from another tenant, with their sessions and tokens) is an App Admin's to
        # place; otherwise any Org Admin could take it over by granting a membership and then resetting its password.
        return target.last_login is None and not _has_bugbounty(target)
    return existing_org_ids <= managed
