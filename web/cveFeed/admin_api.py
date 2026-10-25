"""Administration API behind /cve/admin/ (session + CSRF, never part of the agent API).

Who may do what:
  App Admin (superuser)  anything: any account, create/rename/delete organizations and projects, timings.
  Org Admin              accounts that belong to their organizations (create, reset password, reset MFA, enable or
                         disable), memberships in their org or its projects, MFA status, create/delete their projects.
  everyone else          403.
Every handler checks the specific org it touches, so an Org Admin of A can never reach B.
"""
import json
import re
import secrets

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.utils.text import slugify

from dashboard.models import (ApiCredential, AuditLog, Org, OrgMembership, Project, ProjectMembership, SystemTimings,
                              UserProfile)
from tenancy import roles


class AdminError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _body(request):
    try:
        data = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        raise AdminError(400, 'body must be valid JSON')
    return data if isinstance(data, dict) else {}


def audit(actor, action, target='', org=None, **detail):
    AuditLog.objects.create(actor=actor, actor_name=actor.username, action=action, target=target[:300],
                            org_id=getattr(org, 'pk', org), detail=detail)


def temp_password():
    return secrets.token_urlsafe(12)


def _need_org(actor, org_id):
    org = Org.objects.filter(pk=org_id).first() if str(org_id).isdigit() else None
    if not org or not roles.can_manage_org(actor, org.pk):
        raise AdminError(404, 'organization not found')  # same answer whether it is missing or not yours
    return org


def _need_user(actor, user_id, credentials=False):
    user = User.objects.filter(pk=user_id).first() if str(user_id).isdigit() else None
    if not user or not roles.can_manage_user(actor, user):
        raise AdminError(404, 'user not found')
    if credentials and not roles.can_manage_credentials(actor, user):
        raise AdminError(403, 'this user also belongs to an organization you do not administer; ask an App Admin')
    return user


def _revoke_tokens(user):
    """A password or MFA reset must also cut off bearer tokens, which otherwise keep working."""
    from dashboard.models import ApiToken
    ApiToken.objects.filter(user=user, revoked=False).update(revoked=True)


def _profile(user):
    return UserProfile.objects.get_or_create(user=user)[0]


# --- serialisation ----------------------------------------------------------------------

def user_dict(actor, u):
    managed = roles.managed_org_ids(actor)
    memberships = []
    for m in OrgMembership.objects.filter(user=u).select_related('org'):
        if actor.is_superuser or m.org_id in managed:
            memberships.append({'kind': 'org', 'id': m.id, 'scope_id': m.org_id, 'scope_name': m.org.name, 'role': m.role,
                                'label': roles.ROLE_LABELS.get(('org', m.role), m.role)})
    for m in ProjectMembership.objects.filter(user=u).select_related('project__org'):
        if actor.is_superuser or m.project.org_id in managed:
            memberships.append({'kind': 'project', 'id': m.id, 'scope_id': m.project_id,
                                'scope_name': f'{m.project.name}' + (f' ({m.project.org.name})' if m.project.org else ''),
                                'role': m.role, 'label': roles.ROLE_LABELS.get(('project', m.role), m.role)})
    p = UserProfile.objects.filter(user=u).first()
    return {'id': u.id, 'username': u.username, 'first_name': u.first_name, 'last_name': u.last_name,
            'name': u.get_full_name() or u.username, 'email': u.email, 'is_active': u.is_active, 'is_superuser': u.is_superuser,
            'last_login': u.last_login.isoformat() if u.last_login else None, 'date_joined': u.date_joined.isoformat(),
            'mfa_enabled': bool(p and p.mfa_enabled), 'bugbounty_enabled': bool(p and p.bugbounty_enabled),
            'must_change_password': bool(p and p.must_change_password), 'memberships': memberships,
            'role_label': 'App Admin' if u.is_superuser else (memberships[0]['label'] if memberships else 'No access')}


def org_dict(o):
    return {'id': o.id, 'name': o.name, 'slug': o.slug, 'require_mfa': o.require_mfa,
            'projects': [{'id': p.id, 'name': p.name, 'slug': p.slug} for p in o.projects.order_by('name')],
            'members': OrgMembership.objects.filter(org=o).count(), 'admins': OrgMembership.objects.filter(org=o, role='admin').count()}


# --- users ------------------------------------------------------------------------------

def users_list(request, actor):
    qs = User.objects.all() if actor.is_superuser else roles.users_in_orgs(roles.managed_org_ids(actor))
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(username__icontains=q) | qs.filter(email__icontains=q) | qs.filter(first_name__icontains=q) | qs.filter(last_name__icontains=q)
    users = list(qs.distinct().order_by('username')[:500])
    return {'results': [user_dict(actor, u) for u in users], 'actor': {'is_superuser': actor.is_superuser, 'id': actor.id}}


def _membership_target(actor, scope, scope_id, role):
    if scope not in roles.ASSIGNABLE or role not in roles.ASSIGNABLE[scope]:
        raise AdminError(400, f'role must be one of {", ".join(roles.ASSIGNABLE.get(scope, ()))} for a {scope}')
    if scope == 'org':
        org = _need_org(actor, scope_id)
        return org, org
    project = Project.objects.filter(pk=scope_id).select_related('org').first() if str(scope_id).isdigit() else None
    if not project or not project.org_id or not roles.can_manage_org(actor, project.org_id):
        raise AdminError(404, 'project not found')
    return project, project.org


def _grant(scope, target, user, role):
    if scope == 'org':
        OrgMembership.objects.update_or_create(user=user, org=target, defaults={'role': role})
    else:
        ProjectMembership.objects.update_or_create(user=user, project=target, defaults={'role': role})


@transaction.atomic
def users_create(request, actor):
    data = _body(request)
    username = str(data.get('username', '')).strip()
    if not re.fullmatch(r'[\w.@+-]{3,150}', username):
        raise AdminError(400, 'username must be 3 or more letters, digits or . @ + - _')
    if User.objects.filter(username__iexact=username).exists():
        raise AdminError(409, 'that username is taken')
    scope, role = data.get('scope', 'org'), data.get('role', 'user')
    target, org = _membership_target(actor, scope, data.get('scope_id'), role)
    password = str(data.get('password') or '').strip() or temp_password()
    try:
        validate_password(password)
    except ValidationError as exc:
        raise AdminError(400, ' '.join(exc.messages))
    user = User.objects.create_user(username=username, password=password, email=str(data.get('email', '')).strip()[:254],
                                    first_name=str(data.get('first_name', '')).strip()[:150],
                                    last_name=str(data.get('last_name', '')).strip()[:150])
    _grant(scope, target, user, role)
    profile = _profile(user)
    profile.must_change_password, profile.onboarded = True, True  # only the app admin goes through the setup wizard
    profile.save(update_fields=['must_change_password', 'onboarded'])
    audit(actor, 'user.create', username, org=org, scope=scope, role=role)
    return {**user_dict(actor, user), 'temporary_password': password}, 201


def users_update(request, actor, user_id):
    data = _body(request)
    user = _need_user(actor, user_id, credentials='is_active' in data)
    if 'is_active' in data:
        if user.pk == actor.pk and not data['is_active']:
            raise AdminError(409, 'you cannot disable your own account')
        user.is_active = bool(data['is_active'])
    for field, limit in (('first_name', 150), ('last_name', 150), ('email', 254)):
        if field in data:
            setattr(user, field, str(data[field]).strip()[:limit])
    user.save()
    audit(actor, 'user.update', user.username, fields=sorted(data))
    return user_dict(actor, user)


def users_reset_password(request, actor, user_id):
    user = _need_user(actor, user_id, credentials=True)
    password = temp_password()
    user.set_password(password)  # also invalidates the user's existing sessions
    user.save()
    profile = _profile(user)
    profile.must_change_password = True
    profile.save(update_fields=['must_change_password'])
    _revoke_tokens(user)
    audit(actor, 'user.reset_password', user.username)
    return {'username': user.username, 'temporary_password': password}


def users_reset_mfa(request, actor, user_id):
    user = _need_user(actor, user_id, credentials=True)
    profile = _profile(user)
    profile.mfa_enabled, profile.mfa_secret, profile.recovery_codes, profile.mfa_last_step = False, '', [], 0
    profile.save()
    _revoke_tokens(user)
    audit(actor, 'user.reset_mfa', user.username)
    return user_dict(actor, user)


def users_delete(request, actor, user_id):
    if not actor.is_superuser:
        raise AdminError(403, 'only an App Admin can delete accounts; remove the user from your organization instead')
    user = User.objects.filter(pk=user_id).first() if str(user_id).isdigit() else None
    if not user:
        raise AdminError(404, 'user not found')
    if user.pk == actor.pk:
        raise AdminError(409, 'you cannot delete your own account')
    if user.is_superuser and User.objects.filter(is_superuser=True, is_active=True).count() <= 1:
        raise AdminError(409, 'this is the last App Admin')
    name = user.username
    user.delete()
    audit(actor, 'user.delete', name)
    return {'deleted': True}


# --- memberships ----------------------------------------------------------------------------

def memberships_set(request, actor):
    data = _body(request)
    user = User.objects.filter(pk=data['user_id']).first() if str(data.get('user_id', '')).isdigit() else \
        User.objects.filter(username__iexact=str(data.get('username', '')).strip()).first()
    if not user or user.is_superuser or not roles.can_grant_membership_to(actor, user):
        # same 404 whether the user does not exist or is simply out of reach: no existence oracle
        raise AdminError(404, 'user not found')
    scope, role = data.get('scope'), data.get('role')
    target, org = _membership_target(actor, scope, data.get('scope_id'), role)
    if scope == 'org' and user.pk == actor.pk and not actor.is_superuser and role != 'admin':
        raise AdminError(409, 'you cannot lower your own Org Admin role')
    _grant(scope, target, user, role)
    audit(actor, 'membership.set', f'{user.username} -> {target}', org=org, scope=scope, role=role)
    return user_dict(actor, user)


def memberships_delete(request, actor, scope, membership_id):
    model = {'org': OrgMembership, 'project': ProjectMembership}.get(scope)
    m = model.objects.filter(pk=membership_id).select_related('user').first() if model and str(membership_id).isdigit() else None
    org = (m.org if scope == 'org' else m.project.org) if m else None
    if not m or not org or not roles.can_manage_org(actor, org.pk):
        raise AdminError(404, 'membership not found')
    if scope == 'org' and m.user_id == actor.pk and not actor.is_superuser:
        raise AdminError(409, 'you cannot remove your own Org Admin membership')
    who = m.user.username
    m.delete()
    audit(actor, 'membership.remove', who, org=org, scope=scope)
    return {'deleted': True}


# --- organizations ------------------------------------------------------------------------------

def orgs_list(request, actor):
    qs = Org.objects.filter(pk__in=roles.managed_org_ids(actor)).order_by('name')
    return {'results': [org_dict(o) for o in qs]}


def _unique_slug(model, name, fallback):
    base = slugify(name)[:50] or fallback
    slug, n = base, 2
    while model._base_manager.filter(slug=slug).exists():  # unscoped, so a hidden project's slug still counts
        slug, n = f'{base}-{n}', n + 1
    return slug


def orgs_create(request, actor):
    if not actor.is_superuser:
        raise AdminError(403, 'only an App Admin can create organizations')
    name = str(_body(request).get('name', '')).strip()[:100]
    if len(name) < 2:
        raise AdminError(400, 'give the organization a name')
    org = Org.objects.create(name=name, slug=_unique_slug(Org, name, 'org'))
    audit(actor, 'org.create', name, org=org)
    return org_dict(org), 201


def orgs_update(request, actor, org_id):
    org = _need_org(actor, org_id)
    data = _body(request)
    if 'name' in data:
        name = str(data['name']).strip()[:100]
        if len(name) < 2:
            raise AdminError(400, 'give the organization a name')
        org.name = name
    if 'require_mfa' in data:
        org.require_mfa = bool(data['require_mfa'])
    org.save()
    audit(actor, 'org.update', org.name, org=org, fields=sorted(data))
    return org_dict(org)


def org_api_credentials_list(request, actor, org_id):
    """What services are configured for this organization, never the secrets themselves."""
    from cveFeed.api_credentials import SERVICES, credential_summary, used_in_scans
    org = _need_org(actor, org_id)
    rows = {c.service: c for c in ApiCredential.objects.filter(org=org)}
    return {'results': [
        {'service': service, 'label': label, 'fields': [{'name': n, 'label': d, 'secret': s} for n, d, s in fields],
         'configured': service in rows, 'used_in_scans': used_in_scans(service), 'set': credential_summary(rows[service]) if service in rows else {}}
        for service, (label, fields, _) in SERVICES.items()]}


def org_api_credential_set(request, actor, org_id, service):
    """Save (or update) this organization's key for ``service``. A blank field keeps what was stored."""
    from cveFeed.api_credentials import SERVICES
    org = _need_org(actor, org_id)
    if service not in SERVICES:
        raise AdminError(404, f'unknown service {service!r}')
    data = _body(request)
    _, fields, _ = SERVICES[service]
    cred = ApiCredential.objects.filter(org=org, service=service).first() or ApiCredential(org=org, service=service)
    value = dict(cred.value or {})
    for name, _label, _secret in fields:
        if data.get(name) and str(data[name]).strip():
            value[name] = str(data[name]).strip()[:500]
    if not value:  # never store an empty row: it would show as configured while feeding nothing to bbot
        raise AdminError(400, 'enter a value to save')
    cred.value = value
    cred.save()
    audit(actor, 'org.api_key.set', service, org=org)
    return {'service': service}


def org_api_credential_delete(request, actor, org_id, service):
    org = _need_org(actor, org_id)
    ApiCredential.objects.filter(org=org, service=service).delete()
    audit(actor, 'org.api_key.remove', service, org=org)
    return {'deleted': True}


@transaction.atomic
def orgs_delete(request, actor, org_id):
    if not actor.is_superuser:
        raise AdminError(403, 'only an App Admin can delete organizations')
    org = Org.objects.filter(pk=org_id).first() if str(org_id).isdigit() else None
    if not org:
        raise AdminError(404, 'organization not found')
    data = _body(request)
    if data.get('confirm') != org.name:
        raise AdminError(400, 'type the organization name to confirm')
    projects = list(org.projects.all())
    if projects and not data.get('delete_projects'):
        raise AdminError(409, f'it still has {len(projects)} project(s); delete them too to continue')
    name = org.name
    for project in projects:
        project.delete()
    org.delete()
    audit(actor, 'org.delete', name, projects=len(projects))
    return {'deleted': True, 'projects_deleted': len(projects)}


# --- projects ------------------------------------------------------------------------------------

def projects_list(request, actor):
    qs = Project.objects.filter(org_id__in=roles.managed_org_ids(actor)).select_related('org').order_by('org__name', 'name')
    return {'results': [{'id': p.id, 'name': p.name, 'slug': p.slug, 'org_id': p.org_id, 'org_name': p.org.name} for p in qs]}


def projects_create(request, actor):
    data = _body(request)
    org = _need_org(actor, data.get('org_id'))
    name = str(data.get('name', '')).strip()[:100]
    if len(name) < 2:
        raise AdminError(400, 'give the project a name')
    if roles.is_reserved_project(name):
        raise AdminError(400, f'"{roles.ALL_PROJECTS}" is reserved for the all-projects view; choose another name')
    project = Project.objects.create(name=name, slug=_unique_slug(Project, name, 'project'), insert_date=timezone.now(), org=org)
    audit(actor, 'project.create', name, org=org)
    return {'id': project.id, 'name': project.name, 'slug': project.slug, 'org_id': org.id, 'org_name': org.name}, 201


@transaction.atomic
def projects_delete(request, actor, project_id):
    project = Project.objects.filter(pk=project_id).select_related('org').first() if str(project_id).isdigit() else None
    if not project or not project.org_id or not roles.can_manage_org(actor, project.org_id):
        raise AdminError(404, 'project not found')
    if _body(request).get('confirm') != project.name:
        raise AdminError(400, 'type the project name to confirm')
    name, org = project.name, project.org
    project.delete()  # cascades to its targets, scans and findings
    audit(actor, 'project.delete', name, org=org)
    return {'deleted': True}


# --- timings (App Admin) --------------------------------------------------------------------------

TIMING_LIMITS = {'cve_sync_minutes': (5, 1440), 'hygiene_hour_utc': (0, 23), 'ct_watch_minutes': (5, 1440),
                 'discovery_timeout_hours': (1, 48), 'nuclei_timeout_hours': (1, 24)}


def timings_get(request, actor):
    t = SystemTimings.current()
    return {**{k: getattr(t, k) for k in TIMING_LIMITS}, 'limits': TIMING_LIMITS}


def apply_timings(t):
    """Push the schedule-related timings into celery beat."""
    from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask
    interval, _ = IntervalSchedule.objects.get_or_create(every=t.cve_sync_minutes, period='minutes')
    PeriodicTask.objects.filter(name='cvengine-cve-sync').update(interval=interval)
    crontab, _ = CrontabSchedule.objects.get_or_create(minute='17', hour=str(t.hygiene_hour_utc), day_of_week='*',
                                                       day_of_month='*', month_of_year='*')
    PeriodicTask.objects.filter(name='cvengine-hygiene-daily').update(crontab=crontab)
    ct_interval, _ = IntervalSchedule.objects.get_or_create(every=t.ct_watch_minutes, period='minutes')
    PeriodicTask.objects.filter(name='cvengine-ct-watch').update(interval=ct_interval)


def timings_put(request, actor):
    if not actor.is_superuser:
        raise AdminError(403, 'only an App Admin can change timings')
    data = _body(request)
    t = SystemTimings.objects.first() or SystemTimings()
    for key, (low, high) in TIMING_LIMITS.items():
        if key in data:
            try:
                value = int(data[key])
            except (TypeError, ValueError):
                raise AdminError(400, f'{key} must be a number')
            if not low <= value <= high:
                raise AdminError(400, f'{key} must be between {low} and {high}')
            setattr(t, key, value)
    t.save()
    apply_timings(t)
    audit(actor, 'timings.update', '', **{k: getattr(t, k) for k in TIMING_LIMITS})
    return timings_get(request, actor)


def audit_list(request, actor):
    qs = AuditLog.objects.all() if actor.is_superuser else AuditLog.objects.filter(org_id__in=roles.managed_org_ids(actor))
    return {'results': [{'id': a.id, 'actor': a.actor_name, 'action': a.action, 'target': a.target, 'detail': a.detail,
                         'at': a.created_at.isoformat()} for a in qs[:200]]}


def _safe_activity_text(value):
    """Keep a useful short line while suppressing common credential shapes in older activity."""
    value = str(value or '')[:500]
    value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+', 'Bearer [redacted]', value)
    value = re.sub(r'(?i)\b(authorization|api[_-]?key|token|password|secret)\b\s*[:=]\s*[^\s,;]+',
                   r'\1=[redacted]', value)
    value = re.sub(r'(?i)\bsk-ant-[A-Za-z0-9_-]+', '[redacted]', value)
    return value


def activity_list(request, actor):
    """A bounded page of retained activity. Org admins see only their organizations; raw detail is never returned."""
    from django.db.models import Q
    from django.utils.dateparse import parse_datetime
    from cveFeed.models import AgentActivity

    params = request.GET
    try:
        page = int(params.get('page', 1))
        page_size = int(params.get('page_size', 100))
    except (TypeError, ValueError):
        raise AdminError(400, 'page and page_size must be integers')
    if page < 1 or not 1 <= page_size <= 200:
        raise AdminError(400, 'page must be positive and page_size must be from 1 to 200')
    qs = AgentActivity.objects.select_related('project')
    if not actor.is_superuser:
        qs = qs.filter(project__org_id__in=roles.managed_org_ids(actor))
    project = params.get('project', '').strip()
    if project:
        qs = qs.filter(project__slug=project)
    kind = params.get('kind', '').strip()
    if kind:
        if kind not in AgentActivity.KINDS:
            raise AdminError(400, 'unknown activity kind')
        qs = qs.filter(kind=kind)
    if params.get('errors') == '1':
        qs = qs.filter(status='failed')
    stage = params.get('stage', '').strip()[:64]
    if stage:
        qs = qs.filter(detail__stage=stage)
    for key in ('job_id', 'finding_id'):
        value = params.get(key, '').strip()
        if value:
            if not value.isdecimal():
                raise AdminError(400, f'{key} must be a positive integer')
            qs = qs.filter(**{f'detail__{key}': int(value)})
    query = params.get('q', '').strip()[:100]
    if query:
        qs = qs.filter(Q(message__icontains=query) | Q(cve_id__icontains=query))
    for key, op in (('from', 'gte'), ('to', 'lte')):
        value = params.get(key, '').strip()
        if value:
            try:
                when = parse_datetime(value)
            except ValueError:  # well formed but impossible, e.g. month 13
                when = None
            if when is None or timezone.is_naive(when):
                raise AdminError(400, f'{key} must be an ISO timestamp with timezone')
            qs = qs.filter(**{f'created_at__{op}': when})
    count = qs.count()
    start = (page - 1) * page_size
    rows = []
    diagnostic_fields = ('id', 'time', 'stage', 'category', 'failure_code', 'finding_kind',
                         'provider', 'model', 'http_status', 'stop_reason',
                         'output_length', 'attempt_id', 'job_id', 'finding_id', 'stack', 'outcome', 'action')
    for item in qs.order_by('-id')[start:start + page_size]:
        raw_diagnostic = (item.detail or {}).get('diagnostic')
        diagnostic = ({key: _safe_activity_text(value) for key in diagnostic_fields
                       if (value := raw_diagnostic.get(key)) is not None}
                      if isinstance(raw_diagnostic, dict) else None)
        rows.append({'id': item.pk, 'at': item.created_at.isoformat(), 'status': item.status,
                     'kind': item.kind, 'project': item.project.slug if item.project else None,
                     'message': _safe_activity_text(item.message), 'diagnostic': diagnostic})
    return {'count': count, 'page': page, 'page_size': page_size, 'results': rows}


def scheduler_health(request, actor):
    """Bounded, read-only scheduler and worker snapshot for the App Admin.

    Beat's database timestamp proves dispatch, not execution or process liveness. Worker
    inspection has a short timeout and returns counts only; task arguments never leave
    the worker or appear in this response.
    """
    if not actor.is_superuser:
        raise AdminError(403, 'App Admin only')
    from datetime import timedelta
    from django_celery_beat.models import PeriodicTask
    from cveFeed.models import (AutomaticValidation, DeferredRetest, OnDemandValidation, AgentActivity,
                                AssessmentReview, ArchiveRediscovery, InactiveArchiveReview, HostAssessment, HostState)
    from reNgine.celery import app
    from startScan.models import ScanHistory

    now = timezone.now()
    schedules = []
    for task in PeriodicTask.objects.filter(enabled=True).select_related('interval').order_by('name')[:100]:
        next_due = None
        if task.interval_id and task.last_run_at:
            interval = task.interval
            seconds = (interval.every * {'days': 86400, 'hours': 3600, 'minutes': 60,
                                         'seconds': 1, 'microseconds': 0.000001}.get(interval.period, 0))
            if seconds:
                next_due = task.last_run_at + timedelta(seconds=seconds)
        overdue = bool(next_due and next_due < now - timedelta(seconds=60))
        schedules.append({'name': task.name, 'task': task.task, 'queue': task.queue or 'default',
                          'last_dispatch': task.last_run_at.isoformat() if task.last_run_at else None,
                          'next_due': next_due.isoformat() if next_due else None,
                          'next_due_state': 'past_due_unconfirmed' if overdue else ('estimated' if next_due else 'unknown'),
                          'dispatch_count': task.total_run_count,
                          'next_due_note': None if next_due else 'unknown for this schedule'})
    expected = {'discovery_worker': 'discovery_queue', 'cve_feed_worker': 'cve_feed_queue',
                'validation_priority_worker': 'validation_priority_queue', 'classic_worker': 'api_queue'}
    worker_state = 'unknown'
    worker_note = 'Worker inspection did not return queue information.'
    workers = []
    try:
        inspector = app.control.inspect(timeout=5)
        queues = inspector.active_queues() or {}
        if queues:
            active_warning = ''
            def is_worker_name(name, prefix):
                # Celery deployments use both worker@host and celery@worker hostnames.
                return prefix in str(name).split('@')
            try:
                active = inspector.active() or {}
            except Exception:  # queue routing remains observable even if the active-task query times out
                active = {}
                active_warning = ' Active-task inspection did not respond.'
            for prefix, queue in expected.items():
                names = [name for name in queues if is_worker_name(name, prefix)]
                workers.append({'worker': prefix, 'queue': queue, 'responding': bool(names),
                                'consuming': any(any(q.get('name') == queue for q in queues.get(name) or []) for name in names)
                                if names else None,
                                'active': sum(len(active.get(name) or []) for name in names) if active and names else None})
            missing = [row['worker'] for row in workers if row['consuming'] is not True]
            worker_state = 'degraded' if missing else 'responding'
            worker_note = ('Missing or unconfirmed required queue consumers: ' + ', '.join(missing)
                           if missing else 'Required queue names were reported by workers; this does not prove scheduled tasks executed.') + active_warning
    except Exception as exc:  # noqa: BLE001 - expose a safe category, never raw broker addresses or credentials
        worker_note = ('Worker inspection failed (broker connection).' if isinstance(exc, (ConnectionError, OSError))
                       else 'Worker inspection failed (internal error).')

    jobs = {}
    for label, model in (('manual_validation', OnDemandValidation), ('automatic_validation', AutomaticValidation),
                         ('deferred_retest', DeferredRetest)):
        qs = model.objects.filter(status__in=['pending', 'dispatching', 'queued', 'running'])
        oldest = qs.order_by('created_at').values_list('created_at', flat=True).first()
        jobs[label] = {'pending': qs.count(), 'oldest': oldest.isoformat() if oldest else None}
    jobs['scans'] = {'pending': ScanHistory.objects.filter(scan_status=-1).count(),
                     'running': ScanHistory.objects.filter(scan_status=1).count()}
    host_jobs = HostAssessment.objects.filter(status__in=('queued', 'running'))
    oldest_host = host_jobs.order_by('created_at').values_list('created_at', flat=True).first()
    jobs['host_assessment'] = {'pending': host_jobs.count(), 'oldest': oldest_host.isoformat() if oldest_host else None}
    activity = {'running': None, 'done': None, 'failed': None}
    for row in AgentActivity.objects.order_by('-id').values('created_at', 'kind', 'status')[:1000]:
        if row['status'] in activity and activity[row['status']] is None:
            activity[row['status']] = {'at': row['created_at'].isoformat(), 'stage': row['kind']}
    latest_review = AssessmentReview.objects.order_by('-id').first()
    review = None
    if latest_review:
        decisions = list(latest_review.decisions.select_related('project').order_by('-id')[:20])
        review = {'id': latest_review.pk, 'status': latest_review.status,
                  'started_at': latest_review.started_at.isoformat() if latest_review.started_at else None,
                  'finished_at': latest_review.finished_at.isoformat() if latest_review.finished_at else None,
                  'reviewed': latest_review.reviewed_projects, 'total': latest_review.total_projects,
                  'cursor_project_id': latest_review.cursor_project_id, 'model_calls': latest_review.model_calls,
                  'actions': latest_review.queued_actions, 'errors': latest_review.error_count,
                  'performance': latest_review.performance, 'note': latest_review.error,
                  'recent_decisions': [{'project': d.project.slug, 'action': d.action, 'status': d.status,
                                        'reason': d.reason, 'job_id': d.job_id} for d in decisions]}
    from cveFeed.scan_control import pause_requested
    latest_archive = ArchiveRediscovery.objects.order_by('-id').first()
    archive = {'archived_hosts': HostState.objects.filter(archived_at__isnull=False).count(),
               'run_id': latest_archive.pk if latest_archive else None,
               'status': latest_archive.status if latest_archive else 'never_run',
               'checked': latest_archive.checked if latest_archive else 0,
               'total_at_start': latest_archive.total if latest_archive else 0,
               'reactivated': latest_archive.reactivated if latest_archive else 0,
               'deferred': latest_archive.deferred if latest_archive else 0,
               'errors': latest_archive.errors if latest_archive else 0,
               'cursor': latest_archive.cursor_hoststate_id if latest_archive else 0,
               'finished_at': latest_archive.finished_at.isoformat() if latest_archive and latest_archive.finished_at else None}
    latest_inactive = InactiveArchiveReview.objects.order_by('-id').first()
    inactive = {'retired_unarchived': HostState.objects.filter(retired_at__isnull=False,
                         archived_at__isnull=True).count(),
                'run_id': latest_inactive.pk if latest_inactive else None,
                'status': latest_inactive.status if latest_inactive else 'never_run',
                'checked': latest_inactive.checked if latest_inactive else 0,
                'archived': latest_inactive.archived if latest_inactive else 0,
                'reactivated': latest_inactive.reactivated if latest_inactive else 0,
                'deferred': latest_inactive.deferred if latest_inactive else 0,
                'errors': latest_inactive.errors if latest_inactive else 0,
                'cursor': latest_inactive.cursor_hoststate_id if latest_inactive else 0}
    return {'at': now.isoformat(), 'workers_state': worker_state, 'worker_note': worker_note, 'workers': workers,
            'scanning_paused': pause_requested(), 'assessment_review': review, 'archive_rediscovery': archive,
            'inactive_archive_review': inactive,
            'scheduler_process': 'unknown', 'scheduler_note': 'Last dispatch comes from Beat; this web request cannot inspect its process.',
            'schedules': schedules, 'jobs': jobs, 'last_activity': activity, 'activity_window': 1000}


def scan_control_get(request, actor):
    if not actor.is_superuser:
        raise AdminError(403, 'App Admin only')
    from cveFeed.models import ScanControl
    from startScan.models import ScanHistory
    from reNgine.celery import app

    row = ScanControl.current()
    active = None
    if row.paused:
        try:
            replies = app.control.inspect(timeout=2).active()
            if isinstance(replies, dict) and replies:
                active = sum(len(tasks) for tasks in replies.values() if isinstance(tasks, list))
        except Exception:
            pass
    return {'paused': row.paused, 'state': ('error' if row.last_error else
            'stopping' if row.paused and active is not None and active > 0 else
            'paused' if row.paused and active == 0 else
            'pause_requested' if row.paused else 'running'),
            'active_worker_tasks': active, 'tracked_running_scans': ScanHistory.objects.filter(scan_status=1).count(),
            'reason': row.reason, 'actor': row.actor, 'changed_at': row.changed_at.isoformat(),
            'last_error': row.last_error,
            'note': 'Worker inspection is unavailable; active process shutdown is unconfirmed.' if row.paused and active is None else
                    'Stopped scans remain stopped; queued jobs resume when scanning resumes.'}


def scan_control_set(request, actor):
    if not actor.is_superuser:
        raise AdminError(403, 'App Admin only')
    from cveFeed.models import ScanControl
    from cveFeed.scan_control import abort_running_scans, updater_idle

    body = _body(request)
    action = body.get('action')
    if action not in ('pause', 'resume') or body.get('confirm') != {'pause': 'Pause all scanning', 'resume': 'Resume scanning'}.get(action):
        raise AdminError(400, 'confirm the exact global scanning action')
    if action == 'resume':
        try:
            with updater_idle(), transaction.atomic():
                row = ScanControl.current()
                row = ScanControl.objects.select_for_update().get(pk=row.pk)
                if row.paused:
                    row.paused, row.reason, row.actor, row.changed_at, row.last_error = False, '', actor.username, timezone.now(), ''
                    row.save(update_fields=['paused', 'reason', 'actor', 'changed_at', 'last_error'])
                    audit(actor, 'scanning.resume', 'all projects')
        except (OSError, RuntimeError) as exc:
            raise AdminError(409, 'An update is running or its lock is unavailable; scanning cannot resume yet') from exc
    else:
        with transaction.atomic():
            row = ScanControl.current()
            row = ScanControl.objects.select_for_update().get(pk=row.pk)
            if not row.paused:
                row.paused, row.reason, row.actor, row.changed_at, row.last_error = True, 'Paused by App Admin', actor.username, timezone.now(), ''
                row.save(update_fields=['paused', 'reason', 'actor', 'changed_at', 'last_error'])
                audit(actor, 'scanning.pause', 'all projects')
            elif row.last_error:
                row.last_error = ''
                row.save(update_fields=['last_error'])
        try:
            abort_running_scans(actor)
        except Exception:
            ScanControl.objects.filter(pk=1).update(last_error='Some active scans could not be stopped; inspect worker activity.')
    return scan_control_get(request, actor)


# --- routing --------------------------------------------------------------------------------------

ROUTES = [
    ('GET', r'users', users_list), ('POST', r'users', users_create),
    ('PATCH', r'users/(?P<user_id>\d+)', users_update), ('DELETE', r'users/(?P<user_id>\d+)', users_delete),
    ('POST', r'users/(?P<user_id>\d+)/reset-password', users_reset_password),
    ('POST', r'users/(?P<user_id>\d+)/reset-mfa', users_reset_mfa),
    ('POST', r'memberships', memberships_set),
    ('DELETE', r'memberships/(?P<scope>org|project)/(?P<membership_id>\d+)', memberships_delete),
    ('GET', r'orgs', orgs_list), ('POST', r'orgs', orgs_create),
    ('PATCH', r'orgs/(?P<org_id>\d+)', orgs_update), ('DELETE', r'orgs/(?P<org_id>\d+)', orgs_delete),
    ('GET', r'orgs/(?P<org_id>\d+)/api-keys', org_api_credentials_list),
    ('PUT', r'orgs/(?P<org_id>\d+)/api-keys/(?P<service>[-\w]+)', org_api_credential_set),
    ('DELETE', r'orgs/(?P<org_id>\d+)/api-keys/(?P<service>[-\w]+)', org_api_credential_delete),
    ('GET', r'projects', projects_list), ('POST', r'projects', projects_create),
    ('DELETE', r'projects/(?P<project_id>\d+)', projects_delete),
    ('GET', r'timings', timings_get), ('PUT', r'timings', timings_put),
    ('GET', r'audit', audit_list),
    ('GET', r'activity', activity_list),
    ('GET', r'health', scheduler_health),
    ('GET', r'scan-control', scan_control_get), ('POST', r'scan-control', scan_control_set),
]
COMPILED = [(m, re.compile(f'^{p}/?$'), fn) for m, p, fn in ROUTES]


def dispatch(request, path):
    actor = request.user
    if not (actor.is_authenticated and roles.is_admin_anywhere(actor)):
        return JsonResponse({'error': 'administrators only'}, status=403)
    path, methods = path.strip('/'), []
    for method, regex, fn in COMPILED:
        match = regex.match(path)
        if not match:
            continue
        methods.append(method)
        if method != request.method:
            continue
        try:
            result = fn(request, actor, **match.groupdict())
        except AdminError as exc:
            return JsonResponse({'error': exc.message}, status=exc.status)
        data, status = result if isinstance(result, tuple) else (result, 200)
        return JsonResponse(data, status=status)
    return JsonResponse({'error': 'method not allowed' if methods else 'not found'}, status=405 if methods else 404)
