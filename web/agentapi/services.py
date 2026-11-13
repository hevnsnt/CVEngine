"""Operations shared by the REST API and the MCP tools.

Every function takes a ``Ctx`` (the acting user and, for token calls, the token)
and enforces tenancy itself: the project must be visible to the user, writes need
a role above audit, and a read-only token can never write. Queries are filtered
to the project explicitly, in addition to the request-wide data scope.
"""
import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from typing import Optional

from django.contrib.postgres.expressions import ArraySubquery
from django.db.models import AutoField, Lookup
from django.utils import timezone

from cveFeed import match_policy, result_cuts
from cveFeed.counts import running_window
from cveFeed.discovery import NUCLEI_SCAN_ACTIVITY_NAMES
from tenancy import roles

logger = logging.getLogger(__name__)

PAGE_SIZE_DEFAULT = 50
PAGE_SIZE_MAX = 200


def _max_targets():
    try:
        return max(1, int(os.environ.get('CVENGINE_MAX_TARGETS_PER_ADD', '')))
    except ValueError:
        return 10000


TARGET_EXPAND_CAP = _max_targets()  # addresses one CIDR or range may expand to; bulk add shares the same limit
SEVERITY_NAMES = {-1: 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
FALSE_POSITIVES = ('likely_false_positive', 'not_applicable')


class ApiError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra  # extra: fields the caller can act on, sent beside the error


@dataclass
class Ctx:
    user: object
    token: Optional[object] = None
    org: str = ''  # the organization the All projects view is narrowed to ('' = every organization; see roles.scope_org)


# --- access ------------------------------------------------------------------

ALL_PROJECTS = roles.ALL_PROJECTS


class AllProjects:
    """What ``get_project`` returns for the reserved slug ``_all``: not a project, but "every project the caller may see".

    ``ids`` is the caller's allowed project ids, resolved once from the tenancy layer. It is a sorted tuple, so a list service
    filters ``project_id__in=project.ids`` and an empty tuple matches nothing. It is read-only by construction: ``get_project``
    refuses a write on it, and it has no ``pk`` or ``id``, so it can never be handed to a query that expects a real project."""
    is_all = True
    slug = ALL_PROJECTS
    name = 'All projects'

    def __init__(self, ids):
        self.ids = tuple(sorted(ids))

    def __repr__(self):
        return f'<AllProjects {len(self.ids)} projects>'


def _is_all(project):
    return isinstance(project, AllProjects)


def _allowed_ids(user):
    """The ids of the projects ``user`` may see: the tenancy allowed set (``None`` for a superuser means every project), cut down
    to projects that exist and are visible through the scoped manager."""
    from dashboard.models import Project
    allowed = roles.allowed_project_ids(user)
    qs = Project.objects.all() if allowed is None else Project.objects.filter(id__in=allowed)
    return qs.values_list('id', flat=True)


def get_project(ctx, slug, write=False):
    """Return (project, role). 404 when not visible (same as missing), 403 on a forbidden write.

    The reserved slug ``_all`` returns an ``AllProjects`` marker and the caller's best role instead: the read-only view over every
    project the caller may see. A write there is a 400, so ``_all`` can never be a way around a project's own authorization:
    every mutation names one real project and passes that project's role check."""
    from dashboard.models import Project
    if slug == ALL_PROJECTS:
        if write:
            raise ApiError(400, 'pick a project to make changes')
        role = roles.user_best_role(ctx.user)
        if not role:
            raise ApiError(404, 'project not found')
        return AllProjects(roles.org_project_ids(list(_allowed_ids(ctx.user)), getattr(ctx, 'org', ''))), role
    project = Project.objects.filter(slug=slug or '').first()
    role = roles.effective_role(ctx.user, project) if project else None
    if not role:
        raise ApiError(404, 'project not found')
    if write:
        if role == roles.AUDIT:
            raise ApiError(403, 'audit role is read only')
        if ctx.token and ctx.token.read_only:
            raise ApiError(403, 'this token is read only')
    return project, role


def get_one_project(ctx, slug, write=False):
    """``get_project`` for an operation that only makes sense inside one project (an item by id, secrets, exclusions): ``_all`` is a 400."""
    if slug == ALL_PROJECTS:
        raise ApiError(400, 'pick a project to make changes' if write else 'pick a project: this works on one project at a time')
    return get_project(ctx, slug, write=write)


def _scoped(qs, project, lookup):
    """``qs`` limited to ``project``: one project, or in the all-projects view the caller's allowed projects, filtered explicitly
    so the query is bounded (the tenancy-scoped managers are the second guard). ``lookup`` is the path to the project, e.g.
    ``target_domain__project``."""
    if _is_all(project):
        return qs.filter(**{f'{lookup}_id__in': list(project.ids)})
    return qs.filter(**{lookup: project})


def _tagged(serialize, project_of):
    """Wrap a row serializer so each all-projects row names its project: ``project`` (slug) and ``project_name``.
    ``project_of(obj)`` must read a project the queryset already joined (select_related), so there is no query per row."""
    def wrapped(obj):
        out = serialize(obj)
        project = project_of(obj)
        out['project'], out['project_name'] = (project.slug, project.name) if project else (None, None)
        return out
    return wrapped


def require_write_token(ctx):
    if ctx.token and ctx.token.read_only:
        raise ApiError(403, 'this token is read only')


def _int_param(value, name):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):  # OverflowError: JSON 1e999 parses to infinity
        raise ApiError(400, f'{name} must be an integer')


MAX_PAGE = 10 ** 6  # beyond this the OFFSET is past any table; an absurd page is clamped instead of overflowing the database's bigint


def page_args(params, zero_ok=False):
    """``(page, size)`` from ``page`` and ``page_size``: page at least 1 (and at most MAX_PAGE), size from 1 to PAGE_SIZE_MAX, a 400
    for anything that is not a whole number. The one place the bounds live, so no list route can be asked for a negative or a giant window.
    With ``zero_ok`` a ``page_size`` of 0 is kept: the route answers with its counts and no rows, which is all a chip or a badge needs."""
    try:
        page = min(MAX_PAGE, max(1, int(params.get('page', 1))))
        size = int(params.get('page_size', PAGE_SIZE_DEFAULT))
    except (TypeError, ValueError, OverflowError):  # OverflowError: a JSON 1e999 parses to infinity
        raise ApiError(400, 'page and page_size must be integers')
    return page, min(PAGE_SIZE_MAX, max(0 if zero_ok and size == 0 else 1, size))


def paginate(queryset, params, serialize):
    """One page of ``queryset``. ``page_size=0`` returns the count and no rows."""
    page, size = page_args(params, zero_ok=True)
    total = queryset.count()
    start = (page - 1) * size
    return {'count': total, 'page': page, 'page_size': size,
            'results': [serialize(o) for o in queryset[start:start + size]] if size else []}


def paginate_by_ids(queryset, params, load):
    """The same page ``paginate`` gives, with the heavy query run once. ``queryset`` is the ordered set of rows; its ids are read in one query, the
    count is their number and the page is a slice of them, and only that slice is loaded (``load(ids)``, rows in the order given). ``paginate``
    runs the queryset twice, a COUNT and the page, and when the queryset is the one-row-per-host collapse each run costs 0.5 s at 10,000 hosts.
    ``page_size=0`` keeps the count query: it needs no ids."""
    page, size = page_args(params, zero_ok=True)
    if not size:
        return {'count': queryset.count(), 'page': page, 'page_size': 0, 'results': []}
    ids = list(queryset.values_list('pk', flat=True))
    start = (page - 1) * size
    return {'count': len(ids), 'page': page, 'page_size': size, 'results': load(ids[start:start + size])}


def _digits(value, longest=9):
    """True when ``value`` is a short run of ASCII digits, so int() of it cannot fail (str.isdigit() is also true of superscripts) or
    run past the database's integer."""
    return isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= longest


def _iso(value):
    return value.isoformat() if value else None


def _user_brief(user):
    """{id, username, name} for a status-change actor or an assignee, None when there is none."""
    return {'id': user.id, 'username': user.username, 'name': user.get_full_name() or user.username} if user else None


def _closure_fields(kind, obj):
    """``closure_note``, ``closed_by``, ``closed_at`` and ``closed_automatically`` of a finding (cveFeed.closure.closure_of): the note a
    person wrote when closing it (fixed, accepted_risk or false_positive) with who and when, or the reason the engine stored when it
    closed it on its own (``closed_by`` null, ``closed_automatically`` true); all null for a finding that is still open."""
    from cveFeed import closure
    note, user, when, automatic = closure.closure_of(kind, obj)
    return {'closure_note': note, 'closed_by': _user_brief(user), 'closed_at': _iso(when), 'closed_automatically': automatic}


def _comment_count(obj, kind):
    """``obj.comment_count`` when the queryset annotated it (every list and detail path does, in one query for the page), else a
    count for this one row, so a serializer handed a plain, unannotated row still answers instead of raising."""
    count = getattr(obj, 'comment_count', None)
    if count is not None:
        return count
    from cveFeed.models import FindingComment
    return FindingComment.objects.filter(finding_kind=kind, finding_id=obj.pk).count()


def _comment_count_annotation(kind):
    """An annotation expression counting cveFeed.models.FindingComment rows of ``kind`` for each row of the annotated
    queryset, by a correlated subquery rather than a join (a comment is addressed by (kind, id), not a real FK, so a
    join would fan out the outer rows). Not project-scoped: (kind, id) alone already names one finding anywhere."""
    from django.db.models import Count, IntegerField, OuterRef, Subquery
    from django.db.models.functions import Coalesce

    from cveFeed.models import FindingComment
    sub = FindingComment.objects.filter(finding_kind=kind, finding_id=OuterRef('pk')) \
        .order_by().values('finding_id').annotate(n=Count('id')).values('n')
    return Coalesce(Subquery(sub, output_field=IntegerField()), 0)


# --- identity ----------------------------------------------------------------

def _project_roles(ctx):
    from dashboard.models import Project
    return [{'slug': p.slug, 'name': p.name, 'role': roles.effective_role(ctx.user, p),
             'org': p.org.slug if p.org_id else None, 'org_name': p.org.name if p.org_id else None}
            for p in Project.objects.select_related('org').order_by('name')]


def me(ctx):
    from agentapi import agent_broker
    projects = _project_roles(ctx)
    profile = getattr(ctx.user, 'tenancy_profile', None)
    return {'username': ctx.user.username, 'projects': projects,
            'bugbounty_enabled': ctx.user.is_superuser or bool(profile and profile.bugbounty_enabled),
            'token': {'name': ctx.token.name, 'read_only': ctx.token.read_only,
                      'assets': ctx.token.assets} if ctx.token else None,
            'agent': agent_broker.identity(ctx)}


def list_projects(ctx, params=None):
    return {'results': _project_roles(ctx)}


def list_engines(ctx, params=None):
    from scanEngine.models import EngineType
    return {'results': [{'id': e.id, 'name': e.engine_name, 'default': bool(e.default_engine)}
                        for e in EngineType.objects.order_by('engine_name')]}


# --- targets and scans ---------------------------------------------------------

def _target(d):
    out = {'id': d.id, 'name': d.name, 'alias': d.alias, 'note': d.note, 'description': d.description,
           'created': _iso(d.insert_date), 'last_scan': _iso(d.start_scan_date),
           'scope_mode': d.scope_mode, 'host_scoped': d.is_host_scoped(), 'discovery_mode': d.discovery_mode,
           'expect_private_ca': bool(d.expect_private_ca)}
    if hasattr(d, 'n_hosts'):  # list view: how big the target is and how much of it is exposed
        out['hosts'], out['exposed'] = d.n_hosts, d.n_exposed
    return out


def _target_search(qs, q):
    """``qs`` (Domains) narrowed to the ones whose name, alias or note contains ``q``: the one search the target list and "delete all matching" share."""
    from django.db.models import Q
    q = str(q)
    return qs.filter(Q(name__icontains=q) | Q(alias__icontains=q) | Q(note__icontains=q))


def list_targets(ctx, slug, params):
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(Domain.objects.all(), project, 'project')
    qs = qs.order_by('name', 'project_id', 'id') if everywhere else qs.order_by('name')
    if everywhere:
        qs = qs.select_related('project')
    if params.get('q'):
        qs = _target_search(qs, params['q'])
    page = paginate(qs, params, _tagged(_target, lambda d: d.project) if everywhere else _target)
    _count_target_hosts(page['results'])
    return page


def _count_target_hosts(rows):
    """Put ``hosts`` and ``exposed`` on each target of one page, counted the way the Hosts page and the dashboard count (``cveFeed.counts``): a host
    is one per project and name, names on the same addresses fold together, and a scan-less row is not a second host. They were counted as current
    Subdomain rows, so one target read 3 on the Targets table and 1 on the Hosts page (review 1 F2). One grouped query per page, for its targets only."""
    from django.db.models import Count

    from cveFeed import counts
    from targetApp.models import Domain
    ids = [r['id'] for r in rows]
    if not ids:
        return
    reps = counts.host_reps(domain_ids=ids)
    hosts = dict(reps.order_by().values('target_domain_id').annotate(n=Count('pk')).values_list('target_domain_id', 'n'))
    projects = set(Domain.objects.filter(pk__in=ids).values_list('project_id', flat=True))
    exposed = dict(counts.exposed_among(reps, project_ids=projects).order_by().values('target_domain_id').annotate(n=Count('pk'))
                   .values_list('target_domain_id', 'n'))
    for row in rows:
        row['hosts'], row['exposed'] = hosts.get(row['id'], 0), exposed.get(row['id'], 0)


def get_target(ctx, slug, target_id):
    from targetApp.models import Domain
    project, _ = get_one_project(ctx, slug)
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    return _target(d)


def set_target_scope(ctx, slug, target_id, scope_mode):
    """Set how far a target's scope reaches: ``auto`` (the shared-domain list decides), ``host`` (exactly this host: never its parent
    domain, and no name under it is discovered, kept or scanned) or ``parent`` (the registrable domain is owned, even on the shared list: use
    with care). The same choice can be made when the target is added (``scope_mode``, or ``=example.com`` in Add targets)."""
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    if scope_mode in (None, ''):
        raise ApiError(400, 'scope_mode must be auto, host or parent')
    scope_mode = _scope_mode(scope_mode)
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    d.scope_mode = scope_mode
    d.save(update_fields=['scope_mode'])
    return _target(d)


def clean_alias_note(alias=None, note=None):
    """``{'alias': ..., 'note': ...}`` for the fields given (``None`` leaves a field alone, ``''`` clears it), cleaned and bounded
    (targetApp.alias_note), or a 400 naming the field."""
    from targetApp import alias_note
    fields = {}
    try:
        if alias is not None:
            fields['alias'] = alias_note.clean_alias(alias)
        if note is not None:
            fields['note'] = alias_note.clean_note(note)
    except ValueError as e:
        raise ApiError(400, str(e))
    return fields


def set_target_profile(ctx, slug, target_id, alias=None, note=None):
    """Set the alias (a short display name) and/or the note of a target. Only the fields given change; an empty string clears one. Display
    only: the target's name is what is scanned and never changes."""
    from cveFeed.admin_api import audit
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    fields = clean_alias_note(alias, note)
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    changed = [key for key, value in fields.items() if getattr(d, key) != value]
    if changed:
        for key in changed:
            setattr(d, key, fields[key])
        d.save(update_fields=changed)
        audit(ctx.user, 'target.profile', f'{d.name} in {slug}', project.org, project=slug, name=d.name, fields=changed)
    return _target(d)


def set_target_discovery_mode(ctx, slug, target_id, discovery_mode):
    """Change the mode a target is discovered in whenever discovery starts on its own: ``standard``, ``deep``, ``passive``, or ``manual``
    (never started automatically; only a person's Discover or Scan, once a mode is chosen). Changing it starts nothing."""
    from cveFeed.admin_api import audit
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    if not isinstance(discovery_mode, str) or discovery_mode not in {m for m, _label in Domain.DISCOVERY_MODES}:
        raise ApiError(400, 'discovery_mode must be standard, deep, passive or manual')
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    if d.discovery_mode != discovery_mode:
        audit(ctx.user, 'target.discovery_mode', d.name, project.org, project=slug, was=d.discovery_mode, now=discovery_mode)
        d.discovery_mode = discovery_mode
        d.save(update_fields=['discovery_mode'])
    return _target(d)


def set_target_private_ca(ctx, slug, target_id, expect_private_ca):
    """Say whether a target's devices use their vendor's own private CA. When they do, an untrusted or self-signed certificate chain on
    the target is expected and the hygiene check rates it information instead of medium. Applies from the next hygiene run."""
    from cveFeed.admin_api import audit
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    if isinstance(expect_private_ca, str) and expect_private_ca.strip().lower() in ('true', 'false', '1', '0', 'yes', 'no'):
        expect_private_ca = expect_private_ca.strip().lower() in ('true', '1', 'yes')
    if not isinstance(expect_private_ca, bool):
        raise ApiError(400, 'expect_private_ca must be true or false')
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    if d.expect_private_ca != expect_private_ca:
        audit(ctx.user, 'target.private_ca', d.name, project.org, project=slug, was=d.expect_private_ca, now=expect_private_ca)
        d.expect_private_ca = expect_private_ca
        d.save(update_fields=['expect_private_ca'])
    return _target(d)


def _expand_target(value, project=None):
    """Validate one pasted target and expand it: ``(kind, names)``. A CIDR or range is sized before expanding, so a /8 is
    never built. ``project`` (an id) lets an address inside a network that project declared internal
    (``cveFeed.models.InternalRange``) through: it becomes a target, but only a Sentinel inside that network ever scans it."""
    import ipaddress
    from targetApp.target_types import CIDR, DOMAIN, RANGE, classify_target, expand_cidr, expand_range, is_scannable_ip, range_size
    kind = classify_target(value)
    if not kind:
        raise ApiError(400, 'not a domain, IP, CIDR or range')
    if kind == CIDR:
        size = ipaddress.ip_network(value.strip(), strict=False).num_addresses
    elif kind == RANGE:
        size = range_size(value)
    else:
        size = 1
    if size > TARGET_EXPAND_CAP:
        raise ApiError(400, f'{kind} covers {size} addresses; the cap is {TARGET_EXPAND_CAP}')
    if kind == DOMAIN:
        names = [value.strip().lower()]
    elif kind == CIDR:
        names = expand_cidr(value, max_hosts=TARGET_EXPAND_CAP)
    elif kind == RANGE:
        names = expand_range(value)
    else:
        names = [value.strip()]
    if not names:
        raise ApiError(400, 'target expands to no hosts')
    if kind != DOMAIN:
        from targetApp.target_types import in_internal_range, internal_networks
        internal = internal_networks(project)
        blocked = next((n for n in names if not is_scannable_ip(n) and not in_internal_range(n, internal)), None)  # no project to is_scannable_ip: a tailnet address is only ever imported by the Tailscale sync
        if blocked:
            raise ApiError(400, f'{blocked} is a loopback, link-local or internal address, which cannot be scanned '
                                '(an operator can allow internal ranges with CVENGINE_ALLOW_PRIVATE_TARGETS=1)')
    return kind, names


def _not_internal(project, domains):
    """``domains`` without the ones named by an address inside a network ``project`` declared internal."""
    from targetApp.target_types import in_internal_range, internal_networks
    nets = internal_networks(project.id)
    return [d for d in domains if not (nets and in_internal_range(d.name, nets))]


def _discovery_mode(mode):
    """The mode to store on new targets: ``mode`` (standard, deep, passive, or manual for "just add them, do not scan yet"), standard when
    none is given. Anything else is refused, since the stored mode decides what every later automatic scan of the target may do."""
    from targetApp.models import Domain
    if mode in (None, ''):
        return Domain.DISCOVERY_STANDARD
    if not isinstance(mode, str) or mode not in {m for m, _label in Domain.DISCOVERY_MODES}:
        raise ApiError(400, 'mode must be standard, deep, passive or manual')
    return mode


def _scope_mode(value):
    """The scope to store on new targets: ``value`` (auto, host or parent), auto when none is given. Anything else is refused, with the
    same message as ``set_target_scope``."""
    from targetApp.models import Domain
    if value in (None, ''):
        return Domain.SCOPE_AUTO
    if not isinstance(value, str) or value not in {m for m, _label in Domain.SCOPE_MODES}:
        raise ApiError(400, 'scope_mode must be auto, host or parent')
    return value


HOST_ONLY_MARK = '='  # "=example.com" in Add targets: exactly this host (scope_mode 'host'), no subdomain discovered, kept or scanned


def split_scope_mark(entry):
    """``(entry without its leading '=', whether it had one)``. The mark is what a person types to add exactly one host: ``=example.com``."""
    entry = entry if isinstance(entry, str) else ''
    if entry.startswith(HOST_ONLY_MARK):
        return entry[len(HOST_ONLY_MARK):], True
    return entry, False


def _create_domains(project, names, description='', excluded=None, discovery_mode='standard', scopes=None):
    """Create a Domain per name in bulk, in order. Returns (the rows created, the names that already existed). Domain
    names are unique within an organization, so a name another project of the same organization holds counts as existing (another
    organization's record of the same name is a different, separate record). A name the project's organization
    excluded for good ("Remove & exclude") is never created; it is appended to ``excluded`` when a list is given. ``scopes`` maps a name to the
    scope_mode it is created with (auto when it is not named); a name that already exists keeps its own."""
    from cveFeed.exclusions import excluded_names, normalize
    from targetApp.models import Domain, org_domains
    from startScan.ip_rows import org_id_of_project
    names = list(dict.fromkeys(names))
    org_id = org_id_of_project(project.id)
    banned = excluded_names(project.id, names_only=True)  # adding a target is not scanning it: an address-excluded name is added, then never scanned
    if banned:
        skipped = [n for n in names if normalize(n) in banned]
        if excluded is not None:
            excluded.extend(skipped)
        names = [n for n in names if n not in set(skipped)]
    existing = set()
    for start in range(0, len(names), 1000):
        existing.update(org_domains(project).filter(name__in=names[start:start + 1000]).values_list('name', flat=True))
    wanted = [n for n in names if n not in existing]
    now = timezone.now()
    created = []
    for start in range(0, len(wanted), 1000):
        part = wanted[start:start + 1000]
        # ignore_conflicts: a concurrent add of the same name must not fail the whole batch; the re-read says what we own
        Domain.objects.bulk_create([Domain(name=n, project=project, org_id=org_id, description=description or None, insert_date=now,
                                                      discovery_mode=discovery_mode, scope_mode=(scopes or {}).get(n, Domain.SCOPE_AUTO)) for n in part],
                                   ignore_conflicts=True)
        created += Domain.objects.filter(project=project, name__in=part).order_by('id')
    created.sort(key=lambda d: d.id)
    return created, [n for n in names if n in existing]


def add_target(ctx, slug, value, description='', discover=False, mode=None, scope_mode=None):
    """Add a domain, IP, CIDR or range as target(s); ranges expand to individual IPs (capped). Every address of a range is
    queued for discovery, in order. ``scope_mode`` (auto, host or parent; auto when omitted) is stored on a new domain target, and a
    leading ``=`` (``=example.com``) means host: exactly that host. An address target has no subdomains and keeps auto."""
    from targetApp.models import Domain
    from targetApp.target_types import DOMAIN
    project, _ = get_project(ctx, slug, write=True)
    if not isinstance(value, str):
        raise ApiError(400, 'value must be text')
    stored = _discovery_mode(mode)
    scope = _scope_mode(scope_mode)
    value, exact = split_scope_mark(value.strip())
    kind, names = _expand_target(value, project.id)
    scope = Domain.SCOPE_HOST if exact else scope
    scopes = {n: scope for n in names} if kind == DOMAIN else {}
    excluded = []
    created, existing = _create_domains(project, names, description, excluded, stored, scopes)
    if excluded and not created and not existing:
        raise ApiError(409, f'{excluded[0]} is excluded for this organization and is never added or scanned '
                            '(an organization admin can lift the exclusion)')
    if kind == DOMAIN and created and not created[0].exact_host_only():  # every domain target is "subscribed": watched for new certificates going
        # forward, except one that is exactly one host (no name under it would be taken)
        from cveFeed import ct_queue
        ct_queue.queue_lookups([created[0].id], ct_queue.ADD_LIFETIME)  # one marker per domain: adding it twice queues one lookup
    scan_ids = []
    created_for_discovery = _not_internal(project, created)  # a Sentinel inside an internal network scans those; bbot here never does
    deferred = 0
    if discover and created_for_discovery and stored != Domain.DISCOVERY_MANUAL:  # bbot discovery streams into the dashboard as it runs
        scans, deferred = _discover_new(created_for_discovery, stored, project.id, initiated_by=ctx.user)
        scan_ids = [scan.id for scan in scans]
    return {'kind': kind, 'created': [_target(d) for d in created], 'already_exists': existing, 'excluded': excluded, 'scan_ids': scan_ids,
            'discovery_deferred': deferred}


SCAN_STATUS_FILTER = {'queued': -1, '-1': -1, 'failed': 0, '0': 0, 'running': 1, '1': 1, 'finished': 2, 'success': 2, '2': 2,
                      'aborted': 3, '3': 3}


def _scan(s, detail=False, queued=None, stalled_before=None):
    """``queued`` is a callable returning the queued scan ids, so a page of scans looks the queue up at most once. ``stalled_before`` is the
    moment a running scan counts as stalled when it started earlier (``now - running_window()``): a list computes it once for the whole page,
    because running_window() reads the timing settings and would otherwise cost one query per row."""
    if stalled_before is None:
        stalled_before = timezone.now() - running_window()
    out = {'id': s.id, 'target': s.domain.name, 'target_id': s.domain_id, 'engine': s.scan_type.engine_name,
           'status': s.scan_status, 'started': _iso(s.start_scan_date), 'finished': _iso(s.stop_scan_date),
           'error': s.error_message,
           'stalled': s.scan_status == 1 and s.start_scan_date < stalled_before,  # marked running, but older than any scan can run
           'kind': 'retest' if 'retest' in (s.tasks or []) else 'hosts' if 'host_pipeline' in (s.tasks or []) else 'discovery'}
    if s.scan_status == -1:  # how many scans are ahead of this one in the queue
        from cveFeed.discovery import queue_position
        out['queue_position'] = queue_position(s.id, queued() if queued else None)
    if hasattr(s, 'n_hosts'):  # list view
        out['hosts'], out['findings'] = s.n_hosts, s.n_vulns
        out['top_severity'] = SEVERITY_NAMES.get(s.top_sev) if s.n_vulns else None
    if detail:
        from startScan.models import Subdomain, Vulnerability
        out['subdomains'] = Subdomain.objects.filter(scan_history=s).count()
        out['vulnerabilities'] = Vulnerability.objects.filter(scan_history=s).count()
        from startScan.models import EndPoint
        out['endpoints'] = EndPoint.objects.filter(scan_history=s).count()
        out['severity_counts'] = {SEVERITY_NAMES[k]: Vulnerability.objects.filter(scan_history=s, severity=k).count()
                                  for k in (4, 3, 2, 1, 0)}
        from cveFeed.models import AgentActivity  # the hosts this scan did not touch because of the organization's do-not-scan list, and why
        out['not_scanned'] = [{'message': a.message, 'hosts': (a.detail or {}).get('hosts', [])} for a in
                              AgentActivity.objects.filter(detail__scan_id=s.id, detail__address_excluded=True).order_by('id')[:20]]
    return out


def list_scans(ctx, slug, params):
    """The project's scans: running first, then queued (next up first), then everything else newest first. Counts of hosts and
    findings are looked up for the page only, in two grouped queries, instead of joining hosts and findings for every scan
    (that join multiplies rows and makes the list slow, or fail, once scans hold thousands of hosts)."""
    from django.db.models import Case, Count, IntegerField, Max, Value, When, F
    from startScan.models import ScanHistory, Subdomain, Vulnerability
    from cveFeed.discovery import queued_ids
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(ScanHistory.objects.all(), project, 'domain__project').select_related('domain__project' if everywhere else 'domain', 'scan_type')
    if params.get('target_id'):
        qs = qs.filter(domain_id=_int_param(params['target_id'], 'target_id'))
    from cveFeed import counts
    status = str(params.get('status', '')).lower()
    if status in ('running', '1'):  # the dashboard's definition: a scan "running" since before the window is stalled
        qs = counts.running_scans(qs)
    elif status == 'active':  # running (the dashboard's definition) and queued together: one request where the shell used two
        from django.db.models import Q
        qs = qs.filter(Q(pk__in=counts.running_scans(qs).values('pk')) | Q(scan_status=-1))
    elif status == 'stalled':
        qs = counts.stalled_scans(qs)
    elif SCAN_STATUS_FILTER.get(status) is not None:
        qs = qs.filter(scan_status=SCAN_STATUS_FILTER[status])
    qs = qs.order_by(
        Case(When(scan_status=1, then=Value(0)), When(scan_status=-1, then=Value(1)), default=Value(2), output_field=IntegerField()),
        Case(When(scan_status=-1, then=F('id')), default=-F('id'), output_field=IntegerField()))
    page, size = page_args(params, zero_ok=True)  # page_size=0: the counts alone
    total = qs.count()
    start = (page - 1) * size
    scans = list(qs[start:start + size]) if size else []
    ids = [s.id for s in scans]
    hosts = dict(Subdomain.objects.filter(scan_history_id__in=ids).values_list('scan_history_id').annotate(n=Count('id')))
    found = {sid: (n, top) for sid, n, top in Vulnerability.objects.filter(scan_history_id__in=ids)
             .values_list('scan_history_id').annotate(n=Count('id'), top=Max('severity'))}
    for sc in scans:
        sc.n_hosts, (sc.n_vulns, sc.top_sev) = hosts.get(sc.id, 0), found.get(sc.id, (0, None))
    cache = []

    def queued():
        if not cache:
            cache.append(queued_ids())
        return cache[0]
    stalled_before = timezone.now() - running_window()  # once per page, not once per row
    serialize = _tagged(lambda sc: _scan(sc, queued=queued, stalled_before=stalled_before), lambda sc: sc.domain.project) if everywhere \
        else (lambda sc: _scan(sc, queued=queued, stalled_before=stalled_before))
    return {'count': total, 'page': page, 'page_size': size, 'results': [serialize(sc) for sc in scans]}


def get_scan(ctx, slug, scan_id):
    from startScan.models import ScanHistory
    project, _ = get_one_project(ctx, slug)
    s = ScanHistory.objects.filter(domain__project=project, id=scan_id).select_related('domain', 'scan_type').first()
    if not s:
        raise ApiError(404, 'scan not found')
    return _scan(s, detail=True)


def _scan_in_project(ctx, slug, scan_id):
    from startScan.models import ScanHistory
    project, _ = get_one_project(ctx, slug)
    scan = ScanHistory.objects.filter(domain__project=project, id=scan_id).first()
    if not scan:
        raise ApiError(404, 'scan not found')
    return scan


def _scan_subdomain(sub):
    return {'id': sub.id, 'name': sub.name, 'http_status': sub.http_status, 'title': sub.page_title,
            'webserver': sub.webserver, 'cdn': sub.cdn_name if sub.is_cdn else None,
            'important': bool(sub.is_important), 'url': sub.http_url,
            'ips': [ip.address for ip in sub.ip_addresses.all()],
            'technologies': [t.name for t in sub.technologies.all()]}


def list_scan_subdomains(ctx, slug, scan_id, params):
    from startScan.models import Subdomain
    scan = _scan_in_project(ctx, slug, scan_id)
    qs = Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses', 'technologies').order_by('name')
    if params.get('q'):
        qs = qs.filter(name__icontains=params['q'])
    if _digits(params.get('http_status')):
        qs = qs.filter(http_status=int(params['http_status']))
    return paginate(qs, params, _scan_subdomain)


def _scan_endpoint(e):
    return {'id': e.id, 'url': e.http_url, 'http_status': e.http_status, 'title': e.page_title,
            'content_type': e.content_type, 'webserver': e.webserver, 'source': e.source,
            'patterns': (e.matched_gf_patterns or '').split(',') if e.matched_gf_patterns else [],
            'host': e.subdomain.name if e.subdomain else None, 'discovered': _iso(e.discovered_date)}


def list_scan_endpoints(ctx, slug, scan_id, params):
    from startScan.models import EndPoint
    scan = _scan_in_project(ctx, slug, scan_id)
    qs = EndPoint.objects.filter(scan_history=scan).select_related('subdomain').order_by('http_url')
    if params.get('q'):
        qs = qs.filter(http_url__icontains=params['q'])
    if _digits(params.get('http_status')):
        qs = qs.filter(http_status=int(params['http_status']))
    return paginate(qs, params, _scan_endpoint)


def list_scan_vulnerabilities(ctx, slug, scan_id, params):
    from startScan.models import Vulnerability
    scan = _scan_in_project(ctx, slug, scan_id)
    qs = Vulnerability.objects.filter(scan_history=scan).select_related('subdomain', 'triage__verdict', 'remediation_by', 'assignee') \
        .prefetch_related('cve_ids', 'tags', _matches_of_host()).annotate(comment_count=_comment_count_annotation('vulnerability')).order_by('-severity', '-id')
    inverse = {v: k for k, v in SEVERITY_NAMES.items()}
    if params.get('severity') in inverse:
        qs = qs.filter(severity=inverse[params['severity']])
    return paginate(qs, params, _vuln)


def scan_activity(ctx, slug, scan_id, params):
    """The scan's task timeline (what ran, when, whether it failed)."""
    from startScan.models import ScanActivity
    scan = _scan_in_project(ctx, slug, scan_id)
    labels = {-1: 'queued', 0: 'failed', 1: 'running', 2: 'success', 3: 'aborted'}
    qs = ScanActivity.objects.filter(scan_of=scan).order_by('time', 'id')
    return paginate(qs, params, lambda a: {
        'id': a.id, 'title': a.title, 'name': a.name, 'time': _iso(a.time),
        'status': labels.get(a.status, str(a.status)), 'error': a.error_message})


def start_scan(ctx, slug, target_id, engine_id=None):
    """Start discovery on a target. ``engine_id`` is optional and ignored apart from being validated."""
    from cveFeed.discovery import start_discovery
    from scanEngine.models import EngineType
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    domain = Domain.objects.filter(project=project, id=target_id).first()
    if not domain:
        raise ApiError(404, 'target not found')
    _refuse_excluded(project, domain)
    internal = _internal_scan(ctx, project, domain)
    if internal:
        return internal
    if engine_id is not None and not EngineType.objects.filter(id=engine_id).exists():
        raise ApiError(404, 'engine not found')
    scan = start_discovery(domain, _run_mode(domain), initiated_by=ctx.user)
    return {'scan_id': scan.id, 'status': 'queued'}


def _internal_scan(ctx, project, domain):
    """The response of starting a scan on ``domain`` when it is inside a network the project declared internal: it is queued for a Sentinel
    inside that network (``cveFeed.internal_scan``), never discovered or scanned from this server; ``None`` for any other target."""
    from targetApp.target_types import sentinel_only_target
    if not sentinel_only_target(domain.name, project.id):
        return None
    from cveFeed import internal_scan
    try:
        scan = internal_scan.start(domain, initiated_by=ctx.user)
    except ValueError as exc:  # the range, exclusion, or bounty policy changed after the request's first check
        raise ApiError(409, str(exc)) from exc
    return {'scan_id': scan.id, 'status': 'queued', 'internal': True}


def _refuse_excluded(project, domain):
    """409 when the target itself is a host its organization excluded for good."""
    from cveFeed.exclusions import address_excluded, is_excluded
    if is_excluded(project.id, domain.name, names_only=True):
        raise ApiError(409, f'{domain.name} is excluded for this organization and is not scanned')
    refusal = address_excluded(project.id, domain.name)
    if refusal:
        raise ApiError(409, f'{domain.name} is not scanned: {refusal}')


def _abort_scan(scan, user=None):
    """Stop one queued or running scan: mark it and its activities aborted, raise the stop flag (the pipeline exits at its next
    check and each heavy job kills its scanner process tree, which also releases the memory reservation and the ledger and
    domain claims it holds), and revoke the celery task. Returns True when the scan was still active."""
    from django.utils import timezone as tz
    from reNgine import resources
    from reNgine.celery import app as celery_app
    from startScan.models import ScanActivity, ScanHistory
    stopped = ScanHistory.objects.filter(pk=scan.pk, scan_status__in=(-1, 1)).update(
        scan_status=3, stop_scan_date=tz.now(), aborted_by=user, error_message='Stopped by a person')
    if not stopped:
        return False
    ScanActivity.objects.filter(scan_of=scan, status__in=(-1, 1)).update(status=3, time=tz.now(), error_message='Stopped by a person')
    resources.request_abort(scan.pk)
    for task_id in scan.celery_ids or []:
        try:
            celery_app.control.revoke(task_id, terminate=True, signal='SIGTERM')
        except Exception:  # noqa: BLE001 - the flag above is what actually stops the work; a broker hiccup must not fail the stop
            pass
    from cveFeed import activity
    activity.log('scan', f'Stopped the scan of {scan.domain.name} (scan #{scan.pk})', project=scan.domain.project_id, scan_id=scan.pk)
    return True


def stop_scan(ctx, slug, scan_id):
    """Stop one queued or running scan of the project. Needs write access; a finished scan is a 409."""
    from startScan.models import ScanHistory
    project, _ = get_project(ctx, slug, write=True)
    scan = ScanHistory.objects.filter(domain__project=project, id=scan_id).select_related('domain').first()
    if not scan:
        raise ApiError(404, 'scan not found')
    if not _abort_scan(scan, ctx.user):
        raise ApiError(409, 'scan is not queued or running')
    return {'stopped': 1, 'scan_ids': [scan.id]}


def stop_scans(ctx, slug):
    """Stop every queued and running scan of the project."""
    from startScan.models import ScanHistory
    project, _ = get_project(ctx, slug, write=True)
    ids = []
    for scan in ScanHistory.objects.filter(domain__project=project, scan_status__in=(-1, 1)).select_related('domain').order_by('id'):
        if _abort_scan(scan, ctx.user):
            ids.append(scan.id)
    return {'stopped': len(ids), 'scan_ids': ids}


DELETE_MAX_IDS = 5000


def delete_targets(ctx, slug, ids=None, all_matching=False, q=''):
    """Delete targets and everything under them (hosts, scans, findings, result files). Pass ``ids``, or
    ``all_matching`` (optionally narrowed by ``q``, the same search the target list uses). A target with a scan
    still running or queued is skipped, not deleted, and reported. Only this project's targets are ever touched."""
    import os
    from reNgine.common_func import SCAN_RESULTS_ROOT, safe_remove_path
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    qs = Domain.objects.filter(project=project)
    if all_matching:
        if q:
            qs = _target_search(qs, str(q)[:200])
    elif ids is not None:
        if not isinstance(ids, list) or not ids:
            raise ApiError(400, 'ids must be a non-empty list')
        if len(ids) > DELETE_MAX_IDS:
            raise ApiError(400, f'at most {DELETE_MAX_IDS} targets per request; use all_matching to clear a whole list')
        qs = qs.filter(id__in=[_int_param(i, 'ids') for i in ids])
    else:
        raise ApiError(400, 'give ids, or all_matching')
    wanted = list(qs.values_list('id', 'name'))
    busy = set(ScanHistory.objects.filter(domain_id__in=[i for i, _ in wanted], scan_status__in=(-1, 1))
               .values_list('domain_id', flat=True))
    deleted = 0
    todo = [(i, n) for i, n in wanted if i not in busy]
    for start in range(0, len(todo), 200):
        chunk = todo[start:start + 200]
        scan_dirs = [f'{n}_{sid}' for sid, n in ScanHistory.objects.filter(domain_id__in=[i for i, _ in chunk])
                     .values_list('id', 'domain__name')]
        from django.db import transaction
        with transaction.atomic():
            Domain.objects.filter(project=project, id__in=[i for i, _ in chunk]).delete()
            from cveFeed import snapshot_cache
            snapshot_cache.bump_on_commit()  # the targets, hosts and findings under them leave the live screen's numbers
        for name in [n for _, n in chunk] + scan_dirs:  # exact directory names, never a prefix match
            safe_remove_path(os.path.join(SCAN_RESULTS_ROOT, name), SCAN_RESULTS_ROOT)
        deleted += len(chunk)
    if deleted:
        from cveFeed.admin_api import audit
        audit(ctx.user, 'targets.delete', slug, count=deleted, skipped_running=len(busy), project=slug)
    return {'deleted': deleted, 'skipped_running': len(busy), 'matched': len(wanted)}


def _run_mode(domain, mode=None):
    """The mode a person's discovery of ``domain`` runs in: the one asked for (standard, deep or passive), else the one stored on the target.
    A manual only target has no mode to fall back on, so a run of it names one (and discover_target then keeps it)."""
    from targetApp.models import Domain
    if mode in (None, ''):
        if domain.discovery_mode == Domain.DISCOVERY_MANUAL:
            raise ApiError(409, f'{domain.name} is set to manual only (added with "just add them, do not scan yet"): choose standard, deep or passive to discover it')
        return domain.discovery_mode
    if mode not in (Domain.DISCOVERY_STANDARD, Domain.DISCOVERY_DEEP, Domain.DISCOVERY_PASSIVE):
        raise ApiError(400, 'mode must be standard, deep or passive')
    return mode


def discover_target(ctx, slug, target_id, mode=None):
    """Start a bbot discovery plus nuclei pipeline on one existing target, in ``mode`` (kept on the target) or the target's own. The answer
    says what actually happened: ``discovery_mode`` is the mode stored on the target after the call, ``scan_mode`` the mode the returned scan
    runs in (a scan already going keeps the mode it was started in, so the two can differ; an internal target's scan has none, and its stored
    mode is not changed)."""
    from cveFeed.discovery import start_discovery
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    domain = Domain.objects.filter(project=project, id=target_id).first()
    if not domain:
        raise ApiError(404, 'target not found')
    _refuse_excluded(project, domain)
    internal = _internal_scan(ctx, project, domain)
    if internal:
        return {**internal, 'discovery_mode': domain.discovery_mode, 'scan_mode': ''}
    run = _run_mode(domain, mode)
    scan = start_discovery(domain, run, initiated_by=ctx.user)
    if run != domain.discovery_mode:  # a mode chosen here is the mode the target is rescanned in from now on
        domain.discovery_mode = run
        domain.save(update_fields=['discovery_mode'])
    return {'scan_id': scan.id, 'status': 'started', 'discovery_mode': domain.discovery_mode, 'scan_mode': scan.discovery_mode or run}


RESCAN_MAX_HOSTS = 200


def rescan_hosts(ctx, slug, target_id, hosts):
    """Take specific hosts of a target through nmap, the exposure check, nuclei and correlation now, without a bbot run. The
    hosts must be the target itself or under it; scanners still skip what they covered inside their window."""
    from cveFeed.tasks import host_pipeline
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    domain = Domain.objects.filter(project=project, id=target_id).first()
    if not domain:
        raise ApiError(404, 'target not found')
    if isinstance(hosts, str):
        hosts = re.split(r'[\s,]+', hosts)
    if not isinstance(hosts, (list, tuple)) or not hosts:
        raise ApiError(400, 'hosts must be a non-empty list of host names')
    hosts = hosts[:RESCAN_MAX_HOSTS * 10]  # what is read is bounded; the first RESCAN_MAX_HOSTS that qualify are queued
    names = list(dict.fromkeys(str(h).strip().lower().rstrip('.') for h in hosts if str(h).strip()))
    from cveFeed.exclusions import drop_excluded
    inside = drop_excluded(project.id, [n for n in names if domain.includes_host(n)])  # excluded hosts are never scanned
    if not inside:
        if domain.exact_host_only():
            raise ApiError(400, f'{domain.name} is scoped to that host only: none of the hosts is {domain.name}')
        raise ApiError(400, f'none of the hosts is {domain.name} or under it')
    inside = inside[:RESCAN_MAX_HOSTS]
    host_pipeline.delay(domain.id, inside, by_person=True)
    return {'queued': len(inside), 'skipped': len(names) - len(inside), 'target_id': domain.id}


def _host_id(value):
    if value in (None, ''):
        raise ApiError(400, 'missing field(s): host_id')
    return _int_param(value, 'host_id')


def request_host_assessment(ctx, slug, host_id):
    """Queue a fresh assessment of one inventory row, with the project and target taken from storage."""
    from cveFeed.host_assessment import enqueue, serialize
    from startScan.models import Subdomain
    project, _ = get_project(ctx, slug, write=True)  # first: an ``_all`` or read-only caller is refused before the body is read
    host_id = _host_id(host_id)
    sub = Subdomain.objects.filter(pk=host_id, target_domain__project=project).select_related('target_domain').first()
    if not sub:
        raise ApiError(404, 'host not found')
    try:
        job, created = enqueue(project, sub, user=ctx.user)
    except ValueError as exc:
        raise ApiError(409, str(exc)) from exc
    except RuntimeError as exc:
        raise ApiError(429, str(exc)) from exc
    return {**serialize(job), 'created': created}


def _screenshot_host_row(ctx, slug, host_id, write):
    from startScan.models import Subdomain
    project, _ = get_project(ctx, slug, write=True) if write else get_one_project(ctx, slug)
    sub = (Subdomain.objects.filter(pk=_host_id(host_id), target_domain__project=project).select_related('target_domain')
           .prefetch_related('ip_addresses__ports').first())
    if not sub:
        raise ApiError(404, 'host not found')
    return project, sub


def request_host_screenshot(ctx, slug, host_id):
    """Take screenshot: queue a fresh browser capture of every web page of one inventoried host (cveFeed.web_shot; a Sentinel takes it, and the pages wait while none can). It goes through the same
    gates as a host assessment (scope, exclusions, archive, the bug bounty program's scope) and is allowed for a person even where the program has
    not confirmed automated testing. The pictures arrive within a minute or so; ``GET .../screenshots`` shows how it went."""
    from cveFeed import web_shot
    from cveFeed.host_assessment import _admit
    project, sub = _screenshot_host_row(ctx, slug, host_id, write=True)  # first: an ``_all`` or read-only caller is refused before anything else
    try:
        _admit(project, sub, unattended=False)
    except ValueError as exc:
        raise ApiError(409, str(exc)) from exc
    why = web_shot.unavailable_reason()
    if why:
        raise ApiError(503, why)
    summary = web_shot.queue_host(project, sub, by_person=True)
    rows = host_screenshots(ctx, slug, host_id)
    if summary['blocked'] and not summary['queued']:
        raise ApiError(409, rows['note'] or 'this host cannot be photographed', screenshots=rows['screenshots'])
    return {**rows, 'status': 'queued' if summary['queued'] or summary['kept'] else 'nothing_to_capture', 'queued': summary['queued'],
            'pages': summary['targets']}


def host_screenshots(ctx, slug, host_id):
    """What the browser captures of one host say: every page's outcome and reason, and whether anything is waiting."""
    from cveFeed import web_shot
    from cveFeed.models import HostScreenshot
    project, sub = _screenshot_host_row(ctx, slug, host_id, write=False)
    name = web_shot.host_of(sub)
    rows = list(HostScreenshot.objects.filter(project=project, host=name))
    shown = web_shot.pictures(rows)
    return {'host': name, 'host_id': sub.pk, 'available': web_shot.available(), 'unavailable_reason': web_shot.unavailable_reason() or None,
            'queued': sum(1 for r in rows if r.outcome == 'queued'),
            'screenshots': [web_shot.describe(r, name) for r in sorted(rows, key=web_shot.rank)],
            'note': web_shot.note_for(rows, has_web_evidence=bool(web_shot.web_targets(sub)), legacy=not shown and bool(sub.screenshot_path))}


def get_host_assessment(ctx, slug, assessment_id):
    from cveFeed.host_assessment import serialize
    from cveFeed.models import HostAssessment
    project, _ = get_one_project(ctx, slug)  # an assessment belongs to one project; ``_all`` is a 400, not a crash
    job = HostAssessment.objects.filter(pk=assessment_id, project=project).first()
    if not job:
        raise ApiError(404, 'host assessment not found')
    return serialize(job)


def latest_host_assessment(ctx, slug, host_id):
    from cveFeed.host_assessment import serialize
    from cveFeed.models import HostAssessment
    from startScan.models import Subdomain
    project, _ = get_one_project(ctx, slug)
    sub = Subdomain.objects.filter(pk=_host_id(host_id), target_domain__project=project).first()
    if not sub:
        raise ApiError(404, 'host not found')
    job = HostAssessment.objects.filter(project=project, host=sub.name.lower().rstrip('.')).order_by('-id').first()
    return serialize(job) if job else {'status': 'never_requested'}


def stop_host_assessment(ctx, slug, assessment_id):
    from cveFeed.models import HostAssessment
    project, _ = get_project(ctx, slug, write=True)
    job = HostAssessment.objects.filter(pk=assessment_id, project=project).select_related('scan').first()
    if not job:
        raise ApiError(404, 'host assessment not found')
    if job.status not in ('queued', 'running'):
        return {'id': job.pk, 'status': job.status}
    HostAssessment.objects.filter(pk=job.pk, status__in=('queued', 'running')).update(
        status='stopped', finished_at=timezone.now(), error='Stopped by a person')
    if job.scan_id:
        from cveFeed.host_assessment import BATCH_STOPPED
        # a batch is one scan over several hosts: stopping one host's assessment stops the run, the only way to stop scanning that host (stages cannot
        # drop one host mid-run). The other hosts it carried are settled now with a reason of their own, which a first-pass sweep does not count as
        # an attempt (``coverage_topup.host_coverage_due``), so they are queued again by the next sweep instead of waiting out the 24 hours
        HostAssessment.objects.filter(scan_id=job.scan_id, status__in=('queued', 'running')).update(
            status='stopped', finished_at=timezone.now(), error=BATCH_STOPPED)
        _abort_scan(job.scan, ctx.user)
    return {'id': job.pk, 'status': 'stopped'}


BULK_MAX_ENTRIES = TARGET_EXPAND_CAP  # lines one bulk request may carry
BULK_MAX_EXPANDED = TARGET_EXPAND_CAP  # rows one request may create after expanding ranges (a /8 per line is never built)


def _start_discoveries(domains, mode, project_id, initiated_by=None):
    """Queue discovery for each domain with one summary line in the AI feed instead of one per target."""
    from cveFeed import activity
    from cveFeed.discovery import start_discoveries
    from reNgine import discovery_events as bbot_lib
    mode = mode or bbot_lib.DEFAULT_MODE
    scans = start_discoveries(domains, mode, quiet=True, initiated_by=initiated_by)
    if scans:
        activity.log('discovery', f'Queued {mode} discovery of {len(scans)} target{"s" if len(scans) != 1 else ""}', project=project_id)
    return scans


BULK_DISCOVER_NOW = 50  # targets one add queues for discovery at once (CVENGINE_BULK_DISCOVER_NOW); the work conductor takes the rest


def _discover_new(domains, mode, project_id, initiated_by=None):
    """Queue discovery for the first ``BULK_DISCOVER_NOW`` of ``domains`` and leave the rest to the work conductor. Returns ``(scans, deferred)``.

    One request that adds hundreds of targets used to queue hundreds of scans in the same second: first in, first out, so every other project's
    scans waited behind them. The conductor already feeds the discovery queue with the targets that have never been scanned or have waited
    longest, one per project per minute, so the targets left for it are scanned all the same and interleaved with everyone else's. With the
    conductor off (``CVENGINE_WORK_DEPTH=0``) nothing would pick them up, so then every target is queued now."""
    from cveFeed import activity, conductor
    from cveFeed import tunables
    cap = max(1, int(tunables.value('bulk_discover_now', BULK_DISCOVER_NOW)))  # saved on Settings, configMaxxing, else CVENGINE_BULK_DISCOVER_NOW, else 50
    if not conductor.wanted_depth():
        cap = len(domains) or 1
    else:  # what the project already has waiting counts against the batch: two pastes in a row are not two batches
        from cveFeed.discovery import QUEUED
        from startScan.models import ScanHistory
        cap = max(0, cap - ScanHistory.objects.filter(domain__project_id=project_id, scan_status=QUEUED).count())
    now, rest = domains[:cap], domains[cap:]
    scans = _start_discoveries(now, mode, project_id, initiated_by=initiated_by) if now else []
    if rest:
        activity.log('discovery', f'{len(rest)} more new target{"s" if len(rest) != 1 else ""} will be scanned by the work conductor, one project at a '
                                  f'time, instead of all being queued at once ({len(now)} were queued now)', project=project_id)
    return scans, len(rest)


_SCHEME_RE = re.compile(r'^[a-z][a-z0-9+.\-]*://', re.I)
# Both parts are bounded and cannot contain another '[' or '(': a long run of '[' with no ']' then costs one short scan per '[',
# not a scan to the end of the line for each (the unbounded form was quadratic, and it runs before any authorization).
_MD_LINK_RE = re.compile(r'\[[^\[\]]{0,500}\]\(([^()\s]{0,2048})\)')
MAX_TARGET_TEXT = 2_000_000  # characters of pasted text one request may carry
MAX_TARGET_TOKEN = 2048  # a longer token is never a domain, IP, CIDR or range
_CIDR_LIKE_RE = re.compile(r'^[0-9a-fA-F:.]+/\d{1,3}$')
_HOST_PORT_RE = re.compile(r'^(.+):(\d{1,5})$')


def normalize_target(token):
    """Reduce one pasted token to the thing to scan: a URL (any scheme: http://, https://, ssh://, ...) becomes its host,
    with credentials, port, path, query and fragment dropped; ``*.example.com`` and ``example.com.`` lose the wildcard and
    the trailing dot; a single-address CIDR (/32, /128) becomes the bare IP. Domains, IPs, CIDRs and ranges pass through. A leading ``-``
    (exclude) or ``=`` (exactly this host) is kept in front of the normalized rest."""
    t = (token or '').strip().strip('"\'<>`,;')
    if not t:
        return ''
    if t.startswith('-') and len(t) > 1:  # "-example.com": exclude it (see _add_targets)
        rest = normalize_target(t[1:])
        return '-' + rest if rest and not rest.startswith('-') else ''
    if t.startswith(HOST_ONLY_MARK) and len(t) > 1:  # "=example.com": add exactly this host (see add_entries); "==x" or "=-x" stays invalid
        rest = normalize_target(t[1:])
        return HOST_ONLY_MARK + rest if rest else ''
    if _SCHEME_RE.match(t):
        t = _SCHEME_RE.sub('', t, count=1)
    elif not _CIDR_LIKE_RE.match(t) and '/' in t:
        pass  # host/path with no scheme: the split below handles it
    if not _CIDR_LIKE_RE.match(t):
        t = re.split(r'[/?#]', t, maxsplit=1)[0]  # drop path, query, fragment
        t = t.rsplit('@', 1)[-1]  # drop user:password@
        if t.startswith('['):  # [v6]:port
            t = t[1:].split(']', 1)[0]
        else:
            m = _HOST_PORT_RE.match(t)
            if m and t.count(':') == 1:
                t = m.group(1)
    t = t.lower().rstrip('.')
    if t.startswith('*.'):
        t = t[2:]
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})/32$', t) or re.match(r'^([0-9a-f:]+)/128$', t)
    return m.group(1) if m else t


def parse_target_list(text):
    """Split pasted text (newlines, commas, spaces, # comments, markdown links, URLs) into unique targets, in order. A ``=`` standing alone
    marks the next entry on its line (``= example.com`` is ``=example.com``); one left at the end of a line stays, to be reported."""
    seen, out = set(), []

    def keep(token):
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    for line in (text or '')[:MAX_TARGET_TEXT].splitlines():
        line = _MD_LINK_RE.sub(r'\1', line.split('#', 1)[0])  # a comment, then [text](url) -> url
        mark = False
        for token in re.split(r'[,\s;]+', line):
            if not token or len(token) > MAX_TARGET_TOKEN:
                continue
            if token.strip('"\'<>`,;') == HOST_ONLY_MARK:  # "= example.com": the mark belongs to the entry after it
                mark = True
                continue
            if mark:
                token, mark = HOST_ONLY_MARK + token, False
            keep(normalize_target(token))
        if mark:
            keep(HOST_ONLY_MARK)  # a mark with nothing after it: "not a domain", reported like any invalid entry
    return out


BULK_MAX_PROJECTS = 50
BULK_MAX_EXCLUSIONS = 100  # ``-domain`` lines one Add targets paste may carry; each one purges a whole domain tree organization-wide


def has_org_headers(text):
    """True when the paste uses group headers: a ``##Org`` line or any ``#Name`` line (``# a comment`` with a space
    after the hash is a comment, not a header)."""
    return any(re.match(r'^\s*#\S', line) for line in (text or '').splitlines())


def parse_org_text(text, default_project=None, max_entries=None, max_projects=None):
    """Parse the grouped bulk format: an optional ``##Organization``, ``#Project`` to open a project, and the targets
    (any separator parse_target_list takes) under it. Returns (org_name or None, [(project, [targets])], errors).
    Targets above the first project header go to ``default_project`` when given, else they are reported; a second
    ``##`` header is reported. ``# comment`` lines are ignored. Linear in the size of the paste (a set per project does
    the de-duplication); ``max_entries`` / ``max_projects`` stop the parse with a 400 as soon as the paste carries more, so
    an oversized paste is refused before it is walked to the end."""
    org, groups, errors, current = None, [], [], None
    by_name, seen, total = {}, {}, 0  # project name (lower case) -> group; id(group) -> its entries as a set; entries kept so far

    def open_project(name):
        group = by_name.get(name.lower())
        if group is None:
            if max_projects is not None and len(groups) >= max_projects:
                raise ApiError(400, f'more than {max_projects} projects; the limit is {max_projects} per request')
            group = (name, [])
            by_name[name.lower()] = group
            seen[id(group)] = set()
            groups.append(group)
        return group

    for raw in (text or '').splitlines():
        line = raw.strip()
        if line.startswith('##'):
            name = line.lstrip('#').strip()
            if not name:
                continue
            if org is not None and name.lower() != org.lower():
                errors.append({'value': f'##{name}', 'error': 'only one organization per paste'})
            elif org is None:
                org = name
            continue
        if line.startswith('#'):
            name = line[1:].strip()
            if name and not line[1:2].isspace():  # "#Name" opens a project; "# note" is a comment
                current = open_project(name)
            continue
        for entry in parse_target_list(line):
            if current is None and default_project:
                current = open_project(default_project)
            if current is None:
                errors.append({'value': entry, 'error': 'no #Project header above this line'})
            elif entry not in seen[id(current)]:
                seen[id(current)].add(entry)
                current[1].append(entry)
                total += 1
                if max_entries is not None and total > max_entries:
                    raise ApiError(400, f'more than {max_entries} entries; the limit is {max_entries} per request')
    return org, groups, errors


def _visible_org(user, org):
    from dashboard.models import OrgMembership, ProjectMembership
    return bool(org) and (user.is_superuser or OrgMembership.objects.filter(user=user, org=org).exists()
                          or ProjectMembership.objects.filter(user=user, project__org=org).exists())


def _current_org(user, current_slug=None):
    """The organization the user is working in: that of the project they are viewing, else the first org they belong
    to. Returns (org, project or None)."""
    from dashboard.models import Org, OrgMembership, Project, ProjectMembership
    project = Project.objects.filter(slug=current_slug).first() if current_slug else None  # scoped: only visible ones
    if project and project.org_id and _visible_org(user, project.org):
        return project.org, project
    membership = OrgMembership.objects.filter(user=user).select_related('org').order_by('id').first()
    if membership:
        return membership.org, None
    pm = ProjectMembership.objects.filter(user=user, project__org__isnull=False).select_related('project__org').order_by('id').first()
    if pm:
        return pm.project.org, None
    if user.is_superuser:
        return Org.objects.order_by('id').first(), None
    return None, None


def _org_for_bulk(ctx, name, current_slug=None):
    """The organization to use and a note when it is not the one named. A named organization that exists and that
    the caller belongs to is used; one that does not exist (or that the caller cannot see, which looks the same)
    falls back to the caller's current organization, so nothing is created and no org name can be probed."""
    from django.utils.text import slugify
    from dashboard.models import Org
    user = ctx.user
    if name:
        org = Org.objects.filter(name__iexact=name).first() or Org.objects.filter(slug=slugify(name)).first()
        if _visible_org(user, org):
            return org, None
    org, _ = _current_org(user, current_slug)
    if org is None:
        raise ApiError(403, 'you are not a member of any organization')
    if name:
        return org, f'organization "{name}" does not exist, so the projects went into your current organization "{org.name}"'
    return org, None


def _audit(user, action, target, org):
    from dashboard.models import AuditLog
    AuditLog.objects.create(actor=user, actor_name=user.username, action=action, target=target[:300], org_id=org.pk, detail={'via': 'bulk'})


def add_targets_by_org(ctx, text, discover=True, mode=None, current_project=None, scope_mode=None):
    """Bulk add across one organization's projects from the ``##Org`` / ``#Project`` paste format. Missing
    projects are created (needs the org admin role); every project's targets are added with that project's own
    write check, so one forbidden or invalid section never blocks the others. With no ``##Org`` (or one that does not
    exist) the caller's current organization is used; ``current_project`` is the project they are viewing, which
    also receives any targets that appear above the first ``#Project`` header. ``scope_mode`` is the scope of every new domain target, and an
    ``=example.com`` line is exactly that host (see ``add_entries``)."""
    from django.utils.text import slugify
    from dashboard.models import Project
    require_write_token(ctx)
    if not isinstance(text, str):
        raise ApiError(400, 'text must be pasted text')
    manual = _discovery_mode(mode) == 'manual'
    batch_scope = _scope_mode(scope_mode)
    org, current = _current_org(ctx.user, current_project)
    if org is None:  # authorize before the paste is read: a caller with no organization gets nothing parsed
        raise ApiError(403, 'you are not a member of any organization')
    org_name, groups, errors = parse_org_text(text, default_project=current.name if current else None,
                                              max_entries=BULK_MAX_ENTRIES, max_projects=BULK_MAX_PROJECTS)
    if not groups:
        raise ApiError(400, 'no #Project sections found')
    org, org_note = _org_for_bulk(ctx, org_name, current_project)
    can_create = roles.can_manage_org(ctx.user, org.id)
    results = []
    used, note = mode, None
    scan_ids, deferred = [], 0
    for pname, entries in groups:
        res = {'project': pname, 'slug': None, 'project_created': False, 'received': len(entries), 'created': 0,
               'already_exists': [], 'invalid': [], 'excluded': [], 'error': None, 'scope_modes': {}}
        results.append(res)
        try:
            project = Project.objects.filter(org=org, name__iexact=pname).first()
            if project is None:
                if not can_create:
                    raise ApiError(403, f'creating a project in "{org.name}" needs the admin role there')
                if not 2 <= len(pname) <= 100:
                    raise ApiError(400, 'project names are 2 to 100 characters')
                if roles.is_reserved_project(pname):  # "_all" is the slug of the all-projects view, never a project
                    raise ApiError(400, f'"{roles.ALL_PROJECTS}" is reserved for the all-projects view; choose another project name')
                base = slugify(pname)[:50] or 'project'
                slug, n = base, 2
                while Project._base_manager.filter(slug=slug).exists() or roles.is_reserved_project(slug):  # unscoped: a slug taken by a project the caller cannot see still counts
                    slug, n = f'{base}-{n}', n + 1
                project = Project.objects.create(name=pname, slug=slug, insert_date=timezone.now(), org=org)
                _audit(ctx.user, 'project.create', pname, org)
                res['project_created'] = True
            res['slug'] = project.slug
            if not entries:
                continue
            added = _add_targets(ctx, project.slug, entries, False, used, batch_scope)  # the mode and scope are stored with the targets; discovery is queued below
            res.update(created=added['created'], already_exists=added['already_exists'], invalid=added['invalid'], excluded=added['excluded'],
                       scope_modes=added['scope_modes'])
            if discover and not manual and added['domains']:
                scans, left = _discover_new(added['domains'], used, project.id, initiated_by=ctx.user)
                scan_ids += [scan.id for scan in scans]
                deferred += left
        except ApiError as exc:
            res['error'] = exc.message
    return {'organization': org.name, 'organization_note': org_note, 'projects': results, 'created': sum(r['created'] for r in results),
            'projects_created': sum(r['project_created'] for r in results), 'invalid': errors,
            'discovery_started': len(scan_ids), 'discovery_deferred': deferred, 'scan_ids': scan_ids, 'mode': used, 'mode_note': note,
            'scope_mode': batch_scope}


def add_targets(ctx, slug, values, discover=True, mode=None, scope_mode=None):
    out = _add_targets(ctx, slug, values, discover, mode, scope_mode)
    out.pop('domains')
    return out


def _exclude_patterns(ctx, slug, patterns):
    """Apply the ``-example.com`` lines of an Add targets paste: each excludes the domain and everything under it for the whole
    organization and removes its hosts and targets. ``(done, refused)``: what each removed, and the lines that could not be applied
    (no organization-level role, not a domain name ...)."""
    from agentapi import host_manage
    done, refused = [], []
    for pattern in dict.fromkeys(patterns):
        try:
            r = host_manage.exclude_host(ctx, slug, pattern, reason='Excluded from Add targets', include_subdomains=True)
        except ApiError as exc:
            refused.append({'value': '-' + pattern, 'error': exc.message})
            continue
        done.append({'pattern': r['host'], 'hosts_removed': r['hosts_removed'], 'targets_removed': r['targets_removed'],
                     'findings_removed': r['findings_removed'], 'projects_affected': r['projects_affected']})
    return done, refused


def _add_targets(ctx, slug, values, discover, mode, scope_mode=None):
    """Add many targets at once. ``values`` is a list or pasted text. Each entry is validated on its own, so one
    bad line never blocks the rest; the response says what happened to every line. Every target that is created is
    queued for discovery, first in, first out. ``scope_mode`` is the batch's scope; an ``=example.com`` entry is host whatever it says."""
    project, _ = get_project(ctx, slug, write=True)
    _discovery_mode(mode)  # before the exclusions below, which cannot be undone
    batch_scope = _scope_mode(scope_mode)
    if values is not None and not isinstance(values, (str, list)):
        raise ApiError(400, 'targets must be a list or pasted text')
    entries = parse_target_list(values) if isinstance(values, str) else [t for t in dict.fromkeys(normalize_target(str(v)) for v in (values or [])) if t]
    if not entries:
        raise ApiError(400, 'no targets found in the input')
    patterns = [e[1:] for e in entries if e.startswith('-')]  # "-example.com": exclude that domain and everything under it
    entries = [e for e in entries if not e.startswith('-')]
    if len(entries) + len(patterns) > BULK_MAX_ENTRIES:  # before the exclusions below: each is an irreversible organization-wide purge
        raise ApiError(400, f'{len(entries) + len(patterns)} entries; the limit is {BULK_MAX_ENTRIES} per request')
    if len(patterns) > BULK_MAX_EXCLUSIONS:
        raise ApiError(400, f'{len(patterns)} exclusions; the limit is {BULK_MAX_EXCLUSIONS} per request')
    excluded, refused = _exclude_patterns(ctx, slug, patterns)  # first, so nothing added below can land inside what was just excluded
    if not entries:
        return {'received': len(patterns), 'created': 0, 'created_names': [], 'domains': [], 'already_exists': [], 'invalid': refused,
                'excluded': excluded, 'discovery_started': 0, 'scan_ids': [], 'mode': mode, 'mode_note': None,
                'scope_mode': batch_scope, 'scope_modes': {}}
    return add_entries(project, entries, discover, mode, excluded, refused, initiated_by=ctx.user, scope_mode=batch_scope)


def add_entries(project, entries, discover=True, mode=None, excluded=(), refused=(), initiated_by=None, scope_mode=None):
    """Add already-normalized targets to ``project``: the part of Add targets that does not depend on who is asking, so an automated
    source (the runZero import) goes through the same expansion, private-range policy, organization exclusions, organization-wide
    uniqueness and discovery queueing. The caller has already checked that it may write to ``project``.

    ``initiated_by`` is recorded on the ``ScanHistory`` rows discovery queues for the newly-created targets; left unset (as the
    runZero import leaves it) for a source with no asking user.

    ``scope_mode`` (auto when omitted, what every target was created with before it existed) is stored on each new domain target; an entry
    written ``=example.com`` is created as host (exactly that host) whatever the batch says, and wins over the same name written without it.
    An address, CIDR or range has no subdomains: the mark and the batch scope are ignored for it."""
    from targetApp.models import Domain
    from targetApp.target_types import DOMAIN
    if len(entries) > BULK_MAX_ENTRIES:
        raise ApiError(400, f'{len(entries)} entries; the limit is {BULK_MAX_ENTRIES} per request')
    stored = _discovery_mode(mode)  # kept on every target this creates: the mode its later automatic scans use
    batch_scope = _scope_mode(scope_mode)
    received = len(entries)
    marked, plain, written = set(), [], {}
    for entry in entries:
        name, exact = split_scope_mark(entry)
        if exact:
            marked.add(name)
        plain.append(name)
        written.setdefault(name, entry)  # what the person wrote, for a line that is reported back
    entries = list(dict.fromkeys(plain))  # "=example.com" and "example.com" in one paste are one target, created as exactly that host
    names, domain_names, invalid, seen = [], [], [], set()
    for entry in entries:
        if len(names) >= BULK_MAX_EXPANDED:
            invalid.append({'value': written[entry], 'error': f'skipped: one request may add at most {BULK_MAX_EXPANDED} targets after expanding ranges'})
            continue
        try:
            kind, expanded = _expand_target(entry, project.id)
        except ApiError as exc:
            invalid.append({'value': written[entry], 'error': exc.message})
            continue
        fresh = [n for n in dict.fromkeys(expanded) if n not in seen]
        if len(names) + len(fresh) > BULK_MAX_EXPANDED:  # the cap counts what is added, so the last range cannot overshoot it
            invalid.append({'value': written[entry], 'error': f'skipped: one request may add at most {BULK_MAX_EXPANDED} targets after expanding ranges'})
            continue
        for name in fresh:
            seen.add(name)
            names.append(name)
            if kind == DOMAIN:
                domain_names.append(name)
    skipped = []
    scopes = {n: (Domain.SCOPE_HOST if n in marked else batch_scope) for n in domain_names}
    created, existing = _create_domains(project, names, excluded=skipped, discovery_mode=stored, scopes=scopes)
    invalid += [{'value': n, 'error': 'excluded for this organization: never added or scanned'} for n in skipped]
    invalid += refused
    if domain_names:  # domain targets are watched for new certificates going forward
        from cveFeed import ct_queue
        names_wanted = set(domain_names)
        wanted = [d for d in created if d.name in names_wanted and not d.exact_host_only()]  # exactly one host: no name under it would be taken
        ct_queue.queue_lookups([d.id for d in wanted], ct_queue.ADD_LIFETIME)  # spaced out (crt.sh blocks a burst), marked, and expiring
    scan_ids, used, note, deferred = [], mode, None, 0
    to_discover = _not_internal(project, created)  # targets inside a declared internal network are a Sentinel's to scan, never discovered from here
    if discover and to_discover and stored != Domain.DISCOVERY_MANUAL:  # manual: "just add them, do not scan yet"
        scans, deferred = _discover_new(to_discover, used, project.id, initiated_by=initiated_by)
        scan_ids = [scan.id for scan in scans]
    return {'received': received, 'created': len(created), 'created_names': [d.name for d in created][:200],
            'domains': created, 'already_exists': existing, 'invalid': invalid, 'excluded': excluded,
            'discovery_started': len(scan_ids), 'discovery_deferred': deferred, 'scan_ids': scan_ids, 'mode': used, 'mode_note': note,
            'scope_mode': batch_scope, 'scope_modes': {d.name: d.scope_mode for d in created[:200]}}


# --- inventory and findings ----------------------------------------------------

def _heat_reasons(sub, capped=True):
    """What a host's colour rests on: its CVE matches (rated as they apply to a host) and its open findings, hottest first. ``capped=False``
    rates each CVE match by ``threat.validation_heat`` (the heat once proven): what a confirmer (OpenVAS) orders hosts by. Each CVE reason says
    why it has its heat (``threat.heat_reason``: "on the KEV; version not proven", "not on the KEV and no known exploit", ...)."""
    from cveFeed.counts import finding_is_live, match_is_live
    from cveFeed.distro import label_for
    from cveFeed.threat import (LEGACY_POLICY, SEVERITY_HEAT, finding_cve_names, finding_heat, finding_heat_reason, heat_policy, heat_reason,
                                hot_cve_names, match_heat, validation_heat)
    reasons = []
    for m in sub.cve_matches.all():
        if not match_is_live(m):  # ruled out by the AI, or closed (fixed, accepted risk, false positive): not a reason for the host's colour
            continue
        c = m.cve_entry
        uncapped, shown = validation_heat(m), match_heat(m)
        temp = shown if capped else uncapped
        held = shown != uncapped  # a match held below the heat it would have once proven: say so, so KEV is never hidden
        why = heat_reason(m, shown)
        reasons.append({'kind': 'cve', 'label': c.cve_id, 'description': _cve_description(c, 180),
                        'detail': (f'CVSS {c.cvss}' if c.cvss is not None else 'no score') +
                        (', listed as exploited' if c.kev else '') + (', AI confirmed' if m.ai_verdict == 'affected' else '') +
                        (f', {label_for(m.distro_status, m.distro_fixed_version)}' if m.distro_status in ('patched', 'vulnerable') else '') +
                        (f': {why}' if why else ''),
                        'temp': temp, 'kev': bool(c.kev), 'heat_capped': held, 'heat_reason': why,
                        'finding': 'match', 'id': m.id, 'classification': _classification_of(m)})
    # a scanner finding that names CVEs follows the CVE rule under the KEV policy (threat.finding_heat); any other keeps its severity heat
    live = [v for v in sub.vulnerability_set.all() if finding_is_live(v) and v.severity in SEVERITY_HEAT]
    hot = (hot_cve_names({n for v in live for n in finding_cve_names(v)}) if live and heat_policy() != LEGACY_POLICY else set())
    for v in live:
        temp = finding_heat(v, capped=capped, hot_names=hot)
        why = finding_heat_reason(v, temp, hot)
        reasons.append({'kind': 'finding', 'label': v.name, 'detail': SEVERITY_NAMES.get(v.severity, str(v.severity)) + (f': {why}' if why else ''),
                        'temp': temp, 'finding': 'vulnerability', 'id': v.id, **({'heat_reason': why} if why else {}),
                        'classification': _classification_of(v)})
    rank = {'fire': 0, 'smoke': 1, 'ice': 2}
    return sorted(reasons, key=lambda r: rank.get(r['temp'], 3))


NUCLEI_STAGES = NUCLEI_SCAN_ACTIVITY_NAMES  # see cveFeed.discovery.NUCLEI_SCAN_ACTIVITY_NAMES: the one shared list of stage names that mean "nuclei ran"


def _host_heat(sub, reasons=None):
    """The host's worst threat temperature (fire, smoke, ice, clean or unscanned), for the colour in lists and maps."""
    from cveFeed.threat import HEAT_RANK
    reasons = _heat_reasons(sub) if reasons is None else reasons
    if reasons:
        return max((r['temp'] for r in reasons), key=HEAT_RANK.get)
    from startScan.models import ScanActivity
    scan_ran = getattr(sub, '_nuclei_ran_scan', None)  # set for a whole page at once by ``_prime_nuclei``
    if scan_ran is None:
        scan_ran = bool(sub.scan_history_id and ScanActivity.objects.filter(scan_of_id=sub.scan_history_id, name__in=NUCLEI_STAGES, status=2).exists())
    return 'clean' if bool(sub.vulnerability_set.all()) or scan_ran else 'unscanned'


def _prime_nuclei(*groups):
    """Read, for every host row of ``groups`` (lists of Subdomain rows) at once, whether a nuclei stage finished in the scan that wrote it: one query,
    where ``_host_heat`` asked once per host with no finding (the dearest part of listing a few thousand clean hosts)."""
    from startScan.models import ScanActivity
    rows = [r for group in groups for r in group if r.scan_history_id]
    if not rows:
        return
    done = set(ScanActivity.objects.filter(scan_of_id__in={r.scan_history_id for r in rows}, name__in=NUCLEI_STAGES, status=2).values_list('scan_of_id', flat=True).distinct())
    for r in rows:
        r._nuclei_ran_scan = r.scan_history_id in done


def _host_names(sub):
    """Names an IP target answers to (reverse DNS and certificate), recorded at discovery. Not added as targets: they may be
    out of scope. Empty for a hostname."""
    from cveFeed.models import DiscoveryEvent
    from targetApp.target_types import IP, classify_target
    if classify_target(sub.name) != IP or not sub.target_domain_id:
        return []
    return sorted({(e.module, e.label) for e in DiscoveryEvent.objects.filter(
        domain_id=sub.target_domain_id, host=sub.name, module__in=('ptr', 'tls-san'))})


def _also_served(sub, ips, shared):
    """The other sites the virtual host sweep found on this host's addresses: ``[{'name', 'address', 'status', 'title'}]``, not the host itself."""
    project = sub.target_domain.project_id if sub.target_domain else None
    found = (shared or {}).get('vhosts') or {}
    out = []
    for address in sorted(ips):
        for row in found.get((project, address), []):
            if row.host.lower() != sub.name.lower():
                answer = (row.evidence or {}).get('answer', {})
                out.append({'name': row.host, 'address': address, 'status': answer.get('status'), 'title': answer.get('title', '')})
    return out[:20]


def _merge_group(sub, others):
    """The whole host as one: ``sub`` (the richest copy of the name) plus its other current-inventory copies. IPs are merged by
    address and ports by (address, number, protocol), CVE matches by CVE id and open findings by id, so the counts agree with the
    score and the web routes, which are both read by name."""
    from cveFeed.counts import finding_is_live, match_is_live
    from cveFeed.threat import HEAT_RANK
    from startScan.models import open_services
    ips, seen_ports = {}, set()
    reasons, seen_reasons = [], {}
    vulns, seen_vulns = {}, set()
    cves = set()
    for row in [sub, *others]:
        for ip in row.ip_addresses.all():
            entry = ips.setdefault(ip.address, {'ip': ip, 'ports': []})
            if ip.full_scanned_at and (not entry['ip'].full_scanned_at or ip.full_scanned_at > entry['ip'].full_scanned_at):
                entry['ip'] = ip
            for p in open_services(ip):
                key = (ip.address, p.number, p.protocol)
                if key not in seen_ports:
                    seen_ports.add(key)
                    entry['ports'].append(p)
        for r in _heat_reasons(row):
            key = (r['kind'], r['finding'], r['label'] if r['kind'] == 'cve' else r['id'])
            if key not in seen_reasons:
                seen_reasons[key] = len(reasons)
                reasons.append(r)
            elif HEAT_RANK.get(r['temp'], 0) > HEAT_RANK.get(reasons[seen_reasons[key]]['temp'], 0):
                # one CVE on two copies (or two products) of the host: the hotter one speaks for it, so a validated copy is not hidden
                # behind a version-only one that the cap holds at smoke
                reasons[seen_reasons[key]] = r
        for m in row.cve_matches.all():
            if match_is_live(m):
                cves.add(m.cve_entry.cve_id)
        for v in row.vulnerability_set.all():
            if finding_is_live(v) and v.id not in seen_vulns:
                seen_vulns.add(v.id)
                vulns[v.id] = v
    rank = {'fire': 0, 'smoke': 1, 'ice': 2}
    reasons.sort(key=lambda r: rank.get(r['temp'], 3))
    return ips, reasons, sorted(vulns.values(), key=lambda v: -v.severity), len(cves)


def _host(sub, others=(), labels=(), profile=None, excluded=False, root=None, shared=None):
    """One host row. ``others`` are the same name's other current-inventory Subdomain rows (see ``_name_siblings``): the counts, IPs,
    ports, matches and open findings cover all of them, while score, technologies and screenshot come from ``sub``."""
    ips, reasons, vulns, cve_count = _merge_group(sub, others)
    techs = {t.name for row in [sub, *others] for t in row.technologies.all() if t.name}
    score_detail = list(sub.score_detail or [])
    if not ips:
        score_detail = [line for line in score_detail if not str(line.get('label', '')).startswith(('Reachable on a public IP', 'Public IP observed'))]
    display_score = min(100, sum(int(line.get('points') or 0) for line in score_detail)) if score_detail else 0
    http, hosting_info, details = _host_record(sub, ips, techs, root)
    on_ip = (shared or {}).get('names_on_ip', {})
    countries = (shared or {}).get('countries', {})
    archived = ((shared or {}).get('archive') or {}).get((sub.target_domain.project_id if sub.target_domain else None, sub.name.lower())) or {}
    host_key = (sub.target_domain.project_id if sub.target_domain else None, sub.name.lower())
    rdp_shots_by_port = ((shared or {}).get('rdp_shots') or {}).get(host_key) or {}
    static_rdp = {r.port: r for r in ((shared or {}).get('shots') or {}).get(host_key, []) if r.scheme == 'rdp'}  # an RDP port that requires NLA: the outcome, not nothing
    from cveFeed import host_context, subdir_apps
    probe_rows = ((shared or {}).get('probes') or {}).get(host_key) or []
    unverified = _unverified_products(sub, others, ips)
    from cveFeed import internal_view
    network = internal_view.network_of(sub.target_domain.project_id if sub.target_domain else None, sub.name)
    row = {'id': sub.id, 'internal': network is not None, 'network': network,
            # what version and identity probes and the WordPress scan found, and where a WordPress candidate stands (detected how, scanned when, or why not)
            'probes': [{'probe': r.probe, 'kind': r.kind, 'product': r.product, 'version': r.version, 'variant': r.variant, 'outcome': r.outcome,
                        'confidence': r.confidence, 'source': r.source, 'observed_at': r.observed_at.isoformat()}
                       for r in probe_rows if r.kind in ('version', 'identity', 'edge')][:40],
            'also_served': _also_served(sub, ips, shared),
            'served_from': [{'address': r.product, 'status': (r.evidence or {}).get('answer', {}).get('status'), 'title': (r.evidence or {}).get('answer', {}).get('title', '')}
                            for r in probe_rows if r.kind == 'vhost' and r.outcome == 'found'][:10],
            'subdirectory_apps': subdir_apps.applications_from_rows(probe_rows),
            'wordpress': host_context.wordpress_summary(probe_rows), 'heat': _host_heat_merged(sub, others, reasons), 'heat_reasons': reasons[:12], 'host': sub.name,
            'target': sub.target_domain.name if sub.target_domain else None, 'target_id': sub.target_domain_id,
            'http_status': http['status'], 'title': http['title'], 'score': display_score, 'score_detail': score_detail, 'zombie': False,
            **_screenshot_fields(sub, http, ips, (shared or {}).get('shots', {}).get(host_key, []), (shared or {}).get('legacy_shots', {}).get(host_key), network),
            'technologies': sorted(techs),
            'technology_details': details,
            # products seen with no version: kept as metadata, never matched to CVEs until a version is found (cveFeed.match_policy)
            'unverified_products': unverified,
            # what the web archive says the host ran at some point: historical evidence, never a current technology
            'archived_technologies': [{'name': n, 'urls': i.get('count', 0), 'examples': (i.get('sample') or [])[:3]}
                                      for n, i in sorted(archived.items())],
            'http': http,
            'hosting': hosting_info,
            'names': _host_names(sub),
            # the other names that point at this host's addresses: one host, several domain names
            'aliases': sorted({o.name for o in others if o.name.lower() != sub.name.lower()}, key=str.lower),
            'ips': [{'address': addr, 'os': e['ip'].os_guess,
                     'reverse': e['ip'].reverse_pointer or '', 'country': countries.get(e['ip'].geo_iso_id, ''),
                     'names_on_ip': on_ip.get(addr, 0), 'is_cdn': bool(e['ip'].is_cdn),
                     'facts': (e['ip'].fingerprint or {}).get('facts') or {},
                     'runzero': (e['ip'].fingerprint or {}).get('runzero') or None,  # runZero's view of the address (cveFeed.runzero_sync)
                     'full_scanned_at': e['ip'].full_scanned_at.isoformat() if e['ip'].full_scanned_at else None,
                     'full_scan_ports': e['ip'].full_scan_ports,
                     # UDP ports nothing answered on (open or filtered): shown as a note, never as a service
                     'udp_unanswered': sorted(p.number for p in e['ip'].ports.all() if p.state == 'open|filtered' and p.protocol == 'udp'),
                     # what the last fingerprint pass cut for this address (a port list past its cap, a clipped banner, nmap's time limit), in words (cveFeed.result_cuts)
                     'cut_notes': [result_cuts.words(c) for c in result_cuts.clean(((e['ip'].fingerprint or {}).get('result_cuts') or {}).get('nmap'))],
                     'ports': [
                {'number': p.number, 'service': p.service_name, 'protocol': p.protocol, 'product': p.product,
                 'version': p.version, 'cpe': p.cpe, 'os': p.os_guess, 'banner': (p.banner or '')[:500], 'tunnel': (p.extra or {}).get('tunnel') or '',
                 'info': p.service_extra or '', 'scripts': {k: str(v)[:800] for k, v in list(((p.extra or {}).get('scripts') or {}).items())[:12]},
                 'db': (p.extra or {}).get('db') or None,
                 'http': p.http or None, 'tls': p.tls or None,
                 'rdp_screenshot': _rdp_screenshot_field(sub, rdp_shots_by_port.get(p.number), static_rdp.get(p.number))} for p in e['ports']]} for addr, e in ips.items()],
            'vulns': [{'id': v.id, 'name': v.name, 'severity': SEVERITY_NAMES.get(v.severity, str(v.severity)), 'url': v.http_url,
                       'classification': _classification_of(v)} for v in vulns][:15],
            # the list above is capped and includes informational detections; these are the real counts, split the way the Scanner
            # findings page and the dashboard split them: findings (low or worse) and informational detections
            'vuln_count': sum(1 for v in vulns if v.severity != 0), 'info_count': sum(1 for v in vulns if v.severity == 0),
            'cve_matches': cve_count,
            'labels': list(labels),
            'profile': profile or dict(NO_PROFILE), 'excluded': bool(excluded),
            # what a person calls the host and wrote about it (display only; ``aliases`` above are the other DNS names on its addresses)
            **alias_and_note(sub, others, (shared or {}).get('tags') or {}),
            'inventory': _host_inventory(sub, others, shared)}
    row['scan_blocked'] = _scan_blocked(sub, host_key[0], list(ips), shared)
    if (shared or {}).get('coverage') is not None:
        row['check_coverage'] = _check_coverage(shared['coverage'], sub, others, host_key[0], excluded, hosting_info, reasons, unverified,
                                                 probe_rows, root, shared.get('coverage_rich', False))
    return row


def _scan_blocked(sub, project_id, addresses, shared):
    """Why this host is not scanned: ``''`` when it is, else the plain reason (an address of it is on the organization's do-not-scan list, or the list could not be
    read). One list read per project per page (``shared`` carries it)."""
    from cveFeed import exclusions
    try:
        cache = shared.setdefault('address_networks', {}) if isinstance(shared, dict) else {}
        if project_id not in cache:
            cache[project_id] = exclusions.address_networks(project_id)
        refusals = exclusions.address_refusals(project_id, addresses, networks=cache[project_id])
    except Exception:  # noqa: BLE001 - the list could not be read: say so rather than show the host as scanned
        return exclusions.UNREADABLE
    if not refusals:
        return ''
    first = next(iter(refusals.values()))
    if first.unreadable:
        return str(first)
    ip = next(iter(refusals))
    return f"{sub.name} is not scanned: it resolves to {ip}, which is on the organization's do-not-scan list ({first.entry})"


def _check_coverage(loaded, sub, others, project_id, excluded, hosting_info, reasons, unverified, probe_rows, root, rich):
    """The host's check coverage (cveFeed.check_coverage): ``{done, applicable, paused, checks}``, or None when it could not be worked out, which
    never breaks the host record."""
    from cveFeed import check_coverage
    try:
        return check_coverage.for_host(
            loaded, sub, others, project_id, excluded=excluded, shared_platform=bool(hosting_info.get('shared_ip')),
            hot_cves=[r['label'] for r in reasons if r['kind'] == 'cve' and r['temp'] in ('fire', 'smoke')], unversioned=len(unverified),
            probe_rows=probe_rows, root=root, rich=rich)
    except Exception:  # noqa: BLE001 - accounting only: a host is shown without it rather than not at all
        logger.exception('check coverage failed for host %s', sub.name)
        return None


def _coverage_for(subs, others, project, rich=False):
    """The batched evidence for the check coverage of a page of hosts (a fixed number of queries, whatever the page holds), or None when it
    could not be loaded."""
    from cveFeed import check_coverage
    try:
        return check_coverage.load([(s, others.get(s.id, ()), _pid_of(project, s)) for s in subs])
    except Exception:  # noqa: BLE001
        logger.exception('check coverage could not be loaded')
        return None


def _host_inventory(sub, others, shared):
    """The brief of the newest host inventory report tied to this host or one of its names, or None."""
    found = (shared or {}).get('inventories') or {}
    names = [sub.name.lower(), *(o.name.lower() for o in others)]
    return next((found[(sub.target_domain.project_id if sub.target_domain else None, n)] for n in names
                 if (sub.target_domain.project_id if sub.target_domain else None, n) in found), None)


def _inventories_for(project, subs, others):
    """``{(project id, lowercase host): brief}`` of the host inventory reports tied to a page of hosts (and their other names): one
    query, newest report of each host first."""
    from cveFeed import host_inventory
    from cveFeed.models import HostInventory
    wanted = {s.name.lower() for s in subs} | {o.name.lower() for rows in others.values() for o in rows}
    pids = _pids_of(project, subs)
    days = {pid: host_inventory.stale_days_of(pid) for pid in pids}
    out = {}
    for inv in HostInventory.objects.filter(project_id__in=pids, host__in=wanted).order_by('reported_at', 'id'):
        out[(inv.project_id, inv.host)] = host_inventory.brief(inv, days[inv.project_id])
    return out


def _unverified_products(sub, others, ips):
    """The host's products that no version was found for, from its technologies and the open ports already gathered for the record."""
    from cveFeed import match_policy
    technologies = [(t.id, t.name) for row in [sub, *others] for t in row.technologies.all() if t.name]
    ports = [(address, port) for address, entry in ips.items() for port in entry['ports']]
    return match_policy.unversioned_leads(technologies, ports)[:50]


def _screenshot_fields(sub, http, ips, rows, legacy_id, network=None):
    """The screenshot part of a host record. The browser's captures (``HostScreenshot``, cveFeed.web_shot) come first; a discovery screenshot
    (``Subdomain.screenshot_path``, the discovery's own screenshot) is the fallback, and it is the newest same-name row that has one, not just ``sub``: a rescan
    writes a new row with no screenshot, and it used to hide the older row's. ``screenshot_note`` says why there is none (or what the latest
    attempt did), never "none yet" without a reason."""
    from cveFeed import web_shot
    pictures = web_shot.pictures(rows)
    legacy = sub.id if sub.screenshot_path else legacy_id
    legacy_shown = not pictures and legacy is not None
    web_ports = any(web_shot.KNOWN_WEB_PORTS.get(p.number) or 'http' in (p.service_name or '').lower() for e in ips.values() for p in e['ports'])
    ports_known = any(e['ports'] for e in ips.values())
    note = web_shot.note_for(rows, has_web_evidence=bool(http.get('url') or http.get('status') or web_ports), legacy=legacy_shown,
                             network=network, ports_known=ports_known)
    shown = pictures[0] if pictures else None
    return {'screenshot': bool(pictures) or legacy_shown, 'screenshot_note': note,
            'screenshot_source': 'browser' if pictures else 'discovery' if legacy_shown else None,
            'screenshot_alt': web_shot.alt_text(sub.name.lower().rstrip('.'), shown) if shown else f'Screenshot of {sub.name}',
            'screenshot_version': int(shown.captured_at.timestamp()) if shown and shown.captured_at else 0,
            'screenshots': [web_shot.describe(r, sub.name.lower().rstrip('.')) for r in sorted((r for r in rows if r.scheme != 'rdp'), key=web_shot.rank)]}


def _rdp_screenshot_field(sub, shot, static=None):
    """What the host record sends about one port's RDP capture (cveFeed.rdp_shot), or None when there is none. A port that needs NLA has no picture
    to send; its outcome (``cveFeed.web_shot``) is sent instead of nothing."""
    if not shot:
        if static is not None and static.outcome == 'nla_required':
            return {'url': None, 'outcome': 'nla_required', 'reason': static.reason, 'logged_in_user': '', 'summary': '', 'error': '',
                    'captured_at': static.attempted_at.isoformat() if static.attempted_at else None}
        return None
    return {'url': f'/cve/{sub.target_domain.project.slug}/hosts/{sub.id}/rdp-screenshot/{shot.port}/' if sub.target_domain else None,
            'outcome': 'ok', 'logged_in_user': shot.logged_in_user, 'summary': shot.ai_summary, 'error': shot.ai_error,
            'captured_at': shot.captured_at.isoformat() if shot.captured_at else None}


def _host_record(sub, ips, techs, root):
    """``(http, hosting, technology_details)`` for one host: the Shodan-style part of the record. What the host row stores wins; what
    the web route check saw on the root page (its status, title, Server and X-Powered-By headers) fills what the row lacks, so a host
    the route check reached is never shown as unprobed."""
    from cvengine_scanner import cms, fingerprint

    from cveFeed import cms_evidence, hosting, js_libraries
    from cveFeed.correlation import split_name_version
    evidence = dict((root.evidence or {}) if root else {})
    http = {'url': sub.http_url or (root.url if root else None),
            'status': sub.http_status or (root.http_status if root and root.http_status else 0),
            'title': sub.page_title or (root.title if root and root.title else None),
            'webserver': sub.webserver or evidence.get('server', ''), 'powered_by': evidence.get('powered_by', ''),
            'content_type': sub.content_type or (root.content_type if root else '') or '',
            'redirect_to': root.redirect_to if root else '', 'cname': sub.cname or '',
            'checked': root.checked_at.isoformat() if root and root.checked_at else None,
            'source': 'host scan' if sub.http_status else ('web route check' if root else '')}
    pointers = [e['ip'].reverse_pointer for e in ips.values() if e['ip'].reverse_pointer]
    info = hosting.classify(name=sub.name, cname=sub.cname or '', webserver=http['webserver'], reverse_pointers=pointers,
                            cdn_name=sub.cdn_name or '', is_cdn=bool(sub.is_cdn or any(e['ip'].is_cdn for e in ips.values())))
    from_page = {f['name']: f['source'] for f in evidence.get('fingerprints') or []}
    wrong = cms_evidence.superseded(sub, techs | set(from_page))  # a version of a one-core product the evidence disproves: kept, shown, never matched
    libraries = {str(r.get('product', '')).lower(): r for r in (evidence.get('libraries') or {}).values() if isinstance(r, dict)} \
        if isinstance(evidence.get('libraries'), dict) else {}
    details = []
    for name in sorted(techs | set(from_page)):
        base, version = split_name_version(name)
        row = {'name': base or name, 'version': version, 'category': fingerprint.categorize(name),
               'source': from_page.get(name, 'scan'), **({'superseded': True} if (cms.key(base), version) in wrong else {})}
        record = libraries.get((base or '').lower()) if js_libraries.is_library(name) else None
        if record:  # every copy of the library on the front page and the one that runs (cveFeed.js_libraries)
            row.update(library_details(record, version))
        details.append(row)
    return http, info, details


def library_details(record, version):
    """The host record's view of one JavaScript library: where this version came from, every copy on the front page and which runs."""
    from cveFeed.host_context import library_copies
    copies = library_copies(record, limit=8)
    mine = next((c for c in copies if c['version'] == version and c['state'] in ('effective', 'unresolved')), None) or \
        next((c for c in copies if c['version'] == version), None)
    out = {'copies': copies, 'version_source': (mine or {}).get('version_source') or record.get('version_source') or ''}
    if mine:
        out['copy_state'] = mine['state']
    if record.get('copies_unresolved'):
        out['copies_unresolved'] = True
    return out


def _roots_for(project, subs):
    """``{(project id, lowercase host): the newest root-page RouteAuth row}`` for a page of hosts: one query."""
    from cveFeed.models import RouteAuth
    out = {}
    wanted = {s.name.lower() for s in subs}
    for row in RouteAuth.objects.filter(project_id__in=_pids_of(project, subs), host__in=wanted, path='/', retired_at__isnull=True) \
            .order_by('checked_at', 'id'):
        key = (row.project_id, row.host)
        # the https answer speaks for the host; an http redirect only when nothing else was seen
        if key not in out or row.url.startswith('https') or not out[key].url.startswith('https'):
            out[key] = row
    return out


def _shared_for(project, subs):
    """Per-page lookups for the IP rows: how many names of the project's own inventory sit on each address, and country names."""
    from django.db.models import Count
    from startScan.models import CountryISO, Subdomain
    addresses = {ip.address for sub in subs for ip in sub.ip_addresses.all() if ip.address}
    names = {}
    if addresses:
        for row in Subdomain.objects.filter(target_domain__project_id__in=_pids_of(project, subs), ip_addresses__address__in=addresses) \
                .values('ip_addresses__address').annotate(n=Count('name', distinct=True)):
            names[row['ip_addresses__address']] = row['n']
    geo_ids = {ip.geo_iso_id for sub in subs for ip in sub.ip_addresses.all() if ip.geo_iso_id}
    countries = {c.id: c.name or c.iso for c in CountryISO.objects.filter(id__in=geo_ids)} if geo_ids else {}
    from cveFeed.models import HostArchive, RdpScreenshot
    archive = {(row.project_id, row.host): row.technologies for row in HostArchive.objects.filter(
        project_id__in=_pids_of(project, subs), host__in={s.name.lower() for s in subs})}
    rdp_shots = {}
    for row in RdpScreenshot.objects.filter(project_id__in=_pids_of(project, subs), host__in={s.name.lower() for s in subs}):
        rdp_shots.setdefault((row.project_id, row.host), {})[row.port] = row
    from cveFeed.models import HostScreenshot
    shots = {}
    for row in HostScreenshot.objects.filter(project_id__in=_pids_of(project, subs), host__in={s.name.lower().rstrip('.') for s in subs}):
        shots.setdefault((row.project_id, row.host), []).append(row)
    # the newest row of each name that has a discovery screenshot: what the host shows when its own row has none (a rescan writes a row without one)
    legacy_shots = {}
    for pid, name, row_id in Subdomain.objects.filter(target_domain__project_id__in=_pids_of(project, subs), name__in={s.name for s in subs}) \
            .exclude(screenshot_path__isnull=True).exclude(screenshot_path='').order_by('id').values_list('target_domain__project_id', 'name', 'id'):
        legacy_shots[(pid, name.lower())] = row_id
    from cveFeed.models import ProbeObservation
    probe_rows = {}
    for row in ProbeObservation.objects.filter(project_id__in=_pids_of(project, subs), host__in={s.name.lower() for s in subs}).order_by('-observed_at'):
        probe_rows.setdefault((row.project_id, row.host), []).append(row)
    # other sites the virtual host sweep found on these addresses (cveFeed.vhost_scan), by (project, address)
    vhosts = {}
    for row in ProbeObservation.objects.filter(project_id__in=_pids_of(project, subs), probe='vhost-probe', kind='vhost', outcome='found',
                                               product__in=list(addresses)).order_by('host'):
        vhosts.setdefault((row.project_id, row.product), []).append(row)
    return {'names_on_ip': names, 'countries': countries, 'archive': archive, 'rdp_shots': rdp_shots, 'shots': shots, 'legacy_shots': legacy_shots,
            'probes': probe_rows, 'vhosts': vhosts}


NO_PROFILE = {'owner': '', 'purpose': '', 'criticality': 'unknown'}


def alias_and_note(sub, others, tags):
    """``{alias, alias_from, note, note_from}`` for one host, from ``tags`` (``_profiles_for``: the alias and note of every HostProfile among the page's
    names). The host's own name first, then the other names on its addresses (the Hosts page shows them as one host, so a person's alias on
    the name that used to be on display still shows when another name takes its place), then the target when the host is the target itself
    (an IP added as a target): ``*_from`` says which, ``host`` or ``target``, or is empty. Display only."""
    group = [sub, *sorted(others, key=lambda r: r.name.lower())]
    out = {'alias': '', 'alias_from': '', 'note': '', 'note_from': ''}
    for key in ('alias', 'note'):
        for row in group:
            pid = row.target_domain.project_id if row.target_domain else None
            value = (tags.get((pid, row.name.lower())) or {}).get(key, '')
            if value:
                out[key], out[f'{key}_from'] = value, 'host'
                break
        else:
            for row in group:
                if row.target_domain and row.name.lower() == row.target_domain.name.lower() and getattr(row.target_domain, key):
                    out[key], out[f'{key}_from'] = getattr(row.target_domain, key), 'target'
                    break
    return out


def _pid_of(project, sub):
    """The id of the project a host row belongs to: the one project asked for, or (all-projects view) its own target's project."""
    return sub.target_domain.project_id if _is_all(project) else project.id


def _pids_of(project, subs):
    """The project ids a page of hosts spans: just the project's, or the projects of the page's own rows in the all-projects view."""
    return sorted({_pid_of(project, s) for s in subs})


def _profiles_for(project, subs, others=None):
    """``({(project id, lowercase host): {owner, purpose, criticality}}, {(project id, lowercase host) that is excluded}, {(project id, lowercase host):
    {alias, note}})`` for a page of hosts: two queries however many projects the page spans. The asset information a person typed on the host page,
    whether the project's organization excluded the name, and the alias and note of every name that has one: the page's names and, with ``others``
    (``_name_siblings``), the other names on the same addresses, so an alias still shows when another name of the host is the one on display."""
    from cveFeed.models import HostExclusion, HostProfile
    wanted = {s.name.lower() for s in subs} | {o.name.lower() for rows in (others or {}).values() for o in rows}
    pids = _pids_of(project, subs)
    profiles, tags = {}, {}
    for row in HostProfile.objects.filter(project_id__in=pids, host__in=wanted):
        profiles[(row.project_id, row.host)] = {'owner': row.owner, 'purpose': row.purpose, 'criticality': row.criticality}
        if row.alias or row.note:
            tags[(row.project_id, row.host)] = {'alias': row.alias, 'note': row.note}
    try:  # the organization's exclusions reach every project of the org
        excluded = set(HostExclusion.objects.filter(org__projects__id__in=pids, host__in=wanted).values_list('org__projects__id', 'host'))
    except Exception:  # noqa: BLE001 - same as cveFeed.exclusions: a lookup problem never breaks a listing
        excluded = set()
    return profiles, excluded, tags


def _labels_for(project, subs):
    """``{(project id, lowercase host): [{'label', 'detail'}]}`` for a page of hosts: one query. Informational detections (WAF, a server
    version, ...) that are chips on the host, not findings."""
    from cveFeed.models import HostLabel
    out = {}
    for row in HostLabel.objects.filter(project_id__in=_pids_of(project, subs), host__in={s.name.lower() for s in subs}).order_by('label')[:2000]:
        out.setdefault((row.project_id, row.host), []).append({'label': row.label, 'detail': row.detail})
    return out


def _host_heat_merged(sub, others, reasons):
    """The group's heat: the reasons decide it; with none, clean if any copy has been through nuclei, else unscanned."""
    if reasons or not others:
        return _host_heat(sub, reasons)
    heats = [_host_heat(row, []) for row in [sub, *others]]
    return 'clean' if 'clean' in heats else heats[0]


def _name_siblings(project, subs):
    """``{sub.id: [other current rows of the same host]}`` for a page of hosts: a few queries for the whole page. The same host is
    the same name in the same project (other targets and scans) and every other name that resolves to exactly the same addresses
    (see ``cveFeed.counts.with_host_key``); a name in another project is a different host."""
    from cveFeed.counts import host_siblings
    from startScan.models import Subdomain
    subs = list(subs)
    if not subs:
        return {}
    ids = host_siblings([s.id for s in subs])
    wanted = {i for rows in ids.values() for i, _ in rows}
    rows = {r.id: r for r in Subdomain.objects.filter(id__in=wanted).select_related('target_domain').prefetch_related(
        'ip_addresses__ports', 'cve_matches__cve_entry', triage_prefetch('cve_matches__triage'), 'vulnerability_set', triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags', 'technologies')}
    return {s.id: [rows[i] for i, _ in ids.get(s.id, []) if i in rows] for s in subs}


@AutoField.register_lookup
class _InArray(Lookup):
    """``id__in_array=ArraySubquery(...)``: ``id = ANY(ARRAY(subquery))``. The subquery runs once and its ids are looked up in the array, where
    ``id IN (subquery)`` lets Postgres rescan the subquery for every row when it misjudges how many rows it returns."""
    lookup_name = 'in_array'

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        return f'{lhs} = ANY({rhs})', (*lhs_params, *rhs_params)


def _one_per_host(qs, per_project=False):
    """Collapse a Subdomain queryset to one row per host. First one row per hostname: the one with the most open ports, then the most
    IPs, then the newest scan (a scan-less row last). Then names that resolve to exactly the same addresses (``example.com`` and
    ``www.example.com``) become one host: the project's own target name first, else the shortest name (see
    ``cveFeed.counts.with_host_key``; a name behind a CDN, or without an address, stays alone). Two Postgres DISTINCT ON passes over
    the filtered ids, then a plain ``id__in`` so ordering and paging stay ordinary. Richness comes from subqueries on a fresh
    queryset, so search joins cannot inflate the counts. ``per_project`` (the all-projects view) keeps one row per (project,
    hostname): the same name in two projects is two hosts."""
    from django.db.models import Case, Count, F, IntegerField, OuterRef, Subquery, Value, Window, When
    from django.db.models.functions import Coalesce, Length, RowNumber
    from cveFeed.counts import with_host_key
    from startScan.models import OPEN_PORT_STATES, Port, Subdomain
    ports = Port.objects.filter(state__in=OPEN_PORT_STATES, ports__ip_addresses=OuterRef('pk')).order_by() \
        .values('ports__ip_addresses').annotate(c=Count('id', distinct=True)).values('c')
    ips = Subdomain.ip_addresses.through.objects.filter(subdomain_id=OuterRef('pk')).order_by() \
        .values('subdomain_id').annotate(c=Count('id')).values('c')
    keys = ('target_domain__project_id', 'name') if per_project else ('name',)
    by_name = Subdomain.objects.filter(id__in=qs.order_by().values('id')).order_by(
        *keys, Coalesce(Subquery(ports), Value(0)).desc(), Coalesce(Subquery(ips), Value(0)).desc(),
        F('scan_history_id').desc(nulls_last=True), '-id').distinct(*keys).values('id')
    own_target = Case(When(name=F('target_domain__name'), then=Value(0)), default=Value(1), output_field=IntegerField())
    # a window rather than DISTINCT ON: the key is an annotation, which DISTINCT ON cannot keep once the query is cut to ids
    rep = with_host_key(Subdomain.objects.filter(id__in=by_name)).annotate(_rank=Window(
        RowNumber(), partition_by=[F('host_key')],
        order_by=[own_target.asc(), Length('name').asc(), F('name').asc(), Coalesce(Subquery(ports), Value(0)).desc(), F('id').desc()])
    ).filter(_rank=1).values('id')
    # the ids are gathered into an array once and looked up in it (``id = ANY(ARRAY(...))``). ``id IN (subquery)`` let Postgres guess one row for the
    # window query and rescan its 8,000 rows for each of 10,000 hosts: 4.8 s at that size, 0.1 s with the array
    return Subdomain.objects.filter(id__in_array=ArraySubquery(rep))


def _hosts_page(project, qs, params, extra=None, coverage=True, load=None, page_extra=None):
    """Paginate hosts with each row's same-name copies folded in (one extra query per page). ``coverage=False`` leaves out ``check_coverage``
    (the PDF report does not print it). In the all-projects view each row
    also names its project, and everything folded in (copies, labels, asset info, exclusions) is looked up per (project, host)."""
    everywhere = _is_all(project)
    page = paginate_by_ids(qs, params, load) if load else paginate(qs, params, lambda sub: sub)
    subs = page['results']
    others = _name_siblings(project, subs)
    _prime_nuclei(subs, *others.values())
    labels = _labels_for(project, subs)
    profiles, excluded, tags = _profiles_for(project, subs, others)
    roots, shared = _roots_for(project, subs), _shared_for(project, subs)
    shared['tags'] = tags
    shared['inventories'] = _inventories_for(project, subs, others)
    if coverage:  # which of the checks that apply to each host have run: a few queries for the whole page (cveFeed.check_coverage)
        shared['coverage'] = _coverage_for(subs, others, project)
    if page_extra:  # an ``extra`` that needs one lookup for the whole page: ``page_extra(subs, shared)`` returns the per-host function
        extra = page_extra(subs, shared)
    rows = []
    for sub in subs:
        key = (_pid_of(project, sub), sub.name.lower())
        row = {**_host(sub, others[sub.id], labels.get(key, ()), profiles.get(key), key in excluded, roots.get(key), shared),
               **(extra(sub) if extra else {})}
        if everywhere:
            row['project'], row['project_name'] = sub.target_domain.project.slug, sub.target_domain.project.name
        rows.append(row)
    page['results'] = rows
    return page


def host_group(project, sub):
    """The single-host view of ``sub``: its name's other current rows folded in, whichever row was asked for."""
    key = (project.id, sub.name.lower())
    others = _name_siblings(project, [sub])
    profiles, excluded, tags = _profiles_for(project, [sub], others)
    shared = {**_shared_for(project, [sub]), 'tags': tags, 'inventories': _inventories_for(project, [sub], others),
              'coverage': _coverage_for([sub], others, project), 'coverage_rich': True}  # the single host also names each address, port or CVE judged
    return _host(sub, others[sub.id], _labels_for(project, [sub]).get(key, ()),
                 profiles.get(key), key in excluded, _roots_for(project, [sub]).get(key), shared)


def _mark_zombies(project, page):
    """Set ``zombie`` on a page of hosts: one lookup for the page's names, after pagination. In the all-projects view a host is a
    zombie only in the project whose state says so."""
    from cveFeed.models import HostState
    names = {h['host'].lower() for h in page['results']}
    if _is_all(project):
        states = {(row['project__slug'], row['host']): row for row in
                  HostState.objects.filter(project_id__in=project.ids, host__in=names).values(
                      'project__slug', 'host', 'zombie_since', 'archived_at', 'archive_reason', 'pinned',
                      'archive_checked_at', 'archive_check_status', 'archive_assessment_id')}
        for h in page['results']:
            row = states.get((h['project'], h['host'].lower()), {})
            h['zombie'] = bool(row.get('zombie_since'))
            h['archived'] = bool(row.get('archived_at'))
            h['archive_reason'] = row.get('archive_reason') or ''
            h['pinned'] = bool(row.get('pinned'))
            h['archive_checked_at'] = _iso(row.get('archive_checked_at'))
            h['archive_check_status'] = row.get('archive_check_status') or ''
            h['archive_assessment_id'] = row.get('archive_assessment_id')
        return _mark_secrets(project, page)
    states = {row['host']: row for row in HostState.objects.filter(project=project, host__in=names).values(
        'host', 'zombie_since', 'archived_at', 'archive_reason', 'pinned', 'archive_checked_at',
        'archive_check_status', 'archive_assessment_id')}
    for h in page['results']:
        row = states.get(h['host'].lower(), {})
        h['zombie'] = bool(row.get('zombie_since'))
        h['archived'] = bool(row.get('archived_at'))
        h['archive_reason'] = row.get('archive_reason') or ''
        h['pinned'] = bool(row.get('pinned'))
        h['archive_checked_at'] = _iso(row.get('archive_checked_at'))
        h['archive_check_status'] = row.get('archive_check_status') or ''
        h['archive_assessment_id'] = row.get('archive_assessment_id')
    return _mark_secrets(project, page)


def _mark_secrets(project, page):
    """Set ``secrets`` on a page of hosts: how many exposed secrets that count (cveFeed.secrets_inventory) each one serves now, for the host's
    Secrets chip. One query for the page."""
    from django.db.models import Count

    from cveFeed import secrets_catalog
    from cveFeed.models import SecretOccurrence
    names = {h['host'].lower() for h in page['results']}
    rows = (_scoped(SecretOccurrence.objects.all(), project, 'project').filter(host__in=names, retired_at__isnull=True)
            .exclude(finding__status__in=secrets_catalog.QUIET_STATUSES).values('project__slug', 'host')
            .annotate(n=Count('finding', distinct=True)))
    counts = {(r['project__slug'], r['host']): r['n'] for r in rows}
    for h in page['results']:
        key = (h['project'] if _is_all(project) else project.slug, h['host'].lower())
        h['secrets'] = counts.get(key, 0)
    return page


def _host_order(params):
    """Hosts come highest score first, then by name; ``?sort=name`` keeps plain name order."""
    sort = params.get('sort') or 'score'
    if sort not in ('score', 'name'):
        raise ApiError(400, 'sort must be score or name')
    return ('-score', 'name') if sort == 'score' else ('name',)


def _internal_filter(qs, params, prefix=''):
    """``?internal=1`` keeps only the hosts inside a network their project declared internal, ``?internal=0`` only the others; absent, all."""
    from cveFeed import internal_view
    value = str(params.get('internal', '')).strip().lower()
    if value in ('1', 'true', 'yes', 'only'):
        return qs.filter(internal_view.internal_q(prefix))
    if value in ('0', 'false', 'no', 'external'):
        return qs.exclude(internal_view.internal_q(prefix))
    return qs


def list_hosts(ctx, slug, params):
    """The Shodan-style inventory: hosts with IPs, open ports and service/product/version, highest score first (?sort=name)."""
    from django.db.models import Q
    from startScan.models import Subdomain
    project, _ = get_project(ctx, slug)
    from cveFeed.correlation import latest_scan_q
    qs = _scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
    if params.get('q'):
        qs = qs.filter(Q(name__icontains=params['q']) | _alias_note_q(params['q'], project))
    if params.get('target_id'):
        qs = qs.filter(target_domain_id=_int_param(params['target_id'], 'target_id'))
    qs = _internal_filter(qs, params)
    ordered = _one_per_host(qs, per_project=_is_all(project)).order_by(*_host_order(params))

    def load(ids):  # the page's rows with what the host cards read, in the order of ``ids``
        rows = Subdomain.objects.filter(pk__in=ids).select_related('target_domain__project' if _is_all(project) else 'target_domain') \
            .prefetch_related('ip_addresses__ports', 'cve_matches__cve_entry', triage_prefetch('cve_matches__triage'), 'vulnerability_set', triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags', 'technologies')
        by_id = {row.pk: row for row in rows}
        return [by_id[i] for i in ids if i in by_id]
    return _mark_zombies(project, _hosts_page(project, ordered, params, load=load))


SEARCH_FIELDS = ('tech', 'banner', 'port', 'proto', 'product', 'service', 'os', 'cve', 'ip', 'host', 'vuln', 'sev', 'auth',
                  'sensitive', 'zombie', 'country', 'alias', 'note', 'secret')
MAX_SEARCH_QUERY, MAX_SEARCH_TERMS, MAX_SEARCH_VALUE, MAX_SEARCH_VALUES = 1000, 15, 200, 40
MAX_NEGATED_TERMS = 3  # every negated term is a pass over the whole project's hosts (review 2 F1): three is a real query, fifteen is an abuse
_SEARCH_TERM = re.compile(r'(-)?(?:([A-Za-z]+):)?(?:"([^"]*)"|(\S+))')


def parse_search(query):
    """Split a search into terms: ``[(negated, field or None, value, quoted)]``. A bare word has no field; ``field:value``
    filters one field; ``-term`` negates; a quoted value (``"apache tomcat"``, ``tech:"apache tomcat"``) is a phrase, and
    never split on comma even if it contains one (``quoted`` says so, for the comma-OR a field value otherwise gets)."""
    query = query or ''
    if not isinstance(query, str):
        raise ApiError(400, 'q must be text')
    if len(query) > MAX_SEARCH_QUERY:
        raise ApiError(400, f'the search is longer than {MAX_SEARCH_QUERY} characters')
    terms = []
    for m in _SEARCH_TERM.finditer(query):
        neg, field, quoted, bare = m.group(1), m.group(2) or '', m.group(3), m.group(4) or ''
        is_quoted = quoted is not None
        value = (quoted if is_quoted else bare).strip()
        if field and field.lower() not in SEARCH_FIELDS:
            value, field, is_quoted = f'{field}:{value}', '', False  # "http://x" or "foo:bar": not a field, just text
        if value:
            if len(value) > MAX_SEARCH_VALUE:
                raise ApiError(400, f'a search term is longer than {MAX_SEARCH_VALUE} characters')
            terms.append((bool(neg), field.lower() or None, value, is_quoted))
    terms = _bind_versions(terms)
    if len(terms) > MAX_SEARCH_TERMS:
        raise ApiError(400, f'a search may have at most {MAX_SEARCH_TERMS} terms')
    if sum(1 for t in terms if t[0]) > MAX_NEGATED_TERMS:
        raise ApiError(400, f'a search may have at most {MAX_NEGATED_TERMS} negated terms')
    values = sum(min(MAX_SEARCH_TERMS, len([p for p in value.split(',') if p.strip()])) if field and not quoted and ',' in value else 1 for _, field, value, quoted in terms)
    if values > MAX_SEARCH_VALUES:
        # every value is several EXISTS subqueries: fifteen terms of fifteen values made a query of a million characters that took Postgres seconds to plan
        raise ApiError(400, f'a search may name at most {MAX_SEARCH_VALUES} values in all (every term, and every item of a comma list)')
    return terms


_SEARCH_VERSION = re.compile(r'^v?\d+(?:\.\d+)+$')


def _bind_versions(terms):
    """A bare word followed by a bare dotted version (``wordpress 7.1``, ``nginx 1.24.0``) is one term, the product at that version: the version
    alone ("7.1") matches any address, banner or title that happens to contain it, which is never what a search for a release means. The term is
    ``('techver', 'wordpress 7.1')``. A version on its own, a quoted phrase, a negation or a field filter keeps its old meaning."""
    out = []
    for neg, field, value, quoted in terms:
        previous = out[-1] if out else None
        if (field is None and not quoted and not neg and _SEARCH_VERSION.match(value) and previous is not None
                and previous[1] is None and not previous[0] and not previous[3] and ' ' not in previous[2] and not _SEARCH_VERSION.match(previous[2])):
            out[-1] = (False, 'techver', f'{previous[2]} {value.lstrip("v")}', False)
            continue
        out.append((neg, field, value, quoted))
    return out


_V4 = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
_H = '[0-9a-f]{1,4}'
_V6 = (f'^(({_H}:){{7}}{_H}|({_H}:){{1,7}}:|({_H}:){{1,6}}:{_H}|({_H}:){{1,5}}(:{_H}){{1,2}}|({_H}:){{1,4}}(:{_H}){{1,3}}|({_H}:){{1,3}}(:{_H}){{1,4}}|'
       f'({_H}:){{1,2}}(:{_H}){{1,5}}|{_H}:(:{_H}){{1,6}}|:((:{_H}){{1,7}}|:))$')
# IpAddress.address is free text (a stored row can be anything), and ``address::inet`` raises for the first row that is not an address: one bad row of
# any organization then failed the search of every other (review 2 of 2026-11-09, P4). A row is cast only after a regular expression says it is an
# address, and the guard is a CASE so Postgres does not evaluate the cast first. An IPv4 range is compared as whole numbers, with no cast at all.
_INSIDE_SQL = {
    False: ("CASE WHEN address ~ %s THEN ((split_part(address, '.', 1)::bigint << 24) + (split_part(address, '.', 2)::bigint << 16) "
            "+ (split_part(address, '.', 3)::bigint << 8) + split_part(address, '.', 4)::bigint) BETWEEN %s AND %s ELSE false END"),
    True: "CASE WHEN address ~* %s THEN address::inet <<= %s::inet ELSE false END",
}


def _inside_params(net):
    network = ipaddress.ip_network(net)
    if network.version == 4:
        return [_V4, int(network.network_address), int(network.broadcast_address)]
    return [_V6, net]


def _ip_filter(value):
    """A Q matching hosts with an IP equal to ``value``, inside it (``10.0.0.0/24``, via Postgres ``inet``), or starting with it."""
    from django.db.models import Q
    from startScan.models import IpAddress
    if '/' in value:
        try:
            net = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ApiError(400, f'{value} is not a valid CIDR range')
        inside = IpAddress.objects.extra(where=[_INSIDE_SQL[':' in net]], params=_inside_params(net)).values('pk')
        return Q(ip_addresses__in=inside)
    try:
        return Q(ip_addresses__address=str(ipaddress.ip_address(value)))
    except ValueError:
        return Q(ip_addresses__address__startswith=value)


def _alias_note_q(value, project, fields=('alias', 'note')):
    """A Q matching the hosts whose alias or note (``fields``) contains ``value``: the HostProfile of the host's own name, and, for a host that is
    its target itself (an address added as a target), the target's. One correlated subquery on the (project, host) key of HostProfile, so a search
    costs no extra query. In the all-projects view the profile must be of the host's own project. A name is compared lowercase, as HostProfile
    stores it."""
    from django.db.models import Exists, F, OuterRef, Q
    from django.db.models.functions import Lower

    from cveFeed.models import HostProfile
    text, target_text = Q(), Q()
    for field in fields:
        text |= Q(**{f'{field}__icontains': value})
        target_text |= Q(**{f'target_domain__{field}__icontains': value})
    own = HostProfile.objects.filter(text, host=Lower(OuterRef('name')))
    own = own.filter(project_id=OuterRef('target_domain__project_id')) if _is_all(project) or project is None else own.filter(project=project)
    return Q(Exists(own)) | (Q(name__iexact=F('target_domain__name')) & target_text)


def _hosts_named_in(rows, project):
    """A Q matching the hosts named by ``rows`` (RouteAuth or HostState rows, narrowed to ``project`` or, when it is None, unnarrowed).
    By name inside one project. In the all-projects view by (project, name): a route or zombie state of one project must never
    mark a host of the same name in another."""
    from django.db.models import Exists, OuterRef, Q
    if _is_all(project):
        rows = _scoped(rows, project, 'project')
        return Q(Exists(rows.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'))))
    if project is not None:
        rows = rows.filter(project=project)
    return Q(name__in=rows.values('host'))


# The JSON keys inside the evidence stores that say what a host runs. Searched by key, never as raw JSON text, so a word like
# "source" or "markers" does not match every row that happens to have that key.
_ROUTE_EVIDENCE_KEYS = ('server', 'powered_by', 'fingerprint_names', 'cookies')  # RouteAuth.evidence: headers, fingerprint names, cookie names
_PORT_TEXT = ('banner', 'service_extra', 'extra__script_text', 'http__webserver', 'http__title')  # Port: raw service text, NSE output, HTTP


def _running_q(value, project):
    """A Q matching hosts that run ``value`` anywhere CVEngine saw it: the technology list, the Server header and X-Powered-By,
    the product, version and CPE nmap found, the service banner and NSE script output, the HTTP title, the cookie names and
    fingerprints of the host's live routes. ``php`` finds a host whether the evidence is a header, a PHPSESSID cookie, an
    OpenSSH-style banner or a technology row. Port evidence counts only on open ports, route evidence only on routes that answer."""
    from django.db.models import Q

    from cveFeed.models import RouteAuth
    ports = 'ip_addresses__ports__'
    open_port = Q(**{ports + 'state__in': ('', 'open')})
    q = Q(webserver__icontains=value) | Q(technologies__name__icontains=value)
    for lookup in ('product', 'version', 'cpe', *_PORT_TEXT):
        q |= Q(**{f'{ports}{lookup}__icontains': value}) & open_port
    routes = RouteAuth.objects.filter(retired_at__isnull=True)
    route_hit = Q()
    for key in _ROUTE_EVIDENCE_KEYS:
        route_hit |= Q(**{f'evidence__{key}__icontains': value})
    from cveFeed.models import HostArchive
    return q | _hosts_named_in(routes.filter(route_hit), project) | _hosts_named_in(HostArchive.objects.filter(tech_text__icontains=value), project)


def _banner_q(value):
    """A Q matching hosts with ``value`` in a service banner, an NSE script's output (ssh-hostkey, ssl-cert, ftp-anon,
    rdp-ntlm-info, smb-os-discovery ...) or the extra info nmap printed, on an open port."""
    from django.db.models import Q
    ports = 'ip_addresses__ports__'
    q = Q()
    for lookup in ('banner', 'extra__script_text', 'service_extra'):
        q |= Q(**{f'{ports}{lookup}__icontains': value})
    return q & Q(**{ports + 'state__in': ('', 'open')})


def _term_filter(field, value, project=None):
    """The Q for one search term. Every lookup is a join the database does, so nothing is looped over in Python."""
    from django.db.models import Q
    ports = 'ip_addresses__ports__'
    open_port = Q(**{ports + 'state__in': ('', 'open')})  # a closed or filtered port is not on the host any more
    if field is None:
        q = _running_q(value, project)
        for lookup in ('name', 'page_title', 'ip_addresses__address', 'ip_addresses__os_guess',
                       'vulnerability__name', 'cve_matches__cve_entry__cve_id'):
            q |= Q(**{f'{lookup}__icontains': value})
        q |= Q(**{ports + 'service_name__icontains': value}) & open_port
        return q | _alias_note_q(value, project)
    if field == 'tech':
        return _running_q(value, project)
    if field == 'techver':  # "wordpress 7.1": the product at that release (7.1, 7.1.4), on a technology row or an open port, on the same row
        product, version = value.rsplit(' ', 1)
        at_release = lambda prefix: Q(**{prefix + 'version': version}) | Q(**{prefix + 'version__startswith': version + '.'})  # noqa: E731
        return (Q(technologies__name__icontains=product) & at_release('technologies__')) | \
            (Q(**{ports + 'product__icontains': product}) & at_release(ports) & open_port)
    if field == 'banner':
        return _banner_q(value)
    if field == 'port':
        if not value.isdigit():
            raise ApiError(400, 'port: takes a port number, e.g. port:3306 (use product: or service: for names)')
        return Q(**{ports + 'number': int(value)}) & open_port
    if field == 'proto':
        if value.lower() not in ('tcp', 'udp'):
            raise ApiError(400, 'proto: takes tcp or udp, e.g. proto:udp port:161')
        same = ('', 'tcp') if value.lower() == 'tcp' else ('udp',)  # a row from before the protocol was recorded is TCP
        return Q(**{ports + 'protocol__in': same}) & open_port
    if field == 'product':
        return Q(**{ports + 'product__icontains': value}) & open_port
    if field == 'service':
        return Q(**{ports + 'service_name__icontains': value}) & open_port
    if field == 'os':
        return Q(ip_addresses__os_guess__icontains=value)
    if field == 'country':
        return Q(ip_addresses__geo_iso__iso__iexact=value) | Q(ip_addresses__geo_iso__name__icontains=value)
    if field == 'cve':
        return Q(cve_matches__cve_entry__cve_id__icontains=value)
    if field == 'ip':
        return _ip_filter(value)
    if field == 'host':
        return Q(name__icontains=value) | _alias_note_q(value, project, ('alias',))
    if field in ('alias', 'note'):
        return _alias_note_q(value, project, (field,))
    if field == 'vuln':
        return Q(vulnerability__name__icontains=value)
    if field == 'sev':
        inverse = {name: k for k, name in SEVERITY_NAMES.items()}
        if value.lower() not in inverse:
            raise ApiError(400, f'sev: takes one of {", ".join(n for n in inverse if n != "unknown")}')
        return Q(vulnerability__severity=inverse[value.lower()])
    if field == 'auth':
        from cveFeed.models import RouteAuth
        if value.lower() not in RouteAuth.STATES:
            raise ApiError(400, f'auth: takes one of {", ".join(RouteAuth.STATES)}')
        return _hosts_named_in(RouteAuth.objects.filter(auth_state=value.lower()), project)
    if field == 'zombie':
        from cveFeed.models import HostState
        if value.lower() not in ('yes', 'no'):
            raise ApiError(400, 'zombie: takes yes or no')
        q = _hosts_named_in(HostState.objects.filter(zombie_since__isnull=False), project)
        return q if value.lower() == 'yes' else ~q
    if field == 'sensitive':
        from cveFeed import sensitive
        from cveFeed.models import RouteAuth
        kind = value.lower()
        if kind != 'any' and kind not in sensitive.TYPE_GROUPS:
            raise ApiError(400, 'sensitive: takes any, credentials, pii or internal')
        routes = RouteAuth.objects.filter(sensitive_score__gt=0) if kind == 'any' else RouteAuth.objects.filter(sensitive__has_any_keys=list(sensitive.TYPE_GROUPS[kind]))
        return _hosts_named_in(routes, project)
    if field == 'secret':  # hosts that serve an exposed secret now (the secrets inventory): any, a class, live, or a provider
        from cveFeed import secrets_catalog
        from cveFeed.models import SecretOccurrence
        kind = value.lower()
        rows = SecretOccurrence.objects.filter(retired_at__isnull=True).exclude(finding__status__in=secrets_catalog.QUIET_STATUSES)
        if kind in ('p', 's', 'i'):
            rows = rows.filter(finding__klass=kind.upper())
        elif kind == 'live':
            rows = rows.filter(finding__status='live')
        elif kind != 'any':
            rows = rows.filter(finding__provider__iexact=value)
        return _hosts_named_in(rows, project)
    raise ApiError(400, f'unknown field {field}:')


def _port_evidence(p, v, field):
    """Which stored text of an open port holds ``v`` (lowercase), as a short label, or '' when none does. ``banner:`` looks only at
    raw service text; ``tech:`` and bare words also look at product, version, CPE and the port's HTTP server and title."""
    texts = [('banner', p.banner), ('info', p.service_extra)]
    texts += [(sid, out) for sid, out in ((p.extra or {}).get('scripts') or {}).items()]
    if field != 'banner':
        http = p.http or {}
        texts += [('product', p.product), ('version', p.version), ('cpe', p.cpe), ('web server', http.get('webserver')),
                  ('title', http.get('title'))]
    for label, text in texts:
        if v in str(text or '').lower():
            return label
    return ''


def _routes_for(subs):
    """``{(project id, host): up to 20 live RouteAuth rows}`` for a page of hosts: one query, where ``_route_reasons`` asked once per host."""
    from cveFeed.models import RouteAuth
    out = {}
    for row in RouteAuth.objects.filter(project_id__in={s.target_domain.project_id for s in subs}, host__in={s.name for s in subs}, retired_at__isnull=True).order_by('id'):
        rows = out.setdefault((row.project_id, row.host), [])
        if len(rows) < 20:
            rows.append(row)
    return out


def _route_reasons(sub, v, routes=None):
    """What the host's live routes say it runs that holds ``v``: Server and X-Powered-By headers, fingerprints, cookie names. ``routes`` is the page's
    ``_routes_for`` (without it the host's rows are read here, one query)."""
    from cveFeed.models import RouteAuth
    out = []
    key = (sub.target_domain.project_id, sub.name)
    rows = routes.get(key, []) if routes is not None else RouteAuth.objects.filter(project_id=key[0], host=sub.name, retired_at__isnull=True)[:20]
    for route in rows:
        evidence = route.evidence or {}
        for key, label in (('server', 'Server header'), ('powered_by', 'X-Powered-By')):
            if v in str(evidence.get(key, '')).lower():
                out.append(f'{label} {evidence[key]}')
        for found in evidence.get('fingerprints') or []:
            if v in str(found.get('name', '')).lower():
                out.append(f'{found["name"]} ({found.get("source", "route")})')
        out += [f'cookie {c}' for c in evidence.get('cookies') or [] if v in str(c).lower()]
    return out


def _archive_reasons(sub, v, archive=None):
    """Technologies the web archive says the host ran at some point that hold ``v``. Historical, so labelled as such. ``archive`` is the page's
    ``{(project id, lowercase host): technologies}`` (``_shared_for``); without it the row is read here, one query."""
    from cveFeed.models import HostArchive
    if archive is not None:
        technologies = archive.get((sub.target_domain.project_id, sub.name.lower())) or {}
    else:
        row = HostArchive.objects.filter(project_id=sub.target_domain.project_id, host=sub.name).first()
        technologies = row.technologies if row else {}
    return [f'seen in web archive: {name} ({info.get("count", 0)} URLs)' for name, info in technologies.items() if v in name.lower()]


def _matched_for_page(subs, shared, terms):
    """The per-host ``matched`` function of a search page, with the route rows read once for the page when a term can match them."""
    routes = _routes_for(subs) if any(not neg and field in (None, 'tech') for neg, field, _value, _quoted in terms) and subs else {}
    return lambda sub: {'matched': _why_matched(sub, terms, routes, shared['archive'])}


def _why_matched(sub, terms, routes=None, archive=None):
    """What each positive term matched on this host, for the results list (read from the page's prefetched rows; ``routes`` and ``archive`` are the
    page's lookups, see ``_routes_for`` and ``_shared_for``)."""
    from startScan.models import open_services
    reasons = []
    for neg, field, value, _quoted in terms:
        if neg:
            continue
        v = value.lower()
        has = lambda text: v in (text or '').lower()  # noqa: E731
        if field in (None, 'host') and has(sub.name):
            reasons.append(f'host {sub.name}')
        if field in (None, 'ip'):
            for ip in sub.ip_addresses.all():
                if field is None and has(ip.address):
                    reasons.append(f'IP {ip.address}')
                elif field == 'ip':
                    try:
                        hit = ipaddress.ip_address(ip.address) in ipaddress.ip_network(value, strict=False) if '/' in value else ip.address == value or ip.address.startswith(value)
                    except ValueError:
                        hit = False
                    if hit:
                        reasons.append(f'IP {ip.address}')
        if field == 'techver':
            product, version = v.rsplit(' ', 1)
            reasons += [f'technology {t.name}' for t in sub.technologies.all()
                        if product in (t.name or '').lower() and (t.version == version or (t.version or '').startswith(version + '.'))]
            for ip in sub.ip_addresses.all():
                for p in open_services(ip):
                    if product in (p.product or '').lower() and (p.version == version or (p.version or '').startswith(version + '.')):
                        reasons.append(f'port {p.number} {p.product} {p.version}')
        if field in (None, 'tech'):
            reasons += [f'technology {t.name}' for t in sub.technologies.all() if has(t.name)]
            if has(sub.webserver):
                reasons.append(f'web server {sub.webserver}')
            reasons += _route_reasons(sub, v, routes)
            reasons += _archive_reasons(sub, v, archive)
        for ip in sub.ip_addresses.all():
            if field in (None, 'os') and has(ip.os_guess):
                reasons.append(f'OS {ip.os_guess}')
            if field == 'country' and ip.geo_iso and (has(ip.geo_iso.iso) or has(ip.geo_iso.name)):
                reasons.append(f'country {ip.geo_iso.name or ip.geo_iso.iso}')
            for p in open_services(ip):
                label = f'port {p.number}{"/udp" if p.protocol == "udp" else ""} {" ".join(x for x in (p.product, p.version) if x) or p.service_name or ""}'.strip()
                if field == 'port' and str(p.number) == value:
                    reasons.append(label)
                elif field == 'proto' and (p.protocol or 'tcp') == v:
                    reasons.append(label)
                elif field in (None, 'product') and has(p.product):
                    reasons.append(label)
                elif field in (None, 'service') and has(p.service_name):
                    reasons.append(label)
                elif field is None and (has(p.version) or has(p.cpe) or str(p.number) == value):
                    reasons.append(label)
                elif field in (None, 'tech', 'banner') and (hit := _port_evidence(p, v, field)):
                    reasons.append(f'{label} ({hit})')
        if field in (None, 'vuln', 'sev'):
            for x in sub.vulnerability_set.all():
                if (field == 'sev' and SEVERITY_NAMES.get(x.severity) == v) or (field != 'sev' and has(x.name)):
                    reasons.append(f'finding {x.name}')
        if field in (None, 'cve'):
            reasons += [f'CVE {m.cve_entry.cve_id}' for m in sub.cve_matches.all() if has(m.cve_entry.cve_id)]
        if field is None and has(sub.page_title):
            reasons.append(f'title {sub.page_title}')
        if field == 'auth':
            reasons.append(f'auth {v}')
        if field == 'sensitive':
            reasons.append(f'sensitive {v}')
        if field == 'secret':
            reasons.append(f'secret {v}')
        if field == 'zombie' and v == 'yes':
            reasons.append('zombie: DNS gone, still answering')
    return list(dict.fromkeys(reasons))[:8]


def _alias_reasons(row, terms):
    """What each positive term matched in a host row's alias or note, for the results list (the row already carries both, so no query)."""
    reasons = []
    for neg, field, value, _quoted in terms:
        v = value.lower()
        if neg or field not in (None, 'host', 'alias', 'note'):
            continue
        if field != 'note' and v in row['alias'].lower():
            reasons.append(f'alias {row["alias"]}')
        if field in (None, 'note') and v in row['note'].lower():
            note = ' '.join(row['note'].split())
            reasons.append(f'note {note[:60]}{"…" if len(note) > 60 else ""}')
    return reasons


HEAT_FACET_VALUES = ('fire', 'smoke', 'ice', 'clean', 'unscanned')
HEAT_FACET_CAP = 5000  # hosts a facet count (and a ?heat= filter) will walk before reporting the rest truncated; a search
# this wide needs narrowing with q anyway, and a plain heat chip's own count stays an honest lower bound, never wrong upward


def _heat_facets(project, qs):
    """``({fire,smoke,ice,clean,unscanned: count}, {sub.id: heat}, truncated)`` for every host ``qs`` matches, up to
    HEAT_FACET_CAP, with the rule _host() itself uses (so a chip's count and a host's own badge never disagree). ``truncated`` means
    more than the cap matched q; the count is then a lower bound.

    Computed in the database: the heat of each row is the hottest of its live CVE matches (``match_heat_rank_expr``) and live findings
    (``finding_heat_rank_expr``), grouped by row, and a host is the group of rows ``host_siblings`` names, so no model instance of a
    match, finding, address or port is built. ``_heat_facets_walk`` is the same answer read through the models (the test pins them equal)."""
    from django.db.models import Max
    from cveFeed.counts import CLOSED, RULED_OUT, host_siblings
    from cveFeed.models import CVEMatch
    from cveFeed.threat import SEVERITY_HEAT, finding_heat_rank_expr, match_heat_rank_expr
    from startScan.models import ScanActivity, Subdomain, Vulnerability
    # one more than the cap is read, so "more matched than the cap" is known without a COUNT: when qs is the one-row-per-host collapse a COUNT is a second run of it
    own = list(qs.order_by('id').values_list('id', 'scan_history_id')[:HEAT_FACET_CAP + 1])
    truncated = len(own) > HEAT_FACET_CAP
    own = own[:HEAT_FACET_CAP]
    ids = [i for i, _s in own]
    siblings = host_siblings(ids)
    wanted = set(ids) | {i for rows in siblings.values() for i, _n in rows}
    scans = dict(own)
    extra = [i for i in wanted if i not in scans]
    if extra:
        scans.update(Subdomain.objects.filter(id__in=extra).values_list('id', 'scan_history_id'))
    wanted_ids = list(wanted)
    rank = {}
    for sub_id, r in (CVEMatch.objects.filter(subdomain_id__in=wanted_ids).exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED)
                      .annotate(_r=match_heat_rank_expr()).order_by().values('subdomain_id').annotate(top=Max('_r')).values_list('subdomain_id', 'top')):
        rank[sub_id] = max(rank.get(sub_id, 0), r or 0)
    findings = Vulnerability.objects.filter(subdomain_id__in=wanted_ids)
    for sub_id, r in (findings.filter(open_status=True, severity__in=list(SEVERITY_HEAT)).exclude(remediation_status__in=CLOSED)
                      .annotate(_r=finding_heat_rank_expr()).order_by().values('subdomain_id').annotate(top=Max('_r')).values_list('subdomain_id', 'top')):
        rank[sub_id] = max(rank.get(sub_id, 0), r or 0)
    has_finding = set(findings.order_by().values_list('subdomain_id', flat=True).distinct())
    done = set(ScanActivity.objects.filter(scan_of_id__in={s for s in scans.values() if s}, name__in=NUCLEI_STAGES, status=2)
               .order_by().values_list('scan_of_id', flat=True).distinct())
    names = {3: 'fire', 2: 'smoke', 1: 'ice'}
    counts = {v: 0 for v in HEAT_FACET_VALUES}
    heat_by_id = {}
    for sub_id in ids:
        group = [sub_id, *(i for i, _n in siblings.get(sub_id, []))]
        top = max(rank.get(i, 0) for i in group)
        if top:
            heat = names[top]
        else:  # no reason: clean if any copy has a finding or has been through nuclei, else unscanned
            heat = 'clean' if any(i in has_finding or scans.get(i) in done for i in group) else 'unscanned'
        counts[heat] += 1
        heat_by_id[sub_id] = heat
    return counts, heat_by_id, truncated


def _heat_facets_walk(project, qs):
    """``({fire,smoke,ice,clean,unscanned: count}, {sub.id: heat}, truncated)`` for every host ``qs`` matches, up to
    HEAT_FACET_CAP, computed with the same group-merge logic _host() itself uses (so a chip's count and a host's own
    badge never disagree). ``truncated`` means more than the cap matched q; the count is then a lower bound."""
    subs = list(qs.select_related('target_domain').prefetch_related(
        'ip_addresses__ports', 'cve_matches__cve_entry', triage_prefetch('cve_matches__triage'), 'vulnerability_set', triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags',
    ).order_by('id')[:HEAT_FACET_CAP + 1])
    truncated = len(subs) > HEAT_FACET_CAP
    subs = subs[:HEAT_FACET_CAP]
    others = _name_siblings(project, subs)
    _prime_nuclei(subs, *others.values())
    counts = {v: 0 for v in HEAT_FACET_VALUES}
    heat_by_id = {}
    for sub in subs:
        sibs = others.get(sub.id, [])
        _, reasons, _, _ = _merge_group(sub, sibs)
        heat = _host_heat_merged(sub, sibs, reasons)
        counts[heat] = counts.get(heat, 0) + 1
        heat_by_id[sub.id] = heat
    return counts, heat_by_id, truncated


HEAT_FACET_SECONDS = 15  # the least time the whole-match counts of a search (heat chips, facets, coverage) are served from the shared snapshot cache
HEAT_FACET_CEILING = 120  # the most: a walk over thousands of hosts that took T seconds is served for 10 x T, so the dashboard's poll never spends over a tenth of a core on it


def facet_freshness(took):
    """How long a walk that took ``took`` seconds is served from the snapshot cache."""
    return int(min(HEAT_FACET_CEILING, max(HEAT_FACET_SECONDS, 10 * (took or 0))))


def _cached_facets(project, qs, terms, params, facet_names, facet_size, with_unscannable):
    """What a search counts over its whole match (heat per host, the unscannable split, the other facets): walking up to HEAT_FACET_CAP hosts with
    everything their heat reads is the dearest thing the Hosts page and the dashboard's coverage tile ask for, and they ask every few seconds. It is a
    shared snapshot (``cveFeed.snapshot_cache``) keyed by who may see the rows (the project ids, the caller's allowed projects) and by the search
    itself, fresh for ``facet_freshness`` of what the last walk cost and dropped at once by a revision bump (a finding was closed)."""
    import time

    from django.core.cache import cache

    from cveFeed import snapshot_cache

    def compute():
        started = time.monotonic()
        counts, by_id, truncated = _heat_facets(project, qs)
        try:
            cache.set(cost_key, time.monotonic() - started, 3600)
        except Exception:  # noqa: BLE001
            pass
        return {'heat': counts, 'by_id': by_id, 'truncated': truncated,
                'unscannable': _unscannable_facet(qs, by_id) if with_unscannable else None,
                'facets': _search_facets(by_id.keys(), facet_names, facet_size) if facet_names else {}}
    ids = sorted(project.ids) if _is_all(project) else [project.pk]
    scope = snapshot_cache.scope_hash('search-facets', ids, [list(t) for t in terms], str(params.get('internal', '')).strip().lower(), facet_names, facet_size, with_unscannable)
    cost_key = f'cve:snap:search-facets:cost:{scope}'
    try:
        fresh = facet_freshness(cache.get(cost_key))
    except Exception:  # noqa: BLE001 - an unreadable cache is the shortest freshness, as everywhere in snapshot_cache
        fresh = HEAT_FACET_SECONDS
    return snapshot_cache.snapshot('search-facets', scope, compute, fresh)['payload']


def _unscannable_facet(qs, heat_by_id):
    """``{count, private, no_dns, unknown}``: the hosts counted as ``unscanned`` that have no address a scanner can use, so "never scanned" can say
    which are waiting their turn and which have nothing to scan. ``private`` points inside a private network (only a Sentinel inside it can scan
    it, once the project declares the range), ``no_dns`` has no DNS answer, ``unknown`` has not been looked at yet (cveFeed.unresolved_archive)."""
    from cveFeed.models import HostState
    out = {'count': 0, 'private': 0, 'no_dns': 0, 'unknown': 0}
    ids = [i for i, h in heat_by_id.items() if h == 'unscanned']
    if not ids:
        return out
    # the ids ARE rows of ``qs`` (the heat walk read them from it): looking them up in the table runs ``qs`` (the host collapse) no second time
    from startScan.models import Subdomain
    rows = list(Subdomain.objects.filter(id__in=ids, ip_addresses__isnull=True).order_by().values_list('target_domain__project_id', 'name').distinct())
    notes = {(p, h): n for p, h, n in HostState.objects.filter(
        project_id__in={p for p, _n in rows}, host__in={n.lower() for _p, n in rows}).values_list('project_id', 'host', 'resolution_note')}
    for project_id, name in rows:
        note = notes.get((project_id, name.lower()), '')
        out['count'] += 1
        out['private' if note.startswith('private') else 'no_dns' if note.startswith('no DNS') else 'unknown'] += 1
    return out


SEARCH_FACET_FIELDS = ('port', 'product', 'tech', 'os', 'country')
SEARCH_FACET_SIZE_DEFAULT = 10
SEARCH_FACET_SIZE_MAX = 50


def _search_facets(host_ids, names, size):
    """``{facet name: [{value, count}]}``, highest count first, over the given host ids: each count is the number of
    distinct hosts with that value, the same ids (and so the same cap and truncation) ``_heat_facets`` already counted
    for ``facets.heat``. ``host_ids`` can be any iterable (a dict's keys included); it is only ever used as a filter."""
    from django.db.models import Count
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(id__in=list(host_ids))
    sources = {
        'port': (base.filter(ip_addresses__ports__state__in=('', 'open')).exclude(ip_addresses__ports__number=0),
                 'ip_addresses__ports__number'),
        'product': (base.filter(ip_addresses__ports__state__in=('', 'open')).exclude(ip_addresses__ports__product=''),
                    'ip_addresses__ports__product'),
        'tech': (base.exclude(technologies__name=''), 'technologies__name'),
        'os': (base.exclude(ip_addresses__os_guess=''), 'ip_addresses__os_guess'),
        'country': (base.exclude(ip_addresses__geo_iso__isnull=True), 'ip_addresses__geo_iso__name'),
    }
    out = {}
    for name in names:
        qs, column = sources[name]
        rows = qs.values(column).annotate(n=Count('id', distinct=True)).order_by('-n', column)[:size]
        out[name] = [{'value': row[column], 'count': row['n']} for row in rows]
    return out


def _term_q(field, value, quoted, project):
    """The Q of one parsed term: a filter value takes a comma-separated list for OR, unless it was quoted."""
    from django.db.models import Q
    if field and not quoted and ',' in value:
        q = Q()
        for part in [p.strip() for p in value.split(',') if p.strip()][:MAX_SEARCH_TERMS]:
            q |= _term_filter(field, part, project)
        return q
    return _term_filter(field, value, project)


def _search_matches(project, terms):
    """The current-inventory Subdomain rows that satisfy every term (before they are folded into one row per host). The one
    place a search is turned into a queryset, shared by the interactive search and the saved-search evaluator."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    qs = _scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
    for neg, field, value, quoted in terms:
        q = _term_q(field, value, quoted, project)
        # A negated term is "no row of this host satisfies q". exclude(q) would split q's conditions on the same relation into one
        # subquery each (a port that is 161, and some port that is open), so a host with a closed port 161 plus any open port would
        # drop out. One positive filter inside a single subquery keeps every condition on the same port row.
        # A positive term is the same subquery, not a join on the outer query: a bare word joins technologies, addresses, ports, findings and CVE
        # matches at once, and the rows multiply (hosts x addresses x ports x findings x matches) before they are folded back into one per host.
        # That is what made a search over every project time out; a semi-join per term costs the host's own rows only.
        found = _host_has(q)
        qs = qs.filter(~found) if neg else qs.filter(found)
    return qs


def _host_has(q):
    """A condition on a Subdomain row that holds when some row of the host satisfies ``q``. ``q`` is the term's own Q: for a bare word a long OR over the host's
    addresses, ports, technologies, findings and CVE matches. Put in one subquery that is one join of all of them, and a word such as ``nginx`` made the
    database build 150,000 joined rows to find 1,300 hosts (300 ms, twice a search). The OR of conditions on one host's rows holds when any branch holds
    for some row, so each branch is its own semi-join and only joins what it needs (70 ms). A branch that is an AND (a port that is open AND has a
    product) stays one subquery, so its conditions still apply to the same port row."""
    from django.db.models import Exists, OuterRef, Q
    from startScan.models import Subdomain
    branches = [c if isinstance(c, Q) else Q(c) for c in q.children] if q.connector == Q.OR and not q.negated and len(q.children) > 1 else [q]
    found = Q()
    for branch in branches:
        found |= Q(Exists(Subdomain.objects.filter(branch, pk=OuterRef('pk'))))
    return found


def search_host_rows(project, terms):
    """One Subdomain row per host that matches ``terms``: what the interactive search lists and a saved search counts."""
    return _one_per_host(_search_matches(project, terms), per_project=_is_all(project))


def check_search(query):
    """The parsed terms of ``query``, or a 400 naming the problem: too long, too many terms, or a value a filter cannot take
    (``port:abc``, ``sev:scary``, a bad CIDR). Builds every term's filter without running it, so a saved search is rejected when
    it is saved, not when it is first evaluated. A search with no terms lists every host, which is nothing to watch: refused."""
    terms = parse_search(query)
    if not terms:
        raise ApiError(400, 'the search is empty: add at least one term, for example tech:grafana')
    for _, field, value, quoted in terms:
        _term_q(field, value, quoted, None)
    return terms


def search_hosts(ctx, slug, params):
    """Shodan-style host search. ``q`` is a space-separated list of ANDed terms: a bare word matches hostname, IP, technology,
    port product / service / version / CPE / banner, Server and X-Powered-By headers, cookie names, OS, finding name, CVE id and
    page title; ``tech:`` (everything a host runs, from any of that), ``banner:`` (service banners and NSE output), ``port:``, ``product:``,
    ``service:``, ``os:``, ``cve:``, ``ip:`` (an address or CIDR), ``host:``, ``vuln:``, ``sev:`` and ``auth:`` (open, login,
    session_required, sso ...) and ``sensitive:`` (any, credentials, pii, internal), ``secret:`` (any, p, s, i, live or a provider such as
    google: hosts that serve an exposed secret the inventory counts), ``zombie:`` (yes, no) and ``country:`` (ISO code
    or name) filter one field; a filter value takes a comma-separated list for OR (``port:80,443``), unless quoted; ``-term``
    negates; quote a phrase; a bare word followed by a dotted version (``wordpress 7.1``) is that product at that release, a version on its own
    keeps matching any text that contains it. ``exposed=1`` keeps only the exposed hosts (the dashboard tile's rule); ``heat`` (fire|smoke|ice|clean|unscanned) narrows the page to that heat; ``facets.heat`` in the response
    always counts every value over the whole match of q, ignoring ``heat`` itself, so the chips keep their real totals while one is
    selected. Counting heat walks the match (up to HEAT_FACET_CAP hosts), so ``facets=none`` skips it and every facet (``facets`` is
    then null), and ``page_size=0`` answers with ``count`` alone (no rows, no facets): the cheap modes for a poll, a palette or a badge.
    ``facets`` (comma-separated, among port|product|tech|os|country) adds the same whole-match counting for those fields,
    each up to ``facet_size`` values (default 10, max 50), highest count first. Each result says what matched. No ``q`` lists every
    host. Highest score first; ``sort=name`` for names."""
    from startScan.models import Subdomain
    project, _ = get_project(ctx, slug)
    heat = params.get('heat') or ''
    if heat and heat not in HEAT_FACET_VALUES:
        raise ApiError(400, f'heat must be one of {", ".join(HEAT_FACET_VALUES)}')
    facet_names = [f.strip() for f in (params.get('facets') or '').split(',') if f.strip() and f.strip().lower() != 'none']  # facets=none: see below
    bad_facets = [f for f in facet_names if f not in SEARCH_FACET_FIELDS]
    if bad_facets:
        raise ApiError(400, f'facets must be among {", ".join(SEARCH_FACET_FIELDS)}: unknown {", ".join(bad_facets)}')
    try:
        facet_size = min(SEARCH_FACET_SIZE_MAX, max(1, int(params.get('facet_size', SEARCH_FACET_SIZE_DEFAULT))))
    except (TypeError, ValueError, OverflowError):
        raise ApiError(400, 'facet_size must be an integer')
    terms = parse_search(params.get('q'))
    qs = _internal_filter(search_host_rows(project, terms), params)
    if str(params.get('exposed') or '').lower() in ('1', 'true', 'yes'):  # the hosts the dashboard's Exposed tile counts (cveFeed.counts.exposed_among)
        from cveFeed.counts import exposed_among
        qs = qs.filter(pk__in=exposed_among(qs, project_ids=None if _is_all(project) else [project.id]).values('pk'))
    # facets=none and page_size=0 are the cheap modes: no walk over the match for heat counts (a poll, a palette, an export page need none)
    counts_only = page_args(params, zero_ok=True)[1] == 0
    no_facets = counts_only or str(params.get('facets') or '').strip().lower() == 'none'
    if no_facets:
        facet_names = []
    if counts_only and not heat:
        return {'count': qs.count(), 'page': 1, 'page_size': 0, 'results': [], 'facets': None, 'has_internal': _any_internal()}
    if heat or not no_facets:
        bundle = _cached_facets(project, qs, terms, params, facet_names, facet_size, with_unscannable=not no_facets)
        heat_counts, heat_by_id, heat_truncated, unscannable, search_facets = bundle['heat'], bundle['by_id'], bundle['truncated'], bundle['unscannable'], bundle['facets']
    else:
        heat_counts, heat_by_id, heat_truncated, unscannable, search_facets = {}, {}, False, None, {}
    if heat:
        qs = qs.filter(id__in=[i for i, h in heat_by_id.items() if h == heat])
    ordered = qs.order_by(*_host_order(params))

    def load(ids):  # the page's rows with what the host cards read, in the order of ``ids``
        rows = Subdomain.objects.filter(pk__in=ids).select_related('target_domain__project' if _is_all(project) else 'target_domain').prefetch_related(
            'ip_addresses__ports', 'cve_matches__cve_entry', triage_prefetch('cve_matches__triage'), 'vulnerability_set', triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags', 'technologies')
        by_id = {row.pk: row for row in rows}
        return [by_id[i] for i in ids if i in by_id]
    # the ids are read once and paged in Python (paginate_by_ids): the page used to run the collapse for its COUNT and again for its slice
    page = _mark_zombies(project, _hosts_page(project, ordered, params, load=load, page_extra=lambda subs, shared: _matched_for_page(subs, shared, terms)))
    for row in page['results']:
        row['matched'] = list(dict.fromkeys([*_alias_reasons(row, terms), *row['matched']]))[:8]
    page['facets'] = None if no_facets else {'heat': heat_counts, 'truncated': heat_truncated, 'unscannable': unscannable,
                                             **search_facets}
    page['has_internal'] = _any_internal()  # a project the caller sees declared an internal network: the page offers the scope filter
    return page


def _any_internal():
    from cveFeed import internal_view
    return internal_view.any_visible()


def _matches_of_host():
    """Prefetch of each finding's host's CVE matches (one query for a page, whether or not any exists): where a CVE id links to."""
    from django.db.models import Prefetch

    from cveFeed.models import CVEMatch
    return Prefetch('subdomain__cve_matches', queryset=CVEMatch.objects.select_related('cve_entry'))


def _cve_match_ids(v):
    """{CVE id: match id} for the CVEs this finding names that CVEngine also matched on the same host: where each CVE links to."""
    if not v.subdomain_id:
        return {}
    matches = {m.cve_entry.cve_id.upper(): m.id for m in v.subdomain.cve_matches.all()}
    return {c.name: matches[c.name.upper()] for c in v.cve_ids.all() if c.name.upper() in matches}


def _vuln(v):
    return {'id': v.id, 'name': v.name, 'severity': SEVERITY_NAMES.get(v.severity, str(v.severity)),
            'url': v.http_url, 'host': v.subdomain.name if v.subdomain else None, 'open': v.open_status,
            'cves': [c.name for c in v.cve_ids.all()], 'cve_matches': _cve_match_ids(v), 'discovered': _iso(v.discovered_date),
            'description': v.description, 'remediation': v.remediation, 'source': v.source,
            'remediation_status': v.remediation_status, 'remediation_note': v.remediation_note,
            'remediation_updated': _iso(v.remediation_updated_at),
            'status_changed_at': _iso(v.remediation_updated_at), 'status_changed_by': _user_brief(v.remediation_by),
            'assignee': _user_brief(v.assignee), 'comment_count': _comment_count(v, 'vulnerability'), **_closure_fields('vulnerability', v),
            'seen_while_authenticated': any(t.name == 'seen-while-authenticated' for t in v.tags.all()),  # an authenticated request saw it (cveFeed.auth_checks)
            'first_seen': _iso(_seen(v, 'first_seen', v.discovered_date)), 'last_seen': _iso(_seen(v, 'last_seen', v.discovered_date)),
            'internal': _internal_row(v.target_domain.project_id if v.target_domain_id else None, v.subdomain.name if v.subdomain else ''),
            'heat_override': _heat_override(_triage_of(v)), 'triage': _triage_brief(_triage_of(v)),
            'retest': _retest_of(v)}


def _internal_row(project_id, host):
    """Whether a row's host is inside a network its project declared internal (``cveFeed.internal_view``)."""
    from cveFeed import internal_view
    return internal_view.is_internal(project_id, host)


def list_vulnerabilities(ctx, slug, params):
    from startScan.models import Vulnerability
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(Vulnerability.objects.all(), project, 'target_domain__project').select_related('subdomain', 'target_domain', 'triage__verdict', 'triage__heat_override_by', 'remediation_by', 'assignee') \
        .prefetch_related('cve_ids', 'tags', _matches_of_host()).annotate(comment_count=_comment_count_annotation('vulnerability')).order_by('-severity', '-id')
    if everywhere:
        qs = qs.select_related('target_domain__project')
    inverse = {v: k for k, v in SEVERITY_NAMES.items()}
    if params.get('severity') in inverse:
        qs = qs.filter(severity=inverse[params['severity']])
    elif params.get('severity') == 'actionable':  # everything but informational: the Vulnerabilities page's default view
        from cveFeed.counts import actionable_findings
        qs = actionable_findings(qs)
    if params.get('open') in ('true', 'false'):
        qs = qs.filter(open_status=params['open'] == 'true')
    if params.get('classification'):
        qs = qs.filter(triage__classification=params['classification'])
    qs = _internal_filter(qs, params, 'subdomain__')
    return paginate(qs, params, _tagged(_vuln, lambda v: v.target_domain.project) if everywhere else _vuln)


def _cert(c):
    return {'id': c.id, 'host': c.host, 'port': c.port, 'subject': c.subject, 'issuer': c.issuer, 'sans': c.sans[:10],
            'not_before': _iso(c.not_before), 'not_after': _iso(c.not_after), 'days_left': c.days_left,
            'signature_algorithm': c.signature_algorithm, 'key': c.key_description, 'protocol': c.protocol,
            'chain_error': c.chain_error, 'legacy_tls': c.legacy_tls, 'checked': _iso(c.checked_at)}


def list_certificates(ctx, slug, params):
    """TLS certificates seen on the project's hosts, soonest expiry first. ?expiring_within=30 narrows to those due."""
    from cveFeed.models import TlsCertificate
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(TlsCertificate.objects.all(), project, 'domain__project').order_by('not_after', 'id')
    if everywhere:
        qs = qs.select_related('domain__project')
    if _digits(params.get('expiring_within'), 6):
        from cveFeed.counts import expiring_certificates
        qs = expiring_certificates(qs, int(params['expiring_within']))
    if params.get('q'):
        qs = qs.filter(host__icontains=params['q'])
    return paginate(qs, params, _tagged(_cert, lambda c: c.domain.project) if everywhere else _cert)


def _situation_ids(project):
    return list(project.ids) if _is_all(project) else [project.pk]


def list_situations(ctx, slug, params):
    """What needs a person, one host at a time, ranked (cveFeed.situations: the rank rule and the narrative are documented there). ``q``: part of a
    host name. Paged (``page``, ``page_size``); ``state`` is ``attention``, ``clear`` (scanned, nothing needs you) or ``unscanned``. The all-projects
    view ranks across the projects the caller can see; each row names its project."""
    from cveFeed import situations
    project, _ = get_project(ctx, slug)
    page, size = page_args(params, zero_ok=True)
    q = str(params.get('q') or '').strip()[:200]
    tier = str(params.get('tier') or 'all').strip().lower()
    if tier not in situations.WORST_AT_LEAST:
        raise ApiError(400, f'tier must be {", ".join(situations.WORST_AT_LEAST)}')
    return situations.listing(_situation_ids(project), q=q, page=page, size=size, tier=tier)


def get_situation(ctx, slug, host):
    """One situation with its narrative and up to 200 of its findings, each with the link that opens it. 404 when nothing open on the host needs a person
    (or it is not in the project). Needs one project: a host name can exist in two."""
    from cveFeed import situations
    project, _ = get_one_project(ctx, slug)
    row = situations.one([project.pk], host)
    if row is None:
        raise ApiError(404, 'no situation for this host: nothing open on it needs a person')
    return row


def _hygiene(f):
    return {'id': f.id, 'host': f.host, 'check': f.check_name, 'severity': SEVERITY_NAMES.get(f.severity, str(f.severity)),
            'title': f.title, 'detail': f.detail, 'evidence': f.evidence, 'status': f.status,
            'remediation_status': f.remediation_status, 'remediation_note': f.remediation_note,
            'remediation_updated': _iso(f.remediation_updated_at),
            'status_changed_at': _iso(f.remediation_updated_at), 'status_changed_by': _user_brief(f.remediation_by),
            'assignee': _user_brief(f.assignee), 'comment_count': _comment_count(f, 'hygiene'), **_closure_fields('hygiene', f),
            'first_seen': _iso(f.first_seen), 'last_seen': _iso(f.last_seen), 'domain': f.domain.name,
            'triage': _triage_brief(_triage_of(f)),
            'retest': _retest_of(f)}


def list_hygiene(ctx, slug, params):
    """TLS, certificate, email-authentication (SPF, DKIM, DMARC, CAA) and cleartext-service findings."""
    from cveFeed.models import HygieneFinding
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(HygieneFinding.objects.all(), project, 'domain__project').select_related(
        'domain__project' if everywhere else 'domain', 'triage__verdict', 'remediation_by', 'assignee') \
        .annotate(comment_count=_comment_count_annotation('hygiene')).order_by('-severity', 'host', 'id')
    qs = qs.filter(status=params.get('status') or 'open')
    inverse = {v: k for k, v in SEVERITY_NAMES.items()}
    if params.get('severity') in inverse:
        qs = qs.filter(severity=inverse[params['severity']])
    if params.get('check'):
        qs = qs.filter(check_name__startswith=params['check'])  # e.g. spf, dmarc, dkim, tls, cleartext
    if params.get('q'):
        qs = qs.filter(host__icontains=params['q'])
    return paginate(qs, params, _tagged(_hygiene, lambda f: f.domain.project) if everywhere else _hygiene)


def _change(c):
    return {'id': c.id, 'kind': c.kind, 'host': c.host, 'ip': c.ip or None, 'port': c.port, 'before': c.before,
            'after': c.after, 'target': c.domain.name, 'target_id': c.domain_id, 'scan_id': c.scan_id,
            'detected': _iso(c.detected_at)}


_SINCE_SHORT = re.compile(r'^(\d{1,4})([hdw])$')


def _since(params, default_days=7):
    """?since= accepts an ISO 8601 datetime or a shorthand like 24h / 7d / 4w; default: the last 7 days."""
    from datetime import timedelta

    from django.utils.dateparse import parse_datetime
    raw = (params.get('since') or '').strip()
    if not raw:
        return timezone.now() - timedelta(days=default_days)
    short = _SINCE_SHORT.match(raw.lower())
    if short:
        unit = {'h': 'hours', 'd': 'days', 'w': 'weeks'}[short.group(2)]
        return timezone.now() - timedelta(**{unit: int(short.group(1))})
    try:
        when = parse_datetime(raw)
    except ValueError:
        when = None
    if when is None:
        raise ApiError(400, 'since must be an ISO 8601 datetime or a shorthand such as 24h, 7d or 4w')
    return timezone.make_aware(when) if timezone.is_naive(when) else when


def list_changes(ctx, slug, params):
    """What changed in the inventory since ?since= (default 7 days): hosts appearing or retiring, ports opened or closed,
    product/version, technology, certificate and auth-state changes. Newest first."""
    from cveFeed.models import AssetChange
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(AssetChange.objects.filter(detected_at__gte=_since(params)), project, 'project').select_related('domain', *(['project'] if everywhere else []))
    if params.get('kind'):
        if params['kind'] not in AssetChange.KINDS:
            raise ApiError(400, f'kind must be one of: {", ".join(AssetChange.KINDS)}')
        qs = qs.filter(kind=params['kind'])
    if params.get('host'):
        qs = qs.filter(host__icontains=params['host'])
    if params.get('target_id'):
        qs = qs.filter(domain_id=_int_param(params['target_id'], 'target_id'))
    if params.get('scan_id'):
        qs = qs.filter(scan_id=_int_param(params['scan_id'], 'scan_id'))
    return paginate(qs.order_by('-detected_at', '-id'), params, _tagged(_change, lambda c: c.project) if everywhere else _change)


def activity_days(ctx, slug, params):
    """The dashboard's Activity card: exact per-day counts of new findings (by heat tier and type) and inventory changes for the last ``days``
    (default 90, at most 366) calendar days in ``tz`` (an IANA name, default UTC; ``series`` picks findings, changes and scans, default the first two): one grouped query per series, over the same scoped querysets
    the Findings (``status=all``) and Changes lists use (``cveFeed.activity_days``). Shared through the snapshot cache like the other dashboard
    cards, so a poll or a second viewer of the same scope costs no query."""
    from cveFeed import activity_days as ad
    from cveFeed import snapshot_cache
    from cveFeed.models import AssetChange
    project, _ = get_project(ctx, slug)
    try:
        days = min(ad.MAX_DAYS, max(1, int(params.get('days', ad.DEFAULT_DAYS))))
    except (TypeError, ValueError, OverflowError):
        raise ApiError(400, 'days must be an integer')
    zone = ad.zone_of(params.get('tz'))
    first, last, _start, _end = ad.window(days, zone)
    wanted = tuple(sorted({x.strip() for x in str(params.get('series') or 'findings,changes').split(',') if x.strip()}))
    if not wanted or any(x not in ('findings', 'changes', 'scans') for x in wanted):
        raise ApiError(400, 'series must be a list of findings, changes and scans')

    def compute():
        from startScan.models import ScanHistory
        return ad.build(_finding_sources(project, {'status': 'all'}) if 'findings' in wanted else None,
                        _scoped(AssetChange.objects.all(), project, 'project') if 'changes' in wanted else None, days, str(zone),
                        scans_qs=_scoped(ScanHistory.objects.all(), project, 'domain__project') if 'scans' in wanted else None)
    ids = sorted(project.ids) if _is_all(project) else [project.pk]
    scope = snapshot_cache.scope_hash('activity-days', ids, str(zone), days, wanted, last.isoformat())  # a new local day is a new key
    return snapshot_cache.snapshot('activity-days', scope, compute, ACTIVITY_DAYS_FRESH_SECONDS)['payload']


ACTIVITY_DAYS_FRESH_SECONDS = 30  # a count of days, not a live number: one build serves every viewer of the scope for this long (a closed finding drops it at once, as for the other cards)


MAX_STATS_HISTORY_DAYS = 365


def _snapshot_row(s):
    return {'date': s.date.isoformat(), 'hosts': s.hosts, 'exposed_hosts': s.exposed_hosts,
            'open_findings': s.open_findings, 'cve_matches': s.cve_matches, 'fixed': s.fixed,
            'mean_days_to_fix': s.mean_days_to_fix}


def stats_history(ctx, slug, params):
    """Daily snapshots of this project's inventory and findings counts, oldest first, for the trend charts nothing else
    in the schema keeps a past for: ?days= (default 90, capped at 365). Each row is {date, hosts, exposed_hosts,
    open_findings: {critical..info}, cve_matches: {fire, smoke, ice}, fixed, mean_days_to_fix}, written once a day by
    cveFeed.tasks.snapshot_daily_stats; a day with no row (the feature just turned on, or a day the beat task missed)
    is simply absent rather than backfilled. ``_all`` sums every visible project's rows for each date; its
    mean_days_to_fix is the unweighted mean of the projects that have one that day, since the raw per-finding
    durations are not stored."""
    from datetime import timedelta

    from cveFeed.models import StatsSnapshot
    from cveFeed.stats_history import CVE_MATCH_HEATS, OPEN_FINDING_BANDS
    project, _ = get_project(ctx, slug)
    try:
        days = min(MAX_STATS_HISTORY_DAYS, max(1, int(params.get('days', 90))))
    except (TypeError, ValueError, OverflowError):
        raise ApiError(400, 'days must be an integer')
    since = timezone.localdate() - timedelta(days=days - 1)
    qs = _scoped(StatsSnapshot.objects.filter(date__gte=since), project, 'project').order_by('date')
    if not _is_all(project):
        return [_snapshot_row(s) for s in qs]
    by_date = {}
    for s in qs:
        row = by_date.setdefault(s.date, {'date': s.date.isoformat(), 'hosts': 0, 'exposed_hosts': 0,
                                           'open_findings': {b: 0 for b in OPEN_FINDING_BANDS},
                                           'cve_matches': {h: 0 for h in CVE_MATCH_HEATS}, 'fixed': 0, '_days': []})
        row['hosts'] += s.hosts
        row['exposed_hosts'] += s.exposed_hosts
        row['fixed'] += s.fixed
        for band, n in (s.open_findings or {}).items():
            if band in row['open_findings']:
                row['open_findings'][band] += n
        for heat, n in (s.cve_matches or {}).items():
            if heat in row['cve_matches']:
                row['cve_matches'][heat] += n
        if s.mean_days_to_fix is not None:
            row['_days'].append(s.mean_days_to_fix)
    results = []
    for row in by_date.values():
        days_list = row.pop('_days')
        row['mean_days_to_fix'] = round(sum(days_list) / len(days_list), 2) if days_list else None
        results.append(row)
    return sorted(results, key=lambda r: r['date'])


def _activity(a):
    scan_id = (a.detail or {}).get('scan_id')
    return {'id': a.id, 'kind': a.kind, 'message': a.message, 'status': a.status, 'repeat': a.repeat,
            'cve_id': a.cve_id or None, 'scan_id': scan_id if isinstance(scan_id, int) else None,
            'project': a.project.slug if a.project_id else None,
            'created': _iso(a.created_at), 'finished': _iso(a.finished_at)}


def list_activity(ctx, slug, params):
    """What the AI engine did, newest first: this project's entries plus the system-wide ones (no project). ?kind= filters."""
    from django.db.models import Q

    from cveFeed.models import AgentActivity
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = AgentActivity.objects.filter(Q(project_id__in=list(project.ids)) | Q(project__isnull=True)).select_related('project') if everywhere \
        else AgentActivity.objects.filter(Q(project=project) | Q(project__isnull=True)).select_related('project')
    if params.get('kind'):
        if params['kind'] not in AgentActivity.KINDS:
            raise ApiError(400, f'kind must be one of: {", ".join(AgentActivity.KINDS)}')
        qs = qs.filter(kind=params['kind'])
    return paginate(qs.order_by('-id'), params, _tagged(_activity, lambda a: a.project) if everywhere else _activity)


def _route(r):
    return {'id': r.id, 'host': r.host, 'url': r.url, 'path': r.path, 'auth_state': r.auth_state, 'http_status': r.http_status,
            'redirect_to': r.redirect_to or None, 'provider': r.provider or None, 'title': r.title, 'evidence': r.evidence,
            'sensitive': r.sensitive, 'sensitive_score': r.sensitive_score,  # counts and masked samples only, never values
            'retired_at': _iso(r.retired_at), 'zombie_since': _iso(r.zombie_since),
            'target': r.domain.name, 'checked': _iso(r.checked_at), 'first_seen': _iso(r.first_seen),
            'triage': _triage_brief(_triage_of(r))}


def list_routes(ctx, slug, params):
    """Web routes and how they answer an anonymous GET: open, login, session_required, sso, redirect, not_found, catch_all (the server answers every path alike), error."""
    from cveFeed.models import RouteAuth
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(RouteAuth.objects.all(), project, 'project').select_related('domain', 'triage__verdict', *(['project'] if everywhere else []))
    if params.get('auth_state'):
        if params['auth_state'] not in RouteAuth.STATES:
            raise ApiError(400, f'auth_state must be one of: {", ".join(RouteAuth.STATES)}')
        qs = qs.filter(auth_state=params['auth_state'])
    if params.get('host'):
        qs = qs.filter(host__icontains=params['host'])
    if params.get('q'):
        qs = qs.filter(url__icontains=params['q'])
    if params.get('sensitive') in ('1', 'true'):
        qs = qs.filter(sensitive_score__gt=0)
    if params.get('zombie') in ('1', 'true'):
        qs = qs.filter(zombie_since__isnull=False)
    if params.get('target_id'):
        qs = qs.filter(domain_id=_int_param(params['target_id'], 'target_id'))
    return paginate(qs.order_by('host', 'path', 'id'), params, _tagged(_route, lambda r: r.project) if everywhere else _route)


def run_hygiene_checks(ctx, slug, target_id=None):
    """Queue a certificate / TLS / SPF / DKIM / DMARC check for one target, or every target in the project."""
    from cveFeed.tasks import run_hygiene_task
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    qs = Domain.objects.filter(project=project)
    if target_id:
        qs = qs.filter(id=target_id)
    ids = list(qs.values_list('id', flat=True))
    if target_id and not ids:
        raise ApiError(404, 'target not found')
    for domain_id in ids:
        run_hygiene_task.delay(domain_id)
    return {'queued': len(ids)}


# --- project-level API keys (Shodan, Censys, ...) -------------------------------

def list_api_credentials(ctx, slug):
    """What services are configured for this project (and inherited from its org), never the secrets
    themselves. Readable by anyone who can see the project; only a project or organization admin may change them (as the
    organization's own keys, which a project key overrides)."""
    from cveFeed.api_credentials import SERVICES, service_entry
    from dashboard.models import ApiCredential
    project, role = get_one_project(ctx, slug)  # secrets belong to one project
    org_rows = {c.service: c for c in ApiCredential.objects.filter(org_id=project.org_id)} if project.org_id else {}
    project_rows = {c.service: c for c in ApiCredential.objects.filter(project=project)}
    results = []
    for service, (label, fields, _) in SERVICES.items():
        cred = project_rows.get(service) or org_rows.get(service)
        results.append({**service_entry(service, label, fields, cred),
                        'scope': ('project' if service in project_rows else 'org' if cred else None)})
    return {'results': results, 'can_edit': role == roles.ADMIN and not (ctx.token and ctx.token.read_only)}


def _api_key_project(ctx, slug):
    """The project for changing its API keys: a project key replaces the organization's key for every scan of the project, so it needs the
    admin role (the project's, its organization's, or an App Admin), like the organization's own keys."""
    project, role = get_project(ctx, slug, write=True)
    if role != roles.ADMIN:
        raise ApiError(403, 'project API keys are managed by a project or organization admin')
    return project, role


def set_api_credential(ctx, slug, service, values):
    """Save a project's own key for ``service``. A blank field keeps whatever was stored for that field."""
    from cveFeed.api_credentials import RETIRED, SERVICES
    from dashboard.models import ApiCredential
    project, _ = _api_key_project(ctx, slug)
    if service not in SERVICES:
        raise ApiError(404, f'unknown service {service!r}')
    if service in RETIRED:
        raise ApiError(410, RETIRED[service])
    _, fields, _ = SERVICES[service]
    values = values if isinstance(values, dict) else {}
    cred = ApiCredential.objects.filter(project=project, service=service).first() or ApiCredential(project=project, service=service)
    value = dict(cred.value or {})
    for name, _label, _secret in fields:
        if values.get(name) and str(values[name]).strip():
            value[name] = str(values[name]).strip()[:500]
    if not value:  # never store an empty row: it would show as configured while feeding nothing to bbot
        raise ApiError(400, 'enter a value to save')
    cred.value = value
    cred.save()
    from cveFeed.admin_api import audit
    audit(ctx.user, 'project.api_key.set', f'{project.slug}:{service}', org=project.org_id)
    return {'service': service, 'scope': 'project'}


def delete_api_credential(ctx, slug, service):
    """Remove the project's own key for ``service`` (its organization's key, if any, still applies)."""
    from dashboard.models import ApiCredential
    project, _ = _api_key_project(ctx, slug)
    removed, _ = ApiCredential.objects.filter(project=project, service=service).delete()
    if removed:
        from cveFeed.admin_api import audit
        audit(ctx.user, 'project.api_key.remove', f'{project.slug}:{service}', org=project.org_id)
    return {'deleted': True}


# --- runZero asset inventory (cveFeed.runzero_sync) -----------------------------

def _runzero_project(ctx, slug, write=False):
    """The project, for a runZero operation: it reaches an outside service with the project's token and can add targets, so it is
    for an App Admin or the project's organization admin, never for a plain member."""
    project, role = get_one_project(ctx, slug, write=write)
    if role != roles.ADMIN:
        raise ApiError(403, 'the runZero sync is managed by an organization admin or an App Admin')
    return project


def get_runzero(ctx, slug):
    """The runZero sync of this project: whether a token is saved, whether importing new targets is on and with which search,
    when it last ran, how it went (counts or the last error) and how often it runs. Never the token."""
    from cveFeed import runzero_sync
    return runzero_sync.status(_runzero_project(ctx, slug))


def set_runzero(ctx, slug, body):
    """Change this project's runZero settings: ``import_enabled`` (add the addresses runZero knows and cvENGINE does not as
    targets; off by default) and ``search`` (the runZero inventory search that limits what is imported; blank means alive:true)."""
    from cveFeed import runzero_sync
    project = _runzero_project(ctx, slug, write=True)
    body = body if isinstance(body, dict) else {}
    if 'import_enabled' not in body and 'search' not in body:
        raise ApiError(400, 'send import_enabled and/or search')
    if 'import_enabled' in body and not isinstance(body['import_enabled'], bool):
        raise ApiError(400, 'import_enabled must be true or false')
    if 'search' in body and not isinstance(body['search'], str):
        raise ApiError(400, 'search must be text')
    row = runzero_sync.settings_for(project)
    if 'import_enabled' in body:
        row.import_enabled = body['import_enabled']
    if 'search' in body:
        row.search = runzero_sync.clean_search(body['search'])
    row.save(update_fields=['import_enabled', 'search', 'updated_at'])
    from cveFeed.admin_api import audit
    audit(ctx.user, 'project.runzero.settings', project.slug, org=project.org_id, import_enabled=row.import_enabled)
    return runzero_sync.status(project)


def run_runzero_sync(ctx, slug):
    """Queue a runZero sync of this project now (it also runs on its own schedule). One at a time, and not more than once a minute."""
    from cveFeed import runzero_sync
    from cveFeed.tasks import runzero_sync_project
    project = _runzero_project(ctx, slug, write=True)
    if not runzero_sync.token_for(project):
        raise ApiError(400, 'save a runZero token for this project or its organization first (API keys)')
    current = runzero_sync.status(project)
    if current['state'] == 'running':
        raise ApiError(409, 'a runZero sync of this project is already running')
    row = runzero_sync.settings_for(project)
    if row.started_at and timezone.now() - row.started_at < runzero_sync.MIN_GAP:
        raise ApiError(429, 'a runZero sync started less than a minute ago; wait a moment')
    runzero_sync_project.delay(project.id)
    from cveFeed.admin_api import audit
    audit(ctx.user, 'project.runzero.sync', project.slug, org=project.org_id)
    return {'queued': True}


# --- CVEs, matches and remediation ---------------------------------------------

def _cve_description(c, limit=500):
    """Use the feed's human prose, falling back to its title; never fill a gap with a guessed vulnerability."""
    text = (c.summary or c.original_description or c.title or '').strip()
    return text[:limit].rsplit(' ', 1)[0] + '…' if len(text) > limit and ' ' in text[:limit] else text[:limit]


MAX_LISTED_RANGES = 60  # ranges of one affected block an advisory lists in full; more are counted (ranges_total), never cut silently


def _cve_context(c):
    """Structured advisory context. Unknown feed signals stay unknown, not false."""
    from urllib.parse import urlparse
    refs = []
    for ref in (c.references if isinstance(c.references, list) else [])[:40]:
        url = ref if isinstance(ref, str) else ref.get('url', '') if isinstance(ref, dict) else ''
        if not isinstance(url, str) or len(url) > 2000:
            continue
        try:
            parsed = urlparse(url)
            allowed = parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
        except ValueError:
            continue
        if allowed:
            refs.append(url)
    if re.fullmatch(r'CVE-\d{4}-\d{4,}', c.cve_id, re.I):
        refs = [f'https://www.cve.org/CVERecord?id={c.cve_id}', f'https://nvd.nist.gov/vuln/detail/{c.cve_id}', *refs]
    listed = ((getattr(c, 'intel', None) or {}).get('kev') or {}) if isinstance(getattr(c, 'intel', None), dict) else {}
    if c.kev is True and (not listed or 'cisa_kev' in listed):  # known exploited by CISA, not only by another catalogue
        refs.insert(0, 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog')
    from cveFeed.correlation import MAX_RANGES_PER_ITEM, prepared_ranges  # the ranges as matching reads them
    affected = []
    for item in (c.affected if isinstance(c.affected, list) else [])[:30]:
        if isinstance(item, dict):
            part = {k: item.get(k) for k in ('vendor', 'product', 'package') if isinstance(item.get(k), str) and item.get(k)}
            # every range matching reads, never a silent cut: a record with 25 release branches (WordPress' CVE-2026-119977, 4.7 through
            # 7.1.3) read as if it stopped at the 20th (6.6.10) looked like a match made from the description
            ranges = prepared_ranges((item.get('ranges') if isinstance(item.get('ranges'), list) else [])[:MAX_RANGES_PER_ITEM], keep_unusable=True)
            part['ranges'] = [{k: v for k, v in rng.items() if isinstance(v, (str, int, float))} for rng in ranges[:MAX_LISTED_RANGES]]
            if len(ranges) > MAX_LISTED_RANGES:
                part['ranges_total'] = len(ranges)  # the list above is the first MAX_LISTED_RANGES of them
            if isinstance(item.get('range_corrections'), list) and item['range_corrections']:
                part['range_corrections'] = item['range_corrections'][:5]  # a bound cvENGINE corrected, with its sources (range_corrections)
            affected.append(part)
    return {'description': (c.original_description or c.summary or c.title or '').strip()[:12000],
            'summary': (c.summary or '').strip()[:3000], 'affected': affected, 'references': list(dict.fromkeys(refs))[:40],
            'sources': [s for s in (c.sources if isinstance(c.sources, list) else [])[:20]
                        if isinstance(s, (str, dict))],
            'exploitation': {'cisa_kev': c.kev, 'exploit_db': c.exploit_db, 'epss_elevated': c.epss_reached, **_intel_brief(c),
                             'note': 'Catalog and exploit references describe the CVE, not proof that this host is vulnerable.'}}


def _intel_brief(c):
    """Who reported each exploitation signal (cveFeed.intel), for the advisory panel; empty when only cve.now spoke."""
    from cveFeed.intel import SOURCES
    intel = c.intel if isinstance(getattr(c, 'intel', None), dict) else {}
    kev = intel.get('kev') if isinstance(intel.get('kev'), dict) else {}
    exploits = intel.get('exploits') if isinstance(intel.get('exploits'), dict) else {}
    epss = intel.get('epss') if isinstance(intel.get('epss'), dict) else {}
    out = {}
    if kev:
        out['exploited_by'] = [{'source': SOURCES[name]['label'], 'since': str((detail or {}).get('added') or (detail or {}).get('since') or '')[:40],
                                'ransomware': bool((detail or {}).get('ransomware'))} for name, detail in kev.items() if name in SOURCES]
    if exploits:
        out['public_exploits'] = {SOURCES[name]['label']: len(items) for name, items in exploits.items()
                                  if name in SOURCES and isinstance(items, list)}
    if isinstance(epss.get('score'), (int, float)):
        out['epss'] = {'score': epss['score'], 'percentile': epss.get('percentile')}
    return out

def _cve(c, brief=False):
    from cveFeed.threat import classify_threat_tier
    tier = classify_threat_tier(kev=c.kev, epss_reached=c.epss_reached, exploit_db=c.exploit_db, cvss=c.cvss)
    out = {'cve_id': c.cve_id, 'title': c.title, 'short_description': _cve_description(c, 180),
           'cvss': c.cvss, 'tier': tier, 'kev': c.kev,
           'exploit_db': c.exploit_db, 'published': _iso(c.published_at), 'local_only': bool(c.local_only)}
    if not brief:
        out.update(_cve_context(c))
    return out


def _require_member(ctx):
    if not roles.user_best_role(ctx.user):
        raise ApiError(403, 'no organization or project access')


def list_cve_feed(ctx, params):
    from cveFeed.models import CVEEntry
    _require_member(ctx)
    qs = CVEEntry.objects.order_by('-published_at', '-id')
    if params.get('q'):
        qs = qs.filter(cve_id__icontains=params['q'])
    wanted = params.get('tier')
    if wanted:  # filtered by the database, as the dashboard's tier tiles count it (``views.tier_counts``): the count is the true total, not a sample
        from cveFeed.threat import FIRE, ICE, SMOKE, fire_tier_q, hot_tier_q
        if wanted == FIRE:
            qs = qs.filter(fire_tier_q())
        elif wanted == SMOKE:
            qs = qs.filter(hot_tier_q()).exclude(fire_tier_q())
        elif wanted == ICE:
            qs = qs.exclude(hot_tier_q())
        else:
            qs = qs.none()  # an unknown tier matches nothing, as the old filter did
    return paginate(qs, params, lambda c: _cve(c, brief=True))


def _detection(c):
    """The shared detection strategy of a CVE (cveFeed.detection), or None before one is written. It is data about the CVE, the
    same for every organization."""
    row = getattr(c, 'detection', None) if c.pk else None
    if row is None:
        return None
    strategy = row.strategy or None
    if strategy:
        # re-validated and re-rendered on read: the commands and the profile are always the current renderer's (an older record's dpkg
        # check of an npm packaging, or an nmap step for a JavaScript file, is never shown), whoever wrote the record
        from cveFeed import detection
        clean, _ = detection.validate_strategy(strategy)
        strategy = detection.finalize(clean, c.cvss_vector) if clean else strategy
    return {'source': row.source, 'schema_version': row.schema_version, 'strategy': strategy,
            'ai_model': row.ai_model or None, 'updated': _iso(row.updated_at)}


def get_cve(ctx, cve_id):
    from cveFeed.models import CVEEntry
    _require_member(ctx)
    c = CVEEntry.objects.filter(cve_id=cve_id.upper()).select_related('detection').first()
    if not c:
        raise ApiError(404, 'CVE not found')
    out = _cve(c)
    out['detection'] = _detection(c)
    return out


def get_cve_detection(ctx, cve_id):
    """The detection strategy alone: remote and local checks, as data an agent or scanner can act on with its own primitives."""
    return get_cve(ctx, cve_id)['detection'] or {'source': None, 'strategy': None,
                                                  'note': 'no detection strategy has been written for this CVE yet'}


def update_cve_detection(ctx, cve_id, guidance=None, strategy=None):
    """Change the shared detection record of one CVE (App Admin only: the record is the same for every organization). Give ``guidance``
    (plain text with new facts: the AI reviewer container revises the record with it, validated like any model answer, and the record changes
    when that answer lands) or ``strategy`` (a whole record written by a person, validated, never overwritten by the model afterwards).
    Returns the stored record, and for guidance ``revision: {state: queued, job_id}``."""
    from cveFeed import detection, detection_author
    from cveFeed.models import CVEDetection, CVEEntry
    if not ctx.user.is_superuser:
        raise ApiError(403, 'only an App Admin can change the shared CVE detection records')
    if (guidance is None) == (strategy is None):
        raise ApiError(400, 'give either guidance (text) or strategy (an object)')
    cve = CVEEntry.objects.filter(cve_id=str(cve_id).upper()).first()
    if not cve:
        raise ApiError(404, 'CVE not found')
    row = CVEDetection.objects.filter(cve_entry=cve).select_related('cve_entry').first() or CVEDetection(cve_entry=cve)
    problems = []
    if strategy is not None:
        clean, problems = detection.validate_strategy(strategy)
        if clean is None:
            raise ApiError(400, 'the strategy is not usable: ' + '; '.join(problems[:5]))
        from cveFeed import locality
        final = detection.finalize(clean, cve.cvss_vector)
        CVEDetection.objects.update_or_create(cve_entry=cve, defaults={
            'strategy': final, 'source': 'manual', 'schema_version': detection.SCHEMA_VERSION, 'ai_problems': problems[:10]})
        locality.apply_scope(cve, final.get('scope', ''))
    else:
        if not isinstance(guidance, str) or not 10 <= len(guidance.strip()) <= 3000:
            raise ApiError(400, 'guidance must be text of 10 to 3000 characters')
        from cveFeed import ai_jobs
        if not ai_jobs.ai_on():
            raise ApiError(409, 'no AI provider is configured: add one in Settings > AI model, or send a strategy yourself')
        if row.pk is None:
            row.strategy, row.source, row.rules_at = detection.finalize(detection.rules_strategy(cve), cve.cvss_vector) or {}, 'rules', timezone.now()
            row.save()
        if row.source == 'manual':
            raise ApiError(409, 'a person wrote this record: send a strategy to change it')
        # the AI reviewer container revises it (cveFeed.ai_jobs): the record changes when its answer lands and passes validation
        queued = detection_author.revise_with_guidance(row, guidance.strip())
    from cveFeed.admin_api import audit
    audit(ctx.user, 'cve.detection.update', cve.cve_id, None, cve=cve.cve_id, via='strategy' if strategy is not None else 'guidance')
    cve.refresh_from_db()
    out = _detection(CVEEntry.objects.select_related('detection').get(pk=cve.pk))
    out['problems'] = problems[:10]
    if guidance is not None:
        out['revision'] = {'state': 'queued', 'job_id': queued.pk,
                           'note': 'the AI reviewer container revises the record with this guidance; read it again in a minute'}
    return out


def _match(m):
    from cveFeed.distro import label_for
    from cveFeed.threat import heat_reason, match_heat, validation_heat
    sub = m.subdomain
    cve = _cve(m.cve_entry, brief=True)
    cve['feed_tier'] = cve['tier']
    cve['tier'] = match_heat(m)  # rated as it applies to this host (the heat policy: a KEV match is fire only when its version is proven)
    cve['validation_tier'] = validation_heat(m)  # the heat once proven: what orders validation
    cve['heat_capped'] = cve['tier'] != cve['validation_tier']
    return {'id': m.id, 'cve': cve, 'host': sub.name if sub else None, 'version_only': match_policy.is_version_only(m),
            'version_proven': match_policy.version_proven(m), 'heat_reason': heat_reason(m, cve['tier']),
            'heat_override': _heat_override(_triage_of(m)),
            'product': m.matched_product, 'version': m.matched_version, 'in_affected_range': m.version_in_range,
            'confidence': m.confidence, 'source': m.source, 'host_reported': m.source == 'host',
            'ai_verdict': m.ai_verdict, 'ai_reason': m.ai_reason,
            'assessment_status': ('closed_not_applicable' if m.ai_verdict == 'not_affected' and
                                  (m.ai_reason or '').startswith('Closed automatically:')
                                  else 'candidate'),
            'distro_status': m.distro_status, 'distro_fixed_version': m.distro_fixed_version,
            'distro_label': label_for(m.distro_status, m.distro_fixed_version),
            'evidence': m.evidence or {}, 'template_result': m.template_result, 'template_id': m.template_id,
            'template_tested': _iso(m.template_tested_at),
            'remediation_status': m.remediation_status, 'remediation_note': m.remediation_note,
            'remediation_updated': _iso(m.remediation_updated_at),
            'status_changed_at': _iso(m.remediation_updated_at), 'status_changed_by': _user_brief(m.remediation_by),
            'assignee': _user_brief(m.assignee), 'comment_count': _comment_count(m, 'match'), 'agent_task': _agent_task_of(m),
            **_closure_fields('match', m),
            'first_seen': _iso(_seen(m, 'first_seen', m.created_at)), 'last_seen': _iso(_seen(m, 'last_seen', m.updated_at)),
            'triage': _triage_brief(_triage_of(m)),
            'retest': _retest_of(m)}


def _agent_task_of(m):
    """The agent work waiting on or doing this match, as the list query annotated it (see _agent_task_annotations), else None."""
    status = getattr(m, 'agent_task_status', None)
    return {'kind': m.agent_task_kind, 'status': status, 'agent': m.agent_task_agent} if status else None


def _agent_task_annotations():
    """Per match, the newest unfinished agent task: its status, kind and the agent holding it (None while it is queued), in one subquery each
    so a page of matches costs no query per row."""
    from django.db.models import OuterRef, Subquery

    from agentapi.models import ACTIVE_TASK_STATUSES, AgentTask
    active = AgentTask.objects.filter(match=OuterRef('pk'), status__in=ACTIVE_TASK_STATUSES).order_by('-id')
    return {'agent_task_status': Subquery(active.values('status')[:1]), 'agent_task_kind': Subquery(active.values('kind')[:1]),
            'agent_task_agent': Subquery(active.values('agent__name')[:1])}


def _matches_qs(project):
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    qs = _scoped(CVEMatch.objects.all(), project, 'subdomain__target_domain__project').filter(latest_scan_q('subdomain__')) \
        .select_related('cve_entry', 'subdomain', 'triage__verdict', 'triage__heat_override_by', 'remediation_by', 'assignee') \
        .annotate(comment_count=_comment_count_annotation('match'), **_agent_task_annotations()).order_by('-confidence', '-id')
    # the host's target joined in either case: a list row reads its project (``_finding_row``) and must not ask for it row by row
    return qs.select_related('subdomain__target_domain__project') if _is_all(project) else qs.select_related('subdomain__target_domain')


def list_matches(ctx, slug, params):
    project, _ = get_project(ctx, slug)
    qs = _matches_qs(project)
    if params.get('status') == 'closed':  # any closing status: fixed, accepted_risk or false_positive
        from cveFeed.counts import CLOSED
        qs = qs.filter(remediation_status__in=CLOSED)
    elif params.get('status') in RETEST_FACETS:  # verified_fixed, unverified_fixed, reopened: the same retest states the Findings list filters on
        from cveFeed import counts as counts_lib
        qs = qs.filter(counts_lib.retest_q(params['status'], 'triage__'))
    elif params.get('status'):
        qs = qs.filter(remediation_status=params['status'])
    if params.get('verdict') == 'active':  # not ruled out by the AI: the dashboard's CVE matches count
        from cveFeed.counts import RULED_OUT
        qs = qs.exclude(ai_verdict=RULED_OUT)
    elif params.get('verdict'):
        qs = qs.filter(ai_verdict=params['verdict'])
    if params.get('classification'):
        qs = qs.filter(triage__classification=params['classification'])
    if params.get('host'):
        qs = qs.filter(subdomain__name__icontains=params['host'])
    if params.get('cve'):  # one CVE id: where a CVE named in free text (an activity line) links to
        qs = qs.filter(cve_entry__cve_id__iexact=params['cve'].strip()[:40])
    if _kev_only(params):
        qs = qs.filter(cve_entry__kev=True)
    return paginate(qs, params, _tagged(_match, lambda m: m.subdomain.target_domain.project) if _is_all(project) else _match)


# --- the unified Findings list: CVE matches, scanner findings and hygiene findings as one population ------------------

FINDING_TYPES = {'cve': 'match', 'scanner': 'vulnerability', 'hygiene': 'hygiene'}  # facet -> the finding-detail kind
# the Findings list's status facet: actionable (the default), closed (any closing status), one closing status on its own, or all
# verified_fixed, unverified_fixed (fixed and not verified by a retest) and reopened (a retest found it still reproduces) read the retest state
# (cveFeed.counts.retest_q)
FINDING_STATUS_FACETS = ('actionable', 'closed', 'fixed', 'accepted_risk', 'false_positive', 'verified_fixed', 'unverified_fixed', 'reopened', 'all')
RETEST_FACETS = ('verified_fixed', 'unverified_fixed', 'reopened')
HEAT_FACETS = {'fire': 3, 'smoke': 2, 'ice': 1}
MAX_FINDINGS = 2000  # rows the merged list can page through; the counts stay exact beyond it
# the Findings list's AI facet: what the AI reviewer's newest verdict on a finding says. disputed: it called the finding a false positive and
# the server did not close it (a person should look); real: it called the finding real (any true_* verdict)
AI_FACETS = ('disputed', 'real', 'all')


def _ai_facet(qs, facet):
    """``qs`` (findings with a ``triage`` row) narrowed to the ones whose newest AI review says ``facet`` (``reviewer.review_summary``)."""
    from django.db.models import Q

    from cveFeed import reviewer
    qs = qs.annotate(**reviewer.newest_review_q('triage__'))
    if facet == 'disputed':
        return qs.filter(review_verdict='false_positive').exclude(review_outcome='closed')
    return qs.filter(Q(review_verdict__in=reviewer.REAL_VERDICTS))


def _kev_only(params):
    """``kev=1`` (or true, yes): only CVE matches of a CVE listed as exploited. Heat alone does not say KEV (a KEV match whose version is not
    proven is smoke, ``threat.match_heat``), so this is how a person or an agent finds them all. Any other value is ignored."""
    return str(params.get('kev') or '').strip().lower() in ('1', 'true', 'yes', 'on')


def _finding_sources(project, params):
    """The querysets the facets allow, keyed by type, each annotated with ``heat_rank`` (3 fire, 2 smoke, 1 ice, 0 none: the
    host card's rules, threat.match_temperature and SEVERITY_HEAT) and ``sev`` (0 info .. 4 critical; a CVE by its CVSS band,
    an unscored one as low), and filtered by heat, severity, status and host.

    "Actionable" (the default) is what heats a host on its card: a CVE match the AI did not rule out, an open scanner finding
    above info, an open hygiene finding above info. ``status=all`` adds the rest (informational, closed, ruled out). ``status=closed``
    is the findings a person closed (fixed, accepted_risk or false_positive), and one of those three exactly that one, whatever the scan
    or the AI says about them."""
    from django.db.models import Case, F, IntegerField, Q, Value, When

    from cveFeed.models import HygieneFinding
    from cveFeed.threat import CRITICAL_CVSS, HIGH_CVSS, finding_heat_rank_expr, match_heat_rank_expr, severity_heat_rank_expr
    from startScan.models import Vulnerability
    wanted = params.get('type') or 'all'
    if wanted != 'all' and wanted not in FINDING_TYPES:
        raise ApiError(400, f'type must be all or one of {", ".join(FINDING_TYPES)}')
    ai = str(params.get('ai') or 'all')
    if ai not in AI_FACETS:
        raise ApiError(400, f'ai must be {", ".join(AI_FACETS[:-1])} or {AI_FACETS[-1]}')
    kev = _kev_only(params)
    if kev:
        wanted = 'cve' if wanted in ('all', 'cve') else None  # a scanner or hygiene finding has no KEV listing: none of them is KEV
    from cveFeed import counts as counts_lib
    from cveFeed.closure import CLOSED
    status = params.get('status') or 'actionable'
    if status not in FINDING_STATUS_FACETS:
        raise ApiError(400, f'status must be {", ".join(FINDING_STATUS_FACETS[:-1])} or {FINDING_STATUS_FACETS[-1]}')
    # closed: any closing remediation status; fixed, accepted_risk or false_positive: exactly that one
    by_status = Q(remediation_status__in=CLOSED) if status == 'closed' else Q(remediation_status=status) if status in CLOSED else None
    heat, severity = params.get('heat') or 'all', params.get('severity') or 'all'
    inverse = {v: k for k, v in SEVERITY_NAMES.items() if k >= 0}
    if heat != 'all' and heat not in HEAT_FACETS:
        raise ApiError(400, 'heat must be all, fire, smoke or ice')
    if severity != 'all' and severity not in inverse:
        raise ApiError(400, 'severity must be all, critical, high, medium, low or info')
    everywhere = _is_all(project)
    cve_band = Case(When(cve_entry__cvss__gte=CRITICAL_CVSS, then=Value(4)), When(cve_entry__cvss__gte=HIGH_CVSS, then=Value(3)),
                    When(cve_entry__cvss__gte=4.0, then=Value(2)), default=Value(1), output_field=IntegerField())
    sources = {}
    if wanted in ('all', 'cve'):
        qs = _matches_qs(project).annotate(heat_rank=match_heat_rank_expr(), sev=cve_band, when=F('created_at'))
        if kev:
            qs = qs.filter(cve_entry__kev=True)
        if status == 'actionable':
            qs = qs.exclude(ai_verdict='not_affected').exclude(remediation_status__in=CLOSED)
        elif by_status is not None:
            qs = qs.filter(by_status)
        elif status in RETEST_FACETS:
            qs = qs.filter(counts_lib.retest_q(status, 'triage__'))
        if params.get('host'):
            qs = qs.filter(subdomain__name__icontains=params['host'])
        sources['cve'] = qs
    if wanted in ('all', 'scanner'):
        qs = _scoped(Vulnerability.objects.all(), project, 'target_domain__project') \
            .select_related('subdomain', 'triage__verdict', 'triage__heat_override_by', 'remediation_by', 'assignee',
                            'target_domain__project' if everywhere else 'target_domain') \
            .annotate(heat_rank=finding_heat_rank_expr(), sev=F('severity'), when=F('discovered_date'),
                      comment_count=_comment_count_annotation('vulnerability'))
        if status == 'actionable':
            qs = qs.filter(open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED)
        elif by_status is not None:
            qs = qs.filter(by_status)
        elif status in RETEST_FACETS:
            qs = qs.filter(counts_lib.retest_q(status, 'triage__'))
        if params.get('host'):
            qs = qs.filter(subdomain__name__icontains=params['host'])
        sources['scanner'] = qs
    if wanted in ('all', 'hygiene'):
        qs = _scoped(HygieneFinding.objects.all(), project, 'domain__project') \
            .select_related('domain__project' if everywhere else 'domain', 'triage__verdict', 'remediation_by', 'assignee') \
            .annotate(heat_rank=severity_heat_rank_expr(), sev=F('severity'), when=F('first_seen'),
                      comment_count=_comment_count_annotation('hygiene'))
        if status == 'actionable':
            qs = qs.filter(status='open', severity__gte=1).exclude(remediation_status__in=CLOSED)
        elif by_status is not None:
            qs = qs.filter(by_status)
        elif status in RETEST_FACETS:
            qs = qs.filter(counts_lib.retest_q(status, 'triage__'))
        if params.get('host'):
            qs = qs.filter(host__icontains=params['host'])
        sources['hygiene'] = qs
    internal = str(params.get('internal', '')).strip().lower()
    if internal in ('1', 'true', 'yes', 'only', '0', 'false', 'no', 'external'):
        from cveFeed import internal_view
        only = internal in ('1', 'true', 'yes', 'only')
        for key, qs in list(sources.items()):
            q = (internal_view.internal_q('subdomain__') if key in ('cve', 'scanner')
                 else internal_view.internal_q('', 'host', 'domain__project_id'))
            sources[key] = qs.filter(q) if only else qs.exclude(q)
    for key, qs in sources.items():
        if ai != 'all':
            qs = _ai_facet(qs, ai)
        if heat != 'all':
            qs = qs.filter(heat_rank=HEAT_FACETS[heat])
        if severity != 'all':
            qs = qs.filter(sev=inverse[severity])
        from cveFeed import reviewer
        sources[key] = qs.annotate(**reviewer.newest_review_row_q('triage__')).order_by('-heat_rank', '-sev', F('when').desc(nulls_last=True), '-id')
    return sources


def _finding_row(kind, obj):
    """One row of the unified list: enough for the list card and the badges; the detail comes from finding_detail."""
    from cveFeed.threat import HEAT_RANK
    heat = {rank: name for name, rank in HEAT_RANK.items()}.get(obj.heat_rank, '')
    if kind == 'cve':
        cve, sub = obj.cve_entry, obj.subdomain
        title, host = cve.cve_id, sub.name if sub else None
        note = ' '.join(filter(None, [obj.matched_product, obj.matched_version])) or ''
        if obj.source == 'host':
            note += ' (reported by the host)'
        status = 'ruled out' if obj.ai_verdict == 'not_affected' else obj.remediation_status
        # KEV is shown on the row whatever the heat: a known-exploited match whose version is not proven shows smoke, not fire
        from cveFeed.threat import heat_reason, validation_heat
        extra = {'cvss': cve.cvss, 'description': _cve_description(cve, 160), 'kev': bool(cve.kev), 'exploit': bool(cve.exploit_db),
                 'version_only': match_policy.is_version_only(obj), 'version_proven': match_policy.version_proven(obj),
                 'heat_capped': heat != validation_heat(obj),  # held below the heat it would have once proven
                 'heat_reason': heat_reason(obj, heat)}
    elif kind == 'scanner':
        title, host, note = obj.name, obj.subdomain.name if obj.subdomain else None, obj.source or ''
        status, extra = ('closed' if not obj.open_status else obj.remediation_status), {}
        from cveFeed.threat import manual_heat_reason
        manual = manual_heat_reason(obj)  # a heat set by hand says who and why (no extra query: the list joins the row and the user)
        if manual:
            extra['heat_reason'] = manual
    else:
        title, host, note = obj.title, obj.host, obj.check_name
        status, extra = ('resolved' if obj.status == 'resolved' else obj.remediation_status), {}
    project_id = {'cve': lambda o: o.subdomain.target_domain.project_id if o.subdomain else None, 'scanner': lambda o: o.target_domain.project_id,
                  'hygiene': lambda o: o.domain.project_id}[kind](obj)
    return {'type': kind, 'kind': FINDING_TYPES[kind], 'id': obj.id, 'title': title, 'host': host, 'note': note,
            'internal': _internal_row(project_id, host or ''),
            'heat': heat, 'severity': SEVERITY_NAMES.get(obj.sev, str(obj.sev)), 'status': status,
            'remediation_note': getattr(obj, 'remediation_note', ''),
            'status_changed_at': _iso(getattr(obj, 'remediation_updated_at', None)),
            'status_changed_by': _user_brief(getattr(obj, 'remediation_by', None)), **_closure_fields(FINDING_TYPES[kind], obj),
            'assignee': _user_brief(getattr(obj, 'assignee', None)), 'comment_count': getattr(obj, 'comment_count', 0),
            'agent_task': _agent_task_of(obj) if kind == 'cve' else None, 'detected': _iso(obj.when), 'first_seen': _iso(obj.when),
            'heat_override': _heat_override(_triage_of(obj)) if kind != 'hygiene' else None, 'triage': _triage_brief(_triage_of(obj)),
            'retest': _retest_of(obj),
            'ai_review': None, '_triage_id': getattr(_triage_of(obj), 'pk', None), '_review_read': hasattr(obj, 'review_row'),
            '_review': _review_from_row(obj), **extra}


def _review_from_row(obj):
    from cveFeed import reviewer
    return reviewer.summary_from_row(obj)


def _attach_reviews(rows):
    """Fill ``ai_review`` (the newest AI review of the finding: verdict, confidence, reason, note, model, outcome in plain words) of every
    row of a list page. A grouped row (``group``) stands for several hosts: it shows the newest review across its members and says so
    (``scope_text``: how many of its hosts the reviewer has looked at). A row read by the list queries already carries its own review (one
    subquery in the row's own query, ``reviewer.newest_review_row_q``); a query for reviews runs only for a group row's members (two) or a
    row read some other way. Never a query per row."""
    from cveFeed import reviewer
    from cveFeed.models import Triage
    groups = {r['id']: r['group']['member_ids'] for r in rows if r.get('group') and r.get('kind') == 'match'}
    by_match = {}
    if groups:
        wanted = {i for ids in groups.values() for i in ids}
        by_match = dict(Triage.objects.filter(match_id__in=wanted).values_list('match_id', 'pk'))
    ids = [r.get('_triage_id') for r in rows if not r.get('_review_read')] + list(by_match.values())
    found = reviewer.review_summaries(ids)
    for row in rows:
        own = row.pop('_review') if row.pop('_review_read') else found.get(row['_triage_id'])
        row.pop('_triage_id', None)
        members = groups.get(row['id']) if row.get('group') and row.get('kind') == 'match' else None
        if members:
            seen = [found[by_match[m]] for m in members if by_match.get(m) in found]
            own = max(seen, key=lambda r: r['at']) if seen else None
            if own:
                own = {**own, 'scope_text': f"This is the newest AI review of the {len(members)} hosts in this group; it has looked at {len(seen)} of them."}
        row['ai_review'] = own
    return rows


def _finding_project(kind, obj):
    return {'cve': lambda o: o.subdomain.target_domain.project, 'scanner': lambda o: o.target_domain.project,
            'hygiene': lambda o: o.domain.project}[kind](obj)


GROUP_MODES = ('none', 'cve')  # group=cve: the same script on sibling hosts is one row (cveFeed.finding_groups)


def list_findings(ctx, slug, params):
    """Every finding of the project in one list, hottest first: CVE matches, scanner findings and hygiene findings. Facets:
    type (all|cve|scanner|hygiene), heat (all|fire|smoke|ice), severity (all|critical|high|medium|low|info), status
    (actionable, the default, or all), host, and kev=1 (CVE matches of a CVE listed as exploited only, whatever their heat). ``counts`` holds the total of each type under the same facets; the list itself
    pages through at most MAX_FINDINGS rows (``truncated`` says when there are more).

    ``group=cve`` folds the CVE matches of one script on sibling hosts into one row (``_grouped_findings``); the default
    (``group=none``) is one row per host, as it always was."""
    project, _ = get_project(ctx, slug)
    page, size = page_args(params, zero_ok=True)  # page_size=0: the counts alone
    group = str(params.get('group') or 'none').strip().lower()
    if group not in GROUP_MODES:
        raise ApiError(400, 'group must be none or cve')
    sources = _finding_sources(project, params)
    counts = {key: qs.count() for key, qs in sources.items()}
    if group == 'cve':
        return _grouped_findings(project, sources, counts, page, size)
    total = sum(counts.values())
    start, stop = (page - 1) * size, min(page * size, MAX_FINDINGS)
    merged = []
    for key, qs in sources.items():  # the top ``stop`` of each source holds the top ``stop`` of the merged order
        merged += [(key, obj) for obj in (qs[:stop] if stop > start else [])]
    epoch = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)  # not now().replace(year=1970): that raises on 29 February
    merged.sort(key=lambda pair: (pair[1].heat_rank, pair[1].sev, pair[1].when or epoch, pair[1].id), reverse=True)
    everywhere = _is_all(project)
    results = []
    for key, obj in merged[start:stop]:
        row = _finding_row(key, obj)
        if everywhere:
            owner = _finding_project(key, obj)
            row['project'], row['project_name'] = (owner.slug, owner.name) if owner else (None, None)
        results.append(row)
    _attach_reviews(results)
    return {'count': min(total, MAX_FINDINGS), 'total': total, 'truncated': total > MAX_FINDINGS, 'page': page,
            'page_size': size, 'counts': {key: counts.get(key, 0) for key in FINDING_TYPES}, 'retest': _retest_counts(project), 'results': results}


RETEST_COUNTS_SECONDS = 30  # how long one scope's retest counts are shared; a finding marked fixed or reopened drops them at once (the revision bump)


def _retest_counts(project):
    """The retest states of the project's findings, from ``cveFeed.counts.retest_counts``: {verified_fixed, unverified_fixed, reopened}. Three whole-project
    aggregates, so they are a shared snapshot (``cveFeed.snapshot_cache``, keyed by the project ids and the caller's allowed projects) and not part of every
    Findings request: the count-only polls and the page loads read the same copy, and a finding marked fixed or reopened (``bump_stats_revision``) drops it."""
    from cveFeed import counts as counts_lib
    from cveFeed import snapshot_cache
    ids = sorted(project.ids) if _is_all(project) else [project.pk]
    scope = snapshot_cache.scope_hash('retest-counts', ids)
    return snapshot_cache.snapshot('retest-counts', scope, lambda: counts_lib.retest_counts(ids), RETEST_COUNTS_SECONDS)['payload']


def _grouped_findings(project, sources, counts, page, size):
    """``list_findings`` with ``group=cve``: the same facets and order, but the CVE matches of one script on sibling hosts are one row
    (the rule is in ``cveFeed.finding_groups``). A group row is its hottest member's ordinary row (its id and kind open that member)
    plus ``group``: every member's id, host and own status, and the split of heat, status, classification and validation.

    ``counts`` stays per host finding, as without grouping; ``row_counts`` is the rows of each type the grouped list has, ``total`` and
    ``count`` count rows (they page the list), ``findings_total`` is the host findings behind them, ``groups`` the rows that stand for
    more than one host and ``grouped_findings`` the host findings inside those. Queries: the counts, one values() pass over the
    filtered CVE matches (at most GROUP_SCAN_MAX, ``group_scan_truncated`` past that: the rest stay one row each), the top of the
    scanner and hygiene lists, and one query for the representatives on the page."""
    from cveFeed import finding_groups
    cve_qs = sources.get('cve')
    built, scanned = finding_groups.read(cve_qs) if cve_qs is not None else ([], 0)
    overflow = max(0, counts.get('cve', 0) - scanned)
    row_counts = {key: counts.get(key, 0) for key in FINDING_TYPES}
    if cve_qs is not None:
        row_counts['cve'] = len(built) + overflow
    multi = [g for g in built if len(g['members']) > 1]
    total = sum(row_counts.values())
    start, stop = (page - 1) * size, min(page * size, MAX_FINDINGS)
    epoch = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
    merged = []
    if stop > start:
        merged += [('cve', g) for g in built[:stop]]
        if overflow and len(built) < stop:  # past the pass's cap: the remaining matches, one row each, in the list's order
            merged += [('cve-obj', obj) for obj in cve_qs[scanned:scanned + stop - len(built)]]
        for key in ('scanner', 'hygiene'):
            if key in sources:
                merged += [(key, obj) for obj in sources[key][:stop]]

    def order(pair):
        key, item = pair
        if key == 'cve':
            return finding_groups.sort_key(item['rep'])
        return (item.heat_rank, item.sev, item.when or epoch, item.id)
    merged.sort(key=order, reverse=True)
    page_items = merged[start:stop]
    rep_ids = [item['rep']['id'] for key, item in page_items if key == 'cve']
    reps = {obj.id: obj for obj in cve_qs.filter(id__in=rep_ids).select_related('subdomain__target_domain')} if rep_ids else {}
    everywhere = _is_all(project)
    results = []
    for key, item in page_items:
        if key == 'cve':
            obj = reps.get(item['rep']['id'])
            if obj is None:  # gone between the two reads (a rescan retired it): the next page load settles it
                continue
            row = _finding_row('cve', obj)
            if len(item['members']) > 1:
                row['group'] = finding_groups.summary(item, _iso)
        else:
            key, obj = ('cve' if key == 'cve-obj' else key), item
            row = _finding_row(key, obj)
        if everywhere:
            owner = _finding_project(key, obj)
            row['project'], row['project_name'] = (owner.slug, owner.name) if owner else (None, None)
        results.append(row)
    _attach_reviews(results)
    return {'count': min(total, MAX_FINDINGS), 'total': total, 'truncated': total > MAX_FINDINGS, 'page': page, 'page_size': size,
            'counts': {key: counts.get(key, 0) for key in FINDING_TYPES}, 'group': 'cve', 'row_counts': row_counts,
            'findings_total': sum(counts.values()), 'groups': len(multi), 'grouped_findings': sum(len(g['members']) for g in multi),
            'group_scan_truncated': overflow > 0, 'results': results}


def _host_of(obj):
    """``(project id, host name)`` of a finding that belongs to a host, else None. A hygiene finding names its host (the apex
    domain for the email checks) and the target it was checked under."""
    if hasattr(obj, 'check_name'):
        domain = getattr(obj, 'domain', None)
        return (domain.project_id, obj.host) if domain and domain.project_id and obj.host else None
    sub = getattr(obj, 'subdomain', None)
    domain = getattr(sub, 'target_domain', None) if sub else None
    return (domain.project_id, sub.name) if sub and domain and domain.project_id else None


def _rescore_hosts(hosts):
    """Rescore these ``(project id, host name)`` pairs: a finding fixed or reopened changes the host's score and colour at once, not at
    the next daily pass."""
    from cveFeed import scoring
    by_project = {}
    for project_id, name in hosts:
        by_project.setdefault(project_id, set()).add(name)
    for project_id, names in by_project.items():
        scoring.rescore_quietly(project_id, sorted(names)[:scoring.CHUNK])


def _check_status(status):
    from cveFeed.closure import STATUSES
    if status not in STATUSES:
        raise ApiError(400, f'status must be one of {", ".join(STATUSES)}')


def _clean_note(note):
    """The note of a status change as stored (cveFeed.closure.clean_note: stripped, control characters removed, at most 2000 characters),
    ``None`` when the caller left it out. A 400 for one that is not text or too long, raised before anything is written."""
    from cveFeed import closure
    try:
        return closure.clean_note(note)
    except closure.NoteError as exc:
        raise ApiError(400, str(exc))


def _apply_remediation(obj, status, note, user, rescore=True):
    """Set and save the remediation fields shared by CVEMatch, Vulnerability and HygieneFinding (the same tuple of
    statuses, cveFeed.closure.STATUSES, enforced here once). ``note`` is a true PATCH field: ``None`` (the default, meaning the caller's
    body left it out) leaves whatever note is already stored; an explicit value, including '', replaces it. Closing with fixed,
    accepted_risk or false_positive makes it the closure note, with who (remediation_by) and when (remediation_updated_at). The note is
    cleaned and cut to 2000 characters here (the request paths refuse a longer one with a 400 first, via _clean_note; an agent's own
    report is cut, as before). Raises on an unrecognized status; never touches whatever auto-managed liveness field (open_status,
    HygieneFinding.status, ai_verdict) the model also carries, which stays under the scan/check pipeline."""
    from cveFeed import closure
    _check_status(status)
    note = closure.clip_note(note)
    fields = ['remediation_status', 'remediation_updated_at', 'remediation_by']
    before = obj.remediation_status
    obj.remediation_status, obj.remediation_updated_at, obj.remediation_by = status, timezone.now(), user
    if note is not None:
        obj.remediation_note = note
        fields.append('remediation_note')
    obj.save(update_fields=fields)
    from cveFeed import fix_retest
    fix_retest.status_changed(obj, before, status)  # marked fixed (by a person, the API or an agent): the check that proved it is run again on a Sentinel
    from django.db import transaction

    from cveFeed.views import bump_stats_revision
    transaction.on_commit(bump_stats_revision)  # the dashboards read a snapshot: whoever closed a finding sees the numbers move now (review 1 F11)
    host = _host_of(obj) if rescore else None
    if host:
        _rescore_hosts([host])


UNSET = object()  # a PATCH field the caller's body left out entirely, as opposed to an explicit null/empty value


def _record_status_change(project, kind, finding_id, before, after, actor, note=None):
    """The audit event of one status change: who, the status before and after, and the note sent with it (left out when none was)."""
    from cveFeed.models import FindingAuditEvent
    FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=finding_id, event='status',
                                      actor=actor, before={'status': before},
                                      after={'status': after, **({'note': note} if note is not None else {})})


def _log_status(project, message, before, status, note, **detail):
    """The activity feed's line for a status change, with the statuses before and after and the note (clipped) in its detail, so the feed
    and the audit trail agree."""
    from cveFeed import activity
    extra = {'note': note[:500]} if note else {}
    activity.log('remediation', message, project=project, before=before, after=status, **detail, **extra)


def _resolve_assignee(project, assignee):
    """The User a request names as assignee (a user id), or None for None/''/0 (unassign). The new assignee must be someone who can
    already see this project (the same check PATCH .../profile and everywhere else that names a user by id uses); an id naming nobody,
    or nobody with access, is a 400. Run before anything is written, so a bad assignee never leaves a half-applied update."""
    from django.contrib.auth.models import User
    if assignee in (None, '', 0, '0'):
        return None
    try:
        new_user = User.objects.get(pk=int(assignee))
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        raise ApiError(400, 'assignee must be the id of a user who can see this project, or null')
    if not roles.effective_role(new_user, project):
        raise ApiError(400, 'assignee must be the id of a user who can see this project, or null')
    return new_user


def _apply_assignee(project, kind, obj, new_user, actor):
    """Set or clear ``obj.assignee`` to ``new_user`` (from _resolve_assignee) and write the audit event."""
    from cveFeed.models import FindingAuditEvent
    before = _user_brief(obj.assignee)
    obj.assignee = new_user
    obj.save(update_fields=['assignee'])
    FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=obj.pk, event='assignee', actor=actor,
                                      before={'assignee': before}, after={'assignee': _user_brief(new_user)})


def update_match(ctx, slug, match_id, status=None, note=None, assignee=UNSET):
    """At least one of ``status``/``assignee`` is required; either can be sent alone, the same true-partial-update
    semantics ``note`` already has. A status change and an assignee change are logged as separate audit events even
    when sent in the same call, since they are independent facts a reader may want separately."""
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before body validation
    if status is None and assignee is UNSET:
        raise ApiError(400, 'missing field(s): status or assignee')
    if status is not None:
        _check_status(status)
    note = _clean_note(note)
    m = _matches_qs(project).filter(id=match_id).first()
    if not m:
        raise ApiError(404, 'match not found')
    new_user = _resolve_assignee(project, assignee) if assignee is not UNSET else None  # before the first write
    if status is not None:
        before = m.remediation_status
        _apply_remediation(m, status, note, ctx.user)
        _record_status_change(project, 'match', m.id, before, status, ctx.user, note)
        _log_status(project, f'{m.cve_entry.cve_id} on {m.subdomain.name if m.subdomain else "?"} marked {status}',
                    before, status, note, finding_kind='match', finding_id=m.id)
    if assignee is not UNSET:
        _apply_assignee(project, 'match', m, new_user, ctx.user)
    return _match(m)


STATUS_KINDS = ('match', 'vulnerability', 'hygiene')  # finding kinds with a remediation workflow; a web route has none
MAX_BULK_STATUS = 200


def update_finding_status(ctx, slug, kind, finding_id, status=None, note=None, assignee=UNSET):
    """Set the remediation status (open/in_progress/fixed/accepted_risk/false_positive), note and/or assignee of one finding: a CVE
    match, scanner finding or hygiene finding; at least one of status/assignee is required. Same permissions and
    project-scoped 404 as update_match, which this delegates to for kind='match' so the two routes agree exactly. A
    web route has no remediation workflow (its auth_state already says what it needs), so 'route' 400s here the same
    as any other unrecognized kind."""
    if kind == 'match':
        return update_match(ctx, slug, finding_id, status, note=note, assignee=assignee)
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before kind/status validation
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    if status is None and assignee is UNSET:
        raise ApiError(400, 'missing field(s): status or assignee')
    if status is not None:
        _check_status(status)
    note = _clean_note(note)
    obj = _finding_obj(project, kind, finding_id)
    new_user = _resolve_assignee(project, assignee) if assignee is not UNSET else None  # before the first write
    if status is not None:
        before = obj.remediation_status
        _apply_remediation(obj, status, note, ctx.user)
        _record_status_change(project, kind, finding_id, before, status, ctx.user, note)
        _log_status(project, f'{kind} finding #{finding_id} marked {status}', before, status, note,
                    finding_kind=kind, finding_id=finding_id)
    if assignee is not UNSET:
        _apply_assignee(project, kind, obj, new_user, ctx.user)
    return _vuln(obj) if kind == 'vulnerability' else _hygiene(obj)


def get_finding_retest(ctx, slug, kind, finding_id):
    """The retest state of one finding (a CVE match, scanner finding or hygiene finding): ``{kind, id, status, retest, history}`` where ``retest`` is
    {state, label, text, at, sentinel, reason, can_retest} (state is '' for a finding that was not marked fixed, else verifying, verified_fixed,
    still_reproduces, not_verified or no_check) and ``history`` the tries, newest first, with their Sentinel, time, reason and evidence."""
    project, _ = get_one_project(ctx, slug)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    obj = _finding_obj(project, kind, finding_id)
    return {'kind': kind, 'id': obj.pk, 'status': obj.remediation_status, 'retest': _retest_of(obj), 'history': _retest_history(_triage_of(obj))}


def start_finding_retest(ctx, slug, kind, finding_id):
    """Retest now: re-run on a Sentinel the check that proved a finding marked fixed. Same permissions as changing its status. Only a finding marked
    fixed can be retested (400 otherwise); one already being retested answers the same (no second one is queued); one with no check to repeat
    answers state ``no_check``. Answers what ``get_finding_retest`` does, with ``queued`` true when a retest was queued by this call."""
    from cveFeed import fix_retest
    project, _ = get_one_project(ctx, slug, write=True)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    obj = _finding_obj(project, kind, finding_id)
    if obj.remediation_status != 'fixed':
        raise ApiError(400, 'only a finding marked fixed can be retested')
    t = _triage_of(obj)
    if t is None:
        return {**get_finding_retest(ctx, slug, kind, finding_id), 'queued': False}
    from cveFeed.models import FixRetest
    already = FixRetest.objects.filter(triage=t, status__in=('queued', 'running')).exists()
    job, _state = fix_retest.request(t, ctx.user, 'manual')
    if job is not None and not already:
        from cveFeed import activity
        activity.log('remediation', f'{kind} finding #{finding_id}: retest requested', project=project, finding_kind=kind, finding_id=finding_id)
    t.refresh_from_db()
    return {**get_finding_retest(ctx, slug, kind, finding_id), 'queued': job is not None and not already}


MAX_FINDING_ID = 2 ** 31 - 1


def _bulk_status_each(ctx, project, items, status, note):
    """The bulk status change one finding at a time (``update_finding_status`` for each): the way back when the batched one could not be written."""
    updated, failed, hosts = 0, [], set()
    for item in items:
        kind = item.get('kind') if isinstance(item, dict) else None
        finding_id = item.get('id') if isinstance(item, dict) else None
        try:
            if not isinstance(item, dict) or kind is None or finding_id is None:
                raise ApiError(400, 'each item must be an object with kind and id')
            if kind not in STATUS_KINDS:
                raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
            obj = _finding_obj(project, kind, finding_id)
            before = obj.remediation_status
            _apply_remediation(obj, status, note, ctx.user, rescore=False)
            _record_status_change(project, kind, finding_id, before, status, ctx.user, note)
            host = _host_of(obj)
            if host:
                hosts.add(host)
            updated += 1
        except ApiError as e:
            failed.append({'kind': kind, 'id': finding_id, 'error': e.message})
        except Exception:  # noqa: BLE001 - one bad row must never fail the rest of the batch
            logger.warning('bulk remediation update failed for %s %s', kind, finding_id, exc_info=True)
            failed.append({'kind': kind, 'id': finding_id, 'error': 'could not be updated'})
    return updated, failed, hosts


def _bulk_status_batched(ctx, project, items, status, note):
    """``(updated, failed, hosts)`` of a bulk status change in a fixed number of queries (a query per kind to read the findings, one to write each kind, one for the
    audit events, a few for the retests) where ``_bulk_status_each`` runs about five per finding. Each finding gets what a single change gives it: the status, who and when,
    its audit event and the retest hook (``fix_retest.status_changed_many``); the statistics revision and the host rescoring happen once. ``None`` when the batch could not
    be written (nothing of it is kept): the caller then does it one finding at a time."""
    from django.db import transaction

    from cveFeed import closure, fix_retest
    from cveFeed.models import FindingAuditEvent
    from cveFeed.views import bump_stats_revision
    failed, wanted = {}, {}  # item position -> failure; (kind, id) -> the positions asking for it
    for position, item in enumerate(items):
        kind = item.get('kind') if isinstance(item, dict) else None
        finding_id = item.get('id') if isinstance(item, dict) else None
        if not isinstance(item, dict) or kind is None or finding_id is None:
            failed[position] = {'kind': kind, 'id': finding_id, 'error': 'each item must be an object with kind and id'}
        elif kind not in STATUS_KINDS:
            failed[position] = {'kind': kind, 'id': finding_id, 'error': f'kind must be one of {", ".join(STATUS_KINDS)}'}
        else:
            try:
                number = int(finding_id)
            except (TypeError, ValueError, OverflowError):
                failed[position] = {'kind': kind, 'id': finding_id, 'error': 'could not be updated'}
                continue
            if not 0 <= number <= MAX_FINDING_ID:
                failed[position] = {'kind': kind, 'id': finding_id, 'error': 'finding not found'}
                continue
            wanted.setdefault((kind, number), []).append(position)
    try:
        found = {}
        for kind in STATUS_KINDS:
            ids = [n for k, n in wanted if k == kind]
            if ids:
                found.update({(kind, o.pk): o for o in _finding_qs(project, kind).filter(pk__in=ids)})
        now = timezone.now()
        clipped = closure.clip_note(note)  # as ``_apply_remediation`` stores it
        changes, events, written = [], [], {}
        for (kind, number), positions in wanted.items():
            obj = found.get((kind, number))
            if obj is None:
                for position in positions:
                    failed[position] = {'kind': items[position]['kind'], 'id': items[position]['id'], 'error': 'finding not found'}
                continue
            for position in positions:  # a finding named twice is changed twice, as one at a time: the second time from what the first left
                before = obj.remediation_status
                obj.remediation_status, obj.remediation_updated_at, obj.remediation_by = status, now, ctx.user
                if note is not None:
                    obj.remediation_note = clipped
                changes.append((obj, before, position))
                written.setdefault(kind, {})[obj.pk] = obj
                events.append(FindingAuditEvent(project=project, finding_kind=kind, finding_id=obj.pk, event='status', actor=ctx.user, before={'status': before},
                                                after={'status': status, **({'note': note} if note is not None else {})}))
        fields = ['remediation_status', 'remediation_updated_at', 'remediation_by'] + (['remediation_note'] if note is not None else [])
        with transaction.atomic():
            for objs in written.values():
                type(next(iter(objs.values()))).objects.bulk_update(list(objs.values()), fields)
            FindingAuditEvent.objects.bulk_create(events)
    except Exception:  # noqa: BLE001 - whatever stopped the batch, the findings are then changed one at a time, each failing on its own
        logger.warning('bulk remediation update could not be written in one go', exc_info=True)
        return None
    fix_retest.status_changed_many([(o, before) for o, before, _ in changes], status, now)  # marked fixed: the check that proved it is run again on a Sentinel (never raises)
    transaction.on_commit(bump_stats_revision)  # the dashboards read a snapshot: whoever closed the findings sees the numbers move now (review 1 F11)
    hosts = {h for h in (_host_of(o) for o, _, _ in changes) if h}
    return len(changes), [failed[p] for p in sorted(failed)], hosts


def bulk_update_finding_status(ctx, slug, items, status, note=None):
    """Set the same remediation status and note on up to MAX_BULK_STATUS findings at once (closing them as fixed, accepted_risk or
    false_positive puts the one note on every one, each audited on its own). Each item is independent
    (one bad kind or id never blocks the rest, and a finding belonging to another project 404s exactly like a missing
    one); returns {updated, failed: [{kind, id, error}]} so the caller can report partial failures. A bad status or note fails the
    whole call before anything is written."""
    from cveFeed import activity
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before any body validation
    _check_status(status)
    note = _clean_note(note)
    if not isinstance(items, list) or not items:
        raise ApiError(400, 'items must be a non-empty list')
    if len(items) > MAX_BULK_STATUS:
        raise ApiError(400, f'at most {MAX_BULK_STATUS} items per call')
    done = _bulk_status_batched(ctx, project, items, status, note)
    updated, failed, hosts = done if done is not None else _bulk_status_each(ctx, project, items, status, note)
    _rescore_hosts(hosts)  # once per host, not once per finding
    # findings and the hosts they are on: a grouped row of the Findings list is sent as its members, so this counts hosts, not rows
    activity.log('remediation', f'bulk marked {updated} finding(s) on {len(hosts)} host(s) {status}', project=project, count=updated,
                 hosts=len(hosts), failed=len(failed), after=status, **({'note': note[:500]} if note else {}))
    return {'updated': updated, 'failed': failed}


# --- a heat set by hand ------------------------------------------------------------------------------------------------

HEAT_KINDS = ('match', 'vulnerability')  # finding kinds with a heat a person can set; a hygiene finding and a web route have none
HEAT_VALUES = ('fire', 'smoke', 'ice')
MAX_BULK_HEAT = 500
HEAT_REASON_MAX = 1000


def _shown_heat(kind, obj):
    """The heat a CVE match or a scanner finding shows on its host (``threat.match_heat``, ``threat.finding_heat``; a heat set by hand wins)."""
    from cveFeed.threat import finding_heat, match_heat
    return match_heat(obj) if kind == 'match' else finding_heat(obj)


def _shown_heat_reason(kind, obj, heat):
    from cveFeed.threat import finding_heat_reason, heat_reason
    return heat_reason(obj, heat) if kind == 'match' else finding_heat_reason(obj, heat)


def _check_heat_kind(kind):
    if kind not in HEAT_KINDS:
        raise ApiError(400, 'kind must be match or vulnerability: a hygiene finding or a web route has no heat to set')


def _clean_heat(heat, reason):
    """``(heat, reason)`` as stored: heat one of fire, smoke, ice, or '' (null or empty: go back to the heat cvENGINE derives); the reason
    cleaned like a closure note, at most HEAT_REASON_MAX characters, and required when setting a heat. A 400 before anything is written."""
    from cveFeed import closure
    if heat is None:
        heat = ''
    if not isinstance(heat, str) or heat.strip().lower() not in ('', *HEAT_VALUES):
        raise ApiError(400, 'heat must be fire, smoke or ice, or null to go back to the heat cvENGINE derives')
    heat = heat.strip().lower()
    try:
        reason = closure.clean_note(reason, limit=HEAT_REASON_MAX)
    except closure.NoteError as exc:
        raise ApiError(400, str(exc).replace('note', 'reason'))
    if heat and not reason:
        raise ApiError(400, 'reason is required: say why this finding is ' + heat)
    return heat, reason or ''


def _apply_heat(project, kind, obj, heat, reason, actor):
    """Set (``heat``) or clear (``''``) the heat of one finding the caller loaded through ``_finding_obj``, on its Triage row (made the way
    triage makes it, ``triage.track``, when the finding has none yet), and write the audit event (``heat``: the heat shown and the override
    before and after, who, and the reason). Returns ``(obj, heat shown before, heat shown after, changed)``; the same heat and reason again
    change nothing."""
    from cveFeed import triage as triage_lib
    from cveFeed.models import FindingAuditEvent, Triage
    row = _triage_of(obj)
    if row is None:
        if not triage_lib.track([obj]):
            raise ApiError(409, 'this finding has no owning project to rate it under')
        obj = _finding_obj(project, kind, obj.pk)  # again, with its new Triage row
        row = _triage_of(obj)
        if row is None:
            raise ApiError(409, 'this finding has no triage record to rate it on')
    before, old = _shown_heat(kind, obj), row.heat_override or ''
    if heat == old and (not heat or reason == row.heat_override_reason):
        return obj, before, before, False
    now = timezone.now()
    fields = {'heat_override': heat, 'heat_override_reason': reason if heat else '', 'heat_override_by': actor if heat else None,
              'heat_override_at': now if heat else None}
    Triage.objects.filter(pk=row.pk).update(**fields, updated_at=now)  # these four only: nothing triage or validation wrote is touched
    for name, value in fields.items():
        setattr(row, name, value)
    after = _shown_heat(kind, obj)
    FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=obj.pk, event='heat', actor=actor,
                                      before={'heat': before, 'override': old or None},
                                      after={'heat': after, 'override': heat or None, 'reason': reason})
    return obj, before, after, True


def _heat_followup(project, changes, heat, reason):
    """After heat changes (``[(kind, finding, before, after)]``): rescore their hosts once each, page the CVE matches that now show fire and
    did not before (``notify.fire_set_by_hand``: at most once per match, never a closed one; lowering never pages), make the dashboards
    re-read, and write one activity line."""
    from django.db import transaction

    from cveFeed import activity, notify
    from cveFeed.threat import FIRE
    if not changes:
        return
    hosts = {h for h in (_host_of(obj) for _kind, obj, _b, _a in changes) if h}
    _rescore_hosts(hosts)
    raised = [obj.pk for kind, obj, before, after in changes if kind == 'match' and after == FIRE and before != FIRE]
    if raised:
        transaction.on_commit(lambda: notify.fire_set_by_hand(raised))
    try:
        from cveFeed.views import bump_stats_revision
        bump_stats_revision()  # the dashboards' fire, smoke and ice counts are a snapshot
    except Exception:  # noqa: BLE001 - the change is stored; the snapshot follows at its next refresh
        logger.warning('could not refresh the dashboard snapshot after a heat change', exc_info=True)
    if len(changes) == 1:
        kind, obj, before, after = changes[0]
        what = (f'{obj.cve_entry.cve_id} on {obj.subdomain.name if obj.subdomain else "?"}' if kind == 'match'
                else f'{kind} finding #{obj.pk}')
        message = f'{what} set to {heat} by hand' if heat else f'{what}: heat set by hand cleared ({after} again)'
    else:
        message = (f'{len(changes)} finding(s) on {len(hosts)} host(s) set to {heat} by hand' if heat
                   else f'heat set by hand cleared on {len(changes)} finding(s) on {len(hosts)} host(s)')
    activity.log('remediation', message, project=project, count=len(changes), heat=heat or None, **({'reason': reason[:500]} if reason else {}))


def _heat_state(kind, obj, changed):
    """What a heat write answers: the finding, the heat it shows now and why, and the heat set by hand (null when cleared)."""
    heat = _shown_heat(kind, obj)
    return {'kind': kind, 'id': obj.pk, 'heat': heat, 'heat_reason': _shown_heat_reason(kind, obj, heat) if heat else '',
            'heat_override': _heat_override(_triage_of(obj)), 'changed': changed}


def set_finding_heat(ctx, slug, kind, finding_id, heat, reason=None):
    """Re-rate one finding by hand: set the heat a CVE match (``kind=match``) or a scanner finding (``kind=vulnerability``) shows to fire,
    smoke or ice, with a reason (required), or clear it (``heat`` null or '') so cvENGINE derives it again. The heat set wins everywhere a
    heat is read (``threat.manual_heat``): lists, counts, the heat facet, host heat and scores, reports, the graph, OpenVAS and validation
    order, alerts and the API. Same permissions and project-scoped 404 as ``update_finding_status`` (a read-only token or the audit role is a
    403, ``_all`` a 400). A hygiene finding or a web route has no heat (400). Audited on the finding (``event: heat``); a match raised to
    fire is paged once like any match that becomes fire."""
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before body validation
    _check_heat_kind(kind)
    heat, reason = _clean_heat(heat, reason)
    obj = _finding_obj(project, kind, finding_id)
    obj, before, after, changed = _apply_heat(project, kind, obj, heat, reason, ctx.user)
    if changed:
        _heat_followup(project, [(kind, obj, before, after)], heat, reason)
    return _heat_state(kind, obj, changed)


def bulk_set_finding_heat(ctx, slug, items, heat, reason=None):
    """``set_finding_heat`` for up to MAX_BULK_HEAT findings at once, with one heat and one reason: ``items`` is ``[{kind, id}, ...]``. Each
    item is independent (one bad kind or id never blocks the rest, and another project's finding 404s exactly like a missing one); each
    change is audited on its own finding; hosts are rescored once and the matches raised to fire are paged in one message. A bad heat or
    reason fails the whole call before anything is written. Returns ``{updated, unchanged, failed: [{kind, id, error}]}``."""
    project, _ = get_project(ctx, slug, write=True)
    heat, reason = _clean_heat(heat, reason)
    if not isinstance(items, list) or not items:
        raise ApiError(400, 'items must be a non-empty list')
    if len(items) > MAX_BULK_HEAT:
        raise ApiError(400, f'at most {MAX_BULK_HEAT} items per call')
    changes, unchanged, failed = [], 0, []
    for item in items:
        kind = item.get('kind') if isinstance(item, dict) else None
        finding_id = item.get('id') if isinstance(item, dict) else None
        try:
            if not isinstance(item, dict) or kind is None or finding_id is None:
                raise ApiError(400, 'each item must be an object with kind and id')
            _check_heat_kind(kind)
            try:
                finding_id = int(finding_id)
            except (TypeError, ValueError):
                raise ApiError(400, 'id must be a whole number')
            obj, before, after, changed = _apply_heat(project, kind, _finding_obj(project, kind, finding_id), heat, reason, ctx.user)
            if changed:
                changes.append((kind, obj, before, after))
            else:
                unchanged += 1
        except ApiError as e:
            failed.append({'kind': kind, 'id': finding_id, 'error': e.message})
        except Exception:  # noqa: BLE001 - one bad row must never fail the rest of the batch
            logger.warning('bulk heat change failed for %s %s', kind, finding_id, exc_info=True)
            failed.append({'kind': kind, 'id': finding_id, 'error': 'could not be updated'})
    _heat_followup(project, changes, heat, reason)
    return {'updated': len(changes), 'unchanged': unchanged, 'failed': failed}


MAX_ASSET_PATTERNS = 500


class AssetFilter:
    """Registered assets (names, parent domains, IPs, CIDRs) read once, so each host is a few set lookups and one containment test per
    network instead of re-parsing every pattern for every host (500 patterns over 2,000 matches took about 90 seconds)."""

    def __init__(self, patterns):
        self.names, self.networks = set(), []
        for pattern in patterns:
            p = pattern.strip().lower()
            if not p:
                continue
            self.names.add(p)
            try:
                self.networks.append(ipaddress.ip_network(p, strict=False))
            except ValueError:
                continue

    def __bool__(self):
        return bool(self.names)

    def matches(self, host_names, ips):
        """Whether a host (name and IPs) falls under any registered asset: name, parent domain, IP or CIDR."""
        for name in host_names:
            labels = name.split('.')
            if any('.'.join(labels[i:]) in self.names for i in range(len(labels))):
                return True
        if self.networks:
            for ip in ips:
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(address.version == net.version and address in net for net in self.networks):
                    return True
        return False


def asset_matches(host_names, ips, patterns):
    return AssetFilter(patterns).matches(host_names, ips)


def register_assets(ctx, assets):
    """An agent registers the hosts/IPs/CIDRs it is responsible for; /work then defaults to them."""
    if not ctx.token:
        raise ApiError(400, 'assets are registered on an API token; call this with a token')
    if not isinstance(assets, list) or not all(isinstance(a, str) for a in assets) or len(assets) > 500:
        raise ApiError(400, 'assets must be a list of up to 500 strings')
    ctx.token.assets = [a.strip() for a in assets if a.strip()]
    ctx.token.save(update_fields=['assets'])
    return {'assets': ctx.token.assets}


WORK_ITEMS_WINDOW = 2000  # the matches ``work_items`` reads, best ranked first (highest confidence)


def work_items(ctx, slug, params):
    """Remediation handoff: confirmed or pending CVE-on-host matches still to fix, narrowed to the
    agent's registered assets (or ?assets=a,b) and optionally to a tier (``fire``, ``smoke`` or ``ice``, filtered in the database). At most ``WORK_ITEMS_WINDOW``
    matches are read, best ranked first; ``truncated`` is true when there were more. It refers to that project-wide window, before the asset filter (which looks only
    at the window): with assets set it can be true when none of the window belongs to them."""
    from cveFeed.models import CVEMatch
    project, _ = get_one_project(ctx, slug)
    asked = [a.strip() for a in (params.get('assets') or '').split(',') if a.strip()]
    if len(asked) > MAX_ASSET_PATTERNS:
        raise ApiError(400, f'assets must list at most {MAX_ASSET_PATTERNS} hosts, IPs or CIDRs')
    patterns = asked or (ctx.token.assets if ctx.token else [])
    wanted = AssetFilter(patterns)
    placed = {}  # subdomain id -> whether it is one of the assets; a host with many matches is tested once
    # Closed asset correlations do not belong in remediation work. An unresolved candidate with a low-confidence
    # triage classification remains reviewable unless the caller requests ?include_fp=0.

    from cveFeed.counts import CLOSED
    qs = _matches_qs(project).exclude(ai_verdict='not_affected') \
        .exclude(version_in_range=False) \
        .exclude(remediation_status__in=CLOSED) \
        .prefetch_related('subdomain__ip_addresses')
    if params.get('include_fp') == '0':
        qs = qs.exclude(triage__classification__in=FALSE_POSITIVES)
    tier = params.get('tier')
    if tier:  # the tier is a filter of the query (the database form of the heat every list shows), not of the 2,000 rows that happened to rank first
        from cveFeed.threat import HEAT_RANK, match_heat_rank_expr
        qs = qs.annotate(_heat_rank=match_heat_rank_expr()).filter(_heat_rank=HEAT_RANK[tier]) if tier in HEAT_RANK else qs.none()
    rows = list(qs[:WORK_ITEMS_WINDOW + 1])
    truncated = len(rows) > WORK_ITEMS_WINDOW  # more matches than the window: the list below is the best-ranked part of them, and says so
    items = []
    for m in rows[:WORK_ITEMS_WINDOW]:
        sub = m.subdomain
        ips = [ip.address for ip in sub.ip_addresses.all()] if sub else []
        if wanted:
            key = sub.pk if sub else None
            if key not in placed:
                placed[key] = wanted.matches([sub.name.lower()] if sub else [], ips)
            if not placed[key]:
                continue
        item = _match(m)
        item['ips'] = ips
        item['host_score'] = sub.score if sub else 0
        item['fixed_in'] = _fixed_versions(m.cve_entry, m.matched_product)
        items.append(item)
    order = {'fire': 0, 'smoke': 1, 'ice': 2}
    items.sort(key=lambda i: (i['triage']['classification'] in FALSE_POSITIVES, order.get(i['cve']['tier'], 3), -(i['cve']['cvss'] or 0),
                              -i['host_score']))  # likely false positives last; the host score breaks ties
    matches = len(items)
    items = _one_item_per_upgrade(items)
    page, size = page_args(params)
    return {'count': len(items), 'matches': matches, 'truncated': truncated, 'registered_assets': patterns, 'page': page, 'page_size': size,
            'results': items[(page - 1) * size:page * size]}


def _upgrade_to(version, fixed):
    """The fixed version an upgrade from ``version`` needs: the lowest of ``fixed`` above it (one per release line), or the only one listed.
    '' when that cannot be told."""
    from cveFeed.finding_lifecycle import _version_key
    current = _version_key(version)
    above = sorted((key, f) for f in fixed for key in [_version_key(f)] if key is not None and current is not None and key > current)
    if above:
        return above[0][1]
    return fixed[0] if len(fixed) == 1 else ''


def _one_item_per_upgrade(items):
    """Remediation work, one item per upgrade: the CVE matches on one host that the same upgrade of the same component fixes
    (CVE-2020-11022 and CVE-2020-11023 on one jQuery 3.4.1, both fixed in 3.5.0) are one item, the hottest match standing for them with
    ``cves`` and ``match_ids`` naming them all and ``upgrade_to`` the version that fixes them. Each match keeps its own row, status and
    triage (update_remediation_status takes any of the ids). ``items`` arrive in the work list's order and keep it."""
    out, by_key = [], {}
    for item in items:
        fix = _upgrade_to(item.get('version') or '', item.get('fixed_in') or [])
        key = (item.get('host'), (item.get('product') or '').lower(), item.get('version') or '', fix) if fix and item.get('host') else None
        lead = by_key.get(key) if key else None
        if lead is not None:
            lead['cves'].append(item['cve']['cve_id'])
            lead['match_ids'].append(item['id'])
            continue
        item.update(cves=[item['cve']['cve_id']], match_ids=[item['id']], upgrade_to=fix)
        out.append(item)
        if key:
            by_key[key] = item
    return out


def _fixed_versions(cve, product):
    fixed = []
    for item in cve.affected or []:
        if product and product.lower() not in str(item.get('product', '')).lower():
            continue
        for rng in item.get('ranges', []) or []:
            if rng.get('fixed'):
                fixed.append(rng['fixed'])
    return sorted(set(fixed))


# --- AI triage, validation and the finding detail -------------------------------

FINDING_KINDS = ('match', 'vulnerability', 'route', 'hygiene')
HISTORY_KINDS = ('service_changed', 'port_opened', 'port_closed', 'tech_added', 'tech_removed', 'tech_version_changed', 'auth_changed',
                 'sensitive_found')
EXCERPT_CAP = 4096  # request / response excerpts, returned by the detail endpoint only, never in a list


def _triage_of(obj):
    """The Triage row of a finding, or None (a finding not triaged yet has none)."""
    from django.core.exceptions import ObjectDoesNotExist
    try:
        return obj.triage
    except ObjectDoesNotExist:
        return None


def triage_prefetch(path):
    """A prefetch of the Triage rows at ``path`` (``cve_matches__triage``, ``vulnerability_set__triage``) with the user who set a heat by
    hand joined in: the host cards' heat reasons name them (``threat.manual_heat_reason``) at no extra query."""
    from django.db.models import Prefetch

    from cveFeed.models import Triage
    return Prefetch(path, queryset=Triage.objects.select_related('heat_override_by'))


def _heat_override(t):
    """``{heat, reason, by, at}`` of a heat a person set on a finding (``Triage.heat_override``), or None while cvENGINE derives it."""
    if t is None or not t.heat_override:
        return None
    return {'heat': t.heat_override, 'reason': t.heat_override_reason, 'at': _iso(t.heat_override_at),
            'by': _user_brief(t.heat_override_by if t.heat_override_by_id else None)}


def _seen(obj, name, fallback):
    t = _triage_of(obj)
    return getattr(t, name, None) or fallback


def _classification_of(obj):
    t = _triage_of(obj)
    return t.classification if t else ''


def _library_read_step(steps):
    from cveFeed.validation import library_read_step
    return library_read_step(steps)


def _ai_connected():
    """Whether an AI provider that can make a request is set up: without one a finding is never triaged, so it is not waiting for it."""
    try:
        from cveFeed import ai_jobs
        return ai_jobs.ai_on()
    except Exception:  # noqa: BLE001 - an unreadable setting is "not connected", never a failed detail pane
        return False


def _review_of(t):
    """The AI reviewer's newest verdict on a finding (``cveFeed.reviewer.review_summary``: verdict, confidence, reason_code, note, model,
    outcome, held_reason, at, and verdict_text, outcome_text, disputed, says_real in plain words), or None while it has not reviewed it."""
    from cveFeed import reviewer
    return reviewer.review_summary(t.pk) if t is not None else None


def _retest_of(obj):
    """What the finding shows about its retest after it was marked fixed (``cveFeed.fix_retest.summary``): {state, label, text, at, sentinel, reason,
    can_retest}. Read from the Triage row every list already joins: no query of its own."""
    from cveFeed import fix_retest
    return fix_retest.summary(obj.remediation_status, _triage_of(obj))


def _retest_history(t, limit=10):
    """The tries of a finding's retest, newest first (one query, the detail pane and ``get_finding_retest`` only): when, which Sentinel, the outcome,
    why, and the evidence of the new exchange."""
    if t is None:
        return []
    from cveFeed.models import FixRetest
    return [{'id': r.pk, 'status': r.status, 'outcome': r.outcome, 'reason': r.reason, 'source': r.source, 'sentinel': r.sentinel,
             'checks': (r.check_run or {}).get('checks') or [], 'evidence': r.evidence or {}, 'attempt': r.attempts,
             'requested': _iso(r.created_at), 'finished': _iso(r.finished_at), 'next_attempt': _iso(r.next_attempt_at),
             'requested_by': _user_brief(r.requested_by)}
            for r in FixRetest.objects.filter(triage=t).select_related('requested_by').order_by('-id')[:limit]]


def _triage_brief(t):
    """What a list card needs to show the classification and validation badges without a second request."""
    from cveFeed import triage as triage_lib
    if t is None:
        return {'classification': '', 'status': 'untracked', 'validation_status': 'none', 'overridden': False, 'severity_adjust': 0,
                'first_seen': None, 'last_seen': None}
    v = t.verdict
    validation_status = ('observed' if t.validation_status == 'clean' and t.validation_steps and
                         all(step.get('result') in ('observed', 'reaffirmed') for step in t.validation_steps)
                         else t.validation_status)
    if validation_status in ('none', 'no_check') and _library_read_step(t.validation_steps):
        validation_status = 'observed'  # shown as a check that ran: cvENGINE read the library's served file (validation.library_step)
    return {'classification': t.classification, 'status': t.status, 'validation_status': validation_status,
            'overridden': triage_lib.overridden(v, t),
            'severity_adjust': triage_lib.shown_severity_adjust(v, t),
            'first_seen': _iso(t.first_seen), 'last_seen': _iso(t.last_seen)}


def _finding_qs(project, kind):
    """The project's findings of ``kind`` as the finding screens read them (the rows ``_finding_obj`` and ``_finding_objs`` pick from)."""
    from cveFeed.models import HygieneFinding, RouteAuth
    from startScan.models import Vulnerability
    if kind not in FINDING_KINDS:
        raise ApiError(404, 'unknown finding kind')
    if kind == 'match':
        return _matches_qs(project)
    if kind == 'vulnerability':
        return Vulnerability.objects.filter(target_domain__project=project).select_related(
            'subdomain__target_domain', 'target_domain', 'triage__verdict', 'triage__heat_override_by', 'remediation_by', 'assignee') \
            .prefetch_related('cve_ids', 'cwe_ids', 'tags').annotate(comment_count=_comment_count_annotation('vulnerability'))
    if kind == 'route':
        return RouteAuth.objects.filter(project=project).select_related('domain', 'triage__verdict')
    return HygieneFinding.objects.filter(domain__project=project).select_related(
        'domain', 'triage__verdict', 'remediation_by', 'assignee').annotate(comment_count=_comment_count_annotation('hygiene'))


def _finding_obj(project, kind, finding_id):
    """The project's finding of ``kind`` with this id, or 404: another project's id is 404 exactly like a missing one."""
    obj = _finding_qs(project, kind).filter(pk=finding_id).first()
    if obj is None:
        raise ApiError(404, 'finding not found')
    return obj


def _cap_text(value):
    return None if value is None else str(value)[:EXCERPT_CAP]


def _kv(label, value):
    return {'label': label, 'value': '' if value is None else str(value)}


def _how_found_match(m):
    from cveFeed.distro import label_for
    ev = m.evidence or {}
    steps, excerpts = [], {}
    found = ' '.join(x for x in (m.matched_product, m.matched_version or '(no version)') if x)
    if m.source == 'host':
        steps.append(_kv('Observed', f'{found}, reported by the host itself' + (f' ({ev["component"]})' if ev.get('component') and ev['component'] != m.matched_product else '')))
        steps.append(_kv('Found by', 'the host inventory report' + (f' of {ev["reported_at"][:10]}' if ev.get('reported_at') else '')
                         + ('; a flaw only usable from the host itself, so no external scan can see it' if ev.get('scope') == 'local' else '')))
        if ev.get('purl'):
            steps.append(_kv('Package', ev['purl']))
    elif m.source == 'port':
        where = f'{ev.get("ip")}:{ev.get("port")}' if ev.get('ip') else ''
        steps.append(_kv('Observed', f'{found} on {where}'.strip() + (f' ({ev["service_extra"]})' if ev.get('service_extra') else '')))
        steps.append(_kv('Found by', 'nmap service detection of an open port'
                         + (f', method {ev["method"]}' + (' (guessed from the port number, not probed)' if ev['method'] == 'table' else '')
                            if ev.get('method') else '')))
    elif ev.get('version_source') == 'body' and isinstance(ev.get('script_url'), str) and ev['script_url']:
        # cvENGINE read the library's served file itself (cveFeed.js_libraries): where the version came from, which page loads it, and when
        from cveFeed import validation
        reading = validation.library_reading(m)
        confidence = ev.get('version_confidence')
        number = isinstance(confidence, (int, float)) and not isinstance(confidence, bool)
        how = reading.get('how') or ('banner' if number and confidence >= 0.9 else 'signature')
        state = ev.get('copy_state') if isinstance(ev.get('copy_state'), str) else ''
        steps.append(_kv('Observed', f'{found}, read from the file\'s own {"banner" if how == "banner" else "code"} at {ev["script_url"]}'))
        steps.append(_kv('Loaded by', (reading.get('page_url') or 'the host\'s front page')
                         + {'effective': ' (the copy the page runs)', 'shadowed': ' (a later copy replaces it)',
                            'fallback': ' (a fallback, loaded only when another script fails)',
                            'unresolved': ' (the page does not show which copy runs)'}.get(state, '')))
        steps.append(_kv('Found by', 'library body read' + (f', {_iso(reading["read_at"])}' if reading.get('read_at') else '')))
        excerpts['script_url'] = _cap_text(ev['script_url'])
    else:
        steps.append(_kv('Observed', f'{found} (technology fingerprint of the web server)'))
        steps.append(_kv('Found by', 'technology detection'))
    if ev.get('cpe'):
        steps.append(_kv('CPE', ev['cpe']))
    rng = ev.get('range') or {}
    if rng:
        steps.append(_kv('Advisory range', ', '.join(f'{k} {v}' for k, v in rng.items() if v) or 'no usable bound'))
    inside = {True: 'inside the affected range', False: 'outside the affected range', None: 'unknown (no version, or no usable bound to compare)'}
    steps.append(_kv('Version check', inside[m.version_in_range]))
    if m.distro_status in ('patched', 'vulnerable') or ev.get('distro'):
        steps.append(_kv('Distribution', label_for(m.distro_status, m.distro_fixed_version)
                         or ', '.join(f'{k} {v}' for k, v in (ev.get('distro') or {}).items() if v)))
    if m.template_result:
        steps.append(_kv('Template check', f'{m.template_result.replace("_", " ")}' + (f' ({m.template_id})' if m.template_id else '')
                         + (f', tested {_iso(m.template_tested_at)}' if m.template_tested_at else '')))
    else:
        steps.append(_kv('Template check', 'not tested'))
    return {'steps': steps, 'excerpts': excerpts}


def _how_found_vulnerability(v):
    names = [c.name for c in v.cve_ids.all()]
    steps = [_kv('Source', v.source or 'scanner'), _kv('Template', v.template_id), _kv('Matcher', v.matcher_name),
             _kv('Matched at', v.http_url), _kv('CVE', ', '.join(names)),
             _kv('Extracted', '; '.join((v.extracted_results or [])[:5]))]
    return {'steps': [s for s in steps if s['value']], 'excerpts': {'request': _cap_text(v.request), 'response': _cap_text(v.response)}}


def _how_found_route(r):
    ev = r.evidence or {}
    steps = [_kv('URL', r.url), _kv('Anonymous GET answered', f'{r.http_status} ({r.auth_state.replace("_", " ")})'),
             _kv('Markers', ', '.join(ev.get('markers') or [])), _kv('Cookies set', ', '.join(ev.get('cookies') or [])),
             _kv('Sensitive data', ', '.join(f'{k}: {(v or {}).get("count", 0)}' for k, v in (r.sensitive or {}).items()))]
    return {'steps': [s for s in steps if s['value']], 'excerpts': {}}


def _how_found_hygiene(f):
    steps = [_kv('Check', f.check_name), _kv('Host', f.host)] + [_kv(str(k), v) for k, v in list((f.evidence or {}).items())[:20]]
    return {'steps': steps, 'excerpts': {}}


def _history(project, host):
    from cveFeed.models import AssetChange
    qs = AssetChange.objects.filter(project=project, host=host, kind__in=HISTORY_KINDS).select_related('domain').order_by('-detected_at', '-id')
    return [_change(c) for c in qs[:30]]


def _finding_summary(kind, obj):
    """(title, host, target name, scanner severity number or None)."""
    if kind == 'match':
        cvss = obj.cve_entry.cvss
        base = 4 if cvss and cvss >= 9 else 3 if cvss and cvss >= 7 else 2 if cvss and cvss >= 4 else 1 if cvss else 0
        sub = obj.subdomain
        return (f'{obj.cve_entry.cve_id} on {obj.matched_product or "a product"} {obj.matched_version}'.strip(), sub.name if sub else '',
                sub.target_domain.name if sub and sub.target_domain else '', base)
    if kind == 'vulnerability':
        return (obj.name, obj.subdomain.name if obj.subdomain else '', obj.target_domain.name if obj.target_domain else '', obj.severity)
    if kind == 'route':
        return (f'{obj.path} is open' if obj.auth_state == 'open' else obj.url, obj.host, obj.domain.name, None)
    return (obj.title, obj.host, obj.domain.name, obj.severity)


def _tracked_secrets(vuln):
    """The secrets inventory rows a nuclei token or bbot secret finding fed (cveFeed.secrets_inventory): masked, never the value."""
    from cveFeed import secrets_inventory
    return [{'id': s.pk, 'masked': s.masked, 'label': secrets_inventory.kind_of(s).label, 'class': s.klass, 'status': s.status,
             'severity': SEVERITY_NAMES.get(s.severity, 'unknown'), 'severity_basis': s.severity_basis}
            for s in secrets_inventory.tracked(vuln.pk)]


def finding_detail(ctx, slug, kind, finding_id):
    """Everything about one finding: why it matters, how it was found (the evidence chain), when it was first and last seen with the
    host's change history, the AI classification (and the model's own words when the rules overrode it), the fix, and every
    validation check that ran with its exact command and result. Request and response excerpts appear here and nowhere in a list."""
    from cveFeed import triage as triage_lib
    project, _ = get_one_project(ctx, slug)
    obj = _finding_obj(project, kind, finding_id)
    t = _triage_of(obj)
    v = t.verdict if t else None
    title, host, target, base = _finding_summary(kind, obj)
    how = {'match': _how_found_match, 'vulnerability': _how_found_vulnerability, 'route': _how_found_route,
           'hygiene': _how_found_hygiene}[kind](obj)
    adjust = triage_lib.shown_severity_adjust(v, t) if t else 0  # a step down only where the answer was reached (task 256)
    text = triage_lib.verdict_text(v, t)  # the model's words only on a finding of the project the answer was reached in (task 256)
    severity_ai = (SEVERITY_NAMES.get(triage_lib.adjusted_severity(base, adjust, bool(t and t.hard_evidence)))
                   if base is not None and adjust else None)
    remediation = {'text': text['remediation'], 'scanner': getattr(obj, 'remediation', '') if kind == 'vulnerability' else ''}
    if kind == 'match':
        remediation.update(fixed_in=_fixed_versions(obj.cve_entry, obj.matched_product), local_checks=(t.local_checks if t else None) or None)
    closed = _closure_fields(kind, obj) if kind in STATUS_KINDS else {}
    if kind in STATUS_KINDS:  # match, vulnerability, hygiene: a web route has no remediation workflow
        remediation.update(status=obj.remediation_status, note=obj.remediation_note, **closed)
    assessment_status = ('closed_not_applicable' if kind == 'match' and obj.ai_verdict == 'not_affected' and
                         (obj.ai_reason or '').startswith('Closed automatically:')
                         else 'candidate' if kind == 'match' else None)
    steps = (t.validation_steps if t else []) or []
    first = (t.first_seen if t else None) or getattr(obj, 'created_at', None) or getattr(obj, 'first_seen', None) or getattr(obj, 'discovered_date', None)
    last = (t.last_seen if t else None) or getattr(obj, 'updated_at', None) or getattr(obj, 'last_seen', None) or getattr(obj, 'checked_at', None) or first
    evidence = {k: ({kk: (_cap_text(vv) if isinstance(vv, str) else vv) for kk, vv in (e or {}).items()})
                for k, e in ((t.validation_evidence if t else None) or {}).items()}
    diagnostic = None
    if t and t.status == 'error' and t.reason.startswith('{'):
        import json
        try:
            candidate = json.loads(t.reason)
            if isinstance(candidate, dict) and candidate.get('stage') == 'ai_triage':
                diagnostic = {key: candidate.get(key) for key in (
                    'id', 'time', 'stage', 'category', 'finding_ids', 'provider', 'model', 'attempt_id', 'outcome', 'action',
                    'http_status', 'stop_reason', 'output_length', 'digest') if candidate.get(key) is not None}
        except (TypeError, ValueError):
            pass
    automatic = None
    if t:
        if kind == 'match':
            from cveFeed.models import OnDemandValidation
            job = OnDemandValidation.objects.filter(match=obj, requested_by__isnull=True,
                                                      project=project).order_by('-id').first()
        else:
            from cveFeed.models import AutomaticValidation
            job = AutomaticValidation.objects.filter(triage=t, project=project).order_by('-id').first()
        if job:
            result = job.result or {}
            automatic = {'id': job.pk, 'status': job.status, 'priority': job.priority,
                         'source': 'manual' if kind != 'match' and job.source == 'manual' else 'automatic',
                         'created': _iso(job.created_at), 'started': _iso(job.started_at),
                         'finished': _iso(job.finished_at), 'check_state': result.get('check_state'),
                         'ai_state': result.get('ai_state'),
                         'reason': result.get('reason') if result.get('reason') in (
                             'no_longer_eligible', 'finding_removed', 'evidence_changed', 'out_of_scope') else None,
                         'error': 'Validation failed; see scoped activity and worker diagnostics.' if job.error else ''}
    heat = _shown_heat(kind, obj) if kind in HEAT_KINDS else None
    return {
        'kind': kind, 'id': obj.pk, 'title': title, 'host': host, 'target': target,
        # the heat it shows on its host, why, and a heat a person set by hand (null: cvENGINE derives it); a hygiene finding or a route has none
        'heat': heat, 'heat_reason': _shown_heat_reason(kind, obj, heat) if heat else '',
        'heat_override': _heat_override(t) if kind in HEAT_KINDS else None,
        'confidence': obj.confidence if kind == 'match' else None,  # the rules' match score; the detail pane no longer needs the list row for it
        'host_reported': kind == 'match' and obj.source == 'host', 'assessment_status': assessment_status,
        'assessment_reason': obj.ai_reason if assessment_status == 'closed_not_applicable' else '',
        'automatic_validation': automatic,
        'ai_review': _review_of(t),
        'severity': SEVERITY_NAMES.get(base) if base is not None else None, 'severity_ai': severity_ai,
        'first_seen': _iso(first), 'last_seen': _iso(last), 'history': _history(project, host),
        'why_it_matters': text['impact'],
        'ai': {'classification': t.classification if t else '', 'status': t.status if t else 'untracked',
               'connected': _ai_connected(),  # "Waiting for AI triage" is only true while a model is connected to do it
               'reason': f'AI review failed ({diagnostic["category"]}); retry scheduled.' if diagnostic else t.reason if t else '',
               'diagnostic': diagnostic,
               'overridden': triage_lib.overridden(v, t),
               'model_classification': v.model_classification if v else '',
               'model_reason': text['model_reason'], 'model': v.model if v else '', 'invalid_output': bool(v and v.invalid_output),
               'triaged': _iso(v.created_at) if v else None, 'severity_adjust': adjust, 'severity_reason': text['severity_reason'] if adjust else '',
               'hard_evidence': (t.hard_evidence if t else []) or [], 'advice': text['validation_notes']},
        'how_found': how, 'remediation': remediation,
        'status_changed_at': _iso(obj.remediation_updated_at) if kind in STATUS_KINDS else None,
        'status_changed_by': _user_brief(obj.remediation_by) if kind in STATUS_KINDS else None,
        'assignee': _user_brief(obj.assignee) if kind in STATUS_KINDS else None,
        'comment_count': obj.comment_count if kind in STATUS_KINDS else 0,
        'closure_note': closed.get('closure_note'), 'closed_by': closed.get('closed_by'), 'closed_at': closed.get('closed_at'),
        'closed_automatically': closed.get('closed_automatically', False),
        'agent_task': _agent_task_of(obj) if kind == 'match' else None,
        'retest': {**_retest_of(obj), 'history': _retest_history(t)} if kind in STATUS_KINDS else None,
        'secrets': _tracked_secrets(obj) if kind == 'vulnerability' else [],  # "Tracked in Secrets": the inventory rows a token finding fed
        'cve': {**_cve_context(obj.cve_entry), 'detection': _detection(obj.cve_entry)} if kind == 'match' else None,
        'confirm': _confirm_guide(obj) if kind == 'match' else None,
        'validation': {'status': _triage_brief(t)['validation_status'] if t else 'none', 'steps': steps, 'evidence': evidence,
                       'validated': _iso(t.validated_at) if t else None, 'next_attempt': _iso(t.next_attempt_at) if t else None,
                       'confidence_adjust': t.confidence_adjust if t else 0.0},
    }


def _confirm_guide(m):
    """How to confirm this one match by hand (cveFeed.confirm_guide): where to look, what to look for, the read-only steps with the match's
    real host, port and URL, how to read the answer and how to fix it. None when it cannot be built; it never fails the detail."""
    from cveFeed import confirm_guide
    try:
        return confirm_guide.match_guide(m)
    except Exception:  # noqa: BLE001 - the guide is help on top of the evidence; a gap in it must not cost the finding its page
        import logging
        logging.getLogger(__name__).warning('could not build the confirm guide of match %s', m.pk, exc_info=True)
        return None


MAX_COMMENT_LENGTH = 4000


def _comment(c):
    return {'id': c.id, 'text': c.text, 'author': _user_brief(c.author), 'created': _iso(c.created_at)}


def list_finding_comments(ctx, slug, kind, finding_id, params=None):
    """The comments on one finding, oldest first, a page at a time."""
    from cveFeed.models import FindingComment
    project, _ = get_one_project(ctx, slug)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    _finding_obj(project, kind, finding_id)  # 404 for an unknown finding, or one in another project
    rows = FindingComment.objects.filter(project=project, finding_kind=kind, finding_id=finding_id).select_related('author').order_by('id')
    return paginate(rows, params or {}, _comment)


def add_finding_comment(ctx, slug, kind, finding_id, text):
    """Add one comment, logged to the finding's audit trail. A write like any other (read-only tokens and the audit
    role cannot comment; ``_all`` is never writable), even though it does not touch the finding's own remediation
    fields, since it creates a row."""
    from cveFeed.models import FindingAuditEvent, FindingComment
    project, _ = get_one_project(ctx, slug, write=True)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    if not isinstance(text, str) or not text.strip():
        raise ApiError(400, 'text must not be empty')
    obj = _finding_obj(project, kind, finding_id)
    comment = FindingComment.objects.create(project=project, finding_kind=kind, finding_id=obj.pk, author=ctx.user, text=text[:MAX_COMMENT_LENGTH])
    FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=obj.pk, event='comment', actor=ctx.user,
                                      before={}, after={'comment_id': comment.id, 'text': comment.text[:200]})
    return _comment(comment)


def _audit_event(e):
    return {'id': e.id, 'event': e.event, 'actor': _user_brief(e.actor), 'before': e.before, 'after': e.after, 'created': _iso(e.created_at)}


def finding_audit(ctx, slug, kind, finding_id, params=None):
    """One finding's audit trail, newest first: status changes, assignee changes, and comments, each with who, when,
    and (status/assignee) what changed from and to. A comment's own text is also in GET .../comments; it is repeated
    here as a short before/after so the trail reads as one timeline without a second request."""
    from cveFeed.models import FindingAuditEvent
    project, _ = get_one_project(ctx, slug)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    _finding_obj(project, kind, finding_id)
    rows = FindingAuditEvent.objects.filter(project=project, finding_kind=kind, finding_id=finding_id).select_related('actor')
    return paginate(rows.order_by('-id'), params or {}, _audit_event)


MAX_SLA_DAYS = 3650


def _project_settings(project, sla):
    from agentapi.inventory import project_policy
    from cveFeed import host_review
    from cveFeed.models import DEFAULT_SLA_DAYS
    return {'sla_days': sla, 'sla_defaults': DEFAULT_SLA_DAYS, 'inventory': project_policy(project), 'host_review_mode': host_review.mode_of(project)}


def get_project_settings(ctx, slug):
    """This project's settings: ``sla_days`` (days to fix per severity: critical, high, medium, low), the same for everyone,
    so a UI's "overdue" is consistent. ``sla_defaults`` is what an unset severity falls back to. ``inventory`` is the host inventory
    policy: ``create_hosts`` (whether a report from an unscanned host adds it as a target) and ``stale_days``."""
    from cveFeed.models import ProjectSettings
    project, _ = get_one_project(ctx, slug)
    return _project_settings(project, ProjectSettings.sla_for(project))


def set_project_settings(ctx, slug, body):
    """Change this project's settings. ``sla_days`` is a partial update: send only the severities to change, each a whole
    number of days from 1 to 3650, or ``null`` to go back to the default. Anyone with a write role may change it, like the
    project's API keys; a read-only token or the audit role may not. ``inventory`` ({create_hosts, stale_days}) changes the host
    inventory policy instead of, or as well as, the SLA. ``host_review_mode`` (``auto``, ``recommend`` or ``off``) sets what the AI host review may do
    in this project: ``auto`` starts its read-only next step by itself (a person sets it in the web interface, an API key cannot), ``recommend`` (the default)
    only proposes it, ``off`` stops reviewing hosts here."""
    from cveFeed.models import DEFAULT_SLA_DAYS, ProjectSettings
    project, _ = get_one_project(ctx, slug, write=True)
    if isinstance(body, dict) and 'host_review_mode' in body:
        mode = body['host_review_mode']
        if mode not in ProjectSettings.HOST_REVIEW_MODES:
            raise ApiError(400, f'host_review_mode must be one of: {", ".join(ProjectSettings.HOST_REVIEW_MODES)}')
        if ctx.token is not None:  # an API key or an agent may only turn the host review DOWN (auto, then recommend, then off): a person sets it up, in the web interface
            from cveFeed import host_review
            if host_review.MODE_RANK[mode] > host_review.MODE_RANK[host_review.mode_of(project)]:
                raise ApiError(403, 'only a person raises the host review (off to recommend, anything to automatic), in the web interface; an API key may only lower it')
        row, _created = ProjectSettings.objects.get_or_create(project=project)
        row.host_review_mode, row.updated_by = mode, ctx.user
        row.save(update_fields=['host_review_mode', 'updated_by', 'updated_at'])
        if 'sla_days' not in body and 'inventory' not in body:
            return _project_settings(project, ProjectSettings.sla_for(project))
    if isinstance(body, dict) and 'inventory' in body:  # the host inventory policy (agentapi.inventory), alone or beside sla_days
        from agentapi.inventory import set_policy
        set_policy(ctx, project, body['inventory'])
        if 'sla_days' not in body:
            return _project_settings(project, ProjectSettings.sla_for(project))
    changes = body.get('sla_days') if isinstance(body, dict) else None
    if not isinstance(changes, dict) or not changes:
        raise ApiError(400, 'sla_days must be an object naming at least one severity (or inventory, to change the host inventory policy)')
    unknown = [k for k in changes if k not in DEFAULT_SLA_DAYS]
    if unknown:
        raise ApiError(400, f'sla_days severities must be among {", ".join(DEFAULT_SLA_DAYS)}: unknown {", ".join(map(str, unknown))}')
    row, _created = ProjectSettings.objects.get_or_create(project=project)
    stored = dict(row.sla_days or {})
    for severity, days in changes.items():
        if days is None:
            stored.pop(severity, None)
        elif isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_SLA_DAYS:
            raise ApiError(400, f'{severity} must be a whole number of days from 1 to {MAX_SLA_DAYS}, or null for the default')
        else:
            stored[severity] = days
    row.sla_days, row.updated_by = stored, ctx.user
    row.save(update_fields=['sla_days', 'updated_by', 'updated_at'])
    return _project_settings(project, ProjectSettings.sla_for(project))


def list_members(ctx, slug, params=None):
    """Users who can act on this project, for an assignee picker: its direct members, plus an organization's members
    when the project belongs to one (an org role already grants project access, see tenancy.roles.effective_role). A
    superuser with no membership row of their own is not listed; assign to an actual team member instead."""
    from django.contrib.auth.models import User
    from django.db.models import Q
    project, _ = get_one_project(ctx, slug)
    members = Q(project_memberships__project=project)
    if project.org_id:
        members |= Q(org_memberships__org_id=project.org_id)
    users = User.objects.filter(members).distinct().order_by('username')
    return paginate(users, params or {}, _user_brief)


def _triage_item(t):
    finding = t.finding
    kind = {'cve_match': 'match', 'nuclei': 'vulnerability', 'db_exposure': 'vulnerability', 'bbot': 'vulnerability',
            'route_auth': 'route', 'hygiene': 'hygiene'}[t.kind]
    title = (finding.cve_entry.cve_id if kind == 'match' else finding.name if kind == 'vulnerability'
             else finding.url if kind == 'route' else finding.title) if finding else ''
    return {'id': t.id, 'kind': t.kind, 'finding': {'type': kind, 'id': finding.pk if finding else None}, 'host': t.host, 'title': title,
            **_triage_brief(t)}


def list_triage(ctx, slug, params):
    """Triage of every finding: ?status= (pending, triaged, not_triaged, error), ?classification=, ?validation= (hit, clean, failed,
    pending, no_check, skipped_blocked, none) and ?kind=. Findings classified as likely false positives are listed like any other."""
    from cveFeed.models import Triage
    project, _ = get_one_project(ctx, slug)
    qs = Triage.objects.filter(project=project).select_related('verdict', 'match__cve_entry', 'vulnerability', 'route', 'hygiene')
    for param, field, allowed in (('status', 'status', Triage.STATUSES), ('validation', 'validation_status', Triage.VALIDATION_STATUSES),
                                  ('kind', 'kind', Triage.KINDS), ('classification', 'classification', None)):
        if params.get(param):
            if allowed and params[param] not in allowed:
                raise ApiError(400, f'{param} must be one of: {", ".join(allowed)}')
            qs = qs.filter(**{field: params[param]})
    return paginate(qs.order_by('-last_seen', '-id'), params, _triage_item)


def retriage_finding(ctx, slug, kind, finding_id):
    """Queue one owned finding through the same bounded validation worker used for automatic review."""
    if kind == 'match':
        return validate_match_now(ctx, slug, finding_id)
    from datetime import timedelta
    from django.db import transaction
    from cveFeed import activity, hot_validation, triage as triage_lib
    from cveFeed.models import AutomaticValidation, Triage
    from cveFeed.tasks import automatic_validate_finding
    from dashboard.models import Project
    project, _ = get_project(ctx, slug, write=True)
    obj = _finding_obj(project, kind, finding_id)
    pairs = triage_lib.track([obj])
    if not pairs:
        raise ApiError(409, 'this finding has no owning project to triage it under')
    row = pairs[0][0]
    if not hot_validation.manual_eligible(row):
        raise ApiError(409, 'this finding is closed or no longer in project scope')
    with transaction.atomic():
        Project.objects.select_for_update().get(pk=project.pk)
        now = timezone.now()
        AutomaticValidation.objects.filter(project=project, source='manual', status='queued',
            created_at__lt=now - timedelta(minutes=10)).update(status='failed', error='request expired before a worker accepted it',
                                                              finished_at=now)
        AutomaticValidation.objects.filter(project=project, source='manual', status='running',
            started_at__lt=now - timedelta(minutes=30)).update(status='failed', error='worker lease expired', finished_at=now)
        row = Triage.objects.select_for_update().get(pk=row.pk, project=project)
        active = AutomaticValidation.objects.filter(triage=row, status__in=('queued', 'running')).order_by('-id').first()
        if active:
            return {'queued': True, 'id': active.pk, 'status': active.status, 'triage': _triage_brief(row)}
        previous = AutomaticValidation.objects.filter(triage=row, source='manual').order_by('-id').first()
        if previous and previous.signature == row.signature and previous.status == 'completed' and previous.finished_at and \
                previous.finished_at >= now - timedelta(minutes=5):
            return {'queued': False, 'id': previous.pk, 'status': 'completed', 'triage': _triage_brief(row)}
        if previous and previous.signature == row.signature and previous.status == 'failed' and previous.next_attempt_at and \
                previous.next_attempt_at > now:
            raise ApiError(429, 'this finding can be retried after its validation backoff')
        if hot_validation._active_count(project.pk) >= hot_validation.PROJECT_ACTIVE_CAP:
            raise ApiError(429, 'this project already has 10 validation requests in progress')
        if AutomaticValidation.objects.filter(project=project, source='manual', requested_by=ctx.user,
                created_at__gte=now - timedelta(hours=1)).count() >= 20:
            raise ApiError(429, 'hourly validation request limit reached')
        job = AutomaticValidation.objects.create(triage=row, project=project, signature=row.signature,
                                                 priority=3, source='manual', requested_by=ctx.user, attempts=1,
                                                 requested_token_id=ctx.token.pk if ctx.token else None)
    try:
        automatic_validate_finding.apply_async(args=[job.pk], priority=3)
    except Exception as exc:
        AutomaticValidation.objects.filter(pk=job.pk, status='queued').update(status='failed',
            error='validation broker rejected the request', finished_at=timezone.now(),
            next_attempt_at=timezone.now() + timedelta(minutes=5))
        activity.log('validate', f'Manual validation #{job.pk} could not be queued', project=project,
                     status='failed', job_id=job.pk, finding_id=row.pk)
        raise ApiError(503, 'validation queue is unavailable') from exc
    activity.log('validate', f'Manual validation #{job.pk} queued for finding #{row.pk}', project=project,
                 job_id=job.pk, finding_id=row.pk, priority=3, queue='validation_priority_queue')
    return {'queued': True, 'id': job.pk, 'status': 'queued', 'triage': _triage_brief(row)}


def _validation_request(job):
    return {'id': job.pk, 'match_id': job.match_id, 'status': job.status, 'created': _iso(job.created_at),
            'started': _iso(job.started_at), 'finished': _iso(job.finished_at), 'result': job.result,
            'error': job.error}


def validate_match_now(ctx, slug, match_id):
    """Queue one owned finding only. The project lock makes per-project limits and deduplication atomic."""
    from datetime import timedelta
    from django.db import transaction
    from cveFeed import activity
    from cveFeed.models import OnDemandValidation
    from dashboard.models import Project

    project, _ = get_one_project(ctx, slug, write=True)
    match = _matches_qs(project).filter(pk=match_id).first()
    if match is None or not match.subdomain_id or not match.subdomain.target_domain_id:
        raise ApiError(404, 'match not found')
    if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith('Closed automatically:'):
        raise ApiError(409, 'this candidate correlation is closed; it will be reconsidered if the product evidence changes')
    with transaction.atomic():
        Project.objects.select_for_update().get(pk=project.pk)
        now = timezone.now()
        OnDemandValidation.objects.filter(project=project, status='queued', created_at__lt=now - timedelta(minutes=10)).update(
            status='failed', error='queue request expired before a worker accepted it', finished_at=now)
        OnDemandValidation.objects.filter(project=project, status='running', started_at__lt=now - timedelta(minutes=30)).update(
            status='failed', error='worker lease expired; request may be retried', finished_at=now)
        active = OnDemandValidation.objects.filter(match=match, status__in=('queued', 'running')).order_by('-id').first()
        if active:
            return _validation_request(active)
        recent = OnDemandValidation.objects.filter(match=match, status='completed', created_at__gte=now - timedelta(minutes=5)).order_by('-id').first()
        if recent:
            return _validation_request(recent)
        if OnDemandValidation.objects.filter(project=project, status__in=('queued', 'running')).count() >= 10:
            raise ApiError(429, 'this project already has 10 validation requests in progress')
        if OnDemandValidation.objects.filter(project=project, requested_by=ctx.user,
                                             created_at__gte=timezone.now() - timedelta(hours=1)).count() >= 20:
            raise ApiError(429, 'hourly validation request limit reached')
        job = OnDemandValidation.objects.create(match=match, project=project, requested_by=ctx.user, source='manual',
                                               requested_token_id=ctx.token.pk if ctx.token else None)
    from cveFeed.tasks import validate_match_on_demand
    try:
        validate_match_on_demand.apply_async(args=[job.pk], priority=3)
    except Exception as exc:
        OnDemandValidation.objects.filter(pk=job.pk, status='queued').update(status='failed', error='could not queue the job',
                                                                              finished_at=timezone.now())
        activity.log('validate', f'Validation request #{job.pk} could not be queued for {match.cve_entry.cve_id} on {match.subdomain.name}',
                     project=project, cve_id=match.cve_entry.cve_id, status='failed', request_id=job.pk, match_id=match.pk)
        raise ApiError(503, 'validation queue is unavailable') from exc
    activity.log('validate', f'Validation request #{job.pk} queued for {match.cve_entry.cve_id} on {match.subdomain.name}',
                 project=project, cve_id=match.cve_entry.cve_id, request_id=job.pk, match_id=match.pk)
    return _validation_request(job)


def validation_request(ctx, slug, match_id, request_id):
    from datetime import timedelta
    from cveFeed.models import OnDemandValidation
    project, _ = get_one_project(ctx, slug)
    if not _matches_qs(project).filter(pk=match_id).exists():
        raise ApiError(404, 'match not found')
    job = OnDemandValidation.objects.filter(pk=request_id, match_id=match_id, project=project).first()
    if not job:
        raise ApiError(404, 'validation request not found')
    now = timezone.now()
    if ((job.status == 'queued' and job.created_at < now - timedelta(minutes=10)) or
            (job.status == 'running' and job.started_at and job.started_at < now - timedelta(minutes=30))):
        OnDemandValidation.objects.filter(pk=job.pk, status=job.status).update(
            status='failed', error='validation worker lease expired', finished_at=now)
        job.refresh_from_db()
    return _validation_request(job)
