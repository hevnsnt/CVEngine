"""Operations shared by the REST API and the MCP tools.

Every function takes a ``Ctx`` (the acting user and, for token calls, the token)
and enforces tenancy itself: the project must be visible to the user, writes need
a role above audit, and a read-only token can never write. Queries are filtered
to the project explicitly, in addition to the request-wide data scope.
"""
import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Optional

from django.utils import timezone

from cveFeed.counts import RUNNING_WINDOW
from tenancy import roles

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
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


@dataclass
class Ctx:
    user: object
    token: Optional[object] = None


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
        return AllProjects(_allowed_ids(ctx.user)), role
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
    except (TypeError, ValueError):
        raise ApiError(400, f'{name} must be an integer')


def paginate(queryset, params, serialize):
    try:
        page = max(1, int(params.get('page', 1)))
        size = min(PAGE_SIZE_MAX, max(1, int(params.get('page_size', PAGE_SIZE_DEFAULT))))
    except (TypeError, ValueError):
        raise ApiError(400, 'page and page_size must be integers')
    total = queryset.count()
    start = (page - 1) * size
    return {'count': total, 'page': page, 'page_size': size,
            'results': [serialize(o) for o in queryset[start:start + size]]}


def _iso(value):
    return value.isoformat() if value else None


def _user_brief(user):
    """{id, username, name} for a status-change actor or an assignee, None when there is none."""
    return {'id': user.id, 'username': user.username, 'name': user.get_full_name() or user.username} if user else None


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

def me(ctx):
    from dashboard.models import Project
    projects = [{'slug': p.slug, 'name': p.name, 'role': roles.effective_role(ctx.user, p)}
                for p in Project.objects.order_by('name')]
    profile = getattr(ctx.user, 'tenancy_profile', None)
    return {'username': ctx.user.username, 'projects': projects,
            'bugbounty_enabled': ctx.user.is_superuser or bool(profile and profile.bugbounty_enabled),
            'token': {'name': ctx.token.name, 'read_only': ctx.token.read_only,
                      'assets': ctx.token.assets} if ctx.token else None}


def list_projects(ctx, params=None):
    return {'results': me(ctx)['projects']}


def list_engines(ctx, params=None):
    from scanEngine.models import EngineType
    return {'results': [{'id': e.id, 'name': e.engine_name, 'default': bool(e.default_engine)}
                        for e in EngineType.objects.order_by('engine_name')]}


# --- targets and scans ---------------------------------------------------------

def _target(d):
    out = {'id': d.id, 'name': d.name, 'description': d.description,
           'created': _iso(d.insert_date), 'last_scan': _iso(d.start_scan_date),
           'scope_mode': d.scope_mode, 'host_scoped': d.is_host_scoped()}
    if hasattr(d, 'n_hosts'):  # list view: how big the target is and how much of it is exposed
        out['hosts'], out['exposed'] = d.n_hosts, d.n_exposed
    return out


def list_targets(ctx, slug, params):
    from targetApp.models import Domain
    from django.db.models import Count
    project, _ = get_project(ctx, slug)
    from cveFeed.correlation import latest_scan_q
    current = latest_scan_q('subdomain__')  # each host once, from its domain's current scan
    from cveFeed.counts import exposure_filter
    exposed = exposure_filter('subdomain__')  # the same definition as the dashboard's Exposed hosts
    everywhere = _is_all(project)
    qs = _scoped(Domain.objects.all(), project, 'project')
    qs = qs.order_by('name', 'project_id', 'id') if everywhere else qs.order_by('name')
    qs = qs.annotate(n_hosts=Count('subdomain', filter=current, distinct=True), n_exposed=Count('subdomain', filter=exposed & current, distinct=True))
    if everywhere:
        qs = qs.select_related('project')
    if params.get('q'):
        qs = qs.filter(name__icontains=params['q'])
    return paginate(qs, params, _tagged(_target, lambda d: d.project) if everywhere else _target)


def get_target(ctx, slug, target_id):
    from targetApp.models import Domain
    project, _ = get_one_project(ctx, slug)
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    return _target(d)


def set_target_scope(ctx, slug, target_id, scope_mode):
    """Set how far a target's scope reaches: ``auto`` (the shared-domain list decides), ``host`` (this host only, never its
    parent domain) or ``parent`` (the registrable domain is owned, even on the shared list: use with care)."""
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    if scope_mode not in {m for m, _label in Domain.SCOPE_MODES}:
        raise ApiError(400, 'scope_mode must be auto, host or parent')
    d = Domain.objects.filter(project=project, id=target_id).first()
    if not d:
        raise ApiError(404, 'target not found')
    d.scope_mode = scope_mode
    d.save(update_fields=['scope_mode'])
    return _target(d)


def _expand_target(value):
    """Validate one pasted target and expand it: ``(kind, names)``. A CIDR or range is sized before expanding, so a /8 is
    never built."""
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
        blocked = next((n for n in names if not is_scannable_ip(n)), None)
        if blocked:
            raise ApiError(400, f'{blocked} is a loopback, link-local or internal address, which cannot be scanned '
                                '(an operator can allow internal ranges with CVENGINE_ALLOW_PRIVATE_TARGETS=1)')
    return kind, names


def _create_domains(project, names, description='', excluded=None):
    """Create a Domain per name in bulk, in order. Returns (the rows created, the names that already existed). Domain
    names are globally unique in reNgine, so a name another project holds counts as existing. A name the project's organization
    excluded for good ("Remove & exclude") is never created; it is appended to ``excluded`` when a list is given."""
    from cveFeed.exclusions import excluded_names, normalize
    from targetApp.models import Domain
    names = list(dict.fromkeys(names))
    banned = excluded_names(project.id)
    if banned:
        skipped = [n for n in names if normalize(n) in banned]
        if excluded is not None:
            excluded.extend(skipped)
        names = [n for n in names if n not in set(skipped)]
    existing = set()
    for start in range(0, len(names), 1000):
        existing.update(Domain._base_manager.filter(name__in=names[start:start + 1000]).values_list('name', flat=True))
    wanted = [n for n in names if n not in existing]
    now = timezone.now()
    created = []
    for start in range(0, len(wanted), 1000):
        part = wanted[start:start + 1000]
        # ignore_conflicts: a concurrent add of the same name must not fail the whole batch; the re-read says what we own
        Domain.objects.bulk_create([Domain(name=n, project=project, description=description or None, insert_date=now) for n in part],
                                   ignore_conflicts=True)
        created += Domain.objects.filter(project=project, name__in=part).order_by('id')
    created.sort(key=lambda d: d.id)
    return created, [n for n in names if n in existing]


def add_target(ctx, slug, value, description='', discover=False, mode=None):
    """Add a domain, IP, CIDR or range as target(s); ranges expand to individual IPs (capped). Every address of a range is
    queued for discovery, in order."""
    from targetApp.target_types import DOMAIN
    project, _ = get_project(ctx, slug, write=True)
    kind, names = _expand_target(value)
    excluded = []
    created, existing = _create_domains(project, names, description, excluded)
    if excluded and not created and not existing:
        raise ApiError(409, f'{excluded[0]} is excluded for this organization and is never added or scanned '
                            '(an organization admin can lift the exclusion)')
    if kind == DOMAIN and created:  # every domain target is "subscribed": watched for new certificates going forward
        from cveFeed.tasks import watch_certificate_transparency
        watch_certificate_transparency.delay(created[0].id)
    scan_ids = []
    if discover and created:  # bbot discovery streams into the dashboard as it runs
        from cveFeed.discovery import start_discoveries
        scan_ids = [scan.id for scan in start_discoveries(created, **({'mode': mode} if mode else {}))]
    return {'kind': kind, 'created': [_target(d) for d in created], 'already_exists': existing, 'excluded': excluded, 'scan_ids': scan_ids}


SCAN_STATUS_FILTER = {'queued': -1, '-1': -1, 'failed': 0, '0': 0, 'running': 1, '1': 1, 'finished': 2, 'success': 2, '2': 2,
                      'aborted': 3, '3': 3}


def _scan(s, detail=False, queued=None):
    """``queued`` is a callable returning the queued scan ids, so a page of scans looks the queue up at most once."""
    out = {'id': s.id, 'target': s.domain.name, 'target_id': s.domain_id, 'engine': s.scan_type.engine_name,
           'status': s.scan_status, 'started': _iso(s.start_scan_date), 'finished': _iso(s.stop_scan_date),
           'error': s.error_message,
           'stalled': s.scan_status == 1 and s.start_scan_date < timezone.now() - RUNNING_WINDOW,  # marked running, but older than any scan can run
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
    elif status == 'stalled':
        qs = counts.stalled_scans(qs)
    elif SCAN_STATUS_FILTER.get(status) is not None:
        qs = qs.filter(scan_status=SCAN_STATUS_FILTER[status])
    qs = qs.order_by(
        Case(When(scan_status=1, then=Value(0)), When(scan_status=-1, then=Value(1)), default=Value(2), output_field=IntegerField()),
        Case(When(scan_status=-1, then=F('id')), default=-F('id'), output_field=IntegerField()))
    try:
        page = max(1, int(params.get('page', 1)))
        size = min(PAGE_SIZE_MAX, max(1, int(params.get('page_size', PAGE_SIZE_DEFAULT))))
    except (TypeError, ValueError):
        raise ApiError(400, 'page and page_size must be integers')
    total = qs.count()
    start = (page - 1) * size
    scans = list(qs[start:start + size])
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
    serialize = _tagged(lambda sc: _scan(sc, queued=queued), lambda sc: sc.domain.project) if everywhere else (lambda sc: _scan(sc, queued=queued))
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
    if params.get('http_status', '').isdigit():
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
    if params.get('http_status', '').isdigit():
        qs = qs.filter(http_status=int(params['http_status']))
    return paginate(qs, params, _scan_endpoint)


def list_scan_vulnerabilities(ctx, slug, scan_id, params):
    from startScan.models import Vulnerability
    scan = _scan_in_project(ctx, slug, scan_id)
    qs = Vulnerability.objects.filter(scan_history=scan).select_related('subdomain', 'triage__verdict', 'remediation_by', 'assignee') \
        .prefetch_related('cve_ids', _matches_of_host()).annotate(comment_count=_comment_count_annotation('vulnerability')).order_by('-severity', '-id')
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
    if engine_id is not None and not EngineType.objects.filter(id=engine_id).exists():
        raise ApiError(404, 'engine not found')
    scan = start_discovery(domain)
    return {'scan_id': scan.id, 'status': 'queued'}


def _refuse_excluded(project, domain):
    """409 when the target itself is a host its organization excluded for good."""
    from cveFeed.exclusions import is_excluded
    if is_excluded(project.id, domain.name):
        raise ApiError(409, f'{domain.name} is excluded for this organization and is not scanned')


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
            qs = qs.filter(name__icontains=str(q)[:200])
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
        Domain.objects.filter(project=project, id__in=[i for i, _ in chunk]).delete()
        for name in [n for _, n in chunk] + scan_dirs:  # exact directory names, never a prefix match
            safe_remove_path(os.path.join(SCAN_RESULTS_ROOT, name), SCAN_RESULTS_ROOT)
        deleted += len(chunk)
    if deleted:
        from cveFeed.admin_api import audit
        audit(ctx.user, 'targets.delete', slug, count=deleted, skipped_running=len(busy), project=slug)
    return {'deleted': deleted, 'skipped_running': len(busy), 'matched': len(wanted)}


def discover_target(ctx, slug, target_id, mode=None):
    """Start a bbot discovery plus nuclei pipeline on one existing target."""
    from cveFeed.discovery import start_discovery
    from targetApp.models import Domain
    project, _ = get_project(ctx, slug, write=True)
    domain = Domain.objects.filter(project=project, id=target_id).first()
    if not domain:
        raise ApiError(404, 'target not found')
    _refuse_excluded(project, domain)
    scan = start_discovery(domain, mode) if mode else start_discovery(domain)
    return {'scan_id': scan.id, 'status': 'started'}


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
    suffix = domain.name.lower()
    names = list(dict.fromkeys(str(h).strip().lower().rstrip('.') for h in hosts if str(h).strip()))
    from cveFeed.exclusions import drop_excluded
    inside = drop_excluded(project.id, [n for n in names if n == suffix or n.endswith('.' + suffix)])  # excluded hosts are never scanned
    if not inside:
        raise ApiError(400, f'none of the hosts is {domain.name} or under it')
    inside = inside[:RESCAN_MAX_HOSTS]
    host_pipeline.delay(domain.id, inside)
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
        _abort_scan(job.scan, ctx.user)
    return {'id': job.pk, 'status': 'stopped'}


BULK_MAX_ENTRIES = TARGET_EXPAND_CAP  # lines one bulk request may carry
BULK_MAX_EXPANDED = TARGET_EXPAND_CAP  # rows one request may create after expanding ranges (a /8 per line is never built)


def _start_discoveries(domains, mode, project_id):
    """Queue discovery for each domain with one summary line in the AI feed instead of one per target."""
    from cveFeed import activity
    from cveFeed.discovery import start_discoveries
    from reNgine import bbot as bbot_lib
    mode = mode or bbot_lib.DEFAULT_MODE
    scans = start_discoveries(domains, mode, quiet=True)
    if scans:
        activity.log('discovery', f'Queued {mode} discovery of {len(scans)} target{"s" if len(scans) != 1 else ""}', project=project_id)
    return scans


_SCHEME_RE = re.compile(r'^[a-z][a-z0-9+.\-]*://', re.I)
_MD_LINK_RE = re.compile(r'\[[^\]]*\]\(([^)\s]*)\)')
_CIDR_LIKE_RE = re.compile(r'^[0-9a-fA-F:.]+/\d{1,3}$')
_HOST_PORT_RE = re.compile(r'^(.+):(\d{1,5})$')


def normalize_target(token):
    """Reduce one pasted token to the thing to scan: a URL (any scheme: http://, https://, ssh://, ...) becomes its host,
    with credentials, port, path, query and fragment dropped; ``*.example.com`` and ``example.com.`` lose the wildcard and
    the trailing dot; a single-address CIDR (/32, /128) becomes the bare IP. Domains, IPs, CIDRs and ranges pass through."""
    t = (token or '').strip().strip('"\'<>`,;')
    if not t:
        return ''
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
    """Split pasted text (newlines, commas, spaces, # comments, markdown links, URLs) into unique targets, in order."""
    seen, out = set(), []
    for line in (text or '').splitlines():
        line = _MD_LINK_RE.sub(r'\1', line.split('#', 1)[0])  # a comment, then [text](url) -> url
        for token in re.split(r'[,\s;]+', line):
            token = normalize_target(token)
            if token and token not in seen:
                seen.add(token)
                out.append(token)
    return out


BULK_MAX_PROJECTS = 50


def has_org_headers(text):
    """True when the paste uses group headers: a ``##Org`` line or any ``#Name`` line (``# a comment`` with a space
    after the hash is a comment, not a header)."""
    return any(re.match(r'^\s*#\S', line) for line in (text or '').splitlines())


def parse_org_text(text, default_project=None):
    """Parse the grouped bulk format: an optional ``##Organization``, ``#Project`` to open a project, and the targets
    (any separator parse_target_list takes) under it. Returns (org_name or None, [(project, [targets])], errors).
    Targets above the first project header go to ``default_project`` when given, else they are reported; a second
    ``##`` header is reported. ``# comment`` lines are ignored."""
    org, groups, errors, current = None, [], [], None
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
                current = next((g for g in groups if g[0].lower() == name.lower()), None)
                if current is None:
                    current = (name, [])
                    groups.append(current)
            continue
        for entry in parse_target_list(line):
            if current is None and default_project:
                current = next((g for g in groups if g[0].lower() == default_project.lower()), None)
                if current is None:
                    current = (default_project, [])
                    groups.append(current)
            if current is None:
                errors.append({'value': entry, 'error': 'no #Project header above this line'})
            elif entry not in current[1]:
                current[1].append(entry)
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


def add_targets_by_org(ctx, text, discover=True, mode=None, current_project=None):
    """Bulk add across one organization's projects from the ``##Org`` / ``#Project`` paste format. Missing
    projects are created (needs the org admin role); every project's targets are added with that project's own
    write check, so one forbidden or invalid section never blocks the others. With no ``##Org`` (or one that does not
    exist) the caller's current organization is used; ``current_project`` is the project they are viewing, which
    also receives any targets that appear above the first ``#Project`` header."""
    from django.utils.text import slugify
    from dashboard.models import Project
    require_write_token(ctx)
    _, current = _current_org(ctx.user, current_project)
    org_name, groups, errors = parse_org_text(text, default_project=current.name if current else None)
    if not groups:
        raise ApiError(400, 'no #Project sections found')
    total = sum(len(g[1]) for g in groups)
    if len(groups) > BULK_MAX_PROJECTS:
        raise ApiError(400, f'{len(groups)} projects; the limit is {BULK_MAX_PROJECTS} per request')
    if total > BULK_MAX_ENTRIES:
        raise ApiError(400, f'{total} entries; the limit is {BULK_MAX_ENTRIES} per request')
    org, org_note = _org_for_bulk(ctx, org_name, current_project)
    can_create = roles.can_manage_org(ctx.user, org.id)
    results = []
    used, note = mode, None
    scan_ids = []
    for pname, entries in groups:
        res = {'project': pname, 'slug': None, 'project_created': False, 'received': len(entries), 'created': 0,
               'already_exists': [], 'invalid': [], 'error': None}
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
            added = _add_targets(ctx, project.slug, entries, False, None)
            res.update(created=added['created'], already_exists=added['already_exists'], invalid=added['invalid'])
            if discover and added['domains']:
                scan_ids += [scan.id for scan in _start_discoveries(added['domains'], used, project.id)]
        except ApiError as exc:
            res['error'] = exc.message
    return {'organization': org.name, 'organization_note': org_note, 'projects': results, 'created': sum(r['created'] for r in results),
            'projects_created': sum(r['project_created'] for r in results), 'invalid': errors,
            'discovery_started': len(scan_ids), 'scan_ids': scan_ids, 'mode': used, 'mode_note': note}


def add_targets(ctx, slug, values, discover=True, mode=None):
    out = _add_targets(ctx, slug, values, discover, mode)
    out.pop('domains')
    return out


def _add_targets(ctx, slug, values, discover, mode):
    """Add many targets at once. ``values`` is a list or pasted text. Each entry is validated on its own, so one
    bad line never blocks the rest; the response says what happened to every line. Every target that is created is
    queued for discovery, first in, first out."""
    from targetApp.target_types import DOMAIN
    project, _ = get_project(ctx, slug, write=True)
    entries = parse_target_list(values) if isinstance(values, str) else [t for t in dict.fromkeys(normalize_target(str(v)) for v in (values or [])) if t]
    if not entries:
        raise ApiError(400, 'no targets found in the input')
    if len(entries) > BULK_MAX_ENTRIES:
        raise ApiError(400, f'{len(entries)} entries; the limit is {BULK_MAX_ENTRIES} per request')
    names, domain_names, invalid, seen = [], [], [], set()
    for entry in entries:
        if len(names) >= BULK_MAX_EXPANDED:
            invalid.append({'value': entry, 'error': f'skipped: one request may add at most {BULK_MAX_EXPANDED} targets after expanding ranges'})
            continue
        try:
            kind, expanded = _expand_target(entry)
        except ApiError as exc:
            invalid.append({'value': entry, 'error': exc.message})
            continue
        for name in expanded:
            if name not in seen:
                seen.add(name)
                names.append(name)
                if kind == DOMAIN:
                    domain_names.append(name)
    excluded = []
    created, existing = _create_domains(project, names, excluded=excluded)
    invalid += [{'value': n, 'error': 'excluded for this organization: never added or scanned'} for n in excluded]
    if domain_names:  # domain targets are watched for new certificates going forward
        from cveFeed.tasks import watch_certificate_transparency
        names_wanted = set(domain_names)
        wanted = [d for d in created if d.name in names_wanted]
        for i, d in enumerate(wanted):  # crt.sh blocks a burst, so each check starts a couple of seconds after the last
            watch_certificate_transparency.apply_async(args=[d.id], countdown=int(i * 2.5))
    scan_ids, used, note = [], mode, None
    if discover and created:
        scan_ids = [scan.id for scan in _start_discoveries(created, used, project.id)]
    return {'received': len(entries), 'created': len(created), 'created_names': [d.name for d in created][:200],
            'domains': created, 'already_exists': existing, 'invalid': invalid,
            'discovery_started': len(scan_ids), 'scan_ids': scan_ids, 'mode': used, 'mode_note': note}


# --- inventory and findings ----------------------------------------------------

def _heat_reasons(sub):
    """What a host's colour rests on: its CVE matches (rated as they apply to a host) and its open findings, hottest first."""
    from cveFeed.distro import label_for
    from cveFeed.threat import SEVERITY_HEAT, classify_threat_tier, match_temperature
    reasons = []
    for m in sub.cve_matches.all():
        if m.ai_verdict == 'not_affected':
            continue
        c = m.cve_entry
        tier = classify_threat_tier(kev=c.kev, epss_reached=c.epss_reached, exploit_db=c.exploit_db, cvss=c.cvss)
        reasons.append({'kind': 'cve', 'label': c.cve_id, 'description': _cve_description(c, 180),
                        'detail': (f'CVSS {c.cvss}' if c.cvss is not None else 'no score') +
                        (', listed as exploited' if c.kev else '') + (', AI confirmed' if m.ai_verdict == 'affected' else '') +
                        (f', {label_for(m.distro_status, m.distro_fixed_version)}' if m.distro_status in ('patched', 'vulnerable') else ''),
                        'temp': match_temperature(tier, c.cvss, m.ai_verdict, m.distro_status),
                        'finding': 'match', 'id': m.id, 'classification': _classification_of(m)})
    for v in sub.vulnerability_set.all():
        if v.open_status and v.severity in SEVERITY_HEAT:
            reasons.append({'kind': 'finding', 'label': v.name, 'detail': SEVERITY_NAMES.get(v.severity, str(v.severity)),
                            'temp': SEVERITY_HEAT[v.severity], 'finding': 'vulnerability', 'id': v.id,
                            'classification': _classification_of(v)})
    rank = {'fire': 0, 'smoke': 1, 'ice': 2}
    return sorted(reasons, key=lambda r: rank.get(r['temp'], 3))


NUCLEI_STAGES = ('nuclei_scan', 'nuclei_targeted_scan')  # a finished targeted pass (or an older blanket one) means nuclei ran


def _host_heat(sub, reasons=None):
    """The host's worst threat temperature (fire, smoke, ice, clean or unscanned), for the colour in lists and maps."""
    from cveFeed.threat import HEAT_RANK
    reasons = _heat_reasons(sub) if reasons is None else reasons
    if reasons:
        return max((r['temp'] for r in reasons), key=HEAT_RANK.get)
    from startScan.models import ScanActivity
    nuclei_ran = bool(sub.vulnerability_set.all()) or (sub.scan_history_id and ScanActivity.objects.filter(
        scan_of_id=sub.scan_history_id, name__in=NUCLEI_STAGES, status=2).exists())
    return 'clean' if nuclei_ran else 'unscanned'


def _host_names(sub):
    """Names an IP target answers to (reverse DNS and certificate), recorded at discovery. Not added as targets: they may be
    out of scope. Empty for a hostname."""
    from cveFeed.models import DiscoveryEvent
    from targetApp.target_types import IP, classify_target
    if classify_target(sub.name) != IP or not sub.target_domain_id:
        return []
    return sorted({(e.module, e.label) for e in DiscoveryEvent.objects.filter(
        domain_id=sub.target_domain_id, host=sub.name, module__in=('ptr', 'tls-san'))})


def _merge_group(sub, others):
    """The whole host as one: ``sub`` (the richest copy of the name) plus its other current-inventory copies. IPs are merged by
    address and ports by (address, number, protocol), CVE matches by CVE id and open findings by id, so the counts agree with the
    score and the web routes, which are both read by name."""
    from startScan.models import open_ports
    ips, seen_ports = {}, set()
    reasons, seen_reasons = [], set()
    vulns, seen_vulns = {}, set()
    cves = set()
    for row in [sub, *others]:
        for ip in row.ip_addresses.all():
            entry = ips.setdefault(ip.address, {'ip': ip, 'ports': []})
            if ip.full_scanned_at and (not entry['ip'].full_scanned_at or ip.full_scanned_at > entry['ip'].full_scanned_at):
                entry['ip'] = ip
            for p in open_ports(ip):
                key = (ip.address, p.number, p.protocol)
                if key not in seen_ports:
                    seen_ports.add(key)
                    entry['ports'].append(p)
        for r in _heat_reasons(row):
            key = (r['kind'], r['finding'], r['label'] if r['kind'] == 'cve' else r['id'])
            if key not in seen_reasons:
                seen_reasons.add(key)
                reasons.append(r)
        for m in row.cve_matches.all():
            if m.ai_verdict != 'not_affected':
                cves.add(m.cve_entry.cve_id)
        for v in row.vulnerability_set.all():
            if v.open_status and v.id not in seen_vulns:
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
    return {'id': sub.id, 'heat': _host_heat_merged(sub, others, reasons), 'heat_reasons': reasons[:12], 'host': sub.name,
            'target': sub.target_domain.name if sub.target_domain else None, 'target_id': sub.target_domain_id,
            'http_status': http['status'], 'title': http['title'], 'score': display_score, 'score_detail': score_detail, 'zombie': False,
            'screenshot': bool(sub.screenshot_path),
            'technologies': sorted(techs),
            'technology_details': details,
            # what the web archive says the host ran at some point: historical evidence, never a current technology
            'archived_technologies': [{'name': n, 'urls': i.get('count', 0), 'examples': (i.get('sample') or [])[:3]}
                                      for n, i in sorted(archived.items())],
            'http': http,
            'hosting': hosting_info,
            'names': _host_names(sub),
            'ips': [{'address': addr, 'os': e['ip'].os_guess,
                     'reverse': e['ip'].reverse_pointer or '', 'country': countries.get(e['ip'].geo_iso_id, ''),
                     'names_on_ip': on_ip.get(addr, 0), 'is_cdn': bool(e['ip'].is_cdn),
                     'facts': (e['ip'].fingerprint or {}).get('facts') or {},
                     'full_scanned_at': e['ip'].full_scanned_at.isoformat() if e['ip'].full_scanned_at else None,
                     'full_scan_ports': e['ip'].full_scan_ports, 'ports': [
                {'number': p.number, 'service': p.service_name, 'protocol': p.protocol, 'product': p.product,
                 'version': p.version, 'cpe': p.cpe, 'os': p.os_guess, 'banner': (p.banner or '')[:500],
                 'info': p.service_extra or '', 'scripts': {k: str(v)[:800] for k, v in list(((p.extra or {}).get('scripts') or {}).items())[:12]},
                 'db': (p.extra or {}).get('db') or None,
                 'http': p.http or None, 'tls': p.tls or None,
                 'rdp_screenshot': _rdp_screenshot_field(sub, rdp_shots_by_port.get(p.number))} for p in e['ports']]} for addr, e in ips.items()],
            'vulns': [{'id': v.id, 'name': v.name, 'severity': SEVERITY_NAMES.get(v.severity, str(v.severity)), 'url': v.http_url,
                       'classification': _classification_of(v)} for v in vulns][:15],
            # the list above is capped and includes informational detections; these are the real counts, split the way the Scanner
            # findings page and the dashboard split them: findings (low or worse) and informational detections
            'vuln_count': sum(1 for v in vulns if v.severity != 0), 'info_count': sum(1 for v in vulns if v.severity == 0),
            'cve_matches': cve_count,
            'labels': list(labels),
            'profile': profile or dict(NO_PROFILE), 'excluded': bool(excluded)}


def _rdp_screenshot_field(sub, shot):
    """What the host record sends about one port's RDP capture (cveFeed.rdp_shot), or None when there is none."""
    if not shot:
        return None
    return {'url': f'/cve/{sub.target_domain.project.slug}/hosts/{sub.id}/rdp-screenshot/{shot.port}/' if sub.target_domain else None,
            'logged_in_user': shot.logged_in_user, 'summary': shot.ai_summary, 'error': shot.ai_error,
            'captured_at': shot.captured_at.isoformat() if shot.captured_at else None}


def _host_record(sub, ips, techs, root):
    """``(http, hosting, technology_details)`` for one host: the Shodan-style part of the record. What the host row stores wins; what
    the web route check saw on the root page (its status, title, Server and X-Powered-By headers) fills what the row lacks, so a host
    the route check reached is never shown as unprobed."""
    from cveFeed import fingerprint, hosting
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
    details = []
    for name in sorted(techs | set(from_page)):
        base, version = split_name_version(name)
        details.append({'name': base or name, 'version': version, 'category': fingerprint.categorize(name),
                        'source': from_page.get(name, 'scan')})
    return http, info, details


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
    return {'names_on_ip': names, 'countries': countries, 'archive': archive, 'rdp_shots': rdp_shots}


NO_PROFILE = {'owner': '', 'purpose': '', 'criticality': 'unknown'}


def _pid_of(project, sub):
    """The id of the project a host row belongs to: the one project asked for, or (all-projects view) its own target's project."""
    return sub.target_domain.project_id if _is_all(project) else project.id


def _pids_of(project, subs):
    """The project ids a page of hosts spans: just the project's, or the projects of the page's own rows in the all-projects view."""
    return sorted({_pid_of(project, s) for s in subs})


def _profiles_for(project, subs):
    """``({(project id, lowercase host): {owner, purpose, criticality}}, {(project id, lowercase host) that is excluded})`` for a page of
    hosts: two queries however many projects the page spans. The asset information a person typed on the host page, and whether the
    project's organization excluded the name."""
    from cveFeed.models import HostExclusion, HostProfile
    wanted = {s.name.lower() for s in subs}
    pids = _pids_of(project, subs)
    profiles = {(row.project_id, row.host): {'owner': row.owner, 'purpose': row.purpose, 'criticality': row.criticality}
                for row in HostProfile.objects.filter(project_id__in=pids, host__in=wanted)}
    try:  # the organization's exclusions reach every project of the org
        excluded = set(HostExclusion.objects.filter(org__projects__id__in=pids, host__in=wanted).values_list('org__projects__id', 'host'))
    except Exception:  # noqa: BLE001 - same as cveFeed.exclusions: a lookup problem never breaks a listing
        excluded = set()
    return profiles, excluded


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
    """``{sub.id: [other current rows of the same name in the same project]}`` for a page of hosts: one query for the whole page.
    A name in another project is a different host: copies are grouped by (project, name), never by name alone."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    subs = list(subs)
    if not subs:
        return {}
    rows = Subdomain.objects.filter(target_domain__project_id__in=_pids_of(project, subs), name__in={s.name for s in subs}).filter(latest_scan_q()) \
        .exclude(id__in=[s.id for s in subs]).select_related('target_domain') \
        .prefetch_related('ip_addresses__ports', 'cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set', 'vulnerability_set__triage', 'technologies')
    by_name = {}
    for row in rows:
        by_name.setdefault((row.target_domain.project_id, row.name), []).append(row)
    return {s.id: by_name.get((_pid_of(project, s), s.name), []) for s in subs}


def _one_per_host(qs, per_project=False):
    """Collapse a Subdomain queryset to one row per hostname: the one with the most open ports, then the most IPs, then the newest
    scan (a scan-less row last). A single Postgres DISTINCT ON over the filtered ids, then a plain ``id__in`` so ordering and paging
    stay ordinary. Richness comes from subqueries on a fresh queryset, so search joins cannot inflate the counts. ``per_project``
    (the all-projects view) keeps one row per (project, hostname): the same name in two projects is two hosts."""
    from django.db.models import Count, F, OuterRef, Subquery, Value
    from django.db.models.functions import Coalesce
    from startScan.models import OPEN_PORT_STATES, Port, Subdomain
    ports = Port.objects.filter(state__in=OPEN_PORT_STATES, ports__ip_addresses=OuterRef('pk')).order_by() \
        .values('ports__ip_addresses').annotate(c=Count('id', distinct=True)).values('c')
    ips = Subdomain.ip_addresses.through.objects.filter(subdomain_id=OuterRef('pk')).order_by() \
        .values('subdomain_id').annotate(c=Count('id')).values('c')
    keys = ('target_domain__project_id', 'name') if per_project else ('name',)
    rep = Subdomain.objects.filter(id__in=qs.order_by().values('id')).order_by(
        *keys, Coalesce(Subquery(ports), Value(0)).desc(), Coalesce(Subquery(ips), Value(0)).desc(),
        F('scan_history_id').desc(nulls_last=True), '-id').distinct(*keys).values('id')
    return Subdomain.objects.filter(id__in=rep)


def _hosts_page(project, qs, params, extra=None):
    """Paginate hosts with each row's same-name copies folded in (one extra query per page). In the all-projects view each row
    also names its project, and everything folded in (copies, labels, asset info, exclusions) is looked up per (project, host)."""
    everywhere = _is_all(project)
    page = paginate(qs, params, lambda sub: sub)
    subs = page['results']
    others = _name_siblings(project, subs)
    labels = _labels_for(project, subs)
    profiles, excluded = _profiles_for(project, subs)
    roots, shared = _roots_for(project, subs), _shared_for(project, subs)
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
    profiles, excluded = _profiles_for(project, [sub])
    key = (project.id, sub.name.lower())
    return _host(sub, _name_siblings(project, [sub])[sub.id], _labels_for(project, [sub]).get(key, ()),
                 profiles.get(key), key in excluded, _roots_for(project, [sub]).get(key), _shared_for(project, [sub]))


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
        return page
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
    return page


def _host_order(params):
    """Hosts come highest score first, then by name; ``?sort=name`` keeps plain name order."""
    sort = params.get('sort') or 'score'
    if sort not in ('score', 'name'):
        raise ApiError(400, 'sort must be score or name')
    return ('-score', 'name') if sort == 'score' else ('name',)


def list_hosts(ctx, slug, params):
    """The Shodan-style inventory: hosts with IPs, open ports and service/product/version, highest score first (?sort=name)."""
    from startScan.models import Subdomain
    project, _ = get_project(ctx, slug)
    from cveFeed.correlation import latest_scan_q
    qs = _scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
    if params.get('q'):
        qs = qs.filter(name__icontains=params['q'])
    if params.get('target_id'):
        qs = qs.filter(target_domain_id=_int_param(params['target_id'], 'target_id'))
    qs = _one_per_host(qs, per_project=_is_all(project)).select_related('target_domain__project' if _is_all(project) else 'target_domain') \
        .prefetch_related('ip_addresses__ports', 'cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set', 'vulnerability_set__triage', 'technologies').order_by(*_host_order(params))
    return _mark_zombies(project, _hosts_page(project, qs, params))


SEARCH_FIELDS = ('tech', 'banner', 'port', 'product', 'service', 'os', 'cve', 'ip', 'host', 'vuln', 'sev', 'auth',
                  'sensitive', 'zombie', 'country')
_SEARCH_TERM = re.compile(r'(-)?(?:([A-Za-z]+):)?(?:"([^"]*)"|(\S+))')


def parse_search(query):
    """Split a search into terms: ``[(negated, field or None, value, quoted)]``. A bare word has no field; ``field:value``
    filters one field; ``-term`` negates; a quoted value (``"apache tomcat"``, ``tech:"apache tomcat"``) is a phrase, and
    never split on comma even if it contains one (``quoted`` says so, for the comma-OR a field value otherwise gets)."""
    terms = []
    for m in _SEARCH_TERM.finditer(query or ''):
        neg, field, quoted, bare = m.group(1), m.group(2) or '', m.group(3), m.group(4) or ''
        is_quoted = quoted is not None
        value = (quoted if is_quoted else bare).strip()
        if field and field.lower() not in SEARCH_FIELDS:
            value, field, is_quoted = f'{field}:{value}', '', False  # "http://x" or "foo:bar": not a field, just text
        if value:
            terms.append((bool(neg), field.lower() or None, value, is_quoted))
    return terms


def _ip_filter(value):
    """A Q matching hosts with an IP equal to ``value``, inside it (``10.0.0.0/24``, via Postgres ``inet``), or starting with it."""
    from django.db.models import Q
    from startScan.models import IpAddress
    if '/' in value:
        try:
            net = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ApiError(400, f'{value} is not a valid CIDR range')
        inside = IpAddress.objects.extra(where=['address::inet <<= %s::inet'], params=[net]).values('pk')
        return Q(ip_addresses__in=inside)
    try:
        return Q(ip_addresses__address=str(ipaddress.ip_address(value)))
    except ValueError:
        return Q(ip_addresses__address__startswith=value)


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
        return q
    if field == 'tech':
        return _running_q(value, project)
    if field == 'banner':
        return _banner_q(value)
    if field == 'port':
        if not value.isdigit():
            raise ApiError(400, 'port: takes a port number, e.g. port:3306 (use product: or service: for names)')
        return Q(**{ports + 'number': int(value)}) & open_port
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
        return Q(name__icontains=value)
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


def _route_reasons(sub, v):
    """What the host's live routes say it runs that holds ``v``: Server and X-Powered-By headers, fingerprints, cookie names."""
    from cveFeed.models import RouteAuth
    out = []
    rows = RouteAuth.objects.filter(project_id=sub.target_domain.project_id, host=sub.name, retired_at__isnull=True)[:20]
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


def _archive_reasons(sub, v):
    """Technologies the web archive says the host ran at some point that hold ``v``. Historical, so labelled as such."""
    from cveFeed.models import HostArchive
    row = HostArchive.objects.filter(project_id=sub.target_domain.project_id, host=sub.name).first()
    return [f'seen in web archive: {name} ({info.get("count", 0)} URLs)' for name, info in (row.technologies if row else {}).items()
            if v in name.lower()]


def _why_matched(sub, terms):
    """What each positive term matched on this host, for the results list (read from the page's prefetched rows)."""
    from startScan.models import open_ports
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
        if field in (None, 'tech'):
            reasons += [f'technology {t.name}' for t in sub.technologies.all() if has(t.name)]
            if has(sub.webserver):
                reasons.append(f'web server {sub.webserver}')
            reasons += _route_reasons(sub, v)
            reasons += _archive_reasons(sub, v)
        for ip in sub.ip_addresses.all():
            if field in (None, 'os') and has(ip.os_guess):
                reasons.append(f'OS {ip.os_guess}')
            if field == 'country' and ip.geo_iso and (has(ip.geo_iso.iso) or has(ip.geo_iso.name)):
                reasons.append(f'country {ip.geo_iso.name or ip.geo_iso.iso}')
            for p in open_ports(ip):
                label = f'port {p.number} {" ".join(x for x in (p.product, p.version) if x) or p.service_name or ""}'.strip()
                if field == 'port' and str(p.number) == value:
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
        if field == 'zombie' and v == 'yes':
            reasons.append('zombie: DNS gone, still answering')
    return list(dict.fromkeys(reasons))[:8]


HEAT_FACET_VALUES = ('fire', 'smoke', 'ice', 'clean', 'unscanned')
HEAT_FACET_CAP = 5000  # hosts a facet count (and a ?heat= filter) will walk before reporting the rest truncated; a search
# this wide needs narrowing with q anyway, and a plain heat chip's own count stays an honest lower bound, never wrong upward


def _heat_facets(project, qs):
    """``({fire,smoke,ice,clean,unscanned: count}, {sub.id: heat}, truncated)`` for every host ``qs`` matches, up to
    HEAT_FACET_CAP, computed with the same group-merge logic _host() itself uses (so a chip's count and a host's own
    badge never disagree). ``truncated`` means more than the cap matched q; the count is then a lower bound."""
    total = qs.count()
    subs = list(qs.select_related('target_domain').prefetch_related(
        'ip_addresses__ports', 'cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set', 'vulnerability_set__triage',
    ).order_by('id')[:HEAT_FACET_CAP])
    others = _name_siblings(project, subs)
    counts = {v: 0 for v in HEAT_FACET_VALUES}
    heat_by_id = {}
    for sub in subs:
        sibs = others.get(sub.id, [])
        _, reasons, _, _ = _merge_group(sub, sibs)
        heat = _host_heat_merged(sub, sibs, reasons)
        counts[heat] = counts.get(heat, 0) + 1
        heat_by_id[sub.id] = heat
    return counts, heat_by_id, total > HEAT_FACET_CAP


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


def search_hosts(ctx, slug, params):
    """Shodan-style host search. ``q`` is a space-separated list of ANDed terms: a bare word matches hostname, IP, technology,
    port product / service / version / CPE / banner, Server and X-Powered-By headers, cookie names, OS, finding name, CVE id and
    page title; ``tech:`` (everything a host runs, from any of that), ``banner:`` (service banners and NSE output), ``port:``, ``product:``,
    ``service:``, ``os:``, ``cve:``, ``ip:`` (an address or CIDR), ``host:``, ``vuln:``, ``sev:`` and ``auth:`` (open, login,
    session_required, sso ...) and ``sensitive:`` (any, credentials, pii, internal), ``zombie:`` (yes, no) and ``country:`` (ISO code
    or name) filter one field; a filter value takes a comma-separated list for OR (``port:80,443``), unless quoted; ``-term``
    negates; quote a phrase. ``heat`` (fire|smoke|ice|clean|unscanned) narrows the page to that heat; ``facets.heat`` in the response
    always counts every value over the whole match of q, ignoring ``heat`` itself, so the chips keep their real totals while one is
    selected. ``facets`` (comma-separated, among port|product|tech|os|country) adds the same whole-match counting for those fields,
    each up to ``facet_size`` values (default 10, max 50), highest count first. Each result says what matched. No ``q`` lists every
    host. Highest score first; ``sort=name`` for names."""
    from django.db.models import Q

    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    project, _ = get_project(ctx, slug)
    heat = params.get('heat') or ''
    if heat and heat not in HEAT_FACET_VALUES:
        raise ApiError(400, f'heat must be one of {", ".join(HEAT_FACET_VALUES)}')
    facet_names = [f.strip() for f in (params.get('facets') or '').split(',') if f.strip()]
    bad_facets = [f for f in facet_names if f not in SEARCH_FACET_FIELDS]
    if bad_facets:
        raise ApiError(400, f'facets must be among {", ".join(SEARCH_FACET_FIELDS)}: unknown {", ".join(bad_facets)}')
    try:
        facet_size = min(SEARCH_FACET_SIZE_MAX, max(1, int(params.get('facet_size', SEARCH_FACET_SIZE_DEFAULT))))
    except (TypeError, ValueError):
        raise ApiError(400, 'facet_size must be an integer')
    terms = parse_search(params.get('q'))
    qs = _scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
    for neg, field, value, quoted in terms:
        if field and not quoted and ',' in value:
            q = Q()
            for part in (p.strip() for p in value.split(',') if p.strip()):
                q |= _term_filter(field, part, project)
        else:
            q = _term_filter(field, value, project)
        qs = qs.exclude(q) if neg else qs.filter(q)
    qs = _one_per_host(qs, per_project=_is_all(project))
    heat_counts, heat_by_id, heat_truncated = _heat_facets(project, qs)
    search_facets = _search_facets(heat_by_id.keys(), facet_names, facet_size) if facet_names else {}
    if heat:
        qs = qs.filter(id__in=[i for i, h in heat_by_id.items() if h == heat])
    qs = qs.select_related('target_domain__project' if _is_all(project) else 'target_domain').prefetch_related(
        'ip_addresses__ports', 'cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set', 'vulnerability_set__triage', 'technologies').order_by(*_host_order(params))
    page = _mark_zombies(project, _hosts_page(project, qs, params, lambda sub: {'matched': _why_matched(sub, terms)}))
    page['facets'] = {'heat': heat_counts, 'truncated': heat_truncated, **search_facets}
    return page


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
            'assignee': _user_brief(v.assignee), 'comment_count': v.comment_count,
            'first_seen': _iso(_seen(v, 'first_seen', v.discovered_date)), 'last_seen': _iso(_seen(v, 'last_seen', v.discovered_date)),
            'triage': _triage_brief(_triage_of(v))}


def list_vulnerabilities(ctx, slug, params):
    from startScan.models import Vulnerability
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(Vulnerability.objects.all(), project, 'target_domain__project').select_related('subdomain', 'triage__verdict', 'remediation_by', 'assignee') \
        .prefetch_related('cve_ids', _matches_of_host()).annotate(comment_count=_comment_count_annotation('vulnerability')).order_by('-severity', '-id')
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
    if params.get('expiring_within', '').isdigit():
        from cveFeed.counts import expiring_certificates
        qs = expiring_certificates(qs, int(params['expiring_within']))
    if params.get('q'):
        qs = qs.filter(host__icontains=params['q'])
    return paginate(qs, params, _tagged(_cert, lambda c: c.domain.project) if everywhere else _cert)


def _hygiene(f):
    return {'id': f.id, 'host': f.host, 'check': f.check_name, 'severity': SEVERITY_NAMES.get(f.severity, str(f.severity)),
            'title': f.title, 'detail': f.detail, 'evidence': f.evidence, 'status': f.status,
            'remediation_status': f.remediation_status, 'remediation_note': f.remediation_note,
            'remediation_updated': _iso(f.remediation_updated_at),
            'status_changed_at': _iso(f.remediation_updated_at), 'status_changed_by': _user_brief(f.remediation_by),
            'assignee': _user_brief(f.assignee), 'comment_count': f.comment_count,
            'first_seen': _iso(f.first_seen), 'last_seen': _iso(f.last_seen), 'domain': f.domain.name,
            'triage': _triage_brief(_triage_of(f))}


def list_hygiene(ctx, slug, params):
    """TLS, certificate and email-authentication (SPF, DKIM, DMARC, CAA) findings."""
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
        qs = qs.filter(check_name__startswith=params['check'])  # e.g. spf, dmarc, dkim, tls
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
    except (TypeError, ValueError):
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
    """Web routes and how they answer an anonymous GET: open, login, session_required, sso, redirect, not_found, error."""
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
    themselves. Readable by anyone who can see the project; only a write-role may change them."""
    from cveFeed.api_credentials import SERVICES, credential_summary, used_in_scans
    from dashboard.models import ApiCredential
    project, role = get_one_project(ctx, slug)  # secrets belong to one project
    org_rows = {c.service: c for c in ApiCredential.objects.filter(org_id=project.org_id)} if project.org_id else {}
    project_rows = {c.service: c for c in ApiCredential.objects.filter(project=project)}
    results = []
    for service, (label, fields, _) in SERVICES.items():
        cred = project_rows.get(service) or org_rows.get(service)
        results.append({
            'service': service, 'label': label, 'fields': [{'name': n, 'label': d, 'secret': s} for n, d, s in fields],
            'configured': bool(cred), 'scope': ('project' if service in project_rows else 'org' if cred else None),
            'used_in_scans': used_in_scans(service),
            'set': credential_summary(cred) if cred else {},
        })
    return {'results': results, 'can_edit': role != roles.AUDIT}


def set_api_credential(ctx, slug, service, values):
    """Save a project's own key for ``service``. A blank field keeps whatever was stored for that field."""
    from cveFeed.api_credentials import SERVICES
    from dashboard.models import ApiCredential
    project, _ = get_project(ctx, slug, write=True)
    if service not in SERVICES:
        raise ApiError(404, f'unknown service {service!r}')
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
    project, _ = get_project(ctx, slug, write=True)
    removed, _ = ApiCredential.objects.filter(project=project, service=service).delete()
    if removed:
        from cveFeed.admin_api import audit
        audit(ctx.user, 'project.api_key.remove', f'{project.slug}:{service}', org=project.org_id)
    return {'deleted': True}


# --- CVEs, matches and remediation ---------------------------------------------

def _cve_description(c, limit=500):
    """Use the feed's human prose, falling back to its title; never fill a gap with a guessed vulnerability."""
    text = (c.summary or c.original_description or c.title or '').strip()
    return text[:limit].rsplit(' ', 1)[0] + '…' if len(text) > limit and ' ' in text[:limit] else text[:limit]


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
    affected = []
    for item in (c.affected if isinstance(c.affected, list) else [])[:30]:
        if isinstance(item, dict):
            part = {k: item.get(k) for k in ('vendor', 'product', 'package') if isinstance(item.get(k), str) and item.get(k)}
            part['ranges'] = [{k: v for k, v in rng.items() if isinstance(v, (str, int, float))}
                              for rng in (item.get('ranges') if isinstance(item.get('ranges'), list) else [])[:20]
                              if isinstance(rng, dict)]
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
           'exploit_db': c.exploit_db, 'published': _iso(c.published_at)}
    if not brief:
        out.update(_cve_context(c))
    return out


def _require_member(ctx):
    if not roles.user_best_role(ctx.user):
        raise ApiError(403, 'no organization or project access')


def list_cve_feed(ctx, params):
    from cveFeed.models import CVEEntry
    from cveFeed.threat import classify_threat_tier
    _require_member(ctx)
    qs = CVEEntry.objects.order_by('-published_at', '-id')
    if params.get('q'):
        qs = qs.filter(cve_id__icontains=params['q'])
    wanted = params.get('tier')
    if wanted:  # tier is derived, so filter in Python over a bounded window
        window = [c for c in qs[:2000] if classify_threat_tier(
            kev=c.kev, epss_reached=c.epss_reached, exploit_db=c.exploit_db, cvss=c.cvss) == wanted]
        size = min(PAGE_SIZE_MAX, int(params.get('page_size', PAGE_SIZE_DEFAULT)))
        return {'count': len(window), 'page': 1, 'page_size': size, 'results': [_cve(c, True) for c in window[:size]]}
    return paginate(qs, params, lambda c: _cve(c, brief=True))


def get_cve(ctx, cve_id):
    from cveFeed.models import CVEEntry
    _require_member(ctx)
    c = CVEEntry.objects.filter(cve_id=cve_id.upper()).first()
    if not c:
        raise ApiError(404, 'CVE not found')
    return _cve(c)


def _match(m):
    from cveFeed.distro import label_for
    from cveFeed.threat import match_temperature
    sub = m.subdomain
    cve = _cve(m.cve_entry, brief=True)
    cve['feed_tier'] = cve['tier']
    cve['tier'] = match_temperature(cve['tier'], m.cve_entry.cvss, m.ai_verdict, m.distro_status)  # rated as it applies to this host
    return {'id': m.id, 'cve': cve, 'host': sub.name if sub else None,
            'product': m.matched_product, 'version': m.matched_version, 'in_affected_range': m.version_in_range,
            'confidence': m.confidence, 'source': m.source, 'ai_verdict': m.ai_verdict, 'ai_reason': m.ai_reason,
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
            'assignee': _user_brief(m.assignee), 'comment_count': m.comment_count,
            'first_seen': _iso(_seen(m, 'first_seen', m.created_at)), 'last_seen': _iso(_seen(m, 'last_seen', m.updated_at)),
            'triage': _triage_brief(_triage_of(m))}


def _matches_qs(project):
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    qs = _scoped(CVEMatch.objects.all(), project, 'subdomain__target_domain__project').filter(latest_scan_q('subdomain__')) \
        .select_related('cve_entry', 'subdomain', 'triage__verdict', 'remediation_by', 'assignee') \
        .annotate(comment_count=_comment_count_annotation('match')).order_by('-confidence', '-id')
    return qs.select_related('subdomain__target_domain__project') if _is_all(project) else qs


def list_matches(ctx, slug, params):
    project, _ = get_project(ctx, slug)
    qs = _matches_qs(project)
    if params.get('status'):
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
    return paginate(qs, params, _tagged(_match, lambda m: m.subdomain.target_domain.project) if _is_all(project) else _match)


# --- the unified Findings list: CVE matches, scanner findings and hygiene findings as one population ------------------

FINDING_TYPES = {'cve': 'match', 'scanner': 'vulnerability', 'hygiene': 'hygiene'}  # facet -> the finding-detail kind
HEAT_FACETS = {'fire': 3, 'smoke': 2, 'ice': 1}
MAX_FINDINGS = 2000  # rows the merged list can page through; the counts stay exact beyond it


def _finding_sources(project, params):
    """The querysets the facets allow, keyed by type, each annotated with ``heat_rank`` (3 fire, 2 smoke, 1 ice, 0 none: the
    host card's rules, threat.match_temperature and SEVERITY_HEAT) and ``sev`` (0 info .. 4 critical; a CVE by its CVSS band,
    an unscored one as low), and filtered by heat, severity, status and host.

    "Actionable" (the default) is what heats a host on its card: a CVE match the AI did not rule out, an open scanner finding
    above info, an open hygiene finding above info. ``status=all`` adds the rest (informational, closed, ruled out)."""
    from django.db.models import Case, F, IntegerField, Value, When

    from cveFeed.models import HygieneFinding
    from cveFeed.threat import CRITICAL_CVSS, HIGH_CVSS, match_heat_rank_expr, severity_heat_rank_expr
    from startScan.models import Vulnerability
    wanted = params.get('type') or 'all'
    if wanted != 'all' and wanted not in FINDING_TYPES:
        raise ApiError(400, f'type must be all or one of {", ".join(FINDING_TYPES)}')
    status = params.get('status') or 'actionable'
    if status not in ('actionable', 'all'):
        raise ApiError(400, 'status must be actionable or all')
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
        if status == 'actionable':
            qs = qs.exclude(ai_verdict='not_affected').exclude(remediation_status__in=('fixed', 'accepted_risk'))
        if params.get('host'):
            qs = qs.filter(subdomain__name__icontains=params['host'])
        sources['cve'] = qs
    if wanted in ('all', 'scanner'):
        qs = _scoped(Vulnerability.objects.all(), project, 'target_domain__project') \
            .select_related('subdomain', 'triage__verdict', 'remediation_by', 'assignee', *(['target_domain__project'] if everywhere else [])) \
            .annotate(heat_rank=severity_heat_rank_expr(), sev=F('severity'), when=F('discovered_date'),
                      comment_count=_comment_count_annotation('vulnerability'))
        if status == 'actionable':
            qs = qs.filter(open_status=True, severity__gte=1).exclude(remediation_status__in=('fixed', 'accepted_risk'))
        if params.get('host'):
            qs = qs.filter(subdomain__name__icontains=params['host'])
        sources['scanner'] = qs
    if wanted in ('all', 'hygiene'):
        qs = _scoped(HygieneFinding.objects.all(), project, 'domain__project') \
            .select_related('domain__project' if everywhere else 'domain', 'triage__verdict', 'remediation_by', 'assignee') \
            .annotate(heat_rank=severity_heat_rank_expr(), sev=F('severity'), when=F('first_seen'),
                      comment_count=_comment_count_annotation('hygiene'))
        if status == 'actionable':
            qs = qs.filter(status='open', severity__gte=1).exclude(remediation_status__in=('fixed', 'accepted_risk'))
        if params.get('host'):
            qs = qs.filter(host__icontains=params['host'])
        sources['hygiene'] = qs
    for key, qs in sources.items():
        if heat != 'all':
            qs = qs.filter(heat_rank=HEAT_FACETS[heat])
        if severity != 'all':
            qs = qs.filter(sev=inverse[severity])
        sources[key] = qs.order_by('-heat_rank', '-sev', F('when').desc(nulls_last=True), '-id')
    return sources


def _finding_row(kind, obj):
    """One row of the unified list: enough for the list card and the badges; the detail comes from finding_detail."""
    from cveFeed.threat import HEAT_RANK
    heat = {rank: name for name, rank in HEAT_RANK.items()}.get(obj.heat_rank, '')
    if kind == 'cve':
        cve, sub = obj.cve_entry, obj.subdomain
        title, host = cve.cve_id, sub.name if sub else None
        note = ' '.join(filter(None, [obj.matched_product, obj.matched_version])) or ''
        status = 'ruled out' if obj.ai_verdict == 'not_affected' else obj.remediation_status
        extra = {'cvss': cve.cvss, 'description': _cve_description(cve, 160)}
    elif kind == 'scanner':
        title, host, note = obj.name, obj.subdomain.name if obj.subdomain else None, obj.source or ''
        status, extra = ('closed' if not obj.open_status else obj.remediation_status), {}
    else:
        title, host, note = obj.title, obj.host, obj.check_name
        status, extra = ('resolved' if obj.status == 'resolved' else obj.remediation_status), {}
    return {'type': kind, 'kind': FINDING_TYPES[kind], 'id': obj.id, 'title': title, 'host': host, 'note': note,
            'heat': heat, 'severity': SEVERITY_NAMES.get(obj.sev, str(obj.sev)), 'status': status,
            'remediation_note': getattr(obj, 'remediation_note', ''),
            'status_changed_at': _iso(getattr(obj, 'remediation_updated_at', None)),
            'status_changed_by': _user_brief(getattr(obj, 'remediation_by', None)),
            'assignee': _user_brief(getattr(obj, 'assignee', None)), 'comment_count': getattr(obj, 'comment_count', 0),
            'detected': _iso(obj.when), 'first_seen': _iso(obj.when), 'triage': _triage_brief(_triage_of(obj)), **extra}


def _finding_project(kind, obj):
    return {'cve': lambda o: o.subdomain.target_domain.project, 'scanner': lambda o: o.target_domain.project,
            'hygiene': lambda o: o.domain.project}[kind](obj)


def list_findings(ctx, slug, params):
    """Every finding of the project in one list, hottest first: CVE matches, scanner findings and hygiene findings. Facets:
    type (all|cve|scanner|hygiene), heat (all|fire|smoke|ice), severity (all|critical|high|medium|low|info), status
    (actionable, the default, or all) and host. ``counts`` holds the total of each type under the same facets; the list itself
    pages through at most MAX_FINDINGS rows (``truncated`` says when there are more)."""
    project, _ = get_project(ctx, slug)
    try:
        page = max(1, int(params.get('page', 1)))
        size = min(PAGE_SIZE_MAX, max(1, int(params.get('page_size', PAGE_SIZE_DEFAULT))))
    except (TypeError, ValueError):
        raise ApiError(400, 'page and page_size must be integers')
    sources = _finding_sources(project, params)
    counts = {key: qs.count() for key, qs in sources.items()}
    total = sum(counts.values())
    start, stop = (page - 1) * size, min(page * size, MAX_FINDINGS)
    merged = []
    for key, qs in sources.items():  # the top ``stop`` of each source holds the top ``stop`` of the merged order
        merged += [(key, obj) for obj in (qs[:stop] if stop > start else [])]
    epoch = timezone.now().replace(year=1970)
    merged.sort(key=lambda pair: (pair[1].heat_rank, pair[1].sev, pair[1].when or epoch, pair[1].id), reverse=True)
    everywhere = _is_all(project)
    results = []
    for key, obj in merged[start:stop]:
        row = _finding_row(key, obj)
        if everywhere:
            owner = _finding_project(key, obj)
            row['project'], row['project_name'] = (owner.slug, owner.name) if owner else (None, None)
        results.append(row)
    return {'count': min(total, MAX_FINDINGS), 'total': total, 'truncated': total > MAX_FINDINGS, 'page': page,
            'page_size': size, 'counts': {key: counts.get(key, 0) for key in FINDING_TYPES}, 'results': results}


def _apply_remediation(obj, status, note, user):
    """Set and save the remediation fields shared by CVEMatch, Vulnerability and HygieneFinding (the same tuple of
    statuses, enforced here once). ``note`` is a true PATCH field: ``None`` (the default, meaning the caller's body left
    it out) leaves whatever note is already stored; an explicit value, including '', replaces it. Raises on an
    unrecognized status; never touches whatever auto-managed liveness field (open_status, HygieneFinding.status,
    ai_verdict) the model also carries, which stays under the scan/check pipeline."""
    from cveFeed.models import CVEMatch
    if status not in CVEMatch.REMEDIATION_STATUSES:
        raise ApiError(400, f'status must be one of {", ".join(CVEMatch.REMEDIATION_STATUSES)}')
    fields = ['remediation_status', 'remediation_updated_at', 'remediation_by']
    obj.remediation_status, obj.remediation_updated_at, obj.remediation_by = status, timezone.now(), user
    if note is not None:
        obj.remediation_note = note[:2000]
        fields.append('remediation_note')
    obj.save(update_fields=fields)


UNSET = object()  # a PATCH field the caller's body left out entirely, as opposed to an explicit null/empty value


def _record_status_change(project, kind, finding_id, before, after, actor):
    from cveFeed.models import FindingAuditEvent
    FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=finding_id, event='status',
                                      actor=actor, before={'status': before}, after={'status': after})


def _apply_assignee(project, kind, obj, assignee, actor):
    """Set or clear ``obj.assignee`` (a user id, or None/''/0 to unassign) and write the audit event. The new assignee
    must be someone who can already see this project (the same check PATCH .../profile and everywhere else that names
    a user by id uses); an id naming nobody, or nobody with access, is a 400."""
    from django.contrib.auth.models import User

    from cveFeed.models import FindingAuditEvent
    before = _user_brief(obj.assignee)
    if assignee in (None, '', 0, '0'):
        new_user = None
    else:
        try:
            new_user = User.objects.get(pk=int(assignee))
        except (TypeError, ValueError, User.DoesNotExist):
            raise ApiError(400, 'assignee must be the id of a user who can see this project, or null')
        if not roles.effective_role(new_user, project):
            raise ApiError(400, 'assignee must be the id of a user who can see this project, or null')
    obj.assignee = new_user
    obj.save(update_fields=['assignee'])
    FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=obj.pk, event='assignee', actor=actor,
                                      before={'assignee': before}, after={'assignee': _user_brief(new_user)})


def update_match(ctx, slug, match_id, status=None, note=None, assignee=UNSET):
    """At least one of ``status``/``assignee`` is required; either can be sent alone, the same true-partial-update
    semantics ``note`` already has. A status change and an assignee change are logged as separate audit events even
    when sent in the same call, since they are independent facts a reader may want separately."""
    from cveFeed import activity
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before body validation
    if status is None and assignee is UNSET:
        raise ApiError(400, 'missing field(s): status or assignee')
    m = _matches_qs(project).filter(id=match_id).first()
    if not m:
        raise ApiError(404, 'match not found')
    if status is not None:
        before = m.remediation_status
        _apply_remediation(m, status, note, ctx.user)
        _record_status_change(project, 'match', m.id, before, status, ctx.user)
        activity.log('remediation', f'{m.cve_entry.cve_id} on {m.subdomain.name if m.subdomain else "?"} marked {status}',
                     project=project, finding_kind='match', finding_id=m.id)
    if assignee is not UNSET:
        _apply_assignee(project, 'match', m, assignee, ctx.user)
    return _match(m)


STATUS_KINDS = ('match', 'vulnerability', 'hygiene')  # finding kinds with a remediation workflow; a web route has none
MAX_BULK_STATUS = 200


def update_finding_status(ctx, slug, kind, finding_id, status=None, note=None, assignee=UNSET):
    """Set the remediation status (open/in_progress/fixed/accepted_risk), note and/or assignee of one finding: a CVE
    match, scanner finding or hygiene finding; at least one of status/assignee is required. Same permissions and
    project-scoped 404 as update_match, which this delegates to for kind='match' so the two routes agree exactly. A
    web route has no remediation workflow (its auth_state already says what it needs), so 'route' 400s here the same
    as any other unrecognized kind."""
    from cveFeed import activity
    if kind == 'match':
        return update_match(ctx, slug, finding_id, status, note=note, assignee=assignee)
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before kind/status validation
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    if status is None and assignee is UNSET:
        raise ApiError(400, 'missing field(s): status or assignee')
    obj = _finding_obj(project, kind, finding_id)
    if status is not None:
        before = obj.remediation_status
        _apply_remediation(obj, status, note, ctx.user)
        _record_status_change(project, kind, finding_id, before, status, ctx.user)
        activity.log('remediation', f'{kind} finding #{finding_id} marked {status}', project=project,
                     finding_kind=kind, finding_id=finding_id)
    if assignee is not UNSET:
        _apply_assignee(project, kind, obj, assignee, ctx.user)
    return _vuln(obj) if kind == 'vulnerability' else _hygiene(obj)


def bulk_update_finding_status(ctx, slug, items, status, note=None):
    """Set the same remediation status and note on up to MAX_BULK_STATUS findings at once. Each item is independent
    (one bad kind or id never blocks the rest, and a finding belonging to another project 404s exactly like a missing
    one); returns {updated, failed: [{kind, id, error}]} so the caller can report partial failures."""
    from cveFeed import activity
    from cveFeed.models import CVEMatch
    project, _ = get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before any body validation
    if status not in CVEMatch.REMEDIATION_STATUSES:
        raise ApiError(400, f'status must be one of {", ".join(CVEMatch.REMEDIATION_STATUSES)}')
    if not isinstance(items, list) or not items:
        raise ApiError(400, 'items must be a non-empty list')
    if len(items) > MAX_BULK_STATUS:
        raise ApiError(400, f'at most {MAX_BULK_STATUS} items per call')
    updated, failed = 0, []
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
            _apply_remediation(obj, status, note, ctx.user)
            _record_status_change(project, kind, finding_id, before, status, ctx.user)
            updated += 1
        except ApiError as e:
            failed.append({'kind': kind, 'id': finding_id, 'error': e.message})
        except Exception as e:  # noqa: BLE001 - one bad row must never fail the rest of the batch
            failed.append({'kind': kind, 'id': finding_id, 'error': str(e)})
    activity.log('remediation', f'bulk marked {updated} finding(s) {status}', project=project, count=updated, failed=len(failed))
    return {'updated': updated, 'failed': failed}


def asset_matches(host_names, ips, patterns):
    """Whether a host (name and IPs) falls under any registered asset: name, parent domain, IP or CIDR."""
    for pattern in patterns:
        p = pattern.strip().lower()
        if not p:
            continue
        for name in host_names:
            if name == p or name.endswith('.' + p):
                return True
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        for ip in ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    return True
            except ValueError:
                continue
    return False


def register_assets(ctx, assets):
    """An agent registers the hosts/IPs/CIDRs it is responsible for; /work then defaults to them."""
    if not ctx.token:
        raise ApiError(400, 'assets are registered on an API token; call this with a token')
    if not isinstance(assets, list) or not all(isinstance(a, str) for a in assets) or len(assets) > 500:
        raise ApiError(400, 'assets must be a list of up to 500 strings')
    ctx.token.assets = [a.strip() for a in assets if a.strip()]
    ctx.token.save(update_fields=['assets'])
    return {'assets': ctx.token.assets}


def work_items(ctx, slug, params):
    """Remediation handoff: confirmed or pending CVE-on-host matches still to fix, narrowed to the
    agent's registered assets (or ?assets=a,b) and optionally to a tier."""
    from cveFeed.models import CVEMatch
    project, _ = get_one_project(ctx, slug)
    patterns = [a for a in (params.get('assets') or '').split(',') if a.strip()] or \
        (ctx.token.assets if ctx.token else [])
    # Closed asset correlations do not belong in remediation work. An unresolved candidate with a low-confidence
    # triage classification remains reviewable unless the caller requests ?include_fp=0.
    from django.db.models import Q
    qs = _matches_qs(project).exclude(ai_verdict='not_affected') \
        .exclude(version_in_range=False) \
        .exclude(remediation_status__in=('fixed', 'accepted_risk')) \
        .prefetch_related('subdomain__ip_addresses')
    if params.get('include_fp') == '0':
        qs = qs.exclude(triage__classification__in=FALSE_POSITIVES)
    items = []
    for m in qs[:2000]:
        sub = m.subdomain
        ips = [ip.address for ip in sub.ip_addresses.all()] if sub else []
        if patterns and not asset_matches([sub.name.lower()] if sub else [], ips, patterns):
            continue
        item = _match(m)
        if params.get('tier') and item['cve']['tier'] != params['tier']:
            continue
        item['ips'] = ips
        item['host_score'] = sub.score if sub else 0
        item['fixed_in'] = _fixed_versions(m.cve_entry, m.matched_product)
        items.append(item)
    order = {'fire': 0, 'smoke': 1, 'ice': 2}
    items.sort(key=lambda i: (i['triage']['classification'] in FALSE_POSITIVES, order.get(i['cve']['tier'], 3), -(i['cve']['cvss'] or 0),
                              -i['host_score']))  # likely false positives last; the host score breaks ties
    size = min(PAGE_SIZE_MAX, int(params.get('page_size', PAGE_SIZE_DEFAULT)))
    return {'count': len(items), 'registered_assets': patterns, 'results': items[:size]}


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


def _seen(obj, name, fallback):
    t = _triage_of(obj)
    return getattr(t, name, None) or fallback


def _classification_of(obj):
    t = _triage_of(obj)
    return t.classification if t else ''


def _triage_brief(t):
    """What a list card needs to show the classification and validation badges without a second request."""
    if t is None:
        return {'classification': '', 'status': 'untracked', 'validation_status': 'none', 'overridden': False, 'severity_adjust': 0,
                'first_seen': None, 'last_seen': None}
    v = t.verdict
    validation_status = ('observed' if t.validation_status == 'clean' and t.validation_steps and
                         all(step.get('result') in ('observed', 'reaffirmed') for step in t.validation_steps)
                         else t.validation_status)
    return {'classification': t.classification, 'status': t.status, 'validation_status': validation_status,
            'overridden': bool(v and (v.overridden or t.classification != v.classification)),
            'severity_adjust': v.severity_adjust if v else 0,
            'first_seen': _iso(t.first_seen), 'last_seen': _iso(t.last_seen)}


def _finding_obj(project, kind, finding_id):
    """The project's finding of ``kind`` with this id, or 404: another project's id is 404 exactly like a missing one."""
    from cveFeed.models import HygieneFinding, RouteAuth
    from startScan.models import Vulnerability
    if kind not in FINDING_KINDS:
        raise ApiError(404, 'unknown finding kind')
    if kind == 'match':
        obj = _matches_qs(project).filter(pk=finding_id).first()
    elif kind == 'vulnerability':
        obj = Vulnerability.objects.filter(target_domain__project=project, pk=finding_id).select_related(
            'subdomain', 'target_domain', 'triage__verdict', 'remediation_by', 'assignee') \
            .prefetch_related('cve_ids', 'cwe_ids', 'tags').annotate(comment_count=_comment_count_annotation('vulnerability')).first()
    elif kind == 'route':
        obj = RouteAuth.objects.filter(project=project, pk=finding_id).select_related('domain', 'triage__verdict').first()
    else:
        obj = HygieneFinding.objects.filter(domain__project=project, pk=finding_id).select_related(
            'domain', 'triage__verdict', 'remediation_by', 'assignee').annotate(comment_count=_comment_count_annotation('hygiene')).first()
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
    steps = []
    found = ' '.join(x for x in (m.matched_product, m.matched_version or '(no version)') if x)
    if m.source == 'port':
        where = f'{ev.get("ip")}:{ev.get("port")}' if ev.get('ip') else ''
        steps.append(_kv('Observed', f'{found} on {where}'.strip() + (f' ({ev["service_extra"]})' if ev.get('service_extra') else '')))
        steps.append(_kv('Found by', 'nmap service detection of an open port'
                         + (f', method {ev["method"]}' + (' (guessed from the port number, not probed)' if ev['method'] == 'table' else '')
                            if ev.get('method') else '')))
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
    return {'steps': steps, 'excerpts': {}}


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
    adjust = v.severity_adjust if v else 0
    severity_ai = (SEVERITY_NAMES.get(triage_lib.adjusted_severity(base, adjust, bool(t and t.hard_evidence)))
                   if base is not None and adjust else None)
    remediation = {'text': v.remediation if v else '', 'scanner': getattr(obj, 'remediation', '') if kind == 'vulnerability' else ''}
    if kind == 'match':
        remediation.update(fixed_in=_fixed_versions(obj.cve_entry, obj.matched_product), local_checks=(t.local_checks if t else None) or None)
    if kind in STATUS_KINDS:  # match, vulnerability, hygiene: a web route has no remediation workflow
        remediation.update(status=obj.remediation_status, note=obj.remediation_note)
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
    return {
        'kind': kind, 'id': obj.pk, 'title': title, 'host': host, 'target': target,
        'assessment_status': assessment_status,
        'assessment_reason': obj.ai_reason if assessment_status == 'closed_not_applicable' else '',
        'automatic_validation': automatic,
        'severity': SEVERITY_NAMES.get(base) if base is not None else None, 'severity_ai': severity_ai,
        'first_seen': _iso(first), 'last_seen': _iso(last), 'history': _history(project, host),
        'why_it_matters': v.impact if v else '',
        'ai': {'classification': t.classification if t else '', 'status': t.status if t else 'untracked',
               'reason': f'AI review failed ({diagnostic["category"]}); retry scheduled.' if diagnostic else t.reason if t else '',
               'diagnostic': diagnostic,
               'overridden': bool(v and (v.overridden or (t and t.classification != v.classification))),
               'model_classification': v.model_classification if v else '',
               'model_reason': v.model_reason if v else '', 'model': v.model if v else '', 'invalid_output': bool(v and v.invalid_output),
               'triaged': _iso(v.created_at) if v else None, 'severity_adjust': adjust, 'severity_reason': v.severity_reason if v else '',
               'hard_evidence': (t.hard_evidence if t else []) or [], 'advice': (v.validation_notes if v else []) or []},
        'how_found': how, 'remediation': remediation,
        'status_changed_at': _iso(obj.remediation_updated_at) if kind in STATUS_KINDS else None,
        'status_changed_by': _user_brief(obj.remediation_by) if kind in STATUS_KINDS else None,
        'assignee': _user_brief(obj.assignee) if kind in STATUS_KINDS else None,
        'comment_count': obj.comment_count if kind in STATUS_KINDS else 0,
        'cve': _cve_context(obj.cve_entry) if kind == 'match' else None,
        'validation': {'status': _triage_brief(t)['validation_status'] if t else 'none', 'steps': steps, 'evidence': evidence,
                       'validated': _iso(t.validated_at) if t else None, 'next_attempt': _iso(t.next_attempt_at) if t else None,
                       'confidence_adjust': t.confidence_adjust if t else 0.0},
    }


MAX_COMMENT_LENGTH = 4000


def _comment(c):
    return {'id': c.id, 'text': c.text, 'author': _user_brief(c.author), 'created': _iso(c.created_at)}


def list_finding_comments(ctx, slug, kind, finding_id):
    """Every comment on one finding, oldest first."""
    from cveFeed.models import FindingComment
    project, _ = get_one_project(ctx, slug)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    _finding_obj(project, kind, finding_id)  # 404 for an unknown finding, or one in another project
    rows = FindingComment.objects.filter(project=project, finding_kind=kind, finding_id=finding_id).select_related('author')
    return {'results': [_comment(c) for c in rows]}


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


def finding_audit(ctx, slug, kind, finding_id):
    """One finding's audit trail, newest first: status changes, assignee changes, and comments, each with who, when,
    and (status/assignee) what changed from and to. A comment's own text is also in GET .../comments; it is repeated
    here as a short before/after so the trail reads as one timeline without a second request."""
    from cveFeed.models import FindingAuditEvent
    project, _ = get_one_project(ctx, slug)
    if kind not in STATUS_KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(STATUS_KINDS)}')
    _finding_obj(project, kind, finding_id)
    rows = FindingAuditEvent.objects.filter(project=project, finding_kind=kind, finding_id=finding_id).select_related('actor')
    return {'results': [_audit_event(e) for e in rows]}


def list_members(ctx, slug):
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
    return {'results': [_user_brief(u) for u in users]}


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
