"""Host inventory over the agent API: the ingest endpoint reporter scripts post to, and the reads and admin steps around it.

``post_report`` is the only thing an ``inventory`` token (agentapi.auth) can reach. It cleans the report with
``cveFeed.inventory_schema``, stores it with ``cveFeed.host_inventory`` and queues the CVE side for a worker. The rest are ordinary
project-scoped calls: list and read the reports, adopt an unmatched one, remove one, and mint a reporter token.
"""
import hashlib
import ipaddress
import json
import logging
import socket
from datetime import timedelta

from django.core.exceptions import RequestDataTooBig
from django.utils import timezone

from agentapi import auth
from agentapi.services import ApiError, get_one_project, paginate
from cveFeed import host_inventory as store, inventory_schema as schema
from reNgine.client_ip import client_ip
from tenancy import throttle

logger = logging.getLogger(__name__)

RATE_WINDOW = 3600
MAX_TOKEN_NAME = 100
TOKEN_DAYS = 365  # a reporter token expires after this long; mint a new one to renew it
MAX_CREATED_PER_DAY = 20  # hosts a project's reports may add as targets in a day


def read_body(request):
    """The decoded JSON of a report, or an ApiError: a body over the limit is 413 before it is parsed, and one that is not a JSON
    object is 400."""
    try:
        if int(request.META.get('CONTENT_LENGTH') or 0) > schema.MAX_BODY_BYTES:
            raise ApiError(413, f'the report is larger than {schema.MAX_BODY_BYTES // 1024} KiB')
    except ValueError:
        raise ApiError(400, 'bad Content-Length')
    try:
        body = request.body
    except RequestDataTooBig:
        raise ApiError(413, f'the report is larger than {schema.MAX_BODY_BYTES // 1024} KiB')
    if len(body) > schema.MAX_BODY_BYTES:
        raise ApiError(413, f'the report is larger than {schema.MAX_BODY_BYTES // 1024} KiB')
    try:
        return json.loads(body or b'{}')
    except (ValueError, RecursionError):
        raise ApiError(400, 'the report must be valid JSON')


def _check_token(ctx, project):
    """A reporter token may only post to its own project (the middleware already says so; this is the same rule where the data is)."""
    token = ctx.token
    if token and token.scope == auth.SCOPE_INVENTORY and token.project_id != project.id:
        raise ApiError(403, 'this token can only post inventory reports to its own project')


def _count(key, limit, message):
    if throttle.exceeded(key, limit):
        raise ApiError(429, message)
    throttle.count(key, RATE_WINDOW)


def _who(ctx):
    return ctx.token.pk if ctx.token else f'u{ctx.user.pk}'


def _rate_limit(ctx, project):
    """The coarse limits, before the body is read: one token's reports over all its machines, and the project's over all tokens."""
    _count(f'inventory-rate-token:{_who(ctx)}', store.TOKEN_REPORTS_PER_HOUR, f'at most {store.TOKEN_REPORTS_PER_HOUR} reports an hour per token')
    _count(f'inventory-rate-project:{project.pk}', store.PROJECT_REPORTS_PER_HOUR, f'at most {store.PROJECT_REPORTS_PER_HOUR} reports an hour per project')


def _rate_limit_machine(ctx, report):
    """One machine through one token: a fleet sharing a token is not slowed down by its size, a machine in a loop is."""
    machine = hashlib.sha256(schema.machine_key(report['host']).encode()).hexdigest()[:20]
    _count(f'inventory-rate:{_who(ctx)}:{machine}', store.REPORTS_PER_HOUR,
           f'at most {store.REPORTS_PER_HOUR} reports an hour from one machine: send fewer, or less often')


def _queue(inv):
    """Queue the CVE side of a report. A broker problem must not lose the report, which is already stored: the next scan or report
    runs it again."""
    from cveFeed.tasks import correlate_host_inventory
    try:
        correlate_host_inventory.delay(inv.id)
    except Exception:  # noqa: BLE001
        logger.warning('could not queue the CVE correlation of inventory report %s', inv.id, exc_info=True)


def _create_host(ctx, project, inv):
    """Add the machine as a target (its FQDN, else its first address) and start discovery. A name the organization excluded, or an
    address the scanner refuses, leaves the report unmatched for an administrator."""
    from agentapi import services
    value = _target_value(inv)
    if not value:
        return False
    try:
        services.add_target(ctx, project.slug, value, description='Added from a host inventory report', discover=True)
    except ApiError as e:
        logger.info('inventory host %s not created: %s', value, e.message)
        return False
    inv.host, inv.match_basis = value.lower(), 'created'
    inv.save(update_fields=['host', 'match_basis'])
    return True


def _target_value(inv):
    return inv.fqdn if '.' in (inv.fqdn or '') else (inv.ips[0] if inv.ips else '')


def _resolves_to(name, address):
    try:
        wanted = ipaddress.ip_address(address)
        return any(ipaddress.ip_address(info[4][0].split('%')[0]) == wanted for info in socket.getaddrinfo(name, None))
    except (OSError, ValueError):
        return False


def _may_create(project, inv, source_ip):
    """Whether a report may add its machine to the project on its own. A reporter only says what it is, so a name it claims is added
    only when it is the machine's own: inside a domain the project already has, or resolving to the address the report came from (a
    machine reporting itself by address must come from that address). Otherwise a token could have the server scan any domain it names.
    A day's creations are capped."""
    from targetApp.models import Domain
    value = _target_value(inv)
    if not value or throttle.exceeded(f'inventory-create:{project.pk}', MAX_CREATED_PER_DAY):
        return False
    if '.' in (inv.fqdn or ''):
        inside = any(inv.fqdn == d or inv.fqdn.endswith('.' + d) for d in Domain.objects.filter(project=project).values_list('name', flat=True))
        return inside or _resolves_to(inv.fqdn, source_ip)
    return value == source_ip


def _audit(ctx, project, inv, outcome, created):
    from cveFeed.admin_api import audit
    audit(ctx.user, 'inventory.report', f'{inv.hostname or inv.key} in {project.slug}', project.org, project=project.slug,
          machine=inv.hostname, outcome=outcome, host=inv.host or None, match=inv.match_basis or 'unmatched',
          os=f'{inv.os_name} {inv.os_version}'.strip(), packages=inv.package_count, created_host=created, token=ctx.token.prefix if ctx.token else None)


def _audit_refusal(ctx, project, report, why):
    from cveFeed.admin_api import audit
    host = report['host']
    audit(ctx.user, 'inventory.refused', f'{host.get("fqdn") or host.get("hostname") or "a machine"} in {project.slug}', project.org,
          project=project.slug, why=why, token=ctx.token.prefix if ctx.token else None)


def post_report(ctx, slug, request):
    """Accept one host's report. 201 for a machine's first report, 200 for a later one (``outcome`` says ``new``, ``changed``: its
    operating system or the host it is tied to moved, or ``updated``). The answer says only whether the report was
    tied to a host (``matched``, ``created``, ``unmatched``) and how much was kept, never which host, so a reporter learns nothing about
    the project's other hosts."""
    project, _role = get_one_project(ctx, slug, write=True)
    _check_token(ctx, project)
    _rate_limit(ctx, project)
    try:
        report = schema.validate(read_body(request))
    except schema.InventoryError as e:
        raise ApiError(e.status, str(e))
    _rate_limit_machine(ctx, report)
    source_ip = client_ip(request)
    try:
        inv, outcome = store.ingest(project, report, token_id=ctx.token.pk if ctx.token else None, source_ip=source_ip)
    except store.ReportRefused as e:
        if e.why:
            _audit_refusal(ctx, project, report, e.why)
        raise ApiError(e.status, str(e))
    from cveFeed.models import ProjectSettings
    allowed = ProjectSettings.objects.filter(project=project, inventory_create_hosts=True).exists()
    created = bool(not inv.host and allowed and _may_create(project, inv, source_ip) and _create_host(ctx, project, inv))
    if created:
        throttle.count(f'inventory-create:{project.pk}', 86400)
    if outcome != 'updated' or created:  # a daily report that changed nothing would only bury what an administrator reads the trail for
        _audit(ctx, project, inv, outcome, created)
    if inv.host:
        _queue(inv)
    status = 'created' if created else 'matched' if inv.host else 'unmatched'
    return {'accepted': True, 'outcome': outcome, 'status': status, 'packages': inv.package_count, 'dropped': report['dropped'],
            'stale_after_days': store.stale_days(project)}, 201 if outcome == 'new' else 200


# --- reading and administering ------------------------------------------------------------------------------------------

def _qs(project):
    from cveFeed.models import HostInventory
    return HostInventory.objects.filter(project=project)


def list_inventories(ctx, slug, params):
    """The project's host reports, newest first. ``status``: ``matched``, ``unmatched`` (waiting for an administrator) or ``stale``;
    ``q`` filters by host name, FQDN or address."""
    from datetime import timedelta

    from django.db.models import Q
    from django.utils import timezone
    project, _ = get_one_project(ctx, slug)
    days = store.stale_days(project)
    qs = _qs(project).order_by('-reported_at', '-id')
    status = params.get('status') or ''
    if status not in ('', 'matched', 'unmatched', 'stale', 'fresh'):
        raise ApiError(400, 'status must be matched, unmatched, stale or fresh')
    cutoff = timezone.now() - timedelta(days=days)
    qs = {'matched': qs.exclude(host=''), 'unmatched': qs.filter(host=''), 'stale': qs.filter(reported_at__lt=cutoff),
          'fresh': qs.filter(reported_at__gte=cutoff), '': qs}[status]
    if params.get('q'):
        q = params['q'][:200]
        qs = qs.filter(Q(hostname__icontains=q) | Q(fqdn__icontains=q) | Q(host__icontains=q) | Q(ips__icontains=q))
    now = timezone.now()
    page = paginate(qs, params, lambda inv: store.brief(inv, days, now))
    page['stale_after_days'] = days
    return page


def get_inventory(ctx, slug, inventory_id=None, host=None, params=None):
    """One report in full, by id or by the host it is tied to (the newest if several are). ``q``, ``page`` and ``page_size`` page
    through its packages (the package list can be thousands of rows)."""
    project, _ = get_one_project(ctx, slug)
    qs = _qs(project)
    if inventory_id is None and not host:
        raise ApiError(400, 'give a host name or a report id')
    if inventory_id is not None:
        inv = qs.filter(pk=inventory_id).first()
    else:
        from agentapi.host_manage import clean_host
        inv = qs.filter(host=clean_host(host)).order_by('-reported_at', '-id').first()
    if inv is None:
        raise ApiError(404, 'no inventory report for that host')
    return store.detail(inv, store.stale_days(project), params or {})


def adopt(ctx, slug, inventory_id, host=None, create=False):
    """Decide what an unmatched report is: tie it to a host the project already scans (``host``), or add the machine as a target
    (``create``, which starts discovery; refused for a name the organization excluded)."""
    project, _ = get_one_project(ctx, slug, write=True)
    inv = _qs(project).filter(pk=inventory_id).first()
    if inv is None:
        raise ApiError(404, 'inventory report not found')
    if bool(host) == bool(create):
        raise ApiError(400, 'name either a host to tie this report to, or ask to create it as a target')
    if host:
        from agentapi.host_manage import clean_host
        name = clean_host(host)
        if not store._current(project).filter(name__iexact=name).exists():
            raise ApiError(404, 'that host is not in this project\'s inventory')
        store.adopt(inv, name)
    elif not _create_host(ctx, project, inv):
        raise ApiError(409, 'this machine could not be added as a target (excluded, an address the scanner refuses, or nothing to add)')
    from cveFeed.admin_api import audit
    audit(ctx.user, 'inventory.adopt', f'{inv.hostname or inv.key} in {slug}', project.org, project=slug, host=inv.host, created=bool(create))
    _queue(inv)
    return store.brief(inv, store.stale_days(project))


def delete_inventory(ctx, slug, inventory_id):
    project, _ = get_one_project(ctx, slug, write=True)
    inv = _qs(project).filter(pk=inventory_id).first()
    if inv is None:
        raise ApiError(404, 'inventory report not found')
    from cveFeed.admin_api import audit
    audit(ctx.user, 'inventory.delete', f'{inv.hostname or inv.key} in {slug}', project.org, project=slug, host=inv.host or None)
    inv.delete()
    return {'deleted': True}


def delete_unmatched(ctx, slug):
    """Delete every report that is tied to no host: the administrator's clean-up of what a token filled the list with."""
    project, _ = get_one_project(ctx, slug, write=True)
    count = store.delete_unmatched(project)
    from cveFeed.admin_api import audit
    audit(ctx.user, 'inventory.delete_unmatched', f'in {slug}', project.org, project=slug, deleted=count)
    return {'deleted': count}


def create_token(ctx, slug, name):
    """Mint a reporter token for one project: it can post that project's inventory reports and nothing else. Whoever may write to the
    project may mint it, and it acts with that person's role, so it is revoked with the person."""
    from tenancy import audit as trail
    if not slug:
        raise ApiError(400, 'an inventory token belongs to one project: name it in project')
    project, _ = get_one_project(ctx, slug, write=True)
    name = str(name or '').strip()[:MAX_TOKEN_NAME] or f'inventory reporter for {project.slug}'
    expires = timezone.now() + timedelta(days=TOKEN_DAYS)
    token, raw = auth.create_token(ctx.user, name, scope=auth.SCOPE_INVENTORY, project=project, expires_at=expires)
    trail.record_for_user(ctx.user, 'token.create', ctx.user, token=token.prefix, read_only=False, scope=auth.SCOPE_INVENTORY, project=project.slug,
                          expires=expires.date().isoformat())
    return {'id': token.id, 'name': token.name, 'scope': auth.SCOPE_INVENTORY, 'project': project.slug, 'token': raw, 'expires': expires.isoformat(),
            'note': f'Store this on the host it reports from. It is not shown again, it can only post this project\'s inventory, and it expires in {TOKEN_DAYS} days (create a new one to renew it).'}


def project_policy(project):
    """The inventory settings of one project, as the settings API shows them."""
    from cveFeed.models import ProjectSettings
    row = ProjectSettings.objects.filter(project=project).first()
    return {'create_hosts': bool(row and row.inventory_create_hosts), 'stale_days': row.inventory_stale_days if row else store.DEFAULT_STALE_DAYS}


def set_policy(ctx, project, changes):
    """Change the inventory settings (``create_hosts``, ``stale_days``) of a project the caller can write to; only the keys given."""
    from cveFeed.models import ProjectSettings
    if not isinstance(changes, dict) or not changes or set(changes) - {'create_hosts', 'stale_days'}:
        raise ApiError(400, 'inventory takes create_hosts (true or false) and/or stale_days (1 to %d)' % store.MAX_STALE_DAYS)
    row, _ = ProjectSettings.objects.get_or_create(project=project)
    if 'create_hosts' in changes:
        if not isinstance(changes['create_hosts'], bool):
            raise ApiError(400, 'create_hosts must be true or false')
        row.inventory_create_hosts = changes['create_hosts']
    if 'stale_days' in changes:
        days = changes['stale_days']
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= store.MAX_STALE_DAYS:
            raise ApiError(400, f'stale_days must be a whole number of days from 1 to {store.MAX_STALE_DAYS}')
        row.inventory_stale_days = days
    row.updated_by = ctx.user
    row.save(update_fields=['inventory_create_hosts', 'inventory_stale_days', 'updated_by', 'updated_at'])
    return project_policy(project)
