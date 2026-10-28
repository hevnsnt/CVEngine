"""A project's declared internal networks (REST): the private ranges a Sentinel deployed inside them will scan for the project.

Project administrators only (an organization admin of the project's organization, or an App Admin): a range tells this server which
private addresses may become targets, so it is an authorisation, and the list itself describes a customer's internal network. Declaring
a range adds nothing to what this server scans: ``targetApp.target_types.is_scannable_ip`` still refuses every such address for local
execution. See ``cveFeed.models.InternalRange``.
"""
from django.db import IntegrityError

from agentapi.services import ApiError, _iso, get_one_project
from tenancy import audit, roles

MAX_RANGES = 50


def _admin(ctx, slug, write=False):
    project, role = get_one_project(ctx, slug, write=write)
    if role != roles.ADMIN:
        raise ApiError(403, 'only a project administrator can manage internal ranges')
    return project


def _row(r):
    return {'id': r.pk, 'cidr': r.cidr, 'description': r.description, 'created': _iso(r.created_at),
            'created_by': r.created_by.username if r.created_by_id else None,
            'last_discovery_at': _iso(r.last_discovery_at), 'last_discovery_hosts': r.last_discovery_hosts,
            'last_discovery_error': r.last_discovery_error}


def list_ranges(ctx, slug):
    from cveFeed.models import InternalRange
    project = _admin(ctx, slug)
    return {'project': project.slug, 'results': [_row(r) for r in InternalRange.objects.filter(project=project).select_related('created_by')]}


def add_range(ctx, slug, body):
    from cveFeed.models import InternalRange
    from targetApp.target_types import clean_internal_cidr
    project = _admin(ctx, slug, write=True)
    if not isinstance(body, dict) or set(body) - {'cidr', 'description'}:
        raise ApiError(400, 'send {cidr, description}')
    try:
        cidr = clean_internal_cidr(body.get('cidr'))
    except ValueError as exc:
        raise ApiError(400, str(exc))
    description = body.get('description') or ''
    if not isinstance(description, str) or len(description) > 200:
        raise ApiError(400, 'description must be text of at most 200 characters')
    if InternalRange.objects.filter(project=project).count() >= MAX_RANGES:
        raise ApiError(400, f'a project may declare at most {MAX_RANGES} internal ranges')
    try:
        row = InternalRange.objects.create(project=project, cidr=cidr, description=description.strip(), created_by=ctx.user)
    except IntegrityError:
        raise ApiError(409, f'{cidr} is already declared for this project')
    audit.record(ctx.user, 'internal_range.add', f'{project.slug} {cidr}', org=project.org_id, project=project.slug, cidr=cidr)
    return _row(row)


def delete_range(ctx, slug, range_id):
    from cveFeed.models import InternalRange
    project = _admin(ctx, slug, write=True)
    row = InternalRange.objects.filter(project=project, pk=range_id).first()
    if row is None:
        raise ApiError(404, 'internal range not found')
    cidr = row.cidr
    row.delete()
    audit.record(ctx.user, 'internal_range.delete', f'{project.slug} {cidr}', org=project.org_id, project=project.slug, cidr=cidr)
    return {'deleted': cidr, 'note': 'targets already added inside it stay, but nothing scans them until the range is declared again'}


def discover_now(ctx, slug, range_id):
    """Queue a host discovery of one declared range now. Refused with the reason when no Sentinel inside the network could take it, so
    "scan now" never reports a sweep that nobody will run."""
    from agentapi import sentinel_broker
    from cveFeed import internal_discovery
    from cveFeed.models import InternalRange
    from cveFeed.tasks import run_internal_discovery
    project = _admin(ctx, slug, write=True)
    row = InternalRange.objects.filter(project=project, pk=range_id).first()
    if row is None:
        raise ApiError(404, 'internal range not found')
    if not internal_discovery.chunks(row.cidr)[1]:
        raise ApiError(400, 'IPv6 ranges are not swept; add their hosts by hand')
    if not sentinel_broker.any_scanner_for(project, 'discover', internal=True):
        raise ApiError(409, 'no Sentinel is online that declares network:internal and discover for this project; nothing would sweep the range')
    run_internal_discovery.delay(row.pk)
    audit.record(ctx.user, 'internal_range.discover', f'{project.slug} {row.cidr}', org=project.org_id, project=project.slug, cidr=row.cidr)
    return {'queued': row.cidr}
