"""Tailscale integration for agents (REST and MCP): read the connection and its devices, and start a sync. Administrators only.

A project administrator (an organization admin of the project's organization, or an App Admin) may read and sync; every other role,
including a project member, gets 403, because the connection decides which addresses scanners may reach. Connecting, changing and
disconnecting a tailnet, and its credentials, are in Settings (superuser) and are not part of this API. No response carries a
credential: ``credential_kind`` says only whether an OAuth client or an access token is saved.
"""
from agentapi.services import ApiError, _iso, get_one_project, paginate
from tenancy import roles


def _admin(ctx, slug, write=False):
    project, role = get_one_project(ctx, slug, write=write)
    if role != roles.ADMIN:
        raise ApiError(403, 'only a project administrator can use the Tailscale integration')
    return project


def _link(project):
    from cveFeed.models import TailscaleLink
    return TailscaleLink.objects.filter(project=project).select_related('project').first()


def tailscale_status(ctx, slug):
    """The project's tailnet connection: tailnet name, device counts, last sync, errors and settings; ``connected: false`` when none."""
    from cveFeed import tailscale_admin, tailscale_local
    project = _admin(ctx, slug)
    link = _link(project)
    sidecar = {'present': tailscale_local.available()}
    if link is None:
        return {'connected': False, 'sidecar': sidecar}
    status = tailscale_admin.link_dict(link)
    status.pop('project')
    return {'connected': True, **status, 'sidecar': sidecar}


def _device(row):
    facts = row.facts or {}
    return {
        'id': row.id, 'name': row.name, 'addresses': row.addresses, 'target_id': row.domain_id, 'target': row.domain.name if row.domain else None,
        'online': row.online, 'departed': row.departed_at is not None, 'departed_at': _iso(row.departed_at),
        'os': facts.get('os', ''), 'client_version': facts.get('client_version', ''), 'update_available': facts.get('update_available'),
        'tags': facts.get('tags', []), 'user': facts.get('user', ''), 'key_expiry_disabled': facts.get('key_expiry_disabled'),
        'key_expires': facts.get('expires', ''), 'last_seen': facts.get('last_seen', ''), 'ssh': facts.get('ssh'),
        'exit_node': facts.get('exit_node'), 'enabled_routes': facts.get('enabled_routes', []),
        'first_seen': _iso(row.first_seen), 'last_synced': _iso(row.last_seen), 'scan_queued': _iso(row.scan_queued_at),
    }


def tailscale_devices(ctx, slug, params):
    """The tailnet devices imported into the project with what Tailscale reported about each (state=active|offline|departed, q=name)."""
    from cveFeed.models import TailscaleDevice
    project = _admin(ctx, slug)
    qs = TailscaleDevice.objects.filter(project=project).select_related('domain').order_by('name', 'id')
    state = params.get('state') or 'active'
    if state == 'departed':
        qs = qs.filter(departed_at__isnull=False)
    elif state == 'offline':
        qs = qs.filter(departed_at__isnull=True, online=False)
    elif state == 'active':
        qs = qs.filter(departed_at__isnull=True)
    elif state != 'all':
        raise ApiError(400, 'state must be active, offline, departed or all')
    if params.get('q'):
        qs = qs.filter(name__icontains=params['q'])
    return paginate(qs, params, _device)


def tailscale_sync(ctx, slug):
    """Queue a sync of the project's tailnet now (it also runs every 15 minutes)."""
    from cveFeed.tasks import sync_tailscale_link
    project = _admin(ctx, slug, write=True)
    link = _link(project)
    if link is None:
        raise ApiError(404, 'that project has no tailnet connected')
    if not link.enabled:
        raise ApiError(409, 'the tailnet connection is switched off')
    sync_tailscale_link.delay(link.pk)
    from cveFeed.admin_api import audit
    audit(ctx.user, 'tailscale.sync', project.slug, org=project.org_id, project=project.slug)
    return {'queued': True}
