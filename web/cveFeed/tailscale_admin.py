"""Settings > Tailscale: connect a tailnet to a project, tune the sync, test the connection and see its status.

Superuser only, like the rest of /cve/api/settings (the dispatcher enforces it). Connecting a tailnet is the act that authorises
scanning its devices' tailnet addresses (see cveFeed.tailscale_scope), which is an instance-wide decision, so it is not delegated to
project or organization roles. Secrets are write-only: a response says whether credentials are set, never what they are, and a blank
field on update keeps the stored value. Reading and syncing for project admins is in agentapi.services (REST and MCP).
"""
import re

from django.utils import timezone

from cveFeed import tailscale_api, tailscale_scope
from cveFeed.tailscale_api import TailscaleError, clean_text

MAX_LIST = 30
_TAG_RE = re.compile(r'^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$')
_OS_RE = re.compile(r'^[A-Za-z][A-Za-z0-9 ._-]{0,31}$')


def _error(status, message):
    from cveFeed.settings_api import SettingsError
    return SettingsError(status, message)


def credential_kind(credentials):
    credentials = credentials or {}
    if credentials.get('client_id') and credentials.get('client_secret'):
        return 'oauth'
    return 'token' if credentials.get('access_token') else None


def link_dict(link):
    """One link as the settings page sees it: no secret, only what is set."""
    from cveFeed.models import TailscaleDevice
    devices = TailscaleDevice.objects.filter(link=link)
    active = devices.filter(departed_at__isnull=True)
    project = link.project
    return {
        'project': {'id': project.id, 'name': project.name, 'slug': project.slug}, 'enabled': link.enabled,
        'credential_kind': credential_kind(link.credentials), 'use_local': link.use_local, 'routing': link.routing,
        'scan_reachable': link.scan_reachable, 'auto_scan': link.auto_scan,
        'max_devices': link.max_devices, 'only_tags': link.only_tags, 'skip_tags': link.skip_tags, 'only_os': link.only_os,
        'check_policy': link.check_policy, 'tailnet': link.tailnet_name, 'device_count': link.device_count,
        'imported': active.count(), 'online': active.filter(online=True).count(), 'offline': active.filter(online=False).count(),
        'departed': devices.filter(departed_at__isnull=False).count(),
        'last_sync_at': link.last_sync_at.isoformat() if link.last_sync_at else None, 'last_status': link.last_status,
        'last_error': link.last_error, 'local': link.local_state or {},
    }


def tailscale_get(request):
    from cveFeed.models import TailscaleLink
    from dashboard.models import Project
    links = TailscaleLink.objects.select_related('project').order_by('project__name')
    linked = {link.project_id for link in links}
    return {
        'links': [link_dict(link) for link in links],
        'projects': [{'id': p.id, 'name': p.name, 'slug': p.slug, 'org': p.org.name if p.org else ''}
                     for p in Project.objects.select_related('org').order_by('name') if p.id not in linked],
    }


def _project(project_id):
    from dashboard.models import Project
    project = Project.objects.filter(pk=project_id).first() if str(project_id).isdigit() else None
    if project is None:
        raise _error(404, 'project not found')
    return project


def _list(data, key, current, pattern, what):
    """A cleaned list field: ``current`` when the key is absent; entries are trimmed, de-duplicated and must match ``pattern``."""
    if key not in data:
        return current
    value = data[key]
    if isinstance(value, str):
        value = re.split(r'[\s,]+', value)
    if not isinstance(value, list):
        raise _error(400, f'{key} must be a list')
    out = []
    for item in value:
        item = clean_text(item, 64)
        if not item:
            continue
        if not pattern.match(item):
            raise _error(400, f'{item!r} is not a valid {what}')
        if item not in out:
            out.append(item)
    if len(out) > MAX_LIST:
        raise _error(400, f'{key} holds at most {MAX_LIST} entries')
    return out


def _credentials(data, current):
    """The credentials after applying ``data``: a blank field keeps the stored one; a new kind replaces the old; ``clear`` removes it."""
    if data.get('clear_credentials'):
        return {}
    given = {k: clean_text(data.get(k), 500) for k in ('access_token', 'client_id', 'client_secret')}
    if given['access_token'] and (given['client_id'] or given['client_secret']):
        raise _error(400, 'give either an API access token or an OAuth client, not both')
    if given['access_token']:
        return {'access_token': given['access_token']}
    if given['client_id'] or given['client_secret']:
        merged = {'client_id': given['client_id'] or current.get('client_id', ''), 'client_secret': given['client_secret'] or current.get('client_secret', '')}
        if not (merged['client_id'] and merged['client_secret']):
            raise _error(400, 'an OAuth client needs both its client id and its client secret')
        return merged
    return dict(current or {})


def tailscale_put(request, project_id):
    from cveFeed.admin_api import audit
    from cveFeed.models import TailscaleLink
    from cveFeed.settings_api import _body
    data = _body(request)
    project = _project(project_id)
    link = TailscaleLink.objects.filter(project=project).first() or TailscaleLink(project=project, enabled=False)
    was_enabled = link.enabled
    link.credentials = _credentials(data, link.credentials)
    for flag in ('enabled', 'use_local', 'auto_scan', 'check_policy'):
        if flag in data:
            setattr(link, flag, bool(data[flag]))
    if 'routing' in data:
        if data['routing'] not in ('auto', 'host'):
            raise _error(400, 'routing must be auto (this server\'s tailscale node) or host (the Docker host is on the tailnet)')
        if data['routing'] != link.routing:
            link.routing = data['routing']
            link.scan_reachable = link.routing == 'host'  # "host" is taken at the operator's word; "auto" is proved by the next sync
    if 'max_devices' in data:
        try:
            link.max_devices = int(data['max_devices'])
        except (TypeError, ValueError):
            raise _error(400, 'max_devices must be a number')
        if not 1 <= link.max_devices <= 5000:
            raise _error(400, 'max_devices must be between 1 and 5000')
    link.only_tags = _list(data, 'only_tags', link.only_tags, _TAG_RE, 'tag (like tag:server)')
    link.skip_tags = _list(data, 'skip_tags', link.skip_tags, _TAG_RE, 'tag (like tag:server)')
    link.only_os = _list(data, 'only_os', link.only_os, _OS_RE, 'operating system')
    if link.enabled and not (link.credentials or link.use_local):
        raise _error(400, 'add credentials or turn on this server\'s own Tailscale node, or there is nothing to read the tailnet from')
    link.updated_by = request.user
    link.save()
    tailscale_scope.invalidate()
    audit(request.user, 'tailscale.link.enable' if link.enabled and not was_enabled else 'tailscale.link.update', project.slug, org=project.org_id,
          project=project.slug, enabled=link.enabled, auto_scan=link.auto_scan, credentials=credential_kind(link.credentials) or 'none')
    return link_dict(link)


def tailscale_delete(request, project_id):
    from cveFeed import tailscale_sync
    from cveFeed.admin_api import audit
    from cveFeed.models import TailscaleLink
    project = _project(project_id)
    link = TailscaleLink.objects.filter(project=project).first()
    if link is None:
        raise _error(404, 'that project has no tailnet connected')
    now = timezone.now()
    for row in link.devices.filter(departed_at__isnull=True).select_related('domain'):
        tailscale_sync.retire(link, row, 'the tailnet was disconnected from this project', now)
    link.delete()
    tailscale_scope.invalidate()
    audit(request.user, 'tailscale.link.remove', project.slug, org=project.org_id, project=project.slug)
    return {'deleted': True}


def tailscale_sync_now(request, project_id):
    from cveFeed.admin_api import audit
    from cveFeed.models import TailscaleLink
    from cveFeed.tasks import sync_tailscale_link
    project = _project(project_id)
    link = TailscaleLink.objects.filter(project=project).first()
    if link is None:
        raise _error(404, 'that project has no tailnet connected')
    if not link.enabled:
        raise _error(409, 'turn the connection on first')
    from cveFeed.tailscale_sync import MANUAL_SYNC_GAP, manual_sync_allowed
    if not manual_sync_allowed(link.pk):
        raise _error(429, f'a sync was started less than {MANUAL_SYNC_GAP} seconds ago; wait before asking again')
    sync_tailscale_link.delay(link.pk)
    audit(request.user, 'tailscale.sync', project.slug, org=project.org_id, project=project.slug)
    return {'queued': True}


def node_state_from_worker():
    """This server's own node as the worker sees it (the web container has no status file): ``{present, state?, error?}``."""
    from cveFeed.tasks import tailscale_node_state
    try:
        return tailscale_node_state.delay().get(timeout=20)
    except Exception:  # noqa: BLE001 - no worker answered in time: say so, never fail the whole test
        return {'present': False, 'error': 'no worker answered; is the celery container running?'}


def test_connection(credentials, use_local=True):
    """Try the credentials and the local node without saving or importing anything. ``{ok, devices, tailnet, policy, local, error}``."""
    out = {'ok': False, 'devices': None, 'tailnet': '', 'policy': None, 'local': None, 'error': ''}
    if credentials:
        try:
            client = tailscale_api.Client(credentials)
            api_devices = client.devices()
            out['devices'], out['tailnet'] = len(api_devices), tailscale_api.tailnet_suffix(api_devices)
            try:
                client.policy()
                out['policy'] = 'readable'
            except TailscaleError as exc:
                out['policy'] = f'not readable: {exc}'
        except TailscaleError as exc:
            out['error'] = str(exc)
    if use_local:
        node = node_state_from_worker()
        if node.get('state'):
            out['local'] = node['state']
            if out['devices'] is None:
                out['devices'], out['tailnet'] = node['peer_count'], out['tailnet'] or node['state']['tailnet']
        elif node.get('error'):
            out['local'] = {'error': node['error']}
    out['ok'] = out['devices'] is not None
    if not out['ok'] and not out['error']:
        out['error'] = 'no credentials are saved and this server\'s own Tailscale node is not running'
    return out


def tailscale_test(request, project_id):
    from cveFeed.models import TailscaleLink
    from cveFeed.settings_api import _body
    data = _body(request)
    project = _project(project_id)
    link = TailscaleLink.objects.filter(project=project).first()
    credentials = _credentials(data, link.credentials if link else {})
    return test_connection(credentials, use_local=bool(data.get('use_local', True)))
