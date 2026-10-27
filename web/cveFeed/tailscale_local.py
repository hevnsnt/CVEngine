"""This server's own tailscaled, read from the status file its sidecar publishes (the `tailscale status --json` data), with no credential.

The `tailscale` compose profile runs a tailscaled sidecar in the celery container's network namespace. The sidecar rewrites
``status.json`` every few seconds into a volume that only celery mounts, read-only: it holds what `tailscale status --json` prints
(whether the node is connected, which tailnet it is in, every peer this node may see: name, addresses, OS, tags, online state, routes
it is primary for, key expiry) with the login URL removed. That is enough to enumerate and scan a tailnet without any API credential,
and the control-plane API adds what a node cannot see (client versions, the update flag, key-expiry settings, the policy file).

cvENGINE deliberately does not mount tailscaled's own control socket anywhere: whoever can connect to it as root (every container
runs as root) can reconfigure the node. A file is read-only data, and a stale file is how a dead sidecar shows: a status older than
``MAX_AGE`` seconds counts as no node. The path is a deployment setting (``CVENGINE_TAILSCALE_STATUS_FILE``), never user input, and the
web container has no such file: only the worker reads the node.
"""
import json
import os
import time

from cveFeed.tailscale_api import MAX_BODY_BYTES, MAX_DEVICES, TailscaleError, clean_text, normalise

DEFAULT_STATUS_FILE = '/var/run/tailscale-status/status.json'
MAX_AGE = 90  # seconds; the sidecar rewrites the file about every 15
LIVE_CACHE_SECONDS = 30

_live = {'at': 0.0, 'ok': False}


def status_path():
    return os.environ.get('CVENGINE_TAILSCALE_STATUS_FILE', '').strip() or DEFAULT_STATUS_FILE


def available():
    """Whether a status file exists here, fresh or not."""
    return os.path.exists(status_path())


def _status_json():
    path = status_path()
    try:
        age = time.time() - os.stat(path).st_mtime
        with open(path, 'rb') as handle:
            body = handle.read(MAX_BODY_BYTES + 1)
    except OSError as exc:
        raise TailscaleError('this server has no status from its Tailscale node (%s)' % type(exc).__name__) from None
    if age > MAX_AGE:
        raise TailscaleError('the Tailscale node has not reported for %d seconds: it is not running' % age)
    if len(body) > MAX_BODY_BYTES:
        raise TailscaleError('the node status is larger than cvENGINE reads')
    try:
        data = json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise TailscaleError('the node status is not JSON') from None
    if not isinstance(data, dict):
        raise TailscaleError('the node status is in an unexpected shape')
    return data


def live():
    """Whether this server's node is up right now (a fresh status that says Running), cached for LIVE_CACHE_SECONDS. This is asked
    when a scan is admitted, so a sidecar that died stops tailnet scanning within seconds instead of leaving the packets to leave by
    the Docker default route."""
    now = time.monotonic()
    if now - _live['at'] > LIVE_CACHE_SECONDS or _live['at'] == 0.0:
        try:
            _live['ok'] = _status_json().get('BackendState') == 'Running'
        except TailscaleError:
            _live['ok'] = False
        _live['at'] = now
    return _live['ok']


def invalidate():
    _live['at'] = 0.0


def _user_login(users, user_id):
    entry = users.get(str(user_id)) if isinstance(users, dict) else None
    return clean_text(entry.get('LoginName'), 120) if isinstance(entry, dict) else ''


def parse_peer(raw, users):
    """One peer of the status as a device record, or None. A node shared in from another tailnet (``ShareeNode``) is marked external."""
    if not isinstance(raw, dict):
        return None
    online = raw.get('Online')
    tags = raw.get('Tags') if isinstance(raw.get('Tags'), list) else []
    routes = raw.get('PrimaryRoutes') if isinstance(raw.get('PrimaryRoutes'), list) else []
    hostkeys = raw.get('sshHostKeys') if 'sshHostKeys' in raw else raw.get('SSH_HostKeys')
    return normalise(
        'local', raw.get('ID') or raw.get('PublicKey'), raw.get('DNSName'), raw.get('HostName'), raw.get('TailscaleIPs') or [],
        os=raw.get('OS'), tags=tags, user='' if tags else _user_login(users, raw.get('UserID')),
        is_external=raw.get('ShareeNode') is True, key_expiry_disabled=None,
        expires=raw.get('KeyExpiry'), last_seen=raw.get('LastSeen'), online=online if isinstance(online, bool) else None,
        enabled_routes=routes, ssh=bool(hostkeys) if isinstance(hostkeys, list) else None,
        exit_node_option=raw['ExitNodeOption'] if isinstance(raw.get('ExitNodeOption'), bool) else None)


def read():
    """``(state, devices)``: the node's own state (a small typed dict) and the peer records, or raises TailscaleError. ``self_ids`` in
    the state lists this node's own ids so the sync never imports the scanner as a target."""
    data = _status_json()
    users = data.get('User') if isinstance(data.get('User'), dict) else {}
    peers = data.get('Peer') if isinstance(data.get('Peer'), dict) else {}
    devices = []
    for raw in list(peers.values())[:MAX_DEVICES]:
        device = parse_peer(raw, users)
        if device:
            devices.append(device)
    own = data.get('Self') if isinstance(data.get('Self'), dict) else {}
    tailnet = data.get('CurrentTailnet') if isinstance(data.get('CurrentTailnet'), dict) else {}
    state = {
        'backend_state': clean_text(data.get('BackendState'), 32), 'version': clean_text(data.get('Version'), 64),
        'tailnet': clean_text(tailnet.get('Name'), 200) or clean_text(data.get('MagicDNSSuffix'), 200),
        'magic_dns_suffix': clean_text(tailnet.get('MagicDNSSuffix') or data.get('MagicDNSSuffix'), 200),
        'self_name': clean_text(own.get('DNSName'), 253).lower().rstrip('.'),
        'self_ids': [i for i in (clean_text(own.get('ID'), 80), clean_text(own.get('PublicKey'), 80)) if i],
        'self_online': own.get('Online') is True, 'peers': len(devices),
    }
    return state, devices
