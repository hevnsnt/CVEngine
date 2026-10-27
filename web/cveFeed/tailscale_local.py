"""This server's own tailscaled, read through its LocalAPI (the `tailscale status --json` data), with no CLI and no credential.

The `tailscale` compose profile runs a tailscaled sidecar and shares its state socket (a named volume, read-only) with the web and
celery containers. GET /localapi/v0/status over that unix socket answers what `tailscale status --json` prints: whether the node is
connected, which tailnet it is in, and every peer this node may see (its ACL view): name, addresses, OS, tags, online state, routes
it is primary for, key expiry. That is enough to enumerate and scan a tailnet without any API credential; the control-plane API
adds what a node cannot see (client versions, the update flag, key-expiry settings, the policy file).

Only the read-only status call is made. The socket path is a deployment setting (``CVENGINE_TAILSCALE_SOCKET``), never user input.
"""
import http.client
import json
import os
import socket

from cveFeed.tailscale_api import MAX_BODY_BYTES, MAX_DEVICES, TailscaleError, clean_text, normalise

DEFAULT_SOCKET = '/var/run/tailscale/tailscaled.sock'
HOST_HEADER = 'local-tailscaled.sock'  # what the tailscale CLI sends; tailscaled expects it


def socket_path():
    return os.environ.get('CVENGINE_TAILSCALE_SOCKET', '').strip() or DEFAULT_SOCKET


def available():
    path = socket_path()
    return os.path.exists(path)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__(HOST_HEADER, timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _status_json(timeout=10):
    conn = _UnixConnection(socket_path(), timeout)
    try:
        conn.request('GET', '/localapi/v0/status', headers={'Host': HOST_HEADER})
        response = conn.getresponse()
        body = response.read(MAX_BODY_BYTES + 1)
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise TailscaleError('this server cannot reach its tailscaled (%s)' % type(exc).__name__) from None
    finally:
        conn.close()
    if status != 200 or len(body) > MAX_BODY_BYTES:
        raise TailscaleError('tailscaled answered HTTP %d to the status request' % status)
    try:
        data = json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise TailscaleError('tailscaled answered with something that is not JSON') from None
    if not isinstance(data, dict):
        raise TailscaleError('tailscaled answered with a status in an unexpected shape')
    return data


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
