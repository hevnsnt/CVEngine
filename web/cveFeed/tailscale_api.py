"""Tailscale control-plane client (https://api.tailscale.com/api/v2) and the typed device record both Tailscale sources produce.

Two credentials work, and an OAuth client is the better one: it is scoped, and a leak is cut off by revoking it.
  * OAuth client (``client_id`` + ``client_secret``): exchanged at POST /api/v2/oauth/token for a one-hour access token.
  * API access token (``access_token``, ``tskey-api-...``): sent as a bearer token; Tailscale expires these after at most 90 days.
Only read endpoints are used: GET /api/v2/tailnet/-/devices?fields=all and GET /api/v2/tailnet/-/acl (Accept: application/json, so the
policy comes back as plain JSON without comments). The tailnet is always "-" (the credential's own), so the only host this talks to is
api.tailscale.com, a constant: there is no user-supplied URL to guard.

Everything the service returns is untrusted data. ``normalise`` types, clips and validates each field into a fixed record (addresses
must lie in the tailnet ranges, names must look like names, lists are capped), so a hostile or malformed device cannot put an
internal address, markup or a megabyte of text into the inventory. Secrets are held only in a ``Client`` and never appear in an error.
"""
import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone as dt_timezone

from django.utils.dateparse import parse_datetime

from cveFeed.tailscale_scope import parse_address

API_BASE = 'https://api.tailscale.com'
TOKEN_URL = f'{API_BASE}/api/v2/oauth/token'
DEVICES_URL = f'{API_BASE}/api/v2/tailnet/-/devices?fields=all'
POLICY_URL = f'{API_BASE}/api/v2/tailnet/-/acl'
TIMEOUT = 20
MAX_BODY_BYTES = 16 * 1024 * 1024  # a tailnet of tens of thousands of devices is still under this
MAX_DEVICES = 20000
MAX_ADDRESSES, MAX_TAGS, MAX_ROUTES = 8, 20, 64
ONLINE_WINDOW = timedelta(minutes=10)  # last seen this recently counts as online when the service gives no connection flag
DEFAULT_ROUTES = ('0.0.0.0/0', '::/0')  # an exit node is a device whose approved routes include both

_TAG_RE = re.compile(r'^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$')
_NAME_RE = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
_VERSION_RE = re.compile(r'^[0-9A-Za-z.+_-]{1,64}$')
_HOST_CHARS = re.compile(r'[^A-Za-z0-9._-]')
_OS_CHARS = re.compile(r'[^A-Za-z0-9 ._-]')
_LOGIN_RE = re.compile(r"^[A-Za-z0-9._%+'@-]{1,120}$")  # a login name is an email-like token; anything else is not shown


class TailscaleError(Exception):
    """A failure with a message that is safe to show: it never carries a credential, a URL query or the service's own text."""


# --- typed, clipped values ---------------------------------------------------------------------------------------------------

def clean_text(value, limit):
    """``value`` as printable text of at most ``limit`` characters, '' for anything that is not a string."""
    if not isinstance(value, str):
        return ''
    text = ''.join(ch for ch in value if unicodedata.category(ch)[0] != 'C' or ch == ' ').strip()
    return text[:limit]


def _flag(value):
    return value is True


def _time(value):
    """An ISO 8601 UTC timestamp, or '' for text that is not one or is the zero time Tailscale uses for "never"."""
    if not isinstance(value, str) or len(value) > 64:
        return ''
    try:
        parsed = parse_datetime(value)
    except ValueError:
        return ''
    if parsed is None or parsed.year < 2010:
        return ''
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return parsed.astimezone(dt_timezone.utc).isoformat()


def _addresses(values):
    found = []
    for value in values if isinstance(values, list) else []:
        ip = parse_address(value)
        if ip is not None and str(ip) not in found:
            found.append(str(ip))
        if len(found) >= MAX_ADDRESSES:
            break
    return found


def _tags(values):
    return [t for t in dict.fromkeys(v for v in (values if isinstance(values, list) else []) if isinstance(v, str) and _TAG_RE.match(v))][:MAX_TAGS]


def _routes(values):
    found = []
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, str) or len(value) > 64:
            continue
        try:
            net = str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError:
            continue
        if net not in found:
            found.append(net)
        if len(found) >= MAX_ROUTES:
            break
    return found


def _dns_name(value, hostname):
    """The device's MagicDNS name (lowercase, no trailing dot) when it looks like a host name, else its host name, else ''."""
    for candidate in (value, hostname):
        text = clean_text(candidate, 253).lower().rstrip('.')
        if text and _NAME_RE.match(text):
            return text
    return ''


def normalise(source, node_id, name, hostname, addresses, os='', client_version='', update_available=None, tags=(), user='',
              authorized=True, is_external=False, key_expiry_disabled=None, expires='', last_seen='', created='', online=None,
              advertised_routes=(), enabled_routes=(), ssh=None, exit_node_option=None, blocks_incoming=None):
    """The fixed device record, from values already typed by a parser; None for a device that has no usable id or no tailnet address.
    ``None`` in a flag means "this source did not say", which the checks treat as unknown, never as false."""
    hostname = _HOST_CHARS.sub('', clean_text(hostname, 200))[:100]  # free text from a device owner reaches findings and agents: keep it to name characters
    user = user if isinstance(user, str) and _LOGIN_RE.match(user.strip()) else ''
    node_id = clean_text(str(node_id) if isinstance(node_id, int) and not isinstance(node_id, bool) else node_id, 80)
    addresses = _addresses(addresses)
    if not node_id or not addresses:
        return None
    enabled = _routes(enabled_routes)
    exit_option = exit_node_option if exit_node_option is not None else all(r in enabled for r in DEFAULT_ROUTES)
    return {
        'source': source, 'node_id': node_id, 'name': _dns_name(name, hostname) or node_id.lower(),
        'hostname': hostname, 'addresses': addresses, 'os': _OS_CHARS.sub('', clean_text(os, 64))[:32],
        'client_version': client_version if isinstance(client_version, str) and _VERSION_RE.match(client_version) else '',
        'update_available': update_available, 'tags': _tags(tags), 'user': user.strip(),
        'authorized': authorized, 'is_external': is_external, 'key_expiry_disabled': key_expiry_disabled,
        'expires': _time(expires), 'last_seen': _time(last_seen), 'created': _time(created), 'online': online,
        'advertised_routes': _routes(advertised_routes), 'enabled_routes': enabled, 'ssh': ssh,
        'exit_node': exit_option, 'blocks_incoming': blocks_incoming,
    }


def _online(raw, last_seen, now):
    connected = raw.get('connectedToControl')
    if isinstance(connected, bool):
        return connected
    if last_seen:
        return now - datetime.fromisoformat(last_seen) <= ONLINE_WINDOW
    return None


def parse_device(raw, now=None):
    """One entry of the devices list as a device record, or None when it is not a usable device."""
    if not isinstance(raw, dict):
        return None
    now = now or datetime.now(dt_timezone.utc)
    last_seen = _time(raw.get('lastSeen'))
    return normalise(
        'api', raw.get('nodeId') or raw.get('id'), raw.get('name'), raw.get('hostname'), raw.get('addresses') or [],
        os=raw.get('os'), client_version=raw.get('clientVersion'),
        update_available=raw['updateAvailable'] if isinstance(raw.get('updateAvailable'), bool) else None,
        tags=raw.get('tags') or [], user=raw.get('user'),
        authorized=raw['authorized'] is not False if 'authorized' in raw else True,
        is_external=_flag(raw.get('isExternal')),
        key_expiry_disabled=raw['keyExpiryDisabled'] if isinstance(raw.get('keyExpiryDisabled'), bool) else None,
        expires=raw.get('expires'), last_seen=last_seen, created=raw.get('created'), online=_online(raw, last_seen, now),
        advertised_routes=raw.get('advertisedRoutes') or [], enabled_routes=raw.get('enabledRoutes') or [],
        blocks_incoming=raw['blocksIncomingConnections'] if isinstance(raw.get('blocksIncomingConnections'), bool) else None)


def parse_devices(payload, now=None):
    """Device records from the devices response, at most MAX_DEVICES, in order, one per node id."""
    items = payload.get('devices') if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise TailscaleError('Tailscale answered with a device list in an unexpected shape')
    devices, seen = [], set()
    for raw in items[:MAX_DEVICES]:
        device = parse_device(raw, now)
        if device and device['node_id'] not in seen:
            seen.add(device['node_id'])
            devices.append(device)
    return devices


def tailnet_suffix(devices):
    """The MagicDNS suffix most devices share (``tail1234.ts.net``), the tailnet's own name, or ''."""
    counts = {}
    for device in devices:
        name = device.get('name') or ''
        if name.endswith('.ts.net') and name.count('.') >= 2:
            suffix = name.split('.', 1)[1]
            counts[suffix] = counts.get(suffix, 0) + 1
    return max(counts, key=counts.get) if counts else ''


def fingerprint(device):
    """What makes a device worth scanning again: a change in any of these. Not its online state or last seen time."""
    keys = ('addresses', 'os', 'client_version', 'tags', 'advertised_routes', 'enabled_routes', 'ssh', 'name')
    return hashlib.sha1(json.dumps({k: device.get(k) for k in keys}, sort_keys=True).encode()).hexdigest()


# --- the HTTP client ---------------------------------------------------------------------------------------------------------

def _send(method, url, headers=None, data=None, timeout=TIMEOUT):
    """One bounded HTTPS request: ``(status, body bytes)``. No redirects, and the body is read up to MAX_BODY_BYTES only."""
    import requests
    try:
        with requests.request(method, url, headers=headers, data=data, timeout=timeout, allow_redirects=False, stream=True) as response:
            body = response.raw.read(MAX_BODY_BYTES + 1, decode_content=True)
            return response.status_code, body
    except requests.RequestException as exc:
        raise TailscaleError('could not reach api.tailscale.com (%s)' % type(exc).__name__) from None


class Client:
    """Read-only access to one tailnet. ``credentials`` is the stored dict; nothing here logs or returns it."""

    def __init__(self, credentials, send=None):
        credentials = credentials if isinstance(credentials, dict) else {}
        self._token = clean_text(credentials.get('access_token'), 500)
        self._client_id = clean_text(credentials.get('client_id'), 200)
        self._client_secret = clean_text(credentials.get('client_secret'), 500)
        self._send = send or _send
        if not (self._token or (self._client_id and self._client_secret)):
            raise TailscaleError('no Tailscale credentials are saved: add an OAuth client or an API access token')

    def _bearer(self):
        if self._token:
            return self._token
        form = 'client_id=%s&client_secret=%s' % (_form(self._client_id), _form(self._client_secret))
        status, body = self._send('POST', TOKEN_URL, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=form)
        if status in (400, 401, 403):
            raise TailscaleError('Tailscale rejected the OAuth client (wrong id or secret, or the client was revoked)')
        if status != 200:
            raise TailscaleError('Tailscale could not issue an access token (HTTP %d)' % status)
        answer = _json(body)
        token = answer.get('access_token') if isinstance(answer, dict) else None
        if not isinstance(token, str) or not token:
            raise TailscaleError('Tailscale issued no access token')
        self._token = token
        return token

    def get(self, url, accept='application/json'):
        status, body = self._send('GET', url, headers={'Authorization': 'Bearer ' + self._bearer(), 'Accept': accept})
        if status == 401:
            raise TailscaleError('Tailscale rejected the credentials (expired or revoked)')
        if status == 403:
            raise TailscaleError('the credentials lack a scope this needs (see docs/TAILSCALE.md for the read-only scopes)')
        if status == 429:
            raise TailscaleError('Tailscale is rate limiting this tailnet; the next sync tries again')
        if status != 200:
            raise TailscaleError('Tailscale answered HTTP %d' % status)
        if len(body) > MAX_BODY_BYTES:
            raise TailscaleError('Tailscale answered with more data than cvENGINE reads')
        return _json(body)

    def devices(self):
        return parse_devices(self.get(DEVICES_URL))

    def policy(self):
        """The tailnet policy as a dict (plain JSON), or raises TailscaleError."""
        policy = self.get(POLICY_URL)
        if not isinstance(policy, dict):
            raise TailscaleError('Tailscale answered with a policy in an unexpected shape')
        return policy


def _form(value):
    from urllib.parse import quote
    return quote(value, safe='')


def _json(body):
    try:
        return json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise TailscaleError('Tailscale answered with something that is not JSON') from None
