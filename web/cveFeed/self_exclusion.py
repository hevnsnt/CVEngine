"""This cvENGINE server is never a scan target: its own public names and the public addresses they resolve to are refused for every project, every
Sentinel and the built-in scanner.

Why: a Sentinel that shares the server's public address (one at the owner's home, behind the same router) or any Sentinel whose target domain also holds
the server's name (``scanner.example.com`` under ``example.com``) would otherwise send web probes at the server itself. The input guard reads some of
those probes as attacks and bans the address, which locks the owner and the Sentinel out.

The names come from the server's own settings, never from a guess about a parent domain:

* ``DOMAIN_NAME`` (the public name every link is built from),
* ``CVENGINE_ALLOWED_HOSTS`` (the other names and addresses users reach the server by; they are in ``ALLOWED_HOSTS``),
* the hosts of ``CVENGINE_CSRF_TRUSTED_ORIGINS`` (a public https origin in front of the server),
* ``CVENGINE_OWN_ADDRESSES`` (addresses of an instance behind NAT or a load balancer, the same setting OpenVAS reads).

Loopback names, names without a dot (compose service names such as ``web``) and wildcard entries (``.example.com``, ``*``) are left out: only the
server's exact names are excluded, never the domain above them. The addresses are the public (global) addresses the names resolve to, plus any public
address written in those settings and every address in ``CVENGINE_OWN_ADDRESSES``. A private address is left out unless listed there, because the same
private address is a different host on another network.

The lookup result is kept for ``TTL`` seconds in this process. A failed lookup keeps the last good answer and is retried after ``RETRY`` seconds, so a
DNS outage never removes an address that was known. Only the server's own addresses are kept here; every exclusion DECISION is still made per call by
``cveFeed.exclusions`` (this only adds refusals, it never lets anything through).
"""
import ipaddress
import logging
import os
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

LABEL = 'This cvENGINE server, never scanned'
TTL = 300  # seconds a lookup of the server's own names is kept
RETRY = 60  # seconds before a failed lookup is asked again (the last good answer stays meanwhile)
MAX_NAMES = 50
_LOCAL_NAMES = ('localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback')

_lock = threading.Lock()
_state = {'at': 0.0, 'key': None, 'addresses': frozenset()}


def _host_of(text):
    """The bare lowercase host of a setting value (a name, ``name:port``, ``[v6]:port`` or a URL), or ''."""
    text = str(text or '').strip()
    if not text:
        return ''
    try:
        host = urlsplit(text if '://' in text else '//' + text).hostname or ''
    except ValueError:
        return ''
    return host.strip().lower().rstrip('.')


def _address(text):
    try:
        ip = ipaddress.ip_address(str(text).split('%')[0].strip().strip('[]'))
    except ValueError:
        return None
    return ip.ipv4_mapped or ip if ip.version == 6 else ip


def _settings_hosts():
    """Every host the settings name for this server: ``DOMAIN_NAME``, ``ALLOWED_HOSTS`` and the CSRF trusted origins."""
    from django.conf import settings
    hosts = [_host_of(getattr(settings, 'DOMAIN_NAME', ''))]
    hosts += [_host_of(h) for h in getattr(settings, 'ALLOWED_HOSTS', ()) or () if isinstance(h, str) and not h.startswith(('.', '*'))]
    hosts += [_host_of(o) for o in getattr(settings, 'CSRF_TRUSTED_ORIGINS', ()) or () if isinstance(o, str) and '*' not in o]
    return [h for h in dict.fromkeys(hosts) if h]


def names():
    """The server's own public host names (lowercase, exact): never a loopback name, a name without a dot or a wildcard."""
    out = []
    for host in _settings_hosts():
        if _address(host) is not None or host in _LOCAL_NAMES or host.endswith('.localhost') or '.' not in host or '*' in host:
            continue
        out.append(host)
    return frozenset(out[:MAX_NAMES])


def _listed_addresses():
    """Addresses written in the settings: every one in ``CVENGINE_OWN_ADDRESSES``, and the public ones among the server's host settings."""
    out = set()
    for part in os.environ.get('CVENGINE_OWN_ADDRESSES', '').split(','):
        ip = _address(part)
        if ip is not None and not ip.is_loopback and not ip.is_unspecified:
            out.add(ip)
    for host in _settings_hosts():
        ip = _address(host)
        if ip is not None and ip.is_global:
            out.add(ip)
    return out


def _resolve(name):
    import socket
    return {item[4][0] for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)}


def addresses():
    """The server's own addresses (``ip_address`` objects): those listed in settings, and the public addresses its names resolve to (kept ``TTL`` seconds;
    a failed lookup keeps the last good answer)."""
    listed = _listed_addresses()
    wanted = tuple(sorted(names()))
    now = time.monotonic()
    with _lock:
        if _state['key'] == wanted and _state['at'] and now - _state['at'] < TTL:
            return frozenset(listed | set(_state['addresses']))
        previous = _state['addresses'] if _state['key'] == wanted else frozenset()
    found, failed = set(), False
    for name in wanted:
        try:
            resolved = _resolve(name)
        except Exception:  # noqa: BLE001 - DNS down or the test rig's block: keep what was known, ask again soon
            failed = True
            continue
        for text in resolved:
            ip = _address(text)
            if ip is not None and ip.is_global:
                found.add(ip)
    if failed:
        found |= set(previous)  # a lookup that failed never drops an address that was known
    with _lock:
        _state.update(key=wanted, addresses=frozenset(found), at=(now - TTL + RETRY) if failed else now)
    return frozenset(listed | found)


def networks():
    """The server's own addresses as single address networks (/32, /128), for a scope's denied ranges and the exclusion sets."""
    return tuple(ipaddress.ip_network(ip) for ip in sorted(addresses(), key=lambda a: (a.version, int(a))))


def summary():
    """What the UI shows beside an exclusion list: ``{'label', 'names', 'addresses'}``."""
    return {'label': LABEL, 'names': sorted(names()), 'addresses': [str(n.network_address) for n in networks()]}


def forget():
    """Drop the kept lookup (tests, and a settings change in a running process)."""
    with _lock:
        _state.update(at=0.0, key=None, addresses=frozenset())
