"""This cvENGINE server is never a scan target: its own public names are refused for every project, every Sentinel and the built-in scanner, and so
are the addresses that are the server's own origin.

Why: a Sentinel that shares the server's public address (one at the owner's home, behind the same router) or any Sentinel whose target domain also holds
the server's name (``scanner.example.com`` under ``example.com``) would otherwise send web probes at the server itself. The input guard reads some of
those probes as attacks and bans the address, which locks the owner and the Sentinel out.

The names come from the server's own settings, never from a guess about a parent domain:

* ``DOMAIN_NAME`` (the public name every link is built from),
* ``CVENGINE_ALLOWED_HOSTS`` (the other names and addresses users reach the server by; they are in ``ALLOWED_HOSTS``),
* the hosts of ``CVENGINE_CSRF_TRUSTED_ORIGINS`` (a public https origin in front of the server).

Loopback names, names without a dot (compose service names such as ``web``) and wildcard entries (``.example.com``, ``*``) are left out: only the
server's exact names are excluded, never the domain above them. The names are always excluded (they fail closed: no lookup is needed to refuse them).

An address is denied only when it is the server's own origin:

* every address in ``CVENGINE_SELF_ADDRESSES`` and ``CVENGINE_OWN_ADDRESSES`` (written by the owner; the origin behind a CDN, NAT or a load balancer),
* a public address written in the host settings above,
* a public address of the machine's own network interfaces, when the process can see one,
* a public address the names resolve to, unless it is a SHARED address: inside a CDN's published edge range (``cveFeed.hosting.PROVIDER_RANGES``,
  Cloudflare's), flagged as a CDN address in the inventory, or one that unrelated hosts in the inventory resolve to too. A name behind Cloudflare
  resolves to Cloudflare's anycast addresses, which front many unrelated sites; denying them refused every customer site on Cloudflare.

A private address is left out unless listed in a setting, because the same private address is a different host on another network. ``summary`` says
which addresses are denied and why, and which resolved addresses were left out and why, for the do-not-scan list in the UI and over MCP.

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
_state = {'at': 0.0, 'key': None, 'addresses': {}, 'shared': {}, 'interfaces': {}}


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


SETTING_ENVS = ('CVENGINE_SELF_ADDRESSES', 'CVENGINE_OWN_ADDRESSES')


def _listed_addresses():
    """``{address: reason}`` for the addresses written in the settings: every one in ``CVENGINE_SELF_ADDRESSES`` and ``CVENGINE_OWN_ADDRESSES``, and the
    public ones among the server's host settings."""
    out = {}
    for env in SETTING_ENVS:
        for part in os.environ.get(env, '').split(','):
            ip = _address(part)
            if ip is not None and not ip.is_loopback and not ip.is_unspecified:
                out.setdefault(ip, f'set in {env}')
    for host in _settings_hosts():
        ip = _address(host)
        if ip is not None and ip.is_global:
            out.setdefault(ip, "written in the server's host settings")
    return out


def _interface_addresses():
    """The public addresses of this machine's own network interfaces that the process can see (none inside a container on a bridge network): the
    source address of the default route (a UDP socket that is connected sends nothing) and the global IPv6 addresses the kernel lists."""
    import socket
    found = set()
    for family, probe in ((socket.AF_INET, '192.0.2.1'), (socket.AF_INET6, '2001:db8::1')):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 9))
                found.add(sock.getsockname()[0])
        except (OSError, RuntimeError):  # no route of that family, or the test rig's block
            continue
    try:
        with open('/proc/net/if_inet6') as fh:
            for line in fh:
                raw = line.split()[0] if line.strip() else ''
                if len(raw) == 32:
                    found.add(':'.join(raw[i:i + 4] for i in range(0, 32, 4)))
    except OSError:
        pass
    out = set()
    for text in found:
        ip = _address(text)
        if ip is not None and ip.is_global:
            out.add(ip)
    return out


def _resolve(name):
    import socket
    return {item[4][0] for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)}


def _related(name, own_names):
    """True when ``name`` is one of the server's names or sits beside one (``www.example.com`` beside ``scanner.example.com``): the owner's own hosts,
    which may well share the server's machine, so they never make the server's address look shared."""
    name = (name or '').strip().lower().rstrip('.')
    for own in own_names:
        parent = own.split('.', 1)[1] if own.count('.') >= 2 else own
        if name == own or name == parent or name.endswith('.' + parent):
            return True
    return False


def _shared_reasons(candidates, own_names):
    """``{address: reason}`` for the resolved addresses that are SHARED, not the server's own origin: inside a CDN's published edge range, flagged as a
    CDN address in the inventory, or one that unrelated hosts in the inventory resolve to as well. Read with the tenancy scope lifted, because the
    answer is kept per process for every caller; only the reason text, never another project's data, leaves this module (it names at most three
    hosts, and only on the App Admin's server list)."""
    from cveFeed import hosting
    out = {}
    for ip in candidates:
        known = hosting.provider_range(str(ip))
        if known:
            out[ip] = f"{known[0]}'s shared {known[1].upper()} edge range, which fronts many other sites"
    rest = [str(ip) for ip in candidates if ip not in out]
    if not rest:
        return out
    from startScan.models import IpAddress, Subdomain
    from tenancy import scope
    tokens = scope.set_scope(None, None)
    try:
        flagged = set(IpAddress.objects.filter(address__in=rest, is_cdn=True).values_list('address', flat=True))
        rows = list(Subdomain.objects.filter(ip_addresses__address__in=rest).values_list('ip_addresses__address', 'name').distinct()[:5000])
    finally:
        scope.reset_scope(tokens)
    others = {}
    for address, name in rows:
        if name and not _related(name, own_names):
            others.setdefault(address, set()).add(name.strip().lower())
    for ip in candidates:
        text = str(ip)
        if ip in out:
            continue
        if text in flagged:
            out[ip] = 'flagged as a CDN address in the inventory'
        elif others.get(text):
            hosts = sorted(others[text])
            more = f' and {len(hosts) - 3} more' if len(hosts) > 3 else ''
            out[ip] = f"shared: unrelated hosts resolve to it too ({', '.join(hosts[:3])}{more})"
    return out


def _lookup(wanted):
    """``(denied, shared, failed)``: the public addresses the names resolve to, split into the server's own (``{address: reason}``) and the shared
    ones it must never deny (``{address: reason}``)."""
    resolved, failed = {}, False
    for name in wanted:
        try:
            answer = _resolve(name)
        except Exception:  # noqa: BLE001 - DNS down or the test rig's block: keep what was known, ask again soon
            failed = True
            continue
        for text in answer:
            ip = _address(text)
            if ip is not None and ip.is_global:
                resolved.setdefault(ip, name)
    try:
        shared = _shared_reasons(list(resolved), wanted)
    except Exception:  # noqa: BLE001 - the inventory could not be read: only a CDN range decides, the rest stay denied
        logger.warning("could not read the inventory to tell whether this server's addresses are shared", exc_info=True)
        from cveFeed import hosting
        shared = {ip: f"{k[0]}'s shared {k[1].upper()} edge range, which fronts many other sites"
                  for ip in resolved if (k := hosting.provider_range(str(ip)))}
    denied = {ip: f'{name} resolves to it' for ip, name in resolved.items() if ip not in shared}
    left = {ip: f'{resolved[ip]} resolves to it, but it is not denied: {why}' for ip, why in shared.items()}
    return denied, left, failed


def _state_now():
    """The kept lookup, refreshed when older than ``TTL``: ``(denied, shared, interfaces)``."""
    wanted = tuple(sorted(names()))
    now = time.monotonic()
    with _lock:
        if _state['key'] == wanted and _state['at'] and now - _state['at'] < TTL:
            return _state['addresses'], _state['shared'], _state['interfaces']
        same = _state['key'] == wanted
        previous, previous_shared = (_state['addresses'], _state['shared']) if same else ({}, {})
    denied, shared, failed = _lookup(wanted)
    if failed:  # a lookup that failed never drops an address that was known
        denied = {**previous, **denied}
        shared = {ip: why for ip, why in {**previous_shared, **shared}.items() if ip not in denied}
    try:
        interfaces = {ip: "an address of this server's own network interface" for ip in _interface_addresses()}
    except Exception:  # noqa: BLE001 - nothing seen is nothing added; the settings still apply
        interfaces = {}
    with _lock:
        _state.update(key=wanted, addresses=denied, shared=shared, interfaces=interfaces, at=(now - TTL + RETRY) if failed else now)
    return denied, shared, interfaces


def reasons():
    """``{address: reason}`` for every address of this server that is denied: those set in the settings, the machine's own public interface
    addresses, and the public addresses its names resolve to that are not shared (kept ``TTL`` seconds; a failed lookup keeps the last good answer)."""
    denied, _shared, interfaces = _state_now()
    out = dict(denied)
    out.update(interfaces)
    out.update(_listed_addresses())  # a setting is the strongest reason, so it is the one shown
    return out


def addresses():
    """The server's own addresses (``ip_address`` objects) that are denied; see ``reasons``."""
    return frozenset(reasons())


def not_denied():
    """``{address: reason}`` for the addresses the server's names resolve to that are shared (a CDN edge, or used by unrelated hosts) and therefore
    never denied, unless a setting or an interface names them as the server's own."""
    _denied, shared, _interfaces = _state_now()
    mine = addresses()
    return {ip: why for ip, why in shared.items() if ip not in mine}


def _ordered(ips):
    return sorted(ips, key=lambda a: (a.version, int(a)))


def networks():
    """The server's own addresses as single address networks (/32, /128), for a scope's denied ranges and the exclusion sets."""
    return tuple(ipaddress.ip_network(ip) for ip in _ordered(addresses()))


def summary():
    """What the UI and MCP show beside an exclusion list: ``{'label', 'names', 'addresses', 'address_reasons', 'not_denied'}``. ``addresses`` are the
    denied ones; ``address_reasons`` says why each is denied; ``not_denied`` lists the addresses the names resolve to that are left scannable, and why."""
    why = reasons()
    left = not_denied()
    return {'label': LABEL, 'names': sorted(names()), 'addresses': [str(ip) for ip in _ordered(why)],
            'address_reasons': [{'address': str(ip), 'reason': why[ip]} for ip in _ordered(why)],
            'not_denied': [{'address': str(ip), 'reason': left[ip]} for ip in _ordered(left)]}


def forget():
    """Drop the kept lookup (tests, and a settings change in a running process)."""
    with _lock:
        _state.update(at=0.0, key=None, addresses={}, shared={}, interfaces={})
