"""The egress proxy of Settings > Proxy, applied to the scans that run on this server.

One place decides whether scan traffic leaves through a proxy and which one. The setting is ``scanEngine.Proxy`` (``use_proxy`` and one proxy
URL per line, ``http``, ``https``, ``socks5`` or ``socks5h``); a line that is not one of those is skipped, never guessed at. The setting is read
at most once every few seconds, so a hot path (every probe asks) does not query the database per call. A proxy is picked per request, round
robin over the valid lines the caller can use.

What goes through it (traffic to SCANNED TARGETS sent from this server): the in-process probes (through ``cveFeed.pinned_transport``, which
keeps vetting and pinning the numeric destination and sends that address to the proxy, never the name), ``db_exposure``'s HTTP checks
(``requests``), and the external tools that take a proxy: nuclei, bbot, WPScan, testssl.sh and wafw00f (``for_tool``). What does not: nmap, naabu,
the UDP sweeps, the raw database and RDP checks and OpenVAS use raw sockets and connect directly, a Sentinel keeps its own egress, and no call to a
third-party API (CVE feeds, AI providers, Shodan, GitHub, HackerOne, runZero, Tailscale, crt.sh) uses it.

Loopback, this stack's own services, private, link-local and tailnet addresses (unless ``CVENGINE_PROXY_PRIVATE=1``) and anything in ``CVENGINE_PROXY_BYPASS`` or ``NO_PROXY`` (host names, ``.suffix`` domains, IPs and CIDR
ranges, comma separated) are never sent through a proxy (no_proxy semantics), so a scan of a local fixture stays local.

A proxy that is down fails the request: there is no fallback to a direct connection, which would reveal the address the proxy is there to hide.
A proxy URL's password is never logged or put in an error: log ``describe(spec)``, never the URL.
"""
import base64
import ipaddress
import itertools
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

logger = logging.getLogger(__name__)

SCHEMES = ('http', 'https', 'socks5', 'socks5h')
IN_PROCESS_SCHEMES = ('http', 'socks5', 'socks5h')  # a TLS session cannot be nested in the TLS of an https:// proxy with the ssl module
DEFAULT_PORTS = {'http': 80, 'https': 443, 'socks5': 1080, 'socks5h': 1080}
CACHE_SECONDS = 5
MAX_LINE = 400
MAX_REPLY_HEADER = 16 * 1024
STACK_HOSTS = frozenset({'localhost', 'db', 'redis', 'web', 'celery', 'celery-beat', 'proxy', 'certs', 'tailscale'})


class ProxyUnavailable(RuntimeError):
    """The proxy is switched on but no configured proxy can carry this request (the tool or client does not speak its kind). The request must
    not go out directly: the caller skips it and says so."""


@dataclass(frozen=True, repr=False)
class ProxySpec:
    scheme: str
    host: str
    port: int
    username: str = ''
    password: str = ''

    def __repr__(self):  # never the password, wherever a spec ends up
        return f'ProxySpec({describe(self)})'

    __str__ = __repr__

    @property
    def netloc(self):
        return f'[{self.host}]:{self.port}' if ':' in self.host else f'{self.host}:{self.port}'

    @property
    def url(self):
        """The full URL, userinfo included: for a tool or a client that takes a URL. Never log it."""
        auth = ''
        if self.username or self.password:
            auth = quote(self.username, safe='') + (':' + quote(self.password, safe='') if self.password else '') + '@'
        return f'{self.scheme}://{auth}{self.netloc}'

    @property
    def plain_url(self):
        return f'{self.scheme}://{self.netloc}'

    @property
    def credentials(self):
        return f'{self.username}:{self.password}' if (self.username or self.password) else ''

    def authorization(self):
        """The ``Proxy-Authorization`` header value of an HTTP proxy, '' without credentials."""
        return 'Basic ' + base64.b64encode(self.credentials.encode('utf-8')).decode('ascii') if self.credentials else ''


def describe(spec):
    """``scheme://host:port`` and whether a login is set: what a log line or an error may say about a proxy."""
    return f'{spec.plain_url}{" (with login)" if spec.credentials else ""}'


def parse(line):
    """The ``ProxySpec`` of one proxy URL, or None when it is not a usable one (another scheme, no host, a bad port, a path, control characters,
    too long). ``socks4`` and the like are not supported."""
    text = (line or '').strip()
    if not text or len(text) > MAX_LINE or any(ord(c) <= 32 or ord(c) == 127 for c in text):
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
        host = parts.hostname
        user, password = parts.username, parts.password
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in SCHEMES or not host or parts.path not in ('', '/') or parts.query or parts.fragment:
        return None
    if port is not None and not 0 < port < 65536:
        return None
    user, password = unquote(user or ''), unquote(password or '')
    if any(ord(c) < 32 or ord(c) == 127 for c in user + password) or len(user) > 255 or len(password) > 255:
        return None
    return ProxySpec(scheme, host.lower(), port or DEFAULT_PORTS[scheme], user, password)


# ----------------------------------------------------------------------------- the setting, read at most every few seconds

_cache = {'at': None, 'specs': ()}
_cache_lock = threading.Lock()
_turn = itertools.count()


def reset_cache():
    """Forget the cached setting (the Settings API calls this on a save; tests call it between cases)."""
    with _cache_lock:
        _cache['at'] = None
        _cache['specs'] = ()


def _load():
    from scanEngine.models import Proxy
    row = Proxy.objects.first()
    if row is None or not row.use_proxy:
        return ()
    return tuple(spec for spec in (parse(ln) for ln in (row.proxies or '').splitlines()) if spec is not None)


def configured():
    """The valid proxies of the setting when it is on, else an empty tuple. Cached for ``CACHE_SECONDS``; when the database cannot be read the
    last known setting stays in force (a scan that needs the database fails anyway)."""
    now = time.monotonic()
    with _cache_lock:
        if _cache['at'] is not None and now - _cache['at'] < CACHE_SECONDS:
            return _cache['specs']
    try:
        specs = _load()
    except Exception as exc:  # noqa: BLE001 - a database hiccup must not break a probe; the previous answer is kept
        logger.warning('the egress proxy setting could not be read (%s); keeping the last known one', type(exc).__name__)
        specs = _cache['specs']
    with _cache_lock:
        _cache['at'], _cache['specs'] = now, specs
    return specs


def enabled():
    return bool(configured())


# ----------------------------------------------------------------------------- what never goes through a proxy

def _bypass_entries():
    entries = [e.strip().lower() for var in ('CVENGINE_PROXY_BYPASS', 'NO_PROXY', 'no_proxy') for e in os.environ.get(var, '').split(',') if e.strip()]
    stack = set(STACK_HOSTS)
    for url in (os.environ.get('CELERY_BROKER', ''), os.environ.get('CELERY_BACKEND', '')):
        host = urlsplit(url).hostname if url else None
        if host:
            stack.add(host.lower())
    postgres = os.environ.get('POSTGRES_HOST', '')
    if postgres and not postgres.startswith('/'):
        stack.add(postgres.lower())
    return entries, stack


# RFC 1918, carrier-grade NAT (a tailnet), link-local and unique-local space; spelled out because ``is_private`` also covers the documentation ranges
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
                                                          'fc00::/7', 'fe80::/10'))


def private_bypass():
    """Private, link-local and tailnet addresses skip the proxy unless ``CVENGINE_PROXY_PRIVATE=1``: a proxy somewhere else cannot reach them."""
    return os.environ.get('CVENGINE_PROXY_PRIVATE', '').strip().lower() not in ('1', 'true', 'yes', 'on')


def bypass(host):
    """True for a destination that is never sent through a proxy: loopback, private, link-local and tailnet addresses (unless
    ``CVENGINE_PROXY_PRIVATE=1``), this stack's own services, ``localhost``, and what
    ``CVENGINE_PROXY_BYPASS`` or ``NO_PROXY`` lists. ``host`` is a name or an IP literal."""
    name = str(host or '').strip().strip('[]').lower().rstrip('.')
    if not name:
        return True
    entries, stack = _bypass_entries()
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback or ip.is_unspecified or (private_bypass() and any(ip in net for net in PRIVATE_NETWORKS if net.version == ip.version)):
            return True
        for entry in entries:
            try:
                if ('/' in entry and ip in ipaddress.ip_network(entry, strict=False)) or ip == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return name in stack
    if name in stack or name.endswith('.localhost'):
        return True
    for entry in entries:
        entry = entry.lstrip('*')
        if entry in ('', '.'):
            continue
        if name == entry.lstrip('.') or name.endswith('.' + entry.lstrip('.')):
            return True
    return False


# ----------------------------------------------------------------------------- choosing a proxy

def pick(host=None, schemes=SCHEMES):
    """The proxy for one request, or None for a direct connection (the setting is off, or ``host`` is one that never goes through a proxy).
    Round robin over the configured proxies whose scheme is in ``schemes``. Raises ``ProxyUnavailable`` when the setting is on and no proxy
    can carry this kind of request."""
    specs = configured()
    if not specs or (host is not None and bypass(host)):
        return None
    usable = [s for s in specs if s.scheme in schemes]
    if not usable:
        raise ProxyUnavailable('Settings > Proxy is on, but none of its proxies is of a kind this check can use (' + ', '.join(schemes) + ')')
    return usable[next(_turn) % len(usable)]


def requests_proxies(host=None):
    """The ``proxies`` argument of a ``requests`` call: ``{}`` for a direct connection, else the picked proxy for http and https URLs. A session
    built for it must not read the environment's proxy settings (``trust_env = False``) so no proxy is added behind the setting's back."""
    spec = pick(host)
    return {'http': spec.url, 'https': spec.url} if spec is not None else {}


# ----------------------------------------------------------------------------- external tools

# tool -> (schemes it can use, how it takes the proxy as arguments). Each lambda gets the ProxySpec.
def _wpscan_args(spec):
    return ['--proxy', spec.plain_url] + (['--proxy-auth', spec.credentials] if spec.credentials else [])


TOOLS = {
    'nuclei': (('http', 'https', 'socks5'), lambda s: ['-proxy', s.url]),
    'bbot': (SCHEMES, lambda s: ['-c', f'web.http_proxy={s.url}']),  # bbot's own setting; bbot.private_config moves it into a 0600 file
    'wpscan': (SCHEMES, _wpscan_args),
    'wafw00f': (('http', 'https', 'socks5'), lambda s: ['-p', s.url]),
    'testssl': (('http',), lambda s: ['--proxy', s.netloc]),  # testssl.sh speaks to a plain HTTP proxy only, and has no way to give it a login
}


def hostname(target):
    """The host of a tool target: a URL, ``host:port``, a bare host or an IP literal (IPv6 included)."""
    text = str(target or '').strip()
    if '://' in text:
        return urlsplit(text).hostname or ''
    if text.startswith('['):
        return text[1:].split(']', 1)[0]
    return text.rsplit(':', 1)[0] if text.count(':') == 1 else text


def for_tool(tool, hosts=None):
    """The command line arguments (a list, empty for a direct run) that send ``tool`` through the picked proxy. ``hosts`` are the destinations
    of the run: when every one never goes through a proxy (loopback), the run stays direct. Raises ``ProxyUnavailable`` when the setting is on
    and no configured proxy suits the tool, or (testssl.sh) every suitable one needs a login the tool cannot send."""
    schemes, build = TOOLS[tool]
    everything = configured()
    if not everything or (hosts is not None and all(bypass(hostname(h)) for h in hosts)):
        return []
    specs = [s for s in everything if s.scheme in schemes and (tool != 'testssl' or not s.credentials)]
    if not specs:
        raise ProxyUnavailable(f'Settings > Proxy is on, but {tool} cannot use any of its proxies (it takes ' + ', '.join(schemes) +
                               (' without a login' if tool == 'testssl' else '') + ')')
    return build(specs[next(_turn) % len(specs)])


# ----------------------------------------------------------------------------- connecting through a proxy (in-process clients)

def connect_proxy(spec, timeout):
    """A TCP connection to the proxy itself (the address an administrator typed in Settings, so no destination vetting applies to it)."""
    return socket.create_connection((spec.host, spec.port), timeout=timeout)


def _read_exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError('the proxy closed the connection')
        data += chunk
    return data


def _http_connect(sock, ip, port, spec):
    authority = f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'
    lines = [f'CONNECT {authority} HTTP/1.1', f'Host: {authority}', 'Proxy-Connection: keep-alive']
    if spec.credentials:
        lines.append('Proxy-Authorization: ' + spec.authorization())
    sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode('ascii'))
    head = b''
    while not head.endswith(b'\r\n\r\n'):  # one byte at a time: nothing the target sends after the tunnel opens may be read here
        byte = sock.recv(1)
        if not byte:
            raise OSError('the proxy closed the connection')
        head += byte
        if len(head) > MAX_REPLY_HEADER:
            raise OSError('the proxy answered with too long a header')
    status = head.split(b'\r\n', 1)[0].split()
    if len(status) < 2 or not status[0].startswith(b'HTTP/') or status[1] != b'200':
        raise OSError(f'the proxy refused the tunnel (status {status[1].decode("ascii", "replace")[:3] if len(status) > 1 else "?"})')


def _socks5_connect(sock, ip, port, spec):
    """SOCKS5 CONNECT to the numeric address (``socks5h`` makes no difference here: the name was resolved and vetted before this)."""
    login = spec.credentials != ''
    sock.sendall(b'\x05\x02\x00\x02' if login else b'\x05\x01\x00')
    version, method = _read_exact(sock, 2)
    if version != 5 or method == 0xFF or (method == 2 and not login) or method not in (0, 2):
        raise OSError('the proxy offered no method this client can use')
    if method == 2:
        user, password = spec.username.encode('utf-8'), spec.password.encode('utf-8')
        sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if _read_exact(sock, 2)[1] != 0:
            raise OSError('the proxy refused the login')
    address = ipaddress.ip_address(ip)
    sock.sendall(b'\x05\x01\x00' + (b'\x04' if address.version == 6 else b'\x01') + address.packed + int(port).to_bytes(2, 'big'))
    version, code, _reserved, kind = _read_exact(sock, 4)
    if version != 5 or code != 0:
        raise OSError(f'the proxy refused the connection (SOCKS reply {code})')
    if kind == 3:  # the bound address, read and dropped
        _read_exact(sock, _read_exact(sock, 1)[0] + 2)
    elif kind in (1, 4):
        _read_exact(sock, (4 if kind == 1 else 16) + 2)
    else:
        raise OSError('the proxy answered with an unknown address type')


def open_tunnel(spec, ip, port, timeout):
    """A socket connected to ``ip:port`` THROUGH the proxy: HTTP CONNECT or SOCKS5, always to the numeric address the caller vetted. Raises
    ``OSError`` when the proxy cannot be reached or refuses; there is no direct fallback. ``spec`` must be of an ``IN_PROCESS_SCHEMES`` kind."""
    if spec.scheme not in IN_PROCESS_SCHEMES:
        raise ProxyUnavailable('an https:// proxy cannot carry this check; use an http:// or socks5:// proxy')
    deadline = time.monotonic() + timeout
    sock = connect_proxy(spec, timeout)
    try:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        (_http_connect if spec.scheme == 'http' else _socks5_connect)(sock, ip, port, spec)
        return sock
    except BaseException:
        sock.close()
        raise
