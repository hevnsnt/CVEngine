"""Numeric socket connections for in-process scanner probes.

Admission and connection share the same addresses. This does not constrain DNS
lookups or outbound connections made by external scanner processes.

When Settings > Proxy is on (``cveFeed.egress_proxy``) the connection goes through the proxy, but the decision stays here: every address is
vetted (``resolve``, and again in ``open_socket``) before anything is sent, and the proxy is only ever asked for that numeric address (an HTTP
CONNECT or SOCKS5 request to the IP, or an absolute-URI request to it for plain HTTP), with the original Host header and TLS server name
untouched. A failed proxy fails the connection; it never falls back to a direct one.
"""
import http.client
import ipaddress
import socket
import time

from cveFeed import egress_proxy
from targetApp.target_types import is_scannable_ip


def _is_literal(host, ip):
    try:
        return ipaddress.ip_address(host.strip('[]')) == ip
    except ValueError:
        return False


def resolve(host, port, project=None):
    """Resolve once, rejecting failed/empty answers or any prohibited address. ``project`` may authorise a tailnet device of its own,
    and only when ``host`` is that address itself: a name that resolves into a tailnet never is."""
    if not isinstance(host, str) or not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise ValueError('invalid probe hostname')
    if any(c in host for c in '/\\@%') or not 0 < int(port) < 65536:
        raise ValueError('invalid probe destination')
    answers = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC,
                                 type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    pinned = []
    for family, kind, proto, _name, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError('unsupported address family')
        ip = ipaddress.ip_address(address[0])
        if not is_scannable_ip(str(ip), project=project if _is_literal(host, ip) else None):
            raise ValueError('probe destination is prohibited')
        # Reconstruct numeric sockaddr; never pass an untrusted hostname to connect.
        numeric = (str(ip), int(port)) if family == socket.AF_INET else (str(ip), int(port), 0, 0)
        item = (family, numeric)
        if item not in pinned:
            pinned.append(item)
    if not pinned:
        raise ValueError('probe destination did not resolve')
    return tuple(pinned)


_AUTO = object()


def open_socket(addresses, timeout, project=None, host=None, proxy=_AUTO):
    """Connect only to vetted numeric addresses within one connection budget (``project`` as for ``resolve``: the vetted address of a
    tailnet device of that project is vetted again here, but a name's answer was already refused there). With Settings > Proxy on, the
    connection is a tunnel through the proxy to that same vetted address (``host``, when given, is the name, for the proxy bypass list;
    ``proxy`` is the choice a caller already made, None for a direct connection)."""
    if proxy is _AUTO:
        proxy = _proxy_for(addresses, host)
    deadline = time.monotonic() + timeout
    last_error = OSError('no probe address available')
    for family, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not is_scannable_ip(str(ip), project=project):
            raise ValueError('probe destination is prohibited')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('probe connection timed out')
        if proxy is not None:
            try:
                return egress_proxy.open_tunnel(proxy, str(ip), address[1], remaining)
            except OSError as exc:
                last_error = exc
                continue
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(remaining)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error


def _proxy_for(addresses, host=None, schemes=egress_proxy.IN_PROCESS_SCHEMES):
    """The proxy this connection goes through, None for a direct one: the setting is off, or the destination (its name or any vetted address)
    is loopback or one of this stack's own services."""
    if not egress_proxy.configured():
        return None
    if (host is not None and egress_proxy.bypass(host)) or any(egress_proxy.bypass(address[0]) for _family, address in addresses):
        return None
    return egress_proxy.pick(schemes=schemes)


class HTTPConnection(http.client.HTTPConnection):
    """Single-origin HTTP, optionally over TLS, with no hostname fallback. Through an HTTP proxy, plain HTTP is sent as an absolute-URI request
    to the vetted address (the proxy then needs no CONNECT permission for the port); TLS, and every SOCKS proxy, use a tunnel."""
    def __init__(self, host, port, addresses, timeout, context=None, project=None):
        super().__init__(host, port, timeout=timeout)
        self.addresses = addresses
        self.context = context
        self.project = project
        self._forward = None  # (proxy, 'ip:port') while a plain request is forwarded by an HTTP proxy

    def connect(self):
        self._forward = None
        proxy = _proxy_for(self.addresses, self.host)
        if proxy is not None and proxy.scheme == 'http' and self.context is None:
            self.sock = self._connect_forward(proxy)
            return
        raw = open_socket(self.addresses, self.timeout, project=self.project, host=self.host, proxy=proxy)
        try:
            self.sock = self.context.wrap_socket(raw, server_hostname=self.host) if self.context else raw
        except Exception:
            raw.close()
            raise

    def _connect_forward(self, proxy):
        """Plain HTTP through an HTTP proxy: vet every address as ``open_socket`` does, connect to the proxy, remember the first vetted address
        to name in each request line."""
        for _family, address in self.addresses:
            if not is_scannable_ip(str(ipaddress.ip_address(address[0])), project=self.project):
                raise ValueError('probe destination is prohibited')
        if not self.addresses:
            raise OSError('no probe address available')
        _family, address = self.addresses[0]
        numeric = f'[{address[0]}]' if ':' in address[0] else address[0]
        sock = egress_proxy.connect_proxy(proxy, self.timeout)
        self._forward = (proxy, f'{numeric}:{address[1]}')
        return sock

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        forward = self._forward is not None and url.startswith('/')
        if forward:  # absolute-URI to the vetted address; the Host header stays the original name (http.client would derive it from the URL)
            url = f'http://{self._forward[1]}{url}'
        super().putrequest(method, url, skip_host=skip_host or forward, skip_accept_encoding=skip_accept_encoding)
        if forward and not skip_host:
            name = f'[{self.host}]' if ':' in self.host else self.host
            self.putheader('Host', name if self.port == 80 else f'{name}:{self.port}')
        if forward and self._forward[0].credentials:
            self.putheader('Proxy-Authorization', self._forward[0].authorization())

    def getresponse(self):
        response = super().getresponse()
        if self._forward is not None and response.status == 407:
            response.close()
            raise OSError('the proxy refused the login or asked for one')
        return response
