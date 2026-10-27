"""Numeric socket connections for in-process scanner probes.

Admission and connection share the same addresses. This does not constrain DNS
lookups or outbound connections made by external scanner processes.
"""
import http.client
import ipaddress
import socket
import time

from targetApp.target_types import is_scannable_ip


def _is_literal(host, ip):
    try:
        return ipaddress.ip_address(host.strip('[]')) == ip
    except ValueError:
        return False


def resolve(host, port):
    """Resolve once, rejecting failed/empty answers or any prohibited address."""
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
        if not is_scannable_ip(str(ip), tailnet=_is_literal(host, ip)):  # a name that resolves into a tailnet is not that tailnet's device
            raise ValueError('probe destination is prohibited')
        # Reconstruct numeric sockaddr; never pass an untrusted hostname to connect.
        numeric = (str(ip), int(port)) if family == socket.AF_INET else (str(ip), int(port), 0, 0)
        item = (family, numeric)
        if item not in pinned:
            pinned.append(item)
    if not pinned:
        raise ValueError('probe destination did not resolve')
    return tuple(pinned)


def open_socket(addresses, timeout):
    """Connect only to vetted numeric addresses within one connection budget."""
    deadline = time.monotonic() + timeout
    last_error = OSError('no probe address available')
    for family, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not is_scannable_ip(str(ip)):
            raise ValueError('probe destination is prohibited')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('probe connection timed out')
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(remaining)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error


class HTTPConnection(http.client.HTTPConnection):
    """Single-origin HTTP, optionally over TLS, with no hostname fallback."""
    def __init__(self, host, port, addresses, timeout, context=None):
        super().__init__(host, port, timeout=timeout)
        self.addresses = addresses
        self.context = context

    def connect(self):
        raw = open_socket(self.addresses, self.timeout)
        try:
            self.sock = self.context.wrap_socket(raw, server_hostname=self.host) if self.context else raw
        except Exception:
            raw.close()
            raise
