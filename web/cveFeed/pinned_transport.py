"""The vetted lookup of a target name (``resolve``).

This server opens no connection to a target: every probe is a Sentinel's (``agentapi.probe_dispatch``). ``resolve`` stays for the checks that
must refuse a name that points at a prohibited address before any task is built (``tls_audit``, ``openvas_scan``): it returns the numeric
addresses of a name or raises ``ValueError``, and sends nothing to the host (the answer comes from the recursive resolver).
"""
import ipaddress
import socket

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
