"""The real client IP of a request.

``REMOTE_ADDR`` is the directly connected peer. Behind the shipped nginx that is the proxy, so when the
operator lists the proxy's network in ``CVENGINE_TRUSTED_PROXIES`` (comma separated CIDRs) the address is
taken from ``X-Forwarded-For`` instead: walking from the right, the first hop that is not itself a trusted
proxy. Nothing a client puts at the left of that header can be picked, and with no trusted proxies the
header is ignored entirely (it is attacker-settable).
"""
import ipaddress
import os


def _parse(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return getattr(ip, 'ipv4_mapped', None) or ip  # ::ffff:1.2.3.4 is 1.2.3.4


def trusted_proxies():
    nets = []
    for part in os.environ.get('CVENGINE_TRUSTED_PROXIES', '').split(','):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return nets


def _in(ip, nets):
    return any(ip.version == n.version and ip in n for n in nets)


def client_ip(request):
    """The client address as a string ('' if REMOTE_ADDR is missing or unparseable)."""
    remote = _parse(request.META.get('REMOTE_ADDR', ''))
    if remote is None:
        return ''
    nets = trusted_proxies()
    if not nets or not _in(remote, nets):
        return str(remote)
    for hop in reversed([h for h in request.META.get('HTTP_X_FORWARDED_FOR', '').split(',') if h.strip()]):
        ip = _parse(hop)
        if ip is None:
            return str(remote)  # a malformed hop means the chain cannot be trusted
        if not _in(ip, nets):
            return str(ip)
    return str(remote)
