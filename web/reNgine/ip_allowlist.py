"""Perimeter IP allowlist: when an App Admin turns it on, every request whose connecting IP is not on
the list is refused before it reaches sessions, auth, or any view (web UI, Django admin, agent API,
MCP, everything). Runs as the second entry in MIDDLEWARE, right after SecurityMiddleware.

The client address comes from reNgine.client_ip: REMOTE_ADDR, or, when the peer is in
CVENGINE_TRUSTED_PROXIES (the shipped nginx), the last X-Forwarded-For hop that is not a trusted proxy.
With no trusted proxies configured X-Forwarded-For is ignored, since any client can set it.

Addresses banned by the input guard (reNgine.input_guard, AbuseBan) are refused here too.
"""
import ipaddress
import logging
import time

logger = logging.getLogger(__name__)

_CACHE_SECONDS = 10
_cache = {'at': 0.0, 'enabled': False, 'networks': []}


def _load():
    from dashboard.models import IpAccessControl, IpAllowlistEntry
    now = time.time()
    if now - _cache['at'] < _CACHE_SECONDS:
        return _cache['enabled'], _cache['networks']
    enabled = IpAccessControl.current().enabled
    networks = []
    if enabled:
        for cidr in IpAllowlistEntry.objects.values_list('cidr', flat=True):
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning('skipping invalid IP allowlist entry %r', cidr)
    _cache.update(at=now, enabled=enabled, networks=networks)
    return enabled, networks


def is_allowed(ip_str):
    """True if the allowlist is off, or ``ip_str`` matches an entry. False (never an exception) otherwise."""
    enabled, networks = _load()
    if not enabled:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    ip = getattr(ip, 'ipv4_mapped', None) or ip
    return any(ip.version == net.version and ip in net for net in networks)


def invalidate_cache():
    _cache['at'] = 0.0


class IpAllowlistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from reNgine.client_ip import client_ip
        from reNgine.input_guard import is_banned
        remote = client_ip(request)
        if is_banned(remote):
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden('Access denied.')
        if not is_allowed(remote):
            logger.warning('blocked request from %s (not on IP allowlist): %s %s', remote, request.method, request.path)
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden('Access denied.')
        return self.get_response(request)
