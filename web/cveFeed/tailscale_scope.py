"""Which tailnet addresses a scanner may be pointed at, and why.

CGNAT space (100.64.0.0/10) and Tailscale's unique-local range (fd7a:115c:a1e0::/48) are "internal" to cvENGINE's target policy
(targetApp.target_types), so on a normal install nothing in them can be scanned. A person who connects a tailnet and turns the
integration on has, by that act, said the tailnet's devices are theirs to scan. This module turns that into something narrow and
checkable instead of a switch for the whole range: an address is authorised only while it is the tailnet address of a device that
a ``TailscaleLink`` imported (``TailscaleDevice`` row, link enabled, device not departed) and the scanner can really reach that
link's tailnet (``scan_reachable``, so a tailnet that is only read through the API never authorises an address that the scanner's
own tailnet might also use for a different machine). Nothing else in the ranges becomes scannable, the link can be switched off at
any time, and the loopback, link-local and metadata blocks are never consulted here. The caller decides which addresses may use this
(target_types.is_scannable_ip): an address presented as the host itself, never one a DNS name resolved to or a person typed.

The set is cached for a short time per process: the policy check runs on hot paths, and only for an address that would otherwise
be refused. A change (sync, disabling the link) clears the cache of the process that made it; other workers follow within
``CACHE_SECONDS``.
"""
import ipaddress
import time

TAILNET_V4 = ipaddress.ip_network('100.64.0.0/10')
TAILNET_V6 = ipaddress.ip_network('fd7a:115c:a1e0::/48')
# 100.100.100.100 is Tailscale's own resolver and 100.100.100.200 a cloud metadata address: never a device, whatever a feed says
RESERVED = (ipaddress.ip_network('100.100.100.0/24'),)
CACHE_SECONDS = 30

_cache = {'at': 0.0, 'addresses': frozenset()}


def parse_address(value):
    """The tailnet IP address ``value`` names, or None: text that is not an address, an address outside the tailnet ranges, one with
    a scope id, and the reserved ones are all None. Device lists come from an outside service, so every address passes through here."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if getattr(ip, 'scope_id', None) is not None:
        return None
    if ip.version == 4 and ip in TAILNET_V4 and not any(ip in net for net in RESERVED):
        return ip
    if ip.version == 6 and ip in TAILNET_V6:
        return ip
    return None


def is_tailnet_address(value):
    return parse_address(value) is not None


def invalidate():
    _cache['at'] = 0.0


def _load():
    """The addresses of devices of enabled links whose tailnet the scanner can reach (cveFeed.tailscale_sync checks that at every sync),
    not departed and still a target. An address that devices of two links both carry is ambiguous (tailnets reuse the 100.x range, and
    only one of them is the scanner's own) and is left out, whether or not the other link is reachable."""
    from cveFeed.models import TailscaleDevice
    rows = TailscaleDevice.objects.filter(departed_at__isnull=True, domain__isnull=False).values_list(
        'link_id', 'addresses', 'link__enabled', 'link__scan_reachable')
    owners, usable = {}, set()
    for link_id, addresses, enabled, reachable in rows.iterator():
        for address in addresses or []:
            ip = parse_address(address)
            if ip is not None:
                owners.setdefault(str(ip), set()).add(link_id)
                if enabled and reachable:
                    usable.add(str(ip))
    return frozenset(address for address in usable if len(owners[address]) == 1)


def authorised_addresses():
    now = time.monotonic()
    if now - _cache['at'] > CACHE_SECONDS or _cache['at'] == 0.0:
        _cache['addresses'] = _load()
        _cache['at'] = now
    return _cache['addresses']


def is_authorised(ip):
    """True when ``ip`` (an ``ipaddress`` object) is the address of an imported tailnet device."""
    ip = parse_address(ip)
    return ip is not None and str(ip) in authorised_addresses()
