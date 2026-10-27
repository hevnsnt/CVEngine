"""Which tailnet addresses a scanner may be pointed at, and why.

CGNAT space (100.64.0.0/10) and Tailscale's unique-local range (fd7a:115c:a1e0::/48) are "internal" to cvENGINE's target policy
(targetApp.target_types), so on a normal install nothing in them can be scanned. A person who connects a tailnet and turns the
integration on has, by that act, said the tailnet's devices are theirs to scan. This module turns that into something narrow and
checkable instead of a switch for the whole range. An address is authorised, for ONE project, only while all of this holds:

  * it is the tailnet address of a device a ``TailscaleLink`` of that project imported, and the device's target is named by that very
    address (so a name that resolves there, or an address typed into another project, is never it);
  * the link is switched on, synced successfully within the last two sync intervals, and can reach its tailnet: the sync proved it
    (``scan_reachable``), and a link that depends on this server's own node also needs that node up right now;
  * no device of another link carries the same address (tailnets reuse the 100.x range, and only one is the scanner's own).

The caller names the project (``is_scannable_ip(address, project=...)``); nothing in the ranges is scannable without it, an address
unwrapped from a mapped, NAT64 or 6to4 form never is, and the loopback, link-local and metadata blocks are never consulted here.

The set is cached for a short time per process: the policy check runs on hot paths, and only for an address that would otherwise be
refused. A change (sync, disabling the link) clears the cache of the process that made it; other workers follow within
``CACHE_SECONDS``.
"""
import ipaddress
import time
from datetime import timedelta

from django.utils import timezone

TAILNET_V4 = ipaddress.ip_network('100.64.0.0/10')
TAILNET_V6 = ipaddress.ip_network('fd7a:115c:a1e0::/48')
# 100.100.100.100 is Tailscale's own resolver and 100.100.100.200 a cloud metadata address: never a device, whatever a feed says
RESERVED = (ipaddress.ip_network('100.100.100.0/24'),)
CACHE_SECONDS = 30

_cache = {'at': 0.0, 'addresses': {}}


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


SYNC_MINUTES = 15  # the beat interval of the sync (migration 0088)
FRESH_FOR = timedelta(minutes=2 * SYNC_MINUTES)  # a link that has not synced successfully this recently authorises nothing


def _load():
    """``{address: project id}`` of the addresses that may be scanned right now. A device counts when it is not departed, its
    target is named by that very address, and its link is switched on, synced successfully (ok or partial) within FRESH_FOR, and
    can reach its tailnet: the sync proved it and, for a link that depends on this server's own node, that node is up now
    (cveFeed.tailscale_local.live). An address that devices of two links both carry is ambiguous (tailnets reuse the 100.x range, and
    only one of them is the scanner's own) and is left out, whether or not the other link qualifies."""
    from cveFeed import tailscale_local
    from cveFeed.models import TailscaleDevice
    rows = TailscaleDevice.objects.filter(departed_at__isnull=True, domain__isnull=False).values_list(
        'link_id', 'addresses', 'project_id', 'domain__name', 'link__enabled', 'link__scan_reachable', 'link__last_status',
        'link__last_sync_at', 'link__routing')
    cutoff = timezone.now() - FRESH_FOR
    owners, usable, node_up = {}, {}, None
    for link_id, addresses, project_id, target, enabled, reachable, status, synced, routing in rows.iterator():
        for address in addresses or []:
            ip = parse_address(address)
            if ip is not None:
                owners.setdefault(str(ip), set()).add(link_id)
                good = enabled and reachable and status in ('ok', 'partial') and synced is not None and synced >= cutoff
                if good and routing == 'auto':
                    node_up = tailscale_local.live() if node_up is None else node_up
                    good = node_up
                if good and str(ip) == target:
                    usable[str(ip)] = project_id
    return {address: project for address, project in usable.items() if len(owners[address]) == 1}


def authorised_addresses():
    now = time.monotonic()
    if now - _cache['at'] > CACHE_SECONDS or _cache['at'] == 0.0:
        _cache['addresses'] = _load()
        _cache['at'] = now
    return _cache['addresses']


def is_authorised(ip, project_id):
    """True when ``ip`` is the tailnet address of an imported device of ``project_id`` that may be scanned now."""
    ip = parse_address(ip)
    return ip is not None and project_id is not None and authorised_addresses().get(str(ip)) == project_id
