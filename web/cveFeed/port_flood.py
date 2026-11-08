"""A host that answers on an unusually large number of ports (a tarpit, or a firewall or CDN edge that accepts everything).

The full-port sweep keeps at most ``agentapi.sentinel_dispatch.TARPIT_PORTS`` open ports of such an address (a Sentinel cuts its report, and the
server cuts any report that is longer), so the Services tab shows a short list instead of tens of thousands of rows. This module is the one note
that stands for the rest: one info finding per host (check ``portflood_many_ports``), derived from the ports already stored, never from a new probe.
Info findings carry no score points (the host score reads hygiene findings of severity low or worse). The finding resolves when a later sweep no
longer shows that many open ports. ``CVENGINE_HYGIENE_PORTFLOOD=0`` turns it off.
"""
import logging
import os

from cveFeed.hygiene import INFO, Finding

logger = logging.getLogger(__name__)

CHECK = 'portflood_many_ports'
PREFIX = 'portflood_'
THRESHOLD = 100  # open TCP ports on one address; agentapi.sentinel_dispatch.TARPIT_PORTS is the number a sweep keeps, so a cut list reaches it exactly
NOTE = 'port list truncated: this host answers on an unusually large number of ports (tarpit or filtering device)'
FIX = ('Nothing to fix on your side if this is a CDN edge or a filtering device. If the address is yours, check the firewall rule that answers for '
       'closed ports (a SYN-ACK for everything hides which services are really there) and a tarpit such as LaBrea or portspoof.')


def enabled():
    return os.environ.get('CVENGINE_HYGIENE_PORTFLOOD', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def evaluate(name, counts):
    """The finding of host ``name`` (or None): ``counts`` is ``{address: open TCP ports stored}``."""
    flooded = {a: n for a, n in counts.items() if n >= THRESHOLD}
    if not flooded:
        return None
    addresses = sorted(flooded)
    seen = max(flooded.values())
    evidence = {'source': 'port sweep', 'addresses': addresses[:10], 'open_ports_kept': seen, 'port_list_truncated': True,
                'severity_basis': 'rated info: a list of this length says something about the host, not about a service on it', 'remediation': FIX}
    return Finding(CHECK, INFO, f'{name}: answers on an unusually large number of ports ({seen}+ kept; the list is cut)',
                   f'{NOTE}. The ports shown are the first {seen}; the rest are not stored, and none of them is a finding of its own. Fix: {FIX}', name, evidence)


def findings_for(domain, hosts=None):
    """The port-flood finding of each host of ``domain`` (limited to ``hosts`` when given), from the stored ports."""
    if not enabled() or not domain.project_id:
        return []
    from django.db.models import Count, Q

    from cveFeed.cleartext import _allowed, _newest_rows, _scope
    from startScan.models import OPEN_PORT_STATES, TCP_PROTOCOLS, IpAddress, Port, Subdomain
    wanted, banned = _scope(domain, hosts)
    crowded = (IpAddress.objects.annotate(n=Count('ports', filter=Q(ports__state__in=OPEN_PORT_STATES, ports__protocol__in=TCP_PROTOCOLS)))
               .filter(n__gte=THRESHOLD))
    names = {n for n in Subdomain.objects.filter(target_domain=domain, ip_addresses__in=crowded).order_by().values_list('name', flat=True).distinct()
             if _allowed(n, wanted, banned)}
    if not names:
        return []
    out = []
    for sub in _newest_rows(domain, names, Port.objects.none()):
        counts = {ip.address: ip.n for ip in crowded.filter(pk__in=[i.pk for i in sub.ip_addresses.all()])}
        finding = evaluate(sub.name, counts)
        if finding:
            out.append(finding)
    return out
