"""The names of internal hosts, and the printer mark, kept on the host's target row (``targetApp.Domain``).

An internal host is stored by its address (``192.168.1.71``), which stays its identity everywhere. The Sentinel's ``discover`` sweep, run
inside the network, also reports what the address is called: the reverse DNS name its own resolver got (a home or office router answers for
the devices it leased an address to), the host's own mDNS name (``.local``) and its NetBIOS computer name. ``pick`` chooses one in that
order, ``store`` keeps it on the target row at each sweep, and every page, report and MCP answer writes the host as ``label``:
``brwa8934a937f17 (192.168.1.71)``. This server never asks anything of the range itself.

``mark_printers`` sets the printer mark from a fingerprint (``cvengine_scanner.printers.printer_evidence``); the internal pipeline then scans
the host gently (``cveFeed.internal_scan``).
"""
import ipaddress
import logging
import re

from django.utils import timezone

logger = logging.getLogger(__name__)

MAX_NAME = 253
SOURCES = ('rdns', 'mdns', 'netbios')
_LABEL = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$')
_NETBIOS = re.compile(r'^[A-Za-z0-9!#$%&\'()\-.@^_{}~]{1,15}$')
# a router's own suffix for its leases says nothing a person needs: ``johnny.lan`` reads as ``johnny``. A real domain is kept whole.
LOCAL_SUFFIXES = ('.lan', '.local', '.home', '.home.arpa', '.localdomain', '.internal', '.domain')


def _clean(value):
    if not isinstance(value, str):
        return ''
    name = value.strip().rstrip('.')
    if not name or len(name) > MAX_NAME or not all(_LABEL.match(part) for part in name.split('.')):
        return ''
    try:
        ipaddress.ip_address(name)
        return ''  # an address is not a name
    except ValueError:
        pass
    return name


def short(name):
    """``name`` without a home network suffix (``johnny.lan`` is ``johnny``); any other name as it is."""
    lowered = name.lower()
    for suffix in LOCAL_SUFFIXES:
        if lowered.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return name


def pick(item):
    """``(name, source)`` for one ``discover`` host row: its reverse DNS name, else its mDNS name, else its NetBIOS name; ``('', '')`` when it has
    none. Each is plain host name text or it is not used."""
    if not isinstance(item, dict):
        return '', ''
    for value in item.get('hostnames') or []:
        name = _clean(value)
        if name:
            return short(name), 'rdns'
    names = item.get('names') if isinstance(item.get('names'), dict) else {}
    name = _clean(names.get('mdns'))
    if name:
        return short(name), 'mdns'
    netbios = names.get('netbios')
    if isinstance(netbios, str) and _NETBIOS.match(netbios.strip()):
        return netbios.strip(), 'netbios'
    return '', ''


def label(display_name, address):
    """``display_name (address)``, or ``address`` alone when there is no name (or the name is the address)."""
    address = address or ''
    if not display_name or display_name.lower() == address.lower():
        return address
    return f'{display_name} ({address})'


def store(project, found):
    """Keep the names a sweep reported, ``{address: (name, source)}``, on the project's target rows of those addresses. A name that changed is
    replaced; a host that answered no name this time keeps the one it had (one sweep can miss a host that is asleep). Returns how many rows
    changed. The internal host table is rebuilt so every page shows the new names."""
    from targetApp.models import Domain
    from cveFeed import internal_view
    wanted = {ip: pair for ip, pair in found.items() if pair and pair[0]}
    if not wanted:
        return 0
    now = timezone.now()
    changed = 0
    for row in Domain.objects.filter(project=project, name__in=list(wanted)).only('id', 'name', 'display_name', 'display_name_source'):
        name, source = wanted[row.name]
        if row.display_name == name[:MAX_NAME] and row.display_name_source == source:
            Domain.objects.filter(pk=row.pk).update(display_name_at=now)
            continue
        Domain.objects.filter(pk=row.pk).update(display_name=name[:MAX_NAME], display_name_source=source, display_name_at=now)
        changed += 1
    if changed:
        internal_view.invalidate()
    return changed


def mark_printer(project, address, ports, os_guess='', snmp_text=''):
    """Set or clear the printer mark of the project's target row for ``address`` from its fingerprint (``ports`` as the Sentinel reported them).
    Returns the evidence (a list of reasons; empty when the host is not a printer)."""
    from cvengine_scanner import printers
    from targetApp.models import Domain
    from cveFeed import internal_view
    evidence = printers.printer_evidence(ports, os_guess, snmp_text)
    text = '; '.join(evidence)[:300]
    updated = Domain.objects.filter(project=project, name=address).exclude(printer=bool(evidence), printer_evidence=text) \
        .update(printer=bool(evidence), printer_evidence=text)
    if updated:
        internal_view.invalidate()
        logger.info('internal host %s %s a printer (%s)', address, 'is' if evidence else 'is no longer', text or 'no evidence')
    return evidence


def is_printer(project_id, address):
    """Whether the project's target row for ``address`` carries the printer mark (read from the database, not the page table)."""
    from targetApp.models import Domain
    return Domain.objects.filter(project_id=project_id, name=address, printer=True).exists()
