"""Whether an operating system guess made from this server's network can be believed.

nmap's OS detection reads how a host answers crafted TCP, UDP and ICMP packets. On Docker Desktop (macOS, and Windows) a container's traffic
leaves through the VM's user-space network stack, which answers for itself, so every host gets a guess that describes that stack (one install
saw Google Fuchsia on an Ubuntu server and a NAS, and an Apple OS X release on an iDRAC). The open ports and services are right; the OS guess
is not. A Linux host, or a Sentinel on the network, measures the real host.

``unreliable()`` is True when this server runs behind such a network: Docker Desktop on macOS (the VM kernel is named linuxkit), on Windows
(WSL 2, "microsoft-standard-WSL2") and OrbStack. ``CVENGINE_OS_DETECTION`` overrides the check: ``trust`` believes the guesses anyway (a setup
known to pass packets through unchanged), ``distrust`` never believes them.

What does cross that network is a full TCP connection, so what the services say about themselves still arrives: the distribution in an SSH or
HTTP banner, the operating system CPE and ``ostype`` of nmap's service detection. ``from_services()`` reads the host's operating system from
that, so a host behind Docker Desktop still has one, named for what it is and marked as service evidence rather than a packet fingerprint.
``clear_stored_guesses()`` removes the packet guesses an earlier version stored on such an install.
"""
import logging
import os
import platform
import re

logger = logging.getLogger(__name__)

KERNEL_MARKERS = ('linuxkit', 'microsoft', 'wsl2', 'orbstack')

REASON = ("packet-based operating system detection was measured through Docker Desktop's network, which answers for itself and not for the "
          "host, so no guess is given; the operating system below, where there is one, comes from what the services report")


def _kernel():
    try:
        with open('/proc/sys/kernel/osrelease', encoding='ascii') as handle:
            return handle.read().strip()
    except OSError:
        return platform.release()


def unreliable():
    mode = os.environ.get('CVENGINE_OS_DETECTION', 'auto').strip().lower()
    if mode == 'trust':
        return False
    if mode == 'distrust':
        return True
    kernel = _kernel().lower()
    return any(marker in kernel for marker in KERNEL_MARKERS)


DISTRO_NAMES = {'ubuntu': 'Ubuntu', 'debian': 'Debian', 'rhel': 'Red Hat Enterprise Linux', 'centos': 'CentOS', 'alpine': 'Alpine Linux'}
_OS_CPE = re.compile(r'cpe:/o:(?P<vendor>[a-z0-9_]+):(?P<product>[a-z0-9_]+)(?::(?P<version>[\w.]+))?', re.IGNORECASE)
BASIS = 'service detection'


def _cpe_name(cpes):
    for cpe in cpes or ():
        match = _OS_CPE.match(str(cpe))
        if not match:
            continue
        vendor, product, version = match.group('vendor').lower(), match.group('product').lower(), match.group('version') or ''
        if product == 'linux_kernel':
            return 'Linux'
        name = ' '.join(word.capitalize() for word in (product if product.startswith(vendor) else f'{vendor}_{product}').split('_'))
        return f'{name} {version}'.strip()
    return ''


def from_services(ports):
    """What the open services say the operating system is, ``{}`` when they do not say: ``{os, source, basis}``. The most specific answer
    wins: a distribution and release (from the banner's package release or the OS CPE), then an operating system CPE, then the ``ostype``
    nmap read. ``basis`` names the port it came from. Nothing here is measured from packets, so it is correct behind NAT."""
    best = None  # (rank, port number, os, basis)
    for port in ports:
        if port.state not in ('', 'open'):
            continue
        extra = port.extra or {}
        service = f'{port.service_name or "service"} on port {port.number}'
        if port.distro:
            name = DISTRO_NAMES.get(port.distro, port.distro.title())
            found = (3, f'{name} {port.distro_release}'.strip(), service)
        elif _cpe_name(extra.get('cpes')):
            found = (2, _cpe_name(extra.get('cpes')), service)
        elif extra.get('ostype'):
            found = (1, str(extra['ostype'])[:60], service)
        else:
            continue
        if best is None or (found[0], -(port.number or 0)) > (best[0], -(best[3] or 0)):
            best = (*found, port.number)
    if not best:
        return {}
    return {'os': best[1][:200], 'source': BASIS, 'basis': best[2][:80]}


def clear_stored_guesses():
    """On an install behind such a network, remove the packet guesses an earlier version stored (nmap's, recognised by their accuracy and
    by not being the host's own report), and fill the address from its services when they name the system. Returns how many addresses
    changed. Idempotent and cheap on an install that measures correctly (it returns at once)."""
    if not unreliable():
        return 0
    from cveFeed import service_intel
    from startScan.models import IpAddress
    changed = 0
    rows = IpAddress.objects.exclude(os_guess='').filter(os_accuracy__isnull=False)
    for ip in rows.prefetch_related('ports').iterator(chunk_size=500):
        fingerprint = ip.fingerprint or {}
        if fingerprint.get('host_reported'):
            continue  # the machine's own report, not a measurement
        fingerprint = {k: v for k, v in fingerprint.items() if k != 'os_matches'}
        ip.os_guess, ip.os_accuracy, ip.fingerprint = '', None, fingerprint
        ip.save(update_fields=['os_guess', 'os_accuracy', 'fingerprint'])
        service_intel.apply_host_facts(ip)
        changed += 1
    if changed:
        logger.info('removed %d operating system guess(es) measured through this network; services name the system where they can', changed)
    return changed
