"""Whether an operating system guess made from this server's network can be believed.

nmap's OS detection reads how a host answers sixteen crafted TCP, UDP and ICMP probes, some of them malformed on purpose. It is only as good
as the path: the probes must arrive as sent and the answers come back as sent. Two things in a container's path break that, and neither is
a setting of CVEngine's:

* **Docker Desktop (macOS, Windows).** Container traffic leaves through the VM's user-space network stack, which terminates each connection
  and answers for the remote host itself ("How Docker Desktop Networking Works Under the Hood"). The open ports and services are right, since
  the stack makes the real connection; every OS guess describes the stack (one install saw Google Fuchsia on an Ubuntu server and a NAS, and
  an Apple OS X release on an iDRAC). Recognised from the VM kernel (linuxkit, WSL 2, OrbStack).
* **A translating path** (Docker's default bridge network on Linux, iptables NAT with conntrack). A probe with an impossible flag combination
  is marked INVALID by conntrack, is not translated, and its answer is lost: in a measured lab the FIN+PSH+URG probe was answered directly and
  lost behind the NAT, and the top guess for a Linux host changed from "Linux 5.3 - 5.4 (97%)" to "HP P2000 G3 NAS device (93%)". Measured
  by ``cveFeed.path_probe`` (``check_os_path``, daily), which sends that probe and a plain SYN to closed ports of hosts the scans reach.

Both are fixed by taking the translation out of the path (host networking or macvlan on a Linux engine, a Sentinel on the network): the same
lab gave the direct result exactly with either. ``unreliable()`` is True for either cause. ``CVENGINE_OS_DETECTION`` overrides it: ``trust``
believes the guesses anyway, ``distrust`` never does.

What does cross either path is a full TCP connection, so what the services say about themselves still arrives: the distribution in an SSH
or HTTP banner, the operating system CPE and ``ostype`` of nmap's service detection. ``from_services()`` reads the host's operating system
from that, marked as service evidence and not as a packet fingerprint. ``clear_stored_guesses()`` removes the packet guesses stored before.
"""
import logging
import os
import platform
import re

logger = logging.getLogger(__name__)

KERNEL_MARKERS = ('linuxkit', 'microsoft', 'wsl2', 'orbstack')
PATH_CACHE_KEY = 'cvengine:os-path'
PATH_TTL = 8 * 86400  # a verdict is kept this long; the daily check renews it

REASONS = {
    'docker-desktop': ("packet-based operating system detection ran through Docker Desktop's network, which answers for itself and not for "
                       "the host, so no guess is given; the operating system below, where there is one, comes from what the services report"),
    'translated': ("packet-based operating system detection ran through a network path that translates addresses (Docker's default bridge "
                   "network), which loses some of its probes, so no guess is given; the operating system below, where there is one, comes "
                   "from what the services report"),
    'override': 'packet-based operating system detection is switched off (CVENGINE_OS_DETECTION=distrust); the operating system below, '
                'where there is one, comes from what the services report',
}
REASON = REASONS['docker-desktop']
REMEDY = ("Run the scanners on the host's network or give the container its own address on the LAN (docker-compose.hostnet.yml, "
          "docker-compose.macvlan.yml), or run a Sentinel on a Linux machine on the network to be measured. See docs/DEPLOYMENT.md.")


def _kernel():
    try:
        with open('/proc/sys/kernel/osrelease', encoding='ascii') as handle:
            return handle.read().strip()
    except OSError:
        return platform.release()


def path_state():
    """The last measured verdict of the path check (``cveFeed.path_probe.check`` plus ``at``), ``{'state': 'unknown'}`` when none."""
    try:
        from django.core.cache import cache
        return cache.get(PATH_CACHE_KEY) or {'state': 'unknown'}
    except Exception:  # noqa: BLE001 - a cache problem is "not measured", never a failed scan
        return {'state': 'unknown'}


def cause():
    """Why guesses are not believed, or None when they are: ``override`` (CVENGINE_OS_DETECTION=distrust), ``docker-desktop`` (the VM
    kernel), ``translated`` (the measured path)."""
    mode = os.environ.get('CVENGINE_OS_DETECTION', 'auto').strip().lower()
    if mode == 'trust':
        return None
    if mode == 'distrust':
        return 'override'
    kernel = _kernel().lower()
    if any(marker in kernel for marker in KERNEL_MARKERS):
        return 'docker-desktop'
    if path_state().get('state') == 'interfering':
        return 'translated'
    return None


def unreliable():
    return cause() is not None


def reason():
    return REASONS.get(cause() or 'docker-desktop', REASON)


def record_path(result, now=None):
    """Keep the path check's verdict. A change to or from ``interfering`` is logged, and a new ``interfering`` removes the packet guesses
    stored while it was not known. Returns the stored dict."""
    from django.core.cache import cache
    from django.utils import timezone
    earlier = path_state()
    before = earlier.get('state')
    stamp = (now or timezone.now()).isoformat()
    after = result.get('state')
    if after == 'unknown' and before not in (None, 'unknown'):
        # not enough to say this time: the earlier verdict stands until it expires
        kept = {**earlier, 'checked_at': stamp}
        cache.set(PATH_CACHE_KEY, kept, PATH_TTL)
        return kept
    stored = {**result, 'at': stamp}
    cache.set(PATH_CACHE_KEY, stored, PATH_TTL)
    if after != before:
        logger.warning('operating system detection path: %s -> %s %s', before or 'unmeasured', after,
                       f"({result.get('lost')} of {result.get('answered')} hosts lost the malformed probe)" if after in ('interfering', 'direct') else '')
        if after == 'interfering':
            clear_stored_guesses()
    return stored


def status():
    """What an operator sees (get_system_status): whether guesses are believed, why not, how it was measured, and what to do."""
    why = cause()
    measured = path_state()
    out = {'trusted': why is None, 'cause': why, 'path': {k: measured.get(k) for k in ('state', 'answered', 'lost', 'hosts', 'at', 'why')
                                                         if measured.get(k) is not None}}
    if why in ('docker-desktop', 'translated'):
        out['remedy'] = REMEDY
    return out


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
