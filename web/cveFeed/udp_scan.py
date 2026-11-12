"""Background UDP exposure sweep: a slow, polite look at a short list of UDP ports of ONE in-scope IP at a time, run by a Sentinel.

The TCP sweep (cveFeed.fullscan) never touches UDP, and the services that matter most for exposure there (DNS, NTP, SNMP, IKE, IPMI,
SSDP, memcached) all speak it. A scanner scans a small curated list (``DEFAULT_PORTS``, the scanner library's) at a low rate, one IP at a time, each
IP at most once a week (the ledger service ``udp-scan``). It rides the same celery-beat firing as the TCP sweep (``background_full_scan`` calls
``kick``) but runs on a queue of its own (``udp_queue``), and has its own switch (``CVENGINE_UDPSCAN``, on by default). Like the other slow sweeps it
stops while scanning is paused, scans no address an organization excluded or that is not scannable, and skips a project whose bug bounty
engagement has not confirmed automated testing. Like the TCP full-port sweep, it also defers its whole firing, instance-wide,
while any project still has a host missing core first-pass coverage (see cveFeed.coverage_topup.backlog_exists): a deep UDP
sweep of one address is never worth more than a first pass over every host.

Nothing runs on this server. Each address goes to a live, eligible Sentinel (``agentapi.sentinel_dispatch.try_nmap_udp``); with none able to take it
the address stays due (``ScannerUnavailable``) and is never scanned here. A Sentinel's UDP report travels as the scanner's own raw XML, not pre-parsed
JSON: UDP's state vocabulary and script output are read correctly only by the scanner library's ``parse_xml`` (``cveFeed.port_inventory.parse_xml``),
so that one function, hardened against hostile XML, is the sole place a report is ever turned into a record.

What a UDP answer means. UDP has no handshake: a port that replies is ``open``; one that sends an ICMP port-unreachable is ``closed``;
silence is ``open|filtered`` (open but quiet, or dropped by a firewall), which a scanner cannot tell apart. ``-sV`` sends its service
probes to the ``open|filtered`` ports and promotes the ones that answer to ``open``, so only a port that answered is ever stored as
``open`` (and so in the exposure, the heat, the CVE evidence and the search). A port that stayed silent is stored as ``open|filtered``
only on a host that answered other probes with a port-unreachable (so the silence is selective, not a firewall dropping everything),
and is never counted as open anywhere (``startScan.models.OPEN_PORT_STATES``). A port that was open and goes silent keeps its state
for ``UNANSWERED_LIMIT`` sweeps, because one lost datagram is not a closed port.

What it records: the open UDP ports and their service, product and version (the same ``Port`` rows and the same CVE correlation as
TCP services, keyed by number and protocol, so UDP 161 and TCP 161 are two rows); product and version a script proved when ``-sV``
named none (SNMP sysDescr, SSDP server string, NTP readvar); and findings for the services that should not answer the internet
(memcached, SNMP with the public community, NTP control queries, SSDP, IPMI). Findings are derived from the stored ports of each
host, never from one run, so a host with two addresses keeps what the other address showed.
"""
import json
import logging
import os
import re
import time
from datetime import timedelta

from django.utils import timezone

from cvengine_scanner import flags as scan_flags

logger = logging.getLogger(__name__)

SERVICE = 'udp-scan'  # ledger: one sweep per IP per week (CVENGINE_TTL_UDP_SCAN, hours)
FAILED_SERVICE = 'udp-scan-failed'  # an IP whose sweep failed is asked again tomorrow, not at the next firing
NO_IPV6_SERVICE = 'udp-scan-noipv6'  # an IPv6 address the Sentinel had no route to: not scanned, not failed (one probe a day, see ``_ipv6_blocked``)
NO_IPV6_KEY = 'cvengine:udpscan:noipv6'  # set for a day when a Sentinel said it has no IPv6 route: no IPv6 address is sent until it expires
NO_IPV6_TTL = 24 * 3600
QUEUE = 'udp_queue'
CLAIM_KEY = 'cvengine:udpscan'
CLAIM_TTL = 3 * 3600
STATUS_KEY = 'cvengine:udpscan:status'
STATUS_TTL = 30 * 24 * 3600
RUN_BUDGET_SECONDS = 8 * 60  # a firing starts no new IP after this, so it ends before the next one
MAX_ELIGIBLE = 5000  # in-scope addresses looked at per pick
MAX_CHECKED = 50  # scope checks (they resolve names) per pick
MAX_EMPTY_PER_DAY = 3  # times in 24 hours a scanner may return an unusable report for one address before it is asked again tomorrow
EMPTY_TTL = 24 * 3600
EMPTY_KEY = 'cvengine:udpscan:empty:'
MAX_WAITING = 3  # addresses no scanner could take that end a firing: a scanner that is offline is offline for the rest too
MAX_FINDING_HOSTS = 10  # names of one address that get its findings
MAX_PORTS = 64
UNANSWERED_LIMIT = 2  # sweeps in a row a port that was open may stay silent before it is no longer called open
OPEN_FILTERED = 'open|filtered'

# The curated list: what matters for exposure, not what is common (the scanner library's UDP_PORTS; each is documented in docs/PIPELINE.md).
DEFAULT_PORTS = scan_flags.UDP_PORTS
PORT_NOTES = {
    53: 'DNS', 67: 'DHCP server', 68: 'DHCP client', 69: 'TFTP', 123: 'NTP', 137: 'NetBIOS name service', 161: 'SNMP',
    500: 'IKE (IPsec VPN)', 514: 'syslog', 623: 'IPMI (BMC)', 1194: 'OpenVPN', 1812: 'RADIUS authentication',
    1813: 'RADIUS accounting', 1900: 'SSDP (UPnP)', 4500: 'IPsec NAT-T', 5060: 'SIP', 5353: 'mDNS', 11211: 'memcached',
}
INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4

# Findings: check name -> (port, severity, what it is, why it is that severity, the fix, the script that proves it or '').
# A finding with a script needs that script's answer on the port, otherwise the answer alone (state ``open``: a reply came back).
RISKY = {
    'udp_memcached': (11211, HIGH, 'memcached answers on UDP',
                      'memcached answers any UDP datagram without authentication: it can be used to reflect and amplify a flood '
                      'at a victim (amplification of tens of thousands of times), and to read or change the cache.',
                      'Do not expose memcached. Bind it to localhost or a private interface, disable UDP (-U 0), and firewall '
                      'port 11211 from the internet.', ''),
    'udp_snmp_public': (161, HIGH, 'SNMP answers the default "public" community',
                        'The device handed its system description to the default read community, so anyone can read its '
                        'configuration and network details, and the same community is often accepted for more.',
                        'Disable SNMPv1 and v2c, or change the community to a long secret and restrict it to the management '
                        'network. Use SNMPv3 with authentication and encryption, and firewall UDP 161 from the internet.',
                        'snmp-sysdescr'),
    'udp_ntp_readvar': (123, LOW, 'NTP answers control queries (readvar)',
                        'The server answers NTP mode 6 control queries from any source: it discloses its version, system and '
                        'configuration, and can be used to reflect a flood at a victim.',
                        'Restrict control queries (restrict ... noquery in ntp.conf, or the equivalent) and update ntpd. A public '
                        'time server should answer time requests only.', 'ntp-info'),
    'udp_ssdp': (1900, MEDIUM, 'SSDP (UPnP discovery) answers',
                 'A UPnP discovery service answers the internet: it describes the device, can be used to reflect and amplify a '
                 'flood, and often fronts a UPnP control interface that lets software open ports in the firewall.',
                 'Disable UPnP on internet-facing interfaces and block UDP 1900 at the border.', ''),
    'udp_ipmi': (623, HIGH, 'IPMI (the server management controller) answers',
                 'The baseboard management controller answers the internet. IPMI 2.0 discloses password hashes to anyone who asks '
                 '(RAKP, CVE-2013-4786) and the controller gives full control of the machine.',
                 'Put the management interface on a separate management network, never on a public address, and block UDP 623.', 'ipmi-version'),
}
SEVERITY_WORDS = {INFO: 'info', LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical'}


_last_status = {}
_empty_local = {}
_ipv6_local = {}


class UdpScanError(RuntimeError):
    """The sweep of one address produced no usable result."""


class NoIpv6Route(UdpScanError):
    """The Sentinel had no route to an IPv6 address: nmap finished and scanned no host. A fact about the Sentinel, not a failed scan of the
    address; ``scan_ip`` records it once and stops sending IPv6 addresses (``_ipv6_blocked``) instead of failing each one."""


# ----------------------------------------------------------------------------- settings

def _truthy(value):
    return str(value).strip().lower() not in ('0', 'false', 'no', 'off')


def enabled():
    """CVENGINE_UDPSCAN: on unless it is 0/false/no/off."""
    return _truthy(os.environ.get('CVENGINE_UDPSCAN', '1'))


def ports():
    """The UDP ports a scanner sweeps: the scanner library's curated list (``DEFAULT_PORTS``)."""
    return list(DEFAULT_PORTS)


def _store():
    from reNgine import resources
    return getattr(resources.get_store(), 'r', None)


def record_status(state, reason='', **extra):
    """Remember what the last firing found out (``ok``, ``unavailable`` with the reason, ``paused``) where the web container can read it:
    the capability belongs to the worker container, so only the worker can say. Never fatal."""
    value = {'state': state, 'reason': reason, 'at': timezone.now().isoformat(), **extra}
    _last_status.update(value=value)  # this process's own copy, for a store that cannot be reached
    try:
        client = _store()
        if client is not None:
            client.set(STATUS_KEY, json.dumps(value), ex=STATUS_TTL)
    except Exception:  # noqa: BLE001
        logger.warning('could not record the UDP sweep status', exc_info=True)
    return value


def recorded_status():
    try:
        client = _store()
        raw = client.get(STATUS_KEY) if client is not None else None
        return json.loads(raw) if raw else _last_status.get('value')
    except Exception:  # noqa: BLE001
        return _last_status.get('value')


def status(problems=None):
    """For the system status: whether the sweep is on and able to run, the last thing it said, and what it holds. ``problems`` (a list)
    receives a line when the sweep cannot run."""
    from cveFeed import ledger
    from startScan.models import Port
    last = recorded_status() or {}
    if not enabled():
        state, reason = 'off', 'CVENGINE_UDPSCAN is off'
    else:
        state, reason = last.get('state') or 'waiting', last.get('reason') or ''
    if state == 'unavailable' and problems is not None:
        problems.append(f'udp scan: {reason}')
    cutoff = timezone.now() - timedelta(seconds=ledger.ttl(SERVICE))
    from cveFeed.models import ServiceRun
    return {'enabled': enabled(), 'state': state, 'reason': reason, 'last_firing_at': last.get('at'),
            'ports': ports(), 'ips_covered': ServiceRun.objects.filter(service=SERVICE, status='done', finished_at__gte=cutoff).count(),
            'open_udp_ports': Port.objects.filter(protocol='udp', state='open').count(),
            'unanswered_udp_ports': Port.objects.filter(protocol='udp', state=OPEN_FILTERED).count()}


# ----------------------------------------------------------------------------- choosing the address

def asset_of(ip):
    """The ledger key of one IpAddress row: the same address in two organizations is two rows, so two assets."""
    address = (ip.address or '').strip().lower()
    return f'{address}@{ip.org_id}' if ip.org_id else address


def due(limit=MAX_ELIGIBLE):
    """In-scope addresses whose last sweep is older than the TTL, never-swept first, then the longest waiting, minus the ones that
    failed recently. In scope is the TCP sweep's: attached to an active host of a project, not a CDN. A project whose bug bounty
    engagement has not confirmed automated testing does not count (the helper the conductor and the bucket sweep use), so an address
    reached only through such a project is never scanned."""
    from django.db.models import Exists, OuterRef
    from cveFeed import fullscan, ledger
    from cveFeed.conductor import bounty_blocked_projects
    from startScan.models import IpAddress
    attached = fullscan.active_attached(OuterRef('pk')).exclude(target_domain__project_id__in=bounty_blocked_projects())
    rows = list(IpAddress.objects.filter(Exists(attached), is_cdn=False, address__isnull=False)
                .exclude(address='').order_by('id')[:limit])
    assets = {asset_of(ip): ip for ip in rows}
    fresh = ledger.fresh(SERVICE, assets)
    failed = ledger.fresh(FAILED_SERVICE, assets) | ledger.fresh(NO_IPV6_SERVICE, assets)  # an IPv6 address a Sentinel had no route to waits out its day too
    last = ledger.last_run(SERVICE, assets)
    epoch = timezone.now() - timedelta(days=36500)
    wanted = [(last.get(asset) or epoch, ip.id, ip) for asset, ip in assets.items() if asset not in fresh and asset not in failed]
    return [ip for _when, _pk, ip in sorted(wanted, key=lambda item: item[:2])]


def pick(skip=()):
    """The next IpAddress to scan, or None. The gate is the TCP sweep's own (``fullscan.in_scope``): a scannable address, a name that
    is not excluded or archived and does not resolve anywhere blocked, never a shared platform's edge. ``skip`` holds ids this firing
    already found no scanner for."""
    from cveFeed import fullscan
    no_ipv6 = _ipv6_blocked()  # a Sentinel with no IPv6 route was found today: IPv6 addresses wait for the next probe, silently
    for ip in due()[:MAX_CHECKED]:
        if ip.pk in skip or (no_ipv6 and _is_ipv6(ip.address)):
            continue
        try:
            if fullscan.in_scope(ip):
                return ip
        except Exception:  # noqa: BLE001 - one odd row must not stop the rotation
            logger.warning('udp scan: could not check %s', ip.address, exc_info=True)
    return None


# ----------------------------------------------------------------------------- the address, and what a report says about it

def normalize_address(value):
    """One spelling of an IP address, for comparing the server's string with the one a scanner's report carries: nmap prints an IPv6 address
    in its own compressed form (``2600:1900::1a0:0``), the database may hold ``2600:1900:0:0::1a0:0``, ``...::`` with a trailing ``::``,
    upper case, ``[brackets]`` or a ``%zone``. IPv4 and anything that is not an address come back stripped and lower-cased."""
    import ipaddress
    text = str(value or '').strip().lower()
    if text.startswith('[') and text.endswith(']'):
        text = text[1:-1]
    text = text.split('%', 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


_HOSTS = re.compile(r'<hosts\b[^>]*>')
_FINISHED = re.compile(r'<finished\b[^>]*\bexit="success"')


def report_counts(xml_text):
    """``(up, down, total)`` hosts nmap says it scanned, or None when the report has no ``finished ... exit="success"`` marker (cut short or
    not nmap's)."""
    xml_text = xml_text or ''
    if not _FINISHED.search(xml_text):
        return None
    found = _HOSTS.search(xml_text)
    if not found:
        return None
    try:
        values = {k: int(re.search(rf'\b{k}="(\d+)"', found.group(0)).group(1)) for k in ('up', 'down', 'total')}
    except (AttributeError, ValueError):
        return None
    return values['up'], values['down'], values['total']


def host_from_report(xml_text, address):
    """The parsed host record of ``address`` in a Sentinel's raw ``-sU`` XML. The one reader, used by ``agentapi.sentinel_dispatch.try_nmap_udp``.

    - the host is in the report (compared by ``normalize_address`` on both sides): its record.
    - nmap finished and counted the address as scanned but wrote no host element (a host that did not answer on its own link: nmap leaves
      a down host out): a clean record, ``{'ip', 'status': 'down', 'ports': []}``, so the sweep completes with no open ports.
    - nmap finished but scanned nothing (``total`` 0: no route to the address, e.g. a Sentinel with no IPv6, or a name it could not
      resolve): ``UdpScanError``. Nothing was sent, so this is not a result and not a wait: the address is asked again tomorrow.
    - an empty, cut short, or other-addresses-only report: ``ScannerReportedNothing`` (counted, see ``MAX_EMPTY_PER_DAY``).
    """
    from cveFeed.port_inventory import parse_xml
    from reNgine.resources import ScannerReportedNothing
    want = normalize_address(address)
    hosts = parse_xml(xml_text or '')
    host = next((h for h in hosts if normalize_address(h.get('ip')) == want), None)
    if host is not None:
        return host
    counts = report_counts(xml_text)
    if counts is None:
        raise ScannerReportedNothing('nmap_udp', 'a Sentinel returned an empty or unfinished report for the address')
    up, down, total = counts
    if hosts:
        named = ', '.join(sorted({str(h.get('ip')) for h in hosts})[:3])
        raise ScannerReportedNothing('nmap_udp', f'a Sentinel\'s report named other addresses only ({named})')
    if total == 0 and _is_ipv6(want):
        raise NoIpv6Route(f'nmap scanned no host for {address}: the Sentinel has no route to IPv6 addresses')
    if total == 0:
        raise UdpScanError(f'nmap scanned no host for {address}: the Sentinel could not reach it (no route to the address, or a name it could not resolve)')
    return {'ip': want, 'status': 'down', 'ports': [], 'extraports': [], 'scanned_udp': set()}


def _is_ipv6(address):
    import ipaddress
    try:
        return ipaddress.ip_address(normalize_address(address)).version == 6
    except ValueError:
        return False


def _ipv6_blocked(now=None):
    """Whether a Sentinel said, within the last day, that it cannot reach IPv6 addresses (Redis, else this process)."""
    try:
        client = _store()
        if client is not None:
            return bool(client.exists(NO_IPV6_KEY))
    except Exception:  # noqa: BLE001 - a flag that cannot be read must not stop the sweep
        logger.warning('could not read the no-IPv6 flag', exc_info=True)
    now = time.time() if now is None else now
    return now - _ipv6_local.get('at', -NO_IPV6_TTL) < NO_IPV6_TTL


def _ipv6_block():
    _ipv6_local['at'] = time.time()
    try:
        client = _store()
        if client is not None:
            client.set(NO_IPV6_KEY, '1', ex=NO_IPV6_TTL)
    except Exception:  # noqa: BLE001
        logger.warning('could not set the no-IPv6 flag', exc_info=True)


def _ipv6_unblock():
    _ipv6_local.clear()
    try:
        client = _store()
        if client is not None:
            client.delete(NO_IPV6_KEY)
    except Exception:  # noqa: BLE001
        pass


def _empty_count(asset, now=None):
    """Count one unusable report for ``asset`` today and return how many there have been in the last 24 hours (Redis, else this process)."""
    key = EMPTY_KEY + asset
    try:
        client = _store()
        if client is not None:
            count = int(client.incr(key))
            if count == 1:
                client.expire(key, EMPTY_TTL)
            return count
    except Exception:  # noqa: BLE001 - a counter that cannot be read must not stop the sweep
        logger.warning('could not count an empty UDP report', exc_info=True)
    now = time.time() if now is None else now
    stamps = [t for t in _empty_local.get(asset, []) if now - t < EMPTY_TTL] + [now]
    _empty_local[asset] = stamps
    return len(stamps)


def _empty_reset(asset):
    _empty_local.pop(asset, None)
    try:
        client = _store()
        if client is not None:
            client.delete(EMPTY_KEY + asset)
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------------------- reading the answer

_SYSDESCR = (
    (re.compile(r'Cisco IOS XE Software.*?Version\s+(\d+(?:\.\d+)+[\w.]*)', re.I | re.S), 'Cisco IOS XE'),
    (re.compile(r'Cisco IOS Software.*?Version\s+(\d+\.\d+\([\w.]+\)[\w]*)', re.I | re.S), 'Cisco IOS'),
    (re.compile(r'JUNOS\s+(\d+\.\d+[\w.\-]*)', re.I), 'Junos OS'),
)
_UPNP = (
    (re.compile(r'MiniUPnPd/(\d+(?:\.\d+)+)', re.I), 'MiniUPnPd'),
    (re.compile(r'Portable SDK for UPnP devices/(\d+(?:\.\d+)+)', re.I), 'libupnp'),
)
_NTP = re.compile(r'ntpd\s+(\d+\.\d+\.\d+(?:p\d+)?)', re.I)


def identify(rec):
    """``(product, version, cpe)`` a script proved for an open UDP service when ``-sV`` named no product, or None. Only a few
    patterns whose product and version are stated outright: SNMP sysDescr of Cisco IOS, IOS XE and Junos, the SSDP server string of
    MiniUPnPd and the portable UPnP SDK, and the NTP readvar version. A guess from a kernel string is not evidence."""
    scripts = rec.get('scripts') or {}
    if rec['number'] == 161 and scripts.get('snmp-sysdescr'):
        for pattern, product in _SYSDESCR:
            found = pattern.search(scripts['snmp-sysdescr'])
            if found:
                return product, found.group(1)[:60], ''
    if rec['number'] == 1900:
        text = ' '.join([scripts.get('upnp-info') or '', rec.get('banner') or '', rec.get('service_extra') or ''])
        for pattern, product in _UPNP:
            found = pattern.search(text)
            if found:
                return product, found.group(1), ''
    if rec['number'] == 123 and scripts.get('ntp-info'):
        found = _NTP.search(scripts['ntp-info'])
        if found:
            return 'NTP', found.group(1), f'cpe:/a:ntp:ntp:{found.group(1)}'
    return None


def classify(host):
    """What one UDP scan report says per UDP port: ``{number: state}`` for every port the run probed (a port the scanner summarised in
    ``extraports`` takes that state), and whether the host answered anything (an ``open`` reply or a ``closed`` port-unreachable)."""
    states = {r['number']: r.get('state') or '' for r in host.get('ports', []) if r.get('protocol') == 'udp' and r.get('number')}
    summarised = [s for s in (host.get('extraports') or ()) if s]
    if len(summarised) == 1:
        for number in (host.get('scanned_udp') or set()) - set(states):
            states[number] = summarised[0]
    answered = any(state in ('open', 'closed') for state in states.values())
    return states, answered


def _signature(ip):
    return {p.number: (p.product, p.version) for p in ip.ports.filter(protocol='udp', state='open')}


def record_run(ip, host, now=None):
    """Store one UDP scan report for ``ip``. Returns ``{'open': [...], 'unanswered': [...], 'closed': [...], 'changed': [...]}`` (port
    numbers; ``changed`` are open ports that are new or whose product or version changed). A silent port gets a row only when it has
    none and the host answered something else (see the module note); an existing row is judged by the rules below."""
    from cveFeed import port_inventory
    if host.get('status') == 'down' and not host.get('ports'):  # the address did not answer at all: a finished sweep with nothing to store
        return {'open': [], 'closed': [], 'unanswered': [], 'changed': [], 'down': True}
    now = now or timezone.now()
    states, answered = classify(host)
    existing = {p.number: p for p in ip.ports.filter(protocol='udp')}
    before = _signature(ip)
    keep = []
    for rec in host.get('ports', []):
        if rec.get('protocol') != 'udp' or not rec.get('number'):
            continue
        rec = {**rec, 'scripts': scan_flags.reviewed_scripts(rec.get('scripts'))}
        if rec.get('state') == 'open':
            if not rec.get('product'):
                proved = identify(rec)
                if proved:
                    rec.update(product=proved[0], version=proved[1], method='probed', **({'cpe': proved[2], 'cpes': [proved[2]]} if proved[2] else {}))
            keep.append(rec)
        elif rec.get('state') == OPEN_FILTERED and answered and rec['number'] not in existing:
            keep.append({**rec, 'scripts': {}, 'banner': '', 'product': '', 'version': ''})
    port_inventory.persist_inventory([{**host, 'ports': keep, 'scanned': None, 'scanned_udp': None, 'os_guess': ''}], org_id=ip.org_id)
    stored = {p.number: p for p in ip.ports.filter(protocol='udp')}
    open_now = []
    for number, port in stored.items():
        state = states.get(number)
        if state is None:  # not probed this run: unchanged
            continue
        extra = dict(port.extra or {})
        fields = []
        if state == 'open':
            extra.pop('udp_unanswered', None)
            extra['udp_scanned_at'] = now.isoformat()
            rec = next(r for r in keep if r['number'] == number and r.get('state') == 'open')
            if not rec['scripts']:  # this run is the whole truth: a script that no longer answers is no longer evidence
                extra.pop('scripts', None)
                extra.pop('script_text', None)
            open_now.append(number)
        elif state == 'closed':
            extra.pop('udp_unanswered', None)
            if port.state != 'closed':
                port.state = 'closed'
                fields.append('state')
        elif port.state == 'open' and state in (OPEN_FILTERED, 'filtered'):
            silent = int(extra.get('udp_unanswered') or 0) + 1
            extra['udp_unanswered'] = silent
            if silent >= UNANSWERED_LIMIT:
                port.state = OPEN_FILTERED
                fields.append('state')
        elif port.state == 'closed' and state == OPEN_FILTERED and answered:
            port.state = OPEN_FILTERED
            fields.append('state')
        if extra != (port.extra or {}):
            port.extra = extra
            fields.append('extra')
        if fields:
            port.save(update_fields=sorted(set(fields)))
    after = _signature(ip)
    return {'open': sorted(open_now), 'closed': sorted(n for n, s in states.items() if s == 'closed'),
            'unanswered': sorted(n for n, s in states.items() if s in (OPEN_FILTERED, 'filtered')),
            'changed': sorted(n for n, sig in after.items() if before.get(n) != sig)}


# ----------------------------------------------------------------------------- findings

def evaluate(name, ports_):
    """The findings of one host from its stored UDP ports (``Port`` rows of every address it has): a list of ``hygiene.Finding``. Only a
    port that answered (state ``open``) counts, and a finding that needs a script needs that script's output on the port."""
    from cveFeed.hygiene import Finding
    found = {}
    for port in ports_:
        if port.protocol != 'udp' or port.state != 'open':
            continue
        scripts = (port.extra or {}).get('scripts') or {}
        for check, (number, severity, what, why, fix, script) in RISKY.items():
            if port.number != number or (script and not scripts.get(script)):
                continue
            row = found.setdefault(check, {'severity': severity, 'what': what, 'why': why, 'fix': fix, 'ports': [], 'seen': {}})
            row['ports'].append(port)
            if script:
                row['seen'][port.id] = str(scripts[script])[:200]
    out = []
    for check, row in found.items():
        addresses = sorted({a for p in row['ports'] for a in p.ports.values_list('address', flat=True)})
        evidence = {'source': 'nmap -sU', 'protocol': 'udp', 'port': row['ports'][0].number, 'addresses': addresses[:10],
                    'service': row['ports'][0].service_name or '', 'product': row['ports'][0].product or '',
                    'version': row['ports'][0].version or '', 'severity_basis': row['why'], 'remediation': row['fix']}
        if row['seen']:
            evidence['answer'] = next(iter(row['seen'].values()))
        out.append(Finding(check, row['severity'], f'{name}: {row["what"]} ({row["ports"][0].number}/udp)',
                           f'{row["why"]} Fix: {row["fix"]}', name, evidence))
    return out


def finding_hosts(ip):
    """``[(domain, name)]`` of the active hosts on ``ip`` that may carry its findings: not excluded and not archived."""
    from cveFeed import fullscan
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import excluded_names
    from targetApp.models import Domain
    rows = list(fullscan.active_attached(ip).values_list('name', 'target_domain_id', 'target_domain__project_id').distinct()[:MAX_FINDING_HOSTS * 3])
    banned, out, seen = {}, [], set()
    domains = {d.pk: d for d in Domain.objects.filter(pk__in={r[1] for r in rows})}
    for name, domain_id, project in rows:
        if project not in banned:
            banned[project] = excluded_names(project) | archived_names(project)
        key = (domain_id, name.lower())
        if name.lower().rstrip('.') in banned[project] or key in seen:
            continue
        seen.add(key)
        out.append((domains[domain_id], name))
    return out[:MAX_FINDING_HOSTS]


def host_udp_ports(domain, name):
    """The UDP ``Port`` rows on every address the named host has (any scan of that target)."""
    from startScan.models import IpAddress, Port
    ips = IpAddress.objects.filter(ip_addresses__target_domain=domain, ip_addresses__name=name)
    return list(Port.objects.filter(ports__in=ips, protocol='udp').distinct())


def store_findings(ip):
    """Make the UDP findings of every host on ``ip`` agree with the stored ports: record what they show, resolve what they no longer
    do. Returns the number of findings now open. Never fatal."""
    from cveFeed import hygiene
    total, by_domain = 0, {}
    try:
        for domain, name in finding_hosts(ip):
            found = evaluate(name, host_udp_ports(domain, name))
            total += len(found)
            hygiene.store_findings(domain, found, hosts={name}, owns=lambda check: check.startswith('udp_'))
            by_domain[domain.pk] = domain
        for domain_id in by_domain:
            try:  # the medium and worse findings are triaged (impact and a fix), as after every hygiene check
                from cveFeed import triage
                triage.triage_hygiene(domain_id)
            except Exception:  # noqa: BLE001
                logger.exception('could not triage the UDP findings of target %s', domain_id)
    except Exception:  # noqa: BLE001
        logger.exception('could not store the UDP findings of %s', ip.address)
    return total


# ----------------------------------------------------------------------------- the sweep

def queue_retests(ip, numbers, project, pipeline=None):
    """The hosts on ``ip`` go through the re-test pipeline (cveFeed.retest) once after a UDP service appeared or changed, so the new
    evidence is correlated, triaged and diffed like a TCP one. One re-test per host per day (the retest ledger). Returns the names."""
    from cveFeed import fullscan, ledger, retest
    queued = []
    by_domain = {}
    for domain_id, name, project_id in fullscan.active_attached(ip).values_list('target_domain_id', 'name', 'target_domain__project_id'):
        by_domain.setdefault((domain_id, project_id), set()).add(name.lower())
    for (domain_id, project_id), names in list(by_domain.items())[:retest.max_hosts()]:
        names = [n for n in sorted(names) if n not in ledger.fresh(retest.RETEST_SERVICE, names, project_id)][:retest.max_hosts()]
        if not names:
            continue
        try:
            if pipeline:
                pipeline(domain_id, names)
                ledger.record(retest.RETEST_SERVICE, names, project_id)
            else:
                from cveFeed.tasks import retest_hosts
                retest_hosts.delay(domain_id, names)
                ledger.record(retest.RETEST_SERVICE, names, project_id, status='queued')
            queued.extend(names)
        except Exception:  # noqa: BLE001
            logger.exception('could not re-test %s after a UDP service on %s', names, ip.address)
    return queued


def scan_ip(ip, pipeline=None):
    """Scan one IpAddress on a scanner and record it. Returns the result dict (``ok`` False with an ``error`` when the scan failed).
    ``pipeline(domain_id, names)`` runs the re-test inline. Nothing runs on this server: with no scanner able to take it the address stays due."""
    from cveFeed import activity, fullscan, ledger
    from reNgine.resources import MemoryBusy, ScanAborted, ScannerReportedNothing, ScannerUnavailable
    address, asset = ip.address, asset_of(ip)
    from cveFeed.conductor import bounty_blocked_projects
    project = fullscan.active_attached(ip).exclude(target_domain__project_id__in=bounty_blocked_projects()).values_list(
        'target_domain__project_id', flat=True).first()
    running = activity.log('run_check', f'Background UDP scan of {address} ({len(ports())} ports: DNS, NTP, SNMP, IKE and the like)',
                           project=project, status='running')
    try:
        from agentapi import sentinel_dispatch
        from dashboard.models import Project
        project_obj = Project.objects.filter(pk=project).first() if project else None
        if project_obj is None:  # an address no project scans has no scanner to take it
            raise ScannerUnavailable('nmap_udp', 'the address is attached to no project a scanner could take it for')
        host = sentinel_dispatch.try_nmap_udp(project_obj, address)
        outcome = record_run(ip, host)
    except ScannerReportedNothing as exc:  # a Sentinel finished but the report is unusable: asked again a few times a day, then tomorrow
        count = _empty_count(asset)
        if count >= MAX_EMPTY_PER_DAY:
            logger.warning('background UDP scan of %s: a scanner returned an unusable report %d times today (%s); asking again tomorrow', address, count, exc.why)
            ledger.record(FAILED_SERVICE, [asset])
            activity.settle(running, 'failed', message=activity.diagnostic(
                f'Background UDP scan of {address}', f'a scanner returned an unusable report {count} times today ({exc.why}); the address is asked again tomorrow',
                'ScannerReportedNothing'))
            return {'ip': address, 'ok': False, 'error': 'ScannerReportedNothing', 'parked': True}
        logger.warning('background UDP scan of %s is waiting for a scanner: %s', address, exc)
        activity.settle(running, 'done', message=f'Background UDP scan of {address} is waiting: a scanner returned an unusable report ({exc.why}); '
                        f'asked again ({count} of {MAX_EMPTY_PER_DAY} today)')
        return {'ip': address, 'ok': False, 'error': type(exc).__name__, 'waiting': True}
    except ScannerUnavailable as exc:  # no scanner could take it and it never runs here: not the address's failure, and it stays due
        logger.warning('background UDP scan of %s is waiting for a scanner: %s', address, exc)
        activity.settle(running, 'done', message=f'Background UDP scan of {address} is waiting: no scanner could take this work ({exc.kind}); '
                        'the address stays due until one can')
        return {'ip': address, 'ok': False, 'error': type(exc).__name__, 'waiting': True}
    except NoIpv6Route as exc:  # the Sentinel cannot reach IPv6: said once, the address recorded as not scanned, no IPv6 address sent until tomorrow
        first = not _ipv6_blocked()
        _ipv6_block()
        ledger.record(NO_IPV6_SERVICE, [asset])
        logger.info('background UDP scan of %s not run: %s', address, exc)
        activity.settle(running, 'done', message=(
            f'Background UDP scan of {address} not run: this Sentinel cannot reach IPv6 addresses (it has no IPv6 route). IPv6 addresses are not scanned '
            'for UDP until a Sentinel with IPv6 is available; one address is tried again tomorrow' if first else
            f'Background UDP scan of {address} not run: this Sentinel cannot reach IPv6 addresses'))
        return {'ip': address, 'ok': False, 'error': type(exc).__name__, 'unreachable': 'ipv6'}
    except Exception as exc:  # noqa: BLE001 - failure stays visible, and the address is asked again tomorrow
        logger.warning('background UDP scan of %s failed: %s', address, exc, exc_info=not isinstance(exc, UdpScanError))  # a UdpScanError says all there is
        if not isinstance(exc, (MemoryBusy, ScanAborted)):
            ledger.record(FAILED_SERVICE, [asset])
        activity.settle(running, 'failed', message=activity.diagnostic(f'Background UDP scan of {address}', f'{type(exc).__name__}: {exc}',
                                                                      type(exc).__name__))
        return {'ip': address, 'ok': False, 'error': type(exc).__name__}
    ledger.record(SERVICE, [asset])
    _empty_reset(asset)
    if _is_ipv6(address):  # a Sentinel did reach an IPv6 address: the day's block no longer holds
        _ipv6_unblock()
    if outcome.get('down'):
        activity.settle(running, 'done', message=f'Background UDP scan of {address}: the host did not answer, so no open UDP ports; asked again next week')
        return {'ip': address, 'ok': True, **outcome, 'findings': 0}
    findings = store_findings(ip)
    activity.settle(running, 'done', message=(
        f'Background UDP scan of {address}: {len(outcome["open"])} port(s) answered'
        + (f' ({", ".join(map(str, outcome["open"]))})' if outcome['open'] else '')
        + (f', {len(outcome["unanswered"])} silent (open or filtered)' if outcome['unanswered'] else '')
        + (f', {findings} finding(s)' if findings else '')), open_ports=len(outcome['open']), findings=findings)
    result = {'ip': address, 'ok': True, **outcome, 'findings': findings}
    if outcome['changed']:
        try:
            result['retested'] = queue_retests(ip, outcome['changed'], project, pipeline)
        except Exception:  # noqa: BLE001 - never lets the follow-up undo the scan
            logger.exception('UDP scan: re-testing hosts on %s failed', address)
    return result


def run(pipeline=None, clock=time.monotonic):
    """One firing: IPs one at a time until the time budget is spent, under one Redis claim, never while scanning is paused.

    Also skips the whole firing, instance-wide, while any project (not bounty-blocked) still has a host missing
    core first-pass coverage (see cveFeed.coverage_topup.backlog_exists): every host gets a first look before any
    one address gets a UDP exposure sweep. The next firing checks again.
    """
    from cveFeed import coverage_topup
    from reNgine import resources
    if not enabled():
        return {'skipped': 'CVENGINE_UDPSCAN is off'}
    from agentapi import scanner_state
    waiting = scanner_state.skip_note('nmap_udp')  # no scanner can run it and this server never does: nothing is dispatched, raised or logged
    if waiting:
        return {'skipped': waiting}
    if coverage_topup.backlog_exists():
        coverage_topup.log_deferral('UDP scan')
        return {'skipped': 'coverage backlog: first-pass hosts are still outstanding'}
    if resources.global_pause_requested(fail_closed=True):
        return {'skipped': 'scanning is paused'}
    from agentapi import stage_runs
    if pipeline is None:
        # an address a Sentinel scans is waited for without holding the worker (agentapi.stage_runs): the callback goes on with the next one
        if stage_runs.enabled() and stage_runs.busy('sweep.udp'):
            return {'skipped': 'another UDP sweep is running (it waits on a Sentinel)'}
        return stage_runs.run('sweep.udp', {}, first=lambda: _sweep(None, clock))
    return _sweep(pipeline, clock)


def _resume_sweep(context):
    return _sweep(None, time.monotonic)


def _sweep(pipeline, clock):
    from agentapi import stage_runs
    from reNgine import resources
    from startScan.models import IpAddress
    in_run = stage_runs.current() is not None
    if in_run:  # the passes of one firing share its time budget, its place and the addresses it found no scanner for
        clock = time.time
        started = stage_runs.once('udp:started', time.time)
    else:
        started = clock()
    scanned, waiting = [], set(stage_runs.recall('udp:waiting', []))
    claim = stage_runs.claim_kwargs('udp-sweep', f'udpscan-{os.getpid()}')
    with resources.redis_claim(CLAIM_KEY, claim.pop('owner'), CLAIM_TTL, **claim) as held:
        if held is not True:
            return {'skipped': f'another UDP sweep is running ({held})'}
        record_status('ok')
        while clock() - started < RUN_BUDGET_SECONDS:
            if resources.global_pause_requested(fail_closed=True):
                scanned.append({'skipped': 'scanning is paused'})
                break
            current = stage_runs.recall('udp:current')
            ip = IpAddress.objects.filter(pk=current).first() if current else None
            ip = ip or (pick(waiting) if waiting else pick())
            if ip is None:
                break
            stage_runs.remember('udp:current', ip.pk)  # the address a later pass continues with, if this one waits on a Sentinel
            outcome = scan_ip(ip, pipeline=pipeline)
            stage_runs.remember('udp:current', None)
            scanned.append(outcome)
            if outcome.get('waiting'):  # no scanner could take it, so it is still due: not picked again by this firing (it would fail at once, over and over)
                waiting.add(ip.pk)
                stage_runs.remember('udp:waiting', sorted(waiting))
                if len(waiting) >= MAX_WAITING:  # a scanner that is down is down for everyone: the next firing asks again
                    break
    return {'scanned': scanned}


def kick():
    """Called by every firing of the TCP sweep's beat task: queue one UDP sweep on ``udp_queue``. At most one is queued per five
    minutes, and a queued one that nobody picks up expires, so a stopped worker cannot pile them up. Returns whether one was queued."""
    from cveFeed import ledger
    if not enabled() or not ledger.sweep_claim('udp-kick', 5 * 60):
        return False
    try:
        from cveFeed.tasks import udp_scan_sweep
        udp_scan_sweep.apply_async(expires=15 * 60)
        return True
    except Exception:  # noqa: BLE001 - the TCP sweep's firing must never fail because of this
        logger.warning('could not queue the UDP sweep', exc_info=True)
        return False


def _register():
    from agentapi import stage_runs
    stage_runs.adapter('sweep.udp', queue='udp_queue')(_resume_sweep)


_register()
