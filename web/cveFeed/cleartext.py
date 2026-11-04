"""Cleartext administration services: Telnet, FTP without TLS, rlogin / rsh / rexec, and a login page served over plain HTTP.

The TLS and email checks (cveFeed.hygiene) say nothing about a service that carries a password in the clear, so a router with Telnet and FTP
open read "0 certificates, 0 issues". These findings are derived from what the scans already stored, never from a new probe: the open TCP
ports of a host's addresses (nmap's service names) and the route check's login pages. ``hygiene.run_hygiene`` calls ``findings_for`` and stores
the result with its own findings (check names ``cleartext_*``), so status, assignee, comments, triage, notifications, reports, the host score and
the API work as for every other hygiene finding, and a finding resolves when a later run no longer shows the service.

What counts. A service is named by nmap (``Port.service_name``): ``telnet``; ``ftp``; ``exec``, ``login`` and ``shell`` on 512 to 514
(rexec, rlogin, rsh); the same names with a TLS tunnel (``telnets``, ``ftps``, ``ssl/...``) are encrypted and never reported. The service
must have answered as itself: a protocol greeting (a stored banner) or nmap's fingerprint of it (``method`` ``probed``). A port nmap named
from its port table alone is not reported: a front end that accepts a connection on every port and closes it says nothing on 21 or 513, and
nmap still calls those ports ftp and login. An address that accepts everything (``ACCEPT_ALL_PORTS`` or more open ports that sent nothing
and that nmap could not name, the control ports) needs a banner: a fingerprint without one is not enough there. FTP is not reported when the scan read its certificate
(nmap's ``ssl-cert`` script negotiates AUTH TLS on an FTP port): that proves the server offers TLS, not that it insists on it, so the
finding for FTP without that evidence says "unencrypted unless TLS is enforced", never that it is plain. Only a port that answered counts
(``open``): closed, filtered and ``open|filtered`` are not findings, and UDP 514 is syslog, not rsh. A login page counts only when the
route check saw it over ``http://`` and nothing says the host also speaks HTTPS (no open TLS web port, no HTTPS route).

Grade. Medium on an internal host, high on a public one; a login page over HTTP is low and medium. A host is public when an address on
which the service answers is a public internet address (``targetApp.target_types.is_public_address``, judged from the address alone, as the
host score does). A CDN edge address and a tailnet address are left out: the first is not the owner's service, and the Tailscale checks
already report remote administration on a tailnet address (``ts_remote_admin_exposed``).

Quiet. One finding per host and check, naming every port and address (a host with two addresses and two Telnet ports has one finding). A
host the organization excluded or the project archived has none. ``CVENGINE_HYGIENE_CLEARTEXT=0`` turns the check off: no finding is made
and the open ones resolve at the next hygiene run. Like the other hygiene checks it runs for the targets the hygiene sweep and a person's
request reach, so a bug bounty project that has not confirmed automated testing is not swept (the sweep itself asks); it sends nothing.

Not covered, because it would need a probe this module does not make: SNMP v1 / v2c in general (the UDP sweep already reports a device that
answers the default ``public`` community, ``udp_snmp_public``), and whether an FTP server that offers AUTH TLS also accepts a plain login.
"""
import logging
import os

from cveFeed.hygiene import HIGH, LOW, MEDIUM, Finding

logger = logging.getLogger(__name__)

PREFIX = 'cleartext_'
MAX_PORTS = 10  # ports and addresses named in one finding
MAX_URLS = 5

TELNET, FTP, RSERVICES, HTTP_LOGIN = 'cleartext_telnet', 'cleartext_ftp', 'cleartext_rservices', 'cleartext_http_login'
R_PORTS = (512, 513, 514)  # rexec, rlogin, rsh (TCP; UDP 514 is syslog)
R_NAMES = ('exec', 'login', 'shell', 'rexec', 'rlogin', 'rsh')
SERVICE_NAMES = ('telnet', 'ftp') + R_NAMES
ENCRYPTED_NAMES = ('telnets', 'ftps', 'ftps-data', 'tcpwrapped')
SEEN_NUMBERS = (21, 23) + R_PORTS  # the ports a candidate is looked for on, besides the service names above
# open TCP ports with no greeting and no product on one address from which it is taken to accept every connection (a top-1000 nmap scan of
# a normal host shows a handful of open ports; of a front end that accepts everything, nearly all of them)
ACCEPT_ALL_PORTS = 25

# check -> (what it is, internal grade, public grade, why it matters, the fix)
CHECKS = {
    TELNET: ('Telnet', MEDIUM, HIGH,
             'Telnet sends the login and everything typed in cleartext, so anyone on the path can read the password and take the session.',
             'Turn Telnet off and use SSH. If the device cannot, restrict the port to a management network and firewall it from the internet.'),
    FTP: ('FTP', MEDIUM, HIGH,
          'Plain FTP sends the login and the files in cleartext, so anyone on the path can read the password. The scan found no sign that the '
          'server offers TLS (a certificate was not read over AUTH TLS); if TLS is enforced the finding does not apply.',
          'Use SFTP or FTPS and require TLS (refuse plain logins), or turn FTP off. Restrict the port to a management network and firewall it '
          'from the internet.'),
    RSERVICES: ('rlogin, rsh or rexec', MEDIUM, HIGH,
                'The r-services send the session in cleartext and trust the address of the caller (.rhosts, hosts.equiv), so an attacker on the '
                'path can read or take it, and a forged address can log in without a password.',
                'Turn the r-services off and use SSH. Remove .rhosts and hosts.equiv entries and firewall ports 512 to 514.'),
    HTTP_LOGIN: ('A login page over plain HTTP', LOW, MEDIUM,
                 'The login page is served over http:// and the host has no HTTPS service the scans saw, so a password typed into it crosses '
                 'the network in cleartext.',
                 'Serve the site over HTTPS (a certificate and a listener on 443) and redirect HTTP to it.'),
}
SEVERITY_WORDS = {LOW: 'low', MEDIUM: 'medium', HIGH: 'high'}


def _truthy(value):
    return str(value).strip().lower() not in ('0', 'false', 'no', 'off')


def enabled():
    """CVENGINE_HYGIENE_CLEARTEXT: on unless it is 0/false/no/off."""
    return _truthy(os.environ.get('CVENGINE_HYGIENE_CLEARTEXT', '1'))


# ----------------------------------------------------------------------------- what a port is

def classify(port):
    """The check a stored port belongs to, or None. ``port`` is a ``Port`` row (open TCP is the caller's business)."""
    name = (port.service_name or '').strip().lower()
    if not name or name in ENCRYPTED_NAMES or name.startswith('ssl/') or (port.extra or {}).get('tunnel') == 'ssl':
        return None
    if name == 'telnet':
        return TELNET
    if name == 'ftp':
        return FTP
    if name in R_NAMES and (port.number in R_PORTS or name in ('rexec', 'rlogin', 'rsh')):
        return RSERVICES
    return None


def offers_tls(port):
    """True when the scan read a certificate from the port (nmap's ssl-cert negotiates AUTH TLS on FTP)."""
    return bool(port.tls) or bool((port.extra or {}).get('scripts', {}).get('ssl-cert'))


def _public(addresses):
    """Whether any of ``addresses`` is a public internet address (and not a tailnet one), judged from the address alone."""
    from cveFeed.tailscale_scope import is_tailnet_address
    from targetApp.target_types import is_public_address
    return any(is_public_address(a) and not is_tailnet_address(a) for a in addresses)


def _tailnet(address):
    from cveFeed.tailscale_scope import is_tailnet_address
    return is_tailnet_address(address)


def greeting(port):
    """How the service on ``port`` answered as itself: ``'banner'`` (a stored greeting), ``'fingerprint'`` (nmap matched its answer), or ''
    (named from the port number alone)."""
    if (port.banner or '').strip():
        return 'banner'
    if (port.extra or {}).get('method') == 'probed' or (port.product or '').strip():
        return 'fingerprint'
    return ''


def evaluate(name, entries, accepts_all=()):
    """The cleartext findings of one host from ``entries``, ``[(address, Port)]`` of its open TCP ports: a list of ``hygiene.Finding``.
    ``accepts_all`` holds the addresses that accept a connection on every port (see ``ACCEPT_ALL_PORTS``)."""
    found = {}
    for address, port in entries:
        check = classify(port)
        if not check or _tailnet(address) or (check == FTP and offers_tls(port)):
            continue
        answered = greeting(port)
        if not answered or (address in accepts_all and answered != 'banner'):
            continue  # no greeting: a port that accepts and closes is not a cleartext service
        row = found.setdefault(check, {})
        row.setdefault(port.number, {'port': port, 'addresses': set()})['addresses'].add(address)
    out = []
    for check, ports in found.items():
        what, internal, public, why, fix = CHECKS[check]
        addresses = sorted({a for p in ports.values() for a in p['addresses']})
        exposure = 'public' if _public(addresses) else 'internal'
        severity = public if exposure == 'public' else internal
        numbers = sorted(ports)
        first = ports[numbers[0]]['port']
        identified = greeting(first)
        where = ', '.join(f'{n}/tcp' for n in numbers[:MAX_PORTS])
        basis = (f'rated {SEVERITY_WORDS[severity]}: {what} answers on {"a public internet address" if exposure == "public" else "an internal address"}'
                 f'; whether a login works was not tested')
        detail = f'{why} Fix: {fix}'
        evidence = {'source': 'nmap', 'protocol': 'tcp', 'exposure': exposure, 'port': first.number, 'ports': numbers[:MAX_PORTS],
                    'addresses': addresses[:MAX_PORTS], 'service': first.service_name or '', 'product': first.product or '',
                    'version': first.version or '', 'identified': identified, 'severity_basis': basis, 'remediation': fix}
        if (first.banner or '').strip():
            evidence['banner'] = ' '.join(first.banner.split())[:200]
        if check == FTP:
            evidence['tls_seen'] = False
        out.append(Finding(check, severity, f'{name}: {what} is open ({where})', detail, name, evidence))
    return out


def evaluate_http_login(name, urls, addresses):
    """The plain-HTTP login finding of one host (``urls`` are its login pages over http://), or None."""
    what, internal, public, why, fix = CHECKS[HTTP_LOGIN]
    exposure = 'public' if _public(addresses) else 'internal'
    severity = public if exposure == 'public' else internal
    evidence = {'source': 'route check', 'exposure': exposure, 'urls': sorted(urls)[:MAX_URLS], 'https_seen': False,
                'severity_basis': f'rated {SEVERITY_WORDS[severity]}: the login page is served over http:// on '
                                  f'{"a public internet address" if exposure == "public" else "an internal address"} and no HTTPS service was seen',
                'remediation': fix}
    return Finding(HTTP_LOGIN, severity, f'{name}: {what.lower()} ({len(urls)} page{"s" if len(urls) != 1 else ""}, no HTTPS)',
                   f'{why} Fix: {fix}', name, evidence)


# ----------------------------------------------------------------------------- from the stored data

def _newest_rows(domain, names, ports_queryset):
    """One Subdomain row per name (the newest finished scan's, as the host score reads it) with its non-CDN addresses and their ports."""
    from django.db.models import Prefetch

    from cveFeed.scoring import row_preference, usable_rows
    from startScan.models import IpAddress, Subdomain
    addresses = IpAddress.objects.filter(is_cdn=False).exclude(address__isnull=True).prefetch_related(Prefetch('ports', queryset=ports_queryset))
    return list(usable_rows(Subdomain.objects.filter(target_domain=domain, name__in=sorted(names)))
                .order_by('name', *row_preference()).distinct('name').prefetch_related(Prefetch('ip_addresses', queryset=addresses)))


def _scope(domain, hosts):
    """``(names to look at, names a person or the project took out)``: ``hosts`` when a run is limited to some, lowercase."""
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import excluded_names
    banned = excluded_names(domain.project_id) | archived_names(domain.project_id)
    wanted = None if hosts is None else {h.lower().rstrip('.') for h in hosts}
    return wanted, banned


def _allowed(name, wanted, banned):
    key = name.lower().rstrip('.')
    return (wanted is None or key in wanted) and key not in banned


def service_findings(domain, hosts=None):
    """Telnet, FTP and r-service findings of the target's hosts, from the open TCP ports stored for their addresses."""
    from django.db.models import Q

    from startScan.models import OPEN_PORT_STATES, TCP_PROTOCOLS, Port, Subdomain
    wanted, banned = _scope(domain, hosts)
    candidates = Port.objects.filter(state__in=OPEN_PORT_STATES, protocol__in=TCP_PROTOCOLS).filter(
        Q(number__in=SEEN_NUMBERS) | Q(service_name__in=SERVICE_NAMES))
    names = {n for n in Subdomain.objects.filter(target_domain=domain, ip_addresses__ports__in=candidates).order_by().values_list('name', flat=True).distinct()
             if _allowed(n, wanted, banned)}
    out = []
    rows = _newest_rows(domain, names, candidates)
    accepts_all = _accepting_everything({ip.pk for sub in rows for ip in sub.ip_addresses.all()})
    for sub in rows:
        entries = [(ip.address, port) for ip in sub.ip_addresses.all() for port in ip.ports.all()]
        out += evaluate(sub.name, entries, accepts_all)
    return out


def _accepting_everything(ip_ids):
    """The addresses among ``ip_ids`` with ``ACCEPT_ALL_PORTS`` or more open TCP ports that sent no greeting and that nmap could not name a
    product for: the control ports that show the address accepts a connection on any port."""
    from django.db.models import Count, Q

    from startScan.models import OPEN_PORT_STATES, TCP_PROTOCOLS, IpAddress
    if not ip_ids:
        return set()
    silent = Q(ports__state__in=OPEN_PORT_STATES, ports__protocol__in=TCP_PROTOCOLS, ports__banner='', ports__product='')
    rows = IpAddress.objects.filter(pk__in=ip_ids).annotate(silent=Count('ports', filter=silent)).filter(silent__gte=ACCEPT_ALL_PORTS)
    return set(rows.values_list('address', flat=True))


def _has_https(sub, routes):
    """Whether the stored data says the host speaks HTTPS: an open TLS web port (the route check's own reading of its bases) or an HTTPS route."""
    from cveFeed import route_auth
    if any(base.startswith('https://') for base in route_auth.web_bases(sub)):
        return True
    return any(r.url.startswith('https://') and r.auth_state not in ('error', 'not_found') for r in routes)


def http_login_findings(domain, hosts=None):
    """A finding for each host whose login page the route check saw over plain HTTP and that has no HTTPS service."""
    from django.db.models import Prefetch

    from cveFeed.models import RouteAuth
    from cveFeed.scoring import row_preference, usable_rows
    from startScan.models import IpAddress, Subdomain
    wanted, banned = _scope(domain, hosts)
    rows = [r for r in RouteAuth.objects.filter(project_id=domain.project_id, domain=domain, auth_state='login', retired_at__isnull=True,
                                                url__startswith='http://')]
    names = {r.host.lower() for r in rows if _allowed(r.host, wanted, banned)}
    if not names:
        return []
    routes = {}
    for r in RouteAuth.objects.filter(project_id=domain.project_id, domain=domain, host__in=sorted(names), retired_at__isnull=True):
        routes.setdefault(r.host.lower(), []).append(r)
    subs = (usable_rows(Subdomain.objects.filter(target_domain=domain, name__in=sorted(names))).order_by('name', *row_preference()).distinct('name')
            .prefetch_related(Prefetch('ip_addresses', queryset=IpAddress.objects.filter(is_cdn=False).prefetch_related('ports'))))
    out = []
    for sub in subs:
        host_routes = routes.get(sub.name.lower(), [])
        if _has_https(sub, host_routes):
            continue
        urls = [r.url for r in host_routes if r.auth_state == 'login' and r.url.startswith('http://')]
        addresses = sorted({ip.address for ip in sub.ip_addresses.all() if ip.address and not _tailnet(ip.address)})
        if urls and addresses:
            out.append(evaluate_http_login(sub.name, urls, addresses))
    return out


def findings_for(domain, hosts=None):
    """Every cleartext finding of ``domain``'s hosts (limited to ``hosts`` when given): none when the check is off or the target has no
    project (exclusions and the bounty gate belong to a project)."""
    if not enabled() or not domain.project_id:
        return []
    return service_findings(domain, hosts) + http_login_findings(domain, hosts)
