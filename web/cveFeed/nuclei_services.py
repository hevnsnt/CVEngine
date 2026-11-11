"""What speaks on each ``host:port`` of a template-scan task, from the evidence the server already holds, so a port only receives the templates of its protocol.

Before, every ``host:port`` of a task got the whole template set: over 11,000 http templates and the raw tcp, javascript and ssl ones. Scanning a host
sent tens of thousands of connections to its SSH and mail daemons (sshd logged 34,000 "banner exchange: invalid format" lines in 20 minutes and
refused its own administrator's logins). The server labels every ``host:port`` of a task with one class (``cvengine_scanner.flags``: ``web``, a protocol
class such as ``ssh`` or ``smtp``, or ``unknown``) and sends the labels in the task (``services``) with the budget (``budget``); the Sentinel sends each
port only the templates of its class (the Sentinel's template run, ``client.tools``). A port that is not web never receives an http template.

The evidence, in the order it is read (``classify``):
1. an http service name (``http``, ``https``, ``http-proxy``, ``ssl/http``...) or a stored http result (``Port.http``, which only the web probe ingest
   writes: the ``http_probe`` kind does not): web.
2. the service name the port scan gave (``Port.service_name``, ``ssl/`` removed): its protocol class; a TLS tunnel on a protocol that is not http: ``tls``.
3. nothing named, but the product says http: web.
4. nothing named: the port number: a well-known web port is web, a well-known service port is its class. ``tcpwrapped`` (the connection was accepted
   and closed: nothing was seen to speak http) is never web: its number gives a service class, else ``unknown``.
5. otherwise ``unknown``: a named service with no class of its own, or nothing known. It receives the generic network templates (raw tcp, javascript and
   ssl templates that belong to no class), under the same pacing, and never an http template.
No target is dropped here: the list a pass builds is unchanged, each ``host:port`` gets a label. A task carries at most ``MAX_SERVICE_PORTS`` ports that are
not web (``chunks``): the rest go in further tasks, so a Sentinel's task time covers them.
"""
from cvengine_scanner import flags as scan_flags

WEB, UNKNOWN = scan_flags.NUCLEI_WEB, scan_flags.NUCLEI_UNKNOWN
MAX_SERVICE_PORTS = scan_flags.NUCLEI_SERVICE_MAX_PORTS  # the most ports that are not web one task carries
# the port scan says unknown when it could not tell: that name carries no evidence, so the port number is read. tcpwrapped is read by number too, but
# never as web (see ``classify``)
_NO_EVIDENCE = ('', 'unknown', 'tcpwrapped')


def _web_ports():
    from cveFeed import route_auth
    return route_auth.WEB_PORTS


def _is_http_name(name):
    from cveFeed import route_auth
    return name in route_auth.HTTP_SERVICE_NAMES or name.startswith('http') or name.startswith('https')


def classify(number, service='', product='', http=None, tunnel=''):
    """The class of one port from what was observed on it (see the module's list of evidence)."""
    name = (service or '').strip().lower()
    secure = (tunnel or '').lower() == 'ssl' or name.startswith('ssl/')
    if name.startswith('ssl/'):
        name = name[4:]
    if http or _is_http_name(name):
        return WEB
    klass = scan_flags.NUCLEI_SERVICE_NAMES.get(name)
    if klass:
        return 'tls' if secure and klass != 'tls' else klass
    if name in _NO_EVIDENCE:
        wrapped = name == 'tcpwrapped'  # accepted the connection and closed it: nothing was seen to speak http
        if 'http' in (product or '').lower() and not wrapped:
            return WEB
        if number in _web_ports() and not wrapped:
            return WEB
        klass = scan_flags.NUCLEI_SERVICE_PORTS.get(number)
        if klass and not (wrapped and klass == WEB):
            return klass
    return UNKNOWN


def classify_port(port):
    """``classify`` for a ``startScan.models.Port`` row."""
    return classify(port.number, port.service_name, port.product, port.http, ((port.extra or {}).get('tunnel') or '') if isinstance(port.extra, dict) else '')


def _port_of(target):
    """``(host, port)`` of a ``host:port`` target, else ``None`` (a bare host, an address, a URL, an IPv6 literal)."""
    if '://' in target or target.count(':') != 1:
        return None
    host, _, port = target.partition(':')
    return (host.lower(), int(port)) if host and port.isdigit() else None


def labels_for(scan, targets):
    """``{target: class}`` for each ``host:port`` of ``targets``, read from the scan's inventory with three queries however many targets there are
    (only the hosts of ``targets`` are loaded). A bare host, an address or a URL is web and has no entry. A port the inventory has no row for is read by
    its number alone; when the rows of a host's addresses disagree about what speaks on a port, nothing is known about it (``unknown``)."""
    from django.db.models import Prefetch
    from django.db.models.functions import Lower

    from startScan.models import Port, Subdomain, open_ports
    wanted = {}
    for target in targets:
        pair = _port_of(target)
        if pair:
            wanted[target] = pair
    if not wanted:
        return {}
    hosts = {host for host, _port in wanted.values()}
    numbers = {number for _host, number in wanted.values()}
    seen = {}
    subs = (Subdomain.objects.annotate(lowered=Lower('name')).filter(scan_history=scan, lowered__in=hosts)
            .prefetch_related(Prefetch('ip_addresses__ports', queryset=Port.objects.filter(number__in=numbers))))
    for sub in subs:
        for ip in sub.ip_addresses.all():
            for port in open_ports(ip):
                seen.setdefault((sub.name.lower(), port.number), set()).add(classify_port(port))
    labels = {}
    for target, (host, number) in wanted.items():
        classes = seen.get((host, number)) or {classify(number)}
        labels[target] = next(iter(classes)) if len(classes) == 1 else UNKNOWN
    return labels


def chunks(targets, labels, size, max_ports=None):
    """``targets`` in order, in lists of at most ``size`` and at most ``max_ports`` (``MAX_SERVICE_PORTS``) targets whose label is not web: a Sentinel
    checks each of those ports one template at a time, so a task with many of them would not fit its time. The rest go in further tasks (none is dropped)."""
    max_ports = MAX_SERVICE_PORTS if max_ports is None else max_ports
    out, current, ports = [], [], 0
    for target in targets:
        service = labels.get(target, WEB) != WEB
        if current and (len(current) >= size or (service and ports >= max_ports)):
            out.append(current)
            current, ports = [], 0
        current.append(target)
        ports += service
    if current:
        out.append(current)
    return out
