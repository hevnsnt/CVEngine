"""What speaks on each ``host:port`` of a template-scan task, from the evidence the server already holds, so a port only receives the templates of its protocol.

Before, every ``host:port`` of a task got the whole template set: over 11,000 http templates and the raw tcp, javascript and ssl ones. Scanning a host
sent tens of thousands of connections to its SSH and mail daemons (sshd logged 34,000 "banner exchange: invalid format" lines in 20 minutes and
refused its own administrator's logins). The server labels every ``host:port`` of a task with one class (``cvengine_scanner.flags``: ``web``, a protocol
class such as ``ssh`` or ``smtp``, or ``unknown``) and sends the labels in the task (``services``) with the per-service budget (``budget``); the Sentinel
sends each port only the templates of its class, and nothing to an ``unknown`` one (the Sentinel's template run, ``client.tools``).

The evidence, in the order it is read (``classify``):
1. an http service name (``http``, ``https``, ``http-proxy``, ``ssl/http``...) or a stored http probe result: web.
2. the service name the port scan gave (``Port.service_name``, ``ssl/`` removed): its protocol class; a TLS tunnel on a protocol that is not http: ``tls``.
3. nothing named, but the product says http: web.
4. nothing named: the port number: a well-known web port is web, a well-known service port is its class.
5. otherwise ``unknown``: no template is sent (a port nothing says anything about is not probed with a library of web exploits).
No target is dropped here: the list a pass builds is unchanged, each ``host:port`` gets a label.
"""
from cvengine_scanner import flags as scan_flags

WEB, UNKNOWN = scan_flags.NUCLEI_WEB, scan_flags.NUCLEI_UNKNOWN
# the port scan says tcpwrapped or unknown when it could not tell: those names carry no evidence, so the port number is read
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
        if 'http' in (product or '').lower():
            return WEB
        if number in _web_ports():
            return WEB
        klass = scan_flags.NUCLEI_SERVICE_PORTS.get(number)
        if klass:
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
    """``{target: class}`` for each ``host:port`` of ``targets`` (the scan's own inventory is read once). A bare host, an address or a URL is web and
    has no entry. A port the inventory has no row for is read by its number alone; when the rows of a host's addresses disagree about what speaks
    on a port, nothing is known about it (``unknown``: nothing is sent)."""
    from startScan.models import Subdomain, open_ports
    wanted = {}
    for target in targets:
        pair = _port_of(target)
        if pair:
            wanted[target] = pair
    if not wanted:
        return {}
    hosts = {host for host, _port in wanted.values()}
    seen = {}
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'):
        if sub.name.lower() not in hosts:
            continue
        for ip in sub.ip_addresses.all():
            for port in open_ports(ip):
                seen.setdefault((sub.name.lower(), port.number), set()).add(classify_port(port))
    labels = {}
    for target, (host, number) in wanted.items():
        classes = seen.get((host, number)) or {classify(number)}
        labels[target] = next(iter(classes)) if len(classes) == 1 else UNKNOWN
    return labels
