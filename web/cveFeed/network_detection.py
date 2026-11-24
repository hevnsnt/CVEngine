"""The network detection pass: nuclei's ``network/detection/`` templates on the open ports of a host that do not speak HTTP, so the services the light
technology pass never names (RDP, Redis, MongoDB, MySQL, VNC, RabbitMQ, ActiveMQ, the SSH and FTP variants, mail servers) get a product, and a version
when the service states one.

Why it is its own pass. The light pass runs ``-tags tech``, which only the http technology templates carry: a non-web ``host:port`` of that pass gets no
template at all. A ``nuclei_light`` task that carries ``network_detection`` (contract 10, ``cvengine_scanner.flags.NUCLEI_DETECTION_SINCE``) runs, on each
non-web port, only the templates of the port's class that are on the Sentinel library's service-port allowlist and whose reviewed path is under
``network/detection/`` (``cvengine_scanner.nuclei_allowlist.is_detection``): nuclei's raw tcp type, one template at a time, under the service budget, with
dos, default-login, bruteforce, fuzz and intrusive always excluded. Never ``network/cves`` or anything that sends a credential.

Where it runs. Only on a Sentinel (``nuclei_light`` is ``NEVER_LOCAL``), and only on one that declared contract 10 or later: an older Sentinel ignores the field
and its light pass checks nothing on these ports, so the broker never hands it such a task (``sentinel_broker.network_detection_task``) and the stage waits
(the ports stay due) while no live Sentinel can run it.

What is sent. The scan's open TCP ports (``nuclei_scan.scan_targets``: excluded, archived, bug bounty out-of-scope and CDN hosts are already left out) whose
label (``nuclei_services.labels_for``) is not web and is a class the allowlist has a detection template for (``nuclei_allowlist.detection_classes``: no TLS,
SMB, MSSQL, PostgreSQL, LDAP or Memcached port is sent; their checks are javascript or ssl templates, or there are none). An unattended scan of a bug bounty
project that has not confirmed automated testing sends nothing (``bounty_gate``). At most ``NUCLEI_DETECTION_MAX_PORTS`` ports a task, ``NUCLEI_DETECTION_BUDGET``
per port. Covered for ``ledger`` ``nuclei-netdetect`` (7 days); a port only partly checked is asked again after a day.

What is stored (``ingest``). One reading per finding (``reading``): the product the template names and a version only when an extracted value is shaped like
one and is the product's own (a protocol's version such as VNC's ``RFB 003.008``, rsync's ``RSYNCD: 31.0``, the JVM a JDWP port names or SSH's ``2.0`` is never
taken). Then, on the matching ``Port`` row (the port the task named, on an address of the host):
  - nmap named no product: the product (and the version) are filled in;
  - nmap named the same product without a version: the version is filled in;
  - otherwise the port row is left as nmap wrote it (nmap's product and version always win), and a versioned reading of another product is stored as a
    first-party reading (``source_versions.store_port``, probe ``vsrc:nuclei``), which correlation matches like any technology.
Correlation then matches the port and the readings as usual (the pipeline's correlation stage runs after this one).
"""
import logging
import os
import re
import tempfile

logger = logging.getLogger(__name__)

SERVICE = 'nuclei-netdetect'
FILL_KEY = 'nuclei_detect'  # Port.extra: what the pass filled into the row
STAGE = 'nuclei_netdetect_scan'
TITLE = 'Nuclei network detection pass'
BOUNTY_REASON = 'the bug bounty engagement has not confirmed automated testing'

# The product a template names, where its own title would not read as the product correlation knows (a CPE product, or what nmap calls it). Any other
# template is read from its title (``_title_product``).
PRODUCTS = {
    'openssh-detect': 'OpenSSH', 'sshd-dropbear-detect': 'Dropbear sshd', 'bitvise-detect': 'Bitvise WinSSHD', 'erlang-otp-ssh-detect': 'Erlang/OTP',
    'maverick-ssh-detect': 'Maverick SSHD', 'huawei-ssh-detect': 'Huawei SSH', 'mikrotik-ssh-detect': 'MikroTik RouterOS sshd',
    'redis-detect': 'Redis', 'mongodb-detect': 'MongoDB', 'mysql-detect': 'MySQL', 'mssql-detect': 'Microsoft SQL Server', 'samba-detect': 'Samba',
    'rabbitmq-detect': 'RabbitMQ', 'apache-activemq-detect': 'Apache ActiveMQ', 'activemq-openwire-transport-detect': 'Apache ActiveMQ',
    'rdp-detection': 'Microsoft Terminal Services', 'rdp-detect': 'Microsoft Terminal Services', 'vnc-service-detect': 'VNC',
    'proftpd-server-detect': 'ProFTPD', 'vsftpd-detect': 'vsftpd', 'pure-ftpd-detect': 'Pure-FTPd', 'filezilla-ftp-detect': 'FileZilla Server',
    'serv-u-ftp-detect': 'Serv-U', 'microsoft-ftp-service': 'Microsoft ftpd', 'microsoft-ftp-detect': 'Microsoft ftpd', 'exim-detect': 'Exim',
    'clamav-detect': 'ClamAV', 'weblogic-t3-detect': 'Oracle WebLogic Server', 'weblogic-iiop-detect': 'Oracle WebLogic Server',
    'oracle-tns-listener': 'Oracle TNS Listener', 'ibm-db2-database-server': 'IBM Db2', 'sap-router-detect': 'SAProuter', 'sap-router': 'SAProuter',
    'vmware-authentication-daemon': 'VMware Authentication Daemon', 'jdwp-detect': 'Java Debug Wire Protocol', 'java-rmi-detect': 'Java RMI',
    'gnu-inetutils-ftpd-detect': 'GNU inetutils ftpd', 'xlight-ftp-service-detect': 'Xlight FTP Server', 'xlight-ftp-detect': 'Xlight FTP Server',
}
# Templates whose extracted value is never the product's version: a protocol's version (RFB, RSYNCD, the CQL protocol), the JVM behind a debug port (a Java
# runtime reading of its own, ``cveFeed.java_runtime``), the CLR, a kernel, a host name, a part number or a build date.
NO_VERSION = frozenset({
    'vnc-service-detect', 'rsyncd-service-detect', 'cql-native-transport', 'jdwp-detect', 'dotnet-remoting-service-detect', 'detect-addpac-voip-gateway',
    'adsb-ultrafeeder-detect', 'rdp-detection', 'rdp-detect', 'fortinet-fgfm-detect', 'siemens-s7-detect', 'checkpoint-ftp-detect', 'ibm-ftp-detect',
    'medusa-ftp-detect', 'tnftpd-detect', 'netbsd-ftpd-detect', 'lanier-ftp-detect', 'hummingbird-ftp-detect', 'riak-detect', 'vtun-server',
})
# A version as a service states it: digits, at least one dot, a patch or build tail (8.9p1, 1.3.5e, 2020.81, 12.2.1.3.0, 4.0.0-beta). A zero-padded first part
# (``003.008``) is a protocol's, never a release.
_VERSION = re.compile(r'^(?:0|[1-9]\d{0,4})(?:\.\d{1,9}){1,4}[0-9A-Za-z.+~-]{0,30}$')
_TITLE_WORDS = re.compile(r'(?i)[\s:–-]*\b(?:detect|detected|detection|service|fingerprint|version|protocol)\s*$')
_GENERIC = frozenset({'server', 'service', 'services', 'daemon', 'protocol', 'detect', 'detection', 'free', 'pro', 'edition', 'ftp', 'ssh', 'smtp', 'mail'})


def _title_product(name):
    """The product a template's title names: ``Redis Service - Detect`` is Redis, ``Apache ActiveMQ Detection`` Apache ActiveMQ, ``Exim - Detect`` Exim."""
    text = (name or '').strip()
    for _ in range(4):  # "VNC Service Detection": two trailing words
        stripped = _TITLE_WORDS.sub('', text).strip()
        if stripped == text or not stripped:
            break
        text = stripped
    return re.sub(r'[\s:–-]+$', '', text)[:100]


def product_of(line):
    """The product one result line names (``PRODUCTS``, else the template's title)."""
    template = str(line.get('template-id') or '').strip()
    info = line.get('info') if isinstance(line.get('info'), dict) else {}
    return PRODUCTS.get(template) or _title_product(str(info.get('name') or ''))


def _words(product, name):
    """What a version may follow in an extracted value: the product's whole name, the product its title names, then each of their words that is not a generic
    one (``OpenSSH_8.9p1``, ``ProFTPD 1.3.5e``, ``Acme Widget Server 5.1.2``)."""
    out = [p for p in dict.fromkeys((product.strip(), _title_product(name))) if p and ' ' in p]
    for word in re.findall(r'[A-Za-z][A-Za-z0-9+-]{2,}', f'{product} {name}'):
        if word.lower() not in _GENERIC and word.lower() not in {w.lower() for w in out}:
            out.append(word)
    return out


def versions_of(line, product):
    """The versions one result line states for ``product``: an extracted value that is a version on its own (a template's ``group: 1``), or the version that
    follows the product's name inside one (``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`` is 8.9p1, never the protocol's 2.0). A value of a template in
    ``NO_VERSION``, or one that is not shaped like a version (``_VERSION``), is none."""
    from cveFeed.correlation import stated_version
    template = str(line.get('template-id') or '').strip()
    if template in NO_VERSION:
        return []
    info = line.get('info') if isinstance(line.get('info'), dict) else {}
    words = _words(product, str(info.get('name') or ''))
    found = []
    for value in line.get('extracted-results') or []:
        text = str(value or '').strip()[:300]
        if not text:
            continue
        candidates = [text.lstrip('vV')] if _VERSION.match(text.lstrip('vV')) else []
        for word in words:
            phrase = r'\s+'.join(re.escape(part) for part in word.split())
            after = re.search(rf'(?i)(?:^|[^A-Za-z0-9]){phrase}(?:[\s_/:-]|\s+v(?:ersion)?\.?\s*)*v?(\d[0-9A-Za-z.+~-]*)', text)
            if after:
                candidates.append(after.group(1).rstrip('.-'))
        for candidate in candidates:
            if _VERSION.match(candidate) and stated_version(product, candidate):
                found.append(candidate)
    return list(dict.fromkeys(found))


def technology_name(line):
    """The technology one result line names, in the stored form (``Name`` or ``Name:version``, as ``nuclei_scan.tech_name_from`` writes it): the product and,
    when several versions are stated, the highest (the conservative reading, as the technology pass takes it)."""
    from cveFeed.correlation import stored_technology_name
    from cveFeed.nuclei_scan import _version_order
    product = stored_technology_name(product_of(line))
    if not product:
        return ''
    found = versions_of(line, product)
    return f'{product}:{max(found, key=_version_order)}' if found else product


def reading(line):
    """``(product, version)`` of one result line (``version`` is '' when it states none), read back from ``technology_name`` the way correlation splits a
    stored technology (``correlation.split_name_version``)."""
    from cveFeed.correlation import split_name_version
    name = technology_name(line)
    if not name:
        return '', ''
    product, version = split_name_version(name)
    return product, version if _VERSION.match(version or '') else ''


def target_of(line):
    """The ``host:port`` one result line matched (``matched-at``, a scheme such as ``tls://`` dropped), lower case, or ``None``."""
    for raw in (line.get('matched-at'), line.get('host')):
        text = str(raw or '').strip().lower()
        if '://' in text:
            text = text.split('://', 1)[1]
        text = text.split('/', 1)[0]
        if text.count(':') == 1:
            host, _, port = text.partition(':')
            if host and port.isdigit() and 0 < int(port) < 65536:
                return f'{host.rstrip(".")}:{int(port)}'
    return None


# ----------------------------------------------------------------------------- what is sent

def candidate_targets(scan):
    """``(targets, labels)``: the scan's non-web ``host:port`` targets of a class the network detection pass has a template for, and every port's label."""
    from cvengine_scanner import nuclei_allowlist

    from cveFeed import nuclei_scan, nuclei_services
    _hostnames, _ips, ports = nuclei_scan.scan_targets(scan)
    targets = [f'{host}:{number}' for host, number in sorted(ports)]
    labels = nuclei_services.labels_for(scan, targets)
    classes = nuclei_allowlist.detection_classes()
    return [t for t in targets if labels.get(t, nuclei_services.WEB) in classes], labels


def bounty_refusal(scan):
    """Why an unattended scan of a bug bounty project may not run the pass ('' when it may): the program has not confirmed automated testing. A scan a person
    started is their decision (``bounty_gate``); every host was already held to the program's scope by ``scan_targets``."""
    from cveFeed.bounty_gate import Gate
    if scan.initiated_by_id is not None:
        return ''
    return BOUNTY_REASON if Gate().project_blocked(scan.domain.project_id) else ''


def has_work(scan):
    """Whether the scan has a port the pass would be sent to (the pipeline runs the stage only then)."""
    try:
        return bool(candidate_targets(scan)[0])
    except Exception:  # noqa: BLE001 - asking must never cost the pipeline its other stages
        logger.exception('could not read the network detection targets of scan %s', scan.pk)
        return False


# ----------------------------------------------------------------------------- what is stored

def _ports_of(scan, host, number):
    """``[(subdomain, Port)]`` of the open TCP port ``number`` on the addresses of ``host`` in ``scan``."""
    from django.db.models.functions import Lower

    from startScan.models import Subdomain, open_ports
    out = []
    for sub in Subdomain.objects.annotate(lowered=Lower('name')).filter(scan_history=scan, lowered=host).select_related('target_domain') \
            .prefetch_related('ip_addresses__ports'):
        for ip in sub.ip_addresses.all():
            out += [(sub, p) for p in open_ports(ip) if p.number == number]
    return out


def _same_product(a, b):
    from cveFeed.correlation import _norm
    from cveFeed.source_versions import _same_product as same
    return same(_norm(a), {_norm(b)})


def apply_to_port(port, product, version, template):
    """Fill what nmap left out of ``port`` from one reading: the product (and version) when nmap named no product, the version when nmap named the same product
    without one. Never changes a product or a version nmap stated. Returns what changed (``'product'``, ``'version'`` or ``''``)."""
    if not product:
        return ''
    stated_product, stated_version = (port.product or '').strip(), (port.version or '').strip()
    changed = ''
    if not stated_product:
        port.product, changed = product[:255], 'product'
        if version:
            port.version = version[:100]
    elif version and not stated_version and _same_product(stated_product, product):
        port.version, changed = version[:100], 'version'
    if changed:
        port.extra = {**(port.extra if isinstance(port.extra, dict) else {}),
                      'nuclei_detect': {'template': str(template)[:80], 'product': product[:100], 'version': (version or '')[:60], 'filled': changed}}
        port.save(update_fields=['product', 'version', 'extra'])
    return changed


def ingest(scan, lines, targets):
    """Store what the pass's result ``lines`` say about the ports of ``targets`` (the ``host:port`` list the tasks named; a line about any other port is not
    read). Returns ``{'ports': filled port rows, 'readings': readings stored, 'hosts': {host: [technology names]}, 'changed': [subdomains]}``."""
    from cveFeed import source_versions
    wanted = {str(t).strip().lower().rstrip('.') for t in targets}
    per_port = {}  # (host, number) -> [(product, version, template)]
    for line in lines:
        where = target_of(line)
        if where is None or where not in wanted:
            continue
        product, version = reading(line)
        if not product:
            continue
        host, _, number = where.partition(':')
        per_port.setdefault((host, int(number)), []).append((product, version, str(line.get('template-id') or '')))
    out = {'ports': 0, 'readings': 0, 'hosts': {}, 'changed': []}
    for (host, number), found in per_port.items():
        found.sort(key=lambda f: (not f[1], f[2]))  # a versioned reading first: it fills more
        rows = _ports_of(scan, host, number)
        for product, version, _template in found:
            out['hosts'].setdefault(host, []).append(f'{product}:{version}' if version else product)
        for sub, port in rows:
            readings = []
            for product, version, template in found:
                if apply_to_port(port, product, version, template):
                    out['ports'] += 1
                    if sub not in out['changed']:
                        out['changed'].append(sub)
                readings.append(_port_reading(port, product, version, template, number))
            readings = [r for r in readings if r]
            if source_versions.store_port(sub, source_versions.NUCLEI_PROBE, number, readings):
                out['readings'] += len(readings)
                if sub not in out['changed']:
                    out['changed'].append(sub)
    return out


def _port_reading(port, product, version, template, number):
    """The first-party reading (``vsrc:nuclei``) one result is for a port, or None: the version this pass filled into the port row (so a later
    port scan that names the product without a version keeps it while the reading is fresh: ``port_inventory.persist_inventory``), a versioned
    product other than the port's own, or an unversioned one as an identity reading (shown, searched and a lead, never a technology). A product
    nmap itself stated is not read twice."""
    from cveFeed import source_versions
    said = f'nuclei {template} on port {number}'
    source = f'nuclei:{template}'[:48]
    if _same_product(port.product or '', product):
        fill = (port.extra or {}).get('nuclei_detect') if isinstance(port.extra, dict) else None
        if version and isinstance(fill, dict) and fill.get('version') == version and (port.version or '').strip() == version:
            got = source_versions.product_reading(product, version, source, evidence=said)
            return {**got, 'on_port': True} if got else None  # the port row states it and is matched: no second technology
        return None
    if version:
        return source_versions.product_reading(product, version, source, evidence=said)
    return source_versions.identity_reading(product, source, evidence=said)


# ----------------------------------------------------------------------------- the pipeline stage

def run_for_scan(scan_id, stream, force=False):
    """The pipeline stage: send the scan's non-web ports of a detectable class to a Sentinel through ``stream`` (``sentinel_dispatch.wrap_nuclei_stream(scan,
    'nuclei_light')``, called with ``network_detection=True``), store what comes back (``ingest``) and correlate each host that changed. Ports this project's
    pass covered inside the TTL are not sent again (``force``: a re-test). Returns ``{'targets', 'sent', 'ports', 'readings', 'hosts'}``; raises
    ``ScannerUnavailable`` (from the stream) when no Sentinel can take it: the ports stay due. The pipeline's correlation stage, which runs after this one,
    matches what was stored."""
    from cveFeed import activity, ledger, nuclei_scan
    from cvengine.resources import ScannerUnavailable
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project = scan.domain.project_id
    why = bounty_refusal(scan)
    if why:
        activity.log('run_check', f'{TITLE} skipped for {scan.domain.name}: {why}', project=project, scan_id=scan.id)
        return {'targets': 0, 'sent': 0, 'ports': 0, 'readings': 0, 'hosts': {}, 'skipped': why}
    targets, _labels = candidate_targets(scan)
    summary = {'targets': len(targets), 'sent': 0, 'ports': 0, 'readings': 0, 'hosts': {}}
    if not targets:
        return summary
    covered = set() if force else set(ledger.fresh(SERVICE, targets, project))
    held = set() if force else nuclei_scan.backed_off(SERVICE, [t for t in targets if t not in covered], project) | \
        nuclei_scan.no_check_held(SERVICE, [t for t in targets if t not in covered], project)
    todo = [t for t in targets if t not in covered and t not in held]
    if not todo:
        return {**summary, 'covered': len(covered)}
    with ledger.claim_many(f'{SERVICE}@{project}', todo) as won:
        mine = [t for t in todo if t in set(won)]
        if not mine:
            return {**summary, 'covered': len(covered)}
        running = activity.log('run_check', f'Nuclei is identifying the services on {len(mine)} non-web port(s) of {scan.domain.name} with the network detection '
                               f'templates, scan #{scan.id}', project=project, status='running', scan_id=scan.id)
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
            handle.write('\n'.join(mine) + '\n')
            path = handle.name
        lines = []
        try:
            for line in stream(path, network_detection=True):
                lines.append(line)
        except ScannerUnavailable as exc:
            activity.settle(running, 'done', message=f'{TITLE} for {scan.domain.name} is waiting: {exc}')
            got = ingest(scan, lines, mine)  # what a Sentinel already returned is kept; nothing is recorded as covered
            return {**summary, 'sent': len(mine), 'ports': got['ports'], 'readings': got['readings'], 'hosts': got['hosts'], 'skipped': str(exc)[:290]}
        finally:
            os.unlink(path)
        got = ingest(scan, lines, mine)
        nuclei_scan.record_reached(SERVICE, mine, project, scan, stream)
        n = sum(len(v) for v in got['hosts'].values())
        activity.settle(running, 'done', message=f'{TITLE} on {scan.domain.name}: {n} service(s) identified on {len(got["hosts"])} host(s), '
                        f'{got["ports"]} port(s) given a product or version nmap did not state, {got["readings"]} reading(s) stored')
    return {**summary, 'sent': len(mine), 'ports': got['ports'], 'readings': got['readings'], 'hosts': got['hosts']}
