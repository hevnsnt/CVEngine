"""nmap OS/service fingerprinting over every IP discovery found: one ``-O -sV`` pass (OS guess,
service/version on the thousand most common ports plus the high-risk ones in EXTRA_PORTS, at version intensity 7 with the NSE scripts in NSE_SCRIPTS, so each service gives up its banner and what it reveals about its host). That single run per IP is the pipeline's whole port scan; the full ``-p-`` sweep is far too slow
to run inline, so it is a slow background task of its own (see cveFeed.fullscan). Both feed
the same Shodan-style inventory (Port / IpAddress) that bbot and nuclei write to, so correlate_cves and the hosts page see
one consistent picture regardless of which tool found what.
"""
import logging
import os
import re
import subprocess
import tempfile

from django.db import DatabaseError
from django.utils import timezone

from cveFeed import distro as distro_lib
from cveFeed import naabu_scan

logger = logging.getLogger(__name__)

NMAP_BIN = 'nmap'
# NSE scripts that read what a service says about itself and its host. All are in nmap's safe or discovery categories and none
# exploits anything: banner (the raw greeting), ssh-hostkey and ssh2-enum-algos (SSH server identity), ssl-cert (certificate
# subject, issuer, validity), http-headers, http-title, http-server-header (the Server header when -sV could not read it) and
# http-generator (the generator meta tag of the front page: one GET), ftp-anon (whether anonymous login is accepted, and the top level
# listing it shows), rdp-ntlm-info (the OS build, host and domain names RDP's NTLM challenge reveals, without logging in),
# rdp-enum-encryption (which RDP security layers the server accepts, so a server that does not insist on NLA is visible),
# smb-os-discovery and nbstat (OS, host and domain names over SMB and NetBIOS). mysql-info, mongodb-info, redis-info,
# memcached-info and couchdb-stats read each database's own pre-authentication greeting for its version and build details;
# ms-sql-ntlm-info reads the same NTLM challenge rdp-ntlm-info does, over SQL Server's own protocol; ms-sql-info asks the SQL
# Server Browser service, once per host, which instances exist and their exact version. None of these sends a credential or
# reads a credential-protected value; cveFeed.db_intel turns their output into Port.version/Port.extra, and
# cveFeed.db_exposure separately tests whether a database answers a real query with no authentication at all. Scripts only
# run on ports whose service matches.
NSE_SCRIPTS = ('banner', 'ssh-hostkey', 'ssh2-enum-algos', 'ssl-cert', 'http-headers', 'http-title', 'http-server-header', 'http-generator',
               'ftp-anon',
               'rdp-ntlm-info', 'rdp-enum-encryption', 'smb-os-discovery', 'nbstat', 'mysql-info', 'ms-sql-info',
               'ms-sql-ntlm-info', 'mongodb-info', 'redis-info', 'memcached-info', 'couchdb-stats')
NSE_FLAGS = ['--script', ','.join(NSE_SCRIPTS), '--script-timeout', '30s']
# nmap's own documentation says a version scan "automatically executes the scripts in the version category" (rpcinfo,
# hnap-info, vmware-version, skypev2-version, and more) whenever -sV runs, regardless of --script; these "cannot be
# selected explicitly", so there is no flag that turns them off while keeping -sV. Their output is hidden from the
# console but still written to -oX, which is exactly what this module parses. None of them have been reviewed the way
# NSE_SCRIPTS has, so persist_inventory drops anything -sV smuggled in before it is ever stored, searched or shown.
# The UDP sweep (cveFeed.udp_scan) adds five scripts, each reviewed as read-only: snmp-sysdescr (one SNMP GET of sysDescr and the uptime
# with the default community "public": a reply is proof that community works), snmp-info (the SNMPv3 engine ID, the probe -sV sends),
# ntp-info (the time and the "readvar" variables: version, system, processor), upnp-info (one SSDP M-SEARCH: the server string and
# device description) and ipmi-version (one Get Channel Authentication Capabilities request: the IPMI version and the
# authentication types offered, no login). ntp-monlist is deliberately absent: nmap files it under "intrusive" and says the
# target records the request. Together with nbstat above (UDP 137) they only run on UDP ports whose service matches.
UDP_NSE_SCRIPTS = ('snmp-sysdescr', 'snmp-info', 'ntp-info', 'upnp-info', 'ipmi-version')
NSE_SCRIPT_SET = frozenset(NSE_SCRIPTS) | frozenset(UDP_NSE_SCRIPTS)


def _reviewed_scripts(scripts):
    """``scripts`` with every id outside NSE_SCRIPT_SET dropped. See the note above NSE_SCRIPT_SET for why -sV can hand
    us scripts nobody asked for and nobody has reviewed."""
    return {sid: text for sid, text in (scripts or {}).items() if sid in NSE_SCRIPT_SET}
FAST_FLAGS = ['-sV', '--version-intensity', '7', '-O', '--osscan-limit', '--top-ports', '1000', '-Pn', '-T4',
              '--max-retries', '2', '--min-hostgroup', '32', '--defeat-rst-ratelimit', *NSE_FLAGS]
FULL_PORT_FLAGS = ['-p-', '--open', '-T4', '-Pn']
# nmap's --top-ports ranks ports by how often they are open across the internet, not by how dangerous an open one is, so
# the thousand it picks leave out most of the services an exposure check cares about (Redis is 2742th, MongoDB 2169th,
# the Docker API 3217th, kubelet is not ranked at all). The pass scans the top thousand plus these, about 3% more probes.
EXTRA_PORTS = (
    2181, 2375, 2376, 2379, 2380,     # Zookeeper, Docker API (plain and TLS), etcd
    3100, 4369, 5601, 5672, 5984,     # Loki, Erlang epmd, Kibana, AMQP, CouchDB
    6379, 6380, 6443, 7474, 8086,     # Redis, Kubernetes API, Neo4j, InfluxDB
    8161, 8200, 8500, 8834, 8983,     # ActiveMQ console, Vault, Consul, Nessus, Solr
    9042, 9092, 9100, 9200, 9300,     # Cassandra, Kafka, node exporter, Elasticsearch HTTP and transport
    9443, 10250, 10255, 11211, 15672, # alternate HTTPS, kubelet, kubelet read-only, Memcached, RabbitMQ console
    16686, 27017, 27018, 50070, 61616, 1883, 8883,  # Jaeger, MongoDB, Hadoop, ActiveMQ, MQTT (plain and TLS)
)
TOP_PORTS = 1000
NMAP_SERVICES = ('/usr/local/share/nmap/nmap-services', '/usr/share/nmap/nmap-services')  # built from source / distro package
_port_list = []


def top_tcp_ports(count=TOP_PORTS, paths=NMAP_SERVICES):
    """The ``count`` most frequently open TCP ports from nmap's own frequency table (what ``--top-ports`` uses), or None when
    the table cannot be read."""
    for path in paths:
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                rows = []
                for line in handle:
                    parts = line.split()
                    if len(parts) < 3 or line.startswith('#') or not parts[1].endswith('/tcp'):
                        continue
                    try:
                        rows.append((float(parts[2]), int(parts[1].split('/')[0])))
                    except ValueError:
                        continue
            rows.sort(key=lambda row: (-row[0], row[1]))
            return [port for _, port in rows[:count]]
        except OSError:
            continue
    return None


def fast_flags(paths=NMAP_SERVICES):
    """FAST_FLAGS with ``--top-ports 1000`` replaced by ``-p <the top thousand plus EXTRA_PORTS>``. If nmap's frequency table
    cannot be read, FAST_FLAGS unchanged plus the extra ports cannot be expressed, so the plain top thousand is scanned."""
    if paths == NMAP_SERVICES and _port_list:
        ports = _port_list[0]
    else:
        top = top_tcp_ports(TOP_PORTS, paths)
        ports = sorted(set(top) | set(EXTRA_PORTS)) if top else None
        if paths == NMAP_SERVICES and ports:
            _port_list.append(ports)
    if not ports:
        logger.warning('nmap-services not found; scanning --top-ports %s without the extra high-risk ports', TOP_PORTS)
        return list(FAST_FLAGS)
    i = FAST_FLAGS.index('--top-ports')
    return [*FAST_FLAGS[:i], '-p', naabu_scan.port_argument(ports), *FAST_FLAGS[i + 2:]]


HOST_TIMEOUT_FAST = '8m'  # a host that has not finished in 8 minutes is skipped, not waited for
HOST_TIMEOUT_FULL = '10m'
MAX_TARGETS = 200
NMAP_CHUNK = 64  # hosts per nmap process: keeps each run's memory small, and a memory kill only repeats part of the work
PROCESS_TIMEOUT_BUFFER = 300  # on top of three host timeouts, for nmap's own startup/teardown
HOST_GROUPS_ALLOWED = 3  # hosts run in parallel groups, so a chunk takes a few host timeouts, not one per host


def _minutes(host_timeout):
    return int(host_timeout.rstrip('m'))


def build_targets(ips, limit=MAX_TARGETS):
    """Pure: the deduplicated, sorted IP list for nmap. Hostnames are never scanned: nmap resolves them to the very same
    IPs, and several names on one address would be fingerprinted once each (nmap finds the ports itself)."""
    return sorted({i for i in ips if i})[:limit]


def _is_ipv6(target):
    import ipaddress
    try:
        return ipaddress.ip_address(str(target).strip().strip('[]')).version == 6
    except ValueError:
        return False


_HOST_START = re.compile(r'<host[\s>]')


def merge_xml(first, second):
    """``first`` (an nmap XML report) with the ``<host>`` elements of ``second`` added before its closing tag, so one report can answer for an
    IPv4 run and an IPv6 run (nmap takes one address family per run). A report with no hosts adds nothing."""
    start, end = _HOST_START.search(second or ''), (second or '').rfind('</host>')
    closing = (first or '').rfind('</nmaprun>')
    if not start or end < 0 or closing < 0:
        return first if closing >= 0 or not start else second
    return first[:closing] + second[start.start():end + len('</host>')] + '\n' + first[closing:]


def run_nmap_xml(targets, flags, host_timeout, kind='nmap', wait_timeout=None, before_launch=None):
    """Write ``targets`` to a scratch file and run nmap against them, returning its XML report text. nmap scans one address family per run
    and needs ``-6`` for IPv6 (without it an IPv6 address is "failed to resolve" and the report has no host), so IPv6 targets run on their own
    with ``-6`` and their hosts are merged into the one report returned. The run waits its
    turn for memory (as heavy job ``kind``, for at most ``wait_timeout`` seconds) and raises reNgine.resources.MemoryKill if it
    had to be stopped to protect the container. ``before_launch`` may raise to revoke a job after memory admission,
    immediately before process creation; it must re-read any authorization state that could change during the wait."""
    v6 = [t for t in targets if _is_ipv6(t)]
    if v6:
        v4 = [t for t in targets if not _is_ipv6(t)]
        if v4:
            first = run_nmap_xml(v4, flags, host_timeout, kind, wait_timeout, before_launch)
            return merge_xml(first, run_nmap_xml(v6, flags, host_timeout, kind, wait_timeout, before_launch))
        flags = ['-6', *[f for f in flags if f != '-6']]
    from targetApp.target_types import refuse_local
    refuse_local('nmap')
    from reNgine import resources
    timeout = HOST_GROUPS_ALLOWED * _minutes(host_timeout) * 60 + PROCESS_TIMEOUT_BUFFER
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(targets) + '\n')
        path = f.name
    cmd = [NMAP_BIN, *flags, '--host-timeout', host_timeout, '-oX', '-', '-iL', path]
    try:
        label = ', '.join(targets[:3]) if kind != 'nmap' else f'{len(targets)} host(s)'
        with resources.heavy_job(kind, label=label, wait_timeout=wait_timeout) as job:
            if before_launch is not None:
                before_launch()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            job.attach(proc)
            try:
                out, _err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                resources.terminate_group(proc, grace=5)
                proc.communicate()
                raise
            job.raise_if_killed()
            return out
    finally:
        os.unlink(path)


def run_nmap_args(args, label, timeout):
    """Run nmap with exactly ``args`` (after the binary) and return its stdout, waiting its turn for memory like run_nmap_xml. Used by
    the validation check, which must be able to show the exact command it ran. Raises subprocess.TimeoutExpired, or
    reNgine.resources.MemoryKill if it had to be stopped to protect the container."""
    from reNgine import resources
    with resources.heavy_job('nmap', label=label) as job:
        proc = subprocess.Popen([NMAP_BIN, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        job.attach(proc)
        try:
            out, _err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            resources.terminate_group(proc, grace=5)
            proc.communicate()
            raise
        job.raise_if_killed()
        return out


def parse_xml(xml_text):
    """nmap XML report text -> extract_nmap_inventory's per-host service records; [] on anything unparseable.

    This function also reads XML a Sentinel reported (``agentapi.sentinel_dispatch.try_nmap_udp``), not only this
    process's own nmap subprocess, so an entity-expansion or external-entity payload must fail safe here exactly as it
    would from any other untrusted input, never expand or fetch anything. A real nmap report never declares a custom
    ENTITY, so one is refused outright before parsing (it is the one thing ``xmltodict.parse``'s own default entity
    handling does not stop: that default only blocks an *external* DTD/entity fetch, not an all-internal expansion
    bomb). No extra dependency: a hardened ``expat`` module here would need ``defusedexpat`` (an old, unmaintained C
    extension), not the unrelated pure-Python ``defusedxml`` package, which has no drop-in ``expat`` module at all."""
    import xmltodict

    from reNgine.nmap_service import extract_nmap_inventory
    if not (xml_text or '').strip():
        return []
    if '<!ENTITY' in xml_text:
        logger.warning('refused to parse nmap XML output: it declares a custom ENTITY')
        return []
    try:
        data = xmltodict.parse(xml_text)
    except Exception:  # noqa: BLE001 - a truncated/partial XML report, or a defused attack payload, must not crash the pipeline
        logger.warning('could not parse nmap XML output', exc_info=True)
        return []
    return extract_nmap_inventory(data)


def persist_inventory(inventory, source='nmap', org_id=None, os_reliable=None):
    """Write parsed nmap records onto Port/IpAddress, creating a Port row if nothing found it first
    (unlike reNgine.tasks.persist_nmap_service_inventory, which only enriches rows naabu already made:
    here nmap itself is the thing finding these ports, so there may be nothing to enrich yet).
    Ports are kept per IP: update_or_create_port matches by number alone, which would write the product and version
    seen on one IP's 443 onto every IP's 443. ``os_reliable`` says whether the operating system guesses in ``inventory`` were measured
    from a network that can be believed: None for a scan this server ran itself (see cveFeed.os_detection: behind Docker Desktop's
    network the guess describes the network, so it is not stored), True for a Sentinel's result."""
    from cveFeed import os_detection
    from cveFeed.host_inventory import keeps_reported_os
    from startScan.ip_rows import get_or_create_ip
    from startScan.models import TCP_PROTOCOLS, IpAddress, Port
    ports_written = hosts_with_os = 0
    now = timezone.now()
    if os_reliable is None:
        os_reliable = not os_detection.unreliable()
    for host in inventory:
        ip_addr = host.get('ip')
        if not ip_addr:
            continue
        ip_obj, _ = get_or_create_ip(ip_addr, org_id)
        if host.get('os_guess') and os_reliable and not keeps_reported_os(ip_obj):  # the host's own report outranks a network guess
            ip_obj.os_guess = host['os_guess']
            ip_obj.os_accuracy = host.get('os_accuracy')
            ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'os_source': 'nmap'}
            ip_obj.last_seen = now
            fit_columns(ip_obj)
            ip_obj.save(update_fields=['os_guess', 'os_accuracy', 'last_seen', 'fingerprint'])
            if host.get('os_matches'):  # the runners-up: a guess a few points ahead of another family is not settled
                ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'os_matches': host['os_matches']}
                ip_obj.save(update_fields=['fingerprint'])
            hosts_with_os += 1
        if host.get('closed_tcp'):
            # a port this host answered with a reset, and when: the path check (cveFeed.path_probe) probes it, from this server, later
            ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'closed_tcp': host['closed_tcp'], 'closed_tcp_at': now.isoformat()}
            ip_obj.save(update_fields=['fingerprint'])
        host_scripts = _reviewed_scripts(host.get('hostscripts'))
        if host_scripts:
            # smb-os-discovery and nbstat describe the host, not one port
            ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'scripts': host_scripts}
            ip_obj.save(update_fields=['fingerprint'])
        for rec in host.get('ports', []):
            if not rec.get('number'):
                continue
            protocol = 'udp' if rec.get('protocol') == 'udp' else 'tcp'  # UDP 161 and TCP 161 are two services: two rows
            same_protocol = ('udp',) if protocol == 'udp' else TCP_PROTOCOLS
            port = ip_obj.ports.filter(number=rec['number'], protocol__in=same_protocol).order_by('id').first()
            if port is not None and port.ports.exclude(pk=ip_obj.pk).exists():
                ip_obj.ports.remove(port)  # a row shared with other IPs by older code: give this IP its own
                port = None
            if port is not None and _unprobed(rec) and (port.product or (port.extra or {}).get('method') == 'probed'):
                # a run with no -sV (the -p- sweep, naabu) knows only that the port is open: what a fingerprinting pass found (distro,
                # package release, CPEs, TLS tunnel, the service name) is not what this run says, and must not be overwritten by a port-table guess
                for field in ('protocol', 'state'):
                    if rec.get(field):
                        setattr(port, field, rec[field])
                port.last_seen = now
                port.save(update_fields=['protocol', 'state', 'last_seen'])
                ip_obj.ports.add(port)
                ports_written += 1
                continue
            if port is None:
                port = Port(number=rec['number'], protocol=protocol, service_name=rec.get('service_name') or None)
            elif rec.get('service_name'):
                port.service_name = rec['service_name']
            if port.pk and rec.get('product') and rec['product'] != port.product:
                # a different product answers on this port now: the version, CPE and banner belonged to the old one, and a scan that
                # reports none for the new one must not leave them behind to be matched against its CVEs
                port.version = port.service_extra = port.cpe = port.banner = ''
            elif port.pk and rec.get('product') and rec.get('method') == 'probed' and not rec.get('version') and not _cpe_version(rec):
                # the same product answered and no longer states a version (server_tokens off, an upgrade): the old version, and the CPE
                # that carried it, are not what runs there now
                port.version = port.cpe = ''
            for field in ('protocol', 'state', 'product', 'version', 'service_extra', 'cpe'):
                if rec.get(field):
                    setattr(port, field, rec[field])
            info = distro_lib.parse_distro(rec.get('product', ''), rec.get('version', ''), rec.get('service_extra', ''),
                                           rec.get('cpes') or [rec.get('cpe', '')])
            # everything nmap said, not just the first CPE: the OS CPE carries the distro release, and "table" means the service
            # name was guessed from the port number, not probed (a weak signal for any conclusion drawn from it)
            port.extra = {**(port.extra or {}), 'cpes': (rec.get('cpes') or [])[:8], 'ostype': rec.get('ostype', ''),
                          'method': rec.get('method', '')}
            for key in ('tunnel', 'hostname', 'devicetype', 'confidence'):  # only what this run stated: a service that dropped TLS is not still "ssl"
                if rec.get(key):
                    port.extra[key] = rec[key]
                else:
                    port.extra.pop(key, None)
            if rec.get('tls'):
                port.tls = rec['tls']  # the certificate ssl-cert read, in the same place bbot's TLS facts go
            kept_scripts = _reviewed_scripts(rec.get('scripts'))
            if kept_scripts:
                port.extra['scripts'] = kept_scripts  # this run's reviewed NSE output; a run with none kept leaves the last in place
                port.extra['script_text'] = '\n'.join(kept_scripts.values())  # flat text for search, without the script ids
            if rec.get('banner'):
                port.banner = rec['banner']
            port.distro, port.distro_release = info['distro'], info['release']
            port.package_release, port.upstream_version = info['package_release'], info['upstream_version']
            port.source = source
            port.last_seen = now
            fit_columns(port)
            try:
                port.save()
            except DatabaseError:  # one port must not cost the rest of the chunk
                logger.warning('could not store port %s of %s', rec.get('number'), ip_addr, exc_info=True)
                continue
            ip_obj.ports.add(port)
            ports_written += 1
        close_unreported_ports(ip_obj, host)
    return {'ports': ports_written, 'hosts_with_os': hosts_with_os}


def _unprobed(rec):
    """True for a record that carries no fingerprint: nmap did not probe the service (no -sV, so the name is the port table's guess) and
    named no product, version or CPE."""
    return rec.get('method') != 'probed' and not (rec.get('product') or rec.get('version') or rec.get('cpes') or rec.get('cpe'))


def _cpe_version(rec):
    """The version an application CPE of this record states, or ''."""
    from cveFeed.correlation import parse_cpe
    return next((parsed[2] for parsed in (parse_cpe(c) for c in rec.get('cpes') or [rec.get('cpe', '')]) if parsed and parsed[2]), '')


def fit_columns(instance):
    """Clip every text value to its column, so a banner or product string a scanned host controls cannot make a save fail."""
    for field in instance._meta.concrete_fields:
        limit = getattr(field, 'max_length', None)
        value = getattr(instance, field.attname, None)
        if limit and isinstance(value, str) and len(value) > limit:
            setattr(instance, field.attname, value[:limit])


def close_unreported_ports(ip_obj, host):
    """A port the run probed and did not find open is closed now: mark it, so nothing keeps scanning, correlating or listing a
    service that is gone. Only when the host evidently answered (it reported an open port, or nmap counted closed ones: an RST
    came back), and only for TCP ports inside the set the run probed, so a top-1000 run never closes 8443 it did not try and a
    silent or unreachable host (everything "filtered") does not wipe what was open last time. Returns the ports closed."""
    scanned = host.get('scanned')
    if not scanned or host.get('timedout'):  # a host nmap gave up on was not probed to the end: what it did not list is not closed
        return 0
    reported = {rec['number'] for rec in host.get('ports', []) if rec.get('number')}
    answered = any(rec.get('state') == 'open' for rec in host.get('ports', [])) or 'closed' in (host.get('extraports') or ())
    if host.get('status', 'up') != 'up' or not answered:
        return 0
    closed = 0
    for port in ip_obj.ports.all():
        if port.number in scanned and port.number not in reported and port.protocol in ('', 'tcp') and port.state in ('', 'open'):
            port.state = 'closed'
            port.save(update_fields=['state'])
            closed += 1
    return closed


def scan_in_chunks(runner, targets, flags, host_timeout, size=NMAP_CHUNK, flags_for=None, org_id=None):
    """Run nmap over ``targets`` in chunks and persist each chunk as it finishes. If a run is stopped for memory, that
    chunk is halved and retried (down to a handful of hosts) before giving up. ``flags_for(chunk)`` may choose each chunk's flags
    (naabu's open ports); None from it means the chunk has nothing to fingerprint. Returns the summed persist counts."""
    from reNgine.resources import MemoryKill
    totals = {'ports': 0, 'hosts_with_os': 0}
    pending = [targets[i:i + size] for i in range(0, len(targets), size)]
    while pending:
        chunk = pending.pop(0)
        chunk_flags = flags_for(chunk) if flags_for else flags
        if chunk_flags is None:
            continue
        try:
            xml = runner(chunk, chunk_flags, host_timeout)
        except MemoryKill:
            if len(chunk) <= 4:
                raise
            half = len(chunk) // 2
            logger.warning('nmap was stopped for memory on %s hosts; retrying as %s + %s', len(chunk), half, len(chunk) - half)
            pending[0:0] = [chunk[:half], chunk[half:]]
            continue
        result = persist_inventory(parse_xml(xml), org_id=org_id)
        for key in totals:
            totals[key] += result.get(key, 0)
    return totals


def _plural(n, word):
    return f'{n} {word}{"s" if n != 1 else ""}'


def run_nmap_for_scan(scan_id, runner=run_nmap_xml, naabu_runner=None, force=False, dispatch=True):
    """Fingerprint the scan's discovered IPs that no scan has covered recently, in one ``-O -sV --top-ports 1000`` pass (the full-port
    sweep is the background task in cveFeed.fullscan). Only IPs are scanned, each at most once per TTL across all scans (see
    cveFeed.ledger); an IP another pipeline is scanning right now is left to it. ``runner(targets, flags, host_timeout) ->
    xml text`` is injectable so tests need no nmap binary. When naabu is installed (see cveFeed.naabu_scan) it finds the open TCP
    ports first and nmap fingerprints only those; without it, or if it fails, the ``--top-ports 1000`` pass above is unchanged.

    ``dispatch`` (on by default) is the one seam a registered Sentinel (agentapi.sentinel_dispatch) uses: after naabu
    discovers ports, each address is offered to a live, eligible Sentinel for this project; what a
    Sentinel actually fingerprints is persisted through the exact same ``persist_inventory`` this module already calls,
    and whatever is left (everything, when no Sentinel is registered or none answers in time) runs locally exactly as
    before. Callers that pass their own ``naabu_runner`` (tests) are never second-guessed: dispatch only ever supplies
    its own naabu_runner when the caller left that argument out."""
    from cveFeed import activity, ledger
    from cveFeed.nuclei_scan import scan_targets
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    from startScan.ip_rows import org_id_of_project
    org_id = org_id_of_project(project)
    _hostnames, ips, _ports = scan_targets(scan)
    all_ips = build_targets(ips, limit=None)
    from cveFeed import hosting
    shared = hosting.shared_by_address(all_ips)
    if shared:
        # Netlify, Vercel, a CDN edge: the address belongs to the platform and other customers answer on it, so it is not ours to scan
        hosting.mark_shared(shared)
        all_ips = [i for i in all_ips if i not in shared]
        providers = ', '.join(sorted({v['provider'] for v in shared.values() if v['provider']})) or 'a shared platform'
        activity.log('run_check', f'nmap left {len(shared)} shared platform address(es) alone for {domain.name} ({providers}): '
                     'other customers answer on them', project=project, scan_id=scan.id)
    if not all_ips:
        if not shared:
            activity.log('run_check', f'nmap skipped for {domain.name}: discovery found no IPs to scan', project=project)
        return {'targets': 0, 'shared': len(shared)} if shared else {'targets': 0}

    fast_todo = all_ips if force else [i for i in all_ips if i not in ledger.fresh('nmap-fast', all_ips, project)]
    if not fast_todo:
        activity.log('run_check', f'nmap skipped for {domain.name}: all {_plural(len(all_ips), "IP")} were fingerprinted '
                     f'in the last {ledger.ttl_label("nmap-fast")}', project=project, scan_id=scan.id)
        return {'targets': len(all_ips), 'reused': len(all_ips)}
    result = {'targets': len(all_ips), 'reused': len(all_ips) - len(fast_todo)}

    with ledger.claim_many(f'nmap-fast@{project}', fast_todo) as won:
        targets = build_targets(won)
        if targets:
            reused = len(all_ips) - len(fast_todo)
            note = f' ({reused} already fingerprinted in the last {ledger.ttl_label("nmap-fast")})' if reused else ''
            busy = len(fast_todo) - len(won)
            note += f' ({busy} being scanned by another scan)' if busy else ''
            fast_running = activity.log('run_check', f'nmap is fingerprinting {len(targets)} new IP(s) for {domain.name}{note} '
                                        f'(-O -sV, the top 1000 ports plus {len(EXTRA_PORTS)} high-risk ones), scan #{scan_id}', project=project, status='running', scan_id=scan.id)
            try:
                effective_naabu_runner = naabu_runner
                sentinel_targets, sentinel_totals = targets, {'ports': 0, 'hosts_with_os': 0}
                if dispatch:
                    from agentapi import sentinel_dispatch
                    if naabu_runner is None:  # a caller's own override (tests) is never second-guessed
                        effective_naabu_runner = sentinel_dispatch.wrap_naabu_runner(domain.project, scan)
                ports_by_ip = naabu_scan.discover(targets, scan, effective_naabu_runner)
                local_ports = ports_by_ip
                if dispatch:
                    sentinel_targets, sentinel_totals, local_ports = sentinel_dispatch.try_nmap(
                        domain.project, scan, targets, org_id=org_id, ports_by_ip=ports_by_ip)
                flags = fast_flags()
                # An address a Sentinel already fingerprinted has its operating system from the Sentinel: its top-up pass over the ports the
                # Sentinel missed gets no closed probe port, so nmap's OS detection does not run and cannot replace that guess with a weaker one.
                topped_up = {ip for ip in sentinel_targets if local_ports is not None and ports_by_ip is not None and ip in local_ports
                             and local_ports[ip] != ports_by_ip.get(ip)}
                fast = {'ports': 0, 'hosts_with_os': 0}
                for group, os_probe in (([i for i in sentinel_targets if i not in topped_up], True), ([i for i in sentinel_targets if i in topped_up], False)):
                    if not group:
                        continue
                    done = scan_in_chunks(runner, group, flags, HOST_TIMEOUT_FAST,
                                          flags_for=naabu_scan.flags_for(local_ports, flags, os_probe) if local_ports is not None else None,
                                          org_id=org_id)
                    fast = {key: fast.get(key, 0) + done.get(key, 0) for key in set(fast) | set(done)}
                fast = {key: fast.get(key, 0) + sentinel_totals.get(key, 0) for key in set(fast) | set(sentinel_totals)}
            except Exception as exc:  # noqa: BLE001 - a bad nmap run must not take the rest of the pipeline down
                logger.exception('nmap fast scan failed for scan %s', scan_id)
                ledger.record('nmap-fast', targets, project, scan, 'failed')
                activity.settle(fast_running, 'failed', message=f'nmap failed for {domain.name}: {exc}')
                return {**result, 'error': str(exc)}
            ledger.record('nmap-fast', targets, project, scan)
            activity.settle(fast_running, 'done', message=(
                f'nmap fingerprinted {domain.name}: {_plural(fast["ports"], "service")}, '
                f'{fast["hosts_with_os"]} OS guess{"es" if fast["hosts_with_os"] != 1 else ""}'), **fast)
            result['fast'] = fast
    return result
