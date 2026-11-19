"""Storing what a scanner reports about a host's ports and operating system.

The scan tools run on a Sentinel (the built-in scanner or an external one); this module is what the server does with the report:
``parse_xml`` (the scanner library's strict, hardened parser) reads a Sentinel's raw XML, and ``persist_inventory`` writes the parsed records
onto IpAddress / Port. Nothing here launches a tool.
"""
import logging
import re

from django.db import DatabaseError
from django.utils import timezone

from cveFeed import distro as distro_lib
from cvengine_scanner.flags import reviewed_scripts
from cvengine_scanner.nmap import parse_xml  # noqa: F401 - the one parser of a Sentinel's raw XML report, re-exported for the callers

logger = logging.getLogger(__name__)


def persist_inventory(inventory, source='nmap', org_id=None, os_reliable=None):
    """Write parsed scanner records onto Port/IpAddress, creating a Port row if nothing found it first
    (unlike reNgine.tasks.persist_nmap_service_inventory, which only enriches rows a port sweep already made:
    here the fingerprinting pass is the thing finding these ports, so there may be nothing to enrich yet).
    Ports are kept per IP: update_or_create_port matches by number alone, which would write the product and version
    seen on one IP's 443 onto every IP's 443. ``os_reliable`` says whether the operating system guesses in ``inventory`` were measured
    from a network that can be believed: None for a scan this server ran itself (see cveFeed.os_detection: behind Docker Desktop's
    network the guess describes the network, so it is not stored), True for a Sentinel's result.

    One transaction for the chunk, and a handful of statements per host whatever its port count: the IP rows of the chunk are read at once, a
    host's ports once, the ports it shares with another IP in one look, then one save of the address, one insert of the new ports and their links,
    one update of the ports that changed (only the columns that changed) and one update of the ports it closed."""
    from django.db import transaction

    from cveFeed import os_detection
    from cveFeed.host_inventory import keeps_reported_os
    from startScan.models import TCP_PROTOCOLS
    from startScan.ip_rows import get_or_create_ip
    ports_written = hosts_with_os = 0
    now = timezone.now()
    from_here = os_reliable is None
    if from_here:
        os_reliable = not os_detection.unreliable()
    hosts = [host for host in inventory if host.get('ip')]
    with transaction.atomic():
        known = _ips_of([host['ip'] for host in hosts], org_id)
        for host in hosts:
            ip_addr = host['ip']
            ip_obj = known.get(ip_addr)
            if ip_obj is None:
                ip_obj, _ = get_or_create_ip(ip_addr, org_id)
                known[ip_addr] = ip_obj
            fields = set()
            if host.get('os_guess') and os_reliable and not keeps_reported_os(ip_obj):  # the host's own report outranks a network guess
                ip_obj.os_guess = host['os_guess']
                ip_obj.os_accuracy = host.get('os_accuracy')
                # where the guess was made: a Sentinel measured it on its own network, this server's scanner on its own path
                # (cveFeed.os_detection.guess_believed), and the two are told apart later
                ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'os_source': 'nmap' if from_here else 'sentinel'}
                ip_obj.last_seen = now
                fit_columns(ip_obj)
                fields |= {'os_guess', 'os_accuracy', 'last_seen', 'fingerprint'}
                if host.get('os_matches'):  # the runners-up: a guess a few points ahead of another family is not settled
                    ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'os_matches': host['os_matches']}
                hosts_with_os += 1
            if host.get('closed_tcp'):
                # a port this host answered with a reset, and when: the path check (cveFeed.path_probe) probes it, from this server, later
                ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'closed_tcp': host['closed_tcp'], 'closed_tcp_at': now.isoformat()}
                fields.add('fingerprint')
            host_scripts = reviewed_scripts(host.get('hostscripts'))
            if host_scripts:
                # smb-os-discovery and nbstat describe the host, not one port
                ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'scripts': host_scripts}
                fields.add('fingerprint')
            if 'cuts' in host:
                # what this run cut for the host (a port list past its cap, a clipped banner, nmap's own time limit), shown on the host page: a run that cut nothing clears the last note
                fingerprint = dict(ip_obj.fingerprint or {})
                if host['cuts']:
                    fingerprint['result_cuts'] = {'nmap': host['cuts'], 'at': now.isoformat()}
                else:
                    fingerprint.pop('result_cuts', None)
                if fingerprint != (ip_obj.fingerprint or {}):
                    ip_obj.fingerprint = fingerprint
                    fields.add('fingerprint')
            if fields:
                ip_obj.save(update_fields=sorted(fields))
            if not host.get('ports') and not host.get('scanned'):
                continue  # nothing to write or close: the IP's ports are not even read
            written, linked = _persist_ports(ip_obj, host, source, now, TCP_PROTOCOLS)
            ports_written += written
            close_unreported_ports(ip_obj, host, ports=linked)
    return {'ports': ports_written, 'hosts_with_os': hosts_with_os}


_PORT_FIELDS = ('number', 'service_name', 'protocol', 'state', 'product', 'version', 'service_extra', 'cpe', 'distro', 'distro_release', 'package_release',
                'upstream_version', 'banner', 'tls', 'extra', 'source', 'last_seen')  # every column ``_persist_ports`` may change


def _ips_of(addresses, org_id):
    """``{address: IpAddress}`` for ``addresses`` in the organization: the rows that exist, read in one query (the oldest row of an address that older
    data holds twice, as ``get_or_create_ip`` picks), and the missing ones created together (a row another worker creates at the same moment wins,
    as in ``get_or_create_ip``: the insert skips it and the read finds it)."""
    from startScan.models import IpAddress
    from targetApp.target_types import is_public_address
    found = {}
    if not addresses:
        return found
    for ip in IpAddress.objects.filter(org_id=org_id, address__in=set(addresses)).order_by('id'):
        found.setdefault(ip.address, ip)
    missing = [address for address in dict.fromkeys(addresses) if address not in found]
    if missing:
        IpAddress.objects.bulk_create([IpAddress(address=address, org_id=org_id, is_private=not is_public_address(address)) for address in missing],
                                      ignore_conflicts=True)
        for ip in IpAddress.objects.filter(org_id=org_id, address__in=missing).order_by('id'):
            found.setdefault(ip.address, ip)
            ip._created_now = True  # no port can be linked to it yet: its ports are not read
    return found


def _persist_ports(ip_obj, host, source, now, tcp_protocols):
    """Write ``host``'s port records onto ``ip_obj``'s own ports (see ``persist_inventory``). Returns ``(written, linked)``: the records stored
    and the IP's ports as they stand afterwards."""
    import copy

    from django.db import transaction

    from startScan.models import IpAddress, Port
    through = IpAddress.ports.through
    linked = [] if getattr(ip_obj, '_created_now', False) else list(ip_obj.ports.order_by('id'))  # the IP's own ports, oldest first, as a lookup by number then id finds them
    before = {port.pk: {f: copy.deepcopy(getattr(port, f)) for f in _PORT_FIELDS} for port in linked}
    shared = set(through.objects.filter(port_id__in=list(before)).exclude(ipaddress_id=ip_obj.pk).values_list('port_id', flat=True)) if before else set()
    unlink, created, stored = [], [], []  # ports to unlink from this IP; new ports; the port of each record written (in record order)
    known = set(before)  # existing rows, and (by id()) the rows this run created: what a lookup in the database would have found by now
    seen = lambda port: (port.pk in known) if port.pk else (id(port) in known)  # noqa: E731
    for rec in host.get('ports', []):
        if not rec.get('number'):
            continue
        rec = mariadb_version(split_header_product(rec))
        protocol = 'udp' if rec.get('protocol') == 'udp' else 'tcp'  # UDP 161 and TCP 161 are two services: two rows
        same_protocol = ('udp',) if protocol == 'udp' else tcp_protocols
        number = int(rec['number'])
        port = next((p for p in linked if p.number == number and p.protocol in same_protocol), None)
        if port is not None and port.pk in shared:
            unlink.append(port.pk)  # a row shared with other IPs by older code: give this IP its own
            linked.remove(port)
            port = None
        if port is not None and _unprobed(rec) and (port.product or (port.extra or {}).get('method') == 'probed' or port.service_extra):
            # a run with no -sV (the -p- sweep, a port discovery pass) knows only that the port is open: what a fingerprinting pass found (distro,
            # package release, CPEs, TLS tunnel, the service name) is not what this run says, and must not be overwritten by a port-table guess.
            # A stored service_extra is a fingerprint too: only a service probe's match line gives one (the scanner's soft match "generic dns
            # response: REFUSED" names "domain" even when the probing did not finish), so 5353 stays "domain", never the table's "mdns"
            for field in ('protocol', 'state'):
                if rec.get(field):
                    setattr(port, field, rec[field])
            port.last_seen = now
            stored.append(port)
            continue
        if port is None:
            port = Port(number=number, protocol=protocol, service_name=rec.get('service_name') or None)
        elif rec.get('service_name'):
            port.service_name = rec['service_name']
        if seen(port) and rec.get('product') and rec['product'] != port.product:
            # a different product answers on this port now: the version, CPE and banner belonged to the old one, and a scan that
            # reports none for the new one must not leave them behind to be matched against its CVEs
            port.version = port.service_extra = port.cpe = port.banner = ''
        elif seen(port) and rec.get('product') and rec.get('method') == 'probed' and not rec.get('version') and not _cpe_version(rec):
            # the same product answered and no longer states a version (server_tokens off, an upgrade): the old version, and the CPE
            # that carried it, are not what runs there now, unless a fresh first-party reading of the same product on this port states it
            # (the network detection pass filled it: nmap's probe does not read it, the template does)
            port.version, port.cpe = _read_version(ip_obj, port, rec['product']), ''
        for field in ('protocol', 'state', 'product', 'version', 'service_extra', 'cpe'):
            if rec.get(field):
                setattr(port, field, rec[field])
        info = distro_lib.parse_distro(rec.get('product', ''), rec.get('version', ''), rec.get('service_extra', ''),
                                       rec.get('cpes') or [rec.get('cpe', '')], rec.get('banner') or port.banner or '')
        # everything the scanner said, not just the first CPE: the OS CPE carries the distro release, and "table" means the service
        # name was guessed from the port number, not probed (a weak signal for any conclusion drawn from it)
        port.extra = {**(port.extra or {}), 'cpes': (rec.get('cpes') or [])[:8], 'ostype': rec.get('ostype', ''),
                      'method': rec.get('method', '')}
        for key in ('tunnel', 'hostname', 'devicetype', 'confidence'):  # only what this run stated: a service that dropped TLS is not still "ssl"
            if rec.get(key):
                port.extra[key] = rec[key]
            else:
                port.extra.pop(key, None)
        if rec.get('tls'):
            port.tls = rec['tls']  # the certificate ssl-cert read, in the same place every other TLS fact goes
        kept_scripts = reviewed_scripts(rec.get('scripts'))
        if kept_scripts:
            port.extra['scripts'] = kept_scripts  # this run's reviewed NSE output; a run with none kept leaves the last in place
            port.extra['script_text'] = '\n'.join(kept_scripts.values())  # flat text for search, without the script ids
        if rec.get('banner'):
            port.banner = rec['banner']
            store_servicefp(port)
        if isinstance(rec.get('version_scripts'), dict) and rec['version_scripts']:
            # what nmap's version category scripts printed on their own (never reviewed output): kept as text for banner: and tech: search
            port.extra['version_scripts'] = {k: v for k, v in rec['version_scripts'].items() if isinstance(v, str)}
            port.extra['version_script_text'] = '\n'.join(port.extra['version_scripts'].values())[:8000]
        # the distro reading: the four columns, and the rest of it (source package, codename, how the release was read, another publisher's build)
        # for the host page and search
        store_distro(port, info)
        port.source = source
        port.last_seen = now
        fit_columns(port)
        if not seen(port):
            known.add(id(port))
            created.append(port)
            linked.append(port)
        stored.append(port)
    changed, columns = [], set()
    for port in linked:
        if port.pk in before:
            diff = {f for f in _PORT_FIELDS if getattr(port, f) != before[port.pk][f]}
            if diff:
                changed.append(port)
                columns |= diff
    columns = sorted(columns)
    failed = set()  # id() of the ports that could not be stored: one port must not cost the rest of the chunk
    if unlink or created or changed:
        try:
            with transaction.atomic():
                if unlink:
                    through.objects.filter(ipaddress_id=ip_obj.pk, port_id__in=unlink).delete()
                if created:
                    Port.objects.bulk_create(created)
                    through.objects.bulk_create([through(ipaddress_id=ip_obj.pk, port_id=port.pk) for port in created], ignore_conflicts=True)
                if changed:
                    Port.objects.bulk_update(changed, columns)
        except DatabaseError:  # one at a time, so only the port that cannot be stored is lost
            if unlink:
                through.objects.filter(ipaddress_id=ip_obj.pk, port_id__in=unlink).delete()
            fresh = {id(port) for port in created}
            for port in created + changed:
                new = id(port) in fresh
                if new:
                    port.pk = port.id = None
                try:
                    with transaction.atomic():
                        port.save(**({} if new else {'update_fields': columns}))
                        if new:
                            through.objects.get_or_create(ipaddress_id=ip_obj.pk, port_id=port.pk)
                except DatabaseError:
                    logger.warning('could not store port %s of %s', port.number, ip_obj.address, exc_info=True)
                    if new:
                        port.pk = port.id = None
                    failed.add(id(port))
    linked = [port for port in linked if id(port) not in failed or port.pk]
    return sum(1 for port in stored if id(port) not in failed), linked


def split_header_product(rec):
    """``rec`` with a Server-header token nmap stored as the product ("nginx/1.24.0 (Ubuntu)", "awselb/2.0": its http-server-header script
    fills an unidentified service's product with the header) split into the product, its version (when the scanner stated none) and the
    comment (when it stated no extra info), as nmap's own fingerprint would have stored them (``correlation.split_port_product``). A path, a
    URL or a protocol's version (Microsoft-HTTPAPI/2.0) is not split into a version. Returns a new dict; anything else unchanged."""
    from cveFeed.correlation import split_port_product
    product = rec.get('product') or ''
    if '/' not in product:
        return rec
    name, version, rest = split_port_product(product, rec.get('version') or '')
    if name == product.strip():
        return rec
    out = {**rec, 'product': name, 'version': version}
    if rest and not rec.get('service_extra'):
        out['service_extra'] = rest[:255]
    return out
_MARIADB_PREFIX = re.compile(r'^5\.5\.5-(?=\d+\.\d)')


def mariadb_version(rec):
    """``rec`` with the "5.5.5-" MariaDB's handshake puts before its version (old MySQL clients refuse a server below 5.5) taken off the
    version and the CPEs nmap read it into (``cpe:/a:mariadb:mariadb:5.5.5-10.11.19`` is MariaDB 10.11.19), so the stored version is the
    release a search for ``tech:mariadb@10.11`` and a person read. Only for MariaDB; anything else unchanged. Returns a new dict."""
    names = f"{rec.get('product') or ''} {rec.get('version') or ''} {rec.get('cpe') or ''} {' '.join(rec.get('cpes') or [])}".lower()
    if 'mariadb' not in names:
        return rec
    out = {**rec, 'version': _MARIADB_PREFIX.sub('', str(rec.get('version') or ''))}
    fix = lambda cpe: re.sub(r'(?i)^(cpe:/a:mariadb:mariadb:)5\.5\.5-(?=\d)', r'\1', cpe) if isinstance(cpe, str) else cpe  # noqa: E731
    if rec.get('cpe'):
        out['cpe'] = fix(rec['cpe'])
    if rec.get('cpes'):
        out['cpes'] = [fix(c) for c in rec['cpes']]
    return out


def store_distro(port, info):
    """Write a distro reading (``distro.parse_distro``) onto a Port row in memory: the four columns and ``extra['distro']``
    (``correlation.stored_distro``). Returns whether anything changed; the caller saves."""
    from cveFeed.correlation import stored_distro
    before = (port.distro, port.distro_release, port.package_release, port.upstream_version, (port.extra or {}).get('distro') or {})
    port.distro, port.distro_release = info['distro'][:16], info['release'][:16]
    port.package_release, port.upstream_version = info['package_release'][:64], info['upstream_version'][:64]
    extra = dict(port.extra or {})
    kept = stored_distro(info)
    if kept:
        extra['distro'] = kept
    else:
        extra.pop('distro', None)
    port.extra = extra
    return before != (port.distro, port.distro_release, port.package_release, port.upstream_version, kept)


def _read_version(ip_obj, port, product):
    """The version a fresh first-party reading of ``product`` states for ``port`` (the network detection pass's reading,
    ``source_versions.NUCLEI_PROBE``: it filled it into the row, ``cveFeed.network_detection``), or ''. Fresh: seen inside the pass's ledger
    window; a pass that no longer reads it drops it."""
    from datetime import timedelta

    from cveFeed import ledger, network_detection, source_versions
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    fill = (port.extra or {}).get(network_detection.FILL_KEY) if isinstance(port.extra, dict) else None
    version = (port.version or '').strip()
    if not version or not isinstance(fill, dict) or fill.get('version') != version:
        return ''
    hosts = {n.lower().rstrip('.') for n in Subdomain.objects.filter(ip_addresses=ip_obj).values_list('name', flat=True)[:200]}
    cutoff = timezone.now() - timedelta(seconds=ledger.ttl(network_detection.SERVICE))
    for row in ProbeObservation.objects.filter(probe=source_versions.NUCLEI_PROBE, host__in=hosts, port=port.number, kind='version', outcome='found',
                                               version=version, observed_at__gte=cutoff):
        if network_detection._same_product(row.product, product):
            return version
    return ''


def _unprobed(rec):
    """True for a record that carries no fingerprint: the scanner did not probe the service (no -sV, so the name is the port table's guess) and
    named no product, version or CPE."""
    return rec.get('method') != 'probed' and not (rec.get('product') or rec.get('version') or rec.get('cpes') or rec.get('cpe'))


def _cpe_version(rec):
    """The version an application CPE of this record states, or ''."""
    from cveFeed.correlation import parse_cpe
    return next((parsed[2] for parsed in (parse_cpe(c) for c in rec.get('cpes') or [rec.get('cpe', '')]) if parsed and parsed[2]), '')


def fit_columns(instance):
    """Clip every text value to its column, and drop the NUL characters PostgreSQL refuses to store, so a banner or product string a scanned
    host controls cannot make a save fail."""
    for field in instance._meta.concrete_fields:
        limit = getattr(field, 'max_length', None)
        value = getattr(instance, field.attname, None)
        if isinstance(value, str) and '\x00' in value:
            value = value.replace('\x00', '')
            setattr(instance, field.attname, value)
        if limit and isinstance(value, str) and len(value) > limit:
            setattr(instance, field.attname, value[:limit])


def close_unreported_ports(ip_obj, host, ports=None):
    """A port the run probed and did not find open is closed now: mark it, so nothing keeps scanning, correlating or listing a
    service that is gone. Only when the host evidently answered (it reported an open port, or it counted closed ones: an RST
    came back), and only for TCP ports inside the set the run probed, so a top-1000 run never closes 8443 it did not try and a
    silent or unreachable host (everything "filtered") does not wipe what was open last time. ``ports``: the IP's ports when the caller
    holds them already (else they are read). Returns the ports closed."""
    from startScan.models import Port
    scanned = host.get('scanned')
    if not scanned or host.get('timedout'):  # a host the scanner gave up on was not probed to the end: what it did not list is not closed
        return 0
    reported = {rec['number'] for rec in host.get('ports', []) if rec.get('number')}
    answered = any(rec.get('state') == 'open' for rec in host.get('ports', [])) or 'closed' in (host.get('extraports') or ())
    if host.get('status', 'up') != 'up' or not answered:
        return 0
    closing = [port for port in (ip_obj.ports.all() if ports is None else ports)
               if port.number in scanned and port.number not in reported and port.protocol in ('', 'tcp') and port.state in ('', 'open')]
    if closing:
        Port.objects.filter(pk__in=[port.pk for port in closing]).update(state='closed')
        for port in closing:
            port.state = 'closed'
    return len(closing)


def store_servicefp(port):
    """Keep the decoded text of a banner that is nmap's service fingerprint (``cveFeed.servicefp``) in ``Port.extra['servicefp']`` (what
    ``banner:`` and ``tech:`` search, and what the host page shows), or drop it when the banner is no fingerprint. In memory; the caller saves.
    Returns whether it changed."""
    from cveFeed import servicefp
    extra = dict(port.extra or {}) if isinstance(port.extra, dict) else {}
    decoded = servicefp.text(port.banner or '')
    before = extra.get('servicefp')
    if decoded:
        extra['servicefp'] = decoded
    else:
        extra.pop('servicefp', None)
    port.extra = extra
    return before != extra.get('servicefp')
