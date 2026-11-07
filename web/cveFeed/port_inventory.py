"""Storing what a scanner reports about a host's ports and operating system.

The scan tools run on a Sentinel (the built-in scanner or an external one); this module is what the server does with the report:
``parse_xml`` (the scanner library's strict, hardened parser) reads a Sentinel's raw XML, and ``persist_inventory`` writes the parsed records
onto IpAddress / Port. Nothing here launches a tool.
"""
import logging

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
    network the guess describes the network, so it is not stored), True for a Sentinel's result."""
    from cveFeed import os_detection
    from cveFeed.host_inventory import keeps_reported_os
    from startScan.ip_rows import get_or_create_ip
    from startScan.models import TCP_PROTOCOLS, Port
    ports_written = hosts_with_os = 0
    now = timezone.now()
    from_here = os_reliable is None
    if from_here:
        os_reliable = not os_detection.unreliable()
    for host in inventory:
        ip_addr = host.get('ip')
        if not ip_addr:
            continue
        ip_obj, _ = get_or_create_ip(ip_addr, org_id)
        if host.get('os_guess') and os_reliable and not keeps_reported_os(ip_obj):  # the host's own report outranks a network guess
            ip_obj.os_guess = host['os_guess']
            ip_obj.os_accuracy = host.get('os_accuracy')
            # where the guess was made: a Sentinel measured it on its own network, this server's scanner on its own path
            # (cveFeed.os_detection.guess_believed), and the two are told apart later
            ip_obj.fingerprint = {**(ip_obj.fingerprint or {}), 'os_source': 'nmap' if from_here else 'sentinel'}
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
        host_scripts = reviewed_scripts(host.get('hostscripts'))
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
            if port is not None and _unprobed(rec) and (port.product or (port.extra or {}).get('method') == 'probed' or port.service_extra):
                # a run with no -sV (the -p- sweep, a port discovery pass) knows only that the port is open: what a fingerprinting pass found (distro,
                # package release, CPEs, TLS tunnel, the service name) is not what this run says, and must not be overwritten by a port-table guess.
                # A stored service_extra is a fingerprint too: only a service probe's match line gives one (the scanner's soft match "generic dns
                # response: REFUSED" names "domain" even when the probing did not finish), so 5353 stays "domain", never the table's "mdns"
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
    """True for a record that carries no fingerprint: the scanner did not probe the service (no -sV, so the name is the port table's guess) and
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
    service that is gone. Only when the host evidently answered (it reported an open port, or it counted closed ones: an RST
    came back), and only for TCP ports inside the set the run probed, so a top-1000 run never closes 8443 it did not try and a
    silent or unreachable host (everything "filtered") does not wipe what was open last time. Returns the ports closed."""
    scanned = host.get('scanned')
    if not scanned or host.get('timedout'):  # a host the scanner gave up on was not probed to the end: what it did not list is not closed
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
