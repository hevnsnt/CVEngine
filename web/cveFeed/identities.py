"""Which network operating system or appliance a host is, from what a scan already stored: no request is made here.

A FortiGate's port scan says "Fortinet FortiOS 6.2 - 7.2" in its OS guess and its management certificate is the factory one (``CN=FG101FTK...,
O=Fortinet``), yet nothing made it a product: an operating system guess is never matched by name, and a certificate was only shown. The guess, its
runners-up and the certificate are read here against ``data/network_identities.json`` (the network operating systems whose CVE records name them,
``recog.NETWORK_OS``'s, and a curated table of appliance default certificates, each with its source), and an operating system CPE a port carries
for one of them is read the same way. Each is an identity reading (``cveFeed.identity_readings``: no version, outcome ``hidden``, never a
technology) under ``vsrc:nmap`` (``source_versions.nmap_readings``): shown, searched (``tech:fortios``, ``component:fortios``, ``os:fortios``),
a lead for the version source reads (``version_sources.host_products``: the edge build reads of FortiOS and PAN-OS) and for correlation
(``collect_leads``: a product seen without a version is a lead for the targeted checks, never a match).

An OS guess counts only where it can be believed (``os_detection.guess_believed``) and, for a runner-up, at 85% accuracy or more.
"""
import functools
import json
import os
import re

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'network_identities.json')
MIN_RUNNER_UP_ACCURACY = 85


@functools.lru_cache(maxsize=1)
def table():
    """``(systems, certificates)`` of the data file, patterns compiled."""
    with open(DATA_FILE, encoding='utf-8') as fh:
        doc = json.load(fh)
    systems = [(e['product'], e.get('cpe') or '', re.compile(e['guess'], re.I)) for e in doc.get('systems', ())]
    certificates = [(e['product'], e.get('cpe') or '', e.get('field') or 'subject', [re.compile(p, re.I) for p in e.get('all', ())], e.get('source') or '')
                    for e in doc.get('certificates', ())]
    return systems, certificates


def system_of(text):
    """``(product, CPE)`` of the network operating system an OS name names, or None."""
    text = str(text or '')[:200]
    for product, cpe, pattern in table()[0]:
        if pattern.search(text):
            return product, cpe
    return None


def _reading(product, cpe, said, source='nmap-os'):
    from cveFeed import identity_readings
    return identity_readings.reading(product, source, evidence=said, cpe=cpe)


def guess_readings(ip):
    """The identity readings an address's OS guess and its believable runners-up name (``[reading]``)."""
    from cveFeed import os_detection
    if not os_detection.guess_believed(ip):
        return []
    fingerprint = ip.fingerprint if isinstance(ip.fingerprint, dict) else {}
    names = [(ip.os_guess or '', 'nmap OS guess')]
    for match in (fingerprint.get('os_matches') or [])[:5] if isinstance(fingerprint.get('os_matches'), list) else ():
        if isinstance(match, dict):
            try:
                accuracy = int(match.get('accuracy') or 0)
            except (TypeError, ValueError):
                accuracy = 0
            if accuracy >= MIN_RUNNER_UP_ACCURACY:
                names.append((str(match.get('name') or ''), f'nmap OS match ({accuracy}%)'))
    out, seen = [], set()
    for name, how in names:
        found = system_of(name)
        if found and found[0] not in seen:
            seen.add(found[0])
            out.append(_reading(found[0], found[1], f'{how}: {name[:120]} ({ip.address})'))
    return [r for r in out if r]


def certificate_readings(port):
    """The identity readings a port's certificate (``Port.tls``: ssl-cert's subject and issuer) names: the first appliance whose every pattern
    matches."""
    tls = port.tls if isinstance(getattr(port, 'tls', None), dict) else {}
    for product, cpe, field, patterns, _source in table()[1]:
        text = str(tls.get(field) or '')[:300]
        if text and patterns and all(p.search(text) for p in patterns):
            got = _reading(product, cpe, f'certificate {field} on port {port.number}: {text[:160]}', source='nmap-ssl-cert')
            return [got] if got else []
    return []


def cpe_readings(port):
    """The identity (or, versioned, product) readings the operating system CPEs nmap gave a port name, for a network operating system of the
    table (``cpe:/o:fortinet:fortios``): nmap names the system a service runs on, and only these systems' records name them."""
    from cveFeed import source_versions
    extra = port.extra if isinstance(port.extra, dict) else {}
    out = []
    for cpe in [port.cpe, *(extra.get('cpes') or [])][:9]:
        found = re.match(r'^cpe:/o:([^:\s]+):([^:\s]+)(?::([^:\s]*))?', str(cpe or '').strip(), re.I)
        if not found:
            continue
        system = system_of(f'{found.group(1)} {found.group(2)}'.replace('_', ' '))
        if not system:
            continue
        version = found.group(3) or ''
        said = f'nmap CPE {cpe}'
        got = source_versions.product_reading(system[0], version, 'nmap-cpe', evidence=said, cpe=cpe) if version not in ('', '-', '*') else None
        out.append(got or _reading(system[0], cpe, said, source='nmap-cpe'))
    return [r for r in out if r]


def host_readings(sub, ports):
    """``[(port number, reading)]``: what the host's addresses' OS guesses (port 0), its open ports' certificates and operating system CPEs name."""
    out, seen = [], set()
    for ip in sub.ip_addresses.all():
        for r in guess_readings(ip):
            if (0, r['label']) not in seen:
                seen.add((0, r['label']))
                out.append((0, r))
    for _address, port in ports:
        if port.state not in ('', 'open'):
            continue
        for r in certificate_readings(port) + cpe_readings(port):
            if (port.number, r['label']) not in seen:
                seen.add((port.number, r['label']))
                out.append((port.number, r))
    return out


def products(sub):
    """``[(product, '')]`` of the identity readings stored for ``sub`` (``version_sources.host_products``: a lead for the version source reads)."""
    return [(row.product, '') for row in products_rows(sub)]


def collect_leads(subdomain, product_index, cve_by_id, rows, scan_history=None, min_confidence=0.0, leads=None):
    """The identity readings of ``subdomain`` as correlation's unversioned products: each a lead (``correlation._record_matches`` with no version:
    the CVEs it could be about), never a match. Returns 0 (no match is made)."""
    if leads is None:
        return 0
    from cveFeed.correlation import _MIN_TOKEN, _norm, _record_matches
    for row in products_rows(subdomain):
        token = _norm(row.product)
        if len(token) < _MIN_TOKEN:
            continue
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        _record_matches(subdomain, row.product, '', token, 'tech', product_index, cve_by_id, min_confidence, scan_history, rows,
                        cpe=(ev.get('cpe') or '')[:255], leads=leads)
    return 0


def products_rows(sub):
    """The identity readings stored for ``sub``: first-party rows that name a product with no version (outcome ``hidden``)."""
    from cveFeed import source_versions
    return [row for row in source_versions._rows(sub)
            if row.kind == 'version' and row.outcome == 'hidden' and not row.version and row.probe in source_versions.FIRST_PARTY_PROBES]


def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_identities --apply``): decode the service fingerprints the ports already store
    (``Port.extra['servicefp']``, ``cveFeed.servicefp``), then read every current host's stored data again (``version_sources.refresh_host``: the
    network operating system its OS guess, certificates and OS CPEs name, Recog's identities and the hardware it names, the headers of a decoded
    fingerprint) and correlate the hosts that gained or lost a reading. Idempotent. Returns ``{'ports', 'hosts', 'moved', 'matches'}``."""
    import logging

    from cveFeed import correlation, port_inventory, version_sources
    from startScan.models import Port, Subdomain
    logger = logging.getLogger(__name__)
    fingerprints = Port.objects.filter(banner__startswith='SF-Port')
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(base.order_by('id').values_list('id', flat=True))
    out = {'ports': fingerprints.count(), 'hosts': len(ids), 'moved': 0, 'matches': 0}
    if not apply:
        return out
    for port in fingerprints.iterator(chunk_size=500):
        if port_inventory.store_servicefp(port):
            port.save(update_fields=['extra'])
    moved = []
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        for sub in subs:
            try:
                version_sources.refresh_host(sub)
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('identity catch-up of host %s failed', sub.pk)
                continue
            if getattr(sub, '_version_changed', False):
                moved.append(sub.pk)
    # the SSH banners the SSH inspection stored (cveFeed.ssh_scan): read as vsrc:ssh readings of the host's current row
    from cveFeed import source_versions, ssh_scan
    from cveFeed.models import ProbeObservation
    for row in ProbeObservation.objects.filter(probe=ssh_scan.PROBE, kind=ssh_scan.OBS_KIND, product=ssh_scan.BANNER_ID, outcome='found').iterator(chunk_size=500):
        evidence = row.evidence if isinstance(row.evidence, dict) else {}
        sub = source_versions._current_row(row.domain_id, row.host)
        if sub is None or not isinstance(evidence.get('evidence'), str):
            continue
        try:
            if source_versions.store_ssh(sub, row.port, evidence['evidence']) and sub.pk not in moved:
                moved.append(sub.pk)
        except Exception:  # noqa: BLE001 - one banner never stops the catch-up
            logger.exception('SSH banner catch-up of host %s failed', sub.pk)
    out['moved'] = len(moved)
    if moved:
        cve_by_id, index = correlation.cve_pool()
        for start in range(0, len(moved), batch):
            subs = list(Subdomain.objects.filter(pk__in=moved[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out
