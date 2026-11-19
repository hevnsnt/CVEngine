"""Service feature readings a Sentinel made of an address, stored for the host names of the project at that address.

The fingerprint pass and the ``ssh_probe`` kind talk to an address, not a name: their ``service_features`` items (``cvengine_scanner.features``:
SSH algorithms, SMTP EHLO keywords, SMB dialect, compression, signing and SMBv1, RDP NLA) name the IP address they were read from. A reading of the
service on that address and port holds for every host name of the project's current inventory that resolves to it (``correlation.latest_scan_q``)
and for the address itself when the project holds it as a host or target. This module expands the items to those names and stores them through the
one ingest every kind uses (``service_features.ingest``), which re-evaluates the CVE matches of the hosts whose readings changed.

``covered``: when a result read a service (any reading of one family, ``family``, on an address and port), every feature of that family the kind
reads there is covered, so a stored reading the new result did not repeat is removed (unknown), never kept stale and never read as "no".
None of these features is edge-sensitive: a CDN does not answer SSH, SMTP, SMB or RDP for a host.
"""
import logging

from cvengine_scanner.features import MAX_ITEMS, clean_features

logger = logging.getLogger(__name__)

MAX_NAMES_PER_ADDRESS = 200  # host names one address's readings are stored for (a shared hosting address can carry thousands)

# the features each kind reads, by family: what a result that read the family on an endpoint covers there (the fingerprint pass's and ssh_probe's)
FINGERPRINT_FEATURES = ('ssh_terrapin', 'ssh_cbc', 'ssh_aes_gcm', 'rdp_nla', 'smtp_chunking', 'smtp_starttls', 'smtp_smtputf8', 'smtp_8bitmime',
                 'smtp_pipelining', 'smtp_auth', 'smb_dialect', 'smb_compression', 'smb_signing', 'smbv1')
SSH_PROBE_FEATURES = ('ssh_terrapin', 'ssh_cbc', 'ssh_aes_gcm', 'ssh_auth_methods')


def family(feature):
    """``ssh``, ``smtp``, ``smb`` (smbv1 included) or ``rdp``: the service a feature is read from."""
    return 'smb' if feature.startswith('smb') else feature.split('_', 1)[0]


def names_at(project_id, addresses):
    """``{address: [names]}``: the project's current host names that resolve to each address, and the address itself (stored only when the project
    holds it as a host or a target: ``service_features.ingest`` skips any other)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    addresses = sorted({str(a) for a in addresses if a})
    out = {a: [a] for a in addresses}
    if not addresses:
        return out
    current = Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id).values('pk')
    rows = (Subdomain.objects.filter(pk__in=current, ip_addresses__address__in=addresses)
            .values_list('ip_addresses__address', 'name').distinct().order_by('ip_addresses__address', 'name'))
    for address, name in rows:
        name = (name or '').lower().rstrip('.')
        if name and name not in out[address] and len(out[address]) < MAX_NAMES_PER_ADDRESS + 1:
            out[address].append(name)
    return out


def store(project_id, items, source, names_by_address, reads, now=None):
    """Store the readings ``items`` (each naming an address) for the names at that address (``names_by_address``, ``names_at``'s shape). Only
    addresses in ``names_by_address`` are stored: the caller passes the ones its task asked. ``source`` is the task kind and ``reads`` the features
    it reads (``FINGERPRINT_FEATURES``, ``SSH_PROBE_FEATURES``): a reading of another feature is not stored. Returns the totals of
    ``service_features.ingest``. Never raises: a reading that cannot be stored costs only itself."""
    from cveFeed import service_features
    by_name = {}
    for item in clean_features(items):
        if item['feature'] not in reads:
            continue
        for name in names_by_address.get(item['host'], ()):
            entry = by_name.setdefault(name, {'items': [], 'covered': set()})
            entry['items'].append({**item, 'host': name})
            entry['covered'] |= {(name, item['port'], f) for f in reads if family(f) == family(item['feature'])}
    totals = {'stored': 0, 'removed': 0, 'changed_hosts': []}
    batch, covered = [], set()

    def flush():
        if not batch:
            return
        try:
            done = service_features.ingest(project_id, list(batch), source, covered=set(covered), now=now)
        except Exception:  # noqa: BLE001 - the result's own records are stored already; the readings come again with the next pass
            logger.exception('could not store %d service feature reading(s) of a %s result', len(batch), source)
            return
        totals['stored'] += done['stored']
        totals['removed'] += done['removed']
        totals['changed_hosts'] += done['changed_hosts']

    for name, entry in sorted(by_name.items()):
        if batch and len(batch) + len(entry['items']) > MAX_ITEMS:  # a name's readings stay in one batch: its covered set is whole
            flush()
            batch, covered = [], set()
        batch.extend(entry['items'][:MAX_ITEMS])
        covered |= entry['covered']
    flush()
    return totals


def store_fingerprint(project_id, result, addresses, source, now=None):
    """The readings of a fingerprint pass's result (its cleaned ``service_features``; ``source`` is its task kind) for the addresses its task
    asked (``addresses``)."""
    items = (result or {}).get('service_features') or []
    if not items:
        return {'stored': 0, 'removed': 0, 'changed_hosts': []}
    asked = {str(a) for a in addresses}
    read = {i.get('host') for i in items if isinstance(i, dict)} & asked
    return store(project_id, items, source, names_at(project_id, read), FINGERPRINT_FEATURES, now=now)
