"""Keep cvENGINE in step with a project's runZero inventory (see cveFeed.runzero for the client).

Two jobs, one pass:

* Enrichment, always on once a runZero token is saved. For every runZero asset whose address is an IP cvENGINE already holds for
  this project (``IpAddress``, in the project's organization and reached through one of its own hosts), runZero's facts (OS, hardware,
  type, tags, site, names, last seen) are stored under ``IpAddress.fingerprint['runzero']`` and an empty ``os_guess`` is filled.
  runZero's own CVE reports for those hosts are stored beside them and are additional evidence only: they raise the confidence of a
  CVE match cvENGINE already found on that host and port, they never create a match and never confirm one.
* Import, off until the project turns it on. Addresses runZero knows and cvENGINE does not are added as targets through the same
  code as Add targets (``agentapi.services.add_entries``), so exclusions, the private-range policy and organization uniqueness all
  apply. A public address is imported only inside a network the organization already has as a target (a CIDR block or address). Names are imported only when they sit under a domain the organization already has: a name on a network is claimed by
  whoever runs that device, so it is never trusted as a scope decision.

A sync never raises: its outcome (or the reason it failed) is recorded on ``RunZeroSync`` and in the activity feed.
"""
import logging
import os
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from cveFeed import activity, runzero

logger = logging.getLogger(__name__)

SERVICE = 'runzero'
DEFAULT_INTERVAL_HOURS = 6
DEFAULT_IMPORT_MAX = 500
STALE_RUNNING = timedelta(minutes=30)  # a "running" row older than this is a worker that died, not a sync in progress
MIN_GAP = timedelta(seconds=60)  # Sync now cannot be repeated faster than this
MAX_VULNS_PER_IP = 50
CHUNK = 1000


def _env_int(name, default, low, high):
    try:
        return min(high, max(low, int(os.environ.get(name, default))))
    except ValueError:
        return default


def interval_hours():
    """How often each project syncs, from CVENGINE_RUNZERO_SYNC_HOURS (default 6, at least 1)."""
    return _env_int('CVENGINE_RUNZERO_SYNC_HOURS', DEFAULT_INTERVAL_HOURS, 1, 24 * 14)


def import_max():
    """The most new targets one sync may add, from CVENGINE_RUNZERO_IMPORT_MAX (default 500). The rest wait for the next sync."""
    return _env_int('CVENGINE_RUNZERO_IMPORT_MAX', DEFAULT_IMPORT_MAX, 1, 5000)


def token_for(project):
    """The project's (or its organization's) runZero token, or ''."""
    from cveFeed.api_credentials import resolve_for_project
    return str((resolve_for_project(project).get(SERVICE) or {}).get('api_key') or '').strip()


def settings_for(project):
    from cveFeed.models import RunZeroSync
    return RunZeroSync.objects.get_or_create(project=project)[0]


def clean_search(value):
    """A runZero search string as stored: printable text, at most 300 characters; blank means the default."""
    text = ''.join(c for c in str(value or '') if c.isprintable()).strip()[:300]
    return text or 'alive:true'


def _iso(value):
    return value.isoformat() if value else None


def status(project):
    """What the API keys page, REST and MCP show about this project's runZero sync. Nothing secret."""
    from cveFeed.models import RunZeroSync
    row = RunZeroSync.objects.filter(project=project).first()
    running = bool(row and row.status == 'running' and row.started_at and timezone.now() - row.started_at < STALE_RUNNING)
    state = 'running' if running else (row.status if row and row.status in ('ok', 'error') else 'never')
    return {'configured': bool(token_for(project)), 'import_enabled': bool(row and row.import_enabled),
            'search': row.search if row else RunZeroSync.DEFAULT_SEARCH,
            'state': state,
            'last_sync_at': _iso(row.last_sync_at) if row else None, 'last_ok_at': _iso(row.last_ok_at) if row else None,
            'last_error': (row.last_error or None) if row else None, 'counts': (row.counts or {}) if row else {},
            'interval_hours': interval_hours(), 'import_max': import_max()}


# --- host facts ----------------------------------------------------------------------------------------------------

def _newest_by_address(assets):
    """{address: asset}: when runZero lists one address on several assets (two sites, a re-used address) the most recently seen wins."""
    out = {}
    for asset in assets:
        for address in asset['addresses']:
            if address not in out or asset['last_seen'] > out[address]['last_seen']:
                out[address] = asset
    return out


def _known_ips(project, addresses):
    """The project's own IpAddress rows (its organization's rows, reached through one of the project's hosts) for these addresses.
    Another organization's rows for the same address are different rows and are never returned."""
    from startScan.models import IpAddress
    addresses = sorted(addresses)
    found = []
    for start in range(0, len(addresses), CHUNK):
        found += IpAddress.objects.filter(org_id=project.org_id, address__in=addresses[start:start + CHUNK],
                                          ip_addresses__target_domain__project=project).distinct()
    return found


def _block(asset, reports):
    vulns = sorted(reports, key=lambda r: -(r['cvss3'] or 0))[:MAX_VULNS_PER_IP]
    return {'asset_id': asset['id'], 'os': asset['os'], 'os_version': asset['os_version'], 'hw': asset['hw'], 'type': asset['type'],
            'tags': asset['tags'], 'site': asset['site'], 'names': asset['names'], 'alive': asset['alive'], 'last_seen': asset['last_seen'],
            'vulns': [{k: v[k] for k in ('cve', 'port', 'transport', 'severity', 'cvss3', 'name')} for v in vulns]}


def _store(ip, block):
    """Write ``block`` on the address. True when anything changed (an unchanged block is not rewritten, so a sync of an unchanged
    inventory writes nothing). nmap and the service-intel stage keep their own keys in ``fingerprint``; this one is only ours."""
    fingerprint = dict(ip.fingerprint or {})
    fields = []
    if {k: v for k, v in (fingerprint.get('runzero') or {}).items() if k != 'updated'} != block:
        fingerprint['runzero'] = {**block, 'updated': timezone.now().isoformat()}
        ip.fingerprint = fingerprint
        fields.append('fingerprint')
    os_text = ' '.join(p for p in (block['os'], block['os_version']) if p)[:255]
    if os_text and not ip.os_guess:
        ip.os_guess = os_text
        fields.append('os_guess')
    if fields:
        ip.save(update_fields=fields)
    return bool(fields)


def _corroborate_matches(project, ips):
    """Raise the confidence of the project's existing port-based CVE matches that runZero also reports, once each. Matches the AI
    ruled out or the distribution patched are left alone, and ``ai_verdict`` is never touched: this is evidence, not a verdict."""
    from cveFeed.models import CVEMatch
    changed = 0
    for ip in ips:
        cves = {v['cve'] for v in ((ip.fingerprint or {}).get('runzero') or {}).get('vulns') or []}
        if not cves:
            continue
        matches = CVEMatch.objects.filter(subdomain__target_domain__project=project, subdomain__ip_addresses=ip, source='port',
                                          cve_entry__cve_id__in=cves).exclude(ai_verdict='not_affected').exclude(distro_status='patched')
        for match in matches.select_related('cve_entry').distinct():
            evidence = dict(match.evidence or {})
            if evidence.get('runzero') or match.cve_entry.cve_id not in runzero.reported_cves(ip, evidence.get('port')):
                continue
            match.confidence, match.evidence = runzero.boosted(match.confidence), {**evidence, 'runzero': True, 'confidence_before': match.confidence}
            match.save(update_fields=['confidence', 'evidence', 'updated_at'])
            changed += 1
    return changed


def _forget_absent(project, present):
    """Remove runZero's block from the project's addresses runZero no longer lists: an asset that left the inventory must not keep describing
    the host (its OS, its CVE reports) for ever. Returns how many were cleared."""
    from startScan.models import IpAddress
    stale = IpAddress.objects.filter(org_id=project.org_id, fingerprint__has_key='runzero', ip_addresses__target_domain__project=project
                                     ).exclude(address__in=list(present)).distinct()
    cleared = 0
    for ip in stale:
        fingerprint = dict(ip.fingerprint or {})
        fingerprint.pop('runzero', None)
        ip.fingerprint = fingerprint
        ip.save(update_fields=['fingerprint'])
        cleared += 1
    return cleared


def _retract_matches(project):
    """Take back the confidence boost of a match whose CVE runZero no longer reports for the host (the report went away, or the asset left
    the inventory): the evidence it was boosted by is gone. Returns how many were retracted."""
    from cveFeed.models import CVEMatch
    changed = 0
    boosted = CVEMatch.objects.filter(subdomain__target_domain__project=project, source='port', evidence__runzero=True).select_related('cve_entry')
    for match in boosted.distinct():
        evidence = dict(match.evidence or {})
        reported = any(match.cve_entry.cve_id in runzero.reported_cves(ip, evidence.get('port')) for ip in match.subdomain.ip_addresses.all())
        if reported:
            continue
        before = evidence.pop('confidence_before', None)
        evidence.pop('runzero', None)
        match.confidence = before if isinstance(before, (int, float)) else max(0.0, round(match.confidence - runzero.BOOST, 2))
        match.evidence = evidence
        match.save(update_fields=['confidence', 'evidence', 'updated_at'])
        changed += 1
    return changed


def _enrich(project, by_ip, reports, partial=False):
    """Store runZero's facts on the project's matching addresses. ``(matched, updated, reports_kept, corroborated)``. ``partial`` says
    the walk stopped early (the quota, the record cap) so the lists are not all of runZero's answer: what was read is stored, but a block
    or a CVE report that is merely absent from it is kept, never taken to mean runZero dropped it. The same goes for an empty answer
    while hosts carry runZero data (a token whose search scope changed): nothing is retired on silence."""
    known = _known_ips(project, by_ip)
    by_address = {}
    for report in reports:
        by_address.setdefault(report['address'], []).append(report)
    updated = kept = 0
    for ip in known:
        mine = by_address.get(ip.address, [])
        kept += len(mine)
        block = _block(by_ip[ip.address], mine)
        if partial:
            block['vulns'] = ((ip.fingerprint or {}).get('runzero') or {}).get('vulns', []) if not mine else block['vulns']
        updated += _store(ip, block)
    forgotten = 0
    if not partial and by_ip:
        forgotten = _forget_absent(project, by_ip)
        _retract_matches(project)
    return len(known), updated + forgotten, kept, _corroborate_matches(project, known)


# --- importing targets ---------------------------------------------------------------------------------------------

def _apexes(project):
    from targetApp.models import org_domains
    from targetApp.target_types import DOMAIN, classify_target
    return {n.lower() for n in org_domains(project).values_list('name', flat=True) if classify_target(n) == DOMAIN}


def _in_scope(name, apexes):
    parts = name.lower().split('.')
    return any('.'.join(parts[i:]) in apexes for i in range(len(parts)))


def _existing(project, names):
    from targetApp.models import org_domains
    names = list(names)
    have = set()
    for start in range(0, len(names), CHUNK):
        have.update(org_domains(project).filter(name__in=names[start:start + CHUNK]).values_list('name', flat=True))
    return have


def _owned_networks(project):
    """The networks the organization already has as targets (a CIDR block or a single address): the proof that it may scan inside them."""
    import ipaddress

    from targetApp.models import org_domains
    from targetApp.target_types import CIDR, IP, classify_target
    networks = []
    for name in org_domains(project).values_list('name', flat=True):
        if classify_target(name) in (CIDR, IP):
            try:
                networks.append(ipaddress.ip_network(name.strip(), strict=False))
            except ValueError:
                continue
    return networks


def _may_import(address, networks):
    """A public address is imported only inside a network the organization already owns as a target: an inventory search such as ``alive:true``
    can hold third-party addresses (a partner's range, a cloud address a device talked to), and nobody authorized scanning those. An address
    that is not a public one (a private or tailnet range) is only here because the operator's policy already allows scanning that range."""
    import ipaddress
    ip = ipaddress.ip_address(address)
    if not ip.is_global:
        return True
    return any(ip.version == net.version and ip in net for net in networks)


def _import_candidates(project, assets):
    """``(entries, skipped)``: new IPs and in-scope names worth adding (at most the import cap), and why the others were not."""
    from targetApp.target_types import DOMAIN, classify_target, is_scannable_ip
    skipped = {}
    networks = _owned_networks(project)

    def skip(reason, count=1):
        skipped[reason] = skipped.get(reason, 0) + count
    apexes = _apexes(project)
    wanted, seen = [], set()
    for asset in assets:
        for address in asset['addresses']:
            if address in seen:
                continue
            seen.add(address)
            if is_scannable_ip(address):
                if _may_import(address, networks):
                    wanted.append(address)
                else:
                    skip('not_owned')  # a public address outside every network the organization has as a target
            else:
                skip('blocked')  # loopback, link-local or, unless CVENGINE_ALLOW_PRIVATE_TARGETS is set, a private range
        for name in asset['names']:
            name = name.lower().rstrip('.')
            if name in seen or classify_target(name) != DOMAIN or '.' not in name:
                continue  # NetBIOS names and other words are not targets
            seen.add(name)
            if _in_scope(name, apexes):
                wanted.append(name)
            else:
                skip('name_out_of_scope')
    have = _existing(project, wanted)
    fresh = [w for w in wanted if w not in have]
    skip('already_known', len(wanted) - len(fresh))
    limit = import_max()
    if len(fresh) > limit:
        skip('over_cap', len(fresh) - limit)
    return fresh[:limit], skipped


def _import(project, assets):
    """``(imported, skipped)``. New targets go through Add targets' own code and are queued for discovery like any other."""
    from agentapi import services
    entries, skipped = _import_candidates(project, assets)
    if not entries:
        return 0, skipped
    try:
        result = services.add_entries(project, entries, discover=True)
    except services.ApiError as exc:
        skipped['rejected'] = len(entries)
        logger.warning('runZero import for project %s was refused: %s', project.pk, exc.message)
        return 0, skipped
    for key, value in (('already_known', len(result['already_exists'])),
                       ('excluded', sum('excluded' in str(i.get('error', '')) for i in result['invalid'])),
                       ('invalid', sum('excluded' not in str(i.get('error', '')) for i in result['invalid']))):
        if value:
            skipped[key] = skipped.get(key, 0) + value
    return result['created'], skipped


# --- one sync --------------------------------------------------------------------------------------------------------

def _claim(project):
    """The project's RunZeroSync row, marked running, or None when another sync of this project is in progress."""
    from cveFeed.models import RunZeroSync
    with transaction.atomic():
        row = RunZeroSync.objects.select_for_update().get_or_create(project=project)[0]
        now = timezone.now()
        if row.status == 'running' and row.started_at and now - row.started_at < STALE_RUNNING:
            return None
        row.status, row.started_at = 'running', now
        row.save(update_fields=['status', 'started_at', 'updated_at'])
    return row


def _run(project, row, token):
    client = runzero.Client(token)
    assets, assets_cut = client.fetch_assets('')  # all of it: enrichment is not limited by the import search
    by_ip = _newest_by_address(assets)
    reports, reports_cut = ([], False)
    if by_ip:
        reports, reports_cut = client.fetch_vulnerabilities('')
    partial = bool(assets_cut or reports_cut or client.quota_low)
    matched, updated, kept, corroborated = _enrich(project, by_ip, reports, partial)
    counts = {'assets': len(assets), 'matched_hosts': matched, 'updated_hosts': updated, 'cve_reports': kept,
              'corroborated_matches': corroborated, 'truncated': partial}
    if client.quota_low:
        counts['quota_low'] = True  # runZero's daily quota is nearly spent: the sync stopped early and the next one carries on
    if row.import_enabled:
        chosen = assets if not row.search else client.fetch_assets(row.search)[0]
        counts['imported'], counts['skipped'] = _import(project, chosen)
    return counts


def _summary(counts):
    text = f"runZero sync: {counts['assets']} assets read, {counts['matched_hosts']} matched hosts ({counts['updated_hosts']} updated)"
    if counts.get('cve_reports'):
        text += f", {counts['cve_reports']} CVE reports"
    if 'imported' in counts:
        text += f", {counts['imported']} targets imported"
    return text


def _finish(project, row, counts=None, error=''):
    now = timezone.now()
    row.status, row.last_sync_at = ('error', now) if error else ('ok', now)
    if error:
        row.last_error = error[:300]
    else:
        row.last_error, row.last_ok_at, row.counts = '', now, counts
    row.save(update_fields=['status', 'last_sync_at', 'last_error', 'last_ok_at', 'counts', 'updated_at'])
    if error:
        activity.log('runzero', f'runZero sync failed: {error}', project=project, status='failed')
    else:
        activity.log('runzero', _summary(counts), project=project, **{k: v for k, v in counts.items() if k != 'skipped'})
    return {'state': row.status, 'error': error or None, 'counts': counts or {}}


def sync_project(project):
    """Run one sync now. Returns ``{'state': 'ok'|'error'|'busy'|'no_key', ...}``; never raises."""
    token = token_for(project)
    if not token:
        return {'state': 'no_key', 'error': 'no runZero token is saved for this project or its organization', 'counts': {}}
    row = _claim(project)
    if row is None:
        return {'state': 'busy', 'error': None, 'counts': {}}
    try:
        counts = _run(project, row, token)
    except runzero.RunZeroError as exc:
        return _finish(project, row, error=exc.message)
    except Exception as exc:  # noqa: BLE001 - a sync must never take the worker down; the reason is kept in the log under an id
        return _finish(project, row, error=activity.diagnostic('runZero sync', repr(exc).replace(token, '***'), type(exc).__name__))
    return _finish(project, row, counts=counts)


def configured_project_ids():
    """Ids of the projects with a runZero token of their own or inherited from their organization."""
    from dashboard.models import ApiCredential, Project
    own = set(ApiCredential.objects.filter(service=SERVICE, project__isnull=False).values_list('project_id', flat=True))
    orgs = list(ApiCredential.objects.filter(service=SERVICE, org__isnull=False).values_list('org_id', flat=True))
    return own | set(Project.objects.filter(org_id__in=orgs).values_list('id', flat=True))


def due_project_ids():
    """Ids of the projects that have a runZero token and have not synced for ``interval_hours()`` (or at all)."""
    from cveFeed.models import RunZeroSync
    ids = configured_project_ids()
    cutoff = timezone.now() - timedelta(hours=interval_hours())
    recent = set(RunZeroSync.objects.filter(project_id__in=ids, last_sync_at__gt=cutoff).values_list('project_id', flat=True))
    return sorted(ids - recent)
