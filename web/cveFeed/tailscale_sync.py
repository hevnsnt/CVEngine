"""Keep a project's targets in step with its tailnet: enumerate, import, mark, retire, check and (optionally) scan.

One sync of one ``TailscaleLink``:
  1. Read the tailnet: the control-plane API when credentials are saved (the full device list, client versions, key-expiry settings,
     the policy file) and this server's own tailscaled when the sidecar is running (peers it can see, online state, SSH). The API list
     wins; the local view fills in what only a node knows. If neither answers, nothing changes and the error is kept for the status.
  2. Choose what to import: authorised, not shared in from another tailnet (those machines belong to someone else), not this scanner's
     own node, matching the tag and OS filters, not excluded by the organization (HostExclusion). New devices are capped per run.
  3. Each imported device becomes a target named by its tailnet IPv4 address (an IPv6 one only when it has none): the name every scanner
     already treats as a bare IP target, so nmap, nuclei and the rest need no special case. The device's facts (MagicDNS name, OS,
     client version, tags, routes, key expiry, user) are stored on a TailscaleDevice row and as chips on the host.
  4. A device that is gone (left the tailnet, no longer matches the filters) keeps its history, is archived (reversibly), and its
     address stops being scannable; one that returns is restored. An empty answer never retires anything.
  5. Tailscale findings are stored as hygiene findings (cveFeed.tailscale_checks); with auto-scan on, new and changed online devices
     go through the normal pipeline (cveFeed.discovery.start_discoveries), up to the cap, never while scanning is paused.
Everything that arrives from Tailscale was typed and clipped by tailscale_api before it got here.
"""
import logging

from django.db import transaction
from django.utils import timezone

from cveFeed import tailscale_api, tailscale_checks, tailscale_local, tailscale_scope
from cveFeed.tailscale_api import TailscaleError

logger = logging.getLogger(__name__)

ARCHIVE_MARK = 'Tailscale sync: '
LOCK_SECONDS = 900
CHIP_SOURCE = 'tailscale'
MAX_DEVICES_PER_RUN = 5000
NOT_REACHABLE = 'scans cannot reach this tailnet yet: start the tailscale compose profile, or set routing to "host" if the Docker host is on it'


def primary_address(device):
    """The address a device is stored under: its first tailnet IPv4, else its first IPv6."""
    addresses = device['addresses']
    return next((a for a in addresses if ':' not in a), addresses[0])


# --- reading the tailnet -----------------------------------------------------------------------------------------------------

def read_tailnet(link):
    """``(devices, policy, local_state, notes)``: the merged device records (None when neither source answered), the policy dict or
    None, this server's own tailscaled state (``{}`` without a sidecar) and the errors met on the way, all safe to show. When credentials
    are saved but the API did not answer, ``local_state['api_failed']`` is True: the local peers are then only the part of the tailnet this
    node may see, so the list is no ground for retiring a device."""
    notes, api_devices, policy, local_devices, local_state = [], None, None, None, {}
    if link.credentials:
        try:
            client = tailscale_api.Client(link.credentials)
            api_devices = client.devices()
            if link.check_policy:
                try:
                    policy = client.policy()
                except TailscaleError as exc:
                    notes.append(f'policy file not read: {exc}')
        except TailscaleError as exc:
            notes.append(str(exc))
    if link.use_local and tailscale_local.available():
        try:
            local_state, local_devices = tailscale_local.read()
        except TailscaleError as exc:
            notes.append(str(exc))
    local_state['api_failed'] = bool(link.credentials) and api_devices is None
    if api_devices is None and local_devices is None:
        return None, None, local_state, notes
    local_state['reachable'] = scanner_reaches(link, api_devices, local_devices is not None, local_state)
    return merge(api_devices, local_devices, local_state), policy, local_state, notes


def scanner_reaches(link, api_devices, local_ok, local_state):
    """Whether scans can reach this link's tailnet. "host" is the operator's word (the Docker host is on the tailnet). Otherwise this
    server's own tailscaled must be running in it: with the API list, the scanner's own node is one of that list's devices (the
    same node id), which cannot be true for a different tailnet; with only the local view, the node being up is the whole answer."""
    if link.routing == 'host':
        return True
    if not local_ok or local_state.get('backend_state') != 'Running':
        return False
    if api_devices is None:
        return True
    own = set(local_state.get('self_ids') or [])
    return any(d['node_id'] in own for d in api_devices)


def merge(api_devices, local_devices, local_state):
    """The API list is complete, so it is the base and the local view only adds what a node alone knows (online state, whether
    Tailscale SSH is offered). Without the API the local peers are the list. This node's own ids never come through."""
    own = set(local_state.get('self_ids') or [])
    if api_devices is None:
        return [d for d in local_devices if d['node_id'] not in own]
    local = {d['node_id']: d for d in local_devices or []}
    merged = []
    for device in api_devices:
        if device['node_id'] in own:
            continue
        seen = local.get(device['node_id'])
        if seen:
            if seen['online'] is not None:
                device['online'] = seen['online']
            if device['ssh'] is None:
                device['ssh'] = seen['ssh']
        merged.append(device)
    return merged


def exclusion_reason(device, excluded):
    """Why the organization's exclusions keep this device out, or None: any name or address of it that is excluded counts."""
    from cveFeed.exclusions import normalize
    names = [device['name'], device['hostname'], *device['addresses']]
    return next((n for n in names if n and normalize(n) in excluded), None)


def select(link, devices, excluded):
    """``(wanted, skipped)``: the devices to import, in a stable order, and counts of the ones left out by reason."""
    only_tags, skip_tags = set(link.only_tags or []), set(link.skip_tags or [])
    only_os = {o.lower() for o in link.only_os or []}
    wanted, skipped = [], {}

    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1

    for device in sorted(devices, key=lambda d: (d['name'], d['node_id'])):
        tags = set(device['tags'])
        if device['is_external']:
            skip('shared_in')
        elif not device['authorized']:
            skip('unauthorized')
        elif only_tags and not (tags & only_tags):
            skip('tag_filter')
        elif tags & skip_tags:
            skip('tag_filter')
        elif only_os and device['os'].lower() not in only_os:
            skip('os_filter')
        elif exclusion_reason(device, excluded):
            skip('excluded')
        else:
            wanted.append(device)
    return wanted, skipped


# --- importing ---------------------------------------------------------------------------------------------------------------

def _describe(device):
    bits = [device['name']] + [b for b in (device['os'], f'Tailscale {device["client_version"]}' if device['client_version'] else '') if b]
    return ('Tailscale device: ' + ', '.join(bits))[:500]


def _domain_for(link, host, device):
    """The target for a device address in the link's project, created when new. None when another project of the organization already
    holds that name (domain names are unique per organization, and this device is not ours to move)."""
    from startScan.ip_rows import org_id_of_project
    from targetApp.models import Domain, org_domains
    existing = org_domains(link.project_id).filter(name=host).first()
    if existing is not None:
        return existing if existing.project_id == link.project_id else None
    return Domain.objects.create(name=host, project=link.project, org_id=org_id_of_project(link.project_id), ip_address_cidr=host,
                                 description=_describe(device), insert_date=timezone.now())


def _addresses_of_other_links(link):
    """Every address a device of another link holds (tailnets reuse the 100.x range, so one address can be two machines)."""
    from cveFeed.models import TailscaleDevice
    held = set()
    for addresses in TailscaleDevice.objects.filter(departed_at__isnull=True).exclude(link=link).values_list('addresses', flat=True):
        held.update(addresses or [])
    return held


def _chips(device):
    chips = [('Tailscale device', device['name'])]
    chips += [(f'ts {tag}', tag) for tag in device['tags']]
    if device['online'] is False:
        chips.append(('tailscale offline', 'not connected at the last sync'))
    if device['exit_node']:
        chips.append(('tailscale exit node', 'approved exit node'))
    if device['enabled_routes'] and not device['exit_node']:
        chips.append(('tailscale subnet router', ', '.join(device['enabled_routes'][:5])))
    if device['ssh']:
        chips.append(('tailscale ssh', 'Tailscale SSH host keys are published'))
    if device['os']:
        chips.append((f'ts os {device["os"].lower()}', device['os']))
    if device['client_version']:
        chips.append((f'ts client {device["client_version"]}', device['client_version']))
    return chips[:30]


def _store_chips(link, domain, host, device):
    from cveFeed.models import HostLabel
    HostLabel.objects.filter(project=link.project, host=host, source=CHIP_SOURCE).delete()
    HostLabel.objects.bulk_create([HostLabel(project=link.project, domain=domain, host=host, label=label[:64], kind='tailscale',
                                             source=CHIP_SOURCE, detail=detail[:300]) for label, detail in _chips(device)],
                                  ignore_conflicts=True)
    from cveFeed.models import HostProfile
    owner = device['user'] or ', '.join(device['tags'])
    profile, _ = HostProfile.objects.get_or_create(project=link.project, host=host, defaults={'owner': owner[:200], 'purpose': 'Tailscale device'})
    if owner and not profile.owner:  # a person's own edit is never overwritten
        profile.owner = owner[:200]
        profile.save(update_fields=['owner', 'updated_at'])


def import_device(link, device, now, row=None, taken=frozenset()):
    """Create or update the target and the TailscaleDevice row of one device (``row`` is the one already loaded for it, ``taken`` the
    addresses other links hold). ``(row, status)`` where status is 'new', 'changed' or 'same', or ``(None, 'conflict')`` when the
    address belongs to another tailnet or project. A 'same' row is only updated in memory (online state, last seen): the caller saves
    all of them in one query, and no per-device query runs for a device that did not change."""
    from cveFeed.models import TailscaleDevice
    host = primary_address(device)
    digest = tailscale_api.fingerprint(device)
    facts = {k: v for k, v in device.items() if k != 'node_id'}
    if row is not None and row.domain_id and not row.departed_at and row.fingerprint == digest:
        went_online_or_off = row.online != bool(device['online'])
        row.online, row.facts, row.last_seen = bool(device['online']), facts, now
        if went_online_or_off:  # the offline chip follows
            _store_chips(link, row.domain, host, device)
        return row, 'same'
    with transaction.atomic():  # a new or changed device is written whole or not at all
        domain = row.domain if row is not None and row.domain_id else None
        if domain is None:
            if taken.intersection(device['addresses']):
                return None, 'conflict'
            domain = _domain_for(link, host, device)
            if domain is None:
                return None, 'conflict'
        if row is None:
            row = TailscaleDevice(link=link, project=link.project, node_id=device['node_id'], first_seen=now)
            status = 'new'
        else:
            status = 'changed'
        row.domain, row.name, row.addresses, row.online = domain, device['name'], device['addresses'], bool(device['online'])
        row.facts, row.fingerprint, row.last_seen, row.departed_at = facts, digest, now, None
        row.save()
        _store_chips(link, domain, host, device)
        _restore_if_ours(link, host)
    return row, status


def _restore_if_ours(link, host):
    """A device that came back is restored when this sync archived it; a person's own archive is theirs to lift."""
    from cveFeed.models import HostState
    HostState.objects.filter(project=link.project, host=host, archived_at__isnull=False, archived_by_user=False,
                             archive_reason__startswith=ARCHIVE_MARK).update(archived_at=None, archive_reason='')


def retire(link, row, why, now):
    """The device is gone from the tailnet (or the filters): archive its host (never a pinned or already archived one), resolve its
    Tailscale findings and stop its address being scannable."""
    from cveFeed.models import HostState, HygieneFinding
    row.departed_at, row.online = now, False
    row.save(update_fields=['departed_at', 'online'])
    if row.domain_id:
        host = primary_address({'addresses': row.addresses}) if row.addresses else row.domain.name
        state, _ = HostState.objects.get_or_create(project=link.project, host=host, defaults={'domain': row.domain})
        if not state.archived_at and not state.pinned:
            state.archived_at, state.archive_reason, state.archived_by_user = now, (ARCHIVE_MARK + why)[:300], False
            state.save(update_fields=['archived_at', 'archive_reason', 'archived_by_user'])
        HygieneFinding.objects.filter(domain=row.domain, check_name__startswith=tailscale_checks.PREFIX, status='open').update(
            status='resolved', resolved_at=now)


# --- findings ----------------------------------------------------------------------------------------------------------------

def _open_ports(rows):
    """``{domain id: [{'number', 'service'}]}``: the open ports a scan found on the tailnet addresses of these devices, in one query."""
    from startScan.models import OPEN_PORT_STATES, IpAddress
    wanted = {r.domain_id: set(r.addresses) for r in rows if r.domain_id}
    found = {}
    query = IpAddress.objects.filter(ip_addresses__target_domain_id__in=list(wanted), ports__state__in=OPEN_PORT_STATES).values_list(
        'ip_addresses__target_domain_id', 'address', 'ports__number', 'ports__service_name')
    for domain_id, address, number, service in query.distinct():
        if address in wanted.get(domain_id, ()):
            found.setdefault(domain_id, {}).setdefault(number, {'number': number, 'service': service or ''})
    return {d: sorted(ports.values(), key=lambda p: p['number']) for d, ports in found.items()}


def device_findings(link, rows, now):
    """Store the Tailscale findings of every imported device, each on its own target. A device with nothing found and nothing open
    from before costs no query beyond the two that load the ports and the open findings for the whole run."""
    from cveFeed.hygiene import store_findings
    from cveFeed.models import HygieneFinding
    rows = [r for r in rows if r.domain_id]
    ports = _open_ports(rows)
    open_now = set(HygieneFinding.objects.filter(domain_id__in=[r.domain_id for r in rows], check_name__startswith=tailscale_checks.PREFIX,
                                                 status='open').values_list('domain_id', 'host'))
    count = 0
    for row in rows:
        host = primary_address({'addresses': row.addresses})
        found = tailscale_checks.evaluate_device(row.facts, host, now=now, ports=ports.get(row.domain_id, []))
        if found or (row.domain_id, host) in open_now:
            store_findings(row.domain, found, hosts=[host], owns=lambda check: check.startswith(tailscale_checks.PREFIX))
        count += len(found)
    return count


def policy_findings(link, policy, rows):
    """The tailnet-wide findings, kept on an anchor target (an imported device's, under the tailnet's own name). The anchor is the first
    imported device that is still on the tailnet: when it leaves (its target stays, archived or its address unused) the findings move to
    another device instead of sitting on a host that no longer exists, and the old anchor's copies are resolved."""
    from cveFeed.hygiene import store_findings
    owns = lambda check: check.startswith(tailscale_checks.PREFIX)  # noqa: E731
    host = f'tailnet:{link.tailnet_name or "-"}'[:500]
    present = [r.domain for r in rows if r.domain is not None and r.departed_at is None]
    anchor = link.anchor_domain
    if anchor is None or (present and anchor.pk not in {d.pk for d in present}):
        replacement = present[0] if present else (anchor or next((r.domain for r in rows if r.domain is not None), None))
        if replacement is None:
            return 0
        if anchor is not None and replacement.pk != anchor.pk:
            store_findings(anchor, [], hosts=[host], owns=owns)  # resolve what the departed anchor held; the new one raises it again
        anchor = replacement
        link.anchor_domain = anchor
    found = tailscale_checks.evaluate_policy(policy, host, link.tailnet_name)
    store_findings(anchor, found, hosts=[host], owns=owns)
    return len(found)


# --- scanning ----------------------------------------------------------------------------------------------------------------

def queue_scans(link, pending, now):
    """Queue the normal discovery pipeline for these ``(row, status)`` devices (online ones, up to the cap). Returns ``(queued, why not)``."""
    from cveFeed.scan_control import pause_requested
    if not pending:
        return 0, ''
    if not link.scan_reachable:
        return 0, NOT_REACHABLE
    if pause_requested():
        return 0, 'scanning is paused'
    from cveFeed import activity
    from cveFeed.discovery import start_discoveries
    from cveFeed.models import TailscaleDevice
    batch = pending[:link.max_devices]
    domains = [r.domain for r in batch if r.domain is not None]
    try:
        start_discoveries(domains, quiet=True)
    except RuntimeError as exc:  # no scan engine configured
        return 0, str(exc)[:200]
    TailscaleDevice.objects.filter(pk__in=[r.pk for r in batch]).update(scan_queued_at=now)
    activity.log('discovery', f'Queued discovery of {len(domains)} Tailscale device{"s" if len(domains) != 1 else ""}', project=link.project_id)
    return len(domains), ''


# --- the sync ----------------------------------------------------------------------------------------------------------------

def sync_link(link_id, scan=True):
    """Run one sync of a link. Returns a summary dict; never raises for a Tailscale problem (it is recorded on the link)."""
    from cveFeed.models import TailscaleLink
    from reNgine import resources
    link = TailscaleLink.objects.select_related('project', 'anchor_domain').filter(pk=link_id).first()
    if link is None:
        return {'status': 'missing'}
    if not link.enabled:
        return {'status': 'disabled'}
    with resources.redis_claim(f'cvengine:tailscale:sync:{link.pk}', link.pk, LOCK_SECONDS) as holder:
        if holder is not True:
            return {'status': 'busy'}
        return _sync(link, scan)


def _sync(link, scan):
    from cveFeed import activity
    from cveFeed.exclusions import excluded_names
    from cveFeed.models import TailscaleDevice
    now = timezone.now()
    devices, policy, local_state, notes = read_tailnet(link)
    if devices is None:
        if link.routing == 'auto':  # a tailnet that cannot be read is not one the scanner can be said to reach
            link.scan_reachable = False
        _record(link, now, 'error', notes[0] if notes else 'no Tailscale source is available', local_state, link.device_count)
        tailscale_scope.invalidate()
        return {'status': 'error', 'error': link.last_error}
    link.tailnet_name = (local_state.get('tailnet') or tailscale_api.tailnet_suffix(devices) or link.tailnet_name)[:200]
    wanted, skipped = select(link, devices, excluded_names(link.project_id))
    existing = {r.node_id: r for r in TailscaleDevice.objects.filter(link=link).select_related('domain')}
    counts = {'new': 0, 'changed': 0, 'same': 0, 'departed': 0, 'conflict': 0, 'deferred': 0}
    rows, pending, unchanged = [], [], []
    new_budget = max(1, link.max_devices)
    taken = None  # the addresses other links hold, loaded once and only when a new device needs it
    for device in wanted[:MAX_DEVICES_PER_RUN]:
        if device['node_id'] not in existing or existing[device['node_id']].departed_at:
            if new_budget <= 0:
                counts['deferred'] += 1  # the rest follow on the next run
                continue
            new_budget -= 1
        if device['node_id'] not in existing and taken is None:
            taken = _addresses_of_other_links(link)
        row, status = import_device(link, device, now, row=existing.get(device['node_id']), taken=taken or frozenset())
        counts[status] += 1
        if row is None:
            continue
        if status == 'same':
            unchanged.append(row)
        rows.append(row)
        if device['online'] and (status in ('new', 'changed') or row.scan_queued_at is None):
            pending.append(row)
    if unchanged:  # one query for every device that only moved its online state and last seen time
        TailscaleDevice.objects.bulk_update(unchanged, ['online', 'facts', 'last_seen'], batch_size=500)
    if local_state.get('api_failed'):  # the API list is the complete one: a node's own view is a subset, so nobody is retired on it
        notes.append('the Tailscale API did not answer, so no device was retired')
    elif devices:  # an empty answer is never read as "everyone left"
        still_wanted = {d['node_id'] for d in wanted}  # imported, or deferred by the cap or a conflict: not gone
        for node_id, row in existing.items():
            if node_id not in still_wanted and not row.departed_at:
                retire(link, row, 'left the tailnet or no longer matches the filters', now)
                counts['departed'] += 1
    else:
        notes.append('Tailscale listed no devices, so nothing was retired')
    link.scan_reachable = bool(local_state.get('reachable'))
    link.last_sync_at, link.last_status = now, 'partial' if notes else 'ok'
    link.save(update_fields=['scan_reachable', 'last_sync_at', 'last_status'])  # before any scan is queued, so the workers that pick it up already see the authority
    tailscale_scope.invalidate()
    findings = device_findings(link, rows, now)
    if policy is not None:
        findings += policy_findings(link, policy, rows)
    try:
        queued, why_not = queue_scans(link, pending, now) if scan and link.auto_scan else (0, '')
    except Exception:  # noqa: BLE001 - the devices and findings are already stored; say so and carry on
        logger.exception('could not queue scans for the tailnet of project %s', link.project_id)
        queued, why_not = 0, 'the scans could not be queued'
    if why_not and why_not != NOT_REACHABLE:
        notes.append(f'scans not queued: {why_not}')
    link.device_count = len(devices)
    if link.auto_scan and not link.scan_reachable:
        notes.append(NOT_REACHABLE)
    _record(link, now, 'partial' if notes else 'ok', '; '.join(notes), local_state, len(devices))
    tailscale_scope.invalidate()
    summary = {'status': link.last_status, 'devices': len(devices), 'imported': len(rows), **counts, 'skipped': skipped,
               'findings': findings, 'queued': queued, 'error': link.last_error}
    activity.log('inventory', f'Tailscale sync: {len(devices)} device{"s" if len(devices) != 1 else ""}, {counts["new"]} new, '
                 f'{counts["departed"]} left, {queued} queued for scanning', project=link.project_id, **{k: v for k, v in summary.items() if k != 'error'})
    return summary


SHOWN_LOCAL = ('backend_state', 'tailnet', 'self_name', 'version', 'peers', 'reachable')  # what the status shows of this server's own node


def _record(link, now, status, error, local_state, count):
    link.last_sync_at, link.last_status, link.last_error = now, status, error[:300]
    link.device_count, link.local_state = count, {k: local_state[k] for k in SHOWN_LOCAL if k in local_state}
    link.save(update_fields=['last_sync_at', 'last_status', 'last_error', 'device_count', 'local_state', 'tailnet_name', 'anchor_domain', 'scan_reachable', 'updated_at'])


MANUAL_SYNC_GAP = 60  # seconds between syncs started by a person or an agent for one link


def manual_sync_allowed(link_id):
    """True when a sync of this link may be started by hand now: one per MANUAL_SYNC_GAP seconds (shared by Settings, REST and MCP, and
    by every worker through the cache), so a loop of requests cannot keep the control-plane API and the database busy."""
    from django.core.cache import cache
    from django.db import connection
    return bool(cache.add(f'tailscale:manual-sync:{connection.settings_dict["NAME"]}:{link_id}', 1, MANUAL_SYNC_GAP))


def sync_all():
    """Every enabled link (the beat task). One link failing never stops the others."""
    from cveFeed.models import TailscaleLink
    out = {}
    for link_id in TailscaleLink.objects.filter(enabled=True).values_list('pk', flat=True):
        try:
            out[link_id] = sync_link(link_id)
        except Exception:  # noqa: BLE001 - recorded, and the next link still runs
            logger.exception('Tailscale sync of link %s failed', link_id)
            TailscaleLink.objects.filter(pk=link_id).update(last_status='error', last_error='the sync failed unexpectedly; see the worker log',
                                                            last_sync_at=timezone.now())
            out[link_id] = {'status': 'error'}
    return out
