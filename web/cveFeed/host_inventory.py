"""Host inventory reports: storing what a machine said about itself and tying it to the host cvENGINE scans.

``ingest`` takes a report already cleaned by ``cveFeed.inventory_schema`` and, in one transaction, keeps the latest report per machine
(``HostInventory``) with a short summarised history, finds the project's host it describes, and lets an on-host report outrank the
network's guess at the operating system. The CVE side (``cveFeed.inventory_match``) runs afterwards in a worker.

Matching a report to a host, in order: the host's name (the report's FQDN or host name is a name the project scans), then its addresses
(a current-inventory host that resolves to one of them, never a CDN address), then a short host name that is the first label of exactly
one scanned name. A host that matches nothing is recorded as unmatched for an administrator to adopt, or, when the project allows it,
added as a target (a name its organization excluded is refused either way).
"""
import ipaddress
import logging
import os
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from cveFeed import inventory_schema as schema

logger = logging.getLogger(__name__)

HISTORY_KEEP = 20
DEFAULT_STALE_DAYS = 14
MAX_STALE_DAYS = 365
MAX_MACHINES_PER_PROJECT = 5000
MAX_UNMATCHED_PER_PROJECT = 500  # reports tied to no host: only an administrator's attention empties them, so they are capped lower
UNMATCHED_KEEP_DAYS = 30  # an unmatched report nobody adopted in this long is dropped when the next new one arrives
REPORTS_PER_HOUR = 12  # per machine and token: a script on a daily or hourly timer never gets near it, a loop does
TOKEN_REPORTS_PER_HOUR = 10000  # per token and per project, over every machine: room for a whole fleet reporting in one hour
PROJECT_REPORTS_PER_HOUR = 20000
# addresses that many unrelated machines share: container bridges, hypervisor NAT and carrier-grade NAT. A report that lists one says
# nothing about which scanned host it is, so they are never used to match a host
SHARED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '172.16.0.0/12', '192.168.99.0/24', '192.168.122.0/24', '192.168.56.0/24', '10.0.2.0/24', '100.64.0.0/10', '198.18.0.0/15'))
CHANGED_NAMES = 10  # package names a history entry spells out
REPORTED_OS_DAYS = 60  # how long a host-reported operating system outranks a network scan's guess


NOT_ACCEPTED = 'the report was not accepted (an administrator can read why in the audit log)'


class ReportRefused(Exception):
    """A valid report the server will not take (an excluded host, a full project, another token's machine); ``status`` goes with it.
    ``why`` is what only an administrator should read (it goes to the audit log, never to the reporter)."""

    def __init__(self, message, status, why=''):
        super().__init__(message)
        self.status, self.why = status, why


def stale_days(project):
    from cveFeed.models import ProjectSettings
    row = ProjectSettings.objects.filter(project=project).first()
    return row.inventory_stale_days if row else DEFAULT_STALE_DAYS


def stale_days_of(project_id):
    from cveFeed.models import ProjectSettings
    return ProjectSettings.objects.filter(project_id=project_id).values_list('inventory_stale_days', flat=True).first() or DEFAULT_STALE_DAYS


def is_stale(inv, days, now=None):
    return (now or timezone.now()) - inv.reported_at > timedelta(days=days)


# --- matching a report to a host --------------------------------------------------------------------------------------

def _current(project):
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    return Subdomain.objects.filter(latest_scan_q(), target_domain__project=project)


def _by_name(current, names):
    query = Q()
    for name in names:
        query |= Q(name__iexact=name)
    found = sorted({n.lower() for n in current.filter(query).values_list('name', flat=True)}) if names else []
    return found


def is_shared_address(address):
    try:
        return any(ipaddress.ip_address(address) in net for net in SHARED_NETWORKS)
    except ValueError:
        return True


def _by_address(current, ips):
    """The project host that resolves to most of the reported addresses, or ''. Names on the same addresses are one host
    (cveFeed.counts.with_host_key), and the host is shown under the project's own target name, then the shortest name. Addresses
    many machines share (container bridges, NAT) are ignored."""
    from agentapi.services import _one_per_host
    ips = [a for a in ips if not is_shared_address(a)]
    if not ips:
        return ''
    rows = current.filter(ip_addresses__address__in=ips, ip_addresses__is_cdn=False)
    if not rows.exists():
        return ''
    reps = list(_one_per_host(rows, per_project=True).values_list('id', 'name'))
    overlap = {}
    for sub_id, address in current.filter(id__in=[i for i, _ in reps], ip_addresses__address__in=ips).values_list('id', 'ip_addresses__address'):
        overlap.setdefault(sub_id, set()).add(address)
    return min(((-len(overlap.get(i, ())), len(n), n.lower()) for i, n in reps))[2]


def _by_short_name(current, hostname):
    found = {n.lower() for n in current.filter(name__istartswith=hostname + '.').values_list('name', flat=True)}
    return next(iter(found)) if len(found) == 1 else ''


def find_host(project, host):
    """``(name, basis)`` of the project's host a report describes (``('', '')`` when none): see the module's matching order."""
    current = _current(project)
    names = [n for n in (host.get('fqdn'), host.get('hostname')) if n]
    exact = _by_name(current, names)
    if exact:
        return (next((n for n in exact if n == host.get('fqdn')), exact[0]), 'name')
    if host.get('ips'):
        found = _by_address(current, host['ips'])
        if found:
            return found, 'ip'
    short = host.get('hostname') and '.' not in host['hostname'] and _by_short_name(current, host['hostname'])
    return (short, 'name') if short else ('', '')


def reported_names(host):
    return [n for n in (host.get('fqdn'), host.get('hostname')) if n]


def check_excluded(project, host):
    """Refuse a report for a host the organization excluded. The reporter is told only that the report was not accepted: naming the
    reason would let anyone holding a token probe which host names the organization excluded."""
    from cveFeed.exclusions import is_excluded
    for name in reported_names(host):
        if is_excluded(project.id, name):
            raise ReportRefused(NOT_ACCEPTED, 409, why=f'{name} is excluded for the organization')


# --- history -----------------------------------------------------------------------------------------------------------

def _package_map(packages):
    return {(p['e'], p['n'], p.get('a', '')): p.get('v', '') for p in packages}


def diff_packages(before, after):
    """``{added, removed, changed, names}`` between two package lists (names: the first few that changed, added ones first)."""
    old, new = _package_map(before), _package_map(after)
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    changed = [k for k in new if k in old and new[k] != old[k]]
    names = [k[1] for k in (added + changed + removed)][:CHANGED_NAMES]
    return {'added': len(added), 'removed': len(removed), 'changed': len(changed), 'names': names}


def _os_summary(os_block):
    return ' '.join(x for x in (os_block.get('name'), os_block.get('version'), os_block.get('build')) if x)[:200]


def _trim_history(inv):
    from cveFeed.models import HostInventoryReport
    old = list(inv.history.order_by('-reported_at', '-id').values_list('id', flat=True)[HISTORY_KEEP:])
    if old:
        HostInventoryReport.objects.filter(id__in=old).delete()


# --- storing ------------------------------------------------------------------------------------------------------------

def _existing(project, report, token_id):
    """The stored row of this machine: by its key, or (a script that gained a machine id since its first report) by the host name
    it reported before, which then takes the machine id as its key. A machine belongs to the token that first reported it: another
    live token (a stolen one, or a second one that claims the same name) is refused, so one reporter cannot speak for another's machine.
    A token that no longer exists, was revoked or has expired owns nothing: its project's replacement token (a renewal, or a rotation after
    a leak) takes the machine over, so a yearly renewal does not lock the whole fleet out. A signed-in administrator may update any report."""
    from cveFeed.models import HostInventory
    host = report['host']
    key = schema.machine_key(host)
    inv = HostInventory.objects.filter(project=project, key=key).first()
    if inv is None and host.get('machine_id'):
        names = ['h:' + n.lower() for n in (host.get('fqdn'), host.get('hostname')) if n]
        inv = HostInventory.objects.filter(project=project, key__in=names).order_by('id').first()
        if inv:
            inv.key = key
    if inv is not None and token_id is not None and inv.token_id != token_id:
        if _owner_is_live(project, inv.token_id):
            raise ReportRefused(NOT_ACCEPTED, 409, why=f'token {token_id} tried to report for a machine held by token {inv.token_id}: delete that report to let '
                                                        'another token take the machine over')
        inv.token_id = token_id  # the owner is gone, revoked or expired: the new token of this project takes the machine over
    return inv, key


def _owner_is_live(project, owner_id):
    """Whether the token that owns a machine can still report for it. A report made by a signed-in administrator has no token and stays
    the administrator's to replace."""
    if owner_id is None:
        return True
    from dashboard.models import ApiToken
    return ApiToken.objects.filter(pk=owner_id, project=project, revoked=False, user__is_active=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())).exists()


def _assign(inv, report, now, token_id, source_ip):
    host, os_block = report['host'], report['os']
    inv.hostname, inv.fqdn, inv.ips = host['hostname'], host['fqdn'], host['ips']
    inv.os_family, inv.os_name, inv.os_version, inv.os_build = os_block['family'], os_block['name'], os_block['version'], os_block['build']
    inv.os_kernel, inv.os_arch, inv.os_info = os_block['kernel'], os_block['arch'], os_block
    inv.packages, inv.package_count = report['packages'], len(report['packages'])
    inv.patches, inv.services = report['patches'], report['services']
    inv.details = {'runtime': report['runtime'], 'security': report['security'], 'macs': host['macs'], 'dropped': report['dropped'],
                   'assessment': (inv.details or {}).get('assessment', {})}
    inv.script_name, inv.script_version = report['script']['name'], report['script']['version']
    inv.collected_at = schema.parse_time(report['collected_at'])
    inv.reported_at, inv.source_ip = now, (source_ip or '')[:64]
    if inv.pk is None:
        inv.token_id = token_id  # the owner is whoever reported first, and stays


def has_live_report(project, name, exclude_pk, now):
    """Whether another machine's report for the host ``name`` is still fresh: a host speaks through one live report at a time."""
    from cveFeed.models import HostInventory
    return HostInventory.objects.filter(project=project, host=name, reported_at__gte=now - timedelta(days=stale_days(project))).exclude(
        pk=exclude_pk).exists()


def _normal(address):
    try:
        ip = ipaddress.ip_address(str(address).strip().split('%')[0])
    except ValueError:
        return ''
    return str(getattr(ip, 'ipv4_mapped', None) or ip)


def corroborates(project, name, host, source_ip=''):
    """Whether a report that matched the host ``name`` (by that name or by an address it lists) came from one of that host's addresses.
    What a report says about itself, its names and its address list, is only the reporter's word, so a token holder must not be able to
    speak for any scanned host by listing its name or addresses; the address the request came from is the one witness the reporter does not
    write, so it is the only witness whenever the request's address is known. A host with no address to compare (none known, or only CDN or shared ones) has nothing to contradict the match, so it passes.
    The check is off by default: a holder of a token for the project may report for the project's hosts, and many estates are scanned at an
    address (a load balancer or NAT) that their reports never come from. ``CVENGINE_INVENTORY_STRICT=1`` turns it on."""
    if os.environ.get('CVENGINE_INVENTORY_STRICT', '').strip().lower() not in ('1', 'true', 'yes', 'on'):
        return True
    seen = {_normal(a) for a in _current(project).filter(name__iexact=name, ip_addresses__is_cdn=False).values_list('ip_addresses__address', flat=True)
            if a and not is_shared_address(a)}
    seen.discard('')
    if not seen:
        return True
    if not _normal(source_ip):  # no request address (a caller that has none): the reported list is all there is to compare
        return bool(seen & {_normal(a) for a in host.get('ips') or []})
    return _normal(source_ip) in seen


def _claim_host(project, inv, host, now, source_ip=''):
    """Tie the report to the project host it describes, when it may. A report never takes a host that another machine's fresh
    report already speaks for (that needs an administrator, who adopts it), never moves an established match on an address alone, and
    never overrides an administrator's choice. A claim that is refused is kept as ``claimed_host`` for the administrator to see."""
    name, basis = find_host(project, host)
    claimed = dict(inv.details or {})
    claimed.pop('claimed_host', None)
    claimed.pop('claim_blocked', None)
    inv.details = claimed
    if not name or name == inv.host or (inv.host and (inv.match_basis == 'adopted' or basis == 'ip')):
        return
    if has_live_report(project, name, inv.pk, now):
        inv.details = {**claimed, 'claimed_host': name}
        return
    if not corroborates(project, name, host, source_ip):
        inv.details = {**claimed, 'claimed_host': name, 'claim_blocked': 'the report did not come from an address the scanner saw for that host'}
        return  # an administrator can adopt it if it is right
    inv.host, inv.match_basis = name, basis


def _prune_unmatched(project, now):
    from cveFeed.models import HostInventory
    HostInventory.objects.filter(project=project, host='', reported_at__lt=now - timedelta(days=UNMATCHED_KEEP_DAYS)).delete()


def delete_unmatched(project):
    """Drop every report tied to no host (an administrator's clean-up). Returns how many."""
    from cveFeed.models import HostInventory
    unmatched = HostInventory.objects.filter(project=project, host='')
    count = unmatched.count()
    unmatched.delete()
    return count


def _store(project, report, token_id, source_ip, now):
    from cveFeed.models import HostInventory, HostInventoryReport
    inv, key = _existing(project, report, token_id)
    outcome = 'updated'
    if inv is None:
        inv, outcome = HostInventory(project=project, key=key), 'new'
    before_packages, before_os, before_host = inv.packages, _os_summary(inv.os_info or {}), inv.host
    _assign(inv, report, now, token_id, source_ip)
    _claim_host(project, inv, report['host'], now, source_ip)
    if outcome == 'new':
        _prune_unmatched(project, now)
        if HostInventory.objects.filter(project=project).count() >= MAX_MACHINES_PER_PROJECT:
            raise ReportRefused(f'this project already holds {MAX_MACHINES_PER_PROJECT} reporting machines', 409)
        if not inv.host and HostInventory.objects.filter(project=project, host='').count() >= MAX_UNMATCHED_PER_PROJECT:
            raise ReportRefused(f'this project already holds {MAX_UNMATCHED_PER_PROJECT} reports tied to no host: an administrator has to adopt or delete them', 409)
    inv.save()
    changes = {'first': True} if outcome == 'new' else {**diff_packages(before_packages, inv.packages), 'os_changed': before_os != _os_summary(inv.os_info)}
    if outcome == 'updated' and (changes['os_changed'] or inv.host != before_host):
        outcome = 'changed'
    HostInventoryReport.objects.create(inventory=inv, reported_at=now, script_version=inv.script_version, os_summary=_os_summary(inv.os_info),
                                       package_count=inv.package_count, changes=changes)
    _trim_history(inv)
    if inv.host:
        apply_to_scan_data(inv, project, now)
    return inv, outcome


def ingest(project, report, token_id=None, source_ip='', now=None):
    """Store one cleaned report and return ``(inventory, outcome)``, ``outcome`` being ``new`` (the first report of this machine),
    ``changed`` (its operating system or the host it is tied to moved) or ``updated``. Raises ReportRefused for a host the
    organization excluded, a machine another token owns, or a project that holds too many machines. The host matching and the
    operating system update happen here; the CVE correlation is the caller's to queue (it needs a worker)."""
    now = now or timezone.now()
    check_excluded(project, report['host'])
    for attempt in (1, 2):
        try:
            with transaction.atomic():
                return _store(project, report, token_id, source_ip, now)
        except IntegrityError:  # two first reports of one machine at once: the loser's second try updates the winner's row
            if attempt == 2:
                raise


def adopt(inv, name):
    """Tie an unmatched report to the project host ``name`` by hand (an administrator's decision, kept across later reports)."""
    inv.host, inv.match_basis = name.lower(), 'adopted'
    inv.details = {k: v for k, v in (inv.details or {}).items() if k not in ('claimed_host', 'claim_blocked')}
    inv.save(update_fields=['host', 'match_basis', 'details'])
    apply_to_scan_data(inv, inv.project, timezone.now())


# --- an on-host report outranks a network guess ----------------------------------------------------------------------

def keeps_reported_os(ip_obj, now=None):
    """True while a host-reported operating system is recent enough that an nmap guess must not replace it."""
    seen = (ip_obj.fingerprint or {}).get('host_reported') or {}
    at = schema.parse_time(seen.get('at'))
    return bool(at and (now or timezone.now()) - at <= timedelta(days=REPORTED_OS_DAYS))


def apply_to_scan_data(inv, project, now):
    """Write the host-reported operating system over the network's guess for the machine's addresses, and note on each open port the
    process the host says listens there. Only addresses this project's own scans linked to the host the report is tied to (and the
    report lists): the report's address list is the reporter's claim, and an address row belongs to the whole organization, so a
    claimed address of another project's host must never be touched. Existing Port rows only: a socket nobody can reach from outside
    is not an exposed port."""
    from startScan.models import IpAddress
    if not inv.ips or not inv.host:
        return
    linked = _current(project).filter(name__iexact=inv.host, ip_addresses__address__in=inv.ips).values_list('ip_addresses', flat=True)
    pretty = (inv.os_info.get('pretty') or ' '.join(x for x in (inv.os_name, inv.os_version) if x))[:255]
    stamp = {'os': pretty, 'build': inv.os_build, 'at': now.isoformat(), 'inventory_id': inv.id}
    listeners = {}
    for item in inv.services:
        listeners.setdefault((item['p'], item['n']), []).append(item)
    for ip in IpAddress.objects.filter(org_id=project.org_id, pk__in=list(linked)).prefetch_related('ports'):
        ip.os_guess, ip.os_accuracy = pretty, 100
        ip.fingerprint = {**(ip.fingerprint or {}), 'host_reported': stamp}
        ip.save(update_fields=['os_guess', 'os_accuracy', 'fingerprint'])
        for port in ip.ports.all():
            found = [s for s in listeners.get((port.protocol or 'tcp', port.number), []) if s['a'] in ('*', ip.address)]
            if found and found[0]['x']:
                port.extra = {**(port.extra or {}), 'host_reported': {'process': found[0]['x'], 'at': now.isoformat()}}
                port.save(update_fields=['extra'])


# --- reading ------------------------------------------------------------------------------------------------------------

def brief(inv, days, now=None):
    """One report in a list: who, what, how old and whether it still counts."""
    now = now or timezone.now()
    return {'id': inv.id, 'host': inv.host or None, 'matched': bool(inv.host), 'match_basis': inv.match_basis or None,
            'hostname': inv.hostname, 'fqdn': inv.fqdn, 'ips': inv.ips,
            'os': {'family': inv.os_family, 'name': inv.os_name, 'version': inv.os_version, 'build': inv.os_build,
                   'kernel': inv.os_kernel, 'arch': inv.os_arch, 'pretty': (inv.os_info or {}).get('pretty', '')},
            'packages': inv.package_count, 'reported_at': inv.reported_at.isoformat(), 'age_hours': int((now - inv.reported_at).total_seconds() // 3600),
            'stale': is_stale(inv, days, now), 'stale_after_days': days, 'claimed_host': (inv.details or {}).get('claimed_host'), 'claim_blocked': (inv.details or {}).get('claim_blocked'), 'script': f'{inv.script_name} {inv.script_version}'.strip()}


def _package_rows(inv, params, limit):
    from cveFeed import inventory_schema
    needle = (params.get('q') or '').strip().lower()
    rows = sorted((p for p in inv.packages if not needle or needle in p['n'].lower() or needle in (p.get('s') or '').lower()),
                  key=lambda p: (p['n'].lower(), p['e'], p.get('v', '')))
    try:
        page, size = max(1, int(params.get('page', 1))), min(limit, max(1, int(params.get('page_size', 100))))
    except (TypeError, ValueError):
        page, size = 1, 100
    start = (page - 1) * size
    return {'count': len(rows), 'page': page, 'page_size': size,
            'results': [inventory_schema.identity(p, inv.os_info or {}) for p in rows[start:start + size]]}


def findings_summary(inv):
    """How many live CVE matches the host's own report made (local-only ones counted separately)."""
    from cveFeed.counts import CLOSED, RULED_OUT
    from cveFeed.models import CVEMatch
    if not inv.host:
        return {'total': 0, 'local_only': 0}
    live = CVEMatch.objects.filter(source='host', subdomain__target_domain__project_id=inv.project_id, subdomain__name__iexact=inv.host,
                                   evidence__inventory_id=inv.id).exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED)
    return {'total': live.count(), 'local_only': live.filter(cve_entry__local_only=True).count()}


def detail(inv, days, params=None, now=None, package_limit=200):
    """One report in full: the list fields plus a page of normalised packages, patches, listening services, runtime and security
    posture, the summarised history and what the CVE correlation made of it."""
    params = params or {}
    out = brief(inv, days, now)
    out.update({'packages_page': _package_rows(inv, params, package_limit), 'patches': inv.patches, 'services': inv.services,
                'runtime': (inv.details or {}).get('runtime', {}), 'security': (inv.details or {}).get('security', {}),
                'dropped': (inv.details or {}).get('dropped', {}), 'assessment': (inv.details or {}).get('assessment', {}),
                'os_detail': {k: v for k, v in (inv.os_info or {}).items() if v not in ('', [], None)},
                'collected_at': inv.collected_at.isoformat() if inv.collected_at else None, 'findings': findings_summary(inv),
                'history': [{'reported_at': h.reported_at.isoformat(), 'script_version': h.script_version, 'os': h.os_summary,
                            'packages': h.package_count, 'changes': h.changes} for h in inv.history.all()[:HISTORY_KEEP]]})
    return out


def run_correlation(inv_id):
    """The worker side of a report: match its packages and operating system against the CVEs and record what came of it."""
    from cveFeed import inventory_match
    from cveFeed.models import HostInventory
    inv = HostInventory.objects.filter(pk=inv_id).select_related('project').first()
    if inv is None:
        return {'status': 'skipped', 'reason': 'gone'}
    result = inventory_match.refresh(inv, stale_days(inv.project))
    if result['status'] == 'done':
        inv.details = {**(inv.details or {}), 'assessment': {'at': timezone.now().isoformat(), 'local': result['local'],
                                                                'external': result['external'], 'confirmed': result['confirmed'],
                                                                'notes': result['notes']}}
        inv.save(update_fields=['details'])
    return result


def refresh_scope(scan=None, project_slug=None):
    """Queue the CVE side again for the reporting hosts a correlation pass covers: the hosts of one scan, one project, or all of them
    (a feed sync brings new CVEs). A new scan makes new host rows and a host report's matches live on the current one, so this puts them
    back. One task per report, so thousands of machines are thousands of short jobs spread over the workers, not one that runs for an
    hour; a report that cannot be queued is skipped (the next pass tries it again) and never stops the scan pipeline that called it.
    Returns how many were queued."""
    from cveFeed.models import HostInventory
    from cveFeed.tasks import correlate_host_inventory
    from startScan.models import Subdomain
    qs = HostInventory.objects.exclude(host='')
    if scan is not None:
        qs = qs.filter(project_id=scan.domain.project_id, host__in={n.lower() for n in Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True)})
    elif project_slug:
        qs = qs.filter(project__slug=project_slug)
    queued = 0
    for inv_id in qs.values_list('id', flat=True):
        try:
            correlate_host_inventory.delay(inv_id)
            queued += 1
        except Exception:  # noqa: BLE001
            logger.warning('could not queue the CVE correlation of host report %s', inv_id, exc_info=True)
    return queued
