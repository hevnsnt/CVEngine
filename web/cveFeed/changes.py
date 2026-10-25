"""Asset change model: what is different about a host since CVEngine last looked.

Port and IpAddress rows are shared and rewritten in place by every scan, so "the previous scan's rows" is not a previous
snapshot. Each host therefore carries its own stored snapshot (``HostState``); a finished scan is diffed against it, the
differences are appended to ``AssetChange``, and the snapshot is replaced. Evaluators (``host_state``, ``diff_states``)
are pure functions so every rule is unit tested without a database.
"""
import hashlib
import json
import logging

from django.db import transaction
from django.utils import timezone

from cveFeed import scoring, shots

logger = logging.getLogger(__name__)

MAX_HOSTS_PER_DIFF = 5000  # bbot already caps a scan at MAX_EVENTS_PER_SCAN events
MAX_CHANGES_PER_SCAN = 2000
MAX_RETIRE_CHECKS = 200
CHUNK = 500


# ----------------------------------------------------------------------------- snapshots (pure)

def host_state(sub):
    """The snapshot of one prefetched Subdomain (``ip_addresses__ports``, ``technologies``):
    ``{"ips": {ip: {"ports": {"443/tcp": {service, product, version}}}}, "techs": [...], "http": {status, title}}``.
    Only open ports count, and only addresses a scanner may touch."""
    from targetApp.target_types import is_scannable_ip
    ips = {}
    for ip in sub.ip_addresses.all():
        address = (ip.address or '').strip()
        if not address or not is_scannable_ip(address):
            continue
        ports = ips.setdefault(address, {'ports': {}})['ports']
        for port in ip.ports.all():
            if (port.state or '') not in ('', 'open'):
                continue
            ports[f'{port.number}/{port.protocol or "tcp"}'] = {
                'service': port.service_name or '', 'product': port.product or '', 'version': port.version or ''}
    state = {'ips': ips, 'techs': sorted({t.name for t in sub.technologies.all() if t.name})}
    if (sub.http_status or 0) > 0:
        state['http'] = {'status': sub.http_status, 'title': (sub.page_title or '')[:200]}
    if getattr(sub, 'screenshot_hash', ''):  # compared by the dedicated screenshot step, not by diff_states
        state['screenshot'] = {'hash': sub.screenshot_hash, 'subdomain_id': sub.id, 'scan_id': sub.scan_history_id}
    return state


def fingerprint(state):
    """Hash of the canonical snapshot. The screenshot counts by its hash only: its subdomain and scan ids change with every
    scan and must not make an unchanged host look changed."""
    shot = state.get('screenshot')
    if shot:
        state = {**state, 'screenshot': shot.get('hash')}
    return hashlib.sha1(json.dumps(state, sort_keys=True).encode()).hexdigest()


def _port_number(key):
    try:
        return int(str(key).split('/')[0])
    except ValueError:
        return None


def diff_states(before, after):
    """``[(kind, ip, port, before_value, after_value)]`` between two snapshots. A new IP opens all its ports (CDNs rotate
    addresses, so there is no separate "IP changed"); a product appearing where there was none is nmap enrichment, not
    a change."""
    before, after = before or {}, after or {}
    out = []
    b_ips, a_ips = before.get('ips') or {}, after.get('ips') or {}
    for ip in sorted(set(a_ips) | set(b_ips)):
        b_ports = (b_ips.get(ip) or {}).get('ports') or {}
        a_ports = (a_ips.get(ip) or {}).get('ports') or {}
        for key in sorted(set(a_ports) - set(b_ports), key=lambda k: (_port_number(k) or 0, k)):
            out.append(('port_opened', ip, _port_number(key), None, {'port': key, **a_ports[key]}))
        for key in sorted(set(b_ports) - set(a_ports), key=lambda k: (_port_number(k) or 0, k)):
            out.append(('port_closed', ip, _port_number(key), {'port': key, **b_ports[key]}, None))
        for key in sorted(set(a_ports) & set(b_ports), key=lambda k: (_port_number(k) or 0, k)):
            was, now = b_ports[key], a_ports[key]
            if (was.get('product'), was.get('version')) == (now.get('product'), now.get('version')):
                continue
            if not (was.get('product') or was.get('version')):
                continue
            out.append(('service_changed', ip, _port_number(key),
                        {'port': key, 'product': was.get('product', ''), 'version': was.get('version', '')},
                        {'port': key, 'product': now.get('product', ''), 'version': now.get('version', '')}))
    # Technologies are compared by name. The light pass re-extracts versions on every run, so a banner that flips between
    # "nginx" and "nginx:1.18.0" is not an added and a removed technology; a version that differs on both sides is its own kind.
    b_techs, a_techs = _tech_versions(before.get('techs')), _tech_versions(after.get('techs'))
    for name in sorted(set(a_techs) - set(b_techs)):
        out.append(('tech_added', '', None, None, _tech_label(name, a_techs[name])))
    for name in sorted(set(b_techs) - set(a_techs)):
        out.append(('tech_removed', '', None, _tech_label(name, b_techs[name]), None))
    for name in sorted(set(a_techs) & set(b_techs)):
        if a_techs[name] and b_techs[name] and a_techs[name] != b_techs[name]:
            out.append(('tech_version_changed', '', None, _tech_label(name, b_techs[name]), _tech_label(name, a_techs[name])))
    return out


def _tech_versions(techs):
    """{name: set of versions} from the snapshot's technology strings ("nginx:1.18.0"); a name seen bare has no versions."""
    from cveFeed.correlation import split_name_version
    out = {}
    for tech in techs or []:
        name, version = split_name_version(tech)
        key = name.strip().lower()
        out.setdefault(key, set())
        if version:
            out[key].add(version)
    return out


def _tech_label(name, versions):
    return f'{name}:{sorted(versions)[0]}' if versions else name


# ----------------------------------------------------------------------------- the diff

def _chunks(items, size=CHUNK):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _current_states(scan):
    from startScan.models import Subdomain
    current = {}
    qs = Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports', 'technologies').order_by('id')
    for sub in qs.iterator(chunk_size=CHUNK):
        name = (sub.name or '').strip().lower()
        if not name or name in current:
            continue
        current[name] = host_state(sub)
        if len(current) >= MAX_HOSTS_PER_DIFF:
            break
    return current


def _record_baseline(scan, project, current, now):
    from cveFeed import activity
    from cveFeed.models import HostState
    rows = [HostState(project_id=project, domain_id=scan.domain_id, host=name, state=state, fingerprint=fingerprint(state),
                      scan=scan, last_seen=now) for name, state in current.items()]
    with transaction.atomic():
        for part in _chunks(rows):
            HostState.objects.bulk_create(part, ignore_conflicts=True)  # the name may already be known from a parent target
            existing = {h.host: h for h in HostState.objects.filter(project_id=project, host__in=[r.host for r in part])
                        if h.scan_id != scan.id}
            for row in part:
                if row.host in existing:
                    existing[row.host].state, existing[row.host].fingerprint = row.state, row.fingerprint
                    existing[row.host].scan, existing[row.host].last_seen = scan, now
                    existing[row.host].retired_at = None
                    existing[row.host].inactive_first_absent_at = None
                    existing[row.host].inactive_last_absent_at = None
                    existing[row.host].inactive_absent_checks = 0
                    if row.state.get('ips') and not existing[row.host].archived_by_user:  # a person's archive stays
                        existing[row.host].archived_at, existing[row.host].archive_reason = None, ''
                        existing[row.host].archive_check_status = 'rediscovered_scan'
            HostState.objects.bulk_update(list(existing.values()), ['state', 'fingerprint', 'scan', 'last_seen', 'retired_at',
                                                                      'inactive_first_absent_at', 'inactive_last_absent_at',
                                                                      'inactive_absent_checks',
                                                                      'archived_at', 'archive_reason', 'archive_check_status'],
                                          batch_size=CHUNK)
    activity.log('changes', f'Baseline recorded for {scan.domain.name}: {len(current)} hosts', project=project, scan_id=scan.id)
    scoring.rescore_quietly(project, list(current), scan_id=scan.id)
    return {'hosts': len(current), 'changes': 0, 'baseline': True}


def _retire(scan, current, resolver, checker, now, tcp_checker=None):
    """Hosts of the target that this full scan no longer found. Only a name that also stops resolving is a candidate: a
    standard or passive run that finds fewer names than a deep one did must not retire hosts that are still there. A candidate
    whose last known web address still answers is a zombie (reported once, not retired); one that answers nowhere is retired.
    Returns ``(changes, retired, zombies)``."""
    from cveFeed import zombie
    from cveFeed.models import AssetChange, HostState
    project = scan.domain.project_id
    candidates = []
    stale = HostState.objects.filter(domain_id=scan.domain_id, retired_at__isnull=True).order_by('last_seen', 'id')
    for host in stale.values_list('host', flat=True)[:MAX_HOSTS_PER_DIFF + MAX_RETIRE_CHECKS]:
        if host not in current:
            candidates.append(host)
            if len(candidates) >= MAX_RETIRE_CHECKS:
                break
    if not candidates:
        return [], 0, 0
    resolved = {name for name, _ in resolver(candidates)}
    gone = [h for h in candidates if h not in resolved]
    rows = {r.host: r for r in HostState.objects.filter(project_id=project, host__in=gone, retired_at__isnull=True)}
    alive, checked = zombie.check_hosts([h for h in gone if h in rows], {h: r.state for h, r in rows.items()}, checker)
    open_ports = zombie.tcp_probe_hosts([h for h in checked if h not in alive], {h: r.state for h, r in rows.items()}, tcp_checker)
    changes, retire, touched = [], [], []
    for host in checked:
        row = rows[host]
        row.last_alive_check = now
        if host in alive:
            if row.zombie_since is None:
                row.zombie_since = now
                changes.append(AssetChange(project_id=project, domain_id=scan.domain_id, scan=scan, host=host, kind='zombie_host',
                                           before={'ips': sorted((row.state or {}).get('ips') or {})}, after={'alive': alive[host]},
                                           detected_at=now))
        else:
            row.retired_at, row.zombie_since = now, None
            retire.append(row)
            changes.append(AssetChange(project_id=project, domain_id=scan.domain_id, scan=scan, host=host, kind='host_retired',
                                       before={'ips': sorted((row.state or {}).get('ips') or {})},
                                       after={'tcp_alive': open_ports[host]} if host in open_ports else None, detected_at=now))
        touched.append(row)
    HostState.objects.bulk_update(touched, ['retired_at', 'zombie_since', 'last_alive_check'], batch_size=CHUNK)
    return changes, len(retire), len(alive)


def record_scan_changes(scan_id, resolver=None, checker=None, tcp_checker=None):
    """Diff a finished scan's hosts against their stored snapshots, append the differences and replace the snapshots.
    The first scan of a target only records a baseline (no changes: everything would be "new")."""
    from cveFeed import activity, discovery
    from cveFeed.models import AssetChange, HostState, RouteAuth
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    project = scan.domain.project_id
    if not project:
        return {'changes': 0, 'skipped': 'no project'}
    resolver = resolver or discovery.resolve_names
    partial = discovery.HOST_PIPELINE_TASK in (scan.tasks or [])
    now = timezone.now()
    current = _current_states(scan)
    if not HostState.objects.filter(domain_id=scan.domain_id).exists():
        return _record_baseline(scan, project, current, now)

    known = {}
    for part in _chunks(current):
        known.update({h.host: h for h in HostState.objects.filter(project_id=project, host__in=part)})
    rows, new_rows, changed_rows, unchanged, shot_diffs = [], [], [], [], []
    limit = shots.threshold()

    def change(kind, host, ip='', port=None, before=None, after=None):
        rows.append(AssetChange(project_id=project, domain_id=scan.domain_id, scan=scan, host=host, kind=kind, ip=ip or '',
                                port=port, before=before, after=after, detected_at=now))

    for host, state in current.items():
        row, print_ = known.get(host), fingerprint(state)
        if row is None:
            change('host_new', host, after=state)
            new_rows.append(HostState(project_id=project, domain_id=scan.domain_id, host=host, state=state, fingerprint=print_,
                                      scan=scan, last_seen=now))
            continue
        was_zombie = row.zombie_since is not None
        was_archived = row.archived_at is not None and bool(state.get('ips')) and not row.archived_by_user  # a person's archive stays
        if was_archived:
            row.archived_at, row.archive_reason, row.archive_check_status = None, '', 'rediscovered_scan'
            if row.retired_at is None:
                change('host_returned', host, after={'evidence': 'scannable address in a new scan'})
        if was_zombie:
            if row.retired_at is None:
                change('host_returned', host, after=state)
            change('zombie_cleared', host, before={'zombie_since': row.zombie_since.isoformat()})
            row.zombie_since = None
        if row.retired_at is not None:
            change('host_returned', host, after=state)
            row.retired_at = None
        elif row.fingerprint == print_ and not was_zombie and not was_archived:
            unchanged.append(host)
            continue
        was_shot, new_shot = (row.state or {}).get('screenshot') or {}, state.get('screenshot') or {}
        if was_shot.get('hash') and new_shot.get('hash') and len(shot_diffs) < shots.MAX_SHOT_DIFFS_PER_SCAN:
            try:
                distance = shots.hamming(was_shot['hash'], new_shot['hash'])
            except ValueError:  # a damaged snapshot: nothing to compare
                distance = 0
            if distance >= limit:
                shot_diffs.append((host, was_shot, new_shot, distance))
        for kind, ip, port, was, now_value in diff_states(row.state, state):
            change(kind, host, ip, port, was, now_value)
        row.state, row.fingerprint, row.scan, row.last_seen = state, print_, scan, now
        row.inactive_first_absent_at, row.inactive_last_absent_at, row.inactive_absent_checks = None, None, 0
        changed_rows.append(row)

    if shot_diffs:
        root_auth = {}
        for host, auth in RouteAuth.objects.filter(project_id=project, host__in=[d[0] for d in shot_diffs], path='/') \
                .order_by('checked_at').values_list('host', 'auth_state'):
            root_auth[host] = auth  # the newest check of the front page wins
        for host, was_shot, new_shot, distance in shot_diffs:
            change('screenshot_changed', host, before=was_shot,
                   after={**new_shot, 'distance': distance, 'root_auth': root_auth.get(host, '')})
    retired = zombies = 0
    if not partial:
        retire_rows, retired, zombies = _retire(scan, current, resolver, checker, now, tcp_checker)
        rows.extend(retire_rows)

    truncated = len(rows) > MAX_CHANGES_PER_SCAN
    rows = rows[:MAX_CHANGES_PER_SCAN]
    with transaction.atomic():
        for part in _chunks(rows):
            AssetChange.objects.bulk_create(part)
        for part in _chunks(new_rows):
            HostState.objects.bulk_create(part, ignore_conflicts=True)
        HostState.objects.bulk_update(changed_rows, ['state', 'fingerprint', 'scan', 'last_seen', 'retired_at', 'zombie_since',
                                                      'inactive_first_absent_at', 'inactive_last_absent_at', 'inactive_absent_checks',
                                                      'archived_at', 'archive_reason', 'archive_check_status'], batch_size=CHUNK)
        for part in _chunks(unchanged):
            HostState.objects.filter(project_id=project, host__in=part).update(
                last_seen=now, scan=scan, inactive_first_absent_at=None,
                inactive_last_absent_at=None, inactive_absent_checks=0)

    counts = {}
    for r in rows:
        counts[r.kind] = counts.get(r.kind, 0) + 1
    if counts:
        summary = ', '.join(f'{n} {k.replace("_", " ")}' for k, n in sorted(counts.items()))
        activity.log('changes', f'Changes for {scan.domain.name}: {summary}', project=project, scan_id=scan.id, **counts)
    else:
        logger.debug('no changes for scan %s', scan.id)
    scoring.rescore_quietly(project, list(current), scan_id=scan.id)
    try:
        from cveFeed import retest
        retest.queue_retests(scan)
    except Exception:  # noqa: BLE001 - a re-test that could not be queued must not undo the diff
        logger.exception('could not queue a re-test for scan %s', scan.id)
    return {'hosts': len(current), 'changes': len(rows), 'truncated': truncated, 'retired': retired, 'zombies': zombies,
            'by_kind': counts}


# ----------------------------------------------------------------------------- helpers for other modules

def _cert_key(cert):
    """The five fields whose difference is a certificate change; ``cert`` is a TlsCertificate or a probe dict."""
    get = cert.get if isinstance(cert, dict) else (lambda k, d=None: getattr(cert, k, d))
    not_after = get('not_after')
    return {'subject': get('subject') or '', 'issuer': get('issuer') or '', 'sans': sorted(get('sans') or []),
            'not_after': not_after.isoformat() if hasattr(not_after, 'isoformat') else (not_after or None),
            'key_description': get('key_description') or ''}


def record_cert_change(domain, host, port, before, after, project_id):
    """One ``cert_changed`` row when a host presents a different certificate than at the last check (``before`` None = first
    sight, nothing to report)."""
    from cveFeed.models import AssetChange
    if before is None:
        return None
    was, now = _cert_key(before), _cert_key(after)
    if was == now:
        return None
    return AssetChange.objects.create(project_id=project_id, domain=domain, host=host, kind='cert_changed', port=port,
                                      before=was, after=now)


def record_auth_change(project_id, domain_id, scan_id, host, url, before_state, after_state, evidence=None):
    from cveFeed.models import AssetChange
    return AssetChange.objects.create(
        project_id=project_id, domain_id=domain_id, scan_id=scan_id, host=host, kind='auth_changed',
        before={'auth_state': before_state, 'url': url}, after={'auth_state': after_state, 'url': url, **(evidence or {})})


def record_sensitive_change(project_id, domain_id, scan_id, host, url, before_types, found):
    """A route now serves a kind of sensitive data it did not before. Types and counts only: no samples in the change log."""
    from cveFeed.models import AssetChange
    return AssetChange.objects.create(
        project_id=project_id, domain_id=domain_id, scan_id=scan_id, host=host, kind='sensitive_found',
        before={'types': sorted(before_types)},
        after={'url': url, 'types': sorted(found), 'counts': {t: v['count'] for t, v in found.items()}})


def record_route_change(kind, project_id, domain_id, scan_id, host, before, after):
    """A route was retired (it said not found after answering) or is a zombie (a retired or documented-as-gone route answers)."""
    from cveFeed.models import AssetChange
    return AssetChange.objects.create(project_id=project_id, domain_id=domain_id, scan_id=scan_id, host=host, kind=kind,
                                      before=before, after=after)
