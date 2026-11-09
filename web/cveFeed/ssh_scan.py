"""Read-only inspection of the SSH services a scan already found open (task kind ``ssh_probe``, contract version 3).

A Sentinel runs the inspection (``cvengine_scanner.probes.ssh_probe``: one ``sshamble scan`` with the single ``badkeys-blocklist`` check, no credential
and no key ever sent). This server installs and runs no SSH tool and opens no connection: it chooses which endpoints to ask, builds the task and its
scope policy (``cveFeed.probe_scope.for_ssh``), validates what comes back (``agentapi.probe_results.clean_ssh_probe``) and stores it.

Which endpoints. After the port stage: every open TCP port of the scan that is port 22 or whose detected service, product or banner is SSH
(``is_ssh_port``). One endpoint is one (address, port), however many names point at it. Nothing else is asked, and an address the organization
excluded, a bug bounty program's scope or the address rules refuse is never sent.

How often. An endpoint is inspected once a week (``ledger`` service ``ssh-probe``), sooner when the banner or software version the port stage read for the port
changed since the last inspection (a fingerprint kept with the stored banner observation), and again a day later when the inspection could not be
completed (service ``ssh-probe-failed``: the host was not reached, or the blocklist check could not run). A retest or a forced stage asks again now.

What is stored.

* **Inventory facts** (the banner and software version, host key algorithms and sizes, offered authentication methods, algorithm lists, extensions) are
  ``ProbeObservation`` rows of kind ``ssh``, one per host name, port and observation id (the dedupe key), outcome ``found``. They are facts, not findings: weak
  algorithms and password authentication are classes the template checks already report. An observation the Sentinel could not verify is stored with outcome
  ``unverified`` (never ``found``, never clean) and shows as such.
* **A compromised host key** (the host key is on the badkeys blocklist) is one finding per host name and endpoint, severity high, set here: the severity a
  Sentinel reports is never used. A later complete inspection that finds the key off the blocklist closes it.

An endpoint the Sentinel did not answer, a task that failed and a host that was not reached are never read as clean: nothing is recorded as done, the endpoint
stays due, and with no scanner able to take the kind the stage waits (``ScannerUnavailable``; the kind is in ``sentinel_dispatch.NEVER_LOCAL``).
"""
import hashlib
import logging
import os
import re

from django.utils import timezone

logger = logging.getLogger(__name__)

KIND = 'ssh_probe'  # the Sentinel task kind
SERVICE = 'ssh-probe'  # the ledger service: one row per ``address:port``, a week
FAILED_SERVICE = 'ssh-probe-failed'  # an endpoint that could not be inspected completely: asked again after a day
PROBE = 'ssh-probe'  # ProbeObservation.probe
OBS_KIND = 'ssh'  # ProbeObservation.kind
SOURCE = 'ssh-probe'  # Vulnerability.source
TEMPLATE_ID = 'ssh-badkeys-blocklist'
FINDING_NAME = 'SSH host key is on the badkeys compromised-key blocklist'
HIT_ID = 'badkeys_blocklist_hit'  # the observation ids the Sentinel's parser writes for the one verdict
CLEAR_ID = 'badkeys_blocklist_clear'
BANNER_ID = 'ssh_banner'
MAX_TARGETS_PER_TASK = 25  # the contract's bound (cvengine_scanner.probes.ssh_probe.MAX_TARGETS)
MAX_PER_SCAN = 100  # endpoints one scan sends (four tasks); the rest are due on the next scan
SEVERITY_HIGH = 3  # the scale of scanner findings: 0 info, 1 low, 2 medium, 3 high, 4 critical (the severity a Sentinel reports is never used)
UNVERIFIED = 'unverified'  # the ProbeObservation outcome of an observation that was not verified

_SSH_NAME = re.compile(r'(?:^|[^a-z0-9])ssh(?:$|[^a-z0-9])')


def enabled():
    return os.environ.get('CVENGINE_SSH_PROBE', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def max_per_scan():
    try:
        return max(1, int(os.environ.get('CVENGINE_SSH_PROBE_MAX_ENDPOINTS', MAX_PER_SCAN)))
    except ValueError:
        return MAX_PER_SCAN


def is_ssh_port(port):
    """Whether an open TCP port row is an SSH endpoint: port 22, or a detected service name, product or banner that says SSH. Reads attributes
    tolerantly (a stored ``Port`` or a plain object); a UDP port is never one."""
    if (getattr(port, 'protocol', 'tcp') or 'tcp') not in ('tcp', 'tcp6'):
        return False
    if getattr(port, 'number', 0) == 22:
        return True
    service = (getattr(port, 'service_name', '') or '').lower()
    product = (getattr(port, 'product', '') or '').lower()
    banner = (getattr(port, 'banner', '') or '')[:16].lstrip()
    return bool(_SSH_NAME.search(service)) or 'openssh' in product or 'dropbear' in product or banner.startswith('SSH-')


def fingerprint(port):
    """A short digest of what the port stage read for the port (banner, product and version): when it changes the endpoint is due again before its week is up.
    Empty when nothing was read (an unknown fingerprint is never a change)."""
    parts = [(getattr(port, 'banner', '') or '').strip()[:255], (getattr(port, 'product', '') or '').strip(), (getattr(port, 'version', '') or '').strip()]
    if not any(parts):
        return ''
    return hashlib.sha256('|'.join(parts).encode('utf-8', 'replace')).hexdigest()[:12]


def candidates(scan):
    """``{(address, port): {'subs': [Subdomain], 'fp': fingerprint}}`` for the SSH endpoints of this scan's open ports, leaving out the hosts the
    organization excluded, what a bug bounty program's scope does not name and the addresses a scanner may not reach. Every name that answers at an
    address is listed with it."""
    from startScan.models import Subdomain
    return _candidates(scan.domain.project_id, Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'))


def candidates_for_hosts(project_id, names):
    """``candidates`` for the current inventory rows (``correlation.latest_scan_q``, one per host) of the named hosts of a project, for the work planner,
    which inspects endpoints without a scan of its own. Each ``subs`` entry is a stored row, so ``sub.scan_history`` is the scan that found it."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id, name__in=sorted({n.lower().rstrip('.') for n in names}))
            .select_related('scan_history', 'target_domain').prefetch_related('ip_addresses__ports'))
    return _candidates(project_id, rows)


def _candidates(project, subdomains):
    from cveFeed.bounty_gate import Gate
    from cveFeed.exclusions import excluded_names, normalize
    from startScan.models import open_ports
    from targetApp.target_types import is_scannable_ip
    banned = excluded_names(project, strict=True)  # an authorization check fails closed
    gate = Gate(blocked=())
    out = {}
    for sub in subdomains:
        if normalize(sub.name) in banned or gate.refusal(project, sub.name, unattended=False):
            continue
        for ip in sub.ip_addresses.all():
            if not is_scannable_ip(ip.address, project=project) or gate.refusal(project, ip.address, unattended=False, derived=True):
                continue
            for port in open_ports(ip):
                if not is_ssh_port(port):
                    continue
                entry = out.setdefault((ip.address, port.number), {'subs': [], 'fp': ''})
                if sub.pk not in {s.pk for s in entry['subs']}:
                    entry['subs'].append(sub)
                entry['fp'] = entry['fp'] or fingerprint(port)
    return out


def asset(address, port):
    return f'{address}:{port}'


def stored_fingerprints(project_id, hosts):
    """``{(host, port): fingerprint}`` kept with the stored banner observations of ``hosts``: what the port stage read when the endpoint was last inspected."""
    from cveFeed.models import ProbeObservation
    out = {}
    for host, port, evidence in ProbeObservation.objects.filter(project_id=project_id, host__in=list(hosts), probe=PROBE, kind=OBS_KIND,
                                                                product=BANNER_ID).values_list('host', 'port', 'evidence'):
        out[(host, port)] = (evidence or {}).get('port_fp', '')
    return out


def due(project_id, found, force=False):
    """The endpoints of ``found`` (``candidates``) to ask now, in a stable order, at most ``max_per_scan``: those with no inspection inside the week, no
    incomplete one inside the day, or whose banner changed since the last. ``force`` (a retest) asks every one."""
    from cveFeed import ledger
    keys = sorted(found)
    if not keys:
        return []
    if force:
        return keys[:max_per_scan()]
    assets = [asset(*k) for k in keys]
    done = ledger.fresh(SERVICE, assets, project_id)
    retry_later = ledger.fresh(FAILED_SERVICE, assets, project_id)
    known = stored_fingerprints(project_id, {s.name.lower() for k in keys for s in found[k]['subs']})
    out = []
    for key in keys:
        name = ledger._norm(asset(*key))
        fp = found[key]['fp']
        changed = bool(fp) and any(known.get((s.name.lower(), key[1]), fp) != fp for s in found[key]['subs'])
        if changed or (name not in done and name not in retry_later):
            out.append(key)
    return out[:max_per_scan()]


def build_target(keys, project_id):
    """The ``ssh_probe`` target of one task: the endpoints (an address, asked as itself, and its port) and the scope policy."""
    from cveFeed import probe_scope
    return {'targets': [{'address': a, 'port': p} for a, p in keys], 'scope': probe_scope.for_ssh(project_id, [a for a, _p in keys])}


def _dispatch(project, keys, scan):
    from agentapi import probe_dispatch
    return probe_dispatch.try_ssh_probe(project, keys, scan=scan)


def run_for_scan(scan_id, force=False, dispatch=None):
    """Inspect the SSH endpoints of this scan's open ports on a Sentinel and file what comes back. Returns ``{'endpoints', 'inspected', 'incomplete',
    'findings', 'waiting'}``. ``dispatch(project, keys, scan)`` replaces ``probe_dispatch.try_ssh_probe`` in tests: it returns ``{(address, port): row}``.
    Raises ``ScannerUnavailable`` when no scanner can take the kind, and after the answered endpoints are stored when a task ended without an answer:
    those endpoints stay due and the stage waits (nothing runs on this server)."""
    from agentapi import sentinel_dispatch
    from cveFeed import activity
    from reNgine.resources import ScannerUnavailable
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    project = scan.domain.project
    summary = {'endpoints': 0, 'inspected': 0, 'incomplete': 0, 'findings': 0, 'waiting': 0}
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates(scan)
    keys = due(project.pk, found, force=force)
    summary['endpoints'] = len(found)
    if not keys:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)  # raises ScannerUnavailable when none can take it: the kind has no local path
        dispatch = _dispatch
    _inspect(project, keys, found, lambda key: scan, lambda project_, chunk: dispatch(project_, chunk, scan), summary)
    activity.log('run_check', f'SSH inspection of {summary["inspected"]} of {len(keys)} endpoint(s) of {scan.domain.name}: {summary["findings"]} compromised host key(s)'
                 + (f'; {summary["incomplete"]} could not be inspected completely' if summary['incomplete'] else '')
                 + (f'; {summary["waiting"]} wait for a scanner' if summary['waiting'] else ''), project=project.pk, scan_id=scan.id)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} SSH endpoint(s): they stay due')
    return summary


def _inspect(project, keys, found, scan_for, send, summary):
    """Claim ``keys`` (the endpoints to ask), send them in tasks of ``MAX_TARGETS_PER_TASK`` through ``send(project, chunk)`` and file every answer under
    ``scan_for(key)`` (the scan a finding and the ledger row belong to). Adds to ``summary``; what no Sentinel answered is counted as waiting."""
    from cveFeed import ledger
    with ledger.claim_many(f'{SERVICE}@{project.pk}', [asset(*k) for k in keys]) as won:
        won = set(won)
        keys = [k for k in keys if ledger._norm(asset(*k)) in won]
        for start in range(0, len(keys), MAX_TARGETS_PER_TASK):
            chunk = keys[start:start + MAX_TARGETS_PER_TASK]
            chunk = [k for k in chunk if _still_allowed(project.pk, found[k]['subs'])]  # excluded since the plan was made: not sent
            if not chunk:
                continue
            answered = send(project, chunk)
            for key in chunk:
                row = (answered or {}).get(key)
                if row is None:  # no answer for this endpoint: unknown, due again, nothing recorded
                    summary['waiting'] += 1
                    continue
                subs = _allowed_subs(project.pk, found[key]['subs'])
                scan = scan_for(key)
                complete, filed = store_row(project.pk, scan, subs, key[0], key[1], row, found[key]['fp'])
                summary['findings'] += filed
                if complete:
                    summary['inspected'] += 1
                    ledger.record(SERVICE, [asset(*key)], project.pk, scan)
                else:
                    summary['incomplete'] += 1
                    ledger.record(FAILED_SERVICE, [asset(*key)], project.pk, scan)


def run_for_hosts(project, host_names, keys=None, dispatch=None, priority=1):
    """Inspect the SSH endpoints of the named hosts' current inventory rows on a Sentinel and file what comes back: the work planner's entry
    (``cveFeed.work_planner``), the same plan, scope gates, ledger and storage as ``run_for_scan`` with no scan of its own. ``keys`` narrows it to the
    endpoints the planner chose; what is not due (a fresh ledger row, a changed banner aside) is not sent. ``dispatch(project, chunk)`` replaces the
    Sentinel call in tests. Returns the summary of ``run_for_scan``; raises ``ScannerUnavailable`` as it does, after filing the answered endpoints."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    summary = {'endpoints': 0, 'inspected': 0, 'incomplete': 0, 'findings': 0, 'waiting': 0}
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates_for_hosts(project.pk, host_names)
    if keys is not None:
        wanted = {(a, int(p)) for a, p in keys}
        found = {k: v for k, v in found.items() if k in wanted}
    todo = due(project.pk, found)
    summary['endpoints'] = len(found)
    if not todo:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)  # raises ScannerUnavailable when none can take it
        dispatch = lambda project_, chunk: probe_dispatch.try_ssh_probe(project_, chunk, priority=priority)  # noqa: E731
    _inspect(project, todo, found, lambda key: found[key]['subs'][0].scan_history, dispatch, summary)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} SSH endpoint(s): they stay due')
    return summary


def _allowed_subs(project_id, subs):
    from cveFeed.exclusions import excluded_names, normalize
    banned = excluded_names(project_id, strict=True)
    return [s for s in subs if normalize(s.name) not in banned]


def _still_allowed(project_id, subs):
    return bool(_allowed_subs(project_id, subs))


def _has_verified(row, ident):
    return any(o['id'] == ident and o['verified'] for o in row['observations'])


def compromised(row):
    """Whether a host entry says the host key is on the blocklist: the host was reached and a check hit or the verified verdict observation says so."""
    return bool(row['reached'] and (row['check_hits'] or _has_verified(row, HIT_ID)))


def key_checked(row):
    """Whether the host key was checked against the blocklist and read clean: reached, and the verified clear verdict is there. Anything else (the data
    missing on the Sentinel, no key read) is unknown, never clean."""
    return bool(row['reached'] and _has_verified(row, CLEAR_ID) and not compromised(row))


def store_row(project_id, scan, subs, address, port, row, fp=''):
    """File one cleaned host entry for every name in ``subs``. Returns ``(complete, findings)``: ``complete`` is true when the host was reached and the
    blocklist check ran (so the weekly window applies); anything less is asked again after a day."""
    from cveFeed.models import ProbeObservation
    now = timezone.now()
    verdict = compromised(row) or key_checked(row)
    filed = 0
    for sub in subs:
        host = sub.name.lower().rstrip('.')
        seen = []
        for obs in row['observations']:
            evidence = {'id': obs['id'], 'title': obs['title'], 'evidence': obs['evidence'], 'verified': obs['verified'], 'address': address}
            if obs['id'] == BANNER_ID and obs['verified'] and fp:
                evidence['port_fp'] = fp
            seen.append(obs['id'])
            ProbeObservation.objects.update_or_create(
                project_id=project_id, host=host, probe=PROBE, port=port, kind=OBS_KIND, product=obs['id'][:120],
                defaults={'domain_id': scan.domain_id, 'version': '', 'variant': '', 'url': '', 'outcome': 'found' if obs['verified'] else UNVERIFIED,
                          'confidence': 1.0 if obs['verified'] else 0.0, 'source': 'sshamble', 'evidence': evidence, 'observed_at': now})
        if row['reached']:  # a complete picture of the endpoint: a fact it no longer reports (or an earlier "could not be inspected") is gone
            ProbeObservation.objects.filter(project_id=project_id, host=host, probe=PROBE, port=port, kind=OBS_KIND).exclude(product__in=seen).delete()
        if compromised(row):
            filed += _file_finding(scan, sub, address, port, row)
        elif key_checked(row):
            _close_finding(scan, sub, address, port)
    return bool(row['reached'] and verdict), filed


def _file_finding(scan, sub, address, port, row):
    """The one finding of the kind: the host key is on the badkeys blocklist. High severity, decided here. One row per host name and endpoint: a rescan
    updates it."""
    from reNgine.tasks import save_vulnerability
    proof = '; '.join(f"{h['id']}{(' ' + h['proof']) if h['proof'] else ''}" for h in row['check_hits'][:5])
    if not proof:
        proof = '; '.join(o['evidence'] for o in row['observations'] if o['id'] == HIT_ID and o['verified'])[:300]
    _vuln, created = save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, source=SOURCE, template_id=TEMPLATE_ID, name=FINDING_NAME,
        severity=SEVERITY_HIGH, http_url=f'ssh://{address}:{port}', type='ssh',
        description=f'A Sentinel read the SSH host key of {address}:{port} and it is on the badkeys blocklist of compromised or weak keys ({proof}). '
                    'Anyone who holds the published private key can impersonate this server to the people and systems that trust it.',
        impact='The server cannot prove its identity: a person in the network path can pose as it and read or change what its users send.',
        remediation='Generate new SSH host keys on this server (ssh-keygen -A after removing the old ones), restart sshd, and tell the people and systems that '
                    'trust the old fingerprint. Find out why a blocklisted key was installed (a cloned image or a weak random source).',
        extracted_results=[proof] if proof else [], tags=['ssh', 'host-key'])
    return 1 if created else 0


def _close_finding(scan, sub, address, port):
    """A complete inspection that read the key as not on the blocklist: the finding of an earlier inspection is gone. A finding a person already dealt with
    keeps its status."""
    from startScan.models import Vulnerability
    Vulnerability.objects.filter(target_domain__project_id=scan.domain.project_id, subdomain__name=sub.name, source=SOURCE, template_id=TEMPLATE_ID,
                                 http_url=f'ssh://{address}:{port}', open_status=True, remediation_status='open').update(open_status=False)
