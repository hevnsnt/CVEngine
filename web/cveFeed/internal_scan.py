"""Scanning the targets a project declared internal (``cveFeed.models.InternalRange``): only ever through a Sentinel deployed inside
that network, never from this server.

An internal target is a Domain whose name is an address inside a declared range that this server may not scan itself
(``targetApp.target_types.sentinel_only_target``). The normal pipeline never touches it: its local stages all refuse the address, and
most of them (route checks, probes, hygiene, database exposure, screenshots) have no Sentinel path at all. This driver is the one
pipeline for such a target, and every step in it is a ``SentinelTask`` for a Sentinel that declares ``network:internal`` (an outside
Sentinel cannot reach the address and would report an empty result as clean). There is no local fallback anywhere: when no such
Sentinel answers, the step fails and the scan says so, and the next sweep tries again.

What it runs: the host record for the address (no network access), an nmap fingerprint, a TLS audit of each TLS port nmap found, the nuclei
technology pass, CVE correlation, then the AI-targeted nuclei pass. Each stage is the external pipeline's own function (same
parsing, same persistence); only the execution seam differs. ``internal_scope`` makes the stages treat the address as a target and makes
every local scanner refuse to run, so a seam that was missed fails loudly. Stages that run from this server directly (route checks,
probes, hygiene, database exposure, screenshots) have no Sentinel path and are not run. WPScan runs through a Sentinel on the sites the Sentinel-run technology
pass tagged as WordPress (this server sends no probe of its own), and OpenVAS has its own opt-in sweep (``cveFeed.openvas_scan.internal_batch``).
"""
import logging
import os
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

TASK_TAG = 'internal_pipeline'  # ScanHistory.tasks marks a scan that belongs to this driver
SWEEP_MAX = 20  # targets one sweep queues (CVENGINE_INTERNAL_SCAN_MAX)
FAILURE_RETRY = timedelta(hours=1)  # avoid repeatedly queueing a failed target when a sweep is retried


def cadence():
    """How long a target is left alone after a scan before the sweep queues it again (CVENGINE_INTERNAL_SCAN_DAYS, default 7)."""
    try:
        return timedelta(days=max(1, int(os.environ.get('CVENGINE_INTERNAL_SCAN_DAYS', '7'))))
    except ValueError:
        return timedelta(days=7)


def start(domain, initiated_by=None):
    """Queue an internal scan of ``domain`` and return its ``ScanHistory``; one already queued or running is returned instead of a second."""
    from cveFeed.discovery import QUEUED, _active_filter, pick_engine
    from cveFeed.bounty_gate import Gate
    from cveFeed.exclusions import is_excluded
    from cveFeed.tasks import run_internal_scan
    from startScan.models import ScanHistory
    from targetApp.target_types import sentinel_only_target
    if not sentinel_only_target(domain.name, domain.project_id):
        raise ValueError(f'{domain.name} is not inside an internal range of its project')
    if is_excluded(domain.project_id, domain.name):
        raise ValueError(f'{domain.name} is excluded for this organization')
    why = Gate().refusal(domain.project_id, domain.name, unattended=initiated_by is None)
    if why:
        raise ValueError(f'{domain.name} is not scanned: {why}')
    active = ScanHistory.objects.filter(_active_filter(), domain=domain, tasks__contains=[TASK_TAG]).order_by('id').first()
    if active:
        return active
    engine = pick_engine()
    if engine is None:
        raise RuntimeError('no scan engine is configured')
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=QUEUED,
                                      results_dir='/usr/src/scan_results', initiated_by=initiated_by, tasks=[TASK_TAG])
    run_internal_scan.delay(scan.id)
    return scan


def due_targets(limit=SWEEP_MAX, now=None):
    """Internal targets to scan now, oldest scan first: not scanned inside the cadence, none with a scan going, and only in a project
    where a live ``network:internal`` Sentinel could take the work (a scan nobody can run would only fail)."""
    from django.db.models import Exists, F, OuterRef, Q, Subquery
    from django.db.models.functions import Coalesce
    from agentapi import sentinel_broker
    from cveFeed.bounty_gate import Gate
    from cveFeed.discovery import SUCCESS, FAILED, _active_filter
    from cveFeed.exclusions import excluded_names
    from dashboard.models import Project
    from startScan.models import ScanActivity, ScanHistory
    from targetApp.models import Domain
    from targetApp.target_types import internal_networks, sentinel_only_target
    now = now or timezone.now()
    cutoff = now - cadence()
    retry_cutoff = now - FAILURE_RETRY
    busy = set(ScanHistory.objects.filter(_active_filter(), tasks__contains=[TASK_TAG]).values_list('domain_id', flat=True))
    from cveFeed.models import InternalRange
    chosen = []
    gate = Gate()
    failed_stage = ScanActivity.objects.filter(scan_of_id=OuterRef('pk'), status=FAILED)
    attempts = (ScanHistory.objects.filter(domain_id=OuterRef('pk'), tasks__contains=[TASK_TAG])
                .annotate(stage_failed=Exists(failed_stage), completed_at=Coalesce('stop_scan_date', 'start_scan_date')))
    last_success = (attempts.filter(scan_status=SUCCESS, stage_failed=False)
                    .order_by('-completed_at').values('completed_at')[:1])
    last_failure = (attempts.filter(Q(scan_status=FAILED) | Q(scan_status=SUCCESS, stage_failed=True))
                    .order_by('-completed_at').values('completed_at')[:1])
    for project in Project.objects.filter(pk__in=InternalRange.objects.values('project_id')).select_related('org'):
        if len(chosen) >= limit:
            break
        if not sentinel_broker.any_scanner_for(project, 'nmap', internal=True):
            continue
        nets = internal_networks(project.id)
        banned = excluded_names(project.id)
        rows = (Domain.objects.filter(project=project).annotate(last_success=Subquery(last_success), last_failure=Subquery(last_failure))
                .order_by(F('last_success').asc(nulls_first=True), 'id'))
        for domain in rows:
            if len(chosen) >= limit:
                break
            recent_failure = domain.last_failure and (not domain.last_success or domain.last_failure > domain.last_success)
            if (domain.id in busy
                    or (recent_failure and domain.last_failure >= retry_cutoff)
                    or (not recent_failure and domain.last_success and domain.last_success >= cutoff)
                    or not sentinel_only_target(domain.name, project.id, nets)
                    or domain.name.lower().rstrip('.') in banned or gate.refusal(project.id, domain.name)):
                continue
            chosen.append(domain)
    return chosen


def sweep():
    """One round of the scheduled sweep: queue the due internal targets. Returns how many."""
    from cveFeed.scan_control import pause_requested
    if pause_requested():
        return {'started': 0, 'skipped': 'paused'}
    try:
        limit = max(1, int(os.environ.get('CVENGINE_INTERNAL_SCAN_MAX', str(SWEEP_MAX))))
    except ValueError:
        limit = SWEEP_MAX
    started = 0
    for domain in due_targets(limit):
        try:
            start(domain)
            started += 1
        except ValueError:  # policy or range changed after due_targets selected it
            continue
        except Exception:  # noqa: BLE001 - one target's trouble must not stop the round
            logger.exception('internal scan sweep: could not queue %s', domain.name)
    return {'started': started}


def _nmap(scan, project, ip, org_id, dispatch):
    """Fingerprint ``ip`` through an internal Sentinel and store what it found; an ``error`` when none answered."""
    from cveFeed import ledger
    from cveFeed.nmap_scan import persist_inventory
    result = dispatch(project, 'nmap', {'addresses': [ip]}, host=ip, ips=[ip], scan=scan, internal=True)
    if result is None:
        return {'error': 'no Sentinel inside the network answered (one must declare network:internal and cover this project)'}
    inventory = [{'ip': h['ip'], 'os_guess': h.get('os_guess', ''), 'os_accuracy': None, 'ports': h.get('ports', [])}
                 for h in result.get('hosts', []) if h.get('ip') == ip]
    if not inventory:
        return {'error': 'the Sentinel reported nothing for the address'}
    totals = persist_inventory(inventory, org_id=org_id, os_reliable=result.get('os_reliable') is not False)  # the Sentinel's own network, unless it says it sits behind Docker Desktop's
    ledger.record('nmap-fast', [ip], project.id, scan)  # what the check coverage of the host reads
    return {'hosts': len(inventory), **totals}


def _testssl(scan, project, domain, ip, org_id, dispatch):
    """A TLS audit of each TLS port nmap found open on ``ip``, through an internal Sentinel; findings and CVE evidence are stored by the
    same functions the external sweep uses."""
    from cveFeed import ledger, testssl_scan
    from startScan.models import IpAddress, Subdomain, open_ports
    sub = Subdomain.objects.filter(scan_history=scan, name=ip).select_related('target_domain').first()
    ip_obj = IpAddress.objects.filter(address=ip, org_id=org_id).first()
    ports = {p.number: p for p in open_ports(ip_obj)} if ip_obj else {}
    tested = failed = issues = 0
    for number, starttls in testssl_scan.tls_ports(ports):
        where = f'{ip}:{number}'
        result = dispatch(project, 'testssl', {'host': ip, 'ip': ip, 'port': number, 'starttls': starttls or ''}, host=ip, ips=[ip],
                          scan=scan, internal=True)
        evaluated = testssl_scan.evaluate((result or {}).get('items') or [], where) if result is not None else None
        if evaluated is None or not evaluated.tested:
            if result is not None:  # a Sentinel answered and the test did not complete: a failed run; no answer at all is not a run
                ledger.record(testssl_scan.FAILED_SERVICE, [where], project.id, scan)
            failed += 1
            continue
        testssl_scan.record_observations(project.id, domain.id, ip, number, evaluated, ip)
        testssl_scan.store(domain, ip, number, evaluated, where)
        if sub is not None:
            testssl_scan.run_for_host(sub)
        ledger.record(testssl_scan.SERVICE, [where], project.id, scan)
        tested += 1
        issues += len(evaluated.findings)
    out = {'tested': tested, 'failed': failed, 'issues': issues}
    if failed and not tested:
        out['error'] = 'no TLS test completed'
    return out


def _udp(scan, project, ip, org_id, dispatch):
    """The UDP exposure sweep of ``ip`` through an internal Sentinel; the raw nmap XML is parsed and stored by the external sweep's own functions."""
    from cveFeed import ledger, nmap_scan, udp_scan
    from startScan.models import IpAddress
    result = dispatch(project, 'nmap_udp', {'address': ip}, host=ip, ips=[ip], scan=scan, internal=True)
    if result is None:
        return {'error': 'no Sentinel inside the network answered'}
    host = next((h for h in nmap_scan.parse_xml(result.get('xml') or '') if h.get('ip') == ip), None)
    ip_obj = IpAddress.objects.filter(address=ip, org_id=org_id).first()
    if host is None or ip_obj is None:
        if ip_obj is not None:
            ledger.record(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip_obj)])
        return {'error': 'the Sentinel reported nothing for the address'}
    outcome = udp_scan.record_run(ip_obj, host)
    ledger.record(udp_scan.SERVICE, [udp_scan.asset_of(ip_obj)])
    return {'open': len(outcome['open']), 'changed': len(outcome['changed'])}


def run(scan_id, dispatch=None, nuclei_stream=None, provider=False, wp_runner=None):
    """Run the internal pipeline for one queued scan. ``dispatch`` replaces ``sentinel_dispatch.dispatch_or_none`` in tests, ``nuclei_stream``
    (``kind -> stream``) replaces the Sentinel nuclei streams, and ``provider`` (``False`` = the configured AI, ``None`` = none) the AI planner."""
    from agentapi import sentinel_dispatch
    from cveFeed import activity
    from cveFeed.discovery import FAILED, RUNNING, SUCCESS, _stage, mark_running
    from cveFeed.bounty_gate import Gate
    from cveFeed.exclusions import is_excluded
    from reNgine.tasks import persist_bbot_result
    from reNgine import bbot as bbot_lib
    from startScan.ip_rows import org_id_of_project
    from startScan.models import ScanActivity, ScanHistory
    from targetApp.target_types import sentinel_only_target
    dispatch = dispatch or sentinel_dispatch.dispatch_or_none
    mark_running(scan_id)
    scan = ScanHistory.objects.select_related('domain__project__org').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project
    ip = domain.name
    if scan.scan_status == 3:
        return {'scan_id': scan_id, 'status': 'aborted'}
    if not sentinel_only_target(ip, project.id):  # the range was removed (or the operator now allows private targets) since it was queued
        message = f'{ip} is no longer inside an internal range of this project; nothing was scanned'
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message)
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    if is_excluded(project.id, ip):
        message = f'{ip} is excluded for this organization and is not scanned'
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message)
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    why = Gate().refusal(project.id, ip, unattended=scan.initiated_by_id is None)
    if why:
        message = f'{ip} is not scanned: {why}'
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message[:290])
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    running = activity.log('run_check', f'Internal scan of {ip}: a Sentinel inside the network does the scanning, never this server',
                           project=project.id, status='running', scan_id=scan.id)
    org_id = org_id_of_project(project.id)
    persist_bbot_result(bbot_lib.BbotResult(subdomains={ip}, resolutions={(ip, ip)}),
                        ctx={'scan_history_id': scan.id, 'domain_id': domain.id, 'subdomain_id': None, 'subscan_id': None})
    from cveFeed import nuclei_scan, wpscan_scan
    from targetApp.target_types import internal_scope
    with internal_scope():
        nmap = _stage(scan, 'nmap scan (internal Sentinel)', 'nmap_scan', lambda: _nmap(scan, project, ip, org_id, dispatch), fallback={'hosts': 0})
        if not nmap.get('error'):
            def stream(kind):
                return nuclei_stream(kind) if nuclei_stream else sentinel_dispatch.wrap_nuclei_stream(scan, kind, internal=True)
            _stage(scan, 'TLS audit (internal Sentinel)', 'internal_testssl', lambda: _testssl(scan, project, domain, ip, org_id, dispatch), fallback={'tested': 0})
            _stage(scan, 'UDP exposure sweep (internal Sentinel)', 'internal_udp_scan', lambda: _udp(scan, project, ip, org_id, dispatch), fallback={'open': 0})
            _stage(scan, 'Nuclei HTTP and technology pass (internal Sentinel)', 'nuclei_light_scan',
                   lambda: nuclei_scan.run_light_nuclei(scan.id, stream=stream('nuclei_light')), fallback={'targets': 0, 'techs': {}})
            _stage(scan, 'WPScan of WordPress sites (internal Sentinel)', 'internal_wpscan',
                   lambda: wpscan_scan.run_wpscan(scan.id, runner=wp_runner, internal=True), fallback={'sites': 0})
            from cveFeed.tasks import correlate_cves
            _stage(scan, 'CVE correlation', 'cve_correlation', lambda: correlate_cves(scan_history_id=scan.id),
                   fallback={'subdomains': 0, 'matches': 0})
            _stage(scan, 'Nuclei targeted pass (internal Sentinel)', 'nuclei_targeted_scan',
                   lambda: nuclei_scan.run_targeted_nuclei(scan.id, stream=stream('nuclei_targeted'), provider=provider), fallback={'targets': 0})
    failed_names = list(ScanActivity.objects.filter(scan_of=scan, status=FAILED).order_by('id').values_list('name', flat=True))
    status = FAILED if nmap.get('error') else SUCCESS
    error = nmap.get('error') or (('Failed stages: ' + ', '.join(failed_names)) if failed_names else '')
    ScanHistory.objects.filter(pk=scan_id).update(scan_status=status, stop_scan_date=timezone.now(), error_message=(error or '')[:290] or None)
    activity.settle(running, 'done' if status == SUCCESS else 'failed',
                    message=(f'Internal scan of {ip} finished: {nmap.get("ports", 0)} service(s) found{("; " + error) if error else ""}' if status == SUCCESS
                             else f'Internal scan of {ip} failed: {error}'))
    return {'scan_id': scan_id, 'status': status, 'error': error or '', 'failed_stages': failed_names, 'nmap': nmap}
