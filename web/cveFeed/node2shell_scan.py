"""Detection for CVE-2026-111497 ("node2shell"), a Node.js HTTP request-handling vulnerability. Uses Assetnote's
own read-only detector (``cveFeed.vendor.node2shell``, MIT licensed, vendored with its own provenance header,
https://github.com/assetnote/node2shell-scanner), run only against a host a technology row or a route fingerprint
already names Node.js or Express.

This check's network footprint is much larger than every other check in the pipeline: alongside a few small
requests it uploads one Brotli-encoded body, about 23 MB on the wire, to see whether the target's HTTP handling
reaches the same response class for it as for an ordinary small one. It never executes a command and never sends
a credential; a target is reported vulnerable only when two earlier control requests first establish distinct,
stable response classes and the large body still lands in the valid one. Because of that footprint this check is
opt-in (``CVENGINE_NODE2SHELL=1``), bounded per scan (``CVENGINE_NODE2SHELL_MAX_HOSTS``), and run at most once per
host per window (``CVENGINE_TTL_NODE2SHELL``, the service ledger), the same shape as ``cveFeed.wpscan_scan``.
"""
import logging
import os
import re

logger = logging.getLogger(__name__)

SERVICE = 'node2shell'
CVE_ID = 'CVE-2026-111497'
DEFAULT_TIMEOUT = 90
DEFAULT_MAX_HOSTS = 5
NODE_NAME_RE = re.compile(r'^(express|node\.?js)', re.I)


def enabled():
    return os.environ.get('CVENGINE_NODE2SHELL', '0').strip().lower() not in ('0', 'false', 'no', 'off')


def check_timeout():
    try:
        return max(10, int(os.environ.get('CVENGINE_NODE2SHELL_TIMEOUT', DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def max_hosts():
    try:
        return max(1, int(os.environ.get('CVENGINE_NODE2SHELL_MAX_HOSTS', DEFAULT_MAX_HOSTS)))
    except ValueError:
        return DEFAULT_MAX_HOSTS


def node_sites(scan):
    """``[(Subdomain, base URL)]`` for this scan's hosts a technology row or a route fingerprint already names
    Node.js or Express, excluded and blocked names already removed (the same target list every stage uses)."""
    from cveFeed.models import RouteAuth
    from cveFeed.nuclei_scan import scan_targets
    from startScan.models import Subdomain
    allowed, _ips, _ports = scan_targets(scan)
    subs = {s.name: s for s in Subdomain.objects.filter(scan_history=scan, name__in=allowed)}
    if not subs:
        return []
    names = {n for n, s in subs.items() if any(NODE_NAME_RE.match(t.name or '') for t in s.technologies.all())}
    routes = RouteAuth.objects.filter(project_id=scan.domain.project_id, host__in=list(subs), retired_at__isnull=True)
    for host, evidence in routes.values_list('host', 'evidence'):
        found = [str(n) for n in (evidence or {}).get('fingerprint_names') or []]
        if any(NODE_NAME_RE.match(n) for n in found):
            names.add(host)
    sites = []
    for name in sorted(names):
        sub = subs[name]
        base = (sub.http_url or f'https://{name}').split('?')[0]
        sites.append((sub, base if base.startswith(('http://', 'https://')) else f'https://{name}'))
    return sites


def run_check(url, timeout_s=None):
    """Call the vendored detector for one URL. Returns its result dict; never raises (the vendored module already
    catches its own network and protocol errors into an INCONCLUSIVE result, and anything else is folded the
    same way here, as a last resort)."""
    from cveFeed.vendor import node2shell
    try:
        return node2shell.check_vulnerability(url, timeout=timeout_s or check_timeout(), verify_ssl=True)
    except Exception as exc:  # noqa: BLE001 - a bad target must never interrupt the scan
        logger.warning('node2shell check failed for %s: %s', url, exc)
        return {'vulnerable': None, 'verdict': 'ERROR', 'error': str(exc)[:200], 'reason': str(exc)[:200]}


def run_for_scan(scan_id, checker=run_check, force=False):
    """Run the node2shell check against every Node.js or Express host this scan found, bounded per scan and
    TTL-gated. A critical finding is raised only when the detector's own verdict is VULNERABLE. Returns a summary
    dict; never raises."""
    from cveFeed import activity, ledger
    from startScan.models import ScanHistory
    if not enabled():
        return {'checked': 0, 'skipped': 'disabled'}
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project, scan.domain
    sites = node_sites(scan)
    if not sites:
        return {'checked': 0}
    covered = set() if force else ledger.fresh(SERVICE, [s.name for s, _ in sites], project.id)
    todo = [(s, u) for s, u in sites if s.name not in covered][:max_hosts()]
    if not todo:
        return {'checked': len(sites), 'tested': 0, 'reused': len(covered)}
    running = activity.log('run_check', f'Checking {len(todo)} Node.js host(s) of {domain.name} for {CVE_ID} '
                           '(about 23 MB uploaded per host; read-only, no credential sent)',
                           project=project, status='running', scan_id=scan.id)
    vulnerable = errors = 0
    for sub, url in todo:
        result = checker(url)
        ledger.record(SERVICE, [sub.name], project.id, scan)
        if result.get('vulnerable') is True:
            vulnerable += 1
            _record_finding(scan, sub, url, result)
        elif result.get('vulnerable') is None:
            errors += 1
    activity.settle(running, 'done', message=(
        f'node2shell check for {domain.name}: {vulnerable} of {len(todo)} host(s) vulnerable to {CVE_ID}'
        + (f', {errors} inconclusive' if errors else '')))
    return {'checked': len(sites), 'tested': len(todo), 'vulnerable': vulnerable, 'errors': errors, 'reused': len(covered)}


def _record_finding(scan, sub, url, result):
    from reNgine.tasks import save_vulnerability
    evidence = (result.get('response') or '')[:2048]
    save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=url, name=f'{CVE_ID} (node2shell)',
        severity=4, source='node2shell', template_id='node2shell-cve-2026-111497', type='rce', cve_ids=[CVE_ID],
        description=(f"A read-only, no-exploitation probe (Assetnote's node2shell detector) found this host "
                     f'vulnerable to {CVE_ID}: {result.get("reason", "")}'),
        remediation='Update Node.js to a version that fixes this issue, and restart the affected service.',
        extracted_results=[evidence] if evidence else [], tags=['node2shell', CVE_ID.lower()])
