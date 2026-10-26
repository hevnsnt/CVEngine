"""WPScan for the WordPress sites CVEngine already found.

A host is scanned only after an earlier stage fingerprinted it as WordPress (a technology row or a route fingerprint), never
blind. WPScan runs read-only (version, plugin, theme, config-backup and database-export detection, and listing the first
author ids; no password guessing). Its known-vulnerability data comes from the wpscan.com API, so the token is a project or
organization API key (Settings, API keys, WPScan), handed to WPScan in its environment and never on the command line or in a
log. Without a token WPScan still reports versions, plugins and exposures, only without vulnerability data.

Results become scanner findings (source ``wpscan``, with CVE ids where WPScan names them) and technology rows, so they reach
the Findings view and CVE correlation like every other finding. A site is scanned at most once a week (the service ledger).

WPScan's own licence allows testing your own systems and penetration testing, and requires a commercial licence for managed or
hosted services (see docs/CONFIGURATION.md).
"""
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

WPSCAN_BIN = 'wpscan'
SERVICE = 'wpscan'
DEFAULT_TIMEOUT = 15 * 60
DEFAULT_MAX_SITES = 10
ENUMERATE = 'vp,vt,cb,dbe,u1-10'
MAX_OUTPUT = 8 * 1024 * 1024
FLAGS = ['--format', 'json', '--no-banner', '--random-user-agent', '--max-threads', '5', '--request-timeout', '30',
         '--connect-timeout', '15', '--detection-mode', 'mixed', '--disable-tls-checks', '--enumerate', ENUMERATE]
OK_EXIT_CODES = (0, 5)  # 5 means "vulnerabilities found"
# severity of WPScan's "interesting findings" by their type; unlisted types are informational
INTERESTING_SEVERITY = {'config_backup': 3, 'db_export': 3, 'debug_log': 2, 'upload_directory_listing': 1, 'multisite': 0}
CVE_PART = re.compile(r'^(?:CVE-)?(\d{4}-\d{4,})$', re.I)


def wpscan_timeout():
    try:
        return max(60, int(os.environ.get('CVENGINE_WPSCAN_TIMEOUT', DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def max_sites():
    try:
        return max(1, int(os.environ.get('CVENGINE_WPSCAN_MAX_SITES', DEFAULT_MAX_SITES)))
    except ValueError:
        return DEFAULT_MAX_SITES


def installed():
    return shutil.which(WPSCAN_BIN) is not None


def api_token(project):
    """The project's (or its organization's) WPScan token, or ''."""
    from cveFeed.api_credentials import resolve_for_project
    return (resolve_for_project(project).get('wpscan') or {}).get('api_key') or ''


def severity_from_score(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return 2  # WPScan did not rate it: medium
    return 4 if score >= 9 else 3 if score >= 7 else 2 if score >= 4 else 1


def wordpress_sites(scan):
    """``[(Subdomain, base URL)]`` for this scan's hosts that were fingerprinted as WordPress, excluded and blocked names removed."""
    from cveFeed.models import RouteAuth
    from startScan.models import Subdomain
    allowed, _ips, _ports = _scan_targets(scan)
    subs = {s.name: s for s in Subdomain.objects.filter(scan_history=scan, name__in=allowed)}
    names = {n for n, s in subs.items() if s.technologies.filter(name__istartswith='wordpress').exists()}
    routes = RouteAuth.objects.filter(project_id=scan.domain.project_id, host__in=list(subs), retired_at__isnull=True)
    for host, evidence in routes.values_list('host', 'evidence'):
        found = [str(n) for n in (evidence or {}).get('fingerprint_names') or []]
        if any(n.lower().startswith('wordpress') for n in found):
            names.add(host)
    sites = []
    for name in sorted(names):
        sub = subs[name]
        base = (sub.http_url or f'https://{name}').split('?')[0]
        sites.append((sub, base if base.startswith(('http://', 'https://')) else f'https://{name}'))
    return sites


def _scan_targets(scan):
    from cveFeed.nuclei_scan import scan_targets
    return scan_targets(scan)


def run_wpscan_process(url, token, timeout=None):
    """Run WPScan on one site and return its parsed JSON report. The token travels in the environment. Raises on a timeout, a
    bad exit code or unreadable output; an unreachable-or-not-WordPress site (exit 4) is a ``ValueError`` the caller treats as
    "nothing to report"."""
    env = {k: v for k, v in os.environ.items() if k != 'WPSCAN_API_TOKEN'}
    if token:
        env['WPSCAN_API_TOKEN'] = token
    with tempfile.TemporaryDirectory(prefix='wpscan-') as tmp:
        out = os.path.join(tmp, 'report.json')
        proc = subprocess.run([WPSCAN_BIN, '--url', url, *FLAGS, '-o', out], env=env, timeout=timeout or wpscan_timeout(),
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if proc.returncode == 4:
            raise ValueError('not running WordPress, or not reachable')
        if proc.returncode not in OK_EXIT_CODES:
            raise RuntimeError(_redact((proc.stderr or '').strip().splitlines()[-1] if proc.stderr else f'exit {proc.returncode}', token))
        if not os.path.exists(out) or os.path.getsize(out) > MAX_OUTPUT:
            raise RuntimeError('WPScan wrote no usable report')
        with open(out, encoding='utf-8', errors='replace') as f:
            return json.load(f)


def _redact(text, token):
    return (text or '').replace(token, '***')[:200] if token else (text or '')[:200]


def _cves(references):
    out = []
    for part in (references or {}).get('cve') or []:
        match = CVE_PART.match(str(part).strip())
        if match:
            out.append('CVE-' + match.group(1))
    return out


def _urls(references):
    return [u for u in (references or {}).get('url') or [] if isinstance(u, str)][:10]


def _vuln_rows(report, base):
    """``[(name, severity, description, cves, references, component)]`` from one WPScan report: the vulnerabilities of the core,
    the main theme, every plugin and theme, plus exposures it listed."""
    rows = []

    def add(component, version, items):
        label = f'{component} {version}'.strip()
        for v in items or []:
            cvss = v.get('cvss') or {}
            fixed = v.get('fixed_in')
            note = f'Fixed in {fixed}.' if fixed else 'No fixed version is listed.'
            rows.append((f'{label}: {v.get("title", "known vulnerability")}'[:500], severity_from_score(cvss.get('score')),
                         f'{note} Reported by WPScan for {label}.', _cves(v.get('references')), _urls(v.get('references')), component))
    version = report.get('version') or {}
    add('WordPress', version.get('number') or '', version.get('vulnerabilities'))
    theme = report.get('main_theme') or {}
    add(f'WordPress theme {theme.get("slug", "")}', (theme.get('version') or {}).get('number') or '', theme.get('vulnerabilities'))
    for kind, items in (('plugin', report.get('plugins')), ('theme', report.get('themes'))):
        for slug, info in (items or {}).items():
            add(f'WordPress {kind} {slug}', (info.get('version') or {}).get('number') or '', info.get('vulnerabilities'))
    for item in report.get('interesting_findings') or []:
        kind = str(item.get('type') or '')
        severity = INTERESTING_SEVERITY.get(kind)
        if severity is None:
            continue  # headers, robots, readme and the like are not findings
        rows.append((f'WordPress: {item.get("to_s", kind)}'[:500], severity, f'WPScan found {kind.replace("_", " ")} at {item.get("url", base)}.',
                     [], _urls(item.get('references')), kind))
    users = sorted((report.get('users') or {}))[:10]
    if users:
        rows.append(('WordPress usernames can be listed', 1, 'The author archive or REST API names these accounts: ' + ', '.join(users) + '.',
                     [], [], 'users'))
    return rows


def _technologies(report):
    """Technology names to attach to the host: the core version and each plugin and theme with a detected version."""
    names = []
    core = (report.get('version') or {}).get('number')
    if core:
        names.append(f'WordPress:{core}')
    for kind, items in (('plugin', report.get('plugins')), ('theme', report.get('themes'))):
        for slug, info in (items or {}).items():
            number = (info.get('version') or {}).get('number')
            if number:
                names.append(f'WordPress {kind} {slug}:{number}')
    theme = report.get('main_theme') or {}
    if theme.get('slug') and (theme.get('version') or {}).get('number'):
        names.append(f'WordPress theme {theme["slug"]}:{theme["version"]["number"]}')
    return sorted(set(names))[:60]


def persist_report(scan, sub, url, report):
    """Save one site's report; returns ``(new findings, technologies added)``."""
    from reNgine.tasks import save_vulnerability
    from startScan.ip_rows import get_or_create_first
    from startScan.models import Technology
    new = 0
    for name, severity, description, cves, refs, component in _vuln_rows(report, url):
        _vuln, created = save_vulnerability(
            target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=url, name=name, severity=severity,
            description=description, source='wpscan', template_id='wpscan:' + component[:150], type='wpscan', cve_ids=cves,
            references=refs, tags=['wordpress', 'wpscan'])
        new += int(created)
    added = 0
    for tech_name in _technologies(report):
        tech, _ = get_or_create_first(Technology, name=tech_name)
        if not sub.technologies.filter(pk=tech.pk).exists():
            sub.technologies.add(tech)
            added += 1
    return new, added


def remaining_requests(report):
    """WPScan API requests the token has left, from the report, or None when it does not say."""
    value = (report.get('vuln_api') or {}).get('requests_remaining')
    return value if isinstance(value, int) else None


def run_wpscan(scan_id, runner=None, force=False):
    """The pipeline stage: WPScan every WordPress site of the scan not scanned in the last week. Returns a summary dict;
    ``error`` is set only when every attempted site failed."""
    from cveFeed import activity, ledger
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project, scan.domain
    runner = runner or run_wpscan_process
    if runner is run_wpscan_process and not installed():
        return {'sites': 0, 'skipped': 'wpscan is not installed'}
    sites = wordpress_sites(scan)
    if not sites:
        return {'sites': 0}
    covered = set() if force else ledger.fresh(SERVICE, [s.name for s, _ in sites], project.id)
    todo = [(s, u) for s, u in sites if s.name not in covered][:max_sites()]
    if not todo:
        return {'sites': len(sites), 'scanned': 0, 'reused': len(covered)}
    token = api_token(project)
    running = activity.log('run_check', f'WPScan is checking {len(todo)} WordPress site(s) of {domain.name}'
                           + ('' if token else ' (no API token: versions and exposures only)'),
                           project=project, status='running', scan_id=scan.id)
    findings = added = 0
    errors, scanned = [], []
    for sub, url in todo:
        try:
            report = runner(url, token)
        except ValueError as exc:  # not WordPress after all: nothing to report, and no reason to ask again for a week
            ledger.record(SERVICE, [sub.name], project.id, scan)
            errors.append(f'{sub.name}: {exc}')
            continue
        except Exception as exc:  # noqa: BLE001 - one site failing must not stop the rest
            logger.warning('wpscan failed for %s: %s', sub.name, _redact(str(exc), token))
            ledger.record(SERVICE, [sub.name], project.id, scan, 'failed')
            errors.append(f'{sub.name}: {_redact(str(exc), token)}')
            continue
        new, techs = persist_report(scan, sub, url, report)
        findings, added = findings + new, added + techs
        ledger.record(SERVICE, [sub.name], project.id, scan)
        scanned.append(sub.name)
        left = remaining_requests(report)
        if left is not None and left <= 0:
            errors.append('the WPScan API token has no requests left today; the remaining sites wait')
            break
    summary = {'sites': len(sites), 'scanned': len(scanned), 'findings': findings, 'technologies': added, 'reused': len(covered)}
    failed_all = bool(errors) and not scanned and all('not running WordPress' not in e for e in errors)
    message = (f'WPScan finished {domain.name}: {len(scanned)} site(s), {findings} new finding(s)'
               + (f'; {len(errors)} problem(s): {errors[0]}' if errors else ''))
    activity.settle(running, 'failed' if failed_all else 'done', message=message, **summary)
    if failed_all:
        summary['error'] = errors[0][:290]
    return summary
