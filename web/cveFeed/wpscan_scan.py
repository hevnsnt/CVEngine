"""WPScan as the primary WordPress assessment.

Every host that shows any sign of WordPress is checked: a technology tag, a header or page signature, the login page, the REST API,
the web archive's memory of the host, plugin or theme paths in crawled URLs, an earlier probe. A cheap read-only probe
(``cveFeed.probes``, probe ``wordpress-detect``) confirms the signature with browser-like requests, follows apex and www redirects, and
records an edge that challenged the scanner instead of concluding "not WordPress". Then WPScan runs on every candidate and on every name of
a grouped host that probes positive. Nothing is skipped silently: each candidate ends in a recorded state on the host (``state_of``).

WPScan runs read-only (version, plugins, themes, config backups, database exports, timthumbs and the first author ids; no password
guessing). Its vulnerability data comes from the wpscan.com API, so the token is a project or organization API key (Settings, API keys,
WPScan), given to WPScan in its environment and never on the command line or in a log. The free plan allows 25 requests a day: when the
budget is spent WPScan still runs without the token (versions, plugins, themes, exposures and users come from the scan itself) and the
host says its vulnerability data was not checked.

Results become findings (source ``wpscan``, with CVE ids where WPScan names them and what to do about them), technology rows and, for the
core, every plugin and every theme, versioned sightings (``ProbeObservation`` rows) that ``cveFeed.wp_correlation`` correlates with CVEs by
exact plugin identity.

WPScan's own licence allows testing your own systems and penetration testing, and requires a commercial licence for managed or hosted
services (see docs/CONFIGURATION.md)."""
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

WPSCAN_BIN = 'wpscan'
SERVICE = 'wpscan'
PARTIAL_SERVICE = 'wpscan-partial'  # a run that finished but could not check vulnerability data: asked again soon
PROBE_SERVICE = 'wp-probe'
DEFAULT_TIMEOUT = 15 * 60
DEFAULT_MAX_SITES = 20
# WPScan 4: plugins are no longer enumerated by default, so the tokens are explicit. ap and at list the plugins and themes the site's own pages
# reference (with versions, no API token needed); cb config backups; dbe database exports; u1-10 the first author ids. vp and vt only report
# vulnerable ones and need the API, so they cannot give versions without a token. tt (timthumbs, 2,568 requests alone) is opt-in
# (CVENGINE_WPSCAN_TIMTHUMBS=1). Plugin and theme detection are set to passive explicitly: in WPScan 4 they fall back to the global
# --detection-mode, and mixed with "ap" asks for every plugin and theme slug WPScan knows (about 170,000 requests), which no run survives.
ENUMERATE = 'ap,at,cb,dbe,u1-10'
MAX_OUTPUT = 8 * 1024 * 1024
THROTTLE_MS = 100  # --throttle waits between requests (and runs WPScan on one thread): gentle on the site and on its WAF
DEFAULT_STAGE_SECONDS = 60 * 60
# The thorough pass: plugin and theme detection in mixed mode asks the site for every plugin and theme slug WPScan knows (about 170,000
# requests), which finds the ones a page never links. It takes hours, so it is never part of the scan: a one-site-at-a-time background task
# (``run_thorough``) with its own long timeout, started after the quick pass, resumable and never blocking correlation or triage.
THOROUGH_PROBE = 'wpscan-thorough'
THOROUGH_SERVICE = 'wpscan-thorough'
THOROUGH_QUEUE = 'wpscan_queue'
DEFAULT_THOROUGH_TIMEOUT = 12 * 60 * 60
THOROUGH_ENUMERATE = 'ap,at,tt'
THOROUGH_STATES = ('pending', 'running', 'done', 'partial', 'blocked', 'failed')


def timthumbs():
    return os.environ.get('CVENGINE_WPSCAN_TIMTHUMBS', '').strip().lower() in ('1', 'true', 'yes', 'on')


def stage_seconds():
    try:
        return max(60, int(os.environ.get('CVENGINE_WPSCAN_STAGE_SECONDS', DEFAULT_STAGE_SECONDS)))
    except ValueError:
        return DEFAULT_STAGE_SECONDS


def thorough_timeout():
    try:
        return max(600, int(os.environ.get('CVENGINE_WPSCAN_THOROUGH_TIMEOUT', DEFAULT_THOROUGH_TIMEOUT)))
    except ValueError:
        return DEFAULT_THOROUGH_TIMEOUT


def wpscan_args(timeout, thorough=False):
    """The WPScan options for one site. ``--max-scan-duration`` ends the scan 30 seconds before the process would be killed, so a slow site
    still gives a partial report instead of nothing. The quick pass reads plugins and themes passively; the thorough pass asks for every one
    WPScan knows (mixed detection) and the timthumbs."""
    mode = 'mixed' if thorough else 'passive'
    enumerate_ = THOROUGH_ENUMERATE if thorough else ENUMERATE + (',tt' if timthumbs() else '')
    return ['--format', 'json', '--no-banner', '--random-user-agent', '--throttle', str(THROTTLE_MS), '--request-timeout', '30',
            '--connect-timeout', '15', '--detection-mode', 'mixed', '--plugins-detection', mode, '--themes-detection', mode,
            '--disable-tls-checks', '--enumerate', enumerate_, '--max-scan-duration', str(max(30, timeout - 30))]


OK_EXIT_CODES = (0, 5)  # 5 means "vulnerabilities found"; 1 bad option, 2 interrupted, 3 unexpected exception, 4 the scan did not finish
# severity of WPScan's "interesting findings" by their type; unlisted types are informational
INTERESTING_SEVERITY = {'config_backup': 3, 'db_export': 3, 'debug_log': 2, 'upload_directory_listing': 1, 'multisite': 0, 'xmlrpc': 1,
                        'registration': 1, 'search_replace_db2': 3, 'full_path_disclosure': 1}
CVE_PART = re.compile(r'^(?:CVE-)?(\d{4}-\d{4,})$', re.I)
NOT_WORDPRESS = re.compile(r'not seem to be running wordpress', re.I)
BLOCKED = re.compile(r'\b(?:403|429|503|forbidden|blocked|waf|firewall|captcha|challenge|access denied|too many requests)\b', re.I)
VULN_DATA = {'checked': 'checked', 'no_token': 'not checked: no API token', 'exhausted': 'not checked: API token budget exhausted',
             'error': 'not checked: the WPScan API returned an error'}
BUDGET_ERROR = re.compile(r'limit|quota|exhaust|too many|requests', re.I)
# any of these in a technology name says the host runs (or is hosted for) WordPress
WP_TECH = re.compile(r'^(wordpress|woocommerce|wp ?engine|elementor|wpml|yoast|wp-)', re.I)
WP_URL = r'/wp-(content|includes|json|login\.php|admin)|/xmlrpc\.php'
STATES = ('not_wordpress', 'candidate', 'detected', 'scanned', 'blocked', 'failed', 'waiting', 'unavailable')


class NotWordPress(ValueError):
    """WPScan could reach the site and it is not WordPress."""


class Blocked(RuntimeError):
    """WPScan was refused or challenged by an edge (a 403, 429 or 503, a captcha or a challenge page)."""


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


def max_probe_hosts():
    try:
        return max(1, int(os.environ.get('CVENGINE_WP_PROBE_MAX_HOSTS', 100)))
    except ValueError:
        return 100


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


# ----------------------------------------------------------------------------- candidates: any sign of WordPress

def _scan_targets(scan):
    from cveFeed.nuclei_scan import scan_targets
    return scan_targets(scan)


def candidate_signals(scan, subs):
    """``{host name: [signal, ...]}`` for the scan's hosts that show any sign of WordPress: a live technology tag, a route check fingerprint or
    wp-login page, a crawled URL under wp-content, a title or label, the web archive's memory of the host, an earlier positive probe or scan."""
    from cveFeed.models import HostArchive, HostLabel, ProbeObservation, RouteAuth
    from startScan.models import EndPoint
    project = scan.domain.project_id
    names = {s.name.lower() for s in subs}
    found = {}

    def add(host, signal):
        host = (host or '').lower()
        if host in names and signal not in found.setdefault(host, []):
            found[host].append(signal)
    for sub in subs:
        if any(WP_TECH.match(t.name or '') for t in sub.technologies.all()):
            add(sub.name, 'technology tag')
        if re.search(r'wordpress', sub.page_title or '', re.I):
            add(sub.name, 'page title')
        if re.search(r'wp ?engine', sub.webserver or '', re.I):
            add(sub.name, 'server header')
    for host, path, state, evidence in RouteAuth.objects.filter(project_id=project, host__in=list(names), retired_at__isnull=True).values_list(
            'host', 'path', 'auth_state', 'evidence'):
        if any(str(n).lower().startswith('wordpress') for n in (evidence or {}).get('fingerprint_names') or []):
            add(host, 'front page fingerprint')
        if path.startswith('/wp-login') and state == 'login':  # a login form at wp-login.php; a catch-all that answers 200 to every path is not one
            add(host, f'route {path}')
    for host, tech in HostArchive.objects.filter(project_id=project, host__in=list(names)).values_list('host', 'technologies'):
        if any(str(k).lower().startswith('wordpress') for k in (tech or {})):
            add(host, 'web archive')
    for host in EndPoint.objects.filter(scan_history=scan, http_url__iregex=WP_URL).values_list('subdomain__name', flat=True)[:5000]:
        add(host, 'crawled WordPress path')
    for host in HostLabel.objects.filter(project_id=project, host__in=list(names), label__icontains='wordpress').values_list('host', flat=True):
        add(host, 'host label')
    for host, probe in ProbeObservation.objects.filter(project_id=project, host__in=list(names), kind='wordpress', outcome='found',
                                                       probe__in=('wordpress-detect', 'wpscan')).values_list('host', 'probe'):
        add(host, 'earlier probe' if probe == 'wordpress-detect' else 'earlier scan')
    return found


def siblings_of(subs, hosts):
    """Names that share an address with a host in ``hosts`` (one site, several names: apex, www, stage): probed too, and scanned when they
    probe positive."""
    by_ip = {}
    for sub in subs:
        for ip in sub.ip_addresses.all():
            by_ip.setdefault(ip.address, set()).add(sub.name.lower())
    out = set()
    for names in by_ip.values():
        if names & hosts:
            out |= names
    return out - hosts


def wordpress_sites(scan):
    """``[(Subdomain, base URL)]`` for this scan's hosts with any sign of WordPress, excluded and blocked names removed."""
    from startScan.models import Subdomain
    allowed, _ips, _ports = _scan_targets(scan)
    subs = list(Subdomain.objects.filter(scan_history=scan, name__in=allowed).prefetch_related('technologies', 'ip_addresses'))
    found = candidate_signals(scan, subs)
    by_name = {s.name.lower(): s for s in subs}
    return [(by_name[name], _base_of(by_name[name])) for name in sorted(found)]


def _base_of(sub):
    base = (sub.http_url or f'https://{sub.name}').split('?')[0]
    return base if base.startswith(('http://', 'https://')) else f'https://{sub.name}'


# ----------------------------------------------------------------------------- running WPScan

def _read_report(path):
    if not os.path.exists(path) or os.path.getsize(path) > MAX_OUTPUT:
        return None
    with open(path, encoding='utf-8', errors='replace') as f:
        try:
            return json.load(f)
        except ValueError:
            return None


# what WPScan (a Ruby program that talks to an untrusted site) needs from the worker's environment; the database password, the field-encryption
# key and every other secret stay out of it
CHILD_ENV_KEYS = ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'GEM_HOME', 'GEM_PATH', 'BUNDLE_PATH', 'RUBYLIB', 'RUBYOPT', 'SSL_CERT_FILE',
                  'SSL_CERT_DIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy',
                  'https_proxy', 'no_proxy')


def child_env(token):
    env = {k: os.environ[k] for k in CHILD_ENV_KEYS if k in os.environ}
    if token:
        env['WPSCAN_API_TOKEN'] = token  # the environment is where WPScan reads its token: never the command line
    return env


def run_wpscan_process(url, token, timeout=None, thorough=False):
    """Run WPScan on one site and return its parsed JSON report (local execution only - see ``_classify`` for what a
    Sentinel-dispatched run shares with this). The token travels in the environment."""
    from targetApp.target_types import refuse_local
    refuse_local('WPScan')
    env = child_env(token)
    with tempfile.TemporaryDirectory(prefix='wpscan-') as tmp:
        out = os.path.join(tmp, 'report.json')
        limit = timeout or (thorough_timeout() if thorough else wpscan_timeout())
        proc = subprocess.run([WPSCAN_BIN, '--url', url, *wpscan_args(limit, thorough), '-o', out], env=env, timeout=limit,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        return _classify(_read_report(out), proc.returncode, proc.stderr, token)


def _classify(report, returncode, stderr='', token=''):
    """A wpscan process's outcome - its own exit code, its JSON report if it wrote one, and stderr if it did not - turned
    into a report dict, or raised as ``NotWordPress``/``Blocked``/``RuntimeError``. The one function either a local run
    (``run_wpscan_process``) or a Sentinel's reported ``{report, returncode, stderr_tail}`` (``agentapi.sentinel_dispatch.
    wrap_wpscan_runner``) goes through, so a dispatched site is classified exactly as a local one would be - no
    detection logic (what counts as "not WordPress" or "blocked") is duplicated on the Sentinel side.

    Exit code 4 means the scan did not finish; the report's ``scan_aborted`` text says why: ``NotWordPress`` (WPScan says
    the site is up and is not WordPress), ``Blocked`` (an edge refused or challenged WPScan) or a ``RuntimeError``
    (including no report at all). A report that has results despite the abort is returned, marked ``cvengine_partial``."""
    if returncode == 4:
        if report is None:
            raise RuntimeError('WPScan did not finish and wrote no report')  # not "not WordPress": nothing was read
        reason = str(report.get('scan_aborted') or '')
        if any(report.get(k) for k in ('version', 'plugins', 'themes', 'interesting_findings')):
            return {**report, 'cvengine_partial': reason[:120] or 'the scan did not finish'}  # what it read before it stopped
        if NOT_WORDPRESS.search(reason):
            raise NotWordPress('WPScan says the site is up and is not running WordPress')
        if BLOCKED.search(reason):
            raise Blocked(_redact(reason, token))
        raise RuntimeError(_redact(reason or 'the scan did not finish', token))
    if returncode not in OK_EXIT_CODES:
        raise RuntimeError(_redact((stderr or '').strip().splitlines()[-1] if stderr else f'exit {returncode}', token))
    if report is None:
        raise RuntimeError('WPScan wrote no usable report')
    return report


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
    """``[(name, severity, description, cves, references, component)]`` from one WPScan report: the vulnerabilities of the core, the main
    theme, every plugin and theme, what WPScan found exposed, users, and components it calls outdated. Each says what to do."""
    rows = []

    def add(component, version, items):
        label = f'{component} {version}'.strip()
        for v in items or []:
            cvss = v.get('cvss') or {}
            fixed = v.get('fixed_in')
            note = f'Fixed in {fixed}. Remediation: update {component} to {fixed} or later.' if fixed else (
                'No fixed version is listed. Remediation: remove or replace the component, or restrict access to it.')
            rows.append((f'{label}: {v.get("title", "known vulnerability")}'[:500], severity_from_score(cvss.get('score')),
                         f'{note} Reported by WPScan for {label}.', _cves(v.get('references')), _urls(v.get('references')), component))

    def outdated(component, info):
        latest = info.get('latest_version')
        version = (info.get('version') or {}).get('number')
        if info.get('outdated') and latest and version:
            rows.append((f'{component} {version} is outdated (latest {latest})'[:500], 1,
                         f'WPScan reports {component} {version}; the latest release is {latest}. Remediation: update {component}.',
                         [], [], f'{component} outdated'))
    version = report.get('version') or {}
    add('WordPress', version.get('number') or '', version.get('vulnerabilities'))
    if version.get('status') == 'outdated' and version.get('number'):
        rows.append((f'WordPress {version["number"]} is outdated'[:500], 1,
                     f'WPScan reports WordPress {version["number"]} as outdated. Remediation: update WordPress.', [], [], 'WordPress outdated'))
    theme = report.get('main_theme') or {}
    add(f'WordPress theme {theme.get("slug", "")}', (theme.get('version') or {}).get('number') or '', theme.get('vulnerabilities'))
    if theme.get('slug'):
        outdated(f'WordPress theme {theme["slug"]}', theme)
    for kind, items in (('plugin', report.get('plugins')), ('theme', report.get('themes'))):
        for slug, info in (items or {}).items():
            add(f'WordPress {kind} {slug}', (info.get('version') or {}).get('number') or '', info.get('vulnerabilities'))
            outdated(f'WordPress {kind} {slug}', info)
    for item in report.get('interesting_findings') or []:
        kind = str(item.get('type') or '')
        severity = INTERESTING_SEVERITY.get(kind)
        if severity is None:
            continue  # headers, robots, readme and the like are not findings
        rows.append((f'WordPress: {item.get("to_s", kind)}'[:500], severity, f'WPScan found {kind.replace("_", " ")} at {item.get("url", base)}. '
                     'Remediation: remove or restrict access to it.', [], _urls(item.get('references')), kind))
    users = sorted((report.get('users') or {}))[:10]
    if users:
        rows.append(('WordPress usernames can be listed', 1, 'The author archive or REST API names these accounts: ' + ', '.join(users) +
                     '. Remediation: block author enumeration and the users REST route for anonymous requests.', [], [], 'users'))
    for name in sorted((report.get('timthumbs') or {}))[:5]:
        rows.append((f'WordPress: timthumb found at {name}'[:500], 3, 'An old TimThumb script is a well known remote file inclusion risk. '
                     'Remediation: delete it or update to a current release.', [], [], 'timthumb'))
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


def components(report):
    """``[(kind, slug, version, extra)]`` for the core, every plugin and every theme in a report (kind ``core``, ``wp-plugin``, ``wp-theme``);
    a component whose version WPScan could not read has an empty version. Slugs are cut to a safe alphabet."""
    out = [('core', 'WordPress', str((report.get('version') or {}).get('number') or ''), {'status': (report.get('version') or {}).get('status') or ''})]
    for kind, items in (('wp-plugin', report.get('plugins')), ('wp-theme', report.get('themes'))):
        for slug, info in list((items or {}).items())[:200]:
            slug = re.sub(r'[^A-Za-z0-9._-]', '', str(slug))[:80]
            if slug and isinstance(info, dict):
                out.append((kind, slug, str((info.get('version') or {}).get('number') or ''),
                            {'latest': str(info.get('latest_version') or '')[:30], 'outdated': bool(info.get('outdated')),
                             'found_by': str(info.get('found_by') or '')[:60]}))
    return out


def vulnerability_data(report, token):
    """Whether WPScan could check vulnerability data: ``checked``, ``no_token``, ``exhausted`` (the API says its limit is reached) or ``error``
    (any other API error: the token may be fine, so it is not given up)."""
    api = report.get('vuln_api') or {}
    if not token:
        return 'no_token'
    if isinstance(api.get('requests_remaining'), int) and api['requests_remaining'] < 0:
        return 'exhausted'
    if api.get('error'):
        return 'exhausted' if BUDGET_ERROR.search(str(api['error'])) else 'error'
    return 'checked'


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


README_TITLE = re.compile(r'^===\s*(.{1,120}?)\s*===', re.M)
MAX_TITLE_LOOKUPS = 8


def plugin_titles(base, report, allowed, get=None, sleep=None, project=None):
    """``{slug: title}`` read from each plugin's own readme.txt (``=== Plugin Name ===``, one small GET, at most MAX_TITLE_LOOKUPS per host): an
    advisory names a plugin by its title, and a slug alone often differs from it. A plugin whose readme cannot be read has no title."""
    import time

    from cveFeed import probes
    get = get or (lambda url: probes.fetch(url, allowed=allowed, project=project))
    out = {}
    for slug in sorted((report.get('plugins') or {}))[:MAX_TITLE_LOOKUPS]:
        slug = re.sub(r'[^A-Za-z0-9._-]', '', str(slug))[:80]
        if not slug:
            continue
        (sleep or time.sleep)(probes.REQUEST_GAP)
        try:
            found = README_TITLE.search((get(f'{base.rstrip("/")}/wp-content/plugins/{slug}/readme.txt') or {}).get('body') or '')
        except (OSError, ValueError):
            continue
        if found:
            out[slug] = re.sub(r'[^A-Za-z0-9 ._+&()-]', '', found.group(1))[:120]
    return out


def record_components(project_id, domain_id, host, report, titles=None):
    """Store the core, plugin and theme versions WPScan read as sightings the CVE correlation uses (with the plugin title when a readme gave
    one); a plugin that is no longer reported is removed. Returns the number of plugins and themes with a version."""
    from cveFeed.models import ProbeObservation
    titles = titles or {}
    now = timezone.now()
    keep = {'wpscan-plugin': set(), 'wpscan-theme': set()}
    versioned = 0
    for kind, slug, version, extra in components(report):
        probe = {'core': 'wpscan-core', 'wp-plugin': 'wpscan-plugin', 'wp-theme': 'wpscan-theme'}[kind]
        ProbeObservation.objects.update_or_create(
            project_id=project_id, host=host.lower(), probe=probe, port=0, kind='version' if kind == 'core' else kind, product=slug,
            defaults={'domain_id': domain_id, 'version': version[:100],
                      'outcome': 'found' if version else 'hidden', 'confidence': 0.9 if version else 0.5, 'source': 'wpscan',
                      'evidence': {**extra, **({'title': titles[slug]} if slug in titles else {})}, 'observed_at': now})
        if kind != 'core':
            keep[probe].add(slug)
            versioned += int(bool(version))
    for probe, slugs in keep.items():
        ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), probe=probe).exclude(product__in=slugs).delete()
    return versioned


def remaining_requests(report):
    """WPScan API requests the token has left, from the report, or None when it does not say."""
    value = (report.get('vuln_api') or {}).get('requests_remaining')
    return value if isinstance(value, int) else None


# ----------------------------------------------------------------------------- states: what happened to each candidate, on the host

def record_state(project_id, domain_id, host, state, reason='', **extra):
    """Record where a WordPress candidate stands (one of STATES) with the reason, so a host never silently has no WPScan result."""
    from cveFeed.models import ProbeObservation
    ProbeObservation.objects.update_or_create(
        project_id=project_id, host=host.lower(), probe='wpscan', port=0, kind='wordpress', product='WordPress',
        defaults={'domain_id': domain_id, 'version': str(extra.get('version') or '')[:100], 'variant': state,
                  'outcome': {'scanned': 'found', 'blocked': 'challenged', 'not_wordpress': 'absent'}.get(state, 'hidden'),
                  'confidence': 1.0 if state == 'scanned' else 0.0, 'source': 'wpscan',
                  'evidence': {'state': state, 'reason': str(reason)[:300], **{k: v for k, v in extra.items() if k != 'version'}},
                  'observed_at': timezone.now()})


def record_thorough(project_id, domain_id, host, state, reason='', **extra):
    """Record where the thorough pass stands on a host (one of THOROUGH_STATES), so the host page and the system status can say it."""
    from cveFeed.models import ProbeObservation
    ProbeObservation.objects.update_or_create(
        project_id=project_id, host=host.lower(), probe=THOROUGH_PROBE, port=0, kind='wordpress', product='WordPress',
        defaults={'domain_id': domain_id, 'variant': state, 'outcome': {'done': 'found', 'partial': 'found', 'blocked': 'challenged'}.get(state, 'hidden'),
                  'confidence': 1.0 if state == 'done' else 0.0, 'source': 'wpscan',
                  'evidence': {'state': state, 'reason': str(reason)[:300], **extra}, 'observed_at': timezone.now()})


def thorough_of(rows):
    """``{'state', 'reason', 'at', ...}`` for the thorough pass on one host, or None when it was never queued."""
    row = next((r for r in rows if r.probe == THOROUGH_PROBE), None)
    if row is None:
        return None
    evidence = row.evidence or {}
    return {'state': evidence.get('state') or 'failed', 'reason': evidence.get('reason', ''), 'at': row.observed_at.isoformat(),
            'plugins': evidence.get('plugins'), 'cut_short': evidence.get('cut_short', '')}


def state_of(rows):
    """``{'state', 'reason', 'detected_how', ...}`` for one host from its probe rows, or None when nothing suggests WordPress. The scan's own
    state wins; without one, a positive probe is "detected" and any other sign is "candidate"."""
    scan = next((r for r in rows if r.probe == 'wpscan'), None)
    detect_row = next((r for r in rows if r.probe == 'wordpress-detect'), None)
    base = {'detected_how': detect_row.source if detect_row and detect_row.outcome == 'found' else '',
            'probe': detect_row.outcome if detect_row else '', 'hint': ((detect_row.evidence or {}).get('hint') if detect_row else '') or '',
            'thorough': thorough_of(rows)}
    if scan is not None and (scan.evidence or {}).get('state') == 'not_wordpress' and base['detected_how']:
        return {**base, 'state': 'failed', 'reason': 'WPScan could not see WordPress, the probe did', 'scanned_at': scan.observed_at.isoformat()}
    if scan is not None:
        evidence = scan.evidence or {}
        return {**base, 'state': evidence.get('state') or 'failed', 'reason': evidence.get('reason', ''), 'scanned_at': scan.observed_at.isoformat(),
                'findings': evidence.get('findings'), 'vulnerability_data': evidence.get('vulnerability_data', ''),
                'next_scan': evidence.get('next_scan', ''), 'core': scan.version}
    if detect_row is not None:
        if detect_row.outcome == 'found':
            return {**base, 'state': 'detected', 'reason': 'WordPress was detected; WPScan has not run on it yet', 'core': detect_row.version}
        if detect_row.outcome == 'challenged':
            return {**base, 'state': 'blocked', 'reason': 'the edge challenged the scanner, so WordPress could not be confirmed'}
        if detect_row.outcome == 'absent':
            return {**base, 'state': 'not_wordpress', 'reason': 'the probe found no WordPress signature'}
    signals = next((r for r in rows if r.probe == 'wordpress-signals'), None)
    if signals is not None:
        return {**base, 'state': 'candidate', 'reason': 'signs of WordPress: ' + ', '.join((signals.evidence or {}).get('signals') or [])}
    return None


def record_signals(project_id, domain_id, host, signals):
    from cveFeed.models import ProbeObservation
    ProbeObservation.objects.update_or_create(
        project_id=project_id, host=host.lower(), probe='wordpress-signals', port=0, kind='wordpress', product='WordPress',
        defaults={'domain_id': domain_id, 'outcome': 'found', 'confidence': 0.5, 'source': (signals[0] if signals else '')[:48],
                  'evidence': {'signals': signals[:10]}, 'observed_at': timezone.now()})


def status_counts(project_ids=None):
    """``{'hosts', 'scanned', 'never_scanned', 'reasons': {state: n}}`` over the hosts with any WordPress state: the system status line."""
    from cveFeed.models import ProbeObservation
    qs = ProbeObservation.objects.filter(kind='wordpress', probe__in=('wpscan', 'wordpress-detect', 'wordpress-signals', THOROUGH_PROBE))
    if project_ids is not None:
        qs = qs.filter(project_id__in=project_ids)
    by_host = {}
    for row in qs.order_by('project_id', 'host'):
        by_host.setdefault((row.project_id, row.host), []).append(row)
    reasons, scanned, hosts, thorough = {}, 0, 0, {}
    for rows in by_host.values():
        state = state_of(rows)
        if state is None or state['state'] == 'not_wordpress':
            continue
        hosts += 1
        if state['state'] == 'scanned':
            scanned += 1
        else:
            reasons[state['state']] = reasons.get(state['state'], 0) + 1
        if state['thorough']:
            thorough[state['thorough']['state']] = thorough.get(state['thorough']['state'], 0) + 1
    return {'hosts': hosts, 'scanned': scanned, 'never_scanned': hosts - scanned, 'reasons': reasons, 'thorough': thorough}


# ----------------------------------------------------------------------------- the stage

def detect(scan, subs, candidates, probe_get=None, sleep=None, force=False):
    """Run the read-only WordPress probe on the candidates, their grouped names and, within the cap, the other web hosts; record each result.
    Returns ``{host: first observation}`` for the hosts probed now."""
    from cveFeed import ledger, probes, route_auth
    from reNgine import resources
    project, domain = scan.domain.project_id, scan.domain
    by_name = {s.name.lower(): s for s in subs}
    siblings = siblings_of(subs, set(candidates))
    web = {name for name, s in by_name.items() if route_auth.web_bases(s)}
    order = list(dict.fromkeys(sorted(set(candidates) & web) + sorted(siblings & web) + sorted(web)))[:max_probe_hosts()]
    covered = set() if force else ledger.fresh(PROBE_SERVICE, order, project)
    group = set(candidates) | siblings
    results = {}
    kwargs = {'get': probe_get, 'project': project} if probe_get else {'project': project}
    if sleep:
        kwargs['sleep'] = sleep
    for host in order:
        if host in covered:
            continue
        if resources.abort_requested(scan.id) or resources.global_pause_requested(fail_closed=True):
            break
        sub = by_name[host]
        allowed = (group & set(by_name)) | probes.allowed_names(sub)
        found = []
        for base in route_auth.web_bases(sub):
            try:
                found = probes.run_http_probe('wordpress-detect', base, allowed, **kwargs)
            except Exception as exc:  # noqa: BLE001 - one host failing never stops the rest
                logger.info('WordPress probe failed for %s: %s', host, type(exc).__name__)
                found = []
            if found and found[0]['outcome'] == 'found':
                break
        if not found:
            ledger.record(PROBE_SERVICE, [host], project, scan, 'failed')
            continue
        probes.record(project, domain.id, host, 'wordpress-detect', found)
        if found[0]['outcome'] == 'found':
            probes.apply_to_subdomain(sub, found)
        ledger.record(PROBE_SERVICE, [host], project, scan, 'failed' if found[0]['outcome'] == 'challenged' else 'done')
        results[host] = found[0]
    return results


def run_wpscan(scan_id, runner=None, force=False, probe_get=None, sleep=None):
    """The pipeline stage: probe for WordPress, then WPScan every host that shows any sign of it (and every grouped name that probes
    positive), positive probes first. Never silent: every candidate gets a recorded state. Returns a summary dict; ``error`` is set only when
    every attempted site failed."""
    from cveFeed import activity, ledger, probes, wp_correlation
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project_id, scan.domain
    real_runner = runner is None
    if real_runner:
        from agentapi import sentinel_dispatch
        runner = sentinel_dispatch.wrap_wpscan_runner(domain.project, scan=scan)
    allowed, _ips, _ports = _scan_targets(scan)
    subs = list(Subdomain.objects.filter(scan_history=scan, name__in=allowed).prefetch_related('technologies', 'ip_addresses__ports'))
    by_name = {s.name.lower(): s for s in subs}
    signals = candidate_signals(scan, subs)
    for host, found in signals.items():
        record_signals(project, domain.id, host, found)
    probed = detect(scan, subs, signals, probe_get=probe_get, sleep=sleep, force=force)
    positive = {h for h, o in probed.items() if o['outcome'] == 'found'}
    for host in sorted(h for h, o in probed.items() if o['outcome'] == 'absent' and h not in signals):
        record_state(project, domain.id, host, 'not_wordpress', 'the probe found no WordPress signature')
    wanted = sorted(set(signals) | positive, key=lambda h: (h not in positive, h))
    summary = {'candidates': len(signals), 'probed': len(probed), 'sites': len(wanted), 'scanned': 0, 'findings': 0, 'technologies': 0, 'reused': 0}
    wp_correlation.carry_forward(scan)
    if not wanted:
        return summary
    if runner is run_wpscan_process and not installed():
        for host in wanted:
            record_state(project, domain.id, host, 'unavailable', 'WPScan is not installed in this worker image')
        return {**summary, 'skipped': 'wpscan is not installed'}
    fresh = set() if force else ledger.fresh(SERVICE, wanted, project) | ledger.fresh(PARTIAL_SERVICE, wanted, project)
    summary['reused'] = len([h for h in wanted if h in fresh])
    history = ledger.last_run(SERVICE, wanted, project)
    epoch = timezone.now() - timedelta(days=36500)
    # due first (the fresh ones are not due), positive probes first, then the never-scanned and longest-waiting: a cap cuts only what waits
    todo = sorted((h for h in wanted if h not in fresh), key=lambda h: (h not in positive, history.get(ledger._norm(h)) or epoch, h))
    for host in todo[max_sites():]:
        record_state(project, domain.id, host, 'waiting', f'over the per-scan limit of {max_sites()} sites; it goes first next time')
    todo = todo[:max_sites()]
    if not todo:
        return summary
    token = api_token(domain.project)
    running = activity.log('run_check', f'WPScan is checking {len(todo)} WordPress site(s) of {domain.name}'
                           + ('' if token else ' (no API token: versions, plugins and exposures only)'),
                           project=project, status='running', scan_id=scan.id)
    errors, scanned, token_ok = [], [], bool(token)
    started = time.monotonic()
    for index, host in enumerate(todo):
        if time.monotonic() - started > stage_seconds():
            for waiting in todo[index:]:
                record_state(project, domain.id, waiting, 'waiting', 'the WPScan stage used its time budget; it goes first next time')
            break
        sub, url = by_name[host], _base_of(by_name[host])
        use = token if token_ok else ''
        try:
            report = _scan_site(runner, url, use, sub, project)
        except ValueError as exc:  # NotWordPress (or any ValueError a runner raises): WPScan says the site is up and is not WordPress
            if host in positive or _probe_positive(project, host):
                # the probe read a WordPress signature and WPScan did not: a WAF served WPScan a decoy page, or it was sent elsewhere. Not "not
                # WordPress": it stays a candidate that failed, and is asked again at the next scan
                ledger.record(SERVICE, [host], project, scan, 'failed')
                record_state(project, domain.id, host, 'failed', 'WPScan could not see WordPress, the probe did: the site may serve WPScan a '
                             'different page than it serves other visitors')
                errors.append(f'{host}: WPScan could not see WordPress')
                continue
            ledger.record(SERVICE, [host], project, scan)
            record_state(project, domain.id, host, 'not_wordpress', str(exc))
            errors.append(f'{host}: not running WordPress')
            continue
        except Blocked as exc:
            ledger.record(SERVICE, [host], project, scan, 'failed')
            record_state(project, domain.id, host, 'blocked', _hint(str(exc), token))
            errors.append(f'{host}: blocked by the edge')
            continue
        except Exception as exc:  # noqa: BLE001 - one site failing must not stop the rest
            logger.warning('wpscan failed for %s: %s', host, _redact(str(exc), token))
            ledger.record(SERVICE, [host], project, scan, 'failed')
            record_state(project, domain.id, host, 'failed', _redact(str(exc), token))
            activity.diagnostic(f'WPScan on {host}', _redact(str(exc), token))  # the raw text goes to the worker log, not the feed
            errors.append(f'{host}: WPScan failed (see the host page)')
            continue
        new, techs = persist_report(scan, sub, url, report)
        titles = plugin_titles(url, report, probes.allowed_names(sub), get=probe_get, sleep=sleep, project=project)
        versioned = record_components(project, domain.id, host, report, titles)
        data = 'exhausted' if token and not use else vulnerability_data(report, use)  # a site run after the budget ran out has no vulnerability data
        left = remaining_requests(report)
        if data == 'exhausted' or (left is not None and left <= 0):
            token_ok = False
        # a token that could not be used, an API error or a scan cut short: asked again soon. Without any token a run cannot be more complete
        partial = data in ('exhausted', 'error') or bool(report.get('cvengine_partial'))
        service = PARTIAL_SERVICE if partial else SERVICE
        ledger.record(service, [host], project, scan)
        record_state(project, domain.id, host, 'scanned', '', version=(report.get('version') or {}).get('number') or '',
                     findings=len(_vuln_rows(report, url)), new_findings=new, plugins=versioned, vulnerability_data=VULN_DATA[data],
                     **({'cut_short': report['cvengine_partial']} if report.get('cvengine_partial') else {}),
                     next_scan=(timezone.now() + timedelta(seconds=ledger.ttl(service))).date().isoformat())
        wp_correlation.run_for_host(sub)
        summary['findings'] += new
        summary['technologies'] += techs
        scanned.append(host)
    summary['scanned'] = len(scanned)
    summary['thorough_queued'] = queue_thorough(project, scanned, domain.id, dispatch=real_runner) if scanned else 0
    failed_all = bool(errors) and not scanned and all('not running WordPress' not in e for e in errors)
    message = (f'WPScan finished {domain.name}: {len(scanned)} site(s), {summary["findings"]} new finding(s)'
               + ('; the API token budget ran out, so later sites were scanned without vulnerability data' if token and not token_ok else '')
               + (f'; {len(errors)} problem(s): {errors[0]}' if errors else ''))
    activity.settle(running, 'failed' if failed_all else 'done', message=message, **summary)
    if failed_all:
        summary['error'] = errors[0][:290]
    return summary


# ----------------------------------------------------------------------------- the thorough pass

def queue_thorough(project_id, hosts, domain_id, dispatch=True):
    """Mark the hosts the quick pass scanned as waiting for the thorough pass (unless one finished inside its window) and start the
    background task. Returns how many were queued."""
    from cveFeed import ledger
    due = [h for h in hosts if h not in ledger.fresh(THOROUGH_SERVICE, [h], project_id)]
    for host in due:
        record_thorough(project_id, domain_id, host, 'pending', 'queued after the quick pass; it takes hours and runs in the background')
    if due and dispatch:
        try:
            from cveFeed.tasks import wpscan_thorough
            wpscan_thorough.apply_async(args=[project_id], queue=THOROUGH_QUEUE)
        except Exception:  # noqa: BLE001 - the hosts stay pending: the next scan's quick pass asks again
            logger.exception('could not start the thorough WPScan pass for project %s', project_id)
    return len(due)


def _pending_hosts(project_id):
    """The hosts waiting for the thorough pass, longest-waiting first: ``[(host, domain_id)]``."""
    from cveFeed.models import ProbeObservation
    rows = ProbeObservation.objects.filter(project_id=project_id, probe=THOROUGH_PROBE, variant__in=('pending', 'running')).order_by('observed_at', 'host')
    return [(r.host, r.domain_id) for r in rows]


def _latest_row(project_id, host):
    from startScan.models import Subdomain
    return Subdomain.objects.filter(target_domain__project_id=project_id, name=host).select_related('scan_history', 'target_domain').order_by('-scan_history_id').first()


def run_thorough(project_id, runner=None, sleep=None, probe_get=None):
    """The thorough WPScan pass for one project: every host waiting for it, one at a time, with plugin and theme detection in mixed mode and
    as long a timeout as it needs (``CVENGINE_WPSCAN_THOROUGH_TIMEOUT``, 12 hours by default; WPScan writes a partial report before then).
    One pass per project at a time (a Redis claim kept alive while it runs). It stops when scans are paused or stopped, leaves the host
    waiting, and a later run carries on. A site that cannot be reached or that an edge challenges is recorded as such, never retried in a loop.
    Returns ``{'done', 'partial', 'blocked', 'failed', 'skipped'}`` counts.

    Never dispatched to a Sentinel, unlike ``run_wpscan``: ``agentapi.sentinel_dispatch.dispatch_or_none`` waits out a bounded
    timeout before falling back to local execution, which fits a per-scan stage, not a pass that may legitimately run for
    hours - the same one-shot-dispatch mismatch that already keeps vhost/subdirectory discovery off Sentinels."""
    from cveFeed import activity, exclusions, ledger, probes, wp_correlation
    from reNgine import resources
    summary = {'done': 0, 'partial': 0, 'blocked': 0, 'failed': 0}
    if runner is None and not installed():
        return {**summary, 'skipped': 'wpscan is not installed'}
    runner = runner or (lambda url, token: run_wpscan_process(url, token, thorough=True))
    owner = f'thorough-{os.getpid()}'
    with resources.redis_claim(f'cvengine:wpscan:thorough:{project_id}', owner, 300) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another thorough pass is running for this project'}
        while True:
            if resources.global_pause_requested(fail_closed=True):
                return {**summary, 'skipped': 'scanning is paused: the hosts stay waiting'}
            todo = _pending_hosts(project_id)
            if not todo:
                return summary
            host, domain_id = todo[0]
            sub = _latest_row(project_id, host)
            if sub is None or (exclusions.excluded_names(project_id) and exclusions.normalize(host) in exclusions.excluded_names(project_id)):
                record_thorough(project_id, domain_id, host, 'failed', 'the host is no longer a target of the project')
                summary['failed'] += 1
                continue
            scan, url = sub.scan_history, _base_of(sub)
            token = api_token(sub.target_domain.project)
            record_thorough(project_id, domain_id, host, 'running', 'WPScan is asking the site for every plugin and theme it knows; this takes hours')
            running = activity.log('run_check', f'Thorough WPScan pass on one WordPress site of {sub.target_domain.name}', project=project_id, status='running',
                                   scan_id=scan.id)
            try:
                report = _scan_site(runner, url, token, sub, project_id)
            except Blocked as exc:
                record_thorough(project_id, domain_id, host, 'blocked', _hint(str(exc), token))
                ledger.record(THOROUGH_SERVICE, [host], project_id, scan, 'failed')
                summary['blocked'] += 1
                activity.settle(running, 'done', message=f'Thorough WPScan pass: {host} is protected by an edge that challenged the scanner')
                continue
            except Exception as exc:  # noqa: BLE001 - ValueError (not WordPress), a timeout, a crash: recorded, and the next host goes on
                reason = _redact(str(exc), token) or 'WPScan failed'
                record_thorough(project_id, domain_id, host, 'failed', reason)
                ledger.record(THOROUGH_SERVICE, [host], project_id, scan, 'failed')
                summary['failed'] += 1
                activity.settle(running, 'failed', message=activity.diagnostic(f'Thorough WPScan pass on {host}', reason))
                continue
            new, _techs = persist_report(scan, sub, url, report)
            titles = plugin_titles(url, report, probes.allowed_names(sub), get=probe_get, sleep=sleep, project=project_id)
            versioned = record_components(project_id, domain_id, host, report, titles)
            wp_correlation.run_for_host(sub)
            cut = report.get('cvengine_partial') or ''
            state = 'partial' if cut else 'done'
            service = THOROUGH_SERVICE + ('-partial' if cut else '')
            ledger.record(service, [host], project_id, scan)
            record_thorough(project_id, domain_id, host, state, cut and 'the scan stopped before it finished; what it read is kept and it runs again tomorrow',
                            plugins=versioned, new_findings=new, **({'cut_short': cut} if cut else {}))
            summary[state] += 1
            activity.settle(running, 'done', message=f'Thorough WPScan pass on {host}: {state}, {versioned} plugin/theme version(s), {new} new finding(s)')


REDIRECT = re.compile(r'redirects? to:?\s*(https?://[^\s\'"]{1,300})', re.I)


def _scan_site(runner, url, token, sub, project):
    """Run WPScan on ``url``. WPScan stops at a main redirect it will not follow (an apex that redirects to www); the redirect is asked once,
    and only when its target is a name of this host's own group that passes the probe gate (a safe address, not excluded). It never follows
    redirects to anywhere else and never uses WPScan's own ``--follow-redirect``."""
    from urllib.parse import urlsplit

    from cveFeed import probes
    try:
        return runner(url, token)
    except (ValueError, Blocked):
        raise
    except RuntimeError as exc:
        found = REDIRECT.search(str(exc))
        host = (urlsplit(found.group(1)).hostname or '').lower() if found else ''
        if not host or host not in probes.allowed_names(sub) or host == (urlsplit(url).hostname or '').lower() or not probes._permitted(host, project):
            raise
        return runner(found.group(1).rstrip('/.,)'), token)


def _probe_positive(project_id, host):
    """Whether the WordPress probe read a signature on this host (a stored result, for a host the probe skipped this scan as fresh)."""
    from cveFeed.models import ProbeObservation
    return ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), probe='wordpress-detect', kind='wordpress', outcome='found').exists()


def _hint(reason, token):
    return ('the edge refused or challenged WPScan (' + _redact(reason, token)[:120] + '). Allow the scanner\'s address or user agent in the WAF or '
            'bot rules for this host, then rescan; cvENGINE never tries to get past a challenge')
