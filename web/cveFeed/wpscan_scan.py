"""The WordPress assessment: what the server does around a Sentinel's WordPress scan.

Every host that shows any sign of WordPress is checked: a technology tag, a header or page signature, the login page, the REST API,
the web archive's memory of the host, plugin or theme paths in crawled URLs, an earlier probe. A cheap read-only probe
(``cveFeed.probes``, probe ``wordpress-detect``) confirms the signature with browser-like requests, follows apex and www redirects, and
records an edge that challenged the scanner instead of concluding "not WordPress". Then a Sentinel scans every candidate and every name of
a grouped host that probes positive (task kind ``wpscan``, ``agentapi.sentinel_dispatch.wrap_wpscan_runner``): this server never runs the scan
itself, and with no scanner able to take it the sites stay due. Nothing is skipped silently: each candidate ends in a recorded state on the
host (``state_of``).

The Sentinel reports a raw JSON report, an exit code and the tail of stderr; ``_classify`` turns that into a report or a classified failure.
Nothing in a report is trusted or executed: it is clipped and stored. The report's vulnerability data comes from a vulnerability API, so the
token is a project or organization API key (Settings, API keys), sent with the one task and scrubbed from it afterwards. The free plan allows
25 requests a day: when the budget is spent the scan still runs without the token (versions, plugins, themes, exposures and users come from the
scan itself) and the host says its vulnerability data was not checked.

Results become findings (source ``wpscan``, with CVE ids where the report names them and what to do about them), technology rows and, for the
core, every plugin and every theme, versioned sightings (``ProbeObservation`` rows) that ``cveFeed.wp_correlation`` correlates with CVEs by
exact plugin identity."""
import logging
import os
import re
import time
from datetime import timedelta
from urllib.parse import urlsplit

from django.utils import timezone

logger = logging.getLogger(__name__)

SERVICE = 'wpscan'
PARTIAL_SERVICE = 'wpscan-partial'  # a run that finished but could not check vulnerability data: asked again soon
PROBE_SERVICE = 'wp-probe'
REDIRECT_SERVICE = 'wpscan-redirected'  # a site that sent the scan to another site: asked again in a few hours, never the week a scanned site rests
NOT_SCANNABLE_SERVICE = 'wpscan-not-scannable'  # WordPress that WPScan will not scan (hosted on wordpress.com): looked at again tomorrow
DEFAULT_MAX_SITES = 20
DEFAULT_STAGE_SECONDS = 60 * 60
QUEUE = 'wpscan_queue'
# The thorough pass: plugin and theme detection in mixed mode asks the site for every plugin and theme slug the scanner knows (about 170,000
# requests), which finds the ones a page never links. It takes hours, so it is never part of the scan: a one-site-at-a-time background task
# (``run_thorough``) that hands each site to a Sentinel as the task kind ``wpscan_thorough`` (its own long budget, one per project at a time),
# started after the quick pass, resumable and never blocking correlation or triage. This server never runs it.
THOROUGH_PROBE = 'wpscan-thorough'
THOROUGH_SERVICE = 'wpscan-thorough'
THOROUGH_QUEUE = QUEUE
THOROUGH_KIND = 'wpscan_thorough'
DEFAULT_THOROUGH_TIMEOUT = 12 * 60 * 60
MIN_THOROUGH_TIMEOUT = 600
MAX_THOROUGH_TIMEOUT = 24 * 60 * 60  # what the contract and the Sentinel accept: a longer budget is held to this
THOROUGH_RETRIES = 6  # times the pass is asked again when no scanner could take it (``cveFeed.tasks.wpscan_thorough``)
THOROUGH_RETRY_DELAY = 30 * 60  # seconds; the n-th retry waits n times this
THOROUGH_STATES = ('pending', 'running', 'done', 'partial', 'blocked', 'failed')


def thorough_timeout():
    """Seconds one site's thorough pass may take on a Sentinel (``CVENGINE_WPSCAN_THOROUGH_TIMEOUT``, 12 hours by default, between ten minutes
    and a day): it travels with the task, the Sentinel ends the scan 30 seconds before it and reports what it read, and the broker keeps the task's
    lease alive for that long (plus a grace to report) and no longer."""
    try:
        value = int(os.environ.get('CVENGINE_WPSCAN_THOROUGH_TIMEOUT', DEFAULT_THOROUGH_TIMEOUT))
    except ValueError:
        return DEFAULT_THOROUGH_TIMEOUT
    return min(MAX_THOROUGH_TIMEOUT, max(MIN_THOROUGH_TIMEOUT, value))


def stage_seconds():
    try:
        return max(60, int(os.environ.get('CVENGINE_WPSCAN_STAGE_SECONDS', DEFAULT_STAGE_SECONDS)))
    except ValueError:
        return DEFAULT_STAGE_SECONDS


OK_EXIT_CODES = (0, 5)  # 5 means "vulnerabilities found"; 1 bad option, 2 interrupted, 3 unexpected exception, 4 the scan did not finish
# severity of the scan's "interesting findings" by their type; unlisted types are informational
INTERESTING_SEVERITY = {'config_backup': 3, 'db_export': 3, 'debug_log': 2, 'upload_directory_listing': 1, 'multisite': 0, 'xmlrpc': 1,
                        'registration': 1, 'search_replace_db2': 3, 'full_path_disclosure': 1}
CVE_PART = re.compile(r'^(?:CVE-)?(\d{4}-\d{4,})$', re.I)
NOT_WORDPRESS = re.compile(r'not seem to be running wordpress', re.I)
BLOCKED = re.compile(r'\b(?:403|429|503|forbidden|blocked|waf|firewall|captcha|challenge|access denied|too many requests)\b', re.I)
VULN_DATA = {'checked': 'checked', 'no_token': 'not checked: no API token', 'exhausted': 'not checked: API token budget exhausted',
             'error': 'not checked: the vulnerability API returned an error'}
BUDGET_ERROR = re.compile(r'limit|quota|exhaust|too many|requests', re.I)
# any of these in a technology name says the host runs (or is hosted for) WordPress
WP_TECH = re.compile(r'^(wordpress|woocommerce|wp ?engine|elementor|wpml|yoast|wp-)', re.I)
WP_URL = r'/wp-(content|includes|json|login\.php|admin)|/xmlrpc\.php'
STATES = ('not_wordpress', 'candidate', 'detected', 'scanned', 'blocked', 'failed', 'waiting', 'queued', 'unavailable', 'unreachable', 'redirected', 'not_scannable')
RECENT_PROBE = timedelta(days=1)  # a site the WordPress probe read this recently that now reads as down is a failure to retry, not a site that is gone
QUICK_ATTEMPTS = 6   # a deferred site is asked again this many times, a little later each time, before it waits for the next scan
QUICK_DELAY = 120    # seconds; the n-th retry waits n times this


class NotWordPress(ValueError):
    """The scan could reach the site and it is not WordPress."""


class Blocked(RuntimeError):
    """The scan was refused or challenged by an edge (a 403, 429 or 503, a captcha or a challenge page)."""


class SiteUnreachable(Exception):
    """The site did not answer the scan (down, no such name, refused the connection, timed out). Not a failed scan and not "not WordPress": nothing was
    read, and the site is asked again at the next scan."""


class RedirectsElsewhere(RuntimeError):
    """The site redirects to another site the scan will not be carried to (``Sentinel`` follows redirects within one site only). A RuntimeError so that
    ``_scan_site`` still follows a redirect to a name of the host's own group. Not a failed scan: the other site is scanned under its own name."""

    def __init__(self, target):
        self.target = target
        super().__init__(f'The URL supplied redirects to {target}')


class NotScannable(Exception):
    """A site WPScan will not scan (hosted on wordpress.com). It is WordPress, so it is not "not WordPress", and nothing can be read: not a failure."""


class ToolFailure(RuntimeError):
    """WPScan itself failed (it crashed, ran out of time, was killed, or could not update its own database). ``what`` is a fixed sentence that says
    what failed, safe for the activity feed; the text of the exception is the tool's own last line, redacted, for the host page and the worker log."""

    def __init__(self, what, detail=''):
        self.what = what
        super().__init__(detail or what)


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


def api_token(project):
    """The project's (or its organization's) WordPress vulnerability API token, or ''."""
    from cveFeed.api_credentials import resolve_for_project
    return (resolve_for_project(project).get('wpscan') or {}).get('api_key') or ''


def severity_from_score(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return 2  # the scan did not rate it: medium
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


def last_line(text):
    """The last non-empty line of a process's output, clipped: what the scanner said last, for a failure that wrote no report."""
    lines = [line.strip() for line in str(text or '').splitlines() if line.strip()]
    return lines[-1][:300] if lines else ''


# what the scanner's own exit codes mean when nothing else says why it stopped
EXIT_MEANING = {1: 'the scan refused its options or the address it was given', 2: 'the scan was interrupted', 3: 'the scan hit an unexpected error'}
_DOWN = re.compile(r"seems to be down(?: \((.*)\))?|^HTTP Error: \S+ \((?!status: )(.*)\)", re.I | re.S)  # WPScan's TargetDown, and an HTTP error with no status
_WPSCAN_REDIRECT = re.compile(r'The URL supplied redirects to (https?://\S+?)\.?(?:\s|$)')
_HOSTED = re.compile(r'hosted on WordPress\.com', re.I)
_DURATION = re.compile(r'Max Scan Duration Reached', re.I)
_UPDATE = re.compile(r'Update required|checksums do not match|Unable to get https?://data\.wpscan\.org|database file is missing', re.I)
DB_FAILURE = "this Sentinel's WPScan vulnerability database is missing or could not be updated"
TIME_FAILURE = 'the scan ran out of its time limit before it read anything'


def _aborted(reason, token, otherwise=None):
    """The ending ``reason`` (WPScan's ``scan_aborted`` text, or the last line it printed) is, raised as what it is. Order matters: a site that is down
    is told apart before an edge's refusal, and the tool's own failures before the unknown."""
    if NOT_WORDPRESS.search(reason):
        raise NotWordPress('the scan says the site is up and is not running WordPress')
    if _HOSTED.search(reason):
        raise NotScannable('the site is hosted on WordPress.com, which WPScan does not scan')
    found = _DOWN.search(reason)
    if found:
        why = _redact((found.group(1) or found.group(2) or '').strip(), token)[:120]
        raise SiteUnreachable('the site did not answer the scan' + (f' ({why})' if why else ''))
    found = _WPSCAN_REDIRECT.search(reason)
    if found and _URL_SHAPE.match(found.group(1)):
        raise RedirectsElsewhere(found.group(1))
    if _UPDATE.search(reason):
        raise ToolFailure(DB_FAILURE, _redact(reason, token))
    if _DURATION.search(reason):
        raise ToolFailure(TIME_FAILURE, _redact(reason, token))
    if BLOCKED.search(reason):
        raise Blocked(_redact(reason, token))
    if otherwise is not None:
        raise otherwise(_redact(reason, token))
    raise RuntimeError(_redact(reason or 'the scan did not finish', token))


_URL_SHAPE = re.compile(r'^https?://[A-Za-z0-9][A-Za-z0-9.:_/%?&=~+-]{0,300}$')


def _classify(report, returncode, stderr='', token=''):
    """A Sentinel's reported outcome of one WordPress scan - the scanner's exit code, its JSON report if it wrote one, and the tail of stderr if it
    did not - turned into a report dict, or raised as what it is. The one function every dispatched site goes through
    (``agentapi.sentinel_dispatch.wrap_wpscan_runner``), so what each ending means is decided here and nowhere else. Nothing in the report or the
    text is trusted: the text is clipped and the token redacted.

    Exit code 4 means the scan did not finish; the report's ``scan_aborted`` text says why (``_aborted``): ``NotWordPress`` (the site is up and
    is not WordPress), ``NotScannable`` (hosted on wordpress.com), ``SiteUnreachable`` (down), ``RedirectsElsewhere`` (it redirects to another
    site), ``Blocked`` (an edge refused or challenged the scan), ``ToolFailure`` (out of time, or its own database could not be updated) or a
    ``RuntimeError`` (anything else, with the tool's own words). A report that has results despite the abort is returned, marked
    ``cvengine_partial``. Any other exit code but 0 and 5 is the tool failing: ``ToolFailure`` says which."""
    if returncode == 4:
        if report is None:
            said = last_line(stderr)
            if said:  # the tool printed why and wrote no report: the same endings, read from that line
                _aborted(said, token, otherwise=lambda text: ToolFailure('the scan did not finish and wrote no report', text))
            raise ToolFailure('the scan did not finish and wrote no report', 'the scan did not finish and wrote no report')  # not "not WordPress": nothing was read
        reason = str(report.get('scan_aborted') or '')
        if any(report.get(k) for k in ('version', 'plugins', 'themes', 'interesting_findings')):
            return {**report, 'cvengine_partial': reason[:120] or 'the scan did not finish'}  # what it read before it stopped
        _aborted(reason, token)
    if returncode not in OK_EXIT_CODES:
        said = last_line(stderr)
        if isinstance(returncode, int) and returncode < 0:
            raise ToolFailure('the scan was killed before it finished, usually at its time limit', _redact(said, token) or f'the scan was killed (signal {-returncode})')
        meaning = EXIT_MEANING.get(returncode, 'the scan stopped')
        raise ToolFailure(meaning, _redact(said or f'{meaning} (exit {returncode})', token))
    if report is None:
        raise ToolFailure('the scan wrote no usable report', 'the scan wrote no usable report')
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
    """``[(name, severity, description, cves, references, component)]`` from one WordPress scan report: the vulnerabilities of the core, the main
    theme, every plugin and theme, what the scan found exposed, users, and components it calls outdated. Each says what to do."""
    rows = []

    def add(component, version, items):
        label = f'{component} {version}'.strip()
        for v in items or []:
            cvss = v.get('cvss') or {}
            fixed = v.get('fixed_in')
            note = f'Fixed in {fixed}. Remediation: update {component} to {fixed} or later.' if fixed else (
                'No fixed version is listed. Remediation: remove or replace the component, or restrict access to it.')
            rows.append((f'{label}: {v.get("title", "known vulnerability")}'[:500], severity_from_score(cvss.get('score')),
                         f'{note} Reported by the WordPress scan for {label}.', _cves(v.get('references')), _urls(v.get('references')), component))

    def outdated(component, info):
        latest = info.get('latest_version')
        version = (info.get('version') or {}).get('number')
        if info.get('outdated') and latest and version:
            rows.append((f'{component} {version} is outdated (latest {latest})'[:500], 1,
                         f'The WordPress scan reports {component} {version}; the latest release is {latest}. Remediation: update {component}.',
                         [], [], f'{component} outdated'))
    version = report.get('version') or {}
    add('WordPress', version.get('number') or '', version.get('vulnerabilities'))
    if version.get('status') == 'outdated' and version.get('number'):
        rows.append((f'WordPress {version["number"]} is outdated'[:500], 1,
                     f'The WordPress scan reports WordPress {version["number"]} as outdated. Remediation: update WordPress.', [], [], 'WordPress outdated'))
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
        rows.append((f'WordPress: {item.get("to_s", kind)}'[:500], severity, f'The WordPress scan found {kind.replace("_", " ")} at {item.get("url", base)}. '
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
    a component whose version the scan could not read has an empty version. Slugs are cut to a safe alphabet."""
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
    """Whether the scan could check vulnerability data: ``checked``, ``no_token``, ``exhausted`` (the API says its limit is reached) or ``error``
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
    """Save one site's report; returns ``(new findings, technologies added)``. The open rows of this host that the versions it read are past
    the fix of are closed as fixed (cveFeed.finding_lifecycle.close_fixed_wpscan_rows)."""
    from cveFeed import finding_lifecycle
    from reNgine.tasks import save_vulnerability
    from startScan.ip_rows import get_or_create_first
    from startScan.models import Technology
    new, seen = 0, {}
    for name, severity, description, cves, refs, component in _vuln_rows(report, url):
        vuln, created = save_vulnerability(
            target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=url, name=name, severity=severity,
            description=description, source='wpscan', template_id='wpscan:' + component[:150], type='wpscan', cve_ids=cves,
            references=refs, tags=['wordpress', 'wpscan'])
        new += int(created)
        if vuln is not None:
            seen[vuln.name] = vuln.pk
    try:
        finding_lifecycle.close_fixed_wpscan_rows(scan, sub, report, seen)
    except Exception:  # noqa: BLE001 - closing what a newer version fixed never fails the stage; the next scan tries again
        logger.exception('could not close the fixed WordPress scan findings of %s', getattr(sub, 'name', ''))
    added = 0
    for tech_name in _technologies(report):
        tech, _ = get_or_create_first(Technology, name=tech_name)
        if not sub.technologies.filter(pk=tech.pk).exists():
            sub.technologies.add(tech)
            added += 1
    return new, added


MAX_TITLE_LOOKUPS = 8


def plugin_titles(scan, sub, base, report):
    """``{slug: title}`` read from each plugin's own readme.txt (``=== Plugin Name ===``, one small GET each, at most MAX_TITLE_LOOKUPS per host, made by
    a Sentinel: ``page_read``, op ``readme``; this server sends nothing to the site): an advisory names a plugin by its title, and a slug alone often
    differs from it. A plugin whose readme cannot be read has no title. Returns None when the titles are unknown (the read could not be made, or no
    Sentinel could take it): ``record_components`` keeps the titles it already holds. A title is an enrichment, not a verdict, so an unanswered read
    never discards the scan that was just made, and never turns into \"this plugin has no title\"."""
    from agentapi import probe_dispatch
    from reNgine.resources import ScannerUnavailable
    slugs = [re.sub(r'[^A-Za-z0-9._-]', '', str(slug))[:80] for slug in sorted((report.get('plugins') or {}))[:MAX_TITLE_LOOKUPS]]
    slugs = [slug for slug in dict.fromkeys(slugs) if slug and slug[0].isalnum() and '..' not in slug]
    if not slugs:
        return {}
    try:
        return probe_dispatch.readme_titles(scan.domain.project, scan, sub, base, slugs)
    except (RuntimeError, ScannerUnavailable) as exc:  # the scanner could not make the read, or none could take it: unknown, never "no titles"
        logger.info('plugin titles of %s were not read: %s', sub.name, exc)
        return None


def record_components(project_id, domain_id, host, report, titles=None):
    """Store the core, plugin and theme versions the scan read as sightings the CVE correlation uses (with the plugin title when a readme gave
    one); a plugin that is no longer reported is removed. Returns the number of plugins and themes with a version."""
    from cveFeed.models import ProbeObservation
    keep_known = titles is None  # the titles could not be read this time: the title each plugin row already holds stays
    titles = titles or {}
    now = timezone.now()
    keep = {'wpscan-plugin': set(), 'wpscan-theme': set()}
    versioned = 0
    for kind, slug, version, extra in components(report):
        probe = {'core': 'wpscan-core', 'wp-plugin': 'wpscan-plugin', 'wp-theme': 'wpscan-theme'}[kind]
        if keep_known and kind == 'wp-plugin':
            known = ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), probe=probe, product=slug).first()
            if known and (known.evidence or {}).get('title'):
                titles = {**titles, slug: known.evidence['title']}
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
    """Vulnerability API requests the token has left, from the report, or None when it does not say."""
    value = (report.get('vuln_api') or {}).get('requests_remaining')
    return value if isinstance(value, int) else None


# ----------------------------------------------------------------------------- states: what happened to each candidate, on the host

def record_state(project_id, domain_id, host, state, reason='', **extra):
    """Record where a WordPress candidate stands (one of STATES) with the reason, so a host never silently has no scan result.

    The core version the last successful scan read stays on the row through a run that could not read one (blocked by the edge, failed, waiting,
    queued): the host page shows the state with the version it last knew, and only a scan that read the site (``scanned``) or found it is not
    WordPress replaces or clears it."""
    from cveFeed.models import ProbeObservation
    host = host.lower()
    version = str(extra.get('version') or '')[:100]
    if not version and state not in ('scanned', 'not_wordpress'):
        previous = ProbeObservation.objects.filter(project_id=project_id, host=host, probe='wpscan', port=0, kind='wordpress', product='WordPress').first()
        version = previous.version if previous else ''
    ProbeObservation.objects.update_or_create(
        project_id=project_id, host=host, probe='wpscan', port=0, kind='wordpress', product='WordPress',
        defaults={'domain_id': domain_id, 'version': version, 'variant': state,
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
        return {**base, 'state': 'failed', 'reason': 'the scan could not see WordPress, the probe did', 'scanned_at': scan.observed_at.isoformat()}
    if scan is not None:
        evidence = scan.evidence or {}
        return {**base, 'state': evidence.get('state') or 'failed', 'reason': evidence.get('reason', ''), 'scanned_at': scan.observed_at.isoformat(),
                'findings': evidence.get('findings'), 'vulnerability_data': evidence.get('vulnerability_data', ''),
                'next_scan': evidence.get('next_scan', ''), 'core': scan.version}
    if detect_row is not None:
        if detect_row.outcome == 'found':
            return {**base, 'state': 'detected', 'reason': 'WordPress was detected; the scan has not run on it yet', 'core': detect_row.version}
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

def _ask_wordpress(scan, chosen):
    """``{host: observations}`` of the ``wordpress-detect`` probe a Sentinel ran for each ``(sub, bases)`` of ``chosen`` (``agentapi.probe_dispatch.try_http_probes``:
    one ``http_probe`` task per chunk, this server asks the site for nothing). A host's bases are asked in order and the first that is WordPress ends
    its list; an answer that is an error is no answer (``[]``: the host stays due, never read as \"not WordPress\"). Raises ``ScannerUnavailable``
    when no Sentinel can take the work or a task ended with no result: nothing was asked, nothing is recorded."""
    from agentapi import probe_dispatch
    from cveFeed import probes
    from reNgine import resources
    pending = {sub.name.lower(): (sub, list(bases)) for sub, bases in chosen}
    results = {}
    while pending:
        planned, asked = [], {}
        for host, (sub, bases) in pending.items():
            entry = {'probe': 'wordpress-detect', 'label': probes.BY_ID['wordpress-detect']['label'], 'family': 'http', 'target': {'base': bases.pop(0)}, 'for': []}
            asset = probes.asset_key(host, entry)
            planned.append((sub, asset, entry))
            asked[host] = asset
        for start in range(0, len(planned), probe_dispatch.MAX_PROBES_PER_TASK):
            if resources.abort_requested(scan.id) or resources.global_pause_requested(fail_closed=True):
                return results
            answered = probe_dispatch.try_http_probes(scan.domain.project, scan, planned[start:start + probe_dispatch.MAX_PROBES_PER_TASK])
            for sub, asset, _entry in planned[start:start + probe_dispatch.MAX_PROBES_PER_TASK]:
                got = answered.get(asset)
                host = sub.name.lower()
                if got is None or isinstance(got, Exception):
                    logger.info('WordPress probe failed for %s: %s', host, type(got).__name__ if got is not None else 'no answer')
                    got = []
                results[host] = got
        pending = {host: (sub, bases) for host, (sub, bases) in pending.items()
                   if bases and not (results.get(host) and results[host][0]['outcome'] == 'found')}
    return results


def detect(scan, subs, candidates, force=False, only=None):
    """Run the read-only WordPress probe on the candidates, their grouped names and, within the cap, the other web hosts; record each result.
    The probe is a Sentinel's (``http_probe``, probe ``wordpress-detect``): this server sends nothing to a site. Returns ``{host: first observation}``
    for the hosts probed now. ``ScannerUnavailable`` (no Sentinel can take it) propagates: nothing is recorded and every site stays due."""
    from cveFeed import ledger, probes, route_auth
    project, domain = scan.domain.project_id, scan.domain
    by_name = {s.name.lower(): s for s in subs}
    siblings = siblings_of(subs, set(candidates))
    web = {name for name, s in by_name.items() if route_auth.web_bases(s)}
    order = list(dict.fromkeys(sorted(set(candidates) & web) + sorted(siblings & web) + sorted(web)))[:max_probe_hosts()]
    if only is not None:
        order = [h for h in order if h in only]
    covered = set() if force else ledger.fresh(PROBE_SERVICE, order, project)
    results = {}
    chosen = [(by_name[host], route_auth.web_bases(by_name[host])) for host in order if host not in covered]
    answers = _ask_wordpress(scan, chosen) if chosen else {}
    for host in order:
        if host in covered or host not in answers:
            continue
        sub, found = by_name[host], answers[host]
        if not found:
            ledger.record(PROBE_SERVICE, [host], project, scan, 'failed')
            continue
        probes.record(project, domain.id, host, 'wordpress-detect', found[:1])
        if found[1:]:  # the upgrade directory's state is its own probe: the rows that read 'wordpress-detect' as the host's WordPress state stay one
            probes.record(project, domain.id, host, 'wp-upgrade-dir', found[1:])
            from cveFeed import wp_core
            wp_core.record_exposure(scan, sub, found[1].get('variant'), found[0].get('version', ''))
        if found[0]['outcome'] == 'found':
            probes.apply_to_subdomain(sub, found)
        ledger.record(PROBE_SERVICE, [host], project, scan, 'failed' if found[0]['outcome'] == 'challenged' else 'done')
        results[host] = found[0]
    return results


def run_wpscan(scan_id, runner=None, force=False, internal=False, only=None, attempt=0):
    """The pipeline stage: probe for WordPress, then scan every host that shows any sign of it (and every grouped name that probes
    positive), positive probes first. Never silent: every candidate gets a recorded state. Returns a summary dict; ``error`` is set only when
    every attempted site failed.

    ``internal`` is the run for a host inside a declared internal network (``cveFeed.internal_scan``): the scan runs only through a Sentinel inside
    it, the sites are the ones the Sentinel-run technology pass already tagged as WordPress (this server sends no probe of
    its own, to the site or to its plugin pages), and no thorough pass is queued (its Sentinel would not be inside the network).

    A site the stage cannot reach in time (over the per-scan limit, out of the stage's time budget, no memory for it) is not left for the next
    scan: it is queued as its own background job (``queue_quick``), which asks again a little later, up to ``QUICK_ATTEMPTS`` times. ``only``
    limits the run to those hosts (that job's call); ``attempt`` counts its retries. The summary's ``deferred`` lists the hosts queued."""
    from cveFeed import activity, ledger, wp_correlation
    from reNgine import resources
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project_id, scan.domain
    real_runner = runner is None
    unavailable = None
    if real_runner:
        from agentapi import sentinel_dispatch
        try:
            runner = sentinel_dispatch.wrap_wpscan_runner(domain.project, scan=scan, internal=internal)
        except resources.ScannerUnavailable as exc:  # no scanner can take it and the scan may not run here: said below, once there is a site to scan
            unavailable = exc
    allowed, _ips, _ports = _scan_targets(scan)
    subs = list(Subdomain.objects.filter(scan_history=scan, name__in=allowed).prefetch_related('technologies', 'ip_addresses__ports'))
    by_name = {s.name.lower(): s for s in subs}
    signals = candidate_signals(scan, subs)
    if only is not None:
        signals = {h: v for h, v in signals.items() if h in only}
    for host, found in signals.items():
        record_signals(project, domain.id, host, found)
    probed, probe_waiting = {}, None
    if not internal:
        try:
            probed = detect(scan, subs, signals, force=force, only=only)
        except resources.ScannerUnavailable as exc:  # no Sentinel can ask the sites: nothing is recorded, they stay due, and none is read as not WordPress
            probe_waiting = exc
            logger.warning('WordPress detection of scan %s is waiting for a scanner: %s', scan_id, exc)
    positive = {h for h, o in probed.items() if o['outcome'] == 'found'}
    for host in sorted(h for h, o in probed.items() if o['outcome'] == 'absent' and h not in signals):
        record_state(project, domain.id, host, 'not_wordpress', 'the probe found no WordPress signature')
    wanted = sorted(set(signals) | positive, key=lambda h: (h not in positive, h))
    deferred = []
    summary = {'candidates': len(signals), 'probed': len(probed), 'sites': len(wanted), 'scanned': 0, 'findings': 0, 'technologies': 0, 'reused': 0}
    if probe_waiting is not None:  # the sites with a sign of WordPress are still scanned below; the ones only the probe could name wait for it
        summary['probe_waiting'] = probe_waiting.kind
    wp_correlation.carry_forward(scan)
    if not wanted:
        if probe_waiting is not None:  # nothing could be asked: not 'no WordPress here', and every site stays due
            return {**summary, 'skipped': f'no scanner could take this work ({probe_waiting.kind}); the sites stay due until one can'}
        return summary
    fresh = set() if force else (ledger.fresh(SERVICE, wanted, project) | ledger.fresh(PARTIAL_SERVICE, wanted, project)
                                | ledger.fresh(REDIRECT_SERVICE, wanted, project) | ledger.fresh(NOT_SCANNABLE_SERVICE, wanted, project))
    summary['reused'] = len([h for h in wanted if h in fresh])
    history = ledger.last_run(SERVICE, wanted, project)
    epoch = timezone.now() - timedelta(days=36500)
    # due first (the fresh ones are not due), positive probes first, then the never-scanned and longest-waiting: a cap cuts only what waits
    todo = sorted((h for h in wanted if h not in fresh), key=lambda h: (h not in positive, history.get(ledger._norm(h)) or epoch, h))
    for host in todo[max_sites():]:
        record_state(project, domain.id, host, 'waiting', f'over the per-scan limit of {max_sites()} sites; it goes first next time')
        deferred.append(host)
    todo = todo[:max_sites()]
    if not todo:
        summary['deferred'] = queue_quick(scan, deferred, attempt, dispatch=real_runner and not internal)
        return summary
    if unavailable is not None:  # nothing is recorded in the ledger (the sites stay due) and it is not a failure: the next scan asks again
        message = f'no scanner could take this work ({unavailable.kind}); the sites stay due until one can'
        logger.warning('WordPress scan of scan %s is waiting for a scanner: %s', scan_id, unavailable)
        for host in todo:
            record_state(project, domain.id, host, 'waiting', f'no scanner could take this work ({unavailable.kind}); it goes first next time')
        activity.log('run_check', f'WordPress scan for {domain.name} is waiting: {message}', project=project, scan_id=scan.id)
        return {**summary, 'skipped': message}
    token = api_token(domain.project)
    running = activity.log('run_check', f'The WordPress scan is checking {len(todo)} WordPress site(s) of {domain.name}'
                           + ('' if token else ' (no API token: versions, plugins and exposures only)'),
                           project=project, status='running', scan_id=scan.id)
    down, attempted, followed = [], 0, set()  # sites that read as down, sites the scan was asked about, redirect targets added to this run
    errors, notes, scanned, token_ok = [], [], [], bool(token)  # errors: the scan went wrong; notes: a site that is not scannable (down, moved, not WordPress)
    no_scanner = None
    if real_runner:
        # waiting on Sentinels without the worker (agentapi.stage_runs): every site's task is sent first, and the loop below runs once they are all
        # in, so this stage's summary covers every site (outside a StageRun this does nothing and each site waits in turn, as before)
        from agentapi import sentinel_dispatch
        sentinel_dispatch.prefetch_wpscan(domain.project, scan, [_base_of(by_name[h]) for h in todo], token, internal=internal)
    started = time.monotonic()
    for index, host in enumerate(todo):
        if time.monotonic() - started > stage_seconds():
            for waiting in todo[index:]:
                record_state(project, domain.id, waiting, 'waiting', 'the WordPress scan stage used its time budget; it goes first next time')
                deferred.append(waiting)
            break
        sub, url = by_name[host], _base_of(by_name[host])
        use = token if token_ok else ''
        attempted += 1
        try:
            report = _scan_site(runner, url, use, sub, project)
        except ValueError as exc:  # NotWordPress (or any ValueError a runner raises): the scan says the site is up and is not WordPress
            if host in positive or _probe_positive(project, host):
                # the probe read a WordPress signature and the scan did not: a WAF served the scan a decoy page, or it was sent elsewhere. Not "not
                # WordPress": it stays a candidate that failed, and is asked again at the next scan
                ledger.record(SERVICE, [host], project, scan, 'failed')
                record_state(project, domain.id, host, 'failed', 'the scan could not see WordPress, the probe did: the site may serve the scan a '
                             'different page than it serves other visitors')
                errors.append(f'{host}: the scan could not see WordPress')
                continue
            ledger.record(SERVICE, [host], project, scan)
            record_state(project, domain.id, host, 'not_wordpress', str(exc))
            notes.append(f'{host}: not running WordPress')
            continue
        except Blocked as exc:
            ledger.record(SERVICE, [host], project, scan, 'failed')
            record_state(project, domain.id, host, 'blocked', _hint(str(exc), token))
            errors.append(f'{host}: blocked by the edge')
            continue
        except SiteUnreachable as exc:  # nothing was read: asked again at the next scan
            ledger.record(SERVICE, [host], project, scan, 'failed')
            reason = _redact(str(exc), token)
            if _probe_recent(project, host):  # WordPress was read on this site within a day and it does not answer now: a failure to retry, not a quiet skip
                record_state(project, domain.id, host, 'failed', f'{reason}; the WordPress probe read this site within the last day, so the Sentinel or its network may be at fault')
                errors.append(f'{host}: the site answered the WordPress probe within a day and does not answer the scan')
                continue
            record_state(project, domain.id, host, 'unreachable', reason)
            down.append((host, reason))
            notes.append(f'{host}: not reachable')
            continue
        except RedirectsElsewhere as exc:  # the site sends visitors to another site; a target of this project is scanned under its own name
            ledger.record(REDIRECT_SERVICE, [host], project, scan)  # its own record with a short window: a passing redirect (maintenance, login) does not hide the site for a week
            target = (urlsplit(exc.target).hostname or '').lower().rstrip('.')
            if target and target in by_name and target != host and target not in todo and target not in followed and target not in fresh and _target_permitted(target, project):
                followed.add(target)
                todo.append(target)  # scanned in this run, under its own name
                record_state(project, domain.id, host, 'redirected', f'the site redirects to {exc.target}, another target of this project; that name is scanned instead')
                notes.append(f'{host}: redirects to {target}, which is scanned')
            else:
                record_state(project, domain.id, host, 'redirected', f'the site redirects to {exc.target}, another site; it is not scanned under this name (asked again in a few hours)')
                notes.append(f'{host}: redirects to another site')
            continue
        except NotScannable as exc:  # WordPress, but not one WPScan can scan
            ledger.record(NOT_SCANNABLE_SERVICE, [host], project, scan)
            record_state(project, domain.id, host, 'not_scannable', str(exc))
            notes.append(f'{host}: not scannable by WPScan')
            continue
        except (resources.ScanAborted, resources.MemoryBusy) as exc:  # stopped, or no memory for it: not the site's fault, and nothing after it can run
            no_scanner = exc if isinstance(exc, resources.ScannerUnavailable) else None  # a scanner that is offline is not memory pressure
            for waiting in todo[index:]:
                record_state(project, domain.id, waiting, 'waiting', (f'no scanner could take this work ({no_scanner.kind}); it goes first next time' if no_scanner
                                                                       else 'the scan was stopped or memory was short; it goes first next time'))
                if not isinstance(exc, resources.ScanAborted):  # a person stopped the scan: nothing is queued behind them
                    deferred.append(waiting)
            break
        except Exception as exc:  # noqa: BLE001 - one site failing must not stop the rest
            logger.warning('WordPress scan failed for %s: %s', host, _redact(str(exc), token))
            ledger.record(SERVICE, [host], project, scan, 'failed')
            record_state(project, domain.id, host, 'failed', _redact(str(exc), token))
            activity.diagnostic(f'WordPress scan on {host}', _redact(str(exc), token))  # the raw text goes to the worker log, not the feed
            what = getattr(exc, 'what', '')  # a ToolFailure's own fixed sentence says what failed and holds nothing of the site or the token
            errors.append(f'{host}: {what} (see the host page)' if what else f'{host}: the scan failed (see the host page)')
            continue
        titles = {} if internal else plugin_titles(scan, sub, url, report)  # before the report is saved: a wait for a scanner repeats this pass
        new, techs = persist_report(scan, sub, url, report)
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
    if down and not scanned and len(down) == attempted and attempted >= 2:
        # not one site could be scanned and every one read as down: more likely the Sentinel's own DNS or route out is broken than that every site is gone.
        # The sites stay recorded as unreachable and asked again, and the stage is kept as failed, naming the Sentinel
        sentinel = getattr(runner, 'last_sentinel', '') or 'the Sentinel that ran it'
        errors.append(f'every one of the {attempted} sites read as down; {sentinel} may have broken DNS or no route out (check that Sentinel)')
        for host, reason in down:
            record_state(project, domain.id, host, 'unreachable', f'{reason}; every site of this scan read as down, so the Sentinel may be at fault')
        notes = [n for n in notes if not n.endswith('not reachable')]
    summary['scanned'] = len(scanned)
    summary['deferred'] = queue_quick(scan, deferred, attempt, dispatch=real_runner and not internal)
    summary['thorough_queued'] = queue_thorough(project, scanned, domain.id, dispatch=real_runner) if scanned and not internal else 0
    failed_all = bool(errors) and not scanned  # a site that is down, moved or not WordPress is a note, never a failure of the stage
    message = (f'WordPress scan finished {domain.name}: {len(scanned)} site(s), {summary["findings"]} new finding(s)'
               + ('; the API token budget ran out, so later sites were scanned without vulnerability data' if token and not token_ok else '')
               + (f'; {len(errors)} problem(s): {errors[0]}' if errors else '')
               + (f'; not scanned: {"; ".join(notes[:3])}' + (f' and {len(notes) - 3} more' if len(notes) > 3 else '') if notes else '')
               + (f'; no scanner could take the remaining sites ({no_scanner.kind}), so they stay due until one can' if no_scanner else ''))
    activity.settle(running, 'failed' if failed_all else 'done', message=message, **summary)
    if failed_all:
        summary['error'] = errors[0][:290]
    return summary


# ----------------------------------------------------------------------------- the queued quick pass

def queue_quick(scan, hosts, attempt=0, dispatch=True):
    """Queue the quick pass for hosts the stage could not reach (``wpscan_quick``, on the WordPress scan queue, a little later each attempt): they are
    marked ``queued`` and not left for the next scan. Past ``QUICK_ATTEMPTS`` they stay ``waiting`` for it. Returns the hosts queued."""
    hosts = sorted(set(hosts))
    if not hosts or not dispatch or attempt >= QUICK_ATTEMPTS:
        return []
    domain = scan.domain
    try:
        from cveFeed.tasks import wpscan_quick
        wpscan_quick.apply_async(args=[scan.id, hosts, attempt + 1], countdown=QUICK_DELAY * (attempt + 1), queue=QUEUE)
    except Exception:  # noqa: BLE001 - the hosts stay waiting: the next scan's quick pass asks again
        logger.exception('could not queue the WordPress quick pass for %s', domain.name)
        return []
    for host in hosts:
        record_state(domain.project_id, domain.id, host, 'queued', f'The scan could not reach this site in time; it is queued and asked again (attempt {attempt + 1} of {QUICK_ATTEMPTS})')
    return hosts


def _requeue_quick(scan, hosts, attempt):
    """Ask again at the same attempt, after the same delay, without using one up and without touching any host's recorded state: the quick pass
    that found no scanner online (``scanner_state``) has not failed, so it waits for one instead of spending its tries."""
    try:
        from cveFeed.tasks import wpscan_quick
        wpscan_quick.apply_async(args=[scan.id, sorted(hosts), attempt], countdown=QUICK_DELAY * max(1, attempt), queue=QUEUE)
    except Exception:  # noqa: BLE001 - the hosts stay recorded as they were: the next scan's quick pass asks again
        logger.exception('could not queue the WordPress quick pass for %s', scan.domain.name)


def run_quick(scan_id, hosts, attempt=1, runner=None):
    """The queued quick pass: the stage's WordPress scan run for just these hosts, under the same checks (exclusions, bug bounty confirmation, ledger
    freshness, memory), one run per project at a time. Whatever it still cannot reach is queued again by ``run_wpscan`` until the attempts are
    spent. Returns the run's summary, or ``{'skipped': why}``."""
    from reNgine import resources
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').filter(pk=scan_id).first()
    if scan is None:
        return {'skipped': 'the scan is gone'}
    only = {h.lower() for h in hosts}
    if resources.global_pause_requested(fail_closed=True) or resources.abort_requested(scan_id):
        queue_quick(scan, only, attempt, dispatch=not resources.abort_requested(scan_id))
        return {'skipped': 'scanning is paused: the hosts stay queued'}
    from agentapi import scanner_state
    waiting = scanner_state.skip_note('wpscan')
    if waiting:  # no scanner can run it and this server may not: asked again at the same attempt a little later, with no run and no activity line
        _requeue_quick(scan, only, attempt)
        return {'skipped': waiting}
    if runner is None:
        # the sites a Sentinel scans are waited for without holding the worker (agentapi.stage_runs): the callback finishes the pass
        from agentapi import stage_runs
        context = {'scan_id': scan_id, 'hosts': sorted(only), 'attempt': attempt}
        return stage_runs.run('wpscan.quick', context, first=lambda: _quick(scan, only, attempt), project=scan.domain.project_id, scan=scan_id)
    return _quick(scan, only, attempt, runner=runner)


def _resume_quick(context):
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').filter(pk=context['scan_id']).first()
    if scan is None:
        return {'skipped': 'the scan is gone'}
    return _quick(scan, set(context['hosts']), context['attempt'])


def _quick(scan, only, attempt, runner=None):
    from agentapi import stage_runs
    from reNgine import resources
    claim = stage_runs.claim_kwargs('wpscan-quick', f'quick-{os.getpid()}')
    with resources.redis_claim(f'cvengine:wpscan:quick:{scan.domain.project_id}', claim.pop('owner'), 600, **claim) as holder:
        if holder is not True:
            queue_quick(scan, only, attempt)
            return {'skipped': 'another quick pass is running for this project'}
        return run_wpscan(scan.pk, runner=runner, only=only, attempt=attempt)


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
            logger.exception('could not start the thorough WordPress scan pass for project %s', project_id)
    return len(due)


def _pending_hosts(project_id):
    """The hosts waiting for the thorough pass, longest-waiting first: ``[(host, domain_id)]``."""
    from cveFeed.models import ProbeObservation
    rows = ProbeObservation.objects.filter(project_id=project_id, probe=THOROUGH_PROBE, variant__in=('pending', 'running')).order_by('observed_at', 'host')
    return [(r.host, r.domain_id) for r in rows]


def _latest_row(project_id, host):
    from startScan.models import Subdomain
    from targetApp.models import Domain, in_target_scope_q
    # a target set to manual only is never given the thorough pass on a schedule: its host is no longer one the pass may scan; nor is a name
    # kept under a target that is now exactly one host
    return (Subdomain.objects.filter(target_domain__project_id=project_id, name=host).exclude(target_domain__discovery_mode=Domain.DISCOVERY_MANUAL)
            .filter(in_target_scope_q()).select_related('scan_history', 'target_domain').order_by('-scan_history_id').first())


def run_thorough(project_id, runner=None):
    """The thorough pass for one project: every host waiting for it, one at a time, each handed to a Sentinel as one ``wpscan_thorough`` task
    (plugin and theme detection in mixed mode, as long a budget as it needs: ``CVENGINE_WPSCAN_THOROUGH_TIMEOUT``, 12 hours by default; the
    Sentinel ends the scan 30 seconds before it and reports what it read). One pass per project at a time (a Redis claim kept alive while it runs, and
    the Sentinel side runs one such task per project at a time too). It stops when scans are paused or stopped, leaves the host waiting, and a later
    run carries on. A site that cannot be reached or that an edge challenges is recorded as such, never retried in a loop.
    Returns ``{'done', 'partial', 'blocked', 'failed', 'skipped'}`` counts.

    This server never runs it (``wpscan_thorough`` is in ``agentapi.sentinel_dispatch.NEVER_LOCAL``): with no scanner able to take the work, or
    one that did not finish it in time, the host stays ``pending`` and nothing is recorded as done, so a later pass asks again. The report is
    classified by ``_classify`` and stored exactly like the quick pass's, nothing in it is trusted or executed. ``runner`` is the seam the tests use
    (``runner(url, token, timeout) -> report``)."""
    from cveFeed import activity, exclusions, ledger, wp_correlation
    from reNgine import resources
    summary = {'done': 0, 'partial': 0, 'blocked': 0, 'failed': 0}
    owner = f'thorough-{os.getpid()}'
    with resources.redis_claim(f'cvengine:wpscan:thorough:{project_id}', owner, 300) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another thorough pass is running for this project'}
        from cveFeed.bounty_gate import Gate
        while True:
            if resources.global_pause_requested(fail_closed=True):
                return {**summary, 'skipped': 'scanning is paused: the hosts stay waiting'}
            gate = Gate()  # read again for every host: a confirmation withdrawn while the pass runs stops it at the next site
            if gate.project_blocked(project_id):
                return {**summary, 'skipped': 'the bug bounty engagement has not confirmed automated testing: the hosts stay waiting'}
            todo = _pending_hosts(project_id)
            if not todo:
                return summary
            host, domain_id = todo[0]
            sub = _latest_row(project_id, host)
            if sub is None or (exclusions.excluded_names(project_id) and exclusions.normalize(host) in exclusions.excluded_names(project_id)):
                record_thorough(project_id, domain_id, host, 'failed', 'the host is no longer a target of the project, or its target is set to manual only or to that host only')
                summary['failed'] += 1
                continue
            why = gate.refusal(project_id, host)  # a bug bounty project that has not confirmed automated testing, or a host outside the program's scope
            if why:
                record_thorough(project_id, domain_id, host, 'failed', 'not scanned: ' + why)
                summary['failed'] += 1
                continue
            scan, url = sub.scan_history, _base_of(sub)
            token = api_token(sub.target_domain.project)
            record_thorough(project_id, domain_id, host, 'running', 'a Sentinel is asking the site for every plugin and theme it knows; this takes hours')
            running = activity.log('run_check', f'Thorough WordPress scan on one WordPress site of {sub.target_domain.name}', project=project_id, status='running',
                                   scan_id=scan.id)
            try:
                if runner is None:
                    from agentapi import sentinel_dispatch
                    report = _scan_site(sentinel_dispatch.wrap_wpscan_thorough_runner(sub.target_domain.project, scan=scan, timeout_seconds=thorough_timeout()),
                                        url, token, sub, project_id)
                else:
                    report = _scan_site(runner, url, token, sub, project_id)
            except Blocked as exc:
                record_thorough(project_id, domain_id, host, 'blocked', _hint(str(exc), token))
                ledger.record(THOROUGH_SERVICE, [host], project_id, scan, 'failed')
                summary['blocked'] += 1
                activity.settle(running, 'done', message=f'Thorough WordPress scan pass: {host} is protected by an edge that challenged the scanner')
                continue
            except resources.ScannerUnavailable as exc:  # no scanner can take it, or none finished it: not a failure, nothing is recorded as done
                record_thorough(project_id, domain_id, host, 'pending', f'no scanner could take this work ({exc.kind}); it runs again later')
                activity.settle(running, 'done', message=f'Thorough WordPress scan pass on {host}: no scanner could take this work ({exc.kind}); the host stays waiting')
                return {**summary, 'skipped': f'no scanner could take this work ({exc.kind}): the hosts stay waiting', 'unavailable': True}
            except (resources.ScanAborted, resources.MemoryBusy) as exc:  # stopped or no memory: the host stays waiting, a later run carries on
                record_thorough(project_id, domain_id, host, 'pending', 'the pass was stopped or memory was short; it runs again later')
                activity.settle(running, 'done', message=f'Thorough WordPress scan pass on {host}: stopped before it finished ({type(exc).__name__}); the host stays waiting')
                return {**summary, 'skipped': 'scanning was stopped or memory was short: the hosts stay waiting'}
            except (SiteUnreachable, RedirectsElsewhere, NotScannable, NotWordPress) as exc:  # the site cannot be scanned: said as that, not as a failure
                reason = _redact(str(exc), token)
                record_thorough(project_id, domain_id, host, 'failed', reason)
                ledger.record(THOROUGH_SERVICE, [host], project_id, scan, 'failed')
                summary['failed'] += 1
                activity.settle(running, 'done', message=f'Thorough WordPress scan pass on {host}: not scanned: {reason}')
                continue
            except Exception as exc:  # noqa: BLE001 - a timeout, a crash: recorded, and the next host goes on
                reason = _redact(str(exc), token) or 'the thorough scan failed'
                record_thorough(project_id, domain_id, host, 'failed', reason)
                ledger.record(THOROUGH_SERVICE, [host], project_id, scan, 'failed')
                summary['failed'] += 1
                activity.settle(running, 'failed', message=activity.diagnostic(f'Thorough WordPress scan pass on {host}', reason))
                continue
            titles = plugin_titles(scan, sub, url, report)  # before the report is saved: a wait for a scanner repeats this pass
            new, _techs = persist_report(scan, sub, url, report)
            versioned = record_components(project_id, domain_id, host, report, titles)
            wp_correlation.run_for_host(sub)
            cut = report.get('cvengine_partial') or ''
            state = 'partial' if cut else 'done'
            service = THOROUGH_SERVICE + ('-partial' if cut else '')
            ledger.record(service, [host], project_id, scan)
            record_thorough(project_id, domain_id, host, state, cut and 'the scan stopped before it finished; what it read is kept and it runs again tomorrow',
                            plugins=versioned, new_findings=new, **({'cut_short': cut} if cut else {}))
            summary[state] += 1
            activity.settle(running, 'done', message=f'Thorough WordPress scan pass on {host}: {state}, {versioned} plugin/theme version(s), {new} new finding(s)')


REDIRECT = re.compile(r'redirects? to:?\s*(https?://[^\s\'"]{1,300})', re.I)


def _scan_site(runner, url, token, sub, project):
    """Run the scan on ``url``. The scan stops at a main redirect it will not follow (an apex that redirects to www); the redirect is asked once,
    and only when its target is a name of this host's own group that passes the probe gate (a safe address, not excluded). It never follows
    redirects to anywhere else and never asks the scanner to follow redirects itself."""
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


def _probe_recent(project_id, host):
    """Whether the WordPress probe read a signature on this host within the last day."""
    from cveFeed.models import ProbeObservation
    return ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), probe='wordpress-detect', kind='wordpress', outcome='found',
                                           observed_at__gte=timezone.now() - RECENT_PROBE).exists()


def _target_permitted(host, project):
    from cveFeed import probes
    try:
        return bool(probes._permitted(host, project))
    except Exception:  # noqa: BLE001 - a name that cannot be checked is not followed
        return False


def _probe_positive(project_id, host):
    """Whether the WordPress probe read a signature on this host (a stored result, for a host the probe skipped this scan as fresh)."""
    from cveFeed.models import ProbeObservation
    return ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), probe='wordpress-detect', kind='wordpress', outcome='found').exists()


def _hint(reason, token):
    return ('the edge refused or challenged the scan (' + _redact(reason, token)[:120] + '). Allow the scanner\'s address or user agent in the WAF or '
            'bot rules for this host, then rescan; cvENGINE never tries to get past a challenge')


def _register():
    from agentapi import stage_runs
    stage_runs.adapter('wpscan.quick', queue='wpscan_queue')(_resume_quick)


_register()
