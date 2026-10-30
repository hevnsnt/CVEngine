"""WordPress core older than the October 2026 security release (7.1.4 and its backports), and whether ``wp-content/upgrade/`` is reachable.

WordPress 7.1.4 (28 October 2026) fixes 22 vulnerabilities in core. The worst is an unauthenticated race condition in the core update process that
can end in remote code execution: while an update runs, the package is extracted into ``wp-content/upgrade/`` under a name an attacker can guess,
and that copy includes ``wp-admin/setup-config.php``, which starts on its own and can be pointed at a database the attacker controls. It needs
no account, but the attacker has to hit the seconds-long window an update takes, and ``wp-content/upgrade/`` has to be reachable over the web.
Wordfence reports exploitation attempts after the release. A firewall plugin cannot stop it (the extracted copy loads WordPress from its own
files, so the site's plugins never run for that request); denying the directory at the web server does. Sources: WordPress.org's 7.1.4 release
notes, Patchstack's and Wordfence's write-ups of it. No CVE number was published in them, so none is attached here: once the feed has one, the
ordinary CVE correlation matches it on the same version.

This module holds the fix table (the release for each branch), the version check, the classifier for the answer a ``wp-content/upgrade/`` request
draws, and the pipeline stage that turns what the WordPress probe and WPScan already recorded into a finding. It sends nothing itself: the one
extra request, a GET of the directory, is made by the WordPress probe (``cveFeed.probes``) on a site that is already known to be WordPress.
"""
import logging
import re

logger = logging.getLogger(__name__)

ADVISORY = 'WordPress 7.1.4 security release'
RELEASED = '2026-10-28'
SOURCE = 'wp-core-advisory'
TEMPLATE_ID = 'wordpress-core-update-window-rce'
FINDING_NAME = 'WordPress core is older than the October 2026 security release (unauthenticated update-window RCE)'
UPGRADE_PATH = '/wp-content/upgrade/'
UPGRADE_MISSING = '/wp-content/upgrade/cvengine-probe-7f3a/'  # a path that cannot exist under it
EXPOSED_NAME = 'WordPress wp-content/upgrade/ is reachable over the web'
REFERENCES = [
    'https://wordpress.org/documentation/wordpress-version/version-7-1-4/',
    'https://patchstack.com/articles/wordpress-7-1-4-security-release/',
    'https://www.wordfence.com/blog/2026/10/wordpress-7-1-4-security-release-rce/',
]

# The first release of each branch that has the fix, from the release notes ("WordPress x.y is affected ... Version a.b.c has been released").
FIXED = {
    '7.1': '7.1.4', '7.0': '7.0.8', '6.9': '6.9.11', '6.8': '6.8.12', '6.7': '6.7.11', '6.6': '6.6.11', '6.5': '6.5.14', '6.4': '6.4.14',
    '6.3': '6.3.14', '6.2': '6.2.15', '6.1': '6.1.16', '6.0': '6.0.18', '5.9': '5.9.20', '5.8': '5.8.19', '5.7': '5.7.21', '5.6': '5.6.23',
    '5.5': '5.5.24', '5.4': '5.4.25', '5.3': '5.3.27', '5.2': '5.2.30', '5.1': '5.1.28', '5.0': '5.0.31', '4.9': '4.9.35', '4.8': '4.8.34',
    '4.7': '4.7.39',
}
OLDEST_BRANCH = (4, 7)   # 4.6 and earlier no longer receive security updates: there is nothing to update to within the branch

PATCHED, BEHIND, UNSUPPORTED, NEWER, UNKNOWN = 'patched', 'behind', 'unsupported', 'newer', 'unknown'
_VERSION = re.compile(r'^\s*v?(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?(?P<rest>.*)$')


def parse(version):
    """``(major, minor, patch)`` from a WordPress version string, or None when it is not one. ``6.9`` is 6.9.0; a pre-release ("7.2-beta3")
    returns None: whether it has the fix cannot be said from its number."""
    found = _VERSION.match(str(version or ''))
    if not found or found.group('rest').strip():
        return None
    return int(found.group(1)), int(found.group(2)), int(found.group(3) or 0)


def assess(version):
    """``(state, fixed)``: ``patched``, ``behind`` (``fixed`` is the release that has the fix), ``unsupported`` (a branch before 4.7: no fix exists),
    ``newer`` (a branch this table does not know yet, newer than 7.1: not judged) or ``unknown`` (no usable version)."""
    parsed = parse(version)
    if parsed is None:
        return UNKNOWN, ''
    major, minor, patch = parsed
    fixed = FIXED.get(f'{major}.{minor}')
    if fixed is None:
        if (major, minor) < OLDEST_BRANCH:
            return UNSUPPORTED, ''
        return (NEWER, '') if (major, minor) > (7, 1) else (UNKNOWN, '')  # a branch between 4.7 and 7.1 that the table lacks: not judged
    return (PATCHED, fixed) if (major, minor, patch) >= parse(fixed) else (BEHIND, fixed)


# ----------------------------------------------------------------------------- the answer a wp-content/upgrade/ request draws

LISTING, REACHABLE, DENIED, UNKNOWN_DIR = 'listing', 'reachable', 'denied', 'unknown'
_LISTING = re.compile(r'<title>\s*Index of\s+/|<h1>\s*Index of\s+/|\[To Parent Directory\]|<a href="\?C=[NMSD];O=[AD]"', re.I)
BLANK = 16   # a body this short once stripped is WordPress's own index.php ("Silence is golden"), not a page


def classify_dir(response, missing=None):
    """What the answer to a GET of ``/wp-content/upgrade/`` says: ``listing`` (the server lists the directory), ``reachable`` (the directory
    answers 200 with an empty page, which is WordPress's own index.php: nothing denies the path, so the folder an update extracts into is
    served too), ``denied`` (401, 403, 404 or 410: something denies it, or it is not there) or ``unknown`` (a challenge, a redirect, an error,
    or a page that says nothing). ``missing`` is the answer for a path that cannot exist under it: when that also answers an empty 200, the
    server answers every path alike, which says nothing about this one."""
    if not response:
        return UNKNOWN_DIR
    if response.get('challenge'):
        return UNKNOWN_DIR
    status = response.get('status') or 0
    body = (response.get('body') or '')
    if status in (401, 403, 404, 410):
        return DENIED
    if status != 200:
        return UNKNOWN_DIR
    if _LISTING.search(body[:64 * 1024]):
        return LISTING
    if len(re.sub(r'<\?php.*?(?:\?>|\Z)|\s+', '', body, flags=re.S)) <= BLANK:
        if missing and (missing.get('status') or 0) == 200 and len(re.sub(r'\s+', '', missing.get('body') or '')) <= BLANK:
            return UNKNOWN_DIR   # every path under it answers the same empty page: a catch-all, not this directory
        return REACHABLE
    return UNKNOWN_DIR


# ----------------------------------------------------------------------------- the stage

def _severity(state, directory):
    """Behind the fix with the directory reachable is the condition the attack needs (4, critical); behind alone is 3 (the attacker has to hit a
    seconds-long window, so it is not practical on its own); a patched site whose directory is open is hygiene."""
    if state in (BEHIND, UNSUPPORTED):
        return 4 if directory in (LISTING, REACHABLE) else 3
    return 0


def _core_version(rows):
    """The core version a host's stored probe rows state: WPScan's reading first (it reads the core files), then the WordPress probe's."""
    wpscan = next((r for r in rows if r.probe == 'wpscan-core' and r.version), None)
    detect = next((r for r in rows if r.probe == 'wordpress-detect' and r.kind == 'wordpress' and r.outcome == 'found' and r.version), None)
    row = wpscan or detect
    return (row.version, row.probe) if row else ('', '')


def evaluate(scan, subs, rows_by_host=None):
    """Record the findings for the WordPress hosts of ``scan``: ``[(host, state, fixed, directory)]`` for the hosts judged. Reads only what the
    probe and WPScan stored, so a host probed before this check existed is judged on the next scan without a new request."""
    from cveFeed.models import ProbeObservation
    from reNgine.tasks import save_vulnerability
    project = scan.domain.project_id
    names = [s.name.lower() for s in subs]
    if rows_by_host is None:
        rows_by_host = {}
        for row in ProbeObservation.objects.filter(project_id=project, host__in=names, probe__in=('wpscan-core', 'wordpress-detect', 'wp-upgrade-dir')):
            rows_by_host.setdefault(row.host, []).append(row)
    out = []
    for sub in subs:
        rows = rows_by_host.get(sub.name.lower(), [])
        version, source = _core_version(rows)
        if not version:
            continue
        state, fixed = assess(version)
        directory = next((r.variant for r in rows if r.probe == 'wp-upgrade-dir' and r.kind == 'wp-upgrade-dir'), UNKNOWN_DIR)
        url = ((sub.http_url or f'https://{sub.name}').split('?')[0]).rstrip('/')
        if state in (BEHIND, UNSUPPORTED):
            severity = _severity(state, directory)
            if state == BEHIND:
                what = (f'WordPress {version} (read from {"WPScan" if source == "wpscan-core" else "the page"}) is older than {fixed}, the release of its '
                        f'branch that carries the {ADVISORY} ({RELEASED}).')
                fix = f'Update WordPress to {fixed} or later (or the current release, 7.1.4).'
            else:
                what = (f'WordPress {version} is on a branch that no longer receives security updates, so the fixes of the {ADVISORY} ({RELEASED}) '
                        'do not exist for it.')
                fix = 'Update WordPress to a supported branch (7.1.4 is the current release).'
            reach = {LISTING: ' The directory wp-content/upgrade/ is served and lists its contents.',
                     REACHABLE: ' The directory wp-content/upgrade/ is served (nothing denies it), which is the condition the attack needs.',
                     DENIED: ' wp-content/upgrade/ is denied or absent, which stops the attack even before the update.'}.get(directory, '')
            save_vulnerability(
                target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=url, name=FINDING_NAME, severity=severity,
                source=SOURCE, template_id=TEMPLATE_ID, type='rce', cve_ids=[], references=REFERENCES, tags=['wordpress', 'wordpress-core', 'rce'],
                description=('The security release fixes 22 vulnerabilities, the worst an unauthenticated race condition in the core update process that can '
                             'lead to remote code execution. It needs the seconds-long window an update takes and a reachable wp-content/upgrade/; '
                             'Wordfence reports exploitation attempts. ' + what + reach),
                remediation=(fix + ' Until then deny web access to wp-content/upgrade/ at the web server (a WordPress firewall plugin cannot stop '
                             'this) and check that the directory is not listable.'),
                extracted_results=[f'core version: {version}', f'fixed in: {fixed or "no fix for this branch"}', f'wp-content/upgrade/: {directory}'])
        elif state == PATCHED and directory in (LISTING, REACHABLE):
            save_vulnerability(
                target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=url + '/wp-content/upgrade/', name=EXPOSED_NAME, severity=1,
                source=SOURCE, template_id='wordpress-upgrade-dir-exposed', type='exposure', cve_ids=[], references=REFERENCES,
                tags=['wordpress', 'wordpress-core', 'hardening'],
                description=('WordPress extracts every update into wp-content/upgrade/, and until 7.1.4 the folder was predictable and could be used to run '
                             'the installer for a few seconds of every update. This site has the fix, but the directory is still served'
                             + (' and lists its contents' if directory == LISTING else '') + ', which gives an attacker the chance again if another '
                             'flaw like it appears.'),
                remediation='Deny web access to wp-content/upgrade/ at the web server and check that the directory is not listable.',
                extracted_results=[f'core version: {version}', f'wp-content/upgrade/: {directory}'])
        out.append((sub.name.lower(), state, fixed, directory))
    return out


def applicable(scan):
    """Whether any host of ``scan`` has a stored WordPress core version (so the stage has something to judge and adds no empty step to the scan)."""
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    names = Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True)
    return ProbeObservation.objects.filter(project_id=scan.domain.project_id, probe__in=('wpscan-core', 'wordpress-detect'), host__in=[n.lower() for n in names]) \
        .exclude(version='').exists()


def run_for_scan(scan_id):
    """The pipeline stage. Returns ``{'hosts': judged, 'behind': n, 'exposed': n}``."""
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    subs = list(Subdomain.objects.filter(scan_history=scan))
    judged = evaluate(scan, subs)
    return {'hosts': len(judged), 'behind': sum(1 for _h, s, _f, _d in judged if s in (BEHIND, UNSUPPORTED)),
            'exposed': sum(1 for _h, _s, _f, d in judged if d in (LISTING, REACHABLE))}
