"""Whether a WordPress site's ``wp-content/upgrade/`` directory is reachable over the web.

WordPress 7.1.4 (28 October 2026) fixes an unauthenticated race condition in the core update process that can end in remote code execution: while
an update runs, the package is extracted into ``wp-content/upgrade/`` under a name an attacker can guess, and that copy includes
``wp-admin/setup-config.php``, which starts on its own and can be pointed at a database the attacker controls. It needs the seconds-long window an
update takes and a reachable directory; Wordfence reports exploitation attempts. A firewall plugin cannot stop it (the extracted copy loads
WordPress from its own files, so the site's plugins never run for that request); denying the directory at the web server does. Sources: the 7.1.4
release notes, Patchstack's and Wordfence's write-ups.

Whether a site runs a release that has the fix is the CVE pipeline's job: the version cveFeed.cms reads is matched against the advisory once the
feed has it. This module adds what no CVE record can say, whether the mitigation is in place: the WordPress probe (cveFeed.probes) asks a site it
already knows is WordPress for the directory (one GET, a second only to tell an empty page from a catch-all), ``classify_dir`` reads the answer,
and ``record_exposure`` turns a served directory into a finding.
"""
import re

UPGRADE_PATH = '/wp-content/upgrade/'
UPGRADE_MISSING = '/wp-content/upgrade/cvengine-probe-7f3a/'  # a path that cannot exist under it
SOURCE = 'wordpress-upgrade-dir'
TEMPLATE_ID = 'wordpress-upgrade-dir-exposed'
FINDING_NAME = 'WordPress wp-content/upgrade/ is reachable over the web'
REFERENCES = [
    'https://wordpress.org/documentation/wordpress-version/version-7-1-4/',
    'https://patchstack.com/articles/wordpress-7-1-4-security-release/',
    'https://www.wordfence.com/blog/2026/10/wordpress-7-1-4-security-release-rce/',
]

LISTING, REACHABLE, DENIED, UNKNOWN_DIR = 'listing', 'reachable', 'denied', 'unknown'
_LISTING = re.compile(r'<title>\s*Index of\s+/|<h1>\s*Index of\s+/|\[To Parent Directory\]|<a href="\?C=[NMSD];O=[AD]"', re.I)
BLANK = 16   # a body this short once stripped is WordPress's own index.php ("Silence is golden"), not a page


def classify_dir(response, missing=None):
    """What the answer to a GET of ``/wp-content/upgrade/`` says: ``listing`` (the server lists the directory), ``reachable`` (it answers 200 with
    an empty page, which is WordPress's own index.php: nothing denies the path, so the folder an update extracts into is served too), ``denied``
    (401, 403, 404 or 410: something denies it, or it is not there) or ``unknown`` (a challenge, a redirect, an error, or a page that says
    nothing). ``missing`` is the answer for a path that cannot exist under it: when that also answers an empty 200, the server answers every path
    alike, which says nothing about this one."""
    if not response or response.get('challenge'):
        return UNKNOWN_DIR
    status = response.get('status') or 0
    body = response.get('body') or ''
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


def record_exposure(scan, sub, state, version=''):
    """Record the finding for a served directory (``listing`` is medium, ``reachable`` low: hardening) on ``sub``. Returns True when one was saved."""
    if state not in (LISTING, REACHABLE):
        return False
    from reNgine.tasks import save_vulnerability
    url = ((sub.http_url or f'https://{sub.name}').split('?')[0]).rstrip('/') + UPGRADE_PATH
    save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=url, name=FINDING_NAME, severity=2 if state == LISTING else 1,
        source=SOURCE, template_id=TEMPLATE_ID, type='exposure', cve_ids=[], references=REFERENCES, tags=['wordpress', 'hardening'],
        description=('WordPress extracts every update into wp-content/upgrade/. Until WordPress 7.1.4 (and the backports of 28 October 2026) the '
                     'folder was predictable and could be used to run the installer for the few seconds an update takes, which ends in remote code '
                     'execution without an account. This directory is served' + (' and lists its contents' if state == LISTING else '') +
                     (f' (core version read: {version})' if version else '') + ', so a release without the fix is open to it and a release with the fix '
                     'has no protection if a flaw like it appears again.'),
        remediation='Deny web access to wp-content/upgrade/ at the web server (a WordPress firewall plugin cannot stop this), check that the directory '
                    'is not listable, and update WordPress to 7.1.4 or the fixed release of its branch.',
        extracted_results=[f'wp-content/upgrade/: {state}'] + ([f'core version: {version}'] if version else []))
    return True
