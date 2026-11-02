"""Where a CMS states its own version: one table, read by whatever has a page in hand.

A product's version is rarely in one place and never in the same place on every site: a theme strips the generator tag, a CDN rewrites the
head, a hardened site hides the readme. What stays is that the core ships files whose version query string IS the core version, and that
some routes (a feed, a manifest) print it. The sources for a product are therefore data, ordered by cost:

* ``passive`` sources read pages the probe already fetched (no request): the generator tag, and the core's own versioned assets.
* ``asked`` sources are one extra GET, made only when no passive source answered.

Reading is pure (``read``) and keeps every candidate with its source, so a disagreement is visible in the evidence and the best source wins by
confidence, not by position in the page. The asset patterns name the files whose ``?ver=`` is the core version: a file that carries a
library's own version (jQuery, jquery-migrate, the ``dist`` script packages) says nothing about the core and is never listed. Reading the
first ``?ver=`` of any asset under ``/wp-includes/`` would store jQuery's 3.7.1 as the WordPress version of a site that runs 7.1.4.

Adding a product is adding a row to ``SOURCES`` (a version a page already carries) and, for a file a product serves its version in, a probe to
``cveFeed.probes.PROBES`` (Drupal's change log, Joomla's manifests, Magento's release notes). ``MARKERS`` is how a page says which product it is
(read by ``cveFeed.fingerprint``, so the name is a lead for those probes). The places to look were taken from CMSeeK's per-CMS version routines
(https://github.com/Tuhinshubhra/CMSeeK, GPL-3.0, credited in THIRD-PARTY.md), written here as data with the false-positive guards this scanner
needs: a bare major ("Drupal 10") is no version, and a library's own version is never a product's.
"""
import re

VERSION = r'(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)'


def _asset(path_pattern):
    """The core file ``path_pattern`` (a regex for the part after /wp-includes/ or /wp-admin/) with its version query string."""
    return re.compile(r'/wp-(?:includes|admin)/' + path_pattern + r'\?ver=' + VERSION + r'(?![\w.-])')


def _attr(path_pattern):
    """A page marker: the path appears in a src or href attribute (a post that merely mentions it in text is not a site that serves it)."""
    return re.compile(r"""(?:src|href|action)=["'][^"'\s]*""" + path_pattern, re.I)


# (pattern, product, source): how a page says which product serves it. The name alone is a lead: the probes that follow it find the version.
MARKERS = (
    (re.compile(r'/wp-content/|/wp-includes/'), 'WordPress', 'page:wp-content'),
    (re.compile(r'Drupal\.settings|drupalSettings|/sites/default/files/|/core/misc/drupal\.js'), 'Drupal', 'page:drupal'),
    (_attr(r'/(?:media/(?:system|jui|vendor)/|components/com_[a-z0-9_]+/|templates/[\w-]+/(?:css|js)/)'), 'Joomla', 'page:joomla'),
    (re.compile(r'index\.php\?option=com_[a-z0-9_]+'), 'Joomla', 'page:joomla'),
    (_attr(r'/(?:static/version\d{6,}/|skin/frontend/|media/catalog/product/|js/mage/)'), 'Magento', 'page:magento'),
    (re.compile(r'\bMage\.Cookies\b|mage/cookies'), 'Magento', 'page:magento'),
    (_attr(r'/(?:typo3temp/|typo3conf/)'), 'TYPO3', 'page:typo3'),
    (_attr(r'/umbraco/'), 'Umbraco', 'page:umbraco'),
    # forums: the footer link text is how a board says what it runs (a post that names MyBB is not the footer's closing tag)
    (re.compile(r'>MyBB(?: \d[\d.]*)?</a>'), 'MyBB', 'page:mybb'),
    (re.compile(r'\bsmf_(?:version|scripturl)\b|>SMF(?: \d[\d.]*)?</a>|/Themes/default/scripts/script\.js'), 'Simple Machines Forum', 'page:smf'),
    (re.compile(r'https?://(?:www\.)?phpbb\.com/|/styles/prosilver/'), 'phpBB', 'page:phpbb'),
    (re.compile(r'PunBB</a>'), 'PunBB', 'page:punbb'),
    (re.compile(r'Powered by XMB\b'), 'XMB', 'page:xmb'),
    (re.compile(r'Powered by YAF\.NET\b'), 'YetAnotherForum.NET', 'page:yaf'),
    (re.compile(r'/assets/nodebb\.min\.js'), 'NodeBB', 'page:nodebb'),
    (re.compile(r'data-xf-init|/js/xf/|Forum software by XenForo'), 'XenForo', 'page:xenforo'),
    (_attr(r'/clientscript/vbulletin'), 'vBulletin', 'page:vbulletin'),
    (re.compile(r'data-discourse-setup|/assets/discourse[-.]'), 'Discourse', 'page:discourse'),
    (re.compile(r'flarum-loading|/assets/forum(?:-[a-f0-9]{6,})?\.js'), 'Flarum', 'page:flarum'),
)


class Source:
    """One place a version is stated. ``where`` is ``body`` (any fetched page), a path the source is asked for, or ``header:<name>``."""
    __slots__ = ('label', 'pattern', 'confidence', 'path', 'header')

    def __init__(self, label, pattern, confidence, path=None, header=None):
        self.label, self.pattern, self.confidence, self.path, self.header = label, re.compile(pattern, re.I) if isinstance(pattern, str) else pattern, confidence, path, header


SOURCES = {
    'WordPress': (
        # passive: the generator tag is read by cveFeed.versions (it parses every generator tag of a page); these are the core's own assets
        Source('asset:emoji-release', _asset(r'js/wp-emoji-release(?:\.min)?\.js'), 0.85),
        Source('asset:embed', _asset(r'js/wp-embed(?:\.min)?\.js'), 0.85),
        Source('asset:block-library', _asset(r'css/dist/block-library/[\w.-]+\.css'), 0.85),
        Source('asset:core-css', _asset(r'css/(?:classic-themes|buttons|dashicons|admin-bar|editor)(?:\.min)?\.css'), 0.85),
        Source('asset:login-css', _asset(r'css/(?:login|forms|l10n)(?:\.min)?\.css'), 0.85),
        # asked: the feed prints the core version in its generator element unless a plugin removed it
        Source('feed:generator', r'<generator>\s*https?://wordpress\.org/\?v=' + VERSION + r'\s*</generator>', 0.9, path='/feed/'),
        Source('readme', r'Version\s+' + VERSION, 0.6, path='/readme.html'),
    ),
    # forums: the version is in the footer link or a script variable; a board that hides it states none, and a post that names a release is not read
    'MyBB': (Source('footer', r'>MyBB (' + VERSION[1:-1] + r')</a>', 0.85),),
    'Simple Machines Forum': (
        Source('footer', r'>SMF (' + VERSION[1:-1] + r')</a>', 0.85),
        Source('script:smf_version', r'smf_version\s*=\s*["\']SMF (' + VERSION[1:-1] + r')', 0.85),
    ),
    'PunBB': (Source('footer', r'PunBB</a> (' + VERSION[1:-1] + r')', 0.85),),
    'XMB': (Source('footer', r'Powered by XMB (' + VERSION[1:-1] + r')', 0.85),),
    'YetAnotherForum.NET': (Source('footer', r'Powered by YAF\.NET (' + VERSION[1:-1] + r')', 0.85),),
    'NodeBB': (Source('script:config', r'var config\s*=\s*\{[^}]{0,2000}?"version"\s*:\s*"(' + VERSION[1:-1] + r')"', 0.85),),
    'Vanilla': (Source('header:x-garden-version', r'Vanilla (' + VERSION[1:-1] + r')', 0.9, header='x-garden-version'),),
    'Drupal': (
        # Drupal 8 and later version their own core scripts with the core release; the vendored libraries beside them carry the library's version
        Source('asset:drupal.js', r'/core/misc/(?:drupal|drupalSettingsLoader|drupal\.init)(?:\.min)?\.js\?v=' + VERSION + r'(?![\w.-])', 0.85),
    ),
}


def passive(product):
    """The sources that read a page already fetched."""
    return [s for s in SOURCES.get(product, ()) if s.path is None]


def asked(product):
    """The sources that need their own request, as ``(path, [sources])`` in the order they are tried."""
    paths = {}
    for source in SOURCES.get(product, ()):
        if source.path:
            paths.setdefault(source.path, []).append(source)
    return list(paths.items())


def read(product, pages):
    """``[(version, source label, confidence)]`` for every candidate ``pages`` state, best first. ``pages`` is ``[(path, response)]``: a
    passive source reads each body, an asked source reads only the response for its own path."""
    found = []
    for source in SOURCES.get(product, ()):
        for path, response in pages:
            if not response or (source.path is not None and path != source.path):
                continue
            body = response.get('body') or ''
            if source.header:
                text = str((response.get('headers') or {}).get(source.header, ''))
            else:
                text = body
            match = source.pattern.search(text)
            if match:
                found.append((match.group(1), source.label, source.confidence))
                break
    # the most trusted source first; among equals, the version most sources agree on
    votes = {}
    for version, _label, _c in found:
        votes[version] = votes.get(version, 0) + 1
    return sorted(found, key=lambda f: (-f[2], -votes[f[0]], f[1]))


def best(product, pages):
    """``(version, label)`` of the best candidate, or ``('', '')``."""
    found = read(product, pages)
    return (found[0][0], found[0][1]) if found else ('', '')


# ----------------------------------------------------------------------------- one core per host

def key(name):
    """A product name as the correlation compares it: letters and digits, lowercase."""
    return re.sub(r'[^a-z0-9]', '', str(name or '').lower())


# a host serves one WordPress core, one Drupal core, one board: two versions of these are two claims about one thing, never two installs
SINGLE_INSTANCE = frozenset({key(product) for _p, product, _s in MARKERS} | {key(product) for product in SOURCES})
# libraries a core ships or its themes load: their version numbers are the usual wrong answer for a core's (jQuery 3.7.1 is not WordPress 3.7.1)
LIBRARIES = frozenset({'jquery', 'jquerymigrate', 'jqueryui', 'bootstrap', 'angularjs', 'react', 'vuejs', 'lodash', 'momentjs', 'underscorejs',
                       'swiper', 'datatables'})
TRUSTED = 0.6  # the least confidence at which a probe's reading of a product's version settles a dispute


def disproven(pairs, attested=None):
    """``{(product key, version)}`` a host's technologies state that the evidence shows are wrong, for ``pairs`` of ``(name, version)``.

    Only a version that is disproved is returned, never a guess at the right one. When a product that runs once per host has two versions:
    one a probe states (``attested``: ``{product key: {versions}}``, from what WPScan or a version probe read on this host) settles it, and
    the others are dropped; with none attested, a version that is also a library's version on the same host is the library's number read as
    the core's and is dropped, unless it is the only version left. A dispute neither rule settles keeps every version: a host's risk is never
    hidden by choosing between two claims at random."""
    attested = attested or {}
    cores, libraries = {}, set()
    for name, version in pairs:
        k = key(name)
        if not version:
            continue
        if k in SINGLE_INSTANCE:
            cores.setdefault(k, set()).add(version)
        elif k in LIBRARIES:
            libraries.add(version)
    out = set()
    for k, found in cores.items():
        if len(found) < 2:
            continue
        stated = found & set(attested.get(k, ()))
        if stated:
            out |= {(k, v) for v in found - stated}
            continue
        borrowed = found & libraries
        if borrowed and found - borrowed:
            out |= {(k, v) for v in borrowed}
    return out


def attested(project_id, host, keys):
    """``{product key: {versions}}`` a probe read on this host for the products in ``keys``: WPScan's core, the WordPress probe, a version probe."""
    from cveFeed.models import ProbeObservation
    found = {}
    rows = ProbeObservation.objects.filter(project_id=project_id, host=str(host).lower(), outcome='found', confidence__gte=TRUSTED) \
        .exclude(version='').values_list('product', 'version')
    for product, version in rows:
        if key(product) in keys:
            found.setdefault(key(product), set()).add(version)
    return found


def superseded(subdomain, technologies):
    """``{(product key, version)}`` of ``subdomain``'s technologies that ``disproven`` rules out. Reads the probe evidence only when a one-core
    product has more than one version, so a host with no dispute costs no query. ``technologies`` is the host's Technology rows (or names)."""
    from cveFeed.correlation import split_name_version
    pairs = [split_name_version(getattr(t, 'name', t) or '') for t in technologies]
    seen = {}
    for name, version in pairs:
        if version and key(name) in SINGLE_INSTANCE:
            seen.setdefault(key(name), set()).add(version)
    disputed = {k for k, versions in seen.items() if len(versions) > 1}
    if not disputed:
        return set()
    project = subdomain.target_domain.project_id
    return disproven(pairs, attested(project, subdomain.name, disputed))
