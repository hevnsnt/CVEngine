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
