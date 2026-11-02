"""JavaScript libraries a web page loads: which library each script is, the version the file itself states, and which copy runs.

A library version is read from the FILE: its comment banner (``/*! jQuery v3.2.1 | (c) JS Foundation``, ``jQuery JavaScript Library v3.2.1``,
``jQuery UI - v1.12.1``, ``Bootstrap v4.6.0``) or, for a few libraries, a code signature that only the library's own file has (jQuery's
``X.fn = X.prototype = {jquery: version`` with the version string it names). The script's URL is only a hint:

- a version in a query string (``jquery.min.js?ver=1.0.4``) is never a version. WordPress and most themes put their own asset version there
  (the cache-buster of a theme at 1.0.4 is not jQuery 1.0.4); it is recorded on the copy as ``query_version`` so correlation can recognise
  the same string arriving from another tool, and never used;
- a version in the file name or a CDN path (``jquery-3.4.1.min.js``, ``/ajax/libs/jquery/3.4.1/jquery.min.js``) is used only when the
  body could not be read or states no version (a minified file with its banner stripped), labelled ``version_source='filename'`` with a low
  ``version_confidence``. It never proves a vulnerable range on its own (the version-only ceiling of ``triage`` already holds such a match
  at needs_validation, and correlation caps its confidence);
- one script names one library by its name: ``bootstrap.min.js?ver=1.0.4`` is Bootstrap (no version) and nothing else, and a jQuery plugin
  (``jquery.fancybox.js``) is not jQuery.

Several copies of a library on one page are all recorded (``copies``, in document order; a ``<script>`` in an HTML comment or in another
script's text is not a copy, a ``document.write`` fallback is a ``fallback``). Scripts run in document order (``defer`` and module scripts
after the others, ``async`` in no knowable order), and a later full load of a library replaces the global the earlier one set, unless the page
calls ``jQuery.noConflict(true)``. So the last copy in execution order is ``effective`` and the earlier ones ``shadowed``, when that last
copy's own file was read and states its version; otherwise (a copy not served or not read, a file name against a banner, ``async``,
``noConflict(true)``) the record says ``copies_unresolved``. Correlation matches the effective copy as usual, keeps a shadowed copy or a
fallback as a candidate at SHADOWED_CAP and each copy of an unresolved set at UNRESOLVED_CAP: nothing the page loads is hidden.

Fetching is the caller's (``cveFeed.route_auth._read_scripts`` and the ``html-libraries`` probe), through the same pinned, bounded,
anonymous GET as every route check, and only for scripts the page itself references (``vetter``): its own host, a host of the same site that
the project itself holds (not for a host-scoped, passive or manual only target), or a public library CDN, on port 80, 443 or the page's own.
Budgets per page host, per script host and per scan (``Reader``); what was read is cached by URL, per project, with its ETag or length.
``CVENGINE_SCRIPT_BODY_READ=0`` turns reading off. Everything here except ``read_page`` (and its cache and budget) is pure."""
import hashlib
import itertools
import logging
import os
import re
import threading
import time
from urllib.parse import parse_qsl, urljoin, urlsplit

logger = logging.getLogger(__name__)

MAX_SCRIPTS_PER_HOST = 6     # scripts read per page host, all its pages and web bases together
MAX_SCRIPT_BYTES = 300 * 1024  # of the decoded body of one script
MAX_PER_SCRIPT_HOST = 40     # requests one script host (a shared static host, a CDN) receives in one scan
SCRIPT_HOST_GAP = 0.5        # seconds between two requests to one script host, across every worker of the scan
DEFAULT_MAX_REQUESTS, DEFAULT_MAX_SECONDS = 300, 600  # script requests and seconds of reading per scan (CVENGINE_SCRIPT_READ_MAX_*)
MAX_ENTRIES = 80             # script tags read from one page
MAX_COPIES = 8               # copies of one library kept on the record
HEAD = 4096                  # a banner is in the first bytes of a file
SCAN = 128 * 1024            # a code signature is looked for this far in
CACHE_SECONDS = 24 * 3600    # a site's own script, or a CDN URL with no version in it, is read again after a day
CDN_CACHE_SECONDS = 30 * 24 * 3600  # a versioned file on a public CDN does not change
CACHE_KEEP_SECONDS = 30 * 24 * 3600  # how long an entry is kept to send its ETag back (If-None-Match) once it is due again
CONFIDENCE = {'banner': 0.9, 'signature': 0.8, 'filename': 0.4}
UNRESOLVED_CAP = 0.5         # the most a copy of an unresolved set may be trusted
SHADOWED_CAP = 0.4           # the most a copy a later one replaces (or a fallback) may be trusted: kept, never hidden

# key -> (product name stored on the host, file name stems, extra directory names a CDN uses for it)
LIBRARIES = {
    'jquery': ('jQuery', ('jquery', 'jquery-slim'), ()),
    'jquery-ui': ('jQuery UI', ('jquery-ui', 'jqueryui'), ('jqueryui', 'ui')),
    'jquery-migrate': ('jQuery Migrate', ('jquery-migrate',), ()),
    'bootstrap': ('Bootstrap', ('bootstrap', 'bootstrap-bundle'), ('twitter-bootstrap',)),
    'angularjs': ('AngularJS', ('angular', 'angularjs'), ('angular.js',)),
    'react': ('React', ('react', 'react-dom'), ()),
    'vue': ('Vue.js', ('vue',), ()),
    'lodash': ('Lodash', ('lodash',), ('lodash.js',)),
    'moment': ('Moment.js', ('moment', 'moment-with-locales'), ('moment.js',)),
    'underscore': ('Underscore.js', ('underscore',), ('underscore.js',)),
    'swiper': ('Swiper', ('swiper', 'swiper-bundle'), ()),
    'datatables': ('DataTables', ('datatables', 'jquery-datatables'), ('datatables.net',)),
}
PRODUCTS = {product.lower(): key for key, (product, _s, _d) in LIBRARIES.items()}
_STEMS = {stem: key for key, (_p, stems, _d) in LIBRARIES.items() for stem in stems}
_DIRS = {**_STEMS, **{d: key for key, (_p, _s, dirs) in LIBRARIES.items() for d in dirs}}

# hosts that serve published library files: a versioned file there is the library itself, and reading it touches no target
CDN_HOSTS = ('code.jquery.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'fastly.jsdelivr.net', 'unpkg.com', 'ajax.googleapis.com',
             'ajax.aspnetcdn.com', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'netdna.bootstrapcdn.com',
             'cdn.datatables.net', 'cdn.staticfile.org', 'lib.baomitu.com')
# third-party analytics and advertising: never read, whatever the page says
ANALYTICS = ('googletagmanager.com', 'google-analytics.com', 'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
             'facebook.net', 'connect.facebook.net', 'hotjar.com', 'segment.com', 'segment.io', 'clarity.ms', 'hs-scripts.com',
             'hs-analytics.net', 'hsforms.net', 'mxpnl.com', 'mixpanel.com', 'newrelic.com', 'nr-data.net', 'quantserve.com',
             'scorecardresearch.com', 'adobedtm.com', 'omtrdc.net', 'demdex.net', 'linkedin.com', 'licdn.com', 'twitter.com',
             'ads-twitter.com', 'tiktok.com', 'bing.com', 'yandex.ru', 'cloudflareinsights.com', 'pinimg.com', 'snapchat.com')

_VERSION = r'(\d{1,4}\.\d{1,4}(?:\.\d{1,4})?)'
_SUFFIXES = ('min', 'slim', 'prod', 'production', 'umd', 'esm', 'global', 'full', 'pack', 'packed', 'dev', 'development', 'browser',
             'runtime', 'cjs', 'custom')
_SUFFIX_RE = re.compile(r'[.-](?:' + '|'.join(_SUFFIXES) + r')$')
_FILE_VERSION_RE = re.compile(r'[.-]v?' + _VERSION + r'$')
_DIR_VERSION_RE = re.compile(r'^v?' + _VERSION + r'$')

# ------------------------------------------------------------------ what the file states

# a banner line: the start of a comment or a line inside one. One run of blanks on each side of the comment mark, never two runs that could
# share the same blanks (a line of 300 KB of spaces is read once, not split every way)
_LINE = r'(?m)^﻿?[ \t]*(?:(?:/\*+!?|\*|//!?)[ \t]*)?'
_BANNERS = (
    ('jquery', re.compile(_LINE + r'jQuery (?:JavaScript Library )?v' + _VERSION + r'(?=[\s|,-]|$)')),
    ('jquery', re.compile(_LINE + r'jQuery ' + _VERSION + r' - New Wave')),
    ('jquery-ui', re.compile(_LINE + r'jQuery UI(?: [A-Z][A-Za-z]{1,20})? (?:- )?v?' + _VERSION + r'\b')),
    ('jquery-migrate', re.compile(_LINE + r'jQuery Migrate (?:- )?v?' + _VERSION + r'\b')),
    ('bootstrap', re.compile(_LINE + r'Bootstrap v' + _VERSION + r'\b')),
    ('bootstrap', re.compile(_LINE + r'bootstrap-(?:transition|modal|dropdown|scrollspy|tab|tooltip|popover|alert|button|collapse|carousel'
                             r'|typeahead|affix)\.js v' + _VERSION + r'\b')),
    ('angularjs', re.compile(r'@license AngularJS v' + _VERSION + r'\b')),
    ('react', re.compile(r'@license React v' + _VERSION + r'\b')),
    ('vue', re.compile(_LINE + r'Vue\.js v' + _VERSION + r'\b')),
    ('lodash', re.compile(_LINE + r'(?:@license )?lodash ' + _VERSION + r'\b', re.IGNORECASE)),
    ('moment', re.compile(r'(?m)^//! moment\.js[ \t]*\r?\n//! version[ \t]*:[ \t]*' + _VERSION + r'\b')),
    ('underscore', re.compile(_LINE + r'Underscore\.js ' + _VERSION + r'\b')),
    ('swiper', re.compile(_LINE + r'Swiper ' + _VERSION + r'\b')),
    ('datatables', re.compile(_LINE + r'DataTables ' + _VERSION + r'\b')),
)
# jQuery's own prototype: ``jQuery.fn = jQuery.prototype = { jquery: version`` (minified ``k.fn=k.prototype={jquery:f``) and the version string
# the variable was given just before it, or the literal itself in old releases. Bounded names and gaps: the scanned host controls the text.
_JQ_PROTO = re.compile(r'([A-Za-z_$][\w$]{0,30})\.fn\s{0,8}=\s{0,8}\1\.prototype\s{0,8}=\s{0,8}\{')
_JQ_KEY = re.compile(r'(?<![\w$.])jquery\s{0,8}:\s{0,8}(?:["\']' + _VERSION + r'["\']|([A-Za-z_$][\w$]{0,30})\b)')
_SIGNATURES = (
    ('jquery-ui', re.compile(r'\.ui\.version\s{0,8}=\s{0,8}["\']' + _VERSION + r'["\']')),
    ('jquery-ui', re.compile(r'\.extend\(\s{0,8}[\w$]{1,30}\.ui\s{0,8},\s{0,8}\{\s{0,8}version\s{0,8}:\s{0,8}["\']' + _VERSION + r'["\']')),
    ('jquery-migrate', re.compile(r'\.migrateVersion\s{0,8}=\s{0,8}["\']' + _VERSION + r'["\']')),
    ('bootstrap', re.compile(r'\b(?:Modal|Tooltip|Popover|Collapse|Carousel|Dropdown|Button|Alert|Affix|ScrollSpy|Tab)\.VERSION\s{0,8}=\s{0,8}'
                             r'["\']' + _VERSION + r'["\']')),
)


def _jquery_signature(text):
    """The version jQuery's own prototype names, or ''."""
    for proto in itertools.islice(_JQ_PROTO.finditer(text), 5):  # the library has one; a page of look-alikes is not read on and on
        window = text[proto.end():proto.end() + 6000]
        key = _JQ_KEY.search(window)
        if not key:
            continue
        if key.group(1):
            return key.group(1)
        name = re.escape(key.group(2))
        before = text[max(0, proto.start() - 4000):proto.start()]
        assigned = list(re.finditer(r'(?<![\w$.])' + name + r'\s{0,8}=\s{0,8}["\']' + _VERSION + r'["\']', before))
        if assigned:
            return assigned[-1].group(1)
    return ''


def read_body(text):
    """``[(library key, version, how)]`` the text of one script states: ``how`` is ``banner`` (a comment at the top of the file names it) or
    ``signature`` (code only the library's own file has). One entry per library, the banner first. A bundle that carries several libraries
    names each."""
    text = text or ''
    head, body = text[:HEAD], text[:SCAN]
    out, seen = [], set()
    for key, pattern in _BANNERS:
        found = pattern.search(head)
        if found and key not in seen:
            seen.add(key)
            out.append((key, found.group(1), 'banner'))
    if 'jquery' not in seen:
        version = _jquery_signature(body)
        if version:
            seen.add('jquery')
            out.append(('jquery', version, 'signature'))
    for key, pattern in _SIGNATURES:
        if key in seen:
            continue
        found = pattern.search(body)
        if found:
            seen.add(key)
            out.append((key, found.group(1), 'signature'))
    return out


# ------------------------------------------------------------------ what the URL says (a hint at most)

def identify(url):
    """``{'library', 'filename_version', 'query_version'}`` for one script URL: the library its file name is (one name, one library), the
    version its file name or CDN directory carries (a hint), and the version a query string carries (never used)."""
    out = {'library': '', 'filename_version': '', 'query_version': ''}
    try:
        parts = urlsplit(url or '')
    except ValueError:
        return out
    for key, value in parse_qsl(parts.query or '', keep_blank_values=False)[:20]:
        if key.lower() in ('ver', 'v', 'version') and re.fullmatch(_VERSION, value.strip()):
            out['query_version'] = value.strip()
            break
    segments = [s for s in (parts.path or '').split('/') if s][-8:]
    if not segments:
        return out
    stem = segments[-1].lower()
    if not stem.endswith('.js'):
        return out
    stem = stem[:-3]
    version = ''
    for _ in range(4):  # jquery-3.4.1.min, jquery.min, jquery-ui.custom.min-1.12.1 ...
        trimmed = _SUFFIX_RE.sub('', stem)
        found = _FILE_VERSION_RE.search(trimmed)
        if found and not version:
            version, trimmed = found.group(1), trimmed[:found.start()]
        if trimmed == stem:
            break
        stem = trimmed
    library = _STEMS.get(re.sub(r'[._]', '-', stem))
    if not library:
        return out
    out['library'] = library
    if not version:  # a CDN path: /ajax/libs/jquery/3.4.1/jquery.min.js, /npm/jquery@3.4.1/dist/jquery.min.js, /bootstrap/4.6.0/js/...
        for index, segment in enumerate(segments[:-1]):
            name, at, tagged = segment.lower().partition('@')
            if at and _DIRS.get(name) == library and _DIR_VERSION_RE.match(tagged):
                version = _DIR_VERSION_RE.match(tagged).group(1)
                break
            if _DIRS.get(name) == library and index + 1 < len(segments) - 1 and _DIR_VERSION_RE.match(segments[index + 1]):
                version = _DIR_VERSION_RE.match(segments[index + 1]).group(1)
                break
    out['filename_version'] = version
    return out


# ------------------------------------------------------------------ the page: scripts in document order

_SCRIPT_OPEN = re.compile(r'<script\b([^<>]{0,2000})>', re.IGNORECASE)
_ATTR = re.compile(r'''([^\s"'<>/=]{1,40})(?:\s{0,4}=\s{0,4}(?:"([^"]{0,1000})"|'([^']{0,1000})'|([^\s"'<>`=]{1,1000})))?''')
_JS_TYPES = ('', 'text/javascript', 'application/javascript', 'application/x-javascript', 'text/ecmascript', 'module')
NOCONFLICT = re.compile(r'\.noConflict\(\s{0,4}(?:true|!0)\s{0,4}\)')
# ``window.jQuery || document.write('<script src="/js/jquery-1.8.3.min.js"><\/script>')``: a copy the page loads only when another failed
_WRITE_SRC = re.compile(r'''document\.write(?:ln)?\(\s{0,8}["']\s{0,8}<script\b[^<>]{0,300}?\bsrc\s{0,4}=\s{0,4}\\?["']?([^"'\\\s<>]{1,500})''',
                        re.IGNORECASE)
MAX_INLINE = 65536  # of an inline script, read for noConflict and fallbacks


def _attributes(text):
    """The attributes of a tag, lower-case names, the first of a repeated name (as a browser reads them). A value is never read as a name:
    ``data-x=" type=foo"`` is one attribute."""
    out = {}
    for found in _ATTR.finditer(text or ''):
        name = found.group(1).lower()
        if name not in out:
            out[name] = next((g for g in found.groups()[1:] if g is not None), None)
    return out


def _absolute(value, page_url):
    """The absolute http(s) URL a ``src`` names, or None: whitespace around it is dropped (as a browser does); another scheme, a backslash or
    user information (which browsers and Python read differently) is never followed."""
    value = (value or '').strip()
    if not value or '\\' in value or any(ord(c) < 32 for c in value):
        return None
    try:
        absolute = urljoin(page_url or '', value)
        parts = urlsplit(absolute)
        parts.port  # noqa: B018 - raises for a port that is not a number
    except ValueError:
        return None
    if parts.scheme not in ('http', 'https') or not parts.hostname or '@' in parts.netloc:
        return None
    return absolute[:1000]


def parse_page(body, page_url):
    """The page's scripts in document order: ``[{'order', 'url', 'timing', 'noconflict', 'fallback'}]``. ``url`` is absolute (None for an
    inline script); ``timing`` is ``sync``, ``defer`` (also a module script) or ``async``; ``noconflict`` marks an inline script that calls
    ``noConflict(true)``; ``fallback`` marks a script an inline ``document.write`` loads only when an earlier one failed (it never replaces the
    copy that did load). The page is read the way a browser tokenizes it: a ``<script>`` inside an HTML comment or inside another script's
    text is not a script. ``nomodule`` scripts (skipped by every current browser), non-JavaScript types and ``data:`` or other non-HTTP
    sources are left out."""
    text = body or ''
    lower = text.lower()
    out, pos, order = [], 0, 0
    while len(out) < MAX_ENTRIES:
        start = lower.find('<script', pos)
        if start == -1:
            break
        comment = lower.find('<!--', pos, start)
        if comment != -1:  # a comment before the next tag hides everything up to its end, tags included
            end = lower.find('-->', comment + 4)
            if end == -1:
                break
            pos = end + 3
            continue
        tag = _SCRIPT_OPEN.match(text, start)
        if not tag:
            pos = start + 7
            continue
        close = lower.find('</script', tag.end())
        inner = text[tag.end():close if close != -1 else len(text)]
        pos = close + 8 if close != -1 else len(text)
        this = order
        order += 1
        attrs = _attributes(tag.group(1))
        kind = (attrs.get('type') or '').split(';')[0].strip().lower()
        if kind not in _JS_TYPES or 'nomodule' in attrs:
            continue
        timing = 'async' if 'async' in attrs else 'defer' if ('defer' in attrs or kind == 'module') else 'sync'
        if 'src' in attrs:
            url = _absolute(attrs['src'], page_url)
            if url:
                out.append({'order': this, 'url': url, 'timing': timing, 'noconflict': False})
            continue
        inline = inner[:MAX_INLINE]
        out.append({'order': this, 'url': None, 'timing': 'sync' if kind != 'module' else 'defer', 'noconflict': bool(NOCONFLICT.search(inline))})
        for written in itertools.islice(_WRITE_SRC.finditer(inline), 3):
            url = _absolute(written.group(1), page_url)
            if url and len(out) < MAX_ENTRIES:
                out.append({'order': this, 'url': url, 'timing': 'sync', 'noconflict': False, 'fallback': True})
    return out


# ------------------------------------------------------------------ which hosts may be read

_PRIVATE_SUFFIXES = None


def _site(name):
    """The registrable domain of a host name (``static.example.com`` -> ``example.com``), read with the public suffix list's private section
    too, so a tenant of a platform (``a.blogspot.com``, ``x.herokuapp.com``) is its own site; a name under a shared platform cvENGINE lists
    is its own site too; the last two labels under a suffix the list does not know (``corp.internal``); None for an address."""
    global _PRIVATE_SUFFIXES
    from targetApp.shared_domains import shared_domain_of
    from targetApp.target_types import DOMAIN, apex_domain, classify_target
    name = (name or '').lower().rstrip('.')
    if classify_target(name) != DOMAIN:
        return None
    if shared_domain_of(name):
        return name
    try:
        if _PRIVATE_SUFFIXES is None:
            import tldextract
            _PRIVATE_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
        site = _PRIVATE_SUFFIXES(name).top_domain_under_public_suffix
    except Exception:  # noqa: BLE001 - no suffix list: the plain registrable domain
        site = apex_domain(name)
    return site or '.'.join(name.split('.')[-2:])


def _same_site(host, page_host):
    site = _site(page_host)
    return bool(site) and site == _site(host)


def _under(host, domains):
    return any(host == d or host.endswith('.' + d) for d in domains)


def kind_of(url, page_url):
    """``same-host``, ``same-site``, ``cdn``, ``analytics`` or ``third-party`` for a script of the page at ``page_url``."""
    host = (urlsplit(url).hostname or '').lower().rstrip('.')
    page_host = (urlsplit(page_url or '').hostname or '').lower().rstrip('.')
    if _under(host, ANALYTICS):
        return 'analytics'
    if host == page_host:
        return 'same-host'
    if host in CDN_HOSTS:
        return 'cdn'
    if page_host and _same_site(host, page_host):
        return 'same-site'
    return 'third-party'


def enabled():
    """``CVENGINE_SCRIPT_BODY_READ=0`` (or false, no, off) turns script reading off: a script's name stays a hint, nothing is fetched."""
    return os.environ.get('CVENGINE_SCRIPT_BODY_READ', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _held_back(target):
    """Why a page of ``target`` (a Domain) has no scripts read, or '': a passive target is never connected to beyond what discovery asked, and a
    manual only one ("just add it, do not scan yet") not at all."""
    from targetApp.models import Domain
    mode = getattr(target, 'discovery_mode', '')
    if mode in (Domain.DISCOVERY_PASSIVE, Domain.DISCOVERY_MANUAL):
        return f'{mode} target'
    return ''


def vetter(page_url, project=None, gate=None, target=None):
    """``vet(url)``: '' when a script may be read, else why not. Nothing is read when script reading is off or the page's target is passive or
    manual only. Only ports 80, 443 and the page's own are read. A third-party or analytics script is never read. Another host of the same
    site is read only when the target is not host scoped and the host is one of this project's own inventoried hosts held by a target that is
    neither manual only nor passive; it then passes, like a CDN, the SSRF address check and the organization's exclusions and archived hosts,
    and the bug bounty program's scope. Each host is asked once. The page's own host was vetted before the page was read; the pinned transport
    vets every address again when it connects."""
    memo = {}
    page = urlsplit(page_url or '')
    try:
        page_port = page.port or (443 if page.scheme == 'https' else 80)
    except ValueError:
        page_port = None
    held = '' if enabled() else 'script reading is off'
    held = held or (_held_back(target) if target is not None else '')

    def vet(url):
        if held:
            return held
        try:
            port = urlsplit(url).port
        except ValueError:
            return 'bad port'
        if port not in (None, 80, 443, page_port):
            return 'port'
        kind = kind_of(url, page_url)
        if kind in ('analytics', 'third-party'):
            return kind
        if kind == 'same-host':
            return ''
        host = (urlsplit(url).hostname or '').lower().rstrip('.')
        if host not in memo:
            memo[host] = _refusal(host, kind, project, gate, target)
        return memo[host]
    return vet


def _refusal(host, kind, project, gate, target):
    from cveFeed import route_auth
    if kind == 'same-site':
        if not project:
            return 'not a host of this project'
        if target is not None and target.is_host_scoped():
            return 'host-scoped target'
        from cveFeed.manual_only import other_holder
        holder = other_holder(project, host)
        if holder is None:
            return 'not a host of this project'  # never inventoried, or held only by a manual only target
        if _held_back(holder):
            return f'held by a {_held_back(holder)}'
    if not route_auth.host_allowed(host, project):
        return 'address not allowed'
    if project:
        from cveFeed.archive_rediscovery import archived_names
        from cveFeed.exclusions import is_excluded
        if is_excluded(project, host) or host in archived_names(project):
            return 'excluded'
        if kind == 'same-site':
            from cveFeed.bounty_gate import Gate
            reason = (gate or Gate(blocked=())).refusal(project, host, unattended=False)
            if reason:
                return 'outside the bug bounty scope'
    return ''


# ------------------------------------------------------------------ one scan's budget

def _int_env(name, default):
    try:
        return max(1, int(os.environ.get(name, '')))
    except ValueError:
        return default


class Reader:
    """One scan's script reading, shared by every worker: at most ``max_requests`` script requests and ``max_seconds`` of reading in the scan,
    MAX_PER_SCRIPT_HOST requests to any one script host with SCRIPT_HOST_GAP seconds between two of them, and each script URL read once per scan
    (a static host that many page hosts share is asked once). ``fresh`` (a forced re-test) reads past the cache, sending the stored ETag."""

    def __init__(self, project=None, fresh=False, max_requests=None, max_seconds=None, clock=time.monotonic, sleep=time.sleep):
        self.project, self.fresh = project, fresh
        self.max_requests = max_requests or _int_env('CVENGINE_SCRIPT_READ_MAX_REQUESTS', DEFAULT_MAX_REQUESTS)
        self.max_seconds = max_seconds or _int_env('CVENGINE_SCRIPT_READ_MAX_SECONDS', DEFAULT_MAX_SECONDS)
        self.clock, self.sleep = clock, sleep
        self.started = clock()
        self.requests = 0
        self.by_host, self.next_at, self.seen = {}, {}, {}
        self.lock = threading.Lock()

    def known(self, url):
        with self.lock:
            return self.seen.get(url)

    def keep(self, url, outcome):
        with self.lock:
            self.seen[url] = outcome

    def admit(self, url):
        """'' and a reserved slot (after the gap to the script host has passed), or why the request is not made."""
        host = (urlsplit(url).hostname or '').lower()
        with self.lock:
            now = self.clock()
            if self.requests >= self.max_requests:
                return 'scan request limit'
            if now - self.started > self.max_seconds:
                return 'scan time limit'
            if self.by_host.get(host, 0) >= MAX_PER_SCRIPT_HOST:
                return 'script host limit'
            self.requests += 1
            self.by_host[host] = self.by_host.get(host, 0) + 1
            at = max(now, self.next_at.get(host, now))
            self.next_at[host] = at + SCRIPT_HOST_GAP
        if at > now:
            self.sleep(at - now)
        return ''


# ------------------------------------------------------------------ the cache (by URL, with the validator it was served with)

def _cache():
    try:
        from django.core.cache import cache
        return cache
    except Exception:  # noqa: BLE001 - no cache configured: every script is read
        return None


def _cache_key(url, project=None):
    """A public CDN file is the same for everyone; anything else is the project's own (an address only that project may reach, a tailnet
    device), so its entry is never read for another project."""
    scope = 'cdn' if kind_of(url, '') == 'cdn' else f'p{project or 0}'
    return f'jslib:v2:{scope}:' + hashlib.sha256(url.encode('utf-8', 'replace')).hexdigest()


def _fresh_for(url):
    """Seconds a cached reading of ``url`` is used without asking again: 30 days for a versioned file on a public CDN, a day otherwise (a CDN
    URL with no version in it, such as ``jquery-latest.js``, changes)."""
    if kind_of(url, '') == 'cdn' and identify(url)['filename_version']:
        return CDN_CACHE_SECONDS
    return CACHE_SECONDS


def _cached(url, project=None):
    cache = _cache()
    if cache is None:
        return None
    try:
        return cache.get(_cache_key(url, project))
    except Exception:  # noqa: BLE001
        return None


def _remember(url, read, project=None):
    """Keep what one script said with the ETag or length it was served with. Only an answer that carried a validator is kept."""
    if not (read.get('etag') or read.get('length')):
        return
    cache = _cache()
    if cache is None:
        return
    try:
        cache.set(_cache_key(url, project), {**read, 'checked': time.time()}, CACHE_KEEP_SECONDS)
    except Exception:  # noqa: BLE001
        pass


_ETAG = re.compile(r'^(?:W/)?"[\x21\x23-\x7e]{0,100}"$')


def _read_one(url, fetch, cached=None):
    """``(read, reason)`` for one script: what it states, or why nothing was read. A ``304`` to the stored ETag keeps the cached reading."""
    etag = (cached or {}).get('etag') or ''
    if etag and _ETAG.match(etag):
        got = fetch(url, headers={'If-None-Match': etag})
    else:
        got = fetch(url)
    status = (got or {}).get('status') or 0
    if status == 304 and cached:
        return {k: v for k, v in cached.items() if k != 'checked'}, ''
    if not 200 <= status < 300 or (got or {}).get('challenge'):
        return None, 'not served'
    text = got.get('body') or ''
    raw = got.get('bytes')
    size = raw if isinstance(raw, int) else len(text.encode('utf-8', 'replace'))
    truncated = size >= MAX_SCRIPT_BYTES
    headers = got.get('raw_headers') or {}
    return {'found': [list(f) for f in read_body(text)], 'truncated': truncated,
            'sha256': '' if truncated else hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest(),
            'etag': str(headers.get('etag') or '')[:120], 'length': str(headers.get('content-length') or '')[:20]}, ''


def _order_to_read(entries, page_url):
    """The scripts worth reading, best first: those whose name is a library, then the page's other same-host and same-site scripts (a bundle
    names its libraries in its banners), then the fallbacks an inline script would write. Scripts on a CDN are read only when their name is
    a library."""
    named, other, fallback = [], [], []
    for entry in entries:
        if not entry.get('url'):
            continue
        if entry.get('fallback'):
            fallback.append(entry)
        elif entry.get('library'):
            named.append(entry)
        elif kind_of(entry['url'], page_url) in ('same-host', 'same-site'):
            other.append(entry)
    return named + other + fallback


def read_page(entries, page_url, fetch, vet, budget, before_each=None, stop=None, reader=None, project=None):
    """Read the scripts of a parsed page (``parse_page``) through ``fetch(url)`` (the caller's pinned, bounded GET returning the route probe
    dict; called as ``fetch(url, headers={'If-None-Match': etag})`` to revalidate a cached reading) and return ``resolve``'s records. ``vet``
    is ``vetter``'s; ``budget`` is ``{'left': n}``, shared by every page of one host; ``reader`` is the scan's ``Reader`` (one is made when
    none is given); ``before_each()`` runs before each request, ``stop()`` ends the reading (a scan stop)."""
    reader = reader if reader is not None else Reader(project)
    project = project if project is not None else reader.project
    entries = [dict(e) for e in entries or []]
    for entry in entries:
        if entry.get('url'):
            entry.update(identify(entry['url']))
    for entry in _order_to_read(entries, page_url):
        url = entry['url']
        if stop is not None and stop():
            entry['skipped'] = 'scan stopped'
            continue
        try:
            reason = vet(url)
        except Exception:  # noqa: BLE001 - a host that cannot be vetted is not read
            logger.info('script host could not be vetted', exc_info=True)
            reason = 'not vetted'
        if reason:
            entry['skipped'] = reason
            continue
        known = reader.known(url)
        if known is not None:  # read already in this scan (a static host shared by many page hosts)
            entry.update({'read': known[0]} if known[0] is not None else {'skipped': known[1]})
            continue
        cached = _cached(url, project)
        if cached is not None and not reader.fresh and time.time() - (cached.get('checked') or 0) < _fresh_for(url):
            entry['read'] = {k: v for k, v in cached.items() if k != 'checked'}
            continue
        if budget.get('left', 0) <= 0:
            entry['skipped'] = 'page host limit'
            continue
        refused = reader.admit(url)
        if refused:
            entry['skipped'] = refused
            continue
        budget['left'] -= 1
        if before_each is not None:
            before_each()
        try:
            read, why = _read_one(url, fetch, cached)
        except Exception as exc:  # noqa: BLE001 - a script that cannot be read is skipped; its name stays a hint
            logger.info('script read failed: %s', type(exc).__name__)
            read, why = None, 'unreachable'
        reader.keep(url, (read, why))
        if read is None:
            entry['skipped'] = why
            continue
        entry['read'] = read
        _remember(url, read, project)
    return resolve(entries)


# ------------------------------------------------------------------ several copies: which one runs

def _execution_rank(entry):
    if entry['timing'] == 'async':
        return None
    return entry['order'] + (100000 if entry['timing'] == 'defer' else 0)


def _copies(entries):
    """``{library key: [copy]}`` from the read (or unread) scripts, in document order."""
    out = {}
    for entry in entries:
        if not entry.get('url'):
            continue
        read = entry.get('read') or None
        claims = {}
        for key, version, how in (read or {}).get('found') or []:
            claims.setdefault(key, (version, 'body', how))
        library = entry.get('library')
        if library and library not in claims:
            # the body was not read, or states no version (a minified file whose banner was stripped): the file name is a hint
            version = entry.get('filename_version') or ''
            claims[library] = (version, 'filename' if version else '', 'filename' if version else '')
        for key, (version, source, how) in claims.items():
            copy = {'url': entry['url'][:300], 'version': version, 'source': source, 'how': how, 'order': entry['order'],
                    'timing': entry['timing'], 'rank': _execution_rank(entry)}
            if entry.get('fallback'):
                copy['fallback'] = True
            if key == library and entry.get('query_version'):
                copy['query_version'] = entry['query_version']
            if key == library and entry.get('filename_version') and source == 'body' and entry['filename_version'] != version:
                copy['filename_version'] = entry['filename_version']  # the name said otherwise: the file wins
            if source == 'body' and read.get('sha256'):
                copy['sha256'] = read['sha256']
            if source != 'body':
                copy['not_read'] = entry.get('skipped') or ('no version in the file' if read is not None else 'not read')
            out.setdefault(key, []).append(copy)
    return out


def resolve(entries):
    """``{library key: record}`` for a page's scripts (``parse_page`` entries, with ``read`` where the body was read). A record names the
    effective copy (``version``, ``version_source``, ``version_confidence``, ``script_url``, ``script_sha256``), lists every ``copy`` with
    its ``state`` and says ``copies_unresolved`` (with ``unresolved_reason``) when the page does not show which one runs.

    The last copy in execution order is ``effective`` and the earlier ones ``shadowed`` only when that last copy's own file was read and states
    its version: a copy that was not served, not read or states no version may never have loaded, and a file name is never trusted over what a
    file states, so it never shadows another; the set is unresolved instead. A ``document.write`` fallback is a ``fallback``: it loads only
    when the copy before it failed. ``tech_names`` are every versioned copy: correlation (``HostLibraries.judge``) decides how far each is
    trusted."""
    noconflict = [_execution_rank(e) for e in entries if e.get('noconflict')]
    records = {}
    for key, copies in _copies(entries).items():
        product = LIBRARIES[key][0]
        ordered = sorted(copies, key=lambda c: (c['rank'] is None, c['rank'] if c['rank'] is not None else c['order']))
        ranked = [c for c in ordered if not c.get('fallback')]
        fallbacks = [c for c in ordered if c.get('fallback')]
        first = next((c['rank'] for c in ranked if c['rank'] is not None), None)
        for copy in ranked:
            if key == 'jquery' and copy['rank'] is not None and any(n is not None and n < copy['rank'] for n in noconflict):
                copy['loaded_after_noconflict'] = True
        reasons = []
        if not ranked:
            reasons.append('only a fallback the page loads when another script fails names it')
        elif len({c['version'] for c in ranked}) > 1:
            if any(c['rank'] is None for c in ranked):
                reasons.append('a copy is loaded with async, so the order the copies run in is unknown')
            if key == 'jquery' and first is not None and any(n is not None and n > first for n in noconflict):
                reasons.append('the page calls jQuery.noConflict(true) after a copy, which hands the global back to the earlier copy')
            if ranked[-1]['source'] != 'body':
                reasons.append(f'the last copy ({ranked[-1].get("not_read") or "unread"}) may not load and its file does not state its version')
        effective = ranked[-1] if ranked else fallbacks[-1]
        for copy in ranked:
            if reasons:
                copy['state'] = 'unresolved'
            elif copy is effective:
                copy['state'] = 'effective'
            else:
                copy['state'] = 'shadowed'
                if effective['version'] and effective['version'] != copy['version']:
                    copy['shadowed_by'] = effective['version']
        for copy in fallbacks:
            copy['state'] = 'fallback'
        if reasons:  # the record speaks for the last copy whose file states it (else the last versioned one), as a guess
            effective = (next((c for c in reversed(ordered) if c['version'] and c['source'] == 'body'), None)
                         or next((c for c in reversed(ordered) if c['version']), effective))
        confidence = CONFIDENCE.get(effective['how'], 0.0) if effective['version'] else 0.0
        if reasons:
            confidence = min(confidence, UNRESOLVED_CAP)
        names = [f'{product}:{v}' for v in dict.fromkeys(c['version'] for c in ordered if c['version'])]
        record = {'product': product, 'version': effective['version'], 'version_source': effective['source'] or '',
                  'version_confidence': confidence, 'how': effective['how'] or '', 'script_url': effective['url'],
                  'script_sha256': effective.get('sha256', ''), 'copies_unresolved': bool(reasons), 'tech_names': names or [product],
                  'copies': [{k: v for k, v in c.items() if k not in ('rank',)} for c in ordered][:MAX_COPIES]}
        if reasons:
            record['unresolved_reason'] = '; '.join(reasons)
        records[key] = record
    return records


def names_of(records):
    """``[(name, source)]`` the host stores for ``resolve``'s records: ``script:body`` or ``script:filename`` by where each version came from."""
    out = []
    for record in (records or {}).values():
        sources = {}
        for copy in record.get('copies') or []:
            if copy.get('version') and copy.get('source') == 'body':
                sources[copy['version']] = 'script:body'
        for name in record['tech_names']:
            out.append((name, sources.get(name.partition(':')[2], 'script:filename')))
    return out


_TOKENS = {re.sub(r'[^a-z0-9]', '', n) for n in (*PRODUCTS, *LIBRARIES)}


def is_library(name):
    """Whether a stored technology name (``jQuery:3.4.1``) or an advisory's product name (``jquery_ui``) is one of the libraries read here."""
    return re.sub(r'[^a-z0-9]', '', (name or '').split(':', 1)[0].lower()) in _TOKENS


# ------------------------------------------------------------------ correlation: which stored versions a match may stand on

FILENAME_SOURCES = ('script:name', 'script:filename')  # 'script:name' is how a name hint (or a ?ver= string) was labelled before 1.3.2
LEGACY_NOTE = ('read from the script name or its query string by a scan before 1.3.2; the next route check reads the file itself')
SHADOWED_NOTE = 'shadowed by {by} loaded later; older code or closures may still use it'
FALLBACK_NOTE = 'a fallback the page loads only when an earlier script fails to load'


class HostLibraries:
    """What one host's front page says about its libraries: the newest record per library (route check or ``html-libraries`` probe) and,
    for data recorded before records existed, the names read from script URLs. ``judge(product, version)`` tells correlation whether a
    stored version may make a match and with what evidence."""

    def __init__(self, records=None, legacy=None):
        self.records = records or {}  # library key -> record
        self.legacy = legacy or {}    # (library key, version) -> source, from fingerprints that predate records

    @classmethod
    def for_subdomain(cls, subdomain):
        from cveFeed.models import ProbeObservation, RouteAuth
        project = subdomain.target_domain.project_id if subdomain.target_domain_id else None
        if not project:
            return cls()
        host = subdomain.name.lower()
        dated, legacy = [], {}
        for row in RouteAuth.objects.filter(project_id=project, host=host, path='/', retired_at__isnull=True).only('evidence', 'checked_at'):
            evidence = row.evidence or {}
            if isinstance(evidence.get('libraries'), dict):
                dated += [(row.checked_at, key, rec) for key, rec in evidence['libraries'].items() if isinstance(rec, dict)]
            for found in evidence.get('fingerprints') or []:
                if isinstance(found, dict) and found.get('source') in FILENAME_SOURCES:
                    _legacy_add(legacy, found.get('name'), found['source'])
        for row in ProbeObservation.objects.filter(project_id=project, host=host, kind='version', probe__in=('html-libraries', 'headers-root')) \
                .only('product', 'version', 'source', 'evidence', 'observed_at'):
            record = (row.evidence or {}).get('library')
            if isinstance(record, dict) and PRODUCTS.get(str(record.get('product', '')).lower()):
                dated.append((row.observed_at, PRODUCTS[str(record['product']).lower()], record))
            elif row.source in FILENAME_SOURCES and row.version:
                _legacy_add(legacy, f'{row.product}:{row.version}', row.source)
        records = {}
        for when, key, record in sorted(dated, key=lambda item: (item[0] is not None, item[0] or 0)):
            records[key] = record  # the newest reading of each library wins
        return cls(records, legacy)

    def judge(self, product, version):
        """``(skip, evidence, cap)``: whether a stored ``product`` ``version`` must not make a match, the evidence a match carries, and the
        most its confidence may be (None: no cap). Only a version a script's query string or name carried, where the file itself states
        another or nothing, is skipped; a copy a later one replaces and a fallback stay candidates at SHADOWED_CAP."""
        key = PRODUCTS.get((product or '').strip().lower())
        if not key or not version:
            return False, {}, None
        record = self.records.get(key)
        if record is None:
            return self._judge_legacy(key, version)
        copies = [c for c in record.get('copies') or [] if isinstance(c, dict)]
        summary = [{k: c.get(k) for k in ('url', 'version', 'source', 'order', 'state', 'loaded_after_noconflict') if c.get(k) not in (None, '')}
                   for c in copies][:MAX_COPIES]
        base = {'copies': summary, **({'copies_unresolved': True} if record.get('copies_unresolved') else {})}
        mine = [c for c in copies if c.get('version') == version]
        rank = {'effective': 0, 'unresolved': 1, 'shadowed': 2, 'fallback': 3}
        mine.sort(key=lambda c: (rank.get(c.get('state'), 9), c.get('source') != 'body'))
        if mine:
            copy = mine[0]
            state, source = copy.get('state'), copy.get('source') or ''
            confidence = CONFIDENCE.get(copy.get('how') or '', 0.0)
            cap = CONFIDENCE['filename'] if source == 'filename' else None
            evidence = {**base, 'script_url': copy.get('url', ''), **({'script_sha256': copy['sha256']} if copy.get('sha256') else {}),
                        'version_source': source, 'copy_state': state}
            if state == 'unresolved':
                cap = min(cap if cap is not None else 1.0, UNRESOLVED_CAP)
            elif state in ('shadowed', 'fallback'):
                cap = min(cap if cap is not None else 1.0, SHADOWED_CAP)
                by = copy.get('shadowed_by') or record.get('version') or 'a later copy'
                evidence['version_note'] = SHADOWED_NOTE.format(by=by) if state == 'shadowed' else FALLBACK_NOTE
            evidence['version_confidence'] = min(confidence, cap) if cap is not None else confidence
            return False, evidence, cap
        if any(version in (c.get('query_version'), c.get('filename_version')) for c in copies):
            return True, {}, None  # the string a script's query or name carries, where the file states otherwise or nothing
        return False, {'copies': summary, 'version_source': 'other'}, None  # another tool read it; shown with what the page itself says

    def _judge_legacy(self, key, version):
        """A version stored before records existed, from a script's name or its query string (one cannot be told from the other any more):
        kept as a candidate at the file-name confidence, never dropped, until the next route check reads the file."""
        source = self.legacy.get((key, version))
        if source is None:
            return False, {}, None
        note = LEGACY_NOTE if source == 'script:name' else 'read from the script\'s file name only; the file itself was not read'
        return False, {'version_source': 'filename', 'version_confidence': CONFIDENCE['filename'], 'version_note': note}, CONFIDENCE['filename']


def _legacy_add(legacy, name, source):
    product, _, version = str(name or '').partition(':')
    key = PRODUCTS.get(product.strip().lower())
    if key and version:
        legacy.setdefault((key, version.strip()), source)


def legacy_roots(evidence):
    """Whether a stored root route's evidence predates script reading: library names from script URLs and no ``libraries`` record. Such a route
    is checked again at the next scan, inside its window, so the files themselves are read."""
    evidence = evidence or {}
    if isinstance(evidence.get('libraries'), dict):
        return False
    return any(isinstance(f, dict) and f.get('source') == 'script:name' and is_library(f.get('name')) for f in evidence.get('fingerprints') or [])
