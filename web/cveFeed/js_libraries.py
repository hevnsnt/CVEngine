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

Several copies of a library on one page are all recorded (``copies``, in document order). Scripts run in document order (``defer`` and
module scripts after the others, ``async`` in no knowable order), and a later full load of a library replaces the global the earlier one
set, unless the page calls ``jQuery.noConflict(true)`` (which hands the global back). So the last copy in execution order is ``effective``
and the earlier ones ``shadowed``; correlation matches the effective copy only. When the order cannot be told from the page (an ``async``
copy, a ``noConflict(true)`` after a copy, a last copy with no readable version) the record says ``copies_unresolved`` and every versioned
copy stays a candidate at reduced confidence.

Fetching is the caller's (``cveFeed.route_auth._read_scripts`` and the ``html-libraries`` probe), through the same pinned, bounded,
anonymous GET as every route check, and only for scripts the page itself references: its own host, the same registrable site (each such
host vetted for address, exclusions and the bug bounty scope) or a public library CDN. At most MAX_SCRIPTS_PER_HOST scripts per host, at
most MAX_SCRIPT_BYTES of decoded body each; what was read is cached by URL with its ETag or length. Everything here except ``read_page``
(and its cache) is pure."""
import hashlib
import itertools
import logging
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

logger = logging.getLogger(__name__)

MAX_SCRIPTS_PER_HOST = 6     # scripts read per host, all pages and web bases together
MAX_SCRIPT_BYTES = 300 * 1024  # of the decoded body of one script
MAX_ENTRIES = 80             # script tags read from one page
MAX_COPIES = 8               # copies of one library kept on the record
HEAD = 4096                  # a banner is in the first bytes of a file
SCAN = 128 * 1024            # a code signature is looked for this far in
CACHE_SECONDS = 24 * 3600    # a site's own script, read again after a day
CDN_CACHE_SECONDS = 30 * 24 * 3600  # a versioned file on a public CDN does not change
CONFIDENCE = {'banner': 0.9, 'signature': 0.8, 'filename': 0.4}
UNRESOLVED_CAP = 0.5         # the most a copy of an unresolved set may be trusted

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

_LINE = r'(?m)^﻿?[ \t]*(?:/\*+!?|\*|//!?)?[ \t]*'  # a banner line: the start of a comment, or a line inside one
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

_SCRIPT_TAG = re.compile(r'<script\b([^<>]{0,2000})>', re.IGNORECASE)
_SRC = re.compile(r'''(?:^|\s)src\s{0,4}=\s{0,4}(?:"([^"<>]{1,500})"|'([^'<>]{1,500})'|([^"'\s<>]{1,500}))''', re.IGNORECASE)
_TYPE = re.compile(r'''(?:^|\s)type\s{0,4}=\s{0,4}["']?([^"'\s<>]{1,60})''', re.IGNORECASE)
_FLAG = re.compile(r'(?:^|\s)(async|defer)(?=[\s=/]|$)', re.IGNORECASE)
_JS_TYPES = ('', 'text/javascript', 'application/javascript', 'application/x-javascript', 'text/ecmascript', 'module')
NOCONFLICT = re.compile(r'\.noConflict\(\s{0,4}(?:true|!0)\s{0,4}\)')


def parse_page(body, page_url):
    """The page's scripts in document order: ``[{'order', 'url', 'timing', 'noconflict'}]``. ``url`` is absolute (None for an inline
    script), ``timing`` is ``sync``, ``defer`` (also a module script) or ``async``, ``noconflict`` marks an inline script that calls
    ``noConflict(true)``. A ``data:`` or other non-HTTP source and a script of a non-JavaScript type are left out."""
    text = body or ''
    out = []
    for order, tag in enumerate(_SCRIPT_TAG.finditer(text)):
        if len(out) >= MAX_ENTRIES:
            break
        attrs = tag.group(1)
        kind = (_TYPE.search(attrs).group(1).lower() if _TYPE.search(attrs) else '')
        if kind not in _JS_TYPES:
            continue
        flags = {f.lower() for f in _FLAG.findall(attrs)}
        timing = 'async' if 'async' in flags else 'defer' if ('defer' in flags or kind == 'module') else 'sync'
        src = _SRC.search(attrs)
        if src:
            value = next(g for g in src.groups() if g is not None).strip()
            try:
                absolute = urljoin(page_url or '', value)
                parts = urlsplit(absolute)
            except ValueError:
                continue
            if parts.scheme not in ('http', 'https') or not parts.hostname:
                continue  # data:, blob:, javascript: and the like are never fetched
            out.append({'order': order, 'url': absolute[:1000], 'timing': timing, 'noconflict': False})
        else:
            end = text.find('</script', tag.end(), tag.end() + 65536)
            inline = text[tag.end():end if end != -1 else tag.end() + 65536]
            out.append({'order': order, 'url': None, 'timing': 'sync' if kind != 'module' else 'defer',
                        'noconflict': bool(NOCONFLICT.search(inline))})
    return out


# ------------------------------------------------------------------ which hosts may be read

def _site(name):
    """The registrable domain of a host name (``static.example.com`` -> ``example.com``), the last two labels under a suffix the public
    list does not know (``corp.internal``), None for an address."""
    from targetApp.target_types import DOMAIN, apex_domain, classify_target
    if classify_target(name) != DOMAIN:
        return None
    return apex_domain(name) or '.'.join(name.split('.')[-2:])


def _same_site(host, page_host):
    from targetApp.shared_domains import shared_domain_of
    if shared_domain_of(page_host) or shared_domain_of(host):
        return False  # a tenant of a shared platform owns its own name only
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


def vetter(page_url, project=None, gate=None):
    """``vet(url)``: '' when a script may be read, else why not. A third-party or analytics script is never read. Another host (the same
    site or a CDN) passes the SSRF address check, the organization's exclusions and archived hosts and, for the same site, the bug bounty
    program's scope, each asked once per host. The page's own host was vetted before the page was read; the pinned transport vets every
    address again when it connects."""
    memo = {}

    def vet(url):
        kind = kind_of(url, page_url)
        if kind in ('analytics', 'third-party'):
            return kind
        if kind == 'same-host':
            return ''
        host = (urlsplit(url).hostname or '').lower().rstrip('.')
        if host not in memo:
            memo[host] = _refusal(host, kind, project, gate)
        return memo[host]
    return vet


def _refusal(host, kind, project, gate):
    from cveFeed import route_auth
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


# ------------------------------------------------------------------ reading the scripts (network through the caller's fetch)

def _cache():
    try:
        from django.core.cache import cache
        return cache
    except Exception:  # noqa: BLE001 - no cache configured: every script is read
        return None


def _cache_key(url):
    return 'jslib:v1:' + hashlib.sha256(url.encode('utf-8', 'replace')).hexdigest()


def _cached(url):
    cache = _cache()
    if cache is None:
        return None
    try:
        return cache.get(_cache_key(url))
    except Exception:  # noqa: BLE001
        return None


def _remember(url, read, kind):
    """Keep what one script said, keyed by its URL with the ETag or length it was served with. Only an answer that carried a validator
    is kept (a server that sends neither is read again next time)."""
    if not (read.get('etag') or read.get('length')):
        return
    cache = _cache()
    if cache is None:
        return
    try:
        cache.set(_cache_key(url), read, CDN_CACHE_SECONDS if kind == 'cdn' else CACHE_SECONDS)
    except Exception:  # noqa: BLE001
        pass


def _read_one(url, fetch):
    """What one fetched script states, or None when it could not be read as a script."""
    got = fetch(url)
    status = (got or {}).get('status') or 0
    if not 200 <= status < 300 or (got or {}).get('challenge'):
        return None
    text = got.get('body') or ''
    raw = got.get('bytes')
    size = raw if isinstance(raw, int) else len(text.encode('utf-8', 'replace'))
    truncated = size >= MAX_SCRIPT_BYTES
    headers = got.get('raw_headers') or {}
    return {'found': [list(f) for f in read_body(text)], 'truncated': truncated,
            'sha256': '' if truncated else hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest(),
            'etag': str(headers.get('etag') or '')[:120], 'length': str(headers.get('content-length') or '')[:20]}


def _order_to_read(entries, page_url):
    """The scripts worth reading, best first: those whose name is a library, then the page's other same-host scripts (a bundle names
    its libraries in its banners). Scripts on a CDN are read only when their name is a library."""
    named, other = [], []
    for entry in entries:
        if not entry.get('url'):
            continue
        kind = kind_of(entry['url'], page_url)
        if entry.get('library'):
            named.append(entry)
        elif kind in ('same-host', 'same-site'):
            other.append(entry)
    return named + other


def read_page(entries, page_url, fetch, vet, budget, before_each=None, stop=None):
    """Read the scripts of a parsed page (``parse_page``) through ``fetch(url)`` (the caller's pinned, bounded GET returning the route
    probe dict) and return ``resolve``'s records. ``vet`` is ``vetter``'s; ``budget`` is ``{'left': n}``, shared by every page of one
    host; ``before_each()`` runs before each request (the gap between requests), ``stop()`` ends the reading (a scan stop)."""
    entries = [dict(e) for e in entries or []]
    for entry in entries:
        if entry.get('url'):
            entry.update(identify(entry['url']))
    for entry in _order_to_read(entries, page_url):
        if stop is not None and stop():
            break
        try:
            reason = vet(entry['url'])
        except Exception:  # noqa: BLE001 - a host that cannot be vetted is not read
            logger.info('script host could not be vetted', exc_info=True)
            reason = 'not vetted'
        if reason:
            entry['skipped'] = reason
            continue
        kind = kind_of(entry['url'], page_url)
        cached = _cached(entry['url'])
        if cached is not None:
            entry['read'] = cached
            continue
        if budget.get('left', 0) <= 0:
            entry['skipped'] = 'limit'
            continue
        budget['left'] -= 1
        if before_each is not None:
            before_each()
        try:
            read = _read_one(entry['url'], fetch)
        except Exception as exc:  # noqa: BLE001 - a script that cannot be read is skipped; its name stays a hint
            logger.info('script read failed: %s', type(exc).__name__)
            entry['skipped'] = 'unreachable'
            continue
        if read is None:
            entry['skipped'] = 'not served'
            continue
        entry['read'] = read
        _remember(entry['url'], read, kind)
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
            if key == library and entry.get('query_version'):
                copy['query_version'] = entry['query_version']
            if key == library and entry.get('filename_version') and source == 'body' and entry['filename_version'] != version:
                copy['filename_version'] = entry['filename_version']  # the name said otherwise: the file wins
            if source == 'body' and read.get('sha256'):
                copy['sha256'] = read['sha256']
            if entry.get('skipped') and source != 'body':
                copy['not_read'] = entry['skipped']
            out.setdefault(key, []).append(copy)
    return out


def resolve(entries):
    """``{library key: record}`` for a page's scripts (``parse_page`` entries, with ``read`` where the body was read). A record names the
    effective copy (``version``, ``version_source``, ``version_confidence``, ``script_url``, ``script_sha256``), lists every ``copy`` with
    its ``state`` (effective, shadowed or unresolved) and says ``copies_unresolved`` when the page does not show which one runs.
    ``tech_names`` are the names the host stores: the effective copy, or every versioned copy of an unresolved set."""
    noconflict = [_execution_rank(e) for e in entries if e.get('noconflict')]
    records = {}
    for key, copies in _copies(entries).items():
        product = LIBRARIES[key][0]
        ranked = sorted(copies, key=lambda c: (c['rank'] is None, c['rank'] if c['rank'] is not None else c['order']))
        first = next((c['rank'] for c in ranked if c['rank'] is not None), None)
        for copy in ranked:
            if key == 'jquery' and copy['rank'] is not None and any(n is not None and n < copy['rank'] for n in noconflict):
                copy['loaded_after_noconflict'] = True
        versions = {c['version'] for c in ranked}
        reasons = []
        if len(versions) > 1:
            if any(c['rank'] is None for c in ranked):
                reasons.append('a copy is loaded with async, so the order the copies run in is unknown')
            if key == 'jquery' and first is not None and any(n is not None and n > first for n in noconflict):
                reasons.append('the page calls jQuery.noConflict(true) after a copy, which hands the global back to the earlier copy')
            if not ranked[-1]['version']:
                reasons.append('the last copy states no readable version')
        effective = ranked[-1]
        for copy in ranked:
            copy['state'] = 'unresolved' if reasons else ('effective' if copy is effective else 'shadowed')
        if reasons:  # the record speaks for the last versioned copy, as a guess, and every versioned copy stays a candidate
            effective = next((c for c in reversed(ranked) if c['version']), effective)
        confidence = CONFIDENCE.get(effective['how'], 0.0) if effective['version'] else 0.0
        if reasons:
            confidence = min(confidence, UNRESOLVED_CAP)
        if reasons:
            names = [f'{product}:{v}' for v in dict.fromkeys(c['version'] for c in ranked if c['version'])]
        else:
            names = [f'{product}:{effective["version"]}' if effective['version'] else product]
        record = {'product': product, 'version': effective['version'], 'version_source': effective['source'] or '',
                  'version_confidence': confidence, 'how': effective['how'] or '', 'script_url': effective['url'],
                  'script_sha256': effective.get('sha256', ''), 'copies_unresolved': bool(reasons), 'tech_names': names or [product],
                  'copies': [{k: v for k, v in c.items() if k not in ('rank',)} for c in ranked][:MAX_COPIES]}
        if reasons:
            record['unresolved_reason'] = '; '.join(reasons)
        records[key] = record
    return records


def names_of(records):
    """``[(name, source)]`` the host stores for ``resolve``'s records: ``script:body`` or ``script:filename`` by where the version came from."""
    out = []
    for record in (records or {}).values():
        source = 'script:body' if record['version_source'] == 'body' else 'script:filename'
        out += [(name, source) for name in record['tech_names']]
    return out


def is_library(name):
    """Whether a stored technology name (``jQuery:3.4.1``) is one of the libraries read here."""
    return (name or '').split(':', 1)[0].strip().lower() in PRODUCTS


# ------------------------------------------------------------------ correlation: which stored versions a match may stand on

FILENAME_SOURCES = ('script:name', 'script:filename')  # 'script:name' is how a name hint (or a ?ver= string) was labelled before 1.3.2
LEGACY_NOTE = ('read from the script name or its query string by a scan before 1.3.2; the next route check reads the file itself')


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
        most its confidence may be (None: no cap)."""
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
        live = [c for c in copies if c.get('version') == version and c.get('state') in ('effective', 'unresolved')]
        if live:
            copy = next((c for c in live if c.get('source') == 'body'), live[0])
            source = copy.get('source') or ''
            confidence = CONFIDENCE.get(copy.get('how') or '', 0.0)
            cap = CONFIDENCE['filename'] if source == 'filename' else None
            if copy.get('state') == 'unresolved':
                confidence = min(confidence, UNRESOLVED_CAP)
                cap = min(cap if cap is not None else 1.0, UNRESOLVED_CAP)
            return False, {**base, 'script_url': copy.get('url', ''), **({'script_sha256': copy['sha256']} if copy.get('sha256') else {}),
                           'version_source': source, 'version_confidence': confidence, 'copy_state': copy.get('state')}, cap
        if any(c.get('version') == version and c.get('state') == 'shadowed' for c in copies):
            return True, {}, None  # a copy a later one replaces: listed on the effective copy's match, never matched itself
        if any(version in (c.get('query_version'), c.get('filename_version')) for c in copies):
            return True, {}, None  # the string a script's query or name carries, where the file states otherwise or nothing
        return False, {'copies': summary, 'version_source': 'other'}, None  # another tool read it; shown with what the page itself says

    def _judge_legacy(self, key, version):
        source = self.legacy.get((key, version))
        if source is None:
            return False, {}, None
        shared = {k for (k, v) in self.legacy if v == version}
        if len(shared) > 1:
            return True, {}, None  # one string read as two libraries' versions (jQuery 1.0.4 and Bootstrap 1.0.4): an asset cache-buster
        note = LEGACY_NOTE if source == 'script:name' else 'read from the script\'s file name only; the file itself was not read'
        return False, {'version_source': 'filename', 'version_confidence': CONFIDENCE['filename'], 'version_note': note}, CONFIDENCE['filename']


def _legacy_add(legacy, name, source):
    product, _, version = str(name or '').partition(':')
    key = PRODUCTS.get(product.strip().lower())
    if key and version:
        legacy.setdefault((key, version.strip()), source)
