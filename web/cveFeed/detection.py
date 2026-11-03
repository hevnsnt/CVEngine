"""One shared detection strategy per CVE.

``CVEEntry`` is a single table for every organization, and so is the detection record: how to tell, remotely and on the host
itself, whether a product is affected is a fact about the CVE, not about a project, so it is written once and used by all.

A strategy is DATA, never a program. Every check is one of a fixed set of kinds with a fixed set of parameters, each checked
against an allowlist here (read-only HTTP methods, nmap scripts from the reviewed list, plain file and package names). Nothing in
a strategy is a shell command, and whatever executes a check (the scanners, a host agent) does so through its own primitive for that
kind. That is what lets an AI model draft strategies from untrusted feed text: its output is parsed against this schema, and
anything outside it is dropped.

Two authors, in order:
  1. ``rules``: deterministic, from the CVE's own affected products and ranges (and an installed nuclei template). Free, instant.
  2. ``ai``: asked once per CVE, within a daily budget, for the checks the rules cannot know (an HTTP marker, a config setting).
     The model's answer replaces nothing the rules wrote; it is merged in after validation.
A ``manual`` strategy is never overwritten by either.
"""
import json
import re

SCHEMA_VERSION = 4  # 2 adds the plain-language guidance (identify, confirm_steps, true/false-positive signs); 3 adds the script_version
#                     remote check (a client-side JavaScript library read from the script files a page loads); 4 sorts each product the
#                     advisory names into a class (cveFeed.detection_classes: ``components``), checks a language package in the application's
#                     dependency tree instead of with dpkg, rpm or apk, adds the bundled_copy host check and the advisory's own
#                     ``exploit_precondition``. Older records stay valid
MAX_CHECKS = 12  # a library with five packagings, its system packages and the bundled-copy search fits
GUIDANCE_LISTS = {'confirm_steps': (6, 240), 'true_positive_signs': (4, 180), 'false_positive_signs': (4, 180)}
GUIDANCE_TEXT = {'identify': 320, 'scope_reason': 200, 'revision_note': 200, 'exploit_precondition': 300}
SCOPES = ('external', 'local_only', 'unclear')  # can an outside scan decide this CVE, only the host itself, or cannot tell
CONFIDENCE = ('high', 'medium', 'low')

_ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,39}$')
_PRODUCT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._+/@-]{0,99}$')
_VERSION = re.compile(r'^[0-9][0-9A-Za-z._+~:-]{0,63}$')
_PACKAGE = re.compile(r'^[A-Za-z0-9@][A-Za-z0-9._+@/:-]{0,99}$')  # ':' for a Maven group:artifact, a leading '@' for an npm scope
_HTTP_PATH = re.compile(r'^/[A-Za-z0-9._~!$&\'()*+,;=:@%/-]{0,199}$')
_FILE_PATH = re.compile(r'^(?:/|[A-Za-z]:\\)[A-Za-z0-9._ @+()\\/-]{1,199}$')
_TEMPLATE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_MARKER = re.compile(r'^[\x20-\x7e]{1,100}$')
_SERVICE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')
_KEY = re.compile(r'^[A-Za-z0-9._:/-]{1,80}$')
_DOTS = re.compile(r'\.\.')  # a path that climbs out of where it starts

ECOSYSTEMS = ('any', 'dpkg', 'rpm', 'apk', 'pip', 'npm', 'gem', 'maven', 'nuget', 'go', 'composer', 'cargo')
COMPONENT_CLASSES = ('client_library', 'language_package', 'os_package', 'os_platform', 'cms_component', 'network_product', 'other')
MAX_COMPONENTS = 8
HTTP_METHODS = ('GET', 'HEAD')  # a check never changes anything on the target
TLS_PROPERTIES = ('protocol', 'cipher', 'cert_expiry', 'cert_key_bits')
VERSION_SOURCES = ('service_banner', 'http_header', 'technology', 'any')


# The system-wide packages that ship a client-side library (cveFeed.js_libraries.LIBRARIES key -> [(ecosystem, package, major)]): the only host
# check that means anything for such a library. A copy a website bundles is not a package; only reading the page's scripts finds it. Checked
# against the Debian and Fedora package indexes: Debian and Ubuntu package the libraries as libjs-* (node-* for the npm copy), Fedora and EPEL
# as js-*; Alpine packages none of them. ``major`` names the one major release line a package ships (Debian's libjs-bootstrap is Bootstrap 3,
# libjs-bootstrap4 is 4.x, libjs-bootstrap5 and node-bootstrap are 5.x): such a package is checked only against a range of its own line,
# because a package check compares with the fixed release alone and would flag a 3.x package for a 4.x-only flaw.
SYSTEM_PACKAGES = {
    'jquery': (('dpkg', 'libjs-jquery', None), ('dpkg', 'node-jquery', None), ('rpm', 'js-jquery', None)),
    'jquery-ui': (('dpkg', 'libjs-jquery-ui', None), ('rpm', 'js-jquery-ui', None)),
    'bootstrap': (('dpkg', 'libjs-bootstrap', 3), ('dpkg', 'libjs-bootstrap4', 4), ('dpkg', 'libjs-bootstrap5', 5), ('dpkg', 'node-bootstrap', 5)),
    'angularjs': (('dpkg', 'libjs-angularjs', None),),
    'lodash': (('dpkg', 'libjs-lodash', None), ('dpkg', 'node-lodash', None)),
    'underscore': (('dpkg', 'libjs-underscore', None), ('dpkg', 'node-underscore', None), ('rpm', 'js-underscore', None)),
    'moment': (('dpkg', 'libjs-moment', None), ('dpkg', 'node-moment', None)),
    'datatables': (('dpkg', 'libjs-jquery-datatables', None),),
}
# Packages, by their exact name, that vendor a library into an application (a Rails gem, a Sass port): their versions are the package's own,
# and the copy they put on a page is the one the script read finds. Anything else an advisory names (lodash.merge, a separate npm package with
# its own versions) keeps its own checks.
BUNDLED_BY = {'jquery': ('jquery-rails',), 'jquery-ui': ('jquery-ui-rails',), 'bootstrap': ('bootstrap-sass',)}
LIBRARY_TOOL = 'html-libraries probe'


def _libraries():
    from cveFeed.js_libraries import LIBRARIES
    return LIBRARIES


def _token(name):
    return re.sub(r'[^a-z0-9]', '', str(name or '').lower())


def library_key(name):
    """The ``cveFeed.js_libraries.LIBRARIES`` key an advisory's product or package name is, or ''. The name must be the library itself (its
    key or product name, any case or punctuation: ``jQuery``, ``jquery_ui``, ``Vue.js``), or a packaging that keeps the library's own version
    numbers and names it as its last part (``components/jquery`` on Composer, ``org.webjars.npm:jquery``). A plugin or a framework that ships
    the library (``jquery-validation``, ``jquery-rails``) and a different product with a similar name (``@angular/core``) are not it."""
    tokens = {_token(n): key for key, (product, _s, _d) in _libraries().items() for n in (key, product)}
    raw = str(name or '').strip().lower()
    found = tokens.get(_token(raw), '')
    if not found and re.search(r'[/:]', raw):
        found = tokens.get(_token(re.split(r'[/:]', raw)[-1]), '')
    return found


def _bundles(name, keys):
    """Whether ``name`` (an advisory entry that is not the library itself) is, by its exact name, a package that vendors one of the libraries
    ``keys`` (BUNDLED_BY: ``jquery-rails`` in a jQuery advisory). Its version is the package's, not the library's, and the copy it puts on a
    page is found by the script read. A package merely named after the library (``lodash.merge``) is not one."""
    name = str(name or '').strip().lower()
    return bool(name) and any(name in BUNDLED_BY.get(key, ()) for key in keys)


# Libraries whose name an advisory also gives to server-side code (``react``: React Server Components, react-server-dom-*, react-dom/server,
# Next.js; ``vue``: vue-server-renderer). Such an advisory is about code that runs on the server, which no script a page loads shows, so it is
# never taken for the browser library. Decided on the package names the advisory lists and its words, conservatively: a sign of either
# keeps the CVE's ordinary record.
SERVER_SIDE = {
    'react': (re.compile(r'^(?:react-server(?:-dom-[a-z0-9-]+)?|react-dom/server|next|nextjs|next\.js|@next/[a-z0-9-]+|react-router|@remix-run/[a-z0-9-]+'
                         r'|@vercel/[a-z0-9-]+|waku|@parcel/rsc)$'),
              re.compile(r'server[ -]?components?|server[ -]?functions?|server[ -]?actions?|react-server|\bRSC\b|server[ -]side render|\bSSR\b|'
                         r'renderTo(?:String|PipeableStream|ReadableStream|StaticMarkup)|react-dom/server|next\.js|\bnextjs\b|flight protocol|'
                         r'node\.js', re.IGNORECASE)),
    'vue': (re.compile(r'^(?:vue-server-renderer|@vue/server-renderer|nuxt|@nuxt/[a-z0-9-]+|vue-template-compiler|@vue/compiler-sfc)$'),
            re.compile(r'server[ -]?render|server[ -]side|\bSSR\b|nuxt|node\.js', re.IGNORECASE)),
}


def _server_side(key, affected, text=''):
    """Whether an advisory naming library ``key`` (SERVER_SIDE) is about its server-side code: one of its entries is a server package, or its
    words say so. A library with no such twin is never server-side."""
    rules = SERVER_SIDE.get(key)
    if not rules:
        return False
    packages, words = rules
    for item in affected or []:
        if not isinstance(item, dict):
            continue
        for field in ('product', 'package'):
            name = str(item.get(field) or '').strip().lower()
            if name and packages.match(name.split(':')[-1]):
                return True
    return bool(words.search(text or ''))


def client_libraries(affected, text=None):
    """``{library key: [ranges of each entry naming it]}`` for the entries of a CVE's ``affected`` list that name a client-side library
    cvENGINE reads from script files (``library_key``), in the order the advisory names them. Each value is a list of the entries' range
    lists, as the feed gives them. A library whose advisory is about its server-side code (``_server_side``: a server package among the
    entries, or, with ``text``, the advisory's own words) is left out: that CVE keeps its ordinary checks."""
    from cveFeed.correlation import clean_affected
    out = {}
    for item in clean_affected(affected):
        key = next((k for k in (library_key(item.get(f)) for f in ('product', 'package') if isinstance(item.get(f), str)) if k), '')
        if key:
            out.setdefault(key, []).append(item.get('ranges') or [])
    return {key: ranges for key, ranges in out.items() if not _server_side(key, affected, text or '')}


def cve_libraries(cve):
    """``client_libraries`` for a CVE record, read with its title and description: the one every caller with a CVEEntry uses."""
    text = ' '.join(str(getattr(cve, field, '') or '') for field in ('title', 'original_description', 'summary'))
    return client_libraries(getattr(cve, 'affected', None) or [], text)


def _nse_allowlist():
    from cveFeed.nmap_scan import NSE_SCRIPTS
    return tuple(NSE_SCRIPTS)


# --- parameter validators: each returns the cleaned params or None ---------------------------------------------------------

def _str(value, pattern, optional=False):
    if value is None and optional:
        return ''
    if isinstance(value, str) and pattern.match(value):
        return value
    return None


def _ranges(value):
    if not isinstance(value, list) or not 0 < len(value) <= 10:
        return None
    out = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {'introduced', 'fixed', 'last_affected'}:
            return None
        clean = {}
        for key, raw in item.items():
            if not isinstance(raw, str) or not _VERSION.match(raw):
                return None
            clean[key] = raw
        if not clean:
            return None
        out.append(clean)
    return out


def _p_version_banner(p):
    if set(p) - {'product', 'ranges', 'source'}:
        return None
    product = _str(p.get('product'), _PRODUCT)
    ranges = _ranges(p.get('ranges'))
    source = p.get('source', 'any')
    if product is None or ranges is None or source not in VERSION_SOURCES:
        return None
    return {'product': product, 'ranges': ranges, 'source': source}


def _p_script_version(p):
    """A client-side library read from the script files a page loads: ``library`` is a ``js_libraries.LIBRARIES`` key; ``product`` is always
    that library's own name, whatever the input said."""
    if set(p) - {'product', 'library', 'ranges'} or p.get('library') not in _libraries():
        return None
    ranges = _ranges(p.get('ranges'))
    if ranges is None:
        return None
    return {'product': _libraries()[p['library']][0], 'library': p['library'], 'ranges': ranges}


def _p_http_probe(p):
    if set(p) - {'method', 'path', 'expect_status', 'expect_contains', 'expect_absent'}:
        return None
    method = p.get('method', 'GET')
    path = p.get('path')
    status = p.get('expect_status', [200])
    if method not in HTTP_METHODS or not isinstance(path, str) or not _HTTP_PATH.match(path) or _DOTS.search(path):
        return None
    if not isinstance(status, list) or not 0 < len(status) <= 5 or any(
            isinstance(s, bool) or not isinstance(s, int) or not 100 <= s <= 599 for s in status):
        return None
    out = {'method': method, 'path': path, 'expect_status': status}
    for key in ('expect_contains', 'expect_absent'):
        if key in p:
            marker = _str(p[key], _MARKER)
            if marker is None:
                return None
            out[key] = marker
    if 'expect_contains' not in out and 'expect_absent' not in out:
        return None  # a status code alone says nothing about a vulnerability
    return out


def _p_nuclei_template(p):
    template_id = _str(p.get('template_id'), _TEMPLATE_ID) if set(p) == {'template_id'} else None
    return {'template_id': template_id} if template_id else None


def _p_nse_script(p):
    if set(p) - {'script', 'expect_contains'} or p.get('script') not in _nse_allowlist():
        return None
    out = {'script': p['script']}
    if 'expect_contains' in p:
        marker = _str(p['expect_contains'], _MARKER)
        if marker is None:
            return None
        out['expect_contains'] = marker
    return out


def _p_tls_check(p):
    if set(p) != {'property', 'expect'} or p['property'] not in TLS_PROPERTIES:
        return None
    expect = _str(p['expect'], _MARKER)
    return {'property': p['property'], 'expect': expect} if expect else None


def _p_port_service(p):
    port = p.get('port')
    service = _str(p.get('service'), _SERVICE, optional=True)
    if set(p) - {'port', 'service'} or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or service is None:
        return None
    return {'port': port, 'service': service} if service else {'port': port}


def _p_package_version(p):
    if set(p) - {'ecosystem', 'package', 'affected_below', 'fixed_version'}:
        return None
    package = _str(p.get('package'), _PACKAGE)
    ecosystem = p.get('ecosystem', 'any')
    if package is None or ecosystem not in ECOSYSTEMS:
        return None
    out = {'ecosystem': ecosystem, 'package': package}
    for key in ('affected_below', 'fixed_version'):
        if key in p:
            if not isinstance(p[key], str) or not _VERSION.match(p[key]):
                return None
            out[key] = p[key]
    if 'affected_below' not in out and 'fixed_version' not in out:
        return None
    return out


def _p_file_version(p):
    if set(p) != {'path', 'contains'}:
        return None
    path, contains = _str(p['path'], _FILE_PATH), _str(p['contains'], _MARKER)
    return {'path': path, 'contains': contains} if path and contains and not _DOTS.search(path) else None


def _p_config_setting(p):
    if set(p) - {'path', 'key', 'match', 'value'}:
        return None
    path, key, match = _str(p.get('path'), _FILE_PATH), _str(p.get('key'), _KEY), p.get('match', 'present')
    if not path or _DOTS.search(path) or not key or match not in ('present', 'absent', 'equals'):
        return None
    out = {'path': path, 'key': key, 'match': match}
    if match == 'equals':
        value = _str(p.get('value'), _MARKER)
        if value is None:
            return None
        out['value'] = value
    return out


def _p_service_state(p):
    state = p.get('state')
    service = _str(p.get('service'), _SERVICE) if set(p) == {'service', 'state'} else None
    return {'service': service, 'state': state} if service and state in ('running', 'stopped', 'enabled', 'disabled') else None


def _p_bundled_copy(p):
    """A copy of a client-side library a site bundles in its own files, found on the web server by the library's own banner line (the
    pattern is cvENGINE's, per library: never taken from the input)."""
    if set(p) != {'library'} or p.get('library') not in _libraries():
        return None
    return {'library': p['library']}


REMOTE_KINDS = {'version_banner': _p_version_banner, 'http_probe': _p_http_probe, 'nuclei_template': _p_nuclei_template,
                'nse_script': _p_nse_script, 'tls_check': _p_tls_check, 'port_service': _p_port_service, 'script_version': _p_script_version}
LOCAL_KINDS = {'package_version': _p_package_version, 'file_version': _p_file_version, 'config_setting': _p_config_setting,
               'service_state': _p_service_state, 'bundled_copy': _p_bundled_copy}


def _components(value, problems):
    """The ``components`` of a record (cveFeed.detection_classes): each product the advisory names, its class and its ecosystem coordinates,
    validated like every other part. Rules-written; a model's or a seed's copy is checked the same way."""
    if value in (None, []):
        return []
    if not isinstance(value, list):
        problems.append('components is not a list')
        return []
    out = []
    for item in value[:MAX_COMPONENTS]:
        if not isinstance(item, dict) or set(item) - {'name', 'class', 'library', 'coordinates', 'platforms'}:
            problems.append('components: an entry is not a component')
            continue
        name, cls = _str(item.get('name'), _PRODUCT) or _str(item.get('name'), _PACKAGE), item.get('class')  # a product, or a package (@scope/name)
        library = item.get('library') or ''
        if name is None or cls not in COMPONENT_CLASSES or (library and library not in _libraries()):
            problems.append('components: a bad name, class or library')
            continue
        coordinates = []
        for coord in (item.get('coordinates') or [])[:MAX_COMPONENTS] if isinstance(item.get('coordinates'), list) else []:
            if isinstance(coord, dict) and set(coord) == {'ecosystem', 'package'} and coord['ecosystem'] in ECOSYSTEMS and \
                    _str(coord['package'], _PACKAGE) is not None:
                coordinates.append({'ecosystem': coord['ecosystem'], 'package': coord['package']})
        platforms = [t for t in (_str(x, _PRODUCT) for x in (item.get('platforms') or [])[:6]) if t] if isinstance(item.get('platforms'), list) else []
        clean = {'name': name, 'class': cls, 'library': library, 'coordinates': coordinates}
        if platforms:
            clean['platforms'] = platforms
        out.append(clean)
    return out


def _text(value, limit):
    from reNgine.ai_providers import clean_text
    return clean_text(value, limit) if isinstance(value, str) else None


def _checks(value, kinds, problems, label):
    if value is None:
        return []
    if not isinstance(value, list):
        problems.append(f'{label} is not a list')
        return []
    out, seen = [], set()
    for index, check in enumerate(value[:MAX_CHECKS * 2]):
        if len(out) >= MAX_CHECKS:
            problems.append(f'{label}: more than {MAX_CHECKS} checks, the rest were dropped')
            break
        tag = f'{label}[{index}]'
        if not isinstance(check, dict) or set(check) - {'id', 'kind', 'description', 'params', 'confidence'}:
            problems.append(f'{tag}: not a check')
            continue
        kind, params = check.get('kind'), check.get('params')
        check_id = check.get('id') or f'{kind}-{index + 1}'
        if kind not in kinds or not isinstance(params, dict) or not isinstance(check_id, str) or not _ID.match(check_id) or check_id in seen:
            problems.append(f'{tag}: unknown kind, bad params or a bad id')
            continue
        clean = kinds[kind](params)
        description = _text(check.get('description', ''), 200)
        confidence = check.get('confidence', 'medium')
        if clean is None or description is None or confidence not in CONFIDENCE:
            problems.append(f'{tag}: {kind} parameters are not allowed')
            continue
        seen.add(check_id)
        out.append({'id': check_id, 'kind': kind, 'description': description, 'params': clean, 'confidence': confidence})
    return out


def validate_strategy(obj):
    """``(strategy, problems)``: the cleaned strategy (None when nothing usable is left) and what was dropped and why. A check that
    fails validation is dropped on its own; the rest of the strategy stands."""
    problems = []
    if not isinstance(obj, dict):
        return None, ['the strategy is not an object']
    obj = {k: v for k, v in obj.items() if k != 'validation'}  # computed by finalize(), never taken from the input
    for key in ('remote_checks', 'local_checks'):
        if isinstance(obj.get(key), list):
            obj[key] = [{k: v for k, v in c.items() if k not in ('how', 'commands')} if isinstance(c, dict) else c for c in obj[key]]
    allowed = {'summary', 'remote_checks', 'local_checks', 'prerequisites', 'false_positive_notes', 'remediation', 'safety',
               *GUIDANCE_TEXT, *GUIDANCE_LISTS, 'scope', 'components'}
    for key in set(obj) - allowed:
        problems.append(f'unknown key {str(key)[:40]!r} dropped')
    if obj.get('safety', 'read_only') != 'read_only':
        return None, problems + ['safety must be read_only']
    out = {'safety': 'read_only',
           'summary': _text(obj.get('summary', ''), 400) or '',
           'remote_checks': _checks(obj.get('remote_checks'), REMOTE_KINDS, problems, 'remote_checks'),
           'local_checks': _checks(obj.get('local_checks'), LOCAL_KINDS, problems, 'local_checks'),
           'false_positive_notes': _text(obj.get('false_positive_notes', ''), 400) or '',
           'remediation': _text(obj.get('remediation', ''), 600) or ''}
    prerequisites = obj.get('prerequisites', [])
    out['prerequisites'] = [t for t in (_text(p, 150) for p in prerequisites[:5]) if t] if isinstance(prerequisites, list) else []
    for key, cap in GUIDANCE_TEXT.items():
        out[key] = _text(obj.get(key, ''), cap) or ''
    scope = obj.get('scope', '')
    if scope and scope not in SCOPES:
        problems.append(f'scope must be one of {", ".join(SCOPES)}')
        scope = ''
    out['scope'] = scope or ''
    for key, (count, cap) in GUIDANCE_LISTS.items():
        items = obj.get(key, [])
        if items and not isinstance(items, list):
            problems.append(f'{key} is not a list')
            items = []
        out[key] = [t for t in (_text(i, cap) for i in (items or [])[:count]) if t]
    components = _components(obj.get('components'), problems)
    if components:
        out['components'] = components
    written = out['identify'] or out['scope'] or any(out[key] for key in GUIDANCE_LISTS)
    if not out['remote_checks'] and not out['local_checks'] and not written:
        return None, problems + ['no usable check or guidance']
    return out, problems


def parse_ai_strategy(text):
    """The strategy in a model reply (the one JSON object in it), validated; ``(None, problems)`` when there is none."""
    decoder = json.JSONDecoder()
    candidates = []
    for match in re.finditer(r'\{', text or ''):
        try:
            candidate, _ = decoder.raw_decode(text, match.start())
        except (json.JSONDecodeError, TypeError, RecursionError):
            continue
        if isinstance(candidate, dict) and ({'remote_checks', 'local_checks', 'identify', 'confirm_steps', 'scope'} & set(candidate)):
            candidates.append(candidate)
    if len(candidates) != 1:
        return None, ['the reply has no single strategy object']
    return validate_strategy(candidates[0])


# --- the rules author ------------------------------------------------------------------------------------------------------

def _range_params(rng):
    out = {}
    for src, dst in (('introduced', 'introduced'), ('fixed', 'fixed'), ('lastAffected', 'last_affected'), ('last_affected', 'last_affected')):
        value = rng.get(src)
        if isinstance(value, str) and _VERSION.match(value) and value not in ('0', '0.0', '0.0.0'):
            out[dst] = value
    return out


def _cve_text(cve):
    return ' '.join(str(getattr(cve, field, '') or '') for field in ('title', 'original_description', 'summary'))


def _slug(name):
    return re.sub(r'[^a-z0-9]+', '-', str(name).lower()).strip('-')[:24] or 'product'


def _entry_ranges(entries):
    """The ranges of ``entries`` as matching reads them (each once, at most 10)."""
    from cveFeed.correlation import prepared_ranges
    out = []
    for item in entries:
        for rng in (_range_params(x) for x in prepared_ranges(item.get('ranges'))[:10]):
            if rng and rng not in out:
                out.append(rng)
    return out[:10]


def _only_fix(ranges):
    fixes = {r['fixed'] for r in ranges if r.get('fixed')}
    return fixes.pop() if len(fixes) == 1 else None


def rules_strategy(cve, template_ids=()):
    """The strategy the CVE's own record supports, with no AI. Each product the advisory names is sorted into a class first
    (``detection_classes.components``), and gets the checks that fit it:

    - a client-side JavaScript library cvENGINE reads from script files (``client_libraries``): a ``script_version`` check, host checks for the
      system-wide packages that ship it (SYSTEM_PACKAGES), a check of each language packaging the advisory names in the application's
      dependency tree (npm, Composer, Maven/WebJars, RubyGems, NuGet) and a ``bundled_copy`` search of the web root; never nmap, dpkg, rpm or
      apk for a packaging;
    - a language package (npm, PyPI, Maven, ...): a technology-fingerprint version check and its own ecosystem's dependency check;
    - an OS distribution's package: that distribution's package manager only, against the distribution's own fixed build; the distribution
      release (``Red Hat Enterprise Linux 9``) and a container image are never a banner;
    - a CMS extension: its own version, never a JavaScript library of the same name;
    - any other product: its banner (a response header for a web server) and the host's package, under the name the OS ships it as.
    Any installed nuclei template is added. None when the record names no product."""
    from cveFeed import detection_classes as classes
    from cveFeed.correlation import clean_affected
    text = _cve_text(cve)
    affected = clean_affected(cve.affected)
    libraries = cve_libraries(cve)
    # a CMS extension that shares a library's name (Drupal's "Bootstrap" theme) is that extension, not the library
    libraries = {k: v for k, v in libraries.items() if not any(
        classes.is_cms_component(item, text) for item in affected if any(library_key(item.get(f)) == k for f in ('product', 'package')))}
    comps = classes.components(affected, text, tuple(libraries))
    remote, local = _library_checks(libraries) if libraries else ([], [])
    language_cve = any(c['class'] == 'language_package' for c in comps)
    seen_ids = {c['id'] for c in remote + local}

    def add(target, check):
        if check['id'] not in seen_ids:
            seen_ids.add(check['id'])
            target.append(check)
    for comp in comps[:MAX_COMPONENTS]:
        entries = [affected[i] for i in comp['entries']]
        ranges = _entry_ranges(entries)
        cls, name = comp['class'], comp['name']
        if cls == 'client_library':
            if comp['library'] not in libraries:
                continue
            for coord in comp['coordinates']:
                if coord['ecosystem'] not in classes.LANGUAGE:
                    continue
                own = [e for e in entries if str(e.get('package') or '') == coord['package']]
                fixed = _only_fix(_entry_ranges(own))
                if fixed:
                    label = classes.ECOSYSTEM_LABELS.get(coord['ecosystem'], coord['ecosystem'])
                    add(local, {'id': f"dep-{coord['ecosystem']}-{_slug(coord['package'])}"[:40], 'kind': 'package_version', 'confidence': 'high',
                                'description': f"the application's {label} dependency {coord['package']} is older than {fixed}",
                                'params': {'ecosystem': coord['ecosystem'], 'package': coord['package'], 'affected_below': fixed}})
            add(local, {'id': f"bundled-{comp['library']}"[:40], 'kind': 'bundled_copy', 'confidence': 'medium',
                        'description': f'a copy of {name} the site bundles in its own files states a version inside an affected range',
                        'params': {'library': comp['library']}})
            continue
        if cls in ('os_platform', 'other') or not ranges:
            continue
        slug = _slug(name)
        fixed = _only_fix(ranges) or next((r['fixed'] for r in ranges if r.get('fixed')), None)
        if cls == 'os_package':
            ecosystems = [c['ecosystem'] for c in comp['coordinates'] if c['ecosystem'] in classes.DISTRO] or \
                         [e for e in (classes.inferred_ecosystem({'package': name.lower(), 'ranges': ranges}),) if e in classes.DISTRO] or ['any']
            for eco in dict.fromkeys(ecosystems):
                package = classes.os_package_name(name, eco)
                if package and fixed and _PACKAGE.match(package):
                    where = f" ({', '.join(comp.get('platforms', [])[:2])})" if comp.get('platforms') else ''
                    add(local, {'id': f'package-{slug}' if eco == 'any' else f'package-{eco}-{slug}'[:40], 'kind': 'package_version',
                                'confidence': 'high',
                                'description': f'the installed {package} package is older than the fixed build {fixed}{where}'[:200],
                                'params': {'ecosystem': eco, 'package': package, 'affected_below': fixed}})
            continue
        if cls in ('language_package', 'cms_component'):
            if _PRODUCT.match(name):  # an npm scope (@angular/common) is no name a fingerprint states; its dependency check stays
                add(remote, {'id': f'version-{slug}', 'kind': 'version_banner', 'confidence': 'medium' if cls == 'cms_component' else 'low',
                             'description': (f'the {name} version the site states (its readme, stylesheet or generator tag) is inside an '
                                             'affected range' if cls == 'cms_component' else
                                             f'a technology fingerprint names {name} at a version inside an affected range (the dependency '
                                             'tree decides)')[:200],
                             'params': {'product': name, 'ranges': ranges, 'source': 'technology'}})
            for coord in comp['coordinates']:
                own = [e for e in entries if str(e.get('package') or '') == coord['package']]
                bound = _only_fix(_entry_ranges(own))
                if coord['ecosystem'] in classes.LANGUAGE and bound:
                    label = classes.ECOSYSTEM_LABELS.get(coord['ecosystem'], coord['ecosystem'])
                    add(local, {'id': f'package-{slug}' if len(comp['coordinates']) == 1 else f"dep-{coord['ecosystem']}-{slug}"[:40],
                                'kind': 'package_version', 'confidence': 'high',
                                'description': f"the application's {label} dependency {coord['package']} is older than {bound}"[:200],
                                'params': {'ecosystem': coord['ecosystem'], 'package': coord['package'], 'affected_below': bound}})
            continue
        # a network product: what its banner or response header states, and the package the host installed it from
        if fixed and classes.is_distro_build(fixed) and all(classes.is_distro_build(r.get('fixed') or r.get('last_affected') or '')
                                                           for r in ranges):
            continue  # a distribution's build number is no upstream version a banner could state
        if not _PRODUCT.match(name):
            continue
        if not comp['coordinates'] and language_cve:
            # the CNA's vendor/product line for what the OSV entries name as a language package (angular beside @angular/common): a
            # fingerprint names it, nmap never does
            add(remote, {'id': f'version-{slug}', 'kind': 'version_banner', 'confidence': 'low',
                         'description': f'a technology fingerprint names {name} at a version inside an affected range (the dependency '
                                        'tree decides)'[:200], 'params': {'product': name, 'ranges': ranges, 'source': 'technology'}})
            continue
        source = 'http_header' if classes.WEB_SERVER_WORDS.search(name) else 'any'
        add(remote, {'id': f'version-{slug}', 'kind': 'version_banner', 'confidence': 'medium',
                     'description': f'{name} reports a version inside an affected range (a banner can hide a backported fix)'[:200],
                     'params': {'product': name, 'ranges': ranges, 'source': source}})
        package = next((c['package'] for c in comp['coordinates']), None)
        if package and fixed:
            os_name = classes.os_package_name(package, 'any')
            if os_name and _PACKAGE.match(os_name):
                add(local, {'id': f'package-{slug}', 'kind': 'package_version', 'confidence': 'high',
                            'description': f'the installed {os_name} package is older than the fixed release {fixed}',
                            'params': {'ecosystem': 'any', 'package': os_name, 'affected_below': fixed}})
    for template_id in list(template_ids)[:2]:
        if isinstance(template_id, str) and _TEMPLATE_ID.match(template_id):
            remote.append({'id': f'nuclei-{template_id.lower()}'[:40].rstrip('-_'), 'kind': 'nuclei_template', 'confidence': 'high',
                           'description': 'a nuclei template exists for this CVE', 'params': {'template_id': template_id}})
    if not remote and not local:
        return None
    components = [{k: v for k, v in c.items() if k in ('name', 'class', 'library', 'coordinates', 'platforms')} for c in comps
                  if c['class'] != 'client_library' or c['library'] in libraries][:MAX_COMPONENTS]
    precondition = classes.exploit_precondition(getattr(cve, 'original_description', '') or getattr(cve, 'summary', '') or '')
    strategy, _ = validate_strategy({'summary': (cve.title or cve.cve_id)[:400], 'remote_checks': remote, 'local_checks': local,
                                     'components': components, 'exploit_precondition': precondition,
                                     **rules_guidance(remote, local, bool(template_ids), components)})
    return strategy


def _major(version):
    found = re.match(r'(\d+)', str(version or ''))
    return int(found.group(1)) if found else None


def _package_bound(ranges, major):
    """The one fixed release a package check compares with: for a package of every release line (``major`` None) the advisory's only fix;
    for a package of one line, the only fix of the ranges that cover that line (introduced, or 0, at or below it; fixed at or above it).
    None when there is none, or more than one."""
    fixes = set()
    for rng in ranges:
        if not rng.get('fixed'):
            continue
        if major is not None:
            low, high = _major(rng.get('introduced') or '0'), _major(rng['fixed'])
            if low is None or high is None or not low <= major <= high:
                continue
        fixes.add(rng['fixed'])
    return fixes.pop() if len(fixes) == 1 else None


def _library_checks(libraries):
    """``(remote, local)``: one ``script_version`` check per library the advisory names, with its ranges as matching reads them (each range
    once), and a package check for each system-wide package that ships the library, against the one fixed release of its release line
    (``_package_bound``)."""
    from cveFeed.correlation import prepared_ranges
    remote, local = [], []
    for key, entries in list(libraries.items())[:4]:
        ranges = []
        for entry in entries:
            for rng in (_range_params(x) for x in prepared_ranges(entry)[:10]):
                if rng and rng not in ranges:
                    ranges.append(rng)
        if not ranges:
            continue
        product = _libraries()[key][0]
        remote.append({'id': f'script-{key}', 'kind': 'script_version', 'confidence': 'medium',
                       'description': f'a script the page loads states a {product} version inside an affected range (read from the file itself)',
                       'params': {'library': key, 'ranges': ranges[:10]}})
        for ecosystem, package, major in SYSTEM_PACKAGES.get(key, ()):
            fixed = _package_bound(ranges, major)
            if not fixed:
                continue  # no range of this package's release line, or several fixes: no one bound fits a package whose release is not known yet
            local.append({'id': f'pkg-{package}'[:40], 'kind': 'package_version', 'confidence': 'medium',
                          'description': f'the system-wide {package} package is older than {fixed} (a distribution may backport the fix; '
                                         'a copy a website bundles is not a package)',
                          'params': {'ecosystem': ecosystem, 'package': package, 'affected_below': fixed}})
    return remote, local


def _range_text(params):
    parts = []
    if params.get('introduced'):
        parts.append(f"from {params['introduced']}")
    if params.get('fixed'):
        parts.append(f"before {params['fixed']}")
    elif params.get('last_affected'):
        parts.append(f"up to {params['last_affected']}")
    return ' '.join(parts) or 'every version'


def _primary(components, remote, local):
    """The class the record's guidance is written for: a client-side library first, then the first product that got a check."""
    if any(c['kind'] == 'script_version' for c in remote):
        return 'client_library'
    for comp in components or []:
        if comp['class'] in ('os_platform', 'other', 'client_library'):
            continue
        return comp['class']
    return 'network_product'


def _ranges_text(ranges):
    """Every affected range in words (at most three): a host on another release line must see its own (nginx 1.18 is in 0.5.13 to 1.28.3,
    not in the first range 1.29.0 to 1.29.7)."""
    return ' or '.join(dict.fromkeys(_range_text(r) for r in (ranges or [])[:3])) or 'every version'


def rules_guidance(remote, local, has_template, components=None):
    """Plain guidance a person can follow, written from the checks alone (no model), in the words that fit the kind of product: what is
    affected, the steps to confirm it, and what makes a match true or false. A model-written record replaces it with something specific to
    the CVE. No "backported fix" language where no distribution package is involved (a served JavaScript file, an npm dependency)."""
    primary = _primary(components, remote, local)
    if primary == 'client_library':
        return library_guidance(remote, local, has_template, components)
    if primary == 'language_package':
        return _language_guidance(remote, local, has_template, components)
    if primary == 'os_package':
        return _os_package_guidance(remote, local, has_template, components)
    if primary == 'cms_component':
        return _cms_guidance(remote, local, has_template, components)
    versions = [c for c in remote if c['kind'] == 'version_banner']
    fixed = next((r['fixed'] for c in versions for r in c['params']['ranges'] if r.get('fixed')), None)
    identify = '; '.join(f"{c['params']['product']} {_ranges_text(c['params']['ranges'])}" for c in versions[:2])
    header = bool(versions) and versions[0]['params'].get('source') == 'http_header'
    steps = []
    if versions:
        product = versions[0]['params']['product']
        steps.append(f'Read the {product} version the host states: the match names the host, port and the banner or header cvENGINE read '
                     + ('(curl -sI shows the Server or X-Powered-By header).' if header else '(nmap -sV on that port shows the banner).'))
        steps.append('Compare it with the affected range' + (f' and the fixed release {fixed}.' if fixed else '.'))
    if has_template:
        steps.append('Run Validate now: the nuclei template for this CVE checks it from outside.')
    if local:
        steps.append('On the host, run the package check for its platform below: a Linux distribution backports fixes without changing the '
                     'upstream version, so its package release decides.')
    steps.append("Check the distribution's own security tracker for this CVE and the installed package release.")
    return {
        'identify': (f'Affects {identify}.' if identify else ''),
        'confirm_steps': steps[:6],
        'true_positive_signs': (['The nuclei template for this CVE matches.'] if has_template else []) +
                               (['The version found is inside the affected range, and the host\'s package release is not listed as fixed by '
                                 'its distribution.'] if versions else []),
        'false_positive_signs': ['The version found is at or above the fixed release.',
                                 'The distribution backported the fix, so the older version number is already patched.',
                                 'A proxy, load balancer or CDN in front states its own version, not the product behind it.',
                                 'The component is not installed, not reachable, or not the product the match was made on.'],
    }


def _coordinates_text(components, classes_=('language_package', 'client_library', 'cms_component')):
    from cveFeed.detection_classes import ECOSYSTEM_LABELS, LANGUAGE
    parts = []
    for comp in components or []:
        if comp['class'] not in classes_:
            continue
        for coord in comp.get('coordinates', []):
            if coord['ecosystem'] in LANGUAGE:
                parts.append(f"{ECOSYSTEM_LABELS[coord['ecosystem']]} {coord['package']}")
    return ', '.join(dict.fromkeys(parts))


def _language_guidance(remote, local, has_template, components):
    deps = [c for c in local if c['kind'] == 'package_version']
    fixed = next((c['params']['affected_below'] for c in deps if c['params'].get('affected_below')), None)
    versions = [c for c in remote if c['kind'] == 'version_banner']
    identify = '; '.join(f"{c['params']['product']} {_ranges_text(c['params']['ranges'])}" for c in versions[:2])
    where = _coordinates_text(components, ('language_package',))
    steps = ['From outside cvENGINE sees only a technology fingerprint (headers, page markers, a generator tag): it names the framework, '
             'rarely the exact dependency version.',
             f"In the application's source or deployment, read the resolved version from its lockfile or package manager ({where or 'the commands below'})."[:240],
             'Compare it with the affected range' + (f' and the fixed release {fixed}.' if fixed else '.'),
             "Check whether the application uses the affected feature: the advisory's condition is quoted with the guidance."]
    if has_template:
        steps.insert(1, 'Run Validate now: the nuclei template for this CVE checks it from outside.')
    return {
        'identify': (f'Affects {identify}: a dependency of an application, which no service banner or OS package states.' if identify else
                     'Affects a dependency of an application, which no service banner or OS package states.'),
        'confirm_steps': steps[:6],
        'true_positive_signs': (['The nuclei template for this CVE matches.'] if has_template else []) + [
            "The application's lockfile or package manager resolves the package to a version inside the affected range.",
            'The application uses the affected feature or function the advisory names.'],
        'false_positive_signs': ['The resolved version is at or above the fixed release.',
                                 'The package is only a development or build dependency and is not deployed.',
                                 'The fingerprint named a different product or framework than the advisory\'s package.'],
    }


def _os_package_guidance(remote, local, has_template, components):
    from cveFeed.detection_classes import ECOSYSTEM_LABELS
    packages = [c for c in local if c['kind'] == 'package_version']
    comp = next((c for c in components or [] if c['class'] == 'os_package'), {})
    platforms = ', '.join(comp.get('platforms', [])[:3])
    first = packages[0]['params'] if packages else {}
    label = ECOSYSTEM_LABELS.get(first.get('ecosystem', 'any'), 'package')
    fixed = first.get('affected_below', '')
    steps = [f"The fixed release {fixed} is a distribution's own package build{f' for {platforms}' if platforms else ''}: it applies only to "
             'those releases.' if fixed else 'The advisory names a distribution package: its own build decides, not the upstream version.',
             'On the host, read the installed package release with the command for its platform below and compare it with the fixed build.',
             "On another distribution, check that distribution's own security tracker for this CVE: its fixed build has a different number.",
             'A service banner states the upstream version only, so it cannot show which package build is installed.']
    if has_template:
        steps.append('Run Validate now: the nuclei template for this CVE checks it from outside.')
    return {
        'identify': f"Affects the {label} {first.get('package') or comp.get('name', '')}"
                    + (f' before {fixed}' if fixed else '') + (f' on {platforms}' if platforms else '') + '.',
        'confirm_steps': steps[:6],
        'true_positive_signs': (['The nuclei template for this CVE matches.'] if has_template else []) + [
            'The installed package release is older than the fixed build, on a release the advisory names.'],
        'false_positive_signs': ['The installed release is the fixed build or later.',
                                 "The host runs another distribution, whose own tracker lists this CVE as fixed or not affecting it.",
                                 'The package is not installed on the host.'],
    }


def _cms_guidance(remote, local, has_template, components):
    versions = [c for c in remote if c['kind'] == 'version_banner']
    product = versions[0]['params']['product'] if versions else next((c['name'] for c in components or [] if c['class'] == 'cms_component'), '')
    fixed = next((r['fixed'] for c in versions for r in c['params']['ranges'] if r.get('fixed')), None)
    identify = '; '.join(f"{c['params']['product']} {_ranges_text(c['params']['ranges'])}" for c in versions[:2])
    steps = [f'Read the {product} version from its own files: a WordPress plugin\'s readme.txt "Stable tag", a theme\'s style.css "Version", '
             'a Drupal module\'s .info.yml "version".',
             'Compare it with the affected range' + (f' and the fixed release {fixed}.' if fixed else '.'),
             'In the CMS administration (Plugins, Appearance or Extend), confirm the extension is installed and active.']
    if has_template:
        steps.append('Run Validate now: the nuclei template for this CVE checks it from outside.')
    return {
        'identify': (f'Affects the CMS extension {identify} (a plugin, theme or module), not a JavaScript library of the same name.'
                     if identify else 'Affects a CMS extension (a plugin, theme or module).'),
        'confirm_steps': steps[:6],
        'true_positive_signs': (['The nuclei template for this CVE matches.'] if has_template else []) + [
            'The extension\'s readme or stylesheet states a version inside the affected range, and the extension is active.'],
        'false_positive_signs': ['The extension\'s own files state a version at or above the fixed release.',
                                 'The extension is installed but not active.',
                                 'A JavaScript library or another product of the same name matched, not the CMS extension.'],
    }


def library_guidance(remote, local, has_template, components=None):
    """``rules_guidance`` for a client-side JavaScript library: the version is read from the script files a page loads, which copy runs
    decides, and a vulnerable version is not yet an exploitable page. An advisory that also names another product (CVE-2020-11022 names
    maximebf/debugbar beside jQuery) says how to check that one too."""
    from cveFeed.detection_classes import console_expression
    scripts = [c for c in remote if c['kind'] == 'script_version']
    others = [c for c in remote if c['kind'] == 'version_banner']
    products = list(dict.fromkeys(_libraries()[c['params']['library']][0] for c in scripts))
    product = products[0]
    key = scripts[0]['params']['library']
    fixed = next((r['fixed'] for c in scripts for r in c['params']['ranges'] if r.get('fixed')), None)
    identify = '; '.join(f"{_libraries()[c['params']['library']][0]} {_ranges_text(c['params']['ranges'])}" for c in scripts[:2])
    also = '; '.join(f"{c['params']['product']} {_ranges_text(c['params']['ranges'])}" for c in others[:2])
    console = console_expression(key)
    deps = _coordinates_text(components, ('client_library',))
    steps = [f'Open each script the page loads that names {product} and read the version in its first comment line: the html-libraries '
             'probe (Validate now) reads the same, never a ?ver= query string or the file name alone.',
             (f'In the browser console on that page, run {console}: it prints the version of the copy that actually runs.' if console else
              'When the page loads several copies, look at the one that runs (effective): a copy shadowed by a later one, or a fallback that '
              'loads only when another script fails, may never run.'),
             'Compare that version with the affected range' + (f' and the fixed release {fixed}.' if fixed else '.'),
             f'Check how the page uses {product}: the flaw needs attacker-controlled input (for an XSS flaw, HTML) to reach the affected '
             'functions, so a vulnerable version alone does not make the page exploitable.']
    if deps:
        steps.append(f"In the application's code, find which packaging supplies it ({deps}) with the dependency checks below."[:240])
    if others:
        steps.append(f"For {', '.join(dict.fromkeys(c['params']['product'] for c in others[:2]))}, which the advisory also names, read its "
                     'version where the application declares it and compare it with its own range.')
    if has_template:
        steps.append('Run Validate now: the nuclei template for this CVE checks it from outside.')
    if any(c['kind'] == 'package_version' and c['params']['ecosystem'] in ('dpkg', 'rpm', 'apk') for c in local):
        steps.append(f'On a host that ships {product} system-wide, run the package check below; a copy a website bundles is not a '
                     'package, and only the script read finds it.')
    return {
        'identify': (f'Affects {identify}, wherever a web page loads it (a copy bundled with the site or served from a CDN), or a '
                     'system-wide package ships it.' + (f' Also {also}.' if also else '')),
        'confirm_steps': steps[:6],
        'true_positive_signs': (['The nuclei template for this CVE matches.'] if has_template else []) + [
            f'The {product} file the page loads states a version inside the affected range (its banner or code), and it is the copy that runs.',
            f'A public CDN URL with an affected {product} version in it (for example /ajax/libs/jquery/1.12.4/), whose file states that version.',
            f'The page passes attacker-controlled input to the affected {product} functions.'],
        'false_positive_signs': ['The version the file states is at or above the fixed release.',
                                 'Only a ?ver= query string or the file name carried the version; the file itself states another or none.',
                                 'The script is shadowed by a later copy that is fixed, or is a fallback that loads only when another fails.',
                                 'The page no longer loads that copy, or the host only redirects to another one (a redirect alias).'],
    }


def installed_template_ids(cve):
    """Ids of nuclei templates installed for this CVE (the file stems); empty when none or the directory is unavailable."""
    try:
        from cveFeed.templategen import find_existing_template
        import os
        return [os.path.splitext(os.path.basename(p))[0] for p in find_existing_template(cve.cve_id)]
    except Exception:  # noqa: BLE001 - coverage is a hint; a missing templates directory must not stop authoring
        return []


def merge_strategies(base, extra):
    """``base`` with the checks of ``extra`` whose ids it lacks, keeping each list within MAX_CHECKS. For the written guidance, ``extra``
    wins where it has something and ``base`` fills the rest."""
    if not base:
        return extra
    if not extra:
        return base
    merged = dict(base)
    for key in ('remote_checks', 'local_checks'):
        have = {c['id'] for c in base[key]}
        merged[key] = (list(base[key]) + [c for c in extra[key] if c['id'] not in have])[:MAX_CHECKS]
    # the words a person reads: what the second author wrote wins over the rules' generic text, and generic text fills what it left empty
    for key in ('summary', 'false_positive_notes', 'remediation', 'scope', *GUIDANCE_TEXT):
        merged[key] = extra.get(key) or base.get(key) or ''
    for key in ('prerequisites', *GUIDANCE_LISTS):
        merged[key] = extra.get(key) or base.get(key) or []
    return merged


# --- what the strategy means: rendering and the validation profile -----------------------------------------------------------

ATTACK_VECTORS = {'N': 'network', 'A': 'adjacent', 'L': 'local', 'P': 'physical'}
_AV = re.compile(r'(?:^|/)AV:([NALP])(?:/|$)')
RENDERED_KEYS = ('how', 'commands')


def attack_vector(cvss_vector):
    found = _AV.search(cvss_vector or '')
    return ATTACK_VECTORS[found.group(1)] if found else None


def validation_profile(strategy, cvss_vector=''):
    """What a person (or a scanner) needs to know to decide a match for this CVE: whether it can be decided from outside, with which
    tools, and what makes a match validated, in need of validation, likely false, or not applicable. Computed from the checks and the
    CVSS attack vector, never written by a model. ``max_remote_state`` uses the triage states: confirmed (validated), likely,
    needs_validation."""
    remote, local = strategy.get('remote_checks', []), strategy.get('local_checks', [])
    vector = attack_vector(cvss_vector)
    scripts = [c for c in remote if is_script_read(c)]  # a client-side library: read from the page's script files, never by nmap
    decisive = [c for c in remote if c['kind'] in ('nuclei_template', 'http_probe', 'nse_script') and c['confidence'] in ('high', 'medium')]
    if vector in ('local', 'physical') and not decisive:
        determinable = 'no'
    elif decisive:
        determinable = 'yes'
    elif remote:
        determinable = 'partial'
    else:
        determinable = 'no'
    max_state = {'yes': 'confirmed', 'partial': 'likely', 'no': 'needs_validation'}[determinable]
    tools = []
    kinds = {_remote_kind(c) for c in remote}
    for kind, tool in (('nuclei_template', 'nuclei'), ('script_version', LIBRARY_TOOL), ('version_banner', 'nmap'),
                       ('version_header', 'curl'), ('version_fingerprint', 'technology fingerprint'), ('nse_script', 'nmap'),
                       ('port_service', 'nmap'), ('http_probe', 'curl'), ('tls_check', 'openssl')):
        if kind in kinds and tool not in tools:
            tools.append(tool)
    for check in local:
        tool = {'package_version': 'dependency tree' if _language_check(check) else 'package manager', 'file_version': 'grep',
                'config_setting': 'grep', 'service_state': 'systemctl', 'bundled_copy': 'grep'}.get(check['kind'], '')
        if tool and tool not in tools:
            tools.append(tool)
    validated, needs, false_positive = [], [], []
    for check in remote:
        p = check['params']
        if check['kind'] == 'nuclei_template':
            validated.append(f"the nuclei template {p['template_id']} matches")
        elif check['kind'] == 'http_probe':
            validated.append(f"{p['method']} {p['path']} answers as described in the check")
        elif check['kind'] == 'nse_script':
            validated.append(f"the nmap script {p['script']} output matches")
        elif is_script_read(check):
            product = _script_product(check)
            needs.append(f"only the {product} version a script file on the page states is in an affected range: whether the page can be "
                         f"exploited depends on how it uses {product}")
        elif check['kind'] == 'version_banner' and p.get('source') == 'technology':
            needs.append(f"only a technology fingerprint names {p['product']} at a version in an affected range: the application's own "
                         'dependency tree or files decide')
        elif check['kind'] == 'version_banner':
            needs.append(f"only the reported {p['product']} version is in an affected range (a banner can hide a backported fix)")
        elif check['kind'] in ('tls_check', 'port_service'):
            needs.append('the exposed service looks like the affected one, but nothing proves the vulnerable code path')
    for check in local:
        p = check['params']
        if check['kind'] == 'package_version' and _language_check(check):
            validated.append(f"in the application's dependency tree, {p['package']} resolves to a version older than "
                             f"{p.get('affected_below') or p.get('fixed_version')}")
        elif check['kind'] == 'bundled_copy':
            validated.append(f"on the web server, a bundled {_libraries()[p['library']][0]} file states a version inside an affected range")
        elif check['kind'] == 'package_version' and scripts:
            validated.append(f"on the host, the system-wide {p['package']} package is older than "
                             f"{p.get('affected_below') or p.get('fixed_version')} (a copy a website bundles is not a package: the script read decides that)")
        elif check['kind'] == 'package_version':
            validated.append(f"on the host, the installed {p['package']} is older than {p.get('affected_below') or p.get('fixed_version')}")
        elif check['kind'] in ('file_version', 'config_setting', 'service_state'):
            validated.append(f"on the host, the {check['kind'].replace('_', ' ')} check matches")
    if not validated and not needs:
        needs.append('the record names no check: read the advisory')
    needs.append('a check could not run (host unreachable, port filtered, login unavailable)')
    false_positive.append('the version is at or above the fixed release')
    distro = any(c['kind'] == 'package_version' and not _language_check(c) for c in local) or any(
        c['kind'] == 'version_banner' and c['params'].get('source') != 'technology' for c in remote)
    if distro:
        false_positive.append('the distribution lists the package as patched (a backported fix)')
    if any(_language_check(c) for c in local):
        false_positive.append('the package is only a development or build dependency and is not deployed')
    not_applicable = ['the affected component is not installed or not exposed on the host']
    if scripts:
        product = _script_product(scripts[0])
        false_positive = ['the version the script file states is at or above the fixed release',
                          'only a ?ver= query string or the file name carried the version; the file itself states another or none',
                          'the affected copy is shadowed by a later, fixed copy, or the page is a redirect alias of another host'] + (
            ['the distribution lists the system-wide package as patched (a backported fix)']
            if any(c['kind'] == 'package_version' and c['params']['ecosystem'] in ('dpkg', 'rpm', 'apk') for c in local) else [])
        not_applicable = [f'no page on the host loads {product} and no system-wide package ships it (a copy a website bundles is found only '
                          'by reading its pages)']
    out = {
        'attack_vector': vector,
        'remote_determinable': determinable,
        'max_remote_state': max_state,
        'host_validation': bool(local),
        'recommended_tools': tools,
        'validated_when': validated[:8],
        'needs_validation_when': needs[:8],
        'likely_false_positive_when': false_positive,
        'not_applicable_when': not_applicable + (
            ['the host cannot be reached by a local attacker'] if vector in ('local', 'physical') else []),
    }
    if scripts:
        product = _script_product(scripts[0])
        out['remote_note'] = (f'cvENGINE reads the {product} version from the script files the page loads (the html-libraries probe), from '
                              'the file itself, never from a ?ver= string or the file name alone. A hit proves that version is on the page, '
                              'not that the page is exploitable: that depends on how the page uses it.')
    return out


def _remote_kind(check):
    """The kind a remote check is read as, for the tools it needs: a library read, a version from a response header or a technology
    fingerprint (no nmap for either), else its own kind."""
    if is_script_read(check):
        return 'script_version'
    if check['kind'] == 'version_banner':
        return {'http_header': 'version_header', 'technology': 'version_fingerprint'}.get(check['params'].get('source'), 'version_banner')
    return check['kind']


def _language_check(check):
    """Whether a host check is of a language package (npm, PyPI, Maven, ...), read in the application's dependency tree, never with an OS
    package manager. An ``any`` package whose name can only be a language coordinate (``components/jquery``, ``org.webjars.npm:jquery``,
    ``@scope/name``) counts too."""
    if check['kind'] != 'package_version':
        return False
    from cveFeed.detection_classes import LANGUAGE, language_ecosystem_of
    eco = check['params'].get('ecosystem')
    return eco in LANGUAGE or (eco == 'any' and bool(language_ecosystem_of(check['params'].get('package'))))


def is_script_read(check):
    """Whether a remote check is a client-side library version read from a page's script files: a ``script_version`` check, or a
    ``version_banner`` (an older or model-written record) whose product is a library cvENGINE reads that way. nmap cannot read either. A
    banner check of a library whose name is also server-side code (SERVER_SIDE: React, Vue) is not reinterpreted: without the advisory it
    cannot be told which one it is, so it stays as it was written."""
    if check['kind'] == 'script_version':
        return True
    if check['kind'] == 'version_banner' and check['params'].get('source') == 'technology':
        return False  # a CMS extension or a language package that shares a library's name (Drupal's "Bootstrap" theme): never a script read
    key = library_key(check['params'].get('product')) if check['kind'] == 'version_banner' else ''
    return bool(key) and key not in SERVER_SIDE


def _script_product(check):
    key = check['params'].get('library') or library_key(check['params'].get('product'))
    return _libraries()[key][0] if key in _libraries() else check['params'].get('product', '')


def finalize(strategy, cvss_vector=''):
    """The strategy with every rendered part recomputed: the remote ``how``, the local ``commands`` and the ``validation`` profile. Run
    after every write that changes the checks; whatever those fields held before (a model cannot supply them) is discarded."""
    from cveFeed.detection_commands import render_local, render_remote
    if not strategy:
        return strategy
    out = {k: v for k, v in strategy.items() if k != 'validation'}
    for key, renderer, field in (('remote_checks', render_remote, 'how'), ('local_checks', render_local, 'commands')):
        checks = []
        for check in out.get(key, []):
            check = {k: v for k, v in check.items() if k not in RENDERED_KEYS}
            rendered = renderer(check)
            if rendered:
                check[field] = rendered
            checks.append(check)
        out[key] = checks
    out['validation'] = validation_profile(out, cvss_vector)
    return out


def prompt_guidance(cve):
    """The record's own words, trimmed, for an AI prompt about a match of this CVE: a hint about what makes it apply and what makes it
    false, never evidence (what this host showed is). None when the CVE has no record yet. Safe to read on any CVEEntry."""
    row = getattr(cve, 'detection', None)
    strategy = (row.strategy if row is not None else None) or {}
    if not strategy:
        return None
    profile = strategy.get('validation') or {}
    out = {'summary': strategy.get('summary') or '', 'identify': strategy.get('identify') or '',
           'true_positive_signs': (strategy.get('true_positive_signs') or [])[:3],
           'false_positive_signs': (strategy.get('false_positive_signs') or [])[:3],
           'decidable_from_outside': profile.get('remote_determinable') or '',
           'how_checked': profile.get('remote_note') or '',
           'written_by': row.source}
    return {k: v for k, v in out.items() if v} or None
