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

SCHEMA_VERSION = 3  # 2 adds the plain-language guidance (identify, confirm_steps, true/false-positive signs); 3 adds the script_version
#                     remote check (a client-side JavaScript library read from the script files a page loads). Older records stay valid
MAX_CHECKS = 8
GUIDANCE_LISTS = {'confirm_steps': (6, 240), 'true_positive_signs': (4, 180), 'false_positive_signs': (4, 180)}
GUIDANCE_TEXT = {'identify': 320, 'scope_reason': 200, 'revision_note': 200}
SCOPES = ('external', 'local_only', 'unclear')  # can an outside scan decide this CVE, only the host itself, or cannot tell
CONFIDENCE = ('high', 'medium', 'low')

_ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,39}$')
_PRODUCT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._+/@-]{0,99}$')
_VERSION = re.compile(r'^[0-9][0-9A-Za-z._+~:-]{0,63}$')
_PACKAGE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+@/-]{0,99}$')
_HTTP_PATH = re.compile(r'^/[A-Za-z0-9._~!$&\'()*+,;=:@%/-]{0,199}$')
_FILE_PATH = re.compile(r'^(?:/|[A-Za-z]:\\)[A-Za-z0-9._ @+()\\/-]{1,199}$')
_TEMPLATE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_MARKER = re.compile(r'^[\x20-\x7e]{1,100}$')
_SERVICE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')
_KEY = re.compile(r'^[A-Za-z0-9._:/-]{1,80}$')
_DOTS = re.compile(r'\.\.')  # a path that climbs out of where it starts

ECOSYSTEMS = ('any', 'dpkg', 'rpm', 'apk', 'pip', 'npm', 'gem', 'maven', 'nuget', 'go')
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


REMOTE_KINDS = {'version_banner': _p_version_banner, 'http_probe': _p_http_probe, 'nuclei_template': _p_nuclei_template,
                'nse_script': _p_nse_script, 'tls_check': _p_tls_check, 'port_service': _p_port_service, 'script_version': _p_script_version}
LOCAL_KINDS = {'package_version': _p_package_version, 'file_version': _p_file_version, 'config_setting': _p_config_setting,
               'service_state': _p_service_state}


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
               *GUIDANCE_TEXT, *GUIDANCE_LISTS, 'scope'}
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


def rules_strategy(cve, template_ids=()):
    """The strategy the CVE's own record supports, with no AI: a version check per affected product, a package check where the
    record names a package and a fixed version, and any installed nuclei template. None when the record names no product.

    A client-side JavaScript library cvENGINE reads from script files (``client_libraries``) gets a ``script_version`` check instead of a
    banner check, and host checks only for the system-wide packages that ship it (SYSTEM_PACKAGES); an entry that is a package bundling the
    library (``jquery-rails``) gets no check of its own: the copy it puts on a page is the one the script read finds."""
    from cveFeed.correlation import clean_affected, prepared_ranges
    libraries = cve_libraries(cve)
    remote, local = [], []
    if libraries:
        remote, local = _library_checks(libraries)
    for item in clean_affected(cve.affected)[:6]:
        product = next((item.get(k) for k in ('product', 'package') if isinstance(item.get(k), str) and _PRODUCT.match(item[k])), None)
        ranges = [r for r in (_range_params(x) for x in prepared_ranges(item.get('ranges'))[:10]) if r]  # as matching reads them, then capped
        if not product or not ranges:
            continue
        if libraries and (any(library_key(item.get(k)) for k in ('product', 'package')) or
                          any(_bundles(item.get(k), libraries) for k in ('product', 'package') if isinstance(item.get(k), str))):
            continue  # the library itself, or a package that bundles it: the script read above decides, never a banner or a host package name
        slug = re.sub(r'[^a-z0-9]+', '-', product.lower()).strip('-')[:24] or 'product'
        remote.append({'id': f'version-{slug}', 'kind': 'version_banner', 'confidence': 'medium',
                       'description': f'{product} reports a version inside an affected range (a banner can hide a backported fix)',
                       'params': {'product': product, 'ranges': ranges, 'source': 'any'}})
        package = item.get('package')
        fixed = next((r['fixed'] for r in ranges if 'fixed' in r), None)
        if isinstance(package, str) and _PACKAGE.match(package) and fixed:
            local.append({'id': f'package-{slug}', 'kind': 'package_version', 'confidence': 'high',
                          'description': f'the installed {package} package is older than the fixed release {fixed}',
                          'params': {'ecosystem': 'any', 'package': package, 'affected_below': fixed}})
    for template_id in list(template_ids)[:2]:
        if isinstance(template_id, str) and _TEMPLATE_ID.match(template_id):
            remote.append({'id': f'nuclei-{template_id.lower()}'[:40].rstrip('-_'), 'kind': 'nuclei_template', 'confidence': 'high',
                           'description': 'a nuclei template exists for this CVE', 'params': {'template_id': template_id}})
    if not remote and not local:
        return None
    strategy, _ = validate_strategy({'summary': (cve.title or cve.cve_id)[:400], 'remote_checks': remote, 'local_checks': local,
                                     **rules_guidance(remote, local, bool(template_ids))})
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


def rules_guidance(remote, local, has_template):
    """Plain guidance a person can follow, written from the checks alone (no model): what is affected, the steps to confirm it, and what
    makes a match true or false. A model-written record replaces it with something specific to the CVE."""
    if any(c['kind'] == 'script_version' for c in remote):
        return library_guidance(remote, local, has_template)
    versions = [c for c in remote if c['kind'] == 'version_banner']
    fixed = next((r['fixed'] for c in versions for r in c['params']['ranges'] if r.get('fixed')), None)
    identify = '; '.join(f"{c['params']['product']} {_range_text(c['params']['ranges'][0])}" for c in versions[:2])
    steps = []
    if versions:
        steps.append(f"Find the exact {versions[0]['params']['product']} version on the host (the Services tab shows what cvENGINE saw).")
        steps.append('Compare it with the affected range' + (f' and the fixed release {fixed}.' if fixed else '.'))
    if has_template:
        steps.append('Run Validate now: the nuclei template for this CVE checks it from outside.')
    if local:
        steps.append('On the host, run the check for its platform below and compare the result with what it says to look for.')
    steps.append('If it is a Linux package, check the distribution security tracker: a backported fix keeps the old version number.')
    return {
        'identify': (f'Affects {identify}.' if identify else ''),
        'confirm_steps': steps[:6],
        'true_positive_signs': (['The nuclei template for this CVE matches.'] if has_template else []) +
                               (['The version found is inside the affected range and the service is reachable.'] if versions else []),
        'false_positive_signs': ['The version found is at or above the fixed release.',
                                 'The distribution backported the fix, so the older version number is already patched.',
                                 'The component is not installed, not reachable, or not the product the match was made on.'],
    }


def library_guidance(remote, local, has_template):
    """``rules_guidance`` for a client-side JavaScript library: the version is read from the script files a page loads, which copy runs
    decides, and a vulnerable version is not yet an exploitable page. An advisory that also names another product (CVE-2020-11022 names
    maximebf/debugbar beside jQuery) says how to check that one too."""
    scripts = [c for c in remote if c['kind'] == 'script_version']
    others = [c for c in remote if c['kind'] == 'version_banner']
    products = list(dict.fromkeys(_libraries()[c['params']['library']][0] for c in scripts))
    product = products[0]
    fixed = next((r['fixed'] for c in scripts for r in c['params']['ranges'] if r.get('fixed')), None)
    identify = '; '.join(f"{_libraries()[c['params']['library']][0]} {_range_text(c['params']['ranges'][0])}" for c in scripts[:2])
    also = '; '.join(f"{c['params']['product']} {_range_text(c['params']['ranges'][0])}" for c in others[:2])
    steps = [f'Read the {product} version from the script files the page loads: the html-libraries probe (Validate now runs it) reads each '
             'file\'s own banner or code, never a ?ver= query string or the file name alone.',
             'When the page loads several copies, look at the one that runs (effective): a copy shadowed by a later one, or a fallback that '
             'loads only when another script fails, may never run.',
             'Compare that version with the affected range' + (f' and the fixed release {fixed}.' if fixed else '.'),
             f'Check how the page uses {product}: the flaw needs attacker-controlled input (for an XSS flaw, HTML) to reach the affected '
             'functions, so a vulnerable version alone does not make the page exploitable.']
    if others:
        steps.append(f"For {', '.join(dict.fromkeys(c['params']['product'] for c in others[:2]))}, which the advisory also names, find the exact "
                     'version on the host (the Services tab shows what cvENGINE saw) and compare it with its own range.')
    if has_template:
        steps.append('Run Validate now: the nuclei template for this CVE checks it from outside.')
    if local:
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
                                 'The host only redirects to another one (a redirect alias): the page and its scripts are that host\'s.'],
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
    kinds = {'script_version' if is_script_read(c) else c['kind'] for c in remote}
    for kind, tool in (('nuclei_template', 'nuclei'), ('script_version', LIBRARY_TOOL), ('version_banner', 'nmap'), ('nse_script', 'nmap'),
                       ('port_service', 'nmap'), ('http_probe', 'curl'), ('tls_check', 'openssl')):
        if kind in kinds and tool not in tools:
            tools.append(tool)
    for check in local:
        for tool in {'package_version': 'package manager', 'file_version': 'grep', 'config_setting': 'grep', 'service_state': 'systemctl'}.get(check['kind'], '').split(','):
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
        elif check['kind'] == 'version_banner':
            needs.append(f"only the reported {p['product']} version is in an affected range (a banner can hide a backported fix)")
        elif check['kind'] in ('tls_check', 'port_service'):
            needs.append('the exposed service looks like the affected one, but nothing proves the vulnerable code path')
    for check in local:
        p = check['params']
        if check['kind'] == 'package_version' and scripts:
            validated.append(f"on the host, the system-wide {p['package']} package is older than "
                             f"{p.get('affected_below') or p.get('fixed_version')} (a copy a website bundles is not a package: the script read decides that)")
        elif check['kind'] == 'package_version':
            validated.append(f"on the host, the installed {p['package']} is older than {p.get('affected_below') or p.get('fixed_version')}")
        elif check['kind'] in ('file_version', 'config_setting', 'service_state'):
            validated.append(f"on the host, the {check['kind'].replace('_', ' ')} check matches")
    if not validated and not needs:
        needs.append('the record names no check: read the advisory')
    needs.append('a check could not run (host unreachable, port filtered, login unavailable)')
    false_positive += ['the version is at or above the fixed release', "the distribution lists the package as patched (a backported fix)"]
    not_applicable = ['the affected component is not installed or not exposed on the host']
    if scripts:
        product = _script_product(scripts[0])
        false_positive = ['the version the script file states is at or above the fixed release',
                          'only a ?ver= query string or the file name carried the version; the file itself states another or none',
                          'the affected copy is shadowed by a later, fixed copy, or the page is a redirect alias of another host'] + (
            ['the distribution lists the system-wide package as patched (a backported fix)'] if local else [])
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


def is_script_read(check):
    """Whether a remote check is a client-side library version read from a page's script files: a ``script_version`` check, or a
    ``version_banner`` (an older or model-written record) whose product is a library cvENGINE reads that way. nmap cannot read either. A
    banner check of a library whose name is also server-side code (SERVER_SIDE: React, Vue) is not reinterpreted: without the advisory it
    cannot be told which one it is, so it stays as it was written."""
    if check['kind'] == 'script_version':
        return True
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
