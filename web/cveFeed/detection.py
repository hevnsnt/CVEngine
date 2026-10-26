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

SCHEMA_VERSION = 1
MAX_CHECKS = 8
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
                'nse_script': _p_nse_script, 'tls_check': _p_tls_check, 'port_service': _p_port_service}
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
    allowed = {'summary', 'remote_checks', 'local_checks', 'prerequisites', 'false_positive_notes', 'remediation', 'safety'}
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
    if not out['remote_checks'] and not out['local_checks']:
        return None, problems + ['no usable check']
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
        if isinstance(candidate, dict) and ('remote_checks' in candidate or 'local_checks' in candidate):
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
    record names a package and a fixed version, and any installed nuclei template. None when the record names no product."""
    from cveFeed.correlation import clean_affected
    remote, local = [], []
    for item in clean_affected(cve.affected)[:6]:
        product = next((item.get(k) for k in ('product', 'package') if isinstance(item.get(k), str) and _PRODUCT.match(item[k])), None)
        ranges = [r for r in (_range_params(x) for x in item.get('ranges', [])[:10]) if r]
        if not product or not ranges:
            continue
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
    strategy, _ = validate_strategy({'summary': (cve.title or cve.cve_id)[:400], 'remote_checks': remote, 'local_checks': local})
    return strategy


def installed_template_ids(cve):
    """Ids of nuclei templates installed for this CVE (the file stems); empty when none or the directory is unavailable."""
    try:
        from cveFeed.templategen import find_existing_template
        import os
        return [os.path.splitext(os.path.basename(p))[0] for p in find_existing_template(cve.cve_id)]
    except Exception:  # noqa: BLE001 - coverage is a hint; a missing templates directory must not stop authoring
        return []


def merge_strategies(base, extra):
    """``base`` with the checks of ``extra`` whose ids it lacks, keeping each list within MAX_CHECKS. Text fields fill only when empty."""
    if not base:
        return extra
    if not extra:
        return base
    merged = dict(base)
    for key in ('remote_checks', 'local_checks'):
        have = {c['id'] for c in base[key]}
        merged[key] = (list(base[key]) + [c for c in extra[key] if c['id'] not in have])[:MAX_CHECKS]
    for key in ('summary', 'false_positive_notes', 'remediation'):
        merged[key] = base[key] or extra[key]
    merged['prerequisites'] = base['prerequisites'] or extra['prerequisites']
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
    kinds = {c['kind'] for c in remote}
    for kind, tool in (('nuclei_template', 'nuclei'), ('version_banner', 'nmap'), ('nse_script', 'nmap'), ('port_service', 'nmap'),
                       ('http_probe', 'curl'), ('tls_check', 'openssl')):
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
        elif check['kind'] == 'version_banner':
            needs.append(f"only the reported {p['product']} version is in an affected range (a banner can hide a backported fix)")
        elif check['kind'] in ('tls_check', 'port_service'):
            needs.append('the exposed service looks like the affected one, but nothing proves the vulnerable code path')
    for check in local:
        p = check['params']
        if check['kind'] == 'package_version':
            validated.append(f"on the host, the installed {p['package']} is older than {p.get('affected_below') or p.get('fixed_version')}")
        elif check['kind'] in ('file_version', 'config_setting', 'service_state'):
            validated.append(f"on the host, the {check['kind'].replace('_', ' ')} check matches")
    if not validated and not needs:
        needs.append('the record names no check: read the advisory')
    needs.append('a check could not run (host unreachable, port filtered, login unavailable)')
    false_positive += ['the version is at or above the fixed release', "the distribution lists the package as patched (a backported fix)"]
    return {
        'attack_vector': vector,
        'remote_determinable': determinable,
        'max_remote_state': max_state,
        'host_validation': bool(local),
        'recommended_tools': tools,
        'validated_when': validated[:8],
        'needs_validation_when': needs[:8],
        'likely_false_positive_when': false_positive,
        'not_applicable_when': ['the affected component is not installed or not exposed on the host'] + (
            ['the host cannot be reached by a local attacker'] if vector in ('local', 'physical') else []),
    }


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
