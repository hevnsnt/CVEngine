"""The allowlist an AI-written or approved nuclei template must meet, as a whole document, before the server sends it to a Sentinel that is not the
built-in scanner (``agentapi.ai_checks.external_problem``). The Sentinel applies the same rules itself (``cvengine_scanner.check_allowlist`` of the
scanner library, this file rule for rule); both are tested against one corpus (the library's ``fixtures/checks/corpus.json``, field ``sentinel``,
``tests.test_ai_checks_on_sentinels``), and the tables of both are compared there too.

Every rule here is an allowlist, so a nuclei feature this module does not know is refused by default:

- **One plain YAML document that PyYAML and nuclei read alike** (``yaml_problem``). nuclei reads templates with Go's ``gopkg.in/yaml.v3`` (YAML 1.2);
  PyYAML is YAML 1.1. They disagree on duplicate keys (PyYAML keeps the last, yaml.v3 refuses or keeps another), a second document (yaml.v3 reads
  the first), anchors, aliases and merge keys, explicit tags, YAML 1.1 words such as ``on``/``yes``/``no`` (PyYAML: booleans, yaml.v3: strings),
  non-decimal or sexagesimal numbers, and the line breaks U+0085, U+2028 and U+2029 (YAML 1.1 only). Any of these is refused, so the text this
  module judges is the text nuclei runs.
- **Known keys only** (``TOP_KEYS``, ``INFO_KEYS``, per-protocol ``BLOCK_KEYS``, ``MATCHER_KEYS``, ``EXTRACTOR_KEYS``): matched exactly, so a
  look-alike (``b\u043edy`` with a Cyrillic o, ``Method``) or a future nuclei key is refused.
- **Every expression uses only listed names** (``expression_problem``): each ``{{...}}`` anywhere in the document, every ``dsl`` string of a matcher or
  extractor, and every ``variables`` value. A function call must be one of ``FUNCTIONS``, pure string, encoding, hash and comparison helpers with no
  network, file, environment, clock or sleep effect; ``resolve``, ``jarm``, ``public_ip``, ``wappalyzer``, ``llm_prompt``, ``wait_for``,
  ``print_debug``, ``unix_time``, ``date_time``, ``rand_*`` and every other helper are refused. A bare name must be a target placeholder
  (``PLACEHOLDERS``), a response part (``RESPONSE_NAMES``, optionally numbered ``body_2``) or a variable or extractor the template itself defines.
  nuclei's other expression marker (U+00A7) is refused anywhere.
- **Plain requests to the task's own host and port** (``http_problem``): methods GET, HEAD or OPTIONS; a raw request is exactly one request line and
  header lines, no body, no ``@`` annotation (``@Host`` re-aims a request), no ``Content-Length``, ``Transfer-Encoding`` or ``Connection``; a ``Host``
  header only in raw text and only ``{{Hostname}}``, ``{{Host}}`` or ``{{Host}}:{{Port}}``; no ``Authorization``, ``Cookie``, ``Proxy-*``,
  forwarding or rewrite header, and no header whose name or value looks like a credential.

Pure: text in, a reason out (``''`` when acceptable).
"""
import re

TOP_KEYS = frozenset({'id', 'info', 'variables', 'http', 'requests', 'network', 'tcp', 'dns', 'ssl', 'stop-at-first-match'})
INFO_KEYS = frozenset({'name', 'author', 'severity', 'description', 'reference', 'tags', 'classification', 'metadata', 'remediation', 'impact'})
CLASSIFICATION_KEYS = frozenset({'cve-id', 'cwe-id', 'cvss-metrics', 'cvss-score', 'epss-score', 'epss-percentile', 'cpe'})
_COMMON_BLOCK = frozenset({'matchers', 'matchers-condition', 'extractors'})
BLOCK_KEYS = {
    'http': _COMMON_BLOCK | {'method', 'path', 'raw', 'headers', 'host-redirects', 'max-redirects', 'redirects', 'stop-at-first-match', 'max-size'},
    'network': _COMMON_BLOCK | {'host', 'inputs', 'read-size'},
    'dns': _COMMON_BLOCK | {'name', 'type', 'class', 'recursion'},
    'ssl': _COMMON_BLOCK | {'address', 'min_version', 'max_version'},
}
BLOCK_KEYS['requests'] = BLOCK_KEYS['http']
BLOCK_KEYS['tcp'] = BLOCK_KEYS['network']
INPUT_KEYS = frozenset({'read'})
MATCHER_KEYS = frozenset({'type', 'part', 'words', 'regex', 'status', 'size', 'dsl', 'binary', 'condition', 'negative', 'name', 'case-insensitive',
                          'match-all', 'internal', 'encoding'})
MATCHER_TYPES = frozenset({'word', 'regex', 'status', 'size', 'dsl', 'binary'})
EXTRACTOR_KEYS = frozenset({'type', 'part', 'name', 'regex', 'group', 'kval', 'dsl', 'internal', 'case-insensitive'})
EXTRACTOR_TYPES = frozenset({'regex', 'kval', 'dsl'})  # no json (gojq can read the environment) or xpath
METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})
DNS_TYPES = frozenset({'A', 'AAAA', 'CNAME', 'NS', 'TXT', 'MX', 'SOA', 'PTR', 'CAA', 'SRV'})
TLS_VERSIONS = frozenset({'sslv3', 'tls10', 'tls11', 'tls12', 'tls13'})
SEVERITIES = frozenset({'info', 'low', 'medium', 'high', 'critical', 'unknown'})

# Target placeholders nuclei fills from the input it was pointed at. ``randstr`` (and ``randstr_1``...) is a random word nuclei makes once per run.
PLACEHOLDERS = frozenset({'BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'Path', 'Scheme', 'FQDN', 'randstr'})
# Response parts a matcher or extractor reads (a lookup in the response map: no side effect). http ones may be numbered for a multi-request check.
RESPONSE_NAMES = frozenset({'body', 'header', 'all_headers', 'status_code', 'content_length', 'content_type', 'response', 'raw', 'request', 'duration',
                            'host', 'matched', 'data', 'answer', 'ns', 'extra', 'question', 'rcode',
                            'tls_version', 'cipher', 'expired', 'self_signed', 'mismatched', 'revoked', 'untrusted', 'not_before', 'not_after',
                            'subject_cn', 'subject_org', 'subject_an', 'issuer_cn', 'issuer_org', 'serial'})
_NUMBERED = frozenset({'body', 'header', 'all_headers', 'status_code', 'content_length', 'content_type', 'response', 'raw', 'request', 'duration'})
PARTS = frozenset({'body', 'header', 'all_headers', 'all', 'response', 'raw', 'request', 'content_type', 'data', 'answer', 'ns', 'extra', 'question'})
# nuclei DSL helpers (``nuclei -ldf`` of the pinned image) that only compute on their arguments: no network, file, environment, clock or sleep, and
# output bounded by their input (no ``repeat``, ``rand_base`` or decompression, which a template could use to exhaust memory).
FUNCTIONS = frozenset({
    'contains', 'contains_all', 'contains_any', 'starts_with', 'ends_with', 'line_starts_with', 'line_ends_with', 'equals_any',
    'regex', 'regex_any', 'regex_all', 'compare_versions', 'len',
    'to_lower', 'to_upper', 'trim', 'trim_left', 'trim_right', 'trim_space', 'trim_prefix', 'trim_suffix', 'replace', 'reverse', 'concat',
    'to_number', 'to_string',
    'base64', 'base64_decode', 'hex_encode', 'hex_decode', 'url_encode', 'url_decode', 'html_escape', 'html_unescape',
    'md5', 'sha1', 'sha256', 'mmh3',
})
LITERALS = frozenset({'true', 'false'})
MAX_EXPRESSION = 1000
MAX_HEADERS = 12

# Headers a check never sets: the destination (``Host`` outside raw text), forwarding and rewrite headers that steer a proxy or a back end,
# credentials, and the framing headers that make one request into two.
FORBIDDEN_HEADERS = frozenset({'host', 'authorization', 'proxy-authorization', 'cookie', 'cookie2', 'forwarded', 'x-real-ip', 'x-original-url',
                               'x-rewrite-url', 'x-host', 'x-http-method-override', 'x-http-method', 'x-method-override', 'content-length',
                               'transfer-encoding', 'connection', 'upgrade', 'te', 'expect', 'keep-alive', 'trailer', 'http2-settings'})
_FORBIDDEN_HEADER_PREFIXES = ('proxy-', 'x-forwarded-', 'x-original-', 'x-envoy-')
_CREDENTIAL_NAME = re.compile(r'(?i)auth|token|secret|passw|api[-_]?key|session|cookie|credential|jwt|csrf|xsrf|signature|bearer')
_CREDENTIAL_VALUE = re.compile(
    r'(?i)\b(?:bearer|basic|digest|negotiate|ntlm|token|apikey)\s+\S'  # an authorization scheme
    r'|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}'  # a JWT
    r'|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'  # an AWS key id
    r'|(?:passw\w*|secret|token|api[-_]?key|session\w*|sid|auth\w*)\s*[=:]'  # name=value or name: value
    r'|[A-Za-z0-9+/_-]{32,}={0,2}')  # a long opaque string
_HEADER_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')
_RAW_HOST = re.compile(r'^\{\{(?:Hostname|Host)\}\}$|^\{\{Host\}\}:\{\{Port\}\}$')
_REQUEST_LINE = re.compile(r'^(GET|HEAD|OPTIONS) (\S+) HTTP/1\.[01]$')
_IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,40}$')
_META_KEY = re.compile(r'^[a-z][a-z0-9_-]{0,40}$')
_TEMPLATE_ID = re.compile(r'^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*$')
_NUMBERED_NAME = re.compile(r'^([a-z_]+?)_([1-9][0-9]?)$')
_RANDSTR = re.compile(r'^randstr(?:_[1-9][0-9]?)?$')
# YAML 1.1 line breaks (YAML 1.2 reads them as ordinary characters), bidi controls and every C0/C1 control but tab and newline.
_BAD_CHARS = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]')
_TOKEN = re.compile(r'''\s+|(?P<str>'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")|(?P<num>\d+(?:\.\d+)?)|(?P<id>[A-Za-z_][A-Za-z0-9_]*)'''
                    r'''|(?P<op>==|!=|>=|<=|=~|!~|&&|\|\||[-+*/%<>!(),?:])''')
_PLAIN_INT = re.compile(r'^[-+]?(?:0|[1-9][0-9]*)$')
_PLAIN_BOOL = frozenset({'true', 'True', 'TRUE', 'false', 'False', 'FALSE'})
_PLAIN_NULL = frozenset({'', '~', 'null', 'Null', 'NULL'})


def _fail(reason):
    return f'template not validated: {reason}'


# --- the YAML document ------------------------------------------------------------------------------------------------------------------------

def yaml_problem(text):
    """Why ``text`` is not one plain YAML document PyYAML and nuclei's yaml.v3 read alike, or ``''`` (see the module text)."""
    import yaml
    if not isinstance(text, str) or not text or '\0' in text:
        return _fail('empty or not text')
    bad = _BAD_CHARS.search(text)
    if bad:
        return _fail(f'it contains the control or line-break character U+{ord(bad.group()):04X}')
    if '\u00a7' in text:
        return _fail("it contains nuclei's second expression marker (U+00A7)")
    try:
        events = list(yaml.parse(text, Loader=yaml.SafeLoader))
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return _fail('not valid YAML, or more than one YAML document')
    if sum(isinstance(e, yaml.DocumentStartEvent) for e in events) != 1:
        return _fail('a template is exactly one YAML document')
    resolver = yaml.resolver.Resolver()
    for event in events:
        if isinstance(event, yaml.DocumentStartEvent) and (event.version or event.tags):
            return _fail('YAML directives are not allowed')
        if isinstance(event, yaml.DocumentEndEvent) and event.explicit:
            return _fail('an explicit document end (...) is not allowed: a template is one document')
        if isinstance(event, yaml.AliasEvent) or getattr(event, 'anchor', None) is not None:
            return _fail('anchors and aliases are not allowed in a template')
        if isinstance(event, (yaml.ScalarEvent, yaml.SequenceStartEvent, yaml.MappingStartEvent)) and event.tag is not None:
            return _fail('explicit YAML tags are not allowed')
        if isinstance(event, yaml.ScalarEvent) and event.style is None:
            problem = _plain_scalar_problem(resolver.resolve(yaml.ScalarNode, event.value, (True, False)), event.value)
            if problem:
                return _fail(problem)
    return _duplicate_problem(root)


def _plain_scalar_problem(tag, value):
    kind = tag.rsplit(':', 1)[-1]
    if kind == 'merge':
        return 'YAML merge keys are not allowed'
    if kind == 'str' or (kind == 'bool' and value in _PLAIN_BOOL) or (kind == 'int' and _PLAIN_INT.match(value)) or \
            (kind == 'null' and value in _PLAIN_NULL):
        return ''
    return f'the plain value {value[:40]!r} reads differently in YAML 1.1 and 1.2 (quote it, or write true, false or a decimal number)'


def _duplicate_problem(node):
    import yaml
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key, value in node.value:
                if not isinstance(key, yaml.ScalarNode):
                    return _fail('a mapping key must be a plain string')
                if key.value == '<<':
                    return _fail('YAML merge keys are not allowed')
                if key.value in seen:
                    return _fail(f'the key {key.value[:40]!r} appears twice in one mapping')
                seen.add(key.value)
                stack.append(value)
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return ''


# --- expressions --------------------------------------------------------------------------------------------------------------------------------

def expression_problem(expr, names=frozenset()):
    """Why the nuclei expression ``expr`` (the inside of ``{{...}}`` or a ``dsl`` string) is not allowed, or ``''``: only the tokens of a plain
    expression (string and number literals, names, comparison, logic, arithmetic, parentheses, commas, the ternary), every call a ``FUNCTIONS``
    helper, every bare name a placeholder, a response part, ``true``/``false`` or one of ``names`` (the template's own variables and extractors).
    No member access (``.``), indexing, braces or any other character."""
    if not isinstance(expr, str) or not expr.strip() or len(expr) > MAX_EXPRESSION:
        return 'an expression is empty or too long'
    tokens, pos = [], 0
    while pos < len(expr):
        match = _TOKEN.match(expr, pos)
        if match is None:
            return f'an expression contains {expr[pos]!r}, which no allowed expression uses: {expr[:60]!r}'
        pos = match.end()
        if match.lastgroup:
            tokens.append((match.lastgroup, match.group(match.lastgroup)))
    for i, (kind, value) in enumerate(tokens):
        if kind != 'id':
            continue
        called = i + 1 < len(tokens) and tokens[i + 1] == ('op', '(')
        if called:
            if value not in FUNCTIONS:
                return f'the helper {value}() is not on the allowlist of side-effect-free helpers'
        elif not _known_name(value, names):
            return f'the name {value!r} is not a target placeholder, a response part or a variable of the template'
    return ''


def _known_name(name, names):
    if name in PLACEHOLDERS or name in RESPONSE_NAMES or name in LITERALS or name in names or _RANDSTR.match(name):
        return True
    numbered = _NUMBERED_NAME.match(name)
    return bool(numbered and numbered.group(1) in _NUMBERED)


def braces_problem(text, names):
    """Why a string's ``{{...}}`` expressions are not all allowed, or ``''``. An opening ``{{`` with no closing ``}}`` is refused too."""
    pos = 0
    while True:
        start = text.find('{{', pos)
        if start < 0:
            return ''
        end = text.find('}}', start + 2)
        if end < 0:
            return 'an expression is opened with {{ and never closed'
        problem = expression_problem(text[start + 2:end], names)
        if problem:
            return problem
        pos = end + 2


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


# --- keys and requests ------------------------------------------------------------------------------------------------------------------------

def _keys_problem(mapping, allowed, where):
    if not isinstance(mapping, dict):
        return f'{where} must be a mapping'
    unknown = sorted(str(k) for k in mapping if not isinstance(k, str) or k not in allowed)
    return f'{where} uses a key not on the allowlist: {unknown[0][:40]!r}' if unknown else ''


def _scalar(value):
    return isinstance(value, (str, int, float)) and not isinstance(value, bool) or isinstance(value, bool)


def _info_problem(info):
    problem = _keys_problem(info, INFO_KEYS, 'info')
    if problem:
        return problem
    if not isinstance(info.get('name'), str) or str(info.get('severity', '')).lower() not in SEVERITIES:
        return 'info needs a name and a known severity'
    for key in ('name', 'author', 'severity', 'description', 'remediation', 'impact'):
        if key in info and not isinstance(info[key], str):
            return f'info {key} must be text'
    for key in ('reference', 'tags'):
        value = info.get(key)
        if value is not None and not isinstance(value, str) and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
            return f'info {key} must be text or a list of text'
    if 'classification' in info:
        problem = _keys_problem(info['classification'], CLASSIFICATION_KEYS, 'info classification')
        if problem or not all(_scalar(v) or (isinstance(v, list) and all(_scalar(i) for i in v)) for v in info['classification'].values()):
            return problem or 'info classification holds only plain values'
    if 'metadata' in info:
        meta = info['metadata']
        if not isinstance(meta, dict) or not all(isinstance(k, str) and _META_KEY.match(k) for k in meta) or \
                not all(_scalar(v) or (isinstance(v, list) and all(_scalar(i) for i in v)) for v in meta.values()):
            return 'info metadata holds only plain names and values'
    return ''


def header_problem(name, value):
    """Why a request header may not be sent by a check, or ``''``: a plain name not on ``FORBIDDEN_HEADERS``, no credential in its name or value."""
    if not isinstance(name, str) or not _HEADER_NAME.match(name):
        return f'the header name {str(name)[:40]!r} is not a plain header name'
    lowered = name.lower()
    if lowered in FORBIDDEN_HEADERS or lowered.startswith(_FORBIDDEN_HEADER_PREFIXES):
        return f'the header {name!r} steers or authenticates a request, which a check never does'
    if _CREDENTIAL_NAME.search(lowered):
        return f'the header {name!r} carries a credential, which a check never sends'
    if not isinstance(value, str) or '\n' in value or '\r' in value:
        return f'the header {name!r} must have one line of text as its value'
    if _CREDENTIAL_VALUE.search(value):
        return f'the value of the header {name!r} looks like a credential, which a check never sends'
    return ''


def raw_problem(text):
    """Why a raw request is not exactly one GET, HEAD or OPTIONS request to the task's own host with plain headers and no body, or ``''``."""
    if not isinstance(text, str):
        return 'a raw request must be text'
    lines = text.split('\n')
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines or '\r' in text:
        return 'a raw request is one request line and header lines'
    line = _REQUEST_LINE.match(lines[0])
    if not line:
        return f'a raw request line must be GET, HEAD or OPTIONS, a path and HTTP/1.1: {lines[0][:60]!r}'
    target = line.group(2)
    if not (target.startswith('/') and not target.startswith('//')) and not (target == '{{BaseURL}}' or target.startswith('{{BaseURL}}/')):
        return f'a raw request line must use /path or {{{{BaseURL}}}}/path: {lines[0][:60]!r}'
    hosts = 0
    for header in lines[1:]:
        if not header.strip():
            return 'a raw request may not have a body (or a second request after a blank line)'
        if header.startswith('@'):
            return f'a raw request annotation ({header.split(":", 1)[0][:20]}) can re-aim or reshape a request and is not allowed'
        name, sep, value = header.partition(':')
        if not sep or not value.startswith(' ') and value:
            return f'a raw request holds a line that is not a header: {header[:60]!r}'
        value = value.strip()
        if name.lower() == 'host':
            hosts += 1
            if not _RAW_HOST.match(value) or hosts > 1:
                return 'a raw Host header must be {{Hostname}}, {{Host}} or {{Host}}:{{Port}}, once'
            continue
        problem = header_problem(name, value)
        if problem:
            return problem
    if len(lines) - 1 > MAX_HEADERS:
        return f'a raw request may set at most {MAX_HEADERS} headers'
    return ''


def http_problem(block):
    """The request rules of one http block (``raw_problem``, ``header_problem``, methods, redirects to the same host only)."""
    if 'raw' in block:
        if 'method' in block or 'path' in block or 'headers' in block:
            return 'a raw request block may not also name a method, path or headers'
        raws = block['raw']
        if not isinstance(raws, list) or not raws:
            return 'raw requests must be a list'
        for raw in raws:
            problem = raw_problem(raw)
            if problem:
                return problem
    else:
        if block.get('method', 'GET') not in METHODS:
            return f'the http method {str(block.get("method"))[:20]!r} is not GET, HEAD or OPTIONS'
        if not isinstance(block.get('path'), list) or not block['path'] or not all(isinstance(p, str) for p in block['path']):
            return 'an http block needs a list of paths'
        headers = block.get('headers') or {}
        if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
            return f'headers must be a mapping of at most {MAX_HEADERS} entries'
        for name, value in headers.items():
            problem = header_problem(name, value)
            if problem:
                return problem
    if block.get('redirects', False) is not False:
        return 'redirects to other hosts are not allowed'
    if not isinstance(block.get('host-redirects', False), bool):
        return 'host-redirects must be true or false'
    if 'max-redirects' in block and not (type(block['max-redirects']) is int and 0 <= block['max-redirects'] <= 3):
        return 'max-redirects must be 0 to 3'
    if 'max-size' in block and not (type(block['max-size']) is int and 0 < block['max-size'] <= 10 * 1024 * 1024):
        return 'max-size must be a positive number of bytes up to 10 MiB'
    return ''


def _part_ok(part):
    if not isinstance(part, str):
        return False
    numbered = _NUMBERED_NAME.match(part)
    return part in PARTS or bool(numbered and numbered.group(1) in _NUMBERED)


def _operators_problem(block, names):
    for key, allowed, types, where in (('matchers', MATCHER_KEYS, MATCHER_TYPES, 'a matcher'), ('extractors', EXTRACTOR_KEYS, EXTRACTOR_TYPES,
                                                                                              'an extractor')):
        items = block.get(key) or []
        if not isinstance(items, list):
            return f'{key} must be a list'
        for item in items:
            problem = _keys_problem(item, allowed, where)
            if problem:
                return problem
            if item.get('type') not in types:
                return f'{where} of type {str(item.get("type"))[:20]!r} is not allowed'
            part = item.get('part')
            if part is not None and not _part_ok(part):
                return f'{where} reads the part {str(part)[:30]!r}, which is not a response part'
            for field in ('condition',):
                if field in item and item[field] not in ('and', 'or'):
                    return f'{where} condition must be and or or'
            dsl = item.get('dsl')
            if dsl is not None:
                if not isinstance(dsl, list) or not all(isinstance(d, str) for d in dsl):
                    return f'{where} dsl must be a list of expressions'
                for expr in dsl:
                    problem = expression_problem(expr, names)
                    if problem:
                        return f'{where} dsl: {problem}'
    if block.get('matchers-condition', 'and') not in ('and', 'or'):
        return 'matchers-condition must be and or or'
    return ''


def _defined_names(doc):
    """The names a template defines for its own expressions: its ``variables`` and the ``name`` of each extractor."""
    names = set()
    variables = doc.get('variables') or {}
    if isinstance(variables, dict):
        names.update(k for k in variables if isinstance(k, str))
    for proto in BLOCK_KEYS:
        for block in doc.get(proto) or [] if isinstance(doc.get(proto), list) else []:
            for extractor in (block.get('extractors') or []) if isinstance(block, dict) and isinstance(block.get('extractors'), list) else []:
                if isinstance(extractor, dict) and isinstance(extractor.get('name'), str):
                    names.add(extractor['name'])
    return names


def _variables_problem(variables, names):
    if not isinstance(variables, dict):
        return 'variables must be a mapping'
    for key, value in variables.items():
        if not isinstance(key, str) or not _IDENT.match(key) or key in PLACEHOLDERS or key in RESPONSE_NAMES or key in FUNCTIONS or key in LITERALS:
            return f'the variable name {str(key)[:40]!r} is not a plain name of its own'
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return f'the variable {key!r} must be text or a number'
        outside = re.sub(r'\{\{.*?\}\}', '', str(value))
        call = re.search(r'([A-Za-z_]\w*)\s*\(', outside)
        if call:
            return f'the variable {key!r} calls the helper {call.group(1)}() outside an expression'
    return ''


def allowlist_problem(text):
    """Why ``text`` is not on the allowlist a Sentinel other than the built-in scanner runs, or ``''`` (the module text)."""
    problem = yaml_problem(text)
    if problem:
        return problem
    import yaml
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        return _fail('not a template')
    problem = _keys_problem(doc, TOP_KEYS, 'the template')
    if problem:
        return _fail(problem)
    if not isinstance(doc.get('id'), str) or not _TEMPLATE_ID.match(doc['id']):
        return _fail('missing or malformed id')
    problem = _info_problem(doc.get('info'))
    if problem:
        return _fail(problem)
    if 'stop-at-first-match' in doc and not isinstance(doc['stop-at-first-match'], bool):
        return _fail('stop-at-first-match must be true or false')
    names = frozenset(_defined_names(doc))
    if 'variables' in doc:
        problem = _variables_problem(doc['variables'], names)
        if problem:
            return _fail(problem)
    protocols = [p for p in BLOCK_KEYS if p in doc]
    if not protocols:
        return _fail('no protocol section')
    for proto in protocols:
        blocks = doc[proto]
        if not isinstance(blocks, list) or not blocks:
            return _fail(f'malformed {proto} section')
        for block in blocks:
            problem = _keys_problem(block, BLOCK_KEYS[proto], f'a {proto} block') or _block_problem(proto, block) or _operators_problem(block, names)
            if problem:
                return _fail(problem)
    for value in _strings(doc):
        problem = braces_problem(value, names)
        if problem:
            return _fail(problem)
    return ''


def _block_problem(proto, block):
    if proto in ('http', 'requests'):
        return http_problem(block)
    if proto in ('network', 'tcp'):
        inputs = block.get('inputs') or []
        if not isinstance(inputs, list) or any(_keys_problem(i, INPUT_KEYS, 'a network input') or type(i.get('read')) is not int for i in inputs):
            return 'network checks may only read banners (inputs: read)'
        if 'read-size' in block and not (type(block['read-size']) is int and 0 < block['read-size'] <= 65536):
            return 'read-size must be 1 to 65536'
        hosts = block.get('host')
        if not isinstance(hosts, list) or not hosts or not all(h in ('{{Hostname}}', '{{Host}}', '{{Host}}:{{Port}}') for h in hosts):
            return 'a network host must be {{Hostname}}, {{Host}} or {{Host}}:{{Port}}'
        return ''
    if proto == 'dns':
        if block.get('name', '{{FQDN}}') != '{{FQDN}}' or str(block.get('type', 'A')) not in DNS_TYPES:
            return 'a dns check asks only for {{FQDN}}, with a plain record type'
        if block.get('class', 'inet') != 'inet' or not isinstance(block.get('recursion', True), bool):
            return 'a dns check uses class inet and a true or false recursion'
        return ''
    if block.get('address', '{{Host}}:{{Port}}') != '{{Host}}:{{Port}}':
        return 'ssl address must be {{Host}}:{{Port}}'
    if any(k in block and block[k] not in TLS_VERSIONS for k in ('min_version', 'max_version')):
        return 'ssl versions must be one of ' + ', '.join(sorted(TLS_VERSIONS))
    return ''
