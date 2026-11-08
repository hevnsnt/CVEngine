"""AI nuclei-template generation for CVEs no installed template covers.

Flow (PIPELINE.md stage 7): use an approved installed template when available.
Otherwise the AI may write a draft, whose syntax and false positives are tested against
a benign local fixture on the built-in scanner (``sentinel_dispatch.try_nuclei_validate``).
A draft is never executed on a customer host merely because its YAML parsed and the
scanner accepted its syntax. The server runs no template itself: every check and every test
goes to a scanner, and with none live the work waits (``ScannerUnavailable``).

Sandbox: model output is untrusted. ``static_check`` only admits passive-ish
protocols (http/network/dns/ssl/tcp), rejects ``code``/``javascript``/``headless``/
``file`` (arbitrary execution or local file access) and anything off-schema, and
a scanner runs templates with code templates disabled, a timeout, and a rate limit, only
against hosts already in the inventory.
"""
import datetime
import json
import logging
import os
import re

import yaml

from cveFeed.safeyaml import load_template
from reNgine import ai_prompts
from reNgine.ai_providers import UNTRUSTED_NOTICE, clean_text

logger = logging.getLogger(__name__)

TEMPLATES_ROOT = os.environ.get("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")
# Deliberately NOT under TEMPLATES_ROOT: the blanket `nuclei -l` pass loads everything in the default template
# directory, which would run an AI-written template against every tenant's hosts. These run only via explicit -t.
GENERATED_DIR = os.environ.get("CVENGINE_GENERATED_TEMPLATES_DIR", "/root/cvengine-generated-templates")
MAX_TEMPLATE_BYTES = 20000
RUN_TIMEOUT = 180
CHUNK_HOSTS = 100  # hosts per template check

ALLOWED_PROTOCOLS = {"http", "requests", "network", "tcp", "dns", "ssl"}
FORBIDDEN_PROTOCOLS = {"code", "javascript", "headless", "file", "workflows", "flow"}
ALLOWED_TOP_KEYS = ALLOWED_PROTOCOLS | {"id", "info", "variables", "self-contained", "stop-at-first-match"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,100}$")
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

SYSTEM_PROMPT = ai_prompts.compose('template_generation',
    "Write it as nuclei v3 YAML. Output ONLY one YAML document, "
    "no prose. Rules: id must be the lowercase CVE id (e.g. cve-2024-1234); include "
    "info.name, info.author: cvengine-ai, info.severity, info.description, "
    "info.reference, info.tags including the CVE id; use ONLY the http or network "
    "protocol; the check must be non-destructive and detect the vulnerability by "
    "version or a safe response marker with matchers (never exploit, never write or "
    "delete data, no code/javascript/headless/file protocols, no interactsh). Requests may "
    "target only the scanned host: http paths must be {{BaseURL}} or {{BaseURL}}/path; network checks may only read banners without sending inputs. Network hosts "
    "must be {{Hostname}} or {{Host}}; never include any other URL or hostname, and no "
    "redirects. " + UNTRUSTED_NOTICE)


def _clean_value(value, limit, depth=0):
    """clean_text through nested lists and dicts (the feed's ``affected`` entries and ``references`` are third-party strings)."""
    if isinstance(value, str):
        return clean_text(value, limit)
    if depth < 4 and isinstance(value, (list, tuple)):
        return [_clean_value(v, limit, depth + 1) for v in value[:100]]
    if depth < 4 and isinstance(value, dict):
        return {clean_text(k, 80): _clean_value(v, limit, depth + 1) for k, v in list(value.items())[:50]}
    return value


def prompt_parts(cve_info):
    """The user message of a template draft (cveFeed.ai_jobs): the request, and the CVE feed's data fenced by the AI reviewer container."""
    safe = {k: _clean_value(v, 4000 if isinstance(v, str) else 500) for k, v in cve_info.items()}
    return [{'text': 'Write a nuclei detection template for this CVE:'}, {'fence': 'CVE', 'data': safe}]


def extract_yaml(text):
    """Pull the YAML out of a model reply (handles ``` fences)."""
    fence = re.search(r"```(?:ya?ml)?\s*\n(.*?)```", text or "", re.DOTALL)
    return (fence.group(1) if fence else (text or "")).strip()


FORBIDDEN_KEYS = {"self-contained", "redirects", "host-redirects", "max-redirects", "unsafe", "race", "pipeline",
                  "code", "javascript", "headless", "file", "flow", "workflows", "resolvers", "proxy",
                  # request multipliers and stateful tricks: an inline payload list or thread count multiplies the
                  # requests MAX_REQUESTS counts, and the check must stay a handful of read-only requests
                  "payloads", "attack", "fuzzing", "iterate-all", "threads", "cookie-reuse", "skip-variables-check", "body"}
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}  # a version or marker check reads; it never changes state on the target
PROTOCOL_SECTIONS = ("http", "requests", "network", "tcp", "dns", "ssl")
# words every server of a kind says: a template whose only evidence is one of these flags every host running it
GENERIC_WORDS = {"nginx", "apache", "server", "openresty", "iis", "microsoft-iis", "http", "html", "ok", "200", "tomcat",
                 "php", "express", "lighttpd", "litespeed", "cloudflare", "http/1.1", "http/1.0", "text/html"}
CONTENT_MATCHERS = {"word", "regex", "binary", "xpath", "json"}
SAFE_VARS = {"BaseURL", "RootURL", "Hostname", "Host", "Port", "FQDN", "Scheme", "Path", "randstr"}
MAX_REQUESTS = 6
# Installed templates may follow redirects on the same host (nuclei's host-redirects), a few hops at most; following them
# to another host (redirects: true) stays refused. AI-written templates get no redirects at all.
HOST_REDIRECT_KEYS = {"host-redirects", "max-redirects", "redirects"}
MAX_HOST_REDIRECTS = 3
_VAR_RE = re.compile(r"\{\{\s*([^}]*?)\s*\}\}")
_HOST_OK = re.compile(r"^\{\{(?:Hostname|Host)\}\}(?::\{\{Port\}\}|:\d{1,5})?$")


def _only_safe_vars(text):
    return all(name.split("(")[0].strip() in SAFE_VARS or name.startswith("rand_") for name in _VAR_RE.findall(text))


def _bound_http_path(value, allow_root_url=False):
    """A placeholder must end the authority before any model-controlled suffix."""
    if not isinstance(value, str) or any(ord(c) < 32 for c in value) or "\\" in value:
        return False
    placeholders = ("{{BaseURL}}", "{{RootURL}}") if allow_root_url else ("{{BaseURL}}",)
    return any(value == prefix or value.startswith(prefix + "/") for prefix in placeholders)


def _host_redirect_problem(key, value):
    if key == "host-redirects":
        return "" if isinstance(value, bool) else "host-redirects must be true or false"
    if key == "redirects":
        return "" if value is False else "redirects to other hosts are not allowed"
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_HOST_REDIRECTS:
        return f"max-redirects must be 0 to {MAX_HOST_REDIRECTS}"
    return ""


def destination_check(doc, allow_root_url=False, allow_host_redirects=False):
    """A generated template may talk only to the host nuclei is pointed at. Every request destination must be a
    {{BaseURL}}/{{Hostname}}/{{Host}} placeholder: no absolute URLs, no literal hosts, no redirects, no resolvers.
    allow_host_redirects admits same-host redirects (host-redirects, max-redirects up to MAX_HOST_REDIRECTS), for the
    installed templates. Returns a reason string, or "" when the document is acceptable."""
    if not isinstance(doc, dict):
        return "template must be a mapping"
    for proto in PROTOCOL_SECTIONS:
        if proto not in doc:
            continue
        blocks = doc[proto]
        if not isinstance(blocks, list) or not blocks or any(not isinstance(b, dict) for b in blocks):
            return f"malformed {proto} section"
        for block in blocks:
            for key in ("path", "raw", "inputs", "matchers", "extractors"):
                if key in block and not isinstance(block[key], list):
                    return f"malformed {proto} {key} list"

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                key = str(k).lower()
                if allow_host_redirects and key in HOST_REDIRECT_KEYS:
                    r = _host_redirect_problem(key, v)
                    if r:
                        return r
                    continue
                if key in FORBIDDEN_KEYS:
                    return f"forbidden key {k!r}"
                r = walk(v, f"{path}.{k}")
                if r:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = walk(v, path)
                if r:
                    return r
        return ""
    reason = walk({k: v for k, v in doc.items() if k != "info"})
    if reason:
        return reason
    variables = doc.get("variables") or {}
    if not isinstance(variables, dict) or any(str(k).strip() in SAFE_VARS for k in variables):
        return "template variables must not override built-in target variables"
    requests_seen = 0
    for proto in ("http", "requests"):
        for block in doc.get(proto) or []:
            if not isinstance(block, dict):
                return f"malformed {proto} section"
            for p in block.get("path") or []:
                requests_seen += 1
                if not _bound_http_path(p, allow_root_url) or "://" in str(p) or not _only_safe_vars(str(p)):
                    return f"http path must be {{{{BaseURL}}}} or {{{{BaseURL}}}}/path and contain no other URL: {str(p)[:80]!r}"
            for raw in block.get("raw") or []:
                requests_seen += 1
                text = str(raw)
                if "://" in text or not _only_safe_vars(text):
                    return "raw request contains an absolute URL or an unknown variable"
                first = text.strip().splitlines()[0] if text.strip() else ""
                fields = first.split()
                target = fields[1] if len(fields) == 3 else ""
                relative = target.startswith("/") and not target.startswith("//") and "\\" not in target
                if not (relative or _bound_http_path(target, allow_root_url)):
                    return f"raw request line must use /path or {{{{BaseURL}}}}/path: {first[:60]!r}"
                for line in text.splitlines()[1:]:
                    if line.lower().startswith("host:") and not _HOST_OK.match(line.split(":", 1)[1].strip()):
                        return "raw Host header must be {{Hostname}} or {{Host}}"
    for proto in ("network", "tcp"):
        for block in doc.get(proto) or []:
            if not isinstance(block, dict):
                return f"malformed {proto} section"
            inputs = block.get("inputs") or []
            if not isinstance(inputs, list) or any(not isinstance(i, dict) or i.get("data") for i in inputs):
                return "network checks may only read banners; outgoing data is not allowed"
            for key in ("host", "address"):
                values = block.get(key) or []
                for h in values if isinstance(values, list) else [values]:
                    requests_seen += 1
                    if not _HOST_OK.match(str(h)):
                        return f"network {key} must be {{{{Hostname}}}} or {{{{Host}}}} (optionally with a port): {str(h)[:60]!r}"
    for block in doc.get("ssl") or []:
        if isinstance(block, dict) and str(block.get("address", "{{Host}}:{{Port}}")) != "{{Host}}:{{Port}}":
            return "ssl address must be {{Host}}:{{Port}}"
    for block in doc.get("dns") or []:
        if isinstance(block, dict) and str(block.get("name", "{{FQDN}}")) != "{{FQDN}}":
            return "dns name must be {{FQDN}}"
    if requests_seen > MAX_REQUESTS:
        return f"too many requests ({requests_seen}; the limit is {MAX_REQUESTS})"
    return ""


def _is_status_only(matcher):
    kind = str(matcher.get("type", "")).lower()
    if kind == "status":
        return True
    if kind == "dsl":
        exprs = [str(e).lower() for e in (matcher.get("dsl") or [])]
        return bool(exprs) and all("status_code" in e and not any(w in e for w in ("body", "header", "contains", "regex", "content_length"))
                                   for e in exprs)
    return False


def _is_content(matcher):
    kind = str(matcher.get("type", "")).lower()
    return kind in CONTENT_MATCHERS or (kind == "dsl" and not _is_status_only(matcher))


def _is_generic(matcher):
    """A word matcher whose every word is a bare server/banner word (no version number, no distinguishing text)."""
    if str(matcher.get("type", "")).lower() != "word":
        return False
    words = [str(w).strip().lower() for w in (matcher.get("words") or [])]
    return bool(words) and all(w in GENERIC_WORDS for w in words)


def matcher_check(doc):
    """The evidence rules. A template without matchers (extractors only) matches every live host, a status-only matcher
    matches every host that answers 200, and a lone "nginx" word matches every nginx: none of those is a detection. Methods
    stay read-only. Returns a reason string, or "" when acceptable."""
    for proto in PROTOCOL_SECTIONS:
        for block in doc.get(proto) or []:
            if not isinstance(block, dict):
                continue
            matchers = [m for m in (block.get("matchers") or []) if isinstance(m, dict)]
            if not matchers:
                return f"{proto} block has no matchers: an extractor alone reports every live host as vulnerable"
            condition = str(block.get("matchers-condition", "or")).lower()
            if any(_is_status_only(m) for m in matchers):
                if condition != "and" or not any(_is_content(m) for m in matchers):
                    return "a status-code matcher must be combined (matchers-condition: and) with a word, regex or binary matcher"
            content = [m for m in matchers if _is_content(m)]
            if content and all(_is_generic(m) for m in content):
                return "the only word matchers are generic server banners; pair them with a version regex or specific marker"
            if not content:
                return f"{proto} block has no word, regex or binary matcher"
            if proto in ("http", "requests"):
                method = str(block.get("method", "GET")).upper()
                if "raw" not in block and method not in ALLOWED_METHODS:
                    return f"http method {method} is not allowed (read-only checks: {sorted(ALLOWED_METHODS)})"
                for raw in block.get("raw") or []:
                    first = str(raw).strip().splitlines()[0] if str(raw).strip() else ""
                    verb = first.split(" ", 1)[0].upper()
                    if verb not in ALLOWED_METHODS:
                        return f"raw request method {verb or '?'} is not allowed (read-only checks: {sorted(ALLOWED_METHODS)})"
    return ""


def static_check(yaml_text, expected_cve_id=None):
    """Return (ok, reason). Pure: no I/O, so the safety gate is unit-testable."""
    if not yaml_text or len(yaml_text.encode()) > MAX_TEMPLATE_BYTES:
        return False, "empty or too large"
    try:
        doc = load_template(yaml_text)
    except yaml.YAMLError as e:
        return False, f"invalid YAML: {e}"
    if not isinstance(doc, dict):
        return False, "template must be a YAML mapping"
    bad = set(doc) & FORBIDDEN_PROTOCOLS
    if bad:
        return False, f"forbidden protocol(s): {sorted(bad)}"
    unknown = set(doc) - ALLOWED_TOP_KEYS
    if unknown:
        return False, f"unexpected top-level key(s): {sorted(unknown)}"
    if not ID_RE.match(str(doc.get("id", ""))):
        return False, "missing or malformed id"
    if expected_cve_id and expected_cve_id.lower() not in str(doc["id"]).lower() \
            and expected_cve_id.lower() not in json.dumps(doc.get("info", {})).lower():
        return False, "template does not reference the CVE"
    info = doc.get("info")
    if not isinstance(info, dict) or not info.get("name") or \
            str(info.get("severity", "")).lower() not in SEVERITIES:
        return False, "info.name and a valid info.severity are required"
    if not (set(doc) & ALLOWED_PROTOCOLS):
        return False, "no http/network/dns/ssl protocol section"
    reason = destination_check(doc) or matcher_check(doc)
    if reason:
        return False, reason
    lowered = yaml_text.lower()
    if "interactsh" in lowered or re.search(r"\boast\b", lowered):
        return False, "out-of-band (interactsh) checks are not allowed"
    return True, ""


# ----------------------------------------------------------------------------- what a hit shows: the flaw, or a version string

# A template may detect a CVE "by version" (the writer is told so, and the gate accepts a version regex): a hit of such a template is the
# version read once more, the same evidence correlation already had, never a demonstration of the flaw. ``template_evidence`` sorts a
# template into one of the two, deterministically. It is an allowlist: a template is VERSION_EVIDENCE only when every part of it is one
# this classifier positively recognises as a plain read decided by a version; anything else, anything it cannot read, every ssl, dns,
# flow or unknown block is BEHAVIOR_EVIDENCE, so a genuine hit is never downgraded.
VERSION_EVIDENCE, BEHAVIOR_EVIDENCE = "version", "behavior"
# what a version-class hit is recorded as on the CVE match (template_result): it is not "vulnerable", so it is not hard evidence
# (match_policy.has_hard_evidence), does not lift the heat, confirm the triage row, record a nuclei-cve finding or page
VERSION_ONLY_RESULT = "version_only"
_TEMPLATE_KEYS = {"id", "info", "http", "requests", "tcp", "network", "variables", "stop-at-first-match", "self-contained"}
_PLAIN_PATH = re.compile(r"^(?:\{\{(?:BaseURL|RootURL)\}\})?(?:/[A-Za-z0-9_.~+-]*)*$")  # a static path: no query, no escapes, no variables
_HOST_VALUE = "{{Hostname}}"  # the one request header a version check may set: any other header value can carry a payload
_PLAIN_HTTP_KEYS = {"method", "path", "raw", "headers", "matchers", "matchers-condition", "extractors", "host-redirects", "max-redirects",
                    "redirects", "stop-at-first-match", "max-size", "id", "name", "read-all", "disable-cookie"}
_PLAIN_NETWORK_KEYS = {"host", "address", "port", "read-size", "read-all", "matchers", "matchers-condition", "extractors", "id", "name"}
_MATCHER_KEYS = {"type", "part", "words", "regex", "dsl", "status", "condition", "name", "case-insensitive", "internal", "match-all"}
_CONTENT_PARTS = {"", "body", "header", "content_type", "all", "response", "raw", "data"}
# a version number inside a regex: digits (or a digit class) on both sides of an escaped dot ("3\.4", "\d+\.\d", "[0-4]\.", "(49|50)\.")
_REGEX_VERSION = re.compile(r"(?:\d|\\d|\]|\))(?:[+*?]|\{\d{1,3}(?:,\d{0,3})?\})?\\\.(?:\d|\\d|\[|\()")
# ... but an address (four dotted numbers) is a disclosure's own marker, not a version
_REGEX_ADDRESS = re.compile(r"(?:(?:\d{1,3}|\\d(?:[+*]|\{\d(?:,\d)?\})?|\[[^\]]{1,10}\](?:[+*]|\{\d(?:,\d)?\})?)\\\.){3}")
_REGEX_GROUP_SYNTAX = re.compile(r"\(\?P?<(?:[=!]|[A-Za-z_]\w{0,30}>)")
_WORD_CHARS = re.compile(r"^[A-Za-z0-9 ._/-]{1,80}$")  # a product and version token: no markup, quotes or payload characters
_IDENTITY_WORD = re.compile(r"^[A-Za-z0-9 ._/-]{1,80}:?$")
_IDENTITY_ATTRIBUTE = re.compile(r"""^(?:class|id)=(?:"[A-Za-z0-9 _-]{1,40}"|'[A-Za-z0-9 _-]{1,40}')$""")
_WORD_VERSION = re.compile(r"(?<![\d.])\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?![\d.]*\.\d)")
_MIME = re.compile(r"^(?:application|text)/[a-z0-9.+-]{1,40}$")
# what a product's own name never contains: a word with one of these is a marker of what a response disclosed, not an identity
_SENSITIVE = re.compile(r"(?i)pass|secret|token|key|private|root|admin|uid|credential|session|cookie|config|user|ssh-|begin |aws|db_|env")
_CONSTRAINT = re.compile(r"""^\s*(?:'\s*(?:[<>]=?|==?|!=)?\s*v?\d[\w.+-]{0,40}\s*'|"\s*(?:[<>]=?|==?|!=)?\s*v?\d[\w.+-]{0,40}\s*")\s*$""")
_COMPARE = re.compile(r"compare_versions\(\s*([A-Za-z_]\w{0,40})\s*((?:,\s*(?:'[^'\n]{1,60}'|\"[^\"\n]{1,60}\")\s*){1,6})\)")
_CONTAINS = re.compile(r"""^\s*(?:i?contains|contains_all|contains_any)\(\s*(?:body|header|all|response|content_type)\s*((?:,\s*(?:'[^'\n]{1,80}'|"[^"\n]{1,80}")\s*){1,8})\)\s*$""")
_STATUS_DSL = re.compile(r"^\s*status_code\s*==\s*2\d\d\s*$")
# "HTTP/1.1 200", and its regex forms with or without the slash ("HTTP\/1\.1", "HTTP[/]1\.1", "^HTTP.1\.0 200", "HTTP/\d", "HTTP\S1\.1",
# "HTTP\x2F1\.1"): a status line, never a product's version. "HTTP" then up to eight marks (a slash, a dot, a class bracket, an escaped
# character, a character class such as \S or \s, a hex, unicode or octal escape) and a protocol digit; a product
# word after it ("Apache HTTP Server 2.4", "IBM_HTTP_Server/8.5", "HTTPd/2.4") is no status line
_STATUS_LINE = re.compile(r"(?i)HTTP(?:[^A-Za-z0-9\\]|\\(?:[^A-Za-z0-9]|[sw]|x[0-9a-f]{2}|u[0-9a-f]{4}|u\{[0-9a-f]{1,6}\}|[0-7]{3})){0,8}"
                          r"(?:[0-3]|\\d|\[)")


# a page whose answer is itself the exposure (status pages, configuration and backup files, the process table, a Java app's descriptors,
# metrics, environment and diagnostic endpoints, password and key files, API descriptions, a registry's catalogue, CGI scripts, error
# logs): a version read there is read from a disclosure, so the hit is the disclosure's
_EXPOSURE_PATH = re.compile(r"(?i)server-(?:status|info)|application\.(?:properties|ya?ml)|(?:^|/)\.(?:env|git|svn|hg|ds_store)|actuator|phpinfo"
                            r"|info\.php|backup|\.(?:bak|old|orig|swp|sql|zip|tar|gz|tgz|7z|rar|ya?ml|ini|conf|config|log|properties|env)$"
                            r"|web\.config|wp-config|(?:^|/)(?:config|configuration|debug|console|admin|proc|etc|sys|dev|boot|windows|winnt)(?:/|$)"
                            r"|(?:^|/)(?:config|settings|appsettings|credentials|secrets?)\.json|web-inf|meta-inf|jolokia|\.axd(?:/|$)"
                            r"|(?:^|/)(?:env|metrics|prometheus|health|trace|dump|heapdump|threaddump|mappings|beans|configprops|loggers)(?:/|$|\.)"
                            r"|(?:^|/)\.ht[a-z]{1,10}$|(?:^|/)(?:swagger|openapi|api-docs)(?:\.json|\.ya?ml|/|$)|(?:^|/)\.(?:npmrc|aws|docker|ssh|kube)(?:/|$)"
                            r"|(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$|(?:^|/)v2/_catalog|(?:^|/)(?:nginx|fpm|php-fpm|apc|haproxy)[_-]?status"
                            r"|(?:^|/)status(?:/|$|\.)|cgi-bin/|(?:^|/)error[_.-]?log")


def _plain_path(value):
    text = str(value or "").strip()
    rest = re.sub(r"^\{\{(?:BaseURL|RootURL)\}\}", "", text)
    return bool(_PLAIN_PATH.match(text)) and ".." not in text and "//" not in rest and not _EXPOSURE_PATH.search(rest)


def _plain_header(name, value):
    """The one header a version check may send: Host naming the host itself. Any other header (a User-Agent, an Accept-Language, a
    Connection list) can carry an injection, a file name or a hop-by-hop trick."""
    return str(name or "").strip().lower() == "host" and str(value if value is not None else "").strip() == _HOST_VALUE


def _plain_raw(raw):
    """A raw request that only reads: GET or HEAD of a static path, the ordinary headers with ordinary values, no body."""
    lines = str(raw or "").replace("\r\n", "\n").strip("\n").split("\n")
    fields = lines[0].split() if lines else []
    if len(fields) != 3 or fields[0].upper() not in ("GET", "HEAD") or not _plain_path(fields[1]) or not re.match(r"^HTTP/[12](?:\.[01])?$", fields[2]):
        return False
    host = False
    for index, line in enumerate(lines[1:], 1):
        if not line.strip():
            return host and not any(rest.strip() for rest in lines[index + 1:])  # a body is something sent
        if ":" not in line or not _plain_header(*line.split(":", 1)):
            return False
        host = True
    return host  # a request with no Host header is not an ordinary read


def _plain_requests(proto, block):
    """Whether one protocol block only reads (nothing a hit could owe to a payload)."""
    if proto in ("http", "requests"):
        if set(map(str, block)) - _PLAIN_HTTP_KEYS:
            return False
        if str(block.get("method", "GET")).upper() not in ("GET", "HEAD"):
            return False
        headers = block.get("headers")
        if headers is not None and not (isinstance(headers, dict) and all(_plain_header(k, v) for k, v in headers.items())):
            return False
        paths, raws = block.get("path") or [], block.get("raw") or []
        if not isinstance(paths, list) or not isinstance(raws, list) or not (paths or raws):
            return False
        return all(_plain_path(p) for p in paths) and all(_plain_raw(r) for r in raws)
    if proto in ("network", "tcp"):
        return not (set(map(str, block)) - _PLAIN_NETWORK_KEYS)  # no inputs: a banner read, nothing sent
    return False


def _strings(text):
    return re.findall(r"""'([^'\n]*)'|"([^"\n]*)\"""", text)


def _compare_only(expr, names):
    """Whether a DSL expression is only ``compare_versions`` calls over extracted versions (``names``) with version constraints, joined by
    ``&&``, ``||``, ``!`` and parentheses."""
    used = []

    def one(found):
        constraints = re.findall(r"""'[^'\n]*'|"[^"\n]*\"""", found.group(2))
        if found.group(1) not in names or not constraints or not all(_CONSTRAINT.match(c) for c in constraints):
            used.append(False)
        else:
            used.append(True)
        return " X "
    rest = _COMPARE.sub(one, str(expr))
    return bool(used) and all(used) and bool(re.fullmatch(r"(?:\s|X|\(|\)|&&|\|\||!)*", rest))


def _tokens(text):
    return {t for t in re.findall(r"[a-z0-9]+", str(text or "").lower()) if len(t) >= 2}


_TITLE_DASH = re.compile(r"\s[-\u2013\u2014]\s")  # "Product 1.2 - Vulnerability title": the product is what comes before the first dash


def _identity_tokens(doc):
    """The words the template itself names its product with: info.name's product part (what comes before the first `` - ``; the rest is the
    vulnerability's title, "Email Address Disclosure", "Directory Listing", and a name with no dash names no product apart from its
    title), metadata vendor and product, and the classification CPE's product."""
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cpe = str(classification.get("cpe") or "").split(":")
    name = _TITLE_DASH.split(str(info.get("name") or ""), 1)
    product = name[0] if len(name) > 1 else ""
    return _tokens(" ".join([product, str(metadata.get("vendor") or ""), str(metadata.get("product") or ""), cpe[4] if len(cpe) > 4 else ""]))


def _identity_word(word, identity):
    """A word that only names the product: plain text (a trailing colon allowed, ``SH Version:``) or a class or id attribute
    (``class="ncentral"``) whose every word the template's own product identity (``_identity_tokens``) has, with nothing a secret or a
    disclosure would contain. Any other word (``email``, ``Index of /``, ``"role":"admin"``) may be a disclosure's marker."""
    word = str(word).strip()
    attribute = _IDENTITY_ATTRIBUTE.match(word)
    if not (_IDENTITY_WORD.match(word) or attribute) or _SENSITIVE.search(word):
        return False
    value = word.split("=", 1)[1] if attribute else word
    tokens = _tokens(value)
    return bool(tokens) and tokens <= identity


def _part_ok(matcher, names):
    part = str(matcher.get("part", "") or "").strip().lower()
    return part in _CONTENT_PARTS or part in names


def _matcher_kind(matcher, names, identity=frozenset()):
    """``version`` (decides on a version), ``identity`` (names the product: a plain product word, a MIME type), ``status`` (a 2xx status)
    or ``other``. Only the first three may make a template version-class."""
    if not set(map(str, matcher)) <= _MATCHER_KEYS or matcher.get("negative") or not _part_ok(matcher, names):
        return "other"
    kind = str(matcher.get("type", "")).lower()
    if kind == "status":
        codes = matcher.get("status") or []
        return "status" if codes and all(isinstance(c, int) and 200 <= c < 300 for c in codes) else "other"
    if kind == "dsl":
        exprs = [str(e) for e in matcher.get("dsl") or []]
        if exprs and all(_compare_only(e, names) for e in exprs):
            return "version"
        if exprs and all(_STATUS_DSL.match(e) for e in exprs):
            return "status"
        if exprs and all(_CONTAINS.match(e) and all(_identity_word(a or b, identity) for a, b in _strings(_CONTAINS.match(e).group(1)))
                         for e in exprs):
            return "identity"
        return "other"
    if kind == "regex":
        patterns = [str(p) for p in matcher.get("regex") or []]
        if patterns and all(_REGEX_VERSION.search(p) and not _REGEX_ADDRESS.search(p) and not re.search(r"[<>'\"]", _REGEX_GROUP_SYNTAX.sub("", p))
                            and not _STATUS_LINE.search(p) and len(p) <= 200 for p in patterns):
            return "version"
        return "other"
    if kind == "word":
        words = [str(w) for w in matcher.get("words") or []]
        if not words:
            return "other"
        if all(_WORD_CHARS.match(w) and _WORD_VERSION.search(w) and not _STATUS_LINE.search(w) for w in words):
            return "version"
        if str(matcher.get("part", "")).lower() in ("header", "content_type") and all(_MIME.match(w.strip().lower()) for w in words):
            return "identity"
        if all(_identity_word(w, identity) for w in words):
            return "identity"
    return "other"


def _decided_by_version(block, names, identity=frozenset()):
    matchers = block.get("matchers")
    if not isinstance(matchers, list) or not matchers or not all(isinstance(m, dict) for m in matchers):
        return False
    kinds = [_matcher_kind(m, names, identity) for m in matchers]
    if "other" in kinds or "version" not in kinds:
        return False
    if str(block.get("matchers-condition", "or")).lower() == "and":
        return True  # every matcher must hold: one decides on the version, the rest only name the product or want a 2xx answer
    return all(k == "version" for k in kinds)  # any matcher can fire alone: each must be a version


_CAPTURE = re.compile(r"\((?!\?)([^()]{1,120})\)")


# a capture group of digits and dots only: digit classes (``\d``, ``[0-9]``, ``[0-9.]``, ``[\d.]``), escaped dots and quantifiers. An
# unescaped dot (any character), a letter or anything else is not a version: ``(.+\d.+)`` captures whatever the response held
_VERSION_GROUP = re.compile(r"(?:\\d|\[(?:0-9|\\d|\\?\.|_|-){1,6}\]|\\\.|[+*?]|\{\d{1,3}(?:,\d{0,3})?\})+")


def _version_shaped(pattern):
    """Whether a regex extractor captures a version: a group made of digits and dots only (``([0-9.]+)``, ``(\\d+\\.\\d+)``)."""
    return any(_VERSION_GROUP.fullmatch(group) and ("\\d" in group or "0-9" in group) and "." in group
               for group in _CAPTURE.findall(str(pattern)))


def _extractor_names(doc):
    """The extractors whose value is a version: a regex extractor every pattern of which captures digits and dots. ``compare_versions``
    or a version word over anything else (a JSON field, a DSL value, ``(.*?)``) is a comparison of whatever the response held."""
    names = set()
    for proto in ("http", "requests", "network", "tcp"):
        for block in doc.get(proto) or []:
            for extractor in (block.get("extractors") or []) if isinstance(block, dict) else []:
                if (isinstance(extractor, dict) and extractor.get("name") and str(extractor.get("type", "")).lower() == "regex"
                        and isinstance(extractor.get("regex"), list) and extractor["regex"]
                        and all(_version_shaped(p) for p in extractor["regex"])):
                    names.add(str(extractor["name"]))
    return names


def template_evidence(text):
    """VERSION_EVIDENCE when a hit of this template (its YAML ``text``) shows only a version string, else BEHAVIOR_EVIDENCE. Pure, and an
    allowlist. A template is version-class only when:

      * its top-level keys are ones this reads (id, info, http/requests, tcp/network, variables, stop-at-first-match, self-contained
        false): ssl, dns, flow, websocket, headless, code and anything unknown are behaviour;
      * it has ONE request block, and it only reads: GET or HEAD of a static path (no query, no ``..``, no empty segment, no escapes, no
        variable but ``{{BaseURL}}``, not a page that is itself an exposure: a status page, a configuration, backup or log file, the
        process table), no request header but ``Host: {{Hostname}}`` (a raw request must send it), no body; or a network banner read
        with nothing sent;
      * it is decided by a version: ``compare_versions`` over a regex extractor that captures digits and dots, a regex that spells a version
        number, or product-and-version words (never an HTTP status line). With ``matchers-condition: and`` the other matchers may only name
        the product with words the template's own name, vendor, product or CPE has, match a MIME type or want a 2xx status; with ``or``
        every matcher must be a version.

    A template it cannot parse is behaviour, so a genuine hit is never read as a version."""
    try:
        return _template_evidence(text)
    except Exception:  # noqa: BLE001 - a field of an unexpected shape: never downgrade
        return BEHAVIOR_EVIDENCE


def _template_evidence(text):
    try:
        doc = load_template(text) if text else None
    except Exception:  # noqa: BLE001 - unreadable: never downgrade
        return BEHAVIOR_EVIDENCE
    if not isinstance(doc, dict) or set(map(str, doc)) - _TEMPLATE_KEYS or doc.get("self-contained"):
        return BEHAVIOR_EVIDENCE
    names, identity = _extractor_names(doc), frozenset(_identity_tokens(doc))
    blocks = []
    for proto in ("http", "requests", "network", "tcp"):
        found = doc.get(proto) or []
        if not isinstance(found, list):
            return BEHAVIOR_EVIDENCE
        blocks += [(proto, block) for block in found]
    if len(blocks) != 1:  # one read, decided by its own answer: a later request may owe its answer to an earlier one
        return BEHAVIOR_EVIDENCE
    proto, block = blocks[0]
    if not isinstance(block, dict) or not _plain_requests(proto, block) or not _decided_by_version(block, names, identity):
        return BEHAVIOR_EVIDENCE
    return VERSION_EVIDENCE


def evidence_of_template(path):
    """``template_evidence`` of the approved template at ``path`` (BEHAVIOR_EVIDENCE when it cannot be read: never a downgrade)."""
    try:
        from cveFeed.validation import approved_template
        text, problem = approved_template(path)
    except Exception:  # noqa: BLE001
        return BEHAVIOR_EVIDENCE
    try:
        return BEHAVIOR_EVIDENCE if problem else template_evidence(text)
    except Exception:  # noqa: BLE001 - never downgrade on a template this cannot read
        return BEHAVIOR_EVIDENCE


def is_confirmed(outcome):
    """Whether a template test outcome demonstrates the flaw: it matched, and the template is not a version-class one."""
    return bool(outcome.get("vulnerable")) and outcome.get("template_evidence") != VERSION_EVIDENCE


def is_version_hit(outcome):
    """Whether a template test outcome matched only a version string (a version-class template)."""
    return bool(outcome.get("vulnerable")) and outcome.get("template_evidence") == VERSION_EVIDENCE


_TEMPLATE_INDEX = {}  # roots -> (signature, {cve_id_lower: [paths]})


def invalidate_template_index():
    _TEMPLATE_INDEX.clear()


def _mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


def _template_index(roots):
    """{cve_id_lower: [paths]} from one walk of ``roots``, rebuilt when a root or nuclei's .checksum marker changes
    (a template update, another worker's save) or when invalidate_template_index() is called."""
    key = tuple(roots)
    signature = tuple((_mtime(r), _mtime(os.path.join(r, ".checksum"))) for r in key)
    cached = _TEMPLATE_INDEX.get(key)
    if cached and cached[0] == signature:
        return cached[1]
    index = {}
    for root in key:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                stem, dot, ext = name.rpartition(".")
                if dot and ext.lower().startswith("y") and ext.lower().endswith("ml"):
                    index.setdefault(stem.lower(), []).append(os.path.join(dirpath, name))
    _TEMPLATE_INDEX[key] = (signature, index)
    return index


def find_existing_template(cve_id, roots=None):
    """Template coverage: paths of installed templates named for ``cve_id``."""
    roots = roots or [TEMPLATES_ROOT, GENERATED_DIR]
    # case-insensitive: upstream names files CVE-..., generated ones use the lowercase id
    return sorted(_template_index(roots).get(cve_id.lower(), []))


def validate_anywhere(text, project=None):
    """The syntax check and the benign loopback fixture of a new template, ``(valid, output)``, on the built-in scanner (a ``nuclei_validate`` task in
    mode ``validate``). The kind never runs on this server: a check no scanner could take is not a verdict on the template,
    ``ScannerUnavailable`` goes to the caller."""
    from agentapi import sentinel_dispatch
    valid, output, fixture_ok, fixture_note = sentinel_dispatch.try_nuclei_validate(text, project)
    if valid:
        output = (output + '\n' + (fixture_note or 'the benign local fixture was not run')).strip()
        valid = fixture_ok is True
    return valid, output


def _host_key(value):
    """The bare lowercase hostname of a host or URL, to pair a template result with the host that was asked about."""
    value = str(value or "").strip().lower()
    value = value.split("://", 1)[-1].split("/", 1)[0]
    if value.startswith("["):
        return value.split("]", 1)[0].lstrip("[")
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def run_template(path, hosts, project=None):
    """Run one approved template against ``hosts`` on the built-in scanner (a ``nuclei_validate`` task in mode ``test``, filed under ``project``,
    the one the hosts belong to: never another tenant's); returns a ``{host, vulnerable, output}`` per host, in order. The scanner runs exactly the
    bytes ``approved_template`` inspected. Nothing runs on this server: a host no scanner took, or a call with no project, is reported as not
    tested (an error outcome) and stays due.

    One more look at the names first: a name a tenant controls can answer a public address when the host list is vetted and an internal one later,
    so the names are resolved again here, at launch, and one that now resolves to a blocked address is reported as not tested instead of being
    sent to a scanner. (The scanner resolves the name itself a moment later: this narrows the window, it does not close it.)"""
    from targetApp.target_types import IP, bare_host, blocked_names, classify_target
    hosts = [hosts] if isinstance(hosts, str) else list(hosts)
    names = {bare_host(h) for h in hosts}
    blocked = blocked_names([n for n in names if n and classify_target(n) != IP]) if hosts else set()
    allowed = [h for h in hosts if bare_host(h) not in blocked]
    ran = iter(_run_on_scanner(path, allowed, project) if allowed else [])
    return [{"host": h, "vulnerable": False, "output": "", "error": "the host name now resolves to an address that may not be scanned"}
            if bare_host(h) in blocked else next(ran) for h in hosts]


def _run_on_scanner(path, hosts, project):
    """The outcomes of the template at ``path`` over ``hosts``, from the built-in scanner (``sentinel_dispatch.try_template_test``), one per host."""
    if project is None:
        return [{"host": host, "vulnerable": False, "output": "", "error": "not tested: a template check needs the project the host belongs to"}
                for host in hosts]
    from cveFeed.validation import approved_template
    text, problem = approved_template(path)
    if problem:
        return [{"host": host, "vulnerable": False, "output": "", "error": problem} for host in hosts]
    from agentapi import sentinel_dispatch
    return sentinel_dispatch.try_template_test(text, hosts, project)


def _test_chunk(path, hosts, project=None):
    """The check for a chunk of hosts, run by a scanner (``run_template``). A host the scanner could not test comes back as an error outcome."""
    hosts = [hosts] if isinstance(hosts, str) else list(hosts)
    return run_template(path, hosts, project=project)


def templates_dir_problem(generated=None, root=None):
    """Why the generated-templates directory and nuclei's template root must not be set as they are, or "" when they are apart.
    AI-written templates are run only by explicit ``-t``; the blanket ``nuclei -l`` pass loads everything under the template root,
    so a generated directory inside it would run unproven templates against every tenant's hosts, and a root inside the generated
    directory would put nuclei's own templates in the directory a factory reset empties."""
    generated = os.path.realpath(generated or GENERATED_DIR)
    root = os.path.realpath(root or TEMPLATES_ROOT)

    def inside(child, parent):
        return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)
    if inside(generated, root):
        return (f"CVENGINE_GENERATED_TEMPLATES_DIR ({generated}) is inside the nuclei templates directory ({root}): the blanket nuclei "
                "pass would run AI-written templates against every host. Set it to a directory outside it.")
    if inside(root, generated):
        return (f"NUCLEI_TEMPLATES_DIR ({root}) is inside CVENGINE_GENERATED_TEMPLATES_DIR ({generated}): a factory reset empties "
                "that directory. Keep the two apart.")
    return ""


def save_template_file(template_id, yaml_text):
    problem = templates_dir_problem()
    if problem:
        raise RuntimeError(problem)
    if not ID_RE.fullmatch(template_id):
        raise ValueError('invalid generated template filename')
    os.makedirs(GENERATED_DIR, exist_ok=True)
    path = os.path.join(GENERATED_DIR, f"{template_id}.yaml")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(yaml_text)
    invalidate_template_index()
    return path


def restore_missing_files():
    """Write back the file of every validated AI template that is missing from GENERATED_DIR, from the copy kept in the database.
    A container that is recreated (every update does) starts with an empty directory unless it is a volume; without this the
    templates would have to be regenerated and re-reviewed after each deploy. A template is written back only if its row is still
    ``valid``, its recorded path is inside GENERATED_DIR, and it passes the static safety gate again. Returns the counts."""
    from cveFeed.models import GeneratedTemplate
    generated = os.path.realpath(GENERATED_DIR)
    restored = skipped = 0
    for tmpl in GeneratedTemplate.objects.filter(status=GeneratedTemplate.STATUS_VALID).exclude(path='').select_related('cve_entry'):
        if os.path.lexists(tmpl.path):
            continue
        stem, ext = os.path.splitext(os.path.basename(tmpl.path))
        if os.path.dirname(os.path.realpath(tmpl.path)) != generated or ext != '.yaml' or not ID_RE.fullmatch(stem):
            skipped += 1
            continue
        ok, reason = static_check(tmpl.yaml, expected_cve_id=tmpl.cve_entry.cve_id)
        if not ok:
            logger.warning('not restoring generated template %s: %s', tmpl.template_id, reason)
            skipped += 1
            continue
        try:
            save_template_file(stem, tmpl.yaml)
        except FileExistsError:
            continue
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning('could not restore generated template %s: %s', tmpl.template_id, exc)
            skipped += 1
            continue
        restored += 1
    return {'restored': restored, 'skipped': skipped}


def cve_info_for(cve):
    from cveFeed.correlation import prepared_ranges  # the ranges as matching reads them: a branch the CVE List split in two is one range
    affected = cve.affected
    if isinstance(affected, list):
        affected = [{**item, "ranges": prepared_ranges(item["ranges"], keep_unusable=True)} if isinstance(item, dict) and isinstance(item.get("ranges"), list)
                    else item for item in affected]
    return {"id": cve.cve_id, "title": cve.title,
            "description": cve.original_description or cve.summary,
            "cvss": cve.cvss, "affected": affected, "references": cve.references}


class TemplateBudgetExceeded(Exception):
    """No AI template is written now: the CVE had an attempt recently, or the daily budget is spent."""


GENERATION_DEFAULTS = {'TEMPLATE_GEN_MAX_PER_DAY': 10, 'TEMPLATE_GEN_CVE_DAYS': 7}


def generation_limit(name):
    """A template-generation limit: for the daily budget what an App Admin saved on Settings, configMaxxing (``cveFeed.tunables``), else
    CVENGINE_<NAME> in the environment, else the default."""
    from cveFeed import tunables
    if name.lower() in tunables.BY_KEY:
        return tunables.value(name.lower(), GENERATION_DEFAULTS[name])
    try:
        return max(1, int(os.environ.get(f'CVENGINE_{name}', '')))
    except ValueError:
        return GENERATION_DEFAULTS[name]


def _generation_lease(cve):
    """Claim this CVE for one generation attempt, or raise TemplateBudgetExceeded. Every attempt, whatever its outcome, is a
    GeneratedTemplate row, so the rows are the ledger: one attempt per CVE per TEMPLATE_GEN_CVE_DAYS, and at most
    TEMPLATE_GEN_MAX_PER_DAY across all projects in any 24 hours. The cache lease stops two workers writing the same CVE at once."""
    from django.core.cache import cache
    from django.utils import timezone

    from cveFeed.models import GeneratedTemplate
    now = timezone.now()
    recent = GeneratedTemplate.objects.filter(cve_entry=cve,
                                              created_at__gte=now - datetime.timedelta(days=generation_limit('TEMPLATE_GEN_CVE_DAYS')))
    last = recent.order_by('-created_at').first()
    if last is not None:
        raise TemplateBudgetExceeded(f'an AI check for {cve.cve_id} was already attempted on {last.created_at:%Y-%m-%d} ({last.status})')
    from cveFeed.models import AIJob
    asked = AIJob.objects.filter(kind='template_generation', created_at__gte=now - datetime.timedelta(days=1), status__in=AIJob.OPEN).count()
    if GeneratedTemplate.objects.filter(created_at__gte=now - datetime.timedelta(days=1)).count() + asked >= generation_limit('TEMPLATE_GEN_MAX_PER_DAY'):
        raise TemplateBudgetExceeded('the daily AI template budget is spent')
    if AIJob.objects.filter(kind='template_generation', dedupe=f'template:{cve.pk}', status__in=AIJob.OPEN).exists():
        raise TemplateBudgetExceeded(f'an AI check for {cve.cve_id} is already being written')
    key = f'cvengine:templategen:{cve.pk}'
    if not cache.add(key, 1, timeout=15 * 60):
        raise TemplateBudgetExceeded(f'an AI check for {cve.cve_id} is already being written')
    return key


def generate_template(cve, project=None, candidate_only=True):
    """Ask the AI for a template: one job queued for the AI reviewer container (cveFeed.ai_jobs). When it lands, ``job_answer`` gates it
    (static check, the syntax check and the benign fixture on a scanner) and keeps it as a draft: an AI template is never installed or run on a host
    without independently reviewed positive fixture evidence. Raises TemplateBudgetExceeded instead of asking when the generation budget
    does not allow an attempt, and ScannerUnavailable (before the AI is asked) when no scanner could check the template it would write.
    Returns the job."""
    if not candidate_only:
        raise ValueError('an AI template requires independently reviewed positive fixture evidence before installation')
    from django.core.cache import cache
    from agentapi import sentinel_dispatch
    from cveFeed import activity, ai_jobs
    key = _generation_lease(cve)
    try:
        sentinel_dispatch.nuclei_validate_ready(project)  # raises ScannerUnavailable before the AI is asked for a template nothing could check
        # the reply is a template, whose literal values (a JWT in a header, a Basic credential, a PEM header matcher) must survive: only the
        # prompt is masked
        job = ai_jobs.enqueue('template_generation', 'template_generation', system=SYSTEM_PROMPT, parts=prompt_parts(cve_info_for(cve)),
                              options={'redact_reply': False}, context={'cve': cve.pk, 'project': project}, project=project,
                              dedupe=f'template:{cve.pk}', priority=7)
        activity.log('write_check', f'Asked the AI reviewer container to write a nuclei check for {cve.cve_id}', project=project,
                     cve_id=cve.cve_id)
        return job
    finally:
        cache.delete(key)


def _job_model(job):
    return f'{job.provider}:{job.model}' if job.provider else (job.model or 'unknown')


def job_answer(job, text):
    """The model's template arrived: gated as before (static check, then the syntax check and the benign fixture on a scanner:
    nothing unvalidated ever exists under GENERATED_DIR) and saved as a draft or as invalid."""
    from cveFeed.models import CVEEntry, GeneratedTemplate
    from cveFeed import activity
    from reNgine.resources import ScannerUnavailable
    cve = CVEEntry.objects.filter(pk=job.context.get('cve')).first()
    if cve is None:
        return None
    project = job.context.get('project')
    text = extract_yaml(text)
    ok, reason = static_check(text, expected_cve_id=cve.cve_id)
    tmpl = GeneratedTemplate(cve_entry=cve, yaml=text, ai_model=_job_model(job)[:128],
                             template_id=(load_template(text) or {}).get("id", "") if ok else "")
    if not ok:
        tmpl.status, tmpl.validation_output = GeneratedTemplate.STATUS_INVALID, f"static check: {reason}"
        tmpl.save()
        activity.log('write_check', f'The AI-written check for {cve.cve_id} failed the static check', project=project, cve_id=cve.cve_id)
        return None
    with activity.step('validate', f'Validating the check for {cve.cve_id} (safety gate and nuclei -validate)',
                       project=project, cve_id=cve.cve_id) as handle:
        try:
            valid, output = validate_anywhere(text, project)
        except ScannerUnavailable as exc:  # the scanner went away between the check above and now: never a draft without its check
            valid, output = False, f'not validated: no scanner could take this work ({exc.kind}); the CVE is tried again later'
        handle.done_message = f'Check for {cve.cve_id} {"passed" if valid else "failed"} validation'
    tmpl.status = GeneratedTemplate.STATUS_DRAFT if valid else GeneratedTemplate.STATUS_INVALID
    tmpl.validation_output = (output + '\nRequires a reviewed positive fixture before execution on a customer host.'
                              if valid else output)
    tmpl.save()
    return None


def job_failure(job, category, detail):
    """A failed provider call is still a billable attempt: the ledger row is left, so the CVE is not asked again at once."""
    from cveFeed.models import CVEEntry, GeneratedTemplate
    cve = CVEEntry.objects.filter(pk=job.context.get('cve')).first()
    if cve is not None:
        GeneratedTemplate.objects.create(cve_entry=cve, yaml='', status=GeneratedTemplate.STATUS_INVALID, ai_model=_job_model(job)[:128],
                                         validation_output=f'the AI provider call failed ({category}); no template was written')


def _severity_of(cvss, fallback):
    """The Vulnerability severity (0 info .. 4 critical) a CVE's CVSS score maps to."""
    if cvss is None:
        return fallback
    return 4 if cvss >= 9.0 else 3 if cvss >= 7.0 else 2 if cvss >= 4.0 else 1 if cvss > 0 else 0


def record_outcomes(cve, outcomes, project=None, template_id=""):
    """Persist what the template test found, so it shows in the findings, host heat and graph rather than only in the activity
    log: a vulnerable host gets a Vulnerability (source 'nuclei-cve', linked to the CVE, with the matched request and response as
    evidence), and every tested host's CVEMatch records the result ("vulnerable", "no_match", or "error" when it could not be
    tested). A hit of a version-class template (``template_evidence``) is recorded as VERSION_ONLY_RESULT and makes no finding: it read
    the version again, it did not show the flaw. Only a "vulnerable" result ever replaces a "vulnerable" one (from nuclei, OpenVAS or
    the TLS audit): a version hit, a miss or an error of a later run never lowers a confirmation. Only hosts of ``project`` are touched: without
    one nothing is guessed.

    A version-class hit proves the version is on the host (``match_policy.version_read_from_component``): under the KEV heat policy a KEV or
    exploited match it turns from smoke to fire is rescored and paged once (``scoring.evidence_arrived``, ``notify.fire_confirmed``: once per
    heat rule), the state read before the write (``threat.unproven``) so a match that was already fire is not paged again. It is still no
    confirmed finding (no Vulnerability, no "template test confirmed" message). Returns the number of findings saved."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch
    from reNgine.tasks import parse_nuclei_result, save_vulnerability
    from startScan.models import Subdomain
    if project is None or not outcomes:
        return 0
    by_host = {}
    for outcome in outcomes:
        by_host.setdefault(_host_key(outcome["host"]), outcome)
    latest = {}  # newest copy of each host per target (hosts are stored once per scan)
    for sub in Subdomain.objects.filter(name__in=list(by_host), target_domain__project_id=project) \
            .select_related("target_domain", "scan_history").order_by("-id"):
        latest.setdefault((sub.name, sub.target_domain_id), sub)
    from cveFeed import template_gates, threat
    # a template that matches patched releases too (template_gates.GATES): its hit on a host whose release is patched is no hit
    gated = {name for (name, _d), sub in latest.items() if template_gates.out_of_range({cve.cve_id, template_id or ''}, sub)}
    now, saved, proved = timezone.now(), 0, []
    for name, outcome in by_host.items():
        # a version-class template's hit is the version read again (template_evidence): recorded as such, never as "vulnerable"
        result = ("error" if outcome.get("error") else VERSION_ONLY_RESULT if is_version_hit(outcome)
                  else "vulnerable" if outcome["vulnerable"] and name not in gated else "no_match")
        rows = CVEMatch.objects.filter(cve_entry=cve, subdomain__name=name, subdomain__target_domain__project_id=project)
        if result != "vulnerable":
            # a confirmation stands until a person or a confirming check says otherwise: a version read again, a miss or an error of a later
            # run (a timeout, a WAF that answered this time, a template that changed) never lowers it, whichever tester made it
            rows = rows.exclude(template_result="vulnerable")
        unproven = ({m.pk for m in rows.select_related("cve_entry", "triage") if threat.unproven(m)}
                    if result == VERSION_ONLY_RESULT and threat.heat_policy() != threat.LEGACY_POLICY else set())
        rows.update(template_result=result, template_id=(template_id or "")[:128], template_tested_at=now)
        if unproven:  # read before the write: only a real smoke-to-fire change is rescored and paged
            proved += [m.pk for m in CVEMatch.objects.filter(pk__in=unproven).select_related("cve_entry", "triage")
                       if not threat.unproven(m) and threat.match_heat(m) == threat.FIRE]
    for (name, _domain_id), sub in latest.items():
        outcome = by_host[name]
        hit = outcome.get("hit")
        if not (is_confirmed(outcome) and hit) or name in gated:
            continue  # only a hit that shows the flaw is a confirmed finding
        try:
            data = parse_nuclei_result(hit)
        except (KeyError, TypeError, AttributeError):
            data = {"name": cve.cve_id, "type": "http", "severity": 0, "template": "", "template_url": "",
                    "template_id": template_id, "description": "", "matcher_name": hit.get("matcher-name", ""),
                    "curl_command": hit.get("curl-command"), "request": hit.get("request"), "response": hit.get("response"),
                    "extracted_results": hit.get("extracted-results", []), "cvss_metrics": "", "cvss_score": None,
                    "cve_ids": [], "cwe_ids": [], "references": [], "tags": []}
        data.update(
            source="nuclei-cve", severity=_severity_of(cve.cvss, data.get("severity", 0)), cvss_score=cve.cvss,
            template_url=str(data.get("template_url") or "")[:2500], tags=list(data.get("tags") or []) + ["cve-check"] + (["seen-while-authenticated"] if outcome.get("authenticated") else []),
            cve_ids=sorted({*(data.get("cve_ids") or []), cve.cve_id}), template_id=data.get("template_id") or template_id)
        data["name"] = f'{cve.cve_id}: {data["name"]}'[:2500] if data.get("name") and data["name"] != cve.cve_id else cve.cve_id
        save_vulnerability(target_domain=sub.target_domain, scan_history=sub.scan_history, subdomain=sub,
                           http_url=hit.get("matched-at") or hit.get("host") or name, **data)
        saved += 1
    if proved:
        from cveFeed import scoring
        scoring.evidence_arrived(proved, confirmed=proved)
    return saved


def run_cve_tests(cve, hosts, ai=False, project=None):
    """Stage 7: test with a policy-approved installed template, or (``ai``) ask for an unrun draft.

    Returns {'source': 'existing'|'candidate'|'none', 'template': path/id, 'results': [...]}.
    """
    from cveFeed import activity
    from reNgine.resources import ScannerUnavailable
    with activity.step('run_check', f'Checking nuclei template coverage for {cve.cve_id}', project=project,
                       cve_id=cve.cve_id) as handle:
        from cveFeed.validation import resolve_template
        safe_path, reason = resolve_template(cve.cve_id)
        handle.done_message = (f'A safe template for {cve.cve_id} is available' if safe_path else reason)
    if safe_path:
        path, source, tmpl = safe_path, "existing", None
    else:
        if not ai:
            return {"source": "none", "template": "", "results": [], "reason": reason or "no AI provider configured"}
        try:
            job = generate_template(cve, project=project, candidate_only=True)
        except (TemplateBudgetExceeded, ScannerUnavailable) as exc:
            reason = str(exc) if isinstance(exc, TemplateBudgetExceeded) else f'no scanner could check it now ({exc.kind})'
            activity.log('write_check', f'Not writing a nuclei check for {cve.cve_id}: {reason}', project=project, cve_id=cve.cve_id)
            return {"source": "none", "template": "", "results": [], "reason": reason}
        return {"source": "candidate", "template": "", "results": [], "job": job.pk,
                "reason": "an AI draft is being written; it is validated when it lands and is never run on a host before a person reviews it"}
    results = []
    evidence = evidence_of_template(path)  # what a hit of this template shows: the flaw, or the version string only
    from targetApp.target_types import scannable_hosts
    hosts = scannable_hosts(hosts, project=project)  # whatever called us, nothing that resolves to a blocked address is ever tested
    for start in range(0, len(hosts), CHUNK_HOSTS):
        chunk = hosts[start:start + CHUNK_HOSTS]
        label = chunk[0] if len(chunk) == 1 else f'{len(chunk)} hosts'
        with activity.step('run_check', f'Running the {cve.cve_id} check against {label}', project=project,
                           cve_id=cve.cve_id) as handle:
            outcomes = _test_chunk(path, chunk, project=getattr(project, 'pk', project))
            for outcome in outcomes:
                outcome['template_evidence'] = evidence
            errors = sum(bool(o.get('error')) for o in outcomes)
            handle.done_message = (f'{errors} of {len(outcomes)} checks failed for {cve.cve_id}' if errors else
                                   f'{sum(o["vulnerable"] for o in outcomes)} of {len(outcomes)} hosts matched {cve.cve_id}'
                                   + (' (a version check: the version only)' if evidence == VERSION_EVIDENCE else ''))
        results.extend(outcomes)
    for outcome in results:
        host = outcome['host']
        activity.log('validate', (f'Check failed for {host} and {cve.cve_id}: {outcome["error"]}' if outcome.get('error')
                                  else f'Template matched only the version string for {cve.cve_id} on {host}: the version is in range, '
                                       'the flaw itself was not shown' if is_version_hit(outcome)
                                  else f'Template matched {cve.cve_id} on {host}' + (', seen while authenticated' if outcome.get('authenticated') else '')
                                  if outcome['vulnerable']
                                  else f'Template did not match {cve.cve_id} on {host}'),
                     project=project, cve_id=cve.cve_id, vulnerable=is_confirmed(outcome))
    try:
        record_outcomes(cve, results, project=project, template_id=tmpl.template_id if tmpl else os.path.basename(path)[:-5])
    except Exception:  # noqa: BLE001 - failing to record a result must not lose the test that ran
        logger.exception("could not record the %s check results", cve.cve_id)
    try:  # the same outcomes are the validation record of each host's finding
        from cveFeed import validation
        validation.record_template_outcomes(cve, results, project, path)
    except Exception:  # noqa: BLE001
        logger.exception("could not record the %s check results as validation", cve.cve_id)
    if tmpl:
        tmpl.test_results = [{k: v for k, v in r.items() if k != "hit"} for r in results]
        tmpl.save(update_fields=["test_results"])
    return {"source": source, "template": path, "results": results}
