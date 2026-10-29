"""AI nuclei-template generation for CVEs no installed template covers.

Flow (PIPELINE.md stage 7): use an approved installed template when available.
Otherwise the AI may write a draft and test its syntax and false positives against
a benign local fixture. A draft is never executed on a customer host merely because
its YAML parsed and Nuclei accepted its syntax.

Sandbox: model output is untrusted. ``static_check`` only admits passive-ish
protocols (http/network/dns/ssl/tcp), rejects ``code``/``javascript``/``headless``/
``file`` (arbitrary execution or local file access) and anything off-schema, and
nuclei runs with code templates disabled, a timeout, and a rate limit, only
against hosts already in the inventory.
"""
import datetime
import json
import logging
import os
import re
import subprocess
import tempfile

import yaml

from cveFeed.safeyaml import load_template
from reNgine.ai_providers import UNTRUSTED_NOTICE, clean_text, untrusted_block

logger = logging.getLogger(__name__)

TEMPLATES_ROOT = os.environ.get("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")
# Deliberately NOT under TEMPLATES_ROOT: the blanket `nuclei -l` pass loads everything in the default template
# directory, which would run an AI-written template against every tenant's hosts. These run only via explicit -t.
GENERATED_DIR = os.environ.get("CVENGINE_GENERATED_TEMPLATES_DIR", "/root/cvengine-generated-templates")
NUCLEI_BIN = "nuclei"
MAX_TEMPLATE_BYTES = 20000
VALIDATE_TIMEOUT = 60
RUN_TIMEOUT = 180
CHUNK_HOSTS = 100  # hosts per nuclei process; halved when the process has to be stopped for memory
RATE_LIMIT = "10"

ALLOWED_PROTOCOLS = {"http", "requests", "network", "tcp", "dns", "ssl"}
FORBIDDEN_PROTOCOLS = {"code", "javascript", "headless", "file", "workflows", "flow"}
ALLOWED_TOP_KEYS = ALLOWED_PROTOCOLS | {"id", "info", "variables", "self-contained", "stop-at-first-match"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,100}$")
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

SYSTEM_PROMPT = (
    "You write nuclei v3 detection templates in YAML. Output ONLY one YAML document, "
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


def build_prompt(cve_info):
    safe = {k: _clean_value(v, 4000 if isinstance(v, str) else 500) for k, v in cve_info.items()}
    return "Write a nuclei detection template for this CVE:\n" + untrusted_block("CVE", safe)


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


def _run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def validate_with_nuclei(path):
    proc = _run([NUCLEI_BIN, "-validate", "-t", path, "-duc", "-silent"], VALIDATE_TIMEOUT)
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0 and "error" not in output.lower(), output[-2000:]


def test_benign_fixture(path):
    """A bounded localhost false-positive smoke test. It cannot prove a true-positive match."""
    import http.server
    import threading

    class Benign(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'CVEngine benign fixture: resource not found')

        do_HEAD = do_GET
        do_OPTIONS = do_GET

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Benign)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proc = _run([NUCLEI_BIN, '-t', path, '-u', f'http://127.0.0.1:{server.server_port}', '-jsonl', '-silent',
                     '-duc', '-ni', '-rl', '2', '-timeout', '2', '-retries', '0'], 30)
        if proc.returncode != 0:
            return False, 'local fixture execution failed'
        for line in proc.stdout.splitlines():
            if line.strip():
                try:
                    if is_hit(json.loads(line)):
                        return False, 'matched a benign local fixture (possible false positive)'
                except ValueError:
                    return False, 'local fixture returned malformed output'
        return True, 'no match on benign local fixture; positive detection remains unverified'
    except (OSError, subprocess.TimeoutExpired):
        return False, 'local fixture test unavailable or timed out'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _host_key(value):
    """The bare lowercase hostname of a host or URL, to pair a nuclei result with the host that was asked about."""
    value = str(value or "").strip().lower()
    value = value.split("://", 1)[-1].split("/", 1)[0]
    if value.startswith("["):
        return value.split("]", 1)[0].lstrip("[")
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def run_template(path, hosts, secret_file=None, redact=()):
    """``_run_template`` after one more look at the names: a name a tenant controls can answer a public address when the host list
    is vetted and an internal one later, so the names are resolved again here, at launch, and one that now resolves to a blocked
    address is reported as not tested instead of being handed to nuclei. (The name is still resolved by nuclei itself a moment later:
    this narrows the window, it does not close it.)"""
    from targetApp.target_types import IP, bare_host, blocked_names, classify_target
    hosts = [hosts] if isinstance(hosts, str) else list(hosts)
    names = {bare_host(h) for h in hosts}
    blocked = blocked_names([n for n in names if n and classify_target(n) != IP]) if hosts else set()
    if not blocked:
        return _run_template(path, hosts, secret_file=secret_file, redact=redact)
    allowed = [h for h in hosts if bare_host(h) not in blocked]
    ran = iter(_run_template(path, allowed, secret_file=secret_file, redact=redact) if allowed else [])
    return [{"host": h, "vulnerable": False, "output": "", "error": "the host name now resolves to an address that may not be scanned"}
            if bare_host(h) in blocked else next(ran) for h in hosts]


def _run_template(path, hosts, secret_file=None, redact=()):
    """Run one template against ``hosts`` (one nuclei process, ``-l`` a host file); returns a
    {host, vulnerable, output} per host, in order. Waits its turn for memory; if it had to be stopped to protect the
    container it raises reNgine.resources.MemoryKill. ``secret_file`` (a nuclei secrets file, see cveFeed.auth_nuclei) makes it a signed-in
    check without redirects, and ``redact`` lists the secret values to strip from every line of output and from an error message."""
    from reNgine import resources
    hosts = [hosts] if isinstance(hosts, str) else list(hosts)
    from cveFeed.validation import approved_template
    text, problem = approved_template(path)
    if problem:
        return [{"host": host, "vulnerable": False, "output": "", "error": problem} for host in hosts]
    if not hosts:
        return []
    timeout = min(RUN_TIMEOUT + 10 * len(hosts), 1800)
    # Execute exactly the bytes the policy inspected, not a mutable shared file.
    with tempfile.TemporaryDirectory(prefix="cvengine-template-run-") as scratch:
        template_path = os.path.join(scratch, "approved.yaml")
        host_path = os.path.join(scratch, "hosts.txt")
        with open(template_path, "w", encoding="utf-8") as handle:
            handle.write(text)
        with open(host_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(hosts) + "\n")
        cmd = [NUCLEI_BIN, "-t", template_path, "-l", host_path, "-jsonl", "-silent", "-duc", "-ni",
               "-rl", RATE_LIMIT, "-timeout", "10", "-retries", "0"]
        if secret_file:
            cmd += ["-sf", secret_file, "-dr"]
        from cveFeed import egress_proxy
        try:
            cmd += egress_proxy.for_tool("nuclei", hosts)  # Settings > Proxy: these hosts are scan targets (loopback stays direct)
        except egress_proxy.ProxyUnavailable as exc:
            return [{"host": host, "vulnerable": False, "output": "", "error": str(exc)} for host in hosts]
        with resources.heavy_job("template-test", label=hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts") as job:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            job.attach(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                resources.terminate_group(proc, grace=5)
                proc.communicate()
                raise
            job.raise_if_killed()
            if proc.returncode != 0:
                reason = (err or f'nuclei exited with status {proc.returncode}').strip()[-300:]
                if redact:
                    from cveFeed.auth_checks import redact_text
                    reason = redact_text(reason, redact)
                return [{"host": host, "vulnerable": False, "output": "", "error": reason} for host in hosts]
    hits, rows, malformed = {}, {}, False
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            malformed = True
            continue
        if not isinstance(row, dict):
            malformed = True
            continue
        if not is_hit(row):
            continue
        if redact:
            from cveFeed.auth_checks import redact_obj
            row = redact_obj(row, redact)
            line = json.dumps(row)
        key = _host_key(row.get("host") or row.get("matched-at") or row.get("ip"))
        hits.setdefault(key, []).append(line)
        rows.setdefault(key, row)
    if malformed:
        return [{"host": host, "vulnerable": False, "output": "", "error": "nuclei returned malformed JSON output"} for host in hosts]
    return [{"host": host, "vulnerable": bool(hits.get(_host_key(host))),
             "output": "\n".join(hits.get(_host_key(host), []))[-2000:],
             "hit": _trim_hit(rows.get(_host_key(host)))} for host in hosts]


def is_hit(row):
    """Whether a nuclei result line is a matcher hit. nuclei also reports extractor-only output (a value it pulled out of
    a response), which says what a host runs but not that it is vulnerable: a line counts when a matcher fired
    (matcher-name, or matcher-status true) and not when matcher-status is false or only extracted values are present."""
    if row.get("matcher-status") is False:
        return False
    if row.get("matcher-name") or row.get("matcher-status") is True:
        return True
    return False


def _trim_hit(row):
    """The first result line of a host, with its request and response bounded: evidence for a Vulnerability row."""
    if not row:
        return None
    return {k: (v[:8000] if isinstance(v, str) and k in ("request", "response", "curl-command") else v)
            for k, v in row.items()}


def _run_template_with_retry(path, hosts, attempts=2):
    """The check for a chunk of hosts. If its process is stopped to protect the container's memory the chunk is halved and
    each half queues again (the gate waits for room); a single host gets ``attempts`` tries before it is reported as not
    tested."""
    from reNgine.resources import MemoryKill
    hosts = [hosts] if isinstance(hosts, str) else list(hosts)
    try:
        return run_template(path, hosts)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return [{"host": host, "vulnerable": False, "output": "", "error": f"not tested: {type(exc).__name__}"} for host in hosts]
    except MemoryKill:
        if len(hosts) > 1:
            mid = len(hosts) // 2
            return _run_template_with_retry(path, hosts[:mid], attempts) + _run_template_with_retry(path, hosts[mid:], attempts)
        if attempts > 1:
            return _run_template_with_retry(path, hosts, attempts - 1)
        return [{"host": hosts[0], "vulnerable": False, "output": "", "error": "not tested: the server ran low on memory"}]


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


def approve_reviewed_template(template_pk):
    """Promote a draft only after a checked-in, independent CVE fixture detects
    the positive response and rejects the negative response on loopback.

    This is an explicit maintainer operation. It does not execute on a customer
    target, and a passing fixture does not prove a live host is affected.
    """
    from django.db import transaction
    from django.utils import timezone
    from cveFeed.models import GeneratedTemplate
    from cveFeed import template_fixtures

    with transaction.atomic():
        tmpl = GeneratedTemplate.objects.select_for_update().select_related('cve_entry').get(pk=template_pk)
        if tmpl.status != GeneratedTemplate.STATUS_DRAFT or tmpl.path:
            return False, 'only an uninstalled draft can be reviewed'
        fixture, provenance, reason = template_fixtures.load(tmpl.cve_entry.cve_id)
        if reason:
            return False, reason
        ok, reason = static_check(tmpl.yaml, expected_cve_id=tmpl.cve_entry.cve_id)
        if not ok:
            return False, f'static safety gate failed: {reason}'
        with tempfile.TemporaryDirectory(prefix='cvengine-reviewed-') as scratch:
            candidate = os.path.join(scratch, f'{tmpl.template_id}.yaml')
            with open(candidate, 'x') as stream:
                stream.write(tmpl.yaml)
            try:
                valid, output = validate_with_nuclei(candidate)
            except (OSError, subprocess.TimeoutExpired):
                return False, 'Nuclei syntax validation unavailable or timed out'
            if not valid:
                return False, f'Nuclei syntax validation failed: {output[-300:]}'
            verified, reason = template_fixtures.verify(candidate, tmpl.yaml, fixture)
            if not verified:
                return False, reason
        # Coverage lookup indexes filenames by CVE ID. Exclusive creation
        # prevents another draft from replacing an approved detector.
        try:
            installed = save_template_file(tmpl.cve_entry.cve_id.lower(), tmpl.yaml)
        except FileExistsError:
            return False, 'a generated template already exists for this CVE; review it before replacing anything'
        tmpl.path = installed
        tmpl.status = GeneratedTemplate.STATUS_VALID
        tmpl.positive_fixture_verified_at = timezone.now()
        tmpl.positive_fixture_source = provenance
        tmpl.validation_output = (tmpl.validation_output + '\n' + reason)[-2000:]
        tmpl.save(update_fields=['path', 'status', 'positive_fixture_verified_at',
                                 'positive_fixture_source', 'validation_output'])
        return True, reason


def cve_info_for(cve):
    return {"id": cve.cve_id, "title": cve.title,
            "description": cve.original_description or cve.summary,
            "cvss": cve.cvss, "affected": cve.affected, "references": cve.references}


class TemplateBudgetExceeded(Exception):
    """No AI template is written now: the CVE had an attempt recently, or the daily budget is spent."""


GENERATION_DEFAULTS = {'TEMPLATE_GEN_MAX_PER_DAY': 10, 'TEMPLATE_GEN_CVE_DAYS': 7}


def generation_limit(name):
    """A template-generation limit, overridable by CVENGINE_<NAME> in the environment."""
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
    if GeneratedTemplate.objects.filter(created_at__gte=now - datetime.timedelta(days=1)).count() >= generation_limit('TEMPLATE_GEN_MAX_PER_DAY'):
        raise TemplateBudgetExceeded('the daily AI template budget is spent')
    key = f'cvengine:templategen:{cve.pk}'
    if not cache.add(key, 1, timeout=15 * 60):
        raise TemplateBudgetExceeded(f'an AI check for {cve.cve_id} is already being written')
    return key


def generate_template(cve, provider, project=None, candidate_only=True):
    """Ask the AI for a template and gate it. On-demand candidates stay drafts after a benign fixture test. Raises
    TemplateBudgetExceeded instead of calling the AI when the generation budget does not allow an attempt."""
    if not candidate_only:
        raise ValueError('an AI template requires independently reviewed positive fixture evidence before installation')
    from django.core.cache import cache
    key = _generation_lease(cve)
    try:
        return _generate_template(cve, provider, project)
    finally:
        cache.delete(key)


def _generate_template(cve, provider, project):
    from cveFeed.models import GeneratedTemplate

    from cveFeed import activity
    with activity.step('write_check', f'Writing a nuclei check for {cve.cve_id} with {provider.name}',
                       project=project, cve_id=cve.cve_id) as handle:
        from reNgine.ai_providers import usage_stage
        try:
            with usage_stage('template_generation'):
                text = extract_yaml(provider.complete(SYSTEM_PROMPT, build_prompt(cve_info_for(cve))))
        except Exception as exc:
            # a failed provider call is still a billable attempt: leave the ledger row, so the next run does not retry this CVE at once
            GeneratedTemplate.objects.create(cve_entry=cve, yaml='', status=GeneratedTemplate.STATUS_INVALID,
                                             ai_model=f"{provider.name}:{provider.model}"[:128],
                                             validation_output=f'the AI provider call failed ({type(exc).__name__}); no template was written')
            raise
        handle.done_message = f'Wrote a nuclei check for {cve.cve_id}'
    ok, reason = static_check(text, expected_cve_id=cve.cve_id)
    tmpl = GeneratedTemplate(
        cve_entry=cve, yaml=text, ai_model=f"{provider.name}:{provider.model}",
        template_id=(load_template(text) or {}).get("id", "") if ok else "")
    if not ok:
        tmpl.status, tmpl.validation_output = GeneratedTemplate.STATUS_INVALID, f"static check: {reason}"
        tmpl.save()
        return tmpl
    with activity.step('validate', f'Validating the check for {cve.cve_id} (safety gate and nuclei -validate)',
                       project=project, cve_id=cve.cve_id) as handle:
        # validated in a private scratch directory: nothing unvalidated ever exists under GENERATED_DIR
        with tempfile.TemporaryDirectory(prefix="cvengine-validate-") as scratch:
            candidate = os.path.join(scratch, f"{tmpl.template_id}.yaml")
            with open(candidate, "w") as f:
                f.write(text)
            valid, output = validate_with_nuclei(candidate)
            if valid:
                fixture_ok, fixture_note = test_benign_fixture(candidate)
                output = (output + '\n' + fixture_note).strip()
                if not fixture_ok:
                    valid = False
        handle.done_message = f'Check for {cve.cve_id} {"passed" if valid else "failed"} validation'
    tmpl.status = GeneratedTemplate.STATUS_DRAFT if valid else GeneratedTemplate.STATUS_INVALID
    tmpl.validation_output = (output + '\nRequires a reviewed positive fixture before execution on a customer host.'
                              if valid else output)
    tmpl.save()
    return tmpl


def _severity_of(cvss, fallback):
    """The Vulnerability severity (0 info .. 4 critical) a CVE's CVSS score maps to."""
    if cvss is None:
        return fallback
    return 4 if cvss >= 9.0 else 3 if cvss >= 7.0 else 2 if cvss >= 4.0 else 1 if cvss > 0 else 0


def record_outcomes(cve, outcomes, project=None, template_id=""):
    """Persist what the template test found, so it shows in the findings, host heat and graph rather than only in the activity
    log: a vulnerable host gets a Vulnerability (source 'nuclei-cve', linked to the CVE, with the matched request and response as
    evidence), and every tested host's CVEMatch records the result ("vulnerable", "no_match", or "error" when it could not be
    tested). Only hosts of ``project`` are touched: without one nothing is guessed. Returns the number of findings saved."""
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
    now, saved = timezone.now(), 0
    for name, outcome in by_host.items():
        result = "error" if outcome.get("error") else ("vulnerable" if outcome["vulnerable"] else "no_match")
        CVEMatch.objects.filter(cve_entry=cve, subdomain__name=name, subdomain__target_domain__project_id=project).update(
            template_result=result, template_id=(template_id or "")[:128], template_tested_at=now)
    for (name, _domain_id), sub in latest.items():
        outcome = by_host[name]
        hit = outcome.get("hit")
        if not (outcome["vulnerable"] and hit):
            continue
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
    return saved


def run_cve_tests(cve, hosts, provider=None, project=None):
    """Stage 7: test with a policy-approved installed template, or save an unrun draft.

    Returns {'source': 'existing'|'candidate'|'none', 'template': path/id, 'results': [...]}.
    """
    from cveFeed import activity
    with activity.step('run_check', f'Checking nuclei template coverage for {cve.cve_id}', project=project,
                       cve_id=cve.cve_id) as handle:
        from cveFeed.validation import resolve_template
        safe_path, reason = resolve_template(cve.cve_id)
        handle.done_message = (f'A safe template for {cve.cve_id} is available' if safe_path else reason)
    if safe_path:
        path, source, tmpl = safe_path, "existing", None
    else:
        if provider is None:
            return {"source": "none", "template": "", "results": [], "reason": reason or "no AI provider configured"}
        try:
            tmpl = generate_template(cve, provider, project=project, candidate_only=True)
        except TemplateBudgetExceeded as exc:
            activity.log('write_check', f'Not writing a nuclei check for {cve.cve_id}: {exc}', project=project, cve_id=cve.cve_id)
            return {"source": "none", "template": "", "results": [], "reason": str(exc)}
        return {"source": "candidate" if tmpl.status == tmpl.STATUS_DRAFT else "none",
                "template": tmpl.template_id, "results": [], "reason": tmpl.validation_output}
    results = []
    from targetApp.target_types import scannable_hosts
    hosts = scannable_hosts(hosts, project=project)  # whatever called us, nothing that resolves to a blocked address is ever tested
    for start in range(0, len(hosts), CHUNK_HOSTS):
        chunk = hosts[start:start + CHUNK_HOSTS]
        label = chunk[0] if len(chunk) == 1 else f'{len(chunk)} hosts'
        with activity.step('run_check', f'Running the {cve.cve_id} check against {label}', project=project,
                           cve_id=cve.cve_id) as handle:
            outcomes = _run_template_with_retry(path, chunk)
            from cveFeed import auth_nuclei  # a stored sign-in adds a signed-in run for the hosts it covers
            outcomes = auth_nuclei.merge_template_outcomes(path, chunk, outcomes, project)
            errors = sum(bool(o.get('error')) for o in outcomes)
            handle.done_message = (f'{errors} of {len(outcomes)} checks failed for {cve.cve_id}' if errors else
                                   f'{sum(o["vulnerable"] for o in outcomes)} of {len(outcomes)} hosts matched {cve.cve_id}')
        results.extend(outcomes)
    for outcome in results:
        host = outcome['host']
        activity.log('validate', (f'Check failed for {host} and {cve.cve_id}: {outcome["error"]}' if outcome.get('error')
                                  else f'Template matched {cve.cve_id} on {host}' + (', seen while authenticated' if outcome.get('authenticated') else '')
                                  if outcome['vulnerable']
                                  else f'Template did not match {cve.cve_id} on {host}'),
                     project=project, cve_id=cve.cve_id, vulnerable=outcome['vulnerable'])
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
