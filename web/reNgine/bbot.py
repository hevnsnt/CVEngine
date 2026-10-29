"""bbot integration: run bbot in-process-tree (no remote host) and normalise its JSON events.

bbot 3.x emits one JSON object per line on stdout (``--json``). Events reference
their parent by id, ``data`` is ``None`` for structured events (the payload is in
``data_json``), and ``discovery_path`` narrates how an event was found.
"""
import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

BBOT_BIN = 'bbot'
DEFAULT_PRESETS = ('subdomain-enum',)
DEFAULT_TIMEOUT = 6 * 3600
# passive: only public data sources (CT logs, passive DNS, InternetDB...); nothing is sent to the target.
# standard (the default): subdomain enumeration plus bbot's quick web preset, limited to modules flagged "safe" (no brute
# forcing, spidering or other loud modules). bbot 3.x calls the quick web preset "web" (older releases "web-basic"), and
# it ANDs required flags, so "passive,safe" would drop every active web module and leave nothing for the preset to do.
# The web-screenshots preset adds gowitness (flagged safe), so every web host gets a front-page screenshot in the default mode, not only in deep.
# deep: bbot's kitchen-sink preset (everything: subdomain, cloud, code and email enumeration, spidering, web
# probing, directory and parameter discovery, takeover checks...). It is active: it sends traffic to the
# target, so it is only for targets you are authorized to test. bbot 3.x has no "allow deadly modules" flag
# (that belongs to a different tool/version); --force only skips its own precondition warnings.
MODES = {
    'passive': {'presets': ('subdomain-enum',), 'args': ['-rf', 'passive']},
    'standard': {'presets': ('subdomain-enum', 'web', 'web-screenshots'), 'args': ['-rf', 'safe', '--force']},
    'deep': {'presets': ('kitchen-sink',), 'args': ['--force']},
}
MODE_ARGS = {name: m['args'] for name, m in MODES.items()}  # kept for callers that read the extra args
DEFAULT_MODE = 'standard'
PRESET_FLAG = '--cvengine-preset'  # internal: marks the private preset file private_config passes to build_command
HEAVY_KIND = {'deep': 'bbot-deep', 'passive': 'bbot-passive'}  # any other mode is the standard weight
BBOT_SEVERITIES = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
# Event types worth showing to a human in the live feed.
INTERESTING = {'DNS_NAME', 'IP_ADDRESS', 'OPEN_TCP_PORT', 'URL', 'TECHNOLOGY', 'WAF', 'FINDING', 'VULNERABILITY',
               'STORAGE_BUCKET', 'EMAIL_ADDRESS', 'ASN', 'SOCIAL', 'CODE_REPOSITORY', 'WEBSCREENSHOT', 'PROTOCOL'}


@dataclass
class BbotResult:
    subdomains: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    ports: set = field(default_factory=set)         # (host, port)
    urls: set = field(default_factory=set)          # (url, http status bbot tagged it with; 0 when unknown)
    technologies: set = field(default_factory=set)  # (host, technology)
    resolutions: set = field(default_factory=set)   # (name, ip)
    edges: set = field(default_factory=set)         # (parent_host, child_host) for the spider graph
    findings: list = field(default_factory=list)    # dicts: name, severity (0-4), host, url, description
    screenshots: list = field(default_factory=list)  # dicts: host, rel_path (under the bbot scan's own home dir), url
    http: list = field(default_factory=list)        # dicts from HTTP_RESPONSE events: host, url, port, status, title, webserver, ...


@dataclass
class Observed:
    """One event as shown in the live feed."""
    type: str
    label: str
    host: str = ''
    parent_host: str = ''
    module: str = ''


TITLE_MAX = 80
_TITLE_BREAK = re.compile(r'\s[-\u2013\u2014]\s|:\s|:$|\.\s|\n')


def short_title(description):
    """A concise finding name from bbot's description, which runs on into confidence, signature, trigger and module lines:
    "No DMARC record found - domain has no protection ... Trigger: [...]" -> "No DMARC record found". The text before the first
    " - ", ": ", ". " or line break, capped at ``TITLE_MAX`` on a word boundary. The full text stays in the description."""
    text = str(description or '').strip()
    head = ' '.join(_TITLE_BREAK.split(text, 1)[0].split()).strip(' -:.') or ' '.join(text.split())[:TITLE_MAX]
    if len(head) > TITLE_MAX:
        head = head[:TITLE_MAX].rsplit(' ', 1)[0].rstrip(' ,;-:') + '\u2026'
    return (head[:1].upper() + head[1:]) or 'Finding'


# Informational bbot detections ("WAF Detection", "Nginx version detect", "uses federated authentication") are host labels, not
# findings. The cutoff is conservative, because a real exposure dropped is a false negative:
#   * bbot severity LOW or higher is always a finding, whatever the text;
#   * text that reads like an exposure (leak, takeover, missing SPF/DMARC, a bucket, a credential...) is always a finding, even at
#     info: it is hidden by the list's default severity filter but never lost;
#   * otherwise severity INFO that bbot stated is a label, and so is a FINDING bbot gave no severity when its text reads like a
#     detection (detect, version, WAF, technology, federated, ...). Anything else with no severity stays a finding.
_EXPOSURE = re.compile(
    r'leak|disclos|credential|secret|passw|token|api[ _-]?key|takeover|vulnerab|misconfig|\bno (spf|dmarc|dkim|dnssec|caa|mx)\b|'
    r'\bmissing\b|default (login|cred|pass)|backup|\.git\b|\.env\b|directory listing|bucket|unauth|anonymous|admin(istrat\w+)? panel|'
    r'open redirect|inject|traversal|\bcve-\d|\bexploit|\bexpos(ed|ure)\b.*\b(database|admin|panel|file|key|config)|private key|sensitive',
    re.I)
_DETECTION = re.compile(
    r'detect|version|\bwaf\b|firewall|technolog|fingerprint|identified|federated|powered by|\buses\b|response \(body\)|\bcdn\b|banner', re.I)
_DETECTION_LABELS = (
    (re.compile(r'\bwaf\b|web application firewall', re.I), 'WAF'),
    (re.compile(r'federated auth', re.I), 'federated auth'),
    (re.compile(r'^http response \(body\)', re.I), 'response body match'),
)
_VERSION_DETECT = re.compile(r'^(.+?)\s+version\b', re.I)
_DETECT_TAIL = re.compile(r'\s*\b(detect(ed|ion|ed)?|identified)\b\s*$', re.I)
LABEL_MAX = 40


def is_informational(name, description, severity, severity_stated=True):
    """True for a bbot detection that is a host label rather than a finding (see the cutoff above). Pure."""
    if severity and severity > 0:
        return False
    text = f'{name} {description}'
    if _EXPOSURE.search(text):
        return False
    return True if severity_stated else bool(_DETECTION.search(name or ''))


def label_for(name):
    """A short chip label for a detection name: "WAF Detection" -> "WAF", "Nginx version detect" -> "nginx version", a
    sensible fallback (the first four words without a trailing "detect") for the rest. Bounded to ``LABEL_MAX``. Pure."""
    title = short_title(name)
    for pattern, label in _DETECTION_LABELS:
        if pattern.search(title):
            return label
    m = _VERSION_DETECT.match(title)
    if m and len(m.group(1)) <= 24:
        product = m.group(1)
        return f'{product.lower() if product.istitle() else product} version'
    words = _DETECT_TAIL.sub('', title).split()
    return (' '.join(words[:4])[:LABEL_MAX].rstrip(' ,;-:') or 'detection')


def finding_key(description):
    """A short stable digest of a finding's full text. The short name no longer tells two findings apart ("Open S3 bucket: a" and
    "...: b" are both "Open S3 bucket"), so the digest goes in the finding's matcher key and neither is merged into the other."""
    import hashlib
    return hashlib.sha1(str(description or '').encode('utf-8', 'replace')).hexdigest()[:16]


def _payload(event):
    data = event.get('data')
    return data if data is not None else event.get('data_json')


def _label(etype, payload, host):
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        if etype == 'TECHNOLOGY':
            return f"{payload.get('technology', '?')} on {payload.get('host') or host or '?'}"
        if etype == 'WAF':
            return f"WAF {str(payload.get('waf') or '?')[:80]} on {payload.get('host') or host or '?'}"
        if etype in ('FINDING', 'VULNERABILITY'):
            return str(payload.get('description') or payload.get('name') or 'finding')[:200]
        if etype == 'ASN':
            return f"AS{payload.get('asn', '?')} {payload.get('name', '')}".strip()
        return str(payload.get('url') or payload.get('host') or next(iter(payload.values()), ''))[:200]
    return host or ''


def waf_product(name):
    """The product a bbot ``WAF`` event names (wafw00f's list gives "FortiWeb (Fortinet)", "BIG-IP AppSec Manager (F5 Networks)"): the part
    before the vendor in brackets, so it reads like any other technology name. "generic detection" says a firewall answered and not which
    one, so it names nothing. Pure."""
    text = re.sub(r'\s*\([^)]*\)\s*$', '', str(name or '')).strip()[:80]
    return '' if not text or text.lower() in ('generic detection', 'unknown', 'none') else text


def parse_event(event, result, hosts=None):
    """Fold one decoded bbot JSON event into ``result``; returns an Observed for the live feed or None.

    ``hosts`` maps event id -> host so a child event can be linked to its parent's host.
    """
    hosts = {} if hosts is None else hosts
    if (event.get('scope_distance') or 0) > 0:
        return None  # bbot also reports neighbours (an MX's mail host, a name server): not part of this target
    etype, payload, host = event.get('type'), _payload(event), event.get('host')
    if host and event.get('id'):
        hosts[event['id']] = host
    parent_host = hosts.get(event.get('parent')) or ''
    if etype == 'DNS_NAME' and isinstance(payload, str):
        name = payload.lower()
        result.subdomains.add(name)
        for ip in event.get('resolved_hosts') or []:
            if ':' not in ip:
                result.ips.add(ip)
                result.resolutions.add((name, ip))
    elif etype == 'IP_ADDRESS' and isinstance(payload, str):
        result.ips.add(payload)
    elif etype == 'OPEN_TCP_PORT' and isinstance(payload, str) and ':' in payload:
        h, _, port = payload.rpartition(':')
        if port.isdigit():
            result.ports.add((h.strip('[]'), int(port)))
    elif etype == 'URL' and isinstance(payload, str):
        result.urls.add((payload, _status_from_tags(event.get('tags'))))
    elif etype == 'TECHNOLOGY' and isinstance(payload, dict):
        result.technologies.add((payload.get('host') or host, payload.get('technology')))
    elif etype == 'WAF' and isinstance(payload, dict):
        product = waf_product(payload.get('waf'))
        if product:  # the firewall's own name is a technology of the host, like any other fingerprint
            result.technologies.add((payload.get('host') or host, product))
    elif etype == 'HTTP_RESPONSE' and isinstance(payload, dict):
        record = http_response_record(payload, host)
        if record and len(result.http) < MAX_HTTP_RESPONSES:
            result.http.append(record)
    elif etype == 'WEBSCREENSHOT' and isinstance(payload, dict) and payload.get('path'):
        result.screenshots.append({'host': (host or '').lower(), 'rel_path': payload['path'], 'url': payload.get('url', '')})
    if etype in ('FINDING', 'VULNERABILITY') and isinstance(payload, dict):
        sev = BBOT_SEVERITIES.get(str(payload.get('severity', 'INFO')).upper(), 0)
        description = str(payload.get('description') or payload.get('name') or etype.title())
        stated = str(payload.get('severity') or '').upper() in BBOT_SEVERITIES
        name = short_title(description)
        result.findings.append({
            'name': name, 'informational': is_informational(name, description, sev, stated),
            'severity': sev, 'host': (payload.get('host') or host or '').lower(),
            'url': payload.get('url') or '', 'description': description, 'module': event.get('module') or ''})
    edge_host = (host or '').lower()
    if edge_host and parent_host and edge_host != parent_host.lower():
        result.edges.add((parent_host.lower(), edge_host))
    if etype not in INTERESTING:
        return None
    return Observed(type=etype, label=_label(etype, payload, host), host=host or '',
                    parent_host=parent_host, module=event.get('module') or '')


MAX_HTTP_RESPONSES = 5000  # per result: one per URL bbot fetched, kept for the host fields and the port's http record


def http_response_record(payload, host=''):
    """What a bbot HTTP_RESPONSE event says about one answer, bounded: host, URL, port, status, title, server, content type. None
    when it names no URL. bbot (httpx) reports the headers as a dict with lowercase names and also as ``raw_header`` text."""
    url = str(payload.get('url') or '')[:2000]
    if not url:
        return None
    from urllib.parse import urlparse
    parsed = urlparse(url)
    headers = payload.get('header') if isinstance(payload.get('header'), dict) else {}
    lowered = {str(k).lower().replace('_', '-'): v for k, v in headers.items()}

    def header(name):
        value = lowered.get(name, '')
        return str(value[0] if isinstance(value, list) and value else value)[:300]
    try:
        status = int(payload.get('status_code') or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        port = int(payload.get('port') or parsed.port or (443 if parsed.scheme == 'https' else 80))
    except (TypeError, ValueError):
        port = 0
    return {'host': (payload.get('host') or parsed.hostname or host or '').lower(), 'url': url, 'port': port, 'status': status,
            'title': str(payload.get('title') or '')[:500], 'webserver': str(payload.get('webserver') or header('server'))[:300],
            'content_type': str(payload.get('content_type') or header('content-type'))[:200],
            'location': str(payload.get('location') or header('location'))[:500]}


def _status_from_tags(tags):
    """The HTTP status bbot put on a URL event as a ``status-200`` tag, or 0."""
    for tag in tags or []:
        if isinstance(tag, str) and tag.startswith('status-') and tag[7:].isdigit():
            return int(tag[7:])
    return 0


def parse_output(lines):
    result, hosts = BbotResult(), {}
    for line in lines:
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            parse_event(json.loads(line), result, hosts)
        except json.JSONDecodeError:
            continue
    return result


def build_command(targets, presets=None, mode=DEFAULT_MODE, extra_args=(), strict_scope=False):
    """The bbot command line. ``strict_scope`` adds bbot's ``--strict-scope`` (exact matches only: a target's subdomains are
    not in scope either), used for a host-scoped target such as a tenant on a shared provider domain, where the host is all that
    is owned. Not applied to an owned apex: there the subdomains ARE the point of the run."""
    cfg = MODES.get(mode, MODES['passive'])
    cmd = [BBOT_BIN, '-t', *targets]
    args, names = list(extra_args), list(presets or cfg['presets'])
    if PRESET_FLAG in args:  # private_config's key file travels as one more preset, after the named ones
        at = args.index(PRESET_FLAG)
        names.append(args[at + 1])
        del args[at:at + 2]
    cmd += ['-p', *names]  # one -p with every preset: bbot's -p takes the list and a second -p replaces the first
    if strict_scope:
        cmd.append('--strict-scope')
    return cmd + cfg['args'] + ['--json', '-y', '--no-color', *args]


class BbotProcessError(RuntimeError):
    """bbot exited abnormally before producing any usable output (crash, missing binary, bad preset...).
    ``returncode`` is set when known; -9 means the kernel killed it, almost always for memory."""
    returncode = None


_CONFIG_REJECTED = re.compile(r'Error parsing command-line (?:config option|preset)|Could not find preset', re.I)
# "Setup soft-failed for shodan_dns: Error with API (401 Unauthorized": a module that could not start (a rejected or missing key)
# is skipped and the scan goes on, so this line is the only place a rejected key shows
_SOFT_FAIL = re.compile(r'Setup soft-failed for (\w+): (.{1,200})')
_ERROR_LINE = re.compile(r'(?:\b\w*(?:Error|Exception)\b|\bfailed\b|\bFailed\b|\bCRITICAL\b)')


def config_secrets(extra_args):
    """The values of the ``-c path=value`` flags: API keys that must never reach a log line or an error message."""
    args = list(extra_args or ())
    return [a.split('=', 1)[1] for prev, a in zip(args, args[1:]) if prev == '-c' and '=' in a and a.split('=', 1)[1]]


def redact(text, secrets):
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, '***')
        for part in secret.split(':'):  # a "id:secret" pair may be echoed in pieces
            if len(part) >= 6:
                text = text.replace(part, '***')
    return text


def failure_message(returncode, stderr_lines):
    """A readable reason first (the activity feed shows only the start of a message, and a traceback's cause is at its
    end), then the stderr tail for the details."""
    lines = [ln.strip() for ln in stderr_lines if ln.strip()]
    if returncode == -9:
        reason = ('the process was killed, almost always by the kernel running out of memory (too many discoveries '
                  'at once or too little RAM: lower DISCOVERY_CONCURRENCY or add memory)')
    else:
        found = next((ln for ln in reversed(lines) if _ERROR_LINE.search(ln) and not ln.startswith('File ')), None)
        reason = (found or (lines[-1] if lines else 'no error output'))[:300]
    tail = ' | '.join(lines[-12:])[-900:]
    return f'bbot exited with status {returncode} before producing any results: {reason}' + (f' [stderr: {tail}]' if tail else '')


@contextlib.contextmanager
def private_config(extra_args):
    """Move the ``-c path=value`` flags (API keys) out of the command line and into a preset file only this user can read.

    Arguments are visible to every process in the container through /proc/<pid>/cmdline and in process listings and crash dumps,
    so a key never goes there. bbot 3.x takes only ``key=value`` after ``-c`` (a file there is rejected and the scan does not
    run), so the keys go in a preset file, ``{config: {modules: {...}}}``, which bbot merges with the named presets when its
    absolute path is listed after them. The file lives in a fresh 0700 directory, is created 0600 and is deleted, with its
    directory, when the run ends, however it ends. Yields the argument list to use instead (the file travels as PRESET_FLAG and
    is placed by build_command); with no ``-c key=value`` flags nothing is written and the list is returned unchanged."""
    args = list(extra_args or ())
    config, rest, i = {}, [], 0
    while i < len(args):
        if args[i] == '-c' and i + 1 < len(args) and '=' in args[i + 1] and not os.path.exists(args[i + 1]):
            path, _, value = args[i + 1].partition('=')
            node = config
            keys = path.split('.')
            for key in keys[:-1]:
                node = node.setdefault(key, {})
            node[keys[-1]] = value
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if not config:
        yield args
        return
    import yaml
    directory = tempfile.mkdtemp(prefix='cvengine-bbot-')  # mkdtemp creates it 0700
    try:
        path = os.path.join(directory, 'keys.yml')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            yaml.safe_dump({'config': config}, handle)
        yield [*rest, PRESET_FLAG, path]
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def stream_events(targets, presets=None, mode=DEFAULT_MODE, timeout=DEFAULT_TIMEOUT, extra_args=(), strict_scope=False, problems=None):
    """Run bbot and yield decoded JSON events as they arrive; API keys in ``extra_args`` reach bbot through a private temporary
    config file (see private_config), never through its command line. ``problems``, when given, collects ``(module, reason)`` for every
    module bbot skipped at start-up. See _stream_events for the rest.

    Settings > Proxy (``cveFeed.egress_proxy``) is applied through bbot's own ``web.http_proxy`` setting, so the HTTP requests of its modules
    go through it (the passive modules' calls to third-party services included: bbot cannot tell them apart). The proxy URL (it may carry a
    login) travels in the same private config file as the API keys. bbot's DNS lookups and any module that is not HTTP are not proxied.
    Raises ``ProxyUnavailable`` when the setting is on and no proxy suits bbot, rather than run it directly."""
    from cveFeed import egress_proxy
    extra_args = [*(extra_args or ()), *egress_proxy.for_tool('bbot')]
    with private_config(extra_args) as args:
        yield from _stream_events(targets, presets, mode, timeout, args, secrets=config_secrets(extra_args), strict_scope=strict_scope,
                                  problems=problems)


def _stream_events(targets, presets=None, mode=DEFAULT_MODE, timeout=DEFAULT_TIMEOUT, extra_args=(), secrets=None, strict_scope=False,
                   problems=None):
    """Run bbot and yield decoded JSON events as they arrive (kills bbot after ``timeout`` seconds).

    A process that exits with a nonzero status and never produced a single event is a silent failure
    (a crash, a worker restart killing it, a bad preset), not "discovery found nothing": that must
    surface as an error rather than a scan quietly marked finished with 0 hosts.

    The run waits its turn for memory (reNgine.resources) and is stopped cleanly if the container runs low:
    ``MemoryKill`` is raised so the caller can retry lighter instead of losing the worker to the OOM killer.

    ``extra_args`` is typically the ``-c modules.<name>.api_key=...`` flags from
    cveFeed.api_credentials.bbot_config_args, so a project's Shodan/Censys/etc. keys reach the modules
    that use them.
    """
    import collections
    import threading

    from reNgine import resources
    secrets = config_secrets(extra_args) if secrets is None else secrets
    with resources.heavy_job(HEAVY_KIND.get(mode, 'bbot-standard'), label=','.join(targets)[:80]) as job:
        proc = subprocess.Popen(build_command(targets, presets, mode, extra_args, strict_scope), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1, start_new_session=True)
        job.attach(proc)
        stderr_tail = collections.deque(maxlen=50)

        def _drain_stderr():
            for line in proc.stderr:
                line = redact(line.rstrip('\n'), secrets)
                stderr_tail.append(line)
                found = _SOFT_FAIL.search(line)
                if found and problems is not None:
                    problems.append((found.group(1), found.group(2).strip()))

        drain = threading.Thread(target=_drain_stderr, daemon=True)
        drain.start()
        timed_out = threading.Event()
        timer = threading.Timer(timeout, lambda: (timed_out.set(), resources.terminate_group(proc, grace=5)))
        timer.start()
        produced_any = False
        try:
            for line in proc.stdout:
                line = line.strip()
                if line.startswith('{'):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    produced_any = True
                    yield event
        finally:
            timer.cancel()
            if proc.poll() is None:
                resources.terminate_group(proc, grace=5)
            proc.wait()
            drain.join(timeout=5)
            proc.stdout.close()
            proc.stderr.close()
            job.raise_if_killed()
            if not produced_any and not timed_out.is_set() and proc.returncode not in (0, None):
                error = BbotProcessError(failure_message(proc.returncode, list(stderr_tail)))
                error.returncode = proc.returncode
                raise error
            if not produced_any and not timed_out.is_set() and any(_CONFIG_REJECTED.search(ln) for ln in stderr_tail):
                # bbot prints this, runs no scan and exits 0: that is a failed run, not a discovery that found nothing
                error = BbotProcessError(failure_message(0, list(stderr_tail)).replace('before producing any results', 'without scanning'))
                error.returncode = 0
                raise error


def run_bbot(targets, presets=None, mode=DEFAULT_MODE, timeout=DEFAULT_TIMEOUT, extra_args=(), strict_scope=False):
    """Run bbot to completion and return one BbotResult."""
    result, hosts = BbotResult(), {}
    for event in stream_events(targets, presets, mode, timeout, extra_args, strict_scope):
        parse_event(event, result, hosts)
    return result
