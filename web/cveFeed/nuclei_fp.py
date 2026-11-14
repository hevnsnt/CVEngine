"""Scanner artefacts in nuclei results: matches that say more about the listener than about the product a template looks for.

Three shapes are dropped before a result becomes a finding (``nuclei_scan._run_nuclei`` asks ``RunScreen`` about every line):

* An echo port. A network (``tcp``/``javascript``) template sends a payload and matches words in the answer; a port that echoes its input
  answers with the payload itself, and the words are in it. A protocol match is dropped when its response equals, contains or is contained in
  the request it sent, when nmap named the port ``echo``, or when one port matched two or more unrelated protocol templates in one run (a
  port speaks one protocol: PostgreSQL and RocketMQ on the same port is a listener that answers everything).
* The same body for every request. A template that matched an error page the host returns for anything (a load balancer's "503 No server is
  available to handle this request") has learned nothing from its own request. A match is dropped when the responses nuclei recorded for it
  are all the same body, or when its response is an error (4xx/5xx) and a control request for a path no site serves returns the same status
  and the same body. Only HTTP matches above info are checked, and only when the scan recorded the response: nothing is re-requested to
  guess what a match saw.

Every dropped line is counted by reason, so the run's summary says what was set aside; nothing about it is stored as a finding.

``bounded`` clips the request and response a finding keeps (the evidence a person and the triage read) to ``MAX_EVIDENCE`` characters each.
"""
import hashlib
import logging
import re
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_EVIDENCE = 8 * 1024  # characters of the matched request and of the response a nuclei finding keeps
PROTOCOL_TYPES = frozenset({'tcp', 'network', 'javascript', 'js'})
PROTOCOL_TAGS = frozenset({'network', 'tcp', 'js', 'javascript'})
MIN_ECHO = 4  # an echoed payload shorter than this proves nothing (a lone newline, "OK")
MIN_PARTIAL_ECHO = 8  # a response that is only part of the request must be at least this long to count as an echo of it
CONTROL_BYTES = 64 * 1024
CONTROL_SEVERITIES = frozenset({'low', 'medium', 'high', 'critical'})
# tags and template-id words that say what kind of check a template is, not which product it is for: two templates that share only these
# are unrelated (``apache`` is a vendor of many unrelated products: RocketMQ and ActiveMQ are not one protocol)
GENERIC = frozenset({
    'network', 'tcp', 'udp', 'js', 'javascript', 'unauth', 'unauthenticated', 'noauth', 'misconfig', 'exposure', 'exposed', 'detect',
    'detection', 'enum', 'default', 'login', 'default-login', 'vuln', 'cve', 'kev', 'vkev', 'edb', 'intrusive', 'auth', 'bypass',
    'auth-bypass', 'rce', 'disclosure', 'info', 'discovery', 'service', 'database', 'db', 'panel', 'tech', 'ssl', 'tls', 'oss', 'apache',
    'access', 'check', 'broker', 'server', 'open', 'version', 'config', 'unauthorized', 'anonymous', 'weak', 'brute', 'bruteforce',
    'injection', 'cnvd', 'seclists', 'passive', 'msf', 'packetstorm', 'huntr'})
_CVE_TAG = re.compile(r'^(cve|cnvd)\d{4}$|^cve-\d{4}-\d+$|^\d+$')
_STATUS_LINE = re.compile(r'(?m)^HTTP/\d(?:\.\d)? (\d{3})[^\r\n]*\r?\n')
_UNPRINTABLE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

ECHO, ECHO_SERVICE, MANY_PROTOCOLS, SAME_BODY = 'echo', 'echo_service', 'many_protocols', 'same_body'
REASONS = {ECHO: 'the port echoed the template request', ECHO_SERVICE: 'nmap names the port an echo service',
           MANY_PROTOCOLS: 'the port matched unrelated protocol templates', SAME_BODY: 'every request returned the same body'}


def bounded(text, limit=MAX_EVIDENCE):
    """``text`` as stored evidence: a string of at most ``limit`` characters, without NUL and other control bytes (newlines kept), or None."""
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    text = _UNPRINTABLE.sub('', text)
    return text if len(text) <= limit else text[:limit]


def _text(value):
    return value if isinstance(value, str) else ('' if value is None else str(value))


# ----------------------------------------------------------------------------- what a line is

def matched_at(line):
    return _text(line.get('matched-at') or line.get('host')).strip()


def is_protocol(line):
    """A network-protocol template match (raw TCP or a javascript protocol check), as opposed to HTTP, DNS or TLS. A Sentinel's line does not
    always say its type (it reads ``http``): a ``host:port`` match of a template tagged as a network check is one."""
    kind = _text(line.get('type')).lower()
    if kind in PROTOCOL_TYPES:
        return True
    if kind not in ('', 'http'):
        return False
    tags = {str(t).lower() for t in ((line.get('info') or {}).get('tags') or [])}
    return '://' not in matched_at(line) and bool(tags & PROTOCOL_TAGS)


def port_key(line):
    """``(host, port)`` of a protocol match, lowercase, or None when the match names no port."""
    raw = matched_at(line)
    if '://' in raw:
        parts = urlsplit(raw)
        return ((parts.hostname or '').lower(), parts.port) if parts.port else None
    if raw.startswith('['):
        host, _, rest = raw[1:].partition(']')
        port = rest.lstrip(':')
    elif raw.count(':') == 1:
        host, port = raw.split(':')
    else:
        return None
    return (host.lower(), int(port)) if port.isdigit() else None


def echoes(line):
    """True when the response is the request coming back: equal, containing it, or contained in it."""
    request, response = _text(line.get('request')).strip(), _text(line.get('response')).strip()
    if len(request) < MIN_ECHO or len(response) < MIN_ECHO:
        return False
    return request in response or (len(response) >= MIN_PARTIAL_ECHO and response in request)


def product_words(line):
    """The words of a template's tags and id that name what it is for (not generic words like ``unauth``, ``network`` or a CVE year)."""
    info = line.get('info') or {}
    tags = {str(t).lower() for t in (info.get('tags') or []) if isinstance(t, str)}
    words = {t for t in tags if t not in GENERIC and not _CVE_TAG.match(t)}
    if not words:
        ident = _text(line.get('template-id')).lower()
        words = {w for w in re.split(r'[^a-z0-9]+', ident) if len(w) > 2 and w not in GENERIC and not _CVE_TAG.match(w)}
    return words


def unrelated(lines):
    """True when the templates of ``lines`` include two that are about different products."""
    by_template = {}
    for line in lines:
        by_template.setdefault(_text(line.get('template-id')).lower(), product_words(line))
    groups = [words for words in by_template.values() if words]
    for i, first in enumerate(groups):
        for second in groups[i + 1:]:
            if not first & second:
                return True
    return False


# ----------------------------------------------------------------------------- HTTP: the same body for every request

def responses(raw):
    """``[(status, location, body)]`` of the HTTP responses in a nuclei ``response`` field (one or several, as nuclei recorded them)."""
    raw = _text(raw)
    starts = [m for m in _STATUS_LINE.finditer(raw)]
    out = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(raw)
        chunk = raw[match.start():end]
        head, sep, body = chunk.partition('\r\n\r\n')
        if not sep:
            head, _, body = chunk.partition('\n\n')
        location = ''
        for header in head.splitlines()[1:]:
            name, _, value = header.partition(':')
            if name.strip().lower() == 'location':
                location = value.strip()
        out.append((int(match.group(1)), location, body))
    return out


def _norm(body):
    return ' '.join(_text(body).split())


def same_bodies(answers):
    """True when two or more responses are the same status, redirect target and non-empty body."""
    if len(answers) < 2:
        return False
    first = (answers[0][0], answers[0][1], _norm(answers[0][2]))
    return bool(first[2]) and all((s, loc, _norm(b)) == first for s, loc, b in answers[1:])


def control_url(url):
    """A path on the same origin that no site serves. The token is a function of the origin and this server's secret, not random: an asynchronous
    stage runs the same code again after each wait, and a control read that asked a different path each time would be a new task every pass."""
    import hashlib

    from django.conf import settings
    parts = urlsplit(url)
    origin = f'{parts.scheme}://{parts.netloc}'.lower()
    token = hashlib.sha256(f'{settings.SECRET_KEY}:control:{origin}'.encode()).hexdigest()[:12]
    return f'{parts.scheme}://{parts.netloc}/.cvengine-control-{token}'


def body_digest(body):
    """The SHA-256 of ``body`` with its whitespace collapsed: what a Sentinel returns of a control answer instead of the body (``page_read`` op ``control``)."""
    return hashlib.sha256(_norm(body).encode('utf-8', 'replace')).hexdigest()


def control_get(urls, project=None, scan=None):
    """``{url: (status, location, digest) or None}`` for the control paths in ``urls``, each read once by a Sentinel (``page_read``, op ``control``: this
    server sends nothing to the host). ``None`` is a URL that could not be read: it decides nothing (see ``Screen``). ``ScannerUnavailable`` when no
    Sentinel can take the work: the stage waits and its targets stay due."""
    if not urls:
        return {}
    from agentapi import probe_dispatch
    from dashboard.models import Project
    if project is None:
        return {url: None for url in urls}
    return probe_dispatch.control_reads(Project.objects.get(pk=project), scan, urls)


def needs_control(line):
    """The control URL a match must be compared with, or None when the match is decided without one (not HTTP above info, no recorded response, every
    recorded response the same body, a success page or an empty body: none of them is asked of the host)."""
    severity = _text((line.get('info') or {}).get('severity')).lower()
    if _text(line.get('type')).lower() not in ('', 'http') or severity not in CONTROL_SEVERITIES:
        return None
    answers = responses(line.get('response'))
    if not answers or same_bodies(answers):
        return None
    status, _location, body = answers[-1]
    if status < 400 or not _norm(body):
        return None
    url = matched_at(line)
    return control_url(url) if '://' in url else None


ARTEFACT, CLEAN, UNSCREENED = 'artefact', 'clean', 'unscreened'
UNSCREENED_TAG = 'unscreened-same-body'  # on a finding kept because the control read that would have told a catch-all page apart could not be made


class SameBody:
    """The same-body screen of one run: ``prefetch(lines)`` asks for the control read every line needs (one task for up to ten origins, each origin once),
    ``judge(line)`` is ``'artefact'`` (the host gives this answer to anything: set it aside), ``'clean'`` (it does not) or ``'unscreened'`` (the control
    read the line needed could not be made, so nothing is known: the finding is kept and marked, never taken as \"not a catch-all\"). ``control`` replaces
    ``control_get`` (tests). ``ScannerUnavailable`` from the control read is not caught: the stage waits and the targets stay due."""

    def __init__(self, project=None, scan=None, control=None):
        self.project, self.scan, self.control = project, scan, control
        self.controls = {}

    def prefetch(self, lines):
        wanted = [url for url in dict.fromkeys(needs_control(line) for line in lines if isinstance(line, dict)) if url and url not in self.controls]
        if wanted:
            got = (self.control or control_get)(wanted, self.project, self.scan) or {}
            for url in wanted:
                self.controls[url] = got.get(url)

    def judge(self, line):
        answers = responses(line.get('response'))
        if not answers:
            return CLEAN
        if _text((line.get('info') or {}).get('severity')).lower() in CONTROL_SEVERITIES and _text(line.get('type')).lower() in ('', 'http') and same_bodies(answers):
            return ARTEFACT
        url = needs_control(line)
        if url is None:
            return CLEAN
        got = self.controls.get(url)
        if not got:
            logger.info('nuclei control read for %s was not answered: the match is kept, unscreened', urlsplit(matched_at(line)).netloc)
            return UNSCREENED
        status, location, body = answers[-1]
        return ARTEFACT if (status, location, body_digest(body)) == (got[0], got[1], got[2]) else CLEAN


# ----------------------------------------------------------------------------- one run

class RunScreen:
    """Sorts the lines of one nuclei run. ``offer(line)`` is ``'keep'`` (save it now), ``'hold'`` (a protocol match: judged with the run's
    other matches on that port by ``release()``) or a drop reason. ``echo_ports`` is a set of ``(host or address, port)`` nmap named echo."""

    def __init__(self, echo_ports=(), project=None, control=None, scan=None):
        self.echo_ports = {(str(h).lower(), int(p)) for h, p in echo_ports}
        self.project = project
        self.same = SameBody(project, scan, control)
        self.held = {}
        self.dropped = {}
        self.unscreened = 0  # kept matches whose control read could not be made
        self._unscreened = set()

    def prefetch(self, lines):
        """Ask for the control reads the ``lines`` (one chunk's matches) need, before any is offered: one Sentinel task for up to ten origins."""
        self.same.prefetch(lines)

    def is_unscreened(self, line):
        """True for a kept match that was not checked against its control (the read could not be made): it is saved, and marked."""
        return id(line) in self._unscreened

    def _drop(self, reason, line):
        self.dropped[reason] = self.dropped.get(reason, 0) + 1
        logger.info('nuclei match %s at %s set aside: %s', line.get('template-id'), matched_at(line)[:200], REASONS[reason])
        return reason

    def offer(self, line):
        if is_protocol(line):
            key = port_key(line)
            if key and key in self.echo_ports:
                return self._drop(ECHO_SERVICE, line)
            if echoes(line):
                return self._drop(ECHO, line)
            if key is None:
                return 'keep'
            self.held.setdefault(key, []).append(line)
            return 'hold'
        verdict = self.same.judge(line)
        if verdict == ARTEFACT:
            return self._drop(SAME_BODY, line)
        if verdict == UNSCREENED:
            self._unscreened.add(id(line))
            self.unscreened += 1
        return 'keep'

    def release(self):
        """The held protocol matches that stand, and forget them: a port with matches of unrelated templates keeps none."""
        out = []
        for _key, lines in self.held.items():
            if unrelated(lines):
                for line in lines:
                    self._drop(MANY_PROTOCOLS, line)
                continue
            out += lines
        self.held = {}
        return out

    def reset(self):
        """Forget what is held (a retried run sends its lines again)."""
        self.held = {}
        self._unscreened = set()

    def summary(self):
        """``'2 (the port echoed the template request: 2)'`` style text of what was set aside, or ''."""
        total = sum(self.dropped.values())
        if not total:
            return ''
        return f'{total} ({"; ".join(f"{REASONS[k]}: {v}" for k, v in sorted(self.dropped.items()))})'
