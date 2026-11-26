"""Input guard: reject requests that carry attack payloads, and ban whoever keeps sending them. (Requests a browser marks cross-site are rejected but never counted, so a
hostile page cannot get a visitor banned.)

Runs after authentication (so the actor is known) and before roles and views. It reads the query string and the
JSON or form body; multipart uploads and credential-like fields (passwords, tokens, keys, engine YAML) are not
inspected. Two kinds of hit:

* signatures: shell command injection, `${...}`/backtick substitution, path traversal, NUL bytes, SQL injection
  (weight 3) and script or template-injection markers (weight 2). Patterns are specific enough that ordinary
  text does not trip them.
* strict fields: values that must be a hostname, IP, CIDR, range, slug or id (``value``, ``host``, ``project``,
  ...) containing anything else, and bulk target lists with shell metacharacters inside a token (weight 1).

Free-text fields of an authenticated API or MCP call (a finding comment, a remediation note, an agent's summary or tool
output) are not scanned: they hold prose, backticked commands and tables by nature, are stored and shown as text, and never reach
a shell, a query or a template (see API_FREE_TEXT_FIELDS).

Every hit is rejected with 400 and stored as an AbuseStrike. Strikes from one user or one IP inside the window
add up; at the threshold (``CVENGINE_GUARD_STRIKES``, default 3, so one command-injection attempt is enough) the
signed-in session that sent the request is ended (the person signs in again) and a public IP is blocked for 24 hours
(``AbuseBan``). The guard never disables an account and never revokes an API token: a request can be forced on a
signed-in person by a link they click, so the most a payload may cost an account is one sign-in, and every action is
written to the audit log (``abuse.session_ended``, ``abuse.user_flagged``, ``abuse.ip_banned``) for an App Admin to judge.
Private and proxy addresses are never IP-banned (that would block a whole site), and superusers are only logged
(``abuse.superuser_flagged``). An App Admin lifts an address ban in Settings, IP allowlist and bans (or Django admin, AbuseBan.lifted).

The owner is never locked out silently: an address that in the last 24 hours was the source of a signed-in App Admin session or of a live Sentinel's
calls (``cvengine.guard_sources``) is not banned at the threshold. Its strikes are kept, the audit log says ``abuse.ban_withheld``, and an App Admin
alert names the address, the path and the reason. A 403 that refuses an address carries ``X-CVEngine-Refusal`` (``banned``, ``not_allowlisted``), so a
Sentinel can tell it from a refusal of its token.

Which hits count (review r3 S1). A browser labels every request with ``Sec-Fetch-Site``. ``cross-site`` and ``same-site``
come from another site's page; ``none`` is a navigation the person started outside any page (a link in a mail or chat
app, a bookmark, a typed address) and ``same-origin`` a link inside this site. A GET or HEAD with any of those labels is
a navigation a link can start, so it is rejected and stored (weight 0, for the record) but never counted. Counted are the
requests a link cannot force: a non-safe method (POST, PUT, PATCH, DELETE) that is not cross-site or same-site, and any
request without the header (scripts, scanners, API clients). A client can still send a header of its choice to stay
uncounted; its payload is refused all the same.
"""
import json
import logging
import os
import re
import time
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone
from cvengine import guard_sources
from cvengine.usage_stamps import durable_commit

logger = logging.getLogger(__name__)

WINDOW = timedelta(minutes=15)
IP_BAN = timedelta(hours=24)
MAX_BODY = 256 * 1024
MAX_STRINGS = 2000
MAX_STRING = 5000

_CMDS = (r'cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|python3?|perl|ruby|php|rm|chmod|chown|echo|'
         r'ping|nslookup|dig|sleep|powershell|cmd|certutil|busybox|telnet|ssh|scp|base64|env|printenv|touch|mkdir|'
         r'tee|eval|exec|nmap|masscan|sudo|su|kill|mv|cp|dd|tar|unzip|git|pip3?|npm|node')
SIGNATURES = [
    ('command_injection', 3, re.compile(r'(?:[;|&`]|\$\(|&&|\|\|)\s*(?:' + _CMDS + r')(?=\s|$|[;|&<>`)])', re.I)),
    ('command_substitution', 3, re.compile(r'`[^`\s][^`]{0,100}`|\$\([^)]{1,100}\)|\$\{[^}]{1,100}\}')),
    ('path_traversal', 3, re.compile(r'\.\.[/\\]|%2e%2e(?:%2f|/|%5c)|/etc/(?:passwd|shadow|hosts)\b|/proc/self|c:\\windows', re.I)),
    ('null_byte', 3, re.compile(r'\x00|%00')),
    ('sql_injection', 3, re.compile(
        r"\bunion\b\s+(?:all\s+)?select\b|\bselect\b.{0,40}\bfrom\b.{0,40}\b(?:information_schema|pg_catalog|pg_shadow)\b|"
        r";\s*(?:drop|truncate|alter)\s+\w|;\s*(?:delete\s+from|insert\s+into|update\s+\w+\s+set)\b|"
        r"\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bpg_sleep\s*\(|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|"
        r"'\s*(?:or|and)\s+'", re.I | re.S)),
    ('script_or_template_injection', 2, re.compile(
        r'<\s*script|javascript\s*:|\bon(?:error|load|click|mouseover)\s*=|'
        r'\{\{.{0,80}(?:__|config|self\b|request\b|cycler|lipsum).{0,80}\}\}|\{%\s*(?:import|include|extends|load)\b', re.I | re.S)),
]
CREDENTIAL_KEY = re.compile(r'pass|secret|token|key|otp|mfa|code|yaml|config|prompt', re.I)
STRICT_FIELDS = {'value', 'target', 'host', 'hostname', 'domain', 'project', 'slug', 'org', 'subdomain',
                 'target_id', 'scan_id', 'engine_id', 'match_id', 'org_id', 'project_id'}
BULK_FIELDS = {'text', 'targets', 'assets'}
STRICT_OK = re.compile(r'^[A-Za-z0-9._:/\[\] \-]*$')
# A target typed for Add targets may start with one '=' ("=example.com": exactly that host, agentapi.services.HOST_ONLY_MARK). That mark is
# allowed in front of the ``value`` field only; the rest of the value is held to STRICT_OK like any other strict field.
HOST_MARK_FIELDS = frozenset({'value'})
TOKEN_BAD = re.compile(r'[|&$`<>(){}\\]')
_MD_LINK = re.compile(r'\[[^\]]*\]\(([^)\s]*)\)')
EXEMPT_PATH = re.compile(r'^/(staticfiles|login|logout|mfa|admin)(/|$)')
# A bug bounty report is about attack strings: its steps, evidence and impact carry `<script>`, `' OR 1=1--`, `../../etc/passwd` and
# `curl ... | sh` by nature, and a hunter who saved such a report would be struck and, at the threshold, locked out. On the report and
# engagement endpoints only, these free-text fields are not scanned. They are stored as text, shown with textContent, exported as
# Markdown and sent as JSON; they never reach a shell, a query string or a template. Every other field there (host, project, value,
# ids) and every other endpoint keeps the full rules.
BOUNTY_TEXT_PATH = re.compile(r'^/cve/api/bounty/(reports|engagements)(/|$)')
# A host inventory report (agentapi.inventory) is machine-made data about a computer: its package and service names are whatever that
# software is called, and a host an attacker controls can name them anything, which must not get the reporter's owner locked out. Its
# body is not scanned here because it is not free text: cveFeed.inventory_schema allows one fixed shape and cleans every string, and
# nothing in it reaches a shell, a query or a template. Its address and query string are still checked.
INVENTORY_PATH = re.compile(r'^/api/v1/projects/[-\w]+/inventory/?$')
# What a Sentinel reports (the result of a scan-stage task, the partial batches of a streamed one, its heartbeat) is machine data about scanned hosts: a nuclei template's description,
# a TLS audit finding, a WordPress scan report excerpt or a banner is whatever that software or a hostile host says, and backticks, `${...}`, `<script>`
# and SQL fragments appear in it routinely. Counting it against the Sentinel's owner would disable an administrator's account and revoke
# its tokens for one template with a backtick in its description (and the result would be lost). Its body is not scanned here because it is
# not free text: ``agentapi.sentinel_broker.clean_result``, ``sentinel_stream.clean_partial`` and ``sentinel_settings.clean_info`` allow one fixed shape per kind, clip every
# string and cap every list, and nothing in it reaches a shell, a query or a template. Its address and query string are still checked, and
# so is every other Sentinel route (registration and bootstrap carry what a person typed).
SENTINEL_MACHINE_PATH = re.compile(r'^/api/v1/sentinel/(?:tasks/\d+/(?:result|partial)|heartbeat)/?$')
# The AI reviewer's verdicts and operations report are the same kind of machine data: a model's note about a finding quotes what the scanned
# host served (a script tag, an SQL fragment, a template expression) as a matter of course. cveFeed.reviewer accepts only enums and one note,
# which it strips of markup and links and stores as text; nothing in it reaches a shell, a query or a template. An answer to one of the
# pipeline's AI jobs (cveFeed.ai_jobs) is a model's reply about scanned hosts, a nuclei template among them: it is checked by the stage's own
# validator, stored as data and never reaches a shell, a query or a template either.
REVIEWER_MACHINE_PATH = re.compile(r'^/api/v1/reviewer/(?:findings/t\d{1,12}/(?:verdict|refusal)|ops/report|jobs/\d{1,12}/result)/?$')
BOUNTY_TEXT_FIELDS = frozenset({'title', 'summary', 'steps', 'impact', 'remediation', 'references', 'evidence', 'response', 'request', 'curl',
                                'note', 'notes', 'location_url', 'cwe', 'cvss_vector'})


# The same holds for the free-text fields of an authenticated agent call (REST /api/v1 and MCP /mcp): an agent's comment or tool
# output is ordinary prose with backticks, `; env` and markdown tables, and one such sentence used to be a command_injection strike
# that disabled the account. Only these field names are skipped; hosts, projects, values, ids and target lists keep the full rules.
# `text` is a comment on the comment endpoints only: on the bulk target endpoints it is a pasted target list.
API_PATH = re.compile(r'^/(api/v1|mcp)(/|$)')
API_FREE_TEXT_FIELDS = frozenset({'note', 'notes', 'comment', 'summary', 'output', 'message', 'reason', 'purpose'})
API_COMMENT_PATH = re.compile(r'^/api/v1/projects/[-\w]+/(?:findings/[a-z]+/\d+/comments|hosts/\d+/notes)/?$')
MCP_COMMENT_TOOLS = frozenset({'add_finding_comment', 'add_host_note'})


def _free_text_fields(request, data):
    """The field names left out of the inspection for this request: empty unless an authenticated agent call."""
    user = getattr(request, 'user', None)
    if not API_PATH.match(request.path) or user is None or not user.is_authenticated:
        return frozenset()
    comment = bool(API_COMMENT_PATH.match(request.path))
    if request.path.startswith('/mcp') and isinstance(data, dict):
        params = data.get('params')
        comment = isinstance(params, dict) and params.get('name') in MCP_COMMENT_TOOLS
    return API_FREE_TEXT_FIELDS | {'text', 'evidence'} if comment else API_FREE_TEXT_FIELDS


def _without_host_mark(name, text):
    """``text`` without the one leading '=' a host-only target carries, for the fields that take one (HOST_MARK_FIELDS)."""
    stripped = text.lstrip()
    return stripped[1:] if name in HOST_MARK_FIELDS and stripped.startswith('=') else text


def _authority(token):
    """The part of a pasted token that must be a hostname or address: for a URL, the host (not its path or query,
    which legitimately hold & ? = and so on); otherwise the token up to any slash."""
    rest = token.split('://', 1)[1] if '://' in token else token
    rest = re.split(r'[/?#]', rest, maxsplit=1)[0]
    return rest.rsplit('@', 1)[-1] if '@' in rest else rest


def _threshold():
    try:
        return max(1, int(os.environ.get('CVENGINE_GUARD_STRIKES', '3')))
    except ValueError:
        return 3


def _strings(node, key='', depth=0):
    """Yield (field, text) for every string value in a decoded JSON/form structure."""
    if depth > 6:
        return
    if isinstance(node, str):
        yield key, node[:MAX_STRING]
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _strings(v, str(k), depth + 1)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _strings(v, key, depth + 1)


def inspect(pairs):
    """Pure: [(field, text)] -> [(category, weight, field, sample)]. Credential-like fields are skipped."""
    hits = []
    for count, (field, text) in enumerate(pairs):
        if count >= MAX_STRINGS:
            break
        name = field.rsplit('.', 1)[-1].lower()
        if CREDENTIAL_KEY.search(name) and name not in STRICT_FIELDS | BULK_FIELDS:
            continue
        if name in BULK_FIELDS:  # "# comments" in a pasted list are not input
            text = '\n'.join(line.split('#', 1)[0] for line in text.splitlines())
        for category, weight, pattern in SIGNATURES:
            m = pattern.search(text)
            if m:
                hits.append((category, weight, name, text[max(0, m.start() - 20):m.end() + 20]))
                break
        else:
            if name in STRICT_FIELDS and not STRICT_OK.match(_without_host_mark(name, text)):
                hits.append(('strict_field', 1, name, text))
            elif name in BULK_FIELDS:
                for line in text.splitlines():
                    if line.lstrip().startswith('#'):
                        continue
                    line = _MD_LINK.sub(r'\1', line.split('#', 1)[0])  # pasted [text](url) is fine
                    bad = next((t for t in re.split(r'[,\s;]+', line) if TOKEN_BAD.search(_authority(t))), None)
                    if bad:
                        hits.append(('strict_field', 1, name, bad))
                        break
    return hits


def _request_pairs(request):
    pairs = [(k, v) for k in request.GET for v in request.GET.getlist(k)]
    ctype = (request.META.get('CONTENT_TYPE') or '').split(';')[0].strip().lower()
    try:
        length = int(request.META.get('CONTENT_LENGTH') or 0)
    except ValueError:
        length = 0
    data = None
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and 0 < length <= MAX_BODY and not INVENTORY_PATH.match(request.path) \
            and not SENTINEL_MACHINE_PATH.match(request.path) and not REVIEWER_MACHINE_PATH.match(request.path):
        if ctype == 'application/json':
            try:
                data = json.loads(request.body.decode('utf-8', 'replace'))
                pairs.extend(_strings(data))
            except ValueError:
                pass
        elif ctype == 'application/x-www-form-urlencoded':
            pairs.extend((k, v) for k in request.POST for v in request.POST.getlist(k))
    if BOUNTY_TEXT_PATH.match(request.path):
        pairs = [(k, v) for k, v in pairs if k.rsplit('.', 1)[-1].lower() not in BOUNTY_TEXT_FIELDS]
    free = _free_text_fields(request, data)
    if free:
        pairs = [(k, v) for k, v in pairs if k.rsplit('.', 1)[-1].lower() not in free]
    return pairs


# --- bans -------------------------------------------------------------------------------------------------

_ban_cache = {'at': 0.0, 'ips': frozenset()}


def banned_ips():
    now = time.time()
    if now - _ban_cache['at'] < 10:
        return _ban_cache['ips']
    from dashboard.models import AbuseBan
    from django.db.models import Q
    ips = frozenset(AbuseBan.objects.filter(lifted=False).exclude(ip='')
                    .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())).values_list('ip', flat=True))
    _ban_cache.update(at=now, ips=ips)
    return ips


def is_banned(ip):
    try:
        return bool(ip) and ip in banned_ips()
    except Exception:  # noqa: BLE001 - a database hiccup must not lock everyone out
        logger.exception('ban lookup failed')
        return False


def invalidate_cache():
    _ban_cache['at'] = 0.0


def _ip_is_banable(ip):
    from cvengine.client_ip import _in, _parse, trusted_proxies
    parsed = _parse(ip)
    if parsed is None or parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return False
    return not _in(parsed, trusted_proxies())


def _stored(text, limit):
    """Attacker-supplied text as it is kept: truncated, and without NUL bytes, which Postgres refuses in text. A strike for a NUL byte
    carries one in its sample, so without this the insert failed and the very request that earned a strike never counted."""
    return str(text).replace('\x00', '')[:limit]


def _audit(user, action, target, **detail):
    from dashboard.models import AuditLog
    AuditLog.objects.create(actor=user, actor_name=getattr(user, 'username', '') or 'anonymous', action=action,
                            target=_stored(target, 300), detail={k: _stored(v, 600) if isinstance(v, str) else v for k, v in detail.items()})


# Safe methods a link or a navigation can produce. Stored as weight 0 when the browser says it was such a navigation (see _counted).
NAVIGATION_METHODS = frozenset({'GET', 'HEAD'})
NAVIGATION_SITES = frozenset({'none', 'same-origin'})
FOREIGN_SITES = frozenset({'cross-site', 'same-site'})


def _counted(request):
    """True when the hits of this request may add up to a ban: a request a link or another site cannot make for the person (module docstring)."""
    site = request.META.get('HTTP_SEC_FETCH_SITE', '').strip().lower()
    if site in FOREIGN_SITES:
        return False
    return not (request.method in NAVIGATION_METHODS and site in NAVIGATION_SITES)


def _end_session(request, user):
    """Ends the signed-in browser session that sent the request; True if there was one. A bearer token is never touched."""
    if getattr(request, 'api_token', None) is not None or not hasattr(request, 'session'):
        return False
    if getattr(request, 'user', None) is None or getattr(request.user, 'pk', None) != user.pk:
        return False
    from django.contrib.auth import logout
    logout(request)
    return True


def record_and_maybe_ban(request, hits, ip, user, counted=True):
    """Store the strikes; act if the user's or the IP's recent total reaches the threshold. Returns True if it acted (a session ended
    or an address banned). ``counted=False`` stores them with weight 0: kept for the record, never part of a total.

    The account is never disabled and no token is revoked (review r3 S1): a user at the threshold loses the browser session that sent the
    request and is written to the audit log, and a public address at the threshold is banned for IP_BAN."""
    from django.db.models import Sum

    from dashboard.models import AbuseBan, AbuseStrike
    for category, weight, field, sample in hits[:5]:
        AbuseStrike.objects.create(user=user, username=getattr(user, 'username', '') if user else '', ip=ip, weight=weight if counted else 0,
                                   category=category, field=_stored(field, 80), sample=_stored(sample, 200), path=_stored(request.path, 200))
    if not counted:
        return False
    since = timezone.now() - WINDOW
    # Two separate tallies: a person's account answers for that person's strikes only, and an address for what came from it.
    # Summing both let one user's strikes (or a neighbour behind the same NAT) act on an account that had one point.
    recent = AbuseStrike.objects.filter(created_at__gte=since)
    user_total = (recent.filter(user=user).aggregate(t=Sum('weight'))['t'] or 0) if user else 0
    ip_total = (recent.filter(ip=ip).aggregate(t=Sum('weight'))['t'] or 0) if ip else 0
    user_over = bool(user) and user_total >= _threshold()
    ban_ip = bool(ip) and ip_total >= _threshold()
    if not (user_over or ban_ip):
        return False
    total = user_total if user_over else ip_total
    reason = _stored(f'{hits[0][0]} in "{hits[0][2]}" ({total} strike points in {int(WINDOW.total_seconds() // 60)} min)', 300)
    if user and user.is_superuser:
        if user_over:
            _audit(user, 'abuse.superuser_flagged', user.username, reason=reason, ip=ip)
        return False
    ended = banned = False
    if user_over:
        ended = _end_session(request, user)
        _audit(user, 'abuse.session_ended' if ended else 'abuse.user_flagged', user.username, reason=reason, ip=ip)
    if ban_ip and _ip_is_banable(ip) and not AbuseBan.objects.filter(ip=ip, lifted=False, expires_at__gt=timezone.now()).exists():
        sources = guard_sources.protected(ip)
        if sources:  # the owner's own address or a live Sentinel's: never banned silently, an App Admin is told instead
            withhold_ban(ip, request.path, reason, sources, user)
            logger.warning('input guard: ban of %s withheld (%s): %s', ip, ', '.join(guard_sources.KINDS[k] for k, _ in sources), reason)
            return ended
        with durable_commit():  # a ban a crash could undo would let the address straight back in
            AbuseBan.objects.create(ip=ip, username=getattr(user, 'username', '') if user else '', reason=reason,
                                    expires_at=timezone.now() + IP_BAN)
        _audit(user, 'abuse.ip_banned', ip, reason=reason)
        invalidate_cache()
        banned = True
    logger.warning('input guard: user=%s ip=%s session ended=%s address banned=%s: %s', getattr(user, 'username', None), ip, ended, banned, reason)
    return ended or banned


REFUSAL_HEADER = 'X-CVEngine-Refusal'  # on every 403 that refuses an ADDRESS (a ban, the IP allowlist), never on a refusal of a token or a right
ALERT_CODE = 'ban_withheld'
ALERT_REFRESH = 60  # seconds: the alert of one address is written again at most this often (a scan sends many requests)


def refused(response, why='banned'):
    """``response`` marked as a refusal of the client's address (``banned`` or ``not_allowlisted``): a Sentinel then knows its token is fine and backs
    off instead of asking its operator to re-enroll it."""
    response[REFUSAL_HEADER] = why
    return response


def withhold_ban(ip, path, reason, sources, user=None):
    """The guard would ban ``ip``, but it is the owner's own address or a live Sentinel's (``guard_sources``): keep the strikes (already stored), write
    the audit row and open or refresh one App Admin alert per address (the status strip and the alerts list show it) naming the address, the path and
    the reason. Never raises."""
    try:
        from django.core.cache import cache
        if not cache.add(f'ban-withheld:{ip}', 1, ALERT_REFRESH):
            return None
    except Exception:  # noqa: BLE001 - no cache: write it every time rather than never
        pass
    who = '; '.join(f'{guard_sources.KINDS[k]}{f" ({n})" if n else ""}' for k, n in sources)
    try:
        _audit(user, 'abuse.ban_withheld', ip, reason=reason, path=_stored(path, 200), protected=who)
    except Exception:  # noqa: BLE001
        logger.warning('input guard: could not write the audit row of a withheld ban', exc_info=True)
    try:
        import hashlib
        from cveFeed import reviewer
        from cveFeed.models import AdminAlert
        now = timezone.now()
        code = f'{ALERT_CODE}_{hashlib.sha1(ip.encode()).hexdigest()[:12]}'  # one open alert per address
        title = _stored(f'Requests from {ip} would have been banned, but it is {who}', 200)
        detail = (f'The input guard counted enough strike points against {ip} to ban it for {int(IP_BAN.total_seconds() // 3600)} hours, but in the last 24 hours '
                  f'that address was used by {who}. A ban would lock you or that Sentinel out, so it was not banned; the strikes are kept (Django admin, Abuse '
                  f'strikes).\nLast path: {_stored(path, 200)}\nReason: {reason}\nIf the requests are a Sentinel scanning this server, check the target '
                  f'scope; if they are not yours, add a ban by hand in Django admin.')
        facts = {'ip': ip, 'path': _stored(path, 200), 'reason': reason, 'protected': [k for k, _ in sources]}
        digest = hashlib.sha1(f'{code}|{ip}'.encode()).hexdigest()[:20]
        alert = AdminAlert.objects.filter(code=code, resolved_at__isnull=True).first()
        if alert is None:
            return AdminAlert.objects.create(code=code, severity='warning', title=title, detail=detail, facts=facts, digest=digest, first_seen=now, last_seen=now,
                                             **reviewer.carried_dismissal(code, digest, 'warning', now))
        alert.title, alert.detail, alert.facts, alert.last_seen = title, detail, facts, now
        alert.save(update_fields=['title', 'detail', 'facts', 'last_seen'])
        return alert
    except Exception:  # noqa: BLE001
        logger.warning('input guard: could not raise the alert of a withheld ban', exc_info=True)
        return None


def _oversize_api_json(request):
    """True for a JSON body over ``MAX_BODY`` sent to the REST API or the MCP endpoint (not the machine routes, which carry their own bounds). The guard
    inspects nothing above ``MAX_BODY``, so a body that large would otherwise reach the handlers uninspected (review 2 F6): it is refused instead."""
    if request.method not in ('POST', 'PUT', 'PATCH') or not API_PATH.match(request.path):
        return False
    if INVENTORY_PATH.match(request.path) or SENTINEL_MACHINE_PATH.match(request.path) or REVIEWER_MACHINE_PATH.match(request.path):
        return False
    if (request.META.get('CONTENT_TYPE') or '').split(';')[0].strip().lower() != 'application/json':
        return False
    try:
        return int(request.META.get('CONTENT_LENGTH') or 0) > MAX_BODY
    except ValueError:
        return False


class InputGuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        guard_sources.note_request(request)  # the owner's and the live Sentinels' addresses are never banned silently (record_and_maybe_ban)
        if EXEMPT_PATH.match(request.path):
            return self.get_response(request)
        if _oversize_api_json(request):
            return JsonResponse({'error': f'the request body is larger than {MAX_BODY // 1024} KiB'}, status=413)
        try:
            hits = inspect(_request_pairs(request))
        except Exception:  # noqa: BLE001 - never take the app down because inspection failed
            logger.exception('input guard failed to inspect a request')
            hits = []
        if not hits:
            return self.get_response(request)
        # A page on another site can make a victim's browser send these requests (an image tag, an auto-submitted
        # form). Browsers label those cross-site/same-site; reject them but never record them against the victim.
        if request.META.get('HTTP_SEC_FETCH_SITE', '').strip().lower() in FOREIGN_SITES:
            return JsonResponse({'error': 'Request rejected.'}, status=400)
        from cvengine.client_ip import client_ip
        user = getattr(request, 'user', None)
        user = user if user is not None and user.is_authenticated else None
        banned = False
        try:
            banned = record_and_maybe_ban(request, hits, client_ip(request), user, counted=_counted(request))
        except Exception:  # noqa: BLE001
            logger.exception('input guard could not record a strike')
        if banned:
            return refused(JsonResponse({'error': 'This session or address has been blocked for sending malicious input.'}, status=403))
        return JsonResponse({'error': 'Request rejected: it contains characters or patterns that are not valid input.'}, status=400)
