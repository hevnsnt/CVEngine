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

Every hit is rejected with 400 and stored as an AbuseStrike. Strikes from one user or one IP inside the window
add up; at the threshold (``CVENGINE_GUARD_STRIKES``, default 3, so one command-injection attempt is enough) the
account is disabled, its API tokens are revoked, and a public IP is blocked for 24 hours (``AbuseBan``). Private
and proxy addresses are never IP-banned (that would block a whole site), and superusers are only logged. An admin
lifts a ban in Django admin (AbuseBan.lifted) and re-enables the user.
"""
import ipaddress
import json
import logging
import os
import re
import time
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone

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
BOUNTY_TEXT_FIELDS = frozenset({'title', 'summary', 'steps', 'impact', 'remediation', 'references', 'evidence', 'response', 'request', 'curl',
                                'note', 'notes', 'location_url', 'cwe', 'cvss_vector'})


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
            if name in STRICT_FIELDS and not STRICT_OK.match(text):
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
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and 0 < length <= MAX_BODY and not INVENTORY_PATH.match(request.path):
        if ctype == 'application/json':
            try:
                pairs.extend(_strings(json.loads(request.body.decode('utf-8', 'replace'))))
            except ValueError:
                pass
        elif ctype == 'application/x-www-form-urlencoded':
            pairs.extend((k, v) for k in request.POST for v in request.POST.getlist(k))
    if BOUNTY_TEXT_PATH.match(request.path):
        pairs = [(k, v) for k, v in pairs if k.rsplit('.', 1)[-1].lower() not in BOUNTY_TEXT_FIELDS]
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
    from reNgine.client_ip import _in, _parse, trusted_proxies
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


def record_and_maybe_ban(request, hits, ip, user):
    """Store the strikes; ban if the user's or the IP's recent total reaches the threshold. Returns True if banned."""
    from django.db.models import Q, Sum

    from dashboard.models import AbuseBan, AbuseStrike
    for category, weight, field, sample in hits[:5]:
        AbuseStrike.objects.create(user=user, username=getattr(user, 'username', '') if user else '', ip=ip, weight=weight,
                                   category=category, field=_stored(field, 80), sample=_stored(sample, 200), path=_stored(request.path, 200))
    since = timezone.now() - WINDOW
    who = Q(ip=ip) if ip else Q(pk__in=[])
    if user:
        who |= Q(user=user)
    total = AbuseStrike.objects.filter(who, created_at__gte=since).aggregate(t=Sum('weight'))['t'] or 0
    if total < _threshold():
        return False
    reason = _stored(f'{hits[0][0]} in "{hits[0][2]}" ({total} strike points in {int(WINDOW.total_seconds() // 60)} min)', 300)
    if user and user.is_superuser:
        _audit(user, 'abuse.superuser_flagged', user.username, reason=reason, ip=ip)
        return False
    if user:
        from dashboard.models import ApiToken
        user.is_active = False
        user.save(update_fields=['is_active'])
        ApiToken.objects.filter(user=user, revoked=False).update(revoked=True)
        AbuseBan.objects.create(user=user, username=user.username, ip='', reason=reason)
        _audit(user, 'abuse.account_disabled', user.username, reason=reason, ip=ip)
    if ip and _ip_is_banable(ip) and not AbuseBan.objects.filter(ip=ip, lifted=False, expires_at__gt=timezone.now()).exists():
        AbuseBan.objects.create(ip=ip, username=getattr(user, 'username', '') if user else '', reason=reason,
                                expires_at=timezone.now() + IP_BAN)
        _audit(user, 'abuse.ip_banned', ip, reason=reason)
        invalidate_cache()
    logger.warning('input guard banned user=%s ip=%s: %s', getattr(user, 'username', None), ip, reason)
    return True


class InputGuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if EXEMPT_PATH.match(request.path):
            return self.get_response(request)
        try:
            hits = inspect(_request_pairs(request))
        except Exception:  # noqa: BLE001 - never take the app down because inspection failed
            logger.exception('input guard failed to inspect a request')
            hits = []
        if not hits:
            return self.get_response(request)
        # A page on another site can make a victim's browser send these requests (an image tag, an auto-submitted
        # form). Browsers label those cross-site/same-site; reject them but never count them against the victim.
        if request.META.get('HTTP_SEC_FETCH_SITE', '').lower() in ('cross-site', 'same-site'):
            return JsonResponse({'error': 'Request rejected.'}, status=400)
        from reNgine.client_ip import client_ip
        user = getattr(request, 'user', None)
        user = user if user is not None and user.is_authenticated else None
        banned = False
        try:
            banned = record_and_maybe_ban(request, hits, client_ip(request), user)
        except Exception:  # noqa: BLE001
            logger.exception('input guard could not record a strike')
        if banned:
            return JsonResponse({'error': 'This account or address has been blocked for sending malicious input.'}, status=403)
        return JsonResponse({'error': 'Request rejected: it contains characters or patterns that are not valid input.'}, status=400)
