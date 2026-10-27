"""Authenticated checks: request headers and a cookie the owner supplies for a target they may test, sent by Nuclei and the web route
check so the scanners see the signed-in application and not only its login page.

What is stored (``cveFeed.models.AuthCredential``): a label, header name/value pairs, an optional cookie string, the ``scheme:port``
origins it may be sent to, and an expiry (30, 90 or 120 days, or an explicit never), for one host of a target or for every host of that target. The values are
encrypted at rest (``reNgine.crypto_fields``, so ``rotate_field_key`` re-encrypts them with every other secret) and are write-only:
no read returns one, only the header names.

The scope guard is ``AuthScope.credential``: a credential goes to a request only when its destination host is exactly the host it
was stored for (or, for a target-wide one, the target's own name or one of its subdomains), the destination ``scheme:port`` is one of
its origins, and it has not expired. Callers run the normal vetting first (``pinned_transport.resolve``,
``target_types.scannable_hosts``, exclusions); this module never widens what those allow.

``redact_text`` and ``redact_obj`` remove every secret value (and the usual encodings of it) from anything that is about to be stored
or shown: scanner request and response dumps, evidence, error messages. Nothing in this module logs a value.
"""
import base64
import contextlib
import datetime
import ipaddress
import json
import math
import os
import re
import shutil
import tempfile
from urllib.parse import quote, quote_plus

from django.utils import timezone

SEEN_TAG = 'seen-while-authenticated'  # the tag a finding carries when an authenticated request saw it
SEEN_LABEL = 'seen while authenticated'
MAX_HEADERS = 10
MAX_HEADER_VALUE = 2000
MAX_COOKIE = 4000
MAX_LABEL = 80
MIN_SECRET_LENGTH = 6  # a shorter value could not be told apart from ordinary text when it is redacted from stored evidence
DEFAULT_ORIGINS = ('https:443',)
EXPIRY_DAYS = (30, 90, 120)
EXPIRY_HELP = 'expires is required and must be 30, 90 or 120 (days from now) or "never"'
SCOPES = ('host', 'target')
SCOPE_HELP = 'scope is required and must be "host" (with host: one host of the target) or "target" (every host of the target)'
REDACTED = '[redacted]'
HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
COOKIE_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$")
# Headers that frame the request or name its destination: sending a stored value for one of them could not be a sign-in.
FORBIDDEN_HEADERS = frozenset({'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer', 'expect',
                               'proxy-authorization', 'proxy-connection', 'keep-alive', 'accept-encoding', 'range', 'content-type'})
WARNING = ('Use a dedicated low-privilege test account for this, not a real person\'s session. The values expire when the session '
           'does, so choose an expiry (30, 90 or 120 days, or never on purpose) and replace them. Scans only send read-only requests (the Nuclei template read-only policy still '
           'applies), but an application can still change state on a GET, so keep the account\'s data disposable.')


class CredentialError(ValueError):
    """A rejected value, worded for the person who typed it. Never contains a header or cookie value."""


# ----------------------------------------------------------------------------- validation

def normalize_host(value):
    """The lowercase host name or IP address a credential is stored for, or ``''`` when blank. A scheme, port, path or
    wildcard is refused: the scheme and port are the origins, and a host is never a pattern."""
    from targetApp.target_types import DOMAIN, IP, classify_target
    text = str(value or '').strip().lower().rstrip('.')
    if not text:
        return ''
    bare = text[1:-1] if text.startswith('[') and text.endswith(']') else text
    kind = classify_target(bare)
    if kind not in (DOMAIN, IP) or '*' in bare:
        raise CredentialError('host must be a plain host name or IP address (no scheme, port, path or wildcard); leave it blank only with scope "target"')
    return str(ipaddress.ip_address(bare)) if kind == IP else bare


def host_in_target(host, domain):
    """Whether ``host`` belongs to ``domain`` (a target): its own name, or a subdomain of it unless the target is host-only
    (a tenant of a provider's shared domain, see ``Domain.is_host_scoped``)."""
    from targetApp.target_types import DOMAIN, classify_target
    name = (domain.name or '').strip().lower().rstrip('.')
    host = (host or '').strip().lower().rstrip('.')
    if not host or not name:
        return False
    if host == name:
        return True
    return (classify_target(name) == DOMAIN and not domain.is_host_scoped() and host.endswith('.' + name))


def clean_origins(raw):
    """``['https:443', ...]`` from a list of ``scheme:port`` strings; default HTTPS on 443. Plain ``http`` is accepted only when it is named."""
    if raw is None or raw == []:
        return list(DEFAULT_ORIGINS)
    if not isinstance(raw, (list, tuple)) or len(raw) > 8:
        raise CredentialError('origins must be a list of at most 8 entries like "https:443"')
    out = []
    for item in raw:
        match = re.fullmatch(r'(https?):(\d{1,5})', str(item or '').strip().lower())
        if not match or not 0 < int(match.group(2)) < 65536:
            raise CredentialError('each origin must look like "https:443" or "http:8080" (scheme, colon, port)')
        origin = f'{match.group(1)}:{int(match.group(2))}'
        if origin not in out:
            out.append(origin)
    return out


def _no_control(text, what):
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise CredentialError(f'{what} must be one line without control characters')


def clean_headers(raw, existing=()):
    """``[[name, value], ...]`` from a list of ``{name, secret}`` objects (the field is called ``secret`` so the request-inspection guard, which
    skips credential-like fields, never reads or stores a sample of a value). A blank value for a name already stored keeps the stored value
    (``existing`` is that stored list), so one header can be changed without typing the others again; a blank value for a new name is an
    error. Names are case-insensitively unique, values are one line of at most MAX_HEADER_VALUE characters and at least MIN_SECRET_LENGTH."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        raw = [{'name': k, 'secret': v} for k, v in raw.items()]
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_HEADERS:
        raise CredentialError(f'headers must be a list of at most {MAX_HEADERS} {{name, secret}} entries')
    stored = {str(n).lower(): (str(n), v) for n, v in existing}
    out, seen = [], set()
    for item in raw:
        if not isinstance(item, dict):
            raise CredentialError('each header must be an object with a name and a secret (its value)')
        name, value = str(item.get('name') or '').strip(), item.get('secret')
        if not HEADER_NAME.match(name):
            raise CredentialError('a header name may use letters, digits and - _ . only, up to 64 characters')
        low = name.lower()
        if low == 'cookie':
            raise CredentialError('send cookies in the cookie field, not as a header')
        if low in FORBIDDEN_HEADERS:
            raise CredentialError(f'the {name} header frames the request and cannot be set here')
        if low in seen:
            raise CredentialError(f'the {name} header is listed twice')
        seen.add(low)
        if value is None or str(value) == '':
            if low not in stored:
                raise CredentialError(f'the {name} header needs a value')
            out.append(list(stored[low]))
            continue
        value = str(value).strip()
        _no_control(value, f'the {name} value')
        if not MIN_SECRET_LENGTH <= len(value) <= MAX_HEADER_VALUE:
            raise CredentialError(f'the {name} value must be {MIN_SECRET_LENGTH} to {MAX_HEADER_VALUE} characters (a shorter one cannot be kept out of stored evidence)')
        out.append([name, value])
    return out


def parse_cookie(text):
    """``[(name, value), ...]`` from a ``a=b; c=d`` cookie string; an entry without ``=`` is an error."""
    pairs = []
    for part in text.split(';'):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition('=')
        if not sep or not COOKIE_NAME.match(name.strip()):
            raise CredentialError('the cookie must look like name=value; name2=value2')
        pairs.append((name.strip(), value.strip()))
    return pairs


def clean_cookie(raw):
    """The cookie string to store, '' for none, or None when ``raw`` is None (keep what is stored)."""
    if raw is None:
        return None
    text = str(raw).strip()
    if text.lower().startswith('cookie:'):
        text = text[7:].strip()
    if not text:
        return ''
    _no_control(text, 'the cookie')
    if not MIN_SECRET_LENGTH <= len(text) <= MAX_COOKIE:
        raise CredentialError(f'the cookie must be {MIN_SECRET_LENGTH} to {MAX_COOKIE} characters')
    if not parse_cookie(text):
        raise CredentialError('the cookie must look like name=value; name2=value2')
    return text


def compute_expiry(raw, now=None):
    """The stored ``expires_at`` for an expiry choice: 30, 90 or 120 (days from now, as a number or a digit string) or ``never`` (None,
    the only case that stores no expiry). Always a deliberate choice: a missing or blank value is refused, never defaulted."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise CredentialError(EXPIRY_HELP)
    if isinstance(raw, bool):
        raise CredentialError(EXPIRY_HELP)
    text = str(raw).strip().lower()
    if text == 'never':
        return None
    if text.isdigit() and int(text) in EXPIRY_DAYS:
        return (now or timezone.now()) + datetime.timedelta(days=int(text))
    raise CredentialError(EXPIRY_HELP)


def clean_scope(scope, host, domain):
    """The host a credential is stored for (``''`` for every host of the target) from an explicit ``scope``: ``host`` (needs ``host``, one host
    of the target) or ``target`` (every host of the target; ``host`` must be blank). A missing scope is refused, so a blank host never
    silently widens a credential to the whole target."""
    kind = str(scope).strip().lower() if isinstance(scope, str) else ''
    if kind not in SCOPES:
        raise CredentialError(SCOPE_HELP)
    host = normalize_host(host)
    if kind == 'target':
        if host:
            raise CredentialError('scope "target" sends the credential to every host of the target, so leave host blank; use scope "host" for one host')
        return ''
    if not host:
        raise CredentialError('scope "host" needs a host: the one host of the target the credential is for')
    if not host_in_target(host, domain):
        raise CredentialError(f'{host} is not part of the target {domain.name}')
    return host


# ----------------------------------------------------------------------------- reading a stored credential

def stored_headers(cred):
    """``[(name, value), ...]`` as stored. Values: keep inside this module and the scanners' own channels; never return one."""
    return [(str(n), str(v)) for n, v in (cred.secret or {}).get('headers', [])]


def stored_cookie(cred):
    return str((cred.secret or {}).get('cookie') or '')


def header_names(cred):
    return [n for n, _ in stored_headers(cred)]


def cookie_names(cred):
    try:
        return [n for n, _ in parse_cookie(stored_cookie(cred))]
    except CredentialError:
        return []


def is_expired(cred, now=None):
    return cred.expires_at is not None and cred.expires_at <= (now or timezone.now())


def summary(cred, now=None):
    """The masked view of a credential: header and cookie NAMES, never a value. Every read goes through here."""
    expired = is_expired(cred, now)
    days_left = None
    if cred.expires_at is not None:
        days_left = 0 if expired else max(0, math.ceil((cred.expires_at - (now or timezone.now())).total_seconds() / 86400))
    return {'id': cred.id, 'target_id': cred.domain_id, 'target': cred.domain.name, 'host': cred.host or None,
            'scope': 'host' if cred.host else 'target', 'label': cred.label, 'origins': list(cred.origins or []),
            'header_names': header_names(cred), 'cookie_names': cookie_names(cred),
            'expires_at': cred.expires_at.isoformat() if cred.expires_at else None, 'never_expires': cred.expires_at is None,
            'days_left': days_left,
            'state': 'expired' if expired else 'active', 'expired': expired,
            'updated_at': cred.updated_at.isoformat() if cred.updated_at else None,
            'updated_by': cred.updated_by.username if cred.updated_by_id else None,
            'last_used_at': cred.last_used_at.isoformat() if cred.last_used_at else None}


def request_headers(cred):
    """``[(name, value), ...]`` to put on a request, the cookie last as a ``Cookie`` header."""
    out = stored_headers(cred)
    cookie = stored_cookie(cred)
    if cookie:
        out.append(('Cookie', cookie))
    return out


# ----------------------------------------------------------------------------- the scope guard

def origin_of(scheme, port):
    return f'{str(scheme).lower()}:{int(port)}'


class AuthScope:
    """The credentials of one target, and the rule for when one may be sent. Build it with ``for_domain``; ask ``credential(host, scheme,
    port)`` for the credential that applies to a destination (None when none does) or ``headers_for`` for what to put on the request."""

    def __init__(self, creds, now=None):
        self.now = now
        self.creds = [c for c in creds]
        self.used = {}

    @classmethod
    def for_domain(cls, domain, now=None):
        from cveFeed.models import AuthCredential
        return cls(AuthCredential.objects.filter(domain=domain).select_related('domain'), now)

    def __bool__(self):
        return bool(self.creds)

    def secret_values(self):
        """Every value this scope holds, expired or not, for redaction."""
        return secret_values(self.creds)

    def credential(self, host, scheme, port):
        """The credential allowed to go to ``scheme://host:port``: not expired, destination host exactly the stored host (or, for a
        target-wide credential, the target's name or one of its subdomains), ``scheme:port`` among its origins. A host-specific one
        wins over a target-wide one; two are never merged."""
        host = str(host or '').strip().lower().rstrip('.')
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        if not host or str(scheme).lower() not in ('http', 'https'):
            return None
        try:
            origin = origin_of(scheme, port)
        except (TypeError, ValueError):
            return None
        now = self.now or timezone.now()
        best = None
        for cred in self.creds:
            if is_expired(cred, now) or origin not in (cred.origins or []):
                continue
            if cred.host:
                if cred.host == host:
                    return cred
            elif best is None and host_in_target(host, cred.domain):
                best = cred
        return best

    def headers_for(self, host, scheme, port):
        """``[(name, value), ...]`` for a request to ``scheme://host:port``, ``[]`` when no credential applies."""
        cred = self.credential(host, scheme, port)
        if cred is None:
            return []
        self.used[cred.pk] = cred
        return request_headers(cred)

    def mark_used(self):
        """Stamp ``last_used_at`` on every credential this scope sent (once per scan stage, not per request)."""
        if self.used:
            from cveFeed.models import AuthCredential
            AuthCredential.objects.filter(pk__in=list(self.used)).update(last_used_at=timezone.now())
            self.used = {}


def note_expired(scope, domain, project, scan):
    """One activity line per scan and credential when a stored sign-in has expired and so was not sent."""
    from django.core.cache import cache
    from cveFeed import activity
    now = timezone.now()
    for cred in scope.creds:
        if is_expired(cred, now):
            try:
                fresh = cache.add(f'cvengine:authcheck-expired:{revision(cred)}:{scan.id}', 1, timeout=3600)
            except Exception:  # noqa: BLE001 - without the cache the line may repeat
                fresh = True
            if fresh:
                activity.log('run_check', f'The stored sign-in for {cred.host or domain.name} expired and was not sent; signed-in checks '
                             f'were skipped for it', project=project, scan_id=scan.id, status='failed')


# ----------------------------------------------------------------------------- redaction

def secret_values(creds):
    """The strings to keep out of anything stored or shown: every header value, the part of one after its scheme word ("Bearer abc"
    gives "abc", since a page may echo only the token), the whole cookie string and each cookie value, and the usual encodings of
    each (URL-quoted, form-quoted, JSON-escaped, base64). Longest first, so a whole value goes before the part of it."""
    found = set()

    def add(value):
        value = str(value or '')
        if len(value) < MIN_SECRET_LENGTH:
            return
        found.add(value)
        for variant in (quote(value, safe=''), quote_plus(value), json.dumps(value)[1:-1],
                        base64.b64encode(value.encode('utf-8', 'replace')).decode().rstrip('=')):
            if len(variant) >= MIN_SECRET_LENGTH:
                found.add(variant)
    for cred in creds:
        for _name, value in stored_headers(cred):
            add(value)
            head, sep, tail = value.partition(' ')
            if sep and tail.strip():
                add(tail.strip())
        cookie = stored_cookie(cred)
        if cookie:
            add(cookie)
            try:
                for _name, value in parse_cookie(cookie):
                    add(value)
            except CredentialError:
                pass
    return sorted(found, key=len, reverse=True)


def redact_text(text, values):
    """``text`` with every secret in ``values`` replaced by ``[redacted]``."""
    if not isinstance(text, str) or not values:
        return text
    for value in values:
        if value in text:
            text = text.replace(value, REDACTED)
    return text


def redact_obj(obj, values):
    """``obj`` (nested dicts, lists and strings, such as a nuclei result line) with every secret value redacted, keys included."""
    if not values:
        return obj
    if isinstance(obj, str):
        return redact_text(obj, values)
    if isinstance(obj, list):
        return [redact_obj(item, values) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(item, values) for item in obj)
    if isinstance(obj, dict):
        return {redact_text(k, values) if isinstance(k, str) else k: redact_obj(v, values) for k, v in obj.items()}
    return obj


def safe_error(exc, values):
    """An exception as a short, redacted line for an activity row or a log: the type and the redacted message, never a secret."""
    return redact_text(f'{type(exc).__name__}: {exc}'.strip(), values)[:300]


# ----------------------------------------------------------------------------- the nuclei secrets file

def target_parts(target):
    """``(host, port or None)`` of a nuclei target string (``host`` or ``host:port``); a URL, a path or anything odd gives ``(None, None)``."""
    text = str(target or '').strip().lower()
    if not text or '/' in text or '@' in text or any(c.isspace() for c in text):
        return None, None
    if text.startswith('['):
        host, _, rest = text[1:].partition(']')
        if rest and not rest.startswith(':'):
            return None, None
        port = rest[1:] if rest else ''
    elif text.count(':') == 1:
        host, _, port = text.partition(':')
    else:
        host, port = text, ''
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        return None, None
    return host, (int(port) if port else None)


def _url(host, scheme, port):
    name = f'[{host}]' if ':' in host else host
    default = 443 if scheme == 'https' else 80
    return f'{scheme}://{name}' + ('' if port == default else f':{port}')


def _domain_key(host, port):
    """How nuclei's secrets file names a destination: the host, with the port only when it is not 80 or 443 (nuclei does not tell those two
    apart, which is why a destination that would need two different credentials is refused below)."""
    name = f'[{host}]' if ':' in host else host
    return name if port in (80, 443) else f'{name}:{port}'


def plan_nuclei(scope, targets):
    """The signed-in nuclei targets for the nuclei ``targets`` (``host`` or ``host:port`` strings) of a scan: ``[(url, credential, domain)]``.
    Each ``url`` is an explicit ``scheme://host[:port]`` for one origin a credential covers (a bare host stands for the default ports,
    ``host:port`` for that port), so nuclei is never left to pick a scheme the credential was not stored for; ``domain`` is how nuclei's
    secrets file names that destination. A target with no applicable credential contributes nothing. When two credentials would apply to the
    same secrets-file domain (nuclei cannot tell http://host from https://host) only the first, the HTTPS one, is kept."""
    items, owner = [], {}
    for target in targets:
        host, port = target_parts(target)
        if not host:
            continue
        for scheme in ('https', 'http'):
            number = port or (443 if scheme == 'https' else 80)
            cred = scope.credential(host, scheme, number)
            if cred is None:
                continue
            domain = _domain_key(host, number)
            if owner.setdefault(domain, cred.pk) != cred.pk:
                continue
            url = _url(host, scheme, number)
            if all(item[0] != url for item in items):
                items.append((url, cred, domain))
    return items


def entries_for(items):
    """``[(credential, [secrets-file domain, ...])]`` for plan items, one entry per credential."""
    grouped = {}
    for _url_, cred, domain in items:
        grouped.setdefault(cred.pk, (cred, []))[1].append(domain)
    return [(cred, list(dict.fromkeys(domains))) for cred, domains in grouped.values()]


def secrets_document(entries):
    """The nuclei secrets file (the ``static`` format of nuclei's authenticated scans) for ``entries``, as a dict: one ``Header`` secret per
    credential, limited to exactly the listed domains. Nuclei applies it only to a request whose host (and port, unless 80 or 443) equals one."""
    secrets = []
    for cred, domains in entries:
        headers = [{'key': name, 'value': value} for name, value in request_headers(cred)]
        if headers and domains:
            secrets.append({'type': 'Header', 'domains': list(domains), 'headers': headers})
    return {'id': 'cvengine-authenticated-checks', 'info': {'name': 'cvENGINE authenticated checks', 'author': 'cvENGINE'}, 'static': secrets}


@contextlib.contextmanager
def secrets_file(entries):
    """Write the nuclei secrets file for ``entries`` to a private directory (0700) as a 0600 file, yield its path, and delete both afterwards,
    whatever happens. The path goes on the command line; the values never do."""
    scratch = tempfile.mkdtemp(prefix='cvengine-auth-')
    try:
        os.chmod(scratch, 0o700)
        path = os.path.join(scratch, 'secrets.json')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(secrets_document(entries), handle)
        yield path
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ----------------------------------------------------------------------------- lookups for the stages

def credentials_for_hosts(project_id, hosts):
    """The credentials of ``project_id`` that could apply to any of ``hosts`` (an exact host match, or a target-wide one whose target contains
    the host), for the template checks, which know a project and host names but not a target."""
    from cveFeed.models import AuthCredential
    wanted = {str(h).strip().lower().rstrip('.') for h in hosts if h}
    if not wanted:
        return []
    rows = AuthCredential.objects.filter(project_id=project_id).select_related('domain')
    return [c for c in rows if (c.host in wanted) or (not c.host and any(host_in_target(h, c.domain) for h in wanted))]


def revision(cred):
    """A short token that changes whenever the credential is replaced or edited, for the ledger key of its checks (a new credential is
    checked again at once, not after the old one's TTL)."""
    stamp = cred.updated_at.strftime('%y%m%d%H%M%S%f') if cred.updated_at else '0'
    return f'{cred.pk}.{stamp}'
