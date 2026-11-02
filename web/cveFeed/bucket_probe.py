"""Anonymous reads of cloud storage endpoints: does a bucket exist, does it list for everyone, can everyone read an object in it.

The checks only ever issue HTTPS ``GET`` and ``HEAD`` to the documented storage endpoints of AWS S3, Google Cloud Storage and Azure Blob
(never to a project host, never on a port other than 443), with no credentials and no signature. The listing is read once (the first
page, 20 keys at most) and one listed object is asked for with ``HEAD``: no object content is ever downloaded. Each connection goes
through ``cveFeed.pinned_transport``, so the storage hostname is resolved once and refused when it answers with a prohibited address.

The response parsers read the documented formats (S3 ``ListBucketResult`` and ``Error``, the GCS JSON object listing and error, the
Azure ``EnumerationResults``). XML is read with patterns, not a parser: the body comes from a third party and a bucket owner decides
what is in it, so no entity or DTD is ever expanded. Pure functions plus one network function, ``http_fetch``, that tests replace.
"""
import html
import json
import logging
import os
import re
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import quote

logger = logging.getLogger(__name__)

S3, GCS, AZURE = 's3', 'gcs', 'azure'
PROVIDER_LABELS = {S3: 'AWS S3', GCS: 'Google Cloud Storage', AZURE: 'Azure Blob Storage'}

MAX_KEYS = 20  # the first listing page, never more: also the most object names kept
MAX_BODY = 256 * 1024  # a 20-key listing is a few KB; a body past this is cut and still parsed
TIMEOUT = 10
DEFAULT_RPS = 2.0
REGION = re.compile(r'^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$')  # us-east-1, eu-central-1, us-gov-west-1, ap-southeast-2
S3_NAME = re.compile(r'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')
GCS_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$')
AZURE_ACCOUNT = re.compile(r'^[a-z0-9]{3,24}$')
AZURE_CONTAINER = re.compile(r'^(?:\$web|\$root|[a-z0-9](?:[a-z0-9]|-(?!-)){1,61}[a-z0-9])$')

# The hosts a request may go to: the storage platforms' own endpoints and nothing else (see ``endpoint_allowed``).
_ENDPOINTS = (
    re.compile(r'^s3\.amazonaws\.com$'),
    re.compile(r'^[a-z0-9-]+\.s3\.amazonaws\.com$'),  # virtual-hosted, DNS-style names (no dot in the bucket name)
    re.compile(r'^s3\.[a-z]{2}(?:-[a-z]+)+-\d{1,2}\.amazonaws\.com$'),
    re.compile(r'^[a-z0-9-]+\.s3\.[a-z]{2}(?:-[a-z]+)+-\d{1,2}\.amazonaws\.com$'),
    re.compile(r'^storage\.googleapis\.com$'),
    re.compile(r'^[a-z0-9]{3,24}\.blob\.core\.windows\.net$'),
)


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)  # lowercase names, only the few the checks read
    body: bytes = b''


@dataclass
class Verdict:
    """What anonymous access to one bucket (or Azure container) showed.

    ``state``: ``public`` (anyone can list it), ``private`` (it exists and refuses an anonymous listing), ``missing`` (the name is not
    registered: anyone could create it), ``unknown`` (no usable answer: rate limited, a network error, an unexpected reply)."""
    state: str = 'unknown'
    objects: list = field(default_factory=list)  # raw names from the first listing page, at most MAX_KEYS; never stored as they are
    truncated: bool = False  # the listing says there is more than the first page
    region: str = ''
    object_read: object = None  # True/False when one listed object was asked for with HEAD, None when none was
    status: int = 0
    code: str = ''  # the provider's error code (AccessDenied, NoSuchBucket, ...), a short token
    request_count: int = 0


# ----------------------------------------------------------------------------- pacing

class Pacer:
    """The global request rate: ``rate`` requests per second across every worker (one Redis key that expires after one interval), or in
    this process alone when Redis cannot be reached. ``clock`` and ``sleep`` are replaced in tests."""
    KEY = 'cvengine:buckets:pace'

    def __init__(self, rate=None, clock=time.monotonic, sleep=time.sleep, client=None):
        self.rate = rate if rate else request_rate()
        self.clock, self.sleep, self.client = clock, sleep, client
        self.next_at = 0.0
        self.lock = threading.Lock()

    def _redis(self):
        if self.client is not None:
            return self.client
        from reNgine import resources
        return getattr(resources.get_store(), 'r', None)

    def wait(self):
        interval = 1.0 / self.rate
        client = self._redis()
        if client is not None:
            try:
                for _ in range(int(60 / interval) + 2):  # bounded: a stuck key never holds the sweep for good
                    if client.set(self.KEY, '1', nx=True, px=max(1, int(interval * 1000))):
                        return
                    self.sleep(min(interval, max(0.01, (client.pttl(self.KEY) or 10) / 1000.0)))
                return
            except Exception:  # noqa: BLE001 - pace this process alone when Redis cannot be asked
                pass
        with self.lock:
            now = self.clock()
            delay = self.next_at - now
            self.next_at = max(now, self.next_at) + interval
        if delay > 0:
            self.sleep(delay)


def request_rate():
    """Requests per second, ``CVENGINE_BUCKETS_RPS`` clamped to 0.1 to 5: a storage sweep is slow on purpose."""
    try:
        return min(5.0, max(0.1, float(os.environ.get('CVENGINE_BUCKETS_RPS', DEFAULT_RPS))))
    except ValueError:
        return DEFAULT_RPS


_pacer = None


def pacer():
    global _pacer
    if _pacer is None or _pacer.rate != request_rate():
        _pacer = Pacer()
    return _pacer


# ----------------------------------------------------------------------------- the one network function

def endpoint_allowed(host):
    """Whether ``host`` is a documented storage endpoint of the three providers. Every request is checked against this."""
    host = (host or '').lower()
    return any(p.match(host) for p in _ENDPOINTS)


def http_fetch(method, url, paced=True):
    """One anonymous ``GET`` or ``HEAD`` of a storage endpoint over verified HTTPS on 443, no redirect followed, no credentials, at most
    MAX_BODY bytes of the body. Raises ``ValueError`` for any other method, scheme, host or port (and for an address
    ``pinned_transport`` refuses) before anything is sent, and ``OSError``/``HTTPException`` for a network failure."""
    import http.client
    from urllib.parse import urlsplit

    from cveFeed import pinned_transport
    if method not in ('GET', 'HEAD'):
        raise ValueError('bucket checks are read-only: GET or HEAD')
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.port not in (None, 443) or parts.username or parts.password or not endpoint_allowed(parts.hostname):
        raise ValueError('not a documented storage endpoint')
    if any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError('invalid storage URL')
    host = parts.hostname.lower()
    addresses = pinned_transport.resolve(host, 443)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # certificate and name verification stay on: this is the platform's own name
    connection = pinned_transport.HTTPConnection(host, 443, addresses, TIMEOUT, context=context)
    path = parts.path or '/'
    if parts.query:
        path += '?' + parts.query
    if paced:
        pacer().wait()
    try:
        connection.request(method, path, headers={'Host': host, 'User-Agent': 'cvENGINE bucket check', 'Accept': '*/*', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        body = b'' if method == 'HEAD' else pinned_transport.read_body(response, MAX_BODY)
        keep = ('x-amz-bucket-region', 'content-type', 'x-ms-error-code', 'x-goog-error')
        return Response(response.status, {k: response.getheader(k) or '' for k in keep}, body)
    except (http.client.HTTPException, ValueError) as exc:  # ValueError: a body that claims an encoding it is not in
        raise OSError(f'storage endpoint answered badly: {type(exc).__name__}') from None
    finally:
        connection.close()


# ----------------------------------------------------------------------------- reading the documented formats

def _text(body):
    return (body or b'')[:MAX_BODY].decode('utf-8', errors='replace')


def _code(text):
    match = re.search(r'<Code>\s*([A-Za-z0-9_.-]{1,64})\s*</Code>', text)
    return match.group(1) if match else ''


def parse_s3_listing(body):
    """``(keys, truncated)`` of an S3 ``ListBucketResult``, or None when the body is not one. Keys are unescaped, at most MAX_KEYS."""
    text = _text(body)
    if '<ListBucketResult' not in text:
        return None
    keys = [html.unescape(k) for k in re.findall(r'<Contents>.*?<Key>(.*?)</Key>', text, re.S)]
    return keys[:MAX_KEYS], bool(re.search(r'<IsTruncated>\s*true\s*</IsTruncated>', text, re.I)) or len(keys) > MAX_KEYS


def parse_gcs_listing(body):
    """``(names, truncated)`` of a GCS JSON object listing (``storage#objects``), or None when the body is not one."""
    try:
        data = json.loads(_text(body))
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get('kind') != 'storage#objects':
        return None
    names = [i['name'] for i in data.get('items') or [] if isinstance(i, dict) and isinstance(i.get('name'), str)]
    return names[:MAX_KEYS], bool(data.get('nextPageToken')) or len(names) > MAX_KEYS


def gcs_error(body):
    """``(code, message)`` of a GCS JSON error body, ``(0, '')`` when it is not one."""
    try:
        error = json.loads(_text(body)).get('error') or {}
        return int(error.get('code') or 0), str(error.get('message') or '')[:200]
    except (ValueError, AttributeError, TypeError):
        return 0, ''


def parse_azure_listing(body):
    """``(blob names, truncated)`` of an Azure ``EnumerationResults`` container listing, or None when the body is not one."""
    text = _text(body)
    if '<EnumerationResults' not in text:
        return None
    names = [html.unescape(n) for n in re.findall(r'<Blob>\s*<Name>(.*?)</Name>', text, re.S)]
    return names[:MAX_KEYS], bool(re.search(r'<NextMarker>\s*[^<\s]', text)) or len(names) > MAX_KEYS


# ----------------------------------------------------------------------------- the three providers

def s3_url(name, region=None, key=None, query=''):
    """The request URL for a bucket: virtual-hosted style when the name has no dot (the endpoint's certificate is for ``*.s3...``), path
    style otherwise. ``region`` (read from the platform's own redirect header and matched against REGION) selects the regional host."""
    host = f's3.{region}.amazonaws.com' if region else 's3.amazonaws.com'
    path = '/' + quote(key, safe='/') if key else '/'
    if '.' in name:
        return f'https://{host}/{name}{path if key else "/"}{query}'
    return f'https://{name}.{host}{path}{query}'


def check_s3(name, fetch):
    verdict = Verdict()
    region = ''
    for _ in range(2):  # the global endpoint answers 301 PermanentRedirect for a bucket in another region: follow it once, by region
        verdict.request_count += 1
        got = fetch('GET', s3_url(name, region or None, query=f'?max-keys={MAX_KEYS}'))
        verdict.status = got.status
        text = _text(got.body)
        verdict.code = _code(text)
        if got.status == 301 and not region:
            found = (got.headers.get('x-amz-bucket-region') or '').strip().lower()
            if REGION.match(found):
                region = verdict.region = found
                continue
            return verdict  # a redirect we cannot place: unknown
        break
    if got.status == 200:
        listing = parse_s3_listing(got.body)
        if listing is None:
            return verdict
        verdict.state, (verdict.objects, verdict.truncated) = 'public', listing
        verdict.region = region or got.headers.get('x-amz-bucket-region', '') or verdict.region
        return verdict
    if got.status == 404 and verdict.code == 'NoSuchBucket':
        verdict.state = 'missing'
    elif got.status in (403, 400) and verdict.code in ('AccessDenied', 'AllAccessDisabled', 'AccountProblem', 'AuthorizationHeaderMalformed',
                                                       'InvalidAccessKeyId', 'MethodNotAllowed'):
        verdict.state = 'private'
        verdict.region = region or got.headers.get('x-amz-bucket-region', '')
    return verdict


def s3_object_url(name, region, key):
    return s3_url(name, region or None, key=key)


def check_gcs(name, fetch):
    verdict = Verdict(request_count=1)
    got = fetch('GET', f'https://storage.googleapis.com/storage/v1/b/{quote(name, safe="")}/o?maxResults={MAX_KEYS}&fields=kind,nextPageToken,items(name)')
    verdict.status = got.status
    code, message = gcs_error(got.body)
    if got.status == 200:
        listing = parse_gcs_listing(got.body)
        if listing is not None:
            verdict.state, (verdict.objects, verdict.truncated) = 'public', listing
        return verdict
    if got.status == 404 and 'does not exist' in message.lower():
        verdict.state, verdict.code = 'missing', 'NoSuchBucket'
    elif got.status in (401, 403):
        verdict.state, verdict.code = 'private', 'AccessDenied'
    return verdict


def gcs_object_url(name, key):
    return f'https://storage.googleapis.com/{quote(name, safe="")}/{quote(key, safe="/")}'


def azure_host(account):
    return f'{account}.blob.core.windows.net'


def check_azure(account, container, fetch, dns_exists):
    """An account is checked by its DNS name (an account that was deleted has no address: that is the takeover condition); a container
    is listed only when the caller has one it saw somewhere (never guessed)."""
    verdict = Verdict()
    exists = dns_exists(azure_host(account))
    if exists is False:
        verdict.state, verdict.code = 'missing', 'NXDOMAIN'
        return verdict
    if exists is None:
        return verdict
    verdict.state = 'private'  # the account exists; a listing is attempted below when there is a container to ask about
    if not container:
        return verdict
    verdict.request_count = 1
    got = fetch('GET', f'https://{azure_host(account)}/{quote(container, safe="$")}?restype=container&comp=list&maxresults={MAX_KEYS}')
    verdict.status = got.status
    verdict.code = _code(_text(got.body)) or got.headers.get('x-ms-error-code', '')
    if got.status == 200:
        listing = parse_azure_listing(got.body)
        if listing is None:
            verdict.state = 'unknown'
        else:
            verdict.state, (verdict.objects, verdict.truncated) = 'public', listing
    elif got.status not in (400, 403, 404, 409):
        verdict.state = 'unknown'
    return verdict


def azure_object_url(account, container, key):
    return f'https://{azure_host(account)}/{quote(container, safe="$")}/{quote(key, safe="/")}'


def dns_exists(host):
    """True when ``host`` has an address, False when DNS says it does not exist (NXDOMAIN), None when DNS gave no usable answer."""
    import dns.exception
    import dns.resolver

    from cveFeed.hygiene import _resolver
    try:
        return bool(list(_resolver().resolve(host, 'A')))
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True  # the name exists, it just has no A record
    except (dns.exception.DNSException, OSError):
        return None


# ----------------------------------------------------------------------------- object names

# Names a person would not leave in a public bucket: backups, database dumps, keys, credentials, state files.
SENSITIVE_NAME = re.compile(
    r'(?:\.(?:sql|sqlite3?|db|mdb|bak|backup|dump|dmp|pem|key|p12|pfx|jks|kdbx|ovpn|tfstate|tfvars|env|htpasswd|npmrc|pgpass)(?:\.[a-z0-9]{1,5})?$)'
    r'|(?:^|[/_.-])(?:backups?|dumps?|db[_-]?(?:dump|backup)|database|passwords?|passwd|secrets?|credentials?|private[_-]?key|id_(?:rsa|dsa|ecdsa|ed25519)|'
    r'kubeconfig|terraform|\.aws|\.env|\.git)(?:$|[/_.-])', re.I)
# What a secret embedded in a name looks like: provider key ids and tokens, JWTs, key=value pairs, and long mixed-case random tokens.
_SECRET_SEGMENT = (
    re.compile(r'(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{12,}'), re.compile(r'AIza[0-9A-Za-z_-]{30,}'),
    re.compile(r'(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}'), re.compile(r'(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}'),
    re.compile(r'xox[abprs]-[A-Za-z0-9-]{10,}'), re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),
    re.compile(r'(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|sig(?:nature)?)[=:][^/]+', re.I),
)
REDACTED = '[redacted]'
MAX_NAME = 200


def _random_token(segment):
    base = segment.rsplit('.', 1)[0] if re.search(r'\.[A-Za-z0-9]{1,5}$', segment) else segment
    return len(base) >= 24 and bool(re.fullmatch(r'[A-Za-z0-9+_=-]+', base)) and all(
        re.search(p, base) for p in ('[a-z]', '[A-Z]', '[0-9]'))


def redact_name(name):
    """An object name as it may be stored: every path segment that looks like a secret (a provider key id or token, a JWT, ``key=value``
    with a secret word, a long random mixed-case token) is replaced by ``[redacted]``; the rest is kept, at most MAX_NAME characters.
    Hex digests and UUIDs are not secrets and stay."""
    out = []
    for segment in str(name).split('/'):
        if any(p.search(segment) for p in _SECRET_SEGMENT) or _random_token(segment):
            out.append(REDACTED)
        else:
            out.append(segment)
    return re.sub(r'[\x00-\x1f\x7f]', '?', '/'.join(out))[:MAX_NAME]


def is_sensitive_name(name):
    return bool(SENSITIVE_NAME.search(str(name)))


def pick_object(names):
    """The one listed object a HEAD may ask for: the first that is a file (not a folder marker) and not sensitive-looking. A bucket whose
    every object looks sensitive gets no read test at all: the listing alone is the finding."""
    return next((n for n in names if n and not n.endswith('/') and not is_sensitive_name(n)), None)


def head_object(url, fetch):
    """True when an anonymous HEAD of ``url`` succeeds (2xx), False when refused, None when it gave no usable answer."""
    status = fetch('HEAD', url).status
    if 200 <= status < 300:
        return True
    return False if status in (401, 403, 404) else None


# ----------------------------------------------------------------------------- the whole check

def check(provider, name, container='', fetch=http_fetch, dns=dns_exists, read_object=True):
    """Check one bucket (or Azure account and container) anonymously. Returns a ``Verdict``; never raises for a network failure (that is
    state ``unknown``). ``fetch(method, url)`` and ``dns(host)`` are replaced in tests."""
    try:
        if provider == S3:
            verdict = check_s3(name, fetch)
        elif provider == GCS:
            verdict = check_gcs(name, fetch)
        elif provider == AZURE:
            verdict = check_azure(name, container, fetch, dns)
        else:
            raise ValueError('unknown provider')
    except (OSError, ValueError) as exc:  # a refused address, a timeout, a reset: no answer, not a finding either way
        logger.info('bucket check of %s %s gave no answer: %s', provider, name, type(exc).__name__)
        return Verdict(state='unknown')
    if verdict.state == 'public' and read_object:
        key = pick_object(verdict.objects)
        if key:
            url = (s3_object_url(name, verdict.region, key) if provider == S3 else gcs_object_url(name, key) if provider == GCS
                   else azure_object_url(name, container, key))
            try:
                verdict.request_count += 1
                verdict.object_read = head_object(url, fetch)
            except (OSError, ValueError):
                verdict.object_read = None
    return verdict
