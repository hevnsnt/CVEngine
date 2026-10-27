"""A small client for the runZero Export API (asset inventory), read-only.

Only runZero's hosted console is supported: the base URL is fixed, so there is no user-supplied address to point at an internal
service. The token (an Export API token, ``ET...``; organization and account tokens also work for these paths) travels in the
``Authorization: Bearer`` header, never in a URL, a log line or an error message.

Everything the API returns is untrusted data: it is read in bounded chunks, parsed leniently, and every field is typed and clipped
before it leaves this module, so a malformed or hostile reply degrades to "fewer records", never to an exception or a huge value.

Endpoints used (https://console.runzero.com/api/v1.0): ``GET /export/org/assets.json`` and ``/export/org/vulnerabilities.json``
with ``search`` (runZero inventory search syntax), ``fields`` (comma separated), ``page_size`` and ``start_key``. With ``page_size``
the reply is ``{"assets": [...], "next_key": "..."}`` (``"vulnerabilities"`` for the second); without it, a bare array.
"""
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timezone as dt_timezone
from email.utils import parsedate_to_datetime

import requests

logger = logging.getLogger(__name__)

BASE_URL = 'https://console.runzero.com/api/v1.0'
USER_AGENT = 'cvENGINE-runzero-sync'
TIMEOUT = (10, 60)  # connect, read
PAGE_SIZE = 500
MAX_PAGES = 100
MAX_RECORDS = 50_000  # per call: the most one sync reads, so a huge inventory cannot exhaust memory or the daily API budget
MAX_BODY_BYTES = 32 * 1024 * 1024  # one reply, however it is framed
MAX_RETRIES = 3
MAX_WAIT = 60.0  # seconds one rate-limit or server-error wait may take
RETRY_STATUS = (429, 502, 503, 504)
TOKEN_RE = re.compile(r'^[A-Za-z0-9._~+/=-]{8,300}$')
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)

ASSET_FIELDS = ('id', 'addresses', 'addresses_extra', 'names', 'os', 'os_version', 'hw', 'type', 'tags', 'site_name', 'alive',
                'last_seen')
VULN_FIELDS = ('vulnerability_cve', 'vulnerability_name', 'vulnerability_severity', 'vulnerability_cvss3_base_score',
               'vulnerability_service_address', 'vulnerability_service_port', 'vulnerability_service_transport', 'addresses',
               'vulnerability_asset_id')


class RunZeroError(Exception):
    """A failure that is safe to show to a user: ``kind`` is one of auth, rate_limit, network, http, bad_response, too_large."""

    def __init__(self, kind, message, status=None):
        super().__init__(message)
        self.kind, self.message, self.status = kind, message, status


# --- typed, clipped values -------------------------------------------------------------------------------------------

def _text(value, limit):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ''
    return ''.join(c for c in str(value).strip() if c.isprintable())[:limit]


def _texts(value, limit, count):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    out = []
    for item in value:
        text = _text(item, limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= count:
            break
    return out


def _ips(value, count=20):
    """Valid IP addresses only, in their canonical text form (an IPv6 address always compressed), at most ``count``."""
    out = []
    for text in _texts(value, 64, count * 2):
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue
        if getattr(ip, 'scope_id', None) is None and str(ip) not in out:
            out.append(str(ip))
        if len(out) >= count:
            break
    return out


def _tags(value, count=20):
    """runZero tags are a {name: value} map; an older or odd shape (a list) is accepted too. Each becomes ``name`` or ``name:value``."""
    if isinstance(value, dict):
        items = [f'{k}:{v}' if _text(v, 1) else str(k) for k, v in list(value.items())[:count * 2]]
    else:
        items = value
    return _texts(items, 100, count)


def _time(value):
    """ISO-8601 UTC text for a unix time in seconds, or ''. Out-of-range or non-numeric values are dropped."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ''
    try:
        return datetime.fromtimestamp(value, tz=dt_timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ''


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value == value and abs(value) < 1e6 else None  # NaN and absurd values are dropped


def _port(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 < number < 65536 else None


def parse_asset(raw):
    """One asset as a typed dict, or None when it has no usable address."""
    if not isinstance(raw, dict):
        return None
    addresses = list(dict.fromkeys(_ips(raw.get('addresses')) + _ips(raw.get('addresses_extra'))))
    if not addresses:
        return None
    alive = raw.get('alive')
    return {'id': _text(raw.get('id'), 64), 'addresses': addresses[:20], 'names': _texts(raw.get('names'), 255, 20),
            'os': _text(raw.get('os'), 100), 'os_version': _text(raw.get('os_version'), 100), 'hw': _text(raw.get('hw'), 100),
            'type': _text(raw.get('type'), 60), 'tags': _tags(raw.get('tags')), 'site': _text(raw.get('site_name'), 100),
            'alive': alive if isinstance(alive, bool) else None, 'last_seen': _time(raw.get('last_seen'))}


def parse_vulnerability(raw):
    """The CVE reports of one runZero vulnerability record: a list of ``{address, port, cve, ...}`` (empty when it names no CVE or no
    address). A record is kept only for what cvENGINE can use: a CVE id, where it was seen, and a few facts to show."""
    if not isinstance(raw, dict):
        return []
    cves = list(dict.fromkeys(m.upper() for m in CVE_RE.findall(' '.join(_texts(raw.get('vulnerability_cve'), 400, 10)))))[:10]
    service = _ips(raw.get('vulnerability_service_address'), 1)
    addresses = service or _ips(raw.get('addresses'), 5)  # without a service address the report is about the whole asset
    if not cves or not addresses:
        return []
    port = _port(raw.get('vulnerability_service_port')) if service else None
    common = {'port': port, 'transport': _text(raw.get('vulnerability_service_transport'), 10).lower(),
              'name': _text(raw.get('vulnerability_name'), 200), 'severity': _text(raw.get('vulnerability_severity'), 20).lower(),
              'cvss3': _number(raw.get('vulnerability_cvss3_base_score'))}
    return [{'address': a, 'cve': cve, **common} for a in addresses for cve in cves]


BOOST = 0.1  # added to the confidence of a CVE match runZero also reports: it orders lists, it does not confirm anything


def boosted(confidence):
    return min(1.0, round(confidence + BOOST, 2))


def reported_cves(ip, port):
    """The CVE ids runZero reported for this IpAddress (stored by cveFeed.runzero_sync) that apply to ``port``; a report without a
    port is about the whole host."""
    vulns = ((ip.fingerprint or {}).get('runzero') or {}).get('vulns') or []
    return {v['cve'] for v in vulns if isinstance(v, dict) and v.get('cve') and v.get('port') in (None, port)}


# --- the client ------------------------------------------------------------------------------------------------------

def valid_token(token):
    return isinstance(token, str) and bool(TOKEN_RE.match(token.strip()))


def _retry_wait(response, attempt):
    """Seconds to wait before retrying: the server's Retry-After (seconds or an HTTP date) when it sent one, else 2, 4, 8."""
    header = response.headers.get('Retry-After')
    delay = None
    if header:
        try:
            delay = float(header)
        except ValueError:
            try:
                delay = (parsedate_to_datetime(header) - datetime.now(dt_timezone.utc)).total_seconds()
            except (TypeError, ValueError):
                delay = None
    if delay is None:
        delay = 2 ** (attempt + 1)
    return max(0.0, min(delay, MAX_WAIT))


def _read(response):
    """The reply body, read in chunks so an oversized one is refused instead of buffered."""
    chunks, size = [], 0
    try:
        for chunk in response.iter_content(256 * 1024):
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise RunZeroError('too_large', 'runZero sent a reply larger than the limit; narrow the search')
            chunks.append(chunk)
    finally:
        response.close()
    return b''.join(chunks)


class Client:
    """Reads one runZero organization with one token. ``session`` and ``sleep`` are injectable for tests."""

    def __init__(self, token, session=None, sleep=time.sleep):
        token = (token or '').strip()
        if not valid_token(token):
            raise RunZeroError('auth', 'the runZero token is missing or has characters a token never contains')
        self._token = token
        self.session = session or requests.Session()
        self.sleep = sleep

    def _request(self, path, params):
        headers = {'Authorization': f'Bearer {self._token}', 'Accept': 'application/json', 'User-Agent': USER_AGENT}
        for attempt in range(MAX_RETRIES + 1):
            try:
                # no redirects: a redirect must never carry the bearer token to another host
                response = self.session.get(f'{BASE_URL}{path}', params=dict(params), headers=headers, timeout=TIMEOUT, stream=True,
                                            allow_redirects=False)
            except requests.RequestException as exc:
                raise RunZeroError('network', f'could not reach runZero ({type(exc).__name__})')
            status = response.status_code
            if status in RETRY_STATUS and attempt < MAX_RETRIES:
                wait = _retry_wait(response, attempt)
                response.close()
                self.sleep(wait)
                continue
            if status in (401, 403):
                response.close()
                raise RunZeroError('auth', f'runZero rejected the token (HTTP {status}); use an Export API token for this organization')
            if status == 429:
                response.close()
                raise RunZeroError('rate_limit', 'runZero is rate limiting this token (HTTP 429); the next sync will try again')
            if status != 200:
                response.close()
                raise RunZeroError('http', f'runZero answered HTTP {status}', status)
            return _read(response)

    def _get_json(self, path, params):
        body = self._request(path, params)
        try:
            return json.loads(body)
        except (ValueError, RecursionError):
            raise RunZeroError('bad_response', 'runZero sent a reply that is not valid JSON')

    def _pages(self, path, key, search, fields, limit):
        """Yield raw records across pages, at most ``limit``. A reply that is a bare array is one page; a missing, empty or
        repeated ``next_key`` ends the walk, so a hostile server cannot loop us."""
        params = {'page_size': PAGE_SIZE}
        if search:
            params['search'] = search
        if fields:
            params['fields'] = ','.join(fields)
        seen_keys, count = set(), 0
        for _ in range(MAX_PAGES):
            try:
                data = self._get_json(path, params)
            except RunZeroError as exc:
                if exc.status == 400 and 'fields' in params:  # an unknown field name: ask again for whole records (still size-capped)
                    params.pop('fields')
                    continue
                raise
            records, next_key = (data, '') if isinstance(data, list) else (
                data.get(key) if isinstance(data, dict) else None, data.get('next_key') if isinstance(data, dict) else '')
            if not isinstance(records, list):
                raise RunZeroError('bad_response', 'runZero sent a reply in an unexpected shape')
            for record in records:
                yield record
                count += 1
                if count >= limit:
                    return
            next_key = next_key if isinstance(next_key, str) else ''
            if not next_key or next_key in seen_keys:
                return
            seen_keys.add(next_key)
            params['start_key'] = next_key

    def test_connection(self):
        """Raise RunZeroError when the token does not work; otherwise return how many assets the first page held (0 or 1)."""
        data = self._get_json('/export/org/assets.json', {'page_size': 1, 'fields': 'id'})
        records = data if isinstance(data, list) else data.get('assets') if isinstance(data, dict) else None
        if not isinstance(records, list):
            raise RunZeroError('bad_response', 'runZero sent a reply in an unexpected shape')
        return len(records)

    def fetch_assets(self, search='', limit=MAX_RECORDS):
        """``(assets, truncated)``: typed assets that have at least one valid address, and whether the limit cut the list short."""
        out, raw = [], 0
        for record in self._pages('/export/org/assets.json', 'assets', _text(search, 300), ASSET_FIELDS, limit):
            raw += 1
            asset = parse_asset(record)
            if asset:
                out.append(asset)
        return out, raw >= limit

    def fetch_vulnerabilities(self, search='', limit=MAX_RECORDS):
        """``(reports, truncated)``: every ``{address, port, cve, ...}`` runZero reports, and whether the limit cut the list short."""
        out, raw = [], 0
        for record in self._pages('/export/org/vulnerabilities.json', 'vulnerabilities', _text(search, 300), VULN_FIELDS, limit):
            raw += 1
            out.extend(parse_vulnerability(record))
        return out, raw >= limit
