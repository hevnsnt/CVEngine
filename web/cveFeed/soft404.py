"""Whether a server's answer for a path is its answer for any path: the "soft 404", a page that exists for every address.

Single-page apps, appliances and WAFs answer every path with one page (200 and a shell, a redirect to a login page, a 403), which says
nothing about whether the route is there. Every directory brute-forcer (ffuf's auto-calibration, feroxbuster's wildcard filter, dirsearch,
gobuster) and Nikto handle it the same way, and so does the research the term comes from (Bar-Yossef et al., "Sic transit gloria telae",
WWW 2004): ask for paths that cannot exist, in the same directory and with the same kind of name as the one being checked, and compare
what comes back with what the real path gave, after taking out what changes between two requests for the same page.

What is compared: the status, the content type, where a redirect leads (with the requested path taken out of it: a server that sends
every path to ``/login?next=<path>`` sends them all to the same place) and the body, normalised (the requested path, ids, tokens, nonces
and times removed) and compared as a hash, or, for a page that still moves, as a set of word shingles. A title is not required.

Pure: nothing here asks the network.
"""
import hashlib
import re
from urllib.parse import quote, unquote, urlsplit

MARKER = '{path}'
MAX_SHINGLES = 400
SIMILAR = 0.9           # Jaccard similarity of two bodies' shingles at or above which they are the same page
LENGTH_SLACK = 0.35     # and their lengths differ by no more than this share of the longer
SHORT_BODY = 64         # under this many bytes a body is only the same page when it is identical

_UUID = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
_LONG_HEX = re.compile(r'\b[0-9a-f]{16,}\b', re.I)
_BASE64ISH = re.compile(r'(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_-])')
_ISO_TIME = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?')
_DATE = re.compile(r'\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,? \d{1,2} [A-Z][a-z]{2,8} \d{4})\b')
_BIG_NUMBER = re.compile(r'\b\d{6,}\b')
_TOKEN_ATTR = re.compile(r'(?i)\b(nonce|csrf[-_\w]*|xsrf[-_\w]*|token|authenticity_token|requestid|request-id|trace-?id)\b(["\']?\s*[:=]\s*["\']?)[^"\'\s<>]{4,}')
_META_TOKEN = re.compile(r'(?i)(<meta[^>]+name=["\'](?:csrf|xsrf)[^>]*content=["\'])[^"\']*')
_WORD = re.compile(r'[A-Za-z0-9]{2,}')


def normalise(text, path=''):
    """``text`` with what differs between two requests for the same page taken out: the requested path (raw, percent-encoded and decoded),
    ids and long hex or base64 strings, dates and times, long numbers, and nonce, CSRF and token values."""
    text = str(text or '')
    for form in {path, unquote(path), quote(path, safe='')} - {'', '/'}:
        text = text.replace(form, MARKER)  # with its slash only: the bare word may be part of the page's own text
    text = _META_TOKEN.sub(r'\1', text)
    text = _TOKEN_ATTR.sub(r'\1\2', text)
    for pattern in (_UUID, _LONG_HEX, _ISO_TIME, _DATE, _BASE64ISH, _BIG_NUMBER):
        text = pattern.sub('', text)
    return re.sub(r'\s+', ' ', text).strip()


def _shingles(text, size=4):
    words = _WORD.findall(text.lower())
    if len(words) <= size:
        return frozenset({' '.join(words)}) if words else frozenset()
    grams = {' '.join(words[k:k + size]) for k in range(len(words) - size + 1)}
    if len(grams) > MAX_SHINGLES:  # a stable sample, so two long pages are sampled alike
        grams = set(sorted(grams, key=lambda g: hashlib.md5(g.encode()).digest())[:MAX_SHINGLES])
    return frozenset(grams)


def _redirect_target(location, path):
    """Where a redirect leads, as path and query, with the requested path taken out."""
    if not location:
        return ''
    try:
        parts = urlsplit(str(location).strip())
    except ValueError:
        return ''
    target = (parts.path or '/') + ('?' + parts.query if parts.query else '')
    return normalise(target.lower(), path.lower())[:300]


def fingerprint(result, path=''):
    """The comparable form of one answer (a probe result: ``status``, ``content_type``, ``location``, ``body``, ``bytes``) to a request
    for ``path``. Nothing of the body is kept but a hash and a sample of word groups."""
    body = result.get('body') or ''
    clean = normalise(body, path)
    return {
        'status': int(result.get('status') or 0),
        'type': str(result.get('content_type') or '').split(';')[0].strip().lower(),
        'redirect': _redirect_target(result.get('location'), path),
        'hash': hashlib.sha1(clean.encode('utf-8', 'replace')).hexdigest()[:16],
        'length': int(result.get('bytes') if result.get('bytes') is not None else len(body)),
        'shingles': _shingles(clean),
    }


def similarity(a, b):
    """Jaccard similarity of two shingle sets (1.0 for two empty ones)."""
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def same(answer, missing):
    """True when ``answer`` is the server's answer for a path that is not there (``missing``, both from ``fingerprint``): the same status
    and type, a redirect that leads to the same place, or a body that is the same after normalising, or close enough to it that only a
    changing part differs."""
    if not answer or not missing or answer['status'] != missing['status'] or answer['type'] != missing['type']:
        return False
    if 300 <= answer['status'] < 400:
        return answer['redirect'] == missing['redirect']
    if answer['hash'] == missing['hash']:
        return True
    longer = max(answer['length'], missing['length'])
    if longer < SHORT_BODY:
        return False
    if abs(answer['length'] - missing['length']) > LENGTH_SLACK * longer:
        return False
    return similarity(answer['shingles'], missing['shingles']) >= SIMILAR


def public(fp):
    """What may be stored of a fingerprint as evidence: no body, no shingles."""
    return {'status': fp['status'], 'type': fp['type'], 'redirect': fp['redirect'], 'hash': fp['hash'], 'length': fp['length']}
