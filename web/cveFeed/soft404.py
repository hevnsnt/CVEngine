"""Whether a server's answer for a path is its answer for any path: the "soft 404", a page that exists for every address.

Single-page apps, appliances and WAFs answer every path with one page (200 and a shell, a redirect to a login page, a 403), which says
nothing about whether the route is there. Every directory brute-forcer (ffuf's auto-calibration, feroxbuster's wildcard filter, dirsearch,
gobuster) and Nikto handle it the same way, and so does the research the term comes from (Bar-Yossef et al., "Sic transit gloria telae",
WWW 2004): ask for paths that cannot exist, in the same directory and with the same kind of name as the one being checked, and compare
what comes back with what the real path gave, after taking out what changes between two requests for the same page.

What is compared: the status, the content type, where a redirect leads (with the requested path taken out of it: a server that sends
every path to ``/login?next=<path>`` sends them all to the same place) and the body, normalised (the requested path, ids, tokens, nonces
and times removed) and compared as a hash, or, for a page that still moves, as a set of word shingles that must also agree on the title and on whether a sign-in form is there.

Pure: nothing here asks the network.
"""
import functools
import hashlib
import re
from urllib.parse import quote, quote_plus, unquote, urlsplit

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
_PASSWORD_FIELD = re.compile(r'<input\b[^<>]{0,1000}?type=["\']?password', re.I)
_WORD = re.compile(r'[A-Za-z0-9]{2,}')


MIN_SLUG = 3  # a bare name shorter than this is not taken out of a page: "a" or "id" are ordinary words


def _forms(value):
    """``value`` as a page may print it: raw, percent-decoded, percent-encoded and form-encoded."""
    return {value, unquote(value), quote(value, safe=''), quote_plus(value)} - {''}


@functools.lru_cache(maxsize=256)
def _path_pattern(path):
    """One case-insensitive pattern for every way a page can name the requested ``path``: with its slash (``/admin``, ``%2Fadmin``), and as the
    bare last segment (with or without its extension) or the bare path without its slashes (``"admin"``, ``admin/users``, ``admin - Portal``), which a "page not found" text
    or a title prints. A bare name is only taken out as a whole word: ``administrator`` is left alone. None when there is nothing to take out."""
    slashed = _forms(path) - {'/'}
    stripped = path.strip('/')
    last = stripped.rsplit('/', 1)[-1]
    bare = set()
    for name in (stripped, last, last.rsplit('.', 1)[0] if '.' in last else ''):  # the file name's stem too: a page for wp-login.php may say "wp-login"
        if len(unquote(name)) >= MIN_SLUG:
            bare |= _forms(name)
    parts = []
    if slashed:
        parts.append('|'.join(re.escape(f) for f in sorted(slashed, key=len, reverse=True)))
    if bare:
        parts.append('(?<![A-Za-z0-9])(?:' + '|'.join(re.escape(f) for f in sorted(bare, key=len, reverse=True)) + ')(?![A-Za-z0-9])')
    return re.compile('|'.join(parts), re.I) if parts else None


def normalise(text, path=''):
    """``text`` with what differs between two requests for the same page taken out: the requested path (with or without its slash, in any case,
    raw, percent-encoded and decoded), ids and long hex or base64 strings, dates and times, long numbers, and nonce, CSRF and token values."""
    text = str(text or '')
    pattern = _path_pattern(path) if path else None
    if pattern:
        text = pattern.sub(MARKER, text)
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
        'title': normalise(result.get('title') or '', path).lower()[:120],
        'form': bool(_PASSWORD_FIELD.search(body)),
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
    and type, a redirect that leads to the same place, or a body that is the same after normalising, or close enough to it (the same title and
    the same sign-in form or none) that only a changing part differs."""
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
    if answer['title'] != missing['title'] or answer['form'] != missing['form']:
        return False  # a page of its own on the same template: another title, or a sign-in form the missing page lacks
    return similarity(answer['shingles'], missing['shingles']) >= SIMILAR


def public(fp):
    """What may be stored of a fingerprint as evidence: no body, no shingles."""
    return {'status': fp['status'], 'type': fp['type'], 'redirect': fp['redirect'], 'hash': fp['hash'], 'length': fp['length']}
