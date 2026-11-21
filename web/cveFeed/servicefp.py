"""nmap's service fingerprint, decoded: what an unidentified service answered, as text the banner readers can read.

When nmap's probes name no service it prints a fingerprint (``servicefp``) of the raw replies, and the scanner library keeps it as the port's
banner (``cvengine_scanner.nmap._banner_from``, clipped). It is stored as nmap writes it, wrapped at 80 columns behind ``SF:`` and escaped::

    SF-Port80-TCP:V=7.94SVN%I=7%D=11/18%Time=6737A0C1%P=x86_64-pc-linux-gnu%r(GetRequest,16F,"HTTP/1\\.0\\x20301\\x20Moved\\x20Permanently\\r\\n
    SF:Server:\\x20nginx/1\\.18\\.0\\r\\n...")%r(HTTPOptions,...

so ``banner:"Server: nginx"`` never found it and the readers (Recog, the header parser) never saw a reply. ``decode`` turns it back into
``[(probe, text)]`` (``\\xNN``, ``\\r``, ``\\n``, ``\\t``, ``\\0`` and an escaped character unescaped; a reply the clip cut short is kept as far as it
goes), ``text`` joins them for search (``Port.extra['servicefp']``), ``greeting`` is the first line the NULL or GenericLines probe got (an SSH, FTP,
SMTP, POP3 or IMAP greeting, read by Recog's banner databases) and ``http_headers`` the headers of the first HTTP reply (GetRequest,
HTTPOptions, FourOhFourRequest: read by the header readers and Recog's ``http_header.*`` databases). Pure: nothing here makes a request.
"""
import re

MAX_TEXT = 4000      # Port.extra['servicefp']: what search reads
MAX_REPLIES = 12
_SEGMENT = re.compile(r'%r\(([A-Za-z0-9_-]{1,40}),([0-9A-Fa-f]{1,6}),"')
_ESCAPES = {'r': '\r', 'n': '\n', 't': '\t', '0': '\x00', 'a': '\x07', 'b': '\x08', 'f': '\x0c', 'v': '\x0b', 'e': '\x1b'}
GREETING_PROBES = ('NULL', 'GenericLines')
HTTP_PROBES = ('GetRequest', 'HTTPOptions', 'FourOhFourRequest', 'RTSPRequest')


def is_servicefp(banner):
    return str(banner or '').lstrip().startswith('SF-Port')


def _unwrap(text):
    """The fingerprint as one line: nmap breaks it every 80 columns and starts each continuation line with ``SF:``."""
    return re.sub(r'\r?\n(?:SF:)?', '', str(text or ''))


def _unescape(body):
    """The reply an escaped body stands for, and where the body ended (its closing quote), or ``len(body)`` when the clip cut it short."""
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == '"':
            return ''.join(out), i
        if ch == '\\' and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == 'x' and re.match(r'[0-9A-Fa-f]{2}', body[i + 2:i + 4]):
                out.append(chr(int(body[i + 2:i + 4], 16)))
                i += 4
                continue
            out.append(_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out), len(body)


def decode(banner):
    """``[(probe name, reply text)]`` of a stored fingerprint, in order, or ``[]`` for a banner that is not one. A byte outside printable text is
    kept as the character it is (the readers match text); a NUL is dropped (PostgreSQL refuses it)."""
    if not is_servicefp(banner):
        return []
    text = _unwrap(banner)
    out, pos = [], 0
    while len(out) < MAX_REPLIES:
        found = _SEGMENT.search(text, pos)
        if not found:
            break
        reply, end = _unescape(text[found.end():])
        out.append((found.group(1), reply.replace('\x00', '')))
        pos = found.end() + end + 1
    return out


def as_text(replies):
    """The decoded replies as one text for search and display (``Port.extra['servicefp']``): each under its probe's name, clipped."""
    parts = [f'[{probe}]\n{reply.strip()}' for probe, reply in replies if reply.strip()]
    return '\n'.join(parts)[:MAX_TEXT]


def text(banner):
    return as_text(decode(banner))


def greeting(replies):
    """The first line a service sent unasked (the NULL probe) or after a bare newline (GenericLines), or ''."""
    for probe, reply in replies:
        if probe in GREETING_PROBES:
            for line in reply.replace('\r', '').split('\n'):
                if line.strip():
                    return line.strip()[:300]
    return ''


def http_headers(replies):
    """``{lowercase name: value}`` of the headers of the first HTTP reply among ``replies`` (``HTTP/1.x <status>`` then ``Name: value`` lines up to
    the blank line), or {}; a header that repeats keeps its first value, except Set-Cookie, kept apart by ``http_cookies``."""
    for probe, reply in replies:
        if probe not in HTTP_PROBES or not reply.startswith('HTTP/'):
            continue
        headers = {}
        for line in reply.replace('\r', '').split('\n')[1:60]:
            if not line.strip():
                break
            name, sep, value = line.partition(':')
            if sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,40}', name.strip()) and value.strip():
                headers.setdefault(name.strip().lower(), value.strip()[:300])
        return headers
    return {}


def http_cookies(replies):
    """The cookie names the first HTTP reply set (``Set-Cookie: NAME=...``): what Recog's cookie database reads."""
    for probe, reply in replies:
        if probe not in HTTP_PROBES or not reply.startswith('HTTP/'):
            continue
        out = []
        for line in reply.replace('\r', '').split('\n')[1:60]:
            if not line.strip():
                break
            name, sep, value = line.partition(':')
            if sep and name.strip().lower() == 'set-cookie':
                cookie = value.strip().split('=', 1)[0].strip()
                if re.fullmatch(r"[A-Za-z0-9_.$!#%&'*+^`|~-]{1,80}", cookie):
                    out.append(cookie)
        return out[:20]
    return []
