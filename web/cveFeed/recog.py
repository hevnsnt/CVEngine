"""Rapid7 Recog on the server: the product, vendor, version and CPE a banner cvENGINE already stored states, read with Recog's fingerprint
databases (https://github.com/rapid7/recog, BSD-2-Clause, vendored unchanged in ``data/recog/`` at the commit ``manifest.json`` pins;
``scripts/update_recog.py`` refreshes it). Nothing is sent anywhere: only stored text is read.

The databases and what each reads (``DATABASES``: Recog's ``matches`` name, the file, and the stored text it is given):

  http_header.server    http_servers.xml    a Server header: the web check's (``Subdomain.webserver``), a port's ``http-server-header`` and
                                            ``http-headers`` NSE output, a live route's kept headers (``RouteAuth.evidence``)
  http_header.cookie    http_cookies.xml    a Set-Cookie line of a port's ``http-headers`` output; a cookie a live route set (by name)
  ssh.banner            ssh_banners.xml     an SSH identification string (``Port.banner``), less its ``SSH-2.0-`` prefix, as Recog reads it
  smtp.banner           smtp_banners.xml    an SMTP greeting (``Port.banner``) less its ``220`` code
  ftp.banner            ftp_banners.xml     an FTP greeting (``Port.banner``) less its ``220`` code
  pop3.banner           pop_banners.xml     a POP3 greeting (``Port.banner``) less its ``+OK``
  imap4.banner          imap_banners.xml    an IMAP greeting (``Port.banner``) less its ``* OK`` and a leading ``[CAPABILITY ...]``
  telnet.banner         telnet_banners.xml  a telnet banner (``Port.banner`` of a telnet port)
  snmp.sys_description  snmp_sysdescr.xml   an SNMP agent's sysDescr (the UDP sweep's ``snmp-sysdescr`` output, less its uptime line)
  mysql.banners         mysql_banners.xml   the server version a MySQL handshake states (``mysql-info``'s ``Version:``)
  ntp.banner            ntp_banners.xml     the readvar variables of ``ntp-info`` (Recog's ``ntp.readvar``), rebuilt in readvar's own form

Left out: Recog's x509 subject and issuer databases state no version for any fingerprint, so they cannot give a reading; there is no RDP
database in Recog; nothing stored holds a DNS ``version.bind`` answer.

Recog's patterns are Ruby regular expressions. They are translated (``translate``): Ruby's ``^`` and ``$`` always match at line breaks
(``re.MULTILINE``), ``REG_DOT_NEWLINE`` and ``REG_MULTILINE`` are Ruby's ``/m`` (``re.DOTALL``), ``REG_ICASE`` is ``re.IGNORECASE``, and
``(?<name>``, ``\\h``, ``\\z``, ``\\Z`` and the POSIX bracket classes are spelled the Python way. A fingerprint is loaded only when its
pattern compiles, it has no nested unbounded quantifier with no literal each repetition must contain (``(.+)*``: the shape
of catastrophic backtracking, ``risky``) and every one of its own
``<example>`` entries matches with the values the example states; the rest are skipped and counted (``stats``). Input is clipped to
``MAX_INPUT`` characters before any pattern sees it. Like Recog, the first fingerprint of a database that matches is the answer.
"""
import base64
import functools
import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DATA = Path(__file__).with_name('data') / 'recog'
MAX_INPUT = 1024        # characters of one banner a pattern sees (Recog's banners are a line or a few)
# matches name -> file. ntp.banner is Recog's ntp.readvar database; telnet_banners.xml names no matches attribute
DATABASES = {
    'http_header.server': 'http_servers.xml',
    'http_header.cookie': 'http_cookies.xml',
    'ssh.banner': 'ssh_banners.xml',
    'smtp.banner': 'smtp_banners.xml',
    'ftp.banner': 'ftp_banners.xml',
    'pop3.banner': 'pop_banners.xml',
    'imap4.banner': 'imap_banners.xml',
    'telnet.banner': 'telnet_banners.xml',
    'snmp.sys_description': 'snmp_sysdescr.xml',
    'mysql.banners': 'mysql_banners.xml',
    'ntp.banner': 'ntp_banners.xml',
}
FLAGS = {'REG_ICASE': re.IGNORECASE, 'REG_DOT_NEWLINE': re.DOTALL, 'REG_MULTILINE': re.DOTALL, 'REG_LINE_ANY_CRLF': 0, 'REG_LINE_ANCHORS': 0}
_POSIX = {'alpha': 'a-zA-Z', 'digit': '0-9', 'alnum': 'a-zA-Z0-9', 'upper': 'A-Z', 'lower': 'a-z', 'space': r'\s', 'xdigit': '0-9a-fA-F',
          'word': r'\w', 'blank': r' \t', 'punct': r'!-/:-@\[-`{-~', 'print': r'\x20-\x7e', 'graph': r'\x21-\x7e', 'cntrl': r'\x00-\x1f\x7f'}
# a group holding an unbounded quantifier, itself repeated without bound: (a+)+, (\w*\s?)*, (.+)*, (?:\.\d+)*
_NESTED = re.compile(r'\((?:\?:)?([^()]*(?<!\\)[+*][^()]*)\)(?:[+*]|\{\d*,\})')
# what is left of a group's content once its classes, wildcards and quantifiers are taken out: a literal that must appear in each repetition
_NOT_LITERAL = re.compile(r'\[[^\]]*\]|\\[dDwWsShH]|\\.(?=[?*+{])|(?<!\\)\.|\{\d*,?\d*\}|[+*?]|[^\\](?=[?*+{])')


def risky(python):
    """Whether a pattern can backtrack catastrophically: a group repeated without bound, one of whose alternatives repeats without bound and
    holds no literal every repetition must contain (``(.+)*``, ``(\\w+\\s?)+``, ``(a|b+)*``). ``(?:\\.\\d+)*`` is safe: each repetition starts
    at a dot."""
    for found in _NESTED.finditer(python):
        for alternative in found.group(1).split('|'):
            if re.search(r'(?<!\\)[+*]|\{\d*,\}', alternative) and not _NOT_LITERAL.sub('', alternative):
                return True
    return False
_INTERPOLATE = re.compile(r'\{([a-z0-9_.]+)\}')


@dataclass
class Fingerprint:
    pattern: str
    regex: re.Pattern
    description: str
    params: list            # [(pos, name, value)]
    examples: list = field(default_factory=list)  # [(text, {name: expected value})]

    def match(self, text):
        """``{name: value}`` of the params a matching ``text`` gives (the static ones interpolated), or None."""
        found = self.regex.search(text)
        if not found:
            return None
        out = {}
        for pos, name, value in self.params:
            if pos == 0:
                if value is not None:
                    out[name] = value
            elif pos <= (found.re.groups or 0):
                got = found.group(pos)
                if got is not None and got != '':
                    out[name] = got
        for name, value in list(out.items()):
            if '{' in value:
                filled = _INTERPOLATE.sub(lambda m: out[m.group(1)] if '{' not in out.get(m.group(1), '{') else m.group(0), value)
                if _INTERPOLATE.search(filled):
                    del out[name]  # a value naming a param this match did not give (a CPE without the version): not stated
                else:
                    out[name] = filled
        out['fingerprint.description'] = self.description
        return out


def translate(pattern):
    """A Ruby (Onigmo) pattern as Python's ``re`` reads it the same way, or None when it uses something that has no equivalent."""
    out, i, n = [], 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == '\\' and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == 'h':
                out.append('0-9a-fA-F' if in_class else '[0-9a-fA-F]')
            elif nxt == 'H' and not in_class:
                out.append('[^0-9a-fA-F]')
            elif nxt == 'z' and not in_class:
                out.append(r'\Z')
            elif nxt == 'Z' and not in_class:
                out.append(r'(?=\n?\Z)')
            elif nxt in 'GKRXp' and not in_class:
                return None  # \G, \K, \R, \X and \p{...} have no Python equivalent
            else:
                out.append(c + nxt)
            i += 2
            continue
        if in_class:
            if pattern.startswith('[:', i):
                end = pattern.find(':]', i + 2)
                name = pattern[i + 2:end] if end > 0 else ''
                if name.lstrip('^') not in _POSIX or name.startswith('^'):
                    return None
                out.append(_POSIX[name])
                i = end + 2
                continue
            if c == '[':
                return None  # a nested class (Ruby's [a-z&&[^aeiou]])
            if c == ']':
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == '[':
            in_class = True
            out.append(c)
            i += 1
            if i < n and pattern[i] == '^':
                out.append('^')
                i += 1
            if i < n and pattern[i] == ']':  # a ']' first in a class is a literal
                out.append(r'\]')
                i += 1
            continue
        if pattern.startswith('(?<', i) and i + 3 < n and pattern[i + 3] not in '=!':
            out.append('(?P<')
            i += 3
            continue
        if pattern.startswith('(?', i):
            # Ruby's inline (?m) / (?m: ...) is Python's (?s): the dot matches a newline
            found = re.match(r'\(\?([imx]*)(?:-([imx]*))?([:)])', pattern[i:])
            if found:
                on, off, end = found.group(1).replace('m', 's'), (found.group(2) or '').replace('m', 's'), found.group(3)
                if end == ')' and i != 0:
                    return None  # a flag switched on mid-pattern for the rest of it: Python allows flags only at the start
                out.append('(?' + on + (f'-{off}' if off else '') + end)
                i += found.end()
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def _text(example):
    raw = example.text or ''
    if example.get('_encoding') == 'base64':
        try:
            return base64.b64decode(raw).decode('utf-8', 'replace')
        except ValueError:
            return None
    return raw


def _verified(fp):
    """Whether every example of ``fp`` matches it with the values the example states."""
    for text, expected in fp.examples:
        if text is None:
            return False
        got = fp.match(text[:MAX_INPUT])
        if got is None or any(got.get(k) != v for k, v in expected.items()):
            return False
    return True


def _load_file(path):
    """``(fingerprints, skipped {reason: count})`` of one database file."""
    root = ET.parse(path).getroot()
    loaded, skipped = [], {}
    for el in root.findall('fingerprint'):
        pattern = el.get('pattern') or ''
        flags = re.MULTILINE  # Ruby's ^ and $ always match at a line break
        unknown = False
        for flag in filter(None, (f.strip() for f in (el.get('flags') or '').split(','))):
            if flag not in FLAGS:
                unknown = True
            flags |= FLAGS.get(flag, 0)
        python = translate(pattern)
        reason = None
        if unknown or python is None:
            reason = 'untranslatable'
        elif risky(python):
            reason = 'backtracking'
        else:
            try:
                regex = re.compile(python, flags)
            except re.error:
                reason = 'compile'
        if reason is None:
            params = []
            for param in el.findall('param'):
                try:
                    params.append((int(param.get('pos') or 0), param.get('name') or '', param.get('value')))
                except ValueError:
                    continue
            examples = [(_text(ex), {k: v for k, v in ex.attrib.items() if not k.startswith('_')}) for ex in el.findall('example')]
            fp = Fingerprint(pattern, regex, ' '.join((el.findtext('description') or '').split())[:200], params, examples)
            if _verified(fp):
                loaded.append(fp)
                continue
            reason = 'examples'
        skipped[reason] = skipped.get(reason, 0) + 1
    return loaded, skipped


@functools.lru_cache(maxsize=1)
def databases():
    """``{matches name: [Fingerprint]}``, loaded and verified once per process."""
    out, skipped = {}, {}
    for name, filename in DATABASES.items():
        try:
            out[name], lost = _load_file(DATA / filename)
        except (OSError, ET.ParseError):
            logger.exception('Recog database %s could not be read', filename)
            out[name], lost = [], {'unreadable': 1}
        for reason, count in lost.items():
            skipped[reason] = skipped.get(reason, 0) + count
    databases.skipped = skipped
    return out


def stats():
    """``{'commit', 'loaded', 'skipped': {reason: count}, 'per_database': {name: loaded}}``."""
    dbs = databases()
    try:
        commit = json.loads((DATA / 'manifest.json').read_text()).get('commit', '')
    except (OSError, ValueError):
        commit = ''
    return {'commit': commit, 'loaded': sum(len(v) for v in dbs.values()), 'skipped': dict(getattr(databases, 'skipped', {})),
            'per_database': {k: len(v) for k, v in dbs.items()}}


def match(database, text):
    """The params of the first fingerprint of ``database`` (a ``DATABASES`` name) that matches ``text``, or None. ``text`` is untrusted: it is
    clipped to ``MAX_INPUT`` characters and NUL bytes are dropped before any pattern sees it."""
    if not isinstance(text, str) or not text.strip():
        return None
    text = text.replace('\x00', '')[:MAX_INPUT]
    for fp in databases().get(database, ()):
        got = fp.match(text)
        if got is not None:
            got['recog.database'] = database
            return got
    return None


# ----------------------------------------------------------------------------- what a match states

# the network operating systems whose own name a CVE record uses: an os.* result naming one is a product reading (like an SNMP sysDescr's
# Cisco IOS, cveFeed.version_catalogue.from_sysdescr); any other operating system is only a hint, never matched by name (match_policy.is_os_sighting)
NETWORK_OS = {
    ('cisco', 'ios'): 'Cisco IOS', ('cisco', 'ios-xe'): 'Cisco IOS XE', ('cisco', 'ios xe'): 'Cisco IOS XE', ('cisco', 'ios-xr'): 'Cisco IOS XR',
    ('cisco', 'nx-os'): 'Cisco NX-OS', ('fortinet', 'fortios'): 'FortiOS', ('juniper', 'junos os'): 'Junos OS', ('juniper', 'junos'): 'Junos OS',
    ('palo alto networks', 'pan-os'): 'PAN-OS', ('sonicwall', 'sonicos'): 'SonicOS', ('mikrotik', 'routeros'): 'RouterOS',
}
# words that name a kind of software, not one product: a product named only with them ("HTTPD", "Proxy", "FTP Server") is its vendor's
_GENERIC_WORDS = frozenset({'httpd', 'http', 'https', 'server', 'web', 'ftp', 'ftpd', 'sshd', 'ssh', 'smtp', 'smtpd', 'esmtp', 'mail', 'proxy',
                            'pop', 'pop3', 'imap', 'imap4', 'daemon', 'service', 'iis', 'snmp', 'agent', 'telnet', 'telnetd'})


def _label(vendor, product):
    """The name a reading carries: Recog's product, after its vendor when the product's own name is only generic words or very short
    ("Apache HTTPD", "Microsoft IIS", "AnalogX Proxy")."""
    vendor, product = (vendor or '').strip(), (product or '').strip()
    words = re.findall(r'[a-z0-9]+', product.lower())
    if vendor and (len(product) <= 3 or set(words) <= _GENERIC_WORDS) and not product.lower().startswith(vendor.lower()):
        return f'{vendor} {product}'
    return product


def results(params):
    """What a match states, as ``[{'part', 'label', 'vendor', 'product', 'version', 'cpe', 'network_os'}]``: the service, the service's
    component, the operating system and the hardware (``hw.*``: the device's model and its version), each when it names a product; ``version``
    is '' when the fingerprint states none (an identity: the product is known, its version is not)."""
    out = []
    for part in ('service', 'service.component', 'os', 'hw'):
        product, version = params.get(f'{part}.product'), params.get(f'{part}.version') or ''
        if not product or '{' in product:
            continue
        vendor = params.get(f'{part}.vendor') or ''
        cpe = params.get(f'{part}.cpe23') or ''
        network = NETWORK_OS.get((vendor.lower(), product.lower())) if part == 'os' else None
        out.append({'part': part, 'label': network or _label(vendor, product), 'vendor': vendor, 'product': product, 'version': version,
                    'cpe': cpe, 'network_os': bool(network)})
    return out


# ----------------------------------------------------------------------------- the stored banners each database reads

_SSH = re.compile(r'^SSH-\d{1,2}(?:\.\d{1,2})?-(\S.{0,300})$')
_CODE_220 = re.compile(r'^220[ -]\s*(.*)$')
_POP = re.compile(r'^\+OK\s*(.*)$')
_IMAP = re.compile(r'^\*\s+OK\s+(?:\[[^\]]{0,600}\]\s*)?(.*)$')
_FTP_WORDS = re.compile(r'ftp', re.I)
_SMTP_WORDS = re.compile(r'smtp|e?smtp|mail|postfix|exim|sendmail', re.I)
_SNMP_UPTIME = re.compile(r'^\s*System uptime:', re.I)
_NTP_LINE = re.compile(r'^\s*([a-z_]{2,20}):\s*(.{1,200})$', re.I)
_MYSQL_VERSION = re.compile(r'(?mi)^\s*Version:\s*(\S{1,80})')


def _lines(text):
    return [line.strip() for line in str(text or '').replace('\r', '').split('\n') if line.strip()]


def _service(port):
    return (getattr(port, 'service_name', '') or '').lower()


def banner_texts(port):
    """``[(database, text, said)]`` of one port's stored banner (``Port.banner``): the text in the form Recog's database reads it, and what was
    stored, for the evidence. A banner that is the port scan's service fingerprint of an unidentified service (``cveFeed.servicefp``) is read decoded:
    the greeting its NULL or GenericLines probe got as a banner, and the Server header and cookies of its first HTTP reply."""
    from cveFeed import servicefp
    replies = servicefp.decode(getattr(port, 'banner', '') or '')
    if replies:
        out = []
        first = servicefp.greeting(replies)
        if first:
            out += [(db, text, f'service fingerprint {said}') for db, text, said in _banner_lines([first], port)]
        server = servicefp.http_headers(replies).get('server')
        if server:
            out.append(('http_header.server', server, f'service fingerprint Server: {server}'))
        out += [('http_header.cookie', f'{name}=', f'service fingerprint cookie {name}') for name in servicefp.http_cookies(replies)]
        return out
    return _banner_lines(_lines(getattr(port, 'banner', '') or ''), port)


def _banner_lines(lines, port):
    if not lines:
        return []
    first, service, number = lines[0], _service(port), getattr(port, 'number', 0)
    found = _SSH.match(first)
    if found:
        return [('ssh.banner', found.group(1).strip(), f'SSH banner: {first}')]
    found = _POP.match(first)
    if found and found.group(1):
        return [('pop3.banner', found.group(1).strip(), f'POP3 banner: {first}')]
    found = _IMAP.match(first)
    if found and found.group(1):
        return [('imap4.banner', found.group(1).strip(), f'IMAP banner: {first}')]
    found = _CODE_220.match(first)
    if found and found.group(1):
        if 'ftp' in service or number in (21, 990) or (not ('smtp' in service or number in (25, 465, 587)) and _FTP_WORDS.search(first)):
            return [('ftp.banner', found.group(1).strip(), f'FTP banner: {first}')]
        if 'smtp' in service or 'submission' in service or number in (25, 465, 587) or _SMTP_WORDS.search(first):
            return [('smtp.banner', found.group(1).strip(), f'SMTP banner: {first}')]
        return []
    if 'telnet' in service or number in (23, 2323):
        text = '\n'.join(lines[:20])
        return [('telnet.banner', text, f'telnet banner: {" / ".join(lines[:3])}')]
    return []


def _header_lines(text):
    """``[(lowercase name, value)]`` of the ``Name: value`` lines of a stored header dump, every one (Set-Cookie repeats)."""
    out = []
    for line in _lines(str(text or '')[:8000]):
        name, sep, value = line.partition(':')
        if sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,40}', name.strip()) and value.strip():
            out.append((name.strip().lower(), value.strip()))
    return out


def ntp_readvar(text):
    """``ntp-info``'s ``key: value`` lines in the readvar form Recog's NTP database reads (``version="ntpd 4.2.8p15...", processor="x86_64",
    system="Linux/5.15.0"``), or ''."""
    pairs = []
    for line in _lines(text)[:30]:
        found = _NTP_LINE.match(line)
        if found and found.group(1).lower() not in ('receive time stamp',):
            pairs.append(f'{found.group(1).lower()}="{found.group(2).strip()}"')
    return ', '.join(pairs) if any(p.startswith('version=') for p in pairs) else ''


def sysdescr(text):
    """An SNMP agent's sysDescr as the UDP sweep's ``snmp-sysdescr`` stored it, less the uptime line the script appends."""
    kept = []
    for line in str(text or '').replace('\r', '').split('\n'):
        if _SNMP_UPTIME.match(line):
            break
        kept.append(line.strip())
    return '\n'.join(k for k in kept if k).strip()


def script_texts(port):
    """``[(database, text, said)]`` of one port's stored NSE output (``Port.extra['scripts']``)."""
    extra = port.extra if isinstance(getattr(port, 'extra', None), dict) else {}
    scripts = extra.get('scripts') if isinstance(extra.get('scripts'), dict) else {}
    out = []
    for line in _lines(scripts.get('http-server-header'))[:4]:
        out.append(('http_header.server', line, f'http-server-header: {line}'))
    for name, value in _header_lines(scripts.get('http-headers'))[:60]:
        if name == 'server':
            out.append(('http_header.server', value, f'http-headers Server: {value}'))
        elif name == 'set-cookie':
            out.append(('http_header.cookie', value, f'http-headers Set-Cookie: {value[:80]}'))
    found = _MYSQL_VERSION.search(str(scripts.get('mysql-info') or '')[:4000])
    if found:
        out.append(('mysql.banners', found.group(1), f'mysql-info Version: {found.group(1)}'))
    readvar = ntp_readvar(scripts.get('ntp-info'))
    if readvar:
        out.append(('ntp.banner', readvar, f'ntp-info: {readvar[:160]}'))
    if (getattr(port, 'protocol', '') or '') == 'udp' and isinstance(scripts.get('snmp-sysdescr'), str):
        text = sysdescr(scripts['snmp-sysdescr'])
        if text:
            out.append(('snmp.sys_description', text, f'sysDescr: {text[:200]}'))
    return out


def route_texts(routes):
    """``[(database, text, said)]`` of a host's live routes (``RouteAuth.evidence``): the Server header each kept, and the cookies it set (by
    name: the probe keeps no cookie value, and Recog's cookie patterns read the name)."""
    out, seen = [], set()
    for evidence in routes:
        if not isinstance(evidence, dict):
            continue
        headers = evidence.get('headers') if isinstance(evidence.get('headers'), dict) else {}
        for value in (evidence.get('server'), headers.get('server')):
            if isinstance(value, str) and value.strip() and ('s', value) not in seen:
                seen.add(('s', value))
                out.append(('http_header.server', value.strip(), f'route Server: {value.strip()}'))
        for name in (evidence.get('cookies') or [])[:20] if isinstance(evidence.get('cookies'), list) else ():
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.$!#%&'*+^`|~-]{1,80}", name) and ('c', name) not in seen:
                seen.add(('c', name))
                out.append(('http_header.cookie', f'{name}=', f'route cookie {name}'))
    return out
