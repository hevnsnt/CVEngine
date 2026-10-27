"""The "inventory v1" report a host sends about itself, and what the server accepts of it.

A reporter script (``scripts/inventory``) runs on the machine, so it can see what an external scan cannot: the exact operating system
build, the installed packages and their versions, the patches, what listens. This module is the only gate between that JSON and the
database. The report is untrusted input (a compromised or malicious host can send anything), so nothing is stored as it came:

* the shape is fixed (every key named here, nothing else), the sizes are capped, and a list over its cap is refused, not truncated
  (a silently shortened package list would hide the very packages that matter);
* every string is cleaned (no control, bidirectional or zero-width characters, collapsed whitespace, a length cap) and every field
  with a known form (addresses, hashes, dates, ports, ecosystems) must have it, or is dropped and counted in ``dropped``;
* an item that does not validate costs only itself. A package list with one bad row keeps the rest.

Pure Python (no Django imports) so it is unit-testable on its own. The wire format is documented in docs/HOST-INVENTORY.md.
"""
import ipaddress
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

SCHEMA = 'cvengine-inventory/1'
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 8
MAX_PACKAGES = 15000
MAX_PATCHES = 2000
MAX_SERVICES = 1000
MAX_UNITS = 1000
MAX_FEATURES = 500
MAX_CONTAINERS = 200
MAX_KERNELS = 20
MAX_IPS = 64
MAX_MACS = 16
FAMILIES = ('linux', 'windows', 'macos')
# the package managers and catalogues a reporter reads (what a package's version means, and so how it is compared, depends on it)
ECOSYSTEMS = ('dpkg', 'rpm', 'apk', 'pacman', 'snap', 'flatpak', 'brew', 'win', 'macpkg', 'macapp')
CONTAINER_RUNTIMES = ('docker', 'podman')
CLOCK_SKEW = timedelta(days=1)  # a host clock further ahead than this is not believed

_ID = re.compile(r'^[a-z0-9][a-z0-9._-]{0,39}$')
_HOSTNAME = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$')
_MACHINE_ID = re.compile(r'^[0-9a-f]{64}$')
_MAC = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
_ARCH = re.compile(r'^[A-Za-z0-9_.-]{1,20}$')
_VERSION = re.compile(r'^[\x21-\x7e][\x20-\x7e]{0,99}$')
_PATCH_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$')
_DATE = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
_ISO = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?$')
# what a package manager can put in a version (dpkg, rpm, apk, pacman): no spaces, so free text can never pass as one
_SYSTEM_VERSION = re.compile(r'^[0-9A-Za-z][0-9A-Za-z.+~^:_-]{0,99}$')
_SCRIPT_VERSION = re.compile(r'^[0-9][0-9A-Za-z.+-]{0,19}$')
_CPE = re.compile(r'^cpe:(?:/|2\.3:)[\x21-\x7e]{1,190}$')
# variation selectors are not control characters but are invisible, and a long run of them can carry a hidden message
_INVISIBLE = re.compile('[\ufe00-\ufe0f\U000e0100-\U000e01ef]')
_SPACES = re.compile(r'\s+')
_PROCESS = re.compile(r'^[\w.@+:-]{1,60}$', re.ASCII)
SECURITY_TEXT = {'firewall': 80, 'selinux': 20, 'apparmor': 20, 'auto_updates': 80, 'disk_encryption': 80, 'antivirus': 120,
                 'secure_boot': 20, 'sip': 20, 'gatekeeper': 20}
SECURITY_DAYS = ('antivirus_signature_age_days',)


class InventoryError(ValueError):
    """A report the server refuses outright; ``status`` is the HTTP status that goes with it."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _printable(value):
    """``value`` as one line of text a person or a language model can read without surprises. Compatibility-normalised (NFKC), every
    white-space run one space, and every character that is not printable dropped: that is exactly the control (including the C1 set
    and its CSI), format (bidirectional, zero-width, soft hyphen, word joiner, tag characters), private-use and unassigned
    characters of Unicode, plus the variation selectors."""
    if not (value.isascii() and value.isprintable()):
        value = _INVISIBLE.sub('', _SPACES.sub(' ', unicodedata.normalize('NFKC', value)))
        value = ''.join(c for c in value if c.isprintable())
    return _SPACES.sub(' ', value).strip()


def text(value, limit):
    """``value`` as clean one-line text of at most ``limit`` characters; '' for anything that is not a string."""
    if not isinstance(value, str):
        return ''
    return _printable(value)[:limit]


def _match(value, pattern, limit=300):
    cleaned = text(value, limit)
    return cleaned if pattern.match(cleaned) else ''


def _int(value, low, high):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def too_deep(node, limit=MAX_DEPTH):
    """True when lists and objects nest deeper than ``limit`` (iterative, so the check itself cannot recurse)."""
    stack = [(node, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (list, dict)):
            if depth > limit:
                return True
            stack.extend((child, depth + 1) for child in (item.values() if isinstance(item, dict) else item)
                         if isinstance(child, (list, dict)))
    return False


def parse_time(value):
    """A report timestamp as an aware UTC datetime, or None when it is not an ISO 8601 time."""
    cleaned = text(value, 40)
    if not _ISO.match(cleaned):
        return None
    try:
        parsed = datetime.fromisoformat(cleaned.replace('Z', '+00:00').replace(' ', 'T'))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _time(value, now):
    parsed = parse_time(value)
    return parsed.isoformat() if parsed and parsed <= now + CLOCK_SKEW else ''


def clean_address(value):
    """A host's own address in its compressed form, or '' for what is no use for matching a host: loopback, link-local, multicast,
    the unspecified address, an IPv6 zone suffix (``fe80::1%eth0``) and anything that is not an address."""
    cleaned = text(value, 64).split('%', 1)[0]
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        return ''
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast or address.is_reserved:
        return ''
    return str(address)


def _unique(items):
    return list(dict.fromkeys(items))


def _list(value, name, cap):
    """``value`` as a list within ``cap`` entries; a list over its cap is refused (never cut short)."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise InventoryError(f'{name} must be a list')
    if len(value) > cap:
        raise InventoryError(f'{name} has {len(value)} entries; the limit is {cap}', 413)
    return value


def _host(raw, dropped):
    if not isinstance(raw, dict):
        raise InventoryError('host must be an object')
    reported = _list(raw.get('ips'), 'host.ips', MAX_IPS)
    ips = [a for a in (clean_address(i) for i in reported) if a]
    macs = [m for m in (text(i, 20).lower() for i in _list(raw.get('macs'), 'host.macs', MAX_MACS)) if _MAC.match(m)]
    host = {'hostname': _match(raw.get('hostname'), _HOSTNAME, 253), 'fqdn': _match(raw.get('fqdn'), _HOSTNAME, 253).lower(),
            'machine_id': _match(raw.get('machine_id'), _MACHINE_ID, 64), 'ips': _unique(ips), 'macs': _unique(macs)}
    dropped['addresses'] = len(reported) - len(host['ips'])
    if not (host['hostname'] or host['fqdn'] or host['machine_id'] or host['ips']):
        raise InventoryError('host needs at least a hostname, an address or a machine_id')
    return host


def _os(raw, now):
    if not isinstance(raw, dict):
        raise InventoryError('os must be an object')
    family = text(raw.get('family'), 16).lower()
    if family not in FAMILIES:
        raise InventoryError(f'os.family must be one of {", ".join(FAMILIES)}')
    name = text(raw.get('name'), 120)
    if not name:
        raise InventoryError('os.name is required')
    like = [i for i in (text(x, 40).lower() for x in (raw.get('id_like') if isinstance(raw.get('id_like'), list) else [])[:5]) if _ID.match(i)]
    return {'family': family, 'id': _match(raw.get('id'), _ID, 40), 'id_like': like, 'name': name,
            'version': _match(raw.get('version'), _VERSION, 60), 'build': _match(raw.get('build'), _VERSION, 60),
            'codename': text(raw.get('codename'), 40), 'pretty': text(raw.get('pretty'), 160), 'edition': text(raw.get('edition'), 80),
            'kernel': _match(raw.get('kernel'), _VERSION, 80), 'arch': _match(raw.get('arch'), _ARCH, 20),
            'cpe': _match(raw.get('cpe'), _CPE, 200), 'last_boot': _time(raw.get('last_boot'), now),
            'last_update': _time(raw.get('last_update'), now)}


def _package(raw):
    if not isinstance(raw, dict):
        return None
    name, ecosystem = text(raw.get('n'), 200), text(raw.get('e'), 12).lower()
    if not name or ecosystem not in ECOSYSTEMS:
        return None
    version = _match(raw.get('v'), _SYSTEM_VERSION if ecosystem in PURL_TYPES else _VERSION, 100)
    out = {'n': name, 'v': version, 'e': ecosystem}
    arch, source = _match(raw.get('a'), _ARCH, 20), text(raw.get('s'), 200)
    if arch:
        out['a'] = arch
    if source and source != name:
        out['s'] = source
    return out


def _packages(raw, dropped):
    items = _list(raw, 'packages', MAX_PACKAGES)
    seen, out = set(), []
    for item in items:
        pkg = _package(item)
        if pkg is None:
            continue
        key = (pkg['e'], pkg['n'], pkg['v'], pkg.get('a', ''))
        if key not in seen:
            seen.add(key)
            out.append(pkg)
    dropped['packages'] = len(items) - len(out)
    return out


def _patches(raw, dropped):
    items = _list(raw, 'patches', MAX_PATCHES)
    out = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        ident = _match(item.get('i'), _PATCH_ID, 40)
        if ident and ident not in out:
            installed = text(item.get('t'), 10)
            out[ident] = {'i': ident, 't': installed if _DATE.match(installed) else '', 'd': text(item.get('d'), 100)}
    dropped['patches'] = len(items) - len(out)
    return list(out.values())


def _services(raw, dropped):
    items = _list(raw, 'services', MAX_SERVICES)
    out = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        proto, port = text(item.get('p'), 3).lower(), _int(item.get('n'), 1, 65535)
        address = '*' if text(item.get('a'), 4) == '*' else clean_address(item.get('a'))
        if proto not in ('tcp', 'udp') or port is None or not address:
            continue
        out.setdefault((proto, address, port), {'p': proto, 'a': address, 'n': port, 'x': _match(item.get('x'), _PROCESS, 60)})
    dropped['services'] = len(items) - len(out)
    return sorted(out.values(), key=lambda s: (s['n'], s['p'], s['a']))


def _runtime(raw):
    raw = raw if isinstance(raw, dict) else {}
    reboot = raw.get('reboot_required')
    containers = {}
    for item in _list(raw.get('containers'), 'runtime.containers', MAX_CONTAINERS):
        if isinstance(item, dict) and text(item.get('rt'), 12).lower() in CONTAINER_RUNTIMES and text(item.get('image'), 200):
            containers[(text(item['rt'], 12).lower(), text(item['image'], 200))] = {'rt': text(item['rt'], 12).lower(), 'image': text(item['image'], 200)}
    units = [u for u in (text(x, 100) for x in _list(raw.get('units'), 'runtime.units', MAX_UNITS)) if u]
    features = [f for f in (text(x, 100) for x in _list(raw.get('features'), 'runtime.features', MAX_FEATURES)) if f]
    kernels = [k for k in (_match(x, _VERSION, 80) for x in _list(raw.get('kernels_installed'), 'runtime.kernels_installed', MAX_KERNELS)) if k]
    return {'reboot_required': reboot if isinstance(reboot, bool) else None, 'kernels_installed': _unique(kernels),
            'containers': list(containers.values()), 'units': _unique(units), 'features': _unique(features)}


def _security(raw):
    raw = raw if isinstance(raw, dict) else {}
    out = {key: text(raw.get(key), limit) for key, limit in SECURITY_TEXT.items() if text(raw.get(key), limit)}
    for key in SECURITY_DAYS:
        if _int(raw.get(key), 0, 36500) is not None:
            out[key] = raw[key]
    return out


def _script(raw):
    raw = raw if isinstance(raw, dict) else {}
    name = text(raw.get('name'), 40)
    version = text(raw.get('version'), 20)
    return {'name': name if _ID.match(name.lower()) else '', 'version': version if _SCRIPT_VERSION.match(version) else ''}


def validate(report, now=None):
    """The cleaned report for a decoded JSON body. Raises InventoryError for a report that cannot be used at all (not an object,
    another schema, no way to tell which machine it is, a list past its cap); anything smaller that does not validate is dropped and
    counted in ``dropped``."""
    now = now or datetime.now(timezone.utc)
    if not isinstance(report, dict):
        raise InventoryError('the report must be a JSON object')
    if too_deep(report):
        raise InventoryError('the report nests too deeply')
    schema = text(report.get('schema'), 40)
    if not schema.startswith('cvengine-inventory/'):
        raise InventoryError(f'schema must be {SCHEMA}')
    if schema != SCHEMA:
        raise InventoryError(f'this server reads {SCHEMA}, not {schema[:40]}: update the server or the reporter script')
    dropped = {}
    host = _host(report.get('host'), dropped)
    return {'schema': SCHEMA, 'script': _script(report.get('script')), 'collected_at': _time(report.get('collected_at'), now),
            'host': host, 'os': _os(report.get('os'), now), 'packages': _packages(report.get('packages'), dropped),
            'patches': _patches(report.get('patches'), dropped), 'services': _services(report.get('services'), dropped),
            'runtime': _runtime(report.get('runtime')), 'security': _security(report.get('security')),
            'dropped': {k: v for k, v in dropped.items() if v}}


def is_version_text(value):
    """Whether ``value`` is plain version text (no spaces, only what a version can hold), safe to show as the version of a match."""
    return bool(_SYSTEM_VERSION.match(value or ''))


def machine_key(host):
    """What names one machine across its reports: its app-specific machine id hash, else its lowercase host name."""
    if host.get('machine_id'):
        return host['machine_id']
    return 'h:' + (host.get('fqdn') or host.get('hostname') or ','.join(host.get('ips') or [])).lower()


# --- package identity: purl style -------------------------------------------------------------------------------------

PURL_TYPES = {'dpkg': 'deb', 'rpm': 'rpm', 'apk': 'apk', 'pacman': 'alpm'}


def _enc(value):
    return quote(value, safe='~:.-_') if value else ''


def distro_of(os_block, ecosystem):
    """``(vendor, release)`` of the distribution a system package belongs to: the os-release ID and VERSION_ID (Alpine's own version
    for apk). Empty for a catalogue that is not a distribution's."""
    if ecosystem not in PURL_TYPES:
        return '', ''
    vendor = 'alpine' if ecosystem == 'apk' else os_block.get('id') or ''
    return vendor, os_block.get('version') or ''


def purl(pkg, os_block):
    """The package URL (https://github.com/package-url/purl-spec) of one package, with its distribution when it has one:
    ``pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04``. System packages use their registered purl type
    (deb, rpm, apk, alpm); a catalogue that has none (snap, flatpak, brew, Windows and macOS software) is ``pkg:generic`` with the
    catalogue named in an ``ecosystem`` qualifier, so no type is invented."""
    ecosystem, name, version = pkg['e'], pkg['n'], pkg.get('v', '')
    vendor, release = distro_of(os_block, ecosystem)
    qualifiers = {}
    if pkg.get('a'):
        qualifiers['arch'] = pkg['a']
    if ecosystem in PURL_TYPES:
        if ecosystem == 'rpm' and re.match(r'^[0-9]+:', version):
            qualifiers['epoch'], version = version.split(':', 1)
        if vendor:
            qualifiers['distro'] = f'{vendor}-{release}' if release else vendor
        head = f'pkg:{PURL_TYPES[ecosystem]}/{_enc(vendor or "unknown")}/{_enc(name.lower() if ecosystem != "rpm" else name)}'
    else:
        qualifiers['ecosystem'] = ecosystem
        head = f'pkg:generic/{_enc(name)}'
    query = '&'.join(f'{k}={_enc(v)}' for k, v in sorted(qualifiers.items()))
    return head + (f'@{_enc(version)}' if version else '') + (f'?{query}' if query else '')


def identity(pkg, os_block):
    """One package in the normalised form the API returns and correlation reads: name, version, ecosystem, distribution,
    architecture, source package and purl."""
    vendor, release = distro_of(os_block, pkg['e'])
    return {'name': pkg['n'], 'version': pkg.get('v', ''), 'ecosystem': pkg['e'], 'distro': vendor, 'distro_release': release,
            'arch': pkg.get('a', ''), 'source': pkg.get('s', ''), 'purl': purl(pkg, os_block)}
