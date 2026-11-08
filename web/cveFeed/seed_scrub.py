"""The last check before a CVE seed leaves this instance: nothing of the tenant may be in it.

A seed is meant to be shared with another install, so it must hold public CVE data and shared detection records and nothing about the
instance that wrote it. The records are built from the catalog and from model-written text (a summary, the plain-language steps of a
detection record, a reason), and a model that was shown a host or a person's note can repeat it. So every string of every record is read
here, and a record that mentions this instance's organizations, projects, domains, host names or addresses, or that looks like a secret
or an internal path, is dropped and counted (``dropped`` in the manifest says how many, by what kind of reason, and for which CVE; it never
says what was found).

Two kinds of fields. The model-written and detection fields are *strict*: they are scanned for everything, including private addresses,
internal paths, assignments like ``password=...`` and long random-looking tokens. The feed's own fields (title, description, references, ...)
are public text from outside; they are scanned for tenant names and secrets too, but a tenant name that turns up in more than
``PUBLIC_TERM_RECORDS`` feed records is a public name (a project named after a well-known vendor, a target that is a public site): it is
ignored in the feed fields and still enforced in the strict ones.
"""
import ipaddress
import math
import re
from collections import Counter

PUBLIC_TERM_RECORDS = 50
MIN_NAME = 5
GENERIC_NAMES = frozenset({'default', 'project', 'projects', 'example', 'sample', 'demo', 'admin', 'public', 'private', 'internal', 'production',
                           'staging', 'security', 'company', 'organization', 'organisation', 'testing', 'global', 'servers', 'network'})
STRICT_FIELDS = ('summary', 'summary_model', 'detection')
REASONS = ('tenant_name', 'tenant_host', 'tenant_address', 'private_address', 'secret', 'internal_path')

_HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+')
_V4 = re.compile(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9]|\.[0-9]|-[0-9A-Za-z])')  # not a longer version string (10.3.6.0.0, 10.2.1.9-57sv)
_HOSTLIKE = re.compile(r'(?i)(?:\b(?:host|ip|address|addr) |://|@)(' + _V4.pattern + r')|(' + _V4.pattern + r')(?=:\d{2,5}\b|/\d{1,2}\b)')
_V6 = re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])')

SECRET_PATTERNS = [re.compile(p) for p in (
    r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY',
    r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b',
    r'\bgh[pousr]_[A-Za-z0-9]{30,}',
    r'\bgithub_pat_[A-Za-z0-9_]{30,}',
    r'\bglpat-[A-Za-z0-9_-]{16,}',
    r'\bxox[abposr]-[A-Za-z0-9-]{10,}',
    r'hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+',
    r'\bsk-ant-[A-Za-z0-9_-]{10,}',
    r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}',
    r'\b[sprw]k_(?:live|test)_[A-Za-z0-9]{16,}',
    r'\bAIza[0-9A-Za-z_-]{35}\b',
    r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',
    r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}',
    r'\b[a-z]{2,10}_(?:live|test|prod|secret|token|pat)_[A-Za-z0-9]{16,}',
    r'(?i)\b(?:tok|token|secret|apikey|api-key|pat)[_-][A-Za-z0-9]{24,}',
)]
_URL_CREDENTIALS = re.compile(r'(?i)\b[a-z][a-z0-9+.-]*://([^\s/:@]+):([^\s/@]+)@')  # credentials inside a URL
_PLACEHOLDER = re.compile(r'(?i)^(?:user(?:name)?|pass(?:word)?|admin|root|login|secret|xxx+|\*+|\.+|[<{$%\[].*)$')
# an assignment of a value to a secret-sounding name, and a long run of random-looking characters: strict fields only (a CVE description
# legitimately says "the password parameter" or quotes a proof of concept)
_ASSIGNED = re.compile(r'(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?key|access[_-]?key|credential)s?["\']?\s*[:=]\s*["\']?(?!\$|\{|<|%|\*|x{3,})(?=[^\s"\',;]*\d)[^\s"\',;]{8,}')  # a value with a digit in it
_RANDOM = re.compile(r'[A-Za-z0-9+=]{32,}')  # no '-' or '_': a hyphenated slug of words is not a token
_PATHS = re.compile(r'/usr/src/(?:app|scan_results|github)\b|/root/\.config|/root/nuclei-templates|/var/lib/cvengine|(?<![A-Za-z0-9._-])/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._ -]+|[A-Za-z]:\\Users\\')
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', 'fc00::/7', 'fe80::/10')]


def _entropy(text):
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _strings(value):
    """Every string inside a JSON-like value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _normal_ip(text):
    try:
        return str(ipaddress.ip_address(text.strip('[]').split('%')[0]))
    except ValueError:
        return None


class Scrub:
    """What this instance calls its own, and the scan that finds it in a record."""

    def __init__(self, names=(), hosts=(), addresses=()):
        names = {n.strip().lower() for n in names if isinstance(n, str)}
        self.names = {n for n in names if len(n) >= MIN_NAME and n not in GENERIC_NAMES}
        self.hosts = {h.strip().lower().rstrip('.') for h in hosts if isinstance(h, str) and '.' in h}
        self.addresses = set()
        for a in addresses:
            if isinstance(a, str) and (ip := _normal_ip(a)):
                self.addresses.add(ip)
        self.hosts -= self.addresses
        self.name_re = (re.compile(r'(?<![A-Za-z0-9])(?:' + '|'.join(re.escape(n) for n in sorted(self.names, key=len, reverse=True)) + r')(?![A-Za-z0-9])',
                                   re.IGNORECASE) if self.names else None)
        self.ignored = set()  # tenant terms found to be public in the feed fields (see ``learn``)

    @property
    def size(self):
        return len(self.names) + len(self.hosts) + len(self.addresses)

    @classmethod
    def from_database(cls):
        """This instance's own names, hosts and addresses, from every table that holds them."""
        from dashboard.models import Org, Project
        from cveFeed.models import HostInventory, TailscaleDevice
        from startScan.models import IpAddress, Subdomain
        from targetApp.models import Domain
        names, hosts, addresses = set(), set(), set()
        for model in (Org, Project):
            for name, slug in model.objects.values_list('name', 'slug').iterator():
                names.update((name, slug))
        for (name,) in Domain.objects.values_list('name').distinct().iterator(chunk_size=5000):
            hosts.add(name)
            addresses.add(name)
        for (name,) in Subdomain.objects.values_list('name').distinct().iterator(chunk_size=5000):
            hosts.add(name)
            addresses.add(name)
        for (address,) in IpAddress.objects.values_list('address').distinct().iterator(chunk_size=5000):
            addresses.add(address)
        for name, device_addresses in TailscaleDevice.objects.values_list('name', 'addresses').iterator():
            hosts.add(name)
            addresses.update(a for a in (device_addresses or []) if isinstance(a, str))
        for (name,) in HostInventory.objects.exclude(hostname='').values_list('hostname').distinct().iterator():
            hosts.add(name)
        return cls(names, hosts, addresses)

    # --- scanning -----------------------------------------------------------------------------------------------------------

    def _tenant_hits(self, text, skip_ignored=False):
        """The (reason, term) pairs of this instance's own names, hosts and addresses found in ``text``."""
        found = set()
        if self.name_re:
            for match in self.name_re.finditer(text):
                found.add(('tenant_name', match.group(0).lower()))
        if self.hosts or self.addresses:
            lowered = text.lower()
            for token in _HOST.findall(lowered):
                labels = token.rstrip('.').split('.')
                for start in range(len(labels) - 1):  # a.b.example.com: also b.example.com and example.com
                    candidate = '.'.join(labels[start:])
                    if candidate in self.hosts:
                        found.add(('tenant_host', candidate))
                        break
            for token in _V4.findall(text):
                if (ip := _normal_ip(token)) and ip in self.addresses:
                    found.add(('tenant_address', ip))
            if ':' in text:
                for token in _V6.findall(text):
                    if token.count(':') >= 2 and (ip := _normal_ip(token)) and ip in self.addresses:
                        found.add(('tenant_address', ip))
        if skip_ignored:
            found = {pair for pair in found if pair[1] not in self.ignored}
        return found

    def learn(self, texts_by_record):
        """Pass one over the feed fields: a tenant term that appears in more than PUBLIC_TERM_RECORDS records' feed text is public."""
        counts = Counter()
        for texts in texts_by_record:
            seen = set()
            for text in texts:
                seen.update(term for _, term in self._tenant_hits(text))
            counts.update(seen)
        self.ignored = {term for term, n in counts.items() if n > PUBLIC_TERM_RECORDS}
        return self.ignored

    def _general(self, text, strict):
        reasons = set()
        if any(p.search(text) for p in SECRET_PATTERNS) or any(not (_PLACEHOLDER.match(u) and _PLACEHOLDER.match(w)) for u, w in _URL_CREDENTIALS.findall(text)):
            reasons.add('secret')
        if strict:
            if _ASSIGNED.search(text):
                reasons.add('secret')
            for run in _RANDOM.findall(text):
                if any(c.isdigit() for c in run) and any(c.isalpha() for c in run) and _entropy(run) >= 4.2:
                    reasons.add('secret')
                    break
            if _PATHS.search(text):
                reasons.add('internal_path')
            # a private address in the position of a host (after ://, @, "host", "ip", "address"; before :port or /prefix): the
            # same four numbers in "older than 10.3.183.67" are a version
            for token in [m.group(1) or m.group(2) for m in _HOSTLIKE.finditer(text)] + [t for t in _V6.findall(text) if t.count(':') >= 2]:
                ip = _normal_ip(token)
                if ip and any(ipaddress.ip_address(ip) in net for net in _PRIVATE_NETS if net.version == ipaddress.ip_address(ip).version):
                    reasons.add('private_address')
        return reasons

    def check(self, value, strict):
        """The reasons ``value`` (any JSON-like value) may not be exported: a set of REASONS, empty when it is clean."""
        reasons = set()
        for text in _strings(value):
            if len(text) < 4:
                continue
            reasons.update(reason for reason, _ in self._tenant_hits(text, skip_ignored=not strict))
            reasons.update(self._general(text, strict))
        return reasons

    def check_record(self, record):
        """``(record_reasons, detection_reasons)``: why the whole line may not go, and why only its detection block may not."""
        whole = set()
        for field, value in record.items():
            if field == 'detection' or field in STRICT_FIELDS:
                if field != 'detection':
                    whole |= self.check(value, strict=True)
            else:
                whole |= self.check(value, strict=False)
        return whole, self.check(record.get('detection'), strict=True) if record.get('detection') else set()

    @staticmethod
    def feed_texts(record):
        return [t for field, value in record.items() if field != 'detection' and field not in STRICT_FIELDS for t in _strings(value) if len(t) >= 4]
