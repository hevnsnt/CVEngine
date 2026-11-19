"""Which hosts run a product, at which version, and which ones have no version known: the names behind the host search's ``tech:`` filter.

``tech:<name>`` is the one way to ask "which hosts run X" (``agentapi.services`` builds the query; this module reads the name). A host runs X when
any place its software is recorded names it: a technology row, an open port's product or CPE, the Server header the web check stored, a live
route's headers and fingerprints, a version source reading (first- or third-party, a product or a language runtime), and for Java a Java runtime
reading. A name is matched three ways, and a host is found by any of them:

* as text, inside what was stored (``tech:php`` finds a PHPSESSID cookie): what ``tech:`` always did, so no search loses a host;
* as the same product, through the product name normalisation correlation uses: the name read as ``tech_coverage.normalise_sighting`` reads it
  (a ``Name:version``, a ``product/version`` header token, a CPE, a detector's template word or rename), reduced to correlation's token
  (``correlation._norm``), widened to every spelling ``data/product_aliases.json`` gives the same software (``tech:apache httpd``,
  ``tech:apache http server`` and ``tech:apachegeneric`` are one product), and compared the way ``correlation.name_matches_token`` compares
  names: the same token, with a vendor in front ("Apache Tomcat" for ``tomcat``) or descriptive words, an edition or a detector's template word
  after it ("Grafana OSS", "nginx version"), never a longer different product ("php" is not "phpMyAdmin");
* through what it runs on (``data/runs_on.json``): a host showing WordPress runs PHP, a host showing Tomcat runs Java (Java's products are
  ``java_runtime.JAVA_PRODUCT_RE``, the rule that makes a host a candidate for runtime CVEs), so ``tech:php`` and ``tech:java`` find them.

After ``@``, the version state, with the syntax ``component:`` and ``runtime:`` use: ``@unknown`` (or ``@none``) a host that runs it where no
source states a version of that product (for a platform found through what runs on it: no reading of the platform itself), ``@known`` the
opposite, ``@<version>`` that release (a prefix: 7.1 finds 7.1 and 7.1.4, never 7.10). Everything here is a pure function of the name: the
regular expressions it returns are written so the database (PostgreSQL ``~*``) and Python (the results' explanation) read them the same way."""
import functools
import json
import os
import re
from dataclasses import dataclass

from cveFeed import correlation

RUNS_ON_FILE = os.path.join(os.path.dirname(__file__), 'data', 'runs_on.json')
ANY, UNKNOWN, KNOWN, RELEASE = 'any', 'unknown', 'known', 'release'
STATES = {'any': ANY, 'all': ANY, 'yes': ANY, 'unknown': UNKNOWN, 'none': UNKNOWN, 'unread': UNKNOWN, 'known': KNOWN}
_RELEASE = re.compile(r'^v?(\d[0-9a-z._+~-]{0,39})$', re.IGNORECASE)  # 7.1, 2.4.52, 8u392, 1.0.2k, 22.4R2
MAX_NAME = 200  # MAX_SEARCH_VALUE: a bare word and its version (techver) is read here too
_SEP = '[^a-z0-9]'
# words a detector appends to a product's name ("Nginx version", "Microsoft IIS Detect"): correlation.tech_name drops them
_TEMPLATE_WORDS = ('version', 'detect', 'detected', 'detection', 'fingerprint')
_VERSION_GAP = r'(?:\s*[:/_-]\s*|\s+)v?'  # what sits between a name and its version: "PHP:8.1", "nginx/1.24.0", "OpenSSH_9.6p1", "Tomcat 10.1"


def _token(text):
    return re.sub(r'[^a-z0-9]', '', str(text or '').lower())


def _words(text):
    return tuple(re.findall(r'[a-z0-9]+', str(text or '').lower()))


def _interleave(token):
    """A token as a pattern that matches every spelling ``correlation._norm`` reduces to it: case and punctuation between its characters are
    free ("phpMyAdmin", "php-my-admin"), nothing else is."""
    return f'{_SEP}*'.join(token)


def _alts(items):
    return '|'.join(sorted(set(items), key=lambda s: (-len(s), s)))


def _usable(spelling):
    """A spelling that can stand for a product as a whole name: long enough, not a generic label, and not only words that describe a product
    ("HTTP Server": Apache's and Oracle's both)."""
    token = _token(spelling)
    if len(token) < correlation._MIN_TOKEN or token in correlation.GENERIC_PRODUCT_TOKENS:
        return False
    return not all(w in correlation._TRAILER_WORDS or w in correlation.GENERIC_WORDS for w in _words(spelling))


@functools.lru_cache(maxsize=1)
def _alias_groups():
    """Every set of spellings ``data/product_aliases.json`` says name one product: an alias entry (its names and products, with the vendors its
    CPEs must name), a restricted name list, a rename (the detector's name and the product it reads as), and the names whose stated version is a
    protocol's (``protocol``: never a version of the product)."""
    with open(correlation.ALIASES_FILE, encoding='utf-8') as fh:
        doc = json.load(fh)
    groups = []  # (names a detector reports, products a record names, vendors its CPEs name)
    for entry in doc.get('aliases', ()):
        groups.append((tuple(entry.get('names', ())), tuple(entry.get('products', ())), tuple(entry.get('vendors', ()))))
    for entry in doc.get('restrict', ()):
        groups.append((tuple(entry.get('names', ())), (), tuple(entry.get('vendors', ()))))
    for entry in doc.get('renames', ()):
        groups.append((tuple(entry.get('names', ())), (entry['to'],) if entry.get('to') else (), ()))
    protocol = tuple(name for entry in doc.get('protocol_versions', ()) for name in entry.get('names', ()))
    return tuple(groups), protocol


@dataclass(frozen=True)
class Platform:
    key: str
    label: str
    names: tuple        # what a search for the platform may be typed as
    runtime: str        # the version_sources runtime component that states its own version, or 'java_runtime'
    py_pattern: str     # the products that run on it, as a Python pattern (re.IGNORECASE)

    @property
    def pg_pattern(self):
        return self.py_pattern.replace(r'\b', r'\y')  # PostgreSQL's word boundary

    def product_re(self):
        return re.compile(self.py_pattern, re.IGNORECASE)


def _product_pattern(entry):
    if entry.get('pattern'):
        alternatives = [entry['pattern']]
    else:
        alternatives = []
    for name in entry.get('names', ()):
        words = [re.escape(w) for w in str(name).lower().split()]
        alternatives.append(r'(?<![a-z0-9])' + r'[\s_-]+'.join(words) + r'(?![a-z0-9])')
    return '|'.join(f'(?:{a})' for a in alternatives)


@functools.lru_cache(maxsize=1)
def platforms():
    """``{key: Platform}`` from ``data/runs_on.json``; Java's products are ``java_runtime.JAVA_PRODUCT_RE``."""
    from cveFeed import java_runtime
    with open(RUNS_ON_FILE, encoding='utf-8') as fh:
        doc = json.load(fh)
    out = {}
    for entry in doc.get('platforms', ()):
        if entry.get('products_from') == 'cveFeed.java_runtime.JAVA_PRODUCT_RE':
            pattern = java_runtime.JAVA_PRODUCT_RE.pattern
        else:
            pattern = '|'.join(f'(?:{_product_pattern(p)})' for p in entry.get('products', ()))
        out[entry['key']] = Platform(entry['key'], entry['label'], tuple(entry.get('names', ())), entry.get('runtime', ''), pattern)
    return out


def platform_of(name):
    """The platform ``name`` names (``java``, ``JDK``, ``php``, ``asp.net``, ``node.js`` ...), or None."""
    token = _token(name)
    for platform in platforms().values():
        if token and token in {_token(n) for n in platform.names}:
            return platform
    return None


def _group_of(spelling):
    """``(keys, cpe pairs)``: the tokens of every spelling of the product ``spelling`` names (``data/product_aliases.json``, compared with
    ``correlation.name_matches_token``), and the (vendors, products) its CPEs carry. A name a detector reports is taken as the aliases list it;
    the typed name and a record's product only when they can stand for a product on their own (``_usable``: never "HTTP Server")."""
    token = correlation._norm(spelling)
    keys, pairs = {token} if _usable(spelling) else set(), []
    groups, _protocol = _alias_groups()
    for names, products, vendors in groups:
        tokens = {correlation._norm(n) for n in (*names, *products)}
        if token in tokens or any(t and correlation.name_matches_token(token, t) for t in tokens):
            keys.update(_token(n) for n in names if len(_token(n)) >= correlation._MIN_TOKEN and _token(n) not in correlation.GENERIC_PRODUCT_TOKENS)
            keys.update(_token(p) for p in products if _usable(p))
            if vendors:
                pairs.append((tuple(vendors), tuple(products or names)))
    return keys, pairs


def base_name(name):
    """The product a typed name names, read as the coverage report reads a sighting (``tech_coverage.normalise_sighting``: a
    ``Name:version``, a ``product/version`` token or a CPE split off, a detector's template word or rename applied)."""
    from cveFeed import tech_coverage
    return tech_coverage.normalise_sighting(name)['name'] or str(name or '').strip()


@dataclass(frozen=True)
class Spec:
    """One ``tech:`` value: ``raw`` (the name as typed, lowercase, for the text match), ``state`` (ANY, UNKNOWN, KNOWN or RELEASE), ``release`` (the
    release prefix of RELEASE), ``keys`` (the tokens of every spelling of the product), ``cpe_pairs`` and ``platform``."""
    raw: str
    label: str
    state: str
    release: str
    keys: tuple
    cpe_pairs: tuple
    protocol_keys: tuple
    platform: object

    # ------------------------------------------------------------------ patterns (one string: PostgreSQL ~* and Python re.IGNORECASE)
    def _head(self, keys=None):
        keys = self.keys if keys is None else keys
        vendors = _alts(correlation.VENDOR_PREFIX_WORDS)
        trailers = _alts([*correlation._TRAILER_WORDS, *_TEMPLATE_WORDS])
        return rf'{_SEP}*(?:(?:{vendors}){_SEP}+)*(?:{_alts(_interleave(k) for k in keys)})(?:{_SEP}+(?:{trailers}))*'

    def _tail(self, versioned):
        """What follows a name: any version or none, or (``versioned``) a version, at the release when one was asked."""
        if not versioned:
            return rf'(?:{_VERSION_GAP}[0-9].*)?(?:\s*\(.*\))?$'
        if self.state == RELEASE:
            return rf'{_VERSION_GAP}{re.escape(self.release)}(?:$|[^0-9])'
        return rf'{_VERSION_GAP}[0-9]'

    @property
    def stating_keys(self):
        """The spellings whose stated version is this product's (``protocol_versions``: "Apache Tomcat/Coyote JSP engine 1.1" is Tomcat, at no
        release of it)."""
        return tuple(k for k in self.keys if k not in self.protocol_keys)

    def name_re(self, versioned=False, stating=False):
        """A stored name (a technology, a port's product, a reading's product) that is this product, with its version in the name when
        ``versioned``; ``stating``: only a spelling whose version is the product's. '' when no spelling can be compared as a whole name (the
        text match alone applies)."""
        keys = self.stating_keys if versioned or stating else self.keys
        return rf'^{self._head(keys)}{self._tail(versioned)}' if keys else ''

    def header_re(self, versioned=False):
        """A token of a Server or X-Powered-By header ("nginx/1.18 PHP/8.1", "Microsoft-IIS/10.0") that is this product."""
        if not self.keys or versioned and not self.stating_keys:
            return ''
        if versioned:
            release = re.escape(self.release) + '(?:$|[^0-9])' if self.state == RELEASE else '[0-9]'
            return rf'(?:^|[\s(,;]){self._head(self.stating_keys)}/v?{release}'
        return rf'(?:^|[\s(,;]){self._head()}(?:$|[\s/;,()])'

    def fingerprint_re(self, versioned=False):
        """A name in a route's fingerprint list (``["PHP:8.2.30"]``) that is this product."""
        if not self.keys or versioned and not self.stating_keys:
            return ''
        if versioned:
            release = re.escape(self.release) + '(?:$|[^0-9])' if self.state == RELEASE else '[0-9]'
            return rf'(?:^|"){self._head(self.stating_keys)}{_VERSION_GAP}{release}'
        return rf'(?:^|"){self._head()}(?:{_VERSION_GAP}[0-9][^"]*)?(?:"|$)'

    def cpe_re(self, versioned=False):
        """A CPE that names this product: any vendor with a spelling of the product, or a vendor and product the aliases pair."""
        alternatives = [rf'[^:]*:{_SEP}*(?:{_alts(_interleave(k) for k in self.keys)})'] if self.keys else []
        for vendors, products in self.cpe_pairs:
            vtokens = [_token(v) for v in vendors if _token(v)]
            ptokens = [_token(p) for p in products if len(_token(p)) >= correlation._MIN_TOKEN]
            if vtokens and ptokens:
                alternatives.append(rf'{_SEP}*(?:{_alts(_interleave(v) for v in vtokens)}):{_SEP}*(?:{_alts(_interleave(p) for p in ptokens)})')
        if not alternatives:
            return ''
        if not versioned:
            tail = '(?::|$)'
        elif self.state == RELEASE:
            tail = rf':v?{re.escape(self.release)}(?:$|[^0-9])'
        else:
            tail = ':v?[0-9]'
        return rf'^cpe:(?:/|2\.3:)a:(?:{"|".join(alternatives)}){tail}'

    def release_re(self):
        """A stored version that states a version (KNOWN and UNKNOWN), or this release (RELEASE): 7.1 finds 7.1 and 7.1.4, never 7.10."""
        if self.state == RELEASE:
            return rf'^v?{re.escape(self.release)}(?:$|[^0-9])'
        return r'^v?[0-9]'

    # ------------------------------------------------------------------ the same rules in Python, for the results' explanation
    @functools.cached_property
    def _py(self):
        compile_ = lambda p: re.compile(p, re.IGNORECASE) if p else None  # noqa: E731
        return {'name': compile_(self.name_re()), 'stating': compile_(self.name_re(stating=True)), 'name_v': compile_(self.name_re(True)),
                'header': compile_(self.header_re()), 'header_v': compile_(self.header_re(True)),
                'fingerprint': compile_(self.fingerprint_re()), 'fingerprint_v': compile_(self.fingerprint_re(True)),
                'cpe': compile_(self.cpe_re()), 'cpe_v': compile_(self.cpe_re(True)), 'release': compile_(self.release_re()),
                'platform': self.platform.product_re() if self.platform else None}

    def matches(self, kind, text):
        """Whether ``text`` matches this spec's ``kind`` of pattern: ``name``, ``stating`` and ``name_v`` (``name_re``), ``header`` and
        ``header_v``, ``fingerprint`` and ``fingerprint_v``, ``cpe`` and ``cpe_v``, or ``platform`` (a product that runs on the platform)."""
        found = self._py[kind]
        return bool(found and text and found.search(str(text)[:300]))

    def version_ok(self, version):
        """Whether a stated ``version`` is one this spec's state asks for: any version, or the release for RELEASE."""
        return bool(version) and bool(self._py['release'].search(str(version)))


def parse(value):
    """The Spec of a ``tech:`` value (``php``, ``apache httpd``, ``wordpress@unknown``, ``tomcat@10.1``, ``java@known``), or None for one it cannot
    read: an empty name, one longer than MAX_NAME, or a qualifier after ``@`` that is neither a state nor a release."""
    text = (value or '').strip()
    name, release, state = text, '', ANY
    if '@' in text:
        name, _sep, qualifier = text.rpartition('@')
        qualifier = qualifier.strip().lower()
        if qualifier in STATES:
            state = STATES[qualifier]
        elif _RELEASE.match(qualifier):
            state, release = RELEASE, _RELEASE.match(qualifier).group(1)
        else:
            return None
    name = name.strip()
    if not name or len(name) > MAX_NAME:
        return None
    platform = platform_of(name)
    base = base_name(name)
    keys, pairs = _group_of(base)
    if platform:
        for other in platform.names:
            more, more_pairs = _group_of(other)
            keys |= more
            pairs += more_pairs
        if platform.key == 'java' and release.startswith('1.'):  # Java's own legacy spelling: 1.8.0_392 is 8u392, 1.8 the line 8
            from cvengine_scanner import java
            norm = java.normalize_version(release)
            if norm:
                release = str(norm['major']) if norm['line_only'] else norm['version']
    keys = tuple(sorted(keys))
    pairs = tuple(dict.fromkeys(pairs))
    _groups, protocol = _alias_groups()
    protocol_keys = tuple(sorted({_token(p) for p in protocol} & set(keys)))  # "Apache Tomcat/Coyote JSP engine 1.1" names Tomcat, not its release
    label = platform.label if platform else name
    return Spec(name.lower(), label, state, release, keys, pairs, protocol_keys, platform)
