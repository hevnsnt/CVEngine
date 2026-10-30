"""Correlate stored cve.now entries against the discovered asset inventory.

Deterministic candidate generation first: match each discovered Technology (and
its version, when reNgine captured one) against the product/package names and
version ranges in `CVEEntry.affected`. Candidates become `CVEMatch` rows with a
heuristic confidence; the user's chosen AI model can then confirm each one
(`ai_confirm_match`), which is what makes exposure precise rather than noisy.

The version/name helpers are pure Python (no Django import) so they are unit
testable on their own.
"""
import logging
import re

from cveFeed import distro as distro_lib
from cveFeed import match_policy
from cveFeed import runzero

logger = logging.getLogger(__name__)

_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")
_MIN_TOKEN = 3  # ignore 1-2 char product tokens to avoid noise
# Cloud-provider and generic service labels identify infrastructure, not a vulnerable product.
# A concrete product (for example Multi Model Server) must be observed separately.
# Single words too common to identify a product when they are all that is left of a longer name.
GENERIC_WORDS = frozenset({
    'cms', 'server', 'core', 'api', 'web', 'app', 'http', 'https', 'framework', 'project', 'client', 'service', 'services',
    'sdk', 'cli', 'lib', 'library', 'tool', 'tools', 'manager', 'platform', 'engine', 'plugin', 'module', 'data', 'cloud',
    'ssl', 'tls', 'js', 'html', 'proxy', 'gateway', 'portal', 'admin', 'system',
})
GENERIC_PRODUCT_TOKENS = frozenset({
    'aws', 'awsservice', 'amazonaws', 'amazonwebservices', 'amazonwebservice',
    'azure', 'azureservice', 'microsoftazure', 'googlecloud', 'googlecloudservice',
    'cloudservice', 'webservice', 'service',
    # a category a scanner reports when it sees one, not a product: "WAF" says a firewall answered, not which one
    'waf', 'webapplicationfirewall',
})


# A technology some scanner stored as a CPE ("cpe:/a:openbsd:openssh:7.2p2") or as a banner token ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"):
# the product and version are in there, not in a name that happens to contain colons or an underscore.
_CPE_TECH_RE = re.compile(r"^cpe:(?:/a:|2\.3:a:)([^:\s]*):([^:\s]+)(?::([^:\s]+))?", re.IGNORECASE)
_BANNER_TECH_RE = re.compile(r"^([A-Za-z][\w.+-]*?)_(\d[\w.+~-]*)(?:\s|$)")


def split_name_version(tech_name):
    """reNgine stores tech as 'Name' or 'Name:version' (httpx tech-detect); a scanner may also store a CPE or a 'Name_version' banner."""
    if not tech_name:
        return "", ""
    name = tech_name.strip()
    cpe = _CPE_TECH_RE.match(name)
    if cpe:
        version = cpe.group(3) or ""
        return cpe.group(2).replace("_", " "), version if version[:1].isdigit() else ""
    banner = _BANNER_TECH_RE.match(name)
    if banner:
        return banner.group(1).replace("_", " "), banner.group(2)
    if ":" in name:
        base, _, ver = name.rpartition(":")
        if ver and ver[0].isdigit():
            return base.strip(), ver.strip()
    return name, ""


_EPOCH_RE = re.compile(r"^\s*\d+:(?=\d)")  # a dpkg/rpm epoch: "1:8.9p1-3ubuntu0.6"
_HASH_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)  # a git commit, not a version
# a pre-release marker straight after the numbers: 2.0-beta9, 1.0rc1, 9.0.0-M1, 3.0.0.dev4. It sorts before the release, so it
# becomes a negative component (2.0-beta9 -> (2, 0, -3, 9) < (2, 0)). The bare letters a/b/m need a number after them: "1.0.2a"
# is OpenSSL's patch letter, not an alpha.
_PRE_RE = re.compile(r"^[-_.~+ ]?(?:(alpha|beta|rc|cr|pre|dev|snapshot)|(a|b|m))[-_. ]?(\d+)?", re.IGNORECASE)
# one or two letters straight after a three-part version, then the end or a separator: 1.0.2k, 1.1.1n-fips, 0.9.8zh. Not "8.9p1"
# (OpenSSH portable's p is followed by a digit and the version has two parts).
_PATCH_LETTER_RE = re.compile(r"^([a-z]{1,2})(?![a-z0-9])", re.IGNORECASE)
_PORTABLE_PATCH_RE = re.compile(r"^[-_. ]?p(\d+)(?![A-Za-z0-9])", re.IGNORECASE)  # 8.9p1, 9.6p1
_MARIADB_PREFIX_RE = re.compile(r"^5\.5\.5-(?=\d)")
_DATE_RE = re.compile(r"^(\d{4})[-/](\d{1,2})(?:[-/](\d{1,2}))?(?![\d.])")
_PRE_RANK = {"dev": -6, "snapshot": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4, "m": -3, "pre": -2, "cr": -1, "rc": -1}


class _Patched(tuple):
    """A version with a distribution-style patch suffix (OpenSSH 8.9p1, OpenSSL 1.0.2k). It compares like the plain tuple;
    ``release`` is the same version without the suffix, for an inclusive upper bound that names only the release."""
    release = ()


def _patched(release, parts):
    out = _Patched(parts)
    out.release = tuple(release)
    return out


def parse_version(value, strict=False):
    """Best-effort dotted version -> tuple of ints, else None.

    A leading epoch ("1:") is dropped, a "v" prefix ignored, and a pre-release marker becomes a negative component so
    2.0-beta9 sorts before 2.0. A commit hash is not a version. With ``strict`` (a bound from a feed, not a banner) the text must
    start with a digit, so a ref like "main" or a hash can never be read as version 3."""
    if not value:
        return None
    text = _EPOCH_RE.sub("", str(value)).strip()
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        text = text[1:]
    text = _MARIADB_PREFIX_RE.sub("", text)  # MariaDB's handshake says "5.5.5-10.6.12-MariaDB": the real version follows the prefix
    if _HASH_RE.match(text) and not text.isdigit():
        return None
    dated = _DATE_RE.match(text)  # 2024-01-15 is the date 2024, 1, 15, not the version 2024
    match = None if dated else (_VER_RE.match(text) if strict else _VER_RE.search(text))
    if not match and not dated:
        return None
    try:
        parts = [int(part) for part in dated.groups(default="0")[:3]] if dated else [int(part) for part in match.group(1).split(".")]
    except ValueError:
        return None
    if dated:
        return tuple(parts[:3 if dated.group(3) else 2])
    rest = text[match.end():]
    pre = _PRE_RE.match(rest)
    if pre and (pre.group(1) or pre.group(3)):
        parts += [_PRE_RANK[(pre.group(1) or pre.group(2)).lower()], int(pre.group(3) or 0)]
    elif _PORTABLE_PATCH_RE.match(rest):  # OpenSSH's 8.9p1 < 8.9p2 < 9.0: the patch level is a part after the release
        return _patched(parts, parts + [0, int(_PORTABLE_PATCH_RE.match(rest).group(1))])
    elif len(parts) == 3:
        letters = _PATCH_LETTER_RE.match(rest)
        if letters:  # OpenSSL's 1.1.1k < 1.1.1n < 1.1.1zh: the letters are a fourth component, so a patch level is not dropped
            return _patched(parts, parts + [sum(ord(c) - 96 for c in letters.group(1).lower())])
    return tuple(parts)


def _vcmp(a, b):
    """Compare two version tuples, zero-padded so (1,18) == (1,18,0)."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in_range(ver, rng):
    """Return True / False / None(unknown) for ver within an affected range dict. A range with no usable bound is unknown,
    never "in range": only a real bound can put a version inside it."""
    if ver is None:
        return None
    if str(rng.get("type") or "SEMVER").upper() not in ("SEMVER", "ECOSYSTEM"):
        return None  # a GIT range is commit hashes: it cannot be compared with a version
    bounds = [(rng.get(key), parse_version(rng.get(key), strict=True)) for key in ("introduced", "fixed", "lastAffected")]
    if any(raw and parsed is None for raw, parsed in bounds):
        return None  # a bound that is not a version ("unspecified", a hash) makes the whole range unknown, never "in range"
    introduced, fixed, last = (parsed for _raw, parsed in bounds)
    if introduced is None and fixed is None and last is None:
        return None  # no usable bound: the range says nothing about this version
    if introduced is not None and _vcmp(ver, introduced) < 0:
        return False
    if fixed is not None and _vcmp(ver, fixed) >= 0:
        return False
    if last is not None:
        # "up to 8.9" and a single listed "1.0.2" mean the whole release: a build with a patch suffix (8.9p1, 1.0.2k) is inside it,
        # unless the bound names a patch level itself
        within = ver.release if isinstance(ver, _Patched) and not isinstance(last, _Patched) else ver
        if _vcmp(within, last) > 0:
            return False
    return True


# Normalizing a name throws its word boundaries away ("craftcms/cms" and "craftcmscms" both become one token), and a plain
# substring test on the result matches "cms" inside "datocms" and "php" inside "phpmyadmin". The boundaries are kept here,
# keyed by the normalized token, so name matching can require that a shorter name is a whole run of words of the longer one.
# Two registries. The catalogue's own names (CVE products, packages, CPEs) fill ``_WORDS``; the strings a scanned host reports
# (banners, headers, technology labels) are attacker-influenced, so they fill a small separate table that drops its oldest entry
# when full and can never use up the catalogue's slots. A token with no recorded boundaries simply matches only itself, so the
# catalogue registry logs once when it is full: past that point names that need word boundaries stop matching.
_WORDS = {}
_WORDS_MAX_TOKENS = 50000
_HOST_WORDS = {}
_HOST_WORDS_MAX_TOKENS = 2000
_WORDS_MAX_RAW = 200
_WORDS_MAX_WORDS = 8
_WORD_RE = re.compile(r"[a-z0-9]+")
_COORDINATE_RE = re.compile(r"^[^\s:/]+(?:[:/][^\s:/]+)*[:/]([^\s:/]+)$")  # group:artifact or vendor/package, never a name with spaces
_words_full_logged = False


def _words_for(token):
    """Every recorded word split of a normalized token (the token itself as one word when none was recorded)."""
    known = _WORDS.get(token)
    host = _HOST_WORDS.get(token)
    if known and host:
        return known | host
    return known or host or ((token,),)


def _norm(value, catalogue=False):
    """The name without punctuation or case. Its word boundaries are recorded for ``name_matches_token``: in the catalogue registry
    when ``catalogue`` (a name from a CVE record), otherwise in the bounded table of host-reported names."""
    global _words_full_logged
    text = (value or "").lower()
    token = re.sub(r"[^a-z0-9]", "", text)
    if token and len(text) <= _WORDS_MAX_RAW:
        words = tuple(_WORD_RE.findall(text))
        if 1 < len(words) <= _WORDS_MAX_WORDS:
            table, cap = (_WORDS, _WORDS_MAX_TOKENS) if catalogue else (_HOST_WORDS, _HOST_WORDS_MAX_TOKENS)
            if token not in table and len(table) >= cap:
                if not catalogue:
                    del table[next(iter(table))]  # host-fed: the oldest name makes room
                else:
                    if not _words_full_logged:
                        _words_full_logged = True
                        logger.warning('the product word registry is full (%d names): longer product names that need word boundaries '
                                       'will only match exactly', cap)
                    return token
            known = table.setdefault(token, set())
            known.add(words)
            artifact = _COORDINATE_RE.match(text)  # "org.apache.logging.log4j:log4j-core" is also just "log4j-core"
            if artifact:
                known.add(tuple(_WORD_RE.findall(artifact.group(1))))
    return token


def affected_product_tokens(affected_item):
    """Normalized product/package tokens for one affected entry.

    The vendor is never a token, alone or joined to the product: "apache" or "microsoft" would make every CVE of the
    vendor a candidate for a host running any product of it (an Apache HTTP Server host is not a Log4j host), and a
    vendor+product token would match a bare "Apache" banner to Log4j and Tomcat. The vendor is only used to
    disambiguate (see _vendor_ok)."""
    tokens = set()
    vendor = _norm(affected_item.get("vendor"), True)
    for key in ("product", "package"):
        token = _norm(affected_item.get(key), True)
        if len(token) < _MIN_TOKEN or token in GENERIC_PRODUCT_TOKENS:
            continue
        if key == "product" and vendor and token in GENERIC_WORDS:
            # "cms", "server", "core": the product alone names nothing ("datocms" is not Craft's "cms"). With a vendor, the
            # vendor's own name for the software ("craftcms") is the identity; it matches the exact name only.
            if len(vendor) >= _MIN_TOKEN and vendor not in GENERIC_PRODUCT_TOKENS:
                tokens.add(vendor)
            continue
        tokens.add(token)
    return tokens


# Names scanners report that differ from the feed's product naming: normalized tech token -> product tokens naming the
# same software. Dropping the vendor token must not create false negatives for these. Aliases are the only widening.
PRODUCT_ALIASES = {
    # "httpserver" is the NVD-style product ("http_server"); "apachehttpserver" is how the CNA's own record names it ("Apache HTTP Server")
    "apachehttpd": {"httpserver", "apachehttpserver", "apache2"},
    "apachehttpserver": {"httpserver", "apache2"},
    "httpd": {"httpserver", "apachehttpserver", "apache2"},
    "apache": {"httpserver", "apachehttpserver", "apache2"},
    "microsoftiishttpd": {"internetinformationservices", "iis"},
    "microsoftiis": {"internetinformationservices", "iis"},
    "iis": {"internetinformationservices"},
    "eximsmtpd": {"exim"},
    "phpfpm": {"php"},  # PHP's FastCGI process manager is PHP, and its advisories are PHP's
    "iscbind": {"bind"},
    "bind9": {"bind"},
    "nextjs": {"next"},  # the npm package of Next.js is named "next"
    # product strings nmap's service detection really prints, which name the product with extra words the advisory's name lacks: a version seen
    # for one of these is the product's (validation.interpret needs the pair to agree before it reaffirms a CVE from a version)
    "apachetomcatcoyotejspengine": {"tomcat"},
    "apachecoyote": {"tomcat"},
    "nodejsexpressframework": {"express"},
    "vmwareesxisoapapi": {"esxi"},
    "ciscoioshttpconfig": {"ios"},
    "golangnethttpserver": {"go"},
    "pythonbasehttpserver": {"python"},
    # package names a host's own package manager reports (cveFeed.inventory_match): the feed names the same software differently
    "apache2": {"httpserver", "apachehttpserver"},
    "opensshserver": {"openssh"},
    "linuxkernel": {"linux"},
}


def tech_tokens(token):
    """The tech token plus the product tokens it is an alias of."""
    return {token} | PRODUCT_ALIASES.get(token, set())


def parse_cpe(cpe):
    """'cpe:/a:apache:http_server:2.4.52' (2.2) or 'cpe:2.3:a:apache:http_server:2.4.52:...' -> (vendor, product,
    version) with vendor/product normalized like the index tokens; None for an OS/hardware CPE or an unparseable one."""
    text = (cpe or "").strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")[2:]
    elif text.startswith("cpe:/"):
        parts = text[5:].split(":")
    else:
        return None
    if len(parts) < 3 or parts[0] != "a":
        return None
    product = _norm(parts[2], True)
    version = parts[3] if len(parts) > 3 and parts[3] not in ("*", "-") else ""
    if len(product) < _MIN_TOKEN:
        return None
    return _norm(parts[1], True), product, version


# Words that may surround a product name without making it another product: "apache http server" is Apache's server, "nginx web
# server" is nginx. Anything else around a name ("ingress", "ui", "proxy manager", "image resizing", "rails", "plugin") names a
# different product that merely contains the shorter name, so it must never be matched to it: only the words below are allowed
# after a name, and everything not listed is a sibling.
DESCRIPTOR_WORDS = frozenset({'server', 'http', 'https', 'httpd', 'daemon', 'web', 'framework', 'engine', 'project', 'software',
                              'core', 'cms', 'js', 'application', 'program', 'service', 'services'})
# an edition, a release channel or a packaging of the same software: "NGINX Open Source" and "NGINX Plus" are nginx, "Grafana OSS",
# "GitLab CE/EE" and "Splunk Enterprise" are Grafana, GitLab and Splunk. "ADC" is the NetScaler appliance's own name for itself.
EDITION_WORDS = frozenset({'oss', 'plus', 'ce', 'ee', 'community', 'enterprise', 'edition', 'suite', 'collaboration', 'webmail',
                           'obsidian', 'cumulative', 'update', 'cache', 'adc', 'lts', 'libs', 'lib', 'devel'})
# what nmap appends to a product to name the service: "Postfix smtpd", "Dovecot imapd", "Samba smbd", "PostgreSQL DB"
SERVICE_WORDS = frozenset({'smtpd', 'imapd', 'pop3d', 'smbd', 'sshd', 'db'})
# words that only mean something together ("data" and "store" alone name nothing)
TRAILING_PHRASES = (('open', 'source'), ('data', 'center'), ('http', 'proxy'), ('key', 'value', 'store'), ('rest', 'api'),
                    ('service', 'pack'))
_EDITION_NUMBER = re.compile(r'^(?:\d+|cu\d+|sp\d+|r\d+)$')  # 2016, "Cumulative Update 14" or CU14, SP1, R2
_TRAILER_WORDS = DESCRIPTOR_WORDS | EDITION_WORDS | SERVICE_WORDS | {w for phrase in TRAILING_PHRASES for w in phrase}
# a vendor in front of the product ("apache tomcat", "f5 nginx"): the same product named the way its vendor does
VENDOR_PREFIX_WORDS = frozenset({'apache', 'microsoft', 'oracle', 'gnu', 'eclipse', 'f5', 'ibm', 'google', 'cisco', 'vmware', 'adobe',
                                 'atlassian', 'red', 'hat', 'redhat', 'aws', 'amazon', 'palo', 'alto', 'networks', 'fortinet',
                                 'mikrotik', 'jfrog', 'citrix', 'twitter'})


def name_matches_token(tech_token, product_token):
    """A discovered tech token names the same product as an affected product token: the same name, or one of them is the other
    plus only descriptive words, an edition or the vendor ("apache http server" for "apache", "nginx open source" for "nginx", "apache
    tomcat" for "tomcat"). A shorter name never stands for a longer, different product: "nginx" is not "ingress-nginx" or "nginx ui",
    "php" is not "phpmyadmin", "cloudflare" is not a plugin that works with it."""
    if (len(tech_token) < _MIN_TOKEN or len(product_token) < _MIN_TOKEN
            or tech_token in GENERIC_PRODUCT_TOKENS or product_token in GENERIC_PRODUCT_TOKENS):
        return False
    if tech_token == product_token:
        return True
    for tech_words in _words_for(tech_token):
        for product_words in _words_for(product_token):
            inner, outer = (tech_words, product_words) if len(tech_words) <= len(product_words) else (product_words, tech_words)
            if not _word_run_ok(inner):
                continue
            if outer == inner * (len(outer) // len(inner)):  # the same name, or repeated as in "symfony/symfony"
                return True
            if _core(tech_words) == _core(product_words) and _word_run_ok(_core(tech_words)):  # "F5 NGINX" and "NGINX Open Source"
                return True
            if any(_same_product_around(outer[:i], outer[i + len(inner):])
                   for i in range(len(outer) - len(inner) + 1) if outer[i:i + len(inner)] == inner):
                return True
    return False


def _same_product_around(before, after):
    """Whether the words around a shared name only describe it (see DESCRIPTOR_WORDS), give its edition or name its vendor."""
    return all(w in VENDOR_PREFIX_WORDS or w in DESCRIPTOR_WORDS for w in before) and _trailer_ok(after)


def _core(words):
    """The words of a name without its leading vendor and its trailing descriptors or edition (always at least one word left)."""
    if words[0] not in VENDOR_PREFIX_WORDS and words[-1] not in _TRAILER_WORDS and not _EDITION_NUMBER.match(words[-1]):
        return words  # the usual case, and this runs for every candidate of a lookup
    start = 0
    while start < len(words) - 1 and words[start] in VENDOR_PREFIX_WORDS:
        start += 1
    end = next(i for i in range(start + 1, len(words) + 1) if _trailer_ok(words[i:]))
    return words[start:end]


def _trailer_ok(words):
    i = 0
    while i < len(words):
        phrase = next((p for p in TRAILING_PHRASES if words[i:i + len(p)] == p), None)
        if phrase:
            i += len(phrase)
        elif words[i] in DESCRIPTOR_WORDS or words[i] in EDITION_WORDS or words[i] in SERVICE_WORDS or _EDITION_NUMBER.match(words[i]):
            i += 1
        else:
            return False
    return True


def _word_run_ok(words):
    """A run of whole words that may stand for a product when it is all that is compared: long enough, not a generic label
    ('aws service'), and not one generic word ('server')."""
    joined = "".join(words)
    if len(joined) < _MIN_TOKEN or joined in GENERIC_PRODUCT_TOKENS:
        return False
    return not (len(words) == 1 and words[0] in GENERIC_WORDS)


def confidence_for(ver, in_range, kev):
    """Heuristic 0..1 confidence before any AI confirmation.

    Version confirmed in range is strong; unknown version is a weak-to-medium
    candidate; out of range is zero (dropped). KEV nudges it up.
    """
    if in_range is False:
        return 0.0
    base = 0.85 if in_range is True else (0.5 if ver is None else 0.4)
    if kev:
        base = min(1.0, base + 0.1)
    return round(base, 2)


# --- Django-dependent orchestration (imports models lazily) --------------------

class ProductIndex(dict):
    """token -> set of CVEEntry ids, with a memo of the fuzzy token -> candidate ids lookups so a product seen on many
    hosts is resolved once, and a word -> product tokens map so a lookup compares a name only with the products that share a word
    with it (not with all of them). Built by build_product_index and never mutated afterwards (the memo and the map rely on that)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.memo = {}
        self._by_word = None

    def candidate_tokens(self, token):
        """The product tokens that can name the same product as ``token``: a match needs every word of the shorter name inside the
        longer one, so the two always share a word. A token that is itself a product token is always a candidate."""
        if self._by_word is None:
            self._by_word = {}
            for product_token in self:
                for words in _words_for(product_token):
                    for word in words:
                        self._by_word.setdefault(word, set()).add(product_token)
        found = {token} if token in self else set()
        for words in _words_for(token):
            for word in words:
                found |= self._by_word.get(word, set())
        return found


MAX_AFFECTED_ITEMS = 500
MAX_RANGES_PER_ITEM = 100


def clean_affected(value):
    """The dict entries of a CVE's ``affected`` list, each with a list of dict ranges. A third-party feed decides this shape, and one
    malformed entry (a string, a null, ranges that are not a list) must not stop correlation for every CVE after it."""
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:MAX_AFFECTED_ITEMS]:
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges")
        if ranges is not None:
            item = {**item, "ranges": [r for r in ranges[:MAX_RANGES_PER_ITEM] if isinstance(r, dict)] if isinstance(ranges, list) else []}
        out.append(item)
    return out


def build_product_index(cves):
    """Map a normalized product token -> set of CVEEntry ids, for fast lookup.

    `cves` is any iterable of CVEEntry (a queryset or a list).
    """
    index = ProductIndex()
    for cve in cves:
        for item in (cve.affected or []):
            for token in affected_product_tokens(item):
                index.setdefault(token, set()).add(cve.id)
    return index


def _candidate_tokens(token, product_index):
    """The product tokens worth comparing with ``token`` (all of them for a plain dict index)."""
    return product_index.candidate_tokens(token) if hasattr(product_index, "candidate_tokens") else product_index


def _fuzzy_ids(token, product_index):
    """CVE ids whose product/package token plausibly names ``token`` (memoized per index)."""
    memo = getattr(product_index, "memo", None)
    if memo is not None and token in memo:
        return memo[token]
    ids = set()
    for product_token in _candidate_tokens(token, product_index):
        if name_matches_token(token, product_token):
            ids |= product_index[product_token]
    if memo is not None:
        memo[token] = ids
    return ids


def _vendor_ok(item, *hints):
    """True when the item names no vendor, or its vendor contains one of the (normalized) hints."""
    vendor = _norm(item.get("vendor"), True)
    return not vendor or any(h in vendor or vendor in h for h in hints)


# alias target -> vendor words that must appear when the item names a vendor (Oracle's "HTTP Server" is not Apache's)
_ALIAS_VENDOR = {"httpserver": ("apache",), "apache2": ("apache",)}


def _item_hits(item, token, aliases=(), cpe_product=None, cpe_vendor=""):
    """Whether one affected entry names the discovered product. With a CPE the product must equal it (and the vendor,
    when the entry has one, must agree); otherwise fuzzy token containment, plus exact alias names."""
    own = {_norm(item.get(k), True) for k in ("product", "package")} - {""}
    if cpe_product:
        if cpe_product in own:
            return _vendor_ok(item, cpe_vendor, cpe_vendor[:6])
        # an entry named some other way (the CNA's own "Apache HTTP Server" next to NVD's "http_server") still counts when it is the same
        # vendor's: the CPE must not hide the records that do not use its spelling
        if not _vendor_ok(item, cpe_vendor, cpe_vendor[:6]) or not item.get("vendor"):
            return False
    tokens = affected_product_tokens(item)
    if any(name_matches_token(token, t) for t in tokens):
        return True
    for alias in aliases:
        if alias in tokens and (alias not in _ALIAS_VENDOR or _vendor_ok(item, *_ALIAS_VENDOR[alias])):
            return True
    return False


def _bounded(rng):
    return version_in_range((0,), rng) is not None  # a range with at least one usable bound


def pair_split_ranges(ranges):
    """The ranges with each ``introduced``-only range joined to the ``fixed``-only range right after it.

    The CVE List writes a branch as two ``versions`` entries when its lower bound is "7.13.0" and its upper bound is "lessThan 7.13.7", and the
    conversion keeps them as two ranges: ``[{"introduced": "7.13.0"}, {"fixed": "7.13.7"}]``. Read alone, the first says "7.13.0 and every later
    version", the second "every version before 7.13.7", so the fixed 7.13.7, 7.18.1 and everything in between read as vulnerable (issue 205,
    CVE-2022-26134). Joined, they are the branch the advisory means. Only a pair that alternates in order and whose fix is newer than its
    introduction is joined; an ``introduced`` range with no fixed range after it stays open (a branch with no fix), and any other shape is
    returned as it was."""
    out, i = [], 0
    ranges = list(ranges)
    while i < len(ranges):
        rng = ranges[i]
        nxt = ranges[i + 1] if i + 1 < len(ranges) else None
        if (nxt is not None and rng.get("introduced") and not rng.get("fixed") and not rng.get("lastAffected")
                and nxt.get("fixed") and not nxt.get("introduced") and not nxt.get("lastAffected")
                and str(rng.get("type") or "SEMVER").upper() == str(nxt.get("type") or "SEMVER").upper()):
            intro, fixed = parse_version(rng["introduced"], strict=True), parse_version(nxt["fixed"], strict=True)
            if intro is not None and fixed is not None and _vcmp(fixed, intro) > 0:
                out.append({**rng, "fixed": nxt["fixed"]})
                i += 2
                continue
        out.append(rng)
        i += 1
    return out


def _is_branch_range(rng):
    """One maintained branch of a branch-by-branch fix list: introduced "8.2" or "8.2.*", fixed "8.2.35"."""
    intro = parse_version(rng.get("introduced"), strict=True)
    fixed = parse_version(rng.get("fixed"), strict=True)
    return bool(intro and fixed and len(intro) <= 2 and len(fixed) > len(intro) and fixed[:len(intro)] == intro)


def lowest_listed_branch(ranges):
    """The oldest branch an advisory lists, when every one of its ranges is a branch fix (two or more of them, as PHP, Django
    and Rails publish); None for any other shape of advisory."""
    bounded = [r for r in ranges if _bounded(r)]
    if len(bounded) < 2 or not all(_is_branch_range(r) for r in bounded):
        return None
    return min(parse_version(r["introduced"], strict=True) for r in bounded)


def branch_unlisted(ver, ranges):
    """True when ``ver`` is older than every branch a branch-by-branch advisory lists. Such an advisory names only the branches
    that received a fix; an older branch is not cleared by it (end-of-life releases never get a fix, so are usually still
    exposed), so the answer for it is "unknown", not "not in range"."""
    lowest = lowest_listed_branch(ranges)
    return bool(lowest and ver and _vcmp(ver[:len(lowest)], lowest) < 0)


def fix_only_branch_list(ranges):
    """True for a list of two or more ranges that each carry only a ``fixed`` bound: the shape some feeds give a branch-by-branch advisory
    (PHP2Shell: fixed 8.2.35, 8.3.36, 8.4.27, 8.5.12). The lower bound was dropped, so a range read alone says "every version before
    the fix", which for one branch's fix includes the other, older branches' already patched releases."""
    if len(ranges) < 2:
        return False
    for rng in ranges:
        if (rng.get("introduced") or rng.get("lastAffected") or not rng.get("fixed")
                or str(rng.get("type") or "SEMVER").upper() not in ("SEMVER", "ECOSYSTEM") or parse_version(rng.get("fixed"), strict=True) is None):
            return False
    return True


def fix_only_branch_verdict(ver, ranges):
    """``(verdict, fixed)`` for ``ver`` against a fix-only branch list, without inventing a lower bound: a fix only speaks for the
    versions that are on its own line of releases. True/False/None as for ``version_in_range``; ``fixed`` is the fix the answer was
    read against (None when none applies).

    1. A fix on the host's own major.minor branch decides: vulnerable when the host is before it.
    2. Otherwise the fixes on the host's major: exactly one decides (an advisory of release trains named by their major, such as
       18.19.1, 20.11.1 and 21.6.2, or one fix at x.y.0), several that the host sits between or before are a branch the advisory does
       not list: unknown, never cleared (an end-of-life branch gets no fix).
    3. Newer than every fix: not vulnerable. Another major, older than every fix: unknown. Between majors: unknown."""
    parsed = sorted(((parse_version(r["fixed"], strict=True), r["fixed"]) for r in ranges), key=lambda pair: pair[0])
    if not ver or len(ver) < 1:
        return None, None
    own = [pair for pair in parsed if pair[0][:2] == tuple(ver[:2])]
    if own:
        fix = own[0]
        return (_vcmp(ver, fix[0]) < 0), fix[1]
    if _vcmp(ver, parsed[-1][0]) >= 0:
        return False, None
    same_major = [pair for pair in parsed if pair[0][:1] == tuple(ver[:1])]
    if len(same_major) == 1:
        fix = same_major[0]
        return (_vcmp(ver, fix[0]) < 0), fix[1]
    return None, None


def _match_candidates(name, ver, token, product_index, cve_by_id, cpe=None, details=None):
    """Yield (cve, matched_product, in_range) for CVEs plausibly affecting a
    discovered product `token` (normalized) at version `ver` (tuple or None).

    Only the ranges of the affected entry that names the product are tested, never another product of the same vendor.
    An entry with no usable version bound gives in_range None (unknown), never True. ``cpe`` (nmap's 'cpe:/a:vendor:
    product:version') names the product exactly; it is tried first and the name match is the fallback.

    ``details``, when given, is a dict that receives ``{cve.id: {"affected_index", "range"}}``: which affected entry and which
    range decided the result (the evidence stored on the match).

    Reads only the pre-built product_index / cve_by_id; shared by the technology
    fingerprint path and the nmap/Port service path so both score identically.
    """
    cpe_parts = parse_cpe(cpe)
    candidate_ids, cpe_product, cpe_vendor = set(), None, ""
    if cpe_parts:
        cpe_vendor, cpe_product, _ = cpe_parts
        candidate_ids = set(product_index.get(cpe_product, ()))
        if not candidate_ids:
            cpe_product = None
    aliases = tuple(sorted(PRODUCT_ALIASES.get(token, ())))
    # the name match is always added: a CPE names the product exactly, but CVEs whose own record spells it differently are still about it
    candidate_ids |= set(_fuzzy_ids(token, product_index))
    for alias in aliases:
        candidate_ids |= product_index.get(alias, set())

    for cid in candidate_ids:
        cve = cve_by_id[cid]
        hit = [(i, item) for i, item in enumerate(cve.affected or []) if _item_hits(item, token, aliases, cpe_product, cpe_vendor)]
        if not hit:
            continue
        # Every hit names the same product (see name_matches_token): a wrapper or repackaging with its own version numbers
        # ("jquery-rails", "ingress-nginx") is another product and was never a hit, so its ranges are never compared.
        in_range, matched_product = None, name
        if ver is not None:
            in_range, unknown = False, False
            for index, item in hit:
                ranges = pair_split_ranges([r for r in (item.get("ranges") or []) if _bounded(r)])
                if not ranges:
                    unknown = True  # the advisory names the product but no version bound: nothing to test against
                    continue
                if fix_only_branch_list(ranges):
                    # no lower bounds were published: each fix is compared only with the releases of its own line (issue 205)
                    result, fixed = fix_only_branch_verdict(ver, ranges)
                    if result is True:
                        in_range = True
                        matched_product = item.get("product") or item.get("package") or name
                        if details is not None:
                            details[cve.id] = {"affected_index": index, "range": {"fixed": str(fixed)[:60]}, "no_lower_bound": True}
                        break
                    if result is None:
                        unknown = True
                    continue
                for rng in ranges:
                    result = version_in_range(ver, rng)
                    if result is True:
                        in_range = True
                        matched_product = item.get("product") or item.get("package") or name
                        if details is not None:
                            details[cve.id] = {"affected_index": index, "range": {k: str(v)[:60] for k, v in rng.items()
                                                                                  if k in ("introduced", "fixed", "lastAffected")}}
                        break
                    if result is None:
                        unknown = True
                if in_range is True:
                    break
            if in_range is not True and unknown:
                in_range = None
            if in_range is False and not _is_ice(cve) and any(
                    branch_unlisted(ver, [r for r in (item.get("ranges") or []) if _bounded(r)]) for _i, item in hit):
                in_range = None  # older than every branch the advisory fixes: unlisted, not cleared
                if details is not None:
                    low = next(lowest_listed_branch(item.get("ranges") or []) for _i, item in hit
                               if branch_unlisted(ver, [r for r in (item.get("ranges") or []) if _bounded(r)]))
                    details[cve.id] = {"affected_index": hit[0][0], "range": {}, "branch_unlisted": True,
                                       "lowest_listed_branch": ".".join(map(str, low))}
        if details is not None and cve.id not in details and hit:
            details[cve.id] = {"affected_index": hit[0][0], "range": {}}
        yield cve, matched_product, in_range


def _is_ice(cve):
    from cveFeed.threat import ICE, classify_threat_tier
    return classify_threat_tier(
        kev=getattr(cve, "kev", None), epss_reached=getattr(cve, "epss_reached", None),
        exploit_db=getattr(cve, "exploit_db", None), cvss=getattr(cve, "cvss", None)) == ICE


class DbFixLookup:
    """DistroFix rows for (distro, package, CVE) as {release, fixed_version, status} dicts, each read from the database once.
    Correlation takes any callable with this signature, so tests inject a fake instead of filling the table."""

    def __init__(self):
        self.memo = {}

    def __call__(self, distro, package, cve_id):
        key = (distro, package, cve_id)
        if key not in self.memo:
            from cveFeed.models import DistroFix
            self.memo[key] = [{"release": r.release, "fixed_version": r.fixed_version, "status": r.status}
                              for r in DistroFix.objects.filter(distro=distro, package=package, cve_id=cve_id)]
        return self.memo[key]


def port_distro(port):
    """The distro info of a Port row: what nmap persisted, else read from its banner fields now (rows older than the distro
    columns). The package name is derived, never stored."""
    info = {"distro": getattr(port, "distro", "") or "", "release": getattr(port, "distro_release", "") or "",
            "package_release": getattr(port, "package_release", "") or "", "upstream_version": getattr(port, "upstream_version", "") or ""}
    if not info["distro"]:
        info = distro_lib.parse_distro(port.product, port.version, getattr(port, "service_extra", ""), [getattr(port, "cpe", "")])
    info["package"] = distro_lib.package_for(port.product, info["distro"], info["upstream_version"]) if info["distro"] else ""
    return info


def _record_matches(subdomain, name, version, token, source, product_index,
                    cve_by_id, min_confidence, scan_history, rows=None, cpe="", distro=None, fix_lookup=None, evidence=None,
                    corroborated=(), leads=None):
    """Work out the CVEMatch rows for one discovered product on a subdomain and append them to ``rows``
    (written in a batch by ``save_matches``). Returns the number of matches found. ``leads``, when given, is a dict that receives
    ``{cve.id: {(domain id, host name)}}`` for the CVEs a product seen without a version could be about."""
    if not version and cpe:  # nmap sometimes names the version only in the CPE
        version = (parse_cpe(cpe) or ("", "", ""))[2]
    ver = parse_version(version)
    if match_policy.is_os_sighting(name, cpe):
        return 0  # an operating system fingerprint is decided by the host's own report, not by its name
    if ver is None:
        # A product seen without a version is a lead (match_policy.unversioned_products), never a match: naming a product says nothing
        # about which of its advisories apply.
        if leads is not None:
            for cve, _product, _in_range in _match_candidates(name, None, token, product_index, cve_by_id, cpe=cpe):
                leads.setdefault(cve.id, set()).add((subdomain.target_domain_id, subdomain.name))
        return 0
    found = 0
    details = {}
    for cve, matched_product, in_range in _match_candidates(
            name, ver, token, product_index, cve_by_id, cpe=cpe, details=details):
        confidence = confidence_for(ver, in_range, cve.kev)
        if confidence < min_confidence or confidence <= 0.0:
            continue
        unbounded = False
        if not match_policy.hard_version_evidence(in_range, details.get(cve.id)):
            # The advisory gives no version bound to test this version against: product-wide, so no evidence. The host is still a lead
            # (a template test needs no version), and an actively exploited (KEV) CVE is kept as a candidate that needs validation:
            # "version unknown" (match_policy.is_version_unknown), reviewed at the lowest priority. It is not frozen: the next correlation
            # after the CVE gains a range replaces this row's evidence, so the flag lifts and the match is judged on its version.
            if leads is not None:
                leads.setdefault(cve.id, set()).add((subdomain.target_domain_id, subdomain.name))
            if not cve.kev:
                continue
            unbounded = True
        status, fixed = distro_lib.NO_DATA, ""
        if distro and distro.get("distro") and in_range is True:
            # Upstream says in range; the distro may have backported the fix. Never dropped: a patched match is kept,
            # at low confidence and labelled, so a wrong distro reading can only demote it, not hide it.
            rows_for = fix_lookup(distro["distro"], distro.get("package", ""), getattr(cve, "cve_id", "")) \
                if fix_lookup and distro.get("package") else []
            status, fixed = distro_lib.judge(distro, rows_for)
            if status == distro_lib.PATCHED:
                confidence = 0.2
            elif status == distro_lib.VULNERABLE:
                confidence = 0.95  # the distro's own tracker lists this package release as affected: the strongest evidence there is
        reported = bool(corroborated) and getattr(cve, "cve_id", "") in corroborated and status != distro_lib.PATCHED
        if reported:  # runZero's own scan reports it too (cveFeed.runzero_sync): more evidence, never a verdict and never a new match
            confidence = runzero.boosted(confidence)
        rows.append({
            "cve_entry_id": cve.id, "subdomain_id": subdomain.id, "source": source,
            "matched_product": matched_product[:255], "matched_version": version[:100],
            "version_in_range": in_range, "confidence": confidence,
            "scan_history_id": scan_history.id if scan_history else subdomain.scan_history_id,
            "distro_status": status, "distro_fixed_version": fixed[:64],
            "evidence": {**(evidence or {}), "raw_version": version[:100], **details.get(cve.id, {}), **({"unbounded": True} if unbounded else {}),
                         **({"runzero": True} if reported else {}),
                         **({"distro": {k: v for k, v in distro.items() if v}} if distro and distro.get("distro") else {})},
        })
        found += 1
    return found


def signature_of(obj):
    """What a verdict depends on: the CVE, the product and version found, whether it is in range, and how it was found."""
    return (getattr(obj, "cve_entry_id"), obj.matched_product, obj.matched_version, obj.version_in_range, obj.source)


# the stored reasons of a deterministic closure (this module, cveFeed.locality, cveFeed.match_policy): a verdict that starts with one
# was reached on the evidence alone, so it is reusable and a person's or the AI's later answer does not replace it
DIFFERENT_PRODUCT = 'Closed automatically: different product'
# the first wording of the same closure ("invalid product correlation") is still on rows closed before it was reworded: it is read the same
AUTO_CLOSED = (DIFFERENT_PRODUCT, 'Closed automatically: invalid product correlation', 'Closed automatically: local-only',
               match_policy.NO_EVIDENCE)


def closure_summary(reason):
    """The first sentence of a stored closure reason without its "Closed automatically:" lead, for a one-line activity entry."""
    text = (reason or '').strip()
    if text.startswith('Closed automatically:'):
        text = text[len('Closed automatically:'):].strip()
    return text.split('. ')[0].rstrip('.')[:200]


def _names(values, limit=3):
    seen = []
    for value in values:
        value = ' '.join(str(value or '').split())[:60]
        if value and value.lower() not in [x.lower() for x in seen]:
            seen.append(value)
    return ', '.join('"%s"' % v for v in seen[:limit])


def invalid_identity_reason(match):
    """A reason to close this *candidate correlation*, never a claim that the host lacks backend software.

    A frontend banner or missing version is not negative evidence. Only the identity that originally
    produced the match is compared with the advisory's named products, using the same aliases as
    candidate generation. Conflicting positive evidence prevents automatic closure.
    """
    if match.template_result == 'vulnerable' or match.distro_status == 'vulnerable' or match_policy.has_standing(match):
        return ''  # a check found it, or a person or the host vouches for it: no name comparison closes that
    if getattr(match.cve_entry, 'local_only', False):  # not a product question: nothing outside the host can decide this CVE
        from cveFeed.locality import reason_text
        return reason_text()
    # The sighting the match was made from, not the product the advisory names: a match in range stores the advisory's own name, which
    # always matches itself, so only the original sighting can show that a different product was linked (an "nginx" fingerprint
    # against ingress-nginx's ranges).
    name, cpe = match_policy.sighting_of(match)
    reason = match_policy.no_evidence_reason(match, name, cpe)
    if reason:
        return reason
    affected = clean_affected(match.cve_entry.affected)
    if not any(isinstance(item, dict) and affected_product_tokens(item) for item in affected):
        return ''
    token = _norm(name)
    if not token:
        return ''
    cve = match.cve_entry
    index = build_product_index([cve])
    if any(_match_candidates(name, None, token, index, {cve.pk: cve}, cpe=cpe)):
        return ''
    seen = _names([name])
    covers = _names(item.get('product') or item.get('package') for item in affected if isinstance(item, dict))
    if token in GENERIC_PRODUCT_TOKENS:
        basis = f'the recorded fingerprint {seen} is a generic cloud or service label, not the affected software'
    elif covers:
        basis = f'it was recorded as {seen}, but the advisory covers {covers}'
    else:
        basis = f'it was recorded as {seen}, which is not a product this advisory names'
    return (DIFFERENT_PRODUCT + '; ' + basis + '. This closes this candidate match only; '
            'it does not establish that the software is absent elsewhere on the host.')


def close_invalid_correlation(match, reason=None):
    """Persist a scoped, auditable closure and a reusable deterministic verdict for bad product links."""
    from django.utils import timezone
    from cveFeed import activity, scoring, triage
    from cveFeed.models import CVEMatch, MatchVerdict, TriageVerdict

    reason = reason or invalid_identity_reason(match)
    if not reason:
        return False
    if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith(AUTO_CLOSED):
        return False
    pairs = triage.track([match])
    if not pairs:
        return False
    row, _ = pairs[0]
    # A verdict is shared by every host with the same evidence. One reached by comparing names is only about this sighting, and a
    # version inside the affected range is the evidence another host with the same product and version stands on: it never leaves this row.
    shared = match.version_in_range is not True
    verdict = None
    if shared:
        verdict, _ = TriageVerdict.objects.update_or_create(kind='cve_match', signature=row.signature, defaults={
            'classification': 'not_applicable', 'reason': reason, 'model_classification': '', 'model_reason': '',
            'overridden': False, 'model': 'deterministic-correlation', 'invalid_output': False})
    row.verdict, row.status, row.classification, row.reason = verdict, 'triaged', 'not_applicable', reason
    row.save(update_fields=['verdict', 'status', 'classification', 'reason', 'updated_at'])
    CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='not_affected', ai_reason=reason, ai_model='deterministic-correlation',
                                               confidence=0.0, updated_at=timezone.now())
    match.ai_verdict, match.ai_reason, match.ai_model, match.confidence = 'not_affected', reason, 'deterministic-correlation', 0.0
    if shared:
        MatchVerdict.objects.update_or_create(cve_entry=match.cve_entry, matched_product=match.matched_product,
            matched_version=match.matched_version, version_in_range=match.version_in_range, source=match.source,
            defaults={'ai_verdict': 'not_affected', 'ai_reason': reason, 'ai_model': 'deterministic-correlation'})
    activity.log('confirm', f'{match.cve_entry.cve_id}: closed for this asset ({closure_summary(reason)})',
                 project=row.project_id, cve_id=match.cve_entry.cve_id, match_id=match.pk,
                 finding_id=row.pk, decision='closed_not_applicable', reason=reason)
    scoring.rescore_for_matches([match])
    from django.db import transaction
    from cveFeed.views import bump_stats_revision
    transaction.on_commit(bump_stats_revision)
    return True


def _seedable(verdict, row):
    """The stored verdict a new or moved match may start from: never a clearing one (not_affected) for a version in the affected range
    that no distribution has patched, whose evidence the verdict was not reached on (the signature does not carry the distro result)."""
    if verdict and verdict.ai_verdict == "not_affected":
        if row["evidence"].get("unbounded") and (verdict.ai_reason or '').startswith(match_policy.NO_EVIDENCE):
            return None  # closed for lack of a version bound before the KEV exception: the candidate is wanted now
        if row["version_in_range"] is True and row["distro_status"] != distro_lib.PATCHED:
            return None
        if (row["version_in_range"] is not False and row["distro_status"] != distro_lib.PATCHED
                and not (verdict.ai_reason or '').startswith(AUTO_CLOSED)):
            return None
    return verdict


_MATCH_FIELDS = ("matched_version", "version_in_range", "confidence", "scan_history_id", "distro_status", "distro_fixed_version",
                 "evidence")


def _row_strength(row):
    """Orders sightings of one match: hard evidence (a template hit, a distribution tracker), then a version inside the range, then an
    unknown range, then outside it."""
    return (row.get("template_result") == "vulnerable" or row.get("distro_status") == "vulnerable",
            row.get("version_in_range") is True, row.get("version_in_range") is None)


def _carry_remediation(fresh):
    """Give each new match the remediation state of the same finding on the host's earlier scan. Hosts are stored once per scan, so
    the next scan's host row starts with no matches of its own; without this, everything a person marked fixed, in progress or accepted
    risk would reappear as open after the next scan."""
    from cveFeed.models import CVEMatch
    from startScan.models import Subdomain
    hosts = {sid: (domain_id, name) for sid, domain_id, name in
             Subdomain.objects.filter(pk__in={m.subdomain_id for m in fresh}).values_list("id", "target_domain_id", "name")}
    domains = {d for d, _n in hosts.values()}
    names = {n for _d, n in hosts.values()}
    base = (CVEMatch.objects.filter(cve_entry_id__in={m.cve_entry_id for m in fresh}, subdomain__target_domain_id__in=domains,
                                    subdomain__name__in=names)
            .exclude(subdomain_id__in=list(hosts)).select_related("subdomain"))
    # A remediation decision applies to this CVE on this host, even when a feed
    # changes the product label or evidence source. Use the newest host-level
    # row: preferring an older exact-product row would undo a later reopening.
    # Each scan keeps a copy, so let PostgreSQL return just one row per key.
    by_host_fields = ("cve_entry_id", "subdomain__target_domain_id", "subdomain__name")
    by_host = {(m.cve_entry_id, m.subdomain.target_domain_id, m.subdomain.name): m
               for m in base.order_by(*by_host_fields, "-id").distinct(*by_host_fields)}
    if not by_host:
        return
    for match in fresh:
        domain_id, name = hosts.get(match.subdomain_id, (None, None))
        before = by_host.get((match.cve_entry_id, domain_id, name))
        if before is not None:
            match.remediation_status, match.remediation_note = before.remediation_status, before.remediation_note
            match.remediation_updated_at, match.remediation_by_id, match.assignee_id = (
                before.remediation_updated_at, before.remediation_by_id, before.assignee_id)


def save_matches(rows, covered=None):
    """Upsert CVEMatch rows in two statements: bulk_create(ignore_conflicts) for the new ones, bulk_update for the
    existing ones whose evidence changed. Remediation fields are never touched. When the version or its range result
    changes, the AI verdict of the old evidence is replaced by the stored verdict for the new one (or cleared), so the new
    signature is judged, not inherited.

    ``covered`` is ``(subdomain_ids, cve_ids)``: the hosts these rows were computed for and the CVE pool they were checked
    against. Matches of those hosts and CVEs that the rows no longer contain (the version moved out of range, the product is
    gone) are closed: deleted, or, when a person has already worked the match, kept as not_affected with their remediation
    state, so a stale exposure is never reported and a person's decision is never lost."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch, MatchVerdict

    unique = {}
    for r in rows:  # two sightings of one product on one host (two ports, two banners): keep the strongest evidence, not the last
        key = (r["cve_entry_id"], r["subdomain_id"], r["source"], r["matched_product"])
        if key not in unique or _row_strength(r) >= _row_strength(unique[key]):
            unique[key] = r
    touched = set()  # hosts whose verdict was reset or whose match was closed: their score must follow
    if covered:
        touched |= close_stale(unique, covered)
    if not unique:
        if touched:
            from cveFeed import scoring
            scoring.rescore_subdomain_ids(touched)
        return 0
    existing = {
        (m.cve_entry_id, m.subdomain_id, m.source, m.matched_product): m
        for m in CVEMatch.objects.filter(subdomain_id__in={k[1] for k in unique}).only(
            "id", "cve_entry_id", "subdomain_id", "source", "matched_product", "ai_verdict", "ai_reason", "ai_model",
            *_MATCH_FIELDS)}
    fresh, changed = [], []
    now = timezone.now()
    verdicts = {}
    moved = {k for k, r in unique.items() if k in existing and (
        existing[k].matched_version != r["matched_version"] or existing[k].version_in_range != r["version_in_range"]
        or existing[k].distro_status != r["distro_status"]
        or ((existing[k].ai_reason or '').startswith('Closed automatically:') and
            any(getattr(existing[k], field) != r[field] for field in _MATCH_FIELDS)))}
    if any(key not in existing for key in unique) or moved:  # a new match of a kind the AI already judged starts out judged
        verdicts = {signature_of(v): v for v in MatchVerdict.objects.filter(
            cve_entry_id__in={k[0] for k in unique if k not in existing or k in moved})}
    for key, row in unique.items():
        match = existing.get(key)
        signature = (row["cve_entry_id"], row["matched_product"], row["matched_version"], row["version_in_range"], row["source"])
        if match is None:
            verdict = _seedable(verdicts.get(signature), row)
            extra = ({"ai_verdict": verdict.ai_verdict, "ai_reason": verdict.ai_reason, "ai_model": verdict.ai_model}
                     if verdict else {})
            fresh.append(CVEMatch(**row, **extra))
        elif any(getattr(match, f) != row[f] for f in _MATCH_FIELDS):
            for f in _MATCH_FIELDS:
                setattr(match, f, row[f])
            if key in moved:
                verdict = _seedable(verdicts.get(signature), row)
                match.ai_verdict = verdict.ai_verdict if verdict else ""
                match.ai_reason = verdict.ai_reason if verdict else ""
                match.ai_model = verdict.ai_model if verdict else ""
            match.updated_at = now
            changed.append(match)
    if fresh:
        _carry_remediation(fresh)
        CVEMatch.objects.bulk_create(fresh, ignore_conflicts=True, batch_size=1000)
    if changed:
        CVEMatch.objects.bulk_update(changed, [*_MATCH_FIELDS, "ai_verdict", "ai_reason", "ai_model", "updated_at"], batch_size=1000)
    touched |= {k[1] for k in moved}
    if touched:
        from cveFeed import scoring
        scoring.rescore_subdomain_ids(touched)
    return len(unique)


_CORRELATED_SOURCES = ("tech", "port")


def close_rejected():
    """Close every open match of a CVE its CNA has rejected: a rejected CVE is not a vulnerability, and its old matches would otherwise
    stay in the findings for good. Matches a person already worked keep their remediation state. Returns how many were closed."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch
    from cveFeed import scoring
    open_matches = CVEMatch.objects.filter(cve_entry__status__icontains="reject").exclude(
        ai_verdict="not_affected", ai_reason__startswith="Closed automatically:")
    closed = 0
    while rows := list(open_matches.order_by('pk').values_list('pk', 'subdomain_id')[:scoring.CHUNK]):
        ids = [pk for pk, _ in rows]
        updated = open_matches.filter(pk__in=ids).update(
            ai_verdict="not_affected", confidence=0.0, updated_at=timezone.now(),
            ai_reason="Closed automatically: the CVE was rejected by its CNA.")
        closed += updated
        if updated:
            scoring.rescore_subdomain_ids({subdomain_id for _, subdomain_id in rows})
    return closed


def close_stale(current, covered):
    """Close the matches of ``covered`` hosts and CVEs that ``current`` (the keys just computed) no longer contains. Returns the
    ids of the hosts that had one closed."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch

    subdomain_ids, cve_ids = covered
    if not subdomain_ids:
        return set()
    stale_keep, hosts = [], set()
    for m in CVEMatch.objects.filter(subdomain_id__in=list(subdomain_ids), source__in=_CORRELATED_SOURCES).only(
            "id", "cve_entry_id", "subdomain_id", "source", "matched_product", "ai_verdict", "ai_reason", "template_result",
            "remediation_status", "version_in_range"):
        if m.cve_entry_id not in cve_ids or (m.cve_entry_id, m.subdomain_id, m.source, m.matched_product) in current:
            continue
        if m.template_result == 'vulnerable':
            continue  # a template hit is evidence of the vulnerability itself: not seeing the product's banner again does not retire it
        if m.remediation_status != 'open' and m.version_in_range is None:
            continue  # worked by a person before the evidence policy, with no version behind it: their decision stands, it is not ours to close
        if m.ai_verdict == 'not_affected' and (m.ai_reason or '').startswith('Closed automatically:'):
            continue
        stale_keep.append(m)
        hosts.add(m.subdomain_id)
    if stale_keep:
        CVEMatch.objects.filter(pk__in=[m.pk for m in stale_keep]).update(
            ai_verdict="not_affected", confidence=0.0, updated_at=timezone.now(),
            ai_reason="Closed automatically: the host no longer matches this CVE (the version moved out of the affected range "
                      "or the product is gone).")
        from cveFeed import activity
        from startScan.models import Subdomain
        projects = dict(Subdomain.objects.filter(pk__in=hosts).values_list('id', 'target_domain__project_id'))
        for match in stale_keep:
            if projects.get(match.subdomain_id):
                activity.log('confirm', 'CVE candidate closed after its product or version disappeared from inventory',
                             project=projects[match.subdomain_id], match_id=match.pk, decision='closed_not_applicable')
    return hosts


def collect_subdomain_matches(subdomain, product_index, cve_by_id, min_confidence=0.0, scan_history=None, rows=None,
                              fix_lookup=None, leads=None):
    """The CVEMatch rows for one subdomain, appended to ``rows`` (a new list when omitted). Returns the rows.

    Two deterministic sources are correlated against the CVE product index:
    - "tech": reNgine's httpx technology fingerprints (stored as name[:version]).
    - "port": the Shodan-style nmap -sV service data on the host's open ports
      (Port.product / Port.version), reached via the subdomain's IP addresses.
    """
    rows = [] if rows is None else rows
    fix_lookup = fix_lookup or DbFixLookup()

    # Technology fingerprints (httpx tech-detect).
    for tech in subdomain.technologies.all():
        name, version = split_name_version(tech.name)
        token = _norm(name)
        if len(token) < _MIN_TOKEN:
            continue
        _record_matches(
            subdomain, name, version, token, "tech",
            product_index, cve_by_id, min_confidence, scan_history, rows, evidence={"source": "tech", "source_id": tech.id},
            leads=leads)

    # nmap -sV service data on the host's open ports (Shodan-style inventory).
    from startScan.models import open_services
    for ip in subdomain.ip_addresses.all():
        for port in open_services(ip):  # a UDP service that identified itself (SNMP, NTP, SSDP, memcached) is evidence like a TCP one
            name = (port.product or "").strip()
            token = _norm(name)
            if len(token) < _MIN_TOKEN:
                continue
            version = (port.version or "").strip()
            _record_matches(
                subdomain, name, version, token, "port",
                product_index, cve_by_id, min_confidence, scan_history, rows, cpe=port.cpe or "",
                distro=port_distro(port), fix_lookup=fix_lookup, corroborated=runzero.reported_cves(ip, port.number),
                evidence={"source": "port", "source_id": port.id, "ip": ip.address, "port": port.number, "protocol": port.protocol or "tcp",
                          "service_extra": (port.service_extra or "")[:255], "cpe": (port.cpe or "")[:255],
                          "method": ((port.extra or {}).get("method") or "")},
                leads=leads)
    return rows


def correlate_subdomain(subdomain, product_index, cve_by_id, min_confidence=0.0, scan_history=None, fix_lookup=None):
    """Create/update CVEMatch rows for one subdomain. Returns number of matches."""
    return save_matches(collect_subdomain_matches(
        subdomain, product_index, cve_by_id, min_confidence=min_confidence, scan_history=scan_history, fix_lookup=fix_lookup),
        covered=({subdomain.id}, set(cve_by_id)))


def correlate_subdomains(subdomains, product_index, cve_by_id, min_confidence=0.0, scan_history=None, batch=500,
                         fix_lookup=None, leads=None):
    """Correlate an iterable of subdomains, writing the matches ``batch`` hosts at a time. ``leads`` (a dict) receives the
    hosts that run a CVE's product with no version found (see ``_record_matches``).
    Returns (hosts walked, matches recorded)."""
    hosts = matches = 0
    rows, ids = [], set()
    pool = set(cve_by_id)
    fix_lookup = fix_lookup or DbFixLookup()
    for sub in subdomains:
        hosts += 1
        ids.add(sub.id)
        collect_subdomain_matches(sub, product_index, cve_by_id, min_confidence, scan_history, rows, fix_lookup, leads)
        if hosts % batch == 0:
            matches += save_matches(rows, covered=(ids, pool))
            rows, ids = [], set()
    return hosts, matches + save_matches(rows, covered=(ids, pool))


# One product index per process, rebuilt only when the CVE table changes (a new or re-synced entry moves the key).
_INDEX_CACHE = {"key": None, "value": None}
_LOCAL_CACHE = {"key": None, "value": None}
_CVE_FIELDS = ("id", "cve_id", "affected", "kev", "epss_reached", "exploit_db", "cvss")


def _pool(qs, cache, key):
    if cache["key"] == key:
        return cache["value"]
    cve_by_id = {c.id: c for c in qs}
    for c in cve_by_id.values():
        c.affected = clean_affected(c.affected)
    value = (cve_by_id, build_product_index(cve_by_id.values()))
    cache.update(key=key, value=value)
    return value


def cve_pool(cve_limit=None):
    """(cve_by_id, product_index) for the stored CVEs, cached per process. Never loads the prose columns."""
    from django.db.models import Count, Max, Q

    from cveFeed.models import CVEEntry

    stamp = CVEEntry.objects.aggregate(n=Count("id"), latest=Max("synced_at"), local=Count("id", filter=Q(local_only=True)))
    key = (cve_limit, stamp["n"], stamp["latest"], stamp["local"])
    if _INDEX_CACHE["key"] == key:
        return _INDEX_CACHE["value"]
    # a rejected CVE matches nothing, and neither does one only usable from the host itself (cveFeed.locality)
    qs = CVEEntry.objects.exclude(status__icontains="reject").exclude(local_only=True).only(*_CVE_FIELDS).order_by("-published_at")
    return _pool(qs[:cve_limit] if cve_limit else qs, _INDEX_CACHE, key)


def local_pool():
    """(cve_by_id, product_index) for the CVEs only usable from the host itself. External correlation never reads it: only what a host
    reported about itself (cveFeed.inventory_match) is checked against these."""
    from django.db.models import Count, Max

    from cveFeed.models import CVEEntry

    qs = CVEEntry.objects.exclude(status__icontains="reject").filter(local_only=True)
    stamp = qs.aggregate(n=Count("id"), latest=Max("synced_at"))
    return _pool(qs.only(*_CVE_FIELDS).order_by("-published_at"), _LOCAL_CACHE, (stamp["n"], stamp["latest"]))


def _index_hit(token, product_index):
    """Whether any product of the index can be ``token``: by name, or by an alias (nmap's "Apache httpd" is the advisory's "HTTP Server")."""
    return (any(name_matches_token(token, product_token) for product_token in _candidate_tokens(token, product_index))
            or any(alias in product_index for alias in PRODUCT_ALIASES.get(token, ())))


def latest_scan_q(prefix=""):
    """The rows of each domain's current inventory: hosts are stored once per scan, so listings, matches and auto-fire must read
    one scan's copy, not every scan's. That is the domain's latest successful full scan, plus the successful host-pipeline scans
    (a rescan, a re-test, new hosts from certificate transparency) that ran after it, plus rows with no scan. A host-pipeline scan
    holds only the hosts it ran on, so it adds to the inventory instead of replacing it; when a host appears in more than one of
    these scans, the newest row wins. A domain that has never had a successful full scan keeps all its rows (newest per host),
    so a first scan in progress (or one that failed part way) does not hide the hosts it found. ``prefix`` reaches the host
    from another model ("subdomain__" for a CVEMatch)."""
    from django.db.models import Exists, F, Max, OuterRef, Q, Subquery
    from django.db.models.functions import Coalesce

    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory, Subdomain

    done = ScanHistory.objects.filter(scan_status=2)
    full = done.exclude(tasks__contains=[HOST_PIPELINE_TASK])
    latest_full = full.values("domain_id").annotate(last=Max("id")).values("last")
    newest_full_of = full.filter(domain_id=OuterRef("domain_id")).order_by("-id").values("id")[:1]
    after_full = done.filter(tasks__contains=[HOST_PIPELINE_TASK]).annotate(
        full_id=Coalesce(Subquery(newest_full_of), 0)).filter(id__gt=F("full_id")).values("id")
    newer_row = Subdomain.objects.filter(scan_history_id__in=after_full, target_domain_id=OuterRef(prefix + "target_domain_id"),
                                         name=OuterRef(prefix + "name"), scan_history_id__gt=OuterRef(prefix + "scan_history_id"))
    return ((Q(**{prefix + "scan_history_id__in": latest_full}) | Q(**{prefix + "scan_history_id__in": after_full})
             | Q(**{prefix + "scan_history__isnull": True})
             | ~Q(**{prefix + "target_domain_id__in": full.values("domain_id")}))
            & ~Q(Exists(newer_row)))


def candidate_subdomains(product_index, base=None):
    """Subdomains worth correlating against ``product_index``: hosts carrying a technology or an nmap product that
    matches one of its tokens, from each domain's current inventory (latest_scan_q: the latest full scan, the host-pipeline scans after
    it, and the scan-less rows certificate transparency created). A partial scan of one host is not the whole inventory, and older
    scans' copies of the same host are skipped. Returns a queryset."""
    from django.db.models import Q

    from cveFeed.models import CVEMatch
    from startScan.models import IpAddress, Port, Subdomain, Technology

    tech_ids, tokens = [], {}
    for tech_id, tech_name in Technology.objects.values_list("id", "name").iterator():
        token = _norm(split_name_version(tech_name)[0])
        if len(token) < _MIN_TOKEN:
            continue
        if token not in tokens:
            tokens[token] = _index_hit(token, product_index)
        if tokens[token]:
            tech_ids.append(tech_id)
    products = set()
    for product in Port.objects.exclude(product="").values_list("product", flat=True).distinct():
        token = _norm(product.strip())
        if len(token) >= _MIN_TOKEN and _index_hit(token, product_index):
            products.add(product)

    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values("subdomain_id")
    ips = IpAddress.ports.through.objects.filter(port__product__in=products).values("ipaddress_id")
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values("subdomain_id")
    matched = CVEMatch.objects.filter(source__in=_CORRELATED_SOURCES).values("subdomain_id")  # re-checked so a stale match closes
    qs = (Subdomain.objects if base is None else base).filter(Q(id__in=by_tech) | Q(id__in=by_port) | Q(id__in=matched)).filter(latest_scan_q())
    return qs.prefetch_related("technologies", "ip_addresses__ports")


def ai_confirm_match(match, provider=None):
    """Triage one CVEMatch with the user's chosen AI model and store the result as the legacy ``ai_verdict``.

    The model's answer goes through the same rules as every finding (cveFeed.triage.apply_rules): confirmed, likely and
    needs_validation map to affected, affected and uncertain; likely_false_positive and not_applicable map to not_affected, but never
    for a match with hard evidence (a version inside the affected range, a template hit, a distribution tracker listing the package as
    affected), which stays at least uncertain. ``provider`` defaults to the one configured in AIProviderSettings; with none configured
    (or on a provider error) the match is returned unconfirmed, so deterministic correlation still works without an API key.
    This is the stateless single-match form; auto-fire and the pipeline use cveFeed.triage, which also shares one answer per signature.
    """
    from reNgine.ai_providers import AIProviderError, triage_finding
    try:
        if provider is None:
            from reNgine.ai_settings import get_configured_provider
            provider = get_configured_provider()
        if provider is None:
            return match
        from cveFeed import activity, triage
        cve = match.cve_entry
        host = match.subdomain.name if match.subdomain else ""
        described = triage.describe_cve_match(match)
        domain = getattr(match.subdomain, 'target_domain', None)
        project = getattr(domain, 'project_id', None)
        with activity.step('confirm', f'Asking {provider.name} whether {host or "a host"} is affected by {cve.cve_id}',
                           project=project, cve_id=cve.cve_id) as handle:
            answer = triage_finding(provider, 'cve_match', described['payload'])
            outcome = triage.apply_rules('cve_match', described['facts'], answer['parsed'])
            handle.done_message = (f'{host}: {outcome["classification"].replace("_", " ")} for {cve.cve_id}'
                                   f' ({outcome["reason"][:120]})')
    except AIProviderError as e:
        logger.warning("AI confirmation skipped for match %s: %s", match.pk, e)
        return match
    match.ai_verdict = triage.verdict_for(outcome["classification"])
    match.ai_reason = outcome["reason"][:2000]
    match.ai_model = answer["model"]
    match.save(update_fields=["ai_verdict", "ai_reason", "ai_model", "updated_at"])
    from cveFeed import scoring
    scoring.rescore_for_matches([match])  # a verdict moves the host's score
    return match
