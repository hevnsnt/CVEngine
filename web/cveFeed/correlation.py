"""Correlate stored cve.now entries against the discovered asset inventory.

Deterministic candidate generation first: match each discovered Technology (and
its version, when reNgine captured one) against the product/package names and
version ranges in `CVEEntry.affected`. Candidates become `CVEMatch` rows with a
heuristic confidence; the AI triage (cveFeed.triage) then judges each one,
which is what makes exposure precise rather than noisy.

The version/name helpers are pure Python (no Django import) so they are unit
testable on their own.
"""
import json
import logging
import os
import re
from functools import cmp_to_key

from cvengine_scanner import cms, versions

from cveFeed import cms_evidence
from cveFeed import distro as distro_lib
from cveFeed import js_libraries
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
            return base.strip(), stated_version(base, ver.strip())
    slash = split_slash_version(name)
    if slash:
        return slash[0], slash[1]
    return name, ""


# A Server-header token stored whole as a product or a technology name ("nginx/1.28.3", "awselb/2.0", "nginx/1.24.0 (Ubuntu)"): nmap's
# http-server-header script fills an unidentified service's product with the header, so the version sits in the name and the name matches
# nothing. The product is one word (no space, no "/" or ":", so never a path or a URL) and what follows the "/" is a version (digits and
# dots, a "v" before it allowed), then the end or a space (a comment, a module). A protocol's own "HTTP/1.1" is not a product.
_SLASH_VERSION_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._+-]*)/[vV]?(\d+(?:\.\d+)*)(?:\s+(.*))?$", re.DOTALL)
_PROTOCOL_NAMES = frozenset({"http", "https", "spdy", "quic", "tls", "ssl", "dtls", "sip", "rtsp", "rtp", "ftp", "smtp", "h2", "h3"})


def split_slash_version(text):
    """``(product, version, rest)`` of a ``product/version`` Server-header token stored as a name, or None when the text is not one (a path,
    a URL, ``foo/bar``, a protocol). ``rest`` is what followed it: the comment without its parentheses ("Ubuntu") or the next tokens. A bare
    major or a SKU ("Microsoft-Azure-Application-Gateway/v2") is no version (it would sit inside every "before 2.x" range), and a protocol's
    version (``stated_version``: Microsoft-HTTPAPI/2.0) is never the product's: the product is still split off, without one."""
    found = _SLASH_VERSION_RE.match(str(text or "").strip()[:500])
    if not found or found.group(1).lower() in _PROTOCOL_NAMES:
        return None
    product, number, rest = found.group(1), found.group(2), (found.group(3) or "").strip()
    if rest.startswith("(") and rest.endswith(")") and rest.count("(") == 1:
        rest = rest[1:-1].strip()
    return product, stated_version(product, number if "." in number else ""), rest


def split_port_product(product, version=""):
    """``(product, version, rest)`` of a stored port product as correlation reads it: a ``product/version`` header token is split
    (``split_slash_version``), a version the scanner stated in its own column wins, and a protocol's version is dropped."""
    product, version = str(product or "").strip(), str(version or "").strip()
    slash = split_slash_version(product)
    if slash:
        return slash[0], stated_version(slash[0], version) or slash[1], slash[2]
    return product, stated_version(product, version), ""


def stored_technology_name(name):
    """A technology name in the stored form ("Name" or "Name:version"): a ``product/version`` header token becomes ``product:version``."""
    slash = split_slash_version(name)
    if not slash:
        return name
    return f"{slash[0]}:{slash[1]}" if slash[1] else slash[0]


def stated_version(name, version):
    """``version``, or "" when the name's "/x.y" is the version of a protocol or an API, never of the product
    (``protocol_versions`` in data/product_aliases.json: Microsoft-HTTPAPI/2.0 is the HTTP Server API's version, not a Windows build)."""
    return "" if version and _norm(name) in PROTOCOL_VERSION_NAMES else version


# a technology template named for the product ("Nginx version", "Microsoft IIS Detect"): the technology pass drops the word now, rows an
# earlier build stored still carry it
_TEMPLATE_WORD_RE = re.compile(r"\s+(?:version|detect|detected|detection|fingerprint)\s*$", re.IGNORECASE)


def tech_name(name):
    """The product a stored technology name names, as correlation matches it: the name without a trailing template word, and a
    detector's name for a reading that names another product (``renames`` in data/product_aliases.json: "AspNet Version Disclosure" is
    the X-AspNet-Version header, read as ASP.NET and then as its CLR line by ``read_technology``)."""
    stripped = _TEMPLATE_WORD_RE.sub("", name or "")
    stripped = stripped if stripped.strip() else (name or "")
    return TECH_RENAMES.get(_norm(stripped), stripped)


def read_technology(stored):
    """``(name, version)`` of a stored technology as correlation reads it: split (``split_name_version``), the template word and a
    detector's name dropped (``tech_name``), and an X-AspNet-Version CLR line read as the .NET Framework's (``versions.legacy_aspnet``)."""
    name, version = split_name_version(stored or "")
    return versions.legacy_aspnet(tech_name(name), version)


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
# Junos: 22.4R2-S2 is the second service release of release 2 of 22.4, so 22.4R2 < 22.4R2-S1 < 22.4R2-S2 < 22.4R3 < 23.2R1. The release and the
# service release become the third and fourth components. Only a two-part version of 8 or later followed by an upper-case R and a number
# (the form Juniper alone uses), so no other version string is read differently.
_JUNOS_RELEASE_RE = re.compile(r"^R(\d+)(?:-S(\d+)|\.(\d+))?(?![0-9A-Za-z])")
# Ivanti and Pulse Connect Secure write a service release the same way with a dot: 22.7R2.5 is the fifth service release of 22.7R2, so
# 22.7R2 < 22.7R2.4 < 22.7R2.5 < 22.7R3 (the third group above; Junos's own respins, 15.1R7.9, order the same way).
# NetScaler (Citrix ADC and Gateway) names a build of a release train: 13.1-49.15 is build 49.15 of 13.1, so 13.1-48.47 < 13.1-49.15 < 14.1-4.42.
# Only a two-part train of 10 or later followed by a dash and a two-part build; it reads as a patched release (an upper bound "13.1" names the
# whole train, as "8.9" does for 8.9p1).
_TRAIN_BUILD_RE = re.compile(r"^-(\d{1,3})\.(\d{1,4})(?![\d.A-Za-z])")
# PAN-OS names a hotfix of a release: 10.2.9-h1 is the first hotfix of 10.2.9, so 10.2.9 < 10.2.9-h1 < 10.2.9-h3 < 10.2.10.
_HOTFIX_RE = re.compile(r"^-h(\d{1,3})(?![0-9A-Za-z])")
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
    text = _EPOCH_RE.sub("", str(value)).strip().replace("\\", "")  # a CPE escapes "15.2\\(4\\)m7"
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        text = text[1:]
    text = _MARIADB_PREFIX_RE.sub("", text)  # MariaDB's handshake says "5.5.5-10.6.12-MariaDB": the real version follows the prefix
    if _HASH_RE.match(text) and not text.isdigit():
        return None
    dated = _DATE_RE.match(text)  # 2024-01-15 is the date 2024, 1, 15, not the version 2024
    match = None if dated else (_VER_RE.match(text) if strict else _VER_RE.search(text))
    if not match and not dated:
        return None
    if match and text[match.end():match.end() + 1] == "(":
        # a Cisco build ("15.2(4)M7"): never a range bound, and as a host's version it can only equal a listed build (``_Build``)
        if strict:
            return None
        build = _Build(int(part) for part in match.group(1).split("."))
        build.text = build_key(text[match.start():].split()[0])
        return build
    try:
        parts = [int(part) for part in dated.groups(default="0")[:3]] if dated else [int(part) for part in match.group(1).split(".")]
    except ValueError:
        return None
    if dated:
        return tuple(parts[:3 if dated.group(3) else 2])
    rest = text[match.end():]
    junos = _JUNOS_RELEASE_RE.match(rest) if len(parts) == 2 and parts[0] >= 8 else None
    if junos:
        return tuple(parts + [int(junos.group(1)), int(junos.group(2) or junos.group(3) or 0)])
    train = _TRAIN_BUILD_RE.match(rest) if len(parts) == 2 and parts[0] >= 10 else None
    if train:
        return _patched(parts, parts + [int(train.group(1)), int(train.group(2))])
    hotfix = _HOTFIX_RE.match(rest) if len(parts) == 3 else None
    if hotfix:
        return _patched(parts, parts + [int(hotfix.group(1))])
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


# A build a vendor names with a parenthesised rebuild: Cisco IOS "15.2(4)M7", NX-OS "9.3(8)" and "7.0(3)I7(5a)", ASA's own "9.16(4)18", Zyxel
# "2.90(AAHK.2)C0". Read for its first numbers it is 15.2, which would put every 15.2 build (and, as a bound, every 15.x release) inside a
# range it says nothing about. Such a version is only ever compared for equality with a build an advisory lists (``item_verdict``), the way
# NVD's CPEs spell it: lower case, the parentheses kept ("15.2(4)m7").
_BUILD_KEY_RE = re.compile(r"^[0-9][0-9a-z.()_+~-]*$")
_LEADING_ZEROS_RE = re.compile(r"(?<![0-9])0+(?=[0-9])")  # IOS XE prints 17.09.04a for the build its advisories list as 17.9.4a
_DIGIT_BUILD_RE = re.compile(r"^(\d+(?:\.\d+)*)\((\d+)\)(\d*)$")  # ASA "9.16(4)18" is the build its advisories list as 9.16.4.18
MAX_BUILD_LENGTH = 64
MAX_BUILDS_PER_ITEM = 2000  # Cisco's largest list (CVE-2023-20109, IOS) has 674


class _Build(tuple):
    """A host's version that is a parenthesised build (see ``build_key``): it compares like the release it starts with everywhere outside
    matching, as it always did, and matching never reads it against a range, only against the exact builds an advisory lists."""
    text = None


def build_key(value):
    """The normalized text of one exact build, for equality only: lower case, no "v" prefix, no leading zeros in a number, parentheses kept
    ("15.2(4)M7" -> "15.2(4)m7", "17.09.04a" -> "17.9.4a"). None for text that is not one build (empty, too long, spaces or other words)."""
    text = str(value or "").strip().lower().replace("\\", "")
    if text[:1] == "v" and text[1:2].isdigit():
        text = text[1:]
    text = _LEADING_ZEROS_RE.sub("", text)
    return text if len(text) <= MAX_BUILD_LENGTH and _BUILD_KEY_RE.match(text) else None


def build_keys(value):
    """Every key the build ``value`` is listed under: its own, and for a build whose parenthesised part and suffix are numbers (ASA's
    "9.16(4)18", "9.8(4)") the dotted form the advisories use ("9.16.4.18", "9.8.4")."""
    key = build_key(value)
    if not key:
        return []
    digits = _DIGIT_BUILD_RE.match(key)
    return [key] + ([".".join(p for p in digits.groups() if p)] if digits else [])


def _vcmp(a, b):
    """Compare two version tuples, zero-padded so (1,18) == (1,18,0)."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in_range(ver, rng):
    """Return True / False / None(unknown) for ver within an affected range dict. A range with no usable bound is unknown,
    never "in range": only a real bound can put a version inside it."""
    if ver is None or isinstance(rng, _Unpaired) or isinstance(ver, _Build):
        # a bound that pairing could not place (``pair_split_ranges``) says nothing certain about any version, and a parenthesised build is
        # never placed inside a range by its first numbers (``item_verdict`` compares it with the listed builds)
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


# Names scanners report that differ from the feed's product naming, read from data/product_aliases.json (every entry cites the CPE or CVE
# record that spells the product that way; cveFeed.tech_coverage measures what is still unmatched). Dropping the vendor token must not create
# false negatives for these. Aliases are the only widening, and each is held to its vendors.
ALIASES_FILE = os.path.join(os.path.dirname(__file__), "data", "product_aliases.json")
PRODUCT_ALIASES = {}  # normalized tech token -> product tokens naming the same software
ALIAS_VENDORS = {}  # (tech token, product token) -> vendor tokens the record must name, when it names one
NAME_VENDORS = {}  # tech token -> (vendor tokens, a record must name one): a bare name another vendor uses for a different product
AMBIGUOUS_PRODUCTS = set()  # product tokens two vendors use: a record naming no vendor never confirms a name for them
VENDOR_CLASSES = {}  # vendor token -> the vendor tokens that are the same vendor across renames and acquisitions
TECH_RENAMES = {}  # normalized detector name -> the product name its reading is read as ("AspNet Version Disclosure" -> "ASP.NET")
PROTOCOL_VERSION_NAMES = set()  # normalized names whose stated version is a protocol's or an API's, never the product's


def _vendor_tokens(values):
    return tuple(t for t in (_norm(v, True) for v in values or ()) if t)


def load_aliases(path=ALIASES_FILE):
    """Read the alias data into the tables above (replacing what they held). Returns the parsed document."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    aliases, alias_vendors, name_vendors, ambiguous, classes = {}, {}, {}, set(), {}
    for entry in doc.get("aliases", ()):
        vendors = _vendor_tokens(entry.get("vendors"))
        products = {t for t in (_norm(p, True) for p in entry.get("products", ())) if len(t) >= _MIN_TOKEN}
        for name in entry.get("names", ()):
            token = _norm(name)
            for product in products - {token}:
                aliases.setdefault(token, set()).add(product)
                alias_vendors[(token, product)] = vendors
    for entry in doc.get("restrict", ()):
        for name in entry.get("names", ()):
            name_vendors[_norm(name)] = (_vendor_tokens(entry.get("vendors")), bool(entry.get("require_vendor")))
    for entry in doc.get("ambiguous_products", ()):
        ambiguous.add(_norm(entry.get("product"), True))
    for entry in doc.get("vendor_renames", ()):
        group = frozenset(_vendor_tokens(entry.get("vendors")))
        for vendor in group:
            classes[vendor] = classes.get(vendor, frozenset()) | group
    renames = {_norm(name): entry["to"] for entry in doc.get("renames", ()) for name in entry.get("names", ()) if entry.get("to")}
    protocol = {_norm(name) for entry in doc.get("protocol_versions", ()) for name in entry.get("names", ())}
    for table, value in ((PRODUCT_ALIASES, aliases), (ALIAS_VENDORS, alias_vendors), (NAME_VENDORS, name_vendors), (VENDOR_CLASSES, classes),
                         (TECH_RENAMES, renames)):
        table.clear()
        table.update(value)
    for table, value in ((AMBIGUOUS_PRODUCTS, ambiguous), (PROTOCOL_VERSION_NAMES, protocol)):
        table.clear()
        table.update(value)
    return doc


load_aliases()


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
            if item["ranges"] and _is_netscaler(item):
                item["ranges"] = [_netscaler_range(r) for r in item["ranges"]]
        if "builds" in item:  # the exact builds the advisory lists (cveFeed.intel.convert_affected), each a ``build_key``
            builds = item["builds"]
            builds = [b for b in (build_key(b) for b in builds[:MAX_BUILDS_PER_ITEM] if isinstance(b, str)) if b] if isinstance(builds, list) else []
            item = {**item, "builds": list(dict.fromkeys(builds))}
            if not item["builds"]:
                del item["builds"]
        out.append(item)
    return out


_NETSCALER_TRAIN_RE = re.compile(r"^(\d{2}\.\d)(?:-[A-Za-z]{2,8})?$")  # 13.1, 13.1-FIPS, 12.1-NDcPP
_NETSCALER_BUILD_RE = re.compile(r"^\d{1,3}\.\d{1,4}$")


def _is_netscaler(item):
    vendor, product = _norm(item.get("vendor")), _norm(item.get("product"))
    return product.startswith("netscaler") or (vendor in ("citrix", "netscaler") and product in ("adc", "gateway", "applicationdeliverycontroller"))


def _netscaler_range(rng):
    """A NetScaler record's range read the way Citrix writes it: the release train as ``introduced`` and only the build as the bound
    (``introduced 13.1, fixed 49.15`` is 13.1 up to build 49.15, so ``fixed`` reads 13.1-49.15). Read literally it would put every later train
    (14.1) inside it. A range already written with whole builds is unchanged."""
    train = _NETSCALER_TRAIN_RE.match(str(rng.get("introduced") or "").strip())
    if not train:
        return rng
    out = dict(rng)
    for key in ("fixed", "lastAffected"):
        bound = str(rng.get(key) or "").strip()
        if _NETSCALER_BUILD_RE.match(bound):
            out[key] = f"{train.group(1)}-{bound}"
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


# what a feed writes for a vendor it does not name
_NO_VENDOR = frozenset({"na", "unknown", "none", "unspecified"})


def _real_vendor(item):
    """The item's normalized vendor, or '' when it names none (or writes a placeholder such as "n/a" or "[UNKNOWN]")."""
    vendor = _norm(item.get("vendor"), True)
    return "" if vendor in _NO_VENDOR else vendor


def _with_renames(hints):
    """The hints with every other spelling of the same vendor (data/product_aliases.json vendor_renames: nmap's igor_sysoev is F5's nginx)."""
    out = []
    for hint in hints:
        out.append(hint)
        out.extend(VENDOR_CLASSES.get(hint, ()))
    return out


def _vendor_ok(item, *hints):
    """True when the item names no vendor, or its vendor contains one of the (normalized) hints or another spelling of it."""
    vendor = _real_vendor(item)
    return not vendor or any(h and (h in vendor or vendor in h) for h in _with_renames(hints))


def _vendor_led(token):
    """``(lead, rest token)`` for each way a discovered name may start with its vendor: "Ivanti Connect Secure" is ("ivanti", "connectsecure"),
    "Palo Alto Networks GlobalProtect" also ("paloaltonetworks", "globalprotect"). The rest must still name a product on its own, and a record
    reached this way must name that vendor (``_led_by``)."""
    out = []
    for words in _words_for(token):
        for k in range(1, min(3, len(words) - 1) + 1):
            lead, rest = words[:k], words[k:]
            if len("".join(lead)) >= _MIN_TOKEN and _word_run_ok(rest):
                out.append((lead, _norm(" ".join(rest))))
    return out


def _led_by(item, lead):
    """Whether the item's vendor is the vendor a name leads with: the same token ("paloaltonetworks"), its first words ("Progress Software
    Corporation" for "Progress"), or another spelling of it."""
    vendor = _real_vendor(item)
    if not vendor:
        return False
    joined = "".join(lead)
    if vendor == joined or vendor in VENDOR_CLASSES.get(joined, ()):
        return True
    return tuple(_WORD_RE.findall(str(item.get("vendor") or "").lower()))[:len(lead)] == tuple(lead)


def _named_vendor(tech_token, product_token):
    """The vendor words a discovered name puts in front of the product it matched, and that the product's own name does not carry: "cisco"
    for "Cisco IOS" matched to "IOS", nothing for "Cisco IOS XE Software" matched to itself. Empty when the name names no vendor."""
    product_words = {w for words in _words_for(product_token) for w in words}
    for words in _words_for(tech_token):
        lead = []
        for word in words[:-1]:
            if word not in VENDOR_PREFIX_WORDS or word in product_words:
                break
            lead.append(word)
        if lead:
            return tuple(lead)
    return ()


def _named_vendor_ok(tech_token, product_token, item):
    """Whether the vendor a discovered name gives ("Cisco IOS") agrees with the vendor the affected entry names. A vendor word lets a name
    match the bare product ("IOS"), so it must be that vendor's product: Apple's iOS is not Cisco's IOS. An entry with no vendor, or whose
    vendor is the project itself ("nginx" for nginx, "getbootstrap" for bootstrap), is not contradicted."""
    lead = _named_vendor(tech_token, product_token)
    if not lead:
        return True
    vendor = _norm(item.get("vendor"), True)
    if not vendor or vendor in _NO_VENDOR:
        return True
    named = "".join(lead)
    if named in vendor or vendor in named or any(len(w) >= 3 and w in vendor for w in lead):
        return True
    return product_token in vendor


def _item_hits(item, token, aliases=(), cpe_product=None, cpe_vendor="", led=()):
    """Whether one affected entry names the discovered product. With a CPE the product must equal it (and the vendor,
    when the entry has one, must agree); otherwise fuzzy token containment, plus the aliases of data/product_aliases.json held to their
    vendors, plus a name that leads with the entry's own vendor (``led``, from ``_vendor_led``)."""
    restrict = NAME_VENDORS.get(token)
    if restrict:  # a bare name another vendor also uses for a different product ("Express", ".NET")
        vendors, required = restrict
        if (required and not _real_vendor(item)) or not _vendor_ok(item, *vendors):
            return False
    own = {_norm(item.get(k), True) for k in ("product", "package")} - {""}
    if cpe_product:
        if cpe_product in own:
            return _vendor_ok(item, cpe_vendor, cpe_vendor[:6])
        # an entry named some other way (the CNA's own "Apache HTTP Server" next to NVD's "http_server") still counts when it is the same
        # vendor's: the CPE must not hide the records that do not use its spelling. An entry that names no vendor counts only when its own
        # product name starts with the CPE's vendor ("Apache Tomcat" for cpe:/a:apache:tomcat)
        if not _vendor_ok(item, cpe_vendor, cpe_vendor[:6]):
            return False
        if not _real_vendor(item) and not (len(cpe_vendor) >= _MIN_TOKEN and any(
                o.startswith(v) for o in own for v in _with_renames((cpe_vendor,)) if len(v) >= _MIN_TOKEN)):
            return False
    tokens = affected_product_tokens(item)
    unvouched = not _real_vendor(item) and bool(tokens & AMBIGUOUS_PRODUCTS)  # "iOS" with no vendor: Apple's or Cisco's?
    if any(name_matches_token(token, t) and _named_vendor_ok(token, t, item) for t in tokens) and not unvouched:
        return True
    for alias in aliases:
        vendors = ALIAS_VENDORS.get((token, alias), ())
        if alias in tokens and _vendor_ok(item, *vendors) and not unvouched:
            return True
        # the alias read as a name ("Microsoft Exchange Server" for "Microsoft Exchange Server 2019 Cumulative Update 12"), only for an entry
        # that names one of the alias's vendors
        if vendors and _real_vendor(item) and _vendor_ok(item, *vendors) and any(name_matches_token(alias, t) for t in tokens):
            return True
    return any(_led_by(item, lead) and any(name_matches_token(rest, t) for t in tokens) for lead, rest in led)


def _bounded(rng):
    return version_in_range((0,), rng) is not None  # a range with at least one usable bound


class _Unpaired(dict):
    """A range whose bound ``pair_split_ranges`` could not place: it reads as a plain dict everywhere, and ``version_in_range`` says unknown."""


def _only(rng, key):
    """True for a range that carries ``key`` and no other bound."""
    return bool(rng.get(key)) and not any(rng.get(other) for other in ("introduced", "fixed", "lastAffected") if other != key)


def _kind(rng):
    """``("open"|"fixed"|"last", parsed bound)`` for a range that is one bound of a branch and can be compared, else None."""
    if isinstance(rng, _Unpaired) or str(rng.get("type") or "SEMVER").upper() not in ("SEMVER", "ECOSYSTEM"):
        return None
    for kind, key in (("open", "introduced"), ("fixed", "fixed"), ("last", "lastAffected")):
        if _only(rng, key):
            parsed = parse_version(rng[key], strict=True)
            return (kind, parsed) if parsed is not None else None
    return None


def _join(rng, nxt):
    """The branch ``rng`` (introduced only) and the range right after it make, or None when they are not one branch."""
    one = _kind(rng)
    if not one or one[0] != "open":
        return None
    two = _kind(nxt)
    if not two or two[0] == "open" or str(rng.get("type") or "SEMVER").upper() != str(nxt.get("type") or "SEMVER").upper():
        return None
    order = _vcmp(two[1], one[1])
    if order < 0 or (order == 0 and two[0] == "fixed"):
        return None  # the fix is older than the start (a branch with no release, "fixed" at its own start), or the last affected is
    key = "fixed" if two[0] == "fixed" else "lastAffected"
    return {**rng, key: nxt[key]}


def _pair_interleaved(ranges):
    """Pair what the adjacent pass left: introduced-only ranges and the fixed/lastAffected-only ranges that sit inside them.

    A fix older than every start is one more fix-only range (a branch whose start was not published) and stays as it is. A fix at or after
    the lowest start has an introduced range it could close: the bounds are sorted by version and read as the events they are, one
    introduced and then the fix that ends it (``[i1.0, i2.0, f1.5, f2.5]`` is 1.0 to 1.5 and 2.0 to 2.5, wherever the feed listed them), and
    the last introduced may be left open (a branch with no fix). Any other order (two starts then a fix, a fix at its own start, a type that
    differs) cannot be paired without guessing: those ranges become ``_Unpaired``, which are unknown, never "in range"."""
    if not (any(_only(r, "introduced") for r in ranges) and any(_only(r, "fixed") or _only(r, "lastAffected") for r in ranges)):
        return ranges  # the common case, decided without reading a version
    kinds = [_kind(r) for r in ranges]
    opens = [i for i, k in enumerate(kinds) if k and k[0] == "open"]
    closers = [i for i, k in enumerate(kinds) if k and k[0] != "open"]
    if not opens or not closers:
        return ranges
    lowest = min(kinds[i][1] for i in opens)
    inside = [i for i in closers if _vcmp(kinds[i][1], lowest) >= 0]
    if not inside:
        return ranges
    rank = {"fixed": 0, "open": 1, "last": 2}  # at one version a fix comes before a start (an empty branch), a last affected after it (one release)

    def order(a, b):
        return _vcmp(kinds[a][1], kinds[b][1]) or rank[kinds[a][0]] - rank[kinds[b][0]]
    events = sorted(opens + inside, key=cmp_to_key(order))
    pairs, pending = {}, None
    ok = len({str(ranges[i].get("type") or "SEMVER").upper() for i in events}) == 1
    for i in events if ok else ():
        if kinds[i][0] == "open":
            if pending is not None:
                ok = False  # two starts in a row: which one does the next fix end?
                break
            pending = i
        elif pending is None:
            ok = False  # a fix at its own start: no branch
            break
        else:
            pairs[pending] = i
            pending = None
    if not ok:
        unsure = set(opens + inside)
        return [_Unpaired(r) if i in unsure else r for i, r in enumerate(ranges)]
    joined = {o: {**ranges[o], **{k: ranges[c][k] for k in ("fixed", "lastAffected") if ranges[c].get(k)}} for o, c in pairs.items()}
    used = set(pairs.values())
    return [joined.get(i, r) for i, r in enumerate(ranges) if i not in used]


def pair_split_ranges(ranges):
    """The ranges with each ``introduced``-only range joined to the ``fixed``- or ``lastAffected``-only range that closes it.

    The CVE List writes a branch as two ``versions`` entries when its lower bound is "7.13.0" and its upper bound is "lessThan 7.13.7", and the
    conversion keeps them as two ranges: ``[{"introduced": "7.13.0"}, {"fixed": "7.13.7"}]``. Read alone, the first says "7.13.0 and every later
    version", the second "every version before 7.13.7", so the fixed 7.13.7, 7.18.1 and everything in between read as vulnerable (issue 205,
    CVE-2022-26134). Joined, they are the branch the advisory means. First a pair that alternates in order and whose end is newer than its start
    is joined; an ``introduced`` range with no closing range stays open (a branch with no fix). Then what is left is paired by version
    (``_pair_interleaved``), and bounds that still cannot be placed are returned as ``_Unpaired``, which ``version_in_range`` reads as unknown. Any
    other shape is returned as it was."""
    out, i = [], 0
    ranges = list(ranges)
    while i < len(ranges):
        joined = _join(ranges[i], ranges[i + 1]) if i + 1 < len(ranges) else None
        if joined is not None:
            out.append(joined)
            i += 2
            continue
        out.append(ranges[i])
        i += 1
    return _pair_interleaved(out)


def prepared_ranges(ranges, keep_unusable=False):
    """The ranges of one affected entry as every reader must see them: dict ranges only, those with a usable bound joined into branches
    (``pair_split_ranges``). The matcher, the WordPress matcher, the triage brief, the detection strategy and the prompts all read this, so a
    brief, a check and a match agree on what an advisory says. ``keep_unusable`` appends the ranges with no usable bound (a git range, an
    "unspecified" bound) for a reader that shows the record rather than testing a version."""
    ranges = [r for r in ranges or [] if isinstance(r, dict)]
    paired = pair_split_ranges([r for r in ranges if _bounded(r)])
    return paired + [r for r in ranges if not _bounded(r)] if keep_unusable else paired


def range_verdict(ver, ranges):
    """``(result, deciding range, no_lower_bound)`` for ``ver`` against the ranges of one affected entry: result True / False / None
    (unknown) as for ``version_in_range``. The deciding range is the one that put ``ver`` inside (None for any other result);
    ``no_lower_bound`` is True when the answer came from a fix-only branch list (``fix_only_branch_verdict``). One entry with no usable
    bound is unknown. Main correlation and the WordPress matcher both decide through this, so they cannot read a range list differently."""
    prepared = prepared_ranges(ranges)
    if not prepared or isinstance(ver, _Build):
        return None, None, False  # a parenthesised build is compared only with listed builds (``item_verdict``)
    if fix_only_branch_list(prepared):
        # no lower bounds were published: each fix is compared only with the releases of its own line (issue 205)
        result, fixed = fix_only_branch_verdict(ver, prepared)
        return result, ({"fixed": str(fixed)[:60]} if result is True else None), True
    unknown = False
    for rng in prepared:
        result = version_in_range(ver, rng)
        if result is True:
            return True, {k: str(v)[:60] for k, v in rng.items() if k in ("introduced", "fixed", "lastAffected")}, False
        unknown = unknown or result is None
    return (None if unknown else False), None, False


def range_holds(version, rng):
    """True / False / None for the version text ``version`` against one range a match was decided on (``evidence['range']``): an exact build
    (``{"build": ...}``) holds only that build, any other range is read as ``version_in_range`` reads it."""
    if isinstance(rng, dict) and rng.get("build"):
        keys = build_keys(version)
        return (build_key(rng["build"]) in keys) if keys else None
    return version_in_range(parse_version(version), rng or {})


def _exact_single(rng):
    """A range that is one exact version (``introduced`` == ``lastAffected``, no fix): how one listed build is written as a range."""
    return isinstance(rng, dict) and bool(rng.get("introduced")) and rng.get("introduced") == rng.get("lastAffected") and not rng.get("fixed")


def item_verdict(ver, item, raw=None):
    """``range_verdict`` for one affected entry, with the exact builds it lists (``builds``, see cveFeed.intel.convert_affected).

    ``raw`` is the version text as read (``ver`` parsed from it). A version that is one of the listed builds is in range. An entry that lists
    exact builds and no other range is a closed list: a version that is not on it is not in range (15.2(4)M8 against a list holding
    15.2(4)M7), whatever its numbers. A parenthesised build (``_Build``) is never read against a range: it is in range only as a listed build
    or a bound of exactly that build, and unknown against any other range. Without ``raw`` text an entry's ranges decide, as before."""
    ranges = [r for r in item.get("ranges") or [] if isinstance(r, dict)]
    builds = item.get("builds") if isinstance(item.get("builds"), list) else []
    keys = build_keys(raw if raw is not None else getattr(ver, "text", None))
    if keys:
        listed = set(builds)
        hit = next((k for k in keys if k in listed), None)
        if hit:
            return True, {"build": hit}, False
        if isinstance(ver, _Build):
            for rng in ranges:  # a bound that names exactly this build ("through 2.90(AAHK.2)C0")
                for bound in ("introduced", "lastAffected"):
                    if rng.get(bound) and build_key(rng[bound]) in keys and str(rng.get("type") or "SEMVER").upper() in ("SEMVER", "ECOSYSTEM"):
                        return True, {k: str(v)[:60] for k, v in rng.items() if k in ("introduced", "fixed", "lastAffected")}, False
        if listed:
            ranges = [r for r in ranges if not (_exact_single(r) and build_key(r["introduced"]) in listed)]
            if not ranges:
                return False, None, False  # a closed list of builds, and this version is not on it
    if isinstance(ver, _Build):
        return None, None, False
    return range_verdict(ver, ranges)


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
    if isinstance(ver, _Build):
        return False  # a parenthesised build is never placed by its first numbers
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


def named_hits(token, product_index, cve_by_id, cpe=None):
    """Yield ``(cve, [(affected index, item), ...])`` for every CVE with an affected entry that names the discovered product ``token``
    (normalized): its CPE's vendor and product first, then the name itself and its aliases (``PRODUCT_ALIASES``, ``ALIAS_VENDORS``). The one
    place that decides whether a name connects to a CVE record: ``_match_candidates`` judges versions on these entries and
    ``cveFeed.tech_coverage`` counts them."""
    cpe_parts = parse_cpe(cpe)
    candidate_ids, cpe_product, cpe_vendor = set(), None, ""
    if cpe_parts:
        cpe_vendor, cpe_product, _ = cpe_parts
        candidate_ids = set(product_index.get(cpe_product, ()))
        if not candidate_ids:
            cpe_product = None
    aliases = tuple(sorted(PRODUCT_ALIASES.get(token, ())))
    led = _vendor_led(token)
    # the name match is always added: a CPE names the product exactly, but CVEs whose own record spells it differently are still about it
    candidate_ids |= set(_fuzzy_ids(token, product_index))
    for alias in aliases:
        candidate_ids |= product_index.get(alias, set())
        if ALIAS_VENDORS.get((token, alias)):
            candidate_ids |= _fuzzy_ids(alias, product_index)
    for _lead, rest in led:
        candidate_ids |= _fuzzy_ids(rest, product_index)
    for cid in candidate_ids:
        cve = cve_by_id[cid]
        hit = [(i, item) for i, item in enumerate(cve.affected or []) if _item_hits(item, token, aliases, cpe_product, cpe_vendor, led)]
        if hit:
            yield cve, hit


def _match_candidates(name, ver, token, product_index, cve_by_id, cpe=None, details=None, raw=None):
    """Yield (cve, matched_product, in_range) for CVEs plausibly affecting a
    discovered product `token` (normalized) at version `ver` (tuple or None).

    Only the ranges of the affected entry that names the product are tested, never another product of the same vendor.
    An entry with no usable version bound gives in_range None (unknown), never True. ``cpe`` (nmap's 'cpe:/a:vendor:
    product:version') names the product exactly; it is tried first and the name match is the fallback.

    ``details``, when given, is a dict that receives ``{cve.id: {"affected_index", "range"}}``: which affected entry and which
    range decided the result (the evidence stored on the match). ``raw`` is the version text ``ver`` was read from: with it a version is
    also compared with the exact builds an entry lists (``item_verdict``).

    Reads only the pre-built product_index / cve_by_id; shared by the technology
    fingerprint path and the nmap/Port service path so both score identically.
    """
    from cveFeed.version_catalogue import line_conflict, product_line
    line = product_line(name)  # a SharePoint or Exchange line the host's name states: an entry for another line is not this product's
    for cve, hit in named_hits(token, product_index, cve_by_id, cpe):
        # Every hit names the same product (see name_matches_token): a wrapper or repackaging with its own version numbers
        # ("jquery-rails", "ingress-nginx") is another product and was never a hit, so its ranges are never compared.
        if line:
            hit = [(index, item) for index, item in hit if not line_conflict(line, item)]
            if not hit:
                continue  # every entry names another line (a 2019-only record for a 2016 farm): not this product's CVE
        in_range, matched_product = None, name
        if ver is not None:
            in_range, unknown = False, False
            for index, item in hit:
                result, rng, no_lower_bound = item_verdict(ver, item, raw)
                if result is True:
                    in_range = True
                    matched_product = item.get("product") or item.get("package") or name
                    if details is not None:
                        details[cve.id] = {"affected_index": index, "range": rng, **({"no_lower_bound": True} if no_lower_bound else {})}
                    break
                if result is None:
                    unknown = True  # no version bound to test against, or bounds that cannot be read with certainty
            if in_range is not True and unknown:
                in_range = None
            if in_range is False and not _is_ice(cve):
                for _i, item in hit:
                    prepared = prepared_ranges(item.get("ranges") or [])  # read as matching read them: a branch the feed split in two is one
                    if branch_unlisted(ver, prepared):
                        in_range = None  # older than every branch the advisory fixes: unlisted, not cleared
                        if details is not None:
                            details[cve.id] = {"affected_index": hit[0][0], "range": {}, "branch_unlisted": True,
                                               "lowest_listed_branch": ".".join(map(str, lowest_listed_branch(prepared)))}
                        break
        if details is not None and cve.id not in details and hit:
            details[cve.id] = {"affected_index": hit[0][0], "range": {}}
        yield cve, matched_product, in_range


def _is_ice(cve):
    """Whether the end-of-life branch rule passes this CVE by: its ``attention_tier`` (the legacy rating, under either heat policy) is ice.
    Which matches exist is a detection question, so the heat policy does not narrow it."""
    from cveFeed.threat import ICE, attention_tier
    return attention_tier(
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
            from django.db.models import Q

            from cveFeed.models import DistroFix
            which = Q(package=package)
            if distro == "rhel":
                which |= Q(package__startswith=package + ":")  # Red Hat's module streams of the package ("httpd:2.4"): distro.judge picks one
            self.memo[key] = [{"release": r.release, "fixed_version": r.fixed_version, "status": r.status, "package": r.package,
                               "advisory": r.advisory}
                              for r in DistroFix.objects.filter(which, distro=distro, cve_id=cve_id)]
        return self.memo[key]


def port_distro(port):
    """The distro info of a Port row, read from its banner fields (product, version, extra info, the CPEs nmap reported and kept in
    ``extra``, the banner's first line) by ``distro.parse_distro``: the same reading ingest persisted on the row, made again so a row stored by
    an older parser is read by today's (the upgrade backfill ``backfill_distro_readings`` rewrites the columns too). A row whose fields say
    nothing keeps what its columns hold. The package name is derived, never trusted from storage. Read once per row and banner."""
    extra = getattr(port, "extra", None) or {}
    cpes = extra.get("cpes") or [getattr(port, "cpe", "")]
    key = (port.product, port.version, getattr(port, "service_extra", ""), tuple(cpes), getattr(port, "banner", "") or "",
           getattr(port, "distro", ""), getattr(port, "distro_release", ""), getattr(port, "package_release", ""))
    cached = getattr(port, "_cv_distro", None)
    if cached and cached[0] == key:
        return dict(cached[1])
    info = distro_lib.parse_distro(port.product, port.version, getattr(port, "service_extra", ""), cpes, getattr(port, "banner", "") or "")
    if info["distro"] and info["distro"] == getattr(port, "distro", ""):
        # the columns may hold more than the fields show (a build another source of the same row stated): the same distribution's build wins
        if not info["package_release"] and getattr(port, "package_release", ""):
            info["package_release"], info["reading"] = port.package_release, "package"
            info["upstream_version"] = getattr(port, "upstream_version", "") or distro_lib.upstream_of(port.package_release)
            info["package"] = distro_lib.package_for(port.product, info["distro"], info["upstream_version"])
            info.pop("third_party", None)
            other = distro_lib.third_party(info["distro"], info["package_release"])
            if other:
                info["third_party"] = other
        if not info["release"] and getattr(port, "distro_release", ""):
            info["release"], info["release_basis"] = port.distro_release, "stored"
    if not info["distro"] and getattr(port, "distro", ""):
        info = {"distro": port.distro, "release": getattr(port, "distro_release", "") or "",
                "package_release": getattr(port, "package_release", "") or "", "upstream_version": getattr(port, "upstream_version", "") or ""}
        if info["distro"] in distro_lib.RHEL_FAMILY and not info["release"]:
            info["release"] = distro_lib.rhel_release(cpes)
        info["package"] = distro_lib.package_for(port.product, info["distro"], info["upstream_version"])
    try:
        port._cv_distro = (key, dict(info))
    except AttributeError:  # an object that takes no attributes is read again next time
        pass
    return info


def stored_distro(info):
    """What a Port row keeps of a distro reading beyond its four columns (``Port.extra['distro']``): the source package and what the host page
    and search read (codename, how the release was read, whether the build is known, another publisher, an unsynced tracker). {} for none."""
    if not info.get("distro"):
        return {}
    keep = ("package", "codename", "release_basis", "reading", "third_party", "tracker")
    return {k: str(info[k])[:64] for k in keep if info.get(k)}


def _host_readings(subdomain, ports=None):
    """``(families, releases)`` the host's open services, its addresses' OS reports and its Server header name: the distribution families seen,
    and per family the releases read."""
    from startScan.models import open_services
    families, releases = set(), {}
    ports = ports if ports is not None else [p for ip in subdomain.ip_addresses.all() for p in open_services(ip)]
    for port in ports:
        info = port_distro(port)
        if info.get("distro"):
            families.add(info["distro"])
            if info.get("release"):
                releases.setdefault(info["distro"], set()).add(info["release"])
    for ip in subdomain.ip_addresses.all():
        family = distro_lib.rhel_family_of_text(getattr(ip, "os_guess", "") or "")
        if family:
            families.add(family)
            release = distro_lib.rhel_release(text=ip.os_guess)
            if release:
                releases.setdefault(family, set()).add(release)
    header = getattr(subdomain, "webserver", "") or ""
    if header:
        seen = distro_lib.parse_distro("", "", header)
        if seen.get("distro"):
            families.add(seen["distro"])
            if seen.get("release"):
                releases.setdefault(seen["distro"], set()).add(seen["release"])
    return families, releases


def host_distro(subdomain, ports=None, readings=None):
    """The Red Hat family distribution a host runs, as ``{"distro", "release"}``, or ``{}``: what its open services say (the banner and
    the OS CPE nmap read, ``port_distro``), the Server header it sent (``Apache/2.4.37 (Red Hat Enterprise Linux)``) and the operating
    system its addresses report (a host inventory's "Red Hat Enterprise Linux 8.9"). A technology seen in the host's web response (Apache,
    OpenSSL, PHP) carries no distribution of its own, so it is judged against this. Only the Red Hat family is read this way, and any
    sign of another distribution makes it ``{}``: nothing is guessed. Releases that disagree leave the release unknown."""
    families, by_family = readings or _host_readings(subdomain, ports)
    if not families or not families <= set(distro_lib.RHEL_FAMILY):
        return {}
    releases = set().union(*by_family.values()) if by_family else set()
    return {"distro": "centos" if families == {"centos"} else "rhel", "release": releases.pop() if len(releases) == 1 else ""}


def host_debian_hint(subdomain, ports=None, readings=None):
    """The Debian or Ubuntu distribution a host's services and Server header name (``{"distro", "release"}``), or ``{}``: every reading must
    name the same one, and the release is kept only when the readings that state one agree. A technology on such a host (the Apache, PHP or
    OpenSSL a web response names) is judged as a hint by it (``tech_distro``): never shown fixed, because its build is not known."""
    families, by_family = readings or _host_readings(subdomain, ports)
    if len(families) != 1 or not families <= {"ubuntu", "debian"}:
        return {}
    family = next(iter(families))
    releases = by_family.get(family) or set()
    return {"distro": family, "release": releases.pop() if len(releases) == 1 else "", "hint": True}


def tech_distro(host, name, version, raw=""):
    """The distro info a technology is judged by. When the technology's own text is a package build (``PHP:8.1.2-1ubuntu2.14``, a banner token
    ``OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`` in ``raw``), that build. Otherwise, on a Red Hat family host (``host_distro``) or a host every reading
    of which names Debian or Ubuntu (``host_debian_hint``): the package that product is there, its upstream version, no package release (a web
    response never shows the build). ``None`` when there is none or the product is not a package cvENGINE maps."""
    if not version:
        return None
    own = distro_lib.parse_distro(name, version, "", (), raw if raw and "_" in raw else "")
    if own.get("distro") and own.get("package") and own.get("package_release"):
        if host and host.get("distro") == own["distro"] and not own.get("release") and host.get("release"):
            own["release"], own["release_basis"] = host["release"], "host"
        return {**own, "basis": "own"}
    if not host:
        return None
    upstream = re.split(r"\s", version.strip())[0]
    package = distro_lib.package_for(name, host["distro"], upstream)
    if not package:
        return None
    out = {"distro": host["distro"], "release": host.get("release", ""), "package": package, "package_release": "",
           "upstream_version": upstream, "basis": "host"}
    if host.get("hint"):
        from cveFeed import distro_releases
        if not out["release"]:
            out["release"] = distro_releases.release_from_table(host["distro"], package, upstream)
            if out["release"]:
                out["release_basis"] = "table"
        else:
            out["release_basis"] = "host"
        if out["release"]:
            out["codename"] = distro_releases.codename(host["distro"], out["release"])
        out["reading"] = "marker"
    return out


def _record_matches(subdomain, name, version, token, source, product_index,
                    cve_by_id, min_confidence, scan_history, rows=None, cpe="", distro=None, fix_lookup=None, evidence=None,
                    corroborated=(), leads=None, confidence_cap=None):
    """Work out the CVEMatch rows for one discovered product on a subdomain and append them to ``rows``
    (written in a batch by ``save_matches``). Returns the number of matches found. ``leads``, when given, is a dict that receives
    ``{cve.id: {(domain id, host name)}}`` for the CVEs a product seen without a version could be about."""
    if not version and cpe:  # nmap sometimes names the version only in the CPE
        version = (parse_cpe(cpe) or ("", "", ""))[2]
    version = stated_version(name, version)  # a protocol's version is no version of the product (Microsoft HTTPAPI httpd 2.0)
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
            name, ver, token, product_index, cve_by_id, cpe=cpe, details=details, raw=version):
        confidence = confidence_for(ver, in_range, cve.kev)
        if confidence_cap is not None and confidence > 0.0:
            confidence = min(confidence, confidence_cap)  # how far the version itself can be trusted (a library's file-name hint)
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
        status, fixed, fix = distro_lib.NO_DATA, "", None
        if distro and distro.get("distro") and in_range is True:
            # Upstream says in range; the distro may have backported the fix. Never dropped: a patched match is kept,
            # at low confidence and labelled, so a wrong distro reading can only demote it, not hide it.
            rows_for = fix_lookup(distro_lib.fix_distro(distro["distro"]), distro.get("package", ""), getattr(cve, "cve_id", "")) \
                if fix_lookup and distro.get("package") else []
            status, fixed, row = distro_lib.judge_row(distro, rows_for)
            fix = distro_fix_evidence(distro, row, fixed)
            if status == distro_lib.PATCHED:
                confidence = 0.2
            elif status == distro_lib.VULNERABLE:
                confidence = 0.95  # the distro's own tracker lists this package release as affected: the strongest evidence there is
            elif status == distro_lib.BACKPORT:
                confidence = min(confidence, BACKPORT_CONFIDENCE)  # a fixed build exists for the release: likelier patched than not
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
                         **({"distro": {k: v for k, v in distro.items() if v}} if distro and distro.get("distro") else {}),
                         **({"distro_fix": fix} if fix else {})},
        })
        found += 1
    return found


BACKPORT_CONFIDENCE = 0.5  # distro.BACKPORT: a fixed build exists for the host's release and the installed build is not known


def distro_fix_evidence(info, row, fixed):
    """``evidence.distro_fix`` of a match judged by a Red Hat row: the release, the package (a module stream's "httpd:2.4"), the fixed
    build and the advisory that shipped it, so a person can be told which build fixes it. None for other distributions (their evidence
    is unchanged) and when no single row decided the verdict."""
    if not row or distro_lib.fix_distro(info.get("distro", "")) != "rhel":
        return None
    out = {"source": "redhat", "release": str(row.get("release") or ""), "package": row.get("package") or info.get("package", ""),
           "status": row.get("status") or "", "fixed": (fixed or "")[:128], "advisory": (row.get("advisory") or "")[:32]}
    build = distro_lib.fixed_build(out)
    if build:
        out["fixed_build"] = build[:160]
    return {k: v for k, v in out.items() if v}


def signature_of(obj):
    """What a verdict depends on: the CVE, the product and version found, whether it is in range, and how it was found."""
    return (getattr(obj, "cve_entry_id"), obj.matched_product, obj.matched_version, obj.version_in_range, obj.source)


# the stored reasons of a deterministic closure (this module, cveFeed.locality, cveFeed.match_policy): a verdict that starts with one
# was reached on the evidence alone, so it is reusable and a person's or the AI's later answer does not replace it
DIFFERENT_PRODUCT = 'Closed automatically: different product'
# a validation's fresh read of the page's scripts (cveFeed.validation.library_outcome): the library is fixed, or the host is an alias
SCRIPT_READ = 'Closed automatically: fresh script read'
# CVEMatch.source of an OpenVAS NVT result (cveFeed.openvas_scan.SOURCE): reported by a test of the product, not correlated from its name
OPENVAS_SOURCE = 'openvas'
# the first wording of the same closure ("invalid product correlation") is still on rows closed before it was reworded: it is read the same
AUTO_CLOSED = (DIFFERENT_PRODUCT, 'Closed automatically: invalid product correlation', 'Closed automatically: local-only',
               match_policy.NO_EVIDENCE, SCRIPT_READ)


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


LIBRARY_DAMPING_DAYS = 14  # a library match reopened this recently is not closed again on the page's word (only a redirect alias closes it)
# every page-based closure but the redirect alias: a page that changes between readings (A/B, rotating bundles) must not flap a match
_WEAK_LIBRARY_CLOSURES = ('contradicted_by_file', 'named_by_script', 'file_states_nothing', 'no_such_script', 'cache_buster')


def _library_standing(match):
    """Whether someone or something vouches for a library match (``match_policy.has_standing``: worked, assigned, commented, AI-confirmed,
    host-reported, a template hit...) or a validation confirmed it (its Triage row is a hit or classified confirmed): no page reading
    closes it."""
    from django.db.models import Q

    from cveFeed.models import Triage
    if match_policy.has_standing(match):
        return True
    from cveFeed.triage import library_body_proven
    # a confirmation the rules gave because the page's own file stated the version (triage.library_rule) rests on the very reading a newer
    # one may contradict: it is no standing against the page's word, only a validation hit is
    confirmed = Q(classification='confirmed') if not library_body_proven(
        match.source, match.evidence, match.version_in_range, match.distro_status) else Q(pk__in=[])
    return Triage.objects.filter(match_id=match.pk).filter(Q(validation_status='hit') | confirmed).exists()


def _recently_reopened(match, now=None, days=LIBRARY_DAMPING_DAYS):
    from datetime import timedelta

    from django.utils import timezone
    from django.utils.dateparse import parse_datetime
    stamp = (match.evidence or {}).get('library_reopened_at') if isinstance(match.evidence, dict) else None
    when = parse_datetime(stamp) if isinstance(stamp, str) else None
    return bool(when) and when >= (now or timezone.now()) - timedelta(days=days)


def host_library_versions(subdomain):
    """``{(library key, version)}`` the host's technologies name (its prefetched ``technologies`` when loaded)."""
    out = set()
    for tech in subdomain.technologies.all():
        name, version = split_name_version(tech.name)
        key = js_libraries.PRODUCTS.get((name or '').strip().lower())
        if key and version:
            out.add((key, version))
    return out


def library_closure(match, libraries, name=None, now=None, present=None):
    """``(reason, hold)`` for a stored JavaScript library match against its host's page (``libraries``, a ``js_libraries.HostLibraries``):
    the stored reason to close it because the page contradicts it, and whether it must be kept open instead. Only a version the host's
    technologies still name is judged against the page (``present``: ``host_library_versions``); a version the host no longer names is an
    ordinary stale match (``close_stale``'s own closure, as for every product). A page-based closure is held back when a person or a check
    vouches for the match (on this row, or on an earlier scan's row of the host: ``_vouched_on_another_row``), or when it reopened lately
    and the closure is not a redirect alias (a page that changes between readings, A/B or a rotating bundle, must not flap it). The
    reason is never shared with another host (``close_invalid_correlation``, ``_seedable``)."""
    name = name or (match.matched_product if js_libraries.PRODUCTS.get((match.matched_product or '').strip().lower())
                    else match_policy.sighting_of(match)[0])
    key = js_libraries.PRODUCTS.get((name or '').strip().lower())
    if getattr(match, 'source', '') != 'tech' or not match.matched_version or not key:
        return '', False
    if present is None:
        present = host_library_versions(match.subdomain)
    if (key, match.matched_version) not in present:
        return '', False
    skip, evidence, _cap = libraries.judge(name, match.matched_version)
    if not (skip and evidence.get('reason')):
        return '', False
    if _library_standing(match) or _vouched_on_another_row(match.subdomain, name, match.matched_version):
        return '', True  # a person or a check vouched for it, on this row or on an earlier scan's row of the host
    reason = js_libraries.closed_reason(evidence['reason'])
    if js_libraries.closure_kind(reason) in _WEAK_LIBRARY_CLOSURES and _recently_reopened(match, now):
        return '', True
    return reason, False


def library_provenance_reason(match):
    """The stored reason to close a JavaScript library match the host's own page contradicts (``library_closure``), or ''. Read by
    ``invalid_identity_reason``, so triage never asks the AI about it; ``tasks.reconcile_library_provenance`` sweeps the stored ones."""
    if getattr(match, 'source', '') != 'tech' or not match.matched_version or match.subdomain_id is None:
        return ''
    name, _cpe = match_policy.sighting_of(match)
    if not js_libraries.is_library(name):
        return ''
    return library_closure(match, js_libraries.HostLibraries.for_subdomain(match.subdomain), name=name)[0]


def invalid_identity_reason(match):
    """A reason to close this *candidate correlation*, never a claim that the host lacks backend software.

    A frontend banner or missing version is not negative evidence. Only the identity that originally
    produced the match is compared with the advisory's named products, using the same aliases as
    candidate generation. Conflicting positive evidence prevents automatic closure.
    """
    if match.template_result == 'vulnerable' or match.distro_status == 'vulnerable' or match_policy.has_standing(match):
        return ''  # a check found it, or a person or the host vouches for it: no name comparison closes that
    if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith(SCRIPT_READ):
        return match.ai_reason  # a validation read the page's scripts again and closed it: that stands until a person works it
    if getattr(match.cve_entry, 'local_only', False):  # not a product question: nothing outside the host can decide this CVE
        from cveFeed.locality import reason_text
        return reason_text()
    reason = library_provenance_reason(match)
    if reason:
        return reason
    if match.source in ('java', 'runtime', 'build_range', 'windows'):  # build_range: cveFeed.edge_builds matched the CVE's own vendor and product;
        # windows: cveFeed.windows_builds matched the CVE's own entry naming the Windows release
        # Not a name match either (runtime: cveFeed.version_sources, the same for a language runtime): the CVE's own affected entry names the Java runtime (java_runtime.is_runtime_item) and the host's runtime was
        # read or is unknown; the stored name is the fixed "Java runtime", which no advisory spells, so a name comparison would close every one
        return ''
    if match.source == OPENVAS_SOURCE:
        # Not a correlation: the NVT that reported the CVE tested this product on this port itself, whatever its confidence. Its stored
        # name is the NVT and port ("OpenVAS NVT <oid> on 22/tcp"), never an advisory product, so a name comparison would close every
        # OpenVAS match below a hard QoD as "different product" (#414). Its quality of detection is weighed by triage instead.
        return ''
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


def close_invalid_correlation(match, reason=None, host_only=False):
    """Persist a scoped, auditable closure for bad product links, on this row only. ``host_only`` (a closure reached from what this host
    showed, a fresh script read) is kept for the callers; no closure is shared with another host since task 256."""
    from django.utils import timezone
    from cveFeed import activity, scoring, triage
    from cveFeed.models import CVEMatch

    reason = reason or invalid_identity_reason(match)
    if not reason:
        return False
    if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith(AUTO_CLOSED + (js_libraries.LIBRARY_CLOSED,)):
        return False
    pairs = triage.track([match])
    if not pairs:
        return False
    row, _ = pairs[0]
    # Never shared (no MatchVerdict, no TriageVerdict), whether or not ``host_only`` says so: the reason is about this host's own sighting
    # (the port's product, its CPE, a technology name) or its own page (cveFeed.js_libraries, or a validation's fresh script read), which the
    # host's owner controls, while the shared keys hold only the advisory's product and the version. Another host with the same key is judged
    # on its own evidence by the same check, at no cost (task 256).
    row.verdict, row.status, row.classification, row.reason = None, 'triaged', 'not_applicable', reason
    row.save(update_fields=['verdict', 'status', 'classification', 'reason', 'updated_at'])
    CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='not_affected', ai_reason=reason, ai_model='deterministic-correlation',
                                               confidence=0.0, updated_at=timezone.now())
    match.ai_verdict, match.ai_reason, match.ai_model, match.confidence = 'not_affected', reason, 'deterministic-correlation', 0.0
    activity.log('confirm', f'{match.cve_entry.cve_id}: closed for this asset ({closure_summary(reason)})',
                 project=row.project_id, cve_id=match.cve_entry.cve_id, match_id=match.pk,
                 finding_id=row.pk, decision='closed_not_applicable', reason=reason)
    scoring.rescore_for_matches([match])
    from django.db import transaction
    from cveFeed.views import bump_stats_revision
    transaction.on_commit(bump_stats_revision)
    return True


def _seedable(verdict, row):
    """The stored verdict a new or moved match may start from: never a clearing one (not_affected), which may have been reached on another
    tenant's host from what that host said; never an "uncertain" one for a match with hard evidence, which it would keep off the fire page;
    and never an "affected" one for a match that stands on its version string alone (``match_policy.version_only``): the verdict may
    have been earned on a host with a template hit or a distribution listing, which this match does not have, and the ceiling
    (``triage.ceiling``) holds such a match at needs_validation. It starts unjudged instead and is triaged under the ceiling."""
    if verdict and (verdict.ai_reason or '').startswith(js_libraries.LIBRARY_CLOSED):
        return None  # about one host's own page, never another's (and never the same host's once it matches again)
    if verdict and verdict.ai_verdict == "affected" and match_policy.version_only(
            row.get("source"), row.get("evidence"), row.get("version_in_range"), row.get("template_result", ""), row.get("distro_status", "")):
        return None
    if verdict and verdict.ai_verdict == "not_affected":
        # Never a closing one, whatever its reason (task 256): the stored row has no tenant and its key is only the CVE, product, version, range
        # result and source, so it may have been reached on another organization's host from what that host said (a banner, a CPE, a page, an
        # AI reading of them). A shared answer may raise attention, never close. The same host's own answer is carried by triage (its twin).
        return None
    if verdict and verdict.ai_verdict == "uncertain" and match_policy.has_hard_evidence(
            row.get("source"), row.get("evidence"), row.get("template_result", ""), row.get("distro_status", "")):
        # nor lower one: "uncertain" keeps a match with hard evidence out of the fire page (notify.fire_matches), and the stored answer may
        # rest on what another tenant's host showed. Its own triage decides; a version-only match is held there anyway (triage.ceiling)
        return None
    return verdict


_MATCH_FIELDS = ("matched_version", "version_in_range", "confidence", "scan_history_id", "distro_status", "distro_fixed_version",
                 "evidence")


def _row_strength(row):
    """Orders sightings of one match: hard evidence (a template hit, a distribution tracker), then a version inside the range, then an
    unknown range, then outside it. Of two sightings equal in all that, the one whose version a file of the page stated outranks one only a
    name or a query string carried (``version_confidence``): the strongest evidence wins, never whichever row the database returned last."""
    evidence = row.get("evidence")
    confidence = evidence.get("version_confidence") if isinstance(evidence, dict) else None
    return (row.get("template_result") == "vulnerable" or row.get("distro_status") == "vulnerable",
            row.get("version_in_range") is True, row.get("version_in_range") is None,
            confidence if isinstance(confidence, (int, float)) else 0.0)


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
    # A finding is paged as fire once per heat rule, not once per scan (cveFeed.notify): the new copy carries the page, under the rule in force,
    # of any earlier copy of the same CVE on the same host, whichever product label or source it had.
    from django.db.models import Max
    from django.utils import timezone

    from cveFeed import threat
    rule = threat.heat_signature()
    notified = {(c, d, n): at for c, d, n, at in base.filter(fire_notified_at__isnull=False, fire_notified_rule=rule).order_by()
                .values_list(*by_host_fields).annotate(at=Max("fire_notified_at")).values_list(*by_host_fields, "at")}
    hot = None
    now = timezone.now()
    for match in fresh:
        domain_id, name = hosts.get(match.subdomain_id, (None, None))
        key = (match.cve_entry_id, domain_id, name)
        before = by_host.get(key)
        if before is not None:
            match.remediation_status, match.remediation_note = before.remediation_status, before.remediation_note
            match.remediation_updated_at, match.remediation_by_id, match.assignee_id = (
                before.remediation_updated_at, before.remediation_by_id, before.assignee_id)
        if notified.get(key):
            match.fire_notified_at, match.fire_notified_rule = notified[key], rule
        elif before is not None and match_policy.proof_only_unrecorded(before, match.evidence, match.matched_version):
            # The earlier copy was written before correlation recorded what proves its version (the first scan after the update), and it
            # already proved it but for that field: this copy is no new finding, and if it reads fire only because the proof is recorded now,
            # that is no news. It is marked as announced without a message, like everything that was fire when the heat policy took effect
            # (notify.baseline_heat_policy). New proof (nmap now probes the service, another version) is news and is paged.
            if threat.heat_policy() != threat.LEGACY_POLICY:
                if hot is None:
                    from cveFeed.models import CVEEntry
                    hot = set(CVEEntry.objects.filter(threat.hot_q(), pk__in={m.cve_entry_id for m in fresh}).values_list("pk", flat=True))
                if (match.cve_entry_id in hot and match.distro_status != distro_lib.PATCHED and not match_policy.version_unknown(match)
                        and not threat.unproven(match, validation_status="")):
                    match.fire_notified_at, match.fire_notified_rule = now, rule


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
    from cveFeed.triage import SHARED_REASON

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
        for m in CVEMatch.objects.filter(subdomain_id__in={k[1] for k in unique}).order_by().select_related("cve_entry", "triage").only(
            "id", "cve_entry_id", "subdomain_id", "source", "matched_product", "ai_verdict", "ai_reason", "ai_model", "template_result",
            "cve_entry__kev", "cve_entry__exploit_db", "triage__validation_status", *_MATCH_FIELDS)}
    # a NEW KEV match from a technology fingerprint older than a day is held until the version is read again (cveFeed.kev_freshness)
    from cveFeed import kev_freshness
    held = kev_freshness.hold([r for k, r in unique.items() if k not in existing])[1]
    if held:
        held_ids = {id(r) for r in held}
        unique = {k: r for k, r in unique.items() if id(r) not in held_ids}
        kev_freshness.request_reread({r["subdomain_id"] for r in held})
        logger.info('held %d new KEV match(es) on %d host(s) until their version is read again', len(held),
                    len({r["subdomain_id"] for r in held}))
    from cveFeed import threat
    kev_policy = threat.heat_policy() != threat.LEGACY_POLICY
    proved, backfilled = [], []  # matches the new evidence turned proven: news (paged once) or provenance recorded on an old row (not)
    # a library match the host's page closed is reopened on any fresh reading of the page that no longer supports the closure (even a partial
    # one: js_libraries.HostLibraries.judge page_fresh), never because the only reading went stale: that neither reopens it nor starts its
    # damping
    now = timezone.now()
    for key in [k for k, r in unique.items() if k in existing and existing[k].ai_verdict == 'not_affected'
                and (existing[k].ai_reason or '').startswith(js_libraries.LIBRARY_CLOSED)
                and isinstance(r.get("evidence"), dict) and r["evidence"].get("page_fresh") is False]:
        del unique[key]
    fresh, changed = [], []
    verdicts = {}
    for key, row in unique.items():  # a library match the host's page closed matches again (on a fresh reading): remembered, so a flapping
        match = existing.get(key)      # page does not close it daily, and its evidence differs from the closed row's, so it reopens
        if match is not None:
            reopened = (match.evidence or {}).get('library_reopened_at') if isinstance(match.evidence, dict) else None
            if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith(js_libraries.LIBRARY_CLOSED):
                row["evidence"] = {**row["evidence"], "library_reopened_at": now.isoformat()}
            elif reopened and _recently_reopened(match, now):
                row["evidence"] = {**row["evidence"], "library_reopened_at": reopened}
    moved = {k for k, r in unique.items() if k in existing and (
        existing[k].matched_version != r["matched_version"] or existing[k].version_in_range != r["version_in_range"]
        or existing[k].distro_status != r["distro_status"]
        # (a library match the host's page closed always differs when it comes back: its evidence carries library_reopened_at, above)
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
            # never the stored row's words: it has no tenant, so only the fixed note goes with a seeded verdict (task 256)
            extra = ({"ai_verdict": verdict.ai_verdict, "ai_reason": SHARED_REASON, "ai_model": verdict.ai_model}
                     if verdict else {})
            fresh.append(CVEMatch(**row, **extra))
        elif key in moved or any(getattr(match, f) != row[f] for f in _MATCH_FIELDS):
            # what fire needs, read BEFORE the new evidence is written (threat.unproven), so only a real change is rescored and paged
            was_unproven = threat.unproven(match)
            quiet = was_unproven and match_policy.proof_only_unrecorded(match, row["evidence"], row["matched_version"],
                                                                         match_policy._validation_status(match))
            for f in _MATCH_FIELDS:
                setattr(match, f, row[f])
            if was_unproven != threat.unproven(match):
                touched.add(match.subdomain_id)  # proof arrived (or went): the heat, and so the stored score, moved
                if was_unproven and kev_policy and threat.is_hot(match.cve_entry.kev, match.cve_entry.exploit_db):
                    (backfilled if quiet else proved).append(match.pk)
            if key in moved:
                verdict = _seedable(verdicts.get(signature), row)
                match.ai_verdict = verdict.ai_verdict if verdict else ""
                match.ai_reason = SHARED_REASON if verdict else ""
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
    if proved or backfilled:
        # Under the KEV policy proof mostly arrives here (nmap starts to probe the service, a later route check reads the library file):
        # a match it turns fire is paged once (notify.fire_confirmed, fire_notified_at). A row that turns fire only because correlation now
        # records what proves it (written before the rule and already proven but for that field, match_policy.proof_only_unrecorded) is
        # marked as announced without a message, like
        # everything that was fire when the policy took effect (notify.baseline_heat_policy). After the write is committed.
        from django.db import transaction

        from cveFeed import notify

        def follow_up(proved=tuple(proved), backfilled=tuple(backfilled)):
            notify.mark_announced(backfilled)
            notify.fire_confirmed(proved)
        transaction.on_commit(follow_up)
    return len(unique)


_CORRELATED_SOURCES = ("tech", "port", "java", "runtime", "bundled", "build_range", "windows")  # java: cveFeed.java_runtime; runtime, bundled: cveFeed.version_sources; build_range: cveFeed.edge_builds; windows: cveFeed.windows_builds


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
    for m in CVEMatch.objects.filter(subdomain_id__in=list(subdomain_ids), source__in=_CORRELATED_SOURCES).order_by().only(
            "id", "cve_entry_id", "subdomain_id", "source", "matched_product", "matched_version", "evidence", "ai_verdict", "ai_reason",
            "template_result", "remediation_status", "version_in_range", "assignee_id", "distro_status"):
        if m.cve_entry_id not in cve_ids or (m.cve_entry_id, m.subdomain_id, m.source, m.matched_product) in current:
            continue
        if m.template_result == 'vulnerable':
            continue  # a template hit is evidence of the vulnerability itself: not seeing the product's banner again does not retire it
        if m.remediation_status != 'open' and m.version_in_range is None:
            continue  # worked by a person before the evidence policy, with no version behind it: their decision stands, it is not ours to close
        if m.remediation_status != 'open' and m.source == 'tech' and js_libraries.is_library(m.matched_product):
            continue  # a JavaScript library match a person worked: a script read differently (cveFeed.js_libraries) never closes it for them
        if m.ai_verdict == 'not_affected' and (m.ai_reason or '').startswith('Closed automatically:'):
            continue
        stale_keep.append(m)
        hosts.add(m.subdomain_id)
    if stale_keep:
        reasons, held = _library_closures([m for m in stale_keep if m.source == 'tech' and js_libraries.is_library(m.matched_product)])
        stale_keep = [m for m in stale_keep if m.pk not in held]
        hosts = {m.subdomain_id for m in stale_keep}
    if stale_keep:
        by_reason = {}
        for m in stale_keep:
            reason = reasons.get(m.pk) or (
                "Closed automatically: the host no longer matches this CVE (the version moved out of the affected range "
                "or the product is gone).")
            by_reason.setdefault(reason, []).append(m.pk)
        for reason, ids in by_reason.items():
            CVEMatch.objects.filter(pk__in=ids).update(ai_verdict="not_affected", confidence=0.0, updated_at=timezone.now(), ai_reason=reason)
        from cveFeed import activity
        from startScan.models import Subdomain
        projects = dict(Subdomain.objects.filter(pk__in=hosts).values_list('id', 'target_domain__project_id'))
        closed = {}  # project id -> [match id]: one activity line per project, not one per match (a rescan can close hundreds)
        for match in stale_keep:
            if projects.get(match.subdomain_id):
                closed.setdefault(projects[match.subdomain_id], []).append(match.pk)
        for project_id, ids in closed.items():
            message = ('CVE candidate closed after its product or version disappeared from inventory' if len(ids) == 1 else
                       f'{len(ids)} CVE candidates closed after their product or version disappeared from inventory')
            activity.log('confirm', message, project=project_id, match_id=ids[0], match_ids=ids[:CLOSED_SAMPLE], count=len(ids),
                         decision='closed_not_applicable')
    return hosts


CLOSED_SAMPLE = 20  # match ids named in a close_stale activity line: enough to find them, never a row the size of the sweep


def _vouched_on_another_row(subdomain, name, version):
    """Whether another row of this host (an earlier scan's: same name and target) has a library match of ``name`` ``version`` that a person
    or a check vouches for (``_library_standing``)."""
    from cveFeed.models import CVEMatch
    key = js_libraries.PRODUCTS.get((name or '').strip().lower())
    if not key or not subdomain.target_domain_id:
        return False
    tokens = {re.sub(r'[^a-z0-9]', '', key), re.sub(r'[^a-z0-9]', '', js_libraries.LIBRARIES[key][0].lower())}
    for match in (CVEMatch.objects.filter(subdomain__name=subdomain.name, subdomain__target_domain_id=subdomain.target_domain_id, source='tech',
                                          matched_version=version).exclude(subdomain_id=subdomain.pk)
                  .only('id', 'source', 'matched_product', 'evidence', 'version_in_range', 'ai_verdict', 'remediation_status', 'assignee_id', 'template_result',
                        'distro_status')):
        if re.sub(r'[^a-z0-9]', '', (match.matched_product or '').lower()) in tokens and _library_standing(match):
            return True
    return False


def _library_closures(matches):
    """``({match id: stored reason}, {match ids to keep open})`` for the JavaScript library matches among ``matches`` (stale tech matches):
    the reason for those the host's own page contradicts (``library_closure``), and those no page reading may close (vouched for, or
    reopened lately on a weak contradiction), which stay as they are."""
    if not matches:
        return {}, set()
    from startScan.models import Subdomain
    subs = {sub.pk: sub for sub in Subdomain.objects.filter(pk__in={m.subdomain_id for m in matches}).select_related('target_domain')
            .prefetch_related('ip_addresses__ports', 'technologies')}
    hosts = {pk: (js_libraries.HostLibraries.for_subdomain(sub), host_library_versions(sub)) for pk, sub in subs.items()}
    reasons, held = {}, set()
    for m in matches:
        if m.subdomain_id not in hosts:
            continue
        libraries, present = hosts[m.subdomain_id]
        reason, hold = library_closure(m, libraries, present=present)
        if hold:
            held.add(m.pk)
        elif reason:
            reasons[m.pk] = reason
    return reasons, held


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

    # Technology fingerprints (httpx tech-detect). A version of a one-core product the evidence disproves (jQuery's number read as
    # WordPress's) is kept on the host as evidence and not matched.
    technologies = sorted(subdomain.technologies.all(), key=lambda t: t.id)  # a stable order: a tie between two sightings must not depend on the row order the database returns
    # a JavaScript library's version stands on what its file states (cveFeed.js_libraries): a copy a later one replaces, or a string a
    # script's query or name carried where the file says otherwise, is not matched; a file-name-only version is matched at low confidence
    libraries = js_libraries.HostLibraries.for_subdomain(subdomain) if any(js_libraries.is_library(t.name) for t in technologies) else None
    # a core version that is a number a library's own file on the host states is that library's (jQuery 3.7.1 is not WordPress 3.7.1)
    wrong = cms_evidence.superseded(subdomain, technologies, libraries.file_versions() if libraries is not None else ())
    readings = _host_readings(subdomain)
    host = host_distro(subdomain, readings=readings)  # a Red Hat family host: its technologies are judged against Red Hat's data too
    hint = host or host_debian_hint(subdomain, readings=readings)  # a Debian or Ubuntu host: a hint for its technologies, never a fix
    # the CPE a first-party reading named a technology by (nmap's other CPEs on a port, cveFeed.source_versions): matched CPE first like a port's
    from cveFeed import source_versions
    tech_cpes = source_versions.technology_cpes(subdomain) if technologies else {}
    for tech in technologies:
        name, version = split_name_version(tech.name)
        if wrong and (cms.key(name), version) in wrong:
            continue
        # the template word and a detector's name dropped, and an X-AspNet-Version CLR line (an earlier build's "ASP.NET", the technology template's
        # "AspNet Version Disclosure") read as the .NET Framework's
        name, version = read_technology(tech.name)
        token = _norm(name)
        if len(token) < _MIN_TOKEN:
            continue
        library, cap = {}, None
        if libraries is not None and version:
            skip, library, cap = libraries.judge(name, version)
            if skip and _vouched_on_another_row(subdomain, name, version):
                # a person or a check vouched for this version's match on an earlier scan's row of the host: the new row keeps the match
                # (its remediation, assignee and status carried), so a page reading never undoes their work across a rescan
                skip, cap = False, js_libraries.CONFIDENCE['filename']
                library = {'version_source': 'other', 'version_confidence': cap, 'page_fresh': True,
                           'version_note': 'kept: vouched for on an earlier scan of this host, although its page does not show this version'}
            if skip:
                continue
        tech_cpe = tech_cpes.get(tech.name or "", "")
        _record_matches(
            subdomain, name, version, token, "tech",
            product_index, cve_by_id, min_confidence, scan_history, rows, evidence={"source": "tech", "source_id": tech.id, **library,
                                                                                   **({"cpe": tech_cpe[:255]} if tech_cpe else {})},
            leads=leads, confidence_cap=cap, distro=tech_distro(hint, name, version, tech.name), fix_lookup=fix_lookup, cpe=tech_cpe)

    # nmap -sV service data on the host's open ports (Shodan-style inventory).
    from startScan.models import open_services
    for ip in subdomain.ip_addresses.all():
        for port in open_services(ip):  # a UDP service that identified itself (SNMP, NTP, SSDP, memcached) is evidence like a TCP one
            # a Server-header token nmap stored whole ("nginx/1.28.3") is the product and its version
            name, version, _rest = split_port_product(port.product, port.version)
            token = _norm(name)
            if len(token) < _MIN_TOKEN:
                continue
            info = port_distro(port)
            if host and info.get("distro") in distro_lib.RHEL_FAMILY and not info.get("release") and host.get("release"):
                info["release"] = host["release"]  # the release another service or the host's OS states
            _record_matches(
                subdomain, name, version, token, "port",
                product_index, cve_by_id, min_confidence, scan_history, rows, cpe=port.cpe or "",
                distro=info, fix_lookup=fix_lookup, corroborated=runzero.reported_cves(ip, port.number),
                evidence={"source": "port", "source_id": port.id, "ip": ip.address, "port": port.number, "protocol": port.protocol or "tcp",
                          "service_extra": (port.service_extra or "")[:255], "cpe": (port.cpe or "")[:255],
                          "method": ((port.extra or {}).get("method") or ""),
                          # a vendor's own build: its banner states the version that runs (match_policy.vendor_built; a distribution-
                          # packaged, OS-serviced or unknown product's does not); always written, so a row without it predates the rule
                          "vendor_banner": match_policy.vendor_built(name)},
                leads=leads)

    # The versions a third party reported for the host (cveFeed.source_versions: Shodan's InternetDB CPEs, runZero's operating system), under the
    # freshness rule: never when a first-party reading names the product, never older than REPORTED_MAX_AGE_DAYS; CPE first, confidence capped.
    source_versions.collect_reported(subdomain, product_index, cve_by_id, rows, scan_history=scan_history, min_confidence=min_confidence,
                                     fix_lookup=fix_lookup)

    # The Java runtime the host was read to run (cveFeed.java_runtime): a CVE in the JDK itself names the runtime, not a technology or a port
    # product, so it is tested against the host's Java runtime readings, and a host where Java is clear but its version unknown is a candidate.
    from cveFeed import java_runtime
    java_runtime.collect_matches(subdomain, cve_by_id, rows, scan_history=scan_history, min_confidence=min_confidence, fix_lookup=fix_lookup,
                                 host_distro=host)

    # The language runtimes the host states (cveFeed.version_sources): Python, Go, Node.js, PHP, Ruby, .NET Framework, Erlang/OTP, matched
    # against the CVEs whose own record names the runtime by vendor and product, by the Java runtime's rules; a CVE already matched above is not
    # matched twice.
    from cveFeed import version_sources
    version_sources.collect_matches(subdomain, cve_by_id, rows, scan_history=scan_history, min_confidence=min_confidence, fix_lookup=fix_lookup)

    # The components a vendor bundles with a product release the host states (cveFeed.bundled_components: Atlassian's Tomcat, Elasticsearch's
    # Lucene and Log4j, the Jetty in jenkins.war ...): named like a technology, but an inferred version is never a version inside a range, so
    # at most a needs-validation candidate; a CVE already matched above is not matched twice.
    version_sources.collect_bundled(subdomain, product_index, cve_by_id, rows, scan_history=scan_history, min_confidence=min_confidence)
    # The build RANGE an edge appliance's static files put it in (cveFeed.edge_builds: PAN-OS, FortiOS, Pulse Connect Secure): a CVE whose own
    # record names the product and that a release of the range can reach is a needs-validation candidate, never a version in range.
    from cveFeed import edge_builds
    edge_builds.collect_matches(subdomain, cve_by_id, rows, scan_history=scan_history, min_confidence=min_confidence)
    # The Windows release an NTLM challenge states (cveFeed.windows_builds): the release is known, its update revision is not, so a KEV or
    # critical network CVE whose own record names the release and whose range covers it is a needs-validation candidate, never a version in range.
    from cveFeed import windows_builds
    windows_builds.collect_matches(subdomain, cve_by_id, rows, scan_history=scan_history, min_confidence=min_confidence)
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
    from itertools import islice

    from cveFeed import source_versions, version_sources
    walk = iter(subdomains)
    while True:
        chunk = list(islice(walk, batch))
        if not chunk:
            break
        if product_index:
            version_sources.prefetch_bundled(chunk)  # the hosts' bundled component readings in one query, not one per host
            source_versions.prefetch(chunk)  # their source readings (cveFeed.source_versions) in one query, not one per host
            version_sources.prefetch_readings(chunk, cve_by_id)  # their runtime, version range and Java runtime rows, one query each, not one per host
        for sub in chunk:
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
_CVE_FIELDS = ("id", "cve_id", "affected", "kev", "epss_reached", "exploit_db", "cvss", "cvss_vector", "published_at",
               "local_only")  # the vector, date and locality: cveFeed.windows_builds.eligible


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
            or any(alias in product_index or (ALIAS_VENDORS.get((token, alias)) and _fuzzy_ids(alias, product_index))
                   for alias in PRODUCT_ALIASES.get(token, ()))
            or any(_fuzzy_ids(rest, product_index) for _lead, rest in _vendor_led(token)))


def names_rules_touch(name, product_index, cpe="", source="tech"):
    """Whether the name rules of data/product_aliases.json and ``_vendor_led`` can change what a stored name connects to: an alias or a
    restriction names it, its template word is dropped (``tech_name``), it leads with a vendor whose product is in the index, a product two
    vendors use is among its candidates, or its CPE is one the vendor renames or the no-vendor rule read differently. The update backfill
    (manage.py backfill_name_aliases) correlates again the hosts carrying such a name."""
    base = tech_name(name) if source == "tech" else (name or "")
    token = _norm(base)
    if len(token) < _MIN_TOKEN:
        return False
    if base != (name or "") or token in PRODUCT_ALIASES or token in NAME_VENDORS:
        return True
    if any(_fuzzy_ids(rest, product_index) for _lead, rest in _vendor_led(token)):
        return True
    if any(t in product_index and name_matches_token(token, t) for t in AMBIGUOUS_PRODUCTS):
        return True
    parts = parse_cpe(cpe)
    return bool(parts and parts[1] in product_index)


def latest_scan_q(prefix=""):
    """The rows of each domain's current inventory: hosts are stored once per scan, so listings, matches and auto-fire must read
    one scan's copy, not every scan's. That is the domain's latest successful full scan, plus the successful host-pipeline scans
    (a rescan, a re-test, new hosts from certificate transparency) that ran after it, plus rows with no scan. A host-pipeline scan
    holds only the hosts it ran on, so it adds to the inventory instead of replacing it; when a host appears in more than one of
    these scans, the newest row wins. A domain that has never had a successful full scan keeps all its rows (newest per host),
    so a first scan in progress (or one that failed part way) does not hide the hosts it found. ``prefix`` reaches the host
    from another model ("subdomain__" for a CVEMatch)."""
    from django.db.models import Case, Exists, F, Max, OuterRef, Q, Value, When, Window

    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory, Subdomain

    done = ScanHistory.objects.filter(scan_status=2)
    full = done.exclude(tasks__contains=[HOST_PIPELINE_TASK])
    latest_full = full.values("domain_id").annotate(last=Max("id")).values("last")
    # A host-pipeline scan is "after the full scan" when it is newer than the newest full scan of its domain (any, when the domain has none). It was
    # ``id > COALESCE((the newest full scan of the domain), 0)``, a subquery run once per finished host-pipeline scan that walked every finished scan of
    # the domain to find it: a domain keeps 170 or more of them, so 3,300 scans meant 590,000 row visits (1.4 s) each time the set was built, and every
    # host statement builds it once or twice. Now ONE pass over the finished scans: a window gives each row the newest full scan id of its domain, with
    # nothing correlated for the planner to repeat per row (a NOT EXISTS version was hashed on PostgreSQL 16 and read 6.7 million buffers on 18).
    # Both conditions are on windows so that both are applied after them (a plain filter on the tasks would cut the rows the window sees).
    is_full = ~Q(tasks__contains=[HOST_PIPELINE_TASK])
    after_full = (done.annotate(_newest_full=Window(Max(Case(When(is_full, then=F("id")))), partition_by=[F("domain_id")]),
                                _is_pipeline=Window(Max(Case(When(is_full, then=Value(0)), default=Value(1))), partition_by=[F("id")]))
                  .filter(_is_pipeline=1).filter(Q(_newest_full__isnull=True) | Q(id__gt=F("_newest_full"))).values("id"))
    same_host = Subdomain.objects.filter(target_domain_id=OuterRef(prefix + "target_domain_id"),
                                         name=OuterRef(prefix + "name"))
    newer_row = same_host.filter(scan_history_id__in=after_full,
                                 scan_history_id__gt=OuterRef(prefix + "scan_history_id"))
    # Before the first successful full scan, keep the newest scanned copy of each host. A scanless row (certificate transparency,
    # an import) is not a copy of a scan: its own addresses and findings fold into the host, so it stays current beside the scanned copy.
    newer_fallback = same_host.filter(scan_history__isnull=False, id__gt=OuterRef(prefix + "id"))
    return ((Q(**{prefix + "scan_history_id__in": latest_full}) | Q(**{prefix + "scan_history_id__in": after_full})
             | Q(**{prefix + "scan_history__isnull": True})
             | ~Q(**{prefix + "target_domain_id__in": full.values("domain_id")}))
            & ~Q(Exists(newer_row))
            & (Q(**{prefix + "scan_history__isnull": True}) | Q(**{prefix + "target_domain_id__in": full.values("domain_id")})
               | ~Q(Exists(newer_fallback))))


def candidate_subdomains(product_index, base=None):
    """Subdomains worth correlating against ``product_index``: hosts carrying a technology or an nmap product that
    matches one of its tokens, from each domain's current inventory (latest_scan_q: the latest full scan, the host-pipeline scans after
    it, and the scan-less rows certificate transparency created). A partial scan of one host is not the whole inventory, and older
    scans' copies of the same host are skipped. Returns a queryset."""
    from django.db.models import Q

    from cveFeed.models import CVEMatch
    from startScan.models import IpAddress, Port, Subdomain, Technology

    tech_ids, tokens = [], {}
    for tech_id, stored in Technology.objects.values_list("id", "name").iterator():
        token = _norm(tech_name(split_name_version(stored)[0]))
        if len(token) < _MIN_TOKEN:
            continue
        if token not in tokens:
            tokens[token] = _index_hit(token, product_index)
        if tokens[token]:
            tech_ids.append(tech_id)
    products = set()
    for product in Port.objects.exclude(product="").values_list("product", flat=True).distinct():
        token = _norm(split_port_product(product)[0])
        if len(token) >= _MIN_TOKEN and _index_hit(token, product_index):
            products.add(product)

    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values("subdomain_id")
    ips = IpAddress.ports.through.objects.filter(port__product__in=products).values("ipaddress_id")
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values("subdomain_id")
    matched = CVEMatch.objects.filter(source__in=_CORRELATED_SOURCES).values("subdomain_id")  # re-checked so a stale match closes
    wanted = Q(id__in=by_tech) | Q(id__in=by_port) | Q(id__in=matched)
    from cveFeed import java_runtime
    if java_runtime.index_has_runtime(product_index):
        # a runtime CVE in the pool: every host where Java is clear is a candidate, whatever its technologies say (cveFeed.java_runtime)
        wanted |= Q(id__in=java_runtime.java_host_ids(Subdomain.objects if base is None else base))
    from cveFeed import version_sources
    if version_sources.index_has_runtime(product_index):
        # a language runtime CVE in the pool: every host with a runtime reading is a candidate (cveFeed.version_sources)
        wanted |= Q(id__in=version_sources.runtime_host_ids(Subdomain.objects if base is None else base))
    if product_index:
        # a host whose vendor bundle names a component (cveFeed.bundled_components) is a candidate for that component's CVEs
        wanted |= Q(id__in=version_sources.bundled_host_ids(Subdomain.objects if base is None else base))
    if product_index:
        # a host a third party reported a version for (cveFeed.source_versions): a candidate, the freshness rule decides at correlation
        from cveFeed import source_versions
        wanted |= Q(id__in=source_versions.reported_host_ids(Subdomain.objects if base is None else base))
    from cveFeed import edge_builds
    if product_index:
        # an edge appliance's build range (cveFeed.edge_builds): matched by the CVE's vendor and product, not by a technology token
        wanted |= Q(id__in=edge_builds.range_host_ids(Subdomain.objects if base is None else base))
        # a Windows release an NTLM challenge states (cveFeed.windows_builds): matched by the CVE's own entry naming the release
        from cveFeed import windows_builds
        wanted |= Q(id__in=windows_builds.host_ids(Subdomain.objects if base is None else base))
    qs = (Subdomain.objects if base is None else base).filter(wanted).filter(latest_scan_q())
    return qs.prefetch_related("technologies", "ip_addresses__ports")
