"""Distro backports: is a version-in-range match really exposed, or has the distribution patched it?

Linux distributions fix CVEs without changing the upstream version: Ubuntu's OpenSSH "8.9p1" at package release
``1:8.9p1-3ubuntu0.10`` is patched against CVE-2024-6387 (upstream fixed in 9.8p1), while ``3ubuntu0.6`` is not. A version
comparison against upstream ranges cannot tell the two apart, so a patched host is reported as exposed. This module reads the
distro and package release a scanner banner carries, compares it with the distro's own fixed version, and says which of
patched / vulnerable / unknown applies. Correlation never drops a match because of it: a patched match is kept and labelled.

Pure Python (no Django imports) so it is unit-testable on its own. The fixed versions come from ``DistroFix`` rows that
``cveFeed.distro_sync`` fills from the Debian security tracker and OSV (Ubuntu, Debian).
"""
import re

PATCHED, VULNERABLE, UNKNOWN, NO_DATA = "patched", "vulnerable", "unknown", "no_data"
DISTRO_STATUSES = (PATCHED, VULNERABLE, UNKNOWN, NO_DATA)

LABEL_UNKNOWN = "version-only, distro unknown"


def label_for(status, fixed_version=""):
    """The text a person reads next to a match."""
    if status == PATCHED:
        return "patched by distro" + (f" (fixed in {fixed_version})" if fixed_version and fixed_version != "0" else
                                      " (not affected)" if fixed_version == "0" else "")
    if status == VULNERABLE:
        return "vulnerable per distro tracker" + (f" (fixed in {fixed_version})" if fixed_version else " (no fix yet)")
    return LABEL_UNKNOWN


# --- reading the distro out of a scanner's service record -----------------------------------------------------------

_UBUNTU_REV = re.compile(r"\d+ubuntu[\d.]+")
_DEBIAN_REV = re.compile(r"[\w.+~]*[+~]deb(\d+)u\d+")
_RHEL_REV = re.compile(r"\.el(\d+)(?:_\d+)?")
_ALPINE_REV = re.compile(r"-r\d+$")
_NMAP_FORM = re.compile(r"^(?P<up>\S+)\s+(?:Ubuntu|Debian)[-\s]+(?P<rev>\S+)", re.IGNORECASE)  # "8.9p1 Ubuntu 3ubuntu0.6"
_DPKG_FORM = re.compile(r"^(?:\d+:)?\d[\w.+~]*-[\w.+~]+$")  # "2.4.57-2", "1:8.9p1-3ubuntu0.10", "2.4.62-1~deb12u2"
_OS_CPE = re.compile(r"cpe:/o:(?P<vendor>[a-z_]+):(?P<product>[a-z_]+)(?::(?P<ver>[\w.]+))?", re.IGNORECASE)

# normalized product -> package name, per distro family ("*" is every distro). {mm} is major.minor, {m} the major of the
# upstream version (mysql-8.0, postgresql-14, php8.1).
PACKAGES = {
    "openssh": {"*": "openssh"},
    "apachehttpd": {"debian": "apache2", "ubuntu": "apache2", "rhel": "httpd", "centos": "httpd", "*": "apache2"},
    "apachehttpserver": {"debian": "apache2", "ubuntu": "apache2", "rhel": "httpd", "centos": "httpd", "*": "apache2"},
    "nginx": {"*": "nginx"},
    "mysql": {"ubuntu": "mysql-{mm}", "debian": "mysql-{mm}", "*": "mysql"},
    "mariadb": {"debian": "mariadb", "ubuntu": "mariadb-{mm}", "*": "mariadb"},
    "postgresql": {"debian": "postgresql-{m}", "ubuntu": "postgresql-{m}", "*": "postgresql"},
    "eximsmtpd": {"debian": "exim4", "ubuntu": "exim4", "*": "exim"},
    "exim": {"debian": "exim4", "ubuntu": "exim4", "*": "exim"},
    "proftpd": {"debian": "proftpd-dfsg", "ubuntu": "proftpd-dfsg", "*": "proftpd"},
    "iscbind": {"debian": "bind9", "ubuntu": "bind9", "*": "bind"},
    "bind": {"debian": "bind9", "ubuntu": "bind9", "*": "bind"},
    "php": {"debian": "php{mm}", "ubuntu": "php{mm}", "*": "php"},
    "dovecot": {"*": "dovecot"},
    "dovecotimapd": {"*": "dovecot"},
    "dovecotpop3d": {"*": "dovecot"},
    "vsftpd": {"*": "vsftpd"},
    "openssl": {"*": "openssl"},
}


def _norm(value):
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def package_for(product, distro, upstream=""):
    """The distro's source package name for a scanner's product string, or "" for one we have no mapping for."""
    entry = PACKAGES.get(_norm(product))
    if not entry:
        return ""
    template = entry.get(distro) or entry["*"]
    nums = re.match(r"(\d+)(?:\.(\d+))?", upstream or "")
    major = nums.group(1) if nums else ""
    mm = f"{major}.{nums.group(2) or '0'}" if nums else ""
    if ("{m}" in template and not major) or ("{mm}" in template and not mm):
        return ""
    return template.format(m=major, mm=mm)


def _strip_epoch(text):
    return re.sub(r"^\d+:", "", text or "")


def upstream_of(package_release):
    """The upstream version inside a dpkg/rpm version string: no epoch, no distro revision ("1:8.9p1-3ubuntu0.6" -> "8.9p1")."""
    text = _strip_epoch(package_release).rpartition("-")[0] or _strip_epoch(package_release)
    return re.sub(r"[+~](?:dfsg|ds|git|really)[\w.]*$", "", text)


def parse_distro(product="", version="", extrainfo="", cpes=(), banner=""):
    """Read the distribution and package release out of one scanner service record.

    Returns {"distro", "release", "package", "package_release", "upstream_version"}; every value is "" when it cannot be
    told (an empty ``distro`` means "no distro information at all"). ``package_release`` is a dpkg/rpm version string:
    nmap's "8.9p1 Ubuntu 3ubuntu0.6" becomes "8.9p1-3ubuntu0.6". Ubuntu, Debian, RHEL/CentOS and Alpine are recognised."""
    out = {"distro": "", "release": "", "package": "", "package_release": "", "upstream_version": ""}
    version = (version or "").strip()
    text = " ".join([version, extrainfo or "", banner or ""])
    lowered = text.lower()
    cpes = [c for c in (cpes or ()) if c]
    os_cpe = next((m for m in (_OS_CPE.search(c) for c in cpes) if m), None)
    cpe_product = os_cpe.group("product").lower() if os_cpe else ""

    if "ubuntu" in lowered or "ubuntu" in cpe_product:
        out["distro"] = "ubuntu"
    elif _DEBIAN_REV.search(text) or re.search(r"\bdebian\b", lowered) or cpe_product == "debian_linux":
        out["distro"] = "debian"
    elif "red hat" in lowered or "centos" in lowered or "rocky" in lowered or "almalinux" in lowered or _RHEL_REV.search(version) \
            or cpe_product in ("enterprise_linux", "centos", "rhel", "linux_enterprise"):
        out["distro"] = "centos" if "centos" in lowered or cpe_product == "centos" else "rhel"
    elif re.search(r"\balpine\b", lowered) or cpe_product == "alpine_linux":
        out["distro"] = "alpine"
    if not out["distro"]:
        return out

    if os_cpe and os_cpe.group("ver") and out["distro"] in ("ubuntu", "debian"):
        out["release"] = os_cpe.group("ver").split(".")[0] if out["distro"] == "debian" else ".".join(os_cpe.group("ver").split(".")[:2])
    m = _NMAP_FORM.match(version)
    if m:
        out["package_release"] = f'{m.group("up")}-{m.group("rev")}'
    else:
        token = version.split()[0] if version.split() else ""
        if _DPKG_FORM.match(token) and (out["distro"] in ("ubuntu", "debian")):
            out["package_release"] = token
        elif out["distro"] in ("rhel", "centos") and _RHEL_REV.search(token):
            out["package_release"] = token
        elif out["distro"] == "alpine" and _ALPINE_REV.search(token):
            out["package_release"] = token
    release_text = out["package_release"]
    if not out["release"] and out["distro"] == "debian":
        deb = re.search(r"deb(\d+)u", release_text or text)
        out["release"] = deb.group(1) if deb else ""
    if not out["release"] and out["distro"] in ("rhel", "centos"):
        el = _RHEL_REV.search(release_text or version)
        out["release"] = el.group(1) if el else ""
    out["upstream_version"] = upstream_of(release_text) if release_text else (re.split(r"\s", version)[0] if version else "")
    out["package"] = package_for(product, out["distro"], out["upstream_version"])
    return out


# --- version comparison ---------------------------------------------------------------------------------------------

def _dpkg_order(ch):
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _dpkg_part(a, b):
    """Compare two dpkg version fragments (upstream or revision) the way dpkg does."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        si, sj = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        x, y = int(a[si:i] or 0), int(b[sj:j] or 0)
        if x != y:
            return -1 if x < y else 1
    return 0


def _dpkg_split(version):
    epoch = 0
    text = (version or "").strip()
    m = re.match(r"^(\d+):(.*)$", text)
    if m:
        epoch, text = int(m.group(1)), m.group(2)
    upstream, _, revision = text.rpartition("-") if "-" in text else (text, "", "")
    return epoch, upstream, revision


def dpkg_vercmp(a, b):
    """-1, 0 or 1: Debian's version ordering (epoch, upstream version, revision; "~" sorts before everything)."""
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def rpm_vercmp(a, b):
    """-1, 0 or 1: rpm's version-release ordering (epoch:version-release, "~" before and "^" after the plain version)."""
    def split(v):
        epoch, text = 0, (v or "").strip()
        m = re.match(r"^(\d+):(.*)$", text)
        if m:
            epoch, text = int(m.group(1)), m.group(2)
        ver, _, rel = text.partition("-")
        return epoch, ver, rel

    def seg(x, y):
        x, y = x or "", y or ""
        while x or y:
            x = re.sub(r"^[^A-Za-z0-9~^]+", "", x)
            y = re.sub(r"^[^A-Za-z0-9~^]+", "", y)
            if x.startswith("~") or y.startswith("~"):
                if not x.startswith("~"):
                    return 1
                if not y.startswith("~"):
                    return -1
                x, y = x[1:], y[1:]
                continue
            if x.startswith("^") or y.startswith("^"):
                if not x:
                    return -1
                if not y:
                    return 1
                if not x.startswith("^"):
                    return 1
                if not y.startswith("^"):
                    return -1
                x, y = x[1:], y[1:]
                continue
            if not x or not y:
                break
            digit = x[0].isdigit()
            pattern = r"^\d+" if digit else r"^[A-Za-z]+"
            mx, my = re.match(pattern, x), re.match(pattern, y)
            if not mx:
                return -1  # the segments differ in kind: a numeric one is newer
            if not my:
                return 1
            sx, sy = mx.group(0), my.group(0)
            x, y = x[len(sx):], y[len(sy):]
            if digit:
                sx, sy = sx.lstrip("0") or "0", sy.lstrip("0") or "0"
                if len(sx) != len(sy):
                    return -1 if len(sx) < len(sy) else 1
            if sx != sy:
                return -1 if sx < sy else 1
        if not x and not y:
            return 0
        return -1 if not x else 1
    ea, va, ra = split(a)
    eb, vb, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return seg(va, vb) or seg(ra, rb)


def compare_package_release(distro, observed, fixed):
    """-1/0/1 for the observed package release against the distro's fixed version, or None when the distro has no comparator
    here. A banner never carries the dpkg epoch ("8.9p1-3ubuntu0.6" is really "1:8.9p1-3ubuntu0.6"), so an observed version
    without one takes the fixed version's epoch: epochs are constant per package within a release."""
    if not observed or not fixed:
        return None
    if distro in ("ubuntu", "debian"):
        if not re.match(r"^\d+:", observed):
            m = re.match(r"^(\d+:)", fixed)
            observed = (m.group(1) if m else "") + observed
        return dpkg_vercmp(observed, fixed)
    if distro in ("rhel", "centos"):
        return rpm_vercmp(observed, fixed)
    return None


def judge(info, rows):
    """patched / vulnerable / unknown for one host, from its parsed distro info and the DistroFix rows of (package, CVE).

    ``rows`` are dicts {release, fixed_version, status} with status fixed | vulnerable | not_affected | undetermined. The row for
    the host's release is used; with no release known, the row whose fixed version carries the host's upstream version (Ubuntu
    22.04 ships OpenSSH 8.9p1, 24.04 9.6p1, so the upstream version names the release). Returns (status, fixed_version).
    A host without a package release can only be judged by a row that says the release is not affected or has no fix."""
    if not info.get("distro"):
        return NO_DATA, ""
    if not info.get("package"):
        return UNKNOWN, ""  # the distro is known, but not which of its packages this product is
    if info.get("release"):
        chosen = [r for r in rows if str(r.get("release")) == str(info["release"])]
        return _judge_row(info, chosen[0]) if chosen else (UNKNOWN, "")
    # No release known: judge against every release's row. If they all agree the release does not matter (a package release
    # older than every release's fix is vulnerable on any of them; one at or past all of them is patched); if they disagree,
    # the row whose fixed upstream version is the host's own names the release (Ubuntu 22.04 ships OpenSSH 8.9p1, 24.04 9.6p1).
    verdicts = [(row, _judge_row(info, row)) for row in rows]
    verdicts = [(row, v) for row, v in verdicts if v[0] in (PATCHED, VULNERABLE)]
    if not verdicts:
        return UNKNOWN, ""
    if len({v[0] for _row, v in verdicts}) == 1:
        same = [v for row, v in verdicts if upstream_of(row.get("fixed_version")) == (info.get("upstream_version") or "")]
        return (same or [v for _row, v in verdicts])[0]
    same = [v for row, v in verdicts if upstream_of(row.get("fixed_version")) == (info.get("upstream_version") or "")]
    return same[0] if same else (UNKNOWN, "")


def _judge_row(info, row):
    status, fixed = row.get("status") or "fixed", row.get("fixed_version") or ""
    if status == "not_affected" or fixed == "0":
        return PATCHED, "0"
    if status == "vulnerable" and not fixed:
        return VULNERABLE, ""
    if status == "undetermined":
        return UNKNOWN, ""
    cmp = compare_package_release(info["distro"], info.get("package_release", ""), fixed)
    if cmp is None:
        return UNKNOWN, fixed
    return (PATCHED if cmp >= 0 else VULNERABLE), fixed


_KNOWN_PACKAGES = {name for entry in PACKAGES.values() for name in entry.values() if "{" not in name}
_KNOWN_PATTERNS = (re.compile(r"mysql-\d+\.\d+"), re.compile(r"mariadb-\d+\.\d+"), re.compile(r"postgresql-\d+"),
                   re.compile(r"php\d+\.\d+"))


def is_known_package(name):
    """Whether a distro source package is one we map from a scanner product (so DistroFix only stores what can be matched)."""
    return name in _KNOWN_PACKAGES or any(p.fullmatch(name or "") for p in _KNOWN_PATTERNS)


# packages whose dpkg epoch is constant on Debian and Ubuntu but never shown in a banner: OSV compares full dpkg versions, so the
# epoch has to be put back before asking it ("8.9p1-3ubuntu0.6" is "1:8.9p1-3ubuntu0.6")
DEFAULT_EPOCH = {"openssh": "1:", "bind9": "1:", "dovecot": "1:"}


def with_default_epoch(package, package_release):
    if re.match(r"^\d+:", package_release or ""):
        return package_release
    return DEFAULT_EPOCH.get(package, "") + (package_release or "")
