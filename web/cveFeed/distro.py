"""Distro backports: is a version-in-range match really exposed, or has the distribution patched it?

Linux distributions fix CVEs without changing the upstream version: Ubuntu's OpenSSH "8.9p1" at package release
``1:8.9p1-3ubuntu0.10`` is patched against CVE-2024-6387 (upstream fixed in 9.8p1), while ``3ubuntu0.6`` is not. A version
comparison against upstream ranges cannot tell the two apart, so a patched host is reported as exposed. This module reads the
distro and package release a scanner banner carries, compares it with the distro's own fixed version, and says which of
patched / vulnerable / unknown applies. Correlation never drops a match because of it: a patched match is kept and labelled.

Pure Python (no Django imports) so it is unit-testable on its own. The fixed versions come from ``DistroFix`` rows that
``cveFeed.distro_sync`` fills from the Debian security tracker and OSV (Ubuntu, Debian) and from Red Hat's security data (RHEL,
which CentOS, Rocky Linux and AlmaLinux follow).

Red Hat adds one state. Its data says a release has a fix (an RHSA advisory and the fixed package build), but a banner such as
``Apache/2.4.37 (Red Hat Enterprise Linux)`` never shows the rpm release, so the host's build cannot be compared with it. That match
is ``backport``: a fix exists for the host's release, and a person confirms the installed build. It is never proof either way.
"""
import re

PATCHED, VULNERABLE, UNKNOWN, NO_DATA = "patched", "vulnerable", "unknown", "no_data"
BACKPORT = "backport"  # the distribution has a fixed build for the host's release; the installed build is not known
DISTRO_STATUSES = (PATCHED, VULNERABLE, UNKNOWN, NO_DATA, BACKPORT)

# the distributions that follow Red Hat's errata: their packages are judged against Red Hat's data (DistroFix rows of "rhel")
RHEL_FAMILY = ("rhel", "centos")

LABEL_UNKNOWN = "version-only, distro unknown"


def fix_distro(distro):
    """The distribution whose DistroFix rows judge a host of ``distro``: CentOS (and Rocky and Alma, which parse as rhel) read Red Hat's."""
    return "rhel" if distro in RHEL_FAMILY else distro


def fixed_build(fix, fixed_version=""):
    """The fixed package a person installs, "httpd-2.4.37-65.module+el8.10.0+22069+b47f5c72.1", from a match's ``evidence.distro_fix``
    (package and fixed version; a zero epoch is left out, as rpm prints it)."""
    fix = fix if isinstance(fix, dict) else {}
    version = fix.get("fixed") or fixed_version or ""
    package = (fix.get("package") or "").partition(":")[0]
    if not version or version == "0":
        return ""
    if package and re.match(r"^\d+:", version):
        version = re.sub(r"^0:", "", version)
        return f"{package}-{version}"
    return f"{package} {version}".strip()


def label_for(status, fixed_version="", fix=None):
    """The text a person reads next to a match. ``fix`` is the match's ``evidence.distro_fix`` (Red Hat's fixed package and advisory),
    when it has one."""
    if status == PATCHED:
        return "patched by distro" + (f" (fixed in {fixed_version})" if fixed_version and fixed_version != "0" else
                                      " (not affected)" if fixed_version == "0" else "")
    if status == VULNERABLE:
        return "vulnerable per distro tracker" + (f" (fixed in {fixed_version})" if fixed_version else " (no fix yet)")
    if status == BACKPORT:
        build = fixed_build(fix, fixed_version)
        advisory = (fix or {}).get("advisory") if isinstance(fix, dict) else ""
        detail = ", ".join(x for x in ((f"fixed in {build}" if build else ""), advisory or "") if x)
        return "distro fix available, confirm the installed build" + (f" ({detail})" if detail else "")
    return LABEL_UNKNOWN


# --- reading the distro out of a scanner's service record -----------------------------------------------------------

_UBUNTU_REV = re.compile(r"\d+ubuntu[\d.]+")
_DEBIAN_REV = re.compile(r"[\w.+~]*[+~]deb(\d+)u\d+")
_RHEL_REV = re.compile(r"[.+]el(\d+)(?:_\d+)?")  # "-61.el8_9", and a module build's "-65.module+el8.10.0+22069+b47f5c72.1"
_ALPINE_REV = re.compile(r"-r\d+$")
_NMAP_FORM = re.compile(r"^(?P<up>\S+)\s+(?:Ubuntu|Debian)[-\s]+(?P<rev>\S+)", re.IGNORECASE)  # "8.9p1 Ubuntu 3ubuntu0.6"
_DPKG_FORM = re.compile(r"^(?:\d+:)?\d[\w.+~]*-[\w.+~]+$")  # "2.4.57-2", "1:8.9p1-3ubuntu0.10", "2.4.62-1~deb12u2"
_OS_CPE = re.compile(r"cpe:/o:(?P<vendor>[a-z_]+):(?P<product>[a-z_]+)(?::(?P<ver>[\w.]+))?", re.IGNORECASE)
# the OS CPE vendors whose version is a Red Hat family major release ("cpe:/o:redhat:enterprise_linux:8", "cpe:/o:centos:centos:7")
_RHEL_CPE_VENDORS = ("redhat", "centos", "rocky", "rockylinux", "almalinux")
# an operating system's own name with its release, as a host's inventory report or a service names it ("Red Hat Enterprise Linux 8.9 (Ootpa)",
# "CentOS Linux 7", "Rocky Linux 9.3", "AlmaLinux 8.10")
_RHEL_OS_TEXT = re.compile(r"\b(?P<name>red\s*hat\s+enterprise\s+linux(?:\s+server)?|rhel|centos(?:\s+linux)?|rocky(?:\s+linux)?|almalinux)"
                           r"\s*(?:release\s+)?(?P<ver>\d+)(?:\.\d+)*\b", re.IGNORECASE)

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
            or cpe_product in ("enterprise_linux", "centos", "rhel", "linux_enterprise", "rocky", "rocky_linux", "almalinux"):
        out["distro"] = "centos" if "centos" in lowered or cpe_product == "centos" else "rhel"
    elif re.search(r"\balpine\b", lowered) or cpe_product == "alpine_linux":
        out["distro"] = "alpine"
    if not out["distro"]:
        return out

    if os_cpe and os_cpe.group("ver") and out["distro"] in ("ubuntu", "debian"):
        out["release"] = os_cpe.group("ver").split(".")[0] if out["distro"] == "debian" else ".".join(os_cpe.group("ver").split(".")[:2])
    if out["distro"] in RHEL_FAMILY:
        out["release"] = rhel_release(cpes)
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


def rhel_release(cpes=(), text=""):
    """The Red Hat family major release an OS CPE ("cpe:/o:redhat:enterprise_linux:8", "8.4" is 8) or an operating system's name with its
    release ("Red Hat Enterprise Linux 8.9 (Ootpa)") states, else "". Two that disagree state nothing."""
    found = set()
    for cpe in cpes or ():
        m = _OS_CPE.search(cpe or "")
        if m and m.group("ver") and m.group("vendor").lower() in _RHEL_CPE_VENDORS and m.group("ver")[0].isdigit():
            found.add(m.group("ver").split(".")[0])
    for m in _RHEL_OS_TEXT.finditer(text or ""):
        found.add(m.group("ver"))
    return found.pop() if len(found) == 1 else ""


def rhel_family_of_text(text):
    """"centos" or "rhel" when an operating system's name ("CentOS Linux 7", "Red Hat Enterprise Linux 8", "Rocky Linux 9") names the
    Red Hat family, else ""."""
    m = _RHEL_OS_TEXT.search(text or "") or re.search(r"\b(red\s*hat\s+enterprise\s+linux|centos|rocky\s+linux|almalinux)\b", text or "", re.I)
    if not m:
        return ""
    return "centos" if "centos" in m.group(0).lower() else "rhel"


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
    if distro in RHEL_FAMILY:
        if not (is_rpm_evr(fixed) and is_rpm_evr(observed)):
            return None  # a module build named by its stream ("httpd:2.4-8100020240712114234.489197e6") is not an rpm version
        if not re.match(r"^\d+:", observed):
            m = re.match(r"^(\d+:)", fixed)
            observed = (m.group(1) if m else "") + observed
        return rpm_vercmp(observed, fixed)
    return None


_RPM_EVR = re.compile(r"^(?:\d+:)?\d[\w.+~^]*-[\w.+~^]+$")


def is_rpm_evr(text):
    """Whether ``text`` is an rpm epoch:version-release ("1:1.1.1k-9.el8_7", "2.4.37-65.module+el8.10.0+22069+b47f5c72.1")."""
    return bool(_RPM_EVR.match(text or ""))


def judge(info, rows):
    """patched / vulnerable / unknown (and, for the Red Hat family, backport) for one host, from its parsed distro info and the DistroFix
    rows of (package, CVE). Returns (status, fixed_version); ``judge_row`` also returns the row that decided it.

    ``rows`` are dicts {release, fixed_version, status} with status fixed | vulnerable | not_affected | undetermined. The row for
    the host's release is used; with no release known, the row whose fixed version carries the host's upstream version (Ubuntu
    22.04 ships OpenSSH 8.9p1, 24.04 9.6p1, so the upstream version names the release). A host without a package release can
    only be judged by a row that says the release is not affected or has no fix."""
    status, fixed, _row = judge_row(info, rows)
    return status, fixed


def judge_row(info, rows):
    """``judge``, with the DistroFix row (a dict) the verdict came from, or None when no single row decided it."""
    if not info.get("distro"):
        return NO_DATA, "", None
    if not info.get("package"):
        return UNKNOWN, "", None  # the distro is known, but not which of its packages this product is
    rows = _stream_rows(info, rows)
    if info.get("release"):
        chosen = [r for r in rows if str(r.get("release")) == str(info["release"])]
        return (*_judge_row(info, chosen[0]), chosen[0]) if chosen else (UNKNOWN, "", None)
    # No release known: judge against every release's row. If they all agree the release does not matter (a package release
    # older than every release's fix is vulnerable on any of them; one at or past all of them is patched); if they disagree,
    # the row whose fixed upstream version is the host's own names the release (Ubuntu 22.04 ships OpenSSH 8.9p1, 24.04 9.6p1).
    verdicts = [(row, _judge_row(info, row)) for row in rows if row.get("release")]
    verdicts = [(row, v) for row, v in verdicts if v[0] in (PATCHED, VULNERABLE, BACKPORT)]
    if not verdicts:
        return UNKNOWN, "", None
    same = [(row, v) for row, v in verdicts if upstream_of(row.get("fixed_version")) == (info.get("upstream_version") or "")]
    if len({v[0] for _row, v in verdicts}) == 1:
        if same:
            return (*same[0][1], same[0][0])
        if verdicts[0][1][0] == BACKPORT and len({v[1] for _row, v in verdicts}) > 1:
            return BACKPORT, "", None  # every release has a fix, but which build is the host's release's is not known
        return (*verdicts[0][1], verdicts[0][0])
    return (*same[0][1], same[0][0]) if same else (UNKNOWN, "", None)


def _stream_rows(info, rows):
    """For the Red Hat family, the rows that can be about the host's package. RHEL 8 and later ship some packages as module streams
    (``httpd:2.4``, ``php:7.4``), stored with the stream in the package name: a stream row applies to an upstream version inside that
    stream (PHP 7.2.24 is ``php:7.2``), and for a release it replaces the plain row. Two streams of one release that both could apply
    (the upstream version is not known) say nothing about that release. Rows of any other distribution are returned as they are."""
    if info.get("distro") not in RHEL_FAMILY:
        return rows
    upstream = info.get("upstream_version") or ""
    by_release = {}
    for row in rows:
        stream = (row.get("package") or "").partition(":")[2]
        if stream and upstream and upstream != stream and not upstream.startswith(stream + "."):
            continue
        by_release.setdefault(str(row.get("release") or ""), []).append(row)
    out = []
    for group in by_release.values():
        streams = [r for r in group if ":" in (r.get("package") or "")]
        if len(streams) > 1:
            continue
        out.append(streams[0] if streams else group[0])
    return out


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
        if info["distro"] in RHEL_FAMILY and fixed:
            return _backport(info, fixed), fixed
        return UNKNOWN, fixed
    return (PATCHED if cmp >= 0 else VULNERABLE), fixed


def _backport(info, fixed):
    """BACKPORT for a Red Hat fix the host's build cannot be compared with, unless the host's upstream version is newer than the fixed
    build's: then the row may be about another build of the software (a Software Collection, a vendor's own), and it says nothing."""
    upstream = info.get("upstream_version") or ""
    if upstream and is_rpm_evr(fixed) and rpm_vercmp(upstream, upstream_of(fixed)) > 0:
        return UNKNOWN
    return BACKPORT


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
