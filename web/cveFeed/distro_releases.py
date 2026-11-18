"""Which release of a distribution a banner's package build belongs to.

A banner such as ``OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`` names an exact Ubuntu package build, but not the Ubuntu release: nmap's OS CPE for it
is usually ``cpe:/o:canonical:ubuntu_linux`` with no version. The release decides which of the distribution tracker's rows judges the host
(Ubuntu 22.04's fixed build of a CVE is not 24.04's), so it is read here, most certain first:

1. ``stated``: the banner or the OS CPE names it (``cpe:/o:canonical:ubuntu_linux:22.04``, ``Amazon Linux 2023``).
2. ``package``: the package build carries it, by the distribution's own versioning rules: Ubuntu's ``0ubuntu0.22.04.1`` and
   ``1ubuntu2.1~18.04.23``, Debian's ``+deb12u3`` and ``~deb11u1``, Red Hat's ``.el9_4``, Amazon Linux's ``.amzn2``, SUSE's ``150400.6.11.1``
   (SLE 15 SP4).
3. ``table``: the build is one only a single release ever published (``data/distro_packages.json``): Ubuntu's OpenSSH ``8.9p1-3ubuntu0.x``
   is jammy, Debian's ``9.2p1-2`` is bookworm. A banner that shows only the upstream version (``Apache/2.4.52 (Ubuntu)``) is read this way
   only when every build of that upstream version belongs to one release; ``nginx/1.18.0 (Ubuntu)`` (focal and jammy both ship it) names
   none.

The table is built from the distributions' publishing records: Launchpad's publishing history of each source package (the version frozen
in each series' Release pocket, and every version published to -updates and -security) and, for Debian, the versions of each stable suite
(sources.debian.org, tracker.debian.org) and every ``+debNuM`` build ever uploaded (snapshot.debian.org). Every (distribution, release,
package) it names has a citation in the file's ``citations``: the Launchpad page of the package in that series, or the Debian package
tracker. A version the table has not seen (a newer security update) is placed by its revision's prefix (``3ubuntu0.14`` is still jammy's
``3ubuntu0``), and anything ambiguous is left unknown: a guessed release could only mislead.

The reading is pure Python (no Django), like ``cveFeed.distro``; only ``catch_up`` (the upgrade backfill) touches the database.
"""
import json
import os
import re
from functools import lru_cache

STATED, PACKAGE, TABLE = "stated", "package", "table"

# Ubuntu's releases (https://launchpad.net/ubuntu/+series, https://wiki.ubuntu.com/Releases): version -> codename
UBUNTU_CODENAMES = {
    "14.04": "trusty", "14.10": "utopic", "15.04": "vivid", "15.10": "wily", "16.04": "xenial", "16.10": "yakkety", "17.04": "zesty",
    "17.10": "artful", "18.04": "bionic", "18.10": "cosmic", "19.04": "disco", "19.10": "eoan", "20.04": "focal", "20.10": "groovy",
    "21.04": "hirsute", "21.10": "impish", "22.04": "jammy", "22.10": "kinetic", "23.04": "lunar", "23.10": "mantic", "24.04": "noble",
    "24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute", "26.10": "stonking", "27.04": "tenacious",
}
# Debian's releases (https://www.debian.org/releases/): major version -> codename
DEBIAN_CODENAMES = {"8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}
CODENAMES = {"ubuntu": UBUNTU_CODENAMES, "debian": DEBIAN_CODENAMES}
_BY_CODENAME = {name: (distro, release) for distro, table in CODENAMES.items() for release, name in table.items()}

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "distro_packages.json")

_UBUNTU_IN_BUILD = re.compile(r"(?:ubuntu0?\.|[+~]ubuntu|~)(\d\d\.\d\d)(?:\.\d+)*(?=$|[^\d.])")  # 0ubuntu0.22.04.1, +ubuntu22.04.1, ~18.04.23
_DEBIAN_IN_BUILD = re.compile(r"[+~]deb(\d{1,2})u\d+")
_DEBIAN_BPO = re.compile(r"~bpo(\d{1,2})\+\d+")
_RHEL_IN_BUILD = re.compile(r"[.+]el(\d{1,2})(?=[._+]|$)")
_AMZN_IN_BUILD = re.compile(r"\.amzn(2023|\d)(?=[._]|$)")
_SUSE_IN_BUILD = re.compile(r"-1(\d)0(\d)00\.\d")  # 2.4.51-150400.6.11.1: SUSE Linux Enterprise 15 SP4


def codename(distro, release):
    """``jammy`` for ("ubuntu", "22.04"), ``bookworm`` for ("debian", "12"), else ""."""
    return CODENAMES.get(distro, {}).get(str(release or ""), "")


def from_codename(name):
    """("ubuntu", "22.04") for ``jammy`` (any case), else None."""
    return _BY_CODENAME.get((name or "").strip().lower())


def release_from_build(distro, package_release):
    """The release a package build's own versioning names (``8.0.35-0ubuntu0.22.04.1`` is Ubuntu 22.04, ``2.4.62-1~deb12u2`` Debian 12,
    ``8.7p1-38.el9_4.4`` RHEL 9, ``7.4p1-22.amzn2.0.9`` Amazon Linux 2, ``2.4.51-150400.6.11.1`` SUSE 15.4), else ""."""
    text = package_release or ""
    if not text:
        return ""
    if distro == "ubuntu":
        m = _UBUNTU_IN_BUILD.search(text)
        return m.group(1) if m and m.group(1) in UBUNTU_CODENAMES else ""
    if distro == "debian":
        m = _DEBIAN_IN_BUILD.search(text) or _DEBIAN_BPO.search(text)
        return m.group(1) if m else ""
    if distro in ("rhel", "centos"):
        m = _RHEL_IN_BUILD.search(text)
        return m.group(1) if m else ""
    if distro == "amzn":
        m = _AMZN_IN_BUILD.search(text)
        return m.group(1) if m else ""
    if distro == "suse":
        m = _SUSE_IN_BUILD.search(text)
        return (m.group(1) and f"1{m.group(1)}" + (f".{m.group(2)}" if m.group(2) != "0" else "")) if m else ""
    return ""


@lru_cache(maxsize=1)
def table():
    """The release table (``data/distro_packages.json``): ``{distro: {package: {upstream: {revision: [releases]}}}, "citations": {...}}``.
    An unreadable file is an empty table: the release is then only read from what the banner states."""
    try:
        with open(DATA_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def citation(distro, release, package):
    """Where the table's claim that ``release`` of ``distro`` published ``package`` comes from (a URL), or ""."""
    return (table().get("citations") or {}).get(f"{distro}/{release}/{package}", "")


def _base(distro, revision):
    """The part of a revision every update of one release keeps: Ubuntu's ``3ubuntu0`` of ``3ubuntu0.6`` (an update is ``.N`` after it),
    Debian's ``2`` of ``2+deb12u3``."""
    if distro == "ubuntu":
        m = re.match(r"^(.*?ubuntu\d+)", revision)
        return m.group(1) if m else revision
    return re.sub(r"[+~](?:deb\d+u\d+|bpo\d+).*$", "", revision)


def release_from_table(distro, package, upstream, revision=""):
    """The one release of ``distro`` whose ``package`` builds include this one, from the table: the exact revision first, then the
    revision's prefix (a later update of the same release), then, with no revision (a banner that shows only the upstream version), the
    upstream version alone. "" when the table does not know the package or version, or more than one release fits."""
    versions = ((table().get(distro) or {}).get(package) or {}).get(upstream or "")
    if not isinstance(versions, dict) or not versions:
        return ""
    if revision:
        exact = versions.get(revision)
        if exact:
            return exact[0] if len(exact) == 1 else ""
        base = _base(distro, revision)
        if base == revision and distro == "ubuntu" and "ubuntu" not in revision:
            return ""  # an unchanged Debian revision on Ubuntu the table has not seen: not placed
        found = {r for rev, releases in versions.items() if _base(distro, rev) == base for r in releases}
        return found.pop() if len(found) == 1 else ""
    found = {r for releases in versions.values() for r in releases}
    return found.pop() if len(found) == 1 else ""


# --- the one-time catch-up an update runs ------------------------------------------------------------------------------------------------

def catch_up(apply=False, batch=500):
    """``manage.py backfill_distro_readings`` (an upgrade backfill): read every stored service record again with today's parser
    (``distro.parse_distro``: an SSH identification string, the release a build or the table names, another publisher's build, Amazon Linux,
    SUSE and FreeBSD), rewrite the Port rows whose reading changed (the four distro columns and ``extra['distro']``), then correlate again every
    current host with a distribution reading (a changed row, a Debian or Ubuntu service, a Server header naming a distribution), so each match
    is judged by its distribution's own fixed build. Nothing is fetched. Idempotent: a second run finds nothing to rewrite. Returns
    ``{'ports', 'changed', 'hosts', 'matches'}``."""
    from django.db.models import Q

    from cveFeed import correlation, distro as distro_lib
    from cveFeed.port_inventory import store_distro
    from startScan.models import Port, Subdomain
    ids = list(Port.objects.exclude(product="").order_by("id").values_list("id", flat=True))
    out = {"ports": len(ids), "changed": 0, "hosts": 0, "matches": 0}
    changed = []
    for start in range(0, len(ids), batch):
        for port in Port.objects.filter(id__in=ids[start:start + batch]).only(
                "id", "product", "version", "service_extra", "cpe", "banner", "extra", "distro", "distro_release", "package_release",
                "upstream_version"):
            cpes = (port.extra or {}).get("cpes") or [port.cpe]
            info = distro_lib.parse_distro(port.product, port.version, port.service_extra, cpes, port.banner)
            if not info["distro"] and port.distro:
                continue  # nothing in the fields any more says what the columns hold: they stay as ingest wrote them
            if store_distro(port, info):
                changed.append(port.id)
                if apply:
                    port.save(update_fields=["distro", "distro_release", "package_release", "upstream_version", "extra"])
    out["changed"] = len(changed)
    markers = Q()
    for word in ("ubuntu", "debian", "red hat", "centos", "rocky", "almalinux", "amazon", "suse", "freebsd"):
        markers |= Q(webserver__icontains=word)
    hosts = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False).filter(
        Q(ip_addresses__ports__in=changed) | Q(ip_addresses__ports__distro__gt="") | markers)
    host_ids = list(hosts.order_by("id").values_list("id", flat=True).distinct())
    out["hosts"] = len(host_ids)
    if not apply or not host_ids:
        return out
    cve_by_id, index = correlation.cve_pool()
    for start in range(0, len(host_ids), batch):
        subs = Subdomain.objects.filter(id__in=host_ids[start:start + batch]).select_related("target_domain", "scan_history") \
            .prefetch_related("technologies", "ip_addresses__ports")
        out["matches"] += correlation.correlate_subdomains(list(subs), index, cve_by_id, min_confidence=0.4)[1]
    return out


# --- search: distro: and pkg: ------------------------------------------------------------------------------------------------------------

# the names a person types for a distribution (distro:ubuntu, distro:redhat): each is the distro key a reading stores, or the Red Hat family
SEARCH_NAMES = {"ubuntu": ("ubuntu",), "debian": ("debian",), "rhel": ("rhel", "centos"), "redhat": ("rhel", "centos"),
                "centos": ("centos",), "rocky": ("rhel",), "alma": ("rhel",), "almalinux": ("rhel",), "alpine": ("alpine",),
                "amzn": ("amzn",), "amazon": ("amzn",), "suse": ("suse",), "sles": ("suse",), "opensuse": ("suse",),
                "freebsd": ("freebsd",)}
_SEARCH_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}\Z")
_SEARCH_BUILD = re.compile(r"^(?:\d{1,4}:)?[A-Za-z0-9][\w.+~-]{0,63}\Z")
_SEARCH_RELEASE = re.compile(r"^\d{1,4}(?:\.\d{1,2})?\Z")


def _release_q(prefix, release):
    from django.db.models import Q
    return Q(**{prefix + "distro_release": release}) | Q(**{prefix + "distro_release__startswith": release + "."})


def search_q(field, value, prefix="ip_addresses__ports__"):
    """The Q (over a host's open ports, ``prefix``) a ``distro:`` or ``pkg:`` search term means, or None for a value it does not take.

    ``distro:`` takes ``any``, a distribution (``ubuntu``, ``debian``, ``rhel``: the Red Hat family, ``centos``, ``alpine``, ``amzn``, ``suse``,
    ``freebsd``), a codename (``jammy``, ``bookworm``), or a distribution and a release prefix after ``@`` (``ubuntu@22.04``, ``debian@12``,
    ``rhel@9``; ``ubuntu@22`` finds 22.04 and 22.10, never 2.2). ``pkg:`` takes a source package (``openssh``, ``apache2``, ``php8.1``), and
    optionally its build after ``@``: the exact build or one that starts with it (``openssh@1:8.9p1-3ubuntu0.6``: the epoch, which banners never
    show, may be left out; ``openssh@8.9p1-3ubuntu0`` finds every jammy update)."""
    from django.db.models import Q
    open_port = Q(**{prefix + "state__in": ("", "open")})
    text = (value or "").strip().lower() if field == "distro" else (value or "").strip()
    if field == "distro":
        if text == "any":
            return Q(**{prefix + "distro__gt": ""}) & open_port
        named = from_codename(text)
        if named:
            return Q(**{prefix + "distro": named[0], prefix + "distro_release": named[1]}) & open_port
        name, _, release = text.partition("@")
        keys = SEARCH_NAMES.get(name)
        if not keys or (release and not _SEARCH_RELEASE.match(release)):
            return None
        q = Q(**{prefix + "distro__in": list(keys)})
        return (q & _release_q(prefix, release) if release else q) & open_port
    if field == "pkg":
        name, _, build = text.partition("@")
        name = name.lower()
        if not _SEARCH_PACKAGE.match(name) or (build and not _SEARCH_BUILD.match(build)):
            return None
        q = Q(**{prefix + "extra__distro__package": name})
        if build:
            bare = re.sub(r"^\d+:", "", build)
            same = Q(**{prefix + "package_release": bare}) | Q(**{prefix + "package_release__endswith": ":" + bare})
            for sep in (".", "+", "~", "-"):
                same |= Q(**{prefix + "package_release__startswith": bare + sep})
            q &= same
        return q & open_port
    return None


def _port_matches(port, field, value):
    """Whether one Port row is what a ``distro:`` or ``pkg:`` term asks for (``search_q``, read in Python for the results list)."""
    stored = (port.extra or {}).get("distro") or {}
    text = (value or "").strip()
    if field == "distro":
        text = text.lower()
        if text == "any":
            return True
        named = from_codename(text)
        if named:
            return (port.distro, port.distro_release) == named
        name, _, release = text.partition("@")
        if port.distro not in SEARCH_NAMES.get(name, ()):
            return False
        return not release or port.distro_release == release or port.distro_release.startswith(release + ".")
    name, _, build = text.partition("@")
    if str(stored.get("package") or "") != name.lower():
        return False
    if not build:
        return True
    bare, have = re.sub(r"^\d+:", "", build), re.sub(r"^\d+:", "", port.package_release or "")
    return have == bare or any(have.startswith(bare + sep) for sep in ".+~-")


def search_reason(port, field, value):
    """The words the results list shows for a port a ``distro:`` or ``pkg:`` term matched ("openssh 8.9p1-3ubuntu0.6, Ubuntu 22.04 (jammy)"),
    or "" for a port it did not."""
    if not getattr(port, "distro", "") or not _port_matches(port, field, value):
        return ""
    from cveFeed.distro import NAMES
    stored = (port.extra or {}).get("distro") or {}
    name = NAMES.get(port.distro, port.distro)
    where = " ".join(x for x in (name, port.distro_release or "", f"({stored['codename']})" if stored.get("codename") else "") if x)
    if field == "pkg":
        return f"{stored.get('package')} {port.package_release}".strip() + f", {where}"
    return where
