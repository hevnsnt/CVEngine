"""Fill ``DistroFix``: what Ubuntu and Debian say fixes each CVE, per release and package.

Correlation compares a host's package release with these fixed versions to tell a patched backport from a vulnerable
host (see ``cveFeed.distro``). Two sources, both read-only public data, both optional:

* **Debian security tracker** (``/tracker/data/json``, tens of MB): one file with every package x CVE x release. It is
  stream-parsed one package at a time and only the packages we map and the CVEs that matter are kept.
* **OSV.dev**: ``querybatch`` asks which CVEs a package release is still listed under (Ubuntu, Debian), and a per-CVE record
  (``UBUNTU-CVE-...``, ``DEBIAN-CVE-...``) carries the fixed package version per release.

Everything is bounded (CVEs and package queries per run, bytes downloaded, rows written, request timeouts), nothing blocks
correlation, and a source that cannot be reached is reported and skipped: the run still finishes and the next one retries.
The network is behind a ``Fetcher`` so tests inject a fake and never touch the internet.
"""
import codecs
import json
import logging
import re
from datetime import timedelta

from django.utils import timezone

from cveFeed import distro as distro_lib

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
DEBIAN_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"

MAX_CVES = 300  # CVEs looked up per run
MAX_PAIRS = 300  # distinct (package release) OSV questions per run
QUERY_BATCH = 100  # questions per OSV request
MAX_DEBIAN_BYTES = 256 * 1024 * 1024
MAX_BUFFER = 96 * 1024 * 1024  # the biggest single package record (the kernel's) we will hold
MAX_ROWS = 50000
HTTP_TIMEOUT = 30
STREAM_TIMEOUT = 180
TTL = timedelta(hours=24)
DEBIAN_RELEASES = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class Fetcher:
    """The network: JSON GET/POST and a chunked download. Swapped for a fake in tests."""

    def get_json(self, url):
        import requests
        resp = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "cvengine-distro-sync"})
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def post_json(self, url, payload):
        import requests
        resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT, headers={"User-Agent": "cvengine-distro-sync"})
        resp.raise_for_status()
        return resp.json()

    def stream(self, url):
        import requests
        with requests.get(url, stream=True, timeout=STREAM_TIMEOUT, headers={"User-Agent": "cvengine-distro-sync"}) as resp:
            resp.raise_for_status()
            yield from resp.iter_content(chunk_size=1024 * 1024)


# --- streaming a big JSON object -----------------------------------------------------------------------------------

def iter_json_object(chunks, max_buffer=MAX_BUFFER):
    """Yield (key, value) for each member of a top-level JSON object read from an iterable of byte chunks, holding only one
    member at a time (the Debian tracker is one object with tens of MB of members). Raises ValueError on malformed input or a
    single member larger than ``max_buffer``."""
    decoder = json.JSONDecoder()
    text = codecs.getincrementaldecoder("utf-8")(errors="replace")
    source = iter(chunks)
    state = {"buf": "", "done": False}

    def more():
        if state["done"]:
            return False
        try:
            chunk = next(source)
        except StopIteration:
            state["done"] = True
            state["buf"] += text.decode(b"", final=True)
            return False
        state["buf"] += text.decode(chunk) if isinstance(chunk, bytes) else chunk
        if len(state["buf"]) > max_buffer:
            raise ValueError("a JSON member is larger than the buffer limit")
        return True

    def skip(chars):
        pos = 0
        while True:
            buf = state["buf"]
            while pos < len(buf) and buf[pos] in chars:
                pos += 1
            if pos < len(buf):
                state["buf"] = buf[pos:]
                return buf[pos]
            state["buf"] = ""
            pos = 0
            if not more():
                return ""

    def value():
        while True:
            try:
                obj, end = decoder.raw_decode(state["buf"])
                state["buf"] = state["buf"][end:]
                return obj
            except json.JSONDecodeError:
                if state["done"]:
                    raise ValueError("malformed JSON")
                target = len(state["buf"]) * 1.5 + 1
                while len(state["buf"]) < target and more():  # retry after the buffer has grown, not after every chunk
                    pass

    if skip(" \t\r\n") != "{":
        raise ValueError("expected a JSON object")
    state["buf"] = state["buf"][1:]
    while True:
        head = skip(" \t\r\n,")
        if head == "}" or head == "":
            return
        key = value()
        if skip(" \t\r\n") != ":":
            raise ValueError("expected ':'")
        state["buf"] = state["buf"][1:]
        skip(" \t\r\n")
        yield key, value()


def limited(chunks, limit):
    """Pass chunks through until ``limit`` bytes, then stop with ValueError: a runaway download is cut off."""
    total = 0
    for chunk in chunks:
        total += len(chunk)
        if total > limit:
            raise ValueError(f"download is larger than {limit} bytes")
        yield chunk


# --- parsing the two sources ---------------------------------------------------------------------------------------

def osv_ecosystem(distro, release):
    """OSV's ecosystem name for a distro release, or None for one OSV does not carry here."""
    if distro == "ubuntu" and re.fullmatch(r"\d\d\.04", release or ""):
        return f"Ubuntu:{release}" + (":LTS" if int(release[:2]) % 2 == 0 else "")
    if distro == "ubuntu" and re.fullmatch(r"\d\d\.10", release or ""):
        return f"Ubuntu:{release}"
    if distro == "debian" and release:
        return f"Debian:{release}"
    return None


def parse_ecosystem(ecosystem):
    """'Ubuntu:22.04:LTS' -> ('ubuntu', '22.04'); 'Debian:12' -> ('debian', '12'); None for Pro/ESM and other ecosystems."""
    parts = (ecosystem or "").split(":")
    if parts[0] == "Ubuntu" and len(parts) >= 2 and re.fullmatch(r"\d\d\.\d\d", parts[1]):
        return "ubuntu", parts[1]
    if parts[0] == "Debian" and len(parts) == 2 and parts[1].isdigit():
        return "debian", parts[1]
    return None


def osv_fixes(record):
    """DistroFix dicts from one OSV record (an UBUNTU-CVE-/DEBIAN-CVE- advisory): the first fixed package version per release,
    or a "vulnerable" row where the record lists the package with no fix."""
    cves = [c for c in (record.get("upstream") or []) + (record.get("aliases") or []) if _CVE_RE.fullmatch(c)] or \
        _CVE_RE.findall(record.get("id", ""))
    out = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        target = parse_ecosystem(pkg.get("ecosystem"))
        if not target or not distro_lib.is_known_package(pkg.get("name", "")):
            continue
        fixed = ""
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed = event["fixed"]
        for cve in cves[:1]:
            out.append({"distro": target[0], "release": target[1], "package": pkg["name"], "cve_id": cve,
                        "fixed_version": fixed, "status": "fixed" if fixed else "vulnerable"})
    return out


def debian_fixes(members, wanted_cves, max_rows=MAX_ROWS):
    """DistroFix dicts from the Debian tracker's (package, {cve: record}) members: only mapped packages, only ``wanted_cves``,
    only stable releases we know by number."""
    count = 0
    for package, cves in members:
        if not distro_lib.is_known_package(package) or not isinstance(cves, dict):
            continue
        for cve, info in cves.items():
            if cve not in wanted_cves or not isinstance(info, dict):
                continue
            for codename, rel in (info.get("releases") or {}).items():
                release = DEBIAN_RELEASES.get(codename)
                if not release or not isinstance(rel, dict):
                    continue
                status = rel.get("status")
                if status == "resolved":
                    row = {"status": "fixed", "fixed_version": str(rel.get("fixed_version") or "")}
                elif status == "open":
                    row = {"status": "vulnerable", "fixed_version": ""}
                else:
                    row = {"status": "undetermined", "fixed_version": ""}
                yield {"distro": "debian", "release": release, "package": package, "cve_id": cve, **row}
                count += 1
                if count >= max_rows:
                    return


# --- the run ---------------------------------------------------------------------------------------------------------

def _store(rows):
    """Upsert DistroFix rows; returns how many were new or changed."""
    from cveFeed.models import DistroFix
    changed = 0
    now = timezone.now()
    for row in rows:
        key = {k: row[k] for k in ("distro", "release", "package", "cve_id")}
        obj, created = DistroFix.objects.get_or_create(**key, defaults={
            "fixed_version": row["fixed_version"][:128], "status": row["status"], "synced_at": now})
        if created:
            changed += 1
        elif (obj.fixed_version, obj.status) != (row["fixed_version"][:128], row["status"]):
            obj.fixed_version, obj.status, obj.synced_at = row["fixed_version"][:128], row["status"], now
            obj.save(update_fields=["fixed_version", "status", "synced_at"])
            changed += 1
        else:
            DistroFix.objects.filter(pk=obj.pk).update(synced_at=now)
    return changed


def cves_needing_data(limit=MAX_CVES):
    """CVE ids of matches on hosts with a known distro whose distro data is missing or older than the TTL (newest CVEs first)."""
    from cveFeed.models import CVEMatch, DistroFix
    wanted = list(CVEMatch.objects.exclude(distro_status=distro_lib.NO_DATA).order_by("-cve_entry__published_at")
                  .values_list("cve_entry__cve_id", flat=True).distinct()[:limit * 3])
    fresh = set(DistroFix.objects.filter(cve_id__in=wanted, synced_at__gte=timezone.now() - TTL).values_list("cve_id", flat=True))
    return [c for c in dict.fromkeys(wanted) if c not in fresh][:limit]


def package_release_pairs(limit=MAX_PAIRS):
    """The distinct (distro, release, package, package release) the inventory runs, for the OSV question."""
    from startScan.models import Port
    seen, out = set(), []
    for distro, release, product, package_release, upstream in Port.objects.exclude(distro="").exclude(package_release="") \
            .exclude(distro_release="").values_list("distro", "distro_release", "product", "package_release", "upstream_version") \
            .distinct()[:limit * 3]:
        package = distro_lib.package_for(product, distro, upstream)
        ecosystem = osv_ecosystem(distro, release)
        if not package or not ecosystem:
            continue
        key = (distro, release, package, package_release)
        if key not in seen:
            seen.add(key)
            out.append({"distro": distro, "release": release, "package": package, "ecosystem": ecosystem,
                        "version": distro_lib.with_default_epoch(package, package_release)})
        if len(out) >= limit:
            break
    return out


def sync_osv(fetcher, cves, pairs):
    """OSV: the CVEs each observed package release is still listed under (querybatch) join the CVEs we already care about, then
    each one's advisory gives the fixed version per release. Returns the rows."""
    wanted = set(cves)
    for start in range(0, len(pairs), QUERY_BATCH):
        chunk = pairs[start:start + QUERY_BATCH]
        reply = fetcher.post_json(OSV_BATCH_URL, {"queries": [
            {"package": {"name": p["package"], "ecosystem": p["ecosystem"]}, "version": p["version"]} for p in chunk]})
        for result in (reply or {}).get("results", []):
            for vuln in (result or {}).get("vulns", []):
                found = _CVE_RE.findall(vuln.get("id", ""))
                if found:
                    wanted.add(found[0])
    from cveFeed.models import CVEEntry
    known = set(CVEEntry.objects.filter(cve_id__in=list(wanted)).values_list("cve_id", flat=True)) if wanted else set()
    rows = []
    families = sorted({p["distro"] for p in pairs} | {"ubuntu", "debian"})
    for cve in sorted(known)[:MAX_CVES]:
        for family in families:
            prefix = {"ubuntu": "UBUNTU", "debian": "DEBIAN"}.get(family)
            if not prefix:
                continue
            record = fetcher.get_json(OSV_VULN_URL.format(id=f"{prefix}-{cve}"))
            if record:
                rows += osv_fixes(record)
    return rows


def sync_debian(fetcher, cves):
    return list(debian_fixes(iter_json_object(limited(fetcher.stream(DEBIAN_JSON_URL), MAX_DEBIAN_BYTES)), set(cves)))


def sync_distro_fixes(fetcher=None):
    """One bounded pass over both sources. A source that fails is reported in the result and skipped. Returns
    ``{"cves", "rows", "changed", "sources": {name: "ok" | error}}``."""
    fetcher = fetcher or Fetcher()
    cves = cves_needing_data()
    result = {"cves": len(cves), "rows": 0, "changed": 0, "sources": {}}
    if not cves:
        return result
    sources = (("debian", lambda: sync_debian(fetcher, cves)),
               ("osv", lambda: sync_osv(fetcher, cves, package_release_pairs())))
    for name, run in sources:
        try:
            rows = run()
            result["rows"] += len(rows)
            result["changed"] += _store(rows)
            result["sources"][name] = "ok"
        except Exception as exc:  # noqa: BLE001 - an unreachable source must not fail the run or the other source
            logger.warning("distro sync: %s skipped: %s", name, exc)
            result["sources"][name] = f"{type(exc).__name__}: {exc}"[:200]
    return result
