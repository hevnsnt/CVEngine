"""Fill ``DistroFix``: what Ubuntu, Debian and Red Hat say fixes each CVE, per release and package.

Correlation compares a host's package release with these fixed versions to tell a patched backport from a vulnerable
host (see ``cveFeed.distro``). Three sources, all read-only public data, all optional:

* **Debian security tracker** (``/tracker/data/json``, tens of MB): one file with every package x CVE x release. It is
  stream-parsed one package at a time and only the packages we map and the CVEs that matter are kept.
* **OSV.dev**: ``querybatch`` asks which CVEs a package release is still listed under (Ubuntu, Debian), and a per-CVE record
  (``UBUNTU-CVE-...``, ``DEBIAN-CVE-...``) carries the fixed package version per release.
* **Red Hat Security Data API** (``/hydra/rest/securitydata/cve/<CVE>.json``, a few KB each): per RHEL major release, the fix
  state of each package (Not affected, Affected, Fix deferred, Will not fix) and the fixed build with its advisory (RHSA). It is
  the one source that also says "not affected". Only CVEs with an open match on a Red Hat family host (RHEL, CentOS, Rocky, Alma)
  are asked, and each answer is kept for ``TTL``. A fix shipped as a module stream ("httpd:2.4-8100020240712114234.489197e6") names no
  rpm build, so the advisory's OSV record (``RHSA-...``, which Red Hat publishes to OSV) supplies the fixed rpm version.
  The requests carry only the CVE or advisory id.

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
REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{id}.json"

MAX_CVES = 300  # CVEs looked up per run
MAX_PAIRS = 300  # distinct (package release) OSV questions per run
QUERY_BATCH = 100  # questions per OSV request
MAX_DEBIAN_BYTES = 256 * 1024 * 1024
MAX_BUFFER = 96 * 1024 * 1024  # the biggest single package record (the kernel's) we will hold
MAX_ROWS = 50000
HTTP_TIMEOUT = 30
STREAM_TIMEOUT = 180
TTL = timedelta(hours=20)  # under the daily schedule: an answer read yesterday is due today, not every other day (it was 24 h, the period itself)
MAX_REDHAT_CVES = 300  # Red Hat CVE records read per run
MAX_REDHAT_ADVISORIES = 100  # OSV advisory records read per run to name a module stream's fixed rpm build
MAX_REDHAT_BYTES = 4 * 1024 * 1024  # one Red Hat CVE record or OSV advisory record (a few KB; the kernel's advisories are the largest)
MAX_SOURCE_FAILURES = 5  # failed Red Hat reads in one run before the source is reported unreachable (the first failure, before any read)
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

    def stream_if_changed(self, url, etag="", last_modified=""):
        """``(chunks, validators)`` for a download sent with the validators of the last one (If-None-Match, If-Modified-Since); ``chunks`` is
        None when the server answers 304 Not Modified. ``validators`` are the new ``(etag, last_modified)``."""
        import requests
        headers = {"User-Agent": "cvengine-distro-sync"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        resp = requests.get(url, stream=True, timeout=STREAM_TIMEOUT, headers=headers)
        if resp.status_code == 304:
            resp.close()
            return None, (etag, last_modified)
        resp.raise_for_status()

        def chunks():
            with resp:
                yield from resp.iter_content(chunk_size=1024 * 1024)
        return chunks(), (resp.headers.get("ETag") or "", resp.headers.get("Last-Modified") or "")

    def get_json_capped(self, url, limit):
        """A JSON GET read no further than ``limit`` bytes (ValueError past it); None for a 404."""
        import requests
        with requests.get(url, stream=True, timeout=HTTP_TIMEOUT, headers={"User-Agent": "cvengine-distro-sync"}) as resp:
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            body = b"".join(limited(resp.iter_content(chunk_size=64 * 1024), limit))
        return json.loads(body)


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


# Red Hat's product names for a major release's own channels: "Red Hat Enterprise Linux 8", and the Extended Lifecycle Support that
# continues RHEL 6 and 7. Minor-release channels (EUS, AUS, TUS, E4S) and layered products (JBoss Core Services) are other builds.
_RHEL_PRODUCT = re.compile(r"^Red Hat Enterprise Linux (\d+)(?: Extended Lifecycle Support)?$")
_RPM_NEVR = re.compile(r"^(?P<name>.+?)-(?P<evr>\d+:[^-]+-[^-]+)$")  # httpd-0:2.4.57-11.el9_4
_RHEL_MODULE = re.compile(r"^(?P<name>[\w.+-]+?):(?P<stream>[\w.]+)-(?P<version>\d+)\.(?P<context>\w+)$")  # httpd:2.4-8100020240712114234.489197e6
_OSV_RHEL = re.compile(r"^Red Hat:enterprise_linux:(\d+)::")  # Red Hat:enterprise_linux:8::appstream
_RHEL_OPEN = ("affected", "fix deferred", "will not fix")  # affected in the release with no fix (vulnerable, as the Debian tracker's "open")


def _rhel_release(product_name):
    m = _RHEL_PRODUCT.match((product_name or "").strip())
    return m.group(1) if m else ""


def redhat_package(text):
    """``(package, stream, fixed rpm version, module build)`` of a Red Hat package field: ``httpd-0:2.4.57-11.el9_4`` is a plain build,
    ``httpd:2.4-8100020240712114234.489197e6`` a module build (no rpm version), ``httpd:2.4/httpd`` and ``openssl`` a package state's
    name. The stream is "" for a package outside a module."""
    text = (text or "").strip()
    m = _RPM_NEVR.match(text)
    if m:
        return m.group("name"), "", m.group("evr"), ""
    m = _RHEL_MODULE.match(text)
    if m:
        return m.group("name"), m.group("stream"), "", text
    module, _, package = text.partition("/")
    if package:
        name, _, stream = module.partition(":")
        return package, stream if name == package else "", "", ""
    return text, "", "", ""


def redhat_fixes(record):
    """DistroFix dicts from one Red Hat Security Data API CVE record, one per (RHEL major release, package or module stream), plus the
    module builds whose rpm version is still to be read from their advisory (``osv_module_fixes``). A shipped fix wins over a package
    state, and of two fixes for one release the earlier build (an ELS build is later than the release's own). Only packages cvENGINE
    maps are kept."""
    cve = record.get("name") or ""
    if not _CVE_RE.fullmatch(cve):
        return []
    rows = {}
    for item in record.get("package_state") or []:
        release = _rhel_release(item.get("product_name"))
        package, stream, _evr, _module = redhat_package(item.get("package_name"))
        if not release or not distro_lib.is_known_package(package):
            continue
        state = (item.get("fix_state") or "").strip().lower()
        status = "not_affected" if state == "not affected" else "vulnerable" if state in _RHEL_OPEN else "undetermined"
        key = (release, f"{package}:{stream}" if stream else package)
        if key not in rows or (rows[key]["status"] == "undetermined" and status != "undetermined"):
            rows[key] = {"status": status, "fixed_version": "0" if status == "not_affected" else "", "advisory": "", "module": ""}
    for item in record.get("affected_release") or []:
        release = _rhel_release(item.get("product_name"))
        package, stream, evr, module = redhat_package(item.get("package"))
        if not release or not distro_lib.is_known_package(package) or not (evr or module):
            continue
        key = (release, f"{package}:{stream}" if stream else package)
        fix = {"status": "fixed", "fixed_version": evr, "advisory": (item.get("advisory") or "")[:32], "module": module}
        old = rows.get(key)
        if old is None or old["status"] != "fixed" or (evr and old["fixed_version"] and distro_lib.rpm_vercmp(evr, old["fixed_version"]) < 0):
            rows[key] = fix
    return [{"distro": "rhel", "release": release, "package": package, "cve_id": cve, **row} for (release, package), row in rows.items()]


def osv_module_fixes(record, release, package):
    """The fixed rpm version an OSV advisory record (``RHSA-...``) gives ``package`` on RHEL ``release``, or ""."""
    for affected in (record or {}).get("affected") or []:
        pkg = affected.get("package") or {}
        m = _OSV_RHEL.match(pkg.get("ecosystem") or "")
        if not m or m.group(1) != str(release) or pkg.get("name") != package:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return ""


def rhel_cves_needing_data(limit=MAX_REDHAT_CVES):
    """CVE ids with an open match on a Red Hat family host (correlation recorded ``evidence.distro`` of rhel or centos) whose Red Hat
    record was not read within the TTL (newest CVEs first). Each read leaves a row, so a CVE Red Hat has no record of is not asked again
    until the TTL passes."""
    from cveFeed.closure import CLOSED
    from cveFeed.models import CVEMatch, DistroFix
    wanted = list(CVEMatch.objects.filter(evidence__distro__distro__in=list(distro_lib.RHEL_FAMILY))
                  .exclude(remediation_status__in=CLOSED).exclude(ai_verdict="not_affected")
                  .order_by("-cve_entry__published_at").values_list("cve_entry__cve_id", flat=True).distinct()[:limit * 3])
    fresh = set(DistroFix.objects.filter(distro="rhel", cve_id__in=wanted, synced_at__gte=timezone.now() - TTL)
                .values_list("cve_id", flat=True))
    return [c for c in dict.fromkeys(wanted) if c not in fresh][:limit]


def sync_redhat(fetcher, cves):
    """Red Hat: each CVE's record, then the OSV advisory record of each module build it names (bounded, read once per run). Returns the
    rows, with one row per CVE read (no release, no package) that records the lookup."""
    rows, advisories, read, failed = [], {}, 0, 0
    for cve in cves[:MAX_REDHAT_CVES]:
        try:
            record = fetcher.get_json_capped(REDHAT_CVE_URL.format(id=cve), MAX_REDHAT_BYTES)
        except Exception as exc:  # noqa: BLE001 - one CVE that cannot be read is asked again next run; an unreachable source stops here
            failed += 1
            if not read or failed >= MAX_SOURCE_FAILURES:
                raise
            logger.warning("distro sync: Red Hat record of %s skipped: %s", cve, exc)
            continue
        read += 1
        rows.append({"distro": "rhel", "release": "", "package": "", "cve_id": cve, "fixed_version": "", "status": "undetermined",
                     "advisory": "", "module": ""})
        if isinstance(record, dict):
            rows += redhat_fixes(record)
    for row in rows:
        if not row.get("module"):
            continue
        advisory = row["advisory"]
        if advisory and advisory not in advisories and len(advisories) < MAX_REDHAT_ADVISORIES:
            try:
                advisories[advisory] = fetcher.get_json_capped(OSV_VULN_URL.format(id=advisory), MAX_REDHAT_BYTES)
            except Exception as exc:  # noqa: BLE001 - the module build stays named by its stream; the next run asks again
                logger.warning("distro sync: OSV advisory %s skipped: %s", advisory, exc)
                advisories[advisory] = None
        evr = osv_module_fixes(advisories.get(advisory), row["release"], row["package"].partition(":")[0])
        row["fixed_version"] = evr or row["module"]  # a stream-named build cannot be compared: distro.judge says backport
    return rows


# --- the run ---------------------------------------------------------------------------------------------------------

STORE_CHUNK = 1000


def _store(rows):
    """Upsert DistroFix rows in bulk (a Debian pass is up to ``MAX_ROWS``: one query per row took minutes); returns how many were new or
    changed. A row seen twice in ``rows`` counts once, the last one standing."""
    from cveFeed.models import DistroFix
    changed = 0
    now = timezone.now()
    keyed = {}
    for row in rows:
        key = tuple(str(row[k]) for k in ("distro", "release", "package", "cve_id"))
        keyed[key] = (row["fixed_version"][:128], row["status"], (row.get("advisory") or "")[:32])
    keys = list(keyed)
    for start in range(0, len(keys), STORE_CHUNK):
        chunk = keys[start:start + STORE_CHUNK]
        existing = {(o.distro, o.release, o.package, o.cve_id): o for o in DistroFix.objects.filter(
            cve_id__in={k[3] for k in chunk}, distro__in={k[0] for k in chunk})}
        new, updated, touched = [], [], []
        for key in chunk:
            fixed, status, advisory = keyed[key]
            obj = existing.get(key)
            if obj is None:
                new.append(DistroFix(distro=key[0], release=key[1], package=key[2], cve_id=key[3], fixed_version=fixed, status=status,
                                     advisory=advisory, synced_at=now))
            elif (obj.fixed_version, obj.status, obj.advisory) != (fixed, status, advisory):
                obj.fixed_version, obj.status, obj.advisory, obj.synced_at = fixed, status, advisory, now
                updated.append(obj)
            else:
                touched.append(obj.pk)
        DistroFix.objects.bulk_create(new, ignore_conflicts=True)  # a concurrent run that stored the same row first is no error
        DistroFix.objects.bulk_update(updated, ["fixed_version", "status", "advisory", "synced_at"], batch_size=500)
        if touched:
            DistroFix.objects.filter(pk__in=touched).update(synced_at=now)
        changed += len(new) + len(updated)
    return changed


def cves_needing_data(limit=MAX_CVES):
    """CVE ids of matches on hosts with a known distro whose distro data is missing or older than the TTL (newest CVEs first)."""
    from django.db.models import Q

    from cveFeed.models import CVEMatch, DistroFix
    # a match on a Red Hat family host is Red Hat's question (rhel_cves_needing_data): it neither takes a place here nor counts as fresh
    other = Q(evidence__distro__distro__isnull=True) | ~Q(evidence__distro__distro__in=list(distro_lib.RHEL_FAMILY))
    wanted = list(CVEMatch.objects.exclude(distro_status=distro_lib.NO_DATA).filter(other).order_by("-cve_entry__published_at")
                  .values_list("cve_entry__cve_id", flat=True).distinct()[:limit * 3])
    fresh = set(DistroFix.objects.filter(cve_id__in=wanted, synced_at__gte=timezone.now() - TTL).exclude(distro="rhel")
                .values_list("cve_id", flat=True))
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


DEBIAN_SOURCE = "distro:debian"  # the IntelSource row that keeps the tracker download's validators (ETag, Last-Modified)


def sync_debian(fetcher, cves):
    """The Debian tracker's rows for ``cves``. The tracker is one large file; when every CVE asked about was looked up in an earlier download
    (it has a Debian row), the download is conditional, and a 304 means nothing changed since: their rows are only marked as read again.
    A CVE never looked up makes it a full download."""
    from cveFeed.models import DistroFix, IntelSource
    wanted = set(cves)
    looked_up = set(DistroFix.objects.filter(distro="debian", cve_id__in=wanted).values_list("cve_id", flat=True))
    source, _ = IntelSource.objects.get_or_create(name=DEBIAN_SOURCE)
    conditional = hasattr(fetcher, "stream_if_changed") and wanted <= looked_up and (source.etag or source.last_modified)
    if hasattr(fetcher, "stream_if_changed"):
        chunks, (etag, modified) = fetcher.stream_if_changed(DEBIAN_JSON_URL, *((source.etag, source.last_modified) if conditional else ("", "")))
    else:
        chunks, (etag, modified) = fetcher.stream(DEBIAN_JSON_URL), ("", "")
    now = timezone.now()
    if chunks is None:
        DistroFix.objects.filter(distro="debian", cve_id__in=wanted).update(synced_at=now)
        IntelSource.objects.filter(name=DEBIAN_SOURCE).update(last_checked=now, last_error="")
        return []
    rows = list(debian_fixes(iter_json_object(limited(chunks, MAX_DEBIAN_BYTES)), wanted))
    # a CVE the tracker has nothing on (for the packages we map) is recorded as looked up, so the next pass can ask conditionally
    found = {r["cve_id"] for r in rows}
    rows += [{"distro": "debian", "release": "", "package": "", "cve_id": c, "fixed_version": "", "status": "undetermined"}
             for c in sorted(wanted - found)]
    IntelSource.objects.filter(name=DEBIAN_SOURCE).update(etag=(etag or "")[:200], last_modified=(modified or "")[:100], last_checked=now,
                                                          last_changed=now, last_error="")
    return rows


def sync_distro_fixes(fetcher=None):
    """One bounded pass over the sources (Red Hat's only when a Red Hat family host has an open match). A source that fails is reported
    in the result and skipped. Returns ``{"cves", "rows", "changed", "sources": {name: "ok" | error}}``, and ``redhat_cves`` when Red Hat
    was asked."""
    fetcher = fetcher or Fetcher()
    cves = cves_needing_data()
    rhel_cves = rhel_cves_needing_data()
    result = {"cves": len(cves), "rows": 0, "changed": 0, "sources": {}}
    sources = []
    if cves:
        sources += [("debian", lambda: sync_debian(fetcher, cves)),
                    ("osv", lambda: sync_osv(fetcher, cves, package_release_pairs()))]
    if rhel_cves:
        result["redhat_cves"] = len(rhel_cves)
        sources.append(("redhat", lambda: sync_redhat(fetcher, rhel_cves)))
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
