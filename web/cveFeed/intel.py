"""Threat intelligence beyond cve.now: who says a CVE is exploited, how likely exploitation is, and whether exploit code is public.

The cve.now feed reaches only recent CVEs in its incremental walk (and the backfill a few weeks back), so a 2021 CVE that is
exploited today can be missing entirely. These public sources cover the whole history, need no account (VulnCheck aside),
and are each one file or a short paged API:

  cisa_kev       CISA Known Exploited Vulnerabilities catalog (JSON)              exploited in the wild
  euvd           ENISA EU Vulnerability Database, exploited filter (paged API)    exploited in the wild
  vulncheck_kev  VulnCheck KEV (paged API; only with CVENGINE_VULNCHECK_API_KEY)  exploited in the wild
  epss           FIRST EPSS scores for every CVE (daily CSV)                      probability of exploitation in 30 days
  exploit_db     Exploit-DB exploit index (CSV)                                   public exploit code
  metasploit     Metasploit module metadata (JSON)                                weaponized exploit

How they are reconciled into the three signals the fire / smoke / ice tiers read (cveFeed.threat):
  kev           True when cve.now or any exploited-in-the-wild source lists the CVE
  exploit_db    True when cve.now reports an Exploit-DB entry, or Exploit-DB or Metasploit has one
  epss_reached  EPSS >= 0.1 from today's EPSS file when it scores the CVE, else cve.now's value
A source only ever adds evidence: being absent from one source never clears what another reported. Each CVE keeps the
per-source detail in ``CVEEntry.intel``, so the page can say who listed it.

A CVE these sources name that is not stored yet is imported from its CVE List V5 record (the official CVE JSON, with the
CNA's affected products and version ranges and CISA's ADP enrichment), most important first: exploited in the wild, then
weaponized, then likely (EPSS), then any public exploit. Each run imports a bounded number, so a fresh install fills in over a
few hours, and the new CVEs are correlated against the inventory and announced like any new fire-tier CVE.
"""
import zlib
import io
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from functools import cmp_to_key
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
USER_AGENT = "CVEngine threat intelligence (+https://github.com/hevnsnt/CVEngine)"
MAX_BYTES = 64 * 1024 * 1024
MAX_DECOMPRESSED = 512 * 1024 * 1024  # what a feed file may expand to (the real EPSS file is about 20 MB)
EPSS_THRESHOLD = 0.1  # the CVEEntry.epss_reached meaning
CVE5_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve}.json"

SOURCES = {
    "cisa_kev": {"label": "CISA KEV", "kind": "kev", "every": timedelta(hours=6),
                 "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    "euvd": {"label": "ENISA EUVD", "kind": "kev", "every": timedelta(hours=12),
             "url": "https://euvdservices.enisa.europa.eu/api/search?exploited=true&page={page}&size=100"},
    "vulncheck_kev": {"label": "VulnCheck KEV", "kind": "kev", "every": timedelta(hours=12),
                      "url": "https://api.vulncheck.com/v3/index/vulncheck-kev?page={page}&limit=100"},
    "epss": {"label": "FIRST EPSS", "kind": "epss", "every": timedelta(hours=12),
             "url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"},
    "exploit_db": {"label": "Exploit-DB", "kind": "exploit", "every": timedelta(hours=24),
                   "url": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"},
    "metasploit": {"label": "Metasploit", "kind": "exploit", "every": timedelta(hours=24),
                   "url": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"},
}
KEV_SOURCES = tuple(name for name, s in SOURCES.items() if s["kind"] == "kev")
EXPLOIT_SOURCES = tuple(name for name, s in SOURCES.items() if s["kind"] == "exploit")
IMPORT_GROUPS = ("kev", "metasploit", "epss", "exploit_db")  # CVENGINE_INTEL_IMPORT order and default


class SourceError(Exception):
    pass


def _clean(value, limit):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()[:limit]


def _date(value):
    return _clean(value, 40)


def _int_env(name, default, low=0, high=100000):
    try:
        return max(low, min(high, int(os.environ.get(name, default))))
    except ValueError:
        return default


def enabled_sources():
    """The sources this install uses: CVENGINE_INTEL_SOURCES (comma separated) or all; VulnCheck only with its key;
    CVENGINE_INTEL=0 turns the whole feature off."""
    if os.environ.get("CVENGINE_INTEL", "1") == "0":
        return []
    wanted = [s.strip() for s in os.environ.get("CVENGINE_INTEL_SOURCES", ",".join(SOURCES)).split(",") if s.strip()]
    return [s for s in wanted if s in SOURCES and (s != "vulncheck_kev" or os.environ.get("CVENGINE_VULNCHECK_API_KEY"))]


def cache_dir():
    path = os.environ.get("CVENGINE_INTEL_DIR") or os.path.join(settings.MEDIA_ROOT, ".threat-intel")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


# ----------------------------------------------------------------------------- fetching (fixed public addresses only)

def _get(url, headers=None, get=None):
    import requests
    return (get or requests.get)(url, headers={"User-Agent": USER_AGENT, **(headers or {})}, timeout=(10, 120), stream=True)


def _body(resp):
    chunks, size = [], 0
    try:
        for chunk in resp.iter_content(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES:
                raise SourceError("the file is larger than the limit")
            chunks.append(chunk)
    finally:
        resp.close()
    return b"".join(chunks)


def fetch_file(name, etag="", modified="", get=None):
    """``(bytes or None, etag, last_modified)``; None when the server says the file has not changed."""
    headers = {"If-None-Match": etag} if etag else {}
    if modified:
        headers["If-Modified-Since"] = modified
    resp = _get(SOURCES[name]["url"], headers, get)
    if resp.status_code == 304:
        resp.close()
        return None, etag, modified
    if resp.status_code != 200:
        resp.close()
        raise SourceError(f"{SOURCES[name]['label']} answered HTTP {resp.status_code}")
    return _body(resp), (resp.headers.get("ETag") or "")[:200], (resp.headers.get("Last-Modified") or "")[:100]


def fetch_pages(name, get=None, max_pages=60):
    """The items of a paged API source (EUVD, VulnCheck), every page."""
    headers = {"Accept": "application/json"}
    if name == "vulncheck_kev":
        headers["Authorization"] = f"Bearer {os.environ.get('CVENGINE_VULNCHECK_API_KEY', '')}"
    items, page = [], 0 if name == "euvd" else 1
    for _ in range(max_pages):
        resp = _get(SOURCES[name]["url"].format(page=page), headers, get)
        if resp.status_code != 200:
            resp.close()
            raise SourceError(f"{SOURCES[name]['label']} answered HTTP {resp.status_code}")
        doc = json.loads(_body(resp))
        batch = (doc.get("items") if name == "euvd" else doc.get("data")) or []
        items += batch
        if name == "euvd":
            if not batch or len(items) >= int(doc.get("total") or 0):
                break
        elif page >= int((doc.get("_meta") or {}).get("total_pages") or 1):
            break
        page += 1
    return items


# ----------------------------------------------------------------------------- normalizers: {CVE id: small detail}

def parse_cisa_kev(raw):
    out = {}
    for v in json.loads(raw).get("vulnerabilities") or []:
        cve = str(v.get("cveID") or "").strip().upper()
        if CVE_RE.match(cve):
            out[cve] = {"added": _date(v.get("dateAdded")), "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                        "name": _clean(v.get("vulnerabilityName"), 200), "vendor": _clean(v.get("vendorProject"), 100),
                        "product": _clean(v.get("product"), 100)}
    return out


def parse_euvd(items):
    out = {}
    for item in items:
        for cve in CVE_IN_TEXT.findall(str(item.get("aliases") or "")):
            out[cve.upper()] = {"since": _date(item.get("exploitedSince")), "euvd": _clean(item.get("id"), 40)}
    return out


def parse_vulncheck(items):
    out = {}
    for item in items:
        for cve in item.get("cve") or []:
            cve = str(cve).strip().upper()
            if CVE_RE.match(cve):
                out[cve] = {"added": _date(item.get("date_added")),
                            "ransomware": str(item.get("knownRansomwareCampaignUse") or "") == "Known"}
    return out


def _gunzip(raw, limit):
    """Decompress a gzip body, refusing one that expands past ``limit`` bytes (a few KB can claim many GB)."""
    stream = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = stream.decompress(raw, limit + 1)
    if len(out) > limit or stream.unconsumed_tail:
        raise SourceError("the feed expands past the size limit")
    return out


def parse_epss(raw):
    out = {}
    text = _gunzip(raw, MAX_DECOMPRESSED).decode("utf-8", "replace")
    for line in text.splitlines():
        if not line.startswith("CVE-"):
            continue  # the model-version comment and the header
        cve, _, rest = line.partition(",")
        score, _, pct = rest.partition(",")
        try:
            out[cve.upper()] = [round(float(score), 5), round(float(pct), 5)]
        except ValueError:
            continue
    return out


def parse_exploit_db(raw):
    import csv
    out = {}
    for row in csv.DictReader(io.StringIO(raw.decode("utf-8", "replace"))):
        for cve in CVE_IN_TEXT.findall(row.get("codes") or ""):
            ids = out.setdefault(cve.upper(), [])
            if len(ids) < 10 and row.get("id"):
                ids.append(_clean(row["id"], 12))
    return out


def parse_metasploit(raw):
    out = {}
    for module in (json.loads(raw) or {}).values():
        if not isinstance(module, dict):
            continue
        for ref in module.get("references") or []:
            if CVE_RE.match(str(ref).upper()):
                names = out.setdefault(str(ref).upper(), [])
                if len(names) < 5 and module.get("fullname"):
                    names.append(_clean(module["fullname"], 150))
    return out


PARSERS = {"cisa_kev": parse_cisa_kev, "epss": parse_epss, "exploit_db": parse_exploit_db, "metasploit": parse_metasploit}
PAGED = {"euvd": parse_euvd, "vulncheck_kev": parse_vulncheck}


def refresh_source(name, now, get=None):
    """Bring one source's normalized data up to date on disk when it is due. Returns ``(data, changed)``; the data is the cached
    copy when the source is not due, unchanged, or failed (the failure is recorded on the IntelSource row)."""
    from cveFeed.models import IntelSource
    row, _ = IntelSource.objects.get_or_create(name=name)
    path = os.path.join(cache_dir(), f"{name}.json")
    cached = None
    if os.path.exists(path):
        try:
            with open(path) as fh:
                cached = json.load(fh)
        except (OSError, ValueError):
            cached = None
    if cached is not None and row.last_checked and row.last_checked > now - SOURCES[name]["every"]:
        return cached, False
    try:
        if name in PAGED:
            data, etag, modified = PAGED[name](fetch_pages(name, get=get)), "", ""
        else:
            raw, etag, modified = fetch_file(name, row.etag if cached is not None else "", row.last_modified if cached is not None else "", get)
            if raw is None:
                row.last_checked, row.last_error = now, ""
                row.save(update_fields=["last_checked", "last_error"])
                return cached, False
            data = PARSERS[name](raw)
        if not data:
            raise SourceError(f"{SOURCES[name]['label']} returned no CVEs")
        if cached and len(data) < len(cached) * 0.5:
            raise SourceError(f"{SOURCES[name]['label']} lists {len(data)} CVEs against {len(cached)} before; treated as truncated")
    except Exception as exc:  # noqa: BLE001 - one source failing must not stop the others; the cached copy stays in use
        row.last_checked, row.last_error = now, _clean(f"{type(exc).__name__}: {exc}", 300)
        row.save(update_fields=["last_checked", "last_error"])
        logger.warning("threat intel %s: %s", name, exc)
        return cached, False
    tmp = path + ".partial"
    with open(tmp, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)
    changed = data != cached
    row.etag, row.last_modified, row.last_checked, row.last_error, row.cves = etag, modified, now, "", len(data)
    if changed:
        row.last_changed = now
    row.save()
    return data, changed


# ----------------------------------------------------------------------------- reconciling

def intel_for(cve, data):
    """The per-source detail of one CVE across the loaded sources (only what they say about it)."""
    out = {}
    kev = {name: data[name][cve] for name in KEV_SOURCES if cve in (data.get(name) or {})}
    if kev:
        out["kev"] = kev
    epss = (data.get("epss") or {}).get(cve)
    if epss:
        out["epss"] = {"score": epss[0], "percentile": epss[1]}
    exploits = {name: data[name][cve] for name in EXPLOIT_SOURCES if cve in (data.get(name) or {})}
    if exploits:
        out["exploits"] = exploits
    return out


def merged_flags(feed, intel):
    """(kev, epss_reached, exploit_db) from cve.now's exploitation block and the CVE's intel. A source only adds evidence;
    EPSS, when it scores the CVE, is today's value."""
    feed = feed if isinstance(feed, dict) else {}
    intel = intel if isinstance(intel, dict) else {}
    kev = True if intel.get("kev") else feed.get("kev")
    exploit_db = True if intel.get("exploits") else (None if feed.get("exploitDb") is None else bool(feed.get("exploitDb")))
    epss = intel.get("epss")
    epss_reached = (epss["score"] >= EPSS_THRESHOLD) if epss else feed.get("epssReached")
    return kev, epss_reached, exploit_db


def reconcile(data, since=None, now=None, chunk=2000):
    """Bring every stored CVE's intel and signals in line with the sources (only CVEs created after ``since`` when given).
    Returns (rows updated, CVE ids whose signals changed)."""
    from cveFeed.models import CVEEntry
    now = now or timezone.now()
    qs = CVEEntry.objects.order_by("id")
    if since:
        qs = qs.filter(created_at__gte=since)
    updated, changed_ids, last = 0, [], 0
    while True:
        rows = list(qs.filter(id__gt=last).values("id", "cve_id", "kev", "epss_reached", "exploit_db", "intel")[:chunk])
        if not rows:
            return updated, changed_ids
        last = rows[-1]["id"]
        batch = []
        for r in rows:
            intel = intel_for(r["cve_id"].upper(), data)
            # the stored flags are what cve.now last said (from_api writes them), so they are the baseline the sources add to
            kev, epss_reached, exploit_db = merged_flags({"kev": r["kev"], "epssReached": r["epss_reached"], "exploitDb": r["exploit_db"]}, intel)
            flags_moved = (kev, epss_reached, exploit_db) != (r["kev"], r["epss_reached"], r["exploit_db"])
            if not flags_moved and intel == (r["intel"] or {}):
                continue
            entry = CVEEntry(id=r["id"], intel=intel, kev=kev, epss_reached=epss_reached, exploit_db=exploit_db, synced_at=now)
            entry.flags_moved = flags_moved
            batch.append(entry)
        # synced_at moves only with the signals: it keys the correlation pool's cache, which holds them
        moved = [e for e in batch if e.flags_moved]
        CVEEntry.objects.bulk_update(moved, ["intel", "kev", "epss_reached", "exploit_db", "synced_at"], batch_size=500)
        CVEEntry.objects.bulk_update([e for e in batch if not e.flags_moved], ["intel"], batch_size=500)
        updated += len(batch)
        changed_ids += [e.id for e in moved]


# ----------------------------------------------------------------------------- importing CVEs the feed never delivered

def import_candidates(data):
    """CVE ids the sources care about, most important first, without duplicates."""
    groups = [g.strip() for g in os.environ.get("CVENGINE_INTEL_IMPORT", ",".join(IMPORT_GROUPS)).split(",") if g.strip()]
    ordered = []
    for group in groups:
        if group == "kev":
            ids = [c for name in KEV_SOURCES for c in (data.get(name) or {})]
        elif group == "epss":
            ids = [c for c, (score, _pct) in sorted((data.get("epss") or {}).items(), key=lambda kv: -kv[1][0]) if score >= EPSS_THRESHOLD]
        elif group in ("metasploit", "exploit_db"):
            ids = list(data.get(group) or {})
        else:
            continue
        ordered += ids
    return list(dict.fromkeys(c for c in ordered if CVE_RE.match(c)))


def cve5_url(cve):
    _, year, number = cve.split("-")
    return CVE5_URL.format(year=year, bucket=int(number) // 1000, cve=cve)


def fetch_cve5(cve, get=None):
    """The CVE List V5 record, None when it does not exist (404)."""
    resp = _get(cve5_url(cve), {"Accept": "application/json"}, get)
    if resp.status_code == 404:
        resp.close()
        return None
    if resp.status_code != 200:
        resp.close()
        raise SourceError(f"CVE List answered HTTP {resp.status_code} for {cve}")
    return json.loads(_body(resp))


_VERSIONISH = re.compile(r"^[0-9][0-9A-Za-z._+~:-]*$")
_PREFIX = re.compile(r"^(?:version|ver\.?|v)\s*(?=\d)", re.I)
_LEADING = re.compile(r"^([0-9][0-9A-Za-z._+~:-]*)\s+\S")


def _bound(value):
    """``(version, exact)`` for a range bound, or ``(None, False)`` ("*", "unspecified", "n/a", a product name). "Ver2.20" is
    2.20; "8.00 Update 5" is 8.00, not exact: the text after the number is a finer release than a version can say."""
    value = _PREFIX.sub("", str(value or "").strip())
    if _VERSIONISH.match(value):
        return value, True
    found = _LEADING.match(value)
    return (found.group(1), False) if found else (None, False)


_WILDCARD = re.compile(r"^(?:version|ver\.?|v)?\s*(?:(\d+(?:\.\d+)*)\.(?:x|\*)|(\d+(?:\.\d+)+)\*)$", re.I)


def _wildcard_base(value):
    """"2.3.x" or "2.3.*" -> "2.3" (the branch a wildcard names), else None. Juniper writes "21.1*", which is the same branch."""
    found = _WILDCARD.match(str(value or "").strip())
    return (found.group(1) or found.group(2)) if found else None


def _next_branch(base):
    """"2.3" -> "2.4": the first version after every release of branch ``base``."""
    parts = base.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


_VER = r"v?(\d[0-9A-Za-z.+~-]*)"
# a dash is a range only between two dotted versions and with spaces around a plain hyphen: "2.4.1-1" is a Debian-style revision and
# "4.0.0-beta-1" a pre-release, not the range 2.4.1 to 1
_VERD = r"v?(\d+\.[0-9A-Za-z.+~-]*)"
_TEXT_RANGES = (
    (re.compile(rf"^{_VER}\s*(?:through|thru|to)\s*{_VER}$", re.I), lambda m: {"introduced": m.group(1), "lastAffected": m.group(2)}),
    (re.compile(rf"^{_VERD}(?:\s+-\s+|\s*[\u2013\u2014]\s*){_VERD}$", re.I), lambda m: {"introduced": m.group(1), "lastAffected": m.group(2)}),
    (re.compile(rf"^{_VER}\s*(?:and|or)\s*(?:earlier|prior|below|before|lower|older)$", re.I), lambda m: {"lastAffected": m.group(1)}),
    (re.compile(rf"^{_VER}\s*(?:and|or)\s*(?:later|above|newer|higher|after)$|^{_VER}\+$", re.I),
     lambda m: {"introduced": m.group(1) or m.group(2)}),
    (re.compile(rf"^(?:before|prior to|earlier than|older than|<)\s*{_VER}$", re.I), lambda m: {"fixed": m.group(1)}),
    (re.compile(rf"^(?:through|up to and including|<=)\s*{_VER}$", re.I), lambda m: {"lastAffected": m.group(1)}),
    (re.compile(rf"^>=?\s*{_VER}\s*,?\s*(?:and\s*)?<\s*{_VER}$", re.I), lambda m: {"introduced": m.group(1), "fixed": m.group(2)}),
    (re.compile(rf"^>=?\s*{_VER}\s*,?\s*(?:and\s*)?<=\s*{_VER}$", re.I), lambda m: {"introduced": m.group(1), "lastAffected": m.group(2)}),
)


def _text_range(value):
    """``{introduced?, fixed?, lastAffected?}`` for a version written as a range ("2.0 through 2.3", "before 1.5", "3.1 and earlier"), else
    None. CVE List records often put the range in the ``version`` text; reading only its first number turns "2.0 through 2.3" into the
    single version 2.0, which misses every host on 2.1 to 2.3."""
    text = re.sub(r"\s+", " ", str(value or "").strip())
    for pattern, build in _TEXT_RANGES:
        found = pattern.match(text)
        if found:
            return {k: v for k, v in build(found).items() if v}
    return None


def _unaffected_interval(v):
    """``(low, high)`` of an ``unaffected`` version entry as a half-open interval of releases (``low`` None from the first release, ``high`` None
    to the end), or False when the entry is a shape that cannot be read exactly (one exact version, an inclusive upper bound): a hole of one
    release cannot be written as a range, and guessing it would either hide an affected release or flag a fixed one."""
    start = _bound(v.get("version"))[0] if v.get("version") not in (None, "*") else None
    start = None if start in (None, "0", "0.0", "0.0.0") else start
    upper = v.get("lessThan")
    if upper in (None, ""):
        return False  # a single unaffected version, or a bound that is "through": not expressible
    if str(upper).strip() == "*":
        return start, None
    branch = _wildcard_base(upper)
    if branch:  # "2.426.*": every release of the 2.426 line, so the interval ends where the next line begins
        return start, _next_branch(branch)
    bound, exact = _bound(upper)
    return (start, bound) if bound and exact else False


def _default_affected_ranges(entry, kind):
    """Ranges for a CVE 5 entry whose ``defaultStatus`` is ``affected`` and whose ``versions`` list only the releases that are NOT (Jenkins'
    CVE-2024-23897: unaffected below 1.606, from 2.426.3 to the end of the 2.426 line, from 2.440.1 to the end of 2.440, from 2.442 on). The
    affected releases are what lies between those intervals. Read only when every unaffected entry is an interval that can be written exactly;
    otherwise nothing is guessed and the entry yields no ranges, as before."""
    from cveFeed.correlation import parse_version
    versions = [v for v in entry.get("versions") or [] if isinstance(v, dict) and v.get("status") == "unaffected"]
    if str(entry.get("defaultStatus") or "").lower() != "affected" or not versions:
        return []
    intervals = [_unaffected_interval(v) for v in versions]
    if not all(intervals):
        return []

    def key(value):
        return parse_version(value, strict=True) if value else ()
    if any(value and key(value) is None for low, high in intervals for value in (low, high)):
        return []
    intervals.sort(key=lambda i: key(i[0]))
    out, cursor = [], None  # cursor: the first release not yet accounted for (None: from the start)
    for low, high in intervals:
        if key(low) > key(cursor):
            out.append({"type": kind, **({"introduced": cursor} if cursor else {}), "fixed": low})
        if high is None:
            return out  # the rest of the releases are unaffected
        if key(high) > key(cursor):
            cursor = high
    out.append({"type": kind, "introduced": cursor})  # everything after the last unaffected interval
    return out


# what a feed writes for a bound it does not state
_PLACEHOLDERS = frozenset({"unspecified", "unknown", "n/a", "none"})
_ZERO = ("", "*", "0", "0.0", "0.0.0")
_SERVICE_BASE = re.compile(r"^(\d+\.\d+R\d+)-S\d+")  # Junos: 22.3R3-S1 is a service release of the release 22.3R3
_COMMA_VERSION = re.compile(r"^(\d+),(\d+)$")  # a typo the record of CVE-2023-36845 has: the branch "23,2"
_RANGE_BOUNDS = ("introduced", "fixed", "lastAffected")


def _placeholder(value):
    return str(value or "").strip().lower() in _PLACEHOLDERS


def _version_text(value):
    return _COMMA_VERSION.sub(r"\1.\2", str(value or "").strip())


def _cmp(a, b):
    """-1, 0 or 1 for two version texts, None when either is not a version."""
    from cveFeed.correlation import _vcmp, parse_version
    left, right = parse_version(a, strict=True), parse_version(b, strict=True)
    return None if left is None or right is None else _vcmp(left, right)


def _in_branch(version, base):
    """Whether ``version`` is a release of the branch ``base`` ("21.1" and "21.1R3" are in "21.1")."""
    from cveFeed.correlation import parse_version
    low, branch = parse_version(version, strict=True), parse_version(base, strict=True)
    return bool(low and branch and low[:len(branch)] == branch)


def _upper_split(start, value, start_readable=True):
    """The ranges one upper bound text stands for when it is not a plain version, as ``[{introduced?, fixed}]``; None when it is plain.

    * A wildcard that names the branch ``start`` is in ("21.1" below "21.1*", Juniper's way of saying every 21.1 release) is that whole
      branch: from ``start`` to where the next branch begins. Before this it read as "fixed 21.1", an empty range.
    * A comma list of fixes ("22.3R2-S2, 22.3R3-S1") is read as Juniper writes it: nothing before the oldest fix is safe, and a fix that is a
      service release (22.3R3-S1) leaves its own release (22.3R3) exposed up to it. Anything older than the oldest fix is the part that is
      certain; for a list that cannot be read exactly (or a lower bound that cannot) there is no range at all, never an open one."""
    text = str(value or "").strip()
    if "," in text:
        bounds = [_bound(part.strip()) for part in text.split(",") if part.strip()]
        if len(bounds) < 2 or not start_readable or not all(bound and exact for bound, exact in bounds) or any(_cmp(b, b) is None for b, _ in bounds):
            return []
        fixes = sorted({bound for bound, _exact in bounds}, key=cmp_to_key(lambda x, y: _cmp(x, y)))
        if start and _cmp(fixes[0], start) != 1:
            return []
        out = [{**({"introduced": start} if start else {}), "fixed": fixes[0]}]
        for later in fixes[1:]:
            release = _SERVICE_BASE.match(later)
            if release and _cmp(release.group(1), fixes[0]) == 1 and (not start or _cmp(release.group(1), start) == 1):
                out.append({"introduced": release.group(1), "fixed": later})
        return out
    branch = _wildcard_base(text)
    if branch and start and _in_branch(start, branch):
        return [{"introduced": start, "fixed": _next_branch(branch)}]
    return None


def _join_split_branches(versions):
    """CVE 5 ``versions`` with each branch the record wrote as two entries made one. Atlassian writes a branch as ``{version: 7.13.0,
    lessThan: unspecified}`` followed by ``{version: unspecified, lessThan: 7.13.7}`` (Confluence, CVE-2022-26134): read alone the first is
    "7.13.0 and every later release" and the second "everything before 7.13.7", so the fixed releases between them read as exposed. Joined
    they are the branch 7.13.0 to 7.13.7. Only that exact pair is joined, and only when the fix is newer than the start."""
    out, i = [], 0
    versions = list(versions)
    while i < len(versions):
        a = versions[i]
        b = versions[i + 1] if i + 1 < len(versions) else None
        if (isinstance(a, dict) and isinstance(b, dict) and a.get("status") == "affected" == b.get("status")
                and _placeholder(a.get("lessThan")) and not a.get("lessThanOrEqual") and not a.get("changes")
                and a.get("version") and not _placeholder(a["version"]) and _bound(a["version"])[1]
                and _placeholder(b.get("version")) and b.get("lessThan") and not _placeholder(b["lessThan"])
                and not b.get("lessThanOrEqual") and not b.get("changes")
                and _cmp(b["lessThan"], a["version"]) == 1):
            out.append({**a, "lessThan": b["lessThan"]})
            i += 2
            continue
        out.append(a)
        i += 1
    return out


def _joined_feed_ranges(ranges):
    """The ``ranges`` of a cve.now entry with each ``{introduced: X, fixed: unspecified}`` followed by ``{introduced: unspecified, fixed: Y}``
    made one range {X, Y}: the same branch written as two (see ``_join_split_branches``), which is how cve.now carries the CVE List's."""
    out, i = [], 0
    while i < len(ranges):
        a = ranges[i]
        b = ranges[i + 1] if i + 1 < len(ranges) else None
        if (isinstance(a, dict) and isinstance(b, dict) and _placeholder(a.get("fixed")) and not a.get("lastAffected")
                and a.get("introduced") and not _placeholder(a["introduced"]) and _bound(a["introduced"])[1]
                and _placeholder(b.get("introduced")) and b.get("fixed") and not _placeholder(b["fixed"]) and not b.get("lastAffected")
                and a.get("type") == b.get("type") and _cmp(b["fixed"], a["introduced"]) == 1):
            out.append({**a, "fixed": b["fixed"]})
            i += 2
            continue
        out.append(a)
        i += 1
    return out


def _normalized_range(rng):
    """The ranges one cve.now range stands for: a bound the feed marks "unspecified" is no bound, and an upper bound that is a wildcard branch
    or a comma list of fixes is read as ``_upper_split`` reads it. A range that has nothing readable left is dropped."""
    if not isinstance(rng, dict):
        return [rng]
    clean = {k: v for k, v in rng.items() if not (k in _RANGE_BOUNDS and _placeholder(v))}
    start, upper = _version_text(clean["introduced"]) if clean.get("introduced") else None, clean.get("fixed")
    if upper and not clean.get("lastAffected"):
        start_text = start if start and _bound(start)[1] and _bound(start)[0] not in _ZERO else None
        split = _upper_split(start_text, upper, bool(start_text) or str(start or "").strip() in _ZERO)
        if split is not None:
            rest = {k: v for k, v in clean.items() if k not in ("introduced", "fixed")}
            return [{**rest, **piece} for piece in split]
    if clean != rng and not any(_cmp(clean[k], clean[k]) is not None for k in _RANGE_BOUNDS if clean.get(k)):
        return []
    return [clean]


def normalize_feed_ranges(affected):
    """cve.now's ``affected`` with the ranges its CVE List source gave in the forms correlation cannot read made readable: the two halves of a
    branch joined (Confluence CVE-2022-26134: ``{introduced 7.13.0, fixed unspecified}`` and ``{introduced unspecified, fixed 7.13.7}``),
    "unspecified" taken away, Junos' ``21.1*`` made the 21.1 branch and its comma lists of fixes made one range per release train. Entries
    with none of these are returned as they were."""
    out = []
    for item in affected or []:
        ranges = item.get("ranges") if isinstance(item, dict) else None
        if isinstance(ranges, list) and ranges:
            new = [r for rng in _joined_feed_ranges(ranges) for r in _normalized_range(rng)][:100]
            if new != ranges:
                item = {**item, "ranges": new}
        out.append(item)
    return out


def keep_published_ranges(affected, stored):
    """``affected`` (what cve.now says now) with every block that states no range given the ranges the stored CVE List record had for the same
    product. An empty block says nothing, so a refresh must not replace the CVE List's ranges with it (Jenkins, CVE-2024-23897: the feed's
    Jenkins block has none, next to OSV blocks that do). A block with ranges of its own is never touched."""
    from cveFeed.correlation import affected_product_tokens
    out = list(affected or [])
    for i, item in enumerate(out):
        if not isinstance(item, dict) or item.get("ranges") or not (item.get("product") or item.get("package")):
            continue
        wanted = affected_product_tokens(item)
        old = next((o for o in stored or [] if isinstance(o, dict) and o.get("ranges") and wanted & affected_product_tokens(o)), None)
        if wanted and old:
            out[i] = {**item, "ranges": old["ranges"]}
    return out


def _ranges(entry):
    """CVE 5 ``versions`` entries -> correlation ranges ({introduced, fixed | lastAffected}), split at ``changes``. An upper
    bound that is not an exact version ("below 8.00 Update 5") becomes lastAffected 8.00, so the base release still counts."""
    out = []
    kind0 = "GIT" if any(str(v.get("versionType") or "").lower() == "git" for v in entry.get("versions") or [] if isinstance(v, dict)) else "SEMVER"
    out += _default_affected_ranges(entry, kind0)
    for v in _join_split_branches(entry.get("versions") or []):
        if not isinstance(v, dict) or v.get("status") != "affected":
            continue
        kind = "GIT" if str(v.get("versionType") or "").lower() == "git" else "SEMVER"
        textual = _text_range(v.get("version")) if not (v.get("lessThan") or v.get("lessThanOrEqual")) else None
        if textual:  # the range is written in the version field itself
            out.append({"type": kind, **textual})
            continue
        version_text = _version_text(v.get("version"))
        branch = _wildcard_base(version_text)  # "2.3.x": every release of 2.3 (a wildcard is not a version bound)
        start = branch or _bound(version_text)[0]
        start = None if start in ("0", "0.0", "0.0.0") else start
        if v.get("lessThan") and not v.get("changes"):
            split = _upper_split(start, v["lessThan"], bool(start) or version_text in _ZERO or _placeholder(version_text))
            if split is not None:  # a wildcard branch or a comma list of fixes: one range per release train, never an open one
                out += [{"type": kind, **piece} for piece in split]
                continue
        upper = {}
        if v.get("lessThan"):
            below = _wildcard_base(v.get("lessThan"))
            bound, exact = (below, True) if below else _bound(v.get("lessThan"))
            if bound:
                upper = {"fixed": bound} if exact else {"lastAffected": bound}
        elif v.get("lessThanOrEqual"):
            through = _wildcard_base(v.get("lessThanOrEqual"))
            bound, _exact = _bound(v.get("lessThanOrEqual"))
            if through:  # "<= 2.3.x" ends after the last 2.3 release
                upper = {"fixed": _next_branch(through)}
            elif bound:
                upper = {"lastAffected": bound}
        if not v.get("lessThan") and not v.get("lessThanOrEqual"):
            if branch:
                out.append({"type": kind, "introduced": branch, "fixed": _next_branch(branch)})
            elif start:  # one exact version
                out.append({"type": kind, "introduced": start, "lastAffected": start})
            continue
        affected, seg_start = True, start
        changes = [c for c in v.get("changes") or [] if isinstance(c, dict) and _bound(c.get("at"))[1]]
        for change in sorted(changes, key=lambda c: [int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+]", _bound(c["at"])[0])]):
            at = _bound(change["at"])[0]
            if change.get("status") == "unaffected" and affected:
                out.append({k: x for k, x in {"type": kind, "introduced": seg_start, "fixed": at}.items() if x})
                affected = False
            elif change.get("status") == "affected" and not affected:
                seg_start, affected = at, True
        if affected and (seg_start or upper):
            out.append({k: x for k, x in {"type": kind, "introduced": seg_start, **upper}.items() if x})
    return out[:30]


def uses_default_status(entries):
    """Whether any ``affected`` block of a CVE List record states its releases as the unaffected intervals of a ``defaultStatus: affected``
    product (Jenkins), the shape ``_default_affected_ranges`` reads: what a run counts, so the shape can be sized (camstork, issue 210)."""
    return any(isinstance(e, dict) and _default_affected_ranges(e, "SEMVER") for e in entries or [])


def convert_affected(entries):
    """CVE 5 ``affected`` -> the cve.now shape correlation reads: [{vendor, product, package?, ranges}]."""
    from cveFeed.correlation import parse_cpe
    out = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        item = {k: _clean(entry.get(k), 200) for k in ("vendor", "product") if entry.get(k) and str(entry.get(k)).lower() != "n/a"}
        package = entry.get("packageName")
        if not package:  # a CPE names the product the way nmap does ("log4j" for "Apache Log4j2")
            package = next((p[1] for p in (parse_cpe(c) for c in entry.get("cpes") or []) if p and p[1] and p[1] != "*"), "")
        if package:
            item["package"] = _clean(package, 200)
        item["ranges"] = _ranges(entry)
        if item.get("product") or item.get("package"):
            out.append(item)
    return out[:50]


def overlay_branch_ranges(cve_id, affected, get=None):
    """``(affected, overlaid)``: where a feed gave an advisory as a bare list of fixes with no lower bounds (cve.now's PHP2Shell: fixed
    8.2.35, 8.3.36, 8.4.27, 8.5.12), read the bounds the CNA published in the CVE List V5 record (``version: 8.2.*, lessThan: 8.2.35``
    per branch, which ``convert_affected`` turns into introduced and fixed). Nothing is inferred: the ranges are the CNA's own, taken only
    for an entry that names the same product and only when every one of its ranges has both bounds. A record that cannot be read, or has
    no such entry, leaves the feed's ranges as they were; correlation then compares each fix only with its own line of releases."""
    from cveFeed.correlation import affected_product_tokens, fix_only_branch_list
    targets = [i for i, item in enumerate(affected) if fix_only_branch_list([r for r in (item.get("ranges") or []) if isinstance(r, dict)])]
    if not targets:
        return affected, False
    try:
        doc = fetch_cve5(cve_id, get=get)
    except Exception as exc:  # noqa: BLE001 - the feed's own ranges stand; the next refresh asks again
        logger.info("CVE List record of %s not read for its branch bounds: %s", cve_id, exc)
        return affected, False
    containers = (doc or {}).get("containers") or {}
    cna = containers.get("cna") or {}
    published = convert_affected(cna.get("affected")) + convert_affected(
        [a for adp in containers.get("adp") or [] if isinstance(adp, dict) for a in adp.get("affected") or []])
    out, overlaid = list(affected), False
    for i in targets:
        wanted = affected_product_tokens(affected[i])
        for item in published:
            ranges = item.get("ranges") or []
            if (wanted & affected_product_tokens(item) and len(ranges) >= 2 and all(r.get("introduced") and r.get("fixed") for r in ranges)):
                out[i] = {**affected[i], "ranges": ranges}
                overlaid = True
                break
    return out, overlaid


CVSS_PREFERENCE = ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0")


def _metric(containers):
    """The best score any container carries: the newest scoring system first (3.1, 3.0, 4.0, then the obsolete 2.0), and within one system
    the CNA's before the ADPs'. A CNA that only published a CVSS 2.0 score does not outrank an ADP's 3.1 score."""
    for key in CVSS_PREFERENCE:
        for container in containers:
            for metric in container.get("metrics") or []:
                m = metric.get(key) if isinstance(metric, dict) else None
                if isinstance(m, dict) and isinstance(m.get("baseScore"), (int, float)):
                    return float(m["baseScore"]), _clean(m.get("vectorString"), 128), _clean(m.get("baseSeverity"), 32)
    return None, "", ""


def entry_from_cve5(doc, intel):
    """CVEEntry field values from a CVE List V5 record, or None for a record that is not published (rejected, reserved)."""
    meta = doc.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return None
    containers = doc.get("containers") or {}
    cna, adps = containers.get("cna") or {}, [a for a in containers.get("adp") or [] if isinstance(a, dict)]
    description = next((d.get("value") for d in cna.get("descriptions") or [] if str(d.get("lang", "")).startswith("en")), "")
    kev_name = next((k.get("name") for k in (intel.get("kev") or {}).values() if isinstance(k, dict) and k.get("name")), "")
    cvss, vector, severity = _metric([cna, *adps])
    affected = convert_affected(cna.get("affected"))
    if not any(item["ranges"] for item in affected):  # CISA's ADP enrichment often carries the CPE ranges the CNA left out
        affected += convert_affected([a for adp in adps for a in adp.get("affected") or []])
    from cveFeed.models import _feed_time
    published = _feed_time(meta.get("datePublished"))
    return {"title": _clean(cna.get("title") or kev_name or description[:150], 500), "original_description": _clean(description, 20000),
            "cvss": cvss, "cvss_vector": vector, "stated_severity": severity, "affected": affected,
            "references": [r["url"] for r in cna.get("references") or [] if isinstance(r, dict) and str(r.get("url", "")).startswith("http")][:60],
            "status": "PUBLISHED", "published_at": published, "first_seen_at": published}


LAST_IMPORT = {"default_status": 0}  # what the last import_missing saw: records whose affected releases come from default-status ranges


def import_missing(data, limit, now=None, get=None, workers=8):
    """Create up to ``limit`` CVEEntry rows for CVEs the sources name that are not stored. Returns the new rows."""
    from django.core.cache import cache

    from cveFeed.models import CVEEntry
    LAST_IMPORT["default_status"] = 0
    candidates, missing = import_candidates(data), []
    for start in range(0, len(candidates), 2000):
        chunk = candidates[start:start + 2000]
        known = set(CVEEntry.objects.filter(cve_id__in=chunk).values_list("cve_id", flat=True))
        missing += [c for c in chunk if c not in known and not cache.get(f"cvengine:intel-skip:{c}")]
        if len(missing) >= limit:
            break
    missing = missing[:limit]
    if not missing:
        return []

    def load(cve):
        try:
            return cve, fetch_cve5(cve, get=get), None
        except Exception as exc:  # noqa: BLE001 - retried next run
            return cve, None, exc
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fetched = list(pool.map(load, missing))
    labels = {name: SOURCES[name]["label"] for name in SOURCES}
    created = []
    for cve, doc, error in fetched:
        if error is not None:
            logger.warning("threat intel: could not read the CVE List record of %s: %s", cve, error)
            continue
        intel = intel_for(cve, data)
        fields = entry_from_cve5(doc, intel) if doc else None
        if fields is None:  # no record, rejected or reserved: do not ask again for a week
            cache.set(f"cvengine:intel-skip:{cve}", 1, 7 * 86400)
            continue
        if uses_default_status(((doc.get("containers") or {}).get("cna") or {}).get("affected")):
            LAST_IMPORT["default_status"] += 1
        kev, epss_reached, exploit_db = merged_flags({}, intel)
        sources = ["CVE List V5"] + [labels[n] for group in ("kev", "exploits") for n in intel.get(group, {})] + (["FIRST EPSS"] if intel.get("epss") else [])
        obj, made = CVEEntry.objects.get_or_create(cve_id=cve, defaults={**fields, "intel": intel, "kev": kev, "epss_reached": epss_reached,
                                                                         "exploit_db": exploit_db, "sources": sources})
        if made:
            created.append(obj)
    return created


# ----------------------------------------------------------------------------- repairing stored ranges

RANGES_MARKER = "_ranges_repair"  # the IntelSource row whose ``cves`` is the id the repair has reached and ``last_changed`` when it began
# the stored entries whose ranges an older conversion may have got wrong: one imported from the CVE List before the current conversion
# existed, one with a block that states no range (Jenkins, issue 210), one in a form the feed's ranges were not read in ("unspecified" bounds,
# a Junos wildcard branch or comma list of fixes: issue 205)
_REPAIR_SQL = """(
    (sources->0 = '"CVE List V5"'::jsonb AND created_at < %s)
    OR jsonb_path_exists(affected, '$[*] ? (@.ranges.size() == 0)')
    OR jsonb_path_exists(affected, '$[*].ranges[*] ? (@.fixed like_regex "^unspecified$" flag "i" || @.introduced like_regex "^unspecified$" flag "i"
        || @.fixed like_regex "[*,]" || @.introduced like_regex "[,]")')
)"""


def repair_ranges(limit=200, get=None, workers=8, scan=1000, now=None):
    """Re-derive the ranges of stored entries an older conversion got wrong. Returns the counts of one bounded run.

    Resumable: it walks the entries in id order from where the last run stopped (the cursor is the ``_ranges_repair`` IntelSource row) and
    reads the CVE List record of at most ``limit`` of them per run, so it can be called every hour until the table is done, and ``--reset`` of
    ``manage.py repair_cve_ranges`` starts it again.

      * a range in a form cve.now passes on from the CVE List that correlation cannot read is rewritten from the stored data alone (no request)
      * an entry the CVE List import created before the current conversion is re-derived from its record
      * a block with no range of an entry whose record states its releases as the unaffected ranges of a default-affected product (Jenkins)
        takes the ranges the record gives
    An entry that changes is marked for re-correlation and its cached match verdicts are dropped, as a cve.now refresh does."""
    from cveFeed.models import CVEEntry, IntelSource, MatchVerdict
    from django.core.cache import cache
    now = now or timezone.now()
    marker, created = IntelSource.objects.get_or_create(name=RANGES_MARKER)
    if created or not marker.last_changed:
        marker.last_changed = now
        marker.save(update_fields=["last_changed"])
    out = {"scanned": 0, "examined": 0, "normalized": 0, "repaired": 0, "failed": 0}
    rows = list(CVEEntry.objects.extra(where=[_REPAIR_SQL], params=[marker.last_changed]).filter(pk__gt=marker.cves).order_by("pk")[:max(1, scan)])
    plan, last, fetches = [], marker.cves, 0
    for row in rows:
        affected = normalize_feed_ranges(row.affected)
        empty = any(isinstance(i, dict) and not i.get("ranges") and (i.get("product") or i.get("package")) for i in affected)
        reimport = bool(row.sources) and row.sources[0] == "CVE List V5" and row.created_at < marker.last_changed
        if empty or reimport:
            if fetches >= limit:
                break
            fetches += 1
        plan.append((row, affected, empty, reimport))
        last = row.pk

    def load(row):
        try:
            return fetch_cve5(row.cve_id, get=get), None
        except Exception as exc:  # noqa: BLE001 - asked again by a later run
            return None, exc
    wanted = [row for row, _a, empty, reimport in plan if empty or reimport]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        records = dict(zip((r.pk for r in wanted), pool.map(load, wanted)))
    hold = None
    for row, affected, empty, reimport in plan:
        out["scanned"] += 1
        new, from_record = affected, False
        if row.pk in records:
            out["examined"] += 1
            doc, error = records[row.pk]
            if error is not None:
                out["failed"] += 1
                key = f"cvengine:ranges-repair:{row.cve_id}"
                tries = (cache.get(key) or 0) + 1
                cache.set(key, tries, 86400)
                if tries < 3:  # held at this entry for the next run; a third failure lets the run pass it
                    hold = row.pk - 1 if hold is None else min(hold, row.pk - 1)
                logger.warning("ranges repair: could not read the CVE List record of %s: %s", row.cve_id, error)
            else:
                fields = entry_from_cve5(doc, {}) if doc else None
                if fields:
                    published = fields["affected"]
                    cna = ((doc.get("containers") or {}).get("cna") or {})
                    if reimport and any(i.get("ranges") for i in published):
                        new, from_record = published, True
                    elif empty and uses_default_status(cna.get("affected")):
                        new, from_record = keep_published_ranges(affected, published), True
        if new != row.affected:
            sources = list(row.sources or [])
            if from_record and "CVE List V5" not in sources:
                sources.append("CVE List V5")
            CVEEntry.objects.filter(pk=row.pk).update(affected=new, sources=sources, needs_recorrelation=True)
            MatchVerdict.objects.filter(cve_entry_id=row.pk).delete()
            out["repaired" if from_record else "normalized"] += 1
    marker.cves = max(marker.cves, min(last, hold) if hold is not None else last)
    marker.last_checked = now
    marker.save(update_fields=["cves", "last_checked"])
    return out


# ----------------------------------------------------------------------------- one run

def run(now=None, get=None):
    """Refresh the due sources, reconcile the stored CVEs, import the missing ones. Returns a summary dict."""
    from cveFeed.models import IntelSource
    now = now or timezone.now()
    names = enabled_sources()
    if not names:
        return {"status": "disabled"}
    data, any_changed, errors = {}, False, {}
    for name in names:
        loaded, changed = refresh_source(name, now, get=get)
        if loaded:
            data[name] = loaded
        any_changed |= changed
        err = IntelSource.objects.filter(name=name).values_list("last_error", flat=True).first()
        if err:
            errors[name] = err
    marker, _ = IntelSource.objects.get_or_create(name="_reconcile")
    since = None if (any_changed or not marker.last_checked) else marker.last_checked - timedelta(minutes=5)
    updated, changed_ids = reconcile(data, since=since, now=now)
    marker.last_checked = now
    marker.save(update_fields=["last_checked"])
    created = import_missing(data, _int_env("CVENGINE_INTEL_IMPORT_PER_RUN", 2000, 0, 20000), now=now, get=get)
    repaired = {}
    per_run = _int_env("CVENGINE_RANGE_REPAIR_PER_RUN", 200, 0, 5000)
    if per_run:  # a bounded step of the repair of stored ranges (0 turns it off); it never stops the rest of the run
        try:
            repaired = repair_ranges(per_run, get=get, now=now)
        except Exception as exc:  # noqa: BLE001
            logger.warning("threat intel: ranges repair failed: %s", exc)
    if LAST_IMPORT["default_status"]:
        logger.info("threat intel: %s of the %s imported CVE records state their affected releases as unaffected ranges of a default-affected "
                    "product (defaultStatus), which are now read as the releases between those ranges", LAST_IMPORT["default_status"], len(created))
    return {"sources": {n: len(data.get(n) or {}) for n in names}, "errors": errors, "reconciled": updated,
            "signals_changed": changed_ids, "imported": created, "default_status_records": LAST_IMPORT["default_status"],
            "ranges_repaired": repaired.get("repaired", 0) + repaired.get("normalized", 0)}
