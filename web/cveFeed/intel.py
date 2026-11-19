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
import time
from concurrent.futures import ThreadPoolExecutor
from functools import cmp_to_key
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")  # the CVE JSON 5 schema allows up to 19 digits; a cap of 7 would cut an id short
CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,19}(?!\d)", re.I)
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


class TransientSourceError(SourceError):
    """A source answer worth asking again: rate limited (429, or GitHub's 403 with a rate-limit reply), a server error, or a cut
    connection. ``retry_after`` is the wait the source asked for, in seconds, when it said one."""
    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


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


CISA_KEV_COMPLETE = 1000  # a CISA KEV catalog read with fewer entries than this is not taken as the whole list (it holds about 1,500)


def kev_removed(stored_intel, data):
    """Whether a CVE stored as known exploited because CISA listed it has left CISA's catalog: the catalog was read whole this run
    (``CISA_KEV_COMPLETE``), the stored detail shows CISA listed it before, and the catalog does not list it now. Anything less certain (a
    flag only cve.now gave, a catalog that did not load) keeps the flag."""
    listed = ((stored_intel or {}).get("kev") or {}) if isinstance(stored_intel, dict) else {}
    catalog = data.get("cisa_kev") or {}
    return "cisa_kev" in listed and len(catalog) >= CISA_KEV_COMPLETE


def merged_flags(feed, intel):
    """(kev, epss_reached, exploit_db) from cve.now's exploitation block and the CVE's intel. A source only adds evidence;
    EPSS, when it scores the CVE, is today's value."""
    from cveFeed.cve_now import exploitation_flags
    feed = exploitation_flags(feed)  # each signal is an object or null in cve.now's answers since 2026-11: a flag here
    intel = intel if isinstance(intel, dict) else {}
    kev = True if intel.get("kev") else feed.get("kev")
    exploit_db = True if intel.get("exploits") else (None if feed.get("exploitDb") is None else bool(feed.get("exploitDb")))
    epss = intel.get("epss")
    epss_reached = (epss["score"] >= EPSS_THRESHOLD) if epss else feed.get("epssReached")
    return kev, epss_reached, exploit_db


def reconcile(data, since=None, now=None, chunk=2000, turned_hot=None):
    """Bring every stored CVE's intel and signals in line with the sources (only CVEs created after ``since`` when given).
    Returns (rows updated, CVE ids whose signals changed). ``turned_hot``, a list when given, receives the ids of the CVEs that were neither on
    the KEV nor exploited and now are (``threat.is_hot``): their proven matches turn fire (``notify.cves_turned_hot``)."""
    from cveFeed.threat import is_hot
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
            if kev and not intel.get("kev") and kev_removed(r["intel"], data):
                kev = False  # CISA took it off its catalog, which listed it before, and no other source lists it: the flag stood on that listing
            flags_moved = (kev, epss_reached, exploit_db) != (r["kev"], r["epss_reached"], r["exploit_db"])
            if not flags_moved and intel == (r["intel"] or {}):
                continue
            entry = CVEEntry(id=r["id"], intel=intel, kev=kev, epss_reached=epss_reached, exploit_db=exploit_db, synced_at=now)
            entry.flags_moved = flags_moved
            batch.append(entry)
            if turned_hot is not None and is_hot(kev, exploit_db) and not is_hot(r["kev"], r["exploit_db"]):
                turned_hot.append(r["id"])
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
        status, wait = resp.status_code, _retry_after(resp)
        resp.close()
        if status in (403, 408, 425, 429) or status >= 500:
            raise TransientSourceError(f"CVE List answered HTTP {status} for {cve}", retry_after=wait)
        raise SourceError(f"CVE List answered HTTP {status} for {cve}")
    return json.loads(_body(resp))


def _retry_after(resp):
    """The seconds a ``Retry-After`` header asks for (a number only; an HTTP date is ignored), capped at a minute, or None."""
    try:
        value = float((getattr(resp, "headers", None) or {}).get("Retry-After") or "")
    except (TypeError, ValueError):
        return None
    return max(0.0, min(value, 60.0))


FETCH_WAITS = (2, 8, 30)  # seconds before each new try of a record whose read failed for a reason that passes (rate limit, server error)
_sleep = time.sleep  # replaced in tests


def _transient(exc):
    """Whether a failed read is worth trying again: a rate limit or server error, or a connection that failed or was cut."""
    if isinstance(exc, TransientSourceError):
        return True
    try:
        import requests
    except ImportError:  # pragma: no cover
        return False
    return isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.ChunkedEncodingError))


def fetch_cve5_patiently(cve, get=None, waits=None):
    """``fetch_cve5`` that asks again after a read that failed for a reason that passes, waiting ``FETCH_WAITS`` (longer when the source
    asked for longer with ``Retry-After``). An error that will not pass (a record over the size limit, a body that is not JSON, another HTTP
    status) is raised at once, and so is the last transient error once the waits are used up."""
    waits = FETCH_WAITS if waits is None else waits
    for attempt in range(len(waits) + 1):
        try:
            return fetch_cve5(cve, get=get)
        except Exception as exc:  # noqa: BLE001 - re-raised below unless it passes
            if attempt >= len(waits) or not _transient(exc):
                raise
            _sleep(max(waits[attempt], getattr(exc, "retry_after", None) or 0))


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
    # PHP's "7.2.x below 7.2.30" and "7.1.x < 7.1.30": the line, up to the fix
    (re.compile(rf"^(\d+(?:\.\d+)*)\.(?:x|\*)\s*(?:below|before|prior to|earlier than|<)\s*{_VER}$", re.I),
     lambda m: {"introduced": m.group(1), "fixed": m.group(2)}),
    # GitHub's advisories: "= 1.54.0" is that one release
    (re.compile(rf"^=\s*{_VER}$", re.I), lambda m: {"introduced": m.group(1), "lastAffected": m.group(1)}),
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
    release cannot be written as a range, and guessing it would either hide an affected release or flag a fixed one.

    The Linux kernel CNA writes its fixed releases as inclusive wildcards: ``{version: 6.1.117, lessThanOrEqual: 6.1.*}`` is every 6.1 release
    from 6.1.117 on, so the interval ends where 6.2 begins, and ``{version: 6.13, lessThanOrEqual: *}`` is every release from 6.13 on. An
    inclusive bound that is one exact version stays unreadable."""
    start = _bound(v.get("version"))[0] if v.get("version") not in (None, "*") else None
    start = None if start in (None, "0", "0.0", "0.0.0") else start
    upper = v.get("lessThan")
    through = v.get("lessThanOrEqual")
    if upper in (None, "") and through not in (None, ""):
        if str(through).strip() == "*":
            return start, None
        branch = _wildcard_base(through)
        if not branch or (start and _cmp(start, _next_branch(branch)) != -1):
            return False  # "through 2.3.1" (one release more than a half-open interval says), or a branch that ends before it starts
        return start, _next_branch(branch)
    if upper in (None, ""):
        return False  # a single unaffected version: not expressible
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


# a bound that is a distribution package build, not an upstream release: an rpm epoch ("0:8.7p1-38.el9_4.4"), Red Hat's and Fedora's dist tags,
# Debian's and Ubuntu's revisions ("1:9.2p1-2+deb12u3", "8.9p1-3ubuntu0.10"), Amazon Linux's
_DISTRO_EVR_RE = re.compile(r"^\d+:\S|[.-](?:el|fc|amzn|module\+el)\d|ubuntu\d|[+~]deb\d|\+b\d+$", re.IGNORECASE)
DISTRO_RANGE_TYPES = {"rpm": "RPM", "deb": "DEB", "dpkg": "DEB", "debian": "DEB"}  # CVE 5 versionType values of distribution package builds


def _distro_evr(value):
    return bool(value) and isinstance(value, str) and bool(_DISTRO_EVR_RE.search(value.strip()))


def _distro_typed(rng):
    """A range whose bounds are distribution package builds is typed ``RPM`` (or ``DEB``), which correlation never compares with an upstream
    version (``version_in_range`` reads only SEMVER and ECOSYSTEM): read as upstream, "0:8.7p1-38.el9_4.4" put every RHEL 9 OpenSSH 8.7 in
    range. The distribution's own data (cveFeed.distro_sync) decides those hosts."""
    if not isinstance(rng, dict) or str(rng.get("type") or "SEMVER").upper() not in ("SEMVER", "ECOSYSTEM"):
        return rng
    bounds = [str(rng.get(k)) for k in _RANGE_BOUNDS if rng.get(k) and str(rng.get(k)) not in _ZERO]
    if bounds and any(_distro_evr(b) for b in bounds):
        return {**rng, "type": "DEB" if any(re.search(r"ubuntu|deb\d|\+b\d", b, re.I) for b in bounds) else "RPM"}
    return rng


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
            new = [_distro_typed(r) for r in new]
            if new != ranges:
                item = {**item, "ranges": new}
        out.append(item)
    return out


def keep_published_ranges(affected, stored):
    """``affected`` (what cve.now says now) with every block that states no range given the ranges the stored CVE List record had for the same
    product. An empty block says nothing, so a refresh must not replace the CVE List's ranges with it (Jenkins, CVE-2024-23897: the feed's
    Jenkins block has none, next to OSV blocks that do). A block with ranges of its own is never touched.

    A block that lists bare ``versions`` takes them only from the same stored block (the same vendor, product, package and ``versions``), the
    one ``overlay_from_record`` gave the record's ranges: the kernel CNA's records give cve.now two "Linux" blocks, one of git commits and one
    that lists releases, and the second must get back its release ranges, never the first one's commits. When the feed's list changed, the
    block has none and the record is read again."""
    from cveFeed.correlation import affected_product_tokens
    out = list(affected or [])
    for i, item in enumerate(out):
        if not isinstance(item, dict) or not (item.get("product") or item.get("package")):
            continue
        wanted = affected_product_tokens(item)
        if not wanted:
            continue
        if not item.get("ranges"):
            bare = _bare_versions_block(item)
            old = next((o for o in stored or [] if isinstance(o, dict) and o.get("ranges") and wanted & affected_product_tokens(o)
                        and (not bare or _same_block(item, o))), None)
            if old:
                item = out[i] = {**item, "ranges": old["ranges"], **({"reading": old["reading"]} if old.get("reading") else {})}
        if not item.get("builds"):  # the exact builds only the CVE List record lists (Cisco): a feed that does not carry them keeps them
            old = next((o for o in stored or [] if isinstance(o, dict) and o.get("builds") and wanted & affected_product_tokens(o)
                        and _same_vendor(item, o)), None)
            if old:
                out[i] = {**item, "builds": old["builds"]}
    return out


def _same_block(a, b):
    """Two affected blocks with the same vendor, product, package and bare ``versions`` list (one block of the feed, stored and refreshed)."""
    return all((a.get(k) or None) == (b.get(k) or None) for k in ("vendor", "product", "package", "versions"))


def _same_vendor(a, b):
    """Two affected blocks that do not name different vendors (either may name none)."""
    from cveFeed.correlation import _norm
    left, right = _norm(a.get("vendor"), True), _norm(b.get("vendor"), True)
    return not left or not right or left in right or right in left


def _ranges(entry):
    """CVE 5 ``versions`` entries -> correlation ranges ({introduced, fixed | lastAffected}), split at ``changes``. An upper
    bound that is not an exact version ("below 8.00 Update 5") becomes lastAffected 8.00, so the base release still counts. At most 30: a
    record that lists its builds one by one (Cisco) keeps the whole list in the entry's ``builds`` (``_exact_builds``)."""
    out = []
    kind0 = "GIT" if any(str(v.get("versionType") or "").lower() == "git" for v in entry.get("versions") or [] if isinstance(v, dict)) else "SEMVER"
    out += _default_affected_ranges(entry, kind0)
    default_read = bool(out)
    for v in _join_split_branches(entry.get("versions") or []):
        if not isinstance(v, dict) or v.get("status") != "affected":
            continue
        if default_read and not (v.get("lessThan") or v.get("lessThanOrEqual") or v.get("changes")):
            # in a ``defaultStatus: affected`` entry read above, a bare affected version is where the flaw began (the kernel CNA's "5.2"),
            # already inside the ranges: read as one exact version it would only add a range of a single release
            continue
        kind = "GIT" if str(v.get("versionType") or "").lower() == "git" else DISTRO_RANGE_TYPES.get(str(v.get("versionType") or "").lower(), "SEMVER")
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
        # an upper bound that was written but cannot be read ("Apache HTTP Server 2.4*", "publication": issue 696) ends nowhere: the range is
        # left out rather than made open, so every later release is never "in range". Only "*" says the range is open on purpose
        if affected and (seg_start or upper) and (upper or _open_upper(v)):
            out.append({k: x for k, x in {"type": kind, "introduced": seg_start, **upper}.items() if x})
    return [_distro_typed(r) for r in out[:30]]


def _open_upper(v):
    """Whether a CVE 5 ``versions`` entry's upper bound is readable as "no upper bound": none is written, or it is "*"."""
    upper = v.get("lessThan") or v.get("lessThanOrEqual")
    return not upper or str(upper).strip() == "*"


def _unreadable_upper(v):
    """Whether a CVE 5 ``versions`` entry states an upper bound that cannot be read as a version (issue 696)."""
    upper = v.get("lessThan") or v.get("lessThanOrEqual")
    if not upper or _open_upper(v) or _wildcard_base(upper):
        return False
    return not _bound(upper)[0]


def _exact_builds(entry):
    """Every exact build a CVE 5 entry lists as affected (a ``versions`` entry with no upper bound, no wildcard and no range in its text), each as
    ``correlation.build_key`` writes it, in the record's order. Cisco lists every affected build this way (CVE-2023-20109: 674 IOS builds such
    as "15.2(4)M7", 364 IOS XE builds such as "17.9.4a"): a parenthesised build cannot be a range bound and the ranges keep 30, so these are
    the only complete statement of what the advisory covers."""
    from cveFeed.correlation import MAX_BUILDS_PER_ITEM, build_key
    if _default_affected_ranges(entry, "SEMVER"):
        return []  # a bare version of a default-affected entry is where the flaw began (the kernel CNA's "5.2"), not one affected build
    out = []
    for v in _join_split_branches(entry.get("versions") or []):
        if not isinstance(v, dict) or v.get("status") != "affected" or v.get("lessThan") or v.get("lessThanOrEqual") or v.get("changes"):
            continue
        if str(v.get("versionType") or "").lower() == "git":
            continue
        text = _version_text(v.get("version"))
        if _placeholder(text) or text in _ZERO or _text_range(text) or _wildcard_base(text):
            continue
        key = build_key(text)
        if key:
            out.append(key)
    return list(dict.fromkeys(out))[:MAX_BUILDS_PER_ITEM]


def _builds_beyond(ranges, builds):
    """``builds`` when the ranges do not already carry every one of them (a parenthesised build is never a range, and the ranges stop at 30),
    else []: an entry whose few exact versions all fit in its ranges is stored as it always was."""
    from cveFeed.correlation import _exact_single, build_key
    kept = {build_key(r["introduced"]) for r in ranges if _exact_single(r)}
    return builds if set(builds) - kept else []


def uses_default_status(entries):
    """Whether any ``affected`` block of a CVE List record states its releases as the unaffected intervals of a ``defaultStatus: affected``
    product (Jenkins), the shape ``_default_affected_ranges`` reads: what a run counts, so the shape can be sized (camstork, issue 210)."""
    return any(isinstance(e, dict) and _default_affected_ranges(e, "SEMVER") for e in entries or [])


ORACLE_READING = "oracle_supported_versions"  # the ``reading`` of a block whose ranges ``_oracle_line_ranges`` gave


def _is_oracle(entry, assigner):
    """Whether a block follows Oracle's Critical Patch Update convention: the record is Oracle's (``assigner`` "oracle", or not known) and the
    block names Oracle as the vendor."""
    from cveFeed.correlation import _norm
    if assigner and str(assigner).strip().lower() != "oracle":
        return False
    return _norm(entry.get("vendor")).startswith("oracle")


def _oracle_line_ranges(entry):
    """The ranges of an Oracle block that lists only plain exact versions, read as Oracle writes them, or None for any other block.

    Oracle's Critical Patch Update records say "Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, ..." and
    list each as one exact version. It means every supported release of that line up to and including that one: Java 17.0.10 is affected by
    CVE-2026-114938, not only 17.0.21. So each release line becomes one range, from the start of the line to the highest version listed in it
    (``lastAffected``). The line of a Java runtime is its feature release (8, 17, 21), with Oracle's spellings read as the runtime reads them
    (8u511b33-perf is 8.0.511, 17.0.21.0.3 is Oracle's build of 17.0.21); for any other product it is the first two numbers of a version of
    three or more (WebLogic 12.2.1.4.0: 12.2, GraalVM Enterprise 21.3.20.0.3: 21.3) and the first of a two-part one (PeopleTools 8.61: 8).
    A block with any other bound (``lessThan``, ``lessThanOrEqual``, as MySQL's are written), a version that is one number ("Solaris 11") or
    that cannot be read is left to ``_ranges`` as before. Every range has both bounds: never an unbounded match."""
    from cveFeed.correlation import parse_version
    versions = [v for v in entry.get("versions") or [] if isinstance(v, dict)]
    if not versions or str(entry.get("defaultStatus") or "").lower() == "affected":
        return None
    runtime = None
    lines = {}
    for v in versions:
        if (v.get("status") != "affected" or v.get("lessThan") or v.get("lessThanOrEqual") or v.get("changes")
                or str(v.get("versionType") or "").lower() == "git"):
            return None
        text = _version_text(v.get("version"))
        if _placeholder(text) or text in _ZERO or _text_range(text) or _wildcard_base(text):
            return None
        if runtime is None:
            from cveFeed import java_runtime
            runtime = java_runtime.is_runtime_item(entry)
        if runtime:
            from cvengine_scanner import java
            norm = java.normalize_version(text)
            if not norm or norm["line_only"]:
                return None
            key, start, top = ("java", norm["major"]), f"{norm['major']}.0.0", java.dotted(text)
        else:
            bound, exact = _bound(text)
            parts = parse_version(bound, strict=True) if bound and exact else None
            if not parts or len(parts) < 2:
                return None
            line = parts[:2] if len(parts) >= 3 else parts[:1]
            key, start, top = line, ".".join(map(str, line)) + ".0", bound
        if parse_version(top, strict=True) is None:
            return None
        if key not in lines or _cmp(top, lines[key][1]) == 1:
            lines[key] = (start, top)
    return [{"type": "SEMVER", "introduced": start, "lastAffected": top} for start, top in lines.values()]


def _without_product_name(entry):
    """``entry`` with each version text that repeats the product's name in front of the version read as the version alone. Apache's records
    write "Apache HTTP Server 2.4.49" (CVE-2021-42013) and "Apache HTTP Server 2.4 2.4.49" (CVE-2021-41773: the line, then the release),
    which read as no version at all. A text is changed only when what follows the product's own name is one exact version or a written range
    ("2.4.0 to 2.4.37"), after a line it belongs to or not; anything else is left as it was."""
    product = re.sub(r"\s+", " ", str(entry.get("product") or "").strip()).lower()
    versions = entry.get("versions")
    if len(product) < 3 or not isinstance(versions, list):
        return entry
    out, changed = [], False
    for v in versions:
        text = re.sub(r"\s+", " ", v["version"].strip()) if isinstance(v, dict) and isinstance(v.get("version"), str) else ""
        if text.lower().startswith(product + " "):
            rest = text[len(product) + 1:]
            line, _, after = rest.partition(" ")
            first = (_text_range(after) or {}).get("introduced") or after
            if after and _bound(line)[1] and _bound(first)[1] and _in_branch(first, line):
                rest = after  # "2.4 2.4.49", "2.4 2.4.17 to 2.4.48": the line Apache names first, then the release or the range
            if (_bound(rest)[1] and _cmp(rest, rest) is not None) or _text_range(rest):
                v, changed = {**v, "version": rest}, True
        out.append(v)
    return {**entry, "versions": out} if changed else entry


_LLAMACPP_TAG = re.compile(r"(?<![0-9A-Za-z])b(\d{1,6})(?:-[0-9a-f]{4,40})?(?![0-9A-Za-z.])")


def _llamacpp_builds(entry):
    """``entry`` with each llama.cpp build tag in its version texts read as the build number ("< b5662" -> "< 5662", ``lessThan: b5662`` ->
    ``5662``), for an entry that names llama.cpp only (``correlation.is_llamacpp``): its releases are builds, and a tag is no version anywhere
    else. Any other entry, and any other text, is returned as it was."""
    from cveFeed.correlation import is_llamacpp
    versions = entry.get("versions")
    if not isinstance(versions, list) or not is_llamacpp(entry):
        return entry

    def read(text):
        if not isinstance(text, str):
            return text
        return _LLAMACPP_TAG.sub(lambda m: m.group(1) if int(m.group(1)) > 0 else m.group(0), text)
    out = []
    for v in versions:
        if isinstance(v, dict):
            v = {**v, **{k: read(v[k]) for k in ("version", "lessThan", "lessThanOrEqual") if k in v}}
            if isinstance(v.get("changes"), list):
                v["changes"] = [{**c, "at": read(c.get("at"))} if isinstance(c, dict) else c for c in v["changes"]]
        out.append(v)
    return {**entry, "versions": out}


def convert_affected(entries, assigner=""):
    """CVE 5 ``affected`` -> the cve.now shape correlation reads: [{vendor, product, package?, ranges, builds?}]. ``assigner`` is the
    record's ``assignerShortName``: an Oracle record's exact versions are read as Oracle means them (``_oracle_line_ranges``)."""
    from cveFeed.correlation import parse_cpe
    out = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        entry = _llamacpp_builds(_without_product_name(entry))
        item = {k: _clean(entry.get(k), 200) for k in ("vendor", "product") if entry.get(k) and str(entry.get(k)).lower() != "n/a"}
        package = entry.get("packageName")
        if not package:  # a CPE names the product the way nmap does ("log4j" for "Apache Log4j2")
            package = next((p[1] for p in (parse_cpe(c) for c in entry.get("cpes") or []) if p and p[1] and p[1] != "*"), "")
        if package:
            item["package"] = _clean(package, 200)
        oracle = _oracle_line_ranges(entry) if _is_oracle(entry, assigner) else None
        if oracle:
            item["ranges"] = oracle
            item["reading"] = ORACLE_READING  # says the ranges are Oracle's convention read, not versions the record wrote as bounds
            if item.get("product") or item.get("package"):
                out.append(item)
            continue
        item["ranges"] = _ranges(entry)
        builds = _builds_beyond(item["ranges"], _exact_builds(entry))
        if builds:  # the whole list of exact builds (correlation.item_verdict compares a version with it)
            item["builds"] = builds
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


# vendors whose CVE List records state their affected releases as a list of exact versions, which cve.now passes on as ``versions`` with no range
# (Cisco: every affected build; Oracle: the supported versions of each line, see ``_oracle_line_ranges``)
EXACT_LIST_VENDORS = ("cisco", "oracle")


def _exact_list_block(item):
    """A cve.now block of an ``EXACT_LIST_VENDORS`` vendor that lists ``versions`` and no range: the record's exact versions were not read."""
    from cveFeed.correlation import _norm
    vendor = _norm(item.get("vendor")) if isinstance(item, dict) else ""
    return (bool(vendor) and vendor.startswith(EXACT_LIST_VENDORS) and not item.get("ranges") and not item.get("builds")
            and isinstance(item.get("versions"), list) and any(isinstance(v, str) and v.strip() for v in item["versions"]))


_HASHLIKE = re.compile(r"^[0-9a-f]{7,40}$", re.I)  # a commit, never a version bound (an abbreviated hash can be all digits)
_DASHED_PAIR = re.compile(r"^v?\d+(?:\.\d+)+-v?\d+(?:\.\d+)+$")  # "1.0.0-2.2.0": two releases or one with a revision; which is not known


def _bare_versions_block(item):
    """A cve.now block that states no range and lists bare ``versions``: what the CVE List record said was passed on without its bounds."""
    return (isinstance(item, dict) and not item.get("ranges") and not item.get("builds") and isinstance(item.get("versions"), list)
            and any(isinstance(v, str) and v.strip() for v in item["versions"]))


def _readable_version(text, zero_ok=False):
    """Whether a CVE 5 version text is one exact version (or, with ``zero_ok``, a placeholder or zero that means "from the first release")."""
    text = _version_text(text)
    if zero_ok and (text in _ZERO or _placeholder(text)):
        return True
    return (bool(text) and not _HASHLIKE.match(text) and not _DASHED_PAIR.match(text) and _bound(text)[1]
            and _cmp(text, text) is not None)


def _sound_entry(entry):
    """Whether every ``versions`` entry of one CVE 5 entry can be read exactly, so the ranges ``convert_affected`` gives it say what the CNA
    wrote and nothing more. Not sound: any git commit (the kernel CNA's git entry: a hash is never a version bound), a version that is a
    product's name ("10 Version 1607 for 32-bit Systems", Microsoft's records before 2021) or any other text that is not a version, an upper
    bound that is open or not a version, and a ``defaultStatus: affected`` entry whose unaffected releases cannot be read as intervals (then
    every release counts as affected: an unbounded reading, never made into a range)."""
    versions = [v for v in entry.get("versions") or [] if isinstance(v, dict)]
    if not versions or any(str(v.get("versionType") or "").lower() == "git" for v in versions):
        return False
    if str(entry.get("defaultStatus") or "").lower() == "affected" and not _default_affected_ranges(entry, "SEMVER"):
        return False
    for v in _join_split_branches(versions):
        if v.get("status") != "affected":
            continue
        upper = v.get("lessThan") or v.get("lessThanOrEqual")
        if upper:
            start = v.get("version")
            if not (_wildcard_base(upper) or _readable_version(upper)) or not (_wildcard_base(start) or _readable_version(start, True)):
                return False
        elif not (_text_range(v.get("version")) or _wildcard_base(v.get("version")) or _readable_version(v.get("version"))):
            return False
    return True


def _sound_ranges(ranges):
    """Ranges that each have an upper bound and only version bounds: never an open range, never a commit read as a version."""
    return bool(ranges) and all(
        str(r.get("type") or "SEMVER").upper() in ("SEMVER", "ECOSYSTEM") and (r.get("fixed") or r.get("lastAffected"))
        and all(not _HASHLIKE.match(str(r[k])) and _cmp(r[k], r[k]) is not None for k in _RANGE_BOUNDS if r.get(k))
        for r in ranges)


def _listed_text(value):
    """A version text as cve.now and the CVE List both write it: spaces collapsed, GitHub's "= 1.54.0" as "1.54.0" (the feed drops the "=")."""
    return re.sub(r"^=\s*", "", re.sub(r"\s+", " ", str(value or "").strip()))


def record_ranges_for(item, entries, assigner=""):
    """``{ranges, builds?}`` the CVE List record states for one cve.now block that lists bare ``versions``, or None.

    The block is found in the record by its product, its vendor and its versions: the record's entry must list every version the feed passed
    on (the kernel CNA writes two "Linux" entries, git commits and releases; only the release entry lists the feed's "2.6.26"). Exactly one
    entry must match, every one of its versions must be readable (``_sound_entry``) and every range ``convert_affected`` gives it must have an
    upper bound (``_sound_ranges``). Otherwise the block is left as it is, with no range: the feed's list alone means nothing certain (the
    kernel's list is where the flaw began, not the releases it affects), so no range is ever made from it."""
    from cveFeed.correlation import affected_product_tokens
    wanted = affected_product_tokens(item)
    listed = {_listed_text(v) for v in item.get("versions") or [] if isinstance(v, str) and v.strip()}
    if not wanted or not listed:
        return None
    same = [e for e in entries or [] if isinstance(e, dict) and wanted & affected_product_tokens(e) and _same_vendor(item, e)
            and listed <= {_listed_text(v.get("version")) for v in e.get("versions") or [] if isinstance(v, dict)}]
    if len(same) != 1 or not _sound_entry(_llamacpp_builds(_without_product_name(same[0]))):
        return None
    converted = convert_affected(same, assigner)
    if len(converted) != 1 or not _sound_ranges(converted[0].get("ranges")):
        return None
    return {k: converted[0][k] for k in ("ranges", "builds", "reading") if converted[0].get(k)}


def overlay_from_record(affected, doc):
    """``(affected, overlaid)``: each block of ``affected`` that lists bare ``versions`` and no range, given the ranges the CVE List V5 record
    ``doc`` states for it. Cisco's and Oracle's blocks take the ranges and builds of the record's block of the same product (their exact lists
    are read by ``convert_affected``: every Cisco build, Oracle's supported versions per line); every other block takes only what
    ``record_ranges_for`` finds sound. A record that is not published changes nothing."""
    from cveFeed.correlation import affected_product_tokens
    targets = [i for i, item in enumerate(affected or []) if _bare_versions_block(item)]
    fields = entry_from_cve5(doc, {}) if targets and isinstance(doc, dict) else None
    if not fields:
        return affected, False
    published = fields.get("affected") or []
    assigner = (doc.get("cveMetadata") or {}).get("assignerShortName") or ""
    entries = ((doc.get("containers") or {}).get("cna") or {}).get("affected") or []
    out, overlaid = list(affected), False
    for i in targets:
        if _exact_list_block(out[i]):
            wanted = affected_product_tokens(out[i])
            match = next((p for p in published if (p.get("ranges") or p.get("builds")) and wanted & affected_product_tokens(p)
                          and _same_vendor(out[i], p)), None)
        else:
            match = record_ranges_for(out[i], entries, assigner)
        if match:
            out[i] = {**out[i], **{k: match[k] for k in ("ranges", "builds", "reading") if match.get(k)}}
            overlaid = True
    return out, overlaid


def overlay_exact_versions(cve_id, affected, get=None):
    """``(affected, overlaid)``: a cve.now block that carries the record's versions only as a bare ``versions`` list (no range) takes the
    ranges the CVE List V5 record states for it (``overlay_from_record``). cve.now cannot say whether a ``versions`` entry had an upper bound
    (a Linux block lists the release each flaw began in the same way), so nothing is read from that list itself. A record that cannot be read
    leaves the feed's blocks as they were (CVE-2026-114938, Oracle Java SE: stored with no range); a later refresh or the backfill
    (``backfill_bare_versions``) asks again."""
    if not any(_bare_versions_block(item) for item in affected or []):
        return affected, False
    try:
        doc = fetch_cve5(cve_id, get=get)
    except Exception as exc:  # noqa: BLE001 - the feed's blocks stand; a later refresh or the backfill asks again
        logger.info("CVE List record of %s not read for its bare versions: %s", cve_id, exc)
        return affected, False
    return overlay_from_record(affected, doc) if doc else (affected, False)


# ----------------------------------------------------------------------------- open ranges from an unreadable upper bound (issue 696)

def _open_range(rng):
    """A comparable range with a lower bound and no upper one: every release from ``introduced`` on is in it."""
    return (isinstance(rng, dict) and str(rng.get("type") or "SEMVER").upper() in ("SEMVER", "ECOSYSTEM") and rng.get("introduced")
            and not rng.get("fixed") and not rng.get("lastAffected"))


def _record_block(item):
    """A cve.now block taken from a CVE List record (a vendor's product), not an ecosystem package's (OSV's open ranges are meant open)."""
    return isinstance(item, dict) and bool(item.get("product")) and not item.get("package") and not item.get("ecosystem")


def _unchecked_open(item):
    """The lower bounds of ``item``'s open ranges that no reading of its CVE List record has accounted for yet."""
    if not _record_block(item):
        return []
    seen = set(item.get("open_checked") or []) | set(item.get("upper_unreadable") or [])
    return [r["introduced"] for r in item.get("ranges") or [] if _open_range(r) and r["introduced"] not in seen]


def keep_open_checks(affected, stored):
    """``affected`` (what cve.now says now) with what an earlier reading of the CVE List record found about each block's open ranges
    (``close_open_ranges``) carried over from the same stored block: a range whose upper bound the record writes as text is left out again
    without a request, and a range the record means open is not asked about again."""
    from cveFeed.correlation import affected_product_tokens
    out = list(affected or [])
    for i, item in enumerate(out):
        if not _record_block(item):
            continue
        wanted = affected_product_tokens(item)
        old = next((o for o in stored or [] if _record_block(o) and (o.get("open_checked") or o.get("upper_unreadable"))
                    and wanted & affected_product_tokens(o) and _same_vendor(item, o)), None)
        if not old:
            continue
        dropped = set(old.get("upper_unreadable") or [])
        out[i] = {**item, "ranges": [r for r in item.get("ranges") or [] if not (_open_range(r) and r["introduced"] in dropped)],
                  **{k: old[k] for k in ("open_checked", "upper_unreadable") if old.get(k)}}
    return out


def close_open_ranges(affected, doc):
    """``(affected, changed)``: each open range of a CVE List block (``_open_range``) checked against the record ``doc``. When the record's entry
    for that product writes the upper bound of the version the range starts at as text that is no version ("Apache HTTP Server 2.4*" in
    CVE-2021-44224, "Apache APISIX 1.5*" in CVE-2021-43557), cve.now passed it on as an open range, and every later release would be "in
    range": the range is left out and its lower bound kept in the block's ``upper_unreadable`` (the block then has no usable bound for it:
    version unknown, never a match on its own). A range the record means open ("*", or no upper bound) is noted in ``open_checked`` so it is
    not asked about again. ``changed`` is True when a range was left out."""
    from cveFeed.correlation import affected_product_tokens, parse_version
    if not isinstance(doc, dict) or not any(_unchecked_open(item) for item in affected or []):
        return affected, False
    entries = ((doc.get("containers") or {}).get("cna") or {}).get("affected") or []
    out, changed = list(affected), False
    for i, item in enumerate(out):
        starts = _unchecked_open(item)
        if not starts:
            continue
        wanted = affected_product_tokens(item)
        unreadable, readable = set(), set()
        for entry in entries:
            if not isinstance(entry, dict) or not (wanted & affected_product_tokens(entry)) or not _same_vendor(item, entry):
                continue
            entry = _without_product_name(entry)
            for v in entry.get("versions") or []:
                if not isinstance(v, dict) or v.get("status") != "affected":
                    continue
                text = _version_text(v.get("version"))
                start = _wildcard_base(text) or _bound(text)[0]
                if not start:
                    continue
                (unreadable if _unreadable_upper(v) else readable).add(parse_version(start, strict=True) or start)
        drop = [s for s in starts if (parse_version(s, strict=True) or s) in unreadable and (parse_version(s, strict=True) or s) not in readable]
        keep = [s for s in starts if s not in drop]
        item = {**item}
        if drop:
            item["ranges"] = [r for r in item.get("ranges") or [] if not (_open_range(r) and r["introduced"] in drop)]
            item["upper_unreadable"] = sorted(set(item.get("upper_unreadable") or []) | set(drop))[:50]
            changed = True
        if keep:
            item["open_checked"] = sorted(set(item.get("open_checked") or []) | set(keep))[:50]
        out[i] = item
    return out, changed


def overlay_open_ranges(cve_id, affected, get=None):
    """``(affected, changed)``: ``close_open_ranges`` with the CVE List record of ``cve_id`` read when a block has an open range no earlier reading
    accounted for. A record that cannot be read leaves the blocks as they were (a later refresh or the ``open-ranges`` walk asks again)."""
    if not str(cve_id or "").upper().startswith("CVE-") or not any(_unchecked_open(item) for item in affected or []):
        return affected, False
    try:
        doc = fetch_cve5(cve_id, get=get)
    except Exception as exc:  # noqa: BLE001 - the feed's blocks stand; a later refresh or the walk asks again
        logger.info("CVE List record of %s not read for its open ranges: %s", cve_id, exc)
        return affected, False
    return close_open_ranges(affected, doc) if doc else (affected, False)


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
    assigner = meta.get("assignerShortName") or ""
    affected = convert_affected(cna.get("affected"), assigner)
    if not any(item["ranges"] or item.get("builds") for item in affected):  # CISA's ADP enrichment often carries the CPE ranges the CNA left out
        affected += convert_affected([a for adp in adps for a in adp.get("affected") or []], assigner)
    from cveFeed import range_corrections
    affected, _corrected = range_corrections.apply(meta.get("cveId"), affected)  # a sourced correction of a too-narrow bound
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
    OR jsonb_path_exists(affected, '$[*] ? (@.ranges.size() == 0 && !exists(@.builds))')
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
    from cveFeed import range_corrections
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
        empty = any(isinstance(i, dict) and not i.get("ranges") and not i.get("builds") and (i.get("product") or i.get("package")) for i in affected)
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
                    if empty:  # a block the feed passed on as bare ``versions`` takes what the record states for it, when that is sound
                        new, bare = overlay_from_record(new, doc)
                        from_record = from_record or bare
        new, _corrected = range_corrections.apply(row.cve_id, new)  # a sourced correction of a too-narrow bound stays applied
        if new != row.affected:
            sources = list(row.sources or [])
            if from_record and "CVE List V5" not in sources:
                sources.append("CVE List V5")
            CVEEntry.objects.filter(pk=row.pk).update(affected=new, sources=sources, needs_recorrelation=True, synced_at=timezone.now())
            MatchVerdict.objects.filter(cve_entry_id=row.pk).delete()
            out["repaired" if from_record else "normalized"] += 1
    marker.cves = max(marker.cves, min(last, hold) if hold is not None else last)
    marker.last_checked = now
    marker.save(update_fields=["cves", "last_checked"])
    return out


# ----------------------------------------------------------------------------- the exact builds of stored records

BUILDS_LANE = "exact-builds"  # the BackgroundCursor lane whose ``last_pk`` is the last CVEEntry id the backfill has looked at
# the stored entries the CVE List conversion may have cut or misread: a block with the 30 ranges the conversion keeps, a Cisco block with none
# (every build parenthesised, so none was a range, or cve.now's bare ``versions``), and an Oracle block with no range or with exact versions not
# yet read as Oracle's supported-versions convention (``_oracle_line_ranges``). ``wide`` also takes every other block with no range.
_ORACLE_SQL = """jsonb_path_exists(affected, '$[*] ? (@.vendor like_regex "^oracle" flag "i" && !exists(@.reading)
        && (@.ranges.size() == 0 || exists(@.ranges[*] ? (@.introduced == @.lastAffected))))')"""
_BUILDS_SQL = """(
    jsonb_path_exists(affected, '$[*] ? (@.ranges.size() >= 30 && !exists(@.builds))')
    OR jsonb_path_exists(affected, '$[*] ? (@.ranges.size() == 0 && !exists(@.builds)
        && (@.vendor like_regex "cisco" flag "i" || @.product like_regex "cisco" flag "i"))')
    OR """ + _ORACLE_SQL + """
)"""
_BUILDS_WIDE_SQL = """(jsonb_path_exists(affected, '$[*] ? ((@.ranges.size() >= 30 || @.ranges.size() == 0) && !exists(@.builds))')
    OR """ + _ORACLE_SQL + ")"


def builds_candidates(wide=False):
    """The stored entries ``backfill_exact_builds`` reads the CVE List record of, from where the last run stopped."""
    from cveFeed.models import BackgroundCursor, CVEEntry
    cursor = BackgroundCursor.objects.filter(lane=BUILDS_LANE).values_list("last_pk", flat=True).first() or 0
    return CVEEntry.objects.extra(where=[_BUILDS_WIDE_SQL if wide else _BUILDS_SQL]).filter(pk__gt=cursor).order_by("pk")


def backfill_exact_builds(limit=200, get=None, workers=4, wide=False):
    """One bounded step of giving stored entries the exact builds their CVE List record lists (``_exact_builds``). Returns the counts.

    Before the ``builds`` list, the conversion kept 30 ranges and no parenthesised build, so a Cisco host whose build was not among the first 30
    listed (or any IOS or NX-OS build) never matched. Resumable: it reads at most ``limit`` records per call, in id order from the
    ``exact-builds`` cursor. Only ``builds`` (and the ranges of a block that had none) are taken from the record (``keep_published_ranges``,
    ``overlay_from_record``); a changed entry is marked for re-correlation and its cached match verdicts are dropped, as a cve.now refresh
    does. ``done`` is True once the walk reached the end; a record that could not be read is counted in ``failed`` and the walk goes on."""
    def reread(row, doc):
        fields = entry_from_cve5(doc, {}) if doc else None
        if not fields:
            return None
        affected, _bare = overlay_from_record(row.affected, doc)
        return _take_oracle_readings(keep_published_ranges(affected, fields["affected"]), fields["affected"])
    return _reread_walk(BUILDS_LANE, builds_candidates(wide), reread, limit=limit, get=get, workers=workers)


def _reread_walk(lane, candidates, reread, limit=200, get=None, workers=4, material=None):
    """One bounded, resumable step of reading the CVE List record of stored entries again: the first ``limit`` of ``candidates`` (in id order,
    past the ``lane`` cursor) are fetched, ``reread(row, doc)`` gives each its new ``affected`` (None: unchanged), and an entry that changes is
    stored with the "CVE List V5" label (what lets a cve.now refresh keep what the record gave, ``keep_published_ranges``), marked for
    re-correlation, and its cached match verdicts are dropped. Returns ``{scanned, updated, failed, failed_ids, done}``."""
    from cveFeed import range_corrections
    from cveFeed.models import BackgroundCursor, CVEEntry, MatchVerdict
    rows = list(candidates[:max(1, limit)])
    out = {"scanned": len(rows), "updated": 0, "failed": 0, "failed_ids": [], "skipped": 0, "skipped_ids": [], "done": not rows}
    if not rows:
        return out

    def load(row):
        try:
            return row, fetch_cve5_patiently(row.cve_id, get=get), None
        except Exception as exc:  # noqa: BLE001 - counted; a passing failure makes the command try the walk again
            return row, None, exc
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fetched = list(pool.map(load, rows))
    for row, doc, error in fetched:
        if error is not None and _transient(error):  # still rate limited or down after the waits: the walk is tried again later
            out["failed"] += 1
            out["failed_ids"].append(row.cve_id)
            logger.warning("%s: could not read the CVE List record of %s: %s", lane, row.cve_id, error)
            continue
        if error is not None:  # will not read on any try (too large, not JSON, another status): left as stored, never blocks the walk
            out["skipped"] += 1
            out["skipped_ids"].append(row.cve_id)
            logger.warning("%s: the CVE List record of %s cannot be read and is left as stored: %s", lane, row.cve_id, error)
            continue
        new = reread(row, doc)
        if new is None:
            continue
        new, _corrected = range_corrections.apply(row.cve_id, new)  # a sourced correction of a too-narrow bound stays applied
        if new != row.affected:
            sources = list(row.sources or [])
            if "CVE List V5" not in sources:
                sources.append("CVE List V5")
            if material is not None and not material(row.affected, new):
                # only what the walk notes about a block changed (``open_checked``): stored, nothing to correlate again
                CVEEntry.objects.filter(pk=row.pk).update(affected=new)
                continue
            # synced_at moves with the ranges, so the per-process product index (correlation.cve_pool) is built again from them
            CVEEntry.objects.filter(pk=row.pk).update(affected=new, sources=sources, needs_recorrelation=True, synced_at=timezone.now())
            MatchVerdict.objects.filter(cve_entry_id=row.pk).delete()
            out["updated"] += 1
    cursor, _ = BackgroundCursor.objects.get_or_create(lane=lane)
    cursor.last_pk = max(cursor.last_pk, rows[-1].pk)
    cursor.save(update_fields=["last_pk", "updated_at"])
    return out


def _take_oracle_readings(affected, published):
    """``affected`` with each Oracle block that was stored with the record's exact versions as exact ranges given the per-line ranges the record
    reads as now (``_oracle_line_ranges``), for the same product. Any other block is returned as it was."""
    from cveFeed.correlation import affected_product_tokens
    out = list(affected or [])
    for i, item in enumerate(out):
        if not isinstance(item, dict) or item.get("reading"):
            continue
        wanted = affected_product_tokens(item)
        ranges = [r for p in published or [] if p.get("reading") == ORACLE_READING and wanted & affected_product_tokens(p)
                  and _same_vendor(item, p) for r in p["ranges"]]
        if wanted and ranges:  # every line the record gives the product (CISA's ADP writes one block per line: java_se 7u311, 8u301, ...)
            out[i] = {**item, "ranges": [dict(t) for t in dict.fromkeys(tuple(r.items()) for r in ranges)], "reading": ORACLE_READING}
    return out


def reset_exact_builds():
    """Start the walk of ``backfill_exact_builds`` again from the first stored entry."""
    from cveFeed.models import BackgroundCursor
    BackgroundCursor.objects.filter(lane=BUILDS_LANE).delete()


# ----------------------------------------------------------------------------- bare versions lists of stored records

BARE_LANE = "bare-versions"  # the BackgroundCursor lane whose ``last_pk`` is the last CVEEntry id ``backfill_bare_versions`` has looked at
# a block cve.now passed on with no range and a bare ``versions`` list (the kernel CNA's releases, Microsoft's product names, VulDB's exact
# versions, Cisco's builds, Oracle's supported versions): the record's own bounds were never read
_BARE_SQL = """jsonb_path_exists(affected, '$[*] ? (@.ranges.size() == 0 && !exists(@.builds) && @.versions.size() > 0)')"""


def bare_candidates():
    """The stored entries ``backfill_bare_versions`` reads the CVE List record of, from where the last run stopped."""
    from cveFeed.models import BackgroundCursor, CVEEntry
    cursor = BackgroundCursor.objects.filter(lane=BARE_LANE).values_list("last_pk", flat=True).first() or 0
    return CVEEntry.objects.extra(where=[_BARE_SQL]).filter(pk__gt=cursor).order_by("pk")


def backfill_bare_versions(limit=200, get=None, workers=4):
    """One bounded step of giving the stored blocks cve.now passed on as bare ``versions`` the ranges their CVE List record states
    (``overlay_from_record``). Returns ``{scanned, updated, failed, failed_ids, done}`` as ``backfill_exact_builds`` does, with the same walk:
    at most ``limit`` records per call from the ``bare-versions`` cursor, each changed entry marked for re-correlation. A block whose record
    states nothing sound (Microsoft's product names, a git-only list, an open range) is left with no range, as it was."""
    return _reread_walk(BARE_LANE, bare_candidates(), lambda row, doc: overlay_from_record(row.affected, doc)[0] if doc else None,
                        limit=limit, get=get, workers=workers)


def reset_bare_versions():
    """Start the walk of ``backfill_bare_versions`` again from the first stored entry."""
    from cveFeed.models import BackgroundCursor
    BackgroundCursor.objects.filter(lane=BARE_LANE).delete()


LLAMACPP_LANE = "llamacpp-builds"  # the BackgroundCursor lane of ``backfill_llamacpp_builds``
# a bare-versions block of llama.cpp (``correlation.is_llamacpp`` names the vendors): its record's "< b5662" was read as no version before
# ``_llamacpp_builds``, so the block was stored with no range even after ``backfill_bare_versions`` had read it
_LLAMACPP_SQL = """jsonb_path_exists(affected, '$[*] ? (@.ranges.size() == 0 && !exists(@.builds) && @.versions.size() > 0
    && @.product like_regex "llama[._ -]?cpp$" flag "i")')"""


def llamacpp_candidates():
    """The stored entries ``backfill_llamacpp_builds`` reads the CVE List record of, from where the last run stopped."""
    from cveFeed.models import BackgroundCursor, CVEEntry
    cursor = BackgroundCursor.objects.filter(lane=LLAMACPP_LANE).values_list("last_pk", flat=True).first() or 0
    return CVEEntry.objects.extra(where=[_LLAMACPP_SQL]).filter(pk__gt=cursor).order_by("pk")


def backfill_llamacpp_builds(limit=200, get=None, workers=4):
    """One bounded step of reading again the CVE List record of each stored llama.cpp block that has no range and a bare ``versions`` list,
    now that a llama.cpp build tag ("< b5662") reads as its build number. The same walk and the same soundness rules as
    ``backfill_bare_versions``: a block whose record lists a commit or anything else that is not a version stays as it was."""
    return _reread_walk(LLAMACPP_LANE, llamacpp_candidates(), lambda row, doc: overlay_from_record(row.affected, doc)[0] if doc else None,
                        limit=limit, get=get, workers=workers)


def reset_llamacpp_builds():
    """Start the walk of ``backfill_llamacpp_builds`` again from the first stored entry."""
    from cveFeed.models import BackgroundCursor
    BackgroundCursor.objects.filter(lane=LLAMACPP_LANE).delete()


OPEN_LANE = "open-ranges"  # the BackgroundCursor lane of ``backfill_open_ranges``
# a CVE List block (a product, no package) with a range that has a lower bound and no upper one, not yet accounted for by a record reading
_OPEN_SQL = """jsonb_path_exists(affected, '$[*] ? (exists(@.product) && !exists(@.package) && !exists(@.ecosystem)
    && !exists(@.open_checked) && !exists(@.upper_unreadable)
    && exists(@.ranges[*] ? (exists(@.introduced) && !exists(@.fixed) && !exists(@.lastAffected))))')"""


def open_candidates():
    """The stored entries ``backfill_open_ranges`` reads the CVE List record of, from where the last run stopped."""
    from cveFeed.models import BackgroundCursor, CVEEntry
    cursor = BackgroundCursor.objects.filter(lane=OPEN_LANE).values_list("last_pk", flat=True).first() or 0
    return CVEEntry.objects.extra(where=[_OPEN_SQL]).filter(pk__gt=cursor, cve_id__startswith="CVE-").order_by("pk")


def _dropped_a_range(old, new):
    """Whether a block lost a range (what correlation reads), not only gained an ``open_checked`` note."""
    def ranges(affected):
        return [[r for r in (i.get("ranges") or [])] if isinstance(i, dict) else i for i in affected or []]
    return ranges(old) != ranges(new)


def backfill_open_ranges(limit=200, get=None, workers=4):
    """One bounded step of checking the stored open ranges of CVE List blocks against their record (``close_open_ranges``, issue 696): a range
    cve.now or an older conversion made open from an upper bound the record writes as text is left out, and the CVE is marked for
    re-correlation (its open matches outside the real range close). The same walk as ``backfill_bare_versions``."""
    return _reread_walk(OPEN_LANE, open_candidates(), lambda row, doc: close_open_ranges(row.affected, doc)[0] if doc else None,
                        limit=limit, get=get, workers=workers, material=_dropped_a_range)


def reset_open_ranges():
    from cveFeed.models import BackgroundCursor
    BackgroundCursor.objects.filter(lane=OPEN_LANE).delete()


def retype_distro_ranges(apply=False, chunk=500):
    """Type the stored ranges whose bounds are distribution package builds (``_distro_typed``): "0:8.7p1-38.el9_4.4" was read as the upstream
    release 8.7p1 and put every RHEL 9 OpenSSH 8.7 in range. Reads only the stored data (no request). Returns ``{"cves": n, "ids": [...]}``;
    with ``apply`` each changed CVE is written and marked for re-correlation."""
    from cveFeed.models import CVEEntry, MatchVerdict
    out = {"cves": 0, "ids": []}
    last = 0
    qs = CVEEntry.objects.extra(where=["affected::text ~ %s"], params=[r'"(introduced|fixed|lastAffected)": "[^"]*([0-9]+:[0-9]|[.-](el|fc|amzn)[0-9]|ubuntu[0-9]|[+~]deb[0-9])'])
    while True:
        rows = list(qs.filter(pk__gt=last).order_by("pk").only("id", "cve_id", "affected")[:chunk])
        if not rows:
            return out
        last = rows[-1].pk
        for row in rows:
            new = [{**item, "ranges": [_distro_typed(r) for r in item["ranges"]]} if isinstance(item, dict) and isinstance(item.get("ranges"), list)
                   else item for item in row.affected or []]
            if new == row.affected:
                continue
            out["cves"] += 1
            if len(out["ids"]) < 50:
                out["ids"].append(row.cve_id)
            if apply:
                CVEEntry.objects.filter(pk=row.pk).update(affected=new, needs_recorrelation=True, synced_at=timezone.now())
                MatchVerdict.objects.filter(cve_entry_id=row.pk).delete()


RECORD_WALKS = (("bare-versions", BARE_LANE, "backfill_bare_versions"), ("exact-builds", BUILDS_LANE, "backfill_exact_builds"),
                ("open-ranges", OPEN_LANE, "backfill_open_ranges"))
WALK_HOLD_TRIES = 3


def record_walks_step(limit, get=None):
    """One bounded step of each CVE List re-read walk (bare versions, exact builds, open ranges), run with every threat-intel pass: the walks
    follow the catalog as it grows (their cursor is the last CVE id looked at), so a CVE whose record could not be read when it was stored is
    read here instead of never. A record that failed for a reason that passes holds its walk at that CVE for up to ``WALK_HOLD_TRIES`` passes.
    Returns ``{walk: counts}``; a walk that fails is reported and never stops the others."""
    from django.core.cache import cache
    from cveFeed.models import BackgroundCursor, CVEEntry
    out = {}
    for name, lane, func in RECORD_WALKS:
        try:
            before = BackgroundCursor.objects.filter(lane=lane).values_list("last_pk", flat=True).first() or 0
            got = globals()[func](limit=limit, get=get)
            failed = [i for i in got.get("failed_ids") or []]
            if failed:
                first = CVEEntry.objects.filter(cve_id__in=failed).order_by("pk").values_list("pk", flat=True).first()
                key = f"cvengine:record-walk-hold:{lane}:{first}"
                tries = (cache.get(key) or 0) + 1
                cache.set(key, tries, 7 * 86400)
                if first and tries < WALK_HOLD_TRIES:
                    BackgroundCursor.objects.filter(lane=lane).update(last_pk=max(before, first - 1))
            out[name] = {k: got.get(k) for k in ("scanned", "updated", "failed", "done")}
        except Exception as exc:  # noqa: BLE001 - one walk must not stop the others or the intel run
            logger.warning("threat intel: the %s walk failed: %s", name, exc)
            out[name] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
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
    turned_hot = []
    updated, changed_ids = reconcile(data, since=since, now=now, turned_hot=turned_hot)
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
    walks = {}
    per_walk = _int_env("CVENGINE_RECORD_REREAD_PER_RUN", 100, 0, 2000)
    if per_walk:  # the record re-read walks follow the catalog (0 turns them off; the update steps and commands still run them by hand)
        walks = record_walks_step(per_walk, get=get)
    if LAST_IMPORT["default_status"]:
        logger.info("threat intel: %s of the %s imported CVE records state their affected releases as unaffected ranges of a default-affected "
                    "product (defaultStatus), which are now read as the releases between those ranges", LAST_IMPORT["default_status"], len(created))
    return {"sources": {n: len(data.get(n) or {}) for n in names}, "errors": errors, "reconciled": updated,
            "signals_changed": changed_ids, "signals_turned_hot": turned_hot, "imported": created, "default_status_records": LAST_IMPORT["default_status"],
            "ranges_repaired": repaired.get("repaired", 0) + repaired.get("normalized", 0), "record_walks": walks}
