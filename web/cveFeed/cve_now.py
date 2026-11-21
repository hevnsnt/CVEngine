"""Client for the cve.now public vulnerability feed (free, no auth, no key).

cve.now merges the CVE List, GitHub Advisory Database, OSV, NVD, ENISA EUVD,
CISA KEV, FIRST EPSS and Exploit-DB into one entry per vulnerability. CVEngine
syncs this feed and the AI correlation engine matches each entry's affected
products/versions against the discovered asset inventory.

API reference: https://cve.now/llms.txt (changelog: https://cve.now/changelog)
  GET /api/v1/entries?limit=&cursor=   -> {"items": [...summaries], "next_cursor": "..."} (``entries`` and ``nextCursor`` before 2026-11-11);
                                          without a key only the newest 400 are listed, a page past them is a 401 ``depth_limit``
  GET /api/v1/entries?since=<time>     -> the entries cve.now wrote after a time, oldest change first, up to 7 days back with no depth
                                          limit: {"items", "next_cursor", "next_since", "has_more"}; a withdrawn or merged entry is a tombstone
  GET /api/v1/entries/<id>             -> one full entry (severity, exploitation, affected)
  GET /archive/<YYYY-MM-DD>.md         -> every entry published that UTC day (yesterday at the latest), as Markdown lines
  GET /api/v1/status                   -> polling / coverage status
"""
import datetime
import logging
import re
import time
from email.utils import parsedate_to_datetime

import requests

logger = logging.getLogger(__name__)

CVE_NOW_BASE_URL = "https://cve.now/api/v1"
USER_AGENT = "CVEngine/0.1 (+https://github.com/hevnsnt/CVEngine)"
RETRY_STATUS = (429, 500, 502, 503, 504)
MAX_WAIT = 30
TECH_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
FEED_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{3,63}")
DEPTH_LIMIT = "depth_limit"
SINCE_REACH = datetime.timedelta(days=7) - datetime.timedelta(hours=1)  # how far back an anonymous ``since`` reaches (7 days), less a margin
SINCE_PAGE = 200
SINCE_MAX_PAGES = 100  # one window read stops after this many delta pages (20,000 changes) and reports itself incomplete
# a line of a day's archive: "- [CVE-2026-71881](https://cve.now/CVE-2026-71881.md): ...". Only CVE ids: the other ids a day lists (GHSA, RUSTSEC,
# SZB-) are advisories and early warnings, not entries of the CVE catalog
ARCHIVE_LINE_RE = re.compile(r"^- \[(CVE-\d{4}-\d{4,})\]\(https://cve\.now/", re.MULTILINE | re.IGNORECASE)


class DepthLimit(requests.HTTPError):
    """cve.now refused a list page past what a caller without a key may read (the newest 400 results). The listing goes on: this is the
    end of what can be listed this way, not the end of the feed, and not a block."""


class WindowIncomplete(Exception):
    """A date window could not be read in full (a day's archive is missing, or the delta listing ran past its page budget).

    ``partial`` is what was listed anyway and ``complete_below`` the time below which that listing is whole, when only today's delta
    listing ran out (a burst of changes on cve.now): the archive days below it were still read. Both are None otherwise."""

    def __init__(self, message, partial=None, complete_below=None):
        super().__init__(message)
        self.partial = partial
        self.complete_below = complete_below


def _error_code(resp):
    try:
        body = resp.json()
    except (TypeError, ValueError, AttributeError):
        return ""
    return str(body.get("error") or "") if isinstance(body, dict) else ""


def page_rows(data):
    """The rows of one list page: ``items`` (``entries`` in answers from before 2026-11-11)."""
    data = data if isinstance(data, dict) else {}
    rows = data.get("items")
    if not isinstance(rows, list):
        rows = data.get("entries")
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def next_cursor(data):
    """The cursor of the next page, None on the last: ``next_cursor`` (``nextCursor`` before 2026-11-11)."""
    data = data if isinstance(data, dict) else {}
    value = data.get("next_cursor") or data.get("nextCursor")
    return str(value) if value else None


def _flag(value):
    """One exploitation signal as a flag: cve.now states each as an object (``{"dateAdded": ...}``) or null since 2026-11; older answers
    said true or false. An object (or true) is a yes, an empty one (or false) a no, null (or nothing) unknown, as before."""
    return None if value is None else bool(value)


def exploitation_flags(exploitation):
    """``{"kev", "epssReached", "exploitDb"}`` of an entry's exploitation block, each True, False or None (``_flag``)."""
    exploitation = exploitation if isinstance(exploitation, dict) else {}
    return {key: _flag(exploitation.get(key)) for key in ("kev", "epssReached", "exploitDb")}


def _time(value):
    """An aware datetime from a feed time, None when it is missing or not a time."""
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def _retry_delay(resp, attempt):
    """Seconds to wait before retrying: the Retry-After header (seconds or an HTTP date) when it says, else 1, 2, 4."""
    raw = (getattr(resp, "headers", None) or {}).get("Retry-After")
    delay = None
    if raw:
        try:
            delay = float(raw)
        except (TypeError, ValueError):
            try:
                delay = parsedate_to_datetime(raw).timestamp() - time.time()
            except (TypeError, ValueError):
                delay = None
    if delay is None:
        delay = 2 ** attempt
    return max(0.0, min(float(delay), MAX_WAIT))


class CVENowClient:
    """Thin, dependency-light wrapper over the cve.now JSON API."""

    def __init__(self, base_url=CVE_NOW_BASE_URL, timeout=20, session=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.setdefault("Accept", "application/json")
        self.session.headers.setdefault("User-Agent", USER_AGENT)
        self.sleep = time.sleep

    def _response(self, url, params=None, retries=3, **kwargs):
        """GET one URL. A 429 or a 5xx is retried after the server's Retry-After (else 1, 2, 4 s), at most ``retries`` times and never
        longer than ``MAX_WAIT`` seconds in one wait; anything else, a 403 included, is raised at once so a block is never hammered."""
        for attempt in range(retries + 1):
            resp = self.session.get(url, params=params, timeout=self.timeout, **kwargs)
            if resp.status_code in RETRY_STATUS and attempt < retries:
                self.sleep(_retry_delay(resp, attempt))
                continue
            resp.raise_for_status()
            return resp

    def _get(self, path, params=None, retries=3):
        """GET one JSON document under the API (``_response``)."""
        return self._response(f"{self.base_url}{path}", params=params, retries=retries).json()

    def _root(self):
        return self.base_url[:-len("/api/v1")] if self.base_url.endswith("/api/v1") else self.base_url

    def list_entries(self, limit=100, cursor=None):
        """Return one page of entry summaries (newest first) and the next cursor.

        Returns a (entries, next_cursor) tuple; next_cursor is None on the last page. A page past what may be listed without a key (the
        newest 400) raises ``DepthLimit``.
        """
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        try:
            data = self._get("/entries", params=params)
        except requests.HTTPError as exc:
            resp = getattr(exc, "response", None)
            code = _error_code(resp) if resp is not None else ""
            if getattr(resp, "status_code", None) == 401 and (code == DEPTH_LIMIT or (cursor and not code)):
                raise DepthLimit(str(exc), response=resp) from exc
            raise
        return page_rows(data), next_cursor(data)

    def get_entry(self, cve_id):
        """Return the full entry for one id (CVE / GHSA / OSV)."""
        return self._get(f"/entries/{cve_id}")

    def iter_entries(self, max_entries=500, page_size=100, page_pause=0):
        """Yield entry summaries newest-first across pages, up to max_entries. ``page_pause`` seconds pass between page requests. A listing
        that stops at the depth limit ends there and sets ``depth_limited``."""
        seen = 0
        cursor = None
        self.depth_limited = False
        while seen < max_entries:
            if seen and page_pause:
                self.sleep(page_pause)
            try:
                page, cursor = self.list_entries(limit=min(page_size, max_entries - seen), cursor=cursor)
            except DepthLimit:
                self.depth_limited = True
                return
            if not page:
                return
            for entry in page:
                yield entry
                seen += 1
                if seen >= max_entries:
                    return
            if not cursor:
                return

    def iter_pages(self, max_entries=500, page_size=100, page_pause=0, cursor=None):
        """Yield ``(cursor, entries)`` per page, newest first, where ``cursor`` is the one that fetched the page (None for the first), so a
        walk that stops part way can continue from that page later. At most ``max_entries`` entries are read. A listing that stops at the
        depth limit ends there and sets ``depth_limited``: what lies below is read by date windows (``published_between``)."""
        seen = 0
        self.depth_limited = False
        while seen < max_entries:
            if seen and page_pause:
                self.sleep(page_pause)
            try:
                page, following = self.list_entries(limit=min(page_size, max_entries - seen), cursor=cursor)
            except DepthLimit:
                self.depth_limited = True
                return
            if not page:
                return
            yield cursor, page
            seen += len(page)
            cursor = following
            if not cursor:
                return

    def status(self):
        """Return the feed's polling / historical-coverage status."""
        return self._get("/status")

    def changes(self, since, cursor=None, limit=SINCE_PAGE, etag=None):
        """One page of what cve.now wrote after ``since`` (an aware datetime or its RFC 3339 text), oldest change first:
        ``{"items", "next_cursor", "next_since", "has_more", "etag", "not_modified"}``. ``etag`` (of the last answer) is sent as
        If-None-Match; a 304 comes back as ``not_modified`` with no items. Items are list rows plus ``updatedAt``; a withdrawn or merged
        entry is a tombstone ``{id, title, status, updatedAt}`` (merged adds ``supersededBy``)."""
        if isinstance(since, datetime.datetime):
            since = since.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        params = {"since": since, "limit": limit}
        if cursor:
            params["cursor"] = cursor
        kwargs = {"headers": {"If-None-Match": etag}} if etag else {}
        resp = self._response(f"{self.base_url}/entries", params=params, **kwargs)
        if resp.status_code == 304:
            return {"items": [], "next_cursor": None, "next_since": None, "has_more": False, "etag": etag, "not_modified": True}
        data = resp.json()
        data = data if isinstance(data, dict) else {}
        return {"items": page_rows(data), "next_cursor": next_cursor(data), "next_since": data.get("next_since") or None,
                "has_more": bool(data.get("has_more")), "etag": (getattr(resp, "headers", None) or {}).get("ETag"),
                "not_modified": False}

    def search_cves(self, query=None, tech=None, published=None, cursor=None, limit=100):
        """One page of cve.now's search for CVEs (``/api/v1/search`` with ``type=cve``): ``query`` is the ``q`` text (a quoted product name),
        ``tech`` a technology slug, ``published`` a list of date bounds (``[">=2023-01-01", "<2024-01-01"]``). Returns ``(ids, total,
        next_cursor)``. Without a key a search reaches its newest 400 results (a deeper page raises ``DepthLimit``) and 30 searches a
        minute."""
        params = {"type": "cve", "limit": limit}
        if query:
            params["q"] = query
        if tech:
            params["tech"] = tech
        if published:
            params["published"] = list(published)
        if cursor:
            params["cursor"] = cursor
        try:
            data = self._get("/search", params=params)
        except requests.HTTPError as exc:
            resp = getattr(exc, "response", None)
            if getattr(resp, "status_code", None) == 401 and (_error_code(resp) == DEPTH_LIMIT or cursor):
                raise DepthLimit(str(exc), response=resp) from exc
            raise
        data = data if isinstance(data, dict) else {}
        ids = []
        for item in page_rows(data):
            entry_id = str(item.get("id") or "").strip().upper()
            if (item.get("type") in (None, "cve")) and re.match(r"^CVE-\d{4}-\d{4,19}$", entry_id) and entry_id not in ids:
                ids.append(entry_id)
        total = data.get("total")
        return ids, (total if isinstance(total, int) else None), next_cursor(data)

    def tech_slugs(self):
        """``{slug: [title, aliases...]}`` of the technologies cve.now tracks (``/api/v1/tech``)."""
        out = {}
        for item in page_rows(self._get("/tech", params={"limit": 200})):
            slug = str(item.get("id") or "").strip().lower()
            if TECH_RE.match(slug):
                out[slug] = [str(item.get("title") or "")] + [str(a) for a in item.get("aliases") or [] if isinstance(a, str)]
        return out

    def archive_day_ids(self, day):
        """The CVE ids cve.now lists as published on one UTC day (``/archive/<YYYY-MM-DD>.md``, a page per day up to yesterday, with no
        depth limit), in the page's order. A day the archive does not have (today, a future day) raises the HTTP error."""
        resp = self._response(f"{self._root()}/archive/{day.isoformat()}.md", headers={"Accept": "text/markdown"})
        ids, seen = [], set()
        for found in ARCHIVE_LINE_RE.finditer(resp.text or ""):
            entry_id = found.group(1).upper()
            if entry_id not in seen:
                seen.add(entry_id)
                ids.append(entry_id)
        return ids

    def published_between(self, floor, below, now, pause=0.3):
        """``[(id, firstSeenAt or None)]`` of the entries published from ``floor`` to ``below`` (aware datetimes), read by date windows,
        because the newest-first listing stops at the newest 400 for a caller without a key: each whole UTC day before today from its
        archive page, and today (and any part of the window the archive does not have yet) from the delta listing (``since``), which
        reaches back 7 days with no depth limit. An entry first seen late is listed under its publication day, so a window read again
        later finds it. Raises ``WindowIncomplete`` when part of the window could not be listed; an HTTP error is raised as it is. Today's
        delta listing names every change, not only new entries, so a day cve.now rewrites many entries can run past its page budget: the
        archive days are read all the same, and the exception carries them (``partial``, whole below ``complete_below``); today's new
        entries reach the catalog through the sync's own delta read, and tomorrow's archive page lists them."""
        out, seen = [], set()

        def add(entry_id, first_seen=None):
            if entry_id and entry_id not in seen:
                seen.add(entry_id)
                out.append((entry_id, first_seen))
        if below is None or below < floor:
            below = now
        today = now.astimezone(datetime.timezone.utc).date()
        midnight = datetime.datetime.combine(today, datetime.time(), tzinfo=datetime.timezone.utc)
        requests_made, short = 0, None
        if below >= midnight - datetime.timedelta(hours=1):
            # today: the delta listing, from a little before midnight (or the floor), never further back than it reaches
            since_from = max(floor, midnight - datetime.timedelta(hours=1), now - SINCE_REACH)
            cursor, pages = None, 0
            while True:
                if requests_made and pause:
                    self.sleep(pause)
                page = self.changes(since_from, cursor=cursor)
                requests_made += 1
                pages += 1
                for item in page["items"]:
                    if item.get("status") in ("withdrawn", "merged"):
                        continue
                    published = _time(item.get("publishedAt")) or _time(item.get("firstSeenAt"))
                    if published is None or published >= floor:
                        add(str(item.get("id") or "").strip(), item.get("firstSeenAt"))
                if not page["has_more"] or not page["next_cursor"]:
                    break
                if pages >= SINCE_MAX_PAGES:
                    short = since_from  # the rest of today waits for the sync's delta read and tomorrow's archive page; the days below still count
                    break
                cursor = page["next_cursor"]
            last_day = today - datetime.timedelta(days=1)
        else:
            last_day = below.astimezone(datetime.timezone.utc).date()
        day = min(last_day, today - datetime.timedelta(days=1))
        first_day = floor.astimezone(datetime.timezone.utc).date()
        while day >= first_day:
            if requests_made and pause:
                self.sleep(pause)
            try:
                ids = self.archive_day_ids(day)
            except requests.HTTPError as exc:
                if getattr(getattr(exc, "response", None), "status_code", None) == 404:
                    raise WindowIncomplete(f"cve.now has no archive page for {day.isoformat()}") from exc
                raise
            requests_made += 1
            for entry_id in ids:
                add(entry_id)
            day -= datetime.timedelta(days=1)
        if short is not None:
            raise WindowIncomplete(f"the delta listing since {short.isoformat()} has more than {SINCE_MAX_PAGES} pages", partial=out,
                                   complete_below=short)
        return out

    def tech_entry_ids(self, tech):
        """Ids of the entries cve.now files under one technology (``/feed?tech=<slug>&format=json``), newest first. The
        listing is a different index from ``/entries``, so it also reaches entries the newest-first walk never lists."""
        slug = (tech or "").strip().lower()
        if not TECH_RE.match(slug):
            raise ValueError(f"not a cve.now technology slug: {tech!r}")
        root = self._root()
        resp = self.session.get(f"{root}/feed", params={"tech": slug, "format": "json"}, timeout=self.timeout)
        resp.raise_for_status()
        ids, seen = [], set()
        for item in (resp.json().get("items") or []):
            found = FEED_ID_RE.match(str(item.get("id") or ""))
            entry_id = found.group(0).split("#")[0] if found else ""
            if entry_id and entry_id not in seen:
                seen.add(entry_id)
                ids.append(entry_id)
        return ids
