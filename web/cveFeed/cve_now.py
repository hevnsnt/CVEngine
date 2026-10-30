"""Client for the cve.now public vulnerability feed (free, no auth, no key).

cve.now merges the CVE List, GitHub Advisory Database, OSV, NVD, ENISA EUVD,
CISA KEV, FIRST EPSS and Exploit-DB into one entry per vulnerability. CVEngine
syncs this feed and the AI correlation engine matches each entry's affected
products/versions against the discovered asset inventory.

API reference: https://cve.now/llms.txt
  GET /api/v1/entries?limit=&cursor=   -> {"entries": [...summaries], "nextCursor": "..."}
  GET /api/v1/entries/<id>             -> one full entry (severity, exploitation, affected)
  GET /api/v1/status                   -> polling / coverage status
"""
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

    def _get(self, path, params=None, retries=3):
        """GET one JSON document. A 429 or a 5xx is retried after the server's Retry-After (else 1, 2, 4 s), at most
        ``retries`` times and never longer than ``MAX_WAIT`` seconds in one wait; anything else, a 403 included, is raised
        at once so a block is never hammered."""
        for attempt in range(retries + 1):
            resp = self.session.get(
                f"{self.base_url}{path}", params=params, timeout=self.timeout
            )
            if resp.status_code in RETRY_STATUS and attempt < retries:
                self.sleep(_retry_delay(resp, attempt))
                continue
            resp.raise_for_status()
            return resp.json()

    def list_entries(self, limit=100, cursor=None):
        """Return one page of entry summaries (newest first) and the next cursor.

        Returns a (entries, next_cursor) tuple; next_cursor is None on the last
        page.
        """
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        data = self._get("/entries", params=params)
        return data.get("entries", []), data.get("nextCursor")

    def get_entry(self, cve_id):
        """Return the full entry for one id (CVE / GHSA / OSV)."""
        return self._get(f"/entries/{cve_id}")

    def iter_entries(self, max_entries=500, page_size=100, page_pause=0):
        """Yield entry summaries newest-first across pages, up to max_entries. ``page_pause`` seconds pass between page requests."""
        seen = 0
        cursor = None
        while seen < max_entries:
            if seen and page_pause:
                self.sleep(page_pause)
            page, cursor = self.list_entries(
                limit=min(page_size, max_entries - seen), cursor=cursor
            )
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
        walk that stops part way can continue from that page later. At most ``max_entries`` entries are read."""
        seen = 0
        while seen < max_entries:
            if seen and page_pause:
                self.sleep(page_pause)
            page, following = self.list_entries(limit=min(page_size, max_entries - seen), cursor=cursor)
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

    def tech_entry_ids(self, tech):
        """Ids of the entries cve.now files under one technology (``/feed?tech=<slug>&format=json``), newest first. The
        listing is a different index from ``/entries``, so it also reaches entries the newest-first walk never lists."""
        slug = (tech or "").strip().lower()
        if not TECH_RE.match(slug):
            raise ValueError(f"not a cve.now technology slug: {tech!r}")
        root = self.base_url[:-len("/api/v1")] if self.base_url.endswith("/api/v1") else self.base_url
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
