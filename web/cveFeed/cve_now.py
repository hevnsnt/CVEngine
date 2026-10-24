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

import requests

logger = logging.getLogger(__name__)

CVE_NOW_BASE_URL = "https://cve.now/api/v1"
USER_AGENT = "CVEngine/0.1 (+https://github.com/hevnsnt/CVEngine)"


class CVENowClient:
    """Thin, dependency-light wrapper over the cve.now JSON API."""

    def __init__(self, base_url=CVE_NOW_BASE_URL, timeout=20, session=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.setdefault("Accept", "application/json")
        self.session.headers.setdefault("User-Agent", USER_AGENT)

    def _get(self, path, params=None):
        resp = self.session.get(
            f"{self.base_url}{path}", params=params, timeout=self.timeout
        )
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

    def iter_entries(self, max_entries=500, page_size=100):
        """Yield entry summaries newest-first across pages, up to max_entries."""
        seen = 0
        cursor = None
        while seen < max_entries:
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

    def status(self):
        """Return the feed's polling / historical-coverage status."""
        return self._get("/status")
