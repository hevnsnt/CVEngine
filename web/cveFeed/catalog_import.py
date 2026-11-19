"""Every CVE of the products the inventory runs, not only those the feed published while this install was reading it.

The catalog holds what the seed held and what the feed published since. An older CVE that was never exploited (Apache HTTP Server's
CVE-2023-31122, OpenSSH's CVE-2025-26465) is in neither when the seed was built without it, and the threat-intelligence import only brings in
exploited ones, so a host running httpd 2.4.57 never matched it. This asks cve.now for each product a current host runs with a known version:

* the product's names are the catalogue's own (the ``vendor:product`` spellings the host's name connects to through correlation's matcher,
  ``tech_coverage.connect``), or the host's name when it connects to none;
* a name that is one of the technologies cve.now tracks is asked by its slug (``tech=apache-httpd``), any other as a quoted phrase
  (``q="OpenSSH"``), CVEs only;
* without a key a search reaches its newest 400 results and 30 searches a minute, so a product with more is asked one publication year at a
  time, newest first;
* each CVE not stored is read in full and stored (``CVEEntry.from_api``), at most ``CVENGINE_INVENTORY_IMPORT_PER_RUN`` a run (0 turns it off).

A product (or one year of it) whose CVEs are all stored is not asked again for ``DONE_FOR``. ``tasks.import_inventory_cve_history`` runs it
every few hours and matches what it stored against the inventory.
"""
import hashlib
import logging
import os
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

SEARCH_DEPTH = 400           # results a search reaches without a key
SEARCH_PAGE = 100
SEARCH_PAUSE = 2.5           # seconds between searches: 30 a minute
READ_PAUSE = 0.5             # seconds between entry reads: 120 a minute
MAX_SEARCHES = 24            # searches one run makes
MAX_PRODUCTS = 40            # products one run looks at, most hosts first
DONE_FOR = timedelta(days=7)
FIRST_YEAR = 1999
DEFAULT_PER_RUN = 300


def per_run():
    try:
        return max(0, min(5000, int(os.environ.get('CVENGINE_INVENTORY_IMPORT_PER_RUN', DEFAULT_PER_RUN))))
    except ValueError:
        return DEFAULT_PER_RUN


def _key(*parts):
    return 'cvengine:inventory-import:' + hashlib.sha1('|'.join(str(p) for p in parts).encode()).hexdigest()


def products(limit=MAX_PRODUCTS):
    """The product names to ask cve.now about, most hosts first: the catalogue spellings each current host's versioned product connects to,
    or its own name when it connects to none. Operating systems and names that are no software (a CDN, a protocol) are left out."""
    from cveFeed import correlation, match_policy, tech_coverage
    cve_by_id, index = correlation.cve_pool()
    rows = tech_coverage._merge(tech_coverage.sightings_from_db())
    out, seen = [], set()
    for row in sorted(rows, key=lambda r: (-r['versioned'], r['name'].lower())):
        if not row['versioned'] or match_policy.is_os_sighting(row['name'], row['cpe']):
            continue
        if any(tech_coverage.service_kind(row['name'], raw) for raw in sorted(row['raw'])):
            continue
        found = tech_coverage.connect(row['name'], row['cpe'], index, cve_by_id)
        names = [label.split(':', 1)[-1].strip() for label, _n in found['products'].most_common(2)] or [row['name']]
        for name in names:
            token = correlation._norm(name)
            if len(token) >= correlation._MIN_TOKEN and token not in seen:
                seen.add(token)
                out.append(name[:120])
        if len(out) >= limit:
            break
    return out[:limit]


def _norm(text):
    from cveFeed.correlation import _norm
    return _norm(text)


class Budget:
    def __init__(self, reads, searches):
        self.reads, self.searches = reads, searches


def _search(client, budget, name, tech, published=None):
    """Every CVE id one search lists, as deep as it reaches. Returns ``(ids, total, complete)``; ``complete`` is False when the budget ran
    out or the results run past the depth a search reaches."""
    from cveFeed.cve_now import DepthLimit
    ids, cursor, total = [], None, None
    while True:
        if budget.searches <= 0:
            return ids, total, False
        if budget.searches < MAX_SEARCHES:
            client.sleep(SEARCH_PAUSE)
        budget.searches -= 1
        try:
            page, total, cursor = client.search_cves(query=None if tech else f'"{name}"', tech=tech, published=published, cursor=cursor,
                                                     limit=SEARCH_PAGE)
        except DepthLimit:
            return ids, total, False
        ids += [i for i in page if i not in ids]
        if not cursor or not page:
            return ids, total, total is None or len(ids) >= min(total, SEARCH_DEPTH) and total <= SEARCH_DEPTH
        if len(ids) >= SEARCH_DEPTH:
            return ids, total, False


def _windows(now):
    """Publication-year windows, newest first."""
    for year in range(now.year, FIRST_YEAR - 1, -1):
        yield year, [f'>={year}-01-01', f'<{year + 1}-01-01']


def _store_missing(client, budget, ids, created):
    """Read and store the ids not stored yet. Returns True when every one of them is stored."""
    from cveFeed.models import CVEEntry
    have = set(CVEEntry.objects.filter(cve_id__in=ids).values_list('cve_id', flat=True))
    missing = [i for i in ids if i not in have]
    for cve_id in missing:
        if budget.reads <= 0:
            return False
        if created or budget.reads < budget.start_reads:
            client.sleep(READ_PAUSE)
        budget.reads -= 1
        try:
            obj, _ = CVEEntry.from_api(client.get_entry(cve_id))
            created.append(obj.pk)
        except Exception as exc:  # noqa: BLE001 - one entry must not stop the product; it is asked again in a later run
            logger.warning('inventory import: could not read %s: %s', cve_id, exc)
            return False
    return True


def run(client, reads=None, searches=MAX_SEARCHES, now=None, names=None):
    """One bounded pass. Returns ``{"products", "done", "created": [pks], "searches", "reads"}``."""
    from django.core.cache import cache
    now = now or timezone.now()
    reads = per_run() if reads is None else reads
    budget = Budget(reads, searches)
    budget.start_reads = reads
    created, done, asked = [], [], []
    if not reads:
        return {'products': [], 'done': [], 'created': [], 'searches': 0, 'reads': 0}
    try:
        techs = {_norm(n): slug for slug, spellings in client.tech_slugs().items() for n in [slug, *spellings] if n}
        budget.searches -= 1
    except Exception as exc:  # noqa: BLE001 - every product is then asked by name
        logger.info('inventory import: cve.now technologies not read: %s', exc)
        techs = {}
    for name in (products() if names is None else names):
        if budget.searches <= 0 or budget.reads <= 0:
            break
        if cache.get(_key(name)):
            continue
        asked.append(name)
        tech = techs.get(_norm(name))
        ids, total, complete = _search(client, budget, name, tech)
        stored = _store_missing(client, budget, ids, created)
        if total is not None and total > SEARCH_DEPTH:
            # more than one search reaches: one publication year at a time, newest first; a year already stored is not asked again
            complete = True
            for year, window in _windows(now):
                if cache.get(_key(name, year)):
                    continue
                if budget.searches <= 0 or budget.reads <= 0:
                    complete = False
                    break
                year_ids, _year_total, year_complete = _search(client, budget, name, tech, window)
                year_stored = _store_missing(client, budget, year_ids, created)
                if year_complete and year_stored and year < now.year:
                    cache.set(_key(name, year), now.isoformat(), int(DONE_FOR.total_seconds()) * 4)
                complete = complete and year_complete and year_stored
        if complete and stored:
            cache.set(_key(name), now.isoformat(), int(DONE_FOR.total_seconds()))
            done.append(name)
    return {'products': asked, 'done': done, 'created': created, 'searches': searches - budget.searches, 'reads': reads - budget.reads}
