"""How far the CVE feed is known to be complete, and the walk that keeps it so.

A snapshot (the seed) carries its own point in time; the incremental sync only reads what is new, and can fall behind (a worker that
was off, a backlog bigger than one run reads). The standard answer (NVD's modified-since requests, OSV's ``modified_id.csv``, the CVE
List's baseline plus rolling deltas) is a watermark in the listing's own sort-key domain: everything after it has been read, a walk
goes back to a little before it (entries the feed saw late are listed by their publication time, not when they arrived), and the
watermark moves only past a window that was read in full. cve.now lists newest first by ``publishedAt`` (a keyset cursor over it and
the id); an entry's ``firstSeenAt`` trails it by minutes at the median and by more than a day at the tail, so the margin is days.

``covered_through`` is that watermark (cveFeed.models.FeedWatermark). Nothing here asks the network except ``walk``.
"""
import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

SOURCE = 'cve_now'
MARGIN = timedelta(days=3)           # how long after its publication time the feed may have first seen an entry (measured tail: about 27 hours)
LEGACY_DAYS = 30                     # no watermark yet (an install from before it, or no seed): read back this far once
RECHECK = timedelta(hours=6)         # a walk that reached its floor is not repeated sooner than this
STALE_AFTER = timedelta(hours=24)    # a feed that has not been read to its head for this long is reported as behind
ENTRIES_PER_DAY = 800                # about what the feed lists in a day at most: how deep a walk back has to read
MAX_SCAN = 40000


def current():
    from cveFeed.models import FeedWatermark
    return FeedWatermark.objects.get_or_create(source=SOURCE)[0]


def note_snapshot(covers_through):
    """A seed was imported: the feed is complete through ``covers_through`` at most (the newest publication time the snapshot holds).
    The earlier of this and what is already known stands, and a walk in progress is dropped (its head is out of date)."""
    if covers_through is None:
        return
    row = current()
    if row.covered_through is None or covers_through < row.covered_through:
        row.covered_through = covers_through
    row.resume_cursor, row.resume_head, row.checked_at = '', None, None
    row.save()


def floor_for(row, now, window_days=0):
    """The oldest publication time a walk has to read back to: a little before the watermark, or ``LEGACY_DAYS`` (at least the
    configured coverage window) back when there is none."""
    if row.covered_through is not None:
        return row.covered_through - MARGIN
    return now - timedelta(days=max(LEGACY_DAYS, window_days))


def scan_budget(floor, now, base):
    """How many listed entries a walk to ``floor`` may read."""
    return max(base, min(MAX_SCAN, max(0, (now - floor).days) * ENTRIES_PER_DAY + 1000))


def status(now=None):
    """What an operator sees: the feed is complete through ``covered_through``, so many hours behind the present."""
    now = now or timezone.now()
    row = current()
    through = row.covered_through
    lag = None if through is None else max(0.0, (now - through).total_seconds() / 3600)
    return {'covered_through': through.isoformat() if through else None, 'lag_hours': None if lag is None else round(lag, 1),
            'walk_in_progress': bool(row.resume_cursor),
            'last_complete_walk': row.checked_at.isoformat() if row.checked_at else None,
            'behind': bool(through is None or now - through > STALE_AFTER)}


def published(summary):
    """The listing's sort key for one summary: its publication time (the first-seen time only when that is all there is)."""
    from cveFeed.tasks import _parse_time
    return _parse_time(summary.get('publishedAt')) or _parse_time(summary.get('firstSeenAt'))
