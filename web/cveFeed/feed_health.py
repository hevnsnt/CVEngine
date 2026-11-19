"""When each CVE feed last worked, and what an operator should look at when one did not (System status, ``feeds``).

Every feed run records its outcome here, a read that found nothing new included, so a quiet feed and a broken one never look the same.
The record is an ``IntelSource`` row named ``feed:<name>`` (the same columns the threat-intelligence sources keep): ``last_checked`` is
the last attempt, ``last_changed`` the last success, ``last_error`` what the last attempt said when it failed (empty after a success).

``status()`` reads only these rows, the coverage watermark and the threat-intelligence sources: a few small queries, never a count of
the catalog, so the status page answers inside its probe budget.
"""
import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

PREFIX = 'feed:'
# how long each feed may go without a success before it is a problem: a few of its runs
STALE_AFTER = {
    'cve_now_sync': timedelta(hours=3),        # every 30 minutes
    'cve_now_changes': timedelta(hours=3),     # with every sync
    'cve_now_backfill': timedelta(hours=30),   # hourly, a complete walk at least every 6 hours
    'inventory_import': timedelta(days=3),     # every 6 hours, while there is inventory
    'distro_sync': timedelta(hours=60),        # daily
    'threat_intel': timedelta(hours=6),        # hourly
}
LABELS = {'cve_now_sync': 'cve.now sync', 'cve_now_changes': 'cve.now changes', 'cve_now_backfill': 'cve.now coverage walk',
          'inventory_import': 'inventory CVE history', 'distro_sync': 'distribution fixes', 'threat_intel': 'threat intelligence'}
INTEL_STALE = timedelta(hours=48)  # a threat-intelligence source not read for this long (its own TTL is a day at most)
CHANGES_BEHIND = timedelta(hours=6)  # the change listing this far behind the present: CVE updates are not being applied


def record(name, ok, error='', detail=None):
    """Note one run of feed ``name``: ``ok`` (a success, even one that found nothing) or failed with ``error``. ``detail`` (a short text,
    such as the change listing's position) is kept in ``last_modified``. Never raises: a monitoring write must not fail the feed."""
    try:
        from cveFeed.models import IntelSource
        now = timezone.now()
        fields = {'last_checked': now, 'last_error': '' if ok else (str(error) or 'failed')[:300]}
        if ok:
            fields['last_changed'] = now
        if detail is not None:
            fields['last_modified'] = str(detail)[:100]
        row, _ = IntelSource.objects.get_or_create(name=(PREFIX + name)[:32])
        IntelSource.objects.filter(pk=row.pk).update(**fields)
    except Exception:  # noqa: BLE001
        logger.exception('could not record the outcome of the %s feed', name)


def _iso(value):
    return value.isoformat() if value else None


def status(now=None):
    """``{"feeds": {name: {...}}, "intel": {source: {...}}, "watermark": {...}, "problems": [...]}``."""
    from cveFeed import feed_watermark, intel
    from cveFeed.models import IntelSource
    now = now or timezone.now()
    problems, feeds, sources = [], {}, {}
    rows = {r.name: r for r in IntelSource.objects.all()}
    for name, stale in STALE_AFTER.items():
        row = rows.get(PREFIX + name)
        label = LABELS[name]
        entry = {'last_attempt': _iso(row.last_checked) if row else None, 'last_success': _iso(row.last_changed) if row else None,
                 'last_error': (row.last_error or None) if row else None, 'detail': (row.last_modified or None) if row else None}
        feeds[name] = entry
        if row is None or not row.last_checked:
            continue  # never run here (a feed that is off, or an install younger than its first run): nothing to judge
        if row.last_error:
            problems.append(f'feeds: the last {label} run failed: {row.last_error}')
        elif row.last_changed and now - row.last_changed > stale:
            problems.append(f'feeds: {label} has not succeeded for {int((now - row.last_changed).total_seconds() // 3600)} hours')
    changes = rows.get(PREFIX + 'cve_now_changes')
    position = _parse(changes.last_modified) if changes else None
    if position and now - position > CHANGES_BEHIND:
        problems.append(f'feeds: cve.now changes are applied up to {position.isoformat()}, '
                        f'{int((now - position).total_seconds() // 3600)} hours behind')
    try:
        enabled = set(intel.enabled_sources())
    except Exception:  # noqa: BLE001
        enabled = set()
    for name in sorted(enabled):
        row = rows.get(name)
        sources[name] = {'last_checked': _iso(row.last_checked) if row else None, 'last_changed': _iso(row.last_changed) if row else None,
                         'last_error': (row.last_error or None) if row else None, 'cves': row.cves if row else 0}
        if row and row.last_error:
            problems.append(f'feeds: threat intelligence source {name} failed: {row.last_error}')
        elif row and row.last_checked and now - row.last_checked > INTEL_STALE:
            problems.append(f'feeds: threat intelligence source {name} has not been read for '
                            f'{int((now - row.last_checked).total_seconds() // 3600)} hours')
    watermark = feed_watermark.status(now)
    if watermark.get('behind') and watermark.get('covered_through'):
        problems.append(f"feeds: the CVE catalog is known complete only through {watermark['covered_through']} "
                        f"({watermark['lag_hours']} hours behind)")
    if watermark.get('unreadable'):
        problems.append(f"feeds: cve.now entries listed but unreadable on every try: {', '.join(watermark['unreadable'][:5])}")
    return {'feeds': feeds, 'intel': sources, 'watermark': watermark, 'problems': problems}


def _parse(value):
    from django.utils.dateparse import parse_datetime
    try:
        return parse_datetime(value) if value else None
    except (TypeError, ValueError):
        return None
