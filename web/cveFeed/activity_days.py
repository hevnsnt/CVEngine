"""The dashboard's "Activity, last 90 days" card: exact per-day counts, not a sample.

The card used to page through the Findings list (hottest first) and the Changes list (newest first), 200 rows a page and five pages at most, and
count what came back. Past 1,000 rows the numbers were the size of that fetch, not statistics: every big project read "1,000". It now asks the
database to count, one GROUP BY per series:

* ``findings`` is one grouped query per finding type (CVE match, scanner finding, hygiene finding) over the very same querysets the Findings
  page lists with ``status=all`` (``agentapi.services._finding_sources``: same project scope, same heat and severity rules, same "latest scan"
  rule for CVE matches), counted by the day each was first seen, split by heat tier;
* ``changes`` is one grouped query over the inventory changes the Changes page lists, by the day detected.

A day is a calendar day in the viewer's time zone (``tz``, an IANA name the browser sends; UTC when absent or unknown), the days of the window are the
last ``days`` of them including today, and ``total`` is exactly the sum of the days shown, so the card's headline and its cells always agree.
Rows with no date (a scanner finding that never recorded one) cannot be placed on a day and are not in a window.
"""
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

DEFAULT_DAYS = 90
MAX_DAYS = 366
TIERS = ('fire', 'smoke', 'ice')
TYPES = ('cve', 'scanner', 'hygiene')


def zone_of(name):
    """The time zone named ``name`` (an IANA name), or UTC when it is empty or not one."""
    try:
        return ZoneInfo(str(name or '').strip() or 'UTC')
    except Exception:  # noqa: BLE001 - ZoneInfoNotFoundError, ValueError (a path-like name), OSError: all mean "not a zone"
        return ZoneInfo('UTC')


def window(days, zone, now=None):
    """``(first day, last day, start, end)``: the calendar days of the window in ``zone`` and the instants they span (start inclusive, end exclusive)."""
    today = (now or timezone.now()).astimezone(zone).date()
    first = today - timedelta(days=days - 1)
    return (first, today, datetime.combine(first, time.min, tzinfo=zone), datetime.combine(today + timedelta(days=1), time.min, tzinfo=zone))


def tier_of(heat_rank, sev):
    """The tier a finding is drawn in: its heat (3 fire, 2 smoke, 1 ice); one with no heat by its severity (high and critical fire, medium smoke, the rest ice)."""
    if heat_rank in (1, 2, 3):
        return TIERS[3 - heat_rank]
    return 'fire' if (sev or 0) >= 3 else 'smoke' if sev == 2 else 'ice'


def _busiest(days):
    best = None
    for d in days:  # chronological: the first of equal days wins, as the card always showed
        if best is None or d['n'] > best['n']:
            best = d
    return {'date': best['date'], 'n': best['n'], **{t: best.get(t, 0) for t in TIERS if t in best}} if best and best['n'] else None


def findings_by_day(sources, zone, start, end):
    """Per-day findings of ``{type: queryset}`` (the Findings list's own sources): one grouped query each. ``[{date, n, fire, smoke, ice, cve, scanner, hygiene}]``, oldest first, only days with any."""
    days = {}
    for kind, qs in sources.items():
        rows = (qs.order_by().select_related(None).filter(when__gte=start, when__lt=end)
                .annotate(day=TruncDate('when', tzinfo=zone)).values('day', 'heat_rank', 'sev').annotate(n=Count('id')))
        for row in rows:
            d = days.setdefault(row['day'], {'date': row['day'].isoformat(), 'n': 0, 'fire': 0, 'smoke': 0, 'ice': 0, **{t: 0 for t in TYPES}})
            d['n'] += row['n']
            d[tier_of(row['heat_rank'], row['sev'])] += row['n']
            d[kind] += row['n']
    return [days[k] for k in sorted(days)]


def changes_by_day(qs, zone, start, end):
    """Per-day inventory changes of ``qs`` (the Changes list's queryset, any order): one grouped query. ``[{date, n}]``, oldest first, only days with any."""
    rows = (qs.order_by().filter(detected_at__gte=start, detected_at__lt=end)
            .annotate(day=TruncDate('detected_at', tzinfo=zone)).values('day').annotate(n=Count('id')).order_by('day'))
    return [{'date': r['day'].isoformat(), 'n': r['n']} for r in rows]


def scans_by_day(qs, zone, start, end):
    """Per-day scans started of ``qs`` (the Scans list's queryset): one grouped query. ``[{date, n}]``, oldest first, only days with any."""
    rows = (qs.order_by().filter(start_scan_date__gte=start, start_scan_date__lt=end)
            .annotate(day=TruncDate('start_scan_date', tzinfo=zone)).values('day').annotate(n=Count('id')).order_by('day'))
    return [{'date': r['day'].isoformat(), 'n': r['n']} for r in rows]


def build(sources=None, changes_qs=None, days=DEFAULT_DAYS, tz='', now=None, scans_qs=None):
    """The payload for the series asked for (a ``None`` queryset is a series not asked for, and costs no query): Findings ``sources`` (already
    scoped to the caller's projects), the Changes queryset and the Scans queryset."""
    zone = zone_of(tz)
    first, last, start, end = window(days, zone, now)
    out = {'days': days, 'tz': str(zone), 'first': first.isoformat(), 'last': last.isoformat(),
           'since': start.astimezone(ZoneInfo('UTC')).isoformat().replace('+00:00', 'Z')}
    if sources is not None:
        found = findings_by_day(sources, zone, start, end)
        out['findings'] = {'total': sum(d['n'] for d in found), 'by_tier': {t: sum(d[t] for d in found) for t in TIERS},
                           'by_type': {t: sum(d[t] for d in found) for t in TYPES}, 'busiest': _busiest(found), 'days': found}
    for key, qs, fn in (('changes', changes_qs, changes_by_day), ('scans', scans_qs, scans_by_day)):
        if qs is not None:
            rows = fn(qs, zone, start, end)
            out[key] = {'total': sum(d['n'] for d in rows), 'busiest': _busiest(rows), 'days': rows}
    return out
