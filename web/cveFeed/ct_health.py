"""Whether the certificate transparency watch works, per source (System status, Settings, Timings, the ``ct_watch_stalled`` notice).

Every real lookup of the standalone watch (cveFeed.ctmonitor) records its outcome for its source here: ``ok`` with the names the source
gave and the hosts that were new, ``failed`` with why, or ``busy`` (the source's shared pacing held it back for later). The record is a
daily rollup, one ``CtLookupDay`` row per source and UTC day, so the table stays small whatever the number of lookups: one
``UPDATE`` per lookup, which runs at most every couple of seconds on the watch's own queue. Rows older than ``KEEP_DAYS`` are deleted
when a day's first row is written. Every function here is non-fatal: a monitoring write never fails a lookup.
"""
import logging
from datetime import timedelta

from django.db.models import F, Max
from django.utils import timezone

logger = logging.getLogger(__name__)

KEEP_DAYS = 30
STALL_HOURS = 3  # no source answered for this long while lookups were attempted: the ct_watch_stalled notice
OUTCOMES = ('ok', 'failed', 'busy')


def record(source, outcome, names=0, new=0, error='', now=None):
    """Count one lookup of ``source`` with ``outcome`` (``ok``, ``failed`` or ``busy``) in today's row."""
    if outcome not in OUTCOMES:
        return
    try:
        from cveFeed.models import CtLookupDay
        now = now or timezone.now()
        day = now.date()
        fields = {outcome: F(outcome) + 1, 'last_attempt_at': now}
        if outcome == 'ok':
            fields.update(names=F('names') + max(0, int(names)), new_hosts=F('new_hosts') + max(0, int(new)), last_ok_at=now)
        elif outcome == 'failed':
            fields.update(last_failed_at=now, last_error=(str(error) or 'failed')[:300])
        if not CtLookupDay.objects.filter(day=day, source=source).update(**fields):
            _, created = CtLookupDay.objects.get_or_create(day=day, source=source)
            CtLookupDay.objects.filter(day=day, source=source).update(**fields)
            if created:
                CtLookupDay.objects.filter(day__lt=day - timedelta(days=KEEP_DAYS)).delete()
    except Exception:  # noqa: BLE001
        logger.exception('could not record a certificate transparency lookup of %s', source)


def _ago(seconds):
    seconds = max(0, int(seconds))
    if seconds < 90:
        return 'just now' if seconds < 60 else '1 minute ago'
    if seconds < 90 * 60:
        return f'{round(seconds / 60)} minutes ago'
    if seconds < 36 * 3600:
        return f'{round(seconds / 3600)} hours ago'
    return f'{round(seconds / 86400)} days ago'


def _plural(n, word):
    return f'{n} {word}{"" if n == 1 else "s"}'


def summary(now=None):
    """``{"line", "today": {source: {...}}, "totals", "last_ok_at", "last_ok_source", "last_attempt_at", "fallback_enabled"}``. Two small
    reads: today's rows (at most one per source) and the newest success and attempt of every kept row."""
    from cveFeed import ctmonitor
    from cveFeed.models import CtLookupDay
    now = now or timezone.now()
    today = {}
    for row in CtLookupDay.objects.filter(day=now.date()).order_by('source'):
        today[row.source] = {'ok': row.ok, 'failed': row.failed, 'busy': row.busy, 'names': row.names, 'new_hosts': row.new_hosts,
                             'last_ok_at': _iso(row.last_ok_at), 'last_failed_at': _iso(row.last_failed_at), 'last_error': row.last_error or None}
    totals = {k: sum(v[k] for v in today.values()) for k in ('ok', 'failed', 'busy', 'new_hosts')}
    newest = CtLookupDay.objects.filter(last_ok_at__isnull=False).order_by('-last_ok_at').values_list('last_ok_at', 'source').first()
    last_attempt = CtLookupDay.objects.aggregate(at=Max('last_attempt_at'))['at']
    last_ok_at, last_ok_source = newest if newest else (None, None)
    if last_ok_at:
        head = f'last successful lookup {_ago((now - last_ok_at).total_seconds())} ({last_ok_source})'
    elif last_attempt:
        head = 'no successful lookup yet'
    else:
        head = 'no lookup yet'
    line = (f"Certificate Transparency: {head}, {_plural(totals['ok'], 'lookup')} ok, {totals['failed']} failed, "
            f"{_plural(totals['new_hosts'], 'new host')} today")
    fallback = [s for s in today if s != ctmonitor.CRTSH and today[s]['ok']]
    if fallback:
        line += ' (' + ', '.join(f"{today[s]['ok']} answered by {s}" for s in fallback) + ')'
    return {'line': line, 'today': today, 'totals': totals, 'last_ok_at': _iso(last_ok_at), 'last_ok_source': last_ok_source,
            'last_attempt_at': _iso(last_attempt), 'fallback_enabled': ctmonitor.fallback_enabled()}


def stalled_check(now=None):
    """The ``ct_watch_stalled`` operations check: ``{state, title, detail, facts}``. ``ok`` when a source answered within ``STALL_HOURS``, or
    when nothing was attempted in that time (no target to watch, the sweep idle or scanning paused, a restart); ``warning`` when lookups were
    attempted and none succeeded, naming each source's failures and its last error."""
    from cveFeed.models import CtLookupDay
    now = now or timezone.now()
    since = now - timedelta(hours=STALL_HOURS)
    rows = list(CtLookupDay.objects.filter(day__gte=since.date()))
    attempted = [r for r in rows if r.last_attempt_at and r.last_attempt_at >= since]
    succeeded = [r for r in rows if r.last_ok_at and r.last_ok_at >= since]
    if not attempted:
        return {'state': 'ok', 'title': 'Certificate transparency watch: nothing to look up lately', 'detail': '', 'facts': {'attempted': False}}
    if succeeded:
        newest = max(succeeded, key=lambda r: r.last_ok_at)
        return {'state': 'ok', 'title': 'Certificate transparency lookups succeed', 'detail': '',
                'facts': {'attempted': True, 'last_ok_source': newest.source}}
    by_source = {}
    for r in rows:
        if r.last_attempt_at and r.last_attempt_at >= since:
            entry = by_source.setdefault(r.source, {'failed': 0, 'busy': 0, 'last_error': ''})
            entry['failed'] += r.failed
            entry['busy'] += r.busy
            if r.last_error and (not entry.get('_at') or (r.last_failed_at and r.last_failed_at > entry['_at'])):
                entry['last_error'], entry['_at'] = r.last_error, r.last_failed_at
    for entry in by_source.values():
        entry.pop('_at', None)
    last_ok = CtLookupDay.objects.aggregate(at=Max('last_ok_at'))['at']
    parts = []
    for source, entry in sorted(by_source.items()):
        what = []
        if entry['failed']:
            what.append(f"{entry['failed']} failed today" + (f" (last: {entry['last_error']})" if entry['last_error'] else ''))
        if entry['busy']:
            what.append(f"{entry['busy']} held back by its rate limit today")
        parts.append(f"{source}: {', '.join(what) or 'no answer'}")
    detail = (f'No certificate transparency source answered a lookup in the last {STALL_HOURS} hours, so new hosts with a certificate are not '
              f"found between discoveries. {'; '.join(parts)}. "
              + (f'The last successful lookup was {_ago((now - last_ok).total_seconds())}. ' if last_ok else 'No lookup has succeeded yet. ')
              + 'The lookups are tried again on their own; check that this server can reach crt.sh and api.certspotter.com (Settings, Timings, '
                'CT fallback source).')
    return {'state': 'warning', 'title': 'Certificate transparency lookups are failing', 'detail': detail,
            'facts': {'attempted': True, 'sources': {s: {'failing': bool(e['failed']), 'busy': bool(e['busy'])} for s, e in by_source.items()},
                      'last_errors': {s: e['last_error'] for s, e in by_source.items() if e['last_error']},
                      'counts': {s: {'failed': e['failed'], 'busy': e['busy']} for s, e in by_source.items()}}}


def _iso(value):
    return value.isoformat() if value else None
