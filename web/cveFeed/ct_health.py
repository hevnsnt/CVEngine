"""Whether the certificate transparency watch works, per source (System status, Settings, Timings, the ``ct_watch_stalled`` notice).

Every real lookup of the standalone watch (cveFeed.ctmonitor) records its outcome for its source here: ``ok`` with the names the source
gave and the hosts that were new, ``failed`` with why, or ``busy`` (the source's shared pacing held it back for later). The record is a
daily rollup, one ``CtLookupDay`` row per source and UTC day, so the table stays small whatever the number of lookups. Rows older than
``KEEP_DAYS`` are deleted when a day's first row is written. Every function here is non-fatal: a monitoring write never fails a lookup.

In a Celery worker (``install``) the outcomes are added up in memory and written by a timer every ``FLUSH_SECONDS``: one additive
``UPDATE`` per source and day (``ok = ok + n``, the newest time of each kind kept with ``GREATEST``), so any number of processes can
write the same row without losing a count, and a lookup never waits for this row. Every crt.sh lookup held back by pacing used to write
the row itself, and those writes queued on its row lock behind each other's commits: a third of all database statement time. The
worker writes what is left when it stops (``worker_shutdown``, ``worker_process_shutdown``, ``atexit``), and a write that fails is kept
for the next one. Elsewhere (the web, a management command, tests) each outcome is written at once, as before.
"""
import atexit
import logging
import threading
import time
from datetime import timedelta

from django.db.models import Case, F, Max, Q, Value, When
from django.db.models.functions import Greatest
from django.utils import timezone

logger = logging.getLogger(__name__)

KEEP_DAYS = 30
STALL_HOURS = 3  # no source answered for this long while lookups were attempted: the ct_watch_stalled notice
OUTCOMES = ('ok', 'failed', 'busy')


FLUSH_SECONDS = 60  # how long a worker keeps outcomes in memory before it writes them: the status line lags by at most this much
_COUNTS = ('ok', 'failed', 'busy', 'names', 'new_hosts')
_STAMPS = ('last_ok_at', 'last_attempt_at', 'last_failed_at')
_lock = threading.Lock()
_pending = {}  # (day, source): {the counts to add, the newest time of each kind, the error of the newest failure}
_state = {'batching': False, 'flusher': False}


def record(source, outcome, names=0, new=0, error='', now=None):
    """Count one lookup of ``source`` with ``outcome`` (``ok``, ``failed`` or ``busy``) in today's row: at once, or with the next flush
    in a worker (``install``)."""
    if outcome not in OUTCOMES:
        return
    try:
        now = now or timezone.now()
        names, new = max(0, int(names)), max(0, int(new))
        with _lock:  # no I/O while held: a greenlet never yields here
            entry = _pending.setdefault((now.date(), source), dict.fromkeys(_COUNTS, 0))
            entry[outcome] += 1
            _later(entry, 'last_attempt_at', now)
            if outcome == 'ok':
                entry['names'] += names
                entry['new_hosts'] += new
                _later(entry, 'last_ok_at', now)
            elif outcome == 'failed' and _later(entry, 'last_failed_at', now):
                entry['last_error'] = (str(error) or 'failed')[:300]
        if not _state['batching']:
            flush()
    except Exception:  # noqa: BLE001
        logger.exception('could not record a certificate transparency lookup of %s', source)


def _later(entry, field, at):
    """Keep ``at`` as ``entry[field]`` when it is the newest so far; True when it was kept."""
    if entry.get(field) is None or at >= entry[field]:
        entry[field] = at
        return True
    return False


def _merge(key, entry):
    """Put a batch whose write failed back with what was counted meanwhile, so the next flush writes both."""
    with _lock:
        into = _pending.setdefault(key, dict.fromkeys(_COUNTS, 0))
        for name in _COUNTS:
            into[name] += entry[name]
        for name in ('last_ok_at', 'last_attempt_at'):
            if entry.get(name):
                _later(into, name, entry[name])
        if entry.get('last_failed_at') and _later(into, 'last_failed_at', entry['last_failed_at']):
            into['last_error'] = entry.get('last_error', '')


def flush():
    """Write every outcome counted in this process and not written yet: one ``UPDATE`` per source and day. Returns the rows written.
    A batch whose write fails stays for the next flush. Never raises."""
    with _lock:
        if not _pending:
            return 0
        batch = dict(_pending)
        _pending.clear()
    written = 0
    for key, entry in sorted(batch.items(), key=lambda item: (item[0][0], item[0][1])):
        try:
            _write(key, entry)
            written += 1
        except Exception:  # noqa: BLE001
            _merge(key, entry)
            logger.exception('could not write the certificate transparency lookups of %s on %s; kept for the next write', key[1], key[0])
    return written


def _write(key, entry):
    from cveFeed.models import CtLookupDay
    day, source = key
    fields = {name: F(name) + entry[name] for name in _COUNTS if entry[name]}
    for name in _STAMPS:
        if entry.get(name):
            fields[name] = Greatest(F(name), Value(entry[name]))  # GREATEST skips NULL: a first time is taken as it is
    if entry.get('last_failed_at'):
        fields['last_error'] = Case(When(Q(last_failed_at__isnull=True) | Q(last_failed_at__lte=entry['last_failed_at']),
                                         then=Value(entry['last_error'])), default=F('last_error'))
    if not CtLookupDay.objects.filter(day=day, source=source).update(**fields):
        _, created = CtLookupDay.objects.get_or_create(day=day, source=source)
        CtLookupDay.objects.filter(day=day, source=source).update(**fields)
        if created:
            CtLookupDay.objects.filter(day__lt=day - timedelta(days=KEEP_DAYS)).delete()


def _flush_and_release():
    """One timer tick: write, then give back the database connection this greenlet or thread opened, so it holds none between ticks."""
    try:
        flush()
    finally:
        try:
            from django.db import connection
            connection.close()
        except Exception:  # noqa: BLE001
            pass


def _loop(sleep=time.sleep, ticks=None):
    while ticks is None or ticks > 0:
        sleep(FLUSH_SECONDS)
        try:
            if _pending:
                _flush_and_release()
        except Exception:  # noqa: BLE001 - housekeeping must never end the timer
            logger.exception('ct_health: the timed write failed')
        if ticks is not None:
            ticks -= 1


def start_batching():
    """From now on this process adds the outcomes up and a timer writes them every ``FLUSH_SECONDS`` (a greenlet in a gevent worker, a
    daemon thread otherwise). What is left is written when the process stops."""
    if _state['flusher']:
        _state['batching'] = True
        return
    from reNgine import gevent_db
    if gevent_db.gevent_patched():
        import gevent
        gevent.spawn(_loop, gevent.sleep)
    else:
        threading.Thread(target=_loop, name='ct-health-flush', daemon=True).start()
    _state['flusher'] = True
    _state['batching'] = True


def _stopping(**kwargs):
    flush()


def _in_worker():
    """True in a real worker process (started with ``-n``, as every lane is): a test that sends the worker signals starts no timer."""
    from reNgine import lane_memory
    return bool(lane_memory.lane_name())


def _worker_ready(**kwargs):
    if _in_worker():
        start_batching()


def _child_started(**kwargs):
    _state['flusher'] = False  # a forked pool process has no copy of its parent's timer thread
    _worker_ready()


def install():
    """Called once by the Celery app (reNgine/celery.py): batch the outcomes in a worker once it is ready, and write what is left when the
    worker or one of its processes stops, or the interpreter exits."""
    from celery.signals import worker_process_init, worker_process_shutdown, worker_ready, worker_shutdown
    worker_ready.connect(_worker_ready, weak=False, dispatch_uid='ct-health-batch')
    worker_process_init.connect(_child_started, weak=False, dispatch_uid='ct-health-batch-child')
    worker_shutdown.connect(_stopping, weak=False, dispatch_uid='ct-health-flush-worker')
    worker_process_shutdown.connect(_stopping, weak=False, dispatch_uid='ct-health-flush-child')
    atexit.register(flush)


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
