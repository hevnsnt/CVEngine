"""What the outer watchdog looks at (cveFeed.watchdog, docs/WATCHDOG.md): one cheap, bounded snapshot of the instance.

Every part is read by its own probe, each wrapped so a failure becomes ``None`` ("could not tell"), never an exception: a rule never acts on a part
that is ``None``, so a Redis that does not answer cannot make the watchdog restart the workers. Nothing here starts a Celery task or waits on a
Celery consumer, because the watchdog must keep working when the lanes are the thing that is broken. The slow part is one broadcast to the
workers (``active_queues``, at most ``PING_SECONDS`` when a lane is silent, a few milliseconds when all four answer); the rest is a few Redis
reads and a handful of small, indexed queries with a statement timeout.

The probes are methods of ``Probes`` so a test can replace any of them; ``collect`` returns a plain JSON-able dict.
"""
import json
import logging
import os
import shutil
import time

logger = logging.getLogger(__name__)

PING_SECONDS = 3  # a broadcast to the workers waits this long for a silent lane; it returns at once when all four have answered
UNACKED_KEY = 'unacked'
UNACKED_INDEX_KEY = 'unacked_index'
PRIORITY_SUFFIXES = ('', '\x06\x163', '\x06\x166', '\x06\x169')  # kombu's Redis priority steps share one queue name
STALE_SCAN_MINUTES = 30  # a scan running this long with no activity is a candidate for R9 (the real test is ghost_scans.find)


def _lane_table():
    from cveFeed.admin_api import WORKERS  # {worker name prefix: queue}: the layout of celery-entrypoint.sh, one definition
    return dict(WORKERS)


class Probes:
    """The reads. Each returns data or raises; ``collect`` turns a raise into None."""

    def __init__(self, now=None):
        self.now = now or time.time()

    def redis(self):
        from reNgine import resources
        client = resources.redis_client()
        if client is None:
            raise RuntimeError('the broker is not Redis')
        client.ping()
        return client

    def queues(self):
        """{queue: messages waiting}, every priority step added up."""
        client = self.redis()
        out = {}
        for queue in set(_lane_table().values()) | {'default'}:
            out[queue] = sum(int(client.llen(queue + suffix) or 0) for suffix in PRIORITY_SUFFIXES)
        return out

    def unacked(self):
        client = self.redis()
        count = int(client.zcard(UNACKED_INDEX_KEY) or 0)
        oldest = client.zrange(UNACKED_INDEX_KEY, 0, 0, withscores=True) if count else []
        return {'count': count, 'oldest_age_seconds': int(max(0, self.now - oldest[0][1])) if oldest else 0}

    def lanes(self):
        """{worker name: [queues it consumes]} from one broadcast; {} when no worker answered. Raises when the broker cannot be asked."""
        from reNgine.celery import app
        answer = app.control.inspect(timeout=PING_SECONDS, limit=len(_lane_table())).active_queues()
        return {name: [q.get('name') for q in (queues or [])] for name, queues in (answer or {}).items()}

    def lane_work(self, workers=None):
        """{worker name: {'completed': tasks finished since it started, 'active': tasks running, 'capacity': its pool ceiling or None, 'pid': its process id or None}}: what R2 needs, asked
        only while a queue has messages waiting, and only of the workers that answered (so it returns as soon as they have)."""
        from reNgine.celery import app
        inspector = app.control.inspect(timeout=PING_SECONDS, destination=list(workers) if workers else None, limit=len(workers) if workers else len(_lane_table()))
        stats, active = inspector.stats() or {}, inspector.active() or {}
        out = {}
        for name, info in stats.items():
            info = info or {}
            total = info.get('total') or {}
            pool = info.get('pool') or {}
            ceiling = (info.get('autoscaler') or {}).get('max') or pool.get('max-concurrency')
            out[name] = {'completed': sum(v for v in total.values() if isinstance(v, int)),
                         'active': len(active.get(name) or []), 'capacity': ceiling if isinstance(ceiling, int) else None,
                         'pid': info.get('pid') if isinstance(info.get('pid'), int) else None}
        return out

    def beat_age(self):
        from cveFeed import scan_control
        beat = scan_control.beat_heartbeat()
        return None if beat is None else int(max(0, self.now - beat))

    def conductor(self):
        from cveFeed import conductor
        last = conductor.last_round()
        if not last or not last.get('at'):
            return {'age_seconds': None}
        from datetime import datetime, timezone
        at = datetime.fromisoformat(last['at'])
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        return {'age_seconds': int(max(0, self.now - at.timestamp()))}

    def sentinels(self):
        from agentapi import sentinel_broker
        from cveFeed import coverage_topup
        slots = int(sentinel_broker.total_slots() or 0)
        waiting = int(sentinel_broker.waiting_tasks() or 0)
        busy = 0
        if slots:
            from agentapi.models import SENTINEL_ACTIVE_STATUSES, SentinelTask
            busy = SentinelTask.objects.filter(status__in=SENTINEL_ACTIVE_STATUSES).count()
        due = None
        if slots and not waiting:
            due = bool(coverage_topup.backlog_exists())
            if not due:
                due = self._planner_due()
        return {'slots': slots, 'busy': min(busy, slots), 'free': max(slots - busy, 0), 'waiting': waiting, 'due': due}

    @staticmethod
    def _planner_due():
        """True when the work planner (cveFeed.work_planner) has checks ready for a Sentinel (due and past the route check), from its cached census."""
        try:
            from cveFeed import work_planner
            if not work_planner.enabled():
                return False
            return any(row.get('ready', 0) > 0 for row in work_planner.overview()['kinds'])
        except Exception:  # noqa: BLE001 - the planner is an extra reason to feed, never a reason to fail the snapshot
            return False

    def discovery(self):
        from cveFeed import scan_concurrency
        key = 'discovery_concurrency'
        field = scan_concurrency.BY_KEY[key]
        row = scan_concurrency.saved_row()
        got = scan_concurrency.resolve(key, {k: v for k, v in (row.values or {}).items() if k in scan_concurrency.BY_KEY},
                                       scan_concurrency._tuned_from_database())
        meta = (row.meta or {}).get(key) or {}
        running = scan_concurrency.running_discovery()
        return {'value': got['value'], 'source': got['source'], 'env_name': field.env, 'env_value': scan_concurrency.env_value(field),
                'env_pinned': scan_concurrency.env_pin(field), 'floor': field.auto_min, 'saved_by': meta.get('by') if got['source'] == 'admin' else None,
                'running': running['value']}

    def assessments(self):
        from cveFeed.models import HostAssessment
        return HostAssessment.objects.filter(status='queued').count()

    def db(self):
        from django.db import connection
        with connection.cursor() as cur:
            cur.execute('SHOW max_connections')
            maximum = int(cur.fetchone()[0])
            cur.execute("SELECT count(*), coalesce(max(extract(epoch FROM now() - xact_start)) FILTER (WHERE state = 'idle in transaction'), 0) "
                        'FROM pg_stat_activity WHERE datname = current_database()')
            count, idle_tx = cur.fetchone()
        return {'connections': int(count), 'max': maximum, 'idle_in_transaction_seconds': int(idle_tx or 0)}

    def disk(self):
        from django.conf import settings
        usage = shutil.disk_usage(getattr(settings, 'RENGINE_HOME', '/') or '/')
        return {'free_mb': usage.free // (1 << 20), 'total_mb': usage.total // (1 << 20), 'free_pct': round(100 * usage.free / usage.total, 1) if usage.total else None}

    def memory(self):
        """[{host, used_pct}] of every container that published its memory, and this one."""
        from reNgine import resources
        out = []
        for c in (resources.cluster_snapshot().get('containers') or []):
            mem = c.get('memory') or {}
            limit = mem.get('limit_mb') or mem.get('total_mb')
            if limit and mem.get('used_mb') is not None and c.get('age_seconds', 0) < 180:
                out.append({'host': str(c.get('host'))[:40], 'used_pct': round(100 * mem['used_mb'] / limit, 1)})
        return out

    def scans(self):
        from datetime import timedelta

        from django.db.models import Max
        from django.utils import timezone

        from startScan.models import ScanHistory
        cutoff = timezone.now() - timedelta(minutes=STALE_SCAN_MINUTES)
        running = ScanHistory.objects.filter(scan_status=1)
        stale = (running.filter(start_scan_date__lt=cutoff).annotate(last=Max('scanactivity__time')).filter(last__lt=cutoff).count()
                 if running.exists() else 0)
        return {'running': running.count(), 'queued': ScanHistory.objects.filter(scan_status=-1).count(), 'stale_candidates': stale}

    def update(self):
        return update_state()


def update_state():
    """Whether an update owns the stack right now, from what the web container can see: the approval marker, the phase file and the update lock.
    ``active`` is True when any of them says so. The host script checks the same markers and also the host-only lock (scripts/watchdog.sh)."""
    from django.conf import settings

    from cveFeed import updater
    phase = 'idle'
    in_progress = False
    try:
        phase = updater.read_phase().get('phase') or 'idle'
        in_progress = updater.update_in_progress()  # a phase nobody refreshed for two hours is a script that died, not an update
    except Exception:  # noqa: BLE001
        logger.debug('watchdog: update phase unreadable', exc_info=True)
    approved = os.path.lexists(updater._file('.update-approved'))
    locked = _lock_held(os.path.join(getattr(settings, 'RENGINE_HOME', '') or '', '.update-lock'))
    return {'phase': phase, 'approved': approved, 'locked': locked, 'active': in_progress or approved or locked, 'warming_up': _just_updated(phase)}


WARMUP_SECONDS = 600  # a worker lane of a freshly started stack can take minutes to answer its first ping (the CVE-feed lane took about ten on 11/9)


def _just_updated(phase):
    """True for ``WARMUP_SECONDS`` after an update finished: the containers were just recreated and their lanes are still starting. Restarting them again
    in that window (the watchdog did, 10 seconds after the 11/9 update, and then reported "could not fix it") only starts the warm-up over."""
    if phase != 'done':
        return False
    try:
        from datetime import datetime

        from django.utils import timezone

        from cveFeed import updater
        changed = updater.read_phase().get('changed_at')
        return bool(changed) and (timezone.now() - datetime.fromisoformat(changed)).total_seconds() < WARMUP_SECONDS
    except Exception:  # noqa: BLE001 - unreadable means no grace, as before
        return False


def _lock_held(path):
    """Whether another process holds the lock file, tested without waiting and without keeping it. A file that cannot be opened is not held."""
    import fcntl
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


SECTIONS = ('queues', 'unacked', 'lanes', 'beat_age', 'conductor', 'sentinels', 'discovery', 'assessments', 'db', 'disk', 'memory', 'scans', 'update')


def collect(probes=None, now=None):
    """The snapshot: ``{'at', 'redis_ok', <section>: data or None, 'errors': {section: short reason}, 'seconds'}``. Never raises (a time limit's own exception
    is the one thing let through: it derives from BaseException on purpose)."""
    started = time.time()
    probes = probes or Probes(now)
    snap, errors = {'at': now or started}, {}
    for name in SECTIONS:
        try:
            snap[name] = getattr(probes, name)()
        except Exception as exc:  # noqa: BLE001 - one unreadable part must not hide the others
            snap[name] = None
            errors[name] = f'{type(exc).__name__}: {str(exc)[:80]}'
    snap['redis_ok'] = snap['queues'] is not None
    if snap['queues'] and any(snap['queues'].values()) and snap['lanes']:
        try:
            snap['lane_work'] = probes.lane_work(sorted(snap['lanes']))
        except Exception as exc:  # noqa: BLE001
            snap['lane_work'] = None
            errors['lane_work'] = f'{type(exc).__name__}: {str(exc)[:80]}'
    else:
        snap['lane_work'] = {}
    snap['errors'] = errors
    snap['seconds'] = round(time.time() - started, 2)
    return snap


def lane_status(snap):
    """{lane prefix: {'queue', 'present' (True/False/None unknown), 'workers': [...]}} from a snapshot."""
    lanes = snap.get('lanes')
    out = {}
    for prefix, queue in _lane_table().items():
        if lanes is None:
            out[prefix] = {'queue': queue, 'present': None, 'workers': []}
            continue
        names = [n for n, queues in lanes.items() if prefix in str(n).split('@') and queue in (queues or [])]
        out[prefix] = {'queue': queue, 'present': bool(names), 'workers': names}
    return out


def dumps(snap):
    return json.dumps(snap, default=str)
