"""How much memory each Celery worker lane holds, and which tasks it held it after.

On 11/9 the Celery container sat at its 4.5 GiB ceiling and the watchdog paused scanning, but nothing said which lane held it: ``ps`` on the host showed the
CVE-feed lane at 2.0 GiB and the classic lane at 1.5 GiB, and the planner (the first suspect) measured 24 MB. A lane's worker process writes its resident
memory, with the tasks that had just finished, to the cache after every task (at most once every ``WRITE_EVERY`` seconds), and the system status shows it.
It records; it never acts. Gevent runs many tasks at once in one process, so a task's own cost cannot be read exactly: ``max_rss_mb`` is the process size
after the task ended, ``max_growth_mb`` how much the process grew while that task ran (other tasks may account for part of it). A task that tops both
lists run after run is the one to look at.
"""
import json
import os
import sys
import time

CACHE_PREFIX = 'lane_memory:'
RUNNING_PREFIX = 'lane_running:'  # its own key: the tasks in flight change with every task start and end, the memory report is written at most every WRITE_EVERY seconds
LANES = ('discovery', 'cve_feed', 'validation_priority', 'classic')
WRITE_EVERY = 20  # seconds between writes from one process
KEEP_SECONDS = 6 * 3600
MAX_TASKS = 30

_state = {'lane': None, 'started': {}, 'running': {}, 'tasks': {}, 'last_write': 0.0, 'peak_mb': 0.0}
MAX_RUNNING = 50  # tasks listed as in flight in one record


def rss_mb():
    """The resident memory of this process in MB, 0.0 where /proc is not readable."""
    try:
        with open('/proc/self/statm') as handle:
            return int(handle.read().split()[1]) * os.sysconf('SC_PAGE_SIZE') / (1 << 20)
    except (OSError, ValueError, IndexError):
        return 0.0


def lane_name(argv=None):
    """The lane this worker serves, from its ``-n``/``--hostname`` (``cve_feed_worker`` is the ``cve_feed`` lane); '' when it cannot be told."""
    argv = list(sys.argv if argv is None else argv)
    for i, arg in enumerate(argv):
        value = argv[i + 1] if arg in ('-n', '--hostname') and i + 1 < len(argv) else arg.split('=', 1)[1] if arg.startswith('--hostname=') else ''
        if value:
            name = value.split('@')[0]
            return name[:-len('_worker')] if name.endswith('_worker') else name
    return ''


def before(task_id, task_name='?', now=None):
    """A task starts: remember its memory baseline, and write that it is running. A lane in one long task finishes nothing for minutes (and can miss a
    ping), so the start is the only sign of life the watchdog gets from it."""
    now = time.time() if now is None else now
    _state['started'][task_id] = rss_mb()
    _state['running'][task_id] = {'name': task_name, 'since': now}
    for table in ('started', 'running'):
        if len(_state[table]) > 500:  # a task that never reported its end must not grow this forever
            _state[table].pop(next(iter(_state[table])), None)
    write_running()


def after(task_id, task_name, now=None):
    now = time.time() if now is None else now
    size = rss_mb()
    start = _state['started'].pop(task_id, size)
    _state['running'].pop(task_id, None)
    row = _state['tasks'].setdefault(task_name, {'n': 0, 'max_rss_mb': 0.0, 'max_growth_mb': 0.0})
    row['n'] += 1
    row['max_rss_mb'] = max(row['max_rss_mb'], round(size, 1))
    row['max_growth_mb'] = max(row['max_growth_mb'], round(size - start, 1))
    _state['peak_mb'] = max(_state['peak_mb'], size)
    if len(_state['tasks']) > MAX_TASKS:
        for name in sorted(_state['tasks'], key=lambda n: _state['tasks'][n]['max_rss_mb'])[:len(_state['tasks']) - MAX_TASKS]:
            _state['tasks'].pop(name, None)
    write_running()
    if now - _state['last_write'] >= WRITE_EVERY:
        _state['last_write'] = now
        write(now, size)


def write(now, size):
    lane = _state['lane'] or lane_name()
    _state['lane'] = lane
    if not lane:
        return
    try:
        from django.core.cache import cache
        cache.set(CACHE_PREFIX + lane, json.dumps({'pid': os.getpid(), 'at': now, 'rss_mb': round(size, 1), 'peak_mb': round(_state['peak_mb'], 1),
                                                   'tasks': _state['tasks']}), KEEP_SECONDS)
    except Exception:  # noqa: BLE001 - a measurement must never fail a task
        pass


def reset():
    """A worker (re)started: nothing it had running before is running now, so the record is written again without it."""
    _state['running'].clear()
    write_running()


def write_running():
    """Write which tasks this worker has in flight (name and start time) under the lane's own key. Never raises."""
    lane = _state['lane'] or lane_name()
    _state['lane'] = lane
    if not lane:
        return
    try:
        from django.core.cache import cache
        cache.set(RUNNING_PREFIX + lane, json.dumps({'pid': os.getpid(), 'running': list(_state['running'].values())[-MAX_RUNNING:]}), KEEP_SECONDS)
    except Exception:  # noqa: BLE001 - a measurement must never fail a task
        pass


def install():
    from celery.signals import task_postrun, task_prerun, worker_ready

    worker_ready.connect(lambda **kw: reset(), weak=False, dispatch_uid='lane-memory-ready')
    task_prerun.connect(lambda task_id=None, task=None, **kw: before(task_id, getattr(task, 'name', '?')), weak=False, dispatch_uid='lane-memory-pre')
    task_postrun.connect(lambda task_id=None, task=None, **kw: after(task_id, getattr(task, 'name', '?')), weak=False, dispatch_uid='lane-memory-post')


def report(now=None):
    """What the status shows: one row per lane that has reported, biggest first, with its five biggest tasks by size after the task and by growth."""
    from django.core.cache import cache
    now = time.time() if now is None else now
    out = []
    for lane in LANES:
        try:
            raw = cache.get(CACHE_PREFIX + lane)
            data = json.loads(raw) if raw else None
        except Exception:  # noqa: BLE001
            data = None
        if not data:
            continue
        tasks = data.get('tasks') or {}
        out.append({'lane': lane, 'rss_mb': data.get('rss_mb'), 'peak_mb': data.get('peak_mb'), 'age_seconds': int(now - data.get('at', now)),
                    'by_size': [{'task': n, 'runs': t['n'], 'max_rss_mb': t['max_rss_mb']} for n, t in sorted(tasks.items(), key=lambda i: -i[1]['max_rss_mb'])[:5]],
                    'by_growth': [{'task': n, 'runs': t['n'], 'max_growth_mb': t['max_growth_mb']} for n, t in sorted(tasks.items(), key=lambda i: -i[1]['max_growth_mb'])[:5]
                                  if t['max_growth_mb'] > 0]})
    return sorted(out, key=lambda r: -(r['rss_mb'] or 0))


PROGRESS_SECONDS = 90  # a lane that finished a task this recently is working, whatever it did with its last ping


def recent_progress(now=None):
    """``{lane: seconds since it last finished a task}`` for the lanes that finished one within ``PROGRESS_SECONDS``. A worker lane that is busy can miss a
    3 second ping while it works (on 11/9 the CVE-feed lane did, again and again, while finishing a correlation every few seconds), and the watchdog took
    each miss for a dead lane and restarted the container. Finishing work is proof of life that does not depend on a reply to a ping."""
    now = time.time() if now is None else now
    return {row['lane']: row['age_seconds'] for row in report(now) if 0 <= row['age_seconds'] <= PROGRESS_SECONDS}


IN_FLIGHT_SECONDS = 30 * 60  # a task that started this recently is work in progress; one older than this proves nothing (it may be hung)


def in_flight(now=None):
    """``{lane: seconds since its youngest running task started}`` for the lanes with a task that started within ``IN_FLIGHT_SECONDS`` and has not ended.
    A lane in one long task is busy, not dead, even when it finished nothing for minutes and missed its ping. A restarted worker writes a fresh record (``reset``),
    so a task listed by a process that died does not outlive it by more than ``IN_FLIGHT_SECONDS``."""
    from django.core.cache import cache
    now = time.time() if now is None else now
    out = {}
    for lane in LANES:
        try:
            raw = cache.get(RUNNING_PREFIX + lane)
            data = json.loads(raw) if raw else None
        except Exception:  # noqa: BLE001
            data = None
        ages = [now - t['since'] for t in (data or {}).get('running') or [] if isinstance(t, dict) and 'since' in t]
        ages = [int(a) for a in ages if 0 <= a <= IN_FLIGHT_SECONDS]
        if ages:
            out[lane] = min(ages)
    return out
