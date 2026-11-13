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
import threading
import time

CACHE_PREFIX = 'lane_memory:'
RUNNING_PREFIX = 'lane_running:'  # its own key: the tasks in flight change with every task start and end, the memory report is written at most every WRITE_EVERY seconds
LANES = ('discovery', 'cve_feed', 'validation_priority', 'classic')
WRITE_EVERY = 20  # seconds between writes from one process
KEEP_SECONDS = 6 * 3600
MAX_TASKS = 30

RESTARTS_PREFIX = 'lane_restarts:'  # the worker starts seen on this lane (a different process than the one that wrote the last record), kept a week
RESTARTS_KEEP_SECONDS = 7 * 86400
MAX_RESTARTS = 20
PROCESS_STARTED = time.time()  # a restarted container often hands the new worker the same pid, so the start time says whether it is the same process

_state = {'lane': None, 'started': {}, 'running': {}, 'tasks': {}, 'last_write': 0.0, 'peak_mb': 0.0, 'beat_thread': None}
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
    write_running(now)
    _ensure_heartbeat()


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
    write_running(now)
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
        cache.set(CACHE_PREFIX + lane, json.dumps({'pid': os.getpid(), 'started': PROCESS_STARTED, 'at': now, 'rss_mb': round(size, 1), 'peak_mb': round(_state['peak_mb'], 1),
                                                   'limit_mb': container_limit_mb(), 'tasks': _state['tasks']}), KEEP_SECONDS)
    except Exception:  # noqa: BLE001 - a measurement must never fail a task
        pass


def container_limit_mb():
    """The memory limit of the container this worker runs in (every lane of it shares it), in MB: a number, 0 when the container has no limit, None when
    its cgroup cannot be read."""
    try:
        from reNgine import resources
        limit, used = resources.cgroup_memory()
    except Exception:  # noqa: BLE001 - a measurement must never fail a task
        return None
    if used is None:
        return None
    return limit // (1 << 20) if limit else 0


def record_start(now=None):
    """A worker started: when the lane's last record was written by another process, that process is gone, so this is a restart. It is remembered with what
    the lane last held (its size and the time it was last heard from), then the lane's record is written again for this process. The first start of a lane
    has no earlier record and counts nothing. Never raises."""
    lane = _state['lane'] or lane_name()
    _state['lane'] = lane
    if not lane:
        return
    now = time.time() if now is None else now
    try:
        from django.core.cache import cache
        raw = cache.get(CACHE_PREFIX + lane)
        prior = json.loads(raw) if raw else None
        if isinstance(prior, dict) and (prior.get('pid') != os.getpid() or ('started' in prior and prior['started'] != PROCESS_STARTED)):
            try:
                events = json.loads(cache.get(RESTARTS_PREFIX + lane) or '[]')
            except ValueError:
                events = []
            events = [e for e in events if isinstance(e, dict) and now - e.get('at', 0) < RESTARTS_KEEP_SECONDS]
            events.append({'at': now, 'last_heard_at': prior.get('at'), 'last_rss_mb': prior.get('rss_mb'), 'peak_mb': prior.get('peak_mb')})
            cache.set(RESTARTS_PREFIX + lane, json.dumps(events[-MAX_RESTARTS:]), RESTARTS_KEEP_SECONDS)
        _state['last_write'] = now
        write(now, rss_mb())
    except Exception:  # noqa: BLE001 - a measurement must never stop a worker from starting
        pass


def restarts(lane, now=None, within=86400):
    """The restarts of ``lane`` seen in the last ``within`` seconds, oldest first: ``[{at, last_heard_at, last_rss_mb, peak_mb}]``. Raises when the cache cannot
    be read; a record that is not what was written reads as none."""
    from django.core.cache import cache
    now = time.time() if now is None else now
    try:
        events = json.loads(cache.get(RESTARTS_PREFIX + lane) or '[]')
    except ValueError:
        return []
    return [e for e in events if isinstance(e, dict) and isinstance(e.get('at'), (int, float)) and now - e['at'] <= within] if isinstance(events, list) else []


def reset():
    """A worker (re)started or is shutting down: nothing it had running before is running now, so the record is written again without it."""
    _state['running'].clear()
    write_running()


def write_running(now=None):
    """Write which tasks this worker has in flight (name and start time), its process id and the time of this write (``beat``) under the lane's own key.
    The beat is the sign that the worker is alive: ``in_flight`` ignores a record nobody has refreshed lately. Never raises."""
    lane = _state['lane'] or lane_name()
    _state['lane'] = lane
    if not lane:
        return
    now = time.time() if now is None else now
    try:
        from django.core.cache import cache
        cache.set(RUNNING_PREFIX + lane, json.dumps({'pid': os.getpid(), 'beat': now, 'running': list(_state['running'].values())[-MAX_RUNNING:]}), KEEP_SECONDS)
    except Exception:  # noqa: BLE001 - a measurement must never fail a task
        pass


def heartbeat_once(now=None):
    """Refresh the in-flight record while this worker has a task running. Returns True when it wrote one."""
    if not _state['running']:
        return False
    write_running(now)
    return True


_stop = threading.Event()  # the loop waits on this, not on ``time.sleep``: tests patch that one globally, and a call from this thread landed in their mock


def stop():
    """End the heartbeat thread (it also ends with the process)."""
    _stop.set()


def _heartbeat_loop():
    while not _stop.wait(HEARTBEAT_SECONDS):
        try:
            heartbeat_once()
        except Exception:  # noqa: BLE001 - the heartbeat must outlive any one failed write
            pass


def _ensure_heartbeat():
    """Start the one thread that refreshes the record every ``HEARTBEAT_SECONDS`` (a greenlet under gevent, which the workers run: the heartbeat goes on while a
    task is blocked in a socket or a child process, and stops when the process dies, which is the point). Never raises."""
    thread = _state.get('beat_thread')
    if thread is not None and thread.is_alive():
        return
    if not (_state['lane'] or lane_name()):  # not a worker (a test process running tasks eagerly): nobody reads this process's record, and no thread is wanted
        return
    try:
        _stop.clear()
        thread = threading.Thread(target=_heartbeat_loop, name='lane-memory-heartbeat', daemon=True)
        thread.start()
        _state['beat_thread'] = thread
    except Exception:  # noqa: BLE001
        pass


def install():
    from celery.signals import task_postrun, task_prerun, worker_ready, worker_shutdown

    worker_ready.connect(lambda **kw: (record_start(), reset()), weak=False, dispatch_uid='lane-memory-ready')
    worker_shutdown.connect(lambda **kw: reset(), weak=False, dispatch_uid='lane-memory-shutdown')
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
        try:
            tasks = data.get('tasks') or {}
            out.append({'lane': lane, 'rss_mb': data.get('rss_mb'), 'peak_mb': data.get('peak_mb'), 'age_seconds': int(now - data.get('at', now)),
                        'limit_mb': data.get('limit_mb'),
                        'by_size': [{'task': n, 'runs': t['n'], 'max_rss_mb': t['max_rss_mb']} for n, t in sorted(tasks.items(), key=lambda i: -i[1]['max_rss_mb'])[:5]],
                        'by_growth': [{'task': n, 'runs': t['n'], 'max_growth_mb': t['max_growth_mb']} for n, t in sorted(tasks.items(), key=lambda i: -i[1]['max_growth_mb'])[:5]
                                      if t['max_growth_mb'] > 0]})
        except (AttributeError, KeyError, TypeError):  # a record that is not what ``write`` wrote is skipped, never allowed to hide the other lanes
            continue
    return sorted(out, key=lambda r: -(r['rss_mb'] or 0))


PROGRESS_SECONDS = 90  # a lane that finished a task this recently is working, whatever it did with its last ping


def recent_progress(now=None):
    """``{lane: seconds since it last finished a task}`` for the lanes that finished one within ``PROGRESS_SECONDS``. A worker lane that is busy can miss a
    3 second ping while it works (on 11/9 the CVE-feed lane did, again and again, while finishing a correlation every few seconds), and the watchdog took
    each miss for a dead lane and restarted the container. Finishing work is proof of life that does not depend on a reply to a ping."""
    now = time.time() if now is None else now
    return {row['lane']: row['age_seconds'] for row in report(now) if 0 <= row['age_seconds'] <= PROGRESS_SECONDS}


HEARTBEAT_SECONDS = 30  # how often a worker with a task running refreshes its record
BEAT_STALE_SECONDS = 90  # a record whose beat is older than this (three missed beats) was written by a worker that is gone or stuck
# The longest a task may be called busy on its heartbeat alone. A queue's hard time limit (reNgine/time_limits.py) is held below the broker's visibility
# timeout (12 hours), so a task still "running" after that has outlived every limit it can have: the lane's heartbeat then proves the lane lives, not that the
# task works, and the watchdog's other rules judge it again. Below the ceiling a healthy long task that lets the worker yield (a 45 minute port load) is not restarted; one that blocks the worker without yielding stops the beat and is judged like a hung worker.
IN_FLIGHT_MAX_SECONDS = 12 * 3600


def in_flight(now=None, pids=None):
    """``{lane: seconds since its youngest running task started}`` for the lanes whose worker is alive and has a task that has not ended.
    A lane in one long task is busy, not dead, even when it finished nothing for minutes and missed its ping. Alive means: the record's beat is at most
    ``BEAT_STALE_SECONDS`` old (a worker killed without running its shutdown leaves a record that nobody refreshes), and, when ``pids`` says which processes
    answer for the lane (``{lane: {pid, ...}}``), the record was written by one of them (a restarted worker has a new pid). A task older than
    ``IN_FLIGHT_MAX_SECONDS`` is not counted. A record with no beat (written before the heartbeat existed) is not trusted."""
    from django.core.cache import cache
    now = time.time() if now is None else now
    out = {}
    for lane in LANES:
        try:
            raw = cache.get(RUNNING_PREFIX + lane)
            data = json.loads(raw) if raw else None
        except Exception:  # noqa: BLE001
            data = None
        data = data if isinstance(data, dict) else {}
        beat = data.get('beat')
        if not isinstance(beat, (int, float)) or now - beat > BEAT_STALE_SECONDS:
            continue
        if pids and lane in pids and data.get('pid') not in pids[lane]:
            continue
        ages = [now - t['since'] for t in data.get('running') or [] if isinstance(t, dict) and 'since' in t]
        ages = [int(a) for a in ages if 0 <= a <= IN_FLIGHT_MAX_SECONDS]
        if ages:
            out[lane] = min(ages)
    return out
