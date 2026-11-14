"""What each container knows about its own memory, published for the system status (the maintainer's signals, ``agentapi.maintainer_signals``).

A container can read only its own cgroup. The web container never runs a Celery task, so nothing it ran published its memory: on the day it sat at its
1 GiB limit nobody could see it. Now the watchdog tick (``manage.py watchdog_tick``, run in the web container every 30 seconds) publishes the web
container's picture and the worker container's resource tick (``resources.report_state``) publishes that container's, each to one Redis hash
(``HASH``, a field per host): the resident memory against the limit, the highest it reached, and the kernel's count of processes it killed for memory
(``oom_kill`` in the cgroup's ``memory.events``) with the increases remembered for a week.

This is kept apart from ``resources.cluster_snapshot`` on purpose: that snapshot feeds the watchdog's memory pause (R7) and the scanner budgets, and
adding the web container to it would change what they decide. This only measures. Nothing here raises: a cgroup that is missing or malformed publishes
nothing, and the reader then says "unknown".
"""
import json
import logging
import time

logger = logging.getLogger(__name__)

HASH = 'cvengine:signals:containers'
KEEP_SECONDS = 7 * 86400  # how long a container's oom kills and its last picture are remembered
MAX_EVENTS = 50
PUBLISH_EVERY = 10  # seconds: the worker container's resource tick can call this several times a second
_last = {}


def _read(path):
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return None


def _counter(text, key):
    """The number after ``key`` on a ``name value`` line of a cgroup file, or None when the line is not there or is not a number."""
    for line in (text or '').splitlines():
        name, _, value = line.strip().partition(' ')
        if name == key:
            try:
                return int(value)
            except ValueError:
                return None
    return None


def oom_kills(root='/sys/fs/cgroup'):
    """How many processes of this container the kernel has killed for memory since the container started (cgroup v2 ``memory.events``, then v1
    ``memory.oom_control``), or None when neither file can be read."""
    value = _counter(_read(f'{root}/memory.events'), 'oom_kill')
    if value is None:
        value = _counter(_read(f'{root}/memory/memory.oom_control'), 'oom_kill')
    return value


def memory(root='/sys/fs/cgroup'):
    """``{'used_mb', 'limit_mb' (None: no limit), 'peak_mb' (None: not readable)}`` for this container, or None when its cgroup cannot be read."""
    from reNgine import resources
    try:
        limit, used = resources.cgroup_memory(root)
    except (ValueError, TypeError):  # a malformed file
        return None
    if used is None:
        return None
    peak = _read(f'{root}/memory.peak')
    try:
        peak_mb = int(peak) // (1 << 20) if peak is not None else None
    except ValueError:
        peak_mb = None
    return {'used_mb': used // (1 << 20), 'limit_mb': limit // (1 << 20) if limit else None, 'peak_mb': peak_mb}


def next_record(previous, role, host, now, mem, total):
    """The record to store: this reading, with the kernel's count turned into dated increases. The first reading only sets the base (when the earlier
    kills happened is not known); a count lower than the last one means the container was recreated, so what it shows has happened since."""
    events = [e for e in (previous or {}).get('oom_events', []) if isinstance(e, list) and len(e) == 2 and now - e[0] < KEEP_SECONDS]
    before = (previous or {}).get('oom_total')
    if total is not None and isinstance(before, int):
        delta = total - before if total >= before else total
        if delta > 0:
            events.append([now, delta])
    return {'role': role, 'host': host, 'memory': mem, 'oom_total': total, 'oom_events': events[-MAX_EVENTS:], 't': now}


def publish(role, client=None, now=None, root='/sys/fs/cgroup', host=None, force=False):
    """Publish this container's memory and oom kills. True when something was written. Never raises."""
    now = time.time() if now is None else now
    try:
        if not force and now - _last.get(role, 0) < PUBLISH_EVERY:
            return False
        _last[role] = now
        mem = memory(root)
        total = oom_kills(root)
        if mem is None and total is None:
            return False  # no cgroup here: publish nothing, so the reader says unknown instead of a made-up number
        if client is None:
            from reNgine import resources
            client = resources.redis_client()
        if client is None:
            return False
        if host is None:
            import socket
            host = socket.gethostname()
        try:
            previous = json.loads(client.hget(HASH, host) or 'null')
        except ValueError:
            previous = None
        client.hset(HASH, host, json.dumps(next_record(previous if isinstance(previous, dict) else None, role, host, now, mem, total)))
        if client.hlen(HASH) > 12:  # containers that were recreated under other names
            for field, raw in (client.hgetall(HASH) or {}).items():
                try:
                    if now - json.loads(raw).get('t', 0) > KEEP_SECONDS:
                        client.hdel(HASH, field)
                except (ValueError, AttributeError):
                    client.hdel(HASH, field)
        return True
    except Exception:  # noqa: BLE001 - a measurement must never fail the tick or the job monitor that called it
        logger.debug('container signals: could not publish', exc_info=True)
        return False


def read(client, now=None):
    """The published records, newest data first: ``[{role, host, memory, oom_total, oom_kills_24h, last_oom_at, age_seconds}]``. Raises when Redis
    cannot be asked (the caller says unknown); a record that is not JSON is skipped."""
    now = time.time() if now is None else now
    out = []
    for host, raw in (client.hgetall(HASH) or {}).items():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict) or not isinstance(rec.get('t'), (int, float)) or now - rec['t'] > KEEP_SECONDS:
            continue
        events = [e for e in rec.get('oom_events') or [] if isinstance(e, list) and len(e) == 2]
        recent = [e for e in events if now - e[0] <= 86400]
        out.append({'role': rec.get('role'), 'host': str(host)[:40], 'memory': rec.get('memory') if isinstance(rec.get('memory'), dict) else None,
                    'oom_total': rec.get('oom_total'), 'oom_kills_24h': sum(e[1] for e in recent),
                    'last_oom_at': max((e[0] for e in events), default=None), 'age_seconds': int(max(0, now - rec['t']))})
    return sorted(out, key=lambda r: (r['role'] or '', r['host']))
