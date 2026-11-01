"""Memory-aware admission control for the heavy scanner processes (bbot, nmap, nuclei, template tests).

Why: a container has a memory ceiling (the cgroup limit set by ``mem_limit`` in compose). Several scanners at once can
cross it, and then the kernel's OOM killer picks a victim, often the celery worker itself, taking every job with it.

What this does, in order:

1. **Queue.** Every heavy process runs inside ``heavy_job(kind)``. Each kind has an estimated cost in MB. A job starts
   only when the reservations already running plus its cost fit the budget (75% of the container limit by default) AND the
   container really has that much free. Otherwise it waits its turn, polling with jitter, and says so in the AI activity
   feed. A job that is alone always starts, so nothing starves. Reservations live in Redis (shared by all worker
   processes in the container) with a heartbeat TTL, so a crashed worker releases its share by itself.
2. **Watchdog.** While a job runs, a thread measures its real memory (the whole process group). If free memory falls
   below a critical floor, the biggest job in the container is stopped cleanly (SIGTERM, then SIGKILL) BEFORE the kernel
   gets involved, and ``MemoryKill`` is raised so the caller can retry with a lighter profile instead of crashing.
3. **Visibility.** ``snapshot()`` feeds the Settings > Resources page: limit, free memory, running and waiting jobs, and
   the recent memory kills.

Knobs (environment, all optional): HEAVY_MEMORY_BUDGET_MB, HEAVY_HEADROOM_MB, HEAVY_COST_SCALE, HEAVY_COST_<KIND>_MB
(for example HEAVY_COST_BBOT_DEEP_MB), HEAVY_WAIT_SECONDS.
"""
import contextvars
import json
import logging
import os
import random
import signal
import socket
import threading
import time
import uuid
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Estimated peak resident memory per job kind, in MB. Deliberately a little pessimistic.
BASE_COSTS_MB = {
    'bbot-deep': 2400,      # kitchen-sink preset: dozens of modules and a spider (raised to what real runs reach, see effective_cost)
    'bbot-standard': 1000,  # subdomain-enum plus the quick web preset, safe modules only
    'bbot-passive': 700,
    'nuclei': 1000,         # loads thousands of templates
    'nuclei-light': 500,    # fewer parallel hosts
    'nmap': 400,            # -sV over the top 1000 ports; chunks of hosts, and a memory kill halves the chunk
    'nmap-full-bg': 500,    # the background -p- sweep of one IP (cveFeed.fullscan): it waits behind everything else, so discovery is never starved
    'nmap-udp-bg': 300,     # the background UDP sweep of one IP (cveFeed.udp_scan): a few dozen probes, version detection on what answered
    'naabu': 150,           # SYN port discovery over every TCP port, one process for many addresses
    'template-test': 600,   # one generated template against one host
    'route-probe': 150,     # safe GETs over a few threads; no process, so the watchdog only watches the stop flag
    'wpscan': 400,          # WPScan (Ruby) on one site; a thorough pass can run for hours
    'testssl': 150,         # testssl.sh and its openssl children against one TLS port
    'screenshot': 450,      # one headless Chromium and its driver, one page at a time (cveFeed.web_shot); a batch of pages is one job
}
# How many of each kind may run at once in a container, whatever memory is free: these are CPU and network bound, so more
# in parallel only makes every one of them slower. Override with HEAVY_MAX_<KIND>, e.g. HEAVY_MAX_NMAP=2.
MAX_CONCURRENT = {'bbot-deep': 1, 'bbot-standard': 2, 'bbot-passive': 2, 'nuclei': 1, 'nuclei-light': 1, 'nmap': 2, 'nmap-full-bg': 1, 'nmap-udp-bg': 1, 'naabu': 1, 'template-test': 3, 'route-probe': 2, 'wpscan': 2, 'testssl': 2, 'screenshot': 1}
DEFAULT_WAIT_SECONDS = 24 * 3600  # a queued deep discovery may wait behind several others, one at a time
RESERVATION_TTL = 90        # a holder that stops heartbeating loses its reservation after this many seconds
HEARTBEAT_SECONDS = 3
GRACE_SECONDS = 10          # a fresh job is not a kill candidate while it is still loading
POLL_SECONDS = (3, 8)
CGROUP_ROOT = '/sys/fs/cgroup'
MEMINFO = '/proc/meminfo'


class MemoryKill(RuntimeError):
    """The job was stopped because the container was about to run out of memory."""


class MemoryBusy(RuntimeError):
    """The job waited for memory for longer than allowed."""


class ScanAborted(RuntimeError):
    """The scan this work belongs to was stopped by a person; the work stops and the pipeline exits cleanly."""


# --- stopping a scan -----------------------------------------------------------------------------------------------
# The workers are gevent pools, where a celery revoke cannot terminate a running task, so stopping is cooperative: the stop
# sets a flag (Redis, shared by all workers; plus this process), the pipeline checks it between stages, and each heavy job's
# watchdog kills its scanner process tree when the flag is set for the scan it works for.
_current_scan = contextvars.ContextVar('cvengine_current_scan', default=None)
_aborted_here = set()
ABORT_KEY = 'cvengine:abort:'
ABORT_TTL = 24 * 3600


@contextmanager
def scan_context(scan_id):
    """Mark the work in this block as belonging to ``scan_id``, so a stop of that scan reaches its heavy jobs."""
    token = _current_scan.set(scan_id)
    try:
        yield
    finally:
        _current_scan.reset(token)


def request_abort(scan_id):
    _aborted_here.add(int(scan_id))
    client = getattr(get_store(), 'r', None)
    if client is not None:
        try:
            client.set(f'{ABORT_KEY}{int(scan_id)}', '1', ex=ABORT_TTL)
        except Exception:  # noqa: BLE001 - the database status is the source of truth; the flag only speeds things up
            logger.warning('could not publish the abort of scan %s', scan_id, exc_info=True)


def abort_requested(scan_id):
    if scan_id is None:
        return False
    if int(scan_id) in _aborted_here:
        return True
    client = getattr(get_store(), 'r', None)
    try:
        return bool(client is not None and client.get(f'{ABORT_KEY}{int(scan_id)}'))
    except Exception:  # noqa: BLE001
        return False


def global_pause_requested(fail_closed=False):
    """For the watchdogs that stop running work: an unreadable control database is not a pause. A gate about to start work
    passes ``fail_closed=True``."""
    from cveFeed.scan_control import pause_requested
    return pause_requested(fail_closed=fail_closed)


def clear_abort(scan_id):
    _aborted_here.discard(int(scan_id))
    client = getattr(get_store(), 'r', None)
    if client is not None:
        try:
            client.delete(f'{ABORT_KEY}{int(scan_id)}')
        except Exception:  # noqa: BLE001
            pass


def _env_float(name, default=None):
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


# --- reading memory ------------------------------------------------------------------------------------------------

def _cgroup_stat(path, key):
    text = _read(path) or ''
    for line in text.splitlines():
        name, _, value = line.partition(' ')
        if name == key:
            try:
                return int(value)
            except ValueError:
                return 0
    return 0


def cgroup_memory(root=CGROUP_ROOT):
    """(limit_bytes or None for unlimited, working_set_bytes or None if unreadable). Page cache that the kernel can drop
    (inactive file pages) is not counted as used. cgroup v2 first, then v1."""
    limit_raw, current = _read(f'{root}/memory.max'), _read(f'{root}/memory.current')
    if current is not None:
        used = int(current) - _cgroup_stat(f'{root}/memory.stat', 'inactive_file')
        limit = None if limit_raw in (None, 'max') else int(limit_raw)
        return limit, max(used, 0)
    limit_raw, usage = _read(f'{root}/memory/memory.limit_in_bytes'), _read(f'{root}/memory/memory.usage_in_bytes')
    if usage is not None:
        used = int(usage) - _cgroup_stat(f'{root}/memory/memory.stat', 'total_inactive_file')
        limit = int(limit_raw) if limit_raw and int(limit_raw) < 1 << 60 else None
        return limit, max(used, 0)
    return None, None


def meminfo(path=MEMINFO):
    values = {}
    for line in (_read(path) or '').splitlines():
        name, _, rest = line.partition(':')
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[name] = int(parts[0]) // 1024  # kB -> MB
    return values


def memory_state(root=CGROUP_ROOT, meminfo_path=MEMINFO):
    """{'total_mb', 'limit_mb' (None = unlimited), 'used_mb', 'available_mb'} for this container."""
    info = meminfo(meminfo_path)
    host_total, host_available = info.get('MemTotal', 0), info.get('MemAvailable', info.get('MemFree', 0))
    limit, used = cgroup_memory(root)
    if limit is not None and used is not None:
        limit_mb, used_mb = limit // (1 << 20), used // (1 << 20)
        total = min(limit_mb, host_total) if host_total else limit_mb
        available = min(max(limit_mb - used_mb, 0), host_available) if host_available else max(limit_mb - used_mb, 0)
        return {'total_mb': total, 'limit_mb': limit_mb, 'used_mb': used_mb, 'available_mb': available}
    return {'total_mb': host_total, 'limit_mb': None, 'used_mb': max(host_total - host_available, 0), 'available_mb': host_available}


def budget_mb(state):
    return int(_env_float('HEAVY_MEMORY_BUDGET_MB') or state['total_mb'] * 0.75)


def headroom_mb(state):
    return int(_env_float('HEAVY_HEADROOM_MB') or max(256, state['total_mb'] * 0.05))


def critical_mb(state):
    """Below this much free memory the biggest job is stopped before the kernel has to."""
    return int(max(150, state['total_mb'] * 0.03))


LEARNED_MARGIN = 1.2


def _cost_override(kind):
    return _env_float('HEAVY_COST_' + kind.upper().replace('-', '_') + '_MB')


def _static_cap(kind):
    """The cap before anything an App Admin saved: HEAVY_MAX_<KIND>, else the built-in default."""
    return int(_env_float('HEAVY_MAX_' + kind.upper().replace('-', '_')) or MAX_CONCURRENT.get(kind, 2))


# What an App Admin saved on Settings, configMaxxing (cveFeed.scan_concurrency): the web process writes the saved values to this Redis key on every
# save and the 30 second tick writes them again, and each process keeps a copy for SAVED_CACHE_SECONDS. This module only reads the key (it must stay
# importable by itself: it runs inside every scanner task and in a child interpreter in the tests), and only for the caps of the scanner kinds.
SAVED_VALUES_KEY = 'cvengine:scanconc:values'
SAVED_CACHE_SECONDS = 5
_saved = {'at': None, 'values': {}}
_saved_clients = {}
_saved_lock = threading.Lock()


def redis_client():
    """A Redis client for the broker URL, or None when the broker is not Redis. Created once per URL; connects on first use."""
    url = os.environ.get('CELERY_BROKER') or os.environ.get('CELERY_BROKER_URL') or ''
    if not url.startswith(('redis://', 'rediss://', 'unix://')):
        return None
    if url not in _saved_clients:
        import redis
        _saved_clients[url] = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=3, decode_responses=True)
    return _saved_clients[url]


def invalidate_saved():
    with _saved_lock:
        _saved.update(at=None)


def saved_values(now_fn=time.monotonic):
    """The values saved on the configMaxxing page, {key: whole number}, cached SAVED_CACHE_SECONDS. When Redis cannot be reached the last copy this
    process saw is kept; with none, nothing is saved as far as this process knows and the environment and the built-in defaults apply. When Redis
    answers but holds no copy (restarted without persistence, flushed, recreated), the database is the truth: it is read (at most once per cache
    window), used and published again, so a lost copy never silently puts a saved limit back to the default."""
    now = now_fn()
    with _saved_lock:
        if _saved['at'] is not None and now - _saved['at'] < SAVED_CACHE_SECONDS:
            return _saved['values']
    values = None
    try:
        client = redis_client()
        raw = client.get(SAVED_VALUES_KEY) if client is not None else None
        values = json.loads(raw).get('values') if raw else None
        values = values if isinstance(values, dict) else None
    except (ValueError, AttributeError):
        values = None  # a copy nobody can read is no copy
    except Exception:  # noqa: BLE001 - a cache that cannot be read must never stop admission or the conductor
        logger.debug('saved scan concurrency could not be read', exc_info=False)
        with _saved_lock:
            _saved['at'] = now  # no retry on every call during an outage
            return _saved['values']
    if values is None:
        values = _recover_saved(client is not None)
        if values is None:  # the database could not be read either (or this is not a Django process): keep what this process had
            with _saved_lock:
                _saved['at'] = now
                return _saved['values']
    with _saved_lock:
        _saved.update(at=now, values=values)
    return values


def _recover_saved(publish_again):
    """The saved values from the database, published again; None where that cannot be done (a process without Django, a database that is down).
    Imported here so that this module stays importable by itself."""
    try:
        from cveFeed import scan_concurrency
        return scan_concurrency.recover(publish_again)
    except Exception:  # noqa: BLE001
        logger.debug('saved scan concurrency could not be recovered from the database', exc_info=False)
        return None


def _admin_cap(kind):
    """The cap an App Admin saved for a kind, or None."""
    value = saved_values().get('heavy.' + kind)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


# What the auto-tuner chose (cveFeed.autotune), published by the process that changes it and again by the 30 second tick, read and cached the same
# way as the saved values above. The copy holds numbers only while the instance's mode is Auto; Off and Suggest publish an empty copy, so a number
# the tuner chose stops applying within seconds of turning it off. ``CVENGINE_AUTOTUNE=0`` (the kill switch) is honoured here too, by every reader.
AUTO_VALUES_KEY = 'cvengine:autotune:values'
_auto = {'at': None, 'values': {}}
AUTOTUNE_OFF_WORDS = ('0', 'false', 'no', 'off')


def autotune_killed(environ=None):
    """Whether CVENGINE_AUTOTUNE turns auto-tuning off for this process (the environment's kill switch, read on every call)."""
    return str((environ if environ is not None else os.environ).get('CVENGINE_AUTOTUNE', '')).strip().lower() in AUTOTUNE_OFF_WORDS


def auto_values(now_fn=time.monotonic):
    """The numbers the auto-tuner chose and that apply now, ``{key: whole number}`` (empty unless the mode is Auto), cached SAVED_CACHE_SECONDS.
    The same three cases as ``saved_values``: a copy is used; Redis without a copy means the database is read and the copy published again; Redis
    that cannot be reached keeps the last copy this process saw (none: no tuned numbers, so the saved value, the environment or the default)."""
    if autotune_killed():
        return {}
    now = now_fn()
    with _saved_lock:
        if _auto['at'] is not None and now - _auto['at'] < SAVED_CACHE_SECONDS:
            return _auto['values']
    values = None
    try:
        client = redis_client()
        raw = client.get(AUTO_VALUES_KEY) if client is not None else None
        values = json.loads(raw).get('values') if raw else None
        values = values if isinstance(values, dict) else None
    except (ValueError, AttributeError):
        values = None
    except Exception:  # noqa: BLE001 - a cache that cannot be read must never stop admission or the conductor
        logger.debug('auto-tuned values could not be read', exc_info=False)
        with _saved_lock:
            _auto['at'] = now
            return _auto['values']
    if values is None:
        values = _recover_auto(client is not None)
        if values is None:
            with _saved_lock:
                _auto['at'] = now
                return _auto['values']
    values = {k: v for k, v in values.items() if isinstance(v, int) and not isinstance(v, bool)}
    with _saved_lock:
        _auto.update(at=now, values=values)
    return values


def invalidate_auto():
    with _saved_lock:
        _auto.update(at=None)


def _recover_auto(publish_again):
    try:
        from cveFeed import autotune
        return autotune.recover(publish_again)
    except Exception:  # noqa: BLE001
        logger.debug('auto-tuned values could not be recovered from the database', exc_info=False)
        return None


def _auto_cap(kind):
    value = auto_values().get('heavy.' + kind)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def base_cap(kind):
    """The cap in effect: what a person saved (it pins the kind), else what the auto-tuner chose (mode Auto only), else HEAVY_MAX_<KIND>, else
    the built-in default."""
    saved = _admin_cap(kind)
    if saved is not None:
        return saved
    tuned = _auto_cap(kind)
    return tuned if tuned is not None else _static_cap(kind)


def max_concurrent(kind):
    """How many runs of a kind may run at once. Only the auto-tuner (cveFeed.autotune) moves it now, through ``base_cap``: the step the old
    three-hour review kept in Redis (``cvengine:adaptive:max:<kind>``) is no longer read, so a leftover one changes nothing."""
    return max(1, base_cap(kind))


def adaptive_bounds(kind, baseline=None):
    """The range the three-hour review's candidate is judged against (cveFeed.performance_review, which now only reports). The cap an App Admin
    saved is the default maximum; HEAVY_TUNE_MIN/MAX_<KIND> narrow or widen it as before. The auto-tuner has its own range per kind
    (cveFeed.autotune.envelope), which HEAVY_TUNE_MIN/MAX_<KIND> also narrow or widen."""
    baseline = baseline or base_cap(kind)
    saved = _admin_cap(kind)
    suffix = kind.upper().replace('-', '_')
    env_low = max(1, int(_env_float('HEAVY_TUNE_MIN_' + suffix) or 1))
    env_high = int(_env_float('HEAVY_TUNE_MAX_' + suffix) or baseline)
    if saved is None:
        return env_low, max(env_low, env_high)
    return min(env_low, saved), max(env_high, saved)


def cost_mb(kind):
    override = _cost_override(kind)
    if override:
        return int(override)
    return int(BASE_COSTS_MB.get(kind, 500) * (_env_float('HEAVY_COST_SCALE') or 1.0))


def effective_cost(kind, store):
    """What to reserve for a job: the static estimate, or 20% over the peak this kind of job really reached here, whichever
    is larger. An explicit HEAVY_COST_<KIND>_MB always wins. The estimates start as guesses; real runs correct them."""
    if _cost_override(kind):
        return int(_cost_override(kind))
    try:
        learned = store.learned().get(kind, 0)
    except Exception:  # noqa: BLE001 - a Redis hiccup must not stop a scan from starting
        learned = 0
    return int(max(cost_mb(kind), learned * LEARNED_MARGIN))


def _proc_table():
    """``{pid: (ppid, pgrp, rss bytes)}`` of every process (Linux /proc)."""
    page = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096
    table = {}
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        return table
    for pid in pids:
        stat = _read(f'/proc/{pid}/stat')
        if not stat:
            continue
        try:  # the command name may contain spaces and parentheses: fields start after the last ')'
            fields = stat.rsplit(')', 1)[1].split()
            statm = (_read(f'/proc/{pid}/statm') or '0 0').split()
            table[int(pid)] = (int(fields[1]), int(fields[2]), int(statm[1]) * page)
        except (IndexError, ValueError):
            continue
    return table


def tree_pids(root, table=None):
    """The pids of ``root``'s process group and of every descendant by parent pid, however many sessions or groups they started. A browser starts its
    own session: measuring or stopping the group alone saw only the launcher, not the several hundred MB behind it."""
    table = _proc_table() if table is None else table
    found = {pid for pid, (_ppid, pgrp, _rss) in table.items() if pgrp == root}
    found.add(root)
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _pgrp, _rss) in table.items():
            if ppid in found and pid not in found:
                found.add(pid)
                changed = True
    return {pid for pid in found if pid in table}


def tree_rss_mb(root):
    """Resident memory of ``root``'s group and all its descendants, in MB."""
    table = _proc_table()
    return sum(table[pid][2] for pid in tree_pids(root, table)) // (1 << 20)


def group_rss_mb(pgid):
    """Resident memory of every process in a process group, in MB (Linux /proc)."""
    page = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096
    total = 0
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        return 0
    for pid in pids:
        stat = _read(f'/proc/{pid}/stat')
        if not stat:
            continue
        try:  # the command name may contain spaces and parentheses: fields start after the last ')'
            fields = stat.rsplit(')', 1)[1].split()
            if int(fields[2]) != pgid:  # pgrp is the 3rd field after the name (state, ppid, pgrp)
                continue
            statm = (_read(f'/proc/{pid}/statm') or '0 0').split()
            total += int(statm[1]) * page
        except (IndexError, ValueError):
            continue
    return total // (1 << 20)


# --- shared bookkeeping --------------------------------------------------------------------------------------------

class MemoryStore:
    """Reservations kept in this process. Used when Redis is unreachable and by the tests; with the gevent pool every
    job of a container runs in one process anyway."""

    def __init__(self):
        self._lock = threading.Lock()
        self._jobs, self._waiting, self._events = {}, {}, []
        self._learned = {}

    def _purge(self, now):
        for token in [t for t, j in self._jobs.items() if j['exp'] < now]:
            del self._jobs[token]
        for token in [t for t, w in self._waiting.items() if w['exp'] < now]:
            del self._waiting[token]

    def reserve(self, token, mb, label, budget, now, kind='', cap=0):
        with self._lock:
            self._purge(now)
            total = sum(j['mb'] for j in self._jobs.values())
            same = sum(1 for j in self._jobs.values() if j.get('kind') == kind)
            if self._jobs and (total + mb > budget or (cap > 0 and same >= cap)):
                return False
            self._jobs[token] = {'token': token, 'mb': mb, 'label': label, 'kind': kind, 'rss': 0, 'start': now, 'exp': now + RESERVATION_TTL}
            return True

    def heartbeat(self, token, rss_mb, now):
        with self._lock:
            if token in self._jobs:
                self._jobs[token].update(rss=rss_mb, exp=now + RESERVATION_TTL)

    def release(self, token):
        with self._lock:
            self._jobs.pop(token, None)
            self._waiting.pop(token, None)

    def live(self, now):
        with self._lock:
            self._purge(now)
            return [dict(j) for j in self._jobs.values()]

    def wait(self, token, mb, label, now):
        with self._lock:
            self._waiting[token] = {'token': token, 'mb': mb, 'label': label, 'since': self._waiting.get(token, {}).get('since', now),
                                    'exp': now + 30}

    def waiting(self, now):
        with self._lock:
            self._purge(now)
            return [dict(w) for w in self._waiting.values()]

    def event(self, entry):
        with self._lock:
            self._events = ([entry] + self._events)[:50]

    def events(self):
        with self._lock:
            return list(self._events)

    def publish_state(self, state):
        self._state = state

    def learned(self):
        return dict(self._learned)

    def learn(self, kind, mb):
        old = self._learned.get(kind, 0)
        self._learned[kind] = mb if mb >= old else int(old * 0.8 + mb * 0.2)


_RESERVE_LUA = """
local all = redis.call('HGETALL', KEYS[1])
local total, count, same = 0, 0, 0
for i = 1, #all, 2 do
  local j = cjson.decode(all[i + 1])
  if tonumber(j.exp) < tonumber(ARGV[5]) then redis.call('HDEL', KEYS[1], all[i])
  else
    total = total + tonumber(j.mb); count = count + 1
    if j.kind == ARGV[7] then same = same + 1 end
  end
end
local cap = tonumber(ARGV[8])
if count == 0 or (total + tonumber(ARGV[2]) <= tonumber(ARGV[4]) and (cap <= 0 or same < cap)) then
  redis.call('HSET', KEYS[1], ARGV[1], cjson.encode({token = ARGV[1], mb = tonumber(ARGV[2]), label = ARGV[3], kind = ARGV[7],
      rss = 0, start = tonumber(ARGV[5]), exp = tonumber(ARGV[5]) + tonumber(ARGV[6])}))
  redis.call('EXPIRE', KEYS[1], 3600)
  return 1
end
return 0
"""


class RedisStore:
    """The same bookkeeping in Redis, shared by every worker process of the container. Keys carry the container's host
    name, because each container has its own memory budget."""

    def __init__(self, client, namespace):
        self.r = client
        self.jobs_key, self.wait_key, self.events_key = f'{namespace}:jobs', f'{namespace}:wait', f'{namespace}:events'
        self.state_key = f'{namespace}:state'
        self.learned_key = f'{namespace}:learned'
        self.history_key = f'{namespace}:history'
        self._reserve = client.register_script(_RESERVE_LUA)

    def reserve(self, token, mb, label, budget, now, kind='', cap=0):
        return bool(self._reserve(keys=[self.jobs_key], args=[token, mb, label, budget, now, RESERVATION_TTL, kind, cap]))

    def _all(self, key, now):
        out = []
        for _, raw in self.r.hgetall(key).items():
            try:
                item = json.loads(raw)
            except ValueError:
                continue
            if item.get('exp', 0) >= now:
                out.append(item)
        return out

    def heartbeat(self, token, rss_mb, now):
        raw = self.r.hget(self.jobs_key, token)
        if raw:
            item = json.loads(raw)
            item.update(rss=rss_mb, exp=now + RESERVATION_TTL)
            self.r.hset(self.jobs_key, token, json.dumps(item))

    def release(self, token):
        self.r.hdel(self.jobs_key, token)
        self.r.hdel(self.wait_key, token)

    def live(self, now):
        return self._all(self.jobs_key, now)

    def wait(self, token, mb, label, now):
        raw = self.r.hget(self.wait_key, token)
        since = json.loads(raw).get('since', now) if raw else now
        self.r.hset(self.wait_key, token, json.dumps({'token': token, 'mb': mb, 'label': label, 'since': since, 'exp': now + 30}))
        self.r.expire(self.wait_key, 3600)

    def waiting(self, now):
        return self._all(self.wait_key, now)

    def event(self, entry):
        self.r.lpush(self.events_key, json.dumps(entry))
        self.r.ltrim(self.events_key, 0, 49)
        self.r.expire(self.events_key, 7 * 86400)

    def events(self):
        return [json.loads(x) for x in self.r.lrange(self.events_key, 0, 49)]

    def publish_state(self, state):
        """Let the web container (a different memory cgroup) see this container's memory and budget."""
        self.r.set(self.state_key, json.dumps(state), ex=120)
        try:
            self.r.lpush(self.history_key, json.dumps(state))
            self.r.ltrim(self.history_key, 0, 399)
            self.r.expire(self.history_key, 4 * 3600)
        except Exception:
            logger.debug('adaptive telemetry sample could not be stored', exc_info=False)

    def learned(self):
        return {k.decode() if isinstance(k, bytes) else k: int(v) for k, v in self.r.hgetall(self.learned_key).items()}

    def learn(self, kind, mb):
        """Remember the peak memory a job kind really used; it only creeps down, so one small run cannot undo a big one."""
        old = int(self.r.hget(self.learned_key, kind) or 0)
        self.r.hset(self.learned_key, kind, mb if mb >= old else int(old * 0.8 + mb * 0.2))
        self.r.expire(self.learned_key, 30 * 86400)


_store = {'obj': None, 'kind': None}
_store_lock = threading.Lock()


def get_store():
    """Redis when reachable (shared across worker processes), else a per-process store."""
    with _store_lock:
        if _store['obj'] is None:
            url = os.environ.get('CELERY_BROKER') or os.environ.get('CELERY_BROKER_URL') or ''
            if url.startswith(('redis://', 'rediss://', 'unix://')):
                try:
                    import redis
                    client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=5, decode_responses=True)
                    client.ping()
                    _store.update(obj=RedisStore(client, f'cvengine:heavy:{socket.gethostname()}'), kind='redis')
                except Exception as exc:  # noqa: BLE001 - never block scanning because bookkeeping is unavailable
                    logger.warning('memory gate: Redis unavailable (%s); using a per-process gate', exc)
            if _store['obj'] is None:
                _store.update(obj=MemoryStore(), kind='process')
        return _store['obj']


def reset_store():
    with _store_lock:
        _store.update(obj=None, kind=None)


_EXPIRE_IF_OWNER = ("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end")
_DELETE_IF_OWNER = ("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end")


def claim_refresh(client, key, owner, ttl):
    """Extend a claim only while ``owner`` still holds it (one atomic step on the server), so a holder whose claim lapsed and was taken
    by another job can never extend the new holder's. When the key is gone, take it again if nobody has. Returns 'ok', 'regained' or
    'lost'."""
    owner = str(owner)
    if client.eval(_EXPIRE_IF_OWNER, 1, key, owner, int(ttl)):
        return 'ok'
    if client.set(key, owner, nx=True, ex=int(ttl)):
        return 'regained'
    return 'lost'


def claim_release(client, key, owner):
    """Delete a claim only if ``owner`` still holds it, in one atomic step: a lock that lapsed and was taken by another job is not deleted."""
    return bool(client.eval(_DELETE_IF_OWNER, 1, key, str(owner)))


@contextmanager
def redis_claim(key, owner, ttl):
    """Hold ``key`` in Redis for ``owner`` (SET NX EX), refreshing it while the block runs. Yields True when this
    caller holds it, or when no Redis is available to ask, else the owner that does. The key is released on exit, and
    expires on its own ``ttl`` seconds after a crashed worker stops refreshing it."""
    client = getattr(get_store(), 'r', None)
    if client is None:
        yield True
        return
    owner = str(owner)
    try:
        got = client.set(key, owner, nx=True, ex=ttl)
        holder = None if got else client.get(key)
    except Exception:  # noqa: BLE001 - never block scanning because the claim is unavailable
        yield True
        return
    if not got:
        yield holder or 'another job'
        return
    stop = threading.Event()

    def keep_alive():
        while not stop.wait(ttl / 6):
            try:
                if claim_refresh(client, key, owner, ttl) == 'lost':
                    logger.warning('claim %s was taken over by another job while this one still runs; no longer refreshing it', key)
                    return
            except Exception:  # noqa: BLE001
                pass
    threading.Thread(target=keep_alive, name='redis-claim', daemon=True).start()
    try:
        yield True
    finally:
        stop.set()
        try:
            claim_release(client, key, owner)
        except Exception:  # noqa: BLE001
            pass


# --- the gate ------------------------------------------------------------------------------------------------------

def terminate_group(proc, grace=10):
    """Stop a subprocess and everything it started: SIGTERM to its process group, SIGKILL if it lingers. Descendants that left the group (a browser
    starts its own session) are found by parent pid first and stopped with it."""
    try:
        others = tree_pids(proc.pid) - {proc.pid}
    except Exception:  # noqa: BLE001 - the group kill below still happens
        others = set()

    def send(sig):
        try:
            if os.getpgid(proc.pid) == proc.pid:
                os.killpg(proc.pid, sig)
            else:
                proc.send_signal(sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        for pid in others:
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError, OSError):
                pass
    send(signal.SIGTERM)
    deadline = time.time() + grace
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.5)
    if proc.poll() is None or any(os.path.exists(f'/proc/{pid}') for pid in others):
        send(signal.SIGKILL)


class LegacyProcessMonitor:
    """Cooperatively stop older scanner commands that do not use heavy_job."""

    def __init__(self, proc, scan_id=None):
        self.proc, self.scan_id = proc, scan_id
        self.aborted = False
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._watch, name='legacy-scan-stop', daemon=True)
        self.thread.start()

    def _watch(self):
        try:
            while self.proc.poll() is None and not self.stop_event.wait(1):
                if global_pause_requested() or (self.scan_id is not None and abort_requested(self.scan_id)):
                    self.aborted = True
                    terminate_group(self.proc, grace=5)
                    return
        finally:
            from django.db import connections
            connections.close_all()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=2)

    def raise_if_aborted(self):
        if self.aborted:
            raise ScanAborted('scanner process stopped by a scan or global pause')


class Job:
    """One admitted heavy job: tracks the attached process and stops it under memory pressure."""

    def __init__(self, kind, cost, label, store, state_fn, now_fn):
        self.kind, self.cost, self.label = kind, cost, label
        self.token = uuid.uuid4().hex
        self.store, self.state_fn, self.now_fn = store, state_fn, now_fn
        self.proc = None
        self.killed_for_memory = False
        self.scan_id = _current_scan.get()  # the scan this job works for, if a pipeline set one
        self.aborted = False
        self.peak = 0
        self.started = now_fn()
        self._stop = threading.Event()
        self._thread = None

    def attach(self, proc):
        """Tell the gate which subprocess to measure and, if need be, stop. Start it with start_new_session=True so the
        whole tree can be signalled."""
        self.proc = proc
        if global_pause_requested() or (self.scan_id is not None and abort_requested(self.scan_id)):
            self.aborted = True
            terminate_group(proc, grace=5)

    def rss_mb(self):
        return tree_rss_mb(self.proc.pid) if self.proc is not None and self.proc.poll() is None else 0

    def check_once(self):
        """One watchdog tick: publish this job's memory, and stop it if it is the biggest job while memory is critical."""
        now = self.now_fn()
        # a stop comes first, so a store or telemetry problem below can never keep a stopped scan's scanner running
        if not self.aborted and (global_pause_requested() or (self.scan_id is not None and abort_requested(self.scan_id))):
            self.aborted = True  # the scan was stopped: kill the scanner and everything it started
            if self.proc is not None and self.proc.poll() is None:
                logger.info('scanner was stopped: killing %s [%s]', self.kind, self.label)
                terminate_group(self.proc, grace=5)
            return True
        rss = self.rss_mb()
        self.peak = max(self.peak, rss)
        self.store.heartbeat(self.token, rss, now)
        try:
            report_state(self.store, self.state_fn, self.now_fn)
        except Exception:  # noqa: BLE001 - shared telemetry only; the memory checks below still run
            logger.exception('could not publish resource telemetry')
        if self.killed_for_memory or self.proc is None or self.proc.poll() is not None or now - self.started < GRACE_SECONDS:
            return False
        state = self.state_fn()
        if state['available_mb'] >= critical_mb(state):
            return False
        live = self.store.live(now)
        victim = max(live, key=lambda j: (j.get('rss', 0), j['mb']), default=None)
        if victim is None or victim['token'] != self.token:
            return False
        self.killed_for_memory = True
        logger.warning('memory critical (%s MB free): stopping %s [%s] using %s MB', state['available_mb'], self.kind, self.label, rss)
        self.store.event({'t': now, 'kind': self.kind, 'label': self.label, 'rss_mb': rss, 'available_mb': state['available_mb']})
        _log_activity(f'Out of memory ({state["available_mb"]} MB free): stopped a {self.kind} run to protect the other work; '
                      'it will be retried lighter', status='failed')  # system-wide line: never the label, which names a tenant's host
        terminate_group(self.proc)
        return True

    def _run(self):
        try:
            while not self._stop.wait(HEARTBEAT_SECONDS):
                try:
                    self.check_once()
                except Exception:  # noqa: BLE001 - the watchdog must never take the job down by itself
                    logger.exception('memory watchdog tick failed')
        finally:
            from django.db import connections
            connections.close_all()

    def start_watchdog(self):
        self._thread = threading.Thread(target=self._run, name=f'mem-watch-{self.kind}', daemon=True)
        self._thread.start()

    def stop_watchdog(self):
        self._stop.set()

    def raise_if_killed(self):
        if self.aborted or global_pause_requested() or (self.scan_id is not None and abort_requested(self.scan_id)):
            raise ScanAborted(f'{self.kind} was stopped with its scan')
        if self.killed_for_memory:
            raise MemoryKill(f'{self.kind} was stopped because the container ran low on memory')


def _log_activity(message, status='done'):
    try:
        from cveFeed import activity
        return activity.log('run_check', message, status=status)
    except Exception:  # noqa: BLE001 - tests and non-Django callers have no activity feed
        return None


@contextmanager
def heavy_job(kind, label='', cost=None, wait_timeout=None, store=None, state_fn=memory_state, sleep=time.sleep, now_fn=time.time):
    """Run a heavy process under the memory gate::

        with heavy_job('nuclei', label='example.com') as job:
            proc = subprocess.Popen(cmd, ..., start_new_session=True)
            job.attach(proc)
            ...consume the process...
            job.raise_if_killed()
    """
    store = store or get_store()
    cost = cost or effective_cost(kind, store)
    deadline = now_fn() + (wait_timeout if wait_timeout is not None else (_env_float('HEAVY_WAIT_SECONDS') or DEFAULT_WAIT_SECONDS))
    job = Job(kind, cost, label, store, state_fn, now_fn)
    announced = None
    while True:
        now = now_fn()
        state = state_fn()
        alone = not store.live(now)
        roomy = alone or state['available_mb'] >= cost + headroom_mb(state)
        if roomy and store.reserve(job.token, cost, f'{kind}: {label}'[:120], budget_mb(state), now, kind, max_concurrent(kind)):
            break
        if global_pause_requested(fail_closed=True) or (job.scan_id is not None and abort_requested(job.scan_id)):
            store.release(job.token)
            raise ScanAborted(f'{kind} on {label} was stopped before it started')
        store.wait(job.token, cost, f'{kind}: {label}'[:120], now)
        if announced is None or now - announced > 300:
            announced = now
            _log_activity(f'Waiting for memory to start a {kind} run (needs about {cost} MB, {state["available_mb"]} MB free); '
                          'other work is running', status='running')  # system-wide line: never the label, which names a tenant's host
        if now >= deadline:
            store.release(job.token)
            raise MemoryBusy(f'{kind} on {label} waited too long for memory ({state["available_mb"]} MB free, needs {cost} MB)')
        sleep(random.uniform(*POLL_SECONDS))
    job.started = now_fn()
    job.start_watchdog()
    try:
        yield job
    except BaseException:
        # Celery's gevent hard timeout interrupts a scanner with a BaseException, not
        # subprocess.TimeoutExpired. Stop the attached process tree before releasing
        # its memory reservation or another scanner may start beside the orphan.
        if job.proc is not None:
            try:
                terminate_group(job.proc, grace=5)
            except Exception:  # noqa: BLE001 - preserve the original task failure
                logger.exception('could not stop scanner process after heavy job failed')
        raise
    finally:
        job.stop_watchdog()
        store.release(job.token)
        if job.peak >= 50:  # a stopped job only shows a lower bound of what it needed, so leave room above it
            try:
                store.learn(kind, int(job.peak * (1.35 if job.killed_for_memory else 1.0)))
            except Exception:  # noqa: BLE001
                logger.debug('could not record the memory used by %s', kind)


def snapshot(store=None, state_fn=memory_state, now_fn=time.time):
    """What the Settings > Resources page shows."""
    store = store or get_store()
    now, state = now_fn(), state_fn()
    return {
        'memory': state, 'budget_mb': budget_mb(state), 'headroom_mb': headroom_mb(state), 'critical_mb': critical_mb(state),
        'store': _store['kind'] or 'process',
        'running': [{'label': j['label'], 'reserved_mb': j['mb'], 'rss_mb': j.get('rss', 0), 'seconds': int(now - j.get('start', now))}
                    for j in store.live(now)],
        'waiting': [{'label': w['label'], 'needs_mb': w['mb'], 'seconds': int(now - w.get('since', now))} for w in store.waiting(now)],
        'memory_kills': [e for e in store.events() if now - e.get('t', 0) < 86400],
        'costs_mb': {kind: effective_cost(kind, store) for kind in BASE_COSTS_MB},
        'learned_mb': store.learned(),
    }


def report_state(store=None, state_fn=memory_state, now_fn=time.time):
    """Publish this container's memory picture (called every 30 seconds by a beat task and on every watchdog tick)."""
    store = store or get_store()
    state = state_fn()
    now = now_fn()
    waiting, running = {}, {}
    for item in store.waiting(now):
        kind = str(item.get('label', '')).split(':', 1)[0]
        waiting[kind] = waiting.get(kind, 0) + 1
    for item in store.live(now):
        kind = item.get('kind') or str(item.get('label', '')).split(':', 1)[0]
        running[kind] = running.get(kind, 0) + 1
    store.publish_state({'host': socket.gethostname(), 'memory': state, 'budget_mb': budget_mb(state), 'headroom_mb': headroom_mb(state),
                         'critical_mb': critical_mb(state), 'waiting_by_kind': waiting, 'running_by_kind': running,
                         'memory_kills_3h': sum(1 for event in store.events() if now - event.get('t', 0) <= 3 * 3600), 't': now})


def adaptive_history(since):
    """Bounded in-memory telemetry from scanner containers; missing Redis means no tuning."""
    store = get_store()
    if not isinstance(store, RedisStore):
        return []
    samples = []
    for key in store.r.scan_iter(match='cvengine:heavy:*:history'):
        for raw in store.r.lrange(key, 0, 399):
            try:
                item = json.loads(raw)
                if float(item.get('t', 0)) >= since:
                    samples.append(item)
            except (TypeError, ValueError):
                continue
    return samples


def cluster_snapshot(now_fn=time.time):
    """Every container that runs heavy jobs, for the Settings > Resources page. The web container reads what the celery
    containers published to Redis; without Redis it can only describe itself."""
    store = get_store()
    if _store['kind'] != 'redis':
        return {'store': 'process', 'containers': [{'host': socket.gethostname(), **snapshot(store, now_fn=now_fn)}]}
    containers = []
    for key in sorted(store.r.scan_iter(match='cvengine:heavy:*:state')):
        namespace = key[:-len(':state')]
        other = RedisStore(store.r, namespace)
        try:
            published = json.loads(store.r.get(key) or '{}')
        except ValueError:
            continue
        now = now_fn()
        containers.append({
            'host': published.get('host') or namespace.split(':')[2], 'memory': published.get('memory', {}),
            'budget_mb': published.get('budget_mb'), 'headroom_mb': published.get('headroom_mb'), 'critical_mb': published.get('critical_mb'),
            'age_seconds': int(now - published.get('t', now)),
            'running': [{'label': j['label'], 'reserved_mb': j['mb'], 'rss_mb': j.get('rss', 0), 'seconds': int(now - j.get('start', now))}
                        for j in other.live(now)],
            'waiting': [{'label': w['label'], 'needs_mb': w['mb'], 'seconds': int(now - w.get('since', now))} for w in other.waiting(now)],
            'memory_kills': [e for e in other.events() if now - e.get('t', 0) < 86400],
        })
    return {'store': 'redis', 'containers': containers, 'costs_mb': {kind: cost_mb(kind) for kind in BASE_COSTS_MB}}
