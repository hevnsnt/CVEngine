"""Shared runtime helpers of the server's workers: stopping and pausing scans, Redis claims, the published Settings values, and each
container's memory picture.

The server runs no scanner (every scan kind runs on a Sentinel, ``agentapi.sentinel_dispatch.NEVER_LOCAL``), so there is no per-tool memory
gate here any more: what used to admit nmap, nuclei or bbot runs by their estimated memory (``heavy_job``, the ``heavy.<kind>`` limits of
Settings, configMaxxing, and the ``HEAVY_*`` environment variables) was removed with the last local scanner. What remains:

* **Waiting, not failing.** ``ScannerUnavailable`` (and its ``AddressExcluded`` and ``ScannerReportedNothing``) is raised when work needs a
  Sentinel and none can take it: every stage treats it as "not the target's failure, it stays due".
* **Stopping.** ``request_abort``/``abort_requested``/``global_pause_requested``: a cooperative stop flag in Redis that the pipeline checks
  between stages.
* **Claims.** ``redis_claim``, ``claim_refresh``, ``claim_release``: one holder at a time for a key, with owner-checked expiry.
* **Published values.** ``saved_values`` and ``auto_values``: what a person saved on Settings, configMaxxing and what the auto-tuner chose,
  read from Redis by every worker within seconds.
* **Memory picture.** ``memory_state`` (cgroup and ``/proc/meminfo``), published by each worker container every 30 seconds
  (``report_state``) and read back by the web container (``cluster_snapshot``) for the Resources panel, system status and the watchdog's
  memory pause.
"""
import contextvars
import json
import logging
import os
import socket
import threading
import time
from contextlib import contextmanager

logger = logging.getLogger(__name__)

CGROUP_ROOT = '/sys/fs/cgroup'
MEMINFO = '/proc/meminfo'


class MemoryBusy(RuntimeError):
    """Work that could not start now and stays due: the base of ``ScannerUnavailable``. The name is kept from when a memory gate on this
    server raised it; stages catch it as "not the target's failure"."""


class ScannerUnavailable(MemoryBusy):
    """The scan work needs a Sentinel and none could take it, and no kind runs on this server (``sentinel_dispatch.NEVER_LOCAL``). It is
    a ``MemoryBusy`` on purpose: every stage already treats that as "not the target's failure, it stays due", which is what waiting for
    a scanner to come back must look like (nothing marked failed, nothing scanned locally). ``done`` is what a Sentinel did finish of the
    stage before it had to wait (the nmap stage's addresses a Sentinel fully covered, ``sentinel_dispatch.try_nmap``): the caller may mark
    those done, and only the rest stays due. Empty everywhere else."""

    waiting = False  # back-pressure: every Sentinel that can run it was busy (or none claimed it in time); nothing is wrong, so it is not recorded as a failure

    def __init__(self, kind, why='', waiting=False):
        self.kind, self.why, self.done = kind, why, []
        self.waiting = bool(waiting)
        super().__init__(f'no scanner could run {kind} work{": " + why if why else ""}; it stays due until one can')


class AddressExcluded(ScannerUnavailable):
    """The work names an address (or a host that resolves to one) on the organization's do-not-scan list, or the list could not be read: no task is created
    (``agentapi.address_guard``). A ``ScannerUnavailable`` so that every stage already treats it as \"not the target's failure, nothing ran\"; ``refusal`` says
    why, in plain words."""

    def __init__(self, kind, refusal):
        self.kind, self.why, self.done, self.refusal, self.waiting = kind, str(refusal), [], refusal, False
        MemoryBusy.__init__(self, f'{kind} work was not started: {refusal}')


class ScannerReportedNothing(ScannerUnavailable):
    """A Sentinel took the work and finished it, but its report is unusable for the address (empty, cut short, or naming other addresses
    only). Unlike a plain ``ScannerUnavailable`` (no scanner was there), asking again at once cannot help when the scanner keeps returning
    the same, so a caller may cap how often it asks (``cveFeed.udp_scan.MAX_EMPTY_PER_DAY``)."""


class ScanAborted(RuntimeError):
    """The scan this work belongs to was stopped by a person; the work stops and the pipeline exits cleanly."""


# --- stopping a scan -----------------------------------------------------------------------------------------------
# The workers are gevent pools, where a celery revoke cannot terminate a running task, so stopping is cooperative: the stop
# sets a flag (Redis, shared by all workers; plus this process) and the pipeline checks it between stages and before each dispatch.
_current_scan = contextvars.ContextVar('cvengine_current_scan', default=None)
_aborted_here = set()
ABORT_KEY = 'cvengine:abort:'
ABORT_TTL = 24 * 3600


@contextmanager
def scan_context(scan_id):
    """Mark the work in this block as belonging to ``scan_id``, so a stop of that scan reaches it."""
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
    try:  # a stage of it that waits on Sentinels without a worker (agentapi.stage_runs) hears of the stop now, not at its next budget
        from agentapi import stage_runs
        stage_runs.wake_scan(int(scan_id))
    except Exception:  # noqa: BLE001
        pass


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


def memory_state(root=CGROUP_ROOT, meminfo_path=MEMINFO, host=False):
    """{'total_mb', 'limit_mb' (None = unlimited), 'used_mb', 'available_mb'} for this container. ``host`` leaves this container's own cgroup
    limit out: the machine's memory as ``/proc/meminfo`` gives it, which inside a container is the Docker host's (on Docker Desktop, its VM's).
    That is the memory a sidecar in containers of its own (OpenVAS) draws on, not this container's budget."""
    info = meminfo(meminfo_path)
    host_total, host_available = info.get('MemTotal', 0), info.get('MemAvailable', info.get('MemFree', 0))
    limit, used = (None, None) if host else cgroup_memory(root)
    if limit is not None and used is not None:
        limit_mb, used_mb = limit // (1 << 20), used // (1 << 20)
        total = min(limit_mb, host_total) if host_total else limit_mb
        available = min(max(limit_mb - used_mb, 0), host_available) if host_available else max(limit_mb - used_mb, 0)
        return {'total_mb': total, 'limit_mb': limit_mb, 'used_mb': used_mb, 'available_mb': available}
    return {'total_mb': host_total, 'limit_mb': None, 'used_mb': max(host_total - host_available, 0), 'available_mb': host_available}


# What an App Admin saved on Settings, configMaxxing (cveFeed.scan_concurrency): the web process writes the saved values to this Redis key on every
# save and the 30 second tick writes them again, and each process keeps a copy for SAVED_CACHE_SECONDS. This module only reads the key (it must stay
# importable by itself: it runs inside every worker task and in a child interpreter in the tests).
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


# --- the shared Redis handle ---------------------------------------------------------------------------------------

class MemoryStore:
    """No Redis: this process only. ``r`` is None, so a caller that needs Redis (claims, ledgers, the published memory picture) falls back to
    what it does without one. Used by the tests and when the broker is not Redis."""
    r = None

    def publish_state(self, state):
        self._state = state


class RedisStore:
    """The broker's Redis, shared by every worker process. ``namespace`` carries the container's host name: each container publishes its own
    memory picture (``report_state``)."""

    def __init__(self, client, namespace):
        self.r = client
        self.state_key, self.history_key = f'{namespace}:state', f'{namespace}:history'

    def publish_state(self, state):
        """Let the web container (a different memory cgroup) see this container's memory, with a few hours of history for the auto-tuner."""
        self.r.set(self.state_key, json.dumps(state), ex=120)
        try:
            self.r.lpush(self.history_key, json.dumps(state))
            self.r.ltrim(self.history_key, 0, 399)
            self.r.expire(self.history_key, 4 * 3600)
        except Exception:  # noqa: BLE001
            logger.debug('memory history sample could not be stored', exc_info=False)


STATE_PREFIX = 'cvengine:heavy:'  # the key prefix every container publishes under (kept from the memory gate, so readers of an older worker still match)
_store = {'obj': None, 'kind': None}
_store_lock = threading.Lock()


def get_store():
    """Redis when reachable (``.r`` is the client), else a per-process store whose ``.r`` is None."""
    with _store_lock:
        if _store['obj'] is None:
            url = os.environ.get('CELERY_BROKER') or os.environ.get('CELERY_BROKER_URL') or ''
            if url.startswith(('redis://', 'rediss://', 'unix://')):
                try:
                    import redis
                    client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=5, decode_responses=True)
                    client.ping()
                    _store.update(obj=RedisStore(client, f'{STATE_PREFIX}{socket.gethostname()}'), kind='redis')
                except Exception as exc:  # noqa: BLE001 - never block work because shared bookkeeping is unavailable
                    logger.warning('Redis unavailable (%s); claims and the memory picture stay in this process', exc)
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


# The batched forms of the two calls above, for a holder of many claims (a waiting StageRun can hold tens of thousands): one script per
# chunk of at most CLAIM_BATCH keys instead of one round trip per key. KEYS are the claim keys, ARGV the owner of each key in the same order,
# then the ttl. Each key gets exactly what the single-key call does to it: refreshed only while its owner holds it, else taken again when
# nobody has it (the SET NX EX of claim_refresh, done in the same script), else left alone; deleted only while its owner holds it. A key the
# GET fails on (a key of another type) is skipped and marked -1, so the script never stops half way (Redis does not undo the keys a failed
# script already changed); the caller asks that key again on its own, which fails as the single-key call does.
CLAIM_BATCH = 500
_REFRESH_MANY = (
    "local ttl = ARGV[#ARGV] local out = {} "
    "for i, key in ipairs(KEYS) do "
    "local held = redis.pcall('get', key) "
    "if type(held) == 'table' and held.err then out[i] = -1 "
    "elseif held == ARGV[i] then out[i] = redis.call('expire', key, ttl) "
    "elseif redis.call('set', key, ARGV[i], 'NX', 'EX', ttl) then out[i] = 2 "
    "else out[i] = 0 end "
    "end return out")
_RELEASE_MANY = (
    "local out = {} "
    "for i, key in ipairs(KEYS) do "
    "local held = redis.pcall('get', key) "
    "if type(held) == 'table' and held.err then out[i] = -1 "
    "elseif held == ARGV[i] then out[i] = redis.call('del', key) "
    "else out[i] = 0 end "
    "end return out")
_REFRESH_WORDS = {1: 'ok', 2: 'regained', 0: 'lost'}
_AGAIN = object()  # a key the chunk's script could not read: asked again on its own


def _claim_batches(client, pairs, size, batch, single):
    """Run ``batch(chunk)`` per chunk of ``pairs``, in input order. A key the script marked (``_AGAIN``) is asked again on its own with
    ``single(key, owner)``, and a chunk whose call fails is retried key by key the same way, so one bad key never costs the other keys their
    result. A key whose own call fails too gets None. A connection error is not retried key by key: every key would fail the same way, one
    timeout each."""
    out = []
    pairs = [(key, str(owner)) for key, owner in pairs]
    for start in range(0, len(pairs), max(1, int(size))):
        chunk = pairs[start:start + max(1, int(size))]
        try:
            got = batch(chunk)
            if len(got) != len(chunk):
                raise ValueError(f'{len(got)} results for {len(chunk)} claims')
            for (key, owner), result in zip(chunk, got):
                if result is _AGAIN:
                    try:
                        result = single(key, owner)
                    except Exception:  # noqa: BLE001 - the key's result is unknown; a claim left behind expires on its own
                        result = None
                out.append(result)
            continue
        except Exception as exc:  # noqa: BLE001 - retried below, key by key
            if _connection_error(exc):
                logger.debug('claim batch of %s keys failed: Redis unreachable (%s)', len(chunk), exc)
                out.extend([None] * len(chunk))
                continue
            logger.debug('claim batch of %s keys failed (%s); retrying them one by one', len(chunk), exc)
        for key, owner in chunk:
            try:
                out.append(single(key, owner))
            except Exception:  # noqa: BLE001 - the key's result is unknown; a claim left behind expires on its own
                out.append(None)
    return out


def _connection_error(exc):
    try:
        import redis
    except ImportError:  # pragma: no cover - redis is a dependency of the worker image
        return False
    return isinstance(exc, (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError))


def claim_refresh_many(client, pairs, ttl, size=CLAIM_BATCH):
    """``claim_refresh`` for many ``(key, owner)`` pairs: one Redis call per ``size`` keys. Returns one result per pair, in input order, each
    'ok', 'regained' or 'lost' as ``claim_refresh`` would have returned it, or None when that key could not be refreshed at all (Redis
    failed for it even on its own)."""
    ttl = int(ttl)

    def batch(chunk):
        got = client.eval(_REFRESH_MANY, len(chunk), *[k for k, _o in chunk], *[o for _k, o in chunk], ttl)
        return [_AGAIN if int(v) < 0 else _REFRESH_WORDS[int(v)] for v in got]

    return _claim_batches(client, pairs, size, batch, lambda key, owner: claim_refresh(client, key, owner, ttl))


def claim_release_many(client, pairs, size=CLAIM_BATCH):
    """``claim_release`` for many ``(key, owner)`` pairs: one Redis call per ``size`` keys. Returns one result per pair, in input order: True
    when that owner held the key and it was deleted, False when it did not, None when Redis failed for that key even on its own."""
    def batch(chunk):
        got = client.eval(_RELEASE_MANY, len(chunk), *[k for k, _o in chunk], *[o for _k, o in chunk])
        return [_AGAIN if int(v) < 0 else bool(v) for v in got]

    return _claim_batches(client, pairs, size, batch, lambda key, owner: claim_release(client, key, owner))


@contextmanager
def redis_claim(key, owner, ttl, adopt=False, hold=False, keep=None):
    """Hold ``key`` in Redis for ``owner`` (SET NX EX), refreshing it while the block runs. Yields True when this
    caller holds it, or when no Redis is available to ask, else the owner that does. The key is released on exit, and
    expires on its own ``ttl`` seconds after a crashed worker stops refreshing it.

    For a stage that waits on Sentinels without its worker (``agentapi.stage_runs``): ``adopt`` treats a key ``owner`` already holds as won (the
    pass that continues a run takes back the claim its first pass held); ``hold`` keeps the claim, instead of releasing it, when the block ends
    because the run waits (``Suspend``); ``keep`` is a dict the block may set ``keep['seconds']`` in to keep the claim that long after a normal end
    (a pipeline whose stages went on waiting). A kept claim is the run's to release or let expire."""
    client = getattr(get_store(), 'r', None)
    if client is None:
        yield True
        return
    owner = str(owner)
    try:
        got = client.set(key, owner, nx=True, ex=ttl)
        holder = None if got else client.get(key)
        if not got and adopt and holder == owner:
            got = bool(client.expire(key, ttl))
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
    from agentapi import stage_runs
    run = stage_runs.current()
    suspending = False
    try:
        yield True
    except stage_runs.Suspend:
        suspending = hold
        raise
    finally:
        stop.set()
        try:
            if suspending and run is not None:
                claim_refresh(client, key, owner, stage_runs.HOLD_SECONDS)
                run.hold_claim(key, owner)
            elif keep and keep.get('seconds'):
                claim_refresh(client, key, owner, int(keep['seconds']))
            else:
                claim_release(client, key, owner)
        except Exception:  # noqa: BLE001
            pass



# --- each container's memory picture -------------------------------------------------------------------------------

def report_state(store=None, state_fn=memory_state, now_fn=time.time):
    """Publish this container's memory (the 30 second ``report_resources`` beat task): read by ``cluster_snapshot`` in the web container."""
    store = store or get_store()
    now = now_fn()
    store.publish_state({'host': socket.gethostname(), 'memory': state_fn(), 't': now})
    if isinstance(store, RedisStore):  # this container's memory against its limit and its kernel oom kills, for the maintainer's signals (cvengine/container_signals.py)
        from cvengine import container_signals
        container_signals.publish('worker', client=store.r, now=now)


def adaptive_history(since):
    """The memory samples the worker containers published since ``since`` (newest first per container); empty without Redis."""
    store = get_store()
    if not isinstance(store, RedisStore):
        return []
    samples = []
    for key in store.r.scan_iter(match=f'{STATE_PREFIX}*:history', count=1000):
        for raw in store.r.lrange(key, 0, 399):
            try:
                item = json.loads(raw)
                if float(item.get('t', 0)) >= since:
                    samples.append(item)
            except (TypeError, ValueError):
                continue
    return samples


def cluster_snapshot(now_fn=time.time):
    """Every worker container's memory for the Settings > Resources panel, system status and the watchdog: ``{'store', 'containers': [{'host',
    'memory', 'age_seconds'}]}``. The web container reads what the celery containers published to Redis; without Redis it describes itself."""
    store = get_store()
    now = now_fn()
    if _store['kind'] != 'redis':
        return {'store': 'process', 'containers': [{'host': socket.gethostname(), 'memory': memory_state(), 'age_seconds': 0}]}
    containers = []
    for key in sorted(store.r.scan_iter(match=f'{STATE_PREFIX}*:state', count=1000)):
        try:
            published = json.loads(store.r.get(key) or '{}')
        except ValueError:
            continue
        containers.append({'host': published.get('host') or key[len(STATE_PREFIX):-len(':state')], 'memory': published.get('memory', {}),
                           'age_seconds': int(now - published.get('t', now))})
    return {'store': 'redis', 'containers': containers}
