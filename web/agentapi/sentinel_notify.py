"""Redis wake-ups for the Sentinel queue (docs/SCANNER-ARCHITECTURE.md, "Asynchronous stages").

Two waits used to poll the database: a Sentinel's long poll (``sentinel_broker.next_task``, once a second) and a stage that waits for its task
(``sentinel_dispatch``, every half second). Both now block on a Redis list (``BLPOP``) that the event they wait for pushes to:

- a task is queued (``task_queued``): every live Sentinel that could take it (its project, its kind) gets a token on
  ``cvengine:sentinel:wake:agent:<id>``, so the long polls that are waiting for work answer at once;
- a task changes hands (``task_changed``: claimed, reported, failed, expired, cancelled, released): a token on
  ``cvengine:sentinel:wake:task:<id>`` wakes the stage waiting for it, and a task that ended frees a slot of the Sentinel that held it, so that
  Sentinel's long poll is woken too.

A token is one short list entry that expires on its own (``TOKEN_TTL``); nothing reads it but the waits. A missed or lost token costs one safety
interval: every wait still wakes on its own after ``safety_seconds()`` (``CVENGINE_SENTINEL_WAKE_POLL_SECONDS``, default 5) and looks again, so a
Redis that is down, a restart between the event and the wait, or an event this module does not see (a lease that simply ran out) is never more
than that late. Without Redis the waits sleep as before. Every function here swallows its own errors: a wake-up is a speed-up, never a dependency.

A completed task also wakes a ``StageRun`` waiting on it, but not through Redis: ``stage_runs.task_ended`` queues its callback directly.
"""
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

PREFIX = 'cvengine:sentinel:wake'
TOKEN_TTL = 60  # seconds a wake token lives when nobody takes it
DEFAULT_SAFETY = 5  # seconds: the longest a wait sleeps before it looks again by itself
MAX_SAFETY = 30
SAFETY_ENV = 'CVENGINE_SENTINEL_WAKE_POLL_SECONDS'

_clients = {}
_lock = threading.Lock()
_warned = set()


def safety_seconds():
    """``CVENGINE_SENTINEL_WAKE_POLL_SECONDS``: the slow poll that stays as a safety net (default 5, 1 to 30)."""
    try:
        return max(1, min(MAX_SAFETY, int(os.environ.get(SAFETY_ENV, str(DEFAULT_SAFETY)))))
    except ValueError:
        return DEFAULT_SAFETY


def _url():
    return os.environ.get('CELERY_BROKER') or os.environ.get('CELERY_BROKER_URL') or ''


def client():
    """A Redis client for blocking reads, or ``None`` without Redis. Its socket timeout is longer than any wait here (the shared store's client
    times out after five seconds, which a ``BLPOP`` of five seconds would hit)."""
    url = _url()
    if not url.startswith(('redis://', 'rediss://', 'unix://')):
        return None
    with _lock:
        found = _clients.get(url)
        if found is not None:
            return found
        try:
            import redis
            found = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=MAX_SAFETY + 10, decode_responses=True)
        except Exception as exc:  # noqa: BLE001 - a wake-up is a speed-up, never a dependency
            _warn('client', exc)
            return None
        _clients[url] = found
        return found


def _warn(what, exc):
    if what not in _warned:
        _warned.add(what)
        logger.warning('Sentinel wake-ups (%s) are not available, the waits fall back to polling: %s', what, exc)


def agent_key(agent_id):
    return f'{PREFIX}:agent:{int(agent_id)}'


def task_key(task_id):
    return f'{PREFIX}:task:{int(task_id)}'


def _push(keys):
    keys = [k for k in dict.fromkeys(keys)]
    if not keys:
        return 0
    r = client()
    if r is None:
        return 0
    try:
        pipe = r.pipeline(transaction=False)
        for key in keys:
            pipe.lpush(key, '1')
            pipe.ltrim(key, 0, 0)  # one token is enough: a wait wakes once and looks at everything
            pipe.expire(key, TOKEN_TTL)
        pipe.execute()
        return len(keys)
    except Exception as exc:  # noqa: BLE001
        _warn('push', exc)
        return 0


def _after_commit(fn):
    """Run ``fn`` once the current transaction commits (at once outside one), so a woken reader finds the row it was woken for."""
    from django.db import transaction
    try:
        transaction.on_commit(fn)
    except Exception:  # noqa: BLE001 - no usable connection: just do it
        fn()


def wake_agents(agent_ids):
    _after_commit(lambda ids=list(agent_ids): _push([agent_key(i) for i in ids if i]))


def wake_tasks(task_ids):
    _after_commit(lambda ids=list(task_ids): _push([task_key(i) for i in ids if i]))


def task_queued(task):
    """A task was queued: wake the long polls of the live Sentinels that could take it (its project and kind; a signed-in task only the built-in
    scanner). Never raises."""
    def wake(task_id=task.pk):
        try:
            from agentapi import sentinel_broker
            from agentapi.models import SentinelTask
            row = SentinelTask._base_manager.select_related('project__org').filter(pk=task_id, status='queued').first()
            if row is None:
                return
            eligible = sentinel_broker.eligible_sentinels(row.project, row.kind, live_only=True, builtin_only=bool(row.secret_ref))
            _push([agent_key(e.agent.pk) for e in eligible])
        except Exception as exc:  # noqa: BLE001
            _warn('queued', exc)
    _after_commit(wake)  # the lookup too: nothing is asked inside the transaction that queued it


def task_changed(task, agent_id=None):
    """A task was claimed, ended or handed back: wake the stage that waits for it, and (``agent_id``, the Sentinel that held it) that Sentinel's
    long poll, since a slot of it may have freed. Never raises."""
    try:
        wake_tasks([task.pk])
        if agent_id:
            wake_agents([agent_id])
    except Exception as exc:  # noqa: BLE001
        _warn('changed', exc)


def _blpop(keys, timeout):
    """Block on ``keys`` for at most ``timeout`` seconds. ``True``: woken; ``False``: the time ran out; ``None``: there is no Redis to block on."""
    r = client()
    if r is None:
        return None
    try:
        found = r.blpop(keys, timeout=round(max(0.01, float(timeout)), 2))
        return found is not None
    except Exception as exc:  # noqa: BLE001
        _warn('wait', exc)
        return None


def wait_agent(agent_id, timeout, sleep=None):
    """Wait up to ``timeout`` seconds for a wake token of this Sentinel (new work it may take, or a slot of it that freed). Returns whether it was
    woken. Without Redis it sleeps ``timeout`` (``sleep``) and returns False."""
    if timeout <= 0:
        return False
    woke = _blpop([agent_key(agent_id)], timeout)
    if woke is None:
        (sleep or time.sleep)(timeout)
        return False
    return woke


def wait_tasks(task_ids, timeout, sleep=None):
    """Wait up to ``timeout`` seconds for any of ``task_ids`` to change hands. Returns whether it was woken; without Redis it sleeps and returns False."""
    if timeout <= 0:
        return False
    keys = [task_key(i) for i in task_ids if i]
    woke = _blpop(keys, timeout) if keys else None
    if woke is None:
        (sleep or time.sleep)(timeout)
        return False
    return woke
