"""How often the server's own rate limiter refused an agent's call (the maintainer's signals, ``agentapi.maintainer_signals``).

On the day the limiter refused every Sentinel claim for an hour, the only trace was one log line, and the tasks that expired unclaimed read as "waited for a
slot": the status advised adding capacity while every slot was idle. ``agent_broker._hit`` now calls ``note`` where it refuses. A refusal is one
``HINCRBY`` on an hourly Redis hash (field ``action|who``, ``who`` being the token's hash prefix or ``user:<id>``, the very name the limiter counts under)
that expires after ``KEEP_HOURS``; the status reads the last day's hashes (24 small keys) and names each token's Sentinel. Nothing here raises: counting
a refusal must never change the answer the caller gets.
"""
import logging
import time

from django.core.cache import cache

logger = logging.getLogger(__name__)

KEY = 'cvengine:claim_refused:'
KEEP_HOURS = 26
MAX_FIELDS = 200  # distinct (action, caller) pairs one hour keeps: a flood of tokens cannot grow the hash without bound


def _client(key):
    return cache._cache.get_client(key, write=True)  # the Redis client behind the cache, as agent_broker._without_expiry uses it


def note(name, now=None):
    """Count one refusal of the limiter counter ``name`` (``agentapi:<action>:<who>``). Returns True when it was counted."""
    try:
        parts = str(name).split(':', 2)
        if len(parts) != 3 or parts[0] != 'agentapi' or not parts[1] or not parts[2]:
            return False
        field = f'{parts[1]}|{parts[2][:40]}'
        key = KEY + time.strftime('%Y%m%d%H', time.gmtime(time.time() if now is None else now))
        client = _client(key)
        if client.hlen(key) >= MAX_FIELDS and not client.hexists(key, field):
            return False
        client.hincrby(key, field, 1)
        client.expire(key, KEEP_HOURS * 3600)
        return True
    except Exception:  # noqa: BLE001 - a diagnostic: never let it break the refusal it describes
        logger.debug('claim refusals: could not count a refusal', exc_info=True)
        return False


def read(now=None, hours=24):
    """``{(action, who): [this clock hour, the clock hour before, all ``hours`` hours]}`` refusal counts (UTC clock hours: the counter is kept per hour, so
    it cannot say "the last 60 minutes" exactly). Raises when the cache has no Redis client or Redis cannot be asked."""
    now = time.time() if now is None else now
    keys = [KEY + time.strftime('%Y%m%d%H', time.gmtime(now - i * 3600)) for i in range(hours)]
    client = _client(keys[0])
    pipe = client.pipeline(transaction=False)
    for key in keys:
        pipe.hgetall(key)
    out = {}
    for i, rows in enumerate(pipe.execute()):
        for field, count in (rows or {}).items():
            field = field.decode() if isinstance(field, bytes) else field
            action, _, who = field.partition('|')
            try:
                count = int(count)
            except (TypeError, ValueError):
                continue
            row = out.setdefault((action, who), [0, 0, 0])
            row[2] += count
            if i < 2:
                row[i] += count
    return out
