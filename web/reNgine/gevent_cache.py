"""One Django cache client per gevent worker, not one per greenlet.

Django keeps its cache clients in an ``asgiref`` ``Local`` (``django.core.cache.caches``), which is a context variable, and greenlet gives every new greenlet a
context of its own. In a gevent worker each task is a new greenlet, so each task that touched the cache (``reNgine/lane_memory.py`` writes the lane's record at
every task start and end) built a new ``RedisCache``, a new connection pool and a new connection to Redis, which stayed open until the garbage collector freed the
finished greenlet's client (200 finished greenlets left 200 sockets open; on Python 3.14.4 the worker's 30 s young collection often frees none of them, see
``reNgine/gevent_gc.py``). When tasks started in bursts, the classic lane opened Redis connections faster than they were freed: on the VPS on 11/23 it went from
321 to 1,024 open files (its limit) in nine seconds, nearly all of them connections to Redis, every new connection then failed (``OSError: [Errno 24] Too many open files``), and a lane that cannot connect answers no ping and writes no heartbeat,
which is what the watchdog's rule R1 restarts.

``install`` (called by ``reNgine/celery.py`` in a gevent worker) puts a plain shared holder in place of that ``Local``, so every greenlet of the process uses the
same cache client and its one connection pool, and makes that pool a blocking one (``POOL_MAX`` connections; a greenlet that finds them all in use waits up to
``POOL_WAIT_SECONDS`` for one instead of failing with "Too many connections"). A connection is handed to one greenlet at a time and goes back to the pool after
each command; under gevent the pool's lock and queue are gevent's. The web server, beat, the tests and management commands keep Django's own per-thread clients.
"""
import logging

logger = logging.getLogger(__name__)

POOL_MAX = 100          # Redis connections one worker's cache client may hold at once (a lane runs at most a few dozen greenlets)
POOL_WAIT_SECONDS = 20  # how long a cache call waits for a free connection when all of them are in use


class SharedConnections:
    """Stands in for the ``Local`` of a Django connection handler: one attribute per alias, the same for every greenlet and thread of the process."""


def _gevent_worker():
    try:
        from gevent import monkey
        return monkey.is_module_patched('socket')
    except ImportError:
        return False


def install(handler=None):
    """True when the cache handler now shares its clients (a gevent worker). Never raises."""
    if not _gevent_worker():
        return False
    try:
        if handler is None:
            from django.core.cache import caches as handler
        if isinstance(handler._connections, SharedConnections):
            return True
        for conf in handler.settings.values():
            if str(conf.get('BACKEND', '')).endswith('.redis.RedisCache'):
                options = conf.setdefault('OPTIONS', {})
                options.setdefault('pool_class', 'redis.BlockingConnectionPool')
                options.setdefault('max_connections', POOL_MAX)
                options.setdefault('timeout', POOL_WAIT_SECONDS)
        handler._connections = SharedConnections()
    except Exception:  # noqa: BLE001 - a worker with Django's own clients still runs
        logger.warning('gevent_cache: could not share the cache clients between greenlets', exc_info=True)
        return False
    return True
