"""Let a gevent worker keep running while one of its tasks waits for the database.

psycopg2 waits for Postgres inside C code. On a gevent worker that wait freezes the whole process, not just the task that asked: no other greenlet runs,
the worker cannot answer a ping, the scheduler tasks on its lane (the work conductor) stop, and the queue behind it grows. On 11/9 the CVE-feed lane was
caught by ``kill -ABRT`` in exactly that state, inside the work planner's census query, and the watchdog restarted celery three times for a lane that
was only waiting on the database. psycopg2 has a hook for this (``set_wait_callback``); this is the usual gevent one: a query waits on the socket through
gevent, so every other greenlet runs meanwhile. A 3 second query used to leave a 3.01 second gap in a 0.1 second ticker, and leaves 0.10 with it.

Installed only in a process whose sockets gevent has patched (a gevent worker). The web server, the migration, management commands and the tests are
not gevent and keep psycopg2's own wait.
"""
import logging

logger = logging.getLogger(__name__)


def wait_callback(conn, timeout=None):
    """psycopg2's wait callback, waiting through gevent."""
    from gevent.socket import wait_read, wait_write
    from psycopg2 import OperationalError, extensions
    while True:
        state = conn.poll()
        if state == extensions.POLL_OK:
            return
        if state == extensions.POLL_READ:
            wait_read(conn.fileno(), timeout=timeout)
        elif state == extensions.POLL_WRITE:
            wait_write(conn.fileno(), timeout=timeout)
        else:
            raise OperationalError(f'bad state from poll: {state}')


def gevent_patched():
    try:
        from gevent import monkey
        return monkey.is_module_patched('socket')
    except ImportError:
        return False


def install():
    """True when the callback was installed (this process is a gevent worker)."""
    if not gevent_patched():
        return False
    from psycopg2 import extensions
    extensions.set_wait_callback(wait_callback)
    logger.info('gevent worker: database waits yield to other greenlets')
    return True


def thread_name(name):
    """``name`` for a ``threading.Thread``, or None in a gevent worker. Python 3.14 gives a thread's name to the operating system, and in a gevent worker a
    "thread" is a greenlet on the main thread, so naming one renames the whole process in ``ps`` and ``top`` (a Celery lane showed as ``status-warm-row``
    and ``redis-claim``, which read as processes that were not there). Outside gevent the name is kept: it shows in ``py-spy`` and ``ps -L``."""
    return None if gevent_patched() else name
