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
    keep_process_name()
    logger.info('gevent worker: database waits yield to other greenlets')
    return True



def keep_process_name():
    """Stop a thread's name from becoming the process's name. Python 3.14 gives a thread's name to the operating system when it starts
    (``Thread._set_os_name``), and in a gevent worker a "thread" is a greenlet on the main thread, so starting one renamed the whole process in ``ps`` and ``top``
    (a Celery lane showed as ``status-warm-row``, then ``redis-claim``, then ``Thread-1 (keep_``, which read as processes that were not there). Naming the thread
    with ``name=None`` does not help (it gets ``Thread-1 (target)``). A no-op before 3.14, and outside gevent."""
    import threading
    if gevent_patched() and hasattr(threading.Thread, '_set_os_name'):
        threading.Thread._set_os_name = lambda self: None
        return True
    return False
