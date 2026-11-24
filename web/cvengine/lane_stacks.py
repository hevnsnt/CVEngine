"""A worker lane that stops answering can say where it stopped.

The watchdog restarts the celery container when a lane answers no ping and writes no heartbeat for minutes (rule R1). Such a lane is not busy in a
greenlet: its whole process has stopped switching (the heartbeat and the ping are greenlets of their own), so something holds the gevent hub inside C
code, and the restart is the only way out. The restart recreates the container, which drops its log, and nothing said what the lane was doing: on the
VPS the classic lane went silent about once an hour on 11/22 and 11/23 and every one of those restarts left no trace of the cause.

``install`` (called by ``cvengine/celery.py`` in a gevent worker) registers Python's ``faulthandler`` on ``SIGUSR2``. Its handler is C code that runs
even while the interpreter is stuck in a C call, and prints the Python stack of every thread (the main thread's stack is the greenlet that holds the
hub) to the process's real standard error, which is the container log. ``scripts/watchdog.sh`` sends that signal to the four workers before it
recreates the container and keeps the end of the log next to its own (``celery-before-restart.log`` in the update state directory). Celery uses
``SIGUSR1`` for its own Python level dump, which cannot run while the hub is held, and nothing else in the stack uses ``SIGUSR2``.
"""
import faulthandler
import logging
import signal
import sys

logger = logging.getLogger(__name__)

SIGNAL = getattr(signal, 'SIGUSR2', None)


def _gevent_worker():
    try:
        from gevent import monkey
        return monkey.is_module_patched('socket')
    except ImportError:
        return False


def install():
    """True when the handler was registered (a gevent worker on a system with ``SIGUSR2``). Never raises."""
    if SIGNAL is None or not _gevent_worker():
        return False
    stream = sys.__stderr__  # celery replaces sys.stderr with a logging proxy that has no file descriptor; the real one is the container log
    if stream is None:
        return False
    try:
        faulthandler.register(SIGNAL, file=stream, all_threads=True, chain=False)
    except (AttributeError, ValueError, RuntimeError, OSError):
        logger.warning('lane_stacks: could not register the stack dump on SIGUSR2', exc_info=True)
        return False
    return True
