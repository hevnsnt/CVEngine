"""Remote control that survives a dropped broker connection on the gevent workers.

Every CVEngine worker runs a gevent pool (``celery-entrypoint.sh``), and with a green pool celery answers remote control (ping, inspect,
``autoscale``, revoke) from its own greenlet, ``celery.worker.pidbox.gPidbox.loop``. That loop catches only ``socket.timeout`` around
``connection.drain_events``: when the broker connection drops (a Redis restart or failover, a network blip, a client kill), the
``ConnectionError`` ends the greenlet ("... failed with ConnectionError" in the worker log). The worker keeps consuming tasks, because the
consumer reconnects on its own, but answers no remote control until it is restarted. With kombu 5.7 that is the usual outcome of a blip: it
reconnects the task connection in place, so the consumer is not restarted, and the restart was what used to start a new loop. Then:

* ``scan_concurrency.apply_discovery`` and the auto-tune resize (``autotune._resize_discovery_directly``) are lost: no worker answers;
* the admin worker panel's ``inspect()`` and ``autotune_signals`` see no worker;
* a revoke (``agentapi/services.py``) never reaches the worker running the task;
* ``broker_recovery.live_tasks`` hears from only some workers, so a running task that is not acks_late can look orphaned to the reaper.

``install`` (called by ``reNgine/celery.py``) replaces the loop with one that, on any error, logs it, waits (1 s, doubling to 30 s while the
connection keeps failing soon after it is made; it never spins), and connects again with a new channel and broadcast consumer, until the
consumer stops it. The prefork pool (``Pidbox``) is not touched: it answers from the consumer's own connection. ``install`` is idempotent and
never raises; when celery's gevent pidbox does not look as expected it logs a warning and leaves celery's loop in place.
``tests/test_gevent_worker_e2e.py`` cuts a real worker's broker connections and checks that ping and ``autoscale`` are answered again."""
import logging
import threading
import time

logger = logging.getLogger(__name__)

_MARK = '_cvengine_reconnecting_loop'
FIRST_DELAY = 1.0
MAX_DELAY = 30.0
STABLE_AFTER = 60.0  # a connection that stayed up this long starts the next wait from FIRST_DELAY again


def _celery_version():
    try:
        import celery
        return getattr(celery, '__version__', 'unknown')
    except Exception:  # noqa: BLE001
        return 'not importable'


def next_delay(previous, connected_for):
    """How long to wait before the next connection attempt: from FIRST_DELAY again after a connection that stayed up STABLE_AFTER seconds,
    otherwise double the previous wait, at most MAX_DELAY."""
    if not previous or connected_for >= STABLE_AFTER:
        return FIRST_DELAY
    return min(previous * 2, MAX_DELAY)


def loop(self, c):
    """``gPidbox.loop`` that reconnects instead of ending (see the module docstring). Same shutdown contract as celery's: ``on_stop`` sets
    ``_node_shutdown`` and waits for ``_node_stopped``."""
    resets = [self._resets]
    shutdown = self._node_shutdown = threading.Event()
    stopped = self._node_stopped = threading.Event()
    delay = 0.0
    try:
        while not shutdown.is_set() and c.connection:
            connected_at = time.monotonic()
            try:
                with c.connection_for_read() as connection:
                    logger.info('pidbox: Connected to %s.', connection.as_uri())
                    connected_at = time.monotonic()
                    self._do_reset(c, connection)
                    while not shutdown.is_set() and c.connection:
                        if resets[0] < self._resets:
                            resets[0] += 1
                            self._do_reset(c, connection)
                        try:
                            connection.drain_events(timeout=1.0)
                        except TimeoutError:  # socket.timeout: nothing arrived within the second
                            pass
            except Exception as exc:  # whatever ended it, remote control must come back
                if shutdown.is_set() or not c.connection:
                    break
                delay = next_delay(delay, time.monotonic() - connected_at)
                errors = tuple(getattr(c, 'connection_errors', ()) or ()) + tuple(getattr(c, 'channel_errors', ()) or ())
                if isinstance(exc, errors + (OSError,)):
                    logger.warning('pidbox: lost the broker connection (%r); reconnecting in %.0f s.', exc, delay)
                else:
                    logger.exception('pidbox: remote control stopped; restarting it in %.0f s.', delay)
                shutdown.wait(delay)
    finally:
        stopped.set()


def install():
    """Replace ``celery.worker.pidbox.gPidbox.loop`` once (idempotent). Returns True when the loop is in place. Never raises."""
    try:
        from celery.worker import pidbox
        cls = getattr(pidbox, 'gPidbox', None)
        missing = [name for name in ('loop', '_do_reset', 'on_stop') if not callable(getattr(cls, name, None))]
        if cls is None or missing:
            logger.warning('celery %s has no gevent pidbox loop to guard (%s): remote control is left as celery runs it.', _celery_version(),
                           ', '.join(missing) or 'no gPidbox')
            return False
        if getattr(cls, _MARK, False):
            return True
        cls.loop = loop
        setattr(cls, _MARK, True)
        logger.info('Guarded celery %s gevent remote control: it reconnects after a dropped broker connection.', _celery_version())
        return True
    except Exception:  # a worker must start whatever celery looks like
        logger.warning('Could not guard celery %s gevent remote control.', _celery_version(), exc_info=True)
        return False
