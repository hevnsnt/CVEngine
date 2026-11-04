"""An acknowledgement that hits a dropped broker connection must not cost the worker one of its task slots.

With the Redis broker, kombu acknowledges a message in two steps (``kombu.transport.redis.QoS.ack``): it removes the message from the
broker's unacked index, then frees the delivery in the channel's own bookkeeping, whose count of unacknowledged deliveries is what the
prefetch limit is checked against. When the first step raises a connection error (the broker connection dropped while the ack was being
sent: a Redis restart or failover, a network blip, a client kill), the second never runs and the error is only logged ("Couldn't ack").
The delivery then counts against the prefetch for as long as the channel lives. For acks_late tasks (``run_bbot_discovery``,
``run_internal_scan``) the prefetch is what bounds how many run at once, so a worker with a ceiling of 4 runs 3 at a time from then on, 2
after a second such drop, and none after as many drops as its ceiling, until it is restarted. kombu 5.7 keeps the channel across a dropped
BRPOP connection (it reconnects in place), where earlier versions restarted the consumer with a new channel and so hid the leak.
``tests/test_gevent_worker_e2e.py`` shows it end to end: its broker reconnect test failed in CI when the cut landed on an ack.

``install`` (called by ``reNgine/celery.py``) makes the ack try the removal once more on a connection error (the connection pool hands out a
fresh connection for the dropped one; removing an index entry twice is harmless) and free the delivery whatever happens. When the removal
fails twice the error is still raised, so kombu logs it as before, and the message stays in the unacked index: the broker hands it out again
after the visibility timeout, as it does for any message whose ack never reached it. Rejections without requeue go the same way; a rejection
with requeue (``reject(requeue=True)``) is left to kombu, which puts the message back in its queue and frees the delivery itself.

``install`` never raises: when kombu's Redis transport, its ``QoS`` or anything the patch relies on is missing (another kombu version), it
logs a warning naming the kombu version and leaves acknowledgements as kombu makes them."""
import logging

logger = logging.getLogger(__name__)

_MARK = '_cvengine_ack_frees_slot'


def _remove(qos, delivery_tag):
    """Remove ``delivery_tag`` from the broker's unacked index, trying once more after a connection error."""
    errors = tuple(getattr(qos.channel, 'connection_errors', ()) or ())
    try:
        qos._remove_from_indices(delivery_tag).execute()
    except errors:
        logger.warning('The broker connection dropped while acknowledging %s; trying again on a new connection.', delivery_tag)
        qos._remove_from_indices(delivery_tag).execute()


def _kombu_version():
    try:
        import kombu
        return getattr(kombu, '__version__', 'unknown')
    except Exception:  # noqa: BLE001
        return 'not importable'


def install():
    """Patch kombu's Redis QoS once (idempotent). Returns True when the patch is in place, False (with a warning) when it cannot be. Never
    raises."""
    try:
        return _install()
    except Exception:  # a worker must start whatever kombu looks like
        logger.warning('Could not guard kombu %s acknowledgements; they are left as kombu makes them.', _kombu_version(), exc_info=True)
        return False


def _install():
    try:
        from kombu.transport import redis as kombu_redis
        from kombu.transport import virtual
    except ImportError:
        logger.warning('kombu %s has no Redis transport here; acknowledgements are left as kombu makes them.', _kombu_version())
        return False
    qos_cls = getattr(kombu_redis, 'QoS', None)
    base_ack = getattr(getattr(virtual, 'QoS', None), 'ack', None)
    missing = [name for name, ok in (
        ('kombu.transport.redis.QoS', isinstance(qos_cls, type)),
        ('kombu.transport.virtual.QoS.ack', callable(base_ack)),
        ('QoS._remove_from_indices', callable(getattr(qos_cls, '_remove_from_indices', None))),
        ('QoS.reject', callable(getattr(qos_cls, 'reject', None))),
        ('kombu.transport.virtual.QoS._delivered', hasattr(getattr(virtual, 'QoS', None), '_delivered')),
    ) if not ok]
    if missing:
        logger.warning('kombu %s lacks %s: acknowledgements are left as kombu makes them.', _kombu_version(), ', '.join(missing))
        return False
    if getattr(qos_cls, _MARK, False):
        return True
    original_reject = qos_cls.reject

    def ack(self, delivery_tag):
        try:
            _remove(self, delivery_tag)
        finally:
            base_ack(self, delivery_tag)  # frees the delivery (and with it a prefetch slot) even when the broker was not told

    def reject(self, delivery_tag, requeue=False):
        if requeue:  # left to kombu: it restores the message to its queue and frees the delivery
            return original_reject(self, delivery_tag, requeue=True)
        try:
            _remove(self, delivery_tag)
        finally:
            base_ack(self, delivery_tag)
        return None

    qos_cls.ack = ack
    qos_cls.reject = reject
    setattr(qos_cls, _MARK, True)
    logger.info('Guarded kombu %s Redis acknowledgements: a dropped connection no longer costs a prefetch slot.', _kombu_version())
    return True
