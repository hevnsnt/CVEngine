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
after the visibility timeout, as it does for any message whose ack never reached it. Rejections without requeue go the same way."""
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


def install():
    """Patch kombu's Redis QoS once (idempotent). Returns True when the patch is in place."""
    try:
        from kombu.transport import redis as kombu_redis
        from kombu.transport import virtual
    except ImportError:  # pragma: no cover - kombu without its Redis transport (redis-py missing): nothing to patch
        return False
    qos_cls = kombu_redis.QoS
    if getattr(qos_cls, _MARK, False):
        return True
    if not callable(getattr(qos_cls, '_remove_from_indices', None)):
        logger.warning('kombu.transport.redis.QoS has no _remove_from_indices: acknowledgements are left as kombu makes them')
        return False
    original_reject = qos_cls.reject

    def ack(self, delivery_tag):
        try:
            _remove(self, delivery_tag)
        finally:
            virtual.QoS.ack(self, delivery_tag)  # frees the delivery (and with it a prefetch slot) even when the broker was not told

    def reject(self, delivery_tag, requeue=False):
        if requeue:
            return original_reject(self, delivery_tag, requeue=True)
        try:
            _remove(self, delivery_tag)
        finally:
            virtual.QoS.ack(self, delivery_tag)
        return None

    qos_cls.ack = ack
    qos_cls.reject = reject
    setattr(qos_cls, _MARK, True)
    return True
