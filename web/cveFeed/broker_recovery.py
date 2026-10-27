"""Messages a killed worker took from the broker and never acknowledged.

With the Redis broker a worker that has taken a message keeps it in the ``unacked`` hash until it acknowledges it. A worker takes more
messages than it can start at once (its prefetch), so when an update recreates the stack the containers are killed holding queued work
that never started: host assessments, scans, validations. Those messages are not returned to their queue until the broker's visibility
timeout has passed (``CELERY_VISIBILITY_TIMEOUT``, 12 hours here, because a task that waits for its ETA must not be redelivered). Until
then their rows stay "queued", count toward the host-assessment capacity limit ("host assessment queue is at capacity") and nothing runs
them.

``requeue_unacked`` is run by the worker container before its workers start: nothing of this stack consumes at that moment, so every
message still marked unacknowledged belongs to a worker that no longer exists, and each goes back to the front of its own queue. A task
that had already started was acknowledged when it started and is not touched. A message delivered twice is harmless for the work that
is queued by row (an assessment's status moves from queued to running once)."""
import logging

logger = logging.getLogger(__name__)


def requeue_unacked(app=None):
    """Return every unacknowledged message to its queue. Returns how many. Never raises: a broker that cannot be reached is left alone."""
    try:
        from reNgine.celery import app as default_app
        with (app or default_app).connection_for_write() as connection:
            channel = connection.default_channel
            client = getattr(channel, 'client', None)
            index = getattr(channel, 'unacked_index_key', None)
            if client is None or index is None:  # not the Redis transport: nothing to recover this way
                return 0
            tags = [t.decode() if isinstance(t, bytes) else str(t) for t in client.zrange(index, 0, -1)]
            for tag in tags:
                channel.qos.restore_by_tag(tag, leftmost=True)
            return len(tags)
    except Exception:  # noqa: BLE001
        logger.exception('could not return the unacknowledged broker messages to their queues')
        return 0
