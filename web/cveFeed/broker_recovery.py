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


# ---- which tasks still exist -------------------------------------------------------------------------------------------------
# A row that says "queued" is only waiting if a Celery task for it exists somewhere: in a queue, held unacknowledged by a worker, or
# reserved, scheduled or running inside a worker. A worker that acknowledges on receipt and is killed takes its reserved tasks with it
# and leaves nothing in the broker, so the rows they belonged to are orphans.
import json
import time

MAX_QUEUE_SCAN = 20000  # a queue longer than this is not read: "unknown" is safer than a slow or partial answer
PRIORITY_SUFFIXES = ('', '\x06\x163', '\x06\x166', '\x06\x169')  # kombu's Redis priority steps share one queue name
_live = {'at': 0.0, 'ids': None}


def _task_ids(raw):
    """The task id of a broker message: the ``id`` header of the message itself, or of each message in a list (the unacked hash keeps
    ``[message, exchange, routing key]``). The ids of a parent or root task a message mentions are not its own and are left out."""
    try:
        found = json.loads(raw)
    except ValueError:
        return []
    out = []
    for item in found if isinstance(found, list) else [found]:
        headers = item.get('headers') if isinstance(item, dict) else None
        if isinstance(headers, dict) and headers.get('id'):
            out.append(str(headers['id']))
    return out


def live_task_ids(app=None, inspect_timeout=3):
    """The set of Celery task ids that still exist, or None when that cannot be told (no Redis broker, a long queue, no worker
    answered). None means the caller must not conclude that anything is orphaned. Never raises."""
    try:
        from reNgine.celery import app as default_app
        app = app or default_app
        ids = set()
        with app.connection_for_read() as connection:
            channel = connection.default_channel
            client = getattr(channel, 'client', None)
            if client is None or getattr(channel, 'unacked_key', None) is None:
                return None
            queues = list(app.amqp.queues.keys())
            for name in [q + suffix for q in queues for suffix in PRIORITY_SUFFIXES]:
                size = client.llen(name)
                if size > MAX_QUEUE_SCAN:
                    return None
                if size:
                    for raw in client.lrange(name, 0, -1):
                        ids.update(_task_ids(raw))
            for raw in client.hvals(channel.unacked_key):
                ids.update(_task_ids(raw))
        inspector = app.control.inspect(timeout=inspect_timeout)
        answered = False
        for call in (inspector.reserved, inspector.active, inspector.scheduled):
            found = call()
            if found is None:
                continue
            answered = True
            for tasks in found.values():
                for task in tasks:
                    task = task.get('request', task)  # scheduled() wraps the task request
                    if task.get('id'):
                        ids.add(task['id'])
        return ids if answered else None
    except Exception:  # noqa: BLE001
        logger.exception('could not list the Celery tasks that still exist')
        return None


def cached_live_task_ids(max_age=60):
    """``live_task_ids`` at most once per ``max_age`` seconds in this process: callers ask on request paths."""
    now = time.monotonic()
    if now - _live['at'] > max_age:
        _live.update(at=now, ids=live_task_ids())
    return _live['ids']
