"""One notification per auto-fire run for the template tests it queued.

Each CVE's template test runs as its own Celery task, so each would announce its own hits: a bad day (hundreds of hot CVEs) would
be hundreds of messages. A run opens a batch; every test it queues joins it and, when it finishes, leaves its hits there; the last
one out (the run itself holds one place until it has queued everything, so the count cannot reach zero early) sends the single
message. State lives in the shared cache with an expiry, so a worker that dies mid-test leaves nothing behind and, at worst, the
message for that run is not sent. A test started outside a run (an API call) is not in a batch and announces itself.
"""
import logging
import uuid

from django.core.cache import cache

logger = logging.getLogger(__name__)

TTL = 6 * 3600
MAX_HITS = 5000  # (CVE, host) pairs kept per run; the message names a handful and counts the rest


def _key(batch, name):
    return f'cvengine:hits:{batch}:{name}'


def start():
    """Open a batch. The caller holds the first place and must call ``leave`` once it has queued everything."""
    batch = uuid.uuid4().hex
    cache.set(_key(batch, 'pending'), 1, TTL)
    cache.set(_key(batch, 'n'), 0, TTL)
    return batch


def join(batch):
    """A test is queued into the batch."""
    cache.incr(_key(batch, 'pending'))


def record(batch, hits):
    """Leave a finished test's (CVE id, host) pairs in the batch."""
    if not hits:
        return
    index = cache.incr(_key(batch, 'n'))
    cache.set(_key(batch, f'hits:{index}'), list(hits)[:MAX_HITS], TTL)


def leave(batch, send=None):
    """A test (or the run itself) is finished. The last one to leave sends the one message with every recorded hit. Returns True
    when this call sent it."""
    try:
        remaining = cache.decr(_key(batch, 'pending'))
    except ValueError:  # expired: the run was long gone
        return False
    if remaining > 0:
        return False
    from cveFeed import notify
    send = send or notify.template_hits
    hits = []
    try:
        count = int(cache.get(_key(batch, 'n')) or 0)
        for index in range(1, count + 1):
            hits += cache.get(_key(batch, f'hits:{index}')) or []
        cache.delete_many([_key(batch, 'pending'), _key(batch, 'n'), *(_key(batch, f'hits:{i}') for i in range(1, count + 1))])
        return bool(hits and send(hits[:MAX_HITS]))
    except Exception as exc:  # noqa: BLE001 - a notification never fails the run
        logger.warning('batched template hit notification failed (%s)', type(exc).__name__)
        return False
