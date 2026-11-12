"""How long the oldest message of a Celery queue has waited (the maintainer's signals, ``agentapi.maintainer_signals``).

Celery messages carry no send time, so a queue's length says nothing about starvation: 18 scans sat 16 hours behind 360 host assessments in
``discovery_queue`` and nothing could tell. Every message published by this version carries ``cv_sent`` (the time it was published) in its headers,
added by a ``before_task_publish`` handler (``install``). The oldest message of a Redis list is at its tail, so one ``LINDEX -1`` per queue step reads
it, in one pipeline, and only for a queue that has something waiting. A message published before this version has no stamp: its age is unknown, and
is reported as unknown, never as zero.
"""
import json
import time

HEADER = 'cv_sent'
MAX_MESSAGE_BYTES = 1 << 20  # a message this big is not parsed (LINDEX returns the whole message): its age is unknown


def install():
    from celery.signals import before_task_publish

    def stamp(headers=None, **kwargs):
        try:
            if isinstance(headers, dict):
                headers.setdefault(HEADER, round(time.time(), 3))
        except Exception:  # noqa: BLE001 - a measurement must never stop a task from being sent
            pass

    before_task_publish.connect(stamp, weak=False, dispatch_uid='queue-age-stamp')


def sent_at(raw):
    """The publish time stamped on one raw message, or None (no stamp, not JSON, too big)."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', 'replace')
    if not isinstance(raw, str) or len(raw) > MAX_MESSAGE_BYTES:
        return None
    try:
        headers = (json.loads(raw) or {}).get('headers') or {}
        value = headers.get(HEADER)
    except (ValueError, AttributeError, TypeError):
        return None
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def oldest(client, depths, suffixes, now=None):
    """``{queue: {'age_seconds': int or None, 'known': bool}}`` for every queue in ``depths`` that has messages waiting (a queue with none is left out:
    nothing waits, so nothing has an age). ``known`` is False when the oldest message has no stamp. Raises when Redis cannot be asked."""
    now = time.time() if now is None else now
    queues = [q for q, n in depths.items() if n]
    if not queues:
        return {}
    pipe = client.pipeline(transaction=False)
    for queue in queues:
        for suffix in suffixes:
            pipe.lindex(queue + suffix, -1)
    raw = pipe.execute()
    out = {}
    for i, queue in enumerate(queues):
        tails = raw[i * len(suffixes):(i + 1) * len(suffixes)]
        present = [t for t in tails if t is not None]
        stamps = [sent_at(t) for t in present]
        if not present or any(s is None for s in stamps):  # an unstamped tail may be the oldest: the age cannot be claimed
            out[queue] = {'age_seconds': None, 'known': False}
        else:
            out[queue] = {'age_seconds': int(max(0, now - min(stamps))), 'known': True}
    return out
