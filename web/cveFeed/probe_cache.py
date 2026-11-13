"""A slow probe answered from the shared cache, refreshed behind the caller's back.

Asking Celery's workers what they run (``app.control.inspect``) waits the whole timeout whenever the number of workers is not known in advance: 5 seconds
for every System status or worker panel request, with the workers up or not, and the more the workers are busy (a small host at full CPU) the more often
a reply misses the window. A page that polls must never wait for that. ``cached_probe`` serves the last answer while it is younger than ``fresh`` seconds,
serves an older one at once and refreshes it in one background thread (a cache lock keeps it to one), and only the very first call, with nothing held,
computes in the request.
"""
import logging
import threading
import time

logger = logging.getLogger(__name__)




def cached_probe(key, compute, fresh=30, keep=1800, first=None):
    """``(value, taken_at)``: ``compute()``'s last answer. ``fresh``: seconds an answer is served without asking again; ``keep``: how long an older one may still
    be served (and refreshed in the background). A ``compute`` that raises is never cached; in the background the old answer stays. ``first``: a quicker
    ``compute`` for the one call that has nothing held and must answer in the request."""
    from django.core.cache import cache
    now = time.time()
    try:
        held = cache.get(key)
    except Exception:  # noqa: BLE001 - an unreadable cache is no cache: ask
        held = None
    if isinstance(held, dict) and 'at' in held:
        if now - held['at'] >= fresh:
            _refresh_behind(key, compute, keep)
        return held['value'], held['at']
    value = (first or compute)()
    try:
        cache.set(key, {'at': now, 'value': value}, keep)
    except Exception:  # noqa: BLE001
        logger.info('could not keep the answer of probe %s', key)
    return value, now


def _refresh_behind(key, compute, keep):
    """Ask again in a thread, once at a time (the cache lock lasts until the answer is in or 60 seconds)."""
    from django.core.cache import cache
    try:
        if not cache.add(f'{key}:refreshing', 1, 60):
            return
    except Exception:  # noqa: BLE001
        return

    def run():
        try:
            cache.set(key, {'at': time.time(), 'value': compute()}, keep)
        except Exception:  # noqa: BLE001 - the answer held stays, and the next request tries again
            logger.info('could not refresh probe %s', key, exc_info=True)
        finally:
            try:
                cache.delete(f'{key}:refreshing')
            except Exception:  # noqa: BLE001
                pass
    threading.Thread(target=run, name=f'probe-{key}', daemon=True).start()
