"""Test runner that lets ``manage.py test --parallel`` run safely against one Redis server.

Django clones the PostgreSQL test database for every worker, but the tests also use Redis (the Django cache, the scan memory gate,
claims and locks), and ``cache.clear()`` or a held lock in one worker would break a test running in another. Each worker therefore
gets two Redis databases of its own (broker and cache: 2n and 2n+1), flushed when it starts, so Redis has room for 7 workers.
Everything else about a normal (one process) run is unchanged."""
import os
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.test.runner import DiscoverRunner, ParallelTestSuite, _init_worker

MAX_WORKERS = 7  # a default Redis has 16 databases: worker n uses 2n and 2n + 1 (0 and 1 stay with the parent)


def _with_database(url, number):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f'/{number}', '', ''))


def isolate_redis(worker_id):
    """Point this process at Redis databases that no other worker uses. A URL that is not Redis is left alone."""
    from django.test.utils import override_settings

    base = os.environ.get('CELERY_BROKER') or getattr(settings, 'CELERY_BROKER_URL', '')
    if not base.startswith(('redis://', 'rediss://')):
        return
    if not 1 <= worker_id <= MAX_WORKERS:
        raise RuntimeError(f'worker {worker_id}: --parallel is limited to {MAX_WORKERS} workers by the Redis databases available')
    broker, cache = _with_database(base, 2 * worker_id), _with_database(base, 2 * worker_id + 1)
    os.environ['CELERY_BROKER'] = os.environ['CELERY_BROKER_URL'] = broker
    caches = {**settings.CACHES, 'default': {**settings.CACHES['default'], 'LOCATION': cache}}
    # enable() without a matching disable(): this process keeps these settings until it exits, and the setting_changed signal
    # makes Django drop the cache connections it already made
    override_settings(CELERY_BROKER_URL=broker, CACHES=caches).enable()
    from reNgine import resources
    resources.reset_store()
    import redis
    for url in (broker, cache):
        redis.Redis.from_url(url).flushdb()


def _init_isolated_worker(counter, *args, **kwargs):
    from django.test import runner
    _init_worker(counter, *args, **kwargs)
    isolate_redis(runner._worker_id)


class IsolatedRedisParallelSuite(ParallelTestSuite):
    init_worker = _init_isolated_worker


class IsolatedRedisRunner(DiscoverRunner):
    parallel_test_suite = IsolatedRedisParallelSuite

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.parallel > MAX_WORKERS:
            print(f'--parallel {self.parallel} lowered to {MAX_WORKERS}: each worker needs two of Redis\'s 16 databases.')
            self.parallel = MAX_WORKERS
