"""cvengine/gevent_cache.py: in a gevent worker every greenlet uses one Django cache client (one Redis connection pool), where Django's own handler built a new
client, pool and Redis connection for each greenlet, that is for each task, and the classic lane ran out of file descriptors in a burst of tasks."""
from unittest import mock

import gevent
from django.core.cache import CacheHandler
from django.test import SimpleTestCase

from cvengine import gevent_cache

REDIS = {'default': {'BACKEND': 'django.core.cache.backends.redis.RedisCache', 'LOCATION': 'redis://127.0.0.1:1/9'}}


def clients_seen(handler, greenlets=20):
    """The cache client each of ``greenlets`` greenlets gets for 'default' (no connection is made: only the client object is built)."""
    jobs = [gevent.spawn(lambda: handler['default']) for _ in range(greenlets)]
    gevent.joinall(jobs, raise_error=True)
    return [job.value for job in jobs]


class GeventCacheTests(SimpleTestCase):
    def test_django_alone_builds_a_client_per_greenlet(self):
        # the defect: a new greenlet has a context of its own, and Django's handler keeps its clients in a context variable
        seen = clients_seen(CacheHandler({k: dict(v) for k, v in REDIS.items()}))
        self.assertEqual(len({id(c) for c in seen}), len(seen))

    def test_installed_every_greenlet_shares_one_client_with_a_blocking_pool(self):
        handler = CacheHandler({k: dict(v) for k, v in REDIS.items()})
        with mock.patch.object(gevent_cache, '_gevent_worker', return_value=True):
            self.assertTrue(gevent_cache.install(handler))
            self.assertTrue(gevent_cache.install(handler))  # idempotent
        seen = clients_seen(handler)
        self.assertEqual(len({id(c) for c in seen}), 1)
        options = handler.settings['default']['OPTIONS']
        self.assertEqual((options['pool_class'], options['max_connections'], options['timeout']),
                         ('redis.BlockingConnectionPool', gevent_cache.POOL_MAX, gevent_cache.POOL_WAIT_SECONDS))
        import redis
        client = seen[0]._cache
        pool = client._get_connection_pool(write=True)
        self.assertIsInstance(pool, redis.BlockingConnectionPool)
        self.assertEqual(pool.max_connections, gevent_cache.POOL_MAX)
        self.assertIs(client._get_connection_pool(write=True), pool)  # one pool for the process

    def test_options_set_in_the_settings_are_kept(self):
        conf = {'default': {**REDIS['default'], 'OPTIONS': {'max_connections': 7}}}
        handler = CacheHandler(conf)
        with mock.patch.object(gevent_cache, '_gevent_worker', return_value=True):
            gevent_cache.install(handler)
        self.assertEqual(handler.settings['default']['OPTIONS']['max_connections'], 7)

    def test_a_cache_that_is_not_redis_is_shared_but_not_given_redis_options(self):
        handler = CacheHandler({'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
        with mock.patch.object(gevent_cache, '_gevent_worker', return_value=True):
            gevent_cache.install(handler)
        self.assertNotIn('OPTIONS', handler.settings['default'])
        self.assertEqual(len({id(c) for c in clients_seen(handler)}), 1)

    def test_outside_a_gevent_worker_nothing_changes(self):
        handler = CacheHandler({k: dict(v) for k, v in REDIS.items()})
        before = handler._connections
        with mock.patch.object(gevent_cache, '_gevent_worker', return_value=False):
            self.assertFalse(gevent_cache.install(handler))
        self.assertIs(handler._connections, before)
        self.assertNotIn('OPTIONS', handler.settings['default'])

    def test_the_worker_installs_it(self):
        src = (gevent_cache.__file__.rsplit('/', 1)[0] + '/celery.py')
        with open(src) as fh:
            self.assertIn('gevent_cache.install()', fh.read())
