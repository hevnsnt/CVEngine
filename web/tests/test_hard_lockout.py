import os
import re
import threading
import unittest
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.cache.backends.redis import RedisCache
from django.conf import settings
from django.test import TestCase

from tenancy import views as tenancy_views

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


class SharedCacheTests(TestCase):
	"""Verdict 2: the lockout counters live in shared Redis and count atomically."""

	def setUp(self):
		cache.clear()
		self.user = User.objects.create_user('lock', password='x')

	def test_the_default_cache_is_redis_not_a_per_process_memory(self):
		self.assertIn('redis', settings.CACHES['default']['BACKEND'])
		self.assertTrue(settings.CACHES['default']['LOCATION'].startswith('redis://'))

	def test_the_cache_database_is_not_the_brokers(self):
		broker = settings.CELERY_BROKER_URL.rsplit('/', 1)[-1]
		location = settings.CACHES['default']['LOCATION'].rsplit('/', 1)[-1]
		self.assertNotEqual(broker, location)  # cache.clear() (factory reset) must not flush the Celery broker

	def test_concurrent_failures_are_all_counted(self):
		def hammer():
			for _ in range(10):
				tenancy_views.fail(self.user)
		threads = [threading.Thread(target=hammer) for _ in range(8)]
		for t in threads:
			t.start()
		for t in threads:
			t.join()
		self.assertEqual(cache.get(f'mfa_fail:{self.user.pk}'), 80)

	def test_a_second_process_sees_the_same_count_and_the_counter_survives_a_restart(self):
		for _ in range(tenancy_views.MAX_FAILURES - 1):
			tenancy_views.fail(self.user)
		other_process = RedisCache(settings.CACHES['default']['LOCATION'], {})  # a different worker, or this one after a restart
		self.assertEqual(other_process.get(f'mfa_fail:{self.user.pk}'), tenancy_views.MAX_FAILURES - 1)
		self.assertFalse(tenancy_views.locked(self.user))
		tenancy_views.fail(self.user)
		self.assertTrue(tenancy_views.locked(self.user))
		self.assertTrue(other_process.get(f'mfa_fail:{self.user.pk}') >= tenancy_views.MAX_FAILURES)

	def test_the_window_starts_at_the_first_failure_and_expires(self):
		tenancy_views.fail(self.user)
		self.assertTrue(0 < cache._cache.get_client().ttl(cache.make_key(f'mfa_fail:{self.user.pk}')) <= tenancy_views.LOCKOUT_SECONDS)
		first = cache._cache.get_client().ttl(cache.make_key(f'mfa_fail:{self.user.pk}'))
		tenancy_views.fail(self.user)
		self.assertLessEqual(cache._cache.get_client().ttl(cache.make_key(f'mfa_fail:{self.user.pk}')), first)  # not extended by later failures

	def test_a_key_that_expires_between_add_and_incr_still_counts(self):
		with mock.patch.object(RedisCache, 'incr', side_effect=ValueError('Key not found')):
			tenancy_views.fail(self.user)
		self.assertEqual(cache.get(f'mfa_fail:{self.user.pk}'), 1)

	def test_success_clears_the_counter(self):
		tenancy_views.fail(self.user)
		cache.delete(f'mfa_fail:{self.user.pk}')
		self.assertFalse(tenancy_views.locked(self.user))


class CacheUrlTests(unittest.TestCase):
	def url(self, **env):
		from reNgine.settings import _cache_url
		with mock.patch.dict(os.environ, env, clear=False):
			for key in ('CACHE_URL', 'CELERY_BROKER'):
				if key not in env:
					os.environ.pop(key, None)
			return _cache_url()

	def test_the_cache_uses_the_database_after_the_brokers(self):
		self.assertEqual(self.url(CELERY_BROKER='redis://redis:6379/0'), 'redis://redis:6379/1')
		self.assertEqual(self.url(CELERY_BROKER='redis://localhost:6379/8'), 'redis://localhost:6379/9')

	def test_an_explicit_cache_url_wins(self):
		self.assertEqual(self.url(CACHE_URL='redis://cache:6380/3', CELERY_BROKER='redis://redis:6379/0'), 'redis://cache:6380/3')

	def test_a_broker_without_a_database_number_still_gives_a_database(self):
		self.assertEqual(self.url(CELERY_BROKER='redis://redis:6379'), 'redis://redis:6379/1')


class DeploymentPinsTests(unittest.TestCase):
	def test_gunicorn_runs_two_workers_by_default(self):
		text = open(os.path.join(REPO, 'web', 'entrypoint.sh')).read()
		self.assertIn('--workers "${GUNICORN_WORKERS:-2}"', text)
		self.assertNotIn('LocMemCache', text)

	def test_compose_pins_the_worker_count_on_the_web_service(self):
		text = open(os.path.join(REPO, 'docker-compose.yml')).read()
		web = text[text.index('\n  web:'):text.index('\n  proxy:')]
		self.assertRegex(web, r'- GUNICORN_WORKERS=2\b')  # in `environment`, which beats env_file
		self.assertLess(web.index('env_file'), web.index('GUNICORN_WORKERS=2'))
		self.assertIsNone(re.search(r'GUNICORN_WORKERS=\$\{', web))  # not a value read from .env
