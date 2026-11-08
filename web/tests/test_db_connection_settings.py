"""The web container keeps its database connections for a minute (a new one costs 3.8 ms and a backend process; the Sentinels and the dashboards poll every few
seconds); the Celery workers do not (a gevent greenlet per task would each keep one)."""
import re
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parent.parent.parent


class ConnectionReuseTests(SimpleTestCase):
    def test_the_default_is_a_connection_per_request_so_workers_and_tests_are_unchanged(self):
        self.assertEqual(settings.DATABASES['default']['CONN_MAX_AGE'], 0)
        self.assertTrue(settings.DATABASES['default']['CONN_HEALTH_CHECKS'])

    def test_only_the_web_service_sets_it(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        services = re.split(r'\n  (?=[a-z-]+:\n)', compose)
        holders = [s.split(':', 1)[0] for s in services if 'CVENGINE_DB_CONN_MAX_AGE' in s]
        self.assertEqual(holders, ['web'])
        self.assertIn('CVENGINE_DB_CONN_MAX_AGE=${CVENGINE_DB_CONN_MAX_AGE:-60}', compose)

    def test_the_documentation_names_the_database_settings_for_a_small_host(self):
        doc = (ROOT / 'docs' / 'DEPLOYMENT.md').read_text()
        for word in ('POSTGRES_SHARED_BUFFERS', 'POSTGRES_EFFECTIVE_CACHE_SIZE', 'CVENGINE_DB_CONN_MAX_AGE', 'Small hosts'):
            self.assertIn(word, doc)
