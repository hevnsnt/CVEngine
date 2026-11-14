"""The secret values a Sentinel reports live in the task row only for the step that files them. Filing that raises, or a worker that died before it
scrubbed, must not leave a value in the database until the retention sweep."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi.models import SentinelTask
from cveFeed import secrets_scan
from dashboard.models import Org, Project

VALUE = 'zq-example-secret-value-0123456789ab'


class Result(dict):
    task_id = None


class ScrubTests(TestCase):
    def setUp(self):
        cache.delete('sentinel:scrub-stale-values')
        org = Org.objects.create(name='S', slug='scrub')
        self.project = Project.objects.create(name='S', slug='scrub-p', insert_date=timezone.now(), org=org)

    def task(self, kind='secrets_scan', age=timedelta(minutes=30), **extra):
        result = extra.pop('result', {'outcome': 'done', 'findings': [{'url': 'https://a.example.com/x.js', 'secret': VALUE, 'context': VALUE + ' tail'}]})
        return SentinelTask.objects.create(project=self.project, kind=kind, status='done', finished_at=timezone.now() - age, result=result, **extra)

    def test_filing_that_raises_still_scrubs_the_values(self):
        task = self.task(age=timedelta(0))
        result = Result(task.result)
        result.task_id = task.pk
        with mock.patch.object(secrets_scan, '_persist', side_effect=RuntimeError('the inventory is down')):
            with self.assertRaises(RuntimeError):
                secrets_scan.persist(self.project, None, 1, {}, result)
        task.refresh_from_db()
        self.assertNotIn(VALUE, str(task.result))
        self.assertTrue(task.result['values_scrubbed'])

    def test_a_result_nobody_scrubbed_is_scrubbed_by_the_reaper_once_it_is_old_enough(self):
        old = self.task()
        fresh = self.task(age=timedelta(minutes=2))
        route = self.task('route_probe', result={'outcome': 'done', 'routes': [{'url': 'https://a.example.com/', 'credentials': [{'type': 'password', 'value': VALUE}]}]})
        done_already = self.task(result={'outcome': 'done', 'findings': [], 'values_scrubbed': True})
        self.assertEqual(sentinel_broker.scrub_stale_values(), 2)
        for row in (old, route):
            row.refresh_from_db()
            self.assertNotIn(VALUE, str(row.result))
            self.assertTrue(row.result['values_scrubbed'])
        fresh.refresh_from_db()
        self.assertIn(VALUE, str(fresh.result))  # the step that files it may still be running
        done_already.refresh_from_db()
        self.assertEqual(done_already.result, {'outcome': 'done', 'findings': [], 'values_scrubbed': True})

    def test_the_sweep_runs_from_the_reaper_and_at_most_once_a_minute(self):
        old = self.task()
        sentinel_broker.reap_expired()
        old.refresh_from_db()
        self.assertNotIn(VALUE, str(old.result))
        second = self.task()
        sentinel_broker.reap_expired()
        second.refresh_from_db()
        self.assertIn(VALUE, str(second.result))  # inside the minute: left for the next sweep
