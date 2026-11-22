"""A finished web_screenshot task keeps its pictures in the result for the 30 days a task is kept (1.4 GB of the live database). The picture is
in the screenshot store by then, so the sweep drops it from the task and keeps everything else."""
from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi.models import SentinelTask
from dashboard.models import Org, Project

PNG = 'iVBORw0KGgo' + 'A' * 400


class ScreenshotImageScrubTests(TestCase):
    def setUp(self):
        cache.delete('sentinel:scrub-stale-images')
        org = Org.objects.create(name='I', slug='img')
        self.project = Project.objects.create(name='I', slug='img-p', insert_date=timezone.now(), org=org)

    def task(self, kind='web_screenshot', age=timedelta(minutes=30), status='done', **result):
        body = result or {'pages': [{'id': '7', 'outcome': 'ok', 'image': PNG, 'width': 1280}, {'id': '8', 'outcome': 'timeout'}], 'sandbox': {'engaged': True}}
        return SentinelTask.objects.create(project=self.project, kind=kind, status=status, finished_at=timezone.now() - age, result=body)

    def test_an_old_finished_result_loses_its_pictures_and_keeps_the_rest(self):
        old = self.task()
        self.assertEqual(sentinel_broker.scrub_stale_images(), 1)
        old.refresh_from_db()
        self.assertNotIn(PNG, str(old.result))
        self.assertEqual(old.result['pages'], [{'id': '7', 'outcome': 'ok', 'width': 1280}, {'id': '8', 'outcome': 'timeout'}])
        self.assertEqual(old.result['sandbox'], {'engaged': True})
        self.assertTrue(old.result['images_scrubbed'])

    def test_a_new_result_other_kinds_and_scrubbed_ones_are_left_alone(self):
        fresh = self.task(age=timedelta(minutes=2))  # the step that files the pictures may still be running
        other = self.task(kind='nmap', pages=[{'image': PNG}])
        running = self.task(status='running')
        again = self.task(pages=[{'id': '1'}], images_scrubbed=True)
        self.assertEqual(sentinel_broker.scrub_stale_images(), 0)
        for row in (fresh, other, running):
            row.refresh_from_db()
            self.assertIn(PNG, str(row.result))
        again.refresh_from_db()
        self.assertEqual(again.result, {'pages': [{'id': '1'}], 'images_scrubbed': True})

    def test_the_sweep_runs_from_the_reaper_and_at_most_once_a_minute(self):
        first = self.task()
        sentinel_broker.reap_expired()
        first.refresh_from_db()
        self.assertTrue(first.result.get('images_scrubbed'))
        second = self.task()
        sentinel_broker.reap_expired()
        second.refresh_from_db()
        self.assertNotIn('images_scrubbed', second.result)  # inside the minute: left for the next sweep

    def test_the_select_reads_the_partial_index(self):
        from tests.test_hot_indexes import plan
        now = timezone.now()
        qs = (SentinelTask._base_manager.filter(kind='web_screenshot', status='done', finished_at__lt=now - sentinel_broker.STALE_IMAGES_AFTER)
              .exclude(result__has_key='images_scrubbed').order_by('id').values_list('id', flat=True)[:sentinel_broker.STALE_IMAGES_BATCH])
        self.assertIn('sentineltask_unscrub_img_idx', plan(qs))
