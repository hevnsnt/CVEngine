"""Each worker lane reports its memory and the tasks it held it after (reNgine/lane_memory.py)."""
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase

from reNgine import lane_memory as lm


class LaneMemoryTests(SimpleTestCase):
    def setUp(self):
        lm._state.update(lane=None, started={}, tasks={}, last_write=0.0, peak_mb=0.0)
        for lane in lm.LANES:
            cache.delete(lm.CACHE_PREFIX + lane)

    def test_the_lane_comes_from_the_workers_name(self):
        self.assertEqual(lm.lane_name(['celery', 'worker', '-n', 'cve_feed_worker']), 'cve_feed')
        self.assertEqual(lm.lane_name(['celery', '--hostname=classic_worker@h']), 'classic')
        self.assertEqual(lm.lane_name(['manage.py', 'test']), '')

    def test_a_finished_task_is_recorded_with_its_growth_and_the_report_ranks_it(self):
        sizes = iter([100.0, 100.0, 400.0, 400.0])
        with mock.patch.object(lm, 'rss_mb', side_effect=lambda: next(sizes)), mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.before('a')                 # 100
            lm.before('b')                 # 100
            lm.after('a', 'cveFeed.tasks.big', now=1000.0)   # 400: grew 300
            lm.after('b', 'cveFeed.tasks.small', now=1001.0)  # 400: grew 300 as well, but within the write interval
        rows = lm.report(now=1030.0)
        self.assertEqual([r['lane'] for r in rows], ['cve_feed'])
        self.assertEqual(rows[0]['rss_mb'], 400.0)
        self.assertEqual(rows[0]['by_size'][0], {'task': 'cveFeed.tasks.big', 'runs': 1, 'max_rss_mb': 400.0})
        self.assertEqual(rows[0]['by_growth'][0]['max_growth_mb'], 300.0)
        self.assertEqual(rows[0]['age_seconds'], 30)

    def test_a_cache_that_fails_never_fails_the_task(self):
        with mock.patch.object(lm, 'rss_mb', return_value=50.0), mock.patch.object(lm, 'lane_name', return_value='classic'), \
                mock.patch('django.core.cache.cache.set', side_effect=OSError('redis down')):
            lm.before('x')
            lm.after('x', 't', now=5000.0)  # must not raise

    def test_the_system_status_carries_the_lanes(self):
        from agentapi import system_status
        with mock.patch('reNgine.resources.cluster_snapshot', return_value={'store': 'redis', 'containers': []}), \
                mock.patch('reNgine.lane_memory.report', return_value=[{'lane': 'classic', 'rss_mb': 1.0}]):
            self.assertEqual(system_status._memory()['lanes'], [{'lane': 'classic', 'rss_mb': 1.0}])
