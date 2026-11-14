"""cveFeed.db_stats: ANALYZE when a table has no recent statistics."""
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import TestCase

from cveFeed import db_stats


class DbStatsTests(TestCase):
    def setUp(self):
        cache.delete(db_stats.CHECK_KEY)
        cache.delete(db_stats.RUN_KEY)

    def test_the_stale_table_query_runs_on_this_database(self):
        self.assertIsInstance(db_stats.stale_tables(), int)

    def test_it_analyzes_when_a_table_has_no_recent_statistics_and_not_otherwise(self):
        with mock.patch.object(db_stats, 'stale_tables', return_value=0), mock.patch.object(db_stats.connection, 'cursor') as cur:
            self.assertFalse(db_stats.analyze_if_needed())
            cur.assert_not_called()
        cache.delete(db_stats.CHECK_KEY)
        executed = []
        real = connection.cursor

        def spy():
            c = real()
            orig = c.execute
            c.execute = lambda sql, *a, **k: (executed.append(sql), orig(sql, *a, **k))[1]
            return c
        with mock.patch.object(db_stats, 'stale_tables', return_value=3), mock.patch.object(db_stats.connection, 'cursor', side_effect=spy):
            self.assertTrue(db_stats.analyze_if_needed())
        self.assertIn('ANALYZE', executed)
        self.assertTrue(cache.add(db_stats.RUN_KEY, 1, 5))  # the run lock is released
        cache.delete(db_stats.RUN_KEY)

    def test_it_checks_at_most_every_ten_minutes(self):
        with mock.patch.object(db_stats, 'stale_tables', return_value=0) as q:
            db_stats.analyze_if_needed()
            db_stats.analyze_if_needed()
        self.assertEqual(q.call_count, 1)

    def test_a_failure_is_swallowed(self):
        with mock.patch.object(db_stats, 'stale_tables', side_effect=RuntimeError('boom')):
            self.assertFalse(db_stats.analyze_if_needed())
