"""Two hot statements get the index they need (shapes 5 and 6 of the production slow-query list).

* ``scrub_stale_values`` (once a minute, from every broker entry point): finished secrets and route-probe tasks older than ten minutes whose result is not
  scrubbed yet, ``ORDER BY id LIMIT 200``. agentapi_sentineltask holds 30 days of work (about a million rows); the few unscrubbed rows are rare, so
  walking the primary key in id order to find 200 of them read and detoasted the ``result`` of every finished task: up to 8.7 s, every minute. The partial
  index holds only the unscrubbed rows (a row leaves it when it is scrubbed).
* ``detection_author.progress`` (get_system_status, the Settings AI page): ``GROUP BY source`` over the CVE detections that have checks, filtering on
  the ``strategy`` JSON of all of the 38,000 rows (up to 6.4 s). The partial index holds the rows that have checks, with their source.

The tables here are tiny, so each plan is read with sequential and bitmap scans switched off: with no index the only plan left is the table scan.
"""
from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi.models import SentinelTask
from cveFeed import detection_author
from cveFeed.models import CVEDetection, CVEEntry
from dashboard.models import Org, Project


def plan(queryset):
    with connection.cursor() as cursor:
        cursor.execute('SET LOCAL enable_seqscan = off')
        cursor.execute('SET LOCAL enable_bitmapscan = off')  # a tiny table with stale statistics may be read by a bitmap scan of another index; the question is which index serves the query
        return queryset.explain()


class ScrubSelectUsesItsIndexTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()  # the scrub runs at most once a minute: a lock left by another test would make it return at once

    @classmethod
    def setUpTestData(cls):
        cls.project = Project.objects.create(name='X', slug='hi-proj', insert_date=timezone.now(), org=Org.objects.create(name='X', slug='hi-org'))

    def candidates(self):
        now = timezone.now()
        return (SentinelTask._base_manager.filter(kind__in=('secrets_scan', 'route_probe'), status='done', finished_at__lt=now - sentinel_broker.STALE_VALUES_AFTER)
                .exclude(result__has_key='values_scrubbed').order_by('id').values_list('id', flat=True)[:sentinel_broker.STALE_VALUES_BATCH])

    def test_the_select_reads_an_index_that_holds_only_unscrubbed_results(self):
        self.assertIn('sentineltask_unscrubbed_idx', plan(self.candidates()))

    def test_the_select_is_the_one_the_broker_runs(self):
        """The query above is copied from ``scrub_stale_values``: this fails if the broker's own select moves away from the one the index serves."""
        old = timezone.now() - timedelta(hours=1)
        for i in range(3):
            SentinelTask.objects.create(project=self.project, kind='secrets_scan', status='done', finished_at=old, result={'findings': []})
        SentinelTask.objects.create(project=self.project, kind='route_probe', status='done', finished_at=old, result={'values_scrubbed': True})
        self.assertEqual(len(list(self.candidates())), 3)
        self.assertEqual(sentinel_broker.scrub_stale_values(), 3)
        self.assertEqual(len(list(self.candidates())), 0)


class DetectionProgressUsesItsIndexTests(TestCase):
    def by_source(self):
        from django.db.models import Count
        return CVEDetection.objects.exclude(strategy={}).values_list('source').annotate(n=Count('id'))

    def test_the_group_by_reads_an_index_of_the_detections_that_have_checks(self):
        self.assertIn('cvedetection_source_filled_idx', plan(self.by_source()))

    def test_progress_counts_are_unchanged(self):
        for i, (source, strategy) in enumerate((('rules', {'scope': 'web'}), ('rules', {}), ('ai', {'scope': 'web'}), ('manual', {'scope': 'x'}), ('ai', {}))):
            entry = CVEEntry.objects.create(cve_id=f'CVE-2099-5{i:03d}', cvss=5.0, published_at=timezone.now(), affected=[])
            CVEDetection.objects.create(cve_entry=entry, source=source, strategy=strategy)
        got = detection_author.progress()
        self.assertEqual((got['cves'], got['rules'], got['ai'], got['manual']), (5, 1, 1, 1))


class IndexMigrationsAreConcurrentTests(TestCase):
    def test_both_index_migrations_build_concurrently_outside_a_transaction(self):
        """Review 621 defect 6: a large-table index is built CONCURRENTLY in a non-atomic migration, so an upgrade never blocks the feed or the Sentinels."""
        import importlib

        from django.contrib.postgres.operations import AddIndexConcurrently
        for name in ('cveFeed.migrations.0159_cvedetection_source_filled_idx', 'agentapi.migrations.0022_sentineltask_unscrubbed_idx'):
            migration = importlib.import_module(name).Migration
            self.assertFalse(migration.atomic, name)
            self.assertTrue(all(isinstance(op, AddIndexConcurrently) for op in migration.operations), name)
