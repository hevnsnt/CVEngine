"""Two reads of the CVE catalogue that used to scan all of it.

* The CVE explorer's list (GET /cve/api/cves) orders by ``published_at`` newest first with undated rows last, then ``id``. The only date index was
  ascending with nulls last, which gives that order in no direction, so every page read and sorted the whole catalogue (18,500 buffers, 78 to 137
  ms on 59,000 CVEs). Migration 0192 adds ``cvefeed_pub_id_desc_idx`` in exactly that order.
* ``service_features.index`` asked ``COUNT(id), MAX(synced_at)`` of the whole catalogue (``synced_at`` has no index: 150 to 330 ms) once a minute in
  every worker process, to know whether to read the CVEs again. The stamp is now read once for every process and shared through the cache.
"""
import importlib
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import cve_explorer, service_features
from cveFeed.models import CVEEntry

CATALOG_STAMP = 'MAX("cveFeed_cveentry"."synced_at")'


class ExplorerOrderIndexTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        for i in range(30):
            CVEEntry.objects.create(cve_id=f'CVE-2098-{i:04d}', title=f'issue {i}', cvss=[9.8, 7.5, 5.0][i % 3], kev=i % 4 == 0,
                                    published_at=None if i % 10 == 0 else now - timedelta(days=i % 7))

    def test_the_model_and_the_migration_declare_the_same_index(self):
        declared = {i.name: i for i in CVEEntry._meta.indexes}['cvefeed_pub_id_desc_idx']
        migration = importlib.import_module('cveFeed.migrations.0192_cve_pub_id_desc_idx').Migration
        self.assertFalse(migration.atomic)
        built = migration.operations[0].index
        self.assertEqual(built.deconstruct(), declared.deconstruct())
        self.assertLessEqual(len(declared.name), 30)

    def test_the_list_reads_its_page_in_index_order(self):
        # the unfiltered list (the slow one: a filter by severity or KEV narrows by its own index first, 8 to 21 ms on production)
        for number in (1, 2):
            qs = cve_explorer.search('')[(number - 1) * cve_explorer.PAGE_SIZE:number * cve_explorer.PAGE_SIZE]
            with connection.cursor() as cursor:
                cursor.execute('SET LOCAL enable_seqscan = off')  # the fixture is a few rows: make the planner show the path it takes on a catalogue
                plan = qs.explain()
            with self.subTest(page=number):
                self.assertIn('Index Scan using cvefeed_pub_id_desc_idx', plan)
                self.assertNotIn('Sort', plan, 'no sort over the rows: the index gives the order')

    def test_the_order_is_the_one_it_was(self):
        got = [e.cve_id for e in cve_explorer.search('')]
        undated = sorted((e for e in CVEEntry.objects.filter(published_at__isnull=True)), key=lambda e: -e.pk)
        dated = sorted(CVEEntry.objects.filter(published_at__isnull=False), key=lambda e: (-e.published_at.timestamp(), -e.pk))
        self.assertEqual(got, [e.cve_id for e in dated + undated])


class SharedStampTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        CVEEntry.objects.create(cve_id='CVE-2098-9001', title='needs HTTP/2', original_description='HTTP/2 rapid reset')

    def setUp(self):
        service_features.reset_index()
        self.addCleanup(service_features.reset_index)

    def stamp_reads(self):
        with CaptureQueriesContext(connection) as q:
            value = service_features.index()
        return sum(CATALOG_STAMP in x['sql'] for x in q.captured_queries), len(q), value

    def another_process(self):
        service_features._INDEX.update(checked=0.0, stamp=None, value={})  # a process that has not looked yet: the shared stamp stays

    def test_one_read_of_the_catalogue_stamp_for_every_process(self):
        reads, _n, first = self.stamp_reads()
        self.assertEqual(reads, 1)
        self.another_process()
        reads, _n, again = self.stamp_reads()
        self.assertEqual(reads, 0, 'the second process reads the stamp the first one shared')
        self.assertEqual(again, first)

    def test_a_process_whose_index_is_current_reads_nothing_after_its_check_window(self):
        self.stamp_reads()
        service_features._INDEX['checked'] = 0.0  # its INDEX_CHECK window passed
        reads, statements, _value = self.stamp_reads()
        self.assertEqual((reads, statements), (0, 0))

    def test_reset_index_forgets_the_shared_stamp(self):
        self.stamp_reads()
        CVEEntry.objects.create(cve_id='CVE-2098-9002', title='another HTTP/2 flaw', original_description='HTTP/2 CONTINUATION flood')
        self.another_process()
        self.assertEqual(self.stamp_reads()[0], 0)  # within the shared window: the stamp is the one read before the write
        service_features.reset_index()
        reads, _n, value = self.stamp_reads()
        self.assertEqual(reads, 1)
        self.assertEqual(cache.get(service_features.STAMP_KEY)[0], CVEEntry.objects.count())
        self.assertEqual(len(value), len(service_features.index()))

    def test_a_cache_that_does_not_answer_reads_the_database_as_before(self):
        with mock.patch.object(cache, 'get', side_effect=ConnectionError('down')), mock.patch.object(cache, 'set', side_effect=ConnectionError('down')):
            self.assertEqual(self.stamp_reads()[0], 1)
            self.another_process()
            self.assertEqual(self.stamp_reads()[0], 1)
