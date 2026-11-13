"""The live refresher renews a headline snapshot whose inputs did not change instead of recomputing it.

On an install with scanning paused and a page open, ``refresh_live_snapshots`` recomputed the headline counts (4.5 s on a 3-core host, 0.9 s on the heavy
test seed) every few seconds for nothing, and overran its budget. A snapshot now keeps the fingerprint of the tables it reads (PostgreSQL's own insert,
update and delete counters, one cheap read); a due snapshot with the same fingerprint, younger than ``UNCHANGED_KEEP_SECONDS``, is stored again with a
new time and the same payload.
"""
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase

from cveFeed import live_refresh, snapshot_cache


class RenewTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.calls = []
        self.fp = ['a']

    def compute(self):
        self.calls.append(1)
        return {'n': len(self.calls)}

    def refresh(self, **kw):
        return snapshot_cache.refresh('stats', 'renew-test', self.compute, 10, due_age=0, fingerprint=lambda: self.fp[0], **kw)

    def test_the_first_round_computes_and_keeps_the_fingerprint(self):
        status, entry, previous = self.refresh()
        self.assertEqual((status, entry['payload'], entry['fp'], previous), ('refreshed', {'n': 1}, 'a', None))

    def test_a_due_snapshot_with_the_same_fingerprint_is_renewed_not_recomputed(self):
        self.refresh()
        before = cache.get('cve:snap:stats:renew-test')
        status, entry, previous = self.refresh()
        self.assertEqual((status, len(self.calls), entry['payload'], entry['etag']), ('unchanged', 1, {'n': 1}, before['etag']))
        self.assertGreaterEqual(entry['at'], before['at'])
        self.assertEqual(cache.get('cve:snap:stats:renew-test')['by'], 'refresher')

    def test_a_changed_input_recomputes(self):
        self.refresh()
        self.fp[0] = 'b'
        status, entry, _ = self.refresh()
        self.assertEqual((status, len(self.calls), entry['payload'], entry['fp']), ('refreshed', 2, {'n': 2}, 'b'))

    def test_a_moved_revision_recomputes(self):
        self.refresh()
        snapshot_cache.bump_revision()
        self.assertEqual(self.refresh()[0], 'refreshed')

    def test_a_snapshot_is_not_renewed_forever(self):
        self.refresh()
        with mock.patch.object(snapshot_cache, '_now', lambda: __import__('time').time() + snapshot_cache.UNCHANGED_KEEP_SECONDS + 1):
            self.assertEqual(self.refresh()[0], 'refreshed')

    def test_a_fingerprint_that_cannot_be_read_is_never_unchanged(self):
        self.fp[0] = None
        self.refresh()
        self.assertEqual(self.refresh()[0], 'refreshed')
        self.assertEqual(len(self.calls), 2)

    def test_a_snapshot_a_request_built_has_no_fingerprint_and_is_computed_once_by_the_refresher(self):
        cache.set('cve:snap:stats:renew-test', {'payload': {'n': 0}, 'etag': 'x', 'at': snapshot_cache._now() - 99, 'rev': snapshot_cache.revision(), 'by': 'request', 'took': 1}, 60)
        status, entry, _ = self.refresh()
        self.assertEqual((status, entry['fp']), ('refreshed', 'a'))


class FingerprintTests(TestCase):
    def test_the_fingerprint_reads_the_counters_of_the_tables_asked_for(self):
        got = snapshot_cache.table_fingerprint('startScan_subdomain', 'startScan_scanhistory')
        self.assertIsInstance(got, str)
        self.assertIn('startScan_scanhistory', got)

    def test_a_table_that_does_not_exist_gives_no_fingerprint(self):
        self.assertIsNone(snapshot_cache.table_fingerprint('startScan_subdomain', 'no_such_table'))

    def test_the_headline_snapshots_have_a_fingerprint_over_real_tables(self):
        prints = live_refresh.fingerprints()
        self.assertEqual(set(prints), {'stats', 'discovery-counts'})
        self.assertIsNotNone(prints['stats']())
