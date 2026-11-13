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


class CapTests(SimpleTestCase):
    """The renewals stop a fixed time after the payload was COMPUTED: a renewal moves ``at``, never ``computed_at`` (before, the cap was measured from ``at`` and an
    unchanged fingerprint renewed a snapshot for ever: a payload 1,810 s old after 30 minutes of passes every 10 s)."""

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_a_snapshot_renewed_every_ten_seconds_is_recomputed_when_the_cap_comes(self):
        clock, computes = [1000.0], []

        def compute():
            computes.append(clock[0])
            return {'n': len(computes)}
        with mock.patch.object(snapshot_cache, '_now', lambda: clock[0]), mock.patch.object(snapshot_cache, '_elapsed', lambda: clock[0]):
            statuses = []
            for _ in range(180):  # thirty minutes of refresher passes
                statuses.append(snapshot_cache.refresh('stats', 'cap-test', compute, 10, due_age=0, fingerprint=lambda: 'same', unchanged_keep=60)[0])
                clock[0] += 10
        self.assertGreaterEqual(len(computes), 30)  # at least once a minute: 180 passes, 6 per minute
        self.assertLessEqual(max(b - a for a, b in zip(computes, computes[1:])), 70)
        entry = cache.get('cve:snap:stats:cap-test')
        self.assertLess(clock[0] - entry['computed_at'], 70)

    def test_each_snapshot_has_its_own_worst_case_staleness(self):
        self.assertEqual(live_refresh.RENEWAL_SECONDS, {'stats': 60, 'discovery-counts': 300})  # the Sentinel state and the clock-derived numbers are in stats


class GuardTests(TestCase):
    """A snapshot's fingerprint must list every table its computation reads, or a write to the table is not seen while the snapshot is renewed."""

    @classmethod
    def setUpTestData(cls):
        from datetime import timedelta

        from django.utils import timezone

        from agentapi.models import Agent
        from cveFeed.models import InternalRange
        from dashboard.models import ApiToken, Org, Project
        from django.contrib.auth.models import User
        from startScan.models import Subdomain
        from targetApp.models import Domain
        now = timezone.now()
        org = Org.objects.create(name='G', slug='g-org')
        cls.project = Project.objects.create(name='G', slug='g-proj', insert_date=now, org=org)
        domain = Domain.objects.create(name='g.example.test', project=cls.project, insert_date=now)
        Subdomain.objects.create(name='10.1.2.3', target_domain=domain)
        InternalRange.objects.create(project=cls.project, cidr='10.1.0.0/16', description='lab')
        user = User.objects.create_superuser('g-root', 'root@g.example.test', 'x')
        token = ApiToken.objects.create(user=user, name='g', key_hash='g' * 64, prefix='cve_')
        Agent.objects.create(token=token, name='g-sentinel', kind='scanner', status='active', last_seen=now, capabilities=['discover'], network='internal')

    def tables_read(self, compute):
        import re

        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        from cveFeed import internal_view
        internal_view.invalidate()
        with CaptureQueriesContext(connection) as captured:
            compute()
        found = set()
        for query in captured.captured_queries:
            found |= set(re.findall(r'(?:FROM|JOIN) "([^"]+)"', query['sql']))
        return found

    def test_every_table_a_snapshot_reads_is_in_its_fingerprint(self):
        from cveFeed import views
        computes = {'stats': views.stats_payload, 'discovery-counts': views.discovery_counts}
        for name, compute in computes.items():
            missing = self.tables_read(compute) - set(live_refresh.fingerprint_tables(name)) - live_refresh.NOT_AN_INPUT
            self.assertEqual(missing, set(), f'the {name} snapshot reads tables its fingerprint does not list')

    def test_the_stats_snapshot_reads_the_sentinel_state_so_it_is_listed_and_capped_at_a_minute(self):
        from cveFeed import views
        read = self.tables_read(views.stats_payload)
        self.assertIn('agentapi_agent', read)
        self.assertIn('agentapi_agent', live_refresh.fingerprint_tables('stats'))
        self.assertLessEqual(live_refresh.RENEWAL_SECONDS['stats'], 60)


class TrackCountsTests(SimpleTestCase):
    def test_counters_that_are_not_tracked_give_no_fingerprint(self):
        with mock.patch.object(snapshot_cache, '_track_counts', {'on': False}):
            self.assertIsNone(snapshot_cache.table_fingerprint('startScan_subdomain'))


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
        self.assertIsNotNone(prints['stats'][0]())
