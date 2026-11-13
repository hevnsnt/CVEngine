"""The status's counted project rows on a slow server: an expired row is renewed, not counted again, when nothing it reads was written since it was counted.

A counted row was fresh for ``CVENGINE_STATUS_CACHE_SECONDS`` (60) and then counted again (4 to 10 s on a 3-core host), so every other status call on such a
server counted and showed stale rows. The row now keeps a fingerprint of the tables it is counted from (``cveFeed.snapshot_cache.table_fingerprint``, the
mechanism the live snapshots use) and the last result of the browser sandbox; when the row has expired and the fingerprint is the same it is stored again for
another ``CVENGINE_STATUS_CACHE_SECONDS``, for at most ``ROW_RENEWAL_SECONDS`` after it was counted. The numbers that come from the clock (a scan marked
running for longer than the running window becomes ``stalled`` with no write) are therefore never older than that.
"""
import re
import time
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext

from agentapi import system_status
from agentapi.services import Ctx
from cveFeed.models import HostScreenshot, ProbeObservation
from tests.test_status_shared_counts import World


class Fixtures(World):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        project = cls.projects[0]
        from targetApp.models import Domain
        domain = Domain.objects.filter(project=project).first()
        ProbeObservation.objects.create(project=project, domain=domain, host='www.sc0.example.test', probe='wpscan', kind='wordpress', product='WordPress',
                                        outcome='found', evidence={'state': 'scanned', 'findings': 2})
        HostScreenshot.objects.create(project=project, domain=domain, host='sc0.example.test', scheme='https', port=443, outcome='queued')

    def setUp(self):
        super().setUp()
        self.ctx = Ctx(user=self.root)
        self.counted, self.total = [], []
        real_row = system_status._project_row

        def spy(project, shared=None):
            self.counted.append(project.slug)
            self.total.append(project.slug)
            return real_row(project, shared)
        patch = mock.patch.object(system_status, '_project_row', spy)
        patch.start()
        self.addCleanup(patch.stop)

    def expire_rows(self):
        cache.delete_many([system_status._row_keys(p)[0] for p in self.projects])

    def call(self):
        self.counted.clear()
        rows, waiting = system_status._projects_partial(self.ctx)
        return rows, waiting


class GuardTests(World):
    """The fingerprint must list every table the rows read, or a write to the table is not seen while the row is renewed."""

    def tables_read(self, fn):
        with CaptureQueriesContext(connection) as captured:
            fn()
        found = set()
        for query in captured.captured_queries:
            found |= set(re.findall(r'(?:FROM|JOIN) "([^"]+)"', query['sql']))
        return found

    def test_every_table_the_rows_read_is_in_the_fingerprint(self):
        ids = [p.id for p in self.projects]
        listed = set(system_status.row_fingerprint_tables())
        shared = []
        read = self.tables_read(lambda: shared.append(system_status._shared_inputs(ids)))
        self.assertIsNotNone(shared[0])
        read |= self.tables_read(lambda: [system_status._project_row(p, shared[0]) for p in self.projects])
        read |= self.tables_read(lambda: [system_status._project_row(p) for p in self.projects])  # a row that counts for itself reads through other statements
        self.assertEqual(read - listed, set(), 'the project rows read tables the fingerprint does not list')
        self.assertTrue({'startScan_subdomain', 'cveFeed_cvematch', 'startScan_vulnerability', 'cveFeed_hygienefinding', 'cveFeed_probeobservation',
                         'cveFeed_hostscreenshot', 'dashboard_systemtimings'} <= read)  # the world reaches the optional readers too

    def test_the_fingerprint_is_read_from_postgresql_and_carries_the_sandbox_result_and_the_switches(self):
        before = system_status._row_fingerprint()
        self.assertIsInstance(before, str)
        from cveFeed import web_shot
        with mock.patch.object(web_shot, 'sandbox_state', lambda: {'engaged': False, 'reason': 'x', 'at': 't'}):
            self.assertNotEqual(system_status._row_fingerprint(), before)
        for switch in ('CVENGINE_SCREENSHOTS', 'CVENGINE_VHOST', 'CVENGINE_SUBDIR_APPS'):  # a row shows each of them: a restart that flips one must not leave the old row
            with mock.patch.dict('os.environ', {switch: '0'}):
                self.assertNotEqual(system_status._row_fingerprint(), before, switch)


class RenewalTests(Fixtures):
    def test_an_expired_row_with_unchanged_inputs_is_renewed_not_counted(self):
        with mock.patch.object(system_status, '_row_fingerprint', lambda: 'same'):
            rows, _ = self.call()
            self.assertEqual(len(self.counted), 3)
            self.expire_rows()
            again, waiting = self.call()
        self.assertEqual((self.counted, waiting), ([], []))
        self.assertEqual(again, rows)
        self.assertTrue(all(cache.get(system_status._row_keys(p)[0]) for p in self.projects))  # fresh again for CVENGINE_STATUS_CACHE_SECONDS

    def test_a_changed_input_counts_again(self):
        fp = ['a']
        with mock.patch.object(system_status, '_row_fingerprint', lambda: fp[0]):
            self.call()
            self.expire_rows()
            fp[0] = 'b'
            self.call()
        self.assertEqual(len(self.counted), 3)

    def test_a_row_is_counted_again_when_the_cap_comes_whatever_the_fingerprint_says(self):
        start = time.time()
        with mock.patch.object(system_status, '_row_fingerprint', lambda: 'same'):
            self.call()
            self.expire_rows()
            self.call()
            self.assertEqual(self.counted, [])  # renewed
            self.expire_rows()
            with mock.patch.object(system_status.time, 'time', lambda: start + system_status.ROW_RENEWAL_SECONDS + 1):
                self.call()
        self.assertEqual(len(self.counted), 3)

    def test_renewals_do_not_move_when_the_row_was_counted(self):
        """Renewed every minute for ever would never count the clock-derived numbers again: the cap is from the count, not from the last renewal."""
        clock = [time.time()]
        with mock.patch.object(system_status, '_row_fingerprint', lambda: 'same'), mock.patch.object(system_status.time, 'time', lambda: clock[0]):
            counted_at = []
            for _ in range(20):  # twenty minutes of calls, the row expiring between each
                self.call()
                if self.counted:
                    counted_at.append(clock[0])
                self.expire_rows()
                clock[0] += 60
        self.assertGreaterEqual(len(counted_at), 4)  # at least once in each five minutes
        self.assertLessEqual(max(b - a for a, b in zip(counted_at, counted_at[1:])), system_status.ROW_RENEWAL_SECONDS + 60)

    def test_without_readable_counters_a_row_is_counted_each_time_as_before(self):
        with mock.patch.object(system_status, '_row_fingerprint', lambda: None):
            self.call()
            self.expire_rows()
            self.call()
        self.assertEqual(len(self.total), 6)

    def test_with_the_row_cache_off_nothing_is_renewed(self):
        with mock.patch.object(system_status, '_row_fingerprint', lambda: 'same'), mock.patch.dict('os.environ', {'CVENGINE_STATUS_CACHE_SECONDS': '0'}):
            self.call()
            self.call()
        self.assertEqual(len(self.total), 6)

    def test_the_warm_up_keeps_the_fingerprint_so_its_rows_can_be_renewed(self):
        with mock.patch.object(system_status, '_row_fingerprint', lambda: 'same'):
            system_status.warm_project_rows([p.id for p in self.projects])
            self.counted.clear()
            self.expire_rows()
            self.call()
        self.assertEqual(self.counted, [])

    def test_the_fingerprint_is_read_before_the_count_starts(self):
        order = []
        real_shared = system_status._shared_inputs
        with mock.patch.object(system_status, '_row_fingerprint', lambda: order.append('fingerprint') or 'x'), \
                mock.patch.object(system_status, '_shared_inputs', lambda ids: order.append('count') or real_shared(ids)):
            self.call()
        self.assertEqual(order[:2], ['fingerprint', 'count'])
