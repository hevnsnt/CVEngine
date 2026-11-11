"""An idle install does not re-read the whole inventory every minute to learn that nothing is due.

``coverage_topup.host_coverage_due`` (first-pass coverage) and ``stalest_hosts`` (the refresh) read a project's current inventory with six correlated checks
per host. When nothing is due the database evaluates every host to say so, and four callers ask once a minute each (the Sentinel feed, the watchdog
snapshot, the full-port and UDP gates): on the production instance the statement (shape 2 of the slow list) was running in 94 of 120 samples. An empty answer
that took long to compute is now remembered for ten times that (at most five minutes), so the four callers share one reading; an answer that is not empty,
and any answer that was quick to give, is never remembered.
"""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import coverage_topup
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class IdleMemoTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.project = Project.objects.create(name='I', slug='im-proj', insert_date=now, org=Org.objects.create(name='I', slug='im-org'))
        cls.domain = Domain.objects.create(name='im.example.com', project=cls.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='im-engine', yaml_configuration='x', default_engine=True)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, scan_status=2, start_scan_date=now, tasks=[])

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.now = timezone.now()

    def new_host(self, name):
        return Subdomain.objects.create(target_domain=self.domain, name=name, scan_history=self.scan)

    def slow(self, seconds):
        """Every read of the clock the memo times a computation with advances by ``seconds``."""
        ticks = iter(range(0, 10 ** 6))
        return mock.patch.object(coverage_topup, '_monotonic', lambda: next(ticks) * seconds)

    def due(self, **kw):
        return coverage_topup.host_coverage_due(self.project, self.now, limit=5, need_count=False, **kw)[1]

    def test_a_slow_empty_answer_is_shared_by_the_next_callers(self):
        with self.slow(3.0):
            self.assertEqual(self.due(), [])
            host = self.new_host('late.im.example.com')  # becomes due a moment after the reading
            with CaptureQueriesContext(connection) as asked:
                self.assertEqual(self.due(), [])  # the gate, the feed and the watchdog all read the one answer
        self.assertEqual(len(asked), 0)
        cache.clear()  # the memo has run out
        with self.slow(3.0):
            self.assertEqual(self.due(), [host.pk])

    def test_a_quick_answer_is_never_remembered(self):
        with self.slow(0.01):
            self.assertEqual(self.due(), [])
            host = self.new_host('quick.im.example.com')
            self.assertEqual(self.due(), [host.pk])  # as before: the next call sees the new host at once

    def test_an_answer_with_hosts_in_it_is_never_remembered(self):
        host = self.new_host('now.im.example.com')
        with self.slow(3.0):
            self.assertEqual(self.due(), [host.pk])
            second = self.new_host('now2.im.example.com')
            self.assertEqual(sorted(self.due()), sorted([host.pk, second.pk]))

    def test_a_caller_that_counts_the_backlog_always_reads_it(self):
        with self.slow(3.0):
            self.due()  # leaves an empty answer behind
            host = self.new_host('count.im.example.com')
            count, ids = coverage_topup.host_coverage_due(self.project, self.now, limit=5, need_count=True)
        self.assertEqual((count, ids), (1, [host.pk]))

    def test_the_memo_is_one_per_project(self):
        other = Project.objects.create(name='J', slug='im-proj2', insert_date=self.now, org=self.project.org)
        with self.slow(3.0):
            self.due()
            self.assertEqual(coverage_topup.host_coverage_due(other, self.now, limit=5, need_count=False)[1], [])
            with CaptureQueriesContext(connection) as asked:
                coverage_topup.host_coverage_due(other, self.now, limit=5, need_count=False)
        self.assertEqual(len(asked), 0)

    def test_the_refresh_does_not_read_the_inventory_again_while_nothing_is_stale(self):
        host = self.new_host('refresh.im.example.com')
        from cveFeed.models import HostAssessment
        HostAssessment.objects.create(project=self.project, domain=self.domain, host=host.name.lower(), status='completed')
        gap = timedelta(hours=6)
        with self.slow(3.0):
            self.assertEqual(coverage_topup.stalest_hosts(self.project, self.now, 5, gap), [])
            with CaptureQueriesContext(connection) as asked:
                self.assertEqual(coverage_topup.stalest_hosts(self.project, self.now, 5, gap), [])
        self.assertEqual(len(asked), 0)
