"""Short-timeline (5-day) archival of hosts that never once resolve to a scannable IP (cveFeed.unresolved_archive),
kept separate from cveFeed.inactive_archive's 30-day vanished-from-enumeration case."""
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import archive_rediscovery
from cveFeed.unresolved_archive import candidates, check_one, record_attempt, run_page, ttl
from cveFeed.models import HostAssessment, HostExclusion, HostState, UnresolvedArchiveReview
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain


class UnresolvedArchiveTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Unresolved org', slug='unresolved-org')
        self.project = Project.objects.create(name='Unresolved', slug='unresolved', org=self.org, insert_date=self.now)
        self.domain = Domain.objects.create(name='unresolved.example', project=self.project, insert_date=self.now)

    def state(self, host='flaky.unresolved.example', **fields):
        Subdomain.objects.create(target_domain=self.domain, name=host)
        fields.setdefault('last_seen', self.now)
        return HostState.objects.create(project=self.project, domain=self.domain, host=host, **fields)

    def test_a_host_that_always_resolves_is_never_archived_even_after_days_unassessed(self):
        # The critical regression to guard: hosts that resolve fine (HTTP 200) and are simply waiting their turn
        # for an assessment must never be swept up by this path, no matter how old last_seen gets.
        row = self.state(last_seen=self.now - timedelta(days=9))
        self.assertIsNone(row.unresolved_first_at)
        self.assertFalse(candidates(self.now).filter(pk=row.pk).exists())
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, now=self.now), 'deferred')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)

    def test_record_attempt_ignores_results_that_never_attempted_resolution(self):
        # A guard-clause skip (host absent/excluded/paused) or an unexpected exception carries no 'resolved' key and
        # must never be read as either a success or a failure.
        self.assertEqual(record_attempt(self.project, self.domain, 'skip.unresolved.example',
                                        {'status': 'inconclusive', 'error': 'host is absent, excluded, outside scope, or scanning is paused'},
                                        now=self.now), 'skipped')
        self.assertFalse(HostState.objects.filter(project=self.project, host='skip.unresolved.example').exists())

    def test_a_three_day_unbroken_streak_of_no_scannable_ip_is_archived(self):
        host = 'never.unresolved.example'
        Subdomain.objects.create(target_domain=self.domain, name=host)
        t0 = self.now - timedelta(days=6)
        record_attempt(self.project, self.domain, host, {'status': 'inconclusive', 'resolved': 0,
                       'error': 'No scannable IP address resolved; no active checks ran'}, now=t0)
        row = HostState.objects.get(project=self.project, host=host)
        self.assertEqual(row.unresolved_first_at, t0)
        self.assertEqual(row.unresolved_checks, 1)
        # A later failed attempt, still inside the same unbroken streak, bumps the count but keeps the first-failure anchor.
        record_attempt(self.project, self.domain, host, {'status': 'inconclusive', 'resolved': 0,
                       'error': 'No scannable IP address resolved; no active checks ran'}, now=t0 + timedelta(days=3))
        row.refresh_from_db()
        self.assertEqual((row.unresolved_first_at, row.unresolved_checks), (t0, 2))
        self.assertTrue(candidates(self.now).filter(pk=row.pk).exists())
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, now=self.now), 'archived')
        row.refresh_from_db()
        self.assertIsNotNone(row.archived_at)
        self.assertFalse(row.archived_by_user)
        self.assertIn('without once resolving', row.archive_reason)
        self.assertTrue(Subdomain.objects.filter(name=host).exists())  # history retained, same as inactive_archive

    def test_one_success_mid_streak_resets_it(self):
        host = 'recovers.unresolved.example'
        t0 = self.now - timedelta(days=6)
        record_attempt(self.project, self.domain, host, {'status': 'inconclusive', 'resolved': 0}, now=t0)
        record_attempt(self.project, self.domain, host, {'status': 'completed', 'resolved': 1}, now=t0 + timedelta(days=1))
        row = HostState.objects.get(project=self.project, host=host)
        self.assertEqual((row.unresolved_first_at, row.unresolved_last_at, row.unresolved_checks), (None, None, 0))
        self.assertFalse(candidates(self.now).filter(pk=row.pk).exists())
        # A new failure afterwards starts a fresh streak, not a continuation of the old one.
        record_attempt(self.project, self.domain, host, {'status': 'inconclusive', 'resolved': 0}, now=t0 + timedelta(days=4))
        row.refresh_from_db()
        self.assertEqual(row.unresolved_first_at, t0 + timedelta(days=4))
        self.assertEqual(row.unresolved_checks, 1)
        self.assertFalse(candidates(self.now).filter(pk=row.pk).exists())  # not yet 3 days into the new streak

    def test_pinned_excluded_and_actively_queued_hosts_are_never_auto_archived(self):
        old = self.now - timedelta(days=6)
        pinned = self.state('pinned.unresolved.example', pinned=True, unresolved_first_at=old, unresolved_checks=3)
        excluded = self.state('excluded.unresolved.example', unresolved_first_at=old, unresolved_checks=3)
        HostExclusion.objects.create(org=self.org, host=excluded.host)
        queued = self.state('queued.unresolved.example', unresolved_first_at=old, unresolved_checks=3)
        HostAssessment.objects.create(project=self.project, domain=self.domain, host=queued.host, status='queued')
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(pinned, now=self.now), 'deferred')
            self.assertEqual(check_one(excluded, now=self.now), 'deferred')
            self.assertEqual(check_one(queued, now=self.now), 'deferred')
        self.assertFalse(HostState.objects.filter(pk__in=[pinned.pk, excluded.pk, queued.pk],
                                                  archived_at__isnull=False).exists())

    def test_daily_schedule_and_paging(self):
        from django_celery_beat.models import PeriodicTask
        schedule = PeriodicTask.objects.get(name='cvengine-daily-unresolved-archive-review')
        self.assertEqual((schedule.task, schedule.queue, schedule.interval.every, schedule.interval.period),
                         ('review_unresolved_hosts', 'cve_feed_queue', 1, 'days'))
        old = self.now - timedelta(days=6)
        for i in range(3):
            self.state(f'due{i}.unresolved.example', unresolved_first_at=old, unresolved_checks=2)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            result = run_page()
        self.assertEqual(result['checked'], 3)
        self.assertEqual(result['archived'], 3)
        self.assertEqual(UnresolvedArchiveReview.objects.get(pk=result['run_id']).status, 'completed')

    def test_archived_this_way_is_picked_up_restored_and_reassessed_by_the_existing_rediscovery_sweep(self):
        host = 'comesback.unresolved.example'
        old = self.now - timedelta(days=6)
        row = self.state(host, unresolved_first_at=old, unresolved_checks=4)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, now=self.now), 'archived')
        row.refresh_from_db()
        self.assertIsNotNone(row.archived_at)
        # The exact same daily rediscovery sweep cveFeed.archive_rediscovery drives for a host retired 30+ days
        # keys only off archived_at/archived_by_user, so it finds and resolves this host too, exactly as it would
        # for the other archive path.
        resolver = lambda name: ('absent', set()) if name.startswith('cvengine-nonexistent-') else ('resolved', {'8.8.8.8'})
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'unresolved-recheck'
            outcome = archive_rediscovery.check_one(row, resolver=resolver)
        self.assertEqual(outcome, 'reactivated')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)
        self.assertEqual(row.archive_assessment.status, 'queued')
        self.assertEqual(row.archive_assessment.host, host)
