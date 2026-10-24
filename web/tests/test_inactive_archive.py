from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed.inactive_archive import check_one, run_page
from cveFeed.models import HostAssessment, HostExclusion, HostState, InactiveArchiveReview
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain


class InactiveArchiveTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Inactive org', slug='inactive-org')
        self.project = Project.objects.create(name='Inactive', slug='inactive', org=self.org, insert_date=self.now)
        self.domain = Domain.objects.create(name='inactive.example', project=self.project, insert_date=self.now)

    def state(self, host='old.inactive.example', **fields):
        Subdomain.objects.create(target_domain=self.domain, name=host)
        return HostState.objects.create(project=self.project, domain=self.domain, host=host,
            retired_at=self.now - timedelta(days=60), last_seen=self.now - timedelta(days=90),
            last_alive_check=self.now - timedelta(days=60),
            state={'ips': {'8.8.8.8': {'ports': {'443/tcp': {}}}}}, **fields)

    def test_two_negative_observations_must_span_thirty_days(self):
        row = self.state()
        row.retired_at = self.now - timedelta(days=90)
        row.last_seen = self.now - timedelta(days=120)
        row.save(update_fields=['retired_at', 'last_seen'])
        missing = lambda host: ('absent', set())
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, resolver=missing, now=self.now - timedelta(days=31)), 'observed')
            row.refresh_from_db()
            self.assertEqual(row.inactive_absent_checks, 1)
            self.assertEqual(check_one(row, resolver=missing, now=self.now - timedelta(days=2)), 'observed')
            row.refresh_from_db()
            self.assertIsNone(row.archived_at)
            self.assertEqual(check_one(row, resolver=missing, now=self.now), 'archived')
        row.refresh_from_db()
        self.assertIsNotNone(row.archived_at)
        self.assertEqual(row.inactive_absent_checks, 3)
        self.assertTrue(Subdomain.objects.filter(name=row.host).exists())  # history retained

    def test_sparse_or_failed_evidence_never_archives(self):
        never = self.state('never.inactive.example')
        never.last_seen = self.now - timedelta(days=1)
        never.save(update_fields=['last_seen'])
        pinned = self.state('pinned.inactive.example', pinned=True,
            inactive_first_absent_at=self.now - timedelta(days=40), inactive_absent_checks=3)
        failed = self.state('failed.inactive.example',
            inactive_first_absent_at=self.now - timedelta(days=40), inactive_absent_checks=3)
        excluded = self.state('excluded.inactive.example',
            inactive_first_absent_at=self.now - timedelta(days=40), inactive_absent_checks=3)
        HostExclusion.objects.create(org=self.org, host=excluded.host)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(never, resolver=lambda host: ('absent', set()), now=self.now), 'deferred')
            self.assertEqual(check_one(pinned, resolver=lambda host: ('absent', set()), now=self.now), 'deferred')
            self.assertEqual(check_one(failed, resolver=lambda host: ('error', set()), now=self.now), 'error')
            self.assertEqual(check_one(excluded, resolver=lambda host: ('absent', set()), now=self.now), 'deferred')
        self.assertFalse(HostState.objects.filter(pk__in=[never.pk, pinned.pk, failed.pk, excluded.pk],
                                                  archived_at__isnull=False).exists())

    def test_active_assessment_defers_archival(self):
        row = self.state(inactive_first_absent_at=self.now - timedelta(days=40), inactive_absent_checks=2)
        HostAssessment.objects.create(project=self.project, domain=self.domain, host=row.host, status='running')
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, resolver=lambda host: ('absent', set()), now=self.now), 'deferred')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)

    def test_quiet_known_ip_ports_do_not_prove_host_absence(self):
        row = self.state('8.8.8.8', inactive_first_absent_at=self.now - timedelta(days=40),
                         inactive_absent_checks=2)
        row.domain = Domain.objects.create(name='8.8.8.8', project=self.project, insert_date=self.now)
        row.state = {'ips': {'8.8.8.8': {'ports': {'443/tcp': {}}}}}
        row.save(update_fields=['domain', 'state'])
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, tcp_probe=lambda host, port: False, now=self.now), 'deferred')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)
        self.assertEqual(row.inactive_absent_checks, 2)

    def test_out_of_scope_dns_answer_breaks_old_absence_sequence(self):
        row = self.state(inactive_first_absent_at=self.now - timedelta(days=40), inactive_absent_checks=2)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, resolver=lambda host: ('resolved', {'127.0.0.1'}),
                                       now=self.now), 'deferred')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)
        self.assertIsNone(row.inactive_first_absent_at)

    def test_newer_positive_seen_time_resets_old_absence_window(self):
        row = self.state(inactive_first_absent_at=self.now - timedelta(days=80), inactive_absent_checks=3)
        row.last_seen = self.now - timedelta(days=40)
        row.save(update_fields=['last_seen'])
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, resolver=lambda host: ('absent', set()), now=self.now), 'observed')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)
        self.assertEqual(row.inactive_absent_checks, 1)
        self.assertGreater(row.inactive_first_absent_at, row.last_seen)

    def test_reappearance_resets_absence_and_queues_full_host_assessment(self):
        row = self.state(inactive_first_absent_at=self.now - timedelta(days=40), inactive_absent_checks=4)
        resolver = lambda host: ('absent', set()) if host.startswith('cvengine-nonexistent-') else (
            'resolved', {'8.8.8.8'})
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'fixture-assessment'
            self.assertEqual(check_one(row, resolver=resolver, now=self.now), 'reactivated')
        row.refresh_from_db()
        self.assertIsNone(row.retired_at)
        self.assertIsNone(row.inactive_first_absent_at)
        self.assertEqual(row.inactive_absent_checks, 0)
        self.assertEqual(row.archive_assessment.status, 'queued')

    def test_daily_review_is_checkpointed_paged_and_pause_aware(self):
        from django_celery_beat.models import PeriodicTask
        schedule = PeriodicTask.objects.get(name='cvengine-daily-inactive-archive-review')
        self.assertEqual((schedule.task, schedule.queue), ('review_inactive_hosts', 'cve_feed_queue'))
        for i in range(27):
            self.state(f'h{i}.inactive.example')
        resolver = lambda host: ('absent', set())
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.review_inactive_hosts.apply_async') as continuation:
            first = run_page(resolver=resolver)
            self.assertEqual(first['checked'], 25)
            continuation.assert_called_once()
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            paused = run_page(first['run_id'], resolver=resolver)
        self.assertEqual(paused['status'], 'paused')
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            done = run_page(first['run_id'], resolver=resolver)
        self.assertEqual(done['checked'], 27)
        self.assertEqual(InactiveArchiveReview.objects.get(pk=first['run_id']).status, 'completed')
        self.assertEqual(run_page(resolver=resolver)['skipped'], 'already completed today')
