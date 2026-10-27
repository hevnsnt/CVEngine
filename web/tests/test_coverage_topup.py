"""Deterministic, no-model-call top-up of host-assessment coverage (cveFeed.coverage_topup)."""
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import assessment_review as ar
from cveFeed import coverage_topup
from cveFeed import host_assessment
from cveFeed.models import HostAssessment
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain


class CoverageTopupTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Topup org', slug='topup-org')
        self.project = Project.objects.create(name='Topup', slug='topup', org=self.org, insert_date=self.now)
        self.domain = Domain.objects.create(name='topup.example', project=self.project, insert_date=self.now)

    def hosts(self, n, prefix='h'):
        return [Subdomain.objects.create(target_domain=self.domain, name=f'{prefix}{i}.topup.example') for i in range(n)]

    def test_many_due_hosts_are_not_throttled_to_one_per_run(self):
        self.hosts(7)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'topup-task'
            result = coverage_topup.top_up(now=self.now)
        # the per-project cap (5) is reached before the backlog (7) is drained, but far more than the three-hour
        # review's one-due-host-per-project-per-window pace
        self.assertEqual(result['hosts_queued'], 5)
        self.assertEqual(HostAssessment.objects.filter(project=self.project, status='queued').count(), 5)

    def test_the_per_project_cap_binds_before_the_backlog_is_drained(self):
        # Already covered implicitly by test_many_due_hosts_are_not_throttled_to_one_per_run (7 due, 5 queued), but
        # spelled out here against a much larger backlog so the cap, not the backlog size, is clearly what binds.
        self.hosts(50)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'topup-task'
            result = coverage_topup.top_up(now=self.now)
        self.assertEqual(result['hosts_queued'], coverage_topup.PER_PROJECT_LIMIT)
        self.assertEqual(host_assessment.active_count(self.project), coverage_topup.PER_PROJECT_LIMIT)

    def test_the_global_cap_binds_even_with_free_project_capacity(self):
        other = Project.objects.create(name='Topup other', slug='topup-other', org=self.org, insert_date=self.now)
        other_domain = Domain.objects.create(name='other.topup.example', project=other, insert_date=self.now)
        self.hosts(10)  # self.project has 10 due hosts and no active assessments: 5 free slots of its own
        # Fill most of the global cap on another project, leaving a budget of 3 across the whole sweep.
        for i in range(17):
            HostAssessment.objects.create(project=other, domain=other_domain, host=f'busy{i}.other.topup.example', status='running')
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'topup-task'
            result = coverage_topup.top_up(now=self.now)
        # Only 3 are queued even though the project alone has room for 5: the global cap of 20 wins.
        self.assertEqual(result['hosts_queued'], 3)
        self.assertEqual(host_assessment.active_count(), 20)
        self.assertEqual(host_assessment.active_count(self.project), 3)

    def test_a_paused_instance_queues_nothing(self):
        self.hosts(3)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            result = coverage_topup.top_up(now=self.now)
        self.assertEqual(result['skipped'], 'paused')
        sender.assert_not_called()
        self.assertEqual(HostAssessment.objects.count(), 0)

    def test_a_bounty_blocked_project_is_skipped(self):
        self.hosts(3)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value={self.project.pk}), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            result = coverage_topup.top_up(now=self.now)
        self.assertEqual(result['hosts_queued'], 0)
        sender.assert_not_called()

    def test_the_ai_review_and_the_topup_never_double_queue_the_same_host(self):
        [sub] = self.hosts(1)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'review-task'
            status, job_id, _ = ar.dispatch(self.project, {'due_host_id': sub.pk}, 'assess_host')
            self.assertEqual(status, 'queued')
            # The host just got an assessment, so it falls out of host_coverage_due's own population (a recent
            # attempt is deferred, not re-offered) before the top-up sweep ever sees it.
            sender.return_value.id = 'topup-task'
            result = coverage_topup.top_up(now=self.now)
        self.assertEqual(result['hosts_queued'], 0)
        self.assertEqual(HostAssessment.objects.filter(project=self.project, host=sub.name).count(), 1)
        # Belt and braces: even if both mechanisms raced and offered the same host at once, enqueue()'s own
        # active-row check (and IntegrityError fallback) must not create a second active row for it.
        again, created = host_assessment.enqueue(self.project, sub, source='topup')
        self.assertFalse(created)
        self.assertEqual(again.pk, job_id)
        self.assertEqual(HostAssessment.objects.filter(project=self.project, host=sub.name).count(), 1)
