"""A report job nobody started, or whose worker died, ends as a visible failure after minutes, not as "Queued..." for two hours (the twin of an active
report is handed back to whoever asks again, so a dead row hid the fact that nothing was making the report)."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.services import Ctx
from cveFeed import report_export, report_pdf
from cveFeed.models import ReportExport
from dashboard.models import Org, Project, ProjectMembership


class ReportStallTests(TestCase):
    def setUp(self):
        self.org = Org.objects.create(name='Rs', slug='rs-org')
        self.project = Project.objects.create(name='Rs', slug='rs', org=self.org, insert_date=timezone.now())
        self.user = User.objects.create_user('rs-user', password='x')
        ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
        self.now = timezone.now()

    def job(self, status, created_ago, started_ago=None):
        row = ReportExport.objects.create(token=f't{ReportExport.objects.count()}', project=self.project, requested_by=self.user, status=status,
                                          expires_at=self.now + timedelta(hours=24))
        ReportExport.objects.filter(pk=row.pk).update(created_at=self.now - created_ago, started_at=None if started_ago is None else self.now - started_ago)
        return row

    def state(self, row):
        return ReportExport.objects.values_list('status', 'error').get(pk=row.pk)

    def test_a_report_no_worker_started_fails_after_ten_minutes_and_says_why(self):
        waiting = self.job('queued', timedelta(minutes=11))
        fresh = self.job('queued', timedelta(minutes=2))
        report_export._expire_stuck(self.now)
        status, error = self.state(waiting)
        self.assertEqual(status, 'failed')
        self.assertIn('no worker started this report within 10 minutes', error)
        self.assertEqual(self.state(fresh)[0], 'queued')

    def test_a_running_report_fails_once_it_is_past_the_renderers_own_limit(self):
        limit = timedelta(seconds=report_pdf.render_seconds()) + report_export.RUN_MARGIN
        on_time = self.job('running', timedelta(minutes=3), started_ago=timedelta(minutes=2))
        dead = self.job('running', limit + timedelta(minutes=1), started_ago=limit + timedelta(seconds=30))
        report_export._expire_stuck(self.now)
        self.assertEqual(self.state(on_time)[0], 'running')
        status, error = self.state(dead)
        self.assertEqual(status, 'failed')
        self.assertIn('did not finish', error)

    def test_asking_again_after_a_stall_makes_a_new_report_not_the_dead_one(self):
        dead = self.job('queued', timedelta(minutes=30))
        with mock.patch('cveFeed.tasks.generate_report.apply_async') as sender:
            sender.return_value.id = 'task-1'
            job, created = report_export.enqueue(Ctx(user=self.user), 'rs')
        self.assertTrue(created)
        self.assertNotEqual(job.pk, dead.pk)
        self.assertEqual(self.state(dead)[0], 'failed')

    def test_a_worker_that_picks_up_the_dead_row_later_does_nothing(self):
        dead = self.job('queued', timedelta(minutes=30))
        report_export._expire_stuck(self.now)
        self.assertEqual(report_export.execute(dead.pk)['status'], 'skipped')
        self.assertEqual(self.state(dead)[0], 'failed')

    def test_the_renderer_runs_at_a_lower_priority(self):
        with mock.patch('cveFeed.report_pdf.subprocess.run') as run:
            run.return_value = mock.Mock(returncode=0)
            report_pdf.render_pdf('<p>x</p>', '/tmp/never-written.pdf')
        command = run.call_args.args[0]
        if report_pdf._LOW_PRIORITY:
            self.assertEqual(command[:3], ['nice', '-n', '10'])
        self.assertIn('cveFeed.report_render', command)
