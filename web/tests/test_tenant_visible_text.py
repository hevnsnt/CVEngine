"""What every tenant sees must not carry another tenant's facts, and a missing or foreign scan id is a 404 (review 2 F7, F8, F10)."""
from django.http import Http404
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import watchdog, work_planner
from dashboard.models import Org, Project


class PlannerSentenceTests(SimpleTestCase):
    def rows(self, in_flight):
        return {'ssh_probe': {'ready': 10, 'in_flight': in_flight, 'due': 10, 'awaiting': 0}}

    def test_a_scoped_viewer_never_reads_what_was_queued_elsewhere(self):
        last = {'state': 'queued', 'queued': {'ssh_probe': 400}}
        line = work_planner.describe(last, self.rows(0), True, 30, scoped=True)
        self.assertNotIn('400', line)
        self.assertIn('nothing of yours was queued', line)
        line = work_planner.describe(last, self.rows(25), True, 30, scoped=True)
        self.assertIn('25 SSH', line) if 'SSH' in work_planner.specs()['ssh_probe'].noun else self.assertIn('25', line)
        self.assertNotIn('400', line)

    def test_an_instance_wide_viewer_keeps_the_instance_numbers(self):
        line = work_planner.describe({'state': 'queued', 'queued': {'ssh_probe': 400}}, self.rows(0), True, 30, scoped=False)
        self.assertIn('400', line)


class WatchdogLineTests(TestCase):
    def test_switching_a_rule_writes_no_activity_line_so_no_tenant_feed_names_the_admin(self):
        """Review 2 F8 said the line "Switched off by <admin>" reached every tenant's feed. The event is level info, and only a problem or a fix
        writes an activity line: the name stays in the watchdog event list that App Admins read."""
        from django.contrib.auth.models import User

        from cveFeed.models import AgentActivity, WatchdogEvent
        admin = User.objects.create_user('alice-admin', password='x')
        before = AgentActivity.objects.count()
        watchdog.set_enabled('R4', False, admin)
        self.assertEqual(AgentActivity.objects.count(), before)
        self.assertTrue(WatchdogEvent.objects.filter(rule='R4', level='info').exists())


class ReportRouteTests(TestCase):
    def test_a_missing_or_foreign_scan_id_is_a_404_not_a_500(self):
        from startScan import views
        request = RequestFactory().get('/scan/create_report/999999')
        from django.contrib.auth.models import User
        request.user = User.objects.create_superuser('report-viewer', password='x')
        with self.assertRaises(Http404):
            views.create_report(request, 999999)
