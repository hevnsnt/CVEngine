"""Issue #394: on gvmd 22.7 every finished OpenVAS scan was imported as "no scanned host", with 0 results, while the task's report held 118.

The reading of gvmd's answers (get_results, get_reports, get_tasks and their 22.7 / 25 shapes) is the Sentinel's now (client/openvas.py, tested in the
Sentinel repo's client/tests/test_openvas.py and test_openvas_gmp.py). What stays here is what the server does with a report the Sentinel sends back: a
scanned host with nothing found is scanned, a report that names no scanned host is inconclusive and marks nothing scanned, a failed import is a failed
run, and what the activity feed says about a run."""
from django.test import TestCase

from cveFeed import openvas_scan as ov
from cveFeed.models import AgentActivity, OpenvasRun, ScanControl, ServiceRun
from startScan.models import Vulnerability
from tests.test_openvas import APACHE, OID_APACHE, Fixture


class Gvmd227FlowTests(Fixture, TestCase):
    """The whole sweep through a Sentinel's report."""

    def setUp(self):
        super().setUp()
        self.link.hosts, self.link.forced_hosts = ['www.rt.test'], ['www.rt.test']
        self.link.save()

    def test_a_finished_scan_imports_its_results_and_its_host(self):
        out = self.run_scan([APACHE, {**APACHE, 'oid': '1.3.6.1.4.1.25623.1.0.999', 'cves': [], 'qod': 80}])
        self.assertEqual((out['status'], out['results'], out['hosts_scanned'], out['findings']), ('done', 2, 1, 1))
        self.assertTrue(Vulnerability.objects.filter(template_id=f'openvas:{OID_APACHE}', open_status=True).exists())

    def test_a_scanned_host_with_nothing_found_is_scanned_not_inconclusive(self):
        self.run_scan([APACHE])
        out = self.run_scan([], scanned={'93.184.216.5'})  # the Sentinel's gvmd scanned www and found nothing (no result)
        self.assertEqual((out['hosts_scanned'], out['inconclusive']), (1, False))
        self.assertFalse(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)  # a complete scan no longer finds it
        self.assertTrue(ServiceRun.objects.filter(service=ov.SERVICE, asset='www.rt.test').exists())

    def test_an_inconclusive_run_marks_nothing_scanned_and_the_activity_says_so(self):
        self.make_sentinel()
        out = self.run_scan([], scanned=set())  # no result, no host in the report
        run = OpenvasRun.objects.get()
        self.assertTrue(out['inconclusive'])
        self.assertEqual(run.error, ov.INCONCLUSIVE)
        self.assertFalse(ServiceRun.objects.filter(service=ov.SERVICE).exists())
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='www.rt.test').exists())
        line = AgentActivity.objects.filter(detail__openvas_run=run.pk, message__contains=ov.INCONCLUSIVE).get()
        self.assertIn(f'OpenVAS run {run.pk} on www.rt.test (Sentinel task {run.sentinel_task_id})', line.message)
        self.assertIn('none is marked scanned', line.message)

    def test_a_failed_import_fails_the_run_and_asks_the_host_again_in_three_days(self):
        from unittest import mock
        self.make_sentinel()
        self.assertEqual(self.tick()['status'], 'running')
        task = OpenvasRun.objects.get().sentinel_task
        task.result, task.status = {'results': [], 'scanned_addresses': ['93.184.216.5']}, 'done'
        task.save(update_fields=['result', 'status'])
        with mock.patch.object(ov, '_apply_import', side_effect=RuntimeError('boom')):
            self.assertEqual(self.tick()['status'], 'failed')
        run = OpenvasRun.objects.get()
        self.assertIn('could not be imported (RuntimeError)', run.error)
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='www.rt.test').exists())

    def test_the_activity_names_the_run_its_hosts_and_task_and_settles_when_it_ends(self):
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        line = AgentActivity.objects.get(detail__openvas_run=run.pk, detail__progress_line=True)
        self.assertEqual((line.status, line.detail['hosts'], line.detail['sentinel_task']), ('running', ['www.rt.test'], run.sentinel_task_id))
        self.assertEqual(line.message, f'OpenVAS run {run.pk} on www.rt.test (Sentinel task {run.sentinel_task_id}): started')
        task = run.sentinel_task
        task.result, task.status = {'results': [], 'scanned_addresses': ['93.184.216.5']}, 'done'
        task.save(update_fields=['result', 'status'])
        self.tick()
        line.refresh_from_db()
        self.assertEqual(line.status, 'done')
        self.assertIn(': finished after', line.message)

    def test_a_paused_run_settles_its_progress_line(self):
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick()['status'], 'failed')
        line = AgentActivity.objects.get(detail__openvas_run=run.pk, detail__progress_line=True)
        self.assertEqual(line.status, 'failed')
        self.assertIn('failed after', line.message)
        self.assertIn('scanning is paused', line.message)
