import fcntl
import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed.models import ScanControl
from cveFeed.scan_control import PauseAwareScheduler, PauseAwareTask, release_update_pause, request_drain_pause, updater_idle
from dashboard.models import Org, OrgMembership, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain
from tests.test_admin import api
from tests.test_tenancy import client_for


class ScanControlTests(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser('stop-root', 'stop@example.test', 'pw')
        self.admin = User.objects.create_user('stop-org', password='pw')
        org = Org.objects.create(name='Stop Org', slug='stop-org')
        OrgMembership.objects.create(user=self.admin, org=org, role='admin')
        project = Project.objects.create(name='Stop Project', slug='stop-project', org=org, insert_date=timezone.now())
        domain = Domain.objects.create(name='stop.example.test', project=project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='stop-engine', yaml_configuration='x')
        self.running = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
        self.queued = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=-1, start_scan_date=timezone.now())

    def test_global_pause_requires_app_admin_and_explicit_confirmation(self):
        self.assertEqual(api(client_for(self.admin), 'GET', 'scan-control')[0], 403)
        self.assertEqual(api(client_for(self.admin), 'POST', 'scan-control',
                             {'action': 'pause', 'confirm': 'Pause all scanning'})[0], 403)
        self.assertEqual(api(client_for(self.root), 'POST', 'scan-control', {'action': 'pause'})[0], 400)
        self.assertFalse(ScanControl.current().paused)
        self.assertNotContains(client_for(self.admin).get('/cve/_all/activity/'), 'data-app-admin="1"')
        self.assertContains(client_for(self.root).get('/cve/_all/activity/'), 'data-app-admin="1"')

    @mock.patch('reNgine.resources.request_abort')
    @mock.patch('reNgine.celery.app.control.inspect')
    def test_pause_aborts_active_scan_but_keeps_queued_scan_and_is_idempotent(self, inspect, abort):
        inspect.return_value.active.return_value = {'worker@local': []}
        root = client_for(self.root)
        body = {'action': 'pause', 'confirm': 'Pause all scanning'}
        code, result = api(root, 'POST', 'scan-control', body)
        self.assertEqual((code, result['paused']), (200, True))
        self.assertEqual(result['state'], 'paused')
        self.running.refresh_from_db()
        self.queued.refresh_from_db()
        self.assertEqual((self.running.scan_status, self.queued.scan_status), (3, -1))
        abort.assert_called_once_with(self.running.pk)
        self.assertEqual(api(root, 'POST', 'scan-control', body)[0], 200)
        self.assertEqual(ScanControl.objects.count(), 1)
        code, result = api(root, 'POST', 'scan-control', {'action': 'resume', 'confirm': 'Resume scanning'})
        self.assertEqual((code, result['state']), (200, 'running'))
        self.queued.refresh_from_db()
        self.assertEqual(self.queued.scan_status, -1)

    @mock.patch('reNgine.resources.request_abort')
    @mock.patch('reNgine.celery.app.control.inspect')
    def test_failed_stop_is_visible_and_pause_stays_active(self, inspect, abort):
        abort.side_effect = RuntimeError('private failure details')
        inspect.return_value.active.return_value = None
        code, result = api(client_for(self.root), 'POST', 'scan-control',
                           {'action': 'pause', 'confirm': 'Pause all scanning'})
        self.assertEqual((code, result['state']), (200, 'error'))
        self.assertTrue(ScanControl.current().paused)
        self.assertNotIn('private failure details', str(result))

    def test_worker_gate_retries_without_executing_and_scheduler_holds_due_entry(self):
        from cveFeed.tasks import weekly_deep_nuclei
        self.assertIsInstance(weekly_deep_nuclei._get_current_object(), PauseAwareTask)
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        sentinel = RuntimeError('deferred')
        task = weekly_deep_nuclei._get_current_object()
        task.push_request(called_directly=False)  # what a worker does when it runs a queued message
        self.addCleanup(task.pop_request)
        with mock.patch.object(task, 'retry', side_effect=sentinel) as retry:
            with self.assertRaisesRegex(RuntimeError, 'deferred'):
                weekly_deep_nuclei()
        retry.assert_called_once_with(countdown=60, max_retries=None)
        scheduler = object.__new__(PauseAwareScheduler)
        with mock.patch('django_celery_beat.schedulers.DatabaseScheduler.is_due') as base:
            self.assertEqual(scheduler.is_due(object()), (False, 5))
            base.assert_not_called()
        root = Path(__file__).resolve().parents[2]
        for compose in ('docker-compose.yml', 'docker-compose.dev.yml'):
            self.assertIn('--scheduler cveFeed.scan_control:PauseAwareScheduler', (root / compose).read_text())

    def test_a_direct_call_of_a_gated_task_runs_in_line_instead_of_raising_retry(self):
        # an in-process caller (the CVE-correlation scan stage, manage.py correlate_cves, the legacy API views) is not a queued message
        from celery.exceptions import Retry
        from cveFeed.tasks import weekly_deep_nuclei
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        task = weekly_deep_nuclei._get_current_object()
        with mock.patch.object(task, 'run', return_value='ran') as run:
            try:
                self.assertEqual(task(), 'ran')
            except Retry:
                self.fail('a direct call raised Retry')
        run.assert_called_once()

    def test_maintenance_that_never_touches_a_target_keeps_running_during_a_pause(self):
        from cveFeed import scan_control
        from cveFeed.tasks import prune_asset_changes, sync_cve_now_feed
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        for task in (sync_cve_now_feed, prune_asset_changes):
            with mock.patch.object(task._get_current_object(), 'retry', side_effect=AssertionError('deferred')):
                scan_control.defer_if_paused(task._get_current_object())  # no retry: it runs
        scheduler = object.__new__(PauseAwareScheduler)
        entry = mock.Mock(task='sync_cve_now_feed')
        with mock.patch('django_celery_beat.schedulers.DatabaseScheduler.is_due', return_value=(True, 60)):
            self.assertEqual(scheduler.is_due(entry), (True, 60))
            self.assertEqual(scheduler.is_due(mock.Mock(task='validate_sweep')), (False, 5))
        known = {name for name in app_task_names()}
        self.assertFalse(scan_control.PAUSE_EXEMPT_TASKS - known - {'weekly_maintenance'}, 'an exempt name matches no task')
        for scanner in ('assess_host', 'host_pipeline', 'validate_match_on_demand', 'automatic_validate_finding', 'triage_sweep',
                        'template_test_for_cve', 'weekly_deep_nuclei', 'background_full_scan', 'nuclei_scan'):
            self.assertNotIn(scanner, scan_control.PAUSE_EXEMPT_TASKS)

    def test_the_openvas_step_is_exempt_so_a_pause_can_stop_its_running_task(self):
        from cveFeed import scan_control
        self.assertIn('openvas_sweep', scan_control.PAUSE_EXEMPT_TASKS)
        scheduler = object.__new__(PauseAwareScheduler)
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        with mock.patch('django_celery_beat.schedulers.DatabaseScheduler.is_due', return_value=(True, 60)):
            self.assertEqual(scheduler.is_due(mock.Mock(task='openvas_sweep')), (True, 60))

    def test_only_an_operator_pause_counts_as_a_stop_request(self):
        from cveFeed import scan_control
        self.assertFalse(scan_control.operator_pause_requested())
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True})
        self.assertFalse(scan_control.operator_pause_requested())  # an update's drain lets running work finish
        ScanControl.objects.filter(pk=1).update(paused_by_update=False)
        self.assertTrue(scan_control.operator_pause_requested())
        with mock.patch('cveFeed.models.ScanControl.objects.filter', side_effect=RuntimeError('db down')):
            self.assertFalse(scan_control.operator_pause_requested())

    def test_an_unreadable_control_database_gates_new_work_but_kills_nothing_running(self):
        from cveFeed import scan_control
        from reNgine import resources
        with mock.patch('cveFeed.models.ScanControl.objects.filter', side_effect=RuntimeError('db down')):
            self.assertTrue(scan_control.pause_requested())
            self.assertFalse(resources.global_pause_requested())
            self.assertTrue(resources.global_pause_requested(fail_closed=True))

    def test_resume_respects_updater_lock(self):
        from django.conf import settings
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(settings, 'RENGINE_HOME', directory):
            path = os.path.join(directory, '.update-lock')
            with open(path, 'w') as hold:
                fcntl.flock(hold, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(RuntimeError, 'update is running'):
                    with updater_idle():
                        pass
                fcntl.flock(hold, fcntl.LOCK_UN)
            with updater_idle():
                pass

    def test_request_drain_pause_pauses_scanning_and_marks_it_as_an_update_pause(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            request_drain_pause(reason='An update is being applied')
        control = ScanControl.current()
        self.assertEqual((control.paused, control.paused_by_update, control.reason), (True, True, 'An update is being applied'))

    def test_request_drain_pause_never_overrides_an_operators_own_pause(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': False, 'reason': 'manual hold'})
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            request_drain_pause(reason='An update is being applied')
        control = ScanControl.current()
        self.assertEqual((control.paused, control.paused_by_update, control.reason), (True, False, 'manual hold'))

    def test_release_update_pause_only_clears_a_pause_it_set(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': False, 'reason': 'manual hold'})
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            release_update_pause()
        control = ScanControl.current()
        self.assertEqual((control.paused, control.paused_by_update, control.reason), (True, False, 'manual hold'))
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True, 'reason': 'An update is being applied'})
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            release_update_pause()
        control = ScanControl.current()
        self.assertEqual((control.paused, control.paused_by_update, control.reason), (False, False, ''))

    def test_drain_pause_and_release_respect_the_updater_lock(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            path = os.path.join(directory, '.update-lock')
            with open(path, 'w') as hold:
                fcntl.flock(hold, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(RuntimeError, 'update is running'):
                    request_drain_pause()
                with self.assertRaisesRegex(RuntimeError, 'update is running'):
                    release_update_pause()
                fcntl.flock(hold, fcntl.LOCK_UN)

    def test_legacy_process_monitor_stops_process_group_on_global_pause(self):
        from reNgine.resources import LegacyProcessMonitor
        proc = subprocess.Popen(['sleep', '10'], start_new_session=True)
        try:
            with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
                monitor = LegacyProcessMonitor(proc)
                deadline = time.monotonic() + 4
                while proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                monitor.close()
            self.assertIsNotNone(proc.poll())
            self.assertTrue(monitor.aborted)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

    def test_modern_heavy_job_stops_even_without_a_scan_id(self):
        from reNgine import resources
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        store = mock.Mock()
        job = resources.Job('nuclei', 100, 'fixture', store,
                            lambda: {'total_mb': 4000, 'available_mb': 3000, 'used_mb': 1000, 'limit_mb': 4000}, time.time)
        proc = mock.Mock()
        proc.poll.return_value = None
        job.proc = proc
        with mock.patch.object(job, 'rss_mb', return_value=0), mock.patch.object(resources, 'terminate_group') as terminate:
            self.assertTrue(job.check_once())
        self.assertTrue(job.aborted)
        terminate.assert_called_once_with(proc, grace=5)


def app_task_names():
    from reNgine.celery import app
    import cveFeed.tasks, reNgine.tasks  # noqa: F401,E401 - registers every task
    return set(app.tasks)


class OperatorPauseVersusUpdatePauseTests(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser('opv-root', 'opv@example.test', 'pw')
        self.client_root = client_for(self.root)
        self.pause = {'action': 'pause', 'confirm': 'Pause all scanning'}
        self.resume = {'action': 'resume', 'confirm': 'Resume scanning'}

    def test_an_operator_pause_during_an_update_pause_becomes_the_operators_own(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True, 'reason': 'An update is being applied'})
        self.assertEqual(api(self.client_root, 'POST', 'scan-control', self.pause)[0], 200)
        control = ScanControl.current()
        self.assertEqual((control.paused, control.paused_by_update), (True, False))
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            release_update_pause()  # the finishing update must not lift the operator's hold
        self.assertTrue(ScanControl.current().paused)

    def test_an_operator_resume_clears_the_update_flag_too(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True, 'reason': 'x'})
        with tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            self.assertEqual(api(self.client_root, 'POST', 'scan-control', self.resume)[0], 200)
        control = ScanControl.current()
        self.assertEqual((control.paused, control.paused_by_update), (False, False))

    def test_resume_is_refused_while_the_update_script_is_draining_or_applying(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True, 'reason': 'x'})
        phase = {'phase': 'applying', 'detail': '', 'scans_running': 0,
                 'changed_at': timezone.now().isoformat()}
        with mock.patch('cveFeed.updater.read_phase', return_value=phase):
            self.assertEqual(api(self.client_root, 'POST', 'scan-control', self.resume)[0], 409)
        self.assertTrue(ScanControl.current().paused)
        phase['changed_at'] = (timezone.now() - timezone.timedelta(hours=5)).isoformat()  # a script that died long ago
        with mock.patch('cveFeed.updater.read_phase', return_value=phase), \
                tempfile.TemporaryDirectory() as directory, mock.patch('django.conf.settings.RENGINE_HOME', directory):
            self.assertEqual(api(self.client_root, 'POST', 'scan-control', self.resume)[0], 200)
