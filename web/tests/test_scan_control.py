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
from cveFeed.scan_control import PauseAwareScheduler, PauseAwareTask, updater_idle
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
        from reNgine.celery_custom_task import RengineTask
        self.assertIsInstance(weekly_deep_nuclei._get_current_object(), PauseAwareTask)
        self.assertTrue(issubclass(RengineTask, PauseAwareTask))
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        sentinel = RuntimeError('deferred')
        with mock.patch.object(weekly_deep_nuclei._get_current_object(), 'retry', side_effect=sentinel) as retry:
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
