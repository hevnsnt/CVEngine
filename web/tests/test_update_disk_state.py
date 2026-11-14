"""The Update screen's disk state: the host measures where Docker keeps its data (scripts/update-disk.sh, published as .update-disk.json), the app says
so in plain words and keeps Approve off when there is not room, and the closing of ghost scans (cveFeed.ghost_scans)."""
import json
import os
import tempfile
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.utils import timezone

from cveFeed import ghost_scans, updater
from cveFeed.models import UpdateSettings
from tests.test_tenancy import client_for
from tests.test_updater import OLD, fake_github

SENTENCE = 'This update needs about 14 GB of free disk; this server has 9 GB free. Free some space or add disk, then try again.'


class DiskStateTests(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        override = override_settings(BASE_DIR=self.dir)
        override.enable()
        self.addCleanup(override.disable)
        self.admin = User.objects.create_superuser('root', 'r@x.test', 'x')
        with open(os.path.join(self.dir, '.commit'), 'w') as f:
            f.write(OLD + '\n')

    def disk_file(self, free, need, age=0, raw=None):
        with open(os.path.join(self.dir, '.update-disk.json'), 'w') as f:
            f.write(raw if raw is not None else json.dumps({'free_mb': free, 'need_mb': need, 'at': time.time() - age}))

    def available(self):
        return updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))

    def test_no_measurement_blocks_nothing(self):
        self.assertEqual(updater.disk(), {'known': False, 'short': False, 'free_mb': None, 'need_mb': None, 'text': ''})
        self.assertFalse(updater.state(self.available())['disk']['short'])

    def test_not_enough_room_says_the_sentence(self):
        self.disk_file(9500, 14000)
        room = updater.disk()
        self.assertTrue(room['known'] and room['short'])
        self.assertEqual(room['text'], SENTENCE)
        self.assertEqual(updater.state(self.available())['disk']['text'], SENTENCE)

    def test_enough_room_and_odd_files(self):
        self.disk_file(14000, 14000)  # exactly enough
        self.assertEqual((updater.disk()['known'], updater.disk()['short']), (True, False))
        for raw in ('', '[]', '{"free_mb": "lots", "need_mb": 1, "at": 1}', '{"free_mb": -5, "need_mb": 14000, "at": %s}' % time.time(), 'nan'):
            self.disk_file(0, 0, raw=raw)
            self.assertFalse(updater.disk()['known'], raw)

    def test_a_host_that_stopped_measuring_is_not_believed(self):
        self.disk_file(1000, 14000, age=updater.DISK_STALE_SECONDS + 60)
        self.assertFalse(updater.disk()['known'])
        self.assertFalse(updater.disk()['short'])

    def test_approve_is_refused_with_the_same_sentence_and_writes_nothing(self):
        self.disk_file(9500, 14000)
        admin = client_for(self.admin)
        self.available()
        shown = admin.get('/cve/api/settings/updates').json()
        self.assertEqual((shown['status'], shown['disk']['short'], shown['disk']['text']), ('available', True, SENTENCE))
        done = admin.post('/cve/api/settings/updates/approve', '{}', content_type='application/json')
        self.assertEqual(done.status_code, 400)
        self.assertIn(SENTENCE, done.content.decode())
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))
        self.assertEqual(UpdateSettings.current().approved_sha, '')

    def test_approve_works_once_there_is_room(self):
        self.disk_file(9500, 14000)
        admin = client_for(self.admin)
        self.available()
        self.assertEqual(admin.post('/cve/api/settings/updates/approve', '{}', content_type='application/json').status_code, 400)
        self.disk_file(20000, 14000)
        done = admin.post('/cve/api/settings/updates/approve', '{}', content_type='application/json')
        self.assertEqual((done.status_code, done.json()['status']), (200, 'approved'))
        self.assertTrue(os.path.exists(os.path.join(self.dir, '.update-approved')))

    def test_automatic_mode_does_not_approve_into_a_full_disk(self):
        updater.set_mode('auto')
        self.disk_file(9500, 14000)
        row = self.available()
        self.assertFalse(updater.auto_approve(row))
        self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))
        self.disk_file(20000, 14000)
        self.assertTrue(updater.auto_approve(row))

    def test_the_screen_script_disables_the_button_and_says_why(self):
        """The page's code (settings.js) shows the sentence and turns Approve off when disk.short; the rendered text is checked in a browser
        by tests/ui/update-disk.check.js."""
        from pathlib import Path
        source = (Path(__file__).resolve().parents[1] / 'static' / 'cve' / 'settings.js').read_text()
        self.assertIn('s.disk && s.disk.short', source)
        self.assertIn('approveButton.disabled = true', source)
        self.assertIn('s.disk.text', source)


class GhostScanTests(TestCase):
    def setUp(self):
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='example.test')
        self.engine = EngineType.objects.create(engine_name='test engine', yaml_configuration='{}')

    def make(self, **fields):
        from startScan.models import ScanHistory
        return ScanHistory.objects.create(scan_status=1, domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now() - timedelta(minutes=30), **fields)

    def activity(self, scan, minutes_ago):
        from startScan.models import ScanActivity
        return ScanActivity.objects.create(scan_of=scan, title='t', name='n', time=timezone.now() - timedelta(minutes=minutes_ago), status=1)

    def test_a_scan_with_no_worker_and_no_activity_is_a_ghost(self):
        ghost = self.make(celery_ids=['gone'])
        closed = ghost_scans.close(live=set())
        ghost.refresh_from_db()
        self.assertEqual(closed, [ghost.pk])
        self.assertEqual((ghost.scan_status, ghost.error_message), (0, 'interrupted by an update'))
        self.assertIsNotNone(ghost.stop_scan_date)

    def test_a_scan_a_worker_holds_is_never_marked(self):
        held = self.make(celery_ids=['alive'])
        self.assertEqual(ghost_scans.close(live={'alive'}), [])
        held.refresh_from_db()
        self.assertEqual(held.scan_status, 1)

    def test_a_scan_that_shows_progress_keeps_the_wait(self):
        busy = self.make(celery_ids=[])
        self.activity(busy, 1)
        old = self.make(celery_ids=[])
        self.activity(old, 20)
        self.assertEqual(ghost_scans.close(live=set()), [old.pk])
        busy.refresh_from_db()
        self.assertEqual(busy.scan_status, 1)

    def test_a_young_scan_is_not_judged(self):
        from startScan.models import ScanHistory
        young = ScanHistory.objects.create(scan_status=1, domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now() - timedelta(minutes=2), celery_ids=[])
        self.assertEqual(ghost_scans.close(live=set()), [])
        young.refresh_from_db()
        self.assertEqual(young.scan_status, 1)

    def test_nothing_is_closed_when_the_workers_cannot_be_asked(self):
        scan = self.make(celery_ids=[])
        with mock.patch('cveFeed.broker_recovery.live_task_ids', return_value=None):
            self.assertEqual(ghost_scans.close(), [])
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, 1)

    def test_a_scan_waiting_on_sentinels_is_left_alone(self):
        scan = self.make(celery_ids=[])
        with mock.patch('agentapi.stage_runs.open_scan_ids', return_value={scan.pk}):
            self.assertEqual(ghost_scans.close(live=set()), [])

    def test_the_command_prints_what_it_closed(self):
        from io import StringIO
        from django.core.management import call_command
        ghost = self.make(celery_ids=[])
        out = StringIO()
        with mock.patch('cveFeed.broker_recovery.live_task_ids', return_value=set()):
            call_command('update_ghost_scans', stdout=out)
        self.assertIn(f'closed scan {ghost.pk}: interrupted by an update', out.getvalue())
        self.assertIn('ghosts 1', out.getvalue())
