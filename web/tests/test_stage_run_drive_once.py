"""One pending delayed drive per waiting stage run (agentapi.stage_runs._schedule_drive)."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase
from django.utils import timezone

from agentapi import stage_runs
from cveFeed import tasks


class DriveOnceTests(SimpleTestCase):
    def setUp(self):
        cache.delete(stage_runs.drive_key(7))
        self.sent = mock.patch.object(tasks.stage_run_drive, 'apply_async').start()
        mock.patch.object(stage_runs, '_on_commit', lambda fn: fn()).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(cache.delete, stage_runs.drive_key(7))

    def later(self):
        return timezone.now() + timedelta(seconds=40)

    def test_the_second_call_for_a_run_with_a_drive_pending_sends_nothing(self):
        stage_runs._schedule_drive(7, self.later())
        stage_runs._schedule_drive(7, self.later())
        stage_runs._schedule_drive(7, self.later())
        self.assertEqual(self.sent.call_count, 1)
        self.assertEqual(self.sent.call_args.kwargs['kwargs'], {'guarded': True})

    def test_the_drive_that_runs_frees_the_next_one_to_be_scheduled(self):
        stage_runs._schedule_drive(7, self.later())
        with mock.patch.object(stage_runs, 'drive', return_value={}):
            tasks.stage_run_drive.run(7, guarded=True)
        stage_runs._schedule_drive(7, self.later())  # what drive itself does at its end
        self.assertEqual(self.sent.call_count, 2)

    def test_a_wake_up_is_always_sent_and_does_not_disturb_the_pending_drive(self):
        stage_runs._schedule_drive(7, self.later())
        stage_runs._schedule_drive(7, timezone.now())  # a scan was stopped
        self.assertEqual(self.sent.call_count, 2)
        self.assertEqual(self.sent.call_args.kwargs['kwargs'], {'guarded': False})
        with mock.patch.object(stage_runs, 'drive', return_value={}):
            tasks.stage_run_drive.run(7, guarded=False)  # the wake-up ran: the pending delayed drive is still guarded
        stage_runs._schedule_drive(7, self.later())
        self.assertEqual(self.sent.call_count, 2)

    def test_runs_are_independent(self):
        stage_runs._schedule_drive(7, self.later())
        stage_runs._schedule_drive(8, self.later())
        self.assertEqual(self.sent.call_count, 2)
        cache.delete(stage_runs.drive_key(8))
