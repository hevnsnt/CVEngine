"""The operations lifecycles (docs/STATE-MACHINES.md, "Operations"): the update approval and its phase, the scanner choice that rides with an
approval, AI jobs, and who owns the global pause. Each test is one bug that was fixed; the shell-script ones run the real scripts/apply-update.sh
against a throwaway origin with the stub `docker` of tests.test_apply_update_script (skipped where the scripts directory is not available)."""
import json
import os
import shutil
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.utils import timezone

from cveFeed import ai_jobs, scan_control, updater
from cveFeed import watchdog as wd
from cveFeed.models import AIJob, ScanControl, UpdateSettings
from dashboard.models import AuditLog
from reNgine import lifecycle
from reNgine.state_machines import AI_JOB
from tests import test_apply_update_script as harness
from tests.test_updater import NEW, OLD, fake_github

AHEAD = {'status': 'ahead', 'ahead_by': 1, 'commits': []}


class _UpdaterFiles(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        override = override_settings(BASE_DIR=self.dir, RENGINE_HOME=self.dir)
        override.enable()
        self.addCleanup(override.disable)
        self.admin = User.objects.create_superuser('root', 'r@x.test', 'x')

    def write(self, name, text):
        with open(os.path.join(self.dir, name), 'w') as f:
            f.write(text)

    def exists(self, name):
        return os.path.lexists(os.path.join(self.dir, name))

    def install(self, sha):
        self.write('.commit', sha + '\n')

    def phase(self, phase, detail='', at=None):
        self.write('.update-phase.json', json.dumps({'phase': phase, 'detail': detail, 'scans_running': None,
                                                      'changed_at': time.time() if at is None else at}))

    def heartbeat(self):
        self.write('.updater-heartbeat', json.dumps({'at': time.time()}))

    def approved_row(self):
        """An approval of NEW, as Settings > Updates leaves it, on a server with the host updater installed."""
        self.install(OLD)
        self.heartbeat()
        row = updater.check(get=fake_github(compare=AHEAD))
        updater.approve(row, self.admin)
        self.assertEqual(row.approved_sha, NEW)
        return row


class ApprovalTests(_UpdaterFiles):
    """a) web/.commit is written when a deploy STARTS, so it alone does not say the deploy finished."""

    def test_a_deploy_that_failed_after_writing_the_commit_keeps_the_approval_for_the_retry(self):
        row = self.approved_row()
        self.install(NEW)  # the deploy started (scripts/update-deploy.sh writes .commit first) ...
        self.phase('failed', 'The update did not finish: restarting after the migration failed (run 1 of 3). The maintenance page stays up')
        updater.sync_applied(row)  # ... and then the restart failed; the host keeps the approval and retries
        row.refresh_from_db()
        self.assertEqual(row.approved_sha, NEW)
        self.assertTrue(self.exists('.update-approved'))
        self.assertFalse(AuditLog.objects.filter(action='update.applied').exists())
        self.phase('applying', 'migrated')  # still running: not finished either
        updater.sync_applied(row)
        self.assertTrue(self.exists('.update-approved'))

    def test_a_finished_deploy_clears_the_approval_and_says_so_in_the_audit_log(self):
        row = self.approved_row()
        self.install(NEW)
        self.phase('done', at=time.time() - 3600)  # a "done" from before this approval is the last update's, not this one's
        updater.sync_applied(row)
        self.assertTrue(self.exists('.update-approved'))
        self.phase('done')
        updater.sync_applied(row)
        row.refresh_from_db()
        self.assertEqual(row.approved_sha, '')
        self.assertFalse(self.exists('.update-approved'))
        entry = AuditLog.objects.get(action='update.applied')
        self.assertEqual((entry.actor_name, entry.target), ('updater', NEW[:7]))

    def test_a_server_without_the_host_updater_is_still_cleared_by_the_installed_commit(self):
        self.install(OLD)
        row = updater.check(get=fake_github(compare=AHEAD))
        updater.approve(row, self.admin)
        self.install(NEW)  # deployed by hand (make up): nothing on the host reports a phase
        updater.sync_applied(row)
        self.assertEqual(row.approved_sha, '')
        self.assertTrue(AuditLog.objects.filter(action='update.applied').exists())


class LastAttemptTests(_UpdaterFiles):
    """b) Once the approval is gone, a failed phase is the last attempt, not a retry that is pending."""

    KEPT = ("this install's Compose layout is unclear or unusable; the update log says what to set (CVENGINE_COMPOSE_FILES in .env). "
            'The approval is kept and retries by itself')

    def test_a_failure_whose_approval_was_cancelled_is_shown_as_the_last_attempt(self):
        from agentapi.system_status import _update
        row = self.approved_row()
        self.phase('failed', self.KEPT)
        state = updater.state(row)
        self.assertEqual((state['phase'], state['phase_last_attempt']), ('failed', False))
        self.assertIn('retries by itself', state['phase_detail'])  # true while the approval is there
        updater.cancel_approval(row)
        for detail, last in ((updater.state(row)['phase_detail'], updater.state(row)['phase_last_attempt']),
                             (_update()['detail'], _update()['last_attempt'])):
            self.assertTrue(last)
            self.assertNotIn('retries by itself', detail)
            self.assertTrue(detail.startswith('Last attempt ('), detail)
            self.assertIn('Compose layout is unclear', detail)
        self.assertEqual(updater.state(row)['phase'], 'failed')  # still the result of the last update

    def test_a_drain_whose_approval_is_gone_is_not_shown_as_in_progress(self):
        row = self.approved_row()
        self.phase('draining', 'the host could not reach origin/master; it keeps retrying (see the update log)')
        self.assertEqual(updater.state(row)['phase'], 'draining')
        updater.cancel_approval(row)
        state = updater.state(row)
        self.assertEqual((state['phase'], state['phase_detail'], state['phase_last_attempt']), ('idle', '', True))

    def test_a_factory_reset_removing_the_approval_file_is_enough(self):
        from agentapi.system_status import _update
        self.phase('failed', 'the host checkout has local changes to tracked files (x); commit or stash them, the update then retries by itself')
        self.write('.update-approved', NEW + '\n')
        self.assertFalse(_update()['last_attempt'])
        updater._remove_flag()  # what cveFeed.factory_reset does
        out = _update()
        self.assertTrue(out['last_attempt'])
        self.assertNotIn('retries by itself', out['detail'])


@unittest.skipUnless(harness.SCRIPTS.joinpath('apply-update.sh').is_file() and shutil.which('git') and shutil.which('flock'),
                     'needs the repository scripts directory, git and flock')
class ApplyUpdateApprovalTests(unittest.TestCase):
    """c) and d), with the real scripts/apply-update.sh (the fixture of tests.test_apply_update_script, without its tests)."""

    _fixture = harness.ApplyUpdateScriptTests  # referenced through the module, so this module does not run its tests again
    setUp, git, approve, run_script, head, approved, publish_deploy_file = (
        _fixture.setUp, _fixture.git, _fixture.approve, _fixture.run_script, _fixture.head, _fixture.approved, _fixture.publish_deploy_file)

    def log(self):
        return (self.work / 'web' / '.update-log').read_text()

    def test_an_approval_of_a_newer_commit_made_during_the_deploy_is_kept(self):
        newer = 'c' * 40
        # the stub docker: while the build runs, an administrator approves a newer commit (as Settings > Updates writes it)
        real = self.stub / 'docker-real'
        (self.stub / 'docker').rename(real)
        (self.stub / 'docker').write_text('#!/usr/bin/env bash\n'
                                          'if [[ " $* " == *" build "* ]]; then printf "%s\\n" ' + newer + ' > web/.update-approved;'
                                          ' printf "master\\n" > web/.update-branch; printf "both\\n" > web/.update-sentinels; fi\n'
                                          f'exec {real} "$@"\n')
        (self.stub / 'docker').chmod(0o755)
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)
        self.assertEqual((self.work / 'web' / '.update-approved').read_text().strip(), newer)  # the next run applies it
        self.assertTrue((self.work / 'web' / '.update-branch').exists())
        self.assertEqual((self.work / 'web' / '.update-sentinels').read_text().strip(), 'both')
        self.assertIn('a newer approval', self.log())

    def test_the_approval_this_run_applied_is_still_removed(self):
        self.approve()
        (self.work / 'web' / '.update-branch').write_text('master\n')
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.approved())
        self.assertFalse((self.work / 'web' / '.update-branch').exists())

    def test_the_scanner_choice_survives_a_wait_and_reaches_the_deploy(self):
        other = self.tmp / 'other'
        (other / 'scripts').mkdir(exist_ok=True)
        shutil.copy(harness.SCRIPTS / 'host-fit.sh', other / 'scripts' / 'host-fit.sh')
        self.new = self.publish_deploy_file()  # carries scripts/update-deploy.sh and scripts/update-disk.sh: its disk check used to take the choice
        self.approve()
        (self.work / 'web' / '.update-sentinels').write_text('both\n')
        (self.stub / 'running_count').write_text('1\n')
        self.assertEqual(self.run_script().returncode, 3)  # work on this server is settling: the run waits ...
        self.assertTrue((self.work / 'web' / '.update-sentinels').exists())  # ... and keeps the choice
        (self.stub / 'running_count').write_text('0\n')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)
        log = self.log()
        # cvengine_fit_run got the answer (it then writes it to .env with scripts/init-env.sh, which this checkout does not carry)
        self.assertTrue('Which scanners run' in log or 'could not write the scanner choice to .env' in log, log[-3000:])
        self.assertFalse((self.work / 'web' / '.update-sentinels').exists())  # used: it goes with the approval
        self.assertFalse(self.approved())


class AIJobTests(TestCase):
    """e) A job lost while applying tells its stage, and a late continuation does not overwrite the loss."""

    def job(self, status, **fields):
        return AIJob.objects.create(kind='autotune_advice', status=status, context={'x': 1}, **fields)

    def test_the_table_is_registered_with_the_moves_the_queue_makes(self):
        self.assertIs(lifecycle.REGISTRY['ai_job'], AI_JOB)
        self.assertEqual(set(AI_JOB.states), {'queued', 'leased', 'answered', 'applying', 'applied', 'failed', 'expired'})
        for final in ('applied', 'failed', 'expired'):
            self.assertTrue(AI_JOB.is_final(final))
        self.assertFalse(AI_JOB.allowed('failed', 'applied'))

    def test_a_job_lost_while_applying_tells_its_stage(self):
        job = self.job('applying')
        AIJob.objects.filter(pk=job.pk).update(updated_at=timezone.now() - ai_jobs.APPLY_STUCK - timedelta(minutes=1))
        stage = mock.Mock()
        with mock.patch.object(ai_jobs, '_handler', return_value=stage):
            self.assertEqual(ai_jobs.housekeeping()['stuck'], 1)
        job.refresh_from_db()
        self.assertEqual((job.status, job.error_category), ('failed', 'apply_lost'))
        stage.job_failure.assert_called_once()
        self.assertEqual(stage.job_failure.call_args[0][0].pk, job.pk)
        self.assertEqual(stage.job_failure.call_args[0][1], 'apply_lost')

    def test_a_continuation_that_ends_after_the_job_was_given_up_does_not_overwrite_it(self):
        job = self.job('answered', result={'text': 'the answer'}, packet={'options': {'redact_reply': False}})

        def slow_answer(j, text):  # meanwhile the housekeeping pass gave the job up as lost
            AIJob.objects.filter(pk=j.pk).update(status='failed', error_category='apply_lost', finished_at=timezone.now())
            return None
        stage = mock.Mock()
        stage.job_answer.side_effect = slow_answer
        with mock.patch.object(ai_jobs, '_handler', return_value=stage):
            self.assertEqual(ai_jobs.apply(job.pk), 'lost')
        job.refresh_from_db()
        self.assertEqual((job.status, job.error_category), ('failed', 'apply_lost'))

    def test_an_answer_is_still_applied(self):
        job = self.job('answered', result={'text': 'the answer'}, packet={'options': {'redact_reply': False}})
        stage = mock.Mock()
        stage.job_answer.return_value = None
        with mock.patch.object(ai_jobs, '_handler', return_value=stage):
            self.assertEqual(ai_jobs.apply(job.pk), 'applied')
        job.refresh_from_db()
        self.assertEqual((job.status, job.result, job.packet), ('applied', {}, {}))


class PauseOwnerTests(TestCase):
    """f) The watchdog's pressure pause is its own: no update window, no held leases, and each release lifts only its own pause."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        override = override_settings(BASE_DIR=self.dir, RENGINE_HOME=self.dir)
        override.enable()
        self.addCleanup(override.disable)

    def ctx(self, **data):
        return SimpleNamespace(states={'R7': SimpleNamespace(data=dict(data))}, now=timezone.now())

    def pressure_pause(self):
        with mock.patch.object(scan_control, 'hold_sentinel_leases') as hold:
            wd.act_pressure(self.ctx(), wd.Check(True, 'memory is over 90 percent', {'memory': True}))
        return hold

    def test_the_reason_marks_the_owner_the_same_way_in_both_modules(self):
        self.assertEqual(scan_control.WATCHDOG_PAUSE_REASON, wd.PAUSE_REASON)

    def test_a_memory_pause_opens_no_update_window_and_holds_no_lease(self):
        from agentapi.system_status import _scanning
        hold = self.pressure_pause()
        row = ScanControl.objects.get(pk=1)
        self.assertTrue(row.paused)
        self.assertTrue(row.paused_by_update)  # a drain pause: running work carries on (operator_pause_requested stays False)
        self.assertFalse(scan_control.operator_pause_requested())
        self.assertIsNone(row.update_started_at)
        self.assertFalse(scan_control.in_update_grace())  # Sentinel tasks still expire as usual
        hold.assert_not_called()
        self.assertEqual(scan_control.pause_owner(row), 'watchdog')
        self.assertFalse(updater.state(UpdateSettings.current())['scans_paused_by_update'])
        status = _scanning()
        self.assertEqual((status['paused'], status['paused_by_update'], status['paused_by']), (True, False, 'watchdog'))

    def test_the_updaters_release_leaves_the_watchdogs_pause(self):
        self.pressure_pause()
        scan_control.release_update_pause()  # apply-update.sh --release, at the end of an update
        self.assertTrue(ScanControl.objects.get(pk=1).paused)
        self.assertEqual(wd.release_pressure_pause(self.ctx(paused_at='x')), 'resumed the automatic starting of work')
        self.assertFalse(ScanControl.objects.get(pk=1).paused)

    def test_the_watchdogs_release_leaves_an_update_pause(self):
        scan_control.request_drain_pause()
        self.assertTrue(updater.state(UpdateSettings.current())['scans_paused_by_update'])
        self.assertIsNone(wd.release_pressure_pause(self.ctx(paused_at='x')))
        row = ScanControl.objects.get(pk=1)
        self.assertTrue(row.paused)
        self.assertIsNotNone(row.update_started_at)
        self.assertIsNone(row.update_ended_at)  # the update's window stays open until the update ends it
