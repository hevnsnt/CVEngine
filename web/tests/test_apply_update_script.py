"""scripts/apply-update.sh against a throwaway git origin with stub `docker` and `make`, so the real script runs
without touching Docker. Skipped where the scripts directory is not available (inside the web container only
./web is mounted); run it on the host: ``cd web && python3 -m unittest tests.test_apply_update_script``."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'

DOCKER_STUB = """#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls.log"
# the updater is killed (SIGKILL, as a reboot or the OOM killer would) at the first call that matches: it is the shell running the update
if [ -n "${STUB_KILL_ON:-}" ] && [[ " $* " == *"$STUB_KILL_ON"* ]] && [ ! -f "$STUB_DIR/killed" ]; then touch "$STUB_DIR/killed"; kill -KILL $PPID; exit 137; fi
case " $* " in
  *" migrate --check "*) if [ -f "$STUB_DIR/unmigrated_once" ]; then rm -f "$STUB_DIR/unmigrated_once"; exit 1; fi
    if [ -f "$STUB_DIR/unmigrated" ]; then exit 1; fi; exit 0;;
  *" info "*) echo "$STUB_DIR";;
  *"http.client"*) if [ -f "$STUB_DIR/web_not_serving" ]; then exit 1; fi; exit 0;;
  *" exec "*) if [ -f "$STUB_DIR/web_down" ]; then exit 1; fi
    echo "banner line"; cat "$STUB_DIR/running_count" 2>/dev/null || echo 0; exit 0;;
  *" ps -a --filter "*) if [ -f "$STUB_DIR/running_config_files" ]; then echo abc123; fi; exit 0;;
  *" inspect "*) case "$*" in
      *config_files*) cat "$STUB_DIR/running_config_files" 2>/dev/null;;
      *environment_file*) cat "$STUB_DIR/running_env_file" 2>/dev/null;;
      *'.compose.project"'*) cat "$STUB_DIR/running_project" 2>/dev/null;;
    esac; echo; exit 0;;
  *" ps --status running --services "*) if [ -f "$STUB_DIR/service_down" ]; then printf 'web\ncelery\ncelery-beat\ndb\nredis\n'; else printf 'web\ncelery\ncelery-beat\nproxy\ndb\nredis\n'; fi; exit 0;;
  *" config --services "*) printf 'web\\ncelery\\ncelery-beat\\ndb\\nredis\\n'
    case " $* " in *" docker-compose.dev.yml "*) ;; *) echo proxy;; esac; exit 0;;
  *" shell "*) echo "banner line"; cat "$STUB_DIR/running_count" 2>/dev/null || echo 0; exit 0;;
  *" build "*) if [ -f "$STUB_DIR/fail_up" ]; then rm -f "$STUB_DIR/fail_up"; exit 1; fi;;
  *" migrate "*) if [ -f "$STUB_DIR/fail_migrate" ]; then rm -f "$STUB_DIR/fail_migrate"; exit 1; fi;;
  *" --force-recreate "*) if [ -f "$STUB_DIR/fail_recreate_always" ]; then exit 1; fi
    if [ -f "$STUB_DIR/fail_recreate" ]; then rm -f "$STUB_DIR/fail_recreate"; exit 1; fi;;
esac
exit 0
"""
MAKE_STUB = """#!/usr/bin/env bash
echo "make $*" >> "$STUB_DIR/calls.log"
if [ -f "$STUB_DIR/fail_up" ]; then rm -f "$STUB_DIR/fail_up"; exit 1; fi
exit 0
"""


@unittest.skipUnless(SCRIPTS.joinpath('apply-update.sh').is_file() and shutil.which('git') and shutil.which('flock'),
                     'needs the repository scripts directory, git and flock')
class ApplyUpdateScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        for name, body in (('docker', DOCKER_STUB), ('make', MAKE_STUB)):
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub),
                    'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't',
                    'GIT_COMMITTER_EMAIL': 't@t', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull}
        self.env.pop('CVENGINE_COMPOSE_FILE', None)
        self.env['CVENGINE_UPDATE_MIN_FREE_MB'] = '1'  # the test disk is not the server's
        origin, self.work, other = self.tmp / 'origin.git', self.tmp / 'work', self.tmp / 'other'
        self.git('init', '--bare', '-b', 'master', str(origin), cwd=self.tmp)
        self.git('clone', str(origin), str(self.work), cwd=self.tmp)
        self.git('checkout', '-b', 'master', cwd=self.work)
        (self.work / 'scripts').mkdir()
        shutil.copy(SCRIPTS / 'apply-update.sh', self.work / 'scripts' / 'apply-update.sh')
        shutil.copy(SCRIPTS / 'update-state.py', self.work / 'scripts' / 'update-state.py')
        # the one-time PostgreSQL move is a separate script with its own docker calls; here it only records that it ran
        (self.work / 'scripts' / 'upgrade-postgres.sh').write_text('#!/usr/bin/env bash\necho "upgrade-postgres $*" >> "$STUB_DIR/calls.log"\n')
        (self.work / 'scripts' / 'upgrade-postgres.sh').chmod(0o755)
        (self.work / 'web').mkdir()
        (self.work / 'web' / 'README').write_text('v1\n')
        (self.work / 'web' / 'app' / 'migrations').mkdir(parents=True)
        (self.work / 'web' / 'app' / 'migrations' / '0001_initial.py').write_text('# schema\n')
        for compose in ('docker-compose.yml', 'docker-compose.dev.yml'):
            (self.work / compose).write_text('services: {}\n')
        self.git('add', '-A', cwd=self.work)
        self.git('commit', '-m', 'one', cwd=self.work)
        self.git('push', 'origin', 'master', cwd=self.work)
        self.prev = self.git('rev-parse', 'HEAD', cwd=self.work)
        self.git('clone', str(origin), str(other), cwd=self.tmp)
        (other / 'web' / 'README').write_text('v2\n')
        self.git('commit', '-am', 'two', cwd=other)
        self.git('push', 'origin', 'master', cwd=other)
        self.new = self.git('rev-parse', 'HEAD', cwd=other)

    def git(self, *args, cwd):
        return subprocess.run(['git', *args], cwd=cwd, env=self.env, check=True, capture_output=True, text=True).stdout.strip()

    def approve(self, sha=None):
        (self.work / 'web' / '.update-approved').write_text((sha or self.new) + '\n')

    def run_script(self, **extra_env):
        return subprocess.run(['bash', 'scripts/apply-update.sh'], cwd=self.work, env={**self.env, **extra_env},
                              capture_output=True, text=True)

    def calls(self):
        log = self.stub / 'calls.log'
        return log.read_text().splitlines() if log.exists() else []

    def head(self):
        return self.git('rev-parse', 'HEAD', cwd=self.work)

    def approved(self):
        return (self.work / 'web' / '.update-approved').exists()

    def test_nothing_happens_without_an_approval(self):
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.head(), self.prev)

    def test_shared_lock_symlink_cannot_truncate_host_file(self):
        victim = self.tmp / 'host-only'
        victim.write_text('keep me')
        (self.work / 'web' / '.update-lock').symlink_to(victim)
        self.approve('not-a-sha')
        self.assertEqual(self.run_script().returncode, 1)
        self.assertEqual(victim.read_text(), 'keep me')
        self.assertTrue((self.work / '.git' / 'cvengine-update' / 'update.lock').is_file())

    def test_symlink_approval_is_rejected_before_fetch_or_deploy(self):
        approval = self.tmp / 'host-approval'
        approval.write_text(self.new + '\n')
        (self.work / 'web' / '.update-approved').symlink_to(approval)
        self.assertEqual(self.run_script().returncode, 1)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.head(), self.prev)
        self.assertEqual(approval.read_text(), self.new + '\n')

    def test_hardlinked_approval_is_rejected(self):
        approval = self.tmp / 'host-approval'
        approval.write_text(self.new + '\n')
        os.link(approval, self.work / 'web' / '.update-approved')
        self.assertEqual(self.run_script().returncode, 1)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.head(), self.prev)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX FIFOs')
    def test_nonregular_approval_is_rejected_without_blocking(self):
        os.mkfifo(self.work / 'web' / '.update-approved')
        result = subprocess.run(['bash', 'scripts/apply-update.sh'], cwd=self.work,
                                env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), [])

    def test_shared_log_and_commit_symlinks_are_replaced_not_followed(self):
        victim = self.tmp / 'host-only'
        victim.write_text('keep me')
        for name in ('.update-log', '.commit'):
            (self.work / 'web' / name).symlink_to(victim)
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(victim.read_text(), 'keep me')
        for name in ('.update-log', '.commit'):
            self.assertFalse((self.work / 'web' / name).is_symlink())
        self.assertEqual((self.work / 'web' / '.commit').read_text().strip(), self.new)
        self.assertEqual((self.work / 'web' / '.update-log').read_bytes(),
                         (self.work / '.git' / 'cvengine-update' / 'update.log').read_bytes())

    def test_legacy_log_import_keeps_only_bounded_tail(self):
        limit = 8 * 1024 * 1024
        with (self.work / 'web' / '.update-log').open('wb') as log:
            log.write(b'old prefix')
            log.seek(limit + 4096)
            log.write(b'last history line\n')
        self.approve('not-a-sha')
        self.assertEqual(self.run_script().returncode, 1)
        private = (self.work / '.git' / 'cvengine-update' / 'update.log').read_bytes()
        self.assertNotIn(b'old prefix', private)
        self.assertIn(b'last history line', private)
        self.assertLess(len(private), limit + 1024)

    def test_existing_regular_log_history_is_preserved(self):
        (self.work / 'web' / '.update-log').write_text('previous update history\n')
        self.approve()
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue((self.work / 'web' / '.update-log').read_text().startswith(
            'previous update history\n'))

    def test_host_private_lock_serializes_updates(self):
        import fcntl
        state = self.work / '.git' / 'cvengine-update'
        state.mkdir()
        self.approve()
        with (state / 'update.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.head(), self.prev)

    def test_commit_publication_replaces_hardlink_without_changing_host_file(self):
        victim = self.tmp / 'host-only'
        victim.write_text('keep me')
        os.link(victim, self.work / 'web' / '.commit')
        result = subprocess.run(['python3', 'scripts/update-state.py', 'commit', self.new],
                                cwd=self.work, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(victim.read_text(), 'keep me')
        self.assertEqual((self.work / 'web' / '.commit').read_text().strip(), self.new)

    def test_dev_compose_file_deploys_with_that_file_and_restarts_the_code_services(self):
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertIn('docker compose -f docker-compose.dev.yml build web celery celery-beat', calls)
        self.assertIn('docker compose -f docker-compose.dev.yml up -d --no-recreate db redis', calls)
        self.assertIn('docker compose -f docker-compose.dev.yml run --rm --no-deps --entrypoint python3 web manage.py migrate --noinput', calls)
        # the dev compose file has no proxy service, so none is named (naming it made every dev update fail)
        self.assertIn('docker compose -f docker-compose.dev.yml up -d --no-deps --force-recreate web celery celery-beat', calls)
        self.assertFalse([c for c in calls if '--force-recreate' in c and 'proxy' in c])
        self.assertFalse([c for c in calls if '--force-recreate db' in c or '--force-recreate redis' in c])
        self.assertFalse([c for c in calls if c.startswith('make')])
        self.assertEqual(self.head(), self.new)
        self.assertFalse(self.approved())
        self.assertEqual((self.work / 'web' / '.commit').read_text().strip(), self.new)

    def test_production_update_keeps_datastores_and_migrates_before_app_recreation(self):
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertIn('docker compose -f docker-compose.yml up -d --no-recreate db redis', calls)
        self.assertLess(next(i for i, c in enumerate(calls) if ' migrate --noinput' in c),
                        next(i for i, c in enumerate(calls) if '--force-recreate web' in c))
        self.assertTrue(any('-f docker-compose.yml exec' in c for c in calls))  # the scan check
        self.assertIn('docker compose -f docker-compose.yml up -d --no-deps --force-recreate web celery celery-beat proxy', calls)
        self.assertEqual(self.head(), self.new)

    def test_the_deploy_steps_come_from_the_files_that_were_just_merged_not_from_the_script_already_on_the_host(self):
        """The script that applies an update is the copy already on the host, so a step added to it only ran one update late. The steps live in
        scripts/update-deploy.sh, read after the merge: a step the new files add runs in the update that brings them."""
        other = self.tmp / 'other'
        real = (SCRIPTS / 'update-deploy.sh').read_text()
        marker = '  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py migrate --noinput || return 1'
        self.assertIn(marker, real)
        (other / 'scripts').mkdir(exist_ok=True)
        (other / 'scripts' / 'update-deploy.sh').write_text(real.replace(marker, '  "${compose[@]}" images --quiet proxy\n' + marker, 1))
        self.git('add', '-A', cwd=other)
        self.git('commit', '-m', 'a new deploy step', cwd=other)
        self.git('push', 'origin', 'master', cwd=other)
        newest = self.git('rev-parse', 'HEAD', cwd=other)
        self.approve(newest)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertIn('docker compose -f docker-compose.yml images --quiet proxy', calls)  # a step this host's script has never heard of
        self.assertLess(calls.index('docker compose -f docker-compose.yml images --quiet proxy'),
                        next(i for i, c in enumerate(calls) if ' migrate --noinput' in c))
        self.assertEqual(self.head(), newest)

    def test_the_real_deploy_file_does_what_the_built_in_copy_does(self):
        """The same calls in the same order whether the steps come from scripts/update-deploy.sh or from the copy built into the script."""
        self.approve()
        self.assertEqual(self.run_script().returncode, 0)
        built_in = [c for c in self.calls() if c.startswith('docker compose')]
        for path in self.work.glob('web/.update-*'):
            path.unlink()
        self.git('reset', '--hard', self.prev, cwd=self.work)
        (self.stub / 'calls.log').unlink()
        other = self.tmp / 'other'
        (other / 'scripts').mkdir(exist_ok=True)
        shutil.copy(SCRIPTS / 'update-deploy.sh', other / 'scripts' / 'update-deploy.sh')
        self.git('add', '-A', cwd=other)
        self.git('commit', '-m', 'the deploy file', cwd=other)
        self.git('push', 'origin', 'master', cwd=other)
        newest = self.git('rev-parse', 'HEAD', cwd=other)
        self.approve(newest)
        self.assertEqual(self.run_script().returncode, 0)
        from_file = [c for c in self.calls() if c.startswith('docker compose')]
        verification = lambda call: any(x in call for x in ('http.client', 'migrate --check', 'image prune', ' info '))
        self.assertEqual([c for c in from_file if not verification(c)], built_in)

    def test_the_dev_stack_pulls_nothing(self):
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse([c for c in self.calls() if ' pull ' in c])

    def test_waits_while_scans_are_running_and_keeps_the_approval(self):
        (self.stub / 'running_count').write_text('2\n')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 3)  # "still waiting": cron ignores it, the watcher polls slowly on it
        self.assertEqual(self.head(), self.prev)
        self.assertTrue(self.approved())
        self.assertFalse([c for c in self.calls() if ' up ' in c or 'restart' in c or c.startswith('make')])
        self.assertIn('scan(s) running', (self.work / 'web' / '.update-log').read_text())

    def test_waiting_past_the_drain_limit_forces_the_update_ahead(self):
        # CVENGINE_UPDATE_DRAIN_SECONDS=0: the very first wait is already past the limit, so the update proceeds at once
        # instead of exiting 3, the same way it would after really waiting out the default five minutes.
        (self.stub / 'running_count').write_text('2\n')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml', CVENGINE_UPDATE_DRAIN_SECONDS='0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)
        self.assertTrue([c for c in self.calls() if ' up ' in c or 'restart' in c])
        log = (self.work / 'web' / '.update-log').read_text()
        self.assertIn('forcing ahead', log)
        self.assertIn('2 scan(s)/job(s)', log)

    def test_the_drain_timer_does_not_restart_on_every_poll(self):
        # the watcher calls this script again every few seconds while waiting; the drain clock must not reset each time,
        # or a scan that never finishes would block forever no matter how low the limit is set.
        (self.stub / 'running_count').write_text('2\n')
        self.approve()
        first = self.run_script(CVENGINE_UPDATE_DRAIN_SECONDS='100000')
        self.assertEqual(first.returncode, 3)
        since_file = Path(self.git('rev-parse', '--absolute-git-dir', cwd=self.work)) / 'cvengine-update' / 'draining-since'
        self.assertTrue(since_file.is_file())
        recorded = since_file.read_text()
        second = self.run_script(CVENGINE_UPDATE_DRAIN_SECONDS='100000')
        self.assertEqual(second.returncode, 3)
        self.assertEqual(since_file.read_text(), recorded)  # unchanged: still counting from the first wait

    def test_waiting_for_scans_does_not_log_the_err_trap_line(self):
        # exit 3 is an expected, normal "still waiting" control-flow exit under `set -e`, not a command that actually
        # failed; the generic ERR-trap narration ("stopped at line N") must not fire for it on every poll.
        (self.stub / 'running_count').write_text('2\n')
        self.approve()
        for _ in range(3):
            self.assertEqual(self.run_script().returncode, 3)
        log = (self.work / 'web' / '.update-log').read_text()
        self.assertNotIn('stopped at line', log)

    def test_files_pulled_by_hand_but_an_older_build_still_running_are_rebuilt(self):
        # a host without the updater is first brought up to date with `git pull`; the approval must still rebuild the services
        self.git('pull', '--ff-only', 'origin', 'master', cwd=self.work)
        (self.work / 'web' / '.commit').write_text(self.prev + '\n')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('docker compose -f docker-compose.dev.yml build web celery celery-beat', self.calls())
        self.assertIn('docker compose -f docker-compose.dev.yml up -d --no-deps --force-recreate web celery celery-beat', self.calls())
        self.assertIn('running build is', (self.work / 'web' / '.update-log').read_text())
        self.assertFalse(self.approved())
        self.assertEqual((self.work / 'web' / '.commit').read_text().strip(), self.new)

    def mark_deployed(self, sha):
        state = Path(self.git('rev-parse', '--absolute-git-dir', cwd=self.work)) / 'cvengine-update'
        state.mkdir(exist_ok=True)
        (state / 'deployed-commit').write_text(sha + '\n')

    def deployed_marker(self):
        state = Path(self.git('rev-parse', '--absolute-git-dir', cwd=self.work)) / 'cvengine-update'
        marker = state / 'deployed-commit'
        return marker.read_text().strip() if marker.exists() else None

    def test_files_and_build_already_at_the_approved_commit_rebuild_nothing(self):
        self.git('pull', '--ff-only', 'origin', 'master', cwd=self.work)
        (self.work / 'web' / '.commit').write_text(self.new + '\n')
        self.mark_deployed(self.new)
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse([c for c in self.calls() if ' build ' in c])
        self.assertFalse(self.approved())

    def test_an_interrupted_deploy_is_not_reported_as_already_done(self):
        # the files and web/.commit are at the new commit (the deploy writes the marker before it builds) but the run stopped before
        # the migration: nothing on record says the deploy finished, so the approval deploys it instead of answering "already at"
        self.git('pull', '--ff-only', 'origin', 'master', cwd=self.work)
        (self.work / 'web' / '.commit').write_text(self.new + '\n')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertTrue([c for c in calls if ' build ' in c])
        self.assertTrue([c for c in calls if ' migrate --noinput' in c])
        self.assertIn('deploying it again', (self.work / 'web' / '.update-log').read_text())
        self.assertEqual(self.deployed_marker(), self.new)
        self.assertFalse(self.approved())

    def test_a_recorded_deploy_is_still_redone_when_the_database_has_migrations_waiting(self):
        self.git('pull', '--ff-only', 'origin', 'master', cwd=self.work)
        (self.work / 'web' / '.commit').write_text(self.new + '\n')
        self.mark_deployed(self.new)
        (self.stub / 'unmigrated').write_text('')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertTrue([c for c in calls if ' migrate --noinput' in c])
        self.assertTrue([c for c in calls if '--force-recreate web' in c])
        self.assertIn('migrate --check', '\n'.join(calls))

    def test_a_successful_update_records_that_the_deploy_finished(self):
        self.approve()
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.deployed_marker(), self.new)
        self.assertEqual(self.head(), self.new)

    def publish_deploy_file_again(self):
        """A further commit on top of the deploy file, for a second update."""
        other = self.tmp / 'other'
        (other / 'web' / 'README').write_text('v3\n')
        self.git('commit', '-am', 'three', cwd=other)
        self.git('push', 'origin', 'master', cwd=other)
        return self.git('rev-parse', 'HEAD', cwd=other)

    def publish_deploy_file(self):
        """Push scripts/update-deploy.sh to the origin as a new commit, as a release that carries it does; returns that commit."""
        other = self.tmp / 'other'
        (other / 'scripts').mkdir(exist_ok=True)
        shutil.copy(SCRIPTS / 'update-deploy.sh', other / 'scripts' / 'update-deploy.sh')
        self.git('add', '-A', cwd=other)
        self.git('commit', '-m', 'the deploy file', cwd=other)
        self.git('push', 'origin', 'master', cwd=other)
        return self.git('rev-parse', 'HEAD', cwd=other)

    def test_too_little_disk_space_stops_the_update_before_anything_is_built_and_says_so(self):
        self.new = self.publish_deploy_file()
        self.approve()
        result = self.run_script(CVENGINE_UPDATE_MIN_FREE_MB='999999999')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('MB are free where Docker keeps its images', (self.work / 'web' / '.update-log').read_text())
        self.assertEqual(self.head(), self.prev)  # a failure before the migration returns to the previous version

    def test_a_verified_update_removes_the_image_it_replaced_and_a_failed_one_does_not(self):
        self.new = self.publish_deploy_file()
        self.approve()
        self.assertEqual(self.run_script().returncode, 0)
        self.assertIn('docker image prune -f', self.calls())
        (self.stub / 'calls.log').unlink()
        (self.stub / 'web_not_serving').write_text('')
        newest = self.publish_deploy_file_again()
        self.approve(newest)
        self.assertEqual(self.run_script(CVENGINE_VERIFY_WEB_TRIES='2', CVENGINE_VERIFY_POLL='0').returncode, 1)
        self.assertNotIn('docker image prune -f', self.calls())

    def test_a_web_service_that_never_answers_makes_the_update_a_failure_not_a_success(self):
        # "running" is not "working": the update used to be reported done for a web container that was restarting over and over
        (self.stub / 'web_not_serving').write_text('')
        self.new = self.publish_deploy_file()
        self.approve()
        result = self.run_script(CVENGINE_VERIFY_WEB_TRIES='2', CVENGINE_VERIFY_POLL='0')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        log = (self.work / 'web' / '.update-log').read_text()
        self.assertIn('does not answer', log)
        self.assertEqual(self.head(), self.new)  # the schema is already the new one: the old code is not put back on it
        self.assertTrue(self.approved())  # kept: the next run retries
        self.assertFalse(self.deployed_marker())

    def test_a_migration_still_waiting_after_the_restart_is_applied_and_checked_again(self):
        (self.stub / 'unmigrated_once').write_text('')
        self.new = self.publish_deploy_file()
        self.approve()
        result = self.run_script(CVENGINE_VERIFY_POLL='0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('migrations waiting; applying them', (self.work / 'web' / '.update-log').read_text())
        self.assertEqual(self.deployed_marker(), self.new)

    def test_a_migration_that_cannot_be_applied_after_the_restart_fails_the_update(self):
        (self.stub / 'unmigrated').write_text('')
        self.new = self.publish_deploy_file()
        self.approve()
        result = self.run_script(CVENGINE_VERIFY_POLL='0')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('still waiting', (self.work / 'web' / '.update-log').read_text())
        self.assertFalse(self.deployed_marker())

    def killed_then_retried(self, step, deploy_file=False):
        """Kill the updater when it reaches ``step``, then let the next run finish. Returns the retry's calls."""
        if deploy_file:
            self.new = self.publish_deploy_file()
        self.approve()
        killed = self.run_script(STUB_KILL_ON=step, CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(killed.returncode, -9, f'the updater was not killed at {step!r}: {killed.returncode}\n{killed.stdout}{killed.stderr}')
        self.assertTrue(self.approved(), 'a killed update must leave its approval for the retry')
        before = len(self.calls())
        retried = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
        return self.calls()[before:]

    def assert_converged(self, retry_calls):
        self.assertEqual(self.head(), self.new)
        self.assertFalse(self.approved(), (self.work / 'web' / '.update-log').read_text())
        self.assertEqual(self.deployed_marker(), self.new)
        self.assertEqual((self.work / 'web' / '.commit').read_text().strip(), self.new)
        self.assertTrue(any(' migrate --noinput' in c for c in retry_calls), 'the retry must migrate: ' + str(retry_calls))
        self.assertTrue(any('--force-recreate' in c for c in retry_calls), 'the retry must recreate the services')
        self.assertTrue(any('update_scan_pause --release' in c for c in retry_calls), 'scanning must be released again')

    def test_the_stack_is_recreated_with_the_overlay_and_env_file_it_was_started_with(self):
        # a host behind its own proxy: the overlay moves the published port and sets limits, the env file holds its settings
        (self.work / 'docker-compose.vps.yml').write_text('services: {}\n')
        (self.work / '.env.vps').write_text('X=1\n')
        (self.stub / 'running_config_files').write_text(f'{self.work}/docker-compose.yml,{self.work}/docker-compose.vps.yml\n')
        (self.stub / 'running_env_file').write_text(f'{self.work}/.env.vps\n')
        (self.stub / 'running_project').write_text('cvengine\n')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        deploys = [c for c in calls if ' build web' in c or '--force-recreate' in c or ' migrate ' in c or ' exec ' in c]
        self.assertTrue(deploys)
        for call in deploys:
            self.assertIn('--env-file .env.vps -p cvengine -f docker-compose.yml -f docker-compose.vps.yml', call)
        self.assertEqual(self.head(), self.new)

    def test_settings_in_env_say_the_layout_without_asking_the_running_stack(self):
        (self.work / 'docker-compose.vps.yml').write_text('services: {}\n')
        (self.work / '.env.vps').write_text('X=1\n')
        (self.work / '.env').write_text('CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.vps.yml\nCVENGINE_COMPOSE_ENV_FILE=.env.vps\n')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('docker compose --env-file .env.vps -f docker-compose.yml -f docker-compose.vps.yml up -d --no-deps --force-recreate web celery celery-beat proxy', self.calls())

    def test_an_overlay_that_nothing_says_to_use_stops_the_update_before_anything_is_recreated(self):
        (self.work / 'docker-compose.vps.yml').write_text('services: {}\n')  # untracked: this install's own file
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertTrue(self.approved())  # kept: it retries once the setting is there
        self.assertEqual(self.head(), self.prev)
        self.assertFalse([c for c in self.calls() if '--force-recreate' in c or ' build ' in c])
        self.assertIn('docker-compose.vps.yml', (self.work / 'web' / '.update-log').read_text())
        phase = self.phase_file()
        self.assertEqual(phase.get('phase'), 'failed')
        self.assertIn('CVENGINE_COMPOSE_FILES', phase.get('detail', ''))

    def test_a_running_stack_started_from_files_elsewhere_is_not_guessed_at(self):
        (self.stub / 'running_config_files').write_text('/srv/elsewhere/docker-compose.yml\n')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertTrue(self.approved())
        self.assertFalse([c for c in self.calls() if '--force-recreate' in c or ' build ' in c])

    def test_a_service_that_does_not_start_makes_the_update_a_failure_not_a_success(self):
        (self.stub / 'service_down').write_text('')  # the proxy stays "created": its port is taken
        self.approve()
        result = self.run_script(CVENGINE_VERIFY_POLL='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.approved())  # the database is migrated, so it keeps retrying the restart
        self.assertIn('not running: proxy', (self.work / 'web' / '.update-log').read_text())
        self.assertEqual(self.phase_file().get('phase'), 'failed')

    def develop_ahead(self, commit=True):
        """origin/develop: master plus one commit. Returns its tip."""
        other = self.tmp / 'other'
        self.git('checkout', '-b', 'develop', cwd=other)
        (other / 'web' / 'README').write_text('v3\n')
        self.git('commit', '-am', 'three', cwd=other)
        self.git('push', 'origin', 'develop', cwd=other)
        return self.git('rev-parse', 'HEAD', cwd=other)

    def choose_branch(self, branch):
        (self.work / 'web' / '.update-branch').write_text(branch + '\n')

    def test_a_different_update_branch_moves_the_checkout_to_it(self):
        tip = self.develop_ahead()
        self.approve(tip)
        self.choose_branch('develop')
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.work), 'develop')
        self.assertEqual(self.head(), tip)
        self.assertFalse(self.approved())
        self.assertFalse((self.work / 'web' / '.update-branch').exists())
        self.assertIn('switching this checkout from master to develop', (self.work / 'web' / '.update-log').read_text())

    def test_an_update_branch_that_does_not_exist_is_reported_and_nothing_moves(self):
        self.approve()
        self.choose_branch('no-such-branch')
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.work), 'master')
        self.assertTrue(self.approved())  # a fetch that fails is retried
        self.assertFalse([c for c in self.calls() if ' build ' in c])
        self.assertIn('no-such-branch', self.phase_file().get('detail', ''))

    def test_a_commit_that_is_not_on_the_chosen_branch_is_refused_and_says_to_check_again(self):
        self.develop_ahead()
        self.approve('0123456789abcdef0123456789abcdef01234567')
        self.choose_branch('develop')
        self.assertEqual(self.run_script().returncode, 1)
        self.assertEqual(self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.work), 'master')
        self.assertFalse(self.approved())
        self.assertIn('not on develop', self.phase_file().get('detail', ''))

    def test_moving_to_a_branch_that_does_not_contain_what_is_installed_is_a_downgrade_and_refused(self):
        other = self.tmp / 'other'
        self.git('checkout', '--orphan', 'old-line', cwd=other)  # a line of history that does not contain the installed commit
        self.git('rm', '-q', '-r', '-f', 'web/app', cwd=other)  # ... and lacks a migration the installed code has
        self.git('commit', '-m', 'old line', cwd=other)
        self.git('push', 'origin', 'old-line', cwd=other)
        tip = self.git('rev-parse', 'HEAD', cwd=other)
        self.approve(tip)
        self.choose_branch('old-line')
        self.assertEqual(self.run_script().returncode, 1)
        self.assertEqual(self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.work), 'master')
        self.assertFalse(self.approved())
        self.assertIn('downgrade', self.phase_file().get('detail', ''))
        self.assertFalse([c for c in self.calls() if ' build ' in c])

    def test_a_diverged_branch_that_has_every_installed_migration_is_switched_to(self):
        # master carries a hotfix commit that develop only has as its own copy, so develop does not contain master; it has the same migrations
        other = self.tmp / 'other'
        self.git('checkout', '--orphan', 'develop', cwd=other)
        (other / 'web' / 'app' / 'migrations' / '0002_more.py').write_text('# more schema\n')
        self.git('add', '-A', cwd=other)
        self.git('commit', '-m', 'develop, diverged', cwd=other)
        self.git('push', 'origin', 'develop', cwd=other)
        tip = self.git('rev-parse', 'HEAD', cwd=other)
        self.approve(tip)
        self.choose_branch('develop')
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.work), 'develop')
        self.assertEqual(self.head(), tip)
        self.assertIn('have diverged', (self.work / 'web' / '.update-log').read_text())

    def test_a_failed_build_after_switching_returns_to_the_previous_branch_and_commit(self):
        tip = self.develop_ahead()
        (self.stub / 'fail_up').write_text('')
        self.approve(tip)
        self.choose_branch('develop')
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.work), 'master')
        self.assertEqual(self.head(), self.prev)

    def test_a_detached_checkout_is_not_moved_and_the_reason_is_shown(self):
        tip = self.develop_ahead()
        self.git('checkout', '-q', '--detach', cwd=self.work)
        self.approve(tip)
        self.choose_branch('develop')
        self.assertEqual(self.run_script().returncode, 1)
        self.assertIn('not on a branch', self.phase_file().get('detail', ''))

    def test_a_bad_compose_file_value_is_refused_before_anything_runs(self):
        self.approve()
        for bad in ('../docker-compose.dev.yml', 'x; touch /tmp/pwned', 'missing.yml', 'docker-compose.dev.txt'):
            result = self.run_script(CVENGINE_COMPOSE_FILE=bad)
            self.assertEqual(result.returncode, 1, bad)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.head(), self.prev)

    def test_a_commit_not_on_origin_is_refused_and_the_approval_dropped(self):
        self.approve('0123456789abcdef0123456789abcdef01234567')
        self.assertEqual(self.run_script().returncode, 1)
        self.assertFalse(self.approved())
        self.assertEqual(self.head(), self.prev)
        # the reason reaches Settings > Updates: the usual cause is an update branch that is not the one checked out on the server
        phase = self.phase_file()
        self.assertEqual(phase.get('phase'), 'failed')
        self.assertIn('is not on master', phase.get('detail', ''))

    def test_local_changes_to_tracked_files_block_the_update_and_keep_the_approval(self):
        (self.work / 'web' / 'README').write_text('edited locally\n')
        self.approve()
        self.assertEqual(self.run_script().returncode, 1)
        self.assertTrue(self.approved())
        self.assertEqual(self.head(), self.prev)

    def phase_file(self):
        import json
        path = self.work / 'web' / '.update-phase.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def test_a_dirty_checkout_is_reported_in_the_ui_not_just_refused(self):
        (self.work / 'web' / 'README').write_text('edited locally\n')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        phase = self.phase_file()
        self.assertEqual(phase.get('phase'), 'failed')
        self.assertIn('web/README', phase.get('detail', ''))
        self.assertTrue(self.approved())  # kept: it retries once the checkout is clean

    def test_an_unreachable_origin_is_reported_and_the_approval_kept(self):
        self.git('remote', 'set-url', 'origin', str(self.tmp / 'does-not-exist.git'), cwd=self.work)
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        phase = self.phase_file()
        self.assertEqual(phase.get('phase'), 'draining')
        self.assertIn('could not reach origin', phase.get('detail', ''))
        self.assertTrue(self.approved())
        self.assertEqual(self.head(), self.prev)

    def test_an_unexpected_failure_leaves_a_line_in_the_log_instead_of_nothing(self):
        state = self.work / '.git' / 'cvengine-update'
        (state / 'update-state.py').mkdir(parents=True)  # the helper copy lands inside it and cannot be run
        self.approve()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        log = (state / 'update.log').read_text()
        self.assertIn('the update script stopped at line', log)
        self.assertIn('migrate-log', log)  # the command that stopped it
        self.assertTrue(self.approved())

    def install_watcher(self):
        shutil.copy(SCRIPTS / 'update-watch.sh', self.work / 'scripts' / 'update-watch.sh')
        (self.work / 'scripts' / 'update-watch.sh').chmod(0o755)
        (self.work / 'scripts' / 'apply-update.sh').chmod(0o755)

    def run_watch(self, seconds=6):
        return subprocess.run(['bash', 'scripts/update-watch.sh', str(seconds)], cwd=self.work, env=self.env,
                              capture_output=True, text=True, timeout=60)

    def test_the_watcher_applies_an_approval_within_seconds_and_reports_that_it_is_alive(self):
        import time
        self.install_watcher()
        self.approve()
        started = time.monotonic()
        result = self.run_watch(8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)  # updated
        self.assertFalse(self.approved())
        self.assertTrue(any(c.endswith('build web celery celery-beat') for c in self.calls()))
        heartbeat = (self.work / 'web' / '.updater-heartbeat')
        self.assertTrue(heartbeat.exists())
        self.assertLess(time.time() - float(__import__('json').loads(heartbeat.read_text())['at']), 30)
        self.assertLess(time.monotonic() - started, 30)

    def test_the_watcher_with_nothing_approved_only_heartbeats(self):
        self.install_watcher()
        result = self.run_watch(4)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.work / 'web' / '.updater-heartbeat').exists())
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.head(), self.prev)

    def test_two_watchers_do_not_run_at_once(self):
        self.install_watcher()
        first = subprocess.Popen(['bash', 'scripts/update-watch.sh', '6'], cwd=self.work, env=self.env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(first.kill)
        import time
        time.sleep(1)
        started = time.monotonic()
        second = self.run_watch(6)
        self.assertEqual(second.returncode, 0)
        self.assertLess(time.monotonic() - started, 3)  # it found the lock taken and left at once
        first.wait(timeout=30)

    def test_waiting_for_scans_exits_with_3_reports_once_and_keeps_the_approval(self):
        (self.stub / 'running_count').write_text('2\n')
        self.approve()
        first = self.run_script()
        second = self.run_script()
        self.assertEqual((first.returncode, second.returncode), (3, 3))
        self.assertTrue(self.approved())
        log = (self.work / '.git' / 'cvengine-update' / 'update.log').read_text()
        self.assertEqual(log.count('waiting: 2 scan(s) running'), 1)  # once, not on every call
        self.assertEqual(self.phase_file().get('phase'), 'draining')
        self.assertEqual(self.head(), self.prev)

    def test_a_refusal_is_logged_once_however_often_the_watcher_calls(self):
        (self.work / 'web' / 'README').write_text('edited locally\n')
        self.approve()
        for _ in range(3):
            self.assertEqual(self.run_script().returncode, 1)
        log = (self.work / '.git' / 'cvengine-update' / 'update.log').read_text()
        self.assertEqual(log.count('refusing: the checkout has local changes'), 1)

    def test_a_failed_build_returns_to_the_previous_commit_and_redeploys_it(self):
        (self.stub / 'fail_up').write_text('')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.head(), self.prev)
        self.assertFalse(self.approved())
        self.assertEqual(len([c for c in self.calls() if c.endswith('build web celery celery-beat')]), 2)

    def test_migration_failure_does_not_recreate_application_before_rollback(self):
        (self.stub / 'fail_migrate').write_text('')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        calls = self.calls()
        first_migration = next(i for i, c in enumerate(calls) if ' migrate --noinput' in c)
        self.assertFalse(any('--force-recreate web' in c for c in calls[:first_migration + 1]))

    def test_a_restart_that_fails_after_migrating_keeps_the_new_code_and_retries(self):
        (self.stub / 'fail_recreate').write_text('')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)  # never the old code on the new schema
        self.assertFalse(self.approved())
        self.assertEqual(len([c for c in self.calls() if '--force-recreate web' in c]), 2)
        self.assertIn('retrying the restart', (self.work / 'web' / '.update-log').read_text())

    def test_a_restart_that_keeps_failing_after_migrating_keeps_the_new_code_and_the_approval(self):
        (self.stub / 'fail_recreate_always').write_text('')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.head(), self.new)
        self.assertTrue(self.approved())  # the next run retries
        log = (self.work / 'web' / '.update-log').read_text()
        self.assertIn('is not restored', log)
        self.assertNotIn('returning to', log)

    def test_the_scan_check_asks_a_one_off_container_when_web_is_down(self):
        (self.stub / 'web_down').write_text('')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(any(' run --rm --no-deps -T --entrypoint python3 web manage.py shell' in c for c in self.calls()))
        self.assertEqual(self.head(), self.new)

    def test_with_web_down_running_scans_still_hold_the_update(self):
        (self.stub / 'web_down').write_text('')
        (self.stub / 'running_count').write_text('3\n')
        self.approve()
        result = self.run_script()
        self.assertEqual(result.returncode, 3)
        self.assertEqual(self.head(), self.prev)
        self.assertTrue(self.approved())

    # --- .env was tracked before and is untracked by the update ---------------------------------------

    def untrack_env_upstream(self, content='SECRET_TOKEN=original\n'):
        """History as on an old install: .env tracked, then removed by the commit that is being approved."""
        self.git('pull', '-q', '--ff-only', 'origin', 'master', cwd=self.work)
        (self.work / '.env').write_text(content)
        self.git('add', '.env', cwd=self.work)
        self.git('commit', '-m', 'track env', cwd=self.work)
        self.git('push', 'origin', 'master', cwd=self.work)
        self.prev = self.head()
        other = self.tmp / 'other2'
        self.git('clone', str(self.tmp / 'origin.git'), str(other), cwd=self.tmp)
        self.git('rm', '-q', '.env', cwd=other)
        self.git('commit', '-m', 'untrack env', cwd=other)
        self.git('push', 'origin', 'master', cwd=other)
        self.new = self.git('rev-parse', 'HEAD', cwd=other)
        self.tmpdir = self.tmp / 'tmpdir'
        self.tmpdir.mkdir()

    def leftovers(self):
        return list(self.tmpdir.glob('cvengine-env.*'))

    def test_an_unedited_tracked_env_survives_the_update_that_untracks_it(self):
        self.untrack_env_upstream()
        (self.work / '.env').chmod(0o640)
        self.approve()
        result = self.run_script(TMPDIR=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)
        self.assertEqual((self.work / '.env').read_text(), 'SECRET_TOKEN=original\n')
        self.assertEqual((self.work / '.env').stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.leftovers(), [])

    def test_an_edited_tracked_env_does_not_block_the_update_and_keeps_its_edits(self):
        self.untrack_env_upstream()
        (self.work / '.env').write_text('SECRET_TOKEN=edited\n')
        self.approve()
        result = self.run_script(TMPDIR=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)
        self.assertEqual((self.work / '.env').read_text(), 'SECRET_TOKEN=edited\n')
        self.assertEqual(self.leftovers(), [])

    def test_a_deleted_env_does_not_block_the_update(self):
        self.untrack_env_upstream()
        (self.work / '.env').unlink()
        self.approve()
        result = self.run_script(TMPDIR=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.head(), self.new)
        self.assertFalse((self.work / '.env').exists())

    def test_env_is_restored_after_a_failed_build_rolls_back_and_is_never_printed(self):
        self.untrack_env_upstream()
        (self.work / '.env').write_text('SECRET_TOKEN=edited\n')
        (self.stub / 'fail_up').write_text('')
        self.approve()
        result = self.run_script(TMPDIR=str(self.tmpdir), CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.head(), self.prev)
        self.assertEqual((self.work / '.env').read_text(), 'SECRET_TOKEN=edited\n')
        self.assertEqual(self.leftovers(), [])
        everything = result.stdout + result.stderr + (self.work / 'web' / '.update-log').read_text()
        self.assertNotIn('edited', everything.replace('edited locally', ''))
        self.assertNotIn('SECRET_TOKEN', everything)

    def test_the_env_backup_is_private_while_the_merge_runs(self):
        self.untrack_env_upstream()
        # The Docker build happens after the private backup is created.
        (self.stub / 'docker').write_text(DOCKER_STUB.replace(
            '\nesac\nexit 0', '\nesac\nstat -c %a "$TMPDIR"/cvengine-env.* >> "$STUB_DIR/modes.log"\nexit 0'))
        self.approve()
        result = self.run_script(TMPDIR=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set((self.stub / 'modes.log').read_text().split()), {'600'})


PG_DOCKER_STUB = """#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls.log"
case "$1 $2" in
  "volume inspect") case "$3" in *postgres18_data) [ -f "$STUB_DIR/new_volume" ] || exit 1;; *) [ -f "$STUB_DIR/old_volume" ] || exit 1;; esac;;
  "ps -q") echo busy-container;;
  "cp "*) for last; do :; done; echo dump > "$last";;
esac
case " $* " in *" ps -q db "*) echo dbid;; *" count(*) "*) echo 42;; esac
exit 0
"""


# An update killed at each step (a reboot, the OOM killer, a lost session) and then retried must end converged: the new code, the database
# migrated, the services recreated, scanning released, the approval gone. Once with the steps built into the script (the update that brings
# the deploy file) and once with scripts/update-deploy.sh (every update after it).
KILL_STEPS = {
    'during_the_build': ' build ',
    'during_the_migration': ' migrate --noinput',
    # the dangerous one: web/.commit already names the new commit and the files are new, so a run used to answer "already at"
    'after_the_migration_before_the_restart': 'collectstatic',
    'while_the_services_are_recreated': '--force-recreate',
    'right_after_the_files_were_merged': 'up -d --no-recreate db redis',
}


def _killed_update_test(step, deploy_file):
    def test(self):
        self.assert_converged(self.killed_then_retried(step, deploy_file))
    return test


for _name, _step in KILL_STEPS.items():
    for _variant, _deploy_file in (('built_in', False), ('deploy_file', True)):
        _test = _killed_update_test(_step, _deploy_file)
        _test.__name__ = f'test_an_update_killed_{_name}_is_finished_by_the_next_run_{_variant}'
        setattr(ApplyUpdateScriptTests, _test.__name__, _test)


@unittest.skipUnless(SCRIPTS.joinpath('upgrade-postgres.sh').is_file(), 'needs the repository scripts directory')
class UpgradePostgresScriptTests(unittest.TestCase):
    """scripts/upgrade-postgres.sh with a stub `docker`, in a repository with no .env at all."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'scripts').mkdir()
        shutil.copy(SCRIPTS / 'upgrade-postgres.sh', self.tmp / 'scripts' / 'upgrade-postgres.sh')
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        (self.stub / 'docker').write_text(PG_DOCKER_STUB)
        (self.stub / 'docker').chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub)}

    def run_script(self, *args):
        return subprocess.run(['bash', 'scripts/upgrade-postgres.sh', *args], cwd=self.tmp, env=self.env,
                              capture_output=True, text=True)

    def calls(self):
        log = self.stub / 'calls.log'
        return log.read_text().splitlines() if log.exists() else []

    def test_no_old_volume_is_nothing_to_do(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('nothing to upgrade', result.stdout)

    def test_new_volume_present_exits_zero_even_with_the_old_volume_still_there(self):
        (self.stub / 'old_volume').write_text('')
        (self.stub / 'new_volume').write_text('')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('already done', result.stdout)
        self.assertIn('rengine_postgres_data', result.stdout)
        self.assertFalse([c for c in self.calls() if c.startswith('docker run')])

    def test_env_without_the_variables_still_gets_the_defaults(self):
        (self.tmp / '.env').write_text('SOMETHING_ELSE=1\n')
        (self.stub / 'old_volume').write_text('')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertTrue(any('pg_isready -U rengine -d rengine' in c for c in calls))
        self.assertTrue(any('rengine_postgres_data:/var/lib/postgresql/data' in c for c in calls))

    def test_db_container_and_other_users_of_the_old_volume_are_stopped_before_pg12_starts(self):
        (self.stub / 'old_volume').write_text('')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        stop_db = next(i for i, c in enumerate(calls) if c.endswith(' stop db'))
        stop_busy = next(i for i, c in enumerate(calls) if c == 'docker stop busy-container')
        run_pg12 = next(i for i, c in enumerate(calls) if c.startswith('docker run'))
        self.assertLess(stop_db, run_pg12)
        self.assertLess(stop_busy, run_pg12)


if __name__ == '__main__':
    unittest.main()


class HostUpdaterInstallTests(unittest.TestCase):
    """An install that never had the update watcher gets it from the install and from the one manual update it needs."""

    def read(self, *parts):
        return Path(SCRIPTS.parent, *parts).read_text()

    def test_install_sh_installs_the_watcher_unless_automatic_deployment_does(self):
        installer = self.read('install.sh')
        self.assertIn('scripts/install-updater.sh', installer)
        self.assertIn('cvengine-auto-deploy', installer)

    def test_update_sh_leaves_the_watcher_behind_on_success_and_never_fails_the_update_for_it(self):
        update = self.read('scripts', 'update.sh')
        self.assertIn('install-updater.sh', update)
        self.assertIn('cvengine-auto-update', update)  # not twice
        import re
        # the watcher is installed before the success exit of the readiness loop, which polls with `sleep 5` or `sleep "$poll_seconds"`
        self.assertLess(update.index('install-updater.sh'), re.search(r'exit 0\n    fi\n    sleep (5|"\$poll_seconds")', update).start())
        self.assertIn('Could not install the update watcher', update)
