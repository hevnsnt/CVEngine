"""scripts/apply-update.sh against a throwaway git origin with stub `docker` and `make`, so the real script runs
without touching Docker. Skipped where the scripts directory is not available (inside the web container only
./web is mounted); run it on the host: ``cd web && python3 -m unittest tests.test_apply_update_script``."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'

DOCKER_STUB = """#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls.log"
case " $* " in
  *" exec "*) if [ -f "$STUB_DIR/web_down" ]; then exit 1; fi
    echo "banner line"; cat "$STUB_DIR/running_count" 2>/dev/null || echo 0; exit 0;;
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
        origin, self.work, other = self.tmp / 'origin.git', self.tmp / 'work', self.tmp / 'other'
        self.git('init', '--bare', '-b', 'master', str(origin), cwd=self.tmp)
        self.git('clone', str(origin), str(self.work), cwd=self.tmp)
        self.git('checkout', '-b', 'master', cwd=self.work)
        (self.work / 'scripts').mkdir()
        shutil.copy(SCRIPTS / 'apply-update.sh', self.work / 'scripts' / 'apply-update.sh')
        # the one-time PostgreSQL move is a separate script with its own docker calls; here it only records that it ran
        (self.work / 'scripts' / 'upgrade-postgres.sh').write_text('#!/usr/bin/env bash\necho "upgrade-postgres $*" >> "$STUB_DIR/calls.log"\n')
        (self.work / 'scripts' / 'upgrade-postgres.sh').chmod(0o755)
        (self.work / 'web').mkdir()
        (self.work / 'web' / 'README').write_text('v1\n')
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

    def test_waits_while_scans_are_running_and_keeps_the_approval(self):
        (self.stub / 'running_count').write_text('2\n')
        self.approve()
        result = self.run_script(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.head(), self.prev)
        self.assertTrue(self.approved())
        self.assertFalse([c for c in self.calls() if ' up ' in c or 'restart' in c or c.startswith('make')])
        self.assertIn('scan(s) running', (self.work / 'web' / '.update-log').read_text())

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

    def test_local_changes_to_tracked_files_block_the_update_and_keep_the_approval(self):
        (self.work / 'web' / 'README').write_text('edited locally\n')
        self.approve()
        self.assertEqual(self.run_script().returncode, 1)
        self.assertTrue(self.approved())
        self.assertEqual(self.head(), self.prev)

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
        self.assertEqual(result.returncode, 0)
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
