"""scripts/auto-deploy.sh against a throwaway Git remote, a stub updater and a stub docker."""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'auto-deploy.sh'
DOCKER = '''#!/bin/sh
echo "docker $*" >> "$STUB_DIR/calls"
case "$1" in
  ps) [ -e "$STUB_DIR/no_db" ] || echo db-container;;
  exec) [ -e "$STUB_DIR/dump_fail" ] && exit 1
    printf -- '-- PostgreSQL database dump\\n-- Dumped from database version 18\\nSET statement_timeout = 0;\\n';;
esac
exit 0
'''
UPDATER = '''#!/bin/sh
echo "update $* drain=$CVENGINE_UPDATE_DRAIN_SECONDS" >> "$STUB_DIR/calls"
[ -e "$STUB_DIR/update_fail" ] && exit 3
exit 0
'''


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class AutoDeployTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        docker = self.stub / 'docker'
        docker.write_text(DOCKER)
        docker.chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub),
                    'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't',
                    'GIT_COMMITTER_EMAIL': 't@t', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull}
        for key in [k for k in self.env if k.startswith('CVENGINE_')]:
            self.env.pop(key)
        self.origin, self.work, self.other = self.tmp / 'origin.git', self.tmp / 'work', self.tmp / 'other'
        self.git('init', '--bare', '-b', 'master', str(self.origin), cwd=self.tmp)
        self.git('clone', str(self.origin), str(self.work), cwd=self.tmp)
        self.git('checkout', '-b', 'master', cwd=self.work)
        (self.work / 'scripts').mkdir()
        shutil.copy(SCRIPT, self.work / 'scripts' / 'auto-deploy.sh')
        updater = self.work / 'scripts' / 'update.sh'
        updater.write_text(UPDATER)
        updater.chmod(0o755)
        shutil.copy(ROOT / 'scripts' / 'update-state.py', self.work / 'scripts' / 'update-state.py')
        (self.work / 'web').mkdir()
        (self.work / 'web' / 'README').write_text('v1\n')
        (self.work / 'web' / '.update-mode').write_text('auto\n')  # the administrator chose Automatic in Settings > Updates
        self.git('add', '-A', cwd=self.work)
        self.git('commit', '-m', 'v1', cwd=self.work)
        self.git('push', 'origin', 'master', cwd=self.work)
        (self.work / 'web' / 'secret').write_text('key\n')
        (self.work / '.env').write_text('POSTGRES_USER=x\n')

    def git(self, *args, cwd):
        return subprocess.run(['git', *args], cwd=cwd, env=self.env, check=True, capture_output=True, text=True).stdout.strip()

    def push_new_commit(self):
        self.git('clone', str(self.origin), str(self.other), cwd=self.tmp)
        (self.other / 'web' / 'README').write_text('v2\n')
        self.git('commit', '-am', 'v2', cwd=self.other)
        self.git('push', 'origin', 'master', cwd=self.other)

    def run_deploy(self, **env):
        return subprocess.run(['bash', 'scripts/auto-deploy.sh'], cwd=self.work, env={**self.env, **env},
                              capture_output=True, text=True, timeout=60)

    def calls(self):
        path = self.stub / 'calls'
        return path.read_text().splitlines() if path.exists() else []

    def state(self):
        return self.work / '.git' / 'cvengine-auto-deploy'

    def test_unchanged_master_does_nothing(self):
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.calls(), [])

    def test_new_commit_backs_up_then_updates_with_stop_scans(self):
        self.push_new_commit()
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        calls = self.calls()
        self.assertTrue(any(c.startswith('docker exec db-container') for c in calls))
        self.assertIn('update --stop-scans drain=1800', calls)
        self.assertLess(next(i for i, c in enumerate(calls) if c.startswith('docker exec')),
                        calls.index('update --stop-scans drain=1800'))
        backups = list((self.state() / 'backups').glob('cvengine-*.sql.gz'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(oct(backups[0].stat().st_mode & 0o777), '0o600')
        self.assertEqual((self.state() / 'backups' / 'secret').read_text(), 'key\n')
        self.assertIn('Deployed', result.stdout)

    def test_nothing_is_deployed_unless_the_administrator_chose_automatic(self):
        self.push_new_commit()
        for mode in (None, 'manual\n', 'AUTO\n', 'garbage'):
            mode_file = self.work / 'web' / '.update-mode'
            mode_file.unlink(missing_ok=True)
            if mode is not None:
                mode_file.write_text(mode)
            result = self.run_deploy()
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(self.calls(), [], mode)  # no backup, no update
        self.assertEqual((self.state() / 'mode-note').read_text(), 'manual')

    def test_the_manual_notice_is_logged_once_not_every_run(self):
        (self.work / 'web' / '.update-mode').write_text('manual\n')
        first, second = self.run_deploy(), self.run_deploy()
        self.assertIn('Settings > Updates', first.stdout)
        self.assertEqual(second.stdout.strip(), '')

    def test_switching_to_automatic_deploys_on_the_next_run(self):
        self.push_new_commit()
        (self.work / 'web' / '.update-mode').write_text('manual\n')
        self.run_deploy()
        self.assertEqual(self.calls(), [])
        (self.work / 'web' / '.update-mode').write_text('auto\n')
        self.assertEqual(self.run_deploy().returncode, 0)
        self.assertIn('update --stop-scans drain=1800', self.calls())

    def commit_of_its_own(self):
        (self.work / 'web' / 'local-change').write_text('only this checkout has it\n')
        self.git('add', 'web/local-change', cwd=self.work)
        self.git('commit', '-m', 'local', cwd=self.work)

    def test_a_checkout_with_commits_of_its_own_that_has_merged_master_is_level_with_it(self):
        # HEAD never equals master's commit once the checkout has commits of its own: that used to deploy (and back up) at every run
        self.push_new_commit()
        self.commit_of_its_own()
        self.git('fetch', 'origin', 'master', cwd=self.work)
        self.git('merge', '-m', 'merge master', 'origin/master', cwd=self.work)
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.calls(), [])

    def test_a_checkout_with_commits_of_its_own_and_a_master_that_moved_waits_for_a_merge_and_says_so_once(self):
        self.commit_of_its_own()
        self.push_new_commit()
        first, second = self.run_deploy(), self.run_deploy()
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        self.assertEqual(self.calls(), [])  # no backup, no update that cannot move forward
        self.assertIn('commit(s) of its own', first.stdout)
        self.assertIn('Merge it by hand', first.stdout)
        self.assertEqual(second.stdout.strip(), '')
        # once the merge is done by hand nothing is left to deploy, and the note is forgotten
        self.git('merge', '-m', 'merge master', 'origin/master', cwd=self.work)
        self.assertEqual(self.run_deploy().returncode, 0)
        self.assertFalse((self.state() / 'diverged-note').exists())

    def test_a_checkout_on_another_branch_does_nothing_and_says_so_once(self):
        # update.sh only ever deploys master: without this the timer backed up the database and failed inside update.sh at every retry
        self.push_new_commit()
        self.git('checkout', '-b', 'develop', cwd=self.work)
        first, second = self.run_deploy(), self.run_deploy()
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        self.assertEqual(self.calls(), [])
        self.assertIn('not master', first.stdout)
        self.assertEqual(second.stdout.strip(), '')
        self.git('checkout', 'master', cwd=self.work)
        self.assertEqual(self.run_deploy().returncode, 0)
        self.assertIn('update --stop-scans drain=1800', self.calls())

    def test_the_update_is_told_not_to_take_a_second_dump(self):
        self.push_new_commit()
        updater = self.work / 'scripts' / 'update.sh'
        updater.write_text(UPDATER.replace('exit 0\n', 'echo "backups=$CVENGINE_UPDATE_BACKUPS" >> "$STUB_DIR/calls"\nexit 0\n'))
        self.assertEqual(self.run_deploy().returncode, 0)
        self.assertIn('backups=0', self.calls())

    @unittest.skipUnless(os.geteuid() == 0, 'the ownership check only bites root')
    def test_root_can_deploy_a_checkout_owned_by_the_user_who_cloned_it(self):
        self.push_new_commit()
        subprocess.run(['chown', '-R', '1000:1000', str(self.work)], check=True)
        result = self.run_deploy(SUDO_UID='')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('update --stop-scans drain=1800', self.calls())

    def test_failed_backup_never_updates(self):
        self.push_new_commit()
        (self.stub / 'dump_fail').touch()
        result = self.run_deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c.startswith('update ') for c in self.calls()))
        self.assertEqual(list((self.state() / 'backups').glob('*.sql.gz')), [])

    def test_missing_database_container_never_updates(self):
        self.push_new_commit()
        (self.stub / 'no_db').touch()
        result = self.run_deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c.startswith('update ') for c in self.calls()))

    def test_failed_commit_waits_before_retrying(self):
        self.push_new_commit()
        (self.stub / 'update_fail').touch()
        first = self.run_deploy()
        self.assertEqual(first.returncode, 3)
        self.assertTrue((self.state() / 'failed').exists())
        second = self.run_deploy()
        self.assertEqual(second.returncode, 0)
        self.assertEqual(sum(c.startswith('update ') for c in self.calls()), 1)
        third = self.run_deploy(CVENGINE_AUTO_DEPLOY_RETRY_SECONDS='0')
        self.assertEqual(third.returncode, 3)
        self.assertEqual(sum(c.startswith('update ') for c in self.calls()), 2)

    def test_success_clears_the_failure_record(self):
        self.push_new_commit()
        (self.stub / 'update_fail').touch()
        self.run_deploy()
        (self.stub / 'update_fail').unlink()
        result = self.run_deploy(CVENGINE_AUTO_DEPLOY_RETRY_SECONDS='0')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse((self.state() / 'failed').exists())

    def test_settings_come_from_env_file(self):
        self.push_new_commit()
        (self.work / '.env').write_text('CVENGINE_AUTO_DEPLOY_DRAIN_SECONDS=600\nCVENGINE_AUTO_DEPLOY_BACKUPS=0\n')
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('update --stop-scans drain=600', self.calls())
        self.assertFalse(any(c.startswith('docker exec') for c in self.calls()))

    def test_old_backups_are_pruned(self):
        backups = self.state() / 'backups'
        backups.mkdir(parents=True)
        for i in range(9):
            path = backups / f'cvengine-2026010{i}T000000Z-old.sql.gz'
            path.write_bytes(b'x')
            os.utime(path, (time.time() - 1000 + i, time.time() - 1000 + i))
        self.push_new_commit()
        result = self.run_deploy(CVENGINE_AUTO_DEPLOY_BACKUPS='3')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(len(list(backups.glob('cvengine-*.sql.gz'))), 3)

    def test_a_second_run_waits_for_the_first(self):
        self.push_new_commit()
        state = self.state()
        state.mkdir(parents=True, exist_ok=True)
        with open(state / 'lock', 'w') as handle:
            holder = subprocess.Popen(['flock', '-n', str(state / 'lock'), 'sleep', '5'])
            try:
                time.sleep(0.5)
                result = self.run_deploy()
            finally:
                holder.kill()
                holder.wait()
        self.assertEqual(result.returncode, 0)
        self.assertIn('still working', result.stdout)
        self.assertFalse(any(c.startswith('update ') for c in self.calls()))
