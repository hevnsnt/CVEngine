"""scripts/db-settings.sh: the update removes an ALTER SYSTEM value (postgresql.auto.conf) of a setting the compose files pass to the database, so
the db service's command line is the one source of the database's settings (a hand applied ``ALTER SYSTEM SET synchronous_commit = off`` and the
POSTGRES_SYNCHRONOUS_COMMIT switch then agree, and nothing comes back if the switch is ever removed). Runs the real function against a fake
``docker`` that plays Compose and psql: it records every call and keeps the names postgresql.auto.conf holds. Idempotent, and it never fails."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'

# what `docker compose config` prints for the db service of the shipped file (a list, one item per line)
CONFIG = '''services:
  db:
    command:
      - postgres
      - -c
      - max_connections=300
      - -c
      - log_connections=on
      - -c
      - synchronous_commit=off
  web:
    image: cvengine/web:latest
'''

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
STATE = %r
args = sys.argv[1:]
with open(os.path.join(STATE, 'calls.log'), 'a') as fh:
    fh.write(json.dumps(args) + '\n')
def names():
    path = os.path.join(STATE, 'auto_conf')
    return [n for n in open(path).read().split() if n] if os.path.exists(path) else []
if 'config' in args:
    if os.path.exists(os.path.join(STATE, 'config_fails')):
        sys.exit(1)
    sys.stdout.write(open(os.path.join(STATE, 'config.yml')).read())
    sys.exit(0)
if 'exec' in args:
    i = args.index('exec')
    assert args[i + 1:i + 4] == ['-T', 'db', 'sh'], args
    sql = args[-1]
    if os.path.exists(os.path.join(STATE, 'psql_fails')):
        sys.exit(2)
    if sql.startswith('SELECT DISTINCT name FROM pg_file_settings'):
        print('\n'.join(sorted(set(names()))))
    elif sql.startswith('ALTER SYSTEM RESET '):
        if os.path.exists(os.path.join(STATE, 'reset_fails')):
            sys.exit(1)
        name = sql.split()[-1]
        keep = [n for n in names() if n != name]
        with open(os.path.join(STATE, 'auto_conf'), 'w') as fh:
            fh.write('\n'.join(keep))
    elif sql == 'SELECT pg_reload_conf()':
        print('t')
    sys.exit(0)
sys.exit(0)
'''


@unittest.skipUnless(SCRIPTS.joinpath('db-settings.sh').is_file() and shutil.which('bash'), 'needs the repository scripts directory and bash')
class OneSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'config.yml').write_text(CONFIG)
        docker = self.tmp / 'docker'
        docker.write_text(FAKE_DOCKER % str(self.tmp))
        docker.chmod(0o755)

    def auto_conf(self, *names):
        (self.tmp / 'auto_conf').write_text('\n'.join(names))

    def run_step(self, shell_opts=''):
        script = f'{shell_opts}\n. {SCRIPTS / "db-settings.sh"}\ncvengine_db_settings_one_source docker compose -f docker-compose.yml\necho "exit=$?"\n'
        env = {**os.environ, 'PATH': f'{self.tmp}:{os.environ["PATH"]}'}
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env, cwd=self.tmp)

    def calls(self):
        import json
        path = self.tmp / 'calls.log'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def sql(self):
        return [c[-1] for c in self.calls() if 'exec' in c]

    def left(self):
        return sorted(n for n in (self.tmp / 'auto_conf').read_text().split() if n)

    def test_a_hand_applied_value_of_a_setting_the_compose_files_pass_is_removed_and_the_server_reloaded(self):
        self.auto_conf('synchronous_commit')
        out = self.run_step()
        self.assertIn('exit=0', out.stdout)
        self.assertIn('removed the ALTER SYSTEM value of synchronous_commit', out.stdout)
        self.assertEqual(self.sql(), ["SELECT DISTINCT name FROM pg_file_settings WHERE sourcefile LIKE '%/postgresql.auto.conf' ORDER BY name",
                                      'ALTER SYSTEM RESET synchronous_commit', 'SELECT pg_reload_conf()'])
        self.assertEqual(self.left(), [])

    def test_psql_runs_in_the_db_container_as_the_owner_with_no_password_on_the_command_line(self):
        self.auto_conf('synchronous_commit')
        self.run_step()
        for call in (c for c in self.calls() if 'exec' in c):
            self.assertEqual(call[:4], ['compose', '-f', 'docker-compose.yml', 'exec'])
            self.assertEqual(call[4:8], ['-T', 'db', 'sh', '-c'])
            self.assertIn('-U "$POSTGRES_USER" -d "$POSTGRES_DB"', call[8])
            self.assertIn('ON_ERROR_STOP=1', call[8])
            self.assertNotIn('PASSWORD', ' '.join(call))

    def test_a_second_run_changes_nothing(self):
        self.auto_conf('synchronous_commit', 'log_connections')
        self.run_step()
        (self.tmp / 'calls.log').unlink()
        out = self.run_step()
        self.assertEqual(out.stdout.strip(), 'exit=0')
        self.assertEqual(len(self.sql()), 1)  # only the read
        self.assertEqual(self.left(), [])

    def test_a_value_the_compose_files_do_not_pass_is_the_only_source_and_stays(self):
        self.auto_conf('synchronous_commit', 'wal_writer_delay', 'checkpoint_timeout')
        out = self.run_step()
        self.assertIn('exit=0', out.stdout)
        self.assertEqual(self.left(), ['checkpoint_timeout', 'wal_writer_delay'])
        self.assertNotIn('ALTER SYSTEM RESET wal_writer_delay', self.sql())
        self.assertNotIn('ALTER SYSTEM RESET checkpoint_timeout', self.sql())

    def test_compose_files_that_do_not_pass_synchronous_commit_keep_the_hand_applied_value(self):
        (self.tmp / 'config.yml').write_text(CONFIG.replace('      - -c\n      - synchronous_commit=off\n', ''))
        self.auto_conf('synchronous_commit')
        self.run_step()
        self.assertEqual(self.left(), ['synchronous_commit'])
        self.assertNotIn('SELECT pg_reload_conf()', self.sql())

    def test_several_leftovers_are_removed_with_one_reload(self):
        self.auto_conf('synchronous_commit', 'log_connections', 'max_connections')
        out = self.run_step()
        self.assertEqual(self.left(), [])
        self.assertEqual(self.sql().count('SELECT pg_reload_conf()'), 1)
        self.assertIn('log_connections max_connections synchronous_commit', out.stdout)

    def test_a_name_that_is_not_a_plain_setting_name_is_never_put_into_sql(self):
        self.auto_conf('synchronous_commit;drop')
        (self.tmp / 'config.yml').write_text(CONFIG + '      - synchronous_commit;drop=1\n')
        self.run_step()
        self.assertEqual(len(self.sql()), 1)

    def test_it_never_fails_the_update(self):
        for flag in ('config_fails', 'psql_fails', 'reset_fails'):
            with self.subTest(flag):
                self.auto_conf('synchronous_commit')
                (self.tmp / flag).write_text('')
                try:
                    out = self.run_step('set -Eeuo pipefail')  # as scripts/update.sh runs
                finally:
                    (self.tmp / flag).unlink()
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn('exit=0', out.stdout)
                self.assertTrue(out.stdout.splitlines()[0].startswith(('could not', 'removed')), out.stdout)
                self.assertEqual(self.left(), ['synchronous_commit'])

    def test_both_update_paths_run_it_after_the_database_is_up_and_before_the_backup(self):
        deploy = (SCRIPTS / 'update-deploy.sh').read_text()
        self.assertIn('[ -f scripts/db-settings.sh ] && . scripts/db-settings.sh', deploy)  # tests copy only some scripts into their checkout
        step = deploy.index('cvengine_db_settings_one_source "${compose[@]}"')
        self.assertLess(deploy.index('"${compose[@]}" up -d --no-deps db'), step)
        self.assertLess(deploy.index('exec -T db pg_isready'), step)
        self.assertLess(step, deploy.index('backup_database || return 1'))
        manual = (SCRIPTS / 'update.sh').read_text()
        self.assertIn('[[ -f scripts/db-settings.sh ]] && . scripts/db-settings.sh', manual)
        step = manual.index('cvengine_db_settings_one_source "${compose[@]}"')
        self.assertLess(manual.index('"${compose[@]}" up -d --no-deps db'), step)
        self.assertLess(step, manual.index('scripts/db-backup.sh "$STATE"'))
