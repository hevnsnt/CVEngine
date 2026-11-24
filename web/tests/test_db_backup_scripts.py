"""The nightly database dump, its schedule and the restore check (scripts/db-backup-daily.sh, install-db-backup.sh, restore-check.sh) against a
fake docker and a fake crontab: the dump's format, folder and modes, how many days are kept, and that the restore check only ever drops its own
throwaway database."""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'

DOCKER = r'''#!/usr/bin/env python3
import json, sys
from pathlib import Path
STATE = Path(%(state)r)
argv = sys.argv[1:]
with open(STATE / 'calls.jsonl', 'a') as handle:
    handle.write(json.dumps(argv) + '\n')
line = ' '.join(argv)
if argv[:1] == ['compose']:
    if 'ps' in argv:
        print('' if (STATE / 'no_db').exists() else 'dbid')
    sys.exit(0)
if argv[:1] == ['exec']:
    if '-i' in argv[:3]:
        sys.stdin.read()
    if 'pg_isready' in line:
        sys.exit(0)
    if 'pg_dump' in line:
        if (STATE / 'dump_fail').exists():
            sys.exit(1)
        sys.stdout.write('PGDMP fake')
        sys.exit(0)
    if 'pg_restore' in line and '--list' in line:
        print('3456; 0 16385 TABLE DATA public auth_user postgres')
        sys.exit(0)
    if 'pg_restore' in line:
        sys.exit(1 if (STATE / 'restore_fail').exists() else 0)
    if 'printf %%s "$POSTGRES_DB"' in line:
        sys.stdout.write('cvengine')
        sys.exit(0)
    if 'SELECT count(*)' in line:
        table = argv[-1].split('"')[1]
        if (STATE / ('missing_' + table)).exists() and 'restore_check' in argv[-2]:
            sys.exit(1)
        print(7)
        sys.exit(0)
    sys.exit(0)
sys.exit(0)
'''

CRONTAB = r'''#!/bin/sh
f="%(state)s/crontab"
if [ "$1" = "-l" ]; then [ -f "$f" ] && cat "$f"; exit 0; fi
if [ "$1" = "-" ]; then cat > "$f"; exit 0; fi
exit 1
'''


@unittest.skipUnless(shutil.which('bash') and shutil.which('python3'), 'needs bash and python3')
class BackupScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = self.tmp / 'state'
        self.state.mkdir()
        stub = self.tmp / 'stub'
        stub.mkdir()
        (stub / 'docker').write_text(DOCKER % {'state': str(self.state)})
        (stub / 'crontab').write_text(CRONTAB % {'state': str(self.state)})
        for name in ('docker', 'crontab'):
            (stub / name).chmod(0o755)
        self.repo = self.tmp / 'CVEngine'
        (self.repo / 'scripts').mkdir(parents=True)
        for name in ('db-backup-daily.sh', 'install-db-backup.sh', 'restore-check.sh', 'compose-layout.sh'):
            shutil.copy(SCRIPTS / name, self.repo / 'scripts' / name)
        (self.repo / 'docker-compose.yml').write_text('services: {}\n')
        (self.repo / '.env').write_text('POSTGRES_USER=cvengine\nPOSTGRES_DB=cvengine\nCVENGINE_COMPOSE_FILES=docker-compose.yml\n')
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('CVENGINE_', 'COMPOSE_'))}
        self.env['PATH'] = f'{stub}:{os.environ["PATH"]}'

    def run_script(self, name, *args, **extra):
        return subprocess.run(['bash', str(self.repo / 'scripts' / name), *args], text=True, capture_output=True, env={**self.env, **extra},
                               cwd=self.tmp, timeout=60)

    def calls(self):
        path = self.state / 'calls.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def old_dump(self, folder, name, days):
        path = folder / name
        path.write_text('old')
        stamp = time.time() - days * 86400
        os.utime(path, (stamp, stamp))
        return path

    def test_a_dump_is_custom_format_in_a_private_folder_and_old_ones_go(self):
        folder = self.repo / 'backups' / 'db'
        folder.mkdir(parents=True)
        old = self.old_dump(folder, 'cvengine-20260101T000000Z.dump', 9)
        recent = self.old_dump(folder, 'cvengine-20261120T000000Z.dump', 2)
        other = self.old_dump(folder, 'notes.txt', 30)
        proc = self.run_script('db-backup-daily.sh')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        new = Path(proc.stdout.strip().splitlines()[-1])
        if not new.is_absolute():
            new = self.repo / new
        self.assertRegex(new.name, r'^cvengine-\d{8}T\d{6}Z\.dump$')
        self.assertEqual(new.read_text(), 'PGDMP fake')
        self.assertEqual(stat.S_IMODE(new.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        self.assertFalse(old.exists())  # older than the 7 days kept by default
        self.assertTrue(recent.exists())
        self.assertTrue(other.exists())  # only cvengine-*.dump files are ever removed
        dump = next(c for c in self.calls() if 'pg_dump' in ' '.join(c))
        self.assertIn('pg_dump -Fc', ' '.join(dump))
        self.assertFalse(list(folder.glob('*.partial')))

    def test_the_kept_days_and_the_folder_come_from_env(self):
        folder = self.tmp / 'elsewhere'
        folder.mkdir()
        two_days = self.old_dump(folder, 'cvengine-20261120T000000Z.dump', 2.5)
        (self.repo / '.env').write_text((self.repo / '.env').read_text() + f'CVENGINE_DB_BACKUP_DIR={folder}\nCVENGINE_DB_BACKUP_DAYS=2\n')
        proc = self.run_script('db-backup-daily.sh')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(two_days.exists())
        self.assertEqual(len(list(folder.glob('cvengine-*.dump'))), 1)
        self.assertFalse((self.repo / 'backups').exists())

    def test_zero_days_turns_the_nightly_dump_off_but_a_labelled_dump_is_still_taken(self):
        proc = self.run_script('db-backup-daily.sh', CVENGINE_DB_BACKUP_DAYS='0')
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(any('pg_dump' in ' '.join(c) for c in self.calls()))
        proc = self.run_script('db-backup-daily.sh', '--label', 'before-rotation', CVENGINE_DB_BACKUP_DAYS='0')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.strip().endswith('-before-rotation.dump'))

    def test_a_labelled_dump_prunes_nothing(self):
        folder = self.repo / 'backups' / 'db'
        folder.mkdir(parents=True)
        old = self.old_dump(folder, 'cvengine-20260101T000000Z.dump', 30)
        self.assertEqual(self.run_script('db-backup-daily.sh', '--label', 'before-rotation').returncode, 0)
        self.assertTrue(old.exists())

    def test_a_failed_dump_leaves_nothing_behind_and_removes_nothing(self):
        folder = self.repo / 'backups' / 'db'
        folder.mkdir(parents=True)
        old = self.old_dump(folder, 'cvengine-20260101T000000Z.dump', 30)
        (self.state / 'dump_fail').write_text('')
        proc = self.run_script('db-backup-daily.sh')
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(old.exists())
        self.assertEqual(sorted(p.name for p in folder.iterdir()), [old.name])

    def test_no_running_database_fails(self):
        (self.state / 'no_db').write_text('')
        self.assertEqual(self.run_script('db-backup-daily.sh').returncode, 1)

    def test_the_schedule_is_one_marked_crontab_line_and_remove_takes_only_it(self):
        (self.state / 'crontab').write_text('5 4 * * * /usr/local/bin/something # mine\n')
        proc = self.run_script('install-db-backup.sh')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.run_script('install-db-backup.sh')  # a second install replaces, not doubles
        lines = (self.state / 'crontab').read_text().splitlines()
        ours = [l for l in lines if l.endswith('# cvengine-db-backup')]
        self.assertEqual(len(ours), 1)
        self.assertIn(f'cd {self.repo} && scripts/db-backup-daily.sh >> {self.repo}/backups/db/backup.log 2>&1', ours[0])
        self.assertTrue(ours[0].startswith('17 3 * * * '))
        self.assertIn('5 4 * * * /usr/local/bin/something # mine', lines)
        self.assertEqual(stat.S_IMODE((self.repo / 'backups' / 'db').stat().st_mode), 0o700)
        self.assertEqual(self.run_script('install-db-backup.sh', '--remove').returncode, 0)
        self.assertEqual((self.state / 'crontab').read_text().splitlines(), ['5 4 * * * /usr/local/bin/something # mine'])

    def test_the_restore_check_uses_the_newest_dump_and_drops_only_its_own_database(self):
        folder = self.repo / 'backups' / 'db'
        folder.mkdir(parents=True)
        self.old_dump(folder, 'cvengine-20261101T000000Z.dump', 5)
        newest = self.old_dump(folder, 'cvengine-20261122T000000Z.dump', 1)
        proc = self.run_script('restore-check.sh')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(str(newest.name), proc.stdout)
        self.assertIn('Restore check passed', proc.stdout)
        calls = [' '.join(c) for c in self.calls()]
        create = next(c for c in calls if 'createdb' in c)
        scratch = create.split()[-1]
        self.assertRegex(scratch, r'^cvengine_restore_check_\d+$')
        restore = next(c for c in calls if 'pg_restore' in c and '--list' not in c)
        self.assertIn('--no-owner --no-privileges --exit-on-error', restore)
        self.assertTrue(restore.endswith(scratch))
        drops = [c for c in calls if 'dropdb' in c or 'DROP DATABASE' in c]
        self.assertEqual(len(drops), 1)
        self.assertTrue(drops[0].endswith(scratch))
        self.assertLess(calls.index(restore), calls.index(drops[0]))
        self.assertIn('auth_user', proc.stdout)

    def test_a_failed_restore_still_drops_the_throwaway_database(self):
        folder = self.repo / 'backups' / 'db'
        folder.mkdir(parents=True)
        self.old_dump(folder, 'cvengine-20261122T000000Z.dump', 1)
        (self.state / 'restore_fail').write_text('')
        proc = self.run_script('restore-check.sh')
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(any('dropdb' in ' '.join(c) for c in self.calls()))

    def test_a_missing_table_in_the_restored_copy_fails_the_check(self):
        folder = self.repo / 'backups' / 'db'
        folder.mkdir(parents=True)
        self.old_dump(folder, 'cvengine-20261122T000000Z.dump', 1)
        (self.state / 'missing_auth_user').write_text('')
        proc = self.run_script('restore-check.sh')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('FAILED', proc.stderr)
        self.assertTrue(any('dropdb' in ' '.join(c) for c in self.calls()))

    def test_without_a_dump_it_says_how_to_take_one(self):
        proc = self.run_script('restore-check.sh')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('make db-backup', proc.stderr)
        self.assertFalse(any('createdb' in ' '.join(c) for c in self.calls()))

    def test_the_make_targets_and_the_docs_name_them(self):
        makefile = (ROOT / 'Makefile').read_text()
        for target in ('db-backup:', 'db-backup-schedule:', 'restore-check:'):
            self.assertIn(target, makefile)
        deployment = (ROOT / 'docs' / 'DEPLOYMENT.md').read_text()
        for needle in ('make db-backup-schedule', 'make restore-check', 'CVENGINE_DB_BACKUP_DAYS', 'CVENGINE_DB_BACKUP_DIR'):
            self.assertIn(needle, deployment)
