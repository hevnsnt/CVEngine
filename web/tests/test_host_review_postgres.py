"""The host review's postgres rule (scripts/host-review.py): the database's memory settings are sized for the host during an update.

Found on a production host with 12 GB of memory: the database ran with the shipped work_mem of 4MB inside a 2 GB container ceiling and spilled 18 GB to
temporary files in 2,639 sorts. The rule raises only a value that is absent or still the shipped default, never lowers one, never touches a ceiling and
never plans past the ceiling the kernel enforces. The shipped docker-compose.yml is used as it is, so its defaults are the ones the rule reads."""
import argparse
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'host-review.py'
spec = importlib.util.spec_from_file_location('host_review_pg', SCRIPT)
hr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hr)

OVERLAY = 'services:\n  db:\n    mem_limit: "${DB_MEM_LIMIT:-512m}"\n    memswap_limit: "${DB_MEM_LIMIT:-512m}"\n'
KEYS = ('POSTGRES_SHARED_BUFFERS', 'POSTGRES_EFFECTIVE_CACHE_SIZE', 'POSTGRES_WORK_MEM', 'POSTGRES_MAINTENANCE_WORK_MEM')


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        shutil.copy(ROOT / 'docker-compose.yml', self.d / 'docker-compose.yml')
        (self.d / 'docker-compose.vps.yml').write_text(OVERLAY)
        (self.d / '.env').write_text('REDIS_PASSWORD=secret\n')
        self.env('DB_MEM_LIMIT=2g\nREDIS_PASSWORD=secret\n')

    def env(self, text):
        (self.d / '.env.vps').write_text(text)

    def read(self, name='.env.vps'):
        return (self.d / name).read_text()

    def review(self, mem=12288, apply=True, *extra):
        p = argparse.ArgumentParser()
        p.add_argument('--apply', action='store_true')
        p.add_argument('--no-db-restart', action='store_true')
        p.add_argument('--env-file', action='append', default=[])
        p.add_argument('--compose-file', action='append', default=[])
        p.add_argument('--sentinels-live', type=int, default=None)
        p.add_argument('--mem-mb', type=int, default=0)
        p.add_argument('--cores', type=int, default=0)
        p.add_argument('--disk-gb', type=int, default=None)
        argv = (['--apply'] if apply else []) + ['--mem-mb', str(mem), '--cores', '4', '--disk-gb', '50', '--env-file', str(self.d / '.env.vps'),
                                                  '--compose-file', str(self.d / 'docker-compose.yml'), '--compose-file', str(self.d / 'docker-compose.vps.yml'),
                                                  *extra]
        return hr.review(p.parse_args(argv))

    def pg(self, result, kind=None):
        return [f for f in result['findings'] if f['rule'] == 'postgres' and (kind is None or f['kind'] == kind)]

    def values(self):
        """The settings the database would start with: the env file's value, else the shipped default (in MiB)."""
        got = {}
        for key in KEYS:
            text = hr.env_value([str(self.d / '.env.vps')], key) or hr.PG_DEFAULTS[key]
            got[key] = hr.size_bytes(text) // hr.MIB
        return got


class SizingTests(Case):
    def test_the_shipped_compose_file_reads_the_four_settings_with_the_defaults_the_rule_knows(self):
        self.assertEqual(hr.pg_defaults([str(ROOT / 'docker-compose.yml')]), hr.PG_DEFAULTS)
        self.assertEqual(hr.pg_defaults([str(ROOT / 'docker-compose.dev.yml')]), hr.PG_DEFAULTS)

    def test_the_diagnostic_settings_are_never_written_by_the_review(self):
        # track_io_timing and the slow query log are diagnostics an operator turns on while looking (docs/DEPLOYMENT.md, Finding slow queries):
        # the rule does not read them as sizes, and an update never writes or changes them, set or not
        for key in ('POSTGRES_TRACK_IO_TIMING', 'POSTGRES_LOG_MIN_DURATION_STATEMENT', 'POSTGRES_SHARED_PRELOAD_LIBRARIES'):
            self.assertNotIn(key, hr.pg_defaults([str(ROOT / 'docker-compose.yml')]))
        self.review()
        for key in ('POSTGRES_TRACK_IO_TIMING', 'POSTGRES_LOG_MIN_DURATION_STATEMENT'):
            self.assertNotIn(key, self.read())
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_TRACK_IO_TIMING=on\nPOSTGRES_LOG_MIN_DURATION_STATEMENT=1000\n')
        self.review()
        self.assertIn('POSTGRES_TRACK_IO_TIMING=on\n', self.read())
        self.assertIn('POSTGRES_LOG_MIN_DURATION_STATEMENT=1000\n', self.read())
        self.assertEqual(self.read().count('POSTGRES_LOG_MIN_DURATION_STATEMENT='), 1)

    def test_a_12_gb_host_with_a_2g_database_ceiling_gets_raised_values_that_fit_inside_it(self):
        result = self.review()
        v = self.values()
        self.assertEqual(v['POSTGRES_SHARED_BUFFERS'], 512)        # a quarter of 2 GB
        self.assertEqual(v['POSTGRES_WORK_MEM'], 8)                # under 3 GB the database may use: 8MB, not 16MB
        self.assertEqual(v['POSTGRES_MAINTENANCE_WORK_MEM'], 128)
        self.assertGreater(v['POSTGRES_EFFECTIVE_CACHE_SIZE'], 768)
        self.assertLessEqual(v['POSTGRES_EFFECTIVE_CACHE_SIZE'], 12288 * hr.PG_CACHE_PERCENT // 100)
        self.assertLessEqual(hr.pg_needs(v), 2048 * hr.PG_FIT_PERCENT // 100)   # never past the ceiling the kernel enforces
        self.assertIn('DB_MEM_LIMIT=2g', self.read())                         # the ceiling is the limits rule's, never written here
        self.assertEqual(self.read('.env'), 'REDIS_PASSWORD=secret\n')        # only the env file Compose reads is written
        fixed = self.pg(result, 'fixed')
        self.assertEqual(len(fixed), 1)
        self.assertIn('Postgres settings changed, the database restarts once during this update', fixed[0]['text'])
        self.assertEqual(fixed[0]['restart'], 'db')
        self.assertTrue(result['changed'])

    def test_a_bigger_ceiling_gets_16mb_work_mem_and_still_fits(self):
        self.env('DB_MEM_LIMIT=4g\n')
        self.review()
        v = self.values()
        self.assertEqual((v['POSTGRES_SHARED_BUFFERS'], v['POSTGRES_WORK_MEM'], v['POSTGRES_MAINTENANCE_WORK_MEM']), (1024, 16, 256))
        self.assertLessEqual(hr.pg_needs(v), 4096 * hr.PG_FIT_PERCENT // 100)

    def test_shared_buffers_stop_at_2gb(self):
        self.env('DB_MEM_LIMIT=16g\n')
        self.review(mem=32768)
        self.assertEqual(self.values()['POSTGRES_SHARED_BUFFERS'], 2048)
        self.assertIn('POSTGRES_SHARED_BUFFERS=2GB', self.read())

    def test_a_4_gb_host_gets_modest_values(self):
        self.review(mem=4096)
        v = self.values()
        self.assertEqual((v['POSTGRES_WORK_MEM'], v['POSTGRES_MAINTENANCE_WORK_MEM']), (8, 128))
        self.assertLessEqual(v['POSTGRES_SHARED_BUFFERS'], 512)
        self.assertLessEqual(v['POSTGRES_EFFECTIVE_CACHE_SIZE'], 4096 * hr.PG_CACHE_PERCENT // 100)
        self.assertLessEqual(hr.pg_needs(v), 2048 * hr.PG_FIT_PERCENT // 100)

    def test_a_1_gb_host_is_left_as_it_is(self):
        self.env('DB_MEM_LIMIT=768m\n')
        result = self.review(mem=1024)
        self.assertEqual(self.read(), 'DB_MEM_LIMIT=768m\n')
        self.assertEqual(self.pg(result), [])
        self.assertEqual(list(self.d.glob('*.cvengine-review-*')), [])

    def test_without_a_ceiling_the_database_gets_its_share_of_the_host(self):
        (self.d / 'docker-compose.vps.yml').write_text('services:\n  db:\n    ports: []\n')
        self.env('FOO=1\n')
        self.review()
        v = self.values()
        self.assertLessEqual(v['POSTGRES_SHARED_BUFFERS'], 12288 // 2 // 4)
        self.assertGreater(v['POSTGRES_WORK_MEM'], 4)

    def test_the_limits_rule_runs_first_and_the_sizes_fit_the_ceiling_it_raised(self):
        self.env('FOO=1\n')  # DB_MEM_LIMIT unset: the overlay's 512m, which the limits rule raises to 1g on this host
        result = self.review()
        self.assertIn('DB_MEM_LIMIT=1g', self.read())
        rules = [f['rule'] for f in result['findings'] if f['kind'] == 'fixed']
        self.assertEqual(rules, ['limits', 'postgres'])
        v = self.values()
        self.assertLessEqual(hr.pg_needs(v), 1024 * hr.PG_FIT_PERCENT // 100)
        self.assertEqual(v['POSTGRES_WORK_MEM'], 4)  # 1 GB carries no more than the shipped sort memory


class OwnerTests(Case):
    def test_a_value_the_owner_set_above_the_default_is_left_and_the_rest_is_sized(self):
        self.env('DB_MEM_LIMIT=4g\nPOSTGRES_WORK_MEM=24MB\nPOSTGRES_SHARED_BUFFERS=512MB\n')
        result = self.review()
        self.assertIn('POSTGRES_WORK_MEM=24MB', self.read())
        self.assertIn('POSTGRES_SHARED_BUFFERS=512MB', self.read())   # this host would get 1GB, but 512MB is the owner's
        self.assertEqual(self.read().count('POSTGRES_WORK_MEM='), 1)
        self.assertEqual(self.read().count('POSTGRES_SHARED_BUFFERS='), 1)
        self.assertIn('POSTGRES_MAINTENANCE_WORK_MEM=256MB', self.read())  # still the default: sized
        info = [f['text'] for f in self.pg(result, 'info')]
        self.assertTrue(any('POSTGRES_SHARED_BUFFERS=512MB' in t and 'is your own' in t for t in info), info)
        self.assertLessEqual(hr.pg_needs(self.values()), 4096 * hr.PG_FIT_PERCENT // 100)

    def test_a_value_set_below_the_default_is_the_owners_too_and_nothing_is_lowered(self):
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_WORK_MEM=2MB\n')
        self.review()
        self.assertIn('POSTGRES_WORK_MEM=2MB', self.read())
        self.assertEqual(self.read().count('POSTGRES_WORK_MEM='), 1)

    def test_a_value_equal_to_the_shipped_default_is_raised(self):
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_WORK_MEM=4MB\n')
        self.review()
        self.assertIn('POSTGRES_WORK_MEM=8MB', self.read())
        self.assertNotIn('POSTGRES_WORK_MEM=4MB', self.read())

    def test_owner_values_too_big_for_the_ceiling_are_said_and_never_lowered(self):
        self.env('DB_MEM_LIMIT=1g\nPOSTGRES_WORK_MEM=64MB\n')
        result = self.review()
        self.assertIn('POSTGRES_WORK_MEM=64MB', self.read())
        self.assertIn('DB_MEM_LIMIT=1g', self.read())
        warn = self.pg(result, 'warn')
        self.assertEqual(len(warn), 1)
        self.assertIn('Nothing was lowered', warn[0]['text'])

    def test_a_value_the_rule_wrote_is_raised_again_when_the_ceiling_grows(self):
        self.review()
        self.assertIn('POSTGRES_WORK_MEM=8MB', self.read())
        text = self.read().replace('DB_MEM_LIMIT=2g', 'DB_MEM_LIMIT=4g')
        self.env(text)
        self.review()
        self.assertIn('POSTGRES_WORK_MEM=16MB', self.read())
        self.assertEqual(self.read().count('# ' + hr.PG_NOTE + ' work_mem'), 1)  # the old note went with the old line


class DisciplineTests(Case):
    def test_a_second_run_changes_nothing(self):
        self.review()
        snapshot = self.read()
        again = self.review()
        self.assertEqual(snapshot, self.read())
        self.assertEqual(self.pg(again), [])
        self.assertFalse(again['changed'])

    def test_the_env_file_is_backed_up_first(self):
        result = self.review()
        backups = list(self.d.glob('.env.vps.cvengine-review-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'DB_MEM_LIMIT=2g\nREDIS_PASSWORD=secret\n')
        self.assertIn(('backup', 'info'), [(f['rule'], f['kind']) for f in result['findings']])
        changes = self.pg(result, 'fixed')[0]['changes']
        self.assertIn('POSTGRES_WORK_MEM: (not set, 4MB) -> 8MB', changes)

    def test_report_only_changes_nothing(self):
        before = {n: self.read(n) for n in ('.env', '.env.vps', 'docker-compose.vps.yml')}
        result = self.review(apply=False)
        self.assertEqual(before, {n: self.read(n) for n in before})
        self.assertEqual(list(self.d.glob('*.cvengine-review-*')), [])
        warn = self.pg(result, 'warn')
        self.assertEqual(len(warn), 1)
        self.assertIn('work_mem 4MB -> 8MB', warn[0]['text'])
        self.assertFalse(result['changed'])

    def test_a_caller_that_does_not_restart_the_database_leaves_it_for_the_next_update(self):
        before = self.read()
        result = self.review(12288, True, '--no-db-restart')
        self.assertEqual(before, self.read())
        self.assertEqual([f['kind'] for f in self.pg(result)], ['info'])

    def test_a_compose_file_that_does_not_read_the_settings_is_not_sized(self):
        (self.d / 'docker-compose.yml').write_text('services:\n  db:\n    image: x\n')
        result = self.review()
        self.assertEqual(self.pg(result), [])
        self.assertNotIn('POSTGRES_', self.read())


class UpdaterTests(Case):
    def test_the_updater_logs_the_restart_and_says_it_on_the_status_line(self):
        host_fit = ROOT / 'scripts' / 'host-fit.sh'
        script = f'''set -u; cd {self.d}; mkdir -p scripts; cp {SCRIPT} scripts/host-review.py; . {host_fit}
log() {{ echo "LOG: $*"; }}
CVENGINE_HOST_MEM_MB=12288 cvengine_fit_review docker compose --env-file .env.vps -p cvengine -f docker-compose.yml -f docker-compose.vps.yml
echo "short=$cv_fit_short"'''
        out = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('LOG: Fixed: Postgres settings changed, the database restarts once during this update', out.stdout)
        self.assertIn('the database restarts once during this update', out.stdout.split('short=')[1])
        self.assertIn('POSTGRES_WORK_MEM=8MB', self.read())

    def test_settings_sentinels_does_not_write_them_because_it_does_not_restart_the_database(self):
        host_fit = ROOT / 'scripts' / 'host-fit.sh'
        script = f'''set -u; cd {self.d}; mkdir -p scripts; cp {SCRIPT} scripts/host-review.py; . {host_fit}
log() {{ echo "LOG: $*"; }}
CV_FIT_NO_DB_RESTART=1 CVENGINE_HOST_MEM_MB=12288 cvengine_fit_review docker compose --env-file .env.vps -p cvengine -f docker-compose.yml -f docker-compose.vps.yml'''
        out = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn('POSTGRES_', self.read())
        self.assertIn('CV_FIT_NO_DB_RESTART=1 cvengine_fit_run', (ROOT / 'scripts' / 'apply-scanner-plan.sh').read_text())

    def test_every_update_path_runs_the_review_before_it_brings_the_database_up_so_a_changed_setting_recreates_it(self):
        for name, review in (('update.sh', 'cvengine_fit_run "$sentinel_plan"'), ('update-deploy.sh', 'cvengine_fit_run "$fit_plan"')):
            text = (ROOT / 'scripts' / name).read_text()
            # `up -d --no-deps db` (no --no-recreate) recreates the container when its command line, which carries these settings, changed
            self.assertIn('"${compose[@]}" up -d --no-deps db', text, name)
            self.assertLess(text.index(review), text.index('"${compose[@]}" up -d --no-deps db'), name)


class DiagnoseRuleTests(Case):
    """The diagnose rule: the database's lock wait log and WAL timing are on by default in the shipped compose files, reported by the review and
    never written: on is the default, off in the env file is the owner's own, and a compose file that does not pass them is a warning."""

    def diag(self, result, kind=None):
        return [f for f in result['findings'] if f['rule'] == 'diagnose' and (kind is None or f['kind'] == kind)]

    def test_the_shipped_compose_files_turn_both_on_with_env_switches(self):
        for name in ('docker-compose.yml', 'docker-compose.dev.yml'):
            text = (ROOT / name).read_text()
            self.assertIn('"-c", "log_lock_waits=${POSTGRES_LOG_LOCK_WAITS:-on}"', text, name)
            self.assertIn('"-c", "track_wal_io_timing=${POSTGRES_TRACK_WAL_IO_TIMING:-on}"', text, name)
            self.assertEqual(hr.pg_diagnostic_defaults([str(ROOT / name)]), {'POSTGRES_LOG_LOCK_WAITS': 'on', 'POSTGRES_TRACK_WAL_IO_TIMING': 'on'})

    def test_on_by_default_is_said_and_nothing_is_written(self):
        for apply in (False, True):
            result = self.review(apply=apply)
            said = self.diag(result)
            self.assertEqual([f['kind'] for f in said], ['info'])
            self.assertIn('log_lock_waits and track_wal_io_timing on', said[0]['text'])
        self.assertNotIn('LOCK_WAITS', self.read())
        self.assertNotIn('WAL_IO_TIMING', self.read())

    def test_an_empty_value_takes_the_default(self):
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_LOG_LOCK_WAITS=\n')
        said = self.diag(self.review(apply=False))
        self.assertEqual([f['kind'] for f in said], ['info'])
        self.assertIn('log_lock_waits and track_wal_io_timing on', said[0]['text'])

    def test_off_in_the_env_file_is_the_owners_own_and_left(self):
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_TRACK_WAL_IO_TIMING=off\n')
        said = self.diag(self.review())
        self.assertEqual(sorted(f['kind'] for f in said), ['info', 'info'])
        self.assertTrue(any('log_lock_waits on' in f['text'] for f in said))
        self.assertTrue(any('POSTGRES_TRACK_WAL_IO_TIMING=off' in f['text'] and 'left as it is' in f['text'] for f in said))
        self.assertIn('POSTGRES_TRACK_WAL_IO_TIMING=off\n', self.read())
        self.assertEqual(self.read().count('POSTGRES_TRACK_WAL_IO_TIMING='), 1)

    def test_a_compose_file_without_them_is_a_warning_in_the_update_log(self):
        text = (self.d / 'docker-compose.yml').read_text()
        text = text.replace(', "-c", "track_wal_io_timing=${POSTGRES_TRACK_WAL_IO_TIMING:-on}"', '')
        (self.d / 'docker-compose.yml').write_text(text)
        said = self.diag(self.review())
        warn = [f for f in said if f['kind'] == 'warn']
        self.assertEqual(len(warn), 1)
        self.assertIn('do not pass track_wal_io_timing', warn[0]['text'])
        self.assertNotIn('log_lock_waits', warn[0]['text'])
        self.assertNotIn('WAL_IO_TIMING', self.read())  # said, never written
        out = subprocess.run([sys.executable, str(SCRIPT), '--mem-mb', '12288', '--env-file', str(self.d / '.env.vps'),
                              '--compose-file', str(self.d / 'docker-compose.yml')], capture_output=True, text=True, check=True).stdout
        self.assertIn('Warning: The compose files do not pass track_wal_io_timing', out)  # the line cvengine_fit_review copies to the update log

    def test_a_compose_file_that_passes_no_database_setting_is_not_ours_and_says_nothing(self):
        (self.d / 'docker-compose.yml').write_text('services:\n  db:\n    image: "postgres:18-alpine"\n')
        self.assertEqual(self.diag(self.review()), [])

    def test_the_docs_name_both_switches(self):
        config = (ROOT / 'docs' / 'CONFIGURATION.md').read_text()
        for needle in ('| `POSTGRES_LOG_LOCK_WAITS` | `on` |', '| `POSTGRES_TRACK_WAL_IO_TIMING` | `on` |', 'pg_stat_io'):
            self.assertIn(needle, config)
        upgrade = (ROOT / 'docs' / 'UPGRADE.md').read_text()
        section = upgrade.split('### Lock waits and WAL write times are recorded', 1)[1].split('\n### ', 1)[0]
        for needle in ('POSTGRES_LOG_LOCK_WAITS', 'POSTGRES_TRACK_WAL_IO_TIMING', 'log_lock_waits=on', 'track_wal_io_timing=on', 'recreates the `db` container once',
                       'scripts/host-review.py'):
            self.assertIn(needle, section)


class CommitRuleTests(Case):
    """The commit rule: whether a commit waits for its WAL flush (synchronous_commit), off by default in the shipped compose files through
    POSTGRES_SYNCHRONOUS_COMMIT. Said with who set it, never written, and silent for compose files that pass the database no settings."""

    def said(self, result, kind=None):
        return [f for f in result['findings'] if f['rule'] == 'commit' and (kind is None or f['kind'] == kind)]

    def test_the_shipped_compose_files_turn_it_off_with_an_env_switch(self):
        for name in ('docker-compose.yml', 'docker-compose.dev.yml'):
            text = (ROOT / name).read_text()
            self.assertIn('"-c", "synchronous_commit=${POSTGRES_SYNCHRONOUS_COMMIT:-off}"', text, name)
            self.assertNotIn('wal_writer_delay', text.split('command: ["postgres"', 1)[1].split(']', 1)[0], name)  # left at its default
            self.assertEqual(hr.pg_commit_default([str(ROOT / name)]), 'off')

    def test_off_by_default_is_said_as_the_shipped_default_and_nothing_is_written(self):
        for apply in (False, True):
            said = self.said(self.review(apply=apply))
            self.assertEqual([f['kind'] for f in said], ['info'])
            self.assertIn('synchronous_commit=off (the shipped default; POSTGRES_SYNCHRONOUS_COMMIT=on in .env turns it back on)', said[0]['text'])
            self.assertIn('0.6 s', said[0]['text'])
        self.assertNotIn('SYNCHRONOUS_COMMIT', self.read())

    def test_an_empty_value_takes_the_default(self):
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_SYNCHRONOUS_COMMIT=\n')
        said = self.said(self.review(apply=False))
        self.assertIn('synchronous_commit=off (the shipped default', said[0]['text'])

    def test_on_in_the_env_file_is_the_owners_own_and_left(self):
        self.env('DB_MEM_LIMIT=2g\nPOSTGRES_SYNCHRONOUS_COMMIT=on\n')
        said = self.said(self.review())
        self.assertEqual([f['kind'] for f in said], ['info'])
        self.assertIn('synchronous_commit=on (POSTGRES_SYNCHRONOUS_COMMIT=on in', said[0]['text'])
        self.assertIn('your own, left as it is', said[0]['text'])
        self.assertIn('every commit waits for its WAL flush', said[0]['text'])
        self.assertEqual(self.read().count('POSTGRES_SYNCHRONOUS_COMMIT='), 1)

    def test_a_compose_file_without_it_is_said_not_warned(self):
        text = (self.d / 'docker-compose.yml').read_text()
        text = text.replace(',\n              "-c", "synchronous_commit=${POSTGRES_SYNCHRONOUS_COMMIT:-off}"', '')
        self.assertNotIn('synchronous_commit', text.split('command: ["postgres"', 1)[1].split(']', 1)[0])
        (self.d / 'docker-compose.yml').write_text(text)
        said = self.said(self.review())
        self.assertEqual([f['kind'] for f in said], ['info'])
        self.assertIn('do not pass synchronous_commit', said[0]['text'])

    def test_a_compose_file_that_passes_no_database_setting_is_not_ours_and_says_nothing(self):
        (self.d / 'docker-compose.yml').write_text('services:\n  db:\n    image: "postgres:18-alpine"\n')
        self.assertEqual(self.said(self.review()), [])

    def test_the_line_reaches_the_review_output(self):
        out = subprocess.run([sys.executable, str(SCRIPT), '--mem-mb', '12288', '--env-file', str(self.d / '.env.vps'),
                              '--compose-file', str(self.d / 'docker-compose.yml')], capture_output=True, text=True, check=True).stdout
        self.assertIn('The database runs with synchronous_commit=off', out)

    def test_the_docs_name_the_switch_and_the_update_step(self):
        config = (ROOT / 'docs' / 'CONFIGURATION.md').read_text()
        self.assertIn('| `POSTGRES_SYNCHRONOUS_COMMIT` | `off` |', config)
        upgrade = (ROOT / 'docs' / 'UPGRADE.md').read_text()
        section = upgrade.split('### Commits no longer wait for the disk', 1)[1].split('\n### ', 1)[0]
        for needle in ('POSTGRES_SYNCHRONOUS_COMMIT', 'synchronous_commit=off', 'recreates the `db` container once', 'ALTER SYSTEM RESET',
                       'scripts/db-settings.sh', 'scripts/host-review.py', '0.6 s'):
            self.assertIn(needle, section)
