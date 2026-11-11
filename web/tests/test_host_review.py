"""The host review (scripts/host-review.py): settings that do not fit the host are put right at update time, so nobody upgrading from 1.3.x has to find them by hand.

Found on the first 1.4 server: a leftover DISCOVERY_CONCURRENCY=1 pin (one host assessed at a time while the Sentinels idled) and a database held to 512 MB,
which the kernel killed. Both were fixed by hand; this makes the updater do it, with a backup and a line in the update log."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'host-review.py'
spec = importlib.util.spec_from_file_location('host_review', SCRIPT)
hr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hr)

OVERLAY = '''services:
  db:
    <<: *limits
    ports: !reset []
    mem_limit: 512m   # the owner's comment
    memswap_limit: 512m
  web:
    mem_limit: 1g
  celery:
    mem_limit: 4.5g
'''


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / '.env').write_text('FOO=1\nDISCOVERY_CONCURRENCY=1\nREDIS_PASSWORD=secret\n')
        (self.d / '.env.vps').write_text('FOO=1\nDISCOVERY_CONCURRENCY=1\nREDIS_PASSWORD=secret\n')
        (self.d / 'docker-compose.yml').write_text('services:\n  db:\n    image: x\n  web:\n    mem_limit: "${WEB_MEM_LIMIT:-1g}"\n')
        (self.d / 'docker-compose.vps.yml').write_text(OVERLAY)

    def run_review(self, *extra, mem=7941, apply=True):
        argv = (['--apply'] if apply else []) + ['--mem-mb', str(mem), '--cores', '3', '--disk-gb', '40', '--env-file', str(self.d / '.env.vps'),
                                                  '--compose-file', str(self.d / 'docker-compose.yml'), '--compose-file', str(self.d / 'docker-compose.vps.yml'), *extra]
        args = hr.argparse.Namespace()
        parser_args = self.parse(argv)
        return hr.review(parser_args)

    def parse(self, argv):
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument('--apply', action='store_true')
        p.add_argument('--env-file', action='append', default=[])
        p.add_argument('--compose-file', action='append', default=[])
        p.add_argument('--sentinels-live', type=int, default=None)
        p.add_argument('--mem-mb', type=int, default=0)
        p.add_argument('--cores', type=int, default=0)
        p.add_argument('--disk-gb', type=int, default=None)
        return p.parse_args(argv)

    def rules(self, result, kind=None):
        return [(f['rule'], f['kind']) for f in result['findings'] if kind is None or f['kind'] == kind]

    def read(self, name):
        return (self.d / name).read_text()


class PinTests(Case):
    def test_a_leftover_pin_is_removed_from_every_env_file_with_a_backup_and_the_rest_is_untouched(self):
        self.run_review()
        for name in ('.env', '.env.vps'):
            self.assertNotIn('DISCOVERY_CONCURRENCY', self.read(name))
            self.assertIn('REDIS_PASSWORD=secret', self.read(name))
            self.assertIn('FOO=1', self.read(name))
        backups = sorted(p.name for p in self.d.glob('*.cvengine-review-*'))
        self.assertEqual(len([b for b in backups if b.startswith('.env.vps.')]), 1)
        saved = next(self.d.glob('.env.vps.cvengine-review-*')).read_text()
        self.assertIn('DISCOVERY_CONCURRENCY=1', saved)  # the line can be put back by hand

    def test_report_only_changes_nothing(self):
        before = {n: self.read(n) for n in ('.env', '.env.vps', 'docker-compose.vps.yml')}
        result = self.run_review(apply=False)
        self.assertEqual(before, {n: self.read(n) for n in before})
        self.assertEqual(list(self.d.glob('*.cvengine-review-*')), [])
        self.assertIn(('pin', 'warn'), self.rules(result))
        self.assertIn(('limits', 'warn'), self.rules(result))
        self.assertFalse(result['changed'])

    def test_a_pin_of_four_or_more_is_the_owners_own_and_stays(self):
        for name in ('.env', '.env.vps'):
            (self.d / name).write_text('DISCOVERY_CONCURRENCY=4\n')
        result = self.run_review()
        self.assertIn('DISCOVERY_CONCURRENCY=4', self.read('.env.vps'))
        self.assertNotIn('pin', [r for r, _ in self.rules(result)])

    def test_a_small_host_keeps_a_pin_of_one(self):
        result = self.run_review(mem=2048)
        self.assertIn('DISCOVERY_CONCURRENCY=1', self.read('.env.vps'))
        self.assertEqual([k for r, k in self.rules(result) if r == 'pin'], ['info'])

    def test_nothing_scans_here_so_the_pin_is_harmless_and_stays(self):
        (self.d / '.env.vps').write_text('CVENGINE_BUILTIN_SCANNER=0\nDISCOVERY_CONCURRENCY=1\n')
        (self.d / '.env').write_text('')
        args = self.parse(['--apply', '--mem-mb', '7941', '--env-file', str(self.d / '.env.vps'), '--sentinels-live', '0'])
        args.compose_file = []
        hr.review(args)
        self.assertIn('DISCOVERY_CONCURRENCY=1', self.read('.env.vps'))

    def test_no_pin_is_a_quiet_no_op_and_a_second_run_changes_nothing(self):
        self.run_review()
        snapshot = {n: self.read(n) for n in ('.env', '.env.vps', 'docker-compose.vps.yml')}
        again = self.run_review()
        self.assertEqual(snapshot, {n: self.read(n) for n in snapshot})
        self.assertFalse(again['changed'])


class LimitTests(Case):
    def test_a_database_ceiling_below_its_floor_is_raised_in_the_file_that_sets_it_and_only_there(self):
        result = self.run_review()
        text = self.read('docker-compose.vps.yml')
        self.assertIn('    mem_limit: 1g   # the owner\'s comment', text)  # the comment survives
        self.assertIn('    memswap_limit: 1g', text)
        self.assertIn('    mem_limit: 1g\n  celery:', text)  # the web server's own 1g is the same text: unchanged
        self.assertIn('    mem_limit: 4.5g', text)             # the owner's Celery ceiling is not touched
        self.assertIn('<<: *limits', text)
        self.assertIn(('limits', 'fixed'), self.rules(result))
        self.assertTrue(result['changed'])

    def test_a_ceiling_at_or_above_the_floor_is_the_owners_own(self):
        (self.d / 'docker-compose.vps.yml').write_text(OVERLAY.replace('512m', '2g'))
        before = self.read('docker-compose.vps.yml')
        result = self.run_review()
        self.assertEqual(before, self.read('docker-compose.vps.yml'))
        self.assertNotIn(('limits', 'fixed'), self.rules(result))

    def test_a_smaller_host_has_a_lower_floor(self):
        (self.d / 'docker-compose.vps.yml').write_text(OVERLAY.replace('512m', '800m'))
        self.run_review(mem=4096)
        self.assertIn('mem_limit: 800m', self.read('docker-compose.vps.yml'))  # 800 MB is over the 768 MB a small host needs
        (self.d / 'docker-compose.vps.yml').write_text(OVERLAY)
        self.run_review(mem=4096)
        self.assertIn('    mem_limit: 768m', self.read('docker-compose.vps.yml'))

    def test_a_limit_given_as_an_environment_default_is_written_to_the_env_file(self):
        (self.d / 'docker-compose.vps.yml').write_text('services:\n  db:\n    mem_limit: "${DB_MEM_LIMIT:-512m}"\n')
        self.run_review()
        self.assertIn('DB_MEM_LIMIT=1g', self.read('.env.vps'))
        self.assertIn('${DB_MEM_LIMIT:-512m}', self.read('docker-compose.vps.yml'))  # the compose file is not edited
        (self.d / '.env.vps').write_text('DB_MEM_LIMIT=2g\n')
        self.assertFalse(self.run_review()['changed'])  # the owner's value is above the floor

    def test_a_service_without_a_ceiling_has_nothing_to_raise(self):
        (self.d / 'docker-compose.vps.yml').write_text('services:\n  db:\n    ports: !reset []\n')
        result = self.run_review()
        self.assertNotIn(('limits', 'fixed'), self.rules(result))

    def test_the_budget_is_said_and_never_changed(self):
        result = self.run_review(mem=6000)
        self.assertIn(('budget', 'warn'), self.rules(result))
        self.assertIn('mem_limit: 4.5g', self.read('docker-compose.vps.yml'))

    def test_a_full_disk_is_said(self):
        args = self.parse(['--mem-mb', '7941', '--disk-gb', '5'])
        args.compose_file = []
        self.assertIn(('disk', 'warn'), [(f['rule'], f['kind']) for f in hr.review(args)['findings']])


class CommandLineTests(Case):
    def test_it_runs_as_a_script_from_a_compose_command_line_and_prints_what_it_did(self):
        cmd = [sys.executable, str(SCRIPT), '--apply', '--mem-mb', '7941', '--cores', '3', '--disk-gb', '40', '--compose-args', 'docker', 'compose', '--env-file',
               str(self.d / '.env.vps'), '-p', 'cvengine', '-f', str(self.d / 'docker-compose.yml'), '-f', str(self.d / 'docker-compose.vps.yml')]
        out = subprocess.run(cmd, capture_output=True, text=True, cwd=self.d, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('Fixed: Removed DISCOVERY_CONCURRENCY=1', out.stdout)
        self.assertIn('Fixed: The db container was held to 512 MB', out.stdout)
        self.assertIn('was backed up first', out.stdout)
        self.assertNotIn('secret', out.stdout)  # the review never prints the env file's other lines

    def test_the_updater_calls_it_and_the_function_never_fails_an_update(self):
        host_fit = ROOT / 'scripts' / 'host-fit.sh'
        script = f'''set -u; cd {self.d}; mkdir -p scripts; cp {SCRIPT} scripts/host-review.py; . {host_fit}
log() {{ echo "LOG: $*"; }}
CVENGINE_HOST_MEM_MB=7941 cvengine_fit_review docker compose --env-file .env.vps -p cvengine -f docker-compose.yml -f docker-compose.vps.yml
echo "short=$cv_fit_short"; echo "rc=$?"'''
        out = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('LOG: Fixed: Removed DISCOVERY_CONCURRENCY=1', out.stdout)
        self.assertIn('short=settings that did not fit this host were put right', out.stdout)
        self.assertIn('rc=0', out.stdout)
        # without the script (an old checkout) it does nothing and says nothing
        (self.d / 'scripts' / 'host-review.py').unlink()
        out = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0)
        self.assertNotIn('LOG:', out.stdout)
