"""scripts/scanner.sh and scripts/scanner_lock.py: the built-in scanner's pinned image (scanner.lock.json), how every update path fetches it and starts
it after celery, keeps a new image only once it heartbeats and otherwise rolls back to the previous one, and never fails the update."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'
DIGEST = 'sha256:' + 'a' * 64

DOCKER_STUB = """#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls.log"
case " $* " in
  *" config --services "*) printf 'web\\ncelery\\ncelery-beat\\ndb\\nredis\\n'; [ -f "$STUB_DIR/no_scanner" ] || echo scanner; exit 0;;
  *" image inspect "*) for ref in $(cat "$STUB_DIR/images" 2>/dev/null); do [[ " $* " == *" $ref "* ]] && exit 0; done; exit 1;;
  *" pull "*) if [ -f "$STUB_DIR/pull_fails" ]; then exit 1; fi; echo "${@: -1}" >> "$STUB_DIR/images"; exit 0;;
  *" build "*) if [ -f "$STUB_DIR/build_fails" ]; then exit 1; fi; echo "$5" >> "$STUB_DIR/images"; exit 0;;
  *" ps -aq scanner "*) [ -f "$STUB_DIR/running" ] && echo scannerid; exit 0;;
  *" inspect -f "*) cat "$STUB_DIR/running" 2>/dev/null; exit 0;;
  *" --force-recreate scanner "*) image=$(grep -E '^CVENGINE_SCANNER_ROLLBACK_IMAGE=' .env 2>/dev/null | cut -d= -f2-)
    [ -n "$image" ] || image=$(cat "$STUB_DIR/wanted"); echo "$image" > "$STUB_DIR/running"; exit 0;;
  *" exec -T scanner "*) running=$(cat "$STUB_DIR/running" 2>/dev/null); for ref in $(cat "$STUB_DIR/healthy" 2>/dev/null); do [ "$ref" = "$running" ] && exit 0; done; exit 1;;
  *" rm -sf scanner "*) rm -f "$STUB_DIR/running"; exit 0;;
esac
exit 0
"""


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class ScannerScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        (self.stub / 'docker').write_text(DOCKER_STUB)
        (self.stub / 'docker').chmod(0o755)
        self.work = self.tmp / 'work'
        (self.work / 'scripts').mkdir(parents=True)
        for name in ('scanner.sh', 'scanner_lock.py'):
            shutil.copy(SCRIPTS / name, self.work / 'scripts' / name)
        shutil.copy(ROOT / 'docker-compose.yml', self.work / 'docker-compose.yml')
        self.lock({'digest': DIGEST})
        (self.work / '.env').write_text('POSTGRES_DB=x\n')
        self.env = {**{k: v for k, v in os.environ.items() if not k.startswith('CVENGINE_')}, 'PATH': f'{self.stub}:{os.environ["PATH"]}',
                    'STUB_DIR': str(self.stub), 'CVENGINE_SCANNER_READY_SECONDS': '1', 'CVENGINE_SCANNER_POLL': '0'}

    def lock(self, changes):
        data = json.loads((ROOT / 'scanner.lock.json').read_text())
        data.update(changes)
        (self.work / 'scanner.lock.json').write_text(json.dumps(data))
        out = subprocess.run(['python3', 'scripts/scanner_lock.py', 'ref'], cwd=self.work, capture_output=True, text=True, check=True).stdout.strip()
        (self.stub / 'wanted').write_text(out + '\n')
        self.wanted = out

    def run_fn(self, *calls):
        script = '. scripts/scanner.sh\n' + '\n'.join(f'{c} docker compose -f docker-compose.yml' for c in calls)
        return subprocess.run(['bash', '-c', script], cwd=self.work, env=self.env, capture_output=True, text=True, timeout=60)

    def calls(self):
        path = self.stub / 'calls.log'
        return path.read_text().splitlines() if path.exists() else []

    def env_file(self):
        return (self.work / '.env').read_text()

    def test_a_published_pin_is_pulled_started_and_kept_when_it_heartbeats(self):
        (self.stub / 'healthy').write_text(self.wanted + '\n')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'docker pull -q {self.wanted}', self.calls())
        self.assertIn('docker compose -f docker-compose.yml up -d --no-deps --force-recreate scanner', self.calls())
        self.assertIn('reaches the server', result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())

    def test_an_image_that_never_heartbeats_is_rolled_back_to_the_previous_one(self):
        previous = 'ghcr.io/hevnsnt/cvengine-sentinel@sha256:' + 'b' * 64
        (self.stub / 'running').write_text(previous + '\n')
        (self.stub / 'images').write_text(previous + '\n')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rolling back', result.stderr)
        self.assertIn(f'CVENGINE_SCANNER_ROLLBACK_IMAGE={previous}', self.env_file())
        self.assertEqual((self.stub / 'running').read_text().strip(), previous)
        # the next update tries its own pin again
        (self.stub / 'healthy').write_text(self.wanted + '\n')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.assertEqual((self.stub / 'running').read_text().strip(), self.wanted)

    def test_a_first_start_with_no_previous_image_is_never_rolled_back_and_never_fails(self):
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('has not reached the server yet', result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())

    def test_a_pull_that_fails_keeps_the_running_scanner(self):
        previous = 'ghcr.io/hevnsnt/cvengine-sentinel@sha256:' + 'b' * 64
        (self.stub / 'running').write_text(previous + '\n')
        (self.stub / 'images').write_text(previous + '\n')
        (self.stub / 'healthy').write_text(previous + '\n')
        (self.stub / 'pull_fails').write_text('')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('could not pull', result.stderr)
        self.assertIn('make scanner-build', result.stderr)
        self.assertEqual((self.stub / 'running').read_text().strip(), previous)

    def test_without_a_published_digest_the_source_is_built_once(self):
        self.lock({'digest': None})
        self.assertTrue(self.wanted.startswith('cvengine-sentinel-local:'))
        result = self.run_fn('cvengine_scanner_fetch')
        self.assertEqual(result.returncode, 0, result.stderr)
        build = [c for c in self.calls() if c.startswith('docker build')]
        self.assertEqual(len(build), 1)
        self.assertIn('BUILDKIT_CONTEXT_KEEP_GIT_DIR=1', build[0])
        self.assertRegex(build[0], r'https://github\.com/hevnsnt/cvENGINE-sentinel\.git#[0-9a-f]{40}$')
        self.run_fn('cvengine_scanner_fetch')
        self.assertEqual(len([c for c in self.calls() if c.startswith('docker build')]), 1)

    def test_turned_off_it_is_removed_and_nothing_is_fetched(self):
        (self.work / '.env').write_text('CVENGINE_BUILTIN_SCANNER=0\n')
        (self.stub / 'running').write_text(self.wanted + '\n')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('docker compose -f docker-compose.yml rm -sf scanner', self.calls())
        self.assertFalse([c for c in self.calls() if ' pull ' in f' {c} ' or 'force-recreate' in c])

    def test_an_administrators_own_image_is_never_rolled_back(self):
        own = 'cvengine-sentinel-local:latest'
        (self.work / '.env').write_text(f'CVENGINE_SCANNER_IMAGE={own}\n')
        (self.stub / 'images').write_text(own + '\n')
        (self.stub / 'running').write_text('ghcr.io/hevnsnt/cvengine-sentinel@sha256:' + 'b' * 64 + '\n')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.assertFalse([c for c in self.calls() if c.startswith('docker pull')])

    def test_an_install_without_the_service_is_left_alone(self):
        (self.stub / 'no_scanner').write_text('')
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c for c in self.calls() if 'config --services' not in c], [])


class LockTests(unittest.TestCase):
    def test_the_lock_is_valid_and_compose_runs_its_reference(self):
        result = subprocess.run(['python3', str(SCRIPTS / 'scanner_lock.py'), 'check'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_pin_is_by_digest_or_a_source_commit_never_a_tag(self):
        data = json.loads((ROOT / 'scanner.lock.json').read_text())
        self.assertRegex(data['source']['commit'], r'^[0-9a-f]{40}$')
        if data['digest'] is not None:
            self.assertRegex(data['digest'], r'^sha256:[0-9a-f]{64}$')

    def test_pin_rewrites_the_lock_and_the_compose_default_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'scripts').mkdir()
            shutil.copy(SCRIPTS / 'scanner_lock.py', work / 'scripts')
            shutil.copy(ROOT / 'scanner.lock.json', work)
            shutil.copy(ROOT / 'docker-compose.yml', work)
            commit = json.loads((ROOT / 'scanner.lock.json').read_text())['source']['commit']
            out = subprocess.run(['python3', 'scripts/scanner_lock.py', 'pin', '--digest', DIGEST, '--version', commit[:12]], cwd=work,
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout.strip(), f'ghcr.io/hevnsnt/cvengine-sentinel@{DIGEST}')
            self.assertIn(f'ghcr.io/hevnsnt/cvengine-sentinel@{DIGEST}}}}}"', (work / 'docker-compose.yml').read_text())
            self.assertEqual(subprocess.run(['python3', 'scripts/scanner_lock.py', 'check'], cwd=work).returncode, 0)
            bad = subprocess.run(['python3', 'scripts/scanner_lock.py', 'pin', '--digest', 'latest', '--version', commit[:12]], cwd=work,
                                 capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)


class UpdatePathTests(unittest.TestCase):
    """Every path that recreates celery also fetches the scanner's image first and starts the scanner after (it shares celery's network namespace)."""

    def text(self, name):
        return (ROOT / name).read_text()

    def test_each_update_path_fetches_before_and_starts_after(self):
        for name, after in (('scripts/update.sh', 'worker_queues_ready && beat_ready'), ('scripts/update-deploy.sh', 'verify_serving || return 1'),
                            ('scripts/apply-update.sh', 'verify_running "${services[@]}" || return 1'), ('Makefile', '--force-recreate tailscale')):
            with self.subTest(name=name):
                text = self.text(name)
                self.assertIn('cvengine_scanner_fetch', text)
                self.assertIn('cvengine_scanner_start', text)
                self.assertLess(text.index(after), text.index('cvengine_scanner_start'))

    def test_the_web_updater_fetches_before_maintenance(self):
        text = self.text('scripts/update-deploy.sh')
        self.assertLess(text.index('cvengine_scanner_fetch'), text.index('  maintenance_on\n'))
        self.assertLess(text.index('cvengine_scanner_start'), text.index('  prune_old_images\n'))

    def test_make_up_never_waits_for_a_rollback(self):
        self.assertIn('cvengine_scanner_start --no-wait', self.text('Makefile'))

    def test_the_scripts_parse(self):
        for name in ('scripts/scanner.sh', 'scripts/update.sh', 'scripts/update-deploy.sh', 'scripts/apply-update.sh', 'install.sh', 'scripts/init-env.sh'):
            with self.subTest(name=name):
                subprocess.run(['bash', '-n', str(ROOT / name)], check=True)

    def test_the_compose_default_is_the_rollback_then_the_pin(self):
        self.assertRegex(self.text('docker-compose.yml'),
                         re.escape('image: "${CVENGINE_SCANNER_IMAGE:-${CVENGINE_SCANNER_ROLLBACK_IMAGE:-') + r'[^}]+\}\}"')
