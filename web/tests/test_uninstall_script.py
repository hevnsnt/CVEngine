"""scripts/uninstall.sh against a stub docker: it removes one Compose project by its exact label, and nothing matched by name."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'uninstall.sh'
DOCKER = '''#!/bin/sh
echo "docker $*" >> "$STUB_DIR/calls"
case "$1 $2" in
  "ps -a")
    case "$*" in *"label=com.docker.compose.project=acme-install"*) case "$*" in *"-q"*) echo abc123;; *) echo acme-install-web-1;; esac;; esac;;
  "volume ls")
    case "$*" in *"label=com.docker.compose.project=acme-install"*) case "$*" in *"-q"*) echo vol1;; *) echo acme-install_db;; esac;; esac;;
  "network ls")
    case "$*" in *"label=com.docker.compose.project=acme-install"*) case "$*" in *"-q"*) echo net1;; *) echo acme-install_net;; esac;; esac;;
esac
[ "$1" = info ] && [ -e "$STUB_DIR/no_daemon" ] && exit 1
exit 0
'''


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('bash'), 'needs bash')
class UninstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        docker = self.stub / 'docker'
        docker.write_text(DOCKER)
        docker.chmod(0o755)
        self.repo = self.tmp / 'Some-Checkout'
        (self.repo / 'scripts').mkdir(parents=True)
        shutil.copy(SCRIPT, self.repo / 'scripts' / 'uninstall.sh')
        (self.repo / 'docker-compose.yml').write_text('services: {}\n')
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('CVENGINE_', 'COMPOSE_'))}
        self.env.update(PATH=f'{self.stub}:{os.environ["PATH"]}', STUB_DIR=str(self.stub))

    def dotenv(self, text):
        (self.repo / '.env').write_text(text)

    def run_script(self, answer='yes\n', **extra):
        proc = subprocess.run(['bash', str(self.repo / 'scripts' / 'uninstall.sh')], input=answer, text=True, capture_output=True,
                              env={**self.env, **extra}, timeout=30)
        calls = (self.stub / 'calls').read_text().splitlines() if (self.stub / 'calls').exists() else []
        return proc, calls

    def destructive(self, calls):
        return [c for c in calls if any(w in c for w in (' down', ' rm ', 'volume rm', 'network rm', 'rmi'))]

    def test_it_removes_one_project_by_label_and_never_matches_a_name(self):
        self.dotenv('COMPOSE_PROJECT_NAME=acme-install\n')
        proc, calls = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('docker compose -p acme-install -f docker-compose.yml down --volumes --remove-orphans --rmi local', calls)
        self.assertIn('docker rm -f abc123', calls)
        self.assertIn('docker volume rm vol1', calls)
        self.assertIn('docker network rm net1', calls)
        joined = '\n'.join(calls)
        self.assertNotIn('name=', joined)  # nothing is selected by a name that merely contains a word
        self.assertNotIn('rengine', joined)
        self.assertNotIn('prune', joined)
        for call in calls:
            if call.startswith(('docker ps', 'docker volume ls', 'docker network ls')):
                self.assertIn('label=com.docker.compose.project=acme-install', call)

    def test_it_lists_what_it_will_remove_before_asking(self):
        self.dotenv('COMPOSE_PROJECT_NAME=acme-install\n')
        proc, _ = self.run_script(answer='no\n')
        for name in ('acme-install-web-1', 'acme-install_db', 'acme-install_net', "project 'acme-install'"):
            self.assertIn(name, proc.stdout)

    def test_anything_but_yes_removes_nothing(self):
        self.dotenv('COMPOSE_PROJECT_NAME=acme-install\n')
        for answer in ('no\n', '\n', 'maybe\n', ''):
            (self.stub / 'calls').unlink(missing_ok=True)
            proc, calls = self.run_script(answer=answer)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(self.destructive(calls), [], answer)
            self.assertIn('aborted', proc.stdout.lower())

    def test_the_project_comes_from_the_setting_then_the_env_file_then_the_directory(self):
        self.dotenv('COMPOSE_PROJECT_NAME=from-dotenv\n')
        _, calls = self.run_script(CVENGINE_COMPOSE_PROJECT='from-setting')
        self.assertTrue(any('compose -p from-setting ' in c for c in calls))
        (self.stub / 'calls').unlink()
        _, calls = self.run_script()
        self.assertTrue(any('compose -p from-dotenv ' in c for c in calls))
        (self.repo / '.env').unlink()
        (self.stub / 'calls').unlink()
        _, calls = self.run_script()
        self.assertTrue(any('compose -p some-checkout ' in c for c in calls))  # Compose's own default: the lowercased directory name

    def test_a_bad_project_name_stops_everything(self):
        for bad in ('Bad Name', '-leading', 'a;rm -rf /', '$(id)'):
            self.dotenv(f'COMPOSE_PROJECT_NAME={bad}\n')
            (self.stub / 'calls').unlink(missing_ok=True)
            proc, calls = self.run_script()
            self.assertNotEqual(proc.returncode, 0, bad)
            self.assertEqual(self.destructive(calls), [], bad)

    def test_no_docker_daemon_stops_before_anything_is_listed_or_removed(self):
        self.dotenv('COMPOSE_PROJECT_NAME=acme-install\n')
        (self.stub / 'no_daemon').write_text('')
        proc, calls = self.run_script()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.destructive(calls), [])
        self.assertIn('Docker daemon', proc.stderr)

    def test_a_compose_file_name_is_validated(self):
        self.dotenv('COMPOSE_PROJECT_NAME=acme-install\n')
        proc, calls = self.run_script(CVENGINE_COMPOSE_FILES='../evil.yml')
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.destructive(calls), [])
