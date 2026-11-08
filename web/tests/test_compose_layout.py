"""scripts/enable-redis-auth.sh and scripts/rotate-field-key.sh recreate services with the Compose files, env file and project the installation
runs with, never with docker-compose.yml alone (an overlay that frees a published port, memory limits, a separate env file)."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKER = '''#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls"
case " $* " in
  *" version "*) exit 0;;
  *" ps -a --filter "*) [ -f "$STUB_DIR/running_config_files" ] && echo abc123; exit 0;;
  *" inspect -f "*) case "$*" in
      *config_files*) cat "$STUB_DIR/running_config_files" 2>/dev/null;;
      *environment_file*) cat "$STUB_DIR/running_env_file" 2>/dev/null;;
      *'.compose.project"'*) cat "$STUB_DIR/running_project" 2>/dev/null;;
    esac; echo; exit 0;;
  *" ps -q --status running scanner "*) [ -f "$STUB_DIR/scanner_running" ] && echo scanner-container; exit 0;;
  *" config --services "*) printf 'db\\nredis\\nweb\\ncelery\\ncelery-beat\\nproxy\\n'; exit 0;;
esac
exit 0
'''


@unittest.skipUnless((ROOT / 'scripts' / 'compose-layout.sh').is_file() and shutil.which('bash'), 'needs the repository scripts directory')
class ComposeLayoutTests(unittest.TestCase):
    WORK = 'work'

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        (self.stub / 'docker').write_text(DOCKER)
        (self.stub / 'docker').chmod(0o755)
        self.work = self.tmp / self.WORK
        (self.work / 'scripts').mkdir(parents=True)
        for name in ('compose-layout.sh', 'enable-redis-auth.sh', 'rotate-field-key.sh'):
            shutil.copy(ROOT / 'scripts' / name, self.work / 'scripts' / name)
            (self.work / 'scripts' / name).chmod(0o755)
        (self.work / 'docker-compose.yml').write_text('services: {}\n')
        (self.work / 'docker-compose.vps.yml').write_text('services: {}\n')
        (self.work / '.env.vps').write_text('X=1\n')
        (self.work / '.env').write_text('POSTGRES_USER=x\n')
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub)}
        for key in [k for k in self.env if k.startswith('CVENGINE_')]:
            self.env.pop(key)

    def run_script(self, name, **env):
        return subprocess.run(['bash', f'scripts/{name}'], cwd=self.work, env={**self.env, **env}, capture_output=True, text=True, timeout=60)

    def calls(self):
        path = self.stub / 'calls'
        return path.read_text().splitlines() if path.exists() else []

    def recreates(self):
        return [c for c in self.calls() if '--force-recreate' in c]

    def test_the_running_stacks_overlay_env_file_and_project_are_used(self):
        (self.stub / 'running_config_files').write_text(f'{self.work}/docker-compose.yml,{self.work}/docker-compose.vps.yml\n')
        (self.stub / 'running_env_file').write_text(f'{self.work}/.env.vps\n')
        (self.stub / 'running_project').write_text('cvengine\n')
        result = self.run_script('enable-redis-auth.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recreates(), ['docker compose --env-file .env.vps -p cvengine -f docker-compose.yml -f docker-compose.vps.yml up -d --force-recreate redis web celery celery-beat proxy'])

    def test_the_redis_password_goes_into_the_env_file_compose_reads(self):
        # Compose fills ${REDIS_PASSWORD} from the env file it is given (.env.vps), not from .env: a password only in .env left Redis open
        (self.stub / 'running_config_files').write_text(f'{self.work}/docker-compose.yml,{self.work}/docker-compose.vps.yml\n')
        (self.stub / 'running_env_file').write_text(f'{self.work}/.env.vps\n')
        result = self.run_script('enable-redis-auth.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        values = {name: [l for l in (self.work / name).read_text().splitlines() if l.startswith('REDIS_PASSWORD=')] for name in ('.env', '.env.vps')}
        self.assertEqual(len(values['.env']), 1)
        self.assertRegex(values['.env'][0], r'^REDIS_PASSWORD=[A-Za-z0-9]{32}$')
        self.assertEqual(values['.env.vps'], values['.env'])
        again = self.run_script('enable-redis-auth.sh')  # a second run keeps the same password in both
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual((self.work / '.env.vps').read_text().count('REDIS_PASSWORD='), 1)
        self.assertEqual({l for l in (self.work / '.env.vps').read_text().splitlines() if l.startswith('REDIS_PASSWORD=')}, set(values['.env']))

    def test_settings_in_env_say_the_layout(self):
        (self.work / '.env').write_text('CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.vps.yml\nCVENGINE_COMPOSE_ENV_FILE=.env.vps\n')
        result = self.run_script('rotate-field-key.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recreates(), ['docker compose --env-file .env.vps -f docker-compose.yml -f docker-compose.vps.yml up -d --force-recreate web celery celery-beat'])
        self.assertFalse([c for c in self.calls() if c.startswith('docker compose -f docker-compose.yml ')])

    def test_a_plain_install_uses_docker_compose_yml(self):
        result = self.run_script('enable-redis-auth.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recreates(), ['docker compose -f docker-compose.yml up -d --force-recreate redis web celery celery-beat proxy'])

    def test_a_running_built_in_scanner_is_recreated_with_celery_whose_network_it_shares(self):
        # the scanner uses network_mode service:celery: a celery that is recreated alone leaves it in a dead namespace where `web` no longer resolves
        # (the Upgrade rehearsal failure after make redis-auth)
        (self.stub / 'scanner_running').touch()
        result = self.run_script('enable-redis-auth.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recreates(), ['docker compose -f docker-compose.yml up -d --force-recreate redis web celery celery-beat proxy scanner'])
        result = self.run_script('rotate-field-key.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recreates()[-1], 'docker compose -f docker-compose.yml up -d --force-recreate web celery celery-beat scanner')

    def test_a_scanner_that_is_not_running_is_not_started_by_these_scripts(self):
        # an install that removed or stopped its scanner (host-fit, an external Sentinel) must not get one back
        for name in ('enable-redis-auth.sh', 'rotate-field-key.sh'):
            self.assertEqual(self.run_script(name).returncode, 0)
        self.assertFalse([c for c in self.recreates() if 'scanner' in c])

    def test_a_running_stack_started_from_files_elsewhere_stops_the_script_before_anything_is_recreated(self):
        (self.stub / 'running_config_files').write_text('/srv/elsewhere/docker-compose.yml\n')
        for name in ('enable-redis-auth.sh', 'rotate-field-key.sh'):
            result = self.run_script(name)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn('CVENGINE_COMPOSE_FILES', result.stderr)
        self.assertEqual(self.recreates(), [])


class ComposeLayoutWithSpacesTests(ComposeLayoutTests):
    """The same, for an installation whose path holds spaces (issue #394: a project under "/Volumes/<two words>" was cut at the first space,
    and every script that recreates or execs a service refused to run)."""
    WORK = 'My Disk/cv engine'

