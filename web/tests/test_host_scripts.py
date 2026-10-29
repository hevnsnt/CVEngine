"""Host-side scripts that run as root: the state helper's OpenVAS actions, the installer checks and the workflows. Skipped inside the web
container, where only ./web is mounted."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'
HAVE_SCRIPTS = SCRIPTS.joinpath('update-state.py').is_file()


@unittest.skipUnless(HAVE_SCRIPTS, 'needs the repository scripts directory')
class OpenvasStateTests(unittest.TestCase):
    """The OpenVAS switch runs as root on a directory the web container can write: it must never follow a link planted there."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'web').mkdir()
        self.victim = self.tmp / 'host-only'
        self.victim.write_text('keep me')

    def state(self, *args):
        return subprocess.run(['python3', '-I', str(SCRIPTS / 'update-state.py'), *args], cwd=self.tmp, capture_output=True, text=True)

    def answer(self, **extra):
        return json.dumps({'want': 'on', 'state': 'ok', 'ok': True, 'error': '', 'at': 1700000000, **extra})

    def test_the_answer_replaces_a_planted_link_instead_of_writing_through_it(self):
        for name in ('.openvas-applied', '.openvas-applied.tmp'):
            (self.tmp / 'web' / name).symlink_to(self.victim)
        result = self.state('openvas-applied', self.answer())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.victim.read_text(), 'keep me')
        published = self.tmp / 'web' / '.openvas-applied'
        self.assertFalse(published.is_symlink())
        self.assertEqual(json.loads(published.read_text())['state'], 'ok')

    def test_a_hard_linked_destination_is_replaced_not_written(self):
        os.link(self.victim, self.tmp / 'web' / '.openvas-applied')
        self.assertEqual(self.state('openvas-applied', self.answer()).returncode, 0)
        self.assertEqual(self.victim.read_text(), 'keep me')

    def test_only_the_documented_answer_is_published(self):
        for bad in ('not json', '[]', self.answer(want='sideways'), self.answer(state='maybe'), self.answer(ok='yes'), self.answer(error='x' * 201)):
            self.assertEqual(self.state('openvas-applied', bad).returncode, 1, bad)
        self.assertFalse((self.tmp / 'web' / '.openvas-applied').exists())

    def test_the_log_tail_replaces_a_planted_link(self):
        (self.tmp / 'web' / '.openvas-log').symlink_to(self.victim)
        private = self.tmp / 'private.log'
        private.write_bytes(b'x' * 100000 + b'last line\n')
        self.assertEqual(self.state('openvas-log', str(private)).returncode, 0)
        self.assertEqual(self.victim.read_text(), 'keep me')
        published = (self.tmp / 'web' / '.openvas-log').read_bytes()
        self.assertTrue(published.endswith(b'last line\n'))
        self.assertLessEqual(len(published), 65536)

    def test_the_request_is_read_without_following_links_and_only_on_or_off_count(self):
        wanted = self.tmp / 'web' / '.openvas-wanted'
        wanted.write_text('on\n')
        self.assertEqual(self.state('openvas-wanted').stdout.strip(), 'on')
        wanted.write_text('off')
        self.assertEqual(self.state('openvas-wanted').stdout.strip(), 'off')
        wanted.write_text('rm -rf /')
        self.assertEqual(self.state('openvas-wanted').stdout.strip(), '')
        wanted.unlink()
        self.victim.write_text('on')
        wanted.symlink_to(self.victim)
        self.assertEqual(self.state('openvas-wanted').stdout.strip(), '')

    def test_nothing_outside_the_publisher_writes_into_web(self):
        sync = (SCRIPTS / 'openvas-sync.sh').read_text()
        watch = (SCRIPTS / 'update-watch.sh').read_text()
        for text in (sync, watch):
            self.assertNotRegex(text, r'>>?\s*"?web/')  # a plain redirection into the shared mount follows links, as root
        self.assertNotIn('$APPLIED.tmp', sync)
        self.assertNotIn('mv -f', sync)


@unittest.skipUnless(HAVE_SCRIPTS and os.geteuid() == 0 and shutil.which('git'), 'needs root and git')
class RootOwnershipTests(unittest.TestCase):
    """cron and systemd start the updater as root with no SUDO_UID; git refuses another user's repository ("dubious ownership") unless told."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.env = {k: v for k, v in os.environ.items() if k != 'SUDO_UID'}
        self.env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        (self.tmp / 'scripts').mkdir()
        (self.tmp / 'web').mkdir()
        for name in ('update-state.py', 'install-updater.sh', 'apply-update.sh', 'update-watch.sh'):
            shutil.copy(SCRIPTS / name, self.tmp / 'scripts' / name)
        subprocess.run(['git', 'init', '-q', str(self.tmp)], check=True, env=self.env)
        subprocess.run(['chown', '-R', '1000:1000', str(self.tmp)], check=True)

    def test_the_state_helper_finds_its_directory_in_a_checkout_owned_by_someone_else(self):
        result = subprocess.run(['python3', '-I', 'scripts/update-state.py', 'directory'], cwd=self.tmp, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip().endswith('.git/cvengine-update'))

    def test_the_watcher_installs_when_it_can_start_the_way_cron_starts_it(self):
        stub = self.tmp / 'stub'
        stub.mkdir()
        (stub / 'crontab').write_text('#!/bin/sh\n[ "$1" = "-l" ] && exit 0\ncat > "$STUB_CRON"\n')
        (stub / 'crontab').chmod(0o755)
        env = {**self.env, 'PATH': f'{stub}:{os.environ["PATH"]}', 'STUB_CRON': str(self.tmp / 'cron'), 'CVENGINE_NO_START': '1'}
        result = subprocess.run(['bash', 'scripts/install-updater.sh'], cwd=self.tmp, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('update-watch.sh', (self.tmp / 'cron').read_text())


@unittest.skipUnless(HAVE_SCRIPTS, 'needs the repository scripts directory')
class InstallerCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'scripts').mkdir()
        shutil.copy(SCRIPTS / 'init-env.sh', self.tmp / 'scripts' / 'init-env.sh')
        shutil.copy(ROOT / '.env.example', self.tmp / '.env.example')
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub), 'CVENGINE_DETECT_IP': '10.1.2.3'}

    def docker(self, body):
        (self.stub / 'docker').write_text('#!/bin/sh\necho "docker $*" >> "$STUB_DIR/calls"\n' + body)
        (self.stub / 'docker').chmod(0o755)

    def init_env(self):
        result = subprocess.run(['bash', 'scripts/init-env.sh'], cwd=self.tmp, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return (self.tmp / '.env').read_text()

    def redis_password(self, text):
        return [line.split('=', 1)[1] for line in text.splitlines() if line.startswith('REDIS_PASSWORD=')][-1]

    def test_another_stacks_redis_container_does_not_leave_a_new_install_with_an_open_broker(self):
        # the old test was "any container name on this host contains redis"; Compose's own labels say whose container it is
        self.docker('case "$*" in *"--filter"*) ;; *) echo myapp-redis-1; echo openvas-redis;; esac\nexit 0\n')
        self.assertNotEqual(self.redis_password(self.init_env()), '')

    def test_an_installation_with_its_own_redis_keeps_its_open_broker_until_make_redis_auth(self):
        self.docker('case "$*" in *"com.docker.compose.service=redis"*) echo abc123;; esac\nexit 0\n')
        self.assertEqual(self.redis_password(self.init_env()), '')
        self.assertIn('label=com.docker.compose.project.working_dir=', (self.stub / 'calls').read_text())

    def test_secrets_are_not_put_on_awks_command_line(self):
        for name in ('init-env.sh', 'enable-redis-auth.sh', 'rotate-field-key.sh'):
            text = (SCRIPTS / name).read_text()
            self.assertNotIn('-v value=', text, name)
            self.assertIn('ENVIRON["CVENGINE_AWK_VALUE"]', text, name)
        env = self.init_env()
        self.assertEqual(len(self.redis_password(env)), 24)

    def test_the_installer_refuses_a_compose_that_is_too_old_and_names_the_requirement(self):
        text = (ROOT / 'install.sh').read_text()
        self.assertIn('compose version --short', text)
        self.assertIn('needs 2.24 or newer', text)


@unittest.skipUnless(yaml and (ROOT / '.github' / 'workflows').is_dir(), 'needs PyYAML and the workflows')
class WorkflowTests(unittest.TestCase):
    def load(self, name):
        return yaml.safe_load((ROOT / '.github' / 'workflows' / name).read_text())

    def steps(self, workflow, job):
        return {step.get('name', ''): step for step in self.load(workflow)['jobs'][job]['steps']}

    def test_every_workflow_parses(self):
        for path in sorted((ROOT / '.github' / 'workflows').glob('*.yml')):
            self.assertIsInstance(yaml.safe_load(path.read_text()), dict, path.name)

    def test_a_pushed_tag_must_be_on_master_and_an_existing_tag_is_built_from_the_tag(self):
        text = (ROOT / '.github' / 'workflows' / 'release.yml').read_text()
        self.assertIn('compare/master...$SHA', text)  # the push event is checked, not only the manual run
        self.assertIn('refs/tags/$TAG', text)
        self.assertNotRegex(text, r'git archive[^\n]*\bHEAD\b')  # the archives are of the tag, not of whatever the checkout is on
        self.assertIn('git checkout --quiet "refs/tags/$TAG"', text)

    def test_the_tool_checks_send_a_token_for_the_github_api(self):
        for workflow in ('tool-release-gate.yml', 'tool-releases.yml', 'release.yml'):
            self.assertIn('GITHUB_TOKEN: ${{ github.token }}', (ROOT / '.github' / 'workflows' / workflow).read_text(), workflow)

    def test_a_model_change_without_a_migration_fails_the_build(self):
        steps = self.steps('build-pr.yml', 'security-tests')
        self.assertIn('makemigrations --check --dry-run', steps['No model change without its migration']['run'])


if __name__ == '__main__':
    unittest.main()
