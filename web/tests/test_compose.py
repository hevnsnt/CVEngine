"""The compose files forward .env to the containers (parsed, so no Docker is needed). Skipped inside the web
container, where only ./web is mounted."""
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
FILES = ('docker-compose.yml', 'docker-compose.dev.yml')
APP_SERVICES = ('web', 'celery', 'celery-beat')


def load(name):
    return yaml.safe_load((ROOT / name).read_text())['services']


def env_keys(service):
    return {item.split('=', 1)[0] for item in service.get('environment', [])}


@unittest.skipUnless(yaml and all((ROOT / f).is_file() for f in FILES), 'needs PyYAML and the compose files')
class ComposeEnvTests(unittest.TestCase):
    def test_app_services_read_dot_env_when_present(self):
        for name in FILES:
            for svc in APP_SERVICES:
                self.assertIn({'path': '.env', 'required': False}, load(name)[svc].get('env_file', []), f'{name} {svc}')

    def test_internal_settings_stay_explicit_so_dot_env_cannot_override_them(self):
        # compose lets `environment:` win over `env_file:`
        for name in FILES:
            for svc in APP_SERVICES:
                keys = env_keys(load(name)[svc])
                for required in ('DEBUG', 'CELERY_BROKER', 'CELERY_BACKEND', 'POSTGRES_HOST'):
                    self.assertIn(required, keys, f'{name} {svc} {required}')

    def test_dev_file_forwards_the_target_and_proxy_switches(self):
        for svc in ('web', 'celery'):
            keys = env_keys(load('docker-compose.dev.yml')[svc])
            self.assertIn('CVENGINE_ALLOW_PRIVATE_TARGETS', keys)
            self.assertIn('CVENGINE_TRUSTED_PROXIES', keys)

    def test_the_celery_container_has_an_init_process_and_time_to_stop_its_workers(self):
        # the entrypoint turns SIGTERM into a warm shutdown and exits when a worker dies; both need a PID 1 that behaves
        for name in FILES:
            celery = load(name)['celery']
            self.assertIs(celery.get('init'), True, name)
            self.assertEqual(celery.get('stop_grace_period'), '60s', name)

    def test_the_openvas_feed_containers_come_back_after_a_host_reboot(self):
        services = load('docker-compose.yml')
        for name in ('vulnerability-tests', 'notus-data', 'scap-data', 'cert-bund-data', 'dfn-cert-data', 'data-objects', 'report-formats'):
            self.assertEqual(services[f'openvas-{name}'].get('restart'), 'unless-stopped', name)

    def test_unused_concurrency_variables_are_gone(self):
        for name in FILES + ('.env.example',):
            text = (ROOT / name).read_text()
            self.assertNotIn('MAX_CONCURRENCY', text, name)
            self.assertNotIn('MIN_CONCURRENCY', text, name)


@unittest.skipUnless(yaml and (ROOT / 'docker-compose.yml').is_file(), 'needs PyYAML and the compose file')
class BuiltinScannerComposeTests(unittest.TestCase):
    """The optional built-in scanner service (docs/SCANNER-ARCHITECTURE.md): built from a pinned Sentinel commit, and it waits for the server's enrollment."""

    @classmethod
    def setUpClass(cls):
        cls.scanner = load('docker-compose.yml')['scanner']

    def script(self):
        return self.scanner['entrypoint'][2].replace('$$', '$')

    def test_it_stays_behind_its_profile_and_keeps_the_image_name(self):
        self.assertEqual(self.scanner['profiles'], ['builtin-scanner'])
        self.assertIn('${CVENGINE_SCANNER_IMAGE:-', self.scanner['image'])

    def test_the_default_build_context_is_a_pinned_commit_never_a_branch(self):
        context = self.scanner['build']['context']
        self.assertRegex(context, r'^\$\{CVENGINE_SCANNER_SOURCE:-https://[^#}]+\.git#[0-9a-f]{40}\}$')

    def test_the_build_keeps_the_git_directory_so_the_version_stamp_is_the_commit(self):
        self.assertEqual(self.scanner['build']['args'], {'BUILDKIT_CONTEXT_KEEP_GIT_DIR': '1'})

    def test_the_start_period_covers_the_wait_for_the_enrollment(self):
        self.assertEqual(self.scanner['healthcheck']['start_period'], '10m')

    def test_the_entrypoint_waits_for_the_blob_only_without_a_persisted_token(self):
        script = self.script()
        self.assertIn('[ ! -s /var/lib/cvengine-sentinel/token.json ]', script)
        self.assertIn('waiting for the server to write the enrollment; needs CVENGINE_BUILTIN_SCANNER=1 and an App Admin', script)
        self.assertEqual(script.count('waiting for the server'), 1)  # one line, not one per poll
        self.assertLess(script.index('waiting for the server'), script.index('while '))
        self.assertLess(script.index('while '), script.index('CVENGINE_SENTINEL_BLOB='))
        self.assertTrue(script.rstrip().endswith('exec /opt/sentinel/docker-entrypoint.sh python3 -m client'))

    def test_the_entrypoint_is_valid_shell(self):
        subprocess.run(['sh', '-n'], input=self.script(), text=True, check=True)

    def run_entrypoint(self, token=False, blob=None, patience=0):
        """Run the extracted script over stand-in paths, with the final `exec` replaced by an echo of what the scanner would have started with."""
        with tempfile.TemporaryDirectory() as tmp:
            state, boot = Path(tmp, 'state'), Path(tmp, 'bootstrap')
            state.mkdir()
            boot.mkdir()
            if token:
                (state / 'token.json').write_text('{}')
            if blob is not None:
                (boot / 'blob').write_text(blob)
            script = (self.script().replace('/var/lib/cvengine-sentinel', str(state)).replace('/bootstrap', str(boot))
                      .replace('-lt 300', f'-lt {patience}').replace('sleep 2', 'sleep 0'))
            script = script.replace('exec /opt/sentinel/docker-entrypoint.sh python3 -m client', 'echo "started blob=${CVENGINE_SENTINEL_BLOB:-none}"')
            return subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=30, check=True).stdout.splitlines()

    def test_without_a_token_or_blob_it_logs_once_waits_then_proceeds(self):
        out = self.run_entrypoint(patience=5)
        self.assertEqual(len([line for line in out if line.startswith('waiting for the server')]), 1)
        self.assertEqual(out[-1], 'started blob=none')

    def test_with_a_persisted_token_it_does_not_wait(self):
        self.assertEqual(self.run_entrypoint(token=True, patience=5), ['started blob=none'])

    def test_with_a_blob_it_does_not_wait_and_passes_it_on(self):
        self.assertEqual(self.run_entrypoint(blob='abc123', patience=5), ['started blob=abc123'])


if __name__ == '__main__':
    unittest.main()
