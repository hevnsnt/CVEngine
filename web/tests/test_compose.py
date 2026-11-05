"""The compose files forward .env to the containers (parsed, so no Docker is needed). Skipped inside the web
container, where only ./web is mounted."""
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

    def test_the_celery_container_can_give_chromium_its_sandbox(self):
        # Playwright's seccomp profile (Docker's default plus user namespaces), vendored unchanged from microsoft/playwright v1.64.1
        import hashlib
        import json
        path = 'config/seccomp/playwright-chromium.json'
        for name in FILES:
            self.assertIn(f'seccomp=./{path}', load(name)['celery'].get('security_opt', []), name)
        data = (ROOT / path).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), 'cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849')
        rule = json.loads(data)['syscalls'][0]
        self.assertEqual((sorted(rule['names']), rule['action']), (['clone', 'setns', 'unshare'], 'SCMP_ACT_ALLOW'))

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
    """The built-in scanner service (docs/BUILTIN-SCANNER.md): on by default, the image scanner.lock.json pins, celery's network namespace, a health check
    on its heartbeats, and the enrollment read from the shared volume by the client itself."""

    @classmethod
    def setUpClass(cls):
        cls.compose = load('docker-compose.yml')
        cls.scanner = cls.compose['scanner']

    def test_it_is_a_default_service_not_behind_a_profile(self):
        self.assertNotIn('profiles', self.scanner)

    def test_it_runs_the_pinned_image_and_never_builds_one(self):
        self.assertTrue(self.scanner['image'].startswith('${CVENGINE_SCANNER_IMAGE:-${CVENGINE_SCANNER_ROLLBACK_IMAGE:-'))
        self.assertNotIn('build', self.scanner)
        self.assertEqual(self.scanner['pull_policy'], 'missing')

    def test_it_shares_celerys_network_namespace(self):
        self.assertEqual(self.scanner['network_mode'], 'service:celery')
        self.assertNotIn('networks', self.scanner)
        self.assertIn('celery', self.scanner['depends_on'])

    def test_it_has_its_raw_socket_capabilities_and_nothing_that_would_block_them(self):
        self.assertEqual(sorted(self.scanner['cap_add']), ['NET_ADMIN', 'NET_RAW'])
        self.assertFalse([o for o in self.scanner.get('security_opt', []) if 'no-new-privileges' in o])

    def test_it_is_built_in_mode_reading_its_enrollment_from_the_shared_volume(self):
        env = self.scanner['environment']
        self.assertEqual(env['CVENGINE_SENTINEL_BUILTIN'], '1')
        self.assertEqual(env['CVENGINE_SENTINEL_BLOB_FILE'], '/bootstrap/blob')
        self.assertNotIn('CVENGINE_SENTINEL_UPDATE', env)  # built-in mode forces it off
        self.assertIn('web', env['NO_PROXY'])
        self.assertIn('scanner_bootstrap:/bootstrap:ro', self.scanner['volumes'])
        self.assertNotIn('entrypoint', self.scanner)

    def test_the_health_check_and_restart_policy_restart_a_wedged_scanner(self):
        self.assertEqual(self.scanner['healthcheck']['test'], ['CMD', 'python3', '-m', 'client.control', 'health'])
        self.assertEqual(self.scanner['healthcheck']['start_period'], '10m')
        self.assertEqual(self.scanner['restart'], 'unless-stopped')

    def test_it_has_a_memory_limit(self):
        self.assertEqual(self.scanner['mem_limit'], '${SCANNER_MEM_LIMIT:-2g}')

    def test_the_host_network_overlay_points_it_at_a_published_web(self):
        overlay = (ROOT / 'docker-compose.hostnet.yml').read_text()  # read as text: it uses Compose's own !reset tag
        self.assertIn('      - CVENGINE_SCANNER_SERVER_URL=http://127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}\n', overlay)
        self.assertIn('  web:\n    ports:\n      - "127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}:8000"\n', overlay)

if __name__ == '__main__':
    unittest.main()
