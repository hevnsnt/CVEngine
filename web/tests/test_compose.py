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

    def test_the_celery_container_carries_no_browser_profile(self):
        # the screenshot browser runs on a Sentinel (kind web_screenshot): the server's own containers keep Docker's default seccomp profile
        for name in FILES:
            for svc in APP_SERVICES:
                self.assertEqual([o for o in load(name)[svc].get('security_opt', []) if 'seccomp' in o], [], f'{name} {svc}')

    def test_no_openvas_container_is_defined_here(self):
        # OpenVAS runs on a Sentinel (kind openvas): the Greenbone containers are the Sentinel's compose file's, not this one's
        self.assertFalse([name for name in load('docker-compose.yml') if name.startswith('openvas')])

    def test_unused_concurrency_variables_are_gone(self):
        for name in FILES + ('.env.example',):
            text = (ROOT / name).read_text()
            self.assertNotIn('MAX_CONCURRENCY', text, name)
            self.assertNotIn('MIN_CONCURRENCY', text, name)


@unittest.skipUnless(yaml and (ROOT / 'docker-compose.yml').is_file(), 'needs PyYAML and the compose file')
class BuiltinScannerComposeTests(unittest.TestCase):
    """The built-in scanner service (docs/BUILTIN-SCANNER.md): on by default, the digest scanner.lock.json pins, a network of its own, a health check
    on its heartbeats, and the enrollment read from the shared volume by the client itself."""

    @classmethod
    def setUpClass(cls):
        cls.compose = load('docker-compose.yml')
        cls.scanner = cls.compose['scanner']

    def test_it_is_a_default_service_not_behind_a_profile(self):
        self.assertNotIn('profiles', self.scanner)

    def test_it_runs_the_pinned_digest_and_never_builds_an_image(self):
        self.assertTrue(self.scanner['image'].startswith('${CVENGINE_SCANNER_IMAGE:-${CVENGINE_SCANNER_ROLLBACK_IMAGE:-'))
        self.assertRegex(self.scanner['image'], r'cvengine-sentinel@sha256:[0-9a-f]{64}\}\}$')
        self.assertNotIn('build', self.scanner)
        self.assertEqual(self.scanner['pull_policy'], '${CVENGINE_SCANNER_PULL_POLICY:-missing}')

    def test_it_has_a_network_of_its_own_shared_only_with_web(self):
        # every scan leaves from here, so the server's containers carry no scan traffic; the scanner reaches web and nothing else of the stack
        self.assertNotIn('network_mode', self.scanner)
        self.assertEqual(self.scanner['networks'], ['scanner_network'])
        self.assertNotIn('celery', self.scanner['depends_on'])
        self.assertIn('web', self.scanner['depends_on'])
        self.assertIn('scanner_network', self.compose['web']['networks'])
        on_it = sorted(name for name, svc in self.compose.items() if 'scanner_network' in (svc.get('networks') or []))
        self.assertEqual(on_it, ['scanner', 'web'])
        for name, svc in self.compose.items():
            self.assertNotEqual(svc.get('network_mode'), 'service:celery', name)

    def test_the_tailscale_sidecar_joins_the_scanner_not_celery(self):
        self.assertEqual(self.compose['tailscale']['network_mode'], 'service:scanner')
        self.assertEqual(self.compose['tailscale']['depends_on'], ['scanner'])

    def test_it_has_the_sentinels_reduced_capability_set_and_nothing_that_would_block_it(self):
        # SN-8, as proven by the Sentinel's own CI (scripts/ci_scan_smoke.sh there): every capability dropped, NET_RAW for nmap's SYN scan, OS detection and UDP
        # sweep and naabu, SYS_CHROOT for Chromium's sandbox. The third entry repeats SYS_CHROOT unless scripts/scanner.sh gives an older image NET_ADMIN.
        self.assertEqual(self.scanner['cap_drop'], ['ALL'])
        # the file as written (nothing is interpolated here): the third entry is the one variable scripts/scanner.sh may set to NET_ADMIN for an older image
        self.assertEqual(self.scanner['cap_add'], ['NET_RAW', 'SYS_CHROOT', '${CVENGINE_SCANNER_EXTRA_CAP:-SYS_CHROOT}'])
        self.assertFalse(self.scanner.get('privileged'))
        # not set, for the reasons in docker-compose.yml: read_only (bbot's ~/.bbot/tools) and no-new-privileges (file capabilities)
        self.assertFalse([o for o in self.scanner.get('security_opt', []) if 'no-new-privileges' in o])
        self.assertFalse(self.scanner.get('read_only'))

    def test_no_overlay_changes_the_scanners_capabilities(self):
        for name in ('docker-compose.hostnet.yml', 'docker-compose.macvlan.yml', 'docker-compose.apparmor.yml', 'docker-compose.dev.yml', 'docker-compose.setup.yml'):
            path = ROOT / name
            if not path.is_file():
                continue
            text = path.read_text()  # not parsed: an overlay may use compose tags (!reset) that a plain YAML reader refuses
            self.assertNotIn('cap_add', text, name)
            self.assertNotIn('cap_drop', text, name)

    def test_the_built_in_scanner_can_give_chromium_its_sandbox(self):
        # Playwright's seccomp profile (Docker's default plus user namespaces), vendored unchanged from microsoft/playwright v1.64.1: the web_screenshot
        # kind runs Chromium in this container, and it proves the sandbox engaged before it opens a page
        import hashlib
        import json
        path = 'config/seccomp/playwright-chromium.json'
        self.assertIn(f'seccomp=./{path}', self.scanner.get('security_opt', []))
        data = (ROOT / path).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), 'cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849')
        rule = json.loads(data)['syscalls'][0]
        self.assertEqual((sorted(rule['names']), rule['action']), (['clone', 'setns', 'unshare'], 'SCMP_ACT_ALLOW'))

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
        self.assertEqual(self.scanner['mem_limit'], '${SCANNER_MEM_LIMIT:-3g}')

    def test_the_host_network_overlay_points_it_at_a_published_web(self):
        overlay = (ROOT / 'docker-compose.hostnet.yml').read_text()  # read as text: it uses Compose's own !reset tag
        self.assertIn('      - CVENGINE_SCANNER_SERVER_URL=http://127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}\n', overlay)
        self.assertIn('  web:\n    ports:\n      - "127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}:8000"\n', overlay)

if __name__ == '__main__':
    unittest.main()
