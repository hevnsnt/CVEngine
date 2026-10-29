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

    def test_the_openvas_feed_containers_come_back_after_a_host_reboot(self):
        services = load('docker-compose.yml')
        for name in ('vulnerability-tests', 'notus-data', 'scap-data', 'cert-bund-data', 'dfn-cert-data', 'data-objects', 'report-formats'):
            self.assertEqual(services[f'openvas-{name}'].get('restart'), 'unless-stopped', name)

    def test_unused_concurrency_variables_are_gone(self):
        for name in FILES + ('.env.example',):
            text = (ROOT / name).read_text()
            self.assertNotIn('MAX_CONCURRENCY', text, name)
            self.assertNotIn('MIN_CONCURRENCY', text, name)


if __name__ == '__main__':
    unittest.main()
