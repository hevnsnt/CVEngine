"""install.sh against stub tools (no Docker needed) and the certificate name list."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

STUBS = {
    'id': '#!/bin/sh\n[ "$1" = "-u" ] && echo 0 || /usr/bin/id "$@"\n',
    'docker': '#!/bin/sh\ncase "$1" in --version) echo "Docker version 27.0.1, build x";; esac\n[ -e "$STUB_DIR/no_daemon" ] && [ "$1" = info ] && exit 1\nexit 0\n',
    'make': '''#!/bin/sh
echo "make $1" >> "$STUB_DIR/calls"
case "$1" in
 admin) printf 'docker compose exec -T web python3 manage.py create_admin\\n====\\n  CVEngine admin account\\n    Password  : Abc123Xyz\\n====\\n';;
 certs) mkdir -p secrets/certs; echo x > secrets/certs/rengine.pem;;
 build) [ -e "$STUB_DIR/build_fails" ] && exit 2;;
esac
exit 0
''',
    'curl': '#!/bin/sh\ncase "$*" in *http_code*) printf "%s" "${STUB_HTTP:-302}";; esac\nexit 0\n',
    'sleep': '#!/bin/sh\nexit 0\n',
}


@unittest.skipUnless(shutil.which('bash') and Path('/proc/meminfo').exists(), 'needs bash on Linux')
class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = self.tmp / 'repo'
        (self.repo / 'scripts').mkdir(parents=True)
        for rel in ('install.sh', 'scripts/init-env.sh', '.env.example'):
            shutil.copy(ROOT / rel, self.repo / rel)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        for name, body in STUBS.items():
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub),
                    'CVENGINE_DETECT_IP': '10.1.2.3'}

    def run_install(self, *args, **env):
        proc = subprocess.run(['bash', 'install.sh', *args], cwd=self.repo, capture_output=True, text=True,
                              env={**self.env, **env}, timeout=60)
        calls = (self.stub / 'calls').read_text().split() if (self.stub / 'calls').exists() else []
        return proc, calls

    def test_a_clean_machine_gets_one_summary_with_the_address_and_password(self):
        proc, _ = self.run_install()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('https://10.1.2.3/', proc.stdout)
        self.assertIn('Password  : Abc123Xyz', proc.stdout)
        self.assertNotIn('docker compose exec', proc.stdout)  # make's command echo is not shown
        self.assertIn('DOMAIN_NAME=10.1.2.3', (self.repo / '.env').read_text())

    def test_it_runs_the_steps_in_order(self):
        _, calls = self.run_install()
        order = [c for c in calls if c in ('certs', 'build', 'up', 'migrate', 'admin')]
        self.assertEqual(order[:2] + order[-2:], ['certs', 'build', 'migrate', 'admin'])
        self.assertLess(order.index('build'), order.index('up'))

    def test_a_domain_option_is_used(self):
        proc, _ = self.run_install('--domain', 'scanner.example.com')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('https://scanner.example.com/', proc.stdout)

    def test_running_again_keeps_the_secrets_and_the_certificate(self):
        self.run_install()
        first = (self.repo / '.env').read_text()
        proc, calls = self.run_install()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / '.env').read_text(), first)

    def test_a_stopped_docker_daemon_stops_with_the_fix_not_a_stack_trace(self):
        (self.stub / 'no_daemon').write_text('')
        proc, calls = self.run_install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('Docker daemon is not running', proc.stderr)
        self.assertNotIn('build', calls)

    def test_a_failed_build_says_so_and_never_creates_an_admin(self):
        (self.stub / 'build_fails').write_text('')
        proc, calls = self.run_install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('The build failed', proc.stderr)
        self.assertNotIn('admin', calls)

    def test_a_site_that_never_answers_fails_after_waiting(self):
        proc, calls = self.run_install(STUB_HTTP='000')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('did not come up', proc.stderr)
        self.assertNotIn('admin', calls)

    def test_help_and_unknown_options(self):
        self.assertEqual(self.run_install('-h')[0].returncode, 0)
        self.assertNotEqual(self.run_install('--bogus')[0].returncode, 0)


@unittest.skipUnless(shutil.which('sh') and shutil.which('openssl'), 'needs sh and openssl')
class CertificateNamesTests(unittest.TestCase):
    def san(self, name, extra=''):
        script = (ROOT / 'certs' / 'entrypoint.sh').read_text()
        start = script.index('san_list() {')
        func = script[start:script.index('\n}\n', start) + 3]
        return subprocess.run(['sh', '-c', f'{func}\nsan_list "$1"', 'x', name], capture_output=True, text=True,
                              env={**os.environ, 'CERT_EXTRA_SANS': extra}).stdout.strip()

    def test_an_ip_address_gets_an_ip_entry_and_a_name_a_dns_entry(self):
        self.assertEqual(self.san('10.0.0.5'), 'IP:10.0.0.5,DNS:localhost,IP:127.0.0.1')
        self.assertEqual(self.san('scan.example.com:8443'), 'DNS:scan.example.com,DNS:localhost,IP:127.0.0.1')

    def test_extra_names_are_added_once(self):
        self.assertEqual(self.san('localhost', 'a.example,10.0.0.5, a.example'),
                         'DNS:localhost,IP:127.0.0.1,DNS:a.example,IP:10.0.0.5')

    def test_openssl_accepts_the_list_and_records_the_ip(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=t',
                            '-keyout', f'{d}/k', '-out', f'{d}/c', '-addext', f'subjectAltName={self.san("10.0.0.5")}'],
                           check=True, capture_output=True)
            text = subprocess.run(['openssl', 'x509', '-in', f'{d}/c', '-noout', '-text'], capture_output=True, text=True).stdout
            self.assertIn('IP Address:10.0.0.5', text)
            self.assertIn('DNS:localhost', text)
