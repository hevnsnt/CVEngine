"""The web interface certificate: its lifetime, its automatic renewal before it expires (certs/entrypoint.sh, scripts/renew-certs.sh), and the
warnings the app shows (Settings > Updates, get_system_status)."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / 'certs' / 'entrypoint.sh'
DAY = 86400


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def openssl(*args, **kw):
    return subprocess.run(['openssl', *args], capture_output=True, text=True, **kw)


@unittest.skipUnless(shutil.which('sh') and shutil.which('openssl'), 'needs sh and openssl')
class EntrypointTests(unittest.TestCase):
    """certs/entrypoint.sh against a real openssl, in a temporary directory instead of /certs."""

    ENV = {'AUTHORITY_PASSWORD': 'test-pass', 'AUTHORITY_NAME': 'Test CA', 'COMPANY': 'Co', 'COUNTRY_CODE': 'XX', 'STATE': 'S', 'CITY': 'C',
           'DOMAIN_NAME': '10.0.0.5'}

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix='cvengine-certs-test-')
        cls.legacy = os.path.join(cls.base, 'legacy')  # what an older install holds: a 10-year certificate
        cls.run_script(cls.legacy, CERT_VALID_DAYS='3650')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    @classmethod
    def run_script(cls, directory, **env):
        done = subprocess.run(['sh', str(ENTRYPOINT)], capture_output=True, text=True,
                              env={**os.environ, **cls.ENV, 'CERT_DIR': directory, **env})
        assert done.returncode == 0, done.stdout + done.stderr
        return done.stdout

    def fresh_copy(self):
        directory = tempfile.mkdtemp(dir=self.base)
        os.rmdir(directory)
        shutil.copytree(self.legacy, directory)
        return directory

    def lifetime_days(self, pem):
        """The days from now until the certificate ends, found with -checkend alone (no date arithmetic): the largest whole number of days it survives."""
        days = 0
        for step in (4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1):
            if openssl('x509', '-in', pem, '-noout', '-checkend', str((days + step) * DAY)).returncode == 0:
                days += step
        return days

    def pubkey(self, pem):
        return openssl('x509', '-in', pem, '-noout', '-pubkey').stdout

    def test_the_first_run_creates_the_authority_and_a_397_day_certificate(self):
        directory = os.path.join(self.base, 'first')
        out = self.run_script(directory)
        self.assertIn('cert-result: issued', out)
        pem = os.path.join(directory, 'rengine.pem')
        self.assertEqual(self.lifetime_days(pem), 396)  # valid for 397 days from a moment ago: 396 whole days remain
        self.assertEqual(openssl('verify', '-CAfile', os.path.join(directory, 'ca.crt'), pem).returncode, 0)
        san = openssl('x509', '-in', pem, '-noout', '-ext', 'subjectAltName').stdout
        self.assertIn('IP Address:10.0.0.5', san)
        self.assertIn('DNS:localhost', san)
        self.assertRegex(out, r'cert-not-after: \w{3} +\d+ [\d:]+ \d{4} GMT')

    def test_a_ten_year_certificate_is_reissued_once_with_the_same_key_authority_names_and_file(self):
        directory = self.fresh_copy()
        pem, key = os.path.join(directory, 'rengine.pem'), os.path.join(directory, 'rengine_rsa.key')
        self.assertGreater(self.lifetime_days(pem), 3000)
        before = {'key': sha(key), 'ca': sha(os.path.join(directory, 'ca.crt')), 'cakey': sha(os.path.join(directory, 'ca.key')),
                  'pub': self.pubkey(pem), 'inode': os.stat(pem).st_ino, 'chain_inode': os.stat(os.path.join(directory, 'rengine_chain.pem')).st_ino,
                  'san': openssl('x509', '-in', pem, '-noout', '-ext', 'subjectAltName').stdout}
        out = self.run_script(directory)
        self.assertIn('cert-result: issued', out)
        self.assertIn('more than 400 days', out)
        self.assertEqual(self.lifetime_days(pem), 396)
        self.assertEqual(sha(key), before['key'])  # same key
        self.assertEqual(self.pubkey(pem), before['pub'])
        self.assertEqual(sha(os.path.join(directory, 'ca.crt')), before['ca'])  # the authority is never touched
        self.assertEqual(sha(os.path.join(directory, 'ca.key')), before['cakey'])
        self.assertEqual(openssl('x509', '-in', pem, '-noout', '-ext', 'subjectAltName').stdout, before['san'])  # same names
        self.assertEqual(openssl('verify', '-CAfile', os.path.join(directory, 'ca.crt'), pem).returncode, 0)
        # in place: the proxy's bind mounts follow the file, so a new file would stay invisible to it
        self.assertEqual(os.stat(pem).st_ino, before['inode'])
        self.assertEqual(os.stat(os.path.join(directory, 'rengine_chain.pem')).st_ino, before['chain_inode'])
        again = self.run_script(directory)  # and it is now left alone
        self.assertIn('cert-result: kept', again)

    def test_a_certificate_with_plenty_of_time_is_left_alone(self):
        directory = self.fresh_copy()
        self.run_script(directory)  # now a 397 day one
        pem = os.path.join(directory, 'rengine.pem')
        before = sha(pem)
        out = self.run_script(directory)
        self.assertIn('cert-result: kept', out)
        self.assertEqual(sha(pem), before)

    def test_a_certificate_with_fewer_than_30_days_left_is_renewed_and_one_with_more_is_not(self):
        directory = self.fresh_copy()
        self.run_script(directory, CERT_VALID_DAYS='29')
        pem = os.path.join(directory, 'rengine.pem')
        self.assertEqual(self.lifetime_days(pem), 28)
        out = self.run_script(directory)
        self.assertIn('cert-result: issued', out)
        self.assertIn('fewer than 30 days remain', out)
        self.assertEqual(self.lifetime_days(pem), 396)
        again = self.fresh_copy()
        self.run_script(again, CERT_VALID_DAYS='60')
        before = sha(os.path.join(again, 'rengine.pem'))
        self.assertIn('cert-result: kept', self.run_script(again))
        self.assertEqual(sha(os.path.join(again, 'rengine.pem')), before)

    def test_new_names_get_a_new_certificate_for_the_same_key(self):
        directory = self.fresh_copy()
        self.run_script(directory)
        pem = os.path.join(directory, 'rengine.pem')
        pub = self.pubkey(pem)
        out = self.run_script(directory, CERT_EXTRA_SANS='scan.example.test')
        self.assertIn('it does not cover scan.example.test', out)
        self.assertIn('DNS:scan.example.test', openssl('x509', '-in', pem, '-noout', '-ext', 'subjectAltName').stdout)
        self.assertEqual(self.pubkey(pem), pub)
        out = self.run_script(directory, DOMAIN_NAME='10.0.0.9', CERT_EXTRA_SANS='scan.example.test')
        self.assertIn('IP Address:10.0.0.9', openssl('x509', '-in', pem, '-noout', '-ext', 'subjectAltName').stdout)

    def test_a_certificate_not_signed_by_this_authority_or_for_another_key_is_replaced(self):
        directory = self.fresh_copy()
        self.run_script(directory)
        other = os.path.join(self.base, 'other-authority')
        self.run_script(other)  # a second authority
        shutil.copyfile(os.path.join(other, 'rengine.pem'), os.path.join(directory, 'rengine.pem'))
        out = self.run_script(directory)
        self.assertIn('not signed by this authority', out)
        self.assertEqual(openssl('verify', '-CAfile', os.path.join(directory, 'ca.crt'), os.path.join(directory, 'rengine.pem')).returncode, 0)

    def test_renewing_only_ours_never_replaces_a_certificate_another_authority_issued_and_never_creates_an_authority(self):
        directory = self.fresh_copy()
        other = os.path.join(self.base, 'other-authority-by-name')
        self.run_script(other, AUTHORITY_NAME='Some Public CA')
        pem = os.path.join(directory, 'rengine.pem')
        shutil.copyfile(os.path.join(other, 'rengine.pem'), pem)  # as a Let's Encrypt certificate someone installed would be
        before = {name: sha(os.path.join(directory, name)) for name in os.listdir(directory)}
        out = self.run_script(directory, CERT_ONLY_OURS='1', CERT_FORCE='1')
        self.assertIn('cert-result: external', out)
        self.assertEqual({name: sha(os.path.join(directory, name)) for name in os.listdir(directory)}, before)
        bare = os.path.join(self.base, 'bare')
        os.makedirs(bare)
        shutil.copyfile(pem, os.path.join(bare, 'rengine.pem'))
        self.assertIn('cert-result: external', self.run_script(bare, CERT_ONLY_OURS='1'))
        self.assertEqual(os.listdir(bare), ['rengine.pem'])  # no authority was made
        # asked for explicitly (make certs, the installer) it replaces it, as it always did
        self.assertIn('cert-result: issued', self.run_script(directory))

    def test_renewing_only_ours_still_renews_our_own(self):
        directory = self.fresh_copy()
        self.assertIn('cert-result: issued', self.run_script(directory, CERT_ONLY_OURS='1'))
        self.assertIn('cert-result: kept', self.run_script(directory, CERT_ONLY_OURS='1'))

    def test_force_reissues(self):
        directory = self.fresh_copy()
        self.run_script(directory)
        self.assertIn('CERT_FORCE=1', self.run_script(directory, CERT_FORCE='1'))

    def test_a_failed_signature_leaves_the_certificate_in_place(self):
        directory = self.fresh_copy()
        self.run_script(directory)
        pem = os.path.join(directory, 'rengine.pem')
        before = sha(pem)
        done = subprocess.run(['sh', str(ENTRYPOINT)], capture_output=True, text=True,
                              env={**os.environ, **self.ENV, 'CERT_DIR': directory, 'CERT_FORCE': '1', 'AUTHORITY_PASSWORD': 'wrong password'})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(sha(pem), before)
        self.assertEqual(openssl('verify', '-CAfile', os.path.join(directory, 'ca.crt'), pem).returncode, 0)


FAKE_DOCKER = '''#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls"
case " $* " in
  *" ps -a --filter "*) exit 0;;
  *" compose version"*) exit 0;;
  *" ps --status running --services "*) printf 'web\\nproxy\\n'; exit 0;;
  *" run --rm -T --no-deps -e CERT_ONLY_OURS=1 certs"*) cat "$STUB_DIR/certs_output"; exit "$(cat "$STUB_DIR/certs_status" 2>/dev/null || echo 0)";;
  *" exec -T proxy nginx -s reload"*) test ! -e "$STUB_DIR/reload_fails"; exit $?;;
esac
exit 0
'''


@unittest.skipUnless(shutil.which('git') and shutil.which('flock') and shutil.which('python3'), 'needs git, flock and python3')
class RenewScriptTests(unittest.TestCase):
    """scripts/renew-certs.sh in a throwaway checkout with a stub docker."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cvengine-renew-test-'))
        self.addCleanup(shutil.rmtree, self.dir, True)
        for name in ('renew-certs.sh', 'compose-layout.sh', 'update-state.py'):
            (self.dir / 'scripts').mkdir(exist_ok=True)
            shutil.copy(ROOT / 'scripts' / name, self.dir / 'scripts' / name)
        (self.dir / 'web').mkdir()
        (self.dir / 'secrets' / 'certs').mkdir(parents=True)
        (self.dir / 'secrets' / 'certs' / 'rengine.pem').write_text('x')
        for name in ('docker-compose.yml', 'docker-compose.setup.yml'):
            (self.dir / name).write_text('services: {}\n')
        self.stub = self.dir / 'stub'
        self.stub.mkdir()
        (self.stub / 'docker').write_text(FAKE_DOCKER)
        (self.stub / 'docker').chmod(0o755)
        self.env = {'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub), 'HOME': str(self.dir),
                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull}
        subprocess.run(['git', 'init', '-q'], cwd=self.dir, check=True, env=self.env)
        self.certs('cert-result: kept\ncert-not-after: Nov 30 00:33:02 2027 GMT\n')

    def certs(self, output, status=0):
        (self.stub / 'certs_output').write_text(output)
        (self.stub / 'certs_status').write_text(str(status))

    def run_script(self, *args, **env):
        return subprocess.run(['bash', 'scripts/renew-certs.sh', *args], cwd=self.dir, capture_output=True, text=True, env={**self.env, **env})

    def calls(self):
        path = self.stub / 'calls'
        return path.read_text().splitlines() if path.exists() else []

    def status(self):
        return json.loads((self.dir / 'web' / '.cert-status.json').read_text())

    def test_a_certificate_that_is_still_good_is_checked_published_and_the_proxy_left_alone(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        certs_call, = [c for c in self.calls() if ' run ' in c]
        self.assertIn('-f docker-compose.setup.yml', certs_call)
        self.assertNotIn('-f docker-compose.yml', certs_call)  # the certs service lives in its own file
        self.assertFalse([c for c in self.calls() if 'nginx' in c])
        row = self.status()
        self.assertEqual((row['result'], row['error']), ('kept', ''))
        self.assertEqual(row['not_after'], 1827534782.0)  # Nov 30 00:33:02 2027 GMT
        self.assertIsNone(row['renewed_at'])

    def test_an_issued_certificate_is_loaded_by_a_reload_not_a_restart(self):
        self.certs('Creating new certificate\ncert-result: issued\ncert-not-after: Nov 30 00:33:02 2027 GMT\n')
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue([c for c in self.calls() if c.endswith('exec -T proxy nginx -s reload')])
        self.assertFalse([c for c in self.calls() if 'force-recreate' in c])
        row = self.status()
        self.assertEqual(row['result'], 'issued')
        self.assertGreater(row['renewed_at'], time.time() - 60)

    def test_a_reload_that_fails_falls_back_to_recreating_the_proxy_and_says_so_when_that_fails_too(self):
        self.certs('cert-result: issued\ncert-not-after: Nov 30 00:33:02 2027 GMT\n')
        (self.stub / 'reload_fails').write_text('')
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue([c for c in self.calls() if 'up -d --no-deps --force-recreate proxy' in c])
        self.assertIn('recreated', done.stdout)

    def test_a_certificate_someone_else_issued_is_reported_as_such_and_the_proxy_left_alone(self):
        self.certs('cert-result: external\ncert-not-after: Nov 30 00:33:02 2027 GMT\n')
        self.assertEqual(self.run_script().returncode, 0)
        self.assertFalse([c for c in self.calls() if 'nginx' in c or 'force-recreate' in c])
        self.assertEqual(self.status()['result'], 'external')

    def test_the_certs_run_asks_to_renew_only_our_own(self):
        self.run_script()
        certs_call, = [c for c in self.calls() if ' run ' in c]
        self.assertIn('-e CERT_ONLY_OURS=1', certs_call)

    def test_no_reload_leaves_the_proxy_to_the_caller(self):
        self.certs('cert-result: issued\ncert-not-after: Nov 30 00:33:02 2027 GMT\n')
        self.assertEqual(self.run_script('--no-reload').returncode, 0)
        self.assertFalse([c for c in self.calls() if 'nginx' in c or 'force-recreate' in c])
        self.assertEqual(self.status()['result'], 'issued')

    def test_a_failure_is_published_and_retried_within_the_hour_not_the_next_day(self):
        self.certs('Could not sign the certificate; the one in place was not changed.\n', status=1)
        done = self.run_script()
        self.assertEqual(done.returncode, 1)
        row = self.status()
        self.assertEqual(row['result'], 'failed')
        self.assertIn('Could not sign', row['error'])
        state = subprocess.run(['python3', 'scripts/update-state.py', 'directory'], cwd=self.dir, capture_output=True, text=True, env=self.env).stdout.strip()
        due = int((Path(state) / 'cert-next-check').read_text())
        self.assertLessEqual(due - time.time(), 3600 + 5)

    def test_if_due_does_nothing_until_the_next_check_is_due(self):
        self.assertEqual(self.run_script('--if-due').returncode, 0)
        first = len(self.calls())
        self.assertGreater(first, 0)
        self.assertEqual(self.run_script('--if-due').returncode, 0)
        self.assertEqual(len(self.calls()), first)  # not due yet: no docker call at all
        self.assertEqual(self.run_script('--if-due', CVENGINE_CERT_CHECK_SECONDS='0').returncode, 0)
        self.assertEqual(len(self.calls()), first)  # the interval of the run that wrote the file stands: still not due
        state = subprocess.run(['python3', 'scripts/update-state.py', 'directory'], cwd=self.dir, capture_output=True, text=True, env=self.env).stdout.strip()
        (Path(state) / 'cert-next-check').write_text(str(int(time.time()) - 1))
        self.assertEqual(self.run_script('--if-due').returncode, 0)
        self.assertGreater(len(self.calls()), first)

    def test_an_install_without_the_bundled_authority_is_left_alone(self):
        (self.dir / 'secrets' / 'certs' / 'rengine.pem').unlink()
        done = self.run_script()
        self.assertEqual((done.returncode, self.calls(), (self.dir / 'web' / '.cert-status.json').exists()), (0, [], False))

    def test_the_stacks_project_and_env_file_are_used_for_the_certs_run(self):
        (self.dir / '.env.production').write_text('A=1\n')
        done = self.run_script(CVENGINE_COMPOSE_PROJECT='mystack', CVENGINE_COMPOSE_ENV_FILE='.env.production')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        certs_call, = [c for c in self.calls() if ' run ' in c]
        self.assertIn('--env-file .env.production', certs_call)
        self.assertIn('-p mystack', certs_call)

    def test_it_is_started_by_the_watcher_the_auto_deploy_timer_and_both_update_paths(self):
        for name in ('update-watch.sh', 'auto-deploy.sh', 'update-deploy.sh', 'update.sh'):
            self.assertIn('renew-certs.sh', (ROOT / 'scripts' / name).read_text(), name)

    def test_shell_syntax(self):
        for name in ('renew-certs.sh', 'update-watch.sh', 'auto-deploy.sh', 'update-deploy.sh', 'update.sh'):
            self.assertEqual(subprocess.run(['bash', '-n', str(ROOT / 'scripts' / name)]).returncode, 0, name)
        self.assertEqual(subprocess.run(['sh', '-n', str(ENTRYPOINT)]).returncode, 0)


@unittest.skipUnless(shutil.which('git') and shutil.which('python3'), 'needs git and python3')
class CertStatusPublishTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cvengine-certstatus-test-'))
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / 'web').mkdir()

    def publish(self, *args):
        return subprocess.run(['python3', str(ROOT / 'scripts' / 'update-state.py'), 'cert-status', *args], cwd=self.dir, capture_output=True, text=True)

    def row(self):
        return json.loads((self.dir / 'web' / '.cert-status.json').read_text())

    def test_the_earlier_end_date_and_renewal_time_are_kept_when_a_check_cannot_say(self):
        self.assertEqual(self.publish('issued', 'Nov 30 00:33:02 2027 GMT', '').returncode, 0)
        renewed = self.row()['renewed_at']
        self.assertEqual(self.publish('failed', '', 'docker is not available').returncode, 0)
        row = self.row()
        self.assertEqual((row['result'], row['error'], row['not_after'], row['renewed_at']), ('failed', 'docker is not available', 1827534782.0, renewed))
        self.publish('kept', 'Dec  1 00:00:00 2027 GMT', '')
        self.assertEqual(self.row()['renewed_at'], renewed)

    def test_odd_input_is_refused(self):
        self.assertNotEqual(self.publish('maybe', '', '').returncode, 0)
        self.assertNotEqual(self.publish('kept', 'x' * 100, '').returncode, 0)
        self.assertNotEqual(self.publish('failed', '', 'e' * 300).returncode, 0)
        self.assertFalse((self.dir / 'web' / '.cert-status.json').exists())


class CertificateStatusTests(TestCase):
    NOW = 1_800_000_000.0

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        override = override_settings(BASE_DIR=self.dir)
        override.enable()
        self.addCleanup(override.disable)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def report(self, **row):
        row = {'checked_at': self.NOW - 3600, 'result': 'kept', 'error': '', 'not_after': self.NOW + 300 * DAY, 'renewed_at': None, **row}
        Path(self.dir, '.cert-status.json').write_text(json.dumps(row))

    def read(self):
        from cveFeed import updater
        return updater.certificate(now=self.NOW)

    def test_nothing_reported_means_nothing_is_claimed(self):
        out = self.read()
        self.assertEqual((out['known'], out['problem'], out['state']), (False, None, 'unknown'))

    def test_a_healthy_certificate_reports_its_days_and_no_problem(self):
        self.report(renewed_at=self.NOW - 10 * DAY)
        out = self.read()
        self.assertEqual((out['known'], out['days_left'], out['state'], out['problem']), (True, 300, 'ok', None))
        self.assertTrue(out['last_renewed_at'].startswith('2027'))

    def test_under_30_days_is_a_warning_and_so_is_expired(self):
        self.report(not_after=self.NOW + 12 * DAY + 100)
        out = self.read()
        self.assertEqual((out['days_left'], out['state']), (12, 'expiring'))
        self.assertIn('expires in 12 days', out['problem'])
        self.report(not_after=self.NOW + 30 * DAY + 100)
        self.assertIsNone(self.read()['problem'])
        self.report(not_after=self.NOW - 3 * DAY)
        out = self.read()
        self.assertEqual(out['state'], 'expired')
        self.assertIn('has expired', out['problem'])

    def test_an_external_certificate_that_is_running_out_says_it_is_not_renewed_here(self):
        self.report(result='external', not_after=self.NOW + 9 * DAY + 100)
        problem = self.read()['problem']
        self.assertIn('expires in 9 days', problem)
        self.assertIn('not renewed automatically', problem)
        self.assertNotIn('renew-certs.sh', problem)  # nothing here would renew it
        self.report(result='external')
        self.assertIsNone(self.read()['problem'])

    def test_a_failed_renewal_and_a_silent_check_are_problems_even_with_time_left(self):
        self.report(result='failed', error='the certs service failed: no space left')
        out = self.read()
        self.assertIn('no space left', out['problem'])
        self.assertEqual(out['days_left'], 300)
        self.report(checked_at=self.NOW - 5 * DAY)
        self.assertIn('has not run for 5 days', self.read()['problem'])

    def test_garbage_is_unknown_not_an_error(self):
        Path(self.dir, '.cert-status.json').write_text('[1,2')
        self.assertFalse(self.read()['known'])
        Path(self.dir, '.cert-status.json').write_text(json.dumps({'checked_at': 'soon'}))
        self.assertFalse(self.read()['known'])
        Path(self.dir, '.cert-status.json').write_text(json.dumps({'checked_at': float('inf'), 'not_after': 1}))
        self.assertFalse(self.read()['known'])

    def test_the_updates_page_state_carries_it(self):
        from cveFeed import updater
        self.report(not_after=time.time() + 5 * DAY)
        with mock.patch.object(updater, 'installed_sha', return_value=''):
            from cveFeed.models import UpdateSettings
            state = updater.state(UpdateSettings())
        self.assertEqual(state['certificate']['state'], 'expiring')


class SystemStatusCertificateTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        from agentapi.auth import create_token
        cls.root = User.objects.create_superuser('certroot', 'r@x.io', 'x')
        cls.member = User.objects.create_user('certmember', password='x')
        _, cls.t_root = create_token(cls.root, 'root')
        _, cls.t_member = create_token(cls.member, 'member')

    def status(self, token, certificate):
        from tests.test_agentapi import call
        from tests.test_system_status import patched
        a, b, c = patched()
        with a, b, c, mock.patch('cveFeed.updater.certificate', return_value=certificate):
            return call(token, 'GET', '/api/v1/system/status')[1]

    def test_an_expiring_certificate_is_a_problem_for_an_app_admin_and_invisible_to_others(self):
        report = {'known': True, 'days_left': 9, 'state': 'expiring', 'problem': 'The web interface certificate expires in 9 days; it should have been renewed.'}
        data = self.status(self.t_root, report)
        self.assertEqual(data['system']['certificate']['days_left'], 9)
        self.assertTrue([p for p in data['problems'] if p.startswith('certificate: The web interface certificate expires in 9 days')])
        self.assertEqual(data['overall'], 'degraded')
        member = self.status(self.t_member, report)
        self.assertIsNone(member['system'])
        self.assertFalse([p for p in member['problems'] if p.startswith('certificate')])

    def test_a_healthy_certificate_adds_no_problem(self):
        data = self.status(self.t_root, {'known': True, 'days_left': 300, 'state': 'ok', 'problem': None})
        self.assertEqual(data['system']['certificate']['state'], 'ok')
        self.assertFalse([p for p in data['problems'] if p.startswith('certificate')])
