"""The two halves of hosted single sign-on meet here (hosted/ scripts and nginx on one side, web/hostedsso on the other): each test runs the real script
or the real management command and feeds its output to the real application code, so a disagreement between the two sides shows up as a failure.
No network, no Docker daemon, no secrets (the script stubs of test_hosted_mode stand in for docker and friends)."""
import json
import shlex
import time
from io import StringIO
from pathlib import Path

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, override_settings

from hostedsso import gating
from hostedsso.models import SsoIdentity
from hostedsso.verify import ASSERTION, LOGOUT, SsoError, verify
from tests.test_hosted_mode import ScriptCase
from tests.test_hosted_sso import EDGE, FixedVectorTests, settings_probe

ENV_HEAD = 'CVENGINE_HOSTED=1\nCVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.hosted.yml\nDOMAIN_NAME=s-abcd1234.cvengine.live\n'


class ScriptedCase(ScriptCase, TestCase):
    """ScriptCase (scripts under stubs) with a database for the application side."""

    ready = True

    def setUp(self):
        super().setUp()
        if self.ready:
            self.state.mkdir()
            (self.state / 'ready').write_text('x\n')
        self.write_env('CVENGINE_SSO=0\nCVENGINE_SSO_ENFORCE=0\n')

    def write_env(self, extra=''):
        (self.repo / '.env').write_text(ENV_HEAD + extra)


class BreakGlassEndToEndTests(ScriptedCase):
    """cvl-sso-mode.sh writes CVENGINE_SSO_BREAKGLASS_UNTIL; the settings and hostedsso.gating read it."""

    def window(self, minutes):
        self.assertEqual(self.run_script('cvl-set-sso-keys.sh', json.dumps({'keys': [{'kid': 'a', 'kty': 'OKP', 'crv': 'Ed25519', 'x': 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE', 'status': 'current'}]})).returncode, 0)
        before = int(time.time())
        done = self.run_script('cvl-sso-mode.sh', '', ['--sso', 'on', '--enforce', 'on', '--breakglass', str(minutes)], CVL_NOW=str(before))
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        value = self.env_file()['CVENGINE_SSO_BREAKGLASS_UNTIL']
        self.assertRegex(value, r'^[0-9]{10}$')  # Unix seconds, digits only
        self.assertEqual((report['breakglass_until'], int(value)), (before + minutes * 60, before + minutes * 60))
        return before, value

    def test_the_value_the_script_writes_is_the_integer_the_settings_read(self):
        env = self.env_file()
        for minutes in (1, 30, 60):
            before, value = self.window(minutes)
            env = self.env_file()
            got = settings_probe(CVENGINE_HOSTED=env['CVENGINE_HOSTED'], CVENGINE_SSO=env['CVENGINE_SSO'], CVENGINE_SSO_ENFORCE=env['CVENGINE_SSO_ENFORCE'],
                                 CVENGINE_SSO_BREAKGLASS_UNTIL=value)
            self.assertEqual((got['CVENGINE_SSO'], got['CVENGINE_SSO_ENFORCE'], got['CVENGINE_SSO_BREAKGLASS_UNTIL']), (True, True, int(value)), minutes)
            self.assertIs(type(got['CVENGINE_SSO_BREAKGLASS_UNTIL']), int)
            with override_settings(CVENGINE_SSO_BREAKGLASS_UNTIL=got['CVENGINE_SSO_BREAKGLASS_UNTIL']):
                self.assertTrue(gating.breakglass_active(now=before + 5), minutes)  # open, even for the longest window the script allows (60 min)
                self.assertTrue(gating.breakglass_active(now=before + minutes * 60 - 1), minutes)
                self.assertFalse(gating.breakglass_active(now=before + minutes * 60), minutes)  # closed at the stated second

    def test_the_login_page_follows_the_window_the_script_opened(self):
        before, value = self.window(30)
        with override_settings(CVENGINE_HOSTED=True, CVENGINE_SSO=True, CVENGINE_SSO_ENFORCE=True, CVENGINE_SSO_BREAKGLASS_UNTIL=int(value), ALLOWED_HOSTS=['*']):
            self.assertEqual(Client().get('/login/', **EDGE).status_code, 200)  # open and through the edge: the form is offered
            refused = Client().get('/login/?next=/cve/p/')  # open but not through the edge: still refused
            self.assertEqual((refused.status_code, refused['Location']), (302, '/_cvl/start?next=%2Fcve%2Fp%2F'))
        with override_settings(CVENGINE_HOSTED=True, CVENGINE_SSO=True, CVENGINE_SSO_ENFORCE=True, CVENGINE_SSO_BREAKGLASS_UNTIL=int(value) - 3600, ALLOWED_HOSTS=['*']):
            self.assertEqual(Client().get('/login/', **EDGE).status_code, 302)  # the window has passed

    def test_off_removes_the_setting_and_the_application_sees_it_closed(self):
        self.window(10)
        done = self.run_script('cvl-sso-mode.sh', '', ['--breakglass', 'off'])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn('CVENGINE_SSO_BREAKGLASS_UNTIL', self.env_file())
        got = settings_probe(CVENGINE_HOSTED='1', CVENGINE_SSO='1', CVENGINE_SSO_ENFORCE='1')
        self.assertEqual(got['CVENGINE_SSO_BREAKGLASS_UNTIL'], 0)
        with override_settings(CVENGINE_SSO_BREAKGLASS_UNTIL=0):
            self.assertFalse(gating.breakglass_active())


class LinkThroughThePersonalizeScriptTests(ScriptedCase):
    """cvl-personalize.sh calls ``manage.py link_sso_identity --email=<e> --subject=<s>``: run exactly that argv through the real command."""

    GOOD = {'customer_slug': 'acme', 'email': 'owner@acme.example'}

    def argv(self, subject, **env):
        self.write_env('CVENGINE_SSO=1\n')
        done = self.run_script('cvl-personalize.sh', json.dumps({**self.GOOD, 'sso_subject': subject}), **env)
        self.assertEqual(done.returncode, 0, done.stderr)
        links = [e for e in self.events() if e.startswith('link ')]
        self.assertTrue(links)
        return shlex.split(links[-1].split('manage.py link_sso_identity', 1)[1])

    def run_link(self, argv):
        out = StringIO()
        call_command('link_sso_identity', *argv, stdout=out)
        return out.getvalue().strip()

    def test_the_exact_argv_of_the_script_is_accepted_and_a_retry_is_idempotent(self):
        user = User.objects.create_user('admin', 'Owner@Acme.Example', 'x')
        subject = '3f2b8c1e-5d4a-4e7b-9a10-6c2d8e4f1a77'
        argv = self.argv(subject)
        self.assertEqual(argv, ['--email=owner@acme.example', f'--subject={subject}'])
        self.assertEqual(self.run_link(argv), 'linked')
        self.assertEqual(self.run_link(argv), 'already linked')  # the provisioner retried the whole script
        identity = SsoIdentity.objects.get()
        self.assertEqual((identity.user, identity.subject, identity.issuer), (user, subject, 'https://cvengine.live'))

    def test_every_subject_the_script_accepts_the_command_accepts(self):
        User.objects.create_user('admin', 'owner@acme.example', 'x')
        for subject in ('abcdefgh', 'A' * 64, 'u-1_2-3_4', '0' * 8, '--email-x'):
            argv = self.argv(subject)
            self.assertEqual(argv[1], f'--subject={subject}')
            self.run_link(argv)
            self.assertEqual(SsoIdentity.objects.get().subject, subject)
            SsoIdentity.objects.all().delete()

    def test_a_retry_with_a_different_subject_is_refused_not_silently_moved(self):
        User.objects.create_user('admin', 'owner@acme.example', 'x')
        self.run_link(self.argv('first-subject-1'))
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            self.run_link(self.argv('second-subject-2'))
        self.assertEqual(SsoIdentity.objects.get().subject, 'first-subject-1')


class KeyFileThroughTheScriptsTests(ScriptedCase):
    ready = False
    """The key file the scripts install is the one the verifier reads (same path default, same format)."""

    def test_the_default_path_is_the_same_on_both_sides_and_the_compose_mount(self):
        got = settings_probe()
        self.assertEqual(got['CVENGINE_SSO_KEYS_FILE'], '/etc/cvl/sso-keys.json')
        compose = (Path(__file__).resolve().parents[2] / 'docker-compose.hosted.yml').read_text()
        self.assertIn('${CVL_SSO_KEYS_FILE:-/etc/cvl/sso-keys.json}:/etc/cvl/sso-keys.json:ro', compose)

    def vector(self):
        return json.loads(FixedVectorTests.VECTOR.read_text())

    def test_a_key_set_pushed_by_the_script_verifies_the_fixed_vector(self):
        data = self.vector()
        done = self.run_script('cvl-set-sso-keys.sh', json.dumps(data['jwks']))
        self.assertEqual(done.returncode, 0, done.stderr)
        target = self.etc / 'sso-keys.json'
        aud = data['assertion']['claims']['aud']
        with override_settings(CVENGINE_SSO_KEYS_FILE=str(target), CVENGINE_SSO_AUDIENCE=aud, CVENGINE_SSO_ISSUER=data['assertion']['claims']['iss']):
            self.assertEqual(verify(data['assertion']['jws'], ASSERTION, now=data['assertion']['now'])['sub'], data['assertion']['claims']['sub'])
            self.assertEqual(verify(data['logout']['jws'], LOGOUT, now=data['logout']['now'])['aud'], aud)
            # the same file replaced in place by an empty set (revoke everything): nothing verifies any more
            done = self.run_script('cvl-set-sso-keys.sh', json.dumps({'keys': []}))
            self.assertEqual(done.returncode, 0, done.stderr)
            with self.assertRaises(SsoError), self.assertLogs('hostedsso.verify', 'WARNING'):
                verify(data['assertion']['jws'], ASSERTION, now=data['assertion']['now'])

    def test_the_stock_file_first_boot_writes_verifies_nothing(self):
        data = self.vector()
        device = self.tmp / 'volume-device'
        device.write_text('')
        done = self.run_script('cvl-firstboot.sh', CVL_VOLUME_DEVICE=str(device), CVL_ORIGIN_HOST='s-abcd1234.cvengine.live')
        self.assertEqual(done.returncode, 0, done.stderr)
        target = self.etc / 'sso-keys.json'
        self.assertEqual(json.loads(target.read_text()), {'keys': []})
        with override_settings(CVENGINE_SSO_KEYS_FILE=str(target), CVENGINE_SSO_AUDIENCE=data['assertion']['claims']['aud']):
            with self.assertRaises(SsoError), self.assertLogs('hostedsso.verify', 'WARNING'):
                verify(data['assertion']['jws'], ASSERTION, now=data['assertion']['now'])
