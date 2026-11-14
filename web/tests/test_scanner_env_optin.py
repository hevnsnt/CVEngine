"""The built-in scanner is on by default and needs nothing in .env: a default install.sh / init-env.sh writes the same .env as before, and the
opt-out (--no-builtin-scanner) writes only CVENGINE_BUILTIN_SCANNER=0. CVENGINE_LOCAL_FALLBACK is never written."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNER_KEYS = ('COMPOSE_PROFILES', 'CVENGINE_BUILTIN_SCANNER', 'CVENGINE_LOCAL_FALLBACK', 'SCANNER_MEM_LIMIT')
GENERATED = ('POSTGRES_PASSWORD', 'AUTHORITY_PASSWORD', 'CVENGINE_FIELD_KEY', 'REDIS_PASSWORD', 'DOMAIN_NAME')
STUBS = {
    'id': '#!/bin/sh\n[ "$1" = "-u" ] && echo 0 || /usr/bin/id "$@"\n',
    'docker': '#!/bin/sh\ncase "$1" in --version) echo "Docker version 27.0.1, build x";; esac\nexit 0\n',
    'make': '#!/bin/sh\ncase "$1" in certs) mkdir -p secrets/certs; echo x > secrets/certs/rengine.pem;; admin) printf "====\\nPassword  : Abc123Xyz\\n====\\n";; esac\nexit 0\n',
    'curl': '#!/bin/sh\ncase "$*" in *http_code*) printf "302";; esac\nexit 0\n',
    'sleep': '#!/bin/sh\nexit 0\n',
}


def active(text):
    """The uncommented KEY=value lines of an env file, as a dict."""
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.lstrip().startswith('#'))


def commented(text, key):
    return any(line.startswith(f'# {key}=') for line in text.splitlines())


class EnvExampleTests(unittest.TestCase):
    def test_the_scanner_settings_are_commented_examples_only(self):
        text = (ROOT / '.env.example').read_text()
        for key in SCANNER_KEYS:
            self.assertNotIn(key, active(text), f'{key} must not be active in .env.example')
        self.assertTrue(commented(text, 'CVENGINE_BUILTIN_SCANNER'))
        self.assertFalse(commented(text, 'CVENGINE_LOCAL_FALLBACK'))  # ignored since 1.4: no example to copy, only a line saying so
        self.assertIn('CVENGINE_LOCAL_FALLBACK is ignored since 1.4', text)
        self.assertTrue(commented(text, 'SCANNER_MEM_LIMIT'))
        self.assertNotIn('COMPOSE_PROFILES=builtin-scanner', text)


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class InitEnvTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        (self.dir / 'scripts').mkdir()
        shutil.copy(ROOT / 'scripts' / 'init-env.sh', self.dir / 'scripts' / 'init-env.sh')
        shutil.copy(ROOT / '.env.example', self.dir / '.env.example')

    def init(self, **env):
        base = {k: v for k, v in os.environ.items() if k not in SCANNER_KEYS + ('CVENGINE_ENABLE_BUILTIN_SCANNER',)}
        return subprocess.run(['bash', 'scripts/init-env.sh'], cwd=self.dir, capture_output=True, text=True, check=True,
                              env={**base, 'CVENGINE_DETECT_IP': '10.1.2.3', **env}).stdout

    def env(self):
        return active((self.dir / '.env').read_text())

    def test_the_default_env_is_the_example_plus_the_generated_values_and_nothing_about_the_scanner(self):
        out = self.init()
        env = self.env()
        example = active((ROOT / '.env.example').read_text())
        self.assertEqual(set(env) - set(example), set(), 'init-env.sh added a setting the example does not have')
        self.assertEqual(set(example) - set(env), set())
        for key, value in example.items():
            if key not in GENERATED:
                self.assertEqual(env[key], value, f'{key} changed from the example')
        for key in SCANNER_KEYS:
            self.assertNotIn(key, env)
        self.assertNotIn('scanner', out.lower())

    def test_an_empty_or_one_is_the_default(self):
        self.init()
        baseline = {k: v for k, v in self.env().items() if k not in GENERATED}
        for value in ('', '1'):
            (self.dir / '.env').unlink(missing_ok=True)
            self.init(CVENGINE_ENABLE_BUILTIN_SCANNER=value)
            self.assertEqual({k: v for k, v in self.env().items() if k not in GENERATED}, baseline)

    def test_opting_out_writes_the_switch_off_and_never_the_local_fallback(self):
        out = self.init(CVENGINE_ENABLE_BUILTIN_SCANNER='0')
        env = self.env()
        self.assertEqual(env['CVENGINE_BUILTIN_SCANNER'], '0')
        self.assertNotIn('CVENGINE_LOCAL_FALLBACK', env)
        self.assertNotIn('COMPOSE_PROFILES', env)
        self.assertIn('stays off', out)

    def test_an_owner_set_switch_is_left_alone(self):
        (self.dir / '.env').write_text('CVENGINE_BUILTIN_SCANNER=1\nCVENGINE_LOCAL_FALLBACK=none\nPOSTGRES_PASSWORD=x\nAUTHORITY_PASSWORD=y\n')
        self.init(CVENGINE_ENABLE_BUILTIN_SCANNER='0')
        self.assertEqual(self.env()['CVENGINE_BUILTIN_SCANNER'], '1')
        self.assertEqual(self.env()['CVENGINE_LOCAL_FALLBACK'], 'none')


@unittest.skipUnless(shutil.which('bash') and Path('/proc/meminfo').exists(), 'needs bash on Linux')
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = self.tmp / 'repo'
        (self.repo / 'scripts').mkdir(parents=True)
        for rel in ('install.sh', 'scripts/init-env.sh', 'scripts/host-fit.sh', '.env.example'):
            shutil.copy(ROOT / rel, self.repo / rel)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        for name, body in STUBS.items():
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        base = {k: v for k, v in os.environ.items() if k not in SCANNER_KEYS + ('CVENGINE_ENABLE_BUILTIN_SCANNER',)}
        self.env = {**base, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'CVENGINE_DETECT_IP': '10.1.2.3', 'CVENGINE_INSTALL_PORTS': ''}  # the host's own 443 may be taken: the stubs need no ports
        self.env.pop('CI', None)  # GitHub Actions sets CI, which (rightly) silences the question

    def install(self, *args):
        return subprocess.run(['bash', 'install.sh', *args], cwd=self.repo, capture_output=True, text=True, env=self.env, timeout=60)

    def scanner_free(self):
        return {k: v for k, v in active((self.repo / '.env').read_text()).items() if k != 'SCANNER_MEM_LIMIT'}  # set on a small host

    def test_a_plain_install_writes_the_same_env_as_init_env_with_no_scanner_switch(self):
        proc = self.install()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        env = self.scanner_free()
        for key in SCANNER_KEYS:
            self.assertNotIn(key, env)
        self.assertEqual(set(env), set(active((ROOT / '.env.example').read_text())))

    def test_the_old_opt_in_flag_is_accepted_and_changes_nothing(self):
        proc = self.install('--builtin-scanner')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', self.scanner_free())

    def test_the_opt_out_flag_turns_it_off(self):
        proc = self.install('--no-builtin-scanner')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.scanner_free()['CVENGINE_BUILTIN_SCANNER'], '0')

    def test_a_small_host_gets_a_smaller_scanner_limit(self):
        # the rule is scripts/host-fit.sh's, shared with the updater (tests/test_host_fit_script.py runs it); install.sh calls it
        self.assertIn('cvengine_fit_memory .env', (self.repo / 'install.sh').read_text())
        self.assertIn('cv_fit_small_kb=7000000', (ROOT / 'scripts' / 'host-fit.sh').read_text())

    def test_the_port_check_still_refuses_a_busy_port_and_defaults_to_443_and_8082(self):
        import socket
        text = (ROOT / 'install.sh').read_text()
        self.assertIn('https_port=${https_port:-443}', text)
        self.assertIn('http_port=${http_port:-8082}', text)
        self.assertIn('CVENGINE_INSTALL_PORTS-$https_port $http_port', text)
        if not shutil.which('ss'):
            self.skipTest('needs ss')
        with socket.socket() as busy:
            busy.bind(('127.0.0.1', 0))
            busy.listen(1)
            self.env['CVENGINE_INSTALL_PORTS'] = str(busy.getsockname()[1])
            proc = self.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('is already in use', proc.stdout + proc.stderr)
        self.assertFalse((self.repo / '.env').exists())

    def test_help_mentions_the_opt_out(self):
        proc = self.install('-h')
        self.assertIn('--no-builtin-scanner', proc.stdout)


@unittest.skipUnless(shutil.which('bash') and Path('/proc/meminfo').exists(), 'needs bash on Linux')
class SentinelChoiceTests(InstallTests):
    """install.sh --sentinels and the one question (asked only on a terminal)."""

    def install_tty(self, answers, *args, env=None):
        """Run the installer with a pseudo terminal as stdin and stdout, typing ANSWERS (one string per line) at its prompts."""
        import pty
        import select
        import time
        master, slave = pty.openpty()
        proc = subprocess.Popen(['bash', 'install.sh', *args], cwd=self.repo, stdin=slave, stdout=slave, stderr=slave,
                                env={**self.env, **(env or {})}, close_fds=True)
        os.close(slave)
        out, pending, deadline = b'', list(answers), time.time() + 60
        while time.time() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if pending and out.rstrip().endswith(b']:'):  # "Choose 1, 2 or 3 [1]:"
                    os.write(master, pending.pop(0).encode() + b'\n')
                    out += b'<<typed>>'
            elif proc.poll() is not None:
                break
        proc.wait(timeout=30)
        os.close(master)
        return proc, out.decode(errors='replace')

    def test_internal_is_the_default_and_writes_nothing_about_the_scanner(self):
        proc = self.install('--sentinels=internal')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for key in SCANNER_KEYS + ('CVENGINE_SENTINEL_PLAN',):
            self.assertNotIn(key, self.scanner_free())
        self.assertNotIn('external Sentinels only', proc.stdout)
        self.assertIn('setup continues in the browser', proc.stdout)

    def test_external_turns_the_built_in_scanner_off_and_says_so_on_the_finish_screen(self):
        proc = self.install('--sentinels=external')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.scanner_free()['CVENGINE_BUILTIN_SCANNER'], '0')
        self.assertIn('as chosen', proc.stdout)

    def test_both_keeps_the_scanner_on_records_the_plan(self):
        proc = self.install('--sentinels', 'both')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        env = self.scanner_free()
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', env)
        self.assertEqual(env['CVENGINE_SENTINEL_PLAN'], 'both')
        self.assertIn('plus external Sentinels', proc.stdout)

    def test_a_bad_or_conflicting_choice_is_refused_before_anything_runs(self):
        for args in (('--sentinels=bogus',), ('--sentinels=both', '--no-builtin-scanner'), ('--sentinels',)):
            proc = self.install(*args)
            self.assertNotEqual(proc.returncode, 0, args)
            self.assertFalse((self.repo / '.env').exists(), args)

    def test_a_rerun_keeps_the_choice_and_a_flag_switches_it(self):
        self.install('--sentinels=external')
        proc = self.install()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.scanner_free()['CVENGINE_BUILTIN_SCANNER'], '0')
        self.assertIn('external Sentinels only', proc.stdout)
        proc = self.install('--sentinels=internal')
        self.assertEqual(self.scanner_free()['CVENGINE_BUILTIN_SCANNER'], '1')
        self.assertNotIn('external Sentinels only', proc.stdout)

    def test_openvas_is_never_installed_or_started(self):
        proc = self.install('--sentinels=both')
        self.assertIn('OpenVAS:   not installed', proc.stdout)
        self.assertFalse([k for k, v in active((self.repo / '.env').read_text()).items() if 'openvas' in (k + v).lower()])
        self.assertNotIn('COMPOSE_PROFILES', self.scanner_free())

    def test_the_question_on_a_terminal_has_three_answers(self):
        for answer, plan in (('1', None), ('', None), ('2', 'both'), ('3', 'external'), ('external', 'external')):
            with self.subTest(answer=answer):
                (self.repo / '.env').unlink(missing_ok=True)
                proc, out = self.install_tty([answer])
                self.assertEqual(proc.returncode, 0, out)
                self.assertIn('Will you add external Sentinels', out)
                self.assertIn('Built-in scanner only', out)
                env = self.scanner_free()
                if plan == 'external':
                    self.assertEqual(env['CVENGINE_BUILTIN_SCANNER'], '0')
                elif plan == 'both':
                    self.assertEqual(env['CVENGINE_SENTINEL_PLAN'], 'both')
                else:
                    self.assertNotIn('CVENGINE_BUILTIN_SCANNER', env)
                    self.assertNotIn('CVENGINE_SENTINEL_PLAN', env)

    def test_a_wrong_answer_asks_again_and_three_wrong_ones_take_the_default(self):
        proc, out = self.install_tty(['x', '3'])
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn('Please type 1, 2 or 3', out)
        self.assertEqual(self.scanner_free()['CVENGINE_BUILTIN_SCANNER'], '0')
        (self.repo / '.env').unlink()
        proc, out = self.install_tty(['x', 'y', 'z'])
        self.assertIn('Taking the default', out)
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', self.scanner_free())

    def test_nothing_is_asked_without_a_terminal_or_with_n_or_ci_or_a_flag_or_an_earlier_choice(self):
        proc = self.install()  # no terminal: the safe default, no prompt
        self.assertNotIn('Will you add', proc.stdout)
        for label, args, env in (('-n', ('-n',), None), ('--non-interactive', ('--non-interactive',), None), ('CI', (), {'CI': 'true'}),
                                 ('flag', ('--sentinels=internal',), None)):
            with self.subTest(label=label):
                (self.repo / '.env').unlink(missing_ok=True)
                proc, out = self.install_tty([], *args, env=env)
                self.assertEqual(proc.returncode, 0, out)
                self.assertNotIn('Will you add', out)
        with self.subTest(label='earlier choice'):
            (self.repo / '.env').write_text('CVENGINE_BUILTIN_SCANNER=0\n')
            proc, out = self.install_tty([])
            self.assertNotIn('Will you add', out)
            self.assertIn('keeping the scanner choice already in .env', out)
        with self.subTest(label='existing installation'):
            (self.repo / '.env').write_text('POSTGRES_PASSWORD=abc\nAUTHORITY_PASSWORD=def\n')
            proc, out = self.install_tty([])
            self.assertNotIn('Will you add', out)
            self.assertIn('existing installation', out)

    def test_help_documents_the_flag_and_that_openvas_is_never_installed(self):
        out = self.install('-h').stdout
        for word in ('--sentinels', 'internal', 'both', 'external', '--non-interactive', 'OpenVAS is never installed'):
            self.assertIn(word, out)


class OpenvasOffByDefaultTests(unittest.TestCase):
    def test_no_openvas_service_starts_without_its_profile(self):
        text = (ROOT / 'docker-compose.yml').read_text()
        import re
        blocks = re.findall(r'\n  (openvas-[a-z-]+):\n(.*?)(?=\n  [a-z#]|\Z)', text, re.S)
        self.assertGreaterEqual(len(blocks), 10)
        for name, block in blocks:
            self.assertIn('profiles: ["openvas"]', block, name)

    def test_no_profile_is_active_in_the_example_and_make_up_names_no_openvas_service(self):
        self.assertNotIn('COMPOSE_PROFILES', active((ROOT / '.env.example').read_text()))
        make = (ROOT / 'Makefile').read_text()
        services = next(line for line in make.splitlines() if line.startswith('SERVICES '))
        self.assertNotIn('openvas', services)

    def test_the_installer_never_starts_or_names_openvas_services(self):
        text = (ROOT / 'install.sh').read_text()
        self.assertNotIn('openvas-up', text)
        self.assertNotIn('--profile', text)
        self.assertNotIn('openvas-sync', text)


class ReviewerImageReadableTests(unittest.TestCase):
    def test_the_package_is_made_readable_for_the_unprivileged_user(self):
        text = (ROOT / 'reviewer' / 'Dockerfile').read_text()
        self.assertLess(text.index('COPY cvengine_reviewer'), text.index('chmod -R a+rX'))
        self.assertLess(text.index('chmod -R a+rX'), text.index('USER 10002'))

