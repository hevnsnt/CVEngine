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
        self.assertTrue(commented(text, 'CVENGINE_LOCAL_FALLBACK'))
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
        for rel in ('install.sh', 'scripts/init-env.sh', '.env.example'):
            shutil.copy(ROOT / rel, self.repo / rel)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        for name, body in STUBS.items():
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        base = {k: v for k, v in os.environ.items() if k not in SCANNER_KEYS + ('CVENGINE_ENABLE_BUILTIN_SCANNER',)}
        self.env = {**base, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'CVENGINE_DETECT_IP': '10.1.2.3'}

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
        text = (self.repo / 'install.sh').read_text()
        self.assertIn("printf 'SCANNER_MEM_LIMIT=1g\\n' >> .env", text)
        self.assertIn('-lt 7000000', text)

    def test_help_mentions_the_opt_out(self):
        proc = self.install('-h')
        self.assertIn('--no-builtin-scanner', proc.stdout)
