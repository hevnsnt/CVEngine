"""scripts/rotate-secrets.sh against a fake docker: the order of the steps, a clean environment for every docker call, backups, dry run, refusals.

The fake docker (a Python script first on PATH) records every call with its environment and standard input, keeps the passwords PostgreSQL
and Redis would hold (ALTER ROLE through psql's standard input, the Redis password Compose passes when redis is recreated), and answers
the checks the script makes. Nothing here talks to a real Docker daemon.
"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'
ROTATED = ('POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'CVENGINE_DB_APP_PASSWORD', 'CVENGINE_FIELD_KEY', 'CVENGINE_FIELD_KEY_PREVIOUS', 'RENGINE_SECRET_KEY')

DOCKER = r'''#!/usr/bin/env python3
import json, os, re, sys
from pathlib import Path
STATE = Path(%(state)r)
argv = sys.argv[1:]
stdin = '' if sys.stdin is None or sys.stdin.isatty() else None
def knob(name):
    return (STATE / name).exists()
def load():
    path = STATE / 'db.json'
    return json.loads(path.read_text()) if path.exists() else {}
def save(data):
    (STATE / 'db.json').write_text(json.dumps(data))
def env_value(key, name):
    for line in reversed(Path(name).read_text().splitlines()):
        if line.startswith(key + '='):
            return line.split('=', 1)[1]
    return ''
def record(**extra):
    entry = {'argv': argv, 'env': sorted(os.environ), **extra}
    with open(STATE / 'calls.jsonl', 'a') as handle:
        handle.write(json.dumps(entry) + '\n')

if argv[:1] == ['compose']:
    rest = argv[1:]
    env_file = '.env'
    while rest and rest[0].startswith('-'):
        if rest[0] == '--env-file':
            env_file = rest[1]
        rest = rest[2:] if rest[0] in ('--env-file', '-p', '-f') else rest[1:]
    sub = rest[0] if rest else ''
    if sub == 'exec' and '-c' in rest and 'psycopg2' in ' '.join(rest):
        password = sys.stdin.readline().rstrip('\n')
        record(stdin='<password>')
        sys.exit(0 if load().get('pg', {}).get(rest[-1]) == password else 1)
    snapshot = {}
    if sub == 'up':
        snapshot = {name: Path(name).read_text() for name in ('.env', env_file) if Path(name).exists()}
        snapshot['secret'] = Path('web/secret').read_text() if Path('web/secret').exists() else ''
        if 'redis' in rest:
            data = load(); data['redis'] = env_value('REDIS_PASSWORD', env_file); save(data)
    record(snapshot=snapshot)
    if sub == 'version':
        sys.exit(0)
    if sub == 'ps':
        if '--services' in rest:
            print((STATE / 'running').read_text().strip())
        else:
            print({'db': 'dbid', 'redis': 'redisid'}.get(rest[-1], rest[-1] + 'id'))
        sys.exit(0)
    if sub == 'config':
        if '--services' in rest:
            print('db\nredis\nweb\ncelery\ncelery-beat\nproxy\nscanner\nreviewer')
        else:
            print(json.dumps({'services': {'proxy': {'ports': [{'target': 443, 'published': '443'}]}}}))
        sys.exit(0)
    if sub == 'exec':
        line = ' '.join(rest)
        if 'HTTPConnection' in line:
            sys.exit(0)
        if 'rotate_field_key --check' in line:
            if '--strict' in line and knob('strict_fail'):
                print('Stored secrets: 2 under the current key, 1 under an older key, 0 unreadable.'); sys.exit(1)
            if '--strict' not in line and knob('unreadable'):
                print('Stored secrets: 2 under the current key, 0 under an older key, 1 unreadable.'); sys.exit(1)
            print('Stored secrets: 3 under the current key, 0 under an older key, 0 unreadable.')
            sys.exit(0)
        if 'rotate_field_key' in line:
            print('3 row(s) re-encrypted.')
            sys.exit(0)
        if 'db_app_role status' in line:
            print('app cvengine_app')
            sys.exit(0)
    sys.exit(0)

if argv[:1] == ['exec']:
    interactive = '-i' in argv[:3]
    data = sys.stdin.read() if interactive else ''
    line = ' '.join(argv)
    if 'redisid' in argv:
        if interactive:
            record(stdin='<password>')
            print('PONG' if data.strip() == load().get('redis') else 'NOAUTH Authentication required.')
        else:
            record()
            print('PONG' if knob('redis_open') else 'NOAUTH Authentication required.')
        sys.exit(0)
    record(stdin=data)
    if 'pg_isready' in line:
        sys.exit(0)
    if 'pg_roles' in line:
        print('1')
        sys.exit(0)
    if 'pg_dump' in line:
        sys.stdout.write('PGDMP fake custom format dump')
        sys.exit(0)
    if 'pg_restore' in line and '--list' in line:
        print('3456; 0 16385 TABLE DATA public auth_user postgres')
        sys.exit(0)
    if 'psql' in line and interactive:
        if knob('alter_fail'):
            sys.exit(3)
        db = load()
        for role, password in re.findall(r'ALTER ROLE "([^"]+)" WITH PASSWORD \'([^\']*)\'', data):
            db.setdefault('pg', {})[role] = password
        save(db)
        sys.exit(0)
    sys.exit(0)
record()
sys.exit(0)
'''

CURL = '#!/bin/sh\nprintf 200\n'

# Dummy values of the fixture install. Plain names on purpose: they are what the test files get written with (CodeQL reads a value reached
# through a password or secret name as real clear text storage; these are not).
V_PG, V_REDIS, V_APP, V_FIELD, V_DJANGO = 'oldpg', 'oldredis', 'oldapp', 'oldfieldkey', 'old-django-secret'
OLD = {
    'POSTGRES_PASSWORD': V_PG, 'REDIS_PASSWORD': V_REDIS, 'CVENGINE_DB_APP_PASSWORD': V_APP,
    'CVENGINE_FIELD_KEY': V_FIELD, 'SECRET': V_DJANGO,
}


def env_values(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            out[key] = value
    return out


@unittest.skipUnless(shutil.which('bash') and shutil.which('python3'), 'needs bash and python3')
class RotateSecretsScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = self.tmp / 'state'
        self.state.mkdir()
        stub = self.tmp / 'stub'
        stub.mkdir()
        (stub / 'docker').write_text(DOCKER % {'state': str(self.state)})
        (stub / 'curl').write_text(CURL)
        for name in ('docker', 'curl'):
            (stub / name).chmod(0o755)
        self.repo = self.tmp / 'CVEngine'
        (self.repo / 'scripts').mkdir(parents=True)
        (self.repo / 'web').mkdir()
        for name in ('rotate-secrets.sh', 'db-backup-daily.sh', 'compose-layout.sh', 'db-app-role.sh', 'redis-password.sh'):
            shutil.copy(SCRIPTS / name, self.repo / 'scripts' / name)
        for name in ('docker-compose.yml', 'docker-compose.vps.yml'):
            (self.repo / name).write_text('services: {}\n')
        self.dotenv = ('POSTGRES_USER=rengine\nPOSTGRES_DB=rengine\n'
                       f"POSTGRES_PASSWORD={V_PG}\nREDIS_PASSWORD={V_REDIS}\n"
                       f"CVENGINE_DB_APP_PASSWORD={V_APP}\nCVENGINE_FIELD_KEY={V_FIELD}\n"
                       'CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.vps.yml\nCVENGINE_COMPOSE_ENV_FILE=.env.vps\n'
                       'CVENGINE_COMPOSE_PROJECT=cvengine\nDOMAIN_NAME=example.org\n')
        self.vps = ('POSTGRES_USER=rengine\nPOSTGRES_DB=rengine\n'
                    f"POSTGRES_PASSWORD={V_PG}\nREDIS_PASSWORD={V_REDIS}\n"
                    f"CVENGINE_DB_APP_PASSWORD={V_APP}\nCVENGINE_FIELD_KEY={V_FIELD}\n")
        (self.repo / '.env').write_text(self.dotenv)
        (self.repo / '.env.vps').write_text(self.vps)
        (self.repo / 'web' / 'secret').write_text(V_DJANGO)
        (self.repo / 'web' / 'secret').chmod(0o600)
        (self.state / 'running').write_text('db\nredis\nweb\ncelery\ncelery-beat\nproxy\nreviewer\n')
        (self.state / 'db.json').write_text(json.dumps({'pg': {'rengine': V_PG, 'cvengine_app': V_APP},
                                                         'redis': V_REDIS}))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('CVENGINE_', 'COMPOSE_', 'DOCKER_')) and k not in ROTATED}
        self.env.update(PATH=f'{stub}:{os.environ["PATH"]}', FOO_UNRELATED='leak-me', CVENGINE_ROTATE_WAIT='5')

    def run_script(self, *args, stdin=None, **extra):
        return subprocess.run(['bash', str(self.repo / 'scripts' / 'rotate-secrets.sh'), *args], input=stdin, text=True, capture_output=True,
                              env={**self.env, **extra}, cwd=self.tmp, timeout=120)

    def calls(self):
        path = self.state / 'calls.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def index(self, calls, predicate, start=0):
        for number, call in enumerate(calls[start:], start):
            if predicate(call):
                return number
        self.fail('no such call')

    def ups(self, calls):
        return [c for c in calls if c['argv'][:1] == ['compose'] and 'up' in c['argv']]

    def test_a_dry_run_prints_the_plan_the_warning_and_the_checklist_and_changes_nothing(self):
        proc = self.run_script('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for needle in ('Plan', 'ALTER ROLE rengine and cvengine_app', 'redis web celery celery-beat reviewer', 'Restart the proxy',
                       'signs EVERYONE out', 'recovery codes', 'What this script cannot rotate', 'admin login password', 'MCP and agent API tokens',
                       'Sentinel tokens', "root password", 'control panel password', 'Third party API keys'):
            self.assertIn(needle, proc.stdout)
        self.assertEqual((self.repo / '.env').read_text(), self.dotenv)
        self.assertEqual((self.repo / '.env.vps').read_text(), self.vps)
        self.assertEqual((self.repo / 'web' / 'secret').read_text(), OLD['SECRET'])
        self.assertFalse((self.repo / 'backups').exists())
        self.assertEqual(self.ups(self.calls()), [])
        self.assertFalse(any(c['argv'][:1] == ['exec'] for c in self.calls()))

    def test_it_refuses_while_the_shell_exports_a_variable_it_rotates(self):
        for name in ROTATED:
            for args in ((), ('--dry-run',), ('--yes',)):
                with self.subTest(name=name, args=args):
                    (self.state / 'calls.jsonl').unlink(missing_ok=True)
                    proc = self.run_script(*args, **{name: 'stale-value'})
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn(name, proc.stderr)
                    self.assertIn('unset', proc.stderr)
                    self.assertEqual(self.calls(), [])
        self.assertEqual((self.repo / '.env').read_text(), self.dotenv)

    def test_without_a_terminal_it_needs_yes(self):
        proc = self.run_script(stdin='yes\n')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('--yes', proc.stderr)
        self.assertEqual(self.ups(self.calls()), [])
        self.assertEqual((self.repo / '.env').read_text(), self.dotenv)

    def test_a_rotation_runs_in_order_from_a_clean_environment_and_verifies(self):
        proc = self.run_script('--yes')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('Rotation done and verified.', proc.stdout)
        dotenv, vps = env_values(self.repo / '.env'), env_values(self.repo / '.env.vps')
        for key in ('POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'CVENGINE_DB_APP_PASSWORD', 'CVENGINE_FIELD_KEY'):
            self.assertNotEqual(dotenv[key], OLD[key], key)
            self.assertEqual(dotenv[key], vps[key], key)  # both files agree
            self.assertRegex(dotenv[key], r'^[A-Za-z0-9]{32,}$')
        self.assertNotIn('CVENGINE_FIELD_KEY_PREVIOUS', dotenv)
        self.assertNotIn('CVENGINE_FIELD_KEY_PREVIOUS', vps)
        self.assertEqual(dotenv['DOMAIN_NAME'], 'example.org')  # other lines untouched
        secret = (self.repo / 'web' / 'secret').read_text().strip()
        self.assertRegex(secret, r'^[A-Za-z0-9]{64}$')
        self.assertEqual(stat.S_IMODE((self.repo / 'web' / 'secret').stat().st_mode), 0o600)
        db = json.loads((self.state / 'db.json').read_text())
        self.assertEqual(db['pg'], {'rengine': dotenv['POSTGRES_PASSWORD'], 'cvengine_app': dotenv['CVENGINE_DB_APP_PASSWORD']})
        self.assertEqual(db['redis'], dotenv['REDIS_PASSWORD'])

        # backups: the old keys in one 0700 folder, the dump in another
        keydirs = list((self.repo / 'backups').glob('keys-*'))
        self.assertEqual(len(keydirs), 1)
        self.assertEqual(stat.S_IMODE(keydirs[0].stat().st_mode), 0o700)
        self.assertEqual((keydirs[0] / '.env').read_text(), self.dotenv)
        self.assertEqual((keydirs[0] / '.env.vps').read_text(), self.vps)
        self.assertEqual((keydirs[0] / 'secret').read_text(), OLD['SECRET'])
        dumps = list((self.repo / 'backups' / 'db').glob('cvengine-*-before-rotation.dump'))
        self.assertEqual(len(dumps), 1)
        self.assertEqual(stat.S_IMODE(dumps[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(dumps[0].parent.stat().st_mode), 0o700)
        self.assertFalse(list(keydirs[0].glob('*.dump')))

        calls = self.calls()
        dump = self.index(calls, lambda c: 'pg_dump' in ' '.join(c['argv']))
        alter = self.index(calls, lambda c: 'ALTER ROLE' in (c.get('stdin') or ''))
        ups = [n for n, c in enumerate(calls) if c['argv'][:1] == ['compose'] and 'up' in c['argv']]
        self.assertEqual(len(ups), 2)
        rotate = self.index(calls, lambda c: c['argv'][-1] == 'rotate_field_key')
        strict = self.index(calls, lambda c: '--strict' in c['argv'])
        proxy = self.index(calls, lambda c: c['argv'][-2:] == ['restart', 'proxy'])
        redis_check = self.index(calls, lambda c: 'redisid' in c['argv'])
        self.assertLess(dump, alter)
        self.assertLess(alter, ups[0])
        self.assertLess(ups[0], rotate)
        self.assertLess(rotate, strict)
        self.assertLess(strict, ups[1])
        self.assertLess(ups[1], proxy)
        self.assertLess(proxy, redis_check)
        first, second = calls[ups[0]], calls[ups[1]]
        self.assertEqual(first['argv'][:9], ['compose', '--env-file', '.env.vps', '-p', 'cvengine', '-f', 'docker-compose.yml', '-f', 'docker-compose.vps.yml'])
        self.assertEqual(first['argv'][9:], ['up', '-d', '--force-recreate', 'redis', 'web', 'celery', 'celery-beat', 'reviewer'])
        self.assertEqual(second['argv'][9:], ['up', '-d', '--force-recreate', 'web', 'celery', 'celery-beat', 'reviewer'])
        # the first recreate runs with the new passwords and the old field key kept as the previous one, and the old Django secret
        at_first = env_values_text(first['snapshot']['.env'])
        self.assertEqual(at_first['CVENGINE_FIELD_KEY_PREVIOUS'], OLD['CVENGINE_FIELD_KEY'])
        self.assertEqual(env_values_text(first['snapshot']['.env.vps'])['POSTGRES_PASSWORD'], dotenv['POSTGRES_PASSWORD'])
        self.assertEqual(first['snapshot']['secret'], OLD['SECRET'])
        # the second without the previous key and with the new secret
        self.assertNotIn('CVENGINE_FIELD_KEY_PREVIOUS', env_values_text(second['snapshot']['.env']))
        self.assertEqual(second['snapshot']['secret'].strip(), secret)

        # every docker call ran with a clean environment, and no secret was ever on a command line
        new_values = [dotenv[k] for k in ('POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'CVENGINE_DB_APP_PASSWORD', 'CVENGINE_FIELD_KEY')] + [secret]
        for call in calls:
            self.assertFalse(set(call['env']) & set(ROTATED), call['argv'])
            self.assertNotIn('FOO_UNRELATED', call['env'])
            joined = ' '.join(call['argv'])
            for value in new_values + [OLD['POSTGRES_PASSWORD'], OLD['REDIS_PASSWORD']]:
                self.assertNotIn(value, joined)
        for needle in ('the old password of rengine is refused', 'Redis refuses a client without the password', 'Stored secrets: 3 under the current key',
                       'signs EVERYONE out', 'What this script cannot rotate'):
            self.assertIn(needle, proc.stdout)

    def test_a_legacy_install_without_a_field_key_gets_one_and_no_previous_key(self):
        for name in ('.env', '.env.vps'):
            path = self.repo / name
            path.write_text(''.join(l + '\n' for l in path.read_text().splitlines() if not l.startswith('CVENGINE_FIELD_KEY=')))
        proc = self.run_script('--yes')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        first = self.ups(self.calls())[0]
        self.assertNotIn('CVENGINE_FIELD_KEY_PREVIOUS', env_values_text(first['snapshot']['.env']))
        self.assertIn('CVENGINE_FIELD_KEY', env_values(self.repo / '.env'))
        self.assertNotIn('CVENGINE_FIELD_KEY', env_values(self.repo / '.env.vps'))  # written to the Compose env file only when it had one

    def test_a_failed_alter_role_puts_the_env_files_back_and_recreates_nothing(self):
        (self.state / 'alter_fail').write_text('')
        proc = self.run_script('--yes')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('env files are put back', proc.stderr)
        self.assertEqual((self.repo / '.env').read_text(), self.dotenv)
        self.assertEqual((self.repo / '.env.vps').read_text(), self.vps)
        self.assertEqual(self.ups(self.calls()), [])

    def test_a_secret_still_under_the_old_key_keeps_the_previous_key_and_the_django_secret(self):
        (self.state / 'strict_fail').write_text('')
        proc = self.run_script('--yes')
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(env_values(self.repo / '.env')['CVENGINE_FIELD_KEY_PREVIOUS'], OLD['CVENGINE_FIELD_KEY'])
        self.assertEqual((self.repo / 'web' / 'secret').read_text(), OLD['SECRET'])
        self.assertEqual(len(self.ups(self.calls())), 1)

    def test_secrets_already_unreadable_stop_it_before_anything_changes(self):
        (self.state / 'unreadable').write_text('')
        proc = self.run_script('--yes')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('cannot be read', proc.stderr)
        self.assertEqual((self.repo / '.env').read_text(), self.dotenv)
        self.assertFalse((self.repo / 'backups').exists())

    def test_keep_django_secret_leaves_web_secret_and_signs_nobody_out(self):
        proc = self.run_script('--yes', '--keep-django-secret')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / 'web' / 'secret').read_text(), OLD['SECRET'])
        self.assertIn('nobody is signed out', proc.stdout)
        self.assertNotIn('signs EVERYONE out', proc.stdout)

    def test_the_owner_role_switch_leaves_the_app_role_alone(self):
        (self.repo / '.env.vps').write_text(self.vps + 'CVENGINE_DB_APP_USER=\n')
        proc = self.run_script('--yes')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(env_values(self.repo / '.env.vps')['CVENGINE_DB_APP_PASSWORD'], OLD['CVENGINE_DB_APP_PASSWORD'])
        alter = next(c['stdin'] for c in self.calls() if 'ALTER ROLE' in (c.get('stdin') or ''))
        self.assertIn('ALTER ROLE "rengine"', alter)
        self.assertNotIn('cvengine_app', alter)

    def test_a_redis_that_answers_without_a_password_fails_the_verification(self):
        (self.state / 'redis_open').write_text('')
        proc = self.run_script('--yes')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('FAILED: Redis answers without a password', proc.stdout)
        self.assertIn('What this script cannot rotate', proc.stdout)

    def test_a_field_key_kept_in_a_file_is_refused(self):
        (self.repo / '.env').write_text(self.dotenv + 'CVENGINE_FIELD_KEY_FILE=/run/secrets/field_key\n')
        proc = self.run_script('--yes')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('CVENGINE_FIELD_KEY_FILE', proc.stderr)
        self.assertEqual(self.ups(self.calls()), [])

    def test_the_make_target_and_the_docs_name_it(self):
        self.assertIn('rotate-secrets:', (ROOT / 'Makefile').read_text())
        config = (ROOT / 'docs' / 'CONFIGURATION.md').read_text()
        self.assertIn('make rotate-secrets', config)
        self.assertIn('scripts/rotate-secrets.sh', config)


def env_values_text(text):
    return {line.split('=', 1)[0]: line.split('=', 1)[1] for line in text.splitlines() if '=' in line}
