"""The least privilege database role (reNgine/db_roles.py): which role a process uses, the GRANT statements, the entrypoints' fallback, the
scripts that generate its password, the compose files' data network and log rotation, and the docs. The grants against a real database are
in tests/test_db_app_role_grants.py."""
import importlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from reNgine import db_roles

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

WEB = Path(__file__).resolve().parents[1]
ROOT = WEB.parent
SCRIPTS = ROOT / 'scripts'
APP_SERVICES = ('web', 'celery', 'celery-beat')
ENV = {'POSTGRES_USER': 'cvengine', 'POSTGRES_PASSWORD': 'ownerpw', 'POSTGRES_DB': 'cvengine', 'POSTGRES_HOST': 'db', 'POSTGRES_PORT': '5432',
       'CVENGINE_DB_APP_PASSWORD': 'apppw'}
RUNTIME = ['manage.py', 'runserver']
NO_STATE = '/nonexistent/cvengine-db-role'


def resolve(argv=RUNTIME, state_file=NO_STATE, **overrides):
    environ = {**ENV, **overrides}
    for key, value in overrides.items():
        if value is None:
            environ.pop(key)
    return db_roles.resolve(environ, argv, state_file=state_file)


class ResolveTests(SimpleTestCase):
    def test_runtime_uses_the_app_role(self):
        got = resolve()
        self.assertEqual((got['role'], got['user'], got['password']), ('app', 'cvengine_app', 'apppw'))
        for argv in (['gunicorn'], ['celery', '-A', 'reNgine', 'worker'], ['manage.py', 'watchdog_tick'], ['manage.py', 'shell'],
                     ['manage.py', 'migrate', '--check'], ['manage.py', 'migrate', '--plan'], ['/usr/src/app/manage.py', 'collectstatic']):
            self.assertEqual(resolve(argv)['role'], 'app', argv)

    def test_migrations_and_maintenance_use_the_owner_role(self):
        for command in ('migrate', 'showmigrations', 'createsuperuser', 'test', 'db_app_role', 'dbshell'):
            got = resolve(['manage.py', command, '--noinput'])
            self.assertEqual((got['role'], got['user'], got['password']), ('owner', 'cvengine', 'ownerpw'), command)

    def test_the_env_override_wins_both_ways(self):
        self.assertEqual(resolve(CVENGINE_DB_ROLE='owner')['role'], 'owner')
        self.assertEqual(resolve(['manage.py', 'migrate'], CVENGINE_DB_ROLE='app')['role'], 'app')
        self.assertEqual(resolve(CVENGINE_DB_ROLE='OWNER ')['role'], 'owner')

    def test_no_app_password_means_the_owner_role_as_before(self):
        for missing in ({'CVENGINE_DB_APP_PASSWORD': None}, {'CVENGINE_DB_APP_PASSWORD': ''}):
            got = resolve(**missing)
            self.assertEqual((got['role'], got['user']), ('owner', 'cvengine'))
            self.assertIn('CVENGINE_DB_APP_PASSWORD', got['reason'])

    def test_an_empty_app_user_is_the_rollback_to_the_owner_role(self):
        got = resolve(CVENGINE_DB_APP_USER='')
        self.assertEqual((got['role'], got['user']), ('owner', 'cvengine'))
        self.assertIn('CVENGINE_DB_APP_USER', got['reason'])

    def test_the_app_user_can_be_renamed_but_must_be_a_plain_name_other_than_the_owner(self):
        self.assertEqual(resolve(CVENGINE_DB_APP_USER='scanner_rw')['user'], 'scanner_rw')
        self.assertEqual(resolve(CVENGINE_DB_APP_USER='x"; DROP ROLE y')['role'], 'owner')
        self.assertEqual(resolve(CVENGINE_DB_APP_USER='cvengine')['role'], 'owner')

    def test_a_container_that_fell_back_keeps_the_owner_role_for_every_later_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'db-role'
            db_roles.write_state('owner', 'the role cvengine_app cannot log in yet', str(state))
            self.assertEqual(db_roles.read_state(str(state)), ('owner', 'the role cvengine_app cannot log in yet'))
            got = resolve(state_file=str(state))
            self.assertEqual((got['role'], got['user']), ('owner', 'cvengine'))
            self.assertIn('cannot log in', got['reason'])
            # an explicit choice in the environment is not overridden by the file
            self.assertEqual(resolve(state_file=str(state), CVENGINE_DB_ROLE='app')['role'], 'app')
            db_roles.write_state('app', '', str(state))
            self.assertEqual(resolve(state_file=str(state))['role'], 'app')
            state.write_text('garbage\n')
            self.assertEqual(db_roles.read_state(str(state)), (None, ''))
            with mock.patch.dict(os.environ, {'CVENGINE_DB_ROLE_STATE': str(state)}):
                db_roles.write_state('owner', 'x')
                self.assertEqual(db_roles.read_state(), ('owner', 'x'))

    def test_passwords_may_come_from_docker_secret_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'app').write_text('filepw\n')
            got = resolve(CVENGINE_DB_APP_PASSWORD=None, CVENGINE_DB_APP_PASSWORD_FILE=str(Path(tmp) / 'app'))
            self.assertEqual((got['role'], got['password']), ('app', 'filepw'))


class SettingsTests(SimpleTestCase):
    """settings.DATABASES follows the resolution: the runtime alias gets the app role, the migrate process the owner role."""

    def reload(self, argv, **env):
        from reNgine import settings
        values = {'CVENGINE_DB_ROLE_STATE': NO_STATE, **{k: v for k, v in env.items() if v is not None}}
        with mock.patch.dict(os.environ, values), mock.patch.object(sys, 'argv', argv):
            for key, value in env.items():
                if value is None:
                    os.environ.pop(key, None)
            importlib.reload(settings)
            return settings.DATABASE_ROLE, dict(settings.DATABASES['default'])

    def tearDown(self):
        from reNgine import settings
        importlib.reload(settings)

    def test_runtime_and_migrate(self):
        owner = os.environ.get('POSTGRES_USER')
        role, db = self.reload(['manage.py', 'runserver'], CVENGINE_DB_APP_USER='cvengine_app', CVENGINE_DB_APP_PASSWORD='apppw', CVENGINE_DB_ROLE=None)
        self.assertEqual((role, db['USER'], db['PASSWORD']), ('app', 'cvengine_app', 'apppw'))
        role, db = self.reload(['manage.py', 'migrate', '--noinput'], CVENGINE_DB_APP_USER='cvengine_app', CVENGINE_DB_APP_PASSWORD='apppw',
                               CVENGINE_DB_ROLE=None)
        self.assertEqual((role, db['USER']), ('owner', owner))
        role, db = self.reload(['manage.py', 'runserver'], CVENGINE_DB_APP_USER='cvengine_app', CVENGINE_DB_APP_PASSWORD='apppw', CVENGINE_DB_ROLE='owner')
        self.assertEqual((role, db['USER']), ('owner', owner))

    def test_without_an_app_password_nothing_changes(self):
        role, db = self.reload(['manage.py', 'runserver'], CVENGINE_DB_APP_PASSWORD=None, CVENGINE_DB_ROLE=None)
        self.assertEqual((role, db['USER'], db['PASSWORD']), ('owner', os.environ.get('POSTGRES_USER'), os.environ.get('POSTGRES_PASSWORD')))

    def test_the_test_run_itself_uses_the_owner_role(self):
        from django.conf import settings
        self.assertEqual(settings.DATABASE_ROLE, 'owner')


class GrantSqlTests(SimpleTestCase):
    def test_the_runtime_privileges_and_nothing_more(self):
        sql = db_roles.grant_statements('cvengine', 'cvengine_app', 'cvengine')
        self.assertEqual(sql, [
            'GRANT CONNECT ON DATABASE "cvengine" TO "cvengine_app"',
            'GRANT USAGE ON SCHEMA "public" TO "cvengine_app"',
            'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "cvengine_app"',
            'GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA "public" TO "cvengine_app"',
            'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA "public" TO "cvengine_app"',
            'ALTER DEFAULT PRIVILEGES FOR ROLE "cvengine" IN SCHEMA "public" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "cvengine_app"',
            'ALTER DEFAULT PRIVILEGES FOR ROLE "cvengine" IN SCHEMA "public" GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "cvengine_app"',
            'ALTER DEFAULT PRIVILEGES FOR ROLE "cvengine" IN SCHEMA "public" GRANT EXECUTE ON FUNCTIONS TO "cvengine_app"',
            'GRANT pg_maintain TO "cvengine_app"',
        ])
        text = ' '.join(sql).upper()
        for never in ('TRUNCATE', 'REFERENCES', 'TRIGGER', 'ALL PRIVILEGES', 'CREATE', 'SUPERUSER', 'PG_READ_SERVER_FILES', 'PG_EXECUTE_SERVER_PROGRAM',
                      'PG_WRITE_SERVER_FILES', 'WITH GRANT OPTION', 'TEMPORARY'):
            self.assertNotIn(never, text)
        self.assertNotIn('pg_maintain', ' '.join(db_roles.grant_statements('cvengine', 'cvengine_app', 'cvengine', maintain=False)))

    def test_names_are_quoted_and_unsafe_role_names_refused(self):
        self.assertIn('ON DATABASE "odd""db"', db_roles.grant_statements('o', 'a', 'odd"db')[0])
        for bad in ('', 'a b', 'x"y', '1abc', 'a' * 64):
            with self.assertRaises(db_roles.RoleError):
                db_roles.grant_statements('cvengine', bad, 'cvengine')
            with self.assertRaises(db_roles.RoleError):
                db_roles.grant_statements(bad, 'cvengine_app', 'cvengine')

    def test_the_role_statement_sets_every_attribute_and_only_a_verifier(self):
        verifier = 'SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy'
        for exists, verb in ((False, 'CREATE ROLE'), (True, 'ALTER ROLE')):
            sql = db_roles.role_statement('cvengine_app', verifier, exists)
            self.assertTrue(sql.startswith(f'{verb} "cvengine_app" WITH '), sql)
            for attribute in ('LOGIN', 'NOSUPERUSER', 'NOCREATEDB', 'NOCREATEROLE', 'NOREPLICATION', 'NOBYPASSRLS'):
                self.assertIn(f' {attribute} ', sql)
            self.assertTrue(sql.endswith(f"PASSWORD '{verifier}'"))
        for bad in ('apppw', "x' SUPERUSER '", 'md5abc'):
            with self.assertRaises(db_roles.RoleError):
                db_roles.role_statement('cvengine_app', bad, False)


class ChooseTests(SimpleTestCase):
    """The entrypoints' fallback: a container keeps the owner role when the app role cannot log in, and never locks itself out."""

    def run_choose(self, works, wait=0, **env):
        tried = []
        clock = [0.0]

        def connect(environ, user, password):
            tried.append(user)
            if user in works:
                return mock.Mock()
            raise RuntimeError(f'FATAL:  password authentication failed for user "{user}"')

        def sleep(seconds):
            clock[0] += seconds

        environ = {**ENV, **env}
        return db_roles.choose(environ, wait=wait, connect=connect, sleep=sleep, clock=lambda: clock[0]), tried, clock[0]

    def test_the_app_role_logs_in(self):
        (role, reason), tried, _ = self.run_choose({'cvengine_app', 'cvengine'})
        self.assertEqual((role, reason, tried), ('app', '', ['cvengine_app']))

    def test_a_missing_role_falls_back_to_the_owner_after_the_wait(self):
        (role, reason), tried, waited = self.run_choose({'cvengine'}, wait=30)
        self.assertEqual(role, 'owner')
        self.assertIn('cvengine_app cannot log in yet', reason)
        self.assertGreaterEqual(waited, 30)
        self.assertEqual(set(tried), {'cvengine_app', 'cvengine'})

    def test_the_role_appearing_during_the_wait_is_used(self):
        works = {'cvengine'}
        tried = []
        clock = [0.0]

        def connect(environ, user, password):
            tried.append(user)
            if user in works:
                return mock.Mock()
            raise RuntimeError('auth')

        def sleep(seconds):
            clock[0] += seconds
            works.add('cvengine_app')  # the web service's migrate created it meanwhile

        self.assertEqual(db_roles.choose(ENV, wait=60, connect=connect, sleep=sleep, clock=lambda: clock[0]), ('app', ''))

    def test_a_database_that_answers_nobody_leaves_the_configured_role(self):
        (role, _), _, _ = self.run_choose(set())
        self.assertEqual(role, 'app')

    def test_not_configured_is_the_owner_without_a_connection(self):
        (role, reason), tried, _ = self.run_choose({'cvengine_app'}, CVENGINE_DB_APP_PASSWORD='')
        self.assertEqual((role, tried), ('owner', []))
        self.assertIn('CVENGINE_DB_APP_PASSWORD', reason)


class OwnerFallbackTests(SimpleTestCase):
    """The application containers have no owner password. The gate (manage.py db_app_role gate, run by the migrate service before they start)
    refuses to start them when the app role cannot be used, unless CVENGINE_DB_ALLOW_OWNER_FALLBACK=1, which is then the only way they get it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', str(self.tmp)]))
        self.file = self.tmp / 'password'

    def gate(self, works=('cvengine_app', 'cvengine'), ensure_error=None, **env):
        environ = {**ENV, 'POSTGRES_PASSWORD': 'ownerpw', 'CVENGINE_DB_OWNER_FALLBACK_FILE': str(self.file), 'CVENGINE_DB_ROLE': 'owner', **env}
        for key, value in env.items():
            if value is None:
                environ.pop(key)
        tried, ensured = [], []

        def connect(environ, user, password):
            tried.append((user, password))
            if user in works:
                return mock.Mock()
            raise RuntimeError(f'FATAL:  password authentication failed for user "{user}"\nmore')

        def ensure_role(name, password):
            ensured.append((name, password))
            if ensure_error:
                raise db_roles.RoleError(ensure_error)

        ok, role, lines = db_roles.gate(environ, connect=connect, ensure_role=ensure_role)
        return ok, role, lines, tried, ensured

    def fix_line(self, lines):
        fixes = [line for line in lines if line.startswith('Fix:')]
        self.assertEqual(len(fixes), 1, lines)
        return fixes[0]

    def test_a_working_app_role_passes_and_removes_any_old_fallback_file(self):
        self.file.write_text('ownerpw\n')
        ok, role, lines, tried, ensured = self.gate()
        self.assertEqual((ok, role), (True, 'app'))
        self.assertEqual(ensured, [('cvengine_app', 'apppw')])  # created and granted first, as the owner
        self.assertEqual(tried, [('cvengine_app', 'apppw')])  # then it must log in itself
        self.assertFalse(self.file.exists())
        self.assertFalse([line for line in lines if 'ownerpw' in line])

    def test_a_role_that_cannot_log_in_fails_loudly_with_the_one_line_fix(self):
        ok, role, lines, _, _ = self.gate(works=('cvengine',))
        self.assertEqual((ok, role), (False, None))
        self.assertIn('cvengine_app cannot log in (FATAL:  password authentication failed for user "cvengine_app")', lines[0])
        self.assertIn('not started with the owner password', lines[0])
        fix = self.fix_line(lines)
        self.assertIn('CVENGINE_DB_ALLOW_OWNER_FALLBACK=1', fix)
        self.assertNotIn('\n', fix)
        self.assertFalse(self.file.exists())

    def test_an_empty_app_password_fails_with_its_fix_and_never_tries_the_owner(self):
        for missing in ({'CVENGINE_DB_APP_PASSWORD': ''}, {'CVENGINE_DB_APP_PASSWORD': None}):
            ok, role, lines, tried, ensured = self.gate(**missing)
            self.assertEqual((ok, role, tried, ensured), (False, None, [], []))
            self.assertIn('CVENGINE_DB_APP_PASSWORD is empty', lines[0])
            self.assertIn('cvengine_ensure_db_app_password', self.fix_line(lines))
            self.assertFalse(self.file.exists())

    def test_an_empty_app_user_is_no_longer_a_silent_way_back_to_the_owner(self):
        ok, _, lines, _, _ = self.gate(CVENGINE_DB_APP_USER='')
        self.assertFalse(ok)
        self.assertIn('delete the line CVENGINE_DB_APP_USER=', self.fix_line(lines))
        ok, _, lines, _, _ = self.gate(CVENGINE_DB_APP_USER='cvengine')
        self.assertFalse(ok)
        self.assertIn('CVENGINE_DB_APP_USER', self.fix_line(lines))

    def test_a_role_that_cannot_be_created_fails_with_its_fix(self):
        ok, _, lines, tried, _ = self.gate(ensure_error='the owner role cvengine may not create roles (it needs SUPERUSER or CREATEROLE)')
        self.assertFalse(ok)
        self.assertEqual(tried, [])
        self.assertIn('could not be created or granted', lines[0])
        self.assertIn('CREATEROLE', self.fix_line(lines))

    def test_only_the_explicit_switch_hands_the_owner_password_over(self):
        for value in ('0', 'yes', 'true', ' ', ''):
            ok, _, _, _, _ = self.gate(works=('cvengine',), CVENGINE_DB_ALLOW_OWNER_FALLBACK=value)
            self.assertFalse(ok, value)
            self.assertFalse(self.file.exists(), value)
        ok, role, lines, _, _ = self.gate(works=('cvengine',), CVENGINE_DB_ALLOW_OWNER_FALLBACK='1')
        self.assertEqual((ok, role), (True, 'owner'))
        self.assertIn('WARNING', lines[0])
        self.assertIn('OWNER role cvengine', lines[0])
        self.assertIn('remove CVENGINE_DB_ALLOW_OWNER_FALLBACK', self.fix_line(lines))
        self.assertEqual(self.file.read_text(), 'ownerpw\n')
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        # the app role works again: the next gate takes the password back out of the application's reach, even with the switch still on
        ok, role, _, _, _ = self.gate(CVENGINE_DB_ALLOW_OWNER_FALLBACK='1')
        self.assertEqual((ok, role), (True, 'app'))
        self.assertFalse(self.file.exists())

    def test_the_switch_also_covers_a_missing_app_password(self):
        ok, role, _, _, _ = self.gate(CVENGINE_DB_APP_PASSWORD='', CVENGINE_DB_ALLOW_OWNER_FALLBACK='1')
        self.assertEqual((ok, role), (True, 'owner'))
        self.assertEqual(self.file.read_text(), 'ownerpw\n')

    def test_the_switch_fails_loudly_when_the_password_cannot_be_handed_over(self):
        ok, _, lines, _, _ = self.gate(works=('cvengine',), CVENGINE_DB_ALLOW_OWNER_FALLBACK='1',
                                       CVENGINE_DB_OWNER_FALLBACK_FILE=str(self.tmp / 'missing' / 'password'))
        self.assertFalse(ok)
        self.assertIn('db_owner_fallback', self.fix_line(lines))

    def app_container(self, **env):
        """resolve() as in web, celery or celery-beat: POSTGRES_PASSWORD is empty (docker-compose.yml blanks it)."""
        return resolve(POSTGRES_PASSWORD='', CVENGINE_DB_OWNER_FALLBACK_FILE=str(self.file), **env)

    def test_the_application_has_no_owner_password_without_the_fallback_file(self):
        got = self.app_container(CVENGINE_DB_APP_PASSWORD='')
        self.assertEqual((got['role'], got['password']), ('owner', ''))
        self.assertEqual(db_roles.owner_password({'POSTGRES_PASSWORD': '', 'CVENGINE_DB_OWNER_FALLBACK_FILE': str(self.file)}), '')
        self.assertEqual(self.app_container()['role'], 'app')

    def test_with_the_fallback_file_the_owner_role_works_in_the_application(self):
        self.file.write_text('ownerpw\n')
        got = self.app_container(CVENGINE_DB_APP_PASSWORD='')
        self.assertEqual((got['role'], got['user'], got['password']), ('owner', 'cvengine', 'ownerpw'))
        (role, _), tried, _ = ChooseTests.run_choose(self, {'cvengine'}, POSTGRES_PASSWORD='', CVENGINE_DB_OWNER_FALLBACK_FILE=str(self.file))
        self.assertEqual(role, 'owner')
        self.assertIn(('cvengine'), tried)

    def test_settings_get_the_fallback_password_only_in_process(self):
        self.file.write_text('ownerpw\n')
        env = {**ENV, 'POSTGRES_PASSWORD': '', 'CVENGINE_DB_APP_PASSWORD': '', 'CVENGINE_DB_OWNER_FALLBACK_FILE': str(self.file)}
        with mock.patch.dict(os.environ, env, clear=False):
            db_roles.resolve(os.environ, ['gunicorn'], state_file=None)
            self.assertEqual(os.environ['POSTGRES_PASSWORD'], 'ownerpw')  # what settings.py reads for the owner role
        plain = dict(env)
        db_roles.resolve(plain, ['gunicorn'], state_file=None)
        self.assertEqual(plain['POSTGRES_PASSWORD'], '')  # a dict that is not the process environment is never written

    def test_the_command_exits_non_zero_when_the_gate_fails(self):
        from django.core.management import call_command
        with mock.patch.object(db_roles, 'gate', return_value=(False, None, ['db_app_role: ERROR: x', 'Fix: y'])), \
                self.assertRaises(SystemExit) as raised:
            call_command('db_app_role', 'gate', stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(raised.exception.code, 1)
        out = io.StringIO()
        with mock.patch.object(db_roles, 'gate', return_value=(True, 'app', ['db_app_role: fine'])):
            call_command('db_app_role', 'gate', stdout=out, stderr=io.StringIO())
        self.assertIn('fine', out.getvalue())


class AppRuntimeSqlTests(SimpleTestCase):
    """Every privilege-bearing statement the application runs at run time (not in migrations) is covered by the grants. When this fails, a
    new kind of statement was added: decide whether the app role may run it, extend grant_statements if so, and list it here."""

    ALLOWED = {
        'ANALYZE': ('cveFeed/db_stats.py', 'cveFeed/management/commands/seed_scale_fixture.py'),  # pg_maintain
        'CREATE TEMP TABLE': ('cveFeed/management/commands/seed_scale_fixture.py',),  # TEMPORARY, which PUBLIC has on every database
    }
    FORBIDDEN = re.compile(r'''execute\(\s*f?['"]\s*(TRUNCATE|VACUUM|CLUSTER|REINDEX|LOCK\s+TABLE|COPY\s|CREATE\s+(?:UNIQUE\s+)?INDEX|ALTER\s+(?:TABLE|SYSTEM|ROLE)|'''
                           r'''DROP\s|CREATE\s+(?:ROLE|EXTENSION|TABLE|SCHEMA)|GRANT\s|LISTEN\s|NOTIFY\s|SET\s+ROLE)''', re.IGNORECASE)

    def runtime_sources(self):
        for path in WEB.rglob('*.py'):
            rel = path.relative_to(WEB).as_posix()
            if '/migrations/' in rel or rel.startswith('tests/') or rel == 'reNgine/db_roles.py' or rel == 'startScan/dedupe.py':
                continue
            yield rel, path.read_text(errors='replace')

    def test_no_runtime_ddl_or_superuser_statement(self):
        found = []
        for rel, text in self.runtime_sources():
            for match in self.FORBIDDEN.finditer(text):
                found.append(f'{rel}: {match.group(1)}')
        self.assertEqual(found, [])

    def test_analyze_and_temp_tables_only_where_listed(self):
        for statement, allowed in self.ALLOWED.items():
            pattern = re.compile(r'''execute\(\s*['"]\s*''' + statement.replace(' ', r'\s+'), re.IGNORECASE)
            where = sorted(rel for rel, text in self.runtime_sources() if pattern.search(text))
            self.assertEqual(where, sorted(allowed), statement)

    def test_startscan_dedupe_ddl_runs_only_from_migrations(self):
        users = sorted(rel for rel, text in self.runtime_sources() if re.search(r'startScan\.dedupe|from startScan import dedupe', text))
        self.assertEqual(users, [])


@unittest.skipUnless(yaml and (ROOT / 'docker-compose.yml').is_file(), 'needs PyYAML and the compose files')
class ComposeTests(SimpleTestCase):
    FILES = ('docker-compose.yml', 'docker-compose.dev.yml')

    def load(self, name):
        return yaml.safe_load((ROOT / name).read_text())

    def networks(self, service):
        nets = service.get('networks') or []
        return set(nets) if isinstance(nets, (list, dict)) else set()

    def test_db_and_redis_are_on_the_data_network_with_the_app_services_only(self):
        for name in self.FILES:
            services = self.load(name)['services']
            self.assertEqual(self.networks(services['db']), {'data_network'}, name)
            self.assertEqual(self.networks(services['redis']), {'data_network'}, name)
            on_it = sorted(n for n, s in services.items() if 'data_network' in self.networks(s))
            self.assertEqual(on_it, sorted(['db', 'redis', 'migrate', *APP_SERVICES]), name)
            self.assertEqual(self.networks(services['migrate']), {'data_network'}, name)
            self.assertIn('data_network', self.load(name)['networks'])

    def test_the_reviewer_keeps_reaching_web_and_nothing_with_a_database(self):
        services = self.load('docker-compose.yml')['services']
        reviewer = services['reviewer']
        self.assertEqual(self.networks(reviewer), {'rengine_network'})
        self.assertIn('rengine_network', self.networks(services['web']))  # http://web:8000
        self.assertEqual(reviewer['environment']['CVENGINE_REVIEWER_SERVER'], 'http://web:8000')
        self.assertFalse([k for k in reviewer['environment'] if k.startswith(('POSTGRES', 'REDIS', 'CVENGINE_DB'))])
        source = '\n'.join(p.read_text() for p in (ROOT / 'reviewer' / 'cvengine_reviewer').glob('*.py'))
        for word in ('psycopg', 'redis.Redis', ':5432', ':6379', 'import redis'):
            self.assertNotIn(word, source)
        for name in ('proxy', 'scanner'):
            self.assertNotIn('data_network', self.networks(services[name]))

    def test_the_data_network_is_not_internal_so_the_published_database_port_keeps_working(self):
        compose = self.load('docker-compose.yml')
        self.assertFalse((compose['networks']['data_network'] or {}).get('internal'))
        self.assertEqual(compose['services']['db']['ports'], ['127.0.0.1:5432:5432'])
        self.assertNotIn('ports', compose['services']['web'])  # review r3 S3: opt in with docker-compose.webport.yml
        self.assertEqual(compose['services']['proxy']['ports'], ['${CVENGINE_HTTP_PORT:-8082}:8082/tcp', '${CVENGINE_HTTPS_PORT:-443}:443/tcp'])
        self.assertNotIn('ports', compose['services']['redis'])

    def test_connection_logging_is_on_by_default_with_env_switches(self):
        for name in self.FILES:
            command = self.load(name)['services']['db']['command']
            self.assertIn('log_connections=${POSTGRES_LOG_CONNECTIONS:-on}', command, name)
            self.assertIn('log_disconnections=${POSTGRES_LOG_DISCONNECTIONS:-on}', command, name)
            self.assertEqual(command[0], 'postgres')
            self.assertTrue(all(command[i] == '-c' for i in range(1, len(command), 2)), name)

    def test_every_service_of_every_compose_file_rotates_its_log(self):
        for name in ('docker-compose.yml', 'docker-compose.dev.yml', 'docker-compose.setup.yml'):
            for service, spec in self.load(name)['services'].items():
                logging = spec.get('logging') or {}
                self.assertEqual(logging.get('driver'), 'json-file', f'{name} {service}')
                self.assertEqual(logging.get('options'), {'max-size': '${CVENGINE_LOG_MAX_SIZE:-50m}', 'max-file': '${CVENGINE_LOG_MAX_FILE:-5}'},
                                 f'{name} {service}')

    def test_the_app_services_get_the_app_role_and_nothing_else_does(self):
        for name in self.FILES:
            services = self.load(name)['services']
            for service, spec in services.items():
                env = spec.get('environment') or []
                keys = {item.split('=', 1)[0] for item in env} if isinstance(env, list) else set(env)
                if service in (*APP_SERVICES, 'migrate'):
                    self.assertIn('CVENGINE_DB_APP_USER=${CVENGINE_DB_APP_USER-cvengine_app}', env, f'{name} {service}')
                    self.assertIn('CVENGINE_DB_APP_PASSWORD=${CVENGINE_DB_APP_PASSWORD:-}', env, f'{name} {service}')
                else:
                    self.assertFalse({'CVENGINE_DB_APP_USER', 'CVENGINE_DB_APP_PASSWORD'} & keys, f'{name} {service}')

    def env_of(self, spec):
        env = spec.get('environment') or []
        if isinstance(env, dict):
            return {k: '' if v is None else str(v) for k, v in env.items()}
        return dict(item.split('=', 1) if '=' in item else (item, '') for item in env)

    def test_no_long_running_service_gets_the_owner_password(self):
        # Only db (the server itself) and the one-off migrate service may have POSTGRES_PASSWORD. env_file: .env hands every line of .env to a
        # service, POSTGRES_PASSWORD and DJANGO_SUPERUSER_PASSWORD included, so a service that reads .env must blank both in `environment:`, which
        # Compose lets win over env_file.
        for name in self.FILES:
            for service, spec in self.load(name)['services'].items():
                if service in ('db', 'migrate'):
                    continue
                env = self.env_of(spec)
                where = f'{name} {service}'
                self.assertFalse(env.get('POSTGRES_PASSWORD'), where)
                self.assertNotIn('POSTGRES_PASSWORD_FILE', env, where)
                self.assertFalse(env.get('DJANGO_SUPERUSER_PASSWORD'), where)
                self.assertFalse(any('POSTGRES_PASSWORD' in str(v) for v in env.values()), where)
                reads_dot_env = any((item.get('path') if isinstance(item, dict) else item) == '.env' for item in (spec.get('env_file') or []))
                if reads_dot_env:
                    self.assertEqual(env.get('POSTGRES_PASSWORD'), '', where + ': must blank the password .env would pass')
                    self.assertEqual(env.get('DJANGO_SUPERUSER_PASSWORD'), '', where + ': must blank the admin password .env would pass')
                if service in APP_SERVICES:
                    self.assertEqual(spec.get('restart'), 'always', where)  # these are the long running ones the rule is about

    def test_the_migrate_service_is_the_one_off_owner(self):
        for name in self.FILES:
            services = self.load(name)['services']
            migrate = services['migrate']
            env = self.env_of(migrate)
            self.assertEqual(env['POSTGRES_PASSWORD'], '${POSTGRES_PASSWORD}', name)
            self.assertEqual(env['CVENGINE_DB_ROLE'], 'owner', name)
            self.assertEqual(env['CVENGINE_DB_OWNER_FALLBACK_FILE'], '/var/lib/cvengine-db-owner/password', name)
            self.assertNotIn('CVENGINE_DB_ALLOW_OWNER_FALLBACK', env, name)  # from .env (env_file), or -e from the scripts: never defaulted to off over it
            self.assertEqual(migrate['restart'], 'no', name)
            self.assertEqual(migrate['entrypoint'], '/usr/src/app/migrate-entrypoint.sh', name)
            self.assertEqual(migrate['image'], services['web']['image'], name)  # the same image as web
            for key in ('ports', 'healthcheck', 'profiles'):
                self.assertNotIn(key, migrate, name)
            self.assertIn('db_owner_fallback:/var/lib/cvengine-db-owner', migrate['volumes'], name)
            for service in APP_SERVICES:
                spec = services[service]
                self.assertEqual(spec['depends_on']['migrate'], {'condition': 'service_completed_successfully'}, f'{name} {service}')
                self.assertIn('db_owner_fallback:/var/lib/cvengine-db-owner:ro', spec['volumes'], f'{name} {service}')
                self.assertEqual(self.env_of(spec)['CVENGINE_DB_OWNER_FALLBACK_FILE'], '/var/lib/cvengine-db-owner/password', f'{name} {service}')
            for service, spec in services.items():
                if service not in (*APP_SERVICES, 'migrate'):
                    self.assertFalse([v for v in spec.get('volumes') or [] if 'db_owner_fallback' in str(v)], f'{name} {service}')
            self.assertIn('db_owner_fallback', self.load(name)['volumes'], name)

    @unittest.skipUnless(shutil.which('docker') and subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0,
                         'needs docker compose')
    def test_compose_itself_gives_the_password_only_to_db_and_migrate(self):
        """The effective configuration (docker compose config: env_file merged, overlays applied), with a .env that holds the secrets."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for name in self.FILES:
                shutil.copy(ROOT / name, tmp / name)
            (tmp / '.env').write_text('POSTGRES_USER=cvengine\nPOSTGRES_PASSWORD=owner-canary\nDJANGO_SUPERUSER_PASSWORD=admin-canary\n'
                                      'CVENGINE_DB_APP_PASSWORD=app\nPOSTGRES_DB=cvengine\nPOSTGRES_HOST=db\nPOSTGRES_PORT=5432\nDOMAIN_NAME=x.test\n')
            (tmp / 'secrets' / 'certs').mkdir(parents=True)
            # CI exports its own POSTGRES_* values, and the shell wins over .env; only the .env canaries may count here.
            clean_env = {k: v for k, v in os.environ.items() if not k.startswith(('POSTGRES_', 'CVENGINE_DB_', 'DJANGO_SUPERUSER_', 'DOMAIN_NAME'))}
            for name in self.FILES:
                out = subprocess.run(['docker', 'compose', '-f', name, 'config', '--format', 'json'], cwd=tmp, capture_output=True, text=True, env=clean_env)
                self.assertEqual(out.returncode, 0, out.stderr[-2000:])
                services = json.loads(out.stdout)['services']
                holders = sorted(n for n, spec in services.items() if 'owner-canary' in json.dumps(spec.get('environment') or {}))
                self.assertEqual(holders, ['db', 'migrate'], name)
                self.assertFalse([n for n, spec in services.items() if 'admin-canary' in json.dumps(spec.get('environment') or {})
                                  and n != 'migrate'], name)

    def test_compose_reads_an_empty_app_user_as_empty_for_the_rollback(self):
        # ${VAR-default} (no colon): CVENGINE_DB_APP_USER= in the env file stays empty, which is the way back to the owner role
        text = (ROOT / 'docker-compose.yml').read_text()
        self.assertNotIn('${CVENGINE_DB_APP_USER:-', text)


class MigrateCallersTests(SimpleTestCase):
    """Every place that runs migrate (or createsuperuser) for real does it as the owner role, in the one-off migrate service (the only container
    with the owner's password); the application containers never do."""

    OWNER_LINE = re.compile(r'manage\.py (migrate(?! --check)(?! --plan)|createsuperuser|create_admin|showmigrations|db_app_role gate|test\b)')

    def sources(self):
        for path in [*sorted(SCRIPTS.glob('*.sh')), ROOT / 'Makefile', *sorted(WEB.glob('*.sh'))]:
            if path.is_file():
                yield path, path.read_text().splitlines()

    def test_every_owner_command_runs_in_the_migrate_service(self):
        wrong = []
        for path, lines in self.sources():
            for number, line in enumerate(lines, 1):
                if line.lstrip().startswith('#') or not self.OWNER_LINE.search(line):
                    continue
                where = f'{path.relative_to(ROOT)}:{number}: {line.strip()}'
                if path.name == 'migrate-entrypoint.sh':
                    continue  # the migrate service itself (CVENGINE_DB_ROLE=owner is exported there)
                in_migrate = re.search(r'\bmigrate python3 (manage\.py|"\$@")', line) or re.search(r'migrate python3 "\$@"', line)
                owner_run = re.match(r'\s*(?:if ! |plan=\$\()?owner_run\b', line)
                # the fallback for a Compose layout without the migrate service, and the built-in deploy of checkouts older than update-deploy.sh
                legacy = 'CVENGINE_DB_ROLE=owner --entrypoint python3 web' in line
                if not (in_migrate or owner_run or legacy):
                    wrong.append(where)
                if re.search(r'exec\b.*\bweb\b.*manage\.py (migrate(?! --check)|createsuperuser)', line):
                    wrong.append(where + ' (web has no owner password)')
        self.assertEqual(wrong, [])

    def test_the_owner_run_helpers_use_the_migrate_service(self):
        for name in ('update-deploy.sh', 'update.sh'):
            text = (SCRIPTS / name).read_text()
            body = text[text.index('owner_run() {'):]
            body = body[:body.index('\n}\n')]
            self.assertIn('migrate python3 "$@"', body, name)
            self.assertIn('--entrypoint python3 web "$@"', body, name)  # only for a layout without the service

    def test_no_application_entrypoint_migrates_or_forces_the_owner_role(self):
        for name in ('entrypoint.sh', 'celery-entrypoint.sh', 'beat-entrypoint.sh'):
            text = (WEB / name).read_text()
            code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
            self.assertNotIn('migrate --noinput', code, name)
            self.assertNotIn('CVENGINE_DB_ROLE=owner', code, name)
            # the role is chosen first, then the container waits for the migrations as that role
            self.assertLess(code.index('cvengine_db_role'), code.index('manage.py migrate --check'), name)
        web = (WEB / 'entrypoint.sh').read_text()
        self.assertLess(web.index('manage.py migrate --check'), web.index('gunicorn'))
        migrate = (WEB / 'migrate-entrypoint.sh').read_text()
        self.assertIn('export CVENGINE_DB_ROLE=owner', migrate)
        self.assertLess(migrate.index('python3 manage.py migrate --noinput'), migrate.index('exec python3 manage.py db_app_role gate'))
        self.assertLess(migrate.index('export CVENGINE_DB_ROLE=owner'), migrate.index('exec "$@"'))

    def test_the_post_migrate_step_is_connected(self):
        from django.db.models.signals import post_migrate
        self.assertTrue(any('cvengine-db-app-role' in str(receiver[0]) for receiver in post_migrate.receivers))

    def test_the_update_scripts_generate_the_password_check_the_role_then_migrate_and_restart(self):
        deploy = (SCRIPTS / 'update-deploy.sh').read_text()
        steps = deploy[deploy.index('deploy_steps() {'):]
        order = [steps.index(step) for step in ('cvengine_ensure_db_app_password', 'backup_database || return 1', 'check_db_roles || return 1',
                                                'DEPLOY_STAGE=migrate', 'run_migrations || return 1',
                                                'up -d --no-deps --force-recreate "${services[@]}"', 'verify_serving || return 1',
                                                'cvengine_db_role_report "${compose[@]}"')]
        self.assertEqual(order, sorted(order))
        check = deploy[deploy.index('check_db_roles() {'):]
        self.assertLess(check.index('cvengine_owner_password_check'), check.index('cvengine_db_gate'))
        update = (SCRIPTS / 'update.sh').read_text()
        order = [update.index(step) for step in ('cvengine_ensure_db_app_password', 'scripts/db-backup.sh "$STATE"', 'cvengine_owner_password_check "${compose[@]}" || die',
                                                 'cvengine_db_gate "${compose[@]}" || die', 'owner_run manage.py migrate --noinput',
                                                 'up -d --no-deps --force-recreate "${services[@]}"')]
        self.assertEqual(order, sorted(order))
        make = (ROOT / 'Makefile').read_text()
        up = make[make.index('\nup:'):make.index('\nbuild:')]
        order = [up.index(step) for step in ('cvengine_ensure_db_app_password', 'cvengine_owner_password_check', 'build web', 'up -d db redis',
                                             ') migrate\n', 'up -d --build --no-deps ${SERVICES}')]
        self.assertEqual(order, sorted(order))
        self.assertIn('cvengine_db_role_report', update)
        self.assertIn('cvengine_ensure_db_app_password', (ROOT / 'Makefile').read_text())
        self.assertIn('fill CVENGINE_DB_APP_PASSWORD', (SCRIPTS / 'init-env.sh').read_text())


class PasswordScriptTests(SimpleTestCase):
    """scripts/db-app-role.sh, in the style of scripts/redis-password.sh."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', str(self.tmp)]))

    def run_ensure(self, env_file=''):
        script = f'. {SCRIPTS / "db-app-role.sh"} && cvengine_ensure_db_app_password "$1"'
        return subprocess.run(['bash', '-c', script, 'x', env_file], cwd=self.tmp, capture_output=True, text=True).returncode

    def value(self, name, key='CVENGINE_DB_APP_PASSWORD'):
        lines = [line for line in (self.tmp / name).read_text().splitlines() if line.startswith(f'{key}=')]
        return lines[-1].split('=', 1)[1] if lines else None

    def test_generates_once_into_dot_env_and_the_compose_env_file(self):
        (self.tmp / '.env').write_text('POSTGRES_USER=cvengine\nCVENGINE_DB_APP_PASSWORD=\n')
        (self.tmp / '.env.vps').write_text('POSTGRES_USER=cvengine')  # no final newline
        self.assertEqual(self.run_ensure('.env.vps'), 0)
        password = self.value('.env')
        self.assertRegex(password, r'^[A-Za-z0-9]{32}$')
        self.assertEqual(self.value('.env.vps'), password)
        self.assertIn('POSTGRES_USER=cvengine\nCVENGINE_DB_APP_PASSWORD=', (self.tmp / '.env.vps').read_text())
        # idempotent: a second run changes nothing
        self.assertEqual(self.run_ensure('.env.vps'), 1)
        self.assertEqual((self.value('.env'), self.value('.env.vps')), (password, password))
        self.assertEqual((self.tmp / '.env').read_text().count('CVENGINE_DB_APP_PASSWORD='), 1)

    def test_an_existing_password_is_copied_never_replaced(self):
        (self.tmp / '.env').write_text('CVENGINE_DB_APP_PASSWORD=keepme123\n')
        (self.tmp / '.env.vps').write_text('X=1\n')
        self.assertEqual(self.run_ensure('.env.vps'), 0)
        self.assertEqual((self.value('.env'), self.value('.env.vps')), ('keepme123', 'keepme123'))
        self.assertEqual(self.run_ensure(''), 1)

    def test_the_rollback_is_respected(self):
        (self.tmp / '.env').write_text('CVENGINE_DB_APP_USER=\n')
        self.assertEqual(self.run_ensure(''), 1)
        self.assertIsNone(self.value('.env'))

    def test_no_env_file_no_change(self):
        self.assertEqual(self.run_ensure(''), 1)
        self.assertFalse((self.tmp / '.env').exists())

    def test_the_report_names_a_service_on_the_owner_role(self):
        stub = self.tmp / 'compose'
        stub.write_text('#!/bin/sh\ncase "$*" in *celery-beat*) echo "owner cvengine (CVENGINE_DB_APP_PASSWORD is empty)";; '
                        '*) echo "app cvengine_app";; esac\n')
        stub.chmod(0o755)
        out = subprocess.run(['bash', '-c', f'. {SCRIPTS / "db-app-role.sh"} && cvengine_db_role_report {stub}'], cwd=self.tmp,
                             capture_output=True, text=True).stdout
        self.assertIn('Database role of web: app cvengine_app', out)
        self.assertIn('Database role of celery-beat: owner cvengine', out)
        self.assertIn('Warning: celery-beat still connects to the database as the owner role', out)

    def compose_stub(self, config_json):
        (self.tmp / 'config.json').write_text(config_json)
        stub = self.tmp / 'compose'
        stub.write_text('#!/bin/sh\necho "$*" >> "$(dirname "$0")/calls"\n'
                        'case "$*" in *"config --format json"*) cat "$(dirname "$0")/config.json";; *"db_app_role gate"*) exit "${GATE_EXIT:-0}";; esac\n')
        stub.chmod(0o755)
        return stub

    def run_fn(self, call, **env):
        return subprocess.run(['bash', '-c', f'. {SCRIPTS / "db-app-role.sh"} && {call}'], cwd=self.tmp, capture_output=True, text=True,
                              env={**{k: v for k, v in os.environ.items() if k != 'CVENGINE_DB_ALLOW_OWNER_FALLBACK'}, **env})

    def test_the_owner_password_check_names_a_service_an_overlay_hands_it_to_and_never_the_value(self):
        config = json.dumps({'services': {
            'db': {'environment': {'POSTGRES_PASSWORD': 'canary-pw'}}, 'migrate': {'environment': {'POSTGRES_PASSWORD': 'canary-pw'}},
            'web': {'environment': {'POSTGRES_PASSWORD': ''}}, 'celery': {'environment': {'POSTGRES_PASSWORD': 'canary-pw'}},
            'celery-beat': {'environment': {'POSTGRES_PASSWORD_FILE': '/run/secrets/pw'}}, 'proxy': {}}})
        result = self.run_fn(f'cvengine_owner_password_check {self.compose_stub(config)} -f docker-compose.yml -f docker-compose.vps.yml')
        self.assertEqual(result.returncode, 1)
        self.assertIn('gives the database owner password to: celery celery-beat.', result.stdout)
        self.assertIn('Fix: remove POSTGRES_PASSWORD from the environment of celery celery-beat', result.stdout)
        self.assertNotIn('canary', result.stdout + result.stderr)

    def test_the_owner_password_check_passes_the_shipped_layout_and_an_unreadable_one(self):
        config = json.dumps({'services': {'db': {'environment': {'POSTGRES_PASSWORD': 'x'}}, 'migrate': {'environment': {'POSTGRES_PASSWORD': 'x'}},
                                          'web': {'environment': {'POSTGRES_PASSWORD': ''}}, 'reviewer': {'environment': {'A': 'b'}}}})
        self.assertEqual(self.run_fn(f'cvengine_owner_password_check {self.compose_stub(config)}').returncode, 0)
        self.assertEqual(self.run_fn(f'cvengine_owner_password_check {self.compose_stub("not json")}').returncode, 0)

    def test_the_fallback_switch_is_read_from_the_environment_the_compose_env_file_or_dot_env(self):
        self.assertEqual(self.run_fn('cvengine_db_owner_fallback').stdout.strip(), '0')
        (self.tmp / '.env').write_text('CVENGINE_DB_ALLOW_OWNER_FALLBACK=1\n')
        self.assertEqual(self.run_fn('cvengine_db_owner_fallback').stdout.strip(), '1')
        (self.tmp / '.env.vps').write_text('CVENGINE_DB_ALLOW_OWNER_FALLBACK=0\n')
        self.assertEqual(self.run_fn('cvengine_db_owner_fallback .env.vps').stdout.strip(), '0')
        self.assertEqual(self.run_fn('cvengine_db_owner_fallback .env.vps', CVENGINE_DB_ALLOW_OWNER_FALLBACK='1').stdout.strip(), '1')
        (self.tmp / '.env').write_text('CVENGINE_DB_ALLOW_OWNER_FALLBACK=yes\n')
        self.assertEqual(self.run_fn('cvengine_db_owner_fallback').stdout.strip(), '0')

    def test_the_gate_runs_in_the_migrate_service_with_the_switch_and_returns_its_status(self):
        stub = self.compose_stub('{}')
        (self.tmp / '.env.vps').write_text('CVENGINE_DB_ALLOW_OWNER_FALLBACK=1\n')
        self.assertEqual(self.run_fn(f'cvengine_db_gate {stub} --env-file .env.vps -f docker-compose.yml').returncode, 0)
        self.assertEqual(self.run_fn(f'cvengine_db_gate {stub} -f docker-compose.yml', GATE_EXIT='1').returncode, 1)
        calls = (self.tmp / 'calls').read_text().splitlines()
        self.assertEqual(calls[0], '--env-file .env.vps -f docker-compose.yml run --rm --no-deps -T -e CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 migrate '
                                   'python3 manage.py db_app_role gate')
        self.assertIn('-e CVENGINE_DB_ALLOW_OWNER_FALLBACK=0 migrate', calls[1])

    def test_make_dbshell_and_the_backups_use_the_owner_inside_the_db_container(self):
        make = (ROOT / 'Makefile').read_text()
        dbshell = make[make.index('\ndbshell:'):]
        dbshell = dbshell[:dbshell.index('\n\n')]
        self.assertIn('exec db sh -c \'exec psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"\'', dbshell)
        for name in ('db-backup.sh', 'auto-deploy.sh'):
            self.assertIn('sh -c \'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"\'', (SCRIPTS / name).read_text(), name)
        for target in ('admin', 'admin-password', 'username', 'migrate', 'test'):
            body = make[make.index(f'\n{target}:'):]
            body = body[:body.index('\n\n')]
            self.assertIn(' migrate', body.replace('migrate:', ''), target)
            self.assertNotIn('exec web', body, target)
            self.assertNotIn('exec -T web', body, target)
            self.assertNotIn('exec -e CVENGINE_DB_ROLE=owner web', body, target)


class DocsTests(SimpleTestCase):
    def test_the_docs_explain_the_roles_the_update_and_the_rollback(self):
        config = (ROOT / 'docs' / 'CONFIGURATION.md').read_text()
        for word in ('CVENGINE_DB_APP_USER', 'CVENGINE_DB_APP_PASSWORD', 'CVENGINE_DB_ROLE', 'CVENGINE_DB_ROLE_WAIT', 'POSTGRES_LOG_CONNECTIONS',
                     'POSTGRES_LOG_DISCONNECTIONS', 'CVENGINE_LOG_MAX_SIZE', 'CVENGINE_LOG_MAX_FILE', 'pg_maintain', 'data_network'):
            self.assertIn(word, config)
        upgrade = (ROOT / 'docs' / 'UPGRADE.md').read_text()
        for phrase in ('Database roles', 'CVENGINE_DB_APP_USER=', 'cvengine_app', 'celery-beat', 'reviewer'):
            self.assertIn(phrase, upgrade)
        deployment = (ROOT / 'docs' / 'DEPLOYMENT.md').read_text()
        for phrase in ('cvengine_app', 'data_network', 'CVENGINE_LOG_MAX_SIZE', 'log_connections'):
            self.assertIn(phrase, deployment)

    def test_the_docs_explain_the_migrate_service_and_the_explicit_fallback(self):
        for name in ('CONFIGURATION.md', 'UPGRADE.md', 'DEPLOYMENT.md'):
            text = (ROOT / 'docs' / name).read_text()
            for phrase in ('CVENGINE_DB_ALLOW_OWNER_FALLBACK=1', 'migrate', 'POSTGRES_PASSWORD'):
                self.assertIn(phrase, text, name)
        upgrade = (ROOT / 'docs' / 'UPGRADE.md').read_text()
        section = upgrade[upgrade.index('### The owner password leaves the application containers'):]
        section = section[:section.index('\n### ')]
        for phrase in ('What restarts', 'What an operator does on an existing install', 'docker-compose.vps.yml', 'Fix:', 'make dbshell',
                       'db_owner_fallback'):
            self.assertIn(phrase, section)
        self.assertIn('CVENGINE_DB_OWNER_FALLBACK_FILE', (ROOT / 'docs' / 'CONFIGURATION.md').read_text())
