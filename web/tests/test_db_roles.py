"""The least privilege database role (reNgine/db_roles.py): which role a process uses, the GRANT statements, the entrypoints' fallback, the
scripts that generate its password, the compose files' data network and log rotation, and the docs. The grants against a real database are
in tests/test_db_app_role_grants.py."""
import importlib
import os
import re
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
            self.assertEqual(on_it, sorted(['db', 'redis', *APP_SERVICES]), name)
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
        self.assertEqual(compose['services']['web']['ports'], ['127.0.0.1:8000:8000'])
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
                if service in APP_SERVICES:
                    self.assertIn('CVENGINE_DB_APP_USER=${CVENGINE_DB_APP_USER-cvengine_app}', env, f'{name} {service}')
                    self.assertIn('CVENGINE_DB_APP_PASSWORD=${CVENGINE_DB_APP_PASSWORD:-}', env, f'{name} {service}')
                else:
                    self.assertFalse({'CVENGINE_DB_APP_USER', 'CVENGINE_DB_APP_PASSWORD'} & keys, f'{name} {service}')

    def test_compose_reads_an_empty_app_user_as_empty_for_the_rollback(self):
        # ${VAR-default} (no colon): CVENGINE_DB_APP_USER= in the env file stays empty, which is the way back to the owner role
        text = (ROOT / 'docker-compose.yml').read_text()
        self.assertNotIn('${CVENGINE_DB_APP_USER:-', text)


class MigrateCallersTests(SimpleTestCase):
    """Every place that runs migrate (or createsuperuser) for real uses the owner role; the runtime never does."""

    def test_every_migrate_call_names_the_owner_role(self):
        sources = [*sorted(SCRIPTS.glob('*.sh')), ROOT / 'Makefile', *sorted(WEB.glob('*.sh'))]
        missing = []
        for path in sources:
            if not path.is_file():
                continue
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if line.lstrip().startswith('#'):
                    continue
                if re.search(r'manage\.py (migrate(?! --check)(?! --plan)|createsuperuser)\b', line) and 'CVENGINE_DB_ROLE=owner' not in line:
                    missing.append(f'{path.relative_to(ROOT)}:{number}: {line.strip()}')
        self.assertEqual(missing, [])

    def test_the_web_entrypoint_migrates_as_owner_then_chooses_its_runtime_role(self):
        text = (WEB / 'entrypoint.sh').read_text()
        self.assertLess(text.index('CVENGINE_DB_ROLE=owner python3 manage.py migrate --noinput'), text.index('cvengine_db_role 0'))
        self.assertLess(text.index('cvengine_db_role 0'), text.index('gunicorn'))
        for name in ('celery-entrypoint.sh', 'beat-entrypoint.sh'):
            # the workers wait for the migrations as the owner (the app role does not exist before web's first migrate), then choose
            text = (WEB / name).read_text()
            self.assertLess(text.index('CVENGINE_DB_ROLE=owner python3 manage.py migrate --check'), text.index('cvengine_db_role "${CVENGINE_DB_ROLE_WAIT:-60}"'), name)

    def test_the_post_migrate_step_is_connected(self):
        from django.db.models.signals import post_migrate
        self.assertTrue(any('cvengine-db-app-role' in str(receiver[0]) for receiver in post_migrate.receivers))

    def test_the_update_scripts_generate_the_password_and_report_the_role(self):
        deploy = (SCRIPTS / 'update-deploy.sh').read_text()
        self.assertLess(deploy.index('cvengine_ensure_db_app_password'), deploy.index('run_migrations || return 1'))
        self.assertLess(deploy.index('verify_serving || return 1'), deploy.index('cvengine_db_role_report "${compose[@]}"'))
        update = (SCRIPTS / 'update.sh').read_text()
        self.assertLess(update.index('cvengine_ensure_db_app_password'), update.index('manage.py migrate --noinput'))
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
