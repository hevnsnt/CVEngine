"""The app role against a real database: created and granted by reNgine/db_roles.ensure (the step every migrate runs as the owner role), it can
read and write the application's tables, use their sequences, take advisory locks and ANALYZE (pg_maintain), and it cannot create roles,
create extensions, drop or truncate a table it does not own, create tables, ALTER SYSTEM, or run programs and read files on the server.

The test runner's role is a superuser (as the owner is on a stock install), so it plays the owner here and a second role is created for each
test with a unique name (roles are shared by every database of the server) and dropped afterwards."""
import os
import secrets
from unittest import mock

import psycopg2
from django.core.management import call_command
from django.db import connection
from django.test import TransactionTestCase

from reNgine import db_roles


class AppRoleGrantTests(TransactionTestCase):
    def setUp(self):
        self.app = f'cvengine_app_t{os.getpid()}_{secrets.token_hex(3)}'
        self.password = secrets.token_hex(16)
        self.owner = connection.settings_dict['USER']
        self.connections = []
        self.tables = []
        self.addCleanup(self.drop)

    def drop(self):
        for conn in self.connections:
            conn.close()
        with connection.cursor() as cursor:
            for table in self.tables:
                cursor.execute(f'DROP TABLE IF EXISTS {db_roles.ident(table)}')
            cursor.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', [self.app])
            if cursor.fetchone():
                cursor.execute(f'DROP OWNED BY {db_roles.ident(self.app)}')  # its grants and default privileges in this database
                cursor.execute(f'DROP ROLE {db_roles.ident(self.app)}')

    def login(self, password=None):
        settings = connection.settings_dict
        conn = psycopg2.connect(dbname=settings['NAME'], user=self.app, password=password or self.password, host=settings['HOST'],
                                port=settings['PORT'] or None, connect_timeout=10)
        conn.autocommit = True
        self.connections.append(conn)
        return conn

    def ensure(self):
        return db_roles.ensure(connection, self.app, self.password)

    def refused(self, conn, sql):
        with conn.cursor() as cursor:
            with self.assertRaises(psycopg2.Error, msg=sql) as caught:
                cursor.execute(sql)
        return caught.exception

    def test_the_app_role_is_ordinary_and_can_do_what_the_application_needs(self):
        result = self.ensure()
        self.assertTrue(result['created'])
        self.assertEqual(result['owner'], self.owner)
        with connection.cursor() as cursor:
            cursor.execute('SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = %s',
                           [self.app])
            self.assertEqual(cursor.fetchone(), (False, False, False, False, False, True))
            cursor.execute("SELECT current_setting('server_version_num')::int")
            version = cursor.fetchone()[0]
        self.assertEqual(result['maintain'], version >= db_roles.MAINTAIN_SINCE)
        app = self.login()
        with app.cursor() as cursor:
            cursor.execute('SELECT current_user')
            self.assertEqual(cursor.fetchone()[0], self.app)
            # read and write an application table, through its identity sequence
            cursor.execute("INSERT INTO auth_group (name) VALUES ('db role test') RETURNING id")
            group = cursor.fetchone()[0]
            cursor.execute("UPDATE auth_group SET name = 'db role test 2' WHERE id = %s", [group])
            cursor.execute('SELECT name FROM auth_group WHERE id = %s', [group])
            self.assertEqual(cursor.fetchone()[0], 'db role test 2')
            cursor.execute('DELETE FROM auth_group WHERE id = %s', [group])
            self.assertEqual(cursor.rowcount, 1)
            # the sequence reset load_default_fixtures runs after it inserted rows with explicit keys
            cursor.execute("SELECT setval(pg_get_serial_sequence('\"auth_group\"', 'id'), coalesce(max(\"id\"), 1), max(\"id\") IS NOT null) FROM \"auth_group\"")
            # what the code runs besides the ORM: advisory locks, session settings, statistics views
            cursor.execute('BEGIN')
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', [21860073])
            cursor.execute('SET LOCAL statement_timeout = 5000')
            cursor.execute('COMMIT')
            cursor.execute('SELECT pg_database_size(current_database())')
            cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'")
            cursor.execute('SELECT relname, n_tup_ins FROM pg_stat_user_tables LIMIT 1')
            cursor.execute('SELECT count(*) FROM django_migrations')  # migrate --check
            if result['maintain']:
                del app.notices[:]
                cursor.execute('ANALYZE auth_group')  # cveFeed.db_stats runs ANALYZE from a Celery task
                self.assertFalse([n for n in app.notices if 'permission denied' in n or 'skipping' in n], app.notices)

    def test_the_app_role_cannot_do_what_a_superuser_or_owner_can(self):
        self.ensure()
        app = self.login()
        refused = {
            'CREATE ROLE': f'CREATE ROLE {db_roles.ident(self.app + "_x")}',
            'CREATE EXTENSION (a trusted one)': 'CREATE EXTENSION IF NOT EXISTS hstore',
            'DROP TABLE': 'DROP TABLE auth_group',
            'TRUNCATE': 'TRUNCATE auth_group',
            'ALTER TABLE': 'ALTER TABLE auth_group ADD COLUMN x int',
            'CREATE TABLE': 'CREATE TABLE public.db_role_probe (id int)',
            'ALTER SYSTEM': "ALTER SYSTEM SET work_mem = '8MB'",
            'COPY TO PROGRAM': "COPY (SELECT 1) TO PROGRAM 'true'",
            'read a server file': "SELECT pg_read_file('/etc/hostname')",
            'GRANT to itself': f'GRANT {db_roles.ident(self.owner)} TO {db_roles.ident(self.app)}',
            'ALTER ROLE itself': f'ALTER ROLE {db_roles.ident(self.app)} SUPERUSER',
        }
        for what, sql in refused.items():
            with self.subTest(what):
                self.refused(app, sql)
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM pg_extension WHERE extname = 'hstore'")
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT to_regclass('public.auth_group') IS NOT NULL, to_regclass('public.db_role_probe') IS NULL")
            self.assertEqual(cursor.fetchone(), (True, True))

    def test_tables_a_later_migration_creates_are_covered_by_default_privileges(self):
        self.ensure()
        table = f'db_role_t_{secrets.token_hex(3)}'
        self.tables.append(table)
        with connection.cursor() as cursor:  # as the owner, after the grants, as a migration would
            cursor.execute(f'CREATE TABLE {db_roles.ident(table)} (id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, v text)')
        app = self.login()
        with app.cursor() as cursor:
            cursor.execute(f"INSERT INTO {db_roles.ident(table)} (v) VALUES ('x') RETURNING id")
            cursor.execute(f'SELECT count(*) FROM {db_roles.ident(table)}')
            self.assertEqual(cursor.fetchone()[0], 1)
        self.refused(app, f'DROP TABLE {db_roles.ident(table)}')

    def test_ensure_is_idempotent_and_sets_the_password_each_time(self):
        def snapshot():
            with connection.cursor() as cursor:
                cursor.execute('SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid = d.defaclrole WHERE r.rolname = %s', [self.owner])
                default_acls = cursor.fetchone()[0]
                cursor.execute("SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = %s", [self.app])
                table_grants = cursor.fetchone()[0]
                cursor.execute('SELECT count(*) FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = %s', [self.app])
                return default_acls, table_grants, cursor.fetchone()[0]

        self.assertTrue(self.ensure()['created'])
        first = snapshot()
        self.assertGreater(first[1], 100)  # every application table, four privileges each
        self.assertFalse(self.ensure()['created'])
        self.assertEqual(snapshot(), first)
        self.login()
        old = self.password
        self.password = secrets.token_hex(16)
        self.ensure()
        self.login()
        with self.assertRaises(psycopg2.OperationalError):
            self.login(old)

    def test_a_membership_of_the_owner_added_by_hand_is_removed(self):
        self.ensure()
        with connection.cursor() as cursor:
            cursor.execute(f'GRANT {db_roles.ident(self.owner)} TO {db_roles.ident(self.app)}')
        self.ensure()
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_has_role(%s, %s, %s)', [self.app, self.owner, 'MEMBER'])
            self.assertFalse(cursor.fetchone()[0])

    def test_every_migrate_creates_and_grants_it_and_the_command_does_too(self):
        env = {'CVENGINE_DB_APP_USER': self.app, 'CVENGINE_DB_APP_PASSWORD': self.password}
        with mock.patch.dict(os.environ, env):
            call_command('migrate', verbosity=0)  # nothing to apply; the post_migrate step still runs
        self.login()
        self.password = secrets.token_hex(16)
        with mock.patch.dict(os.environ, {**env, 'CVENGINE_DB_APP_PASSWORD': self.password}):
            call_command('db_app_role', 'ensure', verbosity=0)
        self.login()

    def test_without_a_password_migrate_creates_nothing(self):
        with mock.patch.dict(os.environ, {'CVENGINE_DB_APP_USER': self.app, 'CVENGINE_DB_APP_PASSWORD': ''}):
            self.assertIsNone(db_roles.ensure_after_migrate())
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', [self.app])
            self.assertIsNone(cursor.fetchone())

    def test_the_entrypoint_choice_against_the_database(self):
        settings = connection.settings_dict
        environ = {'POSTGRES_DB': settings['NAME'], 'POSTGRES_HOST': settings['HOST'], 'POSTGRES_PORT': str(settings['PORT'] or ''),
                   'POSTGRES_USER': self.owner, 'POSTGRES_PASSWORD': settings['PASSWORD'],
                   'CVENGINE_DB_APP_USER': self.app, 'CVENGINE_DB_APP_PASSWORD': self.password}
        role, reason = db_roles.choose(environ)  # not created yet: the owner role, so nobody is locked out
        self.assertEqual(role, 'owner')
        self.assertIn(self.app, reason)
        self.ensure()
        self.assertEqual(db_roles.choose(environ), ('app', ''))

    def test_a_non_owner_connection_is_refused(self):
        with self.assertRaises(db_roles.RoleError):
            db_roles.ensure(connection, self.owner, self.password)
        with self.assertRaises(db_roles.RoleError):
            db_roles.ensure(connection, self.app, '')
