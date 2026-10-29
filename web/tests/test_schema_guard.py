"""A web process on newer code than its database answers 503 with Retry-After, not 500, while an update has not migrated yet."""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection, transaction
from django.test import TestCase

from reNgine import schema_guard
from tests.test_tenancy import client_for


def missing_column(*args, **kwargs):
    """A real database error: a query that names a column the table does not have (what new code does against the old schema)."""
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute('select no_such_column from auth_user')


def missing_table(*args, **kwargs):
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute('select 1 from no_such_table')


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('root', 'root@example.org', 'pw-Secret-1')

    def setUp(self):
        schema_guard._checked.update(at=0.0, pending=False)
        schema_guard._logged.update(at=0.0)
        self.client = client_for(self.root)


class BehindTests(Base):
    def error(self, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            return exc

    def test_a_missing_column_or_table_counts_only_while_migrations_are_waiting(self):
        for fn in (missing_column, missing_table):
            exc = self.error(fn)
            with mock.patch.object(schema_guard, 'migrations_pending', return_value=True):
                self.assertTrue(schema_guard.behind(exc), fn.__name__)
            with mock.patch.object(schema_guard, 'migrations_pending', return_value=False):
                self.assertFalse(schema_guard.behind(exc), fn.__name__)  # everything is migrated: it is a bug, and stays a 500

    def test_other_errors_never_count(self):
        with mock.patch.object(schema_guard, 'migrations_pending', return_value=True):
            for exc in (ValueError('x'), KeyError('x'), self.error(lambda: connection.cursor().execute('selec 1'))):
                self.assertFalse(schema_guard.behind(exc), repr(exc))

    def test_a_migrated_test_database_has_nothing_pending(self):
        self.assertFalse(schema_guard.migrations_pending())

    def test_the_pending_check_is_remembered_for_a_few_seconds(self):
        with mock.patch.object(schema_guard, 'MigrationExecutor') as executor:
            executor.return_value.migration_plan.return_value = [('app', 'migration')]
            self.assertTrue(schema_guard.migrations_pending())
            self.assertTrue(schema_guard.migrations_pending())
        self.assertEqual(executor.call_count, 1)

    def test_a_database_that_cannot_answer_is_not_behind(self):
        with mock.patch.object(schema_guard, 'MigrationExecutor', side_effect=RuntimeError('down')):
            self.assertFalse(schema_guard.migrations_pending())


class ApiTests(Base):
    def me(self, pending):
        with mock.patch('agentapi.services.me', side_effect=missing_column), \
                mock.patch.object(schema_guard, 'migrations_pending', return_value=pending):
            return self.client.get('/api/v1/me')

    def test_rest_answers_503_with_retry_after_while_an_update_is_pending(self):
        response = self.me(pending=True)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response['Retry-After'], str(schema_guard.RETRY_AFTER))
        self.assertIn('updating its database', response.json()['error'])

    def test_rest_stays_a_500_when_nothing_is_pending(self):
        self.assertEqual(self.me(pending=False).status_code, 500)

    def test_a_sentinel_poll_and_heartbeat_get_a_503_not_a_500(self):
        from agentapi import sentinel_broker
        from agentapi.auth import create_token
        from dashboard.models import Org, Project
        from django.utils import timezone
        from tests.test_agentapi import call
        from tests.test_sentinels import reset_rates
        org = Org.objects.create(name='Guard', slug='guard')
        Project.objects.create(name='G1', slug='g1', insert_date=timezone.now(), org=org)
        token = create_token(self.root, 'guard-sentinel')[1]
        reset_rates({'t': token})
        status, out = call(token, 'PUT', '/api/v1/sentinel', {'name': 'guard', 'scope': {'projects': ['g1']}, 'capabilities': ['nmap']})
        self.assertIn(status, (200, 201), out)
        for attr, path in (('next_task', '/api/v1/sentinel/tasks/next'), ('heartbeat', '/api/v1/sentinel/heartbeat')):
            with mock.patch.object(sentinel_broker, attr, side_effect=missing_column), \
                    mock.patch.object(schema_guard, 'migrations_pending', return_value=True):
                reset_rates({'t': token})
                self.assertEqual(call(token, 'POST', path, {})[0], 503, path)
            with mock.patch.object(sentinel_broker, attr, side_effect=missing_column), \
                    mock.patch.object(schema_guard, 'migrations_pending', return_value=False):
                reset_rates({'t': token})
                self.assertEqual(call(token, 'POST', path, {})[0], 500, path)


class WebTests(Base):
    def test_a_page_or_settings_route_answers_503_and_the_proxy_shows_its_maintenance_page(self):
        with mock.patch('cveFeed.settings_api.email_get', side_effect=missing_column), \
                mock.patch.object(schema_guard, 'migrations_pending', return_value=True):
            response = self.client.get('/cve/api/settings/email')
        self.assertEqual((response.status_code, response['Retry-After']), (503, str(schema_guard.RETRY_AFTER)))

    def test_the_same_error_is_a_500_once_migrated(self):
        self.client.raise_request_exception = False
        with mock.patch('cveFeed.settings_api.email_get', side_effect=missing_column), \
                mock.patch.object(schema_guard, 'migrations_pending', return_value=False):
            self.assertEqual(self.client.get('/cve/api/settings/email').status_code, 500)

    def test_mcp_lets_the_middleware_answer_503(self):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        with mock.patch('agentapi.mcp.handle_message', side_effect=missing_column), \
                mock.patch.object(schema_guard, 'migrations_pending', return_value=True):
            response = self.client.post('/mcp/', body, content_type='application/json')
        self.assertEqual(response.status_code, 503)
