"""The web service gives every database statement a time limit, and a statement that runs past it is answered plainly (review 2 F2)."""
from unittest import mock

from django.db.utils import OperationalError
from django.test import SimpleTestCase

from agentapi import db_timeout, mcp


class Canceled(Exception):
    pgcode = '57014'


class CancelErrorTests(SimpleTestCase):
    def test_a_cancelled_statement_is_recognised_through_djangos_wrapper(self):
        try:
            try:
                raise Canceled('canceling statement due to statement timeout')
            except Canceled as inner:
                raise OperationalError('canceling statement') from inner
        except OperationalError as wrapped:
            self.assertTrue(db_timeout.hit(wrapped))

    def test_other_errors_are_not_a_timeout(self):
        self.assertFalse(db_timeout.hit(RuntimeError('boom')))
        self.assertFalse(db_timeout.hit(OperationalError('connection refused')))
        self.assertFalse(db_timeout.hit(None))


class SettingTests(SimpleTestCase):
    def test_the_option_reaches_the_connection_only_when_the_service_sets_it(self):
        import importlib
        import os

        from reNgine import settings
        with mock.patch.dict(os.environ, {'CVENGINE_WEB_STATEMENT_TIMEOUT_MS': '30000'}):
            importlib.reload(settings)
            self.assertIn('-c statement_timeout=30000', settings.DATABASES['default']['OPTIONS']['options'])
        with mock.patch.dict(os.environ, {'CVENGINE_WEB_STATEMENT_TIMEOUT_MS': '0'}):
            importlib.reload(settings)
            self.assertNotIn('statement_timeout', settings.DATABASES['default']['OPTIONS']['options'])
        importlib.reload(settings)

    def test_only_the_gunicorn_process_gets_it_not_the_migration_the_commands_or_the_workers(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[2]
        entry = (root / 'web' / 'entrypoint.sh').read_text()
        self.assertIn('export CVENGINE_WEB_STATEMENT_TIMEOUT_MS="${CVENGINE_WEB_STATEMENT_TIMEOUT_MS-30000}"', entry)
        self.assertLess(entry.index('manage.py migrate'), entry.index('export CVENGINE_WEB_STATEMENT_TIMEOUT_MS'))  # the migration runs without it
        self.assertLess(entry.index('export CVENGINE_WEB_STATEMENT_TIMEOUT_MS'), entry.index('exec python3 -m gunicorn'))
        self.assertNotIn('CVENGINE_WEB_STATEMENT_TIMEOUT_MS', (root / 'docker-compose.yml').read_text())  # not in the container's own environment


class McpTests(SimpleTestCase):
    def call(self, name, ident):
        return {'jsonrpc': '2.0', 'id': ident, 'method': 'tools/call', 'params': {'name': name, 'arguments': {}}}

    def test_the_heavy_tools_exist(self):
        for name in mcp.HEAVY_TOOLS:
            self.assertIn(name, mcp.BY_NAME)

    def test_a_cut_off_tool_call_is_a_tool_error_not_an_internal_error(self):
        with mock.patch.object(mcp, 'handle_message', side_effect=OperationalError('x')), \
                mock.patch.object(db_timeout, 'hit', return_value=True):
            out = mcp._internal_error(None, self.call('search_hosts', 7))
        self.assertEqual((out['id'], out['result']['isError']), (7, True))
        self.assertIn('narrow it', out['result']['content'][0]['text'])
