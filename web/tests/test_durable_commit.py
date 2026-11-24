"""The writes that must survive a crash commit durably while the database runs with ``synchronous_commit=off`` server wide
(POSTGRES_SYNCHRONOUS_COMMIT in the compose files): ``usage_stamps.durable_commit`` issues ``SET LOCAL synchronous_commit TO ON`` in the
transaction that carries them. Kept durable: every audit row except the routine Sentinel task lifecycle rows, every token revocation, an address
ban and a validation budget reservation. Everything else keeps the server wide relaxed commit.

The SET is proved two ways: the statement is captured before the write it covers, and (TransactionTestCase, so the write really commits on its
own) ``SHOW synchronous_commit`` run on the same cursor just before the INSERT reads ``on`` while the session itself is ``off``."""
import re
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection, transaction
from django.test import RequestFactory, TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext

from agentapi.auth import create_token
from cvengine import usage_stamps
from dashboard.models import AbuseBan, ApiToken, AuditLog
from tenancy import audit

WEB = Path(__file__).resolve().parents[1]
DURABLE = 'SET LOCAL synchronous_commit TO ON'


def _sqls(ctx):
    return [q['sql'] for q in ctx.captured_queries]


def _index(sqls, prefix):
    return next(i for i, s in enumerate(sqls) if s.startswith(prefix))


class DurableCommitHelperTests(TestCase):
    def test_inside_an_open_transaction_it_sets_the_callers_commit_durable_without_a_savepoint(self):
        with CaptureQueriesContext(connection) as ctx:
            with usage_stamps.durable_commit() as made:
                self.assertTrue(made)
        self.assertEqual(_sqls(ctx), [DURABLE])

    def test_a_security_audit_row_is_written_with_the_setting_made_first(self):
        user = User.objects.create_user('durable_audit', password='x')
        with CaptureQueriesContext(connection) as ctx:
            audit.record(user, 'token.revoke', user.username, token_id=1)
        sqls = _sqls(ctx)
        self.assertLess(sqls.index(DURABLE), _index(sqls, 'INSERT INTO "dashboard_auditlog"'))

    def test_the_routine_sentinel_task_rows_keep_the_relaxed_commit(self):
        for action in sorted(AuditLog.RELAXED_ACTIONS):
            with self.subTest(action), CaptureQueriesContext(connection) as ctx:
                audit.record(None, action, 'sentinel task #1 discover example.com', task_id=1)
            self.assertNotIn(DURABLE, _sqls(ctx))
            self.assertEqual(len([s for s in _sqls(ctx) if s.startswith('INSERT INTO "dashboard_auditlog"')]), 1)

    def test_the_relaxed_actions_are_the_routine_rows_the_weekly_prune_removes_and_nothing_else(self):
        from cveFeed.maintenance import ROUTINE_AUDIT_ACTIONS
        self.assertEqual(AuditLog.RELAXED_ACTIONS - set(ROUTINE_AUDIT_ACTIONS), {'sentinel.task.expire_sweep'})
        self.assertTrue(set(ROUTINE_AUDIT_ACTIONS) <= AuditLog.RELAXED_ACTIONS)
        for action in ('sentinel.secret.read', 'sentinel.discovery_keys.delivered', 'sentinel.check.refused', 'token.revoke', 'agent.revoke',
                       'abuse.ip_banned', 'account.login_locked', 'account.password_change', 'update.applied'):
            self.assertNotIn(action, AuditLog.RELAXED_ACTIONS)

    def test_the_rows_written_are_the_same(self):
        user = User.objects.create_user('durable_same', password='x')
        audit.record(user, 'token.create', 'durable_same', token='abc', read_only=False)
        row = AuditLog.objects.get(action='token.create', target='durable_same')
        self.assertEqual((row.actor_id, row.actor_name, row.detail), (user.pk, 'durable_same', {'token': 'abc', 'read_only': False}))


class RevocationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('durable_revoke', password='x')

    def test_an_administrator_reset_revokes_the_tokens_durably(self):
        from cveFeed import admin_api
        token, _ = create_token(self.user, 'one')
        with CaptureQueriesContext(connection) as ctx:
            admin_api._revoke_tokens(self.user)
        sqls = _sqls(ctx)
        self.assertLess(sqls.index(DURABLE), _index(sqls, 'UPDATE "dashboard_apitoken"'))
        self.assertTrue(ApiToken.objects.get(pk=token.pk).revoked)

    def test_revoking_a_token_through_the_api_is_durable(self):
        from tests.test_agentapi import call
        token, _ = create_token(self.user, 'two')
        with CaptureQueriesContext(connection) as ctx:
            status, body = call(self.user, 'DELETE', f'/api/v1/tokens/{token.pk}')
        self.assertEqual((status, body), (200, {'revoked': True}))
        sqls = _sqls(ctx)
        update = next(i for i, s in enumerate(sqls) if s.startswith('UPDATE "dashboard_apitoken"') and '"revoked"' in s)
        self.assertIn(DURABLE, sqls[:update])
        self.assertTrue(ApiToken.objects.get(pk=token.pk).revoked)

    def test_every_revocation_in_the_code_is_inside_a_durable_commit(self):
        """A source scan: each ``.update(revoked=True)`` outside tests and migrations sits in a ``with durable_commit():`` block opened on the line
        just above it, so a new revocation cannot slip back to the relaxed commit unnoticed."""
        found, wrong = 0, []
        for path in sorted(WEB.rglob('*.py')):
            rel = path.relative_to(WEB).as_posix()
            if rel.startswith('tests/') or '/migrations/' in rel:
                continue
            lines = path.read_text().splitlines()
            for number, line in enumerate(lines):
                if '.update(revoked=True)' not in line:
                    continue
                found += 1
                if not re.match(r'\s*with (?:usage_stamps\.)?durable_commit\(\):', lines[number - 1]):
                    wrong.append(f'{rel}:{number + 1}')
        self.assertGreaterEqual(found, 7)
        self.assertEqual(wrong, [])


class BanAndBudgetTests(TestCase):
    def test_an_address_ban_is_durable(self):
        from cvengine import input_guard
        request = RequestFactory().post('/api/v1/targets', HTTP_SEC_FETCH_SITE='same-origin')
        with mock.patch.dict('os.environ', {'CVENGINE_GUARD_STRIKES': '1'}), CaptureQueriesContext(connection) as ctx:
            self.assertTrue(input_guard.record_and_maybe_ban(request, [('sqli', 5, 'name', "' or 1=1 --")], '8.8.4.4', None))
        sqls = _sqls(ctx)
        self.assertLess(sqls.index(DURABLE), _index(sqls, 'INSERT INTO "dashboard_abuseban"'))
        self.assertTrue(AbuseBan.objects.filter(ip='8.8.4.4', lifted=False).exists())

    def test_a_validation_budget_reservation_is_durable(self):
        from cveFeed import validation
        validation._reserve_validation_check(424242)  # the first of the day creates the rows
        with CaptureQueriesContext(connection) as ctx:
            self.assertTrue(validation._reserve_validation_check(424242))
        sqls = _sqls(ctx)
        self.assertLess(sqls.index(DURABLE), _index(sqls, 'UPDATE "cveFeed_validationbudget"'))
        self.assertEqual(validation.ran_today(424242), 2)


class RealCommitTests(TransactionTestCase):
    """Outside a transaction the write commits on its own, durably; the session's own setting is untouched afterwards."""

    def setUp(self):
        with connection.cursor() as cursor:
            cursor.execute('SET synchronous_commit TO off')  # what the server runs with; the rig may say otherwise
        self.addCleanup(self._reset)

    def _reset(self):
        with connection.cursor() as cursor:
            cursor.execute('RESET synchronous_commit')

    def _setting_at(self, table, write):
        seen = []

        def wrapper(execute, sql, params, many, context):
            if sql.startswith(f'INSERT INTO "{table}"') and not context.get('probed'):
                context['probed'] = True
                context['cursor'].execute('SHOW synchronous_commit')
                seen.append(context['cursor'].fetchone()[0])
            return execute(sql, params, many, context)

        with connection.execute_wrapper(wrapper):
            write()
        return seen

    def show(self):
        with connection.cursor() as cursor:
            cursor.execute('SHOW synchronous_commit')
            return cursor.fetchone()[0]

    def test_a_security_audit_row_commits_durably_and_the_session_stays_relaxed(self):
        self.assertFalse(connection.in_atomic_block)
        self.assertEqual(self._setting_at('dashboard_auditlog', lambda: audit.record(None, 'update.applied', 'abc1234')), ['on'])
        self.assertEqual(self.show(), 'off')

    def test_a_routine_row_keeps_the_relaxed_commit(self):
        self.assertEqual(self._setting_at('dashboard_auditlog', lambda: audit.record(None, 'sentinel.task.claim', 'sentinel task #1')), ['off'])

    def test_inside_a_callers_transaction_the_whole_commit_is_durable_and_ends_with_it(self):
        with transaction.atomic():
            seen = self._setting_at('dashboard_auditlog', lambda: audit.record(None, 'update.approved', 'abc1234'))
            self.assertEqual(self.show(), 'on')  # SET LOCAL: until this transaction's commit
        self.assertEqual(seen, ['on'])
        self.assertEqual(self.show(), 'off')
