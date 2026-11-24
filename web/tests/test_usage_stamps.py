"""Usage stamps (cvengine.usage_stamps): an API token's ``last_used_at``, an agent's ``last_seen`` and a Sentinel's machine numbers are written at most
once per their threshold, by one caller at a time per stale value, in a transaction of their own whose commit does not wait for the WAL flush. Token
authentication is unchanged by any of it: a revoked, expired, unknown or out-of-scope token is refused whatever the stamp, and nothing the stamp does
lets a request in. Security records (a revocation, the audit log) keep a normal commit."""
import threading
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import auth, sentinel_settings
from agentapi.auth import LAST_USED_RESOLUTION, create_token
from agentapi.models import Agent
from dashboard.models import ApiToken
from cvengine import usage_stamps
from tests.test_agentapi import call


def _token_updates(queries):
    return [q['sql'] for q in queries if q['sql'].startswith('UPDATE "dashboard_apitoken"')]


def _relaxed(queries):
    return [q['sql'] for q in queries if 'synchronous_commit' in q['sql']]


def _key(kind, pk, stored):
    return usage_stamps.KEY.format(kind=kind, pk=pk, stored=stored.isoformat() if stored is not None else 'none')


class TokenStampTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('stamp_user', password='x')
        cls.token, cls.raw = create_token(cls.user, 'stamps')

    def set_used(self, when):
        ApiToken.objects.filter(pk=self.token.pk).update(last_used_at=when)
        cache.delete(_key('apitoken', self.token.pk, when))

    def used(self):
        return ApiToken.objects.get(pk=self.token.pk).last_used_at

    def test_a_request_inside_the_threshold_writes_nothing(self):
        stored = timezone.now() - timedelta(seconds=30)
        self.set_used(stored)
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
        self.assertEqual(_token_updates(ctx.captured_queries), [])
        self.assertEqual(self.used(), stored)

    def test_a_request_after_the_threshold_still_writes_last_used(self):
        for stored in (timezone.now() - LAST_USED_RESOLUTION - timedelta(seconds=5), None):
            self.set_used(stored)
            before = timezone.now()
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
            self.assertEqual(len(_token_updates(ctx.captured_queries)), 1, stored)
            self.assertGreaterEqual(self.used(), before)

    def test_the_write_leaves_a_time_another_request_just_wrote(self):
        now = timezone.now()
        token = ApiToken.objects.get(pk=self.token.pk)
        token.last_used_at = now - timedelta(minutes=5)  # what this request read
        cache.delete(_key('apitoken', token.pk, token.last_used_at))
        ApiToken.objects.filter(pk=token.pk).update(last_used_at=now - timedelta(seconds=3))  # another request of the same token, meanwhile
        auth.stamp_last_used(token, now)
        self.assertEqual(self.used(), now - timedelta(seconds=3))

    def test_a_request_that_finds_another_writing_skips_the_write_and_is_still_served(self):
        stored = timezone.now() - timedelta(minutes=5)
        self.set_used(stored)
        cache.add(_key('apitoken', self.token.pk, stored), 1, 60)  # another request of the same token is writing this very stamp
        try:
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
            self.assertEqual(_token_updates(ctx.captured_queries), [])
        finally:
            cache.delete(_key('apitoken', self.token.pk, stored))
        with CaptureQueriesContext(connection) as ctx:  # once that write is done, the next request that finds it stale writes again
            self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
        self.assertEqual(len(_token_updates(ctx.captured_queries)), 1)

    def test_the_hold_ends_with_the_write(self):
        self.set_used(None)
        self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
        self.assertTrue(cache.add(_key('apitoken', self.token.pk, None), 1, 5))  # free again: the writer released it
        cache.delete(_key('apitoken', self.token.pk, None))

    def test_without_the_cache_every_stale_request_writes_as_before(self):
        self.set_used(None)
        with mock.patch.object(usage_stamps.cache, 'add', side_effect=ConnectionError('down')), CaptureQueriesContext(connection) as ctx:
            self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
        self.assertEqual(len(_token_updates(ctx.captured_queries)), 1)
        self.assertIsNotNone(self.used())

    def test_inside_an_open_transaction_the_write_joins_it_unchanged(self):
        self.set_used(None)
        token = ApiToken.objects.get(pk=self.token.pk)
        with CaptureQueriesContext(connection) as ctx:  # a TestCase always runs in a transaction: SET LOCAL would relax the caller's whole commit
            self.assertTrue(auth.stamp_last_used(token))
        self.assertEqual(_relaxed(ctx.captured_queries), [])
        self.assertEqual(len(_token_updates(ctx.captured_queries)), 1)


class NoBypassTests(TestCase):
    """The stamp sits after authentication and the scope check; whatever it does, it never lets a request in."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('stamp_gate', password='x')

    def test_refused_tokens_stay_refused_and_are_not_stamped(self):
        cases = []
        revoked, raw_revoked = create_token(self.user, 'revoked')
        ApiToken.objects.filter(pk=revoked.pk).update(revoked=True)
        cases.append((revoked, raw_revoked, 401))
        expired, raw_expired = create_token(self.user, 'expired', expires_at=timezone.now() - timedelta(minutes=1))
        cases.append((expired, raw_expired, 401))
        sentinel, raw_sentinel = create_token(self.user, 'sentinel-only', scope=auth.SCOPE_SENTINEL)
        cases.append((sentinel, raw_sentinel, 403))  # a Sentinel token may not read /api/v1/me
        for token, raw, status in cases:
            with mock.patch.object(usage_stamps.cache, 'add', return_value=False):  # even when the stamp would be skipped
                self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], status, token.name)
            with mock.patch.object(usage_stamps.cache, 'add', side_effect=ConnectionError('down')):  # or the cache is down
                self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], status, token.name)
            self.assertIsNone(ApiToken.objects.get(pk=token.pk).last_used_at, token.name)
        self.assertEqual(call('cve_not-a-real-token', 'GET', '/api/v1/me')[0], 401)
        self.assertEqual(call(None, 'GET', '/api/v1/me')[0], 401)

    def test_a_skipped_stamp_does_not_skip_authentication(self):
        token, raw = create_token(self.user, 'live')
        with mock.patch.object(usage_stamps.cache, 'add', return_value=False):
            status, body = call(raw, 'GET', '/api/v1/me')
        self.assertEqual(status, 200)
        self.assertEqual(body['username'], 'stamp_gate')
        ApiToken.objects.filter(pk=token.pk).update(revoked=True)  # revoked a moment later: refused at once, the stamp holds nothing that lets it in
        self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], 401)


class AgentTouchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('touch_user', password='x')
        token, _ = create_token(cls.user, 'touch')
        cls.agent = Agent.objects.create(token=token, name='touch-agent', kind='scanner', status='active')

    def test_a_call_that_finds_another_writing_skips_the_write_but_sees_itself_heard(self):
        agent = Agent.objects.get(pk=self.agent.pk)
        now = timezone.now()
        stored = now - timedelta(minutes=10)
        Agent.objects.filter(pk=agent.pk).update(last_seen=stored)
        agent.refresh_from_db()
        cache.add(_key('agent', agent.pk, stored), 1, 15)
        try:
            with self.assertNumQueries(0):
                broker._touch(agent, now)
        finally:
            cache.delete(_key('agent', agent.pk, stored))
        self.assertEqual(agent.last_seen, now)  # its own liveness reads say heard from now, as before
        self.assertEqual(Agent.objects.get(pk=agent.pk).last_seen, stored)
        agent.last_seen = stored
        with self.assertNumQueries(1):
            broker._touch(agent, now)
        self.assertEqual(Agent.objects.get(pk=agent.pk).last_seen, now)


def _show_in_update(table):
    """An execute wrapper that reads ``synchronous_commit`` on the same connection just before an UPDATE of ``table`` runs."""
    seen = []

    def wrapper(execute, sql, params, many, context):
        if sql.startswith(f'UPDATE "{table}"'):
            cursor = context['cursor']
            cursor.execute('SHOW synchronous_commit')
            seen.append((cursor.fetchone()[0], connection.in_atomic_block))
        return execute(sql, params, many, context)
    return seen, wrapper


class RelaxedCommitTests(TransactionTestCase):
    """Outside a test transaction, as on a real request: the stamp runs in its own transaction with synchronous_commit off, and only there."""

    def setUp(self):
        self.user = User.objects.create_user('relaxed_user', password='x')
        self.token, self.raw = create_token(self.user, 'relaxed')
        with connection.cursor() as cursor:
            cursor.execute('SET synchronous_commit TO on')  # the test database runs with it off server wide: start from the production default

    def tearDown(self):
        with connection.cursor() as cursor:
            cursor.execute('RESET synchronous_commit')

    def session_value(self):
        with connection.cursor() as cursor:
            cursor.execute('SHOW synchronous_commit')
            return cursor.fetchone()[0]

    def test_the_token_stamp_commits_without_waiting_and_leaves_the_session_as_it_was(self):
        seen, wrapper = _show_in_update('dashboard_apitoken')
        token = ApiToken.objects.get(pk=self.token.pk)
        with connection.execute_wrapper(wrapper):
            self.assertTrue(auth.stamp_last_used(token))
        self.assertEqual(seen, [('off', True)])
        self.assertEqual(self.session_value(), 'on')
        self.assertIsNotNone(ApiToken.objects.get(pk=self.token.pk).last_used_at)  # committed

    def test_a_real_request_stamps_the_token_and_is_served(self):
        seen, wrapper = _show_in_update('dashboard_apitoken')
        with connection.execute_wrapper(wrapper):
            self.assertEqual(call(self.raw, 'GET', '/api/v1/me')[0], 200)
        self.assertEqual([value for value, _ in seen], ['off'])
        self.assertIsNotNone(ApiToken.objects.get(pk=self.token.pk).last_used_at)
        self.assertEqual(self.session_value(), 'on')

    def test_revoking_a_token_keeps_a_normal_commit(self):
        from tests.test_agentapi import client_for
        seen, wrapper = _show_in_update('dashboard_apitoken')
        with connection.execute_wrapper(wrapper):
            self.assertEqual(client_for(self.user).delete(f'/api/v1/tokens/{self.token.pk}').status_code, 200)
        self.assertTrue(seen)
        self.assertEqual({value for value, _ in seen}, {'on'})
        self.assertTrue(ApiToken.objects.get(pk=self.token.pk).revoked)

    def test_agent_last_seen_commits_without_waiting(self):
        agent = Agent.objects.create(token=self.token, name='relaxed-agent', kind='scanner', status='active')
        seen, wrapper = _show_in_update('agentapi_agent')
        with connection.execute_wrapper(wrapper):
            broker._touch(agent)
        self.assertEqual(seen, [('off', True)])
        self.assertIsNotNone(Agent.objects.get(pk=agent.pk).last_seen)

    def test_record_info_relaxes_only_a_telemetry_refresh(self):
        agent = Agent.objects.create(token=self.token, name='info-agent', kind='scanner', status='active', info={'version': 'v1', 'contract_version': 3})
        seen, wrapper = _show_in_update('agentapi_agent')
        with connection.execute_wrapper(wrapper):
            sentinel_settings.record_info(agent, {'version': 'v1', 'spool': {'count': 2}})  # same version, a spool count: telemetry
        self.assertEqual([value for value, _ in seen], ['off'])
        self.assertEqual(Agent.objects.get(pk=agent.pk).info['spool'], agent.info['spool'])
        seen.clear()
        with connection.execute_wrapper(wrapper), mock.patch('agentapi.sentinel_version.version_changed'):
            sentinel_settings.record_info(agent, {'version': 'v2'})  # a new version: a normal commit
        self.assertEqual([value for value, _ in seen], ['on'])
        self.assertEqual(Agent.objects.get(pk=agent.pk).info['version'], 'v2')

    def test_concurrent_stale_requests_send_one_write(self):
        """Eight requests of one token that all read the same stale stamp at once: one UPDATE, not eight queued on the row lock."""
        stored = ApiToken.objects.get(pk=self.token.pk).last_used_at
        cache.delete(_key('apitoken', self.token.pk, stored))
        start, statements, lock = threading.Barrier(8), [], threading.Lock()
        inside = threading.Event()

        def slow_write(execute, sql, params, many, context):
            if sql.startswith('UPDATE "dashboard_apitoken"'):
                with lock:
                    statements.append(sql)
                inside.set()
                threading.Event().wait(0.3)  # the commit flush of a busy disk: the others arrive while it runs
            return execute(sql, params, many, context)

        def one():
            try:
                token = ApiToken.objects.get(pk=self.token.pk)
                with connection.execute_wrapper(slow_write):
                    start.wait()
                    auth.stamp_last_used(token)
            finally:
                connection.close()

        threads = [threading.Thread(target=one) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(inside.is_set())
        self.assertEqual(len(statements), 1)
        self.assertIsNotNone(ApiToken.objects.get(pk=self.token.pk).last_used_at)
