"""``status_warm_rows``: the Celery task that counts the status's project rows that did not fit its time. It cannot stall a status call (a broker that does not
answer), cannot overlap itself (a lock released only by the run that holds it), and is bounded in the database (a statement timeout)."""
import socket
import threading
import time
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.utils import timezone

from agentapi import system_status
from dashboard.models import Org, Project
from reNgine import resources


class SilentServer:
    """A TCP server that accepts a connection and never says anything: a broker that hangs."""

    def __enter__(self):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.held = []
        self.alive = True
        threading.Thread(target=self.accept, daemon=True).start()
        return self

    def accept(self):
        while self.alive:
            try:
                self.held.append(self.sock.accept()[0])
            except OSError:
                return

    def __exit__(self, *exc):
        self.alive = False
        self.sock.close()
        for conn in self.held:
            conn.close()


class DispatchTests(TransactionTestCase):
    def test_a_broker_that_does_not_answer_cannot_stall_the_status(self):
        from reNgine.celery import app
        client = resources.redis_client()
        client.delete(system_status.WARM_LOCK)
        original = app.connection_for_write
        with SilentServer() as silent, mock.patch.object(app, 'connection_for_write', lambda **kw: original(url=f'redis://127.0.0.1:{silent.port}/0', **kw)):
            started = time.monotonic()
            system_status._warm_rows([1, 2, 3])
            took = time.monotonic() - started
        self.assertLess(took, 3.5)  # connect and each reply wait at most WARM_DISPATCH_TIMEOUT (1 s), no retries; the status budget is 8 s
        self.assertIsNone(client.get(system_status.WARM_LOCK))  # nothing was sent, so nothing holds the lock: the next call asks again

    def test_a_second_dispatch_while_one_is_held_sends_nothing(self):
        client = resources.redis_client()
        client.set(system_status.WARM_LOCK, 'someone-else', ex=60)
        self.addCleanup(client.delete, system_status.WARM_LOCK)
        with mock.patch('cveFeed.tasks.status_warm_rows.apply_async') as send:
            system_status._warm_rows([1])
        send.assert_not_called()
        self.assertEqual(client.get(system_status.WARM_LOCK), 'someone-else')


class TimeoutTests(TransactionTestCase):
    """A statement cancelled by the warm-up's timeout must not take the other rows with it, and no transaction may be left open (the run was one transaction: one
    cancelled statement aborted it and 0 of N rows were kept, and it could stay open for the task's whole time limit)."""

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        org = Org.objects.create(name='T', slug='t-org')
        self.projects = [Project.objects.create(name=f'T{i}', slug=f't-{i}', insert_date=timezone.now(), org=org) for i in range(3)]
        self.client_ = resources.redis_client()
        self.addCleanup(self.client_.delete, system_status.WARM_LOCK)
        self.client_.set(system_status.WARM_LOCK, 'mine', ex=60)

    def slow(self):
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_sleep(2)')

    def assert_clean(self):
        from django.db import connection
        self.assertFalse(connection.in_atomic_block)
        self.assertIsNone(self.client_.get(system_status.WARM_LOCK))  # released
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%%' AND pid <> pg_backend_pid()")
            self.assertEqual(cursor.fetchone()[0], 0)

    def kept(self, project):
        return cache.get(f'sysstatus:project:last:{project.id}')

    def test_the_shared_read_cancelled_by_its_timeout_leaves_every_row_counted_for_itself(self):
        with mock.patch.object(system_status, 'WARM_STATEMENT_MS', 100), mock.patch.object(system_status, '_shared_inputs', lambda ids: self.slow()):
            system_status.warm_project_rows([p.id for p in self.projects], 'mine')
        self.assertTrue(all(self.kept(p) is not None for p in self.projects))
        self.assert_clean()

    def test_one_row_cancelled_by_its_timeout_keeps_the_others(self):
        original = system_status._project_row
        bad = self.projects[1]

        def row(project, shared=None):
            if project.id == bad.id:
                self.slow()
            return original(project, shared)
        with mock.patch.object(system_status, 'WARM_STATEMENT_MS', 100), mock.patch.object(system_status, '_project_row', row), self.assertLogs('agentapi.system_status', 'WARNING') as logged:
            system_status.warm_project_rows([p.id for p in self.projects], 'mine')
        self.assertEqual([self.kept(p) is not None for p in self.projects], [True, False, True])
        self.assertTrue(any(bad.slug in line for line in logged.output))  # named once in the log
        self.assert_clean()


class RunTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        org = Org.objects.create(name='W', slug='w-org')
        self.project = Project.objects.create(name='W', slug='w-proj', insert_date=timezone.now(), org=org)
        self.client_ = resources.redis_client()
        self.addCleanup(self.client_.delete, system_status.WARM_LOCK)

    def test_the_run_keeps_the_rows_and_releases_only_its_own_lock(self):
        self.client_.set(system_status.WARM_LOCK, 'mine', ex=60)
        system_status.warm_project_rows([self.project.id], 'mine')
        self.assertIsNotNone(cache.get(f'sysstatus:project:last:{self.project.id}'))
        self.assertIsNone(self.client_.get(system_status.WARM_LOCK))

    def test_a_run_whose_lock_lapsed_and_was_taken_does_not_delete_the_new_holders(self):
        self.client_.set(system_status.WARM_LOCK, 'the-new-holder', ex=60)
        system_status.warm_project_rows([self.project.id], 'late-run')
        self.assertEqual(self.client_.get(system_status.WARM_LOCK), 'the-new-holder')

    def test_the_run_has_a_statement_timeout(self):
        from django.db import connection
        seen = []
        original = system_status._shared_inputs

        def spy(ids):
            with connection.cursor() as cursor:
                cursor.execute('SHOW statement_timeout')
                seen.append(cursor.fetchone()[0])
            return original(ids)
        with mock.patch.object(system_status, '_shared_inputs', spy):
            system_status.warm_project_rows([self.project.id], 'x')
        self.assertEqual(seen, ['30s'])

    def test_the_task_is_exempt_from_the_scanning_pause_and_named_as_dispatched(self):
        from cveFeed import scan_control
        from cveFeed.tasks import status_warm_rows
        self.assertEqual(status_warm_rows.name, 'status_warm_rows')
        self.assertIn('status_warm_rows', scan_control.PAUSE_EXEMPT_TASKS)
