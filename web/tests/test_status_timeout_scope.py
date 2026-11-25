"""A status count the time left cuts off must not poison the request (CI: the transaction was aborted and every later statement failed), and its
time limit must end with the count (it was a session SET, so a kept connection served the next requests with a 200 ms limit)."""
import time
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from agentapi import system_status
from agentapi.services import Ctx
from dashboard.models import Org, Project


def _setting(name):
    with connection.cursor() as cursor:
        cursor.execute('SHOW ' + name)
        return cursor.fetchone()[0]


def _cut_off(project, shared=None):
    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL statement_timeout = 50")
        cursor.execute('SELECT pg_sleep(1)')  # a real cut-off: Postgres cancels it and aborts the transaction it ran in


class _Fixture:
    def make(self):
        cache.clear()
        self.user = User.objects.create_superuser('st-root', 'st@example.org', 'x')
        org = Org.objects.create(name='st-org', slug='st-org')
        self.project = Project.objects.create(name='st-project', slug='st-project', insert_date=timezone.now(), org=org)
        self.ctx = Ctx(user=self.user)


class InsideATransaction(_Fixture, TestCase):
    def setUp(self):
        self.make()

    def test_a_cut_off_count_leaves_the_transaction_usable(self):
        with mock.patch.object(system_status, '_project_row', _cut_off):
            rows, waiting = system_status._projects_partial(self.ctx, deadline=time.monotonic() + 30)
        self.assertEqual(waiting, ['st-project'])
        self.assertTrue(Project.objects.filter(slug='st-project').exists())  # raised "current transaction is aborted" before


class OnItsOwn(_Fixture, TransactionTestCase):
    def setUp(self):
        self.make()

    def test_the_time_limit_ends_with_the_count(self):
        before = _setting('statement_timeout')
        system_status._projects_partial(self.ctx, deadline=time.monotonic() + 30)
        self.assertEqual(_setting('statement_timeout'), before)

    def test_the_limit_applies_during_the_count(self):
        seen = []

        def row(project, shared=None):
            seen.append(_setting('statement_timeout'))
            return {'slug': project.slug}
        before = _setting('statement_timeout')
        with mock.patch.object(system_status, '_project_row', row):
            system_status._projects_partial(self.ctx, deadline=time.monotonic() + 30)
        self.assertTrue(seen and seen[0] != before, seen)
        self.assertEqual(_setting('statement_timeout'), before)
