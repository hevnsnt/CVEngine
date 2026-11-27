"""A statement time limit set for one block ends with the block, also inside a caller's transaction.

``SET LOCAL`` lasts until the outermost transaction ends, not until a savepoint is released. The status call's signals (``maintainer_signals._bounded``,
2 seconds) and a saved search's run (``saved_searches.current_matches``, 20 seconds) set it inside ``transaction.atomic()``, so in a caller's transaction
the limit stayed for the caller's later statements: in CI, tests.test_query_ceilings asked ``system/status`` and then ``projects/<slug>/work``, and the
work query was cut off by the 2 second limit the status call had left behind (``agentapi.db_timeout.bounded``)."""
from unittest import mock

from django.db import connection
from django.test import TestCase

from agentapi import db_timeout, maintainer_signals
from cveFeed import saved_searches


def _limit():
    with connection.cursor() as cursor:
        cursor.execute('SHOW statement_timeout')
        return cursor.fetchone()[0]


class BoundedBlockTests(TestCase):
    def test_the_limit_holds_inside_the_block_and_the_callers_is_back_after_it(self):
        before = _limit()
        with db_timeout.bounded(1234):
            self.assertEqual(_limit(), '1234ms')
        self.assertEqual(_limit(), before)

    def test_a_caller_with_a_limit_of_its_own_gets_it_back(self):
        with connection.cursor() as cursor:
            cursor.execute('SET LOCAL statement_timeout = 7000')
        with db_timeout.bounded(1234):
            self.assertEqual(_limit(), '1234ms')
        self.assertEqual(_limit(), '7s')

    def test_a_block_that_fails_leaves_the_callers_limit_too(self):
        before = _limit()
        with self.assertRaises(RuntimeError):
            with db_timeout.bounded(1234):
                raise RuntimeError('boom')
        self.assertEqual(_limit(), before)

    def test_the_status_signals_leave_no_limit_behind(self):
        before = _limit()
        with maintainer_signals._bounded():
            self.assertEqual(_limit(), f'{maintainer_signals.DB_STATEMENT_MS // 1000}s')
        self.assertEqual(_limit(), before)

    def test_a_saved_search_run_leaves_no_limit_behind(self):
        seen = []
        rows = mock.MagicMock()
        rows.order_by.return_value.values_list.return_value = []

        def search(project, terms):
            seen.append(_limit())
            return rows
        before = _limit()
        with mock.patch.object(saved_searches, 'search_host_rows', search), mock.patch.object(saved_searches, 'with_host_key', lambda qs: qs):
            self.assertEqual(saved_searches.current_matches(None, 'x'), ({}, False))
        self.assertEqual(seen, [f'{saved_searches.STATEMENT_TIMEOUT_MS // 1000}s'])
        self.assertEqual(_limit(), before)
