"""The watchdog's state rows: read in one query, created when missing, and written by a tick without the switch a person sets, so a tick that read
a rule before a person switched it off never switches it back on."""
from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from cveFeed import watchdog as wd
from cveFeed.models import WatchdogState


class StateRowTests(TestCase):
    def test_the_rows_are_created_once_then_read_in_one_query(self):
        states = wd._states()
        self.assertEqual(list(states), [wd.ALL] + [r.code for r in wd.RULES])
        self.assertEqual(WatchdogState.objects.count(), len(states))
        with CaptureQueriesContext(connection) as queries:
            again = wd._states()
        self.assertEqual(len(queries.captured_queries), 1)
        self.assertEqual({k: v.pk for k, v in again.items()}, {k: v.pk for k, v in states.items()})
        WatchdogState.objects.filter(rule=wd.RULES[0].code).delete()
        self.assertEqual(len(wd._states()), len(states))  # a missing row is made again

    def test_a_tick_write_keeps_the_switch_a_person_set_meanwhile(self):
        code = wd.RULES[0].code
        stale = wd._states()[code]
        wd.set_enabled(code, False, User.objects.create(username='wd-person'))
        stale.status, stale.status_text = 'watching', 'Seen once.'
        wd._save_state(stale)
        row = WatchdogState.objects.get(rule=code)
        self.assertFalse(row.enabled)
        self.assertEqual((row.status, row.status_text), ('watching', 'Seen once.'))
