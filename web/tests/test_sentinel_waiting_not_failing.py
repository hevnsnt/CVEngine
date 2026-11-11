"""A Sentinel task that expired because no slot was free is back-pressure (its targets stay due and are asked again), not a failure.

On the owner's demo instance (one built-in Sentinel, about 1,100 hosts) 89 tasks expired in an hour with "no Sentinel slot freed up in time" and the banner said
"Sentinel tasks are failing: 13 web_screenshot task(s) failed or expired". It now says that only for tasks that failed or that a Sentinel stopped reporting; the
slot waits are counted apart, as a note."""
from datetime import timedelta

from django.utils import timezone

from agentapi import sentinel_broker
from agentapi.models import SentinelTask
from agentapi.system_status import _sentinels
from cveFeed import reviewer
from tests.test_reviewer import Fixture

WAIT = 'no Sentinel slot freed up in time; the targets stay due until a scanner can take the work'


class WaitingIsNotFailingTests(Fixture):
    def add(self, n, status, error, kind='web_screenshot'):
        for _ in range(n):
            SentinelTask.objects.create(project=self.proj, kind=kind, target={}, status=status, error=error, finished_at=timezone.now() - timedelta(minutes=5))

    def check(self, code):
        return {c['code']: c for c in reviewer.ops_checks()}.get(code)

    def test_slot_waits_alone_raise_no_failure(self):
        self.add(13, 'expired', WAIT)
        self.add(6, 'expired', 'no Sentinel claimed the task in time; the targets stay due until a scanner can take the work', kind='naabu')
        self.assertEqual(self.check('sentinel_errors')['state'], 'ok')

    def test_they_are_counted_apart_in_plain_words(self):
        self.add(13, 'expired', WAIT)
        note = self.check('sentinel_waiting')
        self.assertEqual((note['state'], note['severity']), ('warning', 'info'))
        self.assertIn('13 task(s) waited for a Sentinel slot', note['detail'])
        self.assertIn('13 web_screenshot', note['detail'])
        self.assertNotIn('fail', note['detail'].lower())

    def test_failed_tasks_and_tasks_a_sentinel_stopped_reporting_are_still_failures(self):
        self.add(5, 'failed', 'the tool crashed', kind='nmap')
        self.add(5, 'expired', 'the dispatch wait timed out; the targets stay due until a scanner can take the work', kind='naabu')
        failing = self.check('sentinel_errors')
        self.assertEqual(failing['state'], 'problem')
        self.assertIn('5 nmap task(s) failed or stopped reporting', failing['detail'])
        self.assertIn('5 naabu task(s) failed or stopped reporting', failing['detail'])
        self.assertNotIn('expired', failing['detail'])

    def test_waits_do_not_hide_real_failures_in_the_same_hour(self):
        self.add(40, 'expired', WAIT)
        self.add(5, 'failed', 'boom', kind='nmap')
        self.assertEqual(self.check('sentinel_errors')['state'], 'problem')
        self.assertIsNotNone(self.check('sentinel_waiting'))

    def test_the_status_report_does_not_call_slot_waits_a_failure_rate(self):
        self.add(30, 'expired', WAIT)
        self.add(5, 'done', '', kind='nmap')
        problems = []
        out = _sentinels(problems)
        self.assertFalse([p for p in problems if 'failed' in p], problems)
        self.assertEqual(out['finished_24h']['waiting_for_slot'], 30)
        self.assertEqual(out['recent_errors'], [])
        self.add(6, 'failed', 'boom', kind='nmap')
        problems = []
        _sentinels(problems)
        self.assertTrue([p for p in problems if 'failed or stopped reporting' in p], problems)

    def test_the_waiting_prefixes_are_what_the_dispatcher_writes(self):
        from agentapi import sentinel_dispatch
        text = sentinel_dispatch.outcome_text('nmap')
        for written in (f'no Sentinel slot freed up in time; {text}', f'no Sentinel claimed the task in time; {text}'):
            self.assertTrue(written.startswith(sentinel_broker.WAITING_ERRORS), written)
        self.assertFalse(f'the dispatch wait timed out; {text}'.startswith(sentinel_broker.WAITING_ERRORS))
