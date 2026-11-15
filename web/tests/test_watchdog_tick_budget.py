"""The tick command ends inside the host's 55 second timer however long Django took to start (399 "tick failed (exit 124)" lines by 11/15).

``TICK_SECONDS`` (40) and the command's own kill timer (48) counted from the start of the tick, but the host's ``timeout`` counts from the start of the process. Importing
Django took 6 to 12 s on the scanner host when it was quiet and far more under load, so a tick that used its time ran past 55 s and was killed before it printed or
recorded a word.
"""
import json
import subprocess
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from cveFeed import watchdog as wd

HOST_TIMER = 55  # `timeout -k 3 55 python3 manage.py watchdog_tick` in scripts/watchdog.sh


class BudgetTests(SimpleTestCase):
    def test_the_command_is_over_before_the_hosts_timer_whatever_its_start_up_took(self):
        for age in range(0, 70):
            budget = wd.tick_budget(float(age))
            if budget is None:
                continue
            limit, hard = budget
            self.assertLessEqual(age + hard, HOST_TIMER - 5 + 3, f'start-up {age} s: the kill timer would fire after the host timer')
            self.assertLess(limit, hard, f'start-up {age} s: the tick must end itself before the kill timer')
            self.assertGreaterEqual(limit, 3)

    def test_the_old_arithmetic_did_not_hold(self):
        """What the 399 timeouts were: a start-up of 8 s or more and a tick that used its whole 40 s."""
        self.assertGreater(8 + wd.TICK_SECONDS + 8, HOST_TIMER)

    def test_a_quiet_host_gets_the_full_limits(self):
        self.assertEqual(wd.tick_budget(0.0), (wd.TICK_SECONDS, wd.TICK_SECONDS + 8))
        self.assertEqual(wd.tick_budget(2.0), (wd.TICK_SECONDS, wd.TICK_SECONDS + 8))

    def test_a_slow_start_up_shortens_the_tick(self):
        self.assertEqual(wd.tick_budget(20.0), (28.0, 30.0))
        self.assertEqual(wd.tick_budget(44.0), (4.0, 6.0))

    def test_too_little_time_left_means_no_tick(self):
        self.assertIsNone(wd.tick_budget(46.0))
        self.assertIsNone(wd.tick_budget(90.0))

    def test_the_process_age_is_a_small_positive_number_and_zero_when_proc_is_unreadable(self):
        age = wd.process_age_seconds()
        self.assertGreaterEqual(age, 0.0)
        self.assertLess(age, 3600)
        with mock.patch('builtins.open', side_effect=OSError('no /proc')):
            self.assertEqual(wd.process_age_seconds(), 0.0)

    def test_the_process_age_follows_a_process_started_a_while_ago(self):
        src = Path(wd.__file__).read_text()
        start = src.index('def process_age_seconds')
        func = src[start:src.index('\n\n\ndef tick_budget')]
        code = 'import os, time\n' + func + '\ntime.sleep(2)\nprint(process_age_seconds())\n'
        out = subprocess.run(['python3', '-c', code], capture_output=True, text=True, timeout=30)
        self.assertGreaterEqual(float(out.stdout.strip()), 1.5, out.stderr)
        self.assertLess(float(out.stdout.strip()), 30)


class CommandTests(TestCase):
    def run_command(self, age, tick_result=None):
        out = StringIO()
        with mock.patch.object(wd, 'process_age_seconds', return_value=age), mock.patch.object(wd, 'tick', return_value=tick_result or {'ok': True, 'acted': []}) as tick:
            call_command('watchdog_tick', stdout=out)
        return json.loads(out.getvalue()), tick

    def test_a_quiet_start_runs_the_tick_with_the_full_limit(self):
        out, tick = self.run_command(1.0)
        tick.assert_called_once_with(limit=wd.TICK_SECONDS)
        self.assertEqual(out['startup_seconds'], 1.0)
        self.assertTrue(out['ok'])

    def test_a_slow_start_runs_a_shorter_tick_and_says_how_long_start_up_took(self):
        out, tick = self.run_command(30.0)
        tick.assert_called_once_with(limit=18.0)
        self.assertEqual(out['startup_seconds'], 30.0)

    def test_a_start_that_used_the_time_prints_one_line_saying_so_and_does_nothing(self):
        out, tick = self.run_command(48.0)
        tick.assert_not_called()
        self.assertFalse(out['ok'])
        self.assertIn('took 48 s to start this command', out['skipped'])
        self.assertEqual(out['acted'], [])
