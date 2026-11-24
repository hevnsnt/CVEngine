"""The remote half of scripts/scanner_lock.py check: a network failure is retried and then said out loud, a wrong pin still fails."""
import importlib.util
import io
import urllib.error
from contextlib import redirect_stderr
from pathlib import Path
from unittest import TestCase, mock

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'scanner_lock.py'
DATA = {'source': {'repository': 'https://github.com/example/sentinel.git'}}


def load():
    spec = importlib.util.spec_from_file_location('scanner_lock_under_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.REMOTE_PAUSE = 0
    return module


class Answer:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return io.BytesIO(self.body)

    def __exit__(self, *a):
        return False


class RemoteCheckTests(TestCase):
    def setUp(self):
        self.m = load()
        patcher = mock.patch.object(self.m, 'floor_commit', return_value='a' * 40)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_check(self, opener):
        err = io.StringIO()
        with mock.patch.object(self.m.urllib.request, 'urlopen', side_effect=opener) as urlopen, redirect_stderr(err):
            result = self.m.remote_check(DATA)
        return result, urlopen.call_count, err.getvalue()

    def test_a_timeout_is_retried_then_skipped_with_a_message(self):
        result, calls, err = self.run_check(TimeoutError('The read operation timed out'))
        self.assertEqual(result, (True, ''))
        self.assertEqual(calls, self.m.REMOTE_ATTEMPTS)
        self.assertIn('could not reach GitHub', err)
        self.assertIn('timed out', err)

    def test_a_dropped_connection_and_a_server_error_are_the_network_too(self):
        for failure in (urllib.error.URLError('connection reset'), urllib.error.HTTPError('u', 502, 'bad gateway', {}, None), urllib.error.HTTPError('u', 429, 'slow down', {}, None)):
            result, calls, err = self.run_check(failure)
            self.assertEqual(result, (True, ''), failure)
            self.assertEqual(calls, self.m.REMOTE_ATTEMPTS)

    def test_a_timeout_then_an_answer_uses_the_answer(self):
        answers = [TimeoutError('slow'), Answer(b'{"status": "ahead"}')]
        result, calls, _ = self.run_check(answers)
        self.assertEqual(result, (True, ''))
        self.assertEqual(calls, 2)

    def test_a_floor_commit_that_is_not_in_the_repository_still_fails(self):
        result, calls, _ = self.run_check(urllib.error.HTTPError('u', 404, 'nope', {}, None))
        self.assertFalse(result[0])
        self.assertIn('is not in example/sentinel', result[1])
        self.assertEqual(calls, 1)

    def test_a_floor_commit_off_the_main_branch_still_fails(self):
        result, _, _ = self.run_check([Answer(b'{"status": "diverged"}')])
        self.assertFalse(result[0])
        self.assertIn('diverged', result[1])

    def test_any_other_client_error_still_raises(self):
        with self.assertRaises(urllib.error.HTTPError):
            self.run_check(urllib.error.HTTPError('u', 401, 'unauthorized', {}, None))
