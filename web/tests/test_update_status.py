"""scripts/update-status.py: the status the maintenance page shows while an update runs. It is PUBLIC while the flag exists, so these tests check
that only whitelisted text can reach it, and that the updater writes it at each phase. Run on the host: ``cd web && python3 -m unittest tests.test_update_status``."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
HELPER = SCRIPTS / 'update-status.py'

CANARIES = [
    'hunter2canary', 'S3cr3tTokenCanary', 'AKIAIOSFODNN7CANARY', 'canary-user:canary-pass', 'internal.canary.example.com',
    '192.0.2.77', '2001:db8::77', '/opt/cvengine-canary/.env', '/home/canaryuser/.ssh/id_rsa', '/root/.docker/config.json',
    'ghp_CanaryGithubTokenCanaryGithubTokenCanary12', 'eyJhbGciOiJIUzI1NiJ9.canarypayload.canarysig', 'canary@example.org',
    'POSTGRES_PASSWORD=canaryvalue', 'Traceback', 'usr/src/app/canary_module.py',
]
CANARY_LOG = """2026-11-08T22:01:00Z updating abc -> def
 #12 [web 4/9] RUN pip install --index-url https://canary-user:canary-pass@internal.canary.example.com/simple hunter2canary
password=hunter2canary
Authorization: Bearer S3cr3tTokenCanary
aws_access_key_id AKIAIOSFODNN7CANARY
connecting to 192.0.2.77 and 2001:db8::77
cp /opt/cvengine-canary/.env /tmp/x
reading /home/canaryuser/.ssh/id_rsa and /root/.docker/config.json
token ghp_CanaryGithubTokenCanaryGithubTokenCanary12
jwt eyJhbGciOiJIUzI1NiJ9.canarypayload.canarysig
mail canary@example.org
POSTGRES_PASSWORD=canaryvalue
Traceback (most recent call last):
  File "/usr/src/app/canary_module.py", line 3, in <module>
RuntimeError: build step exited with status 1
2026-11-08T22:09:00Z update failed before the database was migrated (at: build); returning to abc
"""


class UpdateStatusHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.status = self.tmp / 'state' / 'status.json'
        self.log = self.tmp / 'update.log'
        self.log.write_text('2026-11-08T22:00:00Z updating\n')
        self.env = {**os.environ, 'CV_STATUS_FILE': str(self.status), 'CV_STATUS_LOG': str(self.log)}

    def run_helper(self, *args):
        return subprocess.run([sys.executable, str(HELPER), *args], env=self.env, capture_output=True, text=True)

    def read(self):
        return json.loads(self.status.read_text())

    def test_each_phase_transition_is_written_with_its_plain_sentence(self):
        self.assertEqual(self.run_helper('begin', 'ABCDEF1234567890abcdef1234567890abcdef12').returncode, 0)
        data = self.read()
        self.assertEqual((data['state'], data['step'], data['sha']), ('working', 'checking', 'abcdef123456'))
        self.assertEqual(oct(self.status.stat().st_mode & 0o777), '0o644')  # the proxy reads it as an unprivileged user
        self.assertEqual(oct(self.status.parent.stat().st_mode & 0o777), '0o755')
        seen = []
        for step in ('stopping', 'build', 'backup', 'migrating', 'starting', 'verifying', 'scanner'):
            self.run_helper('step', step)
            data = self.read()
            seen.append(data['step'])
            self.assertEqual(data['state'], 'working')
            self.assertTrue(data['detail'].endswith('.'))
        self.assertEqual(seen, ['stopping', 'build', 'backup', 'migrating', 'starting', 'verifying', 'scanner'])
        self.assertEqual(data['steps'], ['checking', 'stopping', 'build', 'backup', 'migrating', 'starting', 'verifying', 'scanner'])
        self.run_helper('done')
        self.assertEqual(self.read()['state'], 'done')
        self.run_helper('clear')
        self.assertFalse(self.status.exists())

    def test_an_unknown_step_changes_nothing_and_text_never_comes_from_the_caller(self):
        self.run_helper('begin', 'abcdef1')
        before = self.read()
        self.run_helper('step', 'merging /etc/passwd secret=1')
        self.assertEqual(self.read()['step'], before['step'])
        self.run_helper('begin', 'not a sha; rm -rf /')
        self.assertEqual(self.read()['sha'], '')  # only 7 to 40 hex characters become a short sha
        self.run_helper('fail', 'some free text with /opt/x and 10.0.0.1', 'yes')
        data = self.read()
        self.assertEqual(data['error']['summary'], 'The update did not finish.')
        self.assertNotIn('/opt/x', json.dumps(data))

    def test_the_tick_refreshes_the_time_and_when_the_log_last_grew(self):
        self.run_helper('begin', 'abcdef1')
        os.utime(self.log, (1_700_000_000, 1_700_000_000))
        self.run_helper('tick')
        data = self.read()
        self.assertEqual(data['last_output_at'], 1_700_000_000)
        self.assertGreater(data['updated_at'], 1_700_000_000)

    def test_a_failure_states_what_failed_whether_it_was_restored_and_what_to_do(self):
        self.run_helper('begin', 'abcdef1')
        self.run_helper('step', 'build')
        self.log.write_text(CANARY_LOG)
        self.run_helper('fail', 'build_failed', 'yes')
        data = self.read()
        self.assertEqual(data['state'], 'failed')
        self.assertEqual(data['step'], 'build')
        error = data['error']
        self.assertEqual(error['summary'], 'The new version could not be built.')
        self.assertIs(error['restored'], True)
        self.assertIn('make up', error['next'])
        self.assertIn('update.log', error['next'])
        self.assertLessEqual(len(error['log']), 20)
        self.run_helper('fail', 'previous_failed', 'no')
        self.assertIs(self.read()['error']['restored'], False)
        self.run_helper('fail', 'stopped', 'unknown')
        self.assertIsNone(self.read()['error']['restored'])

    def test_canary_secrets_in_the_log_never_reach_the_public_json(self):
        self.run_helper('begin', 'abcdef1')
        self.log.write_text(CANARY_LOG)
        for reason in ('build_failed', 'unknown'):
            self.run_helper('fail', reason, 'no')
            text = self.status.read_text()
            for canary in CANARIES:
                self.assertNotIn(canary, text, canary)
            self.assertNotRegex(text, r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
            self.assertNotRegex(text, r'(https?|ftp)://')
            self.assertNotRegex(text, r'(?<![\w:])/(opt|home|root|usr|etc|var|tmp)/')
        # the harmless lines are still there: the point of the tail is to say something
        self.assertIn('returning to abc', ' '.join(self.read()['error']['log']))

    def test_the_working_state_carries_no_log_at_all(self):
        self.log.write_text(CANARY_LOG)
        self.run_helper('begin', 'abcdef1')
        self.run_helper('step', 'build')
        self.run_helper('tick')
        text = self.status.read_text()
        self.assertNotIn('"log"', text)
        self.assertNotIn('canary', text.lower())

    def test_the_keys_are_a_fixed_whitelist(self):
        self.run_helper('begin', 'abcdef1')
        self.log.write_text(CANARY_LOG)
        self.run_helper('fail', 'build_failed', 'no')
        data = self.read()
        self.assertEqual(set(data), {'v', 'state', 'step', 'steps', 'detail', 'sha', 'started_at', 'step_started_at', 'updated_at', 'last_output_at', 'error'})
        self.assertEqual(set(data['error']), {'summary', 'restored', 'next', 'log'})

    def test_it_never_fails_the_update_that_calls_it(self):
        env = {**self.env, 'CV_STATUS_FILE': '/proc/nonexistent/status.json'}
        result = subprocess.run([sys.executable, str(HELPER), 'begin', 'abcdef1'], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_no_long_dashes_in_the_sentences(self):
        self.assertNotRegex(HELPER.read_text(), '[\u2013\u2014]')


if __name__ == '__main__':
    unittest.main()
