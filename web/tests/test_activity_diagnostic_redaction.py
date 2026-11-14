from django.test import SimpleTestCase

from cveFeed import activity


class DiagnosticRedactionTests(SimpleTestCase):
    def test_a_secret_in_the_raw_text_does_not_reach_the_worker_log(self):
        secret = 'hunter2-Zq9!kV3pLm'
        raw = f'401 from https://api.example.test/v1: Authorization: Bearer abcDEF1234567890abcDEF123456 password="{secret}" https://bob:{secret}@host.test/x'
        with self.assertLogs('cveFeed.activity', level='WARNING') as logged:
            shown = activity.diagnostic('Sign-in check', raw)
        text = '\n'.join(logged.output)
        self.assertNotIn(secret, text)
        self.assertNotIn('abcDEF1234567890abcDEF123456', text)
        self.assertIn('Sign-in check failed', text)
        self.assertNotIn(secret, shown)

    def test_a_plain_failure_is_still_logged_whole(self):
        with self.assertLogs('cveFeed.activity', level='WARNING') as logged:
            activity.diagnostic('Port scan of 10.0.0.5', 'ConnectionError: timed out after 30 s')
        self.assertIn('ConnectionError: timed out after 30 s', '\n'.join(logged.output))
