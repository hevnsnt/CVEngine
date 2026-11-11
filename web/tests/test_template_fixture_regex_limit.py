"""A matcher regex runs with a time limit (review 2 F5)."""
import time
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import templatefixture as fixture


class RegexLimitTests(SimpleTestCase):
    def test_a_catastrophic_pattern_is_given_up_on_instead_of_holding_the_worker(self):
        started = time.monotonic()
        with mock.patch.object(fixture, 'REGEX_SECONDS', 0.5):
            with self.assertRaises(fixture.Unsupported) as caught:
                fixture._regex_found(r'(a+)+$', 'a' * 40 + '!')
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn('took longer', str(caught.exception))

    def test_an_ordinary_pattern_still_answers_both_ways(self):
        self.assertTrue(fixture._regex_found(r'Server: nginx/(\d+)\.', 'HTTP/1.1 200\r\nServer: nginx/1.24.0\r\n'))
        self.assertFalse(fixture._regex_found(r'apache', 'Server: nginx'))
        self.assertTrue(fixture._regex_found(r'a.b', 'a\nb'))  # DOTALL, as before

    def test_a_pattern_that_does_not_compile_is_unsupported_as_before(self):
        with self.assertRaises(fixture.Unsupported) as caught:
            fixture._regex_found(r'(unclosed', 'x')
        self.assertIn('cannot be evaluated offline', str(caught.exception))
