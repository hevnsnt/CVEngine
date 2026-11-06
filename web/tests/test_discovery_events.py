import os
import unittest
from unittest import mock

from django.test import SimpleTestCase

from reNgine import discovery_events
from reNgine.discovery_events import DEFAULT_MODE, MODES, trufflehog_enabled


class ModesTests(unittest.TestCase):
    """What each discovery mode asks the scanner to run (the server's own table, handed to a Sentinel in the task target)."""

    def test_standard_is_the_default_with_the_web_preset_and_safe_modules(self):
        self.assertEqual(DEFAULT_MODE, 'standard')
        self.assertEqual(MODES['standard']['presets'], ('subdomain-enum', 'web', 'web-screenshots'))  # screenshots in the default mode
        self.assertEqual(MODES['standard']['args'], ['-rf', 'safe', '--force'])

    def test_deep_uses_the_kitchen_sink_preset(self):
        self.assertEqual(MODES['deep']['presets'], ('kitchen-sink',))
        self.assertEqual(MODES['deep']['args'], ['--force'])  # no required-flag filter: every module of the preset may run

    def test_passive_only_asks_public_sources(self):
        self.assertEqual(MODES['passive']['presets'], ('subdomain-enum',))
        self.assertEqual(MODES['passive']['args'], ['-rf', 'passive'])
        self.assertNotIn('--force', MODES['passive']['args'])

    def test_there_are_exactly_three_modes(self):
        self.assertEqual(sorted(MODES), ['deep', 'passive', 'standard'])


class TrufflehogGateTests(SimpleTestCase):
    """The secret-verifying module uses a third party's credential against its issuer, so it is off unless CVENGINE_BBOT_TRUFFLEHOG=1 and the
    project has no bug bounty engagement. The server decides; the task target tells the Sentinel."""

    def test_enabled_reads_the_usual_truthy_words(self):
        for value, expected in (('1', True), ('true', True), ('ON', True), ('0', False), ('', False), ('no', False)):
            with mock.patch.dict('os.environ', {'CVENGINE_BBOT_TRUFFLEHOG': value}):
                self.assertEqual(trufflehog_enabled(), expected, value)

    def test_off_by_default(self):
        with mock.patch.dict('os.environ', {}, clear=False):
            os.environ.pop('CVENGINE_BBOT_TRUFFLEHOG', None)
            self.assertFalse(trufflehog_enabled())
            self.assertFalse(discovery_events.trufflehog_allowed())

    def test_allowed_when_enabled_and_no_project(self):
        with mock.patch.dict('os.environ', {'CVENGINE_BBOT_TRUFFLEHOG': 'yes'}):
            self.assertTrue(discovery_events.trufflehog_allowed())


if __name__ == '__main__':
    unittest.main()
