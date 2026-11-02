"""The nuclei template refresh and what the status says about it."""
from django.test import SimpleTestCase
class TemplateRefreshResultTests(SimpleTestCase):
    """The recorded result of ``nuclei -update-templates`` is the line that says what happened, not a warning that came first."""

    def run_refresh(self, stdout='', stderr='', returncode=0):
        from unittest import mock
        recorded = {}
        proc = mock.Mock(stdout=stdout, stderr=stderr, returncode=returncode)
        with mock.patch('subprocess.run', return_value=proc), mock.patch('django.core.cache.cache.set', side_effect=lambda key, value, ttl: recorded.update(value)), \
                mock.patch('cveFeed.templategen.invalidate_template_index'), mock.patch('cveFeed.activity.log'):
            from cveFeed import tasks
            tasks.update_nuclei_templates()
        return recorded

    def test_a_warning_after_the_message_is_not_the_result(self):
        out = self.run_refresh(stdout='[INF] Successfully updated nuclei-templates (v10.9.9) to /root/nuclei-templates\n',
                               stderr='WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)\n')
        self.assertIn('Successfully updated', out['result'])
        self.assertTrue(out['ok'])

    def test_a_run_that_printed_only_a_warning_says_it_ran_with_no_message(self):
        out = self.run_refresh(stderr='WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)\n')
        self.assertNotIn('sonic', out['result'])
        self.assertTrue(out['ok'])

    def test_a_failed_run_is_recorded_as_failed(self):
        out = self.run_refresh(stderr='[ERR] could not reach github.com\n', returncode=1)
        self.assertFalse(out['ok'])
        self.assertIn('could not reach', out['result'])
