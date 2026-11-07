"""The PDF renderer is a core of CPU while it lays out the pages: its child process runs at a lower priority than the web server and the database."""
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import report_pdf


class ReportRendererPriorityTests(SimpleTestCase):
    def render(self):
        with mock.patch('cveFeed.report_pdf.subprocess.run') as run:
            run.return_value = mock.Mock(returncode=0)
            report_pdf.render_pdf('<p>x</p>', '/tmp/never-written.pdf')
        return run.call_args.args[0]

    def test_the_renderer_runs_at_a_lower_priority(self):
        with mock.patch.object(report_pdf, '_LOW_PRIORITY', ['nice', '-n', '10']):
            command = self.render()
        self.assertEqual(command[:3], ['nice', '-n', '10'])
        self.assertIn('cveFeed.report_render', command)

    def test_without_nice_the_renderer_still_runs_at_the_workers_priority(self):
        with mock.patch.object(report_pdf, '_LOW_PRIORITY', []):
            command = self.render()
        self.assertNotIn('nice', command)
        self.assertIn('cveFeed.report_render', command)
