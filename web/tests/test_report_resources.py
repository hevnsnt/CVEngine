"""Report resource policy regression tests; no external service is required."""
import base64
from html import escape
from unittest import TestCase, mock

import markdown

from startScan.report_resources import CHART_PREFIX, MAX_CHART_BYTES, report_url_fetcher, render_report_pdf


class ReportResourceTests(TestCase):
    def test_denies_network_file_and_untrusted_data_resources(self):
        fetch = report_url_fetcher()
        for url in ('http://127.0.0.1/image.png', 'http://169.254.169.254/image.png',
                    'https://example.test/font.css', 'file:///tmp/report-image.png',
                    'data:image/svg+xml;base64,PHN2Zy8+', '//example.test/image.png'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                fetch(url)

    def test_allows_only_exact_generated_chart(self):
        raw = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>'
        chart = base64.b64encode(raw).decode('ascii')
        fetch = report_url_fetcher((chart, ''))
        self.assertEqual(fetch(CHART_PREFIX + chart), {'string': raw, 'mime_type': 'image/svg+xml'})
        with self.assertRaises(ValueError):
            fetch(CHART_PREFIX + chart + '#fragment')
        with self.assertRaises(ValueError):
            fetch('http://127.0.0.1/nested.svg')

    def test_resource_size_count_and_encoding_are_bounded(self):
        for charts in (('!',), ('A' * (4 * ((MAX_CHART_BYTES + 2) // 3) + 4),), ('', '', '')):
            with self.subTest(charts_length=len(charts)), self.assertRaises(ValueError):
                report_url_fetcher(charts)

    def test_markdown_image_is_denied_at_renderer_boundary(self):
        html = markdown.markdown(escape('![image](http://127.0.0.1/image.png)'))
        self.assertIn('<img ', html)  # HTML escaping alone does not remove Markdown images.
        with mock.patch('startScan.report_resources.HTML') as renderer:
            renderer.return_value.write_pdf.return_value = b'pdf'
            self.assertEqual(render_report_pdf(html), b'pdf')
            options = renderer.call_args.kwargs
            self.assertEqual(options['string'], html)
            with self.assertRaises(ValueError):
                options['url_fetcher']('http://127.0.0.1/image.png')
