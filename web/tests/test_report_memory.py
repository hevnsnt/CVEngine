"""A big report must not need a gigabyte to lay out.

WeasyPrint keeps every page's boxes until the whole document is laid out (about 1.3 MB a page), so the default 500-host, 1000-finding report peaked near
1 GB and a 1 GB container killed the renderer (-9). The renderer now cuts the report at the rows of its two long lists, lays each chunk out on its own and
joins the PDFs (cveFeed/report_render.py). These tests pin that: nothing is lost or repeated at a cut, the footers still say ``Page N of Y`` for the whole
report, the child stays inside a memory budget, and a render the kernel killed is reported in words instead of as ``-9``.
"""
import os
import re
import resource
import subprocess
import sys
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import report_pdf, report_render

WEB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEAD = ('<!doctype html><html><head><meta charset="utf-8"><title>t</title><style>'
        '@page { size: A4; margin: 22mm 17mm 21mm 17mm; @bottom-left { content: element(foot); font: 8pt sans-serif; }'
        ' @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt sans-serif; } }'
        '@page cover { margin: 0; @bottom-left { content: none; } @bottom-right { content: none; } }'
        '.foot { position: running(foot); } .cover { page: cover; height: 297mm; } section.page { break-before: page; }'
        '.finding { margin: 0 0 14pt; border: 1px solid #ccc; padding: 8pt 10pt; } table.grid { width: 100%; border-collapse: collapse; }'
        'table.grid tr { break-inside: avoid; } thead { display: table-header-group; }</style></head><body>')


def report(hosts, findings, words=90):
    rows = ''.join(f'<!--cv:row--><tr><td>host-row-{i}</td><td>{"filler " * 25}</td></tr>' for i in range(hosts))
    body = ''.join(f'<!--cv:row--><div class="finding"><h3>finding-{i}</h3><p>{"lorem ipsum dolor " * words}</p></div>' for i in range(findings))
    return (HEAD + '<div class="foot">cvENGINE test report</div><section class="cover"><h1>Cover</h1></section>'
            '<section class="page"><h2>Hosts</h2><!--cv:begin--><table class="grid"><thead><tr><th>HOSTHEADER</th><th>x</th></tr></thead><tbody>' + rows +
            '<!--cv:end--></tbody></table><!--cv:finish--></section>'
            '<section class="page"><h2>Findings</h2><!--cv:begin-->' + body + '<!--cv:end--><!--cv:finish--></section>'
            '<section class="page"><h2>Method</h2><p>method-tail</p></section></body></html>')


class SplitTests(SimpleTestCase):
    def test_a_small_report_is_one_document(self):
        html = report(3, 3)
        self.assertEqual(report_render.split(html), [html])

    def test_every_row_lands_in_exactly_one_chunk(self):
        html = report(300, 300)
        chunks = report_render.split(html, chunk_bytes=20_000)
        self.assertGreater(len(chunks), 4)
        joined = ' '.join(chunks)
        for i in range(300):
            self.assertEqual(len(re.findall(rf'host-row-{i}<', joined)), 1, i)
            self.assertEqual(len(re.findall(rf'finding-{i}<', joined)), 1, i)
        self.assertEqual(joined.count('Method') and joined.count('method-tail'), 1)
        self.assertEqual(joined.count('<h2>Hosts</h2>'), 1)
        self.assertEqual(joined.count('<h2>Findings</h2>'), 1)
        self.assertEqual(joined.count('Cover'), 1)

    def test_a_cut_table_is_reopened_with_its_header_row_and_every_chunk_has_the_footer_and_the_style(self):
        chunks = report_render.split(report(300, 5), chunk_bytes=20_000)
        for chunk in chunks:
            self.assertIn('<style>', chunk)
            self.assertIn('class="foot"', chunk)
        host_chunks = [c for c in chunks if 'host-row-' in c]
        self.assertGreater(len(host_chunks), 2)
        for c in host_chunks:
            self.assertIn('HOSTHEADER', c)
            self.assertTrue(c.count('<table') == c.count('</table>') == 1, 'a table opened and closed once per chunk')

    def test_the_sections_after_the_last_list_ride_with_it(self):
        chunks = report_render.split(report(2, 300), chunk_bytes=20_000)
        self.assertIn('method-tail', chunks[-1])
        self.assertIn('finding-299', chunks[-1])


def child_peak_mb(html, chunked=True):
    """Peak resident MB of a renderer process (a fresh interpreter, so the figure is the render's own), and its PDF."""
    code = ('import resource, sys\nfrom cveFeed import report_render as r\nhtml = sys.stdin.read()\n'
            f'{"r.render(html, sys.argv[1])" if chunked else "r.render_one(html, sys.argv[1])"}\n'
            'print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)')
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, 'r.pdf')
        proc = subprocess.run([sys.executable, '-c', code, out], input=html, capture_output=True, text=True, cwd=WEB_DIR, timeout=600)
        assert proc.returncode == 0, proc.stderr[-500:]
        with open(out, 'rb') as fh:
            return int(proc.stdout.strip().splitlines()[-1]), fh.read()


class MemoryBudgetTests(SimpleTestCase):
    def test_a_long_report_renders_inside_a_memory_budget_and_the_pages_are_numbered_for_the_whole(self):
        html = report(100, 350, words=330)
        pages_flat = None
        flat_peak, flat_pdf = child_peak_mb(html, chunked=False)
        peak, pdf = child_peak_mb(html, chunked=True)
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(pdf))
        pages_flat = len(PdfReader(io.BytesIO(flat_pdf)).pages)
        total = len(reader.pages)
        self.assertLessEqual(abs(total - pages_flat), 4, 'a cut ends at most one page early')
        self.assertGreater(total, 200)
        self.assertEqual(reader.pages[0].extract_text().strip().count('Page'), 0, 'the cover has no footer')
        for n in (2, total // 2, total):
            self.assertIn(f'Page {n} of {total}', reader.pages[n - 1].extract_text())
        text = ' '.join(p.extract_text() for p in reader.pages)
        for i in range(350):
            self.assertEqual(len(re.findall(rf'finding-{i}\b(?!\d)', text)), 1, i)
        self.assertLess(peak, flat_peak * 0.6, f'chunked {peak} MB against {flat_peak} MB laid out whole')
        self.assertLess(peak, 330, 'the renderer\'s own memory budget on a 350-page report')

    def test_the_child_under_a_hard_address_space_limit_still_renders(self):
        """The same render with the address space capped (``setrlimit`` in the child, as a container limit would): it must finish, not be killed."""
        html = report(60, 150)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'r.pdf')

            def limit():
                resource.setrlimit(resource.RLIMIT_AS, (3 * 1024 ** 3, 3 * 1024 ** 3))
            proc = subprocess.run([sys.executable, '-m', 'cveFeed.report_render', out], input=html.encode(), capture_output=True, cwd=WEB_DIR, preexec_fn=limit, timeout=600)
            self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
            self.assertGreater(os.path.getsize(out), 1000)


class OutOfMemoryMessageTests(SimpleTestCase):
    def run_failing(self, code, peak='812'):
        def fake(cmd, **kw):
            with open(cmd[-1], 'w') as fh:
                fh.write(peak)
            return mock.Mock(returncode=code, stderr=b'')
        with mock.patch('cveFeed.report_pdf.subprocess.run', side_effect=fake):
            with self.assertRaises(report_pdf.RenderError) as ctx:
                report_pdf.render_pdf('<p>x</p>', os.path.join(tempfile.gettempdir(), 'never-written.pdf'))
        return str(ctx.exception)

    def test_a_killed_renderer_is_reported_as_running_out_of_memory_with_what_was_measured(self):
        message = self.run_failing(-9)
        self.assertIn('ran out of memory', message)
        self.assertIn('812 MB', message)
        self.assertIn('when scans are idle', message)
        self.assertNotIn('-9', message)

    def test_the_renderers_own_memory_error_says_the_same(self):
        self.assertIn('ran out of memory', self.run_failing(75))

    def test_any_other_failure_keeps_its_short_message(self):
        self.assertEqual(self.run_failing(1), 'the PDF could not be rendered')
