"""The PDF renderer, run as a child process by cveFeed.report_pdf: ``python -m cveFeed.report_render <output.pdf>`` reads the report's
HTML on stdin and writes the PDF.

It is a separate process so that a large report (WeasyPrint is CPU bound for tens of seconds on hundreds of pages) never stalls the
gevent worker that queued it, a crash or a runaway render takes only this process, and the renderer never sees the worker's
environment: the parent starts it with no database password or API key in it. It imports nothing of Django. Resources are answered only
by startScan.report_resources.ClosedFetcher with an empty map, so a ``file:``, ``http:`` or ``data:`` URL in the page is refused and
nothing is read or fetched.
"""
import sys


def render(html, out_path):
    from startScan.report_resources import report_url_fetcher
    from weasyprint import HTML
    HTML(string=html, url_fetcher=report_url_fetcher()).write_pdf(out_path)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write('usage: python -m cveFeed.report_render <output.pdf>\n')
        return 2
    render(sys.stdin.buffer.read().decode('utf-8'), argv[1])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
