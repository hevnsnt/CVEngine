"""The PDF renderer, run as a child process by cveFeed.report_pdf: ``python -m cveFeed.report_render <output.pdf> [peak-file]`` reads the report's
HTML on stdin and writes the PDF.

It is a separate process so that a large report (WeasyPrint is CPU bound for tens of seconds on hundreds of pages) never stalls the
gevent worker that queued it, a crash or a runaway render takes only this process, and the renderer never sees the worker's
environment: the parent starts it with no database password or API key in it. It imports nothing of Django. Resources are answered only
by startScan.report_resources.ClosedFetcher with an empty map, so a ``file:``, ``http:`` or ``data:`` URL in the page is refused and
nothing is read or fetched.

Memory. WeasyPrint lays out the whole document before it writes a page and keeps every page's boxes until it is done: about 1.3 MB a page, so the
default report (500 hosts, 1000 findings, 670 pages) peaked near 1 GB, 3000 hosts near 2.9 GB, and a 1 GB container killed the renderer (-9). The template
marks its two long lists, the hosts table and the findings, with comment markers (``<!--cv:begin-->``, ``<!--cv:row-->`` before every row, ``<!--cv:end-->``,
``<!--cv:finish-->``). A report bigger than ``CHUNK_BYTES`` of HTML is cut at row markers into chunks, each laid out as a document of its own with the same
head and style (a cut table is reopened with its header row, as it is on every new page anyway), written to a temporary PDF and freed; the PDFs are
joined page by page. Every page is then stamped with its real ``Page N of Y`` (the one thing a chunk cannot know) by a second, nearly empty document that uses
the same ``@page`` rule, so the footer is in the same place in the same type. Cuts between the report's sections cost nothing (each section starts a page
anyway); a cut inside a list means the page before it ends where the chunk ended, so a report of N chunks has at most N-1 pages that end a little early.
A report that fits one chunk is rendered exactly as before.
"""
import gc
import os
import re
import sys
import tempfile
import threading
import time

CHUNK_BYTES = 300_000  # about 90 pages, 120 MB of layout
MARK = re.compile(r'<!--cv:(begin|row|end|finish)-->')
PAGE_OF = 'content: "Page " counter(page) " of " counter(pages)'  # the footer rule in report.html: a chunk cannot know either number


def peak_mb():
    """This process's high-water resident set in MB (Linux ``VmHWM``; 0 where it cannot be read)."""
    try:
        with open('/proc/self/status') as fh:
            for line in fh:
                if line.startswith('VmHWM:'):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    return 0


def watch_peak(path, every=0.25):
    """Keep the peak so far in ``path`` while the render runs: a process the kernel kills leaves no last words, and the parent reads this to say how far it got."""
    def run():
        last = -1
        while True:
            now = peak_mb()
            if now != last:
                try:
                    with open(path, 'w') as fh:
                        fh.write(str(now))
                except OSError:
                    return
                last = now
            time.sleep(every)
    threading.Thread(target=run, daemon=True).start()


def _lists(html):
    out, cur = [], None
    for m in MARK.finditer(html):
        kind = m.group(1)
        if kind == 'begin':
            cur = {'begin': m.end(), 'rows': [], 'end': None, 'finish': None}
            out.append(cur)
        elif cur is not None:
            if kind == 'row':
                cur['rows'].append(m.start())
            elif kind == 'end':
                cur['end'] = m.start()
            else:
                cur['finish'] = m.end()
    return [c for c in out if c['rows'] and c['end'] is not None and c['finish'] is not None]


def split(html, chunk_bytes=CHUNK_BYTES):
    """The report cut into documents of about ``chunk_bytes`` each, at the rows of its long lists: a list of HTML strings (one when the report is small)."""
    lists = _lists(html)
    if len(html) <= chunk_bytes or not lists or '<body>' not in html:
        return [html]
    head = html[:html.index('<body>') + len('<body>')]
    foot = re.search(r'<div class="foot">.*?</div>', html, re.S)
    start = head + (foot.group(0) if foot else '')  # what every document after the first begins with
    chunks, pos = [], 0

    def emit(text):
        chunks.append(text if not chunks else start + text)

    for c in lists:
        rows, end, finish = c['rows'], c['end'], c['finish']
        closer = html[end:finish] + '</section></body></html>'  # shuts the list's table and its section where a cut falls
        opener = '<section class="page">' + html[c['begin']:rows[0]]  # reopens them: the table with its header row
        runs, a = [], 0
        for i in range(1, len(rows)):
            if rows[i] - rows[a] >= chunk_bytes:
                runs.append((a, i))
                a = i
        runs.append((a, len(rows)))
        for g, (a, b) in enumerate(runs):
            text = html[pos if g == 0 else rows[a]:rows[b] if b < len(rows) else end]
            if g > 0:
                text = opener + text
            if b < len(rows):
                emit(text + closer)
            else:
                emit(text + html[end:finish])  # the section goes on in the text after the list
                pos = finish
    rest = html[pos:]
    if rest.strip():
        chunks[-1] += rest  # the sections after the last list (each starts a page of its own) ride with it: no page ends early for them
    return chunks


def render_one(html, out_path, footer=True):
    from startScan.report_resources import report_url_fetcher
    from weasyprint import HTML
    if not footer:
        html = html.replace(PAGE_OF, 'content: none')
    doc = HTML(string=html, url_fetcher=report_url_fetcher()).render()
    pages = len(doc.pages)
    doc.write_pdf(out_path)
    del doc
    gc.collect()
    return pages


def stamp_html(total):
    """``total`` nearly empty pages in the report's own page setup, each with only ``Page N of total`` in the same margin box and type (page 1 is the cover: none)."""
    return ('<!doctype html><meta charset="utf-8"><style>'
            '@page { size: A4; margin: 22mm 17mm 21mm 17mm; '
            f'@bottom-right {{ content: "Page " counter(page) " of {int(total)}"; font: 8pt sans-serif; color: #6b7280; }} }}'
            '@page cover { margin: 0; @bottom-right { content: none; } }'
            'body { margin: 0; } i { display: block; height: 1px; break-after: page; } i.cover { page: cover; }'
            '</style><body><i class="cover"></i>' + '<i></i>' * (int(total) - 1) + '</body>')


def render_chunked(chunks, out_path):
    from pypdf import PdfReader, PdfWriter
    from startScan.report_resources import report_url_fetcher
    from weasyprint import HTML
    with tempfile.TemporaryDirectory(prefix='cv-report-') as work:
        paths, total = [], 0
        for i, chunk in enumerate(chunks):
            path = os.path.join(work, f'part{i}.pdf')
            total += render_one(chunk, path, footer=False)
            paths.append(path)
        stamp = os.path.join(work, 'stamp.pdf')
        HTML(string=stamp_html(total), url_fetcher=report_url_fetcher()).write_pdf(stamp)
        gc.collect()
        stamps = PdfReader(stamp).pages
        writer = PdfWriter()
        n = 0
        for path in paths:
            reader = PdfReader(path)
            if n == 0:
                writer.add_metadata({k: v for k, v in (reader.metadata or {}).items() if isinstance(v, str)})
            for page in reader.pages:
                page.merge_page(stamps[n])
                writer.add_page(page).compress_content_streams()  # the merge leaves the page's content unpacked: 8 times the size
                n += 1
        writer.compress_identical_objects()  # one copy of the stamp's font, not one per page
        with open(out_path, 'wb') as fh:
            writer.write(fh)


def render(html, out_path):
    chunks = split(html)
    if len(chunks) == 1:
        render_one(html, out_path, footer=True)
    else:
        render_chunked(chunks, out_path)


def main(argv):
    if len(argv) not in (2, 3):
        sys.stderr.write('usage: python -m cveFeed.report_render <output.pdf> [peak-file]\n')
        return 2
    if len(argv) == 3:
        watch_peak(argv[2])
    try:
        render(sys.stdin.buffer.read().decode('utf-8'), argv[1])
    except MemoryError:
        sys.stderr.write(f'out of memory at about {peak_mb()} MB\n')
        return 75
    sys.stderr.write(f'peak_rss_mb={peak_mb()}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
