"""HTML and PDF of a report: the template is rendered by Django with autoescape (cveFeed/templates/cveFeed/report.html), then the PDF
is made by a child process (cveFeed.report_render) under a time limit and with a stripped environment."""
import logging
import os
import shutil
import subprocess
import sys

from django.template.loader import render_to_string

logger = logging.getLogger(__name__)

DEFAULT_RENDER_SECONDS = 900
# the renderer is a core of CPU for as long as it lays out the pages (23 s for 460): it runs at a lower priority than the web server and the database
# sharing the host (``nice`` ships with coreutils; without it the renderer simply runs at the worker's own priority)
_LOW_PRIORITY = ['nice', '-n', '10'] if shutil.which('nice') else []
WEB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD_ENV = ('PATH', 'HOME', 'LANG', 'LC_ALL', 'FONTCONFIG_PATH', 'FONTCONFIG_FILE', 'XDG_CACHE_HOME', 'XDG_DATA_DIRS', 'TMPDIR')


class RenderError(Exception):
    """The PDF could not be made (the message is short and safe to show)."""


def render_seconds():
    try:
        return max(30, int(os.environ.get('CVENGINE_REPORT_RENDER_SECONDS', '')))
    except ValueError:
        return DEFAULT_RENDER_SECONDS


def build_html(data):
    return render_to_string('cveFeed/report.html', {'r': data})


def render_pdf(html, out_path, timeout=None):
    """Write the PDF of ``html`` to ``out_path`` (a path this code chose) or raise RenderError. The child gets the HTML on stdin and an
    environment with only what fonts and the dynamic loader need. It keeps its high-water memory in a file beside the output, so a render
    the kernel killed for memory can still say how far it got."""
    env = {k: os.environ[k] for k in CHILD_ENV if k in os.environ}
    peak_file = out_path + '.peak'
    try:
        proc = subprocess.run([*_LOW_PRIORITY, sys.executable, '-s', '-m', 'cveFeed.report_render', out_path, peak_file], input=html.encode('utf-8'),
                              capture_output=True, timeout=timeout or render_seconds(), cwd=WEB_DIR, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        _discard(out_path)
        _discard(peak_file)
        raise RenderError('rendering took too long; narrow the report to one host') from exc
    peak = _read_peak(peak_file)
    _discard(peak_file)
    if proc.returncode != 0:
        logger.error('report renderer failed (%s, peak %s MB): %s', proc.returncode, peak, proc.stderr.decode('utf-8', 'replace')[-500:])
        _discard(out_path)
        if proc.returncode in (-9, 75):  # SIGKILL (the kernel's out-of-memory kill) or the renderer's own MemoryError
            raise RenderError(f'the report ran out of memory while the PDF was laid out (the renderer had reached about {peak} MB). '
                              'Try again when scans are idle, or narrow the report to one host.' if peak else
                              'the report ran out of memory while the PDF was laid out. Try again when scans are idle, or narrow the report to one host.')
        raise RenderError('the PDF could not be rendered')
    return out_path


def _read_peak(path):
    try:
        with open(path) as fh:
            return int(fh.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _discard(path):
    try:
        os.unlink(path)
    except OSError:
        pass
