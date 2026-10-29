"""HTML and PDF of a report: the template is rendered by Django with autoescape (cveFeed/templates/cveFeed/report.html), then the PDF
is made by a child process (cveFeed.report_render) under a time limit and with a stripped environment."""
import logging
import os
import subprocess
import sys

from django.template.loader import render_to_string

logger = logging.getLogger(__name__)

DEFAULT_RENDER_SECONDS = 900
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
    environment with only what fonts and the dynamic loader need."""
    env = {k: os.environ[k] for k in CHILD_ENV if k in os.environ}
    try:
        proc = subprocess.run([sys.executable, '-s', '-m', 'cveFeed.report_render', out_path], input=html.encode('utf-8'),
                              capture_output=True, timeout=timeout or render_seconds(), cwd=WEB_DIR, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        _discard(out_path)
        raise RenderError('rendering took too long; narrow the report to one host') from exc
    if proc.returncode != 0:
        logger.error('report renderer failed (%s): %s', proc.returncode, proc.stderr.decode('utf-8', 'replace')[-500:])
        _discard(out_path)
        raise RenderError('the PDF could not be rendered')
    return out_path


def _discard(path):
    try:
        os.unlink(path)
    except OSError:
        pass
