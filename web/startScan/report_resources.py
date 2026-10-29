"""PDF resources are supplied by the report builder, never fetched from a URL.

Only the exact, bounded chart data generated for this report is permitted. This
also rejects nested SVG resources, remote stylesheets and local file URLs.
"""
import base64
import binascii

from weasyprint import HTML
from weasyprint.urls import URLFetcher, URLFetcherResponse


CHART_PREFIX = 'data:image/svg+xml;base64,'
MAX_CHART_BYTES = 2 * 1024 * 1024
MAX_CHARTS = 2


class ClosedFetcher(URLFetcher):
    """A WeasyPrint 68+ fetcher that answers only from a fixed map of URL to bytes and refuses everything else.

    It subclasses ``URLFetcher`` because WeasyPrint insists on that interface (a plain function that raises makes it fail with an
    AttributeError, and one that returns a dict with an AssertionError), but ``fetch`` never reaches the parent: the http, file and
    ftp handlers it carries are never called, and ``allowed_protocols=()`` and no redirects are a second line behind that."""

    def __init__(self, resources=None):
        super().__init__(allowed_protocols=(), allow_redirects=False, fail_on_errors=False)
        self._resources = dict(resources or {})

    def fetch(self, url, headers=None):
        # No fallback to the parent's fetch: even a data: image is untrusted unless it is one of the exact charts generated for this report.
        if url not in self._resources:
            raise ValueError('external report resources are disabled')
        return URLFetcherResponse(url, self._resources[url], {'Content-Type': 'image/svg+xml'})


def report_url_fetcher(charts=()):
    """Build a closed resource map from trusted chart-generator output only."""
    resources = {}
    for index, chart in enumerate(charts):
        if index >= MAX_CHARTS:
            raise ValueError('too many report charts')
        if not chart:
            continue
        if not isinstance(chart, str) or len(chart) > 4 * ((MAX_CHART_BYTES + 2) // 3):
            raise ValueError('report chart exceeds resource limit')
        try:
            raw = base64.b64decode(chart, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError('invalid report chart encoding') from exc
        if len(raw) > MAX_CHART_BYTES:
            raise ValueError('report chart exceeds resource limit')
        resources[CHART_PREFIX + chart] = raw
    return ClosedFetcher(resources)


def render_report_pdf(html, charts=()):
    return HTML(string=html, url_fetcher=report_url_fetcher(charts)).write_pdf()
