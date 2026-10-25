"""PDF resources are supplied by the report builder, never fetched from a URL.

Only the exact, bounded chart data generated for this report is permitted. This
also rejects nested SVG resources, remote stylesheets and local file URLs.
"""
import base64
import binascii

from weasyprint import HTML


CHART_PREFIX = 'data:image/svg+xml;base64,'
MAX_CHART_BYTES = 2 * 1024 * 1024
MAX_CHARTS = 2


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

    def fetch(url, *args, **kwargs):
        # No default_url_fetcher fallback: even a data: image is untrusted unless
        # it is one of the exact charts generated for this report.
        if url not in resources:
            raise ValueError('external report resources are disabled')
        return {'string': resources[url], 'mime_type': 'image/svg+xml'}

    return fetch


def render_report_pdf(html, charts=()):
    return HTML(string=html, url_fetcher=report_url_fetcher(charts)).write_pdf()
