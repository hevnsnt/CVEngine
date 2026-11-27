"""Donut chart helpers that return SVG documents as base64 strings."""

import base64
import html
import math

from django.db.models import Count

__all__ = [
    'generate_subdomain_chart_by_http_status',
    'generate_vulnerability_chart_by_severity',
]

SEVERITY_ORDER = (4, 3, 2, 1, 0, -1)
SEVERITY_LABELS = {
    4: 'Critical',
    3: 'High',
    2: 'Medium',
    1: 'Low',
    0: 'Info',
    -1: 'Unknown',
}
SEVERITY_COLORS = {
    4: '#b71c1c',
    3: '#e65100',
    2: '#f9a825',
    1: '#1976d2',
    0: '#78909c',
    -1: '#9e9e9e',
}

STATUS_SHADES = {
    '2': ['#2e7d32', '#43a047', '#66bb6a', '#1b5e20', '#81c784', '#388e3c'],
    '3': ['#1565c0', '#1e88e5', '#42a5f5', '#0d47a1', '#64b5f6', '#1976d2'],
    '4': ['#e65100', '#fb8c00', '#ffa726', '#bf360c', '#ffb74d', '#ef6c00'],
    '5': ['#b71c1c', '#e53935', '#ef5350', '#7f0000', '#e57373', '#c62828'],
    'o': ['#6a1b9a', '#8e24aa', '#ab47bc', '#4a148c', '#ba68c8', '#7b1fa2'],
}

WIDTH = 680
RING_CX = 190
OUTER_R = 160
INNER_R = 92
LEGEND_X = 400
LABEL_MIN_FRACTION = 0.06
FONT = 'Helvetica, Arial, sans-serif'


def _encode(svg):
    return base64.b64encode(svg.encode('utf-8')).decode('ascii')


def _text_color(hex_color):
    """Pick black or white text for readability on the given background."""
    h = hex_color.lstrip('#')
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return '#212121' if luminance > 160 else '#ffffff'


def _point(cx, cy, radius, angle):
    return cx + radius * math.cos(angle), cy + radius * math.sin(angle)


def _sector_path(cx, cy, r_out, r_in, start, end):
    x1, y1 = _point(cx, cy, r_out, start)
    x2, y2 = _point(cx, cy, r_out, end)
    x3, y3 = _point(cx, cy, r_in, end)
    x4, y4 = _point(cx, cy, r_in, start)
    large = 1 if (end - start) > math.pi else 0
    return (
        f'M {x1:.2f} {y1:.2f} '
        f'A {r_out} {r_out} 0 {large} 1 {x2:.2f} {y2:.2f} '
        f'L {x3:.2f} {y3:.2f} '
        f'A {r_in} {r_in} 0 {large} 0 {x4:.2f} {y4:.2f} Z'
    )


def _svg_open(height):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" font-family="{FONT}">'
        f'<rect x="0" y="0" width="{WIDTH}" height="{height}" fill="#ffffff"/>'
    )


def _clean_segments(segments):
    cleaned = []
    for label, count, color in segments:
        count = int(count)
        if count > 0:
            cleaned.append((str(label), count, color))
    return cleaned


def _donut(title, segments):
    segments = _clean_segments(segments)
    total = sum(count for _, count, _ in segments)
    safe_title = html.escape(title)

    if total <= 0:
        height = 200
        return _encode(
            _svg_open(height)
            + f'<text x="{WIDTH / 2:.0f}" y="{height / 2 - 10:.0f}" text-anchor="middle" '
            f'font-size="18" font-weight="bold" fill="#212121">{safe_title}</text>'
            f'<text x="{WIDTH / 2:.0f}" y="{height / 2 + 20:.0f}" text-anchor="middle" '
            f'font-size="16" fill="#616161">No data</text>'
            '</svg>'
        )

    row_h = 24
    legend_h = 40 + row_h * len(segments)
    height = max(2 * OUTER_R + 40, legend_h)
    cy = height / 2
    parts = [_svg_open(height)]

    if len(segments) == 1:
        label, count, color = segments[0]
        mid = (OUTER_R + INNER_R) / 2
        parts.append(
            f'<circle cx="{RING_CX}" cy="{cy:.2f}" r="{mid}" fill="none" '
            f'stroke="{color}" stroke-width="{OUTER_R - INNER_R}"/>'
        )
        spans = [(label, count, color, -math.pi / 2, 3 * math.pi / 2)]
    else:
        spans = []
        angle = -math.pi / 2
        for label, count, color in segments:
            sweep = 2 * math.pi * count / total
            spans.append((label, count, color, angle, angle + sweep))
            angle += sweep
        for label, count, color, start, end in spans:
            parts.append(
                f'<path d="{_sector_path(RING_CX, cy, OUTER_R, INNER_R, start, end)}" '
                f'fill="{color}" stroke="#ffffff" stroke-width="1.5"/>'
            )

    mid_r = (OUTER_R + INNER_R) / 2
    for label, count, color, start, end in spans:
        fraction = count / total
        if fraction < LABEL_MIN_FRACTION:
            continue
        x, y = _point(RING_CX, cy, mid_r, (start + end) / 2)
        fill = _text_color(color)
        percent = f'{fraction * 100:.1f}%'
        parts.append(
            f'<text x="{x:.2f}" y="{y - 2:.2f}" text-anchor="middle" font-size="11" '
            f'font-weight="bold" fill="{fill}">{html.escape(label)}</text>'
            f'<text x="{x:.2f}" y="{y + 11:.2f}" text-anchor="middle" font-size="10" '
            f'fill="{fill}">{count} ({percent})</text>'
        )

    parts.append(
        f'<text x="{RING_CX}" y="{cy + 6:.2f}" text-anchor="middle" font-size="18" '
        f'font-weight="bold" fill="#212121">{safe_title}</text>'
    )

    y = (height - row_h * len(segments)) / 2
    for label, count, color in segments:
        parts.append(
            f'<rect x="{LEGEND_X}" y="{y + 4:.2f}" width="14" height="14" rx="2" fill="{color}"/>'
            f'<text x="{LEGEND_X + 24}" y="{y + 16:.2f}" font-size="13" fill="#212121">'
            f'{html.escape(label)}: {count}</text>'
        )
        y += row_h

    parts.append('</svg>')
    return _encode(''.join(parts))


def _status_class(code):
    if 200 <= code < 300:
        return '2'
    if 300 <= code < 400:
        return '3'
    if 400 <= code < 500:
        return '4'
    if 500 <= code < 600:
        return '5'
    return 'o'


def generate_subdomain_chart_by_http_status(subdomains):
    """Donut chart of hosts per HTTP status code, as a base64 SVG string."""
    rows = (
        subdomains.exclude(http_status=0)
        .exclude(http_status__isnull=True)
        .values('http_status')
        .annotate(n=Count('id'))
        .order_by('-n', 'http_status')
    )
    used = {}
    segments = []
    for row in rows:
        code = int(row['http_status'])
        count = int(row['n'])
        if count <= 0:
            continue
        cls = _status_class(code)
        shades = STATUS_SHADES[cls]
        index = used.get(cls, 0)
        used[cls] = index + 1
        segments.append((str(code), count, shades[index % len(shades)]))
    return _donut('HTTP status', segments)


def generate_vulnerability_chart_by_severity(vulnerabilities):
    """Donut chart of findings per severity, as a base64 SVG string."""
    rows = vulnerabilities.values('severity').annotate(n=Count('id'))
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in rows:
        severity = row['severity']
        if severity not in counts:
            severity = -1
        counts[severity] += int(row['n'])
    segments = [
        (SEVERITY_LABELS[s], counts[s], SEVERITY_COLORS[s])
        for s in SEVERITY_ORDER
    ]
    return _donut('Severity', segments)
