import base64
import colorsys
import math
from xml.sax.saxutils import escape

from django.db.models import Count
from reNgine.definitions import NUCLEI_SEVERITY_MAP

from startScan.models import *



"""
    This file is used to generate the charts for the pdf report.
"""

def generate_subdomain_chart_by_http_status(subdomains):
    """
    Generates a donut chart (SVG) for the subdomains based on the http status.
    Includes label, count, and percentage inside the chart segments and in the legend.
    Args:
        subdomains: QuerySet of subdomains.
    Returns:
        SVG image as base64 encoded string (embed as data:image/svg+xml;base64,...).
    """
    http_statuses = (
        subdomains
        .exclude(http_status=0)
        .values('http_status')
        .annotate(count=Count('http_status'))
        .order_by('-count')
    )
    slices = [(str(e['http_status']), e['count'], get_color_by_http_status(e['http_status'])) for e in http_statuses]
    return donut_chart_base64('HTTP Status', slices)



def get_color_by_severity(severity_int):
    """
    Returns a color based on the severity level using a modern color scheme.
    """
    color_map = {
        4: '#FF4D6A',
        3: '#FF9F43',
        2: '#FFCA3A',
        1: '#4ADE80',
        0: '#4ECDC4',
        -1: '#A8A9AD',
    }
    return color_map.get(severity_int, '#A8A9AD')  # Default to gray if severity is unknown

def generate_vulnerability_chart_by_severity(vulnerabilities):
    """
    Generates a donut chart (SVG) for the vulnerabilities based on the severity.
    Args:
        vulnerabilities: QuerySet of Vulnerability objects.
    Returns:
        SVG image as base64 encoded string (embed as data:image/svg+xml;base64,...).
    """
    severity_counts = (
        vulnerabilities
        .values('severity')
        .annotate(count=Count('severity'))
        .order_by('-severity')
    )
    slices = [(NUCLEI_REVERSE_SEVERITY_MAP[e['severity']].capitalize(), e['count'], get_color_by_severity(e['severity']))
              for e in severity_counts]
    return donut_chart_base64('Severity', slices)



def donut_chart_base64(title, slices, size=700):
    """A donut chart with count and percentage on each segment and a legend, as base64 SVG.
    Plain SVG instead of plotly + kaleido: no headless browser, nothing to install, and WeasyPrint draws it natively.
    ``slices`` is [(label, value, color)]; zero or negative values are skipped."""
    slices = [(str(label), int(value), color) for label, value, color in slices if value and value > 0]
    total = sum(v for _, v, _ in slices)
    cx = cy = size / 2 - 60
    outer, inner = size / 2 - 120, (size / 2 - 120) * 0.4
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size - 100}" viewBox="0 0 {size + 120} {size - 100}" font-family="Helvetica, Arial, sans-serif">']
    if not total:
        parts.append(f'<text x="{cx + 60}" y="{cy}" text-anchor="middle" font-size="18" fill="#666">No data</text></svg>')
        return base64.b64encode(''.join(parts).encode('utf-8')).decode('utf-8')
    cx += 60
    angle = -math.pi / 2
    for label, value, color in slices:
        sweep = 2 * math.pi * value / total
        end = angle + sweep
        if len(slices) == 1:  # a full ring cannot be drawn as a single arc
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(outer + inner) / 2}" fill="none" stroke="{escape(color)}" stroke-width="{outer - inner}"/>')
        else:
            large = 1 if sweep > math.pi else 0
            x1, y1 = cx + outer * math.cos(angle), cy + outer * math.sin(angle)
            x2, y2 = cx + outer * math.cos(end), cy + outer * math.sin(end)
            x3, y3 = cx + inner * math.cos(end), cy + inner * math.sin(end)
            x4, y4 = cx + inner * math.cos(angle), cy + inner * math.sin(angle)
            parts.append(f'<path d="M{x1:.1f},{y1:.1f} A{outer},{outer} 0 {large} 1 {x2:.1f},{y2:.1f} L{x3:.1f},{y3:.1f} '
                         f'A{inner},{inner} 0 {large} 0 {x4:.1f},{y4:.1f} Z" fill="{escape(color)}" stroke="#fff" stroke-width="2"/>')
        if sweep > 0.25:  # label only segments big enough to hold it
            mid, radius = angle + sweep / 2, (outer + inner) / 2
            tx, ty = cx + radius * math.cos(mid), cy + radius * math.sin(mid)
            parts.append(f'<text x="{tx:.1f}" y="{ty:.1f}" text-anchor="middle" font-size="16" fill="#111">'
                         f'<tspan x="{tx:.1f}" dy="-6">{escape(label)}</tspan><tspan x="{tx:.1f}" dy="18">{value} ({value / total:.0%})</tspan></text>')
        angle = end
    parts.append(f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" font-size="18" fill="#333">{escape(title)}</text>')
    legend_x, legend_y = cx + outer + 40, cy - 12 * len(slices)
    for i, (label, value, color) in enumerate(slices):
        y = legend_y + i * 28
        parts.append(f'<rect x="{legend_x}" y="{y - 14}" width="16" height="16" fill="{escape(color)}"/>'
                     f'<text x="{legend_x + 24}" y="{y}" font-size="18" fill="#111">{escape(label)}  {value}</text>')
    parts.append('</svg>')
    return base64.b64encode(''.join(parts).encode('utf-8')).decode('utf-8')


def generate_color(base_color, offset):
    r, g, b = int(base_color[1:3], 16), int(base_color[3:5], 16), int(base_color[5:7], 16)
    factor = 1 + (offset * 0.03)
    r, g, b = [min(255, int(c * factor)) for c in (r, g, b)]
    return f"#{r:02x}{g:02x}{b:02x}"


def get_color_by_http_status(http_status):
    """
        Returns the color based on the http status.
        Args:
            http_status: HTTP status code.
        Returns:
            Color code.
    """

    status = int(http_status)
    
    colors = {
        200: "#36a2eb",
        300: "#4bc0c0",
        400: "#ff6384",
        401: "#ff9f40",
        403: "#f27474",
        404: "#ffa1b5",
        429: "#bf7bff",
        500: "#9966ff",
        502: "#8a4fff",
        503: "#c39bd3",
    }


    if status in colors:
        return colors[status]
    elif 200 <= status < 300:
        return generate_color(colors[200], status - 200)
    elif 300 <= status < 400:
        return generate_color(colors[300], status - 300)
    elif 400 <= status < 500:
        return generate_color(colors[400], status - 400)
    elif 500 <= status < 600:
        return generate_color(colors[500], status - 500)
    else:
        return "#c9cbcf"