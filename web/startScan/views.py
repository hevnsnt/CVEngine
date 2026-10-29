"""Downloads for a scan: the PDF/HTML report and plain-text exports of what it found. The classic screens that used to
sit around these are gone (see tenancy.middleware.RetireClassicUiMiddleware); the CVEngine pages link here."""
import markdown

from html import escape

from collections import Counter, defaultdict
from datetime import datetime
from django.db.models import Count, Case, When, IntegerField, Prefetch
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template.loader import get_template
from rolepermissions.decorators import has_permission_decorator

from reNgine.charts import *
from reNgine.common_func import *
from reNgine.definitions import *
from scanEngine.models import *
from startScan.models import *
from targetApp.models import *
from startScan.report_resources import render_report_pdf

# The report is rendered and converted to PDF inside the request, so the per-host and per-finding sections are cut at these
# row counts (the totals, charts and summary tables still cover everything) and say so in the document.
REPORT_MAX_HOSTS = 2000
REPORT_MAX_FINDINGS = 2000


def _text_download(lines, kind, scan):
    """A text/plain attachment with one entry per line, named after the target and the scan's start date."""
    response = HttpResponse('\n'.join(lines) + '\n' if lines else '', content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="{kind}_{scan.domain.name}_{scan.start_scan_date.date()}.txt"'
    return response


def export_subdomains(request, scan_id):
    scan = get_object_or_404(ScanHistory, id=scan_id)
    return _text_download(list(Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True)), 'subdomains', scan)


def export_endpoints(request, scan_id):
    scan = get_object_or_404(ScanHistory, id=scan_id)
    return _text_download(list(EndPoint.objects.filter(scan_history=scan).values_list('http_url', flat=True)), 'endpoints', scan)


def export_urls(request, scan_id):
    scan = get_object_or_404(ScanHistory, id=scan_id)
    urls = Subdomain.objects.filter(scan_history=scan).exclude(http_url__isnull=True).exclude(http_url='')
    return _text_download(list(urls.values_list('http_url', flat=True)), 'urls', scan)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def create_report(request, id):
    primary_color = '#FFB74D'
    secondary_color = '#212121'
    # get report type
    report_type = request.GET['report_type'] if 'report_type' in request.GET  else 'full'
    report_template = request.GET['report_template'] if 'report_template' in request.GET else 'default'

    is_ignore_info_vuln = True if 'ignore_info_vuln' in request.GET else False
    if report_type == 'recon':
        show_recon = True
        show_vuln = False
        report_name = 'Reconnaissance Report'
    elif report_type == 'vulnerability':
        show_recon = False
        show_vuln = True
        report_name = 'Vulnerability Report'
    else:
        # default
        show_recon = True
        show_vuln = True
        report_name = 'Full Scan Report'

    scan = ScanHistory.objects.get(id=id)
    vulns = (
        Vulnerability.objects
        .filter(scan_history=scan)
        .order_by('-severity')
    ) if not is_ignore_info_vuln else (
        Vulnerability.objects
        .filter(scan_history=scan)
        .exclude(severity=0)
        .order_by('-severity')
    )
    unique_vulns = (
        Vulnerability.objects
        .filter(scan_history=scan)
        .values("name", "severity")
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    ) if not is_ignore_info_vuln else (
        Vulnerability.objects
        .filter(scan_history=scan)
        .exclude(severity=0)
        .values("name", "severity")
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    )

    subdomains = (
        Subdomain.objects
        .filter(scan_history=scan)
        .order_by('-content_length')
    )
    subdomain_alive_count = (
        Subdomain.objects
        .filter(scan_history__id=id)
        .values('name')
        .distinct()
        .filter(http_status__exact=200)
        .count()
    )
    subdomains = subdomains.annotate(
        sort_order=Case(
            When(http_status__gte=200, http_status__lt=300, then=1),
            When(http_status__gte=300, http_status__lt=400, then=2),
            When(http_status__gte=400, http_status__lt=500, then=3),
            default=4,
            output_field=IntegerField(),
        )
    ).order_by('sort_order', 'http_status')




    ip_addresses = (
        IpAddress.objects
        .filter(ip_addresses__in=subdomains)
        .distinct()
    )
    # One query each for the hosts (with their addresses and ports), the findings (with their ids and references) and the
    # per-host finding names, instead of several queries per host and per finding while the template renders.
    host_total = subdomains.count()
    host_rows = list(subdomains.prefetch_related(Prefetch(
        'ip_addresses', queryset=IpAddress.objects.select_related('geo_iso').prefetch_related('ports')))[:REPORT_MAX_HOSTS])
    names_by_host, total_by_host = defaultdict(set), Counter()
    per_host = (Vulnerability.objects.filter(scan_history=scan).order_by()
                .values('subdomain__name', 'name', 'severity').annotate(n=Count('id')))
    for row in per_host:
        total_by_host[row['subdomain__name']] += row['n']
        if row['severity'] != 0:
            names_by_host[row['subdomain__name']].add(row['name'])
    for host in host_rows:
        host.report_vulnerability_names = sorted(names_by_host.get(host.name, ()))
        host.report_vulnerability_count = total_by_host.get(host.name, 0)
    ip_total = ip_addresses.count()
    ip_rows = list(ip_addresses.order_by('address').select_related('geo_iso').prefetch_related('ports')[:REPORT_MAX_HOSTS])
    vuln_total = vulns.count()
    vuln_rows = list(vulns.prefetch_related('cve_ids', 'cwe_ids', 'references')[:REPORT_MAX_FINDINGS])
    data = {
        'scan_object': scan,
        'unique_vulnerabilities': unique_vulns,
        'all_vulnerabilities': vuln_rows,
        'all_vulnerabilities_count': vuln_total,
        'findings_cut': f'first {REPORT_MAX_FINDINGS} of {vuln_total} findings' if vuln_total > REPORT_MAX_FINDINGS else '',
        'subdomain_alive_count': subdomain_alive_count,
        'subdomains': host_rows,
        'hosts_cut': f'first {REPORT_MAX_HOSTS} of {host_total} hosts' if host_total > REPORT_MAX_HOSTS else '',
        'ip_addresses': ip_rows,
        'ip_addresses_count': ip_total,
        'show_recon': show_recon,
        'show_vuln': show_vuln,
        'report_name': report_name,
        'is_ignore_info_vuln': is_ignore_info_vuln,
    }

    # Get report related config
    vuln_report_query = VulnerabilityReportSetting.objects.all()
    if vuln_report_query.exists():
        report = vuln_report_query[0]
        data['company_name'] = report.company_name
        data['company_address'] = report.company_address
        data['company_email'] = report.company_email
        data['company_website'] = report.company_website
        data['show_rengine_banner'] = report.show_rengine_banner
        data['show_footer'] = report.show_footer
        data['footer_text'] = report.footer_text
        data['show_executive_summary'] = report.show_executive_summary

        # Replace executive_summary_description with template syntax
        description = report.executive_summary_description or ''  # both are nullable settings
        description = description.replace('{scan_date}', scan.start_scan_date.strftime('%d %B, %Y'))
        description = description.replace('{company_name}', report.company_name or '')
        description = description.replace('{target_name}', scan.domain.name)
        description = description.replace('{subdomain_count}', str(host_total))
        description = description.replace('{vulnerability_count}', str(vuln_total))
        description = description.replace('{critical_count}', str(vulns.filter(severity=4).count()))
        description = description.replace('{high_count}', str(vulns.filter(severity=3).count()))
        description = description.replace('{medium_count}', str(vulns.filter(severity=2).count()))
        description = description.replace('{low_count}', str(vulns.filter(severity=1).count()))
        description = description.replace('{info_count}', str(vulns.filter(severity=0).count()))
        description = description.replace('{unknown_count}', str(vulns.filter(severity=-1).count()))
        if scan.domain.description:
            description = description.replace('{target_description}', scan.domain.description)

        # Convert to Markdown
        data['executive_summary_description'] = markdown.markdown(escape(description))  # no raw HTML: the PDF renderer fetches any URL it finds

        primary_color = report.primary_color
        secondary_color = report.secondary_color

    data['primary_color'] = primary_color
    data['secondary_color'] = secondary_color

    data['subdomain_http_status_chart'] = generate_subdomain_chart_by_http_status(subdomains)
    data['vulns_severity_chart'] = generate_vulnerability_chart_by_severity(vulns) if vulns else ''

    if report_template == 'modern':
        template = get_template('report/modern.html')
    else:
        template = get_template('report/default.html')

    html = template.render(data)
    pdf = render_report_pdf(html, (data['subdomain_http_status_chart'], data['vulns_severity_chart']))

    if 'download' in request.GET:
        response = HttpResponse(pdf, content_type='application/octet-stream')
    else:
        response = HttpResponse(pdf, content_type='application/pdf')

    return response
