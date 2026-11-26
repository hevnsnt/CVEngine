"""The scan PDF report (startScan create_report, report/default.html and report/modern.html, cvengine.charts) after its clean-room rewrite.

These are the acceptance checks of the rewrite's specification: the report names only what it was given, fetches nothing, escapes what a
scan stored, and its charts are self-contained SVG. The query-count and cap checks live in tests/test_report_queries.py."""
import base64
import re
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cvengine import charts
from dashboard.models import Org, Project
from scanEngine.models import EngineType, VulnerabilityReportSetting
from startScan import views
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from startScan.report_resources import render_report_pdf
from targetApp.models import Domain
from tests.test_tenancy import client_for


class ScanReportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        project = Project.objects.create(name='Clean', slug='clean-rep', insert_date=now, org=Org.objects.create(name='C', slug='clean-org'))
        cls.domain = Domain.objects.create(name='clean.test', project=project, insert_date=now)
        cls.user = User.objects.create_superuser('clean-admin', 'clean@example.test', 'pw-12345-long')
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, stop_scan_date=now,
                                              scan_status=2, initiated_by=cls.user, results_dir='/tmp')
        for i, (status, sev) in enumerate(((200, 4), (301, 3), (404, 0), (503, -1))):
            sub = Subdomain.objects.create(name=f'h{i}.clean.test', target_domain=cls.domain, scan_history=cls.scan, http_status=status,
                                           page_title='<script>alert(1)</script>' if i == 0 else f'Title {i}')
            ip = IpAddress.objects.create(address=f'198.51.100.{i + 1}', is_cdn=(i == 1))
            ip.ports.add(Port.objects.create(number=443 + i, service_name='https', description='x', is_uncommon=False))
            sub.ip_addresses.add(ip)
            Vulnerability.objects.create(name=f'Finding <{i}>', severity=sev, subdomain=sub, target_domain=cls.domain, scan_history=cls.scan,
                                         http_url=f'https://h{i}.clean.test/p?q=1', discovered_date=now, source='nuclei',
                                         description='line one\nline two', remediation='upgrade')
        VulnerabilityReportSetting.objects.create(company_name='Acme <Audit>', company_email='a@example.test', show_footer=True,
                                                  footer_text='Confidential"; } body { display: none', show_executive_summary=True,
                                                  executive_summary_description='Scan of {target_name}', show_cvengine_banner=True)

    def html(self, template='modern', report_type='full', **extra):
        with mock.patch.object(views, 'render_report_pdf', return_value=b'%PDF') as pdf:
            response = client_for(self.user).get(f'/scan/create_report/{self.scan.id}',
                                                 {'report_template': template, 'report_type': report_type, **extra})
        self.assertEqual(response.status_code, 200, response.content[:300])
        return pdf.call_args[0][0]

    def test_both_looks_fetch_nothing_and_run_no_script(self):
        for template in ('modern', 'default'):
            html = self.html(template)
            self.assertNotIn('<link', html, template)
            self.assertNotIn('@import', html, template)
            self.assertNotIn('<script', html, template)
            self.assertIsNone(re.search(r'url\(\s*[\'"]?(https?:|//|file:)', html), template)
            for src in re.findall(r'src="([^"]*)"', html):
                self.assertTrue(src.startswith('data:image/svg+xml;base64,'), (template, src[:80]))

    def test_scanned_and_configured_text_is_escaped(self):
        for template in ('modern', 'default'):
            html = self.html(template)
            self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
            self.assertIn('Finding &lt;0&gt;', html)
            self.assertIn('Acme &lt;Audit&gt;', html)
            self.assertNotIn('display: none', re.sub(r'<[^>]+>', '', html.split('</style>')[0]))  # the footer text is not in the CSS
            self.assertIn('Scan of clean.test', html)

    def test_a_full_report_has_every_section_and_the_flags_remove_them(self):
        full = self.html()
        for text in ('h0.clean.test', 'h3.clean.test', '198.51.100.2', 'Finding &lt;3&gt;', 'upgrade', 'https://h1.clean.test/p?q=1'):
            self.assertIn(text, full)
        recon = self.html(report_type='recon')
        self.assertIn('198.51.100.2', recon)
        self.assertNotIn('upgrade', recon)  # no finding cards
        vuln = self.html(report_type='vulnerability')
        self.assertIn('upgrade', vuln)
        self.assertNotIn('198.51.100.2', vuln)  # no address table
        no_info = self.html(ignore_info_vuln='1')
        self.assertNotIn('Finding &lt;2&gt;', no_info)  # the informational finding is left out

    def test_the_html_renders_to_a_pdf_with_only_the_two_charts_as_resources(self):
        html = self.html()
        sub_chart = charts.generate_subdomain_chart_by_http_status(Subdomain.objects.filter(scan_history=self.scan))
        vuln_chart = charts.generate_vulnerability_chart_by_severity(Vulnerability.objects.filter(scan_history=self.scan))
        self.assertTrue(render_report_pdf(html, (sub_chart, vuln_chart)).startswith(b'%PDF'))


class ChartTests(TestCase):
    def svg(self, b64):
        self.assertNotIn('\n', b64)
        text = base64.b64decode(b64, validate=True).decode('utf-8')
        self.assertTrue(text.startswith('<svg'), text[:40])
        self.assertIn('xmlns="http://www.w3.org/2000/svg"', text)
        self.assertIn('viewBox', text)
        for banned in ('<image', 'href', 'url(', '<script', '<foreignObject'):
            self.assertNotIn(banned, text)
        return text

    def test_counts_by_status_and_severity_with_labels_and_shares(self):
        now = timezone.now()
        project = Project.objects.create(name='Ch', slug='chart-rep', insert_date=now, org=Org.objects.create(name='Ch', slug='chart-org'))
        domain = Domain.objects.create(name='chart.test', project=project, insert_date=now)
        user = User.objects.create_user('chart-user')
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='c', yaml_configuration='x'),
                                          start_scan_date=now, initiated_by=user, results_dir='/tmp')
        for i, status in enumerate((200, 200, 200, 404, 0)):
            sub = Subdomain.objects.create(name=f'c{i}.chart.test', target_domain=domain, scan_history=scan, http_status=status)
            Vulnerability.objects.create(name='v', severity=(4 if i < 2 else 1), subdomain=sub, target_domain=domain, scan_history=scan,
                                         http_url='https://x.test/', discovered_date=now)
        status_svg = self.svg(charts.generate_subdomain_chart_by_http_status(Subdomain.objects.filter(scan_history=scan)))
        self.assertIn('200', status_svg)
        self.assertIn('404', status_svg)
        self.assertRegex(status_svg, r'\b3 \(75(\.0)?%\)')  # three of the four hosts with a status (0 is left out)
        sev_svg = self.svg(charts.generate_vulnerability_chart_by_severity(Vulnerability.objects.filter(scan_history=scan)))
        self.assertIn('Critical', sev_svg)
        self.assertIn('Low', sev_svg)
        self.assertLess(sev_svg.index('Critical'), sev_svg.index('Low'))

    def test_no_data_and_a_single_segment_are_valid_svg(self):
        self.assertIn('No data', self.svg(charts.generate_subdomain_chart_by_http_status(Subdomain.objects.none())))
        self.assertIn('No data', self.svg(charts.generate_vulnerability_chart_by_severity(Vulnerability.objects.none())))

    def test_only_the_two_chart_builders_are_exported(self):
        self.assertEqual(sorted(charts.__all__), ['generate_subdomain_chart_by_http_status', 'generate_vulnerability_chart_by_severity'])
