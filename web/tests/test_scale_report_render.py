"""The PDF of a big project must not cost tens of seconds because of how the page is laid out.

WeasyPrint lays a ``display: grid`` box out by measuring the min and max content of every cell, and ``overflow-wrap: anywhere`` on the whole
body makes it count every possible break in every min-content width: with ~3000 key/value lists in a 500-host report those two were over
half of a 40 s render (scripts/scale, SCALE-REPORT.md). The template keeps them out of the repeated parts, and a report of a few hundred findings renders
in seconds (a sanity bound; the two structural tests are the guard)."""
import os
import re
import tempfile
import time

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import report_data, report_pdf
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from scanEngine.models import EngineType
from targetApp.models import Domain

TEMPLATE = os.path.join(os.path.dirname(report_pdf.__file__), 'templates', 'cveFeed', 'report.html')


def stylesheet():
    return re.sub(r'/\*.*?\*/', '', open(TEMPLATE, encoding='utf-8').read().split('</style>')[0], flags=re.S)


class TemplateLayoutTests(SimpleTestCase):
    def test_repeated_blocks_do_not_use_grid_layout(self):
        css = stylesheet()
        self.assertNotRegex(css, r'display:\s*grid', 'a grid is measured cell by cell: use floats or a table for the key/value lists')

    def test_anywhere_wrapping_is_only_on_table_cells(self):
        css = stylesheet()
        for rule in re.findall(r'([^{}]+)\{([^{}]*overflow-wrap:\s*anywhere[^{}]*)\}', css):
            self.assertRegex(rule[0], r'^\s*(table\.grid t[dh]|\.cover td)', rule[0])


class RenderTimeTests(TestCase):
    FINDINGS = 120

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        project = Project.objects.create(name='R', slug='rr', insert_date=now, org=Org.objects.create(name='R', slug='rr-org'))
        domain = Domain.objects.create(name='rr.example.test', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='rr'), start_scan_date=now, scan_status=2)
        for i in range(cls.FINDINGS):
            sub = Subdomain.objects.create(name=f'h{i}.rr.example.test', target_domain=domain, scan_history=scan, http_status=200)
            ip = IpAddress.objects.create(address=f'192.0.2.{i % 250 + 1}')
            ip.ports.add(Port.objects.create(number=8000 + i, service_name='http', state='open'))
            sub.ip_addresses.add(ip)
            Vulnerability.objects.create(name=f'Finding {i}', severity=3, subdomain=sub, target_domain=domain, scan_history=scan, open_status=True,
                                         http_url=f'https://h{i}.rr.example.test/a', discovered_date=now, description='x ' * 150, impact='y ' * 100)
        cls.project = project

    def test_a_report_of_many_findings_renders_in_seconds(self):
        html = report_pdf.build_html(report_data.collect(self.project))
        self.assertGreater(html.count('class="finding'), 50)
        with tempfile.TemporaryDirectory() as d:
            start = time.monotonic()
            report_pdf.render_pdf(html, os.path.join(d, 'r.pdf'), timeout=120)
            took = time.monotonic() - start
        self.assertLess(took, 30, f'{took:.1f} s for {self.FINDINGS} findings')
