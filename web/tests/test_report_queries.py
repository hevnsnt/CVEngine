"""The scan report must not cost queries per host or per finding, and must not render unbounded rows."""
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan import views
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for


class ReportQueryTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.project = Project.objects.create(name='R', slug='rep', insert_date=self.now, org=Org.objects.create(name='R', slug='ro'))
        self.domain = Domain.objects.create(name='rep.test', project=self.project, insert_date=self.now)
        self.user = User.objects.create_superuser('rep-admin', 'rep@example.test', 'pw-12345-long')
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=self.now, initiated_by=self.user, results_dir='/tmp')
        self.hosts = 0

    def add_hosts(self, count):
        for _ in range(count):
            self.hosts += 1
            sub = Subdomain.objects.create(name=f'h{self.hosts}.rep.test', target_domain=self.domain, scan_history=self.scan, http_status=200)
            ip = IpAddress.objects.create(address=f'203.0.113.{self.hosts % 250}')
            ip.ports.add(Port.objects.create(number=443 + self.hosts, service_name='https', description='x', is_uncommon=False))
            sub.ip_addresses.add(ip)
            Vulnerability.objects.create(name=f'finding {self.hosts}', severity=3, subdomain=sub, target_domain=self.domain,
                                         scan_history=self.scan, http_url=f'https://h{self.hosts}.rep.test/a', discovered_date=self.now)

    def render(self, template):
        client = client_for(self.user)
        with mock.patch.object(views, 'render_report_pdf', return_value=b'%PDF') as pdf, CaptureQueriesContext(connection) as queries:
            response = client.get(f'/scan/create_report/{self.scan.id}', {'report_template': template, 'report_type': 'full'})
        self.assertEqual(response.status_code, 200, response.content[:300])
        return pdf.call_args[0][0], len(queries)

    def test_the_query_count_does_not_grow_with_hosts_or_findings(self):
        for template in ('modern', 'default'):
            self.add_hosts(3)
            _, few = self.render(template)
            self.add_hosts(12)
            html, many = self.render(template)
            self.assertLessEqual(many, few + 2, f'{template}: {few} queries for 3 hosts, {many} for 15')
            self.assertIn('finding 15', html)

    def test_a_scan_with_more_rows_than_the_cap_is_cut_and_says_so(self):
        self.add_hosts(7)
        with mock.patch.object(views, 'REPORT_MAX_HOSTS', 3), mock.patch.object(views, 'REPORT_MAX_FINDINGS', 4):
            html, _ = self.render('modern')
        self.assertIn('first 3 of 7 hosts', html)
        self.assertIn('first 4 of 7 findings', html)
        self.assertNotIn('h7.rep.test</span>', html.replace('\n', ''))  # past the cap, so no card for it

    def test_an_empty_executive_summary_or_company_name_is_a_report_not_a_500(self):
        from scanEngine.models import VulnerabilityReportSetting
        VulnerabilityReportSetting.objects.create(company_name=None, executive_summary_description=None)
        self.add_hosts(1)
        self.render('default')
