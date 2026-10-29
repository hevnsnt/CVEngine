"""PDF reports: what the PDF says, that hostile scanned text stays inert, that nothing is fetched or leaked across tenants, who may ask
for and read a report, its expiry and cleanup, and the caps. The PDFs are real (WeasyPrint in its child process) and their text is
read back with pypdf; the HTTP server below is a real local listener that must never see a request."""
import io
import json
import os
import re
import shutil
import tempfile
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone
from pypdf import PdfReader

from agentapi import rest
from agentapi.auth import create_token
from agentapi.services import ApiError, Ctx
from cveFeed import maintenance, report_data, report_export, report_pdf
from cveFeed.models import (CVEEntry, CVEMatch, HygieneFinding, ReportExport, ServiceRun, Triage, TriageVerdict)
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType, VulnerabilityReportSetting
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, rpc, tool_call
from tests.test_tenancy import client_for

NOW = timezone.now()
FAKE_TASK = mock.Mock(id='celery-report-1')


class Sink(BaseHTTPRequestHandler):
    """Records every request: a report that fetches a URL from scanned text would show up here."""
    seen = []

    def do_GET(self):
        Sink.seen.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'x')

    def log_message(self, *args):
        pass


def pdf_text(source):
    """The text of a PDF (path or bytes), whitespace folded so a wrapped line compares equal to the string that was printed."""
    reader = PdfReader(source if isinstance(source, str) else io.BytesIO(source))
    return ' '.join(' '.join(page.extract_text().split()) for page in reader.pages)


def read_pdf(path):
    with open(path, 'rb') as fh:
        return fh.read()


def queued(user, slug, host=None, include_closed=False, run=True):
    """Ask for a report the way the API does (the broker call is replaced, since there is no worker here), then run the task body as the
    worker would. Returns the finished ReportExport row."""
    with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
        job, _ = report_export.enqueue(Ctx(user=user), slug, host=host, include_closed=include_closed)
    if run:
        report_export.execute(job.pk, celery_id='test')
        job.refresh_from_db()
    return job


class ReportBase(TestCase):
    keep_files = False  # a class that makes its reports once, in setUpClass, keeps them between tests

    def setUp(self):
        if not self.keep_files:
            for name in os.listdir(self.reports_dir):
                os.unlink(os.path.join(self.reports_dir, name))

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Sink)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.reports_dir = tempfile.mkdtemp(prefix='cvengine-reports-')
        cls.env = mock.patch.dict(os.environ, {'CVENGINE_REPORT_DIR': cls.reports_dir})
        cls.env.start()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.env.stop()
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.reports_dir, ignore_errors=True)

    @classmethod
    def setUpTestData(cls):
        Sink.seen.clear()
        cls.hostile_banner = f'SSH-2.0-evil <img src="file:///etc/passwd"> <img src="http://127.0.0.1:{cls.port}/banner">'
        cls.hostile_title = f'<script>alert(1)</script><link rel="stylesheet" href="http://127.0.0.1:{cls.port}/css">'
        org_a, org_b = Org.objects.create(name='Acme Org', slug='acme-org'), Org.objects.create(name='Other Org', slug='other-org')
        cls.pa = Project.objects.create(name='Acme Exposure', slug='acme', insert_date=NOW, org=org_a)
        cls.pb = Project.objects.create(name='Other Co', slug='other', insert_date=NOW, org=org_b)
        mk = lambda n, **kw: User.objects.create_user(n, password='x', **kw)
        cls.admin, cls.worker, cls.auditor = mk('root', is_superuser=True), mk('worker'), mk('auditor')
        cls.outsider, cls.assignee = mk('outsider'), mk('dana', first_name='Dana', last_name='Ops')
        ProjectMembership.objects.create(user=cls.worker, project=cls.pa, role='user')
        ProjectMembership.objects.create(user=cls.auditor, project=cls.pa, role='audit')
        ProjectMembership.objects.create(user=cls.assignee, project=cls.pa, role='user')
        OrgMembership.objects.create(user=cls.outsider, org=org_b, role='admin')
        engine = EngineType.objects.create(engine_name='fast', yaml_configuration='x')
        cls.da = Domain.objects.create(name='acme.test', project=cls.pa, insert_date=NOW)
        cls.db = Domain.objects.create(name='other.test', project=cls.pb, insert_date=NOW)
        cls.scan_a = ScanHistory.objects.create(domain=cls.da, scan_type=engine, scan_status=2, start_scan_date=NOW - timedelta(days=2), tasks=[])
        cls.scan_b = ScanHistory.objects.create(domain=cls.db, scan_type=engine, scan_status=2, start_scan_date=NOW - timedelta(days=1), tasks=[])

        def host(domain, scan, name, score, address, ports):
            sub = Subdomain.objects.create(target_domain=domain, scan_history=scan, name=name, score=score,
                                           score_detail=[{'label': 'Fire CVE match', 'points': score}] if score else [])
            ip = IpAddress.objects.create(address=address)
            sub.ip_addresses.add(ip)
            for number, service, product, version, banner in ports:
                ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, version=version, banner=banner))
            return sub
        cls.www = host(cls.da, cls.scan_a, 'www.acme.test', 80, '203.0.113.5',
                       [(443, 'https', 'nginx', '1.18.0', cls.hostile_banner), (22, 'ssh', 'OpenSSH', '8.9', 'SSH-2.0-OpenSSH_8.9')])
        cls.quiet = host(cls.da, cls.scan_a, 'quiet.acme.test', 5, '203.0.113.6', [(80, 'http', 'apache', '2.4.57', '')])
        # the same host name in another tenant: a report of one must never pick up the other
        cls.twin = host(cls.db, cls.scan_b, 'www.acme.test', 99, '198.51.100.7', [(8443, 'https', 'tomcat', '9.0', 'TWIN-BANNER')])
        cls.other = host(cls.db, cls.scan_b, 'app.other.test', 70, '198.51.100.8', [(443, 'https', 'nginx', '1.0', '')])

        fire = CVEEntry.objects.create(cve_id='CVE-2099-1001', kev=True, cvss=9.8, title='nginx request smuggling', published_at=NOW,
                                       summary='Smuggling through chunked bodies.',
                                       affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
        smoke = CVEEntry.objects.create(cve_id='CVE-2099-1002', cvss=7.5, title='OpenSSH oddity', published_at=NOW, affected=[])
        cls.fire_match = CVEMatch.objects.create(cve_entry=fire, subdomain=cls.www, matched_product='nginx', matched_version='1.18.0', version_in_range=True,
                                                 confidence=.9, source='port', template_result='vulnerable', template_id='nginx-smuggle',
                                                 template_tested_at=NOW, remediation_status='in_progress', remediation_note='Waiting for the 1.20 package. Ticket OPS-4821.',
                                                 remediation_updated_at=NOW, remediation_by=cls.worker, assignee=cls.assignee)
        cls.verdict = TriageVerdict.objects.create(kind='cve_match', signature='s' * 40, classification='confirmed', reason='reproduced',
                                                   impact='An attacker can smuggle requests past the front proxy.',
                                                   remediation='Upgrade nginx to 1.20.0 or later and reload the service.')
        cls.proof_cmd = 'nuclei -u https://www.acme.test -t nginx-smuggle.yaml -jsonl'
        Triage.objects.create(project=cls.pa, domain=cls.da, host=cls.www.name, kind='cve_match', match=cls.fire_match, verdict=cls.verdict,
                              status='triaged', classification='confirmed', validation_status='hit',
                              validation_steps=[{'kind': 'nuclei_template', 'label': 'Template nginx-smuggle', 'display': cls.proof_cmd,
                                                 'target': 'www.acme.test:443', 'ran_at': NOW.isoformat(), 'result': 'hit', 'summary': 'template matched',
                                                 'output_excerpt': '', 'error': ''}])
        cls.smoke_match = CVEMatch.objects.create(cve_entry=smoke, subdomain=cls.www, matched_product='OpenSSH', matched_version='8.9', version_in_range=True,
                                                  confidence=.6, source='port')
        cls.fixed_match = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-1003', cvss=9.1, title='old fixed one', published_at=NOW, affected=[]),
                                                  subdomain=cls.quiet, matched_product='apache', matched_version='2.4.57', confidence=.8,
                                                  remediation_status='fixed', remediation_updated_at=NOW)
        cls.accepted_match = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-1004', cvss=7.2, title='accepted one', published_at=NOW, affected=[]),
                                                     subdomain=cls.quiet, matched_product='apache', matched_version='2.4.57', confidence=.8,
                                                     remediation_status='accepted_risk', remediation_note='Internal tool, accepted by the CISO.')
        cls.ruled_out = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-1005', cvss=9.9, title='ruled out by AI', published_at=NOW, affected=[]),
                                                subdomain=cls.www, matched_product='nginx', matched_version='1.18.0', confidence=.8, ai_verdict='not_affected')
        cls.vuln = Vulnerability.objects.create(
            subdomain=cls.www, target_domain=cls.da, scan_history=cls.scan_a, name=f'Exposed admin panel {cls.hostile_title}', severity=4, source='nuclei',
            template_id='admin-panel', matcher_name='status', http_url='https://www.acme.test/admin', discovered_date=NOW,
            description='The admin panel answers without a login.', remediation='Restrict /admin to the office network.',
            curl_command="curl -sk 'https://www.acme.test/admin'", extracted_results=['Admin Console v3'], remediation_status='open')
        cls.false_positive = Vulnerability.objects.create(subdomain=cls.www, target_domain=cls.da, scan_history=cls.scan_a, name='Noise finding',
                                                          severity=3, source='nuclei', http_url='https://www.acme.test/x', discovered_date=NOW)
        Triage.objects.create(project=cls.pa, domain=cls.da, host=cls.www.name, kind='nuclei', vulnerability=cls.false_positive,
                              status='triaged', classification='likely_false_positive')
        HygieneFinding.objects.create(domain=cls.da, host='www.acme.test', check_name='tls_expired', severity=3, title='Certificate for www.acme.test:443 expired',
                                      detail='Renew the certificate.', evidence={'not_after': '2026-01-01'})
        HygieneFinding.objects.create(domain=cls.da, host='acme.test', check_name='spf_missing', severity=2, title='No SPF record',
                                      detail='Anyone can send mail as this domain.')
        HygieneFinding.objects.create(domain=cls.da, host='acme.test', check_name='dmarc_none', severity=2, title='DMARC policy is p=none',
                                      detail='Monitoring only.', remediation_status='accepted_risk', remediation_note='Mail moves next quarter.')
        # the other tenant's findings: unmistakable markers
        cve_b = CVEEntry.objects.create(cve_id='CVE-2099-9999', kev=True, cvss=10.0, title='OTHERTENANT-CVE', published_at=NOW, affected=[])
        CVEMatch.objects.create(cve_entry=cve_b, subdomain=cls.twin, matched_product='tomcat', matched_version='9.0', confidence=.9,
                                remediation_note='OTHERTENANT-NOTE')
        Vulnerability.objects.create(subdomain=cls.other, target_domain=cls.db, scan_history=cls.scan_b, name='OTHERTENANT-VULN', severity=4, source='nuclei',
                                     http_url='https://app.other.test/', discovered_date=NOW)
        HygieneFinding.objects.create(domain=cls.db, host='app.other.test', check_name='tls_expired', severity=3, title='OTHERTENANT-TLS')
        ServiceRun.objects.create(service='nuclei:cve', asset='www.acme.test', project=cls.pa, finished_at=NOW - timedelta(hours=3))
        ServiceRun.objects.create(service='nmap-fast', asset='203.0.113.5', project=None, finished_at=NOW - timedelta(days=1))
        ServiceRun.objects.create(service='bbot', asset='other.test', project=cls.pb, finished_at=NOW)
        VulnerabilityReportSetting.objects.create(company_name='Blue Ridge Security', primary_color='#0F766E', show_footer=True, footer_text='Confidential')


class ReportContentTests(ReportBase):
    """The PDF itself: one project report, one with closed findings, one host report, generated once and read many times."""
    keep_files = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.project_job = queued(cls.worker, 'acme')
        cls.closed_job = queued(cls.worker, 'acme', include_closed=True)
        cls.host_job = queued(cls.worker, 'acme', host='www.acme.test')
        cls.text = pdf_text(os.path.join(cls.reports_dir, cls.project_job.filename))
        cls.closed_text = pdf_text(os.path.join(cls.reports_dir, cls.closed_job.filename))
        cls.host_text = pdf_text(os.path.join(cls.reports_dir, cls.host_job.filename))

    def test_a_valid_pdf_is_produced(self):
        self.assertEqual(self.project_job.status, 'done', self.project_job.error)
        data = read_pdf(os.path.join(self.reports_dir, self.project_job.filename))
        self.assertTrue(data.startswith(b'%PDF-'))
        self.assertTrue(data.rstrip().endswith(b'%%EOF'))
        self.assertEqual(self.project_job.size_bytes, len(data))
        self.assertGreater(len(PdfReader(io.BytesIO(data)).pages), 5)
        self.assertEqual(oct(os.stat(os.path.join(self.reports_dir, self.project_job.filename)).st_mode & 0o777), '0o600')
        self.assertTrue(re.fullmatch(r'[0-9a-f]{48}\.pdf', self.project_job.filename))

    def test_cover_names_the_project_the_date_and_the_scope(self):
        for text in ('Security exposure report', 'Acme Exposure', 'Acme Org', f'{NOW:%Y-%m-%d}', 'blue ridge security',
                     '1 target, 2 hosts in the current inventory', 'acme.test', 'Open findings only', f'{(NOW - timedelta(days=2)):%Y-%m-%d}'):
            self.assertIn(text.lower(), self.text.lower())  # the cover sets some of it in capitals

    def test_executive_summary_counts_by_heat_and_severity_and_lists_top_risks(self):
        summary = self.text[self.text.index('Executive summary'):self.text.index('Hosts Highest score first')]
        # open and not ruled out: the KEV match (fire), the critical scanner finding (fire), the 7.5 match (smoke)
        self.assertIn('This report lists 3 open findings across 2 hosts: 2 fire, 1 smoke and 0 ice', summary)
        self.assertIn('A further 2 TLS, certificate or email hygiene findings are listed separately', summary)
        for severity in ('Critical 2', 'High 1', 'Medium 0', 'Low 0'):  # the bars: one critical match, one critical finding, one 7.5 match
            self.assertIn(severity, summary)
        top = summary[summary.index('Top risks'):]
        self.assertLess(top.index('CVE-2099-1001'), top.index('CVE-2099-1002'))  # hottest first
        self.assertIn('Exposed admin panel', top)
        self.assertIn('1 candidate finding that the AI triage classed as a likely false positive', summary)

    def test_host_table_has_score_and_exposure(self):
        table = self.text[self.text.index('Hosts Highest score first'):self.text.index('Findings CVE matches')]
        self.assertIn('www.acme.test', table)
        self.assertIn('80', table)
        self.assertIn('22/tcp, 443/tcp', table)
        self.assertLess(table.index('www.acme.test'), table.index('quiet.acme.test'))  # by score
        self.assertNotIn('app.other.test', table)

    def test_each_finding_has_its_evidence_remediation_and_tracking(self):
        findings = self.text[self.text.index('Findings CVE matches'):self.text.index('Hygiene: TLS')]
        self.assertIn('CVE-2099-1001 in nginx 1.18.0', findings)
        self.assertIn('CVSS 9.8', findings)
        self.assertIn('listed as exploited (CISA KEV)', findings)
        self.assertIn('Confirmed: a check on the host reproduced it', findings)
        self.assertIn(self.proof_cmd, findings)  # the exact command that proved it
        self.assertIn('Template nginx-smuggle', findings)
        self.assertIn('Fixed in 1.20.0', findings)
        self.assertIn('Upgrade nginx to 1.20.0 or later and reload the service.', findings)
        self.assertIn('An attacker can smuggle requests past the front proxy.', findings)
        self.assertIn('In progress', findings)
        self.assertIn('Dana Ops', findings)  # the assignee
        self.assertIn('Waiting for the 1.20 package. Ticket OPS-4821.', findings)
        self.assertIn('by worker', findings)
        # a version-only match says so, and a scanner finding carries its own remediation and the request it sent
        self.assertIn('Version-based: the detected version is inside the advisory range; not reproduced', findings)
        self.assertIn('Restrict /admin to the office network.', findings)
        self.assertIn("curl -sk 'https://www.acme.test/admin'", findings)
        self.assertIn('Admin Console v3', findings)
        self.assertIn('Open', findings)

    def test_hygiene_findings_are_grouped_into_tls_and_email(self):
        hygiene = self.text[self.text.index('Hygiene: TLS'):self.text.index('Method and validity')]
        self.assertLess(hygiene.index('TLS and certificates'), hygiene.index('Certificate for www.acme.test:443 expired'))
        self.assertLess(hygiene.index('Certificate for www.acme.test:443 expired'), hygiene.index('Email'))
        self.assertIn('No SPF record', hygiene)

    def test_testssl_findings_belong_to_the_tls_section(self):
        # testssl names its checks tlsa_<test> (cveFeed.testssl_scan)
        for check in ('tlsa_sslv3', 'tlsa_null_ciphers', 'tls_weak_key', 'cert_expired'):
            self.assertEqual(report_data._hygiene_group(check), 'TLS and certificates', check)
        self.assertEqual(report_data._hygiene_group('dmarc_missing'), 'Email')
        self.assertEqual(report_data._hygiene_group('caa_missing'), 'Other configuration')

    def test_method_page_says_what_was_scanned_and_when_and_the_validity_caveats(self):
        method = self.text[self.text.index('Method and validity'):]
        self.assertIn('Completed scans 1', method)
        self.assertIn('nuclei template checks', method)
        self.assertIn('nmap service detection on the common ports', method)
        self.assertNotIn('bbot discovery', method)  # another project's run
        self.assertIn('Version-based findings', method)
        self.assertIn('backported patch', method)
        self.assertIn('Outside-in and unauthenticated', method)
        self.assertIn('Point in time', method)
        self.assertIn('Up to 500 hosts, 1000 detailed findings and 500 hygiene findings', method)
        self.assertIn('Nothing was left out of this report by those limits', method)

    def test_closed_findings_are_left_out_by_default_and_listed_on_request(self):
        for text in (self.text,):
            self.assertNotIn('CVE-2099-1003', text)
            self.assertNotIn('CVE-2099-1004', text)
            self.assertNotIn('Internal tool, accepted by the CISO.', text)
        self.assertIn('CVE-2099-1003', self.closed_text)
        self.assertIn('Fixed', self.closed_text)
        self.assertIn('CVE-2099-1004', self.closed_text)
        self.assertIn('Accepted risk', self.closed_text)
        self.assertIn('Internal tool, accepted by the CISO.', self.closed_text)
        self.assertIn('Open, fixed and accepted-risk findings', self.closed_text)
        self.assertIn('lists 5 findings', self.closed_text)
        self.assertIn('DMARC policy is p=none', self.closed_text)
        self.assertIn('Mail moves next quarter.', self.closed_text)
        self.assertNotIn('DMARC policy is p=none', self.text)

    def test_ruled_out_and_false_positive_findings_are_never_listed(self):
        for text in (self.text, self.closed_text):
            self.assertNotIn('CVE-2099-1005', text)
            self.assertNotIn('Noise finding', text)

    def test_host_report_is_about_that_host_only(self):
        self.assertEqual(self.host_job.status, 'done', self.host_job.error)
        self.assertIn('Host security report', self.host_text)
        self.assertIn('www.acme.test', self.host_text)
        self.assertIn('This report lists 3 open findings on this host', self.host_text)
        self.assertIn('Why the score is 80', self.host_text)
        self.assertIn('Fire CVE match', self.host_text)
        self.assertIn('OpenSSH 8.9', self.host_text)  # the services table
        self.assertIn('SSH-2.0-OpenSSH_8.9', self.host_text)
        self.assertIn('Certificate for www.acme.test:443 expired', self.host_text)
        self.assertNotIn('quiet.acme.test', self.host_text)
        self.assertNotIn('No SPF record', self.host_text)  # the domain's mail record belongs to acme.test, not this host

    def test_summary_is_recorded_on_the_row(self):
        self.assertEqual(self.project_job.summary['findings'], 3)
        self.assertEqual(self.project_job.summary['hosts'], 2)
        self.assertEqual(self.project_job.summary['omitted'], {'hosts_omitted': 0, 'findings_omitted': 0, 'hygiene_omitted': 0})


class TenantIsolationTests(ReportBase):
    MARKERS = ('OTHERTENANT', 'CVE-2099-9999', 'Other Co', 'Other Org', 'app.other.test', 'other.test', 'TWIN-BANNER', '198.51.100.7', 'tomcat')

    def assert_clean(self, text):
        for marker in self.MARKERS:
            self.assertNotIn(marker, text)

    def test_project_report_holds_nothing_of_another_tenant(self):
        for include_closed in (False, True):
            job = queued(self.worker, 'acme', include_closed=include_closed)
            self.assertEqual(job.status, 'done', job.error)
            self.assert_clean(pdf_text(os.path.join(self.reports_dir, job.filename)))

    def test_host_report_ignores_the_same_host_name_in_another_tenant(self):
        job = queued(self.worker, 'acme', host='www.acme.test')
        text = pdf_text(os.path.join(self.reports_dir, job.filename))
        self.assert_clean(text)
        self.assertIn('Why the score is 80', text)  # the Acme host (score 80), not the twin (99)
        self.assertNotIn('Why the score is 99', text)

    def test_an_app_admin_asking_for_one_project_still_gets_only_that_project(self):
        job = queued(self.admin, 'acme', include_closed=True)
        self.assert_clean(pdf_text(os.path.join(self.reports_dir, job.filename)))

    def test_the_data_stage_never_returns_a_row_of_another_project(self):
        data = report_data.collect(self.pa, include_closed=True)
        blob = json.dumps(data, default=str)
        self.assert_clean(blob)
        data = report_data.collect(self.pb, include_closed=True)
        self.assertIn('OTHERTENANT-CVE', json.dumps(data, default=str))  # the guard above is not vacuous
        self.assertNotIn('CVE-2099-1001', json.dumps(data, default=str))

    def test_a_host_of_another_project_is_not_found(self):
        with self.assertRaises(ApiError) as caught:
            queued(self.worker, 'acme', host='app.other.test', run=False)
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(LookupError):
            report_data.collect(self.pa, host='app.other.test')

    def test_another_tenants_user_cannot_see_the_project_or_its_report(self):
        job = queued(self.worker, 'acme')
        ctx = Ctx(user=self.outsider)
        for fn in (report_export.status, report_export.download):
            with self.assertRaises(ApiError) as caught:
                fn(ctx, 'acme', job.token)
            self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(ApiError) as caught:
            report_export.enqueue(ctx, 'acme')
        self.assertEqual(caught.exception.status, 404)

    def test_a_report_id_does_not_open_under_another_project_slug(self):
        job = queued(self.worker, 'acme')
        member_of_both = User.objects.create_user('both', password='x')
        ProjectMembership.objects.create(user=member_of_both, project=self.pa, role='user')
        ProjectMembership.objects.create(user=member_of_both, project=self.pb, role='user')
        with self.assertRaises(ApiError) as caught:
            report_export.status(Ctx(user=self.admin), 'other', job.token)
        self.assertEqual(caught.exception.status, 404)

    def test_only_the_user_who_asked_can_read_the_report(self):
        job = queued(self.worker, 'acme')
        for user in (self.auditor, self.admin, self.assignee):  # same project, even an App Admin: not theirs
            with self.assertRaises(ApiError) as caught:
                report_export.download(Ctx(user=user), 'acme', job.token)
            self.assertEqual(caught.exception.status, 404)
        self.assertEqual(report_export.download(Ctx(user=self.worker), 'acme', job.token).status_code, 200)


class PermissionTests(ReportBase):
    def test_every_role_that_can_read_the_project_may_export_it(self):
        for user in (self.worker, self.auditor, self.admin):
            job = queued(user, 'acme', run=False)
            self.assertEqual(job.status, 'queued')
            self.assertEqual(job.requested_by, user)
            self.assertEqual(job.celery_id, 'celery-report-1')

    def test_a_user_without_a_role_gets_404_and_nothing_is_queued(self):
        with self.assertRaises(ApiError) as caught:
            queued(self.outsider, 'acme', run=False)
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(ReportExport.objects.count(), 0)

    def test_the_all_projects_view_is_refused(self):
        with self.assertRaises(ApiError) as caught:
            queued(self.admin, '_all', run=False)
        self.assertEqual((caught.exception.status, caught.exception.message), (400, 'pick a project to make changes'))

    def test_bad_input_is_a_400(self):
        for kwargs in ({'host': '*.acme.test'}, {'host': 'a b'}, {'include_closed': 'yes'}, {'include_closed': None}):
            with self.assertRaises(ApiError) as caught:
                queued(self.worker, 'acme', run=False, **kwargs)
            self.assertEqual(caught.exception.status, 400, kwargs)

    def test_access_removed_before_the_task_runs_leaves_no_report(self):
        job = queued(self.worker, 'acme', run=False)
        ProjectMembership.objects.filter(user=self.worker).delete()
        result = report_export.execute(job.pk)
        job.refresh_from_db()
        self.assertEqual((result['status'], job.status), ('failed', 'failed'))
        self.assertEqual(job.error, 'you no longer have access to this project')
        self.assertEqual(os.listdir(self.reports_dir), [])

    def test_a_disabled_account_gets_nothing(self):
        job = queued(self.worker, 'acme', run=False)
        User.objects.filter(pk=self.worker.pk).update(is_active=False)
        report_export.execute(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertEqual(os.listdir(self.reports_dir), [])

    def test_the_host_vanishing_before_the_task_runs_fails_cleanly(self):
        job = queued(self.worker, 'acme', host='quiet.acme.test', run=False)
        Subdomain.objects.filter(name='quiet.acme.test').delete()
        report_export.execute(job.pk)
        job.refresh_from_db()
        self.assertEqual((job.status, job.error), ('failed', 'the host is no longer in the inventory'))

    def test_a_task_runs_once(self):
        job = queued(self.worker, 'acme', run=False)
        self.assertEqual(report_export.execute(job.pk)['status'], 'done')
        self.assertEqual(report_export.execute(job.pk)['status'], 'skipped')
        self.assertEqual(len(os.listdir(self.reports_dir)), 1)

    def test_asking_again_while_one_is_in_flight_gives_the_same_report(self):
        first = queued(self.worker, 'acme', run=False)
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK) as send:
            again, created = report_export.enqueue(Ctx(user=self.worker), 'acme')
        self.assertFalse(created)
        self.assertEqual(again.pk, first.pk)
        send.assert_not_called()
        other_options = queued(self.worker, 'acme', include_closed=True, run=False)
        self.assertNotEqual(other_options.pk, first.pk)

    def test_asking_for_a_report_is_recorded_in_the_audit_log(self):
        queued(self.auditor, 'acme', host='quiet.acme.test', include_closed=True, run=False)
        row = AuditLog.objects.get(action='report.export')
        self.assertEqual((row.actor, row.target, row.org_id), (self.auditor, 'acme', self.pa.org_id))
        self.assertEqual(row.detail, {'host': 'quiet.acme.test', 'include_closed': True})

    def test_making_a_report_also_removes_the_expired_ones(self):
        old = queued(self.worker, 'acme')
        ReportExport.objects.filter(pk=old.pk).update(expires_at=timezone.now() - timedelta(hours=2))
        queued(self.auditor, 'acme')
        self.assertFalse(ReportExport.objects.filter(pk=old.pk).exists())
        self.assertFalse(os.path.exists(os.path.join(self.reports_dir, old.filename)))

    def test_queue_caps_per_user_per_hour_and_overall(self):
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_ACTIVE_PER_USER': '2'}):
            queued(self.worker, 'acme', run=False)
            queued(self.worker, 'acme', include_closed=True, run=False)
            with self.assertRaises(ApiError) as caught:
                queued(self.worker, 'acme', host='quiet.acme.test', run=False)
            self.assertEqual(caught.exception.status, 429)
            queued(self.auditor, 'acme', run=False)  # another user's allowance is their own
        ReportExport.objects.all().delete()
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_PER_HOUR': '1'}):
            job = queued(self.worker, 'acme')
            self.assertEqual(job.status, 'done')
            with self.assertRaises(ApiError) as caught:
                queued(self.worker, 'acme', include_closed=True, run=False)
            self.assertEqual(caught.exception.status, 429)
        ReportExport.objects.all().delete()
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_ACTIVE_TOTAL': '1'}):
            queued(self.worker, 'acme', run=False)
            with self.assertRaises(ApiError) as caught:
                queued(self.auditor, 'acme', run=False)
            self.assertEqual(caught.exception.status, 429)

    def test_a_broker_failure_marks_the_report_failed_instead_of_waiting_for_ever(self):
        with mock.patch('cveFeed.tasks.generate_report.apply_async', side_effect=OSError('broker down')):
            job, _ = report_export.enqueue(Ctx(user=self.worker), 'acme')
        self.assertEqual(job.status, 'failed')
        self.assertIn('could not be queued', job.error)
        self.assertNotIn('broker down', job.error)

    def test_a_report_whose_worker_died_is_failed_when_polled(self):
        job = queued(self.worker, 'acme', run=False)
        ReportExport.objects.filter(pk=job.pk).update(created_at=timezone.now() - timedelta(hours=3), status='running')
        self.assertEqual(report_export.status(Ctx(user=self.worker), 'acme', job.token)['status'], 'failed')


class ApiTests(ReportBase):
    def setUp(self):
        _, self.token = create_token(self.worker, 'agent')
        _, self.ro_token = create_token(self.worker, 'reader', read_only=True)
        _, self.audit_token = create_token(self.auditor, 'auditor')
        _, self.out_token = create_token(self.outsider, 'outsider')
        self.send = mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK)
        self.send.start()
        self.addCleanup(self.send.stop)

    def get_pdf(self, token, path):
        return Client().get(path, HTTP_AUTHORIZATION=f'Bearer {token}')

    def test_ask_poll_run_download_over_rest(self):
        status, body = call(self.token, 'POST', '/api/v1/projects/acme/reports', {'host': 'www.acme.test'})
        self.assertEqual(status, 202, body)
        self.assertEqual(body['status'], 'queued')
        self.assertEqual(body['host'], 'www.acme.test')
        self.assertIsNone(body['download_url'])
        self.assertEqual(body['status_url'], f"/api/v1/projects/acme/reports/{body['id']}")
        self.assertEqual(self.get_pdf(self.token, body['status_url'] + '/download').status_code, 409)  # not ready yet
        report_export.execute(ReportExport.objects.get(token=body['id']).pk)
        status, body = call(self.token, 'GET', body['status_url'])
        self.assertEqual((status, body['status']), (200, 'done'), body)
        self.assertGreater(body['size_bytes'], 1000)
        self.assertEqual(body['summary']['findings'], 3)
        response = self.get_pdf(self.token, body['download_url'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment; filename="cvengine-report-acme-www.acme.test-', response['Content-Disposition'])
        self.assertEqual(response['Cache-Control'], 'private, no-store')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        content = b''.join(response.streaming_content)
        self.assertTrue(content.startswith(b'%PDF-'))
        self.assertIn('www.acme.test', pdf_text(content))

    def test_a_read_only_token_may_ask_for_a_report_and_read_it(self):
        status, body = call(self.ro_token, 'POST', '/api/v1/projects/acme/reports', {})
        self.assertEqual(status, 202, body)
        report_export.execute(ReportExport.objects.get(token=body['id']).pk)
        self.assertEqual(self.get_pdf(self.ro_token, body['status_url'] + '/download').status_code, 200)
        self.assertEqual(call(self.ro_token, 'POST', '/api/v1/projects/acme/targets', {'value': 'x.acme.test'})[0], 403)  # still read only

    def test_an_audit_user_can_export_and_download(self):
        status, body = call(self.audit_token, 'POST', '/api/v1/projects/acme/reports', {})
        self.assertEqual(status, 202, body)
        report_export.execute(ReportExport.objects.get(token=body['id']).pk)
        self.assertEqual(self.get_pdf(self.audit_token, body['status_url'] + '/download').status_code, 200)

    def test_asking_twice_answers_200_with_the_same_id(self):
        _, first = call(self.token, 'POST', '/api/v1/projects/acme/reports', {})
        status, second = call(self.token, 'POST', '/api/v1/projects/acme/reports', {})
        self.assertEqual((status, second['id']), (200, first['id']))

    def test_other_tenants_and_other_users_get_404(self):
        _, body = call(self.token, 'POST', '/api/v1/projects/acme/reports', {})
        report_export.execute(ReportExport.objects.get(token=body['id']).pk)
        self.assertEqual(call(self.out_token, 'POST', '/api/v1/projects/acme/reports', {})[0], 404)
        self.assertEqual(call(self.out_token, 'GET', body['status_url'])[0], 404)
        self.assertEqual(self.get_pdf(self.out_token, body['status_url'] + '/download').status_code, 404)
        self.assertEqual(self.get_pdf(self.audit_token, body['status_url'] + '/download').status_code, 404)  # same project, not theirs
        self.assertEqual(call(self.token, 'GET', '/api/v1/projects/other/reports/' + body['id'])[0], 404)  # not a project of theirs
        self.assertEqual(call(self.token, 'GET', '/api/v1/projects/acme/reports/' + 'x' * 43)[0], 404)

    def test_authentication_is_required_everywhere(self):
        _, body = call(self.token, 'POST', '/api/v1/projects/acme/reports', {})
        for method, path in (('POST', '/api/v1/projects/acme/reports'), ('GET', body['status_url']), ('GET', body['status_url'] + '/download')):
            self.assertEqual(call(None, method, path, {} if method == 'POST' else None)[0], 401)

    def test_a_signed_in_session_can_download_what_it_asked_for(self):
        client = client_for(self.worker)
        job = queued(self.worker, 'acme')
        response = client.get(f'/api/v1/projects/acme/reports/{job.token}/download')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client_for(self.outsider).get(f'/api/v1/projects/acme/reports/{job.token}/download').status_code, 404)

    def test_the_all_view_and_bad_bodies(self):
        self.assertEqual(call(self.token, 'POST', '/api/v1/projects/_all/reports', {})[0], 400)
        self.assertEqual(call(self.token, 'POST', '/api/v1/projects/acme/reports', {'include_closed': 'yes'})[0], 400)
        self.assertEqual(call(self.token, 'POST', '/api/v1/projects/acme/reports', {'host': 'nope.acme.test'})[0], 404)
        self.assertEqual(call(self.token, 'GET', '/api/v1/projects/_all/reports/abc')[0], 400)

    def test_the_routes_are_in_the_openapi_spec(self):
        paths = rest.openapi_spec()['paths']
        self.assertIn('post', paths['/api/v1/projects/{slug}/reports'])
        self.assertIn('get', paths['/api/v1/projects/{slug}/reports/{token}/download'])

    def test_mcp_tools_queue_and_report_status(self):
        listing = rpc(self.token, 'tools/list')[1]['result']['tools']
        by_name = {t['name']: t for t in listing}
        self.assertTrue(by_name['export_report']['annotations']['readOnlyHint'])
        self.assertIn('get_report', by_name)
        error, queued_report = tool_call(self.token, 'export_report', {'project': 'acme', 'include_closed': True})
        self.assertFalse(error)
        self.assertEqual((queued_report['status'], queued_report['include_closed']), ('queued', True))
        report_export.execute(ReportExport.objects.get(token=queued_report['id']).pk)
        error, state = tool_call(self.token, 'get_report', {'project': 'acme', 'report_id': queued_report['id']})
        self.assertEqual((error, state['status']), (False, 'done'))
        self.assertTrue(state['download_url'].endswith('/download'))
        self.assertTrue(tool_call(self.out_token, 'get_report', {'project': 'acme', 'report_id': queued_report['id']})[0])
        self.assertTrue(tool_call(self.out_token, 'export_report', {'project': 'acme'})[0])
        self.assertFalse(tool_call(self.ro_token, 'export_report', {'project': 'acme', 'host': 'quiet.acme.test'})[0])


class ExpiryAndCleanupTests(ReportBase):
    def test_an_expired_report_is_refused_and_its_file_removed(self):
        job = queued(self.worker, 'acme')
        path = os.path.join(self.reports_dir, job.filename)
        self.assertTrue(os.path.exists(path))
        ctx = Ctx(user=self.worker)
        self.assertEqual(report_export.status(ctx, 'acme', job.token)['status'], 'done')
        ReportExport.objects.filter(pk=job.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
        with self.assertRaises(ApiError) as caught:
            report_export.download(ctx, 'acme', job.token)
        self.assertEqual(caught.exception.status, 410)
        self.assertFalse(os.path.exists(path))
        state = report_export.status(ctx, 'acme', job.token)
        self.assertEqual((state['status'], state['download_url']), ('expired', None))

    def test_the_lifetime_is_24_hours_and_configurable(self):
        job = queued(self.worker, 'acme')
        self.assertAlmostEqual((job.expires_at - job.finished_at).total_seconds(), 24 * 3600, delta=5)
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_TTL_HOURS': '2'}):
            self.assertEqual(report_export.ttl(), timedelta(hours=2))
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_TTL_HOURS': '99999'}):
            self.assertEqual(report_export.ttl(), timedelta(hours=report_export.TTL_HOURS_CEILING))

    def test_pruning_removes_expired_rows_files_and_stray_files_only(self):
        old, fresh = queued(self.worker, 'acme'), queued(self.auditor, 'acme')
        ReportExport.objects.filter(pk=old.pk).update(expires_at=timezone.now() - timedelta(hours=1))
        stray = os.path.join(self.reports_dir, 'f' * 48 + '.pdf')
        partial = os.path.join(self.reports_dir, 'a' * 48 + '.pdf.partial')
        young = os.path.join(self.reports_dir, 'e' * 48 + '.pdf')
        notes = os.path.join(self.reports_dir, 'README.txt')
        for path in (stray, partial, young, notes):
            open(path, 'wb').write(b'x')
        long_ago = (timezone.now() - timedelta(days=3)).timestamp()
        for path in (stray, partial, notes):
            os.utime(path, (long_ago, long_ago))
        result = report_export.prune_expired()
        self.assertEqual(result, {'reports': 1, 'stray_files': 2})
        self.assertFalse(ReportExport.objects.filter(pk=old.pk).exists())
        self.assertFalse(os.path.exists(os.path.join(self.reports_dir, old.filename)))
        self.assertTrue(os.path.exists(os.path.join(self.reports_dir, fresh.filename)))
        self.assertTrue(os.path.exists(young))  # a file that is not old yet may belong to a report being written
        self.assertTrue(os.path.exists(notes))  # not a report file: never touched
        self.assertFalse(os.path.exists(stray) or os.path.exists(partial))

    def test_the_weekly_maintenance_runs_the_cleanup(self):
        job = queued(self.worker, 'acme')
        ReportExport.objects.filter(pk=job.pk).update(expires_at=timezone.now() - timedelta(hours=1))
        with tempfile.TemporaryDirectory() as logs, mock.patch.dict(os.environ, {'CVENGINE_LOG_ARCHIVE_DIR': logs}):
            result = maintenance.run()
        self.assertEqual(result['reports_removed'], {'reports': 1, 'stray_files': 0})
        self.assertFalse(os.path.exists(os.path.join(self.reports_dir, job.filename)))

    def test_a_generation_leaves_no_partial_file_and_a_file_name_cannot_escape_the_directory(self):
        job = queued(self.worker, 'acme')
        self.assertEqual([n for n in os.listdir(self.reports_dir) if n.endswith('.partial')], [])
        ReportExport.objects.filter(pk=job.pk).update(filename='../../../../etc/passwd')
        with self.assertRaises(ApiError) as caught:
            report_export.download(Ctx(user=self.worker), 'acme', job.token)
        self.assertEqual(caught.exception.status, 410)
        for name in ('/etc/passwd', 'x.pdf', '..', ''):
            self.assertIsNone(report_export._path(name))

    def test_a_failed_render_leaves_no_file_and_a_short_error(self):
        job = queued(self.worker, 'acme', run=False)
        with mock.patch('cveFeed.report_pdf.render_pdf', side_effect=report_pdf.RenderError('rendering took too long; narrow the report to one host')):
            report_export.execute(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertEqual(job.error, 'rendering took too long; narrow the report to one host')
        self.assertEqual(os.listdir(self.reports_dir), [])

    def test_an_unexpected_error_is_logged_and_not_shown(self):
        job = queued(self.worker, 'acme', run=False)
        with mock.patch('cveFeed.report_data.collect', side_effect=RuntimeError('/secret/path leaked')):
            with self.assertLogs('cveFeed.report_export', level='ERROR'):
                report_export.execute(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertNotIn('secret', job.error)


class CapTests(ReportBase):
    def test_alias_findings_count_in_the_host_and_project_rows(self):
        alias = Subdomain.objects.create(target_domain=self.da, scan_history=self.scan_a, name='www2.acme.test')
        alias.ip_addresses.add(self.www.ip_addresses.first())
        Vulnerability.objects.create(subdomain=alias, target_domain=self.da, scan_history=self.scan_a,
                                     name='Alias-only exposure', severity=3, source='nuclei', discovered_date=NOW)

        host_report = report_data.collect(self.pa, host='www.acme.test')
        project_report = report_data.collect(self.pa)
        self.assertEqual(host_report['summary']['findings'], 4)
        self.assertEqual(host_report['hosts'][0]['findings'], 5)  # four CVE or scanner findings and one hygiene finding
        self.assertIn('Alias-only exposure', [finding['title'] for finding in host_report['findings']])
        self.assertEqual(next(row['findings'] for row in project_report['hosts'] if row['host'] == 'www.acme.test'), 5)

    def extra_hosts(self, n):
        for i in range(n):
            sub = Subdomain.objects.create(target_domain=self.da, scan_history=self.scan_a, name=f'h{i:02d}.acme.test', score=50 - i)
            ip = IpAddress.objects.create(address=f'203.0.113.{100 + i}')
            sub.ip_addresses.add(ip)
            ip.ports.add(Port.objects.create(number=8000 + i, service_name='http'))

    def test_defaults_and_hard_ceilings(self):
        self.assertEqual(report_data.limits(), {'hosts': 500, 'findings': 1000, 'hygiene': 500})
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_MAX_HOSTS': '10 ** 9', 'CVENGINE_REPORT_MAX_FINDINGS': '999999', 'CVENGINE_REPORT_MAX_HYGIENE': '0'}):
            self.assertEqual(report_data.limits(), {'hosts': 500, 'findings': report_data.CEILING_FINDINGS, 'hygiene': 1})

    def test_the_host_table_is_capped_paginated_and_says_what_it_left_out(self):
        self.extra_hosts(7)
        with mock.patch.object(report_data, 'HOST_PAGE', 3), mock.patch.dict(os.environ, {'CVENGINE_REPORT_MAX_HOSTS': '8'}):
            data = report_data.collect(self.pa)
        self.assertEqual((data['scope']['hosts_total'], data['scope']['hosts_listed'], data['caps']['hosts_omitted']), (9, 8, 1))
        names = [h['host'] for h in data['hosts']]
        self.assertEqual(len(set(names)), 8)  # three pages of 3, 3 and 2, no host twice
        self.assertEqual(names[0], 'www.acme.test')
        self.assertEqual([h['score'] for h in data['hosts']], sorted((h['score'] for h in data['hosts']), reverse=True))

    def test_findings_beyond_the_cap_are_counted_but_not_detailed(self):
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_MAX_FINDINGS': '2', 'CVENGINE_REPORT_MAX_HYGIENE': '1'}):
            data = report_data.collect(self.pa)
            job = queued(self.worker, 'acme')
        self.assertEqual(len(data['findings']), 2)
        self.assertEqual(data['summary']['findings'], 3)  # the counts cover everything
        self.assertEqual(data['summary']['heat'], {'fire': 2, 'smoke': 1, 'ice': 0})
        self.assertEqual(data['caps']['findings_omitted'], 1)
        self.assertEqual(data['caps']['hygiene_omitted'], 1)
        self.assertEqual([f['heat'] for f in data['findings']], ['fire', 'fire'])  # hottest kept
        self.assertEqual(job.status, 'done', job.error)
        text = pdf_text(os.path.join(self.reports_dir, job.filename))
        self.assertIn('Showing the 2 hottest of 3', text)
        self.assertIn('Showing 1 of 2; the report limit is 1', text)
        self.assertEqual(job.summary['omitted']['findings_omitted'], 1)

    def test_a_big_project_still_renders(self):
        self.extra_hosts(60)
        for i in range(60):
            Vulnerability.objects.create(subdomain=self.www, target_domain=self.da, scan_history=self.scan_a, name=f'Bulk finding {i:02d}', severity=2,
                                         source='nuclei', http_url=f'https://www.acme.test/{i}', discovered_date=NOW)
        job = queued(self.worker, 'acme')
        self.assertEqual(job.status, 'done', job.error)
        text = pdf_text(os.path.join(self.reports_dir, job.filename))
        self.assertIn('Bulk finding 59', text)
        self.assertIn('h59.acme.test', text)
        self.assertIn('This report lists 63 open findings', text)


class UntrustedTextTests(ReportBase):
    """Banners, titles and finding text come from the hosts being scanned. They reach the PDF as text and nothing is fetched or read."""

    def setUp(self):
        Sink.seen.clear()

    def hostile_data(self):
        data = report_data.collect(self.pa, include_closed=True)
        return data

    def test_the_template_has_no_way_to_switch_escaping_off(self):
        path = os.path.join(os.path.dirname(report_pdf.__file__), 'templates', 'cveFeed', 'report.html')
        source = open(path).read()
        self.assertIsNone(re.search(r'\|\s*safe|safeseq|mark_safe|\{%\s*autoescape|\{%\s*load\s+(?!static)', source))
        self.assertNotRegex(source, r'(?i)<(img|iframe|object|embed|script|link|use)\b|url\(|@import|@font-face')

    def test_hostile_markup_is_escaped_in_the_html_stage(self):
        html = report_pdf.build_html(self.hostile_data())
        self.assertNotIn('<script', html)
        self.assertNotIn('<img', html)
        self.assertNotIn('<link', html)
        self.assertNotIn('file:///etc/passwd">', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertIn('&lt;link rel=&quot;stylesheet&quot;', html)
        self.assertIn('&lt;img src=&quot;file:///etc/passwd&quot;&gt;', report_pdf.build_html(report_data.collect(self.pa, host='www.acme.test')))

    def test_hostile_text_appears_in_the_pdf_as_text_and_nothing_is_fetched_or_read(self):
        job = queued(self.worker, 'acme', host='www.acme.test')
        self.assertEqual(job.status, 'done', job.error)
        text = pdf_text(os.path.join(self.reports_dir, job.filename))
        self.assertIn('<img src="file:///etc/passwd">', text)  # printed, not loaded
        self.assertIn('<script>alert(1)</script>', text)
        self.assertNotIn('root:x:0:0', text)
        self.assertEqual(Sink.seen, [])
        job = queued(self.worker, 'acme', include_closed=True)
        self.assertEqual(Sink.seen, [])

    def test_a_hostile_note_title_and_company_name_cannot_inject_html_or_css(self):
        evil = f'</style><img src="http://127.0.0.1:{self.port}/note"><style>'
        CVEMatch.objects.filter(pk=self.fire_match.pk).update(remediation_note=evil)
        VulnerabilityReportSetting.objects.update(company_name=evil, footer_text=evil, primary_color='red;}*{}')
        data = report_data.collect(self.pa)
        self.assertEqual(data['branding']['accent'], '#c2410c')  # not an #RRGGBB colour: the default
        html = report_pdf.build_html(data)
        self.assertNotIn('<img', html)
        self.assertNotIn('red;}', html)
        self.assertIn('&lt;/style&gt;&lt;img', html)
        job = queued(self.worker, 'acme')
        self.assertEqual(job.status, 'done', job.error)
        self.assertEqual(Sink.seen, [])

    def test_the_renderer_itself_refuses_every_resource(self):
        """Even if markup got past the template, the renderer would fetch nothing: raw HTML with every kind of reference goes through it."""
        hostile = (f'<html><head><link rel="stylesheet" href="http://127.0.0.1:{self.port}/a.css"><style>@import url("http://127.0.0.1:{self.port}/b.css");'
                   f'body{{background:url(http://127.0.0.1:{self.port}/c.png)}}@font-face{{font-family:x;src:url(file:///etc/passwd)}}</style></head><body>'
                   f'<p>visible text</p><img src="http://127.0.0.1:{self.port}/d.png"><img src="file:///etc/passwd">'
                   f'<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=">'
                   f'<object data="http://127.0.0.1:{self.port}/e"></object><iframe src="file:///etc/passwd"></iframe>'
                   f'<embed src="http://127.0.0.1:{self.port}/f"><svg xmlns="http://www.w3.org/2000/svg"><image href="http://127.0.0.1:{self.port}/g"/></svg>'
                   f'<a href="http://127.0.0.1:{self.port}/h">link</a></body></html>')
        out = os.path.join(self.reports_dir, 'raw.pdf')
        report_pdf.render_pdf(hostile, out)
        text = pdf_text(out)
        self.assertIn('visible text', text)
        self.assertNotIn('root:x:0:0', text)
        self.assertEqual(Sink.seen, [])

    def test_the_renderer_environment_carries_no_secrets(self):
        seen = {}
        real = report_pdf.subprocess.run

        def spy(cmd, **kwargs):
            seen.update(kwargs['env'])
            return real(cmd, **kwargs)
        with mock.patch.dict(os.environ, {'POSTGRES_PASSWORD': 'hunter2', 'CVENGINE_FIELD_KEY': 'secret-key', 'DJANGO_SECRET_KEY': 'k'}), \
                mock.patch.object(report_pdf.subprocess, 'run', side_effect=spy):
            report_pdf.render_pdf('<html><body>x</body></html>', os.path.join(self.reports_dir, 'env.pdf'))
        self.assertTrue(seen)
        self.assertEqual(set(seen) - set(report_pdf.CHILD_ENV), set())
        self.assertNotIn('hunter2', ' '.join(seen.values()))

    def test_a_render_that_takes_too_long_is_killed_and_leaves_no_file(self):
        out = os.path.join(self.reports_dir, 'slow.pdf')
        with self.assertRaises(report_pdf.RenderError) as caught:
            report_pdf.render_pdf('<html><body>x</body></html>', out, timeout=0.05)
        self.assertIn('too long', str(caught.exception))
        self.assertFalse(os.path.exists(out))

    def test_clean_strips_control_characters_and_clips(self):
        self.assertEqual(report_data.clean('a\x00b\x1b[31mred\x07‮ x'), 'ab[31mredx'.replace('‮', '‮'))
        self.assertEqual(report_data.clean('  many   spaces\r\nnext  line  '), 'many spaces\nnext line')
        self.assertEqual(report_data.clean('x' * 50, 10), 'x' * 9 + '…')
        self.assertEqual(report_data.clean(None), '')
        self.assertEqual(len(report_data.clean('A' * 100000, 300)), 300)

    def test_a_banner_of_one_unbroken_megabyte_is_clipped_and_still_renders(self):
        Port.objects.filter(number=22).update(banner='A' * 1_000_000)
        job = queued(self.worker, 'acme', host='www.acme.test')
        self.assertEqual(job.status, 'done', job.error)
        self.assertLess(job.size_bytes, 2_000_000)
