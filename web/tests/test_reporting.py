"""Reporting: reports of a project or of an organization, findings or hosts, as a PDF or a CSV file (cveFeed.report_export, report_csv, agentapi.report_scope),
the page and its navigation entry. Only the PDF layout step is replaced (``report_pdf.render_pdf`` writes a stub): what goes into a report is read from the
real report data, and tenancy is checked on the real rows."""
import csv
import io
import os
import shutil
import tempfile
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from agentapi import report_scope, services as svc
from agentapi.auth import create_token
from agentapi.services import ApiError, Ctx
from cveFeed import nav, report_csv, report_data, report_export, report_pdf
from cveFeed.models import AssetChange, CVEEntry, CVEMatch, HygieneFinding, ReportExport
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call
from tests.test_tenancy import client_for

NOW = timezone.now()
FAKE_TASK = mock.Mock(id='celery-reporting-1')


def stub_render(html, out_path, timeout=None):
    with open(out_path, 'wb') as fh:
        fh.write(b'%PDF-1.4 stub')
    return out_path


class ReportingBase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports_dir = tempfile.mkdtemp(prefix='cvengine-reporting-')
        cls.env = mock.patch.dict(os.environ, {'CVENGINE_REPORT_DIR': cls.reports_dir})
        cls.env.start()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.env.stop()
        shutil.rmtree(cls.reports_dir, ignore_errors=True)

    @classmethod
    def setUpTestData(cls):
        org_a, org_b = Org.objects.create(name='Acme Org', slug='acme-org'), Org.objects.create(name='Other Org', slug='other-org')
        cls.org_a, cls.org_b = org_a, org_b
        cls.web = Project.objects.create(name='Acme Web', slug='acme-web', insert_date=NOW, org=org_a)
        cls.api = Project.objects.create(name='Acme API', slug='acme-api', insert_date=NOW, org=org_a)
        cls.other = Project.objects.create(name='Other Co', slug='other-co', insert_date=NOW, org=org_b)
        cls.loose = Project.objects.create(name='Loose Project', slug='loose', insert_date=NOW)
        mk = lambda n, **kw: User.objects.create_user(n, password='x', email=f'{n}@example.test', **kw)
        cls.root, cls.org_admin, cls.org_member, cls.org_audit = mk('root', is_superuser=True), mk('orgadmin'), mk('orgmember'), mk('orgaudit')
        cls.web_user, cls.web_audit, cls.outsider = mk('webuser'), mk('webaudit'), mk('outsider')
        OrgMembership.objects.create(user=cls.org_admin, org=org_a, role='admin')
        OrgMembership.objects.create(user=cls.org_member, org=org_a, role='user')
        OrgMembership.objects.create(user=cls.org_audit, org=org_a, role='audit')
        ProjectMembership.objects.create(user=cls.web_user, project=cls.web, role='user')
        ProjectMembership.objects.create(user=cls.web_audit, project=cls.web, role='audit')
        OrgMembership.objects.create(user=cls.outsider, org=org_b, role='admin')
        engine = EngineType.objects.create(engine_name='fast', yaml_configuration='x')
        cls.domains, cls.scans = {}, {}
        for project in (cls.web, cls.api, cls.other):
            cls.domains[project.slug] = Domain.objects.create(name=f'{project.slug}.test', project=project, insert_date=NOW)
            cls.scans[project.slug] = ScanHistory.objects.create(domain=cls.domains[project.slug], scan_type=engine, scan_status=2,
                                                                 start_scan_date=NOW - timedelta(days=1), tasks=[])

        def host(project, name, score, address, ports):
            sub = Subdomain.objects.create(target_domain=cls.domains[project.slug], scan_history=cls.scans[project.slug], name=name, score=score,
                                           score_detail=[{'label': 'Fire CVE match', 'points': score}] if score else [])
            ip = IpAddress.objects.create(address=address)
            sub.ip_addresses.add(ip)
            for number, service, product, version in ports:
                ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, version=version))
            return sub
        cls.www = host(cls.web, 'www.acme.test', 80, '203.0.113.5', [(443, 'https', 'nginx', '1.18.0'), (22, 'ssh', 'OpenSSH', '8.9')])
        cls.api_host = host(cls.api, 'api.acme.test', 40, '203.0.113.9', [(8443, 'https', 'tomcat', '9.0')])
        cls.twin = host(cls.other, 'www.acme.test', 99, '198.51.100.7', [(8443, 'https', 'tomcat', '9.0')])  # the same name in another organization
        cve = CVEEntry.objects.create(cve_id='CVE-2099-2001', kev=True, cvss=9.8, title='nginx request smuggling', published_at=NOW,
                                      affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
        cls.match = CVEMatch.objects.create(cve_entry=cve, subdomain=cls.www, matched_product='nginx', matched_version='1.18.0', version_in_range=True,
                                            confidence=.9, source='port', template_result='vulnerable')  # a check reproduced it: fire
        cls.closed = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-2002', cvss=7.5, title='closed one', published_at=NOW, affected=[]),
                                             subdomain=cls.www, matched_product='nginx', matched_version='1.18.0', confidence=.8, remediation_status='fixed',
                                             remediation_updated_at=NOW)
        cls.hostile = Vulnerability.objects.create(subdomain=cls.api_host, target_domain=cls.domains['acme-api'], scan_history=cls.scans['acme-api'],
                                                   name='=HYPERLINK("http://evil.test","click")', severity=4, source='nuclei', http_url='https://api.acme.test/',
                                                   discovered_date=NOW)
        HygieneFinding.objects.create(domain=cls.domains['acme-web'], host='acme.test', check_name='spf_missing', severity=2, title='No SPF record')
        other_cve = CVEEntry.objects.create(cve_id='CVE-2099-9999', kev=True, cvss=10.0, title='OTHERORG-CVE', published_at=NOW, affected=[])
        CVEMatch.objects.create(cve_entry=other_cve, subdomain=cls.twin, matched_product='tomcat', matched_version='9.0', confidence=.9)
        Vulnerability.objects.create(subdomain=cls.twin, target_domain=cls.domains['other-co'], scan_history=cls.scans['other-co'], name='OTHERORG-VULN',
                                     severity=4, source='nuclei', http_url='https://www.acme.test/', discovered_date=NOW)

    def queue(self, user, slug=None, org=None, run=True, **kw):
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
            job, _ = report_export.enqueue(Ctx(user=user), slug, org=org, **kw)
        if run:
            with mock.patch.object(report_pdf, 'render_pdf', side_effect=stub_render):
                report_export.execute(job.pk, celery_id='test')
            job.refresh_from_db()
        return job

    def csv_rows(self, job):
        with open(os.path.join(self.reports_dir, job.filename), encoding='utf-8') as fh:
            text = fh.read()
        self.assertTrue(text.startswith('﻿'))
        return list(csv.reader(io.StringIO(text.lstrip('﻿'))))


class ScopeTests(ReportingBase):
    def test_an_outsider_cannot_resolve_an_organization(self):
        with self.assertRaises(ApiError) as caught:
            report_scope.resolve(Ctx(user=self.outsider), org='acme-org')
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(ApiError) as caught:
            report_scope.resolve(Ctx(user=self.outsider), org='no-such-org')
        self.assertEqual(caught.exception.status, 404)  # the same answer as a missing one

    def test_a_project_member_gets_only_their_projects_of_the_organization(self):
        scope = report_scope.resolve(Ctx(user=self.web_user), org='acme-org')
        self.assertEqual([p.slug for p in scope.projects], ['acme-web'])
        self.assertFalse(scope.whole)
        whole = report_scope.resolve(Ctx(user=self.org_member), org='acme-org')
        self.assertEqual(sorted(p.slug for p in whole.projects), ['acme-api', 'acme-web'])
        self.assertTrue(whole.whole)

    def test_all_both_and_neither_are_400(self):
        for kwargs in ({'project': '_all'}, {'project': 'acme-web', 'org': 'acme-org'}, {}):
            with self.assertRaises(ApiError) as caught:
                report_scope.resolve(Ctx(user=self.root), **kwargs)
            self.assertEqual(caught.exception.status, 400, kwargs)

    def test_the_scopes_list_follows_the_permission_matrix(self):
        def flags(user):
            scopes = report_scope.list_scopes(Ctx(user=user))['scopes']
            return {(s['kind'], s['slug']): (s['can_subscribe'], s['can_view_subscriptions']) for s in scopes}
        audit = flags(self.org_audit)
        self.assertEqual(audit[('org', 'acme-org')], (False, True))
        self.assertEqual(audit[('project', 'acme-web')], (False, True))
        member = flags(self.org_member)
        self.assertEqual(member[('org', 'acme-org')], (False, True))
        self.assertEqual(member[('project', 'acme-web')], (True, True))
        self.assertEqual(flags(self.org_admin)[('org', 'acme-org')], (True, True))
        project_user = flags(self.web_user)
        self.assertEqual(project_user[('project', 'acme-web')], (True, True))
        self.assertEqual(project_user[('org', 'acme-org')], (False, False))  # added to a project only: cannot read the whole organization
        self.assertNotIn(('project', 'other-co'), project_user)
        self.assertEqual(flags(self.web_audit)[('project', 'acme-web')], (False, True))
        self.assertTrue(flags(self.root)[('org', 'other-org')][0])

    def test_scopes_say_whole_and_name_the_organization_of_each_project(self):
        result = report_scope.list_scopes(Ctx(user=self.web_user))
        org = next(s for s in result['scopes'] if s['kind'] == 'org')
        self.assertEqual((org['slug'], org['projects'], org['whole']), ('acme-org', 1, False))
        project = next(s for s in result['scopes'] if s['kind'] == 'project')
        self.assertEqual((project['org'], project['org_name'], project['role']), ('acme-org', 'Acme Org', 'user'))
        self.assertEqual(result['me_email'], 'webuser@example.test')
        Project.objects.filter(pk=self.loose.pk).update(org=None)  # a project is given a default organization when it is made
        everything = report_scope.list_scopes(Ctx(user=self.root))
        loose = next(s for s in everything['scopes'] if s['slug'] == 'loose')
        self.assertEqual((loose['org'], loose['org_name']), ('', ''))

    def test_a_read_only_token_can_never_manage(self):
        scope = report_scope.resolve(Ctx(user=self.root), project='acme-web')
        self.assertTrue(report_scope.can_manage(self.root, scope))
        self.assertFalse(report_scope.can_manage(self.root, scope, token=mock.Mock(read_only=True)))


class DataTests(ReportingBase):
    def test_an_organization_report_holds_only_the_rows_of_its_projects(self):
        scope = report_scope.resolve(Ctx(user=self.org_member), org='acme-org')
        data = report_data.collect(scope.svc_scope(), org=scope.org)
        text = repr(data)
        self.assertNotIn('OTHERORG', text)
        self.assertEqual(data['scope_kind'], 'org')
        self.assertEqual((data['subject'], data['organization'], data['project']), ('Acme Org', 'Acme Org', '2 projects'))
        self.assertEqual(sorted(h['host'] for h in data['hosts']), ['api.acme.test', 'www.acme.test'])
        self.assertEqual({h['project'] for h in data['hosts']}, {'Acme Web', 'Acme API'})
        self.assertEqual({f['project'] for f in data['findings']}, {'Acme Web', 'Acme API'})
        self.assertEqual(data['summary']['findings'], 2)  # the open CVE match and the scanner finding; the closed match is left out

    def test_the_same_host_name_in_two_projects_keeps_its_own_findings(self):
        other_web = Project.objects.create(name='Acme Web Two', slug='acme-web-two', insert_date=NOW, org=self.org_a)
        domain = Domain.objects.create(name='two.test', project=other_web, insert_date=NOW)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.first(), scan_status=2, start_scan_date=NOW, tasks=[])
        Subdomain.objects.create(target_domain=domain, scan_history=scan, name='www.acme.test', score=1)
        scope = report_scope.resolve(Ctx(user=self.org_member), org='acme-org')
        data = report_data.collect(scope.svc_scope(), org=scope.org)
        counts = {(h['project'], h['host']): h['findings'] for h in data['hosts']}
        self.assertEqual(counts[('Acme Web', 'www.acme.test')], 1)
        self.assertEqual(counts[('Acme Web Two', 'www.acme.test')], 0)

    def test_a_hosts_report_has_no_finding_sections(self):
        scope = report_scope.resolve(Ctx(user=self.org_member), org='acme-org')
        data = report_data.collect(scope.svc_scope(), org=scope.org, kind='hosts', now=NOW)
        html = report_pdf.build_html(data)
        self.assertIn('Discovered Hosts Report', html)
        self.assertNotIn('Detailed findings</h2>', html)
        self.assertNotIn('Exposed secrets</h2>', html)
        self.assertNotIn('Summary of findings</h2>', html)
        self.assertIn('www.acme.test', html)
        self.assertEqual(data['findings'], [])
        self.assertEqual(data['hosts_summary']['ports'][0]['hosts'], 1)

    def test_a_findings_report_keeps_its_sections_and_names_the_projects_on_an_organization_cover(self):
        scope = report_scope.resolve(Ctx(user=self.web_user), org='acme-org')
        html = report_pdf.build_html(report_data.collect(scope.svc_scope(), org=scope.org, whole=scope.whole))
        for heading in ('<h2>Executive summary</h2>', '<h2>Summary of findings</h2>', '<h2>Detailed findings</h2>', '<h2>Scope and methodology</h2>',
                        'Low and informational findings</h2>', 'Asset inventory</h2>'):
            self.assertIn(heading, html)
        self.assertNotIn('Exposed secrets</h2>', html)  # an appendix only when there are secrets
        self.assertIn('Acme Web', html)
        self.assertIn('do not have access to', html)  # the cover says it covers only the projects they can read

    def test_new_hosts_counts_the_last_thirty_days_once_per_project_and_name(self):
        for days, host in ((3, 'new.acme.test'), (3, 'NEW.acme.test'), (40, 'old.acme.test')):
            AssetChange.objects.create(project=self.web, domain=self.domains['acme-web'], host=host, kind='host_new', detected_at=NOW - timedelta(days=days))
        self.assertEqual(report_data._new_hosts(self.web, NOW), 1)


class RenderTests(ReportingBase):
    def test_an_organization_pdf_and_a_hosts_pdf_really_render(self):
        from pypdf import PdfReader
        texts = {}
        for kind in ('findings', 'hosts'):
            with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
                job, _ = report_export.enqueue(Ctx(user=self.org_member), None, org='acme-org', kind=kind)
            self.assertEqual(report_export.execute(job.pk)['status'], 'done')  # the real layout step
            job.refresh_from_db()
            reader = PdfReader(os.path.join(self.reports_dir, job.filename))
            texts[kind] = ' '.join(' '.join(page.extract_text().split()) for page in reader.pages)
        self.assertIn('External Attack Surface Assessment', texts['findings'])
        self.assertIn('Acme Org', texts['findings'])
        self.assertIn('Discovered Hosts Report', texts['hosts'])
        self.assertIn('api.acme.test', texts['hosts'])
        self.assertNotIn('OTHERORG', texts['findings'] + texts['hosts'])
        self.assertNotIn('Exposed secrets', texts['hosts'])


class CsvTests(ReportingBase):
    def test_a_hostile_title_is_written_as_text_not_a_formula(self):
        job = self.queue(self.org_member, org='acme-org', fmt='csv')
        rows = self.csv_rows(job)
        self.assertEqual(tuple(rows[0]), report_csv.FINDING_COLUMNS)
        titles = [r[3] for r in rows[1:]]
        self.assertIn("'=HYPERLINK(\"http://evil.test\",\"click\")", titles)
        self.assertNotIn('=HYPERLINK("http://evil.test","click")', titles)
        self.assertFalse(any(t.startswith('=') for t in titles))

    def test_closed_findings_are_left_out_unless_asked_for(self):
        titles = lambda job: {r[4] for r in self.csv_rows(job)[1:]}
        self.assertNotIn('CVE-2099-2002', titles(self.queue(self.org_member, 'acme-web', fmt='csv')))
        self.assertIn('CVE-2099-2002', titles(self.queue(self.org_member, 'acme-web', fmt='csv', include_closed=True)))

    def test_the_rows_name_project_organization_and_a_link_into_the_findings_page(self):
        rows = self.csv_rows(self.queue(self.org_member, org='acme-org', fmt='csv'))[1:]
        by_cve = {r[4]: r for r in rows if r[4]}
        row = by_cve['CVE-2099-2001']
        self.assertEqual((row[1], row[2], row[9], row[10]), ('fire', 'critical', 'Acme Web', 'Acme Org'))
        self.assertEqual(row[6], 'yes')
        self.assertIn(f'/cve/acme-web/vulns/#match-{self.match.pk}', row[17])
        self.assertIn('1.20.0', row[14])

    def test_the_row_cap_is_reported_as_omitted(self):
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_CSV_MAX_ROWS': '1'}):
            job = self.queue(self.org_member, org='acme-org', fmt='csv')
        self.assertEqual(len(self.csv_rows(job)), 2)
        self.assertEqual(job.summary, {'rows': 1, 'omitted': {'rows': 2}})  # the match, the scanner finding and the hygiene finding: three, one kept
        self.assertEqual(job.summary['rows'] + job.summary['omitted']['rows'], 3)

    def test_the_hosts_csv_has_one_row_per_machine(self):
        sibling = Subdomain.objects.create(target_domain=self.domains['acme-web'], scan_history=self.scans['acme-web'], name='alias.acme.test', score=0)
        sibling.ip_addresses.add(*self.www.ip_addresses.all())  # a second name on the same address is the same machine
        rows = self.csv_rows(self.queue(self.org_member, org='acme-org', kind='hosts', fmt='csv'))
        self.assertEqual(tuple(rows[0]), report_csv.HOST_COLUMNS)
        self.assertEqual(len(rows) - 1, 2)
        www = next(r for r in rows[1:] if r[11] == 'Acme Web')
        self.assertEqual((www[6], www[7], www[8], www[12]), ('fire', '80', '1', 'Acme Org'))
        self.assertEqual(www[0], 'www.acme.test')
        self.assertIn('alias.acme.test', www[2])  # the other name on the same address
        self.assertEqual(www[3], '203.0.113.5')
        self.assertEqual(sorted(www[4].split()), ['22/tcp', '443/tcp'])


class ExportTests(ReportingBase):
    def test_an_organization_report_is_queued_run_and_downloaded_by_the_requester_only(self):
        job = self.queue(self.org_member, org='acme-org', run=False)
        self.assertEqual((job.org_id, job.project_id, job.kind, job.format), (self.org_a.pk, None, 'findings', 'pdf'))
        with mock.patch.object(report_pdf, 'render_pdf', side_effect=stub_render):
            self.assertEqual(report_export.execute(job.pk)['status'], 'done')
        response = report_export.download(Ctx(user=self.org_member), None, job.token, org='acme-org')
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('cvengine-report-acme-org-org-', response['Content-Disposition'])
        with self.assertRaises(ApiError) as caught:
            report_export.download(Ctx(user=self.org_admin), None, job.token, org='acme-org')  # another member of the organization
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(ApiError) as caught:
            report_export.status(Ctx(user=self.outsider), None, job.token, org='acme-org')
        self.assertEqual(caught.exception.status, 404)

    def test_rest_routes_queue_poll_and_download_an_organization_report(self):
        _, token = create_token(self.org_member, 'member')
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
            status, body = call(token, 'POST', '/api/v1/orgs/acme-org/reports', {'kind': 'hosts', 'format': 'csv'})
        self.assertEqual(status, 202, body)
        self.assertEqual((body['kind'], body['format'], body['org'], body['project']), ('hosts', 'csv', 'acme-org', None))
        self.assertEqual(body['status_url'], f"/api/v1/orgs/acme-org/reports/{body['id']}")
        report_export.execute(ReportExport.objects.get(token=body['id']).pk)
        status, body = call(token, 'GET', body['status_url'])
        self.assertEqual((status, body['status']), (200, 'done'), body)
        response = Client().get(body['download_url'], HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        self.assertTrue(response['Content-Disposition'].endswith('.csv"'))
        self.assertEqual(Client().get(body['download_url'], HTTP_AUTHORIZATION=f'Bearer {create_token(self.outsider, "o")[1]}').status_code, 404)

    def test_a_read_only_token_may_ask_for_an_organization_report(self):
        _, token = create_token(self.org_member, 'ro', read_only=True)
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
            self.assertEqual(call(token, 'POST', '/api/v1/orgs/acme-org/reports', {})[0], 202)
            self.assertEqual(call(token, 'POST', '/api/v1/projects/acme-web/reports', {'kind': 'hosts'})[0], 202)
        self.assertEqual(call(token, 'POST', '/api/v1/projects/acme-web/targets', {'value': 'x.acme.test'})[0], 403)

    def test_the_request_is_checked(self):
        for org, slug, kwargs, status in ((None, 'acme-web', {'kind': 'nope'}, 400), (None, 'acme-web', {'fmt': 'docx'}, 400), (None, 'acme-web', {'kind': 'hosts', 'host': 'www.acme.test'}, 400),
                                          ('acme-org', None, {'host': 'www.acme.test'}, 400), ('acme-org', 'acme-web', {}, 400), (None, None, {}, 400),
                                          ('other-org', None, {}, 404), (None, 'other-co', {}, 404)):
            with self.assertRaises(ApiError, msg=(org, slug, kwargs)) as caught:
                report_export.enqueue(Ctx(user=self.org_member), slug, org=org, **kwargs)
            self.assertEqual(caught.exception.status, status, (org, slug, kwargs))

    def test_asking_twice_for_the_same_report_gives_the_same_job_and_a_different_kind_a_new_one(self):
        first = self.queue(self.org_member, org='acme-org', run=False)
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
            again, created = report_export.enqueue(Ctx(user=self.org_member), None, org='acme-org')
            hosts, hosts_created = report_export.enqueue(Ctx(user=self.org_member), None, org='acme-org', kind='hosts')
            csv_job, csv_created = report_export.enqueue(Ctx(user=self.org_member), None, org='acme-org', fmt='csv')
        self.assertEqual((again.pk, created), (first.pk, False))
        self.assertTrue(hosts_created and csv_created)
        self.assertEqual(len({first.pk, hosts.pk, csv_job.pk}), 3)

    def test_access_lost_between_asking_and_running_fails_the_job(self):
        job = self.queue(self.org_member, org='acme-org', run=False)
        OrgMembership.objects.filter(user=self.org_member).delete()
        with mock.patch.object(report_pdf, 'render_pdf', side_effect=stub_render):
            result = report_export.execute(job.pk)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('no longer have access', result['error'])
        project_job = self.queue(self.web_user, 'acme-web', run=False)
        ProjectMembership.objects.filter(user=self.web_user).delete()
        self.assertIn('no longer have access', report_export.execute(project_job.pk)['error'])

    def test_a_project_report_is_unchanged_in_kind_and_format_by_default(self):
        job = self.queue(self.web_user, 'acme-web')
        self.assertEqual((job.kind, job.format, job.org_id, job.status), ('findings', 'pdf', None, 'done'))
        self.assertTrue(job.filename.endswith('.pdf'))
        self.assertEqual(report_export.serialize(job)['scope'], {'kind': 'project', 'slug': 'acme-web', 'name': 'Acme Web'})

    def test_the_list_of_my_reports_holds_only_mine_and_only_what_i_can_still_read(self):
        mine = self.queue(self.org_member, org='acme-org')
        self.queue(self.org_admin, org='acme-org')
        projects = self.queue(self.org_member, 'acme-api', kind='hosts', fmt='csv')
        results = report_export.recent(Ctx(user=self.org_member))
        self.assertEqual({r['id'] for r in results}, {mine.token, projects.token})
        OrgMembership.objects.filter(user=self.org_member).delete()
        self.assertEqual(report_export.recent(Ctx(user=self.org_member)), [])
        status, body = call(self.org_admin, 'GET', '/api/v1/reporting/reports')
        self.assertEqual((status, len(body['results'])), (200, 1))

    def test_the_file_name_pattern_accepts_csv_and_nothing_else(self):
        for name, ok in (('a' * 48 + '.pdf', True), ('a' * 48 + '.csv', True), ('a' * 48 + '.html', False), ('a' * 47 + '.csv', False), ('../' + 'a' * 48 + '.csv', False)):
            self.assertEqual(bool(report_export.FILE_RE.match(name)), ok, name)

    def test_reports_scopes_route_and_mcp_tool(self):
        status, body = call(self.org_member, 'GET', '/api/v1/reporting/scopes')
        self.assertEqual(status, 200)
        self.assertIn('mail_ready', body)
        self.assertEqual(body['limits']['recipients'], 10)
        _, token = create_token(self.org_member, 'mcp')
        error, data = tool_call(token, 'list_report_scopes')
        self.assertFalse(error)
        self.assertEqual({s['slug'] for s in data['scopes'] if s['kind'] == 'org'}, {'acme-org'})
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=FAKE_TASK):
            error, data = tool_call(token, 'export_report', {'org': 'acme-org', 'kind': 'hosts', 'format': 'csv'})
        self.assertFalse(error, data)
        self.assertEqual((data['org'], data['kind'], data['format']), ('acme-org', 'hosts', 'csv'))
        error, data = tool_call(token, 'get_report', {'org': 'acme-org', 'report_id': data['id']})
        self.assertFalse(error, data)
        self.assertEqual(data['status'], 'queued')
        error, _ = tool_call(token, 'export_report', {'project': 'acme-web', 'org': 'acme-org'})
        self.assertTrue(error)


class PageTests(ReportingBase):
    def test_the_page_renders_for_an_audit_user_with_reporting_in_the_rail(self):
        response = client_for(self.org_audit).get('/cve/reports/')
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn('<h1>Reporting</h1>', html)
        self.assertIn('id="reports-root"', html)
        self.assertIn('data-nav="Reporting"', html)
        self.assertIn('id="i-report"', html)
        rail = response.context['nav']['rail']
        self.assertEqual([e['label'] for e in rail if e['key'] == 'reporting'], ['Reporting'])
        self.assertTrue(next(e for e in rail if e['key'] == 'reporting')['current'])

    def test_the_page_preselects_the_project_or_organization_in_the_address(self):
        client = client_for(self.org_member)
        html = client.get('/cve/reports/?project=acme-api').content.decode()
        self.assertIn('data-project="acme-api"', html)
        html = client.get('/cve/reports/?org=acme-org').content.decode()
        self.assertIn('data-org="acme-org"', html)
        self.assertEqual(client_for(self.web_user).get('/cve/reports/?project=other-co').status_code, 404)  # the middleware: not theirs

    def test_reporting_sits_after_scans_and_before_scanners_and_in_the_phone_more_sheet(self):
        built = nav.build('reports', 'acme-web', bounty_enabled=True, sentinels_enabled=False)
        self.assertEqual([e['key'] for e in built['rail']], ['overview', 'findings', 'hygiene', 'assets', 'suppliers', 'scans', 'reporting', 'scanners', 'mcp', 'bounty'])
        bare = nav.build('reports', None, bounty_enabled=False, sentinels_enabled=False)
        self.assertEqual([e['label'] for e in bare['rail']], ['Overview', 'Graph', 'Reporting', 'Scanners', 'MCP'])
        self.assertIn('Reporting', [i['label'] for i in built['index']])
        html = client_for(self.org_member).get('/cve/reports/').content.decode()
        sheet = html[html.index('class="sheet-grid"'):]
        self.assertIn('Reporting', sheet[:sheet.index('</div>')])
        self.assertEqual(nav.SECTION_ICON['reporting'], 'report')
