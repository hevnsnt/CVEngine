"""Export one host: ``GET projects/{slug}/hosts/{host_id}/export`` (a ZIP) and the MCP tool ``export_host`` (agentapi/host_export_one.py).

The fixture host has a CVE match, a scanner finding, a hygiene finding, a change history older than 90 days, a certificate, a route whose stored
evidence holds an Authorization header and a cookie, a probe whose evidence holds a token, an exposed secret (stored masked, as always) and two
browser captures on disk. The raw credential strings must not appear anywhere in the ZIP.
"""
import csv
import io
import json
import os
import shutil
import tempfile
import zipfile
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import host_export_one
from agentapi.auth import create_token
from cveFeed.models import (AssetChange, CVEEntry, CVEMatch, HostScreenshot, HostState, HygieneFinding, ProbeObservation, RouteAuth, SecretFinding,
                            SecretOccurrence, TlsCertificate)
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import tool_call

RAW_AUTH = 'Bearer sk_live_RAWVALUE_never_exported'
RAW_COOKIE = 'session=RAWCOOKIE_never_exported'
RAW_TOKEN = 'RAWTOKEN_never_exported'
MASKED = 'AKIA************WXYZ'
PNG = b'\x89PNG\r\n\x1a\n' + b'png-bytes' * 10
JPEG = b'\xff\xd8\xff\xe0' + b'jpeg-bytes' * 10


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.acme = Org.objects.create(name='Acme', slug='h1-acme')
        cls.other = Org.objects.create(name='Other', slug='h1-other')
        cls.web = Project.objects.create(name='Acme Web', slug='h1-web', insert_date=now, org=cls.acme)
        cls.api = Project.objects.create(name='Acme API', slug='h1-api', insert_date=now, org=cls.acme)
        cls.far = Project.objects.create(name='Other', slug='h1-far', insert_date=now, org=cls.other)
        cls.alice = User.objects.create_user('h1_alice', password='x')
        cls.eve = User.objects.create_user('h1_eve', password='x')
        cls.audit_user = User.objects.create_user('h1_audit', password='x')
        ProjectMembership.objects.create(user=cls.alice, project=cls.web, role='user')
        ProjectMembership.objects.create(user=cls.audit_user, project=cls.web, role='audit')
        OrgMembership.objects.create(user=cls.eve, org=cls.other, role='admin')
        cls.t = {n: create_token(u, n)[1] for n, u in (('alice', cls.alice), ('eve', cls.eve), ('audit', cls.audit_user))}
        _, cls.t['ro'] = create_token(cls.alice, 'readonly', read_only=True)
        cls.dom = Domain.objects.create(name='example.com', project=cls.web, insert_date=now)
        cls.dom_api = Domain.objects.create(name='api.example.com', project=cls.api, insert_date=now)
        cls.dom_far = Domain.objects.create(name='far.example.com', project=cls.far, insert_date=now)
        engine = EngineType.objects.create(engine_name='full', yaml_configuration='x')
        cls.scan = ScanHistory.objects.create(domain=cls.dom, scan_type=engine, start_scan_date=now - timedelta(days=2), scan_status=2)

    def setUp(self):
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, True)
        media = self.settings(MEDIA_ROOT=self.media)
        media.enable()
        self.addCleanup(media.disable)
        now = timezone.now()
        self.www = Subdomain.objects.create(target_domain=self.dom, scan_history=self.scan, name='www.example.com', discovered_date=now)
        ip = IpAddress.objects.create(address='203.0.113.10')
        self.www.ip_addresses.add(ip)
        ip.ports.add(Port.objects.create(number=443, service_name='https', product='nginx', version='1.24.0', protocol='tcp', state='open',
                                         banner='=cmd|calc'))
        cve = CVEEntry.objects.create(cve_id='CVE-2099-1', cvss=9.8, title='nginx bug', published_at=now, affected=[])
        self.match = CVEMatch.objects.create(cve_entry=cve, subdomain=self.www, confidence=0.9, matched_product='nginx', matched_version='1.24.0',
                                             version_in_range=True)
        self.vuln = Vulnerability.objects.create(target_domain=self.dom, subdomain=self.www, name='Exposed admin panel', severity=3,
                                                 http_url='https://www.example.com/admin', open_status=True)
        HygieneFinding.objects.create(domain=self.dom, host='www.example.com', check_name='spf_missing', severity=2, title='No SPF')
        HostState.objects.create(project=self.web, domain=self.dom, host='www.example.com', first_seen=now - timedelta(days=400), last_seen=now)
        AssetChange.objects.create(project=self.web, domain=self.dom, host='www.example.com', kind='host_new')
        AssetChange.objects.filter(host='www.example.com').update(detected_at=now - timedelta(days=300))  # older than the page's 90 days
        AssetChange.objects.create(project=self.web, domain=self.dom, host='www.example.com', kind='port_opened', port=443)
        TlsCertificate.objects.create(domain=self.dom, host='www.example.com', port=443, subject='www.example.com', issuer='Test CA',
                                      sans=[f'n{i}.example.com' for i in range(12)], not_after=now + timedelta(days=30))
        RouteAuth.objects.create(project=self.web, domain=self.dom, host='www.example.com', url='https://www.example.com/', path='/',
                                 auth_state='open', http_status=200, title='Welcome',
                                 evidence={'server': 'nginx', 'headers': {'Authorization': RAW_AUTH, 'Cookie': RAW_COOKIE, 'X-Frame-Options': 'DENY'}})
        ProbeObservation.objects.create(project=self.web, domain=self.dom, host='www.example.com', probe='nginx-status', kind='version',
                                        product='nginx', version='1.24.0', evidence={'token': RAW_TOKEN, 'path': '/status'})
        secret = SecretFinding.objects.create(project=self.web, domain=self.dom, fingerprint='e' * 64, kind='aws_access_key', klass='S', masked=MASKED,
                                              provider='aws', severity=3)
        SecretOccurrence.objects.create(finding=secret, project=self.web, domain=self.dom, host='www.example.com', url='https://www.example.com/app.js',
                                        source='kingfisher', rule_id='aws', context='const key = "AKIA************WXYZ";')
        self.plant('shots/www-443.png', PNG)
        self.plant('shots/www-80.jpg', JPEG)
        HostScreenshot.objects.create(project=self.web, domain=self.dom, host='www.example.com', scheme='https', port=443, outcome='ok',
                                      image_path='shots/www-443.png', image_bytes=len(PNG), captured_at=now, title='Welcome')
        HostScreenshot.objects.create(project=self.web, domain=self.dom, host='www.example.com', scheme='http', port=80, outcome='ok',
                                      image_path='shots/www-80.jpg', image_bytes=len(JPEG), captured_at=now)
        HostScreenshot.objects.create(project=self.web, domain=self.dom, host='www.example.com', scheme='https', port=8443, outcome='timeout')
        self.api_host = Subdomain.objects.create(target_domain=self.dom_api, name='api.example.com', discovered_date=now)
        self.far_host = Subdomain.objects.create(target_domain=self.dom_far, name='secret.far.example.com', discovered_date=now)

    def plant(self, rel, data):
        path = os.path.join(self.media, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as fh:
            fh.write(data)

    def get(self, who, sub, project='h1-web'):
        return Client().get(f'/api/v1/projects/{project}/hosts/{sub.pk}/export', HTTP_AUTHORIZATION=f'Bearer {self.t[who]}')

    def zip_of(self, who='alice', sub=None):
        response = self.get(who, sub or self.www)
        self.assertTrue(response.streaming, response.content[:300] if not response.streaming else '')
        self.assertEqual(response.status_code, 200)
        data = b''.join(response.streaming_content)
        return response, zipfile.ZipFile(io.BytesIO(data)), data


class ContentTests(Base):
    def test_the_zip_holds_every_file_with_the_name_the_task_asks_for(self):
        response, zf, _ = self.zip_of()
        self.assertEqual(response['Content-Type'], 'application/zip')
        self.assertRegex(response['Content-Disposition'], r'attachment; filename="host-www\.example\.com-\d{4}-\d{2}-\d{2}\.zip"')
        self.assertEqual(response['Cache-Control'], 'no-store')
        names = set(zf.namelist())
        self.assertLessEqual({'README.txt', 'host.json', 'findings.csv', 'services.csv', 'history.csv', 'certificates.csv', 'inventory.csv'}, names)
        self.assertIsNone(zf.testzip())

    def test_host_json_is_the_versioned_complete_record(self):
        _, zf, _ = self.zip_of()
        r = json.loads(zf.read('host.json'))
        self.assertEqual(r['schema'], host_export_one.SCHEMA)
        self.assertEqual(r['host']['name'], 'www.example.com')
        self.assertEqual(r['host']['id'], self.www.pk)
        self.assertEqual(r['project']['slug'], 'h1-web')
        self.assertIn('score_detail', r['host'])
        self.assertIn('heat_reasons', r['host'])
        self.assertEqual(r['host']['state'][0]['host'], 'www.example.com')
        self.assertEqual([p['number'] for ip in r['services']['addresses'] for p in ip['ports']], [443])
        self.assertEqual([f['title'] for f in r['findings']['cve']], ['CVE-2099-1'])
        self.assertIn('explain', r['findings']['cve'][0])
        self.assertIn('triage', r['findings']['cve'][0])
        self.assertIn('retest', r['findings']['cve'][0])
        self.assertIn('comment_count', r['findings']['scanner'][0])
        self.assertEqual([f['title'] for f in r['findings']['scanner']], ['Exposed admin panel'])
        self.assertEqual([f['title'] for f in r['findings']['hygiene']], ['No SPF'])
        self.assertEqual(len(r['web']['certificates'][0]['sans']), 12, 'every name of the certificate, not the list route\'s ten')
        self.assertEqual([x['path'] for x in r['web']['routes']], ['/'])
        self.assertEqual([p['probe'] for p in r['probes']], ['nginx-status'])
        self.assertEqual([s['scan_id'] for s in r['scans']], [self.scan.pk])
        self.assertIn('check_coverage', r)
        self.assertEqual(r['secrets'][0]['masked'], MASKED)
        self.assertEqual(r['truncated'], {k: False for k in r['truncated']})

    def test_the_history_is_the_whole_timeline_not_the_last_90_days(self):
        _, zf, _ = self.zip_of()
        kinds = [c['kind'] for c in json.loads(zf.read('host.json'))['history']['changes']]
        self.assertEqual(kinds, ['port_opened', 'host_new'])
        rows = list(csv.DictReader(io.StringIO(zf.read('history.csv').decode('utf-8-sig'))))
        self.assertEqual([r['Kind'] for r in rows], ['port_opened', 'host_new'])

    def test_the_csv_files_hold_the_rows_and_a_formula_is_defused(self):
        _, zf, _ = self.zip_of()
        findings = list(csv.DictReader(io.StringIO(zf.read('findings.csv').decode('utf-8-sig'))))
        self.assertEqual(sorted(r['Type'] for r in findings), ['cve', 'hygiene', 'scanner'])
        services = list(csv.DictReader(io.StringIO(zf.read('services.csv').decode('utf-8-sig'))))
        self.assertEqual([(r['Port'], r['Product'], r['Version']) for r in services], [('443', 'nginx', '1.24.0')])
        self.assertEqual(services[0]['Banner'], "'=cmd|calc", 'a banner a spreadsheet would run gets an apostrophe')
        certs = list(csv.DictReader(io.StringIO(zf.read('certificates.csv').decode('utf-8-sig'))))
        self.assertEqual([c['Issuer'] for c in certs], ['Test CA'])

    def test_the_screenshots_are_the_image_files_with_a_manifest(self):
        _, zf, _ = self.zip_of()
        shots = sorted(n for n in zf.namelist() if n.startswith('screenshots/'))
        self.assertEqual(shots, ['screenshots/www.example.com-http-80.jpg', 'screenshots/www.example.com-https-443.png'])
        self.assertEqual(zf.read('screenshots/www.example.com-https-443.png'), PNG)
        self.assertEqual(zf.read('screenshots/www.example.com-http-80.jpg'), JPEG)
        manifest = json.loads(zf.read('host.json'))['screenshots']
        self.assertEqual({m['file'] for m in manifest if m['included']}, set(shots))
        self.assertEqual([m['left_out'] for m in manifest if m['port'] == 8443], ['no picture was taken'])
        self.assertNotIn('image_path', json.dumps(manifest), 'never a server path')

    def test_no_secret_value_token_or_credential_is_anywhere_in_the_zip(self):
        _, zf, raw = self.zip_of()
        everything = b''.join(zf.read(n) for n in zf.namelist())
        for value in (RAW_AUTH, RAW_COOKIE, RAW_TOKEN, 'RAWVALUE', 'RAWCOOKIE', 'RAWTOKEN'):
            self.assertNotIn(value.encode(), everything, value)
        self.assertIn(MASKED.encode(), zf.read('host.json'))
        route = json.loads(zf.read('host.json'))['web']['routes'][0]['evidence']['headers']
        self.assertEqual(route, {'Authorization': host_export_one.MASK, 'Cookie': host_export_one.MASK, 'X-Frame-Options': 'DENY'})

    def test_the_readme_says_what_each_file_is_when_and_which_version(self):
        from django.conf import settings
        _, zf, _ = self.zip_of()
        text = zf.read('README.txt').decode('utf-8')
        for name in ('host.json', 'findings.csv', 'services.csv', 'history.csv', 'certificates.csv', 'inventory.csv', 'screenshots/'):
            self.assertIn(name, text)
        self.assertIn(f'cvENGINE {settings.CVENGINE_CURRENT_VERSION}', text)
        self.assertIn('Exported at 2', text)
        self.assertIn('Every stored screenshot is included.', text)
        self.assertNotIn('\u2014', text)

    def test_each_export_is_written_to_the_audit_log(self):
        self.zip_of()
        row = AuditLog.objects.get(action='host.export')
        self.assertEqual((row.detail['project'], row.detail['host'], row.detail['host_id'], row.detail['kind']), ('h1-web', 'www.example.com', self.www.pk, 'host'))
        self.assertEqual(row.detail['screenshots'], 2)
        self.assertEqual(row.org_id, self.acme.pk)


class AccessTests(Base):
    def test_a_host_of_another_project_is_not_found(self):
        self.assertEqual(self.get('alice', self.api_host).status_code, 404, 'same organization, a project alice is not in')
        self.assertEqual(self.get('alice', self.far_host).status_code, 404, 'another organization, asked under her own project')
        self.assertEqual(self.get('eve', self.www).status_code, 404, 'another tenant cannot tell the project exists')
        self.assertEqual(self.get('eve', self.far_host, project='h1-far').status_code, 200)
        self.assertFalse(AuditLog.objects.filter(action='host.export', detail__host='www.example.com').exists())

    def test_read_only_callers_may_export_what_they_can_read(self):
        self.assertEqual(self.get('ro', self.www).status_code, 200)
        self.assertEqual(self.get('audit', self.www).status_code, 200)

    def test_nothing_without_a_sign_in_and_not_for_all_projects(self):
        self.assertIn(Client().get(f'/api/v1/projects/h1-web/hosts/{self.www.pk}/export').status_code, (401, 403))
        self.assertEqual(self.get('alice', self.www, project='_all').status_code, 400)
        self.assertEqual(Client().get('/api/v1/projects/h1-web/hosts/999999999/export', HTTP_AUTHORIZATION=f'Bearer {self.t["alice"]}').status_code, 404)


class CapTests(Base):
    def test_screenshots_past_the_byte_cap_are_left_out_and_the_readme_says_so(self):
        with mock.patch.object(host_export_one, 'MAX_SCREENSHOT_BYTES', len(PNG) + 1):
            _, zf, _ = self.zip_of()
        self.assertEqual([n for n in zf.namelist() if n.startswith('screenshots/')], ['screenshots/www.example.com-https-443.png'])
        left = [m for m in json.loads(zf.read('host.json'))['screenshots'] if m.get('bytes') and not m['included']]
        self.assertEqual(len(left), 1)
        self.assertIn('over the limit', left[0]['left_out'])
        self.assertIn('1 screenshot(s) were left out', zf.read('README.txt').decode())

    def test_screenshots_past_the_file_cap_are_left_out(self):
        with mock.patch.object(host_export_one, 'MAX_SCREENSHOT_FILES', 1):
            _, zf, _ = self.zip_of()
        self.assertEqual(len([n for n in zf.namelist() if n.startswith('screenshots/')]), 1)

    def test_a_file_outside_the_media_folder_or_not_a_picture_is_never_read(self):
        HostScreenshot.objects.filter(port=80).update(image_path='../../../etc/passwd')
        self.plant('shots/page.html', b'<html>not a picture</html>')
        HostScreenshot.objects.filter(port=443).update(image_path='shots/page.html')
        _, zf, _ = self.zip_of()
        self.assertEqual([n for n in zf.namelist() if n.startswith('screenshots/')], [])
        reasons = sorted(m['left_out'] for m in json.loads(zf.read('host.json'))['screenshots'] if m['port'] in (80, 443))
        self.assertEqual(reasons, ['the file is missing', 'the file is not a PNG or JPEG picture'])

    def test_a_list_past_the_row_cap_is_cut_and_marked(self):
        AssetChange.objects.bulk_create([AssetChange(project=self.web, domain=self.dom, host='www.example.com', kind='port_opened', port=i) for i in range(5)])
        with mock.patch.object(host_export_one, 'MAX_ROWS', 3):
            _, zf, _ = self.zip_of()
        r = json.loads(zf.read('host.json'))
        self.assertEqual(len(r['history']['changes']), 3)
        self.assertTrue(r['truncated']['history'])
        self.assertIn('Lists cut at the limit: history', zf.read('README.txt').decode())

    def test_the_zip_is_written_in_pieces(self):
        response = self.get('alice', self.www)
        pieces = [p for p in response.streaming_content if p]
        self.assertGreater(len(pieces), 3)


class QueryCountTests(Base):
    def count(self):
        with CaptureQueriesContext(connection) as ctx:
            response = self.get('alice', self.www)
            b''.join(response.streaming_content)
        self.assertEqual(response.status_code, 200)
        return len(ctx.captured_queries)

    def add_findings(self, n):
        cves = CVEEntry.objects.bulk_create([CVEEntry(cve_id=f'CVE-2098-{len(CVEEntry.objects.all())}{i}', cvss=7.5, title='t', published_at=timezone.now(), affected=[])
                                             for i in range(n)])
        CVEMatch.objects.bulk_create([CVEMatch(cve_entry=c, subdomain=self.www, confidence=0.5, matched_product='nginx', matched_version='1.24.0') for c in cves])
        Vulnerability.objects.bulk_create([Vulnerability(target_domain=self.dom, subdomain=self.www, name=f'finding {i}', severity=2, open_status=True)
                                           for i in range(n)])
        HygieneFinding.objects.bulk_create([HygieneFinding(domain=self.dom, host='www.example.com', check_name=f'check_{i}', severity=1, title='t')
                                            for i in range(n)])
        AssetChange.objects.bulk_create([AssetChange(project=self.web, domain=self.dom, host='www.example.com', kind='port_opened', port=i) for i in range(n)])

    def test_the_export_reads_a_fixed_number_of_statements_whatever_the_number_of_findings(self):
        self.count()  # warm the per-process caches (exclusion lists, policies) the first export reads once
        few = self.count()
        self.add_findings(60)
        many = self.count()
        print(f'\nexport_host statements: {few} for 3 findings, {many} for 183 findings')
        self.assertEqual(many, few, f'{few} statements for 3 findings, {many} for 183: a statement per finding')


class McpTests(Base):
    def test_the_tool_returns_the_json_record_only(self):
        error, out = tool_call(self.t['alice'], 'export_host', {'project': 'h1-web', 'host_id': self.www.pk})
        self.assertFalse(error, out)
        record = json.loads(out['content'])
        self.assertEqual(record['schema'], host_export_one.SCHEMA)
        self.assertEqual(record['host']['name'], 'www.example.com')
        self.assertEqual(out['screenshots'], 2)
        self.assertIn(f'GET projects/h1-web/hosts/{self.www.pk}/export', out['screenshots_note'])
        self.assertTrue(out['filename'].endswith('.json'))
        self.assertNotIn('RAWVALUE', out['content'])
        self.assertTrue(AuditLog.objects.filter(action='host.export', detail__channel='mcp').exists())

    def test_the_tool_refuses_another_projects_host_and_a_missing_argument(self):
        self.assertTrue(tool_call(self.t['alice'], 'export_host', {'project': 'h1-web', 'host_id': self.api_host.pk})[0])
        self.assertTrue(tool_call(self.t['eve'], 'export_host', {'project': 'h1-web', 'host_id': self.www.pk})[0])
        self.assertTrue(tool_call(self.t['alice'], 'export_host', {'project': 'h1-web'})[0])

    def test_a_record_past_the_answer_cap_is_a_413_that_points_at_the_download(self):
        with mock.patch.object(host_export_one, 'MCP_MAX_BYTES', 100):
            error, text = tool_call(self.t['alice'], 'export_host', {'project': 'h1-web', 'host_id': self.www.pk})
        self.assertTrue(error)
        self.assertIn(f'projects/h1-web/hosts/{self.www.pk}/export', text)

    def test_the_tool_is_listed_with_its_schema_and_counted_as_heavy(self):
        from agentapi import mcp
        self.assertEqual(set(mcp.BY_NAME['export_host'][2]['properties']), {'project', 'host_id'})
        self.assertIn('export_host', mcp.HEAVY_TOOLS)
        self.assertIs(mcp.BY_NAME['export_host'][-1], False, 'read only: no write verdict needed')
