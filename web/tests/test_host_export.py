"""Export all discovered hosts: ``GET projects/{slug}/hosts/export`` and ``GET orgs/{org}/hosts/export`` (agentapi/host_export.py).

Addresses are the documentation range 203.0.113.0/24 (example.com names), and private ones are 10.0.0.0/8. ``is_public_address`` (the repo's one
rule for "an address on the public internet") treats the documentation range as not public, as it must for a real address, so the tests tell
it that one range is public: every other address keeps the real rule.
"""
import csv
import io
import ipaddress
import re
from datetime import timedelta, timezone as _tz
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from agentapi import host_export
from agentapi.auth import create_token
from cveFeed import internal_view
from cveFeed.models import CVEEntry, CVEMatch, ExcludedAddress, HostExclusion, HostState, InternalRange
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain, Vulnerability
from targetApp import target_types
from targetApp.models import Domain
from tests.test_agentapi import tool_call

DOC = ipaddress.ip_network('203.0.113.0/24')
UTC = _tz.utc
REAL_IS_PUBLIC = target_types.is_public_address
FINDING = 'Outdated nginx on the front door'


def public_for_tests(value):
    try:
        if ipaddress.ip_address(str(value).strip().strip('[]')) in DOC:
            return True
    except ValueError:
        pass
    return REAL_IS_PUBLIC(value)


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.acme = Org.objects.create(name='Acme', slug='hx-acme')
        cls.other = Org.objects.create(name='Other Corp', slug='hx-other')
        cls.web = Project.objects.create(name='Acme Web', slug='hx-web', insert_date=now, org=cls.acme)
        cls.api = Project.objects.create(name='Acme API', slug='hx-api', insert_date=now, org=cls.acme)
        cls.secret = Project.objects.create(name='Other Secret', slug='hx-secret', insert_date=now, org=cls.other)
        mk = lambda n: User.objects.create_user(n, password='x')
        cls.alice, cls.boss, cls.eve, cls.root = mk('hx_alice'), mk('hx_boss'), mk('hx_eve'), mk('hx_root')
        cls.root.is_superuser = True
        cls.root.save()
        ProjectMembership.objects.create(user=cls.alice, project=cls.web, role='user')  # one project of the organization, not the other
        OrgMembership.objects.create(user=cls.boss, org=cls.acme, role='admin')
        OrgMembership.objects.create(user=cls.eve, org=cls.other, role='admin')
        cls.t = {n: create_token(u, n)[1] for n, u in (('alice', cls.alice), ('boss', cls.boss), ('eve', cls.eve), ('root', cls.root))}
        _, cls.t_ro = create_token(cls.alice, 'readonly', read_only=True)
        cls.dom = {p.slug: Domain.objects.create(name=f'{p.slug}.example.com', project=p, insert_date=now) for p in (cls.web, cls.api, cls.secret)}
        cls.seen = now - timedelta(days=3)

    def host(self, project, name, *addresses, ports=(), seen=None):
        """A host of ``project`` with its addresses and ports: each port is (address, number, service, product, version[, protocol])."""
        sub = Subdomain.objects.create(target_domain=self.dom[project.slug], name=name, discovered_date=seen or self.seen)
        for address in addresses:
            sub.ip_addresses.add(IpAddress.objects.get_or_create(address=address)[0])
        for address, number, service, product, version, *proto in ports:
            ip = IpAddress.objects.get(address=address)
            ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, version=version, protocol=(proto or ['tcp'])[0], state='open'))
        return sub

    def setUp(self):
        public = mock.patch('targetApp.target_types.is_public_address', side_effect=public_for_tests)
        public.start()
        self.addCleanup(public.stop)
        internal_view.invalidate()
        self.addCleanup(internal_view.invalidate)
        self.www = self.host(self.web, 'www.example.com', '203.0.113.10', ports=[
            ('203.0.113.10', 80, 'http', 'nginx', '1.24.0'), ('203.0.113.10', 443, 'https', 'nginx', '1.24.0'), ('203.0.113.10', 161, 'snmp', '', '', 'udp')])
        self.mail = self.host(self.web, 'mail.example.com', '203.0.113.11', ports=[('203.0.113.11', 25, 'smtp', 'Postfix', '3.8')])
        self.mixed = self.host(self.web, 'mixed.example.com', '203.0.113.13', '10.9.9.9', ports=[('203.0.113.13', 8080, 'http-proxy', '', ''), ('10.9.9.9', 5432, 'postgresql', 'PostgreSQL', '15')])
        self.intranet = self.host(self.web, 'intra.example.com', '10.1.2.3', ports=[('10.1.2.3', 22, 'ssh', 'OpenSSH', '9.6')])
        self.literal = self.host(self.web, '10.0.0.5', '10.0.0.5')
        self.old = self.host(self.web, 'old.example.com', '203.0.113.20')
        HostState.objects.create(project=self.web, domain=self.dom['hx-web'], host='old.example.com', archived_at=timezone.now(), archive_reason='gone')
        self.gone = self.host(self.web, 'gone.example.com', '203.0.113.21')
        HostExclusion.objects.create(org=self.acme, host='gone.example.com')
        self.apihost = self.host(self.api, 'api.example.com', '203.0.113.30', ports=[('203.0.113.30', 443, 'https', 'envoy', '')])
        self.dup = self.host(self.api, 'www.example.com', '203.0.113.10')
        self.hidden = self.host(self.secret, 'hidden.example.com', '203.0.113.99')
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=9.8, title='nginx bug', published_at=timezone.now(), affected=[])
        CVEMatch.objects.create(cve_entry=cve, subdomain=self.www, confidence=0.9, matched_product='nginx', matched_version='1.24.0', version_in_range=True)
        Vulnerability.objects.create(target_domain=self.dom['hx-web'], subdomain=self.www, name=FINDING, severity=4, http_url='https://www.example.com/', open_status=True)

    def get(self, who, path, **params):
        headers = {'HTTP_AUTHORIZATION': f'Bearer {self.t[who] if who in self.t else who}'} if who else {}
        return Client().get(path, params, **headers)

    def body(self, response):
        return b''.join(response.streaming_content).decode('utf-8') if response.streaming else response.content.decode('utf-8')

    def rows(self, who, path, **params):
        response = self.get(who, path, **params)
        self.assertEqual(response.status_code, 200, response.content[:300] if not response.streaming else '')
        text = self.body(response)
        self.assertTrue(text.startswith('﻿'), 'the file starts with the UTF-8 byte order mark')
        return list(csv.DictReader(io.StringIO(text[1:], newline='')))

    def hosts(self, who, path, **params):
        return [r['Host'] for r in self.rows(who, path, **params)]

    def lines(self, who, path, **params):
        response = self.get(who, path, **params)
        self.assertEqual(response.status_code, 200)
        return self.body(response).splitlines()


PROJECT = '/api/v1/projects/hx-web/hosts/export'
ORG = '/api/v1/orgs/hx-acme/hosts/export'


class AccessTests(Base):
    def test_a_project_member_may_export_and_another_organizations_user_gets_not_found(self):
        self.assertEqual(self.get('alice', PROJECT).status_code, 200)
        self.assertEqual(self.get('eve', PROJECT).status_code, 404)  # another tenant cannot tell the project exists
        self.assertEqual(self.get('eve', '/api/v1/projects/hx-nosuch/hosts/export').status_code, 404)

    def test_a_project_the_person_is_not_in_is_not_found_even_inside_their_own_organization(self):
        self.assertEqual(self.get('alice', '/api/v1/projects/hx-api/hosts/export').status_code, 404)
        self.assertEqual(self.get('boss', '/api/v1/projects/hx-api/hosts/export').status_code, 200)

    def test_nothing_without_a_sign_in_and_not_for_all_projects(self):
        self.assertIn(self.get(None, PROJECT).status_code, (401, 403))
        self.assertIn(self.get(None, ORG).status_code, (401, 403))
        self.assertEqual(self.get('root', '/api/v1/projects/_all/hosts/export').status_code, 400)

    def test_a_read_only_token_may_export(self):
        self.assertEqual(self.get(self.t_ro, PROJECT).status_code, 200)

    def test_an_organization_the_person_cannot_see_is_not_found(self):
        self.assertEqual(self.get('eve', ORG).status_code, 404)
        self.assertEqual(self.get('alice', '/api/v1/orgs/hx-other/hosts/export').status_code, 404)
        self.assertEqual(self.get('boss', '/api/v1/orgs/hx-nosuch/hosts/export').status_code, 404)
        self.assertEqual(self.get('eve', '/api/v1/orgs/hx-other/hosts/export').status_code, 200)


class OrganizationTests(Base):
    def test_an_organization_export_holds_every_project_the_person_can_access(self):
        rows = self.rows('boss', ORG)
        self.assertEqual({(r['Project'], r['Host']) for r in rows}, {
            ('Acme Web', 'www.example.com'), ('Acme Web', 'mail.example.com'), ('Acme Web', 'mixed.example.com'),
            ('Acme API', 'api.example.com'), ('Acme API', 'www.example.com')})
        self.assertEqual({r['Organization'] for r in rows}, {'Acme'})

    def test_a_project_member_gets_only_the_projects_they_can_see_and_never_a_project_they_cannot(self):
        rows = self.rows('alice', ORG)
        self.assertEqual({r['Project'] for r in rows}, {'Acme Web'})
        self.assertNotIn('api.example.com', [r['Host'] for r in rows])
        self.assertNotIn('203.0.113.30', self.body(self.get('alice', ORG, format='txt')))

    def test_another_organizations_hosts_never_appear_not_even_for_an_app_admin_asking_for_one_organization(self):
        for who in ('boss', 'alice', 'root'):
            self.assertNotIn('hidden.example.com', self.hosts(who, ORG), who)
        self.assertEqual(self.hosts('eve', '/api/v1/orgs/hx-other/hosts/export'), ['hidden.example.com'])
        self.assertIn('api.example.com', self.hosts('root', ORG))

    def test_the_file_is_named_for_the_project_or_the_organization_and_the_day(self):
        today = timezone.now().strftime('%Y-%m-%d')
        for path, label in ((PROJECT, 'hx-web'), (ORG, 'hx-acme')):
            response = self.get('boss', path)
            self.assertEqual(response['Content-Disposition'], f'attachment; filename="cvengine-hosts-{label}-{today}.csv"')
            self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
            b''.join(response.streaming_content)
        response = self.get('boss', PROJECT, format='txt')
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="cvengine-hosts-hx-web-{today}.txt"')
        self.assertTrue(response['Content-Type'].startswith('text/plain'))
        b''.join(response.streaming_content)


class ScopeTests(Base):
    def test_the_default_is_internet_facing_only(self):
        rows = {r['Host']: r for r in self.rows('boss', PROJECT)}
        self.assertEqual(set(rows), {'www.example.com', 'mail.example.com', 'mixed.example.com'})
        self.assertEqual(rows['mixed.example.com']['IP addresses'], '203.0.113.13')  # its private address is left out, and so is the port on it
        self.assertEqual(rows['mixed.example.com']['Services'], '8080/tcp http-proxy')
        self.assertNotIn('5432', self.body(self.get('boss', PROJECT)))

    def test_scope_all_keeps_internal_hosts_and_private_addresses(self):
        rows = {r['Host']: r for r in self.rows('boss', PROJECT, scope='all')}
        self.assertEqual(set(rows), {'www.example.com', 'mail.example.com', 'mixed.example.com', 'intra.example.com', '10.0.0.5'})
        self.assertEqual(rows['mixed.example.com']['IP addresses'], '10.9.9.9 203.0.113.13')  # in address order
        self.assertIn('5432/tcp PostgreSQL 15', rows['mixed.example.com']['Services'])

    def test_a_host_the_project_declared_internal_is_left_out_of_the_external_list_even_when_its_address_looks_public(self):
        with mock.patch('cveFeed.internal_view.is_internal', side_effect=lambda project_id, name: name == 'mail.example.com'):
            self.assertEqual(set(self.hosts('boss', PROJECT)), {'www.example.com', 'mixed.example.com'})
            self.assertIn('mail.example.com', self.hosts('boss', PROJECT, scope='all'))

    def test_a_host_inside_a_declared_internal_range_is_left_out(self):
        InternalRange.objects.create(project=self.web, cidr='10.20.0.0/24')
        self.host(self.web, '10.20.0.7', '10.20.0.7')
        internal_view.invalidate()
        self.assertNotIn('10.20.0.7', self.hosts('boss', PROJECT))
        self.assertIn('10.20.0.7', self.hosts('boss', PROJECT, scope='all'))

    def test_the_plain_list_of_an_external_export_has_no_private_name_or_address(self):
        text = '\n'.join(self.lines('boss', PROJECT, format='txt'))
        for private in ('10.', 'intra.example.com'):
            self.assertNotIn(private, text)

    def test_an_address_on_the_organizations_do_not_scan_list_is_not_in_a_scope_list(self):
        ExcludedAddress.objects.create(org=self.acme, cidr='203.0.113.11/32')
        self.assertNotIn('mail.example.com', self.hosts('boss', PROJECT, scope='all'))
        self.assertNotIn('203.0.113.11', '\n'.join(self.lines('boss', PROJECT, format='txt', scope='all')))
        self.assertIn('www.example.com', self.hosts('boss', PROJECT, scope='all'))


class ArchivedAndExcludedTests(Base):
    def test_archived_hosts_are_left_out_unless_asked_for(self):
        self.assertNotIn('old.example.com', self.hosts('boss', PROJECT))
        self.assertNotIn('old.example.com', self.hosts('boss', PROJECT, archived='0'))
        self.assertIn('old.example.com', self.hosts('boss', PROJECT, archived='1'))
        self.assertIn('old.example.com', self.lines('boss', PROJECT, format='txt', archived='1'))
        self.assertNotIn('old.example.com', self.lines('boss', PROJECT, format='txt'))

    def test_a_removed_and_excluded_host_is_never_listed(self):
        for params in ({}, {'archived': '1'}, {'scope': 'all', 'archived': '1'}):
            self.assertNotIn('gone.example.com', self.hosts('boss', PROJECT, **params), params)
            self.assertNotIn('gone.example.com', self.hosts('root', ORG, **params), params)
        self.assertNotIn('203.0.113.21', '\n'.join(self.lines('boss', PROJECT, format='txt', scope='all', archived='1')))

    def test_a_domain_excluded_with_its_subdomains_takes_every_name_under_it(self):
        HostExclusion.objects.create(org=self.acme, host='example.com', include_subdomains=True)
        self.assertEqual(self.hosts('boss', PROJECT, scope='all', archived='1'), ['10.0.0.5'])  # the one host not named under example.com


class PlainListTests(Base):
    def test_every_host_name_then_every_address_each_once_and_sorted(self):
        self.host(self.web, 'beta.example.com', '203.0.113.9')
        self.host(self.api, 'alpha.example.com', '203.0.113.9', '203.0.113.100')
        lines = self.lines('boss', ORG, format='txt')
        self.assertEqual(lines, ['alpha.example.com', 'api.example.com', 'beta.example.com', 'mail.example.com', 'mixed.example.com', 'www.example.com',
                                 '203.0.113.9', '203.0.113.10', '203.0.113.11', '203.0.113.13', '203.0.113.30', '203.0.113.100'])
        self.assertEqual(len(lines), len(set(lines)))  # www.example.com is in two projects and 203.0.113.9 on two hosts: each is one line

    def test_a_host_named_by_its_address_is_one_address_line_and_not_a_name_line(self):
        self.host(self.web, '203.0.113.50', '203.0.113.50')
        lines = self.lines('boss', PROJECT, format='txt')
        self.assertEqual(lines.count('203.0.113.50'), 1)
        self.assertGreater(lines.index('203.0.113.50'), lines.index('www.example.com'))

    def test_the_plain_list_has_one_entry_per_line_and_no_header_or_marks(self):
        text = self.body(self.get('boss', PROJECT, format='txt'))
        self.assertFalse(text.startswith('﻿'))
        self.assertTrue(text.endswith('\n'))
        self.assertTrue(all(line and ' ' not in line and ',' not in line for line in text.splitlines()))


class CsvTests(Base):
    def test_the_columns_are_the_scope_columns_and_say_nothing_about_findings(self):
        response = self.get('boss', PROJECT)
        text = self.body(response)
        header = next(csv.reader(io.StringIO(text[1:])))
        self.assertEqual(header, ['Host', 'IP addresses', 'Open TCP ports', 'Open UDP ports', 'Services', 'Web URLs', 'Project', 'Organization', 'Target', 'First seen', 'Last seen'])
        lowered = ' '.join(header).lower()
        for word in ('vuln', 'cve', 'finding', 'heat', 'score', 'owner', 'note', 'label', 'critical', 'severity', 'alias'):
            self.assertNotIn(word, lowered)
        for secret in (FINDING, 'CVE-2099-7', 'nginx bug'):
            self.assertNotIn(secret, text)

    def test_a_host_row_holds_addresses_ports_services_web_urls_and_where_it_was_found(self):
        row = next(r for r in self.rows('boss', PROJECT) if r['Host'] == 'www.example.com')
        self.assertEqual(row['IP addresses'], '203.0.113.10')
        self.assertEqual(row['Open TCP ports'], '80 443')
        self.assertEqual(row['Open UDP ports'], '161')
        self.assertEqual(row['Services'], '80/tcp nginx 1.24.0; 161/udp snmp; 443/tcp nginx 1.24.0')
        self.assertEqual(row['Web URLs'], 'http://www.example.com/; https://www.example.com/')
        self.assertEqual((row['Project'], row['Organization'], row['Target']), ('Acme Web', 'Acme', 'hx-web.example.com'))
        self.assertEqual(row['First seen'], self.seen.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'))

    def test_a_non_web_host_has_no_web_url_and_a_proxy_port_counts_as_web(self):
        rows = {r['Host']: r for r in self.rows('boss', PROJECT)}
        self.assertEqual(rows['mail.example.com']['Web URLs'], '')
        self.assertEqual(rows['mixed.example.com']['Web URLs'], 'http://mixed.example.com:8080/')

    def test_the_first_and_last_seen_come_from_the_projects_record_of_the_host_when_it_has_one(self):
        state = HostState.objects.create(project=self.web, domain=self.dom['hx-web'], host='mail.example.com')
        HostState.objects.filter(pk=state.pk).update(first_seen=timezone.now() - timedelta(days=40), last_seen=timezone.now() - timedelta(days=1))
        row = next(r for r in self.rows('boss', PROJECT) if r['Host'] == 'mail.example.com')
        state.refresh_from_db()
        self.assertEqual(row['First seen'], state.first_seen.strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(row['Last seen'], state.last_seen.strftime('%Y-%m-%dT%H:%M:%SZ'))

    def test_a_cell_a_spreadsheet_would_run_as_a_formula_is_neutralized_like_the_lists_csv_button(self):
        for value in ('=1+1', '+SUM(A1)', '-2', '@cmd', '\tx', '\rx'):
            self.assertTrue(host_export.cell(value).lstrip('"').startswith("'"), repr(value))
        self.assertEqual(host_export.cell('plain'), 'plain')
        self.assertEqual(host_export.cell('a,b'), '"a,b"')
        self.assertEqual(host_export.cell('say "hi"'), '"say ""hi"""')
        self.assertEqual(host_export.cell(None), '')
        self.assertEqual(host_export.cell(['x', 'y']), 'x; y')

    def test_a_host_name_that_starts_like_a_formula_reaches_the_file_as_text(self):
        self.host(self.web, '=cmd|calc.example.com', '203.0.113.12')
        self.host(self.web, '@sum.example.com', '203.0.113.14')
        text = self.body(self.get('boss', PROJECT))
        self.assertIn("'=cmd|calc.example.com,", text)
        self.assertIn("'@sum.example.com,", text)
        self.assertIsNone(re.search(r'(^|\r\n)[=+\-@]', text), 'no line of the file starts a formula')
        self.assertIn('=cmd|calc.example.com', [r['Host'].lstrip("'") for r in self.rows('boss', PROJECT)])

    def test_a_project_or_organization_name_that_starts_like_a_formula_is_neutralized_too(self):
        Project.objects.filter(pk=self.web.pk).update(name='=HYPERLINK("http://x")')
        Org.objects.filter(pk=self.acme.pk).update(name='+Acme')
        rows = self.rows('boss', PROJECT)
        self.assertTrue(rows[0]['Project'].startswith("'=HYPERLINK"))
        self.assertEqual(rows[0]['Organization'], "'+Acme")

    def test_the_file_is_streamed_in_chunks_and_every_chunk_boundary_keeps_every_host(self):
        for n in range(23):
            self.host(self.web, f'bulk{n:02d}.example.com', f'203.0.113.{100 + n}', ports=[(f'203.0.113.{100 + n}', 22, 'ssh', 'OpenSSH', '9')])
        full = self.hosts('boss', PROJECT)
        with mock.patch.object(host_export, 'CHUNK', 5):
            response = self.get('boss', PROJECT)
            self.assertTrue(response.streaming)
            small = list(csv.DictReader(io.StringIO(self.body(response)[1:], newline='')))
        self.assertEqual([r['Host'] for r in small], full)
        self.assertEqual(len(full), 26)  # nothing caps it: the 20,000 rows of the list's CSV button do not apply here

    def test_the_response_carries_the_count_of_hosts(self):
        response = self.get('boss', PROJECT)
        b''.join(response.streaming_content)
        self.assertEqual(response['X-Export-Hosts'], '3')
        self.assertEqual(response['X-Export-Entries'], '3')
        self.assertEqual(response['Cache-Control'], 'no-store')
        response = self.get('boss', PROJECT, format='txt')
        b''.join(response.streaming_content)
        self.assertEqual((response['X-Export-Hosts'], response['X-Export-Entries']), ('3', '6'))  # three hosts, three names and three addresses


class ParameterTests(Base):
    def test_a_bad_value_is_a_400_that_names_the_parameter(self):
        for params, word in (({'format': 'xlsx'}, 'format'), ({'scope': 'everything'}, 'scope'), ({'archived': 'maybe'}, 'archived')):
            response = self.get('boss', PROJECT, **params)
            self.assertEqual(response.status_code, 400, params)
            self.assertIn(word, response.json()['error'])

    def test_the_words_true_and_false_work_for_archived(self):
        self.assertIn('old.example.com', self.hosts('boss', PROJECT, archived='true'))
        self.assertNotIn('old.example.com', self.hosts('boss', PROJECT, archived='false'))


class AuditTests(Base):
    def test_who_exported_what_is_written_before_the_file_is_sent(self):
        response = self.get('boss', PROJECT, scope='all', format='txt', archived='1')
        row = AuditLog.objects.get(action='host.export')  # written before a byte was read
        b''.join(response.streaming_content)
        self.assertEqual(row.actor, self.boss)
        self.assertEqual(row.org, self.acme)
        self.assertIn('hx-web', row.target)
        self.assertEqual({k: row.detail[k] for k in ('project', 'scope', 'format', 'archived', 'hosts')},
                         {'project': 'hx-web', 'scope': 'all', 'format': 'txt', 'archived': True, 'hosts': 6})

    def test_an_organization_export_names_the_organization_and_the_projects_it_covered(self):
        b''.join(self.get('alice', ORG).streaming_content)
        row = AuditLog.objects.get(action='host.export')
        self.assertEqual((row.actor, row.org), (self.alice, self.acme))
        self.assertEqual((row.detail['organization'], row.detail['projects']), ('hx-acme', ['hx-web']))

    def test_a_refused_export_writes_nothing(self):
        self.get('eve', PROJECT)
        self.get('boss', PROJECT, format='nope')
        self.assertFalse(AuditLog.objects.filter(action='host.export').exists())


class McpTests(Base):
    def test_the_tool_returns_the_text_of_the_file(self):
        error, out = tool_call(self.t['boss'], 'export_hosts', {'project': 'hx-web'})
        self.assertFalse(error, out)
        self.assertEqual((out['format'], out['scope'], out['hosts'], out['projects']), ('csv', 'external', 3, ['hx-web']))
        self.assertTrue(out['filename'].startswith('cvengine-hosts-hx-web-') and out['filename'].endswith('.csv'))
        self.assertEqual([r['Host'] for r in csv.DictReader(io.StringIO(out['content'][1:], newline=''))], ['mail.example.com', 'mixed.example.com', 'www.example.com'])

    def test_an_organization_in_the_plain_format_with_the_same_parameters(self):
        error, out = tool_call(self.t['boss'], 'export_hosts', {'org': 'hx-acme', 'format': 'txt', 'scope': 'all', 'archived': True})
        self.assertFalse(error, out)
        self.assertEqual(out['projects'], ['hx-api', 'hx-web'])
        self.assertIn('old.example.com', out['content'].splitlines())
        self.assertIn('10.1.2.3', out['content'].splitlines())

    def test_the_tool_enforces_the_same_access_and_asks_for_exactly_one_of_project_and_org(self):
        self.assertTrue(tool_call(self.t['eve'], 'export_hosts', {'project': 'hx-web'})[0])
        self.assertTrue(tool_call(self.t['eve'], 'export_hosts', {'org': 'hx-acme'})[0])
        self.assertTrue(tool_call(self.t['boss'], 'export_hosts', {'project': 'hx-web', 'org': 'hx-acme'})[0])
        self.assertTrue(tool_call(self.t['boss'], 'export_hosts', {})[0])
        self.assertTrue(tool_call(self.t['boss'], 'export_hosts', {'project': 'hx-web', 'format': 'pdf'})[0])
        self.assertTrue(tool_call(self.t['boss'], 'export_hosts', {'project': '_all'})[0])

    def test_a_list_too_big_for_an_answer_points_at_the_download(self):
        with mock.patch.object(host_export, 'MCP_MAX_BYTES', 100):
            error, text = tool_call(self.t['boss'], 'export_hosts', {'project': 'hx-web'})
        self.assertTrue(error)
        self.assertIn('host.export', text)
