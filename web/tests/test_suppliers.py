import json
import os
import socket
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import ledger, probes, route_auth, slow_web, supplier_checks as sc, supplier_scan as ss, supplier_search, versions
from cveFeed.models import (BountyEngagement, BountyProgram, CVEEntry, HostExclusion, HygieneFinding, ServiceRun, Supplier, SupplierFinding,
                            SupplierHostCard)
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call
from tests.test_tenancy import client_for

PUBLIC = '203.0.113.10'
GOOD_HEADERS = {'strict-transport-security': 'max-age=31536000', 'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
                'x-content-type-options': 'nosniff'}
HTML = '<html><head><title>Vendor portal</title></head><body>Welcome</body></html>'
NO_WAIT = dict(sleep=lambda seconds: None, per_host=0, overall=0)


def page(status=200, body=HTML, server='nginx', powered_by='', headers=None, ctype='text/html', location='', **extra):
    """A response in the shape ``slow_web.get`` returns."""
    raw = {'content-type': ctype, **({'server': server} if server else {}), **({'x-powered-by': powered_by} if powered_by else {}), **(headers or {})}
    return {'status': status, 'location': location, 'www_authenticate': extra.get('www_authenticate', ''), 'cookies': extra.get('cookies', []),
            'content_type': ctype, 'body': body, 'title': route_auth.page_title(body), 'bytes': len(body), 'server': server, 'powered_by': powered_by,
            'headers': versions.keep_headers(raw), 'raw_headers': raw}


def cert(name, days=200, **kw):
    now = timezone.now()
    return {'host': name, 'port': 443, 'subject': name, 'issuer': 'Example CA', 'sans': [name], 'not_before': now - timedelta(days=100),
            'not_after': now + timedelta(days=days), 'signature_algorithm': 'sha256 (sha256WithRSAEncryption)', 'key_description': 'RSA 2048',
            'protocol': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384', 'chain_error': '', 'legacy_tls': False, **kw}


class FakeNet:
    """The whole network of a supplier check: names, pages, certificates and DNS records, and a log of every call. Nothing leaves the process."""

    def __init__(self):
        self.ips, self.pages, self.certs, self.records_txt, self.mx, self.sts_policy, self.known = {}, {}, {}, {}, set(), {}, set()
        self.calls = []

    def site(self, name, ip=PUBLIC, https=None, http=None, tls='good', paths=None, mail=False, server='nginx', powered_by='', headers=None):
        self.ips[name] = [ip] if isinstance(ip, str) else ip
        self.known.add(name)
        self.pages[f'https://{name}/'] = https if https is not None else page(headers={**GOOD_HEADERS, **(headers or {})}, server=server, powered_by=powered_by)
        self.pages[f'http://{name}/'] = http if http is not None else page(301, '', location=f'https://{name}/')
        self.certs[name] = cert(name) if tls == 'good' else tls
        for path, response in (paths or {}).items():
            self.pages[f'https://{name}{path}'] = response
        if mail:
            self.good_mail(name)
        return self

    def good_mail(self, name):
        self.known.add(name)
        self.mx.add(name)
        self.records_txt[name] = ['v=spf1 include:_spf.mail.example.test -all']
        self.records_txt[f'_dmarc.{name}'] = ['v=DMARC1; p=reject; rua=mailto:dmarc@' + name]

    # --- the Network interface
    def resolve(self, name):
        self.calls.append(('resolve', name))
        if name in self.ips:
            return list(self.ips[name])
        raise socket.gaierror(socket.EAI_NONAME, 'not found')

    def fetch(self, url, ip):
        self.calls.append(('fetch', url, ip))
        got = self.pages.get(url, page(404, '<html><title>Not found</title></html>'))
        if isinstance(got, Exception):
            raise got
        return {**got, 'url': url, 'challenge': probes.challenge_of(got)}

    def tls(self, name, addresses):
        self.calls.append(('tls', name, tuple(addresses)))
        got = self.certs.get(name)
        if isinstance(got, Exception):
            raise got
        return got

    def dns_state(self, name):
        return 'ok' if name in self.known else 'nxdomain'

    def txt(self, name):
        return list(self.records_txt.get(name, []))

    def records(self, name, rtype):
        return []

    def has_record(self, name, rtype):
        return rtype == 'MX' and name in self.mx

    def mta_sts_policy(self, domain, addresses):
        self.calls.append(('mta-sts', domain))
        return self.sts_policy.get(domain)

    @property
    def fetched(self):
        return [c[1] for c in self.calls if c[0] == 'fetch']

    @property
    def connections(self):
        return [c for c in self.calls if c[0] in ('fetch', 'tls', 'mta-sts')]


class Fixture:
    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.org1, self.org2 = Org.objects.create(name='One', slug='sup-one'), Org.objects.create(name='Two', slug='sup-two')
        self.project = Project.objects.create(name='Alpha', slug='sup-a', insert_date=now, org=self.org1)
        self.other_project = Project.objects.create(name='Beta', slug='sup-b', insert_date=now, org=self.org2)
        for patch in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('reNgine.tasks.geo_localize.delay'),
                      mock.patch('cveFeed.tasks.run_hygiene_task.delay'), mock.patch('cveFeed.tasks.watch_certificate_transparency.delay')):
            patch.start()
        self.addCleanup(mock.patch.stopall)
        self.own = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        mk = lambda n: User.objects.create_user(n, password='x')
        self.admin, self.member, self.auditor, self.stranger = mk('sup-admin'), mk('sup-member'), mk('sup-auditor'), mk('sup-stranger')
        OrgMembership.objects.create(user=self.admin, org=self.org1, role='admin')
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')
        ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')
        OrgMembership.objects.create(user=self.stranger, org=self.org2, role='admin')
        self.t_admin = create_token(self.admin, 'a')[1]
        self.t_admin_ro = create_token(self.admin, 'ro', read_only=True)[1]
        self.t_member = create_token(self.member, 'm')[1]
        self.t_auditor = create_token(self.auditor, 'u')[1]
        self.t_stranger = create_token(self.stranger, 's')[1]
        self.net = FakeNet()

    def supplier(self, name='Acme Hosting', tier='critical', domains=('portal.vendor.test',), project=None):
        return Supplier.objects.create(project=project or self.project, name=name, tier=tier, domains=list(domains), added_by=self.admin)

    def sweep(self, net=None, **kw):
        self.net = net or self.net
        kw.setdefault('pace', slow_web.Pace(**NO_WAIT))
        return ss.sweep(self.project.id, net=self.net, **kw)

    def expire(self):
        ServiceRun.objects.filter(service__in=(ss.SERVICE, ss.FAILED_SERVICE)).delete()

    def finding(self, supplier, domain, check):
        return SupplierFinding.objects.get(supplier=supplier, domain=domain, check_name=check)

    def checks(self, supplier, status='open'):
        return sorted(SupplierFinding.objects.filter(supplier=supplier, status=status).values_list('check_name', flat=True))


# ----------------------------------------------------------------------------- validation

class DomainValidationTests(SimpleTestCase):
    def test_a_name_is_lowercased_and_stripped_of_its_trailing_dot(self):
        self.assertEqual(ss.clean_domain(' Portal.Vendor.TEST. '), 'portal.vendor.test')

    def test_everything_that_is_not_a_plain_dns_name_is_refused(self):
        for bad in ('*.vendor.test', 'https://vendor.test', 'vendor.test/path', 'user@vendor.test', 'vendor.test:443', '203.0.113.5', '10.0.0.0/24',
                    '203.0.113.1-9', '::1', 'localhost', 'db.internal', 'printer.local', 'nodots', 'bad_name.vendor.test', 'two words.test', 'ünï.test', '',
                    '  ', 'a..b.test', '-x.test', 'x.' + 'a' * 64 + '.test', 'x.test?y=1', 'x.test#frag', 'host.home.arpa', 'abcdefghijklmnop.onion'):
            with self.assertRaises(ss.SupplierError, msg=repr(bad)):
                ss.clean_domain(bad)
        for bad in (None, 5, ['a.test'], {'a': 1}):
            with self.assertRaises(ss.SupplierError):
                ss.clean_domain(bad)

    def test_the_refusal_says_why(self):
        for value, word in (('*.vendor.test', 'wildcard'), ('https://vendor.test', 'URL'), ('203.0.113.5', 'by address'), ('db.internal', 'private')):
            with self.assertRaisesRegex(ss.SupplierError, word):
                ss.clean_domain(value)

    def test_text_is_bounded_and_stripped_of_control_characters(self):
        self.assertEqual(ss.clean_text(' a\x00b\x07 ', 10, 'x'), 'ab')
        with self.assertRaises(ss.SupplierError):
            ss.clean_text('x' * 11, 10, 'x')
        with self.assertRaises(ss.SupplierError):
            ss.clean_text('', 10, 'name', required=True)
        with self.assertRaises(ss.SupplierError):
            ss.clean_tier('urgent')
        self.assertEqual(ss.clean_tier(None), 'normal')

    def test_the_settings_have_safe_defaults_and_bounds(self):
        self.assertEqual((ss.max_per_project(), ss.max_domains(), ss.max_requests()), (50, 10, 600))
        with mock.patch.dict(os.environ, {'CVENGINE_SUPPLIERS_MAX_PER_PROJECT': '999999', 'CVENGINE_SUPPLIERS_MAX_DOMAINS': '0', 'CVENGINE_SUPPLIERS_MAX_REQUESTS': 'x'}):
            self.assertEqual((ss.max_per_project(), ss.max_domains(), ss.max_requests()), (500, 1, 600))
        for off in ('0', 'false', 'off'):
            with mock.patch.dict(os.environ, {'CVENGINE_SUPPLIERS': off}):
                self.assertFalse(ss.enabled())
        self.assertTrue(ss.enabled())


class ProjectRulesTests(Fixture, TestCase):
    def test_a_name_that_is_one_of_the_projects_own_targets_or_under_one_is_refused(self):
        for name in ('example.test', 'www.example.test', 'a.b.example.test'):
            with self.assertRaisesRegex(ss.SupplierError, 'own targets'):
                ss.clean_domains(self.project, [name])
        self.assertEqual(ss.clean_domains(self.project, ['notexample.test', 'example.test.vendor.test']), ['notexample.test', 'example.test.vendor.test'])
        self.assertEqual(ss.clean_domains(self.other_project, ['example.test']), ['example.test'])  # another project's target is no business of this one

    def test_a_name_is_listed_once_per_project_and_the_organizations_exclusions_hold(self):
        self.supplier(domains=['portal.vendor.test'])
        with self.assertRaisesRegex(ss.SupplierError, 'already listed under the supplier Acme Hosting'):
            ss.clean_domains(self.project, ['portal.vendor.test'])
        self.assertEqual(ss.clean_domains(self.other_project, ['portal.vendor.test']), ['portal.vendor.test'])
        HostExclusion.objects.create(org=self.org1, host='gone.vendor.test')
        with self.assertRaisesRegex(ss.SupplierError, 'excluded'):
            ss.clean_domains(self.project, ['gone.vendor.test'])

    def test_a_list_is_distinct_and_capped(self):
        self.assertEqual(ss.clean_domains(self.project, ['A.vendor.test', 'a.vendor.test', 'b.vendor.test']), ['a.vendor.test', 'b.vendor.test'])
        self.assertEqual(ss.clean_domains(self.project, 'a.vendor.test, b.vendor.test'), ['a.vendor.test', 'b.vendor.test'])
        with mock.patch.dict(os.environ, {'CVENGINE_SUPPLIERS_MAX_DOMAINS': '2'}):
            with self.assertRaisesRegex(ss.SupplierError, 'at most 2'):
                ss.clean_domains(self.project, ['a.vendor.test', 'b.vendor.test', 'c.vendor.test'])
        for empty in ([], '', None):
            with self.assertRaises(ss.SupplierError):
                ss.clean_domains(self.project, empty)


# ----------------------------------------------------------------------------- roles, tenancy and the API

class ApiTests(Fixture, TestCase):
    base = '/api/v1/projects/sup-a/suppliers'

    def add(self, token, **body):
        body = {'name': 'Acme Hosting', 'domains': ['portal.vendor.test'], 'tier': 'critical', **body}
        return call(token, 'POST', self.base, body)

    def test_an_organization_admin_adds_and_lists_a_supplier(self):
        status, data = self.add(self.t_admin, contact='support at vendor', notes='hosts our portal')
        self.assertEqual(status, 201)
        self.assertEqual((data['name'], data['tier'], data['domains'], data['added_by']['username']), ('Acme Hosting', 'critical', ['portal.vendor.test'], 'sup-admin'))
        status, listing = call(self.t_admin, 'GET', self.base)
        self.assertEqual((status, listing['count'], listing['can_edit']), (200, 1, True))
        self.assertEqual(listing['results'][0]['findings']['open'], 0)
        self.assertEqual(listing['limits'], {'max_suppliers': 50, 'max_domains': 10})
        self.assertTrue(AuditLog.objects.filter(action='project.supplier.add').exists())

    def test_a_member_and_an_auditor_can_read_but_not_add_or_remove(self):
        supplier = self.supplier()
        for token, can_edit in ((self.t_member, False), (self.t_auditor, False)):
            status, listing = call(token, 'GET', self.base)
            self.assertEqual((status, listing['count'], listing['can_edit']), (200, 1, can_edit))
            self.assertEqual(self.add(token, name='Other', domains=['x.vendor.test'])[0], 403)
            self.assertEqual(call(token, 'DELETE', f'{self.base}/{supplier.id}')[0], 403)
        self.assertEqual(Supplier.objects.count(), 1)

    def test_a_read_only_token_cannot_write_even_for_an_admin(self):
        self.assertEqual(self.add(self.t_admin_ro)[0], 403)
        self.assertEqual(call(self.t_admin_ro, 'GET', self.base)[1]['can_edit'], False)

    def test_another_organization_cannot_see_or_touch_the_project(self):
        supplier = self.supplier()
        self.assertEqual(call(self.t_stranger, 'GET', self.base)[0], 404)
        self.assertEqual(self.add(self.t_stranger)[0], 404)
        self.assertEqual(call(self.t_stranger, 'DELETE', f'{self.base}/{supplier.id}')[0], 404)
        self.assertEqual(call(self.t_stranger, 'GET', f'{self.base}/hosts')[0], 404)
        self.assertEqual(call(self.t_stranger, 'GET', f'{self.base}/findings')[0], 404)
        self.assertEqual(call(self.t_stranger, 'GET', f'{self.base}/{supplier.id}/summary')[0], 404)
        # ... and its own project lists none of Alpha's suppliers, and cannot reach one by id
        self.assertEqual(call(self.t_stranger, 'GET', '/api/v1/projects/sup-b/suppliers')[1]['count'], 0)
        self.assertEqual(call(self.t_stranger, 'DELETE', f'/api/v1/projects/sup-b/suppliers/{supplier.id}')[0], 404)
        self.assertEqual(Supplier.objects.count(), 1)

    def test_the_data_layer_scope_hides_other_projects_rows(self):
        from tenancy import scope
        supplier = self.supplier()
        SupplierFinding.objects.create(supplier=supplier, domain='portal.vendor.test', check_name='x', title='t')
        SupplierHostCard.objects.create(supplier=supplier, domain='portal.vendor.test')
        tokens = scope.set_scope({self.other_project.id})
        try:
            self.assertEqual((Supplier.objects.count(), SupplierFinding.objects.count(), SupplierHostCard.objects.count()), (0, 0, 0))
        finally:
            scope.reset_scope(tokens)
        tokens = scope.set_scope({self.project.id})
        try:
            self.assertEqual((Supplier.objects.count(), SupplierFinding.objects.count(), SupplierHostCard.objects.count()), (1, 1, 1))
        finally:
            scope.reset_scope(tokens)

    def test_bad_input_is_a_400_and_a_name_or_a_cap_a_409(self):
        for body in ({'domains': ['example.test']}, {'domains': ['www.example.test']}, {'domains': ['203.0.113.5']}, {'domains': ['*.vendor.test']},
                     {'domains': ['db.internal']}, {'domains': []}, {'domains': 'a'}, {'tier': 'urgent'}, {'name': ''}, {'name': 'x' * 121}, {'notes': 'x' * 2001}):
            self.assertEqual(self.add(self.t_admin, **body)[0], 400, body)
        self.assertEqual(self.add(self.t_admin)[0], 201)
        self.assertEqual(self.add(self.t_admin, name='acme hosting', domains=['other.vendor.test'])[0], 409)  # the name, whatever its case
        self.assertEqual(self.add(self.t_admin, name='Second', domains=['portal.vendor.test'])[0], 400)  # the domain is taken
        with mock.patch.dict(os.environ, {'CVENGINE_SUPPLIERS_MAX_PER_PROJECT': '1'}):
            self.assertEqual(self.add(self.t_admin, name='Third', domains=['third.vendor.test'])[0], 409)
        self.assertEqual(Supplier.objects.count(), 1)
        self.assertEqual(call(self.t_admin, 'POST', self.base, [1])[0], 400)

    def test_an_admin_removes_a_supplier_with_its_cards_and_findings(self):
        supplier = self.supplier()
        SupplierFinding.objects.create(supplier=supplier, domain='portal.vendor.test', check_name='x', title='t')
        SupplierHostCard.objects.create(supplier=supplier, domain='portal.vendor.test')
        self.assertEqual(call(self.t_admin, 'DELETE', f'{self.base}/{supplier.id}'), (200, {'deleted': True}))
        self.assertEqual((Supplier.objects.count(), SupplierFinding.objects.count(), SupplierHostCard.objects.count()), (0, 0, 0))
        self.assertEqual(call(self.t_admin, 'DELETE', f'{self.base}/{supplier.id}')[0], 404)
        self.assertTrue(AuditLog.objects.filter(action='project.supplier.remove').exists())

    def test_the_all_projects_view_is_read_only_and_not_offered(self):
        self.assertEqual(call(self.t_admin, 'GET', '/api/v1/projects/_all/suppliers')[0], 400)
        self.assertEqual(self.add(self.t_admin, **{}) [0], 201)
        self.assertEqual(call(self.t_admin, 'POST', '/api/v1/projects/_all/suppliers', {'name': 'x', 'domains': ['x.vendor.test']})[0], 400)

    def test_the_mcp_tools_follow_the_same_rules(self):
        from tests.test_agentapi import rpc
        names = {t['name'] for t in rpc(self.t_admin, 'tools/list')[1]['result']['tools']}
        for tool in ('list_suppliers', 'add_supplier', 'remove_supplier', 'list_supplier_findings', 'search_supplier_technology', 'list_supplier_technologies',
                     'set_supplier_finding_status', 'get_supplier_message'):
            self.assertIn(tool, names)
        error, added = tool_call(self.t_admin, 'add_supplier', {'project': 'sup-a', 'name': 'Acme', 'domains': ['portal.vendor.test'], 'tier': 'high'})
        self.assertFalse(error)
        error, listed = tool_call(self.t_member, 'list_suppliers', {'project': 'sup-a'})
        self.assertEqual((error, listed['count']), (False, 1))
        error, message = tool_call(self.t_member, 'add_supplier', {'project': 'sup-a', 'name': 'X', 'domains': ['x.vendor.test']})
        self.assertTrue(error)
        self.assertIn('organization admin', message)
        error, message = tool_call(self.t_admin_ro, 'add_supplier', {'project': 'sup-a', 'name': 'X', 'domains': ['x.vendor.test']})
        self.assertTrue(error)
        error, message = tool_call(self.t_admin, 'add_supplier', {'project': 'sup-a', 'name': 'X', 'domains': ['example.test']})
        self.assertTrue(error)
        self.assertIn('own targets', message)
        error, message = tool_call(self.t_stranger, 'list_suppliers', {'project': 'sup-a'})
        self.assertTrue(error)
        error, removed = tool_call(self.t_member, 'remove_supplier', {'project': 'sup-a', 'supplier': added['id']})
        self.assertTrue(error)
        error, removed = tool_call(self.t_admin, 'remove_supplier', {'project': 'sup-a', 'supplier': added['id']})
        self.assertEqual((error, removed), (False, {'deleted': True}))

    def test_a_finding_is_accepted_by_an_admin_only_and_a_resolved_one_is_left_alone(self):
        supplier = self.supplier()
        row = SupplierFinding.objects.create(supplier=supplier, domain='portal.vendor.test', check_name='hsts_missing', severity=2, title='t', category='web')
        url = f'{self.base}/findings/{row.id}'
        self.assertEqual(call(self.t_member, 'PATCH', url, {'status': 'accepted'})[0], 403)
        self.assertEqual(call(self.t_admin, 'PATCH', url, {'status': 'resolved'})[0], 400)
        status, data = call(self.t_admin, 'PATCH', url, {'status': 'accepted', 'note': 'vendor knows, fix in Q3'})
        self.assertEqual((status, data['status'], data['status_note'], data['status_by']['username']), (200, 'accepted', 'vendor knows, fix in Q3', 'sup-admin'))
        self.assertEqual(call(self.t_member, 'GET', f'{self.base}/findings')[1]['count'], 0)  # no longer in the open list
        self.assertEqual(call(self.t_member, 'GET', f'{self.base}/findings?status=accepted')[1]['count'], 1)
        SupplierFinding.objects.filter(pk=row.id).update(status='resolved')
        self.assertEqual(call(self.t_admin, 'PATCH', url, {'status': 'open'})[0], 409)
        self.assertEqual(call(self.t_admin, 'PATCH', f'{self.base}/findings/999999', {'status': 'open'})[0], 404)

    def test_findings_filter_by_status_severity_category_and_supplier(self):
        a, b = self.supplier(), self.supplier('Beta Co', domains=['b.vendor.test'])
        mk = lambda s, check, sev, cat, status='open': SupplierFinding.objects.create(supplier=s, domain='x.vendor.test', check_name=check, severity=sev, title=check,
                                                                                    category=cat, status=status)
        mk(a, 'tls_expired', 4, 'tls')
        mk(a, 'hsts_missing', 2, 'web')
        mk(b, 'cve_php', 3, 'cve')
        mk(b, 'old', 3, 'tls', 'resolved')
        get = lambda q='': call(self.t_member, 'GET', f'{self.base}/findings{q}')[1]
        self.assertEqual([r['check'] for r in get()['results']], ['tls_expired', 'cve_php', 'hsts_missing'])  # worst first
        self.assertEqual(get('?severity=high')['count'], 2)
        self.assertEqual(get('?category=cve')['count'], 1)
        self.assertEqual(get(f'?supplier={b.id}')['count'], 1)
        self.assertEqual(get('?status=resolved')['count'], 1)
        self.assertEqual(get('?status=all')['count'], 4)
        self.assertEqual(call(self.t_member, 'GET', f'{self.base}/findings?status=bogus')[0], 400)
        self.assertEqual(call(self.t_member, 'GET', f'{self.base}/findings?severity=bogus')[0], 400)
        self.assertEqual(get()['results'][0]['severity'], 'critical')


# ----------------------------------------------------------------------------- the four checks, with the network injected

class CheckTests(Fixture, TestCase):
    D = 'portal.vendor.test'

    def run_domain(self, net=None, domain=None, **kw):
        net = net or self.net
        res = ss.check_domain(domain or self.D, net, slow_web.Pace(**NO_WAIT), ss.Budget(1000), kw.pop('pool', lambda: ({}, {})), **kw)
        return res, {p.check: p for p in res.postures}

    def test_a_healthy_supplier_has_no_findings_and_a_full_card(self):
        self.net.site(self.D, server='nginx/1.25.3')
        res, found = self.run_domain()
        self.assertEqual(found, {})
        self.assertEqual(res.card['state'], 'ok')
        self.assertEqual(res.card['addresses'], [PUBLIC])
        self.assertEqual(res.card['tls']['issuer'], 'Example CA')
        self.assertEqual(res.card['http']['https_status'], 200)

    # --- TLS and certificates
    def test_an_expired_certificate_is_critical_and_one_that_expires_soon_is_not(self):
        self.net.site(self.D, tls=cert(self.D, days=-3))
        _, found = self.run_domain()
        self.assertEqual(found['tls_expired'].severity, sc.CRITICAL)
        self.assertEqual(found['tls_expired'].category, 'tls')
        self.assertIn('renew', found['tls_expired'].ask)
        self.net.site(self.D, tls=cert(self.D, days=20))
        _, found = self.run_domain()
        self.assertEqual(found['tls_expiring'].severity, sc.MEDIUM)

    def test_a_certificate_for_another_name_a_weak_key_and_old_protocols_are_findings(self):
        self.net.site(self.D, tls=cert(self.D, sans=['other.test'], subject='other.test', key_description='RSA 1024', legacy_tls=True,
                                       signature_algorithm='sha1 (sha1WithRSAEncryption)', chain_error='self-signed certificate'))
        _, found = self.run_domain()
        self.assertEqual({'tls_hostname_mismatch', 'tls_weak_key', 'tls_weak_signature', 'tls_legacy_protocol', 'tls_self_signed'}, set(found))

    def test_the_tls_read_goes_only_to_the_vetted_address_on_port_443(self):
        self.net.site(self.D)
        self.run_domain()
        self.assertEqual([c for c in self.net.calls if c[0] == 'tls'], [('tls', self.D, (PUBLIC,))])
        self.assertEqual(ss.numeric_addresses([PUBLIC, '2001:db8::1']), ((socket.AF_INET, (PUBLIC, 443)), (socket.AF_INET6, ('2001:db8::1', 443, 0, 0))))

    def test_a_certificate_that_could_not_be_read_decides_nothing(self):
        self.net.site(self.D, tls=None)
        res, found = self.run_domain()
        self.assertNotIn('tls', res.resolvable)
        self.assertNotIn('tls', res.card)
        self.net.site(self.D, tls=ValueError('unparseable'))
        res, _ = self.run_domain()
        self.assertNotIn('tls', res.resolvable)

    # --- email authentication
    def test_a_mail_domain_without_spf_dmarc_or_mta_sts_is_reported(self):
        self.net.site(self.D)
        self.net.mx.add(self.D)
        res, found = self.run_domain()
        self.assertEqual(found['spf_missing'].severity, sc.MEDIUM)
        self.assertEqual(found['dmarc_missing'].severity, sc.HIGH)
        self.assertEqual(found['mta_sts_missing'].severity, sc.LOW)  # an INFO for owned hosts, a finding for a supplier that receives your mail
        self.assertTrue(all(p.category == 'email' for k, p in found.items() if k.startswith(('spf', 'dmarc', 'mta'))))
        self.assertEqual(res.resolvable['email'], {''})
        self.assertEqual(res.card['mail'], {'handles_mail': True, 'mx': True})

    def test_weak_spf_dmarc_dkim_and_a_testing_mta_sts_policy(self):
        self.net.site(self.D)
        self.net.mx.add(self.D)
        self.net.records_txt[self.D] = ['v=spf1 +all']
        self.net.records_txt[f'_dmarc.{self.D}'] = ['v=DMARC1; p=none']
        self.net.records_txt[f'_mta-sts.{self.D}'] = ['v=STSv1; id=1']
        self.net.ips[f'mta-sts.{self.D}'] = [PUBLIC]
        self.net.sts_policy[self.D] = 'version: STSv1\nmode: testing\nmx: mail.vendor.test\nmax_age: 86400'
        _, found = self.run_domain()
        self.assertEqual(found['spf_allow_all'].severity, sc.CRITICAL)
        self.assertEqual(found['dmarc_none'].severity, sc.MEDIUM)
        self.assertEqual(found['mta_sts_not_enforced'].severity, sc.MEDIUM)
        self.assertNotIn('mta_sts_missing', found)
        self.assertIn(('mta-sts', self.D), self.net.calls)

    def test_a_clean_mail_domain_has_no_email_findings(self):
        self.net.site(self.D, mail=True)
        self.net.records_txt[f'_mta-sts.{self.D}'] = ['v=STSv1; id=1']
        self.net.ips[f'mta-sts.{self.D}'] = [PUBLIC]
        self.net.sts_policy[self.D] = 'version: STSv1\nmode: enforce\nmx: mail.vendor.test\nmax_age: 604800'
        _, found = self.run_domain()
        self.assertEqual([k for k, p in found.items() if p.category == 'email' and k.split('_')[0] in ('spf', 'dmarc', 'mta')], [])

    def test_the_mta_sts_policy_host_is_vetted_like_every_other_connection(self):
        self.net.site(self.D)
        self.net.mx.add(self.D)
        self.net.records_txt[f'_mta-sts.{self.D}'] = ['v=STSv1; id=1']
        self.net.ips[f'mta-sts.{self.D}'] = ['10.1.2.3']
        _, found = self.run_domain()
        self.assertNotIn(('mta-sts', self.D), self.net.calls)
        self.assertIn('mta_sts_policy_unreachable', found)

    def test_dns_that_fails_on_the_way_makes_the_email_review_inconclusive(self):
        self.net.site(self.D)
        self.net.mx.add(self.D)
        states = iter(['ok', 'unknown'])
        with mock.patch.object(self.net, 'dns_state', side_effect=lambda name: next(states)):
            res, found = self.run_domain()
        self.assertNotIn('email', res.resolvable)
        self.assertNotIn('spf_missing', found)

    def test_a_name_that_handles_no_mail_gets_no_email_findings(self):
        self.net.site(self.D)
        res, found = self.run_domain()
        self.assertNotIn('email', res.resolvable)
        self.assertEqual(res.card['mail'], {'handles_mail': False, 'mx': False})

    def test_a_mail_only_name_with_no_address_is_still_reviewed_and_never_contacted(self):
        self.net.known.add('mail.vendor.test')
        self.net.mx.add('mail.vendor.test')
        res, found = self.run_domain(domain='mail.vendor.test')
        self.assertIn('spf_missing', found)
        self.assertEqual(res.card['state'], 'no_address')
        self.assertEqual(self.net.connections, [])

    # --- headers and exposed pages
    def test_missing_security_headers_and_plain_http_are_findings(self):
        self.net.site(self.D, https=page(headers={}), http=page(200))
        res, found = self.run_domain()
        self.assertEqual(found['hsts_missing'].severity, sc.MEDIUM)
        self.assertEqual(found['security_headers_missing'].evidence['missing'], ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options'])
        self.assertEqual(found['http_no_redirect'].severity, sc.MEDIUM)
        self.net.site(self.D, https=page(headers={**GOOD_HEADERS, 'strict-transport-security': 'max-age=300'}))
        _, found = self.run_domain()
        self.assertEqual(found['hsts_weak'].severity, sc.LOW)
        self.assertNotIn('hsts_missing', found)

    def test_a_site_that_answers_only_over_plain_http_is_high(self):
        self.net.site(self.D, https=OSError('refused'), http=page(200), tls=None)
        _, found = self.run_domain()
        self.assertEqual(found['no_https'].severity, sc.HIGH)

    def test_a_listed_admin_page_is_reported_once_with_one_plain_get_per_path(self):
        phpmyadmin = page(200, '<html><title>phpMyAdmin</title><body>phpMyAdmin login</body></html>')
        self.net.site(self.D, paths={'/phpmyadmin/': phpmyadmin, '/manager/html': page(401, '', www_authenticate='Basic realm="Tomcat Manager Application"'),
                                     '/login': page(200, '<title>Sign in [Jenkins]</title>')})
        _, found = self.run_domain()
        self.assertEqual(found['exposed_phpmyadmin'].severity, sc.MEDIUM)
        self.assertEqual(found['exposed_tomcat_manager'].severity, sc.MEDIUM)
        self.assertEqual(found['exposed_login_jenkins'].severity, sc.MEDIUM)
        self.assertEqual(found['exposed_phpmyadmin'].category, 'exposed')
        paths = [u for u in self.net.fetched if u.startswith(f'https://{self.D}/') and u != f'https://{self.D}/']
        self.assertEqual(sorted(paths), sorted(f'https://{self.D}{p}' for p in sc.PATHS))  # each path asked exactly once, from the fixed list
        self.assertEqual(len(sc.PATHS), len(set(sc.PATHS)))
        self.assertLessEqual(len(sc.PATHS), 12)

    def test_a_catch_all_that_answers_200_to_everything_is_not_a_finding(self):
        catch_all = page(200, HTML + '<input type="password">')
        self.net.site(self.D, https=page(200, HTML + '<input type="password">', headers=GOOD_HEADERS))
        for path in sc.PATHS:
            self.net.pages[f'https://{self.D}{path}'] = catch_all
        _, found = self.run_domain()
        self.assertEqual([k for k in found if k.startswith('exposed_')], [])
        self.net.pages[f'https://{self.D}/admin/'] = page(200, '<html><title>Admin sign in</title><form><input type="password"></form></html>')
        _, found = self.run_domain()
        self.assertEqual(found['exposed_admin'].severity, sc.LOW)

    def test_a_path_that_does_not_answer_decides_nothing_and_a_404_resolves(self):
        self.net.site(self.D, paths={'/phpmyadmin/': OSError('timed out')})
        res, found = self.run_domain()
        self.assertNotIn('exposed_phpmyadmin', res.resolvable['exposed'])
        self.assertIn('exposed_solr', res.resolvable['exposed'])

    def test_an_edge_that_challenges_the_request_is_recorded_and_nothing_more_is_asked(self):
        challenge = page(403, '<html><title>Just a moment...</title>cloudflare</html>', server='cloudflare', headers={'cf-mitigated': 'challenge'})
        self.net.site(self.D, https=challenge)
        res, found = self.run_domain()
        self.assertEqual(res.card['state'], 'challenged')
        self.assertEqual(res.card['evidence']['challenged'], 'Cloudflare')
        self.assertEqual([k for k in found if k.startswith(('exposed_', 'cve_', 'security_headers'))], [])
        self.assertEqual([u for u in self.net.fetched if u.count('/') > 3], [])  # no path was asked
        self.assertNotIn('technologies', res.card)

    # --- the card and its technologies
    def test_the_card_carries_headers_certificate_and_the_technology_stack(self):
        self.net.site(self.D, server='nginx/1.18.0 (Ubuntu)', powered_by='PHP/7.4.3', headers={'x-custom': 'yes'},
                      https=page(headers={**GOOD_HEADERS, 'x-custom': 'yes'}, server='nginx/1.18.0 (Ubuntu)', powered_by='PHP/7.4.3',
                                 body='<html><head><title>Vendor portal</title><meta name="generator" content="WordPress 6.2.1"></head><body></body></html>'))
        res, _ = self.run_domain()
        names = {t['name']: t for t in res.card['technologies']}
        self.assertEqual((names['nginx']['version'], names['nginx']['category']), ('1.18.0', 'web server'))
        self.assertEqual((names['PHP']['version'], names['PHP']['category']), ('7.4.3', 'language'))
        self.assertEqual(names['WordPress']['version'], '6.2.1')
        self.assertEqual(names['PHP']['source'], 'header:x-powered-by')
        http_card = res.card['http']
        self.assertEqual((http_card['server'], http_card['powered_by'], http_card['title']), ('nginx/1.18.0 (Ubuntu)', 'PHP/7.4.3', 'Vendor portal'))
        self.assertEqual(http_card['headers']['x-custom'], 'yes')
        self.assertEqual(res.card['tls']['sans'], [self.D])
        self.assertEqual((res.card['tls']['protocol'], res.card['tls']['cipher']), ('TLSv1.3', 'TLS_AES_256_GCM_SHA384'))
        self.assertGreater(res.card['tls']['days_left'], 190)

    def test_cookies_values_never_reach_the_card(self):
        self.net.site(self.D, https=page(headers=GOOD_HEADERS, cookies=['sid']))
        res, _ = self.run_domain()
        self.assertEqual(res.card['http']['cookies'], ['sid'])
        self.assertNotIn('set-cookie', res.card['http']['headers'])

    # --- known CVEs for announced versions (secondary)
    def cve(self, cve_id='CVE-2099-7', product='nginx', ranges=None, cvss=7.5, kev=False):
        return CVEEntry.objects.create(cve_id=cve_id, cvss=cvss, kev=kev, title='t', published_at=timezone.now(),
                                       affected=[{'product': product, 'ranges': ranges if ranges is not None else [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])

    def test_an_announced_version_inside_a_bounded_range_is_an_informational_finding_that_is_never_validated(self):
        self.cve()
        self.net.site(self.D, server='nginx/1.18.0')
        _, found = self.run_domain(pool=lambda: __import__('cveFeed.correlation', fromlist=['x']).cve_pool())
        finding = found['cve_nginx']
        self.assertEqual((finding.category, finding.severity), ('cve', sc.HIGH))
        self.assertEqual(finding.evidence['cves'][0]['id'], 'CVE-2099-7')
        self.assertIs(finding.evidence['validated'], False)
        self.assertIn('Not validated', finding.detail)
        self.assertIn('nginx 1.18.0 is announced', finding.title)
        self.assertIn('backported', finding.ask)

    def test_the_strict_version_rule_no_range_hit_no_version_no_bound(self):
        from cveFeed import correlation
        self.cve('CVE-2099-8', ranges=[])  # the advisory names the product and gives no bound: product-wide, no evidence
        self.cve('CVE-2099-9', product='Apache Tomcat', kev=True, ranges=[])  # even a KEV advisory without a bound is not evidence here
        pool = correlation.cve_pool
        self.net.site(self.D, server='nginx/1.25.3')
        self.assertNotIn('cve_nginx', self.run_domain(pool=pool)[1])
        self.net.site(self.D, server='nginx')  # no version stated: a technology, never a match
        res, found = self.run_domain(pool=pool)
        self.assertEqual([k for k in found if k.startswith('cve_')], [])
        self.assertEqual([(t['name'], t['version']) for t in res.card['technologies']], [('nginx', '')])
        self.net.site(self.D, server='Apache-Coyote/1.1')
        self.assertEqual([k for k in self.run_domain(pool=pool)[1] if k.startswith('cve_')], [])

    def test_a_distribution_build_is_one_step_lower_and_an_edge_masks_the_server_header(self):
        from cveFeed import correlation
        self.cve(cvss=9.8)
        self.net.site(self.D, server='nginx/1.18.0 (Ubuntu)')
        _, found = self.run_domain(pool=correlation.cve_pool)
        self.assertEqual(found['cve_nginx'].severity, sc.HIGH)  # critical, lowered: the distribution may have backported the fix
        self.assertIn('ubuntu build', found['cve_nginx'].title)
        self.net.site(self.D, server='nginx/1.18.0', headers={'cf-ray': 'abc'})
        res, found = self.run_domain(pool=correlation.cve_pool)
        self.assertEqual([k for k in found if k.startswith('cve_')], [])
        self.assertNotIn('cve', res.resolvable)  # behind an edge the banner says nothing: what it was is not decided either

    def test_the_catalog_is_not_read_when_the_stack_shows_no_version(self):
        self.net.site(self.D, server='nginx')
        pool = mock.Mock(side_effect=AssertionError('the catalog must not be loaded'))
        self.run_domain(pool=pool)
        pool.assert_not_called()

    def test_no_check_or_finding_can_say_validated(self):
        fields = {f.name for f in SupplierFinding._meta.get_fields()}
        self.assertFalse({'validated', 'validation', 'ai_verdict', 'template_result', 'remediation_status', 'assignee'} & fields)


# ----------------------------------------------------------------------------- the technology search

class SearchTests(Fixture, TestCase):
    def setUp(self):
        super().setUp()
        self.a = self.supplier('Acme Hosting', 'critical', ['portal.vendor.test', 'api.vendor.test'])
        self.b = self.supplier('Bolt Payments', 'normal', ['pay.bolt.test'])
        self.c = self.supplier('Core Analytics', 'high', ['data.core.test'])
        self.card(self.a, 'portal.vendor.test', [('nginx', '1.18.0', 'web server'), ('PHP', '7.4.3', 'language')], server='nginx/1.18.0', powered_by='PHP/7.4.3')
        self.card(self.a, 'api.vendor.test', [('Express', '', 'framework')], server='', powered_by='Express')
        self.card(self.b, 'pay.bolt.test', [('Node.js', '18.2.0', 'language'), ('nginx', '1.24.0', 'web server')], server='nginx/1.24.0')
        self.card(self.c, 'data.core.test', [('Apache HTTP Server', '2.4.57', 'web server')], server='Apache/2.4.57')

    def card(self, supplier, domain, techs, server='', powered_by=''):
        techs = [{'name': n, 'version': v, 'category': c, 'source': 'header:server'} for n, v, c in techs]
        return SupplierHostCard.objects.create(supplier=supplier, domain=domain, state='ok', checked_at=timezone.now(), technologies=techs,
                                               http={'server': server, 'powered_by': powered_by, 'headers': {'server': server}},
                                               tech_text=sc.tech_text(techs, server, powered_by))

    def hosts(self, q='', token=None):
        status, data = call(token or self.t_member, 'GET', f'/api/v1/projects/sup-a/suppliers/hosts{q}')
        self.assertEqual(status, 200)
        return data

    def test_terms_are_split_on_commas_and_normalized(self):
        self.assertEqual(supplier_search.terms_of(' PHP , node.js ;php:7  '), ['php', 'node.js', 'php 7'])
        self.assertEqual(supplier_search.terms_of('a,' * 20), ['a'])
        self.assertEqual(supplier_search.terms_of(''), [])

    def test_php_finds_every_supplier_host_running_php(self):
        data = self.hosts('?tech=php')
        self.assertEqual([(r['supplier']['name'], r['domain']) for r in data['results']], [('Acme Hosting', 'portal.vendor.test')])
        self.assertEqual(data['results'][0]['matched'], [{'name': 'PHP', 'version': '7.4.3', 'category': 'language'}])
        self.assertEqual(data['terms'], ['php'])

    def test_several_terms_match_any_and_node_matches_nodejs(self):
        data = self.hosts('?tech=php,node')
        self.assertEqual([r['domain'] for r in data['results']], ['portal.vendor.test', 'pay.bolt.test'])  # critical tier first, then normal

    def test_a_version_in_the_term_narrows_it(self):
        self.assertEqual([r['domain'] for r in self.hosts('?tech=nginx 1.1')['results']], ['portal.vendor.test'])
        self.assertEqual([r['domain'] for r in self.hosts('?tech=nginx:1.24')['results']], ['pay.bolt.test'])
        self.assertEqual([r['domain'] for r in self.hosts('?tech=nginx')['results']], ['portal.vendor.test', 'pay.bolt.test'])

    def test_a_raw_banner_matches_when_no_technology_does(self):
        data = self.hosts('?tech=express')
        self.assertEqual([r['domain'] for r in data['results']], ['api.vendor.test'])
        self.card(self.c, 'old.core.test', [], server='Microsoft-IIS/6.0')
        self.assertEqual([(r['domain'], r['matched']) for r in self.hosts('?tech=iis')['results']], [('old.core.test', [])])

    def test_no_term_lists_every_card_and_nothing_matches_nothing(self):
        self.assertEqual(self.hosts()['count'], 4)
        self.assertEqual(self.hosts('?tech=cobol')['count'], 0)

    def test_the_search_narrows_by_supplier_and_tier_and_pages(self):
        self.assertEqual(self.hosts(f'?supplier={self.a.id}')['count'], 2)
        self.assertEqual([r['supplier']['name'] for r in self.hosts('?tier=high')['results']], ['Core Analytics'])
        page = self.hosts('?page_size=1&page=2')
        self.assertEqual((page['count'], len(page['results']), page['page']), (4, 1, 2))

    def test_the_search_never_crosses_projects(self):
        other = self.supplier('Elsewhere', 'normal', ['x.else.test'], project=self.other_project)
        self.card(other, 'x.else.test', [('PHP', '5.6.0', 'language')])
        self.assertEqual([r['domain'] for r in self.hosts('?tech=php')['results']], ['portal.vendor.test'])
        status, data = call(self.t_stranger, 'GET', '/api/v1/projects/sup-b/suppliers/hosts?tech=php')
        self.assertEqual([r['domain'] for r in data['results']], ['x.else.test'])

    def test_the_technologies_the_suppliers_run_are_counted(self):
        status, data = call(self.t_member, 'GET', '/api/v1/projects/sup-a/suppliers/technologies')
        rows = {r['name']: r for r in data['results']}
        self.assertEqual((rows['nginx']['suppliers'], rows['nginx']['hosts'], rows['nginx']['versions']), (2, 2, ['1.18.0', '1.24.0']))
        self.assertEqual(data['results'][0]['name'], 'nginx')  # most widespread first
        self.assertEqual(rows['PHP']['category'], 'language')

    def test_the_mcp_search_tool_answers_the_same(self):
        error, data = tool_call(self.t_member, 'search_supplier_technology', {'project': 'sup-a', 'tech': 'php, node'})
        self.assertEqual((error, data['count']), (False, 2))
        error, data = tool_call(self.t_member, 'list_supplier_technologies', {'project': 'sup-a'})
        self.assertFalse(error)
        self.assertTrue(tool_call(self.t_stranger, 'search_supplier_technology', {'project': 'sup-a'})[0])

    def test_the_message_asks_about_the_matching_technology_first_and_names_nobody_of_ours(self):
        SupplierFinding.objects.create(supplier=self.a, domain='portal.vendor.test', check_name='hsts_missing', severity=2, title='portal.vendor.test does not send HSTS',
                                       detail='Without HSTS a browser can be tricked.', ask='Ask the supplier to send HSTS.', category='web')
        status, data = call(self.t_member, 'GET', f'/api/v1/projects/sup-a/suppliers/{self.a.id}/summary?tech=php')
        text = data['text']
        self.assertEqual((status, data['open']), (200, 1))
        self.assertIn('Your public services announce the following', text)
        self.assertIn('- portal.vendor.test: PHP 7.4.3', text)
        self.assertIn('nginx 1.18.0, PHP 7.4.3', text)
        self.assertIn('What we ask: Ask the supplier to send HSTS.', text)
        self.assertIn('passive', text)
        for private in ('Alpha', 'sup-a', 'sup-admin', 'example.test'):
            self.assertNotIn(private, text)
        self.assertNotIn('—', text)
        self.assertLess(text.index('Your public services announce'), text.index('Open findings'))
        status, data = call(self.t_member, 'GET', f'/api/v1/projects/sup-a/suppliers/{self.b.id}/summary')
        self.assertIn('No open findings', data['text'])


# ----------------------------------------------------------------------------- the sweep

class SweepTests(Fixture, TestCase):
    D = 'portal.vendor.test'

    def setUp(self):
        super().setUp()
        self.s = self.supplier(domains=[self.D])
        self.net.site(self.D, https=page(headers={}, server='nginx/1.25.3'), tls=cert(self.D, days=3))

    def test_a_sweep_stores_the_card_and_the_findings_and_records_the_window(self):
        out = self.sweep()
        self.assertEqual((out['suppliers'], out['domains']), (1, 1))
        self.assertGreater(out['new'], 0)
        self.assertGreater(out['requests'], 10)
        card = SupplierHostCard.objects.get(supplier=self.s, domain=self.D)
        self.assertEqual((card.state, card.addresses), ('ok', [PUBLIC]))
        self.assertEqual(card.tls['issuer'], 'Example CA')
        self.assertEqual(card.http['server'], 'nginx/1.25.3')
        self.assertEqual([t['name'] for t in card.technologies], ['nginx'])
        self.assertIn('nginx 1.25.3', card.tech_text)
        self.assertIsNotNone(card.checked_at)
        self.assertEqual(card.checked_at, card.last_ok_at)
        self.assertEqual({'tls_expiring', 'hsts_missing', 'security_headers_missing'} - set(self.checks(self.s)), set())
        self.s.refresh_from_db()
        self.assertIsNotNone(self.s.last_checked_at)
        self.assertEqual(ServiceRun.objects.filter(service='supplier', asset=str(self.s.pk), project_id=self.project.id, status='done').count(), 1)

    def test_a_supplier_is_checked_once_per_window_then_again(self):
        self.assertEqual(self.sweep()['suppliers'], 1)
        calls = len(self.net.calls)
        self.assertEqual(self.sweep()['suppliers'], 0)
        self.assertEqual(len(self.net.calls), calls)  # nothing was asked inside the weekly window
        ServiceRun.objects.filter(service='supplier').update(finished_at=timezone.now() - timedelta(days=8))
        self.assertEqual(self.sweep()['suppliers'], 1)
        self.assertEqual(SupplierFinding.objects.filter(supplier=self.s, check_name='hsts_missing').count(), 1)  # the same finding, updated

    def test_the_window_is_a_week_and_a_failed_check_a_day_and_both_can_be_set(self):
        self.assertEqual(ledger.ttl('supplier'), 7 * 24 * 3600)
        self.assertEqual(ledger.ttl('supplier-failed'), 24 * 3600)
        with mock.patch.dict(os.environ, {'CVENGINE_TTL_SUPPLIER': '48', 'CVENGINE_TTL_SUPPLIER_FAILED': '2'}):
            self.assertEqual((ledger.ttl('supplier'), ledger.ttl('supplier-failed')), (48 * 3600, 2 * 3600))

    def test_a_problem_that_goes_away_is_resolved_and_one_that_returns_reopens(self):
        self.sweep()
        self.assertIn('hsts_missing', self.checks(self.s))
        self.net.site(self.D, tls=cert(self.D, days=300), server='nginx/1.25.3')  # the supplier fixed headers and renewed
        self.expire()
        out = self.sweep()
        self.assertGreater(out['resolved'], 0)
        self.assertEqual(self.checks(self.s), [])
        row = self.finding(self.s, self.D, 'hsts_missing')
        self.assertEqual(row.status, 'resolved')
        self.assertIsNotNone(row.resolved_at)
        self.net.site(self.D, https=page(headers={}), tls=cert(self.D, days=300))
        self.expire()
        out = self.sweep()
        row.refresh_from_db()
        self.assertEqual((row.status, row.resolved_at, out['reopened'] > 0), ('open', None, True))
        self.assertIn('Reopened', row.status_note)

    def test_resolving_is_idempotent(self):
        self.sweep()
        self.net.site(self.D, tls=cert(self.D, days=300))
        self.expire()
        self.sweep()
        first = self.finding(self.s, self.D, 'hsts_missing').resolved_at
        self.expire()
        self.sweep()
        self.assertEqual(self.finding(self.s, self.D, 'hsts_missing').resolved_at, first)

    def test_an_accepted_finding_stays_accepted_while_found_and_resolves_when_gone(self):
        self.sweep()
        SupplierFinding.objects.filter(supplier=self.s, check_name='hsts_missing').update(status='accepted', status_note='known')
        self.expire()
        self.sweep()
        self.assertEqual(self.finding(self.s, self.D, 'hsts_missing').status, 'accepted')
        self.net.site(self.D, tls=cert(self.D, days=300))
        self.expire()
        self.sweep()
        self.assertEqual(self.finding(self.s, self.D, 'hsts_missing').status, 'resolved')

    def test_a_check_that_got_no_answer_changes_nothing_and_is_asked_again_tomorrow(self):
        self.sweep()
        before = self.checks(self.s)
        self.net.pages[f'https://{self.D}/'] = OSError('timed out')
        self.net.pages[f'http://{self.D}/'] = OSError('timed out')
        self.net.certs[self.D] = None
        self.expire()
        out = self.sweep()
        self.assertEqual(self.checks(self.s), before)  # nothing was resolved because nothing could be seen
        self.assertEqual(out['resolved'], 0)
        self.assertEqual(ServiceRun.objects.filter(service='supplier-failed').count(), 1)
        self.assertEqual(ServiceRun.objects.filter(service='supplier').count(), 0)
        card = SupplierHostCard.objects.get(supplier=self.s)
        self.assertEqual((card.state, card.tls['issuer']), ('unreachable', 'Example CA'))  # the last good card stays, marked unreachable
        self.assertEqual(self.sweep()['suppliers'], 0)  # a day's rest
        ServiceRun.objects.filter(service='supplier-failed').update(finished_at=timezone.now() - timedelta(hours=25))
        self.assertEqual(self.sweep()['suppliers'], 1)

    def test_the_card_keeps_its_last_stack_when_the_page_stops_answering(self):
        self.sweep()
        self.net.pages[f'https://{self.D}/'] = OSError('x')
        self.net.pages[f'http://{self.D}/'] = OSError('x')
        self.expire()
        self.sweep()
        card = SupplierHostCard.objects.get(supplier=self.s)
        self.assertEqual([t['name'] for t in card.technologies], ['nginx'])
        self.assertEqual(card.http['server'], 'nginx/1.25.3')
        self.assertEqual((card.http['https_status'], card.state), (None, 'unreachable'))
        self.assertLess(card.last_ok_at, card.checked_at)

    def test_the_cve_note_resolves_when_the_version_changes(self):
        from cveFeed import correlation
        CVEEntry.objects.create(cve_id='CVE-2099-3', cvss=5.0, title='t', published_at=timezone.now(),
                                affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
        self.net.site(self.D, server='nginx/1.18.0')
        self.sweep(pool=correlation.cve_pool)
        self.assertIn('cve_nginx', self.checks(self.s))
        self.net.site(self.D, server='nginx/1.25.3')
        self.expire()
        self.sweep(pool=correlation.cve_pool)
        self.assertNotIn('cve_nginx', self.checks(self.s))
        self.assertEqual(self.finding(self.s, self.D, 'cve_nginx').status, 'resolved')

    def test_every_request_is_a_get_to_the_listed_name_at_its_vetted_address(self):
        self.sweep()
        from urllib.parse import urlsplit
        for call_ in self.net.calls:
            if call_[0] == 'fetch':
                self.assertEqual(urlsplit(call_[1]).hostname, self.D)
                self.assertIn(urlsplit(call_[1]).scheme, ('http', 'https'))
                self.assertEqual(call_[2], PUBLIC)
        resolved = {c[1] for c in self.net.calls if c[0] == 'resolve'}
        self.assertEqual(resolved, {self.D})  # no other name was looked up: no subdomain, no neighbour
        self.assertEqual({urlsplit(u).port for u in self.net.fetched}, {None})  # only the default ports 443 and 80

    def test_the_request_budget_caps_a_sweep_and_the_rest_waits(self):
        second = self.supplier('Second', 'normal', ['second.vendor.test'])
        self.net.site('second.vendor.test')
        out = self.sweep(budget=ss.Budget(ss.DOMAIN_COST + 2))
        self.assertEqual((out['suppliers'], out['deferred']), (1, 1))
        self.assertLessEqual(out['requests'], ss.DOMAIN_COST + 2)
        self.assertEqual(ServiceRun.objects.filter(service='supplier').count(), 1)
        out = self.sweep()  # the next sweep takes the one that waited
        self.assertEqual(out['suppliers'], 1)
        self.assertEqual(ServiceRun.objects.filter(service='supplier').count(), 2)

    def test_a_supplier_too_big_for_what_is_left_is_deferred_not_half_checked(self):
        self.supplier('Second', 'normal', ['a.vendor.test', 'b.vendor.test'])
        self.net.site('a.vendor.test')
        self.net.site('b.vendor.test')
        out = self.sweep(budget=ss.Budget(ss.DOMAIN_COST * 2))  # the first supplier takes one domain's worth, the second needs two
        self.assertEqual(out['suppliers'], 1)
        self.assertGreaterEqual(out['deferred'], 1)

    def test_critical_suppliers_go_first(self):
        normal = self.supplier('Normal Co', 'normal', ['n.vendor.test'])
        self.net.site('n.vendor.test')
        self.s.tier = 'critical'
        self.s.save()
        self.assertEqual([s.name for s in ss.due_suppliers(self.project.id)], ['Acme Hosting', 'Normal Co'])
        normal.tier = 'critical'
        normal.save()
        self.assertEqual({s.name for s in ss.due_suppliers(self.project.id)}, {'Acme Hosting', 'Normal Co'})

    def test_the_sweep_can_be_turned_off(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SUPPLIERS': '0'}):
            self.assertIn('turned off', self.sweep()['skipped'])
            self.assertIn('turned off', ss.sweep_all(net=self.net)['skipped'])
        self.assertEqual(self.net.calls, [])

    def test_the_schedule_the_queue_and_the_entrypoint(self):
        from django_celery_beat.models import PeriodicTask

        from agentapi import system_status
        from cveFeed import tasks
        task = PeriodicTask.objects.get(name='cvengine-supplier-sweep')
        self.assertEqual((task.task, task.queue, task.enabled, task.crontab.hour), ('supplier_sweep', 'supplier_queue', True, '3'))
        self.assertEqual((tasks.supplier_sweep.name, tasks.supplier_sweep.queue), ('supplier_sweep', 'supplier_queue'))
        self.assertIn('supplier_queue', system_status.QUEUES)
        entry = open(os.path.join(os.path.dirname(__file__), '..', 'celery-entrypoint.sh')).read()
        self.assertIn(',supplier_queue', entry)
        with mock.patch('cveFeed.supplier_scan.sweep_all', return_value={'suppliers': 0}) as sweep_all:
            self.assertEqual(tasks.supplier_sweep(), {'suppliers': 0})
        sweep_all.assert_called_once_with()


# ----------------------------------------------------------------------------- safety

class SafetyTests(Fixture, TestCase):
    D = 'portal.vendor.test'

    def setUp(self):
        super().setUp()
        self.s = self.supplier(domains=[self.D])

    def assert_untouched(self):
        self.assertEqual(self.net.connections, [])
        self.assertEqual(SupplierFinding.objects.count(), 0)

    def test_a_name_that_resolves_to_a_non_public_address_is_never_contacted(self):
        for bad in ('10.0.0.5', '192.168.1.10', '172.16.4.4', '127.0.0.1', '169.254.169.254', '100.64.0.1', '100.100.100.200', '0.0.0.0', '::1', 'fe80::1', 'fd00::5',
                    '::ffff:10.0.0.5', '64:ff9b::a00:5', '192.0.0.192', '224.0.0.1'):
            net = FakeNet().site(self.D, ip=bad)
            out = self.sweep(net)
            self.assertEqual(net.connections, [], bad)
            card = SupplierHostCard.objects.get(supplier=self.s, domain=self.D)
            self.assertEqual(card.state, 'blocked', bad)
            self.assertIn('not public', card.evidence['note'])
            ServiceRun.objects.all().delete()
        self.assertEqual(SupplierFinding.objects.filter(category__in=('tls', 'web', 'exposed', 'cve')).count(), 0)

    def test_one_private_answer_among_public_ones_refuses_the_whole_name(self):
        net = FakeNet().site(self.D, ip=[PUBLIC, '10.0.0.5'])
        self.sweep(net)
        self.assertEqual(net.connections, [])

    def test_the_private_target_switch_does_not_open_a_supplier_to_internal_addresses(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
            for bad in ('10.0.0.5', '192.168.0.1'):
                net = FakeNet().site(self.D, ip=bad)
                self.sweep(net)
                self.assertEqual(net.connections, [], bad)
                ServiceRun.objects.all().delete()

    def test_the_real_lookup_is_vetted_too(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
        with mock.patch('socket.getaddrinfo', return_value=answers):
            self.assertEqual(ss.public_addresses(self.D, ss.Network()), ([], 'blocked'))
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (PUBLIC, 443)), (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 443, 0, 0))]
        with mock.patch('socket.getaddrinfo', return_value=answers):
            self.assertEqual(ss.public_addresses(self.D, ss.Network()), ([PUBLIC, '2001:db8::1'], 'ok'))
        with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(socket.EAI_NONAME, 'x')):
            self.assertEqual(ss.public_addresses(self.D, ss.Network()), ([], 'none'))
        with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(socket.EAI_AGAIN, 'x')):
            self.assertEqual(ss.public_addresses(self.D, ss.Network()), ([], 'unknown'))
        with mock.patch('socket.getaddrinfo', side_effect=TimeoutError):
            self.assertEqual(ss.public_addresses(self.D, ss.Network()), ([], 'unknown'))

    def test_the_real_web_client_connects_to_the_vetted_address_only(self):
        seen = {}

        def probe(url, **kwargs):
            seen.update(url=url, **kwargs)
            return {'status': 200, 'headers': {}, 'body': ''}
        with mock.patch.object(route_auth, 'probe_url', probe):
            ss.Network().fetch(f'https://{self.D}/', PUBLIC)
        self.assertEqual((seen['url'], seen['connect_ip']), (f'https://{self.D}/', PUBLIC))
        self.assertEqual(seen['max_bytes'], slow_web.MAX_RESPONSE_BYTES)
        self.assertIsNone(seen['project'])  # no tailnet authority for a third party

    def test_scanning_paused_stops_the_sweep_before_anything_is_asked(self):
        self.net.site(self.D)
        with mock.patch('reNgine.resources.global_pause_requested', return_value=True) as paused:
            out = self.sweep()
            all_out = ss.sweep_all(net=self.net)
        self.assertIn('paused', out['skipped'])
        self.assertIn('paused', all_out['skipped'])
        paused.assert_called_with(fail_closed=True)  # an unreadable control table is a pause, not a go-ahead
        self.assertEqual(self.net.calls, [])
        self.assertEqual(ServiceRun.objects.count(), 0)  # the supplier stays due

    def test_a_pause_in_the_middle_stops_at_the_next_request_and_records_nothing(self):
        self.net.site(self.D)
        answers = iter([False, False, False, False, True])
        with mock.patch('reNgine.resources.global_pause_requested', side_effect=lambda **kw: next(answers, True)):
            out = self.sweep()
        self.assertIn('paused', out['skipped'])
        self.assertLess(len(self.net.connections), 5)
        self.assertEqual(ServiceRun.objects.filter(service__startswith='supplier').count(), 0)

    def test_a_project_whose_bounty_engagement_has_not_confirmed_automated_testing_is_skipped(self):
        self.net.site(self.D)
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
        out = self.sweep()
        self.assertIn('automated testing', out['skipped'])
        self.assert_untouched()
        BountyEngagement.objects.update(automated_ok=True, policy_ack_at=timezone.now())
        self.assertEqual(self.sweep()['suppliers'], 1)

    def test_one_sweep_runs_at_a_time(self):
        self.net.site(self.D)
        with mock.patch('reNgine.resources.redis_claim') as claim:
            claim.return_value.__enter__.return_value = 'another worker'
            self.assertIn('another supplier sweep', self.sweep()['skipped'])
        self.assertEqual(self.net.calls, [])
        with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
            self.assertIn('another sweep', ss.sweep_all(net=self.net)['skipped'])
        with mock.patch('cveFeed.ledger.sweep_claim', return_value=True) as claim_taken:
            out = ss.sweep_all(net=self.net, pace=slow_web.Pace(**NO_WAIT))
        claim_taken.assert_called_once_with('suppliers', 2 * 60 * 60)
        self.assertEqual(out['suppliers'], 1)

    def test_an_excluded_name_is_not_contacted_and_neither_is_one_that_became_a_target(self):
        self.net.site(self.D)
        HostExclusion.objects.create(org=self.org1, host=self.D)
        self.sweep()
        self.assertEqual(self.net.connections, [])
        self.assertEqual(SupplierHostCard.objects.get(supplier=self.s).state, 'excluded')
        HostExclusion.objects.all().delete()
        self.expire()
        Domain.objects.create(name='vendor.test', project=self.project, insert_date=timezone.now())  # now the project's own target
        self.sweep()
        self.assertEqual(self.net.connections, [])
        self.assertEqual(SupplierHostCard.objects.get(supplier=self.s).state, 'excluded')

    def test_the_web_client_is_the_slow_polite_one_and_the_pace_is_global(self):
        waits = []
        pace = slow_web.Pace(sleep=waits.append, clock=lambda: 0.0, per_host=2.0, overall=0)
        self.net.site(self.D)
        self.sweep(pace=pace)
        self.assertGreater(pace.requests, 10)
        self.assertTrue(all(w == 2.0 for w in waits))  # the per-host gap holds between this name's requests
        import inspect
        self.assertIn('slow_web.get', inspect.getsource(ss.Network.fetch))
        self.assertGreaterEqual(slow_web.global_gap(), 1.0)

    def test_nothing_but_the_listed_name_is_ever_resolved_or_asked(self):
        self.net.site(self.D, mail=True)
        self.net.site('mail.vendor.test')  # an MX host and a neighbour exist, but are not listed
        self.sweep()
        self.assertEqual({c[1] for c in self.net.calls if c[0] == 'resolve'}, {self.D})
        for kind in self.net.connections:
            self.assertNotIn('mail.vendor.test', json.dumps(kind, default=str))


# ----------------------------------------------------------------------------- a supplier is not an owned host

class SeparationTests(Fixture, TestCase):
    D = 'portal.vendor.test'

    def snapshot(self):
        status, stats = call(self.t_admin, 'GET', '/api/v1/system/status')
        status_h, hygiene_list = call(self.t_admin, 'GET', '/api/v1/projects/sup-a/hygiene')
        _s, targets = call(self.t_admin, 'GET', '/api/v1/projects/sup-a/targets')
        _s, hosts = call(self.t_admin, 'GET', '/api/v1/projects/sup-a/hosts')
        _s, findings = call(self.t_admin, 'GET', '/api/v1/projects/sup-a/findings')
        return json.dumps([stats.get('projects'), hygiene_list.get('count'), targets.get('count'), hosts.get('count'), findings.get('count')], sort_keys=True, default=str)

    def test_supplier_findings_do_not_reach_owned_host_counts_stats_or_hygiene(self):
        before = self.snapshot()
        before_stats = client_for(self.admin).get('/cve/api/stats?project=sup-a').content
        self.net.site(self.D, https=page(headers={}), tls=cert(self.D, days=-2), server='nginx/1.18.0', mail=False)
        self.net.mx.add(self.D)
        self.supplier(domains=[self.D])
        out = self.sweep()
        self.assertGreater(out['new'], 3)
        self.assertGreater(SupplierFinding.objects.filter(severity=sc.CRITICAL).count(), 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(client_for(self.admin).get('/cve/api/stats?project=sup-a').content, before_stats)
        self.assertEqual((HygieneFinding.objects.count(), Domain.objects.filter(project=self.project).count(), Subdomain.objects.count()), (0, 1, 0))

    def test_a_supplier_never_becomes_a_target_a_host_or_scan_work(self):
        from cveFeed import conductor, fullscan
        self.net.site(self.D)
        self.supplier(domains=[self.D])
        self.sweep()
        self.assertEqual(list(Domain.objects.values_list('name', flat=True)), ['example.test'])
        self.assertFalse(Subdomain.objects.filter(name=self.D).exists())
        self.assertTrue(set(conductor.next_targets(10)) <= {self.own.id})  # only the project's own target is ever picked for scanning
        from cveFeed.models import HostState
        self.assertEqual(HostState.objects.count(), 0)

    def test_run_hygiene_and_the_owned_stores_do_not_know_suppliers(self):
        from cveFeed import hygiene
        supplier = self.supplier(domains=[self.D])
        SupplierFinding.objects.create(supplier=supplier, domain=self.D, check_name='tls_expired', title='t', category='tls', severity=4)
        hygiene.run_hygiene(self.own.id, probe=lambda host, port: None, emailer=lambda name: ([], []), mx=lambda n, t: False)
        self.assertEqual(SupplierFinding.objects.get().status, 'open')  # the owned-host sweep resolves and counts none of it
        self.assertEqual(HygieneFinding.objects.count(), 0)

    def test_the_supplier_modules_import_no_owned_asset_flow(self):
        import inspect

        from cveFeed import supplier_checks, supplier_scan, supplier_search
        for module in (supplier_scan, supplier_checks, supplier_search):
            source = inspect.getsource(module)
            for forbidden in ('nmap_scan', 'naabu', 'bbot', 'nuclei', 'discovery', 'fullscan', 'host_assessment', 'testssl_scan', 'start_scan', 'remediation'):
                self.assertNotIn(f'import {forbidden}', source, (module.__name__, forbidden))
                self.assertNotIn(f'{forbidden}.', source.replace('``', ''), (module.__name__, forbidden))


# ----------------------------------------------------------------------------- the page

class PageTests(Fixture, TestCase):
    def test_the_suppliers_page_is_part_of_the_project_navigation(self):
        client = client_for(self.member)
        response = client.get('/cve/sup-a/suppliers/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-kind="suppliers"')
        self.assertContains(response, '/cve/sup-a/suppliers/')
        self.assertEqual(client_for(self.stranger).get('/cve/sup-a/suppliers/').status_code, 404)
        self.assertEqual(client_for(self.admin).get('/cve/sup-a/hosts/').status_code, 200)
