import json
import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token

from cveFeed import ledger, supplier_checks as sc, supplier_scan as ss, supplier_search
from cveFeed.models import (BountyEngagement, BountyProgram, CVEEntry, HostExclusion, HygieneFinding, ServiceRun, Supplier, SupplierFinding,
                            SupplierHostCard)
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally
from tests.test_agentapi import call, tool_call
from tests.test_tenancy import client_for

PUBLIC = '203.0.113.10'
ALL_CATEGORIES = {'email': [''], 'tls': ['tls_'], 'web': ['hsts_', 'http_no_redirect', 'no_https', 'security_headers_missing'], 'cve': ['cve_'],
                  'exposed': ['exposed_login']}


def posture(check, severity=sc.MEDIUM, category='web', title='', detail='', **evidence):
    """One finding as a Sentinel reports it (``probe_results.clean_supplier_check`` keeps these six keys; the text to ask the supplier is the server's)."""
    return {'check': check, 'severity': severity, 'title': title or check, 'detail': detail or check, 'category': category, 'evidence': evidence}


def row(domain, postures=(), fingerprints=(), edges=(), distro='', server='nginx/1.25.3', requests=17, answered=True, card=None, resolvable=None, **extra):
    """What a Sentinel reports for one supplier name: a reachable site with a certificate, a front page and the categories it could decide. ``card``
    replaces the card (an unreachable name has no sections); ``resolvable`` the categories it could decide."""
    default_card = {'state': 'ok', 'addresses': [PUBLIC], 'evidence': {'address': 'ok', 'dns': 'ok'},
                    'tls': {'subject': domain, 'issuer': 'Example CA', 'sans': [domain], 'not_before': '2026-01-01T00:00:00+00:00', 'not_after': '2027-01-01T00:00:00+00:00',
                            'days_left': 200, 'key': 'RSA 2048', 'signature': 'sha256 (sha256WithRSAEncryption)', 'protocol': 'TLSv1.3',
                            'cipher': 'TLS_AES_256_GCM_SHA384', 'chain_error': '', 'legacy_tls': False},
                    'mail': {'handles_mail': False, 'mx': False},
                    'http': {'https_status': 200, 'http_status': 301, 'url': f'https://{domain}/', 'status': 200, 'title': 'Vendor portal', 'content_type': 'text/html',
                             'server': server, 'powered_by': '', 'location': '', 'cookies': [], 'bytes': 70, 'headers': {'server': server}}}
    return {'domain': domain, 'postures': list(postures), 'resolvable': ALL_CATEGORIES if resolvable is None else resolvable, 'summary': {'address': 'ok'},
            'card': default_card if card is None else card, 'fingerprints': list(fingerprints) or ([{'name': f'nginx:{server.split("/")[1]}', 'source': 'header:server'}]
                                                                                                      if server and '/' in server else []),
            'edges': list(edges), 'distro': distro, 'answered': answered, 'stopped': False, 'partial': False, 'requests': requests, **extra}


def unreachable(domain, http=None):
    """A name no answer came from: no address read, no certificate, no page (``http`` keeps the status of each scheme only)."""
    return row(domain, answered=False, requests=3, resolvable={}, fingerprints=[], card={
        'state': 'unreachable', 'addresses': [PUBLIC], 'evidence': {'address': 'ok'}, **({'http': http} if http else {})}, server='')


class Fixture:
    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.org1, self.org2 = Org.objects.create(name='One', slug='sup-one'), Org.objects.create(name='Two', slug='sup-two')
        self.project = Project.objects.create(name='Alpha', slug='sup-a', insert_date=now, org=self.org1)
        self.other_project = Project.objects.create(name='Beta', slug='sup-b', insert_date=now, org=self.org2)
        for patch in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('reNgine.tasks.geo_localize.delay'),
                      mock.patch('cveFeed.tasks.run_hygiene_task.delay'), mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async'), mock.patch('cveFeed.ct_queue._client', return_value=None)):
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
        LocalFallback('none').apply(self)  # supplier_check has no local path: the sweep is a scanner's or nothing
        self.guard = assert_ran_nowhere_locally(self, 'supplier_check')
        self.fake, self.tasks, self.rows = None, [], {}  # the fake Sentinel, the tasks it was handed, the row it reports for each name

    def supplier(self, name='Acme Hosting', tier='critical', domains=('portal.vendor.test',), project=None):
        return Supplier.objects.create(project=project or self.project, name=name, tier=tier, domains=list(domains), added_by=self.admin)

    def report(self, task):
        """What the fake Sentinel answers: the row set for each name the task asks about; a name with no row was not checked."""
        self.tasks.append(task)
        domains = task['target']['domains']
        return {'outcome': 'done', 'domains': [self.rows[d] for d in domains if d in self.rows], 'touched': domains, 'refused': []}

    def scanner(self):
        if self.fake is None:
            self.fake = FakeScanner(kinds=['supplier_check'], responders={'supplier_check': self.report}).start_for(self)
        return self.fake

    def sweep(self, **kw):
        self.scanner()
        return ss.sweep(self.project.id, **kw)

    def asked(self):
        """Every name the scanner was asked about, in order."""
        return [d for task in self.tasks for d in task['target']['domains']]

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

class RowTests(Fixture, TestCase):
    """What the server makes of one name's row from a Sentinel (``row_result``): the card, the technology stack and the match of announced versions
    against the CVE catalog. The checks themselves (certificates, mail records, headers, listed pages) are a Sentinel's and are tested in its
    repository: cvengine_scanner/tests/probes/test_suppliers.py."""
    D = 'portal.vendor.test'

    def result(self, found, pool=lambda: ({}, {})):
        res = ss.row_result(found, pool)
        return res, {p.check: p for p in res.postures}

    def test_the_card_carries_headers_certificate_and_the_technology_stack(self):
        found = row(self.D, server='nginx/1.18.0 (Ubuntu)', fingerprints=[
            {'name': 'nginx:1.18.0', 'source': 'header:server'}, {'name': 'PHP:7.4.3', 'source': 'header:x-powered-by'},
            {'name': 'WordPress:6.2.1', 'source': 'meta:generator'}])
        res, _ = self.result(found)
        names = {t['name']: t for t in res.card['technologies']}
        self.assertEqual((names['nginx']['version'], names['nginx']['category']), ('1.18.0', 'web server'))
        self.assertEqual((names['PHP']['version'], names['PHP']['category']), ('7.4.3', 'language'))
        self.assertEqual(names['WordPress']['version'], '6.2.1')
        self.assertEqual(names['PHP']['source'], 'header:x-powered-by')
        self.assertEqual(res.card['http']['server'], 'nginx/1.18.0 (Ubuntu)')
        self.assertEqual(res.card['tls']['sans'], [self.D])
        self.assertEqual((res.card['tls']['protocol'], res.card['tls']['cipher']), ('TLSv1.3', 'TLS_AES_256_GCM_SHA384'))

    def test_a_posture_is_finished_here_the_text_to_ask_the_supplier_is_the_servers_to_write(self):
        res, found = self.result(row(self.D, postures=[posture('tls_expired', sc.CRITICAL, 'tls', 'Certificate expired')]))
        self.assertEqual(found['tls_expired'].severity, sc.CRITICAL)
        self.assertIn('renew', found['tls_expired'].ask)

    def test_a_category_counts_as_decided_only_when_the_card_shows_what_it_needs(self):
        bare = row(self.D, card={'state': 'unreachable', 'addresses': [PUBLIC], 'evidence': {}})  # a bare claim: no certificate, no mail records, no page
        res, _ = self.result(bare)
        self.assertEqual(res.resolvable, {})  # so nothing it no longer lists is resolved
        res, _ = self.result(row(self.D))
        self.assertEqual(set(res.resolvable), {'tls', 'email', 'web', 'exposed', 'cve'})  # a full card backs every category the scanner named

    # --- known CVEs for announced versions (secondary)
    def cve(self, cve_id='CVE-2099-7', product='nginx', ranges=None, cvss=7.5, kev=False):
        return CVEEntry.objects.create(cve_id=cve_id, cvss=cvss, kev=kev, title='t', published_at=timezone.now(),
                                       affected=[{'product': product, 'ranges': ranges if ranges is not None else [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])

    def pool(self):
        from cveFeed import correlation
        return correlation.cve_pool

    def test_an_announced_version_inside_a_bounded_range_is_an_informational_finding_that_is_never_validated(self):
        self.cve()
        _, found = self.result(row(self.D, server='nginx/1.18.0'), pool=self.pool())
        finding = found['cve_nginx']
        self.assertEqual((finding.category, finding.severity), ('cve', sc.HIGH))
        self.assertEqual(finding.evidence['cves'][0]['id'], 'CVE-2099-7')
        self.assertIs(finding.evidence['validated'], False)
        self.assertIn('Not validated', finding.detail)
        self.assertIn('nginx 1.18.0 is announced', finding.title)
        self.assertIn('backported', finding.ask)

    def test_the_strict_version_rule_no_range_hit_no_version_no_bound(self):
        self.cve('CVE-2099-8', ranges=[])  # the advisory names the product and gives no bound: product-wide, no evidence
        self.cve('CVE-2099-9', product='Apache Tomcat', kev=True, ranges=[])  # even a KEV advisory without a bound is not evidence here
        pool = self.pool()
        self.assertNotIn('cve_nginx', self.result(row(self.D, server='nginx/1.25.3'), pool=pool)[1])
        res, found = self.result(row(self.D, server='nginx', fingerprints=[{'name': 'nginx', 'source': 'header:server'}]), pool=pool)  # no version: a technology, never a match
        self.assertEqual([k for k in found if k.startswith('cve_')], [])
        self.assertEqual([(t['name'], t['version']) for t in res.card['technologies']], [('nginx', '')])
        res, found = self.result(row(self.D, server='Apache-Coyote/1.1', fingerprints=[{'name': 'Apache Tomcat:1.1', 'source': 'header:server'}]), pool=pool)
        self.assertEqual([k for k in found if k.startswith('cve_')], [])

    def test_a_distribution_build_is_one_step_lower_and_an_edge_masks_the_server_header(self):
        self.cve(cvss=9.8)
        _, found = self.result(row(self.D, server='nginx/1.18.0 (Ubuntu)', distro='ubuntu'), pool=self.pool())
        self.assertEqual(found['cve_nginx'].severity, sc.HIGH)  # critical, lowered: the distribution may have backported the fix
        self.assertIn('ubuntu build', found['cve_nginx'].title)
        res, found = self.result(row(self.D, server='nginx/1.18.0', edges=['Cloudflare'], resolvable={k: v for k, v in ALL_CATEGORIES.items() if k != 'cve'}), pool=self.pool())  # the scanner leaves cve undecided behind an edge
        self.assertEqual([k for k in found if k.startswith('cve_')], [])
        self.assertNotIn('cve', res.resolvable)  # behind an edge the banner says nothing: what it was is not decided either

    def test_the_catalog_is_not_read_when_the_stack_shows_no_version(self):
        pool = mock.Mock(side_effect=AssertionError('the catalog must not be loaded'))
        self.result(row(self.D, server='nginx', fingerprints=[{'name': 'nginx', 'source': 'header:server'}]), pool=pool)
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
        self.unhealthy = [posture('tls_expiring', sc.MEDIUM, 'tls'), posture('hsts_missing'), posture('security_headers_missing')]
        self.rows[self.D] = row(self.D, postures=self.unhealthy)

    def test_a_sweep_stores_the_card_and_the_findings_and_records_the_window(self):
        out = self.sweep()
        self.assertEqual((out['suppliers'], out['domains']), (1, 1))
        self.assertGreater(out['new'], 0)
        self.assertEqual(out['requests'], 17)
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
        self.assertEqual(len(self.tasks), 1)
        self.assertEqual(self.sweep()['suppliers'], 0)
        self.assertEqual(len(self.tasks), 1)  # nothing was asked inside the weekly window
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
        self.rows[self.D] = row(self.D)  # the supplier fixed headers and renewed
        self.expire()
        out = self.sweep()
        self.assertGreater(out['resolved'], 0)
        self.assertEqual(self.checks(self.s), [])
        found = self.finding(self.s, self.D, 'hsts_missing')
        self.assertEqual(found.status, 'resolved')
        self.assertIsNotNone(found.resolved_at)
        self.rows[self.D] = row(self.D, postures=[posture('hsts_missing')])
        self.expire()
        out = self.sweep()
        found.refresh_from_db()
        self.assertEqual((found.status, found.resolved_at, out['reopened'] > 0), ('open', None, True))
        self.assertIn('Reopened', found.status_note)

    def test_resolving_is_idempotent(self):
        self.sweep()
        self.rows[self.D] = row(self.D)
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
        self.rows[self.D] = row(self.D)
        self.expire()
        self.sweep()
        self.assertEqual(self.finding(self.s, self.D, 'hsts_missing').status, 'resolved')

    def test_a_false_positive_stays_closed_while_found_and_is_not_resolved_or_reopened(self):
        self.sweep()
        SupplierFinding.objects.filter(supplier=self.s, check_name='hsts_missing').update(status='false_positive', status_note='HSTS on the apex')
        self.expire()
        self.sweep()
        found = self.finding(self.s, self.D, 'hsts_missing')
        self.assertEqual((found.status, found.status_note), ('false_positive', 'HSTS on the apex'))
        self.rows[self.D] = row(self.D)
        self.expire()
        self.sweep()  # no longer found: a false positive is left as it is, never resolved and so never reopened as new
        self.assertEqual(self.finding(self.s, self.D, 'hsts_missing').status, 'false_positive')

    def test_a_check_that_got_no_answer_changes_nothing_and_is_asked_again_tomorrow(self):
        self.sweep()
        before = self.checks(self.s)
        self.rows[self.D] = unreachable(self.D)
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
        self.rows[self.D] = unreachable(self.D, http={'https_status': None, 'http_status': None})
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
        self.rows[self.D] = row(self.D, server='nginx/1.18.0')
        self.sweep(pool=correlation.cve_pool)
        self.assertIn('cve_nginx', self.checks(self.s))
        self.rows[self.D] = row(self.D, server='nginx/1.25.3')
        self.expire()
        self.sweep(pool=correlation.cve_pool)
        self.assertNotIn('cve_nginx', self.checks(self.s))
        self.assertEqual(self.finding(self.s, self.D, 'cve_nginx').status, 'resolved')

    def test_the_task_names_the_listed_domain_and_the_pace_and_the_budget_the_scanner_keeps(self):
        self.sweep()
        target = self.tasks[0]['target']
        self.assertEqual(target['domains'], [self.D])  # no other name: no subdomain, no neighbour, no mail host
        self.assertGreaterEqual(target['pace']['gap'], 0.25)
        self.assertGreaterEqual(target['pace']['host_gap'], 0.5)
        self.assertEqual(target['max_requests'], ss.max_requests())

    def test_the_request_budget_caps_a_sweep_and_the_rest_waits(self):
        self.rows[self.D] = row(self.D, requests=ss.DOMAIN_COST)
        self.rows['second.vendor.test'] = row('second.vendor.test', requests=ss.DOMAIN_COST)
        self.supplier('Second', 'normal', ['second.vendor.test'])
        out = self.sweep(budget=ss.Budget(ss.DOMAIN_COST + 2))
        self.assertEqual((out['suppliers'], out['deferred']), (1, 1))
        self.assertLessEqual(out['requests'], ss.DOMAIN_COST + 2)
        self.assertEqual(ServiceRun.objects.filter(service='supplier').count(), 1)
        out = self.sweep()  # the next sweep takes the one that waited
        self.assertEqual(out['suppliers'], 1)
        self.assertEqual(ServiceRun.objects.filter(service='supplier').count(), 2)

    def test_the_task_carries_what_is_left_of_the_budget(self):
        self.sweep(budget=ss.Budget(100))
        self.assertEqual(self.tasks[0]['target']['max_requests'], 100)

    def test_a_supplier_too_big_for_what_is_left_is_deferred_not_half_checked(self):
        self.supplier('Second', 'normal', ['a.vendor.test', 'b.vendor.test'])
        self.rows[self.D] = row(self.D, requests=ss.DOMAIN_COST)
        out = self.sweep(budget=ss.Budget(ss.DOMAIN_COST * 2))  # the first supplier takes one domain's worth, the second needs two
        self.assertEqual(out['suppliers'], 1)
        self.assertGreaterEqual(out['deferred'], 1)
        self.assertEqual(self.asked(), [self.D])

    def test_critical_suppliers_go_first(self):
        normal = self.supplier('Normal Co', 'normal', ['n.vendor.test'])
        self.s.tier = 'critical'
        self.s.save()
        self.assertEqual([s.name for s in ss.due_suppliers(self.project.id)], ['Acme Hosting', 'Normal Co'])
        normal.tier = 'critical'
        normal.save()
        self.assertEqual({s.name for s in ss.due_suppliers(self.project.id)}, {'Acme Hosting', 'Normal Co'})

    def test_the_sweep_can_be_turned_off(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SUPPLIERS': '0'}):
            self.assertIn('turned off', self.sweep()['skipped'])
            self.assertIn('turned off', ss.sweep_all()['skipped'])
        self.assertEqual(self.tasks, [])

    def test_the_stage_waits_with_the_scanner_offline_and_the_supplier_stays_due(self):
        self.sweep()
        self.expire()
        SupplierFinding.objects.all().delete()
        self.fake.go_offline()
        out = self.sweep()
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertEqual(ServiceRun.objects.filter(service__startswith='supplier').count(), 0)  # nothing recorded as checked, not even as failed
        self.assertEqual(SupplierFinding.objects.count(), 0)
        self.assertEqual([s.pk for s in ss.due_suppliers(self.project.id)], [self.s.pk])

    def test_a_task_that_ends_without_a_result_leaves_the_supplier_due(self):
        self.scanner()
        self.fake.set_mode('fail', 'supplier_check')
        out = self.sweep()
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertEqual(ServiceRun.objects.filter(service__startswith='supplier').count(), 0)
        self.assertEqual([s.pk for s in ss.due_suppliers(self.project.id)], [self.s.pk])

    def test_a_name_the_scanner_did_not_report_was_not_checked_and_stays_due(self):
        self.supplier('Second', 'normal', ['second.vendor.test'])  # no row for it: the scanner reports nothing about it
        out = self.sweep()
        self.assertEqual(ServiceRun.objects.filter(service='supplier').count(), 1)  # the first, which answered
        self.assertEqual(SupplierHostCard.objects.filter(domain='second.vendor.test').count(), 0)
        self.assertEqual(out['suppliers'], 2)

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
        self.rows[self.D] = row(self.D)

    def assert_untouched(self):
        self.assertEqual(self.tasks, [])
        self.assertEqual(SupplierFinding.objects.count(), 0)

    def test_a_name_the_scanner_found_at_a_non_public_address_is_stored_as_blocked_with_no_finding_of_a_page_or_certificate(self):
        """The address vetting is the Sentinel's (cvengine_scanner/tests/probes/test_suppliers.py: a name that resolves to a private or loopback address is
        not contacted); this is what the server keeps of that report."""
        self.rows[self.D] = row(self.D, answered=False, requests=0, resolvable={}, fingerprints=[], server='', card={
            'state': 'blocked', 'addresses': [], 'evidence': {'address': 'blocked', 'note': 'The name resolves to an address that is not public, so it was not contacted.'}})
        self.sweep()
        card = SupplierHostCard.objects.get(supplier=self.s, domain=self.D)
        self.assertEqual(card.state, 'blocked')
        self.assertIn('not public', card.evidence['note'])
        self.assertEqual(SupplierFinding.objects.filter(category__in=('tls', 'web', 'exposed', 'cve')).count(), 0)

    def test_scanning_paused_stops_the_sweep_before_anything_is_asked(self):
        with mock.patch('reNgine.resources.global_pause_requested', return_value=True) as paused:
            out = self.sweep()
            all_out = ss.sweep_all()
        self.assertIn('paused', out['skipped'])
        self.assertIn('paused', all_out['skipped'])
        paused.assert_called_with(fail_closed=True)  # an unreadable control table is a pause, not a go-ahead
        self.assertEqual(self.tasks, [])
        self.assertEqual(ServiceRun.objects.count(), 0)  # the supplier stays due

    def test_a_pause_before_the_supplier_is_handed_to_the_scanner_records_nothing_and_leaves_it_due(self):
        answers = iter([False, False, True])  # the sweep's start, the supplier loop, then the pause arrives
        with mock.patch('reNgine.resources.global_pause_requested', side_effect=lambda **kw: next(answers, True)):
            out = self.sweep()
        self.assertIn('paused', out['skipped'])
        self.assertEqual(self.tasks, [])
        self.assertEqual(ServiceRun.objects.filter(service__startswith='supplier').count(), 0)

    def test_a_project_whose_bounty_engagement_has_not_confirmed_automated_testing_is_skipped(self):
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
        out = self.sweep()
        self.assertIn('automated testing', out['skipped'])
        self.assert_untouched()
        BountyEngagement.objects.update(automated_ok=True, policy_ack_at=timezone.now())
        self.assertEqual(self.sweep()['suppliers'], 1)

    def test_one_sweep_runs_at_a_time(self):
        self.scanner()
        with mock.patch('reNgine.resources.redis_claim') as claim:
            claim.return_value.__enter__.return_value = 'another worker'
            self.assertIn('another supplier sweep', self.sweep()['skipped'])
        self.assertEqual(self.tasks, [])
        with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
            self.assertIn('another sweep', ss.sweep_all()['skipped'])
        with mock.patch('cveFeed.ledger.sweep_claim', return_value=True) as claim_taken:
            out = ss.sweep_all()
        claim_taken.assert_called_once_with('suppliers', 2 * 60 * 60)
        self.assertEqual(out['suppliers'], 1)

    def test_an_excluded_name_is_not_contacted_and_neither_is_one_that_became_a_target(self):
        HostExclusion.objects.create(org=self.org1, host=self.D)
        self.sweep()
        self.assertEqual(self.tasks, [])
        self.assertEqual(SupplierHostCard.objects.get(supplier=self.s).state, 'excluded')
        HostExclusion.objects.all().delete()
        self.expire()
        Domain.objects.create(name='vendor.test', project=self.project, insert_date=timezone.now())  # now the project's own target
        self.sweep()
        self.assertEqual(self.tasks, [])
        self.assertEqual(SupplierHostCard.objects.get(supplier=self.s).state, 'excluded')

    def test_only_the_listed_names_that_may_be_contacted_are_sent_to_the_scanner(self):
        self.s.domains = [self.D, 'excluded.vendor.test']
        self.s.save()
        HostExclusion.objects.create(org=self.org1, host='excluded.vendor.test')
        self.sweep()
        self.assertEqual(self.asked(), [self.D])


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
        self.rows[self.D] = row(self.D, server='nginx/1.18.0', postures=[posture('tls_expired', sc.CRITICAL, 'tls'), posture('hsts_missing'), posture('security_headers_missing'),
                                                                         posture('spf_missing', category='email')])
        self.supplier(domains=[self.D])
        out = self.sweep()
        self.assertGreater(out['new'], 3)
        self.assertGreater(SupplierFinding.objects.filter(severity=sc.CRITICAL).count(), 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(client_for(self.admin).get('/cve/api/stats?project=sup-a').content, before_stats)
        self.assertEqual((HygieneFinding.objects.count(), Domain.objects.filter(project=self.project).count(), Subdomain.objects.count()), (0, 1, 0))

    def test_a_supplier_never_becomes_a_target_a_host_or_scan_work(self):
        from cveFeed import conductor, fullscan
        self.rows[self.D] = row(self.D)
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
            for forbidden in ('nmap_scan', 'naabu', 'bbot', 'nuclei', 'discovery', 'fullscan', 'host_assessment', 'tls_audit', 'start_scan', 'remediation'):
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
