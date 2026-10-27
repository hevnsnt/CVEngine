import json
import os
from datetime import timedelta
from unittest import mock

import requests
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import runzero, runzero_sync
from cveFeed.api_credentials import RETIRED, SERVICES, used_in_scans
from cveFeed.correlation import _record_matches
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, HostExclusion, RunZeroSync
from dashboard.models import ApiCredential, AuditLog, Org, OrgMembership, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

TOKEN = 'ET-test-token-0123456789abcdef'
SECRET_FRAGMENT = 'test-token-0123456789'


class FakeResponse:
    def __init__(self, status=200, body=b'', headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.closed = False

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]

    def close(self):
        self.closed = True


def page(key, records, next_key=''):
    return FakeResponse(200, json.dumps({key: records, 'next_key': next_key}).encode())


class FakeSession:
    """Answers each GET from a queue (a FakeResponse or an exception) and remembers what was asked."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def client(*answers):
    session = FakeSession(*answers)
    sleeps = []
    return runzero.Client(TOKEN, session=session, sleep=sleeps.append), session, sleeps


def asset(addresses, **kw):
    return {'id': 'a-1', 'addresses': addresses, 'names': [], 'os': '', 'os_version': '', 'hw': '', 'type': '', 'tags': [], 'site': '',
            'alive': True, 'last_seen': '2026-01-01T00:00:00+00:00', **kw}


def report(address, cve, port=None, **kw):
    return {'address': address, 'cve': cve, 'port': port, 'transport': 'tcp', 'name': 'x', 'severity': 'high', 'cvss3': 8.1, **kw}


class ParsingTests(SimpleTestCase):
    def test_an_asset_is_typed_and_clipped(self):
        a = runzero.parse_asset({
            'id': 'x' * 500, 'addresses': ['192.0.2.7', 'not-an-ip', '2001:DB8:0:0:0:0:0:1', 5, None], 'addresses_extra': ['192.0.2.7', '198.51.100.9'],
            'names': ['host.example.test', 'a' * 1000, {'x': 1}], 'os': 'Ubuntu\x00Linux', 'os_version': 20.04, 'hw': ['not text'],
            'type': 'Server', 'tags': {'owner': 'it', 'bare': ''}, 'site_name': 'Primary', 'alive': 'yes', 'last_seen': 1576300370})
        self.assertEqual(len(a['id']), 64)
        self.assertEqual(a['addresses'], ['192.0.2.7', '2001:db8::1', '198.51.100.9'])
        self.assertEqual(a['names'][0], 'host.example.test')
        self.assertEqual(len(a['names'][1]), 255)
        self.assertEqual((a['os'], a['os_version'], a['hw']), ('UbuntuLinux', '20.04', ''))
        self.assertEqual(a['tags'], ['owner:it', 'bare'])
        self.assertIsNone(a['alive'])  # only a real boolean counts
        self.assertTrue(a['last_seen'].startswith('2019-12-14'))

    def test_junk_assets_are_dropped(self):
        for raw in (None, 'text', [], {}, {'addresses': []}, {'addresses': ['nope']}, {'addresses': 'also nope'}):
            self.assertIsNone(runzero.parse_asset(raw), raw)

    def test_hostile_times_and_numbers_do_not_raise(self):
        self.assertEqual(runzero._time(10 ** 30), '')
        self.assertEqual(runzero._time(float('nan')), '')
        self.assertEqual(runzero._time(True), '')
        self.assertIsNone(runzero._number(float('nan')))
        self.assertIsNone(runzero._number(10 ** 9))
        self.assertIsNone(runzero._port(70000))
        self.assertIsNone(runzero._port('x'))
        self.assertEqual(runzero._port('443'), 443)

    def test_vulnerability_reports_keep_only_real_cve_ids_with_a_place(self):
        rows = runzero.parse_vulnerability({
            'vulnerability_cve': 'cve-2021-44228, CVE-2022-0001 and something else', 'vulnerability_service_address': '192.0.2.7',
            'vulnerability_service_port': '8080', 'vulnerability_service_transport': 'TCP', 'vulnerability_name': 'Log4Shell',
            'vulnerability_severity': 'Critical', 'vulnerability_cvss3_base_score': 10})
        self.assertEqual([(r['cve'], r['address'], r['port'], r['transport'], r['severity'], r['cvss3']) for r in rows],
                         [('CVE-2021-44228', '192.0.2.7', 8080, 'tcp', 'critical', 10.0), ('CVE-2022-0001', '192.0.2.7', 8080, 'tcp', 'critical', 10.0)])
        self.assertEqual(runzero.parse_vulnerability({'vulnerability_cve': 'no cve here', 'addresses': ['192.0.2.7']}), [])
        self.assertEqual(runzero.parse_vulnerability({'vulnerability_cve': 'CVE-2021-1234'}), [])  # nowhere to put it
        self.assertEqual(runzero.parse_vulnerability('x'), [])

    def test_a_report_without_a_service_address_is_about_the_whole_asset(self):
        rows = runzero.parse_vulnerability({'vulnerability_cve': 'CVE-2021-1234', 'addresses': ['192.0.2.7', '192.0.2.8'], 'vulnerability_service_port': 80})
        self.assertEqual([(r['address'], r['port']) for r in rows], [('192.0.2.7', None), ('192.0.2.8', None)])

    def test_token_shape(self):
        self.assertTrue(runzero.valid_token(TOKEN))
        for bad in ('', 'short', 'has space in it 12345', 'new\nline12345678', None, 5):
            self.assertFalse(runzero.valid_token(bad), bad)
        with self.assertRaises(runzero.RunZeroError) as ctx:
            runzero.Client('bad token with spaces')
        self.assertEqual(ctx.exception.kind, 'auth')


class ClientTests(SimpleTestCase):
    def test_pages_are_followed_and_the_token_only_travels_in_the_header(self):
        c, session, _ = client(page('assets', [{'addresses': ['192.0.2.1']}], 'k1'), page('assets', [{'addresses': ['192.0.2.2']}]))
        assets, truncated = c.fetch_assets('alive:true')
        self.assertEqual([a['addresses'] for a in assets], [['192.0.2.1'], ['192.0.2.2']])
        self.assertFalse(truncated)
        (url1, kw1), (url2, kw2) = session.calls
        self.assertEqual(url1, 'https://console.runzero.com/api/v1.0/export/org/assets.json')
        self.assertEqual(kw1['params']['search'], 'alive:true')
        self.assertNotIn('start_key', kw1['params'])
        self.assertEqual(kw2['params']['start_key'], 'k1')
        for url, kw in session.calls:
            self.assertEqual(kw['headers']['Authorization'], f'Bearer {TOKEN}')
            self.assertNotIn(SECRET_FRAGMENT, url + json.dumps(kw['params']))
            self.assertFalse(kw['allow_redirects'])  # a redirect must never carry the bearer token elsewhere
            self.assertEqual(kw['timeout'], runzero.TIMEOUT)

    def test_a_bare_array_is_one_page_and_a_repeated_key_stops_the_walk(self):
        c, session, _ = client(FakeResponse(200, b'[{"addresses": ["192.0.2.1"]}]'))
        self.assertEqual(len(c.fetch_assets()[0]), 1)
        self.assertEqual(len(session.calls), 1)
        c, session, _ = client(page('assets', [{'addresses': ['192.0.2.1']}], 'same'), page('assets', [{'addresses': ['192.0.2.2']}], 'same'),
                               page('assets', [{'addresses': ['192.0.2.3']}], 'same'))
        self.assertEqual(len(c.fetch_assets()[0]), 2)  # the third page is never asked for
        self.assertEqual(len(session.calls), 2)

    def test_a_nearly_spent_daily_quota_stops_the_walk_and_says_so(self):
        low = FakeResponse(200, json.dumps({'assets': [{'addresses': ['192.0.2.1']}], 'next_key': 'k1'}).encode(), {'X-API-Usage-Remaining': '3'})
        c, session, _ = client(low, page('assets', [{'addresses': ['192.0.2.2']}]))
        assets, _ = c.fetch_assets()
        self.assertEqual((len(assets), len(session.calls), c.quota_low, c.remaining), (1, 1, True, 3))  # the second page is not asked for

    def test_plenty_of_quota_or_no_header_changes_nothing(self):
        c, session, _ = client(FakeResponse(200, json.dumps({'assets': [{'addresses': ['192.0.2.1']}], 'next_key': 'k1'}).encode(),
                                            {'X-API-Usage-Remaining': '900'}), page('assets', [{'addresses': ['192.0.2.2']}]))
        self.assertEqual((len(c.fetch_assets()[0]), c.quota_low), (2, False))

    def test_the_vulnerabilities_key_may_be_spelled_the_way_runzeros_prose_spells_it(self):
        record = {'vulnerability_asset_address': '192.0.2.1', 'vulnerability_cve': 'CVE-2099-1'}
        c, _, _ = client(FakeResponse(200, json.dumps({'vulnerabilites': [record], 'next_key': ''}).encode()))
        c.fetch_vulnerabilities()  # no bad_response

    def test_the_record_limit_cuts_the_list_and_says_so(self):
        c, _, _ = client(page('assets', [{'addresses': ['192.0.2.%d' % i]} for i in range(1, 6)], 'more'))
        assets, truncated = c.fetch_assets(limit=3)
        self.assertEqual((len(assets), truncated), (3, True))

    def test_odd_records_inside_a_page_are_skipped_not_fatal(self):
        c, _, _ = client(page('assets', ['x', None, 5, {'addresses': ['192.0.2.1']}, {'addresses': 'junk'}]))
        self.assertEqual(len(c.fetch_assets()[0]), 1)

    def test_a_bad_token_is_reported_without_echoing_it(self):
        for status in (401, 403):
            c, _, sleeps = client(FakeResponse(status, b'{"title": "bad token %s"}' % TOKEN.encode()))
            with self.assertRaises(runzero.RunZeroError) as ctx:
                c.fetch_assets()
            self.assertEqual(ctx.exception.kind, 'auth')
            self.assertNotIn(SECRET_FRAGMENT, ctx.exception.message)
            self.assertEqual(sleeps, [])  # never retried: it would only lock the token out

    def test_a_rate_limit_waits_for_retry_after_then_succeeds(self):
        c, session, sleeps = client(FakeResponse(429, b'', {'Retry-After': '7'}), page('assets', [{'addresses': ['192.0.2.1']}]))
        self.assertEqual(len(c.fetch_assets()[0]), 1)
        self.assertEqual(sleeps, [7.0])
        self.assertEqual(len(session.calls), 2)

    def test_a_rate_limit_that_never_clears_is_a_clear_error_and_waits_are_capped(self):
        c, session, sleeps = client(*[FakeResponse(429, b'', {'Retry-After': '99999'}) for _ in range(runzero.MAX_RETRIES + 1)])
        with self.assertRaises(runzero.RunZeroError) as ctx:
            c.fetch_assets()
        self.assertEqual(ctx.exception.kind, 'rate_limit')
        self.assertEqual(len(sleeps), runzero.MAX_RETRIES)
        self.assertTrue(all(s <= runzero.MAX_WAIT for s in sleeps))

    def test_server_errors_are_retried_then_reported(self):
        c, _, _ = client(FakeResponse(503), page('assets', [{'addresses': ['192.0.2.1']}]))
        self.assertEqual(len(c.fetch_assets()[0]), 1)
        c, _, _ = client(*[FakeResponse(500)])
        with self.assertRaises(runzero.RunZeroError) as ctx:
            c.fetch_assets()
        self.assertEqual((ctx.exception.kind, ctx.exception.status), ('http', 500))

    def test_malformed_json_is_a_bad_response(self):
        for body in (b'<html>Cloudflare</html>', b'', b'{"assets": [', b'\xff\xfe'):
            c, _, _ = client(FakeResponse(200, body))
            with self.assertRaises(runzero.RunZeroError) as ctx:
                c.fetch_assets()
            self.assertEqual(ctx.exception.kind, 'bad_response', body)

    def test_an_unexpected_shape_is_a_bad_response(self):
        for body in (b'{"assets": "no"}', b'{"other": []}', b'"text"', b'5', b'null'):
            c, _, _ = client(FakeResponse(200, body))
            with self.assertRaises(runzero.RunZeroError) as ctx:
                c.fetch_assets()
            self.assertEqual(ctx.exception.kind, 'bad_response', body)

    def test_deeply_nested_json_does_not_crash(self):
        c, _, _ = client(FakeResponse(200, b'[' * 100000 + b']' * 100000))
        with self.assertRaises(runzero.RunZeroError):
            c.fetch_assets()

    def test_an_oversized_reply_is_refused(self):
        body = json.dumps({'assets': [{'addresses': ['192.0.2.1'], 'names': ['x' * 200] * 5}] * 50}).encode()
        with mock.patch.object(runzero, 'MAX_BODY_BYTES', 1024):
            c, _, _ = client(FakeResponse(200, body))
            with self.assertRaises(runzero.RunZeroError) as ctx:
                c.fetch_assets()
        self.assertEqual(ctx.exception.kind, 'too_large')

    def test_huge_values_inside_a_valid_reply_are_clipped(self):
        c, _, _ = client(page('assets', [{'addresses': ['192.0.2.1'], 'os': 'x' * 10 ** 6, 'names': [str(i) + 'n' * 10 ** 5 for i in range(100)], 'tags': {str(i): 'v' * 1000 for i in range(500)}}]))
        a = c.fetch_assets()[0][0]
        self.assertEqual((len(a['os']), len(a['names']), len(a['tags'])), (100, 20, 20))
        self.assertLessEqual(max(len(t) for t in a['tags']), 100)

    def test_a_network_failure_is_reported_without_details_that_could_leak(self):
        c, _, _ = client(requests.ConnectionError('HTTPSConnectionPool: Max retries ... Authorization: Bearer %s' % TOKEN))
        with self.assertRaises(runzero.RunZeroError) as ctx:
            c.fetch_assets()
        self.assertEqual(ctx.exception.kind, 'network')
        self.assertNotIn(SECRET_FRAGMENT, ctx.exception.message)

    def test_an_unknown_field_name_falls_back_to_whole_records(self):
        c, session, _ = client(FakeResponse(400), page('assets', [{'addresses': ['192.0.2.1']}]))
        self.assertEqual(len(c.fetch_assets()[0]), 1)
        self.assertIn('fields', session.calls[0][1]['params'])
        self.assertNotIn('fields', session.calls[1][1]['params'])

    def test_vulnerabilities_use_their_own_key_and_endpoint(self):
        c, session, _ = client(page('vulnerabilities', [{'vulnerability_cve': 'CVE-2021-1234', 'vulnerability_service_address': '192.0.2.1',
                                                         'vulnerability_service_port': 22}]))
        reports, _ = c.fetch_vulnerabilities()
        self.assertEqual([(r['address'], r['cve'], r['port']) for r in reports], [('192.0.2.1', 'CVE-2021-1234', 22)])
        self.assertTrue(session.calls[0][0].endswith('/export/org/vulnerabilities.json'))

    def test_test_connection(self):
        c, session, _ = client(page('assets', [{'id': 'a'}]))
        self.assertEqual(c.test_connection(), 1)
        self.assertEqual(session.calls[0][1]['params']['page_size'], 1)
        c, _, _ = client(FakeResponse(401))
        with self.assertRaises(runzero.RunZeroError):
            c.test_connection()

    def test_the_search_is_clipped_and_cleaned(self):
        c, session, _ = client(page('assets', []))
        c.fetch_assets('alive:true\n' + 'x' * 1000)
        self.assertLessEqual(len(session.calls[0][1]['params']['search']), 300)
        self.assertNotIn('\n', session.calls[0][1]['params']['search'])


class FakeClient:
    """Stands in for runzero.Client in the sync tests."""
    assets, reports, error, searches = [], [], None, []
    quota_low = False

    def __init__(self, token):
        self.token = token

    def fetch_assets(self, search='', limit=0):
        if self.error:
            raise self.error
        FakeClient.searches.append(search)
        return list(self.assets), False

    def fetch_vulnerabilities(self, search='', limit=0):
        return list(self.reports), False


def fake_client(assets=(), reports=(), error=None):
    return mock.patch.object(runzero_sync.runzero, 'Client', type('C', (FakeClient,), {'assets': list(assets), 'reports': list(reports), 'error': error}))


class SyncFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org_a, cls.org_b = Org.objects.create(name='A', slug='rz-a'), Org.objects.create(name='B', slug='rz-b')
        cls.pa = Project.objects.create(name='PA', slug='rz-pa', insert_date=now, org=cls.org_a)
        cls.pa2 = Project.objects.create(name='PA2', slug='rz-pa2', insert_date=now, org=cls.org_a)
        cls.pb = Project.objects.create(name='PB', slug='rz-pb', insert_date=now, org=cls.org_b)
        cls.da = Domain.objects.create(name='a.example.test', project=cls.pa, insert_date=now, org=cls.org_a)
        cls.da2 = Domain.objects.create(name='a2.example.test', project=cls.pa2, insert_date=now, org=cls.org_a)
        cls.db = Domain.objects.create(name='b.example.test', project=cls.pb, insert_date=now, org=cls.org_b)
        cls.sa = Subdomain.objects.create(name='www.a.example.test', target_domain=cls.da)
        cls.sa2 = Subdomain.objects.create(name='www.a2.example.test', target_domain=cls.da2)
        cls.sb = Subdomain.objects.create(name='www.b.example.test', target_domain=cls.db)
        cls.ip_a = IpAddress.objects.create(address='192.0.2.10', org=cls.org_a)
        cls.ip_a2 = IpAddress.objects.create(address='192.0.2.11', org=cls.org_a)  # the org's, but another project's host
        cls.ip_b = IpAddress.objects.create(address='192.0.2.10', org=cls.org_b)  # the same address in another organization
        cls.sa.ip_addresses.add(cls.ip_a)
        cls.sa2.ip_addresses.add(cls.ip_a2)
        cls.sb.ip_addresses.add(cls.ip_b)
        ApiCredential.objects.create(project=cls.pa, service='runzero', value={'api_key': TOKEN})

    def sync(self, project=None, **kw):
        with fake_client(**kw):
            return runzero_sync.sync_project(project or self.pa)


class EnrichmentTests(SyncFixture):
    def test_matching_addresses_get_runzero_facts_and_an_empty_os_guess_is_filled(self):
        a = asset(['192.0.2.10'], os='Ubuntu Linux', os_version='22.04', hw='Dell PowerEdge', type='Server', tags=['prod'], site='Primary', names=['web01'])
        result = self.sync(assets=[a])
        self.assertEqual((result['state'], result['counts']['assets'], result['counts']['matched_hosts'], result['counts']['updated_hosts']), ('ok', 1, 1, 1))
        self.ip_a.refresh_from_db()
        rz = self.ip_a.fingerprint['runzero']
        self.assertEqual((rz['os'], rz['os_version'], rz['hw'], rz['type'], rz['tags'], rz['site'], rz['names']),
                         ('Ubuntu Linux', '22.04', 'Dell PowerEdge', 'Server', ['prod'], 'Primary', ['web01']))
        self.assertEqual(self.ip_a.os_guess, 'Ubuntu Linux 22.04')
        self.assertIsNone(self.ip_a.os_accuracy)  # runZero gives no accuracy figure; it is not invented

    def test_an_existing_os_guess_and_other_fingerprint_keys_are_kept(self):
        IpAddress.objects.filter(pk=self.ip_a.pk).update(os_guess='Linux 5.x (nmap)', fingerprint={'scripts': {'smb-os-discovery': 'x'}, 'facts': {'os': 'F'}})
        self.sync(assets=[asset(['192.0.2.10'], os='Ubuntu Linux')])
        self.ip_a.refresh_from_db()
        self.assertEqual(self.ip_a.os_guess, 'Linux 5.x (nmap)')
        self.assertEqual(set(self.ip_a.fingerprint), {'scripts', 'facts', 'runzero'})

    def test_an_unchanged_inventory_writes_nothing_the_second_time(self):
        self.sync(assets=[asset(['192.0.2.10'], os='Ubuntu Linux')])
        first = IpAddress.objects.get(pk=self.ip_a.pk).fingerprint['runzero']['updated']
        result = self.sync(assets=[asset(['192.0.2.10'], os='Ubuntu Linux')])
        self.assertEqual(result['counts']['updated_hosts'], 0)
        self.assertEqual(IpAddress.objects.get(pk=self.ip_a.pk).fingerprint['runzero']['updated'], first)

    def test_another_organizations_address_and_another_projects_host_are_never_touched(self):
        self.sync(assets=[asset(['192.0.2.10', '192.0.2.11'], os='Ubuntu Linux')])
        self.ip_b.refresh_from_db()
        self.ip_a2.refresh_from_db()
        self.assertNotIn('runzero', self.ip_b.fingerprint)  # same address, other tenant
        self.assertEqual(self.ip_b.os_guess, '')
        self.assertNotIn('runzero', self.ip_a2.fingerprint)  # same org, a host of a project that did not sync
        self.assertEqual(self.ip_a.__class__.objects.get(pk=self.ip_a.pk).fingerprint['runzero']['os'], 'Ubuntu Linux')

    def test_a_token_of_one_tenant_never_reads_another_tenants_token(self):
        ApiCredential.objects.create(project=self.pb, service='runzero', value={'api_key': 'ET-other-tenant-token-xyz'})
        seen = []
        with mock.patch.object(runzero_sync.runzero, 'Client', lambda token: seen.append(token) or FakeClient(token)):
            runzero_sync.sync_project(self.pa)
            runzero_sync.sync_project(self.pb)
        self.assertEqual(seen, [TOKEN, 'ET-other-tenant-token-xyz'])

    def test_the_most_recently_seen_asset_wins_when_an_address_is_listed_twice(self):
        old = asset(['192.0.2.10'], os='Old OS', last_seen='2020-01-01T00:00:00+00:00')
        new = asset(['192.0.2.10'], os='New OS', last_seen='2026-01-01T00:00:00+00:00')
        self.sync(assets=[new, old])
        self.assertEqual(IpAddress.objects.get(pk=self.ip_a.pk).fingerprint['runzero']['os'], 'New OS')

    def test_a_project_without_a_token_does_nothing(self):
        result = self.sync(self.pa2, assets=[asset(['192.0.2.11'])])
        self.assertEqual(result['state'], 'no_key')
        self.assertFalse(RunZeroSync.objects.filter(project=self.pa2).exists())
        self.assertNotIn('runzero', IpAddress.objects.get(pk=self.ip_a2.pk).fingerprint)

    def test_an_organization_token_serves_each_of_its_projects(self):
        ApiCredential.objects.create(org=self.org_a, service='runzero', value={'api_key': 'ET-org-level-token-12345'})
        self.assertEqual(self.sync(self.pa2, assets=[asset(['192.0.2.11'], os='Windows')])['state'], 'ok')
        self.assertEqual(IpAddress.objects.get(pk=self.ip_a2.pk).fingerprint['runzero']['os'], 'Windows')


class ReportsAsEvidenceTests(SyncFixture):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-5', title='t', published_at=timezone.now(), cvss=7.5)
        cls.cve2 = CVEEntry.objects.create(cve_id='CVE-2099-6', title='t', published_at=timezone.now(), cvss=7.5)
        cls.port = Port.objects.create(number=443, product='nginx', version='1.18')
        cls.ip_a.ports.add(cls.port)

    def match(self, cve, **kw):
        defaults = dict(subdomain=self.sa, source='port', matched_product='nginx', confidence=0.85, evidence={'port': 443, 'ip': '192.0.2.10'})
        return CVEMatch.objects.create(cve_entry=cve, **{**defaults, **kw})

    def test_a_report_for_a_matched_cve_raises_its_confidence_once_and_confirms_nothing(self):
        m = self.match(self.cve)
        r = [report('192.0.2.10', 'CVE-2099-5', 443)]
        self.sync(assets=[asset(['192.0.2.10'])], reports=r)
        m.refresh_from_db()
        self.assertEqual((m.confidence, m.evidence['runzero'], m.ai_verdict), (0.95, True, ''))
        self.assertEqual(self.sync(assets=[asset(['192.0.2.10'])], reports=r)['counts']['corroborated_matches'], 0)
        m.refresh_from_db()
        self.assertEqual(m.confidence, 0.95)  # not again on the next sync

    def test_a_boost_is_taken_back_when_the_report_goes_away_or_the_asset_leaves(self):
        m = self.match(self.cve)
        r = [report('192.0.2.10', 'CVE-2099-5', 443)]
        self.sync(assets=[asset(['192.0.2.10'], os='Ubuntu Linux')], reports=r)
        m.refresh_from_db()
        self.assertEqual((m.confidence, m.evidence['runzero']), (0.95, True))
        self.sync(assets=[asset(['192.0.2.10'], os='Ubuntu Linux')], reports=[])  # the report is gone, the asset is still there
        m.refresh_from_db()
        self.assertEqual((m.confidence, 'runzero' in m.evidence), (0.85, False))
        self.sync(assets=[asset(['192.0.2.10'])], reports=r)
        self.sync(assets=[asset(['192.0.2.99'])], reports=[])  # the asset itself left the inventory
        m.refresh_from_db()
        self.ip_a.refresh_from_db()
        self.assertEqual((m.confidence, 'runzero' in m.evidence), (0.85, False))
        self.assertNotIn('runzero', self.ip_a.fingerprint)  # its OS and reports no longer describe the host

    def test_reports_never_create_a_match_and_are_stored_on_the_host(self):
        result = self.sync(assets=[asset(['192.0.2.10'])], reports=[report('192.0.2.10', 'CVE-2099-6', 80)])
        self.assertEqual(CVEMatch.objects.count(), 0)
        self.assertEqual(result['counts']['cve_reports'], 1)
        vulns = IpAddress.objects.get(pk=self.ip_a.pk).fingerprint['runzero']['vulns']
        self.assertEqual([(v['cve'], v['port']) for v in vulns], [('CVE-2099-6', 80)])

    def test_a_report_on_another_port_ruled_out_or_patched_matches_do_not_count(self):
        other_port = self.match(self.cve, matched_product='other', evidence={'port': 8080})
        ruled_out = self.match(self.cve2, ai_verdict='not_affected', confidence=0.0)
        patched = self.match(self.cve2, matched_product='p', distro_status='patched', confidence=0.2)
        self.sync(assets=[asset(['192.0.2.10'])], reports=[report('192.0.2.10', 'CVE-2099-5', 443), report('192.0.2.10', 'CVE-2099-6', 443)])
        for m, expected in ((other_port, 0.85), (ruled_out, 0.0), (patched, 0.2)):
            m.refresh_from_db()
            self.assertEqual(m.confidence, expected)
            self.assertNotIn('runzero', m.evidence)

    def test_a_report_without_a_port_applies_to_the_whole_host(self):
        m = self.match(self.cve)
        self.sync(assets=[asset(['192.0.2.10'])], reports=[report('192.0.2.10', 'CVE-2099-5', None)])
        m.refresh_from_db()
        self.assertEqual(m.confidence, 0.95)

    def test_another_tenants_match_is_not_raised_by_this_tenants_report(self):
        other = CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sb, source='port', confidence=0.85, evidence={'port': 443})
        self.ip_b.ports.add(self.port)
        self.sync(assets=[asset(['192.0.2.10'])], reports=[report('192.0.2.10', 'CVE-2099-5', 443)])
        other.refresh_from_db()
        self.assertEqual(other.confidence, 0.85)

    def test_correlation_applies_the_same_evidence_when_it_finds_the_match_itself(self):
        class Cve:
            id, kev, cve_id = 1, False, 'CVE-2099-5'
            affected = [{'product': 'nginx', 'vendor': 'f5', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]

        from cveFeed.correlation import build_product_index

        class Sub:
            id, scan_history_id = 5, 7
        rows, plain = [], []
        index = build_product_index([Cve])
        _record_matches(Sub, 'nginx', '1.18.0', 'nginx', 'port', index, {1: Cve}, 0.0, None, plain)
        _record_matches(Sub, 'nginx', '1.18.0', 'nginx', 'port', index, {1: Cve}, 0.0, None, rows, corroborated={'CVE-2099-5'})
        self.assertEqual((plain[0]['confidence'], 'runzero' in plain[0]['evidence']), (0.85, False))
        self.assertEqual((rows[0]['confidence'], rows[0]['evidence']['runzero']), (0.95, True))
        _record_matches(Sub, 'nginx', '1.18.0', 'nginx', 'port', index, {1: Cve}, 0.0, None, rows, corroborated={'CVE-1999-1'})
        self.assertEqual(rows[1]['confidence'], 0.85)

    def test_boost_is_capped_at_one(self):
        self.assertEqual(runzero.boosted(0.95), 1.0)
        self.assertEqual(runzero.boosted(1.0), 1.0)


class ImportTests(SyncFixture):
    def run_import(self, assets, enabled=True, search=None, **env):
        row = runzero_sync.settings_for(self.pa)
        row.import_enabled = enabled
        if search is not None:
            row.search = search
        row.save()
        with mock.patch('agentapi.services._start_discoveries', return_value=[]) as discoveries, \
                mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async') as watch, mock.patch.dict(os.environ, env):
            result = self.sync(assets=assets)
        return result, discoveries, watch

    def domains(self):
        return set(Domain.objects.filter(project=self.pa).values_list('name', flat=True))

    def test_import_is_off_by_default(self):
        with mock.patch('agentapi.services._start_discoveries') as discoveries:
            result = self.sync(assets=[asset(['198.51.100.20'])])
        self.assertNotIn('imported', result['counts'])
        self.assertEqual(self.domains(), {'a.example.test'})
        discoveries.assert_not_called()

    def test_new_public_addresses_are_added_as_targets_and_queued_for_discovery(self):
        result, discoveries, _ = self.run_import([asset(['198.51.100.20']), asset(['198.51.100.21'])])
        self.assertEqual(result['counts']['imported'], 2)
        self.assertEqual(self.domains(), {'a.example.test', '198.51.100.20', '198.51.100.21'})
        self.assertEqual(Domain.objects.get(name='198.51.100.20').org_id, self.org_a.pk)  # tenancy: the project's own organization
        self.assertEqual(len(discoveries.call_args[0][0]), 2)
        self.assertFalse(Domain.objects.filter(name='198.51.100.20', project=self.pb).exists())

    def test_known_blocked_and_excluded_addresses_are_skipped_with_reasons(self):
        HostExclusion.objects.create(org=self.org_a, host='198.51.100.30')
        Domain.objects.create(name='198.51.100.40', project=self.pa2, insert_date=timezone.now(), org=self.org_a)  # known to the organization
        result, _, _ = self.run_import([asset(['198.51.100.20', '10.0.0.5', '127.0.0.1', '169.254.1.1', '198.51.100.30', '198.51.100.40'])])
        skipped = result['counts']['skipped']
        self.assertEqual(result['counts']['imported'], 1)
        self.assertEqual((skipped['blocked'], skipped['already_known'], skipped['excluded']), (3, 1, 1))
        self.assertNotIn('10.0.0.5', self.domains())

    def test_a_public_address_outside_every_owned_network_is_never_imported(self):
        """An inventory search can hold addresses nobody authorized scanning (a partner's range, a cloud address a device talked to)."""
        result, discoveries, _ = self.run_import([asset(['8.8.8.8'])])
        self.assertEqual(result['counts']['imported'], 0)
        self.assertEqual(result['counts']['skipped']['not_owned'], 1)
        self.assertEqual(self.domains(), {'a.example.test'})
        discoveries.assert_not_called()

    def test_a_public_address_inside_a_network_the_organization_owns_is_imported(self):
        Domain.objects.create(name='8.8.8.0/24', project=self.pa, insert_date=timezone.now(), org=self.org_a)
        result, _, _ = self.run_import([asset(['8.8.8.8']), asset(['1.1.1.1'])])
        self.assertEqual(result['counts']['imported'], 1)
        self.assertEqual(result['counts']['skipped']['not_owned'], 1)
        self.assertIn('8.8.8.8', self.domains())

    def test_the_networks_of_another_organization_prove_nothing(self):
        Domain.objects.create(name='8.8.8.0/24', project=self.pb, insert_date=timezone.now(), org=self.org_b)
        result, _, _ = self.run_import([asset(['8.8.8.8'])])
        self.assertEqual(result['counts']['skipped']['not_owned'], 1)

    def test_private_ranges_are_imported_only_when_the_operator_allows_them(self):
        result, _, _ = self.run_import([asset(['10.0.0.5'])], CVENGINE_ALLOW_PRIVATE_TARGETS='1')
        self.assertEqual(result['counts']['imported'], 1)
        self.assertIn('10.0.0.5', self.domains())
        self.assertEqual(Domain.objects.filter(name='127.0.0.1').count(), 0)

    def test_names_are_imported_only_under_a_domain_the_organization_already_has(self):
        names = ['api.a.example.test', 'a.example.test', 'attacker.evil.test', 'LAPTOP-F4P1R6', 'printer', 'x.b.example.test']
        result, _, watch = self.run_import([asset(['198.51.100.20'], names=names)])
        self.assertEqual(self.domains(), {'a.example.test', '198.51.100.20', 'api.a.example.test'})
        self.assertEqual(result['counts']['skipped']['name_out_of_scope'], 2)  # evil.test and the other tenant's domain
        self.assertEqual(result['counts']['skipped']['already_known'], 1)
        self.assertEqual(watch.call_count, 1)

    def test_the_import_cap_leaves_the_rest_for_the_next_sync(self):
        assets = [asset(['198.51.100.%d' % i]) for i in range(20, 30)]
        result, _, _ = self.run_import(assets, CVENGINE_RUNZERO_IMPORT_MAX='3')
        self.assertEqual((result['counts']['imported'], result['counts']['skipped']['over_cap']), (3, 7))
        result, _, _ = self.run_import(assets, CVENGINE_RUNZERO_IMPORT_MAX='3')
        self.assertEqual(result['counts']['imported'], 3)  # the next sync carries on

    def test_the_configured_search_limits_what_is_imported_but_not_enrichment(self):
        FakeClient.searches = []
        self.run_import([asset(['198.51.100.20'])], search='tag:edge')
        self.assertEqual(FakeClient.searches, ['', 'tag:edge'])

    def test_a_refusal_from_add_targets_is_counted_not_raised(self):
        from agentapi.services import ApiError
        with mock.patch('agentapi.services.add_entries', side_effect=ApiError(400, 'too many')):
            result, _, _ = self.run_import([asset(['198.51.100.20'])])
        self.assertEqual((result['state'], result['counts']['imported'], result['counts']['skipped']['rejected']), ('ok', 0, 1))


class FailureTests(SyncFixture):
    def test_a_bad_token_is_recorded_clearly_and_logged_to_the_feed(self):
        err = runzero.RunZeroError('auth', 'runZero rejected the token (HTTP 401); use an Export API token for this organization')
        result = self.sync(error=err)
        self.assertEqual(result['state'], 'error')
        row = RunZeroSync.objects.get(project=self.pa)
        self.assertEqual((row.status, row.last_error), ('error', err.message))
        self.assertIsNotNone(row.last_sync_at)
        self.assertIsNone(row.last_ok_at)
        entry = AgentActivity.objects.get(kind='runzero')
        self.assertEqual((entry.status, entry.project_id), ('failed', self.pa.pk))
        self.assertNotIn(SECRET_FRAGMENT, entry.message + row.last_error)

    def test_a_rate_limit_and_a_network_error_are_reported(self):
        for kind, text in (('rate_limit', 'runZero is rate limiting this token'), ('network', 'could not reach runZero (ConnectionError)')):
            RunZeroSync.objects.filter(project=self.pa).update(status='', started_at=None)
            self.assertEqual(self.sync(error=runzero.RunZeroError(kind, text))['error'], text)

    def test_an_unexpected_exception_never_escapes_and_keeps_no_raw_text(self):
        result = self.sync(error=RuntimeError('boom %s' % TOKEN))
        self.assertEqual(result['state'], 'error')
        self.assertIn('diagnostic', result['error'])
        self.assertNotIn(SECRET_FRAGMENT, result['error'])
        self.assertEqual(RunZeroSync.objects.get(project=self.pa).status, 'error')

    def test_the_worker_log_never_holds_the_token_either(self):
        with self.assertLogs('cveFeed.activity', level='WARNING') as logged:
            self.sync(error=RuntimeError('boom %s' % TOKEN))
        self.assertNotIn(SECRET_FRAGMENT, '\n'.join(logged.output))

    def test_a_failure_keeps_the_last_good_counts(self):
        self.sync(assets=[asset(['192.0.2.10'])])
        self.sync(error=runzero.RunZeroError('http', 'runZero answered HTTP 500'))
        row = RunZeroSync.objects.get(project=self.pa)
        self.assertEqual((row.status, row.counts['assets']), ('error', 1))
        self.assertIsNotNone(row.last_ok_at)

    def test_one_sync_at_a_time_and_a_dead_worker_does_not_block_forever(self):
        row = runzero_sync.settings_for(self.pa)
        RunZeroSync.objects.filter(pk=row.pk).update(status='running', started_at=timezone.now())
        self.assertEqual(self.sync()['state'], 'busy')
        RunZeroSync.objects.filter(pk=row.pk).update(started_at=timezone.now() - runzero_sync.STALE_RUNNING - timedelta(minutes=1))
        self.assertEqual(self.sync()['state'], 'ok')

    def test_a_successful_sync_writes_an_activity_entry(self):
        self.sync(assets=[asset(['192.0.2.10'])])
        entry = AgentActivity.objects.get(kind='runzero')
        self.assertEqual(entry.status, 'done')
        self.assertIn('1 assets read', entry.message)


class ScheduleTests(SyncFixture):
    def test_projects_with_a_token_are_due_until_they_have_synced_recently(self):
        ApiCredential.objects.create(org=self.org_b, service='runzero', value={'api_key': 'ET-org-b-token-123456'})
        self.assertEqual(runzero_sync.due_project_ids(), sorted([self.pa.pk, self.pb.pk]))  # own token, and inherited from the organization
        self.sync(assets=[])
        self.assertEqual(runzero_sync.due_project_ids(), [self.pb.pk])
        RunZeroSync.objects.filter(project=self.pa).update(last_sync_at=timezone.now() - timedelta(hours=7))
        self.assertIn(self.pa.pk, runzero_sync.due_project_ids())

    def test_the_interval_comes_from_the_environment(self):
        self.sync(assets=[])
        RunZeroSync.objects.filter(project=self.pa).update(last_sync_at=timezone.now() - timedelta(hours=2))
        self.assertNotIn(self.pa.pk, runzero_sync.due_project_ids())
        with mock.patch.dict(os.environ, {'CVENGINE_RUNZERO_SYNC_HOURS': '1'}):
            self.assertIn(self.pa.pk, runzero_sync.due_project_ids())
        for value, expected in (('bad', 6), ('0', 1), ('-5', 1), ('', 6)):
            with mock.patch.dict(os.environ, {'CVENGINE_RUNZERO_SYNC_HOURS': value}):
                self.assertEqual(runzero_sync.interval_hours(), expected, value)

    def test_the_beat_entry_exists_and_the_task_queues_due_projects(self):
        from django_celery_beat.models import PeriodicTask
        from cveFeed import tasks
        entry = PeriodicTask.objects.get(name='cvengine-runzero-sync')
        self.assertEqual((entry.task, entry.enabled, entry.queue), ('runzero_sync_due', True, 'cve_feed_queue'))
        with mock.patch.object(tasks.runzero_sync_project, 'apply_async') as queued:
            self.assertEqual(tasks.runzero_sync_due(), {'queued': 1})
        self.assertEqual(queued.call_args.kwargs['args'], [self.pa.pk])

    def test_the_project_task_survives_a_deleted_project(self):
        from cveFeed import tasks
        self.assertEqual(tasks.runzero_sync_project(999999)['state'], 'error')


class ApiTests(SyncFixture):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        mk = lambda n, **kw: User.objects.create_user(n, password='x', **kw)
        cls.root = User.objects.create_superuser('rzroot', 'r@x.io', 'x')
        cls.org_admin, cls.member, cls.auditor, cls.stranger = mk('rzoa'), mk('rzm'), mk('rzau'), mk('rzs')
        OrgMembership.objects.create(user=cls.org_admin, org=cls.org_a, role='admin')
        ProjectMembership.objects.create(user=cls.member, project=cls.pa, role='user')
        OrgMembership.objects.create(user=cls.auditor, org=cls.org_a, role='audit')
        OrgMembership.objects.create(user=cls.stranger, org=cls.org_b, role='admin')
        cls.tokens = {u.username: create_token(u, 't')[1] for u in (cls.root, cls.org_admin, cls.member, cls.auditor, cls.stranger)}
        cls.t_ro = create_token(cls.org_admin, 'ro', read_only=True)[1]

    def req(self, user, method, path, body=None):
        return call(self.tokens[user] if user in self.tokens else user, method, f'/api/v1/projects/rz-pa/{path}', body)

    def test_status_is_for_admins_only_and_never_carries_the_token(self):
        for user in ('rzroot', 'rzoa'):
            status, data = self.req(user, 'GET', 'runzero')
            self.assertEqual(status, 200, user)
            self.assertEqual((data['configured'], data['import_enabled'], data['search'], data['state']), (True, False, 'alive:true', 'never'))
            self.assertNotIn(SECRET_FRAGMENT, json.dumps(data))
        for user in ('rzm', 'rzau'):
            self.assertEqual(self.req(user, 'GET', 'runzero')[0], 403, user)
        self.assertEqual(self.req('rzs', 'GET', 'runzero')[0], 404)  # another organization's admin cannot even see it exists

    def test_settings_need_the_admin_role_and_are_validated(self):
        self.assertEqual(self.req('rzoa', 'PUT', 'runzero', {'import_enabled': True, 'search': 'tag:edge'})[1]['import_enabled'], True)
        row = RunZeroSync.objects.get(project=self.pa)
        self.assertEqual((row.import_enabled, row.search), (True, 'tag:edge'))
        self.assertTrue(AuditLog.objects.filter(action='project.runzero.settings', target='rz-pa').exists())
        self.assertEqual(self.req('rzoa', 'PUT', 'runzero', {'search': '   '})[1]['search'], 'alive:true')
        self.assertEqual(self.req('rzoa', 'PUT', 'runzero', {'search': 'x' * 900})[1]['search'], 'x' * 300)
        for body in ({}, {'import_enabled': 'yes'}, {'search': 5}):
            self.assertEqual(self.req('rzoa', 'PUT', 'runzero', body)[0], 400, body)
        for user in ('rzm', 'rzau', 'rzs'):
            self.assertIn(self.req(user, 'PUT', 'runzero', {'import_enabled': True})[0], (403, 404), user)
        self.assertEqual(call(self.t_ro, 'PUT', '/api/v1/projects/rz-pa/runzero', {'import_enabled': False})[0], 403)

    def test_sync_now_queues_one_job_and_refuses_repeats(self):
        with mock.patch('cveFeed.tasks.runzero_sync_project.delay') as delay:
            self.assertEqual(self.req('rzoa', 'POST', 'runzero/sync', {}), (202, {'queued': True}))
            delay.assert_called_once_with(self.pa.pk)
            self.assertTrue(AuditLog.objects.filter(action='project.runzero.sync').exists())
            RunZeroSync.objects.filter(project=self.pa).update(started_at=timezone.now(), status='ok')
            self.assertEqual(self.req('rzoa', 'POST', 'runzero/sync', {})[0], 429)
            RunZeroSync.objects.filter(project=self.pa).update(status='running')
            self.assertEqual(self.req('rzoa', 'POST', 'runzero/sync', {})[0], 409)
            self.assertEqual(delay.call_count, 1)

    def test_sync_now_needs_a_token_and_the_admin_role(self):
        with mock.patch('cveFeed.tasks.runzero_sync_project.delay') as delay:
            for user in ('rzm', 'rzau', 'rzs'):
                self.assertIn(self.req(user, 'POST', 'runzero/sync', {})[0], (403, 404), user)
            ApiCredential.objects.filter(project=self.pa).delete()
            self.assertEqual(self.req('rzoa', 'POST', 'runzero/sync', {})[0], 400)
            self.assertEqual(call(self.t_ro, 'POST', '/api/v1/projects/rz-pa/runzero/sync', {})[0], 403)
            delay.assert_not_called()

    def test_mcp_tools(self):
        with mock.patch('cveFeed.tasks.runzero_sync_project.delay') as delay:
            error, data = tool_call(self.tokens['rzoa'], 'get_runzero_sync', {'project': 'rz-pa'})
            self.assertFalse(error)
            self.assertTrue(data['configured'])
            self.assertFalse(tool_call(self.tokens['rzoa'], 'set_runzero_sync', {'project': 'rz-pa', 'import_enabled': True})[0])
            self.assertEqual(tool_call(self.tokens['rzoa'], 'run_runzero_sync', {'project': 'rz-pa'}), (False, {'queued': True}))
            delay.assert_called_once()
        for name in ('get_runzero_sync', 'run_runzero_sync'):
            self.assertTrue(tool_call(self.tokens['rzm'], name, {'project': 'rz-pa'})[0], name)
        self.assertTrue(RunZeroSync.objects.get(project=self.pa).import_enabled)

    def test_the_host_record_carries_runzeros_view_to_members_of_the_project_only(self):
        self.sync(assets=[asset(['192.0.2.10'], os='Ubuntu Linux', type='Server', tags=['prod'])], reports=[report('192.0.2.10', 'CVE-2099-5', 443)])
        status, data = call(self.tokens['rzm'], 'GET', '/api/v1/projects/rz-pa/hosts')
        self.assertEqual(status, 200)
        rz = data['results'][0]['ips'][0]['runzero']
        self.assertEqual((rz['os'], rz['type'], rz['tags'], rz['vulns'][0]['cve']), ('Ubuntu Linux', 'Server', ['prod'], 'CVE-2099-5'))
        status, data = call(self.tokens['rzs'], 'GET', '/api/v1/projects/rz-pb/hosts')
        self.assertIsNone(data['results'][0]['ips'][0]['runzero'])  # the other organization's host with the same address

    def test_the_system_status_lists_runzero_for_an_app_admin_only(self):
        self.sync(error=runzero.RunZeroError('auth', 'runZero rejected the token (HTTP 401)'))
        status, data = call(self.tokens['rzroot'], 'GET', '/api/v1/system/status')
        self.assertEqual(status, 200)
        rows = data['system']['runzero']['projects']
        self.assertEqual([(r['project'], r['state']) for r in rows], [('rz-pa', 'error')])
        self.assertTrue(any('runZero' in p for p in data['problems']))
        self.assertIsNone(call(self.tokens['rzoa'], 'GET', '/api/v1/system/status')[1]['system'])


class RetiredBinaryEdgeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='R', slug='rz-ret')
        cls.project = Project.objects.create(name='R', slug='rz-ret-p', insert_date=now, org=cls.org)
        cls.admin = User.objects.create_user('rzretadmin', password='x')
        OrgMembership.objects.create(user=cls.admin, org=cls.org, role='admin')
        cls.token = create_token(cls.admin, 't')[1]

    def listing(self):
        return {r['service']: r for r in call(self.token, 'GET', '/api/v1/projects/rz-ret-p/api-keys')[1]['results']}

    def test_the_payload_marks_binaryedge_retired_and_unused_and_runzero_as_read_by_the_sync(self):
        rows = self.listing()
        self.assertEqual(rows['binaryedge']['retired'], RETIRED['binaryedge'])
        self.assertIn('31 March 2025', rows['binaryedge']['retired'])
        self.assertFalse(rows['binaryedge']['used_in_scans'])
        self.assertIsNone(rows['shodan']['retired'])
        self.assertTrue(rows['runzero']['used_by_sync'])
        self.assertFalse(rows['runzero']['used_in_scans'])
        self.assertFalse(used_in_scans('binaryedge'))
        self.assertTrue(SERVICES['binaryedge'])  # the row definition stays so stored keys remain readable

    def test_no_new_binaryedge_key_is_accepted_anywhere(self):
        self.assertEqual(call(self.token, 'PUT', '/api/v1/projects/rz-ret-p/api-keys/binaryedge', {'api_key': 'abc'})[0], 410)
        self.assertFalse(ApiCredential.objects.filter(service='binaryedge').exists())
        from tests.test_admin import api as admin_api_call
        from tests.test_tenancy import client_for
        status, _ = admin_api_call(client_for(self.admin), 'PUT', f'orgs/{self.org.pk}/api-keys/binaryedge', {'api_key': 'abc'})
        self.assertEqual(status, 410)
        self.assertFalse(ApiCredential.objects.filter(service='binaryedge').exists())

    def test_a_key_that_is_already_stored_is_kept_listed_and_removable_but_never_used(self):
        ApiCredential.objects.create(project=self.project, service='binaryedge', value={'api_key': 'old-key'})
        row = self.listing()['binaryedge']
        self.assertEqual((row['configured'], row['retired'] is not None, row['set']), (True, True, {'api_key': True}))
        self.assertNotIn('old-key', json.dumps(row))
        from cveFeed.api_credentials import bbot_config_args
        self.assertNotIn('old-key', ' '.join(bbot_config_args(self.project)))
        self.assertEqual(call(self.token, 'DELETE', '/api/v1/projects/rz-ret-p/api-keys/binaryedge')[0], 200)
        self.assertFalse(ApiCredential.objects.filter(service='binaryedge').exists())

    def test_the_organization_listing_says_the_same(self):
        from tests.test_admin import api as admin_api_call
        from tests.test_tenancy import client_for
        status, data = admin_api_call(client_for(self.admin), 'GET', f'orgs/{self.org.pk}/api-keys')
        rows = {r['service']: r for r in data['results']}
        self.assertEqual((status, rows['binaryedge']['retired'] is not None, rows['binaryedge']['used_in_scans']), (200, True, False))
        self.assertTrue(rows['runzero']['used_by_sync'])
