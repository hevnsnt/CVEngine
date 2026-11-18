"""Edge appliance builds (cveFeed.edge_builds, the edge entries of the version source catalogue, the ``version_digest`` Sentinel kind of contract
version 8): per product a real-shaped answer, a soft-404 or catch-all page that never reads, and a fingerprint several builds share that reads as a
range; the data file's sources and licences; the vendor version formats; how an exact build and a range are matched; and that a contract 7
Sentinel is never sent a digest read."""
import json
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from agentapi import probe_results, sentinel_contract, sentinel_dispatch
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from cveFeed import correlation, edge_builds, match_explain, match_policy, threat, triage, version_sources
from cveFeed import version_catalogue as catalogue
from cveFeed.models import CVEMatch, ProbeObservation
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally, fixture
from tests.test_version_sources import VersionFixture, by_path, cve, ok, read, responder

NETSCALER_48_47 = '1f8b080856ed7a6400037264785f656e'  # the gzip header of rdx_en.json.gz of 13.1-48.47 (timestamp 1685777750)
SOFT_404 = {'status': 200, 'content_type': 'text/html', 'headers': {}, 'text': '', 'json': None}


def digest(head, status=200, sha='ab' * 32, path='/vpn/js/rdx/core/lang/rdx_en.json.gz'):
    return {'path': path, 'status': status, 'content_type': 'application/x-gzip', 'bytes': 49, 'truncated': False, 'headers': {},
            'digest': {'sha256': sha, 'head': head}}


def vhash_of(version):
    return next(e['vhash'] for e in edge_builds.data()['tables']['netscaler_vhash']['entries'] if e['version'] == version)


def found(result):
    return [(r['label'], r['version'], r['confidence'], (r.get('range') or {}).get('candidates')) for r in result['readings']]


class DataTests(SimpleTestCase):
    def test_every_table_names_its_source_and_licence_and_every_entry_its_line(self):
        doc = edge_builds.data()
        for name, table in doc['tables'].items():
            with self.subTest(table=name):
                self.assertTrue(table['source'].startswith('https://'))
                self.assertTrue(table['licence'])
                self.assertTrue(table['entries'])
                for entry in table['entries']:
                    self.assertTrue(entry.get('cite', '').startswith('https://'), entry)
        self.assertEqual(doc['tables']['netscaler_rdx_stamp']['licence'], 'Apache-2.0')
        self.assertIn('Permission is hereby granted', doc['tables']['panos_release_dates']['notice'])  # MIT: the notice travels with the data

    def test_one_fingerprint_is_one_build(self):
        tables = edge_builds.data()['tables']
        for key, name in (('netscaler_rdx_stamp', 'stamp'), ('netscaler_vhash', 'vhash')):
            values = [e[name] for e in tables[key]['entries']]
            self.assertEqual(len(values), len(set(values)), key)
            self.assertFalse([e for e in tables[key]['entries'] if e['version'] == 'unknown'])

    def test_the_products_are_named_as_nvd_and_the_vendors_name_them(self):
        names = edge_builds.product_names()
        self.assertIn(('fortinet', 'fortios'), names['fortios'])
        self.assertIn(('citrix', 'netscalergateway'), names['netscaler'])
        self.assertIn(('citrix', 'netscaleradc'), names['netscaler'])
        self.assertIn(('citrix', 'netscalerapplicationdeliverycontroller'), names['netscaler'])
        self.assertIn(('paloaltonetworks', 'panos'), names['pan-os'])
        self.assertIn(('ivanti', 'connectsecure'), names['connect-secure'])
        self.assertIn(('', 'pulseconnectsecure'), names['connect-secure'])


class VersionFormatTests(SimpleTestCase):
    """The vendors' own version forms, as the stored CVE records write them."""

    def verdict(self, version, ranges, vendor='', product=''):
        items = correlation.clean_affected([{'vendor': vendor, 'product': product, 'ranges': ranges}])
        return correlation.range_verdict(correlation.parse_version(version), items[0]['ranges'])[0]

    def test_netscaler_builds_and_its_records_bounds(self):
        ranges = [{'type': 'SEMVER', 'introduced': '14.1', 'fixed': '8.50'}, {'type': 'SEMVER', 'introduced': '13.1', 'fixed': '49.15'}]
        for version, want in (('13.1-48.47', True), ('13.1-49.15', False), ('14.1-4.42', True), ('14.1-8.50', False), ('14.1-29.72', False)):
            with self.subTest(version=version):
                self.assertEqual(self.verdict(version, ranges, 'Citrix', 'NetScaler ADC'), want)
        # another product's range of the same shape is read as written
        self.assertTrue(self.verdict('14.1', [{'type': 'SEMVER', 'introduced': '13.1', 'fixed': '49.15'}], 'Acme', 'Widget'))

    def test_pan_os_hotfixes_and_connect_secure_service_releases(self):
        pan = [{'type': 'SEMVER', 'introduced': '10.2.0', 'fixed': '10.2.9-h1'}]
        self.assertEqual([self.verdict(v, pan) for v in ('10.2.9', '10.2.9-h1', '10.2.8-h3', '10.2.10')], [True, False, True, False])
        ics = [{'type': 'SEMVER', 'introduced': '22.7R2', 'lastAffected': '22.7R2.4'}]
        self.assertEqual([self.verdict(v, ics) for v in ('22.7R2.4', '22.7R2.5', '22.7R1.3', '22.7R2')], [True, False, False, True])
        self.assertEqual(correlation.parse_version('12.4R2-S3'), (12, 4, 2, 3))  # Junos is read as before


class ReaderTests(SimpleTestCase):
    def test_netscaler_gzip_timestamp_is_an_exact_build(self):
        result = read('netscaler-gzip', digest(NETSCALER_48_47), digest('3c68746d6c3e', status=404))
        self.assertEqual(found(result), [('NetScaler ADC', '13.1-48.47', 'exact', None), ('NetScaler Gateway', '13.1-48.47', 'exact', None)])
        self.assertEqual(catalogue.BY_ID['netscaler-gzip'].task_kind, 'version_digest')

    def test_netscaler_gzip_soft_404_redirect_and_catch_all_never_read(self):
        self.assertEqual(read('netscaler-gzip', digest('3c68746d6c3e3c686561643e'), digest(''))['readings'], [])  # an HTML page's first bytes
        self.assertEqual(read('netscaler-gzip', {**digest(NETSCALER_48_47), 'redirected': True, 'digest': None}, digest(''))['readings'], [])
        self.assertEqual(read('netscaler-gzip', digest(NETSCALER_48_47), digest(NETSCALER_48_47))['state'], 'catch_all')  # every path is "the file"
        unknown = NETSCALER_48_47[:8] + '01020304' + NETSCALER_48_47[16:]  # a timestamp no table entry has
        self.assertEqual(read('netscaler-gzip', digest(unknown), digest(''))['readings'], [])

    def test_netscaler_login_page_build_value(self):
        value = vhash_of('13.1-45.61')
        page = ok(text=f'?v={value}" rel="stylesheet" type="text/css"/><script src="/vpn/js/rdx/core/js/rdx.js?v={value}">',
                  content_type='text/html', path='/vpn/index.html')
        self.assertEqual(found(read('netscaler-vhash', page, ok(status=404, text='', content_type='text/html'))),
                         [('NetScaler ADC', '13.1-45.61', 'exact', None), ('NetScaler Gateway', '13.1-45.61', 'exact', None)])
        self.assertEqual(read('netscaler-vhash', page, page)['state'], 'catch_all')  # the login page for every path
        mixed = ok(text=f'?v={value}" /><link href="x.css?v={"0" * 32}">', content_type='text/html')
        self.assertEqual(read('netscaler-vhash', mixed, SOFT_404)['readings'], [])  # values that disagree
        self.assertEqual(read('netscaler-vhash', ok(text='?v=' + 'f' * 32, content_type='text/html'), SOFT_404)['readings'], [])  # unknown value

    def test_pan_os_build_date_is_a_range_and_a_shared_date_lists_every_release(self):
        css = {'path': '/global-protect/portal/css/login.css', 'status': 200, 'content_type': 'text/css', 'bytes': 10, 'truncated': False,
               'headers': {'etag': '"6e185d5daf9a"', 'last-modified': 'Wed, 21 Aug 2019 20:54:50 GMT'}}
        none = {'path': '/x', 'status': 404, 'content_type': 'text/html', 'headers': {}}
        result = read('panos-globalprotect', css, none, none)
        (label, version, confidence, candidates), = found(result)
        self.assertEqual((label, version, confidence), ('PAN-OS', '', 'inferred'))
        self.assertIn('8.1.10', candidates)  # Bishop Fox's README: 2019-08-21 is 8.1.10
        shared = {**css, 'headers': {'last-modified': 'Thu, 15 Aug 2019 10:00:00 GMT'}}
        many = found(read('panos-globalprotect', shared, none, none))[0][3]
        self.assertTrue({'7.1.24-h1', '8.0.19-h1', '8.1.9-h4'} <= set(many))  # one date, three branches: a range, never one of them
        self.assertEqual(read('panos-globalprotect', css, none, css)['state'], 'catch_all')
        self.assertEqual(read('panos-globalprotect', {**css, 'content_type': 'text/html'}, none, none)['readings'], [])  # a soft 404 page
        later = {**css, 'headers': {'last-modified': 'Mon, 02 Mar 2026 10:00:00 GMT'}}
        self.assertEqual(read('panos-globalprotect', later, none, none)['readings'], [])  # after the table ends: a release it does not know
        clash = {**css, 'headers': {'etag': '"6e185d5daf9a"', 'last-modified': 'Mon, 02 Mar 2020 10:00:00 GMT'}}
        self.assertEqual(read('panos-globalprotect', clash, none, none)['readings'], [])

    def test_fortios_etag_build_time_is_a_range(self):
        page = ok(text='top.location="/remote/login"; </script></html>', content_type='text/html', headers={'etag': '"3a8-64ad3e1c"'})
        none = ok(status=404, text='', content_type='text/html')
        (label, version, confidence, candidates), = found(read('fortios-etag', page, none))
        self.assertEqual((label, version, confidence), ('FortiOS', '', 'inferred'))
        self.assertEqual(read('fortios-etag', page, page)['state'], 'catch_all')
        self.assertEqual(read('fortios-etag', {**page, 'headers': {'etag': '"5f2c1a-abc"'}}, none)['readings'], [])  # no build time in it
        self.assertEqual(read('fortios-etag', {**page, 'text': ''}, none)['readings'], [])  # not the SSL-VPN front page
        self.assertEqual(read('fortios-etag', {**page, 'headers': {'etag': '"3a8-0000ffff"'}}, none)['readings'], [])  # not a build time

    def test_connect_secure_release_is_a_range_and_22x_reads_nothing(self):
        none = ok(status=404, text='', content_type='text/html')
        gina = ok(text='NAME="ProductVersion" VALUE="8.3.7.61383"> <PARAM NAME="x">', content_type='text/plain')
        (label, _v, confidence, candidates), = found(read('connect-secure', gina, none, none))
        self.assertEqual((label, confidence, candidates), ('Pulse Connect Secure', 'inferred', ['8.3R7 to 8.3R7.x']))
        hc = ok(text='<key>version</key> <string>9.1.11.12173</string> <key>x</key>', content_type='application/octet-stream')
        result = read('connect-secure', none, hc, none)
        self.assertEqual(result['readings'][0]['range']['ranges'], [{'introduced': '9.1R11', 'lastAffected': '9.1R11.999'}])
        newer = ok(text='<key>version</key> <string>22.2.16.21349</string>', content_type='application/octet-stream')
        self.assertEqual(read('connect-secure', none, newer, none)['readings'], [])
        self.assertEqual(read('connect-secure', gina, none, gina)['state'], 'catch_all')

    def test_every_edge_entry_is_asked_only_of_its_product(self):
        for source in edge_builds.sources():
            with self.subTest(source=source.id):
                self.assertTrue(source.leads and not source.ports and source.control)
                self.assertLessEqual(len(catalogue.request_specs(source, '0123456789ab')), 3)
        hosts = version_sources.wanted
        self.assertEqual([s.id for s, _b in hosts('h.rt.test', [('nginx', '1.24.0')], [], ['https://h.rt.test'])], [])
        self.assertEqual([s.id for s, _b in hosts('h.rt.test', [('Citrix NetScaler', '')], [], ['https://h.rt.test'])],
                         ['netscaler-vhash', 'netscaler-gzip'])
        self.assertEqual([s.id for s, _b in hosts('h.rt.test', [('FortiGate', '')], [], ['https://h.rt.test'])], ['fortios-etag'])
        self.assertEqual([s.id for s, _b in hosts('h.rt.test', [('Palo Alto Networks GlobalProtect', '')], [], ['https://h.rt.test'])],
                         ['panos-globalprotect'])
        self.assertEqual([s.id for s, _b in hosts('h.rt.test', [('Pulse Secure', '')], [], ['https://h.rt.test'])], ['connect-secure'])
        self.assertEqual([s.id for s, _b in hosts('h.rt.test', [('FortiWeb', '')], [], ['https://h.rt.test'])], [])  # another Fortinet product


class ContractTests(SimpleTestCase):
    def test_only_a_contract_eight_sentinel_is_offered_the_digest_kind(self):
        self.assertEqual(sentinel_contract.kind_since('version_digest'), 8)
        self.assertFalse(sentinel_contract.can_run(7, 'version_digest'))
        self.assertTrue(sentinel_contract.can_run(8, 'version_digest'))
        self.assertTrue(sentinel_contract.can_run(7, 'version_read'))
        self.assertIn('version_digest', SentinelTask.KINDS)
        self.assertIn('version_digest', sentinel_dispatch.NEVER_LOCAL)
        self.assertIn('version_digest', sentinel_dispatch.COMPLETION_CEILING)

    def test_the_cleaner_keeps_a_digest_never_a_body_and_binds_only_what_was_asked(self):
        sent = fixture('version_digest')
        stored = broker.clean_result('version_digest', sent)
        first = stored['reads'][0]['answers']
        self.assertEqual(first[0]['digest']['head'], NETSCALER_48_47)
        self.assertTrue(first[1]['redirected'])
        hostile = {'reads': [{'id': 'a', 'answers': [{'path': '/a.js', 'status': 200, 'body': '<secret>', 'truncated': True,
                                                      'digest': {'sha256': 'a' * 64, 'head': 'zz', 'body': 'x'}}]}], 'touched': [], 'refused': []}
        got = probe_results.clean_version_digest(hostile)['reads'][0]['answers'][0]
        self.assertEqual(got['digest'], {'head': ''})  # a truncated body's hash is dropped, a head that is not hex too
        self.assertNotIn('body', got)
        self.assertNotIn('digest', probe_results.clean_version_read(hostile)['reads'][0]['answers'][0])  # version_read never keeps one
        target = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'version_digest.json').read_text())
        task = SentinelTask(kind='version_digest', target=target)
        extra = {**sent, 'reads': sent['reads'] + [{'id': 'stranger', 'answers': []}]}
        bound = probe_results.bind('version_digest', broker.clean_result('version_digest', extra), task)
        self.assertEqual([r['id'] for r in bound['reads']], [r['id'] for r in target['reads']])
        self.assertIn('vpn.example.com', broker.task_hosts(task)[0])


GZIP_ANSWER = {'status': 200, 'content_type': 'application/x-gzip', 'headers': {}, 'digest': {'sha256': 'ab' * 32, 'head': NETSCALER_48_47}}


class ReadTests(VersionFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.dguard = assert_ran_nowhere_locally(self, 'version_digest')

    def scanner(self, table, contract_version=None):
        return FakeScanner(kinds=['version_read', 'version_digest'], contract_version=contract_version,
                           responders={'version_read': responder(self.vtasks, by_path(table)), 'version_digest': responder(self.vtasks, by_path(table))})

    def test_a_netscaler_is_pinned_by_its_gzip_timestamp_through_the_digest_kind(self):
        scan = self.host_scan(techs=('Citrix NetScaler',))
        with self.scanner({'/vpn/js/rdx/core/lang/rdx_en.json.gz': GZIP_ANSWER}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual(result['asked'], 1)
        kinds = sorted(t.kind for t in SentinelTask.objects.all())
        self.assertEqual(kinds, ['version_digest', 'version_read'])
        digest_task = SentinelTask.objects.get(kind='version_digest')
        self.assertEqual([r['read'] for r in digest_task.target['reads'][0]['requests']], ['digest', 'digest'])
        self.assertFalse(any(r['read'] == 'digest' for e in SentinelTask.objects.get(kind='version_read').target['reads'] for r in e['requests']))
        names = set(scan.subdomain_set.get().technologies.values_list('name', flat=True))
        self.assertTrue({'NetScaler ADC:13.1-48.47', 'NetScaler Gateway:13.1-48.47'} <= names)

    def test_a_contract_seven_sentinel_is_never_sent_a_digest_read(self):
        scan = self.host_scan(techs=('Citrix NetScaler',))
        with FakeScanner(kinds=['version_read'], contract_version=7, responders={'version_read': responder(self.vtasks, by_path({}))}):
            result = version_sources.run_for_scan(scan.id)
        self.assertTrue(result.get('digest_waiting'))
        self.assertEqual(sorted({t.kind for t in SentinelTask.objects.all()}), ['version_read'])
        self.assertEqual([e['id'].split('|')[2] for t in SentinelTask.objects.all() for e in t.target['reads']], ['netscaler-vhash'])

    def test_a_soft_404_host_reads_nothing(self):
        scan = self.host_scan(techs=('Citrix NetScaler',))
        soft = {**GZIP_ANSWER, 'digest': {'sha256': 'cd' * 32, 'head': '3c21444f43545950452068746d6c3e0a'}}  # "<!DOCTYPE html>" for every path
        with self.scanner({'/vpn/js/rdx/core/lang/rdx_en.json.gz': soft}):
            version_sources.run_for_scan(scan.id)
        self.assertFalse(ProbeObservation.objects.filter(probe__startswith='vsrc:netscaler').exists())

    def test_a_range_is_stored_but_never_a_technology(self):
        scan = self.host_scan(techs=('FortiGate',))
        page = {'status': 200, 'content_type': 'text/html', 'headers': {'etag': '"3a8-64ad3e1c"'}, 'text': 'top.location="/remote/login";'}
        with self.scanner({'/': page}):
            version_sources.run_for_scan(scan.id)
        row = ProbeObservation.objects.get(probe='vsrc:fortios-etag')
        self.assertEqual((row.outcome, row.version, row.product, row.evidence['confidence']), ('range', '', 'FortiOS', 'inferred'))
        self.assertFalse([n for n in scan.subdomain_set.get().technologies.values_list('name', flat=True) if n.startswith('FortiOS')])
        payload = version_sources.readings_for([self.project.pk], {'app.rt.test'})[(self.project.pk, 'app.rt.test')]
        self.assertEqual(payload[0]['range']['ranges'][0], {'introduced': '0', 'lastAffected': '7.2.5'})
        self.assertEqual(set(version_sources.search_rows('component', 'fortios').values_list('host', flat=True)), {'app.rt.test'})


FORTIOS_KEV = [{'vendor': 'Fortinet', 'product': 'FortiOS', 'ranges': [{'type': 'SEMVER', 'introduced': '7.4.0', 'lastAffected': '7.4.2'},
                                                                       {'type': 'SEMVER', 'introduced': '7.2.0', 'lastAffected': '7.2.6'}]}]
FORTIOS_NEW = [{'vendor': 'Fortinet', 'product': 'FortiOS', 'ranges': [{'type': 'SEMVER', 'introduced': '7.4.5', 'fixed': '7.4.8'}]}]
NETSCALER = [{'vendor': 'Citrix', 'product': 'NetScaler ADC', 'ranges': [{'type': 'SEMVER', 'fixed': '49.15', 'introduced': '13.1'}]},
             {'vendor': 'Citrix', 'product': 'NetScaler Gateway', 'ranges': [{'type': 'SEMVER', 'fixed': '49.15', 'introduced': '13.1'}]}]


class CorrelationTests(VersionFixture, TestCase):
    def correlate(self, scan, row, source=None):
        cve_by_id, index = correlation.cve_pool()
        subs = correlation.candidate_subdomains(index).filter(scan_history=scan)
        correlation.correlate_subdomains(list(subs), index, cve_by_id, min_confidence=0.4)
        qs = CVEMatch.objects.filter(cve_entry=row).exclude(ai_verdict='not_affected')
        return list(qs.filter(source=source) if source else qs)

    def fortios_range(self, sub):
        version_sources.store_readings(sub, 'vsrc:fortios-etag', edge_builds.read_fortios(
            [ok(text='top.location="/remote/login";', content_type='text/html', headers={'etag': '"3a8-64ad3e1c"'})]), port=443)

    def test_a_range_that_can_reach_the_cve_is_a_needs_validation_candidate(self):
        row = cve('CVE-2024-21762', FORTIOS_KEV, kev=True)
        scan = self.host_scan(techs=('FortiGate',))
        self.fortios_range(scan.subdomain_set.get())
        match, = self.correlate(scan, row)
        self.assertEqual((match.source, match.version_in_range, match.matched_version, match.matched_product), ('build_range', None, '', 'FortiOS'))
        self.assertTrue(match.evidence['range_read'])
        self.assertTrue(match_policy.version_unknown(match))
        self.assertEqual(threat.match_heat(match), threat.ICE)
        self.assertEqual(threat.heat_reason(match), threat.REASON_RANGE_READ)
        loaded = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)
        facts = triage.describe_cve_match(loaded)['facts']
        self.assertTrue(facts['version_unknown'] and facts['range_read'])
        self.assertEqual(triage.version_unknown_outcome(range_read=True)['reason'], match_policy.REASON_RANGE_READ)
        self.assertEqual(match_explain.explain(match)['basis'], 'range_read')
        self.assertEqual(correlation.invalid_identity_reason(loaded), '')

    def test_a_range_no_affected_release_reaches_matches_nothing(self):
        row = cve('CVE-2026-300001', FORTIOS_NEW, kev=True)
        scan = self.host_scan(techs=('FortiGate',))
        self.fortios_range(scan.subdomain_set.get())
        self.assertEqual(self.correlate(scan, row), [])

    def test_a_product_named_without_a_version_alone_matches_nothing(self):
        row = cve('CVE-2024-21762', FORTIOS_KEV, kev=True)
        scan = self.host_scan(techs=('FortiGate',))
        self.assertEqual(self.correlate(scan, row), [])

    def test_an_exact_netscaler_build_is_a_version_only_technology_match(self):
        row = cve('CVE-2023-4966', NETSCALER, kev=True)
        scan = self.host_scan(techs=('Citrix NetScaler',))
        sub = scan.subdomain_set.get()
        version_sources.store_readings(sub, 'vsrc:netscaler-gzip', edge_builds.read_netscaler_gzip([digest(NETSCALER_48_47)]), port=443)
        matches = self.correlate(scan, row, source='tech')
        self.assertEqual(sorted(m.matched_product for m in matches), ['NetScaler ADC', 'NetScaler Gateway'])
        for match in matches:
            self.assertTrue(match.version_in_range)
            self.assertTrue(match_policy.is_version_only(match))
            self.assertFalse(match_policy.version_proven(match))
        fixed = cve('CVE-2026-300002', [{'vendor': 'Citrix', 'product': 'NetScaler ADC', 'ranges': [{'type': 'SEMVER', 'introduced': '13.1', 'fixed': '48.47'}]}])
        self.assertEqual(self.correlate(scan, fixed), [])  # the fixed build itself is not in range
        self.assertEqual(self.correlate(scan, row, source='build_range'), [])
