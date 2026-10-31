import json
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase
from jsonschema import Draft202012Validator

from agentapi import sentinel_broker as broker
from agentapi import sentinel_dispatch as broker_dispatch
from agentapi import sentinel_contract as contract
from agentapi.models import SentinelTask
from agentapi.services import ApiError

FIXTURES = Path(__file__).with_name('fixtures') / 'sentinel_results'
KIND_OF = {'nmap': 'nmap', 'naabu': 'naabu', 'nuclei_light': 'nuclei_light', 'testssl': 'testssl', 'nmap_udp': 'nmap_udp', 'wpscan': 'wpscan',
           'discover': 'discover', 'openvas': 'openvas', 'waf': 'waf', 'error': 'nmap'}


def fixture(name):
    return json.loads((FIXTURES / f'{name}.json').read_text())


def validator(kind):
    return Draft202012Validator(contract.result_schema(kind))


class ContractShapeTests(SimpleTestCase):
    def test_the_schema_itself_is_valid_and_versioned(self):
        Draft202012Validator.check_schema(contract.result_schema('nmap'))
        self.assertIsInstance(contract.version(), int)
        self.assertGreaterEqual(contract.version(), 1)

    def test_every_task_kind_has_a_result_schema(self):
        for kind in SentinelTask.KINDS:
            Draft202012Validator.check_schema(contract.result_schema(kind))

    def test_every_kind_has_a_fixture_and_every_fixture_is_a_kind(self):
        have = {p.stem for p in FIXTURES.glob('*.json')}
        self.assertEqual(have - {'error'}, {k for k in SentinelTask.KINDS if k not in ('nuclei_targeted', 'nuclei_deep')})


class FixtureTests(SimpleTestCase):
    def test_each_fixture_is_a_valid_result_for_its_kind(self):
        for name, kind in KIND_OF.items():
            errors = list(validator(kind).iter_errors(fixture(name)))
            self.assertEqual(errors, [], name)

    def test_the_server_accepts_each_fixture_and_what_it_stores_is_still_in_contract(self):
        for name, kind in KIND_OF.items():
            stored = broker.clean_result(kind, fixture(name))
            self.assertEqual(list(validator(kind).iter_errors(stored)), [], name)

    def test_a_good_result_goes_through_the_server_unchanged(self):
        """The server clips and drops; a correct client never loses anything to it. openvas is left out: its cleaner fills in defaults."""
        for name in ('nmap', 'naabu', 'nuclei_light', 'testssl', 'discover', 'nmap_udp', 'waf'):
            sent = fixture(name)
            self.assertEqual(broker.clean_result(KIND_OF[name], sent), sent, name)

    def test_all_three_nuclei_kinds_share_one_result_shape(self):
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            self.assertEqual(list(validator(kind).iter_errors(fixture('nuclei_light'))), [], kind)


class ContractRejectsTests(SimpleTestCase):
    def test_a_result_with_no_outcome_is_out_of_contract(self):
        self.assertTrue(list(validator('nmap').iter_errors({'hosts': []})))
        self.assertTrue(list(validator('nmap').iter_errors({'outcome': 'ok', 'hosts': []})))

    def test_a_port_number_outside_the_range_is_out_of_contract(self):
        bad = fixture('nmap')
        bad['hosts'][0]['ports'][0]['number'] = 70000
        self.assertTrue(list(validator('nmap').iter_errors(bad)))

    def test_more_hosts_than_one_task_may_name_is_out_of_contract(self):
        bad = {'outcome': 'done', 'hosts': [{'ip': f'192.0.2.{i % 250 + 1}'} for i in range(broker.MAX_ADDRESSES + 1)]}
        self.assertTrue(list(validator('nmap').iter_errors(bad)))

    def test_an_unknown_severity_is_out_of_contract(self):
        bad = fixture('nuclei_light')
        bad['findings'][0]['severity'] = 'catastrophic'
        self.assertTrue(list(validator('nuclei_light').iter_errors(bad)))


class WafContractTests(SimpleTestCase):
    """The ``waf`` kind (contract version 2): the shape, and what the server does with a result that is not."""

    def bad(self, **changes):
        body = fixture('waf')
        body.update(changes)
        return body

    def test_the_fixture_is_a_valid_done_result_and_so_is_an_error(self):
        self.assertEqual(list(validator('waf').iter_errors(fixture('waf'))), [])
        self.assertEqual(list(validator('waf').iter_errors({'outcome': 'error', 'error': 'wafw00f is not installed'})), [])
        self.assertEqual(list(validator('waf').iter_errors({'outcome': 'done', 'products': [], 'generic': True})), [])

    def test_a_done_result_must_say_its_products_and_whether_it_was_generic(self):
        self.assertTrue(list(validator('waf').iter_errors({'outcome': 'done', 'products': []})))
        self.assertTrue(list(validator('waf').iter_errors({'outcome': 'done', 'generic': False})))

    def test_shapes_outside_the_contract_are_rejected(self):
        from cveFeed import waf_scan
        for body in (
                self.bad(products=[{'name': f'W{i}'} for i in range(waf_scan.MAX_PRODUCTS + 1)]),  # too many
                self.bad(products=[{'name': 'x' * (waf_scan.NAME_LEN + 1)}]),  # name too long
                self.bad(products=[{'name': ''}]),
                self.bad(products=[{'name': 'x', 'manufacturer': 'y' * (waf_scan.NAME_LEN + 1)}]),
                self.bad(products=[{'name': 'x', 'version': '1.0'}]),  # unknown field of a product
                self.bad(products=[{'manufacturer': 'only a maker'}]),
                self.bad(products='FortiWeb'), self.bad(generic='yes'),
                self.bad(surprise=1),  # unknown field of the result
                self.bad(outcome='ok')):
            self.assertTrue(list(validator('waf').iter_errors(body)), body)

    def test_the_server_refuses_what_it_cannot_shape_and_clips_the_rest(self):
        from cveFeed import waf_scan
        with self.assertRaises(ApiError):
            broker.clean_result('waf', self.bad(products=[{'name': f'W{i}'} for i in range(waf_scan.MAX_PRODUCTS + 1)]))
        with self.assertRaises(ApiError):
            broker.clean_result('waf', self.bad(products='FortiWeb'))
        with self.assertRaises(ApiError):
            broker.clean_result('waf', {'outcome': 'done', 'generic': False})
        clipped = broker.clean_result('waf', {'outcome': 'done', 'generic': 'yes', 'surprise': 1, 'products': [
            {'name': 'A' * 500, 'manufacturer': 'M' * 500, 'version': '9', 'url': 'http://x/'}, 'junk', {'name': '  '}, {'name': 5}, {'manufacturer': 'x'}]})
        self.assertEqual(clipped, {'outcome': 'done', 'generic': False,
                                   'products': [{'name': 'A' * waf_scan.NAME_LEN, 'manufacturer': 'M' * waf_scan.NAME_LEN}]})
        self.assertEqual(list(validator('waf').iter_errors(clipped)), [])
        self.assertEqual(broker.clean_result('waf', {'outcome': 'done', 'products': [], 'generic': True}),
                         {'outcome': 'done', 'products': [], 'generic': True})

    def test_an_error_result_keeps_only_its_error(self):
        self.assertEqual(broker.clean_result('waf', {'outcome': 'error', 'error': 'x' * 900, 'products': [{'name': 'y'}]}),
                         {'outcome': 'error', 'error': 'x' * 300})

    def test_the_bounds_are_the_ones_the_local_scan_uses(self):
        from cveFeed import waf_scan
        body = contract.load()['$defs']['results']['waf']['allOf'][1]['properties']['products']
        self.assertEqual(body['maxItems'], waf_scan.MAX_PRODUCTS)
        self.assertEqual(body['items']['properties']['name']['maxLength'], waf_scan.NAME_LEN)
        self.assertEqual(body['items']['properties']['manufacturer']['maxLength'], waf_scan.NAME_LEN)
        self.assertEqual(waf_scan.parse_output('[{"detected": true, "firewall": "%s"}]' % ('A' * 500))[0]['firewall'], 'A' * waf_scan.NAME_LEN)

    def test_the_kind_is_new_in_version_two_and_nothing_older_changed(self):
        self.assertGreaterEqual(contract.version(), 2)
        self.assertEqual(contract.min_supported(), 1)
        self.assertEqual(contract.kind_since('waf'), 2)
        self.assertEqual({k: v for k, v in contract.load()['kind_since'].items() if k != 'waf'}, {k: 1 for k in SentinelTask.KINDS if k != 'waf'})


class ContractMatchesTheServerTests(SimpleTestCase):
    """The file and the broker's own limits must not drift apart: a bound changed on one side only fails here."""
    def defs(self):
        return contract.load()['$defs']['results']

    def body(self, kind):
        return self.defs()[kind]['allOf'][1]['properties']

    def test_list_bounds_equal_the_brokers(self):
        from cveFeed.naabu_scan import MAX_OPEN_PER_IP  # noqa: F401 - the naabu cleaner's own limit is the per-address list
        nmap = self.body('nmap')['hosts']
        self.assertEqual(nmap['maxItems'], broker.MAX_ADDRESSES)
        self.assertEqual(nmap['items']['properties']['ports']['maxItems'], broker.MAX_PORTS_PER_HOST)
        self.assertEqual(self.body('naabu')['ports']['maxProperties'], broker.MAX_ADDRESSES)
        nuclei = self.body('nuclei_light')['findings']
        self.assertEqual(nuclei['maxItems'], broker.MAX_FINDINGS_SENT)
        self.assertEqual(nuclei['items']['properties']['extracted_results']['maxItems'], broker.MAX_EXTRACTED)
        self.assertEqual(nuclei['items']['properties']['tags']['maxItems'], broker.MAX_TAGS)
        self.assertEqual(self.body('testssl')['items']['maxItems'], broker.MAX_TESTSSL_ITEMS)
        self.assertEqual(self.body('nmap_udp')['xml']['maxLength'], broker.MAX_NMAP_UDP_XML)
        self.assertEqual(self.body('discover')['hosts']['maxItems'], broker.MAX_DISCOVER_HOSTS)
        openvas = self.body('openvas')
        self.assertEqual(openvas['results']['maxItems'], broker.MAX_OPENVAS_RESULTS)
        self.assertEqual(openvas['results']['items']['properties']['cves']['maxItems'], broker.MAX_OPENVAS_CVES)
        self.assertEqual(openvas['results']['items']['properties']['urls']['maxItems'], broker.MAX_OPENVAS_URLS)
        self.assertEqual(openvas['scanned_addresses']['maxItems'], broker.MAX_ADDRESSES)

    def test_string_lengths_equal_the_brokers(self):
        port = contract.load()['$defs']['port']['properties']
        for field in ('service_name', 'product', 'version'):
            self.assertEqual(port[field]['maxLength'], broker._STR[field], field)
        host = self.body('nmap')['hosts']['items']['properties']
        self.assertEqual(host['ip']['maxLength'], broker._STR['ip'])
        self.assertEqual(host['os_guess']['maxLength'], broker._STR['os_guess'])
        finding = contract.load()['$defs']['finding']['properties']
        for field in ('template_id', 'name', 'host', 'matched_at', 'description', 'matcher_name'):
            self.assertEqual(finding[field]['maxLength'], broker._STR[field], field)

    def test_the_enums_equal_the_brokers(self):
        self.assertEqual(tuple(contract.load()['$defs']['finding']['properties']['severity']['enum']), broker._SEVERITIES)
        self.assertEqual(tuple(contract.load()['$defs']['port']['properties']['state']['enum']), broker._PORT_STATES)
        self.assertEqual(tuple(contract.load()['$defs']['port']['properties']['protocol']['enum']), broker._PROTOCOLS)
        severities = self.body('testssl')['items']['items']['properties']['severity']['enum']
        self.assertEqual(tuple(s for s in severities if s), broker._TESTSSL_SEVERITIES)


TARGETS = Path(__file__).with_name('fixtures') / 'sentinel_targets'


def target_validator(kind):
    return Draft202012Validator(contract.target_schema(kind))


class TargetContractTests(SimpleTestCase):
    """The other direction: what the server hands a Sentinel."""

    def test_every_task_kind_has_a_target_schema_and_a_fixture(self):
        for kind in SentinelTask.KINDS:
            Draft202012Validator.check_schema(contract.target_schema(kind))
        have = {p.stem for p in TARGETS.glob('*.json')}
        self.assertEqual(have, {k for k in SentinelTask.KINDS if k not in ('nuclei_targeted', 'nuclei_deep')})

    def test_each_fixture_is_a_valid_target_for_its_kind(self):
        for path in TARGETS.glob('*.json'):
            self.assertEqual(list(target_validator(path.stem).iter_errors(json.loads(path.read_text()))), [], path.stem)

    def test_the_three_nuclei_kinds_share_one_target_shape(self):
        sent = json.loads((TARGETS / 'nuclei_light.json').read_text())
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            self.assertEqual(list(target_validator(kind).iter_errors(sent)), [], kind)

    def test_a_target_outside_the_contract_is_rejected(self):
        bad = json.loads((TARGETS / 'nmap.json').read_text())
        bad['addresses'] = [f'192.0.2.{i % 250 + 1}' for i in range(broker_dispatch.MAX_ADDRESSES + 1)]
        self.assertTrue(list(target_validator('nmap').iter_errors(bad)))
        self.assertTrue(list(target_validator('nmap').iter_errors({'addresses': ['192.0.2.1'], 'surprise': 1})))
        self.assertTrue(list(target_validator('testssl').iter_errors({'host': 'example.com', 'ip': '192.0.2.1', 'port': 70000})))

    def test_a_waf_target_outside_the_contract_is_rejected(self):
        good = json.loads((TARGETS / 'waf.json').read_text())
        for change in ({'scheme': 'ftp'}, {'scheme': 'HTTPS'}, {'port': 0}, {'port': 70000}, {'port': '443'}, {'host': 'h' * 261}, {'ip': '1' * 61},
                       {'surprise': 1}):
            self.assertTrue(list(target_validator('waf').iter_errors({**good, **change})), change)
        for missing in ('host', 'ip', 'port', 'scheme'):
            self.assertTrue(list(target_validator('waf').iter_errors({k: v for k, v in good.items() if k != missing})), missing)

    def test_the_address_cap_equals_the_dispatchers(self):
        defs = contract.load()['$defs']['targets']
        self.assertEqual(defs['nmap']['properties']['addresses']['maxItems'], broker_dispatch.MAX_ADDRESSES)
        self.assertEqual(defs['naabu']['properties']['addresses']['maxItems'], broker_dispatch.MAX_ADDRESSES)
        self.assertEqual(defs['nuclei_light']['properties']['targets']['maxItems'], broker_dispatch.MAX_ADDRESSES)


class RealTargetBuilderTests(SimpleTestCase):
    """Run the server's own code that builds each target and check what it produced against the schema, so a builder that changes shape
    fails here and not on a Sentinel in the field."""

    def captured(self, call):
        seen = []

        def fake_dispatch(project, kind, target, **kwargs):
            seen.append((kind, target))
            return None
        with mock.patch.object(broker_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(broker_dispatch, 'dispatch_or_none', side_effect=fake_dispatch):
            call()
        return seen

    def check(self, seen, expect_kinds):
        self.assertEqual({k for k, _ in seen}, set(expect_kinds))
        for kind, target in seen:
            self.assertEqual(list(target_validator(kind).iter_errors(target)), [], (kind, target))

    def test_nmap_naabu_udp_and_testssl_targets(self):
        scan = mock.Mock()
        with mock.patch('cveFeed.naabu_scan.run_naabu', return_value={}):  # no Sentinel answers here, so the wrapper would run naabu itself
            seen = self.run_builders(scan)
        self.check(seen, ['nmap', 'naabu', 'nmap_udp', 'testssl'])

    def run_builders(self, scan):
        return self.captured(lambda: (
            broker_dispatch.try_nmap(mock.Mock(), scan, ['192.0.2.10', '192.0.2.11']),
            broker_dispatch.wrap_naabu_runner(mock.Mock(), scan)(['192.0.2.10']),
            broker_dispatch.try_nmap_udp(mock.Mock(), '192.0.2.10', scan),
            broker_dispatch.try_testssl(mock.Mock(), 'example.com', '192.0.2.10', 443, 'smtp', scan)))

    def test_the_nuclei_targets_for_every_kind(self):
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            target = broker_dispatch._nuclei_target(kind, ['https://example.com'], {'tags': {'wordpress', 'tech'}, 'severities': ['high']})
            self.assertEqual(list(target_validator(kind).iter_errors(target)), [], (kind, target))

    def test_the_wpscan_target(self):
        with mock.patch('cveFeed.wpscan_scan.run_wpscan_process', return_value={}):
            seen = self.captured(lambda: broker_dispatch.wrap_wpscan_runner(mock.Mock(), mock.Mock())('https://example.com/', 'example-token'))
        self.check(seen, ['wpscan'])
