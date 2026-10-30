import json
from pathlib import Path

from django.test import SimpleTestCase
from jsonschema import Draft202012Validator

from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi.models import SentinelTask

FIXTURES = Path(__file__).with_name('fixtures') / 'sentinel_results'
KIND_OF = {'nmap': 'nmap', 'naabu': 'naabu', 'nuclei_light': 'nuclei_light', 'testssl': 'testssl', 'nmap_udp': 'nmap_udp', 'wpscan': 'wpscan',
           'discover': 'discover', 'openvas': 'openvas', 'error': 'nmap'}


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
        for name in ('nmap', 'naabu', 'nuclei_light', 'testssl', 'discover', 'nmap_udp'):
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
