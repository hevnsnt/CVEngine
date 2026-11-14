import hashlib
import json
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase
from jsonschema import Draft202012Validator

from agentapi import scanner_state
from agentapi import sentinel_broker as broker
from agentapi import sentinel_dispatch as broker_dispatch
from agentapi import sentinel_contract as contract
from agentapi.models import SentinelTask
from agentapi.services import ApiError

FIXTURES = Path(__file__).with_name('fixtures') / 'sentinel_results'
KIND_OF = {'nmap': 'nmap', 'naabu': 'naabu', 'nuclei_light': 'nuclei_light', 'testssl': 'testssl', 'nmap_udp': 'nmap_udp', 'wpscan': 'wpscan',
           'discover': 'discover', 'openvas': 'openvas', 'waf': 'waf', 'bbot_discovery': 'bbot_discovery', 'http_probe': 'http_probe',
           'dns_resolve': 'dns_resolve', 'secrets_scan': 'secrets_scan', 'error': 'nmap', 'nmap_full': 'nmap_full', 'nmap_verify': 'nmap_verify', 'node2shell': 'node2shell',
           'rdp_shot': 'rdp_shot', 'db_probe': 'db_probe', 'path_probe': 'path_probe', 'nuclei_validate': 'nuclei_validate',
           'alive_check': 'alive_check', 'bucket_check': 'bucket_check', 'vhost_probe': 'vhost_probe', 'subdir_probe': 'subdir_probe', 'supplier_check': 'supplier_check', 'hygiene_check': 'hygiene_check', 'dangling_dns_check': 'dangling_dns_check', 'route_probe': 'route_probe', 'identity_check': 'identity_check', 'web_screenshot': 'web_screenshot', 'ssh_probe': 'ssh_probe', 'wpscan_thorough': 'wpscan_thorough', 'route_probe_signed': 'route_probe_signed', 'page_read': 'page_read'}


V1_SHA256 = {
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': '13328030712a13a881e8dbb94ccd109e10a72cb62ae2d2081e3b0b107dc057fd',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nuclei_light.json': 'ecb620b0742ef52e5af077d16f545fcc93791fc7ec33c95ced0a8a6153b7c60c',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}
V2_SHA256 = {  # v1's files unchanged, and waf, copied when version 3 added bbot_discovery
    **V1_SHA256,
    'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec',
}
V3_SHA256 = {  # v2's files unchanged, and the kinds contract 3 added, copied when version 4 added template_sha256 to nuclei_validate
    **V2_SHA256,
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': 'f883e593add75ca94820db4cdb0a6672fbf5ccfd6fe5f057ade9d28a270fdc54',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_validate.json': '533c5e2f08d47d75f9b955bf6016855e67a1b78e294ad0e30ae2fe4199a6420f',
    'page_read.json': '741898291c9efae370e7452efebf944bd5793f401991ca673bd06e24abfd3e77',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '09c6c960f1e8bb6b224c69ef82fe94bf8520f074ce0bba02da6296e8a773b764',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': 'b480b4088478b54c84ebfb0e33f19dac34c793d6fdf61530bbb260df9fb9c2aa',
    'ssh_probe.json': '2e9a21973309044357eec19664b7c74e01e03d53b25fdf5e183bae4eee62dfd8',
    'subdir_probe.json': 'dbdbdb8319ff6136f819a1bc4db7b2da0d3b9564403fa6e4a332674cafffefba',
    'supplier_check.json': '2a7247d93165eec72b8ff2aef5f8722d92f5978254d04ae4c5f87dcf8f6f32d1',
    'vhost_probe.json': 'acbe876c4ac3ca04b4660ebb2b021f362c7010384079f3c1ea591305d5eec8ad',
    'web_screenshot.json': 'dc0992e6f2842f93e765e2f1b42d85379afbeb8fc5521e6e3ea4501b2d330bfb',
    'wpscan_thorough.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}
V4_SHA256 = {  # every result fixture of contract version 4 (the Sentinel's own v4 set, page_read from v3), copied when version 5 added the nmap detail, the cuts and the bbot finding port
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': 'f883e593add75ca94820db4cdb0a6672fbf5ccfd6fe5f057ade9d28a270fdc54',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': '13328030712a13a881e8dbb94ccd109e10a72cb62ae2d2081e3b0b107dc057fd',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': 'ecb620b0742ef52e5af077d16f545fcc93791fc7ec33c95ced0a8a6153b7c60c',
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'page_read.json': '741898291c9efae370e7452efebf944bd5793f401991ca673bd06e24abfd3e77',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '421bcadc8d86a63959f8b5727aa1c37022360a2914d532c7e121d1b954428366',
    'ssh_probe.json': '2e9a21973309044357eec19664b7c74e01e03d53b25fdf5e183bae4eee62dfd8',
    'subdir_probe.json': 'dbdbdb8319ff6136f819a1bc4db7b2da0d3b9564403fa6e4a332674cafffefba',
    'supplier_check.json': '2a7247d93165eec72b8ff2aef5f8722d92f5978254d04ae4c5f87dcf8f6f32d1',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'vhost_probe.json': 'acbe876c4ac3ca04b4660ebb2b021f362c7010384079f3c1ea591305d5eec8ad',
    'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec',
    'web_screenshot.json': 'dc0992e6f2842f93e765e2f1b42d85379afbeb8fc5521e6e3ea4501b2d330bfb',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
    'wpscan_thorough.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}
PASSES_THROUGH = ('nmap', 'naabu', 'nuclei_light', 'testssl', 'discover', 'nmap_udp', 'nmap_full', 'nmap_verify', 'node2shell', 'rdp_shot',
                  'db_probe', 'path_probe', 'nuclei_validate')  # unchanged by the server (openvas and wpscan fill in defaults)


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
        for name in ('nmap', 'naabu', 'nuclei_light', 'testssl', 'discover', 'nmap_udp', 'waf', 'bbot_discovery', 'secrets_scan'):
            sent = fixture(name)
            self.assertEqual(broker.clean_result(KIND_OF[name], sent), sent, name)

    def test_all_three_nuclei_kinds_share_one_result_shape(self):
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            self.assertEqual(list(validator(kind).iter_errors(fixture('nuclei_light'))), [], kind)


V1 = FIXTURES / 'v1'
V2 = FIXTURES / 'v2'
V3 = FIXTURES / 'v3'
V4 = FIXTURES / 'v4'
FROZEN = {'v1': V1, 'v2': V2, 'v3': V3, 'v4': V4}  # contract version -> its frozen fixtures: a bump to N copies the then-current set into v<N>/ and adds it here


class KindRegistryTests(SimpleTestCase):
    """The kinds are listed once (the contract's ``kind_since``); every other per-kind table is held to that list."""

    def test_the_model_and_the_contract_share_one_list(self):
        self.assertIs(SentinelTask.KINDS, contract.KINDS)
        self.assertEqual(contract.KINDS, tuple(contract.load()['kind_since']))
        self.assertEqual(len(set(contract.KINDS)), len(contract.KINDS))

    def test_the_contract_halves_name_the_same_kinds(self):
        defs = contract.load()['$defs']
        self.assertEqual(set(defs['results']), set(contract.KINDS))
        self.assertEqual(set(defs['targets']), set(contract.KINDS))

    def test_every_kind_has_a_cleaner_and_no_cleaner_is_for_a_stranger(self):
        self.assertEqual(set(broker._CLEANERS), set(contract.KINDS))

    def test_every_kind_has_a_dispatch_budget_or_no_stage_yet(self):
        self.assertEqual(set(broker_dispatch.COMPLETION_CEILING) | set(scanner_state.NO_STAGE), set(contract.KINDS))
        self.assertFalse(set(broker_dispatch.COMPLETION_CEILING) & set(scanner_state.NO_STAGE))  # a kind with a stage is not "no stage"
        self.assertLessEqual(set(broker_dispatch.PER_TARGET_SECONDS), set(contract.KINDS))  # a partial table, but never of a stranger

    def test_the_kinds_the_slot_count_names_exist(self):
        self.assertLessEqual({'nmap', 'nuclei_light'}, set(contract.KINDS))  # project_slots counts these two on purpose


class FrozenFixtureTests(SimpleTestCase):
    """Each frozen set is what a Sentinel of that contract version sent: the server keeps accepting it down to ``min_supported_contract_version``."""

    def frozen(self):
        return [(v, p) for v, folder in FROZEN.items() for p in sorted(folder.glob('*.json'))]

    def test_every_frozen_set_is_complete_for_its_version(self):
        for v, folder in FROZEN.items():
            have = {p.stem for p in folder.glob('*.json')}
            want = {name for name, kind in KIND_OF.items() if contract.kind_since(kind) <= int(v[1:])}
            self.assertEqual(have, want, v)

    def test_the_oldest_supported_version_is_frozen(self):
        self.assertIn(f'v{contract.min_supported()}', FROZEN)

    def test_a_frozen_set_is_never_edited(self):
        """The hashes of ``v1/`` to ``v4/`` as they were copied from the fixtures of contract versions 1 to 4. A fixture that needs to change belongs in a new version's set."""
        for folder, want in ((V1, V1_SHA256), (V2, V2_SHA256), (V3, V3_SHA256), (V4, V4_SHA256)):
            digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.glob('*.json')}
            self.assertEqual(digests, want, folder.name)

    def test_the_server_accepts_every_frozen_fixture_and_it_is_in_contract(self):
        for v, path in self.frozen():
            kind, sent = KIND_OF[path.stem], json.loads(path.read_text())
            self.assertEqual(list(validator(kind).iter_errors(sent)), [], f'{v}/{path.name}')
            stored = broker.clean_result(kind, sent)
            self.assertEqual(list(validator(kind).iter_errors(stored)), [], f'{v}/{path.name}')
            if path.stem in PASSES_THROUGH:
                self.assertEqual(stored, {'outcome': 'done', **sent}, f'{v}/{path.name}')


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
        from cveFeed import waf_fingerprint
        for body in (
                self.bad(products=[{'name': f'W{i}'} for i in range(waf_fingerprint.MAX_PRODUCTS + 1)]),  # too many
                self.bad(products=[{'name': 'x' * (waf_fingerprint.NAME_LEN + 1)}]),  # name too long
                self.bad(products=[{'name': ''}]),
                self.bad(products=[{'name': 'x', 'manufacturer': 'y' * (waf_fingerprint.NAME_LEN + 1)}]),
                self.bad(products=[{'name': 'x', 'version': '1.0'}]),  # unknown field of a product
                self.bad(products=[{'manufacturer': 'only a maker'}]),
                self.bad(products='FortiWeb'), self.bad(generic='yes'),
                self.bad(surprise=1),  # unknown field of the result
                self.bad(outcome='ok')):
            self.assertTrue(list(validator('waf').iter_errors(body)), body)

    def test_the_server_refuses_what_it_cannot_shape_and_clips_the_rest(self):
        from cveFeed import waf_fingerprint
        with self.assertRaises(ApiError):
            broker.clean_result('waf', self.bad(products=[{'name': f'W{i}'} for i in range(waf_fingerprint.MAX_PRODUCTS + 1)]))
        with self.assertRaises(ApiError):
            broker.clean_result('waf', self.bad(products='FortiWeb'))
        with self.assertRaises(ApiError):
            broker.clean_result('waf', {'outcome': 'done', 'generic': False})
        clipped = broker.clean_result('waf', {'outcome': 'done', 'generic': 'yes', 'surprise': 1, 'products': [
            {'name': 'A' * 500, 'manufacturer': 'M' * 500, 'version': '9', 'url': 'http://x/'}, 'junk', {'name': '  '}, {'name': 5}, {'manufacturer': 'x'}]})
        self.assertEqual(clipped, {'outcome': 'done', 'generic': False,
                                   'products': [{'name': 'A' * waf_fingerprint.NAME_LEN, 'manufacturer': 'M' * waf_fingerprint.NAME_LEN}]})
        self.assertEqual(list(validator('waf').iter_errors(clipped)), [])
        self.assertEqual(broker.clean_result('waf', {'outcome': 'done', 'products': [], 'generic': True}),
                         {'outcome': 'done', 'products': [], 'generic': True})

    def test_an_error_result_keeps_only_its_error(self):
        self.assertEqual(broker.clean_result('waf', {'outcome': 'error', 'error': 'x' * 900, 'products': [{'name': 'y'}]}),
                         {'outcome': 'error', 'error': 'x' * 300})

    def test_the_bounds_are_the_ones_the_local_scan_uses(self):
        from cveFeed import waf_fingerprint
        body = contract.load()['$defs']['results']['waf']['allOf'][1]['properties']['products']
        self.assertEqual(body['maxItems'], waf_fingerprint.MAX_PRODUCTS)
        self.assertEqual(body['items']['properties']['name']['maxLength'], waf_fingerprint.NAME_LEN)
        self.assertEqual(body['items']['properties']['manufacturer']['maxLength'], waf_fingerprint.NAME_LEN)
        self.assertEqual(waf_fingerprint._named([('A' * 500, '')])[0]['firewall'], 'A' * waf_fingerprint.NAME_LEN)

    def test_the_kind_is_new_in_version_two_and_nothing_older_changed(self):
        self.assertGreaterEqual(contract.version(), 2)
        self.assertEqual(contract.min_supported(), 1)
        self.assertEqual(contract.kind_since('waf'), 2)
        since = {k: v for k, v in contract.load()['kind_since'].items() if v < 3}  # version 3 added kinds of its own; none older moved
        self.assertEqual({k: v for k, v in since.items() if k != 'waf'}, {k: 1 for k in since if k != 'waf'})


class ContractMatchesTheServerTests(SimpleTestCase):
    """The file and the broker's own limits must not drift apart: a bound changed on one side only fails here."""
    def defs(self):
        return contract.load()['$defs']['results']

    def body(self, kind):
        return self.defs()[kind]['allOf'][1]['properties']

    def test_list_bounds_equal_the_brokers(self):
        from cveFeed.port_stage import MAX_OPEN_PER_IP  # noqa: F401 - the naabu cleaner's own limit is the per-address list
        nmap = self.body('nmap')['hosts']
        self.assertEqual(nmap['maxItems'], broker.MAX_ADDRESSES)
        self.assertEqual(nmap['items']['properties']['ports']['maxItems'], broker.MAX_PORTS_PER_HOST)
        self.assertEqual(self.body('naabu')['ports']['maxProperties'], broker.MAX_ADDRESSES)
        nuclei = self.body('nuclei_light')['findings']
        self.assertEqual(nuclei['maxItems'], broker.MAX_FINDINGS_SENT)
        self.assertEqual(nuclei['items']['properties']['extracted_results']['maxItems'], broker.MAX_EXTRACTED)
        self.assertEqual(nuclei['items']['properties']['tags']['maxItems'], broker.MAX_TAGS)
        self.assertEqual(nuclei['items']['properties']['cve_ids']['maxItems'], broker.MAX_CVE_IDS)
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
                mock.patch.object(broker_dispatch, 'dispatch_or_none', side_effect=fake_dispatch), \
                mock.patch('agentapi.address_guard.task_refusals', return_value={}):  # this class has no database: the do-not-scan list is tested in test_address_guard
            call()
        return seen

    def check(self, seen, expect_kinds):
        self.assertEqual({k for k, _ in seen}, set(expect_kinds))
        for kind, target in seen:
            self.assertEqual(list(target_validator(kind).iter_errors(target)), [], (kind, target))

    def test_nmap_naabu_udp_and_testssl_targets(self):
        scan = mock.Mock()
        seen = self.run_builders(scan)  # no Sentinel answers here: each builder's task is captured, then the stage waits
        self.check(seen, ['nmap', 'naabu', 'nmap_udp', 'testssl'])

    def run_builders(self, scan):
        from reNgine.resources import ScannerUnavailable

        def waits(call):  # nmap, naabu and nmap_udp never run here: with no Sentinel answering, the builder's task is sent and the stage waits
            try:
                return call()
            except ScannerUnavailable:
                return None
        return self.captured(lambda: (
            waits(lambda: broker_dispatch.try_nmap(mock.Mock(), scan, ['192.0.2.10', '192.0.2.11'])),
            waits(lambda: broker_dispatch.wrap_naabu_runner(mock.Mock(), scan)(['192.0.2.10'])),
            waits(lambda: broker_dispatch.try_nmap_udp(mock.Mock(), '192.0.2.10', scan)),
            broker_dispatch.try_testssl(mock.Mock(), 'example.com', '192.0.2.10', 443, 'smtp', scan)))

    def test_the_nuclei_targets_for_every_kind(self):
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            target = broker_dispatch._nuclei_target(kind, ['https://example.com'], {'tags': {'wordpress', 'tech'}, 'severities': ['high']})
            self.assertEqual(list(target_validator(kind).iter_errors(target)), [], (kind, target))

    def test_the_wpscan_target(self):
        def run():
            with self.assertRaises(RuntimeError):  # the stub answers nothing: the server never runs the scan itself, so nothing was read
                broker_dispatch.wrap_wpscan_runner(mock.Mock(), mock.Mock())('https://example.com/', 'example-token')
        seen = self.captured(run)
        self.check(seen, ['wpscan'])

    def test_the_wpscan_thorough_target(self):
        def run():
            with self.assertRaises(RuntimeError):  # the stub answers nothing: the server never runs the scan itself, so nothing was read
                broker_dispatch.wrap_wpscan_thorough_runner(mock.Mock(), mock.Mock(), timeout_seconds=7200)('https://example.com/', 'example-token')
        seen = self.captured(run)
        self.check(seen, ['wpscan_thorough'])
        self.assertEqual(seen[0][1]['timeout_seconds'], 7200)
