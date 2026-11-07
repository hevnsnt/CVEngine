"""A Sentinel's release number (``info.release``, 1.4.0) is display only. What a Sentinel is offered is decided by the contract floor and the kinds the
server knows; the release number never gates anything, a newer Sentinel keeps working, an older client shows ``not reported``."""
from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi import sentinel_settings
from agentapi.models import Agent, SentinelTask
from tests.test_agentapi import call
from tests.test_sentinels import build_world, register_sentinel, reset_rates
from django.test import SimpleTestCase, TestCase


class CleanReleaseTests(SimpleTestCase):
    def test_a_release_number_is_kept_and_anything_else_is_dropped_not_refused(self):
        for good in ('1.4.0', '1.4', '2.0.0', '1.4.0rc1', '10.20.30'):
            self.assertEqual(sentinel_settings.clean_info({'release': good}), {'release': good}, good)
        for bad in ('0.0.0.dev0', '1.4.0.dev3+gabc123', 'v1.4.0', 'abc123def456', '', '1', 14, 1.4, True, ['1.4.0'], {'a': 1}, '1.4.0 ', 'x' * 40, '1.4.0\n'):
            self.assertEqual(sentinel_settings.clean_info({'release': bad}), {}, repr(bad))

    def test_the_words_for_each_contract_state(self):
        self.assertEqual(contract.describe(None)['label'], 'not reported')
        self.assertEqual(contract.describe(contract.version())['state'], 'current')
        newer = contract.describe(contract.version() + 5)
        self.assertEqual((newer['state'], newer['label']), ('newer', 'newer than this server (fine)'))
        self.assertIn('nothing else', newer['reason'])
        if contract.min_supported() > 1:
            old = contract.describe(contract.min_supported() - 1)
            self.assertEqual((old['state'], old['label']), ('unsupported', 'update required'))
            self.assertIn(f'at least {contract.min_supported()}', old['reason'])


class ReleaseNumberTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        reset_rates(self.tokens)

    def live_row(self, agent):
        status, out = call(self.tokens['root'], 'GET', '/api/v1/sentinels/live')
        self.assertEqual(status, 200)
        return {r['id']: r for r in out['results']}[agent.pk]

    def test_the_release_is_stored_and_shown_beside_the_commit_everywhere(self):
        status, out = register_sentinel(self.tokens['alice'], info={'version': 'abc123def456', 'release': '1.4.0', 'contract_version': contract.version()})
        self.assertIn(status, (200, 201), out)
        agent = Agent.objects.get(pk=out['id'])
        self.assertEqual((agent.info['version'], agent.info['release']), ('abc123def456', '1.4.0'))
        row = self.live_row(agent)
        self.assertEqual((row['version'], row['release'], row['release_label']), ('abc123def456', '1.4.0', '1.4.0'))
        status, detail = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')
        self.assertEqual((status, detail['release'], detail['version']), (200, '1.4.0', 'abc123def456'))
        status, listing = call(self.tokens['root'], 'GET', '/api/v1/agents')
        self.assertEqual(status, 200)
        self.assertEqual({r['id']: r for r in listing['results']}[agent.pk]['release'], '1.4.0')
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'version': 'fedcba987654', 'release': '1.4.1', 'contract_version': contract.version()}})
        self.assertEqual(status, 200, beat)
        agent.refresh_from_db()
        self.assertEqual((agent.info['version'], agent.info['release']), ('fedcba987654', '1.4.1'))

    def test_a_client_without_a_release_number_works_and_shows_not_reported(self):
        status, out = register_sentinel(self.tokens['alice'], info={'version': 'abc123def456', 'contract_version': contract.version()})
        self.assertIn(status, (200, 201), out)
        agent = Agent.objects.get(pk=out['id'])
        self.assertNotIn('release', agent.info)
        row = self.live_row(agent)
        self.assertEqual((row['release'], row['release_label']), (None, 'not reported'))
        self.assertIn('nmap', broker.effective_capabilities(agent))
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'contract_version': contract.version()}})
        self.assertEqual(status, 200)
        status, task = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 200)

    def test_a_dev_string_in_the_release_field_is_never_stored_as_a_release(self):
        status, out = register_sentinel(self.tokens['alice'], info={'release': '0.0.0.dev0', 'version': 'abc123def456'})
        self.assertIn(status, (200, 201), out)
        agent = Agent.objects.get(pk=out['id'])
        self.assertNotIn('release', agent.info)
        self.assertEqual(self.live_row(agent)['release_label'], 'not reported')

    def test_a_newer_contract_and_an_unseen_release_still_gets_the_known_kinds_and_nothing_else(self):
        known = set(SentinelTask.KINDS)
        status, out = register_sentinel(self.tokens['alice'], capabilities=sorted(known), info={'version': 'abc123def456', 'release': '9.9.9', 'contract_version': contract.version() + 7, 'future_field': {'x': 1}})
        self.assertIn(status, (200, 201), out)
        agent = Agent.objects.get(pk=out['id'])
        self.assertNotIn('future_field', agent.info)  # a field this server does not read passes without an error and is not stored
        self.assertEqual(agent.info['release'], '9.9.9')
        offered = broker.effective_capabilities(agent) & known
        self.assertEqual(offered, known)  # every kind this server knows, and effective_capabilities adds nothing beyond them
        self.assertTrue(all(contract.can_run(agent.info['contract_version'], kind) for kind in known))
        self.assertFalse(contract.can_run(agent.info['contract_version'], 'a_kind_from_the_future'))
        self.assertFalse(any(contract.can_run(agent.info['contract_version'], kind) for kind in ('a_kind_from_the_future',)))
        self.assertEqual(set(broker.effective_capabilities(agent)) - known - set(agent.capabilities), set())
        row = self.live_row(agent)
        self.assertEqual(row['contract_state'], 'newer')
        self.assertEqual(row['contract_note']['label'], 'newer than this server (fine)')
        self.assertEqual(row['release'], '9.9.9')
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'release': '9.9.10', 'contract_version': contract.version() + 7}})
        self.assertEqual(status, 200, beat)

    def test_a_newer_sentinel_declaring_a_kind_the_server_does_not_know_is_never_offered_it(self):
        status, out = register_sentinel(self.tokens['alice'], capabilities=['nmap', 'a_kind_from_the_future'], info={'release': '9.9.9', 'contract_version': contract.version() + 7})
        if status in (200, 201):
            agent = Agent.objects.get(pk=out['id'])
            self.assertEqual(broker.effective_capabilities(agent) & set(SentinelTask.KINDS), {'nmap'})  # a kind this server has no task for is never one it hands out
            self.assertNotIn('a_kind_from_the_future', SentinelTask.KINDS)
            status, nxt = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0, 'kinds': ['a_kind_from_the_future']})
            self.assertEqual(status, 400)  # the poll itself only takes kinds this server knows
        else:
            self.assertEqual(status, 400, out)  # refused outright is as safe: nothing is offered

    def test_a_newer_sentinel_is_handed_a_task_of_a_kind_the_server_knows(self):
        status, out = register_sentinel(self.tokens['dana'], name='newer-one', capabilities=['nmap'], info={'release': '9.9.9', 'contract_version': contract.version() + 7})
        self.assertIn(status, (200, 201), out)
        task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example', ips=['192.0.2.50'])
        status, got = call(self.tokens['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual((status, got['task']['id'], got['task']['kind']), (200, task.pk, 'nmap'))

    def test_the_release_number_is_not_a_gate(self):
        for release in ('0.1', '1.4.0', '99.0.0'):
            agent = Agent.objects.get(pk=register_sentinel(self.tokens['alice'], info={'release': release, 'contract_version': contract.version()})[1]['id'])
            self.assertIn('nmap', broker.effective_capabilities(agent), release)

    def test_an_unsupported_contract_says_update_required_with_its_reason_and_gets_no_work(self):
        from unittest import mock
        doc = {**contract.load(), 'contract_version': 5, 'min_supported_contract_version': 4}
        with mock.patch.object(contract, 'load', return_value=doc):
            status, out = register_sentinel(self.tokens['alice'], info={'release': '1.3.0', 'contract_version': 2})
            self.assertIn(status, (200, 201), out)
            agent = Agent.objects.get(pk=out['id'])
            self.assertEqual(broker.effective_capabilities(agent) & set(SentinelTask.KINDS), set())
            row = self.live_row(agent)
            self.assertEqual((row['contract_state'], row['contract_note']['label']), ('unsupported', 'update required'))
            self.assertIn('at least 4', row['contract_note']['reason'])
            status, detail = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')
            self.assertEqual(detail['contract_note']['label'], 'update required')
