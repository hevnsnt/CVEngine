"""A Sentinel declares the contract version it speaks (``info.contract_version``) and is offered only the kinds that version can run."""
from unittest import mock

from django.test import SimpleTestCase, TestCase

from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi.models import Agent, SentinelTask
from tests.test_agentapi import call
from tests.test_sentinels import build_world, register_sentinel, reset_rates


class ContractFunctionTests(SimpleTestCase):
    def test_every_kind_has_a_since_version_and_none_is_newer_than_the_contract(self):
        for kind in SentinelTask.KINDS:
            self.assertLessEqual(contract.kind_since(kind), contract.version(), kind)
        self.assertLessEqual(contract.min_supported(), contract.version())

    def test_an_unreported_version_is_taken_as_one(self):
        self.assertTrue(all(contract.can_run(None, kind) for kind in SentinelTask.KINDS if contract.kind_since(kind) == 1))
        self.assertEqual({kind for kind in SentinelTask.KINDS if not contract.can_run(None, kind)}, {'waf'})  # the one kind newer than version 1
        self.assertTrue(all(contract.can_run(1, kind) == contract.can_run(None, kind) for kind in SentinelTask.KINDS))
        self.assertTrue(all(contract.can_run(2, kind) for kind in SentinelTask.KINDS))
        self.assertEqual(contract.state(None), 'unreported')

    def test_a_kind_newer_than_what_the_sentinel_speaks_is_not_offered(self):
        with mock.patch.object(contract, 'load', return_value={**contract.load(), 'contract_version': 3, 'kind_since': {**contract.load()['kind_since'], 'nmap': 3}}):
            self.assertFalse(contract.can_run(2, 'nmap'))
            self.assertTrue(contract.can_run(3, 'nmap'))
            self.assertTrue(contract.can_run(2, 'naabu'))
            self.assertEqual(contract.state(3), 'current')
            self.assertEqual(contract.state(4), 'newer')

    def test_a_version_older_than_the_server_still_speaks_is_unsupported_and_offered_nothing(self):
        with mock.patch.object(contract, 'load', return_value={**contract.load(), 'contract_version': 3, 'min_supported_contract_version': 2}):
            self.assertEqual(contract.state(2), 'previous')
            self.assertEqual(contract.state(1), 'unsupported')
            self.assertFalse(any(contract.can_run(1, kind) for kind in SentinelTask.KINDS))
            self.assertTrue(contract.can_run(2, 'nmap'))

    def test_a_kind_the_contract_does_not_know_is_never_offered(self):
        self.assertFalse(contract.can_run(1, 'telnet'))


class ReportingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        reset_rates(self.tokens)

    def register(self, **info):
        status, out = register_sentinel(self.tokens['alice'], **({'info': info} if info else {}))
        self.assertIn(status, (200, 201), out)
        return Agent.objects.get(pk=out['id']), out

    def test_the_registration_and_every_heartbeat_say_which_contract_the_server_speaks(self):
        _, out = self.register()
        self.assertEqual(out['contract'], contract.reply())
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')
        self.assertEqual(status, 200)
        self.assertEqual(beat['contract'], contract.reply())

    def test_a_declared_version_is_stored_and_shown(self):
        agent, _ = self.register(contract_version=1)
        agent.refresh_from_db()
        self.assertEqual(agent.info['contract_version'], 1)
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'contract_version': 1}})
        self.assertEqual(status, 200)

    def test_a_malformed_version_is_refused_and_nothing_is_stored(self):
        for bad in (0, -1, 1001, True, '1', 1.5, [1]):
            status, out = call(self.tokens['alice'], 'PUT', '/api/v1/sentinel',
                               {'name': 's', 'scope': {'projects': ['sen-a']}, 'info': {'contract_version': bad}})
            self.assertEqual(status, 400, bad)
        self.assertFalse(Agent.objects.filter(kind='scanner').exists())

    def test_a_sentinel_is_offered_only_the_kinds_its_contract_version_can_run(self):
        agent, _ = self.register(contract_version=1)
        agent.refresh_from_db()
        everything = set(agent.capabilities)
        self.assertEqual(broker.effective_capabilities(agent) & set(SentinelTask.KINDS), everything & set(SentinelTask.KINDS))
        newer = {**contract.load(), 'contract_version': 2, 'kind_since': {**contract.load()['kind_since'], 'nmap': 2}}
        with mock.patch.object(contract, 'load', return_value=newer):
            caps = broker.effective_capabilities(agent)
        self.assertNotIn('nmap', caps)
        self.assertIn('naabu', caps)

    def waf_agent(self, **info):
        status, out = register_sentinel(self.tokens['alice'], capabilities=['nmap', 'waf'], **({'info': info} if info else {}))
        self.assertIn(status, (200, 201), out)
        agent = Agent.objects.get(pk=out['id'])
        self.assertIn('waf', agent.capabilities)  # it said so; the question is whether the server believes it
        return agent

    def test_waf_is_offered_only_to_a_sentinel_that_declares_contract_version_two_and_lists_it(self):
        self.assertEqual(contract.kind_since('waf'), 2)
        for info in ({}, {'contract_version': 1}):
            agent = self.waf_agent(**info)
            caps = broker.effective_capabilities(agent)
            self.assertNotIn('waf', caps, info)
            self.assertIn('nmap', caps, info)
            self.assertNotIn('waf', broker.effective(agent).caps, info)
            self.assertFalse(contract.can_run(agent.info.get('contract_version'), 'waf'))
        agent = self.waf_agent(contract_version=2)
        self.assertEqual(broker.effective_capabilities(agent) & {'nmap', 'waf'}, {'nmap', 'waf'})
        self.assertIn('waf', broker.effective(agent).caps)

    def test_a_version_two_sentinel_that_does_not_list_waf_is_not_offered_it(self):
        status, out = register_sentinel(self.tokens['alice'], info={'contract_version': 2})
        self.assertIn(status, (200, 201), out)
        self.assertNotIn('waf', broker.effective_capabilities(Agent.objects.get(pk=out['id'])))

    def test_a_sentinel_that_never_declared_a_version_keeps_working(self):
        agent, _ = self.register()
        agent.refresh_from_db()
        self.assertNotIn('contract_version', agent.info or {})
        self.assertIn('nmap', broker.effective_capabilities(agent))
