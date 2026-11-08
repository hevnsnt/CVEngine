"""The built-in scanner follows the newest published Sentinel, which removes the human who used to approve each image. These are the rails that stay:
the server offers no work to a Sentinel whose contract is below what it speaks (and says so, on screen), a Sentinel on a NEWER contract keeps working on the
kinds the server knows, and the Sentinels page and the system status say which build runs, whether it is the newest the server saw, and since when."""
from unittest import mock

from django.core.cache import cache
from django.utils import timezone

from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi import sentinel_settings, sentinel_version
from agentapi.models import Agent, SentinelTask
from tests.test_agentapi import call
from tests.test_builtin_visible import BuiltinVisibleBase

OLDER = 'This scanner is older than this server needs, update it'
VERSION = 'abcdef012345'


def newer_server(**changes):
    """The contract file as a server one release further on would read it: version 3, and the oldest it still speaks raised to 2."""
    return mock.patch.object(contract, 'load', return_value={**contract.load(), 'contract_version': 3, 'min_supported_contract_version': 2, **changes})


class FloorTests(BuiltinVisibleBase):
    def agent(self, **info):
        agent = self.enroll()
        Agent.objects.filter(pk=agent.pk).update(info={'version': VERSION, **info})
        agent.refresh_from_db()
        return agent

    def test_a_scanner_below_the_contract_floor_is_offered_nothing(self):
        agent = self.agent(contract_version=1)
        with newer_server():
            self.assertEqual(contract.state(1), 'unsupported')
            self.assertFalse(any(contract.can_run(1, kind) for kind in SentinelTask.KINDS))
            self.assertFalse(broker.effective_capabilities(agent) & set(SentinelTask.KINDS))
            self.assertFalse(broker.effective(agent).caps & set(SentinelTask.KINDS))

    def test_the_message_is_the_one_the_page_shows(self):
        with newer_server():
            self.assertEqual(contract.note(1), OLDER)
            self.assertEqual(contract.note(None), OLDER, 'a client that never said is version 1')
            self.assertEqual(contract.note(2), contract.NOTES['previous'])
            self.assertEqual(contract.note(3), '')
        self.assertEqual(contract.note(None), '', 'while the server still speaks version 1 an old client is simply served')
        self.assertIn('newer than this server (fine)', contract.note(contract.version() + 1))

    def test_the_sentinels_page_and_the_system_status_show_the_message(self):
        agent = self.agent(contract_version=1)
        with newer_server():
            rows = {r['id']: r for r in call(self.t_root, 'GET', '/api/v1/sentinels/live')[1]['results']}
            self.assertEqual((rows[agent.pk]['contract_state'], rows[agent.pk]['contract_note']), ('unsupported', OLDER))
            detail = call(self.t_root, 'GET', f'/api/v1/agents/{agent.pk}')[1]
            self.assertEqual(detail['contract'], {'version': 1, 'state': 'unsupported', 'note': OLDER})
            data = self.status(self.t_root)
            block = data['scanning']['builtin_scanner']
            self.assertEqual((block['contract_state'], block['contract_note']), ('unsupported', OLDER))
            self.assertTrue([line for line in self.lines(data) if OLDER in line], data['problems'])
            self.assertEqual(self.status(self.t_member)['scanning']['builtin_scanner'], {'enabled': True, 'enrolled': True, 'live': True})

    def test_a_scanner_on_a_newer_contract_keeps_working_on_the_kinds_the_server_knows(self):
        ahead = contract.version() + 5
        agent = self.agent(contract_version=ahead)
        self.assertEqual(contract.state(ahead), 'newer')
        self.assertTrue(all(contract.can_run(ahead, kind) for kind in SentinelTask.KINDS))
        self.assertFalse(contract.can_run(ahead, 'a_kind_only_a_newer_server_knows'), 'a kind this server does not know is never offered')
        offered = broker.effective_capabilities(agent) & set(SentinelTask.KINDS)
        self.assertEqual(offered, set(agent.capabilities) & set(SentinelTask.KINDS))
        self.assertTrue(offered)
        data = self.status(self.t_root)
        self.assertEqual(data['scanning']['builtin_scanner']['contract_state'], 'newer')
        self.assertEqual(self.lines(data), [], 'newer is fine, not a problem')

    def test_a_field_a_newer_sentinel_sends_that_the_server_does_not_read_is_passed_over(self):
        info = sentinel_settings.clean_info({'version': VERSION, 'contract_version': contract.version() + 1, 'a_field_from_the_future': {'x': 1}})
        self.assertEqual(info, {'version': VERSION, 'contract_version': contract.version() + 1})


class ReleaseTests(BuiltinVisibleBase):
    def test_the_status_says_which_build_runs_and_whether_it_is_the_newest_the_server_saw(self):
        agent = self.enroll()
        Agent.objects.filter(pk=agent.pk).update(info={'version': VERSION, 'contract_version': contract.version()})
        cache.delete(sentinel_version.LATEST_KEY)
        with mock.patch.object(sentinel_version, '_ask_for_refresh'):
            block = self.status(self.t_root)['scanning']['builtin_scanner']
        self.assertEqual((block['version'], block['newest']), (VERSION, None), 'unknown until the cached check has run')
        cache.set(sentinel_version.LATEST_KEY, {'sha': VERSION + 'f' * 28, 'checked_at': timezone.now().isoformat(), 'error': ''}, 600)
        block = self.status(self.t_root)['scanning']['builtin_scanner']
        self.assertEqual((block['newest'], block['newest_version'], block['contract_state']), (True, VERSION, 'current'))
        cache.set(sentinel_version.LATEST_KEY, {'sha': '1' * 40, 'checked_at': timezone.now().isoformat(), 'error': ''}, 600)
        cache.set(sentinel_version.BEHIND_KEY, {VERSION: 4}, 600)
        block = self.status(self.t_root)['scanning']['builtin_scanner']
        self.assertEqual((block['newest'], block['newest_version'], block['behind_by']), (False, '1' * 12, 4))
        self.addCleanup(cache.delete, sentinel_version.LATEST_KEY)
        self.addCleanup(cache.delete, sentinel_version.BEHIND_KEY)

    def test_last_updated_is_when_the_version_changed_and_only_the_server_writes_it(self):
        agent = self.enroll()
        sentinel_settings.record_info(agent, {'version': 'aaaaaaaaaaaa'})
        first = Agent.objects.get(pk=agent.pk).info['version_since']
        self.assertTrue(first)
        sentinel_settings.record_info(Agent.objects.get(pk=agent.pk), {'version': 'aaaaaaaaaaaa', 'contract_version': 3})
        self.assertEqual(Agent.objects.get(pk=agent.pk).info['version_since'], first, 'the same version again moves nothing')
        sentinel_settings.record_info(Agent.objects.get(pk=agent.pk), {'version': 'bbbbbbbbbbbb', 'version_since': '1999-01-01T00:00:00+00:00'})
        later = Agent.objects.get(pk=agent.pk).info['version_since']
        self.assertGreater(later, first)
        self.assertNotIn('1999', later)

    def test_the_sentinels_page_rows_and_the_detail_carry_it(self):
        agent = self.enroll()
        sentinel_settings.record_info(agent, {'version': VERSION, 'contract_version': contract.version()})
        rows = {r['id']: r for r in call(self.t_root, 'GET', '/api/v1/sentinels/live')[1]['results']}
        self.assertTrue(rows[agent.pk]['version_since'])
        self.assertEqual(rows[agent.pk]['contract_note'], '')
        detail = call(self.t_root, 'GET', f'/api/v1/agents/{agent.pk}')[1]
        self.assertTrue(detail['version_since'])
        self.assertEqual(detail['version_state']['version'], VERSION)
        self.assertEqual(detail['contract']['state'], 'current')
