"""SN-4 on the server (contract 5): info.tool_versions and "tools behind"; a Sentinel that sends none is unknown, never behind."""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_settings, sentinel_tools
from agentapi.auth import create_token
from agentapi.models import Agent
from agentapi.services import ApiError


class ToolsBehind(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('tools-owner', password='x')

    def agent(self, info=None):
        token, _raw = create_token(self.user, f'tools-{Agent.objects.count()}')
        return Agent.objects.create(token=token, name=f'tools{Agent.objects.count()}', kind='scanner', status='active', capabilities=['nmap'], info=info or {}, last_seen=timezone.now())

    def test_the_info_of_a_registration_keeps_known_tools_and_clips_the_version(self):
        info = sentinel_settings.clean_info({'tool_versions': {'nuclei': '3.10.0' + 'x' * 60, 'nmap': '7.993', 'mystery': '1.0'}})
        self.assertEqual(info['tool_versions'], {'nuclei': ('3.10.0' + 'x' * 60)[:40], 'nmap': '7.993'})
        self.assertNotIn('tool_versions', sentinel_settings.clean_info({'version': 'abc1234'}))

    def test_a_bad_tool_versions_is_a_400(self):
        for bad in ('x', [1], {'Bad Name': '1'}, {'nuclei': 3}, {f't{i}': '1' for i in range(20)}):
            with self.assertRaises(ApiError, msg=bad):
                sentinel_settings.clean_info({'tool_versions': bad})

    def test_older_tools_are_behind_and_the_row_says_which(self):
        shipped = sentinel_tools.expected()
        agent = self.agent({'tool_versions': {'nuclei': '3.10.0', 'nmap': shipped['nmap'], 'testssl': 'v99.0'}})
        state = sentinel_tools.state(agent)
        self.assertEqual(state['status'], 'behind')
        self.assertEqual(state['behind'], [{'tool': 'nuclei', 'running': '3.10.0', 'current': shipped['nuclei']}])
        self.assertTrue(state['flagged'])
        self.assertIn('nuclei 3.10.0', state['detail'])

    def test_current_newer_and_unreadable_versions_are_not_behind(self):
        shipped = sentinel_tools.expected()
        self.assertEqual(sentinel_tools.state(self.agent({'tool_versions': {'nuclei': shipped['nuclei'], 'bbot': '99.0.0', 'nmap': 'unreadable'}}))['status'], 'current')

    def test_a_contract_4_sentinel_that_sends_none_is_unknown_never_behind(self):
        for info in ({}, {'version': 'abc1234'}, {'tool_versions': {}}):
            state = sentinel_tools.state(self.agent(info))
            self.assertEqual((state['status'], state['behind'], state['flagged']), ('unknown', [], False))

    def test_the_version_compare_reads_numbers_only(self):
        self.assertTrue(sentinel_tools.older('7.97', '7.993'))
        self.assertTrue(sentinel_tools.older('3.2', '3.2.5'))
        self.assertFalse(sentinel_tools.older('v3.11.1', '3.11.1'))
        self.assertFalse(sentinel_tools.older('garbage', '3.11.1'))

    def test_the_agent_row_of_rest_and_mcp_carries_tools_state(self):
        from agentapi import agent_broker
        agent = self.agent({'tool_versions': {'nuclei': '3.0.0'}})
        row = agent_broker.agent_dict(Agent.objects.select_related('token__user').get(pk=agent.pk), counts={})
        self.assertEqual(row['tools_state']['status'], 'behind')
        self.assertEqual(row['tools_state']['behind'][0]['tool'], 'nuclei')
        plain = agent_broker.agent_dict(Agent.objects.select_related('token__user').get(pk=self.agent().pk), counts={})
        self.assertEqual(plain['tools_state']['status'], 'unknown')

    def test_recording_the_info_stores_the_versions_audits_once_and_a_report_without_them_clears_them(self):
        from dashboard.models import AuditLog
        agent = self.agent({'contract_version': 4})
        sentinel_settings.record_info(agent, {'contract_version': 5, 'tool_versions': {'nuclei': '3.10.0'}})
        agent.refresh_from_db()
        self.assertEqual(agent.info['tool_versions'], {'nuclei': '3.10.0'})
        sentinel_settings.record_info(agent, {'contract_version': 5, 'tool_versions': {'nuclei': '3.10.0'}})  # the next heartbeat: the same, no second notice
        self.assertEqual(AuditLog.objects.filter(action='sentinel.tools_behind').count(), 1)
        sentinel_settings.record_info(agent, {'contract_version': 5})
        agent.refresh_from_db()
        self.assertNotIn('tool_versions', agent.info)

    def tearDown(self):
        cache.clear()
