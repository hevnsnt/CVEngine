"""The MCP page (/cve/mcp/, rail entry MCP) and the call log behind its History (agentapi.mcp_log, cveFeed.McpCall): every tool call is
recorded with its key, tool, masked arguments and outcome, never its result; heartbeats and empty polls are left out; people see their own
calls and an App Admin sees everyone's."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import mcp_log
from agentapi.auth import create_token
from cveFeed.models import McpCall
from dashboard.models import Project, ProjectMembership
from tests.test_agentapi import tool_call
from tests.test_tenancy import client_for

TOKEN = 'ghp_' + 'a1B2c3D4e5' * 4  # a GitHub token shape the secret masking knows


class CallLogTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.alice = User.objects.create_user('mcp-alice', password='x')
		cls.bob = User.objects.create_user('mcp-bob', password='x')
		cls.proj = Project.objects.create(name='Mcp', slug='mcp-proj', insert_date=timezone.now())
		ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
		_, cls.key = create_token(cls.alice, 'laptop-agent')
		_, cls.ro = create_token(cls.alice, 'reader', read_only=True)

	def test_a_tool_call_is_recorded_with_its_key_tool_and_project_but_not_its_result(self):
		error, data = tool_call(self.key, 'list_projects')
		self.assertFalse(error)
		row = McpCall.objects.get()
		self.assertEqual((row.username, row.token_name, row.tool, row.ok, row.writes), ('mcp-alice', 'laptop-agent', 'list_projects', True, False))
		self.assertNotIn('mcp-proj', str(row.arguments))  # the result (the project list) is never kept
		tool_call(self.key, 'list_hosts', {'slug': 'mcp-proj'})
		self.assertEqual(McpCall.objects.latest('id').project, 'mcp-proj')

	def test_a_refused_call_is_recorded_with_the_error_the_caller_saw(self):
		error, message = tool_call(self.ro, 'add_targets', {'slug': 'mcp-proj', 'targets': ['example.com']})
		self.assertTrue(error)
		row = McpCall.objects.get()
		self.assertEqual((row.tool, row.ok, row.writes, row.token_name), ('add_targets', False, True, 'reader'))
		self.assertEqual(row.error, message[:300])

	def test_arguments_are_secret_masked_and_clipped(self):
		kept = mcp_log.summarise({'note': f'rotated {TOKEN} today', 'long': 'x' * 900, 'n': 3})
		self.assertNotIn(TOKEN, str(kept))
		self.assertLessEqual(len(kept['long']), mcp_log.STRING_CHARS + 1)
		self.assertEqual(kept['n'], 3)
		self.assertEqual(mcp_log.summarise({f'k{i}': 'y' * 199 for i in range(30)})['_too_long'], True)

	def test_heartbeats_and_polls_that_found_no_work_are_left_out(self):
		self.assertFalse(mcp_log.worth_keeping('agent_heartbeat', True, {}))
		self.assertFalse(mcp_log.worth_keeping('get_next_task', True, {'task': None, 'reason': 'nothing to do'}))
		self.assertTrue(mcp_log.worth_keeping('get_next_task', True, {'task': {'id': 1}}))
		self.assertTrue(mcp_log.worth_keeping('get_next_task', False, None))

	def test_a_logging_failure_never_fails_the_call(self):
		from unittest import mock
		with mock.patch.object(McpCall.objects, 'create', side_effect=RuntimeError('db down')):
			error, _data = tool_call(self.key, 'list_projects')
		self.assertFalse(error)

	def test_a_call_the_statement_timeout_cut_off_is_recorded_as_a_timeout(self):
		from unittest import mock
		from django.db.utils import OperationalError
		cut = OperationalError('canceling statement due to statement timeout')
		cut.__cause__ = type('Canceled', (Exception,), {'pgcode': '57014'})()
		with mock.patch('agentapi.mcp.call_tool', side_effect=cut):
			error, message = tool_call(self.key, 'list_hosts', {'project': 'mcp-proj', 'q': 'x'})
		self.assertTrue(error)
		self.assertIn('narrow it', message)  # the caller's answer is unchanged
		row = McpCall.objects.get()
		self.assertEqual((row.tool, row.ok, row.project, row.token_name), ('list_hosts', False, 'mcp-proj', 'laptop-agent'))
		self.assertTrue(row.error.startswith('timeout:'))
		self.assertEqual(row.arguments, {'project': 'mcp-proj', 'q': 'x'})  # the same masked arguments as any call, never more

	def test_a_call_that_crashed_is_recorded_as_an_internal_error(self):
		from unittest import mock
		with mock.patch('agentapi.mcp.call_tool', side_effect=RuntimeError('a secret path /var/x')):
			tool_call(self.key, 'list_projects')
		row = McpCall.objects.get()
		self.assertEqual((row.ok, row.error), (False, mcp_log.INTERNAL_ERROR))  # the exception's text stays in the server log

	def test_people_see_their_own_calls_and_an_app_admin_sees_everyones(self):
		McpCall.objects.create(user=self.alice, username='mcp-alice', tool='list_projects')
		McpCall.objects.create(user=self.bob, username='mcp-bob', tool='get_cve')
		self.assertEqual(list(mcp_log.visible_to(self.alice).values_list('tool', flat=True)), ['list_projects'])
		admin = User.objects.create_superuser('mcp-admin', password='x')
		self.assertEqual(mcp_log.visible_to(admin).count(), 2)

	def test_old_calls_are_pruned_by_the_weekly_maintenance(self):
		from cveFeed import maintenance
		self.assertEqual(maintenance.RETENTION['McpCall'], ('CVENGINE_MCP_LOG_RETENTION_DAYS', 90, 'at'))


class PageTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.alice = User.objects.create_user('mcp-page-alice', password='x')
		cls.bob = User.objects.create_user('mcp-page-bob', password='x')
		cls.admin = User.objects.create_superuser('mcp-page-admin', password='x')
		McpCall.objects.create(user=cls.alice, username='mcp-page-alice', token_name='laptop', tool='list_projects')
		McpCall.objects.create(user=cls.alice, username='mcp-page-alice', token_name='laptop', tool='add_targets', writes=True, ok=False,
							   error='this API key is read only', arguments={'targets': ['example.com']})
		McpCall.objects.create(user=cls.bob, username='mcp-page-bob', token_name='bobs-key', tool='get_cve')

	def get(self, user, query=''):
		return client_for(user).get('/cve/mcp/' + query).content.decode()

	def test_it_opens_for_anyone_signed_in_with_setups_that_name_this_server(self):
		html = self.get(self.alice)
		self.assertIn('<h1>MCP</h1>', html)
		self.assertIn('claude mcp add --transport http cvengine http://testserver/mcp/', html)
		for client in ('client-claude-code', 'client-claude-desktop', 'client-cursor', 'client-vscode', 'client-curl'):
			self.assertIn(f'id="{client}"', html)
		self.assertIn('id="examples"', html)

	def test_the_history_shows_only_your_own_calls(self):
		html = self.get(self.alice)
		self.assertIn('add_targets', html)
		self.assertIn('this API key is read only', html)
		self.assertNotIn('bobs-key', html)
		self.assertIn('bobs-key', self.get(self.admin))

	def test_the_history_filters_by_outcome_and_writes(self):
		html = self.get(self.alice, '?outcome=failed')
		self.assertIn('add_targets', html.split('id="history"')[1].split('</form>')[1])
		self.assertNotIn('<code>list_projects</code>', html.split('id="history"')[1].split('</form>')[1])
		self.assertIn('No call matches these filters', self.get(self.bob, '?writes=1'))

	def test_the_history_filters_the_calls_that_timed_out(self):
		McpCall.objects.create(user=self.alice, username='mcp-page-alice', token_name='laptop', tool='search_hosts', ok=False, error=mcp_log.TIMEOUT_ERROR)
		table = self.get(self.alice, '?outcome=timeout').split('id="history"')[1].split('</form>')[1]
		self.assertIn('search_hosts', table)
		self.assertNotIn('add_targets', table)  # failed, but not a timeout
		self.assertIn('<option value="timeout" selected>Timed out</option>', self.get(self.alice, '?outcome=timeout'))

	def test_the_rail_has_an_mcp_entry_that_is_current_on_the_page(self):
		html = self.get(self.alice)
		self.assertRegex(html, r'data-nav="MCP" href="/cve/mcp/" aria-current="page"')
