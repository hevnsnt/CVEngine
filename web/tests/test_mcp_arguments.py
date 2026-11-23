"""An MCP tool call with an argument the tool does not take is refused with a message naming it and the arguments the tool takes, so a
misspelt or unsupported filter (q on list_cve_matches) is never silently ignored while the caller believes it applied."""
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import mcp
from agentapi.auth import create_token
from agentapi.services import ApiError
from dashboard.models import Project, ProjectMembership
from tests.test_agentapi import tool_call


class CheckArgumentsTests(SimpleTestCase):
    def test_an_unknown_argument_is_refused_with_its_name_and_the_accepted_ones(self):
        schema = mcp.BY_NAME['list_cve_matches'][2]
        with self.assertRaises(ApiError) as caught:
            mcp.check_arguments(schema, {'project': 'p', 'q': 'openssl'})
        self.assertEqual(caught.exception.status, 400)
        self.assertIn('unknown argument(s): q', caught.exception.message)
        for accepted in ('project', 'status', 'verdict', 'host', 'kev', 'cve', 'page', 'page_size'):
            self.assertIn(accepted, caught.exception.message.split('this tool takes:')[1])

    def test_a_tool_without_arguments_says_so(self):
        with self.assertRaises(ApiError) as caught:
            mcp.check_arguments(mcp.BY_NAME['list_projects'][2], {'slug': 'x'})
        self.assertIn('this tool takes: no arguments', caught.exception.message)

    def test_listed_arguments_still_pass(self):
        mcp.check_arguments(mcp.BY_NAME['list_cve_matches'][2], {'project': 'p', 'status': 'open', 'cve': 'CVE-2024-1', 'classification': 'real'})

    def test_every_schema_says_whether_it_takes_more_and_only_the_sentinel_contract_tools_do(self):
        open_ended = {name for name, _d, schema, _h, _w in mcp.TOOLS if schema['additionalProperties'] is True}
        self.assertEqual(open_ended, {'register_sentinel', 'sentinel_heartbeat', 'report_sentinel_task_result'})
        mcp.check_arguments(mcp.BY_NAME['sentinel_heartbeat'][2], {'running': [1], 'info': {}})  # the Sentinel contract's fields

    def test_the_filters_the_services_already_read_are_listed_so_they_keep_working(self):
        listed = {name: set(schema['properties']) for name, _d, schema, _h, _w in mcp.TOOLS}
        for name, keys in {'list_cve_matches': {'cve', 'classification'}, 'list_vulnerabilities': {'classification', 'internal'},
                           'search_hosts': {'internal', 'exposed'}, 'list_hosts': {'internal'}, 'list_findings': {'internal'},
                           'list_scans': {'status'}, 'list_scan_subdomains': {'http_status'}, 'list_scan_endpoints': {'http_status'},
                           'list_routes': {'target_id'}, 'list_changes': {'target_id', 'scan_id'}, 'list_hygiene_findings': {'q'},
                           'get_threat_digest': {'cadence'}, 'get_remediation_work': {'include_fp'}, 'set_project_settings': {'inventory'},
                           'search_supplier_technology': {'q'}}.items():
            self.assertLessEqual(keys, listed[name], name)


class ToolCallTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.alice = User.objects.create_user('mcp-args-alice', password='x')
        cls.proj = Project.objects.create(name='Args', slug='mcp-args', insert_date=timezone.now())
        ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
        _, cls.key = create_token(cls.alice, 'args-agent')

    def test_q_on_list_cve_matches_is_an_error_the_caller_sees(self):
        error, message = tool_call(self.key, 'list_cve_matches', {'project': 'mcp-args', 'q': 'openssl'})
        self.assertTrue(error)
        self.assertIn('unknown argument(s): q', message)
        self.assertIn('host', message)

    def test_the_same_call_without_it_works(self):
        error, data = tool_call(self.key, 'list_cve_matches', {'project': 'mcp-args'})
        self.assertFalse(error, data)

    def test_the_refusal_is_recorded_in_the_history(self):
        from cveFeed.models import McpCall
        tool_call(self.key, 'list_cve_matches', {'project': 'mcp-args', 'q': 'openssl'})
        row = McpCall.objects.get()
        self.assertFalse(row.ok)
        self.assertIn('unknown argument(s): q', row.error)
