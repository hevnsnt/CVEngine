"""Every tool and route whose token use is refused or narrowed (agentapi.capability_review) says so in its own description, so an agent that
reads only the tool list knows before it calls: a refused one says a person does it, a narrowed one says what a token may do."""
import re

from django.test import SimpleTestCase

from agentapi import capability_review, mcp, rest

TOKEN_RULE = re.compile(r'A person only|A token \(any API token or MCP call\)|an API token is refused|a token is refused', re.I)
PERSON_ONLY = re.compile(r'a person only|signed in as a person \(an API token is refused|a token is refused', re.I)


def verdicts():
    out = {}
    for verdict, _reason, items in capability_review.REVIEW:
        for item in items:
            out.setdefault(item, verdict)
    return out


class TokenRulesDescribedTests(SimpleTestCase):
    def test_every_refused_or_narrowed_mcp_tool_states_the_token_rule(self):
        tools = {name: description for name, description, *_ in mcp.TOOLS}
        missing = sorted(name for name, verdict in verdicts().items() if name in tools and verdict in ('refuse', 'narrow')
                         and not TOKEN_RULE.search(tools[name]))
        self.assertEqual(missing, [], f'these tools refuse or narrow a token but their description does not say so: {missing}')

    def test_every_refused_mcp_tool_says_a_person_does_it(self):
        tools = {name: description for name, description, *_ in mcp.TOOLS}
        missing = sorted(name for name, verdict in verdicts().items() if name in tools and verdict == 'refuse' and not PERSON_ONLY.search(tools[name]))
        self.assertEqual(missing, [], f'refused to every token, but the description does not say a person does it: {missing}')

    def test_every_refused_or_narrowed_rest_route_states_the_token_rule(self):
        routes = {capability_review.route_key(method, pattern): description for method, pattern, description, *_ in rest.ROUTES}
        missing = sorted(key for key, verdict in verdicts().items() if key in routes and verdict in ('refuse', 'narrow')
                         and not TOKEN_RULE.search(routes[key]))
        self.assertEqual(missing, [], f'these routes refuse or narrow a token but their description does not say so: {missing}')

    def test_remove_exclusion_no_longer_reads_as_open_to_an_organization_admin_token(self):
        description = dict((name, d) for name, d, *_ in mcp.TOOLS)['remove_exclusion']
        self.assertTrue(description.startswith('A person only'), description)

    def test_set_project_settings_names_its_inventory_argument(self):
        tool = mcp.BY_NAME['set_project_settings']
        self.assertIn('inventory', tool[2]['properties'])
        self.assertIn('inventory', tool[1])
