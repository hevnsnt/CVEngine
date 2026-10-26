import time

from django.test import SimpleTestCase

from agentapi import services
from agentapi.services import ApiError, parse_search, parse_target_list


class TargetParsingLimitTests(SimpleTestCase):
	def test_a_long_run_of_open_brackets_parses_in_linear_time(self):
		started = time.monotonic()
		self.assertEqual(parse_target_list('[' * 200_000 + ' example.com'), ['example.com'])
		self.assertLess(time.monotonic() - started, 2)

	def test_markdown_links_still_become_their_url(self):
		self.assertEqual(parse_target_list('[the site](https://a.example.com/x)'), ['a.example.com'])
		self.assertEqual(parse_target_list('[b](b.example.com) [c](c.example.com)'), ['b.example.com', 'c.example.com'])

	def test_an_overlong_token_is_dropped_not_normalised(self):
		self.assertEqual(parse_target_list('a' * (services.MAX_TARGET_TOKEN + 1) + ' ok.example.com'), ['ok.example.com'])

	def test_pasted_text_beyond_the_cap_is_ignored(self):
		text = 'first.example.com\n' + ('x' * 100 + '\n') * (services.MAX_TARGET_TEXT // 100) + 'last.example.com'
		self.assertNotIn('last.example.com', parse_target_list(text))


class SearchLimitTests(SimpleTestCase):
	def test_normal_searches_still_parse(self):
		self.assertEqual(len(parse_search('tech:"apache tomcat" -port:80 nginx')), 3)

	def test_too_many_terms_is_a_400(self):
		with self.assertRaises(ApiError) as ctx:
			parse_search(' '.join(f'w{i}' for i in range(services.MAX_SEARCH_TERMS + 1)))
		self.assertEqual(ctx.exception.status, 400)

	def test_an_overlong_query_or_term_is_a_400(self):
		with self.assertRaises(ApiError):
			parse_search('a' * (services.MAX_SEARCH_QUERY + 1))
		with self.assertRaises(ApiError):
			parse_search('"' + 'a' * (services.MAX_SEARCH_VALUE + 1) + '"')

	def test_a_non_text_query_is_a_400_not_a_crash(self):
		with self.assertRaises(ApiError):
			parse_search({'a': 1})


class WrongTypeArgumentTests(SimpleTestCase):
	def test_an_mcp_tool_with_a_wrong_type_gives_a_generic_400(self):
		from unittest import mock

		from agentapi import mcp
		boom = TypeError("unsupported operand secret-internal-detail")
		with mock.patch.dict(mcp.BY_NAME, {'x': ('x', '', {}, mock.Mock(side_effect=boom), False)}):
			with self.assertRaises(ApiError) as ctx:
				mcp.call_tool(None, 'x', {})
		self.assertEqual(ctx.exception.status, 400)
		self.assertNotIn('secret-internal-detail', ctx.exception.message)



class AssetFilterTests(SimpleTestCase):
	def test_names_parent_domains_ips_and_networks_match_as_before(self):
		f = services.AssetFilter(['www.a.example', 'corp.example', '10.1.0.0/16', '203.0.113.7', '2001:db8::/32', ' '])
		self.assertTrue(f.matches(['www.a.example'], []))
		self.assertTrue(f.matches(['deep.er.corp.example'], []))
		self.assertTrue(f.matches(['x.test'], ['10.1.200.3']))
		self.assertTrue(f.matches(['x.test'], ['203.0.113.7']))
		self.assertTrue(f.matches([], ['2001:db8::5']))
		self.assertFalse(f.matches(['notcorp.example', 'a.example'], ['10.2.0.1', '198.51.100.1', 'not-an-ip']))
		self.assertFalse(services.AssetFilter([' ', '']))
		self.assertTrue(services.asset_matches(['a.corp.example'], [], ['corp.example']))

	def test_five_hundred_assets_over_two_thousand_hosts_is_fast(self):
		patterns = [f'10.{n // 250}.{n % 250}.0/24' for n in range(250)] + [f'asset{n}.example' for n in range(250)]
		f = services.AssetFilter(patterns)
		started = time.monotonic()
		hits = sum(f.matches([f'h{n}.other.test'], [f'192.0.2.{n % 250}']) for n in range(2000))
		self.assertEqual(hits, 0)
		self.assertLess(time.monotonic() - started, 2)
