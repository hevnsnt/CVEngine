"""Regression tests for the agent API review (S02-3 ... S02-16): bulk parsing, negated search terms, MCP argument checks,
purging a host, pagination bounds, error handling, assignee validation, API-key roles, batch long polls and the docs table."""
import os
import re
import time
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from urllib.parse import urlencode

from agentapi import mcp
from agentapi import services as svc
from agentapi.auth import create_token
from cveFeed.models import (FindingAuditEvent, FindingComment, HostArchive, HostAssessment, HostExclusion, HostProfile, HostState,
                            HygieneFinding, ProbeObservation, RdpScreenshot)
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, rpc, tool_call


class BulkOrgParseTests(TestCase):
	def test_parse_org_text_is_linear_and_stops_at_the_cap(self):
		text = '##Acme\n#Web\n' + '\n'.join(f'h{i}.example.test' for i in range(60000))
		started = time.monotonic()
		_, groups, _ = svc.parse_org_text(text)
		self.assertEqual(len(groups[0][1]), 60000)
		self.assertLess(time.monotonic() - started, 8)  # the list membership test took 16 s for this
		with self.assertRaises(svc.ApiError) as cm:
			svc.parse_org_text(text, max_entries=1000)
		self.assertEqual(cm.exception.status, 400)
		with self.assertRaises(svc.ApiError):
			svc.parse_org_text('\n'.join(f'#P{i}\na{i}.example.test' for i in range(10)), max_projects=3)

	def test_parse_org_text_still_merges_a_repeated_project_and_drops_repeats(self):
		_, groups, _ = svc.parse_org_text('#Web\na.com\n#web\na.com\nb.com')
		self.assertEqual(groups, [('Web', ['a.com', 'b.com'])])

	def test_a_caller_in_no_organization_is_refused_before_the_paste_is_parsed(self):
		loner = User.objects.create_user('wp14loner', password='x')
		_, tok = create_token(loner, 't')
		with mock.patch.object(svc, 'parse_org_text') as parse:
			status, _ = call(tok, 'POST', '/api/v1/targets/bulk-org', {'text': '#P\na.example.test'})
		self.assertEqual(status, 403)
		parse.assert_not_called()

	def test_an_oversized_paste_is_a_400(self):
		org = Org.objects.create(name='WB', slug='wb')
		user = User.objects.create_user('wp14big', password='x')
		OrgMembership.objects.create(user=user, org=org, role='admin')
		_, tok = create_token(user, 't')
		with mock.patch.object(svc, 'BULK_MAX_ENTRIES', 5):
			status, data = call(tok, 'POST', '/api/v1/targets/bulk-org', {'text': '#P\n' + '\n'.join(f'a{i}.example.test' for i in range(6))})
		self.assertEqual(status, 400, data)
		self.assertIn('limit', data['error'])


class AddTargetsCapTests(TestCase):
	def test_an_oversized_paste_with_an_exclusion_line_deletes_nothing(self):
		org = Org.objects.create(name='WA', slug='wa')
		project = Project.objects.create(name='WA', slug='wa-p', insert_date=timezone.now(), org=org)
		user = User.objects.create_user('wp14adm', password='x')
		OrgMembership.objects.create(user=user, org=org, role='admin')
		keep = Domain.objects.create(name='corp.example.test', project=project, insert_date=timezone.now())
		_, tok = create_token(user, 't')
		lines = ['-corp.example.test'] + [f'a{i}.example.test' for i in range(6)]
		with mock.patch.object(svc, 'BULK_MAX_ENTRIES', 5):
			status, data = call(tok, 'POST', '/api/v1/projects/wa-p/targets/bulk', {'text': '\n'.join(lines), 'discover': False})
		self.assertEqual(status, 400, data)
		self.assertTrue(Domain.objects.filter(pk=keep.pk).exists())
		self.assertFalse(HostExclusion.objects.filter(org=org).exists())

	def test_the_number_of_exclusion_lines_is_capped(self):
		org = Org.objects.create(name='WE', slug='we')
		Project.objects.create(name='WE', slug='we-p', insert_date=timezone.now(), org=org)
		user = User.objects.create_user('wp14adm2', password='x')
		OrgMembership.objects.create(user=user, org=org, role='admin')
		_, tok = create_token(user, 't')
		with mock.patch.object(svc, 'BULK_MAX_EXCLUSIONS', 2):
			status, data = call(tok, 'POST', '/api/v1/projects/we-p/targets/bulk',
								{'text': '-a.example.test\n-b.example.test\n-c.example.test', 'discover': False})
		self.assertEqual(status, 400, data)
		self.assertFalse(HostExclusion.objects.filter(org=org).exists())


class NegatedSearchTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='NS', slug='ns')
		cls.project = Project.objects.create(name='NS', slug='ns-p', insert_date=now, org=org)
		cls.user = User.objects.create_user('wp14search', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='user')
		_, cls.tok = create_token(cls.user, 't')
		domain = Domain.objects.create(name='ns.example.test', project=cls.project, insert_date=now)

		def host(name, ip, ports):
			sub = Subdomain.objects.create(name=name, target_domain=domain)
			addr = IpAddress.objects.create(address=ip)
			sub.ip_addresses.add(addr)
			for number, state, product in ports:
				addr.ports.add(Port.objects.create(number=number, state=state, product=product, service_name='svc'))
		host('closed161.ns.example.test', '10.0.0.1', [(161, 'closed', 'snmpd'), (22, 'open', 'OpenSSH')])
		host('open161.ns.example.test', '10.0.0.2', [(161, 'open', 'snmpd'), (22, 'open', 'OpenSSH')])
		host('plain.ns.example.test', '10.0.0.3', [(443, 'open', 'nginx')])

	def names(self, q):
		status, data = call(self.tok, 'GET', '/api/v1/projects/ns-p/search?' + urlencode({'q': q}))
		self.assertEqual(status, 200, data)
		return sorted(h['host'] for h in data['results'])

	def test_a_negated_port_only_drops_hosts_where_it_is_open(self):
		self.assertEqual(self.names('-port:161'), ['closed161.ns.example.test', 'plain.ns.example.test'])
		self.assertEqual(self.names('port:161'), ['open161.ns.example.test'])

	def test_negated_product_service_and_lists_are_per_port(self):
		self.assertEqual(self.names('-product:snmpd'), ['closed161.ns.example.test', 'plain.ns.example.test'])
		self.assertEqual(self.names('-port:161,443'), ['closed161.ns.example.test'])
		self.assertEqual(self.names('-service:svc'), [])

	def test_a_saved_search_evaluation_uses_the_same_rows(self):
		rows = svc.search_host_rows(self.project, svc.parse_search('-port:161'))
		self.assertEqual(sorted(rows.values_list('name', flat=True)), ['closed161.ns.example.test', 'plain.ns.example.test'])


class CountsOnlySearchTests(NegatedSearchTests):
	def test_page_size_zero_counts_without_walking_heat(self):
		with mock.patch.object(svc, '_heat_facets', side_effect=AssertionError('walked')):
			status, data = call(self.tok, 'GET', '/api/v1/projects/ns-p/search?page_size=0')
		self.assertEqual(status, 200, data)
		self.assertEqual((data['count'], data['results'], data['facets']), (3, [], None))

	def test_facets_none_returns_the_page_without_facets(self):
		with mock.patch.object(svc, '_heat_facets', side_effect=AssertionError('walked')):
			status, data = call(self.tok, 'GET', '/api/v1/projects/ns-p/search?facets=none&page_size=2')
		self.assertEqual((status, data['count'], len(data['results']), data['facets']), (200, 3, 2, None))

	def test_the_default_still_carries_the_heat_facets(self):
		status, data = call(self.tok, 'GET', '/api/v1/projects/ns-p/search')
		self.assertEqual(sum(data['facets']['heat'].values()), 3)

	def test_heat_filter_with_page_size_zero_counts_that_heat(self):
		status, data = call(self.tok, 'GET', '/api/v1/projects/ns-p/search?page_size=0&heat=unscanned')
		self.assertEqual(status, 200, data)
		self.assertEqual(data['results'], [])
		self.assertIsInstance(data['count'], int)


class McpArgumentTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='MA', slug='ma')
		cls.project = Project.objects.create(name='MA', slug='ma-p', insert_date=now, org=org)
		cls.user = User.objects.create_user('wp14mcp', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='admin')
		_, cls.tok = create_token(cls.user, 't')
		domain = Domain.objects.create(name='ma.example.test', project=cls.project, insert_date=now)
		cls.hyg = HygieneFinding.objects.create(domain=domain, host='ma.example.test', check_name='spf_missing', severity=2, title='No SPF',
												assignee=cls.user)

	def test_an_omitted_assignee_is_a_refusal_not_an_unassign(self):
		is_error, text = tool_call(self.tok, 'set_finding_assignee', {'project': 'ma-p', 'kind': 'hygiene', 'id': self.hyg.id})
		self.assertTrue(is_error)
		self.assertIn('assignee', text)
		self.hyg.refresh_from_db()
		self.assertEqual(self.hyg.assignee, self.user)
		self.assertFalse(FindingAuditEvent.objects.exists())
		is_error, _ = tool_call(self.tok, 'set_finding_assignee', {'project': 'ma-p', 'kind': 'hygiene', 'id': self.hyg.id, 'assignee': None})
		self.assertFalse(is_error)  # an explicit null still unassigns
		self.hyg.refresh_from_db()
		self.assertIsNone(self.hyg.assignee)

	def test_an_omitted_self_update_does_not_reset_the_policy(self):
		root = User.objects.create_superuser('wp14root', password='x')
		_, tok = create_token(root, 'r')
		with mock.patch('agentapi.sentinel_settings.set_defaults') as setter:
			is_error, text = tool_call(tok, 'set_sentinel_defaults', {})
		self.assertTrue(is_error)
		setter.assert_not_called()

	def test_a_wrong_type_is_named_and_a_numeric_string_still_works(self):
		is_error, text = tool_call(self.tok, 'get_scan', {'project': 'ma-p', 'scan_id': 'abc'})
		self.assertTrue(is_error)
		self.assertIn('scan_id', text)
		is_error, text = tool_call(self.tok, 'get_scan', {'project': 'ma-p', 'scan_id': True})
		self.assertTrue(is_error)
		is_error, text = tool_call(self.tok, 'list_targets', {'project': 'ma-p', 'page': '1'})
		self.assertFalse(is_error, text)

	def test_a_handler_bug_is_an_internal_error_with_a_traceback_logged(self):
		with mock.patch.object(svc, 'me', side_effect=AttributeError('boom')), self.assertLogs('agentapi.mcp', 'ERROR') as logs:
			status, data = rpc(self.tok, 'tools/call', {'name': 'whoami', 'arguments': {}})
		self.assertEqual(data['error']['code'], -32603)
		self.assertTrue(logs.records[0].exc_info)

	def test_a_batch_does_not_long_poll(self):
		seen = []
		with mock.patch.object(mcp.broker, 'next_task', side_effect=lambda c, a: seen.append(dict(a)) or {'task': None}):
			batch = [{'jsonrpc': '2.0', 'id': i, 'method': 'tools/call', 'params': {'name': 'get_next_task', 'arguments': {'wait': 20}}} for i in range(3)]
			status, data = call(self.tok, 'POST', '/mcp/', batch)
			self.assertEqual(status, 200, data)
			self.assertEqual([a['wait'] for a in seen], [0, 0, 0])
			seen.clear()
			call(self.tok, 'POST', '/mcp/', batch[0])  # a single message may still wait
			self.assertEqual([a['wait'] for a in seen], [20])


class RestErrorTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.user = User.objects.create_user('wp14rest', password='x')
		_, cls.tok = create_token(cls.user, 't')

	def test_a_bug_is_a_json_500_with_a_traceback_logged_not_a_400(self):
		with mock.patch.object(svc, 'list_projects', side_effect=KeyError('boom')), self.assertLogs('agentapi.rest', 'ERROR') as logs:
			status, data = call(self.tok, 'GET', '/api/v1/projects')
		self.assertEqual((status, data), (500, {'error': 'internal error'}))
		self.assertTrue(logs.records[0].exc_info)

	def test_wrong_typed_bodies_are_400s_not_server_errors(self):
		root = User.objects.create_superuser('wp14rest2', password='x')
		org = Org.objects.create(name='RE', slug='re')
		Project.objects.create(name='RE', slug='re-p', insert_date=timezone.now(), org=org)
		_, tok = create_token(root, 't')
		for path, body in (('projects/re-p/targets', {'value': 5}), ('projects/re-p/targets/bulk', {'targets': 5}),
						   ('projects/re-p/targets/bulk', {'text': 5}), ('targets/bulk-org', {'text': 5}),
						   ('projects/re-p/targets/1/scope', {'scope_mode': []})):
			status, data = call(tok, 'POST', '/api/v1/' + path, body)
			self.assertEqual(status, 400, (path, body, data))

	def test_an_id_with_thousands_of_digits_is_a_404(self):
		self.assertEqual(call(self.tok, 'GET', '/api/v1/projects/x/scans/' + '9' * 5000)[0], 404)


class PaginationTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='PG', slug='pg')
		cls.project = Project.objects.create(name='PG', slug='pg-p', insert_date=now, org=org)
		cls.user = User.objects.create_user('wp14page', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='user')
		_, cls.tok = create_token(cls.user, 't')
		for i in range(5):
			Domain.objects.create(name=f't{i}.example.test', project=cls.project, insert_date=now)

	def test_bounds(self):
		url = '/api/v1/projects/pg-p/targets?'
		_, data = call(self.tok, 'GET', url + 'page_size=-1')
		self.assertEqual((data['page_size'], len(data['results'])), (1, 1))
		_, data = call(self.tok, 'GET', url + 'page=100000000000000000000')
		self.assertEqual((data['page'], data['results']), (svc.MAX_PAGE, []))
		_, data = call(self.tok, 'GET', url + 'page_size=0')
		self.assertEqual((data['count'], data['page_size'], data['results']), (5, 0, []))
		self.assertEqual(call(self.tok, 'GET', url + 'page=abc')[0], 400)

	def test_page_args_rejects_an_infinite_json_number(self):
		with self.assertRaises(svc.ApiError):
			svc.page_args({'page': float('inf')})

	def test_the_cve_feed_tier_window_pages_and_never_goes_negative(self):
		from cveFeed.models import CVEEntry
		for i in range(5):
			CVEEntry.objects.create(cve_id=f'CVE-2099-{9000 + i}', published_at=timezone.now())
		with mock.patch('cveFeed.threat.classify_threat_tier', return_value='ice'):
			_, one = call(self.tok, 'GET', '/api/v1/cves?tier=ice&page_size=2&page=1')
			_, two = call(self.tok, 'GET', '/api/v1/cves?tier=ice&page_size=2&page=2')
			_, neg = call(self.tok, 'GET', '/api/v1/cves?tier=ice&page_size=-1')
		self.assertEqual((len(one['results']), len(two['results']), two['page']), (2, 2, 2))
		self.assertNotEqual({r['cve_id'] for r in one['results']}, {r['cve_id'] for r in two['results']})
		self.assertEqual(len(neg['results']), 1)


class AssigneeOrderTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='AO', slug='ao')
		cls.project = Project.objects.create(name='AO', slug='ao-p', insert_date=now, org=org)
		cls.user = User.objects.create_user('wp14assign', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='user')
		_, cls.tok = create_token(cls.user, 't')
		domain = Domain.objects.create(name='ao.example.test', project=cls.project, insert_date=now)
		sub = Subdomain.objects.create(name='www.ao.example.test', target_domain=domain)
		cls.vuln = Vulnerability.objects.create(name='XSS', severity=3, subdomain=sub, target_domain=domain, open_status=True,
												http_url='https://www.ao.example.test/', source='nuclei')

	def test_a_bad_assignee_leaves_the_status_alone(self):
		status, data = call(self.tok, 'PATCH', f'/api/v1/projects/ao-p/findings/vulnerability/{self.vuln.id}',
							{'status': 'fixed', 'assignee': 999999})
		self.assertEqual(status, 400, data)
		self.vuln.refresh_from_db()
		self.assertEqual(self.vuln.remediation_status, 'open')
		self.assertFalse(FindingAuditEvent.objects.exists())

	def test_a_good_pair_applies_both(self):
		status, data = call(self.tok, 'PATCH', f'/api/v1/projects/ao-p/findings/vulnerability/{self.vuln.id}',
							{'status': 'fixed', 'assignee': self.user.id})
		self.assertEqual(status, 200, data)
		self.vuln.refresh_from_db()
		self.assertEqual((self.vuln.remediation_status, self.vuln.assignee), ('fixed', self.user))


class HostProfileExistsTests(TestCase):
	def test_a_profile_needs_a_host_of_the_project(self):
		now = timezone.now()
		org = Org.objects.create(name='HP', slug='hp')
		project = Project.objects.create(name='HP', slug='hp-p', insert_date=now, org=org)
		user = User.objects.create_user('wp14prof', password='x')
		ProjectMembership.objects.create(user=user, project=project, role='user')
		_, tok = create_token(user, 't')
		domain = Domain.objects.create(name='hp.example.test', project=project, insert_date=now)
		Subdomain.objects.create(name='real.hp.example.test', target_domain=domain)
		self.assertEqual(call(tok, 'POST', '/api/v1/projects/hp-p/hosts/made-up.example.test/profile', {'owner': 'x'})[0], 404)
		self.assertFalse(HostProfile.objects.exists())
		self.assertEqual(call(tok, 'POST', '/api/v1/projects/hp-p/hosts/real.hp.example.test/profile', {'owner': 'x'})[0], 200)


class PurgeEvidenceTests(TestCase):
	def test_delete_host_leaves_no_probe_archive_screenshot_assessment_or_notes_behind(self):
		from agentapi import host_manage
		now = timezone.now()
		org = Org.objects.create(name='PE', slug='pe')
		project = Project.objects.create(name='PE', slug='pe-p', insert_date=now, org=org)
		admin = User.objects.create_user('wp14purge', password='x')
		OrgMembership.objects.create(user=admin, org=org, role='admin')
		domain = Domain.objects.create(name='pe.example.test', project=project, insert_date=now)
		keep_name, gone_name = 'keep.pe.example.test', 'gone.pe.example.test'
		for name in (keep_name, gone_name):
			sub = Subdomain.objects.create(name=name, target_domain=domain)
			ProbeObservation.objects.create(project=project, domain=domain, host=name, probe='p', port=443, kind='version', product='x')
			HostArchive.objects.create(project=project, domain=domain, host=name)
			RdpScreenshot.objects.create(project=project, domain=domain, host=name, port=3389, image_path=f'shots/{name}.png')
			HostAssessment.objects.create(project=project, domain=domain, host=name, status='completed')
			vuln = Vulnerability.objects.create(name='V', severity=2, subdomain=sub, target_domain=domain, http_url=f'https://{name}/')
			FindingComment.objects.create(project=project, finding_kind='vulnerability', finding_id=vuln.id, text='note')
			FindingAuditEvent.objects.create(project=project, finding_kind='vulnerability', finding_id=vuln.id, event='status')
			if name == gone_name:
				gone_vuln = vuln.id
		with mock.patch.object(host_manage, '_remove_result_dirs') as remover:
			out = host_manage.delete_host(svc.Ctx(user=admin, token=None), 'pe-p', gone_name)
		for model in (ProbeObservation, HostArchive, RdpScreenshot, HostAssessment):
			self.assertEqual(list(model.objects.values_list('host', flat=True)), [keep_name], model.__name__)
		self.assertFalse(FindingComment.objects.filter(finding_id=gone_vuln).exists())
		self.assertFalse(FindingAuditEvent.objects.filter(finding_id=gone_vuln).exists())
		self.assertEqual(FindingComment.objects.count(), 1)
		self.assertIn(f'shots/{gone_name}.png', remover.call_args[0][0])
		self.assertEqual((out['probes'], out['archives'], out['screenshots'], out['assessments']), (1, 1, 1, 1))


class DocsParityTests(TestCase):
	"""docs/AGENT-API.md names every REST route and every MCP tool, so a new one cannot ship undocumented."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		here = os.path.dirname(os.path.abspath(__file__))
		with open(os.path.join(here, '..', '..', 'docs', 'AGENT-API.md'), encoding='utf-8') as fh:
			cls.doc = fh.read()

	def test_every_mcp_tool_is_named_in_the_doc(self):
		missing = [name for name, *_ in mcp.TOOLS if f'`{name}`' not in self.doc]
		self.assertEqual(missing, [])

	def test_every_rest_route_is_in_the_doc(self):
		"""The tables abbreviate (``.../targets/{id}``, ``GET/POST``), so the check is that the last literal segment of each route path
		appears in the doc as a word."""
		from agentapi import rest
		missing = []
		for method, pattern, _summary, _fn in rest.ROUTES:
			path = re.sub(r'\(\?P<(\w+)>[^)]*\)', '{id}', pattern)
			literal = [seg for seg in path.split('/') if not seg.startswith('{')][-1]
			if not re.search(r'(?<![\w-])' + re.escape(literal) + r'(?![\w-])', self.doc):
				missing.append(f'{method} {path}')
		self.assertEqual(missing, [])


class OpenApiTests(TestCase):
	def test_path_templates_are_declared_and_bootstrap_needs_no_bearer(self):
		from agentapi import rest
		spec = rest.openapi_spec()
		for path, operations in spec['paths'].items():
			for method, op in operations.items():
				declared = {p['name'] for p in op.get('parameters', [])}
				self.assertEqual(set(re.findall(r'\{(\w+)\}', path)), declared, f'{method} {path}')
		self.assertEqual(spec['paths']['/api/v1/sentinels/bootstrap']['post']['security'], [])
		summary = spec['paths']['/api/v1/projects/{slug}/targets/{target_id}/auth-credential']['put']['summary']
		self.assertIn('expires: 30|90|120|never', summary)
		self.assertIn('scope: host|target', summary)
