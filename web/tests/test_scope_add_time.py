"""Scope chosen at add time: "=example.com" (or scope_mode) adds exactly one host, and a target set to scope_mode 'host' never takes,
keeps or scans a name under it. A target added without the mark behaves as before (the regression half of every test)."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.services import normalize_target, parse_org_text, parse_target_list, split_scope_mark
from cveFeed import ctmonitor, discovery, fullscan, hygiene, nuclei_scan, tasks, vhost_scan
from cveFeed.models import DiscoveryEvent
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain, in_target_scope_q
from tests.discovery_fixtures import sentinel_discovery
from tests.test_agentapi import call, tool_call

NOW = timezone.now


# ----------------------------------------------------------------------------- parsing the paste

class MarkerParseTests(SimpleTestCase):
	def test_a_leading_equals_is_kept_in_front_of_the_normalized_host(self):
		self.assertEqual(normalize_target('=example.com'), '=example.com')
		self.assertEqual(normalize_target('=App.Example.com.'), '=app.example.com')
		self.assertEqual(normalize_target('=https://admin:pw@App.Example.com:8443/x?a=b#f'), '=app.example.com')
		self.assertEqual(normalize_target('=*.example.com'), '=example.com')
		self.assertEqual(normalize_target('"=example.com",'), '=example.com')

	def test_addresses_ranges_and_cidrs_keep_the_mark_for_the_server_to_ignore(self):
		self.assertEqual(normalize_target('=203.0.113.7'), '=203.0.113.7')
		self.assertEqual(normalize_target('=203.0.113.7/32'), '=203.0.113.7')
		self.assertEqual(normalize_target('=10.0.0.0/28'), '=10.0.0.0/28')

	def test_the_mark_does_not_collide_with_exclusion_urls_or_query_strings(self):
		self.assertEqual(normalize_target('-example.com'), '-example.com')  # exclude, unchanged
		self.assertEqual(normalize_target('https://example.com/?next=a.com'), 'example.com')  # an '=' inside a URL is not a mark
		self.assertEqual(normalize_target('example.com=x'), 'example.com=x')  # only a leading '=' is a mark; this one stays invalid
		self.assertEqual(normalize_target('=-example.com'), '=-example.com')  # stays invalid, so it is reported, never silently dropped
		self.assertEqual(normalize_target('==example.com'), '==example.com')
		self.assertEqual(normalize_target('-=example.com'), '-=example.com')  # an exclusion pattern the exclude step refuses
		self.assertEqual(normalize_target('='), '=')

	def test_a_paste_keeps_each_marked_entry_as_one_token_in_order(self):
		text = '=a.example, b.example\n-c.example # =commented.example\nhttps://d.example/?q=1\n=a.example\na.example'
		self.assertEqual(parse_target_list(text), ['=a.example', 'b.example', '-c.example', 'd.example', 'a.example'])
		org, groups, errors = parse_org_text('##Acme\n#Web\n=a.example\nb.example')
		self.assertEqual((org, groups, errors), ('Acme', [('Web', ['=a.example', 'b.example'])], []))

	def test_a_mark_standing_alone_belongs_to_the_next_entry_on_its_line(self):
		self.assertEqual(parse_target_list('= spaced.example'), ['=spaced.example'])
		self.assertEqual(parse_target_list('=  "quoted.example", b.example'), ['=quoted.example', 'b.example'])
		self.assertEqual(parse_target_list('a.example =\nb.example'), ['a.example', '=', 'b.example'])  # never carried to the next line
		self.assertEqual(parse_target_list('= -x.example'), ['=-x.example'])  # reported, never an exclusion

	def test_split_scope_mark(self):
		self.assertEqual(split_scope_mark('=a.example'), ('a.example', True))
		self.assertEqual(split_scope_mark('a.example'), ('a.example', False))
		self.assertEqual(split_scope_mark('-a.example'), ('-a.example', False))


class IncludesHostTests(SimpleTestCase):
	def test_an_exact_host_target_holds_only_itself(self):
		d = Domain(name='example.com', scope_mode=Domain.SCOPE_HOST)
		self.assertTrue(d.exact_host_only())
		self.assertTrue(d.includes_host('EXAMPLE.com.'))
		self.assertFalse(d.includes_host('www.example.com'))
		self.assertFalse(d.includes_host('notexample.com'))
		self.assertTrue(d.is_host_scoped())  # bbot runs strict for it, as for any host scoped target

	def test_auto_and_parent_targets_hold_their_tree_as_before(self):
		for mode in (Domain.SCOPE_AUTO, Domain.SCOPE_PARENT):
			d = Domain(name='example.com', scope_mode=mode)
			self.assertFalse(d.exact_host_only())
			self.assertTrue(d.includes_host('a.b.example.com'))
			self.assertFalse(d.includes_host('example.com.evil.net'))
			self.assertFalse(d.includes_host(''))
		tenant = Domain(name='acme.jfrog.com')  # an auto tenant of a shared provider domain keeps its own tree, as before
		self.assertTrue(tenant.is_host_scoped())
		self.assertFalse(tenant.exact_host_only())
		self.assertTrue(tenant.includes_host('api.acme.jfrog.com'))


# ----------------------------------------------------------------------------- creating targets

class AddTimeScopeTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Scoped', slug='scoped')
		cls.org = org
		cls.project = Project.objects.create(name='S', slug='sat', insert_date=NOW(), org=org)
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		cls.user = User.objects.create_user('satuser', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='user')
		_, cls.tok = create_token(cls.user, 't')
		cls.admin = User.objects.create_user('satadmin', password='x')
		OrgMembership.objects.create(user=cls.admin, org=org, role='admin')
		_, cls.tok_admin = create_token(cls.admin, 'a')

	def setUp(self):
		p = mock.patch('cveFeed.ct_queue.queue_lookups')
		self.ct = p.start()
		self.addCleanup(p.stop)

	def scope(self, name):
		return Domain.objects.get(project=self.project, name=name).scope_mode

	def test_a_marked_line_is_exactly_that_host_and_the_rest_are_as_before(self):
		text = '=exact.example\nwide.example\n203.0.113.7\n=203.0.113.8\n=203.0.113.12/30'
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'text': text, 'discover': False})
		self.assertEqual((status, data['invalid']), (201, []))
		self.assertEqual(self.scope('exact.example'), 'host')
		self.assertEqual(self.scope('wide.example'), 'auto')
		for ip in ('203.0.113.7', '203.0.113.8'):
			self.assertEqual(self.scope(ip), 'auto')  # an address has no subdomains: the mark changes nothing
		self.assertEqual(data['scope_mode'], 'auto')
		self.assertEqual(data['scope_modes']['exact.example'], 'host')
		self.assertEqual(data['scope_modes']['wide.example'], 'auto')
		watched = {d for call_ in self.ct.call_args_list for d in call_.args[0]}
		self.assertIn(Domain.objects.get(name='wide.example').id, watched)
		self.assertNotIn(Domain.objects.get(name='exact.example').id, watched)  # exactly one host: crt.sh is not asked

	def test_the_batch_scope_applies_to_unmarked_domains_and_the_mark_overrides_it(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk',
			{'targets': ['=one.example', 'two.example', '203.0.113.9'], 'discover': False, 'scope_mode': 'parent'})
		self.assertEqual(status, 201)
		self.assertEqual((self.scope('one.example'), self.scope('two.example'), self.scope('203.0.113.9')), ('host', 'parent', 'auto'))
		self.assertEqual(data['scope_mode'], 'parent')
		call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'text': 'three.example', 'discover': False, 'scope_mode': 'host'})
		self.assertEqual(self.scope('three.example'), 'host')

	def test_the_same_name_marked_and_unmarked_is_one_target_created_as_exactly_that_host(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'text': 'dup.example\n=dup.example', 'discover': False})
		self.assertEqual((status, data['created'], self.scope('dup.example')), (201, 1, 'host'))

	def test_a_spaced_mark_is_exactly_that_host_and_a_trailing_one_is_reported(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'text': '= spaced.example\nloose.example =', 'discover': False})
		self.assertEqual(status, 201)
		self.assertEqual((self.scope('spaced.example'), self.scope('loose.example')), ('host', 'auto'))
		self.assertEqual([i['value'] for i in data['invalid']], ['='])
		status, data = call(self.tok_admin, 'POST', '/api/v1/targets/bulk-org', {'text': '#S\n= org-spaced.example', 'discover': False})
		self.assertEqual((status, self.scope('org-spaced.example')), (201, 'host'))

	def test_received_counts_what_was_sent(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'targets': ['twice.example', '=twice.example'], 'discover': False})
		self.assertEqual((status, data['received'], data['created']), (201, 2, 1))

	def test_an_existing_target_keeps_its_scope(self):
		Domain.objects.create(name='old.example', project=self.project, insert_date=NOW())
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'text': '=old.example', 'discover': False})
		self.assertEqual((status, data['already_exists'], self.scope('old.example')), (201, ['old.example'], 'auto'))

	def test_a_bad_scope_is_refused_before_anything_is_applied(self):
		Domain.objects.create(name='keep.example', project=self.project, insert_date=NOW())
		for bad in ('everything', 5, ['host']):
			status, data = call(self.tok_admin, 'POST', '/api/v1/projects/sat/targets/bulk',
				{'text': 'new.example\n-keep.example', 'discover': False, 'scope_mode': bad})
			self.assertEqual(status, 400)
			self.assertIn('scope_mode must be auto, host or parent', data['error'])
		self.assertTrue(Domain.objects.filter(name='keep.example').exists())  # the exclusion line was not applied
		self.assertFalse(Domain.objects.filter(name='new.example').exists())

	def test_malformed_marks_are_reported_and_exclusion_still_works(self):
		Domain.objects.create(name='gone.example', project=self.project, insert_date=NOW())
		status, data = call(self.tok_admin, 'POST', '/api/v1/projects/sat/targets/bulk',
			{'text': '==twice.example\n=-mixed.example\n-gone.example\n=fine.example', 'discover': False})
		self.assertEqual(status, 201)
		self.assertEqual(sorted(i['value'] for i in data['invalid']), ['=-mixed.example', '==twice.example'])  # reported as written
		self.assertFalse(Domain.objects.filter(name='gone.example').exists())
		self.assertEqual(self.scope('fine.example'), 'host')

	def test_single_add_takes_the_mark_and_scope_mode_and_echoes_the_stored_scope(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets', {'value': ' =solo.example '})
		self.assertEqual(status, 201)
		self.assertEqual((data['created'][0]['name'], data['created'][0]['scope_mode'], data['created'][0]['host_scoped']),
			('solo.example', 'host', True))
		self.ct.assert_not_called()
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets', {'value': 'owned.example', 'scope_mode': 'parent'})
		self.assertEqual((status, data['created'][0]['scope_mode']), (201, 'parent'))
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets', {'value': 'plain.example'})
		self.assertEqual((status, data['created'][0]['scope_mode']), (201, 'auto'))  # unchanged default
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/sat/targets', {'value': 'x.example', 'scope_mode': 'wide'})[0], 400)
		self.assertFalse(Domain.objects.filter(name='x.example').exists())
		status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets', {'value': '=203.0.113.20', 'scope_mode': 'host'})
		self.assertEqual((status, data['created'][0]['scope_mode']), (201, 'auto'))  # an address: ignored silently

	def test_bulk_by_org_takes_the_mark_and_the_batch_scope(self):
		text = '##Scoped\n#S\n=org-exact.example\norg-wide.example\n#Brand New\n=fresh.example'
		status, data = call(self.tok_admin, 'POST', '/api/v1/targets/bulk-org', {'text': text, 'discover': False, 'scope_mode': 'parent'})
		self.assertEqual(status, 201)
		self.assertEqual(data['scope_mode'], 'parent')
		by_project = {p['project']: p['scope_modes'] for p in data['projects']}
		self.assertEqual(by_project['S'], {'org-exact.example': 'host', 'org-wide.example': 'parent'})
		self.assertEqual(by_project['Brand New'], {'fresh.example': 'host'})
		self.assertEqual(call(self.tok_admin, 'POST', '/api/v1/targets/bulk-org', {'text': '#S\nz.example', 'scope_mode': 'nope'})[0], 400)

	def test_mcp_add_target_and_add_targets_take_the_mark_and_scope_mode(self):
		err, out = tool_call(self.tok, 'add_target', {'project': 'sat', 'value': '=mcp-one.example'})
		self.assertFalse(err)
		self.assertEqual(out['created'][0]['scope_mode'], 'host')
		err, out = tool_call(self.tok, 'add_target', {'project': 'sat', 'value': 'mcp-two.example', 'scope_mode': 'host'})
		self.assertEqual((err, out['created'][0]['scope_mode']), (False, 'host'))
		err, out = tool_call(self.tok, 'add_targets', {'project': 'sat', 'targets': ['=mcp-three.example', 'mcp-four.example'], 'discover': False,
			'scope_mode': 'parent'})
		self.assertFalse(err)
		self.assertEqual(out['scope_modes'], {'mcp-three.example': 'host', 'mcp-four.example': 'parent'})
		err, out = tool_call(self.tok, 'add_targets', {'project': 'sat', 'targets': ['mcp-five.example'], 'scope_mode': 'bogus'})
		self.assertTrue(err)
		self.assertIn('scope_mode must be auto, host or parent', out)

	def test_discovery_of_a_marked_target_is_dispatched_strict(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.tok, 'POST', '/api/v1/projects/sat/targets/bulk', {'text': '=strict.example\nloose.example'})
		self.assertEqual((status, data['discovery_started']), (201, 2))
		seen = {}
		for scan_id, _mode in (c.args for c in queued.call_args_list):
			scan = ScanHistory.objects.get(pk=scan_id)

			def dispatch(project, kind, target, scan, on_partial, **kwargs):
				seen[target['domain']] = target['strict_scope']
				return {'result': {'outcome': 'done', 'partials': 0, 'mode': 'standard'}, 'consumed': 0}
			with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), \
					mock.patch('agentapi.sentinel_stream.dispatch_stream', side_effect=dispatch), \
					mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
				discovery.run_discovery(scan.id)
		self.assertEqual(seen, {'strict.example': True, 'loose.example': False})


# ----------------------------------------------------------------------------- enforcement at every boundary

class EnforcementBase(TestCase):
	def setUp(self):
		org = Org.objects.create(name='E', slug='enf')
		self.project = Project.objects.create(name='E', slug='enf', insert_date=NOW(), org=org)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.exact = Domain.objects.create(name='exact.test', project=self.project, insert_date=NOW(), scope_mode=Domain.SCOPE_HOST)
		self.wide = Domain.objects.create(name='wide.test', project=self.project, insert_date=NOW())
		for p in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('reNgine.tasks.geo_localize.delay'),
				mock.patch('cveFeed.tasks.correlate_cves.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay')):
			p.start()
		self.addCleanup(mock.patch.stopall)

	def scan(self, domain, status=discovery.QUEUED):
		return ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=NOW(), scan_status=status, results_dir='/tmp')

	def names(self, domain, **kw):
		return set(Subdomain.objects.filter(target_domain=domain, **kw).values_list('name', flat=True))

	def host(self, domain, name, address, scan=None, port=443):
		sub = Subdomain.objects.create(target_domain=domain, name=name, scan_history=scan)
		ip = IpAddress.objects.create(address=address, org=domain.org)
		ip.ports.add(Port.objects.create(number=port, protocol='tcp', state='open', service_name='https'))
		sub.ip_addresses.add(ip)
		return sub, ip


def bbot_events(root):
	return [
		{'type': 'SCAN', 'id': 'S', 'data': None, 'data_json': {'name': 'demo'}},
		{'type': 'DNS_NAME', 'id': 'D1', 'data': root, 'host': root, 'module': 'SEED', 'resolved_hosts': ['192.0.2.1'], 'parent': 'S'},
		{'type': 'DNS_NAME', 'id': 'D2', 'data': f'www.{root}', 'host': f'www.{root}', 'module': 'crt', 'resolved_hosts': ['192.0.2.2'], 'parent': 'D1'},
		{'type': 'OPEN_TCP_PORT', 'id': 'P1', 'data': f'www.{root}:443', 'host': f'www.{root}', 'module': 'portscan', 'parent': 'D2'},
		{'type': 'URL', 'id': 'U1', 'data': f'https://www.{root}/', 'host': f'www.{root}', 'module': 'http', 'parent': 'D2', 'tags': ['status-200']},
	]


class DiscoveryIngestionTests(EnforcementBase):
	def test_an_unmarked_target_keeps_its_subdomains_as_before(self):
		scan = self.scan(self.wide)
		with sentinel_discovery(bbot_events('wide.test')):
			discovery.run_discovery(scan.id)
		self.assertEqual(self.names(self.wide), {'wide.test', 'www.wide.test'})
		self.assertTrue(DiscoveryEvent.objects.filter(scan=scan, host='www.wide.test').exists())

	def test_save_subdomain_refuses_a_child_of_an_exact_host_target(self):
		from reNgine.tasks import save_subdomain
		scan = self.scan(self.exact)
		self.assertEqual(save_subdomain('www.exact.test', ctx={'scan_history_id': scan.id, 'domain_id': self.exact.id}), (None, False))
		self.assertEqual(save_subdomain('www.exact.test', ctx={'scan_history_id': scan.id}), (None, False))  # the scan's own target decides
		sub, created = save_subdomain('exact.test', ctx={'scan_history_id': scan.id, 'domain_id': self.exact.id})
		self.assertTrue(created and sub.name == 'exact.test')
		wide = self.scan(self.wide)
		sub, created = save_subdomain('www.wide.test', ctx={'scan_history_id': wide.id, 'domain_id': self.wide.id})
		self.assertTrue(created and sub.name == 'www.wide.test')


class CertificateTransparencyTests(EnforcementBase):
	def test_an_exact_host_target_is_never_looked_up_nor_given_names(self):
		fetch = mock.Mock(return_value={'exact.test', 'www.exact.test'})
		self.assertEqual(ctmonitor.run_ct_watch(self.exact.id, fetch=fetch)['new'], 0)
		fetch.assert_not_called()
		self.assertEqual(self.names(self.exact), set())

	def test_an_unmarked_target_still_gets_new_names(self):
		with mock.patch('cveFeed.tasks.host_pipeline.delay'):
			result = ctmonitor.run_ct_watch(self.wide.id, fetch=lambda name: {'wide.test', 'new.wide.test'})
		self.assertEqual(result['new'], 2)
		self.assertIn('new.wide.test', self.names(self.wide))

	def test_the_sweep_leaves_exact_host_targets_out(self):
		from reNgine import resources
		client = getattr(resources.get_store(), 'r', None)
		if client is not None:
			client.delete('cvengine:sweep:ct-watch')
			self.addCleanup(lambda: client.delete('cvengine:sweep:ct-watch'))
		queued = []
		with mock.patch('cveFeed.ct_queue.queue_lookups', side_effect=lambda ids, **k: queued.extend(ids) or ids), \
				mock.patch('cveFeed.ct_queue.backlog', return_value=0):
			tasks.watch_certificates_all()
		self.assertIn(self.wide.id, queued)
		self.assertNotIn(self.exact.id, queued)


class ReuseAndPipelineTests(EnforcementBase):
	def parent_scan(self):
		parent = Domain.objects.create(name='test', project=self.project, insert_date=NOW())  # a scan that saw both names
		source = self.scan(parent, status=2)
		for name in ('exact.test', 'www.exact.test', 'wide.test', 'www.wide.test'):
			Subdomain.objects.create(scan_history=source, target_domain=parent, name=name)
		return source

	def test_reusing_a_parent_discovery_copies_only_the_exact_host(self):
		source = self.parent_scan()
		exact, wide = self.scan(self.exact), self.scan(self.wide)
		self.assertEqual(discovery.seed_from_scan(exact, source), 1)
		self.assertEqual(self.names(self.exact, scan_history=exact), {'exact.test'})
		self.assertEqual(discovery.seed_from_scan(wide, source), 2)  # unchanged
		self.assertEqual(self.names(self.wide, scan_history=wide), {'wide.test', 'www.wide.test'})

	def test_a_parent_that_only_saw_children_does_not_cover_an_exact_host_target(self):
		from cveFeed.models import ServiceRun
		parent = Domain.objects.create(name='corp.test', project=self.project, insert_date=NOW())
		exact = Domain.objects.create(name='a.corp.test', project=self.project, insert_date=NOW(), scope_mode=Domain.SCOPE_HOST)
		wide = Domain.objects.create(name='b.corp.test', project=self.project, insert_date=NOW())
		source = self.scan(parent, status=2)
		Subdomain.objects.create(scan_history=source, target_domain=parent, name='www.a.corp.test')
		Subdomain.objects.create(scan_history=source, target_domain=parent, name='www.b.corp.test')
		ServiceRun.objects.create(service='bbot', project_id=self.project.id, asset='corp.test', status='done', finished_at=NOW(), scan=source)
		self.assertIsNone(discovery.covering_scan(self.scan(exact)))
		self.assertEqual(discovery.covering_scan(self.scan(wide))[0].id, source.id)  # unchanged
		Subdomain.objects.create(scan_history=source, target_domain=parent, name='a.corp.test')
		self.assertEqual(discovery.covering_scan(self.scan(exact))[0].id, source.id)  # its own name was seen: covered

	def test_the_new_hosts_pipeline_takes_only_the_exact_host(self):
		self.assertEqual(discovery.run_host_pipeline(self.exact.id, ['www.exact.test', 'a.exact.test'])['status'], 'empty')
		self.assertFalse(ScanHistory.objects.filter(domain=self.exact).exists())
		asked = []
		discovery.run_host_pipeline(self.exact.id, ['exact.test', 'www.exact.test'], resolver=lambda names: asked.append(list(names)) or set())
		self.assertEqual(asked, [['exact.test']])
		asked.clear()
		discovery.run_host_pipeline(self.wide.id, ['wide.test', 'www.wide.test'], resolver=lambda names: asked.append(list(names)) or set())
		self.assertEqual(asked, [['wide.test', 'www.wide.test']])

	def test_rescan_hosts_refuses_a_child_of_an_exact_host_target(self):
		user = User.objects.create_user('enfuser', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, tok = create_token(user, 't')
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as queued:
			status, data = call(tok, 'POST', f'/api/v1/projects/enf/targets/{self.exact.id}/rescan-hosts', {'hosts': ['www.exact.test']})
			self.assertEqual(status, 400)
			self.assertIn('scoped to that host only', data['error'])
			status, data = call(tok, 'POST', f'/api/v1/projects/enf/targets/{self.exact.id}/rescan-hosts', {'hosts': ['exact.test', 'www.exact.test']})
			self.assertEqual((status, data['queued'], data['skipped']), (202, 1, 1))
			status, data = call(tok, 'POST', f'/api/v1/projects/enf/targets/{self.wide.id}/rescan-hosts', {'hosts': ['www.wide.test']})
			self.assertEqual((status, data['queued']), (202, 1))
		self.assertEqual([c.args[1] for c in queued.call_args_list], [['exact.test'], ['www.wide.test']])


class ScannerSelectionTests(EnforcementBase):
	"""A row kept from before a target was narrowed to one host is never scanned or swept through it."""

	def setUp(self):
		super().setUp()
		self.done = self.scan(self.exact, status=2)
		self.wide_done = self.scan(self.wide, status=2)
		_, self.exact_ip = self.host(self.exact, 'exact.test', '192.0.2.10', scan=self.done)
		_, self.child_ip = self.host(self.exact, 'old.exact.test', '192.0.2.11', scan=self.done)
		_, self.wide_child_ip = self.host(self.wide, 'www.wide.test', '192.0.2.12', scan=self.wide_done)

	def test_nuclei_targets(self):
		hostnames, ips, _ports = nuclei_scan.scan_targets(self.done)
		self.assertEqual(hostnames, {'exact.test'})
		self.assertNotIn('192.0.2.11', ips)
		self.assertIn('www.wide.test', nuclei_scan.scan_targets(self.wide_done)[0])

	def test_full_port_and_udp_sweeps(self):
		self.assertTrue(fullscan.active_attached(self.exact_ip).exists())
		self.assertFalse(fullscan.active_attached(self.child_ip).exists())
		self.assertTrue(fullscan.active_attached(self.wide_child_ip).exists())

	def test_tls_and_email_hygiene(self):
		with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, **k: list(names)):
			self.assertEqual({h for h, _ in hygiene.tls_targets(self.exact)}, {'exact.test'})
			self.assertIn('www.wide.test', {h for h, _ in hygiene.tls_targets(self.wide)})
		self.assertEqual(hygiene.email_domains(self.exact, lambda n, t: True), ['exact.test'])
		self.assertIn('www.wide.test', hygiene.email_domains(self.wide, lambda n, t: True))

	def test_virtual_host_sweep_addresses(self):
		addresses = vhost_scan.web_addresses(self.project.id)
		self.assertIn('192.0.2.10', addresses)
		self.assertNotIn('192.0.2.11', addresses)
		self.assertIn('192.0.2.12', addresses)

	def test_testssl_audit(self):
		from cveFeed import testssl_scan
		with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, **k: list(names)):
			hosts = {t[0] for t in testssl_scan.targets(self.project.id)}
		self.assertEqual(hosts, {'exact.test', 'www.wide.test'})

	def test_openvas_never_picks_a_name_under_an_exact_host_target(self):
		from cveFeed import openvas_scan
		from startScan.models import Vulnerability
		for sub in Subdomain.objects.filter(name__in=('exact.test', 'old.exact.test', 'www.wide.test')):
			Vulnerability.objects.create(name='XSS', severity=3, subdomain=sub, target_domain=sub.target_domain, open_status=True, source='nuclei')
		self.assertEqual(openvas_scan.hot_names(self.project.id), {'exact.test', 'www.wide.test'})
		_ready, verdicts = openvas_scan.assess(self.project.id, ['old.exact.test', 'www.wide.test'], forced={'old.exact.test'},
			resolve=lambda h, p: '93.184.216.9', blocked=lambda h: False)
		self.assertIn('this host only', verdicts['old.exact.test']['reason'])
		self.assertNotIn('this host only', verdicts['www.wide.test']['reason'] or '')

	def test_openvas_ignores_a_cve_match_on_a_name_under_an_exact_host_target(self):
		from cveFeed import openvas_scan
		from cveFeed.models import CVEEntry, CVEMatch
		cve = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, cvss=9.8, title='nginx bug', published_at=NOW(),
			affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		for sub in Subdomain.objects.filter(name__in=('old.exact.test', 'www.wide.test')):
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9, matched_product='nginx', matched_version='1.18.0', version_in_range=True)
		self.assertEqual(openvas_scan.hot_names(self.project.id), {'www.wide.test'})

	def test_the_thorough_wpscan_pass_skips_a_name_under_an_exact_host_target(self):
		from cveFeed import wpscan_scan
		self.assertIsNone(wpscan_scan._latest_row(self.project.id, 'old.exact.test'))
		self.assertEqual(wpscan_scan._latest_row(self.project.id, 'exact.test').name, 'exact.test')
		self.assertEqual(wpscan_scan._latest_row(self.project.id, 'www.wide.test').name, 'www.wide.test')

	def test_the_web_archive_lookup_ignores_a_name_kept_under_an_exact_host_target(self):
		from cveFeed import archive_urls
		from cveFeed.models import HostArchive
		urls = {'exact.test': ['https://old.exact.test/wp-login.php', 'https://exact.test/wp-login.php'],
			'wide.test': ['https://www.wide.test/wp-login.php']}
		for domain in (self.exact, self.wide):
			with mock.patch.object(archive_urls, 'fetch_urls', side_effect=lambda apex, get=None, exact=False: urls[apex]):
				archive_urls.run_for_domain(domain.id, force=True)
		self.assertEqual(set(HostArchive.objects.values_list('host', flat=True)), {'exact.test', 'www.wide.test'})

	def test_subdirectory_sweep(self):
		from cveFeed import subdir_apps
		names = {e['name'] for e in subdir_apps.web_hosts(self.project.id)}
		self.assertEqual(names, {'exact.test', 'www.wide.test'})

	def test_a_name_another_target_still_holds_stays_in_the_subdirectory_sweep(self):
		"""Regression: the rows kept under the narrowed target are dropped before the rows are collapsed to one per host, so an unmarked
		target holding the same name keeps it in the sweep even when the narrowed target's copy is the richer one."""
		from cveFeed import subdir_apps
		corp = Domain.objects.create(name='corp.test', project=self.project, insert_date=NOW())
		narrow = Domain.objects.create(name='a.corp.test', project=self.project, insert_date=NOW(), scope_mode=Domain.SCOPE_HOST)
		self.host(corp, 'www.a.corp.test', '192.0.2.20', scan=self.scan(corp, status=2))
		rich, ip = self.host(narrow, 'www.a.corp.test', '192.0.2.21', scan=self.scan(narrow, status=2))
		for number in (80, 8443, 8080):
			ip.ports.add(Port.objects.create(number=number, protocol='tcp', state='open', service_name='http'))
		self.assertIn('www.a.corp.test', {e['name'] for e in subdir_apps.web_hosts(self.project.id)})

	def test_scheduled_screenshots_never_plan_a_name_under_an_exact_host_target(self):
		from cveFeed import web_shot
		from cveFeed.models import HostScreenshot
		self.assertEqual(set(web_shot._due_names(self.project.id, 50, NOW())), {'exact.test', 'www.wide.test'})
		old = NOW() - timedelta(days=365)
		for host in ('exact.test', 'old.exact.test', 'www.wide.test'):
			domain = self.wide if host.endswith('wide.test') else self.exact
			HostScreenshot.objects.create(project=self.project, domain=domain, host=host, outcome=web_shot.OK, captured_at=old, attempted_at=old)
		self.assertEqual(set(web_shot._due_names(self.project.id, 50, NOW())), {'exact.test', 'www.wide.test'})  # a stale capture is not refreshed

	def test_scheduled_screenshots_skip_a_name_held_only_under_a_narrowed_target(self):
		from targetApp.models import narrowed_names
		self.assertEqual(narrowed_names(self.project.id, ['OLD.exact.test', 'exact.test', 'www.wide.test', 'unknown.test']), {'old.exact.test'})
		Subdomain.objects.create(target_domain=self.wide, name='old.exact.test')  # another target still holds it: it stays in scope
		self.assertEqual(narrowed_names(self.project.id, ['old.exact.test']), set())
		self.exact.scope_mode = Domain.SCOPE_AUTO
		self.exact.save(update_fields=['scope_mode'])
		self.assertEqual(narrowed_names(self.project.id, ['old.exact.test']), set())  # no exact host target: nothing is narrowed

	def test_the_scope_filter_keeps_rows_without_a_target_and_every_other_target(self):
		orphan = Subdomain.objects.create(name='loose.example')  # no target at all
		kept = set(Subdomain.objects.filter(in_target_scope_q()).values_list('name', flat=True))
		self.assertEqual(kept, {'exact.test', 'www.wide.test', 'loose.example'})
		self.assertTrue(Subdomain.objects.filter(pk=orphan.pk).filter(in_target_scope_q()).exists())


# ----------------------------------------------------------------------------- validation and other work started from a finding

from tests.test_validation import ValidationBase  # noqa: E402


class ValidationScopeTests(ValidationBase):
	"""A finding on a name kept under a target that is now exactly one host is never validated through it; a name an unmarked target also
	holds still is."""

	def setUp(self):
		super().setUp()
		self.domain.scope_mode = Domain.SCOPE_HOST  # v.test, exactly that host
		self.domain.save(update_fields=['scope_mode'])

	def narrowed_match(self):
		return self.match(name='old.v.test')

	def dual_held(self):
		parent = Domain.objects.create(name='test', project=self.project, insert_date=NOW())  # an unmarked target holding the same name
		sub = Subdomain.objects.create(name='old.v.test', target_domain=parent)
		from cveFeed.models import CVEMatch
		return CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0',
			version_in_range=True, source='port', evidence={'ip': '203.0.113.7', 'port': 443})

	def test_the_sweep_does_not_pick_a_finding_on_a_narrowed_name(self):
		from cveFeed import hot_validation, triage
		from cveFeed.models import Triage
		from startScan.models import Vulnerability
		narrowed = self.narrowed_match()
		vuln = Vulnerability.objects.create(name='High', severity=3, source='bbot', subdomain=narrowed.subdomain, target_domain=self.domain)
		own = self.match(name='v.test')
		triage.track(triage.with_cves([narrowed, own]) + [vuln])
		for lane in ('fire', 'smoke'):
			self.assertNotIn('old.v.test', {r.host for r in hot_validation._candidate_rows(lane)}, lane)
		# the KEV match on the target's own name is a fire-lane candidate (under the KEV heat policy no CVE match is a smoke-lane one)
		self.assertEqual({r.host for r in hot_validation._candidate_rows('fire')}, {'v.test'})
		other = self.dual_held()
		triage.track(triage.with_cves([other]))
		picked = {(r.host, r.match_id) for r in hot_validation._candidate_rows('fire')}
		self.assertIn(('old.v.test', other.id), picked)  # the unmarked target's own finding on that name still validates
		self.assertNotIn(('old.v.test', narrowed.id), picked)
		self.assertTrue(Triage.objects.filter(match=narrowed).exists())

	def test_a_queued_or_requested_validation_of_a_narrowed_name_is_refused(self):
		self.narrowed_match()
		stats, calls = self.run_validation([self.rows()[0]])
		self.assertEqual((stats['blocked'], calls), (1, []))
		from cveFeed.models import Triage
		row = Triage.objects.get()
		self.assertEqual(row.validation_status, 'skipped_blocked')
		self.assertIn('this host only', row.validation_steps[0]['summary'])

	def test_a_name_an_unmarked_target_also_holds_still_validates(self):
		self.narrowed_match()
		self.dual_held()
		rows = [r for r in self.rows() if r.host == 'old.v.test']
		stats, calls = self.run_validation(rows)
		self.assertTrue(calls)
		from cveFeed.models import Triage
		self.assertFalse(any('this host only' in (s.get('summary') or '') for r in Triage.objects.all() for s in (r.validation_steps or [])))

	def test_the_workers_skip_a_narrowed_name(self):
		from cveFeed import hot_validation, tasks, triage
		from cveFeed.models import AutomaticValidation, OnDemandValidation, Triage
		from startScan.models import Vulnerability
		narrowed = self.narrowed_match()
		vuln = Vulnerability.objects.create(name='High', severity=3, source='bbot', subdomain=narrowed.subdomain, target_domain=self.domain)
		triage.track(triage.with_cves([narrowed]) + [vuln])
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'), mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
			for row in Triage.objects.all():
				self.assertEqual(hot_validation.enqueue(row, 'fire'), 'queued')  # queued before the target was narrowed, or by a person
		ondemand = OnDemandValidation.objects.get()
		self.assertEqual(tasks.validate_match_on_demand(ondemand.pk)['reason'], 'host_only_scope')
		auto = AutomaticValidation.objects.get()
		self.assertEqual(tasks.automatic_validate_finding(auto.pk)['reason'], 'host_only_scope')
		ondemand.refresh_from_db()
		self.assertEqual(ondemand.status, 'skipped')
		self.assertIn('this host only', ondemand.result['next_action'])

	def test_an_agent_is_not_sent_to_scan_a_narrowed_name(self):
		from agentapi import agent_broker
		from agentapi.services import Ctx
		match = self.narrowed_match()
		with mock.patch('agentapi.agent_tasks.describe', return_value=('network', ['validate:network'])):
			why = agent_broker._queue_one(Ctx(user=User.objects.create_user('ag', password='x')), self.project, match, 'validate', None, None, [])
		self.assertIn('this host only', why)


class NarrowedNamesCostTests(EnforcementBase):
	def test_one_query_without_an_exact_host_target_and_two_with_one(self):
		from targetApp.models import narrowed_names
		Subdomain.objects.create(target_domain=self.exact, name='old.exact.test')
		with self.assertNumQueries(2):
			self.assertEqual(narrowed_names(self.project.id, ['old.exact.test', 'exact.test', 'x.test']), {'old.exact.test'})
		self.exact.scope_mode = Domain.SCOPE_AUTO
		self.exact.save(update_fields=['scope_mode'])
		with self.assertNumQueries(1):
			self.assertEqual(narrowed_names(self.project.id, ['old.exact.test']), set())


class ArchiveQueryTests(EnforcementBase):
	def test_an_exact_host_target_asks_the_archive_for_its_own_urls_only(self):
		from cveFeed import archive_urls
		asked = []

		def get(url, params=None, **kw):
			asked.append(params['url'])
			resp = mock.Mock(status_code=200)
			resp.iter_content.return_value = [b'[]']
			return resp
		archive_urls.run_for_domain(self.exact.id, get=get, force=True)
		archive_urls.run_for_domain(self.wide.id, get=get, force=True)
		self.assertEqual(asked, ['exact.test/*', '*.wide.test'])
