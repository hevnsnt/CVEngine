"""The "All projects" view: the reserved slug ``_all`` lists every project the caller may see, read-only, each row tagged with its own
project. Nothing from a project the caller cannot see may ever appear, and ``_all`` must never be a way to write."""
import json
import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import mcp, rest
from agentapi import services as svc
from agentapi.auth import create_token
from agentapi.services import AllProjects, ApiError, Ctx
from cveFeed.models import (AgentActivity, AssetChange, CVEEntry, CVEMatch, HostProfile, HostState, HygieneFinding, RouteAuth,
                            TlsCertificate)
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for

SHARED = 'www.shared.example.com'  # the same host name in two projects: two hosts, never one


def bearer(token, method, path, body=None):
	c = Client()
	kwargs = dict(content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {token}')
	if method == 'GET':
		r = c.get(path, HTTP_AUTHORIZATION=f'Bearer {token}')
	else:
		r = getattr(c, method.lower())(path, json.dumps(body) if body is not None else None, **kwargs)
	return r.status_code, (r.json() if r.content else None)


class AllProjectsBase(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.now = now
		cls.org1, cls.org2 = Org.objects.create(name='Acme Corp', slug='acme-corp'), Org.objects.create(name='Widgets Inc', slug='widgets-inc')
		cls.pa = Project.objects.create(name='Acme', slug='acme', insert_date=now, org=cls.org1)
		cls.pb = Project.objects.create(name='Widgets', slug='widgets', insert_date=now, org=cls.org1)
		cls.pc = Project.objects.create(name='Gadgets', slug='gadgets', insert_date=now, org=cls.org2)
		cls.engine = EngineType.objects.create(engine_name='fast', yaml_configuration='x')
		cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, cvss=9.8, title='shared bug', published_at=now)
		cls.data = {p.slug: cls.seed(p) for p in (cls.pa, cls.pb, cls.pc)}
		mk = lambda n, **kw: User.objects.create_user(n, password='x', **kw)
		cls.boss = mk('boss', is_superuser=True)
		cls.ann = mk('ann')  # org Acme Corp: Acme and Widgets
		OrgMembership.objects.create(user=cls.ann, org=cls.org1, role='user')
		cls.solo = mk('solo')  # Acme only
		ProjectMembership.objects.create(user=cls.solo, project=cls.pa, role='user')
		cls.auditor = mk('auditor')
		ProjectMembership.objects.create(user=cls.auditor, project=cls.pa, role='audit')
		cls.nobody = mk('nobody')
		# the system-wide activity entry (no project) is visible to every member
		cls.system = AgentActivity.objects.create(kind='feed', message='read the feed', project=None)

	@classmethod
	def seed(cls, project):
		"""One of everything in ``project``; the names say which project a row belongs to."""
		tag, now = project.slug, cls.now
		domain = Domain.objects.create(name=f'{tag}.example.com', project=project, insert_date=now)
		scan = ScanHistory.objects.create(start_scan_date=now, scan_status=2, domain=domain, scan_type=cls.engine)
		shared = Subdomain.objects.create(name=SHARED, target_domain=domain, scan_history=scan, score=50)
		own = Subdomain.objects.create(name=f'only.{tag}.example.com', target_domain=domain, scan_history=scan, score=10)
		ip = IpAddress.objects.create(address={'acme': '203.0.113.1', 'widgets': '203.0.113.2', 'gadgets': '203.0.113.3'}[tag])
		ip.ports.add(Port.objects.create(number=443, service_name='https', state='open', product='nginx', version='1.18.0'))
		shared.ip_addresses.add(ip)
		vuln = Vulnerability.objects.create(name=f'Exposed panel {tag}', severity=3, subdomain=own, target_domain=domain,
			scan_history=scan, http_url=f'https://only.{tag}.example.com/')
		match = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=shared, confidence=0.9, matched_product='nginx', matched_version='1.18.0')
		change = AssetChange.objects.create(project=project, domain=domain, host=SHARED, kind='host_new', scan=scan, detected_at=now)
		activity = AgentActivity.objects.create(kind='scan', message=f'scanned {tag}', project=project)
		cert = TlsCertificate.objects.create(domain=domain, host=SHARED, port=443, not_after=now + timedelta(days=20))
		hygiene = HygieneFinding.objects.create(domain=domain, host=SHARED, check_name='spf_missing', severity=2, title=f'No SPF {tag}')
		route = RouteAuth.objects.create(project=project, domain=domain, host=SHARED, url=f'https://{SHARED}/{tag}', path=f'/{tag}', auth_state='open')
		return {'domain': domain, 'scan': scan, 'shared': shared, 'own': own, 'vuln': vuln, 'match': match, 'change': change,
			'activity': activity, 'cert': cert, 'hygiene': hygiene, 'route': route}

	def ctx(self, user):
		return Ctx(user=user)

	def slugs(self, page):
		return sorted({r['project'] for r in page['results']})


class GetProjectTests(AllProjectsBase):
	def test_all_returns_the_sentinel_with_the_callers_projects(self):
		project, role = svc.get_project(self.ctx(self.ann), '_all')
		self.assertIsInstance(project, AllProjects)
		self.assertEqual((project.slug, project.name), ('_all', 'All projects'))
		self.assertEqual(project.ids, tuple(sorted([self.pa.id, self.pb.id])))
		self.assertEqual(role, 'user')
		self.assertEqual(svc.get_project(self.ctx(self.solo), '_all')[0].ids, (self.pa.id,))
		self.assertEqual(svc.get_project(self.ctx(self.boss), '_all')[0].ids, tuple(sorted([self.pa.id, self.pb.id, self.pc.id])))

	def test_all_is_read_only(self):
		for user in (self.boss, self.ann, self.solo):
			with self.assertRaises(ApiError) as cm:
				svc.get_project(self.ctx(user), '_all', write=True)
			self.assertEqual((cm.exception.status, cm.exception.message), (400, 'pick a project to make changes'))

	def test_a_caller_with_no_access_gets_a_404_not_an_empty_view(self):
		with self.assertRaises(ApiError) as cm:
			svc.get_project(self.ctx(self.nobody), '_all')
		self.assertEqual(cm.exception.status, 404)

	def test_a_real_slug_is_unchanged(self):
		project, role = svc.get_project(self.ctx(self.solo), 'acme')
		self.assertEqual((project, role), (self.pa, 'user'))
		with self.assertRaises(ApiError) as cm:
			svc.get_project(self.ctx(self.solo), 'widgets')
		self.assertEqual(cm.exception.status, 404)

	def test_one_project_only_operations_refuse_all(self):
		with self.assertRaises(ApiError) as cm:
			svc.get_one_project(self.ctx(self.ann), '_all')
		self.assertEqual(cm.exception.status, 400)
		self.assertEqual(svc.get_one_project(self.ctx(self.ann), 'acme')[0], self.pa)


class AllProjectsListTests(AllProjectsBase):
	def test_hosts_span_every_allowed_project_and_are_tagged(self):
		page = svc.list_hosts(self.ctx(self.ann), '_all', {})
		self.assertEqual(self.slugs(page), ['acme', 'widgets'])
		self.assertEqual(page['count'], 4)  # the shared name is two hosts, one per project
		shared = [h for h in page['results'] if h['host'] == SHARED]
		self.assertEqual(sorted(h['project'] for h in shared), ['acme', 'widgets'])
		for h in page['results']:
			self.assertEqual(h['project_name'], {'acme': 'Acme', 'widgets': 'Widgets'}[h['project']])
		# each copy carries its own project's IP, never the other project's
		self.assertEqual({h['project']: h['ips'][0]['address'] for h in shared}, {'acme': '203.0.113.1', 'widgets': '203.0.113.2'})
		self.assertEqual([h['project'] for h in page['results'] if h['host'] == 'only.gadgets.example.com'], [])

	def test_hosts_keep_their_own_projects_asset_info_and_zombie_state(self):
		HostProfile.objects.create(project=self.pa, host=SHARED, owner='Acme team', criticality='high')
		HostState.objects.create(project=self.pa, domain=self.data['acme']['domain'], host=SHARED, zombie_since=self.now)
		page = svc.list_hosts(self.ctx(self.ann), '_all', {})
		by_project = {h['project']: h for h in page['results'] if h['host'] == SHARED}
		self.assertEqual(by_project['acme']['profile']['owner'], 'Acme team')
		self.assertEqual(by_project['widgets']['profile']['owner'], '')
		self.assertTrue(by_project['acme']['zombie'])
		self.assertFalse(by_project['widgets']['zombie'])

	def test_hosts_in_all_mode_are_ordered_by_score_then_name(self):
		page = svc.list_hosts(self.ctx(self.ann), '_all', {})
		scores = [h['score'] for h in page['results']]
		self.assertEqual(scores, sorted(scores, reverse=True))
		self.assertEqual([h['host'] for h in svc.list_hosts(self.ctx(self.ann), '_all', {'sort': 'name'})['results']],
			sorted(h['host'] for h in page['results']))

	def test_search_hosts_all_mode_matches_per_project(self):
		page = svc.search_hosts(self.ctx(self.ann), '_all', {'q': 'www'})
		self.assertEqual(self.slugs(page), ['acme', 'widgets'])
		self.assertEqual(svc.search_hosts(self.ctx(self.ann), '_all', {'q': 'port:443'})['count'], 2)
		self.assertEqual(svc.search_hosts(self.ctx(self.ann), '_all', {'q': 'gadgets'})['count'], 0)
		self.assertEqual(svc.search_hosts(self.ctx(self.boss), '_all', {'q': 'gadgets'})['count'], 1)

	def test_search_state_filters_never_cross_projects(self):
		# only Acme's copy of the shared name is a zombie, and only Acme's route needs a login
		HostState.objects.create(project=self.pa, domain=self.data['acme']['domain'], host=SHARED, zombie_since=self.now)
		RouteAuth.objects.filter(project=self.pa).update(auth_state='login')
		z = svc.search_hosts(self.ctx(self.ann), '_all', {'q': 'zombie:yes'})
		self.assertEqual([(h['project'], h['host']) for h in z['results']], [('acme', SHARED)])
		self.assertEqual(sorted(h['project'] for h in svc.search_hosts(self.ctx(self.ann), '_all', {'q': f'zombie:no host:{SHARED}'})['results']), ['widgets'])
		a = svc.search_hosts(self.ctx(self.ann), '_all', {'q': 'auth:login'})
		self.assertEqual([(h['project'], h['host']) for h in a['results']], [('acme', SHARED)])

	def test_vulnerabilities_matches_changes_activity_are_tagged_and_scoped(self):
		ctx = self.ctx(self.ann)
		vulns = svc.list_vulnerabilities(ctx, '_all', {})
		self.assertEqual(sorted((v['project'], v['name']) for v in vulns['results']), [('acme', 'Exposed panel acme'), ('widgets', 'Exposed panel widgets')])
		matches = svc.list_matches(ctx, '_all', {})
		self.assertEqual(sorted(m['project'] for m in matches['results']), ['acme', 'widgets'])
		self.assertEqual({m['id'] for m in matches['results']}, {self.data['acme']['match'].id, self.data['widgets']['match'].id})
		changes = svc.list_changes(ctx, '_all', {})
		self.assertEqual(sorted(c['project'] for c in changes['results']), ['acme', 'widgets'])
		activity = svc.list_activity(ctx, '_all', {})
		self.assertEqual(sorted(a['message'] for a in activity['results']), ['read the feed', 'scanned acme', 'scanned widgets'])
		tagged = {a['message']: (a['project'], a['project_name']) for a in activity['results']}
		self.assertEqual(tagged['scanned widgets'], ('widgets', 'Widgets'))
		self.assertEqual(tagged['read the feed'], (None, None))  # system-wide: no project to name

	def test_scans_targets_hygiene_certificates_routes_are_tagged_and_scoped(self):
		ctx = self.ctx(self.ann)
		for fn in (svc.list_scans, svc.list_targets, svc.list_hygiene, svc.list_certificates, svc.list_routes):
			page = fn(ctx, '_all', {})
			self.assertEqual(self.slugs(page), ['acme', 'widgets'], fn.__name__)
			self.assertEqual(page['count'], 2, fn.__name__)
			for row in page['results']:
				self.assertEqual(row['project_name'], row['project'].title(), fn.__name__)
		targets = svc.list_targets(ctx, '_all', {})
		self.assertEqual(sorted(t['name'] for t in targets['results']), ['acme.example.com', 'widgets.example.com'])
		self.assertEqual(sorted(t['hosts'] for t in targets['results']), [2, 2])

	def test_filters_still_apply_in_all_mode(self):
		ctx = self.ctx(self.ann)
		self.assertEqual(svc.list_vulnerabilities(ctx, '_all', {'severity': 'critical'})['count'], 0)
		self.assertEqual(svc.list_vulnerabilities(ctx, '_all', {'severity': 'high'})['count'], 2)
		self.assertEqual(svc.list_changes(ctx, '_all', {'kind': 'port_opened'})['count'], 0)
		self.assertEqual(svc.list_hygiene(ctx, '_all', {'check': 'spf'})['count'], 2)
		self.assertEqual(svc.list_certificates(ctx, '_all', {'expiring_within': '30'})['count'], 2)
		self.assertEqual(svc.list_certificates(ctx, '_all', {'expiring_within': '5'})['count'], 0)
		self.assertEqual(svc.list_scans(ctx, '_all', {'status': 'finished'})['count'], 2)
		self.assertEqual(svc.list_matches(ctx, '_all', {'host': 'shared'})['count'], 2)

	def test_paging_counts_all_projects_rows(self):
		page = svc.list_vulnerabilities(self.ctx(self.boss), '_all', {'page_size': '2', 'page': '2'})
		self.assertEqual((page['count'], len(page['results'])), (3, 1))

	def test_every_all_row_names_a_project_the_caller_can_see(self):
		for user, allowed in ((self.ann, {'acme', 'widgets'}), (self.solo, {'acme'}), (self.auditor, {'acme'}), (self.boss, {'acme', 'widgets', 'gadgets'})):
			ctx = self.ctx(user)
			for fn in (svc.list_hosts, svc.search_hosts, svc.list_vulnerabilities, svc.list_matches, svc.list_changes, svc.list_scans,
					svc.list_targets, svc.list_hygiene, svc.list_certificates, svc.list_routes):
				page = fn(ctx, '_all', {})
				self.assertTrue(page['results'], (user.username, fn.__name__))
				self.assertLessEqual({r['project'] for r in page['results']}, allowed, (user.username, fn.__name__))
			for a in svc.list_activity(ctx, '_all', {})['results']:
				self.assertIn(a['project'], allowed | {None})


class SingleProjectMemberTests(AllProjectsBase):
	"""A member of only project A sees only A under ``_all``: over the service layer, the REST API and the MCP tools."""

	LISTS = ('hosts', 'search', 'vulnerabilities', 'matches', 'changes', 'activity', 'scans', 'targets', 'hygiene', 'certificates', 'routes')

	def test_services_return_only_their_project(self):
		ctx = self.ctx(self.solo)
		for fn in (svc.list_hosts, svc.search_hosts, svc.list_vulnerabilities, svc.list_matches, svc.list_changes, svc.list_scans,
				svc.list_targets, svc.list_hygiene, svc.list_certificates, svc.list_routes):
			page = fn(ctx, '_all', {})
			self.assertEqual({r['project'] for r in page['results']}, {'acme'}, fn.__name__)
		self.assertEqual({a['project'] for a in svc.list_activity(ctx, '_all', {})['results']}, {'acme', None})

	def test_rest_returns_only_their_project(self):
		_, token = create_token(self.solo, 'solo')
		for name in self.LISTS:
			status, body = bearer(token, 'GET', f'/api/v1/projects/_all/{name}')
			self.assertEqual(status, 200, name)
			self.assertEqual({r['project'] for r in body['results']} - {None}, {'acme'}, name)
			self.assertNotIn('widgets', json.dumps(body), name)
			self.assertNotIn('gadgets', json.dumps(body), name)

	def test_a_session_user_gets_the_same_through_the_api(self):
		c = client_for(self.solo)
		body = c.get('/api/v1/projects/_all/hosts').json()
		self.assertEqual({h['project'] for h in body['results']}, {'acme'})
		self.assertEqual(c.get('/api/v1/projects/_all/vulnerabilities').json()['count'], 1)

	def test_mcp_tools_return_only_their_project(self):
		_, token = create_token(self.solo, 'solo')
		for tool in ('list_hosts', 'list_vulnerabilities', 'list_cve_matches', 'list_changes', 'list_scans', 'list_targets'):
			status, body = bearer(token, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
				'params': {'name': tool, 'arguments': {'project': '_all'}}})
			self.assertEqual(status, 200)
			self.assertFalse(body['result']['isError'], tool)
			text = body['result']['content'][0]['text']
			rows = json.loads(text)['results']
			self.assertTrue(rows, tool)
			self.assertEqual({r['project'] for r in rows}, {'acme'}, tool)

	def test_the_other_projects_stay_invisible_by_slug(self):
		_, token = create_token(self.solo, 'solo')
		self.assertEqual(bearer(token, 'GET', '/api/v1/projects/widgets/hosts')[0], 404)
		self.assertEqual(bearer(token, 'GET', '/api/v1/projects/gadgets/vulnerabilities')[0], 404)

	def test_a_caller_with_no_access_gets_404_over_rest(self):
		_, token = create_token(self.nobody, 'nobody')
		self.assertEqual(bearer(token, 'GET', '/api/v1/projects/_all/hosts')[0], 404)

	def test_the_data_layer_scope_is_a_second_guard(self):
		"""Even if the explicit filter were widened, the tenancy-scoped managers keep another project's rows out of the request."""
		from tenancy import scope
		tokens = scope.set_scope({self.pa.id}, self.solo)
		try:
			self.assertEqual({v.target_domain.project_id for v in Vulnerability.objects.all()}, {self.pa.id})
			self.assertEqual(Vulnerability.objects.filter(target_domain__project_id__in=[self.pa.id, self.pb.id]).count(), 1)
		finally:
			scope.reset_scope(tokens)


class AllProjectsReadOnlyTests(AllProjectsBase):
	"""``_all`` is never a way to change anything, and every per-item route stays per project."""

	def test_every_write_route_refuses_all(self):
		_, token = create_token(self.boss, 'boss')  # even an App Admin
		writes = [(m, p) for m, p, *_ in rest.ROUTES if m in ('POST', 'PUT', 'PATCH', 'DELETE') and 'slug' in p]
		self.assertGreater(len(writes), 15)
		for method, pattern in writes:
			path = re.sub(r'\(\?P<(\w+)>[^)]*\)', lambda m: {'slug': '_all', 'host': 'x.example.com', 'service': 'shodan', 'kind': 'match'}.get(m.group(1), '1'), pattern)
			status, body = bearer(token, method, f'/api/v1/{path}', {'value': 'x.example.com', 'status': 'open', 'scope_mode': 'host', 'discovery_mode': 'standard', 'target_id': 1})
			self.assertEqual(status, 400, (method, path, body))
			self.assertEqual(body['error'], 'pick a project to make changes', (method, path))

	def test_no_route_fails_with_a_server_error_for_all(self):
		_, token = create_token(self.boss, 'boss')
		reads = [p for m, p, *_ in rest.ROUTES if m == 'GET' and 'slug' in p]
		for pattern in reads:
			path = re.sub(r'\(\?P<(\w+)>[^)]*\)', lambda m: {'slug': '_all', 'kind': 'match'}.get(m.group(1), '1'), pattern)
			status, body = bearer(token, 'GET', f'/api/v1/{path}')
			self.assertIn(status, (200, 400), (path, status, body))

	def test_per_item_and_secret_reads_ask_for_a_project(self):
		_, token = create_token(self.boss, 'boss')
		for path in ('targets/1', 'scans/1', 'scans/1/subdomains', 'scans/1/activity', 'findings/match/1', 'triage', 'work', 'api-keys', 'exclusions'):
			status, body = bearer(token, 'GET', f'/api/v1/projects/_all/{path}')
			self.assertEqual(status, 400, path)
			self.assertEqual(body['error'], 'pick a project: this works on one project at a time', path)

	def test_a_real_slug_still_authorizes_each_write_by_role(self):
		_, token = create_token(self.auditor, 'auditor')
		status, body = bearer(token, 'POST', '/api/v1/projects/acme/targets', {'value': 'new.example.com'})
		self.assertEqual(status, 403)  # an audit role, on the real project
		status, body = bearer(token, 'POST', '/api/v1/projects/_all/targets', {'value': 'new.example.com'})
		self.assertEqual(status, 400)
		self.assertFalse(Domain.objects.filter(name='new.example.com').exists())

	def test_mcp_write_tools_refuse_all(self):
		_, token = create_token(self.boss, 'boss')
		for tool, args in (('add_target', {'value': 'x.example.com'}), ('delete_targets', {'ids': [1]}), ('stop_all_scans', {}),
				('update_remediation_status', {'match_id': 1, 'status': 'fixed'}), ('delete_host', {'host': 'x.example.com'}),
				('exclude_host', {'host': 'x.example.com'}), ('run_hygiene_checks', {})):
			status, body = bearer(token, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
				'params': {'name': tool, 'arguments': {'project': '_all', **args}}})
			self.assertEqual(status, 200)
			self.assertTrue(body['result']['isError'], tool)
			self.assertIn('pick a project', body['result']['content'][0]['text'], tool)

	def test_remediation_status_is_untouched_by_an_all_write_attempt(self):
		match = self.data['acme']['match']
		before = match.remediation_status
		_, token = create_token(self.boss, 'boss')
		self.assertEqual(bearer(token, 'PATCH', f'/api/v1/projects/_all/matches/{match.id}', {'status': 'fixed'})[0], 400)
		match.refresh_from_db()
		self.assertEqual(match.remediation_status, before)


class AllProjectsAddTargetsTests(AllProjectsBase):
	"""Adding targets from the all-projects view goes through the #Project format, one real project per list, each checked on its own."""

	def test_bulk_by_org_adds_to_the_named_project_even_when_the_current_one_is_all(self):
		member = User.objects.create_user('acmemember', password='x')
		OrgMembership.objects.create(user=member, org=self.org1, role='user')
		result = svc.add_targets_by_org(self.ctx(member), '##Acme Corp\n#Widgets\nnew.widgets.example.com\n', discover=False, current_project='_all')
		self.assertEqual(result['projects'][0]['slug'], 'widgets')
		self.assertEqual(result['created'], 1)
		self.assertTrue(Domain.objects.filter(name='new.widgets.example.com', project=self.pb).exists())

	def test_a_plain_list_has_no_project_in_all(self):
		with self.assertRaises(ApiError) as cm:
			svc.add_targets(self.ctx(self.boss), '_all', ['new.example.com'], discover=False)
		self.assertEqual((cm.exception.status, cm.exception.message), (400, 'pick a project to make changes'))
		self.assertFalse(Domain.objects.filter(name='new.example.com').exists())


class AllProjectsQueryTests(AllProjectsBase):
	"""The project is joined in, not fetched per row: more rows cost no more queries."""

	def count_queries(self, fn, *args):
		with CaptureQueriesContext(connection) as q:
			fn(*args)
		return len(q)

	def test_no_query_per_row(self):
		ctx = self.ctx(self.boss)
		lists = (svc.list_vulnerabilities, svc.list_matches, svc.list_changes, svc.list_scans, svc.list_targets, svc.list_hygiene,
			svc.list_certificates, svc.list_routes, svc.list_activity, svc.list_hosts, svc.search_hosts)
		small = {fn.__name__: self.count_queries(fn, ctx, '_all', {}) for fn in lists}
		for project in (self.pa, self.pb, self.pc):
			domain = self.data[project.slug]['domain']
			for i in range(6):
				sub = Subdomain.objects.create(name=f'x{i}.{project.slug}.example.com', target_domain=domain, scan_history=self.data[project.slug]['scan'])
				Vulnerability.objects.create(name=f'v{i}', severity=2, subdomain=sub, target_domain=domain, http_url='https://x/')
				CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id=f'CVE-2098-{project.id}{i}', cvss=5, published_at=self.now),
					subdomain=sub, confidence=0.5)
				AssetChange.objects.create(project=project, domain=domain, host=sub.name, kind='host_new', detected_at=self.now)
				AgentActivity.objects.create(kind='scan', message=f'm{i}', project=project)
				HygieneFinding.objects.create(domain=domain, host=sub.name, check_name='spf_missing', severity=1, title='t')
				TlsCertificate.objects.create(domain=domain, host=sub.name, port=443)
				RouteAuth.objects.create(project=project, domain=domain, host=sub.name, url=f'https://{sub.name}/', path='/', auth_state='open')
				Domain.objects.create(name=f't{i}.{project.slug}.example.com', project=project, insert_date=self.now)
				ScanHistory.objects.create(start_scan_date=self.now, scan_status=0, domain=domain, scan_type=self.engine)  # failed: the hosts stay on the finished scan
		for fn in lists:
			self.assertEqual(self.count_queries(fn, ctx, '_all', {}), small[fn.__name__], fn.__name__)


class AllProjectsPageTests(AllProjectsBase):
	SECTIONS = ('hosts', 'vulns', 'matches', 'changes', 'activity', 'hygiene', 'scans', 'targets')

	def test_section_pages_render_for_a_member(self):
		c = client_for(self.ann)
		for section in self.SECTIONS:
			r = c.get(f'/cve/_all/{section}/')
			self.assertEqual(r.status_code, 200, section)
			html = r.content.decode()
			self.assertIn('All projects', html)
			self.assertIn('data-slug="_all"', html)

	def test_the_switcher_offers_all_projects_selected(self):
		html = client_for(self.ann).get('/cve/_all/vulns/').content.decode()
		self.assertEqual(len(re.findall(r'<option value="_all" selected>All projects</option>', html)), 2)  # sidebar and mobile sheet
		self.assertNotIn('<option value="acme" selected', html)
		self.assertIn('<title>CVEngine · Findings · All projects</title>', html)
		self.assertIn('/cve/_all/hosts/', html)

	def test_a_real_project_page_keeps_its_project_selected_and_offers_all(self):
		html = client_for(self.ann).get('/cve/acme/vulns/').content.decode()
		self.assertIn('<option value="_all" >All projects</option>', html)
		self.assertIn('<option value="acme" selected>Acme</option>', html)

	def test_a_user_with_one_project_does_not_get_the_option(self):
		c = client_for(self.solo)
		html = c.get('/cve/acme/vulns/').content.decode()
		self.assertNotIn('value="_all"', html)
		self.assertNotIn('All projects', html)
		self.assertEqual(c.get('/cve/_all/vulns/').status_code, 200)  # the view itself still works: it is just their one project
		self.assertNotIn('value="_all"', c.get('/cve/_all/vulns/').content.decode())

	def test_a_user_with_no_access_gets_a_404(self):
		self.assertEqual(client_for(self.nobody).get('/cve/_all/vulns/').status_code, 404)

	def test_per_item_routes_stay_project_specific(self):
		c = client_for(self.boss)
		scan = self.data['acme']['scan']
		self.assertEqual(c.get(f'/cve/_all/scans/{scan.id}/').status_code, 404)
		self.assertEqual(c.get(f'/cve/acme/scans/{scan.id}/').status_code, 200)
		self.assertEqual(c.get(f'/cve/_all/hosts/{self.data["acme"]["shared"].id}/screenshot/').status_code, 404)

	def test_api_keys_moved_to_settings(self):
		html = client_for(self.ann).get('/cve/_all/hosts/').content.decode()
		self.assertNotIn('/cve/_all/keys/', html)  # the side bar page is gone: keys live in Settings > API keys and Administration
		self.assertNotEqual(client_for(self.ann).get('/cve/_all/keys/').status_code, 200)
		root = User.objects.create_superuser('keys-root', password='x')
		page = client_for(root).get('/cve/acme/keys/')
		self.assertEqual((page.status_code, page['Location']), (302, '/cve/settings/#keys'))
		_, token = create_token(self.ann, 'key-scope')
		self.assertEqual(bearer(token, 'PUT', '/api/v1/projects/_all/api-keys/shodan', {'api_key': 'x'})[0], 400)

	def test_stats_accept_the_all_marker(self):
		c = client_for(self.ann)
		self.assertEqual(c.get('/cve/api/stats?project=_all').status_code, 200)
		self.assertEqual(c.get('/cve/api/stats?project=nope').status_code, 404)


class ReservedSlugTests(AllProjectsBase):
	def test_a_project_cannot_be_created_with_the_slug(self):
		with self.assertRaises(ValueError):
			Project.objects.create(name='Sneaky', slug='_all', insert_date=self.now, org=self.org1)
		self.assertFalse(Project.objects.filter(slug='_all').exists())

	def test_the_model_reports_it_in_validation(self):
		from django.core.exceptions import ValidationError
		with self.assertRaises(ValidationError):
			Project(name='Sneaky', slug='_all', insert_date=self.now).full_clean()

	def test_bulk_add_refuses_a_project_named_all(self):
		org_admin = User.objects.create_user('orgadmin', password='x')
		OrgMembership.objects.create(user=org_admin, org=self.org1, role='admin')
		for header in ('_all', '_ALL'):
			result = svc.add_targets_by_org(self.ctx(org_admin), f'##Acme Corp\n#{header}\nnew.example.com\n', discover=False, current_project='acme')
			self.assertIn('reserved', result['projects'][0]['error'])
			self.assertEqual(result['projects_created'], 0)
		self.assertFalse(Project.objects.filter(slug__in=('_all', 'all')).exists())
		self.assertFalse(Domain.objects.filter(name='new.example.com').exists())

	def test_the_admin_api_refuses_it(self):
		c = client_for(self.boss)
		r = c.post('/cve/api/admin/projects', json.dumps({'org_id': self.org1.id, 'name': '_all'}), content_type='application/json')
		self.assertEqual(r.status_code, 400)
		self.assertIn('reserved', r.json()['error'])
		self.assertFalse(Project.objects.filter(slug__in=('_all', 'all')).exists())

	def test_an_ordinary_name_still_works(self):
		c = client_for(self.boss)
		r = c.post('/cve/api/admin/projects', json.dumps({'org_id': self.org1.id, 'name': 'All hands'}), content_type='application/json')
		self.assertEqual(r.status_code, 201)
		self.assertEqual(r.json()['slug'], 'all-hands')


class OrgAllProjectsTests(AllProjectsBase):
	"""All projects narrowed to one organization: chosen in the switcher (?org=), remembered by the browser session for the pages and
	polls that do not name it, and named per call by a token caller. An unknown organization never empties the view."""

	def hosts(self, c, qs=''):
		return {h['project'] for h in c.get('/api/v1/projects/_all/hosts' + qs).json()['results']}

	def test_choosing_an_organization_then_all_projects_shows_only_its_projects(self):
		c = client_for(self.boss)  # sees every project: Acme and Widgets in Acme Corp, Gadgets in Widgets Inc
		html = c.get('/cve/_all/hosts/?org=acme-corp').content.decode()
		self.assertIn('<option value="acme-corp" data-projects="acme widgets " selected>', html)
		self.assertIn('All projects in Acme Corp · 2 you can access', html)
		self.assertNotIn('<option value="gadgets"', html)  # the project list is that organization's
		self.assertEqual(self.hosts(c), {'acme', 'widgets'})  # the page's own calls name no organization: the session does
		self.assertEqual(c.get('/cve/api/stats?project=_all').json()['targets'], 2)
		self.assertIn('value="acme-corp" data-projects="acme widgets " selected', c.get('/cve/about/').content.decode())
		html = c.get('/cve/_all/hosts/?org=').content.decode()  # All organizations again
		self.assertIn('<option value="" selected>All organizations</option>', html)
		self.assertEqual(self.hosts(c), {'acme', 'widgets', 'gadgets'})
		self.assertEqual(c.get('/cve/api/stats?project=_all').json()['targets'], 3)

	def test_an_explicit_org_wins_and_an_unknown_one_is_ignored(self):
		c = client_for(self.boss)
		self.assertEqual(self.hosts(c, '?org=widgets-inc'), {'gadgets'})
		self.assertEqual(self.hosts(c, '?org=no-such-org'), {'acme', 'widgets', 'gadgets'})
		_, token = create_token(self.boss, 'boss')
		status, body = bearer(token, 'GET', '/api/v1/projects/_all/hosts?org=acme-corp')
		self.assertEqual((status, {h['project'] for h in body['results']}), (200, {'acme', 'widgets'}))

	def test_it_never_widens_what_the_caller_may_see(self):
		c = client_for(self.ann)  # Acme Corp only
		self.assertEqual(self.hosts(c, '?org=widgets-inc'), {'acme', 'widgets'})
