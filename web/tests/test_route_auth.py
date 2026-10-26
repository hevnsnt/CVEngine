import datetime
import http.server
import json
import threading
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import discovery, route_auth as ra
from cveFeed.models import AgentActivity, AssetChange, RouteAuth, ServiceRun
from dashboard.models import Org, Project, ProjectMembership
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, rpc
from tests.test_perf_hostpipeline import _stages


def probe(status=200, **kw):
	return {'url': kw.pop('url', 'https://www.rt.test/'), 'status': status, 'location': '', 'www_authenticate': '', 'cookies': [],
		'content_type': 'text/html', 'body': '', 'title': '', **kw}


class ClassifyTests(SimpleTestCase):
	def state(self, **kw):
		return ra.classify(probe(**kw))

	def test_401_basic_needs_a_session_and_negotiate_is_sso(self):
		state, evidence = self.state(status=401, www_authenticate='Basic realm="x"')
		self.assertEqual((state, evidence['www_authenticate']), ('session_required', 'Basic'))
		state, evidence = self.state(status=401, www_authenticate='Negotiate')
		self.assertEqual((state, evidence['provider']), ('sso', 'Windows integrated'))
		self.assertEqual(self.state(status=401, www_authenticate='NTLM')[0], 'sso')

	def test_403_needs_a_session(self):
		state, evidence = self.state(status=403)
		self.assertEqual((state, evidence['reason']), ('session_required', 'forbidden'))

	def test_redirects(self):
		state, evidence = self.state(status=302, location='https://login.microsoftonline.com/common/oauth2/authorize?x=1')
		self.assertEqual((state, evidence['provider']), ('sso', 'Entra ID'))
		state, evidence = self.state(status=302, location='/login?next=/admin', url='https://www.rt.test/admin')
		self.assertEqual((state, evidence['redirect_to']), ('session_required', '/login?next=/admin'))
		state, evidence = self.state(status=301, location='https://www.rt.test/', url='http://www.rt.test/')
		self.assertEqual((state, evidence['redirect_to']), ('redirect', 'https://www.rt.test/'))
		self.assertEqual(self.state(status=302, location='https://acme.okta.com/app/x')[1]['provider'], 'Okta')
		self.assertEqual(self.state(status=302, location='https://app.example.com/adfs/ls/?wa=wsignin1.0')[0], 'sso')
		self.assertEqual(self.state(status=302, location='https://github.com/login/oauth/authorize')[1]['provider'], 'GitHub')
		self.assertEqual(self.state(status=302, location='https://github.com/somewhere')[0], 'redirect')

	def test_bodies(self):
		self.assertEqual(self.state(body='<form><input type="password" name="p"></form>')[0], 'login')
		self.assertEqual(self.state(title='Sign in to Acme')[0], 'login')
		state, evidence = self.state(body='<div id="okta-sign-in"></div><input type=password>')
		self.assertEqual((state, evidence['provider']), ('sso', 'Okta'))
		self.assertEqual(self.state(body='<html><h1>Welcome</h1></html>', title='Home')[0], 'open')
		self.assertEqual(self.state(status=405)[0], 'open')
		self.assertEqual(self.state(body='<meta http-equiv="refresh" content="0; url=/login">')[0], 'session_required')
		self.assertEqual(self.state(body='<meta http-equiv="refresh" content="0; url=/home">')[0], 'open')

	def test_not_found_and_errors(self):
		self.assertEqual(self.state(status=404)[0], 'not_found')
		self.assertEqual(self.state(status=410)[0], 'not_found')
		self.assertEqual(self.state(status=503)[0], 'error')

	def test_evidence_carries_markers_bytes_and_cookie_names_never_the_body(self):
		_, evidence = self.state(body='<input type="password">' + 'x' * 100, cookies=['sid', 'csrf'], bytes=123)
		self.assertEqual((evidence['markers'], evidence['bytes'], evidence['cookies']), (['password_input'], 123, ['csrf', 'sid']))
		self.assertNotIn('xxxx', json.dumps(evidence))


def sub_with_ports(name='www.rt.test', ports=(), http_url=None, ip='203.0.113.5'):
	"""A stand-in for a prefetched Subdomain."""
	port_objs = [SimpleNamespace(number=n, service_name=s, product=p, state='open') for n, s, p in ports]
	ips = [SimpleNamespace(address=ip, ports=SimpleNamespace(all=lambda: port_objs))]
	return SimpleNamespace(name=name, http_url=http_url, ip_addresses=SimpleNamespace(all=lambda: ips))


class PlanTests(SimpleTestCase):
	def test_https_for_443_and_8443_http_for_80_and_8080_using_the_hostname(self):
		sub = sub_with_ports(ports=[(443, 'https', ''), (80, 'http', '')])
		self.assertEqual(ra.web_bases(sub), ['https://www.rt.test', 'http://www.rt.test'])
		sub = sub_with_ports(ports=[(8443, 'ssl/http', ''), (8080, 'http-proxy', '')])
		self.assertEqual(ra.web_bases(sub), ['http://www.rt.test:8080', 'https://www.rt.test:8443'])
		self.assertEqual(ra.web_bases(sub_with_ports(ports=[(9000, 'unknown', 'Apache httpd')])), ['http://www.rt.test:9000'])

	def test_bases_are_capped_at_two_preferring_443_then_80(self):
		sub = sub_with_ports(ports=[(8080, 'http', ''), (80, 'http', ''), (443, 'https', ''), (3000, 'http', '')])
		self.assertEqual(ra.web_bases(sub), ['https://www.rt.test', 'http://www.rt.test'])

	def test_http_url_counts_and_a_host_with_nothing_web_yields_nothing(self):
		self.assertEqual(ra.web_bases(sub_with_ports(http_url='https://www.rt.test:9443/app')), ['https://www.rt.test:9443'])
		self.assertEqual(ra.web_bases(sub_with_ports(ports=[(22, 'ssh', 'OpenSSH'), (3306, 'mysql', 'MySQL')])), [])

	def test_route_paths_drop_static_assets_and_queries_and_are_capped(self):
		urls = ['https://h/app.js', 'https://h/static/logo.png?x=1', 'https://h/reports/q4?year=2026', 'https://h/reports/q4',
			'https://h/' + 'a' * 300] + [f'https://h/p{i}' for i in range(30)]
		paths = ra.route_paths(urls)
		self.assertEqual(paths[:len(ra.COMMON_PATHS)], list(ra.COMMON_PATHS))
		extra = paths[len(ra.COMMON_PATHS):]
		self.assertEqual(extra[0], '/reports/q4')
		self.assertEqual(len(extra), ra.MAX_ENDPOINT_PATHS)
		self.assertNotIn('/app.js', extra)
		self.assertFalse(any('?' in p or len(p) > 200 for p in extra))

	def test_host_urls_are_capped_with_the_least_common_paths_dropped_first(self):
		urls = ra.host_urls(['https://h', 'http://h'], ['/', '/a', '/b'], limit=3)
		self.assertEqual(urls, ['https://h/', 'http://h/', 'https://h/a'])


class Handler(http.server.BaseHTTPRequestHandler):
	seen = []

	def do_GET(self):
		Handler.seen.append((self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
		if self.path == '/redir':
			self.send_response(302)
			self.send_header('Location', '/final')
			self.send_header('Set-Cookie', 'sid=abc; Path=/')
			self.end_headers()
			return
		body = b'<html><title>Big Page</title>' + b'A' * (70 * 1024) + b'</html>'
		self.send_response(200)
		self.send_header('Content-Type', 'text/html; charset=utf-8')
		self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		try:
			self.wfile.write(body)
		except (BrokenPipeError, ConnectionResetError):
			pass

	def log_message(self, *args):
		pass


class ProbeTests(SimpleTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
		cls.port = cls.server.server_address[1]
		threading.Thread(target=cls.server.serve_forever, daemon=True).start()

	@classmethod
	def tearDownClass(cls):
		cls.server.shutdown()
		cls.server.server_close()
		super().tearDownClass()

	def setUp(self):
		Handler.seen.clear()
		# This fixture deliberately connects to its own loopback server. Production
		# policy rejection is exercised separately in test_pinned_transport.
		policy = mock.patch('cveFeed.pinned_transport.is_scannable_ip', return_value=True)
		policy.start()
		self.addCleanup(policy.stop)

	def test_reads_at_most_the_sample_cap_and_sends_no_cookies_or_credentials(self):
		result = ra.probe_url(f'http://127.0.0.1:{self.port}/big')
		self.assertEqual(result['status'], 200)
		self.assertLessEqual(result['bytes'], ra.ROUTE_SAMPLE_BYTES)
		self.assertLessEqual(len(result['body']), ra.ROUTE_SAMPLE_BYTES)
		self.assertEqual(result['title'], 'Big Page')
		self.assertEqual(Handler.seen, [('/big', None, None)])

	def test_never_follows_a_redirect(self):
		result = ra.probe_url(f'http://127.0.0.1:{self.port}/redir')
		self.assertEqual((result['status'], result['location'], result['cookies']), (302, '/final', ['sid']))
		self.assertEqual([p for p, _, _ in Handler.seen], ['/redir'])

	def test_rejects_non_http_urls_and_userinfo_before_resolution(self):
		with mock.patch('cveFeed.pinned_transport.resolve') as resolve:
			for url in ('file:///tmp/dummy', 'ftp://example.test/', 'http://u:p@example.test/', 'http://example.test/\n'):
				with self.assertRaises(ValueError):
					ra.probe_url(url)
			resolve.assert_not_called()

	def test_pinned_request_preserves_host_headers_schema_and_read_limit(self):
		from email.message import Message
		response = mock.Mock(status=200)
		response.headers = Message()
		response.headers['Content-Type'] = 'text/html; charset=utf-8'
		response.headers['Set-Cookie'] = 'sid=one; Path=/'
		response.getheader.side_effect = lambda name, default=None: response.headers.get(name, default)
		response.read.return_value = b'<title>Pinned</title>'
		connection = mock.Mock()
		connection.getresponse.return_value = response
		addresses = ((2, ('203.0.113.10', 8443)),)
		with mock.patch('cveFeed.pinned_transport.resolve', return_value=addresses), \
				mock.patch('cveFeed.pinned_transport.HTTPConnection', return_value=connection) as factory:
			result = ra.probe_url('https://original.example.test:8443/a?x=1', max_bytes=100,
							  headers={'Host': 'fallback.example.test'})
		self.assertEqual(factory.call_args.args, ('original.example.test', 8443, addresses, ra.CONNECT_TIMEOUT))
		self.assertFalse(factory.call_args.kwargs['context'].check_hostname)
		request_headers = connection.request.call_args.kwargs['headers']
		self.assertEqual(request_headers['Host'], 'fallback.example.test')
		self.assertEqual(request_headers['Accept-Encoding'], 'identity')
		self.assertNotIn('Authorization', request_headers)
		self.assertNotIn('Cookie', request_headers)
		response.read.assert_called_once_with(100)
		self.assertEqual((result['title'], result['cookies'], result['status']), ('Pinned', ['sid'], 200))
		connection.close.assert_called_once()


class RouteFixture:
	def setUp(self):
		org = Org.objects.create(name='R', slug='r')
		self.project = Project.objects.create(name='P', slug='pr', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='rt.test', project=self.project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		patcher = mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False)
		self.blocked = patcher.start()
		mock.patch('reNgine.tasks.geo_localize.delay').start()
		mock.patch('cveFeed.tasks.run_hygiene_task.delay').start()
		self.addCleanup(mock.patch.stopall)
		self.asked = []
		self.answers = {}

	def scan(self, names=('www.rt.test',), ports=((443, 'https'),), ip='203.0.113.5'):
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1, tasks=[],
			results_dir='x')
		for name in names:
			sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
			ip, _ = IpAddress.objects.get_or_create(address=ip)  # one row per address, shared by every host that resolves there
			sub.ip_addresses.add(ip)
			for number, service in ports:
				if not ip.ports.filter(number=number).exists():
					ip.ports.add(Port.objects.create(number=number, service_name=service, state='open'))
		return scan

	def probe(self, url):
		self.asked.append(url)
		path = url.split('://', 1)[1].split('/', 1)[1]
		return probe(url=url, **self.answers.get('/' + path, {'status': 404}))

	def run_it(self, scan, **kw):
		with mock.patch.object(ra, 'PER_REQUEST_GAP', 0):
			return ra.run_route_auth(scan.id, probe=kw.pop('probe', self.probe))


class RunnerTests(RouteFixture, TestCase):
	def test_routes_are_stored_with_their_state_and_each_url_is_in_the_ledger(self):
		self.answers = {'/': {'status': 200, 'title': 'Home'}, '/login': {'status': 200, 'body': '<input type="password">'},
			'/admin': {'status': 302, 'location': '/login?next=/admin'}, '/api': {'status': 401, 'www_authenticate': 'Bearer'}}
		out = self.run_it(self.scan())
		self.assertEqual(len(self.asked), len(ra.COMMON_PATHS))
		self.assertEqual(out['routes'], len(ra.COMMON_PATHS))
		rows = {r.path: r for r in RouteAuth.objects.filter(project=self.project)}
		self.assertEqual((rows['/'].auth_state, rows['/'].title, rows['/'].host), ('open', 'Home', 'www.rt.test'))
		self.assertEqual(rows['/login'].auth_state, 'login')
		self.assertEqual((rows['/admin'].auth_state, rows['/admin'].redirect_to), ('session_required', '/login?next=/admin'))
		self.assertEqual(rows['/api'].auth_state, 'session_required')
		self.assertEqual(rows['/wp-login.php'].auth_state, 'not_found')
		self.assertEqual(ServiceRun.objects.filter(service='route-auth', status='done').count(), len(ra.COMMON_PATHS))
		self.assertTrue(AgentActivity.objects.filter(kind='run_check', message__startswith='Checked 10 web routes on 1 hosts of rt.test').exists())

	def test_a_second_run_inside_the_ttl_probes_nothing(self):
		self.run_it(self.scan())
		self.asked.clear()
		out = self.run_it(self.scan())
		self.assertEqual(self.asked, [])
		self.assertEqual(out['reused'], len(ra.COMMON_PATHS))

	def test_a_state_flip_on_the_next_run_is_an_auth_change(self):
		self.answers = {'/admin': {'status': 200, 'title': 'Admin'}}
		self.run_it(self.scan())
		self.assertFalse(AssetChange.objects.exists())
		ServiceRun.objects.update(finished_at=timezone.now() - datetime.timedelta(days=8))
		self.answers = {'/admin': {'status': 302, 'location': '/login'}}
		scan = self.scan()
		self.run_it(scan)
		change = AssetChange.objects.get(kind='auth_changed')
		self.assertEqual((change.host, change.before['auth_state'], change.after['auth_state'], change.scan_id),
			('www.rt.test', 'open', 'session_required', scan.id))
		self.assertEqual(change.after['url'], 'https://www.rt.test/admin')

	def test_a_host_resolving_to_a_blocked_address_is_never_probed(self):
		self.blocked.return_value = True
		out = self.run_it(self.scan())
		self.assertEqual(self.asked, [])
		self.assertEqual(out['routes'], 0)
		self.assertEqual(RouteAuth.objects.count(), 0)

	def test_a_blocked_ip_target_is_never_probed(self):
		scan = self.scan(names=('127.0.0.1',))
		self.run_it(scan)
		self.assertEqual(self.asked, [])

	def test_the_per_scan_cap_is_honoured(self):
		with mock.patch.object(ra, 'MAX_URLS_PER_SCAN', 4):
			out = self.run_it(self.scan(names=('a.rt.test', 'b.rt.test')))
		self.assertEqual(len(self.asked), 4)
		self.assertEqual(out['routes'], 4)

	def test_the_stop_flag_ends_the_run_early(self):
		scan = self.scan()

		def stopping(url):
			resources.request_abort(scan.id)
			return probe(url=url, status=200)
		self.addCleanup(resources.clear_abort, scan.id)
		out = self.run_it(scan, probe=stopping)
		self.assertEqual(out['routes'], 1)
		self.assertEqual(RouteAuth.objects.count(), 1)

	def test_the_stage_is_recorded_and_a_stop_ends_the_pipeline_after_it(self):
		scan = self.scan()
		_, kwargs = _stages()
		kwargs.pop('resolver')

		def stopping(url):
			resources.request_abort(scan.id)
			return probe(url=url, status=200)
		kwargs['route_probe'] = stopping
		self.addCleanup(resources.clear_abort, scan.id)
		out = discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False, **kwargs)
		self.assertEqual(out['status'], 'aborted')
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='route_auth_scan').status, discovery.SUCCESS)
		self.assertFalse(ScanActivity.objects.filter(scan_of=scan, name='cve_correlation').exists())

	def test_probe_errors_are_counted_not_stored(self):
		def failing(url):
			raise OSError('connection refused')
		out = self.run_it(self.scan(), probe=failing)
		self.assertEqual((out['routes'], out['errors']), (0, len(ra.COMMON_PATHS)))
		self.assertEqual(RouteAuth.objects.count(), 0)
		self.assertEqual(ServiceRun.objects.filter(service='route-auth', status='failed').count(), len(ra.COMMON_PATHS))

	def test_endpoints_the_scan_found_are_probed_too(self):
		from startScan.models import EndPoint
		scan = self.scan()
		sub = Subdomain.objects.get(scan_history=scan)
		EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, http_url='https://www.rt.test/reports/q4?y=1')
		EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, http_url='https://www.rt.test/app.js')
		self.run_it(scan)
		self.assertIn('https://www.rt.test/reports/q4', self.asked)
		self.assertNotIn('https://www.rt.test/app.js', self.asked)

	def test_a_scan_with_no_web_services_makes_no_requests(self):
		out = self.run_it(self.scan(ports=((22, 'ssh'),)))
		self.assertEqual((out['routes'], self.asked), (0, []))


class ApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org1, org2 = Org.objects.create(name='One', slug='ro1'), Org.objects.create(name='Two', slug='ro2')
		cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=org1)
		cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=org2)
		cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=now)
		alice, bob = User.objects.create_user('ralice', password='x'), User.objects.create_user('rbob', password='x')
		ProjectMembership.objects.create(user=alice, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=bob, project=cls.pb, role='user')
		_, cls.t_alice = create_token(alice, 'a')
		_, cls.t_bob = create_token(bob, 'b')
		for project, domain, host, path, state in ((cls.pa, cls.da, 'www.a.example', '/admin', 'open'),
				(cls.pa, cls.da, 'www.a.example', '/', 'sso'), (cls.pa, cls.da, 'app.a.example', '/', 'login'),
				(cls.pb, cls.db, 'www.b.example', '/', 'sso')):
			RouteAuth.objects.create(project=project, domain=domain, host=host, url=f'https://{host}{path}', path=path, auth_state=state,
				http_status=200)
		for name, domain in (('www.a.example', cls.da), ('app.a.example', cls.da), ('www.b.example', cls.db)):
			Subdomain.objects.create(name=name, target_domain=domain)

	def test_routes_are_project_scoped_and_filterable(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/routes?auth_state=sso')
		self.assertEqual(status, 200)
		self.assertEqual([(r['host'], r['path']) for r in data['results']], [('www.a.example', '/')])
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/routes')[1]['count'], 3)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/routes?host=app')[1]['count'], 1)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/routes?auth_state=bogus')[0], 400)
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-a/routes')[0], 404)

	def test_search_by_auth_state(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/search?q=auth:open')
		self.assertEqual(status, 200)
		self.assertEqual([h['host'] for h in data['results']], ['www.a.example'])
		self.assertIn('auth open', data['results'][0]['matched'])
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/search?q=-auth:open')
		self.assertEqual([h['host'] for h in data['results']], ['app.a.example'])
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/search?q=auth:bogus')[0], 400)

	def test_mcp_tool(self):
		status, data = rpc(self.t_alice, 'tools/call', {'name': 'list_routes', 'arguments': {'project': 'proj-a', 'auth_state': 'login'}})
		self.assertFalse(data['result']['isError'])
		self.assertEqual(json.loads(data['result']['content'][0]['text'])['count'], 1)


class ProbeTimeBudgetTests(SimpleTestCase):
	def test_a_host_that_trickles_bytes_is_cut_off_at_the_total_budget(self):
		import socket
		import time
		from cveFeed import pinned_transport
		listener = socket.socket()
		listener.bind(('127.0.0.1', 0))
		listener.listen(1)
		stop = threading.Event()

		def drip():
			conn, _ = listener.accept()
			try:
				conn.recv(4096)
				conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 70000\r\n\r\n')
				while not stop.is_set():
					conn.sendall(b'a')  # one byte every 0.2 s keeps every per-read timeout satisfied
					time.sleep(0.2)
			except OSError:
				pass
			finally:
				conn.close()

		thread = threading.Thread(target=drip, daemon=True)
		thread.start()
		started = time.monotonic()
		try:
			with mock.patch.object(pinned_transport, 'is_scannable_ip', return_value=True), mock.patch.object(ra, 'PROBE_TOTAL_SECONDS', 1):
				with self.assertRaises(TimeoutError):
					ra.probe_url(f'http://127.0.0.1:{listener.getsockname()[1]}/')
		finally:
			stop.set()
			listener.close()
		self.assertLess(time.monotonic() - started, 5)
