import datetime
import http.server
import json
import threading
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import changes, route_auth as ra, scoring, zombie
from cveFeed.models import AssetChange, HostState, RouteAuth, ServiceRun
from dashboard.models import ProjectMembership
from startScan.models import EndPoint, Subdomain
from tests.test_agentapi import call
from tests.test_changes import ChangeFixture
from tests.test_route_auth import RouteFixture

HOST = {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}


class EndpointsTests(SimpleTestCase):
	def state(self, ports, ip='203.0.113.5'):
		return {'ips': {ip: {'ports': {k: {'service': v} for k, v in ports.items()}}}}

	def test_web_ports_only_443_and_80_first_then_the_lowest_and_at_most_three(self):
		state = self.state({'8080/tcp': 'http-proxy', '22/tcp': 'ssh', '80/tcp': 'http', '443/tcp': 'https', '3000/tcp': 'http', '8443/tcp': 'https'})
		self.assertEqual(zombie.endpoints(state), [('203.0.113.5', 443, 'https'), ('203.0.113.5', 80, 'http'), ('203.0.113.5', 3000, 'http')])

	def test_an_unknown_port_with_an_http_service_counts_and_udp_does_not(self):
		self.assertEqual(zombie.endpoints(self.state({'9000/tcp': 'http'})), [('203.0.113.5', 9000, 'http')])
		self.assertEqual(zombie.endpoints(self.state({'53/udp': 'domain', '443/udp': 'https'})), [])

	def test_addresses_a_scanner_may_not_touch_are_never_asked(self):
		self.assertEqual(zombie.endpoints(self.state({'443/tcp': 'https'}, ip='127.0.0.1')), [])
		self.assertEqual(zombie.endpoints(self.state({'443/tcp': 'https'}, ip='169.254.169.254')), [])
		self.assertEqual(zombie.endpoints({}), [])

	def test_check_hosts_caps_the_number_of_hosts_asked(self):
		states = {f'h{i}.t': self.state({'443/tcp': 'https'}) for i in range(120)}
		asked = []
		alive, checked = zombie.check_hosts(list(states), states, checker=lambda host, ip, port, scheme: asked.append(host) or host == 'h3.t')
		self.assertEqual((len(checked), len(asked), list(alive)), (zombie.MAX_ZOMBIE_CHECKS, zombie.MAX_ZOMBIE_CHECKS, ['h3.t']))
		self.assertEqual(alive['h3.t'], ['203.0.113.5:443'])


class HostHandler(http.server.BaseHTTPRequestHandler):
	hosts = []

	def do_GET(self):
		HostHandler.hosts.append(self.headers.get('Host'))
		self.send_response(404)
		self.send_header('Content-Length', '0')
		self.end_headers()

	def log_message(self, *args):
		pass


class AliveProbeTests(SimpleTestCase):
	def test_any_http_answer_counts_and_the_old_name_is_the_host_header(self):
		server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HostHandler)
		threading.Thread(target=server.serve_forever, daemon=True).start()
		self.addCleanup(server.server_close)
		self.addCleanup(server.shutdown)
		# The probe refuses loopback by design; this fixture is the only loopback server involved.
		with mock.patch('cveFeed.pinned_transport.is_scannable_ip', return_value=True):
			self.assertTrue(zombie.http_alive('old.example.test', '127.0.0.1', server.server_address[1], 'http'))
			self.assertEqual(HostHandler.hosts, ['old.example.test'])
			self.assertFalse(zombie.http_alive('old.example.test', '127.0.0.1', 1, 'http'))
		self.assertFalse(zombie.http_alive('old.example.test', '127.0.0.1', server.server_address[1], 'http'))  # gate on: refused


class ZombieHostTests(ChangeFixture, TestCase):
	def full_scan_without_a(self):
		return self.scan({'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}})

	def setUp(self):
		super().setUp()
		changes.record_scan_changes(self.baseline().id)

	def test_a_gone_name_whose_address_still_answers_is_a_zombie_not_retired(self):
		asked = []

		def checker(host, ip, port, scheme):
			asked.append((host, ip, port, scheme))
			return port == 443
		out = changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: set(), checker=checker)
		self.assertEqual(asked, [('a.ct.test', '203.0.113.5', 443, 'https')])  # only a is gone, and 443 is its only web port
		row = HostState.objects.get(host='a.ct.test')
		self.assertIsNotNone(row.zombie_since)
		self.assertIsNone(row.retired_at)
		self.assertIsNotNone(row.last_alive_check)
		change = AssetChange.objects.get(kind='zombie_host')
		self.assertEqual((change.host, change.after, change.before), ('a.ct.test', {'alive': ['203.0.113.5:443']}, {'ips': ['203.0.113.5']}))
		self.assertFalse(AssetChange.objects.filter(kind='host_retired').exists())
		self.assertEqual((out['zombies'], out['retired']), (1, 0))

	def test_a_zombie_is_reported_once(self):
		always = lambda host, ip, port, scheme: True  # noqa: E731
		changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: set(), checker=always)
		changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: set(), checker=always)
		self.assertEqual(AssetChange.objects.filter(kind='zombie_host', host='a.ct.test').count(), 1)

	def test_a_gone_name_that_answers_nowhere_is_retired(self):
		changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: set(), checker=lambda *a: False)
		row = HostState.objects.get(host='a.ct.test')
		self.assertIsNotNone(row.retired_at)
		self.assertIsNone(row.zombie_since)
		self.assertEqual(list(AssetChange.objects.filter(kind='host_retired').values_list('host', flat=True)), ['a.ct.test'])
		self.assertFalse(AssetChange.objects.filter(kind='zombie_host').exists())

	def test_a_name_that_still_resolves_is_not_checked(self):
		checker = mock.Mock(return_value=True)
		changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: {(n, '203.0.113.5') for n in names}, checker=checker)
		checker.assert_not_called()

	def test_a_partial_scan_never_checks_for_zombies(self):
		checker = mock.Mock(return_value=True)
		partial = self.scan({'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}}, tasks=['host_pipeline'])
		changes.record_scan_changes(partial.id, resolver=lambda names: set(), checker=checker)
		checker.assert_not_called()
		self.assertFalse(AssetChange.objects.filter(kind__in=('zombie_host', 'host_retired')).exists())

	def test_a_zombie_found_again_returns_and_is_cleared(self):
		changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: set(), checker=lambda *a: True)
		back = self.scan({'a.ct.test': HOST, 'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}})
		changes.record_scan_changes(back.id, resolver=lambda names: {(n, 'x') for n in names})
		kinds = sorted(AssetChange.objects.filter(scan=back).values_list('kind', flat=True))
		self.assertEqual(kinds, ['host_returned', 'zombie_cleared'])
		self.assertIsNone(HostState.objects.get(host='a.ct.test').zombie_since)

	def test_the_check_cap_leaves_the_rest_waiting(self):
		hosts = {f'n{i:03d}.ct.test': {'ip': '203.0.113.30', 'ports': [(443, 'https', '', '')]} for i in range(100)}
		hosts['a.ct.test'] = HOST
		changes.record_scan_changes(self.scan(hosts).id, resolver=lambda names: {(n, 'x') for n in names})
		asked = []

		def checker(host, ip, port, scheme):
			asked.append(host)
			return False
		out = changes.record_scan_changes(self.scan({'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}}).id,
			resolver=lambda names: set(), checker=checker)
		self.assertEqual(len(asked), zombie.MAX_ZOMBIE_CHECKS)  # 101 candidates, 100 asked
		self.assertEqual(out['retired'], zombie.MAX_ZOMBIE_CHECKS)
		waiting = HostState.objects.filter(domain=self.domain, retired_at__isnull=True).exclude(host='b.ct.test')
		self.assertEqual(waiting.count(), 1)  # the one beyond the cap waits for the next scan

	def test_a_zombie_host_raises_the_score_by_fifteen(self):
		changes.record_scan_changes(self.full_scan_without_a().id, resolver=lambda names: set(), checker=lambda *a: True)
		Subdomain.objects.create(name='a.ct.test', target_domain=self.domain, scan_history=None)
		scoring.rescore_hosts(self.project.id, ['a.ct.test'])
		detail = {d['label']: d['points'] for d in Subdomain.objects.get(name='a.ct.test', scan_history=None).score_detail}
		self.assertEqual(detail['Zombie host: DNS is gone but it still answers'], 15)


class ZombieRouteTests(RouteFixture, TestCase):
	def backdate(self):
		ServiceRun.objects.update(finished_at=timezone.now() - datetime.timedelta(days=8))

	def test_a_route_that_goes_missing_is_retired_and_one_that_returns_is_a_zombie(self):
		self.answers = {'/admin': {'status': 200, 'title': 'Admin'}}
		self.run_it(self.scan())
		self.backdate()
		self.answers = {'/admin': {'status': 404}}
		scan = self.scan()
		self.run_it(scan)
		row = RouteAuth.objects.get(path='/admin')
		self.assertEqual((row.auth_state, row.previous_state), ('not_found', 'open'))
		self.assertIsNotNone(row.retired_at)
		retired = AssetChange.objects.get(kind='route_retired')
		self.assertEqual((retired.before['auth_state'], retired.after['http_status'], retired.scan_id), ('open', 404, scan.id))
		self.assertFalse(AssetChange.objects.filter(kind='auth_changed').exists())  # the retirement says it
		self.backdate()
		self.answers = {'/admin': {'status': 200, 'title': 'Admin again'}}
		self.run_it(self.scan())
		row.refresh_from_db()
		self.assertIsNotNone(row.zombie_since)
		self.assertIsNotNone(row.retired_at)  # kept: it is history
		zombie_change = AssetChange.objects.get(kind='zombie_route')
		self.assertEqual((zombie_change.after['auth_state'], zombie_change.after['http_status']), ('open', 200))
		self.assertIn('retired_at', zombie_change.before)
		self.backdate()
		self.run_it(self.scan())  # still answering: reported once
		self.assertEqual(AssetChange.objects.filter(kind='zombie_route').count(), 1)

	def test_a_path_bbot_once_saw_gone_that_answers_now_is_a_zombie_with_no_earlier_row(self):
		earlier = self.scan()
		sub = Subdomain.objects.get(scan_history=earlier)
		EndPoint.objects.create(scan_history=earlier, target_domain=self.domain, subdomain=sub, http_url='https://www.rt.test/legacy?x=1',
			http_status=404)
		ServiceRun.objects.all().delete()
		self.answers = {'/legacy': {'status': 200, 'title': 'Still here'}}
		scan = self.scan()
		self.run_it(scan)
		self.assertIn('https://www.rt.test/legacy', self.asked)
		change = AssetChange.objects.get(kind='zombie_route')
		self.assertEqual(change.before, {'endpoint_status': 404, 'scan_id': earlier.id})
		self.assertIsNotNone(RouteAuth.objects.get(path='/legacy').zombie_since)

	def test_a_gone_path_that_stays_gone_is_not_a_zombie(self):
		earlier = self.scan()
		sub = Subdomain.objects.get(scan_history=earlier)
		EndPoint.objects.create(scan_history=earlier, target_domain=self.domain, subdomain=sub, http_url='https://www.rt.test/legacy', http_status=410)
		ServiceRun.objects.all().delete()
		self.answers = {}
		self.run_it(self.scan())
		self.assertFalse(AssetChange.objects.filter(kind='zombie_route').exists())

	def test_priority_paths_come_first_within_the_endpoint_cap(self):
		paths = ra.route_paths([f'https://h/p{i}' for i in range(30)], priority_paths=['https://h/legacy'])
		self.assertEqual(paths[len(ra.COMMON_PATHS)], '/legacy')


class ZombieApiTests(ChangeFixture, TestCase):
	def test_routes_and_search_filter_zombies(self):
		now = timezone.now()
		for host, since in (('a.ct.test', now), ('b.ct.test', None)):
			Subdomain.objects.create(name=host, target_domain=self.domain)
			HostState.objects.create(project=self.project, domain=self.domain, host=host, state={}, zombie_since=since)
			RouteAuth.objects.create(project=self.project, domain=self.domain, host=host, url=f'https://{host}/old', path='/old',
				auth_state='open', retired_at=now, zombie_since=since)
		user = User.objects.create_user('zom', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 't')
		status, data = call(token, 'GET', '/api/v1/projects/pc/routes?zombie=1')
		self.assertEqual([(r['host'], bool(r['zombie_since']), bool(r['retired_at'])) for r in data['results']], [('a.ct.test', True, True)])
		status, data = call(token, 'GET', '/api/v1/projects/pc/search?q=zombie:yes')
		self.assertEqual([(h['host'], h['zombie']) for h in data['results']], [('a.ct.test', True)])
		self.assertIn('zombie: DNS gone, still answering', data['results'][0]['matched'])
		status, data = call(token, 'GET', '/api/v1/projects/pc/search?q=zombie:no')
		self.assertEqual([(h['host'], h['zombie']) for h in data['results']], [('b.ct.test', False)])
		self.assertEqual(call(token, 'GET', '/api/v1/projects/pc/search?q=zombie:maybe')[0], 400)
		status, data = call(token, 'GET', '/api/v1/projects/pc/hosts?sort=name')
		self.assertEqual([(h['host'], h['zombie']) for h in data['results']], [('a.ct.test', True), ('b.ct.test', False)])
		self.assertEqual(call(token, 'GET', '/api/v1/projects/pc/changes?kind=zombie_host')[0], 200)
		self.assertEqual(call(token, 'GET', '/api/v1/projects/pc/changes?kind=zombie_route')[0], 200)
