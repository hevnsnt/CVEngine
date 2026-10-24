import socket
import threading
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import changes, zombie
from cveFeed.models import AssetChange, HostState
from tests.test_changes import ChangeFixture
from tests.test_zombie import HOST


class TcpEndpointTests(SimpleTestCase):
	def state(self, ports, ip='203.0.113.6'):
		return {'ips': {ip: {'ports': {k: {'service': v} for k, v in ports.items()}}}}

	def test_only_non_web_tcp_ports_lowest_first_at_most_three(self):
		state = self.state({'443/tcp': 'https', '3306/tcp': 'mysql', '22/tcp': 'ssh', '8080/tcp': 'http-proxy', '3389/tcp': 'ms-wbt-server', '5432/tcp': 'postgresql'})
		self.assertEqual(zombie.tcp_endpoints(state), [('203.0.113.6', 22), ('203.0.113.6', 3306), ('203.0.113.6', 3389)])

	def test_udp_and_blocked_addresses_are_never_probed(self):
		self.assertEqual(zombie.tcp_endpoints(self.state({'53/udp': 'domain'})), [])
		self.assertEqual(zombie.tcp_endpoints(self.state({'22/tcp': 'ssh'}, ip='127.0.0.1')), [])
		self.assertEqual(zombie.tcp_endpoints(self.state({'22/tcp': 'ssh'}, ip='169.254.169.254')), [])
		self.assertEqual(zombie.tcp_endpoints({}), [])

	def test_the_probe_is_a_connect_that_sends_nothing(self):
		received = []
		server = socket.socket()
		server.bind(('127.0.0.1', 0))
		server.listen(1)
		port = server.getsockname()[1]

		def accept():
			conn, _ = server.accept()
			conn.settimeout(1)
			try:
				received.append(conn.recv(10))
			except OSError:
				received.append(b'')
			conn.close()
		thread = threading.Thread(target=accept, daemon=True)
		thread.start()
		self.assertTrue(zombie.tcp_alive('127.0.0.1', port))
		thread.join(3)
		server.close()
		self.assertEqual(received, [b''])  # connect and close, no payload
		self.assertFalse(zombie.tcp_alive('127.0.0.1', 1))

	def test_the_number_of_hosts_probed_is_capped(self):
		states = {f'h{i}.t': self.state({'22/tcp': 'ssh'}) for i in range(120)}
		asked = []
		out = zombie.tcp_probe_hosts(list(states), states, prober=lambda ip, port: asked.append(ip) or True)
		self.assertEqual((len(asked), len(out)), (zombie.MAX_ZOMBIE_CHECKS, zombie.MAX_ZOMBIE_CHECKS))


class RetiredWithTcpEvidenceTests(ChangeFixture, TestCase):
	"""Verdict 6: a connect on the last non-web ports is evidence on host_retired, never a zombie."""

	def setUp(self):
		super().setUp()
		changes.record_scan_changes(self.baseline().id)
		self.without_b = lambda: self.scan({'a.ct.test': HOST})

	def test_an_ssh_only_host_whose_port_still_answers_is_retired_with_the_evidence_and_is_no_zombie(self):
		asked = []
		out = changes.record_scan_changes(self.without_b().id, resolver=lambda names: set(), checker=lambda *a: False,
			tcp_checker=lambda ip, port: asked.append((ip, port)) or True)
		self.assertEqual(asked, [('203.0.113.6', 22)])
		change = AssetChange.objects.get(kind='host_retired', host='b.ct.test')
		self.assertEqual(change.after, {'tcp_alive': ['203.0.113.6:22']})
		self.assertFalse(AssetChange.objects.filter(kind='zombie_host').exists())
		row = HostState.objects.get(host='b.ct.test')
		self.assertIsNotNone(row.retired_at)
		self.assertIsNone(row.zombie_since)
		self.assertEqual((out['zombies'], out['retired']), (0, 1))

	def test_nothing_answering_leaves_the_retired_row_as_it_was(self):
		changes.record_scan_changes(self.without_b().id, resolver=lambda names: set(), checker=lambda *a: False, tcp_checker=lambda ip, port: False)
		self.assertIsNone(AssetChange.objects.get(kind='host_retired', host='b.ct.test').after)

	def test_a_host_the_http_check_found_is_a_zombie_and_is_not_tcp_probed(self):
		tcp = mock.Mock(return_value=True)
		only_b = self.scan({'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}})  # a is gone and answers on 443
		changes.record_scan_changes(only_b.id, resolver=lambda names: set(), checker=lambda host, ip, port, scheme: True, tcp_checker=tcp)
		tcp.assert_not_called()
		self.assertEqual(AssetChange.objects.get(kind='zombie_host').host, 'a.ct.test')

	def test_a_name_that_still_resolves_is_not_probed(self):
		tcp = mock.Mock(return_value=True)
		changes.record_scan_changes(self.without_b().id, resolver=lambda names: {(n, '203.0.113.6') for n in names}, checker=lambda *a: False, tcp_checker=tcp)
		tcp.assert_not_called()
