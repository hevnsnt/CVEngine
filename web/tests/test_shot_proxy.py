import base64
import socket
import threading
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import shot_proxy

SECRET = 'batch-secret'


def basic(user='3', password=SECRET):
	return 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()


class Upstream:
	"""A tiny TCP server on loopback that records what it was sent and answers one canned reply."""

	def __init__(self, reply=b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello'):
		self.reply, self.received = reply, []
		self.listener = socket.socket()
		self.listener.bind(('127.0.0.1', 0))
		self.listener.listen(5)
		self.port = self.listener.getsockname()[1]
		threading.Thread(target=self._serve, daemon=True).start()

	def _serve(self):
		while True:
			try:
				conn, _ = self.listener.accept()
			except OSError:
				return
			conn.settimeout(3)
			data = b''
			try:
				while b'\r\n\r\n' not in data:
					chunk = conn.recv(4096)
					if not chunk:
						break
					data += chunk
				self.received.append(data)
				conn.sendall(self.reply)
			except OSError:
				pass
			finally:
				conn.close()

	def close(self):
		self.listener.close()


def talk(proxy, raw, read_until_close=True):
	sock = socket.create_connection(('127.0.0.1', proxy.port), timeout=5)
	sock.sendall(raw)
	data = b''
	try:
		while True:
			chunk = sock.recv(4096)
			if not chunk:
				break
			data += chunk
	except socket.timeout:
		pass
	finally:
		sock.close()
	return data


class ProxyBase(SimpleTestCase):
	def setUp(self):
		self.upstream = Upstream()
		self.addCleanup(self.upstream.close)
		self.admitted = []
		self.refuse = set()
		self.fail_connect = False

		def admit(page, host, port):
			self.admitted.append((page, host, port))
			if host in self.refuse:
				return None, 'refused by the guard'
			return '127.0.0.1', ''

		def connect(target, host, port, timeout):
			if self.fail_connect:
				raise OSError('down')
			return socket.create_connection((target, self.upstream.port), timeout)

		self.proxy = shot_proxy.VettingProxy(admit, connect, SECRET)
		self.proxy.start()
		self.addCleanup(self.proxy.stop)


class AuthenticationTests(ProxyBase):
	def test_a_request_without_the_batch_secret_is_asked_for_it(self):
		for header in ('', f'Proxy-Authorization: {basic(password="wrong")}\r\n', 'Proxy-Authorization: Bearer abc\r\n', 'Proxy-Authorization: Basic !!!\r\n'):
			answer = talk(self.proxy, f'GET http://a.example.test/ HTTP/1.1\r\nHost: a.example.test\r\n{header}\r\n'.encode())
			self.assertTrue(answer.startswith(b'HTTP/1.1 407'), (header, answer))
			self.assertIn(b'Proxy-Authenticate: Basic', answer)
		self.assertEqual(self.admitted, [])  # the guards are never asked for an unauthenticated caller
		self.assertEqual(self.upstream.received, [])

	def test_the_user_of_the_credentials_is_the_page_the_guards_are_asked_about(self):
		talk(self.proxy, f'CONNECT www.example.test:443 HTTP/1.1\r\nHost: www.example.test:443\r\nProxy-Authorization: {basic("12")}\r\n\r\n'.encode())
		self.assertEqual(self.admitted, [('12', 'www.example.test', 443)])


class ConnectTests(ProxyBase):
	def connect(self, host='www.example.test', port=443, user='3'):
		return f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: {basic(user)}\r\n\r\n'.encode()

	def test_an_admitted_connect_is_answered_200_and_the_bytes_are_spliced_to_the_vetted_address(self):
		answer = talk(self.proxy, self.connect() + b'GET / HTTP/1.1\r\nHost: www.example.test\r\n\r\n')
		self.assertTrue(answer.startswith(b'HTTP/1.1 200 Connection Established\r\n\r\n'), answer)
		self.assertTrue(answer.endswith(b'hello'))
		self.assertIn(b'GET / HTTP/1.1', self.upstream.received[0])  # what rode the tunnel reached the vetted address
		self.assertEqual(self.admitted, [('3', 'www.example.test', 443)])

	def test_a_refused_connect_is_a_403_and_nothing_connects(self):
		self.refuse = {'internal.example.test'}
		answer = talk(self.proxy, self.connect('internal.example.test', 6379))
		self.assertTrue(answer.startswith(b'HTTP/1.1 403'), answer)
		self.assertEqual(self.upstream.received, [])

	def test_a_connect_that_cannot_be_made_is_a_502_and_never_a_direct_attempt(self):
		self.fail_connect = True
		answer = talk(self.proxy, self.connect())
		self.assertTrue(answer.startswith(b'HTTP/1.1 502'), answer)

	def test_a_guard_that_raises_is_a_refusal(self):
		self.proxy.admit = mock.Mock(side_effect=RuntimeError('database gone'))
		with self.assertLogs('cveFeed.shot_proxy', 'WARNING'):
			answer = talk(self.proxy, self.connect())
		self.assertTrue(answer.startswith(b'HTTP/1.1 403'), answer)

	def test_an_ipv6_literal_authority_is_read_whole(self):
		talk(self.proxy, self.connect('[2001:db8::1]', 8443))
		self.assertEqual(self.admitted[0][1:], ('2001:db8::1', 8443))

	def test_a_connect_with_no_port_is_a_bad_request(self):
		answer = talk(self.proxy, f'CONNECT www.example.test HTTP/1.1\r\nProxy-Authorization: {basic()}\r\n\r\n'.encode())
		self.assertTrue(answer.startswith(b'HTTP/1.1 400'), answer)
		self.assertEqual(self.admitted, [])


class PlainHttpTests(ProxyBase):
	def get(self, url='http://www.example.test/a/b?q=1', extra=''):
		return (f'GET {url} HTTP/1.1\r\nHost: www.example.test\r\nProxy-Authorization: {basic()}\r\nProxy-Connection: keep-alive\r\n'
				f'Connection: keep-alive\r\nAccept: */*\r\n{extra}\r\n').encode()

	def test_a_request_is_rewritten_to_origin_form_with_one_request_per_connection(self):
		answer = talk(self.proxy, self.get())
		self.assertTrue(answer.endswith(b'hello'))
		sent = self.upstream.received[0].decode()
		self.assertTrue(sent.startswith('GET /a/b?q=1 HTTP/1.1\r\n'), sent)  # not the absolute form
		self.assertIn('Host: www.example.test', sent)
		self.assertIn('Accept: */*', sent)
		self.assertIn('Connection: close', sent)  # a later request to another host can never ride this connection
		self.assertNotIn('keep-alive', sent.lower())
		self.assertNotIn('Proxy-', sent)  # the batch secret is not passed to the target
		self.assertEqual(self.admitted, [('3', 'www.example.test', 80)])

	def test_a_refused_plain_request_is_closed_without_an_answer_so_no_page_of_ours_is_drawn(self):
		self.refuse = {'www.example.test'}
		self.assertEqual(talk(self.proxy, self.get()), b'')
		self.assertEqual(self.upstream.received, [])

	def test_a_plain_request_that_cannot_connect_is_closed_without_an_answer(self):
		self.fail_connect = True
		self.assertEqual(talk(self.proxy, self.get()), b'')

	def test_only_plain_http_in_absolute_form_is_accepted(self):
		for target in ('/relative', 'ftp://www.example.test/x', 'https://www.example.test/'):
			answer = talk(self.proxy, self.get(target))
			self.assertTrue(answer.startswith(b'HTTP/1.1 400'), (target, answer))
		self.assertEqual(self.upstream.received, [])

	def test_a_malformed_request_line_is_a_bad_request(self):
		answer = talk(self.proxy, b'NONSENSE\r\n\r\n')
		self.assertTrue(answer.startswith(b'HTTP/1.1 400'), answer)

	def test_a_default_port_and_an_explicit_one_are_told_to_the_guard(self):
		talk(self.proxy, self.get('http://www.example.test:8080/'))
		self.assertEqual(self.admitted[-1][1:], ('www.example.test', 8080))


class LifecycleTests(SimpleTestCase):
	def test_it_listens_on_loopback_only_and_stops_listening(self):
		proxy = shot_proxy.VettingProxy(lambda *a: (None, 'no'), lambda *a: None, 's')
		with proxy:
			self.assertTrue(proxy.server.startswith('http://127.0.0.1:'))
			socket.create_connection(('127.0.0.1', proxy.port), timeout=2).close()
		with self.assertRaises(OSError):
			socket.create_connection(('127.0.0.1', proxy.port), timeout=1)

	def test_connections_beyond_the_cap_are_dropped(self):
		proxy = shot_proxy.VettingProxy(lambda *a: (None, 'no'), lambda *a: None, 's')
		with mock.patch.object(shot_proxy, 'MAX_CONNECTIONS', 0), proxy:
			sock = socket.create_connection(('127.0.0.1', proxy.port), timeout=2)
			sock.settimeout(2)
			self.assertEqual(sock.recv(10), b'')
			sock.close()
