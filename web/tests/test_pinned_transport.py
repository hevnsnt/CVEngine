import os
import socket
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import pinned_transport as transport


def answer(ip, family=socket.AF_INET):
    address = (ip, 443) if family == socket.AF_INET else (ip, 443, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address


class PinnedTransportTests(SimpleTestCase):
    def test_connection_does_not_resolve_again_after_admission(self):
        sock = mock.Mock()
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('203.0.113.10')]) as dns:
            addresses = transport.resolve('asset.example.test', 443)
            dns.side_effect = AssertionError('unexpected second DNS lookup')
            with mock.patch.object(socket, 'socket', return_value=sock):
                self.assertIs(transport.open_socket(addresses, 3), sock)
        sock.connect.assert_called_once_with(('203.0.113.10', 443))
        dns.assert_called_once()

    def test_mixed_allowed_and_prohibited_answers_fail_closed(self):
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('203.0.113.10'), answer('127.0.0.1')]):
            with self.assertRaises(ValueError):
                transport.resolve('asset.example.test', 443)

    def test_empty_or_failed_dns_never_falls_back_to_hostname_connection(self):
        with mock.patch.object(socket, 'socket') as connect:
            for result in ([], OSError('DNS unavailable')):
                with mock.patch.object(socket, 'getaddrinfo') as dns:
                    if isinstance(result, Exception):
                        dns.side_effect = result
                    else:
                        dns.return_value = result
                    with self.assertRaises((ValueError, OSError)):
                        transport.resolve('asset.example.test', 443)
            connect.assert_not_called()

    def test_ipv6_connects_to_numeric_sockaddr(self):
        sock = mock.Mock()
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('2001:db8::1', socket.AF_INET6)]):
            addresses = transport.resolve('ipv6.example.test', 8443)
        with mock.patch.object(socket, 'socket', return_value=sock):
            transport.open_socket(addresses, 3)
        sock.connect.assert_called_once_with(('2001:db8::1', 8443, 0, 0))

    def test_connection_failure_closes_socket_without_dns_fallback(self):
        sock = mock.Mock()
        sock.connect.side_effect = OSError('refused')
        with mock.patch.object(socket, 'socket', return_value=sock), \
                mock.patch.object(socket, 'getaddrinfo') as dns:
            with self.assertRaises(OSError):
                transport.open_socket(((socket.AF_INET, ('203.0.113.10', 443)),), 3)
        dns.assert_not_called()
        sock.close.assert_called_once()

    def test_operator_private_policy_applies_but_loopback_remains_blocked(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
            with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('10.0.0.1')]):
                self.assertTrue(transport.resolve('private.example.test', 443))
            with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('127.0.0.1')]):
                with self.assertRaises(ValueError):
                    transport.resolve('loop.example.test', 443)

    def test_https_preserves_original_sni_and_closes_failed_tls_socket(self):
        raw, context = mock.Mock(), mock.Mock()
        connection = transport.HTTPConnection('original.example.test', 443, (), 3, context=context)
        with mock.patch.object(transport, 'open_socket', return_value=raw):
            connection.connect()
        context.wrap_socket.assert_called_once_with(raw, server_hostname='original.example.test')
        context.wrap_socket.side_effect = OSError('TLS failed')
        with mock.patch.object(transport, 'open_socket', return_value=raw):
            with self.assertRaises(OSError):
                connection.connect()
        raw.close.assert_called_once()
