import os
import socket
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import pinned_transport as transport


def answer(ip, family=socket.AF_INET):
    address = (ip, 443) if family == socket.AF_INET else (ip, 443, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address


class PinnedTransportTests(SimpleTestCase):
    """``pinned_transport.resolve``, the one lookup this server still makes of a target name (to refuse a prohibited address before a task is built). The
    connection, TLS and body reading are a Sentinel's (cvengine_scanner/tests/probes/test_transport.py)."""

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

    def test_operator_private_policy_applies_but_loopback_remains_blocked(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
            with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('10.0.0.1')]):
                self.assertTrue(transport.resolve('private.example.test', 443))
            with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('127.0.0.1')]):
                with self.assertRaises(ValueError):
                    transport.resolve('loop.example.test', 443)


    def test_ipv6_answers_are_numeric_sockaddrs_and_a_repeat_answer_is_kept_once(self):
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('2001:db8::1', socket.AF_INET6), answer('2001:db8::1', socket.AF_INET6)]):
            addresses = transport.resolve('ipv6.example.test', 8443)
        self.assertEqual(addresses, ((socket.AF_INET6, ('2001:db8::1', 8443, 0, 0)),))
