import gzip
import io
import os
import socket
import zlib
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


class FakeResponse:
    """The part of an ``http.client.HTTPResponse`` a body reader uses: ``getheader`` and ``read(n)``, counting what was read."""

    def __init__(self, body, encoding=None):
        self.stream, self.encoding, self.read_total = io.BytesIO(body), encoding, 0

    def getheader(self, name, default=None):
        return self.encoding if name.lower() == 'content-encoding' and self.encoding is not None else default

    def read(self, amt=None):
        chunk = self.stream.read(amt)
        self.read_total += len(chunk)
        return chunk


PAGE = b'<html><head><title>Shelly</title></head><body>Device Model 1PM</body></html>'


def raw_deflate(data):
    packer = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return packer.compress(data) + packer.flush()


class ReadBodyTests(SimpleTestCase):
    """``read_body``: what every in-process HTTP reader gets when a server ignores ``Accept-Encoding: identity`` (the printer and relay of #281)."""

    def test_identity_and_no_header_are_read_as_sent_and_capped(self):
        for encoding in (None, '', 'identity', ' Identity '):
            self.assertEqual(transport.read_body(FakeResponse(PAGE, encoding), 1000), PAGE, encoding)
        self.assertEqual(transport.read_body(FakeResponse(PAGE), 10), PAGE[:10])
        self.assertEqual(transport.read_body(FakeResponse(b''), 10), b'')

    def test_gzip_zlib_deflate_and_raw_deflate_are_decoded(self):
        cases = {'gzip': gzip.compress(PAGE), 'deflate': zlib.compress(PAGE), 'DEFLATE': raw_deflate(PAGE), ' gzip ': gzip.compress(PAGE)}
        for encoding, body in cases.items():
            self.assertEqual(transport.read_body(FakeResponse(body, encoding), 1000), PAGE, encoding)

    def test_the_cap_is_on_the_decompressed_output_and_a_bomb_stops_at_it(self):
        bomb = gzip.compress(b'A' * 50_000_000, compresslevel=9)  # about 50 KB claiming 50 MB
        self.assertLess(len(bomb), 100_000)
        response = FakeResponse(bomb, 'gzip')
        body = transport.read_body(response, 64 * 1024)
        self.assertEqual(len(body), 64 * 1024)
        self.assertLessEqual(response.read_total, 64 * 1024 + transport.COMPRESSED_SLACK)  # the compressed side is bounded too
        self.assertEqual(len(transport.read_body(FakeResponse(zlib.compress(b'A' * 5_000_000), 'deflate'), 1000)), 1000)

    def test_a_page_that_decodes_to_less_than_the_cap_is_whole(self):
        self.assertEqual(transport.read_body(FakeResponse(gzip.compress(PAGE), 'gzip'), len(PAGE)), PAGE)
        self.assertEqual(transport.read_body(FakeResponse(gzip.compress(PAGE), 'gzip'), len(PAGE) + 1), PAGE)

    def test_an_empty_compressed_body_is_empty_not_an_error(self):
        self.assertEqual(transport.read_body(FakeResponse(b'', 'gzip'), 100), b'')

    def test_a_stream_that_does_not_decode_or_ends_early_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'invalid compressed probe response'):
            transport.read_body(FakeResponse(b'not gzip at all', 'gzip'), 100)
        with self.assertRaisesRegex(ValueError, 'incomplete compressed probe response'):
            transport.read_body(FakeResponse(gzip.compress(PAGE * 50)[:40], 'gzip'), 10_000)

    def test_an_encoding_it_cannot_read_is_an_error_not_binary_text(self):
        for encoding in ('br', 'zstd', 'compress', 'gzip, br'):
            with self.assertRaisesRegex(ValueError, 'unsupported probe content encoding'):
                transport.read_body(FakeResponse(b'\x1b\x00', encoding), 100)
