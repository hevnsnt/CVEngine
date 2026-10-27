import ssl
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import legacy_tls


class LegacyTlsTests(SimpleTestCase):
	"""The one module that speaks TLS 1.0 / 1.1 on purpose (the hygiene check for servers that still accept them)."""

	def test_the_client_is_limited_to_the_two_old_versions(self):
		ctx = legacy_tls._context()
		self.assertEqual((ctx.minimum_version, ctx.maximum_version), (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1))
		self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)  # it reads a certificate, it validates nothing

	def test_a_refusing_server_or_a_build_without_the_old_protocols_is_simply_no(self):
		with mock.patch.object(legacy_tls.pinned_transport, 'resolve', return_value=((2, ('203.0.113.10', 443)),)), \
				mock.patch.object(legacy_tls.pinned_transport, 'open_socket', side_effect=OSError('refused')):
			self.assertIsNone(legacy_tls.handshake('asset.example.test', 443, 5))
			self.assertFalse(legacy_tls.accepts('asset.example.test', 443, 5))
		with mock.patch.object(legacy_tls, '_context', side_effect=ssl.SSLError('no TLS 1.0 here')):
			self.assertIsNone(legacy_tls.handshake('asset.example.test', 443, 5))

	def test_only_a_negotiated_old_version_counts_and_the_project_reaches_the_transport(self):
		addresses = ((2, ('203.0.113.10', 443)),)
		tls = mock.MagicMock()
		tls.__enter__.return_value = tls
		tls.getpeercert.return_value, tls.cipher.return_value = b'der', ('AES128-SHA', 'TLSv1', 128)
		ctx, raw = mock.MagicMock(), mock.MagicMock()
		raw.__enter__.return_value = raw
		ctx.wrap_socket.return_value = tls
		with mock.patch.object(legacy_tls, '_context', return_value=ctx), \
				mock.patch.object(legacy_tls.pinned_transport, 'open_socket', return_value=raw) as connect:
			tls.version.return_value = 'TLSv1'
			self.assertEqual(legacy_tls.handshake('asset.example.test', 443, 5, addresses=addresses, project=7), (b'der', 'TLSv1', 'AES128-SHA'))
			self.assertTrue(legacy_tls.accepts('asset.example.test', 443, 5, addresses=addresses))
			tls.version.return_value = 'TLSv1.2'
			self.assertFalse(legacy_tls.accepts('asset.example.test', 443, 5, addresses=addresses))
		connect.assert_any_call(addresses, 5, project=7)
