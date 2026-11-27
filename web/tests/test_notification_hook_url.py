"""Webhook addresses in Settings > Notifications must resolve to public addresses only (N3b review, SSRF).

The notification sender POSTs scan messages to the Slack, Discord and Lark webhook addresses from the server. The fields took any text, so
an address such as ``http://169.254.169.254/latest`` was stored and posted to. The rule fails closed: it is refused when saved (400), and
a value saved before the rule is skipped at send time, on the address the name resolves to then, and logged once with its host.
"""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from scanEngine.models import Notification
from tests.test_settings import send
from tests.test_tenancy import client_for

PUBLIC = [(2, 1, 6, '', ('8.8.4.4', 0))]
LOOPBACK = [(2, 1, 6, '', ('127.0.0.1', 0))]
METADATA = [(2, 1, 6, '', ('169.254.169.254', 0))]


class HookUrlTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.root = User.objects.create_superuser('hook-root', 'hook@example.com', 'x')

	def setUp(self):
		self.c = client_for(self.root)

	def _stored(self, name):
		row = Notification.objects.first()
		return getattr(row, name) if row else ''

	def test_a_metadata_or_link_local_hook_is_refused_and_not_stored(self):
		bad = ['http://169.254.169.254/latest/meta-data/', 'http://[fe80::1]/hook', 'http://metadata.google.internal/x',
		       'http://[::ffff:169.254.169.254]/x', 'http://[fd00:ec2::254]/x', 'http://127.0.0.1:8000/x', 'http://[::1]/x',
		       'http://10.0.0.5/x', 'http://192.168.1.20:8065/hooks/abc', 'http://2852039166/x']
		with mock.patch('socket.getaddrinfo', return_value=METADATA):
			bad.append('http://169.254.169.254.nip.io/x')
			for name in ('slack_hook_url', 'discord_hook_url', 'lark_hook_url'):
				for url in bad:
					with self.subTest(name=name, url=url):
						status, data = send(self.c, 'PUT', 'notifications', {name: url})
						self.assertEqual(status, 400, data)
						self.assertFalse(self._stored(name))

	def test_a_hook_that_is_not_http_is_refused(self):
		for url in ('file:///etc/passwd', 'gopher://x/1', 'hooks.slack.com/services/x', 'javascript:alert(1)'):
			with self.subTest(url=url):
				status, data = send(self.c, 'PUT', 'notifications', {'slack_hook_url': url})
				self.assertEqual(status, 400, data)
				self.assertFalse(self._stored('slack_hook_url'))

	def test_public_and_own_server_hooks_are_kept(self):
		with mock.patch('socket.getaddrinfo', return_value=PUBLIC):
			for name, url in (('slack_hook_url', 'https://hooks.slack.com/services/T/B/x'), ('discord_hook_url', 'https://discord.com/api/webhooks/1/x'),
			                  ('slack_hook_url', 'https://chat.example.org/hooks/abc'), ('lark_hook_url', 'http://8.8.4.4:8065/hooks/abc')):
				with self.subTest(name=name, url=url):
					status, data = send(self.c, 'PUT', 'notifications', {name: url})
					self.assertEqual(status, 200, data)
					self.assertEqual(self._stored(name), url)

	def test_a_stored_hook_is_not_checked_again_when_other_settings_change(self):
		Notification.objects.create(slack_hook_url='http://169.254.169.254/old')  # saved before the rule: left alone until it is replaced
		status, data = send(self.c, 'PUT', 'notifications', {'send_to_slack': True})
		self.assertEqual(status, 200, data)
		status, data = send(self.c, 'PUT', 'notifications', {'clear_slack_hook_url': True})
		self.assertEqual(status, 200, data)
		self.assertEqual(self._stored('slack_hook_url'), '')


	def test_a_name_that_does_not_resolve_is_refused(self):
		with mock.patch('socket.getaddrinfo', side_effect=OSError('no such name')):
			status, data = send(self.c, 'PUT', 'notifications', {'slack_hook_url': 'https://nowhere.example.org/hook'})
		self.assertEqual(status, 400, data)
		self.assertIn('slack_hook_url', data.get('error', '') or str(data))


class SendTimeTests(TestCase):
	"""A value saved before the rule stops working safely: the sender does not call it, logs its host once, and raises nothing."""

	def setUp(self):
		from cvengine import hook_guard
		hook_guard._logged.clear()
		self.addCleanup(hook_guard._logged.clear)

	def _row(self, url):
		Notification.objects.all().delete()
		return Notification.objects.create(slack_hook_url=url, lark_hook_url=url, discord_hook_url=url,
		                                   send_to_slack=True, send_to_lark=True, send_to_discord=True)

	def test_a_stored_non_public_hook_is_not_called_and_logged_once(self):
		from cvengine import common_func
		for url, dns in (('http://169.254.169.254/latest/', None), ('http://[fd00:ec2::254]/x', None), ('http://localhost:8000/x', LOOPBACK),
		                 ('https://rebind.example.org/x', LOOPBACK)):
			with self.subTest(url=url):
				from cvengine import hook_guard
				hook_guard._logged.clear()
				self._row(url)
				patch_dns = mock.patch('socket.getaddrinfo', return_value=dns or PUBLIC)
				with patch_dns, mock.patch.object(common_func.requests, 'post') as post, \
				     mock.patch.object(common_func, 'DiscordWebhook') as hook, self.assertLogs('cvengine.hook_guard', 'WARNING') as logs:
					for _ in range(2):
						common_func.send_slack_message('hello')
						common_func.send_lark_message('hello')
						common_func.send_discord_message('hello')
				post.assert_not_called()
				hook.assert_not_called()
				self.assertEqual(len(logs.output), 3, logs.output)  # once per channel, not once per send
				from cvengine.hook_guard import hook_host
				for line in logs.output:
					self.assertIn(hook_host(url), line)
					self.assertNotIn('/latest', line)  # the host only, never the secret path

	def test_the_resolved_address_is_checked_not_only_the_literal(self):
		from cvengine import common_func
		self._row('https://hooks.slack.com/services/T/B/x')
		with mock.patch('socket.getaddrinfo', return_value=METADATA), mock.patch.object(common_func.requests, 'post') as post, \
		     self.assertLogs('cvengine.hook_guard', 'WARNING'):
			common_func.send_slack_message('hello')
		post.assert_not_called()

	def test_a_public_hook_is_called(self):
		from cvengine import common_func
		self._row('https://hooks.slack.com/services/T/B/x')
		with mock.patch('socket.getaddrinfo', return_value=PUBLIC), mock.patch.object(common_func.requests, 'post') as post:
			common_func.send_slack_message('hello')
		post.assert_called_once()
