import traceback
from types import SimpleNamespace
from unittest import mock

import requests
from django.test import TestCase

from reNgine import common_func, tasks
from scanEngine.models import Notification

TOKEN = '123456:SECRET-bot-token'
SLACK = 'https://hooks.slack.test/services/T000/B000/SLACKSECRET'
DISCORD = 'https://discord.test/api/webhooks/42/DISCORDSECRET'
LARK = 'https://open.lark.test/hook/LARKSECRET'
SECRETS = ('SECRET-bot-token', 'SLACKSECRET', 'DISCORDSECRET', 'LARKSECRET')


def leaky(url):
	"""A requests error the way requests writes it: with the full URL inside."""
	return requests.exceptions.ConnectionError(f'HTTPSConnectionPool: Max retries exceeded with url: {url} (Caused by timeout)')


class WebhookErrorTests(TestCase):
	"""Verdict 9: a webhook URL or bot token never appears in an exception message, its chain or its traceback."""

	def setUp(self):
		Notification.objects.create(send_to_telegram=True, telegram_bot_token=TOKEN, telegram_bot_chat_id='99', send_to_slack=True,
			slack_hook_url=SLACK, send_to_discord=True, discord_hook_url=DISCORD, send_to_lark=True, lark_hook_url=LARK)

	def assert_clean(self, error):
		text = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
		for secret in SECRETS:
			self.assertNotIn(secret, text)
			self.assertNotIn(secret, str(error))
		self.assertIsNone(error.__cause__)
		self.assertTrue(error.__suppress_context__)

	def test_telegram(self):
		with mock.patch('requests.get', side_effect=lambda url, **k: (_ for _ in ()).throw(leaky(url))):
			with self.assertRaises(common_func.NotificationError) as ctx:
				common_func.send_telegram_message('hi')
		self.assert_clean(ctx.exception)
		self.assertEqual(str(ctx.exception), 'telegram notification failed (ConnectionError)')

	def test_slack_and_lark(self):
		for sender, channel in ((common_func.send_slack_message, 'slack'), (common_func.send_lark_message, 'lark')):
			with mock.patch('requests.post', side_effect=lambda url=None, **k: (_ for _ in ()).throw(leaky(url))):
				with self.assertRaises(common_func.NotificationError) as ctx:
					sender('hi')
			self.assert_clean(ctx.exception)
			self.assertTrue(str(ctx.exception).startswith(f'{channel} notification failed'))

	def test_discord(self):
		with mock.patch.object(common_func.DiscordWebhook, 'execute', side_effect=leaky(DISCORD)):
			with self.assertRaises(common_func.NotificationError) as ctx:
				common_func.send_discord_message('hi')
		self.assert_clean(ctx.exception)


	def test_an_http_status_is_kept_because_it_is_not_a_secret(self):
		response = mock.Mock(status_code=401)
		error = requests.exceptions.HTTPError(f'401 Client Error for url: {SLACK}', response=response)
		with mock.patch('requests.post', side_effect=error):
			with self.assertRaises(common_func.NotificationError) as ctx:
				common_func.send_slack_message('hi')
		self.assertEqual(str(ctx.exception), 'slack notification failed (HTTPError, HTTP 401)')
		self.assert_clean(ctx.exception)

	def test_a_channel_that_is_off_still_sends_nothing_and_raises_nothing(self):
		Notification.objects.update(send_to_slack=False)
		with mock.patch('requests.post', side_effect=AssertionError('no network')):
			self.assertIsNone(common_func.send_slack_message('hi'))

	def test_a_successful_send_returns_normally(self):
		with mock.patch('requests.post', return_value=mock.Mock(status_code=200)) as post:
			common_func.send_slack_message('hi')
		self.assertEqual(post.call_args.kwargs['url'], SLACK)

	def test_the_pipeline_notifier_logs_the_type_only(self):
		from cveFeed import notify
		import logging
		with mock.patch('requests.post', side_effect=lambda url=None, **k: (_ for _ in ()).throw(leaky(url))), \
				mock.patch('requests.get', side_effect=lambda url, **k: (_ for _ in ()).throw(leaky(url))), \
				self.assertLogs('cveFeed.notify', level=logging.WARNING) as logs:
			notify.template_hits([('CVE-2099-1', 'a.example.test')])
		for secret in SECRETS:
			self.assertNotIn(secret, '\n'.join(logs.output))


RAN = []


def _ran():
	RAN.append('code ran')


class _Forged:
	def __reduce__(self):
		return (_ran, ())


class DiscordCacheTests(TestCase):
	"""The Discord cache sits in Redis: nothing in it is trusted unless this installation signed it, and the hook URL is not in it."""

	def setUp(self):
		Notification.objects.create(send_to_discord=True, discord_hook_url=DISCORD)
		self.store = {}
		fake = mock.Mock()
		fake.get.side_effect = self.store.get
		fake.set.side_effect = self.store.__setitem__
		patcher = mock.patch.object(common_func, 'DISCORD_WEBHOOKS_CACHE', fake)
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_a_signed_object_round_trips_and_anything_else_is_a_miss(self):
		sealed = common_func._seal({'a': 1})
		self.assertEqual(common_func._unseal(sealed), {'a': 1})
		self.assertIsNone(common_func._unseal(sealed[:-1] + b'x'))  # altered
		self.assertIsNone(common_func._unseal(b'\x80\x04' + b'plain pickle'))  # not signed
		self.assertIsNone(common_func._unseal(None))
		self.assertIsNone(common_func._unseal(b'short'))

	def test_a_forged_pickle_in_redis_is_never_run(self):
		import pickle
		forged = pickle.dumps(_Forged())
		RAN.clear()
		self.store['Scan finished'] = forged
		self.store['Scan finished_embed'] = forged
		with mock.patch.object(common_func.DiscordWebhook, 'execute', return_value=SimpleNamespace(status_code=200, content=b'{}')):
			common_func.send_discord_message('hi', title='Scan finished', fields={'k': 'v'})
		self.assertEqual(RAN, [])

	def test_the_hook_url_is_not_stored_and_an_update_edits_the_first_message(self):
		first = SimpleNamespace(status_code=200, content=b'{}')
		with mock.patch.object(common_func.DiscordWebhook, 'execute', return_value=first):
			common_func.send_discord_message('x', title='Scan finished', fields={'host': 'a.example'})
		self.assertTrue(self.store)
		self.assertFalse([k for k, v in self.store.items() if b'DISCORDSECRET' in v])
		with mock.patch.object(common_func.DiscordWebhook, 'edit', return_value=mock.Mock(status_code=200, content=b'{}')) as edit, \
				mock.patch.object(common_func.DiscordWebhook, 'execute', side_effect=AssertionError('must edit, not send again')):
			common_func.send_discord_message('x', title='Scan finished', fields={'host': 'b.example'})
		self.assertEqual(edit.call_count, 1)
