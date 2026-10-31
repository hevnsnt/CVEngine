import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from dashboard.models import AIProviderSettings, ChaosAPIKey, Org, OrgMembership, Project
from scanEngine.models import EngineType, Notification, Proxy
from startScan.models import ScanHistory
from targetApp.models import Domain
from tests.test_tenancy import client_for

GOOD_YAML = 'subdomain_discovery:\n  uses_tools: [subfinder]\n'


def send(client, method, path, body=None):
	fn = getattr(client, method.lower())
	kwargs = {'content_type': 'application/json'}
	r = fn(f'/cve/api/settings/{path}', json.dumps(body) if body is not None else None, **kwargs) if method != 'GET' else fn(f'/cve/api/settings/{path}')
	return r.status_code, (r.json() if r.content else None)


class SettingsApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.root = User.objects.create_superuser('sroot', 's@x.io', 'x')
		cls.admin = User.objects.create_user('sadmin', password='x')
		org = Org.objects.create(name='S', slug='s')
		OrgMembership.objects.create(user=cls.admin, org=org, role='admin')

	def setUp(self):
		self.c = client_for(self.root)

	def test_superuser_only(self):
		other = client_for(self.admin)  # org admin is still not a superuser
		for method, path in (('GET', 'ai'), ('PUT', 'ai'), ('GET', 'keys'), ('GET', 'scan_policy'), ('PUT', 'proxy')):
			self.assertEqual(send(other, method, path, {} if method == 'PUT' else None)[0], 403, path)
		self.assertEqual(other.get('/cve/settings/').status_code, 403)
		self.assertEqual(self.c.get('/cve/settings/').status_code, 200)
		self.assertEqual(self.client.get('/cve/api/settings/ai').status_code, 302)  # anonymous

	def test_ai_settings_roundtrip_and_secret_is_write_only(self):
		status, data = send(self.c, 'PUT', 'ai', {'provider': 'anthropic', 'api_key': 'sk-ant-secret-123', 'enabled': True,
			'auto_fire': True, 'auto_fire_max_scans': 99999})
		self.assertEqual(status, 200)
		self.assertTrue(data['has_key'])
		self.assertNotIn('sk-ant-secret-123', json.dumps(data))
		self.assertEqual(data['auto_fire_max_scans'], 5000)  # clamped
		send(self.c, 'PUT', 'ai', {'model': 'claude-x', 'api_key': ''})  # blank keeps the key
		cfg = AIProviderSettings.objects.get()
		self.assertEqual((cfg.api_key, cfg.model), ('sk-ant-secret-123', 'claude-x'))
		self.assertNotIn('sk-ant-secret-123', json.dumps(send(self.c, 'GET', 'ai')[1]))
		self.assertEqual(send(self.c, 'PUT', 'ai', {'provider': 'bogus'})[0], 400)

	def test_the_ai_planning_budget_is_a_setting(self):
		data = send(self.c, 'GET', 'ai')[1]
		self.assertEqual((data['plan_daily_total'], data['plan_daily_per_project']), (200, 20))
		status, data = send(self.c, 'PUT', 'ai', {'plan_daily_total': 500, 'plan_daily_per_project': '40'})
		self.assertEqual((status, data['plan_daily_total'], data['plan_daily_per_project']), (200, 500, 40))
		for bad in ({'plan_daily_total': -1}, {'plan_daily_per_project': 'lots'}, {'plan_daily_total': 100001}):
			self.assertEqual(send(self.c, 'PUT', 'ai', bad)[0], 400, bad)
		self.assertEqual(AIProviderSettings.objects.get().plan_daily_total, 500)

	def test_all_nuclei_templates_is_on_until_a_superuser_turns_it_off(self):
		self.assertTrue(send(self.c, 'GET', 'scan_policy')[1]['nuclei_all_templates'])
		self.assertEqual(send(client_for(self.admin), 'PUT', 'scan_policy', {'nuclei_all_templates': False})[0], 403)
		self.assertEqual(send(self.c, 'PUT', 'scan_policy', {'nuclei_all_templates': 'yes'})[0], 400)
		self.assertFalse(send(self.c, 'PUT', 'scan_policy', {'nuclei_all_templates': False})[1]['nuclei_all_templates'])
		from dashboard.models import AuditLog
		self.assertTrue(AuditLog.objects.filter(action='scan_policy.nuclei_all_templates', target='off').exists())
		self.assertTrue(send(self.c, 'PUT', 'scan_policy', {'nuclei_all_templates': True})[1]['nuclei_all_templates'])

	def test_a_stored_ai_key_is_never_kept_for_a_different_address_or_provider(self):
		send(self.c, 'PUT', 'ai', {'provider': 'openai', 'base_url': 'https://llm.example.com/v1', 'api_key': 'sk-keep-me'})
		send(self.c, 'PUT', 'ai', {'model': 'm2'})  # nothing about the connection changed: the key stays
		self.assertEqual(AIProviderSettings.objects.get().api_key, 'sk-keep-me')
		send(self.c, 'PUT', 'ai', {'base_url': 'https://evil.example.net/v1'})  # a new address without a new key: the old key is dropped
		self.assertEqual(AIProviderSettings.objects.get().api_key, '')
		send(self.c, 'PUT', 'ai', {'base_url': 'https://llm.example.com/v1', 'api_key': 'sk-second'})
		send(self.c, 'PUT', 'ai', {'provider': 'anthropic'})  # another provider without a new key
		self.assertEqual(AIProviderSettings.objects.get().api_key, '')

	def test_a_stored_key_follows_the_host_for_every_provider_the_vendor_address_included(self):
		def key():
			return AIProviderSettings.objects.get().api_key

		def fresh(provider, base_url=''):
			AIProviderSettings.objects.all().delete()
			send(self.c, 'PUT', 'ai', {'provider': provider, 'base_url': base_url, 'api_key': 'sk-vendor-key'})
		for provider in ('openai', 'anthropic'):
			fresh(provider)  # no Base URL: the vendor's own address
			send(self.c, 'PUT', 'ai', {'base_url': 'https://gateway.example.net'})
			self.assertEqual(key(), '', f'{provider}: a new host is a new service')
			fresh(provider, 'https://gateway.example.net/v1')
			send(self.c, 'PUT', 'ai', {'base_url': ''})  # back to the vendor: another host again
			self.assertEqual(key(), '', provider)
			fresh(provider, 'https://gateway.example.net/v1')
			send(self.c, 'PUT', 'ai', {'base_url': 'https://GATEWAY.example.net/v1/', 'model': 'm'})  # the same host, spelled another way
			self.assertEqual(key(), 'sk-vendor-key', provider)
			send(self.c, 'PUT', 'ai', {'base_url': 'https://gateway.example.net:8443/v1'})  # another port
			self.assertEqual(key(), '', provider)
		fresh('openai')
		send(self.c, 'PUT', 'ai', {'base_url': 'https://api.openai.com/v1'})  # the vendor's own address written out is not a new service
		self.assertEqual(key(), 'sk-vendor-key')
		fresh('openai')
		self.assertEqual(send(self.c, 'PUT', 'ai', {'base_url': 'https://api.openai.com.evil.example.net/v1'})[0], 200)
		self.assertEqual(key(), '')
		fresh('vllm', 'http://h:8000/v1')
		send(self.c, 'PUT', 'ai', {'base_url': 'http://h:8001/v1'})
		self.assertEqual(key(), '')
		fresh('openai')
		send(self.c, 'PUT', 'ai', {'base_url': 'https://other.example.net/v1', 'api_key': 'sk-typed-for-it'})  # a key typed with the new host is kept
		self.assertEqual(key(), 'sk-typed-for-it')

	def test_every_provider_takes_a_base_url_and_refuses_a_metadata_address(self):
		for provider in ('anthropic', 'openai', 'openrouter', 'ollama', 'vllm', 'lmstudio'):
			status, data = send(self.c, 'PUT', 'ai', {'provider': provider, 'base_url': 'https://gateway.example.net'})
			self.assertEqual((status, data['base_url']), (200, 'https://gateway.example.net'), provider)
			self.assertEqual(send(self.c, 'PUT', 'ai', {'provider': provider, 'base_url': 'http://169.254.169.254/v1'})[0], 400, provider)
			self.assertEqual(send(self.c, 'PUT', 'ai', {'provider': provider, 'base_url': 'ftp://gateway.example.net'})[0], 400, provider)

	def test_model_listing_does_not_send_the_stored_key_to_another_address(self):
		from unittest import mock
		send(self.c, 'PUT', 'ai', {'provider': 'openai', 'base_url': 'https://llm.example.com/v1', 'api_key': 'sk-keep-me'})
		with mock.patch('reNgine.ai_providers.get_provider') as get_provider:
			get_provider.return_value.list_models.return_value = []
			send(self.c, 'POST', 'ai/models', {'provider': 'openai', 'base_url': 'https://evil.example.net/v1'})
			self.assertIsNone(get_provider.call_args.kwargs['api_key'])
			send(self.c, 'POST', 'ai/models', {'provider': 'openai'})
			self.assertEqual(get_provider.call_args.kwargs['api_key'], 'sk-keep-me')

	def test_model_listing_refuses_metadata_addresses_like_saving_does(self):
		from unittest import mock
		with mock.patch('reNgine.ai_providers.get_provider') as get_provider:
			for url in ('http://169.254.169.254/latest', 'http://2852039166/', 'http://metadata.google.internal/'):
				status, _ = send(self.c, 'POST', 'ai/models', {'provider': 'openai', 'base_url': url})
				self.assertEqual(status, 400, url)
			# a name that resolves to a link-local address is refused too
			with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('169.254.169.254', 0))]):
				self.assertEqual(send(self.c, 'POST', 'ai/models', {'provider': 'openai', 'base_url': 'http://169.254.169.254.nip.example.test/'})[0], 400)
				self.assertEqual(send(self.c, 'PUT', 'ai', {'base_url': 'http://169.254.169.254.nip.example.test/'})[0], 400)
			get_provider.assert_not_called()

	def test_api_vault(self):
		status, data = send(self.c, 'PUT', 'keys', {'chaos': {'key': 'chaos-secret'}, 'hackerone': {'key': 'h1', 'username': 'bob'}})
		self.assertEqual((status, data['chaos']['has_key'], data['hackerone']['username']), (200, True, 'bob'))
		self.assertNotIn('chaos-secret', json.dumps(data))
		send(self.c, 'PUT', 'keys', {'chaos': {'key': ''}})
		self.assertEqual(ChaosAPIKey.objects.get().key, 'chaos-secret')
		self.assertFalse(send(self.c, 'PUT', 'keys', {'chaos': {'clear': True}})[1]['chaos']['has_key'])

	def test_notifications_secrets_write_only(self):
		status, data = send(self.c, 'PUT', 'notifications', {'send_to_slack': True, 'slack_hook_url': 'https://hooks.slack.com/x/secret'})
		self.assertTrue(data['send_to_slack'] and data['has_slack_hook_url'])
		self.assertNotIn('secret', json.dumps(data))
		send(self.c, 'PUT', 'notifications', {'slack_hook_url': ''})
		self.assertEqual(Notification.objects.get().slack_hook_url, 'https://hooks.slack.com/x/secret')
		send(self.c, 'PUT', 'notifications', {'clear_slack_hook_url': True})
		self.assertEqual(Notification.objects.get().slack_hook_url, '')

	def test_proxy_validation(self):
		self.assertEqual(send(self.c, 'PUT', 'proxy', {'use_proxy': True, 'proxies': 'http://1.2.3.4:8080\nsocks5://h:1080'})[0], 200)
		self.assertEqual(Proxy.objects.get().proxies, 'http://1.2.3.4:8080\nsocks5://h:1080')
		self.assertEqual(send(self.c, 'PUT', 'proxy', {'proxies': 'not a proxy'})[0], 400)
		self.assertEqual(send(self.c, 'PUT', 'proxy', {'proxies': 'file:///etc/passwd'})[0], 400)

	def test_proxy_passwords_are_never_returned_and_an_unchanged_masked_line_keeps_them(self):
		status, data = send(self.c, 'PUT', 'proxy', {'use_proxy': True, 'proxies': 'http://bob:hunter2@203.0.113.5:8080\nsocks5://203.0.113.6:1080'})
		self.assertEqual(status, 200)
		self.assertNotIn('hunter2', json.dumps(data))
		self.assertEqual(data['proxies'], 'http://bob:***@203.0.113.5:8080\nsocks5://203.0.113.6:1080')
		self.assertTrue(data['has_credentials'])
		got = send(self.c, 'GET', 'proxy')[1]
		self.assertNotIn('hunter2', json.dumps(got))
		# the page sends the masked text back unchanged (plus a new line): the stored password stays
		send(self.c, 'PUT', 'proxy', {'proxies': got['proxies'] + '\nhttp://203.0.113.7:3128'})
		self.assertEqual(Proxy.objects.get().proxies, 'http://bob:hunter2@203.0.113.5:8080\nsocks5://203.0.113.6:1080\nhttp://203.0.113.7:3128')
		# a masked line that matches nothing stored is refused, never saved with the literal ***
		self.assertEqual(send(self.c, 'PUT', 'proxy', {'proxies': 'http://eve:***@203.0.113.9:8080'})[0], 400)
		self.assertNotIn('***', Proxy.objects.get().proxies)
		# a new password replaces the old one
		send(self.c, 'PUT', 'proxy', {'proxies': 'http://bob:newpass@203.0.113.5:8080'})
		self.assertEqual(Proxy.objects.get().proxies, 'http://bob:newpass@203.0.113.5:8080')

	def test_the_inherited_engine_editor_is_gone_and_the_ai_settings_no_longer_carry_an_engine(self):
		# the engine YAML was never read by anything; its create, update and delete endpoints and the auto-fire engine setting are removed
		for method, path in (('GET', 'engines'), ('POST', 'engines'), ('PUT', 'engines/1'), ('DELETE', 'engines/1')):
			self.assertEqual(send(self.c, method, path, {} if method in ('POST', 'PUT') else None)[0], 404, f'{method} {path}')
		self.assertNotIn('auto_fire_engine_id', send(self.c, 'GET', 'ai')[1])

	def test_scans_are_filed_under_the_recommended_engine_not_whichever_default_comes_first(self):
		from cveFeed.discovery import RECOMMENDED_ENGINE, pick_engine
		# the inherited engines are all flagged default; the first of them used to label every scan "Full Scan"
		full = EngineType.objects.create(engine_name='Full Scan', yaml_configuration=GOOD_YAML, default_engine=True)
		recommended = EngineType.objects.create(engine_name=RECOMMENDED_ENGINE, yaml_configuration=GOOD_YAML, default_engine=True)
		self.assertLess(full.id, recommended.id)
		self.assertEqual(pick_engine().id, recommended.id)
		recommended.delete()
		self.assertEqual(pick_engine().id, EngineType.objects.filter(default_engine=True).order_by('id').first().id)  # no recommended one: the lowest id, always

	def test_ip_allowlist_requires_an_entry_and_your_own_ip_before_enabling(self):
		from reNgine import ip_allowlist as ipa
		self.addCleanup(ipa.invalidate_cache)
		self.assertEqual(send(self.c, 'PUT', 'ip_allowlist', {'enabled': True})[0], 400)  # no entries yet
		status, e = send(self.c, 'POST', 'ip_allowlist/entries', {'cidr': '10.0.0.0/8', 'label': 'office'})
		self.assertEqual(status, 201)
		# test client's REMOTE_ADDR (127.0.0.1) is not covered by 10.0.0.0/8
		status, data = send(self.c, 'PUT', 'ip_allowlist', {'enabled': True})
		self.assertEqual((status, data['error']), (400, data.get('error')))
		self.assertIn('not on the allowlist', data['error'])
		send(self.c, 'POST', 'ip_allowlist/entries', {'cidr': '127.0.0.1', 'label': 'me'})
		status, data = send(self.c, 'PUT', 'ip_allowlist', {'enabled': True})
		self.assertEqual((status, data['enabled']), (200, True))

	def test_ip_allowlist_rejects_bad_cidr_and_lists_entries(self):
		from reNgine import ip_allowlist as ipa
		self.addCleanup(ipa.invalidate_cache)
		self.assertEqual(send(self.c, 'POST', 'ip_allowlist/entries', {'cidr': 'not-an-ip'})[0], 400)
		send(self.c, 'POST', 'ip_allowlist/entries', {'cidr': '203.0.113.4', 'label': 'vpn'})
		status, data = send(self.c, 'GET', 'ip_allowlist')
		self.assertEqual((status, data['enabled'], [e['cidr'] for e in data['entries']]), (200, False, ['203.0.113.4/32']))
		self.assertEqual(data['your_ip'], '127.0.0.1')

	def test_ip_allowlist_delete_guard_prevents_self_lockout(self):
		from reNgine import ip_allowlist as ipa
		self.addCleanup(ipa.invalidate_cache)
		send(self.c, 'POST', 'ip_allowlist/entries', {'cidr': '127.0.0.1'})
		send(self.c, 'PUT', 'ip_allowlist', {'enabled': True})
		entry_id = send(self.c, 'GET', 'ip_allowlist')[1]['entries'][0]['id']
		status, data = send(self.c, 'DELETE', f'ip_allowlist/entries/{entry_id}')
		self.assertEqual((status, 'lock your current IP out' in data['error']), (400, True))
		send(self.c, 'POST', 'ip_allowlist/entries', {'cidr': '10.0.0.0/8', 'label': 'other'})
		# now 127.0.0.1 still covered by the entry being deleted is not required since another remains? no:
		# deleting the 127.0.0.1 entry would still lock us out even with the unrelated 10.0.0.0/8 entry present
		self.assertEqual(send(self.c, 'DELETE', f'ip_allowlist/entries/{entry_id}')[0], 400)

	def test_unknown_route_and_method(self):
		self.assertEqual(send(self.c, 'GET', 'nope')[0], 404)
		self.assertEqual(send(self.c, 'DELETE', 'ai')[0], 405)


class CeleryDurabilityTests(TestCase):
	def test_a_dead_worker_gives_its_task_back_the_same_day_and_discovery_is_acked_late(self):
		from django.conf import settings
		from cveFeed.tasks import run_bbot_discovery
		self.assertEqual(settings.CELERY_BROKER_TRANSPORT_OPTIONS['visibility_timeout'], 12 * 3600)
		self.assertTrue(run_bbot_discovery.acks_late)
		self.assertTrue(run_bbot_discovery.reject_on_worker_lost)
