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
		for method, path in (('GET', 'ai'), ('PUT', 'ai'), ('GET', 'keys'), ('GET', 'engines'), ('PUT', 'proxy')):
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
		self.assertEqual(send(self.c, 'PUT', 'ai', {'auto_fire_engine_id': 99999})[0], 400)

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

	def test_engines_crud_and_safe_delete(self):
		status, e = send(self.c, 'POST', 'engines', {'name': 'Mine', 'yaml': GOOD_YAML})
		self.assertEqual(status, 201)
		self.assertEqual(send(self.c, 'POST', 'engines', {'name': 'bad', 'yaml': 'a: [unclosed'})[0], 400)
		self.assertEqual(send(self.c, 'POST', 'engines', {'name': 'list', 'yaml': '- a\n- b'})[0], 400)
		self.assertEqual(send(self.c, 'POST', 'engines', {'name': '', 'yaml': GOOD_YAML})[0], 400)
		self.assertEqual(send(self.c, 'PUT', f"engines/{e['id']}", {'name': 'Renamed'})[1]['name'], 'Renamed')
		# an engine with scan history cannot be deleted (the FK cascades)
		now = timezone.now()
		project = Project.objects.create(name='P', slug='p-s', insert_date=now)
		domain = Domain.objects.create(name='s.example', project=project, insert_date=now)
		ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.get(id=e['id']), start_scan_date=now)
		self.assertEqual(send(self.c, 'DELETE', f"engines/{e['id']}")[0], 409)
		self.assertEqual(ScanHistory.objects.count(), 1)
		ScanHistory.objects.all().delete()
		self.assertEqual(send(self.c, 'DELETE', f"engines/{e['id']}")[0], 200)
		self.assertEqual(send(self.c, 'DELETE', 'engines/999999')[0], 404)

	def test_auto_fire_engine_cannot_be_deleted(self):
		engine = EngineType.objects.create(engine_name='AF', yaml_configuration=GOOD_YAML)
		send(self.c, 'PUT', 'ai', {'auto_fire_engine_id': engine.id})
		self.assertEqual(send(self.c, 'DELETE', f'engines/{engine.id}')[0], 409)

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
