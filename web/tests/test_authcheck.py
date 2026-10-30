import datetime
import http.server
import json
import os
import stat
import tempfile
import threading
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import auth_checks, auth_nuclei, auth_routes, nuclei_scan, route_auth as ra, templategen
from cveFeed.auth_checks import AuthScope, CredentialError
from cveFeed.models import AgentActivity, AuthCredential, HostExclusion, RouteAuth, ScanControl, ServiceRun
from reNgine import crypto_fields
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, rpc, tool_call

SECRET = 'Bearer sk-live-4F9aQ7xT2mZ8'
TOKEN = 'sk-live-4F9aQ7xT2mZ8'  # the part of SECRET after its scheme word, which a page may echo alone
COOKIE = 'sid=s3cr3tSESSION99x; theme=dark'
COOKIE_VALUE = 's3cr3tSESSION99x'
KEY_A, KEY_B = 'a' * 40, 'b' * 40
MISSING = object()  # a body field left out on purpose


def everything_stored():
	"""Every piece of text the app keeps about a scan that could carry a leaked value, as one string."""
	parts = [json.dumps(list(AgentActivity.objects.values_list('message', 'detail')), default=str),
		json.dumps(list(RouteAuth.objects.values_list('evidence', 'title', 'redirect_to')), default=str),
		json.dumps(list(AuditLog.objects.values_list('action', 'target', 'detail')), default=str),
		json.dumps(list(ServiceRun.objects.values_list('service', 'asset')), default=str)]
	for v in Vulnerability.objects.all():
		parts.append(json.dumps([v.name, v.description, v.request, v.response, v.curl_command, v.extracted_results, v.matcher_name,
			v.http_url, [t.name for t in v.tags.all()]], default=str))
	return '\n'.join(parts)


class Fixture(TestCase):
	"""One project with two targets, and the people around it: an App Admin, the organization's admin and member, a project member, an
	auditor, and the admin of another organization."""

	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org, cls.other_org = Org.objects.create(name='AC', slug='ac'), Org.objects.create(name='Other', slug='acother')
		cls.project = Project.objects.create(name='AC', slug='acp', insert_date=now, org=cls.org)
		cls.other_project = Project.objects.create(name='Other', slug='acother-p', insert_date=now, org=cls.other_org)
		cls.domain = Domain.objects.create(name='app.example.test', project=cls.project, insert_date=now)
		cls.sibling = Domain.objects.create(name='shop.example.test', project=cls.project, insert_date=now)
		cls.foreign = Domain.objects.create(name='other.example.test', project=cls.other_project, insert_date=now)
		cls.users = {}
		for name in ('root', 'orgadmin', 'member', 'pmember', 'auditor', 'outsider'):
			cls.users[name] = User.objects.create_user(f'ac_{name}', password='x', is_superuser=name == 'root')
		OrgMembership.objects.create(user=cls.users['orgadmin'], org=cls.org, role='admin')
		OrgMembership.objects.create(user=cls.users['member'], org=cls.org, role='user')
		ProjectMembership.objects.create(user=cls.users['pmember'], project=cls.project, role='user')
		OrgMembership.objects.create(user=cls.users['auditor'], org=cls.org, role='audit')
		OrgMembership.objects.create(user=cls.users['outsider'], org=cls.other_org, role='admin')
		cls.tokens = {n: create_token(u, n)[1] for n, u in cls.users.items()}
		cls.tokens['orgadmin_ro'] = create_token(cls.users['orgadmin'], 'ro', read_only=True)[1]

	def make(self, domain=None, host='app.example.test', origins=('https:443',), headers=None, cookie=COOKIE, expires=None, label='test account'):
		return AuthCredential.objects.create(
			project=(domain or self.domain).project, domain=domain or self.domain, host=host, label=label, origins=list(origins),
			secret={'headers': headers if headers is not None else [['Authorization', SECRET]], 'cookie': cookie}, expires_at=expires)


class ValidationTests(SimpleTestCase):
	def test_headers_are_validated_without_echoing_a_value(self):
		clean = auth_checks.clean_headers([{'name': 'Authorization', 'secret': SECRET}, {'name': 'X-Api-Key', 'secret': 'abcdef123456'}])
		self.assertEqual(clean, [['Authorization', SECRET], ['X-Api-Key', 'abcdef123456']])
		bad = [([{'name': 'Host', 'secret': 'evil.test.example'}], 'frames the request'),
			([{'name': 'Content-Length', 'secret': '123456789'}], 'frames the request'),
			([{'name': 'Cookie', 'secret': 'a=bbbbbbbb'}], 'cookie field'),
			([{'name': 'X-A', 'secret': 'short'}], 'characters'),
			([{'name': 'X-A', 'secret': 'line1111\r\nX-Evil: 1'}], 'one line'),
			([{'name': 'X A', 'secret': 'abcdefgh'}], 'header name'),
			([{'name': 'X-A', 'secret': 'abcdefgh'}, {'name': 'x-a', 'secret': 'abcdefgh'}], 'twice'),
			([{'name': 'X-A', 'secret': ''}], 'needs a value'),
			([{'name': f'X-{i}', 'secret': 'abcdefgh'} for i in range(11)], 'at most')]
		for headers, expect in bad:
			with self.assertRaises(CredentialError) as ctx:
				auth_checks.clean_headers(headers)
			self.assertIn(expect, str(ctx.exception))
			self.assertNotIn('evil.test.example', str(ctx.exception))

	def test_a_blank_value_keeps_only_a_name_already_stored(self):
		self.assertEqual(auth_checks.clean_headers([{'name': 'authorization', 'secret': ''}], [('Authorization', SECRET)]), [['Authorization', SECRET]])
		with self.assertRaises(CredentialError):
			auth_checks.clean_headers([{'name': 'X-New', 'secret': ''}], [('Authorization', SECRET)])

	def test_cookie_origins_host_and_expiry(self):
		self.assertEqual(auth_checks.clean_cookie('Cookie: ' + COOKIE), COOKIE)
		for bad in ('justavalue', 'a=b\r\nX: y', 'x=1'):
			with self.assertRaises(CredentialError):
				auth_checks.clean_cookie(bad)
		self.assertIsNone(auth_checks.clean_cookie(None))
		self.assertEqual(auth_checks.clean_origins(None), ['https:443'])
		self.assertEqual(auth_checks.clean_origins(['HTTPS:8443', 'https:8443', 'http:80']), ['https:8443', 'http:80'])
		for bad in (['ftp:21'], ['https'], ['https:0'], ['https:70000'], 'https:443', ['https:443'] * 1 + ['x'] * 8):
			with self.assertRaises(CredentialError):
				auth_checks.clean_origins(bad)
		self.assertEqual(auth_checks.normalize_host(' App.Example.Test. '), 'app.example.test')
		self.assertEqual(auth_checks.normalize_host(''), '')
		for bad in ('https://app.example.test', 'app.example.test:8443', '*.example.test', 'a/b', 'bad host'):
			with self.assertRaises(CredentialError):
				auth_checks.normalize_host(bad)

	def test_each_expiry_choice_computes_its_expires_at(self):
		now = timezone.now()
		for choice in (30, 90, 120, '30', '90', '120', ' 90 '):
			days = int(str(choice).strip())
			self.assertEqual(auth_checks.compute_expiry(choice, now=now), now + datetime.timedelta(days=days), choice)
		for never in ('never', 'Never', ' NEVER '):
			self.assertIsNone(auth_checks.compute_expiry(never, now=now))

	def test_an_expiry_that_is_missing_or_not_one_of_the_choices_is_refused(self):
		for bad in (None, '', '   ', 0, 7, 31, 365, -30, '45', 'forever', 'none', '2030-01-31T17:00:00Z', 30.5, True, False, [30], {'days': 30}):
			with self.assertRaises(CredentialError, msg=repr(bad)) as ctx:
				auth_checks.compute_expiry(bad)
			self.assertIn('30, 90 or 120', str(ctx.exception))

	def test_the_scope_must_be_chosen_and_a_blank_host_never_means_the_whole_target(self):
		domain = SimpleNamespace(name='app.example.test', is_host_scoped=lambda: False)
		self.assertEqual(auth_checks.clean_scope('host', ' WWW.App.Example.Test ', domain), 'www.app.example.test')
		self.assertEqual(auth_checks.clean_scope('target', '', domain), '')
		self.assertEqual(auth_checks.clean_scope('Target', None, domain), '')
		for scope, host, expect in ((None, '', 'scope is required'), (None, 'app.example.test', 'scope is required'), ('', '', 'scope is required'),
				('all', '', 'scope is required'), ('host', '', 'needs a host'), ('host', '  ', 'needs a host'),
				('target', 'app.example.test', 'leave host blank'), ('host', 'www.other.example.test', 'not part of the target'),
				('host', '*.example.test', 'plain host name'), (['host'], 'app.example.test', 'scope is required')):
			with self.assertRaises(CredentialError, msg=(scope, host)) as ctx:
				auth_checks.clean_scope(scope, host, domain)
			self.assertIn(expect, str(ctx.exception))


class StorageTests(Fixture):
	def raw(self, cred):
		with connection.cursor() as cursor:
			cursor.execute('SELECT secret::text FROM "cveFeed_authcredential" WHERE id = %s', [cred.pk])
			return cursor.fetchone()[0]

	def test_the_database_holds_ciphertext_and_the_orm_reads_the_plaintext(self):
		cred = self.make()
		raw = self.raw(cred)
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE, 'Authorization', 'sid'):
			self.assertNotIn(plain, raw)
		self.assertIn('enc:v1:', raw)
		fresh = AuthCredential.objects.get(pk=cred.pk)
		self.assertEqual(auth_checks.stored_headers(fresh), [('Authorization', SECRET)])
		self.assertEqual(auth_checks.stored_cookie(fresh), COOKIE)

	def test_the_field_key_rotation_re_encrypts_stored_sign_ins(self):
		self.assertIn('AuthCredential', {m.__name__ for m, _ in crypto_fields.encrypted_fields()})
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_A}):
			cred = self.make()
			before = self.raw(cred)
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_B, 'CVENGINE_FIELD_KEY_PREVIOUS': KEY_A}):
			call_command('rotate_field_key', stdout=StringIO())
			after = self.raw(cred)
		self.assertNotEqual(before, after)
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_B, 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):
			self.assertEqual(auth_checks.stored_headers(AuthCredential.objects.get(pk=cred.pk)), [('Authorization', SECRET)])

	def test_the_masked_view_has_names_and_never_a_value(self):
		view = auth_checks.summary(self.make(expires=timezone.now() + datetime.timedelta(days=1)))
		self.assertEqual((view['header_names'], view['cookie_names'], view['state']), (['Authorization'], ['sid', 'theme'], 'active'))
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE, 'dark'):
			self.assertNotIn(plain, json.dumps(view))

	def test_an_expired_credential_reads_as_expired(self):
		view = auth_checks.summary(self.make(expires=timezone.now() - datetime.timedelta(minutes=1)))
		self.assertEqual((view['state'], view['expired'], view['days_left'], view['never_expires']), ('expired', True, 0, False))

	def test_the_masked_view_shows_the_days_left_and_a_deliberate_never(self):
		now = timezone.now()
		view = auth_checks.summary(self.make(host='a.app.example.test', expires=now + datetime.timedelta(days=29, hours=3)), now=now)
		self.assertEqual((view['days_left'], view['never_expires'], view['expires_at'] is not None), (30, False, True))
		view = auth_checks.summary(self.make(host='b.app.example.test', expires=now + datetime.timedelta(hours=2)), now=now)
		self.assertEqual(view['days_left'], 1)
		view = auth_checks.summary(self.make(host='c.app.example.test', expires=None))
		self.assertEqual((view['days_left'], view['never_expires'], view['expires_at']), (None, True, None))


class ApiTests(Fixture):
	url = '/api/v1/projects/acp'

	def put(self, who, body, target=None, **kw):
		return call(self.tokens[who], 'PUT', f'{self.url}/targets/{(target or self.domain).pk}/auth-credential', body)

	def body(self, **extra):
		body = {'label': 'staging test account', 'scope': 'host', 'host': 'app.example.test', 'headers': [{'name': 'Authorization', 'secret': SECRET}],
			'cookie_secret': COOKIE, 'expires': 30, **extra}
		return {k: v for k, v in body.items() if v is not MISSING}

	def test_create_list_replace_and_delete_never_return_a_value(self):
		status, created = self.put('orgadmin', self.body())
		self.assertEqual(status, 200, created)
		status, listed = call(self.tokens['orgadmin'], 'GET', f'{self.url}/auth-credentials')
		self.assertEqual(status, 200)
		row = listed['results'][0]
		self.assertEqual((row['header_names'], row['cookie_names'], row['origins'], row['scope']), (['Authorization'], ['sid', 'theme'], ['https:443'], 'host'))
		self.assertIn('low-privilege', listed['warning'])
		everything = json.dumps([created, listed])
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
			self.assertNotIn(plain, everything)
		# a replace with a blank secret keeps the stored value and a name left out is removed
		status, again = self.put('orgadmin', self.body(headers=[{'name': 'X-Api-Key', 'secret': 'zzzzzz999999'}], cookie_secret=''))
		self.assertEqual(status, 200, again)
		cred = AuthCredential.objects.get()
		self.assertEqual(auth_checks.stored_headers(cred), [('X-Api-Key', 'zzzzzz999999')])
		self.assertEqual(auth_checks.stored_cookie(cred), COOKIE)  # blank cookie keeps it
		self.put('orgadmin', self.body(headers=[{'name': 'x-api-key', 'secret': ''}], cookie_secret='', clear_cookie=True))
		cred = AuthCredential.objects.get()
		self.assertEqual((auth_checks.stored_headers(cred), auth_checks.stored_cookie(cred)), ([('X-Api-Key', 'zzzzzz999999')], ''))
		self.assertEqual(AuthCredential.objects.count(), 1)  # the same target and host replaced the row
		status, _ = call(self.tokens['orgadmin'], 'DELETE', f'{self.url}/auth-credentials/{cred.pk}')
		self.assertEqual((status, AuthCredential.objects.count()), (200, 0))

	def test_the_audit_log_records_names_only(self):
		self.put('orgadmin', self.body())
		cred = AuthCredential.objects.get()
		call(self.tokens['root'], 'DELETE', f'{self.url}/auth-credentials/{cred.pk}')
		rows = list(AuditLog.objects.filter(action__startswith='target.auth_credential'))
		self.assertEqual(sorted(r.action for r in rows), ['target.auth_credential.remove', 'target.auth_credential.set'])
		stored = json.dumps([[r.actor_name, r.target, r.detail] for r in rows])
		self.assertIn('Authorization', stored)
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
			self.assertNotIn(plain, stored)
		self.assertEqual({r.org_id for r in rows}, {self.org.pk})  # the organization's admins read their own trail

	def test_the_untrusted_certificate_switch_is_off_by_default_is_set_read_kept_and_audited(self):
		status, created = self.put('orgadmin', self.body())
		self.assertEqual((status, created['allow_untrusted_certificate']), (200, False))
		self.assertFalse(AuthCredential.objects.get().allow_untrusted_certificate)
		self.assertFalse(AuditLog.objects.filter(action='target.auth_credential.untrusted_certificate').exists())  # nothing changed
		status, on = self.put('orgadmin', self.body(allow_untrusted_certificate=True, headers=[{'name': 'Authorization', 'secret': ''}], cookie_secret=''))
		self.assertEqual((status, on['allow_untrusted_certificate']), (200, True))
		_status, listed = call(self.tokens['orgadmin'], 'GET', f'{self.url}/auth-credentials')
		self.assertIs(listed['results'][0]['allow_untrusted_certificate'], True)
		row, = AuditLog.objects.filter(action='target.auth_credential.untrusted_certificate')
		self.assertEqual((row.actor_name, row.org_id, row.detail['allow_untrusted_certificate']), ('ac_orgadmin', self.org.pk, True))
		# left out on a replace: the choice is kept, and keeping it adds no audit row
		self.put('orgadmin', self.body(headers=[{'name': 'Authorization', 'secret': ''}], cookie_secret=''))
		self.assertTrue(AuthCredential.objects.get().allow_untrusted_certificate)
		self.assertEqual(AuditLog.objects.filter(action='target.auth_credential.untrusted_certificate').count(), 1)
		self.put('root', self.body(allow_untrusted_certificate=False, headers=[{'name': 'Authorization', 'secret': ''}], cookie_secret=''))
		self.assertFalse(AuthCredential.objects.get().allow_untrusted_certificate)
		self.assertEqual(AuditLog.objects.filter(action='target.auth_credential.untrusted_certificate').count(), 2)

	def test_the_untrusted_certificate_switch_must_be_a_boolean_and_is_admin_only(self):
		for bad in ('yes', 1, None, 'true'):
			status, data = self.put('orgadmin', self.body(allow_untrusted_certificate=bad))
			self.assertEqual(status, 400, bad)
			self.assertIn('true or false', json.dumps(data))
		self.assertEqual(AuthCredential.objects.count(), 0)
		for who in ('member', 'pmember', 'auditor'):
			self.assertEqual(self.put(who, self.body(allow_untrusted_certificate=True))[0], 403, who)
		self.assertEqual(AuthCredential.objects.count(), 0)

	def test_the_mcp_list_shows_the_switch(self):
		self.make()
		AuthCredential.objects.update(allow_untrusted_certificate=True)
		error, listed = tool_call(self.tokens['orgadmin'], 'list_auth_credentials', {'project': 'acp'})
		self.assertFalse(error, listed)
		self.assertIs(listed['results'][0]['allow_untrusted_certificate'], True)

	def test_only_an_app_admin_or_the_projects_org_admin_may_touch_it(self):
		cred = self.make()
		for who in ('member', 'pmember', 'auditor'):
			self.assertEqual(call(self.tokens[who], 'GET', f'{self.url}/auth-credentials')[0], 403, who)
			self.assertEqual(self.put(who, self.body())[0], 403, who)
			self.assertEqual(call(self.tokens[who], 'DELETE', f'{self.url}/auth-credentials/{cred.pk}')[0], 403, who)
		self.assertEqual(call(self.tokens['outsider'], 'GET', f'{self.url}/auth-credentials')[0], 404)  # the other organization cannot see the project
		self.assertEqual(self.put('outsider', self.body())[0], 404)
		self.assertEqual(call(self.tokens['outsider'], 'DELETE', f'{self.url}/auth-credentials/{cred.pk}')[0], 404)
		self.assertEqual(call(None, 'GET', f'{self.url}/auth-credentials')[0], 401)
		self.assertEqual(AuthCredential.objects.count(), 1)
		self.assertEqual(call(self.tokens['root'], 'GET', f'{self.url}/auth-credentials')[0], 200)
		self.assertEqual(call(self.tokens['orgadmin'], 'GET', f'{self.url}/auth-credentials')[0], 200)

	def test_a_read_only_token_reads_names_but_cannot_change_anything(self):
		cred = self.make()
		self.assertEqual(call(self.tokens['orgadmin_ro'], 'GET', f'{self.url}/auth-credentials')[0], 200)
		self.assertEqual(self.put('orgadmin_ro', self.body())[0], 403)
		self.assertEqual(call(self.tokens['orgadmin_ro'], 'DELETE', f'{self.url}/auth-credentials/{cred.pk}')[0], 403)
		self.assertEqual(AuthCredential.objects.count(), 1)

	def test_a_target_of_another_project_and_the_all_projects_view_are_refused(self):
		self.assertEqual(self.put('root', self.body(scope='target', host=''), target=self.foreign)[0], 404)
		self.assertEqual(call(self.tokens['root'], 'GET', '/api/v1/projects/_all/auth-credentials')[0], 400)
		self.assertEqual(self.make(self.foreign, host='').project, self.other_project)
		self.assertEqual(call(self.tokens['orgadmin'], 'GET', f'{self.url}/auth-credentials')[1]['results'], [])  # another project's rows never show

	def test_rejections_are_400s_that_do_not_echo_the_value(self):
		bad = [self.body(host='www.other.example.test'), self.body(host='https://app.example.test'), self.body(label=''),
			self.body(headers=[{'name': 'Host', 'secret': SECRET}]), self.body(headers=[], cookie_secret=''),
			self.body(origins=['gopher:70']), self.body(expires=MISSING), self.body(expires='soon'),
			self.body(headers=[{'name': 'X-Short', 'secret': 'abc'}]), self.body(headers='nope')]
		for body in bad:
			status, data = self.put('orgadmin', body)
			self.assertEqual(status, 400, (body, data))
			for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
				self.assertNotIn(plain, json.dumps(data))
		self.assertEqual(AuthCredential.objects.count(), 0)

	def test_a_target_wide_sign_in_and_the_host_must_belong_to_the_target(self):
		self.assertEqual(self.put('orgadmin', self.body(scope='target', host=''))[0], 200)
		self.assertEqual(self.put('orgadmin', self.body(host='www.app.example.test'))[0], 200)
		self.assertEqual(self.put('orgadmin', self.body(host='shop.example.test'))[0], 400)  # the sibling target's host
		self.assertEqual(sorted(AuthCredential.objects.values_list('host', flat=True)), ['', 'www.app.example.test'])

	def test_every_expiry_choice_is_stored_as_a_computed_time_and_never_as_null(self):
		for index, (choice, days) in enumerate(((30, 30), ('30', 30), (90, 90), ('90', 90), (120, 120), ('120', 120))):
			host = f'h{index}.app.example.test'
			before = timezone.now()
			status, data = self.put('orgadmin', self.body(host=host, expires=choice))
			after = timezone.now()
			self.assertEqual(status, 200, data)
			cred = AuthCredential.objects.get(host=host)
			self.assertTrue(before + datetime.timedelta(days=days) <= cred.expires_at <= after + datetime.timedelta(days=days), choice)
			self.assertEqual((data['never_expires'], data['days_left'], data['expires_at'] is not None), (False, days, True))
		status, data = self.put('orgadmin', self.body(host='never.app.example.test', expires='never'))
		self.assertEqual(status, 200, data)
		self.assertIsNone(AuthCredential.objects.get(host='never.app.example.test').expires_at)
		self.assertEqual((data['never_expires'], data['days_left'], data['expires_at']), (True, None, None))

	def test_a_missing_or_invalid_expiry_is_a_400_and_stores_nothing_even_on_a_replace(self):
		for bad in (MISSING, None, '', 0, 7, 365, '45', 'forever', '2030-01-31T17:00:00Z', True, [30]):
			status, data = self.put('orgadmin', self.body(expires=bad))
			self.assertEqual(status, 400, (bad, data))
			self.assertIn('30, 90 or 120', json.dumps(data))
		# the old free-form field is not an expiry
		status, data = self.put('orgadmin', self.body(expires=MISSING, expires_at=(timezone.now() + datetime.timedelta(days=5)).isoformat()))
		self.assertEqual(status, 400, data)
		self.assertEqual(AuthCredential.objects.count(), 0)
		self.assertEqual(self.put('orgadmin', self.body(expires=90))[0], 200)
		status, data = self.put('orgadmin', self.body(expires=MISSING))  # a replace does not silently keep or default it either
		self.assertEqual(status, 400, data)
		self.assertEqual(AuthCredential.objects.get().expires_at.date(), (timezone.now() + datetime.timedelta(days=90)).date())

	def test_a_replace_applies_the_new_expiry_choice(self):
		self.put('orgadmin', self.body(expires='never'))
		self.assertIsNone(AuthCredential.objects.get().expires_at)
		self.assertEqual(self.put('orgadmin', self.body(expires=120))[0], 200)
		self.assertIsNotNone(AuthCredential.objects.get().expires_at)

	def test_the_scope_is_explicit_and_a_blank_host_is_never_the_whole_target(self):
		for body in (self.body(scope=MISSING, host=''), self.body(scope=MISSING, host='app.example.test'), self.body(scope=MISSING, host=MISSING),
				self.body(scope='', host=''), self.body(scope='everything', host=''), self.body(scope='host', host=''), self.body(scope='host', host=MISSING),
				self.body(scope='target', host='app.example.test'), self.body(scope='host', host='shop.example.test')):
			status, data = self.put('orgadmin', body)
			self.assertEqual(status, 400, (body.get('scope'), body.get('host'), data))
			self.assertTrue(data.get('error') or data.get('detail') or data, data)
		self.assertEqual(AuthCredential.objects.count(), 0)
		status, data = self.put('orgadmin', self.body(scope='host', host=''))
		self.assertIn('needs a host', json.dumps(data))
		status, data = self.put('orgadmin', self.body(scope=MISSING, host=''))
		self.assertIn('scope is required', json.dumps(data))
		# both deliberate choices work and are reported back
		status, wide = self.put('orgadmin', self.body(scope='target', host=''))
		self.assertEqual((status, wide['scope'], wide['host']), (200, 'target', None))
		status, narrow = self.put('orgadmin', self.body(scope='host', host='app.example.test'))
		self.assertEqual((status, narrow['scope'], narrow['host']), (200, 'host', 'app.example.test'))
		self.assertEqual(sorted(AuthCredential.objects.values_list('host', flat=True)), ['', 'app.example.test'])

	def test_the_mcp_tools_only_list_and_revoke_and_never_set_a_secret(self):
		from agentapi import mcp
		names = {t[0] for t in mcp.TOOLS}
		self.assertNotIn('set_auth_credential', names)
		self.assertEqual({n for n in names if 'auth_credential' in n}, {'list_auth_credentials', 'delete_auth_credential'})
		_status, data = rpc(self.tokens['orgadmin'], 'tools/call', {'name': 'set_auth_credential', 'arguments': {'project': 'acp', 'target_id': self.domain.pk, 'label': 'x'}})
		self.assertIn('error', data)  # an unknown tool is a protocol error
		_status, listing = rpc(self.tokens['orgadmin'], 'tools/list', {})
		self.assertNotIn('set_auth_credential', json.dumps(listing))
		self.assertEqual(AuthCredential.objects.count(), 0)
		cred = self.make(expires=timezone.now() + datetime.timedelta(days=10))
		error, listed = tool_call(self.tokens['orgadmin'], 'list_auth_credentials', {'project': 'acp'})
		self.assertFalse(error, listed)
		row = listed['results'][0]
		self.assertEqual((row['header_names'], row['scope'], row['days_left'], row['never_expires']), (['Authorization'], 'host', 10, False))
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
			self.assertNotIn(plain, json.dumps(listed))
		self.assertTrue(tool_call(self.tokens['member'], 'list_auth_credentials', {'project': 'acp'})[0])
		self.assertFalse(tool_call(self.tokens['orgadmin_ro'], 'list_auth_credentials', {'project': 'acp'})[0])
		args = {'project': 'acp', 'credential_id': cred.pk}
		self.assertTrue(tool_call(self.tokens['member'], 'delete_auth_credential', args)[0])
		self.assertTrue(tool_call(self.tokens['orgadmin_ro'], 'delete_auth_credential', args)[0])  # a write tool needs a write token
		self.assertEqual(AuthCredential.objects.count(), 1)
		error, _ = tool_call(self.tokens['orgadmin'], 'delete_auth_credential', args)
		self.assertFalse(error)
		self.assertEqual(AuthCredential.objects.count(), 0)

	def test_a_cookie_that_looks_like_an_attack_is_not_a_strike(self):
		status, data = self.put('member', self.body(cookie_secret='a=1; id=5; `x`=$(ls)'))
		self.assertEqual(status, 403)  # refused for the role, not struck as an attack
		status, data = self.put('orgadmin', self.body(headers=[{'name': 'Authorization', 'secret': 'Bearer abc; cat /etc/passwd && ls'}]))
		self.assertEqual(status, 200, data)  # the guard skips credential-like fields, so a session text never earns a strike or is kept as one sample
		from dashboard.models import AbuseStrike
		self.assertEqual(AbuseStrike.objects.count(), 0)


class ScopeTests(Fixture):
	def scope(self, domain=None):
		return AuthScope.for_domain(domain or self.domain)

	def test_exactly_the_host_the_scheme_and_the_port_it_was_stored_for(self):
		self.make(host='app.example.test', origins=['https:443'])
		scope = self.scope()
		self.assertEqual(scope.headers_for('app.example.test', 'https', 443)[0], ('Authorization', SECRET))
		self.assertEqual(scope.headers_for('APP.example.test.', 'https', 443)[0], ('Authorization', SECRET))
		self.assertEqual(scope.headers_for('www.app.example.test', 'https', 443), [])  # a subdomain of the host is another host
		self.assertEqual(scope.headers_for('example.test', 'https', 443), [])
		self.assertEqual(scope.headers_for('evil-app.example.test', 'https', 443), [])
		self.assertEqual(scope.headers_for('app.example.test.evil.test', 'https', 443), [])  # a name that merely starts like it
		self.assertEqual(scope.headers_for('app.example.test', 'http', 443), [])  # another scheme
		self.assertEqual(scope.headers_for('app.example.test', 'https', 8443), [])  # another port
		self.assertEqual(scope.headers_for('app.example.test', 'http', 80), [])  # plain http was never named
		self.assertEqual(scope.headers_for('203.0.113.7', 'https', 443), [])  # the address the name points at is another destination
		self.assertEqual(scope.headers_for('cdn.thirdparty.test', 'https', 443), [])
		self.assertEqual(scope.headers_for('', 'https', 443), [])
		self.assertEqual(scope.headers_for('app.example.test', 'ftp', 443), [])

	def test_the_cookie_goes_as_a_cookie_header(self):
		self.make()
		headers = dict(self.scope().headers_for('app.example.test', 'https', 443))
		self.assertEqual(headers['Cookie'], COOKIE)

	def test_a_target_wide_sign_in_covers_that_targets_hosts_only(self):
		self.make(host='', origins=['https:443', 'http:8080'])
		scope = self.scope()
		for host in ('app.example.test', 'www.app.example.test', 'a.b.app.example.test'):
			self.assertTrue(scope.headers_for(host, 'https', 443), host)
		self.assertTrue(scope.headers_for('www.app.example.test', 'http', 8080))
		for host in ('shop.example.test', 'example.test', 'notapp.example.test', 'app.example.test.evil.test', 'cdn.thirdparty.test'):
			self.assertEqual(scope.headers_for(host, 'https', 443), [], host)
		self.assertEqual(scope.headers_for('www.app.example.test', 'https', 8080), [])

	def test_it_never_reaches_another_target_or_another_project(self):
		self.make(host='')
		self.assertEqual(self.scope(self.sibling).headers_for('app.example.test', 'https', 443), [])  # the sibling target's scope holds nothing
		self.assertEqual(self.scope(self.foreign).headers_for('app.example.test', 'https', 443), [])
		self.assertEqual(auth_checks.credentials_for_hosts(self.other_project.pk, ['app.example.test']), [])
		self.assertEqual(len(auth_checks.credentials_for_hosts(self.project.pk, ['www.app.example.test'])), 1)
		self.assertEqual(auth_checks.credentials_for_hosts(self.project.pk, ['shop.example.test']), [])

	def test_a_host_only_target_does_not_extend_to_its_subdomains(self):
		Domain.objects.filter(pk=self.domain.pk).update(scope_mode=Domain.SCOPE_HOST)
		self.make(host='')
		scope = self.scope(Domain.objects.get(pk=self.domain.pk))
		self.assertTrue(scope.headers_for('app.example.test', 'https', 443))
		self.assertEqual(scope.headers_for('www.app.example.test', 'https', 443), [])

	def test_a_host_specific_sign_in_wins_over_a_target_wide_one_and_they_are_never_merged(self):
		self.make(host='', headers=[['X-Wide', 'wide-value-123']], cookie='')
		self.make(host='app.example.test', headers=[['X-Narrow', 'narrow-value-1']], cookie='')
		scope = self.scope()
		self.assertEqual(scope.headers_for('app.example.test', 'https', 443), [('X-Narrow', 'narrow-value-1')])
		self.assertEqual(scope.headers_for('www.app.example.test', 'https', 443), [('X-Wide', 'wide-value-123')])

	def test_an_expired_sign_in_is_not_sent_and_shows_as_expired(self):
		cred = self.make(expires=timezone.now() - datetime.timedelta(seconds=1))
		self.assertEqual(self.scope().headers_for('app.example.test', 'https', 443), [])
		self.assertEqual(auth_checks.summary(cred)['state'], 'expired')
		cred.expires_at = timezone.now() + datetime.timedelta(hours=1)
		cred.save()
		self.assertTrue(self.scope().headers_for('app.example.test', 'https', 443))
		later = timezone.now() + datetime.timedelta(hours=2)
		self.assertEqual(AuthScope.for_domain(self.domain, now=later).headers_for('app.example.test', 'https', 443), [])

	def test_the_redaction_list_covers_values_parts_and_encodings(self):
		values = auth_checks.secret_values([self.make()])
		self.assertEqual(auth_checks.redact_text(f'x {SECRET} y {TOKEN} z {COOKIE} w {COOKIE_VALUE}', values), 'x [redacted] y [redacted] z [redacted] w [redacted]')
		import base64
		from urllib.parse import quote
		for variant in (quote(SECRET, safe=''), json.dumps(SECRET)[1:-1], base64.b64encode(SECRET.encode()).decode().rstrip('=')):
			self.assertNotIn(TOKEN[:8], auth_checks.redact_text(variant, values))
		obj = {'request': f'GET / HTTP/1.1\r\nAuthorization: {SECRET}\r\nCookie: {COOKIE}', 'extracted-results': [TOKEN], 'info': {'name': 'n'}, 'n': 3}
		self.assertNotIn(TOKEN, json.dumps(auth_checks.redact_obj(obj, values)))
		self.assertEqual(auth_checks.redact_text('plain text', []), 'plain text')


class Handler(http.server.BaseHTTPRequestHandler):
	seen = []  # (server port, path, headers)
	other_port = 0

	def do_GET(self):
		type(self).seen.append((self.server.server_address[1], self.path, dict(self.headers)))
		if self.path == '/redir':
			self.send_response(302)
			self.send_header('Location', f'http://127.0.0.1:{Handler.other_port}/stolen')
			self.send_header('Content-Length', '0')
			self.end_headers()
			return
		body = b'<html><title>Home</title></html>'
		self.send_response(200)
		self.send_header('Content-Type', 'text/html')
		self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, *a):
		pass


class LiveProbeTests(Fixture):
	"""The real probe against two local servers: a credential stored for one origin reaches that origin and nothing else."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.servers = [http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
		cls.port, cls.other = (s.server_address[1] for s in cls.servers)
		Handler.other_port = cls.other
		for s in cls.servers:
			threading.Thread(target=s.serve_forever, daemon=True).start()

	@classmethod
	def tearDownClass(cls):
		for s in cls.servers:
			s.shutdown()
			s.server_close()
		super().tearDownClass()

	def setUp(self):
		Handler.seen.clear()
		policy = mock.patch('cveFeed.pinned_transport.is_scannable_ip', return_value=True)  # this fixture talks to its own loopback servers
		policy.start()
		self.addCleanup(policy.stop)
		self.target = Domain.objects.create(name='127.0.0.1', project=self.project, insert_date=timezone.now())
		self.cred = self.make(self.target, host='127.0.0.1', origins=[f'http:{self.port}'])

	def scope(self):
		return AuthScope.for_domain(self.target)

	def test_the_stored_origin_gets_the_headers(self):
		ra.probe_url(f'http://127.0.0.1:{self.port}/', auth_scope=self.scope())
		(_, _, headers), = Handler.seen
		self.assertEqual((headers['Authorization'], headers['Cookie']), (SECRET, COOKIE))

	def test_an_anonymous_probe_sends_nothing(self):
		ra.probe_url(f'http://127.0.0.1:{self.port}/')
		self.assertNotIn('Authorization', Handler.seen[0][2])
		self.assertNotIn('Cookie', Handler.seen[0][2])

	def test_another_port_of_the_same_host_gets_nothing(self):
		ra.probe_url(f'http://127.0.0.1:{self.other}/', auth_scope=self.scope())
		(_, _, headers), = Handler.seen
		self.assertNotIn('Authorization', headers)
		self.assertNotIn('Cookie', headers)

	def test_another_host_name_for_the_same_server_gets_nothing(self):
		ra.probe_url(f'http://localhost:{self.port}/', auth_scope=self.scope())
		(_, _, headers), = Handler.seen
		self.assertNotIn('Authorization', headers)
		self.assertNotIn('Cookie', headers)

	def test_a_redirect_to_another_origin_is_never_followed_and_never_carries_the_values(self):
		result = ra.probe_url(f'http://127.0.0.1:{self.port}/redir', auth_scope=self.scope())
		self.assertEqual((result['status'], result['location']), (302, f'http://127.0.0.1:{Handler.other_port}/stolen'))
		self.assertEqual([p for _, p, _ in Handler.seen], ['/redir'])  # the other server was never asked
		self.assertFalse([h for port, _, h in Handler.seen if port == self.other])

	def test_an_expired_credential_is_not_sent(self):
		AuthCredential.objects.filter(pk=self.cred.pk).update(expires_at=timezone.now() - datetime.timedelta(minutes=1))
		ra.probe_url(f'http://127.0.0.1:{self.port}/', auth_scope=self.scope())
		self.assertNotIn('Authorization', Handler.seen[0][2])

	def test_a_destination_the_normal_vetting_refuses_is_refused_before_anything_is_sent(self):
		with mock.patch('cveFeed.pinned_transport.is_scannable_ip', return_value=False):
			with self.assertRaises(ValueError):
				ra.probe_url(f'http://127.0.0.1:{self.port}/', auth_scope=self.scope())
		self.assertEqual(Handler.seen, [])

	def test_the_anonymous_header_rule_still_refuses_arbitrary_headers(self):
		with self.assertRaises(ValueError):
			ra.probe_url(f'http://127.0.0.1:{self.port}/', headers={'Authorization': SECRET})


class LiveTlsTests(Fixture):
	"""The real probe and the real certificate check against a local TLS server: one certificate that chains to a CA the client trusts, one that is
	self-signed. The sign-in is sent to the first, withheld from the second unless the target's switch is on, and an anonymous probe is unchanged."""

	@classmethod
	def setUpClass(cls):
		import shutil
		import ssl
		import subprocess
		super().setUpClass()
		cls.scratch = tempfile.mkdtemp(prefix='cvengine-tls-test-')
		d = cls.scratch

		def run(*args):
			subprocess.run(['openssl', *args], cwd=d, check=True, capture_output=True)
		with open(os.path.join(d, 'ext.cnf'), 'w') as handle:
			handle.write('subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n')
		run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-subj', '/CN=test ca',
			'-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
		run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'good.key', '-out', 'good.csr', '-subj', '/CN=127.0.0.1')
		run('x509', '-req', '-in', 'good.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'good.crt', '-days', '2', '-extfile', 'ext.cnf')
		run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.crt', '-days', '2', '-subj', '/CN=127.0.0.1',
			'-addext', 'subjectAltName=IP:127.0.0.1')
		cls.servers = {}
		for name in ('good', 'self'):
			server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.minimum_version = ssl.TLSVersion.TLSv1_2
			context.load_cert_chain(os.path.join(d, f'{name}.crt'), os.path.join(d, f'{name}.key'))
			server.socket = context.wrap_socket(server.socket, server_side=True)
			cls.servers[name] = server
			threading.Thread(target=server.serve_forever, daemon=True).start()
		cls.ca = os.path.join(d, 'ca.crt')
		cls._shutil = shutil

	@classmethod
	def tearDownClass(cls):
		for server in cls.servers.values():
			server.shutdown()
			server.server_close()
		cls._shutil.rmtree(cls.scratch, ignore_errors=True)
		super().tearDownClass()

	def setUp(self):
		Handler.seen.clear()
		for name, value in (('cveFeed.pinned_transport.is_scannable_ip', True),):  # the fixture talks to its own loopback servers
			patcher = mock.patch(name, return_value=value)
			patcher.start()
			self.addCleanup(patcher.stop)
		trust = mock.patch.dict(os.environ, {'SSL_CERT_FILE': self.ca})  # the one CA this test trusts, read by the default verify paths
		trust.start()
		self.addCleanup(trust.stop)
		self.target = Domain.objects.create(name='127.0.0.1', project=self.project, insert_date=timezone.now())
		self.cred = self.make(self.target, host='127.0.0.1', origins=['https:%d' % self.servers['good'].server_address[1],
			'https:%d' % self.servers['self'].server_address[1]])

	def port(self, name):
		return self.servers[name].server_address[1]

	def scope(self):
		return AuthScope.for_domain(self.target)

	def switch(self, on):
		AuthCredential.objects.filter(pk=self.cred.pk).update(allow_untrusted_certificate=on)

	def test_a_certificate_that_verifies_gets_the_sign_in(self):
		result = ra.probe_url(f'https://127.0.0.1:{self.port("good")}/', auth_scope=self.scope())
		self.assertEqual(result['status'], 200)
		(_, _, headers), = Handler.seen
		self.assertEqual((headers['Authorization'], headers['Cookie']), (SECRET, COOKIE))

	def test_an_untrusted_certificate_with_the_switch_off_gets_nothing_and_says_why(self):
		with self.assertRaises(ra.UntrustedCertificate) as caught:
			ra.probe_url(f'https://127.0.0.1:{self.port("self")}/', auth_scope=self.scope())
		self.assertIn('does not verify', str(caught.exception))
		self.assertIn('Trust this certificate anyway', str(caught.exception))
		self.assertEqual(Handler.seen, [])  # the request was never made
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
			self.assertNotIn(plain, str(caught.exception))

	def test_an_untrusted_certificate_with_the_switch_on_gets_the_sign_in(self):
		self.switch(True)
		result = ra.probe_url(f'https://127.0.0.1:{self.port("self")}/', auth_scope=self.scope())
		self.assertEqual(result['status'], 200)
		(_, _, headers), = Handler.seen
		self.assertEqual((headers['Authorization'], headers['Cookie']), (SECRET, COOKIE))

	def test_an_anonymous_probe_still_reads_an_untrusted_certificate_and_sends_nothing(self):
		for flag in (False, True):
			self.switch(flag)
			Handler.seen.clear()
			result = ra.probe_url(f'https://127.0.0.1:{self.port("self")}/')
			self.assertEqual(result['status'], 200)
			self.assertNotIn('Authorization', Handler.seen[0][2])
			self.assertNotIn('Cookie', Handler.seen[0][2])

	def test_the_certificate_check_nuclei_relies_on(self):
		self.assertEqual(auth_checks.certificate_verifies('127.0.0.1', self.port('good')), (True, ''))
		ok, reason = auth_checks.certificate_verifies('127.0.0.1', self.port('self'))
		self.assertFalse(ok)
		self.assertTrue(reason)
		ok, reason = auth_checks.certificate_verifies('127.0.0.1', 1)  # nothing listens: not verifiable, so not sent
		self.assertFalse(ok)
		self.assertNotIn(SECRET, reason)


class SignedRouteTests(Fixture):
	"""The route stage with a stored sign-in, the probe replaced by a fake application that shows a dashboard only to a signed-in request."""

	def setUp(self):
		patcher = mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False)
		patcher.start()
		mock.patch('reNgine.tasks.geo_localize.delay').start()
		self.addCleanup(mock.patch.stopall)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.calls = []

	def scan(self, names=('app.example.test',), ports=((443, 'https'),)):
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1, tasks=[], results_dir='x')
		for number, name in enumerate(names):
			sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
			ip, _ = IpAddress.objects.get_or_create(address=f'203.0.113.{10 + number}')
			sub.ip_addresses.add(ip)
			for port, service in ports:
				ip.ports.add(Port.objects.create(number=port, service_name=service, state='open'))
		return scan

	def probe(self, url, auth_scope=None, **kw):
		from urllib.parse import urlsplit
		parts = urlsplit(url)
		sent = auth_scope.headers_for(parts.hostname, parts.scheme, parts.port or 443) if auth_scope is not None else []
		self.calls.append((url, bool(sent)))
		if sent:  # the page greets the user by echoing the session, as a careless application might
			return {'url': url, 'status': 200, 'location': '', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html',
				'body': '<h1>Dashboard</h1>', 'title': f'Dashboard for {TOKEN} {COOKIE_VALUE}'}
		return {'url': url, 'status': 302, 'location': '/login', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html', 'body': '', 'title': ''}

	def signed_calls(self):
		return [c for c in self.calls if c[1]]

	def test_the_signed_in_answer_is_recorded_beside_the_anonymous_one_and_marked(self):
		self.make(host='app.example.test')
		out = ra.run_route_auth(self.scan().id, probe=self.probe)
		row = RouteAuth.objects.get(url='https://app.example.test/')
		self.assertEqual(row.auth_state, 'session_required')  # the anonymous state stands
		signed = row.evidence['authenticated']
		self.assertEqual((signed['state'], signed['http_status'], signed['seen_while_authenticated']), ('open', 200, True))
		self.assertEqual(out['signed_in']['routes'], len(self.signed_calls()))
		self.assertEqual(out['signed_in']['differs'], out['signed_in']['routes'])
		self.assertNotIn(TOKEN, everything_stored())
		self.assertNotIn(COOKIE_VALUE, everything_stored())
		self.assertIn('[redacted]', signed['title'])
		self.assertTrue(AgentActivity.objects.filter(message__contains='signed in (seen while authenticated)').exists())
		self.assertTrue(AuthCredential.objects.get().last_used_at)

	def test_a_route_not_sent_for_an_untrusted_certificate_is_said_with_the_switch_to_change_it(self):
		self.make(host='app.example.test')

		def probe(url, auth_scope=None, **kw):
			if auth_scope is not None and auth_scope.headers_for('app.example.test', 'https', 443):
				raise ra.UntrustedCertificate('the server certificate does not verify (self-signed certificate), so the stored sign-in was not sent')
			return self.probe(url, auth_scope=auth_scope, **kw)
		out = ra.run_route_auth(self.scan().id, probe=probe)
		self.assertEqual(out['signed_in']['routes'], 0)
		self.assertGreater(out['signed_in']['untrusted_certificate'], 0)
		self.assertEqual(out['signed_in']['errors'], 0)
		line = AgentActivity.objects.filter(message__contains='Trust this certificate anyway').get().message
		self.assertIn('server certificate does not verify', line)
		self.assertNotIn('authenticated', RouteAuth.objects.get(url='https://app.example.test/').evidence)

	def test_another_host_a_third_party_host_and_another_port_are_never_signed_in(self):
		self.make(host='app.example.test')
		scan = self.scan(names=('app.example.test', 'www.example.test', 'cdn.thirdparty.test'), ports=((443, 'https'), (8443, 'https')))
		ra.run_route_auth(scan.id, probe=self.probe)
		for url, sent in self.signed_calls():
			self.assertTrue(url.startswith('https://app.example.test/'), url)  # and 8443 is not an origin the credential was stored for
		self.assertTrue(self.signed_calls())
		self.assertFalse([1 for row in RouteAuth.objects.exclude(host='app.example.test') if 'authenticated' in row.evidence])

	def test_a_target_wide_sign_in_stays_inside_its_target(self):
		self.make(host='')
		scan = self.scan(names=('app.example.test', 'api.app.example.test', 'cdn.thirdparty.test', 'shop.example.test'))
		ra.run_route_auth(scan.id, probe=self.probe)
		signed_hosts = {url.split('/')[2] for url, _ in self.signed_calls()}
		self.assertEqual(signed_hosts, {'app.example.test', 'api.app.example.test'})

	def test_an_expired_sign_in_is_skipped_and_said(self):
		self.make(expires=timezone.now() - datetime.timedelta(minutes=1))
		out = ra.run_route_auth(self.scan().id, probe=self.probe)
		self.assertEqual(self.signed_calls(), [])
		self.assertEqual(out['signed_in'].get('skipped'), 'no covered route')
		self.assertFalse(RouteAuth.objects.filter(evidence__has_key='authenticated').exists())
		self.assertTrue(AgentActivity.objects.filter(message__contains='expired and was not sent').exists())

	def test_without_a_sign_in_nothing_changes(self):
		out = ra.run_route_auth(self.scan().id, probe=lambda url: self.probe(url))
		self.assertNotIn('signed_in', out)
		self.assertEqual(self.signed_calls(), [])

	def test_paused_scanning_sends_nothing_signed_in(self):
		self.make()
		scan = self.scan()
		ra.run_route_auth(scan.id, probe=lambda url, **k: self.probe(url))  # the anonymous rows exist first
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		out = auth_routes.run_signed_in(scan.id, self.probe)
		self.assertEqual(out['skipped'], 'paused or stopped')
		self.assertEqual(self.signed_calls(), [])

	def test_the_ledger_skips_a_repeat_and_a_replaced_credential_runs_again(self):
		cred = self.make()
		scan = self.scan()
		ra.run_route_auth(scan.id, probe=self.probe)
		first = len(self.signed_calls())
		self.assertGreater(first, 0)
		self.assertTrue(ServiceRun.objects.filter(service=auth_routes.SERVICE).exists())
		out = auth_routes.run_signed_in(scan.id, self.probe)
		self.assertEqual((out['skipped'], len(self.signed_calls())), ('recent', first))
		cred.label = 'replaced'
		cred.save()
		auth_routes.run_signed_in(scan.id, self.probe)
		self.assertEqual(len(self.signed_calls()), first * 2)
		# the anonymous check rewrites a route whole; the signed-in evidence is put back
		ra.run_route_auth(scan.id, probe=self.probe, force=True)
		self.assertTrue(RouteAuth.objects.get(url='https://app.example.test/').evidence.get('authenticated'))

	def test_an_excluded_host_is_never_probed_signed_in(self):
		self.make(host='')
		HostExclusion.objects.create(org=self.org, host='api.app.example.test')
		scan = self.scan(names=('app.example.test', 'api.app.example.test'))
		ra.run_route_auth(scan.id, probe=self.probe)
		self.assertFalse([c for c in self.calls if 'api.app.example.test' in c[0]])

	def test_a_host_the_ssrf_gate_refuses_is_never_probed_signed_in(self):
		self.make(host='')
		scan = self.scan(names=('app.example.test', 'api.app.example.test'))
		ra.run_route_auth(scan.id, probe=lambda url, **k: self.probe(url))
		self.calls.clear()
		with mock.patch('targetApp.target_types.resolves_to_blocked', side_effect=lambda host, **k: host == 'api.app.example.test'):
			auth_routes.run_signed_in(scan.id, self.probe, force=True)
		self.assertFalse([c for c in self.calls if 'api.app.example.test' in c[0]])
		self.assertTrue(self.signed_calls())


def nuclei_line(host='https://app.example.test', matched='https://app.example.test/admin', name='Admin panel exposed'):
	return {'template': 'http/exposures/admin.yaml', 'template-id': 'admin-panel', 'type': 'http', 'host': host, 'matched-at': matched,
		'matcher-name': 'body',
		'info': {'name': name, 'severity': 'high', 'description': f'seen with {SECRET}', 'tags': ['exposure']},
		'request': f'GET /admin HTTP/1.1\r\nHost: app.example.test\r\nAuthorization: {SECRET}\r\nCookie: {COOKIE}\r\n\r\n',
		'response': f'HTTP/1.1 200 OK\r\nSet-Cookie: sid={COOKIE_VALUE}\r\n\r\n<p>token {TOKEN}</p>',
		'curl-command': f"curl -X 'GET' -H 'Authorization: {SECRET}' -H 'Cookie: {COOKIE}' 'https://app.example.test/admin'",
		'extracted-results': [TOKEN]}


class NucleiTests(Fixture):
	def setUp(self):
		for name in ('targetApp.target_types.resolves_to_blocked',):
			patcher = mock.patch(name, return_value=False)
			patcher.start()
			self.addCleanup(patcher.stop)
		self.verify = mock.patch('cveFeed.auth_checks.certificate_verifies', return_value=(True, '')).start()  # nuclei never verifies itself
		self.addCleanup(mock.patch.stopall)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.runs = []
		self.leftovers = []

	def make(self, *args, allow_untrusted_certificate=True, **kwargs):
		# Most Nuclei tests exercise the owner's explicit opt-in. Tests for the
		# default, withheld path pass False and verify no secret file is used.
		cred = super().make(*args, **kwargs)
		cred.allow_untrusted_certificate = allow_untrusted_certificate
		cred.save(update_fields=['allow_untrusted_certificate'])
		return cred

	def scan(self, names=('app.example.test',), ports=((443, 'https'),), domain=None):
		scan = ScanHistory.objects.create(domain=domain or self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1)
		for number, name in enumerate(names):
			sub = Subdomain.objects.create(name=name, target_domain=domain or self.domain, scan_history=scan)
			ip, _ = IpAddress.objects.get_or_create(address=f'203.0.113.{20 + number}')
			sub.ip_addresses.add(ip)
			for port, service in ports:
				ip.ports.add(Port.objects.create(number=port, service_name=service, state='open'))
		return scan

	def stream(self, lines=None, error=None):
		def stream(path, secret_file=None, **kwargs):
			run = {'targets': open(path).read().split(), 'secret_file': secret_file, 'kwargs': kwargs}
			if secret_file:
				run['mode'] = stat.S_IMODE(os.stat(secret_file).st_mode)
				run['dir_mode'] = stat.S_IMODE(os.stat(os.path.dirname(secret_file)).st_mode)
				run['document'] = json.load(open(secret_file))
				self.leftovers.append(secret_file)
			self.runs.append(run)
			if secret_file and error:
				raise error
			if secret_file:
				yield from (lines if lines is not None else [nuclei_line()])
		return stream

	def signed_runs(self):
		return [r for r in self.runs if r['secret_file']]

	def test_a_signed_in_pass_runs_for_the_covered_origin_with_the_values_in_a_private_file(self):
		self.make(host='app.example.test')
		out = nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['https://app.example.test'])  # an explicit origin, never a bare host nuclei could read as http
		self.assertEqual((run['mode'], run['dir_mode']), (0o600, 0o700))
		secret, = run['document']['static']
		self.assertEqual((secret['type'], secret['domains']), ('Header', ['app.example.test']))
		self.assertEqual({(h['key'], h['value']) for h in secret['headers']}, {('Authorization', SECRET), ('Cookie', COOKIE)})
		self.assertNotIn(SECRET, json.dumps(run['kwargs']))
		self.assertEqual(out['authenticated']['findings'], 1)
		self.assertEqual(self.runs[0]['secret_file'], None)  # the plain pass ran first, without it

	def test_the_file_and_its_directory_are_removed_afterwards_and_on_failure(self):
		self.make()
		nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		for path in self.leftovers:
			self.assertFalse(os.path.exists(path))
			self.assertFalse(os.path.exists(os.path.dirname(path)))
		self.leftovers.clear()
		ServiceRun.objects.all().delete()
		out = nuclei_scan.run_nuclei(self.scan().id, stream=self.stream(error=RuntimeError('boom')))
		self.assertIn('boom', out['authenticated']['error'])
		self.assertTrue(self.leftovers)
		for path in self.leftovers:
			self.assertFalse(os.path.exists(os.path.dirname(path)))

	def test_a_stored_finding_carries_no_secret_and_is_marked(self):
		self.make()
		scan = self.scan()
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		vuln = Vulnerability.objects.get(scan_history=scan)
		self.assertIn(auth_checks.SEEN_TAG, [t.name for t in vuln.tags.all()])
		for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
			self.assertNotIn(plain, everything_stored())
		self.assertIn('[redacted]', vuln.request)
		self.assertIn('[redacted]', vuln.response)
		self.assertIn('[redacted]', vuln.curl_command)
		self.assertTrue(AgentActivity.objects.filter(message__contains='seen while authenticated').exists())

	def test_an_error_message_carries_no_secret_either(self):
		self.make()
		scan = self.scan()
		out = nuclei_scan.run_nuclei(scan.id, stream=self.stream(error=RuntimeError(f'could not parse {SECRET} and {COOKIE_VALUE}')))
		self.assertNotIn(TOKEN, json.dumps(out))
		self.assertNotIn(COOKIE_VALUE, json.dumps(out))
		for plain in (SECRET, TOKEN, COOKIE_VALUE):
			self.assertNotIn(plain, everything_stored())

	def test_a_finding_the_plain_pass_also_made_is_tagged_and_the_signed_only_ones_are_counted(self):
		self.make()
		scan = self.scan()
		plain = {k: v for k, v in nuclei_line().items() if k not in ('request', 'response', 'curl-command')}
		plain['info'] = {**plain['info'], 'description': 'plain'}
		both = [nuclei_line(), nuclei_line(matched='https://app.example.test/billing', name='Billing exposed')]

		def stream(path, secret_file=None, **k):
			if secret_file:
				yield from both
			else:
				yield plain
		out = nuclei_scan.run_nuclei(scan.id, stream=stream)
		self.assertEqual(Vulnerability.objects.filter(scan_history=scan).count(), 2)
		self.assertEqual(out['authenticated'], {'targets': 1, 'findings': 2, 'new': 1})  # one of the two was not there without signing in
		self.assertEqual(Vulnerability.objects.filter(tags__name=auth_checks.SEEN_TAG).distinct().count(), 2)

	def test_hosts_without_a_sign_in_and_other_ports_get_none(self):
		self.make(host='app.example.test')
		scan = self.scan(names=('app.example.test', 'www.example.test', 'cdn.thirdparty.test'), ports=((443, 'https'), (8443, 'https')))
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['https://app.example.test'])  # not app...:8443, not the address, not another name
		self.assertEqual(run['document']['static'][0]['domains'], ['app.example.test'])
		plain = self.runs[0]['targets']
		self.assertIn('app.example.test:8443', plain)  # the plain pass still covers every port and the address
		self.assertTrue([t for t in plain if t.startswith('203.0.113.')])

	def test_a_successful_preflight_cannot_authorize_a_later_unverified_nuclei_connection(self):
		self.make(host='app.example.test', allow_untrusted_certificate=False)
		out = nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		self.assertEqual(self.signed_runs(), [])  # even a valid preflight cannot authenticate Nuclei's later TLS connection
		self.assertEqual(out['authenticated']['skipped'], 'Nuclei TLS is not verified')
		self.verify.assert_not_called()
		line = AgentActivity.objects.filter(message__contains='Trust this certificate anyway').get().message
		self.assertIn('https://app.example.test', line)
		self.assertIn('Nuclei does not verify TLS', line)
		self.assertEqual(self.runs[0]['secret_file'], None)  # the plain pass still ran

	def test_a_withheld_sign_in_is_recorded_and_the_check_coverage_says_it_is_not_sent(self):
		from cveFeed import check_coverage as cc
		cred = self.make(host='app.example.test', allow_untrusted_certificate=False)
		nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		row = ServiceRun.objects.get(service=auth_nuclei.REFUSED_SERVICE)
		self.assertEqual((row.status, row.asset, row.project_id), ('refused', f'https://app.example.test@{auth_checks.revision(cred)}', self.project.pk))

		def coverage_of_nuclei_signed_in():
			ev = cc.Evidence()
			ev.credentials = {self.project.pk: [AuthCredential.objects.get(pk=cred.pk)]}
			cc._load_signed(ev, [self.project.pk])
			host = cc.HostFacts('app.example.test', self.project.pk, target_name=self.domain.name, target_is_domain=True, addresses=[cc.Addr('203.0.113.9')])
			return {c['id']: c for c in cc.coverage(host, ev)['checks']}['nuclei-signed-in']
		out = coverage_of_nuclei_signed_in()
		self.assertEqual(out['state'], 'not_applicable')
		self.assertIn('is not sent', out['detail'])
		AuthCredential.objects.filter(pk=cred.pk).update(allow_untrusted_certificate=True)  # explicit unverified-TLS opt-in
		self.assertEqual(coverage_of_nuclei_signed_in()['state'], 'due')

	def test_https_nuclei_coverage_is_withheld_before_any_run(self):
		from cveFeed import check_coverage as cc
		cred = self.make(host='app.example.test', allow_untrusted_certificate=False)
		ev = cc.Evidence()
		ev.credentials = {self.project.pk: [cred]}
		host = cc.HostFacts('app.example.test', self.project.pk, target_name=self.domain.name,
		                    target_is_domain=True, addresses=[cc.Addr('203.0.113.9')])
		checks = {item['id']: item for item in cc.coverage(host, ev)['checks']}
		self.assertEqual(checks['nuclei-signed-in']['state'], 'not_applicable')
		self.assertIn('cannot verify TLS', checks['nuclei-signed-in']['detail'])

	def test_the_switch_sends_the_sign_in_to_a_certificate_that_does_not_verify(self):
		self.make(host="app.example.test", allow_untrusted_certificate=False)
		AuthCredential.objects.update(allow_untrusted_certificate=True)
		out = nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['https://app.example.test'])
		self.assertEqual(out['authenticated']['findings'], 1)
		self.verify.assert_not_called()  # the owner chose; nothing to check

	def test_a_plain_http_origin_has_no_certificate_to_check(self):
		self.make(host='app.example.test', origins=['http:80'])
		self.verify.return_value = (False, 'unused')
		nuclei_scan.run_nuclei(self.scan(ports=((80, 'http'),)).id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['http://app.example.test'])
		self.verify.assert_not_called()

	def test_an_origin_on_another_port_is_named_with_its_port_and_only_that_one(self):
		self.make(host='app.example.test', origins=['https:8443'])
		scan = self.scan(ports=((443, 'https'), (8443, 'https')))
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['https://app.example.test:8443'])
		self.assertEqual(run['document']['static'][0]['domains'], ['app.example.test:8443'])

	def test_plain_http_is_covered_only_when_it_was_named(self):
		self.make(host='app.example.test', origins=['https:443', 'http:80'])
		nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(sorted(run['targets']), ['http://app.example.test', 'https://app.example.test'])

	def test_a_target_wide_sign_in_covers_its_own_hosts_and_never_another_target(self):
		self.make(host='')
		scan = self.scan(names=('app.example.test', 'api.app.example.test', 'shop.example.test', 'cdn.thirdparty.test'))
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		run, = self.signed_runs()
		self.assertEqual(sorted(run['targets']), ['https://api.app.example.test', 'https://app.example.test'])
		self.assertEqual(sorted(run['document']['static'][0]['domains']), ['api.app.example.test', 'app.example.test'])

	def test_an_expired_sign_in_is_never_written_to_a_file(self):
		self.make(expires=timezone.now() - datetime.timedelta(minutes=1))
		out = nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		self.assertEqual(self.signed_runs(), [])
		self.assertEqual(out['authenticated'].get('skipped'), 'no covered host')
		self.assertTrue(AgentActivity.objects.filter(message__contains='expired and was not sent').exists())

	def test_a_paused_scan_runs_no_signed_in_pass(self):
		self.make()
		scan = self.scan()
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		out = nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		self.assertEqual((self.signed_runs(), out['authenticated']['skipped']), ([], 'paused or stopped'))

	def test_an_excluded_or_blocked_host_is_dropped_right_before_the_credential_could_go_there(self):
		self.make(host='')
		HostExclusion.objects.create(org=self.org, host='old.app.example.test')
		scan = self.scan()
		out = auth_nuclei.run_authenticated(scan, AuthScope.for_domain(self.domain), ['app.example.test', 'old.app.example.test', 'bad.app.example.test'],
			self.stream(), force=True)
		self.assertEqual(out['findings'], 1)
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['https://app.example.test', 'https://bad.app.example.test'])
		self.runs.clear()
		with mock.patch('targetApp.target_types.resolves_to_blocked', side_effect=lambda host, **k: host == 'bad.app.example.test'):
			auth_nuclei.run_authenticated(scan, AuthScope.for_domain(self.domain), ['app.example.test', 'bad.app.example.test'], self.stream(), force=True)
		run, = self.signed_runs()
		self.assertEqual(run['targets'], ['https://app.example.test'])  # it now resolves to something a scanner must not touch

	def test_the_ledger_skips_a_repeat_and_a_replaced_credential_runs_again(self):
		cred = self.make()
		scan = self.scan()
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		self.assertEqual(len(self.signed_runs()), 1)
		cred.label = 'replaced'
		cred.save()
		nuclei_scan.run_nuclei(scan.id, stream=self.stream())
		self.assertEqual(len(self.signed_runs()), 2)

	def test_the_focused_pass_keeps_its_tags_and_severities_for_the_signed_in_run(self):
		self.make()
		scan = self.scan()
		nuclei_scan.run_nuclei(scan.id, stream=self.stream(), tags=['wordpress'], targets=['app.example.test'], severities=['high'])
		run, = self.signed_runs()
		self.assertEqual((run['kwargs']['tags'], run['kwargs']['severities']), (['wordpress'], ['high']))

	def test_a_target_without_a_sign_in_runs_exactly_as_before(self):
		out = nuclei_scan.run_nuclei(self.scan().id, stream=lambda path: iter([]))
		self.assertNotIn('authenticated', out)

	def test_another_projects_sign_in_is_never_used_for_this_scan(self):
		self.make(self.foreign, host='')
		Domain.objects.filter(pk=self.foreign.pk).update(name='app.example.test')  # the same name, held by another organization
		nuclei_scan.run_nuclei(self.scan().id, stream=self.stream())
		self.assertEqual(self.signed_runs(), [])


class FakeProc:
	"""subprocess.Popen as stream_nuclei and run_template use it."""
	instances = []
	returncode = 0
	lines = []

	def __init__(self, cmd, **kwargs):
		self.cmd, self.kwargs = cmd, kwargs
		self.stdout = iter(json.dumps(line) + '\n' for line in type(self).lines)
		type(self).instances.append(self)

	def poll(self):
		return self.returncode

	def wait(self):
		return self.returncode

	def communicate(self, timeout=None):
		return '\n'.join(json.dumps(line) for line in type(self).lines), ''


class _Job:
	def __enter__(self):
		return self

	def __exit__(self, *exc):
		return False

	def attach(self, proc):
		pass

	def raise_if_killed(self):
		pass


class CommandTests(TestCase):
	def setUp(self):
		FakeProc.instances, FakeProc.lines = [], []

	def test_build_flags_only_adds_the_file_path_and_no_redirects(self):
		plain = nuclei_scan.build_flags(['wordpress'])
		signed = nuclei_scan.build_flags(['wordpress'], secret_file='/tmp/x/secrets.json')
		self.assertNotIn('-sf', plain)
		self.assertNotIn('-dr', plain)
		self.assertEqual(signed[:len(plain)], plain)
		self.assertEqual(signed[len(plain):], ['-sf', '/tmp/x/secrets.json', '-dr'])

	def test_the_nuclei_command_never_holds_a_value(self):
		cred = SimpleNamespace(pk=1, secret={'headers': [['Authorization', SECRET]], 'cookie': COOKIE})
		with auth_checks.secrets_file([(cred, ['app.example.test'])]) as path, \
				mock.patch('cveFeed.nuclei_scan.approved_templates', return_value=('/tmp/approved', 'rev', 1)), \
				mock.patch('reNgine.resources.heavy_job', lambda *a, **k: _Job()), mock.patch.object(nuclei_scan.subprocess, 'Popen', FakeProc):
			with tempfile.NamedTemporaryFile('w', suffix='.txt') as handle:
				handle.write('https://app.example.test\n')
				handle.flush()
				list(nuclei_scan.stream_nuclei(handle.name, secret_file=path))
				list(nuclei_scan.stream_nuclei(handle.name))
		signed, plain = FakeProc.instances
		self.assertEqual(signed.cmd[signed.cmd.index('-sf') + 1], path)
		self.assertIn('-dr', signed.cmd)
		self.assertNotIn('-sf', plain.cmd)
		self.assertNotIn('-dr', plain.cmd)
		for instance in (signed, plain):
			joined = ' '.join(map(str, instance.cmd)) + repr(instance.kwargs)
			for plain_value in (SECRET, TOKEN, COOKIE, COOKIE_VALUE, 'Authorization'):
				self.assertNotIn(plain_value, joined)
			self.assertNotIn('env', instance.kwargs)  # no environment carries a value either
		self.assertFalse(os.path.exists(path))

	def test_the_secrets_file_is_nuclei_static_format_for_exactly_the_listed_domains(self):
		cred = SimpleNamespace(pk=1, secret={'headers': [['X-Api-Key', 'abcdef123456']], 'cookie': ''})
		doc = auth_checks.secrets_document([(cred, ['app.example.test', 'app.example.test:8443'])])
		self.assertEqual(doc['static'], [{'type': 'Header', 'domains': ['app.example.test', 'app.example.test:8443'],
			'headers': [{'key': 'X-Api-Key', 'value': 'abcdef123456'}]}])

	def test_run_template_signed_in_adds_the_file_and_redacts_output(self):
		FakeProc.lines = [{'host': 'https://app.example.test', 'matched-at': 'https://app.example.test/x', 'template-id': 't', 'matcher-name': 'm',
			'request': f'GET /x HTTP/1.1\r\nAuthorization: {SECRET}', 'response': f'echo {TOKEN}', 'curl-command': f'curl -H "Authorization: {SECRET}"'}]
		values = auth_checks.secret_values([SimpleNamespace(secret={'headers': [['Authorization', SECRET]], 'cookie': ''})])
		with mock.patch('cveFeed.validation.approved_template', return_value=('id: fixture', '')), \
				mock.patch('targetApp.target_types.blocked_names', return_value=set()), \
				mock.patch('reNgine.resources.heavy_job', lambda *a, **k: _Job()), mock.patch.object(templategen.subprocess, 'Popen', FakeProc):
			out = templategen.run_template('/t.yaml', ['https://app.example.test'], secret_file='/tmp/x/secrets.json', redact=values)[0]
			plain = templategen.run_template('/t.yaml', ['app.example.test'])[0]
		signed_cmd, plain_cmd = (p.cmd for p in FakeProc.instances)
		self.assertEqual(signed_cmd[signed_cmd.index('-sf') + 1], '/tmp/x/secrets.json')
		self.assertIn('-dr', signed_cmd)
		self.assertNotIn('-sf', plain_cmd)
		self.assertTrue(out['vulnerable'])
		self.assertNotIn(TOKEN, json.dumps(out))
		self.assertIn(TOKEN, json.dumps(plain))  # without a redaction list the run is exactly as it was

	def test_run_template_error_text_is_redacted(self):
		values = auth_checks.secret_values([SimpleNamespace(secret={'headers': [['Authorization', SECRET]], 'cookie': ''})])

		class Failing(FakeProc):
			returncode = 2

			def communicate(self, timeout=None):
				return '', f'invalid header {SECRET}'
		with mock.patch('cveFeed.validation.approved_template', return_value=('id: fixture', '')), \
				mock.patch('reNgine.resources.heavy_job', lambda *a, **k: _Job()), mock.patch.object(templategen.subprocess, 'Popen', Failing):
			out = templategen.run_template('/t.yaml', ['https://app.example.test'], secret_file='/tmp/x/s.json', redact=values)[0]
		self.assertNotIn(TOKEN, out['error'])


class TemplateCheckTests(Fixture):
	"""The CVE template check (templategen.run_cve_tests) with a stored sign-in."""

	def setUp(self):
		patcher = mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.verify = mock.patch('cveFeed.auth_checks.certificate_verifies', return_value=(True, '')).start()
		self.addCleanup(mock.patch.stopall)

	def make(self, *args, allow_untrusted_certificate=True, **kwargs):
		cred = super().make(*args, **kwargs)
		cred.allow_untrusted_certificate = allow_untrusted_certificate
		cred.save(update_fields=['allow_untrusted_certificate'])
		return cred

	def runs(self, plain_hit, signed_hit):
		calls = []

		def run_template(path, hosts, secret_file=None, redact=()):
			calls.append((list(hosts), secret_file, redact))
			hit = signed_hit if secret_file else plain_hit
			return [{'host': h, 'vulnerable': hit, 'output': '', 'hit': {'host': h, 'matcher-name': 'm', 'request': f'Authorization: {SECRET}'} if hit else None}
				for h in hosts]
		return calls, run_template

	def merge(self, plain_hit, signed_hit, hosts=('app.example.test',)):
		calls, fake = self.runs(plain_hit, signed_hit)
		outcomes = [{'host': h, 'vulnerable': plain_hit, 'output': ''} for h in hosts]
		with mock.patch.object(templategen, 'run_template', fake):
			merged = auth_nuclei.merge_template_outcomes('/t.yaml', list(hosts), outcomes, self.project.pk)
		return calls, merged

	def test_a_host_vulnerable_only_when_signed_in_is_reported_and_marked(self):
		self.make()
		calls, merged = self.merge(False, True)
		(urls, secret_file, redact), = calls
		self.assertEqual((urls, bool(secret_file)), (['https://app.example.test'], True))
		self.assertTrue(merged[0]['vulnerable'] and merged[0]['authenticated'])
		self.assertEqual(merged[0]['host'], 'app.example.test')

	def test_nothing_changes_without_a_sign_in_or_when_the_plain_run_already_matched(self):
		calls, merged = self.merge(False, True)
		self.assertEqual((calls, merged[0]['vulnerable']), ([], False))
		self.make()
		calls, merged = self.merge(True, True)
		self.assertNotIn('authenticated', merged[0])

	def test_signed_in_template_requires_explicit_unverified_tls_opt_in(self):
		cred = self.make(allow_untrusted_certificate=False)
		calls, merged = self.merge(False, True)
		self.assertEqual((calls, merged[0]['vulnerable']), ([], False))
		self.verify.assert_not_called()
		AuthCredential.objects.filter(pk=cred.pk).update(allow_untrusted_certificate=True)
		calls, merged = self.merge(False, True)
		self.assertEqual(len(calls), 1)
		self.assertTrue(merged[0]['vulnerable'])

	def test_a_host_the_sign_in_does_not_cover_is_not_run_signed_in(self):
		self.make(host='app.example.test')
		calls, merged = self.merge(False, True, hosts=('shop.example.test', 'cdn.thirdparty.test'))
		self.assertEqual(calls, [])
		self.assertFalse(any(m['vulnerable'] for m in merged))

	def test_a_paused_instance_and_a_failing_run_leave_the_plain_result(self):
		self.make()
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		calls, merged = self.merge(False, True)
		self.assertEqual((calls, merged[0]['vulnerable']), ([], False))
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': False})
		with mock.patch.object(templategen, 'run_template', side_effect=RuntimeError(f'boom {SECRET}')):
			merged = auth_nuclei.merge_template_outcomes('/t.yaml', ['app.example.test'], [{'host': 'app.example.test', 'vulnerable': False, 'output': ''}], self.project.pk)
		self.assertFalse(merged[0]['vulnerable'])

	def test_the_finding_a_signed_in_template_check_saves_is_tagged_and_clean(self):
		from cveFeed.models import CVEEntry
		self.make()
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True),
			start_scan_date=timezone.now(), scan_status=2)
		Subdomain.objects.create(name='app.example.test', target_domain=self.domain, scan_history=scan)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=8.0)
		calls, merged = self.merge(False, True)
		values = auth_checks.secret_values(auth_checks.credentials_for_hosts(self.project.pk, ['app.example.test']))
		merged[0]['hit'] = auth_checks.redact_obj(merged[0]['hit'], values)
		self.assertEqual(templategen.record_outcomes(cve, merged, project=self.project.pk, template_id='t'), 1)
		vuln = Vulnerability.objects.get(scan_history=scan)
		self.assertIn(auth_checks.SEEN_TAG, [t.name for t in vuln.tags.all()])
		self.assertNotIn(TOKEN, everything_stored())


class PlanTests(Fixture):
	def test_plan_is_empty_for_targets_no_credential_covers(self):
		self.make(host='app.example.test')
		scope = AuthScope.for_domain(self.domain)
		for target in ('www.example.test', '203.0.113.5', 'app.example.test:8443', 'https://app.example.test', 'a b', ''):
			self.assertEqual(auth_checks.plan_nuclei(scope, [target]), [], target)
		self.assertEqual([i[0] for i in auth_checks.plan_nuclei(scope, ['app.example.test'])], ['https://app.example.test'])

	def test_two_credentials_for_the_same_secrets_domain_keep_only_the_first(self):
		self.make(host='app.example.test', origins=['https:443'], headers=[['X-One', 'one-value-111']], cookie='')
		self.make(host='', origins=['http:80'], headers=[['X-Two', 'two-value-222']], cookie='')
		items = auth_checks.plan_nuclei(AuthScope.for_domain(self.domain), ['app.example.test'])
		self.assertEqual([i[0] for i in items], ['https://app.example.test'])  # nuclei cannot tell http from https on the default ports
		self.assertEqual([c.host for _, c, _ in items], ['app.example.test'])
