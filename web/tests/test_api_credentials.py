import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import api_credentials as creds
from dashboard.models import ApiCredential, AuditLog, Org, Project, ProjectMembership
from reNgine import bbot as bbot_lib
from tests.test_admin import api as admin_api_call
from tests.test_tenancy import client_for


def project_api(client, method, path, body=None):
	fn = getattr(client, method.lower())
	url = f'/api/v1/{path}'
	r = fn(url, json.dumps(body) if body is not None else None, content_type='application/json') if method != 'GET' else fn(url)
	return r.status_code, (r.json() if r.content else None)


class ResolveAndBbotArgsTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.org = Org.objects.create(name='R', slug='r')
		self.project = Project.objects.create(name='R', slug='rp', insert_date=now, org=self.org)

	def test_project_key_overrides_org_key_for_the_same_service(self):
		ApiCredential.objects.create(org=self.org, service='shodan', value={'api_key': 'org-key'})
		self.assertEqual(creds.resolve_for_project(self.project), {'shodan': {'api_key': 'org-key'}})
		ApiCredential.objects.create(project=self.project, service='shodan', value={'api_key': 'project-key'})
		self.assertEqual(creds.resolve_for_project(self.project), {'shodan': {'api_key': 'project-key'}})

	def test_a_partial_project_row_fills_in_over_the_org_pair_instead_of_blanking_it(self):
		ApiCredential.objects.create(org=self.org, service='censys', value={'api_id': 'org-id', 'api_secret': 'org-secret'})
		ApiCredential.objects.create(project=self.project, service='censys', value={'api_id': 'project-id', 'api_secret': ''})
		self.assertEqual(creds.resolve_for_project(self.project), {'censys': {'api_id': 'project-id', 'api_secret': 'org-secret'}})
		self.assertIn('modules.censys_dns.api_key=project-id:org-secret', creds.bbot_config_args(self.project))

	def test_the_install_wide_chaos_key_is_the_fallback_and_never_overrides_a_scoped_one(self):
		from dashboard.models import ChaosAPIKey
		ChaosAPIKey.objects.create(key='global-chaos')
		self.assertIn('modules.chaos.api_key=global-chaos', creds.bbot_config_args(self.project))
		ApiCredential.objects.create(org=self.org, service='chaos', value={'api_key': 'org-chaos'})
		args = creds.bbot_config_args(self.project)
		self.assertIn('modules.chaos.api_key=org-chaos', args)
		self.assertNotIn('modules.chaos.api_key=global-chaos', args)

	def test_a_rejected_key_is_named_by_its_service(self):
		self.assertEqual(creds.service_for_module('virustotal'), ('virustotal', 'VirusTotal'))
		self.assertEqual(creds.service_for_module('github_org')[0], 'github')
		self.assertIsNone(creds.service_for_module('crt'))

	def test_org_only_services_still_apply_alongside_a_project_specific_one(self):
		ApiCredential.objects.create(org=self.org, service='virustotal', value={'api_key': 'vt'})
		ApiCredential.objects.create(project=self.project, service='censys', value={'api_id': 'id', 'api_secret': 'sec'})
		resolved = creds.resolve_for_project(self.project)
		self.assertEqual(resolved, {'virustotal': {'api_key': 'vt'}, 'censys': {'api_id': 'id', 'api_secret': 'sec'}})

	def test_bbot_config_args_only_for_services_with_a_mapping(self):
		ApiCredential.objects.create(project=self.project, service='shodan', value={'api_key': 'sk-1'})
		ApiCredential.objects.create(project=self.project, service='censys', value={'api_id': 'cid', 'api_secret': 'csec'})
		ApiCredential.objects.create(project=self.project, service='runzero', value={'api_key': 'rz-1'})  # no bbot mapping
		args = creds.bbot_config_args(self.project)
		self.assertIn('modules.shodan_dns.api_key=sk-1', args)
		self.assertIn('modules.shodan_dns.api_key=sk-1', args)
		self.assertNotIn('modules.shodan_idb.api_key=sk-1', args)  # InternetDB is keyless; bbot rejects the option
		self.assertIn('modules.censys_dns.api_key=cid:csec', args)  # bbot's Censys modules take one "id:secret" value
		self.assertFalse([a for a in args if 'censys_ip' in a])  # no scan mode enables censys_ip: a key for it would never be used
		self.assertFalse([a for a in args if a.startswith('modules.censys.')])  # there is no bbot module named "censys"
		self.assertNotIn('rz-1', ' '.join(args))  # runZero has nothing to feed it into yet
		self.assertEqual(args[0::2], ['-c'] * (len(args) // 2))  # every value is preceded by -c

	def test_censys_needs_both_halves_and_every_mapped_module_exists_in_bbot(self):
		ApiCredential.objects.create(project=self.project, service='censys', value={'api_id': 'only-id'})
		self.assertEqual(creds.bbot_config_args(self.project), [])
		# module names verified against bbot 3.x; a typo here makes bbot print a preset error at startup
		real = {'shodan_dns', 'censys_dns', 'virustotal', 'securitytrails', 'fullhunt', 'leakix', 'hunterio', 'chaos',
		        'github_codesearch', 'github_org', 'otx', 'c99', 'bevigil', 'builtwith', 'bufferoverrun'}
		for service, (_label, _fields, mapping) in creds.SERVICES.items():
			for path, _field in mapping:
				module, option = path.split('.')[1:]
				self.assertIn(module, real, service)
				self.assertEqual(option, 'api_key')
		self.assertFalse(creds.used_in_scans('binaryedge'))
		self.assertTrue(creds.used_in_scans('shodan'))

	def test_every_service_with_a_bbot_mapping_feeds_its_key_to_that_module(self):
		"""Not just Shodan and a few others: a service listed on the keys page must reach bbot when a key exists (a dropped mapping, such as
		Hunter.io's, must fail a test)."""
		mapped = {name: spec for name, spec in creds.SERVICES.items() if spec[2]}
		self.assertTrue({'shodan', 'censys', 'virustotal', 'securitytrails', 'fullhunt', 'leakix', 'hunterio', 'chaos', 'github', 'otx', 'c99',
		                 'bevigil', 'builtwith', 'bufferoverrun'} <= set(mapped))
		for name, (_label, fields, mapping) in mapped.items():
			ApiCredential.objects.filter(project=self.project).delete()
			ApiCredential.objects.create(project=self.project, service=name, value={f[0]: f'value-{f[0]}' for f in fields})
			args = ' '.join(creds.bbot_config_args(self.project))
			for path, _field in mapping:
				self.assertIn(path + '=', args, f'{name} does not reach {path}')

	def test_blank_fields_produce_no_args_and_credential_summary_never_leaks_the_secret(self):
		cred = ApiCredential.objects.create(project=self.project, service='shodan', value={})
		self.assertEqual(creds.bbot_config_args(self.project), [])
		self.assertEqual(creds.credential_summary(cred), {'api_key': False})
		cred.value = {'api_key': 'sk-live-secret'}
		self.assertEqual(creds.credential_summary(cred), {'api_key': True})

	def test_a_project_with_no_org_just_uses_its_own_keys(self):
		orphan = Project.objects.create(name='O', slug='orphan', insert_date=timezone.now())
		ApiCredential.objects.create(project=orphan, service='shodan', value={'api_key': 'x'})
		self.assertEqual(creds.resolve_for_project(orphan), {'shodan': {'api_key': 'x'}})


class BbotCommandWiringTests(TestCase):
	def test_extra_args_reach_the_command_line(self):
		cmd = bbot_lib.build_command(['example.com'], extra_args=['-c', 'modules.shodan_dns.api_key=sk-1'])
		self.assertEqual(cmd[-2:], ['-c', 'modules.shodan_dns.api_key=sk-1'])


class SecretRedactionTests(TestCase):
	def test_config_secrets_and_redact_hide_api_keys_in_bbot_stderr(self):
		args = ['-c', 'modules.shodan_dns.api_key=sk-live-secret', '-c', 'modules.censys_dns.api_key=cid12345:csec67890']
		secrets = bbot_lib.config_secrets(args)
		self.assertEqual(secrets, ['sk-live-secret', 'cid12345:csec67890'])
		line = 'Error: bad key sk-live-secret and cid12345 / csec67890'
		out = bbot_lib.redact(line, secrets)
		for leaked in ('sk-live-secret', 'cid12345', 'csec67890'):
			self.assertNotIn(leaked, out)

	def test_a_failed_bbot_run_does_not_put_the_key_in_the_error(self):
		import sys
		script = 'import sys; sys.stderr.write("Traceback\\nValueError: key sk-live-secret rejected\\n"); sys.exit(2)'
		with mock.patch.object(bbot_lib, 'BBOT_BIN', sys.executable), \
				mock.patch.object(bbot_lib, 'build_command', lambda *a, **k: [sys.executable, '-c', script]):
			with self.assertRaises(bbot_lib.BbotProcessError) as ctx:
				list(bbot_lib.stream_events(['example.com'], extra_args=['-c', 'modules.shodan_dns.api_key=sk-live-secret']))
		self.assertNotIn('sk-live-secret', str(ctx.exception))
		self.assertIn('rejected', str(ctx.exception))


class ProjectApiKeyEndpointTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.org = Org.objects.create(name='P', slug='pk')
		self.project = Project.objects.create(name='P', slug='pkp', insert_date=now, org=self.org)
		self.other = Project.objects.create(name='O', slug='pko', insert_date=now, org=Org.objects.create(name='PO', slug='po'))
		self.writer = User.objects.create_user('pkwriter', password='x')
		self.auditor = User.objects.create_user('pkaudit', password='x')
		ProjectMembership.objects.create(user=self.writer, project=self.project, role='user')
		ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')

	def test_list_shows_catalog_with_no_secrets_and_respects_can_edit(self):
		c = client_for(self.writer)
		status, data = project_api(c, 'GET', 'projects/pkp/api-keys')
		self.assertEqual(status, 200)
		self.assertTrue(data['can_edit'])
		services = {r['service']: r for r in data['results']}
		self.assertIn('shodan', services)
		self.assertFalse(services['shodan']['configured'])
		self.assertEqual(client_for(self.auditor).get('/api/v1/projects/pkp/api-keys').json()['can_edit'], False)

	def test_set_then_list_shows_configured_without_leaking_the_value(self):
		c = client_for(self.writer)
		status, _ = project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': 'sk-secret-123'})
		self.assertEqual(status, 200)
		body = c.get('/api/v1/projects/pkp/api-keys').content.decode()
		self.assertNotIn('sk-secret-123', body)
		row = next(r for r in json.loads(body)['results'] if r['service'] == 'shodan')
		self.assertEqual((row['configured'], row['scope'], row['set']), (True, 'project', {'api_key': True}))
		self.assertTrue(row['used_in_scans'])
		self.assertFalse(next(r for r in json.loads(body)['results'] if r['service'] == 'runzero')['used_in_scans'])
		audit = AuditLog.objects.get(action='project.api_key.set')
		self.assertEqual(audit.org_id, self.org.id)
		self.assertNotIn('sk-secret-123', str(audit.detail) + audit.target)

	def test_saving_with_no_value_is_rejected_and_stores_no_empty_row(self):
		c = client_for(self.writer)
		self.assertEqual(project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {})[0], 400)
		self.assertEqual(project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': '   '})[0], 400)
		self.assertFalse(ApiCredential.objects.filter(project=self.project).exists())
		row = next(r for r in project_api(c, 'GET', 'projects/pkp/api-keys')[1]['results'] if r['service'] == 'shodan')
		self.assertFalse(row['configured'])

	def test_values_are_trimmed(self):
		project_api(client_for(self.writer), 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': '  sk-pad \n'})
		self.assertEqual(ApiCredential.objects.get(project=self.project, service='shodan').value, {'api_key': 'sk-pad'})

	def test_blank_value_on_update_keeps_the_stored_key(self):
		c = client_for(self.writer)
		project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': 'sk-first'})
		project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': ''})
		self.assertEqual(ApiCredential.objects.get(project=self.project, service='shodan').value, {'api_key': 'sk-first'})

	def test_audit_cannot_write_and_cross_project_is_404(self):
		c = client_for(self.auditor)
		self.assertEqual(project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': 'x'})[0], 403)
		writer_c = client_for(self.writer)
		self.assertEqual(project_api(writer_c, 'GET', 'projects/pko/api-keys')[0], 404)
		self.assertEqual(project_api(writer_c, 'PUT', 'projects/pko/api-keys/shodan', {'api_key': 'x'})[0], 404)

	def test_unknown_service_is_rejected(self):
		self.assertEqual(project_api(client_for(self.writer), 'PUT', 'projects/pkp/api-keys/not-a-real-service', {'api_key': 'x'})[0], 404)

	def test_delete_removes_the_projects_own_key_but_not_the_orgs(self):
		ApiCredential.objects.create(org=self.org, service='shodan', value={'api_key': 'org-key'})
		c = client_for(self.writer)
		project_api(c, 'PUT', 'projects/pkp/api-keys/shodan', {'api_key': 'project-key'})
		status, data = project_api(c, 'DELETE', 'projects/pkp/api-keys/shodan')
		self.assertEqual(status, 200)
		row = next(r for r in project_api(c, 'GET', 'projects/pkp/api-keys')[1]['results'] if r['service'] == 'shodan')
		self.assertEqual((row['configured'], row['scope']), (True, 'org'))  # falls back to the org's key
		self.assertTrue(AuditLog.objects.filter(action='project.api_key.remove', org=self.org).exists())


class OrgApiKeyAdminEndpointTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.org_a = Org.objects.create(name='AdA', slug='ada')
		self.org_b = Org.objects.create(name='AdB', slug='adb')
		from dashboard.models import OrgMembership
		self.admin_a = User.objects.create_user('orgkeyadmin', password='x')
		self.member_a = User.objects.create_user('orgkeymember', password='x')
		OrgMembership.objects.create(user=self.admin_a, org=self.org_a, role='admin')
		OrgMembership.objects.create(user=self.member_a, org=self.org_a, role='user')

	def test_org_admin_manages_their_orgs_keys(self):
		c = client_for(self.admin_a)
		status, data = admin_api_call(c, 'GET', f'orgs/{self.org_a.id}/api-keys')
		self.assertEqual(status, 200)
		self.assertFalse(next(r for r in data['results'] if r['service'] == 'censys')['configured'])
		status, _ = admin_api_call(c, 'PUT', f'orgs/{self.org_a.id}/api-keys/censys', {'api_id': 'id1', 'api_secret': 'sec1'})
		self.assertEqual(status, 200)
		self.assertEqual(ApiCredential.objects.get(org=self.org_a, service='censys').value, {'api_id': 'id1', 'api_secret': 'sec1'})
		status, _ = admin_api_call(c, 'DELETE', f'orgs/{self.org_a.id}/api-keys/censys')
		self.assertEqual(status, 200)
		self.assertFalse(ApiCredential.objects.filter(org=self.org_a, service='censys').exists())

	def test_non_admin_and_other_orgs_are_refused(self):
		member_c, admin_c = client_for(self.member_a), client_for(self.admin_a)
		self.assertEqual(admin_api_call(member_c, 'GET', f'orgs/{self.org_a.id}/api-keys')[0], 403)
		self.assertEqual(admin_api_call(admin_c, 'GET', f'orgs/{self.org_b.id}/api-keys')[0], 404)
		self.assertEqual(admin_api_call(admin_c, 'PUT', f'orgs/{self.org_b.id}/api-keys/shodan', {'api_key': 'x'})[0], 404)

	def test_org_save_with_no_value_is_rejected_without_an_empty_row(self):
		c = client_for(self.admin_a)
		self.assertEqual(admin_api_call(c, 'PUT', f'orgs/{self.org_a.id}/api-keys/shodan', {})[0], 400)
		self.assertFalse(ApiCredential.objects.filter(org=self.org_a).exists())
		status, data = admin_api_call(c, 'GET', f'orgs/{self.org_a.id}/api-keys')
		self.assertTrue(next(r for r in data['results'] if r['service'] == 'shodan')['used_in_scans'])
