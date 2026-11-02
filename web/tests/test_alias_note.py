"""An alias (a short display name) and a note on targets and on hosts: set over the service layer, REST and MCP with bounds, permission checks
and audit entries; shown beside the address (display only, the address and discovered names stay); searchable by the Hosts search, the
all-projects search and the target list; escaped in the PDF report; and absent, with nothing changed, on a host or target that has none."""
import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import host_manage as hm
from agentapi import services as svc
from agentapi.auth import create_token
from agentapi.services import ApiError, Ctx
from cveFeed import report_data, report_pdf, views
from cveFeed.models import HostProfile
from dashboard.models import AuditLog, Org, OrgMembership, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp import alias_note
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

EVIL = '<script>alert(1)</script> <img src="x" onerror="alert(2)"> & "q"'


class CleaningTests(SimpleTestCase):
	def test_an_alias_is_stripped_and_kept_to_one_line_within_its_bound(self):
		self.assertEqual(alias_note.clean_alias('  Lab printer  '), 'Lab printer')
		self.assertEqual(alias_note.clean_alias(''), '')
		self.assertEqual(alias_note.clean_alias('x' * alias_note.ALIAS_MAX), 'x' * alias_note.ALIAS_MAX)
		for bad in ('x' * (alias_note.ALIAS_MAX + 1), 'two\nlines', 'tab\there', 'nul\x00', 'bidi‮evil', 'sep arator', 7, None, ['a']):
			with self.assertRaises(ValueError, msg=repr(bad)):
				alias_note.clean_alias(bad)

	def test_a_note_may_have_lines_but_no_control_characters_and_is_bounded(self):
		self.assertEqual(alias_note.clean_note(' rack 3\r\nunit 7 \n'), 'rack 3\nunit 7')
		self.assertEqual(alias_note.clean_note('y' * alias_note.NOTE_MAX), 'y' * alias_note.NOTE_MAX)
		for bad in ('y' * (alias_note.NOTE_MAX + 1), 'bell\x07', 'bidi‮evil', 5, None):
			with self.assertRaises(ValueError, msg=repr(bad)):
				alias_note.clean_note(bad)

	def test_markup_is_kept_as_text_not_removed(self):
		self.assertEqual(alias_note.clean_alias('<b>Router</b> & co'), '<b>Router</b> & co')
		self.assertEqual(alias_note.clean_note(EVIL), EVIL)

	def test_the_columns_are_bounded_and_additive(self):
		for model in (Domain, HostProfile):
			self.assertEqual(model._meta.get_field('alias').max_length, alias_note.ALIAS_MAX)
			self.assertEqual(model._meta.get_field('note').max_length, alias_note.NOTE_MAX)
			for name in ('alias', 'note'):  # a row written by anything that does not know them (an older writer) still gets ''
				self.assertEqual(model._meta.get_field(name).db_default, '')


class Base(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org, cls.other_org = Org.objects.create(name='A', slug='an-a'), Org.objects.create(name='B', slug='an-b')
		cls.p1 = Project.objects.create(name='P1', slug='an-p1', insert_date=now, org=cls.org)
		cls.p2 = Project.objects.create(name='P2', slug='an-p2', insert_date=now, org=cls.org)
		cls.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		mk = lambda n: User.objects.create_user(n, password='x')  # noqa: E731
		cls.admin, cls.auditor, cls.outsider = mk('an-admin'), mk('an-aud'), mk('an-out')
		OrgMembership.objects.create(user=cls.admin, org=cls.org, role='admin')
		OrgMembership.objects.create(user=cls.auditor, org=cls.org, role='audit')
		OrgMembership.objects.create(user=cls.outsider, org=cls.other_org, role='admin')
		_, cls.token = create_token(cls.admin, 'rw')
		_, cls.token_ro = create_token(cls.admin, 'ro', read_only=True)
		_, cls.token_aud = create_token(cls.auditor, 'aud')
		_, cls.token_out = create_token(cls.outsider, 'out')
		cls.lab = Domain.objects.create(name='lab.test', project=cls.p1, insert_date=now)
		cls.ip_target = Domain.objects.create(name='10.9.9.5', project=cls.p1, insert_date=now)
		cls.far = Domain.objects.create(name='far.test', project=cls.p2, insert_date=now)
		cls.scans = {d.pk: ScanHistory.objects.create(domain=d, scan_type=cls.engine, scan_status=2, start_scan_date=now - timedelta(hours=1), tasks=[])
					for d in (cls.lab, cls.ip_target, cls.far)}

	def ctx(self, user):
		return Ctx(user=user)

	def host(self, domain, name, *addresses):
		sub = Subdomain.objects.create(target_domain=domain, name=name, scan_history=self.scans[domain.pk])
		for address in addresses:
			sub.ip_addresses.add(IpAddress.objects.get_or_create(address=address)[0])
		return sub

	def hosts(self, slug='an-p1', **params):
		return {h['host']: h for h in svc.list_hosts(self.ctx(self.admin), slug, {'page_size': 100, **params})['results']}

	def search(self, q, slug='an-p1', **params):
		return [h['host'] for h in svc.search_hosts(self.ctx(self.admin), slug, {'q': q, 'page_size': 100, **params})['results']]


class TargetProfileTests(Base):
	def test_set_get_and_clear_with_only_the_given_fields_changing(self):
		ctx = self.ctx(self.admin)
		out = svc.set_target_profile(ctx, 'an-p1', self.lab.id, alias=' Lab network ', note='Owned by IT\nrack 3')
		self.assertEqual((out['alias'], out['note'], out['name']), ('Lab network', 'Owned by IT\nrack 3', 'lab.test'))
		self.assertEqual(svc.set_target_profile(ctx, 'an-p1', self.lab.id, note='moved')['alias'], 'Lab network')
		self.assertEqual(svc.get_target(ctx, 'an-p1', self.lab.id)['note'], 'moved')
		listed = {t['name']: t for t in svc.list_targets(ctx, 'an-p1', {})['results']}
		self.assertEqual((listed['lab.test']['alias'], listed['lab.test']['note']), ('Lab network', 'moved'))
		out = svc.set_target_profile(ctx, 'an-p1', self.lab.id, alias='', note='')
		self.assertEqual((out['alias'], out['note']), ('', ''))

	def test_a_target_with_no_alias_is_listed_with_empty_ones_and_nothing_else_changed(self):
		listed = {t['name']: t for t in svc.list_targets(self.ctx(self.admin), 'an-p1', {})['results']}
		self.assertEqual((listed['10.9.9.5']['alias'], listed['10.9.9.5']['note'], listed['10.9.9.5']['description']), ('', '', None))
		self.assertEqual(listed['10.9.9.5']['name'], '10.9.9.5')

	def test_the_bounds_and_types_are_refused_with_a_400_and_nothing_is_stored(self):
		ctx = self.ctx(self.admin)
		for kwargs in ({'alias': 'x' * 61}, {'note': 'y' * 1001}, {'alias': 'a\nb'}, {'alias': 4}, {'note': ['x']}, {'note': 'bell\x07'}):
			with self.assertRaises(ApiError, msg=kwargs) as cm:
				svc.set_target_profile(ctx, 'an-p1', self.lab.id, **kwargs)
			self.assertEqual(cm.exception.status, 400, kwargs)
		self.assertEqual(Domain.objects.get(pk=self.lab.pk).alias, '')

	def test_who_may_write_audit_role_read_only_token_outsider_other_project_and_all_projects(self):
		for user, slug, status in ((self.auditor, 'an-p1', 403), (self.outsider, 'an-p1', 404), (self.admin, '_all', 400)):
			with self.assertRaises(ApiError) as cm:
				svc.set_target_profile(self.ctx(user), slug, self.lab.id, alias='x')
			self.assertEqual(cm.exception.status, status, (user.username, slug))
		with self.assertRaises(ApiError) as cm:  # a target of another project is not found through this one
			svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.far.id, alias='x')
		self.assertEqual(cm.exception.status, 404)
		self.assertEqual(Domain.objects.filter(alias='x').count(), 0)

	def test_rest_and_mcp_follow_the_same_rules(self):
		url = f'/api/v1/projects/an-p1/targets/{self.lab.id}/profile'
		status, data = call(self.token, 'POST', url, {'alias': 'Lab', 'note': 'n'})
		self.assertEqual((status, data['alias'], data['note']), (200, 'Lab', 'n'))
		status, data = call(self.token, 'PATCH', url, {'note': 'again'})
		self.assertEqual((status, data['alias'], data['note']), (200, 'Lab', 'again'))
		self.assertEqual(call(self.token, 'POST', url, {'alias': 'x' * 61})[0], 400)
		self.assertEqual(call(self.token_ro, 'POST', url, {'alias': 'ro'})[0], 403)
		self.assertEqual(call(self.token_aud, 'POST', url, {'alias': 'aud'})[0], 403)
		self.assertEqual(call(self.token_out, 'POST', url, {'alias': 'out'})[0], 404)
		self.assertEqual(call(self.token, 'GET', f'/api/v1/projects/an-p1/targets/{self.lab.id}')[1]['alias'], 'Lab')
		failed, out = tool_call(self.token, 'set_target_profile', {'project': 'an-p1', 'target_id': self.lab.id, 'alias': 'Via MCP'})
		self.assertEqual((failed, out['alias']), (False, 'Via MCP'))
		self.assertTrue(tool_call(self.token, 'set_target_profile', {'project': 'an-p1', 'target_id': self.lab.id, 'alias': 'x' * 61})[0])
		self.assertTrue(tool_call(self.token_ro, 'set_target_profile', {'project': 'an-p1', 'target_id': self.lab.id, 'alias': 'ro'})[0])
		self.assertTrue(tool_call(self.token, 'set_target_profile', {'project': 'an-p1', 'target_id': 'x', 'alias': 'a'})[0])
		self.assertEqual(Domain.objects.get(pk=self.lab.pk).alias, 'Via MCP')

	def test_a_change_is_audited_with_the_fields_and_an_unchanged_save_is_not(self):
		ctx = self.ctx(self.admin)
		svc.set_target_profile(ctx, 'an-p1', self.lab.id, alias='Lab', note='n')
		svc.set_target_profile(ctx, 'an-p1', self.lab.id, alias='Lab', note='n')  # nothing changed
		svc.set_target_profile(ctx, 'an-p1', self.lab.id, note='n2')
		rows = list(AuditLog.objects.filter(action='target.profile').order_by('id'))
		self.assertEqual([r.detail['fields'] for r in rows], [['alias', 'note'], ['note']])
		self.assertEqual((rows[0].actor, rows[0].org_id, rows[0].target, rows[0].detail['project']), (self.admin, self.org.pk, 'lab.test in an-p1', 'an-p1'))

	def test_the_target_search_and_delete_all_matching_use_the_alias_and_note(self):
		ctx = self.ctx(self.admin)
		svc.set_target_profile(ctx, 'an-p1', self.lab.id, alias='Core Switch', note='second floor closet')
		names = lambda q: [t['name'] for t in svc.list_targets(ctx, 'an-p1', {'q': q})['results']]  # noqa: E731
		self.assertEqual((names('core switch'), names('CLOSET'), names('lab.t'), names('nothing')), (['lab.test'], ['lab.test'], ['lab.test'], []))
		out = svc.delete_targets(ctx, 'an-p1', all_matching=True, q='closet')  # the same match as the list: only the target the list showed
		self.assertEqual(out['matched'], 1)
		self.assertFalse(Domain.objects.filter(pk=self.lab.pk).exists())
		self.assertTrue(Domain.objects.filter(pk=self.ip_target.pk).exists())


class HostProfileTests(Base):
	def setUp(self):
		self.www = self.host(self.lab, 'www.lab.test', '198.51.100.1')
		self.apex = self.host(self.lab, 'lab.test', '198.51.100.1')  # the same addresses: one host, the target's own name shown
		self.printer = self.host(self.ip_target, '10.9.9.5', '10.9.9.5')
		self.plain = self.host(self.lab, 'plain.lab.test', '198.51.100.7')

	def set(self, host, **fields):
		return hm.update_host_profile(self.ctx(self.admin), 'an-p1', host, **fields)

	def test_set_and_read_back_on_the_host_rows_with_bounds(self):
		out = self.set('PLAIN.lab.test', alias=' Door camera ', note='firmware 2.1\nreplace in 2027')
		self.assertEqual((out['host'], out['alias'], out['note']), ('plain.lab.test', 'Door camera', 'firmware 2.1\nreplace in 2027'))
		row = self.hosts()['plain.lab.test']
		self.assertEqual((row['host'], row['alias'], row['alias_from'], row['note'], row['note_from']),
						('plain.lab.test', 'Door camera', 'host', 'firmware 2.1\nreplace in 2027', 'host'))
		self.assertEqual(self.set('plain.lab.test', note='')['alias'], 'Door camera')  # only the field given changes
		self.assertEqual(self.hosts()['plain.lab.test']['note'], '')
		self.set('plain.lab.test', alias='')
		self.assertEqual(self.hosts()['plain.lab.test']['alias'], '')
		for kwargs in ({'alias': 'x' * 61}, {'note': 'y' * 1001}, {'alias': 'a\nb'}, {'alias': 3}, {'note': {}}):
			with self.assertRaises(ApiError, msg=kwargs) as cm:
				self.set('plain.lab.test', **kwargs)
			self.assertEqual(cm.exception.status, 400, kwargs)

	def test_a_host_with_no_alias_is_unchanged(self):
		row = self.hosts()['plain.lab.test']
		self.assertEqual((row['alias'], row['note'], row['alias_from'], row['note_from']), ('', '', '', ''))
		self.assertEqual(row['profile'], svc.NO_PROFILE)  # the asset info keeps its exact shape
		self.assertFalse(HostProfile.objects.exists())
		self.assertEqual(svc.host_group(self.p1, self.plain)['alias'], '')

	def test_the_address_and_discovered_names_stay_the_alias_never_replaces_them(self):
		self.set('10.9.9.5', alias='Lab printer')
		row = self.hosts()['10.9.9.5']
		self.assertEqual((row['host'], [ip['address'] for ip in row['ips']], row['alias']), ('10.9.9.5', ['10.9.9.5'], 'Lab printer'))
		self.assertEqual(Subdomain.objects.get(pk=self.printer.pk).name, '10.9.9.5')

	def test_it_belongs_to_the_host_name_so_a_rescan_and_a_new_scan_row_keep_it(self):
		self.set('plain.lab.test', alias='Door camera')
		newer = ScanHistory.objects.create(domain=self.lab, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now(), tasks=[])
		rescanned = Subdomain.objects.create(target_domain=self.lab, name='plain.lab.test', scan_history=newer)  # a later scan writes a new row
		rescanned.ip_addresses.add(IpAddress.objects.get(address='198.51.100.7'))
		self.assertEqual(self.hosts()['plain.lab.test']['alias'], 'Door camera')
		self.assertEqual(HostProfile.objects.filter(host='plain.lab.test').count(), 1)

	def test_when_names_merge_into_one_host_the_alias_of_either_name_shows(self):
		self.set('www.lab.test', alias='Web front', note='behind the proxy')  # typed while www was the host on display
		rows = self.hosts()
		self.assertEqual(list(set(rows) & {'lab.test', 'www.lab.test'}), ['lab.test'])  # one host: the target's name is the one shown
		self.assertEqual((rows['lab.test']['alias'], rows['lab.test']['alias_from'], rows['lab.test']['note']), ('Web front', 'host', 'behind the proxy'))
		self.set('lab.test', alias='Main site')  # an alias on the shown name wins
		self.assertEqual(self.hosts()['lab.test']['alias'], 'Main site')
		self.assertEqual(self.hosts()['lab.test']['note'], 'behind the proxy')  # the note is taken separately

	def test_a_host_that_is_its_target_falls_back_to_the_targets_alias_and_its_own_wins(self):
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.ip_target.id, alias='Printer target', note='target note')
		row = self.hosts()['10.9.9.5']
		self.assertEqual((row['alias'], row['alias_from'], row['note'], row['note_from']), ('Printer target', 'target', 'target note', 'target'))
		self.set('10.9.9.5', alias='Lab printer')
		row = self.hosts()['10.9.9.5']
		self.assertEqual((row['alias'], row['alias_from'], row['note_from']), ('Lab printer', 'host', 'target'))
		self.assertEqual(self.hosts()['plain.lab.test']['alias'], '')  # another host of another target is untouched

	def test_permissions_audit_and_every_route(self):
		url = '/api/v1/projects/an-p1/hosts/plain.lab.test/profile'
		status, data = call(self.token, 'POST', url, {'alias': 'Cam', 'note': 'n'})
		self.assertEqual((status, data['alias'], data['note']), (200, 'Cam', 'n'))
		self.assertEqual(call(self.token, 'PATCH', url, {'note': 'm'})[1]['alias'], 'Cam')
		self.assertEqual(call(self.token, 'POST', url, {'alias': 'x' * 61})[0], 400)
		self.assertEqual(call(self.token_ro, 'POST', url, {'alias': 'ro'})[0], 403)
		self.assertEqual(call(self.token_aud, 'POST', url, {'alias': 'aud'})[0], 403)
		self.assertEqual(call(self.token_out, 'POST', url, {'alias': 'out'})[0], 404)
		self.assertEqual(call(self.token, 'POST', '/api/v1/projects/an-p1/hosts/nothing.lab.test/profile', {'alias': 'a'})[0], 404)
		failed, out = tool_call(self.token, 'set_host_profile', {'project': 'an-p1', 'host': 'plain.lab.test', 'alias': 'Via MCP', 'note': 'mcp'})
		self.assertEqual((failed, out['alias'], out['note']), (False, 'Via MCP', 'mcp'))
		self.assertTrue(tool_call(self.token, 'set_host_profile', {'project': 'an-p1', 'host': 'plain.lab.test', 'alias': 'x' * 61})[0])
		self.assertTrue(tool_call(self.token_ro, 'set_host_profile', {'project': 'an-p1', 'host': 'plain.lab.test', 'alias': 'ro'})[0])
		self.assertEqual(HostProfile.objects.get(host='plain.lab.test').alias, 'Via MCP')
		fields = [r.detail['fields'] for r in AuditLog.objects.filter(action='host.profile').order_by('id')]
		self.assertEqual(fields, [['alias', 'note'], ['note'], ['alias', 'note']])

	def test_an_owner_only_change_writes_no_alias_audit_and_keeps_the_alias(self):
		self.set('plain.lab.test', alias='Cam')
		self.set('plain.lab.test', owner='Ops', criticality='high')
		self.assertEqual(AuditLog.objects.filter(action='host.profile').count(), 1)
		out = self.hosts()['plain.lab.test']
		self.assertEqual((out['alias'], out['profile']['owner']), ('Cam', 'Ops'))

	def test_the_alias_goes_with_deleted_host_data(self):
		self.set('plain.lab.test', alias='Cam')
		hm.delete_host(self.ctx(self.admin), 'an-p1', 'plain.lab.test')
		self.assertFalse(HostProfile.objects.filter(host='plain.lab.test').exists())

	def test_the_rest_api_stores_markup_as_text_and_the_free_text_note_is_not_a_guard_strike(self):
		url = '/api/v1/projects/an-p1/hosts/plain.lab.test/profile'
		status, data = call(self.token, 'POST', url, {'alias': '<b>Cam</b> & co', 'note': EVIL})
		self.assertEqual((status, data['alias'], data['note']), (200, '<b>Cam</b> & co', EVIL))  # stored and returned as typed
		from dashboard.models import AbuseStrike
		self.assertEqual(AbuseStrike.objects.count(), 0)  # the note held <script> and was not struck
		self.assertEqual(call(self.token, 'POST', url, {'alias': 'cam; ls -la'})[0], 403)  # an alias is not free text: the input guard still reads it
		self.assertEqual(AbuseStrike.objects.count(), 1)


class SearchTests(Base):
	def setUp(self):
		self.cam = self.host(self.lab, 'cam.lab.test', '198.51.100.20')
		self.nas = self.host(self.lab, 'nas.lab.test', '198.51.100.21')
		self.printer = self.host(self.ip_target, '10.9.9.5', '10.9.9.5')
		self.twin_p1 = self.host(self.lab, 'twin.test', '198.51.100.30')
		self.twin_p2 = self.host(self.far, 'twin.test', '198.51.100.31')
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'cam.lab.test', alias='Door camera', note='firmware 2.1, replace in 2027')
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'nas.lab.test', note='backup target for the lab')
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.ip_target.id, alias='Reception printer', note='toner in cupboard')
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'twin.test', alias='Twin of the first project')

	def test_a_bare_word_matches_the_alias_and_the_note(self):
		self.assertEqual(self.search('door'), ['cam.lab.test'])
		self.assertEqual(self.search('"replace in 2027"'), ['cam.lab.test'])
		self.assertEqual(self.search('backup'), ['nas.lab.test'])
		self.assertEqual(self.search('nothing-like-this'), [])
		self.assertEqual(self.search('door camera -firmware'), [])  # negation reads the note too

	def test_the_alias_and_note_filters_and_host_matches_the_alias(self):
		self.assertEqual(self.search('alias:camera'), ['cam.lab.test'])
		self.assertEqual(self.search('alias:backup'), [])  # a note is not an alias
		self.assertEqual(self.search('note:backup'), ['nas.lab.test'])
		self.assertEqual(self.search('note:"firmware 2.1"'), ['cam.lab.test'])
		self.assertEqual(self.search('host:camera'), ['cam.lab.test'])
		self.assertEqual(self.search('host:cam.lab'), ['cam.lab.test'])
		self.assertEqual(self.search('-host:camera host:lab.test'), ['nas.lab.test'])
		self.assertEqual(self.search('alias:camera,nobody'), ['cam.lab.test'])  # a comma list is an OR here too

	def test_a_host_that_is_its_target_matches_the_targets_alias_and_note(self):
		self.assertEqual(self.search('reception'), ['10.9.9.5'])
		self.assertEqual(self.search('alias:printer'), ['10.9.9.5'])
		self.assertEqual(self.search('note:toner'), ['10.9.9.5'])
		self.assertEqual(self.search('reception cupboard'), ['10.9.9.5'])
		self.assertNotIn('cam.lab.test', self.search('reception'))  # another host of another target is not matched by it

	def test_it_says_why_a_host_matched(self):
		page = svc.search_hosts(self.ctx(self.admin), 'an-p1', {'q': 'door firmware'})['results']
		self.assertEqual(len(page), 1)
		self.assertIn('alias Door camera', page[0]['matched'])
		self.assertTrue(any(m.startswith('note firmware 2.1') for m in page[0]['matched']))

	def test_the_host_list_q_finds_by_alias_and_note_too(self):
		self.assertEqual(sorted(self.hosts(q='door')), ['cam.lab.test'])
		self.assertEqual(sorted(self.hosts(q='backup')), ['nas.lab.test'])
		self.assertEqual(sorted(self.hosts(q='reception')), ['10.9.9.5'])
		self.assertIn('cam.lab.test', self.hosts(q='cam.lab'))

	def test_the_all_projects_search_matches_the_alias_of_the_hosts_own_project_only(self):
		rows = svc.search_hosts(self.ctx(self.admin), '_all', {'q': 'alias:twin', 'page_size': 50})['results']
		self.assertEqual([(h['project'], h['host'], h['alias']) for h in rows], [('an-p1', 'twin.test', 'Twin of the first project')])
		rows = svc.search_hosts(self.ctx(self.admin), '_all', {'q': 'twin.test', 'page_size': 50})['results']
		self.assertEqual({(h['project'], h['alias']) for h in rows}, {('an-p1', 'Twin of the first project'), ('an-p2', '')})  # same name, other project: no alias
		self.assertEqual(sorted(h['host'] for h in svc.search_hosts(self.ctx(self.admin), '_all', {'q': 'door', 'page_size': 50})['results']), ['cam.lab.test'])

	def test_searching_by_alias_or_note_costs_the_queries_a_search_by_name_costs(self):
		self.host(self.lab, 'solo-a.lab.test', '198.51.100.40')
		self.host(self.lab, 'solo-b.lab.test', '198.51.100.41')
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'solo-b.lab.test', alias='Spare unit', note='shelf nine')

		def queries(q):
			with CaptureQueriesContext(connection) as ctx:
				found = svc.search_hosts(self.ctx(self.admin), 'an-p1', {'q': q, 'page_size': 100})['results']
			self.assertEqual(len(found), 1, q)
			return len(ctx)
		queries('solo-a')  # warm the caches the first call fills
		bare, field = queries('solo-a'), queries('host:solo-a')  # a bare word reads a little more for its reasons than a field does
		self.assertEqual((queries('solo-b'), queries('spare'), queries('"shelf nine"')), (bare,) * 3)
		self.assertEqual((queries('alias:spare'), queries('note:shelf'), queries('host:spare')), (field,) * 3)

	def test_the_hosts_page_costs_the_same_queries_with_and_without_aliases(self):
		names = [self.host(self.lab, f'more{i}.lab.test', f'198.51.100.{150 + i}').name for i in range(8)]

		def queries(call):
			with CaptureQueriesContext(connection) as ctx:
				call()
			return len(ctx)
		listing = lambda: svc.list_hosts(self.ctx(self.admin), 'an-p1', {'page_size': 100})  # noqa: E731
		searching = lambda: svc.search_hosts(self.ctx(self.admin), 'an-p1', {'q': 'more', 'page_size': 100})  # noqa: E731
		queries(listing), queries(searching)  # warm the caches the first call fills
		before = (queries(listing), queries(searching))
		for i, name in enumerate(names):
			hm.update_host_profile(self.ctx(self.admin), 'an-p1', name, alias=f'More {i}', note='x')
		self.assertEqual((queries(listing), queries(searching)), before)

	def test_a_saved_search_accepts_the_new_filters(self):
		self.assertEqual(len(svc.check_search('alias:camera note:firmware')), 2)


class ReportTests(Base):
	def setUp(self):
		self.cam = self.host(self.lab, 'cam.lab.test', '198.51.100.20')
		self.plain = self.host(self.lab, 'plain.lab.test', '198.51.100.21')
		Vulnerability.objects.create(name='Open admin', severity=3, subdomain=self.cam, target_domain=self.lab, scan_history=self.scans[self.lab.pk],
									http_url='https://cam.lab.test/admin')
		Vulnerability.objects.create(name='Old banner', severity=2, subdomain=self.plain, target_domain=self.lab, scan_history=self.scans[self.lab.pk],
									http_url='https://plain.lab.test/')

	def label(self, **kw):
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'cam.lab.test', **kw)

	def test_the_report_names_the_alias_beside_the_address_in_hosts_findings_and_targets(self):
		self.label(alias='Door camera', note='firmware 2.1')
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.lab.id, alias='Lab network')
		data = report_data.collect(self.p1, include_closed=True)
		rows = {h['host']: h for h in data['hosts']}
		self.assertEqual((rows['cam.lab.test']['alias'], rows['plain.lab.test']['alias']), ('Door camera', ''))
		self.assertEqual({f['host']: f['host_alias'] for f in data['findings']}, {'cam.lab.test': 'Door camera', 'plain.lab.test': ''})
		self.assertIn('lab.test (Lab network)', data['scope']['target_names'])
		html = report_pdf.build_html(data)
		self.assertIn('Door camera', html)
		self.assertIn('Lab network', html)
		self.assertIn('cam.lab.test', html)  # the address stays
		single = report_data.collect(self.p1, host='cam.lab.test')
		self.assertEqual((single['host_alias'], single['host_note'], single['host']), ('Door camera', 'firmware 2.1', 'cam.lab.test'))
		page = report_pdf.build_html(single)
		self.assertIn('cam.lab.test (Door camera)', page)
		self.assertIn('firmware 2.1', page)

	def test_markup_in_the_alias_and_note_reaches_the_report_as_inert_text(self):
		HostProfile.objects.create(project=self.p1, host='cam.lab.test', alias='<b>Cam</b>', note=EVIL)  # stored as typed, whatever wrote it
		Domain.objects.filter(pk=self.lab.pk).update(alias='<i>net</i>')
		for data in (report_data.collect(self.p1, include_closed=True), report_data.collect(self.p1, host='cam.lab.test')):
			html = report_pdf.build_html(data)
			self.assertNotIn('<script', html)
			self.assertNotIn('<img', html)
			self.assertNotIn('<b>Cam', html)
			self.assertNotIn('<i>net', html)
			self.assertIn('&lt;b&gt;Cam&lt;/b&gt;', html)
		html = report_pdf.build_html(report_data.collect(self.p1, host='cam.lab.test'))
		self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
		self.assertNotIn('onerror="', html)

	def test_a_report_without_aliases_prints_no_empty_parentheses_or_notes(self):
		data = report_data.collect(self.p1, host='cam.lab.test')
		self.assertEqual((data['host_alias'], data['host_note']), ('', ''))
		html = report_pdf.build_html(data)
		self.assertNotIn('cam.lab.test ()', html)
		self.assertIsNone(re.search(r'<td>Note</td>', html))
		self.assertEqual(report_data.collect(self.p1)['scope']['target_names'], ['10.9.9.5', 'lab.test'])

	def test_the_scan_report_shows_the_alias_beside_the_name_escaped(self):
		from unittest import mock

		from startScan import views as scan_views
		from tests.test_tenancy import client_for
		HostProfile.objects.create(project=self.p1, host='cam.lab.test', alias='<b>Cam</b>')
		root = User.objects.create_superuser('an-root', 'root@example.test', 'pw-12345-long')
		for template in ('modern', 'default'):
			with mock.patch.object(scan_views, 'render_report_pdf', return_value=b'%PDF') as pdf:
				response = client_for(root).get(f'/scan/create_report/{self.scans[self.lab.pk].pk}', {'report_template': template, 'report_type': 'full'})
			self.assertEqual(response.status_code, 200, response.content[:300])
			html = pdf.call_args[0][0]
			self.assertIn('cam.lab.test', html)
			self.assertIn('&lt;b&gt;Cam&lt;/b&gt;', html, template)
			self.assertNotIn('<b>Cam', html, template)
			self.assertNotIn('plain.lab.test (', html, template)  # a host with no alias gets no parentheses


class GraphTests(Base):
	def test_graph_nodes_carry_the_alias_and_note_only_when_there_are_some(self):
		self.host(self.lab, 'cam.lab.test', '198.51.100.20')
		self.host(self.lab, 'plain.lab.test', '198.51.100.21')
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'cam.lab.test', alias='Door camera', note='firmware 2.1')
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.lab.id, alias='Lab network')
		nodes = {n['label']: n for n in views.graph_payload()['nodes'] if n['kind'] in ('subdomain', 'domain')}
		self.assertEqual((nodes['cam.lab.test']['alias'], nodes['cam.lab.test']['note']), ('Door camera', 'firmware 2.1'))
		self.assertNotIn('alias', nodes['plain.lab.test'])
		self.assertNotIn('note', nodes['plain.lab.test'])
		self.assertEqual(nodes['lab.test']['alias'], 'Lab network')
		self.assertEqual(nodes['cam.lab.test']['label'], 'cam.lab.test')  # the label is still the name

	def test_the_node_card_lists_them_and_a_host_without_one_has_no_rows_for_them(self):
		cam = self.host(self.lab, 'cam.lab.test', '198.51.100.20')
		plain = self.host(self.lab, 'plain.lab.test', '198.51.100.21')
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'cam.lab.test', alias='Door camera', note='firmware 2.1')
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.lab.id, alias='Lab network', note='the lab')
		rows = lambda node: {r['k']: r for r in views.node_detail(node)['rows']}  # noqa: E731
		self.assertEqual((rows(f'sub:{cam.pk}')['Alias']['v'], rows(f'sub:{cam.pk}')['Note']['v']), ('Door camera', 'firmware 2.1'))
		self.assertEqual(rows(f'dom:{self.lab.pk}')['Alias']['v'], 'Lab network')
		self.assertNotIn('Alias', rows(f'sub:{plain.pk}'))

	def test_an_edit_of_an_alias_or_note_changes_the_graph_version(self):
		self.host(self.lab, 'cam.lab.test', '198.51.100.20')
		first = views.graph_version()
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'cam.lab.test', alias='Door camera')
		second = views.graph_version()
		hm.update_host_profile(self.ctx(self.admin), 'an-p1', 'cam.lab.test', alias='Door cam')  # same count, new text
		third = views.graph_version()
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.lab.id, alias='Lab network')
		fourth = views.graph_version()
		svc.set_target_profile(self.ctx(self.admin), 'an-p1', self.lab.id, alias='Lab netwerk')  # same length
		self.assertEqual(len({first, second, third, fourth, views.graph_version()}), 5)
