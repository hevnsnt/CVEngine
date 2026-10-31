"""The discovery mode chosen for a target is stored on it, and nothing that starts discovery on its own widens it (issue 284)."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import conductor, ctmonitor, tasks
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

NOW = timezone.now()


def call(token, method, path, body=None):
	c = Client()
	headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'}
	if method == 'GET':
		response = c.get(path, **headers)
	else:
		response = getattr(c, method.lower())(path, json.dumps(body if body is not None else {}), content_type='application/json', **headers)
	return response.status_code, (response.json() if response.content else None)


def tool(token, name, args=None):
	status, data = call(token, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': args or {}}})
	content = data['result']['content'][0]['text']
	return data['result']['isError'], (json.loads(content) if not data['result']['isError'] else content)


class DiscoveryModeBase(TestCase):
	def setUp(self):
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.org = Org.objects.create(name='O', slug='o')
		self.p1 = Project.objects.create(name='P1', slug='p1', insert_date=NOW, org=self.org)
		self.p2 = Project.objects.create(name='P2', slug='p2', insert_date=NOW, org=self.org)
		for name in ('cveFeed.tasks.run_bbot_discovery.delay', 'cveFeed.tasks.watch_certificate_transparency.delay',
					 'cveFeed.tasks.watch_certificate_transparency.apply_async'):
			patcher = mock.patch(name)
			patcher.start()
			self.addCleanup(patcher.stop)
		self.delay = tasks.run_bbot_discovery.delay

	def domain(self, name, project=None, mode=None):
		extra = {'discovery_mode': mode} if mode else {}
		return Domain.objects.create(name=name, project=project or self.p1, insert_date=NOW, **extra)

	def modes_run(self):
		"""{target name: mode} of every discovery queued so far."""
		by_scan = {s.id: s.domain.name for s in ScanHistory.objects.select_related('domain')}
		return {by_scan[c.args[0]]: c.args[1] for c in self.delay.call_args_list}


class ConductorHonoursTheStoredModeTests(DiscoveryModeBase):
	def setUp(self):
		super().setUp()
		claim = mock.patch('cveFeed.ledger.sweep_claim', return_value=True)
		claim.start()
		self.addCleanup(claim.stop)
		env = mock.patch.dict('os.environ', {'CVENGINE_WORK_DEPTH': '5', 'CVENGINE_WORK_MIN_GAP_HOURS': '2'})
		env.start()
		self.addCleanup(env.stop)

	def test_a_passive_target_is_never_scanned_in_standard_mode(self):
		self.domain('passive.p1.test', self.p1, 'passive')
		self.assertEqual(conductor.keep_work_queued()['started'], 1)
		self.assertEqual(self.modes_run(), {'passive.p1.test': 'passive'})

	def test_each_target_is_started_in_its_own_mode(self):
		self.domain('std.p1.test', self.p1)
		self.domain('deep.p2.test', self.p2, 'deep')
		self.assertEqual(conductor.keep_work_queued()['started'], 2)
		self.assertEqual(self.modes_run(), {'std.p1.test': 'standard', 'deep.p2.test': 'deep'})

	def test_a_manual_only_target_is_never_picked(self):
		self.domain('manual.p1.test', self.p1, 'manual')
		self.assertEqual(conductor.next_targets(5), [])
		self.assertEqual(conductor.keep_work_queued()['started'], 0)
		self.delay.assert_not_called()

	def test_a_manual_only_target_does_not_hold_its_projects_turn(self):
		self.domain('a-manual.p1.test', self.p1, 'manual')
		other = self.domain('b-auto.p1.test', self.p1)
		self.assertEqual(conductor.next_targets(5), [other.id])

	def test_a_row_that_never_had_a_mode_is_standard(self):
		with connection.cursor() as cur:  # what an install that updates has: a row written before the column, filled by the database default
			cur.execute('INSERT INTO "targetApp_domain" (name, project_id, scope_mode, insert_date) VALUES (%s, %s, %s, now())',
						['old.p1.test', self.p1.id, 'auto'])
		self.assertEqual(Domain.objects.get(name='old.p1.test').discovery_mode, 'standard')
		self.assertEqual(Domain(name='new.test').discovery_mode, 'standard')
		conductor.keep_work_queued()
		self.assertEqual(self.modes_run(), {'old.p1.test': 'standard'})


class AddTargetsStoreTheModeTests(DiscoveryModeBase):
	def setUp(self):
		super().setUp()
		self.user = User.objects.create_user('adder', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.p1, role='user')
		self.audit = User.objects.create_user('auditor', password='x')
		ProjectMembership.objects.create(user=self.audit, project=self.p1, role='audit')
		self.admin = User.objects.create_user('orgadmin', password='x')
		OrgMembership.objects.create(user=self.admin, org=self.org, role='admin')
		_, self.tok = create_token(self.user, 't')
		_, self.tok_audit = create_token(self.audit, 'a')
		_, self.tok_admin = create_token(self.admin, 'adm')

	def stored(self, name):
		return Domain.objects.get(name=name, project=self.p1).discovery_mode

	def test_bulk_add_stores_the_chosen_mode_and_scans_in_it(self):
		for mode in ('passive', 'deep', 'standard'):
			status, data = call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': f'{mode}.example', 'mode': mode})
			self.assertEqual((status, data['discovery_started']), (201, 1))
			self.assertEqual(self.stored(f'{mode}.example'), mode)
		self.assertEqual(self.modes_run(), {'passive.example': 'passive', 'deep.example': 'deep', 'standard.example': 'standard'})

	def test_just_add_is_stored_as_manual_only_and_starts_nothing(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'later.example', 'discover': False, 'mode': 'manual'})
		self.assertEqual((status, data['created'], data['discovery_started']), (201, 1, 0))
		self.assertEqual(self.stored('later.example'), 'manual')
		self.delay.assert_not_called()

	def test_no_mode_is_standard_whether_or_not_discovery_starts(self):
		call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'a.example'})
		call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'b.example', 'discover': False})
		self.assertEqual((self.stored('a.example'), self.stored('b.example')), ('standard', 'standard'))

	def test_a_mode_is_stored_even_when_discovery_is_not_started_now(self):
		call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'quiet.example', 'discover': False, 'mode': 'passive'})
		self.assertEqual(self.stored('quiet.example'), 'passive')
		self.delay.assert_not_called()

	def test_manual_with_discovery_asked_for_does_not_scan(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'contradiction.example', 'mode': 'manual'})
		self.assertEqual((status, data['discovery_started']), (201, 0))
		self.delay.assert_not_called()

	def test_an_unknown_mode_is_refused_instead_of_falling_back_to_something(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'x.example', 'mode': 'loud'})
		self.assertEqual(status, 400)
		self.assertFalse(Domain.objects.filter(name='x.example').exists())

	def test_adding_a_name_that_exists_does_not_change_its_mode(self):
		self.domain('kept.example', self.p1, 'passive')
		call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'kept.example', 'discover': False, 'mode': 'deep'})
		self.assertEqual(self.stored('kept.example'), 'passive')

	def test_a_single_add_over_rest_and_mcp_takes_a_mode(self):
		status, data = call(self.tok, 'POST', '/api/v1/projects/p1/targets', {'value': 'one.example', 'discover': True, 'mode': 'passive'})
		self.assertEqual(status, 201)
		self.assertEqual(data['created'][0]['discovery_mode'], 'passive')
		self.assertEqual(self.modes_run(), {'one.example': 'passive'})
		err, data = tool(self.tok, 'add_target', {'project': 'p1', 'value': 'two.example', 'mode': 'manual'})
		self.assertFalse(err)
		self.assertEqual((self.stored('two.example'), data['scan_ids']), ('manual', []))
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/p1/targets', {'value': 'three.example', 'mode': 'loud'})[0], 400)

	def test_a_mode_of_the_wrong_type_is_a_400_not_a_server_error(self):
		for path, body in (('targets', {'value': 'w.example', 'mode': []}), ('targets/bulk', {'text': 'w.example', 'mode': 5}),
						   ('targets/bulk', {'text': '-gone.example', 'mode': {}}), ('targets/1/discovery-mode', {'discovery_mode': []})):
			status, data = call(self.tok_admin, 'POST', '/api/v1/projects/p1/' + path, body)
			self.assertEqual(status, 400, (path, body, data))
		self.assertEqual(call(self.tok_admin, 'POST', '/api/v1/targets/bulk-org', {'text': '##O\n#P1\nw.example', 'mode': []})[0], 400)
		self.assertFalse(Domain.objects.filter(name='w.example').exists())

	def test_mcp_bulk_tools_take_manual(self):
		err, data = tool(self.tok, 'add_targets', {'project': 'p1', 'targets': ['m1.example'], 'mode': 'manual'})
		self.assertFalse(err)
		self.assertEqual((self.stored('m1.example'), data['discovery_started']), ('manual', 0))
		err, data = tool(self.tok_admin, 'add_targets_by_org', {'text': '##O\n#P1\nm2.example', 'mode': 'passive'})
		self.assertFalse(err)
		self.assertEqual(self.stored('m2.example'), 'passive')
		self.assertEqual(self.modes_run(), {'m2.example': 'passive'})

	def test_bulk_by_organization_stores_the_mode(self):
		status, data = call(self.tok_admin, 'POST', '/api/v1/targets/bulk-org', {'text': '##O\n#P1\norg.example', 'mode': 'manual'})
		self.assertEqual((status, data['discovery_started']), (201, 0))
		self.assertEqual(self.stored('org.example'), 'manual')

	def test_targets_report_their_mode(self):
		self.domain('listed.example', self.p1, 'passive')
		status, data = call(self.tok, 'GET', '/api/v1/projects/p1/targets')
		self.assertEqual([t['discovery_mode'] for t in data['results']], ['passive'])
		target_id = data['results'][0]['id']
		self.assertEqual(call(self.tok, 'GET', f'/api/v1/projects/p1/targets/{target_id}')[1]['discovery_mode'], 'passive')

	def test_the_deferred_rest_of_a_big_add_keeps_its_mode_for_the_conductor(self):
		with mock.patch('agentapi.services.BULK_DISCOVER_NOW', 1), mock.patch('cveFeed.conductor.wanted_depth', return_value=3):
			call(self.tok, 'POST', '/api/v1/projects/p1/targets/bulk', {'text': 'q1.example\nq2.example\nq3.example', 'mode': 'passive'})
		self.assertEqual({d.discovery_mode for d in Domain.objects.filter(name__startswith='q')}, {'passive'})


class DiscoverActionTests(DiscoveryModeBase):
	def setUp(self):
		super().setUp()
		self.user = User.objects.create_user('runner', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.p1, role='user')
		self.audit = User.objects.create_user('auditor2', password='x')
		ProjectMembership.objects.create(user=self.audit, project=self.p1, role='audit')
		_, self.tok = create_token(self.user, 't')
		_, self.tok_audit = create_token(self.audit, 'a')

	def discover(self, domain, body=None, token=None):
		return call(token or self.tok, 'POST', f'/api/v1/projects/p1/targets/{domain.id}/discover', body or {})

	def test_discover_without_a_mode_runs_the_stored_one(self):
		passive = self.domain('p.example', mode='passive')
		self.assertEqual(self.discover(passive)[0], 202)
		self.assertEqual(self.modes_run(), {'p.example': 'passive'})

	def test_a_standard_target_still_discovers_in_standard(self):
		self.assertEqual(self.discover(self.domain('s.example'))[0], 202)
		self.assertEqual(self.modes_run(), {'s.example': 'standard'})

	def test_a_mode_given_to_discover_is_kept_for_the_next_automatic_scan(self):
		target = self.domain('c.example')
		self.assertEqual(self.discover(target, {'mode': 'passive'})[0], 202)
		target.refresh_from_db()
		self.assertEqual(target.discovery_mode, 'passive')
		self.assertEqual(self.modes_run(), {'c.example': 'passive'})

	def test_a_manual_only_target_needs_a_mode_chosen_before_it_is_discovered(self):
		target = self.domain('m.example', mode='manual')
		status, data = self.discover(target)
		self.assertEqual(status, 409)
		self.assertIn('manual', data['error'])
		self.delay.assert_not_called()
		self.assertEqual(self.discover(target, {'mode': 'passive'})[0], 202)
		target.refresh_from_db()
		self.assertEqual(target.discovery_mode, 'passive')

	def test_manual_is_not_a_mode_to_run(self):
		target = self.domain('n.example')
		self.assertEqual(self.discover(target, {'mode': 'manual'})[0], 400)
		self.assertEqual(self.discover(target, {'mode': 'loud'})[0], 400)
		target.refresh_from_db()
		self.assertEqual(target.discovery_mode, 'standard')
		self.delay.assert_not_called()

	def test_the_scan_button_and_start_scan_use_the_stored_mode_too(self):
		passive = self.domain('sp.example', mode='passive')
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/p1/scans', {'target_id': passive.id})[0], 202)
		self.assertEqual(self.modes_run(), {'sp.example': 'passive'})
		manual = self.domain('sm.example', mode='manual')
		self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/p1/scans', {'target_id': manual.id})[0], 409)
		err, msg = tool(self.tok, 'start_scan', {'project': 'p1', 'target_id': manual.id})
		self.assertTrue(err)

	def test_mcp_discover_target_uses_the_stored_mode(self):
		passive = self.domain('mp.example', mode='passive')
		err, data = tool(self.tok, 'discover_target', {'project': 'p1', 'target_id': passive.id})
		self.assertFalse(err)
		self.assertEqual(self.modes_run(), {'mp.example': 'passive'})

	def test_the_mode_can_be_changed_over_rest_and_mcp(self):
		target = self.domain('chg.example', mode='manual')
		status, data = call(self.tok, 'POST', f'/api/v1/projects/p1/targets/{target.id}/discovery-mode', {'discovery_mode': 'passive'})
		self.assertEqual((status, data['discovery_mode']), (200, 'passive'))
		err, data = tool(self.tok, 'set_target_discovery_mode', {'project': 'p1', 'target_id': target.id, 'discovery_mode': 'manual'})
		self.assertFalse(err)
		target.refresh_from_db()
		self.assertEqual(target.discovery_mode, 'manual')
		self.assertEqual(call(self.tok, 'POST', f'/api/v1/projects/p1/targets/{target.id}/discovery-mode', {'discovery_mode': 'loud'})[0], 400)
		self.assertEqual(call(self.tok, 'POST', f'/api/v1/projects/p1/targets/{target.id}/discovery-mode', {})[0], 400)
		self.delay.assert_not_called()  # changing the mode never starts a scan

	def test_changing_the_mode_needs_write_access_to_the_project(self):
		target = self.domain('ro.example')
		self.assertEqual(call(self.tok_audit, 'POST', f'/api/v1/projects/p1/targets/{target.id}/discovery-mode', {'discovery_mode': 'passive'})[0], 403)
		self.assertEqual(call(self.tok, 'POST', f'/api/v1/projects/p2/targets/{target.id}/discovery-mode', {'discovery_mode': 'passive'})[0], 404)
		target.refresh_from_db()
		self.assertEqual(target.discovery_mode, 'standard')


class OtherAutomaticPathsTests(DiscoveryModeBase):
	def test_the_weekly_deep_sweep_never_widens_a_passive_or_manual_target(self):
		from cveFeed import ledger
		self.domain('www.passive-apex.com', mode='passive')
		self.domain('www.manual-apex.com', mode='manual')
		self.domain('www.standard-apex.com')
		self.domain('manual-existing.com', mode='manual')
		self.domain('www.manual-existing.com')  # its apex row is manual only: not deep scanned through a standard subdomain either
		with mock.patch.object(ledger, 'sweep_claim', return_value=True):
			tasks.deep_scan_apexes()
		self.assertEqual(self.modes_run(), {'standard-apex.com': 'deep'})
		self.assertFalse(Domain.objects.filter(name__in=['passive-apex.com', 'manual-apex.com']).exists())

	def test_certificate_transparency_does_not_start_the_host_pipeline_for_a_manual_only_target(self):
		manual = self.domain('manual.ct.test', mode='manual')
		auto = self.domain('auto.ct.test', mode='passive')
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline, mock.patch.object(ctmonitor, 'MIN_GAP', (0, 0)):
			ctmonitor.run_ct_watch(manual.id, fetch=lambda name: {'new.manual.ct.test'})
			pipeline.assert_not_called()
			ctmonitor.run_ct_watch(auto.id, fetch=lambda name: {'new.auto.ct.test'})
			pipeline.assert_called_once()
		from startScan.models import Subdomain
		self.assertTrue(Subdomain.objects.filter(target_domain=manual, name='new.manual.ct.test').exists())  # still recorded

	def test_the_assessment_review_rediscovers_in_the_stored_mode_and_skips_manual_targets(self):
		from cveFeed import assessment_review as ar
		passive = self.domain('review.example.test', mode='passive')
		with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
			status, scan_id, _ = ar.dispatch(self.p1, {'due_discovery_target_id': passive.id}, 'discover')
		self.assertEqual(status, 'queued')
		self.assertEqual(self.modes_run(), {'review.example.test': 'passive'})
		manual = self.domain('review-manual.example.test', self.p2, 'manual')
		with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
			self.assertEqual(ar.dispatch(self.p2, {'due_discovery_target_id': manual.id}, 'discover')[0], 'stale')
		self.assertEqual(len(self.delay.call_args_list), 1)

	def test_a_moved_target_is_scanned_in_its_own_mode(self):
		from agentapi.target_move import move_target
		from agentapi.services import Ctx
		user = User.objects.create_user('mover', password='x')
		OrgMembership.objects.create(user=user, org=self.org, role='admin')
		self.domain('moved.example', self.p1, 'passive')
		move_target(Ctx(user=user), self.p1, self.p2, 'moved.example')
		self.assertEqual(self.modes_run(), {'moved.example': 'passive'})
		manual = self.domain('moved-manual.example', self.p1, 'manual')
		move_target(Ctx(user=user), self.p1, self.p2, 'moved-manual.example')
		self.assertEqual(list(self.modes_run()), ['moved.example'])  # a manual only target is moved, not scanned
