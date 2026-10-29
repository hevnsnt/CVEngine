import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import ctmonitor, discovery
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, rpc


def _stages(**over):
	"""Stage doubles, so no scanner binary runs."""
	nmap = []

	def runner(targets, flags, timeout):
		nmap.append(list(targets))
		return ''
	kwargs = dict(resolver=lambda names: {(n, '192.0.2.%d' % (10 + i)) for i, n in enumerate(sorted(names))},
		light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]), nmap_runner=runner,
		db_exposure_checks={}, provider=None, route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
	kwargs.update(over)
	return nmap, kwargs


class HostPipelineTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='H', slug='h')
		self.project = Project.objects.create(name='P', slug='ph', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='hp.test', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		patches = [mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay')]
		self.hygiene = patches[1].start()
		patches[0].start()
		self.addCleanup(mock.patch.stopall)

	def test_new_hosts_are_resolved_recorded_and_taken_through_the_stages_without_bbot(self):
		nmap, kwargs = _stages()
		with mock.patch('reNgine.bbot.stream_events', side_effect=AssertionError('bbot must not run')):
			out = discovery.run_host_pipeline(self.domain.id, ['WWW.hp.test', 'api.hp.test', 'evil.example.com', 'hp.test.evil.com'], **kwargs)
		scan = ScanHistory.objects.get(pk=out['scan_id'])
		self.assertEqual(scan.scan_status, discovery.SUCCESS)
		self.assertEqual(scan.tasks, [discovery.HOST_PIPELINE_TASK])
		self.assertEqual(sorted(Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True)), ['api.hp.test', 'www.hp.test'])
		self.assertEqual(nmap, [['192.0.2.10', '192.0.2.11']])
		self.assertEqual(out['hosts'], 2)
		names = set(ScanActivity.objects.filter(scan_of=scan).values_list('name', flat=True))
		self.assertTrue({'host_resolve', 'nmap_scan', 'db_exposure_scan', 'nuclei_light_scan', 'cve_correlation',
			'nuclei_targeted_scan'} <= names)
		self.hygiene.assert_not_called()  # the hygiene sweep of the whole target is not repeated for a few hosts

	def test_the_ledger_dedupes_a_second_run_over_the_same_hosts(self):
		nmap, kwargs = _stages()
		discovery.run_host_pipeline(self.domain.id, ['www.hp.test'], **kwargs)
		discovery.run_host_pipeline(self.domain.id, ['www.hp.test'], **kwargs)
		self.assertEqual(len(nmap), 1)  # the IP was fingerprinted once

	def test_the_stop_flag_is_honoured_between_stages(self):
		nmap, kwargs = _stages()
		exposure = mock.Mock(return_value={'checked': 0, 'exposed': 0})
		calls = iter([False, True])  # not stopped before nmap, stopped after it
		with mock.patch.object(discovery, 'stopped', side_effect=lambda scan_id: next(calls, True)), \
				mock.patch('cveFeed.db_exposure.run_db_exposure_checks', exposure):
			out = discovery.run_host_pipeline(self.domain.id, ['www.hp.test'], **kwargs)
		self.assertEqual(out['status'], 'aborted')
		self.assertEqual(len(nmap), 1)
		exposure.assert_not_called()

	def test_a_stage_failure_does_not_stop_the_pipeline(self):
		def boom(targets, flags, timeout):
			raise RuntimeError('nmap exploded')
		_, kwargs = _stages(nmap_runner=boom)
		out = discovery.run_host_pipeline(self.domain.id, ['www.hp.test'], **kwargs)
		scan = ScanHistory.objects.get(pk=out['scan_id'])
		self.assertEqual(scan.scan_status, discovery.SUCCESS)  # the host it found stands; the failed stage is on record
		self.assertIn('nmap_scan', scan.error_message)
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='nmap_scan').status, discovery.FAILED)

	def test_nothing_in_scope_creates_no_scan(self):
		_, kwargs = _stages()
		self.assertEqual(discovery.run_host_pipeline(self.domain.id, ['other.example.com'], **kwargs)['status'], 'empty')
		self.assertEqual(ScanHistory.objects.count(), 0)

	def test_a_host_pipeline_does_not_count_as_a_discovery_of_the_target(self):
		engine = EngineType.objects.first()
		ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=discovery.QUEUED, start_scan_date=timezone.now(),
			tasks=[discovery.HOST_PIPELINE_TASK])
		self.assertIsNone(discovery.running_discovery(self.domain))
		real = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=discovery.QUEUED, start_scan_date=timezone.now(),
			tasks=['x'])
		plain = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=discovery.QUEUED, start_scan_date=timezone.now())
		self.assertEqual(discovery.running_discovery(self.domain).id, plain.id)
		self.assertGreater(plain.id, real.id)

	def test_ct_watch_dispatches_the_pipeline_for_newly_created_names_only(self):
		Subdomain.objects.create(target_domain=self.domain, name='known.hp.test')
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as delay:
			ctmonitor.run_ct_watch(self.domain.id, fetch=lambda name: {'known.hp.test', 'new1.hp.test', 'new2.hp.test'})
			ctmonitor.run_ct_watch(self.domain.id, fetch=lambda name: {'known.hp.test', 'new1.hp.test', 'new2.hp.test'})
		delay.assert_called_once_with(self.domain.id, ['new1.hp.test', 'new2.hp.test'])

	def test_a_queue_failure_does_not_lose_the_ct_finds(self):
		with mock.patch('cveFeed.tasks.host_pipeline.delay', side_effect=OSError('broker down')):
			out = ctmonitor.run_ct_watch(self.domain.id, fetch=lambda name: {'new1.hp.test'})
		self.assertEqual(out['new'], 1)
		self.assertTrue(Subdomain.objects.filter(name='new1.hp.test').exists())


class RescanHostsApiTests(TestCase):
	def setUp(self):
		now = timezone.now()
		org = Org.objects.create(name='R', slug='r')
		self.project = Project.objects.create(name='P', slug='pr', insert_date=now, org=org)
		self.domain = Domain.objects.create(name='rs.test', project=self.project, insert_date=now)
		self.user = User.objects.create_user('rsu', password='x')
		self.auditor = User.objects.create_user('rsa', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
		ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')
		_, self.token = create_token(self.user, 'agent')
		_, self.audit_token = create_token(self.auditor, 'auditor')

	def test_rest_queues_the_hosts_under_the_target(self):
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as delay:
			status, body = call(self.token, 'POST', f'/api/v1/projects/pr/targets/{self.domain.id}/rescan-hosts',
				{'hosts': ['www.rs.test', 'API.rs.test.', 'elsewhere.example.com']})
		self.assertEqual(status, 202)
		self.assertEqual(body['queued'], 2)
		self.assertEqual(body['skipped'], 1)
		delay.assert_called_once_with(self.domain.id, ['www.rs.test', 'api.rs.test'], by_person=True)

	def test_rest_validates_and_respects_roles(self):
		path = f'/api/v1/projects/pr/targets/{self.domain.id}/rescan-hosts'
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as delay:
			self.assertEqual(call(self.token, 'POST', path, {'hosts': []})[0], 400)
			self.assertEqual(call(self.token, 'POST', path, {'hosts': ['x.example.com']})[0], 400)
			self.assertEqual(call(self.token, 'POST', '/api/v1/projects/pr/targets/999999/rescan-hosts', {'hosts': ['a.rs.test']})[0], 404)
			self.assertEqual(call(self.audit_token, 'POST', path, {'hosts': ['a.rs.test']})[0], 403)
		delay.assert_not_called()

	def test_mcp_tool_is_listed_as_a_write_tool_and_queues(self):
		_, listing = rpc(self.token, 'tools/list')
		tool = next(t for t in listing['result']['tools'] if t['name'] == 'rescan_hosts')
		self.assertFalse(tool['annotations']['readOnlyHint'])
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as delay:
			_, out = rpc(self.token, 'tools/call', {'name': 'rescan_hosts',
				'arguments': {'project': 'pr', 'target_id': self.domain.id, 'hosts': ['www.rs.test']}})
		self.assertFalse(out['result']['isError'])
		self.assertEqual(json.loads(out['result']['content'][0]['text'])['queued'], 1)
		delay.assert_called_once_with(self.domain.id, ['www.rs.test'], by_person=True)
