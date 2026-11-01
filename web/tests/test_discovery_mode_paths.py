"""Nothing the system starts on its own widens the discovery mode stored on a target (issue 284): a lost queued scan is sent again in the
mode it was queued in, a passive or manual only target gets no scheduled internal scan or certificate-transparency pipeline, and a manual
only target ("just add them, do not scan yet") is left alone by every sweep that picks hosts or targets by itself."""
import json
import uuid
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from cveFeed import assessment_review as ar
from cveFeed import conductor, coverage_topup, ctmonitor, fullscan, host_assessment, reaper, tasks
from cveFeed.models import HostAssessment
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests import test_internal_scan as internal
from tests.test_discovery_mode import DiscoveryModeBase

NOW = timezone.now()


class ScanRowKeepsTheModeTests(DiscoveryModeBase):
	def setUp(self):
		super().setUp()
		claim = mock.patch('cveFeed.ledger.sweep_claim', return_value=True)
		claim.start()
		self.addCleanup(claim.stop)
		env = mock.patch.dict('os.environ', {'CVENGINE_WORK_DEPTH': '5', 'CVENGINE_WORK_MIN_GAP_HOURS': '2'})
		env.start()
		self.addCleanup(env.stop)

	def test_a_queued_scan_records_the_mode_it_was_queued_in(self):
		self.domain('p.test', mode='passive')
		self.domain('d.test', self.p2, mode='deep')
		conductor.keep_work_queued()
		self.assertEqual({s.domain.name: s.discovery_mode for s in ScanHistory.objects.select_related('domain')},
						 {'p.test': 'passive', 'd.test': 'deep'})

	def test_a_scan_from_before_the_mode_was_recorded_has_none(self):
		scan = ScanHistory.objects.create(domain=self.domain('old.test'), scan_type=self.engine, start_scan_date=NOW, scan_status=-1, results_dir='/tmp')
		self.assertEqual(ScanHistory.objects.get(pk=scan.pk).discovery_mode, '')


class LostScanIsRecoveredInItsModeTests(DiscoveryModeBase):
	def setUp(self):
		super().setUp()
		from reNgine import resources
		client = resources.get_store().r
		self.addCleanup(lambda: [client.delete(k) for k in client.scan_iter('cvengine:scan:redispatch:*')])
		[client.delete(k) for k in client.scan_iter('cvengine:scan:redispatch:*')]

	def lost(self, domain, mode='', tasks_=None):
		return ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=NOW - timedelta(hours=2), scan_status=-1,
										  results_dir='/tmp', discovery_mode=mode, tasks=tasks_)

	def sent(self):
		with mock.patch('reNgine.celery.app.send_task') as send:
			count = reaper.redispatch_queued_scans(now=NOW, live=set())
		return count, {c.kwargs['args'][0]: c for c in send.call_args_list}

	def test_a_passive_scan_is_not_recovered_as_a_standard_one(self):
		scan = self.lost(self.domain('p.test'), 'passive')  # a one-off passive run of a standard target: neither the target's mode nor the default
		count, calls = self.sent()
		self.assertEqual(count, 1)
		self.assertEqual(calls[scan.pk].args, ('run_bbot_discovery',))
		self.assertEqual(calls[scan.pk].kwargs['args'], [scan.pk, 'passive'])

	def test_each_scan_is_recovered_in_its_own_mode(self):
		deep = self.lost(self.domain('d.test', self.p1, 'standard'), 'deep')
		std = self.lost(self.domain('s.test', self.p2, 'passive'), 'standard')
		count, calls = self.sent()
		self.assertEqual(count, 2)
		self.assertEqual(calls[deep.pk].kwargs['args'], [deep.pk, 'deep'])
		self.assertEqual(calls[std.pk].kwargs['args'], [std.pk, 'standard'])

	def test_a_scan_with_no_recorded_mode_takes_its_targets_never_a_wider_one(self):
		passive = self.lost(self.domain('old-p.test', mode='passive'))
		deep = self.lost(self.domain('old-d.test', self.p2, 'deep'))
		standard = self.lost(self.domain('old-s.test'))
		manual = self.lost(self.domain('old-m.test', self.p2, 'manual'))
		count, calls = self.sent()
		self.assertEqual(count, 4)
		self.assertEqual({pk: c.kwargs['args'][1] for pk, c in calls.items()},
						 {passive.pk: 'passive', deep.pk: 'deep', standard.pk: 'standard', manual.pk: 'passive'})

	def test_an_internal_scan_is_still_sent_with_its_scan_id_only(self):
		scan = self.lost(self.domain('10.0.0.5'), '', ['internal_pipeline'])
		_, calls = self.sent()
		self.assertEqual(calls[scan.pk].args, ('run_internal_scan',))
		self.assertEqual(calls[scan.pk].kwargs['args'], [scan.pk])

	def test_the_recovered_scan_runs_in_that_mode_end_to_end(self):
		"""The message the reaper sends is the one run_bbot_discovery takes: its second argument is the mode the pipeline runs."""
		scan = self.lost(self.domain('e2e.test', mode='passive'))
		_, calls = self.sent()
		args = calls[scan.pk].kwargs['args']
		with mock.patch('cveFeed.discovery.run_pipeline', return_value={'status': 'ok'}) as run:
			tasks.run_bbot_discovery.apply(args=args)
		run.assert_called_once_with(scan.pk, 'passive')


class WizardTests(DiscoveryModeBase):
	def post(self, **body):
		admin = User.objects.create_superuser('wiz', 'wiz@example.test', 'x')
		c = Client()
		c.force_login(admin)
		response = c.post('/cve/api/welcome/target', json.dumps({'authorized': True, 'project': 'p1', **body}), content_type='application/json')
		return response.status_code, response.json()

	def test_a_new_first_target_is_scanned_in_standard(self):
		status, body = self.post(value='first.example.test')
		self.assertEqual(status, 200, body)
		self.assertEqual(self.modes_run(), {'first.example.test': 'standard'})

	def test_repeating_it_for_a_passive_target_that_exists_keeps_it_passive(self):
		self.domain('again.example.test', mode='passive')
		status, body = self.post(value='again.example.test')
		self.assertEqual(status, 200, body)
		self.assertEqual(self.modes_run(), {'again.example.test': 'passive'})
		self.assertIsNotNone(body['scan_id'])

	def test_repeating_it_for_a_manual_only_target_scans_nothing(self):
		self.domain('manual.example.test', mode='manual')
		status, body = self.post(value='manual.example.test')
		self.assertEqual(status, 200, body)
		self.delay.assert_not_called()
		self.assertIsNone(body['scan_id'])
		self.assertFalse(ScanHistory.objects.exists())


class CertificateTransparencyTests(DiscoveryModeBase):
	def found(self, domain):
		with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline, mock.patch.object(ctmonitor, 'MIN_GAP', (0, 0)):
			ctmonitor.run_ct_watch(domain.id, fetch=lambda name: {f'new.{name}'})
		return pipeline

	def test_a_passive_target_records_new_hosts_and_connects_to_none_of_them(self):
		target = self.domain('passive.ct.test', mode='passive')
		self.found(target).assert_not_called()
		self.assertTrue(Subdomain.objects.filter(target_domain=target, name='new.passive.ct.test').exists())

	def test_a_manual_only_target_records_new_hosts_and_connects_to_none_of_them(self):
		target = self.domain('manual.ct.test', mode='manual')
		self.found(target).assert_not_called()
		self.assertTrue(Subdomain.objects.filter(target_domain=target, name='new.manual.ct.test').exists())

	def test_standard_and_deep_targets_still_get_the_pipeline(self):
		for mode in ('standard', 'deep'):
			target = self.domain(f'{mode}.ct.test', mode=mode)
			self.found(target).assert_called_once()


class InternalSweepTests(internal.Base):
	def setUp(self):
		super().setUp()
		self.sentinel('inside', ['nmap', 'network:internal'])

	def test_a_standard_or_deep_internal_target_is_swept(self):
		for mode in ('standard', 'deep'):
			Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=mode)
			self.assertEqual([d.id for d in internal_scan_due()], [self.domain.id], mode)

	def test_a_passive_or_manual_only_internal_target_is_never_swept(self):
		for mode in ('passive', 'manual'):
			Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=mode)
			self.assertEqual(internal_scan_due(), [], mode)
			with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), mock.patch('cveFeed.tasks.run_internal_scan') as task:
				self.assertEqual(internal_scan_sweep()['started'], 0)
			task.delay.assert_not_called()

	def test_a_person_can_still_start_one(self):
		Domain.objects.filter(pk=self.domain.pk).update(discovery_mode='manual')
		with mock.patch('cveFeed.tasks.run_internal_scan') as task:
			scan = internal_scan_start(self.domain)
		task.delay.assert_called_once_with(scan.id)


def internal_scan_due():
	from cveFeed import internal_scan
	return internal_scan.due_targets()


def internal_scan_sweep():
	from cveFeed import internal_scan
	return internal_scan.sweep()


def internal_scan_start(domain):
	from cveFeed import internal_scan
	return internal_scan.start(domain)


class ManualOnlyHostsTests(DiscoveryModeBase):
	"""Hosts that exist under a target set to manual only (recorded by certificate transparency, or from a scan before it was changed)."""

	def setUp(self):
		super().setUp()
		self.manual = self.domain('manual.hosts.test', mode='manual')
		self.auto = self.domain('auto.hosts.test', self.p2)
		self.manual_host = Subdomain.objects.create(target_domain=self.manual, name='www.manual.hosts.test')
		self.auto_host = Subdomain.objects.create(target_domain=self.auto, name='www.auto.hosts.test')
		for name in ('cveFeed.tasks.assess_host.apply_async', 'cveFeed.tasks.assess_hosts.apply_async'):
			patcher = mock.patch(name, side_effect=lambda *a, **k: mock.Mock(id=str(uuid.uuid4())))
			patcher.start()
			self.addCleanup(patcher.stop)
		patcher = mock.patch('cveFeed.scan_control.pause_requested', return_value=False)
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_a_manual_only_targets_hosts_are_no_first_pass_backlog(self):
		self.assertEqual(ar.host_coverage_due(self.p1, NOW), (0, []))
		count, due = ar.host_coverage_due(self.p2, NOW)
		self.assertEqual((count, due), (1, [self.auto_host.pk]))

	def test_the_top_up_assesses_the_other_projects_hosts_and_not_the_manual_ones(self):
		result = coverage_topup.top_up(now=NOW)
		self.assertEqual(result['hosts_queued'], 1)
		self.assertEqual(list(HostAssessment.objects.values_list('host', flat=True)), ['www.auto.hosts.test'])

	def test_the_refresh_leaves_manual_only_hosts_out(self):
		got = coverage_topup.stalest_hosts(self.p1, NOW, 10, timedelta(hours=1))
		self.assertEqual(got, [])
		self.assertEqual([s.pk for s in coverage_topup.stalest_hosts(self.p2, NOW, 10, timedelta(hours=1))], [self.auto_host.pk])

	def test_the_deep_scan_gate_does_not_wait_for_a_backlog_nothing_will_work_off(self):
		self.assertTrue(coverage_topup.backlog_exists(NOW))  # the other project's host is waiting for its first pass
		self.auto_host.delete()
		self.assertFalse(coverage_topup.backlog_exists(NOW))  # only the manual only target's host is left: no sweep waits for it

	def test_an_automatic_assessment_of_a_manual_only_host_is_refused_a_persons_is_not(self):
		with self.assertRaisesRegex(ValueError, 'manual only'):
			host_assessment.enqueue(self.p1, self.manual_host, source='review')
		self.assertFalse(HostAssessment.objects.exists())
		user = User.objects.create_user('asker', password='x')
		job, created = host_assessment.enqueue(self.p1, self.manual_host, source='manual', user=user)
		self.assertTrue(created)
		self.assertEqual(job.host, 'www.manual.hosts.test')

	def test_a_batch_leaves_the_manual_only_host_out(self):
		jobs, skipped = host_assessment.enqueue_batch(self.p1, [self.manual_host, Subdomain.objects.create(target_domain=self.manual, name='b.manual.hosts.test')])
		self.assertEqual(jobs, [])
		self.assertEqual(len(skipped), 2)
		self.assertTrue(all('manual only' in why for _sub, why in skipped))

	def test_a_queued_assessment_is_dropped_when_the_target_was_made_manual_only_meanwhile(self):
		Domain.objects.filter(pk=self.manual.pk).update(discovery_mode='standard')
		job, _ = host_assessment.enqueue(self.p1, Subdomain.objects.get(pk=self.manual_host.pk), source='topup')
		Domain.objects.filter(pk=self.manual.pk).update(discovery_mode='manual')
		job = HostAssessment.objects.select_related('domain').get(pk=job.pk)
		self.assertTrue(host_assessment._unassessable(job))
		person = User.objects.create_user('p', password='x')
		HostAssessment.objects.filter(pk=job.pk).update(requested_by=person)
		self.assertFalse(host_assessment._unassessable(HostAssessment.objects.select_related('domain').get(pk=job.pk)))

	def test_the_full_port_sweep_never_picks_an_address_only_a_manual_only_target_has(self):
		for address, sub in (('192.0.2.10', self.manual_host), ('192.0.2.11', self.auto_host)):
			sub.ip_addresses.add(IpAddress.objects.create(address=address, org=self.org))
		self.assertEqual(list(fullscan.candidates().values_list('address', flat=True)), ['192.0.2.11'])
		shared = IpAddress.objects.get(address='192.0.2.10')
		self.auto_host.ip_addresses.add(shared)  # another target's host answers on the same address: it is in scope through that one
		self.assertEqual(sorted(fullscan.candidates().values_list('address', flat=True)), ['192.0.2.10', '192.0.2.11'])

	def test_the_udp_sweep_shares_that_selection(self):
		from cveFeed import udp_scan
		self.manual_host.ip_addresses.add(IpAddress.objects.create(address='192.0.2.20', org=self.org))
		self.auto_host.ip_addresses.add(IpAddress.objects.create(address='192.0.2.21', org=self.org))
		self.assertEqual([ip.address for ip in udp_scan.due()], ['192.0.2.21'])

	def test_the_daily_hygiene_sweep_skips_a_manual_only_target(self):
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=True), mock.patch('cveFeed.tasks.run_hygiene_task.delay') as queued:
			tasks.run_hygiene_all()
		self.assertEqual(sorted(c.args[0] for c in queued.call_args_list), [self.auto.id])

	def test_the_weekly_deep_nuclei_lane_has_no_host_of_a_manual_only_target(self):
		from cveFeed.models import BackgroundCursor
		for sub, domain in ((self.manual_host, self.manual), (self.auto_host, self.auto)):
			scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=NOW, scan_status=2, results_dir='/tmp')
			Subdomain.objects.filter(pk=sub.pk).update(scan_history=scan)
		with mock.patch('cveFeed.nuclei_scan.approved_templates', side_effect=RuntimeError('no library')):
			result = tasks.weekly_deep_nuclei()
			self.assertEqual(result['status'], 'failed')  # the other project's host is in the lane: it got as far as the template library
			self.assertEqual(BackgroundCursor.objects.get(lane='weekly_nuclei').last_pk, 0)
			Subdomain.objects.filter(pk=self.auto_host.pk).delete()
			self.assertEqual(tasks.weekly_deep_nuclei()['status'], 'no_inventory')  # only the manual only target's host is left


class QueuedThenMadeManualTests(DiscoveryModeBase):
	"""A target set to manual only after the system queued a scan for it is not scanned when that scan's turn comes."""

	def queued(self, domain, person=None):
		return ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=NOW, scan_status=-1, results_dir='/tmp', initiated_by=person)

	def run_it(self, scan):
		from cveFeed import discovery
		with mock.patch('cveFeed.discovery.run_discovery') as bbot, mock.patch('cveFeed.discovery.mark_running'):
			out = discovery._run_pipeline(scan.pk, 'standard')
		return out, bbot

	def test_a_scan_the_system_queued_is_failed_with_a_reason_when_the_target_is_manual_only_by_then(self):
		scan = self.queued(self.domain('late.example.test', mode='manual'))
		out, bbot = self.run_it(scan)
		bbot.assert_not_called()
		self.assertEqual(out['status'], 0)
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 0)
		self.assertIn('manual only', scan.error_message)

	def test_a_scan_a_person_asked_for_runs_whatever_the_stored_mode(self):
		person = User.objects.create_user('asker2', password='x')
		scan = self.queued(self.domain('asked.example.test', mode='manual'), person)
		with mock.patch('cveFeed.discovery.covering_scan', return_value=None):
			out, bbot = self.run_it(scan)
		bbot.assert_called_once()

	def test_a_standard_target_is_unaffected(self):
		scan = self.queued(self.domain('plain.example.test'))
		with mock.patch('cveFeed.discovery.covering_scan', return_value=None):
			out, bbot = self.run_it(scan)
		bbot.assert_called_once()


class DiscoverAnswerTests(DiscoveryModeBase):
	"""Discover answers with the mode it stored and the mode the scan it returned runs in, so a page shows what happened, not what it asked for."""

	def setUp(self):
		super().setUp()
		from agentapi.auth import create_token
		from dashboard.models import ProjectMembership
		self.user = User.objects.create_user('answerer', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.p1, role='user')
		self.tok = create_token(self.user, 't')[1]

	def discover(self, domain, body=None):
		from tests.test_discovery_mode import call
		return call(self.tok, 'POST', f'/api/v1/projects/p1/targets/{domain.id}/discover', body or {})

	def test_the_answer_names_the_stored_mode_and_the_mode_the_scan_runs_in(self):
		status, out = self.discover(self.domain('a.example', mode='passive'))
		self.assertEqual((status, out['discovery_mode'], out['scan_mode']), (202, 'passive', 'passive'))
		status, out = self.discover(self.domain('b.example', mode='manual'), {'mode': 'deep'})
		self.assertEqual((status, out['discovery_mode'], out['scan_mode']), (202, 'deep', 'deep'))
		self.assertEqual(Domain.objects.get(name='b.example').discovery_mode, 'deep')

	def test_a_scan_already_going_keeps_its_mode_and_the_answer_says_so(self):
		target = self.domain('busy.example')
		first = self.discover(target)[1]
		self.assertEqual((first['discovery_mode'], first['scan_mode']), ('standard', 'standard'))
		status, out = self.discover(target, {'mode': 'deep'})
		self.assertEqual((status, out['scan_id']), (202, first['scan_id']))  # the same scan: it was not started again
		self.assertEqual((out['discovery_mode'], out['scan_mode']), ('deep', 'standard'))  # the target is deep from now on; this scan stays standard
		self.assertEqual(Domain.objects.get(name='busy.example').discovery_mode, 'deep')
		self.assertEqual(ScanHistory.objects.get(pk=first['scan_id']).discovery_mode, 'standard')

	def test_an_internal_target_keeps_its_mode_whatever_was_picked_and_the_answer_says_so(self):
		from cveFeed.models import InternalRange
		InternalRange.objects.create(project=self.p1, cidr='10.20.0.0/24')
		target = self.domain('10.20.0.7', mode='manual')
		with mock.patch('cveFeed.tasks.run_internal_scan'):
			status, out = self.discover(target, {'mode': 'passive'})
		self.assertEqual(status, 202)
		self.assertEqual((out['internal'], out['discovery_mode'], out['scan_mode']), (True, 'manual', ''))
		self.assertEqual(Domain.objects.get(pk=target.pk).discovery_mode, 'manual')  # nothing was stored: the page must not show passive

	def test_mcp_answers_the_same_way(self):
		from tests.test_discovery_mode import tool
		target = self.domain('mcp.example', mode='passive')
		error, out = tool(self.tok, 'discover_target', {'project': 'p1', 'target_id': target.id})
		self.assertFalse(error)
		self.assertEqual((out['discovery_mode'], out['scan_mode']), ('passive', 'passive'))
