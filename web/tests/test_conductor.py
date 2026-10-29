from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import conductor
from cveFeed.models import BountyAsset, BountyEngagement, BountyProgram, HostExclusion, ScanControl
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

NOW = timezone.now()


class ConductorTests(TestCase):
	def setUp(self):
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.org = Org.objects.create(name='O', slug='o')
		self.p1 = Project.objects.create(name='P1', slug='p1', insert_date=NOW, org=self.org)
		self.p2 = Project.objects.create(name='P2', slug='p2', insert_date=NOW, org=self.org)
		patcher = mock.patch('cveFeed.tasks.run_bbot_discovery.delay')
		self.delay = patcher.start()
		self.addCleanup(patcher.stop)
		claim = mock.patch('cveFeed.ledger.sweep_claim', return_value=True)
		claim.start()
		self.addCleanup(claim.stop)
		env = mock.patch.dict('os.environ', {'CVENGINE_WORK_DEPTH': '3', 'CVENGINE_WORK_MIN_GAP_HOURS': '2'})
		env.start()
		self.addCleanup(env.stop)

	def domain(self, name, project=None):
		return Domain.objects.create(name=name, project=project or self.p1, insert_date=NOW)

	def scan(self, domain, status, hours_ago):
		return ScanHistory.objects.create(domain=domain, scan_type=self.engine, scan_status=status,
										  start_scan_date=NOW - timedelta(hours=hours_ago), results_dir='/x')

	def queued_names(self):
		return set(ScanHistory.objects.filter(scan_status=-1).values_list('domain__name', flat=True))

	def test_the_discovery_queue_is_filled_from_the_most_overdue_targets_one_per_project(self):
		a = self.domain('never.p1.test')
		b = self.domain('old.p1.test')
		c = self.domain('older.p2.test', self.p2)
		d = self.domain('fresh.p2.test', self.p2)
		self.scan(b, 2, 50)
		self.scan(c, 2, 400)
		self.scan(d, 2, 1)  # inside the minimum gap
		result = conductor.keep_work_queued()
		self.assertEqual(result['started'], 2)
		self.assertEqual(self.queued_names(), {'never.p1.test', 'older.p2.test'})  # never scanned first; one per project
		self.assertEqual(self.delay.call_count, 2)

	def test_only_the_missing_depth_is_started(self):
		names = [self.domain(f'h{i}.p{1 + i % 2}.test', self.p1 if i % 2 == 0 else self.p2) for i in range(6)]
		self.scan(names[0], 1, 0.5)  # one running
		self.scan(names[1], -1, 0.1)  # one waiting
		result = conductor.keep_work_queued()
		self.assertEqual((result['active'], result['started']), (2, 1))  # depth 3: one more

	def test_a_full_queue_starts_nothing(self):
		doms = [self.domain(f'f{i}.test') for i in range(5)]
		for dom in doms[:3]:
			self.scan(dom, -1, 0)
		self.assertEqual(conductor.keep_work_queued()['started'], 0)

	def test_a_stalled_running_scan_does_not_hold_a_slot_and_its_target_is_picked_again(self):
		dom = self.domain('stuck.test')
		self.scan(dom, 1, 30)  # "running" for 30 hours: stalled
		result = conductor.keep_work_queued()
		self.assertEqual((result['active'], result['started']), (0, 1))

	def test_a_target_with_a_scan_going_is_not_started_twice(self):
		dom = self.domain('busy.test')
		self.scan(dom, 1, 0.2)
		self.assertEqual(conductor.keep_work_queued()['started'], 0)

	def test_excluded_hosts_are_never_picked(self):
		self.domain('gone.test')
		HostExclusion.objects.create(org=self.org, host='gone.test')
		self.assertEqual(conductor.keep_work_queued()['started'], 0)

	def test_a_bug_bounty_project_is_scanned_only_once_automated_testing_is_confirmed(self):
		program = BountyProgram.objects.create(platform='hackerone', handle='acme', name='Acme')
		BountyAsset.objects.create(program=program, kind='domain', identifier='bounty.test')  # the scope names the target (tests.test_bounty_gate: a host it does not name is never scanned)
		self.domain('bounty.test')
		engagement = BountyEngagement.objects.create(project=self.p1, program=program, status='active')
		self.assertEqual(conductor.keep_work_queued()['started'], 0)  # not acknowledged, automated testing not confirmed
		engagement.policy_ack_at = timezone.now()
		engagement.save()
		self.assertEqual(conductor.keep_work_queued()['started'], 0)  # acknowledged, but automated testing not confirmed
		engagement.automated_ok = True
		engagement.status = 'done'
		engagement.save()
		self.assertEqual(conductor.keep_work_queued()['started'], 0)  # confirmed, but the engagement is over
		engagement.status = 'active'
		engagement.save()
		self.assertEqual(conductor.keep_work_queued()['started'], 1)

	def test_nothing_starts_while_scanning_is_paused_or_the_conductor_is_off(self):
		self.domain('a.test')
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		self.assertEqual(conductor.keep_work_queued().get('skipped'), 'paused')
		ScanControl.objects.filter(pk=1).update(paused=False)
		with mock.patch.dict('os.environ', {'CVENGINE_WORK_DEPTH': '0'}):
			self.assertEqual(conductor.keep_work_queued().get('skipped'), 'off')
		self.assertFalse(ScanHistory.objects.exists())

	def test_a_round_that_cannot_claim_the_sweep_does_nothing(self):
		self.domain('a.test')
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
			self.assertEqual(conductor.keep_work_queued().get('skipped'), 'another round is running')
		self.assertFalse(ScanHistory.objects.exists())

	def test_the_schedule_exists_and_runs_every_minute(self):
		from django_celery_beat.models import PeriodicTask
		task = PeriodicTask.objects.get(name='cvengine-work-conductor')
		self.assertEqual((task.task, task.enabled, task.interval.every, task.interval.period), ('work_conductor', True, 1, 'minutes'))

	def test_status_reports_depth_counts_and_the_last_round(self):
		dom = self.domain('s.test')
		self.scan(dom, 1, 0.1)
		with mock.patch.object(conductor, 'last_round', return_value={'at': 'x'}):
			status = conductor.status()
		self.assertEqual((status['wanted_depth'], status['running'], status['queued'], status['last_round']), (3, 1, 0, {'at': 'x'}))
