from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import reaper
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, HostAssessment, OnDemandValidation, ScanControl
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain

NOW = timezone.now()


class ReaperTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='R', slug='r')
		self.project = Project.objects.create(name='R', slug='reap', insert_date=NOW, org=org)
		self.domain = Domain.objects.create(name='reap.example', project=self.project, insert_date=NOW)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-4242', title='t', published_at=NOW)
		self.subs = [Subdomain.objects.create(name=f'h{i}.reap.example', target_domain=self.domain) for i in range(4)]
		self.matches = [CVEMatch.objects.create(cve_entry=cve, subdomain=s, matched_product='nginx') for s in self.subs]

	def assessment(self, host, status, hours, started=True):
		job = HostAssessment.objects.create(project=self.project, domain=self.domain, host=host, status=status)
		when = NOW - timedelta(hours=hours)
		HostAssessment.objects.filter(pk=job.pk).update(created_at=when, started_at=when if started else None)
		return job

	def validation(self, match, status, hours, attempts=1):
		job = OnDemandValidation.objects.create(match=match, project=self.project, status=status, attempts=attempts)
		when = NOW - timedelta(hours=hours)
		OnDemandValidation.objects.filter(pk=job.pk).update(created_at=when, started_at=when if status == 'running' else None)
		return job

	def activity_row(self, message, status, hours):
		row = AgentActivity.objects.create(project=self.project, kind='run_check', message=message, status=status)
		AgentActivity.objects.filter(pk=row.pk).update(created_at=NOW - timedelta(hours=hours))
		return row

	def test_stuck_jobs_fail_with_a_reason_and_live_ones_are_untouched(self):
		lost = self.assessment('h0.reap.example', 'queued', 13, started=False)
		dead = self.assessment('h1.reap.example', 'running', 7)
		busy = self.assessment('h2.reap.example', 'running', 1)
		legacy = self.assessment('h3.reap.example', 'running', 8, started=False)  # no started_at: ages from creation
		stuck_check = self.validation(self.matches[0], 'running', 3)
		exhausted = self.validation(self.matches[1], 'running', 3, attempts=7)
		waiting = self.validation(self.matches[2], 'queued', 1)
		counts = reaper.reap(now=NOW)
		self.assertEqual(counts, {'HostAssessment:queued': 1, 'HostAssessment:running': 2, 'OnDemandValidation:running': 2})
		for job in (lost, dead, busy, legacy, stuck_check, exhausted, waiting):
			job.refresh_from_db()
		self.assertEqual([j.status for j in (lost, dead, legacy)], ['failed'] * 3)
		self.assertIn('still queued after 12 hours', lost.error)
		self.assertIn('no result after 6 hours', dead.error)
		self.assertEqual((busy.status, waiting.status), ('running', 'queued'))
		self.assertEqual(stuck_check.next_attempt_at, NOW)  # due again: the sweep re-queues it
		self.assertIsNone(exhausted.next_attempt_at)  # out of attempts: stays failed

	def test_queued_jobs_wait_during_a_pause_but_running_ones_still_expire(self):
		lost = self.assessment('h0.reap.example', 'queued', 13, started=False)
		dead = self.assessment('h1.reap.example', 'running', 7)
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		reaper.reap(now=NOW)
		lost.refresh_from_db()
		dead.refresh_from_db()
		self.assertEqual((lost.status, dead.status), ('queued', 'failed'))

	def test_a_freed_slot_accepts_a_new_assessment(self):
		from cveFeed.host_assessment import enqueue
		self.assessment('h0.reap.example', 'running', 7)
		with mock.patch('cveFeed.tasks.assess_host.apply_async', return_value=mock.Mock(id='celery-1')):
			job, created = enqueue(self.project, self.subs[0])
			self.assertFalse(created)  # still held by the stuck job
			reaper.reap(now=NOW)
			job, created = enqueue(self.project, self.subs[0])
		self.assertTrue(created)

	def test_a_stuck_activity_row_is_closed_without_losing_its_message(self):
		stuck = self.activity_row('Nuclei is scanning 12 targets for CVE-2099-4242, scan #3', 'running', 12)
		fresh = self.activity_row('Weekly deep Nuclei checking reap.example', 'running', 1)
		counts = reaper.reap(now=NOW)
		self.assertEqual(counts, {'AgentActivity:running': 1})
		stuck.refresh_from_db()
		fresh.refresh_from_db()
		self.assertEqual(stuck.status, 'failed')
		self.assertTrue(stuck.message.startswith('Nuclei is scanning 12 targets for CVE-2099-4242, scan #3'))
		self.assertIn('no result after 11 hours', stuck.message)
		self.assertEqual(stuck.finished_at, NOW)
		self.assertEqual(fresh.status, 'running')  # well within the window: left alone

	def test_the_task_logs_what_it_expired_and_is_scheduled(self):
		from django_celery_beat.models import PeriodicTask
		from cveFeed.scan_control import PAUSE_EXEMPT_TASKS
		from cveFeed.tasks import reap_stuck_jobs
		self.assessment('h1.reap.example', 'running', 7)
		reap_stuck_jobs()
		self.assertIn('1 HostAssessment running', AgentActivity.objects.order_by('-id').first().message)
		self.assertEqual(PeriodicTask.objects.get(name='cvengine-reap-stuck-jobs').interval.every, 15)
		self.assertIn('reap_stuck_jobs', PAUSE_EXEMPT_TASKS)


class RedispatchTests(ReaperTests):
	def setUp(self):
		super().setUp()
		from reNgine import resources
		client = resources.get_store().r
		self.addCleanup(lambda: [client.delete(k) for k in client.scan_iter('cvengine:assess:redispatch:*')])
		[client.delete(k) for k in client.scan_iter('cvengine:assess:redispatch:*')]

	live = None  # None: the broker cannot be asked, which is what a test without workers sees

	def redispatch(self):
		with mock.patch('cveFeed.tasks.assess_host.apply_async', return_value=mock.Mock(id='again-1')) as send, \
				mock.patch('cveFeed.broker_recovery.live_task_ids', return_value=self.live):
			return reaper.redispatch_queued_assessments(now=NOW), send

	def test_an_assessment_nobody_started_is_queued_again_and_remembers_the_new_message(self):
		lost = self.assessment('h0.reap.example', 'queued', 1, started=False)
		count, send = self.redispatch()
		self.assertEqual(count, 1)
		send.assert_called_once_with(args=[lost.pk], queue='discovery_queue')
		lost.refresh_from_db()
		self.assertEqual((lost.status, lost.celery_id), ('queued', 'again-1'))

	def test_a_young_assessment_a_running_one_and_a_paused_system_are_left_alone(self):
		self.assessment('h0.reap.example', 'queued', 0.2, started=False)
		self.assessment('h1.reap.example', 'running', 1)
		self.assertEqual(self.redispatch()[0], 0)
		self.assessment('h2.reap.example', 'queued', 1, started=False)
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		self.assertEqual(self.redispatch()[0], 0)

	def test_the_same_assessment_is_not_queued_again_for_two_hours(self):
		self.assessment('h0.reap.example', 'queued', 1, started=False)
		self.assertEqual(self.redispatch()[0], 1)
		self.assertEqual(self.redispatch()[0], 0)  # a long but healthy queue does not fill with copies

	def test_an_assessment_whose_task_is_still_in_a_queue_or_a_worker_is_not_queued_again(self):
		waiting = self.assessment('h0.reap.example', 'queued', 1, started=False)
		lost = self.assessment('h1.reap.example', 'queued', 1, started=False)
		HostAssessment.objects.filter(pk=waiting.pk).update(celery_id='still-there')
		HostAssessment.objects.filter(pk=lost.pk).update(celery_id='gone')
		self.live = {'still-there'}
		count, send = self.redispatch()
		self.assertEqual(count, 1)
		send.assert_called_once_with(args=[lost.pk], queue='discovery_queue')

	def test_a_second_message_for_a_started_assessment_does_nothing(self):
		from cveFeed.host_assessment import execute
		job = self.assessment('h0.reap.example', 'running', 1)
		self.assertEqual(execute(job.pk), {'status': 'stopped_or_already_started'})

	def test_the_reaper_task_reports_it_as_done_not_failed(self):
		from cveFeed.tasks import reap_stuck_jobs
		self.assessment('h0.reap.example', 'queued', 1, started=False)
		with mock.patch('cveFeed.tasks.assess_host.apply_async', return_value=mock.Mock(id='again-1')):
			counts = reap_stuck_jobs()
		self.assertEqual(counts, {'HostAssessment:requeued': 1})
		row = AgentActivity.objects.order_by('-id').first()
		self.assertEqual(row.status, 'done')
		self.assertIn('Queued 1 host assessment again', row.message)


class CapacityTests(TestCase):
	"""A queued row whose Celery task no longer exists must not hold a slot toward the caps."""

	setUp_base, assessment = ReaperTests.setUp, ReaperTests.assessment

	def count(self, live, project=None):
		from cveFeed import broker_recovery, host_assessment
		broker_recovery._live['at'] = 0.0
		with mock.patch('cveFeed.broker_recovery.live_task_ids', return_value=live):
			return host_assessment.active_count(project)

	def setUp(self):
		self.setUp_base()
		self.old = self.assessment('h0.reap.example', 'queued', 1, started=False)
		self.waiting = self.assessment('h1.reap.example', 'queued', 1, started=False)
		self.young = self.assessment('h2.reap.example', 'queued', 0.01, started=False)
		self.running = self.assessment('h3.reap.example', 'running', 1)
		HostAssessment.objects.filter(pk=self.old.pk).update(celery_id='gone')
		HostAssessment.objects.filter(pk=self.waiting.pk).update(celery_id='alive')
		HostAssessment.objects.filter(pk=self.young.pk).update(celery_id='not-yet-seen')

	def test_an_old_queued_row_with_no_task_is_not_counted(self):
		self.assertEqual(self.count({'alive'}), 3)
		self.assertEqual(self.count({'alive'}, self.project), 3)

	def test_every_row_counts_when_the_broker_cannot_be_asked(self):
		self.assertEqual(self.count(None), 4)

	def test_an_old_queued_row_with_no_task_id_at_all_is_not_counted(self):
		HostAssessment.objects.filter(pk=self.waiting.pk).update(celery_id='')
		self.assertEqual(self.count({'alive'}), 2)

	def test_a_running_row_always_counts(self):
		self.assertEqual(self.count(set()), 2)  # the young queued row and the running one
