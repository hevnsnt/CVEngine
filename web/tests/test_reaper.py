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
