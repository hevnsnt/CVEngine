import datetime
import json
import os
import tarfile
import tempfile
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import maintenance
from cveFeed.models import AgentActivity, AIUsage, TriageCall
from dashboard.models import Org, Project

NOW = timezone.now()


def aged(model, days, field, **values):
	row = model.objects.create(**values)
	model.objects.filter(pk=row.pk).update(**{field: NOW - datetime.timedelta(days=days)})
	return row


class WeeklyMaintenanceTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='M', slug='m')
		self.project = Project.objects.create(name='M', slug='maint', insert_date=NOW, org=org)
		self.dir = tempfile.mkdtemp()
		patch = mock.patch.dict(os.environ, {'CVENGINE_LOG_ARCHIVE_DIR': self.dir})
		patch.start()
		self.addCleanup(patch.stop)

	def seed(self):
		self.old_activity = aged(AgentActivity, 40, 'created_at', kind='scan', message='old line', project=self.project)
		self.new_activity = aged(AgentActivity, 5, 'created_at', kind='scan', message='new line', project=self.project)
		self.old_call = aged(TriageCall, 100, 'started_at', kind='cve_match', signature='a' * 40, project=self.project,
							 status='succeeded', expires_at=NOW)
		self.new_call = aged(TriageCall, 10, 'started_at', kind='cve_match', signature='b' * 40, project=self.project,
							 status='succeeded', expires_at=NOW)
		self.old_usage = aged(AIUsage, 500, 'started_at', provider='anthropic', status='succeeded')
		self.new_usage = aged(AIUsage, 100, 'started_at', provider='anthropic', status='succeeded')

	def test_expired_rows_are_archived_then_deleted_and_recent_rows_stay(self):
		self.seed()
		result = maintenance.run(now=NOW)
		self.assertEqual(result['archived'], {'AgentActivity': 1, 'TriageCall': 1, 'AIUsage': 1})
		self.assertEqual(result['deleted'], {'AgentActivity': 1, 'TriageCall': 1, 'AIUsage': 1})
		self.assertEqual(list(AgentActivity.objects.values_list('message', flat=True)), ['new line'])
		self.assertEqual(list(TriageCall.objects.values_list('pk', flat=True)), [self.new_call.pk])
		self.assertEqual(list(AIUsage.objects.values_list('pk', flat=True)), [self.new_usage.pk])
		self.assertTrue(result['archive'].startswith(self.dir) and result['archive'].endswith('.tar.gz'))
		self.assertEqual(os.stat(result['archive']).st_mode & 0o777, 0o600)
		with tarfile.open(result['archive']) as tar:
			self.assertEqual(sorted(tar.getnames()), ['AIUsage.jsonl', 'AgentActivity.jsonl', 'TriageCall.jsonl'])
			line = json.loads(tar.extractfile('AgentActivity.jsonl').read().decode().splitlines()[0])
		self.assertEqual((line['id'], line['message']), (self.old_activity.pk, 'old line'))

	def test_nothing_is_deleted_when_the_archive_cannot_be_written(self):
		self.seed()
		with mock.patch.object(maintenance, '_export', side_effect=OSError('No space left on device')):
			with self.assertRaises(OSError):
				maintenance.run(now=NOW)
		self.assertEqual(AgentActivity.objects.count(), 2)
		self.assertEqual(TriageCall.objects.count(), 2)
		self.assertEqual(AIUsage.objects.count(), 2)
		self.assertEqual(os.listdir(self.dir), [])  # no partial archive left behind

	def test_no_expired_rows_writes_no_archive_and_old_archives_expire(self):
		stale = os.path.join(self.dir, 'cvengine-logs-20240101T000000Z.tar.gz')
		other = os.path.join(self.dir, 'notes.txt')
		for path in (stale, other):
			open(path, 'w').close()
			old = (NOW - datetime.timedelta(days=400)).timestamp()
			os.utime(path, (old, old))
		result = maintenance.run(now=NOW)
		self.assertEqual((result['archive'], result['archives_removed']), ('', 1))
		self.assertEqual(os.listdir(self.dir), ['notes.txt'])  # only our own archives are pruned

	def test_retention_is_configurable(self):
		self.seed()
		with mock.patch.dict(os.environ, {'CVENGINE_ACTIVITY_RETENTION_DAYS': '3'}):
			maintenance.run(now=NOW)
		self.assertEqual(AgentActivity.objects.count(), 0)

	def test_the_task_logs_its_outcome_and_runs_during_a_pause(self):
		from cveFeed import scan_control
		from cveFeed.tasks import weekly_maintenance
		self.assertIn('weekly_maintenance', scan_control.PAUSE_EXEMPT_TASKS)
		self.seed()
		weekly_maintenance()
		line = AgentActivity.objects.order_by('-id').first()
		self.assertIn('archived and removed 3 log rows', line.message)
		with mock.patch.object(maintenance, 'run', side_effect=OSError('disk full at /srv/x')), \
				self.assertLogs('cveFeed', 'WARNING'):
			self.assertEqual(weekly_maintenance(), {'error': 'OSError'})
		failed = AgentActivity.objects.order_by('-id').first()
		self.assertEqual(failed.status, 'failed')
		self.assertNotIn('/srv/x', failed.message)

	def test_the_schedule_exists(self):
		from django_celery_beat.models import PeriodicTask
		task = PeriodicTask.objects.get(name='cvengine-weekly-maintenance')
		self.assertEqual((task.task, task.crontab.day_of_week, task.enabled), ('weekly_maintenance', '0', True))


class OperationalPruneTests(TestCase):
	"""The tables with no other delete path: ended StageRuns, input guard strikes and bans, expired sessions, finished host assessments."""

	def setUp(self):
		from targetApp.models import Domain
		org = Org.objects.create(name='P', slug='p')
		self.project = Project.objects.create(name='P', slug='prune', insert_date=NOW, org=org)
		self.domain = Domain.objects.create(name='prune.example', project=self.project, insert_date=NOW)

	def test_ended_stage_runs_past_the_retention_go_and_open_or_fresh_ones_stay(self):
		from agentapi.models import StageRun
		old = StageRun.objects.create(kind='sweep', state='done', finished_at=NOW - datetime.timedelta(days=40))
		old_failed = StageRun.objects.create(kind='sweep', state='failed', finished_at=NOW - datetime.timedelta(days=31))
		fresh = StageRun.objects.create(kind='sweep', state='done', finished_at=NOW - datetime.timedelta(days=5))
		waiting = StageRun.objects.create(kind='sweep', state='waiting')
		StageRun.objects.filter(pk=waiting.pk).update(created_at=NOW - datetime.timedelta(days=60))
		self.assertEqual(maintenance.prune_stage_runs(NOW), 2)
		self.assertEqual(set(StageRun.objects.values_list('pk', flat=True)), {fresh.pk, waiting.pk})
		self.assertFalse(StageRun.objects.filter(pk__in=(old.pk, old_failed.pk)).exists())
		with mock.patch.dict(os.environ, {'CVENGINE_STAGE_RUN_RETENTION_DAYS': '3'}):
			self.assertEqual(maintenance.prune_stage_runs(NOW), 1)
		self.assertEqual(list(StageRun.objects.values_list('pk', flat=True)), [waiting.pk])

	def test_old_strikes_and_bans_that_are_over_go(self):
		from dashboard.models import AbuseBan, AbuseStrike
		old_strike = aged(AbuseStrike, 100, 'created_at', category='sqli', ip='203.0.113.9')
		new_strike = aged(AbuseStrike, 10, 'created_at', category='sqli', ip='203.0.113.9')
		long_expired = AbuseBan.objects.create(ip='203.0.113.1', reason='r', expires_at=NOW - datetime.timedelta(days=100))
		recently_expired = AbuseBan.objects.create(ip='203.0.113.2', reason='r', expires_at=NOW - datetime.timedelta(days=10))
		in_force = AbuseBan.objects.create(ip='203.0.113.3', reason='r', expires_at=NOW + datetime.timedelta(hours=5))
		account = aged(AbuseBan, 400, 'created_at', username='mallory', reason='r')  # no expiry, not lifted: the account stays disabled
		old_lifted = aged(AbuseBan, 100, 'created_at', username='bob', reason='r', lifted=True)
		new_lifted = aged(AbuseBan, 10, 'created_at', username='eve', reason='r', lifted=True)
		self.assertEqual(maintenance.prune_abuse(NOW), (1, 2))
		self.assertEqual(list(AbuseStrike.objects.values_list('pk', flat=True)), [new_strike.pk])
		self.assertFalse(AbuseStrike.objects.filter(pk=old_strike.pk).exists())
		self.assertEqual(set(AbuseBan.objects.values_list('pk', flat=True)), {recently_expired.pk, in_force.pk, account.pk, new_lifted.pk})
		self.assertFalse(AbuseBan.objects.filter(pk__in=(long_expired.pk, old_lifted.pk)).exists())

	def test_expired_sessions_go_and_live_ones_stay(self):
		from django.contrib.sessions.models import Session
		Session.objects.create(session_key='a' * 40, session_data='', expire_date=NOW - datetime.timedelta(seconds=1))
		Session.objects.create(session_key='b' * 40, session_data='', expire_date=NOW + datetime.timedelta(days=1))
		self.assertEqual(maintenance.prune_sessions(NOW), 1)
		self.assertEqual(list(Session.objects.values_list('session_key', flat=True)), ['b' * 40])

	def assessment(self, host, days, status='completed', finished=True):
		from cveFeed.models import HostAssessment
		at = NOW - datetime.timedelta(days=days)
		row = HostAssessment.objects.create(project=self.project, domain=self.domain, host=host, status=status)
		HostAssessment.objects.filter(pk=row.pk).update(created_at=at, finished_at=at if finished else None)
		return row

	def test_old_finished_assessments_go_but_the_newest_per_host_and_linked_ones_stay(self):
		from cveFeed.models import HostAssessment, HostState
		a_old = self.assessment('a.prune.example', 200)
		a_newest = self.assessment('a.prune.example', 150)  # old, but the newest of its host: the top-up orders hosts by it
		b_linked = self.assessment('b.prune.example', 200)
		b_new = self.assessment('b.prune.example', 1)
		HostState.objects.create(project=self.project, domain=self.domain, host='b.prune.example', archive_assessment=b_linked)
		c_unfinished = self.assessment('c.prune.example', 200, status='failed', finished=False)  # no finished_at: aged by created_at
		c_active = self.assessment('c.prune.example', 200, status='queued', finished=False)
		d_fresh = self.assessment('d.prune.example', 10)
		d_new = self.assessment('d.prune.example', 1)
		self.assertEqual(maintenance.prune_host_assessments(NOW), 2)
		self.assertEqual(set(HostAssessment.objects.values_list('pk', flat=True)),
						 {a_newest.pk, b_linked.pk, b_new.pk, c_active.pk, d_fresh.pk, d_new.pk})
		self.assertFalse(HostAssessment.objects.filter(pk__in=(a_old.pk, c_unfinished.pk)).exists())
		self.assertEqual(HostState.objects.get(host='b.prune.example').archive_assessment_id, b_linked.pk)

	def test_deletes_run_in_bounded_batches(self):
		from django.db import connection
		from django.test.utils import CaptureQueriesContext

		from dashboard.models import AbuseStrike
		for _ in range(5):
			aged(AbuseStrike, 100, 'created_at', category='sqli', ip='203.0.113.9')
		keep = aged(AbuseStrike, 1, 'created_at', category='sqli', ip='203.0.113.9')
		with mock.patch.object(maintenance, 'DELETE_CHUNK', 2), CaptureQueriesContext(connection) as queries:
			self.assertEqual(maintenance.prune_abuse(NOW)[0], 5)
		deletes = [q['sql'] for q in queries.captured_queries if q['sql'].startswith('DELETE FROM "dashboard_abusestrike"')]
		self.assertEqual(len(deletes), 3)  # 2, 2 and 1 ids
		self.assertEqual(list(AbuseStrike.objects.values_list('pk', flat=True)), [keep.pk])

	def test_keyset_delete_skips_kept_ids_and_pages_past_them(self):
		from dashboard.models import AbuseStrike
		rows = [aged(AbuseStrike, 100, 'created_at', category='sqli') for _ in range(5)]
		kept = {rows[0].pk, rows[1].pk, rows[3].pk}
		self.assertEqual(maintenance.keyset_delete(AbuseStrike.objects.all(), chunk=2, keep=kept), 2)
		self.assertEqual(set(AbuseStrike.objects.values_list('pk', flat=True)), kept)

	def test_the_weekly_run_reports_them_and_one_failure_does_not_stop_the_rest(self):
		from agentapi.models import StageRun
		StageRun.objects.create(kind='sweep', state='done', finished_at=NOW - datetime.timedelta(days=40))
		dir_patch = mock.patch.dict(os.environ, {'CVENGINE_LOG_ARCHIVE_DIR': tempfile.mkdtemp()})
		dir_patch.start()
		self.addCleanup(dir_patch.stop)
		with mock.patch.object(maintenance, 'prune_abuse', side_effect=RuntimeError('boom')), self.assertLogs('cveFeed.maintenance', 'ERROR'):
			result = maintenance.run(now=NOW)
		self.assertEqual(result['pruned'], {'StageRun': 1, 'Session': 0, 'HostAssessment': 0})
		self.assertFalse(StageRun.objects.exists())
