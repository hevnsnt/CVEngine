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
