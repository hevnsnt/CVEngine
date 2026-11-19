"""The Sentinel queue's hot paths at scale: the reaper ends a backlog of queued tasks in one statement (and a held task on its own row, as before),
wakes each waiting stage run once, a claim remembers its Sentinel on the task (``last_holder``) so a late report needs no audit log lookup, a late
report is recorded once through ``late_reported_at``, the orphan check asks the stage runs in SQL, and the weekly maintenance archives and deletes
the routine Sentinel task audit rows past their retention while every other audit action stays."""
import datetime
import importlib
import json
import os
import tarfile
import tempfile
from datetime import timedelta
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_adopt
from agentapi import sentinel_broker as sb
from agentapi.models import Agent, SentinelTask, StageRun
from dashboard.models import AuditLog, Project
from tests.test_sentinels import SentinelBase, call, register_sentinel


def _updates_of_tasks(queries):
    return [q['sql'] for q in queries if q['sql'].startswith('UPDATE "agentapi_sentineltask"')]


class ReaperBatchTests(SentinelBase):
    def queue(self, kind='nmap', age=timedelta(minutes=30), **fields):
        fields.setdefault('target', {'addresses': ['192.0.2.50']})
        task = SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind=kind, ips=['192.0.2.50'], **fields)
        SentinelTask.objects.filter(pk=task.pk).update(created_at=timezone.now() - age)
        return task

    def test_a_queued_backlog_ends_in_one_statement_with_the_same_rows_and_one_summary(self):
        for _ in range(40):
            self.queue()
        young = self.queue(age=timedelta(minutes=1))
        with CaptureQueriesContext(connection) as captured:
            self.assertEqual(sb.reap_expired(), 40)
        self.assertEqual(len(_updates_of_tasks(captured.captured_queries)), 1)  # was one per task
        self.assertLess(len(captured.captured_queries), 12)
        ended = SentinelTask.objects.filter(status='expired')
        self.assertEqual(ended.count(), 40)
        self.assertEqual(set(ended.values_list('error', flat=True)), {'no Sentinel took the task while it waited in the queue'})
        self.assertFalse(ended.filter(finished_at__isnull=True).exists())
        self.assertFalse(ended.exclude(lease_expires_at__isnull=True).exists())
        row = AuditLog.objects.get(action='sentinel.task.expire_sweep')
        self.assertEqual((row.detail['count'], row.detail['by_kind']), (40, {'nmap': 40}))
        young.refresh_from_db()
        self.assertEqual(young.status, 'queued')

    def test_a_task_claimed_meanwhile_is_left_alone(self):
        task = self.queue()
        self.assertEqual(sb._expire_unheld([task.pk], 'x', timezone.now()), {task.pk})
        other = self.queue()
        SentinelTask.objects.filter(pk=other.pk).update(status='claimed')
        self.assertEqual(sb._expire_unheld([other.pk], 'x', timezone.now()), set())
        other.refresh_from_db()
        self.assertEqual(other.status, 'claimed')

    def test_a_held_task_still_ends_on_its_own_row_and_keeps_who_held_it(self):
        _, out = register_sentinel(self.t['dana'])
        agent = Agent.objects.get(pk=out['id'])
        task = self.queue(age=timedelta(0), status='running', agent=agent, lease_expires_at=timezone.now() - timedelta(seconds=5))
        self.assertEqual(sb.reap_expired(), 1)
        task.refresh_from_db()
        self.assertEqual((task.status, task.agent_id, task.last_holder), ('expired', None, agent.pk))
        self.assertEqual(task.result[sb.EXPIRED_AGENT], agent.pk)
        self.assertEqual(task.error, 'the lease expired without a report')

    def test_a_wordpress_token_is_still_scrubbed_from_a_queued_task_the_reaper_ends(self):
        task = self.queue(kind='wpscan', target={'url': 'https://www.a.example/', 'token': 'secret-token'})
        sb.reap_expired()
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')
        self.assertNotIn('secret-token', json.dumps(task.target))

    def test_each_waiting_stage_run_is_asked_once_for_the_whole_sweep(self):
        tasks = [self.queue() for _ in range(5)]
        run = StageRun.objects.create(kind='x', project=Project.objects.get(slug='sen-a'), task_ids=[t.pk for t in tasks], state='waiting')
        StageRun.objects.create(kind='x', project=Project.objects.get(slug='sen-a'), task_ids=[999999], state='waiting')
        with mock.patch('agentapi.stage_runs._try_ready', return_value=True) as ready:
            sb.reap_expired()
        self.assertEqual([c.args[0] for c in ready.call_args_list], [run.pk])
        self.assertIn(ready.call_args.kwargs['ended'], {t.pk for t in tasks})

    def test_a_ready_run_is_resumed_when_its_last_task_is_reaped(self):
        tasks = [self.queue() for _ in range(3)]
        run = StageRun.objects.create(kind='x', project=Project.objects.get(slug='sen-a'), task_ids=[t.pk for t in tasks], state='waiting')
        with mock.patch('agentapi.stage_runs._send_resume') as resume:
            sb.reap_expired()
        run.refresh_from_db()
        self.assertEqual(run.state, 'ready')
        resume.assert_called_once()

    def test_the_two_selects_use_their_indexes(self):
        now = timezone.now()
        with connection.cursor() as cursor:
            cursor.execute('SET LOCAL enable_seqscan = off')
            cursor.execute('SET LOCAL enable_bitmapscan = off')
            plan = SentinelTask._base_manager.filter(status='queued', created_at__lt=now).order_by().explain()
        self.assertIn('sentineltask_queued_age_idx', plan)

    def test_the_index_migration_builds_concurrently_outside_a_transaction(self):
        from django.contrib.postgres.operations import AddIndexConcurrently
        migration = importlib.import_module('agentapi.migrations.0024_sentineltask_queued_age_idx').Migration
        self.assertFalse(migration.atomic)
        self.assertTrue(all(isinstance(op, AddIndexConcurrently) for op in migration.operations))


class LastHolderTests(SentinelBase):
    def setUp(self):
        super().setUp()
        _, out = register_sentinel(self.t['dana'])
        self.agent = Agent.objects.get(pk=out['id'])
        self.task = SentinelTask.objects.create(project=Project.objects.get(slug='sen-a'), kind='nmap', target={'addresses': ['192.0.2.50']},
                                                ips=['192.0.2.50'])

    def test_a_claim_remembers_its_sentinel_and_an_expiry_keeps_it(self):
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual((status, out['task']['id']), (200, self.task.pk))
        self.task.refresh_from_db()
        self.assertEqual(self.task.last_holder, self.agent.pk)
        sb.expire(self.task, 'cancelled by a person')
        self.task.refresh_from_db()
        self.assertEqual((self.task.agent_id, self.task.last_holder), (None, self.agent.pk))
        with CaptureQueriesContext(connection) as captured:
            self.assertTrue(sb._held_before(self.task, self.agent))
            self.assertFalse(sb._held_before(self.task, Agent(pk=self.agent.pk + 1000)))
        self.assertEqual(captured.captured_queries, [])  # the audit log is not asked

    def test_a_task_claimed_before_the_column_existed_still_asks_the_audit_log(self):
        from tenancy import audit
        SentinelTask.objects.filter(pk=self.task.pk).update(status='expired', claimed_at=timezone.now())
        self.task.refresh_from_db()
        self.assertFalse(sb._held_before(self.task, self.agent))
        audit.record(None, 'sentinel.task.claim', 'task', task_id=self.task.pk, agent_id=self.agent.pk)
        self.assertTrue(sb._held_before(self.task, self.agent))

    def test_a_never_claimed_task_was_held_by_nobody_without_a_query(self):
        with CaptureQueriesContext(connection) as captured:
            self.assertFalse(sb._held_before(self.task, self.agent))
        self.assertEqual(captured.captured_queries, [])

    def test_a_late_report_is_recorded_once(self):
        SentinelTask.objects.filter(pk=self.task.pk).update(status='expired', last_holder=self.agent.pk, claimed_at=timezone.now(), error='the dispatch wait timed out')
        self.task.refresh_from_db()
        ctx = type('Ctx', (), {'user': self.dana, 'token': None})()
        sb._record_late(ctx, self.agent, self.task)
        self.task.refresh_from_db()
        self.assertIsNotNone(self.task.late_reported_at)
        self.assertTrue(sb._late_recorded(self.task))
        sb._record_late(ctx, self.agent, self.task)
        self.assertEqual(AuditLog.objects.filter(action='sentinel.task.late', detail__task_id=self.task.pk).count(), 1)


class OrphanCheckTests(SentinelBase):
    def setUp(self):
        super().setUp()
        self.project = Project.objects.get(slug='sen-a')
        self.task = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': ['192.0.2.50']}, ips=['192.0.2.50'])

    def test_an_open_run_holding_the_task_covers_it_whether_its_id_is_stored_as_a_number_or_a_string(self):
        self.assertFalse(sentinel_adopt.covered_by_stage_run(self.task))
        run = StageRun.objects.create(kind='x', project=self.project, task_ids=[str(self.task.pk)], state='waiting')
        self.assertTrue(sentinel_adopt.covered_by_stage_run(self.task))
        StageRun.objects.filter(pk=run.pk).update(task_ids=[self.task.pk + 1, self.task.pk])
        self.assertTrue(sentinel_adopt.covered_by_stage_run(self.task))
        StageRun.objects.filter(pk=run.pk).update(state='done')
        self.assertFalse(sentinel_adopt.covered_by_stage_run(self.task))

    def test_without_an_update_on_record_the_stage_runs_are_not_asked(self):
        with mock.patch('cveFeed.scan_control.update_window', return_value=(None, None, None)), \
                mock.patch('agentapi.sentinel_adopt.covered_by_stage_run') as covered:
            self.assertFalse(sentinel_adopt.orphaned(self.task))
        covered.assert_not_called()


class RoutineAuditRetentionTests(TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = mock.patch.dict(os.environ, {'CVENGINE_LOG_ARCHIVE_DIR': self.dir.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def row(self, action, days_ago):
        row = AuditLog.objects.create(action=action, target='t', detail={'task_id': 1})
        AuditLog.objects.filter(pk=row.pk).update(created_at=timezone.now() - datetime.timedelta(days=days_ago))
        return row.pk

    def test_old_routine_rows_are_archived_then_deleted_and_every_other_action_stays(self):
        from cveFeed import maintenance
        old = [self.row(action, 120) for action in maintenance.ROUTINE_AUDIT_ACTIONS]
        kept = [self.row('sentinel.task.claim', 10), self.row('sentinel.task.expire_sweep', 400), self.row('sentinel.secret.read', 400),
                self.row('user.role_change', 400), self.row('sentinel.task.late', 400)]
        out = maintenance.run()
        self.assertEqual(out['archived'].get('AuditLog'), 3)
        self.assertEqual(out['deleted'].get('AuditLog'), 3)
        self.assertFalse(AuditLog.objects.filter(pk__in=old).exists())
        self.assertEqual(AuditLog.objects.filter(pk__in=kept).count(), len(kept))
        with tarfile.open(out['archive']) as tar:
            lines = tar.extractfile('AuditLog.jsonl').read().decode().splitlines()
        self.assertEqual(sorted(json.loads(line)['id'] for line in lines), sorted(old))

    def test_the_retention_is_a_setting(self):
        from cveFeed import maintenance
        pk = self.row('sentinel.task.complete', 40)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_AUDIT_RETENTION_DAYS': '30'}):
            maintenance.run()
        self.assertFalse(AuditLog.objects.filter(pk=pk).exists())

    def test_nothing_old_means_no_audit_entry(self):
        from cveFeed import maintenance
        self.row('sentinel.task.claim', 5)
        out = maintenance.run()
        self.assertNotIn('AuditLog', out['archived'])
