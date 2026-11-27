"""Queued scans that nothing will ever start (``counts.stuck_queued_q``) are told apart from scans that wait for a worker, and the reaper closes them.

The live case this replays: seven host pipeline rows (``host_pipeline``, ``retest``) stayed queued for days after the worker task that creates and starts them was
killed between the two steps. They held the queue_starvation alert open with the advice to lower the assessment batch, which could never start them, and they
kept the assessment share limit engaged although no scan waited for a slot.
"""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import counts, maintainer_checks as mc, reaper
from cveFeed.models import AgentActivity, HostAssessment, ScanControl
from dashboard.models import Org, Project
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain

NOW = timezone.now()
PIPELINE = ['host_pipeline', 'retest']


class Rows(TestCase):
    def setUp(self):
        from scanEngine.models import EngineType
        org = Org.objects.create(name='S', slug='stuck')
        self.project = Project.objects.create(name='S', slug='stuck', insert_date=NOW, org=org)
        self.domain = Domain.objects.create(name='stuck.example', project=self.project, insert_date=NOW)
        self.engine = EngineType.objects.first() or EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

    def scan(self, hours, tasks=None, status=-1, celery_ids=()):
        return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=NOW - timedelta(hours=hours), scan_status=status,
                                          results_dir='/tmp', celery_ids=list(celery_ids), tasks=tasks)


class StuckDefinitionTests(Rows):
    def test_a_host_pipeline_left_queued_and_a_scan_queued_for_days_are_stuck_and_the_rest_wait(self):
        orphan = self.scan(24 * 12, PIPELINE, celery_ids=['gone'])     # the live #7115
        fresh_pipeline = self.scan(0.1, PIPELINE)                        # its task is between creating and starting it
        waiting = self.scan(3, tasks=None)                               # a discovery waiting its turn (tasks is NULL on these rows)
        ancient = self.scan(49, tasks=None)                              # nothing has started it in two days
        internal = self.scan(49, tasks=['internal_pipeline'])
        self.scan(1, status=1)                                           # running: neither
        stuck = set(ScanHistory.objects.filter(counts.stuck_queued_q(NOW)).values_list('pk', flat=True))
        self.assertEqual(stuck, {orphan.pk, ancient.pk, internal.pk})
        self.assertEqual(set(counts.waiting_scans(now=NOW).values_list('pk', flat=True)), {fresh_pipeline.pk, waiting.pk})
        split = counts.queued_scan_split(NOW)
        self.assertEqual((split['waiting'], split['stuck'], split['stuck_ids']), (2, 3, sorted([orphan.pk, ancient.pk, internal.pk])))
        self.assertAlmostEqual(split['oldest_waiting_age_seconds'], 3 * 3600, delta=5)
        self.assertAlmostEqual(split['oldest_stuck_age_seconds'], 24 * 12 * 3600, delta=5)
        self.assertEqual(counts.queued_scans().count(), 4 + 1)  # the queued count itself is unchanged: every queued row is still a queued row

    def test_the_limit_follows_the_setting(self):
        row = self.scan(30, tasks=None)
        self.assertFalse(ScanHistory.objects.filter(counts.stuck_queued_q(NOW), pk=row.pk).exists())
        with mock.patch.dict('os.environ', {'CVENGINE_SCAN_QUEUED_HOURS': '24'}):
            self.assertTrue(ScanHistory.objects.filter(counts.stuck_queued_q(NOW), pk=row.pk).exists())
        with mock.patch.dict('os.environ', {'CVENGINE_SCAN_QUEUED_HOURS': 'x'}):
            self.assertEqual(counts.queued_scan_limit(), timedelta(hours=48))

    def test_nothing_queued_reads_as_none(self):
        self.assertEqual(counts.queued_scan_split(NOW), {'waiting': 0, 'oldest_waiting_age_seconds': None, 'stuck': 0, 'stuck_ids': [],
                                                         'oldest_stuck_age_seconds': None})


class ExpireStuckQueuedTests(Rows):
    def test_stuck_rows_the_broker_holds_nothing_for_are_failed_with_the_reason_and_kept(self):
        orphan = self.scan(24 * 12, PIPELINE, celery_ids=['gone'])
        ancient = self.scan(49, tasks=None)
        waiting = self.scan(3, tasks=None)
        fresh_pipeline = self.scan(0.1, PIPELINE)
        step = ScanActivity.objects.create(scan_of=orphan, title='Resolve and record new hosts', name='host_resolve', time=orphan.start_scan_date, status=-1)
        closed = reaper.expire_stuck_queued(now=NOW, found=(set(), set()))
        self.assertEqual([pk for pk, _ in closed], [orphan.pk, ancient.pk])
        for row in (orphan, ancient, waiting, fresh_pipeline):
            row.refresh_from_db()
        self.assertEqual((orphan.scan_status, ancient.scan_status, waiting.scan_status, fresh_pipeline.scan_status), (0, 0, -1, -1))
        self.assertEqual((orphan.stop_scan_date, ancient.stop_scan_date), (NOW, NOW))
        self.assertIn('host pipeline stopped before it started it', orphan.error_message)
        self.assertIn('still queued after 48 hours', ancient.error_message)
        self.assertLessEqual(len(orphan.error_message), 300)
        step.refresh_from_db()
        self.assertEqual(step.status, 0)
        self.assertEqual(reaper.expire_stuck_queued(now=NOW, found=(set(), set())), [])  # once only
        self.assertEqual(ScanHistory.objects.filter(pk__in=[orphan.pk, ancient.pk]).count(), 2)  # never deleted

    def test_a_row_the_broker_or_a_stage_run_still_holds_is_left_alone(self):
        by_task = self.scan(24, PIPELINE, celery_ids=['still-there'])
        by_scan_id = self.scan(49, tasks=None)
        carried = self.scan(24, PIPELINE)
        with mock.patch('agentapi.stage_runs.open_scan_ids', return_value={carried.pk}):
            self.assertEqual(reaper.expire_stuck_queued(now=NOW, found=({'still-there'}, {by_scan_id.pk})), [])
        self.assertEqual(ScanHistory.objects.filter(pk__in=[by_task.pk, by_scan_id.pk, carried.pk], scan_status=-1).count(), 3)

    def test_nothing_is_closed_when_the_broker_cannot_be_asked_or_scanning_is_paused(self):
        row = self.scan(24, PIPELINE)
        with mock.patch('cveFeed.broker_recovery.live_tasks', return_value=None):
            self.assertEqual(reaper.expire_stuck_queued(now=NOW), [])
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(reaper.expire_stuck_queued(now=NOW, found=(set(), set())), [])
        row.refresh_from_db()
        self.assertEqual(row.scan_status, -1)

    def test_a_closed_row_may_still_become_a_success_if_its_task_turns_up(self):
        from cvengine.state_machines import SCAN, SUCCESS
        row = self.scan(24, PIPELINE)
        reaper.expire_stuck_queued(now=NOW, found=(set(), set()))
        self.assertEqual(SCAN.move(ScanHistory.objects.filter(pk=row.pk), SUCCESS), 1)

    def test_a_host_pipeline_row_is_never_sent_again_as_a_discovery(self):
        from cvengine import resources
        client = resources.get_store().r
        [client.delete(k) for k in client.scan_iter('cvengine:scan:redispatch:*')]
        self.addCleanup(lambda: [client.delete(k) for k in client.scan_iter('cvengine:scan:redispatch:*')])
        self.scan(2, PIPELINE)  # no Celery id recorded: the redispatch used to send it as run_bbot_discovery of the whole target
        lost = self.scan(2, tasks=None)
        with mock.patch('cvengine.celery.app.send_task') as send:
            self.assertEqual(reaper.redispatch_queued_scans(now=NOW, live=set()), 1)
        send.assert_called_once_with('run_bbot_discovery', args=[lost.pk, 'standard'], queue='discovery_queue')

    def test_the_fifteen_minute_job_closes_them_before_the_redispatch_and_logs_one_line(self):
        from cveFeed.tasks import reap_stuck_jobs
        orphan = self.scan(24 * 12, PIPELINE, celery_ids=['gone'])
        ancient = self.scan(49, tasks=None)  # no Celery id: the redispatch would send it again if it ran first
        with mock.patch('cveFeed.broker_recovery.live_tasks', return_value=(set(), set())), mock.patch('cvengine.celery.app.send_task') as send:
            result = reap_stuck_jobs()
        send.assert_not_called()
        self.assertEqual(result['ScanHistory:queued_stuck'], 2)
        line = AgentActivity.objects.filter(message__startswith='Closed 2 queued scans that nothing would ever start').get()
        self.assertEqual(line.status, 'notice')
        self.assertIn(f'#{orphan.pk}, #{ancient.pk}', line.message)
        self.assertEqual(line.detail.get('scan_ids'), [orphan.pk, ancient.pk])


class ReadersIgnoreStuckRowsTests(Rows):
    def test_the_assessment_share_is_not_held_by_a_stuck_row(self):
        from cveFeed import host_assessment
        self.scan(24 * 12, PIPELINE)
        with mock.patch.object(host_assessment, 'share_limit', return_value=1), mock.patch.object(host_assessment, 'slots_held', return_value=5):
            self.assertFalse(host_assessment.over_share())
            self.scan(2, tasks=None)
            self.assertTrue(host_assessment.over_share())

    def test_the_tuning_starvation_sample_and_the_oldest_queued_signal_leave_stuck_rows_out(self):
        from agentapi import maintainer_signals
        from cveFeed import autotune_signals
        self.scan(24 * 12, PIPELINE)
        self.assertEqual(autotune_signals.starve(NOW.timestamp()), {'scans_queued': 0, 'scan_age_s': None})
        self.assertEqual(maintainer_signals._oldest_db()['scan'], {'state': 'known', 'queued': False, 'age_seconds': None})
        self.scan(2, tasks=None)
        self.assertEqual(autotune_signals.starve(NOW.timestamp())['scans_queued'], 1)
        self.assertTrue(maintainer_signals._oldest_db()['scan']['queued'])

    def test_the_starvation_inputs_count_waiting_and_stuck_apart(self):
        from cveFeed import reviewer
        orphan = self.scan(24 * 12, PIPELINE)
        self.scan(2, tasks=None)
        HostAssessment.objects.create(project=self.project, domain=self.domain, host='a.stuck.example', status='running')
        work = reviewer._starvation_inputs(NOW, False, 0)
        self.assertEqual((work['scans_queued'], work['assessments_running']), (1, 1))
        self.assertAlmostEqual(work['scans_oldest_age_seconds'], 7200, delta=5)
        self.assertEqual((work['scans_stuck']['count'], work['scans_stuck']['ids']), (1, [orphan.pk]))


def work(**over):
    out = {'paused': False, 'scans_queued': 0, 'scans_oldest_age_seconds': None, 'scans_stuck': None, 'assessments_running': 24, 'assessments_queued': 61,
           'sentinel_kinds': []}
    out.update(over)
    return out


STUCK = {'count': 7, 'ids': [7115, 11727, 11728, 11729, 11730, 17961, 17962], 'oldest_age_seconds': 12 * 86400}
OLD_SIGNAL = {'queues': {'state': 'known', 'oldest_queued': {'scan': {'state': 'known', 'queued': True, 'age_seconds': 12 * 86400}}}}


class QueueStarvationVerdictTests(SimpleTestCase):
    def test_the_live_case_stuck_rows_alone_are_not_starvation_and_give_no_batch_advice(self):
        out = mc.queue_starvation(OLD_SIGNAL, work(scans_stuck=STUCK))  # the cached signal still says 12 days: the counted queue wins
        self.assertEqual(out['state'], 'ok')
        self.assertNotIn('Hosts per assessment batch', out['detail'])
        self.assertIn('7 queued scans (#7115, #11727, #11728, #11729, #11730, #17961, #17962, the oldest queued 288 hours ago) are rows that nothing will start',
                      out['detail'])
        self.assertIn('marks such a row failed', out['detail'])
        self.assertEqual(out['facts']['stuck_scans']['count'], 7)

    def test_a_real_wait_behind_assessments_is_still_a_problem_and_the_stuck_rows_are_named_apart(self):
        out = mc.queue_starvation({}, work(scans_queued=2, scans_oldest_age_seconds=2 * 3600, scans_stuck=STUCK))
        self.assertEqual(out['state'], 'problem')
        self.assertIn('2 scans are queued, the oldest for 2 hours, while host assessments hold the discovery workers (24 running, 61 queued)', out['detail'])
        self.assertIn('Hosts per assessment batch', out['detail'])
        self.assertIn('Apart from these, 7 queued scans', out['detail'])

    def test_a_short_real_wait_is_ok(self):
        out = mc.queue_starvation(OLD_SIGNAL, work(scans_queued=1, scans_oldest_age_seconds=600))
        self.assertEqual((out['state'], out['detail']), ('ok', ''))

    def test_one_stuck_row_reads_in_the_singular(self):
        out = mc.queue_starvation({}, work(scans_stuck={'count': 1, 'ids': [9], 'oldest_age_seconds': None}))
        self.assertIn('1 queued scan (#9) is a row that nothing will start', out['detail'])
