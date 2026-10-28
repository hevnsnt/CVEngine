from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import ledger
from cveFeed.models import BackgroundCursor, ServiceRun
from cveFeed.tasks import weekly_deep_nuclei
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class WeeklyDeepNucleiTests(TestCase):
    def setUp(self):
        now = timezone.now()
        project = Project.objects.create(name='Test', slug='weekly', insert_date=now,
                                         org=Org.objects.create(name='Test', slug='weekly'))
        domain = Domain.objects.create(name='weekly.test', project=project, insert_date=now)
        engine = EngineType.objects.create(engine_name='weekly', yaml_configuration='x')
        self.scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now)
        self.first = Subdomain.objects.create(name='a.weekly.test', target_domain=domain, scan_history=self.scan)
        self.second = Subdomain.objects.create(name='b.weekly.test', target_domain=domain, scan_history=self.scan)
        self.project = project

    def run_sweep(self, result=None, allowed=True):
        with mock.patch('cveFeed.nuclei_scan.approved_templates', return_value=('/tmp/approved', 'rev1', 1)), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, **kw: names if allowed else []), \
                mock.patch('cveFeed.nuclei_scan.scan_targets', return_value=(
                    {self.first.name, self.second.name}, set(), {(self.first.name, 8443), (self.second.name, 9443)})), \
                mock.patch('cveFeed.nuclei_scan.run_nuclei', return_value=result or {'targets': 2, 'findings': 0}) as run:
            return weekly_deep_nuclei(), run

    def test_paced_hosts_get_successful_weekly_coverage_with_specific_port(self):
        first, run = self.run_sweep()
        self.assertEqual((first['status'], first['host']), ('done', self.first.name))
        self.assertEqual(run.call_args.kwargs['targets'], [self.first.name, f'{self.first.name}:8443'])
        self.assertEqual(run.call_args.kwargs['service_override'], 'nuclei-deep-target:rev1')
        second, _ = self.run_sweep()
        self.assertEqual((second['status'], second['host']), ('done', self.second.name))
        self.assertEqual(self.run_sweep()[0]['status'], 'no_due_host')
        self.assertEqual(ServiceRun.objects.filter(service='nuclei-deep-host:rev1', status='done').count(), 2)
        self.assertEqual(ledger.ttl('nuclei-deep-host:rev1'), 7 * 24 * 3600)
        self.assertEqual(BackgroundCursor.objects.get(lane='weekly_nuclei').last_pk, self.second.pk)

    def test_execution_failure_does_not_claim_successful_weekly_coverage(self):
        result, _ = self.run_sweep({'error': 'tool failed'})
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(ServiceRun.objects.filter(service='nuclei-deep-host:rev1', status='done').exists())
        self.assertEqual(self.run_sweep()[0]['host'], self.second.name)

    def test_blocked_target_is_not_executed_or_marked_covered(self):
        result, run = self.run_sweep(allowed=False)
        self.assertEqual(result['status'], 'no_due_host')
        run.assert_not_called()
        self.assertFalse(ServiceRun.objects.filter(service='nuclei-deep-host:rev1').exists())

    def test_beat_schedule_routes_the_paced_task_to_the_feed_worker(self):
        from django_celery_beat.models import PeriodicTask
        row = PeriodicTask.objects.get(name='cvengine-weekly-deep-nuclei')
        self.assertEqual((row.task, row.queue, row.interval.every, row.interval.period),
                         ('weekly_deep_nuclei', 'cve_feed_queue', 10, 'minutes'))

    def test_the_pass_offers_its_stream_to_a_live_eligible_sentinel_first(self):
        # weekly_deep_nuclei builds its stream through sentinel_dispatch.wrap_nuclei_stream(scan, 'nuclei_deep'), the
        # same seam the per-scan light/targeted passes use; with no Sentinel registered this stays the identity
        # (stream_nuclei itself), so run_nuclei's own call is unaffected other than the new stream= kwarg.
        from agentapi import sentinel_dispatch
        from cveFeed.nuclei_scan import stream_nuclei
        with mock.patch.object(sentinel_dispatch, 'wrap_nuclei_stream', wraps=sentinel_dispatch.wrap_nuclei_stream) as wrapped:
            _, run = self.run_sweep()
        self.assertEqual(wrapped.call_count, 1)
        scan_arg, kind_arg = wrapped.call_args.args
        self.assertEqual(scan_arg.pk, self.scan.pk)
        self.assertEqual(kind_arg, 'nuclei_deep')
        self.assertIs(run.call_args.kwargs['stream'], stream_nuclei)
