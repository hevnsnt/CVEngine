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
        self.stream = object()  # what a scanner-backed stream is to the sweep: handed to run_nuclei untouched

    def run_sweep(self, result=None, allowed=True):
        with mock.patch('agentapi.sentinel_dispatch.wrap_nuclei_stream', return_value=self.stream) as self.wrapped, mock.patch('cveFeed.nuclei_scan.approved_revision', return_value='rev1'), \
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
        # same seam the per-scan light/targeted passes use, and hands it to run_nuclei untouched: there is no local stream.
        _, run = self.run_sweep()
        self.assertEqual(self.wrapped.call_count, 1)
        scan_arg, kind_arg = self.wrapped.call_args.args
        self.assertEqual(scan_arg.pk, self.scan.pk)
        self.assertEqual(kind_arg, 'nuclei_deep')
        self.assertIs(run.call_args.kwargs['stream'], self.stream)

    def test_reuse_reads_only_the_newest_copy_of_each_finding(self):
        """S04-16: every scan stores its own copy of a finding; the reuse reads one per (name, URL), not the whole history."""
        from cveFeed import nuclei_scan
        from startScan.models import Vulnerability
        engine = EngineType.objects.first()
        domain = self.scan.domain
        scans = [self.scan] + [ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now()) for _ in range(3)]
        for number, old in enumerate(scans):
            sub = Subdomain.objects.get_or_create(name='a.weekly.test', target_domain=domain, scan_history=old)[0]  # setUp stored the first scan's
            for name in ('Exposed panel', 'Old TLS'):
                Vulnerability.objects.create(name=name, http_url='https://a.weekly.test/', target_domain=domain, scan_history=old,
                                             subdomain=sub, severity=2, description=f'copy {number}')
        fresh = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
        Subdomain.objects.create(name='a.weekly.test', target_domain=domain, scan_history=fresh)
        copied, hosts = nuclei_scan.reuse_findings(fresh, self.project.id, ['a.weekly.test'])
        self.assertEqual((copied, hosts), (2, 1))
        self.assertEqual(sorted(Vulnerability.objects.filter(scan_history=fresh).values_list('description', flat=True)), ['copy 3', 'copy 3'])

    def _old_finding(self, scan, sub, name, links=True):
        from startScan.models import CveId, CweId, Vulnerability, VulnerabilityReference, VulnerabilityTags
        vuln = Vulnerability.objects.create(name=name, http_url=f'https://{sub.name}/', target_domain=scan.domain, scan_history=scan,
                                            subdomain=sub, severity=2)
        if links:
            vuln.tags.set([VulnerabilityTags.objects.create(name=f'{name} tag {n}') for n in range(2)])
            vuln.references.add(VulnerabilityReference.objects.create(url=f'https://ref.test/{name}'))
            vuln.cve_ids.add(CveId.objects.create(name=f'CVE-2026-{len(name):04d}'))
            vuln.cwe_ids.add(CweId.objects.create(name='CWE-79'))
        return vuln

    def _links(self, vuln):
        return (sorted(vuln.tags.values_list('pk', flat=True)), sorted(vuln.references.values_list('pk', flat=True)),
                sorted(vuln.cve_ids.values_list('pk', flat=True)), sorted(vuln.cwe_ids.values_list('pk', flat=True)))

    def test_reuse_copies_every_link_of_each_finding(self):
        """A copied finding carries the tags, references, CVE and CWE ids of the copy it was made from, and a finding with none gets none."""
        from cveFeed import nuclei_scan
        from startScan.models import Vulnerability
        linked = self._old_finding(self.scan, self.first, 'Exposed panel')
        bare = self._old_finding(self.scan, self.first, 'Old TLS', links=False)
        fresh = ScanHistory.objects.create(domain=self.scan.domain, scan_type=self.scan.scan_type, scan_status=1, start_scan_date=timezone.now())
        Subdomain.objects.create(name='a.weekly.test', target_domain=self.scan.domain, scan_history=fresh)
        self.assertEqual(nuclei_scan.reuse_findings(fresh, self.project.id, ['a.weekly.test']), (2, 1))
        copies = {v.name: v for v in Vulnerability.objects.filter(scan_history=fresh)}
        self.assertEqual(self._links(copies['Exposed panel']), self._links(linked))
        self.assertEqual(self._links(copies['Old TLS']), ([], [], [], []))
        self.assertEqual(self._links(linked)[0].__len__(), 2)
        self.assertEqual(self._links(bare), ([], [], [], []))  # the source rows are untouched

    def test_reuse_reads_the_links_once_per_chunk_not_per_finding(self):
        """Each extra copied finding costs its own INSERT only: the link reads and writes do not grow with the findings."""
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        from cveFeed import nuclei_scan
        domain = self.scan.domain

        def fresh_scan():
            scan = ScanHistory.objects.create(domain=domain, scan_type=self.scan.scan_type, scan_status=1, start_scan_date=timezone.now())
            Subdomain.objects.create(name='a.weekly.test', target_domain=domain, scan_history=scan)
            return scan
        self._old_finding(self.scan, self.first, 'F0')
        with CaptureQueriesContext(connection) as one:
            self.assertEqual(nuclei_scan.reuse_findings(fresh_scan(), self.project.id, ['a.weekly.test']), (1, 1))
        for n in range(1, 4):
            self._old_finding(self.scan, self.first, f'F{n}')
        with CaptureQueriesContext(connection) as four:
            self.assertEqual(nuclei_scan.reuse_findings(fresh_scan(), self.project.id, ['a.weekly.test']), (4, 1))
        self.assertEqual(len(four) - len(one), 3)
