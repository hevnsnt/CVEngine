"""Scan history retention (cveFeed.scan_retention): old scans go, the current inventory, a domain's newest scans and a person's work stay."""
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from cveFeed import discovery, scan_retention
from cveFeed.models import CVEEntry, CVEMatch, FindingAuditEvent, FindingComment
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

OLD = timedelta(days=400)


class ScanRetentionTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='R', slug='r-org')
        self.project = Project.objects.create(name='R', slug='ret', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='ret.example', project=self.project, insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.now = timezone.now()

    def scan(self, age=OLD, status=2, names=('www.ret.example',), domain=None, tasks=None):
        scan = ScanHistory.objects.create(domain=domain or self.domain, scan_type=self.engine, scan_status=status,
                                          start_scan_date=self.now - age, tasks=tasks)
        for name in names:
            Subdomain.objects.create(name=name, target_domain=domain or self.domain, scan_history=scan)
        return scan

    def ids(self):
        return set(ScanHistory.objects.values_list('id', flat=True))

    def history(self, count=6):
        """Old scans, oldest first, then a recent successful full scan that is the current inventory."""
        old = [self.scan(age=OLD + timedelta(days=count - i)) for i in range(count)]
        current = self.scan(age=timedelta(days=1))
        return old, current

    def test_the_retention_is_180_days_by_default_off_at_zero_and_never_below_30(self):
        self.assertEqual(scan_retention.retention_days({}), 180)
        self.assertEqual(scan_retention.retention_days({'CVENGINE_SCAN_HISTORY_RETENTION_DAYS': '365'}), 365)
        self.assertEqual(scan_retention.retention_days({'CVENGINE_SCAN_HISTORY_RETENTION_DAYS': '5'}), 30)
        self.assertEqual(scan_retention.retention_days({'CVENGINE_SCAN_HISTORY_RETENTION_DAYS': 'soon'}), 180)
        for off in ('0', 'off', 'never'):
            self.assertIsNone(scan_retention.retention_days({'CVENGINE_SCAN_HISTORY_RETENTION_DAYS': off}))

    def test_old_scans_beyond_the_newest_few_are_deleted_with_their_rows(self):
        old, current = self.history()
        result = scan_retention.run(self.now, days=180)
        self.assertEqual(result, {'days': 180, 'scans': 4, 'complete': True})  # the 3 newest scans of the domain stay
        self.assertEqual(self.ids(), {s.id for s in old[4:]} | {current.id})
        self.assertFalse(Subdomain.objects.filter(scan_history_id__in=[s.id for s in old[:4]]).exists())  # their host copies went with them
        self.assertTrue(Subdomain.objects.filter(scan_history=current).exists())

    def test_scans_inside_the_retention_and_unfinished_scans_stay(self):
        recent = self.scan(age=timedelta(days=100))
        queued = self.scan(status=-1)
        running = self.scan(status=1)
        for i in range(4):
            self.scan(age=OLD + timedelta(days=i))
        scan_retention.run(self.now, days=180)
        self.assertTrue({recent.id, queued.id, running.id} <= self.ids())

    def test_the_current_inventory_is_never_deleted_however_old(self):
        # the latest successful full scan is 400 days old and four newer scans failed: it is still what every listing reads
        current = self.scan(age=OLD + timedelta(days=50), names=('www.ret.example', 'api.ret.example'))
        for i in range(4):
            self.scan(age=OLD - timedelta(days=i * 20), status=0, names=())
        scan_retention.run(self.now, days=180)
        self.assertIn(current.id, self.ids())
        self.assertEqual(Subdomain.objects.filter(scan_history=current).count(), 2)

    def test_a_scan_with_work_a_person_did_stays(self):
        old, _ = self.history(8)
        user = User.objects.create_user('worker', password='x')
        worked = Vulnerability.objects.create(name='Exposed thing', severity=3, scan_history=old[0], target_domain=self.domain, remediation_status='fixed')
        noted = Vulnerability.objects.create(name='Other thing', severity=2, scan_history=old[1], target_domain=self.domain, remediation_note='ticket 12')
        assigned = Vulnerability.objects.create(name='Third thing', severity=2, scan_history=old[2], target_domain=self.domain, assignee=user)
        commented = Vulnerability.objects.create(name='Fourth thing', severity=2, scan_history=old[3], target_domain=self.domain)
        FindingComment.objects.create(project=self.project, finding_kind='vulnerability', finding_id=commented.pk, author=user, text='seen')
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=7.5, title='t', published_at=self.now)
        match = CVEMatch.objects.create(cve_entry=cve, subdomain=old[4].subdomain_set.first(), scan_history=old[4], remediation_status='accepted_risk')
        scan_retention.run(self.now, days=180)
        # the five scans holding a person's work stay; the newest two old scans stay as a domain's newest three; only old[5] has no reason to
        self.assertTrue({old[0].id, old[1].id, old[2].id, old[3].id, old[4].id, old[6].id, old[7].id} <= self.ids())
        self.assertNotIn(old[5].id, self.ids())
        for finding in (worked, noted, assigned, commented):
            self.assertTrue(Vulnerability.objects.filter(pk=finding.pk).exists())
        self.assertTrue(CVEMatch.objects.filter(pk=match.pk).exists())

    def test_an_audit_trail_stays_when_the_current_remediation_fields_are_open_again(self):
        old, _ = self.history(6)
        finding = Vulnerability.objects.create(name='Reviewed then reopened', severity=2, scan_history=old[0],
                                                target_domain=self.domain)
        FindingAuditEvent.objects.create(project=self.project, finding_kind='vulnerability', finding_id=finding.pk,
                                         event='status', before={'status': 'in_progress'}, after={'status': 'open'})
        cve = CVEEntry.objects.create(cve_id='CVE-2099-8', cvss=7.5, title='t', published_at=self.now)
        match = CVEMatch.objects.create(cve_entry=cve, subdomain=old[1].subdomain_set.first(), scan_history=old[1])
        FindingAuditEvent.objects.create(project=self.project, finding_kind='match', finding_id=match.pk,
                                         event='assignee', before={'assignee': 1}, after={'assignee': None})
        scan_retention.run(self.now, days=180)
        self.assertTrue({old[0].pk, old[1].pk} <= self.ids())
        self.assertTrue(Vulnerability.objects.filter(pk=finding.pk).exists())
        self.assertTrue(CVEMatch.objects.filter(pk=match.pk).exists())

    def test_one_domain_does_not_protect_or_expose_another(self):
        other = Domain.objects.create(name='other.example', project=self.project, insert_date=timezone.now())
        theirs = [self.scan(age=OLD + timedelta(days=i), domain=other, names=('www.other.example',)) for i in range(2)]
        old, _ = self.history(5)
        scan_retention.run(self.now, days=180)
        self.assertTrue({s.id for s in theirs} <= self.ids())  # only two scans: both are among the newest three of their domain

    def test_newest_scans_for_many_domains_use_one_ranked_query(self):
        other = Domain.objects.create(name='other.example', project=self.project, insert_date=self.now)
        mine = [self.scan(age=OLD + timedelta(days=i), names=()) for i in range(5)]
        theirs = [self.scan(age=OLD + timedelta(days=i), domain=other, names=()) for i in range(5)]
        with self.assertNumQueries(1):
            kept = scan_retention._newest({self.domain.id, other.id})
        self.assertEqual(kept, {s.id for s in mine[-3:] + theirs[-3:]})

    def test_a_dry_run_counts_and_deletes_nothing(self):
        self.history()
        before = self.ids()
        self.assertEqual(scan_retention.run(self.now, days=180, dry_run=True)['scans'], 4)
        self.assertEqual(self.ids(), before)
        out = StringIO()
        call_command('prune_scan_history', '--dry-run', stdout=out)
        self.assertIn('Would delete', out.getvalue())
        self.assertEqual(self.ids(), before)

    def test_the_time_budget_stops_a_run_and_the_next_one_finishes_it(self):
        self.history(10)
        ticks = iter(range(0, 1000, 10))
        partial = scan_retention.run(self.now, days=180, budget_seconds=25, clock=lambda: next(ticks))
        self.assertFalse(partial['complete'])
        self.assertGreater(partial['scans'], 0)
        rest = scan_retention.run(self.now, days=180)
        self.assertTrue(rest['complete'])
        self.assertEqual(partial['scans'] + rest['scans'], 8)  # ten old scans and the current one, the newest three stay

    def test_retention_off_deletes_nothing(self):
        self.history()
        before = self.ids()
        with mock.patch.dict('os.environ', {'CVENGINE_SCAN_HISTORY_RETENTION_DAYS': '0'}):
            self.assertEqual(scan_retention.run(self.now)['scans'], 0)
            from cveFeed.tasks import prune_scan_history
            self.assertIn('off', prune_scan_history()['skipped'])
        self.assertEqual(self.ids(), before)

    def test_the_task_runs_under_a_pause_and_is_scheduled(self):
        from cveFeed.scan_control import PAUSE_EXEMPT_TASKS
        from django_celery_beat.models import PeriodicTask
        self.assertIn('prune_scan_history', PAUSE_EXEMPT_TASKS)
        self.assertTrue(PeriodicTask.objects.filter(name='cvengine-scan-history-retention', task='prune_scan_history', enabled=True).exists())
