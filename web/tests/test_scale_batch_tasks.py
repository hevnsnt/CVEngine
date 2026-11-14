"""Background work that must not cost a statement per host or per candidate (round 2 of the scale work): queueing a batch of host assessments, and the hot
validation sweep turning candidates away. Both ran on the VPS's one Celery at thousands of statements per run."""
import os
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import host_assessment, hot_validation, triage
from cveFeed.models import AutomaticValidation, CVEEntry, HostAssessment, HostExclusion, HostState
from dashboard.models import Org, Project
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain


class EnqueueBatchTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Eb org', slug='eb-org')
        self.project = Project.objects.create(name='Eb', slug='eb', org=self.org, insert_date=self.now)
        self.domain = Domain.objects.create(name='eb.example.test', project=self.project, insert_date=self.now)

    def hosts(self, n, start=0):
        return [Subdomain.objects.create(target_domain=self.domain, name=f'h{i}.eb.example.test') for i in range(start, start + n)]

    def run_batch(self, subs):
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async') as sender, mock.patch('cveFeed.host_assessment._require_capacity'):
            sender.return_value.id = 'eb-task'
            with CaptureQueriesContext(connection) as q:
                jobs, skipped = host_assessment.enqueue_batch(self.project, subs, source='topup')
        return jobs, skipped, len(q)

    def test_the_cost_of_a_batch_does_not_grow_with_its_hosts(self):
        self.run_batch(self.hosts(2))  # fills the process-wide caches
        _, _, few = self.run_batch(self.hosts(4, start=10))
        jobs, skipped, many = self.run_batch(self.hosts(40, start=100))
        self.assertEqual((len(jobs), skipped), (40, []))
        self.assertLessEqual(many - few, 2, (few, many))

    def test_every_gate_still_turns_its_host_away(self):
        subs = self.hosts(6)
        HostExclusion.objects.create(org=self.org, host=subs[0].name)
        HostState.objects.create(project=self.project, domain=self.domain, host=subs[1].name, archived_at=self.now, first_seen=self.now, last_seen=self.now, score=0)
        HostAssessment.objects.create(project=self.project, domain=self.domain, host=subs[2].name, status='queued')
        jobs, skipped, _ = self.run_batch(subs)
        self.assertEqual(sorted(j.host for j in jobs), sorted(s.name for s in subs[3:]))
        reasons = {s.name: why for s, why in skipped}
        self.assertEqual(reasons[subs[0].name], 'host is excluded')
        self.assertIn('archived', reasons[subs[1].name])
        self.assertEqual(reasons[subs[2].name], 'already queued')

    def test_a_host_queued_by_a_second_sweep_in_between_is_left_out_alone(self):
        subs = self.hosts(4)

        def race(_project):  # runs after the gates and before the insert: the other sweep got there first
            HostAssessment.objects.create(project=self.project, domain=self.domain, host=subs[1].name, status='queued')
        with mock.patch('cveFeed.tasks.assess_hosts.apply_async') as sender, mock.patch('cveFeed.host_assessment._require_capacity', side_effect=race):
            sender.return_value.id = 'eb-task'
            jobs, skipped = host_assessment.enqueue_batch(self.project, subs, source='topup')
        self.assertEqual(sorted(j.host for j in jobs), sorted(s.name for s in subs if s != subs[1]))
        self.assertEqual([(s.name, why) for s, why in skipped], [(subs[1].name, 'already queued')])


class HotSweepCostTests(TestCase):
    """A project at its cap turns every candidate away: that must not cost a row lock and a dozen statements each."""

    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='Hs org', slug='hs2-org')
        self.project = Project.objects.create(name='Hs', slug='hs2', org=self.org, insert_date=now)
        self.domain = Domain.objects.create(name='hs.example.test', project=self.project, insert_date=now)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-9', cvss=9.8, kev=True, published_at=now)
        self.patch = mock.patch.dict(os.environ, {'CVENGINE_AUTO_VALIDATE_ALL_MATCHES': '0'})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def candidates(self, n, start=0):
        rows = []
        for i in range(start, start + n):
            sub = Subdomain.objects.create(name=f'c{i}.hs.example.test', target_domain=self.domain)
            rows.append(Vulnerability.objects.create(name=f'finding {i}', severity=4, source='bbot', subdomain=sub, target_domain=self.domain))
        triage.track(rows)

    def sweep(self):
        with mock.patch('cveFeed.hot_validation._backfill_projects', return_value=0), \
                mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'), mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            with CaptureQueriesContext(connection) as q:
                stats = hot_validation.sweep()
        return stats, len(q)

    def test_candidates_of_a_project_at_its_cap_cost_nothing_each(self):
        self.candidates(hot_validation.PROJECT_ACTIVE_CAP + 5)
        first, _ = self.sweep()
        self.assertEqual(first['fire'], hot_validation.PROJECT_ACTIVE_CAP)
        _, few = self.sweep()
        self.candidates(60, start=100)
        stats, many = self.sweep()
        self.assertGreater(stats['project_cap'] + stats['inflight'], 20)
        self.assertEqual(stats['fire'], 0)
        self.assertLessEqual(many - few, 4, (few, many))

    def test_a_running_job_and_a_fresh_one_are_still_counted_as_such(self):
        self.candidates(3)
        first, _ = self.sweep()
        self.assertEqual(first['fire'], 3)
        again, _ = self.sweep()
        self.assertEqual((again['fire'], again['inflight']), (0, 6))  # a critical finding is a candidate of the fire lane and of the smoke lane
        AutomaticValidation.objects.update(status='completed', finished_at=timezone.now())
        fresh, _ = self.sweep()
        self.assertEqual((fresh['fire'], fresh['fresh']), (0, 6))


class DueHostIndexTests(TestCase):
    def test_the_due_host_query_has_the_partial_index_for_its_unresolved_check(self):
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(cursor, HostState._meta.db_table)
        index = constraints['hoststate_unresolved_host_idx']
        self.assertEqual(index['columns'], ['project_id', 'host'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT indexdef FROM pg_indexes WHERE indexname = 'hoststate_unresolved_host_idx'")
            self.assertIn('unresolved_checks >= 1', cursor.fetchone()[0])

    def test_the_due_host_query_is_one_statement(self):
        from cveFeed import coverage_topup
        now = timezone.now()
        org = Org.objects.create(name='Dh org', slug='dh-org')
        project = Project.objects.create(name='Dh', slug='dh', org=org, insert_date=now)
        domain = Domain.objects.create(name='dh.example.test', project=project, insert_date=now)
        for i in range(5):
            Subdomain.objects.create(target_domain=domain, name=f'h{i}.dh.example.test')
        with CaptureQueriesContext(connection) as q:
            _, due = coverage_topup.host_coverage_due(project, now, limit=10, need_count=False)
        self.assertEqual((len(due), len(q)), (5, 1))
