"""Instance-wide deep-scan coverage gate (cveFeed.coverage_topup.backlog_exists): cveFeed.fullscan and
cveFeed.udp_scan must not spend capacity on a full port sweep or a UDP exposure check while any project still has
a host missing its core first pass, but a backlog that is only bounty-blocked or only there because scanning is
paused must not gate deep scanning forever."""
import os
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.db import connection
from django.utils import timezone

from cveFeed import assessment_review as ar
from cveFeed import coverage_topup, fullscan, udp_scan
from cveFeed.models import ScanControl
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain


def fully_covered(domain, engine, host):
    """A Subdomain with every core stage completed: not part of any backlog."""
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
    sub = Subdomain.objects.create(target_domain=domain, scan_history=scan, name=host)
    for stage in ar.HOST_STAGES:
        ScanActivity.objects.create(scan_of=scan, name=stage, title=stage, status=2, time=timezone.now())
    return sub


class BacklogExistsTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Gate org', slug='gate-org')
        self.project = Project.objects.create(name='Gate', slug='gate', org=self.org, insert_date=self.now)
        self.domain = Domain.objects.create(name='gate.example', project=self.project, insert_date=self.now)
        self.engine = EngineType.objects.create(engine_name='gate-engine', yaml_configuration='x')

    def test_no_backlog_anywhere_is_false(self):
        fully_covered(self.domain, self.engine, 'covered.gate.example')
        self.assertFalse(coverage_topup.backlog_exists(now=self.now))

    def test_a_due_host_in_a_different_project_still_gates(self):
        fully_covered(self.domain, self.engine, 'covered.gate.example')  # the swept project has nothing due
        other_org = Org.objects.create(name='Gate other', slug='gate-other-org')
        other = Project.objects.create(name='Gate other', slug='gate-other', org=other_org, insert_date=self.now)
        other_domain = Domain.objects.create(name='other.gate.example', project=other, insert_date=self.now)
        Subdomain.objects.create(target_domain=other_domain, name='due.other.gate.example')
        self.assertTrue(coverage_topup.backlog_exists(now=self.now))

    def test_a_bounty_blocked_project_backlog_does_not_gate(self):
        Subdomain.objects.create(target_domain=self.domain, name='blocked.gate.example')
        with mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value={self.project.pk}):
            self.assertFalse(coverage_topup.backlog_exists(now=self.now))
        # without the bounty block the very same backlog does gate
        self.assertTrue(coverage_topup.backlog_exists(now=self.now))

    def test_a_paused_instance_does_not_gate_either(self):
        Subdomain.objects.create(target_domain=self.domain, name='paused.gate.example')
        self.assertTrue(coverage_topup.backlog_exists(now=self.now))  # the backlog is real
        ScanControl.objects.create(pk=1, paused=True)
        self.assertFalse(coverage_topup.backlog_exists(now=self.now))  # but nothing is eligible to work on right now

    def test_the_gate_is_a_bounded_query_not_an_unbounded_table_scan(self):
        for i in range(40):
            Subdomain.objects.create(target_domain=self.domain, name=f'many{i}.gate.example')
        with CaptureQueriesContext(connection) as queries:
            self.assertTrue(coverage_topup.backlog_exists(now=self.now))
        few_hosts_queries = len(queries)
        self.assertLess(few_hosts_queries, 15)  # one project, short-circuits on the first due id (LIMIT 1), no DISTINCT count
        # A second project with no backlog at all still only costs one more bounded, LIMIT-1 query, however many
        # hosts it holds; the query count tracks the number of PROJECTS walked, not the number of hosts in any of them.
        clean_org = Org.objects.create(name='Gate clean', slug='gate-clean-org')
        clean = Project.objects.create(name='Gate clean', slug='gate-clean', org=clean_org, insert_date=self.now)
        clean_domain = Domain.objects.create(name='clean.gate.example', project=clean, insert_date=self.now)
        for i in range(200):
            fully_covered(clean_domain, self.engine, f'clean{i}.clean.gate.example')
        with CaptureQueriesContext(connection) as queries:
            self.assertTrue(coverage_topup.backlog_exists(now=self.now))  # still gated by self.project alone
        self.assertEqual(len(queries), few_hosts_queries)


class FullScanGateTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Gate full', slug='gate-full-org')
        self.project = Project.objects.create(name='Gate full', slug='gate-full', org=org, insert_date=now)
        self.domain = Domain.objects.create(name='fullgate.example', project=self.project, insert_date=now)
        self.engine = EngineType.objects.create(engine_name='fullgate-engine', yaml_configuration='x')
        for p in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
                  mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'),
                  mock.patch('cveFeed.fullscan.CLAIM_KEY', 'cvengine:fullscan:gate-test'),
                  mock.patch.dict(os.environ, {}, clear=False)):
            p.start()
        self.addCleanup(mock.patch.stopall)
        os.environ.pop('CVENGINE_FULLSCAN', None)
        self._clear_gate_note_key('full-port-scan')

    def _clear_gate_note_key(self, label):
        from reNgine import resources
        client = getattr(resources.get_store(), 'r', None)
        if client is not None:  # a key a previous test run left in Redis would hide what this one checks
            client.delete(f'cvengine:sweep:coverage-gate-note-{label}')

    def test_the_full_port_sweep_is_skipped_while_backlog_exists(self):
        Subdomain.objects.create(target_domain=self.domain, name='due.fullgate.example')
        runner = mock.Mock()
        out = fullscan.run(runner=runner)
        self.assertEqual(out, {'skipped': 'coverage backlog: first-pass hosts are still outstanding'})
        runner.assert_not_called()

    def test_the_full_port_sweep_proceeds_once_the_backlog_is_empty(self):
        fully_covered(self.domain, self.engine, 'covered.fullgate.example')
        out = fullscan.run(runner=mock.Mock())
        self.assertNotEqual(out.get('skipped'), 'coverage backlog: first-pass hosts are still outstanding')

    def test_the_deferral_is_logged_once_not_on_every_firing(self):
        from cveFeed.models import AgentActivity
        Subdomain.objects.create(target_domain=self.domain, name='due.fullgate.example')
        fullscan.run(runner=mock.Mock())
        fullscan.run(runner=mock.Mock())
        notes = AgentActivity.objects.filter(message__startswith='Full-port scan deferred')
        self.assertEqual(notes.count(), 1)
        self.assertIn('1 host', notes.first().message)
        self.assertIn('1 project', notes.first().message)


class UdpScanGateTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Gate udp', slug='gate-udp-org')
        self.project = Project.objects.create(name='Gate udp', slug='gate-udp', org=org, insert_date=now)
        self.domain = Domain.objects.create(name='udpgate.example', project=self.project, insert_date=now)
        self.engine = EngineType.objects.create(engine_name='udpgate-engine', yaml_configuration='x')
        for p in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
                  mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'),
                  mock.patch('cveFeed.udp_scan.CLAIM_KEY', 'cvengine:udpscan:gate-test'),
                  mock.patch.dict(os.environ, {}, clear=False)):
            p.start()
        self.addCleanup(mock.patch.stopall)
        os.environ.pop('CVENGINE_UDPSCAN', None)

    def test_the_udp_sweep_is_skipped_while_backlog_exists_in_another_project(self):
        fully_covered(self.domain, self.engine, 'covered.udpgate.example')  # this project has nothing due
        other_org = Org.objects.create(name='Gate udp other', slug='gate-udp-other-org')
        other = Project.objects.create(name='Gate udp other', slug='gate-udp-other', org=other_org, insert_date=timezone.now())
        other_domain = Domain.objects.create(name='other.udpgate.example', project=other, insert_date=timezone.now())
        Subdomain.objects.create(target_domain=other_domain, name='due.other.udpgate.example')
        runner = mock.Mock()
        out = udp_scan.run(runner=runner)
        self.assertEqual(out, {'skipped': 'coverage backlog: first-pass hosts are still outstanding'})
        runner.assert_not_called()

    def test_the_udp_sweep_proceeds_once_the_backlog_is_empty(self):
        fully_covered(self.domain, self.engine, 'covered.udpgate.example')
        out = udp_scan.run(runner=mock.Mock())
        self.assertNotEqual(out.get('skipped'), 'coverage backlog: first-pass hosts are still outstanding')
