"""A write that changes a number a user reads makes that number fresh at once, even when the snapshot is kept for the longest time it ever is.

The headline counts and the ticker are kept for up to ten times the cost of computing them (``snapshot_cache.COST_FACTOR``, at most
``COST_CEILING`` seconds) on a slow install. That is only fair when every write that moves a number drops the snapshots (a stats revision bump
after commit). These tests pin the lifetime at an hour, prime the snapshots, make one write, and read the count a user reads: it must already
be the new one. Writes through ``_apply_remediation`` (close, reopen, bulk, agent fix) are covered by the bump inside it (PR 594).
"""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import host_manage, services as svc
from cveFeed import counts, snapshot_cache, views
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.discovery_fixtures import sentinel_discovery
from tests.test_discovery import EVENTS


class FreshWorld(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='F', slug='f-org')
        self.project = Project.objects.create(name='F', slug='f-proj', insert_date=now, org=org)
        self.engine = EngineType.objects.create(engine_name='f-engine', yaml_configuration='x', default_engine=True)
        self.domain = Domain.objects.create(name='f.example.com', project=self.project, insert_date=now)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=2, start_scan_date=now - timedelta(hours=3), tasks=[])
        self.user = User.objects.create_superuser('f-root', 'root@f.example.test', 'x')
        self.ctx = svc.Ctx(user=self.user)
        self.subs = []
        for i in range(4):
            sub = Subdomain.objects.create(target_domain=self.domain, name=f'h{i}.f.example.com', scan_history=self.scan, http_status=200)
            sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i + 1}'))
            self.subs.append(sub)
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7001', cvss=9.8, kev=True, published_at=now, affected=[])
        self.matches = [CVEMatch.objects.create(cve_entry=cve, subdomain=s, matched_product='nginx', confidence=.9) for s in self.subs[:3]]
        self.vuln = Vulnerability.objects.create(name='Reflected XSS', severity=3, subdomain=self.subs[3], target_domain=self.domain, open_status=True,
                                                 http_url='https://h3.f.example.com/', source='nuclei')
        self.hyg = HygieneFinding.objects.create(domain=self.domain, host='h3.f.example.com', check_name='spf_missing', severity=2, title='No SPF')
        views.clear_stats_cache()
        self.addCleanup(views.clear_stats_cache)
        longest = mock.patch.object(snapshot_cache, 'fresh_for', lambda name, fresh, entry: 3600)  # the slowest install: a snapshot is kept for an hour
        longest.start()
        self.addCleanup(longest.stop)

    def stats(self):
        return views.cached_stats_snapshot()['payload']

    def ticker(self):
        return views.cached_discovery_counts()

    def written(self, write):
        """Prime both snapshots, run ``write`` (its after-commit callbacks run), and return (stats, ticker) read afterwards."""
        self.stats(), self.ticker()
        with self.captureOnCommitCallbacks(execute=True):
            write()
        return self.stats(), self.ticker()


class ClosingAndReopeningTests(FreshWorld):
    def test_closing_a_match_moves_the_matches_count_at_once(self):
        before = self.stats()['matches']
        after, _ = self.written(lambda: svc.update_match(self.ctx, 'f-proj', self.matches[0].id, status='fixed'))
        self.assertEqual((before, after['matches']), (3, 2))
        self.assertEqual(after['matches'], counts.exposed_matches().count())

    def test_reopening_a_match_moves_it_back_at_once(self):
        svc.update_match(self.ctx, 'f-proj', self.matches[0].id, status='false_positive')
        views.clear_stats_cache()
        self.assertEqual(self.stats()['matches'], 2)
        after, _ = self.written(lambda: svc.update_match(self.ctx, 'f-proj', self.matches[0].id, status='open'))
        self.assertEqual(after['matches'], 3)

    def test_closing_a_finding_moves_the_open_findings_count_at_once(self):
        before = self.stats()['scanner_findings']
        after, _ = self.written(lambda: svc.update_finding_status(self.ctx, 'f-proj', 'vulnerability', self.vuln.id, status='accepted_risk'))
        self.assertEqual((before, after['scanner_findings']), (1, 0))

    def test_closing_hygiene_findings_in_bulk_moves_the_counts_at_once(self):
        before = self.stats()['hygiene_open']
        items = [{'kind': 'hygiene', 'id': self.hyg.id}, {'kind': 'match', 'id': self.matches[1].id}, {'kind': 'vulnerability', 'id': self.vuln.id}]
        after, _ = self.written(lambda: svc.bulk_update_finding_status(self.ctx, 'f-proj', items, 'fixed'))
        self.assertEqual((before, after['hygiene_open'], after['matches'], after['scanner_findings']), (1, 0, 2, 0))

    def test_the_agent_fix_path_moves_the_count_at_once(self):
        """agent_broker closes a match with ``_apply_remediation`` (the call under test here)."""
        after, _ = self.written(lambda: svc._apply_remediation(self.matches[2], 'fixed', 'Fixed by agent', self.user))
        self.assertEqual(after['matches'], 2)


class HostAndTargetWriteTests(FreshWorld):
    def test_deleting_a_host_moves_the_host_counts_at_once(self):
        stats, ticker = self.written(lambda: host_manage.delete_host(self.ctx, 'f-proj', 'h0.f.example.com'))
        self.assertEqual((stats['hosts'], stats['matches'], ticker['hosts']), (3, 2, 3))

    def test_archiving_and_restoring_a_host_refreshes_the_counts(self):
        """Counts do not drop an archived host today; the snapshots are still dropped, so a count that starts to follow it never lags."""
        self.stats()
        rev = snapshot_cache.revision()
        with self.captureOnCommitCallbacks(execute=True):
            host_manage.host_archive(self.ctx, 'f-proj', 'h1.f.example.com', 'archive')
        archived = snapshot_cache.revision()
        with self.captureOnCommitCallbacks(execute=True):
            host_manage.host_archive(self.ctx, 'f-proj', 'h1.f.example.com', 'restore')
        self.assertEqual(len({rev, archived, snapshot_cache.revision()}), 3)

    def test_deleting_a_target_moves_the_counts_at_once(self):
        other = Domain.objects.create(name='g.example.com', project=self.project, insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=other, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now() - timedelta(hours=3), tasks=[])
        Subdomain.objects.create(target_domain=other, name='g.example.com', scan_history=scan, http_status=200).ip_addresses.add(IpAddress.objects.create(address='198.51.100.77'))
        views.clear_stats_cache()
        before = self.stats()
        self.assertEqual((before['targets'], before['hosts']), (2, 5))
        after, ticker = self.written(lambda: svc.delete_targets(self.ctx, 'f-proj', ids=[other.id]))
        self.assertEqual((after['targets'], after['hosts'], ticker['hosts']), (1, 4, 4))

    def test_excluding_a_host_moves_the_counts_at_once(self):
        stats, _ = self.written(lambda: host_manage.exclude_host(self.ctx, 'f-proj', 'h2.f.example.com'))
        self.assertEqual((stats['hosts'], stats['matches']), (3, 2))

    def test_moving_a_host_to_another_project_moves_the_counts_at_once(self):
        Project.objects.create(name='G', slug='g-proj', insert_date=timezone.now(), org=self.project.org)
        with mock.patch('agentapi.services._expand_target', return_value=None), mock.patch('agentapi.services.add_target', return_value={'created': True, 'scan_ids': []}):
            stats, _ = self.written(lambda: host_manage.move_host(self.ctx, 'f-proj', 'h0.f.example.com', 'g-proj', discover=False))
        self.assertEqual((stats['hosts'], stats['matches']), (3, 2))

    def test_deleting_a_project_moves_the_counts_at_once(self):
        import json

        from django.test import RequestFactory

        from cveFeed import admin_api
        other = Project.objects.create(name='H', slug='h-proj', insert_date=timezone.now(), org=self.project.org)
        request = RequestFactory().post('/x', data=json.dumps({'confirm': 'H'}), content_type='application/json')
        stats, _ = self.written(lambda: admin_api.projects_delete(request, self.user, other.id))
        self.assertEqual(stats['hosts'], 4)
        self.assertFalse(Project.objects.filter(pk=other.pk).exists())
        rev = snapshot_cache.revision()
        self.stats()
        request = RequestFactory().post('/x', data=json.dumps({'confirm': 'F'}), content_type='application/json')
        with self.captureOnCommitCallbacks(execute=True):
            admin_api.projects_delete(request, self.user, self.project.id)
        self.assertNotEqual(rev, snapshot_cache.revision())
        self.assertEqual(self.stats()['hosts'], 0)


class ScanTests(FreshWorld):
    def test_a_finished_scan_moves_the_host_counts_at_once(self):
        """A discovery that ends makes its hosts the target's current inventory: the headline and ticker read them on the next poll."""
        domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'), mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False):
            from cveFeed import discovery
            scan = discovery.start_discovery(domain)

        def finish():
            with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'), sentinel_discovery(EVENTS):
                discovery.run_discovery(scan.id)
        stats, ticker = self.written(finish)
        self.assertEqual(stats['hosts'], 4 + 2)
        self.assertEqual(ticker['hosts'], stats['hosts_live'])


class HostRepsAreNotKeptLongTests(FreshWorld):
    def test_the_shared_host_list_is_not_adaptive(self):
        self.assertNotIn('host-reps', snapshot_cache.ADAPTIVE)
