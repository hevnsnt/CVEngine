"""The bounded versions of the queries the review found scanning whole tables: they must answer exactly what they answered before."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import assessment_review as ar
from cveFeed import conductor, counts, views
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, DiscoveryEvent
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for

NOW = timezone.now()


class Fixture(TestCase):
	def setUp(self):
		org = Org.objects.create(name='E', slug='eff')
		self.project = Project.objects.create(name='E', slug='eff-one', insert_date=NOW, org=org)
		self.other = Project.objects.create(name='F', slug='eff-two', insert_date=NOW, org=org)
		self.domain = Domain.objects.create(name='eff.example', project=self.project, insert_date=NOW)
		self.other_domain = Domain.objects.create(name='other.example', project=self.other, insert_date=NOW)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def scan(self, domain=None, status=2, hours=3):
		return ScanHistory.objects.create(domain=domain or self.domain, scan_type=self.engine, scan_status=status, tasks=[],
		                                  start_scan_date=NOW - timedelta(hours=hours))

	def host(self, name, scan, domain=None, ip=None):
		sub = Subdomain.objects.create(target_domain=domain or self.domain, name=name, scan_history=scan)
		if ip:
			sub.ip_addresses.add(IpAddress.objects.get_or_create(address=ip)[0])
		return sub


class CoverageInventoryTests(Fixture):
	def test_a_name_missing_from_the_latest_scan_is_not_due_and_each_host_is_one_row(self):
		old, new = self.scan(hours=30), self.scan(hours=3)
		self.host('gone.eff.example', old)
		self.host('kept.eff.example', old)
		kept = self.host('kept.eff.example', new)
		count, ids = ar.host_coverage_due(self.project, NOW, limit=10)
		self.assertEqual((count, ids), (1, [kept.pk]))


class ExposedAmongTests(Fixture):
	def test_restricting_to_the_projects_gives_the_same_answer(self):
		scan, other_scan = self.scan(), self.scan(self.other_domain)
		a = self.host('a.eff.example', scan, ip='192.0.2.1')
		self.host('b.eff.example', scan, ip='192.0.2.2')
		c = self.host('c.other.example', other_scan, self.other_domain, ip='192.0.2.3')
		cve = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=9.0, kev=True, affected=[])
		for sub in (a, c):
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', confidence=.8)
		reps = counts.host_reps(domain_ids=[self.domain.id])
		self.assertEqual(counts.exposed_among(reps).count(), 1)
		self.assertEqual(counts.exposed_among(reps, project_ids=[self.project.id]).count(), 1)
		self.assertEqual(counts.exposed_among(counts.host_reps(), project_ids=[self.project.id, self.other.id]).count(), 2)

	def test_the_status_snapshot_skips_the_fixed_findings_walk(self):
		from cveFeed import stats_history
		with mock.patch.object(stats_history, '_fixed_stats', side_effect=AssertionError('walked')):
			snap = stats_history.compute_snapshot(self.project, with_fixed=False)
		self.assertEqual((snap['fixed'], snap['mean_days_to_fix']), (0, None))


class DiscoveryCountsTests(Fixture):
	def test_the_ticker_counts_are_kept_for_a_few_seconds_and_dropped_with_the_stats(self):
		views._DISCOVERY_COUNTS_CACHE.clear()
		scan = self.scan()
		self.host('one.eff.example', scan, ip='192.0.2.10')
		user = User.objects.create_user('effuser', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		client = client_for(user)
		self.assertEqual(client.get('/cve/api/discovery').json()['counts']['hosts'], 1)
		self.host('two.eff.example', scan, ip='192.0.2.11')
		self.assertEqual(client.get('/cve/api/discovery').json()['counts']['hosts'], 1)  # inside the cache window
		views.bump_stats_revision()
		self.assertEqual(client.get('/cve/api/discovery').json()['counts']['hosts'], 2)

	def test_after_zero_is_the_tail_not_every_event(self):
		scan = self.scan(status=1)
		for i in range(70):
			DiscoveryEvent.objects.create(scan=scan, domain=self.domain, type='DNS_NAME', label=f'n{i}', host=f'n{i}.eff.example')
		user = User.objects.create_user('effuser2', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		events = client_for(user).get(f'/cve/api/discovery?scan={scan.id}&after=0').json()['events']
		self.assertEqual(len(events), 60)


class BackgroundRunningTests(Fixture):
	def test_lines_under_a_running_scan_are_left_out_and_the_bounds_hold(self):
		running = self.scan(status=1, hours=1)
		under = AgentActivity.objects.create(project=self.project, kind='scan', message='under', status='running', detail={'scan_id': running.id})
		free = AgentActivity.objects.create(project=self.project, kind='scan', message='free', status='running', detail={'scan_id': 999999})
		old = AgentActivity.objects.create(project=self.project, kind='scan', message='old', status='running')
		AgentActivity.objects.filter(pk=old.pk).update(created_at=NOW - counts.BACKGROUND_WINDOW - timedelta(hours=1))
		self.assertEqual(set(counts.background_running().values_list('pk', flat=True)), {free.pk})
		self.assertNotIn(under.pk, counts.background_running().values_list('pk', flat=True))


class GraphEdgesTests(Fixture):
	def test_only_edges_between_drawn_hosts_are_kept_in_a_fixed_order(self):
		scan = self.scan()
		self.host('root.eff.example', scan, ip='192.0.2.20')
		self.host('child.eff.example', scan, ip='192.0.2.21')
		self.host('dead.eff.example', scan)  # never resolved: not drawn
		for parent, host in (('root.eff.example', 'child.eff.example'), ('root.eff.example', 'dead.eff.example'),
		                     ('nobody.eff.example', 'child.eff.example'), ('root.eff.example', 'child.eff.example')):
			DiscoveryEvent.objects.create(scan=scan, domain=self.domain, type='DNS_NAME', host=host, parent_host=parent)
		payload = views.graph_payload()
		ids = {n['label']: n['id'] for n in payload['nodes'] if n['kind'] == 'subdomain'}
		self.assertEqual(set(ids), {'root.eff.example', 'child.eff.example'})
		self.assertIn({'from': ids['root.eff.example'], 'to': ids['child.eff.example']}, payload['edges'])
		self.assertEqual(sum(1 for e in payload['edges'] if e['from'] == ids['root.eff.example'] and e['to'] == ids['child.eff.example']), 1)


class NextTargetsTests(Fixture):
	def test_the_never_scanned_target_comes_first_then_the_longest_since_scanned(self):
		self.scan(hours=40)
		self.scan(hours=30)  # the newest scan of the domain is what counts, not the oldest
		self.assertEqual(conductor.next_targets(5, now=NOW), [self.other_domain.id, self.domain.id])
		self.assertEqual(conductor.next_targets(1, now=NOW), [self.other_domain.id])
