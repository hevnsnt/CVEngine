from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import views
from cveFeed.discovery import queue_position
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for


class GraphPollingTests(TestCase):
	def setUp(self):
		cache.clear()
		now = timezone.now()
		self.project = Project.objects.create(name='G', slug='gp', insert_date=now, org=Org.objects.create(name='G', slug='g'))
		self.domain = Domain.objects.create(name='graph.test', project=self.project, insert_date=now)
		self.sub = Subdomain.objects.create(target_domain=self.domain, name='www.graph.test')
		self.sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.5'))
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-5', kev=True, cvss=9.8, affected=[])
		self.match = CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sub, matched_product='nginx', confidence=0.9)
		self.user = User.objects.create_user('gu', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.project, role='audit')
		self.client_ = client_for(self.user)

	def test_same_version_answers_304_and_a_change_moves_the_version(self):
		# graph_version folds in a wall-clock bucket (GRAPH_VERSION_WINDOW), so two requests that straddle a bucket edge differ: pin the bucket
		patcher = mock.patch.object(views, 'GRAPH_VERSION_WINDOW', 10 ** 12)
		patcher.start()
		self.addCleanup(patcher.stop)
		first = self.client_.get('/cve/api/graph')
		self.assertEqual(first.status_code, 200)
		version = first.json()['version']
		self.assertEqual(self.client_.get(f'/cve/api/graph?v={version}').status_code, 304)
		self.sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.6'))
		changed = self.client_.get(f'/cve/api/graph?v={version}')
		self.assertEqual(changed.status_code, 200)
		self.assertNotEqual(changed.json()['version'], version)

	def test_a_match_verdict_change_moves_the_version(self):
		version = views.graph_version()
		CVEMatch.objects.filter(pk=self.match.pk).update(ai_verdict='not_affected', updated_at=timezone.now())
		self.assertNotEqual(views.graph_version(), version)

	def test_a_new_finding_moves_the_version(self):
		version = views.graph_version()
		Vulnerability.objects.create(subdomain=self.sub, name='x', severity=3)
		self.assertNotEqual(views.graph_version(), version)

	def test_payload_is_cached_between_requests_with_the_same_version(self):
		with mock.patch.object(views, 'graph_payload', wraps=views.graph_payload) as build:
			self.client_.get('/cve/api/graph')
			self.client_.get('/cve/api/graph')
		self.assertEqual(build.call_count, 1)

	def test_the_graph_payload_names_the_matched_cve(self):
		payload = views.graph_payload()
		self.assertIn('cve:%d' % self.cve.pk, {n['id'] for n in payload['nodes']})


class StatsAndQueueTests(TestCase):
	def test_exposed_hosts_is_one_distinct_count(self):
		now = timezone.now()
		project = Project.objects.create(name='S', slug='sp', insert_date=now, org=Org.objects.create(name='S', slug='s'))
		domain = Domain.objects.create(name='stat.test', project=project, insert_date=now)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-6', affected=[])
		a, b, c = (Subdomain.objects.create(target_domain=domain, name=f'{n}.stat.test') for n in 'abc')
		CVEMatch.objects.create(cve_entry=cve, subdomain=a, matched_product='x')
		CVEMatch.objects.create(cve_entry=cve, subdomain=a, matched_product='y')  # same host twice
		CVEMatch.objects.create(cve_entry=cve, subdomain=c, matched_product='z', ai_verdict='not_affected')
		Vulnerability.objects.create(subdomain=a, name='v', severity=3)  # a again
		Vulnerability.objects.create(subdomain=b, name='w', severity=2)
		Vulnerability.objects.create(subdomain=c, name='info', severity=0)
		with mock.patch.object(views, 'tier_counts', return_value={'fire': 0, 'smoke': 0, 'ice': 0}):
			with CaptureQueriesContext(connection) as ctx:
				stats = views.stats_payload()
		self.assertEqual(stats['exposed_hosts'], 2)
		# one query reads matches and findings together (never one per host or a join that multiplies rows); it counts hosts by name
		self.assertEqual(len([q for q in ctx if 'COUNT' in q['sql'] and 'cvematch' in q['sql'].lower()
			and 'vulnerability' in q['sql'].lower()]), 1)

	def test_queue_position_is_one_count_not_a_list_of_every_queued_scan(self):
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		now = timezone.now()
		project = Project.objects.create(name='Q', slug='qp', insert_date=now, org=Org.objects.create(name='Q', slug='q'))
		domain = Domain.objects.create(name='queue.test', project=project, insert_date=now)
		scans = [ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=-1, start_scan_date=now) for _ in range(4)]
		with CaptureQueriesContext(connection) as ctx, mock.patch('cveFeed.discovery.queued_ids') as listing:
			self.assertEqual(queue_position(scans[2].id), 2)
		self.assertEqual(len(ctx), 1)
		listing.assert_not_called()
		self.assertEqual(queue_position(scans[2].id, [s.id for s in scans]), 2)  # the list path still works
