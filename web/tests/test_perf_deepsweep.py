import os
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import discovery, ledger, tasks
from cveFeed.models import ServiceRun
from dashboard.models import Org, Project
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp import target_types as tt
from targetApp.models import Domain


def _clear_claim():
	client = getattr(resources.get_store(), 'r', None)
	if client is not None:
		client.delete('cvengine:sweep:deep-apex')


class ApexTests(TestCase):
	def test_registrable_domain_via_the_public_suffix_list(self):
		cases = {'www.a.com': 'a.com', 'b.a.com': 'a.com', 'a.com': 'a.com', 'x.y.example.co.uk': 'example.co.uk',
			'example.co.uk': 'example.co.uk', 'a.b.c.com.au': 'c.com.au', 'WWW.A.COM.': 'a.com'}
		for name, apex in cases.items():
			self.assertEqual(tt.apex_domain(name), apex, name)

	def test_ips_and_non_domains_have_no_apex(self):
		for value in ('203.0.113.5', '10.0.0.0/24', '1.1.1.1-9', 'com', '', None):
			self.assertIsNone(tt.apex_domain(value), value)

	def test_the_fallback_without_tldextract_handles_the_common_second_levels(self):
		with mock.patch.dict('sys.modules', {'tldextract': None}), mock.patch.object(tt, '_suffix_extractor', None):
			self.assertEqual(tt.apex_domain('www.example.com'), 'example.com')
			self.assertEqual(tt.apex_domain('a.b.example.co.uk'), 'example.co.uk')


class DeepSweepTests(TestCase):
	def setUp(self):
		_clear_claim()
		self.addCleanup(_clear_claim)
		org = Org.objects.create(name='D', slug='dsw')
		self.p1 = Project.objects.create(name='P1', slug='dsw1', insert_date=timezone.now(), org=org)
		self.p2 = Project.objects.create(name='P2', slug='dsw2', insert_date=timezone.now(), org=org)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		patch = mock.patch('cveFeed.tasks.run_bbot_discovery.delay')
		self.queue = patch.start()
		self.addCleanup(patch.stop)

	def _domain(self, name, project=None):
		return Domain.objects.create(name=name, project=project or self.p1, insert_date=timezone.now())

	def _queued(self):
		return {(s.domain.name, s.domain.project_id) for s in ScanHistory.objects.filter(scan_status=discovery.QUEUED)}

	def test_the_apex_of_two_subdomains_is_queued_once_as_a_deep_scan_and_created_as_a_target(self):
		self._domain('www.a.com')
		self._domain('b.a.com')
		out = tasks.deep_scan_apexes()
		self.assertEqual(out['queued'], 1)
		self.assertEqual(self._queued(), {('a.com', self.p1.id)})
		self.assertTrue(Domain.objects.filter(name='a.com', project=self.p1).exists())
		self.assertEqual([c.args[1] for c in self.queue.call_args_list], ['deep'])

	def test_an_existing_apex_target_is_used_and_projects_are_separate(self):
		apex = self._domain('a.com')
		self._domain('www.other.org', self.p2)
		tasks.deep_scan_apexes()
		self.assertEqual(Domain.objects.filter(name='a.com').count(), 1)
		self.assertEqual(self._queued(), {('a.com', self.p1.id), ('other.org', self.p2.id)})
		self.assertEqual(ScanHistory.objects.get(domain=apex).scan_status, discovery.QUEUED)

	def test_ip_targets_are_skipped(self):
		self._domain('203.0.113.9')
		self.assertEqual(tasks.deep_scan_apexes()['queued'], 0)
		self.assertFalse(ScanHistory.objects.exists())

	def test_an_apex_with_a_fresh_deep_run_is_skipped_and_a_stale_one_is_not(self):
		self._domain('www.fresh.com')
		self._domain('www.stale.com')
		ledger.record('bbot-deep', ['fresh.com'], self.p1)
		ledger.record('bbot-deep', ['stale.com'], self.p1)
		ServiceRun.objects.filter(asset='stale.com').update(finished_at=timezone.now() - timedelta(hours=170))
		tasks.deep_scan_apexes()
		self.assertEqual(self._queued(), {('stale.com', self.p1.id)})

	def test_the_window_is_a_week_and_follows_the_env_setting(self):
		self.assertEqual(ledger.ttl('bbot-deep'), 168 * 3600)
		with mock.patch.dict(os.environ, {'CVENGINE_TTL_BBOT_DEEP': '24'}):
			self.assertEqual(ledger.ttl('bbot-deep'), 24 * 3600)

	def test_a_standard_discovery_does_not_count_as_a_deep_one(self):
		self._domain('www.std.com')
		ledger.record('bbot', ['std.com'], self.p1)  # a standard run's ledger row
		tasks.deep_scan_apexes()
		self.assertEqual(self._queued(), {('std.com', self.p1.id)})

	def test_the_cap_applies_oldest_first(self):
		for n in range(5):
			self._domain(f'www.site{n}.com')
		for n, hours in ((0, 10), (1, 500), (2, 300), (3, 200)):  # site4 never had one: it goes first
			ledger.record('bbot-deep', [f'site{n}.com'], self.p1)
			ServiceRun.objects.filter(asset=f'site{n}.com').update(finished_at=timezone.now() - timedelta(hours=hours + 168))
		with mock.patch.dict(os.environ, {'CVENGINE_DEEP_SWEEP_MAX': '2'}):
			out = tasks.deep_scan_apexes()
		self.assertEqual(out['queued'], 2)
		self.assertEqual(out['due'], 5)
		self.assertEqual(self._queued(), {('site4.com', self.p1.id), ('site1.com', self.p1.id)})

	def test_no_second_deep_scan_while_one_is_queued_or_running(self):
		self._domain('www.q.com')
		tasks.deep_scan_apexes()
		_clear_claim()
		again = tasks.deep_scan_apexes()
		self.assertEqual(again['queued'], 0)
		self.assertEqual(ScanHistory.objects.filter(domain__name='q.com').count(), 1)
		ScanHistory.objects.all().delete()
		apex = self._domain('r.com')
		ScanHistory.objects.create(domain=apex, scan_type=self.engine, scan_status=discovery.RUNNING,
			start_scan_date=timezone.now() - timedelta(hours=2))  # a long-running discovery is not the 10-minute double-click window
		_clear_claim()
		tasks.deep_scan_apexes()  # q.com is due again (its queued scan was deleted above); r.com is covered by its running one
		self.assertEqual(ScanHistory.objects.filter(domain=apex).count(), 1)
		self.assertEqual(ScanHistory.objects.filter(domain__name='q.com').count(), 1)

	def test_a_host_pipeline_does_not_hide_the_apex(self):
		apex = self._domain('h.com')
		ScanHistory.objects.create(domain=apex, scan_type=self.engine, scan_status=discovery.QUEUED, start_scan_date=timezone.now(),
			tasks=[discovery.HOST_PIPELINE_TASK])
		self.assertEqual(tasks.deep_scan_apexes()['queued'], 1)

	def test_two_sweeps_never_overlap(self):
		self._domain('www.o.com')
		self.assertEqual(tasks.deep_scan_apexes()['queued'], 1)
		ScanHistory.objects.all().delete()
		self.assertEqual(tasks.deep_scan_apexes()['queued'], 0)  # the claim is still held

	def test_an_apex_held_by_another_project_is_skipped_not_duplicated(self):
		self._domain('taken.com', self.p2)
		self._domain('www.taken.com', self.p1)
		out = tasks.deep_scan_apexes()
		self.assertEqual(out['skipped'], 1)
		self.assertEqual(Domain.objects.filter(name='taken.com').count(), 1)

	def test_the_daily_schedule_exists(self):
		from django_celery_beat.models import PeriodicTask
		task = PeriodicTask.objects.get(name='cvengine-deep-apex-sweep')
		self.assertEqual((task.task, task.queue, task.enabled), ('deep_scan_apexes', 'cve_feed_queue', True))


class DeepSweepFairnessTests(TestCase):
	setUp, _domain, _queued = DeepSweepTests.setUp, DeepSweepTests._domain, DeepSweepTests._queued

	def test_one_project_cannot_fill_the_whole_run(self):
		for i in range(6):
			self._domain(f'www.big{i}.com', self.p1)
		self._domain('www.small.org', self.p2)
		with mock.patch.dict(os.environ, {'CVENGINE_DEEP_SWEEP_PER_PROJECT': '3'}):
			out = tasks.deep_scan_apexes()
		queued = self._queued()
		self.assertEqual(sum(1 for _name, pid in queued if pid == self.p1.id), 3)  # the other three wait for the next run
		self.assertIn(('small.org', self.p2.id), queued)
		self.assertEqual(out['queued'], 4)

	def test_the_per_project_cap_is_not_a_limit_when_the_project_is_alone_and_small(self):
		for i in range(4):
			self._domain(f'www.few{i}.com', self.p1)
		self.assertEqual(tasks.deep_scan_apexes()['queued'], 4)
