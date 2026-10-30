"""A domain's current inventory (correlation.latest_scan_q): the latest successful full scan, plus the successful host-pipeline
scans that ran after it, newest row per host. A host-pipeline scan (a rescan, a re-test, new hosts from certificate transparency)
holds only the hosts it ran on, so it must add to the inventory, never replace it."""
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import discovery
from cveFeed.correlation import latest_scan_q
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_perf_hostpipeline import _stages

HP = [discovery.HOST_PIPELINE_TASK]


class CurrentInventoryTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='Acme', slug='acme-org')
		self.project = Project.objects.create(name='Acme', slug='acme', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='acme.example', project=self.project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def scan(self, status=2, tasks=None, names=()):
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=status,
			start_scan_date=timezone.now(), tasks=tasks)
		for name in names:
			Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
		return scan

	def current(self):
		rows = Subdomain.objects.filter(latest_scan_q(), target_domain=self.domain)
		return sorted(((row.name, row.scan_history_id) for row in rows), key=lambda row: (row[0], row[1] or 0))

	def test_rescanning_one_host_keeps_the_rest_of_the_inventory(self):
		full = self.scan(names=['www.acme.example', 'api.acme.example', 'mail.acme.example'])
		_, kwargs = _stages()
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'):
			out = discovery.run_host_pipeline(self.domain.id, ['www.acme.example'], retest=True, **kwargs)
		self.assertEqual(out['status'], discovery.SUCCESS)
		# every host is still there, once; the rescanned host is read from the rescan, the rest from the full scan
		self.assertEqual(self.current(), [('api.acme.example', full.id), ('mail.acme.example', full.id),
			('www.acme.example', out['scan_id'])])

	def test_a_late_stage_failure_keeps_the_hosts_it_found_current(self):
		full = self.scan(names=['www.acme.example'])
		_, kwargs = _stages()
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'), \
				mock.patch('cveFeed.triage.run_for_scan', side_effect=RuntimeError('boom')):
			out = discovery.run_host_pipeline(self.domain.id, ['new.acme.example'], **kwargs)
		self.assertEqual(out['failed_stages'], ['triage'])
		self.assertEqual(self.current(), [('new.acme.example', out['scan_id']), ('www.acme.example', full.id)])

	def test_new_hosts_from_a_host_pipeline_join_the_full_scan(self):
		full = self.scan(names=['www.acme.example'])
		ct = self.scan(tasks=HP, names=['new.acme.example'])
		self.assertEqual(self.current(), [('new.acme.example', ct.id), ('www.acme.example', full.id)])

	def test_a_later_full_discovery_supersedes_earlier_host_pipelines(self):
		self.scan(names=['www.acme.example'])
		self.scan(tasks=HP, names=['www.acme.example', 'old.acme.example'])
		latest = self.scan(names=['www.acme.example', 'api.acme.example'])
		self.assertEqual(self.current(), [('api.acme.example', latest.id), ('www.acme.example', latest.id)])

	def test_the_newest_host_pipeline_row_wins(self):
		self.scan(names=['www.acme.example'])
		self.scan(tasks=HP, names=['www.acme.example'])
		second = self.scan(tasks=HP, names=['www.acme.example'])
		self.assertEqual(self.current(), [('www.acme.example', second.id)])

	def test_failed_or_running_host_pipelines_do_not_count(self):
		full = self.scan(names=['www.acme.example', 'api.acme.example'])
		self.scan(status=0, tasks=HP, names=['www.acme.example'])
		self.scan(status=1, tasks=HP, names=['www.acme.example'])
		self.assertEqual(self.current(), [('api.acme.example', full.id), ('www.acme.example', full.id)])

	def test_a_domain_with_only_host_pipelines_lists_each_host_once(self):
		self.scan(tasks=HP, names=['www.acme.example', 'api.acme.example'])
		second = self.scan(tasks=HP, names=['www.acme.example'])
		names = [name for name, _ in self.current()]
		self.assertEqual(names, ['api.acme.example', 'www.acme.example'])
		self.assertIn(('www.acme.example', second.id), self.current())

	def test_before_first_successful_full_scan_only_newest_failed_copy_is_current(self):
		old = self.scan(status=0, names=['www.acme.example', 'old.acme.example'])
		newer = self.scan(status=0, names=['www.acme.example'])
		self.assertEqual(self.current(), [('old.acme.example', old.id), ('www.acme.example', newer.id)])

	def test_a_scanned_host_supersedes_its_scanless_discovery_row(self):
		Subdomain.objects.create(name='www.acme.example', target_domain=self.domain)
		partial = self.scan(tasks=HP, names=['www.acme.example'])
		self.assertEqual(self.current(), [('www.acme.example', partial.id)])

	def test_scanless_rediscovery_survives_when_latest_full_scan_omitted_host(self):
		self.scan(names=['www.acme.example'])
		self.scan(names=['other.acme.example'])
		rediscovered = Subdomain.objects.create(name='www.acme.example', target_domain=self.domain)
		self.assertIn(('www.acme.example', None), self.current())
		self.assertEqual([row for row in self.current() if row[0] == rediscovered.name], [(rediscovered.name, None)])

	def test_rows_without_a_scan_stay_current(self):
		self.scan(names=['www.acme.example'])
		Subdomain.objects.create(name='ct.acme.example', target_domain=self.domain, scan_history=None)
		self.assertIn('ct.acme.example', [name for name, _ in self.current()])

	def test_a_cve_match_on_another_host_survives_a_rescan(self):
		full = self.scan(names=['www.acme.example', 'api.acme.example'])
		api = Subdomain.objects.get(scan_history=full, name='api.acme.example')
		cve = CVEEntry.objects.create(cve_id='CVE-2099-42', cvss=9.8, published_at=timezone.now())
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=api, confidence=0.9, matched_product='nginx')
		self.scan(tasks=HP, names=['www.acme.example'])
		self.assertTrue(CVEMatch.objects.filter(latest_scan_q('subdomain__'), pk=match.pk).exists())
