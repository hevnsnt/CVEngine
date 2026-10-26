from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import correlation
from cveFeed.models import CVEEntry, CVEMatch
from cveFeed.tasks import correlate_cves
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain

NGINX = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


class CorrelationPerfTests(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='perf.test', project=project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, cvss=9.8, published_at=timezone.now(),
			affected=NGINX, raw={'big': 'x' * 1000})

	def _scan(self, status=2):
		return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=status,
			start_scan_date=timezone.now())

	def _host(self, name, scan, tech=None, product=None, version='1.18.0'):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
		if tech:
			sub.technologies.add(Technology.objects.get_or_create(name=f'{tech}:{version}')[0])
		if product:
			ip = IpAddress.objects.create(address=f'192.0.2.{sub.id % 250}')
			sub.ip_addresses.add(ip)
			ip.ports.add(Port.objects.create(number=80, product=product, version=version))
		return sub

	def test_index_is_built_once_across_two_calls(self):
		self._host('a.perf.test', self._scan(), tech='nginx')
		with mock.patch.object(correlation, 'build_product_index', wraps=correlation.build_product_index) as build:
			correlate_cves()
			correlate_cves()
			self.assertEqual(build.call_count, 1)
			CVEEntry.objects.filter(pk=self.cve.pk).update(synced_at=timezone.now())  # a re-sync moves the key
			correlate_cves()
			self.assertEqual(build.call_count, 2)

	def test_pool_never_loads_raw(self):
		by_id, _ = correlation.cve_pool()
		self.assertIn('raw', by_id[self.cve.id].get_deferred_fields())

	def test_only_hosts_with_a_matching_product_are_correlated(self):
		scan = self._scan()
		nginx = self._host('web.perf.test', scan, tech='nginx')
		port = self._host('svc.perf.test', scan, product='nginx')
		self._host('other.perf.test', scan, tech='postgresql')
		self._host('bare.perf.test', scan)
		_, index = correlation.cve_pool()
		self.assertEqual(set(correlation.candidate_subdomains(index).values_list('id', flat=True)), {nginx.id, port.id})
		out = correlate_cves()
		self.assertEqual(out['subdomains'], 2)
		self.assertEqual(set(CVEMatch.objects.values_list('subdomain_id', flat=True)), {nginx.id, port.id})

	def test_only_the_latest_successful_scan_and_ct_rows_are_correlated(self):
		old, new, failed = self._scan(), self._scan(), self._scan(status=0)
		self._host('web.perf.test', old, tech='nginx')
		latest = self._host('web.perf.test', new, tech='nginx')
		self._host('web.perf.test', failed, tech='nginx')
		ct = self._host('ct.perf.test', None, tech='nginx')
		correlate_cves()
		self.assertEqual(set(CVEMatch.objects.values_list('subdomain_id', flat=True)), {latest.id, ct.id})

	def test_query_count_does_not_grow_with_the_number_of_hosts(self):
		scan = self._scan()
		self._host('h0.perf.test', scan, tech='nginx')
		correlate_cves()  # warm the index cache and create the first match
		def queries():
			with CaptureQueriesContext(connection) as ctx:
				correlate_cves()
			return len(ctx)
		small = queries()
		for i in range(1, 30):
			self._host(f'h{i}.perf.test', scan, tech='nginx')
		with CaptureQueriesContext(connection) as ctx:
			out = correlate_cves()
		self.assertEqual(out['matches'], 30)
		self.assertEqual(CVEMatch.objects.count(), 30)
		self.assertLessEqual(len(ctx), small + 4)  # a few more statements for the new rows, nowhere near one per host
		self.assertLess(len(ctx), 30)

	def test_rerun_keeps_ai_verdict_and_does_not_touch_unchanged_rows(self):
		self._host('web.perf.test', self._scan(), tech='nginx')
		correlate_cves()
		CVEMatch.objects.update(ai_verdict='affected')
		stamp = CVEMatch.objects.get().updated_at
		correlate_cves()
		match = CVEMatch.objects.get()
		self.assertEqual(match.ai_verdict, 'affected')
		self.assertEqual(match.updated_at, stamp)


class PartialScanInventoryTests(CorrelationPerfTests):
	def test_a_host_pipeline_scan_of_one_host_does_not_hide_the_rest_of_the_inventory(self):
		from cveFeed.discovery import HOST_PIPELINE_TASK
		full = self._scan()
		a_old = self._host('a.perf.test', full, tech='nginx')
		b = self._host('b.perf.test', full, tech='nginx')
		partial = self._scan()
		ScanHistory.objects.filter(pk=partial.pk).update(tasks=[HOST_PIPELINE_TASK])
		a_new = self._host('a.perf.test', partial, tech='nginx')
		_, index = correlation.cve_pool()
		ids = set(correlation.candidate_subdomains(index).values_list('id', flat=True))
		self.assertEqual(ids, {b.id, a_new.id})  # b stays; a's newest row wins over the older copy
		self.assertNotIn(a_old.id, ids)
		self.assertEqual(correlate_cves()['subdomains'], 2)


class PatchLetterVersionTests(TestCase):
	def test_openssl_patch_letters_order_versions(self):
		from cveFeed.correlation import parse_version, version_in_range
		rng = {'introduced': '1.1.1', 'fixed': '1.1.1n'}
		self.assertTrue(parse_version('1.1.1k') < parse_version('1.1.1n') < parse_version('1.1.1za'))
		self.assertTrue(version_in_range(parse_version('1.1.1k'), rng))
		self.assertFalse(version_in_range(parse_version('1.1.1n'), rng))
		self.assertFalse(version_in_range(parse_version('1.1.1w'), rng))
		self.assertTrue(version_in_range(parse_version('1.1.1'), rng))
		self.assertFalse(version_in_range(parse_version('1.0.2zh'), {'introduced': '1.0.2', 'fixed': '1.0.2zf'}))
		self.assertEqual(parse_version('8.9p1'), (8, 9))  # OpenSSH's p is not a patch letter

	def test_cve_list_wildcards_name_a_whole_branch(self):
		from cveFeed import intel
		ranges = intel._ranges({'versions': [
			{'version': '2.3.x', 'status': 'affected'},
			{'version': '0', 'lessThanOrEqual': '3.1.x', 'status': 'affected'},
			{'version': '1.0', 'lessThan': '1.5.x', 'status': 'affected'}]})
		self.assertEqual([(r.get('introduced'), r.get('fixed')) for r in ranges], [('2.3', '2.4'), (None, '3.2'), ('1.0', '1.5')])
		from cveFeed.correlation import parse_version, version_in_range
		self.assertTrue(version_in_range(parse_version('2.3.9'), ranges[0]))
		self.assertFalse(version_in_range(parse_version('2.4.0'), ranges[0]))
