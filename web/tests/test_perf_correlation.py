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
		self.assertEqual(parse_version('8.9p1'), (8, 9, 0, 1))  # OpenSSH's p1 is a patch level after the release, not a letter

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


class MalformedAffectedTests(CorrelationPerfTests):
	def test_a_malformed_affected_entry_does_not_stop_correlation_of_the_rest(self):
		self._host('web.perf.test', self._scan(), tech='nginx')
		CVEEntry.objects.create(cve_id='CVE-2099-2', published_at=timezone.now(),
			affected=['junk', None, {'product': 'nginx', 'ranges': 'not-a-list'}, {'product': 'nginx', 'ranges': [None, 5, {'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		correlation._INDEX_CACHE.update(key=None, value=None)
		out = correlate_cves()
		self.assertEqual(out['subdomains'], 1)
		self.assertTrue(CVEMatch.objects.filter(cve_entry__cve_id='CVE-2099-1').exists())

	def test_from_api_stores_clean_shapes(self):
		obj, _ = CVEEntry.from_api({'id': 'CVE-2099-3', 'severity': [], 'exploitation': 'x', 'affected': 'nope', 'references': {}, 'sources': 3})
		self.assertEqual((obj.affected, obj.references, obj.sources), ([], [], []))
		obj, _ = CVEEntry.from_api({'id': 'CVE-2099-4', 'affected': [{'product': 'p', 'ranges': [1, {'fixed': '2'}]}, 'x']})
		self.assertEqual(obj.affected, [{'product': 'p', 'ranges': [{'fixed': '2'}]}])


class StrongestSightingTests(CorrelationPerfTests):
	def test_the_strongest_of_two_sightings_is_kept_not_the_last(self):
		sub = self._host('web.perf.test', self._scan(), tech='nginx')
		base = dict(cve_entry_id=self.cve.id, subdomain_id=sub.id, source='correlation', matched_product='nginx',
					confidence=0.5, scan_history_id=sub.scan_history_id, distro_status='', distro_fixed_version='', evidence={})
		rows = [{**base, 'matched_version': '1.18.0', 'version_in_range': True},
				{**base, 'matched_version': '1.25.0', 'version_in_range': False}]
		for ordered in (rows, rows[::-1]):
			CVEMatch.objects.all().delete()
			correlation.save_matches(ordered)
			self.assertTrue(CVEMatch.objects.get().version_in_range)


class CpeAndNameSpellingTests(TestCase):
	def test_a_cpe_does_not_hide_records_that_spell_the_product_their_own_way(self):
		from types import SimpleNamespace as NS
		nvd = NS(id=1, cve_id='CVE-A', kev=False, affected=[{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.54'}]}])
		cna = NS(id=2, cve_id='CVE-B', kev=False, affected=[{'vendor': 'Apache', 'product': 'Apache HTTP Server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.55'}]}])
		log4j = NS(id=3, cve_id='CVE-C', kev=False, affected=[{'vendor': 'Apache', 'product': 'Log4j', 'ranges': [{'introduced': '2.0', 'fixed': '2.17'}]}])
		other_vendor = NS(id=4, cve_id='CVE-D', kev=False, affected=[{'vendor': 'Acme', 'product': 'Apache HTTP Server', 'ranges': [{'fixed': '9'}]}])
		pool = {c.id: c for c in (nvd, cna, log4j, other_vendor)}
		index = correlation.build_product_index(pool.values())
		token = correlation._norm('Apache httpd')
		with mock.patch.object(correlation, '_is_ice', return_value=False):
			found = {cve.cve_id: in_range for cve, _p, in_range in correlation._match_candidates(
				'Apache httpd', (2, 4, 52), token, index, pool, cpe='cpe:/a:apache:http_server:2.4.52')}
		self.assertEqual(found.get('CVE-A'), True)
		self.assertEqual(found.get('CVE-B'), True)  # named "Apache HTTP Server" by the CNA: found although an NVD-style record exists
		self.assertNotIn('CVE-C', found)  # another Apache product
		self.assertNotIn('CVE-D', found)  # another vendor's product of the same name

	def test_a_bare_nmap_name_finds_the_cna_spelling_too(self):
		from types import SimpleNamespace as NS
		cna = NS(id=2, cve_id='CVE-B', kev=False, affected=[{'vendor': 'Apache', 'product': 'Apache HTTP Server', 'ranges': [{'fixed': '2.4.55'}]}])
		pool = {2: cna}
		index = correlation.build_product_index(pool.values())
		with mock.patch.object(correlation, '_is_ice', return_value=False):
			found = [c.cve_id for c, _p, r in correlation._match_candidates('Apache httpd', (2, 4, 52), correlation._norm('Apache httpd'), index, pool)]
		self.assertEqual(found, ['CVE-B'])


class TextualRangeTests(TestCase):
	def test_ranges_written_in_the_version_field_keep_both_ends(self):
		from cveFeed import intel
		ranges = intel._ranges({'versions': [{'version': '2.0 through 2.3', 'status': 'affected'}, {'version': 'before 1.5', 'status': 'affected'},
											 {'version': '3.1 and earlier', 'status': 'affected'}, {'version': '1.2.3', 'status': 'affected'}]})
		self.assertEqual([(r.get('introduced'), r.get('fixed'), r.get('lastAffected')) for r in ranges],
						 [('2.0', None, '2.3'), (None, '1.5', None), (None, None, '3.1'), ('1.2.3', None, '1.2.3')])
		from cveFeed.correlation import parse_version, version_in_range
		self.assertTrue(version_in_range(parse_version('2.2.1'), ranges[0]))  # a host on 2.2.1 is inside "2.0 through 2.3"
		self.assertFalse(version_in_range(parse_version('2.4'), ranges[0]))


class ConfirmedMatchesStayOpenTests(CorrelationPerfTests):
	def test_a_nuclei_confirmed_match_is_not_closed_because_a_later_scan_no_longer_sees_the_product(self):
		sub = self._host('web.perf.test', self._scan(), tech='nginx')
		confirmed = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, source='tech', matched_product='nginx', template_result='vulnerable')
		plain = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-77', published_at=timezone.now(), affected=NGINX),
										subdomain=sub, source='tech', matched_product='nginx')
		correlation.save_matches([], covered=({sub.id}, {confirmed.cve_entry_id, plain.cve_entry_id}))  # the product was not seen this time
		confirmed.refresh_from_db()
		plain.refresh_from_db()
		self.assertNotEqual(confirmed.ai_verdict, 'not_affected')
		self.assertEqual(plain.ai_verdict, 'not_affected')


class VersionSpellingTests(TestCase):
	def test_portable_patch_levels_date_versions_and_the_mariadb_prefix(self):
		from cveFeed.correlation import parse_version, version_in_range
		self.assertTrue(parse_version('8.9p1') < parse_version('8.9p2') < parse_version('9.0'))
		self.assertTrue(version_in_range(parse_version('8.9p1'), {'introduced': '8.0', 'fixed': '8.9p2'}))  # p1 is still affected
		self.assertFalse(version_in_range(parse_version('8.9p2'), {'introduced': '8.0', 'fixed': '8.9p2'}))
		self.assertEqual(parse_version('1:8.9p1-3ubuntu0.6'), (8, 9, 0, 1))
		self.assertTrue(parse_version('2024-01-15') < parse_version('2024-02-10'))
		self.assertTrue(version_in_range(parse_version('2024-01-15'), {'fixed': '2024-02-10'}))
		self.assertEqual(parse_version('5.5.5-10.6.12-MariaDB'), (10, 6, 12))
		self.assertEqual(parse_version('5.7.38'), (5, 7, 38))


class RemediationCarriesToTheNextScanTests(CorrelationPerfTests):
	def test_what_a_person_decided_follows_the_host_to_its_next_scan(self):
		old_scan, new_scan = self._scan(), self._scan()
		old = self._host('web.perf.test', old_scan, tech='nginx')
		CVEMatch.objects.create(cve_entry=self.cve, subdomain=old, source='tech', matched_product='nginx', matched_version='1.18.0',
								remediation_status='accepted_risk', remediation_note='vendor says no', remediation_updated_at=timezone.now())
		new = self._host('web.perf.test', new_scan, tech='nginx')
		base = dict(cve_entry_id=self.cve.id, source='tech', matched_product='nginx', matched_version='1.18.0', version_in_range=True,
					confidence=0.9, scan_history_id=new_scan.id, distro_status='', distro_fixed_version='', evidence={})
		correlation.save_matches([{**base, 'subdomain_id': new.id}])
		row = CVEMatch.objects.get(subdomain=new)
		self.assertEqual((row.remediation_status, row.remediation_note), ('accepted_risk', 'vendor says no'))

	def test_a_host_with_no_earlier_decision_starts_open(self):
		scan = self._scan()
		sub = self._host('fresh.perf.test', scan, tech='nginx')
		base = dict(cve_entry_id=self.cve.id, source='tech', matched_product='nginx', matched_version='1.18.0', version_in_range=True,
					confidence=0.9, scan_history_id=scan.id, distro_status='', distro_fixed_version='', evidence={})
		correlation.save_matches([{**base, 'subdomain_id': sub.id}])
		self.assertEqual(CVEMatch.objects.get(subdomain=sub).remediation_status, 'open')


class FindingStateCarriesTests(CorrelationPerfTests):
	def test_a_nuclei_finding_seen_again_on_the_next_scan_keeps_its_remediation_state(self):
		from reNgine.tasks import save_vulnerability
		from startScan.models import Vulnerability
		old_scan, new_scan = self._scan(), self._scan()
		old_sub = self._host('web.perf.test', old_scan)
		first = Vulnerability.objects.create(name='Exposed panel', severity=3, subdomain=old_sub, target_domain=self.domain, scan_history=old_scan,
											 source='nuclei', template_id='panel', http_url='https://web.perf.test/admin', matcher_name='',
											 remediation_status='fixed', remediation_note='patched', discovered_date=timezone.now())
		new_sub = self._host('web.perf.test', new_scan)
		save_vulnerability(name='Exposed panel', severity=3, subdomain=new_sub, target_domain=self.domain, scan_history=new_scan, source='nuclei',
						   template_id='panel', http_url='https://web.perf.test/admin', matcher_name='')
		again = Vulnerability.objects.get(scan_history=new_scan)
		self.assertNotEqual(again.pk, first.pk)
		self.assertEqual((again.remediation_status, again.remediation_note), ('fixed', 'patched'))
