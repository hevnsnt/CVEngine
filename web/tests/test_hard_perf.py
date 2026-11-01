import unittest
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, nuclei_scan, views
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class MemoTests(unittest.TestCase):
	"""Review 3.1: the fuzzy product lookup is resolved once per distinct token, not once per host."""

	def test_name_matching_is_bounded_by_distinct_tokens_not_hosts(self):
		cves = [SimpleNamespace(id=i, affected=[{'product': f'prod{i}', 'ranges': [{'fixed': '9'}]}], kev=False) for i in range(50)]
		index = correlation.build_product_index(cves)
		by_id = {c.id: c for c in cves}
		real = correlation.name_matches_token
		with mock.patch.object(correlation, 'name_matches_token', wraps=real) as spy:
			for _host in range(300):  # 300 hosts all running the same two products
				for name in ('prod7', 'nginx'):
					list(correlation._match_candidates(name, (1, 0), correlation._norm(name), index, by_id))
		first_pass = 2 * len(index)
		self.assertLessEqual(spy.call_count - 300 * 2 * 0, first_pass + 300 * 2 * 2)  # the memo, then only the matched candidates' own checks
		self.assertLess(spy.call_count, 300 * 2 * len(index) / 10)

	def test_a_plain_dict_index_still_works(self):
		cve = SimpleNamespace(id=1, affected=[{'product': 'nginx', 'ranges': [{'fixed': '9'}]}], kev=False)
		index = dict(correlation.build_product_index([cve]))
		self.assertEqual(len(list(correlation._match_candidates('nginx', (1,), 'nginx', index, {1: cve}))), 1)


class LedgerHoistTests(TestCase):
	def test_run_cve_checks_asks_the_ledger_once_per_cve_not_once_per_host(self):
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='h.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
		cve = CVEEntry.objects.create(cve_id='CVE-2099-3', kev=True, cvss=9.8, published_at=timezone.now())
		subs = [Subdomain.objects.create(name=f'h{i}.h.test', target_domain=domain, scan_history=scan) for i in range(25)]
		for sub in subs:
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', confidence=0.9, version_in_range=True)
		with mock.patch('cveFeed.ledger.fresh', return_value=set()) as fresh:
			out = nuclei_scan.run_cve_checks(scan, subs, None, cve_runner=lambda c, hosts, **kw: {'results': []})
		self.assertEqual(fresh.call_count, 1)
		self.assertEqual((out['hosts'], out['not_tested']), (0, 25))  # missing runner rows establish no coverage
