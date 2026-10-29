from datetime import timedelta
import itertools
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import correlation
from cveFeed.autofire import confirm_matches, fire_for_cve, hot_cves_without_run
from cveFeed.models import AutoFireRun, CVEEntry, CVEMatch, MatchVerdict
from cveFeed.threat import FIRE, SMOKE, classify_threat_tier, hot_tier_q
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain

NGINX = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


def _provider(classification='likely'):
	provider = mock.Mock(model='m')
	provider.name = 'fake'
	provider.complete.return_value = ('{"classification": "%s", "reason": "banner matches", "impact": "", "severity_adjust": 0, '
									  '"severity_reason": "", "remediation": "", "validation_steps": []}' % classification)
	return provider


class HotCveSelectionTests(TestCase):
	def test_the_database_tier_filter_agrees_with_the_classifier(self):
		combos = itertools.product((None, True, False), (None, True, False), (None, True, False), (None, 0.0, 6.9, 7.0, 8.9, 9.0, 10.0))
		for n, (kev, epss, edb, cvss) in enumerate(combos):
			CVEEntry.objects.create(cve_id=f'CVE-2099-{n}', kev=kev, epss_reached=epss, exploit_db=edb, cvss=cvss, affected=[])
		hot_ids = set(CVEEntry.objects.filter(hot_tier_q()).values_list('id', flat=True))
		for entry in CVEEntry.objects.all():
			tier = classify_threat_tier(kev=entry.kev, epss_reached=entry.epss_reached, exploit_db=entry.exploit_db, cvss=entry.cvss)
			self.assertEqual(entry.id in hot_ids, tier in (FIRE, SMOKE), entry)

	def test_only_unfired_hot_cves_come_back_in_one_query(self):
		fire = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, affected=[])
		smoke = CVEEntry.objects.create(cve_id='CVE-2099-2', cvss=7.5, affected=[])
		CVEEntry.objects.create(cve_id='CVE-2099-3', cvss=3.0, affected=[])  # ice
		done = CVEEntry.objects.create(cve_id='CVE-2099-4', kev=True, affected=[])
		AutoFireRun.objects.create(cve_entry=done, tier='fire')
		with CaptureQueriesContext(connection) as ctx:
			found = hot_cves_without_run()
			tiers = [c.threat_tier for c in found]
		self.assertEqual({c.id for c in found}, {fire.id, smoke.id})
		self.assertEqual(len(ctx), 1)  # classifying the rows loads nothing more
		self.assertEqual(sorted(tiers), [FIRE, SMOKE])

	def test_a_run_that_errored_is_tried_again_for_two_days_then_left_alone(self):
		failed = CVEEntry.objects.create(cve_id='CVE-2099-5', kev=True, affected=[])
		stale = CVEEntry.objects.create(cve_id='CVE-2099-6', kev=True, affected=[])
		empty = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, affected=[])
		AutoFireRun.objects.create(cve_entry=failed, tier='fire', status='error', error='provider down')
		old = AutoFireRun.objects.create(cve_entry=stale, tier='fire', status='error')
		AutoFireRun.objects.filter(pk=old.pk).update(created_at=timezone.now() - timedelta(hours=49))
		AutoFireRun.objects.create(cve_entry=empty, tier='fire', status='no_targets')
		self.assertEqual({c.id for c in hot_cves_without_run()}, {failed.id})

	def test_firing_again_reuses_the_errored_row(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2099-8', kev=True, affected=[])
		AutoFireRun.objects.create(cve_entry=cve, tier='fire', status='error', error='boom')
		run = fire_for_cve(cve, test_dispatcher=lambda *a: None)
		self.assertEqual(AutoFireRun.objects.filter(cve_entry=cve).count(), 1)
		self.assertEqual((run.status, run.error), ('no_targets', ''))


class MemoisedConfirmTests(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		now = timezone.now()
		project = Project.objects.create(name='M', slug='pm', insert_date=now, org=Org.objects.create(name='M', slug='m'))
		self.domain = Domain.objects.create(name='memo.test', project=project, insert_date=now)
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-9', kev=True, cvss=9.8, published_at=now, affected=NGINX)

	def _host(self, name, version='1.18.0'):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain)
		ip = IpAddress.objects.create(address=f'192.0.2.{sub.id % 250}')
		sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=80, product='nginx', version=version))
		return sub

	def _correlate(self):
		correlation.correlate_subdomains(
			correlation.candidate_subdomains(correlation.build_product_index([self.cve])),
			correlation.build_product_index([self.cve]), {self.cve.id: self.cve}, min_confidence=0.4)

	def test_one_question_for_many_hosts_with_the_same_signature(self):
		for i in range(10):
			self._host(f'h{i}.memo.test')
		self._host('old.memo.test', version='1.19.2')  # a different version is a different question
		self._correlate()
		provider = _provider()
		matches = list(CVEMatch.objects.filter(cve_entry=self.cve).select_related('subdomain'))
		self.assertEqual(confirm_matches(matches, self.cve, provider=provider), 2)
		self.assertEqual(provider.complete.call_count, 2)
		self.assertEqual(set(CVEMatch.objects.values_list('ai_verdict', flat=True)), {'affected'})
		self.assertEqual(MatchVerdict.objects.count(), 2)

	def test_a_later_correlation_reuses_the_stored_verdict_without_asking(self):
		self._host('a.memo.test')
		self._correlate()
		provider = _provider()
		confirm_matches(list(CVEMatch.objects.select_related('subdomain')), self.cve, provider=provider)
		self._host('b.memo.test')  # a new host with the same product and version appears later
		self._correlate()
		matches = list(CVEMatch.objects.filter(cve_entry=self.cve).select_related('subdomain'))
		self.assertEqual(len(matches), 2)
		self.assertEqual({m.ai_verdict for m in matches}, {'affected'})
		self.assertEqual(confirm_matches(matches, self.cve, provider=provider), 0)
		self.assertEqual(provider.complete.call_count, 1)

	def test_no_provider_stores_nothing(self):
		self._host('a.memo.test')
		self._correlate()
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
			confirm_matches(list(CVEMatch.objects.select_related('subdomain')), self.cve)
		self.assertEqual(MatchVerdict.objects.count(), 0)

	def test_the_host_cap_limits_how_many_hosts_are_tested(self):
		for i in range(6):
			self._host(f'h{i}.memo.test')
		calls = []
		run = fire_for_cve(self.cve, max_hosts=4, provider=_provider(), test_dispatcher=lambda *a: calls.append(a))
		self.assertEqual(run.matches_found, 6)
		self.assertEqual(len(calls[0][1]), 4)
		self.assertEqual(run.targets, ['memo.test'])
