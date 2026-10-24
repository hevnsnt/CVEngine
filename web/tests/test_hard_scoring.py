from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, retest, scoring
from cveFeed.models import AssetChange, CVEEntry, CVEMatch
from cveFeed.tasks import correlate_cves
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain


class Fixture(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='A', slug='a')
		self.project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='score.test', project=self.project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-80', kev=True, cvss=9.8, published_at=timezone.now(), affected=[
			{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])

	def scan(self, status):
		return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=status, start_scan_date=timezone.now())

	def host(self, scan, name='www.score.test', match=False):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
		if match:
			CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', confidence=0.9,
				version_in_range=True, ai_verdict='affected', source='port')
		return sub

	def score_of(self, sub):
		return Subdomain.objects.get(pk=sub.pk).score


class PartialRowTests(Fixture):
	"""Verdict 3: scoring reads the host's real row, never a partial one from a failed, aborted or queued scan."""

	def test_a_newer_failed_scan_row_does_not_drop_the_score(self):
		good = self.host(self.scan(2), match=True)
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		fire = self.score_of(good)
		self.assertGreater(fire, 0)
		partial = self.host(self.scan(0))  # a failed run: the name only, no ports, findings or matches
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		self.assertEqual(self.score_of(good), fire)
		self.assertEqual(self.score_of(partial), fire)  # stored on every row of the name, so the sort is consistent

	def test_aborted_and_queued_rows_are_ignored_too(self):
		good = self.host(self.scan(2), match=True)
		for status in (3, -1):
			self.host(self.scan(status))
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		self.assertGreater(self.score_of(good), 0)

	def test_the_source_scans_row_is_preferred(self):
		old = self.scan(2)
		self.host(old, match=True)
		new = self.scan(2)
		quiet = self.host(new)  # the newest finished scan saw nothing on the host
		scoring.rescore_hosts(self.project.id, ['www.score.test'], scan_id=old.id)
		self.assertGreater(self.score_of(quiet), 0)  # scored from old's row (the scan asked for)
		scoring.rescore_hosts(self.project.id, ['www.score.test'], scan_id=new.id)
		self.assertEqual(self.score_of(quiet), scoring.score_host({'cves': [], 'findings': [], 'routes': [], 'public_ip': False, 'recent': ()})[0])

	def test_without_a_scan_the_newest_finished_row_beats_a_newer_running_one(self):
		good = self.host(self.scan(2), match=True)
		self.host(self.scan(1))
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		self.assertGreater(self.score_of(good), 0)

	def test_a_first_scan_still_running_is_scored_from_what_it_has(self):
		running = self.host(self.scan(1), match=True)
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		self.assertGreater(self.score_of(running), 0)

	def test_scan_less_rows_are_usable(self):
		ct = self.host(None, match=True)
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		self.assertGreater(self.score_of(ct), 0)


class RetestOrderTests(Fixture):
	def test_a_failed_scans_zero_score_does_not_push_a_fire_host_back(self):
		source = self.scan(2)
		self.host(source, 'fire.score.test', match=True)
		self.host(source, 'calm.score.test')
		scoring.rescore_hosts(self.project.id, ['fire.score.test', 'calm.score.test'])
		self.host(self.scan(0), 'fire.score.test')  # partial row, score 0
		Subdomain.objects.filter(scan_history__scan_status=0).update(score=0)
		for host in ('calm.score.test', 'fire.score.test'):
			AssetChange.objects.create(project=self.project, domain=self.domain, scan=source, host=host, kind='host_new')
		self.assertEqual(retest.hosts_to_retest(source), ['fire.score.test', 'calm.score.test'])


class VerdictResetRescoreTests(Fixture):
	"""Verdict 12: resetting a verdict (or closing a match) moves the host's score with it."""

	def correlate(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		return correlate_cves()

	def setUp(self):
		super().setUp()
		scan = self.scan(2)
		self.sub = Subdomain.objects.create(name='www.score.test', target_domain=self.domain, scan_history=scan)
		ip = IpAddress.objects.create(address='198.51.100.80')
		self.sub.ip_addresses.add(ip)
		self.port = Port.objects.create(number=80, product='nginx', version='1.18.0')
		ip.ports.add(self.port)

	def test_a_reset_verdict_triggers_a_rescore_of_the_host(self):
		self.correlate()
		CVEMatch.objects.update(ai_verdict='affected', ai_reason='x', ai_model='m')
		self.port.version = '1.19.0'
		self.port.save()
		with mock.patch('cveFeed.scoring.rescore_subdomain_ids') as rescore:
			self.correlate()
		rescore.assert_called_once_with({self.sub.id})
		self.assertEqual(CVEMatch.objects.get().ai_verdict, '')

	def test_a_closed_match_triggers_a_rescore_and_the_score_loses_its_exposure(self):
		self.correlate()
		CVEMatch.objects.update(ai_verdict='affected', ai_reason='x', ai_model='m')
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		before = self.score_of(self.sub)
		self.assertGreater(before, 0)
		self.port.version = '1.26.0'  # out of range: the match is closed
		self.port.save()
		self.correlate()
		self.assertFalse(CVEMatch.objects.exclude(ai_verdict='not_affected').exists())  # closed, kept for the audit trail
		self.assertLess(self.score_of(self.sub), before)

	def test_an_unchanged_match_does_not_rescore(self):
		self.correlate()
		with mock.patch('cveFeed.scoring.rescore_subdomain_ids') as rescore:
			self.correlate()
		rescore.assert_not_called()

	def test_a_scoring_failure_never_breaks_correlation(self):
		self.correlate()
		self.port.version = '1.26.0'
		self.port.save()
		with mock.patch('cveFeed.scoring.rescore_quietly', side_effect=RuntimeError('boom')):
			self.correlate()  # rescore_subdomain_ids swallows it
		self.assertFalse(CVEMatch.objects.exclude(ai_verdict='not_affected').exists())  # closed, kept for the audit trail
