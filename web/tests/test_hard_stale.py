from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation
from cveFeed.models import CVEEntry, CVEMatch, MatchVerdict
from cveFeed.tasks import correlate_cves
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain

NGINX = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


class StaleMatchTests(TestCase):
	"""Review 1.4: a match whose version moved out of range, or whose product is gone, is closed; a changed signature is re-judged."""

	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='stale.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.stale.test', target_domain=self.domain, scan_history=scan)
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, cvss=9.8, published_at=timezone.now(), affected=NGINX)
		self.ip = IpAddress.objects.create(address='192.0.2.50')
		self.sub.ip_addresses.add(self.ip)

	def assertClosed(self, matches):
		"""A match the host no longer supports is closed (not_affected, with the automatic reason), kept for the audit trail."""
		self.assertTrue(matches.exists())
		for match in matches:
			self.assertEqual(match.ai_verdict, 'not_affected')
			self.assertTrue(match.ai_reason.startswith('Closed automatically:'), match.ai_reason)

	def _correlate(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		return correlate_cves()

	def _port(self, product='nginx', version='1.18.0'):
		self.ip.ports.clear()
		port = Port.objects.create(number=80, product=product, version=version)
		self.ip.ports.add(port)
		return port

	def test_a_version_that_moves_out_of_range_closes_the_match(self):
		port = self._port(version='1.18.0')
		self._correlate()
		self.assertEqual(CVEMatch.objects.filter(subdomain=self.sub).count(), 1)
		port.version = '1.26.0'
		port.save()
		self._correlate()
		self.assertClosed(CVEMatch.objects.filter(subdomain=self.sub))

	def test_a_host_whose_product_changed_is_still_walked_and_its_match_closed(self):
		self._port(product='nginx', version='1.18.0')
		self._correlate()
		self._port(product='caddy', version='2.7.0')  # nothing in the CVE index names caddy any more
		self._correlate()
		self.assertClosed(CVEMatch.objects.filter(subdomain=self.sub))

	def test_a_technology_version_out_of_range_closes_the_match(self):
		self.sub.technologies.add(Technology.objects.create(name='nginx:1.18.0'))
		self._correlate()
		self.assertEqual(CVEMatch.objects.filter(subdomain=self.sub, source='tech').count(), 1)
		self.sub.technologies.clear()
		self.sub.technologies.add(Technology.objects.create(name='nginx:1.26.0'))
		self._correlate()
		self.assertClosed(CVEMatch.objects.filter(subdomain=self.sub))

	def test_a_match_a_person_worked_is_kept_closed_not_deleted(self):
		port = self._port()
		self._correlate()
		CVEMatch.objects.filter(subdomain=self.sub).update(remediation_status='accepted_risk', remediation_note='ticket 42')
		port.version = '1.26.0'
		port.save()
		self._correlate()
		match = CVEMatch.objects.get(subdomain=self.sub)
		self.assertEqual((match.ai_verdict, match.confidence, match.remediation_status, match.remediation_note),
			('not_affected', 0.0, 'accepted_risk', 'ticket 42'))
		self.assertIn('no longer matches', match.ai_reason)

	def test_a_cve_outside_the_pool_is_not_closed_by_a_limited_pass(self):
		self._port()
		other = CVEEntry.objects.create(cve_id='CVE-2099-2', kev=True, cvss=9.8, published_at=timezone.now() - timezone.timedelta(days=9),
			affected=NGINX)
		self._correlate()
		self.assertEqual(CVEMatch.objects.filter(subdomain=self.sub).count(), 2)
		correlation._INDEX_CACHE.update(key=None, value=None)
		correlate_cves(cve_limit=1)  # only the newest CVE is in this pass's pool
		self.assertEqual(CVEMatch.objects.filter(subdomain=self.sub).count(), 2)
		self.assertTrue(CVEMatch.objects.filter(cve_entry=other).exists())

	def test_a_changed_version_clears_the_old_verdict(self):
		port = self._port(version='1.18.0')
		self._correlate()
		CVEMatch.objects.filter(subdomain=self.sub).update(ai_verdict='affected', ai_reason='nginx 1.18 is in range', ai_model='m')
		port.version = '1.19.0'  # still affected, but a different signature than the one the AI judged
		port.save()
		self._correlate()
		match = CVEMatch.objects.get(subdomain=self.sub)
		self.assertEqual((match.matched_version, match.version_in_range), ('1.19.0', True))
		self.assertEqual((match.ai_verdict, match.ai_reason, match.ai_model), ('', '', ''))

	def test_a_changed_version_takes_the_stored_verdict_of_the_new_signature(self):
		port = self._port(version='1.18.0')
		self._correlate()
		MatchVerdict.objects.create(cve_entry=self.cve, matched_product='nginx', matched_version='1.19.0', version_in_range=True,
			source='port', ai_verdict='uncertain', ai_reason='known', ai_model='m')
		CVEMatch.objects.filter(subdomain=self.sub).update(ai_verdict='affected', ai_reason='old', ai_model='m')
		port.version = '1.19.0'
		port.save()
		self._correlate()
		self.assertEqual(CVEMatch.objects.get(subdomain=self.sub).ai_verdict, 'uncertain')

	def test_an_unchanged_signature_keeps_its_verdict(self):
		self._port(version='1.18.0')
		self._correlate()
		CVEMatch.objects.filter(subdomain=self.sub).update(ai_verdict='affected', ai_reason='kept', ai_model='m')
		self._correlate()
		self.assertEqual(CVEMatch.objects.get(subdomain=self.sub).ai_verdict, 'affected')
