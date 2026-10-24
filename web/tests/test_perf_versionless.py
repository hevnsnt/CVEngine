from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation
from cveFeed.models import CVEEntry, CVEMatch
from cveFeed.tasks import correlate_cves
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Technology
from targetApp.models import Domain

NGINX = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


class VersionlessNoiseTests(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='V', slug='v')
		project = Project.objects.create(name='P', slug='pv', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='vless.test', project=project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=2,
			start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.vless.test', target_domain=self.domain, scan_history=self.scan)
		self.sub.technologies.add(Technology.objects.create(name='nginx'))  # no version captured

	def _cve(self, cid, affected=NGINX, **signals):
		return CVEEntry.objects.create(cve_id=cid, published_at=timezone.now(), affected=affected, **signals)

	def _matched(self):
		correlate_cves()
		return set(CVEMatch.objects.values_list('cve_entry__cve_id', flat=True))

	def test_ice_cve_with_ranges_is_dropped_but_fire_and_smoke_are_kept(self):
		self._cve('CVE-2099-10', cvss=3.0)  # ice
		self._cve('CVE-2099-11', kev=True)  # fire
		self._cve('CVE-2099-12', cvss=7.5)  # smoke
		self.assertEqual(self._matched(), {'CVE-2099-11', 'CVE-2099-12'})

	def test_ice_advisory_without_ranges_is_kept(self):
		self._cve('CVE-2099-13', affected=[{'product': 'nginx'}], cvss=3.0)
		self._cve('CVE-2099-14', affected=[{'product': 'nginx', 'ranges': [{}]}], cvss=3.0)
		self.assertEqual(self._matched(), {'CVE-2099-13', 'CVE-2099-14'})

	def test_a_known_version_in_range_is_kept_for_ice(self):
		self.sub.technologies.clear()
		self.sub.technologies.add(Technology.objects.create(name='nginx:1.18.0'))
		self._cve('CVE-2099-15', cvss=3.0)
		self.assertEqual(self._matched(), {'CVE-2099-15'})

	def test_at_equal_heat_in_range_matches_are_tested_first(self):
		from cveFeed import nuclei_scan, nuclei_templates
		unknown = self._cve('CVE-2099-16', cvss=8.0)
		in_range = self._cve('CVE-2099-17', cvss=7.1)
		CVEMatch.objects.create(cve_entry=unknown, subdomain=self.sub, matched_product='nginx', confidence=0.5,
			version_in_range=None)
		CVEMatch.objects.create(cve_entry=in_range, subdomain=self.sub, matched_product='nginx', confidence=0.9,
			version_in_range=True)
		asked = []
		runner = lambda cve, hosts, provider=None, project=None: asked.append(cve.cve_id) or {'results': []}
		with mock.patch.object(nuclei_templates, 'MAX_CVES_PER_HOST', 1):
			nuclei_scan.run_cve_checks(self.scan, [self.sub], None, cve_runner=runner)
		self.assertEqual(asked, ['CVE-2099-17'])
