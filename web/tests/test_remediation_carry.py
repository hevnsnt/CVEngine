from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class CarryRemediationTests(TestCase):
	"""A decision a person made about a finding survives the next scan, which stores the host (and so its matches) again."""

	def setUp(self):
		org = Org.objects.create(name='C', slug='c')
		project = Project.objects.create(name='C', slug='carry', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='carry.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scans = [ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, tasks=[],
												 results_dir='x') for _ in range(2)]
		self.old = Subdomain.objects.create(name='www.carry.test', target_domain=self.domain, scan_history=self.scans[0])
		self.new = Subdomain.objects.create(name='www.carry.test', target_domain=self.domain, scan_history=self.scans[1])
		self.cve = CVEEntry.objects.create(cve_id='CVE-2018-16844', title='nginx HTTP/2', published_at=timezone.now())

	def worked(self, status='fixed', source='tech', product='nginx'):
		return CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.old, source=source, matched_product=product, remediation_status=status,
									   remediation_note='patched by ops')

	def row(self, source='tech', product='nginx'):
		return {'cve_entry_id': self.cve.id, 'subdomain_id': self.new.id, 'source': source, 'matched_product': product, 'matched_version': '1.14.0',
				'version_in_range': True, 'confidence': 0.9, 'scan_history_id': self.scans[1].id, 'distro_status': 'no_data',
				'distro_fixed_version': '', 'evidence': {}}

	def test_the_same_finding_on_the_next_scan_keeps_the_decision(self):
		self.worked()
		correlation.save_matches([self.row()])
		match = CVEMatch.objects.get(subdomain=self.new)
		self.assertEqual((match.remediation_status, match.remediation_note), ('fixed', 'patched by ops'))

	def test_a_different_product_label_for_the_same_cve_on_the_same_host_keeps_the_decision(self):
		self.worked(product='nginx')
		correlation.save_matches([self.row(product='NGINX Open Source')])  # the feed now names the product another way
		self.assertEqual(CVEMatch.objects.get(subdomain=self.new).remediation_status, 'fixed')

	def test_another_source_for_the_same_cve_on_the_same_host_keeps_the_decision(self):
		self.worked(source='tech')
		correlation.save_matches([self.row(source='port')])
		self.assertEqual(CVEMatch.objects.get(subdomain=self.new).remediation_status, 'fixed')

	def test_the_newest_decision_wins(self):
		self.worked(status='accepted_risk', product='nginx')
		self.worked(status='fixed', product='NGINX Plus')
		correlation.save_matches([self.row(product='something else')])
		self.assertEqual(CVEMatch.objects.get(subdomain=self.new).remediation_status, 'fixed')

	def test_reopening_the_latest_scan_match_survives_another_scan(self):
		self.worked()
		correlation.save_matches([self.row()])
		reopened_at = timezone.now()
		CVEMatch.objects.filter(subdomain=self.new).update(remediation_status='open', remediation_note='reopened after verification',
			remediation_updated_at=reopened_at)
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.scans[1].scan_type,
			start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='x')
		sub = Subdomain.objects.create(name=self.new.name, target_domain=self.domain, scan_history=scan)
		row = {**self.row(), 'subdomain_id': sub.id, 'scan_history_id': scan.id}
		correlation.save_matches([row])
		match = CVEMatch.objects.get(subdomain=sub)
		self.assertEqual((match.remediation_status, match.remediation_note, match.remediation_updated_at),
			('open', 'reopened after verification', reopened_at))

	def test_an_open_decision_and_note_survive_a_changed_product_label(self):
		self.worked(status='fixed', product='nginx')
		latest = self.worked(status='open', product='NGINX Plus')
		latest.remediation_note = 'reopened by ops'
		latest.save(update_fields=['remediation_note'])
		correlation.save_matches([self.row(product='NGINX Open Source')])
		match = CVEMatch.objects.get(subdomain=self.new)
		self.assertEqual((match.remediation_status, match.remediation_note), ('open', 'reopened by ops'))

	def test_a_decision_about_another_cve_or_host_is_not_inherited(self):
		other = CVEEntry.objects.create(cve_id='CVE-2099-1', title='other', published_at=timezone.now())
		CVEMatch.objects.create(cve_entry=other, subdomain=self.old, source='tech', matched_product='nginx', remediation_status='fixed')
		elsewhere = Subdomain.objects.create(name='api.carry.test', target_domain=self.domain, scan_history=self.scans[0])
		CVEMatch.objects.create(cve_entry=self.cve, subdomain=elsewhere, source='tech', matched_product='nginx', remediation_status='fixed')
		correlation.save_matches([self.row()])
		self.assertEqual(CVEMatch.objects.get(subdomain=self.new).remediation_status, 'open')
