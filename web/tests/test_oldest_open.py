"""The age of the worst open item (cveFeed.counts.oldest_open), as the dashboard's Live counter strip reads it from /cve/api/stats."""
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from cveFeed import counts
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding
from startScan.models import ScanHistory, Subdomain, Vulnerability
from tests.test_counts import CountFixture


def ago(days):
	return timezone.now() - timedelta(days=days, hours=1)


class NothingOpenTests(TestCase):
	def test_no_data_is_null_everywhere(self):
		self.assertEqual(counts.oldest_open(), {'days': None, 'kind': None, 'id': None})


class OldestOpenTests(CountFixture):
	"""The fixture holds one critical match (CVE-2099-1, cvss 9), one ruled-out medium match, a high and a medium finding, and one medium
	hygiene finding; each test sets the ages."""

	def age_all(self, match=None, finding=None, hygiene=None):
		if match is not None:
			CVEMatch.objects.filter(pk=self.m_live.pk).update(created_at=ago(match))
		if finding is not None:
			Vulnerability.objects.filter(pk=self.high_b.pk).update(discovered_date=ago(finding))
		if hygiene is not None:
			HygieneFinding.objects.all().update(severity=4, first_seen=ago(hygiene))
			HygieneFinding.objects.all().update(first_seen=ago(hygiene))

	def test_the_oldest_of_the_three_sources_wins_and_says_which(self):
		self.age_all(match=10, finding=20, hygiene=5)
		self.assertEqual(counts.oldest_open(), {'days': 20, 'kind': 'scanner', 'id': self.high_b.pk})
		self.age_all(match=30)
		self.assertEqual(counts.oldest_open(), {'days': 30, 'kind': 'cve', 'id': self.m_live.pk})
		self.age_all(hygiene=45)
		hygiene = HygieneFinding.objects.get()
		self.assertEqual(counts.oldest_open(), {'days': 45, 'kind': 'hygiene', 'id': hygiene.pk})

	def test_whole_days_rounded_down(self):
		self.age_all(match=3)  # three days and an hour
		self.assertEqual(counts.oldest_open()['days'], 3)

	def test_a_match_counts_from_the_first_scan_that_held_it(self):
		self.age_all(match=60)  # the match of the first scan
		newer_scan = ScanHistory.objects.create(domain=self.da1, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now(), tasks=[])
		current = Subdomain.objects.create(target_domain=self.da1, name=self.live[0].name, scan_history=newer_scan)
		row = CVEMatch.objects.create(cve_entry=self.cve, subdomain=current, matched_product='nginx', confidence=.8)  # stored again by the next scan
		CVEMatch.objects.filter(pk=self.m_b.pk).update(remediation_status='fixed')
		result = counts.oldest_open()
		self.assertEqual((result['days'], result['kind']), (60, 'cve'))
		self.assertEqual(result['id'], row.pk)  # the link is the current row

	def test_a_finding_counts_from_its_earliest_discovery_on_the_host(self):
		self.age_all(finding=3)
		earlier = Vulnerability.objects.create(subdomain=self.b_live, target_domain=self.db, scan_history=None, name='high',
											severity=3, open_status=False, discovered_date=ago(50))
		self.assertEqual(counts.oldest_open()['days'], 50)
		self.assertEqual(counts.oldest_open()['id'], self.high_b.pk)
		earlier.delete()

	def test_only_critical_and_high_count(self):
		Vulnerability.objects.filter(pk=self.medium.pk).update(discovered_date=ago(100))   # medium scanner finding
		HygieneFinding.objects.update(first_seen=ago(100))                                 # medium hygiene finding
		CVEMatch.objects.filter(pk=self.m_ruled_out.pk).update(created_at=ago(100))        # medium CVE, and ruled out
		self.age_all(match=1, finding=2)
		self.assertEqual(counts.oldest_open()['days'], 2)

	def test_closed_ruled_out_and_accepted_items_do_not_count(self):
		self.age_all(match=40, finding=30, hygiene=20)
		CVEMatch.objects.filter(pk=self.m_b.pk).update(remediation_status='fixed')
		CVEMatch.objects.filter(pk=self.m_live.pk).update(remediation_status='accepted_risk')
		Vulnerability.objects.filter(pk=self.high_b.pk).update(open_status=False)
		HygieneFinding.objects.update(remediation_status='fixed')
		self.assertEqual(counts.oldest_open(), {'days': None, 'kind': None, 'id': None})
		CVEMatch.objects.filter(pk=self.m_live.pk).update(remediation_status='open', ai_verdict='not_affected')
		self.assertIsNone(counts.oldest_open()['days'])
		CVEMatch.objects.filter(pk=self.m_live.pk).update(ai_verdict='')
		self.assertEqual(counts.oldest_open()['kind'], 'cve')
		HygieneFinding.objects.update(remediation_status='open', status='resolved')
		self.assertEqual(counts.oldest_open()['kind'], 'cve')  # a resolved hygiene finding is not open

	def test_the_stats_endpoint_carries_the_keys_and_follows_the_callers_projects(self):
		self.age_all(match=10, finding=20, hygiene=5)
		everything = self.stats()
		self.assertEqual((everything['oldest_open_days'], everything['oldest_open_kind'], everything['oldest_open_id']),
						 (20, 'scanner', self.high_b.pk))
		project_a = self.stats('ca')  # the 20 day finding belongs to project B
		self.assertEqual(project_a['oldest_open_days'], 10)
		self.assertEqual(project_a['oldest_open_kind'], 'cve')
