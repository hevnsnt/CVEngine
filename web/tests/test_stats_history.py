from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, StatsSnapshot
from cveFeed.stats_history import compute_snapshot, snapshot_all_projects
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

NOW = timezone.now()
TODAY = timezone.localdate()


class ComputeSnapshotTests(TestCase):
	"""cveFeed.stats_history: the pure computation a daily snapshot is built from, independent of storage or the API."""

	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Snap', slug='snap-org')
		cls.proj = Project.objects.create(name='Snap Project', slug='snap-proj', insert_date=NOW, org=org)
		cls.domain = Domain.objects.create(name='snap.example', project=cls.proj, insert_date=NOW)
		cls.www = Subdomain.objects.create(name='www.snap.example', target_domain=cls.domain)
		cls.api = Subdomain.objects.create(name='api.snap.example', target_domain=cls.domain)
		cls.clean = Subdomain.objects.create(name='clean.snap.example', target_domain=cls.domain)
		kev = CVEEntry.objects.create(cve_id='CVE-2099-8001', kev=True, cvss=9.8, title='t', published_at=NOW)
		mild = CVEEntry.objects.create(cve_id='CVE-2099-8002', cvss=5.0, title='t', published_at=NOW)
		cls.fire_match = CVEMatch.objects.create(cve_entry=kev, subdomain=cls.www, matched_product='nginx')
		cls.ice_match = CVEMatch.objects.create(cve_entry=mild, subdomain=cls.api, matched_product='php')
		cls.fixed_match = CVEMatch.objects.create(cve_entry=mild, subdomain=cls.www, matched_product='openssl',
												  remediation_status='fixed', remediation_updated_at=NOW)
		cls.high_vuln = Vulnerability.objects.create(name='Exposed admin', severity=3, subdomain=cls.www, target_domain=cls.domain,
													 open_status=True, discovered_date=NOW - timedelta(days=5), http_url='https://www.snap.example/')
		cls.fixed_vuln = Vulnerability.objects.create(name='Old XSS', severity=2, subdomain=cls.api, target_domain=cls.domain,
													  open_status=False, discovered_date=NOW - timedelta(days=10),
													  http_url='https://api.snap.example/', remediation_status='fixed',
													  remediation_updated_at=NOW - timedelta(days=2))
		HygieneFinding.objects.create(domain=cls.domain, host='www.snap.example', check_name='dmarc_none', severity=2,
									  title='No DMARC', status='open')

	def test_hosts_and_exposed_hosts(self):
		snap = compute_snapshot(self.proj, date=TODAY)
		self.assertEqual(snap['hosts'], 3)  # www, api, clean
		self.assertEqual(snap['exposed_hosts'], 2)  # www (fire match + vuln), api (ice match) -- clean has neither

	def test_open_findings_and_cve_matches_count_the_actionable_set(self):
		snap = compute_snapshot(self.proj, date=TODAY)
		self.assertEqual(snap['cve_matches'], {'fire': 1, 'smoke': 0, 'ice': 1})  # fixed_match excluded: not actionable
		self.assertEqual(snap['open_findings']['high'], 1)  # high_vuln
		# ice_match's CVE (cvss 5.0) bands as medium by severity even though it heats as ice, plus the open hygiene finding
		self.assertEqual(snap['open_findings']['medium'], 2)

	def test_fixed_count_and_mean_days_to_fix(self):
		snap = compute_snapshot(self.proj, date=TODAY)
		self.assertEqual(snap['fixed'], 2)  # fixed_match, fixed_vuln
		self.assertIsNotNone(snap['mean_days_to_fix'])
		self.assertGreater(snap['mean_days_to_fix'], 0)

	def test_a_project_with_nothing_fixed_has_no_mean(self):
		empty_org = Org.objects.create(name='Empty', slug='empty-org')
		empty = Project.objects.create(name='Empty', slug='empty-proj', insert_date=NOW, org=empty_org)
		snap = compute_snapshot(empty, date=TODAY)
		self.assertEqual((snap['hosts'], snap['fixed'], snap['mean_days_to_fix']), (0, 0, None))
		self.assertEqual(snap['open_findings'], {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0})
		self.assertEqual(snap['cve_matches'], {'fire': 0, 'smoke': 0, 'ice': 0})

	def test_snapshot_all_projects_stores_one_row_per_project_and_is_idempotent(self):
		other_org = Org.objects.create(name='Other', slug='stats-other-org')
		Project.objects.create(name='Other', slug='stats-other-proj', insert_date=NOW, org=other_org)
		saved = snapshot_all_projects(date=TODAY)
		self.assertGreaterEqual(saved, 2)
		self.assertEqual(StatsSnapshot.objects.filter(project=self.proj, date=TODAY).count(), 1)
		row = StatsSnapshot.objects.get(project=self.proj, date=TODAY)
		self.assertEqual(row.hosts, 3)
		snapshot_all_projects(date=TODAY)  # a second run the same day overwrites, not duplicates
		self.assertEqual(StatsSnapshot.objects.filter(project=self.proj, date=TODAY).count(), 1)


class StatsHistoryApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Hist', slug='hist-org')
		cls.pa = Project.objects.create(name='A', slug='hist-a', insert_date=NOW, org=org)
		cls.pb = Project.objects.create(name='B', slug='hist-b', insert_date=NOW, org=org)
		for days_ago, project, hosts, fixed in ((2, cls.pa, 5, 1), (1, cls.pa, 6, 2), (2, cls.pb, 3, 0)):
			StatsSnapshot.objects.create(project=project, date=TODAY - timedelta(days=days_ago), hosts=hosts,
										 exposed_hosts=1, open_findings={'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'info': 0},
										 cve_matches={'fire': 0, 'smoke': 1, 'ice': 0}, fixed=fixed,
										 mean_days_to_fix=3.5 if fixed else None)
		cls.alice, cls.root = User.objects.create_user('hist-alice', password='x'), User.objects.create_superuser('hist-root', 'r@x.io', 'x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		_, cls.token = create_token(cls.alice, 'hist')
		_, cls.root_token = create_token(cls.root, 'hist-root')

	def test_history_is_a_bare_list_oldest_first(self):
		status, body = call(self.token, 'GET', '/api/v1/projects/hist-a/stats/history?days=30')
		self.assertEqual(status, 200)
		self.assertIsInstance(body, list)
		self.assertEqual([r['hosts'] for r in body], [5, 6])
		self.assertEqual(body[0]['cve_matches'], {'fire': 0, 'smoke': 1, 'ice': 0})

	def test_days_bounds_the_window(self):
		# days=N is a window of N calendar days ending today (inclusive); both fixtures are 1-2 days ago, so days=1
		# (today only) catches neither and days=2 catches only the more recent one.
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/hist-a/stats/history?days=1')[1], [])
		status, body = call(self.token, 'GET', '/api/v1/projects/hist-a/stats/history?days=2')
		self.assertEqual(status, 200)
		self.assertEqual(len(body), 1)
		self.assertEqual(body[0]['hosts'], 6)

	def test_bad_days_is_400(self):
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/hist-a/stats/history?days=x')[0], 400)

	def test_a_member_cannot_read_another_projects_history(self):
		self.assertIn(call(self.token, 'GET', '/api/v1/projects/hist-b/stats/history')[0], (403, 404))

	def test_all_projects_sums_rows_per_date(self):
		status, body = call(self.root_token, 'GET', '/api/v1/projects/_all/stats/history?days=3')
		self.assertEqual(status, 200)
		two_days_ago = next(r for r in body if r['hosts'] == 8)  # hist-a 5 + hist-b 3
		self.assertEqual(two_days_ago['fixed'], 1)  # hist-a's 1 + hist-b's 0
		self.assertEqual(two_days_ago['mean_days_to_fix'], 3.5)  # only hist-a has one that day

	def test_mcp_lists_the_same(self):
		is_error, result = tool_call(self.token, 'stats_history', {'project': 'hist-a', 'days': 30})
		self.assertFalse(is_error)
		self.assertEqual([r['hosts'] for r in result], [5, 6])
