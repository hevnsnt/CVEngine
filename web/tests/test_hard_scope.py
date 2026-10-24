from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.services import Ctx, list_hosts, list_matches, list_targets, search_hosts
from cveFeed.autofire import fire_for_cve
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class LatestScanScopeTests(TestCase):
	"""Review 1.5 / 3.3: hosts are stored once per scan; every read must see one scan's copy."""

	def setUp(self):
		now = timezone.now()
		org = Org.objects.create(name='S', slug='s')
		self.project = Project.objects.create(name='S', slug='scope-p', insert_date=now, org=org)
		self.domain = Domain.objects.create(name='scope.example', project=self.project, insert_date=now)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		self.ctx = Ctx(user=User.objects.create_user('scope-admin', password='x', is_superuser=True))
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-9', kev=True, cvss=9.8, published_at=now, affected=[])

	def _scan(self, status=2, domain=None):
		return ScanHistory.objects.create(domain=domain or self.domain, scan_type=self.engine, start_scan_date=timezone.now(),
			scan_status=status)

	def _host(self, scan, name='www.scope.example', domain=None, match=True):
		sub = Subdomain.objects.create(name=name, target_domain=domain or self.domain, scan_history=scan)
		if match:
			CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0',
				confidence=0.9, version_in_range=True)
		return sub

	def test_two_finished_scans_of_one_domain_show_the_host_once_from_the_newer_scan(self):
		old, new = self._scan(), self._scan()
		self._host(old)
		latest = self._host(new)
		hosts = list_hosts(self.ctx, 'scope-p', {})
		self.assertEqual([h['id'] for h in hosts['results']], [latest.id])
		self.assertEqual(hosts['count'], 1)
		self.assertEqual(search_hosts(self.ctx, 'scope-p', {'q': 'www'})['count'], 1)
		matches = list_matches(self.ctx, 'scope-p', {})
		self.assertEqual([m['host'] for m in matches['results']], ['www.scope.example'])
		self.assertEqual(matches['count'], 1)

	def test_a_host_only_the_old_scan_found_is_gone_from_the_inventory(self):
		old, new = self._scan(), self._scan()
		self._host(old, 'gone.scope.example')
		self._host(new, 'here.scope.example')
		self.assertEqual([h['host'] for h in list_hosts(self.ctx, 'scope-p', {})['results']], ['here.scope.example'])

	def test_a_scan_in_progress_does_not_hide_the_last_finished_inventory(self):
		done, running = self._scan(2), self._scan(1)
		self._host(done)
		self._host(running, 'new.scope.example')
		self.assertEqual([h['host'] for h in list_hosts(self.ctx, 'scope-p', {})['results']], ['www.scope.example'])

	def test_a_domain_with_no_finished_scan_keeps_every_host_it_found(self):
		self._host(self._scan(1), 'a.scope.example')
		self._host(self._scan(0), 'b.scope.example', match=False)  # a failed scan that got part way
		self.assertEqual(sorted(h['host'] for h in list_hosts(self.ctx, 'scope-p', {})['results']), ['a.scope.example', 'b.scope.example'])

	def test_rows_with_no_scan_are_kept(self):
		self._host(self._scan())
		ct = Subdomain.objects.create(name='ct.scope.example', target_domain=self.domain)
		self.assertIn(ct.id, [h['id'] for h in list_hosts(self.ctx, 'scope-p', {})['results']])

	def test_another_domains_scans_do_not_hide_this_domains_hosts(self):
		other = Domain.objects.create(name='other.example', project=self.project, insert_date=timezone.now())
		self._host(self._scan())
		self._scan(domain=other)
		self.assertEqual(list_hosts(self.ctx, 'scope-p', {})['count'], 1)

	def test_target_counts_read_the_current_inventory(self):
		self._host(self._scan())
		self._host(self._scan())
		row = next(t for t in list_targets(self.ctx, 'scope-p', {})['results'] if t['name'] == 'scope.example')
		self.assertEqual((row['hosts'], row['exposed']), (1, 1))

	def test_auto_fire_reads_only_the_current_scans_matches(self):
		old, new = self._scan(), self._scan()
		self._host(old, 'www.scope.example')
		latest = self._host(new, 'www.scope.example')
		CVEMatch.objects.filter(subdomain=latest).update(ai_verdict='affected')
		calls = []
		run = fire_for_cve(self.cve, test_dispatcher=lambda pk, hosts, project: calls.append(hosts), correlated=True)
		self.assertEqual(run.matches_found, 1)  # not one per scan
		self.assertEqual(calls, [['www.scope.example']])
