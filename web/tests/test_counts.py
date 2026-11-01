"""Every surface that prints a number reads it from the same definition (cveFeed.counts), so the numbers agree.

The dashboard's status line, the section pages' chips, the Targets table, the attack-surface map, the graph overview and the agent
API each used to count with their own query. These tests build one project set that tells them apart (a host held by two targets,
a name shared by two projects, a host that never resolved, a CVE match the AI ruled out, informational findings, a stalled scan,
an expired certificate) and pin every surface against every other.
"""
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import views
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, TlsCertificate, Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for


class CountFixture(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='C', slug='c')
		cls.pa = Project.objects.create(name='A', slug='ca', insert_date=now, org=org)
		cls.pb = Project.objects.create(name='B', slug='cb', insert_date=now, org=org)
		cls.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		cls.da1 = Domain.objects.create(name='one.test', project=cls.pa, insert_date=now)
		cls.da2 = Domain.objects.create(name='www.one.test', project=cls.pa, insert_date=now)  # a second target of project A
		cls.db = Domain.objects.create(name='two.test', project=cls.pb, insert_date=now)
		cls.scans = {d: ScanHistory.objects.create(domain=d, scan_type=cls.engine, scan_status=2, start_scan_date=now - timedelta(hours=3), tasks=[])
					for d in (cls.da1, cls.da2, cls.db)}
		cls._ip = 0

		def host(domain, name, live=True, http=0):
			sub = Subdomain.objects.create(target_domain=domain, name=name, scan_history=cls.scans[domain], http_status=http)
			if live:
				cls._ip += 1
				sub.ip_addresses.add(IpAddress.objects.create(address=f'192.0.2.{cls._ip}'))
			return sub
		cls.live = [host(cls.da1, f'live{i}.one.test') for i in range(3)]
		cls.dead = host(cls.da1, 'dead.one.test', live=False)
		cls.http_only = host(cls.da1, 'http.one.test', live=False, http=200)
		cls.shared_a = host(cls.da1, 'shared.one.test')         # the same name under two targets of project A: one host
		cls.shared_b = host(cls.da2, 'shared.one.test')
		cls.other_project = host(cls.db, 'shared.one.test')     # the same name in project B: another host
		cls.b_live = host(cls.db, 'b.two.test')

		cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', cvss=9.0, kev=True, affected=[])
		cls.cve2 = CVEEntry.objects.create(cve_id='CVE-2099-2', cvss=5.0, affected=[])

		def match(sub, cve, verdict='', cls_='needs_validation'):
			m = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', confidence=.8, ai_verdict=verdict)
			Triage.objects.create(project=sub.target_domain.project, domain=sub.target_domain, host=sub.name, kind='match', match=m,
								status='triaged', classification=cls_)
			return m
		cls.m_live = match(cls.live[0], cls.cve)
		cls.m_ruled_out = match(cls.live[1], cls.cve2, verdict='not_affected', cls_='likely_false_positive')
		cls.m_b = match(cls.b_live, cls.cve)

		def finding(sub, severity, name='f', **kw):
			return Vulnerability.objects.create(subdomain=sub, target_domain=sub.target_domain, scan_history=sub.scan_history,
											name=name, severity=severity, **kw)
		cls.info = [finding(cls.live[0], 0, 'tech a'), finding(cls.live[1], 0, 'tech b'), finding(cls.live[2], 0, 'tech c')]
		cls.medium = finding(cls.live[2], 2, 'medium')
		cls.closed = finding(cls.live[0], 2, 'closed medium', open_status=False)  # not actionable: it is closed
		cls.high_b = finding(cls.b_live, 3, 'high')

		ScanHistory.objects.create(domain=cls.da1, scan_type=cls.engine, scan_status=1, start_scan_date=now - timedelta(minutes=5), tasks=[])
		ScanHistory.objects.create(domain=cls.da1, scan_type=cls.engine, scan_status=1, start_scan_date=now - timedelta(hours=14), tasks=[])
		ScanHistory.objects.create(domain=cls.db, scan_type=cls.engine, scan_status=-1, start_scan_date=now, tasks=[])
		TlsCertificate.objects.create(domain=cls.da1, host='live0.one.test', not_after=now + timedelta(days=9))
		TlsCertificate.objects.create(domain=cls.da1, host='live1.one.test', not_after=now - timedelta(days=2))
		TlsCertificate.objects.create(domain=cls.db, host='b.two.test', not_after=now + timedelta(days=300))
		HygieneFinding.objects.create(domain=cls.da1, host='live0.one.test', check_name='spf_missing', severity=2, title='x')

		cls.user = User.objects.create_user('counter', password='x')
		for p in (cls.pa, cls.pb):
			ProjectMembership.objects.create(user=cls.user, project=p, role='user')

	def setUp(self):
		cache.clear()
		views.clear_stats_cache()
		self.client_ = client_for(self.user)

	def api(self, path, **params):
		r = self.client_.get(f'/api/v1/{path}', params)
		self.assertEqual(r.status_code, 200, r.content[:200])
		return r.json()

	def stats(self, project=''):
		return self.client_.get('/cve/api/stats', {'project': project} if project else {}).json()


class HostCountTests(CountFixture):
	def test_every_surface_counts_the_same_hosts(self):
		# project A: live0-2, dead, http and shared (two rows, one host) = 6. project B: shared (a different host) and b = 2.
		self.assertEqual(self.api('projects/ca/hosts')['count'], 6)
		self.assertEqual(self.api('projects/cb/hosts')['count'], 2)
		self.assertEqual(self.api('projects/_all/hosts')['count'], 8)
		self.assertEqual(self.stats('ca')['hosts'], 6)
		self.assertEqual(self.stats('cb')['hosts'], 2)
		self.assertEqual(self.stats()['hosts'], 8)

	def test_the_map_draws_exactly_the_live_hosts_the_status_line_reports(self):
		live = self.stats()['hosts_live']
		self.assertEqual(live, 7)  # live0-2, http (answers over HTTP), shared (A), shared (B), b
		nodes = [n for n in views.graph_payload()['nodes'] if n['kind'] == 'subdomain']
		self.assertEqual(len(nodes), live)
		self.assertEqual(len({(n['project'], n['label']) for n in nodes}), live)  # no host twice

	def test_the_dead_host_is_listed_but_not_drawn(self):
		self.assertIn('dead.one.test', {h['host'] for h in self.api('projects/ca/hosts', page_size=50)['results']})
		self.assertNotIn('dead.one.test', {n['label'] for n in views.graph_payload()['nodes']})

	def test_the_exposed_share_is_never_more_than_the_hosts(self):
		s = self.stats()
		self.assertLessEqual(s['exposed_hosts'], s['hosts'])
		self.assertLessEqual(s['hosts_live'], s['hosts'])


class ExposureCountTests(CountFixture):
	def test_exposed_hosts_leave_out_what_the_ai_ruled_out(self):
		# live0 (match), live2 (medium finding), b (match and a high finding); live1 only has a ruled-out match
		self.assertEqual(self.stats('ca')['exposed_hosts'], 2)
		self.assertEqual(self.stats('cb')['exposed_hosts'], 1)
		self.assertEqual(self.stats()['exposed_hosts'], 3)

	def test_the_targets_table_uses_the_same_definition(self):
		by_name = {t['name']: t['exposed'] for t in self.api('projects/ca/targets')['results']}
		self.assertEqual(by_name['one.test'], 2)
		self.assertEqual(by_name['www.one.test'], 0)

	def test_cve_matches_count_what_the_matches_page_opens_on(self):
		self.assertEqual(self.stats()['matches'], 2)
		self.assertEqual(self.api('projects/_all/matches', verdict='active')['count'], 2)
		self.assertEqual(self.api('projects/_all/matches', verdict='not_affected')['count'], 1)
		self.assertEqual(self.api('projects/_all/matches')['count'], 3)  # the API default keeps every verdict; the page asks for active

	def test_a_cve_filter_narrows_to_that_cve(self):
		self.assertEqual({m['host'] for m in self.api('projects/_all/matches', cve='cve-2099-1')['results']}, {'live0.one.test', 'b.two.test'})
		self.assertEqual(self.api('projects/ca/matches', cve='CVE-2099-1')['count'], 1)

	def test_scanner_findings_are_open_and_low_or_worse_on_every_surface(self):
		self.assertEqual(self.stats()['scanner_findings'], 2)  # medium and high; not the closed one, not the three informational
		self.assertEqual(self.api('projects/_all/vulnerabilities', severity='actionable')['count'], 2)
		self.assertEqual(self.api('projects/_all/findings', type='scanner')['total'], 2)  # the Findings page, Scanner, Actionable
		self.assertEqual(self.api('projects/_all/findings', type='scanner', status='all')['total'], 6)
		self.assertEqual(self.api('projects/_all/vulnerabilities', severity='info')['count'], 3)

	def test_the_findings_page_agrees_with_the_dashboard_for_every_type(self):
		s = self.stats()
		self.assertEqual(self.api('projects/_all/findings', type='cve')['total'], s['matches'])
		self.assertEqual(self.api('projects/_all/findings', type='scanner')['total'], s['scanner_findings'])
		self.assertEqual(self.api('projects/_all/findings', type='hygiene')['total'], s['hygiene_open'])
		counts = self.api('projects/_all/findings')['counts']
		self.assertEqual(counts, {'cve': s['matches'], 'scanner': s['scanner_findings'], 'hygiene': s['hygiene_open']})

	def test_hygiene_findings_that_are_fixed_or_accepted_are_not_counted(self):
		for name, state in (('dmarc_missing', 'fixed'), ('dkim_missing', 'accepted_risk')):
			HygieneFinding.objects.create(domain=self.da1, host='live1.one.test', check_name=name, severity=2, title='x', remediation_status=state)
		s = self.stats()
		self.assertEqual(s['hygiene_open'], 1)
		self.assertEqual(self.api('projects/_all/findings', type='hygiene')['total'], s['hygiene_open'])  # the Findings page, Actionable


class ScanAndCertificateCountTests(CountFixture):
	def test_running_is_the_same_on_the_dashboard_and_the_scans_page(self):
		self.assertEqual(self.stats()['scans_running'], 1)
		self.assertEqual(self.api('projects/_all/scans', status='running')['count'], 1)

	def test_a_scan_marked_running_for_over_the_window_is_stalled_everywhere(self):
		stalled = self.api('projects/_all/scans', status='stalled')
		self.assertEqual(stalled['count'], 1)
		self.assertTrue(stalled['results'][0]['stalled'])
		everything = self.api('projects/_all/scans')['results']
		self.assertEqual(sum(1 for s in everything if s['status'] == 1 and not s['stalled']), self.stats()['scans_running'])

	def test_the_running_window_follows_the_configured_timeouts(self):
		from cveFeed import counts
		from dashboard.models import SystemTimings
		SystemTimings.objects.all().delete()
		self.assertEqual(counts.running_window(), timedelta(hours=11))  # the shipped 6 h + 4 h + 1 h
		SystemTimings.objects.create(discovery_timeout_hours=24, nuclei_timeout_hours=8)
		self.assertEqual(counts.running_window(), timedelta(hours=33))
		long_scan = ScanHistory.objects.create(domain=self.da1, scan_type=self.engine, scan_status=1, tasks=[],
		                                       start_scan_date=timezone.now() - timedelta(hours=20))
		self.assertIn(long_scan.pk, counts.running_scans().values_list('pk', flat=True))  # a healthy long scan is not a restart casualty
		self.assertNotIn(long_scan.pk, counts.stalled_scans().values_list('pk', flat=True))

	def test_the_chips_add_up_to_all(self):
		total = self.api('projects/_all/scans')['count']
		parts = sum(self.api('projects/_all/scans', status=s)['count'] for s in ('running', 'stalled', 'queued', 'finished', 'failed', 'aborted'))
		self.assertEqual(parts, total)

	def test_queued_matches(self):
		self.assertEqual(self.stats()['scans_queued'], 1)
		self.assertEqual(self.api('projects/_all/scans', status='queued')['count'], 1)

	def test_the_scan_counts_are_fresh_while_the_rest_is_cached(self):
		first = self.stats()
		ScanHistory.objects.create(domain=self.da1, scan_type=self.engine, scan_status=1, start_scan_date=timezone.now(), tasks=[])
		second = self.stats()  # inside the cache window
		self.assertEqual(second['scans_running'], first['scans_running'] + 1)

	def line(self, project, status='running', kind='run_check', age=timedelta(minutes=5), **detail):
		from cveFeed.models import AgentActivity
		row = AgentActivity.objects.create(kind=kind, message='work', status=status, project=project, detail=detail)
		AgentActivity.objects.filter(pk=row.pk).update(created_at=timezone.now() - age)
		return row

	def test_background_running_counts_work_that_runs_under_a_finished_scan(self):
		self.assertEqual(self.stats()['scans_background_running'], 0)
		self.line(self.pa)                                       # a weekly deep pass: no scan record at all
		self.line(self.pa, scan_id=self.scans[self.da1].id)      # a rescan under a finished scan record
		self.assertEqual(self.stats()['scans_background_running'], 2)

	def test_background_running_leaves_out_what_the_running_scan_already_counts(self):
		running = ScanHistory.objects.filter(scan_status=1).order_by('-start_scan_date').first()
		self.line(self.pa, scan_id=running.id)                   # a stage of a scan scans_running counts
		self.line(self.pa, scan_id=self.scans[self.da1].id)
		self.assertEqual(self.stats()['scans_background_running'], 1)

	def test_background_running_ignores_settled_stale_and_ai_lines(self):
		self.line(self.pa, status='done')
		self.line(self.pa, status='failed')
		self.line(self.pa, kind='confirm')                       # the AI engine reading, not scanning
		self.line(self.pa, age=timedelta(hours=4))               # a casualty of a restart
		self.assertEqual(self.stats()['scans_background_running'], 0)

	def test_background_running_follows_the_project_filter(self):
		self.line(self.pa)
		self.line(self.pb)
		self.line(self.pb)
		self.assertEqual(self.stats()['scans_background_running'], 3)
		self.assertEqual(self.stats('ca')['scans_background_running'], 1)
		self.assertEqual(self.stats('cb')['scans_background_running'], 2)

	def test_certificates_expiring_agree_and_include_the_expired(self):
		self.assertEqual(self.stats()['certs_expiring'], 2)
		self.assertEqual(self.api('projects/_all/certificates', expiring_within='30')['count'], 2)
		self.assertEqual(self.stats()['certs_total'], self.api('projects/_all/certificates')['count'])


class HostRecordTests(CountFixture):
	def record(self, name, project='ca'):
		return next(h for h in self.api(f'projects/{project}/hosts', q=name, page_size=50)['results'] if h['host'] == name)

	def test_the_host_record_counts_findings_and_detections_apart(self):
		h = self.record('live2.one.test')
		self.assertEqual(h['vuln_count'], 1)   # the medium finding
		self.assertEqual(h['info_count'], 1)   # the informational detection
		self.assertEqual(len(h['vulns']), 2)

	def test_the_host_record_counts_the_matches_the_ai_has_not_ruled_out(self):
		self.assertEqual(self.record('live0.one.test')['cve_matches'], 1)
		self.assertEqual(self.record('live1.one.test')['cve_matches'], 0)  # its only match is ruled out

	def test_a_finding_names_the_match_each_of_its_cves_links_to(self):
		cve = self.cve
		from startScan.models import CveId
		ids = CveId.objects.create(name=cve.cve_id)
		self.info[0].cve_ids.add(ids)  # on live0, which has a match for that CVE
		rows = self.api('projects/ca/vulnerabilities', severity='info', page_size=50)['results']
		row = next(r for r in rows if r['id'] == self.info[0].pk)
		self.assertEqual(row['cve_matches'], {cve.cve_id: self.m_live.pk})
		self.assertEqual(next(r for r in rows if r['id'] == self.info[1].pk)['cve_matches'], {})


class GraphNodeLinkTests(CountFixture):
	def detail(self, node_id):
		return views.node_detail(node_id)

	def test_a_host_node_links_its_addresses_target_and_matches(self):
		d = self.detail(f'sub:{self.live[0].pk}')
		rows = {r['k']: r for r in d['rows']}
		self.assertTrue(rows['IP addresses']['links'][0]['href'].startswith('/cve/ca/hosts/?q=ip%3A192.0.2.'))
		self.assertEqual(rows['Target']['links'][0]['href'], '/cve/ca/hosts/?host=one.test')
		self.assertEqual(rows['CVE matches']['links'][0]['href'], f'/cve/ca/matches/#{self.m_live.pk}')

	def test_an_ip_node_links_its_hosts_and_itself(self):
		ip = self.live[0].ip_addresses.first()
		d = self.detail(f'ip:{ip.pk}')
		self.assertEqual(d['link'], f'/cve/ca/hosts/?q=ip%3A{ip.address}')
		self.assertEqual(d['rows'][0]['links'][0]['href'], '/cve/ca/hosts/?host=live0.one.test')

	def test_a_cve_node_links_to_its_matches_and_hosts(self):
		d = self.detail(f'cve:{self.cve.pk}')
		self.assertEqual(d['link'], '/cve/_all/matches/?cve=CVE-2099-1')  # held by two projects
		hosts = next(r for r in d['rows'] if r['k'] == 'Matched hosts')['links']
		self.assertEqual({h['href'] for h in hosts}, {'/cve/ca/hosts/?host=live0.one.test', '/cve/cb/hosts/?host=b.two.test'})
		ruled_out = self.detail(f'cve:{self.cve2.pk}')
		self.assertEqual(ruled_out['link'], '')  # its only match is ruled out, so there is no match page to open
