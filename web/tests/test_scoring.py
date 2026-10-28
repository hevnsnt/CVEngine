import datetime
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import changes, correlation, scoring
from cveFeed.models import AssetChange, CVEEntry, CVEMatch, HostState, HygieneFinding, RouteAuth
from cveFeed.tasks import rescore_all_hosts
from cveFeed.views import graph_payload
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_changes import ChangeFixture


def total(inputs):
	return scoring.score_host(inputs)[0]


def labels(inputs):
	return [d['label'] for d in scoring.score_host(inputs)[1]]


class ScoreHostTests(SimpleTestCase):
	def test_a_clean_host_scores_nothing_and_a_public_ip_alone_scores_ten(self):
		self.assertEqual(scoring.score_host({}), (0, []))
		self.assertEqual(total({'public_ip': True}), 10)
		self.assertEqual(total({'public_ip': False}), 0)

	def test_hygiene_issues_add_the_worst_one_plus_two_per_further_serious_one_capped_at_twenty(self):
		self.assertEqual(total({'hygiene': [{'severity': 4, 'title': 'Certificate has expired'}]}), 20)
		self.assertEqual(total({'hygiene': [{'severity': 2, 'title': 'DMARC missing'}]}), 8)
		self.assertEqual(total({'hygiene': [{'severity': 2, 'title': 'DMARC missing'}, {'severity': 2, 'title': 'SPF soft fail'},
			{'severity': 1, 'title': 'No CAA record'}]}), 10)
		self.assertEqual(total({'hygiene': [{'severity': 3, 'title': 'a'}, {'severity': 3, 'title': 'b'}, {'severity': 3, 'title': 'c'},
			{'severity': 2, 'title': 'd'}]}), 20)
		self.assertEqual(total({'hygiene': [{'severity': 0, 'title': 'info only'}]}), 0)
		self.assertEqual(labels({'hygiene': [{'severity': 4, 'title': 'Certificate has expired'}]}), ['Critical hygiene issue Certificate has expired'])

	def test_cve_points_follow_the_worst_match_and_the_ai_bonus_needs_fire(self):
		self.assertEqual(total({'cves': [{'id': 'CVE-1', 'temp': 'ice'}, {'id': 'CVE-2', 'temp': 'smoke'}]}), 20)
		self.assertEqual(total({'cves': [{'id': 'CVE-1', 'temp': 'ice'}]}), 5)
		self.assertEqual(total({'cves': [{'id': 'CVE-1', 'temp': 'fire'}]}), 40)
		self.assertEqual(total({'cves': [{'id': 'CVE-1', 'temp': 'fire', 'ai_verdict': 'affected'}]}), 50)
		self.assertEqual(total({'cves': [{'id': 'CVE-1', 'temp': 'smoke', 'ai_verdict': 'affected'}]}), 20)
		self.assertIn('Fire CVE match CVE-2026-1234', labels({'cves': [{'id': 'CVE-2026-1234', 'temp': 'fire'}]})[0])

	def test_findings_use_the_worst_open_one(self):
		f = lambda *sev: {'findings': [{'severity': s, 'name': f'n{s}'} for s in sev]}  # noqa: E731
		self.assertEqual((total(f(4)), total(f(3)), total(f(2)), total(f(1)), total(f(1, 2))), (25, 25, 10, 3, 10))
		self.assertEqual(total(f(0)), 0)
		self.assertIn('Critical finding n4', labels(f(4, 1)))

	def test_route_points(self):
		r = lambda path, state: {'routes': [{'path': path, 'auth_state': state}]}  # noqa: E731
		self.assertEqual(total(r('/admin', 'open')), 15)
		self.assertEqual(total(r('/api/', 'open')), 15)
		self.assertEqual(total(r('/actuator/health', 'open')), 15)
		self.assertEqual(total(r('/', 'open')), 5)
		self.assertEqual(total(r('/login', 'login')), 5)
		self.assertEqual(total(r('/admin', 'sso')), 0)
		self.assertEqual(total(r('/admin', 'session_required')), 0)
		self.assertEqual(total(r('/blog', 'open')), 0)
		self.assertEqual(total({'routes': [{'path': '/', 'auth_state': 'open'}, {'path': '/admin', 'auth_state': 'open'}]}), 15)
		self.assertIn('Admin route /admin is open', labels(r('/admin', 'open')))

	def test_sensitive_points_come_from_the_worst_route(self):
		self.assertEqual(total({'routes': [{'path': '/a', 'auth_state': 'sso', 'sensitive_score': 5},
			{'path': '/b', 'auth_state': 'sso', 'sensitive_score': 25}]}), 25)
		self.assertIn('Credentials served on /b', labels({'routes': [{'path': '/b', 'auth_state': 'sso', 'sensitive_score': 25}]}))

	def test_recency(self):
		self.assertEqual(total({'recent': ['host_new']}), 10)
		self.assertEqual(total({'recent': ['host_returned', 'port_opened']}), 10)
		self.assertEqual(total({'recent': ['port_opened']}), 5)
		self.assertEqual(total({'recent': ['service_changed']}), 5)
		self.assertEqual(total({'recent': ['tech_added']}), 0)
		self.assertEqual(labels({'recent': ['host_new']}), ['New this week'])

	def test_zombies(self):
		self.assertEqual(total({'zombie_host': True}), 15)
		self.assertEqual(total({'zombie_route': True}), 5)
		self.assertEqual(total({'zombie_host': True, 'zombie_route': True}), 15)  # capped

	def test_the_score_never_exceeds_100_and_the_detail_adds_up(self):
		inputs = {'cves': [{'id': 'CVE-1', 'temp': 'fire', 'ai_verdict': 'affected'}], 'findings': [{'severity': 4, 'name': 'x'}],
			'routes': [{'path': '/admin', 'auth_state': 'open', 'sensitive_score': 25}], 'public_ip': True, 'recent': ['host_new'],
			'zombie_host': True}
		score, detail = scoring.score_host(inputs)
		self.assertEqual(score, 100)
		self.assertGreater(sum(d['points'] for d in detail), 100)
		small = {'cves': [{'id': 'CVE-1', 'temp': 'smoke'}], 'public_ip': True}
		score, detail = scoring.score_host(small)
		self.assertEqual(score, sum(d['points'] for d in detail))
		self.assertTrue(all(isinstance(d['label'], str) and isinstance(d['points'], int) for d in detail))


class RescoreTests(ChangeFixture, TestCase):
	def setUp(self):
		super().setUp()
		now = timezone.now()
		self.old = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=now, scan_status=2, tasks=[], results_dir='x')
		self.new = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=now, scan_status=2, tasks=[], results_dir='x')
		self.ip = IpAddress.objects.create(address='203.0.113.5')
		self.rows = []
		for scan in (self.old, self.new):
			sub = Subdomain.objects.create(name='www.ct.test', target_domain=self.domain, scan_history=scan)
			sub.ip_addresses.add(self.ip)
			self.rows.append(sub)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-5', kev=True, cvss=9.8, title='t', published_at=now)
		CVEMatch.objects.create(cve_entry=cve, subdomain=self.rows[1], confidence=0.9)
		RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.ct.test', url='https://www.ct.test/admin', path='/admin',
			auth_state='open')
		RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.ct.test', url='https://www.ct.test/api', path='/api',
			auth_state='sso', sensitive_score=15)
		AssetChange.objects.create(project=self.project, domain=self.domain, host='www.ct.test', kind='host_new')
		AssetChange.objects.create(project=self.project, domain=self.domain, host='www.ct.test', kind='host_new',
			detected_at=now - datetime.timedelta(days=30))
		HostState.objects.create(project=self.project, domain=self.domain, host='www.ct.test', state={})

	def test_open_hygiene_issues_of_the_host_raise_its_score_and_resolving_them_lowers_it_again(self):
		from cveFeed.hygiene import Finding, store_findings
		before, _ = self._fire_score()
		store_findings(self.domain, [Finding('tls_expired', 4, 'Certificate has expired', host='www.ct.test')])
		self.rows[1].refresh_from_db()
		self.assertIn('Critical hygiene issue Certificate has expired', [d['label'] for d in self.rows[1].score_detail])
		self.assertGreater(self.rows[1].score, before)
		row = HygieneFinding.objects.get(host='www.ct.test')
		row.remediation_status = 'accepted_risk'
		row.save()
		self.assertNotIn('Critical hygiene issue Certificate has expired', self._fire_score()[1])
		row.remediation_status = 'open'
		row.save()
		store_findings(self.domain, [])  # the next sweep no longer finds it
		self.assertFalse(any('hygiene' in label for label in self._fire_score()[1]))

	def _fire_score(self):
		scoring.rescore_hosts(self.project.id, ['www.ct.test'])
		self.rows[1].refresh_from_db()
		return self.rows[1].score, [d['label'] for d in self.rows[1].score_detail]

	def test_a_match_marked_fixed_or_accepted_stops_heating_the_host_and_reopening_restores_it(self):
		from agentapi.services import Ctx, _heat_reasons, update_match
		from cveFeed.counts import exposed_matches
		ctx = Ctx(user=User.objects.create_user('closer', password='x', is_superuser=True))
		match = CVEMatch.objects.get(subdomain=self.rows[1])
		before, labels_before = self._fire_score()
		self.assertIn('Fire CVE match CVE-2099-5', labels_before)
		self.assertEqual(len(_heat_reasons(self.rows[1])), 1)
		for status in ('fixed', 'accepted_risk'):
			update_match(ctx, self.project.slug, match.id, status=status)  # rescores the host at once
			self.rows[1].refresh_from_db()
			self.assertEqual(self.rows[1].score, before - 40, status)
			self.assertNotIn('Fire CVE match CVE-2099-5', [d['label'] for d in self.rows[1].score_detail])
			self.assertEqual(_heat_reasons(Subdomain.objects.get(pk=self.rows[1].pk)), [])
			self.assertFalse(exposed_matches().filter(pk=match.pk).exists())
		update_match(ctx, self.project.slug, match.id, status='in_progress')
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, before)
		update_match(ctx, self.project.slug, match.id, status='open')
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, before)

	def test_closed_scanner_findings_stop_counting_and_a_bulk_update_rescores_each_host_once(self):
		from agentapi.services import Ctx, bulk_update_finding_status
		ctx = Ctx(user=User.objects.create_user('closer2', password='x', is_superuser=True))
		vuln = Vulnerability.objects.create(name='Admin panel', severity=4, scan_history=self.new, subdomain=self.rows[1],
			target_domain=self.domain, open_status=True)
		match = CVEMatch.objects.get(subdomain=self.rows[1])
		_, labels_before = self._fire_score()
		self.assertIn('Critical finding Admin panel', labels_before)
		with mock.patch('cveFeed.scoring.rescore_quietly', wraps=scoring.rescore_quietly) as spy:
			result = bulk_update_finding_status(ctx, self.project.slug, [{'kind': 'vulnerability', 'id': vuln.id}, {'kind': 'match', 'id': match.id}], 'fixed')
		self.assertEqual(result['updated'], 2)
		self.assertEqual(spy.call_count, 1)
		self.rows[1].refresh_from_db()
		labels_after = [d['label'] for d in self.rows[1].score_detail]
		self.assertNotIn('Critical finding Admin panel', labels_after)
		self.assertNotIn('Fire CVE match CVE-2099-5', labels_after)

	def test_inputs_are_gathered_scored_and_stored_on_every_copy_of_the_host(self):
		self.assertEqual(scoring.rescore_hosts(self.project.id, ['WWW.ct.test', 'unknown.ct.test']), 1)
		for row in self.rows:
			row.refresh_from_db()
			self.assertEqual(row.score, 40 + 15 + 15 + 10 + 10)  # fire CVE, open /admin, PII on a route, public IP, new this week
			self.assertIsNotNone(row.scored_at)
		detail = {d['label']: d['points'] for d in self.rows[0].score_detail}
		self.assertEqual(detail['Fire CVE match CVE-2099-5'], 40)
		self.assertEqual(detail['Admin route /admin is open'], 15)
		self.assertEqual(detail['Personal data served on /api'], 15)
		self.assertEqual(detail['New this week'], 10)
		self.assertEqual(HostState.objects.get(host='www.ct.test').score, 90)

	def test_a_ruled_out_match_and_a_private_ip_do_not_count(self):
		CVEMatch.objects.update(ai_verdict='not_affected')
		self.ip.is_private = True
		self.ip.save()
		AssetChange.objects.all().delete()
		RouteAuth.objects.all().delete()
		scoring.rescore_hosts(self.project.id, ['www.ct.test'])
		self.rows[1].refresh_from_db()
		self.assertEqual((self.rows[1].score, self.rows[1].score_detail), (0, []))

	def test_invalid_product_closure_removes_only_its_risk_and_updates_graph(self):
		match = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get()
		match.cve_entry.affected = [{'product': 'AWS Multi Model Server'}]
		match.cve_entry.save(update_fields=['affected'])
		match.matched_product = 'AWS Service -'
		match.save(update_fields=['matched_product'])
		scoring.rescore_hosts(self.project.id, ['www.ct.test'])
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, 90)
		with self.captureOnCommitCallbacks(execute=True):
			self.assertTrue(correlation.close_invalid_correlation(match))
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, 50)
		self.assertFalse(any('CVE match' in part['label'] for part in self.rows[1].score_detail))
		graph = graph_payload(scan_id=self.new.id)
		host = next(node for node in graph['nodes'] if node['kind'] == 'subdomain')
		self.assertEqual(host['score'], 50)
		self.assertFalse(any('CVE match' in part['label'] for part in host['info']['score_parts']))
		self.assertFalse(correlation.close_invalid_correlation(match))

	def test_other_open_match_keeps_cve_risk_after_one_invalid_closure(self):
		bad = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get()
		bad.cve_entry.affected = [{'product': 'AWS Multi Model Server'}]
		bad.cve_entry.save(update_fields=['affected'])
		bad.matched_product = 'AWS Service -'
		bad.save(update_fields=['matched_product'])
		other_cve = CVEEntry.objects.create(cve_id='CVE-2099-6', kev=True, cvss=9.8, title='Other', published_at=timezone.now())
		CVEMatch.objects.create(cve_entry=other_cve, subdomain=self.rows[1], confidence=0.9, matched_product='other')
		scoring.rescore_hosts(self.project.id, ['www.ct.test'])
		self.assertTrue(correlation.close_invalid_correlation(bad))
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, 90)
		self.assertIn('Fire CVE match CVE-2099-6', [part['label'] for part in self.rows[1].score_detail])

	def test_open_findings_count_and_closed_ones_do_not(self):
		Vulnerability.objects.create(scan_history=self.new, target_domain=self.domain, subdomain=self.rows[1], name='Exposed panel',
			severity=3, open_status=True, http_url='https://www.ct.test/', discovered_date=timezone.now())
		Vulnerability.objects.create(scan_history=self.new, target_domain=self.domain, subdomain=self.rows[1], name='Old', severity=4,
			open_status=False, http_url='https://www.ct.test/x', discovered_date=timezone.now())
		scoring.rescore_hosts(self.project.id, ['www.ct.test'])
		self.rows[1].refresh_from_db()
		self.assertIn('High finding Exposed panel', [d['label'] for d in self.rows[1].score_detail])
		self.assertNotIn('Critical finding Old', [d['label'] for d in self.rows[1].score_detail])

	def test_record_scan_changes_rescores_the_scans_hosts(self):
		with mock.patch('cveFeed.scoring.rescore_hosts') as rescore:
			changes.record_scan_changes(self.new.id)
		rescore.assert_called_once_with(self.project.id, ['www.ct.test'], scan_id=self.new.id)

	def test_a_scoring_failure_never_fails_the_diff(self):
		with mock.patch('cveFeed.scoring.rescore_hosts', side_effect=RuntimeError('boom')):
			out = changes.record_scan_changes(self.new.id)
		self.assertIn('hosts', out)

	def test_a_verdict_rescores_the_matched_hosts(self):
		match = CVEMatch.objects.get()
		with mock.patch('cveFeed.scoring.rescore_quietly') as rescore:
			scoring.rescore_for_matches([CVEMatch.objects.select_related('subdomain__target_domain').get(pk=match.pk)])
		rescore.assert_called_once_with(self.project.id, ['www.ct.test'])

	def test_the_daily_rescore_respects_the_sweep_claim(self):
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
			self.assertEqual(rescore_all_hosts()['hosts'], 0)
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, 0)
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=True):
			self.assertEqual(rescore_all_hosts()['hosts'], 1)
		self.rows[1].refresh_from_db()
		self.assertEqual(self.rows[1].score, 90)

	def test_the_graph_node_carries_the_score(self):
		scoring.rescore_hosts(self.project.id, ['www.ct.test'])
		nodes = [n for n in graph_payload(scan_id=self.new.id)['nodes'] if n['kind'] == 'subdomain']
		self.assertEqual([n['score'] for n in nodes], [90])

	def test_the_hover_card_names_the_hosts_project(self):
		# the dashboard's attack-surface map spans every project the viewer can see, so its hover card
		# must say which project a host belongs to, not just its score and findings
		nodes = [n for n in graph_payload(scan_id=self.new.id)['nodes'] if n['kind'] == 'subdomain']
		self.assertEqual([n['info']['project'] for n in nodes], ['P'])


class OrderingApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.project = Project.objects.create(name='S', slug='proj-s', insert_date=now, org=Org.objects.create(name='S', slug='so'))
		cls.domain = Domain.objects.create(name='s.test', project=cls.project, insert_date=now)
		user = User.objects.create_user('sorter', password='x')
		ProjectMembership.objects.create(user=user, project=cls.project, role='user')
		_, cls.token = create_token(user, 't')
		for name, score in (('a.s.test', 5), ('b.s.test', 90), ('c.s.test', 40), ('d.s.test', 90)):
			Subdomain.objects.create(name=name, target_domain=cls.domain, score=score, score_detail=[{'label': 'x', 'points': score}])

	def hosts(self, path):
		status, data = call(self.token, 'GET', f'/api/v1/projects/proj-s/{path}')
		self.assertEqual(status, 200, data)
		return [h['host'] for h in data['results']]

	def test_hosts_and_search_come_highest_score_first_and_sort_name_keeps_the_old_order(self):
		self.assertEqual(self.hosts('hosts'), ['b.s.test', 'd.s.test', 'c.s.test', 'a.s.test'])
		self.assertEqual(self.hosts('search'), ['b.s.test', 'd.s.test', 'c.s.test', 'a.s.test'])
		self.assertEqual(self.hosts('search?q=s.test&sort=name'), ['a.s.test', 'b.s.test', 'c.s.test', 'd.s.test'])
		self.assertEqual(self.hosts('hosts?sort=name'), ['a.s.test', 'b.s.test', 'c.s.test', 'd.s.test'])

	def test_the_score_and_its_reasons_are_in_the_host(self):
		status, data = call(self.token, 'GET', '/api/v1/projects/proj-s/hosts')
		self.assertEqual((data['results'][0]['score'], data['results'][0]['score_detail']), (90, [{'label': 'x', 'points': 90}]))

	def test_a_bad_sort_is_a_400(self):
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/proj-s/search?sort=bogus')[0], 400)
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/proj-s/hosts?sort=bogus')[0], 400)
