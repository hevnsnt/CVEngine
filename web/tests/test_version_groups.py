"""Many CVEs, one fix: the CVE matches of one product version reading of one host as one group (cveFeed.version_groups), in the grouped
CVE match list (list_cve_matches group_by=product) and the grouped Findings list (list_findings group=product). Display only: every match
keeps its own row, and the ungrouped lists are what they were."""
import json

from django.contrib.auth.models import User
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.services import Ctx, list_findings, list_matches
from cveFeed import version_groups as vg
from cveFeed.models import CVEEntry, CVEMatch, Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

NOW = timezone.now()


def row(mid, cve, host, product='NGINX Open Source', version='1.31.1', heat=1, sev=3, fixed='1.31.9', introduced='1.31.0', project=1,
		classification='needs_validation', hard=False, **extra):
	"""A values() row as ``version_groups.rows_of`` reads it."""
	rng = {'introduced': introduced, **({'fixed': fixed} if fixed else {})}
	return {'id': mid, 'cve_entry_id': int(cve.rsplit('-', 1)[-1]), 'cve_entry__cve_id': cve, 'matched_product': product,
			'matched_version': version, 'source': 'tech', 'template_result': '', 'ai_verdict': '', 'remediation_status': 'open',
			'created_at': NOW, 'updated_at': NOW, 'subdomain_id': 1, 'subdomain__name': host, 'subdomain__target_domain__project_id': project,
			'triage__classification': classification, 'triage__validation_status': 'none', 'triage__first_seen': None,
			'triage__last_seen': None, 'heat_rank': heat, 'sev': sev, 'own_range': rng, 'affected_index': 0, 'hard': hard, **extra}


ALIASES = {(1, 'economicprinciples.org'): ('h', 7), (1, 'www.economicprinciples.org'): ('h', 7)}


def site_of(project, name):
	return ALIASES.get((project, name))


class GroupingHelperTests(SimpleTestCase):
	def test_the_same_version_on_two_aliases_is_one_group(self):
		rows = [row(i * 2 + n, f'CVE-2026-{100 + i}', host) for i in range(3)
				for n, host in enumerate(('economicprinciples.org', 'www.economicprinciples.org'))]
		built = vg.build(rows, site_of)
		self.assertEqual(len(built), 1)
		g = vg.summary(built[0])
		self.assertEqual((g['product'], g['version'], g['cves'], g['findings'], g['hosts']), ('nginx', '1.31.1', 3, 6, 2))
		self.assertEqual(g['host_names'], ['economicprinciples.org', 'www.economicprinciples.org'])
		self.assertEqual(sorted(g['member_ids']), [r['id'] for r in rows])
		# without the fold every name is its own site: two groups
		self.assertEqual(len(vg.build(rows)), 2)

	def test_different_versions_are_different_groups(self):
		rows = [row(1, 'CVE-2026-1', 'a.example'), row(2, 'CVE-2026-2', 'a.example'), row(3, 'CVE-2026-3', 'a.example', version='1.30.2')]
		built = vg.build(rows)
		self.assertEqual([len(i['members']) for i in built], [2, 1])
		self.assertEqual([i['key'][2] for i in built], ['1.31.1', '1.30.2'])

	def test_a_member_without_a_fix_is_named_and_the_others_give_the_version(self):
		rows = [row(1, 'CVE-2026-1', 'a.example', fixed='1.31.2'), row(2, 'CVE-2026-2', 'a.example', fixed='1.31.9'),
				row(3, 'CVE-2026-3', 'a.example', fixed='')]
		fix = vg.summary(vg.build(rows)[0])['fixed_in']
		self.assertEqual((fix['version'], fix['stated'], fix['unstated']), ('1.31.9', 2, ['CVE-2026-3']))
		self.assertEqual(vg.fix_text(fix), 'upgrade to 1.31.9 (1 of the CVEs states no fixed version)')
		none = vg.fix_summary([row(4, 'CVE-2026-4', 'a.example', fixed='')])
		self.assertEqual((none['version'], vg.fix_text(none)), ('', ''))  # never a guess

	def test_mixed_heat_takes_the_hottest_and_leaves_every_member_its_own(self):
		rows = [row(1, 'CVE-2026-1', 'a.example', heat=1, sev=2), row(2, 'CVE-2026-2', 'a.example', heat=2, sev=3),
				row(3, 'CVE-2026-3', 'a.example', heat=1, sev=4)]
		g = vg.summary(vg.build(rows)[0])
		self.assertEqual((g['heat'], g['severity']), ('smoke', 'critical'))
		self.assertEqual({m['id']: m['heat'] for m in g['members']}, {1: 'ice', 2: 'smoke', 3: 'ice'})
		self.assertEqual(g['heat_counts'], {'ice': 2, 'smoke': 1})
		self.assertEqual([r['heat_rank'] for r in rows], [1, 2, 1])  # nothing written back

	def test_jquery_and_nginx_are_separate_and_each_spelling_is_one_product(self):
		rows = [row(1, 'CVE-2026-1', 'a.example', product='NGINX Open Source'), row(2, 'CVE-2026-2', 'a.example', product='nginx'),
				row(3, 'CVE-2020-11022', 'a.example', product='jQuery', version='1.12.1', fixed='3.5.0', introduced='1.2.0', heat=2,
					classification='likely'),
				row(4, 'CVE-2019-11358', 'a.example', product='jquery', version='1.12.1', fixed='3.4.0', introduced='1.1.4',
					classification='confirmed')]
		built = vg.build(rows)
		self.assertEqual(len(built), 2)
		by = {vg.summary(i)['product']: vg.summary(i) for i in built}
		self.assertEqual(set(by), {'nginx', 'jQuery'})
		self.assertEqual((by['jQuery']['cves'], by['jQuery']['fixed_in']['version'], by['jQuery']['heat']), (2, '3.5.0', 'smoke'))
		self.assertEqual(by['jQuery']['triage'], {'needs_validation': 0, 'likely': 1, 'confirmed': 1, 'other': 0})
		self.assertEqual(by['nginx']['triage'], {'needs_validation': 2, 'likely': 0, 'confirmed': 0, 'other': 0})

	def test_hard_evidence_and_a_missing_version_stay_their_own_rows(self):
		rows = [row(1, 'CVE-2026-1', 'a.example'), row(2, 'CVE-2026-2', 'a.example', hard=True), row(3, 'CVE-2026-3', 'a.example', version='')]
		self.assertEqual([len(i['members']) for i in vg.build(rows)], [1, 1, 1])

	def test_never_across_projects(self):
		rows = [row(1, 'CVE-2026-1', 'a.example'), row(2, 'CVE-2026-2', 'a.example', project=2)]
		self.assertEqual(len(vg.build(rows)), 2)

	def test_another_release_line_is_offered_only_when_every_member_leaves_it_outside(self):
		every = {'ranges': [{'fixed': '1.31.9', 'introduced': '1.31.0'}, {'fixed': '1.30.7', 'introduced': '1.30.0'}, {'introduced': '0.5.33'}]}
		rows = [row(1, 'CVE-2026-1', 'a.example'), row(2, 'CVE-2026-2', 'a.example', fixed='1.31.7')]
		affected = {1: [every], 2: [{'ranges': [{'fixed': '1.31.7', 'introduced': '1.31.0'}, {'fixed': '1.30.6', 'introduced': '1.30.0'}]}]}
		fix = vg.fix_summary(rows, affected)
		self.assertEqual((fix['version'], fix['also'], fix['held_by']), ('1.31.9', ['1.30.7'], []))
		self.assertEqual(vg.fix_text(fix), 'upgrade to 1.31.9 or 1.30.7')
		# a member whose own data puts 1.30.7 inside a range (1.13.10 up to 1.31.2) and states no 1.30 fix takes the other line away
		rows.append(row(3, 'CVE-2026-3', 'a.example', fixed='1.31.2', introduced='1.13.10'))
		affected[3] = [{'ranges': [{'fixed': '1.31.2', 'introduced': '1.13.10'}]}]
		fix = vg.fix_summary(rows, affected)
		self.assertEqual((fix['version'], fix['also']), ('1.31.9', []))
		# the same member as F5 writes it (CVE-2026-42055): the 1.30 line's own fix (1.30.2 up to 1.30.3) leaves 1.30.7 outside the wide range
		affected[3] = [{'ranges': [{'fixed': '1.31.2', 'introduced': '1.13.10'}, {'fixed': '1.30.3', 'introduced': '1.30.2'}]}]
		fix = vg.fix_summary(rows, affected)
		self.assertEqual((fix['version'], fix['also'], fix['held_by']), ('1.31.9', ['1.30.7'], []))
		self.assertEqual(vg.fix_text(fix), 'upgrade to 1.31.9 or 1.30.7')

	def test_the_fix_is_raised_to_the_later_fix_of_its_line_another_member_states(self):
		"""nginx 1.24.0 matched on 1.13.10 up to 1.31.2 (own fix 1.31.2) beside a CVE whose 1.31 line is fixed in 1.31.9: 1.31.2 is not the
		release that settles the group, 1.31.9 is."""
		rows = [row(1, 'CVE-2026-1', 'a.example', version='1.24.0', fixed='1.31.2', introduced='1.13.10'),
				row(2, 'CVE-2026-2', 'a.example', version='1.24.0', fixed='1.30.7', introduced='1.25.5')]
		affected = {1: [{'ranges': [{'fixed': '1.31.2', 'introduced': '1.13.10'}, {'fixed': '1.30.3', 'introduced': '1.30.2'}]}],
					2: [{'ranges': [{'fixed': '1.31.9', 'introduced': '1.31.0'}, {'fixed': '1.30.7', 'introduced': '1.25.5'}]}]}
		fix = vg.fix_summary(rows, affected)
		self.assertEqual((fix['version'], fix['also'], fix['held_by']), ('1.31.9', ['1.30.7'], []))
		# without the advisories' data the own fixes are all there is: the highest one, as before
		self.assertEqual(vg.fix_summary(rows)['version'], '1.31.2')

	def test_the_note_says_the_group_rests_on_the_version(self):
		g = vg.summary(vg.build([row(1, 'CVE-2026-1', 'a.example'), row(2, 'CVE-2026-2', 'a.example')])[0])
		self.assertTrue(g['version_only'])
		self.assertIn('rest on the version read (nginx 1.31.1)', g['note'])
		self.assertIn('none of them is confirmed', g['note'])


class GroupedListTests(TestCase):
	"""Two names on one address serve one site (economicprinciples.org and www.), each stored twice (a scanless copy beside the scan's),
	with nginx 1.31.1 and jQuery 1.12.1 read from the fingerprint."""

	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Principles', slug='vg-org')
		cls.project = Project.objects.create(name='Principles', slug='vg-p', insert_date=NOW, org=org)
		cls.domain = Domain.objects.create(name='economicprinciples.org', project=cls.project, insert_date=NOW)
		scan = ScanHistory.objects.create(start_scan_date=NOW, scan_status=2, domain=cls.domain,
										  scan_type=EngineType.objects.create(engine_name='vg', yaml_configuration='x'))
		ip = IpAddress.objects.create(address='203.0.113.80')
		cls.subs = {}
		for name in ('economicprinciples.org', 'www.economicprinciples.org'):
			old = Subdomain.objects.create(name=name, target_domain=cls.domain)
			new = Subdomain.objects.create(name=name, target_domain=cls.domain, scan_history=scan)
			old.ip_addresses.add(ip)
			new.ip_addresses.add(ip)
			cls.subs[name] = (old, new)
		cls.stage = Subdomain.objects.create(name='stage.economicprinciples.org', target_domain=cls.domain, scan_history=scan)
		cls.stage.ip_addresses.add(IpAddress.objects.create(address='203.0.113.81'))
		cls.nginx = [CVEEntry.objects.create(cve_id=f'CVE-2026-{900 + i}', cvss=7.5 if i % 2 else 5.3, title='nginx', published_at=NOW,
											 affected=[{'product': 'NGINX Open Source', 'ranges': [{'introduced': '1.31.0', 'fixed': '1.31.9'},
																								   {'introduced': '1.30.0', 'fixed': '1.30.7'}]}])
					 for i in range(3)]
		cls.jq = CVEEntry.objects.create(cve_id='CVE-2020-11022', cvss=6.9, title='jQuery', published_at=NOW, exploit_db=True,
										 affected=[{'product': 'jQuery', 'ranges': [{'introduced': '1.2.0', 'fixed': '3.5.0'}]}])
		cls.matches = []
		for name, (old, new) in cls.subs.items():
			for sub in (old, new):
				for cve in cls.nginx:
					cls.matches.append(cls.match(cve, sub, 'NGINX Open Source', '1.31.1', {'introduced': '1.31.0', 'fixed': '1.31.9'}))
			cls.matches.append(cls.match(cls.jq, new, 'jQuery', '1.12.1', {'introduced': '1.2.0', 'fixed': '3.5.0'}))
		cls.on_stage = cls.match(cls.nginx[0], cls.stage, 'nginx', '1.18.0', {'introduced': '1.0.0', 'fixed': '1.31.9'})
		cls.proven = cls.match(cls.nginx[1], cls.subs['economicprinciples.org'][1], 'nginx', '1.31.1', {'introduced': '1.31.0', 'fixed': '1.31.9'},
							   template_result='vulnerable')
		user = User.objects.create_user('vg-alice', password='x')
		ProjectMembership.objects.create(user=user, project=cls.project, role='user')
		cls.ctx = Ctx(user=user)
		_, cls.token = create_token(user, 'vg')

	@classmethod
	def match(cls, cve, sub, product, version, rng, **extra):
		m = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product=product, matched_version=version, source='tech',
									evidence={'source': 'tech', 'range': rng, 'affected_index': 0}, **extra)
		Triage.objects.create(project=cls.project, domain=cls.domain, host=sub.name, kind='cve_match', match=m, status='triaged',
							  classification='needs_validation')
		return m

	def grouped(self, **params):
		return list_matches(self.ctx, 'vg-p', {'group_by': 'product', **params})

	def test_one_group_per_product_version_of_one_site(self):
		body = self.grouped()
		groups = [r for r in body['results'] if 'single' not in r]
		singles = [r['single'] for r in body['results'] if 'single' in r]
		self.assertEqual(body['findings_total'], len(self.matches) + 2)
		by = {(g['product'], g['version']): g for g in groups}
		nginx = by[('nginx', '1.31.1')]
		self.assertEqual((nginx['cves'], nginx['findings'], nginx['hosts']), (3, 12, 2))
		self.assertEqual(nginx['host_names'], ['economicprinciples.org', 'www.economicprinciples.org'])
		self.assertEqual(nginx['fix_text'], 'upgrade to 1.31.9 or 1.30.7')
		self.assertEqual(nginx['triage']['needs_validation'], 12)
		jq = by[('jQuery', '1.12.1')]
		self.assertEqual((jq['cves'], jq['findings'], jq['fix_text']), (1, 2, 'upgrade to 3.5.0'))
		# the proven match stays its own, and so does the other host's nginx
		self.assertEqual({s['id'] for s in singles}, {self.proven.id, self.on_stage.id})
		self.assertEqual(sum(g['findings'] for g in groups) + len(singles), body['findings_total'])
		# every match is reachable by id from the groups
		self.assertEqual(sorted(i for g in groups for i in g['member_ids']) + sorted(s['id'] for s in singles),
						 sorted(m.id for m in self.matches) + sorted([self.proven.id, self.on_stage.id]))

	def test_groups_page_with_a_next_marker(self):
		first = self.grouped(page_size=2)
		self.assertEqual((first['count'], len(first['results']), first['has_more'], first['next_page']), (4, 2, True, 2))
		second = self.grouped(page_size=2, page=2)
		self.assertEqual((len(second['results']), second['has_more'], second['next_page']), (2, False, None))
		ids = [json.dumps(r, sort_keys=True) for r in first['results'] + second['results']]
		self.assertEqual(len(set(ids)), 4)

	def test_the_default_list_is_unchanged(self):
		for params in ({}, {'host': 'economicprinciples.org'}, {'page_size': '5', 'page': '2'}):
			plain = list_matches(self.ctx, 'vg-p', dict(params))
			named = list_matches(self.ctx, 'vg-p', {**params, 'group_by': 'none'})
			self.assertEqual(json.dumps(plain, sort_keys=True, default=str), json.dumps(named, sort_keys=True, default=str))
			self.assertNotIn('group_by', plain)
			self.assertTrue(all('cve' in r and 'explain' in r for r in plain['results']))
		for params in ({}, {'type': 'cve'}):
			plain = list_findings(self.ctx, 'vg-p', dict(params))
			named = list_findings(self.ctx, 'vg-p', {**params, 'group': 'none'})
			self.assertEqual(json.dumps(plain, sort_keys=True, default=str), json.dumps(named, sort_keys=True, default=str))
			self.assertFalse(any('group' in r for r in plain['results']))

	def test_a_bad_group_by_is_refused(self):
		status, body = call(self.token, 'GET', '/api/v1/projects/vg-p/matches?group_by=cve')
		self.assertEqual(status, 400, body)

	def test_rest_and_mcp_answer_the_same_groups(self):
		status, rest = call(self.token, 'GET', '/api/v1/projects/vg-p/matches?group_by=product')
		self.assertEqual(status, 200, rest)
		error, mcp = tool_call(self.token, 'list_cve_matches', {'project': 'vg-p', 'group_by': 'product'})
		self.assertFalse(error, mcp)
		self.assertEqual(json.dumps(rest, sort_keys=True), json.dumps(mcp, sort_keys=True))
		error, plain = tool_call(self.token, 'list_cve_matches', {'project': 'vg-p'})
		self.assertFalse(error, plain)
		self.assertNotIn('group_by', plain)

	def test_the_findings_list_groups_by_product_and_keeps_each_member_actionable(self):
		body = list_findings(self.ctx, 'vg-p', {'type': 'cve', 'group': 'product'})
		self.assertEqual(body['group'], 'product')
		self.assertEqual(body['counts']['cve'], len(self.matches) + 2)  # the per-finding count is unchanged
		self.assertEqual(body['row_counts']['cve'], 4)
		groups = [r for r in body['results'] if r.get('group')]
		nginx = next(r for r in groups if r['group']['product'] == 'nginx')
		self.assertEqual(nginx['kind'], 'match')
		self.assertIn(nginx['id'], nginx['group']['member_ids'])
		self.assertEqual(nginx['group']['fix_text'], 'upgrade to 1.31.9 or 1.30.7')
		# a member is still its own finding: one status change moves it alone
		member = nginx['group']['member_ids'][-1]
		status, _ = call(self.token, 'PATCH', f'/api/v1/projects/vg-p/matches/{member}', {'status': 'in_progress'})
		self.assertEqual(status, 200)
		self.assertEqual(CVEMatch.objects.get(pk=member).remediation_status, 'in_progress')
		self.assertEqual(CVEMatch.objects.filter(pk__in=nginx['group']['member_ids'], remediation_status='open').count(),
						 len(nginx['group']['member_ids']) - 1)

	def test_the_grouped_list_costs_the_same_queries_however_many_groups(self):
		self.grouped()  # warm the per-process caches (policy, libraries)
		with CaptureQueriesContext(connection) as all_rows:
			self.grouped()
		with CaptureQueriesContext(connection) as one_host:
			self.grouped(host='stage.')
		self.assertLessEqual(len(all_rows), len(one_host) + 1)  # the host filter adds its own reads; the groups add none
		# access (3), the matches with the current-scan rule (2), the names' current rows and their fold (2), the page's affected ranges (1)
		self.assertLessEqual(len(all_rows), 10, [q['sql'][:120] for q in all_rows.captured_queries])
