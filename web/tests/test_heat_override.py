"""A heat set by hand (``Triage.heat_override``): a person or an agent re-rates a CVE match or a scanner finding fire, smoke or ice with a reason,
and the heat set wins everywhere a heat is read (``cveFeed.threat``: the Python and database forms, capped and not), until cleared.

Written for the operator who reviewed findings through the MCP API and found 4 that should be fire and 107 rated too high, with no way to
say so: REST (one and bulk), MCP (``set_finding_heat``), the audit trail, paging, and that triage, re-triage and rescans keep it."""
import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from agentapi import mcp, services
from agentapi.auth import create_token
from cveFeed import hot_validation, notify, openvas_scan, threat, triage
from cveFeed.models import CVEEntry, CVEMatch, FindingAuditEvent, HygieneFinding, Triage
from cveFeed.threat import FIRE, HEAT_RANK, ICE, SMOKE
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import CveId, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call
from tests.test_heat_policy import LEGACY, Policy

PROVEN = {'source': 'tech', 'version_source': 'body', 'version_confidence': 0.9, 'copy_state': 'effective', 'script_url': 'https://x/lib.js',
		  'copies': [{'url': 'https://x/lib.js', 'source': 'body', 'state': 'effective'}]}


class Fixture(Policy, TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org, other = Org.objects.create(name='Heat', slug='heat-org'), Org.objects.create(name='Else', slug='heat-else')
		cls.proj = Project.objects.create(name='Heat', slug='heat-proj', insert_date=now, org=cls.org)
		cls.other = Project.objects.create(name='Else', slug='heat-else-proj', insert_date=now, org=other)
		cls.domain = Domain.objects.create(name='example.com', project=cls.proj, insert_date=now)
		cls.other_domain = Domain.objects.create(name='else.example.com', project=cls.other, insert_date=now)
		engine = EngineType.objects.create(engine_name='heat-e', yaml_configuration='x', default_engine=True)
		cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, scan_status=2, start_scan_date=now)
		other_scan = ScanHistory.objects.create(domain=cls.other_domain, scan_type=engine, scan_status=2, start_scan_date=now)
		cls.sub = Subdomain.objects.create(name='www.example.com', target_domain=cls.domain, scan_history=cls.scan)
		cls.other_sub = Subdomain.objects.create(name='www.else.example.com', target_domain=cls.other_domain, scan_history=other_scan)
		mk = lambda n: User.objects.create_user(n, password='x')  # noqa: E731
		cls.alice, cls.viewer, cls.outsider = mk('heat-alice'), mk('heat-viewer'), mk('heat-outsider')
		ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
		ProjectMembership.objects.create(user=cls.viewer, project=cls.proj, role='audit')
		OrgMembership.objects.create(user=cls.outsider, org=other, role='admin')
		_, cls.t_alice = create_token(cls.alice, 'agent')
		_, cls.t_ro = create_token(cls.alice, 'ro', read_only=True)
		_, cls.t_viewer = create_token(cls.viewer, 'viewer')
		_, cls.t_out = create_token(cls.outsider, 'out')
		cls.kev = CVEEntry.objects.create(cve_id='CVE-2099-8801', cvss=9.8, kev=True, published_at=now, affected=[])
		cls.cold = CVEEntry.objects.create(cve_id='CVE-2099-8802', cvss=9.8, epss_reached=True, published_at=now, affected=[])
		CveId.objects.create(name='CVE-2099-8801')

	def setUp(self):
		super().setUp()
		mk = lambda cve, product, **f: CVEMatch.objects.create(  # noqa: E731
			cve_entry=cve, subdomain=self.sub, source='tech', matched_product=product, matched_version='1.2', version_in_range=True,
			confidence=0.8, ai_verdict='uncertain', scan_history=self.scan, **f)
		self.fire = mk(self.kev, 'lib-a', evidence=dict(PROVEN))         # on the KEV, version read from the file: fire
		self.smoke = mk(self.kev, 'lib-b', evidence={'source': 'tech'})  # on the KEV, version only inferred: smoke
		self.ice = mk(self.cold, 'lib-c', evidence=dict(PROVEN))         # not on the KEV, no exploit: ice
		self.vuln = Vulnerability.objects.create(name='Exposed panel', severity=3, subdomain=self.sub, target_domain=self.domain,
												 open_status=True, http_url='https://www.example.com/', source='nuclei')
		self.hyg = HygieneFinding.objects.create(domain=self.domain, host='www.example.com', check_name='spf_missing', severity=2, title='No SPF')
		self.foreign = CVEMatch.objects.create(cve_entry=self.kev, subdomain=self.other_sub, source='tech', matched_product='lib-a',
											   matched_version='1.2', version_in_range=True, evidence=dict(PROVEN), confidence=0.8)

	base = '/api/v1/projects/heat-proj'

	def load(self, match):
		return CVEMatch.objects.select_related('cve_entry', 'triage__heat_override_by').get(pk=match.pk)

	def override(self, finding, heat, reason='reviewed by hand', by=None):
		"""A Triage row with a heat set, the way triage makes rows (``triage.track``)."""
		row = triage.track([finding])[0][0]
		Triage.objects.filter(pk=row.pk).update(heat_override=heat, heat_override_reason=reason, heat_override_by=by or self.alice,
												 heat_override_at=timezone.now())
		return row

	def put(self, kind, obj, heat, reason='reviewed by hand', token=None):
		return call(token or self.t_alice, 'POST', f'{self.base}/findings/{kind}/{obj.pk}/heat', {'heat': heat, 'reason': reason})


class SchemaTests(TestCase):
	def test_the_new_columns_have_database_defaults_for_the_update_window(self):
		"""The upgrade rehearsal's schema check (.github/rehearsal/schema.sh): a new NOT NULL column on an existing table needs a database
		default, or the previous release's inserts fail until its workers restart."""
		for name in ('heat_override', 'heat_override_reason'):
			self.assertEqual(Triage._meta.get_field(name).db_default, '')
		for name in ('heat_override_by', 'heat_override_at'):
			self.assertTrue(Triage._meta.get_field(name).null)
		with connection.cursor() as cur:
			cur.execute("select column_name, is_nullable, column_default from information_schema.columns "
						"where table_name = 'cveFeed_triage' and column_name like 'heat_override%%'")
			columns = {name: (nullable, default) for name, nullable, default in cur.fetchall()}
		self.assertEqual(set(columns), {'heat_override', 'heat_override_reason', 'heat_override_by_id', 'heat_override_at'})
		risky = [name for name, (nullable, default) in columns.items() if nullable == 'NO' and default is None]
		self.assertEqual(risky, [])

	def test_the_migration_sets_the_defaults_itself(self):
		from importlib import import_module
		migration = import_module('cveFeed.migrations.0142_triage_heat_override').Migration
		added = {op.name: op.field for op in migration.operations if op.__class__.__name__ == 'AddField'}
		self.assertEqual({added[n].db_default for n in ('heat_override', 'heat_override_reason')}, {''})


class ReadPathTests(Fixture):
	def test_derived_heats_before_any_override(self):
		self.assertEqual([threat.match_heat(self.load(m)) for m in (self.fire, self.smoke, self.ice)], [FIRE, SMOKE, ICE])

	def test_an_override_wins_in_python_capped_and_not_under_either_policy(self):
		self.override(self.fire, ICE)
		self.override(self.smoke, FIRE)
		self.override(self.ice, SMOKE)
		for env in ({}, LEGACY):
			with mock.patch.dict(os.environ, env):
				for match, want in ((self.fire, ICE), (self.smoke, FIRE), (self.ice, SMOKE)):
					m = self.load(match)
					self.assertEqual((threat.match_heat(m), threat.match_heat(m, capped=False), threat.validation_heat(m)), (want, want, want), env)
					self.assertEqual(threat.heat_reason(m), f'set to {want} by heat-alice: reviewed by hand')

	def test_an_override_wins_in_the_database_form_with_one_query(self):
		self.override(self.fire, ICE)
		self.override(self.smoke, FIRE)
		self.override(self.ice, SMOKE)
		want = {self.fire.pk: HEAT_RANK[ICE], self.smoke.pk: HEAT_RANK[FIRE], self.ice.pk: HEAT_RANK[SMOKE]}
		for env in ({}, LEGACY):
			with mock.patch.dict(os.environ, env):
				for capped in (True, False):
					with self.assertNumQueries(1):
						ranks = dict(CVEMatch.objects.annotate(h=threat.match_heat_rank_expr(capped)).values_list('pk', 'h'))
					self.assertEqual({pk: ranks[pk] for pk in want}, want, (env, capped))
					# a match without one keeps the derived heat, the same in both forms
					self.assertEqual(ranks[self.foreign.pk], HEAT_RANK[threat.match_heat(self.load(self.foreign), capped=capped)], (env, capped))

	def test_a_scanner_finding_follows_its_override_in_both_forms(self):
		self.vuln.cve_ids.add(CveId.objects.get(name='CVE-2099-8801'))
		v = Vulnerability.objects.prefetch_related('cve_ids', 'tags').get(pk=self.vuln.pk)
		self.assertEqual(threat.finding_heat(v), FIRE)
		self.override(self.vuln, ICE, reason='a test page')
		for env in ({}, LEGACY):
			with mock.patch.dict(os.environ, env):
				v = Vulnerability.objects.select_related('triage__heat_override_by').prefetch_related('cve_ids', 'tags').get(pk=self.vuln.pk)
				self.assertEqual((threat.finding_heat(v), threat.finding_heat(v, capped=False)), (ICE, ICE))
				self.assertEqual(threat.finding_heat_reason(v, ICE), 'set to ice by heat-alice: a test page')
				for capped in (True, False):
					self.assertEqual(Vulnerability.objects.annotate(h=threat.finding_heat_rank_expr(capped)).get(pk=v.pk).h, HEAT_RANK[ICE])
					# the validation lanes reach the finding from its Triage row
					row = Triage.objects.annotate(h=threat.finding_heat_rank_expr(capped, prefix='vulnerability__')).get(vulnerability=v)
					self.assertEqual(row.h, HEAT_RANK[ICE])

	def test_a_removed_user_still_reads(self):
		self.override(self.smoke, FIRE, by=User.objects.create_user('gone'))
		User.objects.filter(username='gone').delete()
		self.assertEqual(threat.heat_reason(self.load(self.smoke)), 'set to fire by a user no longer here: reviewed by hand')

	def test_the_findings_list_facet_and_counts_follow(self):
		before = services.list_findings(services.Ctx(user=self.alice), 'heat-proj', {'heat': 'smoke', 'type': 'cve'})
		self.assertEqual(before['counts']['cve'], 1)
		self.put('match', self.fire, SMOKE, 'only the login page is reachable')
		self.put('match', self.ice, SMOKE, 'an operator says so')
		status, data = call(self.t_alice, 'GET', f'{self.base}/findings?heat=smoke&type=cve')
		self.assertEqual((status, data['counts']['cve']), (200, 3))
		rows = {r['id']: r for r in data['results']}
		self.assertEqual(set(rows), {self.fire.pk, self.smoke.pk, self.ice.pk})
		self.assertEqual(rows[self.fire.pk]['heat_reason'], 'set to smoke by heat-alice: only the login page is reachable')
		self.assertEqual(rows[self.fire.pk]['heat_override']['heat'], SMOKE)
		self.assertEqual(rows[self.fire.pk]['heat_override']['by']['username'], 'heat-alice')
		self.assertIsNone(rows[self.smoke.pk]['heat_override'])
		self.assertFalse(rows[self.fire.pk]['heat_capped'])
		self.assertEqual(call(self.t_alice, 'GET', f'{self.base}/findings?heat=fire&type=cve')[1]['counts']['cve'], 0)

	def test_the_list_reads_no_query_per_overridden_row(self):
		ctx = services.Ctx(user=self.alice)
		services.list_findings(ctx, 'heat-proj', {'type': 'all'})  # warm what is cached per process
		quiet = self._count(lambda: services.list_findings(ctx, 'heat-proj', {'type': 'all'}))
		for m in (self.fire, self.smoke, self.ice):
			self.override(m, ICE, by=User.objects.create_user(f'u{m.pk}'))
		self.override(self.vuln, SMOKE)
		self.assertEqual(self._count(lambda: services.list_findings(ctx, 'heat-proj', {'type': 'all'})), quiet)

	def _count(self, fn):
		from django.test.utils import CaptureQueriesContext
		with CaptureQueriesContext(connection) as seen:
			fn()
		return len(seen.captured_queries)

	def test_host_heat_follows(self):
		ctx = services.Ctx(user=self.alice)
		host = lambda: next(h for h in services.list_hosts(ctx, 'heat-proj', {})['results'] if h['host'] == 'www.example.com')  # noqa: E731
		self.assertEqual(host()['heat'], FIRE)
		self.put('match', self.fire, SMOKE)
		self.put('vulnerability', self.vuln, SMOKE)
		got = host()
		self.assertEqual(got['heat'], SMOKE)
		self.assertIn('set to smoke by heat-alice: reviewed by hand', [r.get('heat_reason') for r in got['heat_reasons']])
		# the confirmer's view (validation heat: the KEV match whose version is not proven counts as fire there) follows too
		self.assertEqual(openvas_scan.host_heat(self.proj.id, [self.sub.name])[self.sub.name][0], FIRE)
		self.put('match', self.smoke, ICE, 'internal test box')
		self.assertEqual(host()['heat'], SMOKE)
		self.assertEqual(openvas_scan.host_heat(self.proj.id, [self.sub.name])[self.sub.name][0], SMOKE)
		self.put('match', self.ice, FIRE, 'confirmed by hand on the host')
		self.assertEqual(host()['heat'], FIRE)

	def test_the_validation_lanes_follow(self):
		cold, hot = self.override(self.ice, FIRE), self.override(self.smoke, ICE)
		fire_lane = {r.pk for r in hot_validation._candidate_rows(FIRE)}
		ice_lane = {r.pk for r in hot_validation._candidate_rows(ICE)}
		self.assertIn(cold.pk, fire_lane)
		self.assertNotIn(cold.pk, ice_lane)
		self.assertIn(hot.pk, ice_lane)
		self.assertNotIn(hot.pk, fire_lane)
		self.assertEqual(hot_validation.tier_for(Triage.objects.select_related('match__cve_entry').get(pk=cold.pk)), FIRE)


class WriteTests(Fixture):
	def test_set_then_clear_restores_the_derived_heat_and_audits_both(self):
		status, data = self.put('match', self.fire, 'Smoke', '  only reachable from the office  ')
		self.assertEqual(status, 200, data)
		self.assertEqual((data['heat'], data['changed'], data['heat_override']['heat'], data['heat_override']['reason']),
						 (SMOKE, True, SMOKE, 'only reachable from the office'))
		self.assertEqual(data['heat_reason'], 'set to smoke by heat-alice: only reachable from the office')
		row = Triage.objects.get(match=self.fire)
		self.assertEqual((row.heat_override, row.heat_override_by, row.heat_override_at is not None), (SMOKE, self.alice, True))
		self.assertEqual(self.put('match', self.fire, 'smoke', 'only reachable from the office')[1]['changed'], False)  # the same again
		status, data = call(self.t_alice, 'POST', f'{self.base}/findings/match/{self.fire.pk}/heat', {'heat': None, 'reason': 'rescan proved it'})
		self.assertEqual((status, data['heat'], data['heat_override'], data['changed']), (200, FIRE, None, True))
		row.refresh_from_db()
		self.assertEqual((row.heat_override, row.heat_override_reason, row.heat_override_by, row.heat_override_at), ('', '', None, None))
		audit = call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.fire.pk}/audit')[1]['results']
		self.assertEqual([(e['event'], e['before'], e['after']) for e in audit], [
			('heat', {'heat': SMOKE, 'override': SMOKE}, {'heat': FIRE, 'override': None, 'reason': 'rescan proved it'}),
			('heat', {'heat': FIRE, 'override': None}, {'heat': SMOKE, 'override': SMOKE, 'reason': 'only reachable from the office'})])
		self.assertEqual(audit[0]['actor']['username'], 'heat-alice')

	def test_a_finding_without_a_triage_row_gets_one(self):
		self.assertFalse(Triage.objects.filter(vulnerability=self.vuln).exists())
		status, data = self.put('vulnerability', self.vuln, ICE, 'a decoy page')
		self.assertEqual((status, data['heat']), (200, ICE), data)
		row = Triage.objects.get(vulnerability=self.vuln)
		self.assertEqual((row.kind, row.project_id, row.heat_override), ('nuclei', self.proj.pk, ICE))

	def test_the_detail_and_the_lists_carry_it(self):
		self.put('vulnerability', self.vuln, ICE, 'a decoy page')
		detail = call(self.t_alice, 'GET', f'{self.base}/findings/vulnerability/{self.vuln.pk}')[1]
		self.assertEqual((detail['heat'], detail['heat_reason'], detail['heat_override']['heat']), (ICE, 'set to ice by heat-alice: a decoy page', ICE))
		self.assertEqual(call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.fire.pk}')[1]['heat'], FIRE)
		hyg = call(self.t_alice, 'GET', f'{self.base}/findings/hygiene/{self.hyg.pk}')[1]
		self.assertEqual((hyg['heat'], hyg['heat_override']), (None, None))
		vulns = call(self.t_alice, 'GET', f'{self.base}/vulnerabilities')[1]['results']
		self.assertEqual(vulns[0]['heat_override']['reason'], 'a decoy page')
		self.put('match', self.ice, FIRE, 'exploited here')
		match = next(m for m in call(self.t_alice, 'GET', f'{self.base}/matches')[1]['results'] if m['id'] == self.ice.pk)
		self.assertEqual((match['cve']['tier'], match['cve']['validation_tier'], match['heat_override']['heat']), (FIRE, FIRE, FIRE))
		row = next(r for r in call(self.t_alice, 'GET', f'{self.base}/findings?type=scanner&status=all')[1]['results'])
		self.assertEqual((row['heat'], row['heat_reason']), (ICE, 'set to ice by heat-alice: a decoy page'))

	def test_bad_requests_change_nothing(self):
		url = f'{self.base}/findings/match/{self.fire.pk}/heat'
		for body in ({'heat': 'lava', 'reason': 'x'}, {'heat': 3, 'reason': 'x'}, {'heat': 'fire'}, {'heat': 'fire', 'reason': '   '},
					 {'heat': 'fire', 'reason': 'x' * 1001}, {'heat': 'fire', 'reason': ['x']}):
			status, err = call(self.t_alice, 'POST', url, body)
			self.assertEqual(status, 400, (body, err))
		for kind, obj in (('hygiene', self.hyg),):
			status, err = self.put(kind, obj, FIRE)
			self.assertEqual(status, 400)
			self.assertIn('no heat', err['error'])
		self.assertEqual(call(self.t_alice, 'POST', f'{self.base}/findings/route/1/heat', {'heat': 'fire', 'reason': 'x'})[0], 400)
		self.assertFalse(Triage.objects.exclude(heat_override='').exists())
		self.assertFalse(FindingAuditEvent.objects.filter(event='heat').exists())
		self.assertEqual(self.put('match', self.fire, FIRE, 'x' * 1000)[0], 200)

	def test_permissions_and_tenancy(self):
		self.assertEqual(self.put('match', self.fire, ICE, token=self.t_ro)[0], 403)
		self.assertEqual(self.put('match', self.fire, ICE, token=self.t_viewer)[0], 403)
		self.assertEqual(self.put('match', self.fire, ICE, token=self.t_out)[0], 404)  # another organization's user: the project is not there
		# a finding of another project through this one: 404 exactly like a missing one
		self.assertEqual(self.put('match', self.foreign, ICE)[0], 404)
		self.assertEqual(call(self.t_out, 'POST', f'/api/v1/projects/heat-else-proj/findings/match/{self.fire.pk}/heat',
							  {'heat': 'ice', 'reason': 'x'})[0], 404)
		self.assertEqual(call(self.t_alice, 'POST', f'/api/v1/projects/_all/findings/match/{self.fire.pk}/heat',
							  {'heat': 'ice', 'reason': 'x'})[0], 400)
		self.assertFalse(Triage.objects.exclude(heat_override='').exists())
		# the outsider may rate their own project's finding
		status, data = call(self.t_out, 'POST', f'/api/v1/projects/heat-else-proj/findings/match/{self.foreign.pk}/heat', {'heat': 'ice', 'reason': 'x'})
		self.assertEqual((status, data['heat']), (200, ICE))

	def test_bulk_rates_many_with_one_reason_and_reports_each_failure(self):
		items = [{'kind': 'match', 'id': self.fire.pk}, {'kind': 'match', 'id': self.smoke.pk}, {'kind': 'vulnerability', 'id': self.vuln.pk},
				 {'kind': 'match', 'id': self.foreign.pk}, {'kind': 'hygiene', 'id': self.hyg.pk}, {'kind': 'match'}, 'x',
				 {'kind': 'match', 'id': 'abc'}]
		status, data = call(self.t_alice, 'POST', f'{self.base}/findings/heat', {'items': items, 'heat': 'ice', 'reason': 'rated too high'})
		self.assertEqual(status, 200, data)
		self.assertEqual((data['updated'], data['unchanged']), (3, 0))
		self.assertEqual([(f['id'], f['error'][:20]) for f in data['failed']], [
			(self.foreign.pk, 'finding not found'), (self.hyg.pk, 'kind must be match o'), (None, 'each item must be an'), (None, 'each item must be an'),
			('abc', 'id must be a whole n')])
		self.assertEqual(Triage.objects.filter(heat_override=ICE).count(), 3)
		self.assertEqual(FindingAuditEvent.objects.filter(event='heat').count(), 3)
		again = call(self.t_alice, 'POST', f'{self.base}/findings/heat', {'items': items[:3], 'heat': 'ice', 'reason': 'rated too high'})[1]
		self.assertEqual((again['updated'], again['unchanged']), (0, 3))

	def test_bulk_cap_and_body_checks(self):
		url = f'{self.base}/findings/heat'
		over = [{'kind': 'match', 'id': self.fire.pk}] * (services.MAX_BULK_HEAT + 1)
		self.assertEqual(services.MAX_BULK_HEAT, 500)
		self.assertEqual(call(self.t_alice, 'POST', url, {'items': over, 'heat': 'ice', 'reason': 'x'})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', url, {'items': over[:500], 'heat': 'ice', 'reason': 'x'})[0], 200)
		self.assertEqual(call(self.t_alice, 'POST', url, {'items': [], 'heat': 'ice', 'reason': 'x'})[0], 400)
		self.assertEqual(call(self.t_alice, 'POST', url, {'items': over[:1], 'heat': 'ice'})[0], 400)
		self.assertEqual(call(self.t_ro, 'POST', url, {'items': over[:1], 'heat': 'fire', 'reason': 'x'})[0], 403)
		self.assertEqual(call(self.t_viewer, 'POST', url, {'items': over[:1], 'heat': 'fire', 'reason': 'x'})[0], 403)
		self.assertEqual(call(self.t_out, 'POST', url, {'items': over[:1], 'heat': 'fire', 'reason': 'x'})[0], 404)


class McpTests(Fixture):
	def test_the_tool_is_registered_documented_and_writes(self):
		self.assertIn('set_finding_heat', mcp.BY_NAME)
		self.assertTrue(mcp.BY_NAME['set_finding_heat'][4])  # a write: a read-only token is refused
		here = os.path.dirname(os.path.abspath(__file__))
		with open(os.path.join(here, '..', '..', 'docs', 'AGENT-API.md'), encoding='utf-8') as fh:
			doc = fh.read()
		self.assertIn('`set_finding_heat`', doc)
		self.assertIn('findings/heat', doc)

	def test_one_and_many(self):
		error, data = tool_call(self.t_alice, 'set_finding_heat', {'project': 'heat-proj', 'kind': 'match', 'id': self.smoke.pk, 'heat': 'fire',
																   'reason': 'exploited in our logs'})
		self.assertFalse(error, data)
		self.assertEqual((data['heat'], data['heat_override']['reason']), (FIRE, 'exploited in our logs'))
		error, data = tool_call(self.t_alice, 'set_finding_heat', {'project': 'heat-proj', 'heat': 'ice', 'reason': 'not reachable',
																   'items': [{'kind': 'match', 'id': self.fire.pk}, {'kind': 'vulnerability', 'id': self.vuln.pk}]})
		self.assertFalse(error, data)
		self.assertEqual((data['updated'], data['failed']), (2, []))
		error, data = tool_call(self.t_alice, 'set_finding_heat', {'project': 'heat-proj', 'kind': 'match', 'id': self.smoke.pk, 'heat': None})
		self.assertFalse(error, data)
		self.assertEqual((data['heat'], data['heat_override']), (SMOKE, None))
		self.assertTrue(tool_call(self.t_alice, 'set_finding_heat', {'project': 'heat-proj', 'heat': 'ice', 'reason': 'x'})[0])
		self.assertTrue(tool_call(self.t_ro, 'set_finding_heat', {'project': 'heat-proj', 'kind': 'match', 'id': self.fire.pk, 'heat': 'ice',
																  'reason': 'x'})[0])
		self.assertTrue(tool_call(self.t_out, 'set_finding_heat', {'project': 'heat-proj', 'kind': 'match', 'id': self.fire.pk, 'heat': 'ice',
																   'reason': 'x'})[0])
		audit = tool_call(self.t_alice, 'finding_audit', {'project': 'heat-proj', 'kind': 'match', 'id': self.smoke.pk})[1]['results']
		self.assertEqual([e['event'] for e in audit], ['heat', 'heat'])


class PagingTests(Fixture):
	def raise_(self, match, heat=FIRE):
		with self.captureOnCommitCallbacks(execute=True):
			return self.put('match', match, heat, 'seen exploited')

	def test_raising_to_fire_pages_once_and_never_again(self):
		notify.mark_announced([self.fire.pk, self.foreign.pk])  # the matches that were fire already were paged when they were found
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			self.raise_(self.smoke)
			self.assertEqual(sent.call_count, 1)
			self.assertIn('re-rated fire-tier by hand', sent.call_args[0][0])
			self.assertIn('CVE-2099-8801', sent.call_args[0][0])
			self.raise_(self.smoke, SMOKE)  # lowering never pages
			self.raise_(self.smoke)  # raised again: already announced under the rule in force
			for _ in range(3):  # reads never page
				call(self.t_alice, 'GET', f'{self.base}/findings?heat=fire')
			notify.fire_confirmed([self.smoke.pk])  # proof arriving later: no second page either
			notify.cves_turned_hot([self.kev.pk])
		self.assertEqual(sent.call_count, 1, sent.call_args_list)
		self.smoke.refresh_from_db()
		self.assertEqual(self.smoke.fire_notified_rule, threat.heat_signature())

	def test_a_closed_or_already_fire_match_is_not_paged(self):
		CVEMatch.objects.filter(pk=self.ice.pk).update(remediation_status='accepted_risk')
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			self.raise_(self.ice)
			self.raise_(self.fire)  # it was fire already: nothing changed on the host
		self.assertEqual(sent.call_count, 0)
		self.assertIsNone(CVEMatch.objects.get(pk=self.ice.pk).fire_notified_at)

	def test_clearing_back_to_a_derived_fire_pages_like_a_raise(self):
		self.override(self.fire, ICE)
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			with self.captureOnCommitCallbacks(execute=True):
				call(self.t_alice, 'POST', f'{self.base}/findings/match/{self.fire.pk}/heat', {'heat': None})
		self.assertEqual(sent.call_count, 1)

	def test_a_bulk_raise_is_one_message(self):
		other = CVEMatch.objects.create(cve_entry=self.cold, subdomain=self.sub, source='tech', matched_product='lib-d', matched_version='1',
										version_in_range=True, evidence={'source': 'tech'}, scan_history=self.scan)
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			with self.captureOnCommitCallbacks(execute=True):
				call(self.t_alice, 'POST', f'{self.base}/findings/heat', {'items': [{'kind': 'match', 'id': self.smoke.pk}, {'kind': 'match', 'id': other.pk}],
																		  'heat': 'fire', 'reason': 'both exploited'})
		self.assertEqual(sent.call_count, 1)
		self.assertIn('2 CVE matches re-rated', sent.call_args[0][0])


class KeepTests(Fixture):
	def test_re_triage_and_validation_writes_keep_the_override(self):
		self.put('match', self.smoke, FIRE, 'seen exploited')
		row = Triage.objects.get(match=self.smoke)
		# the evidence changed: triage resets the row (verdict, classification, validation plan) and keeps the heat set by hand
		CVEMatch.objects.filter(pk=self.smoke.pk).update(matched_version='1.3', evidence={'source': 'tech', 'changed': True})
		triage.track(triage.with_cves(CVEMatch.objects.filter(pk=self.smoke.pk).select_related('subdomain__target_domain')))
		# a fresh AI review requested by hand (the next track only re-queues it), then a validation writing its result
		match = triage.with_cves(CVEMatch.objects.filter(pk=self.smoke.pk).select_related('subdomain__target_domain'))[0]
		triage.request_fresh_review(Triage.objects.get(pk=row.pk), triage.describe(match), 'n' * 16)
		triage.track([match])
		fresh = Triage.objects.get(pk=row.pk)
		self.assertEqual(fresh.status, 'pending')
		fresh.validation_status, fresh.validation_steps = 'clean', [{'kind': 'x'}]
		fresh.save(update_fields=['validation_status', 'validation_steps', 'updated_at'])
		fresh.refresh_from_db()
		self.assertEqual((fresh.heat_override, fresh.heat_override_reason, fresh.heat_override_by_id), (FIRE, 'seen exploited', self.alice.pk))
		self.assertEqual(threat.match_heat(self.load(self.smoke)), FIRE)

	def test_a_rescan_of_the_same_evidence_keeps_it(self):
		self.put('match', self.smoke, ICE, 'internal test box')
		scan2 = ScanHistory.objects.create(domain=self.domain, scan_type=self.scan.scan_type, scan_status=2, start_scan_date=timezone.now())
		sub2 = Subdomain.objects.create(name='www.example.com', target_domain=self.domain, scan_history=scan2)
		again = CVEMatch.objects.create(cve_entry=self.kev, subdomain=sub2, source='tech', matched_product='lib-b', matched_version='1.2',
										version_in_range=True, evidence={'source': 'tech'}, confidence=0.8, ai_verdict='uncertain', scan_history=scan2)
		triage.track(triage.with_cves(CVEMatch.objects.filter(pk=again.pk).select_related('subdomain__target_domain')))
		row = Triage.objects.get(match=again)
		self.assertEqual((row.heat_override, row.heat_override_reason, row.heat_override_by_id), (ICE, 'internal test box', self.alice.pk))
		self.assertEqual(threat.match_heat(self.load(again)), ICE)

	def test_a_twin_window_keeps_rows_with_only_an_override(self):
		"""A row nobody triaged or validated (no AI configured) is still a twin when a person set its heat."""
		self.put('match', self.smoke, ICE, 'internal test box')
		row = Triage.objects.get(match=self.smoke)
		self.assertEqual((row.status, row.validation_status), ('pending', 'none'))
		Triage.objects.filter(pk=row.pk).update(updated_at=timezone.now() - timedelta(days=1))
		scan2 = ScanHistory.objects.create(domain=self.domain, scan_type=self.scan.scan_type, scan_status=2, start_scan_date=timezone.now())
		sub2 = Subdomain.objects.create(name='www.example.com', target_domain=self.domain, scan_history=scan2)
		again = CVEMatch.objects.create(cve_entry=self.kev, subdomain=sub2, source='tech', matched_product='lib-b', matched_version='1.2',
										version_in_range=True, evidence={'source': 'tech'}, confidence=0.8, ai_verdict='uncertain', scan_history=scan2)
		triage.track(triage.with_cves(CVEMatch.objects.filter(pk=again.pk).select_related('subdomain__target_domain')))
		self.assertEqual(Triage.objects.get(match=again).heat_override, ICE)
