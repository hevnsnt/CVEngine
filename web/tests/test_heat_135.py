"""1.3.5 heat audit (items 1-4 and the heat half of 5), each from a synthetic copy of the stored inputs that rated wrong.

1. A version-only match is smoke at most, KEV or not, even when its version is proven (read from the library file itself): fire needs proof
   of the flaw (a template hit, a validation hit, a host-side check). The Python and database forms agree on the fixture rows.
2. The rules never classify a CVE match above its detection strategy's ``validation.max_remote_state`` on remote evidence (the library rule
   lifted a page's jQuery to confirmed though the strategy says likely at most); "overridden" then reads what the row shows.
3. Exploit-DB alone never lifts a version-only match above smoke, under either heat policy.
4. Triage pending or needs_validation is smoke at most, a validation that came back clean is ice; a validation hit or a template hit that
   showed the flaw lifts both (a confirmation stands).
5. A scanner finding rated by its template's severity alone is smoke until a validation reproduces it; cvENGINE's own checks are not held.

And the dry-run re-rating report (``manage.py rerate_findings``): before/after per project, nothing written without ``--apply``, and no
page sent either way.
"""
import io
import os
from types import SimpleNamespace
from unittest import mock

from django.core.management import call_command
from django.utils import timezone

from cveFeed import notify, rerate, scoring, threat, triage
from cveFeed.models import CVEDetection, CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, HEAT_RANK, ICE, SMOKE
from startScan.models import Subdomain, Vulnerability
from tests.test_heat_policy import LEGACY, Policy
from tests.test_match_policy import Fixture

LEGACY_CAP_FIRE = {**LEGACY, threat.VERSION_ONLY_MAX_HEAT_ENV: 'fire'}
SCRIPT = 'https://www.example.test/js/jquery-3.1.1.min.js'
# what correlation records for the copy the page runs, whose own banner states the version (version proven, flaw not shown)
LIBRARY_BANNER = {'source': 'tech', 'version_source': 'body', 'version_confidence': 0.9, 'copy_state': 'effective', 'script_url': SCRIPT,
				  'copies': [{'url': SCRIPT, 'source': 'body', 'state': 'effective', 'version': '3.1.1'}]}
NAMES = {rank: heat for heat, rank in HEAT_RANK.items()}


class Base(Policy, Fixture):
	def setUp(self):
		super().setUp()
		self.sends = []
		send = mock.patch.object(notify, '_send', side_effect=lambda text, flag, channels=(): self.sends.append(text) or True)
		send.start()
		self.addCleanup(send.stop)

	def entry(self, cve_id, **signals):
		signals = {'kev': False, 'exploit_db': False, 'epss_reached': False, 'cvss': None, **signals}
		return CVEEntry.objects.create(cve_id=cve_id, published_at=timezone.now(), affected=[], **signals)

	def jquery(self, cve, version='3.1.1', evidence=None, **fields):
		"""A jQuery match on the host (each with its own product label: one match per CVE, host, source and product)."""
		taken = CVEMatch.objects.filter(cve_entry=cve, subdomain=self.sub).count()
		return self.match_for(cve, product='jQuery' if not taken else f'jQuery copy {taken}', version=version, in_range=True,
							  evidence=dict(evidence or LIBRARY_BANNER), **fields)

	def triaged(self, m, classification='', status='triaged', validation='none'):
		return Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='cve_match', match=m,
									 classification=classification, status=status, validation_status=validation)

	def heat(self, m):
		"""(Python heat, database heat) of a CVE match, which must agree."""
		m = CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=m.pk)
		sql = CVEMatch.objects.annotate(h=threat.match_heat_rank_expr()).get(pk=m.pk).h
		return threat.match_heat(m), NAMES[sql]

	def before(self, m):
		return rerate.before_match_heat(CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=m.pk), threat.heat_policy())


class VersionOnlyIsSmokeTests(Base):
	"""Item 1 (fixture: jQuery 3.1.1, CVE-2020-11023, version_only and version_proven, rated fire)."""

	def test_a_proven_jquery_version_on_a_kev_cve_is_smoke(self):
		cve = self.entry('CVE-2020-11023', kev=True, exploit_db=True, cvss=6.9, epss_reached=True)
		m = self.jquery(cve, ai_verdict='uncertain')
		self.triaged(m, 'confirmed', validation='observed')  # the library rule's confirmation, the body read observed
		self.assertEqual(self.before(m), FIRE)  # what 1.3.4 showed
		self.assertEqual(self.heat(m), (SMOKE, SMOKE))
		reason = threat.heat_reason(CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=m.pk))
		self.assertEqual(reason, 'on the KEV; version proven: read from the library file itself, but no check has shown the flaw: smoke until '
								 'one does')
		self.assertEqual(threat.validation_heat(CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=m.pk)), FIRE)  # validated first

	def test_the_older_jquery_on_an_exploit_db_cve_is_smoke_too(self):
		cve = self.entry('CVE-2020-11022', exploit_db=True, cvss=6.9, epss_reached=True)
		m = self.jquery(cve, version='1.12.1', ai_verdict='affected')
		self.triaged(m, 'confirmed')
		self.assertEqual((self.before(m), self.heat(m)), (FIRE, (SMOKE, SMOKE)))

	def test_proof_of_the_flaw_makes_it_fire(self):
		cve = self.entry('CVE-2020-11023', kev=True, cvss=6.9)
		for label, fields, validation in (('template hit', {'template_result': 'vulnerable'}, 'none'),
										  ('validation hit', {}, 'hit'),
										  ('host inventory', {'evidence': {**LIBRARY_BANNER, 'host_reported': {'inventory_id': 1}}}, 'none')):
			with self.subTest(label):
				m = self.jquery(cve, **fields, ai_verdict='affected')
				self.triaged(m, 'likely', validation=validation)
				self.assertEqual(self.heat(m), (FIRE, FIRE))

	def test_the_forms_agree_on_every_fixture_row(self):
		cves = [self.entry('CVE-2020-11023', kev=True, exploit_db=True, cvss=6.9), self.entry('CVE-2020-11022', exploit_db=True, cvss=6.9),
				self.entry('CVE-2020-7656', exploit_db=True), self.entry('CVE-2099-0001', cvss=9.8, epss_reached=True)]
		states = [('', 'pending', 'none'), ('needs_validation', 'triaged', 'none'), ('likely', 'triaged', 'none'),
				  ('confirmed', 'triaged', 'observed'), ('needs_validation', 'triaged', 'hit'), ('likely', 'triaged', 'clean'), None]
		evidence = [{}, {'template_result': 'vulnerable'}, {'evidence': {**LIBRARY_BANNER, 'runzero': True}},
					{'evidence': {'source': 'tech', 'version_source': 'filename', 'version_confidence': 0.4}}]
		n = 0
		for cve in cves:
			for fields in evidence:
				for state in states:
					n += 1
					m = self.jquery(cve, version=f'1.{n}', **fields)
					if state:
						self.triaged(m, *state)
		for policy in ({}, LEGACY, LEGACY_CAP_FIRE):
			with mock.patch.dict(os.environ, policy):
				sql = dict(CVEMatch.objects.annotate(h=threat.match_heat_rank_expr()).values_list('pk', 'h'))
				for m in CVEMatch.objects.select_related('cve_entry', 'triage'):
					self.assertEqual(HEAT_RANK[threat.match_heat(m)], sql[m.pk], (policy, m.cve_entry.cve_id, m.evidence, m.template_result))


class ExploitDbAloneTests(Base):
	"""Item 3 (fixture: CVE-2020-7656, no CVSS, a low EPSS, Exploit-DB only, rated fire on a version string)."""

	def test_exploit_db_alone_never_lifts_a_version_only_match(self):
		cve = self.entry('CVE-2020-7656', exploit_db=True)
		m = self.jquery(cve, version='1.8.3', ai_verdict='uncertain')
		self.triaged(m, 'likely')
		self.assertEqual((self.before(m), self.heat(m)), (FIRE, (SMOKE, SMOKE)))  # kev policy
		with mock.patch.dict(os.environ, LEGACY_CAP_FIRE):  # legacy with the version-only cap at fire: still not above smoke
			self.assertEqual((self.before(m), self.heat(m)), (FIRE, (SMOKE, SMOKE)))
		CVEMatch.objects.filter(pk=m.pk).update(template_result='vulnerable')  # proof of the flaw: Exploit-DB counts again
		for policy in ({}, LEGACY_CAP_FIRE, LEGACY):
			with mock.patch.dict(os.environ, policy):
				self.assertEqual(self.heat(m), (FIRE, FIRE), policy)

	def test_kev_or_a_critical_score_still_rates_by_the_legacy_cap(self):
		kev = self.jquery(self.entry('CVE-2099-0002', kev=True, exploit_db=True), ai_verdict='uncertain')
		critical = self.jquery(self.entry('CVE-2099-0003', exploit_db=True, cvss=9.8), version='1.2', ai_verdict='uncertain')
		for m in (kev, critical):
			self.triaged(m, 'likely')
		with mock.patch.dict(os.environ, LEGACY_CAP_FIRE):  # the owner's rollback knob still lifts these: not Exploit-DB alone
			self.assertEqual((self.heat(kev), self.heat(critical)), ((FIRE, FIRE), (FIRE, FIRE)))
		self.assertTrue(threat.exploit_db_alone(SimpleNamespace(exploit_db=True, kev=False, cvss=6.1, epss_reached=True)))
		self.assertFalse(threat.exploit_db_alone(SimpleNamespace(exploit_db=True, kev=False, cvss=7.5, epss_reached=True)))
		self.assertFalse(threat.exploit_db_alone(SimpleNamespace(exploit_db=True, kev=False, cvss=7.5, epss_reached=False), 'affected'))


class TriageStateTests(Base):
	"""Item 4 (fixtures: CVE-2020-11022 matches still pending or classified needs_validation, and one whose validation came back clean, all
	rated fire). Proof of the flaw (a runZero report) is there in each case, so only the triage state holds them."""

	def setUp(self):
		super().setUp()
		self.cve = self.entry('CVE-2020-11022', exploit_db=True, cvss=6.9, epss_reached=True)

	def case(self, classification, status, validation):
		m = self.jquery(self.cve, version=f'1.12.{CVEMatch.objects.count()}', evidence={**LIBRARY_BANNER, 'runzero': True},
						ai_verdict=triage.verdict_for(classification))
		self.triaged(m, classification, status, validation)
		return m

	def test_each_state(self):
		for (classification, status, validation), want, reason in (
				(('needs_validation', 'pending', 'none'), SMOKE, threat.REASON_TRIAGE_PENDING),
				(('', 'pending', 'none'), SMOKE, threat.REASON_TRIAGE_PENDING),
				(('needs_validation', 'triaged', 'no_check'), SMOKE, threat.REASON_TRIAGE_NEEDS_VALIDATION),
				(('likely', 'triaged', 'clean'), ICE, threat.REASON_VALIDATION_CLEAN),
				(('needs_validation', 'triaged', 'hit'), FIRE, None),  # a validation hit is proof: no cap
				(('likely', 'triaged', 'observed'), FIRE, None),
				(('', 'not_triaged', 'none'), FIRE, None)):  # no AI provider: no cap
			with self.subTest(classification=classification, status=status, validation=validation):
				m = self.case(classification, status, validation)
				self.assertEqual(self.before(m), FIRE)
				self.assertEqual(self.heat(m), (want, want))
				loaded = CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=m.pk)
				if reason:
					self.assertIn(reason, threat.heat_reason(loaded))
				with mock.patch.dict(os.environ, LEGACY):
					self.assertEqual(self.heat(m), (want, want))
				self.assertEqual(threat.validation_heat(loaded), FIRE)  # validation still takes it in the fire lane

	def test_a_template_hit_is_not_held_by_a_pending_triage(self):
		m = self.jquery(self.cve, version='1.12.9', template_result='vulnerable', ai_verdict='uncertain')
		self.triaged(m, 'needs_validation', 'pending', 'none')  # what a template hit leaves until triage reads it again
		self.assertEqual(self.heat(m), (FIRE, FIRE))
		Triage.objects.filter(match=m).update(validation_status='clean')  # a confirmation stands: a later miss does not lower it
		self.assertEqual(self.heat(m), (FIRE, FIRE))

	def test_the_host_and_its_score_follow(self):
		self.case('needs_validation', 'pending', 'none')
		sub = Subdomain.objects.prefetch_related('cve_matches__cve_entry', 'cve_matches__triage').get(pk=self.sub.pk)
		from agentapi import services
		self.assertEqual(services._host_heat(sub), SMOKE)
		scoring.rescore_hosts(self.project.id, [self.sub.name])
		self.assertIn('Smoke CVE match', Subdomain.objects.get(pk=self.sub.pk).score_detail[0]['label'])


class ScannerFindingTests(Base):
	"""Item 5, heat half (fixtures: nuclei unauth-psql, apache-rocketmq-broker-unauth and an open-proxy template, high, no request or
	response stored, validation no_check, rated fire from the template's severity)."""

	def finding(self, name, severity=3, source='nuclei', validation=None, classification='likely', status='triaged'):
		v = Vulnerability.objects.create(name=name, severity=severity, source=source, template_id=name, subdomain=self.sub,
										 target_domain=self.domain, scan_history=self.scan, open_status=True, request=None, response=None)
		if validation is not None:
			Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='nuclei', vulnerability=v,
								  classification=classification, status=status, validation_status=validation)
		return v

	def heats(self):
		vulns = Vulnerability.objects.select_related('triage').prefetch_related('cve_ids', 'tags')
		sql = dict(Vulnerability.objects.annotate(h=threat.finding_heat_rank_expr()).values_list('pk', 'h'))
		return {v.pk: (threat.finding_heat(v, hot_names=set()), NAMES.get(sql[v.pk])) for v in vulns}

	def test_a_template_match_waits_for_a_validation(self):
		psql = self.finding('unauth-psql', validation='no_check')
		rocketmq = self.finding('apache-rocketmq-broker-unauth', validation='no_check')
		proxy = self.finding('open-proxy', validation=None)  # never triaged
		reproduced = self.finding('exposed-panel', validation='hit')
		clean = self.finding('exposed-git', validation='clean')
		pending = self.finding('exposed-env', validation='none', classification='', status='pending')
		medium = self.finding('weak-cipher', severity=2, validation='no_check')
		database = self.finding('postgres-no-password', severity=4, source='db_exposure', validation='none')
		dns = self.finding('dangling-ns', severity=3, source='bbot', validation='none')
		for policy in ({}, LEGACY):
			with mock.patch.dict(os.environ, policy):
				heats = self.heats()
				self.assertEqual(heats[psql.pk], (SMOKE, SMOKE), policy)
				self.assertEqual(heats[rocketmq.pk], (SMOKE, SMOKE), policy)
				self.assertEqual(heats[proxy.pk], (SMOKE, SMOKE), policy)
				self.assertEqual(heats[reproduced.pk], (FIRE, FIRE), policy)
				self.assertEqual(heats[clean.pk], (ICE, ICE), policy)
				self.assertEqual(heats[pending.pk], (SMOKE, SMOKE), policy)
				self.assertEqual(heats[medium.pk], (SMOKE, SMOKE), policy)
				self.assertEqual(heats[database.pk], (FIRE, FIRE), policy)  # cvENGINE's own check: not held
				self.assertEqual(heats[dns.pk], (FIRE, FIRE), policy)
		loaded = Vulnerability.objects.select_related('triage').get(pk=psql.pk)
		self.assertEqual(threat.finding_heat_reason(loaded, SMOKE), threat.REASON_NOT_VALIDATED)
		self.assertEqual(rerate.before_finding_heat(loaded, set(), threat.heat_policy()), FIRE)

	def test_the_host_score_counts_it_as_smoke(self):
		self.finding('unauth-psql', validation='no_check')
		scoring.rescore_hosts(self.project.id, [self.sub.name])
		line = [d for d in Subdomain.objects.get(pk=self.sub.pk).score_detail if 'finding' in d['label']][0]
		self.assertEqual(line['points'], scoring.FINDING_HEAT_POINTS[SMOKE])
		self.assertIn('held until a validation confirms it', line['label'])


class RemoteStateTests(Base):
	"""Item 2 (fixture: model "likely", lifted to confirmed by the rules, while the CVE's detection strategy says
	``validation.max_remote_state`` likely)."""

	def facts(self, **kw):
		return {'version_in_range': True, 'distro_status': '', 'template_result': '', 'max_remote_state': 'likely', **kw}

	def parsed(self, said):
		return {'classification': said, 'reason': 'r', 'impact': '', 'severity_adjust': 0, 'severity_reason': '', 'remediation': '',
				'validation_steps': []}

	def test_the_rules_never_lift_above_the_strategy(self):
		out = triage.apply_rules('cve_match', self.facts(template_result='vulnerable', remote_flaw_check=True), self.parsed('confirmed'))
		self.assertEqual((out['classification'], out['overridden']), ('likely', True))
		self.assertIn("detection strategy says a check from outside decides it likely at most", out['reason'])
		out = triage.apply_rules('cve_match', self.facts(template_result='vulnerable', remote_flaw_check=True), self.parsed('likely'))
		self.assertEqual((out['classification'], out['overridden']), ('likely', False))
		# the host's own evidence is not a remote check, and a CVE without a record sets no limit
		out = triage.apply_rules('cve_match', self.facts(distro_status='vulnerable', host_side=True), self.parsed('confirmed'))
		self.assertEqual(out['classification'], 'confirmed')
		out = triage.apply_rules('cve_match', self.facts(template_result='vulnerable', max_remote_state=''), self.parsed('confirmed'))
		self.assertEqual(out['classification'], 'confirmed')
		# a template hit is never held below likely
		self.assertEqual(triage.remote_limit('cve_match', self.facts(max_remote_state='needs_validation', remote_flaw_check=True))[0], 'likely')
		self.assertEqual(triage.remote_limit('cve_match', self.facts(max_remote_state='needs_validation'))[0], 'needs_validation')
		self.assertEqual(triage.remote_limit('nuclei', self.facts()), ('', ''))

	def test_the_library_rule_is_held_and_a_validation_hit_is_not(self):
		text = 'jQuery 3.1.1 is served at ...'
		self.assertEqual(triage._remote_clamp('cve_match', self.facts(), 'confirmed', text, 'observed')[0], 'likely')
		self.assertEqual(triage._remote_clamp('cve_match', self.facts(), 'confirmed', text, 'hit'), ('confirmed', text))

	def test_overridden_reads_what_the_row_shows(self):
		verdict = SimpleNamespace(model_classification='likely', classification='needs_validation', overridden=True)
		self.assertFalse(triage.overridden(verdict, SimpleNamespace(classification='likely')))
		self.assertTrue(triage.overridden(verdict, SimpleNamespace(classification='confirmed')))
		self.assertTrue(triage.overridden(SimpleNamespace(model_classification='', classification='needs_validation'),
										  SimpleNamespace(classification='confirmed')))
		self.assertFalse(triage.overridden(None, SimpleNamespace(classification='confirmed')))

	def test_a_released_row_is_offered_to_the_fire_page(self):
		row = SimpleNamespace(match_id=7, validation_status='none', status='pending', classification='needs_validation')
		self.assertTrue(triage._released(row, 'likely', held=False))
		self.assertFalse(triage._released(row, 'needs_validation', held=False))
		self.assertFalse(triage._released(row, 'likely', held=True))
		self.assertFalse(triage._released(SimpleNamespace(**{**row.__dict__, 'status': 'triaged', 'classification': 'likely'}), 'confirmed',
										  held=False))


class PagingTests(Base):
	"""Item 4's paging question: a match paged as fire under the old rules that is smoke now is never paged because of the change, and real
	proof later pages it once."""

	def test_no_page_from_the_change_and_one_when_proof_arrives(self):
		cve = self.entry('CVE-2020-11023', kev=True, exploit_db=True, cvss=6.9)
		m = self.jquery(cve, ai_verdict='affected')
		row = self.triaged(m, 'confirmed', validation='observed')
		CVEMatch.objects.filter(pk=m.pk).update(fire_notified_at=timezone.now(), fire_notified_rule=threat.heat_signature())
		self.assertEqual(self.heat(m), (SMOKE, SMOKE))
		self.assertFalse(notify.fire_confirmed([m.pk]))
		self.assertFalse(notify.cves_turned_hot([cve.pk]))
		self.assertFalse(notify.fire_matches(timezone.now() - timezone.timedelta(days=1)))
		self.assertEqual(notify.baseline_heat_policy(), 0)
		self.assertEqual(self.sends, [])
		self.assertEqual(rerate.project_report(self.project)['unmark'], 1)
		self.assertIsNotNone(CVEMatch.objects.get(pk=m.pk).fire_notified_at)  # the dry run wrote nothing
		rerate.project_report(self.project, apply=True)
		self.assertIsNone(CVEMatch.objects.get(pk=m.pk).fire_notified_at)
		self.assertEqual(self.sends, [])
		Triage.objects.filter(pk=row.pk).update(validation_status='hit')  # a check reproduced it: fire, paged once
		self.assertTrue(notify.fire_confirmed([m.pk]))
		self.assertFalse(notify.fire_confirmed([m.pk]))
		self.assertEqual(len(self.sends), 1)


class ManualOverrideTests(Base):
	"""A heat a person set (``Triage.heat_override``, PR #415) wins over every 1.3.5 cap, in Python and SQL, and the re-rating report does not
	count it as a change."""

	def test_the_override_beats_the_caps(self):
		cve = self.entry('CVE-2020-11023', kev=True, exploit_db=True, cvss=6.9)
		m = self.jquery(cve, ai_verdict='uncertain')
		self.triaged(m, 'needs_validation', 'pending', 'clean')  # version-only, pending and clean: every cap applies
		self.assertEqual(self.heat(m), (ICE, ICE))
		Triage.objects.filter(match=m).update(heat_override=FIRE, heat_override_reason='reproduced by hand')
		self.assertEqual(self.heat(m), (FIRE, FIRE))
		v = Vulnerability.objects.create(name='unauth-psql', severity=3, source='nuclei', subdomain=self.sub, target_domain=self.domain,
										 scan_history=self.scan, open_status=True)
		Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='nuclei', vulnerability=v, status='pending',
							  validation_status='none', heat_override=FIRE)
		for policy in ({}, LEGACY):
			with mock.patch.dict(os.environ, policy):
				loaded = Vulnerability.objects.select_related('triage').get(pk=v.pk)
				sql = Vulnerability.objects.annotate(h=threat.finding_heat_rank_expr()).get(pk=v.pk).h
				self.assertEqual((threat.finding_heat(loaded, hot_names=set()), NAMES[sql]), (FIRE, FIRE), policy)
		report = rerate.project_report(self.project)
		self.assertEqual((sum(report['cve'].values()), sum(report['scanner'].values())), (0, 0))


class RerateCommandTests(Base):
	"""The Definition-of-done dry run: from -> to counts per project and overall; ``--apply`` only writes the stored follow-ups."""

	def setUp(self):
		super().setUp()
		jquery = self.entry('CVE-2020-11023', kev=True, exploit_db=True, cvss=6.9)
		CVEDetection.objects.create(cve_entry=jquery, strategy={'validation': {'max_remote_state': 'likely'}})
		self.proven = self.jquery(jquery, ai_verdict='affected')
		self.row = self.triaged(self.proven, 'confirmed', validation='observed')
		Triage.objects.filter(pk=self.row.pk).update(reason='jQuery 3.1.1 is served at ...')
		CVEMatch.objects.filter(pk=self.proven.pk).update(fire_notified_at=timezone.now(), fire_notified_rule=threat.heat_signature())
		self.unchanged = self.jquery(jquery, version='3.0.0', template_result='vulnerable', ai_verdict='affected')
		self.triaged(self.unchanged, 'likely')
		self.vuln = Vulnerability.objects.create(name='unauth-psql', severity=3, source='nuclei', subdomain=self.sub, target_domain=self.domain,
												 scan_history=self.scan, open_status=True)

	def run_command(self, *args):
		out = io.StringIO()
		call_command('rerate_findings', *args, stdout=out)
		return out.getvalue()

	def test_the_dry_run_reports_and_writes_nothing(self):
		score = Subdomain.objects.get(pk=self.sub.pk).score
		text = self.run_command()
		self.assertIn(f'{self.project.slug}: 1 open CVE match(es) change heat (fire->smoke 1); 1 open scanner finding(s) change heat '
					  '(fire->smoke 1); 1 host(s) to rescore; 1 fire page mark(s) on matches no longer fire; 1 classification(s) above',
					  text)
		self.assertIn('overall: 1 open CVE match(es) change heat (fire->smoke 1)', text)
		self.assertIn('dry run: nothing written', text)
		self.assertEqual(Triage.objects.get(pk=self.row.pk).classification, 'confirmed')
		self.assertIsNotNone(CVEMatch.objects.get(pk=self.proven.pk).fire_notified_at)
		self.assertEqual(Subdomain.objects.get(pk=self.sub.pk).score, score)
		self.assertEqual(self.sends, [])

	def test_apply_writes_the_follow_ups_and_pages_nothing(self):
		self.run_command('--apply', '--project', self.project.slug)
		row = Triage.objects.get(pk=self.row.pk)
		self.assertEqual(row.classification, 'likely')
		self.assertTrue(row.reason.startswith("The CVE's detection strategy says a check from outside decides it likely at most; kept as likely."))
		self.assertIsNone(CVEMatch.objects.get(pk=self.proven.pk).fire_notified_at)
		self.assertIsNotNone(Subdomain.objects.get(pk=self.sub.pk).scored_at)
		self.assertEqual(self.sends, [])
		text = self.run_command()  # safe to run again: the follow-ups are done, the heat changes stay what they are
		self.assertIn('0 fire page mark(s)', text)
		self.assertIn('0 classification(s) above', text)
