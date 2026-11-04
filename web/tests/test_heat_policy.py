"""The owner's heat policy (CVENGINE_HEAT_POLICY=kev, the default).

- On the KEV (or with a known exploit), and the version is PROVEN on the host => FIRE.
- On the KEV (or with a known exploit), and we only THINK the version is there => SMOKE.
- Not on the KEV and no known exploit => ICE, whatever its CVSS or EPSS, proven or not.

The distribution's "patched" verdict and a CVE with no affected version range stay ice. ``CVENGINE_HEAT_POLICY=legacy`` (or the Heat policy
card on Settings, configMaxxing) brings back the classification before the policy. What counts as proof is ``match_policy.version_proven``.
"""
import itertools
import os
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from agentapi import services
from cveFeed import hot_validation, match_policy, notify, openvas_scan, scoring, threat, tunables
from cveFeed.models import CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, HEAT_RANK, ICE, SMOKE
from startScan.models import Vulnerability
from tests.test_match_policy import Fixture

POLICY = threat.HEAT_POLICY_ENV
LEGACY = {POLICY: 'legacy'}

# the CVE's own signals
CVES = {
	'kev, medium score': {'kev': True, 'exploit_db': False, 'epss_reached': False, 'cvss': 6.1},
	'exploit only, low score': {'kev': False, 'exploit_db': True, 'epss_reached': False, 'cvss': 4.3},
	'critical score and epss, not hot': {'kev': False, 'exploit_db': False, 'epss_reached': True, 'cvss': 9.8},
	'high score, not hot': {'kev': False, 'exploit_db': False, 'epss_reached': False, 'cvss': 7.5},
	'low score, not hot': {'kev': None, 'exploit_db': None, 'epss_reached': None, 'cvss': None},
}
HOT = {'kev, medium score': True, 'exploit only, low score': True, 'critical score and epss, not hot': False, 'high score, not hot': False,
	   'low score, not hot': False}

FILE_BANNER = {'source': 'tech', 'version_source': 'body', 'version_confidence': 0.9, 'copy_state': 'effective', 'script_url': 'https://x/jquery.js',
			   'copies': [{'url': 'https://x/jquery.js', 'source': 'body', 'state': 'effective'}]}
# evidence kind -> (match fields, the Triage row's validation_status, proven?)
EVIDENCE = {
	# proven: hard evidence about the host
	'template hit': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}, 'template_result': 'vulnerable'}, '', True),
	'distribution tracker: vulnerable': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port', 'distro': {'distro': 'debian'}},
										  'distro_status': 'vulnerable'}, '', True),
	'host inventory': ({'source': 'host', 'version_in_range': True, 'evidence': {'source': 'host', 'host_reported': True}}, '', True),
	'runZero report': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port', 'runzero': True}}, '', True),
	'validation hit': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}}, 'hit', True),
	# proven: the version was read from the component itself
	'library file banner': ({'source': 'tech', 'version_in_range': True, 'evidence': dict(FILE_BANNER)}, '', True),
	'library code signature': ({'source': 'tech', 'version_in_range': True, 'evidence': {**FILE_BANNER, 'version_confidence': 0.8}}, '', True),
	'nmap probed service banner': ({'source': 'port', 'version_in_range': True,
									'evidence': {'source': 'port', 'method': 'probed', 'vendor_banner': True, 'raw_version': '2.4.49'}}, '', True),
	# proven: a version-class template (PR #384) read the version on the host
	'version-class template hit': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}, 'template_result': 'version_only'},
								   '', True),
	# never proven
	'library file name or ?ver= hint': ({'source': 'tech', 'version_in_range': True,
										 'evidence': {**FILE_BANNER, 'version_source': 'filename', 'version_confidence': 0.4}}, '', False),
	'library copy shadowed by a later one': ({'source': 'tech', 'version_in_range': True,
											  'evidence': {**FILE_BANNER, 'copy_state': 'shadowed', 'version_confidence': 0.4}}, '', False),
	'library read copy shadowed by a later unread one': ({'source': 'tech', 'version_in_range': True, 'evidence': {
		**FILE_BANNER, 'copies': [{'url': 'https://x/jquery.js', 'source': 'body', 'state': 'shadowed'},
								  {'url': 'https://cdn.x/jquery-1.min.js', 'source': 'filename', 'state': 'effective'}]}}, '', False),
	'library copy of an unresolved set': ({'source': 'tech', 'version_in_range': True,
										   'evidence': {**FILE_BANNER, 'copy_state': 'unresolved', 'copies_unresolved': True,
														'version_confidence': 0.5}}, '', False),
	'library read by another tool': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech', 'version_source': 'other'}}, '', False),
	'technology detection (Wappalyzer)': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech', 'raw_version': '3.1'}}, '', False),
	'distro-packaged banner, no tracker verdict': ({'source': 'port', 'version_in_range': True,
													'evidence': {'source': 'port', 'method': 'probed', 'distro': {'distro': 'ubuntu'}}}, '', False),
	'probed banner of a distro-packaged product, no distro marker': ({'source': 'port', 'version_in_range': True,
																	  'evidence': {'source': 'port', 'method': 'probed', 'vendor_banner': False}}, '', False),
	'probed banner from before the packaging was recorded': ({'source': 'port', 'version_in_range': True,
															  'evidence': {'source': 'port', 'method': 'probed'}}, '', False),
	'nmap port-table guess': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port', 'method': 'table', 'vendor_banner': True}},
							  '', False),
	'nmap banner from before the method was kept': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port'}}, '', False),
	'older than every fixed branch': ({'source': 'tech', 'version_in_range': None, 'evidence': {'source': 'tech', 'branch_unlisted': True}}, '', False),
	'openvas below its quality bar': ({'source': 'openvas', 'version_in_range': None, 'evidence': {'source': 'openvas', 'qod': 30}}, '', False),
	'a re-read version (observed)': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}}, 'observed', False),
	'AI says affected': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}, 'ai_verdict': 'affected'}, '', False),
}


def owner_rule(cve, proven):
	"""The owner's rule, written out independently of the code under test."""
	if not HOT[cve]:
		return ICE
	return FIRE if proven else SMOKE


def fake(evidence, cve):
	fields, validation, _proven = EVIDENCE[evidence]
	entry = SimpleNamespace(**CVES[cve])
	return SimpleNamespace(cve_entry=entry, ai_verdict=fields.get('ai_verdict', 'uncertain'), template_result=fields.get('template_result', ''),
						   distro_status=fields.get('distro_status', 'no_data'), source=fields['source'], evidence=fields['evidence'],
						   version_in_range=fields['version_in_range'], triage=SimpleNamespace(validation_status=validation))


class Policy:
	"""No environment value or saved tunable of ours leaks in: the default (kev) unless a test says otherwise."""

	def setUp(self):
		super().setUp()
		env = mock.patch.dict(os.environ)
		env.start()
		self.addCleanup(env.stop)
		os.environ.pop(POLICY, None)
		os.environ.pop(threat.VERSION_ONLY_MAX_HEAT_ENV, None)
		saved = mock.patch.object(tunables, 'stored_values', return_value={})
		saved.start()
		self.addCleanup(saved.stop)


class OwnerRuleTests(Policy, SimpleTestCase):
	"""The six rules, by the pure form."""

	def test_hot_and_proven_is_fire(self):
		for evidence in [e for e, v in EVIDENCE.items() if v[2]]:
			for cve in ('kev, medium score', 'exploit only, low score'):
				m = fake(evidence, cve)
				self.assertTrue(match_policy.version_proven(m), evidence)
				self.assertEqual(threat.match_heat(m), FIRE, (evidence, cve))
				self.assertEqual(threat.validation_heat(m), FIRE, (evidence, cve))

	def test_hot_and_only_suspected_is_smoke(self):
		for evidence in [e for e, v in EVIDENCE.items() if not v[2]]:
			for cve in ('kev, medium score', 'exploit only, low score'):
				m = fake(evidence, cve)
				self.assertFalse(match_policy.version_proven(m), evidence)
				self.assertEqual(threat.match_heat(m), SMOKE, (evidence, cve))
				self.assertEqual(threat.validation_heat(m), FIRE, (evidence, cve))  # validated first: proof is what makes it fire
				self.assertEqual(threat.heat_reason(m), ('on the KEV' if CVES[cve]['kev'] else 'a public exploit is known') + '; version not proven')

	def test_not_hot_is_ice_even_with_a_critical_score_epss_and_proof(self):
		for evidence, cve in itertools.product(EVIDENCE, [c for c, hot in HOT.items() if not hot]):
			m = fake(evidence, cve)
			self.assertEqual(threat.match_heat(m), ICE, (evidence, cve))
			self.assertEqual(threat.validation_heat(m), ICE, (evidence, cve))
			self.assertEqual(threat.heat_reason(m), 'not on the KEV and no known exploit')
		self.assertEqual(threat.classify_threat_tier(kev=False, epss_reached=True, exploit_db=False, cvss=9.8), ICE)
		self.assertEqual(threat.classify_threat_tier(kev=True, epss_reached=False, exploit_db=False, cvss=2.0), FIRE)

	def test_a_distribution_patch_is_ice_whatever_the_proof(self):
		for evidence in EVIDENCE:
			m = fake(evidence, 'kev, medium score')
			m.distro_status = 'patched'
			self.assertEqual((threat.match_heat(m), threat.validation_heat(m)), (ICE, ICE), evidence)
			self.assertEqual(threat.heat_reason(m), threat.REASON_PATCHED)

	def test_an_unknown_version_range_is_ice(self):
		m = fake('library file banner', 'kev, medium score')
		m.version_in_range, m.evidence = None, {**m.evidence, 'unbounded': True}
		self.assertEqual((threat.match_heat(m), threat.validation_heat(m)), (ICE, ICE))
		self.assertEqual(threat.heat_reason(m), threat.REASON_VERSION_UNKNOWN)

	def test_legacy_brings_back_the_old_classification(self):
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(threat.heat_policy(), threat.LEGACY_POLICY)
			self.assertEqual(threat.classify_threat_tier(kev=False, epss_reached=True, exploit_db=False, cvss=9.8), FIRE)
			self.assertEqual(threat.classify_threat_tier(kev=False, epss_reached=False, exploit_db=False, cvss=7.5), SMOKE)
			# a non-KEV critical with hard evidence is fire again, a version-only one smoke (CVENGINE_VERSION_ONLY_MAX_HEAT)
			self.assertEqual(threat.match_heat(fake('template hit', 'critical score and epss, not hot')), FIRE)
			self.assertEqual(threat.match_heat(fake('technology detection (Wappalyzer)', 'critical score and epss, not hot')), SMOKE)
			# a banner read from the file is no hard evidence under legacy: smoke
			self.assertEqual(threat.match_heat(fake('library file banner', 'kev, medium score')), SMOKE)
			self.assertEqual(threat.validation_heat(fake('library file banner', 'kev, medium score')), FIRE)
			with mock.patch.dict(os.environ, {threat.VERSION_ONLY_MAX_HEAT_ENV: 'fire'}):  # the cap still works under legacy
				self.assertEqual(threat.match_heat(fake('technology detection (Wappalyzer)', 'high score, not hot')), SMOKE)
				self.assertEqual(threat.match_heat(fake('technology detection (Wappalyzer)', 'kev, medium score')), FIRE)

	def test_the_version_only_cap_is_not_read_under_the_owner_rule(self):
		for value in ('fire', 'ice', 'smoke'):
			with mock.patch.dict(os.environ, {threat.VERSION_ONLY_MAX_HEAT_ENV: value}):
				self.assertEqual(threat.match_heat(fake('technology detection (Wappalyzer)', 'kev, medium score')), SMOKE, value)
				self.assertEqual(threat.match_heat(fake('library file banner', 'kev, medium score')), FIRE, value)

	def test_the_setting_reads_kev_or_legacy_and_anything_else_is_the_default(self):
		for raw, policy in (('kev', 'kev'), ('legacy', 'legacy'), (' LEGACY ', 'legacy'), ('', 'kev'), ('nonsense', 'kev'), ('0', 'legacy'),
							('1', 'kev')):
			with mock.patch.dict(os.environ, {POLICY: raw}):
				self.assertEqual(threat.heat_policy(), policy, raw)
		with mock.patch.object(tunables, 'stored_values', return_value={'heat_policy': 0}):
			self.assertEqual(threat.heat_policy(), 'legacy')  # saved on configMaxxing: wins over the environment
		self.assertEqual(threat.heat_signature(), 'kev')
		with mock.patch.dict(os.environ, {**LEGACY, threat.VERSION_ONLY_MAX_HEAT_ENV: 'ice'}):
			self.assertEqual(threat.heat_signature(), 'legacy:ice')

	def test_the_reason_names_the_proof(self):
		self.assertEqual(threat.heat_reason(fake('library file banner', 'kev, medium score')),
						 'on the KEV; version proven: read from the library file itself')
		self.assertEqual(threat.heat_reason(fake('nmap probed service banner', 'kev, medium score')),
						 'on the KEV; version proven: read from the service banner by nmap')
		self.assertEqual(threat.heat_reason(fake('template hit', 'exploit only, low score')), 'a public exploit is known; version proven: template hit')
		self.assertEqual(threat.heat_reason(fake('version-class template hit', 'kev, medium score')),
						 'on the KEV; version proven: a version check read it on the host')

	def test_version_proven_and_vulnerability_confirmed_are_two_notions(self):
		m = fake('version-class template hit', 'kev, medium score')
		self.assertTrue(match_policy.version_proven(m))  # the version is proven: fire on a KEV CVE
		self.assertFalse(match_policy.has_hard_evidence(m.source, m.evidence, m.template_result, m.distro_status, ''))  # the flaw is not shown
		self.assertTrue(match_policy.is_version_only(m))  # so triage stays at needs validation
		m.distro_status = 'patched'
		self.assertFalse(match_policy.version_proven(m))

	def test_the_score_follows(self):
		smoke = {'id': 'CVE-2020-11023', 'temp': SMOKE, 'ai_verdict': 'uncertain'}
		self.assertEqual(scoring.score_host({'cves': [smoke]})[0], scoring.CVE_POINTS[SMOKE])


class DatabaseFormTests(Policy, Fixture):
	"""Lists, counts, filters, reports and the OpenVAS gate read the database form; it agrees with the Python form on every combination."""

	def setUp(self):
		super().setUp()
		self.rows = {}
		for i, (cve, signals) in enumerate(CVES.items()):
			entry = CVEEntry.objects.create(cve_id=f'CVE-2099-{9300 + i}', published_at=timezone.now(), affected=[], **signals)
			for j, evidence in enumerate(EVIDENCE):
				fields, validation, _proven = EVIDENCE[evidence]
				fields = {'ai_verdict': 'uncertain', **fields}
				m = CVEMatch.objects.create(cve_entry=entry, subdomain=self.sub, matched_product=f'p{j}', matched_version='1.2', **fields)
				if validation:
					Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='cve_match', match=m,
										  classification='needs_validation', status='triaged', validation_status=validation)
				self.rows[m.pk] = (evidence, cve)

	def ranks(self, capped=True):
		return dict(CVEMatch.objects.annotate(h=threat.match_heat_rank_expr(capped)).values_list('pk', 'h'))

	def test_every_combination(self):
		ranks, raw = self.ranks(), self.ranks(capped=False)
		loaded = {m.pk: m for m in CVEMatch.objects.select_related('cve_entry', 'triage')}
		proven = set(CVEMatch.objects.filter(match_policy.version_proven_q()).values_list('pk', flat=True))
		for pk, (evidence, cve) in self.rows.items():
			want = owner_rule(cve, EVIDENCE[evidence][2])
			with self.subTest(evidence=evidence, cve=cve):
				self.assertEqual(pk in proven, EVIDENCE[evidence][2])
				self.assertEqual(ranks[pk], HEAT_RANK[want])
				self.assertEqual(threat.match_heat(loaded[pk]), want)
				self.assertEqual(raw[pk], HEAT_RANK[FIRE if HOT[cve] else ICE])

	def test_legacy_database_form_matches_the_python_form(self):
		with mock.patch.dict(os.environ, LEGACY):
			ranks, raw = self.ranks(), self.ranks(capped=False)
			for m in CVEMatch.objects.select_related('cve_entry', 'triage'):
				self.assertEqual(ranks[m.pk], HEAT_RANK[threat.match_heat(m)], self.rows[m.pk])
				self.assertEqual(raw[m.pk], HEAT_RANK[threat.validation_heat(m)], self.rows[m.pk])

	def test_findings_rows_carry_the_heat_and_why(self):
		qs = services._finding_sources(self.project, {'type': 'cve', 'status': 'all'})['cve']
		for obj in qs:
			row = services._finding_row('cve', obj)
			evidence, cve = self.rows[obj.id]
			self.assertEqual(row['heat'], owner_rule(cve, EVIDENCE[evidence][2]), (evidence, cve))
			self.assertTrue(row['heat_reason'], (evidence, cve))
		m = CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=next(pk for pk, v in self.rows.items()
																			   if v == ('technology detection (Wappalyzer)', 'kev, medium score')))
		payload = services._match(m)
		self.assertEqual((payload['cve']['tier'], payload['cve']['feed_tier'], payload['cve']['validation_tier'], payload['cve']['heat_capped']),
						 (SMOKE, FIRE, FIRE, True))
		self.assertEqual(payload['heat_reason'], 'on the KEV; version not proven')
		self.assertTrue(payload['version_proven'] is False)

	def test_the_validation_lane_puts_a_hot_unproven_match_first_and_a_cold_proven_one_last(self):
		smoke = CVEMatch.objects.select_related('cve_entry').get(pk=next(pk for pk, v in self.rows.items()
																		  if v == ('technology detection (Wappalyzer)', 'kev, medium score')))
		cold = CVEMatch.objects.select_related('cve_entry').get(pk=next(pk for pk, v in self.rows.items()
																		 if v == ('template hit', 'critical score and epss, not hot')))
		self.assertEqual(hot_validation.tier_for(SimpleNamespace(kind='cve_match', match_id=smoke.pk, match=smoke)), FIRE)
		self.assertEqual(hot_validation.tier_for(SimpleNamespace(kind='cve_match', match_id=cold.pk, match=cold)), ICE)

	def test_an_ice_host_is_not_an_openvas_candidate(self):
		CVEMatch.objects.exclude(cve_entry__cve_id='CVE-2099-9302').delete()  # only the critical, EPSS, not-hot CVE is left: every match ice
		self.assertEqual(set(openvas_scan.hot_names(self.project.id)), set())
		self.assertEqual(openvas_scan.host_heat(self.project.id, [self.sub.name])[self.sub.name.lower()][0], ICE)
		with mock.patch.dict(os.environ, LEGACY):  # the old rule rated them fire or smoke
			self.assertEqual(set(openvas_scan.hot_names(self.project.id)), {self.sub.name.lower()})

	def test_new_fire_pages_once_and_ice_never(self):
		since = timezone.now() - timezone.timedelta(minutes=5)
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			notify.fire_matches(since)
		text = sent.call_args[0][0] if sent.called else ''
		paged = set(CVEMatch.objects.filter(fire_notified_at__isnull=False).values_list('pk', flat=True))
		self.assertTrue(paged)
		for pk in paged:
			evidence, cve = self.rows[pk]
			self.assertEqual(owner_rule(cve, EVIDENCE[evidence][2]), FIRE, (evidence, cve))
			self.assertTrue(HOT[cve])
		self.assertIn('fire-tier', text)

	def test_proof_arriving_on_a_smoke_match_pages_it_once_as_now_fire(self):
		pk = next(pk for pk, v in self.rows.items() if v == ('technology detection (Wappalyzer)', 'kev, medium score'))
		m = CVEMatch.objects.select_related('cve_entry').get(pk=pk)
		self.assertTrue(threat.unproven(m))
		CVEMatch.objects.filter(pk=pk).update(evidence={**m.evidence, 'runzero': True})
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			notify.fire_confirmed([pk])
			notify.fire_confirmed([pk])
		self.assertEqual(sent.call_count, 1)
		version = next(pk for pk, v in self.rows.items() if v == ('library read by another tool', 'kev, medium score'))
		vm = CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=version)
		self.assertTrue(threat.unproven(vm))
		CVEMatch.objects.filter(pk=version).update(template_result='version_only')  # a version-class template proved the version
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			notify.fire_confirmed([version])
			notify.fire_confirmed([version])
		self.assertEqual(sent.call_count, 1)  # proven by a version check: paged once as fire
		self.assertIn('confirmed, now fire-tier', sent.call_args.args[0])
		self.assertFalse(Vulnerability.objects.exists())  # and no finding: the flaw itself was not shown
		cold = next(pk for pk, v in self.rows.items() if v == ('technology detection (Wappalyzer)', 'critical score and epss, not hot'))
		CVEMatch.objects.filter(pk=cold).update(evidence={'source': 'tech', 'runzero': True})
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			notify.fire_confirmed([cold])
		sent.assert_not_called()  # proof on a CVE that is not hot leaves it ice: no page
		cold_cve = CVEMatch.objects.select_related('cve_entry').get(pk=cold).cve_entry.cve_id
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			self.assertFalse(notify.template_hits([(cold_cve, self.sub.name)]))  # a confirmed hit on an ice CVE is not announced
			self.assertTrue(notify.template_hits([('CVE-2099-77', 'unknown.example.test')]))  # an unknown CVE is never held back
		self.assertEqual(sent.call_count, 1)
