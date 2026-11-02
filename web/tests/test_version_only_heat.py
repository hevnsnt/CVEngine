"""A version-only CVE match is never Fire, KEV or not (1.3.2).

A match with no hard evidence about the host (no template hit, no distribution tracker listing, no host inventory report, no runZero
report, no validation hit: ``match_policy.has_hard_evidence``) is held to ``CVENGINE_VERSION_ONLY_MAX_HEAT`` (smoke by default) everywhere a
heat is shown or counted, while validation keeps ordering it by the uncapped heat, so a known-exploited version-only match is still checked
first. The case that started it: CVE-2020-11023 (jQuery, KEV) shown as Fire on hosts whose only evidence was a version string in a script name.
"""
import itertools
import os
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from agentapi import agent_tasks, services
from cveFeed import hot_validation, match_policy, notify, scoring, stats_history, threat, triage, views
from cveFeed.models import CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, HEAT_RANK, ICE, SMOKE
from startScan.models import IpAddress, Subdomain
from tests.test_match_policy import Cve, Fixture

ENV = threat.VERSION_ONLY_MAX_HEAT_ENV

# evidence kind -> (match fields, the Triage row's validation_status, hard evidence?)
EVIDENCE = {
	'tech version in range': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}}, '', False),
	'banner version (nmap)': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port', 'raw_version': '1.2'}}, '', False),
	'wpscan plugin version': ({'source': 'wpscan', 'version_in_range': True, 'evidence': {'source': 'wpscan'}}, '', False),
	'older than every fixed branch': ({'source': 'tech', 'version_in_range': None, 'evidence': {'source': 'tech', 'branch_unlisted': True}}, '', False),
	'openvas below its quality bar': ({'source': 'openvas', 'version_in_range': None, 'evidence': {'source': 'openvas', 'qod': 30}}, '', False),
	'a re-read version (observed)': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}}, 'observed', False),
	'a template that did not match': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}, 'template_result': 'no_match'}, 'clean', False),
	'template hit': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}, 'template_result': 'vulnerable'}, '', True),
	'distribution tracker: vulnerable': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port'}, 'distro_status': 'vulnerable'}, '', True),
	'host inventory (source host)': ({'source': 'host', 'version_in_range': True, 'evidence': {'source': 'host', 'host_reported': True}}, '', True),
	'host inventory on an external match': ({'source': 'tech', 'version_in_range': True,
											 'evidence': {'source': 'tech', 'host_reported': {'inventory_id': 1}}}, '', True),
	'runZero report': ({'source': 'port', 'version_in_range': True, 'evidence': {'source': 'port', 'runzero': True}}, '', True),
	'validation hit': ({'source': 'tech', 'version_in_range': True, 'evidence': {'source': 'tech'}}, 'hit', True),
}
# the CVE's own signals -> its feed tier
CVES = {
	'kev, medium score': {'kev': True, 'cvss': 6.1},
	'critical score': {'kev': False, 'cvss': 9.8},
	'high score': {'kev': False, 'cvss': 7.5},
	'low score': {'kev': False, 'cvss': 5.0},
}
FEED_TIER = {'kev, medium score': FIRE, 'critical score': FIRE, 'high score': SMOKE, 'low score': ICE}
# triage classification -> the legacy verdict it writes
CLASSES = {'': '', 'needs_validation': 'uncertain', 'likely': 'affected', 'confirmed': 'affected'}


def expected(cve, classification, hard, cap=SMOKE):
	"""The rule, written out independently of the code under test."""
	heat = FEED_TIER[cve]
	if heat == SMOKE and CLASSES[classification] == 'affected':  # a confirmed high score reads as fire
		heat = FIRE
	if not hard and HEAT_RANK[heat] > HEAT_RANK[cap]:
		heat = cap
	return heat


def uncapped(cve, classification):
	return expected(cve, classification, True)


def fake(evidence, cve, classification):
	fields, validation, _hard = EVIDENCE[evidence]
	entry = SimpleNamespace(epss_reached=False, exploit_db=False, **CVES[cve])
	return SimpleNamespace(cve_entry=entry, ai_verdict=CLASSES[classification], template_result=fields.get('template_result', ''),
						   distro_status=fields.get('distro_status', 'no_data'), source=fields['source'], evidence=fields['evidence'],
						   version_in_range=fields['version_in_range'], triage=SimpleNamespace(validation_status=validation))


class TruthTableTests(SimpleTestCase):
	"""Every evidence kind x KEV or not x every classification, by the pure rule."""

	def test_hard_evidence_has_one_definition(self):
		for name, (fields, validation, hard) in EVIDENCE.items():
			self.assertEqual(match_policy.has_hard_evidence(fields['source'], fields['evidence'], fields.get('template_result', ''),
															fields.get('distro_status', ''), validation), hard, name)
			self.assertEqual(match_policy.is_version_only(fake(name, 'low score', '')), not hard, name)

	def test_the_heat_shown_and_the_validation_heat(self):
		for evidence, cve, classification in itertools.product(EVIDENCE, CVES, CLASSES):
			m = fake(evidence, cve, classification)
			hard = EVIDENCE[evidence][2]
			with self.subTest(evidence=evidence, cve=cve, classification=classification):
				self.assertEqual(threat.match_heat(m), expected(cve, classification, hard))
				self.assertEqual(threat.validation_heat(m), uncapped(cve, classification))

	def test_kev_without_hard_evidence_is_never_fire_whatever_the_classification(self):
		for evidence, classification in itertools.product([e for e, v in EVIDENCE.items() if not v[2]], CLASSES):
			m = fake(evidence, 'kev, medium score', classification)
			self.assertEqual(threat.match_heat(m), SMOKE, (evidence, classification))
			self.assertEqual(threat.validation_heat(m), FIRE, (evidence, classification))  # still validated first

	def test_the_setting(self):
		m = fake('tech version in range', 'kev, medium score', 'needs_validation')
		for value, heat in (('fire', FIRE), (' FIRE ', FIRE), ('smoke', SMOKE), ('ice', ICE), ('', SMOKE), ('nonsense', SMOKE)):
			with mock.patch.dict(os.environ, {ENV: value}):
				self.assertEqual(threat.match_heat(m), heat, value)
				self.assertEqual(threat.validation_heat(m), FIRE, value)
		with mock.patch.dict(os.environ, {ENV: 'ice'}):
			for evidence, cve, classification in itertools.product(EVIDENCE, CVES, CLASSES):
				self.assertEqual(threat.match_heat(fake(evidence, cve, classification)),
								 expected(cve, classification, EVIDENCE[evidence][2], cap=ICE), (evidence, cve, classification))
		with mock.patch.dict(os.environ, {ENV: 'fire'}):  # the behaviour before 1.3.2
			for evidence, cve, classification in itertools.product(EVIDENCE, CVES, CLASSES):
				self.assertEqual(threat.match_heat(fake(evidence, cve, classification)), uncapped(cve, classification))

	def test_patched_and_version_unknown_stay_ice(self):
		m = fake('template hit', 'kev, medium score', 'confirmed')
		m.distro_status = 'patched'
		self.assertEqual((threat.match_heat(m), threat.validation_heat(m)), (ICE, ICE))
		m = fake('tech version in range', 'kev, medium score', '')
		m.version_in_range, m.evidence = None, {'source': 'tech', 'unbounded': True}
		self.assertEqual((threat.match_heat(m), threat.validation_heat(m)), (ICE, ICE))

	def test_the_pure_temperature_takes_the_flag(self):
		self.assertEqual(threat.match_temperature(FIRE, 6.1, 'uncertain', '', False, version_only=True), SMOKE)
		self.assertEqual(threat.match_temperature(SMOKE, 7.5, 'affected', '', False, version_only=True), SMOKE)
		self.assertEqual(threat.match_temperature(ICE, 5.0, 'affected', '', False, version_only=True), ICE)
		self.assertEqual(threat.match_temperature(FIRE, 6.1, 'uncertain', '', False), FIRE)

	def test_the_score_follows_the_heat(self):
		version_only = {'id': 'CVE-2020-11023', 'temp': SMOKE, 'ai_verdict': 'uncertain'}
		validated = {'id': 'CVE-2020-11023', 'temp': FIRE, 'ai_verdict': 'affected'}
		self.assertEqual(scoring.score_host({'cves': [version_only]})[0], scoring.CVE_POINTS[SMOKE])
		self.assertEqual(scoring.score_host({'cves': [validated]})[0], scoring.CVE_POINTS[FIRE] + scoring.AI_BONUS)


class DatabaseTruthTableTests(Fixture):
	"""The database form (lists, counts, filters, reports) agrees with the Python form on every combination."""

	def setUp(self):
		super().setUp()
		self.rows = {}
		for i, (cve, signals) in enumerate(CVES.items()):
			entry = CVEEntry.objects.create(cve_id=f'CVE-2099-{9100 + i}', published_at=timezone.now(), affected=[], **signals)
			for j, (evidence, classification) in enumerate(itertools.product(EVIDENCE, CLASSES)):
				fields, validation, _hard = EVIDENCE[evidence]
				m = CVEMatch.objects.create(cve_entry=entry, subdomain=self.sub, matched_product=f'p{j}', matched_version='1.2',
											ai_verdict=CLASSES[classification], **fields)
				if validation or classification:
					Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='cve_match', match=m,
										  classification=classification, status='triaged' if classification else 'pending',
										  validation_status=validation or 'none')
				self.rows[m.pk] = (evidence, cve, classification)

	def ranks(self, capped=True):
		return dict(CVEMatch.objects.annotate(h=threat.match_heat_rank_expr(capped)).values_list('pk', 'h'))

	def check(self, cap):
		ranks, raw = self.ranks(), self.ranks(capped=False)
		loaded = {m.pk: m for m in CVEMatch.objects.select_related('cve_entry', 'triage')}
		self.assertEqual(len(ranks), len(self.rows))  # the Triage join never multiplies a match
		for pk, (evidence, cve, classification) in self.rows.items():
			want = expected(cve, classification, EVIDENCE[evidence][2], cap=cap)
			with self.subTest(cap=cap, evidence=evidence, cve=cve, classification=classification):
				self.assertEqual(ranks[pk], HEAT_RANK[want])
				self.assertEqual(threat.match_heat(loaded[pk]), want)
				self.assertEqual(raw[pk], HEAT_RANK[uncapped(cve, classification)])
				self.assertEqual(threat.validation_heat(loaded[pk]), uncapped(cve, classification))

	def test_every_combination_with_every_cap(self):
		self.check(SMOKE)
		for cap in (FIRE, ICE, SMOKE):
			with mock.patch.dict(os.environ, {ENV: cap}):
				self.check(cap)

	def test_the_queryset_form_of_version_only(self):
		only = set(CVEMatch.objects.filter(match_policy.version_only_q()).values_list('pk', flat=True))
		hard = set(CVEMatch.objects.filter(match_policy.hard_evidence_q()).values_list('pk', flat=True))
		self.assertEqual(only, {pk for pk, (evidence, _c, _k) in self.rows.items() if not EVIDENCE[evidence][2]})
		self.assertEqual(hard, set(self.rows) - only)
		via_triage = set(Triage.objects.filter(match_policy.version_only_q('match__')).values_list('match_id', flat=True))
		self.assertEqual(via_triage, only & set(Triage.objects.values_list('match_id', flat=True)))


JQUERY = [{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]}]


class StoredJqueryMatchTests(Fixture):
	"""The reported case on stored data: a KEV jQuery match made from a version string alone reads Smoke after the update, everywhere,
	with no migration; a validated one stays Fire; validation still takes it first."""

	def setUp(self):
		super().setUp()
		IpAddress.objects.filter(pk=self.ip.pk).update(is_private=True)  # no exposure points: the score is the CVE part alone
		self.entry = self.cve(Cve(1, JQUERY, cve_id='CVE-2020-11023'), kev=True)
		CVEEntry.objects.filter(pk=self.entry.pk).update(cvss=6.9)  # its real score: fire only because it is KEV
		self.entry.refresh_from_db()
		self.tech('jQuery:3.4.1')
		self.correlate()
		self.match = CVEMatch.objects.get(cve_entry=self.entry)
		# what the live data showed: triaged needs_validation, AI uncertain
		triage.track(CVEMatch.objects.filter(pk=self.match.pk).select_related('cve_entry', 'subdomain__target_domain'))
		Triage.objects.filter(match=self.match).update(classification='needs_validation', status='triaged')
		CVEMatch.objects.filter(pk=self.match.pk).update(ai_verdict='uncertain')

	def fresh(self):
		return services._matches_qs(self.project).get(pk=self.match.pk)

	def heat_counts(self):
		return services._heat_facets(self.project, services.search_host_rows(self.project, services.parse_search('')))[0]

	def finding_heat(self, heat):
		return services._finding_sources(self.project, {'type': 'cve', 'heat': heat})['cve'].count()

	def host_score(self):
		scoring.rescore_hosts(self.project.id, [self.sub.name])
		return Subdomain.objects.get(pk=self.sub.pk)

	def graph_heat(self):
		node = next(n for n in views.graph_payload()['nodes'] if n['kind'] == 'subdomain')
		return node['heat'], node['info']['top_tier']

	def validate(self):
		Triage.objects.filter(match=self.match).update(validation_status='hit', classification='confirmed')
		CVEMatch.objects.filter(pk=self.match.pk).update(ai_verdict='affected')

	def assert_everywhere(self, heat, fire_count):
		m = self.fresh()
		self.assertEqual(services._match(m)['cve']['tier'], heat)
		self.assertEqual(CVEMatch.objects.annotate(h=threat.match_heat_rank_expr()).get(pk=self.match.pk).h, HEAT_RANK[heat])
		self.assertEqual(self.heat_counts()[heat], 1)
		self.assertEqual(self.heat_counts()[FIRE], fire_count)
		self.assertEqual(self.finding_heat(heat), 1)
		self.assertEqual(stats_history._open_findings_and_cve_matches(self.project)[1][heat], 1)
		self.assertEqual(self.graph_heat(), (heat, heat))
		sub = Subdomain.objects.get(pk=self.sub.pk)
		self.assertEqual(services._host_heat(sub), heat)

	def test_it_is_version_only_and_reads_smoke_everywhere(self):
		self.assertEqual((self.match.version_in_range, self.match.source, self.match.template_result), (True, 'tech', ''))
		self.assertTrue(match_policy.is_version_only(self.match))
		self.assert_everywhere(SMOKE, 0)
		self.assertEqual(self.finding_heat(FIRE), 0)
		payload = services._match(self.fresh())
		self.assertEqual((payload['cve']['feed_tier'], payload['cve']['validation_tier'], payload['cve']['heat_capped']), (FIRE, FIRE, True))
		self.assertTrue(payload['cve']['kev'])
		self.assertTrue(payload['version_only'])
		row = services._finding_row('cve', services._finding_sources(self.project, {'type': 'cve'})['cve'].get(pk=self.match.pk))
		self.assertEqual((row['heat'], row['kev'], row['version_only']), (SMOKE, True, True))
		reason = services._heat_reasons(Subdomain.objects.get(pk=self.sub.pk))[0]
		self.assertEqual((reason['temp'], reason['kev'], reason['heat_capped']), (SMOKE, True, True))
		self.assertIn('listed as exploited', reason['detail'])
		self.assertIn('version only', reason['detail'])
		sub = self.host_score()
		self.assertEqual(sub.score, scoring.CVE_POINTS[SMOKE])
		self.assertIn('Smoke CVE match CVE-2020-11023', sub.score_detail[0]['label'])

	def test_a_validation_hit_makes_it_fire(self):
		self.validate()
		self.assertFalse(match_policy.is_version_only(self.fresh()))
		self.assert_everywhere(FIRE, 1)
		self.assertFalse(services._match(self.fresh())['cve']['heat_capped'])
		self.assertEqual(self.host_score().score, scoring.CVE_POINTS[FIRE] + scoring.AI_BONUS)

	def test_a_template_hit_makes_it_fire(self):
		CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable')
		self.assert_everywhere(FIRE, 1)

	def test_the_owner_can_restore_the_old_behaviour(self):
		with mock.patch.dict(os.environ, {ENV: 'fire'}):
			self.assert_everywhere(FIRE, 1)
		with mock.patch.dict(os.environ, {ENV: 'ice'}):
			self.assert_everywhere(ICE, 0)

	def test_the_hotter_copy_of_one_cve_speaks_for_the_host(self):
		# the same CVE on a second product of the host, with a template hit: the host is fire, not held at smoke by the first match
		other = CVEMatch.objects.create(cve_entry=self.entry, subdomain=self.sub, source='port', matched_product='jquery-cdn', matched_version='3.4.1',
										version_in_range=True, evidence={'source': 'port'}, template_result='vulnerable')
		_, reasons, _, _ = services._merge_group(Subdomain.objects.get(pk=self.sub.pk), [])
		self.assertEqual([(r['id'], r['temp']) for r in reasons if r['kind'] == 'cve'], [(other.id, FIRE)])

	def test_validation_still_takes_it_first(self):
		row = Triage.objects.get(match=self.match)
		self.assertEqual(hot_validation.tier_for(row), FIRE)
		self.assertIn(row.pk, set(hot_validation._candidate_rows(FIRE).values_list('pk', flat=True)))
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
			self.assertEqual(hot_validation.enqueue(row, FIRE), 'queued')
		self.assertEqual(dispatch.call_args.kwargs['priority'], hot_validation.PRIORITY[FIRE])
		# and an agent's validation work is ordered the same way, while its displayed tier is the capped one
		m = CVEMatch.objects.select_related('cve_entry').get(pk=self.match.pk)
		self.assertEqual((agent_tasks.tier_of(m), agent_tasks.validation_tier_of(m)), (SMOKE, FIRE))

	def test_it_is_not_paged_as_a_new_fire_match_until_a_check_confirms_it(self):
		since = timezone.now() - timedelta(hours=1)
		with mock.patch('cveFeed.notify._send', return_value=True) as send:
			self.assertFalse(notify.fire_matches(since))
			self.assertEqual(send.call_count, 0)
			self.validate()
			self.assertTrue(notify.fire_matches(since))
		self.assertIn('CVE-2020-11023', send.call_args.args[0])

	def test_a_saved_search_on_the_cve_still_finds_the_host(self):
		# saved-search alerts run the host search's own terms; heat is not one of them, so the cap neither hides nor adds a host
		from cveFeed import saved_searches
		found, too_broad = saved_searches.current_matches(self.project, services.parse_search('cve:CVE-2020-11023'))
		self.assertEqual((list(found.values()), too_broad), ([self.sub.name], False))


class RescoreOnCapChangeTests(SimpleTestCase):
	def test_one_rescore_is_queued_when_the_cap_changes(self):
		class Redis:
			value = None

			def getset(self, key, value):
				old, Redis.value = Redis.value, value
				return old
		store = SimpleNamespace(r=Redis())
		with mock.patch('reNgine.resources.get_store', return_value=store), \
				mock.patch('cveFeed.tasks.rescore_all_hosts.apply_async') as queue:
			self.assertTrue(scoring.rescore_if_heat_cap_changed())  # the upgrade: nothing seen yet
			self.assertFalse(scoring.rescore_if_heat_cap_changed())  # a second worker starting
			with mock.patch.dict(os.environ, {ENV: 'fire'}):
				self.assertTrue(scoring.rescore_if_heat_cap_changed())
			self.assertTrue(scoring.rescore_if_heat_cap_changed())  # back to smoke
		self.assertEqual(queue.call_count, 3)

	def test_no_redis_no_rescore_and_never_raises(self):
		with mock.patch('reNgine.resources.get_store', return_value=SimpleNamespace()):
			self.assertFalse(scoring.rescore_if_heat_cap_changed())
		with mock.patch('reNgine.resources.get_store', side_effect=RuntimeError('down')):
			self.assertFalse(scoring.rescore_if_heat_cap_changed())
