"""A CVE that publishes no usable affected version range ("version unknown"), actively exploited or not.

Such a match stays a candidate marked for review: the Needs validation state with its reason, the lowest heat (never Fire or Smoke,
KEV or not), a tiny capped share of the host score, no model call, and it is re-evaluated as soon as the CVE gains a range.
"""
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import match_policy, scoring, triage
from cveFeed.models import CVEMatch, MatchVerdict, Triage, TriageVerdict
from cveFeed.tasks import correlate_refreshed_cves
from cveFeed.threat import ICE, FIRE, HEAT_RANK, SMOKE, classify_threat_tier, match_heat_rank_expr, match_temperature
from startScan.models import IpAddress, Subdomain
from tests.test_match_policy import Cve, Fixture

NO_RANGE = [{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': []}]
WITH_RANGE = [{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': [{'introduced': '2.0', 'fixed': '2.442'}]}]
BELOW_RANGE = [{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': [{'introduced': '1.0', 'fixed': '2.0'}]}]


def provider():
	p = mock.Mock(model='m')
	p.name = 'anthropic'
	return p


class PureRulesTests(SimpleTestCase):
	def test_only_an_unbounded_candidate_without_hard_evidence_is_version_unknown(self):
		unbounded = {'unbounded': True}
		self.assertTrue(match_policy.is_version_unknown(unbounded, None))
		self.assertFalse(match_policy.is_version_unknown({}, None))
		self.assertFalse(match_policy.is_version_unknown(unbounded, True))
		self.assertFalse(match_policy.is_version_unknown(unbounded, None, template_result='vulnerable'))
		self.assertFalse(match_policy.is_version_unknown({**unbounded, 'runzero': True}, None))

	def test_heat_is_ice_even_for_kev_and_a_critical_score(self):
		tier = classify_threat_tier(kev=True, epss_reached=True, exploit_db=True, cvss=9.8)
		self.assertEqual(match_temperature(tier, 9.8, 'affected', '', False), FIRE)
		self.assertEqual(match_temperature(tier, 9.8, 'affected', '', True), ICE)
		self.assertEqual(match_temperature(SMOKE, 7.5, '', '', True), ICE)

	def test_the_score_takes_a_tiny_capped_amount(self):
		def unknown(n):
			return [{'id': f'CVE-2099-{i}', 'temp': ICE, 'version_unknown': True} for i in range(n)]
		self.assertEqual(scoring.score_host({'cves': unknown(1)})[0], 1)
		self.assertEqual(scoring.score_host({'cves': unknown(9)})[0], scoring.VERSION_UNKNOWN_CAP)
		self.assertLess(scoring.VERSION_UNKNOWN_CAP, scoring.CVE_POINTS['ice'])
		# it never lifts a host above what its real matches earn, and the real worst match is unchanged
		real = {'id': 'CVE-1', 'temp': 'fire', 'ai_verdict': 'affected'}
		self.assertEqual(scoring.score_host({'cves': [real]})[0], 50)
		self.assertEqual(scoring.score_host({'cves': [real, *unknown(5)]})[0], 50)
		self.assertEqual(scoring.score_host({'cves': [{'id': 'CVE-2', 'temp': 'ice'}, *unknown(5)]})[0], 5 + scoring.VERSION_UNKNOWN_CAP)

	def test_the_model_cannot_dismiss_or_raise_it(self):
		facts = {'version_in_range': None, 'distro_status': '', 'template_result': '', 'version_unknown': True}
		for said in ('not_applicable', 'likely_false_positive', 'likely', 'confirmed'):
			parsed = {'classification': said, 'reason': 'because', 'severity_adjust': 0, 'impact': '', 'severity_reason': '',
					  'remediation': '', 'validation_steps': []}
			out = triage.apply_rules('cve_match', facts, parsed)
			self.assertEqual(out['classification'], 'needs_validation', said)
		# a template hit is hard evidence about the host and keeps its floor
		hit = triage.apply_rules('cve_match', {**facts, 'template_result': 'vulnerable'}, {'classification': 'not_applicable', 'reason': 'x',
				'severity_adjust': 0, 'impact': '', 'severity_reason': '', 'remediation': '', 'validation_steps': []})
		self.assertEqual(hit['classification'], 'confirmed')


class VersionUnknownTests(Fixture):
	def setUp(self):
		super().setUp()
		IpAddress.objects.filter(pk=self.ip.pk).update(is_private=True)  # no exposure points: the score is the CVE part alone
		self.entry = self.cve(Cve(300, NO_RANGE, cve_id='CVE-2024-23897'), kev=True)
		self.tech('Jenkins:2.426.2')

	def only_match(self):
		return CVEMatch.objects.get(cve_entry=self.entry)

	def triage_all(self, p=None):
		match = triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain').filter(pk=self.only_match().pk))
		return triage.run_triage(triage.track(match), provider=p or provider())

	def heat_rank(self):
		return CVEMatch.objects.annotate(h=match_heat_rank_expr()).get(pk=self.only_match().pk).h

	def host_score(self):
		scoring.rescore_hosts(self.project.id, [self.sub.name])
		return Subdomain.objects.get(pk=self.sub.pk).score

	def test_it_is_marked_for_review_with_its_reason_and_the_model_is_not_asked(self):
		self.correlate()
		p = provider()
		stats = self.triage_all(p)
		match, row = self.only_match(), Triage.objects.get(match=self.only_match())
		self.assertEqual(p.complete.call_count, 0)
		self.assertEqual(stats['asked'], 0)
		self.assertEqual((row.classification, row.status, match.ai_verdict), ('needs_validation', 'triaged', 'uncertain'))
		self.assertEqual(match.ai_reason, match_policy.REASON_VERSION_UNKNOWN)
		self.assertIn('not known', match.ai_reason)
		self.assertTrue(match_policy.version_unknown(match))
		# it is a live match (listed, countable), not a closure
		self.assertNotEqual(match.ai_verdict, 'not_affected')

	def test_it_has_a_very_low_score_and_is_never_fire_or_smoke_with_kev(self):
		self.correlate()
		self.assertTrue(self.entry.kev and self.entry.cvss >= 9)
		self.assertEqual(self.heat_rank(), HEAT_RANK[ICE])
		self.assertEqual(self.host_score(), 1)
		sub = Subdomain.objects.get(pk=self.sub.pk)
		self.assertIn('unknown affected versions', ' '.join(d['label'] for d in sub.score_detail))
		self.triage_all()
		self.assertEqual(self.heat_rank(), HEAT_RANK[ICE])  # a review state does not raise it either
		self.assertEqual(self.host_score(), 1)

	def test_it_is_not_announced_as_a_new_fire_match(self):
		from datetime import timedelta

		from django.utils import timezone

		from cveFeed import notify
		self.correlate()
		with mock.patch.object(notify, '_send', return_value=True) as sent:
			self.assertFalse(notify.fire_matches(timezone.now() - timedelta(days=1)))
		sent.assert_not_called()

	def test_a_model_answer_stored_before_cannot_clear_it(self):
		self.correlate()
		match = self.only_match()
		pairs = triage.track(triage.with_cves([match]))
		verdict = TriageVerdict.objects.create(kind='cve_match', signature=pairs[0][0].signature, classification='not_applicable',
											   reason='the model said so', model='a-model')
		triage._apply(verdict, pairs)
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, 'uncertain')
		self.assertEqual(Triage.objects.get(match=match).classification, 'needs_validation')

	def test_an_old_clearing_verdict_is_not_seeded_onto_a_new_match(self):
		MatchVerdict.objects.create(cve_entry=self.entry, matched_product='Jenkins', matched_version='2.426.2', version_in_range=None,
									source='tech', ai_verdict='not_affected', ai_reason='the model said so', ai_model='a-model')
		self.correlate()
		self.assertEqual(self.only_match().ai_verdict, '')

	def test_a_later_range_lifts_the_flag_and_the_match_is_judged_on_its_version(self):
		self.correlate()
		self.triage_all()
		self.host_score()
		self.assertEqual((self.heat_rank(), self.host_score()), (HEAT_RANK[ICE], 1))
		# the feed now publishes a range that contains the version: the refresh marks the CVE and the recorrelation task runs
		self.entry.affected = WITH_RANGE
		self.entry.needs_recorrelation = True
		self.entry.save()
		correlate_refreshed_cves()
		match = self.only_match()
		self.assertEqual((match.version_in_range, match.evidence.get('unbounded')), (True, None))
		self.assertFalse(match_policy.version_unknown(match))
		# judged on its version like any match: a version alone is smoke at most, KEV or not (1.3.2, test_version_only_heat)
		self.assertEqual(self.heat_rank(), HEAT_RANK[SMOKE])
		self.assertEqual(self.host_score(), scoring.CVE_POINTS['smoke'])
		row = Triage.objects.get(match=match)
		self.assertEqual((row.classification, row.status), ('', 'pending'))  # the old review state is gone with the old evidence
		self.assertNotEqual(match.ai_reason, match_policy.REASON_VERSION_UNKNOWN)
		# and it is now an ordinary match: the model is asked, and it cannot clear a version inside the range
		p = provider()
		p.complete.return_value = '{"classification": "not_applicable", "reason": "no"}'
		self.assertEqual(self.triage_all(p)['asked'], 1)
		self.assertEqual(Triage.objects.get(match=match).classification, 'needs_validation')

	def test_a_later_range_that_excludes_the_version_closes_it(self):
		self.correlate()
		self.triage_all()
		self.entry.affected = BELOW_RANGE
		self.entry.needs_recorrelation = True
		self.entry.save()
		correlate_refreshed_cves()
		match = self.only_match()
		self.assertEqual(match.ai_verdict, 'not_affected')
		self.assertEqual(self.host_score(), 0)

	def test_a_match_with_a_range_is_unaffected(self):
		other = self.cve(Cve(301, WITH_RANGE, cve_id='CVE-2024-99999'), kev=True)
		self.correlate()
		ranged = CVEMatch.objects.get(cve_entry=other)
		self.assertEqual((ranged.version_in_range, ranged.evidence.get('unbounded')), (True, None))
		self.assertFalse(match_policy.version_unknown(ranged))
		rank = CVEMatch.objects.annotate(h=match_heat_rank_expr()).filter(cve_entry=other).values_list('h', flat=True).get()
		self.assertEqual(rank, HEAT_RANK[SMOKE])  # a version in the range alone: smoke at most, KEV or not (1.3.2)
		self.assertEqual(self.host_score(), scoring.CVE_POINTS['smoke'] + 1)  # the ranged match plus one point for the unknown one
		CVEMatch.objects.filter(pk=ranged.pk).update(template_result='vulnerable')  # hard evidence: now it is fire
		rank = CVEMatch.objects.annotate(h=match_heat_rank_expr()).filter(cve_entry=other).values_list('h', flat=True).get()
		self.assertEqual(rank, HEAT_RANK[FIRE])
		self.assertEqual(self.host_score(), scoring.CVE_POINTS['fire'] + 1)
		CVEMatch.objects.filter(pk=ranged.pk).update(template_result='')  # back to the version alone for the triage below
		p = provider()
		p.complete.return_value = '{"classification": "likely", "reason": "banner matches"}'
		match = triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain').filter(pk=ranged.pk))
		self.assertEqual(triage.run_triage(triage.track(match), provider=p)['asked'], 1)

	def test_a_non_kev_cve_without_a_range_still_makes_no_match(self):
		self.entry.kev = False
		self.entry.save()
		CVEMatch.objects.all().delete()
		self.correlate()
		self.assertEqual(CVEMatch.objects.filter(cve_entry=self.entry).count(), 0)
