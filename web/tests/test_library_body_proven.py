"""A JavaScript library version cvENGINE read from the served file's own body, for the copy the page runs, inside the affected range: the
rules confirm the match (``triage.library_rule``), with a reason built from the evidence, the version-only ceiling does not hold it, the body
read is recorded as cvENGINE's own completed check (``validation.record_library_read``) and ``how_found`` says where the version came from.
The same version from a technology fingerprint keeps the ceiling exactly as before, a version outside the range is not confirmed, closed
matches are never touched, and neither the heat nor the paging moves."""
import datetime
import json
import os
import unittest
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, match_policy, threat, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, RouteAuth, Triage
from dashboard.models import Org, Project
from startScan.models import Subdomain, Technology
from targetApp.models import Domain
from tests.test_client_library_detection import JQUERY_11023

HOST = 'www.example.com'
PAGE = f'https://{HOST}/'
JQ = f'https://{HOST}/js/jquery.min.js'
RANGE = {'introduced': '1.0.3', 'fixed': '3.5.0'}
READ_AT = timezone.now() - datetime.timedelta(hours=3)


def parsed(classification='likely', **kw):
	return {'classification': classification, 'reason': 'the model says so', 'impact': 'bad', 'severity_adjust': 0, 'severity_reason': '',
			'remediation': 'upgrade', 'validation_steps': [], **kw}


def body_evidence(**kw):
	"""What correlation records for the effective copy whose own banner states the version (js_libraries.HostLibraries.judge)."""
	return {'source': 'tech', 'version_source': 'body', 'copy_state': 'effective', 'version_confidence': 0.9, 'script_url': JQ,
			'page_fresh': True, 'range': RANGE, 'copies': [{'url': JQ, 'version': '2.1.3', 'source': 'body', 'order': 0, 'state': 'effective'}],
			**kw}


def fingerprint_evidence(**kw):
	"""The same version named by a technology fingerprint only (httpx/Wappalyzer): no file stated it."""
	return {'source': 'tech', 'version_source': 'other', 'version_confidence': 0.4, 'range': RANGE, **kw}


class RuleTests(unittest.TestCase):
	"""The pure layer: ``apply_rules`` and the ceiling."""

	def facts(self, **kw):
		return {'version_in_range': True, 'distro_status': '', 'template_result': '', 'version_only': True, **kw}

	def proof(self, **kw):
		return {'product': 'jQuery', 'version': '2.1.3', 'script_url': JQ, 'how': 'banner', 'range': RANGE, **kw}

	def test_a_body_proven_library_is_confirmed_by_the_rules_in_their_own_words(self):
		for said in ('likely', 'needs_validation', 'likely_false_positive', 'not_applicable', 'confirmed'):
			out = triage.apply_rules('cve_match', self.facts(library_proof=self.proof()), parsed(said))
			self.assertEqual(out['classification'], 'confirmed', said)
			self.assertNotIn('the model says so', out['reason'])
			self.assertIn("jQuery 2.1.3 is served at /js/jquery.min.js (the file's own banner states v2.1.3)", out['reason'])
			self.assertIn('inside the affected range 1.0.3 to before 3.5.0', out['reason'])
			self.assertNotIn(HOST, out['reason'])  # the stored answer is shared by signature: no host in it
			self.assertEqual(out['model_reason'], 'the model says so')
			self.assertEqual(out['overridden'], said != 'confirmed')
		self.assertEqual(triage.ceiling('cve_match', self.facts(library_proof=self.proof())), ('', ''))
		_level, reason = triage.library_rule('cve_match', {'library_proof': self.proof(how='signature')})
		self.assertIn(f'is served at {JQ} (the library\'s own code in the file names version 2.1.3)', reason)

	def test_without_the_proof_the_version_only_ceiling_holds_exactly_as_before(self):
		out = triage.apply_rules('cve_match', self.facts(), parsed('likely'))
		self.assertEqual(out['classification'], 'needs_validation')
		self.assertTrue(out['reason'].startswith('AI said likely but the only evidence is a version string inside the affected range'))

	def test_the_predicate_is_the_library_clause_of_the_heat_policys_proof(self):
		ok = body_evidence()
		self.assertTrue(triage.library_body_proven('tech', ok, True))
		self.assertTrue(match_policy.version_read_from_component(ok))
		for bad in (fingerprint_evidence(), body_evidence(copy_state='shadowed'), body_evidence(copy_state='unresolved'),
					body_evidence(copies_unresolved=True), body_evidence(version_confidence=0.4), body_evidence(version_source='filename'),
					body_evidence(version_confidence=True), body_evidence(version_confidence='0.9')):
			self.assertFalse(triage.library_body_proven('tech', bad, True), bad)
		self.assertFalse(triage.library_body_proven('tech', ok, False))
		self.assertFalse(triage.library_body_proven('tech', ok, None))
		self.assertFalse(triage.library_body_proven('port', ok, True))
		self.assertFalse(triage.library_body_proven('tech', ok, True, distro_status='patched'))
		# a version-class template hit or a vendor banner proves the version for heat, but is not a library body read: the ceiling stays
		self.assertFalse(triage.library_body_proven('port', {'source': 'port', 'method': 'probed', 'vendor_banner': True}, True))

	def test_range_text(self):
		self.assertEqual(triage.range_text({'introduced': '0', 'fixed': '4.4.0'}), 'before 4.4.0')
		self.assertEqual(triage.range_text({'introduced': '1.2', 'last_affected': '1.9'}), '1.2 to up to 1.9')
		self.assertEqual(triage.range_text({}), '')


class Base(TestCase):
	def setUp(self):
		cache.clear()
		org = Org.objects.create(name='Example', slug='example')
		self.project = Project.objects.create(name='P', slug='p-example', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
		self.cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', title='Potential XSS vulnerability in jQuery', kev=True, cvss=6.9,
										   published_at=timezone.now(), affected=JQUERY_11023)
		self.sent = mock.Mock(return_value=False)
		for patched in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
						mock.patch('targetApp.target_types.is_scannable_ip', return_value=True),
						mock.patch('cveFeed.activity.log', return_value=None),
						mock.patch('cveFeed.notify._send', self.sent),
						mock.patch.dict(os.environ, {'CVENGINE_VALIDATE_MAX_PER_RUN': '500', 'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': '500',
													 'CVENGINE_VALIDATE_MAX_PER_DAY': '500'})):
			patched.start()
			self.addCleanup(patched.stop)

	def match(self, version='2.1.3', evidence=None, in_range=True, name=HOST, **kw):
		sub = Subdomain.objects.filter(name=name).first() or Subdomain.objects.create(name=name, target_domain=self.domain)
		tech, _ = Technology.objects.get_or_create(name=f'jQuery:{version}')
		sub.technologies.add(tech)
		evidence = {**(evidence if evidence is not None else body_evidence()), 'source_id': tech.id}
		return CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='jQuery', matched_version=version,
									   version_in_range=in_range, source='tech', confidence=0.9, evidence=evidence, **kw)

	def reading(self, version='2.1.3', how='banner'):
		"""The route check's reading of the front page that found the file stating the version."""
		record = {'product': 'jQuery', 'version': version, 'version_source': 'body', 'version_confidence': 0.9, 'how': how, 'script_url': JQ,
				  'copies': [{'url': JQ, 'version': version, 'source': 'body', 'how': how, 'order': 0, 'state': 'effective'}]}
		return RouteAuth.objects.create(project=self.project, domain=self.domain, host=HOST, path='/', url=PAGE, auth_state='public',
										http_status=200, checked_at=READ_AT, evidence={'libraries': {'jquery': record}})

	def provider(self, said='likely'):
		p = mock.Mock(model='m')
		p.name = 'anthropic'
		p.complete.return_value = json.dumps(parsed(said))
		return p

	def triage_all(self, said='likely'):
		pairs = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
		triage.run_triage(pairs, provider=self.provider(said) if said else None)
		return {row.match_id: row for row in Triage.objects.all()}

	def validate(self, rows):
		def observed(check):
			return {'status': 'observed', 'summary': check['kind']}
		return validation.run_validation(self.project.id, [r.pk for r in rows], runners={k: observed for k in validation.CHECK_KINDS},
										 template_for=lambda cve_id: ('', 'no template covers this CVE'))


class BodyProvenTests(Base):
	def test_a_body_proven_in_range_jquery_match_is_confirmed_with_its_check_and_how_found(self):
		self.reading()
		m = self.match()
		heat_before = threat.match_heat(CVEMatch.objects.select_related('cve_entry').get(pk=m.pk))
		row = self.triage_all('likely')[m.pk]
		self.assertEqual((row.classification, row.status), ('confirmed', 'triaged'))
		self.assertTrue(row.reason.startswith(f"jQuery 2.1.3 is served at {JQ} (the file's own banner states v2.1.3)"), row.reason)
		self.assertNotIn('the model says so', row.reason)
		self.assertEqual(row.verdict.model_classification, 'likely')
		m.refresh_from_db()
		self.assertEqual(m.ai_reason, row.reason)
		self.assertEqual(m.ai_verdict, 'uncertain')  # the legacy verdict (legacy heat, score bonus, standing) does not move
		# validation: the body read is cvENGINE's own completed check, never no_check and never a hit
		self.validate([row])
		row.refresh_from_db()
		self.assertNotIn(row.validation_status, ('no_check', 'none', 'hit'))
		step = validation.library_read_step(row.validation_steps)
		self.assertEqual((step['result'], step['target']), ('reaffirmed', JQ))
		self.assertEqual(step['ran_at'], READ_AT.isoformat())
		self.assertIn(f'Fetched {JQ}: the file\'s own banner states jQuery v2.1.3; it is the copy the page {PAGE} runs', step['summary'])
		self.assertIn(JQ, step['display'])
		self.assertEqual(row.classification, 'confirmed')
		# how it was found
		from agentapi.services import _how_found_match
		how = _how_found_match(CVEMatch.objects.get(pk=m.pk))
		values = {s['label']: s['value'] for s in how['steps']}
		self.assertEqual(values['Observed'], f"jQuery 2.1.3, read from the file's own banner at {JQ}")
		self.assertEqual(values['Loaded by'], f'{PAGE} (the copy the page runs)')
		self.assertTrue(values['Found by'].startswith('library body read'))
		self.assertNotIn('technology fingerprint', json.dumps(how))
		self.assertEqual(how['excerpts'], {'script_url': JQ})
		# the heat and the paging are unchanged: no message was sent, the heat is the same under both policies
		m = CVEMatch.objects.select_related('cve_entry').get(pk=m.pk)
		self.assertEqual(threat.match_heat(m), heat_before)
		self.assertEqual(threat.match_heat(m), threat.FIRE)  # on the KEV and proven, as it was
		with mock.patch.dict(os.environ, {'CVENGINE_HEAT_POLICY': 'legacy'}):
			self.assertEqual(threat.heat_policy(), threat.LEGACY_POLICY)
			self.assertEqual(threat.match_heat(m), threat.SMOKE)  # legacy: still version-only, held at the cap as before
		self.assertFalse(match_policy.has_hard_evidence(m.source, m.evidence, m.template_result, m.distro_status, row.validation_status))
		self.sent.assert_not_called()
		# the page's word can still close it: the rules' confirmation is no standing against a newer reading
		self.assertFalse(correlation._library_standing(m))
		# the startup recap of version-only answers leaves it confirmed
		self.assertEqual(triage.recap_version_only(), 0)
		self.assertEqual(Triage.objects.get(pk=row.pk).classification, 'confirmed')

	def test_a_second_validation_keeps_the_read_and_ends_queued_requests(self):
		self.reading()
		m = self.match()
		row = self.triage_all('likely')[m.pk]
		self.validate([row])
		row.refresh_from_db()
		steps = row.validation_steps
		Triage.objects.filter(pk=row.pk).update(validation_status='pending', validated_at=timezone.now() - datetime.timedelta(days=3))
		row.refresh_from_db()
		stats = self.validate([row])
		row.refresh_from_db()
		self.assertEqual(row.validation_steps, steps)
		self.assertNotIn(row.validation_status, ('pending', 'no_check'))
		self.assertGreater(row.validated_at, timezone.now() - datetime.timedelta(minutes=5))  # not due again at every sweep
		self.assertEqual(stats['no_check'], 0)

	def test_the_same_version_from_a_tech_fingerprint_stays_needs_validation(self):
		m = self.match(evidence=fingerprint_evidence())
		row = self.triage_all('likely')[m.pk]
		self.assertEqual(row.classification, 'needs_validation')
		self.assertIn('only evidence is a version string', row.reason)
		self.validate([row])
		row.refresh_from_db()
		self.assertIsNone(validation.library_read_step(row.validation_steps))
		self.assertEqual(triage.settle_library_proven(), 0)
		from agentapi.services import _how_found_match
		values = {s['label']: s['value'] for s in _how_found_match(CVEMatch.objects.get(pk=m.pk))['steps']}
		self.assertEqual(values['Observed'], 'jQuery 2.1.3 (technology fingerprint of the web server)')

	def test_a_shadowed_body_read_stays_needs_validation(self):
		m = self.match(evidence=body_evidence(copy_state='shadowed', version_confidence=0.4))
		self.assertEqual(self.triage_all('likely')[m.pk].classification, 'needs_validation')

	def test_a_body_proven_version_outside_the_range_is_not_confirmed(self):
		m = self.match(version='3.6.0', in_range=False, evidence=body_evidence())
		row = self.triage_all('likely')[m.pk]
		self.assertNotEqual(row.classification, 'confirmed')
		self.assertNotIn('is served at', row.reason)
		self.validate([row])
		row.refresh_from_db()
		self.assertIsNone(validation.library_read_step(row.validation_steps))

	def test_with_no_provider_nothing_is_confirmed_by_absence(self):
		m = self.match()
		row = self.triage_all(None)[m.pk]
		self.assertEqual((row.status, row.classification), ('not_triaged', ''))


class ExistingRowsTests(Base):
	"""Rows judged before the rule: the data step brings them in line, once, without paging and without touching closed matches."""

	def judged_before_the_rule(self):
		with mock.patch.object(triage, 'library_proof_of', return_value=None):
			return self.triage_all('likely')

	def test_existing_rows_are_settled_once_without_a_page(self):
		self.reading()
		m = self.match()
		row = self.judged_before_the_rule()[m.pk]
		self.assertEqual(row.classification, 'needs_validation')
		m.refresh_from_db()
		before = (m.ai_verdict, m.fire_notified_at, threat.match_heat(CVEMatch.objects.select_related('cve_entry').get(pk=m.pk)))
		self.assertEqual(triage.settle_library_proven(), 1)
		row.refresh_from_db()
		self.assertEqual(row.classification, 'confirmed')
		self.assertTrue(row.reason.startswith(f'jQuery 2.1.3 is served at {JQ}'))
		self.assertEqual(row.verdict.model_classification, 'likely')  # the model's own words are kept on its answer
		self.assertIsNotNone(validation.library_read_step(row.validation_steps))
		self.assertNotEqual(row.validation_status, 'no_check')
		m.refresh_from_db()
		after = (m.ai_verdict, m.fire_notified_at, threat.match_heat(CVEMatch.objects.select_related('cve_entry').get(pk=m.pk)))
		self.assertEqual(before, after)
		self.sent.assert_not_called()
		stamp = Triage.objects.get(pk=row.pk).updated_at
		self.assertEqual(triage.settle_library_proven(), 0)  # idempotent: nothing is written the second time
		self.assertEqual(Triage.objects.get(pk=row.pk).updated_at, stamp)
		# the next triage pass keeps it (the signature did not move, no new question is asked)
		provider = self.provider('likely')
		triage.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=provider)
		provider.complete.assert_not_called()
		self.assertEqual(Triage.objects.get(pk=row.pk).classification, 'confirmed')

	def test_closed_matches_are_untouched(self):
		fixed = self.match(remediation_status='fixed')
		ruled_out = self.match(name='blog.example.com')
		rows = self.judged_before_the_rule()
		CVEMatch.objects.filter(pk=ruled_out.pk).update(ai_verdict='not_affected', ai_reason='Closed automatically: test')
		snapshot = {pk: (r.classification, r.reason, r.validation_steps, r.updated_at) for pk, r in rows.items()}
		self.assertEqual(triage.settle_library_proven(), 0)
		for pk, row in rows.items():
			row.refresh_from_db()
			self.assertEqual((row.classification, row.reason, row.validation_steps, row.updated_at), snapshot[pk])
		self.assertEqual(CVEMatch.objects.get(pk=fixed.pk).remediation_status, 'fixed')
		self.assertEqual(CVEMatch.objects.get(pk=ruled_out.pk).ai_verdict, 'not_affected')


class MutationTests(Base):
	"""Without the new branch (``library_rule`` answering nothing), the same match sits at needs validation: the tests above catch it."""

	def test_removing_the_rule_is_caught(self):
		m = self.match()
		with mock.patch.object(triage, 'library_rule', return_value=('', '')):
			row = self.triage_all('likely')[m.pk]
		self.assertNotEqual(row.classification, 'confirmed')
