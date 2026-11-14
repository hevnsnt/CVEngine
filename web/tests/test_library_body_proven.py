"""A JavaScript library version cvENGINE read from the served file's own body, for the copy the page runs, inside the affected range: the
rules confirm the match (``triage.library_rule``, per row), with a reason built from the evidence, the body read is recorded as cvENGINE's
own completed check (``validation.library_step``) and ``how_found`` says where the version came from. Everything else reads what the row
would have been without the rule: the legacy verdict, heat, paging, standing, the host score, grouping and the validation schedule are
identical to a run with the rule removed. The same version from a technology fingerprint keeps the ceiling, a version outside the range or a
read copy that a later unread copy shadows is not confirmed (nor proven for heat), and closed matches are never touched."""
import datetime
import json
import os
import unittest
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, finding_groups, js_libraries, match_policy, notify, scoring, threat, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, RouteAuth, Triage
from dashboard.models import Org, Project
from startScan.models import Subdomain, Technology
from targetApp.models import Domain
from tests.test_client_library_detection import JQUERY_11023
from tests import ai_queue

HOST = 'www.example.com'
PAGE = f'https://{HOST}/'
JQ = f'https://{HOST}/js/jquery.min.js'
CDN = 'https://cdn.example.net/jquery-2.1.3.min.js'
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


def shadowed_evidence():
	"""The reviewer's case: the read copy (banner 2.1.3) is shadowed by a later copy of the same version that was never read (a CDN file name
	only). ``HostLibraries.judge`` takes the best state of any copy (effective) but the URL, source and confidence of the read one."""
	record = {'product': 'jQuery', 'version': '2.1.3', 'copies': [
		{'url': JQ, 'version': '2.1.3', 'source': 'body', 'how': 'banner', 'order': 0, 'state': 'shadowed'},
		{'url': CDN, 'version': '2.1.3', 'source': 'filename', 'how': 'filename', 'order': 1, 'state': 'effective',
		 'filename_version': '2.1.3', 'not_read': 'third-party host'}]}
	_skip, evidence, _cap = js_libraries.HostLibraries(records={'jquery': record}, page_read=True).judge('jQuery', '2.1.3')
	return {**evidence, 'source': 'tech', 'range': RANGE}


class RuleTests(unittest.TestCase):
	"""The pure layer."""

	def proof(self, **kw):
		return {'product': 'jQuery', 'version': '2.1.3', 'script_url': JQ, 'how': 'banner', 'range': RANGE, **kw}

	def test_the_rule_words_its_reason_from_the_evidence(self):
		level, reason = triage.library_rule('cve_match', {'library_proof': self.proof()})
		self.assertEqual(level, 'confirmed')
		self.assertTrue(reason.startswith(f"jQuery 2.1.3 is served at {JQ} (the file's own banner states v2.1.3), and it is the copy the page runs"))
		self.assertIn('inside the affected range 1.0.3 to before 3.5.0', reason)
		_level, reason = triage.library_rule('cve_match', {'library_proof': self.proof(how='signature')})
		self.assertIn("(the library's own code in the file names version 2.1.3)", reason)
		self.assertEqual(triage.library_rule('cve_match', {}), ('', ''))
		self.assertEqual(triage.library_rule('nuclei', {'library_proof': self.proof()}), ('', ''))

	def test_the_stored_answer_and_the_ceiling_are_what_they_were_without_the_rule(self):
		facts = {'version_in_range': True, 'distro_status': '', 'template_result': '', 'version_only': True}
		with_proof = triage.apply_rules('cve_match', {**facts, 'library_proof': self.proof()}, parsed('likely'))
		without = triage.apply_rules('cve_match', facts, parsed('likely'))
		self.assertEqual(with_proof, without)
		self.assertEqual(with_proof['classification'], 'needs_validation')
		self.assertEqual(triage.ceiling('cve_match', {**facts, 'library_proof': self.proof()})[0], 'needs_validation')

	def test_the_predicate_is_the_library_clause_of_the_heat_policys_proof(self):
		ok = body_evidence()
		self.assertTrue(triage.library_body_proven('tech', ok, True))
		self.assertTrue(match_policy.version_read_from_component(ok))
		for bad in (fingerprint_evidence(), body_evidence(copy_state='shadowed'), body_evidence(copy_state='unresolved'),
					body_evidence(copies_unresolved=True), body_evidence(version_confidence=0.4), body_evidence(version_source='filename'),
					body_evidence(version_confidence=True), body_evidence(version_confidence='0.9'), body_evidence(copies=[]),
					body_evidence(copies=[{'url': JQ, 'version': '2.1.3', 'source': 'body', 'state': 'shadowed'}]),
					body_evidence(copies=[{'url': CDN, 'version': '2.1.3', 'source': 'body', 'state': 'effective'}])):
			self.assertFalse(triage.library_body_proven('tech', bad, True), bad)
		for url in (None, '', '/js/jquery.min.js', 'javascript:alert(1)', 'ftp://www.example.com/jquery.js', ['x']):
			bad = {**body_evidence(), 'script_url': url}
			if url is None:
				bad.pop('script_url')
			self.assertFalse(triage.library_body_proven('tech', bad, True), url)
		self.assertFalse(triage.library_body_proven('tech', ok, False))
		self.assertFalse(triage.library_body_proven('tech', ok, None))
		self.assertFalse(triage.library_body_proven('port', ok, True))
		self.assertFalse(triage.library_body_proven('tech', ok, True, distro_status='patched'))
		self.assertFalse(triage.library_body_proven('port', {'source': 'port', 'method': 'probed', 'vendor_banner': True}, True))

	def test_a_read_copy_a_later_unread_copy_shadows_proves_nothing(self):
		evidence = shadowed_evidence()
		self.assertEqual((evidence['script_url'], evidence['copy_state'], evidence['version_source']), (JQ, 'effective', 'body'))
		self.assertFalse(match_policy.script_copy_read(evidence))
		self.assertFalse(match_policy.version_read_from_component(evidence))
		self.assertFalse(triage.library_body_proven('tech', evidence, True))

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
		ai_queue.run_triage(pairs, provider=self.provider(said) if said else None)
		return {row.match_id: row for row in Triage.objects.all()}

	def without_rule(self):
		"""The rule removed: what the PR's base did with the same match."""
		return mock.patch.object(triage, 'library_proof_of', return_value=None)

	def validate(self, rows):
		def observed(check):
			return {'status': 'observed', 'summary': check['kind']}
		return validation.run_validation(self.project.id, [r.pk for r in rows], runners={k: observed for k in validation.CHECK_KINDS},
										 template_for=lambda cve_id: ('', 'no template covers this CVE'))

	def settle_all(self, batch=triage.SETTLE_BATCH):
		total, after, done = 0, 0, False
		while not done:
			changed, after, done = triage.settle_library_proven(after=after, batch=batch)
			total += changed
		return total

	def state(self, m, policy='kev'):
		"""Everything the rule must not move, for one match."""
		m = CVEMatch.objects.select_related('cve_entry', 'subdomain').get(pk=m.pk)
		with mock.patch.dict(os.environ, {'CVENGINE_HEAT_POLICY': policy}):
			heat = threat.match_heat(m)
			inputs = scoring._cve_inputs(Subdomain.objects.get(pk=m.subdomain_id))
			score = scoring._cve_lines(inputs)
		return {'ai_verdict': m.ai_verdict, 'heat': heat, 'has_standing': match_policy.has_standing(m),
				'library_standing': correlation._library_standing(m), 'score': score, 'fire_notified_at': m.fire_notified_at}


class BodyProvenTests(Base):
	def test_a_body_proven_in_range_jquery_match_is_confirmed_with_its_check_and_how_found(self):
		self.reading()
		m = self.match()
		row = self.triage_all('likely')[m.pk]
		self.assertEqual((row.classification, row.status), ('confirmed', 'triaged'))
		self.assertTrue(row.reason.startswith(f"jQuery 2.1.3 is served at {JQ} (the file's own banner states v2.1.3)"), row.reason)
		self.assertNotIn('the model says so', row.reason)
		self.assertEqual(row.verdict.model_classification, 'likely')
		self.assertEqual(row.verdict.classification, 'needs_validation')  # the shared answer is the ceiling's, as without the rule
		m.refresh_from_db()
		self.assertEqual(m.ai_reason, row.reason)
		self.assertEqual(m.ai_verdict, 'uncertain')
		# validation: the body read is recorded beside the checks; the status and its time are the real checks' (here: none could run)
		self.validate([row])
		row.refresh_from_db()
		step = validation.library_read_step(row.validation_steps)
		self.assertEqual((step['result'], step['target']), ('reaffirmed', JQ))
		self.assertEqual(step['ran_at'], READ_AT.isoformat())
		self.assertIn(f'Fetched {JQ}: the file\'s own banner states jQuery v2.1.3; it is the copy the page {PAGE} runs', step['summary'])
		self.assertIn(JQ, step['display'])
		self.assertEqual(row.validation_status, 'no_check')
		self.assertIsNone(row.validated_at)
		from agentapi.services import _how_found_match, _triage_brief
		self.assertEqual(_triage_brief(row)['validation_status'], 'observed')  # what the page shows: a check ran, not "no check exists"
		self.assertEqual(row.classification, 'confirmed')
		how = _how_found_match(CVEMatch.objects.get(pk=m.pk))
		values = {s['label']: s['value'] for s in how['steps']}
		self.assertEqual(values['Observed'], f"jQuery 2.1.3, read from the file's own banner at {JQ}")
		self.assertEqual(values['Loaded by'], f'{PAGE} (the copy the page runs)')
		self.assertTrue(values['Found by'].startswith('library body read'))
		self.assertNotIn('technology fingerprint', json.dumps(how))
		self.assertEqual(how['excerpts'], {'script_url': JQ})
		self.assertFalse(match_policy.has_hard_evidence(m.source, m.evidence, m.template_result, m.distro_status, row.validation_status))
		self.sent.assert_not_called()
		self.assertFalse(correlation._library_standing(m))  # the page's word can still close it
		self.assertEqual(triage.recap_version_only(), 0)
		self.assertEqual(Triage.objects.get(pk=row.pk).classification, 'confirmed')

	def test_the_same_version_from_a_tech_fingerprint_stays_needs_validation(self):
		m = self.match(evidence=fingerprint_evidence())
		row = self.triage_all('likely')[m.pk]
		self.assertEqual(row.classification, 'needs_validation')
		self.assertIn('only evidence is a version string', row.reason)
		self.validate([row])
		row.refresh_from_db()
		self.assertIsNone(validation.library_read_step(row.validation_steps))
		self.assertEqual(self.settle_all(), 0)
		from agentapi.services import _how_found_match
		values = {s['label']: s['value'] for s in _how_found_match(CVEMatch.objects.get(pk=m.pk))['steps']}
		self.assertEqual(values['Observed'], 'jQuery 2.1.3 (technology fingerprint of the web server)')

	def test_a_read_copy_shadowed_by_an_unread_one_is_not_confirmed_and_not_fire(self):
		m = self.match(evidence=shadowed_evidence())
		row = self.triage_all('needs_validation')[m.pk]
		self.assertEqual(row.classification, 'needs_validation')
		m = CVEMatch.objects.select_related('cve_entry').get(pk=m.pk)
		self.assertFalse(match_policy.version_proven(m))
		self.assertEqual(threat.match_heat(m), threat.SMOKE)  # on the KEV, version not proven (fire on develop before this fix)
		self.assertFalse(CVEMatch.objects.filter(pk=m.pk).filter(match_policy.version_proven_q()).exists())
		self.assertFalse(CVEMatch.objects.filter(pk=m.pk).filter(triage.library_body_proven_q()).exists())

	def test_the_database_forms_agree_with_python(self):
		cases = {'ok': body_evidence(), 'shadowed': shadowed_evidence(), 'no copies': body_evidence(copies=[]),
				 'other copy': body_evidence(copies=[{'url': CDN, 'source': 'body', 'state': 'effective'}]),
				 'relative url': body_evidence(script_url='/js/jquery.min.js',
											   copies=[{'url': '/js/jquery.min.js', 'source': 'body', 'state': 'effective'}]),
				 'fingerprint': fingerprint_evidence(), 'unresolved': body_evidence(copies_unresolved=True)}
		for label, evidence in cases.items():
			m = self.match(name=f'{label.replace(" ", "-")}.example.com', evidence=evidence)
			m.refresh_from_db()
			self.assertEqual(CVEMatch.objects.filter(pk=m.pk).filter(match_policy.version_read_from_component_q()).exists(),
							 match_policy.version_read_from_component(m.evidence), label)
			self.assertEqual(CVEMatch.objects.filter(pk=m.pk).filter(triage.library_body_proven_q()).exists(),
							 triage.library_body_proven(m.source, m.evidence, m.version_in_range, m.distro_status), label)
		self.assertEqual(sorted(CVEMatch.objects.filter(triage.library_body_proven_q()).values_list('subdomain__name', flat=True)),
						 ['ok.example.com'])

	def test_a_body_proven_version_outside_the_range_is_not_confirmed(self):
		m = self.match(version='3.6.0', in_range=False, evidence=body_evidence())
		row = self.triage_all('likely')[m.pk]
		self.assertNotEqual(row.classification, 'confirmed')
		self.assertNotIn('is served at', row.reason)
		self.validate([row])
		row.refresh_from_db()
		self.assertIsNone(validation.library_read_step(row.validation_steps))

	def test_an_answer_that_closes_on_verified_grounds_is_left_as_it_was(self):
		# a verified CDN edge lets the model clear an in-range match (triage.closure_basis): the rule does not reopen what the answer closed,
		# so the row and its legacy verdict agree, as without the rule (a follow-up decides whether the served file should outrank the edge)
		m = self.match()
		with mock.patch.object(triage, 'closure_basis', return_value=['cdn_edge_only']):
			row = self.triage_all('not_applicable')[m.pk]
		m.refresh_from_db()
		self.assertEqual((row.classification, m.ai_verdict), ('not_applicable', 'not_affected'))

	def test_with_no_provider_nothing_is_confirmed_by_absence(self):
		m = self.match()
		row = self.triage_all(None)[m.pk]
		self.assertEqual((row.status, row.classification), ('not_triaged', ''))

	def test_no_script_url_or_odd_evidence_never_breaks_anything(self):
		evidence = body_evidence()
		evidence.pop('script_url')
		m = self.match(evidence=evidence)
		with self.without_rule():
			row = self.triage_all('likely')[m.pk]
		self.assertEqual(self.settle_all(), 0)
		self.validate([Triage.objects.get(pk=row.pk)])
		self.assertEqual(Triage.objects.get(pk=row.pk).classification, 'needs_validation')
		from agentapi.services import _how_found_match
		for i, odd in enumerate(({'source': 'tech', 'version_source': 'body', 'script_url': JQ, 'version_confidence': '0.95'},
								 {'source': 'tech', 'version_source': 'body', 'script_url': JQ, 'version_confidence': 0.9, 'copy_state': ['effective']},
								 {'source': 'tech', 'version_source': 'body', 'script_url': ['x'], 'version_confidence': 0.9})):
			odd_match = self.match(name=f'odd{i}.example.com', evidence=odd)
			_how_found_match(CVEMatch.objects.select_related('subdomain__target_domain').get(pk=odd_match.pk))


class NothingElseMovesTests(Base):
	"""B1: with other hard evidence beside the body read (runZero, the host's own report), on and off the KEV, the legacy verdict, standing
	and paging under the legacy policy are exactly what they are with the rule removed. Since 1.3.5 heat reads the row's own classification
	(``threat.triage_cap``: needs validation is smoke at most), so where the model left such a match at needs validation the rule's
	confirmation is what lets its hard evidence show: heat, the score and the KEV-rule page may only rise with the rule, never fall."""

	def run_case(self, extra, kev, cvss):
		self.cve.kev, self.cve.cvss = kev, cvss
		self.cve.save()
		results = {}
		for label in ('without', 'with'):
			CVEMatch.objects.all().delete()
			Triage.objects.all().delete()
			m = self.match(evidence=body_evidence(**extra))
			since = timezone.now() - datetime.timedelta(minutes=5)
			if label == 'without':
				with self.without_rule():
					rows = self.triage_all('needs_validation')
			else:
				rows = self.triage_all('needs_validation')
				self.assertEqual(rows[m.pk].classification, 'confirmed')
			self.sent.reset_mock()
			with mock.patch.dict(os.environ, {'CVENGINE_HEAT_POLICY': 'legacy'}), mock.patch('cveFeed.notify.enabled_channels', return_value=['slack']):
				notify.fire_matches(since)
				pages_legacy = self.sent.call_count
			self.sent.reset_mock()
			with mock.patch('cveFeed.notify.enabled_channels', return_value=['slack']):
				notify.fire_matches(since)
				pages_kev = self.sent.call_count
			results[label] = {**self.state(m, 'kev'), 'legacy': self.state(m, 'legacy'), 'pages_legacy': pages_legacy, 'pages_kev': pages_kev}
			results[label].pop('fire_notified_at')
			results[label]['legacy'].pop('fire_notified_at')
		moved = {}
		for label in ('with', 'without'):
			moved[label] = (threat.HEAT_RANK[results[label].pop('heat')], threat.HEAT_RANK[results[label]['legacy'].pop('heat')],
							results[label].pop('pages_kev'), results[label].pop('pages_legacy'))
			results[label].pop('score')
			results[label]['legacy'].pop('score')
		self.assertEqual(results['with'], results['without'], (extra, kev, cvss))
		for now, before in zip(moved['with'], moved['without']):
			self.assertGreaterEqual(now, before, (extra, kev, cvss))

	def test_runzero_host_reported_and_non_kev(self):
		for extra in ({'runzero': True}, {'host_reported': {'inventory_id': 1, 'component': 'jquery'}}, {}):
			for kev, cvss in ((True, 9.1), (False, 9.1), (False, 7.5), (True, 6.9)):
				self.run_case(extra, kev, cvss)


class ExistingRowsTests(Base):
	"""Rows judged before the rule: the settle step brings them in line, once, without paging, without touching the validation schedule or
	closed matches, and reaching every row however small the batch."""

	def test_existing_rows_are_settled_once_without_a_page(self):
		self.reading()
		m = self.match()
		with self.without_rule():
			row = self.triage_all('likely')[m.pk]
		self.assertEqual(row.classification, 'needs_validation')
		Triage.objects.filter(pk=row.pk).update(validation_status='pending')
		before = (self.state(m), self.state(m, 'legacy'))
		self.assertEqual(self.settle_all(), 1)
		row.refresh_from_db()
		self.assertEqual(row.classification, 'confirmed')
		self.assertTrue(row.reason.startswith(f'jQuery 2.1.3 is served at {JQ}'))
		self.assertEqual(row.verdict.model_classification, 'likely')
		self.assertIsNotNone(validation.library_read_step(row.validation_steps))
		self.assertEqual((row.validation_status, row.validated_at), ('pending', None))  # still queued for its real check
		self.assertIn(row.pk, validation.due_ids(self.project.id))
		self.assertEqual((self.state(m), self.state(m, 'legacy')), before)
		self.sent.assert_not_called()
		stamp = Triage.objects.get(pk=row.pk).updated_at
		self.assertEqual(self.settle_all(), 0)
		self.assertEqual(Triage.objects.get(pk=row.pk).updated_at, stamp)
		provider = self.provider('likely')
		ai_queue.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=provider)
		provider.complete.assert_not_called()
		self.assertEqual(Triage.objects.get(pk=row.pk).classification, 'confirmed')

	def test_a_small_batch_reaches_every_row(self):
		self.reading()
		ms = [self.match(name=f'h{i}.example.com') for i in range(5)]
		with self.without_rule():
			self.triage_all('likely')
		self.assertEqual(self.settle_all(batch=2), 5)
		self.assertEqual([Triage.objects.get(match_id=m.pk).classification for m in ms], ['confirmed'] * 5)

	def test_the_task_runs_once_in_batches_and_resumes(self):
		from cveFeed import tasks
		from cveFeed.models import BackgroundCursor
		self.reading()
		ms = [self.match(name=f't{i}.example.com') for i in range(3)]
		with self.without_rule():
			self.triage_all('likely')
		ticks = iter([0, 0, 1000])  # one batch, then the time is up
		with mock.patch.object(triage, 'SETTLE_BATCH', 2), mock.patch.object(triage.settle_library_proven, '__defaults__', (0, 2)), \
				mock.patch.object(tasks.settle_library_proven_task, 'apply_async') as again, self.captureOnCommitCallbacks(execute=True):
			first = tasks.settle_library_proven_task(seconds=10, clock=lambda: next(ticks))
		self.assertEqual(first['state'], 'resumed')
		again.assert_called_once()
		self.assertEqual(BackgroundCursor.objects.get(lane=tasks.SETTLE_LANE).last_pk, Triage.objects.get(match_id=ms[1].pk).pk)
		second = tasks.settle_library_proven_task()
		self.assertEqual(second['state'], 'done')
		self.assertEqual([Triage.objects.get(match_id=m.pk).classification for m in ms], ['confirmed'] * 3)
		self.assertEqual(tasks.settle_library_proven_task(), {'state': 'done'})

	def test_an_untriaged_row_gets_the_read_but_no_classification(self):
		self.reading()
		m = self.match()
		row = self.triage_all(None)[m.pk]
		self.assertEqual(self.settle_all(), 1)
		row.refresh_from_db()
		self.assertEqual((row.status, row.classification), ('not_triaged', ''))  # never confirmed by the model's absence
		self.assertIsNotNone(validation.library_read_step(row.validation_steps))

	def test_closed_matches_are_untouched(self):
		fixed = self.match(remediation_status='fixed')
		ruled_out = self.match(name='blog.example.com')
		with self.without_rule():
			rows = self.triage_all('likely')
		CVEMatch.objects.filter(pk=ruled_out.pk).update(ai_verdict='not_affected', ai_reason='Closed automatically: test')
		snapshot = {pk: (r.classification, r.reason, r.validation_steps, r.updated_at) for pk, r in rows.items()}
		self.assertEqual(self.settle_all(), 0)
		for pk, row in rows.items():
			row.refresh_from_db()
			self.assertEqual((row.classification, row.reason, row.validation_steps, row.updated_at), snapshot[pk])
		self.assertEqual(CVEMatch.objects.get(pk=fixed.pk).remediation_status, 'fixed')
		self.assertEqual(CVEMatch.objects.get(pk=ruled_out.pk).ai_verdict, 'not_affected')


class ScheduleTests(Base):
	"""The recorded body read is not a validation to any scheduler."""

	def test_p11_settling_does_not_hold_back_the_fire_lane_script_read(self):
		from cveFeed import hot_validation
		self.reading()
		m = self.match()
		with self.without_rule():
			row = self.triage_all('likely')[m.pk]
		lane = hot_validation.tier_for(Triage.objects.select_related('match__cve_entry').get(pk=row.pk))
		with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async', return_value=None), \
				mock.patch('cveFeed.tasks.validate_match_on_demand.delay', return_value=None):
			from django.db import transaction
			with transaction.atomic():
				point = transaction.savepoint()
				before = hot_validation.enqueue(row, lane)
				transaction.savepoint_rollback(point)
			self.settle_all()
			row.refresh_from_db()
			after = hot_validation.enqueue(row, lane)
		self.assertEqual((before, after), ('queued', 'queued'))

	def test_a_capped_check_stays_pending_as_before(self):
		self.reading()
		m = self.match()
		check = validation._check('script_read', 'Script read', ['probe'], 'probe', f'{PAGE}#script-read', f'{PAGE}#script-read', 'sig', 10)
		results = {}
		for label in ('without', 'with'):
			Triage.objects.all().delete()
			ctx = self.without_rule() if label == 'without' else mock.patch.object(triage, 'CHUNK', triage.CHUNK)
			with ctx:
				row = self.triage_all('likely')[m.pk]
				with mock.patch.object(validation, 'plan_checks', return_value=([check], [])), \
						mock.patch.object(validation, '_reserve_validation_check', return_value=False):
					stats = self.validate([row])
			row.refresh_from_db()
			results[label] = (row.validation_status, row.validated_at is None, row.next_attempt_at, stats['capped'])
		self.assertEqual(results['with'], results['without'])
		self.assertEqual(results['with'][0], 'pending')

	def test_a_finished_check_rolls_up_as_without_the_read(self):
		self.reading()
		m = self.match()
		row = self.triage_all('likely')[m.pk]
		check = validation._check('script_read', 'Script read', ['probe'], 'probe', f'{PAGE}#script-read', f'{PAGE}#script-read', 'sig', 10)
		with mock.patch.object(validation, 'plan_checks', return_value=([check], [])):
			validation.run_validation(self.project.id, [row.pk], runners={'script_read': lambda c: {'status': 'blocked', 'summary': 'held'}},
									  template_for=lambda cve_id: ('', ''))
		row.refresh_from_db()
		self.assertIsNotNone(validation.library_read_step(row.validation_steps))
		self.assertEqual(row.validation_status, 'skipped_blocked')  # the read is not a check here: every real check was blocked


class GroupingTests(Base):
	def test_the_same_file_on_sibling_hosts_still_groups(self):
		self.reading()
		one = self.match()
		two = self.match(name='two.example.com')
		rows = self.triage_all('likely')
		self.assertEqual({rows[one.pk].classification, rows[two.pk].classification}, {'confirmed'})
		built, _n = finding_groups.read(CVEMatch.objects.filter(pk__in=[one.pk, two.pk]).order_by('pk'), with_list_fields=False)
		self.assertEqual([len(g['members']) for g in built], [2])
		# a validation hit still keeps a match its own row, as before
		Triage.objects.filter(match_id=two.pk).update(validation_status='hit')
		built, _n = finding_groups.read(CVEMatch.objects.filter(pk__in=[one.pk, two.pk]).order_by('pk'), with_list_fields=False)
		self.assertEqual(sorted(len(g['members']) for g in built), [1, 1])


class MutationTests(Base):
	"""Without the new branch (``library_rule`` answering nothing), the same match sits at needs validation: the tests above catch it."""

	def test_removing_the_rule_is_caught(self):
		m = self.match()
		with mock.patch.object(triage, 'library_rule', return_value=('', '')):
			row = self.triage_all('likely')[m.pk]
		self.assertEqual(row.classification, 'needs_validation')
