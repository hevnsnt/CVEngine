"""Validating a CVE match on a client-side JavaScript library (jQuery, CVE-2020-11023): the validation reads the page's scripts again
(the html-libraries read), never runs nmap or a HEAD for it, records the fresh version evidence, reaffirms an affected version without
calling it a hit, closes a fixed, gone or redirect-alias match through the guarded closure, and leaves a held-back or failed read alone."""
import unittest
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, match_policy, triage, validation
from cveFeed.models import CVEMatch, MatchVerdict, OnDemandValidation, Triage, TriageVerdict
from dashboard.models import Org, Project
from startScan.models import Subdomain, Technology
from targetApp.models import Domain
from tests.test_client_library_detection import JQUERY_11023

RANGES = [e['ranges'] for e in JQUERY_11023 if e.get('product') == 'jQuery' or e.get('package') in ('jquery', 'jQuery', 'components/jquery',
																									'org.webjars.npm:jquery')]
PAGE = 'https://www.v.test/'


def script(version):
	return f'/*! jQuery v{version} | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){{}}'


class Site:
	"""A fake network for the read: ``pages`` maps a URL to the answer ``probes.fetch`` would give."""
	def __init__(self, pages=None, error=None):
		self.pages, self.error, self.calls = pages or {}, error, []

	def __call__(self, url, headers=None):
		self.calls.append(url)
		if self.error:
			raise self.error
		answer = self.pages.get(url, {'status': 404, 'body': ''})
		return {'final_url': url, 'raw_headers': {}, 'challenge': '', **answer}


def page(*sources, status=200, final=PAGE):
	return {'status': status, 'final_url': final, 'body': ''.join(f'<script src="{s}"></script>' for s in sources)}


def jquery_site(version='1.12.4'):
	return Site({PAGE: page('/js/jquery.min.js'), 'https://www.v.test/js/jquery.min.js': {'status': 200, 'body': script(version)}})


class LibraryPlanTests(unittest.TestCase):
	SIG = 'a' * 40

	def subject(self, **kw):
		return {'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-2020-11023', 'source': 'tech', 'url': PAGE, 'library': 'jquery',
				'library_product': 'jQuery', 'library_ranges': RANGES, 'candidate_services': [{'ip': '203.0.113.7', 'port': 443}],
				'project_id': 1, 'domain_id': 1, 'matched_version': '1.12.4', **kw}

	def test_a_library_match_is_validated_by_the_script_read_and_never_by_nmap_or_a_head(self):
		checks, notes = validation.plan_checks(self.subject(), self.SIG)
		self.assertEqual([c['kind'] for c in checks], ['script_read'])
		self.assertEqual(notes, [])
		check = checks[0]
		self.assertEqual(check['argv'], ['probe', 'html-libraries', 'https://www.v.test'])
		self.assertNotIn('nmap', check['display'])
		self.assertEqual(check['params']['library'], 'jquery')
		with_template, _ = validation.plan_checks(self.subject(), self.SIG, ('/t/CVE-2020-11023.yaml', ''))
		self.assertEqual([c['kind'] for c in with_template], ['nuclei_template', 'script_read'])
		none, notes = validation.plan_checks(self.subject(url=None), self.SIG)
		self.assertEqual(none, [])
		self.assertIn('no web page', notes[0])

	def test_the_plan_always_keeps_the_script_read(self):
		from cveFeed import validation_plan
		checks, _ = validation.plan_checks(self.subject(), self.SIG)
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
			decision, _provider = validation_plan.plan(1, mock.Mock(signature='s'), mock.Mock(), self.subject(), checks, ('', 'none'))
		self.assertEqual(decision['check_kinds'], ['script_read'])


class LibraryOutcomeTests(unittest.TestCase):
	"""``library_outcome`` is pure: what a fresh read means for the match."""
	PARAMS = {'library': 'jquery', 'product': 'jQuery', 'ranges': RANGES, 'version_source': 'body'}

	def record(self, *copies, unresolved=False):
		last = copies[-1]
		return {'jquery': {'product': 'jQuery', 'version': last['version'], 'version_source': last.get('source', 'body'),
						   'version_confidence': 0.9, 'script_url': last['url'], 'copies_unresolved': unresolved, 'copies': list(copies)}}

	def copy(self, version, state='effective', source='body', url='https://www.v.test/js/jquery.min.js'):
		return {'url': url, 'version': version, 'source': source, 'state': state}

	def outcome(self, records=None, **reading):
		return validation.library_outcome(self.PARAMS, {'outcome': 'read', 'status': 200, 'records': records or {}, 'skipped': [], 'unread': [],
														**reading})

	def test_each_reading_has_one_meaning(self):
		reaffirmed = self.outcome(self.record(self.copy('1.12.4')))
		self.assertEqual(reaffirmed['status'], 'reaffirmed')
		self.assertNotIn('close_reason', reaffirmed)
		self.assertEqual((reaffirmed['library']['version'], reaffirmed['library']['version_source']), ('1.12.4', 'body'))
		fixed = self.outcome(self.record(self.copy('3.6.0')))
		self.assertEqual(fixed['status'], 'version_changed')
		self.assertTrue(fixed['close_reason'].startswith(correlation.SCRIPT_READ))
		gone = self.outcome({})
		self.assertEqual(gone['status'], 'version_changed')
		self.assertIn('no longer loads jQuery', gone['close_reason'])
		alias = validation.library_outcome(self.PARAMS, {'outcome': 'alias', 'status': 301, 'alias_of': 'www.other.test'})
		self.assertEqual(alias['status'], 'version_changed')
		self.assertIn('redirect alias', alias['close_reason'])

	def test_anything_that_leaves_doubt_is_observed_and_never_closes(self):
		cases = {
			'shadowed old copy': self.outcome(self.record(self.copy('1.12.4', state='shadowed'), self.copy('3.6.0', url='https://cdn/x.js'))),
			'file name only': self.outcome(self.record(self.copy('1.12.4', source='filename'))),
			'unresolved copies': self.outcome(self.record(self.copy('1.12.4', state='unresolved'), self.copy('3.6.0', state='unresolved'),
														  unresolved=True)),
			'not every script read': self.outcome({}, skipped=[('https://www.v.test/app.js', 'page host limit')]),
			'another tool saw it, a third-party script unread': validation.library_outcome(
				{**self.PARAMS, 'version_source': 'other'}, {'outcome': 'read', 'status': 200, 'records': {}, 'skipped': [],
															  'unread': ['https://widgets.example.net/w.js']}),
			'fixed but another copy unread': self.outcome(self.record(self.copy('3.6.0')), skipped=[('https://www.v.test/b.js', 'not served')]),
			'error page': validation.library_outcome(self.PARAMS, {'outcome': 'error_page', 'status': 403}),
		}
		for name, result in cases.items():
			self.assertEqual(result['status'], 'observed', name)
			self.assertNotIn('close_reason', result, name)
		self.assertEqual(validation.library_outcome(self.PARAMS, {'outcome': 'challenged', 'challenge': 'Cloudflare'})['status'], 'blocked')
		self.assertEqual(validation.library_outcome(self.PARAMS, {'outcome': 'error_page', 'status': 503})['status'], 'failed')


class LibraryValidationTests(TestCase):
	def setUp(self):
		from cveFeed.models import CVEEntry
		org = Org.objects.create(name='V', slug='v')
		self.project = Project.objects.create(name='P', slug='pv', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='v.test', project=self.project, insert_date=timezone.now())
		self.cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', title='Potential XSS vulnerability in jQuery', kev=True, cvss=6.9,
										   published_at=timezone.now(), affected=JQUERY_11023)
		for patched in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
						mock.patch('targetApp.target_types.is_scannable_ip', return_value=True),
						mock.patch('cveFeed.activity.log', return_value=None),
						mock.patch('cveFeed.notify._send', return_value=False),
						mock.patch('cveFeed.probes.REQUEST_GAP', 0)):
			patched.start()
			self.addCleanup(patched.stop)

	def match(self, **kw):
		sub = Subdomain.objects.create(name='www.v.test', target_domain=self.domain, http_url='https://www.v.test')
		tech = Technology.objects.create(name='jQuery:1.12.4')
		sub.technologies.add(tech)
		return CVEMatch.objects.create(
			cve_entry=self.cve, subdomain=sub, matched_product='jQuery', matched_version='1.12.4', version_in_range=True, source='tech',
			confidence=0.9, evidence={'source': 'tech', 'source_id': tech.id, 'version_source': 'body', 'script_url': PAGE + 'js/jquery.min.js',
									  'range': {'introduced': '1.0.3', 'fixed': '3.5.0'}}, **kw)

	def row(self):
		pairs = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
		triage.run_triage(pairs, provider=None)
		return Triage.objects.get()

	def validate(self, site, row=None):
		row = row or self.row()
		calls = []

		def other(kind):
			def run(check):
				calls.append(kind)
				return {'status': 'observed', 'summary': kind}
			return run
		runners = {**{k: other(k) for k in validation.CHECK_KINDS}, 'script_read': lambda check: validation.run_script_read(check, get=site)}
		stats = validation.run_validation(self.project.id, [row.pk], runners=runners, template_for=lambda cve_id: ('', 'no template covers this CVE'))
		row.refresh_from_db()
		return row, stats, calls

	def step(self, row):
		(step,) = [s for s in row.validation_steps if s['kind'] == 'script_read']
		return step

	def test_an_affected_version_read_from_the_file_is_reaffirmed_with_fresh_evidence_never_a_hit(self):
		m = self.match()
		row, stats, calls = self.validate(jquery_site('1.12.4'))
		self.assertEqual(calls, [])  # no nmap, no HEAD, no other probe for a library match
		step = self.step(row)
		self.assertEqual(step['result'], 'reaffirmed')
		library = step['library']
		self.assertEqual((library['version'], library['version_source'], library['version_confidence']), ('1.12.4', 'body', 0.9))
		self.assertEqual(library['copies'][0]['state'], 'effective')
		self.assertNotEqual(row.validation_status, 'hit')
		self.assertNotEqual(row.classification, 'confirmed')
		self.assertEqual(row.validation_evidence, {})
		m.refresh_from_db()
		self.assertFalse(match_policy.has_hard_evidence(m.source, m.evidence, m.template_result, m.distro_status, row.validation_status))
		self.assertNotEqual(m.ai_verdict, 'not_affected')
		from cveFeed.models import ProbeObservation
		self.assertEqual(ProbeObservation.objects.get(probe='html-libraries').version, '1.12.4')  # the fresh reading is the host's too

	def assert_closed(self, m, row, words):
		m.refresh_from_db()
		self.assertEqual(m.ai_verdict, 'not_affected')
		self.assertTrue(m.ai_reason.startswith(correlation.SCRIPT_READ))
		self.assertIn(words, m.ai_reason)
		self.assertEqual(row.classification, 'not_applicable')
		self.assertNotEqual(row.validation_status, 'hit')
		self.assertFalse(MatchVerdict.objects.exists())  # what this host showed is never shared with another host
		self.assertFalse(TriageVerdict.objects.filter(classification='not_applicable').exists())
		# the next triage keeps it closed: the closure is the guarded deterministic one
		triage.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=None)
		m.refresh_from_db()
		self.assertEqual(m.ai_verdict, 'not_affected')

	def test_a_fixed_version_closes_the_match(self):
		m = self.match()
		row, _stats, _calls = self.validate(jquery_site('3.6.0'))
		self.assertEqual(self.step(row)['library']['version'], '3.6.0')
		self.assert_closed(m, row, 'at or above the fixed release')

	def test_a_library_the_page_no_longer_loads_closes_the_match(self):
		m = self.match()
		row, _stats, _calls = self.validate(Site({PAGE: page('/js/app.js'), 'https://www.v.test/js/app.js': {'status': 200, 'body': 'var x=1;'}}))
		self.assert_closed(m, row, 'no longer loads jQuery')

	def test_a_redirect_alias_closes_the_match(self):
		m = self.match()
		site = Site({PAGE: {'status': 301, 'location': 'https://www.other.test/', 'body': ''}})
		row, _stats, _calls = self.validate(site)
		self.assertEqual(site.calls, [PAGE])
		self.assertEqual(self.step(row)['library']['alias_of'], 'www.other.test')
		self.assert_closed(m, row, 'redirect alias')

	def test_a_match_a_person_worked_is_never_closed(self):
		m = self.match(remediation_status='in_progress')
		row, _stats, _calls = self.validate(jquery_site('3.6.0'))
		step = self.step(row)
		self.assertEqual(step['result'], 'observed')
		self.assertIn('not closed: a person worked this match', step['summary'])
		m.refresh_from_db()
		self.assertNotEqual(m.ai_verdict, 'not_affected')
		self.assertEqual(m.remediation_status, 'in_progress')

	def test_a_held_back_target_is_not_read_and_says_why(self):
		self.domain.discovery_mode = Domain.DISCOVERY_PASSIVE
		self.domain.save(update_fields=['discovery_mode'])
		m = self.match()
		site = jquery_site('3.6.0')
		row, _stats, _calls = self.validate(site)
		self.assertEqual(site.calls, [])
		step = self.step(row)
		self.assertEqual(step['result'], 'blocked')
		self.assertIn('passive target', step['summary'])
		m.refresh_from_db()
		self.assertNotEqual(m.ai_verdict, 'not_affected')
		self.assertNotEqual(row.classification, 'not_applicable')

	def test_an_internal_host_is_never_fetched_by_the_server(self):
		m = self.match()
		site = jquery_site('3.6.0')
		with mock.patch('targetApp.target_types.sentinel_only_target', return_value=True):
			row, _stats, _calls = self.validate(site)
		self.assertEqual(site.calls, [])
		self.assertIn('only a Sentinel', self.step(row)['summary'])
		m.refresh_from_db()
		self.assertNotEqual(m.ai_verdict, 'not_affected')

	def test_a_failed_read_changes_nothing_and_is_retried(self):
		m = self.match()
		before = self.row()
		row, stats, _calls = self.validate(Site(error=OSError('connection refused')), row=before)
		self.assertEqual(row.validation_status, 'failed')
		self.assertIsNotNone(row.next_attempt_at)
		self.assertEqual(row.classification, before.classification)
		m.refresh_from_db()
		self.assertNotEqual(m.ai_verdict, 'not_affected')

	def test_the_hot_lane_request_runs_the_script_read_and_ends_on_the_closure(self):
		from cveFeed import tasks
		m = self.match()
		self.row()
		job = OnDemandValidation.objects.create(match=m, project=self.project, evidence_signature='x', priority=0)
		ran = []
		site = jquery_site('3.6.0')

		def read(check):
			ran.append(check['kind'])
			return validation.run_script_read(check, get=site)
		with mock.patch('cveFeed.validation_authority.require_authority'), \
				mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None), \
				mock.patch.dict(validation.RUNNERS, {'script_read': read, 'nmap_sv': lambda c: ran.append('nmap_sv'),
													 'http_head': lambda c: ran.append('http_head')}), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')):
			result = tasks.validate_match_on_demand(job.pk)
		self.assertEqual(ran, ['script_read'])
		self.assertEqual((result['assessment_status'], result['ai_state']), ('closed_not_applicable', 'not_needed'))
		job.refresh_from_db()
		self.assertEqual(job.status, 'completed')
		m.refresh_from_db()
		self.assertTrue(m.ai_reason.startswith(correlation.SCRIPT_READ))
