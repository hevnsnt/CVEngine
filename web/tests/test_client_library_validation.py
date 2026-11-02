"""Validating a CVE match on a client-side JavaScript library (jQuery, CVE-2020-11023): the validation reads the pages' scripts again
(the html-libraries read of every web base), never runs nmap or a HEAD for it, records the fresh version evidence, reaffirms an affected
version without calling it a hit, and closes only what is truly false: a host every root of which permanently redirects elsewhere, or one
whose running copy was read in full and is fixed with every copy of the library read. A library a page no longer shows, a temporary redirect,
a cut-short or unread copy, a run-time loader, a held-back host and a failed read all leave the match as it was."""
import gzip
import os
import re
import unittest
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, match_policy, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, MatchVerdict, OnDemandValidation, RouteAuth, Triage, TriageVerdict
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain, Technology
from targetApp.models import Domain
from tests.test_client_library_detection import JQUERY_11023

RANGES = [e['ranges'] for e in JQUERY_11023 if e.get('product') == 'jQuery' or e.get('package') in ('jquery', 'jQuery', 'components/jquery',
																									'org.webjars.npm:jquery')]
PAGE = 'https://www.v.test/'
JQ = 'https://www.v.test/js/jquery.min.js'
FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'bluegrace')


def script(version, pad=0):
	return f'/*! jQuery v{version} | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){{}}' + ' ' * pad


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


def page(*sources, status=200, extra=''):
	return {'status': status, 'body': ''.join(f'<script src="{s}"></script>' for s in sources) + extra}


def jquery_site(version='1.12.4', **more):
	return Site({PAGE: page('/js/jquery.min.js'), JQ: {'status': 200, 'body': script(version)}, **more})


class LibraryPlanTests(unittest.TestCase):
	SIG = 'a' * 40

	def subject(self, **kw):
		return {'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-2020-11023', 'source': 'tech', 'url': PAGE, 'library': 'jquery',
				'library_product': 'jQuery', 'library_ranges': RANGES, 'candidate_services': [{'ip': '203.0.113.7', 'port': 443}],
				'bases': ['https://www.v.test', 'https://www.v.test:8443'], 'project_id': 1, 'domain_id': 1, 'matched_version': '1.12.4', **kw}

	def test_a_library_match_is_validated_by_the_script_read_of_every_base_and_never_by_nmap_or_a_head(self):
		checks, notes = validation.plan_checks(self.subject(), self.SIG)
		self.assertEqual([c['kind'] for c in checks], ['script_read'])
		self.assertEqual(notes, [])
		check = checks[0]
		self.assertEqual(check['argv'], ['probe', 'html-libraries', 'https://www.v.test', 'https://www.v.test:8443'])
		self.assertEqual(check['params']['bases'], ['https://www.v.test', 'https://www.v.test:8443'])
		self.assertNotIn('nmap', check['display'])
		self.assertTrue(check['params']['unattended'])  # a run the system starts unless the job says a person asked
		with_template, _ = validation.plan_checks(self.subject(), self.SIG, ('/t/CVE-2020-11023.yaml', ''))
		self.assertEqual([c['kind'] for c in with_template], ['nuclei_template', 'script_read'])
		none, notes = validation.plan_checks(self.subject(url=None, bases=[]), self.SIG)
		self.assertEqual(none, [])
		self.assertIn('no web page', notes[0])

	def test_the_plan_always_keeps_the_script_read(self):
		from cveFeed import validation_plan
		checks, _ = validation.plan_checks(self.subject(), self.SIG)
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
			decision, _provider = validation_plan.plan(1, mock.Mock(signature='s'), mock.Mock(), self.subject(), checks, ('', 'none'))
		self.assertEqual(decision['check_kinds'], ['script_read'])


def copy(version, state='effective', source='body', url=JQ, **kw):
	return {'url': url, 'version': version, 'source': source, 'state': state, 'file_read': source == 'body', **kw}


def record(*copies, unresolved=False):
	last = next((c for c in copies if c['state'] == 'effective'), copies[-1])
	return {'jquery': {'product': 'jQuery', 'version': last['version'], 'version_source': last['source'], 'version_confidence': 0.9,
					   'script_url': last['url'], 'copies_unresolved': unresolved, 'copies': list(copies),
					   **({'unresolved_reason': 'a copy is loaded with async'} if unresolved else {})}}


def read_page(records=None, base='https://www.v.test', **kw):
	return {'base': base, 'outcome': 'read', 'status': 200, 'records': records or {}, 'skipped': [], 'scripts': 3, 'lazy': [], **kw}


class LibraryOutcomeTests(unittest.TestCase):
	"""``library_outcome`` is pure: what a fresh read means for the match."""
	PARAMS = {'library': 'jquery', 'product': 'jQuery', 'ranges': RANGES, 'version_source': 'body', 'host': 'www.v.test',
			  'matched_version': '1.12.4', 'script_url': JQ}

	def outcome(self, *pages, params=None, **reading):
		return validation.library_outcome({**self.PARAMS, **(params or {})}, {'pages': list(pages), 'roots': [], **reading})

	def test_what_closes(self):
		reaffirmed = self.outcome(read_page(record(copy('1.12.4'))))
		self.assertEqual(reaffirmed['status'], 'reaffirmed')
		self.assertNotIn('close_reason', reaffirmed)
		self.assertEqual((reaffirmed['library']['version'], reaffirmed['library']['version_source']), ('1.12.4', 'body'))
		fixed = self.outcome(read_page(record(copy('3.6.0'))))
		self.assertEqual(fixed['status'], 'version_changed')
		self.assertTrue(fixed['close_reason'].startswith(correlation.SCRIPT_READ))
		# unrelated scripts the six-script budget left unread never stand in the way of a fixed copy that runs
		budget = self.outcome(read_page(record(copy('3.6.0')), skipped=[('https://www.v.test/theme/a.js', 'page host limit')] * 30))
		self.assertEqual(budget['status'], 'version_changed')
		# a version another tool named closes on the running copy read in full too (BlueGrace's Wappalyzer "jQuery 1.0.4")
		other = self.outcome(read_page(record(copy('3.7.1'))), params={'version_source': 'other', 'script_url': ''})
		self.assertEqual(other['status'], 'version_changed')
		permanent = {'base': 'https://www.v.test', 'outcome': 'redirect', 'status': 301, 'location': 'https://www.other.test/'}
		alias = self.outcome(permanent, {**permanent, 'base': 'http://www.v.test', 'status': 308})
		self.assertEqual(alias['status'], 'version_changed')
		self.assertIn('redirect alias', alias['close_reason'])
		self.assertEqual(self.outcome(read_page({}), script={'status': 404, 'found': [], 'truncated': False})['status'], 'version_changed')
		gone_fixed = self.outcome(read_page({}), script={'status': 200, 'found': [['jquery', '3.6.0', 'banner']], 'truncated': False})
		self.assertEqual(gone_fixed['status'], 'version_changed')

	def test_anything_that_leaves_doubt_is_observed_and_never_closes(self):
		permanent = {'base': 'https://www.v.test', 'outcome': 'redirect', 'status': 301, 'location': 'https://www.other.test/'}
		cases = {
			'a page with no scripts (maintenance, access denied)': self.outcome(read_page({}, scripts=0)),
			'the library gone from a page that loads scripts': self.outcome(read_page({})),
			'the library gone, a version another tool named': self.outcome(read_page({}), params={'version_source': 'other'}),
			'a temporary redirect (302 to a login page)': self.outcome({**permanent, 'status': 302, 'location': 'https://login.microsoftonline.com/'}),
			'one root still answers a page': self.outcome(permanent, read_page({})),
			'a current root route answers 200': self.outcome(permanent, roots=[('http://www.v.test/', 200, '')]),
			'a root redirects to the host itself': self.outcome({**permanent, 'location': 'https://www.v.test/en/'}),
			'shadowed old copy': self.outcome(read_page(record(copy('1.12.4', state='shadowed'), copy('3.6.0', url='https://cdn/x.js')))),
			'file name only': self.outcome(read_page(record(copy('1.12.4', source='filename')))),
			'unresolved copies': self.outcome(read_page(record(copy('1.12.4', state='unresolved'), copy('3.6.0', state='unresolved'),
															   unresolved=True))),
			'the running copy was cut short': self.outcome(read_page(record(copy('3.6.0', truncated=True)))),
			'another copy of the library unread': self.outcome(read_page(record(
				copy('3.6.0'), copy('', state='shadowed', source='', url='https://www.v.test/old/jquery.js', not_read='page host limit')))),
			'another web base not read': self.outcome(read_page(record(copy('3.6.0'))),
													  {'base': 'https://www.v.test:8443', 'outcome': 'unanswered'}),
			'another web base runs an affected copy': self.outcome(read_page(record(copy('3.6.0'))), read_page(
				record(copy('1.12.4', url='https://www.v.test:8443/jquery.js')), base='https://www.v.test:8443')),
			'a run-time loader of the library': self.outcome(read_page(record(copy('3.6.0')), lazy=['jquery'])),
			'the match\'s script cut short': self.outcome(read_page({}), script={'status': 200, 'found': [['jquery', '3.6.0', 'banner']],
																				   'truncated': True}),
			'error page': self.outcome({'base': 'https://www.v.test', 'outcome': 'error_page', 'status': 403}),
		}
		for name, result in cases.items():
			self.assertNotIn('close_reason', result, name)
			self.assertIn(result['status'], ('observed', 'reaffirmed'), name)
		self.assertEqual(cases['another web base runs an affected copy']['status'], 'reaffirmed')
		self.assertIn('not every web base', cases['another web base not read']['summary'])
		self.assertIn('was not read', cases['another copy of the library unread']['summary'])
		self.assertIn('cut at 300 KB', cases['the running copy was cut short']['summary'])
		self.assertEqual(self.outcome({'base': 'https://www.v.test', 'outcome': 'challenged', 'challenge': 'Cloudflare'})['status'], 'blocked')
		self.assertEqual(self.outcome({'base': 'https://www.v.test', 'outcome': 'error_page', 'status': 503})['status'], 'failed')


class Base(TestCase):
	def setUp(self):
		cache.clear()  # a read is reused for ten minutes: each test starts with none
		org = Org.objects.create(name='V', slug='v')
		self.project = Project.objects.create(name='P', slug='pv', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='v.test', project=self.project, insert_date=timezone.now())
		self.cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', title='Potential XSS vulnerability in jQuery', kev=True, cvss=6.9,
										   published_at=timezone.now(), affected=JQUERY_11023)
		for patched in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
						mock.patch('targetApp.target_types.is_scannable_ip', return_value=True),
						mock.patch('cveFeed.activity.log', return_value=None),
						mock.patch('cveFeed.notify._send', return_value=False),
						mock.patch('cveFeed.probes.REQUEST_GAP', 0),
						mock.patch('cveFeed.js_libraries.SCRIPT_HOST_GAP', 0)):
			patched.start()
			self.addCleanup(patched.stop)

	def sub(self, name='www.v.test', domain=None):
		return Subdomain.objects.filter(name=name).first() or Subdomain.objects.create(
			name=name, target_domain=domain or self.domain, http_url=f'https://{name}')

	def match(self, version='1.12.4', cve=None, name='www.v.test', version_source='body', **kw):
		sub = self.sub(name)
		tech, _ = Technology.objects.get_or_create(name=f'jQuery:{version}')
		sub.technologies.add(tech)
		return CVEMatch.objects.create(
			cve_entry=cve or self.cve, subdomain=sub, matched_product='jQuery', matched_version=version, version_in_range=kw.pop('in_range', True),
			source='tech', confidence=0.9, evidence={'source': 'tech', 'source_id': tech.id, 'version_source': version_source,
													 'script_url': JQ if version_source == 'body' else '', 'range': {'introduced': '1.0.3', 'fixed': '3.5.0'}},
			**kw)

	def rows(self):
		pairs = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
		triage.run_triage(pairs, provider=None)
		return list(Triage.objects.order_by('pk'))

	def validate(self, site, rows=None):
		rows = rows or self.rows()
		calls = []

		def other(kind):
			def run(check):
				calls.append(kind)
				return {'status': 'observed', 'summary': kind}
			return run
		runners = {**{k: other(k) for k in validation.CHECK_KINDS}, 'script_read': lambda check: validation.run_script_read(check, get=site)}
		with mock.patch.dict(os.environ, {'CVENGINE_VALIDATE_MAX_PER_RUN': '500', 'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': '500',
										  'CVENGINE_VALIDATE_MAX_PER_DAY': '500'}):
			stats = validation.run_validation(self.project.id, [r.pk for r in rows], runners=runners,
											  template_for=lambda cve_id: ('', 'no template covers this CVE'))
		for row in rows:
			row.refresh_from_db()
		return rows[0], stats, calls

	@staticmethod
	def step(row):
		(step,) = [s for s in row.validation_steps if s['kind'] == 'script_read']
		return step

	def assert_open(self, m):
		m.refresh_from_db()
		self.assertNotEqual(m.ai_verdict, 'not_affected')

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


class LibraryValidationTests(Base):
	def test_an_affected_version_read_from_the_file_is_reaffirmed_with_fresh_evidence_never_a_hit(self):
		m = self.match()
		row, _stats, calls = self.validate(jquery_site('1.12.4'))
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
		self.assert_open(m)
		from cveFeed.models import ProbeObservation
		self.assertFalse(ProbeObservation.objects.exists())  # nothing stored that would move the host's other matches' signatures

	def test_a_fixed_version_read_in_full_closes_even_when_the_budget_left_unrelated_scripts_unread(self):
		m = self.match()
		theme = [f'/theme/js/vendor-{i}.js' for i in range(12)]
		site = Site({PAGE: page('/js/jquery.min.js', *theme), JQ: {'status': 200, 'body': script('3.6.0')},
					 **{f'https://www.v.test{t}': {'status': 200, 'body': 'var a=1;'} for t in theme}})
		row, _stats, _calls = self.validate(site)
		self.assertTrue(self.step(row)['library']['not_read'])  # the six-script budget was spent
		self.assertEqual(self.step(row)['library']['version'], '3.6.0')
		self.assert_closed(m, row, 'at or above the fixed release')

	def test_a_running_copy_cut_short_does_not_close(self):
		m = self.match()
		from cveFeed import js_libraries
		row, _stats, _calls = self.validate(Site({PAGE: page('/js/jquery.min.js'), JQ: {'status': 200, 'bytes': js_libraries.MAX_SCRIPT_BYTES,
																						  'body': script('3.6.0')}}))
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assertIn('cut at', self.step(row)['summary'])
		self.assert_open(m)

	def test_every_web_base_is_read_and_another_base_keeps_the_match(self):
		m = self.match()
		sub = m.subdomain
		ip = IpAddress.objects.create(address='203.0.113.7')
		ip.ports.add(Port.objects.create(number=8443, service_name='https', state='open'))
		sub.ip_addresses.add(ip)
		site = jquery_site('3.6.0', **{'https://www.v.test:8443/': page('/old/jquery.js'),
									   'https://www.v.test:8443/old/jquery.js': {'status': 200, 'body': script('1.12.4')}})
		row, _stats, _calls = self.validate(site)
		self.assertIn('https://www.v.test:8443/', site.calls)
		self.assertEqual(self.step(row)['result'], 'reaffirmed')
		self.assertIn('1.12.4', self.step(row)['summary'])
		self.assert_open(m)

	def test_a_page_with_no_scripts_does_not_close(self):
		m = self.match()
		row, _stats, _calls = self.validate(Site({PAGE: {'status': 200, 'body': '<h1>Access denied</h1>'}}))
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assertIn('next scan', self.step(row)['summary'])
		self.assert_open(m)

	def test_the_matched_script_gone_closes_only_through_its_own_404(self):
		m = self.match()
		site = Site({PAGE: page('/js/app.js'), 'https://www.v.test/js/app.js': {'status': 200, 'body': 'var x=1;'}})
		row, _stats, _calls = self.validate(site)
		self.assertIn(JQ, site.calls)  # the match's own script was asked for again: 404
		self.assert_closed(m, row, 'answers 404')

	def test_a_cut_short_script_stops_the_404_exception(self):
		m = self.match()
		from cveFeed import js_libraries
		site = Site({PAGE: page('/js/app.bundle.js'), 'https://www.v.test/js/app.bundle.js': {'status': 200, 'body': '/* app */',
																							  'bytes': js_libraries.MAX_SCRIPT_BYTES}})
		row, _stats, _calls = self.validate(site)
		self.assertNotIn(JQ, site.calls)  # a bundle read only in part may hold the library: the match's own script is not even asked for
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assert_open(m)

	def test_a_run_time_loader_does_not_close(self):
		m = self.match()
		loader = '<script>var s=document.createElement("script");s.src="/js/legacy/jquery-1.12.4.min.js";document.head.appendChild(s);</script>'
		site = Site({PAGE: page('/js/jquery.min.js', extra=loader), JQ: {'status': 200, 'body': script('3.6.0')}})
		row, _stats, _calls = self.validate(site)
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assertIn('run time', self.step(row)['summary'])
		self.assert_open(m)

	def test_a_permanent_redirect_on_every_root_closes_and_a_temporary_one_never_does(self):
		m = self.match()
		row, _stats, _calls = self.validate(Site({PAGE: {'status': 301, 'location': 'https://www.other.test/', 'body': ''}}))
		self.assertEqual(self.step(row)['library']['pages'][0]['status'], 301)
		self.assert_closed(m, row, 'redirect alias')

	def test_a_302_to_a_login_page_is_not_an_alias(self):
		m = self.match()
		row, _stats, _calls = self.validate(Site({PAGE: {'status': 302, 'location': 'https://login.microsoftonline.com/x', 'body': ''}}))
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assert_open(m)

	def test_a_current_root_that_answers_a_page_stops_the_alias(self):
		m = self.match()
		RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.v.test', path='/', url='http://www.v.test/', http_status=200,
								 auth_state='open', checked_at=timezone.now())
		row, _stats, _calls = self.validate(Site({PAGE: {'status': 301, 'location': 'https://www.other.test/', 'body': ''}}))
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assert_open(m)

	def test_a_match_a_person_worked_is_never_closed(self):
		m = self.match(remediation_status='in_progress')
		row, _stats, _calls = self.validate(jquery_site('3.6.0'))
		step = self.step(row)
		self.assertEqual(step['result'], 'observed')
		self.assertIn('not closed: a person worked this match', step['summary'])
		m.refresh_from_db()
		self.assertNotEqual(m.ai_verdict, 'not_affected')
		self.assertEqual(m.remediation_status, 'in_progress')

	def test_a_closure_is_never_shared_even_for_a_match_whose_range_was_not_read(self):
		# a match whose version was not placed inside the range is the case close_invalid_correlation
		# would share by default: a closure reached from this host's page must still stay on this host
		m = self.match(in_range=None)
		(row, _d), = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))  # no triage pass: it is still open
		check = validation._script_read_check({**validation.subject_for(row, triage.load_findings([row])[0]), 'project_id': self.project.id},
											  row.signature)
		self.assertNotEqual(CVEMatch.objects.get(pk=m.pk).ai_verdict, 'not_affected')  # still open before the read
		result = validation.run_script_read(check, get=jquery_site('3.6.0'))
		self.assertEqual(result['status'], 'version_changed')
		verdicts = set(MatchVerdict.objects.values_list('pk', 'ai_verdict', 'ai_reason'))
		validation.apply_validation(row, check, result)
		m.refresh_from_db()
		self.assertEqual(m.ai_verdict, 'not_affected')
		# host_only: a verdict reached from this host's page is never stored for another host with the same product and version
		self.assertEqual(set(MatchVerdict.objects.values_list('pk', 'ai_verdict', 'ai_reason')), verdicts)
		self.assertFalse(TriageVerdict.objects.filter(reason__startswith=correlation.SCRIPT_READ).exists())

	def test_held_back_hosts_are_not_read_and_say_why(self):
		import contextlib
		cases = (('passive target', {'discovery_mode': Domain.DISCOVERY_PASSIVE}, None, set()),
				 ('only a Sentinel', {}, 'targetApp.target_types.sentinel_only_target', set()),
				 ('host_only_scope', {'scope_mode': Domain.SCOPE_HOST}, None, set()),
				 ('bug bounty', {}, None, 'project'))
		for words, fields, patched, blocked in cases:
			with self.subTest(words):
				cache.clear()
				CVEMatch.objects.all().delete()
				Triage.objects.all().delete()
				Domain.objects.filter(pk=self.domain.pk).update(**{'discovery_mode': Domain.DISCOVERY_STANDARD, 'scope_mode': Domain.SCOPE_AUTO, **fields})
				m = self.match()
				site = jquery_site('3.6.0')
				with contextlib.ExitStack() as stack:
					if patched:
						stack.enter_context(mock.patch(patched, return_value=True))
					stack.enter_context(mock.patch('cveFeed.conductor.bounty_blocked_projects',
												   return_value={self.project.pk} if blocked else set()))
					row, _stats, _calls = self.validate(site)
					reason = validation.script_read_held_back(self.project.id, Subdomain.objects.select_related('target_domain').get(pk=m.subdomain_id))
				self.assertEqual(site.calls, [])
				self.assertIn(words, reason)  # the runner's own gate, whatever path reaches it
				if words != 'host_only_scope':  # run_validation already leaves a narrowed name out before any check (#383)
					step = self.step(row)
					self.assertEqual(step['result'], 'blocked')
					self.assertIn(words, step['summary'])
				self.assert_open(m)

	def test_a_failed_read_changes_nothing_and_is_retried(self):
		m = self.match()
		(before,) = self.rows()
		row, _stats, _calls = self.validate(Site(error=OSError('connection refused')), rows=[before])
		self.assertEqual(row.validation_status, 'failed')
		self.assertIsNotNone(row.next_attempt_at)
		self.assertEqual(row.classification, before.classification)
		self.assert_open(m)

	def test_one_host_with_three_jquery_cves_is_read_once(self):
		cves = [self.cve] + [CVEEntry.objects.create(cve_id=f'CVE-2020-1102{i}', title='jQuery XSS', kev=True, cvss=6.9, published_at=timezone.now(),
													 affected=JQUERY_11023) for i in (1, 2)]
		for cve in cves:
			self.match(cve=cve)
		site = jquery_site('1.12.4')
		self.validate(site)
		self.assertEqual(site.calls.count(PAGE), 1)
		self.assertEqual(site.calls.count(JQ), 1)
		steps = [self.step(r)['result'] for r in Triage.objects.all()]
		self.assertEqual(steps, ['reaffirmed'] * 3)  # every sibling ran: the first read moved no signature


class HotLaneTests(Base):
	def job(self, m, source='automatic'):
		self.rows()
		return OnDemandValidation.objects.create(match=m, project=self.project, evidence_signature='x', priority=0, source=source)

	def run_job(self, job, site, blocked=()):
		from cveFeed import tasks
		ran = []

		def read(check):
			ran.append(check['kind'])
			return validation.run_script_read(check, get=site)
		with mock.patch('cveFeed.validation_authority.require_authority'), \
				mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None), \
				mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value=set(blocked)), \
				mock.patch.dict(validation.RUNNERS, {'script_read': read, 'nmap_sv': lambda c: ran.append('nmap_sv'),
													 'http_head': lambda c: ran.append('http_head')}), \
				mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')):
			return tasks.validate_match_on_demand(job.pk), ran

	def test_the_hot_lane_request_runs_the_script_read_and_ends_on_the_closure(self):
		m = self.match()
		job = self.job(m)
		result, ran = self.run_job(job, jquery_site('3.6.0'))
		self.assertEqual(ran, ['script_read'])
		self.assertEqual((result['assessment_status'], result['ai_state']), ('closed_not_applicable', 'not_needed'))
		job.refresh_from_db()
		self.assertEqual(job.status, 'completed')
		m.refresh_from_db()
		self.assertTrue(m.ai_reason.startswith(correlation.SCRIPT_READ))
		# Validate now on the closed match says why it was closed, not that the product is another one
		again = OnDemandValidation.objects.create(match=m, project=self.project, evidence_signature='y', priority=3, source='manual')
		result, ran = self.run_job(again, jquery_site('3.6.0'))
		self.assertEqual(ran, [])
		self.assertIn('re-read the page\'s scripts', result['check_notes'][0])
		self.assertNotIn('not the software', result['check_notes'][0])

	def test_an_unconfirmed_bug_bounty_project_gets_no_automatic_script_read(self):
		m = self.match()
		site = jquery_site('3.6.0')
		result, ran = self.run_job(self.job(m), site, blocked=[self.project.pk])
		self.assertEqual((ran, site.calls, result['reason']), ([], [], 'bounty_not_confirmed'))
		self.assert_open(m)


def _fixture(name):
	with gzip.open(os.path.join(FIXTURES, name + '.gz'), 'rt', encoding='utf-8', errors='replace') as handle:
		return handle.read()


class BlueGrace(Site):
	"""The BlueGrace hosts as they answered: five names that answer 301 to mybluegrace.com, mybluegrace.com (WordPress, jQuery 3.7.1 from
	wp-includes, 30 theme and plugin scripts, a ``?ver=1.0.4`` theme and a ``?ver=3.2.1`` Gravity Forms that Wappalyzer read as jQuery), and
	info.mybluegrace.com (HubSpot, jQuery 1.11.2)."""
	ALIASES = ('www', 'blog', 'careers', 'bgu', 'givinggrace')

	def __init__(self):
		super().__init__()
		self.main, self.info, self.infojq = _fixture('mybluegrace.com.html'), _fixture('info.mybluegrace.com.html'), _fixture('info-jq.js')

	def __call__(self, url, headers=None):
		self.calls.append(url)
		host, path = re.match(r'https?://([^/]+)(.*)', url).groups()
		answer = {'status': 200, 'body': '!function(){var x=1}();'}
		if host.split('.')[0] in self.ALIASES and path in ('', '/'):
			answer = {'status': 301, 'location': 'https://mybluegrace.com/', 'body': _fixture('www.mybluegrace.com.html')}
		elif host == 'mybluegrace.com' and path == '/':
			answer = {'status': 200, 'body': self.main}
		elif host == 'info.mybluegrace.com' and path == '/':
			answer = {'status': 200, 'body': self.info}
		elif 'jquery-1.11.2.js' in path:
			answer = {'status': 200, 'body': self.infojq}
		elif path.startswith('/wp-includes/js/jquery/jquery.min.js'):
			answer = {'status': 200, 'body': script('3.7.1')}
		elif path.startswith('/wp-includes/js/jquery/jquery-migrate.min.js'):
			answer = {'status': 200, 'body': '/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e){}'}
		return {'final_url': url, 'raw_headers': {}, 'challenge': '', **answer}


class BlueGraceOracleTests(Base):
	"""The owner's BlueGrace hosts, the review's ground truth: the five redirect aliases close, mybluegrace.com's 3.2.1, 1.0.4 and 3.4.1 jQuery
	matches (other tools' readings of ``?ver=`` strings) close on the running jQuery 3.7.1 read in full, and info.mybluegrace.com stays at
	1.11.2, re-affirmed."""

	def test_bluegrace(self):
		domain = Domain.objects.create(name='mybluegrace.com', project=self.project, insert_date=timezone.now())
		cves = [self.cve] + [CVEEntry.objects.create(cve_id=c, title='jQuery XSS', kev=True, cvss=6.9, published_at=timezone.now(), affected=JQUERY_11023)
							 for c in ('CVE-2020-11022', 'CVE-2019-11358')]
		for alias in BlueGrace.ALIASES:
			self.sub(f'{alias}.mybluegrace.com', domain)
			self.match('3.2.1', name=f'{alias}.mybluegrace.com', version_source='other')
		self.sub('mybluegrace.com', domain)
		for cve, version in zip(cves, ('3.2.1', '1.0.4', '3.4.1')):
			self.match(version, cve=cve, name='mybluegrace.com', version_source='other')
		self.sub('info.mybluegrace.com', domain)
		self.match('1.11.2', name='info.mybluegrace.com')
		site = BlueGrace()
		with mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
			self.validate(site)
		got = {}
		for m in CVEMatch.objects.select_related('subdomain'):
			row = Triage.objects.get(match=m)
			got[(m.subdomain.name, m.matched_version)] = (self.step(row)['result'], m.ai_verdict or '')
		want = {(f'{a}.mybluegrace.com', '3.2.1'): ('version_changed', 'not_affected') for a in BlueGrace.ALIASES}
		want.update({('mybluegrace.com', v): ('version_changed', 'not_affected') for v in ('3.2.1', '1.0.4', '3.4.1')})
		want[('info.mybluegrace.com', '1.11.2')] = ('reaffirmed', '')
		self.assertEqual(got, want)
		self.assertEqual(site.calls.count('https://mybluegrace.com/'), 1)  # three matches, one read
