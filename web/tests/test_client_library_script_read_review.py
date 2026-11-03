"""Regression tests from the review of the validation's script read (PR #387): each case below is a genuine affected match the first version
closed. Now an absence never closes (a script that 404s, a library moved deep into a bundle or behind a loader), a fixed version closes only
when the match's own file and every script that could hold the library were read whole in this read and searched end to end, a person's own
Validate now runs in a bug bounty project that has not confirmed automated testing, every redirect hop of the read passes the scope rules,
a port this server held is "held", and a server-side React advisory is not taken for the browser library."""
import time
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import detection, detection_author, js_libraries, local_egress, probes, triage, validation
from cveFeed.models import CVEDetection, CVEEntry, CVEMatch, Triage
from targetApp.models import Domain
from tests.test_client_library_validation import JQ, PAGE, Base, HotLaneTests, Site, jquery_site, page, script

VENDOR = 'https://www.v.test/assets/vendor.js'
FILLER = '/* app code */\n' + ('var a' + 'x' * 60 + '=1;\n') * 2200  # ~140 KB of ordinary code, under MAX_SCRIPT_BYTES
JQ_1124_BODY = ('/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n'
				'!function(a,b){var c="1.12.4",n=function(a,b){};n.fn=n.prototype={jquery:c,constructor:n};}(window);\n')


class AbsenceAndWholeFileTests(Base):
	def assert_kept(self, m, row):
		step = self.step(row)
		self.assertIn(step['result'], ('observed', 'reaffirmed'))
		self.assertNotIn('Closed automatically', step.get('summary', ''))
		self.assert_open(m)
		return step

	def test_an_older_copy_deeper_in_the_running_bundle_keeps_the_match(self):
		# A: a technology scan's 1.12.4; the page's one bundle opens with jQuery 3.7.1 and carries 1.12.4 further in (that later copy runs)
		m = self.match('1.12.4', version_source='other')
		bundle = script('3.7.1') + FILLER[:8000] + '\n' + JQ_1124_BODY
		row, _s, _c = self.validate(Site({PAGE: page('/assets/vendor.js'), VENDOR: {'status': 200, 'body': bundle}}))
		self.assertIn('1.12.4 inside the affected range', self.assert_kept(m, row)['summary'])

	def test_the_matchs_own_file_left_unread_by_the_budget_keeps_the_match(self):
		# B: the match was made on vendor.js's body; the six-script budget goes to library-named files first and vendor.js is never read
		m = self.match('1.12.4')
		CVEMatch.objects.filter(pk=m.pk).update(evidence={**m.evidence, 'script_url': VENDOR})
		named = ['/js/jquery-3.7.1.min.js', '/js/bootstrap.min.js', '/js/lodash.min.js', '/js/moment.min.js', '/js/underscore.min.js',
				 '/js/swiper.min.js']
		pages = {PAGE: page(*named, '/assets/vendor.js'), VENDOR: {'status': 200, 'body': JQ_1124_BODY},
				 'https://www.v.test/js/jquery-3.7.1.min.js': {'status': 200, 'body': script('3.7.1')}}
		pages.update({'https://www.v.test' + n: {'status': 200, 'body': '!function(){}();'} for n in named[1:]})
		site = Site(pages)
		row, _s, _c = self.validate(site)
		self.assertNotIn(VENDOR, site.calls)
		self.assertIn('was not read whole', self.assert_kept(m, row)['summary'])

	def test_the_matchs_own_file_answering_503_keeps_the_match(self):
		# B2: the match's own file is a server error now; a fixed copy elsewhere on the page proves nothing about it
		m = self.match('1.12.4')
		CVEMatch.objects.filter(pk=m.pk).update(evidence={**m.evidence, 'script_url': VENDOR})
		row, _s, _c = self.validate(Site({PAGE: page('/js/jquery-3.7.1.min.js', '/assets/vendor.js'),
										  'https://www.v.test/js/jquery-3.7.1.min.js': {'status': 200, 'body': script('3.7.1')},
										  VENDOR: {'status': 503, 'body': ''}}))
		self.assertIn('503', self.assert_kept(m, row)['summary'])

	def test_a_library_moved_deep_into_a_bundle_keeps_the_match(self):
		# C: the match's own file now 404s; the page's app.js, read whole, carries jQuery 1.12.4 beyond the 4 KB banner and 128 KB code windows
		m = self.match('1.12.4')
		app = FILLER + '\n' + JQ_1124_BODY
		self.assertLess(len(app), js_libraries.MAX_SCRIPT_BYTES)
		self.assertGreater(app.index('jQuery v1.12.4'), js_libraries.SCAN)
		row, _s, _c = self.validate(Site({PAGE: page('/js/app.js'), 'https://www.v.test/js/app.js': {'status': 200, 'body': app}}))
		self.assert_kept(m, row)

	def test_a_library_loaded_by_requirejs_keeps_the_match(self):
		# D: the match's own file 404s and the page loads jQuery through RequireJS paths (no .js in the name, inside an external script)
		m = self.match('1.12.4')
		main = 'requirejs.config({paths:{jquery:"lib/jquery-1.12.4.min"}});require(["jquery"],function($){});'
		row, _s, _c = self.validate(Site({PAGE: page('/js/require.js', extra='<script>var require={baseUrl:"/js"};</script>'),
										  'https://www.v.test/js/require.js': {'status': 200, 'body': '/** vim: et:ts=4 RequireJS 2.3.6 */ var requirejs,require,define;' + main}}))
		self.assert_kept(m, row)

	def test_a_fixed_running_copy_with_a_loader_in_a_read_script_keeps_the_match(self):
		m = self.match('1.12.4')
		loader = 'var s=document.createElement("script");s.src=window.cdn+"/legacy.js";document.head.appendChild(s);'
		row, _s, _c = self.validate(Site({PAGE: page('/js/jquery.min.js', '/js/app.js'), JQ: {'status': 200, 'body': script('3.6.0')},
										  'https://www.v.test/js/app.js': {'status': 200, 'body': loader}}))
		self.assertIn('run time', self.assert_kept(m, row)['summary'])

	def test_a_file_previously_seen_holding_the_library_is_read_again_and_must_be_fixed(self):
		old = 'https://www.v.test/old/jquery.js'
		m = self.match('1.12.4', version_source='other')
		CVEMatch.objects.filter(pk=m.pk).update(evidence={**m.evidence, 'copies': [{'url': old, 'version': '1.12.4', 'source': 'body'}]})
		site = jquery_site('3.6.0', **{old: {'status': 200, 'body': script('1.12.4')}})
		row, _s, _c = self.validate(site)
		self.assertIn(old, site.calls)  # not on the page any more, so fetched on its own, within the budget
		self.assertIn('1.12.4 inside the affected range', self.assert_kept(m, row)['summary'])
		# once that file is fixed (or gone and replaced by the fixed copy, with the old one answering a fixed version), it closes
		cache_clear()
		Triage.objects.all().delete()
		row, _s, _c = self.validate(jquery_site('3.6.0', **{old: {'status': 200, 'body': script('3.6.0')}}))
		self.assert_closed(m, row, 'at or above the fixed release')


def cache_clear():
	from django.core.cache import cache
	cache.clear()


class ManualValidateNowTests(Base):
	job, run_job = HotLaneTests.job, HotLaneTests.run_job
	def test_a_persons_validate_now_runs_in_an_unconfirmed_bug_bounty_project(self):
		# E: a manual request is not an automatic one; only a run the system started waits for the project's confirmation
		m = self.match()
		site = jquery_site('3.6.0')
		result, ran = self.run_job(self.job(m, source='manual'), site, blocked=[self.project.pk])
		self.assertEqual(ran, ['script_read'])
		self.assertIn(JQ, site.calls)
		(step,) = [s for r in Triage.objects.all() for s in (r.validation_steps or []) if s['kind'] == 'script_read']
		self.assertNotEqual(step['result'], 'blocked')
		self.assertNotEqual(result.get('reason'), 'bounty_not_confirmed')

	def test_an_automatic_request_there_still_reads_nothing(self):
		m = self.match()
		site = jquery_site('3.6.0')
		result, ran = self.run_job(self.job(m), site, blocked=[self.project.pk])
		self.assertEqual((ran, site.calls, result['reason']), ([], [], 'bounty_not_confirmed'))


class Network:
	"""``route_auth.probe_url`` for the real ``probes.fetch``: ``answers`` maps a URL to its answer, everything else is a 404."""
	def __init__(self, answers):
		self.answers, self.calls = answers, []

	def __call__(self, url, max_bytes=None, browser=False, project=None, headers=None, **_kw):
		self.calls.append(url)
		answer = self.answers.get(url, {'status': 404, 'body': ''})
		if isinstance(answer, Exception):
			raise answer
		return {'url': url, 'location': '', 'headers': {}, 'raw_headers': {}, 'title': '', **answer}


class RedirectScopeTests(Base):
	"""Every hop of the script read's own GETs, redirects included, passes the scope rules (F2), and a port this server holds is ``held`` (F4)."""

	def check_for(self, m):
		(row, _d), = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
		return validation._script_read_check({**validation.subject_for(row, triage.load_findings([row])[0]), 'project_id': self.project.id},
											 row.signature)

	def read(self, net, check):
		with mock.patch('cveFeed.route_auth.probe_url', net), mock.patch('cveFeed.route_auth.host_allowed', return_value=True), \
				mock.patch('cveFeed.probes.time.sleep'):
			return validation.run_script_read(check)

	def test_a_script_redirect_to_a_host_outside_the_bug_bounty_scope_is_not_followed(self):
		m = self.match()
		apex = 'https://v.test/js/jquery.min.js'
		net = Network({PAGE: {'status': 200, 'body': page('/js/jquery.min.js')['body']},
					   JQ: {'status': 301, 'location': apex, 'body': ''}, apex: {'status': 200, 'body': script('3.6.0')}})
		real = probes.scope_hop

		def refusing(project_id, sub, unattended=True):
			hop = real(project_id, sub, unattended=unattended)
			return lambda host: 'outside the bug bounty scope' if host == 'v.test' else hop(host)
		with mock.patch('cveFeed.probes.scope_hop', side_effect=refusing):
			result = self.read(net, self.check_for(m))
		self.assertIn(JQ, net.calls)
		self.assertNotIn(apex, net.calls)  # v.test is in the host's name group, but the program's scope refuses it at the hop
		self.assertNotIn('close_reason', result)

	def test_the_bounty_gate_is_asked_at_every_hop(self):
		m = self.match()
		apex = 'https://v.test/js/jquery.min.js'
		net = Network({PAGE: {'status': 200, 'body': page('/js/jquery.min.js')['body']},
					   JQ: {'status': 301, 'location': apex, 'body': ''}, apex: {'status': 200, 'body': script('3.6.0')}})
		asked = []

		def refusal(_self, project_id, host=None, unattended=True, derived=False):
			asked.append((host, unattended))
			return 'not in the program scope' if host == 'v.test' else ''
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
			result = self.read(net, self.check_for(m))
		self.assertIn(('v.test', True), asked)
		self.assertNotIn(apex, net.calls)
		self.assertNotIn('close_reason', result)

	def test_a_host_scoped_target_reads_its_own_host_only_at_every_hop(self):
		Domain.objects.filter(pk=self.domain.pk).update(name='www.v.test', scope_mode=Domain.SCOPE_HOST)
		m = self.match()
		apex = 'https://v.test/js/jquery.min.js'
		net = Network({PAGE: {'status': 200, 'body': page('/js/jquery.min.js')['body']},
					   JQ: {'status': 302, 'location': apex, 'body': ''}, apex: {'status': 200, 'body': script('3.6.0')}})
		result = self.read(net, self.check_for(m))
		self.assertIn(JQ, net.calls)
		self.assertNotIn(apex, net.calls)
		self.assertNotIn('close_reason', result)

	def test_a_redirect_inside_the_scope_is_followed(self):
		m = self.match()
		moved = 'https://www.v.test/static/jquery.min.js'
		net = Network({PAGE: {'status': 200, 'body': page('/js/jquery.min.js')['body']},
					   JQ: {'status': 301, 'location': moved, 'body': ''}, moved: {'status': 200, 'body': script('3.6.0')}})
		result = self.read(net, self.check_for(m))
		self.assertIn(moved, net.calls)
		self.assertEqual(result['status'], 'version_changed')

	def test_a_script_on_a_held_port_is_held_not_unreachable(self):
		reader = js_libraries.Reader(1, fresh=True)
		entries = js_libraries.parse_page(page('/js/jquery.min.js')['body'], PAGE)

		def held(url, headers=None):
			raise local_egress.PortHeld(443, 'paced')
		report = {}
		js_libraries.read_page(entries, PAGE, held, lambda url: '', {'left': 6}, reader=reader, report=report)
		self.assertEqual(report['skipped'], [(JQ, 'held')])

	def test_refetch_goes_through_the_vetters_port_rule_and_holds(self):
		m = self.match()
		calls = []

		def get(url):
			calls.append(url)
			raise local_egress.PortHeld(443, 'skipped')
		other_port = probes.refetch_script(self.project.id, m.subdomain, 'https://www.v.test:9443/js/jquery.min.js', get=get, page_url=PAGE)
		self.assertEqual((other_port['whole'], calls), (False, []))
		self.assertIn('port', other_port['error'])
		held = probes.refetch_script(self.project.id, m.subdomain, JQ, get=get, page_url=PAGE)
		self.assertTrue(held['held'])
		self.assertEqual(calls, [JQ])


class WholeBodyTests(TestCase):
	def test_a_banner_and_a_signature_anywhere_in_the_file_are_found(self):
		deep = FILLER + FILLER + '\n' + JQ_1124_BODY  # past both read_body windows
		self.assertEqual(js_libraries.read_body(deep), [])
		found = js_libraries.whole_body(script('3.7.1') + deep)
		self.assertEqual({tuple(v[:2]) for v in found['versions']}, {('jquery', '3.7.1'), ('jquery', '1.12.4')})
		stripped = FILLER + FILLER + '!function(){var f="3.4.1",k=function(){};k.fn=k.prototype={jquery:f,constructor:k}}();'
		self.assertEqual(js_libraries.whole_body(stripped)['versions'], [['jquery', '3.4.1', 'signature']])

	def test_licence_blocks_and_loaders(self):
		text = '/*! Sizzle v2.3.6 */\n' + script('3.6.0') + '/*! For license information please see app.js.LICENSE.txt */'
		found = js_libraries.whole_body(text)
		self.assertEqual(len(found['blocks']), 2)  # jQuery's own banner is identified; the other two are not
		self.assertTrue(js_libraries.rules_out('jquery', found['blocks'][0]))
		self.assertFalse(js_libraries.rules_out('bootstrap', found['blocks'][0]))
		self.assertFalse(js_libraries.rules_out('jquery', '/*! jquery.custom build'))
		dom_eval = 'function DOMEval(e,t,n){var r,i,o=(n=n||document).createElement("script");o.text=e;n.head.appendChild(o)}'
		self.assertEqual(js_libraries.whole_body(dom_eval)['loaders'], [])  # code given to a script element loads no file
		self.assertEqual(js_libraries.whole_body('var s=document.createElement("script");s.src=u;')['loaders'], ['createElement(script)'])
		self.assertIn('requirejs', js_libraries.whole_body('require.config({baseUrl:"/js"})')['loaders'])
		self.assertIn('import()', js_libraries.whole_body('import("./chunk-"+n+".js")')['loaders'])
		self.assertEqual(js_libraries.whole_body('"function"==typeof define&&define.amd&&define("jquery",[],f)')['loaders'], [])

	def test_a_hostile_file_costs_linear_time(self):
		for hostile in (' ' * js_libraries.MAX_SCRIPT_BYTES, ('a' * 31 + '.fn = ') * 8000, '/*!' * 100000,
						'\n * jQuery v' * 25000, 'createElement(x)' * 18000, 'x.fn=x.prototype={' * 16000):
			started = time.monotonic()
			js_libraries.whole_body(hostile[:js_libraries.MAX_SCRIPT_BYTES])
			self.assertLess(time.monotonic() - started, 2.0, hostile[:20])


# CVE-2025-55182 (React Server Components) as the feed gives it: the CPE names facebook react, the packages are the server ones
REACT_RSC = [
	{'vendor': 'facebook', 'product': 'react', 'ranges': [{'introduced': '19.0.0', 'fixed': '19.0.1'}, {'introduced': '19.1.0', 'fixed': '19.1.2'}]},
	{'package': 'react-server-dom-webpack', 'ranges': [{'introduced': '19.0.0', 'fixed': '19.0.1'}]},
	{'package': 'react-server-dom-parcel', 'ranges': [{'introduced': '19.0.0', 'fixed': '19.0.1'}]},
]


class ServerSideReactTests(TestCase):
	def rsc(self, affected=REACT_RSC, title='Remote code execution in React Server Components'):
		return CVEEntry.objects.create(cve_id='CVE-2025-55182', title=title, affected=affected, published_at=timezone.now(),
									   cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')

	def test_a_server_components_advisory_is_not_the_browser_library(self):
		self.assertEqual(detection.library_key('react'), 'react')  # the name alone is the library ...
		self.assertEqual(detection.cve_libraries(self.rsc()), {})  # ... but the advisory is about server code
		self.assertEqual(detection.client_libraries(REACT_RSC), {})  # the server packages alone say so
		# the words alone say so too, when the feed lists only the CPE
		words = CVEEntry(cve_id='CVE-2099-7', title='React Server Components deserialization', affected=REACT_RSC[:1])
		self.assertEqual(detection.cve_libraries(words), {})
		ssr = CVEEntry(cve_id='CVE-2099-8', title='XSS when using server-side rendering with react-dom', affected=REACT_RSC[:1])
		self.assertEqual(detection.cve_libraries(ssr), {})
		browser = CVEEntry(cve_id='CVE-2099-9', title='React XSS in a DOM attribute', affected=REACT_RSC[:1])
		self.assertEqual(list(detection.cve_libraries(browser)), ['react'])

	def test_its_record_keeps_the_ordinary_checks_and_the_backfill_leaves_it(self):
		cve = self.rsc()
		strategy = detection.finalize(detection.rules_strategy(cve, []), cve.cvss_vector)
		self.assertNotIn('script_version', [c['kind'] for c in strategy['remote_checks']])
		self.assertTrue(all(c['how']['tool'] != detection.LIBRARY_TOOL for c in strategy['remote_checks']))
		self.assertNotIn(detection.LIBRARY_TOOL, strategy['validation']['recommended_tools'])
		row = CVEDetection.objects.create(cve_entry=cve, source='rules', strategy=strategy, rules_at=timezone.now())
		before = CVEDetection.objects.get(pk=row.pk)
		self.assertEqual(detection_author.refresh_client_library_records(), 0)
		after = CVEDetection.objects.get(pk=row.pk)
		self.assertEqual((after.strategy, after.updated_at, after.schema_version), (before.strategy, before.updated_at, before.schema_version))

	def test_a_banner_check_on_react_is_not_reinterpreted_as_the_script_read(self):
		check = {'kind': 'version_banner', 'params': {'product': 'react', 'ranges': [{'fixed': '19.0.1'}]}}
		self.assertFalse(detection.is_script_read(check))
		self.assertTrue(detection.is_script_read({'kind': 'version_banner', 'params': {'product': 'jQuery', 'ranges': []}}))

	def test_a_react_match_on_it_is_not_validated_by_the_script_read(self):
		cve = self.rsc()
		match = mock.Mock(source='tech', matched_product='React', cve_entry=cve)
		self.assertEqual(validation.library_of(match), '')
