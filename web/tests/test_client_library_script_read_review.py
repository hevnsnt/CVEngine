"""Regression tests from the review of the validation's script read (PR #387): each case below is a genuine affected match the first version
closed. Now an absence never closes (a script that 404s, a library moved deep into a bundle or behind a loader), a fixed version closes only
when the match's own file and every script that could hold the library were read whole in this read and searched end to end, a person's own
Validate now runs in a bug bounty project that has not confirmed automated testing, every redirect hop of the read passes the scope rules,
a port this server held is "held", and a server-side React advisory is not taken for the browser library. Round 2: a module script, a static
import or re-export and a service worker are loaders, a version another tool named never closes, and an affected copy found again anywhere
reopens a closed match."""
import time
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import detection, detection_author, js_libraries, local_egress, probes, triage, validation
from cveFeed.models import CVEDetection, CVEEntry, CVEMatch, ServiceRun, Triage
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
		m = self.match('1.12.4')  # made on jquery.min.js's own body; the host was also seen loading old/jquery.js
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


JQ371 = 'https://www.v.test/js/jquery-3.7.1.min.js'


class ModuleAndOtherSourceTests(Base):
	"""Round-2 review: a static ES-module import is a loader (Vite output), and a version another tool named never closes on a script read."""
	kept = AbsenceAndWholeFileTests.assert_kept

	def body_match(self, url=JQ):
		m = self.match('1.12.4')  # made on the file's own body: the only kind a fixed version may close
		CVEMatch.objects.filter(pk=m.pk).update(evidence={**m.evidence, 'script_url': url})
		return m

	def test_N1_a_module_entry_that_statically_imports_a_vendor_chunk_keeps_the_match(self):
		for source in ('other', 'body'):
			with self.subTest(source):
				cache_clear()
				CVEMatch.objects.all().delete()
				Triage.objects.all().delete()
				m = self.match('1.12.4', version_source='other') if source == 'other' else self.body_match(JQ371)
				entry = 'import{a as $}from"./vendor-abc123.js";$(function(){});'
				site = Site({PAGE: page('/js/jquery-3.7.1.min.js', extra='<script type="module" src="/assets/index-9f8e.js"></script>'),
							 JQ371: {'status': 200, 'body': script('3.7.1')},
							 'https://www.v.test/assets/index-9f8e.js': {'status': 200, 'body': entry},
							 'https://www.v.test/assets/vendor-abc123.js': {'status': 200, 'body': JQ_1124_BODY + 'window.jQuery=window.$=n;export{n as a};'}})
				row, _s, _c = self.validate(site)
				self.assertNotIn('https://www.v.test/assets/vendor-abc123.js', site.calls)
				self.kept(m, row)

	def test_N2_an_inline_module_that_imports_a_file_keeps_the_match(self):
		for source in ('other', 'body'):
			with self.subTest(source):
				cache_clear()
				CVEMatch.objects.all().delete()
				Triage.objects.all().delete()
				m = self.match('1.12.4', version_source='other') if source == 'other' else self.body_match(JQ371)
				site = Site({PAGE: page('/js/jquery-3.7.1.min.js', extra='<script type="module">import "/assets/legacy.js";</script>'),
							 JQ371: {'status': 200, 'body': script('3.7.1')},
							 'https://www.v.test/assets/legacy.js': {'status': 200, 'body': JQ_1124_BODY}})
				row, _s, _c = self.validate(site)
				self.kept(m, row)

	def test_a_static_import_or_re_export_inside_a_classic_script_keeps_the_match(self):
		for code in ('import "./legacy.js";', 'import * as j from "./jq.js";', 'export { default } from "./jq.js";', 'export*from"./jq.js";'):
			with self.subTest(code):
				cache_clear()
				CVEMatch.objects.all().delete()
				Triage.objects.all().delete()
				m = self.body_match()
				row, _s, _c = self.validate(Site({PAGE: page('/js/jquery.min.js', '/js/app.js'), JQ: {'status': 200, 'body': script('3.6.0')},
												  'https://www.v.test/js/app.js': {'status': 200, 'body': code}}))
				self.assertIn('run time', self.kept(m, row)['summary'])

	def test_N3_a_version_another_tool_saw_elsewhere_never_closes(self):
		m = self.match('1.12.4', version_source='other')
		site = Site({PAGE: page('/js/jquery-3.7.1.min.js', extra='<iframe src="/legacy/"></iframe>'), JQ371: {'status': 200, 'body': script('3.7.1')},
					 'https://www.v.test/legacy/': {'status': 200, 'body': '<script src="/legacy/jquery-1.12.4.min.js"></script>'}})
		row, _s, _c = self.validate(site)
		self.assertIn('another tool', self.kept(m, row)['summary'])

	def test_N4_a_third_party_widget_bundle_the_read_never_fetches_never_closes_a_version_another_tool_named(self):
		m = self.match('1.12.4', version_source='other')
		site = Site({PAGE: page('/js/jquery-3.7.1.min.js', 'https://widget.partner.example/embed.js'), JQ371: {'status': 200, 'body': script('3.7.1')},
					 'https://widget.partner.example/embed.js': {'status': 200, 'body': JQ_1124_BODY}})
		row, _s, _c = self.validate(site)
		self.assertNotIn('https://widget.partner.example/embed.js', site.calls)
		self.kept(m, row)

	def test_N5_a_service_worker_keeps_the_match(self):
		for source in ('other', 'body'):
			with self.subTest(source):
				cache_clear()
				CVEMatch.objects.all().delete()
				Triage.objects.all().delete()
				m = self.match('1.12.4', version_source='other') if source == 'other' else self.body_match(JQ371)
				site = Site({PAGE: page('/js/jquery-3.7.1.min.js', extra='<script>navigator.serviceWorker.register("/sw.js")</script>'),
							 JQ371: {'status': 200, 'body': script('3.7.1')}})
				row, _s, _c = self.validate(site)
				self.kept(m, row)

	def test_N6_a_body_match_whose_own_file_is_fixed_still_closes(self):
		m = self.match('1.12.4')
		row, _s, _c = self.validate(jquery_site('3.6.0'))
		self.assert_closed(m, row, 'at or above the fixed release')

	def test_N7_an_unread_third_party_bundle_that_may_run_an_old_copy_keeps_a_body_match(self):
		# the match's own file now states 3.7.1; a widget loaded after it (a third-party host the vetter never reads) may bundle 1.12.4
		m = self.match('1.12.4')
		widget = 'https://widget.partner.example/embed.js'
		site = Site({PAGE: page('/js/jquery.min.js', widget), JQ: {'status': 200, 'body': script('3.7.1')},
					 widget: {'status': 200, 'body': JQ_1124_BODY + 'window.jQuery=window.$=n;'}})
		row, _s, _c = self.validate(site)
		self.assertNotIn(widget, site.calls)
		self.assertIn(widget, self.kept(m, row)['summary'])

	def test_N8_a_cdn_bundle_the_budget_left_unread_keeps_a_body_match(self):
		m = self.match('1.12.4')
		own = ['/js/a.js', '/js/b.js', '/js/c.js', '/js/d.js', '/js/e.js']
		cdn = 'https://cdn.jsdelivr.net/gh/acme/plugin@1/dist/plugin.bundle.js'
		pages = {PAGE: page('/js/jquery.min.js', *own, cdn), JQ: {'status': 200, 'body': script('3.7.1')}, cdn: {'status': 200, 'body': JQ_1124_BODY}}
		pages.update({'https://www.v.test' + n: {'status': 200, 'body': '!function(){}();'} for n in own})
		site = Site(pages)
		row, _s, _c = self.validate(site)
		self.assertNotIn(cdn, site.calls)
		self.kept(m, row)

	def test_N9_a_match_made_on_a_cdn_file_is_weighed_against_that_file(self):
		old, new = 'https://code.jquery.com/jquery-1.12.4.min.js', 'https://code.jquery.com/jquery-3.7.1.min.js'
		m = self.body_match(old)
		site = Site({PAGE: page(new), new: {'status': 200, 'body': script('3.7.1')}, old: {'status': 200, 'body': script('1.12.4')}})
		row, _s, _c = self.validate(site)
		self.assertIn(old, site.calls)  # the match's own file, re-read: it still states 1.12.4
		self.kept(m, row)

	def test_A1_an_alias_never_closes_a_version_another_tool_saw_on_a_deeper_route(self):
		# bbot or httpx saw jQuery 1.12.4 on /legacy/, which the host still serves; only its front page answers 301 to another host
		m = self.match('1.12.4', version_source='other')
		self.sub('www.other.test')
		site = Site({PAGE: {'status': 301, 'location': 'https://www.other.test/', 'body': ''},
					 'https://www.v.test/legacy/': {'status': 200, 'body': '<script src="/legacy/jquery-1.12.4.min.js"></script>'}})
		row, _s, _c = self.validate(site)
		self.assertIn('another tool', self.kept(m, row)['summary'])

	def test_A2_an_svg_script_given_by_href_is_a_script_the_read_never_reads(self):
		for attribute in ('href', 'xlink:href'):
			with self.subTest(attribute):
				cache_clear()
				CVEMatch.objects.all().delete()
				Triage.objects.all().delete()
				m = self.match('1.12.4')
				site = Site({PAGE: page('/js/jquery.min.js', extra=f'<svg><script {attribute}="/js/old-bundle.js"></script></svg>'),
							 JQ: {'status': 200, 'body': script('3.7.1')}, 'https://www.v.test/js/old-bundle.js': {'status': 200, 'body': JQ_1124_BODY}})
				row, _s, _c = self.validate(site)
				self.assertIn('SVG', self.kept(m, row)['summary'])

	def test_a_later_read_finding_an_affected_copy_deep_in_a_file_reopens_a_closed_match(self):
		m = self.match('1.12.4')
		self.validate(jquery_site('3.6.0'))
		m.refresh_from_db()
		self.assertTrue(validation.closed_by_script_read(m))
		cache_clear()
		ServiceRun.objects.all().delete()
		app = FILLER + '\n' + JQ_1124_BODY  # past both read_body windows: only the whole-file search sees it
		site = Site({PAGE: page('/js/jquery.min.js', '/js/app.js'), JQ: {'status': 200, 'body': script('3.6.0')},
					 'https://www.v.test/js/app.js': {'status': 200, 'body': app}})
		row, _s, _c = self.validate(site, rows=[Triage.objects.get(match=m)])
		self.assertIn('found by searching the whole file', self.step(row)['summary'])
		m.refresh_from_db()
		self.assertFalse(validation.closed_by_script_read(m))
		self.assertLessEqual(m.confidence, js_libraries.SHADOWED_CAP)

	def test_a_later_read_finding_an_affected_copy_anywhere_reopens_a_closed_match(self):
		# F3: closed on a fixed read; the next read finds 1.12.4 again, only as a shadowed copy (observed, not reaffirmed): it reopens
		m = self.match('1.12.4')
		row, _s, _c = self.validate(jquery_site('3.6.0'))
		m.refresh_from_db()
		self.assertTrue(validation.closed_by_script_read(m))
		cache_clear()
		ServiceRun.objects.all().delete()  # as Validate now does: the check is not served from the ledger
		site = Site({PAGE: page('/js/old/jquery.js', '/js/jquery.min.js'), JQ: {'status': 200, 'body': script('3.6.0')},
					 'https://www.v.test/js/old/jquery.js': {'status': 200, 'body': script('1.12.4')}})
		row, _s, _c = self.validate(site, rows=[Triage.objects.get(match=m)])
		self.assertEqual(self.step(row)['result'], 'observed')
		self.assertIn('1.12.4 inside the affected range', self.step(row)['summary'])
		m.refresh_from_db()
		self.assertFalse(validation.closed_by_script_read(m))
		self.assertLessEqual(m.confidence, js_libraries.SHADOWED_CAP)  # an affected copy that may not run: kept as a capped candidate

	def test_every_script_is_asked_for_in_full_never_revalidated_with_an_etag(self):
		m = self.match()
		js_libraries._remember(JQ, {'found': [['jquery', '3.6.0', 'banner']], 'truncated': False, 'sha256': 'x', 'etag': '"v1"', 'length': ''},
							   self.project.id)
		site, sent = jquery_site('3.6.0'), []

		def get(url, headers=None):
			sent.append(headers)
			return site(url)
		result = validation.run_script_read(RedirectScopeTests.check_for(self, m), get=get)
		self.assertIn(JQ, site.calls)
		self.assertEqual(sent, [None, None])  # the page and the script, neither with If-None-Match: a 304 leaves nothing to search
		self.assertEqual(result['status'], 'version_changed')


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
		# the word in a string is not an import: e==="import" (a token name), {type:"export"}
		self.assertEqual(js_libraries.whole_body('if(e==="import"||t===\'export\')return;var k={kind:"import"};')['loaders'], [])
		self.assertIn('static import', js_libraries.whole_body('}import"./x.js";')['loaders'])  # (and the script file name it imports)

	def test_a_hostile_file_costs_linear_time(self):
		for hostile in (' ' * js_libraries.MAX_SCRIPT_BYTES, ('a' * 31 + '.fn = ') * 8000, '/*!' * 100000,
						'\n * jQuery v' * 25000, 'createElement(x)' * 18000, 'x.fn=x.prototype={' * 16000, 'import ' * 45000,
						'export {a,b} ' * 25000, 'import{' + 'a,' * 150000,
						'<script ' * 40000, '<script ' + 'a' * 300000):
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
