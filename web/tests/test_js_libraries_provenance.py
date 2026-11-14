"""Where a JavaScript library version came from decides how far a CVE match may trust it (cveFeed.js_libraries, correlation, probes).

Two leaks the client-side design review found after the 1.3.2 re-cut, on live data:

* a version another fingerprinting tool stored (httpx/Wappalyzer, the nuclei tech pass, bbot: technology source ``scan``) bypassed the
  ladder: ``HostLibraries.judge`` returned ``version_source: other`` with no confidence cap, so a theme's ``jquery.x.js?ver=1.0.4`` read by
  Wappalyzer matched CVE-2020-11023 at 0.95 next to the page's real jQuery 3.7.1;
* a host that only redirects (five names of one site answer a 301 to its apex) was given the libraries of the page it
  redirects to: the probes follow the redirect and recorded the target's scripts on the alias, and correlation matched them there.
"""
import os
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, js_libraries, match_policy
from cveFeed.models import ProbeObservation, RouteAuth
from startScan.models import Subdomain, Technology
from tests import probe_scanner
from tests.test_js_library_versions import JQ_371_MIN, PAGE_URL, NoCache, read
from tests.test_probes import answers, page
from tests import route_scanner
from tests.test_route_auth import RouteFixture


class FakeCVE:
    def __init__(self, cid, affected, kev=True):
        self.id, self.cve_id, self.affected, self.kev = cid, f'CVE-2020-{cid}', affected, kev


JQUERY_XSS = FakeCVE(11023, [{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]}])
NGINX_BUG = FakeCVE(42945, [{'vendor': 'f5', 'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.27.0'}]}])
WORDPRESS_BUG = FakeCVE(77001, [{'vendor': 'wordpress', 'product': 'wordpress', 'ranges': [{'introduced': '7.0.0', 'fixed': '7.1.5'}]}])
CVES = (JQUERY_XSS, NGINX_BUG, WORDPRESS_BUG)

# the live WordPress 7.1.x page: core jQuery 3.7.1, a theme plugin whose cache-buster Wappalyzer reads as "jQuery 1.0.4" and a forms plugin
# whose cache-buster it reads as "jQuery 3.2.1"
WORDPRESS_PAGE = ('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                  '<script src="/wp-content/themes/acme/js/jquery.fancybox.js?ver=1.0.4"></script>'
                  '<script src="/wp-content/plugins/forms/js/forms.min.js?ver=3.2.1"></script>')
FANCYBOX = '/*! fancyBox v2.1.5 fancyapps.com | fancyapps.com/fancybox/#license */\n(function(r,G,f,v){})(window,document,jQuery);'


class Hosts(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'blog.rt.test', 'rt.test'))
        self.index = correlation.build_product_index(CVES)

    def sub(self, name):
        return Subdomain.objects.get(scan_history=self.scan_obj, name=name)

    def root(self, host, status=200, scheme='https', redirect_to='', evidence=None):
        RouteAuth.objects.create(project=self.project, domain=self.domain, host=host, path='/', url=f'{scheme}://{host}/',
                                 auth_state='redirect' if 300 <= status < 400 else 'open', http_status=status, redirect_to=redirect_to,
                                 evidence=evidence or {}, checked_at=timezone.now())

    def matches(self, host, *names):
        sub = self.sub(host)
        for name in names:
            sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        sub = Subdomain.objects.prefetch_related('technologies').get(pk=sub.pk)
        return {(r['matched_product'].lower(), r['matched_version']): r
                for r in correlation.collect_subdomain_matches(sub, self.index, {c.id: c for c in CVES})}


# the plugin as it is served with its licence comment stripped (a minifier's default): nothing in it beyond what was recognised, so the
# page is known whole. The live file keeps its fancyBox licence block, which no rule names: then the page contradicts nothing
FANCYBOX_STRIPPED = '(function(r,G,f,v){})(window,document,jQuery);'
WP_BODIES = {'/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN, '/wp-content/themes/acme/js/jquery.fancybox.js': FANCYBOX_STRIPPED}


def front_page_evidence(page, bodies, serve_rest=True):
    from cveFeed import route_auth
    from tests.test_js_library_versions import same_host_only
    _state, evidence = route_auth.classify({'status': 200, 'body': page, 'url': PAGE_URL, 'content_type': 'text/html', 'headers': {}})
    entries = (evidence.pop('page_scripts', None) or {}).get('scripts') or []

    def fetch(url, headers=None):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        if path in bodies:
            return {'status': 200, 'body': bodies[path], 'content_type': 'application/javascript'}
        if serve_rest:
            return {'status': 200, 'body': 'var site = 1;', 'content_type': 'application/javascript'}
        return {'status': 404, 'body': 'not found', 'content_type': 'text/html'}
    coverage = {}
    with mock.patch.object(js_libraries, '_cache', return_value=None):
        records = js_libraries.read_page(entries, PAGE_URL, fetch, same_host_only, {'left': 50}, reader=js_libraries.Reader(sleep=lambda s: None),
                                         coverage=coverage)
    if 'script_page' in evidence:
        evidence['script_page']['unread'] = coverage.get('scripts', 0) - coverage.get('read', 0)
    return {**evidence, **({'libraries': records} if records else {})}


class AnotherToolsVersionTests(Hosts):
    """1: a version the page's own files did not state stays at most a file-name hint (0.4), whichever tool stored it."""

    def records(self):
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            return read(WORDPRESS_PAGE, {'/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN, '/wp-content/themes/acme/js/jquery.fancybox.js': FANCYBOX})

    def page_evidence(self, page=WORDPRESS_PAGE, bodies=None, serve_rest=True):
        """What the route check stores for a front page it read (route_auth.classify, then the page's scripts read): the library records,
        and the script_page marker with how many scripts were not read whole. ``bodies`` serve scripts by path; with ``serve_rest`` any other
        same-host script answers a small file of no library, so every script is read, else it is not served."""
        return front_page_evidence(page, WP_BODIES if bodies is None and page is WORDPRESS_PAGE else (bodies or {}), serve_rest)

    def test_wordpress_core_jquery_read_from_its_file_closes_the_themes_cache_buster_read_by_a_technology_scan(self):
        # the live case: WordPress 7.1.x loads core jQuery 3.7.1 (its file says so); Wappalyzer read a theme script's ?ver=1.0.4 as jQuery
        records = self.records()
        self.assertEqual([c['version'] for c in records['jquery']['copies']], ['3.7.1'])  # the plugin is not a copy of jQuery
        self.root('www.rt.test', evidence=self.page_evidence())
        found = self.matches('www.rt.test', 'jQuery:3.7.1', 'jQuery:1.0.4', 'jQuery:3.2.1', 'nginx:1.24.0', 'WordPress:7.1.4')
        # the page's files inform and cap, never close: both stay candidates at the file-name confidence, the note says what the file states
        for version in ('1.0.4', '3.2.1'):
            self.assertEqual(found[('jquery', version)]['confidence'], js_libraries.CONFIDENCE['filename'])
        skip, evidence, cap = js_libraries.HostLibraries.for_subdomain(self.sub('www.rt.test')).judge('jQuery', '1.0.4')
        self.assertEqual((skip, cap), (False, js_libraries.CONFIDENCE['filename']))
        self.assertEqual(evidence['version_note'], js_libraries.CONTRADICTS_NOTE.format(name='jQuery', said='3.7.1', version='1.0.4'))
        # server-side products on the same host are not touched
        self.assertEqual(found[('nginx', '1.24.0')]['confidence'], 0.95)
        # the live plugin file keeps its fancyBox licence block, which no rule names: a script carrying more than was recognised may hold
        # any library, so the page contradicts nothing and the technology scan's versions stay capped candidates
        RouteAuth.objects.all().delete()
        self.root('www.rt.test', evidence=self.page_evidence(bodies={**WP_BODIES, '/wp-content/themes/acme/js/jquery.fancybox.js': FANCYBOX}))
        self.assertEqual(RouteAuth.objects.get(host='www.rt.test').evidence['script_page']['unread'], 1)
        for version in ('1.0.4', '3.2.1'):
            match = self.matches('www.rt.test')[('jquery', version)]
            self.assertEqual((match['confidence'], match['evidence']['version_source']), (js_libraries.CONFIDENCE['filename'], 'other'))
        self.assertNotIn('version_source', found[('nginx', '1.24.0')]['evidence'])
        self.assertEqual(found[('wordpress', '7.1.4')]['confidence'], 0.95)

    def test_a_page_that_loads_no_such_script_or_a_themes_ver_proves_nothing(self):
        # every script read whole, none is jQuery, a plugin's ?ver=1.0.4: a script under another name, or one the page loads later, may
        # still be jQuery, so neither an absence nor a cache-buster ever closes a technology scan's version: it stays a capped candidate
        self.root('www.rt.test', evidence=self.page_evidence(page='<script src="/wp-content/plugins/p/app.js?ver=1.0.4"></script>'
                                                                  '<script src="/site.js"></script>'))
        found = self.matches('www.rt.test', 'jQuery:3.2.1', 'jQuery:1.0.4')
        for version in ('3.2.1', '1.0.4'):
            match = found[('jquery', version)]
            self.assertEqual((match['confidence'], match['evidence']['version_source']), (js_libraries.CONFIDENCE['filename'], 'other'))
            self.assertFalse(match_policy.has_hard_evidence('tech', match['evidence']))
            self.assertTrue(match_policy.version_only('tech', match['evidence'], match['version_in_range']))

    def test_a_shadowed_copy_a_technology_scan_named_stays_a_capped_candidate(self):
        page = '<script src="/assets/jquery-3.4.1.min.js"></script><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
        self.root('www.rt.test', evidence=self.page_evidence(page=page, bodies={
            '/assets/jquery-3.4.1.min.js': '/*! jQuery v3.4.1 | (c) JS Foundation */', '/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN}))
        match = self.matches('www.rt.test', 'jQuery:3.4.1')[('jquery', '3.4.1')]
        self.assertEqual((match['confidence'], match['evidence']['copy_state']), (js_libraries.SHADOWED_CAP, 'shadowed'))

    def test_a_front_page_read_before_this_release_without_a_library_keeps_the_cap(self):
        self.root('www.rt.test', evidence={'fingerprints': []})  # a 200 root with no script_page marker and no libraries record
        match = self.matches('www.rt.test', 'jQuery:3.2.1')[('jquery', '3.2.1')]
        self.assertEqual(match['confidence'], js_libraries.CONFIDENCE['filename'])

    def test_an_edge_challenge_page_is_not_a_read_front_page(self):
        from cveFeed import route_auth
        _state, evidence = route_auth.classify({'status': 200, 'url': PAGE_URL, 'content_type': 'text/html', 'headers': {'cf-mitigated': 'challenge'},
                                                'body': '<title>Just a moment...</title>'})
        self.assertNotIn('script_page', evidence)

    def test_with_no_reading_of_the_page_another_tools_version_is_a_capped_candidate(self):
        match = self.matches('www.rt.test', 'jQuery:3.4.1')[('jquery', '3.4.1')]
        self.assertEqual((match['confidence'], match['evidence']['version_source']), (js_libraries.CONFIDENCE['filename'], 'other'))
        self.assertTrue(match['version_in_range'])  # a candidate, never dropped: nothing the file states contradicts it

    def test_a_version_the_file_states_keeps_its_confidence(self):
        records = self.records()
        records['jquery']['copies'][0]['version'] = records['jquery']['version'] = '3.4.1'  # the same page, an older core jQuery
        self.root('www.rt.test', evidence={'libraries': records})
        match = self.matches('www.rt.test', 'jQuery:3.4.1')[('jquery', '3.4.1')]
        self.assertEqual((match['confidence'], match['evidence']['version_source']), (0.95, 'body'))

    def test_judge_caps_every_library_it_covers_and_nothing_else(self):
        libraries = js_libraries.HostLibraries()
        for name in ('jQuery', 'jquery', 'Bootstrap', 'Moment.js', 'jQuery UI', 'DataTables'):
            skip, evidence, cap = libraries.judge(name, '1.0.4')
            self.assertEqual((skip, cap, evidence['version_source']), (False, js_libraries.CONFIDENCE['filename'], 'other'), name)
        for name in ('nginx', 'WordPress', 'OpenSSH', 'jquery-ui-rails'):
            self.assertEqual(libraries.judge(name, '1.0.4'), (False, {}, None), name)


class RedirectAliasCorrelationTests(Hosts):
    """2: a host whose front page only redirects to another host serves none of that host's scripts."""

    def test_the_libraries_another_tool_saw_behind_the_redirect_are_not_matched_on_the_alias(self):
        self.root('blog.rt.test', 301, redirect_to='https://rt.test/')
        self.root('blog.rt.test', 301, scheme='http', redirect_to='https://blog.rt.test/')  # http to https first, then away
        found = self.matches('blog.rt.test', 'jQuery:1.0.4', 'jQuery:3.2.1', 'Bootstrap:1.0.4', 'nginx:1.24.0')
        self.assertNotIn(('jquery', '1.0.4'), found)
        self.assertNotIn(('jquery', '3.2.1'), found)
        self.assertIn(('nginx', '1.24.0'), found)  # the server that answered the redirect is this host's

    def test_a_probe_reading_recorded_on_the_alias_before_the_fix_is_not_matched_either(self):
        self.root('blog.rt.test', 301, redirect_to='https://rt.test/')
        record = {'product': 'jQuery', 'version': '3.2.1', 'version_source': 'filename', 'version_confidence': 0.4, 'tech_names': ['jQuery:3.2.1'],
                  'copies': [{'url': 'https://rt.test/js/jquery-3.2.1.min.js', 'version': '3.2.1', 'source': 'filename', 'state': 'effective'}]}
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='blog.rt.test', probe='html-libraries', port=0, kind='version',
                                        product='jQuery', version='3.2.1', outcome='found', confidence=0.4, source='script:filename',
                                        evidence={'library': record})
        self.assertEqual(self.matches('blog.rt.test', 'jQuery:3.2.1'), {})

    def test_a_host_that_serves_its_own_page_keeps_its_libraries(self):
        self.root('rt.test', 200)
        self.root('rt.test', 301, scheme='http', redirect_to='https://rt.test/')  # a redirect to itself is not an alias
        self.assertIn(('jquery', '3.2.1'), self.matches('rt.test', 'jQuery:3.2.1'))

    def test_a_redirect_to_a_path_of_the_same_host_is_not_an_alias(self):
        self.root('www.rt.test', 302, redirect_to='/en/')
        self.assertIn(('jquery', '3.2.1'), self.matches('www.rt.test', 'jQuery:3.2.1'))

    def test_a_host_with_any_other_answer_at_its_root_is_not_judged_an_alias(self):
        from startScan.models import Port
        self.sub('blog.rt.test').ip_addresses.first().ports.add(Port.objects.create(number=80, service_name='http', state='open'))
        self.root('blog.rt.test', 301, redirect_to='https://rt.test/')
        self.root('blog.rt.test', 403, scheme='http')
        self.assertIn(('jquery', '3.2.1'), self.matches('blog.rt.test', 'jQuery:3.2.1'))

    def test_a_web_port_the_route_check_did_not_read_keeps_the_host_from_being_an_alias(self):
        from startScan.models import Port
        self.sub('blog.rt.test').ip_addresses.first().ports.add(Port.objects.create(number=8443, service_name='https', state='open'))
        self.root('blog.rt.test', 301, redirect_to='https://rt.test/')  # 443 redirects away, 8443 may serve an application of its own
        self.assertIn(('jquery', '3.2.1'), self.matches('blog.rt.test', 'jQuery:3.2.1'))
        row = RouteAuth.objects.create(project=self.project, domain=self.domain, host='blog.rt.test', path='/', url='https://blog.rt.test:8443/',
                                       auth_state='redirect', http_status=302, redirect_to='https://rt.test/', checked_at=timezone.now())
        self.assertIn(('jquery', '3.2.1'), self.matches('blog.rt.test', 'jQuery:3.2.1'))  # a temporary redirect: may serve its own page again
        RouteAuth.objects.filter(pk=row.pk).update(http_status=308)
        self.assertEqual(self.matches('blog.rt.test', 'jQuery:3.2.1'), {})  # every web port redirects away for good: an alias

    def test_a_match_closed_because_the_host_only_redirected_reopens_when_it_serves_its_own_page(self):
        from cveFeed.models import CVEEntry, CVEMatch
        entry = CVEEntry.objects.create(id=JQUERY_XSS.id, cve_id=JQUERY_XSS.cve_id, affected=JQUERY_XSS.affected, kev=True, cvss=6.9,
                                        published_at=timezone.now())
        sub = self.sub('blog.rt.test')
        sub.technologies.add(Technology.objects.get_or_create(name='jQuery:3.2.1')[0])
        index = correlation.build_product_index([entry])

        def correlate():
            correlation.correlate_subdomain(Subdomain.objects.prefetch_related('technologies').get(pk=sub.pk), index, {entry.id: entry})
            return CVEMatch.objects.get(subdomain=sub, cve_entry=entry)
        self.assertEqual(correlate().ai_verdict, '')
        self.root('blog.rt.test', 301, redirect_to='https://rt.test/')
        closed = correlate()
        self.assertEqual(closed.ai_verdict, 'not_affected')
        self.assertTrue(closed.ai_reason.startswith(js_libraries.LIBRARY_CLOSED), closed.ai_reason)
        self.assertIn('only redirects to rt.test', closed.ai_reason)
        # it serves a page of its own now, read lately by the route check: the page loads jQuery 3.2.1, so the match reopens
        evidence = front_page_evidence('<script src="/js/jquery-3.2.1.min.js"></script>', {}, serve_rest=False)  # its file is not read
        RouteAuth.objects.filter(host='blog.rt.test').update(http_status=200, redirect_to='', auth_state='open', evidence=evidence)
        reopened = correlate()
        self.assertEqual((reopened.pk, reopened.ai_verdict, reopened.ai_reason), (closed.pk, '', ''))
        self.assertEqual(reopened.confidence, js_libraries.CONFIDENCE['filename'])

    def test_the_alias_rule_is_pure(self):
        alias = js_libraries.redirect_alias_of
        self.assertEqual(alias([('https://a.test/', 301, 'https://b.test/')], 'a.test'), 'b.test')
        self.assertEqual(alias([('http://a.test/', 301, 'https://a.test/'), ('https://a.test/', 308, '//B.test./x')], 'a.test'), 'b.test')
        self.assertEqual(alias([('http://a.test/', 301, 'https://a.test/')], 'a.test'), '')
        self.assertEqual(alias([('https://a.test/', 301, 'https://b.test/'), ('http://a.test/', 200, '')], 'a.test'), '')
        self.assertEqual(alias([('https://a.test/', None, '')], 'a.test'), '')
        self.assertEqual(alias([], 'a.test'), '')
        away = [('https://a.test/', 301, 'https://b.test/')]
        self.assertEqual(alias(away, 'a.test', ['https://a.test']), 'b.test')
        self.assertEqual(alias(away, 'a.test', ['https://a.test', 'https://a.test:8443']), '')  # a web port with no root read
        self.assertEqual(alias(away + [('https://a.test:8443/', 308, 'https://b.test/')], 'a.test', ['https://a.test', 'https://a.test:8443']),
                         'b.test')
        # only a permanent redirect (301, 308) makes an alias: a temporary one (a login hop, a geo or maintenance switch) does not
        for status in (300, 302, 303, 304, 307):
            self.assertEqual(alias([('https://a.test/', status, 'https://b.test/')], 'a.test'), '', status)
            self.assertEqual(alias([('http://a.test/', 301, 'https://a.test/'), ('https://a.test/', status, 'https://b.test/')], 'a.test'), '')
        self.assertEqual(alias([('https://a.test/', True, 'https://b.test/')], 'a.test'), '')


class RedirectProbeTests(NoCache, SimpleTestCase):
    """2: the probes follow a redirect inside the host's group (apex and www); what the page they land on loads is not the alias's."""

    TARGET = {'/': page(body='<script src="/js/jquery-3.2.1.min.js"></script><script src="/js/bootstrap.min.js?ver=1.0.4"></script>',
                        url='https://rt.test/', headers={'Server': 'nginx/1.24.0'}),
              '/js/jquery-3.2.1.min.js': page(body='/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */',
                                              url='https://rt.test/js/jquery-3.2.1.min.js')}

    def run_probe(self, probe_id, base, table):
        return probe_scanner.run_http_probe(probe_id, base, {'blog.rt.test', 'rt.test', 'www.rt.test'}, get=answers(table))

    def test_the_libraries_probe_records_nothing_for_a_host_that_redirected_elsewhere(self):
        self.assertEqual([o for o in self.run_probe('html-libraries', 'https://blog.rt.test', self.TARGET) if o['kind'] == 'version'], [])

    def test_the_headers_probe_records_nothing_of_the_page_another_host_served(self):
        found = self.run_probe('headers-root', 'https://blog.rt.test', self.TARGET)
        self.assertEqual([o for o in found if js_libraries.is_library(o['product'])], [])
        self.assertNotIn('nginx', {o['product'] for o in found})  # the target's Server header is the target's, too

    def test_the_host_the_page_belongs_to_records_its_libraries(self):
        found = self.run_probe('html-libraries', 'https://rt.test', self.TARGET)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])
        found = self.run_probe('headers-root', 'https://rt.test', self.TARGET)
        self.assertIn(('jQuery', '3.2.1'), {(o['product'], o['version']) for o in found})

    def test_a_redirect_inside_the_same_host_still_records_the_page(self):
        table = {'/': {**self.TARGET['/'], 'final_url': 'https://blog.rt.test/en/', 'url': 'https://blog.rt.test/en/'},
                 '/js/jquery-3.2.1.min.js': self.TARGET['/js/jquery-3.2.1.min.js']}
        found = self.run_probe('html-libraries', 'https://blog.rt.test', table)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])


class StoredMatchClosureTests(Hosts):
    """C: matches stored before the fix are re-checked against the page by the next correlation and by the periodic reconcile sweep."""

    def setUp(self):
        super().setUp()
        from cveFeed.models import CVEEntry
        self.entry = CVEEntry.objects.create(id=JQUERY_XSS.id, cve_id=JQUERY_XSS.cve_id, affected=JQUERY_XSS.affected, kev=True, cvss=6.9,
                                             published_at=timezone.now())
        self.sub_row = self.sub('www.rt.test')
        self.tech = Technology.objects.get_or_create(name='jQuery:1.0.4')[0]
        self.sub_row.technologies.add(self.tech)

    def wordpress_root(self):
        evidence = front_page_evidence(WORDPRESS_PAGE, WP_BODIES)
        self.root('www.rt.test', evidence=evidence)

    def correlate(self):
        from cveFeed.models import CVEMatch
        index = correlation.build_product_index([self.entry])
        correlation.correlate_subdomain(Subdomain.objects.prefetch_related('technologies').get(pk=self.sub_row.pk), index, {self.entry.id: self.entry})
        return CVEMatch.objects.get(subdomain=self.sub_row, cve_entry=self.entry)

    def test_the_next_correlation_keeps_a_technology_scan_match_the_page_contradicts_open_and_capped(self):
        before = self.correlate()
        self.assertEqual((before.ai_verdict, before.confidence), ('', js_libraries.CONFIDENCE['filename']))  # page never read: capped
        self.wordpress_root()
        after = self.correlate()  # the page's files inform and cap, never close (a page can load another copy at run time)
        self.assertEqual((after.ai_verdict, after.confidence), ('', js_libraries.CONFIDENCE['filename']))
        self.assertEqual(after.evidence['version_note'], js_libraries.CONTRADICTS_NOTE.format(name='jQuery', said='3.7.1', version='1.0.4'))

    def stored(self, **fields):
        from cveFeed.models import CVEMatch
        return CVEMatch.objects.create(cve_entry=self.entry, subdomain=self.sub_row, source='tech', matched_product='jquery', matched_version='1.0.4',
                                       version_in_range=True, confidence=0.95, scan_history=self.scan_obj,
                                       evidence={'source': 'tech', 'source_id': self.tech.id, 'raw_version': '1.0.4'}, **fields)

    def test_the_periodic_reconcile_sweep_closes_nothing_on_the_pages_files(self):
        from cveFeed.models import CVEMatch
        from cveFeed.tasks import reconcile_invalid_correlations, reconcile_library_provenance
        match = self.stored()  # as 1.3.2 left it: technology source, confidence 0.95
        self.wordpress_root()
        reconcile_invalid_correlations(limit=100)
        self.assertEqual(reconcile_library_provenance()['closed'], 0)
        self.assertEqual(CVEMatch.objects.get(pk=match.pk).ai_verdict, '')

    def test_a_match_an_earlier_build_closed_on_the_pages_files_is_reopened_once_and_nothing_pages(self):
        from unittest import mock

        from cveFeed import library_reopen
        from cveFeed.models import BackgroundCursor, CVEMatch, Triage
        from cveFeed.correlation import close_invalid_correlation
        self.wordpress_root()
        reasons = {"the page's own scripts say jQuery 3.7.1; the 1.0.4 came from a technology scan": 'contradicted_by_file',
                   "the page's own scripts say jQuery 3.7.1; the 1.0.4 came from a script's name or query string": 'named_by_script',
                   "the jQuery script's own file does not state 1.0.4": 'file_states_nothing', 'the front page loads no jQuery': 'no_such_script',
                   "the 1.0.4 is a theme's cache-buster": 'cache_buster', 'the host only redirects to rt.test; the jQuery seen there is that host\'s':
                   'redirect_alias'}
        rows = {}
        for text, kind in reasons.items():
            CVEMatch.objects.filter(subdomain=self.sub_row).delete()
            match = self.stored()
            self.assertTrue(close_invalid_correlation(match, js_libraries.closed_reason(text)))  # what an earlier build did
            self.assertEqual(js_libraries.closure_kind(CVEMatch.objects.get(pk=match.pk).ai_reason), kind)
            rows[kind] = CVEMatch.objects.get(pk=match.pk)
            CVEMatch.objects.filter(pk=match.pk).update(subdomain=Subdomain.objects.create(
                name=f'{kind}.rt.test', target_domain=self.domain, scan_history=self.scan_obj))  # each on a host of its own
        worked = rows['contradicted_by_file']
        person = CVEMatch.objects.create(cve_entry=self.entry, subdomain=Subdomain.objects.create(name='p.rt.test', target_domain=self.domain,
                                                                                                 scan_history=self.scan_obj),
                                         source='tech', matched_product='jquery', matched_version='1.0.4', version_in_range=True, confidence=0.4,
                                         ai_verdict='not_affected', ai_reason=js_libraries.closed_reason('the front page loads no jQuery'),
                                         ai_model='analyst')  # a person's (or the AI's) closure with the same words: never reopened
        with mock.patch('cveFeed.notify._send', return_value=True) as send:
            counts = library_reopen.reopen_once()
            self.assertIsNone(library_reopen.reopen_once())  # once: the marker makes every later call a single read
        self.assertEqual(send.call_count, 0)  # reopening never pages
        self.assertEqual(counts['reopened'], 5)
        self.assertEqual(counts['by_kind'], {k: 1 for k in js_libraries.FILE_KINDS})
        self.assertEqual(counts['projects'], {self.project.id: 5})
        self.assertTrue(BackgroundCursor.objects.filter(lane=library_reopen.ONCE_LANE, last_pk=library_reopen.DONE).exists())
        for kind, match in rows.items():
            match.refresh_from_db()
            if kind == 'redirect_alias':
                self.assertEqual(match.ai_verdict, 'not_affected')  # the one closure that stays
                continue
            self.assertEqual((match.ai_verdict, match.ai_reason, match.confidence), ('', '', js_libraries.CONFIDENCE['filename']), kind)
            self.assertEqual(match.evidence['reopened_from'], kind)
            self.assertEqual((Triage.objects.get(match=match).classification, Triage.objects.get(match=match).status), ('', 'pending'))
        self.assertEqual(CVEMatch.objects.get(pk=person.pk).ai_verdict, 'not_affected')
        self.assertEqual(worked.pk, rows['contradicted_by_file'].pk)
        # a second, explicit run finds nothing left (idempotent)
        self.assertEqual(library_reopen.reopen_file_closures()['reopened'], 0)

    def test_the_sweep_never_closes_a_match_a_person_worked_or_one_the_page_does_not_contradict(self):
        from cveFeed.models import CVEMatch
        from cveFeed.tasks import reconcile_invalid_correlations
        worked = self.stored(remediation_status='in_progress')
        reconcile_invalid_correlations(limit=100)  # page never read: nothing contradicts it
        self.assertEqual(CVEMatch.objects.get(pk=worked.pk).ai_verdict, '')
        self.wordpress_root()
        reconcile_invalid_correlations(limit=100)
        self.assertEqual(CVEMatch.objects.get(pk=worked.pk).ai_verdict, '')


class SystemicLibraryTests(Hosts):
    """The same provenance step for every library the registry names, not only jQuery: Bootstrap and Lodash."""

    BOOTSTRAP_XSS = FakeCVE(10735, [{'vendor': 'getbootstrap', 'product': 'bootstrap', 'ranges': [{'introduced': '0', 'fixed': '3.4.1'}]}])
    LODASH_POLLUTION = FakeCVE(10744, [{'vendor': 'lodash', 'product': 'lodash', 'ranges': [{'introduced': '0', 'fixed': '4.17.12'}]}])

    def found(self, page, bodies, *names, serve_rest=True):
        RouteAuth.objects.filter(host='www.rt.test').delete()
        self.root('www.rt.test', evidence=front_page_evidence(page, bodies, serve_rest))
        sub = self.sub('www.rt.test')
        for name in names:
            sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        cves = (self.BOOTSTRAP_XSS, self.LODASH_POLLUTION)
        rows = correlation.collect_subdomain_matches(Subdomain.objects.prefetch_related('technologies').get(pk=sub.pk),
                                                     correlation.build_product_index(cves), {c.id: c for c in cves})
        return {(r['matched_product'].lower(), r['matched_version']): r for r in rows}, js_libraries.HostLibraries.for_subdomain(sub)

    def test_bootstrap_and_lodash_versions_stay_candidates_whatever_their_files_say(self):
        page = '<script src="/js/bootstrap.min.js"></script><script src="/js/lodash.min.js"></script>'
        bodies = {'/js/bootstrap.min.js': '/*!\n  * Bootstrap v5.3.2 (https://getbootstrap.com/)\n  */',
                  '/js/lodash.min.js': '/**\n * @license\n * Lodash 4.17.21 <https://lodash.com/>\n */'}
        capped = {('bootstrap', '3.3.7'): js_libraries.CONFIDENCE['filename'], ('lodash', '4.17.4'): js_libraries.CONFIDENCE['filename']}
        # versions the page does not explain (no script URL of it, no other library on it carries them) stay capped candidates
        found, _libraries = self.found(page, bodies, 'Bootstrap:3.3.7', 'Lodash:4.17.4', 'Bootstrap:5.3.2', 'Lodash:4.17.21')
        self.assertEqual({key: m['confidence'] for key, m in found.items()}, capped)
        # explained too (a theme's ?ver= strings), every script read whole: Bootstrap's and Lodash's code is not recognised wherever it
        # appears (a copy without its banner looks like any other code), so their files close nothing: only jQuery's family is closable
        page += '<script src="/wp-content/themes/acme/js/theme.js?ver=3.3.7"></script><script src="/wp-content/plugins/p/p.js?ver=4.17.4"></script>'
        found, libraries = self.found(page, bodies, 'Bootstrap:3.3.7', 'Lodash:4.17.4', 'Bootstrap:5.3.2', 'Lodash:4.17.21')
        self.assertEqual({key: m['confidence'] for key, m in found.items()}, capped)
        for product, version in (('Bootstrap', '3.3.7'), ('Lodash', '4.17.4')):
            skip, evidence, _cap = libraries.judge(product, version)
            self.assertFalse(skip)
            self.assertIn('is not recognised wherever it appears', evidence['version_note'])

    def test_a_themes_ver_never_closes_bootstrap_or_lodash_and_their_own_files_still_prove_them(self):
        page = ('<script src="/js/lodash.min.js"></script><script src="/js/bootstrap.min.js?ver=3.3.7"></script>'
                '<script src="/wp-content/themes/acme/js/theme.js?ver=4.17.4"></script>')
        bodies = {'/js/lodash.min.js': '/** @license lodash 4.17.4 */', '/wp-content/themes/acme/js/theme.js': 'var theme = 1;'}
        found, libraries = self.found(page, bodies, 'Lodash:4.17.4', 'Bootstrap:3.3.7', serve_rest=False)  # bootstrap.min.js is not served
        # Lodash's own file says 4.17.4: proven, whatever a theme's ?ver= says; Bootstrap's own ?ver= alone proves nothing either way
        self.assertEqual(found[('lodash', '4.17.4')]['evidence']['version_source'], 'body')
        self.assertEqual(found[('bootstrap', '3.3.7')]['confidence'], js_libraries.CONFIDENCE['filename'])
        # a theme's ?ver= is never a reason to drop a version, every script read or not
        self.assertFalse(libraries.judge('Bootstrap', '4.17.4')[0])
        _found, libraries = self.found(page, {**bodies, '/js/bootstrap.min.js': 'var bootstrap = 1;'})
        self.assertFalse(libraries.judge('Bootstrap', '4.17.4')[0])


# a whole page whose one jQuery file (served by read_root) says 3.7.1, and whose other script carries the 1.12.4 the technology scan reported
# (a ?ver= string): only a version the page itself explains is ever closed as contradicted by its files
CONTRA = '<script src="/js/jquery.min.js"></script><script src="/site.js?ver=1.12.4"></script>'


ORACLE = os.path.join(os.path.dirname(__file__), 'fixtures', 'js_provenance')


def oracle(name):
    with open(os.path.join(ORACLE, name), encoding='utf-8') as handle:
        return handle.read()


class LiveSiteOracleTests(RouteFixture, TestCase):
    """The live case (2026-11-02, names replaced), replayed through the route check's page read, correlation and closure: a WordPress site
    whose core jQuery file says 3.7.1, five names that only redirect to it, and a hosted landing site whose "/" answers 404 but loads a
    real jQuery 1.11.2. Of the 19 stored matches, the 15 on the names that only redirect close with a true reason; CVE-2020-11023 on the
    landing site stands, proven, and the WordPress site's own matches stay capped candidates: only 2 of the 36 scripts its page loads are
    read whole (6 a host at most, third-party ones never), and a script not read may carry any library under any name, so the page's
    jQuery file contradicts nothing."""

    HOSTS = {'acme.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'www.acme.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'learn.acme.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'donate.acme.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'blog.acme.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'careers.acme.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'info.acme.test': ['jQuery:1.11.2']}
    REDIRECTS = {'www.acme.test': 'https://acme.test/', 'learn.acme.test': 'https://acme.test/', 'donate.acme.test': 'https://acme.test/',
                 'blog.acme.test': 'https://acme.test/', 'careers.acme.test': 'https://acme.test/careers/working-at-acme/'}
    SCRIPTS = {'https://acme.test/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN,
               'https://acme.test/wp-includes/js/jquery/jquery-migrate.min.js': '/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation and other contributors */',
               'https://info.acme.test/hs/hsstatic/jquery-libs/static-1.4/jquery/jquery-1.11.2.js': oracle('jquery-1.11.2-head.js')}

    def setUp(self):
        super().setUp()
        from cveFeed.models import CVEEntry
        from targetApp.models import Domain
        from startScan.models import IpAddress, Port, ScanHistory
        self.site = Domain.objects.create(name='acme.test', project=self.project, insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=self.site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[],
                                          results_dir='x')
        ip = IpAddress.objects.create(address='203.0.113.80')
        ip.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
        self.subs = {}
        for name, techs in self.HOSTS.items():
            sub = Subdomain.objects.create(name=name, target_domain=self.site, scan_history=scan)
            sub.ip_addresses.add(ip)
            sub.technologies.add(*[Technology.objects.get_or_create(name=t)[0] for t in techs])
            self.subs[name] = sub
        self.entries = [
            CVEEntry.objects.create(cve_id='CVE-2020-11023', kev=True, cvss=6.9, published_at=timezone.now(),
                                    affected=[{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]}]),
            CVEEntry.objects.create(cve_id='CVE-2020-11022', cvss=6.9, published_at=timezone.now(),
                                    affected=[{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.12.0', 'fixed': '3.5.0'}]}]),
            CVEEntry.objects.create(cve_id='CVE-2026-114538', cvss=6.1, published_at=timezone.now(),
                                    affected=[{'vendor': 'drupal', 'product': 'bootstrap', 'ranges': [{'introduced': '0.0.0', 'fixed': '3.45.0'}]}])]

    def correlate(self):
        index = correlation.build_product_index(self.entries)
        correlation.correlate_subdomains(Subdomain.objects.filter(pk__in=[s.pk for s in self.subs.values()])
                                         .prefetch_related('technologies', 'ip_addresses__ports'), index, {e.id: e for e in self.entries})

    def read_front_pages(self):
        """The route check's front-page read, against the saved answers: classify, read the scripts, store the root route."""
        from cveFeed import route_auth

        def probe(url, **_kw):
            body = self.SCRIPTS.get(url.split('?', 1)[0])
            return ({'status': 200, 'body': body, 'url': url, 'content_type': 'application/javascript', 'headers': {}} if body is not None
                    else {'status': 404, 'body': 'not found', 'url': url, 'content_type': 'text/html', 'headers': {}})
        answers = {'acme.test': {'status': 200, 'body': oracle('wordpress-front-page.html'), 'title': 'Home'},
                   'info.acme.test': {'status': 404, 'body': oracle('hosted-404-front-page.html'), 'title': 'Page not found'}}
        answers.update({host: {'status': 301, 'location': target, 'body': '<html><head><title>301 Moved Permanently</title></head></html>'}
                        for host, target in self.REDIRECTS.items()})
        for host, answer in answers.items():
            url = f'https://{host}/'
            result = route_auth.analyse({'url': url, 'content_type': 'text/html', 'headers': {}, **answer})
            with mock.patch.object(js_libraries, '_cache', return_value=None):
                route_scanner.read_scripts(result, probe, 0, project=self.project.id, reader=js_libraries.Reader(self.project.id),
                                         target=self.site)
            RouteAuth.objects.create(project=self.project, domain=self.site, host=host, path='/', url=url, auth_state=result['state'],
                                     http_status=answer['status'], redirect_to=result['evidence'].get('redirect_to', ''),
                                     evidence=result['evidence'], checked_at=timezone.now())

    def open_and_closed(self):
        from cveFeed.models import CVEMatch
        rows = list(CVEMatch.objects.filter(subdomain__in=self.subs.values()).select_related('cve_entry', 'subdomain'))
        is_open = [m for m in rows if m.ai_verdict != 'not_affected']
        closed = [m for m in rows if m.ai_verdict == 'not_affected']
        return rows, is_open, closed

    def assert_oracle(self, closed_kinds, proven=True):
        """15 of the 19 close with a true reason, all of them redirect aliases; four stay open: the real jQuery 1.11.2 on the landing site
        (a KEV), and the WordPress site's jQuery and Bootstrap matches, capped candidates: its page loads 36 scripts and only 2 are read
        whole (6 a host at most, third-party ones never), so its one jQuery file contradicts nothing, and a theme's ?ver= never closes
        anything."""
        rows, is_open, closed = self.open_and_closed()
        self.assertEqual(len(rows), 19)
        # the jQuery version an open match on the WordPress site names (3.2.1 or 3.4.1, both in range) is whichever correlation chose
        self.assertEqual(sorted((m.subdomain.name, m.cve_entry.cve_id) for m in is_open),
                         [('acme.test', 'CVE-2020-11022'), ('acme.test', 'CVE-2020-11023'), ('acme.test', 'CVE-2026-114538'),
                          ('info.acme.test', 'CVE-2020-11023')])
        survivor = next(m for m in is_open if m.subdomain.name == 'info.acme.test')
        self.assertEqual(survivor.matched_version, '1.11.2')
        if proven:  # correlated again after the page read: proven by the file's banner
            self.assertEqual((survivor.evidence.get('version_source'), survivor.confidence), ('body', 0.95))
        if proven:
            self.assertTrue(all(m.confidence <= js_libraries.CONFIDENCE['filename'] for m in is_open if m.subdomain.name == 'acme.test'))
        script_page = RouteAuth.objects.get(host='acme.test').evidence['script_page']
        self.assertEqual((script_page['scripts'], script_page['unread']), (36, 34))
        # the page explains every jQuery version the technology scans named (two ?ver= strings, jQuery Migrate 3.4.1): only the 34 scripts
        # not read whole keep them open
        libraries = js_libraries.HostLibraries.for_subdomain(self.subs['acme.test'])
        self.assertEqual([libraries.explains('jquery', v) for v in ('1.0.4', '3.2.1', '3.4.1')], [True, True, True])
        self.assertFalse(libraries.page_read)
        self.assertEqual(len(closed), 15)
        kinds = {}
        for m in closed:
            self.assertTrue(m.ai_reason.startswith(js_libraries.LIBRARY_CLOSED), m.ai_reason)
            kinds[js_libraries.closure_kind(m.ai_reason)] = kinds.get(js_libraries.closure_kind(m.ai_reason), 0) + 1
        self.assertEqual(kinds, closed_kinds)
        by_host = {(m.subdomain.name, m.cve_entry.cve_id): m.ai_reason for m in closed}
        self.assertIn('only redirects to acme.test', by_host[('careers.acme.test', 'CVE-2020-11023')])

    def test_the_next_correlation_closes_the_aliases_and_keeps_the_real_one(self):
        self.correlate()  # as stored before the fix: no front page read
        rows, is_open, _closed = self.open_and_closed()
        self.assertEqual((len(rows), len(is_open)), (19, 19))
        self.read_front_pages()
        self.correlate()
        self.assert_oracle({'redirect_alias': 15})

    def test_the_closures_an_earlier_build_made_on_the_page_reopen_once_and_the_aliases_stay(self):
        """The oracle as the build before the final review left it: 17 closed (15 redirect aliases, 2 jQuery matches on acme.test closed as
        contradicted by the page's file). The one-off step reopens the 2, keeps the 15, and pages nothing."""
        from cveFeed import library_reopen
        from cveFeed.correlation import close_invalid_correlation
        from cveFeed.models import CVEMatch
        self.correlate()
        self.read_front_pages()
        self.correlate()
        for m in CVEMatch.objects.filter(subdomain__name='acme.test', matched_product='jquery').select_related('cve_entry', 'subdomain'):
            self.assertTrue(close_invalid_correlation(m, js_libraries.closed_reason(
                f"the page's own scripts say jQuery 3.7.1; the {m.matched_version} came from a technology scan")))
        _rows, _open, closed = self.open_and_closed()
        self.assertEqual(len(closed), 17)
        with mock.patch('cveFeed.notify._send', return_value=True) as send:
            counts = library_reopen.reopen_once()
        self.assertEqual(send.call_count, 0)
        self.assertEqual((counts['reopened'], counts['by_kind']), (2, {'contradicted_by_file': 2}))
        self.assert_oracle({'redirect_alias': 15}, proven=False)

    def test_the_reconcile_sweep_closes_the_same_aliases_without_a_rescan(self):
        from cveFeed.tasks import reconcile_invalid_correlations
        self.correlate()
        self.read_front_pages()
        with self.assertLogs('cveFeed.tasks', level='INFO') as logs:
            result = reconcile_invalid_correlations(limit=100)
        self.assertEqual(result['closed_by_reason'], {'redirect_alias': 15})
        self.assertIn('closed 15 of', '\n'.join(logs.output))
        self.assert_oracle({'redirect_alias': 15}, proven=False)


def synthesized_page(key, cut):
    """A live front page rebuilt from its script tags at their original byte offsets (everything else is padding), as the route check reads
    it: the first ``cut`` bytes, marked truncated when the page is longer."""
    import json
    with open(os.path.join(ORACLE, 'front-page-script-offsets.json'), encoding='utf-8') as handle:
        page = json.load(handle)[key]
    body = bytearray(b' ' * page['size'])
    for offset, tag in page['scripts']:
        raw = tag.encode('utf-8')
        body[offset:offset + len(raw)] = raw
    body = bytes(body)
    return {'body': body[:cut].decode('utf-8', 'ignore'), 'bytes': min(len(body), cut), 'read_limit': cut, 'truncated': len(body) > cut}


class RawLiveSiteOracleTests(LiveSiteOracleTests):
    """The same live case with the pages at their real length: the WordPress page is 248,915 bytes and its theme, plugin and Bootstrap
    scripts sit 229 KB in. The route check reads a front page up to ROOT_READ_BYTES, so every script tag is seen and every closure carries
    a true reason; read at the old 64 KiB, the page is truncated and its files contradict nothing, so nothing on it closes either way."""

    CUT = None

    def read_front_pages(self):
        from cveFeed import route_auth
        cut = self.CUT or route_scanner.ROOT_READ_BYTES

        def probe(url, **_kw):
            body = self.SCRIPTS.get(url.split('?', 1)[0])
            return ({'status': 200, 'body': body, 'url': url, 'content_type': 'application/javascript', 'headers': {}} if body is not None
                    else {'status': 404, 'body': 'not found', 'url': url, 'content_type': 'text/html', 'headers': {}})
        answers = {'acme.test': {'status': 200, **synthesized_page('wordpress', cut)},
                   'info.acme.test': {'status': 404, **synthesized_page('hosted_404', cut)}}
        answers.update({host: {'status': 301, 'location': target, 'body': '<html><head><title>301 Moved Permanently</title></head></html>'}
                        for host, target in self.REDIRECTS.items()})
        for host, answer in answers.items():
            url = f'https://{host}/'
            result = route_auth.analyse({'url': url, 'content_type': 'text/html', 'headers': {}, 'title': '', **answer})
            with mock.patch.object(js_libraries, '_cache', return_value=None):
                route_scanner.read_scripts(result, probe, 0, project=self.project.id, reader=js_libraries.Reader(self.project.id),
                                         target=self.site)
            RouteAuth.objects.create(project=self.project, domain=self.site, host=host, path='/', url=url, auth_state=result['state'],
                                     http_status=answer['status'], redirect_to=result['evidence'].get('redirect_to', ''),
                                     evidence=result['evidence'], checked_at=timezone.now())

    def test_every_closure_on_the_whole_page_says_what_the_page_really_shows(self):
        self.correlate()
        self.read_front_pages()
        self.correlate()
        self.assert_oracle({'redirect_alias': 15})
        _rows, _open, closed = self.open_and_closed()
        reasons = [m.ai_reason for m in closed if m.subdomain.name == 'acme.test']
        self.assertFalse([r for r in reasons if 'loads no' in r], reasons)  # the page loads Bootstrap: never "loads no Bootstrap script"

    def test_the_page_cut_at_64_kib_contradicts_nothing_so_only_the_aliases_close(self):
        from cveFeed import route_auth
        self.CUT = route_auth.ROUTE_SAMPLE_BYTES
        self.correlate()
        self.read_front_pages()
        self.correlate()
        _rows, is_open, closed = self.open_and_closed()
        self.assertEqual({js_libraries.closure_kind(m.ai_reason) for m in closed}, {'redirect_alias'})
        self.assertEqual(len(closed), 15)
        self.assertEqual(sorted((m.subdomain.name, m.cve_entry.cve_id) for m in is_open),
                         [('acme.test', 'CVE-2020-11022'), ('acme.test', 'CVE-2020-11023'), ('acme.test', 'CVE-2026-114538'),
                          ('info.acme.test', 'CVE-2020-11023')])
        self.assertTrue(all(m.confidence <= js_libraries.CONFIDENCE['filename'] for m in is_open if m.subdomain.name == 'acme.test'))

    def test_the_reconcile_sweep_closes_the_same_aliases_without_a_rescan(self):
        super().test_the_reconcile_sweep_closes_the_same_aliases_without_a_rescan()

    def test_the_next_correlation_closes_the_aliases_and_keeps_the_real_one(self):
        super().test_the_next_correlation_closes_the_aliases_and_keeps_the_real_one()


class ReviewScenarioBase(RouteFixture, TestCase):
    """Hosts, front pages and correlation for the review scenarios, through the real classify, script read, correlation and sweep code."""

    def setUp(self):
        super().setUp()
        from cveFeed.models import CVEEntry
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        self.site = Domain.objects.create(name='x.test', project=self.project, insert_date=timezone.now())
        self.scan_obj = ScanHistory.objects.create(domain=self.site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2,
                                                   tasks=[], results_dir='x')
        self.jq = CVEEntry.objects.create(cve_id='CVE-2020-11023', kev=True, cvss=6.9, published_at=timezone.now(),
                                          affected=[{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]}])
        self.bs = CVEEntry.objects.create(cve_id='CVE-2024-6484', cvss=6.4, published_at=timezone.now(),
                                          affected=[{'vendor': 'getbootstrap', 'product': 'bootstrap', 'ranges': [{'introduced': '3.0.0', 'fixed': '4.0.0'}]}])
        self.entries = [self.jq, self.bs]

    def host(self, name, techs, ports=(443,)):
        from startScan.models import IpAddress, Port
        ip = IpAddress.objects.create(address=f'203.0.113.{100 + Subdomain.objects.count()}')
        for number in ports:
            ip.ports.add(Port.objects.create(number=number, service_name='https' if number == 443 else 'http', state='open'))
        sub = Subdomain.objects.create(name=name, target_domain=self.site, scan_history=self.scan_obj)
        sub.ip_addresses.add(ip)
        sub.technologies.add(*[Technology.objects.get_or_create(name=t)[0] for t in techs])
        return sub

    def redirect_away(self, host, target='target.x.test'):
        """The host's front page now only redirects (301) to another host of the project: the one closure the page can make."""
        if not Subdomain.objects.filter(name=target, target_domain=self.site).exists():
            self.host(target, [])
        return self.read_root(host, 301, '', location=f'https://{target}/')

    def read_root(self, host, status, body='', scheme='https', location='', scripts=None, **extra):
        from cveFeed import route_auth
        url = f'{scheme}://{host}/'
        result = route_auth.analyse({'url': url, 'status': status, 'body': body, 'content_type': 'text/html', 'headers': {}, 'location': location,
                                     **extra})

        served = {f'{scheme}://{host}/site.js': 'var site = 1;', f'{scheme}://{host}/js/jquery.min.js': JQ_371_MIN,  # a file of no library; the
                  **(scripts or {})}                                                                                    # site's jQuery 3.7.1

        def probe(target, **_kw):
            text = served.get(target.split('?', 1)[0])
            return ({'status': 200, 'body': text, 'url': target, 'content_type': 'application/javascript', 'headers': {}} if text is not None
                    else {'status': 404, 'body': 'nf', 'url': target, 'content_type': 'text/html', 'headers': {}})
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            route_scanner.read_scripts(result, probe, 0, project=self.project.id, reader=js_libraries.Reader(self.project.id), target=self.site)
        RouteAuth.objects.update_or_create(project=self.project, url=url, defaults={
            'domain': self.site, 'host': host, 'path': '/', 'auth_state': result['state'], 'http_status': status,
            'redirect_to': result['evidence'].get('redirect_to', ''), 'evidence': result['evidence'], 'checked_at': timezone.now()})
        return result

    def correlate(self, *subs):
        from cveFeed.models import CVEMatch
        index = correlation.build_product_index(self.entries)
        correlation.correlate_subdomains(Subdomain.objects.filter(pk__in=[s.pk for s in subs]).prefetch_related('technologies', 'ip_addresses__ports'),
                                         index, {e.id: e for e in self.entries})
        return {(m.subdomain.name, m.cve_entry.cve_id, m.matched_version): m
                for m in CVEMatch.objects.filter(subdomain__in=subs).select_related('subdomain', 'cve_entry')}



class ReviewScenarioTests(ReviewScenarioBase):
    """The review of #388: E1 to E5, standing, freshness, flapping and the sweep."""

    FILLER = '<div>' + ('x' * 70000) + '</div>'

    def test_e1_a_script_past_the_read_limit_is_never_called_absent(self):
        from cveFeed import route_auth
        sub = self.host('big.x.test', ['Bootstrap:3.4.1'])
        page = ('<html><head><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script></head><body>' + self.FILLER +
                '<script src="/js/bootstrap.min.js"></script></body></html>')
        cut = page.encode()[:route_auth.ROUTE_SAMPLE_BYTES].decode('utf-8', 'ignore')  # what a 64 KiB read returns
        self.read_root('big.x.test', 200, cut, scripts={'https://big.x.test/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        self.assertTrue(RouteAuth.objects.get(host='big.x.test').evidence['script_page']['truncated'])
        match = self.correlate(sub)[('big.x.test', 'CVE-2024-6484', '3.4.1')]
        self.assertEqual((match.ai_verdict, match.confidence), ('', js_libraries.CONFIDENCE['filename']))

    def test_e1b_an_old_copy_past_the_read_limit_is_not_contradicted_by_the_new_one_before_it(self):
        from cveFeed import route_auth
        sub = self.host('big2.x.test', ['jQuery:1.8.3', 'jQuery:3.7.1'])
        page = ('<html><head><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script></head><body>' + self.FILLER +
                '<script src="/legacy/jquery-1.8.3.min.js"></script></body></html>')
        cut = page.encode()[:route_auth.ROUTE_SAMPLE_BYTES].decode('utf-8', 'ignore')
        self.read_root('big2.x.test', 200, cut, scripts={'https://big2.x.test/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        self.assertEqual(self.correlate(sub)[('big2.x.test', 'CVE-2020-11023', '1.8.3')].ai_verdict, '')
        # read whole (the route check reads a front page up to ROOT_READ_BYTES), the old copy is on the page: matched from its name
        self.read_root('big2.x.test', 200, page, scripts={'https://big2.x.test/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN},
                       bytes=len(page), read_limit=route_scanner.ROOT_READ_BYTES, truncated=False)
        match = self.correlate(sub)[('big2.x.test', 'CVE-2020-11023', '1.8.3')]
        self.assertEqual((match.ai_verdict, match.evidence['version_source']), ('', 'filename'))

    def test_e2_every_web_port_must_show_its_page_before_anything_is_absent(self):
        sub = self.host('app.x.test', ['jQuery:1.12.4'], ports=(80, 443))
        self.read_root('app.x.test', 200, '<html><body>It works!</body></html>', scheme='http')  # the default page on :80
        self.read_root('app.x.test', 302, '', location='/login')  # the application on :443 sends visitors to its own /login
        self.assertEqual(self.correlate(sub)[('app.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        # a stand-in on every port proves nothing either: a meta refresh, a maintenance page
        self.read_root('app.x.test', 200, '<meta http-equiv="refresh" content="0;url=/app/"><script src="/a.js"></script>')
        self.assertEqual(self.correlate(sub)[('app.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        self.read_root('app.x.test', 200, '<title>Down for maintenance</title><script src="/a.js"></script>', title='Down for maintenance')
        self.assertEqual(self.correlate(sub)[('app.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')

    def test_e3_another_librarys_own_ver_is_not_a_cache_buster(self):
        for name, prefix in (('pair.x.test', 'https://cdn.vendor-assets.test/js/'), ('pair2.x.test', '/assets/')):
            sub = self.host(name, ['jQuery:3.4.1', 'Bootstrap:3.4.1'])
            self.read_root(name, 200, f'<script src="{prefix}jquery.min.js?ver=3.4.1"></script><script src="{prefix}bootstrap.min.js?ver=3.4.1"></script>')
            found = self.correlate(sub)
            self.assertEqual(found[(name, 'CVE-2020-11023', '3.4.1')].ai_verdict, '', name)
            self.assertEqual(found[(name, 'CVE-2024-6484', '3.4.1')].ai_verdict, '', name)

    def test_e4_a_vouched_for_library_match_is_never_closed_by_a_page_reading(self):
        from django.contrib.auth import get_user_model
        from cveFeed.models import CVEMatch, FindingComment, Triage
        user = get_user_model().objects.create(username='reviewer')
        cases = {'assigned': lambda m: CVEMatch.objects.filter(pk=m.pk).update(assignee=user),
                 'ai-affected': lambda m: CVEMatch.objects.filter(pk=m.pk).update(ai_verdict='affected', ai_reason='Validated: file read'),
                 'commented': lambda m: FindingComment.objects.create(project=self.project, finding_kind='match', finding_id=m.pk, author=user, text='checking'),
                 'validation hit': lambda m: Triage.objects.filter(match=m).update(validation_status='hit'),
                 'confirmed': lambda m: Triage.objects.filter(match=m).update(classification='confirmed')}
        for label, vouch in cases.items():
            name = f'w{len(label)}{label[:3]}.x.test'.replace(' ', '')
            sub = self.host(name, ['jQuery:3.4.1'])
            match = self.correlate(sub)[(name, 'CVE-2020-11023', '3.4.1')]
            from cveFeed import triage
            triage.track(CVEMatch.objects.filter(pk=match.pk).select_related('cve_entry', 'subdomain__target_domain'))
            vouch(match)
            before = CVEMatch.objects.get(pk=match.pk).ai_verdict
            self.read_root(name, 200, CONTRA)  # the page's own jQuery file says 3.7.1
            after = self.correlate(sub)[(name, 'CVE-2020-11023', '3.4.1')]
            self.assertEqual(after.ai_verdict, before, label)
            from cveFeed.tasks import reconcile_library_provenance
            reconcile_library_provenance()
            self.assertEqual(CVEMatch.objects.get(pk=match.pk).ai_verdict, before, label)

    def test_e5_a_closure_about_one_hosts_page_is_never_shared_and_reopens(self):
        from cveFeed.models import CVEEntry, CVEMatch, MatchVerdict, TriageVerdict
        from cveFeed.tasks import reconcile_library_provenance
        kev = CVEEntry.objects.create(cve_id='CVE-2099-0001', kev=True, cvss=9.0, published_at=timezone.now(),
                                      affected=[{'vendor': 'jquery', 'product': 'jquery'}])  # no version bound: an unbounded KEV candidate
        self.entries = [kev]
        a = self.host('a.x.test', ['jQuery:1.12.4'])
        self.correlate(a)
        self.redirect_away('a.x.test')
        self.assertEqual(reconcile_library_provenance()['closed'], 1)
        closed = CVEMatch.objects.get(subdomain=a)
        self.assertTrue(closed.ai_reason.startswith(js_libraries.LIBRARY_CLOSED))
        self.assertFalse(MatchVerdict.objects.filter(ai_reason__startswith=js_libraries.LIBRARY_CLOSED).exists())
        self.assertFalse(TriageVerdict.objects.filter(reason__startswith=js_libraries.LIBRARY_CLOSED).exists())
        b = self.host('b.x.test', ['jQuery:1.12.4'])  # another host (any project) with the same version: its own page was never read
        self.assertEqual(self.correlate(b)[('b.x.test', 'CVE-2099-0001', '1.12.4')].ai_verdict, '')
        self.read_root('a.x.test', 200, '<script src="/js/jquery-1.12.4.min.js"></script>')  # the page now loads it
        reopened = self.correlate(a)[('a.x.test', 'CVE-2099-0001', '1.12.4')]
        self.assertEqual((reopened.pk, reopened.ai_verdict), (closed.pk, ''))
        self.assertIn('library_reopened_at', reopened.evidence)

    def test_a_match_reopens_when_only_its_confidence_comes_back(self):
        from cveFeed.models import CVEMatch
        sub = self.host('c.x.test', ['jQuery:3.4.1'])
        self.read_root('c.x.test', 200, '<script src="/js/jquery-3.4.1.min.js"></script>')  # a fresh reading: the page loads it
        match = self.correlate(sub)[('c.x.test', 'CVE-2020-11023', '3.4.1')]
        # closed by the page with every field as correlation computes it again (the closure kept the confidence)
        CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='not_affected', ai_reason=js_libraries.closed_reason('the front page loads no jQuery'))
        reopened = self.correlate(sub)[('c.x.test', 'CVE-2020-11023', '3.4.1')]
        self.assertEqual((reopened.ai_verdict, reopened.ai_reason), ('', ''))

    def test_a_stale_or_vanished_port_reading_closes_nothing_and_a_retired_404_root_still_counts(self):
        from datetime import timedelta
        sub = self.host('old.x.test', ['jQuery:1.12.4'])
        self.read_root('old.x.test', 200, CONTRA)
        RouteAuth.objects.filter(host='old.x.test').update(checked_at=timezone.now() - timedelta(days=js_libraries.FRESH_DAYS + 1))
        self.assertEqual(self.correlate(sub)[('old.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')  # too old to speak for the page
        gone = self.host('gone.x.test', ['jQuery:1.12.4'])
        self.read_root('gone.x.test', 200, CONTRA, scheme='http')  # a port the host no longer has
        self.assertEqual(self.correlate(gone)[('gone.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        # a front page that answered 200 once and now answers 404 is retired, and the hosted 404 page it serves is the page now
        hosted = self.host('hosted.x.test', ['jQuery:1.12.4', 'jQuery:1.11.2'])
        self.read_root('hosted.x.test', 404, '<script src="/hs/jquery-1.11.2.js"></script><script src="/site.js?ver=1.12.4"></script>',
                       scripts={'https://hosted.x.test/hs/jquery-1.11.2.js': oracle('jquery-1.11.2-head.js')})
        RouteAuth.objects.filter(host='hosted.x.test').update(retired_at=timezone.now(), previous_state='open')
        found = self.correlate(hosted)
        self.assertEqual(found[('hosted.x.test', 'CVE-2020-11023', '1.11.2')].evidence['version_source'], 'body')
        self.assertTrue(all(m.ai_verdict != 'not_affected' or m.matched_version == '1.12.4' for m in found.values()))
        self.assertEqual(found[('hosted.x.test', 'CVE-2020-11023', '1.11.2')].ai_verdict, '')

    def test_the_version_a_file_states_wins_over_a_name_version_whichever_technology_was_stored_first(self):
        # One match is kept per product on a host, the strongest sighting. The file-stated 1.11.2 and the query-string 1.12.4 tied, and the
        # one the database returned last won: the test above failed about 1 run in 100, by the ids the technologies happened to get. Both
        # orders of storing them, and so both orders of reading them back, must keep the version the page's file states.
        for host, techs in (('first.x.test', ['jQuery:1.11.2', 'jQuery:1.12.4']), ('second.x.test', ['jQuery:1.12.4', 'jQuery:1.11.2'])):
            sub = self.host(host, techs)
            page = '<script src="/hs/jquery-1.11.2.js"></script><script src="/site.js?ver=1.12.4"></script>'
            self.read_root(host, 200, page, scripts={f'https://{host}/hs/jquery-1.11.2.js': oracle('jquery-1.11.2-head.js')})
            for _ in range(2):  # and the second pass, over the rows the first wrote
                found = self.correlate(sub)
                self.assertEqual(found[(host, 'CVE-2020-11023', '1.11.2')].evidence['version_source'], 'body', host)
                self.assertNotIn((host, 'CVE-2020-11023', '1.12.4'), found, host)

    def test_a_library_match_that_reopened_lately_is_not_closed_again_on_the_pages_word(self):
        from cveFeed.models import CVEMatch
        from cveFeed.tasks import reconcile_library_provenance
        sub = self.host('flap.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('flap.x.test', 200, CONTRA)  # variant A: the page's one jQuery file says 3.7.1: informs, never closes
        self.assertEqual(self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        self.read_root('flap.x.test', 200, '<script src="/js/jquery-1.12.4.min.js"></script>')  # variant B of the page loads 1.12.4
        self.assertEqual(self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        self.read_root('flap.x.test', 200, CONTRA)  # variant A again, reopened lately: held, the page alternates
        held = self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual(held.ai_verdict, '')
        reconcile_library_provenance()
        self.assertEqual(CVEMatch.objects.get(pk=held.pk).ai_verdict, '')
        # ... a host that now only redirects elsewhere is not a page that alternates: that still closes
        self.host('elsewhere.x.test', [])  # an alias closes only to a host the project inventories
        self.read_root('flap.x.test', 301, '', location='https://elsewhere.x.test/')
        self.assertEqual(self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_library_sweep_looks_only_at_open_matches_in_bounded_batches(self):
        from cveFeed.models import BackgroundCursor, CVEMatch
        from cveFeed.tasks import reconcile_library_provenance
        subs = [self.host(f'h{i}.x.test', ['jQuery:1.12.4']) for i in range(4)]
        self.correlate(*subs)
        for sub in subs:
            self.redirect_away(sub.name)
        first = reconcile_library_provenance(limit=2)
        self.assertEqual((first['reviewed'], first['closed'], first['closed_by_reason']), (2, 2, {'redirect_alias': 2}))
        second = reconcile_library_provenance(limit=2)
        self.assertEqual(second['closed'], 2)
        self.assertEqual(CVEMatch.objects.filter(subdomain__in=subs, ai_verdict='not_affected').count(), 4)
        self.assertEqual(reconcile_library_provenance(limit=2)['reviewed'], 0)  # closed ones are never looked at again
        # out of time: the next run starts where this one stopped
        more = [self.host(f'k{i}.x.test', ['jQuery:1.12.4']) for i in range(3)]
        self.correlate(*more)
        for sub in more:
            self.redirect_away(sub.name)
        BackgroundCursor.objects.filter(lane='library_provenance').update(last_pk=0)
        ticks = iter([0, 0, 0, 1000, 1000, 1000, 1000])
        stopped = reconcile_library_provenance(limit=10, seconds=10, clock=lambda: next(ticks))
        self.assertEqual(stopped['closed'], 2)
        self.assertEqual(reconcile_library_provenance(limit=10)['closed'], 1)


class LibrarySweepCostTests(ReviewScenarioBase):
    """The sweep reads each host's page once a run for all its matches, and a match costs a few queries of its own (who vouches for it)."""

    def queries(self, hosts, tag):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        from cveFeed.models import BackgroundCursor
        from cveFeed.tasks import reconcile_library_provenance
        subs = [self.host(f'{tag}{i}.x.test', ['jQuery:1.12.4', 'Bootstrap:3.3.7']) for i in range(hosts)]
        self.correlate(*subs)  # no page read: nothing closes, every match is looked at
        BackgroundCursor.objects.filter(lane='library_provenance').delete()
        with CaptureQueriesContext(connection) as captured:
            result = reconcile_library_provenance(limit=500)
        self.assertEqual(result['closed'], 0)
        return len(captured.captured_queries), result['libraries']

    def test_a_handful_of_queries_per_match_and_none_per_match_for_the_page(self):
        few, looked_few = self.queries(2, 'a')
        many, looked_many = self.queries(8, 'b')
        per_match = (many - few) / (looked_many - looked_few)
        self.assertLessEqual(per_match, 6)  # measured: 4.0 (who vouches for it: 3; its host's page, read once for both its matches: 1)


class RereviewScenarioTests(ReviewScenarioBase):
    """The re-review of #388 (X1 to X9): what the parse could not see, stale readings, inline libraries, ordinary stale closures."""

    def test_x1_scripts_past_the_parse_limit_make_the_page_not_whole(self):
        sub = self.host('many.x.test', ['Bootstrap:3.4.1', 'jQuery:1.8.3'])
        self.correlate(sub)
        filler = ''.join(f'<script src="/wp-content/plugins/p{i}/a.js?ver=2.{i}"></script>' for i in range(85))
        page = ('<html><head><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script></head><body>' + filler +
                '<script src="/js/bootstrap.min.js"></script><script src="/legacy/jquery-1.8.3.min.js"></script></body></html>')
        self.read_root('many.x.test', 200, page, scripts={'https://many.x.test/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN},
                       bytes=len(page), read_limit=route_scanner.ROOT_READ_BYTES, truncated=False)
        self.assertTrue(RouteAuth.objects.get(host='many.x.test').evidence['script_page']['capped'])
        found = self.correlate(sub)
        self.assertEqual(found[('many.x.test', 'CVE-2024-6484', '3.4.1')].ai_verdict, '')
        self.assertEqual(found[('many.x.test', 'CVE-2020-11023', '1.8.3')].ai_verdict, '')

    def test_x2_a_stale_reading_neither_reopens_nor_starts_the_damping(self):
        from datetime import timedelta
        from cveFeed.models import CVEMatch
        from cveFeed.tasks import reconcile_library_provenance
        sub = self.host('st.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.redirect_away('st.x.test')
        closed = self.correlate(sub)[('st.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual(closed.ai_verdict, 'not_affected')
        RouteAuth.objects.filter(host='st.x.test').update(checked_at=timezone.now() - timedelta(days=js_libraries.FRESH_DAYS + 1))
        stale = self.correlate(sub)[('st.x.test', 'CVE-2020-11023', '1.12.4')]  # the periodic correlation, no scan for 9 days
        self.assertEqual(stale.ai_verdict, 'not_affected')
        self.assertNotIn('library_reopened_at', stale.evidence)
        self.redirect_away('st.x.test')  # the next scan reads the same page
        self.correlate(sub)
        reconcile_library_provenance()
        self.assertEqual(CVEMatch.objects.get(pk=closed.pk).ai_verdict, 'not_affected')

    def test_x5_a_library_pasted_into_the_page_is_on_the_page(self):
        sub = self.host('inl.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('inl.x.test', 200, '<script>/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */!function(a,b){}</script>'
                                          '<script src="/app.js"></script>')
        self.assertEqual(RouteAuth.objects.get(host='inl.x.test').evidence['script_page']['inline'], [{'library': 'jquery', 'version': '1.12.4'}])
        self.assertEqual(self.correlate(sub)[('inl.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')

    def test_x6_an_unclosed_comment_hides_what_follows_so_the_page_is_not_whole(self):
        sub = self.host('cm.x.test', ['Bootstrap:3.4.1'])
        self.correlate(sub)
        self.read_root('cm.x.test', 200, '<script src="/a.js"></script><style>/* <!-- */ body{}</style><script src="/js/bootstrap.min.js"></script>')
        self.assertTrue(RouteAuth.objects.get(host='cm.x.test').evidence['script_page']['capped'])
        self.assertEqual(self.correlate(sub)[('cm.x.test', 'CVE-2024-6484', '3.4.1')].ai_verdict, '')

    def test_x8_a_vouched_for_match_whose_version_left_the_host_closes_as_it_always_did(self):
        from django.contrib.auth import get_user_model
        from cveFeed.models import CVEMatch
        user = get_user_model().objects.create(username='owner8')
        for label, vouch in (('assigned', {'assignee': user}), ('ai', {'ai_verdict': 'affected', 'ai_reason': 'AI: affected'})):
            name = f'up{label}.x.test'
            sub = self.host(name, ['jQuery:1.12.4'])
            match = self.correlate(sub)[(name, 'CVE-2020-11023', '1.12.4')]
            CVEMatch.objects.filter(pk=match.pk).update(**vouch)
            sub.technologies.clear()
            sub.technologies.add(Technology.objects.get_or_create(name='jQuery:3.7.1')[0])  # the owner upgraded jQuery
            self.correlate(sub)
            after = CVEMatch.objects.get(pk=match.pk)
            self.assertEqual(after.ai_verdict, 'not_affected', label)
            self.assertTrue(after.ai_reason.startswith('Closed automatically: the host no longer matches'), label)

    def test_x9_a_whole_page_on_one_port_does_not_speak_for_a_login_on_another(self):
        sub = self.host('mix.x.test', ['jQuery:1.12.4'], ports=(80, 443))
        self.correlate(sub)
        self.read_root('mix.x.test', 200, '<html><script src="/site.js"></script></html>', scheme='http')
        self.read_root('mix.x.test', 302, '', location='/login')
        self.assertEqual(self.correlate(sub)[('mix.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')

    def test_a_page_that_loads_no_script_is_a_stand_in(self):
        from cveFeed import route_auth
        _state, evidence = route_auth.classify({'status': 200, 'url': 'https://x.test/', 'content_type': 'text/html', 'headers': {},
                                                'body': '<html><body><h1>Welcome</h1><p>' + 'text ' * 2000 + '</p></body></html>'})
        self.assertTrue(evidence['script_page']['stub'])

    def test_the_sweep_rolls_its_cursor_back_to_the_first_match_it_did_not_look_at(self):
        from cveFeed.models import BackgroundCursor
        from cveFeed.tasks import reconcile_library_provenance
        subs = [self.host(f'r{i}.x.test', ['jQuery:1.12.4']) for i in range(3)]
        found = self.correlate(*subs)
        for sub in subs:
            self.redirect_away(sub.name)
        ids = sorted(m.pk for m in found.values())
        BackgroundCursor.objects.update_or_create(lane='library_provenance', defaults={'last_pk': ids[0] - 1})
        ticks = iter([0, 0, 1000, 1000, 1000])
        self.assertEqual(reconcile_library_provenance(limit=10, seconds=10, clock=lambda: next(ticks))['closed'], 1)
        self.assertEqual(BackgroundCursor.objects.get(lane='library_provenance').last_pk, ids[1] - 1)
        second = reconcile_library_provenance(limit=1)
        self.assertEqual((second['reviewed'], second['closed']), (1, 1))
        self.assertEqual(BackgroundCursor.objects.get(lane='library_provenance').last_pk, ids[1])
        self.assertEqual(reconcile_library_provenance(limit=1)['closed'], 1)

    def test_seeding_refuses_a_closure_about_one_hosts_page(self):
        from types import SimpleNamespace
        row = {'source': 'tech', 'evidence': {'source': 'tech'}, 'version_in_range': True, 'distro_status': 'no_data'}
        verdict = SimpleNamespace(ai_verdict='not_affected', ai_reason=js_libraries.closed_reason('the front page loads no jQuery'), ai_model='x')
        self.assertIsNone(correlation._seedable(verdict, {**row, 'version_in_range': None}))
        self.assertIsNone(correlation._seedable(verdict, row))


class FrontPageReadTests(SimpleTestCase):
    def test_hostile_front_pages_of_the_full_read_size_stay_fast(self):
        import time
        from cveFeed import route_auth
        n = route_scanner.ROOT_READ_BYTES
        bodies = {'meta without an end': '<meta ' * (n // 6), 'csrf meta without an end': '<meta name="csrf ' * (n // 17),
                  'meta refresh': '<meta http-equiv=refresh ' * (n // 25), 'script openings': '<script ' * (n // 8),
                  'inputs': '<input ' * (n // 7), 'comment openings': '<!--<script src=/a.js>' * (n // 22),
                  'long attributes': ('<script ' + 'a=' * 900 + '>') * (n // 1810), 'emails': ('a' * 64 + '@') * (n // 65)}
        for path in ('/', '/login'):
            for label, body in bodies.items():
                started = time.perf_counter()
                route_auth.analyse({'url': 'https://x.test' + path, 'status': 200, 'content_type': 'text/html', 'headers': {}, 'body': body,
                                    'bytes': len(body), 'read_limit': n, 'title': route_auth.page_title(body)})
                self.assertLess(time.perf_counter() - started, 3.0, (path, label))

    def test_the_csrf_meta_token_is_still_taken_out(self):
        from cvengine_scanner import soft404
        page = '<meta name="csrf-token" content="abc123XYZ"><meta name="description" content="keep me">'
        self.assertEqual(soft404.normalise(page), '<meta name="csrf-token" content=""><meta name="description" content="keep me">')
