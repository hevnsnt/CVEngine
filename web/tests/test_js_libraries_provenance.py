"""Where a JavaScript library version came from decides how far a CVE match may trust it (cveFeed.js_libraries, correlation, probes).

Two leaks the client-side design review found after the 1.3.2 re-cut, on live data:

* a version another fingerprinting tool stored (httpx/Wappalyzer, the nuclei tech pass, bbot: technology source ``scan``) bypassed the
  ladder: ``HostLibraries.judge`` returned ``version_source: other`` with no confidence cap, so a theme's ``jquery.x.js?ver=1.0.4`` read by
  Wappalyzer matched CVE-2020-11023 at 0.95 next to the page's real jQuery 3.7.1;
* a host that only redirects (five ``*.mybluegrace.com`` names answer a 301 to ``mybluegrace.com``) was given the libraries of the page it
  redirects to: the probes follow the redirect and recorded the target's scripts on the alias, and correlation matched them there.
"""
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, js_libraries, match_policy, probes
from cveFeed.models import ProbeObservation, RouteAuth
from startScan.models import Subdomain, Technology
from tests.test_js_library_versions import JQ_371_MIN, NoCache, read
from tests.test_probes import answers, page
from tests.test_route_auth import RouteFixture


class FakeCVE:
    def __init__(self, cid, affected, kev=True):
        self.id, self.cve_id, self.affected, self.kev = cid, f'CVE-2020-{cid}', affected, kev


JQUERY_XSS = FakeCVE(11023, [{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]}])
NGINX_BUG = FakeCVE(42945, [{'vendor': 'f5', 'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.27.0'}]}])
WORDPRESS_BUG = FakeCVE(77001, [{'vendor': 'wordpress', 'product': 'wordpress', 'ranges': [{'introduced': '7.0.0', 'fixed': '7.1.5'}]}])
CVES = (JQUERY_XSS, NGINX_BUG, WORDPRESS_BUG)

# the live WordPress 7.1.x page: core jQuery 3.7.1 and a theme plugin whose cache-buster Wappalyzer reads as "jQuery 1.0.4"
WORDPRESS_PAGE = ('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                  '<script src="/wp-content/themes/acme/js/jquery.fancybox.js?ver=1.0.4"></script>')
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


class AnotherToolsVersionTests(Hosts):
    """1: a version the page's own files did not state stays at most a file-name hint (0.4), whichever tool stored it."""

    def records(self):
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            return read(WORDPRESS_PAGE, {'/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN, '/wp-content/themes/acme/js/jquery.fancybox.js': FANCYBOX})

    def test_a_wappalyzer_version_beside_the_files_reading_is_capped_at_the_file_name_confidence(self):
        records = self.records()
        self.assertEqual([c['version'] for c in records['jquery']['copies']], ['3.7.1'])  # the plugin is not a copy of jQuery
        self.root('www.rt.test', evidence={'libraries': records})
        found = self.matches('www.rt.test', 'jQuery:3.7.1', 'jQuery:1.0.4', 'nginx:1.24.0', 'WordPress:7.1.4')
        match = found[('jquery', '1.0.4')]
        self.assertEqual(match['evidence']['version_source'], 'other')
        self.assertEqual(match['confidence'], js_libraries.CONFIDENCE['filename'])
        self.assertEqual(match['evidence']['version_confidence'], js_libraries.CONFIDENCE['filename'])
        self.assertIn('not read from', match['evidence']['version_note'])
        self.assertEqual([c['version'] for c in match['evidence']['copies']], ['3.7.1'])  # what the page's files say is shown beside it
        # and it can never be hard evidence: the heat stays version-only
        self.assertFalse(match_policy.has_hard_evidence('tech', match['evidence']))
        self.assertTrue(match_policy.version_only('tech', match['evidence'], match['version_in_range']))
        # server-side products on the same host are not touched
        self.assertEqual(found[('nginx', '1.24.0')]['confidence'], 0.95)
        self.assertNotIn('version_source', found[('nginx', '1.24.0')]['evidence'])
        self.assertEqual(found[('wordpress', '7.1.4')]['confidence'], 0.95)

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
        self.root('blog.rt.test', 301, redirect_to='https://rt.test/')
        self.root('blog.rt.test', 403, scheme='http')
        self.assertIn(('jquery', '3.2.1'), self.matches('blog.rt.test', 'jQuery:3.2.1'))

    def test_the_alias_rule_is_pure(self):
        alias = js_libraries.redirect_alias_of
        self.assertEqual(alias([('https://a.test/', 301, 'https://b.test/')], 'a.test'), 'b.test')
        self.assertEqual(alias([('http://a.test/', 301, 'https://a.test/'), ('https://a.test/', 308, '//B.test./x')], 'a.test'), 'b.test')
        self.assertEqual(alias([('http://a.test/', 301, 'https://a.test/')], 'a.test'), '')
        self.assertEqual(alias([('https://a.test/', 301, 'https://b.test/'), ('http://a.test/', 200, '')], 'a.test'), '')
        self.assertEqual(alias([('https://a.test/', None, '')], 'a.test'), '')
        self.assertEqual(alias([], 'a.test'), '')


class RedirectProbeTests(NoCache, SimpleTestCase):
    """2: the probes follow a redirect inside the host's group (apex and www); what the page they land on loads is not the alias's."""

    TARGET = {'/': page(body='<script src="/js/jquery-3.2.1.min.js"></script><script src="/js/bootstrap.min.js?ver=1.0.4"></script>',
                        url='https://rt.test/', headers={'Server': 'nginx/1.24.0'}),
              '/js/jquery-3.2.1.min.js': page(body='/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */',
                                              url='https://rt.test/js/jquery-3.2.1.min.js')}

    def run_probe(self, probe_id, base, table):
        return probes.run_http_probe(probe_id, base, {'blog.rt.test', 'rt.test', 'www.rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_the_libraries_probe_records_nothing_for_a_host_that_redirected_elsewhere(self):
        self.assertEqual([o for o in self.run_probe('html-libraries', 'https://blog.rt.test', self.TARGET) if o['kind'] == 'version'], [])

    def test_the_headers_probe_records_no_script_versions_for_a_host_that_redirected_elsewhere(self):
        found = self.run_probe('headers-root', 'https://blog.rt.test', self.TARGET)
        self.assertEqual([o for o in found if js_libraries.is_library(o['product'])], [])
        self.assertIn(('nginx', '1.24.0'), {(o['product'], o['version']) for o in found if o['kind'] == 'version'})  # the answer's own headers stay

    def test_the_host_the_page_belongs_to_records_its_libraries(self):
        found = self.run_probe('html-libraries', 'https://rt.test', self.TARGET)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])
        found = self.run_probe('headers-root', 'https://rt.test', self.TARGET)
        self.assertIn(('jQuery', '3.2.1'), {(o['product'], o['version']) for o in found})

    def test_through_the_real_redirect_following_fetch(self):
        def probe_url(url, **_kw):
            if url == 'https://blog.rt.test/':
                return {'status': 301, 'location': 'https://rt.test/', 'body': '', 'url': url, 'headers': {}}
            path = '/' + url.split('://', 1)[1].split('/', 1)[1]
            return {**self.TARGET.get(path, page(404, body='not found')), 'url': url}

        def get(url, **kw):
            return probes.fetch(url, probe=probe_url, sleep=lambda s: None, allowed={'blog.rt.test', 'rt.test', 'www.rt.test'})
        with mock.patch.object(probes, '_permitted', return_value=True):
            alias = probes.run_http_probe('html-libraries', 'https://blog.rt.test', set(), get=get, sleep=lambda s: None)
            target = probes.run_http_probe('html-libraries', 'https://rt.test', set(), get=get, sleep=lambda s: None)
        self.assertEqual([o for o in alias if o['kind'] == 'version'], [])
        self.assertEqual([(o['product'], o['version']) for o in target if o['version']], [('jQuery', '3.2.1')])

    def test_a_redirect_inside_the_same_host_still_records_the_page(self):
        table = {'/': {**self.TARGET['/'], 'final_url': 'https://blog.rt.test/en/', 'url': 'https://blog.rt.test/en/'},
                 '/js/jquery-3.2.1.min.js': self.TARGET['/js/jquery-3.2.1.min.js']}
        found = self.run_probe('html-libraries', 'https://blog.rt.test', table)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])
