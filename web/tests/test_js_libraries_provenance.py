"""Where a JavaScript library version came from decides how far a CVE match may trust it (cveFeed.js_libraries, correlation, probes).

Two leaks the client-side design review found after the 1.3.2 re-cut, on live data:

* a version another fingerprinting tool stored (httpx/Wappalyzer, the nuclei tech pass, bbot: technology source ``scan``) bypassed the
  ladder: ``HostLibraries.judge`` returned ``version_source: other`` with no confidence cap, so a theme's ``jquery.x.js?ver=1.0.4`` read by
  Wappalyzer matched CVE-2020-11023 at 0.95 next to the page's real jQuery 3.7.1;
* a host that only redirects (five ``*.mybluegrace.com`` names answer a 301 to ``mybluegrace.com``) was given the libraries of the page it
  redirects to: the probes follow the redirect and recorded the target's scripts on the alias, and correlation matched them there.
"""
import os
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, js_libraries, match_policy, probes
from cveFeed.models import ProbeObservation, RouteAuth
from startScan.models import Subdomain, Technology
from tests.test_js_library_versions import JQ_371_MIN, PAGE_URL, NoCache, read
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

    def page_evidence(self, records=None, page=WORDPRESS_PAGE):
        """What the route check stores for a front page it read: the library records and the script_page marker (route_auth.classify)."""
        from cveFeed import route_auth
        _state, evidence = route_auth.classify({'status': 200, 'body': page, 'url': PAGE_URL, 'content_type': 'text/html', 'headers': {}})
        evidence.pop('page_scripts', None)
        return {**evidence, **({'libraries': records} if records else {})}

    def test_wordpress_core_jquery_read_from_its_file_closes_the_themes_cache_buster_read_by_a_technology_scan(self):
        # the live case: WordPress 7.1.x loads core jQuery 3.7.1 (its file says so); Wappalyzer read a theme script's ?ver=1.0.4 as jQuery
        records = self.records()
        self.assertEqual([c['version'] for c in records['jquery']['copies']], ['3.7.1'])  # the plugin is not a copy of jQuery
        self.root('www.rt.test', evidence=self.page_evidence(records))
        found = self.matches('www.rt.test', 'jQuery:3.7.1', 'jQuery:1.0.4', 'jQuery:3.2.1', 'nginx:1.24.0', 'WordPress:7.1.4')
        self.assertNotIn(('jquery', '1.0.4'), found)
        self.assertNotIn(('jquery', '3.2.1'), found)
        skip, evidence, _cap = js_libraries.HostLibraries.for_subdomain(self.sub('www.rt.test')).judge('jQuery', '1.0.4')
        self.assertTrue(skip)
        self.assertEqual(evidence['reason'], "the page's own scripts say jQuery 3.7.1; the 1.0.4 came from a technology scan")
        # server-side products on the same host are not touched
        self.assertEqual(found[('nginx', '1.24.0')]['confidence'], 0.95)
        self.assertNotIn('version_source', found[('nginx', '1.24.0')]['evidence'])
        self.assertEqual(found[('wordpress', '7.1.4')]['confidence'], 0.95)

    def test_a_front_page_that_loads_no_such_script_closes_a_technology_scans_version(self):
        self.root('www.rt.test', evidence=self.page_evidence(page='<script src="/app.js?ver=1.0.4"></script><script src="/site.js"></script>'))
        libraries = js_libraries.HostLibraries.for_subdomain(self.sub('www.rt.test'))
        self.assertEqual(self.matches('www.rt.test', 'jQuery:3.2.1', 'jQuery:1.0.4'), {})
        self.assertEqual(libraries.judge('jQuery', '3.2.1')[1]['reason'], 'the front page loads no jQuery script; the 3.2.1 came from a technology scan')
        self.assertIn('?ver= cache-buster', libraries.judge('jQuery', '1.0.4')[1]['reason'])

    def test_a_cache_buster_on_the_page_closes_the_version_even_where_no_file_stated_one(self):
        page = '<script src="/js/jquery.min.js"></script><script src="/wp-content/themes/acme/js/theme.js?ver=1.0.4"></script>'
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            records = read(page, {'/js/jquery.min.js': 'no banner here'})  # the jQuery file states no version
        self.root('www.rt.test', evidence=self.page_evidence(records, page=page))
        self.assertNotIn(('jquery', '1.0.4'), self.matches('www.rt.test', 'jQuery:1.0.4', 'jQuery:3.2.1'))
        match = self.matches('www.rt.test', 'jQuery:3.2.1')[('jquery', '3.2.1')]  # not stated anywhere, not a cache-buster: a capped candidate
        self.assertEqual((match['confidence'], match['evidence']['version_source']), (js_libraries.CONFIDENCE['filename'], 'other'))
        self.assertFalse(match_policy.has_hard_evidence('tech', match['evidence']))
        self.assertTrue(match_policy.version_only('tech', match['evidence'], match['version_in_range']))

    def test_a_shadowed_copy_a_technology_scan_named_stays_a_capped_candidate(self):
        page = '<script src="/assets/jquery-3.4.1.min.js"></script><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            records = read(page, {'/assets/jquery-3.4.1.min.js': '/*! jQuery v3.4.1 | (c) JS Foundation */', '/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        self.root('www.rt.test', evidence=self.page_evidence(records, page=page))
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
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='blog.rt.test', path='/', url='https://blog.rt.test:8443/',
                                 auth_state='redirect', http_status=302, redirect_to='https://rt.test/', checked_at=timezone.now())
        self.assertEqual(self.matches('blog.rt.test', 'jQuery:3.2.1'), {})  # every web port redirects away: an alias

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
        RouteAuth.objects.filter(host='blog.rt.test').update(http_status=200, redirect_to='', auth_state='open')  # it serves a page now
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
        self.assertEqual(alias(away + [('https://a.test:8443/', 302, 'https://b.test/')], 'a.test', ['https://a.test', 'https://a.test:8443']),
                         'b.test')


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

    def test_the_headers_probe_records_nothing_of_the_page_another_host_served(self):
        found = self.run_probe('headers-root', 'https://blog.rt.test', self.TARGET)
        self.assertEqual([o for o in found if js_libraries.is_library(o['product'])], [])
        self.assertNotIn('nginx', {o['product'] for o in found})  # the target's Server header is the target's, too

    def test_the_host_the_page_belongs_to_records_its_libraries(self):
        found = self.run_probe('html-libraries', 'https://rt.test', self.TARGET)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])
        found = self.run_probe('headers-root', 'https://rt.test', self.TARGET)
        self.assertIn(('jQuery', '3.2.1'), {(o['product'], o['version']) for o in found})

    def test_through_the_real_redirect_following_fetch(self):
        def probe_url(url, **_kw):
            if url == 'https://blog.rt.test/':
                return {'status': 301, 'location': 'https://rt.test/', 'body': '', 'url': url, 'headers': {'server': 'cloudflare'},
                        'server': 'cloudflare', 'powered_by': '', 'content_type': 'text/html', 'title': '301 Moved Permanently'}
            path = '/' + url.split('://', 1)[1].split('/', 1)[1]
            return {**self.TARGET.get(path, page(404, body='not found')), 'url': url}

        def get(url, **kw):
            return probes.fetch(url, probe=probe_url, sleep=lambda s: None, allowed={'blog.rt.test', 'rt.test', 'www.rt.test'})
        with mock.patch.object(probes, '_permitted', return_value=True):
            alias = probes.run_http_probe('html-libraries', 'https://blog.rt.test', set(), get=get, sleep=lambda s: None)
            target = probes.run_http_probe('html-libraries', 'https://rt.test', set(), get=get, sleep=lambda s: None)
        self.assertEqual([o for o in alias if o['kind'] == 'version'], [])
        self.assertEqual([(o['product'], o['version']) for o in target if o['version']], [('jQuery', '3.2.1')])
        with mock.patch.object(probes, '_permitted', return_value=True):
            headers = probes.run_http_probe('headers-root', 'https://blog.rt.test', set(), get=get, sleep=lambda s: None)
        products = {o['product'] for o in headers if o['kind'] == 'version'}
        self.assertIn('Cloudflare', products)  # what the alias's own redirect answer says about itself stays
        self.assertFalse(products & {'nginx', 'jQuery', 'Bootstrap'}, products)  # the page it leads to is not its

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
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            records = read(WORDPRESS_PAGE, {'/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN, '/wp-content/themes/acme/js/jquery.fancybox.js': FANCYBOX})
        evidence = AnotherToolsVersionTests.page_evidence(self, records)
        self.root('www.rt.test', evidence=evidence)

    def correlate(self):
        from cveFeed.models import CVEMatch
        index = correlation.build_product_index([self.entry])
        correlation.correlate_subdomain(Subdomain.objects.prefetch_related('technologies').get(pk=self.sub_row.pk), index, {self.entry.id: self.entry})
        return CVEMatch.objects.get(subdomain=self.sub_row, cve_entry=self.entry)

    def test_the_next_correlation_closes_a_technology_scan_match_the_page_contradicts(self):
        before = self.correlate()
        self.assertEqual((before.ai_verdict, before.confidence), ('', js_libraries.CONFIDENCE['filename']))  # page never read: capped
        self.wordpress_root()
        after = self.correlate()
        self.assertEqual(after.ai_verdict, 'not_affected')
        self.assertEqual(after.ai_reason, js_libraries.closed_reason("the page's own scripts say jQuery 3.7.1; the 1.0.4 came from a technology scan"))

    def stored(self, **fields):
        from cveFeed.models import CVEMatch
        return CVEMatch.objects.create(cve_entry=self.entry, subdomain=self.sub_row, source='tech', matched_product='jquery', matched_version='1.0.4',
                                       version_in_range=True, confidence=0.95, scan_history=self.scan_obj,
                                       evidence={'source': 'tech', 'source_id': self.tech.id, 'raw_version': '1.0.4'}, **fields)

    def test_the_periodic_reconcile_sweep_closes_a_stored_match_without_a_rescan(self):
        from cveFeed.models import CVEMatch, Triage
        from cveFeed.tasks import reconcile_invalid_correlations
        match = self.stored()  # as 1.3.2 left it: technology source, confidence 0.95
        self.wordpress_root()
        reconcile_invalid_correlations(limit=100)
        match = CVEMatch.objects.get(pk=match.pk)
        self.assertEqual(match.ai_verdict, 'not_affected')
        self.assertIn("the page's own scripts say jQuery 3.7.1; the 1.0.4 came from a technology scan", match.ai_reason)
        self.assertEqual(Triage.objects.get(match=match).classification, 'not_applicable')

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

    def found(self, page, bodies, *names):
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            records = read(page, bodies)
        self.root('www.rt.test', evidence=AnotherToolsVersionTests.page_evidence(self, records, page=page))
        sub = self.sub('www.rt.test')
        for name in names:
            sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        cves = (self.BOOTSTRAP_XSS, self.LODASH_POLLUTION)
        rows = correlation.collect_subdomain_matches(Subdomain.objects.prefetch_related('technologies').get(pk=sub.pk),
                                                     correlation.build_product_index(cves), {c.id: c for c in cves})
        return {(r['matched_product'].lower(), r['matched_version']): r for r in rows}, js_libraries.HostLibraries.for_subdomain(sub)

    def test_bootstrap_and_lodash_versions_the_files_contradict_are_not_matched(self):
        page = '<script src="/js/bootstrap.min.js"></script><script src="/js/lodash.min.js"></script>'
        bodies = {'/js/bootstrap.min.js': '/*!\n  * Bootstrap v5.3.2 (https://getbootstrap.com/)\n  */',
                  '/js/lodash.min.js': '/**\n * @license\n * Lodash 4.17.21 <https://lodash.com/>\n */'}
        found, libraries = self.found(page, bodies, 'Bootstrap:3.3.7', 'Lodash:4.17.4', 'Bootstrap:5.3.2', 'Lodash:4.17.21')
        self.assertEqual(found, {})
        self.assertEqual(libraries.judge('Bootstrap', '3.3.7')[1]['reason'],
                         "the page's own scripts say Bootstrap 5.3.2; the 3.3.7 came from a technology scan")
        self.assertEqual(libraries.judge('Lodash', '4.17.4')[1]['reason'], "the page's own scripts say Lodash 4.17.21; the 4.17.4 came from a technology scan")

    def test_bootstrap_and_lodash_cache_busters_are_not_matched_and_their_own_files_still_are(self):
        page = ('<script src="/js/lodash.min.js"></script><script src="/js/bootstrap.min.js?ver=3.3.7"></script>'
                '<script src="/wp-content/themes/acme/js/theme.js?ver=4.17.4"></script>')
        bodies = {'/js/lodash.min.js': '/** @license lodash 4.17.4 */'}  # bootstrap.min.js could not be read
        found, libraries = self.found(page, bodies, 'Lodash:4.17.4', 'Bootstrap:3.3.7')
        # Lodash's own file says 4.17.4: proven, whatever a theme's cache-buster says; Bootstrap's own ?ver= alone proves nothing either way
        self.assertEqual(found[('lodash', '4.17.4')]['evidence']['version_source'], 'body')
        self.assertEqual(found[('bootstrap', '3.3.7')]['confidence'], js_libraries.CONFIDENCE['filename'])
        _skip, evidence, _cap = libraries.judge('Bootstrap', '4.17.4')
        self.assertIn('cache-buster', evidence['reason'])


ORACLE = os.path.join(os.path.dirname(__file__), 'fixtures', 'js_provenance')


def oracle(name):
    with open(os.path.join(ORACLE, name), encoding='utf-8') as handle:
        return handle.read()


class LiveSiteOracleTests(RouteFixture, TestCase):
    """The live case (2026-11-02, names replaced), replayed through the route check's page read, correlation and closure: a WordPress site
    whose core jQuery file says 3.7.1, five names that only redirect to it, and a hosted landing site whose "/" answers 404 but loads a
    real jQuery 1.11.2. Of the 19 stored matches, 18 close with a reason and exactly one stands: CVE-2020-11023 on the landing site."""

    HOSTS = {'bg.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'www.bg.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'bgu.bg.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'givinggrace.bg.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'blog.bg.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.2.1', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'careers.bg.test': ['Bootstrap:1.0.4', 'jQuery:1.0.4', 'jQuery:3.4.1', 'jQuery:3.7.1'],
             'info.bg.test': ['jQuery:1.11.2']}
    REDIRECTS = {'www.bg.test': 'https://bg.test/', 'bgu.bg.test': 'https://bg.test/', 'givinggrace.bg.test': 'https://bg.test/',
                 'blog.bg.test': 'https://bg.test/', 'careers.bg.test': 'https://bg.test/careers/working-at-acme/'}
    SCRIPTS = {'https://bg.test/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN,
               'https://bg.test/wp-includes/js/jquery/jquery-migrate.min.js': '/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation and other contributors */',
               'https://info.bg.test/hs/hsstatic/jquery-libs/static-1.4/jquery/jquery-1.11.2.js': oracle('jquery-1.11.2-head.js')}

    def setUp(self):
        super().setUp()
        from cveFeed.models import CVEEntry
        from targetApp.models import Domain
        from startScan.models import IpAddress, Port, ScanHistory
        self.site = Domain.objects.create(name='bg.test', project=self.project, insert_date=timezone.now())
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
        answers = {'bg.test': {'status': 200, 'body': oracle('wordpress-front-page.html'), 'title': 'Home'},
                   'info.bg.test': {'status': 404, 'body': oracle('hosted-404-front-page.html'), 'title': 'Page not found'}}
        answers.update({host: {'status': 301, 'location': target, 'body': '<html><head><title>301 Moved Permanently</title></head></html>'}
                        for host, target in self.REDIRECTS.items()})
        for host, answer in answers.items():
            url = f'https://{host}/'
            result = route_auth.analyse({'url': url, 'content_type': 'text/html', 'headers': {}, **answer})
            with mock.patch.object(js_libraries, '_cache', return_value=None):
                route_auth._read_scripts(result, probe, 0, project=self.project.id, reader=js_libraries.Reader(self.project.id),
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
        rows, is_open, closed = self.open_and_closed()
        self.assertEqual(len(rows), 19)
        self.assertEqual([(m.subdomain.name, m.cve_entry.cve_id, m.matched_version) for m in is_open], [('info.bg.test', 'CVE-2020-11023', '1.11.2')])
        survivor = is_open[0]
        if proven:  # correlated again after the page read: proven by the file's banner
            self.assertEqual((survivor.evidence.get('version_source'), survivor.confidence), ('body', 0.95))
        self.assertEqual(len(closed), 18)
        kinds = {}
        for m in closed:
            self.assertTrue(m.ai_reason.startswith(js_libraries.LIBRARY_CLOSED), m.ai_reason)
            kinds[js_libraries.closure_kind(m.ai_reason)] = kinds.get(js_libraries.closure_kind(m.ai_reason), 0) + 1
        self.assertEqual(kinds, closed_kinds)
        by_host = {(m.subdomain.name, m.cve_entry.cve_id): m.ai_reason for m in closed}
        self.assertIn("the page's own scripts say jQuery 3.7.1", by_host[('bg.test', 'CVE-2020-11023')])
        self.assertIn('cache-buster', by_host[('bg.test', 'CVE-2026-114538')])
        self.assertIn('only redirects to bg.test', by_host[('careers.bg.test', 'CVE-2020-11023')])

    def test_the_next_correlation_closes_eighteen_and_keeps_the_real_one(self):
        self.correlate()  # as stored before the fix: no front page read
        rows, is_open, _closed = self.open_and_closed()
        self.assertEqual((len(rows), len(is_open)), (19, 19))
        self.read_front_pages()
        self.correlate()
        self.assert_oracle({'redirect_alias': 15, 'contradicted_by_file': 2, 'cache_buster': 1})

    def test_the_reconcile_sweep_closes_the_same_eighteen_without_a_rescan(self):
        from cveFeed.tasks import reconcile_invalid_correlations
        self.correlate()
        self.read_front_pages()
        with self.assertLogs('cveFeed.tasks', level='INFO') as logs:
            result = reconcile_invalid_correlations(limit=100)
        self.assertEqual(result['closed_by_reason'], {'redirect_alias': 15, 'contradicted_by_file': 2, 'cache_buster': 1})
        self.assertIn('closed 18 of', '\n'.join(logs.output))
        self.assert_oracle({'redirect_alias': 15, 'contradicted_by_file': 2, 'cache_buster': 1}, proven=False)


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
    scripts sit 229 KB in. The route check reads a front page up to ROOT_READ_BYTES, so the whole page is known and every closure carries
    a true reason; read at the old 64 KiB, the page is truncated and proves no absence, so nothing on it closes."""

    CUT = None

    def read_front_pages(self):
        from cveFeed import route_auth
        cut = self.CUT or route_auth.ROOT_READ_BYTES

        def probe(url, **_kw):
            body = self.SCRIPTS.get(url.split('?', 1)[0])
            return ({'status': 200, 'body': body, 'url': url, 'content_type': 'application/javascript', 'headers': {}} if body is not None
                    else {'status': 404, 'body': 'not found', 'url': url, 'content_type': 'text/html', 'headers': {}})
        answers = {'bg.test': {'status': 200, **synthesized_page('wordpress', cut)},
                   'info.bg.test': {'status': 404, **synthesized_page('hosted_404', cut)}}
        answers.update({host: {'status': 301, 'location': target, 'body': '<html><head><title>301 Moved Permanently</title></head></html>'}
                        for host, target in self.REDIRECTS.items()})
        for host, answer in answers.items():
            url = f'https://{host}/'
            result = route_auth.analyse({'url': url, 'content_type': 'text/html', 'headers': {}, 'title': '', **answer})
            with mock.patch.object(js_libraries, '_cache', return_value=None):
                route_auth._read_scripts(result, probe, 0, project=self.project.id, reader=js_libraries.Reader(self.project.id),
                                         target=self.site)
            RouteAuth.objects.create(project=self.project, domain=self.site, host=host, path='/', url=url, auth_state=result['state'],
                                     http_status=answer['status'], redirect_to=result['evidence'].get('redirect_to', ''),
                                     evidence=result['evidence'], checked_at=timezone.now())

    def test_every_closure_on_the_whole_page_says_what_the_page_really_shows(self):
        self.correlate()
        self.read_front_pages()
        self.correlate()
        self.assert_oracle({'redirect_alias': 15, 'contradicted_by_file': 2, 'cache_buster': 1})
        _rows, _open, closed = self.open_and_closed()
        reasons = [m.ai_reason for m in closed if m.subdomain.name == 'bg.test']
        self.assertFalse([r for r in reasons if 'loads no' in r], reasons)  # the page loads Bootstrap: never "loads no Bootstrap script"
        bootstrap = next(m.ai_reason for m in closed if m.subdomain.name == 'bg.test' and m.cve_entry.cve_id == 'CVE-2026-114538')
        self.assertIn('1.0.4 is the ?ver= cache-buster of a script on the same page', bootstrap)

    def test_the_page_cut_at_64_kib_proves_no_absence_so_only_the_aliases_close(self):
        from cveFeed import route_auth
        self.CUT = route_auth.ROUTE_SAMPLE_BYTES
        self.correlate()
        self.read_front_pages()
        self.correlate()
        _rows, is_open, closed = self.open_and_closed()
        self.assertEqual({js_libraries.closure_kind(m.ai_reason) for m in closed}, {'redirect_alias'})
        self.assertEqual(len(closed), 15)
        self.assertEqual(sorted((m.subdomain.name, m.cve_entry.cve_id) for m in is_open),
                         [('bg.test', 'CVE-2020-11022'), ('bg.test', 'CVE-2020-11023'), ('bg.test', 'CVE-2026-114538'),
                          ('info.bg.test', 'CVE-2020-11023')])
        self.assertTrue(all(m.confidence <= js_libraries.CONFIDENCE['filename'] for m in is_open if m.subdomain.name == 'bg.test'))

    def test_the_reconcile_sweep_closes_the_same_eighteen_without_a_rescan(self):
        super().test_the_reconcile_sweep_closes_the_same_eighteen_without_a_rescan()

    def test_the_next_correlation_closes_eighteen_and_keeps_the_real_one(self):
        super().test_the_next_correlation_closes_eighteen_and_keeps_the_real_one()


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

    def read_root(self, host, status, body='', scheme='https', location='', scripts=None, **extra):
        from cveFeed import route_auth
        url = f'{scheme}://{host}/'
        result = route_auth.analyse({'url': url, 'status': status, 'body': body, 'content_type': 'text/html', 'headers': {}, 'location': location,
                                     **extra})

        def probe(target, **_kw):
            text = (scripts or {}).get(target.split('?', 1)[0])
            return ({'status': 200, 'body': text, 'url': target, 'content_type': 'application/javascript', 'headers': {}} if text is not None
                    else {'status': 404, 'body': 'nf', 'url': target, 'content_type': 'text/html', 'headers': {}})
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            route_auth._read_scripts(result, probe, 0, project=self.project.id, reader=js_libraries.Reader(self.project.id), target=self.site)
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
                       bytes=len(page), read_limit=route_auth.ROOT_READ_BYTES, truncated=False)
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
        for name, prefix in (('pair.x.test', 'https://cdn.vendor-assets.test/js/'), ('pair2.x.test', '/js/')):
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
            self.read_root(name, 200, '<script src="/site.js"></script>')  # the page loads no jQuery
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
        self.read_root('a.x.test', 200, '<script src="/site.js"></script>')
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
        match = self.correlate(sub)[('c.x.test', 'CVE-2020-11023', '3.4.1')]
        # closed by the page with every field as correlation computes it again (the closure kept the confidence)
        CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='not_affected', ai_reason=js_libraries.closed_reason('the front page loads no jQuery'))
        reopened = self.correlate(sub)[('c.x.test', 'CVE-2020-11023', '3.4.1')]
        self.assertEqual((reopened.ai_verdict, reopened.ai_reason), ('', ''))

    def test_a_stale_or_vanished_port_reading_closes_nothing_and_a_retired_404_root_still_counts(self):
        from datetime import timedelta
        sub = self.host('old.x.test', ['jQuery:1.12.4'])
        self.read_root('old.x.test', 200, '<script src="/site.js"></script>')
        RouteAuth.objects.filter(host='old.x.test').update(checked_at=timezone.now() - timedelta(days=js_libraries.FRESH_DAYS + 1))
        self.assertEqual(self.correlate(sub)[('old.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')  # too old to speak for the page
        gone = self.host('gone.x.test', ['jQuery:1.12.4'])
        self.read_root('gone.x.test', 200, '<script src="/site.js"></script>', scheme='http')  # a port the host no longer has
        self.assertEqual(self.correlate(gone)[('gone.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        # a front page that answered 200 once and now answers 404 is retired, and the hosted 404 page it serves is the page now
        hosted = self.host('hosted.x.test', ['jQuery:1.12.4', 'jQuery:1.11.2'])
        self.read_root('hosted.x.test', 404, '<script src="/hs/jquery-1.11.2.js"></script>',
                       scripts={'https://hosted.x.test/hs/jquery-1.11.2.js': oracle('jquery-1.11.2-head.js')})
        RouteAuth.objects.filter(host='hosted.x.test').update(retired_at=timezone.now(), previous_state='open')
        found = self.correlate(hosted)
        self.assertEqual(found[('hosted.x.test', 'CVE-2020-11023', '1.11.2')].evidence['version_source'], 'body')
        self.assertTrue(all(m.ai_verdict != 'not_affected' or m.matched_version == '1.12.4' for m in found.values()))
        self.assertEqual(found[('hosted.x.test', 'CVE-2020-11023', '1.11.2')].ai_verdict, '')

    def test_a_library_match_that_reopened_lately_is_not_closed_again_on_weak_grounds(self):
        from cveFeed.models import CVEMatch
        sub = self.host('flap.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('flap.x.test', 200, '<script src="/site.js"></script>')
        self.assertEqual(self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')
        self.read_root('flap.x.test', 200, '<script src="/js/jquery-1.12.4.min.js"></script>')  # variant B of the page loads it
        self.assertEqual(self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        self.read_root('flap.x.test', 200, '<script src="/site.js"></script>')  # variant A again: an absence, weak, reopened lately
        held = self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual(held.ai_verdict, '')
        from cveFeed.tasks import reconcile_library_provenance
        reconcile_library_provenance()
        self.assertEqual(CVEMatch.objects.get(pk=held.pk).ai_verdict, '')
        # ... but the library's own file stating another version is strong: it closes even so
        self.read_root('flap.x.test', 200, '<script src="/js/jquery.min.js"></script>', scripts={'https://flap.x.test/js/jquery.min.js': JQ_371_MIN})
        self.assertEqual(self.correlate(sub)[('flap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_library_sweep_looks_only_at_open_matches_in_bounded_batches(self):
        from cveFeed.models import BackgroundCursor, CVEMatch
        from cveFeed.tasks import reconcile_library_provenance
        subs = [self.host(f'h{i}.x.test', ['jQuery:1.12.4']) for i in range(4)]
        self.correlate(*subs)
        for sub in subs:
            self.read_root(sub.name, 200, '<script src="/site.js"></script>')
        first = reconcile_library_provenance(limit=2)
        self.assertEqual((first['reviewed'], first['closed'], first['closed_by_reason']), (2, 2, {'no_such_script': 2}))
        second = reconcile_library_provenance(limit=2)
        self.assertEqual(second['closed'], 2)
        self.assertEqual(CVEMatch.objects.filter(subdomain__in=subs, ai_verdict='not_affected').count(), 4)
        self.assertEqual(reconcile_library_provenance(limit=2)['reviewed'], 0)  # closed ones are never looked at again
        # out of time: the next run starts where this one stopped
        more = [self.host(f'k{i}.x.test', ['jQuery:1.12.4']) for i in range(3)]
        self.correlate(*more)
        for sub in more:
            self.read_root(sub.name, 200, '<script src="/site.js"></script>')
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
