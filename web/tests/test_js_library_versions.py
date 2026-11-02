"""1.3.2: a JavaScript library's version is read from the file itself, never from a ?ver= string, and several copies on one page are resolved
(cveFeed.js_libraries, the route check's script reading, the html-libraries probe and correlation)."""
import gzip
import io
import unittest
from unittest import mock
from urllib.parse import urlsplit

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase

from cveFeed import correlation, js_libraries, pinned_transport, probes, route_auth, triage
from cveFeed.models import HostExclusion, ProbeObservation, RouteAuth
from startScan.models import Subdomain, Technology
from tests.test_route_auth import RouteFixture, probe

PAGE_URL = 'https://www.rt.test/'

# fixture script bodies, as the libraries ship them
JQ_341_MIN = '/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(e,t){"use strict"}(window);'
JQ_371_MIN = '/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){"use strict"}(window);'
JQ_311_FULL = '/*!\n * jQuery JavaScript Library v3.1.1\n * https://jquery.com/\n */\n(function( global, factory ) {})'
JQ_360_FULL = '/*!\n * jQuery JavaScript Library v3.6.0\n * https://jquery.com/\n */\n(function( global, factory ) {})'
# a bundler kept the code and dropped the banner: jQuery's own prototype still names its version
JQ_351_STRIPPED = ('!function(e,t){"use strict";var n=[],r=Object.getPrototypeOf,f="3.5.1",k=function(e,t){return new k.fn.init(e,t)};'
                   'k.fn=k.prototype={jquery:f,constructor:k,length:0}}(window);')
JQ_1113_STRIPPED = '(function(a,b){var c="1.11.3",m=function(a,b){return new m.fn.init(a,b)},n=/x/;m.fn=m.prototype={jquery:c,constructor:m}})(window);'
JQ_UI = '/*! jQuery UI - v1.12.1 - 2016-09-14\n* http://jqueryui.com\n* Includes: widget.js */'
JQ_MIGRATE = '/*! jQuery Migrate v3.3.2 | (c) OpenJS Foundation and other contributors | jquery.org/license */'
BOOTSTRAP_4 = '/*!\n  * Bootstrap v4.6.0 (https://getbootstrap.com/)\n  * Copyright 2011-2021 The Bootstrap Authors\n  */'
BOOTSTRAP_3_CODE = "+function ($) { 'use strict'; var Modal = function (element, options) {}; Modal.VERSION  = '3.3.7' }(jQuery);"
PLUGIN = '/*!\n * jQuery Form Plugin\n * version: 4.2.2\n * Requires jQuery v1.7.2 or later\n */'
DATEPICKER = '/*!\n * Datepicker for Bootstrap v1.9.0 (https://github.com/uxsolutions/bootstrap-datepicker)\n */'
LODASH_MIN = '/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE */\n;(function(){}).call(this);'
NO_BANNER = '!function(e){e.fn.extend({x:1})}(jQuery);'

# a WordPress theme that enqueues its own copies with the theme's version as the cache-buster
WORDPRESS_PAGE = """<html><head>
<script src="/wp-content/themes/acme/js/jquery.min.js?ver=1.0.4"></script>
<script src="/wp-content/themes/acme/js/bootstrap.min.js?ver=1.0.4"></script>
<script src="/wp-content/themes/acme/js/jquery.fancybox.js?ver=1.0.4"></script>
<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
</head></html>"""
TWO_COPIES = """<script src="/assets/jquery-3.4.1.min.js"></script>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>"""
LATER_PATCHED = """<script src="/js/jquery-3.1.1.js"></script>
<script src="/js/plugins.js"></script>
<script src="/js/jquery-3.6.0.js"></script>"""


def fetcher(bodies, asked=None, **extra):
    """A ``fetch(url)`` that serves ``bodies`` by path (404 for anything else) and records what was asked (with the headers sent)."""
    def fetch(url, headers=None):
        if asked is not None:
            asked.append((url, headers) if headers else url)
        path = urlsplit(url).path
        if path not in bodies:
            return {'status': 404, 'body': 'not found', 'content_type': 'text/html'}
        return {'status': 200, 'body': bodies[path], 'content_type': 'application/javascript', **extra}
    return fetch


def same_host_only(url):
    return '' if js_libraries.kind_of(url, PAGE_URL) == 'same-host' else 'not read in this test'


def reader(**kw):
    return js_libraries.Reader(sleep=lambda s: None, **kw)


def read(page, bodies, asked=None, budget=None, vet=same_host_only, scan=None, **extra):
    entries = js_libraries.parse_page(page, PAGE_URL)
    return js_libraries.read_page(entries, PAGE_URL, fetcher(bodies, asked, **extra), vet, budget or {'left': js_libraries.MAX_SCRIPTS_PER_HOST},
                                  reader=scan or reader())


class NoCache:
    """Each test reads its scripts afresh: nothing an earlier test (or run) cached for the same URL answers for it."""
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(js_libraries, '_cache', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)


class FileContentsTests(unittest.TestCase):
    def test_banners_of_the_libraries_name_them(self):
        self.assertEqual(js_libraries.read_body(JQ_341_MIN), [('jquery', '3.4.1', 'banner')])
        self.assertEqual(js_libraries.read_body(JQ_311_FULL), [('jquery', '3.1.1', 'banner')])
        self.assertEqual(js_libraries.read_body(JQ_UI), [('jquery-ui', '1.12.1', 'banner')])
        self.assertEqual(js_libraries.read_body(JQ_MIGRATE), [('jquery-migrate', '3.3.2', 'banner')])
        self.assertEqual(js_libraries.read_body(BOOTSTRAP_4), [('bootstrap', '4.6.0', 'banner')])
        self.assertEqual(js_libraries.read_body('//! moment.js\n//! version : 2.29.4\n//! authors : Tim Wood\n'), [('moment', '2.29.4', 'banner')])

    def test_code_only_the_library_has_names_it_when_the_banner_was_stripped(self):
        self.assertEqual(js_libraries.read_body(JQ_351_STRIPPED), [('jquery', '3.5.1', 'signature')])
        self.assertEqual(js_libraries.read_body(JQ_1113_STRIPPED), [('jquery', '1.11.3', 'signature')])
        self.assertEqual(js_libraries.read_body(BOOTSTRAP_3_CODE), [('bootstrap', '3.3.7', 'signature')])
        self.assertEqual(js_libraries.read_body('$.ui = $.ui || {}; var version = $.ui.version = "1.13.2";'), [('jquery-ui', '1.13.2', 'signature')])

    def test_a_plugin_that_mentions_a_library_is_not_that_library(self):
        self.assertEqual(js_libraries.read_body(PLUGIN), [])        # "Requires jQuery v1.7.2" is not jQuery 1.7.2
        self.assertEqual(js_libraries.read_body(DATEPICKER), [])    # a Bootstrap plugin's banner is not Bootstrap
        self.assertEqual(js_libraries.read_body(LODASH_MIN), [])    # Lodash's credit to Underscore.js 1.8.3 is neither one's version
        self.assertEqual(js_libraries.read_body(NO_BANNER), [])
        self.assertEqual(js_libraries.read_body('x' * 5000 + JQ_341_MIN), [])  # a banner is at the top of its file

    def test_a_hostile_script_cannot_make_reading_slow(self):
        import time
        started = time.monotonic()
        for body in ('a.fn=a.prototype={' * 20000, 'jquery:' * 40000, ('x' * 30 + '.fn = ') * 6000, '/*! jQuery v' * 30000):
            js_libraries.read_body(body)
        self.assertLess(time.monotonic() - started, 2.0)


class ScriptNameTests(unittest.TestCase):
    def test_a_query_string_is_never_a_version(self):
        for url in ('https://www.rt.test/wp-content/themes/acme/js/jquery.min.js?ver=1.0.4',
                    'https://www.rt.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1', 'https://www.rt.test/js/jquery.js?v=1.12.4'):
            hint = js_libraries.identify(url)
            self.assertEqual((hint['library'], hint['filename_version']), ('jquery', ''), url)
            self.assertTrue(hint['query_version'])

    def test_one_script_is_one_library_and_a_plugin_is_none(self):
        self.assertEqual(js_libraries.identify('https://x.test/js/bootstrap.min.js?ver=1.0.4')['library'], 'bootstrap')
        self.assertEqual(js_libraries.identify('https://x.test/js/jquery.fancybox.js?ver=1.0.4')['library'], '')
        self.assertEqual(js_libraries.identify('https://x.test/js/jquery-migrate.min.js')['library'], 'jquery-migrate')
        self.assertEqual(js_libraries.identify('https://x.test/js/jquery-ui.min.js')['library'], 'jquery-ui')

    def test_a_file_name_or_cdn_path_gives_a_hint(self):
        for url, expected in (('https://x.test/assets/jquery-3.4.1.min.js', ('jquery', '3.4.1')),
                              ('https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js', ('jquery', '3.4.1')),
                              ('https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.slim.min.js', ('jquery', '3.6.0')),
                              ('https://code.jquery.com/ui/1.12.1/jquery-ui.min.js', ('jquery-ui', '1.12.1')),
                              ('https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.bundle.min.js', ('bootstrap', '4.5.2'))):
            hint = js_libraries.identify(url)
            self.assertEqual((hint['library'], hint['filename_version']), expected, url)

    def test_the_page_order_timing_and_skipped_sources(self):
        entries = js_libraries.parse_page('<script src="/a.js"></script><script defer src="/b.js"></script><script type="module" src="/c.js">'
                                          '</script><script async src="/d.js"></script><script src="data:text/javascript,1"></script>'
                                          '<script type="text/template"><p></p></script><script>var j = jQuery.noConflict(true);</script>'
                                          '<img data-src="/e.js">', PAGE_URL)
        self.assertEqual([(e['url'] and urlsplit(e['url']).path, e['timing'], e['noconflict']) for e in entries],
                         [('/a.js', 'sync', False), ('/b.js', 'defer', False), ('/c.js', 'defer', False), ('/d.js', 'async', False),
                          (None, 'sync', True)])


class WordPressCacheBusterTests(NoCache, SimpleTestCase):
    def test_a_theme_version_is_never_read_as_jquery_or_bootstrap(self):
        asked = []
        records = read(WORDPRESS_PAGE, {}, asked)  # nothing readable: the names say which library, the query string says nothing
        self.assertEqual({k: r['version'] for k, r in records.items()}, {'jquery': '', 'bootstrap': ''})
        self.assertEqual(js_libraries.names_of(records), [('jQuery', 'script:filename'), ('Bootstrap', 'script:filename')])
        self.assertNotIn('1.0.4', str(js_libraries.names_of(records)))
        self.assertTrue(all(urlsplit(u).hostname == 'www.rt.test' for u in asked))  # neither data: nor the analytics tag is fetched

    def test_the_files_state_the_versions(self):
        records = read(WORDPRESS_PAGE, {'/wp-content/themes/acme/js/jquery.min.js': JQ_341_MIN,
                                        '/wp-content/themes/acme/js/bootstrap.min.js': BOOTSTRAP_4})
        self.assertEqual((records['jquery']['version'], records['jquery']['version_source']), ('3.4.1', 'body'))
        self.assertEqual(records['bootstrap']['version'], '4.6.0')
        self.assertEqual(records['jquery']['copies'][0]['query_version'], '1.0.4')  # kept, so the string is recognised elsewhere, never used
        self.assertEqual(len(records['jquery']['script_sha256']), 64)
        self.assertEqual(records['jquery']['version_confidence'], js_libraries.CONFIDENCE['banner'])

    def test_a_file_whose_banner_was_stripped_falls_back_to_its_name_at_low_confidence(self):
        records = read('<script src="/js/jquery-1.12.4.min.js"></script>', {'/js/jquery-1.12.4.min.js': NO_BANNER})
        record = records['jquery']
        self.assertEqual((record['version'], record['version_source'], record['version_confidence']), ('1.12.4', 'filename', 0.4))
        self.assertEqual(js_libraries.names_of(records), [('jQuery:1.12.4', 'script:filename')])

    def test_the_file_wins_over_its_name(self):
        records = read('<script src="/js/jquery-1.12.4.min.js"></script>', {'/js/jquery-1.12.4.min.js': JQ_351_STRIPPED})
        self.assertEqual((records['jquery']['version'], records['jquery']['how']), ('3.5.1', 'signature'))
        self.assertEqual(records['jquery']['copies'][0]['filename_version'], '1.12.4')
        skip, _evidence, _cap = js_libraries.HostLibraries(records).judge('jQuery', '1.12.4')
        self.assertTrue(skip)


class SeveralCopiesTests(NoCache, SimpleTestCase):
    def test_the_last_copy_loaded_is_the_effective_one(self):
        records = read(TWO_COPIES, {'/assets/jquery-3.4.1.min.js': JQ_341_MIN, '/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        record = records['jquery']
        self.assertEqual([(c['version'], c['state'], c['order']) for c in record['copies']], [('3.4.1', 'shadowed', 0), ('3.7.1', 'effective', 1)])
        self.assertEqual((record['version'], record['copies_unresolved']), ('3.7.1', False))
        self.assertEqual(record['tech_names'], ['jQuery:3.4.1', 'jQuery:3.7.1'])  # the shadowed copy is kept: correlation caps it
        libraries = js_libraries.HostLibraries(records)
        skip, evidence, cap = libraries.judge('jQuery', '3.4.1')
        self.assertEqual((skip, evidence['copy_state'], cap), (False, 'shadowed', js_libraries.SHADOWED_CAP))
        self.assertEqual(evidence['version_note'], 'shadowed by 3.7.1 loaded later; older code or closures may still use it')
        skip, evidence, cap = libraries.judge('jQuery', '3.7.1')
        self.assertEqual((skip, evidence['copy_state'], evidence['version_source'], cap), (False, 'effective', 'body', None))
        self.assertEqual([c['state'] for c in evidence['copies']], ['shadowed', 'effective'])

    def test_a_patched_copy_loaded_after_a_vulnerable_one_shadows_it(self):
        records = read(LATER_PATCHED, {'/js/jquery-3.1.1.js': JQ_311_FULL, '/js/jquery-3.6.0.js': JQ_360_FULL, '/js/plugins.js': NO_BANNER})
        self.assertEqual({c['version']: c['state'] for c in records['jquery']['copies']}, {'3.1.1': 'shadowed', '3.6.0': 'effective'})
        self.assertEqual(js_libraries.HostLibraries(records).judge('jQuery', '3.1.1')[2], js_libraries.SHADOWED_CAP)

    def test_a_vulnerable_copy_loaded_last_is_the_one_matched(self):
        page = '<script src="/js/jquery-3.6.0.js"></script><script src="/js/jquery-3.1.1.js"></script>'
        records = read(page, {'/js/jquery-3.1.1.js': JQ_311_FULL, '/js/jquery-3.6.0.js': JQ_360_FULL})
        self.assertEqual(records['jquery']['version'], '3.1.1')
        self.assertEqual(js_libraries.HostLibraries(records).judge('jQuery', '3.1.1'), (False, mock.ANY, None))  # the copy that runs: as usual

    def test_defer_runs_after_the_ordinary_scripts(self):
        page = '<script defer src="/js/jquery-3.6.0.js"></script><script src="/js/jquery-3.1.1.js"></script>'
        records = read(page, {'/js/jquery-3.1.1.js': JQ_311_FULL, '/js/jquery-3.6.0.js': JQ_360_FULL})
        self.assertEqual(records['jquery']['version'], '3.6.0')

    def test_an_order_the_page_does_not_show_leaves_every_copy_a_candidate(self):
        bodies = {'/js/jquery-3.1.1.js': JQ_311_FULL, '/js/jquery-3.6.0.js': JQ_360_FULL}
        for page in ('<script async src="/js/jquery-3.6.0.js"></script><script src="/js/jquery-3.1.1.js"></script>',
                     '<script src="/js/jquery-3.6.0.js"></script><script src="/js/jquery-3.1.1.js"></script>'
                     '<script>var old = jQuery.noConflict(true);</script>'):
            record = read(page, bodies)['jquery']
            self.assertTrue(record['copies_unresolved'], page)
            self.assertTrue(record['unresolved_reason'])
            self.assertEqual(set(record['tech_names']), {'jQuery:3.1.1', 'jQuery:3.6.0'})
            skip, evidence, cap = js_libraries.HostLibraries({'jquery': record}).judge('jQuery', '3.1.1')
            self.assertEqual((skip, evidence['copies_unresolved'], evidence['copy_state'], cap), (False, True, 'unresolved', js_libraries.UNRESOLVED_CAP))
            self.assertLessEqual(evidence['version_confidence'], js_libraries.UNRESOLVED_CAP)

    def test_a_copy_after_a_noconflict_call_is_marked(self):
        page = ('<script src="/js/jquery-3.6.0.js"></script><script>var $j = jQuery.noConflict(true);</script>'
                '<script src="/js/jquery-3.1.1.js"></script>')
        record = read(page, {'/js/jquery-3.1.1.js': JQ_311_FULL, '/js/jquery-3.6.0.js': JQ_360_FULL})['jquery']
        self.assertEqual([c.get('loaded_after_noconflict', False) for c in record['copies']], [False, True])

    def test_a_bundle_names_each_library_it_carries(self):
        records = read('<script src="/js/vendor.js"></script>', {'/js/vendor.js': BOOTSTRAP_4 + '\n' + JQ_UI})
        self.assertEqual({k: r['version'] for k, r in records.items()}, {'bootstrap': '4.6.0', 'jquery-ui': '1.12.1'})


class FetchLimitTests(NoCache, SimpleTestCase):
    def test_at_most_six_scripts_per_host_over_its_pages(self):
        page = ''.join(f'<script src="/js/jquery-3.{i}.0.js"></script>' for i in range(10))
        asked, budget = [], {'left': js_libraries.MAX_SCRIPTS_PER_HOST}
        read(page, {}, asked, budget)
        read(page, {}, asked, budget)  # the host's other web base
        self.assertEqual(len(asked), js_libraries.MAX_SCRIPTS_PER_HOST)

    def test_a_body_over_the_cap_is_read_for_its_banner_but_has_no_digest(self):
        records = read('<script src="/js/jquery.js"></script>', {'/js/jquery.js': JQ_341_MIN + ' ' * js_libraries.MAX_SCRIPT_BYTES},
                       bytes=js_libraries.MAX_SCRIPT_BYTES)
        self.assertEqual(records['jquery']['version'], '3.4.1')
        self.assertEqual(records['jquery']['script_sha256'], '')  # a cut body is not the file: no identity is claimed for it

    def test_a_gzip_body_is_decoded_within_the_cap(self):
        raw = gzip.compress((JQ_341_MIN + '\n' + 'var a=1;' * 100000).encode())  # 800 KB decoded

        class Response:
            def __init__(self):
                self.stream = io.BytesIO(raw)

            def getheader(self, name, default=None):
                return 'gzip' if name.lower() == 'content-encoding' else default

            def read(self, n=-1):
                return self.stream.read(n)
        body = pinned_transport.read_body(Response(), js_libraries.MAX_SCRIPT_BYTES)
        self.assertEqual(len(body), js_libraries.MAX_SCRIPT_BYTES)
        records = read('<script src="/js/jquery.js"></script>', {'/js/jquery.js': body.decode()}, bytes=len(body))
        self.assertEqual((records['jquery']['version'], records['jquery']['script_sha256']), ('3.4.1', ''))

    def test_every_probe_read_is_capped(self):
        self.assertEqual(route_auth.MAX_READ_BYTES, js_libraries.MAX_SCRIPT_BYTES)
        with self.assertRaises(ValueError):  # the cap is applied before anything is sent
            route_auth.probe_url('https://www.rt.test/x.js', max_bytes=-1)

    def test_a_page_served_for_a_missing_script_and_an_error_say_nothing(self):
        def fetch(url):
            if url.endswith('a.js'):
                raise OSError('reset')
            return {'status': 200, 'body': '<html><title>Not found</title></html>', 'content_type': 'text/html'}  # a soft 404
        entries = js_libraries.parse_page('<script src="/js/jquery-3.4.1.js"></script><script src="/a.js"></script>', PAGE_URL)
        records = js_libraries.read_page(entries, PAGE_URL, fetch, same_host_only, {'left': 6}, reader=reader())
        self.assertEqual((records['jquery']['version'], records['jquery']['version_source']), ('3.4.1', 'filename'))

    def test_what_was_read_is_cached_by_url_with_its_validator(self):
        url = 'https://www.rt.test/js/cached-jquery.min.js'
        cache.delete(js_libraries._cache_key(url))
        self.addCleanup(cache.delete, js_libraries._cache_key(url))
        asked = []
        with mock.patch.object(js_libraries, '_cache', return_value=cache):
            page = '<script src="/js/cached-jquery.min.js"></script>'
            first = read(page, {'/js/cached-jquery.min.js': JQ_341_MIN}, asked, raw_headers={'etag': '"abc"', 'content-length': '90'})
            again = read(page, {'/js/cached-jquery.min.js': JQ_341_MIN}, asked, raw_headers={'etag': '"abc"', 'content-length': '90'})
        self.assertEqual(asked, [url])
        self.assertEqual(first, again)
        self.assertEqual(cache.get(js_libraries._cache_key(url))['etag'], '"abc"')


class WhichHostsTests(NoCache, RouteFixture, TestCase):
    PAGE = ('<script src="https://static.rt.test/js/jquery-3.4.1.min.js"></script>'
            '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
            '<script src="https://other.example/js/jquery-1.0.0.min.js"></script>'
            '<script src="http://10.0.0.5/js/bootstrap.min.js"></script>')

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'static.rt.test'))  # the static host is one of the project's own

    def vet(self, target=None):
        return js_libraries.vetter(PAGE_URL, self.project.id, target=target or self.domain)

    def test_the_kinds_of_host(self):
        kinds = [js_libraries.kind_of(e['url'], PAGE_URL) for e in js_libraries.parse_page(self.PAGE, PAGE_URL)]
        self.assertEqual(kinds, ['same-site', 'cdn', 'third-party', 'third-party'])
        self.assertEqual(js_libraries.kind_of('https://www.google-analytics.com/analytics.js', PAGE_URL), 'analytics')
        self.assertEqual(js_libraries.kind_of('https://other.herokuapp.com/x.js', 'https://mine.herokuapp.com/'), 'third-party')  # a shared platform

    def test_same_site_and_cdn_scripts_are_read_and_others_never(self):
        vet = self.vet()
        self.assertEqual(vet('https://static.rt.test/js/jquery.js'), '')
        self.assertEqual(vet('https://code.jquery.com/jquery-3.6.0.min.js'), '')
        self.assertEqual(vet('https://other.example/js/jquery.js'), 'third-party')
        self.assertEqual(vet('https://www.googletagmanager.com/gtm.js'), 'analytics')

    def test_an_excluded_host_is_not_read(self):
        HostExclusion.objects.create(org=self.project.org, host='static.rt.test')
        self.assertEqual(self.vet()('https://static.rt.test/js/jquery.js'), 'excluded')

    def test_a_host_outside_the_bug_bounty_scope_is_not_read(self):
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', return_value='not listed in the program scope'):
            self.assertEqual(self.vet()('https://static.rt.test/js/jquery.js'), 'outside the bug bounty scope')
            self.assertEqual(self.vet()('https://code.jquery.com/jquery-3.6.0.min.js'), '')  # a public CDN is not the program's asset

    def test_a_private_address_is_refused(self):
        self.blocked.side_effect = lambda host, *a, **k: host == 'static.rt.test'  # the name resolves to an internal address
        self.assertEqual(self.vet()('https://static.rt.test/js/jquery.js'), 'address not allowed')
        self.assertEqual(self.vet()('http://10.0.0.5/js/bootstrap.min.js'), 'third-party')

    def test_refused_scripts_are_never_fetched_and_their_names_stay_hints(self):
        HostExclusion.objects.create(org=self.project.org, host='static.rt.test')
        asked = []
        entries = js_libraries.parse_page(self.PAGE, PAGE_URL)
        records = js_libraries.read_page(entries, PAGE_URL, fetcher({'/jquery-3.6.0.min.js': '/*! jQuery v3.6.0 | (c) OpenJS */'}, asked), self.vet(),
                                         {'left': 6}, reader=reader())
        self.assertEqual(asked, ['https://code.jquery.com/jquery-3.6.0.min.js'])
        copies = {c['url']: c for c in records['jquery']['copies']}
        self.assertEqual(copies['https://static.rt.test/js/jquery-3.4.1.min.js']['not_read'], 'excluded')
        self.assertEqual(copies['https://code.jquery.com/jquery-3.6.0.min.js']['source'], 'body')


class RouteCheckTests(NoCache, RouteFixture, TestCase):
    def test_the_route_check_stores_what_the_files_state_and_every_copy(self):
        bodies = {'/assets/jquery-3.4.1.min.js': JQ_341_MIN, '/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN}
        self.answers = {'/': {'status': 200, 'body': TWO_COPIES + '<script src="/js/bootstrap.min.js?ver=1.0.4"></script>'}}

        def fake(url):
            path = urlsplit(url).path
            if path in bodies:
                return probe(url=url, content_type='application/javascript', body=bodies[path])
            return self.probe(url)
        scan = self.scan()
        self.run_it(scan, probe=fake)
        root = RouteAuth.objects.get(path='/')
        self.assertNotIn('page_scripts', root.evidence)
        self.assertEqual(root.evidence['libraries']['jquery']['version'], '3.7.1')
        names = root.evidence['fingerprint_names']
        self.assertIn('jQuery:3.7.1', names)
        self.assertIn('jQuery:3.4.1', names)  # shadowed, kept: correlation holds it at a capped confidence
        self.assertEqual([c['state'] for c in root.evidence['libraries']['jquery']['copies']], ['shadowed', 'effective'])
        self.assertIn('Bootstrap', names)
        self.assertFalse([n for n in names if '1.0.4' in n])
        route_auth.link_technologies(scan, {root.url: {'evidence': root.evidence}})
        sub = Subdomain.objects.get(scan_history=scan)
        stored = {t.name for t in sub.technologies.all()}
        self.assertEqual({n for n in stored if n.startswith(('jQuery', 'Bootstrap'))}, {'Bootstrap', 'jQuery:3.4.1', 'jQuery:3.7.1'})


class ProbeTests(NoCache, SimpleTestCase):
    def test_the_libraries_probe_records_the_effective_copy_with_every_copy(self):
        from tests.test_probes import answers, page
        table = {'/': page(body=TWO_COPIES), '/assets/jquery-3.4.1.min.js': page(body=JQ_341_MIN),
                 '/wp-includes/js/jquery/jquery.min.js?ver=3.7.1': page(body=JQ_371_MIN)}
        found = probes.run_http_probe('html-libraries', 'https://www.rt.test', {'www.rt.test'}, get=answers(table), sleep=lambda s: None)
        self.assertEqual([(o['product'], o['version'], o['source'], o['confidence']) for o in found], [('jQuery', '3.7.1', 'script:body', 0.9)])
        self.assertEqual(len(found[0]['evidence']['library']['copies']), 2)
        self.assertEqual(probes.technology_names(found), ['jQuery:3.4.1', 'jQuery:3.7.1'])

    def test_an_unresolved_set_stores_each_versioned_copy(self):
        from tests.test_probes import answers, page
        html = '<script async src="/js/jquery-3.6.0.js"></script><script src="/js/jquery-3.1.1.js"></script>'
        table = {'/': page(body=html), '/js/jquery-3.6.0.js': page(body=JQ_360_FULL), '/js/jquery-3.1.1.js': page(body=JQ_311_FULL)}
        found = probes.run_http_probe('html-libraries', 'https://www.rt.test', {'www.rt.test'}, get=answers(table), sleep=lambda s: None)
        self.assertEqual(sorted(probes.technology_names(found)), ['jQuery:3.1.1', 'jQuery:3.6.0'])
        self.assertLessEqual(found[0]['confidence'], js_libraries.UNRESOLVED_CAP)

    def test_the_headers_probe_keeps_a_file_name_version_as_a_low_confidence_hint(self):
        from tests.test_probes import page
        found = probes.observations_from_page(page(body='<script src="/js/jquery-1.12.4.min.js"></script>'
                                                        '<script src="/js/bootstrap.min.js?ver=1.0.4"></script>'))
        versions = {(o['product'], o['version'], o['confidence']) for o in found if o['kind'] == 'version'}
        self.assertIn(('jQuery', '1.12.4', 0.4), versions)
        self.assertIn(('Bootstrap', '', 0.7), versions)  # a product seen, no version: a lead


class FakeCVE:
    def __init__(self, cid, affected, kev=True):
        self.id, self.cve_id, self.affected, self.kev = cid, f'CVE-2020-{cid}', affected, kev


JQUERY_XSS = FakeCVE(11023, [{'vendor': 'jquery', 'product': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]}])
BOOTSTRAP_XSS = FakeCVE(10735, [{'vendor': 'getbootstrap', 'product': 'bootstrap', 'ranges': [{'introduced': '0', 'fixed': '3.4.0'}]}])


class CorrelationTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan()
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
        self.index = correlation.build_product_index([JQUERY_XSS, BOOTSTRAP_XSS])

    def host(self, *names, evidence=None):
        for name in names:
            self.sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        if evidence is not None:
            from django.utils import timezone
            RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.rt.test', path='/', url=PAGE_URL, auth_state='open',
                                     http_status=200, evidence=evidence, checked_at=timezone.now())
        sub = Subdomain.objects.prefetch_related('technologies').get(pk=self.sub.pk)
        return {(r['matched_version'], r['cve_entry_id']): r for r in
                correlation.collect_subdomain_matches(sub, self.index, {c.id: c for c in (JQUERY_XSS, BOOTSTRAP_XSS)})}

    def records(self, page, bodies):
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            return read(page, bodies)

    def test_a_shadowed_vulnerable_copy_stays_a_capped_labelled_candidate(self):
        records = self.records(TWO_COPIES, {'/assets/jquery-3.4.1.min.js': JQ_341_MIN, '/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        matches = self.host('jQuery:3.4.1', 'jQuery:3.7.1', evidence={'libraries': records})
        self.assertEqual(list(matches), [('3.4.1', 11023)])
        match = matches[('3.4.1', 11023)]
        self.assertEqual((match['confidence'], match['evidence']['copy_state']), (0.4, 'shadowed'))
        self.assertIn('shadowed by 3.7.1 loaded later', match['evidence']['version_note'])
        self.assertTrue(match['version_in_range'])  # a candidate the version-only ceiling holds at needs validation, never hidden

    def test_the_effective_vulnerable_copy_matches_with_its_file_and_the_copies(self):
        page = '<script src="/js/jquery-3.6.0.js"></script><script src="/js/jquery-3.1.1.js"></script>'
        records = self.records(page, {'/js/jquery-3.1.1.js': JQ_311_FULL, '/js/jquery-3.6.0.js': JQ_360_FULL})
        matches = self.host('jQuery:3.1.1', 'jQuery:3.6.0', evidence={'libraries': records})
        self.assertEqual(list(matches), [('3.1.1', 11023)])
        evidence = matches[('3.1.1', 11023)]['evidence']
        self.assertEqual((evidence['version_source'], evidence['copy_state']), ('body', 'effective'))
        self.assertEqual(evidence['script_url'], 'https://www.rt.test/js/jquery-3.1.1.js')
        self.assertEqual(len(evidence['script_sha256']), 64)
        self.assertEqual([c['state'] for c in evidence['copies']], ['shadowed', 'effective'])
        self.assertEqual(matches[('3.1.1', 11023)]['confidence'], 0.95)  # a version the file states: the confidence it always had

    def test_a_file_name_version_matches_only_at_low_confidence(self):
        records = self.records('<script src="/js/jquery-1.12.4.min.js"></script>', {'/js/jquery-1.12.4.min.js': NO_BANNER})
        match = self.host('jQuery:1.12.4', evidence={'libraries': records})[('1.12.4', 11023)]
        self.assertEqual((match['confidence'], match['evidence']['version_source']), (0.4, 'filename'))
        self.assertTrue(match['version_in_range'])  # still a candidate: the version-only ceiling keeps it at needs validation

    def test_a_query_string_version_another_tool_stored_is_not_matched(self):
        records = self.records(WORDPRESS_PAGE, {'/wp-content/themes/acme/js/jquery.min.js': JQ_371_MIN,
                                                '/wp-content/themes/acme/js/bootstrap.min.js': BOOTSTRAP_4})
        self.assertEqual(self.host('jquery:1.0.4', 'bootstrap:1.0.4', 'jQuery:3.7.1', 'Bootstrap:4.6.0', evidence={'libraries': records}), {})

    def test_before_1_3_2_a_name_or_query_version_is_kept_at_low_confidence_never_dropped(self):
        # a real jquery-3.4.1.min.js next to a real bootstrap@3.4.1: one string, two libraries, both genuine
        legacy = {'fingerprints': [{'name': 'jQuery:3.4.1', 'source': 'script:name'}, {'name': 'Bootstrap:3.4.1', 'source': 'script:name'},
                                   {'name': 'jQuery:1.12.4', 'source': 'script:name'}]}
        matches = self.host('jQuery:3.4.1', 'Bootstrap:3.4.1', 'jQuery:1.12.4', evidence=legacy)
        self.assertEqual(set(matches), {('3.4.1', 11023), ('1.12.4', 11023)})  # Bootstrap 3.4.1 is out of its advisory's range
        for match in matches.values():
            self.assertEqual((match['confidence'], match['evidence']['version_source']), (0.4, 'filename'))
            self.assertIn('1.3.2', match['evidence']['version_note'])

    def test_a_library_version_with_no_page_evidence_is_matched_as_before(self):
        match = self.host('jQuery:3.4.1')[('3.4.1', 11023)]
        self.assertEqual(match['confidence'], 0.95)
        self.assertNotIn('version_source', match['evidence'])

    def test_a_probe_record_counts_like_a_route_record(self):
        records = self.records(TWO_COPIES, {'/assets/jquery-3.4.1.min.js': JQ_341_MIN, '/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='html-libraries', port=0, kind='version',
                                        product='jQuery', version='3.7.1', outcome='found', confidence=0.9, source='script:body',
                                        evidence={'library': records['jquery']})
        self.assertEqual(self.host('jQuery:3.4.1', 'jQuery:3.7.1')[('3.4.1', 11023)]['evidence']['copy_state'], 'shadowed')


class TriageTests(unittest.TestCase):
    def test_the_prompt_reads_where_the_version_came_from_and_the_copies_without_the_host(self):
        evidence = {'version_source': 'filename', 'version_confidence': 0.4, 'script_url': 'https://www.rt.test/js/jquery-1.12.4.min.js',
                    'copy_state': 'effective', 'copies': [{'url': 'https://www.rt.test/a/jquery.js', 'version': '3.7.1', 'source': 'body',
                                                           'state': 'shadowed'},
                                                          {'url': 'https://www.rt.test/js/jquery-1.12.4.min.js', 'version': '1.12.4',
                                                           'source': 'filename', 'state': 'effective'}]}
        brief = triage.library_brief(evidence, names={'www.rt.test', 'rt.test'})
        self.assertIn('file name', brief['version_source'])
        self.assertEqual(brief['script'], '/js/jquery-1.12.4.min.js')
        self.assertEqual([(c['version'], c['state']) for c in brief['copies_on_page']], [('3.7.1', 'shadowed'), ('1.12.4', 'effective')])
        self.assertNotIn('rt.test', str(brief))
        self.assertEqual(triage.library_brief({'source': 'tech', 'raw_version': '1.0'}), {})


class ReviewProbeTests(NoCache, SimpleTestCase):
    """The review's probes (1.3.2): a copy that never loads, a commented-out copy, a document.write fallback, nomodule and attribute tricks."""

    def test_a_newer_copy_that_is_not_served_never_shadows_the_copy_that_was_read(self):
        page = ('<script src="/js/jquery-1.12.4.min.js"></script>'
                '<script src="/js/jquery-3.7.1.min.js"></script>')  # the newer one 404s: it may never load
        record = read(page, {'/js/jquery-1.12.4.min.js': '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */'})['jquery']
        self.assertTrue(record['copies_unresolved'])
        self.assertIn('not served', record['unresolved_reason'])
        self.assertEqual((record['version'], record['version_source']), ('1.12.4', 'body'))  # the file that was read speaks for the set
        skip, evidence, cap = js_libraries.HostLibraries({'jquery': record}).judge('jQuery', '1.12.4')
        self.assertEqual((skip, evidence['copy_state'], cap), (False, 'unresolved', js_libraries.UNRESOLVED_CAP))

    def test_a_file_name_never_beats_a_banner_for_which_copy_runs(self):
        page = '<script src="/js/jquery-1.12.4.min.js"></script><script src="/js/jquery-3.7.1.min.js"></script>'
        record = read(page, {'/js/jquery-1.12.4.min.js': JQ_341_MIN.replace('3.4.1', '1.12.4'), '/js/jquery-3.7.1.min.js': NO_BANNER})['jquery']
        self.assertTrue(record['copies_unresolved'])
        self.assertEqual({c['version']: c['source'] for c in record['copies']}, {'1.12.4': 'body', '3.7.1': 'filename'})

    def test_a_commented_out_copy_is_not_a_copy(self):
        page = ('<script src="/js/jquery-1.12.4.min.js"></script>\n'
                '<!-- upgrade pending: <script src="/js/jquery-3.7.1.min.js"></script> -->')
        asked = []
        record = read(page, {'/js/jquery-1.12.4.min.js': '/*! jQuery v1.12.4 | (c) jQuery Foundation */'}, asked)['jquery']
        self.assertEqual([(c['version'], c['state']) for c in record['copies']], [('1.12.4', 'effective')])
        self.assertEqual(asked, ['https://www.rt.test/js/jquery-1.12.4.min.js'])

    def test_a_document_write_fallback_never_replaces_the_copy_that_loaded(self):
        page = ('<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>'
                '<script>window.jQuery || document.write(\'<script src="/js/jquery-1.8.3.min.js"><\\/script>\')</script>')

        def fetch(url, headers=None):
            version = '3.7.1' if '3.7.1' in url else '1.8.3'
            return {'status': 200, 'body': f'/*! jQuery v{version} | (c) */'}
        entries = js_libraries.parse_page(page, PAGE_URL)
        record = js_libraries.read_page(entries, PAGE_URL, fetch, lambda u: '', {'left': 6}, reader=reader())['jquery']
        self.assertEqual([(c['version'], c['state']) for c in record['copies']], [('3.7.1', 'effective'), ('1.8.3', 'fallback')])
        self.assertEqual(record['version'], '3.7.1')
        skip, evidence, cap = js_libraries.HostLibraries({'jquery': record}).judge('jQuery', '1.8.3')
        self.assertEqual((skip, evidence['copy_state'], cap), (False, 'fallback', js_libraries.SHADOWED_CAP))

    def test_tags_inside_script_text_nomodule_and_quoted_attributes(self):
        html = ('<script src="https://www.rt.test/a/jquery-1.8.3.min.js"></script>'
                '<script nomodule src="/legacy/jquery-1.4.js"></script>'
                '<script>var t = "<script src=\'/js/jquery-1.2.js\'></script>";</script>'
                '<script data-x=" type=foo" src="/js/jquery.min.js?ver=1.0.4"></script>'
                '<script src="javascript:alert(1)"></script><script src="https://evil.test\\@www.rt.test/jquery.js"></script>'
                '<script src="https://a.test@evil.test/jquery.js"></script>'
                '<script src=" https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js "></script>')
        urls = [e['url'] for e in js_libraries.parse_page(html, PAGE_URL) if e['url']]
        self.assertEqual(urls, ['https://www.rt.test/a/jquery-1.8.3.min.js', 'https://www.rt.test/js/jquery.min.js?ver=1.0.4',
                                'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js'])

    def test_the_reviews_hostile_inputs_stay_fast(self):
        import time
        n = 300 * 1024
        bodies = [('a' * 30 + '.fn=').ljust(40) * (n // 40), ('abc.fn=abc.prototype={' + ' ' * 5000) * (n // 5000), ' ' * n, '*' * n,
                  '\n *' * (n // 3), ('jQuery UI ' + 'A' * 20 + ' ') * (n // 31), ('.extend( ' + 'a' * 30 + '.ui ,{ version : ') * (n // 60),
                  'Modal.VERSION        ' * (n // 21), ('a.fn=a.prototype={' + 'jquery:' + 'b' * 31) * (n // 60), 'a' * n,
                  ('a.fn' + ' ' * 8 + '=' + ' ' * 8 + 'a.prototype' + ' ' * 8 + '=' + ' ' * 8) * (n // 60), ' \t' * (n // 2)]
        pages = [('<script ' + 'a' * 1999) * (256 * 1024 // 2006), ('<script>' + '.noConflict( ' * 5000 + '</script>') * 4,
                 '<script>' * (256 * 1024 // 8), ('<script src= ' + ' ' * 1990 + '>') * 130, '<script type=x>' * 17000,
                 ('<script>' + 'x' * 60000) * 5, '<!--' * 60000, ('<!-- -->' + '<script>') * 30000]
        for body in bodies:
            started = time.monotonic()
            js_libraries.read_body(body)
            self.assertLess(time.monotonic() - started, 0.5, body[:40])
        for page in pages:
            started = time.monotonic()
            js_libraries.parse_page(page, PAGE_URL)
            self.assertLess(time.monotonic() - started, 0.5, page[:40])
        started = time.monotonic()
        js_libraries.identify('https://x.com/' + 'a/' * 5000 + 'jquery' + '.min' * 1000 + '.js?' + 'v=1&' * 10000)
        self.assertLess(time.monotonic() - started, 0.5)


class BudgetTests(NoCache, SimpleTestCase):
    def test_a_script_url_shared_by_many_page_hosts_is_read_once_per_scan(self):
        asked, scan = [], reader()
        for _host in range(3):  # three page hosts that load one shared static file
            read('<script src="/js/jquery-3.4.1.min.js"></script>', {'/js/jquery-3.4.1.min.js': JQ_341_MIN}, asked, scan=scan)
        self.assertEqual(len(asked), 1)

    def test_the_scan_request_limit_and_the_script_host_limit(self):
        page = ''.join(f'<script src="/js/jquery-3.{i}.0.js"></script>' for i in range(6))
        asked = []
        read(page, {}, asked, scan=reader(max_requests=2))
        self.assertEqual(len(asked), 2)
        asked, scan = [], reader()
        with mock.patch.object(js_libraries, 'MAX_PER_SCRIPT_HOST', 3):
            for _host in range(2):
                read(page, {}, asked, budget={'left': 6}, scan=scan)
        self.assertEqual(len(asked), 3)

    def test_the_scan_time_limit(self):
        now = [0.0]
        scan = js_libraries.Reader(max_seconds=10, clock=lambda: now[0], sleep=lambda s: None)
        now[0] = 11.0
        asked = []
        record = read('<script src="/js/jquery-3.4.1.min.js"></script>', {}, asked, scan=scan)['jquery']
        self.assertEqual(asked, [])
        self.assertEqual(record['copies'][0]['not_read'], 'scan time limit')

    def test_requests_to_one_script_host_are_spaced(self):
        waits = []
        scan = js_libraries.Reader(clock=lambda: 100.0, sleep=waits.append)
        for i in range(3):
            self.assertEqual(scan.admit(f'https://static.example.com/{i}.js'), '')
        self.assertEqual(scan.admit('https://other.example.com/x.js'), '')
        self.assertEqual(waits, [js_libraries.SCRIPT_HOST_GAP, 2 * js_libraries.SCRIPT_HOST_GAP])

    def test_the_off_switch_reads_nothing_and_keeps_the_file_name_hint(self):
        asked = []
        with mock.patch.dict('os.environ', {'CVENGINE_SCRIPT_BODY_READ': '0'}):
            vet = js_libraries.vetter(PAGE_URL)
            entries = js_libraries.parse_page('<script src="/js/jquery-3.4.1.min.js"></script>', PAGE_URL)
            record = js_libraries.read_page(entries, PAGE_URL, fetcher({}, asked), vet, {'left': 6}, reader=reader())['jquery']
        self.assertEqual(asked, [])
        self.assertEqual((record['version'], record['version_source'], record['copies'][0]['not_read']),
                         ('3.4.1', 'filename', 'script reading is off'))


class CacheTests(SimpleTestCase):
    URL = 'https://www.rt.test/js/jquery.min.js'
    CDN = 'https://code.jquery.com/jquery-3.4.1.min.js'

    def setUp(self):
        super().setUp()
        keys = [js_libraries._cache_key(self.URL, p) for p in (1, 2)] + [js_libraries._cache_key(self.CDN, 1)]
        cache.delete_many(keys)
        self.addCleanup(cache.delete_many, keys)
        patcher = mock.patch.object(js_libraries, '_cache', return_value=cache)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_read(self, url, project, asked, scan=None, served=JQ_341_MIN, status=200):
        def fetch(u, headers=None):
            asked.append(headers or {})
            return {'status': status, 'body': served, 'raw_headers': {'etag': '"v1"', 'content-length': '90'}}
        page = f'<script src="{url}"></script>'
        entries = js_libraries.parse_page(page, PAGE_URL)
        return js_libraries.read_page(entries, PAGE_URL, fetch, lambda u: '', {'left': 6}, reader=scan or reader(project=project))

    def test_a_projects_reading_is_never_used_for_another_project(self):
        asked = []
        self.run_read(self.URL, 1, asked)
        self.run_read(self.URL, 1, asked)
        self.assertEqual(len(asked), 1)
        self.run_read(self.URL, 2, asked)  # another tenant: its own request (its addresses, its tailnet, its proxy)
        self.assertEqual(len(asked), 2)
        self.assertNotEqual(js_libraries._cache_key(self.URL, 1), js_libraries._cache_key(self.URL, 2))
        self.assertEqual(js_libraries._cache_key(self.CDN, 1), js_libraries._cache_key(self.CDN, 2))  # a public CDN file is everyone's

    def test_a_forced_re_test_asks_again_with_the_etag_and_a_304_keeps_the_reading(self):
        asked = []
        self.run_read(self.URL, 1, asked)
        records = self.run_read(self.URL, 1, asked, scan=reader(project=1, fresh=True), served='', status=304)
        self.assertEqual(asked[-1], {'If-None-Match': '"v1"'})
        self.assertEqual(records['jquery']['version'], '3.4.1')
        records = self.run_read(self.URL, 1, asked, scan=reader(project=1, fresh=True), served=JQ_371_MIN)
        self.assertEqual(records['jquery']['version'], '3.7.1')  # the fix is seen at once

    def test_a_due_entry_is_revalidated_and_an_unversioned_cdn_url_is_due_after_a_day(self):
        self.assertEqual(js_libraries._fresh_for(self.CDN), js_libraries.CDN_CACHE_SECONDS)
        self.assertEqual(js_libraries._fresh_for('https://code.jquery.com/jquery-latest.min.js'), js_libraries.CACHE_SECONDS)
        self.assertEqual(js_libraries._fresh_for('https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js'), js_libraries.CACHE_SECONDS)
        asked = []
        self.run_read(self.URL, 1, asked)
        with mock.patch.object(js_libraries.time, 'time', return_value=js_libraries.time.time() + js_libraries.CACHE_SECONDS + 5):
            self.run_read(self.URL, 1, asked, served='', status=304)
        self.assertEqual(asked[-1], {'If-None-Match': '"v1"'})

    def test_only_the_etag_header_may_be_added_to_an_anonymous_probe(self):
        with self.assertRaises(ValueError):
            route_auth.probe_url('https://www.rt.test/x.js', headers={'Cookie': 'a=b'})
        with mock.patch.object(pinned_transport, 'resolve', side_effect=LookupError('stop before the network')):
            with self.assertRaises(LookupError):
                route_auth.probe_url('https://www.rt.test/x.js', headers={'If-None-Match': '"v1"'})


class TargetScopeTests(NoCache, RouteFixture, TestCase):
    STATIC = 'https://static.rt.test/js/jquery.js'

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'static.rt.test'))

    def test_a_host_scoped_target_never_reads_a_sibling_host(self):
        self.domain.scope_mode = 'host'
        self.assertEqual(js_libraries.vetter(PAGE_URL, self.project.id, target=self.domain)(self.STATIC), 'host-scoped target')
        self.assertEqual(js_libraries.vetter(PAGE_URL, self.project.id, target=self.domain)('https://www.rt.test/js/jquery.js'), '')

    def test_a_host_the_project_does_not_hold_or_holds_only_manually_is_not_read(self):
        from targetApp.models import Domain
        self.assertEqual(js_libraries.vetter(PAGE_URL, self.project.id, target=self.domain)('https://cdn2.rt.test/jquery.js'),
                         'not a host of this project')
        manual = Domain.objects.create(name='manual.test', project=self.project, insert_date=self.domain.insert_date,
                                       discovery_mode=Domain.DISCOVERY_MANUAL)
        Subdomain.objects.filter(name='static.rt.test').update(target_domain=manual)
        self.assertEqual(js_libraries.vetter(PAGE_URL, self.project.id, target=self.domain)(self.STATIC), 'not a host of this project')

    def test_a_passive_or_manual_target_reads_nothing(self):
        for mode in ('passive', 'manual'):
            self.domain.discovery_mode = mode
            self.assertEqual(js_libraries.vetter(PAGE_URL, self.project.id, target=self.domain)('https://www.rt.test/js/jquery.js'), f'{mode} target')

    def test_only_web_ports(self):
        vet = js_libraries.vetter(PAGE_URL, self.project.id, target=self.domain)
        self.assertEqual(vet('https://static.rt.test:6379/jquery.js'), 'port')
        self.assertEqual(vet('https://www.rt.test:8443/jquery.js'), 'port')
        self.assertEqual(js_libraries.vetter('https://www.rt.test:8443/', self.project.id, target=self.domain)('https://www.rt.test:8443/a.js'), '')
        self.assertEqual(vet('http://static.rt.test:80/jquery.js'), '')

    def test_a_tenant_of_a_shared_platform_is_never_the_same_site(self):
        for page, other in (('https://victim.blogspot.com/', 'https://other.blogspot.com/jquery.js'),
                            ('https://victim.onrender.com/', 'https://other.onrender.com/jquery.js'),
                            ('https://mine.herokuapp.com/', 'https://other.herokuapp.com/x.js'),
                            ('https://a.github.io/', 'https://b.github.io/jquery.js')):
            self.assertEqual(js_libraries.kind_of(other, page), 'third-party', other)


class LegacyAndWorkedTests(RouteFixture, TestCase):
    def test_a_front_page_read_before_1_3_2_is_checked_again_once(self):
        from django.utils import timezone
        self.scan()
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.rt.test', path='/', url=PAGE_URL, auth_state='open',
                                 http_status=200, checked_at=timezone.now(),
                                 evidence={'fingerprints': [{'name': 'jQuery:1.0.4', 'source': 'script:name'}]})
        from cveFeed import ledger
        self.assertEqual(route_auth._legacy_root_urls(self.project.id, [PAGE_URL, 'https://www.rt.test/login']), {ledger._norm(PAGE_URL)})
        RouteAuth.objects.filter(url=PAGE_URL).update(evidence={'fingerprints': [{'name': 'jQuery:3.7.1', 'source': 'script:body'}],
                                                                 'libraries': {}})
        self.assertEqual(route_auth._legacy_root_urls(self.project.id, [PAGE_URL]), set())

    def test_a_library_match_a_person_worked_is_never_closed_by_a_new_reading(self):
        from cveFeed.models import CVEEntry, CVEMatch
        scan = self.scan()
        sub = Subdomain.objects.get(scan_history=scan)
        cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', status='PUBLISHED', original_description='x')
        worked = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='jquery', matched_version='1.0.4',
                                         version_in_range=True, confidence=0.95, remediation_status='in_progress')
        untouched = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='jQuery', matched_version='1.0.5',
                                            version_in_range=True, confidence=0.95)
        correlation.close_stale({}, ({sub.id}, {cve.id}))
        worked.refresh_from_db()
        untouched.refresh_from_db()
        self.assertEqual((worked.ai_verdict, worked.remediation_status), ('', 'in_progress'))
        self.assertEqual(untouched.ai_verdict, 'not_affected')


class ProbePageTests(NoCache, SimpleTestCase):
    def test_the_libraries_probe_reads_no_scripts_of_an_error_or_challenge_page(self):
        from tests.test_probes import answers, page
        for first in (page(404, body=TWO_COPIES), {**page(body=TWO_COPIES), 'challenge': 'Cloudflare'}):
            asked = []

            def get(url, first=first):
                asked.append(url)
                return first if url.endswith('/') else answers({})(url)
            found = probes.run_http_probe('html-libraries', 'https://www.rt.test', {'www.rt.test'}, get=get, sleep=lambda s: None)
            self.assertEqual([o for o in found if o['kind'] == 'version'], [])
            self.assertEqual(asked, ['https://www.rt.test/'])
