"""Regression tests from the independent review of PR #391: a genuine library or template match never closes, or is read as a version check, on partial evidence. Each test asserts the safe outcome."""
from django.utils import timezone

from cveFeed import js_libraries
from cveFeed.models import CVEMatch, RouteAuth
from startScan.models import ScanHistory, Subdomain
from tests.test_js_libraries_provenance import ReviewScenarioBase
from tests.test_js_library_versions import JQ_371_MIN

FILLER = 'var _app_code_' + 'x' * 80 + '=function(){return 1};\n'
# jQuery 1.12.4's own minified code with its banner stripped (webpack/terser extracts licence comments to app.js.LICENSE.txt):
# only the prototype signature names it
JQ_1124_NOBANNER = '!function(a,b){var d="1.12.4",n=function(a,b){return new n.fn.init(a,b)};n.fn=n.prototype={jquery:d,constructor:n,length:0}}(window);'
WEBPACK_HEAD = '/*! For license information please see app.js.LICENSE.txt */\n'


def filler(n):
    return FILLER * (n // len(FILLER) + 1)


# every page here explains the technology scan's 1.12.4 (a script's ?ver=), so only the rule under test keeps the match open
EXPLAINS = '<script src="/site.js?ver=1.12.4"></script>'
PAGE = '<script src="/js/jquery.min.js"></script><script src="/dist/app.js"></script>' + EXPLAINS  # core jQuery 3.7.1 file, the app bundle


class NotAJqueryCopyButCarriesOne(ReviewScenarioBase):
    """The page's one jQuery-named file says 3.7.1 (read whole); a same-host bundle that is not recognised as a jQuery copy carries
    jQuery 1.12.4 (the version the technology scan reported). The tech version is genuine and must not close."""

    def _run(self, host, app, served=True):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        scripts = {f'https://{host}/dist/app.js': app} if served else {}
        self.read_root(host, 200, PAGE, scripts=scripts)
        self.assertEqual(RouteAuth.objects.get(host=host).evidence['script_page']['unread'], 1)  # the bundle is not known whole
        return self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]

    def test_p1_bannerless_jquery_past_128k_in_app_bundle(self):
        m = self._run('p1.x.test', filler(140000) + JQ_1124_NOBANNER)
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_p1b_webpack5_licence_extracted_bundle(self):
        m = self._run('p1b.x.test', WEBPACK_HEAD + filler(140000) + JQ_1124_NOBANNER)
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_p2_app_bundle_cut_at_the_read_limit(self):
        m = self._run('p2.x.test', filler(js_libraries.MAX_SCRIPT_BYTES + 2000) + '/*! jQuery v1.12.4 | (c) jQuery Foundation */\n' + JQ_1124_NOBANNER)
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_p3_app_bundle_not_served(self):
        m = self._run('p3.x.test', '', served=False)
        self.assertNotEqual(m.ai_verdict, 'not_affected')


class SecondCopyInTheSameFile(ReviewScenarioBase):
    """A file whose banner says jQuery 3.7.1 and which carries a second, bannerless jQuery 1.12.4 further in, at any offset."""

    def _run(self, host, bundle):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, '<script src="/js/vendor.js"></script>' + EXPLAINS, scripts={f'https://{host}/js/vendor.js': bundle})
        copies = RouteAuth.objects.get(host=host).evidence['libraries']['jquery']['copies']
        self.assertEqual([(c['version'], c['whole']) for c in copies], [('3.7.1', False)])  # a second copy further in: not known whole
        return self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]

    def test_p4_bannered_371_then_bannerless_1124_within_128k(self):
        m = self._run('p4.x.test', JQ_371_MIN + '\n' + filler(60000) + JQ_1124_NOBANNER)
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_p4b_bannered_371_then_bannerless_1124_past_128k(self):
        m = self._run('p4b.x.test', JQ_371_MIN + '\n' + filler(150000) + JQ_1124_NOBANNER)
        self.assertNotEqual(m.ai_verdict, 'not_affected')


class VouchOnAlias(ReviewScenarioBase):
    def test_v1_alias_closure_held_by_earlier_rows_vouch(self):
        from django.contrib.auth import get_user_model
        from cveFeed.tasks import reconcile_library_provenance, reconcile_invalid_correlations
        user = get_user_model().objects.create(username='v1')
        sub = self.host('al.x.test', ['jQuery:1.12.4'])
        m = self.correlate(sub)[('al.x.test', 'CVE-2020-11023', '1.12.4')]
        CVEMatch.objects.filter(pk=m.pk).update(assignee=user)
        self.host('elsewhere.x.test', [])  # an alias closes only to a host the project inventories
        self.read_root('al.x.test', 301, '', location='https://elsewhere.x.test/')
        self.correlate(sub)
        scan = ScanHistory.objects.create(domain=self.site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='y')
        later = Subdomain.objects.create(name='al.x.test', target_domain=self.site, scan_history=scan)
        later.ip_addresses.add(*sub.ip_addresses.all())
        later.technologies.add(*sub.technologies.all())
        CVEMatch.objects.filter(pk=m.pk).update(assignee=user)
        self.correlate(later)
        reconcile_library_provenance()
        reconcile_invalid_correlations(limit=100)
        row = CVEMatch.objects.filter(subdomain=later).first()
        self.assertIsNotNone(row)
        self.assertNotEqual(row.ai_verdict, 'not_affected')

    def test_v2_comment_vouch_survives_invalid_correlation_sweep(self):
        from cveFeed.models import FindingComment
        from cveFeed.tasks import reconcile_invalid_correlations
        sub = self.host('vs2.x.test', ['jQuery:1.12.4'])
        m = self.correlate(sub)[('vs2.x.test', 'CVE-2020-11023', '1.12.4')]
        FindingComment.objects.create(project=self.project, finding_kind='match', finding_id=m.pk, text='seen on checkout')
        self.read_root('vs2.x.test', 200, '<script src="/js/jquery.min.js"></script>')
        scan = ScanHistory.objects.create(domain=self.site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='y')
        later = Subdomain.objects.create(name='vs2.x.test', target_domain=self.site, scan_history=scan)
        later.ip_addresses.add(*sub.ip_addresses.all())
        later.technologies.add(*sub.technologies.all())
        self.correlate(later)
        reconcile_invalid_correlations(limit=100)
        row = CVEMatch.objects.filter(subdomain=later).first()
        self.assertIsNotNone(row)
        self.assertNotEqual(row.ai_verdict, 'not_affected')




from django.test import SimpleTestCase  # noqa: E402

from cveFeed import templategen  # noqa: E402


def _tpl(name, path, regex, marker=None):
    extra = f"      - type: word\n        words: [{marker}]\n" if marker else ''
    return (f'id: CVE-2099-2000\ninfo: {{name: "{name}", severity: high}}\nhttp:\n  - method: GET\n    path: ["{{{{BaseURL}}}}{path}"]\n'
            f'    matchers-condition: and\n    matchers:\n{extra}      - type: regex\n        regex: [\'{regex}\']\n')


class MarkerWordsFromTheVulnerabilityTitle(SimpleTestCase):
    """B2: the words beside the version matcher may only name the product. info.name's vulnerability title is not the product."""

    def test_c1_email_disclosure_marker(self):
        t = _tpl('Acme Portal - Email Address Disclosure', '/api/v1/team', r'apiVersion.{0,3}1\.[0-4]\.\d', 'email')
        self.assertEqual(templategen.template_evidence(t), templategen.BEHAVIOR_EVIDENCE)

    def test_c1b_directory_listing_marker(self):
        t = _tpl('Acme Router - Directory Listing Enabled', '/files/', r'Acme/2\.[0-3]', 'Directory Listing')
        self.assertEqual(templategen.template_evidence(t), templategen.BEHAVIOR_EVIDENCE)

    def test_c1c_stack_trace_marker(self):
        t = _tpl('Acme Portal - Stack Trace Disclosure', '/', r'Acme 1\.[0-4]\.\d', 'Stack Trace')
        self.assertEqual(templategen.template_evidence(t), templategen.BEHAVIOR_EVIDENCE)


class ExposurePagesNotListed(SimpleTestCase):
    """Follow-up: exposure pages the deny-list misses."""

    def test_e_paths(self):
        for path, regex in (('/config.json', r'acmeVersion.{0,4}2\.[0-3]\.\d'), ('/WEB-INF/web.xml', r'acme-version.3\.1\.\d'),
                            ('/env', r'java\.version.{0,3}1\.8\.\d'), ('/jolokia/version', r'agent.{0,3}1\.[0-6]\.\d'),
                            ('/trace.axd', r'ASP\.NET Version:4\.0\.\d'), ('/.htpasswd', r'apr1.1\.\d'), ('/metrics', r'go1\.1[0-9]')):
            with self.subTest(path=path):
                self.assertEqual(templategen.template_evidence(_tpl('Acme - Exposure', path, regex)), templategen.BEHAVIOR_EVIDENCE)

    def test_status_line_without_slash(self):
        t = _tpl('Acme', '/', r'^HTTP.1\.0 200')
        self.assertEqual(templategen.template_evidence(t), templategen.BEHAVIOR_EVIDENCE)


class StatedAnywhereTests(SimpleTestCase):
    """Part (a) of the fix on its own: the whole read body is searched for every library's banner and code signature."""

    def test_a_bannerless_second_copy_at_any_offset_makes_the_file_not_whole(self):
        for gap in (0, 60000, 150000, js_libraries.MAX_SCRIPT_BYTES - 1000):
            text = JQ_371_MIN + '\n' + filler(gap)[:gap] + JQ_1124_NOBANNER
            with self.subTest(gap=gap):
                found = js_libraries.read_body(text)
                self.assertEqual(found, [('jquery', '3.7.1', 'banner')])
                self.assertIn(('jquery', '1.12.4'), js_libraries._stated_anywhere(text))
                self.assertFalse(js_libraries._states_all(text, found))

    def test_a_second_signature_of_another_library_past_the_first_bytes(self):
        text = JQ_371_MIN + '\n' + filler(140000) + 'var Modal=1;Modal.VERSION="3.3.7";'
        self.assertFalse(js_libraries._states_all(text, js_libraries.read_body(text)))

    def test_the_same_version_stated_twice_is_still_whole(self):
        text = '/*! jQuery v1.12.4 | (c) jQuery Foundation */\n' + JQ_1124_NOBANNER
        found = js_libraries.read_body(text)
        self.assertEqual(found, [('jquery', '1.12.4', 'banner')])
        self.assertTrue(js_libraries._states_all(text, found))

    def test_what_counts_as_read_whole(self):
        self.assertTrue(js_libraries.read_whole({'sha256': 'x', 'whole': True, 'loaders': []}))
        for read in (None, {}, {'sha256': '', 'whole': True, 'loaders': []}, {'sha256': 'x', 'whole': False, 'loaders': []}, {'sha256': 'x'}):
            self.assertFalse(js_libraries.read_whole(read), read)


class EveryScriptOfThePageTests(ReviewScenarioBase):
    """Part (b) of the fix on its own: the page's jQuery file, read whole, contradicts nothing while any other script of the page (of any
    host, a copy of the library or not) or any inline script is not read whole."""

    def _closed(self, host, page, scripts=None):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, page + EXPLAINS, scripts=scripts)
        m = self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]
        # file evidence never closes (only a redirect alias does): whether the page's files, read whole, contradict the version shows in
        # the match's note, the match stays a candidate at the file-name confidence either way
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
        return (m.evidence.get('version_note') or '').startswith(("the page's own scripts state", 'the script named'))

    def test_the_page_read_whole_still_contradicts_it_in_the_note(self):
        self.assertTrue(self._closed('w0.x.test', '<script src="/js/jquery.min.js"></script>'))

    def test_a_third_party_script_never_read(self):
        page = '<script src="/js/jquery.min.js"></script><script src="https://widgets.partner.example/embed.js"></script>'
        self.assertFalse(self._closed('w1.x.test', page))
        self.assertEqual(RouteAuth.objects.get(host='w1.x.test').evidence['script_page']['unread'], 1)

    def test_a_same_host_script_that_states_more_than_was_recognised(self):
        page = '<script src="/js/jquery.min.js"></script><script src="/js/widgets.js"></script>'
        self.assertFalse(self._closed('w2.x.test', page, {'https://w2.x.test/js/widgets.js': '/*! acme-widgets v2.0.1 */\nvar w=1;'}))

    def test_an_inline_script_not_read(self):
        page = '<script src="/js/jquery.min.js"></script><script>/*! acme-tracker v1 | (c) 2024 */ var t=1;</script>'
        self.assertFalse(self._closed('w3.x.test', page))
        self.assertEqual(RouteAuth.objects.get(host='w3.x.test').evidence['script_page']['inline_unread'], 1)

    def test_a_script_over_the_read_budget(self):
        page = '<script src="/js/jquery.min.js"></script>' + ''.join(f'<script src="/s{i}.js"></script>' for i in range(5))
        scripts = {f'https://w4.x.test/s{i}.js': 'var s=1;' for i in range(5)}  # with the jQuery file and site.js, seven: one over six
        self.assertFalse(self._closed('w4.x.test', page, scripts))
        self.assertGreater(RouteAuth.objects.get(host='w4.x.test').evidence['script_page']['unread'], 0)

    def test_the_counts_rule(self):
        read = js_libraries.every_script_read
        self.assertTrue(read({'scripts': 3, 'unread': 0, 'inline_unread': 0, 'loaders': []}))
        self.assertTrue(read({'scripts': 0, 'inline_unread': 0, 'loaders': []}))  # no script with a source: nothing to read
        for page in ({'scripts': 3, 'inline_unread': 0, 'loaders': []}, {'scripts': 3, 'unread': 1, 'inline_unread': 0, 'loaders': []},
                     {'scripts': 3, 'unread': 0, 'inline_unread': 2, 'loaders': []}, {'scripts': 3, 'unread': 0, 'loaders': []},
                     {'scripts': 3, 'unread': '0', 'inline_unread': 0, 'loaders': []},
                     {'scripts': 3, 'unread': False, 'inline_unread': 0, 'loaders': []},
                     {'scripts': 3, 'unread': 0, 'inline_unread': 0}, {'scripts': 3, 'unread': 0, 'inline_unread': 0, 'loaders': ['module script']}):
            self.assertFalse(read(page), page)


class ContradictsRuleTests(SimpleTestCase):
    """``HostLibraries._contradicts`` with the page known whole: an unresolved set of copies, or no copy that runs, contradicts nothing."""

    COPY = {'url': 'https://h.test/js/jquery.min.js', 'version': '3.7.1', 'source': 'body', 'whole': True, 'state': 'effective'}

    def judge(self, record, page_read=True):
        # the page explains 1.12.4 (a script URL carries it): only the copies decide here. Nothing closes on file evidence: whether the copies
        # contradict the version shows in the note
        skip, evidence, cap = js_libraries.HostLibraries({'jquery': record}, page_read=page_read, page_versions={'1.12.4'}).judge('jQuery', '1.12.4')
        self.assertEqual((skip, cap), (False, js_libraries.CONFIDENCE['filename']))
        return (evidence.get('version_note') or '').startswith("the page's own scripts state")

    def test_the_whole_page_with_one_effective_copy_contradicts_it(self):
        self.assertTrue(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies': [dict(self.COPY)]}))

    def test_unresolved_copies_contradict_nothing(self):
        copies = [{**self.COPY, 'state': 'unresolved'}, {**self.COPY, 'version': '3.6.0', 'url': 'https://h.test/b.js', 'state': 'unresolved'}]
        self.assertFalse(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies_unresolved': True, 'copies': copies}))
        # the flag alone holds it, whatever the copies' own states say
        copies = [{**self.COPY, 'state': 'shadowed'}, dict(self.COPY)]
        self.assertFalse(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies_unresolved': True, 'copies': copies}))

    def test_no_copy_that_runs_contradicts_nothing(self):
        for state in ('fallback', 'shadowed', 'unresolved', ''):
            with self.subTest(state=state):
                self.assertFalse(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies': [{**self.COPY, 'state': state}]}))

    def test_a_copy_not_read_whole_contradicts_nothing(self):
        # a copy another reading recorded (the libraries probe, an earlier front page) that was cut or carries more than it states holds
        # the closure even where the route check's own page counts say every script was read
        for copy in ({**self.COPY, 'whole': False}, {k: v for k, v in self.COPY.items() if k != 'whole'},
                     {**self.COPY, 'source': 'filename'}, {**self.COPY, 'version': ''}):
            with self.subTest(copy=copy):
                self.assertFalse(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies': [copy]}))
        later = {**self.COPY, 'url': 'https://h.test/b.js', 'whole': False, 'state': 'shadowed'}
        self.assertFalse(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies': [later, dict(self.COPY)]}))

    def test_a_page_not_known_whole_contradicts_nothing(self):
        self.assertFalse(self.judge({'version': '3.7.1', 'version_source': 'body', 'copies': [dict(self.COPY)]}, page_read=False))


class IdentityFromTheProductTests(SimpleTestCase):
    """B2: only the product part of info.name (before its first dash), metadata vendor and product and the CPE's product name it."""

    def doc(self, name, metadata=None, cpe=''):
        info = {'name': name, **({'metadata': metadata} if metadata else {}), **({'classification': {'cpe': cpe}} if cpe else {})}
        return {'info': info}

    def test_the_tokens(self):
        tokens = templategen._identity_tokens
        self.assertEqual(tokens(self.doc('Acme Portal - Email Address Disclosure')), {'acme', 'portal'})
        self.assertEqual(tokens(self.doc('Acme Portal – Email Disclosure')), {'acme', 'portal'})
        self.assertEqual(tokens(self.doc('Acme Portal Email Disclosure')), set())  # no dash: the title cannot be told from the product
        self.assertEqual(tokens(self.doc('Acme Email Disclosure', {'vendor': 'acme', 'product': 'portal'})), {'acme', 'portal'})
        self.assertEqual(tokens(self.doc('X - Y', cpe='cpe:2.3:a:somevendor:someproduct:*:*')), {'someproduct'})

    def test_the_corpus_version_templates_still_classify_version(self):
        import os
        root = os.path.join(os.path.dirname(__file__), 'fixtures', 'nuclei_templates')
        for name in ('CVE-2021-27651.yaml', 'CVE-2022-29455.yaml'):
            with open(os.path.join(root, name), encoding='utf-8') as handle:
                self.assertEqual(templategen.template_evidence(handle.read()), templategen.VERSION_EVIDENCE, name)

    def test_a_marker_word_from_a_title_with_no_dash(self):
        t = _tpl('Acme Portal Email Address Disclosure', '/api/v1/team', r'apiVersion.{0,3}1\.[0-4]\.\d', 'email')
        self.assertEqual(templategen.template_evidence(t), templategen.BEHAVIOR_EVIDENCE)

    def test_a_product_word_still_names_the_product(self):
        t = _tpl('Acme Portal - Email Address Disclosure', '/about', r'Acme Portal 1\.[0-4]\.\d', 'Acme Portal')
        self.assertEqual(templategen.template_evidence(t), templategen.VERSION_EVIDENCE)


class StatusLineAndExtractorTests(SimpleTestCase):
    def test_status_lines_in_every_regex_form(self):
        for regex in (r'^HTTP/1\.[01] 200', r'HTTP\/1\.1 200', r'HTTP[/]1\.1', r'^HTTP.1\.0 200', r'(?i)http/2\.0', r'HTTP/\d\.\d 200'):
            with self.subTest(regex=regex):
                self.assertEqual(templategen.template_evidence(_tpl('Acme', '/', regex)), templategen.BEHAVIOR_EVIDENCE)

    def test_a_product_called_http_something_is_not_a_status_line(self):
        for text in ('Apache HTTP Server 2.4.49', 'IBM_HTTP_Server/8.5.5', 'HTTPd/2.4.1'):
            self.assertIsNone(templategen._STATUS_LINE.search(text), text)

    def test_a_capture_of_anything_is_not_a_version(self):
        for pattern in (r'Version: (.+\d.+)', r'v(\w+\.\d+)', r'(\d.*)', r'([0-9a-z.]+)', r'(\S+\.\d)'):
            self.assertFalse(templategen._version_shaped(pattern), pattern)
        for pattern in (r'Version: ([0-9.]+)', r'(\d+\.\d+\.\d+)', r'v([\d.]+)', r'([0-9]+\.[0-9]{1,3})', r'([0-9.]+)_([A-Z_0-9]+)'):
            self.assertTrue(templategen._version_shaped(pattern), pattern)


class LoadedAtRuntime(ReviewScenarioBase):
    """A copy no script tag references, loaded by a same-host script at run time (a script loader, a module import, a webpack lazy chunk).
    The technology scan (a browser) sees the runtime jQuery 1.12.4; the static page has only the core 3.7.1 file. The page explains 1.12.4
    (a ?ver= string), so only the run-time loader keeps the match open here."""

    def _run(self, host, page, scripts):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, page + EXPLAINS, scripts=scripts)
        self.assertEqual(RouteAuth.objects.get(host=host).evidence['script_page']['unread'], 1)  # the loading script is not known whole
        return self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]

    def test_p5_script_loader(self):
        host = 'p5.x.test'
        loader = ("(function(){var s=document.createElement('script');s.src='/js/legacy/jquery-1.12.4.min.js';"
                  "s.onload=function(){window.legacy$=jQuery.noConflict(true)};document.head.appendChild(s)})();")
        m = self._run(host, '<script src="/js/jquery.min.js"></script><script src="/js/loader.js"></script>',
                      {f'https://{host}/js/loader.js': loader})
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_p5b_module_import(self):
        host = 'p5b.x.test'
        main = "import $ from './vendor/jquery-1.12.4.js';\n$(function(){ $('.x').show(); });\n"
        m = self._run(host, '<script src="/js/jquery.min.js"></script><script type="module" src="/js/main.js"></script>',
                      {f'https://{host}/js/main.js': main})
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_p5c_webpack_lazy_chunk(self):
        host = 'p5c.x.test'
        runtime = ('(()=>{var e={},r={};function t(o){var n=r[o];if(void 0!==n)return n.exports;var a=r[o]={exports:{}};return e[o](a,a.exports,t),'
                   'a.exports}t.u=e=>"static/js/"+e+"."+{512:"3f9a1c"}[e]+".chunk.js",t.e=e=>Promise.all([]);t.e(512).then(t.bind(t,7512))})();')
        m = self._run(host, '<script src="/js/jquery.min.js"></script><script src="/static/js/main.4b1d.js"></script>',
                      {f'https://{host}/static/js/main.4b1d.js': runtime})
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_an_inline_loader_and_an_import_map(self):
        for host, extra in (('p5d.x.test', "<script>var s=document.createElement('script');s.src=window.legacyUrl;document.head.appendChild(s);</script>"),
                            ('p5e.x.test', '<script type="importmap">{"imports":{"jquery":"/js/vendor/jq.js"}}</script>'),
                            ('p5f.x.test', '<svg><script href="/js/legacy.js"></script></svg>')):
            with self.subTest(host=host):
                sub = self.host(host, ['jQuery:1.12.4'])
                self.correlate(sub)
                self.read_root(host, 200, '<script src="/js/jquery.min.js"></script>' + extra + EXPLAINS)
                self.assertEqual(RouteAuth.objects.get(host=host).evidence['script_page']['inline_unread'], 1)
                self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')


class RuntimeLoaderRuleTests(SimpleTestCase):
    def test_each_kind_of_loader(self):
        for code in ("var s=document.createElement('script');s.src=u;", 'import("./chunk-a1.js").then(f)', "import $ from './jq.js';",
                     "export { a } from './a.js';", '$.getScript(url)', 'require(["legacy"], function(l){})', 'define(["jquery"], function($){})',
                     'System.import("app")', '__webpack_require__.e(12)', '(self.webpackChunkapp=self.webpackChunkapp||[]).push([])',
                     't.e=e=>Promise.all([])', 'navigator.serviceWorker.register(sw)', 'importScripts(x)', 'var u = "/js/widget.js";',
                     "var p = 'vendor/jquery-1.12.4.min';", 'requirejs.config({baseUrl:"/js"})', 'new Worker(url)'):
            with self.subTest(code=code):
                self.assertTrue(js_libraries.runtime_loaders(code), code)

    def test_what_is_no_loader(self):
        for code in ('if(e==="import")return t;', 'var k="require";', "x.type==='define'", '// var jQuery = require("jquery")(window);',
                     '"function"==typeof define&&define.amd&&define("jquery",[],function(){return n})',
                     '"object"==typeof module&&module.exports?module.exports=t(require("jquery")):t(jQuery)',
                     'var o=C.createElement("script");o.text=e;C.head.appendChild(o).parentNode.removeChild(o)',
                     'throw new Error("requires at least jQuery v1.9.1")', 'var a="http://errors.angularjs.org/1.8.3/"', 'var a=1;'):
            with self.subTest(code=code):
                self.assertEqual(js_libraries.runtime_loaders(code), [], code)

    def test_a_reading_before_loaders_were_looked_for_is_not_whole(self):
        self.assertFalse(js_libraries.read_whole({'sha256': 'x', 'whole': True}))
        self.assertFalse(js_libraries.read_whole({'sha256': 'x', 'whole': True, 'loaders': ['import()']}))
        self.assertTrue(js_libraries.read_whole({'sha256': 'x', 'whole': True, 'loaders': []}))


class ExplainedByThePageTests(ReviewScenarioBase):
    """Decision 2: the contradicted-by-file closure closes only a technology-scan version this front page itself explains."""

    def _verdict(self, host, page, version='1.12.4', scripts=None):
        sub = self.host(host, [f'jQuery:{version}'])
        self.correlate(sub)
        self.read_root(host, 200, page, scripts=scripts)
        return self.correlate(sub)[(host, 'CVE-2020-11023', version)]

    def test_a_version_the_page_does_not_explain_stays_a_capped_candidate(self):
        m = self._verdict('ex0.x.test', '<script src="/js/jquery.min.js"></script><script src="/site.js"></script>')
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))

    def test_a_query_string_version_explains_it(self):
        m = self._verdict('ex1.x.test', '<script src="/js/jquery.min.js"></script><script src="/site.js?ver=1.12.4"></script>')
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))  # informs and caps, never closes
        self.assertTrue(m.evidence['version_note'].startswith("the page's own scripts state jQuery 3.7.1"))

    def test_a_file_name_version_explains_it(self):
        m = self._verdict('ex2.x.test', '<script src="/js/jquery.min.js"></script><script src="/js/site-1.12.4.js"></script>',
                          scripts={'https://ex2.x.test/js/site-1.12.4.js': 'var s=1;'})
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))  # informs and caps, never closes
        self.assertTrue(m.evidence['version_note'].startswith("the page's own scripts state jQuery 3.7.1"))

    def test_another_librarys_version_on_the_page_explains_it(self):
        migrate = '/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation and other contributors */\nvar m=1;'
        m = self._verdict('ex3.x.test', '<script src="/js/jquery.min.js"></script><script src="/js/migrate.js"></script>', version='3.4.1',
                          scripts={'https://ex3.x.test/js/migrate.js': migrate})
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))  # informs and caps, never closes
        self.assertTrue(m.evidence['version_note'].startswith("the page's own scripts state jQuery 3.7.1"))

    def test_the_rule(self):
        libraries = js_libraries.HostLibraries({'jquery-migrate': {'copies': [{'version': '3.4.1', 'source': 'body'}]}},
                                               page_versions={'1.0.4'}, inline_versions={('jquery-ui', '1.13.2')})
        self.assertTrue(libraries.explains('jquery', '1.0.4'))
        self.assertTrue(libraries.explains('jquery', '3.4.1'))
        self.assertTrue(libraries.explains('jquery', '1.13.2'))
        self.assertFalse(libraries.explains('jquery', '1.12.4'))
        self.assertFalse(libraries.explains('jquery-ui', '1.13.2'))  # the library's own inline copy is a copy, not an explanation
        self.assertEqual(js_libraries.url_versions(['https://h.test/wp-content/themes/t/js/jquery.fancybox-1.0.4.js?ver=2.0',
                                                    'https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js', 'https://h.test/app.4b1d.js']),
                         ['1.0.4', '2.0', '3.4.1'])


class AliasToSameSite(ReviewScenarioBase):
    """Decision 3: a redirect alias closes only when the target is a host the project inventories."""

    def test_a1_apex_301_to_www_not_in_inventory_keeps_the_match(self):
        apex = self.host('y.x.test', ['jQuery:1.12.4'])
        self.correlate(apex)
        self.read_root('y.x.test', 301, '', location='https://www.y.x.test/')
        self.assertNotEqual(self.correlate(apex)[('y.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')
        self.assertGreater(CVEMatch.objects.exclude(ai_verdict='not_affected').count(), 0)

    def test_an_alias_to_an_inventoried_host_closes(self):
        apex = self.host('z.x.test', ['jQuery:1.12.4'])
        self.host('www.z.x.test', [])
        self.correlate(apex)
        self.read_root('z.x.test', 301, '', location='https://www.z.x.test/')
        m = self.correlate(apex)[('z.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual(m.ai_verdict, 'not_affected')
        self.assertIn('only redirects to www.z.x.test', m.ai_reason)

    def test_a_host_of_the_same_name_in_another_project_is_not_inventory(self):
        from dashboard.models import Org, Project
        from targetApp.models import Domain
        org = Org.objects.create(name='Elsewhere', slug='elsewhere')
        other = Project.objects.create(name='E', slug='elsewhere-p', insert_date=timezone.now(), org=org)
        site = Domain.objects.create(name='w.x.test', project=other, insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='z')
        Subdomain.objects.create(name='www.w.x.test', target_domain=site, scan_history=scan)
        apex = self.host('w.x.test', ['jQuery:1.12.4'])
        self.correlate(apex)
        self.read_root('w.x.test', 308, '', location='https://www.w.x.test/')
        self.assertNotEqual(self.correlate(apex)[('w.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')


class MoreExposureAndStatusTests(SimpleTestCase):
    def test_more_exposure_paths(self):
        for path in ('/swagger.json', '/.npmrc', '/v2/_catalog', '/.aws/credentials', '/id_rsa', '/nginx_status', '/fpm-status', '/status',
                     '/cgi-bin/printenv', '/error_log'):
            with self.subTest(path=path):
                self.assertEqual(templategen.template_evidence(_tpl('Acme - Exposure', path, r'acme.{0,3}2\.[0-3]\.\d')),
                                 templategen.BEHAVIOR_EVIDENCE)

    def test_more_status_line_forms(self):
        for regex in (r'HTTP\S1\.1', r'HTTP\x2F1\.1 200', r'HTTP\s1\.0', r'HTTP/1\.1', r'HTTP\057\d'):
            with self.subTest(regex=regex):
                self.assertEqual(templategen.template_evidence(_tpl('Acme', '/', regex)), templategen.BEHAVIOR_EVIDENCE)


class LoaderReadingTests(SimpleTestCase):
    def test_a_read_script_with_a_loader_is_not_whole(self):
        def fetch(url, headers=None):
            return {'status': 200, 'body': "import $ from './vendor/jquery-1.12.4.js';", 'raw_headers': {'etag': '"a"'}}
        read, _why = js_libraries._read_one('https://h.test/js/main.js', fetch)
        self.assertEqual((read['whole'], read['loaders']), (False, ['static import', 'script file name', 'library file name']))
        read, _why = js_libraries._read_one('https://h.test/js/site.js', lambda url, headers=None: {'status': 200, 'body': 'var a=1;'})
        self.assertEqual((read['whole'], read['loaders']), (True, []))

    def test_a_cached_reading_from_before_loaders_were_looked_for_is_read_again(self):
        from unittest import mock
        old = {'found': [], 'truncated': False, 'whole': True, 'sha256': 'x', 'etag': '"a"', 'length': '', 'checked': __import__('time').time()}
        asked = []

        def fetch(url, headers=None):
            asked.append(headers)
            return {'status': 200, 'body': "import x from './x.js';"}
        entries = js_libraries.parse_page('<script src="/js/main.js"></script>', 'https://h.test/')
        with mock.patch.object(js_libraries, '_cached', return_value=old), mock.patch.object(js_libraries, '_remember'):
            coverage = {}
            js_libraries.read_page(entries, 'https://h.test/', fetch, lambda url: '', {'left': 6},
                                   reader=js_libraries.Reader(sleep=lambda s: None), coverage=coverage)
        self.assertEqual(asked, [None])  # read again, not revalidated with the old ETag
        self.assertEqual(coverage, {'scripts': 1, 'read': 0})


class OneSearchForBothFeaturesTests(SimpleTestCase):
    """After #387: the route check's page read and the validation's script read share one whole-body search (``whole_body``) and one loader
    rule (``runtime_loaders``), so every closure path takes the stricter of the two."""

    def test_states_all_takes_the_whole_body_doubts(self):
        unplaceable = JQ_371_MIN + '\n' + 'x.fn=x.prototype={jquery:v,constructor:x};'  # jQuery code whose version cannot be told
        self.assertIn('jquery', js_libraries.whole_body(unplaceable)['unplaceable'])
        self.assertFalse(js_libraries._states_all(unplaceable, js_libraries.read_body(unplaceable)))
        stray = JQ_371_MIN + '\n/*! acme-widget */ var w=1;\n/*! jQuery v3.7.1 | (c) OpenJS Foundation */'  # as many banners as blocks
        self.assertTrue(js_libraries.whole_body(stray)['blocks'])
        self.assertFalse(js_libraries._states_all(stray, js_libraries.read_body(stray)))
        self.assertTrue(js_libraries._states_all(JQ_371_MIN, js_libraries.read_body(JQ_371_MIN)))

    def test_one_loader_rule(self):
        for code in ('require(["legacy"],f)', '__webpack_require__.e(1)', 'new Worker(u)', "var p='vendor/jquery-1.12.4.min';"):
            self.assertTrue(js_libraries.whole_body(code)['loaders'], code)  # this PR's loaders reach the validation's read
        for markup in ('<script type="module" src="/m.js"></script>', '<script src="/a.js" data-main="app"></script>',
                       '<script type="text/plain" data-cookieconsent="statistics" src="/t.js"></script>', '<script type="importmap">{}</script>'):
            self.assertTrue(js_libraries.parse_page(markup, 'https://h.test/').loaders, markup)  # #387's loaders reach the route check
        page = '<script src="/js/jquery-1.12.4.min.js"></script><script src="/app.js"></script>'
        self.assertEqual(js_libraries.whole_body(page, page=True)['loaders'], [])  # a src attribute is a tag the page parse reads
        self.assertEqual(js_libraries.parse_page(page, 'https://h.test/').loaders, [])
        self.assertTrue(js_libraries.whole_body(page + "<script>var p='/js/legacy.js';</script>", page=True)['loaders'])


class NamedClosureNeedsTheWholePageTests(ReviewScenarioBase):
    """Coordinator decision: a library script whose own ?ver= or file name disagrees with what its file states closes the technology scan's
    version only on a page known whole, like the contradicted-by-file closure: another copy the read did not see may carry the named version."""

    PAGE = '<script src="/js/jquery.min.js?ver=1.12.4"></script>'  # the file says 3.7.1; its query string says 1.12.4

    def _match(self, host, extra='', scripts=None):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, self.PAGE + extra, scripts=scripts)
        return self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]

    def test_the_whole_page_states_it_in_the_note(self):
        m = self._match('nm0.x.test', '<script src="/site.js"></script>')
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))  # informs and caps, never closes
        self.assertEqual(m.evidence['version_note'], js_libraries.STATES_NOTE.format(named='1.12.4', name='jQuery', said='3.7.1'))

    def test_one_unread_script_keeps_it_open(self):
        for host, extra, scripts in (('nm1.x.test', '<script src="/js/missing.js"></script>', None),  # not served
                                     ('nm2.x.test', '<script src="https://widgets.partner.example/w.js"></script>', None),  # never read
                                     ('nm3.x.test', '<script src="/js/loader.js"></script>',
                                      {'https://nm3.x.test/js/loader.js': "import('./legacy/jq.js')"}),  # loads more at run time
                                     ('nm4.x.test', "<script>/*! acme-tracker v1 */ var t=1;</script>", None)):  # inline code unread
            with self.subTest(host=host):
                m = self._match(host, extra, scripts)
                self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
                self.assertIn('not every script of the page was read whole', m.evidence['version_note'])


# synthetic stand-ins for Moment.js builds (no third-party code is copied): the official minified 2.29.1 build has no banner and no code the
# read recognises; the unminified 2.29.4 file opens with moment's own //! banner
MOMENT_2291_MIN = ('!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd'
                   '?define(t):e.moment=t()}(this,function(){"use strict";var H;function f(){return H.apply(null,arguments)}'
                   + 'function m(e){return e instanceof Array||"[object Array]"===Object.prototype.toString.call(e)}' * 400
                   + 'f.version="2.29.1";return f});')
MOMENT_2294 = '//! moment.js\n//! version : 2.29.4\n//! authors : Tim Wood, Iskren Chernev, Moment.js contributors\n' + MOMENT_2291_MIN.replace(
    '"2.29.1"', '"2.29.4"')
APP_WITH_MOMENT_2291 = MOMENT_2291_MIN + '\n;(function(){window.appReady=function(){return moment().format("LL")}})();\n'


class OnlyRecognisedLibrariesCloseTests(ReviewScenarioBase):
    """Final review: a file that states nothing never closes anything (B1), and only a library whose code is recognised wherever it appears
    (``js_libraries.CLOSABLE``: jQuery, jQuery UI, jQuery Migrate) may be closed by the page's files at all (B2)."""

    def setUp(self):
        super().setUp()
        from cveFeed.models import CVEEntry
        self.mo = CVEEntry.objects.create(cve_id='CVE-2022-31129', cvss=7.5, published_at=timezone.now(),
                                          affected=[{'vendor': 'momentjs', 'product': 'moment', 'ranges': [{'introduced': '2.18.0', 'fixed': '2.29.4'}]}])
        self.entries = [self.jq, self.bs, self.mo]

    def _moment(self, host, page, scripts):
        sub = self.host(host, ['Moment.js:2.29.1'])
        self.correlate(sub)
        self.read_root(host, 200, page, scripts=scripts)
        return sub, self.correlate(sub)[(host, 'CVE-2022-31129', '2.29.1')]

    def test_f1_a_file_that_states_nothing_closes_nothing(self):
        host = 'f1.x.test'
        _sub, m = self._moment(host, '<script src="/wp-includes/js/dist/vendor/moment.min.js?ver=2.29.1"></script>',
                               {f'https://{host}/wp-includes/js/dist/vendor/moment.min.js': MOMENT_2291_MIN})
        self.assertTrue(js_libraries.HostLibraries.for_subdomain(Subdomain.objects.get(name=host)).page_read)  # the page is whole
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
        self.assertIn('states no version the read recognises', m.evidence['version_note'])

    def test_f1b_nor_does_the_sweep(self):
        from cveFeed.tasks import reconcile_library_provenance
        host = 'f1b.x.test'
        sub = self.host(host, ['Moment.js:2.29.1'])
        self.correlate(sub)
        self.read_root(host, 200, '<script src="/js/moment.min.js?ver=2.29.1"></script>', scripts={f'https://{host}/js/moment.min.js': MOMENT_2291_MIN})
        out = reconcile_library_provenance()
        self.assertEqual(out['closed'], 0)
        self.assertNotEqual(CVEMatch.objects.get(subdomain=sub, cve_entry=self.mo).ai_verdict, 'not_affected')

    def test_f1_also_for_jquery(self):
        # jQuery's own file with its banner stripped and its code unreadable states nothing either: no closure
        host = 'f1j.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, '<script src="/js/jquery.min.js?ver=1.12.4"></script>', scripts={f'https://{host}/js/jquery.min.js': 'var j=1;'})
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_f6a_named_disagreement_beside_an_unrecognised_bundled_copy(self):
        host = 'f6a.x.test'
        _sub, m = self._moment(host, '<script src="/js/moment.js?ver=2.29.1"></script><script src="/js/app.js"></script>',
                               {f'https://{host}/js/moment.js': MOMENT_2294, f'https://{host}/js/app.js': APP_WITH_MOMENT_2291})
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
        self.assertIn("Moment.js's code is not recognised wherever it appears", m.evidence['version_note'])

    def test_f6b_contradicted_by_file_beside_an_unrecognised_bundled_copy(self):
        host = 'f6b.x.test'
        _sub, m = self._moment(host, '<script src="/js/moment.js"></script><script src="/wp-content/themes/acme/js/app.js?ver=2.29.1"></script>',
                               {f'https://{host}/js/moment.js': MOMENT_2294, f'https://{host}/wp-content/themes/acme/js/app.js': APP_WITH_MOMENT_2291})
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
        self.assertIn("Moment.js's code is not recognised wherever it appears", m.evidence['version_note'])

    def test_f6c_an_unrecognised_copy_pasted_inline(self):
        host = 'f6c.x.test'
        self.assertLess(len(MOMENT_2291_MIN), js_libraries.MAX_INLINE)
        _sub, m = self._moment(host, f'<script src="/js/moment.js?ver=2.29.1"></script><script>{MOMENT_2291_MIN}</script>',
                               {f'https://{host}/js/moment.js': MOMENT_2294})
        self.assertNotEqual(m.ai_verdict, 'not_affected')

    def test_jquery_on_a_whole_page_is_noted_both_ways_never_closed(self):
        # named: the library's own script names 1.12.4, its file says 3.7.1
        sub = self.host('ok1.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('ok1.x.test', 200, '<script src="/js/jquery.min.js?ver=1.12.4"></script>')
        m = self.correlate(sub)[('ok1.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
        self.assertTrue(m.evidence['version_note'].startswith('the script named 1.12.4 states jQuery 3.7.1'))
        # contradicted by file: another script of the page carries 1.12.4
        sub = self.host('ok2.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('ok2.x.test', 200, '<script src="/js/jquery.min.js"></script><script src="/site.js?ver=1.12.4"></script>')
        m = self.correlate(sub)[('ok2.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']))
        self.assertTrue(m.evidence['version_note'].startswith("the page's own scripts state jQuery 3.7.1"))

    def test_an_inline_jquery_code_whose_version_cannot_be_told_is_unread(self):
        page = '<script>x.fn=x.prototype={jquery:v,constructor:x};</script>'
        self.assertEqual(js_libraries.parse_page(page, 'https://h.test/').inline_unread, 1)

    def test_the_allow_list_and_the_kinds(self):
        self.assertEqual(js_libraries.CLOSABLE, ('jquery', 'jquery-ui', 'jquery-migrate'))
        self.assertEqual(set(js_libraries.CLOSABLE), set(js_libraries.SIGNED))  # the libraries the whole-body search finds by their code
        kind = js_libraries.closure_kind
        self.assertEqual(kind(js_libraries.closed_reason("the page's own scripts say jQuery 3.7.1; the 1.12.4 came from a script's name or "
                                                         "query string")), 'named_by_script')
        self.assertEqual(kind(js_libraries.closed_reason("the page's own scripts say jQuery 3.7.1; the 1.12.4 came from a technology scan")),
                         'contradicted_by_file')
        self.assertEqual(kind(js_libraries.closed_reason("the Moment.js script's own file does not state 2.29.1")), 'file_states_nothing')
        self.assertEqual(kind(js_libraries.closed_reason('the host only redirects to x.test; the jQuery seen there is that host\'s')), 'redirect_alias')

    def test_other_libraries_never_close_by_file(self):
        copy = {'url': 'https://h.test/js/moment.js', 'version': '2.29.4', 'source': 'body', 'whole': True, 'state': 'effective',
                'query_version': '2.29.1', 'file_read': True}
        libraries = js_libraries.HostLibraries({'moment': {'version': '2.29.4', 'version_source': 'body', 'copies': [copy]}}, page_read=True,
                                               page_versions={'2.29.1'})
        skip, evidence, cap = libraries.judge('Moment.js', '2.29.1')
        self.assertEqual((skip, cap), (False, js_libraries.CONFIDENCE['filename']))
        self.assertIn('not recognised wherever it appears', evidence['version_note'])
        jq = js_libraries.HostLibraries({'jquery': {'version': '3.7.1', 'version_source': 'body', 'copies': [{**copy, 'version': '3.7.1',
                                                                                                             'query_version': '1.12.4'}]}},
                                        page_read=True, page_versions={'1.12.4'})
        skip, evidence, _cap = jq.judge('jQuery', '1.12.4')
        self.assertFalse(skip)  # nor does jQuery: its note says what the file states
        self.assertTrue(evidence['version_note'].startswith('the script named 1.12.4 states jQuery 3.7.1'))


NAMED_PAGE = '<script src="/js/jquery.min.js?ver=1.12.4"></script>'  # the file says 3.7.1 (read_root serves it); its ?ver= says 1.12.4


class FileEvidenceNeverClosesTests(ReviewScenarioBase):
    """Round four of the loader gap (coordinator decision): static reading cannot prove a page loads nothing else at run time, so the page's
    files never close a technology scan's version; only a redirect alias does. Each loader the read did not know, in a file or inline, and
    each jQuery build the whole-body search takes for another library, keeps the genuine 1.12.4 open as a capped candidate."""

    def _open(self, host, page, scripts=None):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, page, scripts=scripts)
        m = self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]
        self.assertEqual((m.ai_verdict, m.confidence), ('', js_libraries.CONFIDENCE['filename']), host)
        return m

    def _legacy(self, host, code):
        return self._open(host, NAMED_PAGE + '<script src="/js/legacy.js"></script>', {f'https://{host}/js/legacy.js': code})

    def test_l1_document_write_without_a_js_extension(self):
        self._legacy('l1.x.test', 'document.write(\'<script src="/bundles/legacy?v=Xy12"><\\/script>\');')

    def test_l2_jquery_append_of_a_script_tag(self):
        self._legacy('l2.x.test', "$(function(){$('head').append('<script src=\"/bundles/legacy?v=Xy12\"></scr'+'ipt>')});")

    def test_l3_fetch_and_eval(self):
        self._legacy('l3.x.test', "fetch('/bundles/legacy?v=1').then(function(r){return r.text()}).then(function(t){(0,eval)(t)});")

    def test_l4_ajax_with_datatype_script(self):
        self._legacy('l4.x.test', "$.ajax({url:'/bundles/legacy?v=1',dataType:'script',cache:true});")

    def test_l5_an_uppercase_script_element(self):
        self._legacy('l5.x.test', "var s=document.createElement('SCRIPT');s.src='/bundles/legacy?v=1';document.head.appendChild(s);")

    def test_l6_create_element_ns(self):
        self._legacy('l6.x.test', "var s=document.createElementNS('http://www.w3.org/1999/xhtml','script');s.src='/bundles/legacy?v=1';"
                                  "document.head.appendChild(s);")

    def test_l7_a_contextual_fragment(self):
        self._legacy('l7.x.test', "document.head.appendChild(document.createRange().createContextualFragment('<script src=\"/bundles/legacy?v=1\">"
                                  "</scr'+'ipt>'));")

    def test_i2_an_inline_append(self):
        self._open('i2.x.test', NAMED_PAGE + "<script>$('head').append('<script src=\"/bundles/legacy?v=1\"></scr'+'ipt>');</script>")

    def test_i3_an_inline_fetch_and_eval(self):
        self._open('i3.x.test', NAMED_PAGE + "<script>fetch('/bundles/legacy?v=1').then(r=>r.text()).then(t=>(0,eval)(t));</script>")

    def test_g3b_a_prototype_whose_jquery_key_is_far_away(self):
        code = ('!function(w){var v="1.12.4",q=function(s,c){return new q.fn.init(s,c)};q.fn=q.prototype={init:function(s,c){'
                + 'if(!s)return this;' * 400 + 'return this},jquery:v,constructor:q,length:0};w.jQuery=w.$=q}(window);')
        self._open('g3b.x.test', NAMED_PAGE + '<script src="/js/app.js"></script>', {'https://g3b.x.test/js/app.js': code})

    def test_g3c_a_prototype_assigned_separately(self):
        code = ('!function(w){var v="1.12.4",q=function(s,c){return new q.fn.init(s,c)};q.prototype={jquery:v,constructor:q,length:0};'
                'q.fn=q.prototype;w.jQuery=q}(window);')
        self._open('g3c.x.test', NAMED_PAGE + '<script src="/js/app.js"></script>', {'https://g3c.x.test/js/app.js': code})

    def test_only_a_redirect_alias_closes(self):
        sub = self.host('al2.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.redirect_away('al2.x.test')
        m = self.correlate(sub)[('al2.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual((m.ai_verdict, js_libraries.closure_kind(m.ai_reason)), ('not_affected', 'redirect_alias'))
