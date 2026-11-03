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


PAGE = '<script src="/js/jquery.min.js"></script><script src="/dist/app.js"></script>'  # core jQuery 3.7.1 file, then the app bundle


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
        self.read_root(host, 200, '<script src="/js/vendor.js"></script>', scripts={f'https://{host}/js/vendor.js': bundle})
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
        self.read_root('al.x.test', 301, '', location='https://elsewhere.example/')
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
        self.assertTrue(js_libraries.read_whole({'sha256': 'x', 'whole': True}))
        for read in (None, {}, {'sha256': '', 'whole': True}, {'sha256': 'x', 'whole': False}, {'sha256': 'x'}):
            self.assertFalse(js_libraries.read_whole(read), read)


class EveryScriptOfThePageTests(ReviewScenarioBase):
    """Part (b) of the fix on its own: the page's jQuery file, read whole, contradicts nothing while any other script of the page (of any
    host, a copy of the library or not) or any inline script is not read whole."""

    def _closed(self, host, page, scripts=None):
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, page, scripts=scripts)
        return self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict == 'not_affected'

    def test_the_page_read_whole_still_closes(self):
        self.assertTrue(self._closed('w0.x.test', '<script src="/js/jquery.min.js"></script><script src="/site.js"></script>'))

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
        page = '<script src="/js/jquery.min.js"></script>' + ''.join(f'<script src="/s{i}.js"></script>' for i in range(8))
        scripts = {f'https://w4.x.test/s{i}.js': 'var s=1;' for i in range(8)}
        self.assertFalse(self._closed('w4.x.test', page, scripts))
        self.assertGreater(RouteAuth.objects.get(host='w4.x.test').evidence['script_page']['unread'], 0)

    def test_the_counts_rule(self):
        read = js_libraries.every_script_read
        self.assertTrue(read({'scripts': 3, 'unread': 0, 'inline_unread': 0}))
        self.assertTrue(read({'scripts': 0, 'inline_unread': 0}))  # no script with a source: nothing to read
        for page in ({'scripts': 3, 'inline_unread': 0}, {'scripts': 3, 'unread': 1, 'inline_unread': 0},
                     {'scripts': 3, 'unread': 0, 'inline_unread': 2}, {'scripts': 3, 'unread': 0},
                     {'scripts': 3, 'unread': '0', 'inline_unread': 0}, {'scripts': 3, 'unread': False, 'inline_unread': 0}):
            self.assertFalse(read(page), page)


class ContradictsRuleTests(SimpleTestCase):
    """``HostLibraries._contradicts`` with the page known whole: an unresolved set of copies, or no copy that runs, contradicts nothing."""

    COPY = {'url': 'https://h.test/js/jquery.min.js', 'version': '3.7.1', 'source': 'body', 'whole': True, 'state': 'effective'}

    def judge(self, record, page_read=True):
        return js_libraries.HostLibraries({'jquery': record}, page_read=page_read).judge('jQuery', '1.12.4')[0]

    def test_the_whole_page_with_one_effective_copy_closes(self):
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
