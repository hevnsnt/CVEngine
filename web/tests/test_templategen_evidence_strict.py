"""Third review of the template classifier (templategen.template_evidence): a payload in an allowed header value, a data-exposure marker
beside a version, an HTTP status line read as a version, malformed fields; and the results a later run may not lower. Every template here
also passes static_check, so an AI-written template could take each shape."""
import os
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import templategen
from cveFeed.models import CVEMatch
from startScan.models import Vulnerability
from tests.test_templategen_evidence import (ADMIN_LIST_WITH_VERSION, APACHE_TRAVERSAL, FIRE, HOST, JQUERY_VERSION_REGEX, LEGACY,
                                             TRAVERSAL_HIT, VERSION_HIT, TemplateHitTests)

B = templategen.BEHAVIOR_EVIDENCE

SQLI_UA = r"""
id: cve-2099-0101
info: {name: SQL injection through the User-Agent (error based), severity: critical}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    headers:
      User-Agent: "1 AND extractvalue(1,concat(0x7e,version()))"
    matchers:
      - type: regex
        regex: ['XPATH syntax error.{0,3}\d+\.\d+\.\d+']
"""
CMDI_UA = r"""
id: cve-2099-0102
info: {name: Command injection through the User-Agent, severity: critical}
http:
  - method: GET
    path: ["{{BaseURL}}/cgi-bin/status"]
    headers:
      User-Agent: ";/bin/uname -r;"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex: ['\d+\.\d+\.\d+-\d+-generic']
      - type: status
        status: [200]
"""
LFI_ACCEPT_LANGUAGE = r"""
id: cve-2099-0103
info: {name: File read through Accept-Language, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/index.php"]
    headers:
      Accept-Language: "/proc/version"
    matchers:
      - type: regex
        regex: ['Linux version \d+\.\d+']
"""
UNAUTH_STATUS_LINE = r"""
id: cve-2099-0104
info: {name: Unauthenticated customer export, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/api/v1/customers/export"]
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words: ["HTTP/1.1 200"]
      - type: word
        part: body
        words: ["email", "phone", "address"]
        condition: and
"""


class AllowlistTests(SimpleTestCase):
    def test_payload_in_an_allowed_header_value_is_behaviour(self):
        for name, text in (('sqli ua', SQLI_UA), ('cmdi ua', CMDI_UA), ('lfi accept-language', LFI_ACCEPT_LANGUAGE)):
            self.assertEqual(templategen.static_check(text), (True, ''), name)  # the AI gate accepts each
            with self.subTest(name):
                self.assertEqual(templategen.template_evidence(text), B)

    def test_the_authors_admin_list_fixture_with_another_marker_word_is_behaviour(self):
        self.assertEqual(templategen.template_evidence(ADMIN_LIST_WITH_VERSION), B)
        for word in ('email', 'role', 'ssn', 'creditCard', 'Index of /'):
            text = ADMIN_LIST_WITH_VERSION.replace("""['"role":"admin"']""", f"['{word}']")
            self.assertNotEqual(text, ADMIN_LIST_WITH_VERSION)
            with self.subTest(word):
                self.assertEqual(templategen.template_evidence(text), B)

    def test_an_http_status_line_is_not_a_version(self):
        self.assertEqual(templategen.template_evidence(UNAUTH_STATUS_LINE), B)

    def test_malformed_matcher_does_not_crash(self):
        text = JQUERY_VERSION_REGEX.replace('        status:\n          - 200', '        status: 200')
        self.assertNotEqual(text, JQUERY_VERSION_REGEX)
        self.assertEqual(templategen.template_evidence(text), B)


class LaterResultsTests(TemplateHitTests):
    @mock.patch.dict(os.environ, LEGACY)  # under the KEV rule the version hit itself turns the KEV match fire and is paged once (#386)
    def test_a_behavioural_hit_upgrades_version_only(self):
        _r, send1 = self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, templategen.VERSION_ONLY_RESULT)
        result, send = self.run_test(APACHE_TRAVERSAL, TRAVERSAL_HIT)
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual((match.template_result, self.heat()), ('vulnerable', FIRE))
        self.assertEqual(Vulnerability.objects.filter(source='nuclei-cve').count(), 1)
        self.assertEqual((result['vulnerable'], send1.call_count, send.call_count), ([HOST], 0, 1))

    def test_testssl_confirmation_survives_version_hit_and_error(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable', template_id='testssl:heartbleed')
        self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        outcome = [{'host': HOST, 'vulnerable': False, 'error': 'boom', 'output': ''}]
        with mock.patch('cveFeed.validation.resolve_template', return_value=('/templates/x.yaml', '')), \
                mock.patch('cveFeed.validation.approved_template', return_value=(APACHE_TRAVERSAL, '')), \
                mock.patch.object(templategen, '_run_template_with_retry', return_value=outcome), \
                mock.patch('cveFeed.auth_nuclei.merge_template_outcomes', side_effect=lambda path, hosts, outcomes, project: outcomes), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **kw: list(hosts)), \
                mock.patch('reNgine.ai_settings.get_configured_provider', side_effect=RuntimeError('none')), \
                mock.patch('cveFeed.notify._send', return_value=True):
            from cveFeed.tasks import template_test_for_cve
            template_test_for_cve(self.entry.pk, [HOST], project_id=self.project.pk)
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual((match.template_result, match.template_id, self.heat()), ('vulnerable', 'testssl:heartbleed', FIRE))

    def test_a_later_error_or_miss_never_lowers_a_nuclei_confirmation(self):
        self.run_test(APACHE_TRAVERSAL, TRAVERSAL_HIT)
        outcome = [{'host': HOST, 'vulnerable': False, 'error': 'timeout', 'output': ''}]
        with mock.patch('cveFeed.validation.resolve_template', return_value=('/templates/x.yaml', '')), \
                mock.patch('cveFeed.validation.approved_template', return_value=(APACHE_TRAVERSAL, '')), \
                mock.patch.object(templategen, '_run_template_with_retry', return_value=outcome), \
                mock.patch('cveFeed.auth_nuclei.merge_template_outcomes', side_effect=lambda path, hosts, outcomes, project: outcomes), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **kw: list(hosts)), \
                mock.patch('reNgine.ai_settings.get_configured_provider', side_effect=RuntimeError('none')), \
                mock.patch('cveFeed.notify._send', return_value=True):
            from cveFeed.tasks import template_test_for_cve
            template_test_for_cve(self.entry.pk, [HOST], project_id=self.project.pk)
        self.assertEqual((CVEMatch.objects.get(pk=self.match.pk).template_result, self.heat()), ('vulnerable', FIRE))
        self.run_test(APACHE_TRAVERSAL, None, vulnerable=False)  # and a later run that does not match
        self.assertEqual((CVEMatch.objects.get(pk=self.match.pk).template_result, self.heat()), ('vulnerable', FIRE))


class WeakerShapesTests(SimpleTestCase):
    """Shapes that read like a version check but owe their hit to something else: each is behaviour."""

    BASE = r"""
id: cve-2099-0201
info: {name: Acme Portal version check, severity: high, metadata: {vendor: acme, product: portal}}
http:
  - method: GET
    path: ["{{BaseURL}}/static/app.js"]
    extractors:
      - type: regex
        name: version
        internal: true
        group: 1
        regex: ['Acme Portal v([0-9.]+)']
    matchers-condition: and
    matchers:
      - type: word
        words: ["Acme Portal"]
      - type: dsl
        dsl: ["compare_versions(version, '< 2.0')"]
"""

    def test_the_base_shape_is_a_version_check(self):
        self.assertEqual(templategen.template_evidence(self.BASE), templategen.VERSION_EVIDENCE)

    def test_each_weaker_shape_is_behaviour(self):
        shapes = {
            'an extracted value that is not digits and dots': ("regex: ['Acme Portal v([0-9.]+)']", "regex: ['Acme Portal v(.*?)\\n']"),
            'an empty path segment into /proc': ('"{{BaseURL}}/static/app.js"', '"{{BaseURL}}/static//proc/version"'),
            'an exposure page': ('"{{BaseURL}}/static/app.js"', '"{{BaseURL}}/server-status"'),
            'a configuration file': ('"{{BaseURL}}/static/app.js"', '"{{BaseURL}}/application.properties"'),
            'an environment file': ('"{{BaseURL}}/static/app.js"', '"{{BaseURL}}/.env"'),
            'an identity word the template does not name': ('words: ["Acme Portal"]', 'words: ["email"]'),
            'a status line': ('words: ["Acme Portal"]', 'words: ["HTTP/1.1 200"]'),
            'a second request block': ('    matchers-condition: and', '    matchers-condition: and'),
        }
        for label, (old, new) in shapes.items():
            self.assertIn(old, self.BASE, label)
            text = self.BASE.replace(old, new, 1)
            if label == 'a second request block':
                text = text + '  - method: GET\n    path: ["{{BaseURL}}/admin/reset"]\n    matchers:\n      - type: word\n        words: ["Acme Portal"]\n'
            self.assertEqual(templategen.template_evidence(text), B, label)

    def test_a_raw_request_without_a_host_header_is_behaviour(self):
        raw = """
id: cve-2099-0202
info: {name: Acme Portal raw, severity: high}
http:
  - raw:
      - |
        GET / HTTP/1.0

    matchers:
      - type: regex
        regex: ['Acme Portal 1\\.2\\.[0-3]']
"""
        self.assertEqual(templategen.template_evidence(raw), B)
        self.assertEqual(templategen.template_evidence(raw.replace('GET / HTTP/1.0\n', 'GET / HTTP/1.0\n        Host: {{Hostname}}\n')),
                         templategen.VERSION_EVIDENCE)

    def test_a_malformed_template_never_breaks_the_test_run(self):
        with mock.patch('cveFeed.validation.approved_template', return_value=('http: [{matchers: [{type: word, words: 5}]}]', '')):
            self.assertEqual(templategen.evidence_of_template('/templates/x.yaml'), B)
