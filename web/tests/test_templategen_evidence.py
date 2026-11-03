"""A template hit is hard evidence only when the template shows more than a version string (cveFeed.templategen.template_evidence).

The design review's latent hole: the template writer is told to detect "by version or a safe response marker" and the static gate accepts a
version regex, so a template that regex-matches ``jQuery v3.4.1`` in a script set ``template_result='vulnerable'``. That made a version-only
match hard evidence (``match_policy.has_hard_evidence``), lifted it to fire, recorded a confirmed nuclei-cve finding and paged it through
``notify.template_hits``, which never looked at heat. A version-class hit is now recorded as ``version_only``: the version re-read, never a
confirmation. Behavioural templates (a traversal that reads /etc/passwd, an exposed file, a request carrying a payload) are unchanged.
"""
import os
from unittest import mock

import yaml
from django.test import SimpleTestCase

from cveFeed import match_policy, notify, scoring, templategen, threat, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, SMOKE
from startScan.models import Vulnerability
from tests.test_match_policy import JQUERY, Cve, Fixture

# The legacy heat policy rates a version-only match smoke at most (CVENGINE_VERSION_ONLY_MAX_HEAT). Under the KEV heat policy (the default) a
# version-class hit proves the version, so a KEV match it reads turns fire and is paged once: TemplateHitTests has a kev counterpart of each.
LEGACY = {'CVENGINE_HEAT_POLICY': 'legacy'}

# --- version-only templates, as the AI writer and the community write them ---------------------------------------------------------

# a script banner regex: the shape C.6 of the design review describes
JQUERY_VERSION_REGEX = r"""
id: cve-2020-11023
info:
  name: jQuery < 3.5.0 - Cross-Site Scripting
  author: cvengine-ai
  severity: medium
  description: jQuery before 3.5.0 passes HTML containing option elements from untrusted sources to its DOM manipulation methods.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-11023
  tags: cve,cve2020,jquery,xss
http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/js/jquery.min.js"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - 'jQuery v(1\.[0-9]+\.[0-9]+|2\.[0-9]+\.[0-9]+|3\.[0-4]\.[0-9]+)'
      - type: status
        status:
          - 200
"""

# the common community shape: read a plugin's readme, extract its stable tag, compare_versions
WP_PLUGIN_COMPARE_VERSIONS = r"""
id: CVE-2020-35489
info:
  name: WordPress Contact Form 7 < 5.3.2 - Unrestricted File Upload
  author: cvengine
  severity: critical
  tags: cve,cve2020,wordpress,wp-plugin
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/contact-form-7/readme.txt"
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        internal: true
        regex:
          - "(?i)Stable tag:\\s?([\\w.]+)"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Contact Form 7"
      - type: dsl
        dsl:
          - compare_versions(version, '< 5.3.2')
      - type: status
        status:
          - 200
"""

# a Server header banner
APACHE_HEADER_BANNER = r"""
id: cve-2021-41773-version
info: {name: Apache 2.4.49 by its Server header, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: regex
        part: header
        regex:
          - 'Server: Apache/2\.4\.49'
"""

# a network service banner, read without sending anything
OPENSSH_BANNER = r"""
id: cve-2018-15473
info: {name: OpenSSH < 7.7 - User Enumeration (banner), severity: medium}
tcp:
  - host:
      - "{{Hostname}}:22"
    read-size: 64
    matchers:
      - type: regex
        regex:
          - 'SSH-2\.0-OpenSSH_(?:[1-6]\.\d|7\.[0-6])'
"""

# --- behavioural templates: these demonstrate the flaw, and must stay hard evidence --------------------------------------------------

APACHE_TRAVERSAL = r"""
id: CVE-2021-41773
info:
  name: Apache 2.4.49 - Path Traversal and Remote Code Execution
  author: daffainfo
  severity: high
  tags: cve,cve2021,apache,lfi,kev
http:
  - method: GET
    path:
      - "{{BaseURL}}/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
      - type: status
        status:
          - 200
"""

GIT_CONFIG_EXPOSED = r"""
id: cve-2099-0001
info: {name: Exposed .git/config, severity: medium}
http:
  - method: GET
    path: ["{{BaseURL}}/.git/config"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["[core]", "repositoryformatversion"]
        condition: and
      - type: status
        status: [200]
"""

# a version guard on a request that carries a payload: the request is the demonstration
HEADER_BYPASS_WITH_VERSION = r"""
id: cve-2099-0002
info: {name: Admin bypass via X-Original-URL on 4.1.x, severity: high}
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-Original-URL: /admin/users

    matchers-condition: and
    matchers:
      - type: word
        words: ["Manage users"]
      - type: regex
        part: header
        regex: ['X-Powered-By: Acme/4\.1\.\d+']
"""

# either a version string or a marker of the flaw itself: a hit may be the marker
VERSION_OR_MARKER = r"""
id: cve-2099-0003
info: {name: Version or marker, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/debug/vars"]
    matchers:
      - type: regex
        regex: ['Acme/1\.2\.[0-3]']
      - type: word
        words: ['"cmdline":', '"memstats":']
        condition: and
"""

# an internal address disclosed by a plain GET is the flaw's own marker, not a version
IP_DISCLOSURE = r"""
id: cve-2099-0004
info: {name: Internal address disclosure, severity: medium}
http:
  - method: GET
    path: ["{{BaseURL}}/status"]
    matchers:
      - type: regex
        regex: ['10\.\d{1,3}\.\d{1,3}\.\d{1,3}']
"""

SSL_WEAK = """
id: cve-2099-0005
info: {name: Weak TLS, severity: medium}
ssl:
  - address: "{{Host}}:{{Port}}"
    matchers:
      - type: word
        part: tls_version
        words: [tls10]
"""

# --- the review's constructed misfilings (PR #384): each one demonstrates something, so each must stay behaviour ------------------

SHELLSHOCK_UA = r"""
id: cve-2014-6271
info: {name: Shellshock in a CGI, severity: critical}
http:
  - method: GET
    path: ["{{BaseURL}}/cgi-bin/status"]
    headers:
      User-Agent: "() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'"
    matchers:
      - type: word
        part: header
        words: ["Apache/2.2"]
"""

LOG4SHELL_RAW = r"""
id: cve-2021-44228
info: {name: Log4Shell through the User-Agent, severity: critical}
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{interactsh-url}}
        User-Agent: ${jndi:ldap://{{interactsh-url}}/a}

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns"]
      - type: word
        words: ["Apache Tomcat/9.0.1"]
"""

ACCEPT_LANGUAGE_TRAVERSAL = r"""
id: cve-2099-0006
info: {name: Locale file traversal, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    headers:
      Accept-Language: ../../../../etc/passwd
    matchers-condition: and
    matchers:
      - type: regex
        regex: ["root:.*:0:0:"]
      - type: word
        words: ["Acme 1.2.3"]
"""

XSS_WORD_OR = r"""
id: cve-2099-0007
info: {name: Reflected script, severity: medium}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["Mozilla/5.0 <script>alert(1)</script>"]
"""

EXTRACTOR_ONLY_BLOCK = r"""
id: cve-2099-0008
info: {name: Config disclosure, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/config.json"]
    extractors:
      - type: regex
        regex: ['"db_password":"([^"]+)"']
  - method: GET
    path: ["{{BaseURL}}/readme.txt"]
    extractors:
      - type: regex
        name: version
        internal: true
        group: 1
        regex: ["Stable tag: ([0-9.]+)"]
    matchers:
      - type: dsl
        dsl: ["compare_versions(version, '< 2.0')"]
"""

WEBSOCKET_BLOCK = r"""
id: cve-2099-0009
info: {name: Websocket command, severity: critical}
websocket:
  - address: "{{Scheme}}://{{Hostname}}"
    inputs:
      - data: '{"cmd":"id"}'
    matchers:
      - type: word
        words: ["uid="]
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: regex
        regex: ['Acme/1\.2\.[0-3]']
"""

DSL_COMPARE_OR_DISCLOSURE = r"""
id: cve-2099-0010
info: {name: Hash disclosure, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/api/status"]
    extractors:
      - type: regex
        name: version
        internal: true
        group: 1
        regex: ['"version":"([0-9.]+)"']
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '< 2.0') || contains(body, '\"password_hash\"')"
"""

ADMIN_LIST_WITH_VERSION = r"""
id: cve-2099-0011
info: {name: Unauthenticated admin user list, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/api/v1/admin/users"]
    extractors:
      - type: regex
        name: version
        internal: true
        group: 1
        regex: ['X-Acme-Version: ([0-9.]+)']
        part: header
    matchers-condition: and
    matchers:
      - type: word
        words: ['"role":"admin"']
      - type: dsl
        dsl: ["compare_versions(version, '< 3.1.0')"]
"""

FLOW_TEMPLATE = r"""
id: cve-2099-0012
info: {name: Flow, severity: high}
flow: http(1) && http(2)
http:
  - method: GET
    path: ["{{BaseURL}}/a"]
    matchers:
      - type: regex
        regex: ['Acme/1\.2\.[0-3]']
  - method: GET
    path: ["{{BaseURL}}/b"]
    matchers:
      - type: regex
        regex: ['Acme/1\.2\.[0-3]']
"""

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'nuclei_templates')


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as handle:
        return handle.read()


VERSION = {'jquery version regex': JQUERY_VERSION_REGEX, 'wp plugin compare_versions': WP_PLUGIN_COMPARE_VERSIONS,
           'apache server header': APACHE_HEADER_BANNER, 'openssh banner': OPENSSH_BANNER,
           # real community templates (nuclei-templates @ eddca90) that only compare a version they read
           'zimbra ZmSettings.js (CVE-2022-27924)': fixture('CVE-2022-27924.yaml'), 'teleport ping (CVE-2025-49825)': fixture('CVE-2025-49825.yaml'),
           'ivanti welcome.cgi (CVE-2025-0282)': fixture('CVE-2025-0282.yaml'), 'n-central login (CVE-2026-86218)': fixture('CVE-2026-86218.yaml')}
BEHAVIOR = {'apache traversal': APACHE_TRAVERSAL, 'exposed git config': GIT_CONFIG_EXPOSED, 'header payload with a version guard': HEADER_BYPASS_WITH_VERSION,
            'version or marker': VERSION_OR_MARKER, 'ip disclosure': IP_DISCLOSURE, 'ssl': SSL_WEAK,
            'user-agent xss (CVE-2017-4011, real)': fixture('CVE-2017-4011.yaml'), 'shellshock user-agent': SHELLSHOCK_UA,
            'log4shell raw host and user-agent': LOG4SHELL_RAW, 'accept-language traversal': ACCEPT_LANGUAGE_TRAVERSAL,
            'markup in a version word': XSS_WORD_OR, 'an extractor-only block': EXTRACTOR_ONLY_BLOCK, 'an unknown websocket block': WEBSOCKET_BLOCK,
            'compare_versions or a disclosure': DSL_COMPARE_OR_DISCLOSURE, 'admin list and a version': ADMIN_LIST_WITH_VERSION,
            'flow': FLOW_TEMPLATE}


class ClassificationTests(SimpleTestCase):
    def test_templates_that_only_read_a_version_are_version_class(self):
        for name, text in VERSION.items():
            self.assertEqual(templategen.template_evidence(text), templategen.VERSION_EVIDENCE, name)

    def test_templates_that_show_the_flaw_stay_behaviour_class(self):
        for name, text in BEHAVIOR.items():
            self.assertEqual(templategen.template_evidence(text), templategen.BEHAVIOR_EVIDENCE, name)

    def test_one_ordinary_change_turns_a_version_template_into_behaviour(self):
        # the allowlist: each of these, applied to a version-class template, is something it does not positively recognise
        base = JQUERY_VERSION_REGEX
        for change in (('  - method: GET\n', '  - method: GET\n    headers:\n      User-Agent: "x\'><svg/onload=alert(1)>"\n'),
                       ('  - method: GET\n', '  - method: GET\n    headers:\n      Host: evil.example\n'),
                       ('  - method: GET\n', '  - method: GET\n    headers:\n      X-Forwarded-For: 127.0.0.1\n'),
                       ('"{{BaseURL}}/js/jquery.min.js"', '"{{BaseURL}}/js/jquery.min.js?debug=1"'),
                       ('      - type: status\n        status:\n          - 200', '      - type: status\n        status:\n          - 500'),
                       ('      - type: status\n', '      - type: status\n        negative: true\n'),
                       ('http:\n', 'flow: http(1)\nhttp:\n')):
            self.assertIn(change[0], base)
            self.assertEqual(templategen.template_evidence(base.replace(change[0], change[1], 1)), templategen.BEHAVIOR_EVIDENCE, change)
        self.assertEqual(templategen.template_evidence(base.replace('  - method: GET\n', '  - method: GET\n    headers:\n'
                                                                    '      User-Agent: Mozilla/5.0 (X11; Linux x86_64)\n', 1)),
                         templategen.VERSION_EVIDENCE)  # an ordinary browser header is still a plain read

    def test_anything_unreadable_is_behaviour_so_a_genuine_hit_is_never_downgraded(self):
        for text in ('', 'not: [yaml', 'id: x', '- a list', None):
            self.assertEqual(templategen.template_evidence(text), templategen.BEHAVIOR_EVIDENCE, repr(text))

    def test_the_ai_writers_version_template_still_passes_the_static_gate(self):
        # nothing about what may be written changes: the class decides only what a hit counts as
        self.assertEqual(templategen.static_check(JQUERY_VERSION_REGEX, 'CVE-2020-11023'), (True, ''))
        self.assertIsInstance(yaml.safe_load(WP_PLUGIN_COMPARE_VERSIONS), dict)


HOST = 'www.example.test'
VERSION_HIT = {'template-id': 'cve-2020-11023', 'host': f'https://{HOST}', 'matched-at': f'https://{HOST}/js/jquery.min.js',
               'matcher-status': True, 'extracted-results': ['jQuery v3.4.1'], 'type': 'http',
               'request': 'GET /js/jquery.min.js HTTP/1.1', 'response': 'HTTP/1.1 200 OK\r\n\r\n/*! jQuery v3.4.1 | (c) JS Foundation */'}
TRAVERSAL_HIT = {'template-id': 'CVE-2021-41773', 'host': f'https://{HOST}', 'matched-at': f'https://{HOST}/icons/.%2e/%2e%2e/etc/passwd',
                 'matcher-status': True, 'type': 'http', 'request': 'GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1',
                 'response': 'HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash'}


class TemplateHitTests(Fixture):
    """The stored KEV jQuery match (CVE-2020-11023, version-only, smoke) meets a template test."""

    def setUp(self):
        super().setUp()
        self.entry = self.cve(Cve(1, JQUERY.affected, cve_id='CVE-2020-11023'), kev=True)
        CVEEntry.objects.filter(pk=self.entry.pk).update(cvss=6.9)
        self.entry.refresh_from_db()
        self.tech('jQuery:3.4.1')
        self.correlate()
        self.match = CVEMatch.objects.get(cve_entry=self.entry)
        triage.track(CVEMatch.objects.filter(pk=self.match.pk).select_related('cve_entry', 'subdomain__target_domain'))
        self.assertEqual(self.heat(), SMOKE)

    def heat(self):
        return threat.match_heat(CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=self.match.pk))

    def run_test(self, text, hit, vulnerable=True):
        outcome = [{'host': HOST, 'vulnerable': vulnerable, 'output': '{}' if vulnerable else '', **({'hit': hit} if vulnerable else {})}]
        with mock.patch('cveFeed.validation.resolve_template', return_value=('/templates/x.yaml', '')), \
                mock.patch('cveFeed.validation.approved_template', return_value=(text, '')), \
                mock.patch.object(templategen, '_run_template_with_retry', return_value=outcome), \
                mock.patch('cveFeed.auth_nuclei.merge_template_outcomes', side_effect=lambda path, hosts, outcomes, project: outcomes), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **kw: list(hosts)), \
                mock.patch('reNgine.ai_settings.get_configured_provider', side_effect=RuntimeError('none')), \
                mock.patch('cveFeed.notify._send', return_value=True) as send:
            from cveFeed.tasks import template_test_for_cve
            result = template_test_for_cve(self.entry.pk, [HOST], project_id=self.project.pk)
        return result, send

    @mock.patch.dict(os.environ, LEGACY)
    def test_a_version_regex_hit_is_not_hard_evidence_not_fire_and_not_paged(self):
        result, send = self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        match = CVEMatch.objects.select_related('triage').get(pk=self.match.pk)
        self.assertEqual(self.heat(), SMOKE)
        self.assertFalse(match_policy.has_hard_evidence(match.source, match.evidence, match.template_result, match.distro_status,
                                                        match.triage.validation_status))
        self.assertTrue(match_policy.is_version_only(match))
        self.assertFalse(CVEMatch.objects.filter(pk=self.match.pk).filter(match_policy.hard_evidence_q()).exists())  # the database form agrees
        self.assertNotEqual(match.triage.validation_status, 'hit')
        self.assertFalse(Vulnerability.objects.filter(source='nuclei-cve').exists())  # no confirmed finding beside it
        self.assertEqual(result['vulnerable'], [])
        self.assertEqual(send.call_count, 0)
        self.assertEqual(match.template_result, templategen.VERSION_ONLY_RESULT)  # what the test did see stays on the match

    def test_a_behavioural_hit_is_still_hard_evidence_fire_recorded_and_paged(self):
        result, send = self.run_test(APACHE_TRAVERSAL, TRAVERSAL_HIT)
        match = CVEMatch.objects.select_related('triage').get(pk=self.match.pk)
        self.assertEqual(match.template_result, 'vulnerable')
        self.assertEqual(self.heat(), FIRE)
        self.assertEqual(match.triage.validation_status, 'hit')
        self.assertEqual(Vulnerability.objects.filter(source='nuclei-cve').count(), 1)
        self.assertEqual(result['vulnerable'], [HOST])
        self.assertEqual(send.call_count, 1)
        self.assertIn('template test confirmed 1 vulnerable host', send.call_args.args[0])

    def test_the_real_user_agent_xss_template_stays_a_confirmed_hit(self):
        # nuclei-templates CVE-2017-4011: a plain GET of / whose User-Agent carries the payload; the review found it filed as a version check
        hit = {'template-id': 'CVE-2017-4011', 'host': f'https://{HOST}', 'matched-at': f'https://{HOST}', 'matcher-status': True, 'type': 'http',
               'request': "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 ... Firefox/40.1';alert(/XSS/);//",
               'response': "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nvar ua='Mozilla/5.0 ... Firefox/40.1';alert(/XSS/);//"}
        result, send = self.run_test(fixture('CVE-2017-4011.yaml'), hit)
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual((match.template_result, self.heat()), ('vulnerable', FIRE))
        self.assertEqual(Vulnerability.objects.filter(source='nuclei-cve').count(), 1)
        self.assertEqual((result['vulnerable'], send.call_count), ([HOST], 1))

    def test_another_testers_confirmation_survives_a_version_hit_and_a_miss(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable', template_id='openvas:1.3.6.1.4.1.25623.1.0.117251')
        self.assertEqual(self.heat(), FIRE)
        self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual((match.template_result, match.template_id[:8], self.heat()), ('vulnerable', 'openvas:', FIRE))
        self.run_test(APACHE_TRAVERSAL, None, vulnerable=False)
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual((match.template_result, match.template_id[:8], self.heat()), ('vulnerable', 'openvas:', FIRE))

    def test_a_version_hit_never_lowers_a_behavioural_templates_confirmation(self):
        self.run_test(APACHE_TRAVERSAL, TRAVERSAL_HIT)
        self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        self.assertEqual((CVEMatch.objects.get(pk=self.match.pk).template_result, self.heat()), ('vulnerable', FIRE))

    def test_the_validation_check_reads_a_version_hit_as_a_re_read_version(self):
        check = {'kind': 'nuclei_template', 'label': 'nuclei template for CVE-2020-11023', 'display': 'nuclei -t x', 'target': HOST,
                 'params': {'template': '/templates/x.yaml'}}
        for text, hit, status in ((JQUERY_VERSION_REGEX, VERSION_HIT, 'reaffirmed'), (APACHE_TRAVERSAL, TRAVERSAL_HIT, 'hit')):
            with mock.patch('cveFeed.validation.approved_template', return_value=(text, '')), \
                    mock.patch.object(templategen, '_run_template_with_retry',
                                      return_value=[{'host': HOST, 'vulnerable': True, 'output': '{}', 'hit': hit}]):
                self.assertEqual(validation.run_nuclei_template(check)['status'], status)

    @mock.patch.dict(os.environ, LEGACY)
    def test_a_version_hit_through_validation_pages_nothing_and_stays_smoke(self):
        row = Triage.objects.get(match=self.match)
        check = {'kind': 'nuclei_template', 'label': 'nuclei template for CVE-2020-11023', 'display': 'nuclei -t x', 'target': HOST,
                 'service': 'validate-nuclei', 'asset': HOST, 'params': {'template': '/templates/x.yaml'}}
        with mock.patch('cveFeed.validation.approved_template', return_value=(JQUERY_VERSION_REGEX, '')), \
                mock.patch.object(templategen, '_run_template_with_retry',
                                  return_value=[{'host': HOST, 'vulnerable': True, 'output': '{}', 'hit': VERSION_HIT}]), \
                mock.patch('cveFeed.notify._send', return_value=True) as send, \
                mock.patch.object(scoring, 'evidence_arrived', wraps=scoring.evidence_arrived) as arrived:
            validation.apply_validation(row, check, validation.run_nuclei_template(check))
        row.refresh_from_db()
        self.assertEqual(row.validation_status, 'observed')
        self.assertNotEqual(row.classification, 'confirmed')
        self.assertEqual(self.heat(), SMOKE)
        self.assertEqual((send.call_count, arrived.call_count), (0, 0))

    def test_template_hits_respects_the_version_only_cap(self):
        pair = [('CVE-2020-11023', HOST)]
        with mock.patch('cveFeed.notify._send', return_value=True) as send:
            CVEMatch.objects.filter(pk=self.match.pk).update(template_result=templategen.VERSION_ONLY_RESULT)
            self.assertFalse(notify.template_hits(pair))  # version-only on the host: smoke, not paged as a confirmed hit
            self.assertEqual(send.call_count, 0)
            CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable')
            self.assertTrue(notify.template_hits(pair))
            self.assertTrue(notify.template_hits([('CVE-2099-77', 'no-match.example.test')]))  # a hit with no stored match is paged as before
            CVEMatch.objects.filter(pk=self.match.pk).update(template_result='')
            self.assertTrue(notify.template_hits(pair))  # nor is a genuine hit held back because its result is not recorded yet
        self.assertEqual(send.call_count, 3)

    @mock.patch.dict(os.environ, LEGACY)
    def test_fire_confirmed_never_pages_a_version_class_hit(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result=templategen.VERSION_ONLY_RESULT)
        with mock.patch('cveFeed.notify._send', return_value=True) as send:
            scoring.evidence_arrived([self.match.pk], confirmed=[self.match.pk])
        self.assertEqual(send.call_count, 0)
        self.assertIsNone(CVEMatch.objects.get(pk=self.match.pk).fire_notified_at)

    # --- the same under the KEV heat policy (the default) ----------------------------------------------------------------------------

    def test_under_the_kev_rule_a_version_regex_hit_proves_the_version_and_pages_once(self):
        with mock.patch.object(scoring, 'rescore_for_matches') as rescored:
            result, send = self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        match = CVEMatch.objects.select_related('triage').get(pk=self.match.pk)
        self.assertEqual(match.template_result, templategen.VERSION_ONLY_RESULT)
        self.assertEqual(self.heat(), FIRE)  # on the KEV and the version proven on the host
        self.assertTrue(match_policy.version_proven(match))
        self.assertFalse(match_policy.has_hard_evidence(match.source, match.evidence, match.template_result, match.distro_status,
                                                        match.triage.validation_status))  # the flaw is not shown: triage unchanged
        self.assertFalse(Vulnerability.objects.filter(source='nuclei-cve').exists())  # still no confirmed finding
        self.assertEqual(result['vulnerable'], [])
        self.assertEqual(send.call_count, 1)  # one page: confirmed, now fire-tier (never a "template test confirmed" message)
        self.assertIn('confirmed, now fire-tier', send.call_args.args[0])
        self.assertTrue(rescored.called)
        self.assertEqual(match.fire_notified_rule, 'kev')
        _result, send = self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)  # the same hit again: already fire, not paged again
        self.assertEqual(send.call_count, 0)

    def test_under_the_kev_rule_fire_confirmed_pages_a_version_class_hit_on_a_kev_match_once(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result=templategen.VERSION_ONLY_RESULT)
        with mock.patch('cveFeed.notify._send', return_value=True) as send:
            scoring.evidence_arrived([self.match.pk], confirmed=[self.match.pk])
            scoring.evidence_arrived([self.match.pk], confirmed=[self.match.pk])
        self.assertEqual(send.call_count, 1)
        self.assertIsNotNone(CVEMatch.objects.get(pk=self.match.pk).fire_notified_at)

    def test_under_the_kev_rule_a_version_hit_through_validation_proves_the_version_and_pages_once(self):
        row = Triage.objects.get(match=self.match)
        check = {'kind': 'nuclei_template', 'label': 'nuclei template for CVE-2020-11023', 'display': 'nuclei -t x', 'target': HOST,
                 'service': 'validate-nuclei', 'asset': HOST, 'params': {'template': '/templates/x.yaml'}}
        with mock.patch('cveFeed.validation.approved_template', return_value=(JQUERY_VERSION_REGEX, '')), \
                mock.patch.object(templategen, '_run_template_with_retry',
                                  return_value=[{'host': HOST, 'vulnerable': True, 'output': '{}', 'hit': VERSION_HIT}]), \
                mock.patch('cveFeed.notify._send', return_value=True) as send:
            validation.apply_validation(row, check, validation.run_nuclei_template(check))
            row.refresh_from_db()
            validation.apply_validation(row, check, validation.run_nuclei_template(check))  # the same check again: not paged again
        row.refresh_from_db()
        match = CVEMatch.objects.select_related('triage').get(pk=self.match.pk)
        self.assertEqual(row.validation_status, 'observed')  # a re-read version, not a validation hit
        self.assertNotEqual(row.classification, 'confirmed')
        self.assertEqual(match.template_result, templategen.VERSION_ONLY_RESULT)
        self.assertEqual(self.heat(), FIRE)  # the same proof as the template pass: on the KEV and the version proven
        self.assertFalse(Vulnerability.objects.filter(source='nuclei-cve').exists())
        self.assertEqual(send.call_count, 1)
        self.assertIn('confirmed, now fire-tier', send.call_args.args[0])

    def test_under_the_kev_rule_a_version_hit_on_a_cve_that_is_not_hot_pages_nothing(self):
        CVEEntry.objects.filter(pk=self.entry.pk).update(kev=False, exploit_db=False)
        _result, send = self.run_test(JQUERY_VERSION_REGEX, VERSION_HIT)
        self.assertEqual(send.call_count, 0)
        self.assertEqual(threat.match_heat(CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=self.match.pk)), threat.ICE)
