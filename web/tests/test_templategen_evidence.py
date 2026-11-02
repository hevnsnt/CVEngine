"""A template hit is hard evidence only when the template shows more than a version string (cveFeed.templategen.template_evidence).

The design review's latent hole: the template writer is told to detect "by version or a safe response marker" and the static gate accepts a
version regex, so a template that regex-matches ``jQuery v3.4.1`` in a script set ``template_result='vulnerable'``. That made a version-only
match hard evidence (``match_policy.has_hard_evidence``), lifted it to fire, recorded a confirmed nuclei-cve finding and paged it through
``notify.template_hits``, which never looked at heat. A version-class hit is now recorded as ``version_only``: the version re-read, never a
confirmation. Behavioural templates (a traversal that reads /etc/passwd, an exposed file, a request carrying a payload) are unchanged.
"""
from unittest import mock

import yaml
from django.test import SimpleTestCase

from cveFeed import match_policy, notify, scoring, templategen, threat, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, SMOKE
from startScan.models import Vulnerability
from tests.test_match_policy import JQUERY, Cve, Fixture

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

VERSION = {'jquery version regex': JQUERY_VERSION_REGEX, 'wp plugin compare_versions': WP_PLUGIN_COMPARE_VERSIONS,
           'apache server header': APACHE_HEADER_BANNER, 'openssh banner': OPENSSH_BANNER}
BEHAVIOR = {'apache traversal': APACHE_TRAVERSAL, 'exposed git config': GIT_CONFIG_EXPOSED, 'header payload with a version guard': HEADER_BYPASS_WITH_VERSION,
            'version or marker': VERSION_OR_MARKER, 'ip disclosure': IP_DISCLOSURE, 'ssl': SSL_WEAK}


class ClassificationTests(SimpleTestCase):
    def test_templates_that_only_read_a_version_are_version_class(self):
        for name, text in VERSION.items():
            self.assertEqual(templategen.template_evidence(text), templategen.VERSION_EVIDENCE, name)

    def test_templates_that_show_the_flaw_stay_behaviour_class(self):
        for name, text in BEHAVIOR.items():
            self.assertEqual(templategen.template_evidence(text), templategen.BEHAVIOR_EVIDENCE, name)

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

    def run_test(self, text, hit):
        outcome = [{'host': HOST, 'vulnerable': True, 'output': '{}', 'hit': hit}]
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

    def test_the_validation_check_reads_a_version_hit_as_a_re_read_version(self):
        check = {'kind': 'nuclei_template', 'label': 'nuclei template for CVE-2020-11023', 'display': 'nuclei -t x', 'target': HOST,
                 'params': {'template': '/templates/x.yaml'}}
        for text, hit, status in ((JQUERY_VERSION_REGEX, VERSION_HIT, 'reaffirmed'), (APACHE_TRAVERSAL, TRAVERSAL_HIT, 'hit')):
            with mock.patch('cveFeed.validation.approved_template', return_value=(text, '')), \
                    mock.patch.object(templategen, '_run_template_with_retry',
                                      return_value=[{'host': HOST, 'vulnerable': True, 'output': '{}', 'hit': hit}]):
                self.assertEqual(validation.run_nuclei_template(check)['status'], status)

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

    def test_fire_confirmed_never_pages_a_version_class_hit(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result=templategen.VERSION_ONLY_RESULT)
        with mock.patch('cveFeed.notify._send', return_value=True) as send:
            scoring.evidence_arrived([self.match.pk], confirmed=[self.match.pk])
        self.assertEqual(send.call_count, 0)
        self.assertIsNone(CVEMatch.objects.get(pk=self.match.pk).fire_notified_at)
