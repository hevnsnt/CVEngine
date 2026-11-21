"""A template hit is read for what it showed (cveFeed.templategen.hit_evidence), not only for what its template looks like.

The live case: an AI-written check for CVE-2024-38475 (and one for CVE-2023-25690) sent ``GET /`` to a RHEL httpd behind a proxy, read
``Server: Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k``, and matched a word ``Apache`` and a version regex. The static classifier
(``template_evidence``, an allowlist) did not recognise the word (the AI's name has no " - Title" part to take the product from), so the hit was
recorded as ``vulnerable``: triage confirmed it over the AI's own reasoning, the heat went to fire and a confirmed nuclei-cve finding was filed.

The hit itself shows it read a version: the offline evaluator matches the recorded response, stops matching once the version numbers are replaced
by one no range covers, and still matches on what surrounds the version numbers alone. Such a hit is ``version_only``; a hit of the same check
read correctly replaces the stored confirmation and closes the finding that check filed, and a match on a distribution's build is not even
"version proven" by it.
"""
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase

from cveFeed import closure, match_policy, templatefixture, templategen, triage, validation
from cveFeed.models import CVEMatch, FindingAuditEvent, GeneratedTemplate, Triage
from startScan.models import Vulnerability
from tests.test_match_policy import Cve, Fixture, affected

V, B = templategen.VERSION_EVIDENCE, templategen.BEHAVIOR_EVIDENCE
HOST = 'www.example.test'
TEMPLATE_ID = 'cve-2024-38475-ai'

# what the AI writer produces for an httpd range: a plain GET, the product word and a version regex on the Server header
AI_APACHE = r"""
id: cve-2024-38475-ai
info:
  name: Apache HTTP Server mod_rewrite Improper Escaping (CVE-2024-38475)
  author: cvengine-ai
  severity: critical
  classification:
    cve-id: CVE-2024-38475
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Apache"
      - type: regex
        part: header
        regex:
          - 'Apache/2\.4\.([0-9]|[1-4][0-9]|5[0-9])\b'
"""

RHEL_RESPONSE = ('HTTP/1.1 200 OK\r\nDate: Mon, 16 Nov 2026 10:00:00 GMT\r\n'
                 'Server: Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k\r\nVia: 1.1 google\r\n'
                 'Content-Type: text/html; charset=UTF-8\r\n\r\n<html><head><title>Media</title></head><body>Welcome</body></html>')

# a behaviour check: a database file that should never be served, read from a plain path
SQLITE_EXPOSED = """
id: cve-2099-0001-ai
info:
  name: Example App Database Exposure (CVE-2099-0001)
  author: cvengine-ai
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/data/app.sqlite"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "SQLite format 3"
      - type: status
        status:
          - 200
"""
SQLITE_RESPONSE = 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.37\r\nContent-Type: application/octet-stream\r\n\r\nSQLite format 3 users table'

# the same marker gated on the version: the hit needed the marker too, so it showed more than the version
SQLITE_ON_VERSION = SQLITE_EXPOSED.replace("""      - type: status
        status:
          - 200
""", """      - type: regex
        part: header
        regex:
          - 'Apache/2\\.4\\.[0-9]+'
""")

# a disclosure of an internal address: dotted numbers that are not a version
INTERNAL_ADDRESS = r"""
id: cve-2099-0002-ai
info:
  name: Example Proxy Internal Address Disclosure (CVE-2099-0002)
  author: cvengine-ai
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - 'X-Backend: 10\.0\.0\.[0-9]+'
"""
ADDRESS_RESPONSE = 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.37\r\nX-Backend: 10.0.0.12\r\n\r\nok'

# an official-style check decided by a dsl expression: the offline evaluator cannot decide it, so nothing changes
DSL_TEMPLATE = """
id: CVE-2099-0003
info:
  name: Example Server - Version Check
  author: community
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(header, 'Apache/2.4.')"
"""

# a request that carries a payload: whatever it matched, the answer may be owed to what was sent
PAYLOAD_TEMPLATE = AI_APACHE.replace('"{{BaseURL}}"', '"{{BaseURL}}/?q=%3Cscript%3E"')

# two pages, any matcher alone: the recorded hit is one of them and the other may have matched on its marker
TWO_PAGES_OR = r"""
id: cve-2099-0004-ai
info:
  name: Example Two Pages (CVE-2099-0004)
  author: cvengine-ai
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/data/app.sqlite"
    matchers-condition: or
    matchers:
      - type: regex
        part: header
        regex:
          - 'Apache/2\.4\.([0-9]|[1-4][0-9]|5[0-9])\b'
      - type: word
        part: body
        words:
          - "SQLite format 3"
"""

SSH_BANNER = r"""
id: cve-2099-0005-ai
info:
  name: Example SSH Banner (CVE-2099-0005)
  author: cvengine-ai
  severity: high
tcp:
  - host:
      - "{{Hostname}}"
    port: 22
    read-size: 64
    matchers:
      - type: regex
        regex:
          - 'OpenSSH_7\.[0-4]'
"""


def outcome(response, vulnerable=True, template_id=TEMPLATE_ID, **extra):
    hit = {'template-id': template_id, 'template': f'{template_id}.yaml', 'type': 'http', 'host': f'https://{HOST}',
           'matched-at': f'https://{HOST}/', 'extracted-results': ['Apache/2.4.37'], 'request': f'GET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n',
           'response': response, 'info': {'name': 'Apache HTTP Server mod_rewrite (CVE-2024-38475)', 'severity': 'critical',
                                          'classification': {'cve-id': ['CVE-2024-38475']}}}
    return {'host': HOST, 'vulnerable': vulnerable, 'output': '{}', 'hit': hit if vulnerable else None, **extra}


class HitEvidenceTests(SimpleTestCase):
    def test_the_ai_apache_version_check_on_the_rhel_banner_is_a_version_read(self):
        self.assertEqual(templategen.template_evidence(AI_APACHE), B)  # the static allowlist does not know this shape
        self.assertTrue(templatefixture.matches(AI_APACHE, templategen._parse_hit_response(RHEL_RESPONSE, False)[0]))
        self.assertEqual(templategen.hit_evidence(AI_APACHE, outcome(RHEL_RESPONSE)), V)
        self.assertEqual(templategen.outcome_evidence(AI_APACHE, outcome(RHEL_RESPONSE), B), V)

    def test_a_server_apache_word_is_read_the_same_way(self):
        text = AI_APACHE.replace('- "Apache"', '- "Server: Apache"')
        self.assertEqual(templategen.hit_evidence(text, outcome(RHEL_RESPONSE)), V)

    def test_a_behaviour_check_stays_behaviour(self):
        self.assertEqual(templategen.hit_evidence(SQLITE_EXPOSED, outcome(SQLITE_RESPONSE)), B)

    def test_a_marker_gated_on_the_version_stays_behaviour(self):
        # without the version the hit is gone, but it also needed the file's magic: it showed more than a version
        self.assertTrue(templatefixture.matches(SQLITE_ON_VERSION, templategen._parse_hit_response(SQLITE_RESPONSE, False)[0]))
        self.assertEqual(templategen.hit_evidence(SQLITE_ON_VERSION, outcome(SQLITE_RESPONSE)), B)

    def test_an_address_is_not_a_version(self):
        self.assertEqual(templategen.hit_evidence(INTERNAL_ADDRESS, outcome(ADDRESS_RESPONSE)), B)
        fixture = templategen._neutralised({'status': 200, 'headers': {'Server': 'Apache/2.4.37 OpenSSL/1.1.1k', 'X-Backend': '10.0.0.12'},
                                            'body': 'at 192.168.10.1 and v3.5.1, build 2.4.37el8'})
        self.assertEqual(fixture['headers'], {'Server': 'Apache/0.0 OpenSSL/0.0', 'X-Backend': '10.0.0.12'})
        self.assertEqual(fixture['body'], 'at 192.168.10.1 and v0.0, build 0.0l8')

    def test_a_dsl_check_is_unchanged(self):
        self.assertEqual(templategen.template_evidence(DSL_TEMPLATE), B)
        self.assertEqual(templategen.hit_evidence(DSL_TEMPLATE, outcome(RHEL_RESPONSE)), B)

    def test_a_request_with_a_payload_stays_behaviour(self):
        self.assertEqual(templategen.hit_evidence(PAYLOAD_TEMPLATE, outcome(RHEL_RESPONSE)), B)

    def test_two_pages_with_an_or_and_a_marker_stay_behaviour(self):
        # the recorded hit read the version, but the other page's answer may have matched the marker
        self.assertEqual(templategen.hit_evidence(TWO_PAGES_OR, outcome(RHEL_RESPONSE)), B)

    def test_a_clipped_response_is_judged_only_when_every_matcher_holds_on_what_was_kept(self):
        long_body = RHEL_RESPONSE + 'x' * 8000
        self.assertEqual(templategen.hit_evidence(AI_APACHE, outcome(long_body)), V)  # it reads the headers, which are whole
        whole = AI_APACHE.replace('part: header\n        words', 'part: all\n        words')
        self.assertEqual(templategen.hit_evidence(whole, outcome(long_body)), V)  # both matchers hold on what was kept
        # any matcher alone: a marker in the lost tail may have been what matched
        either = AI_APACHE.replace('matchers-condition: and', 'matchers-condition: or').replace(
            'part: header\n        words:\n          - "Apache"', 'part: body\n        words:\n          - "debug-console"')
        self.assertEqual(templategen.hit_evidence(either, outcome(RHEL_RESPONSE)), V)  # whole: the marker is not there, the version decided
        self.assertEqual(templategen.hit_evidence(either, outcome(long_body)), B)
        self.assertEqual(templategen.hit_evidence(AI_APACHE, outcome(RHEL_RESPONSE.split('\r\n\r\n')[0] + 'X-Pad: ' + 'y' * 5000)), B)

    def test_doubt_is_behaviour(self):
        for response in (None, '', 'not an http response', 'HTTP/1.1 200 OK\r\nbroken header line\r\n\r\nx'):
            self.assertEqual(templategen.hit_evidence(AI_APACHE, outcome(response)), B, response)
        self.assertEqual(templategen.hit_evidence(AI_APACHE, {'host': HOST, 'vulnerable': True}), B)
        self.assertEqual(templategen.hit_evidence('id: [', outcome(RHEL_RESPONSE)), B)
        # the evaluator does not agree with the scanner (the banner is outside the regex): never read as a version hit
        self.assertEqual(templategen.hit_evidence(AI_APACHE, outcome(RHEL_RESPONSE.replace('2.4.37', '2.4.62'))), B)
        with mock.patch.object(templatefixture, '_regex_found', side_effect=templatefixture.Unsupported('slow')):
            self.assertEqual(templategen.hit_evidence(AI_APACHE, outcome(RHEL_RESPONSE)), B)

    def test_a_miss_or_an_error_keeps_the_static_reading(self):
        self.assertEqual(templategen.outcome_evidence(AI_APACHE, outcome(RHEL_RESPONSE, vulnerable=False), B), B)
        self.assertEqual(templategen.outcome_evidence(AI_APACHE, outcome(RHEL_RESPONSE, error='timeout'), B), B)

    def test_a_network_banner(self):
        self.assertEqual(templategen.hit_evidence(SSH_BANNER, outcome('SSH-2.0-OpenSSH_7.4\r\n')), V)


class ValidationCheckTests(SimpleTestCase):
    def test_the_validation_check_reads_the_ai_apache_hit_as_a_re_read_version(self):
        check = {'kind': 'nuclei_template', 'label': 'nuclei template for CVE-2024-38475', 'display': 'nuclei -t x', 'target': HOST,
                 'params': {'template': f'/templates/{TEMPLATE_ID}.yaml'}}
        for text, response, status in ((AI_APACHE, RHEL_RESPONSE, 'reaffirmed'), (SQLITE_EXPOSED, SQLITE_RESPONSE, 'hit')):
            with mock.patch('cveFeed.validation.approved_template', return_value=(text, '')), \
                    mock.patch.object(templategen, '_test_chunk', return_value=[outcome(response)]):
                self.assertEqual(validation.run_nuclei_template(check)['status'], status)


HTTPD = Cve(1, affected('HTTP Server', '2.4.0', '2.4.59', 'apache'), cve_id='CVE-2024-38475')


class RecordTests(Fixture):
    def setUp(self):
        super().setUp()
        self.entry = self.cve(HTTPD)
        self.match = self.match_for(self.entry, source='tech', product='HTTP Server', version='2.4.37', in_range=True,
                                    evidence={'source': 'tech', 'raw_version': '2.4.37'}, remediation_status='in_progress')
        triage.track(triage.with_cves(CVEMatch.objects.filter(pk=self.match.pk).select_related('subdomain__target_domain')))

    def confirm(self, template_id=TEMPLATE_ID):
        """The confirmation the bug recorded: the hit read as behaviour, a nuclei-cve finding filed."""
        templategen.record_outcomes(self.entry, [{**outcome(RHEL_RESPONSE, template_id=template_id), 'template_evidence': B}],
                                    project=self.project.pk, template_id=template_id)
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')
        return Vulnerability.objects.get(source='nuclei-cve', template_id=template_id)

    def version_hit(self, template_id=TEMPLATE_ID):
        templategen.record_outcomes(self.entry, [{**outcome(RHEL_RESPONSE, template_id=template_id), 'template_evidence': V}],
                                    project=self.project.pk, template_id=template_id)

    def test_the_same_checks_version_hit_replaces_its_confirmation_and_closes_its_finding(self):
        finding = self.confirm()
        # what the bug left: the row tracked on the confirmation, confirmed over the AI and with the hit as its validation record
        triage.track(triage.with_cves(CVEMatch.objects.filter(pk=self.match.pk).select_related('subdomain__target_domain')))
        Triage.objects.filter(match=self.match).update(classification='confirmed', validation_status='hit')
        row = Triage.objects.get(match=self.match)
        self.assertTrue(any('nuclei template' in fact for fact in row.hard_evidence))
        before_signature = row.signature
        self.version_hit()
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual(match.template_result, templategen.VERSION_ONLY_RESULT)
        self.assertEqual(match.remediation_status, 'in_progress')  # a person's remediation status is never touched
        finding.refresh_from_db()
        self.assertEqual(finding.remediation_status, 'false_positive')
        self.assertTrue(finding.remediation_note.startswith(closure.AUTOMATIC))
        self.assertIn('only read the version string', finding.remediation_note)
        self.assertTrue(closure.closure_of('vulnerability', finding)[3])  # read back as closed automatically
        self.assertTrue(FindingAuditEvent.objects.filter(finding_kind='vulnerability', finding_id=finding.pk, actor=None,
                                                         after__status='false_positive').exists())
        row.refresh_from_db()  # the triage starts over on the new evidence: no template confirmation any more
        self.assertNotEqual(row.signature, before_signature)
        self.assertEqual((row.classification, row.validation_status), ('', 'none'))
        self.assertFalse(any('nuclei template' in fact for fact in row.hard_evidence))
        self.assertTrue(match_policy.is_version_only(CVEMatch.objects.select_related('triage').get(pk=self.match.pk)))

    def test_another_templates_version_hit_does_not_lower_the_confirmation(self):
        finding = self.confirm()
        self.version_hit(template_id='cve-2024-38475-other')
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')
        finding.refresh_from_db()
        self.assertEqual(finding.remediation_status, 'open')

    def test_a_miss_or_an_error_of_the_same_check_does_not_lower_it(self):
        self.confirm()
        for extra in ({'vulnerable': False}, {'error': 'timeout'}):
            templategen.record_outcomes(self.entry, [{**outcome(RHEL_RESPONSE), **extra, 'template_evidence': B}],
                                        project=self.project.pk, template_id=TEMPLATE_ID)
            self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')

    def test_a_finding_a_person_changed_is_left_alone(self):
        finding = self.confirm()
        Vulnerability.objects.filter(pk=finding.pk).update(remediation_status='in_progress')
        self.version_hit()
        finding.refresh_from_db()
        self.assertEqual(finding.remediation_status, 'in_progress')
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, templategen.VERSION_ONLY_RESULT)

    def test_the_template_pass_records_the_ai_apache_hit_as_version_only(self):
        with mock.patch('cveFeed.validation.resolve_template', return_value=(f'/templates/{TEMPLATE_ID}.yaml', '')), \
                mock.patch('cveFeed.validation.approved_template', return_value=(AI_APACHE, '')), \
                mock.patch.object(templategen, '_test_chunk', return_value=[outcome(RHEL_RESPONSE)]), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **kw: list(hosts)):
            result = templategen.run_cve_tests(self.entry, [HOST], project=self.project)
        self.assertEqual(result['results'][0]['template_evidence'], V)
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, templategen.VERSION_ONLY_RESULT)
        self.assertFalse(Vulnerability.objects.filter(source='nuclei-cve').exists())


class DistroProofTests(Fixture):
    def test_a_version_hit_on_a_distribution_build_proves_no_version(self):
        entry = self.cve(HTTPD)
        rhel = {'source': 'tech', 'distro': {'distro': 'rhel', 'release': '8'}}
        self.assertFalse(match_policy.version_read_from_component(rhel, '', templategen.VERSION_ONLY_RESULT))
        self.assertTrue(match_policy.version_read_from_component({'source': 'tech'}, '', templategen.VERSION_ONLY_RESULT))
        on_rhel = self.match_for(entry, version='2.4.37', in_range=True, evidence=rhel, template_result=templategen.VERSION_ONLY_RESULT)
        plain = self.match_for(self.cve(Cve(2, HTTPD.affected, cve_id='CVE-2023-25690')), version='2.4.37', in_range=True,
                               evidence={'source': 'tech'}, template_result=templategen.VERSION_ONLY_RESULT)
        proven = set(CVEMatch.objects.filter(match_policy.version_read_from_component_q()).values_list('pk', flat=True))
        self.assertEqual(proven, {plain.pk})
        self.assertEqual(match_policy.proof_of(on_rhel), '')
        self.assertFalse(match_policy.version_proven(on_rhel))
        self.assertTrue(match_policy.version_proven(plain))


class RecheckCommandTests(Fixture):
    """The one-time correction of the confirmations already stored (``manage.py recheck_template_hits``, run once after the update)."""

    def setUp(self):
        super().setUp()
        self.entry = self.cve(HTTPD)
        self.match = self.match_for(self.entry, source='tech', product='HTTP Server', version='2.4.37', in_range=True,
                                    evidence={'source': 'tech'}, remediation_status='in_progress')
        GeneratedTemplate.objects.create(cve_entry=self.entry, template_id=TEMPLATE_ID, yaml=AI_APACHE, status=GeneratedTemplate.STATUS_VALID,
                                         path=f'/generated/{TEMPLATE_ID}.yaml')
        triage.track(triage.with_cves(CVEMatch.objects.filter(pk=self.match.pk).select_related('subdomain__target_domain')))

    def stored_confirmation(self):
        templategen.record_outcomes(self.entry, [{**outcome(RHEL_RESPONSE), 'template_evidence': B}], project=self.project.pk,
                                    template_id=TEMPLATE_ID)
        return Vulnerability.objects.get(source='nuclei-cve')

    def test_a_dry_run_changes_nothing_and_apply_corrects_from_the_findings_response(self):
        finding = self.stored_confirmation()
        call_command('recheck_template_hits', stdout=mock.MagicMock())
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')
        call_command('recheck_template_hits', '--apply', stdout=mock.MagicMock())
        match = CVEMatch.objects.get(pk=self.match.pk)
        self.assertEqual((match.template_result, match.remediation_status), (templategen.VERSION_ONLY_RESULT, 'in_progress'))
        finding.refresh_from_db()
        self.assertEqual(finding.remediation_status, 'false_positive')
        call_command('recheck_template_hits', '--apply', stdout=mock.MagicMock())  # idempotent: nothing left to change

    def test_the_validation_steps_response_serves_when_no_finding_kept_one(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable', template_id=TEMPLATE_ID)
        Triage.objects.filter(match=self.match).update(validation_status='hit', validation_evidence={'nuclei_template': {
            'matched_at': f'https://{HOST}/', 'response': RHEL_RESPONSE[:4096], 'request': 'GET / HTTP/1.1'}})
        call_command('recheck_template_hits', '--apply', stdout=mock.MagicMock())
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, templategen.VERSION_ONLY_RESULT)
        self.assertNotEqual(Triage.objects.get(match=self.match).validation_status, 'hit')

    def test_a_behaviour_hit_and_a_hit_with_no_stored_response_stay(self):
        GeneratedTemplate.objects.filter(template_id=TEMPLATE_ID).update(yaml=SQLITE_ON_VERSION)
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable', template_id=TEMPLATE_ID)
        call_command('recheck_template_hits', '--apply', stdout=mock.MagicMock())  # nothing stored to read the hit from
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')
        Triage.objects.filter(match=self.match).update(validation_evidence={'nuclei_template': {'response': SQLITE_RESPONSE}})
        call_command('recheck_template_hits', '--apply', stdout=mock.MagicMock())
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')

    def test_an_installed_templates_confirmation_is_not_looked_at(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(template_result='vulnerable', template_id='CVE-2024-38475')
        Triage.objects.filter(match=self.match).update(validation_evidence={'nuclei_template': {'response': RHEL_RESPONSE}})
        call_command('recheck_template_hits', '--apply', stdout=mock.MagicMock())
        self.assertEqual(CVEMatch.objects.get(pk=self.match.pk).template_result, 'vulnerable')
