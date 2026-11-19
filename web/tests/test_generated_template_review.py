"""The review of AI-written templates over REST and MCP (agentapi.generated_templates, cveFeed.template_review).

The live case: two AI-written checks "confirmed" CVE-2024-38475 and CVE-2023-25690 on a RHEL httpd by reading the Server header's version.
Nobody could see their YAML, and the only fix was to expire them and let the AI try again, which kept every confirmation they made. Now an
App Admin or an agent lists and reads them (text for every member, outcomes only on the caller's own hosts), gets a review report, retires
one (its confirmations read again, its finding closed, a match's remediation status untouched) or revises it (a new draft that passes every
gate before it runs anywhere, and retires the old one when it does)."""
import datetime
import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import template_review, templatefixture, templategen, templatevalidate, triage, validation
from cveFeed.models import AgentActivity, AIJob, CVEEntry, CVEMatch, GeneratedTemplate, GeneratedTemplateReview, ReviewerSettings
from dashboard.models import AuditLog, Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

CVE_ID = 'CVE-2024-38475'
TEMPLATE_ID = 'cve-2024-38475'
HOST_A, HOST_B = 'www.a.example', 'www.b.example'

# the AI's check as it ran: the word Apache and a version regex on the Server header of the site root
AI_APACHE = r"""id: cve-2024-38475
info:
  name: Apache HTTP Server mod_rewrite Improper Escaping (CVE-2024-38475)
  author: cvengine-ai
  severity: critical
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
RHEL_RESPONSE = ('HTTP/1.1 200 OK\r\nServer: Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k\r\n'
                 'Content-Type: text/html; charset=UTF-8\r\n\r\n<html><head><title>Media</title></head><body>Welcome</body></html>')

# a statically version-class check: one plain read decided by a version regex alone
VERSION_ONLY = r"""id: cve-2024-38475
info:
  name: Apache HTTP Server 2.4.59 - mod_rewrite Improper Escaping
  severity: critical
  classification:
    cve-id: CVE-2024-38475
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - 'Apache/2\.4\.([0-9]|[1-4][0-9]|5[0-9])\b'
"""

# what a reviser writes instead: a marker only an affected host returns
REVISION = """id: cve-2024-38475
info:
  name: Apache HTTP Server mod_rewrite escaping marker (CVE-2024-38475)
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/rewrite-check/marker.txt"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "unescaped rewrite target 38475"
      - type: status
        status:
          - 200
"""
AFFECTED = {'status': 200, 'headers': {'Server': 'Apache'}, 'body': 'unescaped rewrite target 38475 reached'}
FIXED = {'status': 403, 'headers': {'Server': 'Apache'}, 'body': 'Forbidden'}
FIXTURE_REPLY = json.dumps({'vulnerable': AFFECTED, 'not_affected': FIXED})
AGREE = json.dumps({'verdict': 'agree', 'reasons': ['reads one path and matches a marker only an affected host returns']})
SENTINEL_OK = (True, 'validated', True, 'no benign match')


def outcome(host, response):
    hit = {'template-id': TEMPLATE_ID, 'template': f'{TEMPLATE_ID}.yaml', 'type': 'http', 'host': f'https://{host}', 'matched-at': f'https://{host}/',
           'request': f'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n', 'response': response,
           'info': {'name': 'Apache HTTP Server mod_rewrite (CVE-2024-38475)', 'severity': 'critical'}}
    return {'host': host, 'vulnerable': True, 'output': '{}', 'hit': hit, 'template_evidence': templategen.BEHAVIOR_EVIDENCE}


class World(TestCase):
    def setUp(self):
        cache.clear()
        now = timezone.now()
        self.dir = tempfile.mkdtemp()
        for patcher in (mock.patch.object(templategen, 'GENERATED_DIR', str(Path(self.dir) / 'generated')),
                        mock.patch('cvengine_scanner.template_index.load', return_value={'nuclei_templates': '', 'rules': 0, 'reasons': [], 'templates': {}, 'sha256': ''}),
                        mock.patch('cveFeed.ai_jobs.ai_on', return_value=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        templategen.invalidate_template_index()
        self.addCleanup(templategen.invalidate_template_index)
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.projects, self.matches = {}, {}
        for key, host in (('a', HOST_A), ('b', HOST_B)):
            org = Org.objects.create(name=f'Org {key}', slug=f'org-{key}')
            project = Project.objects.create(name=key.upper(), slug=f'proj-{key}', insert_date=now, org=org)
            domain = Domain.objects.create(name=f'{key}.example', project=project, insert_date=now)
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now)
            Subdomain.objects.create(name=host, target_domain=domain, scan_history=scan)
            self.projects[key] = project
        self.cve = CVEEntry.objects.create(cve_id=CVE_ID, cvss=9.8, published_at=now, title='mod_rewrite', original_description='httpd 2.4.59 and older',
                                           affected=[{'vendor': 'apache', 'product': 'HTTP Server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.60'}]}])
        for key, host in (('a', HOST_A), ('b', HOST_B)):
            sub = Subdomain.objects.get(name=host)
            self.matches[key] = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, source='tech', matched_product='HTTP Server',
                                                        matched_version='2.4.37', version_in_range=True, evidence={'source': 'tech'},
                                                        confidence=0.5, remediation_status='in_progress')
            triage.track(triage.with_cves(CVEMatch.objects.filter(pk=self.matches[key].pk).select_related('subdomain__target_domain')))
        self.tmpl = self.installed(AI_APACHE)
        # what the bug left: both hosts confirmed and a finding filed on each; A's finding kept the RHEL response, B's kept none that parses
        templategen.record_outcomes(self.cve, [outcome(HOST_A, RHEL_RESPONSE)], project=self.projects['a'].pk, template_id=TEMPLATE_ID)
        templategen.record_outcomes(self.cve, [outcome(HOST_B, 'no response kept')], project=self.projects['b'].pk, template_id=TEMPLATE_ID)
        self.tmpl.test_results = [{'host': HOST_A, 'vulnerable': True, 'output': ''}, {'host': HOST_B, 'vulnerable': True, 'output': ''}]
        self.tmpl.save(update_fields=['test_results'])
        self.root = User.objects.create_superuser('root', 'root@example.test', 'x')
        self.alice = User.objects.create_user('alice', password='x')
        ProjectMembership.objects.create(user=self.alice, project=self.projects['a'], role='admin')
        _, self.t_root = create_token(self.root, 'root')
        _, self.t_root_ro = create_token(self.root, 'root-ro', read_only=True)
        _, self.t_alice = create_token(self.alice, 'alice')

    def installed(self, text):
        path = templategen.save_template_file(TEMPLATE_ID, text)
        return GeneratedTemplate.objects.create(cve_entry=self.cve, template_id=TEMPLATE_ID, yaml=text, status=GeneratedTemplate.STATUS_VALID, path=path,
                                                ai_model='test:model', positive_fixture_verified_at=timezone.now(), positive_fixture_source='test',
                                                fixture={'vulnerable': {'status': 200, 'headers': {'Server': 'Apache/2.4.37'}, 'body': ''},
                                                         'not_affected': {'status': 200, 'headers': {'Server': 'Apache/2.4.62'}, 'body': ''}})

    def match(self, key):
        return CVEMatch.objects.get(pk=self.matches[key].pk)

    def finding(self, host):
        return Vulnerability.objects.get(source='nuclei-cve', subdomain__name=host)


class ListAndGetTests(World):
    def test_rest_and_mcp_list_count_only_the_callers_matches(self):
        status, data = call(self.t_alice, 'GET', '/api/v1/generated-templates')
        self.assertEqual(status, 200, data)
        self.assertEqual(data['count'], 1)
        row = data['results'][0]
        self.assertEqual((row['id'], row['cve_id'], row['template_id'], row['status']), (self.tmpl.pk, CVE_ID, TEMPLATE_ID, 'valid'))
        self.assertEqual(row['matches'], {'vulnerable': 1, 'version_only': 0, 'no_match': 0, 'error': 0})  # A's only
        self.assertEqual((row['evidence'], row['superseded_by'], row['author']), (templategen.BEHAVIOR_EVIDENCE, None, 'ai'))
        error, mcp = tool_call(self.t_root, 'list_generated_templates', {'cve_id': CVE_ID})
        self.assertFalse(error, mcp)
        self.assertEqual(mcp['results'][0]['matches']['vulnerable'], 2)  # an App Admin sees every project

    def test_filters(self):
        GeneratedTemplate.objects.create(cve_entry=self.cve, template_id=TEMPLATE_ID, yaml=VERSION_ONLY, status='invalid')
        self.assertEqual(templategen.template_evidence(VERSION_ONLY), templategen.VERSION_EVIDENCE)
        for query, expected in (('status=invalid', 1), ('status=valid', 1), ('evidence=version', 1), ('evidence=behaviour', 1),
                                ('evidence=behavior&status=invalid', 0), ('cve_id=CVE-2099-1', 0)):
            status, data = call(self.t_alice, 'GET', f'/api/v1/generated-templates?{query}')
            self.assertEqual((status, data['count']), (200, expected), query)
        self.assertEqual(call(self.t_alice, 'GET', '/api/v1/generated-templates?status=bogus')[0], 400)
        self.assertEqual(call(self.t_alice, 'GET', '/api/v1/generated-templates?evidence=bogus')[0], 400)
        self.assertEqual(call(None, 'GET', '/api/v1/generated-templates')[0], 401)

    def test_get_shows_the_yaml_to_a_member_and_never_another_tenants_hosts(self):
        status, data = call(self.t_alice, 'GET', f'/api/v1/generated-templates/{self.tmpl.pk}')
        self.assertEqual(status, 200, data)
        self.assertEqual(data['yaml'], AI_APACHE)
        self.assertEqual(data['static_gate'], {'ok': True, 'reason': ''})
        self.assertEqual([m['host'] for m in data['match_list']], [HOST_A])
        self.assertEqual(data['match_list'][0]['hit_evidence'], templategen.VERSION_EVIDENCE)  # the kept response reads as a version
        self.assertIsNone(data['test_results'])
        self.assertNotIn(HOST_B, json.dumps(data))
        self.assertNotIn('proj-b', json.dumps(data))
        error, admin = tool_call(self.t_root, 'get_generated_template', {'id': self.tmpl.pk})
        self.assertFalse(error, admin)
        self.assertEqual(sorted(m['host'] for m in admin['match_list']), [HOST_A, HOST_B])
        self.assertEqual(len(admin['test_results']), 2)
        self.assertEqual(call(self.t_alice, 'GET', '/api/v1/generated-templates/999999')[0], 404)

    def test_a_user_with_no_membership_reads_nothing(self):
        nobody = User.objects.create_user('nobody', password='x')
        _, token = create_token(nobody, 'n')
        self.assertEqual(call(token, 'GET', '/api/v1/generated-templates')[0], 403)
        self.assertEqual(call(token, 'GET', f'/api/v1/generated-templates/{self.tmpl.pk}')[0], 403)


class ReviewReportTests(World):
    def test_the_report_flags_the_version_read_and_the_generic_banner(self):
        status, data = call(self.t_alice, 'GET', f'/api/v1/generated-templates/{self.tmpl.pk}/review')
        self.assertEqual(status, 200, data)
        self.assertEqual([h['host'] for h in data['hits']], [HOST_A])  # B is another tenant's
        self.assertEqual((data['hits'][0]['hit_evidence'], data['hits'][0]['would_be']), (templategen.VERSION_EVIDENCE, 'version_only'))
        text = ' '.join(data['findings'])
        self.assertIn('only read the version string', text)
        self.assertIn('"Apache"', text)
        self.assertEqual(data['fixture_check']['benign'], False)
        self.assertNotIn(HOST_B, json.dumps(data))
        self.assertEqual(self.match('a').template_result, 'vulnerable')  # a report changes nothing

    def test_a_version_class_template_is_flagged_and_a_benign_match_too(self):
        row = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-38475-x', yaml=VERSION_ONLY, status='invalid')
        report = template_review.report(row, template_review.recorded_matches(row))
        self.assertEqual(report['evidence'], templategen.VERSION_EVIDENCE)
        self.assertIn('decides on the version string only', ' '.join(report['findings']))
        loose = VERSION_ONLY.replace("""      - type: regex
        part: header
        regex:
          - 'Apache/2\\.4\\.([0-9]|[1-4][0-9]|5[0-9])\\b'""", """      - type: word
        words:
          - "Welcome\"""")
        row = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-38475-y', yaml=loose, status='invalid')
        self.assertIn('matches the benign page', ' '.join(template_review.report(row, CVEMatch.objects.none())['findings']))

    def test_the_report_is_a_read_that_a_read_only_token_may_ask_for(self):
        error, data = tool_call(self.t_root_ro, 'review_generated_template', {'id': self.tmpl.pk})
        self.assertFalse(error, data)
        self.assertEqual(len(data['hits']), 2)
        self.assertEqual(call(self.t_root_ro, 'GET', f'/api/v1/generated-templates/{self.tmpl.pk}/review')[0], 200)
        error, _ = tool_call(self.t_root, 'review_generated_template', {'id': self.tmpl.pk, 'verdict': 'retire', 'reason': 'x'})
        self.tmpl.refresh_from_db()
        self.assertEqual(self.tmpl.status, 'valid')  # the read tool takes no verdict


class RetireTests(World):
    def test_retire_reads_the_confirmations_again_and_leaves_remediation_alone(self):
        error, data = tool_call(self.t_root, 'set_generated_template_verdict', {'id': self.tmpl.pk, 'verdict': 'retire',
                                                                          'reason': 'reads the Server header version only'})
        self.assertFalse(error, data)
        self.tmpl.refresh_from_db()
        self.assertEqual(self.tmpl.status, 'invalid')
        self.assertIn('reads the Server header version only', self.tmpl.validation_reason)
        a, b = self.match('a'), self.match('b')
        self.assertEqual((a.template_result, a.remediation_status), (templategen.VERSION_ONLY_RESULT, 'in_progress'))  # its kept response is a version read
        self.assertEqual((b.template_result, b.remediation_status), ('', 'in_progress'))  # nothing to read it from: withdrawn
        for host, note in ((HOST_A, 'only read the version string'), (HOST_B, 'was retired by a review')):
            finding = self.finding(host)
            self.assertEqual(finding.remediation_status, 'false_positive', host)
            self.assertIn(note, finding.remediation_note)
        self.assertEqual(data['review']['outcome']['version_only'], 1)
        self.assertEqual(data['review']['outcome']['cleared'], 1)
        self.assertEqual(data['review']['outcome']['findings_closed'], 2)
        review = GeneratedTemplateReview.objects.get(template=self.tmpl)
        self.assertEqual((review.verdict, review.reviewer, review.reason), ('retire', self.root, 'reads the Server header version only'))
        log = AuditLog.objects.get(action='generated_template.retire')
        self.assertEqual((log.actor, log.target, log.detail['cve']), (self.root, TEMPLATE_ID, CVE_ID))
        self.assertIn('via_token', log.detail)
        # retired: never handed to a host again
        self.assertEqual(validation.resolve_template(CVE_ID)[0], '')
        self.assertTrue(validation.approved_template(self.tmpl.path)[1])

    def test_a_finding_a_person_changed_is_left_alone(self):
        Vulnerability.objects.filter(subdomain__name=HOST_B).update(remediation_status='in_progress')
        call(self.t_root, 'POST', f'/api/v1/generated-templates/{self.tmpl.pk}/review', {'verdict': 'retire', 'reason': 'wrong check'})
        self.assertEqual(self.finding(HOST_B).remediation_status, 'in_progress')
        self.assertEqual(self.match('b').template_result, '')

    def test_keep_records_the_review_and_changes_nothing(self):
        status, data = call(self.t_root, 'POST', f'/api/v1/generated-templates/{self.tmpl.pk}/review', {'verdict': 'keep', 'reason': 'looked fine'})
        self.assertEqual(status, 200, data)
        self.tmpl.refresh_from_db()
        self.assertEqual((self.tmpl.status, self.match('a').template_result), ('valid', 'vulnerable'))
        self.assertTrue(AuditLog.objects.filter(action='generated_template.keep', actor=self.root).exists())
        self.assertEqual(GeneratedTemplateReview.objects.get(template=self.tmpl).verdict, 'keep')

    def test_only_an_app_admin_with_a_write_token_gives_a_verdict(self):
        url = f'/api/v1/generated-templates/{self.tmpl.pk}/review'
        self.assertEqual(call(self.t_alice, 'POST', url, {'verdict': 'retire', 'reason': 'x'})[0], 403)  # a project admin is not enough
        self.assertEqual(call(self.t_root_ro, 'POST', url, {'verdict': 'retire', 'reason': 'x'})[0], 403)
        self.assertTrue(tool_call(self.t_alice, 'set_generated_template_verdict', {'id': self.tmpl.pk, 'verdict': 'retire', 'reason': 'x'})[0])
        self.assertTrue(tool_call(self.t_root_ro, 'set_generated_template_verdict', {'id': self.tmpl.pk, 'verdict': 'retire', 'reason': 'x'})[0])
        self.assertEqual(call(self.t_root, 'POST', url, {'verdict': 'retire'})[0], 400)  # a reason is required
        self.assertEqual(call(self.t_root, 'POST', url, {'verdict': 'delete', 'reason': 'x'})[0], 400)
        self.assertEqual(call(self.t_root, 'POST', url, {})[0], 400)
        self.tmpl.refresh_from_db()
        self.assertEqual((self.tmpl.status, self.match('a').template_result), ('valid', 'vulnerable'))
        self.assertFalse(GeneratedTemplateReview.objects.exists())


class RevisionTests(World):
    def setUp(self):
        super().setUp()
        ReviewerSettings.current()
        ReviewerSettings.objects.update(template_validation_enabled=True)

    def revise(self, text=REVISION, token=None, **extra):
        return call(token or self.t_root, 'POST', f'/api/v1/generated-templates/{self.tmpl.pk}/revisions',
                    {'yaml': text, 'reason': 'read a marker, not the version', **extra})

    def test_a_revision_is_a_new_draft_and_never_an_edit_in_place(self):
        status, data = self.revise()
        self.assertEqual(status, 201, data)
        rev = GeneratedTemplate.objects.get(pk=data['revision']['id'])
        self.assertEqual((rev.status, rev.template_id, rev.supersedes_id, rev.revised_by), ('draft', 'cve-2024-38475-r2', self.tmpl.pk, self.root))
        self.assertIn('id: cve-2024-38475-r2', rev.yaml)
        self.assertEqual(templategen.load_template(rev.yaml)['info'], templategen.load_template(REVISION)['info'])
        self.tmpl.refresh_from_db()
        self.assertEqual((self.tmpl.yaml, self.tmpl.status), (AI_APACHE, 'valid'))  # the old row is untouched
        with open(self.tmpl.path) as handle:
            self.assertEqual(handle.read(), AI_APACHE)
        self.assertEqual(data['revision']['revisions'][0]['id'], self.tmpl.pk)
        self.assertEqual(self.revise()[0], 409)  # one pending revision at a time
        log = AuditLog.objects.get(action='generated_template.revise')
        self.assertEqual((log.actor, log.detail['revision']), (self.root, rev.pk))
        listed = call(self.t_alice, 'GET', f'/api/v1/generated-templates?cve_id={CVE_ID}')[1]['results']
        old_row = next(r for r in listed if r['id'] == self.tmpl.pk)
        self.assertEqual(old_row['superseded_by'], {'id': rev.pk, 'template_id': 'cve-2024-38475-r2', 'status': 'draft'})

    def test_a_revision_never_runs_before_it_is_valid(self):
        data = self.revise()[1]
        rev = GeneratedTemplate.objects.get(pk=data['revision']['id'])
        self.assertFalse(Path(templategen.GENERATED_DIR, 'cve-2024-38475-r2.yaml').exists())  # no file while it is a draft
        self.assertEqual(validation.resolve_template(CVE_ID)[0], self.tmpl.path)  # the old check still answers until the revision passes
        Path(templategen.GENERATED_DIR, 'cve-2024-38475-r2.yaml').write_text(rev.yaml)  # even a file planted by hand is refused
        templategen.invalidate_template_index()
        self.assertIn(str(Path(templategen.GENERATED_DIR, 'cve-2024-38475-r2.yaml')), templategen.find_existing_template(CVE_ID))
        self.assertTrue(validation.approved_template(str(Path(templategen.GENERATED_DIR, 'cve-2024-38475-r2.yaml')))[1])

    def test_the_static_gate_refuses_bad_yaml_at_once(self):
        for text, reason in ((REVISION.replace('http:', 'code:'), 'forbidden protocol'),
                             (REVISION.replace('method: GET', 'method: POST'), 'not allowed'),
                             ('id: [', 'invalid YAML'),
                             ('x' * (templategen.MAX_TEMPLATE_BYTES + 1), 'larger than')):
            status, data = self.revise(text)
            self.assertEqual(status, 400, text[:40])
            self.assertIn(reason, data['error'])
        self.assertEqual(self.revise(AI_APACHE)[0], 400)  # the same template again
        self.assertEqual(GeneratedTemplate.objects.count(), 1)
        error, data = tool_call(self.t_root, 'update_generated_template', {'id': self.tmpl.pk, 'yaml': REVISION.replace('http:', 'headless:'),
                                                                          'reason': 'x'})
        self.assertTrue(error)
        self.assertIn('static gate', data)

    def test_a_fixture_given_is_checked_offline(self):
        status, data = self.revise(fixture={'vulnerable': templatefixture.BENIGN, 'not_affected': FIXED})
        self.assertEqual(status, 400)
        self.assertIn('does not match the affected response', data['error'])
        status, data = self.revise(fixture={'vulnerable': AFFECTED, 'not_affected': AFFECTED})
        self.assertEqual(status, 400)
        self.assertIn('fixed response', data['error'])
        status, data = self.revise(fixture={'vulnerable': AFFECTED, 'not_affected': FIXED})
        self.assertEqual(status, 201, data)
        self.assertEqual(GeneratedTemplate.objects.get(pk=data['revision']['id']).submitted_fixture['vulnerable']['body'], AFFECTED['body'])

    def test_only_an_app_admin_with_a_write_token_revises(self):
        self.assertEqual(self.revise(token=self.t_alice)[0], 403)
        self.assertEqual(self.revise(token=self.t_root_ro)[0], 403)
        self.assertTrue(tool_call(self.t_alice, 'update_generated_template', {'id': self.tmpl.pk, 'yaml': REVISION, 'reason': 'x'})[0])
        self.assertEqual(GeneratedTemplate.objects.count(), 1)

    def test_the_valid_revision_retires_the_old_one_and_is_what_runs(self):
        data = self.revise(fixture={'vulnerable': AFFECTED, 'not_affected': FIXED})[1]
        rev = GeneratedTemplate.objects.get(pk=data['revision']['id'])
        with mock.patch('agentapi.sentinel_dispatch.try_nuclei_validate', return_value=SENTINEL_OK):
            templatevalidate.run_pending()  # the same lifecycle as an AI draft: the static gate and the Sentinel, then the AI fixture
        for phase, reply in (('fixture', FIXTURE_REPLY), ('critique', AGREE)):
            rev.refresh_from_db()
            self.assertEqual(rev.status, 'draft', phase)
            job = AIJob.objects.get(kind='template_validation', context__phase=phase, status='queued')
            job.status = 'applying'
            job.save()
            templatevalidate.job_answer(job, reply)
        rev.refresh_from_db()
        self.tmpl.refresh_from_db()
        self.assertEqual((rev.status, self.tmpl.status), ('valid', 'invalid'))
        self.assertIn('superseded by revision', self.tmpl.validation_reason)
        self.assertEqual(validation.resolve_template(CVE_ID)[0], rev.path)
        self.assertTrue(rev.path.endswith('cve-2024-38475-r2.yaml'))
        self.assertEqual((self.match('a').template_result, self.match('b').template_result), (templategen.VERSION_ONLY_RESULT, ''))
        self.assertEqual((self.match('a').remediation_status, self.match('b').remediation_status), ('in_progress', 'in_progress'))
        system = GeneratedTemplateReview.objects.get(template=self.tmpl, verdict='retire')
        self.assertIsNone(system.reviewer)
        self.assertTrue(AuditLog.objects.filter(action='generated_template.retire', actor=None).exists())

    def test_the_revisions_own_fixture_is_a_gate_on_top_of_the_ais(self):
        data = self.revise(fixture={'vulnerable': AFFECTED, 'not_affected': FIXED})[1]
        rev = GeneratedTemplate.objects.get(pk=data['revision']['id'])
        GeneratedTemplate.objects.filter(pk=rev.pk).update(submitted_fixture={'vulnerable': FIXED, 'not_affected': FIXED})  # no longer holds
        rev.refresh_from_db()
        templatevalidate._fixture_answer(rev, json.loads(FIXTURE_REPLY), timezone.now())
        rev.refresh_from_db()
        self.assertEqual(rev.status, 'invalid')
        self.assertIn('given with the revision', rev.validation_reason)

    def test_a_revision_uses_no_ai_generation_budget(self):
        self.revise()
        with mock.patch.object(templategen, 'generation_limit', return_value=1):
            other = CVEEntry.objects.create(cve_id='CVE-2099-7777', cvss=5.0, published_at=timezone.now())
            GeneratedTemplate.objects.filter(pk=self.tmpl.pk).update(created_at=timezone.now() - datetime.timedelta(days=30))
            self.assertTrue(templategen._generation_lease(other))


class OneIdOneTextTests(World):
    def test_a_new_text_under_a_retired_templates_id_is_never_installed(self):
        template_review.retire(self.tmpl, 'reads the version only', self.root)
        Path(self.tmpl.path).unlink()  # a recreated container lost the retired file
        draft = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id=TEMPLATE_ID, yaml=VERSION_ONLY, status='draft')
        job = mock.Mock(provider='', model='test')
        self.assertEqual(templatevalidate.promote(draft, job), 'invalid')
        self.assertFalse(Path(self.tmpl.path).exists())


class InFlightTests(World):
    """A run that started before its template was retired, or before a valid revision superseded it, records nothing it found."""

    def setUp(self):
        super().setUp()
        Vulnerability.objects.all().delete()
        CVEMatch.objects.filter(pk=self.matches['a'].pk).update(template_result='', template_id='')

    def retire_during_the_run(self, response='no response kept'):
        def run(path, hosts, project=None):
            template_review.retire(self.tmpl, 'retired while the run was out', self.root)
            return [{k: v for k, v in outcome(HOST_A, response).items() if k != 'template_evidence'}]
        return mock.patch.object(templategen, '_test_chunk', side_effect=run)

    def test_the_template_pass_discards_the_result_of_a_check_retired_while_it_ran(self):
        with mock.patch('cveFeed.validation.resolve_template', return_value=(self.tmpl.path, '')), self.retire_during_the_run(), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **kw: list(hosts)):
            templategen.run_cve_tests(self.cve, [HOST_A], project=self.projects['a'])
        self.assertEqual(self.match('a').template_result, '')
        self.assertFalse(Vulnerability.objects.exists())
        self.assertEqual(AgentActivity.objects.filter(message__contains='result of a retired check', cve_id=CVE_ID).count(), 1)

    def test_a_validation_step_discards_the_hit_of_a_check_retired_while_it_ran(self):
        from cveFeed.models import Triage
        row = Triage.objects.get(match=self.matches['a'])
        check = validation._template_check(self.tmpl.path, HOST_A, CVE_ID, row.signature, project_id=self.projects['a'].pk)
        with self.retire_during_the_run():
            result = validation.run_nuclei_template(check)
        self.assertEqual(result['status'], 'hit')  # what the scanner said
        validation.apply_validation(row, check, result)
        row.refresh_from_db()
        self.assertNotEqual(row.validation_status, 'hit')
        self.assertNotEqual(row.classification, 'confirmed')
        self.assertEqual(self.match('a').template_result, '')
        self.assertFalse(Vulnerability.objects.exists())
        self.assertTrue(AgentActivity.objects.filter(message__contains='result of a retired check').exists())

    def test_a_superseded_template_is_stale_and_an_upstream_one_never_is(self):
        self.assertIsNone(templategen.stale_generated_template(template_id=TEMPLATE_ID))
        GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-38475-r2', yaml=REVISION, status='valid',
                                         supersedes=self.tmpl, path='/x/cve-2024-38475-r2.yaml')
        self.assertEqual(templategen.stale_generated_template(template_id=TEMPLATE_ID), self.tmpl)
        self.assertEqual(templategen.stale_generated_template(path=self.tmpl.path), self.tmpl)
        self.assertIsNone(templategen.stale_generated_template(template_id='CVE-2024-38475'))
        self.assertIsNone(templategen.stale_generated_template(path='/root/nuclei-templates/http/cves/2024/CVE-2024-38475.yaml'))


class IndexTests(TestCase):
    def test_a_revision_file_is_found_for_its_cve_only_in_the_generated_directory(self):
        root = tempfile.mkdtemp()
        generated, installed = Path(root, 'generated'), Path(root, 'installed')
        generated.mkdir()
        installed.mkdir()
        (generated / 'cve-2024-38475-r2.yaml').write_text('x')
        (installed / 'cve-2024-38475-r3.yaml').write_text('x')
        with mock.patch.object(templategen, 'GENERATED_DIR', str(generated)), mock.patch('cvengine_scanner.template_index.load', return_value={'nuclei_templates': '', 'rules': 0, 'reasons': [], 'templates': {}, 'sha256': ''}):
            templategen.invalidate_template_index()
            self.assertEqual(templategen.find_existing_template(CVE_ID), [str(generated / 'cve-2024-38475-r2.yaml')])
        templategen.invalidate_template_index()
        self.assertEqual(templategen.revision_base('cve-2024-38475-r12'), 'cve-2024-38475')
        self.assertEqual(templategen.revision_base('cve-2024-38475'), '')
        self.assertTrue(templategen.ID_RE.fullmatch(templategen.revision_id(CVE_ID, 2)))


class SurfaceTests(TestCase):
    def test_tools_and_routes_are_registered_documented_and_reviewed(self):
        import os

        from agentapi import capability_review, mcp, rest
        writes = {name: w for name, _d, _s, _f, w in mcp.TOOLS}
        names = ('list_generated_templates', 'get_generated_template', 'review_generated_template', 'set_generated_template_verdict',
                 'update_generated_template')
        self.assertEqual({n: writes[n] for n in names},
                         {'list_generated_templates': False, 'get_generated_template': False, 'review_generated_template': False,
                          'set_generated_template_verdict': True, 'update_generated_template': True})
        reviewed = {key for _v, _r, keys in capability_review.REVIEW for key in keys}
        self.assertNotIn('review_generated_template', reviewed)
        for key in ('set_generated_template_verdict', 'update_generated_template', 'POST generated-templates/{generated_id}/review',
                    'POST generated-templates/{generated_id}/revisions'):
            self.assertIn(key, reviewed)
        self.assertTrue(any(p == r'generated-templates/(?P<generated_id>\d+)/revisions' for _m, p, *_ in rest.ROUTES))
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, '..', '..', 'docs', 'AGENT-API.md'), encoding='utf-8') as fh:
            doc = fh.read()
        for name in names:
            self.assertIn(f'`{name}`', doc)
