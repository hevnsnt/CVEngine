"""Template safety regressions. All scanner processes and external traffic are mocked."""
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from django.test import TestCase as DatabaseTestCase
from django.utils import timezone

from cveFeed import templategen, validation
from cveFeed.models import CVEEntry, GeneratedTemplate


GOOD = '''id: cve-2099-1234
info: {name: Safe version check, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/version"]
    matchers:
      - type: word
        words: ["example-version-1.2.3"]
'''


class GeneratedDestinationTests(TestCase):
    def test_malformed_protocol_shapes_are_refused_without_exception(self):
        for doc in (None, [], {'http': 3}, {'http': {}}, {'http': [None]},
                    {'http': [{'raw': 3}]}, {'tcp': [{'inputs': 'text'}]}):
            with self.subTest(doc=doc):
                self.assertTrue(templategen.destination_check(doc))

    def test_installed_readonly_gate_refuses_malformed_protocol_shapes(self):
        for text in ('http: 3', 'http: {}', 'http: [null]', 'http: [{raw: 3}]',
                     'network: [{inputs: text}]'):
            with self.subTest(text=text):
                self.assertTrue(validation.readonly_problem(text))

    def test_authority_suffixes_are_rejected(self):
        for target in ('{{BaseURL}}.other.test/', '{{BaseURL}}@other.test/',
                       '{{BaseURL}}:8443/', '{{BaseURL}}\\other.test/'):
            with self.subTest(target=target):
                self.assertFalse(templategen.static_check(GOOD.replace('{{BaseURL}}/version', target))[0])

    def test_normal_paths_remain_accepted(self):
        for target in ('{{BaseURL}}', '{{BaseURL}}/', '{{BaseURL}}/version?format=json'):
            with self.subTest(target=target):
                self.assertTrue(templategen.static_check(GOOD.replace('{{BaseURL}}/version', target))[0])

    def test_raw_request_authority_is_bound(self):
        for target in ('//other.test/', '{{BaseURL}}@other.test/', '{{BaseURL}}.other.test/'):
            doc = {'http': [{'raw': [f'GET {target} HTTP/1.1\nHost: {{{{Hostname}}}}\n']} ]}
            self.assertTrue(templategen.destination_check(doc))
        self.assertEqual(templategen.destination_check({'http': [{'raw': ['GET /version HTTP/1.1\nHost: {{Hostname}}\n']}]}), '')

    def test_builtin_target_variable_cannot_be_redefined(self):
        doc = {'variables': {'BaseURL': 'https://other.test'}, 'http': [{'path': ['{{BaseURL}}/']}]}
        self.assertIn('override', templategen.destination_check(doc))

    def test_tcp_outgoing_bytes_are_rejected_but_banner_reads_remain(self):
        for protocol in ('network', 'tcp'):
            doc = {protocol: [{'host': ['{{Hostname}}'], 'inputs': [{'data': 'DUMMY_STATE_CHANGE'}]}]}
            self.assertIn('outgoing', templategen.destination_check(doc))
            doc[protocol][0].pop('inputs')
            doc[protocol][0]['read-size'] = 64
            self.assertEqual(templategen.destination_check(doc), '')


class TemplateExecutionBoundaryTests(DatabaseTestCase):
    def setUp(self):
        from dashboard.models import ScanPolicy
        ScanPolicy.objects.create(nuclei_all_templates=False)  # the restricted policy: only read-only templates run
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.generated = Path(self.scratch.name) / 'generated'
        self.generated.mkdir()
        patch = mock.patch.object(templategen, 'GENERATED_DIR', str(self.generated))
        patch.start()
        self.addCleanup(patch.stop)
        templategen.invalidate_template_index()
        self.addCleanup(templategen.invalidate_template_index)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1234', published_at=timezone.now())

    RELATIVE = 'http/cves/2099/CVE-2099-1234.yaml'

    def install(self, text):
        """An installed template of the pinned release, as the server knows it: an entry of the template index (no file here)."""
        from tests.test_validation import index_of
        patch = mock.patch('cvengine_scanner.template_index.load', return_value=index_of({self.RELATIVE: text}))
        patch.start()
        self.addCleanup(patch.stop)
        templategen.invalidate_template_index()
        return templategen.INSTALLED_PREFIX + self.RELATIVE

    def write(self, root, text):
        path = root / 'cve-2099-1234.yaml'
        path.write_text(text)
        templategen.invalidate_template_index()
        return str(path)

    def test_autofire_refuses_installed_write_template_before_dispatch(self):
        self.install(GOOD.replace('method: GET', 'method: POST'))
        with mock.patch('cveFeed.activity.step'), mock.patch.object(templategen, '_test_chunk') as run:
            result = templategen.run_cve_tests(self.cve, ['dummy.example.test'])
        run.assert_not_called()
        self.assertEqual(result['source'], 'none')
        self.assertIn('POST', result['reason'])

    def test_direct_execution_cannot_bypass_policy(self):
        path = self.install(GOOD.replace('method: GET', 'method: POST'))
        with mock.patch('agentapi.sentinel_dispatch.try_installed_template_test') as sent, mock.patch('agentapi.sentinel_dispatch.try_template_test') as text_sent:
            result = templategen.run_template(path, ['dummy.example.test'], project=1)
        sent.assert_not_called()
        text_sent.assert_not_called()  # a template the policy refuses is never handed to a scanner
        self.assertIn('POST', result[0]['error'])

    def test_generated_file_requires_current_approval_and_exact_content(self):
        path = self.write(self.generated, GOOD)
        self.assertTrue(validation.approved_template(path)[1])
        row = GeneratedTemplate.objects.create(cve_entry=self.cve, path=path, template_id='cve-2099-1234',
                                               yaml=GOOD, status='valid', positive_fixture_verified_at=timezone.now(),
                                               positive_fixture_source='checked-in independent fixture')
        self.assertEqual(validation.approved_template(path), (GOOD, ''))
        Path(path).write_text(GOOD.replace('/version', '/different'))
        self.assertTrue(validation.approved_template(path)[1])
        Path(path).write_text(GOOD)
        row.status = 'invalid'
        row.save()
        self.assertTrue(validation.approved_template(path)[1])

    def test_valid_legacy_generated_row_without_positive_fixture_is_refused(self):
        path = self.write(self.generated, GOOD)
        row = GeneratedTemplate.objects.create(cve_entry=self.cve, path=path,
            template_id='cve-2099-1234', yaml=GOOD, status='valid')
        self.assertIn('reviewed positive fixture', validation.approved_template(path)[1])
        row.positive_fixture_verified_at = timezone.now()
        row.save()
        self.assertIn('reviewed positive fixture', validation.approved_template(path)[1])

    def test_installed_destination_is_bound_and_preserves_upstream_root_url_refusal(self):
        path = self.install(GOOD.replace('{{BaseURL}}/version', '{{BaseURL}}@other.test/'))
        self.assertTrue(validation.approved_template(path)[1])
        mock.patch.stopall()
        path = self.install(GOOD.replace('{{BaseURL}}', '{{RootURL}}'))
        self.assertTrue(validation.approved_template(path)[1])

    def test_outside_the_generated_directory_or_the_index_is_rejected(self):
        outside = Path(self.scratch.name) / 'outside.yaml'
        outside.write_text(GOOD)
        self.assertIn('outside', validation.approved_template(str(outside))[1])
        self.install(GOOD)
        self.assertIn('not a template of the pinned release', validation.approved_template(templategen.INSTALLED_PREFIX + 'http/not-there.yaml')[1])

    def test_an_installed_template_is_sent_by_path_and_index_hash_never_as_text(self):
        path = self.install(GOOD)
        captured = {}

        def scanner(relative, sha256, hosts, project):
            captured.update(relative=relative, sha256=sha256, hosts=list(hosts), project=project)
            return [{'host': host, 'vulnerable': False, 'output': ''} for host in hosts], GOOD
        from cvengine_scanner import template_index
        with mock.patch('agentapi.sentinel_dispatch.try_installed_template_test', side_effect=scanner), \
                mock.patch('agentapi.sentinel_dispatch.try_template_test', side_effect=AssertionError('text sent')):
            out = templategen.run_template(path, ['dummy.example.test'], project=1)
        self.assertEqual(captured, {'relative': self.RELATIVE, 'sha256': template_index.load()['templates'][self.RELATIVE]['sha256'],
                                    'hosts': ['dummy.example.test'], 'project': 1})
        self.assertIn('template_evidence', out[0])  # read from the text the Sentinel ran
