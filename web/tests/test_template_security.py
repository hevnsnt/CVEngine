"""Template safety regressions. All scanner processes and external traffic are mocked."""
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
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
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.installed = Path(self.scratch.name) / 'installed'
        self.generated = Path(self.scratch.name) / 'generated'
        self.installed.mkdir()
        self.generated.mkdir()
        for name, value in (('TEMPLATES_ROOT', self.installed), ('GENERATED_DIR', self.generated)):
            patch = mock.patch.object(templategen, name, str(value))
            patch.start()
            self.addCleanup(patch.stop)
        templategen.invalidate_template_index()
        self.addCleanup(templategen.invalidate_template_index)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1234', published_at=timezone.now())

    def write(self, root, text):
        path = root / 'cve-2099-1234.yaml'
        path.write_text(text)
        templategen.invalidate_template_index()
        return str(path)

    def test_autofire_refuses_installed_write_template_before_dispatch(self):
        self.write(self.installed, GOOD.replace('method: GET', 'method: POST'))
        with mock.patch('cveFeed.activity.step'), mock.patch.object(templategen, '_run_template_with_retry') as run:
            result = templategen.run_cve_tests(self.cve, ['dummy.example.test'])
        run.assert_not_called()
        self.assertEqual(result['source'], 'none')
        self.assertIn('POST', result['reason'])

    def test_direct_execution_cannot_bypass_policy(self):
        path = self.write(self.installed, GOOD.replace('method: GET', 'method: POST'))
        with mock.patch.object(templategen.subprocess, 'Popen') as process:
            result = templategen.run_template(path, ['dummy.example.test'])
        process.assert_not_called()
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
        path = self.write(self.installed, GOOD.replace('{{BaseURL}}/version', '{{BaseURL}}@other.test/'))
        self.assertTrue(validation.approved_template(path)[1])
        path = self.write(self.installed, GOOD.replace('{{BaseURL}}', '{{RootURL}}'))
        self.assertTrue(validation.approved_template(path)[1])

    def test_outside_root_and_oversized_templates_are_rejected(self):
        outside = Path(self.scratch.name) / 'outside.yaml'
        outside.write_text(GOOD)
        self.assertIn('outside', validation.approved_template(str(outside))[1])
        path = self.write(self.installed, 'x' * (validation.MAX_INSTALLED_TEMPLATE_BYTES + 1))
        self.assertIn('too large', validation.approved_template(path)[1])

    def test_runner_uses_the_approved_snapshot_not_the_mutable_original(self):
        path = self.write(self.installed, GOOD)
        captured = {}

        def process(argv, **kwargs):
            copied = argv[argv.index('-t') + 1]
            Path(path).write_text(GOOD.replace('method: GET', 'method: POST'))
            captured.update(path=copied, text=Path(copied).read_text())
            return SimpleNamespace(communicate=lambda **kw: ('', ''), returncode=0)

        with mock.patch('reNgine.resources.heavy_job') as job, \
                mock.patch.object(templategen.subprocess, 'Popen', side_effect=process):
            templategen.run_template(path, ['dummy.example.test'])
        self.assertNotEqual(captured['path'], path)
        self.assertEqual(captured['text'], GOOD)
        self.assertFalse(os.path.exists(captured['path']))
