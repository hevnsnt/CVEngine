import json
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.core.management import call_command
from django.core.management.base import CommandError

from cveFeed import template_fixtures, templategen, validation
from cveFeed.models import CVEEntry, GeneratedTemplate
from tests.test_templategen import GOOD


class ReviewedFixtureTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'fixtures'
        self.root.mkdir()
        patcher = mock.patch.object(template_fixtures, 'ROOT', self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.fixture = {
            'cve_id': 'CVE-2024-1234',
            'source_url': 'https://www.cve.org/CVERecord?id=CVE-2024-1234',
            'reviewed_by': 'maintainer',
            'positive': {'status': 200, 'body': 'nginx/1.18', 'headers': {}},
            'negative': {'status': 404, 'body': 'not found', 'headers': {}},
        }

    def write_fixture(self):
        (self.root / 'CVE-2024-1234.json').write_text(json.dumps(self.fixture))

    def test_missing_or_unsafe_fixture_never_passes_review(self):
        self.assertIn('no independently reviewed', template_fixtures.load('CVE-2024-1234')[2])
        self.fixture['positive']['headers']['Location'] = 'https://elsewhere.test/'
        self.write_fixture()
        self.assertIn('headers are invalid', template_fixtures.load('CVE-2024-1234')[2])
        self.fixture['positive']['headers'] = {}
        self.write_fixture()
        loaded, provenance, reason = template_fixtures.load('CVE-2024-1234')
        self.assertEqual(reason, '')
        self.assertEqual(loaded, self.fixture)
        self.assertIn('sha256:', provenance)

    def test_only_fixed_read_only_http_detector_is_supported(self):
        self.assertTrue(template_fixtures.supported_template(GOOD))
        self.assertFalse(template_fixtures.supported_template(
            GOOD.replace('{{BaseURL}}/version', 'https://elsewhere.test/version')))
        self.assertFalse(template_fixtures.supported_template(GOOD + '\nflow: something\n'))
        self.assertFalse(template_fixtures.supported_template(
            GOOD.replace('method: GET', 'method: POST')))
        with mock.patch.object(template_fixtures, '_case', side_effect=[(True, ''), (False, '')]) as run:
            self.assertTrue(template_fixtures.verify('/tmp/detector.yaml', GOOD, self.fixture)[0])
            self.assertEqual([call.args[2] for call in run.call_args_list], ['/version', '/version'])
        with mock.patch.object(template_fixtures, '_case', side_effect=[(True, ''), (True, '')]):
            self.assertIn('false positive', template_fixtures.verify('/tmp/detector.yaml', GOOD, self.fixture)[1])

    def test_explicit_review_installs_only_after_positive_and_negative_pass(self):
        self.write_fixture()
        cve = CVEEntry.objects.create(cve_id='CVE-2024-1234')
        draft = GeneratedTemplate.objects.create(cve_entry=cve, template_id='cve-2024-1234',
                                                  yaml=GOOD, status=GeneratedTemplate.STATUS_DRAFT)
        generated = Path(self.temp.name) / 'generated'
        with mock.patch.object(templategen, 'GENERATED_DIR', str(generated)), \
                mock.patch.object(templategen, 'validate_with_nuclei', return_value=(True, 'syntax passed')), \
                mock.patch.object(template_fixtures, '_case', side_effect=[(True, ''), (False, '')]):
            ok, reason = templategen.approve_reviewed_template(draft.pk)
            self.assertTrue(ok, reason)
            draft.refresh_from_db()
            self.assertEqual(draft.status, GeneratedTemplate.STATUS_VALID)
            self.assertEqual(Path(draft.path).name, 'cve-2024-1234.yaml')
            self.assertIsNotNone(draft.positive_fixture_verified_at)
            self.assertIn('sha256:', draft.positive_fixture_source)
            self.assertEqual(validation.resolve_template(cve.cve_id)[0], draft.path)
            self.assertFalse(templategen.approve_reviewed_template(draft.pk)[0])

    def test_failed_positive_does_not_install(self):
        self.write_fixture()
        cve = CVEEntry.objects.create(cve_id='CVE-2024-1234')
        draft = GeneratedTemplate.objects.create(cve_entry=cve, template_id='cve-2024-1234',
                                                  yaml=GOOD, status=GeneratedTemplate.STATUS_DRAFT)
        generated = Path(self.temp.name) / 'generated'
        with mock.patch.object(templategen, 'GENERATED_DIR', str(generated)), \
                mock.patch.object(templategen, 'validate_with_nuclei', return_value=(True, 'syntax passed')), \
                mock.patch.object(template_fixtures, '_case', return_value=(False, '')):
            ok, reason = templategen.approve_reviewed_template(draft.pk)
        self.assertFalse(ok)
        self.assertIn('positive reviewed fixture did not match', reason)
        draft.refresh_from_db()
        self.assertEqual(draft.status, GeneratedTemplate.STATUS_DRAFT)
        self.assertFalse(generated.exists())

    def test_approval_command_reports_missing_fixture_without_installing(self):
        cve = CVEEntry.objects.create(cve_id='CVE-2024-1234')
        draft = GeneratedTemplate.objects.create(cve_entry=cve, template_id='cve-2024-1234',
                                                  yaml=GOOD, status=GeneratedTemplate.STATUS_DRAFT)
        with self.assertRaisesMessage(CommandError, 'no independently reviewed positive fixture'):
            call_command('review_generated_template', draft.pk)
        draft.refresh_from_db()
        self.assertEqual(draft.status, GeneratedTemplate.STATUS_DRAFT)
