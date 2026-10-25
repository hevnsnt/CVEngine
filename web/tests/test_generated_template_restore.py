import os
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import templategen
from cveFeed.models import CVEEntry, GeneratedTemplate
from tests.test_templategen import GOOD


class RestoreGeneratedTemplatesTests(TestCase):
	"""An update recreates the containers, which empties a directory that is not a volume. The validated AI templates are kept in the
	database too, and are written back from it, through the same safety gate, when a worker starts."""

	def setUp(self):
		scratch = tempfile.TemporaryDirectory()
		self.addCleanup(scratch.cleanup)
		self.generated = Path(scratch.name) / 'generated'
		self.generated.mkdir()
		patch = mock.patch.object(templategen, 'GENERATED_DIR', str(self.generated))
		patch.start()
		self.addCleanup(patch.stop)
		other = mock.patch.object(templategen, 'TEMPLATES_ROOT', str(Path(scratch.name) / 'installed'))
		other.start()
		self.addCleanup(other.stop)
		templategen.invalidate_template_index()
		self.addCleanup(templategen.invalidate_template_index)
		self.cve = CVEEntry.objects.create(cve_id='CVE-2024-1234', published_at=timezone.now())

	def valid(self, yaml_text=GOOD, **fields):
		path = fields.pop('path', str(self.generated / 'cve-2024-1234.yaml'))
		return GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-1234', yaml=yaml_text, status='valid', path=path, **fields)

	def test_a_missing_file_is_written_back_from_the_database(self):
		tmpl = self.valid()
		self.assertEqual(templategen.restore_missing_files(), {'restored': 1, 'skipped': 0})
		self.assertEqual(Path(tmpl.path).read_text(), GOOD)
		self.assertEqual(oct(os.stat(tmpl.path).st_mode & 0o777), oct(0o600))
		self.assertEqual(templategen.find_existing_template('CVE-2024-1234'), [tmpl.path])  # coverage sees it again

	def test_a_file_that_is_still_there_is_left_alone(self):
		tmpl = self.valid()
		Path(tmpl.path).write_text('id: edited-on-disk\n')
		self.assertEqual(templategen.restore_missing_files(), {'restored': 0, 'skipped': 0})
		self.assertEqual(Path(tmpl.path).read_text(), 'id: edited-on-disk\n')

	def test_a_draft_or_invalid_template_is_never_restored(self):
		for status in ('draft', 'invalid'):
			GeneratedTemplate.objects.create(cve_entry=self.cve, template_id=f'cve-2024-1234-{status}', yaml=GOOD, status=status,
				path=str(self.generated / f'{status}.yaml'))
		self.assertEqual(templategen.restore_missing_files(), {'restored': 0, 'skipped': 0})
		self.assertEqual(os.listdir(self.generated), [])

	def test_a_template_that_no_longer_passes_the_safety_gate_is_not_restored(self):
		self.valid(GOOD + '\ncode:\n  - engine: [sh]\n    source: id\n')
		self.assertEqual(templategen.restore_missing_files(), {'restored': 0, 'skipped': 1})
		self.assertEqual(os.listdir(self.generated), [])

	def test_a_recorded_path_outside_the_generated_directory_is_never_written(self):
		with tempfile.TemporaryDirectory() as elsewhere:
			target = os.path.join(elsewhere, 'cve-2024-1234.yaml')
			self.valid(path=target)
			self.assertEqual(templategen.restore_missing_files(), {'restored': 0, 'skipped': 1})
			self.assertFalse(os.path.exists(target))
		self.valid(path=str(self.generated / '..' / 'cve-2024-1234.yaml'))
		self.assertEqual(templategen.restore_missing_files()['restored'], 0)

	def test_it_is_safe_to_run_twice(self):
		self.valid()
		templategen.restore_missing_files()
		self.assertEqual(templategen.restore_missing_files(), {'restored': 0, 'skipped': 0})

	def test_the_worker_start_hook_restores_and_never_raises(self):
		from reNgine.celery import restore_generated_templates
		tmpl = self.valid()
		restore_generated_templates()
		self.assertTrue(os.path.exists(tmpl.path))
		with mock.patch.object(templategen, 'restore_missing_files', side_effect=RuntimeError('database not ready')):
			restore_generated_templates()  # logged, not raised: the worker still starts
