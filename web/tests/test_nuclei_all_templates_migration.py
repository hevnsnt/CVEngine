import importlib

from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase

from dashboard.models import AuditLog, ScanPolicy

migration = importlib.import_module('dashboard.migrations.0030_nuclei_all_templates_on_by_default')


class NucleiAllTemplatesDefaultTests(TestCase):
	"""The library runs by default; an App Admin's own choice is never overwritten by the update."""

	def test_a_new_install_runs_every_template(self):
		self.assertTrue(ScanPolicy.current().nuclei_all_templates)
		self.assertTrue(ScanPolicy.objects.create().nuclei_all_templates)

	def test_a_row_nobody_changed_follows_the_new_default(self):
		row = ScanPolicy.objects.create(nuclei_all_templates=False)  # what the old factory default stored
		migration.on_unless_chosen(apps, None)
		row.refresh_from_db()
		self.assertTrue(row.nuclei_all_templates)

	def test_a_choice_an_admin_made_is_kept(self):
		row = ScanPolicy.objects.create(nuclei_all_templates=False)
		admin = User.objects.create(username='root')
		AuditLog.objects.create(actor=admin, actor_name='root', action='scan_policy.nuclei_all_templates', target='off')
		migration.on_unless_chosen(apps, None)
		row.refresh_from_db()
		self.assertFalse(row.nuclei_all_templates)
