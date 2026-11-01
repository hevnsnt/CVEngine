"""Data migrations carry their own copy of the logic they need: a later refactor of live application code must not break or change them."""
import importlib
import re
from pathlib import Path

from django.apps import apps
from django.test import TestCase

MIGRATIONS = ('cveFeed.migrations.0041_bbot_info_to_labels', 'startScan.migrations.0011_shorten_bbot_names',
              'startScan.migrations.0015_technology_version_category', 'targetApp.migrations.0003_remove_shared_provider_apexes',
              'agentapi.migrations.0008_clear_stale_status_note')
LIVE_CODE = re.compile(r'^\s*(from|import)\s+(reNgine|cveFeed|agentapi|dashboard|scanEngine|tenancy|targetApp\.(?!migrations)|startScan\.(?!migrations))', re.M)


class FrozenMigrationTests(TestCase):
	def test_no_data_migration_imports_live_application_code(self):
		for name in MIGRATIONS:
			source = Path(importlib.import_module(name).__file__).read_text()
			self.assertIsNone(LIVE_CODE.search(source), name)

	def test_the_technology_migration_fills_version_and_category_without_the_live_helpers(self):
		from startScan.models import Technology
		mod = importlib.import_module('startScan.migrations.0015_technology_version_category')
		Technology.objects.bulk_create([Technology(name='nginx:1.18.0'), Technology(name='cpe:/a:openbsd:openssh:7.2p2'), Technology(name='WordPress')])
		Technology.objects.update(version='', category='')
		mod.fill(apps, None)
		found = {t.name: (t.version, t.category) for t in Technology.objects.all()}
		self.assertEqual(found['nginx:1.18.0'], ('1.18.0', 'web server'))
		self.assertEqual(found['cpe:/a:openbsd:openssh:7.2p2'], ('7.2p2', ''))
		self.assertEqual(found['WordPress'], ('', 'cms'))
