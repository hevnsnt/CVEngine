"""cveFeed 0190 and agentapi 0027: the six tables that churn the most are vacuumed and analyzed at a twentieth of their rows instead of a fifth.

The test database is built by the migrations, so the options must already be on each table's ``pg_class.reloptions``; the reverse puts the
server wide defaults back (``RESET``) and the forward sets them again."""
import importlib

from django.apps import apps
from django.db import connection
from django.test import TestCase

from agentapi.models import SentinelTask
from cveFeed.models import AgentActivity, AssetChange, CVEDetection, ServiceRun, Triage

MIGRATIONS = (importlib.import_module('cveFeed.migrations.0190_autovacuum_busy_tables'), importlib.import_module('agentapi.migrations.0027_sentineltask_autovacuum'))
MODELS = (AgentActivity, SentinelTask, ServiceRun, CVEDetection, Triage, AssetChange)
WANTED = {'autovacuum_vacuum_scale_factor=0.05', 'autovacuum_analyze_scale_factor=0.05'}


def reloptions(table):
    with connection.cursor() as cur:
        cur.execute('SELECT reloptions FROM pg_class WHERE oid = %s::regclass', [connection.ops.quote_name(table)])
        return set(cur.fetchone()[0] or ())


class AutovacuumOptionsTests(TestCase):
    def test_the_migration_names_the_six_busy_tables(self):
        self.assertEqual({apps.get_model(app, name) for migration in MIGRATIONS for app, name in migration.TABLES}, set(MODELS))

    def test_every_busy_table_has_the_options_after_migrate(self):
        for model in MODELS:
            with self.subTest(table=model._meta.db_table):
                self.assertTrue(WANTED <= reloptions(model._meta.db_table), reloptions(model._meta.db_table))

    def test_the_reverse_resets_them_and_the_forward_sets_them_again(self):
        with connection.schema_editor() as editor:
            for migration in MIGRATIONS:
                migration.reset_options(apps, editor)
        for model in MODELS:
            self.assertFalse(WANTED & reloptions(model._meta.db_table), model._meta.db_table)
        with connection.schema_editor() as editor:
            for migration in MIGRATIONS:
                migration.set_options(apps, editor)
        for model in MODELS:
            self.assertTrue(WANTED <= reloptions(model._meta.db_table), model._meta.db_table)

    def test_a_table_the_migration_does_not_name_is_left_at_the_server_defaults(self):
        from cveFeed.models import HostInventory
        self.assertFalse({o for o in reloptions(HostInventory._meta.db_table) if o.startswith('autovacuum_')})
