"""The second drop of reNgine-era tables (dashboard 0037, scanEngine 0008, startScan 0027): run the real migrations from the state before them with a
row in every table they drop and in the tables next to them that stay, and check the upgrade goes through, the dropped tables are gone and the kept
rows are intact."""
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

STATE_BEFORE = [
    ('dashboard', '0036_scan_policy_credential_checks'),
    ('scanEngine', '0007_delete_installedexternaltool'),
    ('startScan', '0026_vulnerability_severity_id_idx'),
]
STATE_AFTER = [
    ('dashboard', '0037_drop_unused_legacy_models'),
    ('scanEngine', '0008_drop_unused_legacy_models'),
    ('startScan', '0027_drop_unused_legacy_models'),
]
DROPPED_TABLES = [
    'dashboard_openaiapikey', 'dashboard_ollamasettings', 'dashboard_netlasapikey', 'dashboard_hackeroneapikey', 'dashboard_searchhistory',
    'dashboard_userpreferences', 'dashboard_inappnotification', 'scanEngine_hackerone', 'startScan_command',
]


def tables():
    return set(connection.introspection.table_names())


class DropUnusedLegacyModelsTests(TransactionTestCase):
    def tearDown(self):
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())  # leave the schema at the latest state for the next test

    def test_the_unused_tables_go_and_the_rows_next_to_them_stay(self):
        executor = MigrationExecutor(connection)
        executor.migrate(STATE_BEFORE)
        old = executor.loader.project_state(STATE_BEFORE).apps
        now = timezone.now()
        User = old.get_model('auth', 'User')
        user = User.objects.create(username='legacy-user')
        Org, Project = old.get_model('dashboard', 'Org'), old.get_model('dashboard', 'Project')
        org = Org.objects.create(name='legacy2', slug='legacy2')
        project = Project.objects.create(name='legacy2', slug='legacy2-p', insert_date=now, org=org)
        domain = old.get_model('targetApp', 'Domain').objects.create(name='legacy2.example.com', project=project, insert_date=now)
        engine = old.get_model('scanEngine', 'EngineType').objects.create(engine_name='legacy2 engine', yaml_configuration='x: {}')
        scan = old.get_model('startScan', 'ScanHistory').objects.create(domain=domain, scan_type=engine, start_scan_date=now)
        step = old.get_model('startScan', 'ScanActivity').objects.create(scan_of=scan, title='step', name='step', time=now, status=1)
        old.get_model('dashboard', 'OpenAiAPIKey').objects.create(key='sk-old')
        old.get_model('dashboard', 'OllamaSettings').objects.create(selected_model='llama')
        old.get_model('dashboard', 'NetlasAPIKey').objects.create(key='nl-old')
        old.get_model('dashboard', 'HackerOneAPIKey').objects.create(username='h1', key='h1-old')
        old.get_model('dashboard', 'ChaosAPIKey').objects.create(key='chaos-kept')
        old.get_model('dashboard', 'SearchHistory').objects.create(user=user, query='nginx')
        old.get_model('dashboard', 'UserPreferences').objects.create(user=user)
        old.get_model('dashboard', 'InAppNotification').objects.create(project=project, title='t', description='d', icon='mdi-x')
        old.get_model('scanEngine', 'Hackerone').objects.create(report_template='x')
        old.get_model('startScan', 'Command').objects.create(scan_history=scan, activity=step, command='nmap -sV x', time=now)
        for name in DROPPED_TABLES:
            self.assertIn(name, tables(), name)

        executor = MigrationExecutor(connection)
        executor.migrate(STATE_AFTER)
        after = tables()
        for name in DROPPED_TABLES:
            self.assertNotIn(name, after, name)
        new = executor.loader.project_state(STATE_AFTER).apps
        self.assertEqual(new.get_model('dashboard', 'ChaosAPIKey').objects.get().key, 'chaos-kept')
        self.assertTrue(new.get_model('auth', 'User').objects.filter(pk=user.pk).exists())
        self.assertEqual(new.get_model('dashboard', 'Project').objects.get(pk=project.pk).slug, 'legacy2-p')
        self.assertEqual(new.get_model('startScan', 'ScanActivity').objects.get(pk=step.pk).scan_of_id, scan.pk)
        self.assertEqual(new.get_model('scanEngine', 'EngineType').objects.get(pk=engine.pk).engine_name, 'legacy2 engine')

    def test_the_vault_and_the_admin_still_work_on_the_migrated_schema(self):
        from django.contrib.auth.models import User
        from django.test import Client
        from dashboard.models import ChaosAPIKey
        root = User.objects.create_superuser('legacy2-root', 'r@example.test', 'pw-12345-long')
        client = Client()
        client.force_login(root)
        ChaosAPIKey.objects.create(key='chaos-value')
        for url in ('/admin/', '/admin/dashboard/', '/admin/scanEngine/', '/admin/startScan/'):
            self.assertEqual(client.get(url).status_code, 200, url)
        from cveFeed import settings_api
        self.assertEqual(settings_api.keys_get(None), {'chaos': {'has_key': True}})
