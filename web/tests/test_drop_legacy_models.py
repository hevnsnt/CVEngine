from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

STATE_BEFORE = [
	('targetApp', '0004_domain_org_unique'),
	('recon_note', '0001_initial'),
	('scanEngine', '0004_encrypt_existing_secrets'),
	('startScan', '0021_scanhistory_initiated_by_set_null'),
	('cveFeed', '0115_openvasproject_excluded'),
]
STATE_AFTER = [
	('targetApp', '0005_drop_organization'),
	('recon_note', '0002_drop_todonote'),
	('scanEngine', '0005_drop_legacy_models'),
	('startScan', '0023_drop_legacy_models'),
	('cveFeed', '0117_drop_cveentry_raw'),
]
DROPPED_TABLES = [
	'targetApp_organization', 'targetApp_organization_domains', 'recon_note_todonote', 'scanEngine_wordlist', 'scanEngine_configuration',
	'scanEngine_interestinglookupmodel', 'startScan_gptvulnerabilityreport', 'startScan_gptvulnerabilityreport_references', 'startScan_s3bucket',
	'startScan_scanhistory_buckets',
]
DROPPED_COLUMNS = {
	'startScan_scanhistory': ['cfg_out_of_scope_subdomains', 'cfg_starting_point_path', 'cfg_excluded_paths', 'cfg_imported_subdomains'],
	'cveFeed_cveentry': ['raw'],
}


def tables():
	return set(connection.introspection.table_names())


def columns(table):
	with connection.cursor() as cursor:
		return {c.name for c in connection.introspection.get_table_description(cursor, table)}


class DropLegacyModelsTests(TransactionTestCase):
	"""Run the real migrations that drop the legacy models and columns, from the state before them with rows in every one of the legacy
	tables (including the rows that reference kept tables): the upgrade must not fail on them, the kept data must be intact, and the
	application must work on the result."""

	def tearDown(self):
		executor = MigrationExecutor(connection)
		executor.migrate(executor.loader.graph.leaf_nodes())  # leave the schema at the latest state for the next test

	def legacy_rows(self, old):
		"""One row in each legacy table, wired to rows of the tables that stay."""
		now = timezone.now()
		Org, Project = old.get_model('dashboard', 'Org'), old.get_model('dashboard', 'Project')
		Domain, Organization = old.get_model('targetApp', 'Domain'), old.get_model('targetApp', 'Organization')
		EngineType = old.get_model('scanEngine', 'EngineType')
		ScanHistory, Subdomain = old.get_model('startScan', 'ScanHistory'), old.get_model('startScan', 'Subdomain')
		Email, Reference = old.get_model('startScan', 'Email'), old.get_model('startScan', 'VulnerabilityReference')
		org = Org.objects.create(name='legacy', slug='legacy')
		project = Project.objects.create(name='legacy', slug='legacy-p', insert_date=now, org=org)
		domain = Domain.objects.create(name='legacy.example.com', project=project, insert_date=now)
		old_org = Organization.objects.create(name='Old group', insert_date=now, project=project)
		old_org.domains.add(domain)
		engine = EngineType.objects.create(engine_name='legacy engine', yaml_configuration='port_scan: {}')
		scan = ScanHistory.objects.create(
			domain=domain, scan_type=engine, start_scan_date=now, tasks=['port_scan'], cfg_out_of_scope_subdomains=['x.legacy.example.com'],
			cfg_starting_point_path='/app', cfg_excluded_paths=['/skip'], cfg_imported_subdomains=['imp.legacy.example.com'], used_gf_patterns='xss')
		scan.emails.add(Email.objects.create(address='ops@example.com'))
		scan.buckets.add(old.get_model('startScan', 'S3Bucket').objects.create(name='legacy-bucket', provider='aws'))
		sub = Subdomain.objects.create(name='www.legacy.example.com', target_domain=domain, scan_history=scan)
		report = old.get_model('startScan', 'GPTVulnerabilityReport').objects.create(url_path='/a', title='old report')
		report.references.add(Reference.objects.create(url='https://example.com/ref'))
		old.get_model('recon_note', 'TodoNote').objects.create(title='check it', scan_history=scan, subdomain=sub, project=project)
		old.get_model('scanEngine', 'Wordlist').objects.create(name='Dicc', short_name='dicc', count=3)
		old.get_model('scanEngine', 'Configuration').objects.create(name='Cfg', short_name='cfg', content='a=1')
		old.get_model('scanEngine', 'InterestingLookupModel').objects.create(keywords='admin, ftp', custom_type=True)
		old.get_model('cveFeed', 'CVEEntry').objects.create(cve_id='CVE-2099-777', kev=True, cvss=9.8, title='kept', raw={'big': 'x' * 100}, affected=[])
		return domain, scan, sub

	def test_the_legacy_tables_and_columns_go_and_the_kept_data_stays(self):
		executor = MigrationExecutor(connection)
		executor.migrate(STATE_BEFORE)
		old = executor.loader.project_state(STATE_BEFORE).apps
		domain, scan, sub = self.legacy_rows(old)
		before_tables = tables()
		for name in DROPPED_TABLES:
			self.assertIn(name, before_tables, name)
		for table, names in DROPPED_COLUMNS.items():
			self.assertTrue(set(names) <= columns(table), table)

		executor = MigrationExecutor(connection)
		executor.migrate(STATE_AFTER)
		after_tables = tables()
		for name in DROPPED_TABLES:
			self.assertNotIn(name, after_tables, name)
		for table, names in DROPPED_COLUMNS.items():
			self.assertFalse(set(names) & columns(table), table)

		new = executor.loader.project_state(STATE_AFTER).apps
		kept_domain = new.get_model('targetApp', 'Domain').objects.get(pk=domain.pk)
		self.assertEqual((kept_domain.name, kept_domain.project_id), ('legacy.example.com', domain.project_id))
		kept_scan = new.get_model('startScan', 'ScanHistory').objects.get(pk=scan.pk)
		self.assertEqual((kept_scan.domain_id, kept_scan.tasks, kept_scan.used_gf_patterns), (domain.pk, ['port_scan'], 'xss'))
		self.assertEqual(list(kept_scan.emails.values_list('address', flat=True)), ['ops@example.com'])
		self.assertEqual(new.get_model('startScan', 'Subdomain').objects.get(pk=sub.pk).scan_history_id, scan.pk)
		self.assertEqual(new.get_model('startScan', 'VulnerabilityReference').objects.count(), 1)  # the reference of the dropped report is a kept table's row
		self.assertEqual(new.get_model('scanEngine', 'EngineType').objects.get().engine_name, 'legacy engine')
		cve = new.get_model('cveFeed', 'CVEEntry').objects.get(cve_id='CVE-2099-777')
		self.assertEqual((cve.kev, cve.cvss, cve.title), (True, 9.8, 'kept'))

	def test_the_application_works_on_the_migrated_schema(self):
		executor = MigrationExecutor(connection)
		executor.migrate(STATE_BEFORE)
		self.legacy_rows(executor.loader.project_state(STATE_BEFORE).apps)
		executor = MigrationExecutor(connection)
		executor.migrate(executor.loader.graph.leaf_nodes())

		from cveFeed.models import CVEEntry
		from scanEngine.models import EngineType
		from startScan.models import ScanHistory, Subdomain
		from targetApp.models import Domain
		domain = Domain.objects.get(name='legacy.example.com')
		scan = ScanHistory.objects.get(domain=domain)
		self.assertEqual(list(Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True)), ['www.legacy.example.com'])
		fresh = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.get(), start_scan_date=timezone.now(), tasks=[])
		self.assertEqual(ScanHistory.objects.filter(domain=domain).count(), 2)
		scan.delete()  # the cascade must not reach for a dropped table
		self.assertEqual(list(ScanHistory.objects.filter(domain=domain)), [fresh])
		entry, created = CVEEntry.from_api({'id': 'CVE-2099-778', 'title': 'new', 'severity': {'cvss': 5.0}})
		self.assertTrue(created)
		self.assertEqual(CVEEntry.objects.filter(cve_id__in=['CVE-2099-777', 'CVE-2099-778']).count(), 2)
		domain.delete()  # and neither must deleting a target
		self.assertFalse(Domain.objects.filter(name='legacy.example.com').exists())
