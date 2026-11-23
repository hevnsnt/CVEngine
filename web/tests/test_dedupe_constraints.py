"""Unique constraints on natural keys that writers looked up without one (docs/UPGRADE.md, Duplicate rows merged before unique constraints).

* A host is one row per (scan, target, name): ``uniq_sub_scan_dom_name``. The migration merges the duplicates first, keeping the oldest row
  (the one every reader already used) and moving what pointed at the others onto it.
* The writers read the winner's row when they lose the race to create one, and a discovery copied into a scan twice does not double it."""
import importlib
from types import SimpleNamespace
from unittest import mock

from django.apps import apps
from django.db import IntegrityError, connection, transaction
from django.db.models.query import QuerySet
from django.test import TransactionTestCase
from django.utils import timezone

from scanEngine.models import EngineType
from startScan.ip_rows import get_or_create_first
from startScan.models import EndPoint, IpAddress, ScanHistory, Subdomain, Technology, Vulnerability
from targetApp.models import Domain


def constraint_exists(name):
	with connection.cursor() as cursor:
		cursor.execute("SELECT contype FROM pg_constraint WHERE conname = %s", [name])
		row = cursor.fetchone()
	return row is not None and row[0] == 'u'


def racing_get(model):
	"""A ``QuerySet.get`` that misses ``model``'s row once, as a writer that read just before another one created it."""
	real = QuerySet.get
	missed = []

	def get(qs, *args, **kwargs):
		if qs.model is model and not missed:
			missed.append(True)
			raise model.DoesNotExist
		return real(qs, *args, **kwargs)
	return get


class Base(TransactionTestCase):
	def setUp(self):
		self.domain = Domain.objects.create(name='dedupe.test', insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='')
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now())
		self.engine = engine

	def host(self, name='a.dedupe.test', scan=None, **fields):
		return Subdomain.objects.create(scan_history=scan or self.scan, target_domain=self.domain, name=name, **fields)


class HostConstraintTests(Base):
	def test_the_constraint_exists_and_refuses_a_second_host_row(self):
		self.assertTrue(constraint_exists('uniq_sub_scan_dom_name'))
		self.host()
		with self.assertRaises(IntegrityError), transaction.atomic():
			self.host()
		other = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now())
		self.host(scan=other)  # the same host in another scan is its own row
		Subdomain.objects.create(target_domain=self.domain, name='a.dedupe.test')  # rows without a scan are not covered
		Subdomain.objects.create(target_domain=self.domain, name='a.dedupe.test')

	def test_a_writer_that_loses_the_race_reads_the_winners_row(self):
		winner = self.host()
		with mock.patch.object(QuerySet, 'get', racing_get(Subdomain)):
			row, created = get_or_create_first(Subdomain, scan_history=self.scan, target_domain=self.domain, name='a.dedupe.test')
		self.assertEqual((row.pk, created), (winner.pk, False))

	def test_record_resolved_does_not_duplicate_a_host_created_meanwhile(self):
		from agentapi.address_guard import record_resolved
		winner = self.host()
		with mock.patch.object(QuerySet, 'get', racing_get(Subdomain)):
			record_resolved(self.scan, self.domain, 'a.dedupe.test', ['192.0.2.10'])
		self.assertEqual(list(Subdomain.objects.filter(name='a.dedupe.test').values_list('pk', flat=True)), [winner.pk])
		self.assertEqual(list(winner.ip_addresses.values_list('address', flat=True)), ['192.0.2.10'])

	def test_a_discovery_copied_twice_into_a_scan_is_stored_once(self):
		from cveFeed import discovery
		source = self.host()
		source.ip_addresses.add(IpAddress.objects.create(address='192.0.2.11'))
		source.technologies.add(Technology.objects.create(name='nginx'))
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now())
		self.assertEqual(discovery.seed_from_scan(scan, self.scan), 1)
		self.assertEqual(discovery.seed_from_scan(scan, self.scan), 1)  # a resumed stage runs the copy again
		copy = Subdomain.objects.get(scan_history=scan)
		self.assertEqual(list(copy.ip_addresses.values_list('address', flat=True)), ['192.0.2.11'])
		self.assertEqual(list(copy.technologies.values_list('name', flat=True)), ['nginx'])


class HostMergeTests(Base):
	"""The data step of startScan 0031, run on duplicates stored while the constraint is off."""
	migration = 'startScan.migrations.0031_uniq_subdomain_scan_host'
	constraint = 'uniq_sub_scan_dom_name'

	def without_constraint(self, build, check=None):
		"""Store duplicates with the constraint off, run the merge in a transaction as RunPython does (the database checks the foreign
		keys at its commit), run ``check`` on the result, put the constraint back (which fails if a duplicate was left)."""
		model_constraint = next(c for c in Subdomain._meta.constraints if c.name == self.constraint)
		with connection.schema_editor() as editor:
			editor.remove_constraint(Subdomain, model_constraint)
		try:
			out = build()
			merge = importlib.import_module(self.migration).merge_duplicate_hosts
			try:
				with transaction.atomic():
					merge(apps, SimpleNamespace(connection=connection))
			except RuntimeError as exc:
				out['error'] = exc
			if check:
				check(out)
		finally:
			with connection.schema_editor() as editor:
				editor.add_constraint(Subdomain, model_constraint)
		return out

	def vuln(self, sub, name='XSS'):
		return Vulnerability.objects.create(scan_history=self.scan, target_domain=self.domain, subdomain=sub, name=name, severity=2)

	def test_the_oldest_row_stays_and_what_pointed_at_the_others_moves_onto_it(self):
		def build():
			old, new = self.host(), self.host(page_title='Login', http_status=200)
			shared, extra_ip = IpAddress.objects.create(address='192.0.2.20'), IpAddress.objects.create(address='192.0.2.21')
			old.ip_addresses.add(shared)
			new.ip_addresses.add(shared, extra_ip)
			nginx = Technology.objects.create(name='nginx')
			old.technologies.add(nginx)
			new.technologies.add(nginx, Technology.objects.create(name='php'))
			return {'old': old, 'new': new, 'vuln': self.vuln(new), 'kept_vuln': self.vuln(old, 'SQLi'),
					'endpoint': EndPoint.objects.create(scan_history=self.scan, target_domain=self.domain, subdomain=new, http_url='https://a/')}
		out = self.without_constraint(build)
		self.assertNotIn('error', out)
		self.assertEqual(list(Subdomain.objects.filter(name='a.dedupe.test').values_list('pk', flat=True)), [out['old'].pk])
		kept = Subdomain.objects.get(pk=out['old'].pk)
		self.assertEqual((kept.page_title, kept.http_status), ('Login', 200))  # facts the kept row lacked
		self.assertEqual(sorted(kept.ip_addresses.values_list('address', flat=True)), ['192.0.2.20', '192.0.2.21'])
		self.assertEqual(sorted(kept.technologies.values_list('name', flat=True)), ['nginx', 'php'])
		self.assertEqual(Vulnerability.objects.get(pk=out['vuln'].pk).subdomain_id, kept.pk)  # the finding is kept, moved
		self.assertEqual(Vulnerability.objects.get(pk=out['kept_vuln'].pk).subdomain_id, kept.pk)
		self.assertEqual(EndPoint.objects.get(pk=out['endpoint'].pk).subdomain_id, kept.pk)

	def test_a_row_with_children_that_would_collide_is_never_deleted(self):
		def build():
			old, new = self.host(), self.host()
			return {'old': old, 'new': new, 'a': self.vuln(old), 'b': self.vuln(new)}  # the same finding on both copies

		def check(out):
			self.assertIsInstance(out.get('error'), RuntimeError)
			self.assertEqual(Subdomain.objects.filter(name='a.dedupe.test').count(), 2)  # rolled back: nothing moved or deleted
			self.assertEqual(Vulnerability.objects.get(pk=out['b'].pk).subdomain_id, out['new'].pk)
			Subdomain.objects.filter(pk=out['new'].pk).delete()  # what a person merging by hand would do, so the constraint goes back
		self.without_constraint(build, check)

	def test_the_migration_builds_the_index_concurrently_outside_a_transaction(self):
		migration = importlib.import_module(self.migration).Migration
		self.assertFalse(migration.atomic)
		sql = ' '.join(str(op.sql) for op in migration.operations[1].database_operations)
		self.assertIn('CREATE UNIQUE INDEX CONCURRENTLY', sql)
		self.assertIn('UNIQUE USING INDEX', sql)
