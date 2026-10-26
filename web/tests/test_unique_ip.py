import importlib
from unittest import mock

from django.apps import apps
from django.db import IntegrityError, connection, transaction
from django.test import TransactionTestCase

from startScan.ip_rows import get_or_create_ip
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain


class UniqueIpTests(TransactionTestCase):
	def test_the_database_refuses_a_second_row_for_an_address_in_the_same_organization(self):
		from dashboard.models import Org
		a, b = Org.objects.create(name='A', slug='ua'), Org.objects.create(name='B', slug='ub')
		IpAddress.objects.create(address='192.0.2.1', org=a)
		IpAddress.objects.create(address='192.0.2.1', org=b)  # another organization has its own row for the same address
		with self.assertRaises(IntegrityError), transaction.atomic():
			IpAddress.objects.create(address='192.0.2.1', org=a)
		IpAddress.objects.create(address='192.0.2.5')
		with self.assertRaises(IntegrityError), transaction.atomic():
			IpAddress.objects.create(address='192.0.2.5')
		IpAddress.objects.create(address='')  # blanks and nulls are not addresses: several may exist
		IpAddress.objects.create(address='')
		IpAddress.objects.create(address=None)
		IpAddress.objects.create(address=None)

	def test_a_loser_of_the_race_reads_the_winners_row(self):
		winner = IpAddress.objects.create(address='192.0.2.2')
		with mock.patch.object(IpAddress.objects, 'get_or_create', side_effect=IntegrityError('duplicate')):
			row, created = get_or_create_ip('192.0.2.2')
		self.assertEqual((row.pk, created), (winner.pk, False))
		self.assertEqual(get_or_create_ip('192.0.2.3')[1], True)

	def test_the_migration_merges_duplicates_keeping_links_ports_and_facts(self):
		migration = importlib.import_module('startScan.migrations.0019_unique_ipaddress')
		constraints = [c for c in IpAddress._meta.constraints if c.name.startswith('uniq_ipaddress_')]
		with connection.schema_editor() as editor:
			for constraint in constraints:
				editor.remove_constraint(IpAddress, constraint)
		try:
			from django.utils import timezone
			domain = Domain.objects.create(name='dup.test', insert_date=timezone.now())
			sub_a = Subdomain.objects.create(name='a.dup.test', target_domain=domain)
			sub_b = Subdomain.objects.create(name='b.dup.test', target_domain=domain)
			first = IpAddress.objects.create(address='198.51.100.9')
			second = IpAddress.objects.create(address='198.51.100.9', os_guess='Linux 5', is_cdn=True)
			sub_a.ip_addresses.add(first, second)
			sub_b.ip_addresses.add(second)
			p22 = Port.objects.create(number=22, protocol='tcp')
			p80 = Port.objects.create(number=80, protocol='tcp')
			p22_dup = Port.objects.create(number=22, protocol='tcp')
			first.ports.add(p22)
			second.ports.add(p22_dup, p80)
			migration.merge_duplicates(apps, None)
		finally:
			with connection.schema_editor() as editor:
				for constraint in constraints:
					editor.add_constraint(IpAddress, constraint)
		self.assertEqual(IpAddress.objects.filter(address='198.51.100.9').count(), 1)
		keeper = IpAddress.objects.get(address='198.51.100.9')
		self.assertEqual(keeper.pk, first.pk)
		self.assertEqual((keeper.os_guess, keeper.is_cdn), ('Linux 5', True))
		self.assertEqual(sorted(keeper.ports.values_list('number', flat=True)), [22, 80])
		self.assertEqual(sorted(Subdomain.objects.filter(ip_addresses=keeper).values_list('name', flat=True)), ['a.dup.test', 'b.dup.test'])


class MigrationTransactionTests(TransactionTestCase):
	def test_the_merge_and_the_unique_index_are_not_one_transaction(self):
		# PostgreSQL refuses to build the index in the transaction that rewrote the rows foreign keys point at ("pending trigger events"),
		# which stopped an update on any install that held duplicate addresses. The upgrade rehearsal runs the real thing.
		migration = importlib.import_module('startScan.migrations.0019_unique_ipaddress')
		self.assertFalse(migration.Migration.atomic)


class TolerantGetOrCreateTests(TransactionTestCase):
	def test_a_duplicated_row_is_not_a_crash(self):
		from startScan.ip_rows import get_or_create_first
		from startScan.models import Technology
		first = Technology.objects.create(name='nginx:1.18.0')
		Technology.objects.create(name='nginx:1.18.0')
		row, created = get_or_create_first(Technology, name='nginx:1.18.0')
		self.assertEqual((row.pk, created), (first.pk, False))
		row, created = get_or_create_first(Technology, name='apache:2.4.1')
		self.assertTrue(created)
