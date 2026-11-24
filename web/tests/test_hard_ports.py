import importlib
from unittest import mock

from django.apps import apps
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext

from cveFeed import port_inventory
from cvengine import common_func, discovery_events as bbot_lib
from cvengine.common_func import update_or_create_port
from cvengine.tasks import persist_bbot_result
from startScan.models import IpAddress, Port


class BbotPortsArePerIpTests(TestCase):
	"""Review 2.4: bbot used to attach one Port row per port number to every IP."""

	def test_bbot_for_another_ip_does_not_inherit_the_nmap_service(self):
		port_inventory.persist_inventory([{'ip': '192.0.2.10', 'ports': [
			{'number': 443, 'state': 'open', 'product': 'nginx', 'version': '1.18.0', 'service_name': 'https'}]}])
		a_port = IpAddress.objects.get(address='192.0.2.10').ports.get(number=443)
		persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.11', 443)}), ctx={})
		b_port = IpAddress.objects.get(address='192.0.2.11').ports.get(number=443)
		self.assertNotEqual(a_port.pk, b_port.pk)
		self.assertEqual((b_port.product, b_port.version), ('', ''))
		a_port.refresh_from_db()
		self.assertEqual((a_port.product, a_port.version), ('nginx', '1.18.0'))
		self.assertFalse(a_port.ports.filter(address='192.0.2.11').exists())

	def test_the_same_ip_reuses_its_own_row(self):
		persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.12', 80)}), ctx={})
		persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.12', 80)}), ctx={})
		self.assertEqual(IpAddress.objects.get(address='192.0.2.12').ports.filter(number=80).count(), 1)



GUESS = {'service_name': 'mdns', 'description': 'Multicast DNS'}  # what the port table says about 5353


class BbotKeepsTheDetectedServiceTests(TestCase):
	"""A bbot discovery only knows a port is open: the service nmap detected, and nmap as the source, must survive it."""

	def nmap_port(self, address, number, service_name):
		port_inventory.persist_inventory([{'ip': address, 'ports': [{'number': number, 'state': 'open', 'service_name': service_name}]}])
		return IpAddress.objects.get(address=address).ports.get(number=number)

	def test_an_nmap_service_name_survives_a_bbot_batch(self):
		port = self.nmap_port('192.0.2.20', 5353, 'domain')
		source, description = port.source, port.description
		with mock.patch('cvengine.tasks.get_port_service_description', return_value=dict(GUESS)):
			persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.20', 5353)}), ctx={})
		port.refresh_from_db()
		self.assertEqual(port.service_name, 'domain')
		self.assertEqual(port.description, description)  # the table's description is of another service
		self.assertEqual(port.source, source)
		self.assertNotEqual(port.source, 'bbot')
		self.assertIsNotNone(port.last_seen)

	def test_an_unknown_port_does_not_clear_the_service_name(self):
		port = self.nmap_port('192.0.2.21', 49999, 'custom-svc')
		with mock.patch('cvengine.tasks.get_port_service_description', return_value={'service_name': '', 'description': ''}):
			persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.21', 49999)}), ctx={})
		port.refresh_from_db()
		self.assertEqual(port.service_name, 'custom-svc')

	def test_a_new_port_gets_the_guessed_name_and_bbot_as_source(self):
		with mock.patch('cvengine.tasks.get_port_service_description', return_value=dict(GUESS)):
			persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.22', 5353)}), ctx={})
		port = IpAddress.objects.get(address='192.0.2.22').ports.get(number=5353)
		self.assertEqual((port.service_name, port.description, port.source), ('mdns', 'Multicast DNS', 'bbot'))
		self.assertIsNotNone(port.last_seen)

	def test_an_existing_port_with_no_name_is_filled(self):
		ip = IpAddress.objects.create(address='192.0.2.23')
		port = Port.objects.create(number=5353, service_name='', description='')
		ip.ports.add(port)
		with mock.patch('cvengine.tasks.get_port_service_description', return_value=dict(GUESS)):
			persist_bbot_result(bbot_lib.BbotResult(ports={('192.0.2.23', 5353)}), ctx={})
		port.refresh_from_db()
		self.assertEqual((port.service_name, port.description, port.source), ('mdns', 'Multicast DNS', 'bbot'))


class UpdateOrCreatePortWritesTests(TestCase):
	def setUp(self):
		self.ip = IpAddress.objects.create(address='192.0.2.30')
		self.port = Port.objects.create(number=22, service_name='ssh', description='OpenSSH server', source='nmap')
		self.ip.ports.add(self.port)

	def test_an_unchanged_port_causes_no_update(self):
		with CaptureQueriesContext(connection) as ctx:
			port, created = update_or_create_port(22, service_name='other', description='a guess', ip=self.ip)
		self.assertFalse(created)
		self.assertEqual(port.pk, self.port.pk)
		self.assertEqual([q['sql'] for q in ctx.captured_queries if q['sql'].lstrip().upper().startswith('UPDATE')], [])
		self.assertEqual(len(ctx.captured_queries), 1)  # the lookup only
		self.port.refresh_from_db()
		self.assertEqual((self.port.service_name, self.port.description), ('ssh', 'OpenSSH server'))

	def test_only_the_empty_field_is_written(self):
		Port.objects.filter(pk=self.port.pk).update(description='')
		with CaptureQueriesContext(connection) as ctx:
			update_or_create_port(22, service_name='ssh', description='Secure Shell', ip=self.ip)
		updates = [q['sql'] for q in ctx.captured_queries if q['sql'].lstrip().upper().startswith('UPDATE')]
		self.assertEqual(len(updates), 1)
		self.assertNotIn('"service_name"', updates[0])
		self.port.refresh_from_db()
		self.assertEqual((self.port.service_name, self.port.description), ('ssh', 'Secure Shell'))


class WhatportisTableTests(SimpleTestCase):
	ROWS = [
		{'name': 'http', 'port': '80', 'protocol': 'tcp', 'description': 'World Wide Web HTTP'},
		{'name': 'www-http', 'port': '80', 'protocol': 'udp', 'description': 'second row of 80'},
		{'name': 'https', 'port': '443', 'protocol': 'tcp', 'description': 'http protocol over TLS/SSL'},
	]

	def setUp(self):
		common_func._WHATPORTIS_TABLE = None
		self.addCleanup(setattr, common_func, '_WHATPORTIS_TABLE', None)

	def test_the_table_is_parsed_once_and_the_first_row_wins(self):
		database = mock.Mock()
		database.all.return_value = [dict(r) for r in self.ROWS]
		with mock.patch('whatportis.db.get_database', return_value=database) as opened:
			first = common_func.get_port_service_description(80)
			second = common_func.get_port_service_description('443')
		self.assertEqual(opened.call_count, 1)
		self.assertEqual(first, {'service_name': 'http', 'description': 'World Wide Web HTTP'})
		self.assertEqual(second, {'service_name': 'https', 'description': 'http protocol over TLS/SSL'})

	def test_a_port_missing_from_the_table_falls_back_to_the_socket_table(self):
		database = mock.Mock()
		database.all.return_value = [dict(r) for r in self.ROWS]
		with mock.patch('whatportis.db.get_database', return_value=database), \
				mock.patch('cvengine.common_func.socket.getservbyport', return_value='ssh'):
			self.assertEqual(common_func.get_port_service_description(22), {'service_name': 'ssh', 'description': ''})

class DeshareMigrationTests(TestCase):
	def test_a_row_shared_by_two_ips_is_split_and_the_first_ip_keeps_it(self):
		module = importlib.import_module('startScan.migrations.0007_deshare_ports')
		a, b, c = (IpAddress.objects.create(address=f'192.0.2.{n}') for n in (21, 22, 23))
		shared = Port.objects.create(number=443, product='nginx', version='1.18.0')
		for ip in (a, b, c):
			ip.ports.add(shared)
		alone = Port.objects.create(number=22, product='openssh')
		a.ports.add(alone)
		module.deshare_ports(apps, None)
		self.assertEqual(a.ports.get(number=443).pk, shared.pk)
		for ip in (b, c):
			copy = ip.ports.get(number=443)
			self.assertNotEqual(copy.pk, shared.pk)
			self.assertEqual((copy.product, copy.version), ('nginx', '1.18.0'))
		self.assertNotEqual(b.ports.get(number=443).pk, c.ports.get(number=443).pk)
		self.assertEqual(a.ports.get(number=22).pk, alone.pk)
		self.assertEqual(Port.objects.filter(number=443).count(), 3)
		module.deshare_ports(apps, None)  # idempotent
		self.assertEqual(Port.objects.filter(number=443).count(), 3)
