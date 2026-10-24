import importlib

from django.apps import apps
from django.test import TestCase

from cveFeed import nmap_scan
from reNgine import bbot as bbot_lib
from reNgine.tasks import persist_bbot_result
from startScan.models import IpAddress, Port


class BbotPortsArePerIpTests(TestCase):
	"""Review 2.4: bbot used to attach one Port row per port number to every IP."""

	def test_bbot_for_another_ip_does_not_inherit_the_nmap_service(self):
		nmap_scan.persist_inventory([{'ip': '192.0.2.10', 'ports': [
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
