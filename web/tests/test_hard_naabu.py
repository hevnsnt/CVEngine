import unittest
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import port_inventory, port_stage
from cveFeed.models import ServiceRun
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_port_inventory import _report


class PureTests(unittest.TestCase):
	def test_the_address_list_is_deduplicated_sorted_and_capped(self):
		self.assertEqual(port_stage.build_targets(['b', 'a', 'b', '', None]), ['a', 'b'])
		self.assertEqual(len(port_stage.build_targets([f'10.0.{n // 250}.{n % 250}' for n in range(500)])), port_stage.MAX_TARGETS)

	def test_the_pass_is_on_by_default_and_the_switch_turns_it_off(self):
		with mock.patch.dict('os.environ', {}, clear=False) as env:
			env.pop('CVENGINE_NAABU', None)
			self.assertTrue(port_stage.enabled())
		for value in ('0', 'false', 'off'):
			with mock.patch.dict('os.environ', {'CVENGINE_NAABU': value}):
				self.assertFalse(port_stage.enabled())



class PipelineTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='N', slug='nb')
		project = Project.objects.create(name='P', slug='pnb', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='nb.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1,
			results_dir='/tmp')
		self.sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='www.nb.test')
		self.ip = IpAddress.objects.create(address='198.51.100.50', org=org)  # IP rows belong to the host's organization
		self.sub.ip_addresses.add(self.ip)
		self.calls = []

	def fingerprint(self, xml=None):
		"""Stands in for the Sentinel's fingerprint pass (``try_nmap``): the report is read and stored as the server reads a real one."""
		def run(project, scan, targets, org_id=None, timeout=None):
			self.calls.append(list(targets))
			text = xml if xml is not None else _report([(22, 'open', 'OpenSSH', '8.9'), (8443, 'open', 'nginx', '1.18.0')],
				scanned='1,3,22,8443,9200').replace('192.0.2.77', '198.51.100.50')
			return port_inventory.persist_inventory(port_inventory.parse_xml(text), org_id=org_id, os_reliable=True)
		return run

	def run_stage(self, naabu=None, xml=None, **kwargs):
		patches = [mock.patch('agentapi.sentinel_dispatch.try_nmap', self.fingerprint(xml))]
		patches.append(mock.patch('agentapi.sentinel_dispatch.wrap_naabu_runner', lambda project, scan, **k: naabu))
		with patches[0], patches[1]:
			return port_stage.run_for_scan(self.scan.id, **kwargs)

	def test_without_the_discovery_pass_only_the_fingerprint_runs(self):
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU': '0'}):
			self.run_stage(naabu=mock.Mock(side_effect=AssertionError('naabu was asked')))
		self.assertEqual(self.calls, [['198.51.100.50']])
		self.assertFalse(ServiceRun.objects.filter(service='naabu').exists())

	def test_discovered_ports_are_persisted_and_the_fingerprint_enriches_them(self):
		out = self.run_stage(naabu=lambda ips: {'198.51.100.50': [22, 8443, 9200]})
		self.assertEqual(out['fast']['ports'], 2)
		ports = {p.number: p for p in self.ip.ports.all()}
		self.assertEqual(ports[9200].source, 'naabu')  # found by the discovery pass, no service confirmed yet
		self.assertEqual((ports[22].product, ports[22].source), ('OpenSSH', 'nmap'))
		self.assertTrue(ServiceRun.objects.filter(service='naabu', asset='198.51.100.50', status='done').exists())

	def test_a_discovery_failure_leaves_the_fingerprint_to_go_on_and_is_recorded(self):
		def boom(ips):
			raise RuntimeError('permission denied: raw sockets')
		out = self.run_stage(naabu=boom)
		self.assertEqual(self.calls, [['198.51.100.50']])
		self.assertNotIn('error', out)  # the pipeline does not depend on the discovery pass
		self.assertEqual(ServiceRun.objects.get(service='naabu').status, 'failed')

	def test_a_tarpit_is_not_a_result_and_does_not_refresh_the_discovery_coverage(self):
		IpAddress.objects.create(address='198.51.100.51', org=self.ip.org)
		result = port_stage.discover(['198.51.100.50', '198.51.100.51'], self.scan,
			runner=lambda ips: {'198.51.100.50': None, '198.51.100.51': [8443]})
		self.assertEqual(result, {'198.51.100.51': [8443]})
		self.assertEqual(ServiceRun.objects.get(service='naabu', asset='198.51.100.50').status, 'failed')
		self.assertEqual(ServiceRun.objects.get(service='naabu', asset='198.51.100.51').status, 'done')

	def test_a_fresh_discovery_result_is_not_asked_for_again_inside_the_ttl(self):
		calls = []
		runner = lambda ips: calls.append(list(ips)) or {'198.51.100.50': [22]}  # noqa: E731
		self.run_stage(naabu=runner)
		ServiceRun.objects.filter(service='nmap-fast').update(finished_at=timezone.now() - timedelta(days=8))  # the fingerprint is due, discovery is not
		self.run_stage(naabu=runner)
		self.assertEqual(len(calls), 1)
		ServiceRun.objects.filter(service='naabu').update(finished_at=timezone.now() - timedelta(days=8))
		ServiceRun.objects.filter(service='nmap-fast').update(finished_at=timezone.now() - timedelta(days=8))
		self.run_stage(naabu=runner)
		self.assertEqual(len(calls), 2)  # past the 7 day TTL

	def test_a_port_the_discovery_no_longer_sees_is_closed_by_the_next_fingerprint_report(self):
		from startScan.models import Port
		self.ip.ports.add(Port.objects.create(number=8080, product='nginx', version='1.18.0', state='open'))
		xml = _report([(22, 'open', 'OpenSSH', '8.9')], scanned='1,3,22,8080').replace('192.0.2.77', '198.51.100.50')
		self.run_stage(naabu=lambda ips: {'198.51.100.50': [22]}, xml=xml)
		self.assertEqual(self.ip.ports.get(number=8080).state, 'closed')

	def test_a_blocked_address_is_never_given_to_the_scanner(self):
		seen = []
		IpAddress.objects.create(address='169.254.169.254')
		self.assertIsNone(port_stage.discover(['169.254.169.254', '127.0.0.1'], self.scan, runner=lambda ips: seen.append(ips) or {}))
		self.assertEqual(seen, [])

	def test_discover_never_raises(self):
		with mock.patch('cveFeed.ledger.fresh', side_effect=RuntimeError('redis down')):
			self.assertIsNone(port_stage.discover(['198.51.100.50'], self.scan, runner=lambda ips: {}))

	def test_naabu_is_a_heavy_job_kind_with_a_ttl(self):
		from cveFeed import ledger
		from reNgine import resources
		self.assertEqual(resources.BASE_COSTS_MB['naabu'], 150)
		self.assertEqual(resources.MAX_CONCURRENT['naabu'], 1)
		self.assertEqual(ledger.ttl('naabu'), 7 * 24 * 3600)
