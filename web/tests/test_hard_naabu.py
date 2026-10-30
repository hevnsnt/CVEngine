import subprocess
import unittest
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import naabu_scan, nmap_scan
from cveFeed.models import ServiceRun
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_nmap_scan import _report


class PureTests(unittest.TestCase):
	def test_output_is_grouped_per_address_and_a_tarpit_is_dropped(self):
		lines = ['{"ip":"198.51.100.1","port":22}', '{"ip":"198.51.100.1","port":8443}', 'noise', '{"ip":"198.51.100.1","port":22}',
			'{"host":"198.51.100.2","port":9200}', '{"ip":"198.51.100.3","port":0}', '{"ip":"198.51.100.3","port":70000}']
		lines += [f'{{"ip":"198.51.100.9","port":{n}}}' for n in range(1, naabu_scan.MAX_OPEN_PER_IP + 2)]
		self.assertEqual(naabu_scan.parse_output('\n'.join(lines)),
			{'198.51.100.1': [22, 8443], '198.51.100.2': [9200], '198.51.100.9': None})

	def test_the_port_argument_is_compact(self):
		self.assertEqual(naabu_scan.port_argument([8080, 22, 80, 81, 82, 443, 22]), '22,80-82,443,8080')
		self.assertEqual(naabu_scan.port_argument([5]), '5')

	def test_a_pass_over_open_ports_gets_closed_probe_ports_so_nmap_can_fingerprint_the_system(self):
		# nmap's -O --osscan-limit needs an open and a closed TCP port; with naabu's open ports alone no host was ever OS-fingerprinted
		with_probe = naabu_scan.flags_for({'a': [22]}, nmap_scan.FAST_FLAGS)(['a'])
		self.assertEqual(with_probe[with_probe.index('-p') + 1], '1,3,22')
		without = naabu_scan.flags_for({'a': [22]}, nmap_scan.FAST_FLAGS, os_probe=False)(['a'])
		self.assertEqual(without[without.index('-p') + 1], '22')  # a top-up pass must not replace another scanner's OS guess with a weaker one
		no_os = naabu_scan.flags_for({'a': [22]}, ['-sV', '--top-ports', '1000', '-Pn'])(['a'])
		self.assertEqual(no_os[no_os.index('-p') + 1], '22')  # no OS detection asked for, nothing to probe
		self.assertIsNone(naabu_scan.flags_for({'a': []}, nmap_scan.FAST_FLAGS)(['a']))  # nothing open: still nothing to fingerprint

	def test_flags_replace_top_ports_with_the_open_ports(self):
		build = naabu_scan.flags_for({'a': [22, 8443], 'b': [8443, 9200], 'c': []}, nmap_scan.FAST_FLAGS)
		flags = build(['a', 'b'])
		self.assertIn('-p', flags)
		self.assertEqual(flags[flags.index('-p') + 1], '1,3,22,8443,9200')
		self.assertNotIn('--top-ports', flags)
		self.assertEqual([f for f in flags if f != '-p' and f != '1,3,22,8443,9200'], [f for f in nmap_scan.FAST_FLAGS if f not in ('--top-ports', '1000')])
		self.assertIsNone(build(['c']))  # nothing open: nothing to fingerprint
		self.assertEqual(build(['a', 'unknown']), nmap_scan.FAST_FLAGS)  # an address with no answer keeps the default ports

	def test_an_unreasonably_long_port_list_keeps_the_default_flags(self):
		build = naabu_scan.flags_for({'a': list(range(1, 60000, 2))}, nmap_scan.FAST_FLAGS)
		self.assertEqual(build(['a']), nmap_scan.FAST_FLAGS)

	def test_enabled_by_default_and_explicit_zero_turns_it_off(self):
		with mock.patch.dict('os.environ', {}, clear=False):
			import os
			os.environ.pop('CVENGINE_NAABU', None)
			self.assertTrue(naabu_scan.enabled())
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU': '0'}):
			self.assertFalse(naabu_scan.enabled())
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU': 'false'}):
			self.assertFalse(naabu_scan.enabled())

	def test_the_binary_is_found_or_absent(self):
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU': '1', 'CVENGINE_NAABU_BIN': 'definitely-not-installed-naabu'}):
			self.assertIsNone(naabu_scan.naabu_path())
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU': '1'}), \
				mock.patch.object(naabu_scan.shutil, 'which', return_value='/usr/local/bin/naabu'):
			self.assertEqual(naabu_scan.naabu_path(), '/usr/local/bin/naabu')

	def test_rate_is_clamped(self):
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU_RATE': '999999'}):
			self.assertEqual(naabu_scan.rate(), 5000)
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU_RATE': 'x'}):
			self.assertEqual(naabu_scan.rate(), naabu_scan.DEFAULT_RATE)


class RunTests(unittest.TestCase):
	def test_the_run_is_gated_reads_a_list_file_and_never_puts_an_address_on_the_command_line(self):
		seen = {}

		class Job:
			def __enter__(self):
				return self

			def __exit__(self, *exc):
				return False

			def attach(self, proc):
				pass

			def raise_if_killed(self):
				pass

		class Proc:
			returncode = 0

			def __init__(self, cmd, **kwargs):
				seen['cmd'] = cmd
				seen['list'] = open(cmd[cmd.index('-list') + 1]).read().split()

			def communicate(self, timeout=None):
				seen['timeout'] = timeout
				return '{"ip":"198.51.100.1","port":8443}\n', ''

		def heavy(kind, **kwargs):
			seen['kind'] = kind
			return Job()
		with mock.patch('reNgine.resources.heavy_job', heavy), mock.patch.object(naabu_scan.subprocess, 'Popen', Proc):
			out = naabu_scan.run_naabu(['198.51.100.1', '198.51.100.2'], binary='/bin/naabu')
		self.assertEqual(out, {'198.51.100.1': [8443]})
		self.assertEqual(seen['kind'], 'naabu')
		self.assertEqual(seen['list'], ['198.51.100.1', '198.51.100.2'])
		self.assertNotIn('198.51.100.1', seen['cmd'])
		self.assertEqual((seen['cmd'][0], seen['cmd'][seen['cmd'].index('-p') + 1]), ('/bin/naabu', '-'))
		self.assertLessEqual(seen['timeout'], naabu_scan.RUN_TIMEOUT_MAX)

	def test_a_failed_run_raises(self):
		class Job:
			def __enter__(self):
				return self

			def __exit__(self, *exc):
				return False

			def attach(self, proc):
				pass

			def raise_if_killed(self):
				pass

		class Proc:
			returncode = 2

			def __init__(self, cmd, **kwargs):
				pass

			def communicate(self, timeout=None):
				return '', 'permission denied: raw sockets'
		with mock.patch('reNgine.resources.heavy_job', lambda *a, **k: Job()), mock.patch.object(naabu_scan.subprocess, 'Popen', Proc):
			with self.assertRaises(RuntimeError):
				naabu_scan.run_naabu(['198.51.100.1'], binary='/bin/naabu')

	def test_with_no_binary_run_naabu_refuses(self):
		with mock.patch.object(naabu_scan, 'naabu_path', return_value=None):
			with self.assertRaises(RuntimeError):
				naabu_scan.run_naabu(['198.51.100.1'])


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

	def runner(self, xml=None):
		def run(targets, flags, host_timeout):
			self.calls.append((list(targets), list(flags)))
			return xml if xml is not None else _report([(22, 'open', 'OpenSSH', '8.9'), (8443, 'open', 'nginx', '1.18.0')],
				scanned='1,3,22,8443,9200').replace('192.0.2.77', '198.51.100.50')
		return run

	def test_without_naabu_the_flags_are_todays(self):
		with mock.patch.dict('os.environ', {'CVENGINE_NAABU_BIN': 'definitely-not-installed-naabu'}):
			nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner())
		self.assertEqual([c[1] for c in self.calls], [nmap_scan.FAST_FLAGS])
		self.assertFalse(ServiceRun.objects.filter(service='naabu').exists())

	def test_naabu_ports_become_the_nmap_port_list_and_open_ports_are_persisted(self):
		out = nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(), naabu_runner=lambda ips: {'198.51.100.50': [22, 8443, 9200]})
		flags = self.calls[0][1]
		self.assertEqual(flags[flags.index('-p') + 1], '1,3,22,8443,9200')
		self.assertNotIn('--top-ports', flags)
		self.assertIn('-sV', flags)
		self.assertEqual(out['fast']['ports'], 2)
		ports = {p.number: p for p in self.ip.ports.all()}
		self.assertEqual(ports[9200].source, 'naabu')  # naabu found it, nmap did not confirm a service yet
		self.assertEqual((ports[22].product, ports[22].source), ('OpenSSH', 'nmap'))
		self.assertTrue(ServiceRun.objects.filter(service='naabu', asset='198.51.100.50', status='done').exists())

	def test_a_naabu_failure_falls_back_to_the_default_flags_and_is_recorded(self):
		def boom(ips):
			raise RuntimeError('permission denied: raw sockets')
		out = nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(), naabu_runner=boom)
		self.assertEqual(self.calls[0][1], nmap_scan.FAST_FLAGS)
		self.assertNotIn('error', out)  # the pipeline does not depend on naabu
		self.assertEqual(ServiceRun.objects.get(service='naabu').status, 'failed')

	def test_a_tarpit_keeps_the_nmap_fallback_and_does_not_refresh_naabu_coverage(self):
		IpAddress.objects.create(address='198.51.100.51', org=self.ip.org)
		ports = list(range(1, naabu_scan.MAX_OPEN_PER_IP + 2))
		result = naabu_scan.discover(['198.51.100.50', '198.51.100.51'], self.scan,
			runner=lambda ips: {'198.51.100.50': None, '198.51.100.51': [8443]})
		self.assertEqual(result, {'198.51.100.51': [8443]})
		self.assertEqual(naabu_scan.flags_for(result, nmap_scan.FAST_FLAGS)(['198.51.100.50']), nmap_scan.FAST_FLAGS)
		self.assertEqual(ServiceRun.objects.get(service='naabu', asset='198.51.100.50').status, 'failed')
		self.assertEqual(ServiceRun.objects.get(service='naabu', asset='198.51.100.51').status, 'done')
		self.assertEqual(naabu_scan.parse_output('\n'.join(f'{{"ip":"198.51.100.50","port":{p}}}' for p in ports)),
			{'198.51.100.50': None})

	def test_a_fresh_naabu_result_is_not_asked_for_again_inside_the_ttl(self):
		calls = []
		runner = lambda ips: calls.append(list(ips)) or {'198.51.100.50': [22]}  # noqa: E731
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(), naabu_runner=runner)
		ServiceRun.objects.filter(service='nmap-fast').update(finished_at=timezone.now() - timedelta(days=8))  # nmap is due, naabu is not
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(), naabu_runner=runner)
		self.assertEqual(len(calls), 1)
		self.assertEqual(self.calls[1][1][self.calls[1][1].index('-p') + 1], '1,3,22,8443')  # the inventory's open ports are re-checked
		ServiceRun.objects.filter(service='naabu').update(finished_at=timezone.now() - timedelta(days=8))
		ServiceRun.objects.filter(service='nmap-fast').update(finished_at=timezone.now() - timedelta(days=8))
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(), naabu_runner=runner)
		self.assertEqual(len(calls), 2)  # past the 7 day TTL

	def test_a_port_naabu_no_longer_sees_is_rechecked_by_nmap_and_closed(self):
		self.ip.ports.add(Port.objects.create(number=8080, product='nginx', version='1.18.0', state='open'))
		xml = _report([(22, 'open', 'OpenSSH', '8.9')], scanned='1,3,22,8080').replace('192.0.2.77', '198.51.100.50')
		nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(xml), naabu_runner=lambda ips: {'198.51.100.50': [22]})
		flags = self.calls[0][1]
		self.assertEqual(flags[flags.index('-p') + 1], '1,3,22,8080')  # the previously open port is part of the check
		self.assertEqual(self.ip.ports.get(number=8080).state, 'closed')

	def test_an_address_with_nothing_open_is_not_fingerprinted_but_is_recorded(self):
		out = nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner(), naabu_runner=lambda ips: {})
		self.assertEqual(self.calls, [])
		self.assertEqual(out['fast']['ports'], 0)
		self.assertTrue(ServiceRun.objects.filter(service='nmap-fast', asset='198.51.100.50').exists())

	def test_a_blocked_address_is_never_given_to_naabu(self):
		seen = []
		IpAddress.objects.create(address='169.254.169.254')
		self.assertIsNone(naabu_scan.discover(['169.254.169.254', '127.0.0.1'], self.scan, runner=lambda ips: seen.append(ips) or {}))
		self.assertEqual(seen, [])

	def test_discover_never_raises(self):
		with mock.patch('cveFeed.ledger.fresh', side_effect=RuntimeError('redis down')):
			self.assertIsNone(naabu_scan.discover(['198.51.100.50'], self.scan, runner=lambda ips: {}))

	def test_naabu_is_a_heavy_job_kind_with_a_ttl(self):
		from cveFeed import ledger
		from reNgine import resources
		self.assertEqual(resources.BASE_COSTS_MB['naabu'], 150)
		self.assertEqual(resources.MAX_CONCURRENT['naabu'], 1)
		self.assertEqual(ledger.ttl('naabu'), 7 * 24 * 3600)
