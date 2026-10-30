import os
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import discovery, fullscan, nmap_scan
from cveFeed.models import AgentActivity, AssetChange, HostState, ServiceRun
from dashboard.models import Org, Project
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


def xml(ip, ports, closed=True):
	body = ''.join(f'<port protocol="tcp" portid="{n}"><state state="open"/><service name="{s}"/></port>' for n, s in ports)
	extra = '<extraports state="closed" count="65000"/>' if closed else ''
	return (f'<?xml version="1.0"?><nmaprun><scaninfo type="syn" protocol="tcp" services="1-65535"/><host><status state="up"/>'
		f'<address addr="{ip}" addrtype="ipv4"/><ports>{extra}{body}</ports></host></nmaprun>')


class FullScanBase(TestCase):
	def setUp(self):
		now = timezone.now()
		org = Org.objects.create(name='F', slug='f')
		self.project = Project.objects.create(name='P', slug='pf', insert_date=now, org=org)
		self.domain = Domain.objects.create(name='fs.test', project=self.project, insert_date=now)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=now, scan_status=2, results_dir='/tmp')
		patches = [mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
			mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'),
			mock.patch('cveFeed.fullscan.CLAIM_KEY', 'cvengine:fullscan:test'),
			# These fixtures do not build full core-stage coverage; the deep-scan coverage gate (see
			# cveFeed.coverage_topup.backlog_exists, tests/test_coverage_gate.py) is exercised on its own there.
			mock.patch('cveFeed.coverage_topup.backlog_exists', return_value=False),
			mock.patch.dict(os.environ, {}, clear=False)]
		for p in patches:
			p.start()
		self.addCleanup(mock.patch.stopall)
		os.environ.pop('CVENGINE_FULLSCAN', None)
		os.environ.pop('CVENGINE_ALLOW_PRIVATE_TARGETS', None)

	def ip(self, address, name=None, scanned=None, ports=(), cdn=False, scan=None, **kw):
		ip = IpAddress.objects.create(address=address, org=self.domain.org, full_scanned_at=scanned, is_cdn=cdn, **kw)
		for n in ports:
			ip.ports.add(Port.objects.create(number=n, protocol='tcp', state='open'))
		if name is not False:
			sub = Subdomain.objects.create(scan_history=scan or self.scan, target_domain=self.domain, name=name or f'h{address.split(".")[-1]}.fs.test')
			sub.ip_addresses.add(ip)
		return ip


class InFlightTests(FullScanBase):
	"""The same host is never swept twice at once: an in-flight sweep is excluded from selection and the IP is claimed atomically."""

	def test_an_in_flight_ip_is_not_picked_again(self):
		now = timezone.now()
		# started a moment ago, never finished -> in flight -> must be skipped even though it is the oldest (null) sweep
		self.ip('192.0.2.1', scanned=None, full_scan_started_at=now - timedelta(minutes=5))
		other = self.ip('192.0.2.2', scanned=now - timedelta(days=1))
		self.assertEqual(fullscan.pick().pk, other.pk)

	def test_a_stale_in_flight_mark_is_eligible_again(self):
		started = timezone.now() - timedelta(seconds=fullscan.IN_FLIGHT_SECONDS + 60)
		stuck = self.ip('192.0.2.1', scanned=None, full_scan_started_at=started)
		self.assertEqual(fullscan.pick().pk, stuck.pk)  # presumed crashed, so it comes back

	def test_claim_ip_is_atomic_and_single_winner(self):
		ip = self.ip('192.0.2.1', scanned=None)
		self.assertTrue(fullscan._claim_ip(ip))   # first caller wins
		self.assertFalse(fullscan._claim_ip(ip))  # second caller sees it in flight and backs off

	def test_a_finished_sweep_clears_the_in_flight_state(self):
		ip = self.ip('192.0.2.1', scanned=None)
		self.assertTrue(fullscan._claim_ip(ip))
		fullscan._advance(ip, 3)  # completion stamps full_scanned_at after the start
		self.assertEqual(fullscan.pick().pk, ip.pk)  # eligible again, and claimable
		self.assertTrue(fullscan._claim_ip(ip))

	def test_run_skips_an_ip_already_being_swept(self):
		busy = self.ip('192.0.2.1', scanned=None, full_scan_started_at=timezone.now() - timedelta(minutes=1))
		fresh = self.ip('192.0.2.2', scanned=timezone.now() - timedelta(days=2))
		seen = []
		out = fullscan.run(runner=lambda t, f, h: seen.append(t[0]) or xml(t[0], []), fingerprint_runner=lambda *a: xml('x', []), pipeline=lambda d, n: None)
		self.assertEqual(seen, ['192.0.2.2'])  # the in-flight one is never swept
		self.assertNotIn('192.0.2.1', seen)


class SelectionTests(FullScanBase):
	def test_oldest_sweep_first_and_never_swept_beats_any_timestamp(self):
		now = timezone.now()
		self.ip('192.0.2.1', scanned=now - timedelta(days=1))
		b = self.ip('192.0.2.2', scanned=now - timedelta(days=9))
		self.assertEqual(fullscan.pick().pk, b.pk)
		c = self.ip('192.0.2.3', scanned=None)
		self.assertEqual(fullscan.pick().pk, c.pk)

	def test_ties_go_to_the_most_open_ports_and_closed_ports_do_not_count(self):
		self.ip('192.0.2.1', ports=[22])
		many = self.ip('192.0.2.2', ports=[22, 80, 443])
		shut = self.ip('192.0.2.3')
		for n in range(1, 9):
			shut.ports.add(Port.objects.create(number=n, protocol='tcp', state='closed'))
		self.assertEqual(fullscan.pick().pk, many.pk)

	def test_out_of_scope_cdn_blocked_and_private_ips_are_never_chosen(self):
		self.ip('192.0.2.1', cdn=True)
		self.ip('192.0.2.2', name=False)  # attached to no host
		self.ip('10.1.2.3')  # private
		self.ip('127.0.0.1')  # always blocked
		orphan = Domain.objects.create(name='orphan.test', insert_date=timezone.now())  # no project
		lonely = IpAddress.objects.create(address='192.0.2.9')
		sub = Subdomain.objects.create(scan_history=self.scan, target_domain=orphan, name='x.orphan.test')
		sub.ip_addresses.add(lonely)
		self.assertIsNone(fullscan.pick())
		with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
			self.assertEqual(fullscan.pick().address, '10.1.2.3')

	def test_a_host_that_resolves_somewhere_blocked_is_skipped(self):
		self.ip('192.0.2.1', name='rebind.fs.test')
		ok = self.ip('192.0.2.2', name='fine.fs.test', scanned=timezone.now())
		with mock.patch('targetApp.target_types.resolves_to_blocked', side_effect=lambda name: name == 'rebind.fs.test'):
			self.assertEqual(fullscan.pick().pk, ok.pk)


class SweepTests(FullScanBase):
	def runner(self, text, calls=None):
		def run(targets, flags, host_timeout):
			if calls is not None:
				calls.append((list(targets), list(flags), host_timeout))
			return text
		return run

	def test_a_sweep_records_the_time_and_count_and_persists_the_ports(self):
		ip = self.ip('192.0.2.1')
		calls = []
		out = fullscan.run(runner=self.runner(xml('192.0.2.1', [(22, 'ssh'), (9999, 'x')]), calls), fingerprint_runner=self.runner(''),
			pipeline=lambda d, n: None)
		self.assertEqual(calls, [(['192.0.2.1'], nmap_scan.FULL_PORT_FLAGS, nmap_scan.HOST_TIMEOUT_FULL)])
		ip.refresh_from_db()
		self.assertIsNotNone(ip.full_scanned_at)
		self.assertEqual(ip.full_scan_ports, 2)
		self.assertEqual(sorted(p.number for p in ip.ports.all()), [22, 9999])
		self.assertEqual(out['swept'][0]['new'], [22, 9999])

	def test_a_port_open_before_and_gone_now_is_closed(self):
		ip = self.ip('192.0.2.1', ports=[22, 8080])
		fullscan.run(runner=self.runner(xml('192.0.2.1', [(22, 'ssh')])), fingerprint_runner=self.runner(''), pipeline=lambda d, n: None)
		self.assertEqual({p.number: p.state for p in ip.ports.all()}, {22: 'open', 8080: 'closed'})
		ip.refresh_from_db()
		self.assertEqual(ip.full_scan_ports, 1)

	def test_one_ip_per_firing_and_the_rotation_moves_on(self):
		self.ip('192.0.2.1')
		self.ip('192.0.2.2')
		seen = []
		for _ in range(3):
			out = fullscan.run(runner=lambda t, f, h: seen.append(t[0]) or xml(t[0], []), fingerprint_runner=self.runner(''))
			self.assertEqual(len(out['swept']), 1)
		self.assertEqual(seen, ['192.0.2.1', '192.0.2.2', '192.0.2.1'])

	def test_batch_size_sweeps_several_in_one_firing(self):
		self.ip('192.0.2.1')
		self.ip('192.0.2.2')
		with mock.patch.dict(os.environ, {'CVENGINE_FULLSCAN_BATCH': '2'}):
			out = fullscan.run(runner=lambda t, f, h: xml(t[0], []), fingerprint_runner=self.runner(''))
		self.assertEqual(len(out['swept']), 2)

	def test_a_failed_sweep_records_attempt_without_claiming_fresh_coverage(self):
		ip = self.ip('192.0.2.1')

		def boom(targets, flags, host_timeout):
			raise RuntimeError('nmap timed out')
		out = fullscan.run(runner=boom)
		ip.refresh_from_db()
		self.assertIsNone(ip.full_scanned_at)
		self.assertIsNotNone(ip.full_scan_started_at)
		self.assertEqual(ip.full_scan_ports, 0)
		self.assertFalse(out['swept'][0]['ok'])
		self.assertTrue(AgentActivity.objects.filter(status='failed', message__contains='192.0.2.1').exists())
		other = self.ip('192.0.2.2')
		self.assertEqual(fullscan.pick().pk, other.pk)  # the stuck host does not come back first

	def test_invalid_output_does_not_advance_full_scan_coverage(self):
		for report in ('', '<nmaprun><host>', '<error/>'):
			with self.subTest(report=report):
				ip = self.ip(f'192.0.2.{10 + len(report)}')
				out = fullscan.sweep_ip(ip, runner=self.runner(report))
				ip.refresh_from_db()
				self.assertFalse(out['ok'])
				self.assertIsNone(ip.full_scanned_at)
				self.assertEqual(ip.full_scan_failures, 1)

	def test_a_paused_scan_picks_and_claims_nothing(self):
		ip = self.ip('192.0.2.1')
		with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
			out = fullscan.run(runner=self.runner(xml('192.0.2.1', [])))
		self.assertEqual(out, {'skipped': 'scanning is paused'})
		ip.refresh_from_db()
		self.assertIsNone(ip.full_scan_started_at)  # S04-14
		self.assertFalse(AgentActivity.objects.filter(message__contains='192.0.2.1').exists())

	def test_a_host_the_sweep_timed_out_on_is_a_failed_sweep_not_a_clean_zero(self):
		"""S04-4: nmap's --host-timeout leaves a host element marked timedout with no ports."""
		ip = self.ip('192.0.2.1', ports=[22])
		text = xml('192.0.2.1', []).replace('<host>', '<host timedout="true">')
		out = fullscan.run(runner=self.runner(text), fingerprint_runner=self.runner(''), pipeline=lambda d, n: None)
		ip.refresh_from_db()
		self.assertFalse(out['swept'][0]['ok'])
		self.assertEqual((ip.full_scanned_at, ip.full_scan_failures), (None, 1))
		self.assertIsNotNone(ip.full_scan_retry_at)
		self.assertEqual(ip.ports.get(number=22).state, 'open')  # nothing was closed on a half answer
		self.assertTrue(AgentActivity.objects.filter(status='failed', message__contains='time limit').exists())

	def test_an_ip_that_keeps_failing_backs_off_and_goes_behind_clean_ones(self):
		from datetime import timedelta
		from django.utils import timezone
		ip = self.ip('192.0.2.1')

		def boom(targets, flags, host_timeout):
			raise RuntimeError('nmap crashed reading /srv/private/x')
		fullscan.run(runner=boom)
		ip.refresh_from_db()
		self.assertEqual(ip.full_scan_failures, 1)
		self.assertAlmostEqual((ip.full_scan_retry_at - timezone.now()).total_seconds(), 6 * 3600, delta=60)
		message = AgentActivity.objects.filter(status='failed').latest('id').message
		self.assertNotIn('/srv/private', message)
		self.assertIn('next try after', message)
		# after the lease and the backoff, a clean never-swept IP still goes first
		type(ip).objects.filter(pk=ip.pk).update(full_scan_started_at=timezone.now() - timedelta(days=1),
												 full_scan_retry_at=timezone.now() - timedelta(minutes=1))
		clean = self.ip('192.0.2.9')
		self.assertEqual(fullscan.pick().pk, clean.pk)
		self.assertGreater(fullscan._back_off(ip) - timezone.now(), timedelta(hours=11))  # second failure: 12 hours
		for _ in range(10):
			retry = fullscan._back_off(ip)
		self.assertLessEqual((retry - timezone.now()).total_seconds(), 7 * 86400 + 60)  # capped at a week
		fullscan._advance(ip, 3)  # a successful sweep clears it
		ip.refresh_from_db()
		self.assertEqual((ip.full_scan_failures, ip.full_scan_retry_at), (0, None))

	def test_waiting_for_memory_is_not_the_addresss_failure(self):
		from reNgine.resources import MemoryBusy
		ip = self.ip('192.0.2.1')

		def busy(targets, flags, host_timeout):
			raise MemoryBusy('nmap-full-bg waited too long for memory')
		fullscan.run(runner=busy)
		ip.refresh_from_db()
		self.assertEqual((ip.full_scan_failures, ip.full_scan_retry_at), (0, None))

	def test_the_claim_allows_one_sweep_at_a_time(self):
		self.ip('192.0.2.1')
		runner = mock.Mock()
		with resources.redis_claim(fullscan.CLAIM_KEY, 'someone-else', 60) as mine:
			if mine is not True:
				self.skipTest('nothing to hold the claim with')
			with mock.patch('cveFeed.fullscan.sweep_ip') as sweep:
				out = fullscan.run(runner=runner)
		self.assertIn('another background sweep', out['skipped'])
		sweep.assert_not_called()

	def test_the_claim_is_released_after_a_firing(self):
		self.ip('192.0.2.1')
		fullscan.run(runner=lambda t, f, h: xml(t[0], []), fingerprint_runner=self.runner(''))
		with resources.redis_claim(fullscan.CLAIM_KEY, 'next', 60) as got:
			self.assertIs(got, True)

	def test_the_off_switch(self):
		ip = self.ip('192.0.2.1')
		runner = mock.Mock()
		with mock.patch.dict(os.environ, {'CVENGINE_FULLSCAN': '0'}):
			out = fullscan.run(runner=runner)
		runner.assert_not_called()
		self.assertIn('skipped', out)
		ip.refresh_from_db()
		self.assertIsNone(ip.full_scanned_at)

	def test_the_task_and_heavy_kind_are_registered(self):
		from cveFeed.tasks import background_full_scan
		self.assertEqual(background_full_scan.name, 'background_full_scan')
		self.assertEqual(resources.BASE_COSTS_MB['nmap-full-bg'], 500)
		self.assertEqual(resources.MAX_CONCURRENT['nmap-full-bg'], 1)

	def test_the_default_runner_uses_the_background_heavy_job(self):
		with mock.patch('cveFeed.nmap_scan.run_nmap_xml', return_value='') as run:
			fullscan._sweep_runner(['192.0.2.1'], nmap_scan.FULL_PORT_FLAGS, '10m')
		self.assertEqual(run.call_args.kwargs['kind'], 'nmap-full-bg')

	def test_the_schedule_migration_created_the_periodic_task(self):
		from django_celery_beat.models import PeriodicTask
		task = PeriodicTask.objects.get(name='cvengine-background-full-scan')
		self.assertEqual((task.task, task.queue, task.enabled), ('background_full_scan', 'cve_feed_queue', True))

	def test_the_pipeline_no_longer_sweeps_every_port(self):
		self.ip('192.0.2.1')
		seen = []

		def runner(targets, flags, host_timeout):
			seen.append(flags)
			return ''
		with mock.patch.dict(os.environ, {'CVENGINE_NMAP_FULL': '1'}):
			nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertTrue(seen)
		self.assertNotIn('-p-', [f for flags in seen for f in flags])


class InvestigationTests(FullScanBase):
	def setUp(self):
		super().setUp()
		self.ip_obj = self.ip('192.0.2.1', name='www.fs.test', ports=[22])
		HostState.objects.create(project=self.project, domain=self.domain, host='www.fs.test', fingerprint='old',
			state={'ips': {'192.0.2.1': {'ports': {'22/tcp': {'service': '', 'product': '', 'version': ''}}}}, 'techs': []})
		self.fp = []
		self.pipelines = []

	def fingerprint_runner(self):
		def run(targets, flags, host_timeout):
			self.fp.append((list(targets), list(flags)))
			return xml('192.0.2.1', [(6379, 'redis')], closed=False).replace('<service name="redis"/>', '<service name="redis" product="Redis" version="6.0.1"/>')
		return run

	def pipeline(self, checks=None):
		def run(domain_id, names):
			self.pipelines.append(list(names))
			return discovery.run_host_pipeline(domain_id, names, retest=True, resolver=lambda n: {(x, '192.0.2.1') for x in n},
				light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]), nmap_runner=lambda t, f, h: '',
				db_exposure_checks=checks if checks is not None else {}, provider=None,
				route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
		return run

	def sweep(self, ports, fp=None, pipeline=None, checks=None):
		return fullscan.run(runner=lambda t, f, h: xml('192.0.2.1', ports), fingerprint_runner=fp or self.fingerprint_runner(),
			pipeline=pipeline or self.pipeline(checks))

	def test_a_new_port_is_fingerprinted_checked_retested_and_recorded_as_a_change(self):
		checks = {'redis': ('Redis', lambda host, port: True)}
		out = self.sweep([(22, 'ssh'), (6379, 'redis')], checks=checks)
		inv = out['swept'][0]['investigation']
		self.assertEqual(inv['ports'], [6379])
		self.assertEqual(self.fp[0][0], ['192.0.2.1'])
		self.assertEqual(self.fp[0][1][-2:], ['-p', '6379'])
		self.assertIn('-sV', self.fp[0][1])
		port = self.ip_obj.ports.get(number=6379)
		self.assertEqual((port.product, port.version), ('Redis', '6.0.1'))
		self.assertEqual(inv['retested'], ['www.fs.test'])
		scan = ScanHistory.objects.exclude(pk=self.scan.pk).get()
		self.assertEqual(scan.tasks, [discovery.HOST_PIPELINE_TASK, 'retest'])  # a small host-pipeline scan, not a discovery
		self.assertTrue(Vulnerability.objects.filter(scan_history=scan, name='Unauthenticated Redis exposure').exists())
		change = AssetChange.objects.get(kind='port_opened')
		self.assertEqual((change.host, change.ip, change.port, change.scan_id), ('www.fs.test', '192.0.2.1', 6379, scan.id))
		self.assertEqual(change.after['product'], 'Redis')

	def test_no_new_port_means_no_investigation(self):
		pipeline = mock.Mock()
		out = self.sweep([(22, 'ssh')], pipeline=pipeline)
		self.assertNotIn('investigation', out['swept'][0])
		self.assertEqual(self.fp, [])
		pipeline.assert_not_called()
		self.assertFalse(AssetChange.objects.exists())

	def test_the_investigation_cap_is_honoured(self):
		ports = [(2000 + i, 'x') for i in range(30)]
		def fp(targets, flags, host_timeout):
			self.fp.append((list(targets), list(flags)))
			return ''
		with mock.patch.dict(os.environ, {'CVENGINE_FULLSCAN_INVESTIGATE_MAX': '5'}):
			out = self.sweep(ports, fp=fp, pipeline=lambda d, n: None)
		inv = out['swept'][0]['investigation']
		self.assertEqual(inv['ports'], [2000, 2001, 2002, 2003, 2004])
		self.assertTrue(inv['capped'])
		self.assertEqual(self.fp[0][1][-1], '2000-2004')
		self.assertEqual(self.ip_obj.ports.filter(state='open').count(), 30)  # every port is still recorded

	def test_an_investigation_failure_still_advances_the_rotation(self):
		with mock.patch('cveFeed.fullscan.investigate', side_effect=RuntimeError('pipeline exploded')):
			out = self.sweep([(6379, 'redis')])
		self.assertEqual(out['swept'][0]['investigation'], {'error': 'investigation failed'})
		self.ip_obj.refresh_from_db()
		self.assertIsNotNone(self.ip_obj.full_scanned_at)
		self.assertEqual(self.ip_obj.full_scan_ports, 1)

	def test_a_failing_fingerprint_or_pipeline_is_not_fatal(self):
		def boom(*a, **k):
			raise RuntimeError('boom')
		out = self.sweep([(6379, 'redis')], fp=boom, pipeline=boom)
		inv = out['swept'][0]['investigation']
		self.assertIn('fingerprint_error', inv)
		self.assertEqual(inv['retested'], [])
		self.ip_obj.refresh_from_db()
		self.assertIsNotNone(self.ip_obj.full_scanned_at)

	def test_a_host_tested_within_the_ledger_window_is_not_tested_again(self):
		pipeline = mock.Mock()
		self.sweep([(22, 'ssh'), (6379, 'redis')], pipeline=pipeline)
		self.assertEqual(pipeline.call_count, 1)
		self.assertTrue(ServiceRun.objects.filter(service='retest', asset='www.fs.test').exists())
		IpAddress.objects.filter(pk=self.ip_obj.pk).update(full_scanned_at=None)
		self.sweep([(22, 'ssh'), (6379, 'redis'), (6380, 'redis')], pipeline=pipeline)
		self.assertEqual(pipeline.call_count, 1)  # the second sweep found 6380, but the host was tested minutes ago

	def test_without_an_injected_pipeline_the_retest_task_is_queued(self):
		with mock.patch('cveFeed.tasks.retest_hosts.delay') as delay:
			fullscan.run(runner=lambda t, f, h: xml('192.0.2.1', [(6379, 'redis')]), fingerprint_runner=self.fingerprint_runner())
		delay.assert_called_once_with(self.domain.id, ['www.fs.test'])


class SurfaceTests(FullScanBase):
	def test_the_host_serializer_shows_the_full_scan(self):
		from agentapi.services import _host
		self.ip('192.0.2.1', name='www.fs.test', scanned=timezone.now(), full_scan_ports=3)
		entry = _host(Subdomain.objects.get(name='www.fs.test'))['ips'][0]
		self.assertEqual(entry['full_scan_ports'], 3)
		self.assertTrue(entry['full_scanned_at'].startswith(str(timezone.now().year)))
		self.ip('192.0.2.2', name='b.fs.test')
		self.assertIsNone(_host(Subdomain.objects.get(name='b.fs.test'))['ips'][0]['full_scanned_at'])
