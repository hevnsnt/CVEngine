import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import activity, discovery
from cveFeed.models import AgentActivity, CVEEntry, DiscoveryEvent
from dashboard.models import Org, Project, UserProfile
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for

EVENTS = [
	{'type': 'DNS_NAME', 'id': 'D1', 'data': 'example.test', 'host': 'example.test', 'module': 'SEED', 'resolved_hosts': ['192.0.2.1'], 'parent': 'S'},
	{'type': 'DNS_NAME', 'id': 'D2', 'data': 'www.example.test', 'host': 'www.example.test', 'module': 'crt', 'resolved_hosts': ['192.0.2.2'], 'parent': 'D1'},
	{'type': 'OPEN_TCP_PORT', 'id': 'P1', 'data': 'www.example.test:443', 'host': 'www.example.test', 'module': 'shodan_idb', 'parent': 'D2'},
	{'type': 'TECHNOLOGY', 'id': 'T1', 'data': None, 'host': 'www.example.test', 'module': 'shodan_idb', 'parent': 'D2',
	 'data_json': {'host': 'www.example.test', 'technology': 'nginx'}},
]


class DiscoveryTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='D', slug='d')
		self.project = Project.objects.create(name='P', slug='pd', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		patcher = mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False)  # no real DNS in tests
		self.resolves_to_blocked = patcher.start()
		self.addCleanup(patcher.stop)

	def test_domain_resolving_to_a_blocked_address_is_never_handed_to_bbot(self):
		scan = self._scan()
		self.resolves_to_blocked.return_value = True
		stream = mock.Mock(side_effect=AssertionError('bbot must not start'))
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, stream=stream)
		self.assertEqual(out['status'], discovery.FAILED)
		self.assertIn('resolves to a loopback, link-local or internal address', out['error'])
		stream.assert_not_called()

	def _scan(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			scan = discovery.start_discovery(self.domain)
		queued.assert_called_once_with(scan.id, 'standard')  # standard is the default
		return scan

	def test_a_rejected_key_becomes_an_activity_line_naming_the_service(self):
		from cveFeed.models import AgentActivity
		from dashboard.models import ApiCredential
		ApiCredential.objects.create(project=self.project, service='virustotal', value={'api_key': 'vt-bad'})
		scan = self._scan()

		def stream(targets, problems=None, **k):
			problems += [('virustotal', 'Error with API (401 Unauthorized'), ('crt', 'unrelated module without a key')]
			return iter(EVENTS)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, stream=stream)
		lines = list(AgentActivity.objects.filter(message__contains='key was not accepted').values_list('message', 'status'))
		self.assertEqual(len(lines), 1)  # the module without a configured key is not blamed on a key
		self.assertIn('VirusTotal', lines[0][0])
		self.assertIn('401', lines[0][0])
		self.assertEqual(lines[0][1], 'failed')

	def test_streaming_discovery_persists_assets_events_and_activity(self):
		scan = self._scan()
		self.assertEqual(scan.scan_status, -1)  # queued until a worker starts it
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay') as correlate:
			out = discovery.run_discovery(scan.id, stream=lambda *a, **k: iter(EVENTS))
		self.assertEqual(out['status'], discovery.SUCCESS)
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 2)
		self.assertEqual(sorted(Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True)),
			['example.test', 'www.example.test'])
		www = Subdomain.objects.get(scan_history=scan, name='www.example.test')
		self.assertEqual([ip.address for ip in www.ip_addresses.all()], ['192.0.2.2'])
		self.assertEqual([p.number for p in www.ip_addresses.first().ports.all()], [443])  # port linked via the host
		kinds = list(DiscoveryEvent.objects.filter(scan=scan).values_list('type', flat=True))
		self.assertEqual(kinds, ['DNS_NAME', 'DNS_NAME', 'OPEN_TCP_PORT', 'TECHNOLOGY'])
		child = DiscoveryEvent.objects.get(scan=scan, label='www.example.test')
		self.assertEqual((child.parent_host, child.module), ('example.test', 'crt'))
		correlate.assert_called_once_with(scan_history_id=scan.id)
		messages = list(AgentActivity.objects.filter(kind='discovery').order_by('id').values_list('message', 'status'))
		self.assertEqual(messages[-1], ('Discovery of example.test finished: 2 hosts found', 'done'))

	def test_flushes_in_batches_so_the_graph_fills_while_running(self):
		scan = self._scan()
		seen_midway = []

		def stream(*a, **k):
			for i in range(discovery.FLUSH_EVERY_EVENTS + 5):
				yield {'type': 'DNS_NAME', 'id': f'X{i}', 'data': f'h{i}.example.test', 'host': f'h{i}.example.test', 'module': 'crt', 'parent': 'S'}
				if i == discovery.FLUSH_EVERY_EVENTS:  # a batch has been flushed before the stream ends
					seen_midway.append(Subdomain.objects.filter(scan_history=scan).count())
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, stream=stream)
		self.assertGreaterEqual(seen_midway[0], discovery.FLUSH_EVERY_EVENTS)
		self.assertEqual(Subdomain.objects.filter(scan_history=scan).count(), discovery.FLUSH_EVERY_EVENTS + 5)

	def test_several_port_rows_with_the_same_number_do_not_break_persistence(self):
		Port.objects.create(number=443, product='nginx', version='1.18')
		Port.objects.create(number=443, product='apache', version='2.4')  # enrichment stores one row per product
		scan = self._scan()
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, stream=lambda *a, **k: iter(EVENTS))
		self.assertEqual(out['status'], discovery.SUCCESS, out)
		# each IP gets its own row: the other hosts' nginx and apache rows are never adopted (their product would bleed in)
		self.assertEqual(Port.objects.filter(number=443).count(), 3)
		self.assertEqual(Port.objects.filter(number=443, product='').count(), 1)

	def test_failure_ends_the_scan_visibly_never_stuck_running(self):
		scan = self._scan()

		def boom(*a, **k):
			yield EVENTS[0]
			raise RuntimeError('bbot exploded')
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay') as correlate:
			out = discovery.run_discovery(scan.id, stream=boom)
		self.assertEqual(out['status'], discovery.FAILED)
		scan.refresh_from_db()
		self.assertEqual((scan.scan_status, scan.error_message), (0, 'bbot exploded'))
		correlate.assert_not_called()
		self.assertEqual(AgentActivity.objects.filter(kind='discovery').order_by('-id').first().status, 'failed')

	def test_a_bbot_crash_after_partial_results_keeps_them_and_the_scan_goes_on_without_counting_as_a_finished_discovery(self):
		from cveFeed.models import ServiceRun
		from reNgine.bbot import BbotProcessError
		scan = self._scan()

		def partial(*args, **kwargs):
			yield EVENTS[0]
			raise BbotProcessError('bbot exited with status 1 after producing partial results')

		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, stream=partial)
		# the hosts it found are the scan's (a failed scan's hosts are not the domain's current inventory), the discovery stage says it was cut short,
		# and it is not coverage another target may reuse
		self.assertEqual(out['status'], discovery.SUCCESS)
		self.assertIn('partial results', out['partial'])
		self.assertTrue(Subdomain.objects.filter(scan_history=scan, name='example.test').exists())
		self.assertTrue(DiscoveryEvent.objects.filter(scan=scan, label='example.test').exists())
		stage = ScanActivity.objects.get(scan_of=scan, name='bbot_discovery')
		self.assertEqual(stage.status, discovery.FAILED)
		self.assertIn('partial results', stage.error_message)
		self.assertFalse(ServiceRun.objects.filter(service='bbot', scan=scan, status='done').exists())

	def test_a_bbot_failure_with_nothing_found_still_fails_the_scan(self):
		from reNgine.bbot import BbotProcessError
		scan = self._scan()

		def nothing(*args, **kwargs):
			raise BbotProcessError('bbot exited with status 1 before producing any results')
			yield
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, stream=nothing)
		self.assertEqual(out['status'], discovery.FAILED)

	def test_deep_run_stopped_for_memory_is_retried_as_standard_and_keeps_what_it_found(self):
		from reNgine.resources import MemoryKill
		scan = self._scan()
		modes = []

		def stream(targets, mode='deep', **k):
			modes.append(mode)
			if mode == 'deep':
				yield EVENTS[0]
				raise MemoryKill('bbot-deep was stopped because the container ran low on memory')
			yield from EVENTS
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, mode='deep', stream=stream)
		self.assertEqual((out['status'], modes), (discovery.SUCCESS, ['deep', 'standard']))
		self.assertTrue(AgentActivity.objects.filter(message__contains='ran out of memory; retrying as standard').exists())

	def test_standard_run_stopped_for_memory_falls_back_to_passive(self):
		from reNgine.resources import MemoryKill
		scan = self._scan()
		modes = []

		def stream(targets, mode='standard', **k):
			modes.append(mode)
			if mode == 'standard':
				raise MemoryKill('bbot-standard was stopped because the container ran low on memory')
			yield from EVENTS
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, mode='standard', stream=stream)
		self.assertEqual((out['status'], modes), (discovery.SUCCESS, ['standard', 'passive']))
		self.assertTrue(AgentActivity.objects.filter(message__contains='ran out of memory; retrying as passive').exists())

	def test_deep_falls_all_the_way_through_standard_to_passive(self):
		from reNgine.resources import MemoryKill
		scan = self._scan()
		modes = []

		def stream(targets, mode='deep', **k):
			modes.append(mode)
			if mode != 'passive':
				raise MemoryKill('low memory')
			yield from EVENTS
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, mode='deep', stream=stream)
		self.assertEqual((out['status'], modes), (discovery.SUCCESS, ['deep', 'standard', 'passive']))
		from cveFeed.models import ServiceRun
		self.assertFalse(ServiceRun.objects.filter(service='bbot-deep').exists())  # it did not finish as a deep run

	def test_a_finished_deep_run_is_recorded_for_the_weekly_sweep_and_a_standard_one_is_not(self):
		from cveFeed.models import ServiceRun
		scan = self._scan()
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, mode='standard', stream=lambda *a, **k: iter(EVENTS))
			self.assertFalse(ServiceRun.objects.filter(service='bbot-deep').exists())
			discovery.run_discovery(scan.id, mode='deep', stream=lambda *a, **k: iter(EVENTS))
		self.assertEqual(list(ServiceRun.objects.filter(service='bbot-deep').values_list('asset', flat=True)), [self.domain.name])

	def test_a_kernel_oom_kill_status_9_is_treated_the_same_way(self):
		scan = self._scan()
		modes = []

		def stream(targets, mode='deep', **k):
			modes.append(mode)
			if mode == 'deep':
				error = RuntimeError('bbot exited with status -9')
				error.returncode = -9
				raise error
			yield from EVENTS
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, mode='deep', stream=stream)
		self.assertEqual((out['status'], modes), (discovery.SUCCESS, ['deep', 'standard']))

	def test_passive_run_that_still_runs_out_of_memory_fails_visibly(self):
		from reNgine.resources import MemoryKill
		scan = self._scan()
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			out = discovery.run_discovery(scan.id, mode='passive', stream=lambda *a, **k: (_ for _ in ()).throw(MemoryKill('low memory')))
		self.assertEqual(out['status'], discovery.FAILED)


class ScreenshotPersistenceTests(TestCase):
	def setUp(self):
		import tempfile
		org = Org.objects.create(name='S', slug='s-shot')
		self.project = Project.objects.create(name='P', slug='p-shot', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.bbot_home = tempfile.mkdtemp()
		self.media_root = tempfile.mkdtemp()
		self.addCleanup(lambda: __import__('shutil').rmtree(self.bbot_home, ignore_errors=True))
		self.addCleanup(lambda: __import__('shutil').rmtree(self.media_root, ignore_errors=True))

	def _scan(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			return discovery.start_discovery(self.domain)

	def _plant_screenshot(self, scan_name, rel_path, content=b'fake-jpeg-bytes'):
		import os
		full = os.path.join(self.bbot_home, scan_name, os.path.dirname(rel_path))
		os.makedirs(full, exist_ok=True)
		with open(os.path.join(full, os.path.basename(rel_path)), 'wb') as f:
			f.write(content)

	def test_persist_screenshots_copies_file_and_sets_subdomain_path(self):
		import os
		scan = self._scan()
		Subdomain.objects.create(scan_history=scan, name='www.example.test')
		rel_path = 'gowitness/screenshots/https---www.example.test-443-.jpeg'
		self._plant_screenshot('scanname1', rel_path)
		with mock.patch('cveFeed.discovery.BBOT_SCANS_HOME', self.bbot_home), self.settings(MEDIA_ROOT=self.media_root):
			discovery.persist_screenshots(scan, [{'host': 'www.example.test', 'rel_path': rel_path, 'url': 'x'}], 'scanname1')
		sub = Subdomain.objects.get(scan_history=scan, name='www.example.test')
		self.assertEqual(sub.screenshot_path, f'example.test_{scan.id}/screenshots/https---www.example.test-443-.jpeg')
		dest = os.path.join(self.media_root, sub.screenshot_path)
		self.assertTrue(os.path.isfile(dest))
		with open(dest, 'rb') as f:
			self.assertEqual(f.read(), b'fake-jpeg-bytes')

	def test_missing_source_file_is_skipped_not_fatal(self):
		scan = self._scan()
		Subdomain.objects.create(scan_history=scan, name='www.example.test')
		with mock.patch('cveFeed.discovery.BBOT_SCANS_HOME', self.bbot_home), self.settings(MEDIA_ROOT=self.media_root):
			discovery.persist_screenshots(scan, [{'host': 'www.example.test', 'rel_path': 'nope.jpeg', 'url': ''}], 'scanname1')
		self.assertEqual(Subdomain.objects.get(scan_history=scan, name='www.example.test').screenshot_path, None)

	def test_unknown_host_or_missing_scan_name_is_skipped(self):
		scan = self._scan()
		rel_path = 'gowitness/screenshots/x.jpeg'
		self._plant_screenshot('scanname1', rel_path)
		with mock.patch('cveFeed.discovery.BBOT_SCANS_HOME', self.bbot_home), self.settings(MEDIA_ROOT=self.media_root):
			discovery.persist_screenshots(scan, [{'host': 'nobody.example.test', 'rel_path': rel_path, 'url': ''}], 'scanname1')
			discovery.persist_screenshots(scan, [{'host': 'www.example.test', 'rel_path': rel_path, 'url': ''}], '')
		self.assertEqual(Subdomain.objects.filter(screenshot_path__isnull=False).count(), 0)

	def test_full_discovery_run_wires_a_screenshot_end_to_end(self):
		scan_events = [
			{'type': 'SCAN', 'id': 'SCAN:1', 'data': None, 'data_json': {'name': 'scanname1'}},
			{'type': 'DNS_NAME', 'id': 'D1', 'data': 'www.example.test', 'host': 'www.example.test', 'module': 'SEED', 'parent': 'SCAN:1'},
			{'type': 'WEBSCREENSHOT', 'id': 'WS1', 'data': None, 'host': 'www.example.test', 'module': 'gowitness',
			 'data_json': {'path': 'gowitness/screenshots/shot.jpeg', 'url': 'https://www.example.test/'}, 'parent': 'D1'},
		]
		self._plant_screenshot('scanname1', 'gowitness/screenshots/shot.jpeg')
		scan = self._scan()
		with mock.patch('cveFeed.discovery.BBOT_SCANS_HOME', self.bbot_home), self.settings(MEDIA_ROOT=self.media_root), \
		     mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, stream=lambda *a, **k: iter(scan_events))
		sub = Subdomain.objects.get(scan_history=scan, name='www.example.test')
		self.assertEqual(sub.screenshot_path, f'example.test_{scan.id}/screenshots/shot.jpeg')


class DiscoveryApiCredentialWiringTests(TestCase):
	"""A project's (or its organization's) Shodan/Censys/etc. keys must reach the actual bbot invocation,
	not just sit in the database."""

	def setUp(self):
		self.org = Org.objects.create(name='K', slug='k')
		self.project = Project.objects.create(name='K', slug='pk2', insert_date=timezone.now(), org=self.org)
		self.domain = Domain.objects.create(name='keyed.test', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def test_configured_keys_are_passed_as_extra_args_to_the_stream(self):
		from dashboard.models import ApiCredential
		ApiCredential.objects.create(org=self.org, service='shodan', value={'api_key': 'sk-live'})
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		seen_kwargs = {}

		def capturing_stream(targets, **kwargs):
			seen_kwargs.update(kwargs)
			return iter(EVENTS)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, stream=capturing_stream)
		self.assertIn('-c', seen_kwargs.get('extra_args', []))
		self.assertIn('modules.shodan_dns.api_key=sk-live', seen_kwargs.get('extra_args', []))

	def test_no_keys_configured_means_no_extra_args(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		seen_kwargs = {}

		def capturing_stream(targets, **kwargs):
			seen_kwargs.update(kwargs)
			return iter(EVENTS)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, stream=capturing_stream)
		self.assertEqual(seen_kwargs.get('extra_args'), [])


class ActivityTests(TestCase):
	def test_step_runs_then_settles_and_failure_is_recorded(self):
		with activity.step('feed', 'Reading') as handle:
			running = AgentActivity.objects.get(message='Reading')
			self.assertEqual(running.status, 'running')
			handle.done_message = 'Read 3 CVEs'
		done = AgentActivity.objects.get(pk=running.pk)
		self.assertEqual((done.status, done.message), ('done', 'Read 3 CVEs'))
		self.assertIsNotNone(done.finished_at)
		with self.assertRaises(ValueError):
			with activity.step('confirm', 'Thinking'):
				raise ValueError('nope')
		self.assertEqual(AgentActivity.objects.get(kind='confirm').status, 'failed')

	def test_log_never_raises(self):
		with mock.patch('cveFeed.models.AgentActivity.objects') as objects:
			objects.create.side_effect = RuntimeError('db down')
			self.assertIsNone(activity.log('feed', 'x'))

	def test_pipeline_steps_are_narrated(self):
		from cveFeed.autofire import fire_for_cve
		from cveFeed.models import CVEMatch
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='af.test', project=project, insert_date=timezone.now())
		sub = Subdomain.objects.create(name='www.af.test', target_domain=domain)
		ip = IpAddress.objects.create(address='192.0.2.9')
		sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=80, product='nginx', version='1.18.0'))
		cve = CVEEntry.objects.create(cve_id='CVE-2099-5', kev=True, cvss=9.8, published_at=timezone.now(),
			affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		calls = []
		fire_for_cve(cve, 1, 3, test_dispatcher=lambda *a: calls.append(a))
		texts = [m for m, in AgentActivity.objects.order_by('id').values_list('message')]
		self.assertTrue(any('is FIRE: looking for exposed hosts' in t or 'identified 1 target' in t for t in texts))
		self.assertTrue(any('Testing 1 host(s) of af.test for CVE-2099-5' in t for t in texts))
		self.assertEqual(calls[0][2], project.id)  # project travels to the template step
		self.assertEqual(AgentActivity.objects.get(cve_id='CVE-2099-5', kind='target').status, 'done')


class WelcomeApiTests(TestCase):
	def setUp(self):
		self.root = User.objects.create_superuser('wroot', 'w@x.io', 'x')
		self.c = client_for(self.root)

	def call(self, method, path, body=None):
		fn = getattr(self.c, method.lower())
		r = fn(f'/cve/api/welcome/{path}', json.dumps(body) if body is not None else None, content_type='application/json') if method != 'GET' else fn(f'/cve/api/welcome/{path}')
		return r.status_code, r.json()

	def test_wizard_renames_the_starter_org_and_project_in_place(self):
		Org.objects.get_or_create(slug='default', defaults={'name': 'Default'})
		Project.objects.create(name='Default', slug='default', insert_date=timezone.now(), org=Org.objects.get(slug='default'))
		self.assertEqual(self.call('GET', 'state')[1]['org']['named'], False)
		self.assertEqual(self.call('POST', 'org', {'name': 'x'})[0], 400)  # too short
		status, s = self.call('POST', 'org', {'name': 'Acme Security'})
		self.assertEqual((status, s['org']['name']), (200, 'Acme Security'))
		self.assertEqual(Org.objects.filter(slug='default').count(), 1)  # renamed, not duplicated
		status, s = self.call('POST', 'project', {'name': 'Production'})
		self.assertEqual((s['project']['name'], s['project']['slug']), ('Production', 'production'))
		self.assertEqual(Project.objects.count(), 1)

	def test_first_target_requires_authorization_and_starts_discovery(self):
		Org.objects.get_or_create(slug='default', defaults={'name': 'Default'})
		self.call('POST', 'org', {'name': 'Acme'})
		self.call('POST', 'project', {'name': 'Prod'})
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.assertEqual(self.call('POST', 'target', {'value': 'example.org'})[0], 400)  # not confirmed
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, r = self.call('POST', 'target', {'value': 'example.org', 'authorized': True})
		self.assertEqual((status, r['created']), (200, ['example.org']))
		self.assertTrue(r['scan_id'])
		queued.assert_called_once()
		self.assertEqual(self.call('POST', 'target', {'value': 'not a target', 'authorized': True})[0], 400)
		self.call('POST', 'finish')
		self.assertTrue(UserProfile.objects.get(user=self.root).onboarded)
		self.assertTrue(self.call('GET', 'state')[1]['onboarded'])


	def _wizard_project(self):
		Org.objects.get_or_create(slug='default', defaults={'name': 'Default'})
		self.call('POST', 'org', {'name': 'Acme'})
		self.call('POST', 'project', {'name': 'Prod'})

	def test_a_missing_engine_is_a_retryable_message_and_the_retry_starts_discovery(self):
		self._wizard_project()
		status, r = self.call('POST', 'target', {'value': 'example.org', 'authorized': True})
		self.assertEqual(status, 503)
		self.assertIn('try again', r['error'])
		self.assertTrue(Domain.objects.filter(name='example.org').exists())  # the target was kept
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			status, r = self.call('POST', 'target', {'value': 'example.org', 'authorized': True})
			self.assertEqual((status, r['created'], r['already_exists']), (200, [], ['example.org']))
			self.assertTrue(r['scan_id'])
			again = self.call('POST', 'target', {'value': 'example.org', 'authorized': True})[1]
		self.assertEqual(again['scan_id'], r['scan_id'])  # still the one scan: starting is safe to repeat
		queued.assert_called_once()

	def test_keys_are_saved_without_ever_being_returned(self):
		from dashboard.models import ApiCredential
		self._wizard_project()
		status, r = self.call('POST', 'keys', {'keys': {'shodan': ' SECRETSHODAN ', 'virustotal': '', 'github': 'not-offered'}})
		self.assertEqual((status, r), (200, {'saved': ['shodan']}))
		cred = ApiCredential.objects.get(service='shodan')
		self.assertEqual(cred.value, {'api_key': 'SECRETSHODAN'})
		self.assertEqual(cred.project.slug, 'prod')
		self.assertFalse(ApiCredential.objects.filter(service__in=['virustotal', 'github']).exists())
		self.assertNotIn('SECRETSHODAN', json.dumps(self.call('GET', 'state')[1]))

	def test_saving_no_keys_is_fine_and_a_non_superuser_is_refused(self):
		self._wizard_project()
		self.assertEqual(self.call('POST', 'keys', {'keys': {}}), (200, {'saved': []}))
		other = client_for(User.objects.create_user('plain', 'p@x.io', 'x'))
		self.assertEqual(other.post('/cve/api/welcome/keys', '{}', content_type='application/json').status_code, 403)


NUCLEI_LINES = [
	{'template': 'http/technologies/nginx-version.yaml', 'template-id': 'nginx-version', 'type': 'http',
	 'info': {'name': 'nginx version', 'severity': 'info', 'description': 'nginx detected', 'tags': ['tech', 'nginx']},
	 'host': 'https://www.example.test', 'matched-at': 'https://www.example.test/', 'matcher-name': 'v'},
	{'template': 'http/cves/CVE-2099-1.yaml', 'template-id': 'CVE-2099-1', 'type': 'http',
	 'info': {'name': 'Example RCE', 'severity': 'critical', 'description': 'bad',
	          'classification': {'cve-id': ['CVE-2099-1'], 'cve_id': ['CVE-2099-1'], 'cvss-score': 9.8}, 'reference': ['https://x']},
	 'host': 'www.example.test:8443', 'matched-at': 'https://www.example.test:8443/x'},
]


class NucleiStageTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='N', slug='n')
		self.project = Project.objects.create(name='P', slug='pn', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def test_pure_target_building_and_host_parsing(self):
		from cveFeed import nuclei_scan as ns
		self.assertEqual(ns.build_targets({'b.test', 'a.test'}, {'192.0.2.1'}, {('a.test', 443), ('a.test', 8080), ('a.test', 80)}),
			['a.test', 'b.test', '192.0.2.1', 'a.test:8080'])  # default ports add nothing; other ports become host:port
		self.assertEqual(ns.host_of({'host': 'https://Www.Example.test:8443/x'}), 'www.example.test')
		self.assertEqual(ns.host_of({'host': 'www.example.test:8443'}), 'www.example.test')
		self.assertEqual(ns.host_of({'host': 'www.example.test'}), 'www.example.test')
		self.assertIn('info', ns.SEVERITIES.split(','))  # info severity is scanned

	def _pipeline(self, events=EVENTS, **overrides):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		kwargs = dict(stream=lambda *a, **k: iter(events), light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
			nmap_runner=lambda *a, **k: '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', db_exposure_checks={}, provider=None,
			route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
		kwargs.update(overrides)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'):
			return scan, discovery.run_pipeline(scan.id, **kwargs)

	def test_a_bbot_crash_part_way_still_runs_the_later_stages_on_what_it_found(self):
		from reNgine.bbot import BbotProcessError
		ran = []

		def crash_after_one(*a, **k):
			yield EVENTS[0]
			raise BbotProcessError('bbot exited with status 1 after producing partial results')

		def nmap(targets, flags, timeout):
			ran.append(list(targets))
			return ''
		scan, out = self._pipeline(stream=crash_after_one, nmap_runner=nmap)
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 2)  # the hosts it found are the domain's current inventory
		self.assertIn('bbot_discovery', out['failed_stages'])  # and the cut-short discovery is on record
		self.assertIn('bbot_discovery', scan.error_message)
		self.assertTrue(Subdomain.objects.filter(scan_history=scan, name='example.test').exists())
		self.assertTrue(ran, 'nmap did not run on what bbot found')

	def test_nuclei_results_persist_including_info(self):
		from startScan.models import Vulnerability
		scan, out = self._pipeline(targeted_stream=lambda path, **k: iter(NUCLEI_LINES))
		self.assertEqual(out['nuclei_targeted']['findings'], 2)
		vulns = {v.name: v for v in Vulnerability.objects.filter(scan_history=scan)}
		self.assertEqual((vulns['nginx version'].severity, vulns['Example RCE'].severity), (0, 4))  # info is kept
		self.assertEqual(vulns['Example RCE'].subdomain.name, 'www.example.test')
		self.assertEqual([c.name for c in vulns['Example RCE'].cve_ids.all()], ['CVE-2099-1'])
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 2)  # finished only after the targeted pass
		names = list(AgentActivity.objects.order_by('id').values_list('message', flat=True))
		self.assertTrue(any('Nuclei confirmed Example RCE (critical) on www.example.test' in m for m in names))
		self.assertTrue(any(m.startswith('Nuclei finished example.test: 2 findings') for m in names))
		# running the blanket runner again does not duplicate findings
		from cveFeed import nuclei_scan
		again = nuclei_scan.run_nuclei(scan.id, stream=lambda path: iter(NUCLEI_LINES))
		self.assertEqual(again['findings'], 0)
		self.assertEqual(Vulnerability.objects.filter(scan_history=scan).count(), 2)

	def test_scan_stays_running_until_the_targeted_pass_is_done_and_its_errors_do_not_fail_discovery(self):
		from startScan.models import ScanActivity

		def boom(path, **kwargs):
			raise RuntimeError('nuclei crashed')
			yield
		scan, out = self._pipeline(targeted_stream=boom)
		self.assertEqual(out['nuclei_targeted']['error'], 'nuclei crashed')
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 2)  # discovery results stand
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='nuclei_targeted_scan').status, 0)

	def test_stages_run_in_order_and_the_light_pass_comes_before_the_targeted_one(self):
		from startScan.models import ScanActivity
		calls = []
		scan, out = self._pipeline(light_stream=lambda path, **k: calls.append('light') or iter([]),
			targeted_stream=lambda path, **k: calls.append('targeted') or iter([]))
		self.assertEqual(list(ScanActivity.objects.filter(scan_of=scan).order_by('id').values_list('name', flat=True)),
			['bbot_discovery', 'nmap_scan', 'db_exposure_scan', 'nuclei_light_scan', 'route_auth_scan', 'version_probes', 'wpscan', 'cve_correlation', 'nuclei_targeted_scan', 'triage', 'asset_changes'])
		self.assertEqual(calls, ['light', 'targeted'])
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='triage').title, 'AI triage and validation')
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='nuclei_light_scan').title, 'Nuclei HTTP and technology pass')
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='nuclei_targeted_scan').title, 'AI-targeted nuclei scan')
		self.assertEqual(set(ScanActivity.objects.filter(scan_of=scan).values_list('status', flat=True)), {2})

	MYSQL_XML = """<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="3306">
		<state state="open"/><service name="mysql" product="MySQL" version="8.0"/></port></ports></host>
		<runstats><finished exit="success"/></runstats></nmaprun>"""
	WORDPRESS = {'template-id': 'tech-detect', 'matcher-name': 'WordPress', 'host': 'https://www.example.test',
	             'info': {'name': 'Wappalyzer Technology Detection', 'severity': 'info'}}

	def test_the_targeted_pass_gets_tags_from_nmap_and_the_light_pass_and_works_without_an_ai(self):
		from startScan.models import Subdomain, Technology
		seen = []

		def targeted(path, **kwargs):
			seen.append((sorted(kwargs['tags']), open(path).read().split(), kwargs.get('severities')))
			return iter([])
		scan, out = self._pipeline(nmap_runner=lambda *a, **k: self.MYSQL_XML, light_stream=lambda path, **k: iter([self.WORDPRESS]),
			targeted_stream=targeted)
		self.assertEqual(seen, [(['cms', 'mysql', 'nginx', 'wordpress'], ['www.example.test', 'www.example.test:3306'], None)])
		self.assertEqual(out['nuclei_light']['techs'], {'www.example.test': ['WordPress']})
		self.assertEqual(sorted(t.name for t in Subdomain.objects.get(scan_history=scan, name='www.example.test').technologies.all()),
			['WordPress', 'nginx'])  # the light pass writes onto the same Technology rows bbot fills
		names = list(AgentActivity.objects.order_by('id').values_list('message', flat=True))
		self.assertTrue(any(m.startswith('nuclei targeted scan of www.example.test:') and '(from bbot, nmap 3306 MySQL 8.0, light pass)' in m
			for m in names), names)

	def test_an_ai_reply_naming_unknown_tags_or_severities_is_dropped(self):
		class Provider:
			def complete(self, system, user):
				return '{"0": {"tags": ["php", "not-a-real-tag", "x; rm -rf /"], "severities": ["high", "bogus"]}}'
		seen = []

		def targeted(path, **kwargs):
			seen.append((sorted(kwargs['tags']), kwargs.get('severities')))
			return iter([])
		self._pipeline(provider=Provider(), targeted_stream=targeted)
		self.assertEqual(seen, [(['nginx', 'php'], ['high'])])  # the static tag stays, the unknown ones are gone

	def test_a_fire_cve_match_runs_its_template_test(self):
		from cveFeed import nuclei_scan
		from cveFeed.models import CVEEntry, CVEMatch
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=EngineType.objects.first(), start_scan_date=timezone.now(), scan_status=1)
		sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='www.example.test')
		hot = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, cvss=9.8, published_at=timezone.now())
		cold = CVEEntry.objects.create(cve_id='CVE-2099-8', cvss=2.0, published_at=timezone.now())
		for cve in (hot, cold):
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, scan_history=scan, confidence=0.9, ai_verdict='affected')
		calls = []
		out = nuclei_scan.run_targeted_nuclei(scan.id, stream=lambda path, **k: iter([]), provider=None,
			cve_runner=lambda cve, hosts, provider=None, project=None: calls.append((cve.cve_id, hosts, project)) or
				{'results': [{'host': hosts[0], 'vulnerable': True}]})
		self.assertEqual(calls, [('CVE-2099-7', ['www.example.test'], self.project.id)])  # fire and smoke only
		self.assertEqual((out['cves'], out['vulnerable']), (1, [('CVE-2099-7', 'www.example.test')]))
		again = nuclei_scan.run_targeted_nuclei(scan.id, stream=lambda path, **k: iter([]), provider=None,
			cve_runner=lambda *a, **k: self.fail('a host checked for this CVE inside the TTL is not checked again'))
		self.assertEqual(again['cve_hosts'], 0)

	def test_bbot_findings_become_scanner_findings(self):
		from startScan.models import Vulnerability
		events = EVENTS + [{'type': 'VULNERABILITY', 'id': 'V1', 'data': None, 'host': 'www.example.test', 'module': 'baddns', 'parent': 'D2',
			'data_json': {'host': 'www.example.test', 'severity': 'HIGH', 'description': 'Subdomain takeover: dangling CNAME', 'url': 'https://www.example.test'}}]
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
			discovery.run_discovery(scan.id, stream=lambda *a, **k: iter(events))
		v = Vulnerability.objects.get(scan_history=scan)
		self.assertEqual((v.name, v.severity, v.source), ('Subdomain takeover', 3, 'bbot'))


class OneDiscoveryPerTargetTests(TestCase):
	"""Many copies of one target's pipeline ran at once on a small server and starved each other of memory."""

	def setUp(self):
		org = Org.objects.create(name='D', slug='d-one')
		project = Project.objects.create(name='Dp', slug='dp-one', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='once.example', project=project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def test_a_second_start_returns_the_scan_already_running(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			first = discovery.start_discovery(self.domain)
			again = discovery.start_discovery(self.domain)
		self.assertEqual(first.id, again.id)
		self.assertEqual(queued.call_count, 1)  # nothing was queued the second time

	def test_a_finished_scan_does_not_block_the_next(self):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			first = discovery.start_discovery(self.domain)
			first.scan_status = discovery.SUCCESS
			first.save()
			second = discovery.start_discovery(self.domain)
		self.assertNotEqual(first.id, second.id)
		self.assertEqual(queued.call_count, 2)

	def test_only_one_pipeline_runs_per_target(self):
		from startScan.models import ScanHistory
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			holder = discovery.start_discovery(self.domain)
		holder.scan_status = discovery.SUCCESS  # so a second scan row can be created for the same domain
		holder.save()
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			other = discovery.start_discovery(self.domain)
		ScanHistory.objects.filter(pk=holder.id).update(scan_status=discovery.RUNNING)  # the holder is the scan whose pipeline is running
		ran = []
		with discovery.domain_lock(self.domain.id, holder.id) as mine:
			if mine is not True:
				self.skipTest('no Redis to hold the lock in this environment')
			out = discovery.run_pipeline(other.id, stream=lambda *a, **k: ran.append(1) or iter([]))
			same = discovery.run_pipeline(holder.id, stream=lambda *a, **k: ran.append(1) or iter([]))
		self.assertEqual(out['status'], 'skipped')
		self.assertEqual(same['status'], 'duplicate')  # the same task delivered twice leaves the first one alone
		self.assertEqual(ran, [])  # neither started bbot
		self.assertEqual(ScanHistory.objects.get(pk=other.id).scan_status, 3)  # aborted, with the reason recorded
		self.assertIn('already running', ScanHistory.objects.get(pk=other.id).error_message)


class RedeliveredDiscoveryTests(TestCase):
	"""A message the queue gives back after a worker died finds the dead worker's lock still held: it asks again later instead of being acked."""

	def test_a_duplicate_for_the_same_scan_is_asked_again_after_the_lock_would_have_expired(self):
		from celery.exceptions import Retry
		from cveFeed.tasks import DUPLICATE_RETRIES, run_bbot_discovery
		task = run_bbot_discovery._get_current_object()
		task.push_request(id='abc', retries=0, called_directly=False)
		self.addCleanup(task.pop_request)
		with mock.patch('cveFeed.discovery.run_pipeline', return_value={'scan_id': 7, 'status': 'duplicate'}), mock.patch('startScan.models.ScanHistory.objects'):
			with mock.patch.object(task, 'retry', side_effect=Retry()) as retry:
				with self.assertRaises(Retry):
					task.run(7)
			retry.assert_called_once_with(countdown=discovery.LOCK_TTL + 15, max_retries=DUPLICATE_RETRIES)
			task.request.retries = DUPLICATE_RETRIES  # it kept finding the lock: a live twin, so the message is let go
			with mock.patch.object(task, 'retry', side_effect=AssertionError('retried forever')):
				self.assertEqual(task.run(7)['status'], 'duplicate')


class NucleiLedgerTests(TestCase):
	"""Nuclei runs once per host per project inside its TTL; a repeat scan reuses the findings instead."""

	def setUp(self):
		org = Org.objects.create(name='NL', slug='nl')
		self.p1 = Project.objects.create(name='P1', slug='nl1', insert_date=timezone.now(), org=org)
		self.p2 = Project.objects.create(name='P2', slug='nl2', insert_date=timezone.now(), org=org)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		# no real DNS: a name that is slow to answer counts as blocked, which dropped a host from the chunk test on a loaded runner
		patcher = mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False)
		patcher.start()
		self.addCleanup(patcher.stop)

	def _scan(self, project, name, host='shared.example.test'):
		domain = Domain.objects.create(name=name, project=project, insert_date=timezone.now())
		scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1)
		Subdomain.objects.create(scan_history=scan, target_domain=domain, name=host)
		return scan

	def _lines(self, host):
		return [{'template': 'x.yaml', 'template-id': 'x', 'type': 'http',
		         'info': {'name': 'Example RCE', 'severity': 'high', 'description': 'bad'},
		         'host': host, 'matched-at': f'https://{host}/x'}]

	def test_second_scan_in_a_project_never_streams_the_shared_host_and_gets_its_findings(self):
		from cveFeed import nuclei_scan
		from startScan.models import Vulnerability
		first, second = self._scan(self.p1, 'one.test'), self._scan(self.p1, 'two.test')
		seen = []

		def stream(path, **kwargs):
			seen.append(open(path).read().split())
			return iter(self._lines('shared.example.test'))
		# stands in for the real scanner, so the approved-template snapshot is stubbed too (no template library on disk here)
		with mock.patch('cveFeed.nuclei_scan.stream_nuclei', stream), \
				mock.patch('cveFeed.nuclei_scan.approved_templates', return_value=('/tmp/approved-templates', 'test-rev', 1)):
			nuclei_scan.run_nuclei(first.id, stream=stream)
			out = nuclei_scan.run_nuclei(second.id, stream=stream)
		self.assertEqual(seen, [['shared.example.test']])  # the second run had nothing left to scan
		self.assertEqual(out['reused'], 1)
		copied = Vulnerability.objects.get(scan_history=second)
		self.assertEqual((copied.name, copied.target_domain.name, copied.subdomain.scan_history_id), ('Example RCE', 'two.test', second.id))
		self.assertTrue(AgentActivity.objects.filter(message__contains='reused 1 finding(s) on 1 host(s) scanned in the last 24h').exists())

	def test_a_different_project_scans_the_same_host_again(self):
		from cveFeed import nuclei_scan
		first, other = self._scan(self.p1, 'one.test'), self._scan(self.p2, 'other.test')
		seen = []

		def stream(path, **kwargs):
			seen.append(open(path).read().split())
			return iter([])
		nuclei_scan.run_nuclei(first.id, stream=stream)
		nuclei_scan.run_nuclei(other.id, stream=stream)
		self.assertEqual(seen, [['shared.example.test'], ['shared.example.test']])

	def test_targets_run_in_chunks_and_each_chunk_is_recorded(self):
		from cveFeed import ledger, nuclei_scan
		scan = self._scan(self.p1, 'one.test')
		for i in range(nuclei_scan.NUCLEI_CHUNK + 5):
			Subdomain.objects.create(scan_history=scan, target_domain=scan.domain, name=f'h{i}.example.test')
		sizes = []

		def stream(path, **kwargs):
			sizes.append(len(open(path).read().split()))
			return iter([])
		nuclei_scan.run_nuclei(scan.id, stream=stream)
		self.assertEqual(sizes, [nuclei_scan.NUCLEI_CHUNK, 6])
		self.assertEqual(len(ledger.fresh('nuclei', [f'h{i}.example.test' for i in range(105)], self.p1)), 105)


class BbotCoverageTests(TestCase):
	"""A target under an already-discovered parent skips bbot and takes the parent's hosts."""

	def setUp(self):
		org = Org.objects.create(name='BC', slug='bc')
		self.project = Project.objects.create(name='P', slug='pbc', insert_date=timezone.now(), org=org)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def _parent(self):
		from cveFeed import ledger
		domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2)
		www = Subdomain.objects.create(scan_history=scan, target_domain=domain, name='www.example.test')
		ip = IpAddress.objects.create(address='192.0.2.9')
		www.ip_addresses.add(ip)
		Subdomain.objects.create(scan_history=scan, target_domain=domain, name='mail.example.test')
		ledger.record('bbot', ['example.test'], self.project, scan)
		return scan

	def _run(self, name):
		domain = Domain.objects.create(name=name, project=self.project, insert_date=timezone.now())
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(domain)
		bbot, nmap, nuclei = mock.Mock(side_effect=AssertionError('bbot must not run')), [], []

		def nmap_runner(targets, flags, timeout):
			nmap.append(list(targets))
			return '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'):
			out = discovery.run_pipeline(scan.id, stream=bbot, light_stream=lambda path, **k: nuclei.append(open(path).read().split()) or iter([]),
				targeted_stream=lambda path, **k: iter([]), nmap_runner=nmap_runner, db_exposure_checks={}, provider=None,
				route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
		return scan, out, bbot, nmap, nuclei

	def test_a_subdomain_of_a_discovered_target_never_calls_bbot_and_is_seeded(self):
		parent = self._parent()
		scan, out, bbot, nmap, nuclei = self._run('www.example.test')
		bbot.assert_not_called()
		self.assertEqual(out['covered_by'], parent.id)
		self.assertEqual(list(Subdomain.objects.filter(scan_history=scan).values_list('name', 'target_domain__name')),
			[('www.example.test', 'www.example.test')])  # only the hosts under this target, owned by it
		self.assertEqual([ip.address for ip in Subdomain.objects.get(scan_history=scan).ip_addresses.all()], ['192.0.2.9'])
		self.assertEqual(nmap, [['192.0.2.9']])  # one pass: the later stages still run, on the seeded host
		self.assertEqual(nuclei, [['www.example.test', '192.0.2.9']])
		from startScan.models import ScanActivity
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='bbot_discovery').status, discovery.SUCCESS)
		self.assertTrue(AgentActivity.objects.filter(message__contains=f'covered by scan #{parent.id} of example.test').exists())
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 2)

	def test_an_expired_or_unrelated_discovery_does_not_cover(self):
		from cveFeed.models import ServiceRun
		from datetime import timedelta
		self._parent()
		ServiceRun.objects.update(finished_at=timezone.now() - timedelta(days=30))
		domain = Domain.objects.create(name='www.example.test', project=self.project, insert_date=timezone.now())
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(domain)
		self.assertIsNone(discovery.covering_scan(scan))
		ServiceRun.objects.update(finished_at=timezone.now())
		other = Domain.objects.create(name='other.test', project=self.project, insert_date=timezone.now())
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			self.assertIsNone(discovery.covering_scan(discovery.start_discovery(other)))


class QueuedScanTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='Q', slug='q-one')
		self.project = Project.objects.create(name='Qp', slug='qp-one', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='queued.example', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def test_a_new_scan_is_queued_and_running_only_once_the_pipeline_starts(self):
		from startScan.models import ScanActivity
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		self.assertEqual(scan.scan_status, discovery.QUEUED)
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='bbot_discovery').status, discovery.QUEUED)
		seen = []

		def stream(*a, **k):
			seen.append((ScanHistory.objects.get(pk=scan.id).scan_status, ScanActivity.objects.get(scan_of=scan, name='bbot_discovery').status))
			return iter([])
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'), \
				mock.patch('cveFeed.tasks.run_hygiene_task.delay'):
			discovery.run_pipeline(scan.id, stream=stream, light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
				nmap_runner=lambda *a, **k: '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', db_exposure_checks={}, provider=None, route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
		self.assertEqual(seen, [(discovery.RUNNING, discovery.RUNNING)])

	def test_a_queued_scan_blocks_a_duplicate_whatever_its_age_but_a_stale_running_one_does_not(self):
		from datetime import timedelta
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
			first = discovery.start_discovery(self.domain)
			ScanHistory.objects.filter(pk=first.id).update(start_scan_date=timezone.now() - timedelta(hours=5))
			self.assertEqual(discovery.start_discovery(self.domain).id, first.id)
			ScanHistory.objects.filter(pk=first.id).update(scan_status=discovery.RUNNING)  # a restart left it "running"
			second = discovery.start_discovery(self.domain)
		self.assertNotEqual(second.id, first.id)
		self.assertEqual(queued.call_count, 2)


class IpTargetTests(TestCase):
	"""bbot finds subdomains; a bare IP has none, so it gets a reverse lookup and its certificate names instead."""

	def setUp(self):
		org = Org.objects.create(name='IP', slug='ip-one')
		self.project = Project.objects.create(name='Ip', slug='ip-p', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='203.0.113.5', project=self.project, insert_date=timezone.now())
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)

	def _run(self, **overrides):
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		bbot, nmap = mock.Mock(side_effect=AssertionError('bbot must not run for an IP')), []

		def runner(targets, flags, timeout):
			nmap.append(list(targets))
			return '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
		kwargs = dict(stream=bbot, light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]), nmap_runner=runner,
			db_exposure_checks={}, provider=None, route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''},
			ip_lookups={'ptr': lambda ip: ['host-5.example.net'], 'certificate': lambda ip: ['shop.example.org', 'www.example.org']})
		kwargs.update(overrides)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'):
			out = discovery.run_pipeline(scan.id, **kwargs)
		return scan, out, bbot, nmap

	def test_an_ip_target_never_calls_bbot_has_its_ip_attached_and_goes_to_nmap(self):
		scan, out, bbot, nmap = self._run()
		bbot.assert_not_called()
		sub = Subdomain.objects.get(scan_history=scan)
		self.assertEqual((sub.name, [ip.address for ip in sub.ip_addresses.all()]), ('203.0.113.5', ['203.0.113.5']))
		self.assertEqual(nmap, [['203.0.113.5']])  # a single fingerprint pass
		scan.refresh_from_db()
		self.assertEqual(scan.scan_status, 2)

	def test_names_are_kept_as_events_on_the_host_and_not_added_as_targets(self):
		scan, out, _bbot, _nmap = self._run()
		names = {(e.module, e.label) for e in DiscoveryEvent.objects.filter(scan=scan, type='DNS_NAME', host='203.0.113.5')}
		self.assertEqual(names, {('ptr', 'host-5.example.net'), ('tls-san', 'shop.example.org'), ('tls-san', 'www.example.org')})
		self.assertEqual(list(Domain.objects.values_list('name', flat=True)), ['203.0.113.5'])  # may be out of scope: shown, not scanned
		self.assertEqual(sorted(out['names']), ['host-5.example.net', 'shop.example.org', 'www.example.org'])

	def test_failing_lookups_do_not_stop_the_pipeline(self):
		def boom(ip):
			raise OSError('refused')
		scan, out, _bbot, nmap = self._run(ip_lookups={'ptr': boom, 'certificate': boom})
		self.assertEqual(out['status'], discovery.SUCCESS)
		self.assertEqual(len(nmap), 1)

	def test_certificate_sweep_skips_ip_targets(self):
		from cveFeed.tasks import watch_certificates_all
		named = Domain.objects.create(name='named.example', project=self.project, insert_date=timezone.now())
		with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async') as queued, \
				mock.patch('cveFeed.ledger.sweep_claim', return_value=True), \
				mock.patch('cveFeed.ct_queue._client', return_value=None):  # the real claim and markers outlive the test, in Redis
			out = watch_certificates_all()
		self.assertEqual(out['queued'], 1)
		self.assertEqual(queued.call_args[1]['args'], [named.id])


class DiscoveryCountsTests(TestCase):
	def test_counts_are_live_numbers_for_the_followed_scan(self):
		from tests.test_tenancy import client_for
		from django.contrib.auth.models import User
		from dashboard.models import ProjectMembership
		org = Org.objects.create(name='C', slug='c-one')
		project = Project.objects.create(name='Cp', slug='cp-one', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='counts.example', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1)
		a, b = IpAddress.objects.create(address='192.0.2.1', os_guess=''), IpAddress.objects.create(address='192.0.2.2', os_guess='')
		for i, ips in enumerate(([a], [a, b], [b])):
			sub = Subdomain.objects.create(scan_history=scan, target_domain=domain, name=f'h{i}.counts.example')
			sub.ip_addresses.add(*ips)
		for ip, numbers in ((a, (22, 80)), (b, (80, 443))):  # ports are rows per IP
			for n in numbers:
				ip.ports.add(Port.objects.create(number=n))
		user = User.objects.create_user('countsuser', password='x')
		ProjectMembership.objects.create(user=user, project=project, role='user')
		d = client_for(user).get(f'/cve/api/discovery?scan={scan.id}').json()
		self.assertEqual(d['counts'], {'hosts': 3, 'ips': 2, 'ports': 4})
		self.assertEqual(d['scan']['error'], '')
		scan.scan_status, scan.error_message = 0, 'bbot exited with code 2'
		scan.save()
		d = client_for(user).get(f'/cve/api/discovery?scan={scan.id}').json()
		self.assertEqual((d['scan']['status'], d['scan']['error']), (0, 'bbot exited with code 2'))  # the badge shows why on hover

	def test_counts_total_every_live_host_not_only_the_followed_scan(self):
		"""The graph drawn above the ticker is the whole project's live map (every host a completed scan or rescan has
		found so far), not just the scan being followed, so the counts below it must total the same picture; otherwise
		a rescan that adds one host reads as "1 host" under a graph showing everything found to date."""
		from cveFeed.discovery import HOST_PIPELINE_TASK
		from tests.test_tenancy import client_for
		from django.contrib.auth.models import User
		from dashboard.models import ProjectMembership
		org = Org.objects.create(name='D', slug='d-one')
		project = Project.objects.create(name='Dp', slug='dp-one', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='total.example', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		full = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
		old = Subdomain.objects.create(scan_history=full, target_domain=domain, name='old.total.example')
		old.ip_addresses.add(IpAddress.objects.create(address='192.0.2.9', os_guess=''))
		rescan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(),
		                                    scan_status=2, tasks=[HOST_PIPELINE_TASK])
		new = Subdomain.objects.create(scan_history=rescan, target_domain=domain, name='new.total.example')
		new.ip_addresses.add(IpAddress.objects.create(address='192.0.2.10', os_guess=''))
		user = User.objects.create_user('totaluser', password='x')
		ProjectMembership.objects.create(user=user, project=project, role='user')
		d = client_for(user).get(f'/cve/api/discovery?scan={rescan.id}&project=dp-one').json()
		self.assertEqual(d['counts'], {'hosts': 2, 'ips': 2, 'ports': 0})  # old.total.example counts too, not only the followed rescan's own row


class BbotUrlTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='U', slug='u')
		self.project = Project.objects.create(name='P', slug='pu', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='url.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1, tasks=[],
			results_dir='x')
		self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id, 'subdomain_id': None, 'subscan_id': None}
		mock.patch('reNgine.tasks.geo_localize.delay').start()
		self.addCleanup(mock.patch.stopall)

	def persist(self, urls, names=('www.url.test',)):
		from reNgine import bbot as bbot_lib
		from reNgine.tasks import persist_bbot_result
		persist_bbot_result(bbot_lib.BbotResult(subdomains=set(names), urls=set(urls)), ctx=self.ctx)

	def test_a_url_event_with_a_status_tag_becomes_an_endpoint_and_fills_the_root_host_fields(self):
		from reNgine import bbot as bbot_lib
		from startScan.models import EndPoint
		result = bbot_lib.parse_output([json.dumps({'type': 'URL', 'id': 'U1', 'data': 'https://www.url.test/', 'host': 'www.url.test',
			'module': 'httpx', 'tags': ['status-200', 'in-scope'], 'parent': 'S'})])
		self.assertEqual(result.urls, {('https://www.url.test/', 200)})
		self.persist(result.urls)
		endpoint = EndPoint.objects.get(scan_history=self.scan)
		self.assertEqual((endpoint.http_url, endpoint.http_status, endpoint.source, endpoint.target_domain_id),
			('https://www.url.test/', 200, 'bbot', self.domain.id))
		sub = Subdomain.objects.get(scan_history=self.scan, name='www.url.test')
		self.assertEqual((sub.http_url, sub.http_status), ('https://www.url.test/', 200))
		self.persist(result.urls)  # a repeat adds nothing
		self.assertEqual(EndPoint.objects.filter(scan_history=self.scan).count(), 1)

	def test_a_deep_path_does_not_become_the_host_url_and_unknown_hosts_are_skipped(self):
		from startScan.models import EndPoint
		self.persist({('https://www.url.test/admin', 403), ('https://other.example.net/', 200)})
		self.assertEqual(list(EndPoint.objects.values_list('http_url', flat=True)), ['https://www.url.test/admin'])
		self.assertFalse(Subdomain.objects.get(name='www.url.test').http_url)

	def test_the_per_scan_cap_holds(self):
		from reNgine import tasks
		from startScan.models import EndPoint
		urls = {(f'https://www.url.test/p{i}', 200) for i in range(8)}
		with mock.patch.object(tasks, 'MAX_BBOT_URLS_PER_SCAN', 5):
			self.persist(urls)
			self.persist({('https://www.url.test/more', 200)})
		self.assertEqual(EndPoint.objects.filter(scan_history=self.scan).count(), 5)
