import json
import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import system_status
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed.models import ScanControl
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

NOW = timezone.now()


class FakeBroker:
	def __init__(self, waiting=None):
		self.waiting = waiting or {}

	def ping(self):
		return True

	def llen(self, name):
		return self.waiting.get(name, 0)

	def hlen(self, name):
		return 2


HEALTH = {'workers_state': 'responding', 'worker_note': 'ok', 'scheduler_note': 'n',
		  'workers': [{'worker': 'discovery_worker', 'queue': 'discovery_queue', 'responding': True, 'consuming': True, 'active': 1}],
		  'schedules': [{'name': 'cve-feed', 'next_due_state': 'estimated'}, {'name': 'late-task', 'next_due_state': 'past_due_unconfirmed'}],
		  'jobs': {'scans': {'pending': 1, 'running': 1}}, 'last_activity': {'running': None, 'done': None, 'failed': None}}
CLUSTER = {'store': 'redis', 'containers': [{'host': 'celery-1', 'memory': {'total_mb': 8000, 'used_mb': 3000, 'available_mb': 5000},
	'budget_mb': 6000, 'headroom_mb': 400, 'critical_mb': 240, 'age_seconds': 20, 'running': [{'label': 'nmap:x'}], 'waiting': [], 'memory_kills': []}]}


def patched(broker=None, health=None, cluster=None):
	return (mock.patch.object(system_status, '_broker_client', lambda: broker or FakeBroker({'discovery_queue': 3})),
			mock.patch('cveFeed.admin_api.scheduler_health', lambda request, actor: health or HEALTH),
			mock.patch('reNgine.resources.cluster_snapshot', lambda: cluster or CLUSTER))


class SystemStatusTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='S', slug='s-org')
		cls.pa = Project.objects.create(name='Alpha', slug='alpha', insert_date=NOW, org=org)
		cls.pb = Project.objects.create(name='Beta', slug='beta', insert_date=NOW, org=org)
		cls.da = Domain.objects.create(name='alpha.example', project=cls.pa, insert_date=NOW)
		cls.db = Domain.objects.create(name='beta.example', project=cls.pb, insert_date=NOW)
		Subdomain.objects.create(name='www.alpha.example', target_domain=cls.da)
		Subdomain.objects.create(name='www.beta.example', target_domain=cls.db)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=NOW, scan_status=1)
		ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=NOW, scan_status=-1)
		ScanHistory.objects.create(domain=cls.db, scan_type=engine, start_scan_date=NOW, scan_status=2)
		cls.member = User.objects.create_user('member', password='x')
		ProjectMembership.objects.create(user=cls.member, project=cls.pa, role='user')
		cls.root = User.objects.create_superuser('root', 'r@x.io', 'x')
		_, cls.t_member = create_token(cls.member, 'agent')
		_, cls.t_member_ro = create_token(cls.member, 'ro', read_only=True)
		_, cls.t_root = create_token(cls.root, 'root')

	def setUp(self):
		# the per-project cache is exercised by CountsCacheTests; here every call counts afresh
		patch = mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': '0'})
		patch.start()
		self.addCleanup(patch.stop)

	def get(self, token):
		return call(token, 'GET', '/api/v1/system/status')

	def run_status(self, token, **kw):
		a, b, c = patched(**kw)
		with a, b, c:
			return self.get(token)

	def test_it_requires_a_token(self):
		self.assertEqual(self.get(None)[0], 401)

	def test_a_member_sees_only_their_projects_and_no_server_internals(self):
		status, data = self.get(self.t_member)
		self.assertEqual(status, 200)
		self.assertEqual([p['slug'] for p in data['projects']], ['alpha'])
		self.assertIsNone(data['system'])
		self.assertIn('App Admin', data['system_note'])
		self.assertEqual(data['scope'], 'projects')
		self.assertEqual(data['totals']['projects'], 1)

	def test_counts_per_project(self):
		_, data = self.get(self.t_member)
		alpha = data['projects'][0]
		self.assertEqual((alpha['targets'], alpha['hosts']), (1, 1))
		self.assertEqual((alpha['scans']['running'], alpha['scans']['queued'], alpha['scans']['stalled']), (1, 1, 0))
		self.assertEqual(alpha['open_findings_total'], 0)
		self.assertEqual(set(alpha['open_findings']), {'critical', 'high', 'medium', 'low', 'info'})

	def test_wordpress_counts_are_per_project_and_say_why_hosts_were_not_scanned(self):
		from cveFeed.models import ProbeObservation

		def state(project, domain, host, name, **evidence):
			ProbeObservation.objects.create(project=project, domain=domain, host=host, probe='wpscan', kind='wordpress', product='WordPress',
				outcome='found' if name == 'scanned' else 'hidden', evidence={'state': name, **evidence})
		state(self.pa, self.da, 'www.alpha.example', 'scanned', findings=3)
		state(self.pa, self.da, 'blog.alpha.example', 'blocked', reason='the edge challenged the scanner')
		state(self.pb, self.db, 'www.beta.example', 'failed')
		_, data = self.get(self.t_member)
		self.assertEqual(data['projects'][0]['wordpress'], {'hosts': 2, 'scanned': 1, 'never_scanned': 1, 'reasons': {'blocked': 1}, 'thorough': {}})
		self.assertEqual([p['slug'] for p in data['projects']], ['alpha'])  # the other project's WordPress host is not counted or shown

	def test_an_app_admin_sees_every_project_and_the_infrastructure(self):
		status, data = self.run_status(self.t_root)
		self.assertEqual(status, 200)
		self.assertEqual(sorted(p['slug'] for p in data['projects']), ['alpha', 'beta'])
		self.assertEqual(data['totals']['hosts'], 2)
		self.assertEqual(data['scope'], 'instance')
		system = data['system']
		self.assertTrue(system['database']['ok'])
		self.assertTrue(system['broker']['ok'])
		self.assertEqual(system['queues']['waiting']['discovery_queue'], 3)
		self.assertEqual((system['queues']['waiting_total'], system['queues']['unacknowledged']), (3, 2))
		self.assertEqual(system['workers']['state'], 'responding')
		self.assertEqual(system['memory']['containers'][0]['available_mb'], 5000)
		self.assertGreater(system['disk']['total_mb'], 0)
		self.assertIn('cve_entries', system['feeds'])
		self.assertFalse(system['ai']['provider_enabled'])
		self.assertTrue(data['version'])

	def test_a_late_schedule_is_a_problem_and_a_queue_backlog_a_note(self):
		_, data = self.run_status(self.t_root)
		self.assertEqual(data['overall'], 'degraded')
		self.assertTrue(any('late-task' in p for p in data['problems']))
		self.assertTrue(any('waiting in the work queues' in n for n in data['notes']))

	def test_a_silent_beat_is_the_one_problem_instead_of_every_schedule_being_late(self):
		silent = dict(HEALTH, beat={'state': 'silent', 'seconds_since_tick': 900})
		_, data = self.run_status(self.t_root, health=silent)
		self.assertTrue(any('celery beat has not ticked for 15 minutes' in p for p in data['problems']))
		self.assertFalse(any('late-task' in p for p in data['problems']))
		self.assertEqual(data['system']['schedules']['beat']['state'], 'silent')

	def test_a_healthy_instance_says_ok(self):
		healthy = dict(HEALTH, schedules=[{'name': 'x', 'next_due_state': 'estimated'}])
		usage = type('Usage', (), {'total': 100 << 30, 'used': 40 << 30, 'free': 60 << 30})()  # not this machine's real disk
		with mock.patch.object(system_status.shutil, 'disk_usage', lambda path: usage):
			_, data = self.run_status(self.t_root, health=healthy)
		self.assertEqual((data['overall'], data['problems']), ('ok', []))

	def test_stale_nuclei_templates_are_a_problem_and_fresh_ones_report_their_age(self):
		import os
		import tempfile
		with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {'NUCLEI_TEMPLATES_DIR': root}), \
				mock.patch.object(system_status, '_tool_version', lambda argv: 'v-test'):
			marker = os.path.join(root, '.checksum')
			open(marker, 'w').close()
			_, data = self.run_status(self.t_root)
			tools = data['system']['tools']
			self.assertLess(tools['nuclei_templates']['age_hours'], 1)
			self.assertEqual(tools['versions']['nuclei'], 'v-test')
			self.assertFalse(any(p.startswith('nuclei templates') for p in data['problems']))
			old = timezone.now().timestamp() - 3 * 24 * 3600
			os.utime(marker, (old, old))
			_, data = self.run_status(self.t_root)
			self.assertTrue(any(p.startswith('nuclei templates: not refreshed for') for p in data['problems']))

	def test_template_files_that_have_not_changed_are_not_a_failure_while_the_refresh_keeps_succeeding(self):
		import os
		import tempfile
		recent = {'at': timezone.now().isoformat(), 'ok': True, 'result': 'Your nuclei-templates are up-to-date'}
		with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {'NUCLEI_TEMPLATES_DIR': root}), \
				mock.patch.object(system_status, '_tool_version', lambda argv: 'v-test'):
			marker = os.path.join(root, '.checksum')
			open(marker, 'w').close()
			old = timezone.now().timestamp() - 4 * 24 * 3600  # no release for four days: the files are as old, the refresh is fine
			os.utime(marker, (old, old))
			with mock.patch.object(system_status, '_template_refresh', lambda: recent):
				_, data = self.run_status(self.t_root)
			self.assertFalse(any(p.startswith('nuclei templates') for p in data['problems']), data['problems'])
			self.assertEqual(data['system']['tools']['nuclei_templates']['last_refresh']['result'], recent['result'])
			failed = dict(recent, ok=False, result='could not reach the template repository')
			with mock.patch.object(system_status, '_template_refresh', lambda: failed):
				_, data = self.run_status(self.t_root)
			self.assertTrue(any('the last refresh failed' in p and 'could not reach' in p for p in data['problems']), data['problems'])
			silent = dict(recent, at=(timezone.now() - timedelta(hours=50)).isoformat())
			with mock.patch.object(system_status, '_template_refresh', lambda: silent):
				_, data = self.run_status(self.t_root)
			self.assertTrue(any('no successful refresh for' in p for p in data['problems']), data['problems'])

	def test_the_version_is_the_version_line_not_a_warning_the_tool_printed_first(self):
		import subprocess
		out = ('WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not\n'
			   '[INF] Nuclei Engine Version: v3.11.1\n')
		system_status._VERSION_CACHE.clear()
		with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='', stderr=out)):
			self.assertEqual(system_status._tool_version(('nuclei', '-version')), '[INF] Nuclei Engine Version: v3.11.1')
		system_status._VERSION_CACHE.clear()
		with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='WARNING: only a warning\n', stderr='')):
			self.assertEqual(system_status._tool_version(('x', '-version')), 'WARNING: only a warning')
		system_status._VERSION_CACHE.clear()

	def test_the_refresh_task_records_what_it_found(self):
		import subprocess
		from django.core.cache import cache
		from cveFeed import tasks
		done = subprocess.CompletedProcess([], 0, stdout='[INF] Your nuclei-templates are up-to-date: v10.9.9\n', stderr='')
		with mock.patch('subprocess.run', return_value=done), mock.patch('cveFeed.activity.log'), \
				mock.patch('cveFeed.templategen.invalidate_template_index'):
			tasks.update_nuclei_templates()
		record = cache.get(system_status.TEMPLATE_REFRESH_KEY)
		self.assertTrue(record['ok'])
		self.assertIn('up-to-date', record['result'])
		cache.delete(system_status.TEMPLATE_REFRESH_KEY)

	def test_members_do_not_see_the_tool_versions(self):
		_, data = self.get(self.t_member)
		self.assertNotIn('tools', json.dumps(data))

	def test_a_probe_that_fails_is_reported_and_does_not_fail_the_answer(self):
		class Down(FakeBroker):
			def ping(self):
				raise ConnectionError('redis://user:secret@redis:6379 refused')
		status, data = self.run_status(self.t_root, broker=Down())
		self.assertEqual(status, 200)
		self.assertEqual(data['overall'], 'degraded')
		self.assertEqual(data['system']['broker'], {'error': 'ConnectionError'})
		self.assertTrue(any(p.startswith('broker:') for p in data['problems']))
		self.assertNotIn('secret', str(data))  # the error text itself is never returned
		self.assertTrue(data['system']['database']['ok'])  # the other probes still ran

	def test_workers_that_do_not_answer_are_a_problem(self):
		degraded = dict(HEALTH, workers_state='degraded', worker_note='Missing or unconfirmed required queue consumers: classic_worker',
						schedules=[])
		_, data = self.run_status(self.t_root, health=degraded)
		self.assertTrue(any('classic_worker' in p for p in data['problems']))

	def test_low_memory_and_a_stale_report_are_problems(self):
		low = {'store': 'redis', 'containers': [dict(CLUSTER['containers'][0], memory={'total_mb': 8000, 'used_mb': 7900, 'available_mb': 100},
													 age_seconds=900)]}
		_, data = self.run_status(self.t_root, cluster=low, health=dict(HEALTH, schedules=[]))
		text = ' '.join(data['problems'])
		self.assertIn('below its critical level', text)
		self.assertIn('has not reported', text)

	def test_low_disk_is_a_problem(self):
		usage = mock.Mock(total=100 << 20, used=95 << 20, free=5 << 20)
		a, b, c = patched()
		with a, b, c, mock.patch('agentapi.system_status.shutil.disk_usage', lambda path: usage):
			_, data = self.get(self.t_root)
		self.assertEqual(data['system']['disk']['free_percent'], 5.0)
		self.assertTrue(any(p.startswith('disk:') for p in data['problems']))

	def test_a_pause_and_a_running_update_are_notes_not_problems(self):
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'reason': 'maintenance window', 'actor': 'bill'})
		with mock.patch('cveFeed.updater.read_phase', lambda: {'phase': 'draining', 'detail': 'waiting', 'scans_running': 2, 'changed_at': 1}):
			_, data = self.get(self.t_root)
		self.assertTrue(data['scanning']['paused'])
		self.assertEqual(data['scanning']['reason'], 'maintenance window')
		self.assertEqual(data['update']['phase'], 'draining')
		self.assertTrue(any('paused: maintenance window' in n for n in data['notes']))
		self.assertTrue(any('update is in progress' in n for n in data['notes']))

	def test_a_member_learns_that_scanning_is_paused_but_not_who_or_why_or_instance_counts(self):
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'reason': 'maintenance window', 'actor': 'bill',
														   'last_error': 'boom'})
		with mock.patch('cveFeed.updater.read_phase', lambda: {'phase': 'draining', 'detail': 'waiting', 'scans_running': 2, 'changed_at': 1}):
			_, data = self.get(self.t_member)
		self.assertTrue(data['scanning']['paused'])
		self.assertEqual(set(data['scanning']), {'paused', 'paused_by_update', 'scanner'})
		self.assertEqual(data['update'], {'phase': 'draining'})
		blob = str(data)
		for secret in ('maintenance window', 'bill', 'boom', 'waiting'):
			self.assertNotIn(secret, blob)

	def test_a_read_only_token_may_read_it(self):
		self.assertEqual(self.get(self.t_member_ro)[0], 200)

	def test_it_is_an_mcp_tool_and_not_a_write(self):
		from agentapi import mcp
		entry = next(t for t in mcp.TOOLS if t[0] == 'get_system_status')
		self.assertFalse(entry[4])
		error, data = tool_call(self.t_member, 'get_system_status')
		self.assertFalse(error)
		self.assertEqual(data['scope'], 'projects')
		a, b, c = patched()
		with a, b, c:
			error, data = tool_call(self.t_root, 'get_system_status')
		self.assertFalse(error)
		self.assertEqual(data['scope'], 'instance')

	def test_no_address_or_credential_is_returned(self):
		_, data = self.run_status(self.t_root)
		text = str(data).lower()
		for word in ('redis://', 'postgres://', 'password', 'secret', 'api_key'):
			self.assertNotIn(word, text)


class WorkConductorStatusTests(TestCase):
	def setUp(self):
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		org = Org.objects.create(name='W', slug='w')
		self.project = Project.objects.create(name='W', slug='ws', insert_date=NOW, org=org)
		self.domain = Domain.objects.create(name='w.test', project=self.project, insert_date=NOW)
		self.user = User.objects.create_superuser('wroot', 'w@x.test', 'x')

	def problems(self):
		problems, notes = [], []
		with mock.patch.dict('os.environ', {'CVENGINE_WORK_DEPTH': '3'}):
			out = system_status._system(self.user, problems, notes)
		return out, problems

	def test_no_work_with_targets_is_a_problem_and_a_queued_scan_clears_it(self):
		out, problems = self.problems()
		self.assertEqual((out['work']['running'], out['work']['queued'], out['work']['targets']), (0, 0, True))
		self.assertTrue([p for p in problems if p.startswith('work: nothing is running or queued')])
		ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=-1, start_scan_date=NOW, results_dir='/x')
		_, problems = self.problems()
		self.assertFalse([p for p in problems if p.startswith('work:')])

	def test_a_paused_instance_is_not_a_work_problem(self):
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
		_, problems = self.problems()
		self.assertFalse([p for p in problems if p.startswith('work:')])


class SentinelStatusTests(TestCase):
	"""system.sentinels: an App Admin (or an agent with only MCP access) sees Sentinel registration counts, how many are
	live, scan-stage queue depth and the last day's completed/failed/expired SentinelTasks, without a separate query per
	Sentinel, and a high failure/expiry share is surfaced as a problem."""

	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Sen', slug='sen-status-org')
		cls.project = Project.objects.create(name='Sen', slug='sen-status-p', insert_date=NOW, org=org)
		cls.root = User.objects.create_superuser('sen-root', 'r@x.io', 'x')
		_, cls.t_root = create_token(cls.root, 'root')

	def make_agent(self, name, status='active', last_seen=None):
		owner = User.objects.create_user(f'owner-{name}', password='x')
		token, _raw = create_token(owner, f'{name}-token')
		return Agent.objects.create(token=token, name=name, kind='scanner', status=status,
								   scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, last_seen=last_seen)

	def make_task(self, agent, status, finished_at=None, error=''):
		return SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': ['192.0.2.9']},
										   host='h.example', ips=['192.0.2.9'], agent=agent, status=status,
										   finished_at=finished_at, error=error)

	def run_status(self):
		a, b, c = patched()
		with a, b, c:
			return call(self.t_root, 'GET', '/api/v1/system/status')

	def test_registered_counts_and_live_window(self):
		self.make_agent('live-one', status='active', last_seen=timezone.now())
		self.make_agent('stale-one', status='active', last_seen=timezone.now() - timedelta(hours=1))
		self.make_agent('pending-one', status='pending')
		_, data = self.run_status()
		sentinels = data['system']['sentinels']
		self.assertEqual(sentinels['registered']['active'], 2)
		self.assertEqual(sentinels['registered']['pending'], 1)
		self.assertEqual(sentinels['live'], 1)

	def test_queue_depth_and_last_day_outcomes(self):
		agent = self.make_agent('worker-one', last_seen=timezone.now())
		self.make_task(agent, 'queued')
		self.make_task(agent, 'running')
		self.make_task(agent, 'done', finished_at=timezone.now())
		self.make_task(agent, 'done', finished_at=timezone.now() - timedelta(days=3))  # outside the 24h window
		_, data = self.run_status()
		sentinels = data['system']['sentinels']
		self.assertEqual(sentinels['queue'], {'queued': 1, 'claimed': 0, 'running': 1})
		self.assertEqual(sentinels['finished_24h']['done'], 1)

	def test_a_high_failure_share_is_a_problem_with_recent_errors_listed(self):
		agent = self.make_agent('flaky-one', last_seen=timezone.now())
		now = timezone.now()
		for _ in range(4):
			self.make_task(agent, 'failed', finished_at=now, error='nmap: connection refused')
		self.make_task(agent, 'done', finished_at=now)
		status, data = self.run_status()
		self.assertEqual(status, 200)
		self.assertEqual(data['overall'], 'degraded')
		self.assertTrue(any('sentinels:' in p for p in data['problems']))
		errors = data['system']['sentinels']['recent_errors']
		self.assertEqual(len(errors), 4)
		self.assertEqual(errors[0]['sentinel'], 'flaky-one')
		self.assertIn('connection refused', errors[0]['error'])

	def test_a_healthy_sentinel_fleet_is_not_a_problem(self):
		# The default HEALTH/CLUSTER fixture (patched()) carries an unrelated past-due schedule, so this checks only
		# that the Sentinel fleet itself contributes no problem, not that the whole snapshot is 'ok'.
		agent = self.make_agent('reliable-one', last_seen=timezone.now())
		for _ in range(5):
			self.make_task(agent, 'done', finished_at=timezone.now())
		status, data = self.run_status()
		self.assertEqual(status, 200)
		self.assertFalse([p for p in data['problems'] if p.startswith('sentinels:')])


class CountsCacheTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='C', slug='c-org')
		cls.project = Project.objects.create(name='Cache', slug='cache-p', insert_date=NOW, org=org)
		cls.user = User.objects.create_user('cacher', password='x')
		ProjectMembership.objects.create(user=cls.user, project=cls.project, role='user')

	def setUp(self):
		from django.core.cache import cache
		self.cache = cache
		self.key = f'sysstatus:project:{self.user.pk}:{self.project.id}'
		self.cache.delete(self.key)
		self.addCleanup(self.cache.delete, self.key)
		self.ctx = mock.Mock(user=self.user)

	def rows(self, seconds, row=None):
		with mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': seconds}), \
				mock.patch.object(system_status, '_project_row', return_value=row or {'slug': 'cache-p'}) as built:
			return system_status._projects(self.ctx), built

	def test_a_second_call_inside_the_window_reuses_the_counts(self):
		first, built = self.rows('60')
		self.assertEqual(built.call_count, 1)
		second, built = self.rows('60', row={'slug': 'changed'})
		self.assertEqual(built.call_count, 0)
		self.assertEqual(second, first)

	def test_zero_turns_the_cache_off(self):
		self.rows('0')
		self.assertIsNone(self.cache.get(self.key))
		_, built = self.rows('0')
		self.assertEqual(built.call_count, 1)

	def test_a_bad_value_falls_back_to_the_default(self):
		with mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': 'soon'}):
			self.assertEqual(system_status._cache_seconds(), system_status.STATUS_CACHE_SECONDS)
