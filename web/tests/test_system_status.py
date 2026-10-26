from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import system_status
from agentapi.auth import create_token
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

	def test_a_healthy_instance_says_ok(self):
		healthy = dict(HEALTH, schedules=[{'name': 'x', 'next_due_state': 'estimated'}])
		_, data = self.run_status(self.t_root, health=healthy)
		self.assertEqual((data['overall'], data['problems']), ('ok', []))

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
		self.assertEqual(set(data['scanning']), {'paused', 'paused_by_update'})
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
