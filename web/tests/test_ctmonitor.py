import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import ctmonitor
from cveFeed.models import AgentActivity, DiscoveryEvent
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for


def _reset_slots():
	ctmonitor._local['next'] = 0.0
	client = ctmonitor._redis()
	if client is not None:
		client.delete(ctmonitor._SLOT_KEY)


def setUpModule():
	# the real lookups wait 1.5 to 2.5 seconds between calls; the tests of everything else must not
	global _gap
	_gap = mock.patch.object(ctmonitor, 'MIN_GAP', (0, 0))
	_gap.start()
	global _pipeline
	_pipeline = mock.patch('cveFeed.tasks.host_pipeline.delay')  # a CT find queues the new-hosts pipeline: not on the real broker
	_pipeline.start()
	_reset_slots()


def tearDownModule():
	_gap.stop()
	_pipeline.stop()
	_reset_slots()


class ParseCtEntriesTests(TestCase):
	def test_extracts_in_scope_names_and_strips_wildcards(self):
		entries = [
			{'name_value': 'www.example.com\n*.example.com'},
			{'name_value': 'api.example.com'},
			{'name_value': 'unrelated-example.com.evil.net'},   # not a subdomain of example.com
			{'name_value': 'example.com.au'},                   # different TLD, must not match
			{'name_value': 'EXAMPLE.COM'},                       # the apex itself, case-insensitive
			{'name_value': 'not a hostname at all !!'},
		]
		self.assertEqual(ctmonitor.parse_ct_entries(entries, 'example.com'),
			{'www.example.com', 'example.com', 'api.example.com'})

	def test_empty_or_malformed_input(self):
		self.assertEqual(ctmonitor.parse_ct_entries([], 'example.com'), set())
		self.assertEqual(ctmonitor.parse_ct_entries([{'name_value': ''}], 'example.com'), set())


class FetchCtNamesTests(TestCase):
	def test_network_failure_returns_empty_set_not_an_exception(self):
		import requests
		with mock.patch('requests.get', side_effect=requests.ConnectionError('down')):
			self.assertEqual(ctmonitor.fetch_ct_names('example.com'), set())

	def test_non_json_response_returns_empty_set(self):
		resp = mock.Mock(); resp.raise_for_status.return_value = None; resp.iter_content.return_value = [b'<html>not json']
		with mock.patch('requests.get', return_value=resp):
			self.assertEqual(ctmonitor.fetch_ct_names('example.com'), set())

	def test_parses_a_real_shaped_response(self):
		resp = mock.Mock()
		resp.raise_for_status.return_value = None
		resp.iter_content.return_value = [json.dumps([{'name_value': 'www.example.com'}, {'name_value': 'mail.example.com\nwebmail.example.com'}]).encode()]
		with mock.patch('requests.get', return_value=resp) as get:
			names = ctmonitor.fetch_ct_names('example.com')
		self.assertEqual(names, {'www.example.com', 'mail.example.com', 'webmail.example.com'})
		self.assertEqual(get.call_args.kwargs['params'], {'q': '%.example.com', 'output': 'json'})
		self.assertTrue(get.call_args.kwargs['stream'])

	def test_a_reply_over_the_size_cap_is_refused_unread(self):
		resp = mock.Mock(); resp.raise_for_status.return_value = None
		resp.iter_content.side_effect = lambda size: iter([b'[' + b' ' * 40] * 3)
		with mock.patch('requests.get', return_value=resp), mock.patch.object(ctmonitor, 'MAX_BYTES', 100):
			self.assertEqual(ctmonitor.fetch_ct_names('example.com'), set())
			self.assertIsNone(ctmonitor._fetch('example.com', sleep=lambda s: None))
		resp.close.assert_called()


class RunCtWatchTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.project = Project.objects.create(name='C', slug='ctp', insert_date=now, org=Org.objects.create(name='C', slug='c'))
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
		Subdomain.objects.create(target_domain=self.domain, name='example.test')  # already known
		self.user = User.objects.create_user('ctuser', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.project, role='audit')

	def test_only_genuinely_new_hosts_are_recorded(self):
		fetch = lambda name: {'example.test', 'new.example.test', 'also-new.example.test'}
		result = ctmonitor.run_ct_watch(self.domain.id, fetch=fetch)
		self.assertEqual(result, {'checked': 3, 'new': 2})
		names = set(Subdomain.objects.filter(target_domain=self.domain).values_list('name', flat=True))
		self.assertEqual(names, {'example.test', 'new.example.test', 'also-new.example.test'})
		new_sub = Subdomain.objects.get(name='new.example.test')
		self.assertTrue(new_sub.is_imported_subdomain)
		event = DiscoveryEvent.objects.get(host='new.example.test')
		self.assertEqual((event.scan, event.domain_id, event.module, event.parent_host), (None, self.domain.id, 'ct-monitor', 'example.test'))
		msg = AgentActivity.objects.filter(kind='discovery', message__icontains='Certificate transparency').first()
		self.assertIsNotNone(msg)
		self.assertIn('2 new hosts', msg.message)

	def test_nothing_new_is_a_quiet_no_op(self):
		result = ctmonitor.run_ct_watch(self.domain.id, fetch=lambda name: {'example.test'})
		self.assertEqual(result, {'checked': 1, 'new': 0})
		self.assertFalse(AgentActivity.objects.filter(kind='discovery', message__icontains='Certificate transparency').exists())

	def test_rerunning_does_not_recreate_or_re_announce_the_same_host(self):
		fetch = lambda name: {'example.test', 'steady.example.test'}
		ctmonitor.run_ct_watch(self.domain.id, fetch=fetch)
		self.assertEqual(ctmonitor.run_ct_watch(self.domain.id, fetch=fetch), {'checked': 2, 'new': 0})
		self.assertEqual(Subdomain.objects.filter(target_domain=self.domain, name='steady.example.test').count(), 1)
		self.assertEqual(AgentActivity.objects.filter(kind='discovery', message__icontains='steady').count(), 1)

	def test_new_hosts_show_up_on_the_project_graph_with_no_scan_attached(self):
		ctmonitor.run_ct_watch(self.domain.id, fetch=lambda name: {'example.test', 'graphed.example.test'})
		g = client_for(self.user).get('/cve/api/graph').json()
		self.assertNotIn('graphed.example.test', {n['label'] for n in g['nodes']})  # a name that has not resolved is not a live system
		from startScan.models import IpAddress
		Subdomain.objects.get(name='graphed.example.test').ip_addresses.add(IpAddress.objects.create(address='192.0.2.77', os_guess=''))
		from cveFeed import views
		views.clear_stats_cache()  # the graph's version is kept a few seconds per scope; a bump (or the passing of the seconds) shows the change
		g = client_for(self.user).get('/cve/api/graph').json()
		self.assertIn('graphed.example.test', {n['label'] for n in g['nodes']})  # once it resolves it appears, with no scan attached


class AddTargetSubscribesToCtWatchTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.project = Project.objects.create(name='S', slug='ctsub', insert_date=now, org=Org.objects.create(name='S', slug='s'))
		self.user = User.objects.create_user('ctsubuser', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.project, role='user')

	def test_adding_a_domain_queues_a_ct_watch_immediately(self):
		from agentapi.services import Ctx, add_target
		with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async') as queued, \
				mock.patch('cveFeed.ct_queue._client', return_value=None):
			add_target(Ctx(user=self.user), 'ctsub', 'newly-added.test')
		queued.assert_called_once()
		domain = Domain.objects.get(name='newly-added.test')
		self.assertEqual(queued.call_args.kwargs['args'], [domain.id])
		self.assertEqual(queued.call_args.kwargs['expires'], 6 * 3600)  # a lookup nobody got to is dropped, not kept for ever

	def test_adding_an_ip_or_range_does_not_trigger_certificate_watching(self):
		from agentapi.services import Ctx, add_target
		with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async') as queued:
			add_target(Ctx(user=self.user), 'ctsub', '203.0.113.5')
		queued.assert_not_called()



class PoliteLookupTests(TestCase):
	"""crt.sh blocks bursts: lookups are spaced, a 429 is backed off from (honouring Retry-After) and retried, not skipped."""

	def setUp(self):
		_reset_slots()
		self.addCleanup(_reset_slots)
		self.sleeps = []
		self.pushed = []
		patcher = mock.patch.object(ctmonitor, 'push_back', side_effect=self.pushed.append)  # record the back-off, do not really wait
		patcher.start()
		self.addCleanup(patcher.stop)

	def _resp(self, status=200, body=None, headers=None):
		r = mock.Mock()
		r.status_code, r.headers = status, headers or {}
		r.iter_content.return_value = [json.dumps(body if body is not None else []).encode()]
		r.raise_for_status.side_effect = None
		return r

	def test_a_429_is_retried_after_the_retry_after_delay_and_then_succeeds(self):
		busy = self._resp(429, headers={'Retry-After': '7'})
		ok = self._resp(200, [{'name_value': 'www.example.com'}])
		with mock.patch('requests.get', side_effect=[busy, ok]) as get:
			entries = ctmonitor._fetch('example.com', sleep=self.sleeps.append)
		self.assertEqual(get.call_count, 2)
		self.assertEqual(entries, [{'name_value': 'www.example.com'}])
		self.assertEqual(self.pushed, [7.0])  # everyone is told to wait out Retry-After before the next lookup

	def test_it_gives_up_visibly_after_several_attempts(self):
		with mock.patch('requests.get', return_value=self._resp(429)) as get:
			self.assertIsNone(ctmonitor._fetch('example.com', sleep=self.sleeps.append))
			self.assertEqual(ctmonitor.fetch_ct_names('example.com'), set())  # the public contract: empty, never an exception
		self.assertEqual(get.call_count, ctmonitor.MAX_ATTEMPTS * 2)

	def test_a_timeout_is_retried_once_more_before_giving_up(self):
		import requests
		ok = self._resp(200, [])
		with mock.patch('requests.get', side_effect=[requests.Timeout('slow'), ok]) as get:
			self.assertEqual(ctmonitor._fetch('example.com', sleep=self.sleeps.append), [])
		self.assertEqual(get.call_count, 2)

	def test_lookups_get_distinct_slots_spaced_by_the_gap(self):
		now = lambda: 1000.0
		waits = [ctmonitor.reserve_slot(2.0, now=now) for _ in range(4)]
		self.assertEqual(waits, [0.0, 2.0, 4.0, 6.0])  # one at a time, in order, across every caller

	def test_a_failed_check_is_reported_so_the_task_can_try_again_later(self):
		from startScan.models import Subdomain
		from targetApp.models import Domain
		from dashboard.models import Org, Project
		org = Org.objects.create(name='C', slug='c-t')
		project = Project.objects.create(name='C', slug='ct-p', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='retry.example', project=project, insert_date=timezone.now())
		with mock.patch.object(ctmonitor, '_fetch', return_value=None):
			self.assertEqual(ctmonitor.run_ct_watch(domain.id), {'checked': 0, 'new': 0, 'failed': True})
