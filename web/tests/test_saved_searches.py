"""Saved searches with alerts: validation at save time, the evaluator (baseline, new matches, aliases, lost access, bounds), the
notification wiring, and tenancy on every REST and MCP entry point."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import OperationalError
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import notify, saved_searches
from cveFeed.models import AgentActivity, SavedSearch
from cveFeed.tasks import evaluate_saved_searches
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from django_celery_beat.models import PeriodicTask
from scanEngine.models import EngineType, Notification
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call
from tests.test_tenancy import client_for

SENDERS = ('send_discord_message', 'send_slack_message', 'send_lark_message', 'send_telegram_message')


class Fixture(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org, other_org = Org.objects.create(name='S', slug='s'), Org.objects.create(name='T', slug='t')
		cls.project = Project.objects.create(name='Saved', slug='ssp', insert_date=now, org=org)
		cls.other_project = Project.objects.create(name='Elsewhere', slug='ssq', insert_date=now, org=other_org)
		cls.domain = Domain.objects.create(name='example.test', project=cls.project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, scan_status=2, start_scan_date=now - timedelta(hours=1), tasks=[])
		mk = lambda name: User.objects.create_user(name, password='x')
		cls.owner, cls.peer, cls.outsider, cls.auditor = mk('ss-owner'), mk('ss-peer'), mk('ss-outsider'), mk('ss-auditor')
		for user, role in ((cls.owner, 'user'), (cls.peer, 'user'), (cls.auditor, 'audit')):
			ProjectMembership.objects.create(user=user, project=cls.project, role=role)
		ProjectMembership.objects.create(user=cls.outsider, project=cls.other_project, role='admin')
		_, cls.token = create_token(cls.owner, 'agent')
		_, cls.token_ro = create_token(cls.owner, 'readonly', read_only=True)
		_, cls.token_outsider = create_token(cls.outsider, 'outsider')
		_, cls.token_peer = create_token(cls.peer, 'peer')
		_, cls.token_auditor = create_token(cls.auditor, 'auditor')

	def setUp(self):
		cache.clear()
		self.counter = 0
		self.sent = []
		for name in SENDERS:
			patcher = mock.patch(f'reNgine.common_func.{name}', side_effect=lambda text, n=name: self.sent.append((n, text)))
			patcher.start()
			self.addCleanup(patcher.stop)

	def host(self, name, *addresses, port=None, product=''):
		"""A host of the current inventory: ``addresses`` are its IPs (shared rows, so the same address is the same IpAddress)."""
		sub = Subdomain.objects.create(target_domain=self.domain, name=name, scan_history=self.scan)
		for address in addresses:
			ip, _ = IpAddress.objects.get_or_create(address=address)
			sub.ip_addresses.add(ip)
			if port:
				ip.ports.add(Port.objects.create(number=port, product=product, state='open'))
		return sub

	def saved(self, query='port:5432', **fields):
		self.counter += 1
		fields.setdefault('name', f'search {self.counter}')
		return SavedSearch.objects.create(project=self.project, owner=self.owner, query=query, **fields)

	def notifications(self, **flags):
		return Notification.objects.create(send_to_slack=True, slack_hook_url='https://hooks.invalid/x', **flags)

	def slack(self):
		return [text for name, text in self.sent if name == 'send_slack_message']


class ValidationTests(Fixture):
	def create(self, **body):
		return call(self.token, 'POST', '/api/v1/projects/ssp/saved-searches', {'name': 'Exposed Postgres', 'query': 'port:5432 -ip:10.0.0.0/8', **body})

	def test_the_documented_examples_are_saved_and_listed(self):
		status, data = self.create()
		self.assertEqual(status, 201, data)
		self.assertEqual((data['query'], data['frequency'], data['alert_new'], data['alert_gone'], data['baseline']), ('port:5432 -ip:10.0.0.0/8', 'daily', True, False, False))
		self.assertEqual(self.create(name='Grafana', query='tech:grafana')[0], 201)
		status, listed = call(self.token, 'GET', '/api/v1/projects/ssp/saved-searches')
		self.assertEqual([s['name'] for s in listed['results']], ['Exposed Postgres', 'Grafana'])
		self.assertEqual(listed['limits']['per_user'], SavedSearch.MAX_PER_USER)

	def test_a_query_the_live_search_would_refuse_cannot_be_saved(self):
		for bad in ('port:abc', 'sev:scary', 'auth:maybe', 'zombie:perhaps', 'sensitive:everything', 'ip:10.0.0.0/99', '', '   ', '-"" ""'):
			status, data = self.create(query=bad)
			self.assertEqual(status, 400, bad)
		self.assertFalse(SavedSearch.objects.exists())

	def test_oversize_and_mistyped_input_is_refused(self):
		cases = [{'query': 'a' * 1001}, {'query': ' '.join(f'w{i}' for i in range(16))}, {'query': 'host:' + 'x' * 201}, {'query': 5}, {'query': None},
				{'name': None}, {'name': '  \t '}, {'frequency': 'every-second'}, {'channels': ['email']}, {'channels': 'slack'},
				{'threshold': 0}, {'threshold': True}, {'threshold': SavedSearch.MAX_MATCHES + 1}, {'threshold': '5'}, {'enabled': 'yes'},
				{'alert_new': 1}, {'owner': 1}, {'project': 'ssq'}]
		for case in cases:
			self.assertEqual(self.create(**case)[0], 400, case)
		self.assertFalse(SavedSearch.objects.exists())

	def test_a_long_name_is_clipped_and_control_characters_are_dropped(self):
		status, data = self.create(name='n' * 200 + '\x07')
		self.assertEqual(status, 201)
		self.assertEqual(data['name'], 'n' * SavedSearch.MAX_NAME)
		self.assertEqual(self.create(name='tab\tand\nnewline')[1]['name'], 'tab and newline')

	def test_names_are_unique_per_owner_and_project_ignoring_case(self):
		self.assertEqual(self.create()[0], 201)
		self.assertEqual(self.create(name='exposed POSTGRES')[0], 400)
		# another member may use the same name: searches are private
		self.assertEqual(call(self.token_peer, 'POST', '/api/v1/projects/ssp/saved-searches', {'name': 'Exposed Postgres', 'query': 'tech:grafana'})[0], 201)

	def test_the_caps_are_per_user_and_per_project(self):
		for i in range(SavedSearch.MAX_PER_USER):
			SavedSearch.objects.create(project=self.other_project, owner=self.owner, name=f'x{i}', query='port:1')
		status, data = self.create()
		self.assertEqual(status, 400)
		self.assertIn('at most', data['error'])
		SavedSearch.objects.filter(owner=self.owner).delete()
		SavedSearch.objects.bulk_create([SavedSearch(project=self.project, owner=self.peer, name=f'p{i}', query='port:1') for i in range(SavedSearch.MAX_PER_PROJECT)])
		status, data = self.create()
		self.assertEqual(status, 400)
		self.assertIn('this project', data['error'])

	def test_update_validates_and_a_new_query_restarts_the_baseline(self):
		s = self.saved(matched={'abc': 'a.example.test'}, baseline_at=timezone.now(), last_match_count=1, last_status='ok')
		url = f'/api/v1/projects/ssp/saved-searches/{s.pk}'
		self.assertEqual(call(self.token, 'PATCH', url, {'query': 'sev:scary'})[0], 400)
		self.assertEqual(call(self.token, 'PATCH', url, {})[0], 400)
		self.assertEqual(call(self.token, 'PATCH', url, {'alert_gone': True, 'frequency': 'weekly'})[0], 200)
		s.refresh_from_db()
		self.assertTrue(s.baseline_at and s.matched)  # settings only: the baseline stands
		status, data = call(self.token, 'PATCH', url, {'query': 'tech:grafana'})
		s.refresh_from_db()
		self.assertEqual((status, data['baseline'], s.matched, s.last_match_count), (200, False, {}, 0))

	def test_switching_a_disabled_search_back_on_restarts_the_baseline(self):
		s = self.saved(enabled=False, matched={'abc': 'a'}, baseline_at=timezone.now(), last_status='disabled', last_error='gone')
		self.assertEqual(call(self.token, 'PATCH', f'/api/v1/projects/ssp/saved-searches/{s.pk}', {'enabled': True})[0], 200)
		s.refresh_from_db()
		self.assertEqual((s.enabled, s.baseline_at, s.matched, s.last_error), (True, None, {}, ''))


class EvaluatorTests(Fixture):
	def test_the_first_evaluation_sets_the_baseline_without_an_alert(self):
		self.notifications()
		self.host('db1.example.test', '198.51.100.1', port=5432)
		self.host('db2.example.test', '198.51.100.2', port=5432)
		s = self.saved()
		out = saved_searches.evaluate(s)
		s.refresh_from_db()
		self.assertEqual((out['status'], out['baseline'], out['alerted'], out['count']), ('ok', True, False, 2))
		self.assertEqual((s.last_match_count, s.last_status, len(s.matched)), (2, 'ok', 2))
		self.assertIsNotNone(s.baseline_at)
		self.assertEqual(self.sent, [])
		self.assertIn('alerts begin with the next check', AgentActivity.objects.get(kind='saved_search').message)

	def test_a_new_match_is_announced_once_naming_the_host_and_linking_the_search(self):
		self.notifications()
		self.host('db1.example.test', '198.51.100.1', port=5432)
		s = self.saved(query='port:5432 -ip:10.0.0.0/8')
		saved_searches.evaluate(s)
		self.host('db2.example.test', '198.51.100.2', port=5432)
		self.host('db3.example.test', '10.1.1.1', port=5432)  # excluded by the -ip term
		s.refresh_from_db()
		out = saved_searches.evaluate(s)
		self.assertEqual((out['alerted'], out['new'], out['new_count']), (True, ['db2.example.test'], 1))
		self.assertEqual(len(self.slack()), 1)
		text = self.slack()[0]
		self.assertIn('1 new host: `db2.example.test`', text)
		self.assertIn('https://', text)
		self.assertIn('/cve/ssp/hosts/?q=port%3A5432%20-ip%3A10.0.0.0%2F8', text)
		s.refresh_from_db()
		self.assertIsNotNone(s.last_alert_at)
		self.assertIn('1 new host (db2.example.test)', AgentActivity.objects.filter(kind='saved_search').first().message)
		# nothing changed since: no second message
		out = saved_searches.evaluate(s)
		self.assertEqual((out['alerted'], len(self.slack())), (False, 1))

	def test_a_message_names_at_most_five_hosts_and_counts_the_rest(self):
		self.notifications()
		s = self.saved(query='port:8443')
		saved_searches.evaluate(s)
		for i in range(7):
			self.host(f'web{i}.example.test', f'198.51.100.{10 + i}', port=8443)
		s.refresh_from_db()
		out = saved_searches.evaluate(s)
		self.assertEqual((out['new_count'], len(out['new'])), (7, 5))
		self.assertEqual(len(self.slack()), 1)
		self.assertIn('7 new hosts', self.slack()[0])
		self.assertIn('and 2 more', self.slack()[0])
		self.assertEqual(self.slack()[0].count('`web'), 5)

	def test_aliases_of_one_machine_are_one_match(self):
		self.notifications()
		self.host('example.test', '198.51.100.30', port=5432)
		s = self.saved()
		first = saved_searches.evaluate(s)
		self.assertEqual(first['count'], 1)
		self.host('www.example.test', '198.51.100.30', port=5432)  # the same addresses: the same host with another name
		s.refresh_from_db()
		out = saved_searches.evaluate(s)
		self.assertEqual((out['count'], out['new_count'], out['alerted']), (1, 0, False))
		self.assertEqual(self.sent, [])
		self.host('other.example.test', '198.51.100.31', port=5432)
		s.refresh_from_db()
		self.assertEqual(saved_searches.evaluate(s)['new'], ['other.example.test'])

	def test_hosts_that_stop_matching_alert_only_when_asked(self):
		self.notifications()
		gone = self.host('old.example.test', '198.51.100.40', port=5432)
		quiet, loud = self.saved(name='quiet'), self.saved(name='loud', alert_gone=True, alert_new=False)
		for s in (quiet, loud):
			saved_searches.evaluate(s)
		gone.ip_addresses.first().ports.update(state='closed')
		for s in (quiet, loud):
			s.refresh_from_db()
			saved_searches.evaluate(s)
		self.assertEqual(len(self.slack()), 1)
		self.assertIn('1 host no longer matches: `old.example.test`', self.slack()[0])
		self.assertIn('`loud`', self.slack()[0])

	def test_a_threshold_alerts_once_per_crossing(self):
		self.notifications()
		s = self.saved(query='port:9000', threshold=2, alert_new=False)
		saved_searches.evaluate(s)
		self.host('a.example.test', '198.51.100.50', port=9000)
		s.refresh_from_db()
		saved_searches.evaluate(s)
		self.assertEqual(self.sent, [])
		self.host('b.example.test', '198.51.100.51', port=9000)
		s.refresh_from_db()
		saved_searches.evaluate(s)
		self.assertEqual(len(self.slack()), 1)
		self.assertIn('2 matches, which reaches the threshold of 2', self.slack()[0])
		self.host('c.example.test', '198.51.100.52', port=9000)
		s.refresh_from_db()
		saved_searches.evaluate(s)
		self.assertEqual(len(self.slack()), 1)  # still above it: not again

	def test_channels_and_the_settings_switch_decide_where_it_goes(self):
		self.notifications()
		Notification.objects.update(send_to_discord=True, discord_hook_url='https://hooks.invalid/d')
		s = self.saved(query='port:7000', channels=['discord'])
		saved_searches.evaluate(s)
		self.host('c.example.test', '198.51.100.60', port=7000)
		s.refresh_from_db()
		saved_searches.evaluate(s)
		self.assertEqual([name for name, _ in self.sent], ['send_discord_message'])
		self.sent.clear()
		Notification.objects.update(send_interesting_notif=False)
		self.host('d.example.test', '198.51.100.61', port=7000)
		s.refresh_from_db()
		out = saved_searches.evaluate(s)
		self.assertEqual((out['new_count'], self.sent), (1, []))  # still recorded and in the activity feed
		self.assertEqual(AgentActivity.objects.filter(kind='saved_search').count(), 3)

	def test_notify_is_called_once_per_evaluation_with_what_changed(self):
		self.host('a.example.test', '198.51.100.70', port=7100)
		s = self.saved(query='port:7100', alert_gone=True)
		saved_searches.evaluate(s)
		self.host('b.example.test', '198.51.100.71', port=7100)
		s.refresh_from_db()
		with mock.patch('cveFeed.saved_searches.notify.saved_search', return_value=True) as sent:
			saved_searches.evaluate(s)
		sent.assert_called_once_with(mock.ANY, ['b.example.test'], [], 2, False)

	def test_an_alert_no_channel_could_deliver_is_tried_again_at_the_next_check(self):
		self.notifications()
		self.host('a.example.test', '198.51.100.70', port=7100)
		s = self.saved(query='port:7100')
		saved_searches.evaluate(s)
		self.host('b.example.test', '198.51.100.71', port=7100)
		s.refresh_from_db()
		before = dict(s.matched)
		with mock.patch('cveFeed.saved_searches.notify.saved_search', return_value=None):  # every channel failed
			out = saved_searches.evaluate(s)
		s.refresh_from_db()
		self.assertEqual((out['status'], out['alerted'], s.last_status, s.matched, s.last_alert_at), ('alert_failed', False, 'alert_failed', before, None))
		self.assertIsNotNone(s.next_run_at)
		with mock.patch('cveFeed.saved_searches.notify.saved_search', return_value=True) as sent:
			out = saved_searches.evaluate(SavedSearch.objects.get(pk=s.pk))
		self.assertEqual((out['status'], out['alerted'], out['new']), ('ok', True, ['b.example.test']))  # the same alert, now delivered
		sent.assert_called_once()

	def test_no_channel_at_all_is_not_a_failure_and_the_baseline_moves_on(self):
		self.host('a.example.test', '198.51.100.70', port=7100)
		s = self.saved(query='port:7100')
		saved_searches.evaluate(s)
		self.host('b.example.test', '198.51.100.71', port=7100)
		s.refresh_from_db()
		with mock.patch('cveFeed.saved_searches.notify.saved_search', return_value=False):
			out = saved_searches.evaluate(s)
		s.refresh_from_db()
		self.assertEqual((out['status'], s.last_status, len(s.matched)), ('ok', 'ok', 2))

	def test_an_owner_who_lost_access_is_switched_off_not_run(self):
		self.host('a.example.test', '198.51.100.80', port=5432)
		s = self.saved()
		saved_searches.evaluate(s)
		ProjectMembership.objects.filter(user=self.owner, project=self.project).delete()
		s = SavedSearch.objects.get(pk=s.pk)
		with mock.patch('cveFeed.saved_searches.current_matches') as run:
			out = saved_searches.evaluate(s)
		run.assert_not_called()
		s.refresh_from_db()
		self.assertEqual((out['status'], s.enabled, s.last_status), ('disabled', False, 'disabled'))
		self.assertIn('no longer has access', s.last_error)
		self.assertIn('was switched off', AgentActivity.objects.filter(kind='saved_search').first().message)
		self.assertEqual(self.sent, [])

	def test_a_deactivated_owner_is_switched_off(self):
		s = self.saved()
		User.objects.filter(pk=self.owner.pk).update(is_active=False)
		s = SavedSearch.objects.select_related('owner').get(pk=s.pk)
		self.assertEqual(saved_searches.evaluate(s)['status'], 'disabled')

	def test_a_query_that_became_invalid_is_switched_off(self):
		s = self.saved(query='port:abc')  # saved by an older version of the rules
		self.assertEqual(saved_searches.evaluate(s)['status'], 'disabled')
		s.refresh_from_db()
		self.assertFalse(s.enabled)

	def test_a_search_that_is_too_broad_is_not_alerted_on(self):
		self.notifications()
		for i in range(3):
			self.host(f'h{i}.example.test', f'198.51.100.{90 + i}', port=5432)
		s = self.saved()
		with mock.patch.object(SavedSearch, 'MAX_MATCHES', 2):
			out = saved_searches.evaluate(s)
		s.refresh_from_db()
		self.assertEqual((out['status'], s.last_status, s.baseline_at, s.matched), ('too_broad', 'too_broad', None, {}))
		self.assertEqual(self.sent, [])

	def test_a_database_failure_is_recorded_without_its_text_and_not_retried_in_a_loop(self):
		s = self.saved()
		with mock.patch('cveFeed.saved_searches.current_matches', side_effect=OperationalError('/var/lib/secret/path timed out')):
			out = saved_searches.evaluate(s)
		s.refresh_from_db()
		self.assertEqual((out['status'], s.last_status), ('error', 'error'))
		self.assertNotIn('secret', s.last_error)
		self.assertNotIn('secret', AgentActivity.objects.filter(kind='saved_search').first().message)
		self.assertGreater(s.next_run_at, timezone.now())

	def test_an_evaluation_of_a_search_edited_meanwhile_is_dropped(self):
		self.host('a.example.test', '198.51.100.99', port=5432)
		stale = self.saved()
		SavedSearch.objects.filter(pk=stale.pk).update(query='tech:grafana')
		saved_searches.evaluate(stale)
		stale.refresh_from_db()
		self.assertEqual((stale.baseline_at, stale.matched), (None, {}))

	def test_two_evaluations_of_one_search_never_overlap(self):
		s = self.saved()
		cache.add(f'cvengine:saved-search:{s.pk}', 1, timeout=60)
		self.assertEqual(saved_searches.evaluate(s)['status'], 'busy')

	def evaluations_cost(self, s):
		from django.db import connection
		from django.test.utils import CaptureQueriesContext
		with CaptureQueriesContext(connection) as ctx:
			saved_searches.evaluate(SavedSearch.objects.select_related('owner', 'project').get(pk=s.pk))
		return len(ctx)

	def test_an_evaluation_costs_the_same_number_of_queries_however_many_hosts_match(self):
		for i in range(30):
			self.host(f'q{i}.example.test', f'198.51.100.{100 + i}', port=5432)
		s = self.saved()
		saved_searches.evaluate(s)
		few = self.evaluations_cost(s)
		for i in range(30):
			self.host(f'r{i}.example.test', f'198.51.101.{100 + i}', port=5432)
		saved_searches.evaluate(SavedSearch.objects.get(pk=s.pk))  # the new hosts are announced here
		self.assertEqual(self.evaluations_cost(s), few)


class DueTests(Fixture):
	def test_only_enabled_due_searches_run_oldest_first_and_a_run_is_bounded(self):
		now = timezone.now()
		a = self.saved(next_run_at=now - timedelta(hours=3))
		b = self.saved(next_run_at=now - timedelta(hours=2))
		c = self.saved(next_run_at=now - timedelta(hours=1))
		later = self.saved(next_run_at=now + timedelta(hours=1))
		off = self.saved(next_run_at=now - timedelta(hours=5), enabled=False)
		with mock.patch.object(saved_searches, 'BATCH', 2):
			out = saved_searches.evaluate_due(now)
		self.assertEqual(out['evaluated'], 2)
		ran = {s.pk for s in SavedSearch.objects.exclude(last_run_at=None)}
		self.assertEqual(ran, {a.pk, b.pk})
		self.assertEqual(saved_searches.evaluate_due(now)['evaluated'], 1)
		self.assertEqual({s.pk for s in SavedSearch.objects.exclude(last_run_at=None)}, {a.pk, b.pk, c.pk})
		for s in (later, off):
			s.refresh_from_db()
			self.assertIsNone(s.last_run_at)

	def test_changing_the_frequency_moves_the_next_check(self):
		now = timezone.now()
		s = self.saved(frequency='weekly', last_run_at=now - timedelta(hours=2), next_run_at=now + timedelta(days=7))
		url = f'/api/v1/projects/ssp/saved-searches/{s.pk}'
		self.assertEqual(call(self.token, 'PATCH', url, {'frequency': 'hourly'})[0], 200)
		s.refresh_from_db()
		self.assertLessEqual(s.next_run_at, now + timedelta(seconds=5))  # an hour after a check made two hours ago: due now, not in a week
		self.assertEqual(call(self.token, 'PATCH', url, {'frequency': 'daily'})[0], 200)
		s.refresh_from_db()
		self.assertGreater(s.next_run_at, now + timedelta(hours=20))
		self.assertEqual(call(self.token, 'PATCH', url, {'name': 'renamed'})[0], 200)  # an edit that is not about the rhythm leaves it alone

	def test_the_next_run_follows_the_frequency(self):
		now = timezone.now()
		hourly, weekly = self.saved(frequency='hourly', next_run_at=now), self.saved(frequency='weekly', next_run_at=now)
		saved_searches.evaluate_due(now)
		hourly.refresh_from_db()
		weekly.refresh_from_db()
		self.assertEqual(hourly.next_run_at - now, timedelta(hours=1))
		self.assertEqual(weekly.next_run_at - now, timedelta(days=7))

	def test_one_search_failing_does_not_stop_the_others(self):
		now = timezone.now()
		bad = self.saved(next_run_at=now - timedelta(hours=2))
		good = self.saved(next_run_at=now - timedelta(hours=1))
		real = saved_searches._evaluate

		def evaluate(search, now):
			if search.pk == bad.pk:
				raise RuntimeError('boom')
			return real(search, now)
		with mock.patch.object(saved_searches, '_evaluate', side_effect=evaluate), self.assertLogs('cveFeed.saved_searches', 'ERROR'):
			out = saved_searches.evaluate_due(now)
		self.assertEqual((out['evaluated'], out['errors']), (2, 1))
		good.refresh_from_db()
		self.assertEqual(good.last_status, 'ok')

	def test_the_beat_task_is_scheduled_and_never_overlaps_itself(self):
		task = PeriodicTask.objects.get(name='cvengine-saved-searches')
		self.assertEqual((task.task, task.enabled, task.queue), ('evaluate_saved_searches', True, 'cve_feed_queue'))
		cache.add('cvengine:saved-searches', 1, timeout=60)
		self.assertIn('skipped', evaluate_saved_searches())
		cache.delete('cvengine:saved-searches')
		self.assertEqual(evaluate_saved_searches()['evaluated'], 0)


class NotifyTextTests(Fixture):
	def test_hostile_names_cannot_add_markup_or_mentions(self):
		self.notifications()
		s = self.saved(name='<!channel> *bold* `x`')
		notify.saved_search(s, ['evil`.example.test', '@everyone'], [], 2, False)
		text = self.slack()[0]
		self.assertNotIn('<!channel>', text)
		self.assertNotIn('@everyone', text)
		self.assertNotIn('*bold*', text)
		self.assertIn('`evil?.example.test`', text)


class TenancyTests(Fixture):
	def setUp(self):
		super().setUp()
		self.s = self.saved(name='mine')
		self.base = '/api/v1/projects/ssp/saved-searches'

	def endpoints(self, sid):
		u = f'{self.base}/{sid}'
		return [('GET', self.base, None), ('POST', self.base, {'name': 'n2', 'query': 'port:22'}), ('GET', u, None), ('PATCH', u, {'enabled': False}),
				('DELETE', u, None), ('POST', f'{u}/run', None), ('GET', f'{u}/matches', None)]

	def test_unauthenticated_callers_get_401(self):
		for method, path, body in self.endpoints(self.s.pk):
			self.assertEqual(call(None, method, path, body)[0], 401, (method, path))

	def test_a_user_of_another_project_sees_the_project_as_missing(self):
		for method, path, body in self.endpoints(self.s.pk):
			self.assertEqual(call(self.token_outsider, method, path, body)[0], 404, (method, path))
		self.assertTrue(SavedSearch.objects.filter(pk=self.s.pk, enabled=True).exists())

	def test_another_member_of_the_project_cannot_see_or_touch_your_search(self):
		status, listed = call(self.token_peer, 'GET', self.base)
		self.assertEqual((status, listed['results']), (200, []))
		for method, path, body in self.endpoints(self.s.pk)[2:]:
			self.assertEqual(call(self.token_peer, method, path, body)[0], 404, (method, path))
		self.assertTrue(SavedSearch.objects.filter(pk=self.s.pk, enabled=True).exists())

	def test_an_id_from_another_project_is_not_found_through_this_one(self):
		theirs = SavedSearch.objects.create(project=self.other_project, owner=self.outsider, name='theirs', query='port:1')
		for method, path, body in self.endpoints(theirs.pk)[2:]:
			self.assertEqual(call(self.token, method, path, body)[0], 404, (method, path))
		self.assertEqual(call(self.token_outsider, 'GET', f'/api/v1/projects/ssq/saved-searches/{theirs.pk}')[0], 200)

	def test_a_read_only_token_and_an_audit_role_can_read_but_not_write(self):
		for token in (self.token_ro, self.token_auditor):
			self.assertEqual(call(token, 'GET', self.base)[0], 200)
		self.assertEqual(call(self.token_ro, 'GET', f'{self.base}/{self.s.pk}')[0], 200)
		self.assertEqual(call(self.token_ro, 'GET', f'{self.base}/{self.s.pk}/matches')[0], 200)
		for method, path, body in self.endpoints(self.s.pk):
			if method == 'GET':
				continue
			self.assertEqual(call(self.token_ro, method, path, body)[0], 403, ('read-only token', method, path))
		for method, path, body in self.endpoints(self.s.pk):
			if method == 'GET':
				continue
			self.assertIn(call(self.token_auditor, method, path, body)[0], (403, 404), ('audit', method, path))
		self.assertEqual(call(self.token_auditor, 'POST', self.base, {'name': 'a', 'query': 'port:22'})[0], 403)
		self.assertTrue(SavedSearch.objects.filter(pk=self.s.pk, enabled=True).exists())

	def test_the_all_projects_view_cannot_hold_or_list_saved_searches(self):
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/_all/saved-searches')[0], 400)
		self.assertEqual(call(self.token, 'POST', '/api/v1/projects/_all/saved-searches', {'name': 'n', 'query': 'port:22'})[0], 400)

	def test_the_session_user_gets_the_same_answers(self):
		browser = client_for(self.owner)
		self.assertEqual(browser.get(self.base).status_code, 200)
		self.assertEqual(client_for(self.peer).get(f'{self.base}/{self.s.pk}').status_code, 404)

	def test_matches_are_the_live_search_with_the_saved_query(self):
		self.host('db1.example.test', '198.51.100.1', port=5432)
		self.host('web.example.test', '198.51.100.2', port=80)
		status, matches = call(self.token, 'GET', f'{self.base}/{self.s.pk}/matches?page_size=10')
		status2, live = call(self.token, 'GET', '/api/v1/projects/ssp/search?q=port:5432&page_size=10')
		self.assertEqual((status, status2), (200, 200))
		self.assertEqual([h['host'] for h in matches['results']], ['db1.example.test'])
		self.assertEqual([h['host'] for h in matches['results']], [h['host'] for h in live['results']])
		self.assertEqual(matches['saved_search']['id'], self.s.pk)
		self.s.refresh_from_db()
		self.assertIsNone(self.s.baseline_at)  # reading does not touch the baseline

	def test_run_now_evaluates_and_is_throttled(self):
		self.host('db1.example.test', '198.51.100.1', port=5432)
		status, data = call(self.token, 'POST', f'{self.base}/{self.s.pk}/run')
		self.assertEqual((status, data['status'], data['baseline'], data['count']), (200, 'ok', True, 1))
		self.assertTrue(data['saved_search']['baseline'])
		self.assertEqual(call(self.token, 'POST', f'{self.base}/{self.s.pk}/run')[0], 429)
		SavedSearch.objects.filter(pk=self.s.pk).update(enabled=False)
		cache.clear()
		self.assertEqual(call(self.token, 'POST', f'{self.base}/{self.s.pk}/run')[0], 400)

	def test_delete_removes_only_the_owners_row(self):
		self.assertEqual(call(self.token, 'DELETE', f'{self.base}/{self.s.pk}')[1], {'deleted': True})
		self.assertFalse(SavedSearch.objects.filter(pk=self.s.pk).exists())

	def test_the_mcp_tools_enforce_the_same_rules(self):
		names = {'list_saved_searches', 'create_saved_search', 'update_saved_search', 'delete_saved_search', 'run_saved_search', 'get_saved_search_matches'}
		status, data = call(self.token, 'POST', '/mcp/', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}})
		tools = {t['name']: t for t in data['result']['tools']}
		self.assertTrue(names <= set(tools))
		self.assertEqual({n for n in names if not tools[n]['annotations']['readOnlyHint']}, {'create_saved_search', 'update_saved_search', 'delete_saved_search', 'run_saved_search'})
		failed, created = tool_call(self.token, 'create_saved_search', {'project': 'ssp', 'name': 'via mcp', 'query': 'tech:grafana', 'frequency': 'hourly'})
		self.assertFalse(failed)
		self.assertEqual((created['name'], created['frequency']), ('via mcp', 'hourly'))
		self.assertEqual([s['name'] for s in tool_call(self.token, 'list_saved_searches', {'project': 'ssp'})[1]['results']], ['mine', 'via mcp'])
		self.assertTrue(tool_call(self.token, 'create_saved_search', {'project': 'ssp', 'name': 'bad', 'query': 'port:abc'})[0])
		self.assertTrue(tool_call(self.token_outsider, 'list_saved_searches', {'project': 'ssp'})[0])
		self.assertTrue(tool_call(self.token_peer, 'delete_saved_search', {'project': 'ssp', 'id': self.s.pk})[0])
		self.assertTrue(tool_call(self.token_ro, 'create_saved_search', {'project': 'ssp', 'name': 'ro', 'query': 'tech:grafana'})[0])
		self.assertTrue(tool_call(self.token_ro, 'run_saved_search', {'project': 'ssp', 'id': self.s.pk})[0])
		self.assertFalse(tool_call(self.token_ro, 'get_saved_search_matches', {'project': 'ssp', 'id': self.s.pk})[0])
		self.assertTrue(tool_call(self.token_peer, 'get_saved_search_matches', {'project': 'ssp', 'id': self.s.pk})[0])
		self.assertTrue(SavedSearch.objects.filter(pk=self.s.pk).exists())
