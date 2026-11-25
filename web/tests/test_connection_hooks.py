"""Hooks on the database connection come off when their block ends.

``tenancy.snapshot.activate`` puts a hook on the connection for each signed-in request, and ``cveFeed.current_scans`` adds its own the first
time a statement uses the current scan sets. ``connection.execute_wrapper`` takes its hook off with ``pop()``, the last one in the list, so the
scan-sets hook added inside the request was taken off in place of the request's hook, and one request hook stayed on the connection for good.
A web thread keeps its connection object across requests (gunicorn gthread), so every request that read the current scans left one more hook,
each run around every later statement of that thread, until the worker was recycled (or the stack ran out).
"""
from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from cveFeed import current_scans
from dashboard.models import Org, OrgMembership, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tenancy import snapshot
from tests.test_tenancy import client_for


class ConnectionHooksComeOffTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Hooks', slug='hooks')
		cls.project = Project.objects.create(name='Hooks', slug='hooks', org=org, insert_date=timezone.now())
		domain = Domain.objects.create(name='hooks.example.com', project=cls.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='hooks', yaml_configuration='x')
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
		Subdomain.objects.create(name='www.hooks.example.com', target_domain=domain, scan_history=scan)
		cls.user = User.objects.create_user('hooks-admin', 'hooks@example.com', 'x')
		OrgMembership.objects.create(user=cls.user, org=org, role='admin')

	def setUp(self):
		self.addCleanup(self._restore, list(connection.execute_wrappers))

	def _restore(self, before):
		connection.execute_wrappers[:] = before

	def _hooks(self):
		return [w.__name__ for w in connection.execute_wrappers]

	def test_signed_in_requests_leave_no_request_hook_behind(self):
		client = client_for(self.user)
		seen = []
		for _ in range(5):
			response = client.get('/api/v1/projects/hooks/hosts')
			self.assertEqual(response.status_code, 200)
			seen.append(self._hooks())
		self.assertNotIn('_watch_writes', sum(seen, []), seen)
		self.assertEqual(len({len(hooks) for hooks in seen}), 1, seen)  # the same hooks after the fifth request as after the first

	def test_the_scan_sets_hook_added_inside_a_snapshot_stays_and_the_snapshot_hook_goes(self):
		connection.execute_wrappers[:] = [w for w in connection.execute_wrappers if w is not current_scans._forget_sets]
		with snapshot.activate(self.user):
			list(Subdomain.objects.filter(scan_history_id__in_current_scans='current').values_list('id', flat=True))
			self.assertIn(current_scans._forget_sets, connection.execute_wrappers)
		self.assertNotIn(snapshot._watch_writes, connection.execute_wrappers)
		self.assertIn(current_scans._forget_sets, connection.execute_wrappers)

	def test_a_counter_block_around_a_scan_sets_query_takes_its_own_hook_off(self):
		connection.execute_wrappers[:] = [w for w in connection.execute_wrappers if w is not current_scans._forget_sets]
		statements = []

		def counter(execute, sql, params, many, context):
			statements.append(sql)
			return execute(sql, params, many, context)
		with connection.execute_wrapper(counter):
			list(Subdomain.objects.filter(scan_history_id__in_current_scans='current').values_list('id', flat=True))
		self.assertNotIn(counter, connection.execute_wrappers)
		self.assertTrue(statements)
