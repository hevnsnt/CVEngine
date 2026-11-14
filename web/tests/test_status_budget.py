"""The system status cannot hang (issue: the full status did not answer for over 60 s on an install whose health, project and activity lists answered in a
second). Every probe has a deadline, the answer a budget, a probe that runs out is named, and an App Admin sees the seconds each probe took."""
import io
import os
import threading
import time
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.utils import timezone

from agentapi import status_probes, system_status
from agentapi.services import Ctx
from agentapi.status_probes import Probe
from dashboard.models import Org, Project, ProjectMembership


def waiting(release):
    return lambda p, n, d: release.wait(30) and None


class EngineTests(SimpleTestCase):
    def setUp(self):
        status_probes.reset()
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        self.addCleanup(status_probes.reset)

    def test_a_probe_that_hangs_is_named_and_the_others_answer(self):
        probes = [Probe('hangs', waiting(self.release), limit=0.5, db=False), Probe('fine', lambda p, n, d: {'ok': 1}, db=False)]
        started = time.monotonic()
        run = status_probes.run(probes, budget=3)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(run.results['hangs'].state, 'timeout')
        self.assertEqual(run.results['hangs'].line, 'hangs: timed out after 0.5 s')
        self.assertEqual((run.results['fine'].state, run.results['fine'].value), ('ok', {'ok': 1}))
        self.assertEqual(run.timings()['not_finished'], ['hangs'])

    def test_the_budget_holds_for_probes_that_are_each_inside_their_own_limit(self):
        probes = [Probe(f'slow{i}', waiting(self.release), limit=30, db=False) for i in range(10)]
        started = time.monotonic()
        run = status_probes.run(probes, budget=1, concurrency=2)
        self.assertLess(time.monotonic() - started, 2.5)
        states = [r.state for r in run.results.values()]
        self.assertEqual(states.count('timeout'), 2)
        self.assertEqual(states.count('skipped'), 8)
        self.assertIn('not run, the status budget was used up', run.results['slow9'].line)

    def test_a_probe_still_running_from_an_earlier_call_is_not_started_again(self):
        started = []
        probe = Probe('once', lambda p, n, d: started.append(1) or self.release.wait(30), limit=0.3, db=False)
        status_probes.run([probe], budget=2)
        run = status_probes.run([probe], budget=2)
        self.assertEqual(len(started), 1)
        self.assertEqual(run.results['once'].state, 'busy')

    def test_a_probe_that_raises_is_named_without_its_message(self):
        def boom(p, n, d):
            raise ValueError('secret address 10.0.0.1')
        run = status_probes.run([Probe('boom', boom, db=False)], budget=2)
        self.assertEqual(run.results['boom'].line, 'boom: could not be read (ValueError)')

    def test_a_late_answer_is_dropped_and_a_dependent_probe_sees_the_failure(self):
        seen = {}
        probes = [Probe('first', waiting(self.release), limit=0.3, db=False), Probe('second', lambda p, n, d: seen.update(d) or 1, after='first', db=False)]
        run = status_probes.run(probes, budget=3)
        self.release.set()
        time.sleep(0.2)
        self.assertEqual(run.results['first'].state, 'timeout')
        self.assertIsNone(run.results['first'].value)
        self.assertIn('error', seen['first'])

    def test_the_threads_database_connection_is_bounded_and_closed(self):
        calls = []
        with mock.patch('agentapi.status_probes._bound_database', lambda limit: calls.append(limit)), \
                mock.patch('django.db.connections.close_all', lambda: calls.append('closed')):
            status_probes.run([Probe('db', lambda p, n, d: 1, limit=2)], budget=3)
        self.assertEqual(calls, [2, 'closed'])


class StatusTests(TransactionTestCase):
    """Committed rows: the probe threads have connections of their own."""

    def setUp(self):
        status_probes.reset()
        self.addCleanup(status_probes.reset)
        cache.clear()
        self.addCleanup(cache.clear)
        self.root = User.objects.create_superuser('sb-root', 'root@sb.example.test', 'x')
        self.member = User.objects.create_user('sb-member', password='x')
        org = Org.objects.create(name='SB', slug='sb-org')
        self.project = Project.objects.create(name='SB', slug='sb-proj', insert_date=timezone.now(), org=org)
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')

    def test_a_hanging_probe_does_not_hang_the_status_and_is_named(self):
        release = threading.Event()
        self.addCleanup(release.set)
        with mock.patch.dict(os.environ, {'CVENGINE_STATUS_PROBE_SECONDS': '1', 'CVENGINE_STATUS_BUDGET_SECONDS': '4'}), \
                mock.patch.object(system_status, '_feeds', lambda: release.wait(30)), \
                mock.patch.object(system_status, '_broker_client', lambda: mock.Mock(ping=lambda: True, llen=lambda n: 0, hlen=lambda n: 0)):
            started = time.monotonic()
            out = system_status.system_status(Ctx(user=self.root))
        self.assertLess(time.monotonic() - started, 4.5)
        self.assertIn('feeds: timed out after 1 s', out['problems'])
        self.assertEqual(out['system']['feeds'], {'error': 'timeout'})
        self.assertEqual(out['overall'], 'degraded')
        self.assertEqual([p['slug'] for p in out['projects']], ['sb-proj'])  # the rest of the answer is there
        self.assertIn('database', out['system'])

    def test_timings_are_for_an_app_admin_only(self):
        with mock.patch.object(system_status, '_broker_client', lambda: mock.Mock(ping=lambda: True, llen=lambda n: 0, hlen=lambda n: 0)):
            admin = system_status.system_status(Ctx(user=self.root))
            member = system_status.system_status(Ctx(user=self.member))
        timings = admin['system']['timings']
        self.assertEqual(timings['budget_seconds'], 8)
        self.assertTrue({'inventory', 'database', 'workers', 'sentinels', 'feeds'} <= set(timings['probes']))
        self.assertTrue(all(isinstance(v, float) for v in timings['probes'].values()))
        self.assertIsNone(member['system'])
        self.assertNotIn('timings', str(member))

    def test_the_command_prints_each_probe(self):
        out = io.StringIO()
        with mock.patch.object(system_status, '_broker_client', lambda: mock.Mock(ping=lambda: True, llen=lambda n: 0, hlen=lambda n: 0)):
            call_command('status_timings', stdout=out)
        text = out.getvalue()
        self.assertIn('status answered in', text)
        self.assertIn('s  inventory', text)
        self.assertIn('sentinels', text)


class ColdInventoryTests(TestCase):
    """A cold project row is not counted fifteen times in a row inside one request."""

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        org = Org.objects.create(name='CI', slug='ci-org')
        self.root = User.objects.create_superuser('ci-root', 'root@ci.example.test', 'x')
        self.projects = [Project.objects.create(name=f'P{i}', slug=f'ci-{i}', insert_date=timezone.now(), org=org) for i in range(4)]

    def test_past_the_deadline_no_row_is_counted_and_the_projects_are_named(self):
        with mock.patch.object(system_status, '_project_row') as built:
            rows, waiting_slugs = system_status._projects_partial(Ctx(user=self.root), deadline=time.monotonic() - 1)
        built.assert_not_called()
        self.assertEqual((rows, waiting_slugs), ([], ['ci-0', 'ci-1', 'ci-2', 'ci-3']))

    def test_a_project_that_does_not_fit_shows_its_last_counts_marked_stale(self):
        cache.set(f'sysstatus:project:last:{self.projects[1].id}', {'slug': 'ci-1', 'name': 'P1'}, 60)
        rows, waiting_slugs = system_status._projects_partial(Ctx(user=self.root), deadline=time.monotonic() - 1)
        self.assertEqual(rows, [{'slug': 'ci-1', 'name': 'P1', 'stale': True}])
        self.assertIn('ci-1', waiting_slugs)

    def test_the_inventory_probe_says_how_many_are_left(self):
        problems = []
        with mock.patch.object(system_status, 'INVENTORY_SECONDS', 0):
            out = system_status._inventory(Ctx(user=self.root), problems)
        self.assertEqual(out['pending'], 4)
        self.assertIn('inventory: 4 of 4 project(s) could not be counted within 0 s', problems[0])

    def test_with_time_every_row_is_counted_and_kept_for_next_time(self):
        rows, waiting_slugs = system_status._projects_partial(Ctx(user=self.root), deadline=time.monotonic() + 60)
        self.assertEqual((len(rows), waiting_slugs), (4, []))
        self.assertIsNotNone(cache.get(f'sysstatus:project:last:{self.projects[0].id}'))


class RedisScanTests(SimpleTestCase):
    def test_the_status_scans_ask_for_a_thousand_keys_at_a_time(self):
        """SCAN with no COUNT hint reads ten keys a call: 300000 keys (a day of Celery results) took 3.2 s against 0.28 s with the hint."""
        from reNgine import resources
        client = mock.Mock()
        client.scan_iter.return_value = iter(())
        store = mock.Mock(r=client)
        store.__class__ = resources.RedisStore
        with mock.patch.object(resources, 'get_store', lambda: store), mock.patch.dict(resources._store, {'kind': 'redis'}):
            resources.cluster_snapshot()
            resources.adaptive_history(0)
        self.assertEqual([c.kwargs.get('count') for c in client.scan_iter.call_args_list], [1000, 1000])

    def test_the_broker_client_has_socket_timeouts(self):
        with mock.patch.dict(os.environ, {'CELERY_BROKER': 'redis://127.0.0.1:6379/11'}):
            kwargs = system_status._broker_client().connection_pool.connection_kwargs
        self.assertEqual((kwargs['socket_connect_timeout'], kwargs['socket_timeout']), (2, 3))
