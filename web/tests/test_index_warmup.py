"""The index review's one new index and the startup warm-up (cveFeed/warmup.py).

* ``sub_lower_name_idx`` (startScan 0036): ``cveFeed.manual_only`` looks a host up by ``LOWER(name)`` within a project for every host a sweep
  considers (about 29,000 times in two hours on a live install). Without the index the planner walked the host table by id from the newest row
  (29,500 buffers, 40 ms for a name the project does not hold). The plans are read with sequential and bitmap scans off, as in test_hot_indexes:
  the tables here are tiny, and the question is which index serves the query.
* The warm-up: once per process, in the background, never raising, bounded, closing its database connections, off with ``CVENGINE_WARMUP=0``,
  started by the web workers and the Celery lanes only (never by ``watchdog_tick`` or ``celery_healthcheck.py``), warming shared public data only.
"""
import importlib
import os
import threading
import time
from pathlib import Path
from unittest import mock

from django.db import connection, connections
from django.db.models.functions import Lower
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.utils import timezone

from cveFeed import manual_only, warmup
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain

WEB = Path(__file__).resolve().parent.parent


def plan(queryset):
    with connection.cursor() as cursor:
        cursor.execute('SET LOCAL enable_seqscan = off')
        cursor.execute('SET LOCAL enable_bitmapscan = off')
        return queryset.explain()


class LowerNameIndexTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.project = Project.objects.create(name='L', slug='lni-proj', insert_date=timezone.now(), org=Org.objects.create(name='L', slug='lni-org'))
        cls.domain = Domain.objects.create(name='example.org', project=cls.project, insert_date=timezone.now())
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i}.example.org', target_domain=cls.domain) for i in range(50)])
        # a project of many targets, like the live one the lookups were slow in, so the planner has a reason to reach the hosts by name
        others = Domain.objects.bulk_create([Domain(name=f't{d}.example.net', project=cls.project, insert_date=timezone.now()) for d in range(40)])
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i}.t{n}.example.net', target_domain=d) for n, d in enumerate(others) for i in range(40)])
        with connection.cursor() as cursor:
            cursor.execute('ANALYZE "startScan_subdomain"')
            cursor.execute('ANALYZE "targetApp_domain"')

    def test_the_index_is_declared_on_the_model_with_a_short_name(self):
        idx = next(i for i in Subdomain._meta.indexes if i.name == 'sub_lower_name_idx')
        self.assertEqual(idx.expressions, (Lower('name'),))
        self.assertLessEqual(len(idx.name), 30)

    def test_the_migration_builds_it_concurrently_after_the_current_leaf(self):
        mod = importlib.import_module('startScan.migrations.0037_subdomain_lower_name_idx')
        self.assertFalse(mod.Migration.atomic)
        self.assertEqual(mod.Migration.dependencies, [('startScan', '0036_uniq_port_ip_number')])
        op = mod.Migration.operations[0]
        self.assertEqual(type(op).__name__, 'AddIndexConcurrently')
        self.assertEqual(op.index.name, 'sub_lower_name_idx')
        self.assertEqual(max(p.name for p in (WEB / 'startScan' / 'migrations').glob('0*.py')), '0037_subdomain_lower_name_idx.py')

    def test_the_name_lookups_of_manual_only_read_it(self):
        # the statements of other_holder and _holders, as they are written there
        one = (Subdomain._base_manager.filter(target_domain__project_id=self.project.id).exclude(target_domain__discovery_mode=Domain.DISCOVERY_MANUAL)
               .annotate(lowered=Lower('name')).filter(lowered='h7.example.org').select_related('target_domain').order_by('-id'))
        many = (Subdomain._base_manager.filter(target_domain__project_id=self.project.id).annotate(lowered=Lower('name'))
                .filter(lowered__in=['h7.example.org', 'h8.example.org']).values_list('lowered', 'target_domain__discovery_mode').distinct())
        self.assertIn('sub_lower_name_idx', plan(one[:1]))
        self.assertIn('sub_lower_name_idx', plan(many))

    def test_manual_only_answers_as_before(self):
        self.assertEqual(manual_only.other_holder(self.project.id, 'H7.Example.org.'), self.domain)
        self.assertIsNone(manual_only.other_holder(self.project.id, 'absent.example.org'))
        self.assertEqual(manual_only.only_manual_hosts(self.project.id, ['h7.example.org']), set())


class WarmupRunTests(SimpleTestCase):
    def test_run_times_every_step_of_the_role_and_logs_one_line(self):
        calls = []
        steps = {'web': (('a', lambda role, deadline: calls.append(('a', role)) or 'ok'), ('b', lambda role, deadline: 'built'))}
        with mock.patch.object(warmup, 'STEPS', steps), self.assertLogs('cveFeed.warmup', 'INFO') as logs:
            out = warmup.run('web')
        self.assertEqual(calls, [('a', 'web')])
        self.assertEqual({k: v[0] for k, v in out.items()}, {'a': 'ok', 'b': 'built'})
        self.assertTrue(all(isinstance(v[1], int) for v in out.values()))
        self.assertEqual(len(logs.records), 1)
        self.assertIn('startup warm-up (web', logs.output[0])
        self.assertIn('a ', logs.output[0])
        self.assertIn(' ms (built)', logs.output[0])

    def test_a_failing_step_never_raises_and_the_next_step_still_runs(self):
        def boom(role, deadline):
            raise RuntimeError('database gone')
        steps = {'web': (('boom', boom), ('next', lambda role, deadline: 'ok'))}
        with mock.patch.object(warmup, 'STEPS', steps), self.assertLogs('cveFeed.warmup', 'INFO'):
            out = warmup.run('web')
        self.assertEqual(out['boom'][0], 'failed: RuntimeError')
        self.assertEqual(out['next'][0], 'ok')

    def test_no_step_starts_after_the_budget(self):
        ran = []
        steps = {'web': (('slow', lambda role, deadline: time.sleep(0.05) or ran.append(1) or 'ok'), ('late', lambda role, deadline: ran.append(2) or 'ok'))}
        with mock.patch.object(warmup, 'STEPS', steps), self.assertLogs('cveFeed.warmup', 'INFO'):
            out = warmup.run('web', budget=0.01)
        self.assertEqual(ran, [1])
        self.assertEqual(out['late'], ('skipped: out of time', 0))

    def test_it_closes_its_database_connections_when_it_ends(self):
        with mock.patch.object(warmup, 'STEPS', {'web': ()}), mock.patch.object(warmup, '_close_connections') as close, \
                self.assertLogs('cveFeed.warmup', 'INFO'):
            warmup.run('web')
        close.assert_called_once()

    def test_it_warms_shared_public_data_only(self):
        """Nothing per tenant: no tenancy snapshot, exclusion list, do-not-scan gate, current scan ids, Overview, alert or stats snapshot."""
        self.assertEqual([name for name, _ in warmup.STEPS['web']], ['urls', 'service_features', 'catalog_counts'])
        self.assertEqual([name for name, _ in warmup.STEPS['celery']], ['service_features'])
        src = (WEB / 'cveFeed' / 'warmup.py').read_text()
        code = src.split('"""', 2)[2]  # the module docstring names what is deliberately left out
        for name in ('tenancy', 'exclusions', 'current_scans', 'snapshot_cache', 'overview', 'situations', 'cached_stats_snapshot', 'excluded_addresses'):
            self.assertNotIn(name, code)


class WarmupStartTests(SimpleTestCase):
    def setUp(self):
        warmup._started['pid'] = None
        self.addCleanup(warmup._started.update, pid=None)

    def test_start_returns_at_once_and_runs_in_a_daemon_thread_once_per_process(self):
        ran = threading.Event()
        threads = []
        real_thread = threading.Thread

        def spy(*args, **kwargs):
            t = real_thread(*args, **kwargs)
            threads.append(t)
            return t
        with mock.patch.object(warmup, 'run', side_effect=lambda role: (time.sleep(0.3), ran.set())), mock.patch.object(warmup.threading, 'Thread', spy), \
                mock.patch.dict(os.environ, {'CVENGINE_WARMUP': '1'}):
            t0 = time.monotonic()
            self.assertTrue(warmup.start('web', delay=0))
            self.assertLess(time.monotonic() - t0, 0.2)  # it never blocks the process that starts it
            self.assertFalse(warmup.start('web', delay=0))  # once per process
            self.assertFalse(warmup.start('celery', delay=0))
            self.assertTrue(ran.wait(5))
        self.assertEqual(len(threads), 1)
        self.assertTrue(threads[0].daemon)

    def test_the_switch_turns_it_off(self):
        for value in ('0', 'false', 'no', 'off', 'OFF'):
            with mock.patch.dict(os.environ, {'CVENGINE_WARMUP': value}), mock.patch.object(warmup.threading, 'Thread') as thread:
                self.assertFalse(warmup.start('web'))
                thread.assert_not_called()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('CVENGINE_WARMUP', None)
            self.assertTrue(warmup.enabled())  # default on

    def test_an_unknown_role_or_a_failing_thread_start_is_refused_without_raising(self):
        self.assertFalse(warmup.start('beat'))
        with mock.patch.object(warmup.threading, 'Thread', side_effect=RuntimeError('cannot start new thread')):
            self.assertFalse(warmup.start('web'))

    def test_a_forked_child_starts_its_own(self):
        with mock.patch.object(warmup.threading, 'Thread') as thread:
            warmup._started['pid'] = -1  # started in a parent before a fork: a different pid
            self.assertTrue(warmup.start('web'))
            thread.assert_called_once()


class FakeCache:
    def __init__(self):
        self.data = {}

    def add(self, key, value, timeout=None):
        if key in self.data:
            return False
        self.data[key] = value
        return True

    def get(self, key, default=None):
        return self.data.get(key, default)

    def delete(self, key):
        self.data.pop(key, None)


class ServiceFeatureStepTests(SimpleTestCase):
    def setUp(self):
        self.cache = FakeCache()
        patcher = mock.patch('django.core.cache.cache', self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_celery_lane_builds_it_under_the_lock_and_frees_the_lock(self):
        with mock.patch('cveFeed.service_features.index') as index:
            self.assertEqual(warmup.warm_service_features('celery', time.monotonic() + 5), 'built')
        index.assert_called_once()
        self.assertNotIn(warmup.BUILD_LOCK, self.cache.data)

    def test_a_web_worker_never_starts_a_full_build_and_waits_without_a_connection(self):
        """No shared copy: a web worker (statements cut at 30 s) waits for a Celery lane to share one, and gives up at the deadline."""
        from cveFeed import service_features
        with mock.patch('cveFeed.service_features.index') as index, mock.patch.object(warmup, 'POLL_SECONDS', 0.01), \
                mock.patch.object(warmup, '_close_connections') as close:
            result = warmup.warm_service_features('web', time.monotonic() + 0.1)
        index.assert_not_called()
        self.assertTrue(result.startswith('skipped'))
        self.assertTrue(close.called)  # no connection held while it waits
        self.cache.data[service_features.INDEX_CACHE_KEY] = {'stamp': None}
        with mock.patch('cveFeed.service_features.index') as index:
            self.assertEqual(warmup.warm_service_features('web', time.monotonic() + 5), 'built')  # a shared copy exists: take it
        index.assert_called_once()

    def test_a_process_waits_while_another_builds_then_takes_the_shared_copy(self):
        from cveFeed import service_features
        self.cache.data[warmup.BUILD_LOCK] = 'other'
        polls = []

        def sleep(seconds):
            polls.append(seconds)
            if len(polls) == 2:  # the other process finishes and shares its copy
                self.cache.data.pop(warmup.BUILD_LOCK)
                self.cache.data[service_features.INDEX_CACHE_KEY] = {'stamp': None}
        with mock.patch('cveFeed.service_features.index') as index, mock.patch.object(warmup.time, 'sleep', sleep), \
                mock.patch.object(warmup, '_close_connections'):
            self.assertEqual(warmup.warm_service_features('celery', time.monotonic() + 30), 'built')
        self.assertEqual(len(polls), 2)
        index.assert_called_once()


class WarmupConnectionTests(TransactionTestCase):
    def test_the_warmup_thread_leaves_no_open_connection(self):
        """A real run in its own thread: the step uses the database, and the thread's connection is closed when it ends."""
        seen = {}

        def step(role, deadline):
            with connections['default'].cursor() as cursor:
                cursor.execute('SELECT 1')
            seen['conn'] = connections['default']
            return 'ok'
        with mock.patch.object(warmup, 'STEPS', {'web': (('db', step),)}), self.assertLogs('cveFeed.warmup', 'INFO'):
            t = threading.Thread(target=warmup.run, args=('web',))
            t.start()
            t.join(10)
        self.assertIsNone(seen['conn'].connection)


class WhoStartsItTests(SimpleTestCase):
    def test_the_web_workers_and_the_celery_lanes_start_it(self):
        wsgi = (WEB / 'cvengine' / 'wsgi.py').read_text()
        self.assertIn("warmup.start('web')", wsgi)
        celery = (WEB / 'cvengine' / 'celery.py').read_text()
        block = celery.split('def start_warmup', 1)[1].split('\n\n\n', 1)[0]
        self.assertIn("warmup.start('celery')", block)
        self.assertIn('@worker_ready.connect()\ndef start_warmup', celery)

    def test_nothing_else_starts_it(self):
        """watchdog_tick (a manage.py command every 30 s) and celery_healthcheck.py (a fresh process every minute) must never run it: only the
        two hooks above call ``warmup.start``, and neither the app config nor those two import them."""
        callers = []
        for path in WEB.rglob('*.py'):
            rel = path.relative_to(WEB).as_posix()
            if rel.startswith('tests/') or rel == 'cveFeed/warmup.py':
                continue
            if 'warmup.start(' in path.read_text(errors='ignore'):
                callers.append(rel)
        self.assertEqual(sorted(callers), ['cvengine/celery.py', 'cvengine/wsgi.py'])
        for rel in ('cveFeed/management/commands/watchdog_tick.py', 'celery_healthcheck.py', 'cveFeed/apps.py', 'cveFeed/watchdog.py'):
            text = (WEB / rel).read_text()
            self.assertNotIn('warmup', text, rel)
            self.assertNotIn('cvengine.wsgi', text, rel)
        self.assertNotIn('import django', (WEB / 'celery_healthcheck.py').read_text())

    def test_the_switch_is_documented(self):
        self.assertIn('`CVENGINE_WARMUP`', (WEB.parent / 'docs' / 'CONFIGURATION.md').read_text())
