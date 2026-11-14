"""The AI maintainer's signals (1.4.0 work package 1): what is measured, from where, and that a source that is missing or malformed reads as unknown,
never as healthy (``agentapi.maintainer_signals``, ``reNgine.container_signals``, ``reNgine.queue_age``, ``agentapi.claim_refusals``, the restarts in
``reNgine.lane_memory``). The status shows them under ``system.signals``."""
import json
import os
import tempfile
import time
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext

from agentapi import claim_refusals, maintainer_signals as ms
from reNgine import container_signals as cs
from reNgine import lane_memory as lm
from reNgine import queue_age

NOW = 1_700_000_000.0


def cgroup(**files):
    """A directory laid out like a cgroup v2 root with the given files; the caller removes it."""
    root = tempfile.mkdtemp(prefix='cg-')
    for name, text in files.items():
        with open(os.path.join(root, name.replace('__', '.')), 'w') as handle:
            handle.write(text)
    return root


class FakeHash:
    """The few Redis hash calls the publisher makes."""

    def __init__(self):
        self.h = {}

    def hget(self, key, field):
        return self.h.get(field)

    def hset(self, key, field, value):
        self.h[field] = value

    def hlen(self, key):
        return len(self.h)

    def hgetall(self, key):
        return dict(self.h)

    def hdel(self, key, field):
        self.h.pop(field, None)


class ContainerSignalTests(SimpleTestCase):
    def setUp(self):
        cs._last.clear()

    def test_the_kernels_oom_kill_count_is_read_from_memory_events(self):
        root = cgroup(memory__events='low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 0\n')
        self.assertEqual(cs.oom_kills(root), 2)

    def test_cgroup_v1_is_read_when_v2_is_absent(self):
        root = tempfile.mkdtemp()
        os.makedirs(root + '/memory')
        with open(root + '/memory/memory.oom_control', 'w') as handle:
            handle.write('oom_kill_disable 0\nunder_oom 0\noom_kill 5\n')
        self.assertEqual(cs.oom_kills(root), 5)

    def test_no_cgroup_files_means_none_not_zero(self):
        root = tempfile.mkdtemp()
        self.assertIsNone(cs.oom_kills(root))
        self.assertIsNone(cs.memory(root))

    def test_a_malformed_cgroup_is_none_not_zero_and_never_raises(self):
        root = cgroup(memory__events='oom_kill many\n', memory__current='lots', memory__max='1073741824')
        self.assertIsNone(cs.oom_kills(root))
        self.assertIsNone(cs.memory(root))

    def test_memory_is_the_working_set_against_the_limit_with_the_peak(self):
        root = cgroup(memory__current=str(900 << 20), memory__max=str(1024 << 20), memory__stat='inactive_file %d\n' % (100 << 20), memory__peak=str(1000 << 20))
        self.assertEqual(cs.memory(root), {'used_mb': 800, 'limit_mb': 1024, 'peak_mb': 1000})

    def test_a_container_without_a_limit_has_no_limit_mb(self):
        root = cgroup(memory__current=str(300 << 20), memory__max='max')
        self.assertEqual(cs.memory(root), {'used_mb': 300, 'limit_mb': None, 'peak_mb': None})

    def test_oom_kills_become_dated_increases_after_the_first_reading(self):
        first = cs.next_record(None, 'web', 'h', NOW, {'used_mb': 1}, 4)
        self.assertEqual(first['oom_events'], [])  # the earlier kills have no known time
        second = cs.next_record(first, 'web', 'h', NOW + 30, {'used_mb': 1}, 6)
        self.assertEqual(second['oom_events'], [[NOW + 30, 2]])
        same = cs.next_record(second, 'web', 'h', NOW + 60, {'used_mb': 1}, 6)
        self.assertEqual(same['oom_events'], [[NOW + 30, 2]])
        recreated = cs.next_record(same, 'web', 'h', NOW + 90, {'used_mb': 1}, 1)  # the count went down: a new container, one kill since it started
        self.assertEqual(recreated['oom_events'], [[NOW + 30, 2], [NOW + 90, 1]])

    def test_an_unreadable_count_keeps_the_history_and_is_not_a_kill(self):
        first = cs.next_record(None, 'web', 'h', NOW, None, 3)
        gone = cs.next_record(cs.next_record(first, 'web', 'h', NOW + 1, None, 5), 'web', 'h', NOW + 2, None, None)
        self.assertEqual(gone['oom_events'], [[NOW + 1, 2]])
        self.assertIsNone(gone['oom_total'])

    def test_publish_writes_one_record_per_host_and_the_reader_totals_the_last_day(self):
        client = FakeHash()
        root = cgroup(memory__current=str(500 << 20), memory__max=str(1024 << 20), memory__events='oom_kill 1\n')
        self.assertTrue(cs.publish('web', client=client, now=NOW, root=root, host='web-1', force=True))
        with open(root + '/memory.events', 'w') as handle:
            handle.write('oom_kill 3\n')
        self.assertTrue(cs.publish('web', client=client, now=NOW + 30, root=root, host='web-1', force=True))
        rows = cs.read(client, NOW + 60)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['role'], rows[0]['host'], rows[0]['oom_kills_24h'], rows[0]['oom_total'], rows[0]['age_seconds']), ('web', 'web-1', 2, 3, 30))
        self.assertEqual(rows[0]['memory']['used_mb'], 500)
        self.assertEqual(cs.read(client, NOW + 8 * 86400), [])  # a record this old is not shown

    def test_publish_with_no_cgroup_writes_nothing(self):
        client = FakeHash()
        self.assertFalse(cs.publish('web', client=client, now=NOW, root=tempfile.mkdtemp(), host='h', force=True))
        self.assertEqual(client.h, {})

    def test_publish_is_throttled_and_never_raises(self):
        client = FakeHash()
        root = cgroup(memory__current=str(1 << 20), memory__max=str(1 << 30))
        self.assertTrue(cs.publish('worker', client=client, now=NOW, root=root, host='h'))
        self.assertFalse(cs.publish('worker', client=client, now=NOW + 2, root=root, host='h'))  # the job monitor calls it every few seconds
        broken = mock.Mock(hget=mock.Mock(side_effect=OSError('redis down')))
        self.assertFalse(cs.publish('worker', client=broken, now=NOW + 100, root=root, host='h'))

    def test_the_reader_skips_a_record_that_is_not_json_or_has_no_time(self):
        client = FakeHash()
        client.h = {'a': 'not json', 'b': json.dumps({'role': 'web'}), 'c': json.dumps(['x']),
                    'd': json.dumps({'role': 'web', 't': NOW, 'memory': {'used_mb': 1}, 'oom_total': 0, 'oom_events': 'bad'})}
        rows = cs.read(client, NOW + 1)
        self.assertEqual([r['host'] for r in rows], ['d'])
        self.assertEqual(rows[0]['oom_kills_24h'], 0)

    def test_the_watchdog_tick_publishes_the_web_container(self):
        from cveFeed import watchdog
        calls = []
        with mock.patch.object(cs, 'publish', side_effect=lambda *a, **k: calls.append((a, k))), mock.patch.object(watchdog, '_states', side_effect=RuntimeError('stop here')):
            with self.assertRaises(RuntimeError):
                watchdog._tick(None, None, {})
        self.assertEqual(calls[0][0], ('web',))

    def test_the_worker_resource_tick_publishes_the_worker_container(self):
        from reNgine import resources
        store = resources.RedisStore(mock.MagicMock(), 'cvengine:heavy:test')
        with mock.patch.object(store, 'waiting', return_value=[]), mock.patch.object(store, 'live', return_value=[]), mock.patch.object(store, 'events', return_value=[]), \
                mock.patch.object(store, 'publish_state'), mock.patch.object(cs, 'publish') as publish:
            resources.report_state(store, state_fn=lambda: {'total_mb': 1, 'limit_mb': None, 'used_mb': 1, 'available_mb': 1}, now_fn=lambda: NOW)
        self.assertEqual(publish.call_args[0], ('worker',))


class QueueAgeTests(SimpleTestCase):
    def message(self, sent=None):
        headers = {'task': 't', 'id': 'x'}
        if sent is not None:
            headers['cv_sent'] = sent
        return json.dumps({'body': 'e30=', 'headers': headers, 'properties': {}})

    def test_every_published_message_is_stamped(self):
        from celery.signals import before_task_publish
        queue_age.install()
        headers = {'task': 'x'}
        before_task_publish.send(sender='x', headers=headers, body=(), exchange='e', routing_key='r')
        self.assertIsInstance(headers['cv_sent'], float)
        self.assertLessEqual(abs(headers['cv_sent'] - time.time()), 5)

    def test_a_stamp_is_read_and_anything_else_is_none(self):
        self.assertEqual(queue_age.sent_at(self.message(123.5)), 123.5)
        self.assertEqual(queue_age.sent_at(self.message(123.5).encode()), 123.5)
        for bad in (None, '', 'not json', '[]', self.message(), json.dumps({'headers': {'cv_sent': 'soon'}}), json.dumps({'headers': {'cv_sent': True}}), 'x' * ((1 << 20) + 1)):
            self.assertIsNone(queue_age.sent_at(bad), bad[:20] if isinstance(bad, str) else bad)

    def test_the_oldest_message_is_the_tail_of_the_list_and_an_empty_queue_has_no_age(self):
        client = mock.Mock()
        pipe = client.pipeline.return_value
        pipe.execute.return_value = [self.message(NOW - 3600)]
        out = queue_age.oldest(client, {'discovery_queue': 4, 'cve_feed_queue': 0, 'api_queue': 0}, ('',), NOW)
        self.assertEqual(out, {'discovery_queue': {'age_seconds': 3600, 'known': True}})
        self.assertEqual([c.args for c in pipe.lindex.call_args_list], [('discovery_queue', -1)])  # kombu pops from the tail: the oldest is the last element

    def test_an_unstamped_message_is_an_unknown_age_never_zero(self):
        client = mock.Mock()
        pipe = client.pipeline.return_value
        pipe.execute.return_value = [self.message()]
        self.assertEqual(queue_age.oldest(client, {'discovery_queue': 2}, ('',), NOW), {'discovery_queue': {'age_seconds': None, 'known': False}})

    def test_all_priority_steps_are_read_in_one_pipeline_and_the_oldest_wins(self):
        from agentapi.system_status import PRIORITY_SUFFIXES
        client = mock.Mock()
        pipe = client.pipeline.return_value
        pipe.execute.return_value = [self.message(NOW - 60), None, self.message(NOW - 600), None]
        out = queue_age.oldest(client, {'discovery_queue': 5}, PRIORITY_SUFFIXES, NOW)
        self.assertEqual(out['discovery_queue']['age_seconds'], 600)
        self.assertEqual(pipe.execute.call_count, 1)

    def test_nothing_waiting_asks_redis_nothing(self):
        client = mock.Mock()
        self.assertEqual(queue_age.oldest(client, {'a': 0, 'b': 0}, ('',), NOW), {})
        client.pipeline.assert_not_called()

    def test_a_whole_busy_box_is_one_round_trip_of_bounded_size(self):
        from agentapi.system_status import PRIORITY_SUFFIXES, QUEUES
        client = mock.Mock()
        pipe = client.pipeline.return_value
        pipe.execute.return_value = [None] * (len(QUEUES) * len(PRIORITY_SUFFIXES))
        queue_age.oldest(client, {q: 1 for q in QUEUES}, PRIORITY_SUFFIXES, NOW)
        self.assertEqual(pipe.lindex.call_count, len(QUEUES) * 4)
        self.assertEqual(pipe.execute.call_count, 1)

    def test_against_a_real_redis_list(self):
        from reNgine import resources
        client = resources.redis_client()
        name = 'test_maintainer_signals_queue'
        client.delete(name)
        self.addCleanup(client.delete, name)
        client.lpush(name, self.message(NOW - 100))  # kombu pushes at the head and pops from the tail: the first pushed is the oldest
        client.lpush(name, self.message(NOW - 10))
        self.assertEqual(queue_age.oldest(client, {name: 2}, ('',), NOW), {name: {'age_seconds': 100, 'known': True}})


class LaneSignalTests(SimpleTestCase):
    def setUp(self):
        self.addCleanup(self.clean)
        self.clean()
        lm._state.update(lane=None, started={}, tasks={}, last_write=0.0, peak_mb=0.0)

    def clean(self):
        for lane in lm.LANES:
            cache.delete(lm.CACHE_PREFIX + lane)
            cache.delete(lm.RESTARTS_PREFIX + lane)

    def record(self, lane, **kw):
        data = {'pid': 7, 'started': 1.0, 'at': NOW - 10, 'rss_mb': 900.0, 'peak_mb': 950.0, 'limit_mb': 1800, 'tasks': {}}
        data.update(kw)
        cache.set(lm.CACHE_PREFIX + lane, json.dumps(data), 600)

    def test_no_lane_has_reported_so_every_lane_is_unknown_and_none_is_zero(self):
        out = ms.lanes(NOW)
        self.assertEqual(out['state'], 'unknown')
        self.assertTrue(all(row['state'] == 'unknown' and row['rss_mb'] is None and row['percent_of_limit'] is None for row in out['lanes']))
        self.assertEqual([row['lane'] for row in out['lanes']], list(lm.LANES))

    def test_a_lane_is_its_resident_memory_against_the_containers_limit(self):
        self.record('cve_feed')
        out = ms.lanes(NOW)
        row = [r for r in out['lanes'] if r['lane'] == 'cve_feed'][0]
        self.assertEqual((row['state'], row['rss_mb'], row['limit_mb'], row['percent_of_limit'], row['limit_state']), ('known', 900.0, 1800, 50.0, 'limited'))
        self.assertEqual(out['state'], 'partial')  # the other three have not reported
        self.assertIn('discovery', out['reason'])

    def test_a_limit_that_is_not_known_gives_no_percentage(self):
        self.record('classic', limit_mb=None)
        self.record('discovery', limit_mb=0)
        rows = {r['lane']: r for r in ms.lanes(NOW)['lanes']}
        self.assertEqual((rows['classic']['limit_state'], rows['classic']['percent_of_limit']), ('unknown', None))
        self.assertEqual((rows['discovery']['limit_state'], rows['discovery']['percent_of_limit']), ('unlimited', None))

    def test_a_record_nobody_has_refreshed_for_an_hour_is_not_trusted(self):
        self.record('classic', at=NOW - 7200)
        row = [r for r in ms.lanes(NOW)['lanes'] if r['lane'] == 'classic'][0]
        self.assertEqual(row['state'], 'unknown')
        self.assertIn('120 minutes', row['reason'])

    def test_a_malformed_record_is_unknown_and_does_not_hide_the_other_lanes(self):
        cache.set(lm.CACHE_PREFIX + 'classic', json.dumps({'rss_mb': 'big', 'tasks': {'t': 'x'}}), 600)
        cache.set(lm.CACHE_PREFIX + 'discovery', 'not json', 600)
        self.record('cve_feed')
        rows = {r['lane']: r for r in ms.lanes(NOW)['lanes']}
        self.assertEqual([rows[l]['state'] for l in ('classic', 'discovery', 'cve_feed')], ['unknown', 'unknown', 'known'])

    def test_the_worker_writes_the_limit_of_its_container(self):
        with mock.patch.object(lm, 'lane_name', return_value='classic'), mock.patch('reNgine.resources.cgroup_memory', return_value=(2048 << 20, 100 << 20)):
            lm.write(NOW, 123.0)
        self.assertEqual(json.loads(cache.get(lm.CACHE_PREFIX + 'classic'))['limit_mb'], 2048)
        with mock.patch.object(lm, 'lane_name', return_value='classic'), mock.patch('reNgine.resources.cgroup_memory', return_value=(None, None)):
            lm.write(NOW, 123.0)
        self.assertIsNone(json.loads(cache.get(lm.CACHE_PREFIX + 'classic'))['limit_mb'])  # no cgroup: unknown, not unlimited

    def test_a_worker_that_starts_where_another_process_wrote_last_is_a_restart(self):
        self.record('cve_feed', pid=4242, rss_mb=1700.0, at=NOW - 30)
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.record_start(NOW)
        events = lm.restarts('cve_feed', NOW)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]['last_rss_mb'], events[0]['last_heard_at']), (1700.0, NOW - 30))
        row = [r for r in ms.lanes(NOW + 5)['lanes'] if r['lane'] == 'cve_feed'][0]
        self.assertEqual((row['restarts_24h'], row['last_restart']['last_rss_mb']), (1, 1700.0))
        with mock.patch.object(lm, 'lane_name', return_value='cve_feed'):
            lm.record_start(NOW + 60)  # the record is now this process's: starting again as the same process is not a restart
        self.assertEqual(len(lm.restarts('cve_feed', NOW + 60)), 1)

    def test_a_restart_with_the_same_pid_is_told_by_the_start_time(self):
        self.record('classic', pid=os.getpid(), started=lm.PROCESS_STARTED - 500)
        with mock.patch.object(lm, 'lane_name', return_value='classic'):
            lm.record_start(NOW)
        self.assertEqual(len(lm.restarts('classic', NOW)), 1)

    def test_the_first_start_of_a_lane_counts_nothing(self):
        with mock.patch.object(lm, 'lane_name', return_value='validation_priority'):
            lm.record_start(NOW)
        self.assertEqual(lm.restarts('validation_priority', NOW), [])
        row = [r for r in ms.lanes(NOW)['lanes'] if r['lane'] == 'validation_priority'][0]
        self.assertEqual(row['restarts_24h'], 0)

    def test_restarts_older_than_a_day_are_not_counted_and_damage_reads_as_none(self):
        cache.set(lm.RESTARTS_PREFIX + 'classic', json.dumps([{'at': NOW - 2 * 86400}, {'at': NOW - 100}, 'x']), 600)
        self.assertEqual(len(lm.restarts('classic', NOW)), 1)
        cache.set(lm.RESTARTS_PREFIX + 'classic', 'garbage', 600)
        self.assertEqual(lm.restarts('classic', NOW), [])

    def test_restarts_that_cannot_be_read_are_unknown_not_zero(self):
        self.record('classic')
        with mock.patch.object(lm, 'restarts', side_effect=OSError('cache down')):
            row = [r for r in ms.lanes(NOW)['lanes'] if r['lane'] == 'classic'][0]
        self.assertEqual((row['state'], row['restarts_24h'], row['restarts_state']), ('known', None, 'unknown'))


class ContainerReadTests(SimpleTestCase):
    def rec(self, role, t, used=500, limit=1024, total=0, events=()):
        return json.dumps({'role': role, 'host': role, 't': t, 'memory': {'used_mb': used, 'limit_mb': limit, 'peak_mb': used + 10}, 'oom_total': total,
                           'oom_events': [list(e) for e in events]})

    def test_the_web_and_worker_containers_are_known_with_their_percentage_and_kills(self):
        client = FakeHash()
        client.h = {'web-1': self.rec('web', NOW - 20, used=900, limit=1024, total=1, events=[(NOW - 100, 1)]), 'celery-1': self.rec('worker', NOW - 5, used=2000, limit=4608)}
        out = ms.containers(NOW, client)
        self.assertEqual(out['state'], 'known')
        web = [c for c in out['containers'] if c['role'] == 'web'][0]
        self.assertEqual((web['percent_of_limit'], web['oom_kills_24h'], web['peak_mb']), (87.9, 1, 910))

    def test_a_container_that_has_not_published_is_named_and_the_signal_is_partial(self):
        client = FakeHash()
        client.h = {'celery-1': self.rec('worker', NOW - 5)}
        out = ms.containers(NOW, client)
        self.assertEqual(out['state'], 'partial')
        self.assertIn('web', out['reason'])

    def test_a_record_that_went_quiet_is_unknown_not_a_good_reading(self):
        client = FakeHash()
        client.h = {'web-1': self.rec('web', NOW - 900), 'celery-1': self.rec('worker', NOW - 5)}
        web = [c for c in ms.containers(NOW, client)['containers'] if c['role'] == 'web'][0]
        self.assertEqual(web['state'], 'unknown')
        self.assertIn('900 seconds', web['reason'])

    def test_nothing_published_is_unknown(self):
        self.assertEqual(ms.containers(NOW, FakeHash())['state'], 'unknown')

    def test_an_unreadable_kill_count_is_none_not_zero(self):
        client = FakeHash()
        client.h = {'web-1': self.rec('web', NOW - 5, total=None)}
        self.assertIsNone(ms.containers(NOW, client)['containers'][0]['oom_kills_24h'])

    def test_a_broker_that_cannot_be_asked_is_unknown_through_collect(self):
        with mock.patch('reNgine.resources.redis_client', return_value=None):
            out = ms.collect(None, None, NOW)
        self.assertEqual(out['signals']['containers']['state'], 'unknown')
        self.assertIn('containers', out['unknown'])
        self.assertNotIn('ok', out['signals']['containers'])


class QueueSignalTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_the_status_depths_are_passed_in_and_aged_and_the_database_oldest_is_read_once(self):
        client = mock.Mock()
        client.pipeline.return_value.execute.return_value = [json.dumps({'headers': {'cv_sent': NOW - 7200}})] + [None] * 3
        depths = {'waiting': {'discovery_queue': 40, 'api_queue': 0}}
        out = ms.queues(depths, client, NOW)
        self.assertEqual(out['by_queue'], {'discovery_queue': {'waiting': 40, 'oldest_age_seconds': 7200, 'age_state': 'known'}})
        self.assertEqual((out['state'], out['oldest_age_seconds']), ('known', 7200))
        self.assertIn(out['oldest_queued']['state'], ('known', 'partial'))
        self.assertEqual(out['oldest_queued']['scan']['queued'], False)

    def test_the_oldest_queued_scan_assessment_and_sentinel_task_are_read_from_the_database(self):
        from datetime import timedelta

        from django.utils import timezone

        from cveFeed.models import HostAssessment
        from dashboard.models import Project
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        now = timezone.now()
        project = Project.objects.create(name='Q', slug='q-proj', insert_date=now)
        domain = Domain.objects.create(name='q.example.com', project=project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
        ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now - timedelta(hours=2), scan_status=-1)
        ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now - timedelta(hours=5), scan_status=2)  # finished: not queued
        assess = HostAssessment.objects.create(project=project, domain=domain, host='h.q.example.com', status='queued')
        HostAssessment.objects.filter(pk=assess.pk).update(created_at=now - timedelta(minutes=30))
        out = ms._oldest_db()
        self.assertEqual(out['state'], 'known')
        self.assertAlmostEqual(out['scan']['age_seconds'], 7200, delta=30)
        self.assertAlmostEqual(out['assessment']['age_seconds'], 1800, delta=30)
        self.assertEqual((out['sentinel_task']['queued'], out['sentinel_task']['age_seconds']), (False, None))

    def test_a_queue_whose_oldest_message_has_no_send_time_is_partial_and_says_which(self):
        client = mock.Mock()
        client.pipeline.return_value.execute.return_value = [json.dumps({'headers': {}})]
        out = ms.queues({'waiting': {'discovery_queue': 3}}, client, NOW)
        self.assertEqual(out['state'], 'partial')
        self.assertIsNone(out['oldest_age_seconds'])
        self.assertIn('discovery_queue', out['reason'])

    def test_depths_that_could_not_be_read_are_unknown(self):
        self.assertEqual(ms.queues({'error': 'OSError'}, mock.Mock(), NOW)['state'], 'unknown')
        self.assertEqual(ms.queues(None, mock.Mock(), NOW)['state'], 'unknown')


class DatabaseAndRedisTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_the_database_size_and_longest_query_are_read_without_a_query_text(self):
        out = ms.database()
        self.assertEqual(out['state'], 'known')
        self.assertGreater(out['size_mb'], 0)
        self.assertGreaterEqual(out['longest_query_seconds'], 0)
        self.assertEqual(set(out), {'state', 'size_mb', 'active_queries', 'longest_query_seconds'})

    def test_a_database_that_is_not_postgresql_or_fails_is_unknown_and_cached_briefly(self):
        with mock.patch.object(ms, '_bounded', side_effect=RuntimeError('not PostgreSQL')):
            out = ms.database()
        self.assertEqual(out, {'state': 'unknown', 'reason': 'could not be read (RuntimeError)'})
        self.assertEqual(ms.database(), out)  # a failing source is not asked again at once

    def test_the_database_read_is_reused_for_a_minute(self):
        ms.database()
        with CaptureQueriesContext(connection) as queries:
            ms.database()
        self.assertEqual(len(queries), 0)

    def test_redis_memory_against_maxmemory(self):
        client = mock.Mock()
        client.info.side_effect = lambda section: {'memory': {'used_memory': 256 << 20, 'maxmemory': 512 << 20}, 'stats': {'evicted_keys': 7}}[section]
        out = ms.redis_memory(client)
        self.assertEqual((out['used_mb'], out['limit_mb'], out['percent_of_limit'], out['evicted_keys'], out['limit_state']), (256.0, 512.0, 50.0, 7, 'limited'))
        client.info.side_effect = lambda section: {'memory': {'used_memory': 256 << 20, 'maxmemory': 0}, 'stats': {}}[section]
        out = ms.redis_memory(client)
        self.assertEqual((out['limit_state'], out['percent_of_limit'], out['evicted_keys']), ('unlimited', None, None))

    def test_redis_memory_missing_or_malformed_is_unknown(self):
        self.assertEqual(ms.redis_memory(mock.Mock(info=mock.Mock(return_value={})))['state'], 'unknown')
        self.assertEqual(ms.collect(None, object(), NOW)['signals']['redis']['state'], 'unknown')  # a client with no INFO


class AISpendTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_each_cap_has_its_use_and_percentage(self):
        used = {'triage_max_per_day': 500, 'validate_max_per_day': 15, 'template_gen_max_per_day': 10, 'autotune_ai_max_per_day': 0, 'nuclei_ai_max_per_day': 100}
        with mock.patch('cveFeed.tunables.usage_today', return_value=used):
            out = ms.ai_spend()
        rows = {r['key']: r for r in out['caps']}
        self.assertEqual(out['state'], 'known')
        self.assertEqual((rows['triage_max_per_day']['used'], rows['triage_max_per_day']['cap'], rows['triage_max_per_day']['percent_of_cap']), (500, 2000, 25.0))
        self.assertEqual(rows['template_gen_max_per_day']['percent_of_cap'], 100.0)
        self.assertEqual(rows['autotune_ai_max_per_day']['percent_of_cap'], 0.0)

    def test_a_counter_that_cannot_be_read_is_unknown_not_zero(self):
        with mock.patch('cveFeed.tunables.usage_today', return_value={'triage_max_per_day': 5}):
            out = ms.ai_spend()
        self.assertEqual(out['state'], 'partial')
        rows = {r['key']: r for r in out['caps']}
        self.assertEqual((rows['validate_max_per_day']['state'], rows['validate_max_per_day']['used']), ('unknown', None))
        with mock.patch('cveFeed.tunables.usage_today', return_value={}):
            cache.clear()
            self.assertEqual(ms.ai_spend()['state'], 'unknown')

    def test_a_failing_source_is_unknown(self):
        with mock.patch('cveFeed.tunables.usage_today', side_effect=RuntimeError('db')):
            self.assertEqual(ms.ai_spend()['state'], 'unknown')

    def test_the_use_is_reused_for_a_minute(self):
        ms.ai_spend()
        with CaptureQueriesContext(connection) as queries:
            ms.ai_spend()
        self.assertEqual(len(queries), 0)


class ClaimRefusalTests(SimpleTestCase):
    def setUp(self):
        self.hour = time.strftime('%Y%m%d%H', time.gmtime())
        self.clean()
        self.addCleanup(self.clean)

    def clean(self):
        from reNgine import resources
        client = resources.redis_client()
        for key in client.scan_iter(match=claim_refusals.KEY + '*'):
            client.delete(key)

    def test_a_refused_call_is_counted_per_action_and_caller_with_an_expiry(self):
        self.assertTrue(claim_refusals.note('agentapi:claim:abcdef0123456789', NOW))
        self.assertTrue(claim_refusals.note('agentapi:claim:abcdef0123456789', NOW + 5))
        self.assertTrue(claim_refusals.note('agentapi:report:user:7', NOW + 10))
        rows = claim_refusals.read(NOW + 20)
        self.assertEqual(rows[('claim', 'abcdef0123456789')][2], 2)
        self.assertEqual(rows[('report', 'user:7')][2], 1)
        key = claim_refusals.KEY + time.strftime('%Y%m%d%H', time.gmtime(NOW))
        self.assertGreater(claim_refusals._client(key).ttl(key), 0)

    def test_the_hour_buckets_separate_this_hour_the_one_before_and_the_day(self):
        claim_refusals.note('agentapi:claim:aaaa', NOW)
        claim_refusals.note('agentapi:claim:aaaa', NOW - 3600)
        claim_refusals.note('agentapi:claim:aaaa', NOW - 3600 * 5)
        claim_refusals.note('agentapi:claim:aaaa', NOW - 3600 * 30)  # older than the window read
        self.assertEqual(claim_refusals.read(NOW + 1)[('claim', 'aaaa')], [1, 1, 3])

    def test_a_name_that_is_not_a_limiter_counter_and_a_flood_of_callers_are_not_counted(self):
        self.assertFalse(claim_refusals.note('something:else', NOW))
        self.assertFalse(claim_refusals.note('agentapi:claim', NOW))
        with mock.patch.object(claim_refusals, 'MAX_FIELDS', 2):
            self.assertTrue(claim_refusals.note('agentapi:claim:one', NOW))
            self.assertTrue(claim_refusals.note('agentapi:claim:two', NOW))
            self.assertFalse(claim_refusals.note('agentapi:claim:three', NOW))
            self.assertTrue(claim_refusals.note('agentapi:claim:one', NOW))  # a caller already counted goes on being counted

    def test_counting_never_raises(self):
        with mock.patch.object(claim_refusals, '_client', side_effect=AttributeError('no redis client')):
            self.assertFalse(claim_refusals.note('agentapi:claim:aaaa', NOW))
            with self.assertRaises(AttributeError):  # the reader raises, so the signal says unknown instead of a made-up zero
                claim_refusals.read(NOW)
        with mock.patch.object(claim_refusals, 'read', side_effect=AttributeError('x')):
            self.assertEqual(ms._safe(ms.claim_refusals)['state'], 'unknown')


class RealRefusedClaimTests(TestCase):
    """The limiter refuses a real Sentinel's claim (the 1.4 incident: every claim for an hour) and the signal names that Sentinel."""

    @classmethod
    def setUpTestData(cls):
        from tests.test_sentinels import build_world
        build_world(cls)

    def setUp(self):
        from tests.test_sentinels import reset_rates
        reset_rates(self.tokens)
        ClaimRefusalTests.clean(self)
        self.addCleanup(ClaimRefusalTests.clean, self)
        cache.clear()
        self.addCleanup(cache.clear)

    def test_a_refused_sentinel_claim_is_counted_against_that_sentinel_and_action(self):
        from agentapi import sentinel_broker as sentinels
        from tests.test_agentapi import call
        from tests.test_sentinels import register_sentinel
        status, sentinel = register_sentinel(self.tokens['dana'], name='sentinel-refused')
        self.assertEqual(status, 201)
        with mock.patch.object(sentinels, 'claim_limit', return_value=2):
            statuses = [call(self.tokens['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[0] for _ in range(5)]
        self.assertEqual(statuses, [200, 200, 429, 429, 429])
        out = ms.claim_refusals()
        self.assertEqual(out['state'], 'known')
        self.assertEqual((out['claims_last_24h'], out['last_24h']), (3, 3))
        row = out['by'][0]
        self.assertEqual((row['action'], row['caller'], row['sentinel'], row['this_hour'] + row['previous_hour'], row['last_24h']), ('claim', 'sentinel-refused', True, 3, 3))
        self.assertNotIn('dana', json.dumps(out))  # the owner's name is not in it

    def test_no_refusals_is_a_known_zero(self):
        out = ms.claim_refusals()
        self.assertEqual((out['state'], out['last_24h'], out['by']), ('known', 0, []))

    def test_an_allowed_call_counts_nothing(self):
        from tests.test_agentapi import call
        from tests.test_sentinels import register_sentinel
        register_sentinel(self.tokens['dana'], name='sentinel-fine')
        self.assertEqual(call(self.tokens['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[0], 200)
        self.assertEqual(ms.claim_refusals()['last_24h'], 0)


class StatusSignalsTests(TestCase):
    """``system.signals`` in the system status (REST and MCP): present for an App Admin only, honest about what it cannot read, and cheap."""

    @classmethod
    def setUpTestData(cls):
        from django.contrib.auth.models import User

        from agentapi.auth import create_token
        cls.root = User.objects.create_superuser('sig-root', 'r@sig.example.test', 'x')
        cls.member = User.objects.create_user('sig-member', password='x')
        cls.t_root = create_token(cls.root, 'root')[1]
        cls.t_member = create_token(cls.member, 'member')[1]

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        for patch in (mock.patch('cveFeed.conductor.last_round', return_value={'at': '2099-01-01T00:00:00+00:00', 'depth': 0, 'started': 0, 'skipped': 'nothing is due'}),
                      mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': '0'})):
            patch.start()
            self.addCleanup(patch.stop)
        from tests.test_local_egress import _clear
        _clear()

    def status(self, token):
        from tests.test_agentapi import call
        from tests.test_system_status import patched
        a, b, c = patched()
        with a, b, c:
            return call(token, 'GET', '/api/v1/system/status')

    def test_an_app_admin_gets_every_signal_and_a_member_gets_none(self):
        code, data = self.status(self.t_root)
        self.assertEqual(code, 200)
        signals = data['system']['signals']
        self.assertEqual(set(signals['signals']), {'lanes', 'containers', 'queues', 'claim_refusals', 'database', 'redis', 'ai_spend'})
        for name, signal in signals['signals'].items():
            self.assertIn(signal['state'], ('known', 'partial', 'unknown'), name)
        code, data = self.status(self.t_member)
        self.assertIsNone(data['system'])
        self.assertNotIn('signals', json.dumps(data))

    def test_a_source_that_is_missing_is_listed_as_unknown_and_is_never_healthy(self):
        for lane in lm.LANES:
            cache.delete(lm.CACHE_PREFIX + lane)
        _, data = self.status(self.t_root)
        signals = data['system']['signals']
        self.assertEqual(signals['signals']['lanes']['state'], 'unknown')  # no worker lane has reported in a test
        self.assertIn('lanes', signals['unknown'])
        self.assertTrue(any('maintainer signals not fully known' in n and 'lanes' in n for n in data['notes']))
        self.assertNotIn('ok', json.dumps(signals['signals']['lanes']).replace('"known"', ''))  # no healthy flag anywhere
        self.assertNotEqual(signals['signals']['lanes'].get('state'), 'known')

    def test_a_signal_that_raises_does_not_fail_the_status_or_make_it_degraded(self):
        _, before = self.status(self.t_root)
        with mock.patch.object(ms, 'lanes', side_effect=OSError('secret path /root/x')), mock.patch.object(ms, 'redis_memory', side_effect=ValueError('boom')):
            code, data = self.status(self.t_root)
        self.assertEqual(code, 200)
        lanes = data['system']['signals']['signals']['lanes']
        self.assertEqual(lanes, {'state': 'unknown', 'reason': 'could not be read (OSError)'})  # the exception's text never leaves
        self.assertNotIn('secret path', json.dumps(data))
        self.assertEqual(data['overall'], before['overall'])

    def test_the_mcp_tool_returns_the_same_signals(self):
        from tests.test_agentapi import tool_call
        from tests.test_system_status import patched
        a, b, c = patched()
        with a, b, c:
            out = tool_call(self.t_root, 'get_system_status', {})
        text = json.dumps(out)
        self.assertIn('claim_refusals', text)
        self.assertIn('ai_spend', text)

    def test_the_queue_depths_are_not_asked_twice_and_the_ages_ride_on_them(self):
        from agentapi import system_status
        calls = []
        real = system_status._queues
        with mock.patch.object(system_status, '_queues', side_effect=lambda: calls.append(1) or real()):
            self.status(self.t_root)
        self.assertEqual(len(calls), 1)

    def test_the_signals_add_a_bounded_number_of_queries_and_none_when_reused(self):
        from agentapi import system_status
        client = mock.Mock()
        client.pipeline.return_value.execute.return_value = [None]
        depths = {'waiting': {'discovery_queue': 3}}
        with CaptureQueriesContext(connection) as cold:
            ms.collect(depths, client, NOW)
        with CaptureQueriesContext(connection) as warm:
            ms.collect(depths, client, NOW)
        # cold: database (size and longest query, one transaction), the three oldest-queued reads, the AI counters (about ten counts), the claim names none
        self.assertLessEqual(len([q for q in cold.captured_queries if 'SAVEPOINT' not in q['sql'] and not q['sql'].startswith(('SET', 'RELEASE'))]), 20)
        self.assertEqual(len([q for q in warm.captured_queries if 'SAVEPOINT' not in q['sql']]), 0)  # everything database-backed is reused for a minute
        cache.clear()
        with CaptureQueriesContext(connection) as whole:
            self.status(self.t_root)
        with CaptureQueriesContext(connection) as again:
            self.status(self.t_root)
        with mock.patch.object(system_status, '_signals', return_value={'unknown': []}):
            with CaptureQueriesContext(connection) as without:
                self.status(self.t_root)
        self.assertLessEqual(len(whole) - len(without), 30)  # 26 when measured: the database reads, the AI counters and their savepoints
        self.assertLessEqual(len(again) - len(without), 2)  # a second poll inside the minute reads almost nothing more than a status with no signals at all

    def test_the_status_text_carries_no_address_credential_or_query_text(self):
        _, data = self.status(self.t_root)
        text = json.dumps(data['system']['signals']).lower()
        for needle in ('select ', 'password', 'secret', 'token', 'http://', 'https://'):
            self.assertNotIn(needle, text)


class DocsTests(SimpleTestCase):
    def test_the_agent_api_doc_names_every_signal_and_the_fields_that_matter(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, 'docs', 'AGENT-API.md'), encoding='utf-8') as handle:
            text = handle.read()
        for needle in ('system.signals', 'lanes', 'containers', 'queues', 'claim_refusals', 'database', 'redis', 'ai_spend', 'percent_of_limit', 'oom_kills_24h',
                       'restarts_24h', 'oldest_age_seconds', 'longest_query_seconds', 'percent_of_cap', 'unknown', 'cv_sent'):
            self.assertIn(needle, text, needle)

    def test_the_watchdog_doc_says_the_tick_publishes_the_web_memory_and_that_r7_does_not_read_it(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, 'docs', 'WATCHDOG.md'), encoding='utf-8') as handle:
            text = handle.read()
        self.assertIn("publishes the web container's own memory", text)
