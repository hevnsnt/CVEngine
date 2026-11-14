"""A cold graph is built by one request, not by every open tab at once (review finding A6).

The graph's cache key carries its version, which moves on every write during a scan, so each viewer's next poll finds the key empty together. Each used to
build the payload (1.2 s and 19 queries at 20,000 hosts); now one takes a short lock and builds, the rest wait for its answer.
"""
import threading
import time
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase

from cveFeed import views


class GraphSingleFlightTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def stampede(self, workers=10):
        calls, results, errors = [], [], []

        def build(domain_id=None, scan_id=None):
            calls.append(1)
            time.sleep(0.4)  # a graph takes a while to build: the others arrive meanwhile
            return {'nodes': [], 'edges': [], 'n': len(calls)}

        def ask():
            try:
                results.append(views.cached_graph('scope-a', 'v1', None, None))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        with mock.patch.object(views, 'graph_payload', build):
            threads = [threading.Thread(target=ask) for _ in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        return calls, results, errors

    def test_ten_viewers_of_a_cold_graph_build_it_once(self):
        calls, results, errors = self.stampede()
        self.assertEqual(errors, [])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(r['version'] == 'v1' and r['n'] == 1 for r in results))

    def test_the_next_poll_is_served_from_the_cache(self):
        self.stampede(2)
        with mock.patch.object(views, 'graph_payload', side_effect=AssertionError('built twice')):
            self.assertEqual(views.cached_graph('scope-a', 'v1', None, None)['version'], 'v1')

    def test_a_new_version_builds_again(self):
        self.stampede(2)
        with mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': []}) as build:
            self.assertEqual(views.cached_graph('scope-a', 'v2', None, None)['version'], 'v2')
        self.assertEqual(build.call_count, 1)

    def test_a_winner_that_died_does_not_block_the_others_for_ever(self):
        cache.add(views.graph_cache_key('scope-a', 'v1') + ':lock', 'dead', 1)  # a lock nobody will release: it expires on its own
        with mock.patch.object(views, 'GRAPH_WAIT_SECONDS', 0.3), mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': []}) as build:
            self.assertEqual(views.cached_graph('scope-a', 'v1', None, None)['version'], 'v1')
        self.assertEqual(build.call_count, 1)

    def test_a_cache_that_does_not_answer_still_gives_the_graph(self):
        broken = mock.Mock(side_effect=ConnectionError('redis is down'))
        with mock.patch('django.core.cache.cache.get', broken), mock.patch('django.core.cache.cache.add', broken), \
                mock.patch('django.core.cache.cache.set', broken), mock.patch('django.core.cache.cache.delete', broken), \
                mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': []}):
            self.assertEqual(views.cached_graph('scope-a', 'v1', None, None)['version'], 'v1')


class SlowGraphBuildTests(SimpleTestCase):
    """A build longer than the viewers' wait (the collapse alone takes up to 9.9 s in production) must not turn into one build per viewer."""

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def run_viewers(self, workers, build_seconds, wait=0.3):
        calls, results = [], []

        def build(domain_id=None, scan_id=None):
            calls.append(1)
            time.sleep(build_seconds)
            return {'nodes': [], 'edges': [], 'n': len(calls)}

        def ask():
            results.append(views.cached_graph('scope-a', 'v2', None, None))
        with mock.patch.object(views, 'GRAPH_WAIT_SECONDS', wait), mock.patch.object(views, 'graph_payload', build):
            threads = [threading.Thread(target=ask) for _ in range(workers)]
            for t in threads:
                t.start()
                time.sleep(0.02)
            for t in threads:
                t.join()
        return calls, results

    def test_viewers_that_outwait_the_wait_get_the_last_good_graph_marked_stale_and_nobody_builds_twice(self):
        with mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': [], 'n': 0}):
            views.cached_graph('scope-a', 'v1', None, None)  # the graph of the version before is the last good one
        calls, results = self.run_viewers(6, build_seconds=1.2)
        self.assertEqual(len(calls), 1)  # was: every waiter built its own after the wait
        self.assertEqual(len(results), 6)
        stale = [r for r in results if r.get('stale')]
        self.assertEqual(len(stale), 5)
        self.assertTrue(all(r['version'] == 'v1' and r['n'] == 0 for r in stale))  # said to be the older version, so the page asks again
        self.assertEqual([r for r in results if not r.get('stale')][0]['version'], 'v2')
        self.assertEqual(views.cached_graph('scope-a', 'v2', None, None)['version'], 'v2')  # the next poll finds the new one

    def test_with_no_last_good_graph_a_viewer_waits_for_the_builder_instead_of_building(self):
        calls, results = self.run_viewers(4, build_seconds=1.0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(r['version'] == 'v2' and not r.get('stale') for r in results))

    def test_the_refresher_never_waits_and_never_builds_a_graph_a_request_is_building(self):
        cache.add(views.graph_cache_key('scope-a', 'v2') + ':lock', 'a-request', 45)
        started = time.monotonic()
        with mock.patch.object(views, 'graph_payload', side_effect=AssertionError('built a second one')):
            self.assertIsNone(views.cached_graph('scope-a', 'v2', None, None, wait=False))
        self.assertLess(time.monotonic() - started, views.GRAPH_WAIT_SECONDS / 2)  # a refresher that waited would wait the whole GRAPH_WAIT_SECONDS

    def test_the_refresher_builds_a_graph_nobody_is_building(self):
        with mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': []}) as build:
            self.assertEqual(views.cached_graph('scope-a', 'v2', None, None, wait=False)['version'], 'v2')
        self.assertEqual(build.call_count, 1)

    def test_a_builder_that_outlived_its_lock_does_not_free_the_next_builders_lock(self):
        lock = views.graph_cache_key('scope-a', 'v2') + ':lock'

        def build(domain_id=None, scan_id=None):
            cache.delete(lock)  # the lock expired during a long build...
            cache.add(lock, 'the-next-builder', 45)  # ...and another builder took it
            return {'nodes': [], 'edges': []}
        with mock.patch.object(views, 'graph_payload', build):
            views.cached_graph('scope-a', 'v2', None, None)
        self.assertEqual(cache.get(lock), 'the-next-builder')

    def test_the_refresher_run_passes_wait_false(self):
        from cveFeed import live_refresh
        with mock.patch.object(views, 'cached_graph') as cached:
            live_refresh._prebuild_graph({'scope': 's', 'args': {}}, {'payload': 'v9'}, None)
        cached.assert_called_once_with('s', 'v9', None, None, wait=False)
