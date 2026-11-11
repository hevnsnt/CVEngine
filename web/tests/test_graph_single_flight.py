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
        cache.add(views.graph_cache_key('scope-a', 'v1') + ':lock', 1, 60)  # a lock nobody will release
        with mock.patch.object(views, 'GRAPH_WAIT_SECONDS', 0.3), mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': []}) as build:
            self.assertEqual(views.cached_graph('scope-a', 'v1', None, None)['version'], 'v1')
        self.assertEqual(build.call_count, 1)

    def test_a_cache_that_does_not_answer_still_gives_the_graph(self):
        broken = mock.Mock(side_effect=ConnectionError('redis is down'))
        with mock.patch('django.core.cache.cache.get', broken), mock.patch('django.core.cache.cache.add', broken), \
                mock.patch('django.core.cache.cache.set', broken), mock.patch('django.core.cache.cache.delete', broken), \
                mock.patch.object(views, 'graph_payload', return_value={'nodes': [], 'edges': []}):
            self.assertEqual(views.cached_graph('scope-a', 'v1', None, None)['version'], 'v1')
