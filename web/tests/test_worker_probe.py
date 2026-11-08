"""A worker that missed one ping is not a missing consumer; one that is really absent is still reported, within two checks."""
from unittest import mock

from django.core.cache import cache
from django.test import TestCase

from cveFeed import admin_api

ALL = {f'celery@{w}': [{'name': q}] for w, q in admin_api.WORKERS.items()}


class FakeApp:
    """``replies`` is a list, one dict of ``{worker: [queues]}`` per ping; the last one repeats."""
    def __init__(self, replies):
        self.replies, self.pings, self.timeouts = list(replies), 0, []
        self.control = self

    def inspect(self, timeout=None, limit=None, destination=None):
        outer = self
        outer.timeouts.append(timeout)

        class Inspector:
            def active_queues(self):
                outer.pings += 1
                return outer.replies.pop(0) if len(outer.replies) > 1 else outer.replies[0]

            def active(self):
                return {name: [] for name in ALL}
        return Inspector()


def without(worker):
    return {k: v for k, v in ALL.items() if k != f'celery@{worker}'}


class WorkerProbeTests(TestCase):
    def setUp(self):
        cache.delete(admin_api.WORKER_MISS_KEY)
        self.addCleanup(cache.delete, admin_api.WORKER_MISS_KEY)
        patch = mock.patch.object(admin_api, '_pause')
        self.pause = patch.start()
        self.addCleanup(patch.stop)

    def test_a_busy_worker_that_answers_a_later_ping_is_not_missing(self):
        app = FakeApp([without('discovery_worker'), ALL])
        out = admin_api._inspect_workers(app)
        self.assertEqual((out['pings'], out['confirmed']), (2, []))
        self.assertEqual(admin_api._absent(out['queues']), [])
        self.pause.assert_called_once_with(admin_api.WORKER_PING_GAP)

    def test_every_ping_waits_ten_seconds_not_five(self):
        app = FakeApp([ALL])
        admin_api._inspect_workers(app)
        self.assertEqual(set(app.timeouts), {10})

    def test_all_workers_answering_costs_one_ping(self):
        app = FakeApp([ALL])
        out = admin_api._inspect_workers(app)
        self.assertEqual((app.pings, out['pings']), (1, 1))
        self.pause.assert_not_called()

    def test_a_missed_worker_is_asked_three_times_then_confirmed_only_on_the_second_check(self):
        app = FakeApp([without('discovery_worker')])
        first = admin_api._inspect_workers(app)
        self.assertEqual((first['pings'], first['confirmed']), (3, []))  # three pings, one check: not yet a problem
        second = admin_api._inspect_workers(app)
        self.assertEqual(second['confirmed'], ['discovery_worker'])  # two checks in a row

    def test_one_answer_between_checks_resets_the_count(self):
        admin_api._inspect_workers(FakeApp([without('discovery_worker')]))
        admin_api._inspect_workers(FakeApp([ALL]))
        again = admin_api._inspect_workers(FakeApp([without('discovery_worker')]))
        self.assertEqual(again['confirmed'], [])

    def test_the_first_request_sends_one_ping_and_confirms_nothing(self):
        app = FakeApp([{}])
        out = admin_api._inspect_workers(app, quick=True)
        self.assertEqual((app.pings, out['pings'], out['confirmed']), (1, 1, []))
        self.assertEqual(admin_api._confirm_misses([]), ({}, []))  # and it counted nothing

    def health(self, probes):
        """scheduler_health with ``probes`` (the cached answers) in place of real ones."""
        from django.contrib.auth.models import AnonymousUser
        user = mock.Mock(is_superuser=True)
        answers = iter(probes)
        with mock.patch.object(admin_api.probe_cache, 'cached_probe', side_effect=lambda *a, **k: (next(answers), 0)):
            return admin_api.scheduler_health(None, user)

    def probe(self, queues, confirmed=(), pings=3, seconds=30):
        return {'queues': queues, 'active': {}, 'active_warning': '', 'pings': pings, 'seconds': seconds, 'confirmed': list(confirmed)}

    def test_an_unconfirmed_miss_is_no_problem_and_says_it_is_confirming(self):
        out = self.health([self.probe(without('discovery_worker'))])
        self.assertEqual(out['workers_state'], 'responding')
        self.assertIn('confirming', out['worker_note'])
        self.assertNotIn('Missing or unconfirmed', out['worker_note'])

    def test_a_worker_that_is_really_absent_is_reported_with_what_was_tried(self):
        out = self.health([self.probe(without('discovery_worker'), confirmed=['discovery_worker'])])
        self.assertEqual(out['workers_state'], 'degraded')
        note = out['worker_note']
        self.assertIn('Missing or unconfirmed required queue consumers: discovery_worker.', note)
        self.assertIn('no reply to 3 pings over 30 s', note)
        self.assertIn('no consumer on the queue', note)

    def test_the_whole_path_raises_within_two_checks_for_an_absent_worker(self):
        app = FakeApp([without('discovery_worker')])
        states = [self.health([admin_api._inspect_workers(app)])['workers_state'] for _ in range(2)]
        self.assertEqual(states, ['responding', 'degraded'])
