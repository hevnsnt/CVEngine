"""Batched claim renewal and release (``cvengine.resources.claim_refresh_many`` and ``claim_release_many``) against a real Redis: the same result per
key and the same Redis state as the single-key calls, one call per chunk of 500 keys, input order kept, and one bad key or one failed chunk never
costs the other keys. Also the callers that hold many claims: a waiting StageRun's drive and close (``agentapi.stage_runs``) and the ledger's
``claim_many``. Every fixture is built from a fixed seed, so a run never depends on set or dict order."""
import math
import os
import random
import time
import unittest
from unittest import mock

from cvengine import resources as res

TTL = 300


def redis_or_skip(case):
    try:
        import redis
        client = redis.Redis.from_url(os.environ.get('CELERY_BROKER', 'redis://localhost:6379/0'), decode_responses=True, socket_connect_timeout=1)
        client.ping()
    except Exception:  # noqa: BLE001
        case.skipTest('no Redis available')
    return client


class Counting:
    """The client, counting every call that goes to Redis (one round trip each)."""

    def __init__(self, client, fail=None):
        self.client, self.calls, self.fail = client, [], fail

    def eval(self, script, numkeys, *args):
        self.calls.append(('eval', numkeys))
        if self.fail is not None:
            self.fail(len(self.calls), numkeys, args)
        return self.client.eval(script, numkeys, *args)

    def set(self, *args, **kwargs):
        self.calls.append(('set', 1))
        return self.client.set(*args, **kwargs)


def _prefix(tag):
    return f'cvengine:test:claimbatch:{tag}:{os.getpid()}:{time.time_ns()}'


STATES = ('mine', 'absent', 'expired', 'foreign', 'mine_no_ttl', 'mine_short')


def _seed(client, key, state):
    """Put ``key`` in ``state`` for owner 'me'."""
    if state == 'mine':
        client.set(key, 'me', ex=100)
    elif state == 'mine_short':
        client.set(key, 'me', ex=5)
    elif state == 'mine_no_ttl':
        client.set(key, 'me')
    elif state == 'foreign':
        client.set(key, 'them', ex=77)
    elif state == 'expired':
        client.set(key, 'me', px=1)


def _snapshot(client, keys):
    pipe = client.pipeline(transaction=False)
    for key in keys:
        pipe.get(key)
        pipe.pttl(key)
    got = pipe.execute()
    return [(got[i], got[i + 1]) for i in range(0, len(got), 2)]


class _RedisCase(unittest.TestCase):
    def setUp(self):
        self.client = redis_or_skip(self)
        self.keys = []
        self.addCleanup(self._clean)

    def _clean(self):
        for start in range(0, len(self.keys), 1000):
            self.client.delete(*self.keys[start:start + 1000])

    def _keys(self, tag, n):
        base = _prefix(tag)
        keys = [f'{base}:{i:06d}' for i in range(n)]
        self.keys.extend(keys)
        return keys

    def assertSameState(self, a, b):
        """Values equal, and each TTL equal within five seconds (no TTL, -1, must be equal exactly). The two sides are set one after the
        other with a 300 s hold, so their TTLs differ by the time between the two calls: about a second on a slow CI runner (1063 ms seen).
        Five seconds still tells a renewed hold (about 300 s) from one left at its old TTL or not set."""
        self.assertEqual(len(a), len(b))
        for i, ((va, ta), (vb, tb)) in enumerate(zip(a, b)):
            self.assertEqual(va, vb, f'value of key {i}')
            if ta < 0 or tb < 0:
                self.assertEqual(ta, tb, f'ttl of key {i}')
            else:
                self.assertLessEqual(abs(ta - tb), 5000, f'ttl of key {i}: {ta} ms against {tb} ms')


class EquivalenceTests(_RedisCase):
    def _mixed(self, n, seed):
        rnd = random.Random(seed)
        states = [rnd.choice(STATES) for _ in range(n)]
        single, batched = self._keys('single', n), self._keys('batched', n)
        pipe = self.client.pipeline(transaction=False)
        for key_a, key_b, state in zip(single, batched, states):
            _seed(pipe, key_a, state)
            _seed(pipe, key_b, state)
        pipe.execute()
        time.sleep(0.01)  # the 'expired' keys lapse
        return states, single, batched

    def test_refresh_many_gives_the_single_key_result_and_state_for_every_key(self):
        states, single, batched = self._mixed(1200, seed=20261124)
        self.assertEqual(set(states), set(STATES))
        expected = [res.claim_refresh(self.client, key, 'me', TTL) for key in single]
        got = res.claim_refresh_many(self.client, [(key, 'me') for key in batched], TTL)
        self.assertEqual(got, expected)
        self.assertEqual(set(got), {'ok', 'regained', 'lost'})
        self.assertSameState(_snapshot(self.client, single), _snapshot(self.client, batched))

    def test_release_many_gives_the_single_key_result_and_state_for_every_key(self):
        states, single, batched = self._mixed(1200, seed=7480)
        expected = [res.claim_release(self.client, key, 'me') for key in single]
        got = res.claim_release_many(self.client, [(key, 'me') for key in batched])
        self.assertEqual(got, expected)
        self.assertEqual(set(got), {True, False})
        self.assertSameState(_snapshot(self.client, single), _snapshot(self.client, batched))

    def test_each_key_is_checked_against_its_own_owner_and_a_repeated_key_runs_in_order(self):
        keys = self._keys('owners', 3)
        self.client.set(keys[0], 'a', ex=50)
        self.client.set(keys[1], 'b', ex=50)
        pairs = [(keys[0], 'a'), (keys[1], 'a'), (keys[2], 'c'), (keys[2], 'd'), (keys[0], 'a')]
        self.assertEqual(res.claim_refresh_many(self.client, pairs, TTL), ['ok', 'lost', 'regained', 'lost', 'ok'])
        self.assertEqual([self.client.get(k) for k in keys], ['a', 'b', 'c'])
        self.assertGreater(self.client.ttl(keys[0]), 250)
        self.assertLessEqual(self.client.ttl(keys[1]), 50)  # another holder's expiry is untouched
        self.assertEqual(res.claim_release_many(self.client, [(keys[2], 'd'), (keys[2], 'c'), (keys[2], 'c')]), [False, True, False])

    def test_an_owner_is_compared_as_text_as_the_single_key_call_does(self):
        key = self._keys('int-owner', 1)[0]
        self.client.set(key, '20101', ex=50)
        self.assertEqual(res.claim_refresh_many(self.client, [(key, 20101)], TTL), ['ok'])
        self.assertEqual(res.claim_release_many(self.client, [(key, 20101)]), [True])


class ChunkTests(_RedisCase):
    def test_chunk_boundaries_cost_one_call_per_500_keys_and_keep_the_input_order(self):
        for n in (0, 1, 499, 500, 501, 1200):
            with self.subTest(keys=n):
                keys = self._keys(f'chunk{n}', n)
                pipe = self.client.pipeline(transaction=False)
                for i, key in enumerate(keys):  # the result follows the index, so an order mistake shows
                    if i % 3 == 0:
                        pipe.set(key, 'me', ex=100)
                    elif i % 3 == 1:
                        pipe.set(key, 'them', ex=100)
                pipe.execute()
                counting = Counting(self.client)
                got = res.claim_refresh_many(counting, [(key, 'me') for key in keys], TTL)
                self.assertEqual(got, [('ok', 'lost', 'regained')[i % 3] for i in range(n)])
                self.assertEqual(len(counting.calls), math.ceil(n / 500))
                self.assertTrue(all(size <= 500 for _kind, size in counting.calls))
                counting = Counting(self.client)
                released = res.claim_release_many(counting, [(key, 'me') for key in keys])
                self.assertEqual(released, [i % 3 != 1 for i in range(n)])  # its own and the regained ones
                self.assertEqual(len(counting.calls), math.ceil(n / 500))

    def test_a_run_holding_74424_claims_renews_them_in_at_most_149_calls(self):
        n = 74424
        keys = self._keys('big', n)
        pairs = [(key, 'stagerun:x:svc') for key in keys]
        counting = Counting(self.client)
        got = res.claim_refresh_many(counting, pairs, TTL)
        self.assertEqual(got, ['regained'] * n)
        self.assertLessEqual(len(counting.calls), math.ceil(n / 500))
        counting = Counting(self.client)
        self.assertEqual(res.claim_refresh_many(counting, pairs, TTL), ['ok'] * n)
        self.assertEqual(len(counting.calls), math.ceil(n / 500))
        counting = Counting(self.client)
        self.assertEqual(res.claim_release_many(counting, pairs), [True] * n)
        self.assertEqual(len(counting.calls), math.ceil(n / 500))
        self.assertEqual(self.client.exists(*keys[:1000]), 0)


class FailureTests(_RedisCase):
    def test_a_bad_key_is_asked_again_on_its_own_and_costs_the_others_nothing(self):
        keys = self._keys('bad', 1200)
        bad = 700  # in the second chunk
        for i in range(0, 1200, 2):
            self.client.set(keys[i], 'me', ex=100)
        self.client.delete(keys[bad])
        self.client.hset(keys[bad], 'x', '1')  # another type: GET on it is an error, so the chunk's script fails
        counting = Counting(self.client)
        got = res.claim_refresh_many(counting, [(key, 'me') for key in keys], TTL)
        expected = ['ok' if i % 2 == 0 else 'regained' for i in range(1200)]
        expected[bad] = None
        self.assertEqual(got, expected)
        with self.assertRaises(Exception):
            res.claim_refresh(self.client, keys[bad], 'me', TTL)  # the single-key call fails on it too
        self.assertEqual(counting.calls, [('eval', 500), ('eval', 500), ('eval', 1), ('eval', 200)])  # the bad key alone, once
        self.assertEqual(self.client.type(keys[bad]), 'hash')  # left as it was
        released = res.claim_release_many(self.client, [(key, 'me') for key in keys])
        self.assertIsNone(released[bad])
        self.assertEqual(released[:bad] + released[bad + 1:], [True] * 1199)

    def test_a_lost_connection_in_one_chunk_is_not_retried_key_by_key_and_the_next_chunk_still_runs(self):
        import redis
        keys = self._keys('conn', 1200)

        def fail(call, numkeys, args):
            if call == 2:
                raise redis.exceptions.ConnectionError('gone')

        counting = Counting(self.client, fail=fail)
        got = res.claim_refresh_many(counting, [(key, 'me') for key in keys], TTL)
        self.assertEqual(got, ['regained'] * 500 + [None] * 500 + ['regained'] * 200)
        self.assertEqual(len(counting.calls), 3)  # no per-key retry of the failed chunk

    def test_a_wrong_number_of_results_is_treated_as_a_failed_chunk(self):
        keys = self._keys('short', 3)

        class Short:
            def eval(self, *args):
                return [1]

        with mock.patch.object(res, 'claim_refresh', return_value='ok') as single:
            self.assertEqual(res.claim_refresh_many(Short(), [(k, 'me') for k in keys], TTL), ['ok', 'ok', 'ok'])
        self.assertEqual(single.call_count, 3)


class StageRunClaimTests(_RedisCase):
    def _store(self):
        return mock.patch.dict(res._store, {'obj': res.RedisStore(self.client, 'cvengine:test:ns'), 'kind': 'redis'})

    def test_the_drive_renews_every_held_claim_in_chunks_and_close_releases_only_its_own(self):
        from agentapi import stage_runs
        keys = self._keys('drive', 1001)
        for i, key in enumerate(keys):
            self.client.set(key, 'them' if i == 600 else 'run', ex=30)
        self.client.delete(keys[5])  # lapsed: taken again by the renewal
        self.client.delete(keys[900])
        self.client.hset(keys[900], 'x', '1')  # a bad key in the second chunk
        claims = [(key, 'run') for key in keys]
        counting = Counting(self.client)
        with self._store(), mock.patch.object(stage_runs, '_redis', return_value=counting):
            stage_runs._renew_claims(claims)
        self.assertEqual(self.client.type(keys[900]), 'hash')
        rest = [k for i, k in enumerate(keys) if i != 900]
        for i, (value, pttl) in zip([i for i in range(1001) if i != 900], _snapshot(self.client, rest)):
            if i == 600:
                self.assertEqual(value, 'them')
                self.assertLessEqual(pttl, 30000)
            else:
                self.assertEqual(value, 'run')
                self.assertGreater(pttl, (stage_runs.HOLD_SECONDS - 5) * 1000, f'key {i}')
        self.assertEqual([c for c in counting.calls if c[0] == 'eval'][-1], ('eval', 1))  # the last chunk of one key: one call
        with mock.patch.object(stage_runs, '_redis', return_value=self.client):
            stage_runs._release_claims(claims)
        values = [v for v, _t in _snapshot(self.client, rest)]
        self.assertEqual(values[600], 'them')
        self.assertEqual([v for i, v in enumerate(values) if i != 600], [None] * 999)
        self.assertEqual(self.client.type(keys[900]), 'hash')

    def test_renew_and_release_never_raise(self):
        from agentapi import stage_runs

        class Broken:
            def eval(self, *args):
                raise RuntimeError('boom')

            def set(self, *args, **kwargs):
                raise RuntimeError('boom')

        with mock.patch.object(stage_runs, '_redis', return_value=Broken()):
            stage_runs._renew_claims([('k', 'o')] * 3)
            stage_runs._release_claims([('k', 'o')] * 3)

    def test_hold_claim_keeps_one_copy_of_each_claim_in_the_order_taken(self):
        from agentapi import stage_runs
        from agentapi.models import StageRun
        row = StageRun(kind='test.claim', context={'_engine': {'claims': [['a', 'x'], ['b', 'x']]}})
        p = stage_runs.Pass(row, 'test.claim')
        for key, owner in (('c', 'x'), ('a', 'x'), ('c', 'x'), ('a', 'y'), ('d', 'x')):
            p.hold_claim(key, owner)
        self.assertEqual(p.claims, [('a', 'x'), ('b', 'x'), ('c', 'x'), ('a', 'y'), ('d', 'x')])
        self.assertEqual(p.engine()['claims'], [['a', 'x'], ['b', 'x'], ['c', 'x'], ['a', 'y'], ['d', 'x']])

    def test_claim_many_in_a_run_takes_back_its_own_skips_another_holder_and_holds_on_suspend(self):
        from agentapi import stage_runs
        from agentapi.models import StageRun
        from cveFeed import ledger
        p = stage_runs.Pass(StageRun(kind='test.claim'), 'test.claim')
        service = f'claimbatch{os.getpid()}{time.time_ns()}'
        owner = p.claim_owner(service)
        assets = [f'h{i:04d}.test' for i in range(1203)]
        self.keys.extend(ledger._key(service, a) for a in assets)
        self.client.set(ledger._key(service, assets[3]), owner, ex=40)  # its earlier pass's claim
        self.client.set(ledger._key(service, assets[700]), 'another-scan', ex=40)
        with self._store(), mock.patch.object(stage_runs, 'current', return_value=p):
            with self.assertRaises(stage_runs.Suspend):
                with ledger.claim_many(service, assets) as won:
                    self.assertEqual(won, [a for a in assets if a != assets[700]])
                    raise stage_runs.Suspend()
        self.assertEqual(p.claims, [(ledger._key(service, a), owner) for a in assets if a != assets[700]])
        snap = _snapshot(self.client, [ledger._key(service, a) for a in assets])
        self.assertEqual(snap[700][0], 'another-scan')
        self.assertTrue(all(v == owner and t > (stage_runs.HOLD_SECONDS - 5) * 1000 for i, (v, t) in enumerate(snap) if i != 700))
        with self._store(), mock.patch.object(stage_runs, 'current', return_value=None):
            with ledger.claim_many(service, assets) as won:
                self.assertEqual(won, [])  # held for the waiting run
        with self._store(), mock.patch.object(stage_runs, 'current', return_value=p):
            with ledger.claim_many(service, assets) as won:
                self.assertEqual(len(won), 1202)  # its next pass takes them back, and releases them when it ends
        values = [v for v, _t in _snapshot(self.client, [ledger._key(service, a) for a in assets])]
        self.assertEqual(values, [None] * 700 + ['another-scan'] + [None] * 502)
