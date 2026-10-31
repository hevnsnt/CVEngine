"""Long-poll waiter slots for Sentinels: a Sentinel's token is not counted against its user's cap (an admin with two external Sentinels and the built-in
scanner, which belongs to the oldest App Admin, keeps all three on long polls), and the built-in scanner is not turned away when other callers hold every
instance slot. Any other token keeps both caps."""
import time

from django.core.cache import cache

from agentapi import agent_broker as broker
from agentapi.auth import SCOPE_SENTINEL, authenticate, create_token
from tests.test_agentapi import call
from tests.test_sentinel_secret_read import SecretBase
from tests.test_sentinels import reset_rates

PROJECT_ENROLL = '/api/v1/projects/sen-a/sentinels/enroll'


class WaiterSlotTests(SecretBase):
    def setUp(self):
        super().setUp()
        self.keys = ['agentapi:waiters']
        for user_id in {self.root.pk, self.dana.pk}:
            self.keys.append(f'agentapi:waiters:user:{user_id}')
        for key in self.keys:
            cache.delete(key)
            self.addCleanup(cache.delete, key)

    def token(self, raw):
        return authenticate(raw)

    def more_sentinels(self, enroller, count):
        raws = []
        for n in range(count):
            _agent, raw = self.enroll(enroller, PROJECT_ENROLL, f'more-{n}')
            raws.append(raw)
        reset_rates(self.t | {f'more-{n}': raw for n, raw in enumerate(raws)})
        return [self.token(raw) for raw in raws]

    def hold(self, tokens, **kwargs):
        """Open a slot for each token at once and say which got one."""
        slots = []

        def nest(rest):
            if not rest:
                return
            with broker._waiter_slot(True, rest[0], **kwargs) as got:
                slots.append(got)
                nest(rest[1:])
        nest(list(tokens))
        return slots

    def test_three_sentinel_tokens_of_one_user_all_get_a_slot(self):
        tokens = [self.token(self.t['external']), *self.more_sentinels(self.t['dana'], 2)]
        self.assertEqual({t.user_id for t in tokens}, {self.dana.pk})
        self.assertEqual({t.scope for t in tokens}, {SCOPE_SENTINEL})
        self.assertEqual(self.hold(tokens), [True, True, True])
        self.assertIsNone(cache.get(f'agentapi:waiters:user:{self.dana.pk}'))  # a Sentinel never touches its user's counter

    def test_a_sentinel_token_still_has_the_instance_cap_and_one_poll_per_token(self):
        token = self.token(self.t['external'])
        with broker._waiter_slot(True, token) as first:
            with broker._waiter_slot(True, token) as same_token:
                pass
        self.assertEqual((first, same_token), (True, False))
        cache.set('agentapi:waiters', broker.MAX_WAITERS, 120)
        with broker._waiter_slot(True, token) as full:
            self.assertFalse(full)

    def test_the_built_in_scanner_gets_a_slot_when_six_other_waiters_hold_the_instance_cap(self):
        builtin_token = self.token(self.t['builtin'])
        external_token = self.token(self.t['external'])
        cache.set('agentapi:waiters', broker.MAX_WAITERS, 120)
        with broker._waiter_slot(True, external_token) as turned_away:
            self.assertFalse(turned_away)
        with broker._waiter_slot(True, builtin_token, exempt_instance=True) as got:
            self.assertTrue(got)
            self.assertEqual(cache.get('agentapi:waiters'), broker.MAX_WAITERS)  # it took nothing from the instance cap
        self.assertEqual(cache.get('agentapi:waiters'), broker.MAX_WAITERS)  # and gave nothing back that it did not take

    def test_the_built_in_scanner_still_holds_only_one_poll(self):
        token = self.token(self.t['builtin'])
        with broker._waiter_slot(True, token, exempt_instance=True) as first:
            with broker._waiter_slot(True, token, exempt_instance=True) as second:
                pass
        self.assertEqual((first, second), (True, False))

    def test_a_token_that_is_not_a_sentinels_keeps_both_caps(self):
        extra = [create_token(self.dana, f'full-{n}')[1] for n in range(3)]
        tokens = [self.token(raw) for raw in extra]
        self.assertEqual({t.scope for t in tokens}, {'full'})
        self.assertEqual(self.hold(tokens), [True, True, False])  # MAX_WAITERS_PER_USER
        cache.delete(f'agentapi:waiters:user:{self.dana.pk}')
        cache.set('agentapi:waiters', broker.MAX_WAITERS, 120)
        self.assertEqual(self.hold(tokens[:1]), [False])  # the instance cap
        self.assertEqual(self.hold(tokens[:1], exempt_instance=True), [True])

    def test_a_sentinel_of_the_same_user_does_not_use_up_a_full_tokens_slots(self):
        sentinels = [self.token(self.t['external']), *self.more_sentinels(self.t['dana'], 1)]
        full = [self.token(create_token(self.dana, f'full-{n}')[1]) for n in range(2)]
        self.assertEqual(self.hold([*sentinels, *full]), [True, True, True, True])

    def test_a_built_in_long_poll_over_http_holds_when_the_instance_cap_is_full_and_an_external_one_does_not(self):
        cache.set('agentapi:waiters', broker.MAX_WAITERS, 120)
        started = time.monotonic()
        status, out = call(self.t['external'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 1})
        self.assertLess(time.monotonic() - started, 0.9)  # no slot: answered at once, told to come back in 5 s
        self.assertEqual((status, out['task'], out['retry_after_seconds']), (200, None, 5))
        started = time.monotonic()
        status, out = call(self.t['builtin'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 1})
        self.assertGreaterEqual(time.monotonic() - started, 0.9)  # a slot: it waited out its poll
        self.assertEqual((status, out['task'], out['retry_after_seconds']), (200, None, 1))
        self.assertEqual(cache.get('agentapi:waiters'), broker.MAX_WAITERS)
