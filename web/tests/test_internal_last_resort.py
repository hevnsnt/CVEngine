"""The built-in scanner is the path of last resort (docs/SCANNER-ARCHITECTURE.md): an external Sentinel that is live and eligible for a task takes it first, and the
built-in one takes it only when it is the sole eligible Sentinel, when the task has waited ``CVENGINE_BUILTIN_FALLBACK_SECONDS`` (default 120, ``0`` = immediately) for the
externals, or when only it can run the kind (``BUILTIN_KINDS``).

Two layers. The claim layer asks ``sentinel_broker._try_claim`` as each Sentinel would, at chosen times, so every branch of the rule is exact. The dispatch layer starts the
built-in ``FakeScanner`` and an external one (``FakeScanner(external=True)``), runs the real ``dispatch_or_none`` wait on the virtual clock (``tests/fake_scanner.py``;
the fakes are served built-in FIRST on every poll, so an external winning is the rule at work, not luck), and reads which Sentinel ended with the task and how long (virtual
seconds) it took."""
from contextlib import contextmanager
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from agentapi import scanner_state
from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from agentapi.services import Ctx
from tests.fake_scanner import FakeScanner, LocalFallback
from tests.test_sentinel_capability_policy import PolicyBase

GRACE = 30


class LastResortBase(PolicyBase):
    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        patcher = mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': str(GRACE), 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(dispatch, 'DISPATCH_POLL_INTERVAL', 2.0)  # a poll is one claim call of the fakes: the broker's own rate limit (60 a minute) counts real time
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def builtin(self, **kwargs):
        kwargs.setdefault('kinds', ['nmap', 'naabu', 'openvas', 'path_probe', 'nuclei_validate', 'route_probe_signed'])
        self.fake = FakeScanner(**kwargs).start_for(self)
        return self.fake

    def outside(self, **kwargs):
        kwargs.setdefault('kinds', ['nmap', 'naabu', 'openvas'])
        kwargs.setdefault('external', True)
        self.ext = FakeScanner(**kwargs).start_for(self)
        return self.ext

    def real_external(self, name='Remote-1', **kwargs):
        return self.external(name, **kwargs)

    @contextmanager
    def virtual_time(self):
        """``timezone.now`` follows the dispatcher's virtual clock, so the age of a queued task (what the grace is measured on) moves with the waits."""
        clock = (getattr(self, 'ext', None) or self.fake).clock
        real = timezone.now
        with mock.patch('django.utils.timezone.now', new=lambda: real() + timedelta(seconds=clock.offset)):
            yield clock

    def run_dispatch(self, kind='nmap', **kwargs):
        before = set(SentinelTask.objects.values_list('pk', flat=True))
        with self.virtual_time() as clock:
            start = clock.offset
            try:
                result = dispatch.dispatch_or_none(self.project, kind, {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], scan=self.scan, **kwargs)
            except Exception as exc:  # noqa: BLE001 - the stage's own outcome (ScannerUnavailable) is part of what a test reads
                result = exc
            took = clock.offset - start
        task = SentinelTask.objects.exclude(pk__in=before).order_by('id').first()
        if task.claimed_at:
            took = (task.claimed_at - task.created_at).total_seconds()  # the age it was claimed at, real time spent in the queries included
        return result, task, took


class ClaimRuleTests(LastResortBase):
    """``_try_claim`` as the built-in scanner and an external Sentinel ask at chosen times."""

    def test_the_built_in_scanner_stands_back_while_an_external_one_is_there_and_the_external_takes_the_task(self):
        fake = self.builtin()
        outside = self.real_external()
        created = timezone.now()
        task = self.queue('nmap', created=created)
        taken, why = self.claim(fake.agent, ['nmap'], created + timedelta(seconds=1))
        self.assertIsNone(taken)
        self.assertIn(f'left to the external Sentinels for up to {GRACE} seconds', why)
        self.assertTrue(why.startswith(sb.HELD_BACK))  # a held-back answer: the long poll looks again in a second
        self.assertEqual(self.claim(outside, ['nmap'], created + timedelta(seconds=2))[0].pk, task.pk)

    def test_the_built_in_scanner_takes_the_task_once_it_has_waited_the_grace(self):
        fake = self.builtin()
        self.real_external()
        created = timezone.now()
        task = self.queue('nmap', created=created)
        self.assertIsNone(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=GRACE - 1))[0])
        taken, _ = self.claim(fake.agent, ['nmap'], created + timedelta(seconds=GRACE + 1))
        self.assertEqual((taken.pk, taken.agent_id), (task.pk, fake.agent.pk))

    def test_with_no_external_sentinel_the_built_in_scanner_takes_it_at_once(self):
        fake = self.builtin()
        created = timezone.now()
        task = self.queue('nmap', created=created)
        self.assertEqual(self.claim(fake.agent, ['nmap'], created)[0].pk, task.pk)

    def test_an_external_that_is_not_heard_from_is_not_there_for_the_task(self):
        fake = self.builtin()
        gone = self.real_external()
        type(gone).objects.filter(pk=gone.pk).update(last_seen=timezone.now() - sb.LIVE_WINDOW - timedelta(seconds=5))
        task = self.queue('nmap')
        self.assertEqual(self.claim(fake.agent, ['nmap'])[0].pk, task.pk)

    def test_an_external_that_cannot_take_this_task_does_not_hold_it(self):
        fake = self.builtin()
        created = timezone.now()
        other_kind = self.real_external('Only-naabu', caps=('naabu',))
        denied = self.real_external('Denied', caps=('nmap',))
        self.manage(denied, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        suspended = self.real_external('Suspended', caps=('nmap',))
        type(suspended).objects.filter(pk=suspended.pk).update(status='suspended')
        elsewhere = self.real_external('Other-project', caps=('nmap',))
        type(elsewhere).objects.filter(pk=elsewhere.pk).update(scope={'orgs': [], 'projects': ['not-this-project'], 'hosts': []})
        task = self.queue('nmap', created=created)
        taken, _ = self.claim(fake.agent, ['nmap'], created + timedelta(seconds=1))
        self.assertEqual(taken.pk, task.pk, f'{other_kind.name}, {suspended.name} and the others are no reason to wait')

    def test_an_external_updating_itself_does_not_hold_it(self):
        fake = self.builtin()
        busy = self.real_external('Updating', caps=('nmap',))
        type(busy).objects.filter(pk=busy.pk).update(info={**busy.info, 'update': {'status': 'updating', 'at': timezone.now().strftime('%Y-%m-%dT%H:%M:%SZ')}})
        task = self.queue('nmap')
        self.assertEqual(self.claim(fake.agent, ['nmap'])[0].pk, task.pk)

    def test_a_full_external_still_holds_the_task_until_the_grace_then_the_built_in_one_takes_it(self):
        fake = self.builtin()
        full = self.real_external('Full', caps=('nmap',), max_concurrent=1)
        self.hold_task(full)
        created = timezone.now()
        task = self.queue('nmap', created=created)
        self.assertIsNone(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=5))[0])
        self.assertEqual(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=GRACE + 1))[0].pk, task.pk)

    def hold_task(self, agent):
        SentinelTask.objects.create(project=self.project, kind='naabu', target={}, agent=agent, status='running', claimed_at=timezone.now(), accepted_at=timezone.now(),
                                    lease_expires_at=timezone.now() + timedelta(minutes=30))

    def test_grace_zero_is_immediate_and_the_built_in_scanner_is_no_longer_held(self):
        fake = self.builtin()
        self.real_external()
        task = self.queue('nmap')
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '0'}):
            self.assertEqual(self.claim(fake.agent, ['nmap'])[0].pk, task.pk)

    def test_the_kinds_only_the_built_in_scanner_runs_are_never_held(self):
        fake = self.builtin()
        self.real_external('Remote-1', caps=('nmap', 'naabu', 'path_probe', 'nuclei_validate', 'route_probe_signed'))
        created = timezone.now()
        for kind in sb.BUILTIN_KINDS:
            task = self.queue(kind, created=created)
            taken, why = self.claim(fake.agent, [kind], created + timedelta(seconds=1))
            self.assertEqual(taken.pk, task.pk, f'{kind}: {why}')

    def test_signed_in_work_goes_to_the_built_in_scanner_at_once(self):
        fake = self.builtin()
        self.real_external()
        task = self.queue('nmap', secret_ref='secret:1')  # no external may be offered it, so none is there for it
        self.assertEqual(self.claim(fake.agent, ['nmap'])[0].pk, task.pk)

    def test_openvas_is_held_for_the_external_that_has_it_and_the_grace_applies(self):
        fake = self.builtin()
        self.manage(fake.agent, {'kinds': {'openvas': {'mode': 'allow', 'max_concurrent': None}}})  # shipped: the built-in scanner denies it
        outside = self.real_external('Remote-1', caps=('openvas',))
        created = timezone.now()
        task = self.queue('openvas', created=created)
        self.assertIsNone(self.claim(fake.agent, ['openvas'], created + timedelta(seconds=10))[0])
        self.assertEqual(self.claim(outside, ['openvas'], created + timedelta(seconds=11))[0].pk, task.pk)
        later = self.queue('openvas', created=created)
        self.assertEqual(self.claim(fake.agent, ['openvas'], created + timedelta(seconds=GRACE + 1))[0].pk, later.pk)

    def test_the_built_in_scanner_prefers_a_kind_when_an_administrator_says_so_and_then_it_is_not_held(self):
        fake = self.builtin()
        self.real_external()
        self.manage(fake.agent, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        task = self.queue('nmap')
        self.assertEqual(self.claim(fake.agent, ['nmap'])[0].pk, task.pk)

    def test_a_per_kind_prefer_among_externals_still_decides_between_them(self):
        fake = self.builtin()
        a = self.real_external('A', caps=('nmap',))
        b = self.real_external('B', caps=('nmap',))
        self.manage(b, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        created = timezone.now()
        task = self.queue('nmap', created=created)
        taken, why = self.claim(a, ['nmap'], created + timedelta(seconds=1))
        self.assertIsNone(taken)
        self.assertIn('held for a Sentinel that prefers it', why)
        self.assertIsNone(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=1))[0])  # and the built-in one still stands back
        self.assertEqual(self.claim(b, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)

    def test_an_external_is_not_held_back_for_a_lighter_built_in_scanner(self):
        fake = self.builtin()
        x = self.real_external('X', caps=('nmap',))
        self.hold_task(x)  # X holds one, the built-in scanner none: it is the lighter, but the last resort is nobody to wait for
        created = timezone.now()
        task = self.queue('nmap', created=created)
        self.assertEqual(self.claim(x, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)
        self.assertEqual(fake.agent.pk, sb.builtin_pk())

    def test_the_built_in_scanner_is_not_held_by_the_balance_or_prefer_rules_once_the_grace_is_over(self):
        fake = self.builtin()
        light = self.real_external('Light', caps=('nmap',))
        self.manage(light, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        self.hold_task(fake.agent)
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '5'}):  # shorter than the 60 s prefer and balance holds
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=2))[0])
            self.assertEqual(self.claim(fake.agent, ['nmap'], created + timedelta(seconds=6))[0].pk, task.pk)


class GraceBudgetTests(LastResortBase):
    def test_the_grace_is_held_to_the_stage_budget_less_one_claim_window(self):
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '100000', 'CVENGINE_SENTINEL_QUEUE_TIMEOUT': '60', 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            self.assertEqual(sb.builtin_fallback_for('nmap'), 60 - 8 - 2)
            self.assertLess(sb.builtin_fallback_for('openvas'), sb.OPENVAS_QUEUE_TTL.total_seconds())

    def test_a_budget_too_small_for_a_grace_means_no_grace(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_QUEUE_TIMEOUT': '5', 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            self.assertEqual(sb.builtin_fallback_for('nmap'), 0)

    def test_the_setting_reads_as_documented(self):
        for raw, wanted in (('', 120), ('x', 120), ('0', 0), ('45', 45), ('-3', 0)):
            with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': raw}):
                self.assertEqual(sb.builtin_fallback_seconds(), wanted, raw)
        with mock.patch.dict('os.environ', clear=False) as env:
            env.pop('CVENGINE_BUILTIN_FALLBACK_SECONDS', None)
            self.assertEqual(sb.builtin_fallback_seconds(), 120)

    def test_an_enormous_grace_never_costs_the_stage_its_task(self):
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '100000', 'CVENGINE_SENTINEL_QUEUE_TIMEOUT': '60'}):
            self.builtin()
            self.outside(mode='idle')
            result, task, took = self.run_dispatch()
            self.assertEqual(task.status, 'done', result)
            self.assertEqual(task.agent_id, self.fake.agent.pk)
            self.assertLessEqual(took, 60 + 1)  # inside the stage's queue budget


class DispatchTests(LastResortBase):
    def test_the_external_sentinel_wins_when_both_are_live(self):
        self.builtin()
        self.outside()
        result, task, took = self.run_dispatch()
        self.assertEqual((task.status, task.agent_id), ('done', self.ext.agent.pk), result)
        self.assertEqual(self.fake.served, [])
        self.assertLess(took, 5)

    def test_every_kind_an_external_has_goes_to_it(self):
        self.builtin()
        self.outside()
        for kind in ('nmap', 'naabu'):
            _, task, _ = self.run_dispatch(kind)
            self.assertEqual(task.agent_id, self.ext.agent.pk, kind)
        self.assertEqual(self.fake.served, [])

    def test_an_external_that_does_not_claim_leaves_the_task_to_the_built_in_scanner_after_the_grace(self):
        self.builtin()
        self.outside(mode='idle')
        result, task, took = self.run_dispatch()
        self.assertEqual((task.status, task.agent_id), ('done', self.fake.agent.pk), result)
        self.assertGreaterEqual(took, GRACE)
        self.assertLessEqual(took, GRACE + 3)

    def test_a_dead_external_means_the_built_in_scanner_takes_it_at_once(self):
        self.builtin()
        self.outside(mode='offline')
        result, task, took = self.run_dispatch()
        self.assertEqual((task.status, task.agent_id), ('done', self.fake.agent.pk), result)
        self.assertLess(took, 5)

    def test_a_full_external_sends_the_task_to_the_built_in_scanner_after_the_grace(self):
        self.builtin()
        self.outside(max_concurrent=1)
        SentinelTask.objects.create(project=self.project, kind='naabu', target={}, agent=self.ext.agent, status='running', claimed_at=timezone.now(),
                                    accepted_at=timezone.now(), lease_expires_at=timezone.now() + timedelta(hours=2))
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'busy')  # the built-in scanner's free slots are not the work's capacity
        result, task, took = self.run_dispatch()
        self.assertEqual((task.status, task.agent_id), ('done', self.fake.agent.pk), result)
        self.assertGreaterEqual(took, GRACE)

    def test_no_external_means_the_built_in_scanner_does_it_with_no_wait(self):
        self.builtin()
        result, task, took = self.run_dispatch()
        self.assertEqual((task.status, task.agent_id), ('done', self.fake.agent.pk), result)
        self.assertLess(took, 5)

    def test_grace_zero_restores_the_immediate_built_in_scanner(self):
        self.builtin()
        self.outside(mode='idle')
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '0'}):
            result, task, took = self.run_dispatch()
        self.assertEqual((task.status, task.agent_id), ('done', self.fake.agent.pk), result)
        self.assertLess(took, 5)

    def test_the_built_in_only_kinds_are_unaffected_by_an_external_sentinel(self):
        self.builtin()
        self.outside(kinds=['nmap', 'naabu', 'path_probe'])  # even one that declares it is never offered it
        result, task, took = self.run_dispatch('path_probe')
        self.assertEqual((task.status, task.agent_id), ('done', self.fake.agent.pk), result)
        self.assertLess(took, 5)

    def test_the_stage_gives_up_on_a_task_nobody_takes_with_no_scanner_taking_it(self):
        self.builtin(mode='idle')
        self.outside(mode='idle')
        result, task, took = self.run_dispatch()
        self.assertEqual(task.status, 'expired')
        self.assertIsInstance(result, Exception)
        self.assertLessEqual(took, GRACE + 8 + 2)  # never past the grace and one claim window


class CapacityAndPageTests(LastResortBase):
    def test_capacity_counts_the_external_sentinels_slots_only_while_one_is_there(self):
        fake = self.builtin(max_concurrent=4)
        outside = self.real_external('Remote-1', caps=('nmap',), max_concurrent=2)
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['live'], state['slots'], state['free']), ('free', 1, 2, 2), state)
        self.assertEqual((state['externals'], state['fallback_seconds']), (1, GRACE))
        type(outside).objects.filter(pk=outside.pk).update(status='suspended')
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['live'], state['slots']), ('free', 1, 4), state)  # only the built-in scanner: its slots count
        self.assertNotIn('fallback_seconds', state)
        self.assertEqual(fake.agent.pk, sb.builtin_pk())

    def test_capacity_counts_everything_when_the_grace_is_off(self):
        self.builtin(max_concurrent=4)
        self.real_external('Remote-1', caps=('nmap',), max_concurrent=2)
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '0'}):
            state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['live'], state['slots']), (2, 6))

    def test_the_built_in_only_kinds_count_the_built_in_scanner(self):
        self.builtin()
        self.real_external('Remote-1', caps=('nmap',))
        self.assertEqual(sb.capacity_state(self.project, 'path_probe')['state'], 'free')

    def test_the_waiting_state_still_counts_the_built_in_scanner_as_a_scanner_for_the_kinds_it_has(self):
        self.builtin(kinds=['nmap'])
        self.assertNotIn('nmap', scanner_state.state(timezone.now())['kinds'])

    def test_the_built_in_scanner_is_named_last_in_what_the_server_says(self):
        fake = self.builtin(kinds=['nmap', 'naabu'])
        self.real_external('Zed', caps=('nmap',))
        self.manage(fake.agent, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        self.manage(sb.Agent.objects.get(name='Zed'), {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        message = sb.capacity_state(self.project, 'nmap', why=True)['message']
        self.assertLess(message.index('off on Zed'), message.index('off on CVEngine Scanner'), message)

    def test_the_sentinels_page_lists_the_built_in_scanner_last_marks_it_and_counts_what_each_side_did(self):
        fake = self.builtin(kinds=['nmap', 'naabu'])
        outside = self.real_external('Alpha', caps=('nmap',))
        now = timezone.now()
        for agent, status, n in ((outside, 'done', 3), (outside, 'failed', 1), (fake.agent, 'done', 2)):
            for _ in range(n):
                SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=agent, status=status, claimed_at=now - timedelta(minutes=5),
                                            finished_at=now - timedelta(minutes=2))
        data = sb.live_overview(Ctx(user=self.root, token=None))
        names = [row['name'] for row in data['results']]
        self.assertEqual(names[-1], 'CVEngine Scanner', names)
        rows = {row['name']: row for row in data['results']}
        self.assertTrue(rows['CVEngine Scanner']['last_resort'])
        self.assertFalse(rows['Alpha']['last_resort'])
        routing = data['routing']
        self.assertEqual((routing['builtin_24h'], routing['external_24h'], routing['externals'], routing['fallback_seconds']), (2, 4, 1, GRACE), routing)
        self.assertEqual(routing['builtin_share_24h'], round(2 / 6, 3))
        self.assertIn('path of last resort', routing['explanation'])
        self.assertIn(f'{GRACE} seconds', routing['explanation'])

    def test_the_page_explanation_says_so_when_the_grace_is_off(self):
        self.builtin(kinds=['nmap'])
        with mock.patch.dict('os.environ', {'CVENGINE_BUILTIN_FALLBACK_SECONDS': '0'}):
            data = sb.live_overview(Ctx(user=self.root, token=None))
        self.assertIn('as soon as it asks', data['routing']['explanation'])
        self.assertEqual(data['routing']['externals'], 0)


class LongPollTests(LastResortBase):
    """A built-in scanner whose only hold is the wait for the externals sleeps until the grace ends, not a poll a second."""

    def test_the_wait_for_the_externals_sleeps_until_the_grace_is_over(self):
        fake = self.builtin()
        self.real_external()
        created = timezone.now()
        self.queue('nmap', created=created)
        taken, why = self.claim(fake.agent, ['nmap'], created + timedelta(seconds=10))
        self.assertIsNone(taken)
        with mock.patch('time.sleep', sb._REAL_SLEEP), mock.patch('agentapi.sentinel_notify.wait_agent') as wait, mock.patch('agentapi.sentinel_notify.safety_seconds', return_value=300):
            sb._await_work(fake.agent, why, 100)
        timeout = wait.call_args.args[1]
        self.assertAlmostEqual(timeout, GRACE - 10 + 0.2, delta=0.5)

    def test_a_prefer_hold_keeps_the_one_second_look(self):
        fake = self.builtin()
        outside = self.real_external('B', caps=('nmap',))
        self.manage(outside, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        peer = self.real_external('A', caps=('nmap',))
        created = timezone.now()
        self.queue('nmap', created=created)
        taken, why = self.claim(peer, ['nmap'], created + timedelta(seconds=1))
        self.assertIsNone(taken)
        sleeps = []
        with mock.patch('time.sleep', sb._REAL_SLEEP), mock.patch('agentapi.sentinel_broker.time.sleep', side_effect=sleeps.append), mock.patch('agentapi.sentinel_notify.wait_agent') as wait:
            sb._await_work(peer, why, 100)
        self.assertFalse(wait.called)
        self.assertEqual(sleeps, [1.0])
