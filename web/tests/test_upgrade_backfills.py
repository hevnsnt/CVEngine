"""The update backfills run by themselves once per install (cveFeed.upgrade_backfills): nobody runs a command on a headless install."""
from unittest import mock

from django.test import TestCase

from cveFeed import upgrade_backfills
from cveFeed.models import AgentActivity, BackgroundCursor


class Calls:
    def __init__(self, fail=()):
        self.names, self.fail = [], set(fail)

    def __call__(self, name, **kwargs):
        assert kwargs.get('apply') is True
        self.names.append(name)
        if name in self.fail:
            raise RuntimeError('boom')
        kwargs['stdout'].write(f'{name}: changed 2\n')


def run_all(call, limit=50):
    for _ in range(limit):
        result = upgrade_backfills.run_next(call=call)
        if result['state'] in ('none', 'off', 'held'):
            return result
    raise AssertionError('did not finish')


class RunNextTests(TestCase):
    def test_every_backfill_runs_once_in_order_and_says_so(self):
        call = Calls()
        self.assertEqual(run_all(call)['state'], 'none')
        self.assertEqual(call.names, list(upgrade_backfills.BACKFILLS))
        self.assertEqual(upgrade_backfills.pending(), [])
        lines = list(AgentActivity.objects.values_list('message', flat=True))
        self.assertTrue(any('Update step dedupe_findings applied: dedupe_findings: changed 2' in line for line in lines))
        run_all(call)
        self.assertEqual(len(call.names), len(upgrade_backfills.BACKFILLS))  # a second worker start runs nothing again

    def test_rerate_findings_runs_last_so_the_rescore_counts_everything_above(self):
        self.assertEqual(upgrade_backfills.BACKFILLS[-1], 'rerate_findings')

    def test_a_failing_backfill_does_not_hold_the_others_back_and_is_given_up_after_three_tries(self):
        call = Calls(fail={'dedupe_findings'})
        self.assertEqual(run_all(call)['state'], 'none')
        others = [name for name in upgrade_backfills.BACKFILLS if name != 'dedupe_findings']
        self.assertEqual([name for name in call.names if name != 'dedupe_findings'], others)
        self.assertEqual(call.names.count('dedupe_findings'), upgrade_backfills.MAX_ATTEMPTS)
        self.assertLess(call.names.index('fold_alias_findings'), call.names.index('dedupe_findings', 3))  # retried after the rest
        failed = AgentActivity.objects.filter(status='failed', message__contains='dedupe_findings')
        self.assertTrue(failed.filter(message__contains='given up').exists())

    def test_a_backfill_that_succeeds_on_a_retry_is_done(self):
        call = Calls(fail={'rerate_hygiene'})
        upgrade_backfills.run_next(call=call)  # the first one runs
        for _ in range(4):
            upgrade_backfills.run_next(call=call)
        call.fail.clear()
        run_all(call)
        self.assertEqual(upgrade_backfills.pending(), [])
        self.assertFalse(AgentActivity.objects.filter(message__contains='given up').exists())

    def test_it_can_be_turned_off(self):
        call = Calls()
        with mock.patch.dict('os.environ', {'CVENGINE_AUTO_BACKFILLS': '0'}):
            self.assertEqual(upgrade_backfills.run_next(call=call)['state'], 'off')
        self.assertEqual(call.names, [])

    def test_another_worker_holding_the_claim_runs_nothing(self):
        import contextlib
        call = Calls()

        @contextlib.contextmanager
        def held(*args):
            yield 'other-worker'
        with mock.patch('reNgine.resources.redis_claim', held):
            self.assertEqual(upgrade_backfills.run_next(call=call)['state'], 'held')
        self.assertEqual(call.names, [])

    def test_a_backfill_added_later_runs_alone_on_an_install_that_ran_the_rest(self):
        run_all(Calls())
        call = Calls()
        with mock.patch.object(upgrade_backfills, 'BACKFILLS', upgrade_backfills.BACKFILLS + ('a_new_backfill',)):
            run_all(call)
        self.assertEqual(call.names, ['a_new_backfill'])


class RealCommandsTests(TestCase):
    def test_every_listed_command_applies_cleanly_on_an_install_with_nothing_to_change(self):
        """A fresh install (or one with nothing to fix) runs each real command with --apply, without a person or an error."""
        with mock.patch('cveFeed.tasks.run_upgrade_backfills.apply_async'):
            result = run_all(None)
        self.assertEqual(result['state'], 'none')
        self.assertFalse(AgentActivity.objects.filter(status='failed').exists(),
                         list(AgentActivity.objects.filter(status='failed').values_list('message', flat=True)))
        for name in upgrade_backfills.BACKFILLS:
            self.assertTrue(BackgroundCursor.objects.filter(lane=('bf:' + name)[:32]).exists(), name)


class WorkerStartTests(TestCase):
    def test_a_worker_start_queues_the_run_while_backfills_are_pending_and_not_after(self):
        from reNgine.celery import run_pending_backfills
        with mock.patch('cveFeed.tasks.run_upgrade_backfills.apply_async') as queued:
            run_pending_backfills()
        queued.assert_called_once()
        run_all(Calls())
        with mock.patch('cveFeed.tasks.run_upgrade_backfills.apply_async') as queued:
            run_pending_backfills()
        queued.assert_not_called()

    def test_the_task_queues_the_next_run_while_any_remain(self):
        from cveFeed.tasks import run_upgrade_backfills
        with mock.patch.object(upgrade_backfills, 'run_next', return_value={'state': 'done', 'name': 'x', 'remaining': 3}), \
                mock.patch('cveFeed.tasks.run_upgrade_backfills.apply_async') as queued:
            run_upgrade_backfills()
        queued.assert_called_once_with(countdown=5)
        with mock.patch.object(upgrade_backfills, 'run_next', return_value={'state': 'failed', 'name': 'x', 'remaining': 3}), \
                mock.patch('cveFeed.tasks.run_upgrade_backfills.apply_async') as queued:
            run_upgrade_backfills()
        queued.assert_called_once_with(countdown=600)
        with mock.patch.object(upgrade_backfills, 'run_next', return_value={'state': 'none', 'name': '', 'remaining': 0}), \
                mock.patch('cveFeed.tasks.run_upgrade_backfills.apply_async') as queued:
            run_upgrade_backfills()
        queued.assert_not_called()
