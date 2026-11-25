"""Failures that a best effort step catches and goes on from are written to the log, so an operator can see them: the step's own
outcome is unchanged (it still goes on), only the silence is gone."""
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase


class WatchdogLogsTests(TestCase):
    def test_a_notice_that_cannot_be_closed_is_logged(self):
        from cveFeed import watchdog
        with mock.patch('cveFeed.models.AdminAlert.objects.filter', side_effect=RuntimeError('database gone')), \
                self.assertLogs('cveFeed.watchdog', 'WARNING') as logs:
            watchdog._expire_open_problem_notice(SimpleNamespace(code='R9'))
        self.assertIn('R9', logs.output[0])
        self.assertIn('database gone', logs.output[0])

    def test_a_worker_resize_that_fails_after_the_override_ends_is_logged_and_the_override_still_ends(self):
        from cveFeed import scan_concurrency, watchdog
        ctx = SimpleNamespace(states={'R3': SimpleNamespace(data={'override': {'key': 'k', 'value': 3, 'env_name': 'CVENGINE_X'}})})
        row = SimpleNamespace(values={'k': 3}, meta={'k': {'by': watchdog.WATCHDOG_ACTOR}})
        with mock.patch.object(scan_concurrency, 'BY_KEY', {'k': SimpleNamespace(auto_min=5)}), \
                mock.patch.object(scan_concurrency, 'saved_row', return_value=row), \
                mock.patch.object(scan_concurrency, 'env_value', return_value=None), \
                mock.patch.object(scan_concurrency, 'env_pin', return_value=False), \
                mock.patch.object(scan_concurrency, 'update') as update, \
                mock.patch.object(scan_concurrency, 'apply_discovery', side_effect=RuntimeError('no worker')), \
                self.assertLogs('cveFeed.watchdog', 'WARNING') as logs:
            why = watchdog.release_pool_override(ctx)
        self.assertIn('no longer holds it down', why)
        update.assert_called_once()
        self.assertNotIn('override', ctx.states['R3'].data)
        self.assertIn('discovery worker could not be resized', logs.output[0])


class ClaimRenewalLogsTests(SimpleTestCase):
    def test_a_claim_that_cannot_be_renewed_or_was_taken_is_logged_and_the_others_are_still_renewed(self):
        from agentapi import stage_runs
        claims = [('k1', 'me'), ('k2', 'me'), ('k3', 'me')]
        with mock.patch.object(stage_runs, '_redis', return_value=object()), \
                mock.patch('cvengine.resources.claim_refresh', side_effect=[RuntimeError('redis gone'), 'lost', 'ok']) as refresh, \
                self.assertLogs('agentapi.stage_runs', 'WARNING') as logs:
            stage_runs._renew_claims(claims)
        self.assertEqual([c.args[1] for c in refresh.call_args_list], ['k1', 'k2', 'k3'])
        self.assertEqual(len(logs.output), 2)
        self.assertIn('could not be renewed, first k1', logs.output[0])
        self.assertIn('taken by another job', logs.output[1])
        self.assertIn('k2', logs.output[1])

    def test_claims_that_renew_log_nothing(self):
        from agentapi import stage_runs
        with mock.patch.object(stage_runs, '_redis', return_value=object()), \
                mock.patch('cvengine.resources.claim_refresh', return_value='ok'), \
                mock.patch.object(stage_runs.logger, 'warning') as warning:
            stage_runs._renew_claims([('k1', 'me')])
        warning.assert_not_called()


class AbortWakeLogsTests(SimpleTestCase):
    def test_a_wake_that_fails_is_logged_and_the_abort_still_stands(self):
        from cvengine import resources
        try:
            with mock.patch.object(resources, 'get_store', return_value=SimpleNamespace(r=None)), \
                    mock.patch('agentapi.stage_runs.wake_scan', side_effect=RuntimeError('broker gone')), \
                    self.assertLogs('cvengine.resources', 'WARNING') as logs:
                resources.request_abort(424242)
            self.assertIn('424242', logs.output[0])
            self.assertIn(424242, resources._aborted_here)
        finally:
            resources._aborted_here.discard(424242)
