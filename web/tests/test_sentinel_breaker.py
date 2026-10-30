"""A Sentinel that keeps failing one kind of work is not handed it for a while: the server runs that work itself, then tries the Sentinel again."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi.models import SentinelTask
from tests.test_sentinel_dispatch import DispatchBase


class BreakerTests(DispatchBase):
    def setUp(self):
        super().setUp()
        self.agent = self.make_sentinel(['nmap', 'nuclei_light'])

    def finish(self, status, kind='nuclei_light', ago=1):
        SentinelTask.objects.create(project=self.project, kind=kind, target={}, agent=self.agent, status=status,
                                    finished_at=timezone.now() - timedelta(minutes=ago))

    def state(self):
        return sb.capacity_state(self.project, 'nuclei_light')['state']

    def test_three_failures_in_a_row_withhold_the_kind_and_the_server_runs_it(self):
        self.assertEqual(self.state(), 'free')
        for ago in (3, 2, 1):
            self.finish('failed', ago=ago)
        self.assertEqual(self.state(), 'none')
        self.assertNotIn('nuclei_light', sb.effective_capabilities(self.agent))
        self.assertIn('nmap', sb.effective_capabilities(self.agent))

    def test_two_failures_are_not_enough(self):
        for ago in (2, 1):
            self.finish('failed', ago=ago)
        self.assertEqual(self.state(), 'free')

    def test_a_success_breaks_the_streak(self):
        self.finish('failed', ago=4)
        self.finish('failed', ago=3)
        self.finish('done', ago=2)
        self.finish('failed', ago=1)
        self.assertEqual(self.state(), 'free')

    def test_other_kinds_are_unaffected_and_do_not_count_toward_the_streak(self):
        self.finish('failed', ago=3)
        self.finish('failed', kind='nmap', ago=2)
        self.finish('failed', ago=1)
        self.assertEqual(self.state(), 'free')
        for ago in (6, 5, 4):
            self.finish('failed', kind='nmap', ago=ago)
        self.assertEqual(sb.capacity_state(self.project, 'nmap')['state'], 'none')
        self.assertEqual(self.state(), 'free')

    def test_after_the_cooldown_the_kind_is_offered_once_more_and_trips_again_if_it_fails(self):
        for ago in (22, 21, 20):
            self.finish('failed', ago=ago)
        self.assertEqual(self.state(), 'free')  # 20 minutes ago is past the 15 minute cool-off: one more try
        self.finish('failed', ago=0)
        self.assertEqual(self.state(), 'none')  # the try failed too: withheld again

    def test_a_probe_that_succeeds_clears_it(self):
        for ago in (22, 21, 20):
            self.finish('failed', ago=ago)
        self.finish('done', ago=0)
        self.assertEqual(self.state(), 'free')

    def test_cancelled_or_expired_tasks_are_not_failures(self):
        for ago, status in ((3, 'expired'), (2, 'expired'), (1, 'expired')):
            self.finish(status, ago=ago)
        self.assertEqual(self.state(), 'free')

    def test_the_cooldown_can_be_turned_off(self):
        for ago in (3, 2, 1):
            self.finish('failed', ago=ago)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_KIND_COOLDOWN_MINUTES': '0'}):
            self.assertEqual(self.state(), 'free')

    def test_the_streak_length_can_be_set(self):
        for ago in (3, 2, 1):
            self.finish('failed', ago=ago)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_KIND_FAIL_STREAK': '5'}):
            self.assertEqual(self.state(), 'free')

    def test_the_withheld_kind_and_its_retry_time_are_reported(self):
        for ago in (3, 2, 1):
            self.finish('failed', ago=ago)
        withheld = sb.failing_kinds(self.agent)
        self.assertEqual(list(withheld), ['nuclei_light'])
        self.assertEqual(withheld['nuclei_light']['failures'], 3)
        self.assertGreater(withheld['nuclei_light']['retry_at'], timezone.now())
