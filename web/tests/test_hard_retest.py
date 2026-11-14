from unittest import mock

from django.test import TestCase

from cveFeed import discovery
from cveFeed.models import HostState
from tests.test_perf_hostpipeline import _stages
from tests.test_retest import RetestFixture
from tests.test_route_auth import RouteFixture


class ForcedRouteAuthTests(RouteFixture, TestCase):
	"""Verdict 7: a re-test asks the host's routes again now, whatever the ledger says."""

	def test_a_fresh_route_is_not_asked_again_unless_forced(self):
		scan = self.scan()
		self.run_it(scan)
		first = len(self.asked)
		self.assertGreater(first, 0)
		again = self.run_it(self.scan())
		self.assertEqual((len(self.asked), again['reused']), (first, first))  # inside the 7 day TTL: nothing is asked
		forced = self.run_it(self.scan(), force=True)
		self.assertEqual(len(self.asked), 2 * first)
		self.assertEqual(forced['routes'], first)
		self.assertEqual(forced['reused'], 0)


class RetestPipelineForcesRouteAuthTests(RetestFixture, TestCase):
	def test_a_retest_run_passes_force_and_a_plain_run_does_not(self):
		HostState.objects.create(project=self.project, domain=self.domain, host='known.ct.test', state={})
		_, kwargs = _stages()
		with mock.patch('cveFeed.route_auth.run_route_auth', return_value={'routes': 0}) as run:
			discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], retest=True, source_scan_id=7, **kwargs)
		self.assertIs(run.call_args.kwargs.get('force'), True)
		_, kwargs = _stages()
		with mock.patch('cveFeed.route_auth.run_route_auth', return_value={'routes': 0}) as run:
			discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		self.assertNotIn('force', run.call_args.kwargs)
