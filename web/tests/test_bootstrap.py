from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import scan_control
from cveFeed.models import CVEEntry
from cveFeed.tasks import BOOTSTRAP_LOCK, bootstrap_first_run


class FirstRunBootstrapTests(TestCase):
	def setUp(self):
		cache.delete(BOOTSTRAP_LOCK)
		self.addCleanup(cache.delete, BOOTSTRAP_LOCK)

	def test_a_new_install_loads_the_seed_then_the_feed_then_threat_intel_then_backfill(self):
		with mock.patch('celery.chain') as chain:
			result = bootstrap_first_run.run()
		self.assertEqual(result, {'started': True})
		names = [sig.task for sig in chain.call_args.args]
		self.assertEqual(names, ['load_cve_seed', 'sync_cve_now_feed', 'sync_threat_intel', 'backfill_cve_now_feed'])  # the published catalog first
		chain.return_value.apply_async.assert_called_once_with()

	def test_an_install_that_already_has_cves_never_repeats_it(self):
		CVEEntry.objects.create(cve_id='CVE-2099-1', published_at=timezone.now())
		with mock.patch('celery.chain') as chain, mock.patch('cveFeed.tasks.load_cve_seed.apply_async'):
			result = bootstrap_first_run.run()
		self.assertEqual(result, {'skipped': 'the CVE feed is already loaded'})
		chain.assert_not_called()

	def test_workers_starting_together_queue_it_once(self):
		with mock.patch('celery.chain') as chain:
			first, second = bootstrap_first_run.run(), bootstrap_first_run.run()
		self.assertEqual(first, {'started': True})
		self.assertIn('already under way', second['skipped'])
		self.assertEqual(chain.return_value.apply_async.call_count, 1)

	def test_it_is_feed_work_that_a_global_pause_does_not_hold_back(self):
		self.assertIn('bootstrap_first_run', scan_control.PAUSE_EXEMPT_TASKS)

	def test_a_worker_coming_up_queues_it_after_a_short_settle_and_never_fails(self):
		from reNgine.celery import start_first_run_bootstrap
		with mock.patch('cveFeed.tasks.bootstrap_first_run.apply_async') as queue:
			start_first_run_bootstrap()
		queue.assert_called_once_with(countdown=45)
		with mock.patch('cveFeed.tasks.bootstrap_first_run.apply_async', side_effect=OSError('broker down')):
			start_first_run_bootstrap()  # must not raise: it would stop the worker from starting

	def test_the_task_is_registered_on_the_feed_queue(self):
		self.assertEqual(bootstrap_first_run.queue, 'cve_feed_queue')
