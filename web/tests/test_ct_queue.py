"""``ctwatch_queue`` stays bounded: the sweep reads the backlog first, a domain with a lookup on its way is not queued again, every
message expires, and a domain whose lookup failed for good is left alone for a while (cveFeed.ct_queue)."""
import os
from unittest import mock

from celery.exceptions import Retry
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import ct_queue, ctmonitor, ledger, tasks
from dashboard.models import Org, Project, ProjectMembership, SystemTimings
from targetApp.models import Domain


class FakeRedis:
	"""The few Redis calls ct_queue makes, in memory (no keys outlive a test)."""

	def __init__(self, waiting=0):
		self.keys, self.waiting, self.ttls = {}, waiting, {}

	def set(self, key, value, nx=False, ex=None):
		if nx and key in self.keys:
			return None
		self.keys[key] = value
		self.ttls[key] = ex
		return True

	def delete(self, key):
		return int(self.keys.pop(key, None) is not None)

	def exists(self, key):
		return int(key in self.keys)

	def llen(self, name):
		return self.waiting if name == ct_queue.QUEUE else 0


class DownRedis(FakeRedis):
	def set(self, *a, **k):
		raise ConnectionError('redis is down')

	def llen(self, name):
		raise ConnectionError('redis is down')

	def delete(self, key):
		raise ConnectionError('redis is down')


class Base(TestCase):
	def setUp(self):
		org = Org.objects.create(name='CTQ', slug='ctq')
		self.project = Project.objects.create(name='P', slug='ctq-p', insert_date=timezone.now(), org=org)
		self.redis = FakeRedis()
		for patcher in (mock.patch.object(ct_queue, '_client', lambda: self.redis),
						mock.patch('cveFeed.ledger.sweep_claim', return_value=True),  # the real claim outlives a test, in Redis
						mock.patch.dict(os.environ, {'CVENGINE_CT_BACKLOG_MAX': ''})):
			patcher.start()
			self.addCleanup(patcher.stop)

	def domains(self, count, prefix='h'):
		return [Domain.objects.create(name=f'{prefix}{i}.test', project=self.project, insert_date=timezone.now()) for i in range(count)]

	def sweep(self, window_minutes=20):
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as publish, \
				mock.patch.object(SystemTimings, 'current', return_value=SystemTimings(ct_watch_minutes=window_minutes)):
			out = tasks.watch_certificates_all()
		return out, publish


class SweepBoundTests(Base):
	def test_a_sweep_is_skipped_when_the_backlog_is_at_the_cap(self):
		self.domains(5)
		self.redis.waiting = ct_queue.DEFAULT_BACKLOG_MAX
		out, publish = self.sweep()
		self.assertEqual(out['queued'], 0)
		self.assertIn('ctwatch_queue already holds', out['skipped'])
		publish.assert_not_called()

	def test_a_sweep_queues_only_the_room_left_under_the_cap(self):
		self.domains(10)
		with mock.patch.dict(os.environ, {'CVENGINE_CT_BACKLOG_MAX': '100'}):
			self.redis.waiting = 94
			out, publish = self.sweep()
		self.assertEqual((out['queued'], publish.call_count), (6, 6))
		self.assertEqual(out['held_back'], 4)

	def test_the_cap_is_one_sweep_batch_at_least(self):
		self.assertEqual(ct_queue.backlog_max(0), ct_queue.DEFAULT_BACKLOG_MAX)
		self.assertEqual(ct_queue.backlog_max(1200), 1200)  # a 60 minute interval queues 1200 an hour: not cut to 500
		with mock.patch.dict(os.environ, {'CVENGINE_CT_BACKLOG_MAX': '50'}):
			self.assertEqual(ct_queue.backlog_max(1200), 50)
		with mock.patch.dict(os.environ, {'CVENGINE_CT_BACKLOG_MAX': 'lots'}):
			self.assertEqual(ct_queue.backlog_max(0), ct_queue.DEFAULT_BACKLOG_MAX)

	def test_every_priority_step_of_the_queue_counts_toward_the_backlog(self):
		seen = []
		client = mock.Mock(llen=lambda name: seen.append(name) or 1)
		with mock.patch.object(ct_queue, '_client', lambda: client):
			self.assertEqual(ct_queue.backlog(), 4)
		self.assertEqual(sorted(seen), sorted('ctwatch_queue' + s for s in ('', '\x06\x163', '\x06\x166', '\x06\x169')))


class MarkerTests(Base):
	def test_a_domain_already_queued_is_not_queued_again_by_the_next_sweep(self):
		self.domains(3)
		first, publish = self.sweep()
		self.assertEqual(first['queued'], 3)
		second, publish2 = self.sweep()  # nothing ran, so the ledger still says "never checked"
		self.assertEqual(second['queued'], 0)
		publish2.assert_not_called()
		self.assertTrue(all(ttl > 20 * 60 for ttl in self.redis.ttls.values()))

	def test_the_marker_is_set_before_publishing_and_dropped_if_publishing_fails(self):
		domain = self.domains(1)[0]
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async', side_effect=OSError('broker')):
			with self.assertRaises(OSError):
				ct_queue.queue_lookups([domain.id], 60)
		self.assertFalse(ct_queue.is_queued(domain.id))

	def test_the_marker_is_cleared_when_the_lookup_ends(self):
		domain = self.domains(1)[0]
		ct_queue.queue_lookups([domain.id], 3600)
		with mock.patch('cveFeed.ctmonitor.run_ct_watch', return_value={'checked': 1, 'new': 0}):
			tasks.watch_certificate_transparency.run(domain.id)
		self.assertFalse(ct_queue.is_queued(domain.id))

	def test_the_marker_is_cleared_when_the_lookup_fails_for_good_or_raises(self):
		domain = self.domains(1)[0]
		for outcome in ({'return_value': {'checked': 0, 'new': 0, 'failed': True}}, {'side_effect': ValueError('unreadable')}):
			ct_queue.queue_lookups([domain.id], 3600)
			task = tasks.watch_certificate_transparency
			task.push_request(retries=3)  # the retries are used up
			try:
				with mock.patch('cveFeed.ctmonitor.run_ct_watch', **outcome):
					try:
						task.run(domain.id)
					except ValueError:
						pass
			finally:
				task.pop_request()
			self.assertFalse(ct_queue.is_queued(domain.id), outcome)

	def test_the_marker_stays_while_the_lookup_is_retried(self):
		domain = self.domains(1)[0]
		ct_queue.queue_lookups([domain.id], 3600)
		with mock.patch('cveFeed.ctmonitor.run_ct_watch', side_effect=ctmonitor.CtBusy(120.0)), \
				mock.patch.object(tasks.watch_certificate_transparency, 'retry', side_effect=Retry()):
			with self.assertRaises(Retry):
				tasks.watch_certificate_transparency.run(domain.id)
		self.assertTrue(ct_queue.is_queued(domain.id))
		with mock.patch('cveFeed.ctmonitor.run_ct_watch', return_value={'checked': 0, 'new': 0, 'failed': True}), \
				mock.patch.object(tasks.watch_certificate_transparency, 'retry', side_effect=Retry()):
			with self.assertRaises(Retry):  # first attempt of a failing lookup: tried again later
				tasks.watch_certificate_transparency.run(domain.id)
		self.assertTrue(ct_queue.is_queued(domain.id))
		self.assertEqual(ledger.fresh(ct_queue.FAILED_SERVICE, [domain.name], self.project), set())  # not a final failure yet


class ExpiryTests(Base):
	def test_the_sweep_publishes_every_lookup_with_a_lifetime_counted_from_its_start(self):
		self.domains(3)
		_, publish = self.sweep(window_minutes=20)
		calls = [c.kwargs for c in publish.call_args_list]
		self.assertEqual([c['countdown'] for c in calls], [0, 2, 5])
		self.assertEqual([c['expires'] for c in calls], [1200, 1202, 1205])

	def test_adding_a_target_publishes_with_a_lifetime(self):
		from agentapi.services import Ctx, add_target
		user = User.objects.create_user('ctquser', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as publish:
			add_target(Ctx(user=user), 'ctq-p', 'added.test')
		self.assertEqual(publish.call_args.kwargs['expires'], ct_queue.ADD_LIFETIME)
		self.assertEqual(publish.call_args.kwargs['args'], [Domain.objects.get(name='added.test').id])


class FailedDomainTests(Base):
	def test_a_domain_that_failed_for_good_is_left_out_of_the_sweeps_until_the_failure_ages_out(self):
		poison, fine = self.domains(2)
		task = tasks.watch_certificate_transparency
		task.push_request(retries=3)
		try:
			with mock.patch('cveFeed.ctmonitor.run_ct_watch', return_value={'checked': 0, 'new': 0, 'failed': True}):
				task.run(poison.id)
		finally:
			task.pop_request()
		out, publish = self.sweep()
		self.assertEqual([c.kwargs['args'] for c in publish.call_args_list], [[fine.id]])
		self.assertEqual(out['recently_failed'], 1)
		from cveFeed.models import ServiceRun
		from datetime import timedelta
		ServiceRun.objects.filter(service=ct_queue.FAILED_SERVICE).update(finished_at=timezone.now() - timedelta(hours=7))
		self.redis.keys.clear()
		_, publish = self.sweep()
		self.assertEqual(sorted(c.kwargs['args'][0] for c in publish.call_args_list), sorted([poison.id, fine.id]))  # asked again after 6 hours

	def test_an_exception_in_the_lookup_is_a_failure_too(self):
		poison, _ = self.domains(2)
		with mock.patch('cveFeed.ctmonitor.run_ct_watch', side_effect=MemoryError('32 MB reply')):
			with self.assertRaises(MemoryError):
				tasks.watch_certificate_transparency.run(poison.id)
		self.assertEqual(ct_queue.recently_failed([(poison.id, poison.name, self.project.id)]), {poison.id})

	def test_the_failure_has_its_own_ttl(self):
		self.assertEqual(ledger.ttl('ct-watch-failed'), 6 * 3600)


class AddPathTests(Base):
	def test_adding_a_target_goes_through_the_shared_helper(self):
		from agentapi.services import Ctx, add_target
		user = User.objects.create_user('ctquser2', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		with mock.patch('cveFeed.ct_queue.queue_lookups') as helper:
			add_target(Ctx(user=user), 'ctq-p', 'single.test')
		helper.assert_called_once_with([Domain.objects.get(name='single.test').id], ct_queue.ADD_LIFETIME)

	def test_a_bulk_add_goes_through_the_shared_helper_for_the_domains_only(self):
		from agentapi.services import add_entries
		with mock.patch('cveFeed.ct_queue.queue_lookups') as helper:
			add_entries(self.project, ['bulk-a.test', 'bulk-b.test', '203.0.113.9'], discover=False)
		ids = sorted(Domain.objects.filter(name__in=['bulk-a.test', 'bulk-b.test']).values_list('id', flat=True))
		helper.assert_called_once()
		self.assertEqual(sorted(helper.call_args.args[0]), ids)
		self.assertEqual(helper.call_args.args[1], ct_queue.ADD_LIFETIME)

	def test_adding_a_domain_the_sweep_already_queued_does_not_queue_it_twice(self):
		domain = self.domains(1)[0]
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as publish:
			self.assertEqual(ct_queue.queue_lookups([domain.id], ct_queue.ADD_LIFETIME), [domain.id])
			self.assertEqual(ct_queue.queue_lookups([domain.id], ct_queue.ADD_LIFETIME), [])
		self.assertEqual(publish.call_count, 1)


class FailOpenTests(Base):
	def test_with_no_redis_a_lookup_is_still_queued_with_its_lifetime(self):
		domain = self.domains(1)[0]
		for client in (None, DownRedis()):
			self.redis = client
			with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as publish:
				self.assertEqual(ct_queue.queue_lookups([domain.id], 600), [domain.id])
				self.assertEqual(ct_queue.queue_lookups([domain.id], 600), [domain.id])  # no marker to stop it: bounded by the lifetime
			self.assertEqual(publish.call_args.kwargs['expires'], 600)
			ct_queue.clear(domain.id)  # never raises

	def test_the_sweep_runs_when_the_backlog_cannot_be_read_and_stays_within_the_cap(self):
		self.domains(5)
		self.redis = DownRedis()
		with mock.patch.dict(os.environ, {'CVENGINE_CT_BACKLOG_MAX': '3'}):
			out, publish = self.sweep()
		self.assertEqual(out['queued'], 3)
		self.assertIsNone(out['backlog'])


class SettingsTests(SimpleTestCase):
	def test_the_new_variable_is_documented(self):
		doc = open(os.path.join(os.path.dirname(__file__), '..', '..', 'docs', 'CONFIGURATION.md')).read()
		self.assertIn('CVENGINE_CT_BACKLOG_MAX', doc)
