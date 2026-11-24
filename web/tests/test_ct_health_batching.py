"""The certificate transparency rollup in a worker: outcomes are added up in memory and written by a timer, one additive UPDATE per source
and day, instead of one UPDATE per lookup on the same hot row (cveFeed/ct_health.py). The figures the status line and the stalled check
show must be the same as when every lookup wrote the row itself, and nothing counted may be lost when a write fails or the worker stops.
No test reaches crt.sh or Cert Spotter: every request is mocked."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.db.models import F
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import ct_health, ctmonitor
from cveFeed.models import CtLookupDay
from tests.test_ct_fallback import FallbackTestCase

FIELDS = ('day', 'source', 'ok', 'failed', 'busy', 'names', 'new_hosts', 'last_ok_at', 'last_attempt_at', 'last_failed_at', 'last_error')


def develop_record(source, outcome, names=0, new=0, error='', now=None):
	"""``ct_health.record`` as it was before batching (one UPDATE per lookup): the reference the batched rollup must match."""
	if outcome not in ct_health.OUTCOMES:
		return
	now = now or timezone.now()
	day = now.date()
	fields = {outcome: F(outcome) + 1, 'last_attempt_at': now}
	if outcome == 'ok':
		fields.update(names=F('names') + max(0, int(names)), new_hosts=F('new_hosts') + max(0, int(new)), last_ok_at=now)
	elif outcome == 'failed':
		fields.update(last_failed_at=now, last_error=(str(error) or 'failed')[:300])
	if not CtLookupDay.objects.filter(day=day, source=source).update(**fields):
		_, created = CtLookupDay.objects.get_or_create(day=day, source=source)
		CtLookupDay.objects.filter(day=day, source=source).update(**fields)
		if created:
			CtLookupDay.objects.filter(day__lt=day - timedelta(days=ct_health.KEEP_DAYS)).delete()


def rows():
	return sorted(CtLookupDay.objects.values_list(*FIELDS))


def rollup_statements(queries):
	return [q['sql'] for q in queries if 'ctlookupday' in q['sql'].lower()]


class Batching:
	"""Mixin: this test runs as a worker does, outcomes kept in memory until a flush, and leaves no state behind for the next test."""

	def start_batching(self):
		ct_health._pending.clear()
		saved = dict(ct_health._state)
		ct_health._state['batching'] = True
		self.addCleanup(ct_health._state.update, saved)
		self.addCleanup(ct_health._pending.clear)


def outcomes(start):
	"""A day of mixed outcomes on both sources, in time order, as the watch produces them."""
	at = lambda minutes: start + timedelta(minutes=minutes)  # noqa: E731
	return [
		('crt.sh', 'busy', {}, at(1)), ('crt.sh', 'busy', {}, at(2)), ('crt.sh', 'ok', {'names': 4, 'new': 1}, at(3)),
		('crt.sh', 'failed', {'error': 'HTTP 502 after 4 attempts'}, at(4)), ('certspotter', 'ok', {'names': 2, 'new': 2}, at(5)),
		('crt.sh', 'busy', {}, at(6)), ('certspotter', 'busy', {}, at(7)), ('crt.sh', 'failed', {'error': ''}, at(8)),
		('crt.sh', 'ok', {'names': 7, 'new': 0}, at(9)), ('certspotter', 'failed', {'error': 'HTTP 429 (rate limited)'}, at(10)),
		('crt.sh', 'busy', {}, at(11)), ('crt.sh', 'ok', {'names': -3, 'new': -1}, at(12)),
	]


class EquivalenceTests(Batching, TestCase):
	def setUp(self):
		cache.clear()
		self.addCleanup(cache.clear)
		self.start = timezone.now().replace(hour=1, minute=0, second=0, microsecond=0)
		self.now = self.start + timedelta(minutes=30)
		CtLookupDay.objects.create(day=self.start.date() - timedelta(days=ct_health.KEEP_DAYS + 2), source='crt.sh', ok=1)  # pruned by both

	def shown(self):
		return rows(), ct_health.summary(self.now), ct_health.stalled_check(self.now)

	def develop(self, events):
		for source, outcome, kw, at in events:
			develop_record(source, outcome, now=at, **kw)
		return self.shown()

	def reset(self):
		CtLookupDay.objects.all().delete()
		CtLookupDay.objects.create(day=self.start.date() - timedelta(days=ct_health.KEEP_DAYS + 2), source='crt.sh', ok=1)

	def test_one_flush_shows_the_same_rows_line_and_check_as_one_write_per_lookup(self):
		events = outcomes(self.start)
		before = self.develop(events)
		self.reset()
		self.start_batching()
		for source, outcome, kw, at in events:
			ct_health.record(source, outcome, now=at, **kw)
		self.assertEqual(ct_health.flush(), 2)
		self.assertEqual(self.shown(), before)
		self.assertIn('4 lookups ok, 3 failed', before[1]['line'])

	def test_flushes_at_any_point_and_from_two_processes_add_up_to_the_same_figures(self):
		events = outcomes(self.start)
		before = self.develop(events)
		self.reset()
		self.start_batching()
		for i, (source, outcome, kw, at) in enumerate(events):
			ct_health.record(source, outcome, now=at, **kw)
			if i in (0, 3, 4, 9):  # timer ticks fall between lookups
				ct_health.flush()
		ct_health.flush()
		self.assertEqual(self.shown(), before)
		# two worker processes writing the same row: each adds its own batch, newest time and newest error win whatever the order
		self.reset()
		first, second = events[::2], events[1::2]
		for batch in (second, first):  # the later events are written first
			for source, outcome, kw, at in batch:
				ct_health.record(source, outcome, now=at, **kw)
			ct_health.flush()
		self.assertEqual(self.shown(), before)

	def test_without_batching_each_outcome_is_written_at_once_as_before(self):
		events = outcomes(self.start)
		before = self.develop(events)
		self.reset()
		for source, outcome, kw, at in events:
			ct_health.record(source, outcome, now=at, **kw)
			self.assertEqual(ct_health._pending, {})
		self.assertEqual(self.shown(), before)


class StatementCountTests(Batching, FallbackTestCase):
	LOOKUPS = 50

	def busy_lookups(self):
		with CaptureQueriesContext(connection) as ctx:
			for _ in range(self.LOOKUPS):
				ctmonitor.reserve_slot(500)  # crt.sh's shared pacing says wait: the lookup goes back to the queue
				with mock.patch.object(ctmonitor.requests, 'get') as get, self.assertRaises(ctmonitor.CtBusy):
					ctmonitor.run_ct_watch(self.domain.id)
				get.assert_not_called()
		return rollup_statements(ctx.captured_queries)

	def test_fifty_busy_lookups_write_the_row_once_not_fifty_times(self):
		self.start_batching()
		during = self.busy_lookups()
		self.assertEqual(during, [])  # no lookup touches the hot row
		with CaptureQueriesContext(connection) as ctx:
			ct_health.flush()
		flush = rollup_statements(ctx.captured_queries)
		self.assertLessEqual(len(flush), 5)  # first row of the day: UPDATE, get_or_create (SELECT, INSERT), UPDATE, prune
		self.assertEqual(ct_health.summary()['totals']['busy'], self.LOOKUPS)
		with CaptureQueriesContext(connection) as ctx:
			self.busy_lookups()
			ct_health.flush()
		self.assertEqual(len(rollup_statements(ctx.captured_queries)), 1)  # the row exists: one UPDATE for fifty lookups
		self.assertEqual(ct_health.summary()['totals']['busy'], 2 * self.LOOKUPS)

	def test_before_batching_every_lookup_wrote_the_row(self):
		during = self.busy_lookups()  # not a worker: written at once, the path every lookup took before
		self.assertGreaterEqual(len(during), self.LOOKUPS)
		self.assertEqual(ct_health.summary()['totals']['busy'], self.LOOKUPS)

	def test_a_lookup_that_raises_is_still_counted_by_the_next_flush(self):
		self.start_batching()
		ctmonitor.reserve_slot(500)
		with mock.patch.object(ctmonitor.requests, 'get'), self.assertRaises(ctmonitor.CtBusy):
			ctmonitor.run_ct_watch(self.domain.id)
		def fails_after_noting(name):
			ctmonitor._note(ctmonitor.CRTSH, 'failed', name, error='x')
			raise RuntimeError('a reply it cannot read')
		with mock.patch.object(ctmonitor, 'lookup', side_effect=fails_after_noting), self.assertRaises(RuntimeError):
			ctmonitor.run_ct_watch(self.domain.id)
		self.assertFalse(CtLookupDay.objects.exists())
		ct_health.flush()
		row = CtLookupDay.objects.get(source='crt.sh')
		self.assertEqual((row.busy, row.failed, row.last_error), (1, 1, 'x'))


class FailureAndShutdownTests(Batching, TestCase):
	def setUp(self):
		self.now = timezone.now()
		self.start_batching()

	def test_a_failed_write_keeps_the_counts_for_the_next_flush(self):
		ct_health.record('crt.sh', 'ok', names=3, new=1, now=self.now - timedelta(seconds=5))
		ct_health.record('crt.sh', 'failed', error='HTTP 502', now=self.now - timedelta(seconds=4))
		with mock.patch.object(ct_health, '_write', side_effect=RuntimeError('database gone')):
			self.assertEqual(ct_health.flush(), 0)  # no exception
		self.assertFalse(CtLookupDay.objects.exists())
		ct_health.record('crt.sh', 'busy', now=self.now)  # counted meanwhile
		self.assertEqual(ct_health.flush(), 1)
		row = CtLookupDay.objects.get(source='crt.sh')
		self.assertEqual((row.ok, row.failed, row.busy, row.names, row.new_hosts, row.last_error), (1, 1, 1, 3, 1, 'HTTP 502'))
		self.assertEqual((row.last_attempt_at, row.last_ok_at), (self.now, self.now - timedelta(seconds=5)))
		self.assertEqual(ct_health._pending, {})

	def test_a_newer_failure_counted_while_the_write_failed_keeps_its_error(self):
		ct_health.record('crt.sh', 'failed', error='old', now=self.now - timedelta(seconds=9))
		with mock.patch.object(ct_health, '_write', side_effect=RuntimeError('database gone')):
			ct_health.flush()
		ct_health.record('crt.sh', 'failed', error='new', now=self.now)
		ct_health.flush()
		self.assertEqual(CtLookupDay.objects.get(source='crt.sh').last_error, 'new')

	def test_the_worker_writes_what_is_left_when_it_stops(self):
		from celery.signals import worker_process_shutdown, worker_shutdown
		with mock.patch.object(ct_health.atexit, 'register') as at_exit:
			ct_health.install()
		at_exit.assert_called_once_with(ct_health.flush)
		for signal, uid in ((worker_shutdown, 'ct-health-flush-worker'), (worker_process_shutdown, 'ct-health-flush-child')):
			ct_health.record('crt.sh', 'busy', now=self.now)
			ours = [r for r in signal.receivers if r[0][0] == uid]
			self.assertEqual(len(ours), 1)
			with mock.patch.object(signal, 'receivers', ours), mock.patch.object(signal, 'sender_receivers_cache', {}):
				signal.send(sender=None)
			self.assertEqual(ct_health._pending, {})
		self.assertEqual(CtLookupDay.objects.get(source='crt.sh').busy, 2)

	def test_the_timer_writes_each_tick_and_survives_a_failed_one(self):
		ct_health.record('crt.sh', 'ok', now=self.now)
		calls = []
		with mock.patch.object(ct_health, '_flush_and_release', side_effect=[RuntimeError('boom'), None]) as tick:
			ct_health._loop(sleep=calls.append, ticks=2)
		self.assertEqual(calls, [ct_health.FLUSH_SECONDS] * 2)
		self.assertEqual(tick.call_count, 2)
		with mock.patch.object(connection, 'close'):  # the test's own connection stays open
			ct_health._loop(sleep=lambda s: None, ticks=1)
		self.assertEqual(CtLookupDay.objects.get(source='crt.sh').ok, 1)

	def test_only_a_real_worker_starts_batching(self):
		from celery.signals import worker_ready
		ct_health._state.update(batching=False, flusher=False)
		ct_health.install()
		ours = [r for r in worker_ready.receivers if r[0][0] == 'ct-health-batch']
		with mock.patch.object(worker_ready, 'receivers', ours), mock.patch.object(worker_ready, 'sender_receivers_cache', {}), \
				mock.patch('gevent.spawn') as spawn, mock.patch.object(ct_health.threading, 'Thread') as thread:
			with mock.patch('cvengine.lane_memory.lane_name', return_value=''):
				worker_ready.send(sender=None)  # a test or a shell: written at once, no timer
			self.assertFalse(ct_health._state['batching'])
			with mock.patch('cvengine.lane_memory.lane_name', return_value='classic'):
				worker_ready.send(sender=None)
			self.assertTrue(ct_health._state['batching'])
			self.assertEqual(spawn.call_count + thread.call_count, 1)
