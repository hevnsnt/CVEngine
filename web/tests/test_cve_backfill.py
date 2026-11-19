import datetime
import unittest
from types import SimpleNamespace
from unittest import mock

import requests
from django.test import TestCase
from django.utils import timezone

from cveFeed import cve_now, tasks
from cveFeed.models import CVEEntry


def _ago(days, hours=0):
	return (timezone.now() - datetime.timedelta(days=days, hours=hours)).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def _full(cid, seen):
	return {'id': cid, 'title': cid, 'firstSeenAt': seen, 'severity': {'cvss': 9.2}, 'affected': [{'product': 'PHP'}]}


def _http_error(status):
	return requests.HTTPError(f'{status}', response=SimpleNamespace(status_code=status))


def _pub(days, hours=0):
	"""A listing summary's times: published that long ago, first seen a few minutes later."""
	return {'publishedAt': _ago(days, hours), 'firstSeenAt': _ago(days, hours - 0.1 if hours else 0)}


def _listing(summaries, size=5):
	"""A ``client.iter_pages`` stand-in over ``summaries``: pages of ``size``, each with the cursor that fetched it (None for the first),
	and a ``cursor`` argument that continues from that page, as the real listing does."""
	pages = [summaries[n:n + size] for n in range(0, len(summaries), size)]

	def iter_pages(max_entries=500, page_size=100, page_pause=0, cursor=None):
		start = int(cursor[1:]) if cursor else 0
		read = 0
		for n in range(start, len(pages)):
			if read >= max_entries:
				return
			yield (f'c{n}' if n else None), pages[n]
			read += len(pages[n])
	return iter_pages


class _BackfillBase(TestCase):
	def setUp(self):
		self.client = mock.Mock()
		self.client.get_entry.side_effect = lambda cid: _full(cid, _ago(3))
		self.client.tech_entry_ids.return_value = []  # the scheduled run also reads the watched technology feeds
		self.client.iter_pages.side_effect = _listing([])
		self.client.published_between.return_value = []  # below the listing: the date windows (cve_now.CVENowClient.published_between)
		patches = [mock.patch('cveFeed.tasks.CVENowClient', return_value=self.client),
				   mock.patch('cveFeed.tasks.auto_fire_new_cves.delay')]
		self.fire = patches[1].start()
		patches[0].start()
		self.addCleanup(mock.patch.stopall)
		self.sleeps = []

	def _store(self, cid, seen):
		CVEEntry.objects.create(cve_id=cid, affected=[], first_seen_at=seen)

	def _run(self, **kw):
		return tasks.backfill_cve_now_feed(sleep=self.sleeps.append, **kw)

	def _watermark(self, **fields):
		from cveFeed import feed_watermark
		row = feed_watermark.current()
		for key, value in fields.items():
			setattr(row, key, value)
		row.save()
		return row

	def _reload(self):
		from cveFeed import feed_watermark
		return feed_watermark.current()


class BackfillTests(_BackfillBase):
	def test_the_walk_does_not_stop_at_known_entries_and_stops_at_the_floor(self):
		now = timezone.now()
		for n in range(60):  # more known entries in a row than the incremental sync's stop of 40
			self._store(f'CVE-2099-{n}', now - datetime.timedelta(hours=n))
		summaries = [{'id': f'CVE-2099-{n}', **_pub(0, n)} for n in range(60)]
		summaries += [{'id': 'CVE-2026-109618', **_pub(4)}, {'id': 'CVE-2026-109619', **_pub(4)},
					  {'id': 'CVE-2020-0001', **_pub(40)}, {'id': 'CVE-2020-0002', **_pub(41)}]
		self.client.iter_pages.side_effect = _listing(summaries)
		out = self._run(days=14)
		self.assertEqual((out['status'], out['created'], out['failed']), ('ok', 2, 0))
		self.assertEqual(sorted(c.args[0] for c in self.client.get_entry.call_args_list), ['CVE-2026-109618', 'CVE-2026-109619'])
		self.assertFalse(CVEEntry.objects.filter(cve_id='CVE-2020-0001').exists())  # older than the floor
		self.assertEqual(len(self.sleeps), 2)  # paused between fetches
		self.assertEqual(len(self.fire.call_args.args[0]), 2)

	def test_the_listing_is_ordered_by_publication_time_and_so_is_the_floor(self):
		# an entry first seen after the floor but published before it is listed below it: the floor is a publication time, so the walk
		# stops at the first entry published before it and does not look further (the margin is what covers the entries that arrive late)
		summaries = [{'id': 'CVE-2026-1', 'publishedAt': _ago(2), 'firstSeenAt': _ago(2)},
					 {'id': 'CVE-2020-1', 'publishedAt': _ago(40), 'firstSeenAt': _ago(1)}]
		self.client.iter_pages.side_effect = _listing(summaries)
		out = self._run(days=14)
		self.assertEqual(out['created'], 1)

	def test_the_listing_time_is_kept_on_the_entry(self):
		self.client.iter_pages.side_effect = _listing([{'id': 'CVE-2026-1', **_pub(2)}])
		self.client.get_entry.side_effect = lambda cid: {'id': cid, 'title': 't'}  # a full entry that omits the time
		self._run(days=14)
		self.assertIsNotNone(CVEEntry.objects.get(cve_id='CVE-2026-1').first_seen_at)

	def test_a_complete_walk_moves_the_watermark_to_the_head_it_started_from(self):
		head = {'id': 'CVE-2026-7', 'publishedAt': _ago(0, 3), 'firstSeenAt': _ago(0, 3)}
		self.client.iter_pages.side_effect = _listing([head, {'id': 'CVE-2026-8', **_pub(2)}, {'id': 'CVE-2020-1', **_pub(40)}])
		out = self._run(days=14)
		row = self._reload()
		self.assertEqual(out['covered_through'], row.covered_through.isoformat())
		self.assertAlmostEqual(row.covered_through.timestamp(), (timezone.now() - datetime.timedelta(hours=3)).timestamp(), delta=120)
		self.assertEqual((row.resume_cursor, row.resume_head), ('', None))
		self.assertIsNotNone(row.checked_at)

	def test_nothing_is_requested_while_the_last_complete_walk_is_recent(self):
		self._watermark(covered_through=timezone.now() - datetime.timedelta(hours=1), checked_at=timezone.now() - datetime.timedelta(hours=1))
		out = self._run(days=14)
		self.assertEqual(out['status'], 'covered')
		self.client.iter_pages.assert_not_called()
		self.client.tech_entry_ids.assert_not_called()
		self.client.get_entry.assert_not_called()

	def test_an_old_complete_walk_is_repeated_back_to_a_little_before_the_watermark(self):
		through = timezone.now() - datetime.timedelta(hours=10)
		self._watermark(covered_through=through, checked_at=timezone.now() - datetime.timedelta(hours=7))
		# published 30 hours ago, so before the watermark, but inside the margin: an entry the feed saw late
		summaries = [{'id': 'CVE-2026-1', **_pub(0, 2)}, {'id': 'CVE-2026-2', **_pub(1, 6)}, {'id': 'CVE-2026-3', **_pub(5)}]
		self.client.iter_pages.side_effect = _listing(summaries)
		out = self._run(days=14)
		self.assertEqual(out['created'], 2)
		self.assertTrue(CVEEntry.objects.filter(cve_id='CVE-2026-2').exists())
		self.assertFalse(CVEEntry.objects.filter(cve_id='CVE-2026-3').exists())  # past the margin

	def test_force_walks_anyway(self):
		self._watermark(covered_through=timezone.now(), checked_at=timezone.now())
		self.client.iter_pages.side_effect = _listing([{'id': 'CVE-2026-6', **_pub(0, 2)}])
		self.assertEqual(self._run(days=14, force=True)['created'], 1)

	def test_zero_days_turns_the_scheduled_run_off(self):
		with mock.patch.dict('os.environ', {'CVENGINE_CVE_COVERAGE_DAYS': '0'}):
			self.assertEqual(self._run()['status'], 'disabled')
		self.client.iter_pages.assert_not_called()

	def test_the_listing_is_read_at_a_polite_pace(self):
		self._run(days=14)
		self.assertEqual(self.client.iter_pages.call_args.kwargs['page_pause'], 0.3)

	def test_a_run_is_bounded_keeps_its_place_and_the_next_one_continues(self):
		summaries = [{'id': f'CVE-2026-{n}', **_pub(2)} for n in range(10)] + [{'id': 'CVE-2020-1', **_pub(60)}]
		self.client.iter_pages.side_effect = _listing(summaries, size=3)
		with mock.patch.object(tasks, 'GAP_MAX_NEW', 4):  # a walk that reads back a long way is allowed more per run
			first = self._run(days=14, max_new=4)
		self.assertEqual((first['created'], first.get('continues')), (4, True))
		self.assertIsNone(self._reload().covered_through)
		self.assertTrue(self._reload().resume_cursor)  # the page it stopped in
		with mock.patch.object(tasks, 'GAP_MAX_NEW', 4):
			self.assertEqual(self._run(days=14, max_new=4)['created'], 4)
			last = self._run(days=14, max_new=4)
		self.assertEqual(last['created'], 2)
		self.assertIn('covered_through', last)
		self.assertEqual(CVEEntry.objects.count(), 10)
		self.assertEqual(self._reload().resume_cursor, '')

	def test_a_backlog_after_an_outage_is_read_in_full_by_repeated_runs(self):
		# 500 entries published over the last two days that were never stored (a worker that was off): the incremental sync's own limits
		# (200 new per run) once left them out for good
		summaries = [{'id': f'CVE-2026-{n}', 'publishedAt': _ago(0, n // 11), 'firstSeenAt': _ago(0, n // 11)} for n in range(500)]
		summaries += [{'id': 'CVE-2020-1', **_pub(60)}]
		self.client.iter_pages.side_effect = _listing(summaries, size=100)
		runs = 0
		with mock.patch.object(tasks, 'GAP_MAX_NEW', 200):
			while runs < 10:
				runs += 1
				if 'covered_through' in self._run(days=14, max_new=200):
					break
		self.assertEqual(CVEEntry.objects.filter(cve_id__startswith='CVE-2026-').count(), 500)
		self.assertIsNotNone(self._reload().covered_through)

	def test_a_failed_fetch_neither_advances_the_watermark_nor_skips_the_entry(self):
		self.client.iter_pages.side_effect = _listing([{'id': 'CVE-2026-1', **_pub(1)}, {'id': 'CVE-2026-2', **_pub(2)}, {'id': 'CVE-2020-1', **_pub(60)}])
		self.client.get_entry.side_effect = _http_error(500)
		out = self._run(days=14)
		self.assertEqual(out['failed'], 2)
		self.assertNotIn('covered_through', out)
		self.assertIsNone(self._reload().covered_through)
		self.client.get_entry.side_effect = lambda cid: _full(cid, _ago(3))
		self.assertEqual(self._run(days=14)['created'], 2)  # the next run reads them again
		self.assertIsNotNone(self._reload().covered_through)

	def test_a_refused_listing_leaves_the_watermark_alone(self):
		self._watermark(covered_through=timezone.now() - datetime.timedelta(days=2), checked_at=timezone.now() - datetime.timedelta(days=2))
		self.client.iter_pages.side_effect = _http_error(403)
		out = self._run(days=14)
		self.assertEqual((out['status'], out['created']), ('blocked', 0))
		self.assertAlmostEqual(self._reload().covered_through.timestamp(), (timezone.now() - datetime.timedelta(days=2)).timestamp(), delta=5)

	def test_an_install_with_no_watermark_reads_back_thirty_days_once(self):
		summaries = [{'id': 'CVE-2026-5', **_pub(22)}, {'id': 'CVE-2020-1', **_pub(60)}]
		self.client.iter_pages.side_effect = _listing(summaries)
		out = self._run()
		self.assertEqual(out['created'], 1)  # 22 days back is outside the 14-day window, inside the one-time 30
		self.assertIn('covered_through', out)
		self.assertEqual(self._run()['status'], 'covered')

	def test_the_walk_may_read_as_deep_as_the_gap(self):
		self._watermark(covered_through=timezone.now() - datetime.timedelta(days=20), checked_at=timezone.now() - datetime.timedelta(days=20))
		self._run()
		from cveFeed import feed_watermark
		budget = self.client.iter_pages.call_args.kwargs['max_entries']
		self.assertGreaterEqual(budget, 22 * feed_watermark.ENTRIES_PER_DAY)
		self.assertLessEqual(budget, feed_watermark.MAX_SCAN)

	def test_exact_ids_are_read_even_when_the_listing_never_shows_them(self):
		out = self._run(ids=['cve-2026-109618', 'CVE-2026-109619', 'not an id', 'CVE-1-2'])
		self.assertEqual(out['created'], 2)
		self.assertEqual(out['invalid'], ['not an id', 'CVE-1-2'])
		self.assertEqual(sorted(c.args[0] for c in self.client.get_entry.call_args_list), ['CVE-2026-109618', 'CVE-2026-109619'])
		self.client.iter_pages.assert_not_called()
		self.assertIsNone(self._reload().covered_through)  # an explicit read says nothing about the feed's completeness

	def test_a_technology_feed_adds_only_the_entries_not_stored(self):
		self._store('CVE-2026-109619', timezone.now())
		self.client.tech_entry_ids.return_value = ['CVE-2026-109618', 'CVE-2026-109619']
		out = self._run(techs=['php'])
		self.assertEqual(out['created'], 1)
		self.assertEqual([c.args[0] for c in self.client.get_entry.call_args_list], ['CVE-2026-109618'])

	def test_the_scheduled_run_reads_the_watched_technologies(self):
		self.client.tech_entry_ids.return_value = ['CVE-2026-109618']
		with mock.patch.dict('os.environ', {'CVENGINE_CVE_WATCH_TECHS': 'php, nextjs'}):
			self._run(days=14)
		self.assertEqual([c.args[0] for c in self.client.tech_entry_ids.call_args_list], ['php', 'nextjs'])

	def test_a_bad_technology_slug_is_reported_not_requested(self):
		self.client.tech_entry_ids.side_effect = ValueError('bad')
		out = self._run(techs=['../etc'])
		self.assertEqual(out['invalid'], ['../etc'])
		self.client.get_entry.assert_not_called()

	def test_a_refusal_stops_the_run_instead_of_hammering(self):
		self.client.get_entry.side_effect = _http_error(403)
		out = self._run(ids=['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'])
		self.assertEqual((out['status'], out['blocked'], out['failed']), ('blocked', True, 1))
		self.assertEqual(self.client.get_entry.call_count, 1)

	def test_one_bad_entry_does_not_stop_the_rest(self):
		def get(cid):
			if cid == 'CVE-2026-1002':
				raise ValueError('bad shape')
			return _full(cid, _ago(2))
		self.client.get_entry.side_effect = get
		out = self._run(ids=['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'])
		self.assertEqual((out['created'], out['failed']), (2, 1))


class DateWindowTests(_BackfillBase):
	"""Below the newest 400 (a 401 ``depth_limit`` without a key) the window is read by date windows; the listing ending is never the floor."""

	def test_a_listing_that_ends_above_the_floor_reads_the_rest_by_date_windows(self):
		self._watermark(covered_through=timezone.now() - datetime.timedelta(days=6))
		self.client.iter_pages.side_effect = _listing([{'id': 'CVE-2026-10', **_pub(0, 2)}, {'id': 'CVE-2026-9', **_pub(0, 5)}])
		self.client.published_between.return_value = [('CVE-2026-8', None), ('CVE-2026-7', _ago(4)), ('CVE-2026-9', None)]
		self._store('CVE-2026-7', None)
		out = self._run()
		floor, below, now = self.client.published_between.call_args.args
		self.assertLess(abs((floor - (timezone.now() - datetime.timedelta(days=9))).total_seconds()), 60)  # the watermark less the margin
		self.assertLess(abs((below - (timezone.now() - datetime.timedelta(hours=5))).total_seconds()), 60)  # the oldest the listing gave
		self.assertEqual(set(CVEEntry.objects.values_list('cve_id', flat=True)), {'CVE-2026-10', 'CVE-2026-9', 'CVE-2026-8', 'CVE-2026-7'})
		self.assertIn('covered_through', out)
		self.assertEqual(out['window_listed'], 3)

	def test_a_window_that_could_not_be_listed_reads_what_it_found_and_does_not_advance(self):
		row = self._watermark(covered_through=timezone.now() - datetime.timedelta(days=6))
		self.client.iter_pages.side_effect = _listing([{'id': 'CVE-2026-10', **_pub(0, 2)}])
		self.client.published_between.side_effect = cve_now.WindowIncomplete('cve.now has no archive page for 2026-11-10')
		out = self._run()
		self.assertEqual(out['status'], 'incomplete')
		self.assertTrue(CVEEntry.objects.filter(cve_id='CVE-2026-10').exists())  # what the listing gave is still read
		self.assertEqual(self._reload().covered_through, row.covered_through)
		self.assertNotIn('covered_through', out)

	def test_a_window_with_more_missing_than_one_run_reads_says_it_continues(self):
		self._watermark(covered_through=timezone.now() - datetime.timedelta(days=6))
		self.client.published_between.return_value = [(f'CVE-2026-{n}', None) for n in range(5)]
		mock.patch.object(tasks, 'GAP_MAX_NEW', 3).start()
		out = self._run(max_new=3)
		self.assertEqual(out['created'], 3)
		self.assertTrue(out['continues'])
		self.assertNotIn('covered_through', out)
		out = self._run(max_new=3)
		self.assertIn('covered_through', out)
		self.assertEqual(CVEEntry.objects.count(), 5)


class WatermarkStatusTests(_BackfillBase):
	def test_the_status_says_how_far_behind_the_feed_is(self):
		from cveFeed import feed_watermark
		self.assertTrue(feed_watermark.status()['behind'])  # nothing is known yet
		self._watermark(covered_through=timezone.now() - datetime.timedelta(hours=3))
		current = feed_watermark.status()
		self.assertFalse(current['behind'])
		self.assertAlmostEqual(current['lag_hours'], 3.0, delta=0.1)
		self._watermark(covered_through=timezone.now() - datetime.timedelta(days=3), resume_cursor='c4')
		late = feed_watermark.status()
		self.assertTrue(late['behind'])
		self.assertTrue(late['walk_in_progress'])

	def test_the_system_status_reports_it(self):
		from agentapi import system_status
		self._watermark(covered_through=timezone.now() - datetime.timedelta(hours=1))
		self.assertFalse(system_status._feeds()['cve_feed_watermark']['behind'])


class ClientPagingTests(unittest.TestCase):
	def test_pages_are_paced_and_the_first_is_not_delayed(self):
		pages = [([{'id': f'CVE-2026-{n}'} for n in range(2)], 'c1'), ([{'id': 'CVE-2026-9'}], 'c2'), ([], None)]
		client = cve_now.CVENowClient(session=mock.Mock(headers={}))
		client.sleep = mock.Mock()
		with mock.patch.object(client, 'list_entries', side_effect=pages):
			got = [e['id'] for e in client.iter_entries(max_entries=10, page_size=2, page_pause=0.3)]
		self.assertEqual(got, ['CVE-2026-0', 'CVE-2026-1', 'CVE-2026-9'])
		self.assertEqual([c.args[0] for c in client.sleep.call_args_list], [0.3, 0.3])

	def test_pages_come_with_the_cursor_that_fetched_them(self):
		client = cve_now.CVENowClient(session=mock.Mock(headers={}))
		client.sleep = mock.Mock()
		with mock.patch.object(client, 'list_entries', side_effect=[([{'id': 'CVE-2026-1'}], 'c1'), ([{'id': 'CVE-2026-2'}], 'c2'), ([{'id': 'CVE-2026-3'}], None)]) as listed:
			got = [(cursor, [e['id'] for e in page]) for cursor, page in client.iter_pages(max_entries=10, page_size=1)]
		self.assertEqual(got, [(None, ['CVE-2026-1']), ('c1', ['CVE-2026-2']), ('c2', ['CVE-2026-3'])])
		with mock.patch.object(client, 'list_entries', side_effect=[([{'id': 'CVE-2026-2'}], None)]) as listed:
			list(client.iter_pages(cursor='c1', page_size=1))
		self.assertEqual(listed.call_args.kwargs['cursor'], 'c1')  # a walk continues from where it stopped

	def test_a_page_past_the_depth_limit_ends_the_listing_quietly(self):
		client = cve_now.CVENowClient(session=mock.Mock(headers={}))
		client.sleep = mock.Mock()
		refused = cve_now.DepthLimit('401', response=SimpleNamespace(status_code=401))
		with mock.patch.object(client, 'list_entries', side_effect=[([{'id': 'CVE-2026-1'}], 'c1'), refused]):
			got = [e['id'] for e in client.iter_entries(max_entries=10)]
		self.assertEqual(got, ['CVE-2026-1'])
		self.assertTrue(client.depth_limited)
		with mock.patch.object(client, 'list_entries', side_effect=[([{'id': 'CVE-2026-1'}], 'c1'), refused]):
			self.assertEqual(len(list(client.iter_pages(max_entries=10))), 1)
		self.assertTrue(client.depth_limited)

	def test_no_pause_by_default(self):
		client = cve_now.CVENowClient(session=mock.Mock(headers={}))
		client.sleep = mock.Mock()
		with mock.patch.object(client, 'list_entries', side_effect=[([{'id': 'CVE-2026-1'}], 'c'), ([{'id': 'CVE-2026-2'}], None)]):
			list(client.iter_entries(max_entries=10))
		client.sleep.assert_not_called()


class ClientRetryTests(unittest.TestCase):
	def _client(self, *responses):
		session = mock.Mock()
		session.headers = {}
		session.get.side_effect = list(responses)
		client = cve_now.CVENowClient(session=session)
		client.sleep = mock.Mock()
		return client, session

	def _resp(self, status, headers=None, body=None):
		r = mock.Mock(status_code=status, headers=headers or {})
		r.json.return_value = body or {}
		r.raise_for_status.side_effect = None if status < 400 else requests.HTTPError(f'{status}', response=r)
		return r

	def test_429_is_retried_after_the_servers_retry_after(self):
		client, session = self._client(self._resp(429, {'Retry-After': '7'}), self._resp(200, body={'ok': 1}))
		self.assertEqual(client._get('/x'), {'ok': 1})
		client.sleep.assert_called_once_with(7.0)
		self.assertEqual(session.get.call_count, 2)

	def test_waits_back_off_and_are_capped(self):
		client, _ = self._client(self._resp(503), self._resp(503), self._resp(503, {'Retry-After': '9999'}), self._resp(200, body={'a': 1}))
		client._get('/x')
		self.assertEqual([c.args[0] for c in client.sleep.call_args_list], [1.0, 2.0, float(cve_now.MAX_WAIT)])

	def test_it_gives_up_after_the_retries(self):
		client, session = self._client(*[self._resp(502)] * 4)
		with self.assertRaises(requests.HTTPError):
			client._get('/x')
		self.assertEqual(session.get.call_count, 4)

	def test_a_403_is_raised_at_once(self):
		client, session = self._client(self._resp(403))
		with self.assertRaises(requests.HTTPError):
			client._get('/x')
		self.assertEqual(session.get.call_count, 1)
		client.sleep.assert_not_called()

	def test_retry_delay_reads_a_date_and_ignores_junk(self):
		self.assertEqual(cve_now._retry_delay(mock.Mock(headers={'Retry-After': 'soon'}), 2), 4.0)
		self.assertEqual(cve_now._retry_delay(mock.Mock(headers={'Retry-After': '-5'}), 0), 0.0)
		self.assertEqual(cve_now._retry_delay(mock.Mock(headers={}), 1), 2.0)

	def test_a_list_page_reads_items_and_next_cursor(self):
		client, session = self._client(self._resp(200, body={'items': [{'id': 'CVE-2026-1'}], 'entries': [{'id': 'CVE-2026-1'}], 'next_cursor': 'n1'}))
		self.assertEqual(client.list_entries(limit=200), ([{'id': 'CVE-2026-1'}], 'n1'))

	def test_a_list_page_in_the_old_shape_still_pages(self):
		client, _ = self._client(self._resp(200, body={'entries': [{'id': 'CVE-2026-2'}], 'nextCursor': 'o1'}))
		self.assertEqual(client.list_entries(), ([{'id': 'CVE-2026-2'}], 'o1'))
		client, _ = self._client(self._resp(200, body={'items': [], 'next_cursor': None}))
		self.assertEqual(client.list_entries(), ([], None))

	def test_a_401_depth_limit_is_its_own_error_and_other_refusals_are_not(self):
		client, _ = self._client(self._resp(401, body={'error': 'depth_limit'}))
		with self.assertRaises(cve_now.DepthLimit):
			client.list_entries(cursor='deep')
		client, _ = self._client(self._resp(403, body={'error': 'forbidden'}))
		with self.assertRaises(requests.HTTPError) as caught:
			client.list_entries(cursor='deep')
		self.assertNotIsInstance(caught.exception, cve_now.DepthLimit)
		client, _ = self._client(self._resp(401, body={'error': 'unauthorized'}))
		with self.assertRaises(requests.HTTPError) as caught:
			client.list_entries()
		self.assertNotIsInstance(caught.exception, cve_now.DepthLimit)

	def test_the_delta_listing_sends_since_and_the_etag_and_reads_a_304(self):
		page = {'items': [{'id': 'CVE-2026-1', 'updatedAt': 'x'}, {'id': 'CVE-2026-2', 'status': 'withdrawn'}], 'next_cursor': 'd1',
				'next_since': '2026-11-18T03:03:14.813Z', 'has_more': True}
		ok = self._resp(200, {'ETag': '"e1"'}, page)
		client, session = self._client(ok, self._resp(304, {'ETag': '"e1"'}))
		since = datetime.datetime(2026, 11, 18, 0, 0, tzinfo=datetime.timezone.utc)
		got = client.changes(since)
		self.assertEqual(session.get.call_args.kwargs['params'], {'since': '2026-11-18T00:00:00.000Z', 'limit': 200})
		self.assertEqual((len(got['items']), got['next_cursor'], got['has_more'], got['etag']), (2, 'd1', True, '"e1"'))
		again = client.changes(got['next_since'], etag=got['etag'])
		self.assertTrue(again['not_modified'])
		self.assertEqual(again['items'], [])
		self.assertEqual(session.get.call_args.kwargs['headers'], {'If-None-Match': '"e1"'})

	def test_a_days_archive_gives_its_cve_ids_only(self):
		text = ('# CVEs published 2026-11-06\n\n## Early warnings\n\n- [SZB-659381b7e7](https://cve.now/SZB-659381b7e7): CISA adds CVE-2026-19868\n'
				'## CVEs\n\n- [CVE-2026-71881](https://cve.now/CVE-2026-71881.md): GBIF (CVSS 4.8, x)\n'
				'- [GHSA-47W9-6R3F-938G](https://cve.now/GHSA-47W9-6R3F-938G.md): LXD\n- [CVE-2026-109469](https://cve.now/CVE-2026-109469.md): y\n'
				'- [CVE-2026-71881](https://cve.now/CVE-2026-71881.md): again\n')
		resp = self._resp(200)
		resp.text = text
		client, session = self._client(resp)
		self.assertEqual(client.archive_day_ids(datetime.date(2026, 11, 6)), ['CVE-2026-71881', 'CVE-2026-109469'])
		self.assertEqual(session.get.call_args.args[0], 'https://cve.now/archive/2026-11-06.md')

	def test_the_exploitation_objects_are_read_as_flags(self):
		flags = cve_now.exploitation_flags({'kev': {'dateAdded': '2021-12-10', 'dueDate': '2021-12-24'}, 'epssReached': {'date': '2026-10-22'},
											'exploitDb': {'ids': ['50592'], 'publishedAt': '2021-12-14'}})
		self.assertEqual(flags, {'kev': True, 'epssReached': True, 'exploitDb': True})
		self.assertEqual(cve_now.exploitation_flags({'kev': None, 'epssReached': None, 'exploitDb': None}),
						 {'kev': None, 'epssReached': None, 'exploitDb': None})
		self.assertEqual(cve_now.exploitation_flags({'kev': True, 'epssReached': False}), {'kev': True, 'epssReached': False, 'exploitDb': None})
		self.assertEqual(cve_now.exploitation_flags(None), {'kev': None, 'epssReached': None, 'exploitDb': None})

	def test_tech_feed_ids_drop_the_update_suffix_and_duplicates(self):
		body = {'items': [{'id': 'CVE-2026-109618#2026-10-23T00:16:34.627Z'}, {'id': 'CVE-2026-109619'},
						  {'id': 'CVE-2026-109618#older'}, {'id': 'GHSA-abcd-efgh-ijkl'}, {'id': '../x'}, {}]}
		client, session = self._client(self._resp(200, body=body))
		self.assertEqual(client.tech_entry_ids('PHP'), ['CVE-2026-109618', 'CVE-2026-109619', 'GHSA-abcd-efgh-ijkl'])
		url = session.get.call_args.args[0]
		self.assertEqual(url, 'https://cve.now/feed')
		self.assertEqual(session.get.call_args.kwargs['params'], {'tech': 'php', 'format': 'json'})

	def test_tech_slug_is_validated_before_any_request(self):
		client, session = self._client()
		for bad in ('', '../etc', 'php&x=1', 'a b', 'x' * 70, None):
			with self.assertRaises(ValueError):
				client.tech_entry_ids(bad)
		session.get.assert_not_called()
