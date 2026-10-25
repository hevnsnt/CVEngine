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


class BackfillTests(TestCase):
	def setUp(self):
		self.client = mock.Mock()
		self.client.get_entry.side_effect = lambda cid: _full(cid, _ago(3))
		self.client.tech_entry_ids.return_value = []  # the scheduled run also reads the watched technology feeds
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

	def test_the_walk_does_not_stop_at_known_entries_and_stops_at_the_window(self):
		now = timezone.now()
		for n in range(60):  # more known entries in a row than the incremental sync's stop of 40
			self._store(f'CVE-2099-{n}', now - datetime.timedelta(hours=n))
		summaries = [{'id': f'CVE-2099-{n}', 'firstSeenAt': _ago(0, n)} for n in range(60)]
		summaries += [{'id': 'CVE-2026-109618', 'firstSeenAt': _ago(4)}, {'id': 'CVE-2026-109619', 'firstSeenAt': _ago(4)},
					  {'id': 'CVE-2020-0001', 'firstSeenAt': _ago(40)}, {'id': 'CVE-2020-0002', 'firstSeenAt': _ago(41)}]
		self.client.iter_entries.return_value = iter(summaries)
		out = self._run(days=14)
		self.assertEqual((out['status'], out['created'], out['failed']), ('ok', 2, 0))
		self.assertEqual(sorted(c.args[0] for c in self.client.get_entry.call_args_list), ['CVE-2026-109618', 'CVE-2026-109619'])
		self.assertTrue(CVEEntry.objects.filter(cve_id='CVE-2026-109618').exists())
		self.assertFalse(CVEEntry.objects.filter(cve_id='CVE-2020-0001').exists())  # older than the window
		self.assertEqual(len(self.sleeps), 2)  # paused between fetches
		self.fire.assert_called_once()
		self.assertEqual(len(self.fire.call_args.args[0]), 2)

	def test_the_listing_time_is_kept_on_the_entry(self):
		self.client.iter_entries.return_value = iter([{'id': 'CVE-2026-1', 'firstSeenAt': _ago(2)}])
		self.client.get_entry.side_effect = lambda cid: {'id': cid, 'title': 't'}  # a full entry that omits the time
		self._run(days=14)
		self.assertIsNotNone(CVEEntry.objects.get(cve_id='CVE-2026-1').first_seen_at)

	def test_nothing_is_requested_when_the_store_already_reaches_back(self):
		self._store('CVE-2026-5', timezone.now() - datetime.timedelta(days=20))
		out = self._run(days=14)
		self.assertEqual(out['status'], 'covered')
		self.client.iter_entries.assert_not_called()
		self.client.tech_entry_ids.assert_not_called()
		self.client.get_entry.assert_not_called()

	def test_force_walks_anyway(self):
		self._store('CVE-2026-5', timezone.now() - datetime.timedelta(days=20))
		self.client.iter_entries.return_value = iter([{'id': 'CVE-2026-6', 'firstSeenAt': _ago(2)}])
		self.client.tech_entry_ids.return_value = []
		self.assertEqual(self._run(days=14, force=True)['created'], 1)

	def test_zero_days_turns_the_scheduled_run_off(self):
		with mock.patch.dict('os.environ', {'CVENGINE_CVE_COVERAGE_DAYS': '0'}):
			self.assertEqual(self._run()['status'], 'disabled')
		self.client.iter_entries.assert_not_called()

	def test_the_listing_is_read_at_a_polite_pace(self):
		self.client.iter_entries.return_value = iter([])
		self._run(days=14)
		self.assertEqual(self.client.iter_entries.call_args.kwargs['page_pause'], 0.3)

	def test_a_run_is_bounded_and_the_next_one_continues(self):
		summaries = [{'id': f'CVE-2026-{n}', 'firstSeenAt': _ago(2)} for n in range(10)]
		self.client.iter_entries.side_effect = lambda **kw: iter(summaries)
		self.client.tech_entry_ids.return_value = []
		self.assertEqual(self._run(days=14, max_new=4)['created'], 4)
		self.assertEqual(self._run(days=14, max_new=4)['created'], 4)
		self.assertEqual(self._run(days=14, max_new=4)['created'], 2)
		self.assertEqual(CVEEntry.objects.count(), 10)

	def test_exact_ids_are_read_even_when_the_listing_never_shows_them(self):
		out = self._run(ids=['cve-2026-109618', 'CVE-2026-109619', 'not an id', 'CVE-1-2'])
		self.assertEqual(out['created'], 2)
		self.assertEqual(out['invalid'], ['not an id', 'CVE-1-2'])
		self.assertEqual(sorted(c.args[0] for c in self.client.get_entry.call_args_list), ['CVE-2026-109618', 'CVE-2026-109619'])
		self.client.iter_entries.assert_not_called()

	def test_a_technology_feed_adds_only_the_entries_not_stored(self):
		self._store('CVE-2026-109619', timezone.now())
		self.client.tech_entry_ids.return_value = ['CVE-2026-109618', 'CVE-2026-109619']
		out = self._run(techs=['php'])
		self.assertEqual(out['created'], 1)
		self.assertEqual([c.args[0] for c in self.client.get_entry.call_args_list], ['CVE-2026-109618'])

	def test_the_scheduled_run_reads_the_watched_technologies(self):
		self.client.iter_entries.return_value = iter([])
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

	def test_a_refused_listing_is_a_status_not_an_exception(self):
		self.client.iter_entries.side_effect = _http_error(403)
		self.client.tech_entry_ids.return_value = []
		out = self._run(days=14)
		self.assertEqual((out['status'], out['created']), ('blocked', 0))

	def test_one_bad_entry_does_not_stop_the_rest(self):
		def get(cid):
			if cid == 'CVE-2026-1002':
				raise ValueError('bad shape')
			return _full(cid, _ago(2))
		self.client.get_entry.side_effect = get
		out = self._run(ids=['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'])
		self.assertEqual((out['created'], out['failed']), (2, 1))


class ClientPagingTests(unittest.TestCase):
	def test_pages_are_paced_and_the_first_is_not_delayed(self):
		pages = [([{'id': f'CVE-2026-{n}'} for n in range(2)], 'c1'), ([{'id': 'CVE-2026-9'}], 'c2'), ([], None)]
		client = cve_now.CVENowClient(session=mock.Mock(headers={}))
		client.sleep = mock.Mock()
		with mock.patch.object(client, 'list_entries', side_effect=pages):
			got = [e['id'] for e in client.iter_entries(max_entries=10, page_size=2, page_pause=0.3)]
		self.assertEqual(got, ['CVE-2026-0', 'CVE-2026-1', 'CVE-2026-9'])
		self.assertEqual([c.args[0] for c in client.sleep.call_args_list], [0.3, 0.3])

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
		r.raise_for_status.side_effect = None if status < 400 else _http_error(status)
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
