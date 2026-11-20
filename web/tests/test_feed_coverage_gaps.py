"""The CVE feed's coverage walk against a feed at the HTTP layer (issue 207, review of the fix).

A fake cve.now serves ``/entries`` newest-first with a keyset cursor and ``/entries/<id>``; each test starts from a seed or from nothing
and runs the scheduled sync and backfill the way the workers do, then counts what the feed lists and the store lacks."""
import datetime
import gzip
import json
import os
import tempfile
from unittest import mock

import requests
from django.test import TestCase
from django.utils import timezone

from cveFeed import cve_now, feed_watermark, seed, tasks
from cveFeed.models import CVEEntry, FeedWatermark

D = datetime.timedelta
PER_DAY = 120


def iso(t):
	return t.strftime('%Y-%m-%dT%H:%M:%S.000Z')


class Resp:
	def __init__(self, data, status=200, text=''):
		self.data, self.status_code, self.headers, self.text = data, status, {}, text

	def json(self):
		return self.data

	def raise_for_status(self):
		if self.status_code >= 400:
			raise requests.HTTPError(str(self.status_code), response=self)


class FakeFeed:
	"""cve.now as it answers since 2026-11-15: ``/entries`` lists ``items`` with ``next_cursor`` and refuses a page past the newest
	``depth`` (401 ``depth_limit``); ``/entries?since=`` lists what changed after a time, oldest first, at most 7 days back; each past UTC
	day has an ``/archive/<day>.md`` page."""
	DEPTH = 400

	def __init__(self, now, days, per_day=PER_DAY, depth=DEPTH):
		self.now, self.headers, self.depth = now, {}, depth
		step = D(days=days) / (days * per_day)
		self.entries = []
		for i in range(days * per_day):
			pub = now - step * i - D(minutes=1)
			self.entries.append({'id': f'CVE-2026-{900000 - i}', 'publishedAt': iso(pub), 'firstSeenAt': iso(pub + D(minutes=10)), '_pub': pub})
		self.by_id = {e['id']: e for e in self.entries}
		self.fail_ids, self.fail_all, self.gets, self.requests = set(), False, 0, []

	def row(self, e, **extra):
		return {**{k: v for k, v in e.items() if k != '_pub'}, 'kev': False, **extra}

	def get(self, url, params=None, timeout=None, headers=None):
		self.requests.append((url, dict(params or {})))
		path = url.split('/api/v1')[-1] if '/api/v1' in url else url.split('cve.now')[-1]
		if path.startswith('/entries/'):
			cid = path.split('/entries/')[1]
			self.gets += 1
			if self.fail_all or cid in self.fail_ids:
				return Resp({}, 500)
			e = self.by_id[cid]
			return Resp({'id': cid, 'title': cid, 'publishedAt': e['publishedAt'], 'firstSeenAt': e['firstSeenAt'], 'severity': {'cvss': 5.0},
						 'affected': [], 'exploitation': {'kev': None, 'epssReached': None, 'exploitDb': None}})
		if path == '/entries' and (params or {}).get('since'):
			since = datetime.datetime.fromisoformat(params['since'].replace('Z', '+00:00'))
			if since < self.now - D(days=7):
				return Resp({'error': 'since_too_old'}, 400)
			changed = sorted((e for e in self.entries if e['_pub'] + D(minutes=10) > since), key=lambda e: e['_pub'])
			start, limit = int(params.get('cursor') or 0), int(params['limit'])
			page = changed[start:start + limit]
			more = start + limit < len(changed)
			return Resp({'items': [self.row(e, updatedAt=e['firstSeenAt']) for e in page], 'next_cursor': str(start + limit) if more else None,
						 'next_since': page[-1]['firstSeenAt'] if page else params['since'], 'has_more': more})
		if path == '/entries':
			start = int((params or {}).get('cursor') or 0)
			limit = int(params['limit'])
			if start >= self.depth:
				return Resp({'error': 'depth_limit', 'message': 'deeper pages need an API key; use since'}, 401)
			nxt = str(start + limit) if start + limit < len(self.entries) else None
			rows = [self.row(e) for e in self.entries[start:start + limit]]
			return Resp({'items': rows, 'entries': rows, 'next_cursor': nxt})
		if path.startswith('/archive/'):
			day = datetime.date.fromisoformat(path.split('/archive/')[1][:10])
			if day >= self.now.date():
				return Resp({}, 404, text='# Not found')
			lines = [f"- [{e['id']}](https://cve.now/{e['id']}.md): {e['id']} (CVSS 5.0, x)" for e in self.entries if e['_pub'].date() == day]
			return Resp({}, 200, text=f'# CVEs published {day}\n\n## CVEs\n\n' + '\n'.join(lines) + '\n')
		if '/feed' in url:
			return Resp({'items': []})
		raise AssertionError(url)


def make_client(feed):
	def factory(*a, **k):
		client = cve_now.CVENowClient(session=feed)
		client.sleep = lambda s: None
		return client
	return factory


class FeedSim(TestCase):
	def setUp(self):
		for target in ('cveFeed.tasks.auto_fire_new_cves.delay', 'cveFeed.tasks.correlate_refreshed_cves.delay',
					   'cveFeed.tasks.correlate_new_cves.delay', 'cveFeed.tasks.import_inventory_cve_history.delay'):
			mock.patch(target).start()
		self.addCleanup(mock.patch.stopall)

	def backfill(self, **kw):
		return tasks.backfill_cve_now_feed(sleep=lambda s: None, **kw)

	def seed_from(self, feed, age_days, covers='keep', generated='keep'):
		"""A seed holding every entry published at least ``age_days`` ago (plus an ancient one), its manifest times optionally doctored."""
		cutoff = feed.now - D(days=age_days)
		CVEEntry.objects.all().delete()
		rows = [CVEEntry(cve_id=e['id'], affected=[], published_at=e['_pub'], first_seen_at=e['_pub'] + D(minutes=10)) for e in feed.entries if e['_pub'] <= cutoff]
		rows.append(CVEEntry(cve_id='CVE-1999-0001', affected=[], published_at=feed.now - D(days=9000)))
		CVEEntry.objects.bulk_create(rows)
		# the exporting install read its feed through the cutoff: the seed says no more than that (seed.covered_through)
		FeedWatermark.objects.update_or_create(source=feed_watermark.SOURCE, defaults={'covered_through': cutoff})
		path = os.path.join(tempfile.mkdtemp(), 's.jsonl.gz')
		with mock.patch('django.utils.timezone.now', return_value=cutoff + D(hours=1)):
			seed.export_seed(path)
		lines = gzip.open(path, 'rt').read().split('\n')
		manifest = json.loads(lines[0])
		for key, value in (('covers_through', covers), ('generated_at', generated)):
			if value is None:
				manifest.pop(key, None)
			elif value != 'keep':
				manifest[key] = value
		lines[0] = json.dumps(manifest)
		with gzip.open(path, 'wt') as out:
			out.write('\n'.join(lines))
		CVEEntry.objects.all().delete()
		FeedWatermark.objects.all().delete()
		seed.import_seed(path)

	def missing_in(self, feed, newer_than_days):
		stored = set(CVEEntry.objects.values_list('cve_id', flat=True))
		return sorted(e['id'] for e in feed.entries if (feed.now - e['_pub']).total_seconds() / 86400 <= newer_than_days and e['id'] not in stored)

	def run_until_covered(self, feed, runs=40):
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			tasks.sync_cve_now_feed()
			for n in range(runs):
				if self.backfill().get('status') == 'covered':
					return n + 1
		return runs


class SeedTimeTests(FeedSim):
	"""A seed's own time is a claim: one that lies in the future must not make the walk skip what lies between."""

	def test_a_covers_through_in_the_future_leaves_no_gap(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 4, covers=iso(timezone.now() + D(days=30)))
		self.run_until_covered(feed)
		self.assertEqual(self.missing_in(feed, 4), [])

	def test_a_generated_at_in_the_future_without_covers_through_leaves_no_gap(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 4, covers=None, generated=iso(timezone.now() + D(days=30)))
		self.run_until_covered(feed)
		self.assertEqual(self.missing_in(feed, 4), [])

	def test_a_stored_future_watermark_is_not_trusted_either(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 4)
		FeedWatermark.objects.update(covered_through=timezone.now() + D(days=30))
		self.run_until_covered(feed)
		self.assertEqual(self.missing_in(feed, 4), [])

	def test_a_few_minutes_of_clock_skew_is_clamped_not_distrusted(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 4, covers=iso(timezone.now() + D(minutes=5)))
		self.assertIsNotNone(feed_watermark.current().covered_through)
		self.assertLessEqual(feed_watermark.current().covered_through, timezone.now())

	def test_an_honest_seed_still_leaves_no_gap(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 4)
		self.run_until_covered(feed)
		self.assertEqual(self.missing_in(feed, 4), [])


class UnreadableEntryTests(FeedSim):
	"""One entry the feed always refuses must not keep the window from being declared covered, and must not be silent."""

	def test_an_entry_that_always_fails_is_recorded_and_the_window_is_still_covered(self):
		feed = FakeFeed(timezone.now(), 6)
		feed.fail_ids = {feed.entries[300]['id']}
		runs = self.run_until_covered(feed, runs=12)
		self.assertLess(runs, 12)
		self.assertIsNotNone(feed_watermark.current().covered_through)
		self.assertEqual(self.missing_in(feed, 5), sorted(feed.fail_ids))  # everything else was read
		status = feed_watermark.status()
		self.assertEqual(status['unreadable'], sorted(feed.fail_ids))
		self.assertFalse(status['behind'])

	def test_a_covered_window_with_unreadable_entries_says_so_in_the_result(self):
		feed = FakeFeed(timezone.now(), 6)
		feed.fail_ids = {feed.entries[10]['id']}
		self.run_until_covered(feed, runs=12)
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			out = self.backfill(force=True)
		self.assertEqual(out.get('unreadable'), sorted(feed.fail_ids))

	def test_nothing_is_given_up_before_it_was_tried_several_times(self):
		feed = FakeFeed(timezone.now(), 6)
		feed.fail_ids = {feed.entries[300]['id']}
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			tasks.sync_cve_now_feed()
			first = self.backfill()
		self.assertEqual(first['failed'], 1)
		self.assertNotIn('covered_through', first)
		self.assertIsNone(feed_watermark.current().covered_through)
		self.assertEqual(feed_watermark.status()['unreadable'], [])

	def test_a_recovered_entry_is_read_and_forgotten(self):
		feed = FakeFeed(timezone.now(), 6)
		bad = feed.entries[300]['id']
		feed.fail_ids = {bad}
		self.run_until_covered(feed, runs=12)
		feed.fail_ids = set()
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			out = self.backfill(force=True)
		self.assertTrue(CVEEntry.objects.filter(cve_id=bad).exists())
		self.assertEqual(feed_watermark.status()['unreadable'], [])
		self.assertNotIn('unreadable', out)

	def test_a_feed_that_refuses_every_entry_never_claims_coverage(self):
		feed = FakeFeed(timezone.now(), 6)
		feed.fail_all = True
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			for n in range(15):
				self.backfill()
		self.assertIsNone(feed_watermark.current().covered_through)
		self.assertTrue(feed_watermark.status()['behind'])
		self.assertLessEqual(len(feed_watermark.status()['unreadable']), feed_watermark.MAX_UNREADABLE)


class AssumedWindowTests(FeedSim):
	"""An install with no seed time and no watermark reads back a fixed window; it says so instead of passing for fully covered."""

	def test_an_old_gap_beyond_the_assumed_window_is_flagged_not_silent(self):
		feed = FakeFeed(timezone.now(), 45)
		CVEEntry.objects.bulk_create([CVEEntry(cve_id=e['id'], affected=[], published_at=e['_pub'], first_seen_at=e['_pub'])
									  for e in feed.entries if e['_pub'] <= feed.now - D(days=44)])
		self.run_until_covered(feed, runs=60)
		status = feed_watermark.status()
		self.assertFalse(status['behind'])
		self.assertEqual(status['window_assumed_days'], feed_watermark.LEGACY_DAYS)
		self.assertTrue(self.missing_in(feed, 43))  # the days beyond it are not read: the status is what says so

	def test_a_seed_without_any_time_is_logged_and_flagged(self):
		feed = FakeFeed(timezone.now(), 8)
		with self.assertLogs('cveFeed.feed_watermark', 'WARNING'):
			self.seed_from(feed, 4, covers=None, generated=None)
		self.run_until_covered(feed)
		self.assertEqual(feed_watermark.status()['window_assumed_days'], feed_watermark.LEGACY_DAYS)

	def test_a_seed_that_states_its_time_is_not_flagged(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 4)
		self.run_until_covered(feed)
		self.assertIsNone(feed_watermark.status()['window_assumed_days'])


class RenamedCursorTests(FeedSim):
	"""cve.now renamed ``nextCursor`` to ``next_cursor`` and stopped anonymous listings at the newest 400 (2026-11): one page must not
	pass for the whole window, and a window falsely declared covered is read again by the update step."""

	def test_the_sync_pages_on_next_cursor_and_stops_quietly_at_the_depth_limit(self):
		feed = FakeFeed(timezone.now(), 8)
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			out = tasks.sync_cve_now_feed(max_new=10000, max_scan=5000)
		self.assertEqual(out['created'], FakeFeed.DEPTH)  # four pages of 100, not one
		self.assertEqual(out['failed'], 0)

	def test_one_page_is_not_taken_for_the_floor(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 6)
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			out = self.backfill()
		self.assertIn('covered_through', out)
		self.assertTrue(out['depth_limited'])
		self.assertEqual(self.missing_in(feed, 6), [])  # 720 entries: the newest 400 by the listing, the rest by date windows
		self.assertTrue(any('/archive/' in url for url, _p in feed.requests))

	def test_date_windows_list_every_day_from_the_archive_and_today_from_the_delta_listing(self):
		now = datetime.datetime(2026, 11, 18, 15, 0, tzinfo=datetime.timezone.utc)
		feed = FakeFeed(now, 8, per_day=300)
		client = make_client(feed)()
		floor, below = now - D(days=5), now - D(hours=2)
		got = client.published_between(floor, below, now, pause=0)
		ids = {i for i, _seen in got}
		wanted = {e['id'] for e in feed.entries if floor <= e['_pub'] < below}
		self.assertFalse(wanted - ids)
		self.assertTrue(all(feed.by_id[i]['_pub'].date() >= floor.date() for i in ids))
		since = [p for url, p in feed.requests if p.get('since')]
		self.assertEqual(since[0]['since'], '2026-11-17T23:00:00.000Z')  # today, from a little before midnight
		days = sorted(url.rsplit('/', 1)[1] for url, _p in feed.requests if '/archive/' in url)
		self.assertEqual(days, ['2026-11-13.md', '2026-11-14.md', '2026-11-15.md', '2026-11-16.md', '2026-11-17.md'])
		feed.requests.clear()
		with mock.patch.object(cve_now, 'SINCE_MAX_PAGES', 1), self.assertRaises(cve_now.WindowIncomplete) as ctx:
			client.published_between(floor, below, now, pause=0)
		# a burst of changes today does not cost the days below it: the archive days are still read, and handed back whole below 23:00
		self.assertEqual(ctx.exception.complete_below, datetime.datetime(2026, 11, 17, 23, 0, tzinfo=datetime.timezone.utc))
		older = {e['id'] for e in feed.entries if floor <= e['_pub'] < ctx.exception.complete_below}
		self.assertFalse(older - {i for i, _seen in ctx.exception.partial})
		self.assertEqual(len([url for url, _p in feed.requests if '/archive/' in url]), 5)

	def test_a_burst_of_changes_today_moves_the_watermark_up_to_today_not_past_it(self):
		now = datetime.datetime(2026, 11, 18, 15, 0, tzinfo=datetime.timezone.utc)
		midnight = datetime.datetime(2026, 11, 18, tzinfo=datetime.timezone.utc)
		feed = FakeFeed(now, 8, per_day=600)  # the newest 400 are all from today: the walk reads today from the delta listing
		with mock.patch('django.utils.timezone.now', return_value=now):
			self.seed_from(feed, 6)
			with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)), mock.patch.object(cve_now, 'SINCE_MAX_PAGES', 1):
				for _run in range(20):  # each run reads its share of the six days behind the seed
					out = self.backfill()
					self.assertEqual(out['status'], 'ok')  # never a failed walk on the status page
					if 'covered_through' in out:
						break
		self.assertIn('has more than 1 pages', out['deferred'])
		# the watermark moves up to where the window was listed whole (23:00 yesterday), not past today: the next walk reads today again
		self.assertEqual(feed_watermark.current().covered_through, midnight - D(hours=1))
		stored = set(CVEEntry.objects.values_list('cve_id', flat=True))
		older = [e['id'] for e in feed.entries if now - D(days=6) <= e['_pub'] < midnight - D(hours=1) and e['id'] not in stored]
		self.assertEqual(older, [])  # the archive days below today were read all the same

	def test_a_window_whose_archive_is_missing_is_not_declared_covered(self):
		feed = FakeFeed(timezone.now(), 8)
		self.seed_from(feed, 6)
		before = feed_watermark.current().covered_through
		real = feed.get

		def no_archive(url, params=None, timeout=None, headers=None):
			return Resp({}, 404, text='# Not found') if '/archive/' in url else real(url, params=params, timeout=timeout, headers=headers)
		feed.get = no_archive
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			out = self.backfill()
		self.assertEqual(out['status'], 'incomplete')
		self.assertEqual(feed_watermark.current().covered_through, before)

	def test_a_falsely_covered_window_is_read_again_and_matched(self):
		from django.core.management import call_command
		feed = FakeFeed(timezone.now(), 12)
		self.seed_from(feed, 11)
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)):
			tasks.sync_cve_now_feed(max_new=50)  # what the old walk did: one page read, and the watermark moved to the head
		FeedWatermark.objects.update(covered_through=timezone.now(), checked_at=timezone.now())
		self.assertTrue(self.missing_in(feed, 11))
		through = iso(feed.now - D(days=11))
		with mock.patch('cveFeed.tasks.recover_cve_feed_window.delay') as queued:
			call_command('recover_feed_gap', stdout=open(os.devnull, 'w'))
			self.assertEqual(feed_watermark.current().covered_through.date(), timezone.now().date())  # a dry run changes nothing
			call_command('recover_feed_gap', apply=True, through=through, stdout=open(os.devnull, 'w'))
		queued.assert_called_once()
		self.assertIsNone(feed_watermark.current().checked_at)
		with mock.patch('cveFeed.tasks.CVENowClient', make_client(feed)), mock.patch('cveFeed.tasks.correlate_cve_rows') as matched:
			out = tasks.recover_cve_feed_window(sleep=lambda s: None)
		self.assertTrue(out['covered'])
		self.assertEqual(self.missing_in(feed, 11), [])
		self.assertEqual(sum(len(c.args[0]) for c in matched.call_args_list), out['created'])  # every CVE read is matched, whatever its tier
		self.assertGreater(out['created'], 0)

	def test_the_update_step_never_moves_the_watermark_forward(self):
		from django.core.management import call_command
		early = timezone.now() - D(days=40)
		FeedWatermark.objects.create(source=feed_watermark.SOURCE, covered_through=early)
		with mock.patch('cveFeed.tasks.recover_cve_feed_window.delay'):
			call_command('recover_feed_gap', apply=True, stdout=open(os.devnull, 'w'))
		self.assertEqual(feed_watermark.current().covered_through, early)


class StaleScoreAfterIpBackfillTests(TestCase):
	"""Issue 212: the migration corrects ``is_private`` only. A score stored before it keeps the "Public IP observed" line until the host is
	rescored (the daily ``rescore_all_hosts``); the rescore is what removes it. There is no one-off rescore flag to set from the migration."""

	def setUp(self):
		from dashboard.models import Org, Project
		from scanEngine.models import EngineType
		from startScan.models import IpAddress, ScanHistory, Subdomain
		from targetApp.models import Domain
		org = Org.objects.create(name='A', slug='a')
		self.project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='score.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.score.test', target_domain=domain, scan_history=scan, score=10,
											score_detail=[{'label': 'Public IP observed in inventory (service reachability unverified)', 'points': 10}])
		self.sub.ip_addresses.add(IpAddress.objects.create(address='10.1.2.3', is_private=False))  # as a scan stored it before the migration

	def test_the_migration_leaves_the_stored_score_and_the_next_rescore_corrects_it(self):
		import importlib
		from django.apps import apps
		from cveFeed import scoring
		from startScan.models import IpAddress, Subdomain
		importlib.import_module('startScan.migrations.0024_ip_is_private_backfill').backfill(apps, None)
		self.assertTrue(IpAddress.objects.get(address='10.1.2.3').is_private)
		self.assertEqual(Subdomain.objects.get(pk=self.sub.pk).score, 10)  # still stale: nothing rescored it
		scoring.rescore_hosts(self.project.id, ['www.score.test'])
		stored = Subdomain.objects.get(pk=self.sub.pk)
		self.assertEqual(stored.score, 0)
		self.assertFalse([line for line in stored.score_detail if 'Public IP' in line['label']])
