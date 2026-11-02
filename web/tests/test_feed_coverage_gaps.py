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
	def __init__(self, data, status=200):
		self.data, self.status_code, self.headers = data, status, {}

	def json(self):
		return self.data

	def raise_for_status(self):
		if self.status_code >= 400:
			raise requests.HTTPError(str(self.status_code), response=self)


class FakeFeed:
	def __init__(self, now, days, per_day=PER_DAY):
		self.now, self.headers = now, {}
		step = D(days=days) / (days * per_day)
		self.entries = []
		for i in range(days * per_day):
			pub = now - step * i - D(minutes=1)
			self.entries.append({'id': f'CVE-2026-{900000 - i}', 'publishedAt': iso(pub), 'firstSeenAt': iso(pub + D(minutes=10)), '_pub': pub})
		self.by_id = {e['id']: e for e in self.entries}
		self.fail_ids, self.fail_all, self.gets = set(), False, 0

	def get(self, url, params=None, timeout=None):
		path = url.split('/api/v1')[-1]
		if path.startswith('/entries/'):
			cid = path.split('/entries/')[1]
			self.gets += 1
			if self.fail_all or cid in self.fail_ids:
				return Resp({}, 500)
			e = self.by_id[cid]
			return Resp({'id': cid, 'title': cid, 'publishedAt': e['publishedAt'], 'firstSeenAt': e['firstSeenAt'], 'severity': {'cvss': 5.0}, 'affected': []})
		if path == '/entries':
			start = int((params or {}).get('cursor') or 0)
			limit = int(params['limit'])
			nxt = str(start + limit) if start + limit < len(self.entries) else None
			return Resp({'entries': [{k: v for k, v in e.items() if k != '_pub'} for e in self.entries[start:start + limit]], 'nextCursor': nxt})
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
		for target in ('cveFeed.tasks.auto_fire_new_cves.delay', 'cveFeed.tasks.correlate_refreshed_cves.delay'):
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
