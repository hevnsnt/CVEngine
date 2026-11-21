"""The CVE feed's health after cve.now's 2026-11 API changes: the delta listing applies changes to stored CVEs (tombstones close matches),
new CVEs are matched whatever their tier, the record re-read walks follow the catalog, open ranges from an unreadable upper bound (#696) and
distribution build bounds are never "in range", numeric revisions compare, the distro sync reads less, and every feed records how it went."""
import datetime
import gzip
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, cve_now, distro_sync, feed_health, intel, tasks
from cveFeed.models import CVEEntry, CVEMatch, DistroFix, FeedWatermark, IntelSource

D = datetime.timedelta


def iso(t):
	return t.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def _host(slug='fh'):
	from dashboard.models import Org, Project
	from startScan.models import Subdomain
	from targetApp.models import Domain
	project = Project.objects.create(name=slug, slug=slug, insert_date=timezone.now(), org=Org.objects.create(name=slug, slug=slug + 'o'))
	domain = Domain.objects.create(name=f'{slug}.test', project=project, insert_date=timezone.now())
	return Subdomain.objects.create(name=f'www.{slug}.test', target_domain=domain)


class FakeClient:
	"""A CVENowClient stand-in: an empty newest-first listing, a delta listing of ``pages``, full entries from ``entries``."""

	def __init__(self, pages=None, entries=None):
		self.pages = list(pages or [])
		self.entries = dict(entries or {})
		self.change_calls, self.reads, self.depth_limited = [], [], False
		self.sleep = lambda s: None

	def iter_entries(self, max_entries=500, page_size=100, page_pause=0):
		return iter([])

	def changes(self, since, cursor=None, limit=200, etag=None):
		self.change_calls.append({'since': since, 'cursor': cursor, 'etag': etag})
		if not self.pages:
			return {'items': [], 'next_cursor': None, 'next_since': since if isinstance(since, str) else iso(since), 'has_more': False,
					'etag': '"e0"', 'not_modified': False}
		return self.pages.pop(0)

	def get_entry(self, cve_id):
		self.reads.append(cve_id)
		value = self.entries[cve_id]
		if isinstance(value, Exception):
			raise value
		return value


def page(items, more=False, cursor=None, next_since='2026-11-18T10:00:00.000Z', etag='"p"'):
	return {'items': items, 'next_cursor': cursor, 'next_since': next_since, 'has_more': more, 'etag': etag, 'not_modified': False}


def full(cid, cvss=5.0, **over):
	return {'id': cid, 'title': cid, 'severity': {'cvss': cvss}, 'affected': [{'product': 'nginx', 'ranges': [{'introduced': '1.0', 'fixed': '1.2'}]}],
			'status': 'published', 'publishedAt': iso(timezone.now() - D(days=1)), **over}


class _SyncBase(TestCase):
	def setUp(self):
		cache.clear()
		for target in ('cveFeed.tasks.auto_fire_new_cves.delay', 'cveFeed.tasks.correlate_refreshed_cves.delay',
					   'cveFeed.tasks.correlate_new_cves.delay', 'cveFeed.tasks.import_inventory_cve_history.delay'):
			mock.patch(target).start()
		mock.patch('cveFeed.tasks._follow_signal_changes').start()
		self.addCleanup(mock.patch.stopall)

	def sync(self, client, **kw):
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client):
			return tasks.sync_cve_now_feed(**kw)

	def stored(self, cid, synced=None, **fields):
		fields.setdefault('affected', [{'product': 'nginx'}])  # with affected data: the refresh of thin recent CVEs leaves it alone
		obj = CVEEntry.objects.create(cve_id=cid, published_at=timezone.now() - D(days=2), status='published', **fields)
		CVEEntry.objects.filter(pk=obj.pk).update(synced_at=synced or timezone.now() - D(days=2))
		return CVEEntry.objects.get(pk=obj.pk)


class ChangesTests(_SyncBase):
	def test_a_changed_stored_cve_is_read_again_and_marked_for_correlation(self):
		self.stored('CVE-2026-1', cvss=5.0)
		upd = iso(timezone.now() - D(minutes=5))
		client = FakeClient([page([{'id': 'CVE-2026-1', 'updatedAt': upd, 'publishedAt': iso(timezone.now() - D(days=2))}], next_since=upd)],
							{'CVE-2026-1': full('CVE-2026-1', cvss=9.8)})
		out = self.sync(client)
		row = CVEEntry.objects.get(cve_id='CVE-2026-1')
		self.assertEqual(row.cvss, 9.8)
		self.assertTrue(row.needs_recorrelation)
		self.assertEqual(out['changes']['changed'], 1)
		self.assertEqual(IntelSource.objects.get(name='feed:cve_now_changes').last_modified, upd)  # the next read starts here

	def test_the_next_read_starts_from_next_since_and_sends_the_etag(self):
		self.sync(FakeClient([page([], next_since='2026-11-18T10:00:00.000Z', etag='"abc"')]))
		IntelSource.objects.filter(name='feed:cve_now_changes').update(last_modified=iso(timezone.now() - D(hours=1)))
		since = IntelSource.objects.get(name='feed:cve_now_changes').last_modified
		client = FakeClient()
		self.sync(client)
		self.assertEqual(client.change_calls[0], {'since': since, 'cursor': None, 'etag': '"abc"'})

	def test_a_304_changes_nothing_and_keeps_the_position(self):
		since = iso(timezone.now() - D(hours=1))
		IntelSource.objects.create(name='feed:cve_now_changes', last_modified=since, etag='"x"')
		self.sync(FakeClient([{'items': [], 'next_cursor': None, 'next_since': None, 'has_more': False, 'etag': '"x"', 'not_modified': True}]))
		row = IntelSource.objects.get(name='feed:cve_now_changes')
		self.assertEqual((row.last_modified, row.etag, row.last_error), (since, '"x"', ''))

	def test_a_tombstone_closes_the_open_matches(self):
		cve = self.stored('CVE-2026-2')
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=_host(), source='tech')
		upd = iso(timezone.now() - D(minutes=1))
		self.sync(FakeClient([page([{'id': 'CVE-2026-2', 'title': 't', 'status': 'merged', 'updatedAt': upd, 'supersededBy': 'CVE-2026-3'}])]))
		self.assertEqual(CVEEntry.objects.get(pk=cve.pk).status, 'merged')
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, 'not_affected')
		correlation._INDEX_CACHE.update(key=None, value=None)
		self.assertNotIn(cve.pk, correlation.cve_pool()[0])

	def test_the_read_budget_stops_the_run_and_the_position_stays_at_what_was_applied(self):
		for n in range(3):
			self.stored(f'CVE-2026-1{n}')
		times = [iso(timezone.now() - D(minutes=30 - n)) for n in range(3)]
		items = [{'id': f'CVE-2026-1{n}', 'updatedAt': times[n]} for n in range(3)]
		client = FakeClient([page(items, next_since=times[2])], {f'CVE-2026-1{n}': full(f'CVE-2026-1{n}') for n in range(3)})
		out = self.sync(client, changes_max=2)
		self.assertEqual(client.reads, ['CVE-2026-10', 'CVE-2026-11'])
		self.assertFalse(out['changes']['complete'])
		row = IntelSource.objects.get(name='feed:cve_now_changes')
		self.assertEqual((row.last_modified, row.etag), (times[1], ''))

	def test_an_entry_stored_after_its_change_is_not_read_again(self):
		self.stored('CVE-2026-4', synced=timezone.now())
		client = FakeClient([page([{'id': 'CVE-2026-4', 'updatedAt': iso(timezone.now() - D(minutes=10))}])])
		self.sync(client)
		self.assertEqual(client.reads, [])

	def test_a_recent_entry_the_catalog_lacks_is_created_and_an_old_one_left_to_the_import(self):
		recent, old = iso(timezone.now() - D(days=1)), iso(timezone.now() - D(days=900))
		client = FakeClient([page([{'id': 'CVE-2026-5', 'publishedAt': recent, 'updatedAt': iso(timezone.now())},
								   {'id': 'CVE-2018-12131', 'publishedAt': old, 'updatedAt': iso(timezone.now())}])],
							{'CVE-2026-5': full('CVE-2026-5')})
		out = self.sync(client)
		self.assertEqual(client.reads, ['CVE-2026-5'])
		self.assertEqual(out['created'], 1)
		tasks.correlate_new_cves.delay.assert_called_once()

	def test_a_position_older_than_since_reaches_restarts_a_few_hours_back(self):
		IntelSource.objects.create(name='feed:cve_now_changes', last_modified=iso(timezone.now() - D(days=9)))
		client = FakeClient()
		out = self.sync(client)
		self.assertTrue(out['changes']['restarted'])
		since = client.change_calls[0]['since']
		self.assertLess(abs((since - (timezone.now() - D(seconds=tasks.CHANGES_FIRST))).total_seconds()), 60)


class RefreshAndLockTests(_SyncBase):
	def test_only_cves_with_open_matches_or_no_affected_data_are_refreshed(self):
		host = _host()
		live, closed, quiet = self.stored('CVE-2026-20'), self.stored('CVE-2026-21'), self.stored('CVE-2026-22')
		CVEMatch.objects.create(cve_entry=live, subdomain=host, source='tech')
		CVEMatch.objects.create(cve_entry=closed, subdomain=host, source='tech', ai_verdict='not_affected')
		CVEMatch.objects.create(cve_entry=quiet, subdomain=host, source='tech', remediation_status='false_positive')
		client = FakeClient(entries={c: full(c) for c in ('CVE-2026-20', 'CVE-2026-21', 'CVE-2026-22')})
		self.sync(client)
		self.assertEqual(client.reads, ['CVE-2026-20'])

	def test_a_failed_refresh_goes_to_the_back_of_the_queue(self):
		cve = self.stored('CVE-2026-23')
		CVEMatch.objects.create(cve_entry=cve, subdomain=_host(), source='tech')
		out = self.sync(FakeClient(entries={'CVE-2026-23': RuntimeError('unreadable')}))
		self.assertEqual(out['failed'], 1)
		self.assertGreater(CVEEntry.objects.get(pk=cve.pk).synced_at, timezone.now() - D(minutes=5))

	def test_a_second_sync_while_one_runs_returns_at_once(self):
		from reNgine import resources
		with resources.redis_claim(tasks.SYNC_LOCK, 'someone-else', 60) as holder:
			if holder is not True:
				self.skipTest('no Redis to hold the claim')
			client = FakeClient()
			out = self.sync(client)
		self.assertEqual(out['status'], 'running')
		self.assertEqual(client.change_calls, [])

	def test_a_listing_failure_settles_the_activity_row_and_is_recorded(self):
		from cveFeed.models import AgentActivity
		client = FakeClient()
		client.iter_entries = mock.Mock(side_effect=cve_now.requests.ConnectionError('reset'))
		out = self.sync(client)
		self.assertIn('listing_error', out)
		self.assertFalse(AgentActivity.objects.filter(status='running').exists())
		self.assertTrue(AgentActivity.objects.filter(status='failed', message__contains='the listing failed').exists())
		self.assertIn('reset', IntelSource.objects.get(name='feed:cve_now_sync').last_error)

	def test_a_read_that_finds_nothing_is_recorded_as_a_success(self):
		self.sync(FakeClient())
		row = IntelSource.objects.get(name='feed:cve_now_sync')
		self.assertIsNotNone(row.last_changed)
		self.assertEqual(row.last_error, '')


class CorrelationQueueTests(TestCase):
	def test_new_cves_are_matched_whatever_their_tier_and_hot_ones_left_to_auto_fire(self):
		cold = CVEEntry.objects.create(cve_id='CVE-2026-30', affected=[], cvss=5.0)
		hot = CVEEntry.objects.create(cve_id='CVE-2026-31', affected=[], kev=True)
		dead = CVEEntry.objects.create(cve_id='CVE-2026-32', affected=[], status='withdrawn')
		with mock.patch('cveFeed.tasks.correlate_cve_rows') as matched:
			out = tasks.correlate_new_cves([cold.pk, hot.pk, dead.pk])
		self.assertEqual(out['correlated'], 1)
		self.assertEqual([c.pk for c in matched.call_args.args[0]], [cold.pk])

	def test_refreshed_cves_drain_in_batches_and_the_rest_is_queued(self):
		for n in range(7):
			CVEEntry.objects.create(cve_id=f'CVE-2026-4{n}', affected=[], needs_recorrelation=True)
		ticks = iter([0, 0, 0, 100, 100])
		with mock.patch('cveFeed.tasks.correlate_cve_rows', return_value=2) as matched, mock.patch('cveFeed.tasks.correlate_refreshed_cves.delay') as again:
			out = tasks.correlate_refreshed_cves(seconds=10, batch=3, clock=lambda: next(ticks))
		self.assertEqual(out, {'correlated': 6, 'left': 1, 'asked': 4})  # each walk's triage questions are added up
		self.assertEqual(matched.call_count, 2)
		again.assert_called_once()
		with mock.patch('cveFeed.tasks.correlate_cve_rows', return_value=0), mock.patch('cveFeed.tasks.correlate_refreshed_cves.delay') as again:
			self.assertEqual(tasks.correlate_refreshed_cves(), {'correlated': 1, 'left': 0, 'asked': 0})
		again.assert_not_called()

	def test_marking_for_correlation_moves_the_pool_key(self):
		row = CVEEntry.objects.create(cve_id='CVE-2026-50', affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0'}]}])
		CVEEntry.objects.filter(pk=row.pk).update(synced_at=timezone.now() - D(days=1))
		before = CVEEntry.objects.get(pk=row.pk).synced_at
		with mock.patch('cveFeed.intel.fetch_cve5_patiently', return_value={}):
			intel._reread_walk('test-lane', CVEEntry.objects.filter(pk=row.pk), lambda r, doc: [{'product': 'nginx', 'ranges': []}])
		self.assertGreater(CVEEntry.objects.get(pk=row.pk).synced_at, before)


class OpenRangeTests(TestCase):
	"""Issue 696: an upper bound written as text must not leave an open range behind."""

	APACHE = {'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server',
			  'versions': [{'version': '2.4.7', 'lessThan': 'Apache HTTP Server 2.4*', 'status': 'affected', 'versionType': 'custom'}]}

	def doc(self, *entries):
		return {'cveMetadata': {'cveId': 'CVE-2021-44224', 'state': 'PUBLISHED', 'assignerShortName': 'apache'},
				'containers': {'cna': {'affected': list(entries)}}}

	def test_the_conversion_leaves_out_a_range_whose_upper_bound_is_text(self):
		self.assertEqual(intel._ranges(self.APACHE), [])
		self.assertEqual(intel._ranges({'versions': [{'version': '1.0', 'lessThan': 'not a version', 'status': 'affected',
													  'changes': [{'at': '2.0', 'status': 'unaffected'}]}]}),
						 [{'type': 'SEMVER', 'introduced': '1.0', 'fixed': '2.0'}])
		self.assertEqual(intel._ranges({'versions': [{'version': '3.0', 'lessThan': '*', 'status': 'affected'}]}),
						 [{'type': 'SEMVER', 'introduced': '3.0'}])  # "*" is open on purpose

	def test_a_feed_block_open_from_text_is_closed_from_the_record_and_one_meant_open_is_noted(self):
		affected = [{'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server', 'ranges': [{'introduced': '2.4.7'}]},
					{'vendor': 'Acme', 'product': 'Widget', 'ranges': [{'introduced': '3.0'}]},
					{'ecosystem': 'npm', 'package': 'left-pad', 'ranges': [{'introduced': '0'}]}]
		doc = self.doc(self.APACHE, {'vendor': 'Acme', 'product': 'Widget', 'versions': [{'version': '3.0', 'lessThan': '*', 'status': 'affected'}]})
		out, changed = intel.close_open_ranges(affected, doc)
		self.assertTrue(changed)
		self.assertEqual(out[0]['ranges'], [])
		self.assertEqual(out[0]['upper_unreadable'], ['2.4.7'])
		self.assertEqual(out[1]['ranges'], [{'introduced': '3.0'}])
		self.assertEqual(out[1]['open_checked'], ['3.0'])
		self.assertEqual(out[2], affected[2])  # a package's open range is OSV's, meant open
		# a refresh carries what the record said, with no request
		again = intel.keep_open_checks([dict(a) for a in affected], out)
		self.assertEqual(again[0]['ranges'], [])
		self.assertFalse(intel._unchecked_open(again[0]) or intel._unchecked_open(again[1]))

	def test_from_api_reads_the_record_once_and_the_host_is_out_of_range(self):
		entry = {'id': 'CVE-2021-44224', 'title': 't', 'affected': [{'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server',
																	   'ranges': [{'introduced': '2.4.7'}]}]}
		with mock.patch('cveFeed.intel.fetch_cve5', return_value=self.doc(self.APACHE)) as fetched:
			obj, _ = CVEEntry.from_api(entry)
			CVEEntry.from_api(entry)
		self.assertEqual(fetched.call_count, 1)
		self.assertEqual(CVEEntry.objects.get(pk=obj.pk).affected[0]['ranges'], [])  # no bound left: version unknown, never "in range"

	def test_the_walk_repairs_stored_rows_and_marks_them(self):
		row = CVEEntry.objects.create(cve_id='CVE-2021-44224', affected=[{'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server',
																		 'ranges': [{'introduced': '2.4.7'}]}])
		kept = CVEEntry.objects.create(cve_id='CVE-2026-60', affected=[{'vendor': 'Acme', 'product': 'Widget', 'ranges': [{'introduced': '3.0'}]}])
		docs = {'CVE-2021-44224': self.doc(self.APACHE),
				'CVE-2026-60': self.doc({'vendor': 'Acme', 'product': 'Widget', 'versions': [{'version': '3.0', 'lessThan': '*', 'status': 'affected'}]})}
		self.assertEqual(intel.open_candidates().count(), 2)
		with mock.patch('cveFeed.intel.fetch_cve5_patiently', side_effect=lambda cid, get=None: docs[cid]):
			out = intel.backfill_open_ranges()
		self.assertEqual(out['updated'], 1)
		row.refresh_from_db()
		kept.refresh_from_db()
		self.assertEqual((row.affected[0]['ranges'], row.needs_recorrelation), ([], True))
		self.assertEqual((kept.affected[0]['open_checked'], kept.needs_recorrelation), (['3.0'], False))
		intel.reset_open_ranges()
		self.assertEqual(intel.open_candidates().count(), 0)  # neither is asked again


class DistroBuildBoundTests(TestCase):
	def test_rpm_and_deb_bounds_are_typed_and_never_in_range(self):
		self.assertEqual(intel._ranges({'versions': [{'version': '0', 'lessThan': '0:8.7p1-38.el9_4.4', 'status': 'affected', 'versionType': 'rpm'}]}),
						 [{'type': 'RPM', 'fixed': '0:8.7p1-38.el9_4.4'}])
		feed = intel.normalize_feed_ranges([{'product': 'openssh', 'ranges': [{'introduced': '0', 'fixed': '0:8.7p1-38.el9_4.4'}]},
											{'product': 'openssh', 'ranges': [{'introduced': '0', 'fixed': '1:9.2p1-2+deb12u3'}]},
											{'product': 'openssh', 'ranges': [{'introduced': '8.0', 'fixed': '9.8p1'}]}])
		self.assertEqual([r['type'] for i in feed[:2] for r in i['ranges']], ['RPM', 'DEB'])
		self.assertNotIn('type', feed[2]['ranges'][0])
		self.assertIsNone(correlation.version_in_range(correlation.parse_version('8.7p1'), feed[0]['ranges'][0]))

	def test_stored_rows_are_typed_once(self):
		row = CVEEntry.objects.create(cve_id='CVE-2024-6387', affected=[{'vendor': 'Red Hat', 'product': 'Red Hat Enterprise Linux 9',
																		 'ranges': [{'introduced': '0', 'fixed': '0:8.7p1-38.el9_4.4'}]}])
		self.assertEqual(intel.retype_distro_ranges()['cves'], 1)
		self.assertEqual(intel.retype_distro_ranges(apply=True)['ids'], ['CVE-2024-6387'])
		row.refresh_from_db()
		self.assertEqual((row.affected[0]['ranges'][0]['type'], row.needs_recorrelation), ('RPM', True))
		self.assertEqual(intel.retype_distro_ranges()['cves'], 0)


class RevisionTests(TestCase):
	def test_a_numeric_dash_revision_is_a_release_of_its_own(self):
		pv = correlation.parse_version
		self.assertEqual(correlation._vcmp(pv('7.1.2-35'), pv('7.1.2-4')), 1)
		self.assertEqual(list(pv('1.2.3-1')), [1, 2, 3])  # still the release: only another revision orders it
		self.assertEqual(correlation._vcmp(pv('1.2.3-1'), pv('1.2.3')), 0)
		self.assertTrue(correlation.version_in_range(pv('7.1.2-3'), {'introduced': '7.0.0', 'fixed': '7.1.2-4'}))
		self.assertFalse(correlation.version_in_range(pv('7.1.2-35'), {'introduced': '7.0.0', 'fixed': '7.1.2-4'}))
		self.assertTrue(correlation.version_in_range(pv('7.1.2-35'), {'introduced': '7.0.0', 'lastAffected': '7.1.2'}))  # every revision of 7.1.2
		self.assertFalse(correlation.version_in_range(pv('7.1.2-35'), {'introduced': '7.0.0', 'fixed': '7.1.2'}))
		self.assertEqual(pv('2.4.57-11.el9'), pv('2.4.57'))  # a distribution build is not a revision
		self.assertEqual(pv('1.18.0-6ubuntu14'), pv('1.18.0'))


class DeadStatusTests(TestCase):
	def test_withdrawn_and_merged_cves_leave_the_pool_and_close_their_matches(self):
		host = _host('ds')
		rows = {s: CVEEntry.objects.create(cve_id=f'CVE-2099-9{n}', status=s, affected=[{'product': 'nginx'}])
				for n, s in enumerate(('withdrawn', 'merged', 'superseded', 'REJECTED', 'published'))}
		matches = {s: CVEMatch.objects.create(cve_entry=r, subdomain=host, source='tech') for s, r in rows.items()}
		correlation._INDEX_CACHE.update(key=None, value=None)
		self.assertEqual(set(correlation.cve_pool()[0]), {rows['published'].pk})
		self.assertEqual(correlation.close_rejected(), 4)
		matches['published'].refresh_from_db()
		self.assertNotEqual(matches['published'].ai_verdict, 'not_affected')


class KevRemovalTests(TestCase):
	def test_a_cve_cisa_dropped_loses_the_flag_and_one_only_cve_now_listed_keeps_it(self):
		catalog = {f'CVE-2020-{n:05d}': {} for n in range(intel.CISA_KEV_COMPLETE)}
		dropped = CVEEntry.objects.create(cve_id='CVE-2022-28958', kev=True, intel={'kev': {'cisa_kev': {'dateAdded': '2022-06-01'}}})
		feed_only = CVEEntry.objects.create(cve_id='CVE-2026-70', kev=True)
		intel.reconcile({'cisa_kev': catalog})
		self.assertIs(CVEEntry.objects.get(pk=dropped.pk).kev, False)
		self.assertIs(CVEEntry.objects.get(pk=feed_only.pk).kev, True)
		again = CVEEntry.objects.create(cve_id='CVE-2022-1', kev=True, intel={'kev': {'cisa_kev': {}}})
		intel.reconcile({'cisa_kev': {'CVE-2020-00001': {}}})  # a catalog that did not load whole says nothing about removals
		self.assertIs(CVEEntry.objects.get(pk=again.pk).kev, True)

	def test_long_cve_numbers_are_ids(self):
		self.assertTrue(intel.CVE_RE.match('CVE-2026-12345678'))
		self.assertEqual(intel.CVE_IN_TEXT.findall('see CVE-2026-123456789 now'), ['CVE-2026-123456789'])


class SeedCoverageTests(TestCase):
	def test_a_seed_never_claims_past_the_watermark_and_null_when_there_is_none(self):
		from cveFeed import seed
		newest = timezone.now() - D(hours=1)
		self.assertIsNone(seed.covered_through(newest))
		FeedWatermark.objects.update_or_create(source='cve_now', defaults={'covered_through': newest - D(days=3)})
		self.assertEqual(seed.covered_through(newest), newest - D(days=3))
		FeedWatermark.objects.update(covered_through=newest + D(days=1))
		self.assertEqual(seed.covered_through(newest), newest)

	def test_a_seed_that_states_null_is_not_taken_for_its_export_time(self):
		from cveFeed import feed_watermark, seed
		CVEEntry.objects.create(cve_id='CVE-2026-80', affected=[], published_at=timezone.now() - D(days=1))
		path = os.path.join(tempfile.mkdtemp(), 's.jsonl.gz')
		seed.export_seed(path)
		self.assertIsNone(json.loads(gzip.open(path, 'rt').readline())['covers_through'])
		CVEEntry.objects.all().delete()
		seed.import_seed(path)
		self.assertIsNone(feed_watermark.current().covered_through)  # the walk reads its usual window back


class DistroSyncTests(TestCase):
	def test_the_ttl_is_under_the_daily_schedule(self):
		self.assertLess(distro_sync.TTL, D(hours=24))

	def test_rows_are_stored_in_bulk_and_counted_once(self):
		DistroFix.objects.create(distro='debian', release='12', package='openssh', cve_id='CVE-2024-6387', fixed_version='1', status='fixed')
		rows = [{'distro': 'debian', 'release': '12', 'package': 'openssh', 'cve_id': 'CVE-2024-6387', 'fixed_version': '2', 'status': 'fixed'},
				{'distro': 'debian', 'release': '11', 'package': 'openssh', 'cve_id': 'CVE-2024-6387', 'fixed_version': '3', 'status': 'fixed'},
				{'distro': 'debian', 'release': '11', 'package': 'openssh', 'cve_id': 'CVE-2024-6387', 'fixed_version': '3', 'status': 'fixed'}]
		with self.assertNumQueries(3):  # one read, one insert, one update, for any number of rows
			self.assertEqual(distro_sync._store(rows), 2)
		self.assertEqual(distro_sync._store(rows), 0)
		self.assertEqual(DistroFix.objects.get(release='12').fixed_version, '2')

	def test_the_debian_tracker_is_only_downloaded_again_when_it_changed_or_a_cve_is_new(self):
		body = json.dumps({'openssh': {'CVE-2024-6387': {'releases': {'bookworm': {'status': 'resolved', 'fixed_version': '1:9.2p1-2+deb12u3'}}}}})

		class Fetcher:
			calls = []

			def stream_if_changed(self, url, etag='', modified=''):
				self.calls.append(etag)
				if etag == '"t1"':
					return None, (etag, modified)
				return iter([body.encode()]), ('"t1"', '')
		fetcher = Fetcher()
		with mock.patch.object(distro_sync.distro_lib, 'is_known_package', return_value=True):
			rows = distro_sync.sync_debian(fetcher, ['CVE-2024-6387', 'CVE-2099-1'])
			distro_sync._store(rows)
			self.assertEqual(fetcher.calls, [''])  # the first download is a full one
			self.assertEqual(distro_sync.sync_debian(fetcher, ['CVE-2024-6387', 'CVE-2099-1']), [])
			self.assertEqual(fetcher.calls, ['', '"t1"'])  # every CVE was looked up before: conditional, and the 304 reads nothing
			distro_sync.sync_debian(fetcher, ['CVE-2024-6387', 'CVE-2099-2'])
			self.assertEqual(fetcher.calls[-1], '')  # a CVE never looked up: a full download
		self.assertTrue(DistroFix.objects.filter(cve_id='CVE-2099-1', package='').exists())


class FeedStatusTests(TestCase):
	def test_failures_and_staleness_are_problems_and_a_quiet_success_is_not(self):
		feed_health.record('cve_now_sync', True)
		self.assertEqual([p for p in feed_health.status()['problems'] if 'cve.now sync' in p], [])
		feed_health.record('distro_sync', False, 'osv: timeout')
		IntelSource.objects.filter(name='feed:cve_now_sync').update(last_changed=timezone.now() - D(hours=10))
		IntelSource.objects.create(name='cisa_kev', last_checked=timezone.now() - D(hours=1), last_error='HTTP 503')
		feed_health.record('cve_now_changes', True, detail=iso(timezone.now() - D(hours=12)))
		problems = feed_health.status()['problems']
		self.assertTrue(any('distribution fixes run failed: osv: timeout' in p for p in problems))
		self.assertTrue(any('cve.now sync has not succeeded for 10 hours' in p for p in problems))
		self.assertTrue(any('cisa_kev failed: HTTP 503' in p for p in problems))
		self.assertTrue(any('changes are applied up to' in p for p in problems))

	def test_the_status_probe_does_not_count_the_catalog_guidance(self):
		from agentapi import system_status
		feed_health.record('distro_sync', False, 'osv: timeout')
		with mock.patch('cveFeed.detection_author.progress', side_effect=AssertionError('slow')):
			out = system_status._feeds()
		self.assertIn('distro_sync', out['health'])
		self.assertTrue(any('osv: timeout' in p for p in out['problems']))


class RecordWalkTests(TestCase):
	def test_each_walk_takes_a_step_and_a_transient_failure_holds_its_place(self):
		cache.clear()
		row = CVEEntry.objects.create(cve_id='CVE-2026-90', affected=[{'vendor': 'Acme', 'product': 'Widget', 'ranges': [{'introduced': '3.0'}]}])
		err = intel.TransientSourceError('rate limited')
		with mock.patch('cveFeed.intel.fetch_cve5_patiently', side_effect=err):
			out = intel.record_walks_step(10)
		self.assertEqual(out['open-ranges']['failed'], 1)
		from cveFeed.models import BackgroundCursor
		self.assertEqual(BackgroundCursor.objects.get(lane=intel.OPEN_LANE).last_pk, row.pk - 1)  # asked again next pass
		self.assertEqual(set(out), {'bare-versions', 'exact-builds', 'open-ranges'})


class CatalogImportTests(TestCase):
	def test_a_products_older_cves_are_read_and_a_product_done_is_not_asked_again(self):
		from cveFeed import catalog_import
		cache.clear()
		CVEEntry.objects.create(cve_id='CVE-2024-6387', affected=[])

		class Client:
			sleep = staticmethod(lambda s: None)
			searches = []

			def tech_slugs(self):
				return {'apache-httpd': ['Apache HTTP Server']}

			def search_cves(self, query=None, tech=None, published=None, cursor=None, limit=100):
				self.searches.append((query, tech, cursor))
				if tech:
					return ['CVE-2023-31122'], 1, None
				return (['CVE-2025-26465', 'CVE-2024-6387'], 3, 'c1') if not cursor else (['CVE-2023-38408'], 3, None)

			def get_entry(self, cve_id):
				return full(cve_id)
		client = Client()
		out = catalog_import.run(client, reads=10, names=['OpenSSH', 'Apache HTTP Server'])
		self.assertEqual(sorted(CVEEntry.objects.filter(pk__in=out['created']).values_list('cve_id', flat=True)),
						 ['CVE-2023-31122', 'CVE-2023-38408', 'CVE-2025-26465'])
		self.assertEqual(client.searches, [('"OpenSSH"', None, None), ('"OpenSSH"', None, 'c1'), (None, 'apache-httpd', None)])
		self.assertEqual(sorted(out['done']), ['Apache HTTP Server', 'OpenSSH'])
		again = catalog_import.run(client, reads=10, names=['OpenSSH', 'Apache HTTP Server'])
		self.assertEqual(again['products'], [])
