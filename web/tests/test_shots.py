import os
import shutil
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import changes, discovery, shots
from cveFeed.models import AgentActivity, AssetChange, HostState, RouteAuth
from startScan.models import Subdomain
from tests.test_changes import ChangeFixture

HOST = {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}


def make_png(path, kind):
	"""A 90 by 80 image: a left-to-right gradient, its mirror, vertical stripes or one flat colour."""
	from PIL import Image
	image = Image.new('L', (90, 80))
	pixels = image.load()
	for x in range(90):
		for y in range(80):
			pixels[x, y] = {'gradient': int(x * 255 / 89), 'reverse': int((89 - x) * 255 / 89), 'stripes': 255 if (x // 10) % 2 else 0,
				'flat': 128}[kind]
	image.save(path)


class HashTests(SimpleTestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

	def image(self, kind):
		path = os.path.join(self.dir, f'{kind}.png')
		make_png(path, kind)
		return path

	def test_identical_images_have_distance_zero_and_a_16_character_hash(self):
		a, b = shots.dhash_file(self.image('gradient')), shots.dhash_file(self.image('gradient'))
		self.assertEqual(len(a), 16)
		self.assertEqual(shots.hamming(a, b), 0)

	def test_a_changed_page_is_far_above_the_threshold(self):
		gradient, reverse = shots.dhash_file(self.image('gradient')), shots.dhash_file(self.image('reverse'))
		stripes, flat = shots.dhash_file(self.image('stripes')), shots.dhash_file(self.image('flat'))
		self.assertEqual(shots.hamming(gradient, reverse), 64)
		self.assertGreaterEqual(shots.hamming(stripes, flat), shots.threshold())
		self.assertLess(shots.hamming('0000000000000000', '000000000000001f'), shots.threshold())

	def test_a_missing_or_corrupt_file_gives_an_empty_hash_and_never_raises(self):
		self.assertEqual(shots.dhash_file(os.path.join(self.dir, 'nope.png')), '')
		bad = os.path.join(self.dir, 'bad.png')
		with open(bad, 'wb') as f:
			f.write(b'not an image')
		self.assertEqual(shots.dhash_file(bad), '')

	def test_the_threshold_can_be_tuned_and_is_clamped(self):
		self.assertEqual(shots.threshold(), 12)
		with mock.patch.dict(os.environ, {'CVENGINE_SHOT_THRESHOLD': '20'}):
			self.assertEqual(shots.threshold(), 20)
		with mock.patch.dict(os.environ, {'CVENGINE_SHOT_THRESHOLD': '999'}):
			self.assertEqual(shots.threshold(), 64)
		with mock.patch.dict(os.environ, {'CVENGINE_SHOT_THRESHOLD': 'x'}):
			self.assertEqual(shots.threshold(), 12)

	def test_without_pillow_the_hash_is_empty(self):
		with mock.patch.object(shots, 'Image', None):
			self.assertEqual(shots.dhash_file(self.image('flat')), '')


class PersistTests(ChangeFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.media_root = tempfile.mkdtemp()
		self.bbot_home = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
		self.addCleanup(shutil.rmtree, self.bbot_home, ignore_errors=True)

	def plant(self, rel_path, kind):
		full = os.path.join(self.bbot_home, 'scanname1', rel_path)
		os.makedirs(os.path.dirname(full), exist_ok=True)
		make_png(full, kind)

	def persist(self, scan, shot_list):
		with mock.patch('cveFeed.discovery.BBOT_SCANS_HOME', self.bbot_home), self.settings(MEDIA_ROOT=self.media_root):
			discovery.persist_screenshots(scan, shot_list, 'scanname1')

	def test_persist_screenshots_stores_the_hash(self):
		scan = self.scan({'www.ct.test': HOST})
		self.plant('gowitness/screenshots/a.png', 'gradient')
		self.persist(scan, [{'host': 'www.ct.test', 'rel_path': 'gowitness/screenshots/a.png', 'url': 'x'}])
		sub = Subdomain.objects.get(scan_history=scan)
		self.assertEqual(sub.screenshot_hash, shots.dhash_file(os.path.join(self.media_root, sub.screenshot_path)))
		self.assertEqual(len(sub.screenshot_hash), 16)

	def test_at_most_the_flush_cap_is_hashed(self):
		scan = self.scan({f'h{i}.ct.test': HOST for i in range(4)})
		items = []
		for i in range(4):
			self.plant(f'gowitness/screenshots/{i}.png', 'gradient')
			items.append({'host': f'h{i}.ct.test', 'rel_path': f'gowitness/screenshots/{i}.png', 'url': 'x'})
		with mock.patch.object(shots, 'MAX_HASH_PER_FLUSH', 2):
			self.persist(scan, items)
		hashed = Subdomain.objects.filter(scan_history=scan).exclude(screenshot_hash='').count()
		self.assertEqual((hashed, Subdomain.objects.filter(scan_history=scan).exclude(screenshot_path=None).count()), (2, 4))

	def test_without_pillow_nothing_raises_and_the_skip_is_logged_once_per_scan(self):
		scan = self.scan({'www.ct.test': HOST})
		self.plant('gowitness/screenshots/a.png', 'gradient')
		item = [{'host': 'www.ct.test', 'rel_path': 'gowitness/screenshots/a.png', 'url': 'x'}]
		with mock.patch.object(shots, 'Image', None):
			self.persist(scan, item)
			self.persist(scan, item)
		self.assertEqual(Subdomain.objects.get(scan_history=scan).screenshot_hash, '')
		lines = AgentActivity.objects.filter(message='screenshot comparison skipped: Pillow is not installed')
		self.assertEqual(sum(l.repeat for l in lines), 1)


class DiffTests(ChangeFixture, TestCase):
	def shot_scan(self, hash_):
		scan = self.scan({'www.ct.test': HOST})
		Subdomain.objects.filter(scan_history=scan).update(screenshot_hash=hash_)
		return scan

	def test_a_small_difference_is_ignored_a_large_one_is_a_change_with_the_front_page_auth_state(self):
		first = self.shot_scan('0000000000000000')
		changes.record_scan_changes(first.id)
		self.assertEqual(HostState.objects.get(host='www.ct.test').state['screenshot']['hash'], '0000000000000000')
		small = self.shot_scan('000000000000001f')  # 5 bits
		changes.record_scan_changes(small.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertFalse(AssetChange.objects.filter(kind='screenshot_changed').exists())
		RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.ct.test', url='https://www.ct.test/', path='/',
			auth_state='login')
		big = self.shot_scan('ffffffffffff001f')
		changes.record_scan_changes(big.id, resolver=lambda names: {(n, 'x') for n in names})
		change = AssetChange.objects.get(kind='screenshot_changed')
		self.assertEqual(change.host, 'www.ct.test')
		small_sub = Subdomain.objects.get(scan_history=small)
		big_sub = Subdomain.objects.get(scan_history=big)
		self.assertEqual(change.before, {'hash': '000000000000001f', 'subdomain_id': small_sub.id, 'scan_id': small.id})
		self.assertEqual(change.after, {'hash': 'ffffffffffff001f', 'subdomain_id': big_sub.id, 'scan_id': big.id, 'distance': 48,
			'root_auth': 'login'})

	def test_a_host_that_lost_its_screenshot_or_never_had_one_emits_nothing(self):
		changes.record_scan_changes(self.shot_scan('0000000000000000').id)
		changes.record_scan_changes(self.shot_scan('').id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertFalse(AssetChange.objects.filter(kind='screenshot_changed').exists())
		self.assertEqual(HostState.objects.get(host='www.ct.test').state.get('screenshot', {}).get('hash'), None)

	def test_an_unchanged_picture_does_not_rewrite_the_snapshot(self):
		first = self.shot_scan('0f0f0f0f0f0f0f0f')
		changes.record_scan_changes(first.id)
		again = self.shot_scan('0f0f0f0f0f0f0f0f')
		out = changes.record_scan_changes(again.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertEqual(out['changes'], 0)
		self.assertEqual(HostState.objects.get(host='www.ct.test').state['screenshot']['scan_id'], first.id)  # the old picture stays "before"

	def test_the_per_scan_cap_holds(self):
		changes.record_scan_changes(self.scan({f'h{i}.ct.test': HOST for i in range(4)}).id)
		for state in HostState.objects.all():
			state.state = {**state.state, 'screenshot': {'hash': '0' * 16, 'subdomain_id': 1, 'scan_id': 1}}
			state.save()
		scan = self.scan({f'h{i}.ct.test': HOST for i in range(4)})
		Subdomain.objects.filter(scan_history=scan).update(screenshot_hash='f' * 16)
		with mock.patch.object(shots, 'MAX_SHOT_DIFFS_PER_SCAN', 3):
			changes.record_scan_changes(scan.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertEqual(AssetChange.objects.filter(kind='screenshot_changed').count(), 3)
