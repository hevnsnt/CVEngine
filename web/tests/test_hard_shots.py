import os
import shutil
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import shots
from tests.test_shots import make_png


class SizeGateTests(SimpleTestCase):
	"""Verdict 8: a screenshot is size-checked before Image.open and a decompression bomb is an empty hash, not a crash."""

	def setUp(self):
		self.dir = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

	def png(self, name='a.png', kind='gradient'):
		path = os.path.join(self.dir, name)
		make_png(path, kind)
		return path

	def test_a_normal_screenshot_still_hashes(self):
		self.assertEqual(len(shots.dhash_file(self.png())), 16)

	def test_a_file_over_the_byte_limit_is_not_opened(self):
		path = self.png()
		with mock.patch.object(shots, 'MAX_SHOT_BYTES', os.stat(path).st_size - 1), mock.patch.object(shots.Image, 'open') as opened:
			self.assertEqual(shots.dhash_file(path), '')
		opened.assert_not_called()

	def test_a_file_at_the_limit_is_hashed(self):
		path = self.png()
		with mock.patch.object(shots, 'MAX_SHOT_BYTES', os.stat(path).st_size):
			self.assertEqual(len(shots.dhash_file(path)), 16)

	def test_the_real_limit_is_eight_megabytes_or_less(self):
		self.assertLessEqual(shots.MAX_SHOT_BYTES, 8 * 1024 * 1024)

	def test_a_decompression_bomb_error_gives_an_empty_hash(self):
		path = self.png()  # make_png images are a few thousand pixels: past twice this limit Pillow raises DecompressionBombError
		with mock.patch.object(shots.Image, 'MAX_IMAGE_PIXELS', 10):
			self.assertEqual(shots.dhash_file(path), '')

	def test_a_decompression_bomb_warning_is_treated_as_an_error_too(self):
		path = self.png()
		from PIL import Image
		with Image.open(path) as image:
			pixels = image.width * image.height
		with mock.patch.object(shots.Image, 'MAX_IMAGE_PIXELS', int(pixels * 0.8)):  # between the limit and twice the limit: a warning
			self.assertEqual(shots.dhash_file(path), '')

	def test_too_many_pixels_in_a_small_file_is_refused(self):
		path = self.png()
		with mock.patch.object(shots, 'MAX_SHOT_PIXELS', 10):
			self.assertEqual(shots.dhash_file(path), '')

	def test_the_warning_filter_does_not_leak_out_of_the_call(self):
		import warnings
		path = self.png()
		with warnings.catch_warnings(record=True) as seen:
			warnings.simplefilter('always')
			shots.dhash_file(path)
			from PIL import Image
			warnings.warn('later', Image.DecompressionBombWarning)
		self.assertEqual(len(seen), 1)
