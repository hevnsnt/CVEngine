import gzip

from django.test import SimpleTestCase, TestCase

from cveFeed import intel


class FeedDecompressionTests(SimpleTestCase):
	def test_epss_still_parses(self):
		raw = gzip.compress(b'#model\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n')
		self.assertEqual(intel.parse_epss(raw), {'CVE-2024-0001': [0.5, 0.9]})

	def test_an_expanding_file_is_refused(self):
		bomb = gzip.compress(b'0' * (3 * 1024 * 1024))
		with self.assertRaises(intel.SourceError):
			intel._gunzip(bomb, 1024 * 1024)
