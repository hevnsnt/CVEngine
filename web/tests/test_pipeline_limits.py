import gzip

from django.test import SimpleTestCase, TestCase

from cveFeed import hygiene, intel, mailfail


class SpfBudgetTests(SimpleTestCase):
	def test_a_wide_include_tree_stops_at_the_query_budget(self):
		asked = []

		def fetch(domain):
			asked.append(domain)
			return ['v=spf1 ' + ' '.join(f'include:n{i}.{domain}' for i in range(40)) + ' -all']

		count = hygiene.count_spf_lookups('evil.example', fetch)
		self.assertLessEqual(len(asked), hygiene.SPF_MAX_QUERIES)
		self.assertGreater(count, hygiene.SPF_LOOKUP_LIMIT)

	def test_mailfail_takes_a_bounded_list_of_domains(self):
		record = ['v=spf1 ' + ' '.join(f'include:n{i}.example' for i in range(500)) + ' -all']
		self.assertEqual(len(mailfail.spf_referenced_domains(record)), mailfail.SPF_MAX_DOMAINS)


class FeedDecompressionTests(SimpleTestCase):
	def test_epss_still_parses(self):
		raw = gzip.compress(b'#model\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n')
		self.assertEqual(intel.parse_epss(raw), {'CVE-2024-0001': [0.5, 0.9]})

	def test_an_expanding_file_is_refused(self):
		bomb = gzip.compress(b'0' * (3 * 1024 * 1024))
		with self.assertRaises(intel.SourceError):
			intel._gunzip(bomb, 1024 * 1024)
